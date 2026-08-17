/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Internal APR file index module.
 */

#include "ampr_emu_index.h"
#include "ampr_emu_fd_cache.h"
#include "ampr_emu_errno.h"
#include "ampr_emu_kernel_file.h"
#include "ampr_emu_kernel_memory.h"
#include "ampr_emu_log.h"
#include "ampr_emu_runtime_memory.h"
#include "ampr_emu_sync.h"
#include "ampr.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <new>

[[maybe_unused]] static inline const char* ampr_log_path_arg(const char* path) {
    return path ? path : "(null)";
}
namespace {

struct CompactFileIndexEntry {
    uint32_t pathOffset{};
    uint32_t pathLength{};
    uint64_t size{};
    int64_t mtime{};
};

struct CompactFileIndexHeader {
    char magic[8];
    uint32_t version;
    uint32_t entrySize;
    uint64_t entryCount;
    uint64_t pathBytes;
    uint64_t hashOffset;
    uint32_t hashSlotSize;
    uint32_t hashSlotCount;
};

struct CompactFileIndexHashSlot {
    uint64_t hash{};
    uint32_t indexPlusOne{};
    uint32_t reserved{};
};

static constexpr uint32_t kCompactIndexHashDuplicate = 1u;

/*
 * Loaded AMPRIDX3 state.
 *
 * The runtime keeps fixed records, the path blob, and the open-addressed hash
 * table resident in the fixed emulator pool.
 */
struct FileIndexState {
    AmprMutex m;
    AmprConditionVariable cv;
    bool loaded{false};
    bool loadAttempted{false};
    bool loading{false};
    bool available{false};
    bool compactAvailable{false};
    CompactFileIndexEntry* compactEntries{nullptr};
    size_t compactEntryCount{0};
    const char* compactPathBlob{nullptr};
    CompactFileIndexHashSlot* compactHashSlots{nullptr};
    size_t compactHashMask{0};
    void* compactMapBase{nullptr};
    size_t compactMapSize{0};
    size_t compactPathBlobSize{0};
};

static std::atomic<FileIndexState*> g_file_index_state{nullptr};
alignas(FileIndexState) static unsigned char g_file_index_state_storage[sizeof(FileIndexState)];
static std::atomic<uint32_t> g_file_index_state_init{0};
enum class FileIndexPublishState : uint8_t {
    Pending,
    Available,
    Unavailable,
};
// A release publication makes every compact-index pointer and count immutable
// and visible to lock-free readers for the remaining module lifetime.
static std::atomic<FileIndexPublishState> g_file_index_publish_state{
    FileIndexPublishState::Pending};

static FileIndexState* file_index_state_create() {
    FileIndexState* p = g_file_index_state.load(std::memory_order_acquire);
    if (p) return p;

    uint32_t expected = 0;
    if (g_file_index_state_init.compare_exchange_strong(expected,
                                                        1u,
                                                        std::memory_order_acq_rel,
                                                        std::memory_order_acquire)) {
        p = new (g_file_index_state_storage) FileIndexState();
        g_file_index_state.store(p, std::memory_order_release);
        g_file_index_state_init.store(2u, std::memory_order_release);
        return p;
    }

    uint32_t spins = 0;
    while (g_file_index_state_init.load(std::memory_order_acquire) != 2u) {
        ampr_spin_pause_or_yield(spins);
    }
    return g_file_index_state.load(std::memory_order_acquire);
}

static FileIndexState& file_index_state() { return *file_index_state_create(); }
} // namespace

static constexpr const char* kAmprApp0Root = "/app0";
static constexpr const char* kAmprApp0IndexPath = "/app0/ampr_emu.index";
static constexpr const char* kAmprApp0IndexTempPath = "/app0/ampr_emu.index.tmp";
static constexpr const char* kAmprApp0IndexBackupPath = "/app0/ampr_emu.index.bak";
static constexpr char kAmprIndexMagic[8] = {'A', 'M', 'P', 'R', 'I', 'D', 'X', '3'};
static constexpr uint32_t kAmprIndexVersion = 3;
static constexpr uint64_t kAmprIndexLoadWaitUs = 500000ull;

enum class CompactIndexLoadResult : uint8_t {
    Loaded,
    Missing,
    Invalid,
    Memory,
};

[[maybe_unused]] static const char* compact_index_load_result_name(CompactIndexLoadResult result) {
    switch (result) {
        case CompactIndexLoadResult::Loaded: return "loaded";
        case CompactIndexLoadResult::Missing: return "missing";
        case CompactIndexLoadResult::Invalid: return "invalid";
        case CompactIndexLoadResult::Memory: return "memory";
        default: return "unknown";
    }
}

static CompactIndexLoadResult load_compact_app0_index_locked(FileIndexState& idx);

static inline char ampr_ascii_lower(char ch) {
    return (ch >= 'A' && ch <= 'Z') ? static_cast<char>(ch - 'A' + 'a') : ch;
}

static constexpr size_t kAmprIndexMaxPath = 4096;
#ifndef SCE_KERNEL_PATH_MAX
#define SCE_KERNEL_PATH_MAX 1024
#endif
#ifndef SCE_KERNEL_NAME_MAX
#define SCE_KERNEL_NAME_MAX 255
#endif

struct App0IndexBuildWorkspace {
    char indexKey[kAmprIndexMaxPath];
    char tempIndexKey[kAmprIndexMaxPath];
    char backupIndexKey[kAmprIndexMaxPath];
    char dir[kAmprIndexMaxPath];
    char path[kAmprIndexMaxPath];
    char pathKey[kAmprIndexMaxPath];
};

// FileIndexState::loading serializes the only runtime index builder.
static App0IndexBuildWorkspace g_app0_index_build_workspace{};

static bool ampr_append_path_char(char* out, size_t outSize, size_t* len, char ch) {
    if (!out || !len || outSize == 0 || *len + 1u >= outSize) {
        return false;
    }
    out[*len] = ch;
    ++*len;
    out[*len] = '\0';
    return true;
}

static int normalize_app0_path_key_result(const char* path,
                                          char* out,
                                          size_t outSize,
                                          size_t* outLen = nullptr,
                                          bool* outHadTrailingSeparator = nullptr) {
    if (out && outSize != 0) {
        out[0] = '\0';
    }
    if (outHadTrailingSeparator) {
        *outHadTrailingSeparator = false;
    }
    if (!path || !out || outSize == 0) return EFAULT;
    if (path[0] == '\0') return EINVAL;
    if (path[0] != '/' && path[0] != '\\') return EINVAL;

    size_t len = 0;
    size_t inputLen = 0;
    bool terminated = false;
    for (size_t i = 0; i < static_cast<size_t>(SCE_KERNEL_PATH_MAX); ++i) {
        if (path[i] == '\0') {
            inputLen = i;
            terminated = true;
            break;
        }
    }
    if (!terminated) return ENAMETOOLONG;
    if (outHadTrailingSeparator && inputLen != 0) {
        const char last = path[inputLen - 1u];
        *outHadTrailingSeparator = last == '/' || last == '\\';
    }

    if (!ampr_append_path_char(out, outSize, &len, '/')) return ENAMETOOLONG;
    const char* p = path;
    while (*p) {
        while (*p == '/' || *p == '\\') ++p;
        if (*p == '\0') break;

        const char* const component = p;
        size_t componentLen = 0;
        while (*p != '\0' && *p != '/' && *p != '\\') {
            ++componentLen;
            if (componentLen > static_cast<size_t>(SCE_KERNEL_NAME_MAX)) {
                return ENAMETOOLONG;
            }
            ++p;
        }
        if (componentLen == 1u && component[0] == '.') {
            continue;
        }
        if (componentLen == 2u && component[0] == '.' && component[1] == '.') {
            if (len <= 1u) {
                return EINVAL;
            }
            while (len > 1u && out[len - 1u] != '/') {
                --len;
            }
            if (len > 1u) {
                --len;
            }
            out[len] = '\0';
            continue;
        }

        if (len > 1u && !ampr_append_path_char(out, outSize, &len, '/')) {
            return ENAMETOOLONG;
        }
        for (size_t i = 0; i < componentLen; ++i) {
            if (!ampr_append_path_char(out, outSize, &len, ampr_ascii_lower(component[i]))) {
                return ENAMETOOLONG;
            }
        }
    }
    if (outLen) *outLen = len;
    return 0;
}

static bool normalize_app0_path_key(const char* path, char* out, size_t outSize, size_t* outLen = nullptr) {
    return normalize_app0_path_key_result(path, out, outSize, outLen) == 0;
}

static int compare_index_path_key(const char* path, const char* key) {
    const unsigned char* a = reinterpret_cast<const unsigned char*>(path ? path : "");
    const unsigned char* b = reinterpret_cast<const unsigned char*>(key ? key : "");
    for (;;) {
        unsigned char ca = *a++;
        unsigned char cb = *b++;
        if (ca == '\\') ca = '/';
        if (cb == '\\') cb = '/';
        ca = static_cast<unsigned char>(ampr_ascii_lower(static_cast<char>(ca)));
        cb = static_cast<unsigned char>(ampr_ascii_lower(static_cast<char>(cb)));
        if (ca != cb) return ca < cb ? -1 : 1;
        if (ca == '\0') return 0;
    }
}

static size_t ampr_round_up_page_size(size_t value) {
    static constexpr size_t kPage = SCE_KERNEL_PAGE_SIZE;
    const size_t mask = kPage - 1u;
    if (value > SIZE_MAX - mask) {
        return SIZE_MAX;
    }
    return (value + mask) & ~mask;
}

static uint64_t ampr_align_up_u64(uint64_t value, uint64_t alignment) {
    if (alignment == 0) {
        return value;
    }
    const uint64_t mask = alignment - 1u;
    if (value > UINT64_MAX - mask) {
        return UINT64_MAX;
    }
    return (value + mask) & ~mask;
}

#if AMPR_EMU_DEBUG_LOG
static void ampr_log_kernel_memory_status(const char* tag, size_t requestSize) {
    const size_t dmemTotal = ampr_real_sceKernelGetDirectMemorySize();
    off_t directStart0 = 0;
    size_t directSize0 = 0;
    const int directRc0 = ampr_real_sceKernelAvailableDirectMemorySize(0,
                                                                       (off_t)dmemTotal,
                                                                       0,
                                                                       &directStart0,
                                                                       &directSize0);
    off_t directStart2m = 0;
    size_t directSize2m = 0;
    const int directRc2m = ampr_real_sceKernelAvailableDirectMemorySize(0,
                                                                        (off_t)dmemTotal,
                                                                        2ull * 1024ull * 1024ull,
                                                                        &directStart2m,
                                                                        &directSize2m);
    int cpuPtTotal = 0;
    int cpuPtAvail = 0;
    int gpuPtTotal = 0;
    int gpuPtAvail = 0;
    const int ptRc = sceKernelGetPageTableStats(&cpuPtTotal,
                                                &cpuPtAvail,
                                                &gpuPtTotal,
                                                &gpuPtAvail);

    const size_t roundedRequest = requestSize ? ampr_round_up_page_size(requestSize) : 0;

    AMPR_LOGF("mem.status tag=%s request=0x%llx dmemTotal=0x%llx directRc0=0x%x directStart0=0x%llx directSize0=0x%llx directRc2m=0x%x directStart2m=0x%llx directSize2m=0x%llx pageTableRc=0x%x cpuPt=%d/%d gpuPt=%d/%d",
              tag ? tag : "(null)",
              (unsigned long long)roundedRequest,
              (unsigned long long)dmemTotal,
              directRc0,
              (unsigned long long)directStart0,
              (unsigned long long)directSize0,
              directRc2m,
              (unsigned long long)directStart2m,
              (unsigned long long)directSize2m,
              ptRc,
              cpuPtAvail,
              cpuPtTotal,
              gpuPtAvail,
              gpuPtTotal);
}
#else
static void ampr_log_kernel_memory_status(const char*, size_t) {}
#endif

static void* ampr_alloc_sdk_cpu_memory(
    size_t size,
    AmprSharedSdkCpuMemoryClass memoryClass = AmprSharedSdkCpuMemoryClass::Persistent) {
    if (size == 0) return nullptr;

    const char* className = ampr_sdk_cpu_memory_class_name(memoryClass);
    const bool mayCreatePool = memoryClass == AmprSharedSdkCpuMemoryClass::Persistent;
    size_t smallSize = 0;
    void* small = ampr_small_slab_alloc(size,
                                               alignof(std::max_align_t),
                                               &smallSize,
                                               className,
                                               mayCreatePool);
    if (small) {
        ampr_sdk_cpu_memory_note_alloc(memoryClass, smallSize);
        AMPR_LOGF("mem.sdk_cpu.alloc ok class=%s owner=small-slab size=0x%llx requested=0x%llx ptr=%p",
                  className,
                  (unsigned long long)smallSize,
                  (unsigned long long)size,
                  small);
        return small;
    }

    const size_t mappedSize = ampr_round_up_page_size(size);
    if (mappedSize == SIZE_MAX) {
        AMPR_CRITICAL_LOGF("apr.index alloc fail reason=size-overflow size=0x%llx",
                           (unsigned long long)size);
        return nullptr;
    }
    size_t poolSize = 0;
    void* pool = nullptr;
    const bool poolUsable = mayCreatePool
        ? ampr_internal_amm_pool_ensure(mappedSize, className)
        : ampr_internal_amm_pool_ready_has_capacity(mappedSize);
    if (poolUsable) {
        pool = ampr_internal_amm_pool_alloc(mappedSize, &poolSize, className, false);
    }
    if (pool) {
        ampr_sdk_cpu_memory_note_alloc(memoryClass, poolSize);
        AMPR_LOGF("mem.sdk_cpu.alloc ok class=%s owner=pool size=0x%llx requested=0x%llx ptr=%p",
                  className,
                  (unsigned long long)poolSize,
                  (unsigned long long)size,
                  pool);
        return pool;
    }

    AMPR_CRITICAL_LOGF("mem.sdk_cpu.alloc fail class=%s size=0x%llx mappedSize=0x%llx fallback=none",
              className,
              (unsigned long long)size,
              (unsigned long long)mappedSize);
    return nullptr;
}

static void ampr_release_sdk_cpu_memory(
    void* base,
    size_t size,
    AmprSharedSdkCpuMemoryClass memoryClass = AmprSharedSdkCpuMemoryClass::Persistent) {
    if (!base || size == 0) return;
    const size_t mappedSize = ampr_round_up_page_size(size);
    if (mappedSize == SIZE_MAX) {
        AMPR_LOGF("mem.sdk_cpu.release skip class=%s base=%p size=0x%llx reason=size-overflow",
                  ampr_sdk_cpu_memory_class_name(memoryClass),
                  base,
                  (unsigned long long)size);
        return;
    }
    size_t smallSize = 0;
    if (ampr_small_slab_free(base, ampr_sdk_cpu_memory_class_name(memoryClass), &smallSize)) {
        if (smallSize != 0) {
            ampr_sdk_cpu_memory_note_free(memoryClass, smallSize);
        }
        return;
    }
    if (ampr_internal_amm_pool_free(base, ampr_sdk_cpu_memory_class_name(memoryClass))) {
        ampr_sdk_cpu_memory_note_free(memoryClass, mappedSize);
        return;
    }
    AMPR_LOGF("apr.index release skip base=%p size=0x%llx reason=unknown-owner",
              base, (unsigned long long)size);
}

class AmprSdkCpuScratchBuffer {
public:
    AmprSdkCpuScratchBuffer() = default;
    explicit AmprSdkCpuScratchBuffer(size_t size,
                                     AmprSharedSdkCpuMemoryClass memoryClass = AmprSharedSdkCpuMemoryClass::Transient) {
        (void)allocate(size, memoryClass);
    }
    ~AmprSdkCpuScratchBuffer() {
        reset();
    }

    AmprSdkCpuScratchBuffer(const AmprSdkCpuScratchBuffer&) = delete;
    AmprSdkCpuScratchBuffer& operator=(const AmprSdkCpuScratchBuffer&) = delete;

    bool allocate(size_t size,
                  AmprSharedSdkCpuMemoryClass memoryClass = AmprSharedSdkCpuMemoryClass::Transient) {
        reset();
        if (size == 0) {
            return false;
        }
        memoryClass_ = memoryClass;
        base_ = ampr_alloc_sdk_cpu_memory(size, memoryClass_);
        if (!base_) {
            return false;
        }
        size_ = size;
        return true;
    }

    void reset() {
        if (base_) {
            ampr_release_sdk_cpu_memory(base_,
                                        size_,
                                        memoryClass_);
        }
        base_ = nullptr;
        size_ = 0;
        memoryClass_ = AmprSharedSdkCpuMemoryClass::Transient;
    }

    char* data() {
        return static_cast<char*>(base_);
    }

    const char* data() const {
        return static_cast<const char*>(base_);
    }

    bool valid() const {
        return base_ != nullptr;
    }

private:
    void* base_{nullptr};
    size_t size_{0};
    AmprSharedSdkCpuMemoryClass memoryClass_{AmprSharedSdkCpuMemoryClass::Transient};
};

class AmprIndexPathStack {
public:
    AmprIndexPathStack() = default;
    ~AmprIndexPathStack() {
        reset();
    }

    AmprIndexPathStack(const AmprIndexPathStack&) = delete;
    AmprIndexPathStack& operator=(const AmprIndexPathStack&) = delete;

    bool push(const char* path) {
        if (!path) return false;
        const size_t len = std::strlen(path);
        if (len == 0 || len >= kAmprIndexMaxPath) {
            return false;
        }
        if (count_ == capacity_ && !grow(capacity_ == 0 ? 256u : capacity_ * 2u)) {
            return false;
        }
        char* slot = slot_at(count_);
        std::memcpy(slot, path, len + 1u);
        ++count_;
        return true;
    }

    bool pop(char* out, size_t outSize) {
        if (!out || outSize == 0 || count_ == 0) return false;
        --count_;
        const char* slot = slot_at(count_);
        const size_t len = std::strlen(slot);
        if (len + 1u > outSize) {
            out[0] = '\0';
            return false;
        }
        std::memcpy(out, slot, len + 1u);
        return true;
    }

    bool empty() const {
        return count_ == 0;
    }

    size_t size() const {
        return count_;
    }

private:
    static constexpr size_t kSlotSize = kAmprIndexMaxPath;

    char* slot_at(size_t index) const {
        return static_cast<char*>(base_) + index * kSlotSize;
    }

    bool grow(size_t newCapacity) {
        if (newCapacity <= capacity_ || newCapacity > SIZE_MAX / kSlotSize) {
            return false;
        }
        const size_t newBytes = newCapacity * kSlotSize;
        void* newBase = ampr_alloc_sdk_cpu_memory(newBytes,
                                                  AmprSharedSdkCpuMemoryClass::Transient);
        if (!newBase) {
            AMPR_CRITICAL_LOGF("apr.index scan.dir-stack alloc fail capacity=%zu bytes=0x%llx",
                               newCapacity,
                               (unsigned long long)newBytes);
            return false;
        }
        if (base_ && count_ != 0) {
            std::memcpy(newBase, base_, count_ * kSlotSize);
        }
        release();
        base_ = newBase;
        bytes_ = newBytes;
        capacity_ = newCapacity;
        return true;
    }

    void release() {
        if (base_) {
            ampr_release_sdk_cpu_memory(base_,
                                        bytes_,
                                        AmprSharedSdkCpuMemoryClass::Transient);
        }
        base_ = nullptr;
        bytes_ = 0;
        capacity_ = 0;
    }

    void reset() {
        count_ = 0;
        release();
    }

    void* base_{nullptr};
    size_t bytes_{0};
    size_t capacity_{0};
    size_t count_{0};
};

static void clear_compact_file_index_locked(FileIndexState& idx) {
    if (idx.compactMapBase) {
        ampr_release_sdk_cpu_memory(idx.compactMapBase,
                                    idx.compactMapSize);
        idx.compactMapBase = nullptr;
        idx.compactMapSize = 0;
    }
    idx.compactEntries = nullptr;
    idx.compactEntryCount = 0;
    idx.compactPathBlob = nullptr;
    idx.compactHashSlots = nullptr;
    idx.compactHashMask = 0;
    idx.compactPathBlobSize = 0;
    idx.compactAvailable = false;
}

static void move_compact_file_index_locked(FileIndexState& dst, FileIndexState& src) {
    clear_compact_file_index_locked(dst);
    dst.compactEntries = src.compactEntries;
    dst.compactEntryCount = src.compactEntryCount;
    dst.compactPathBlob = src.compactPathBlob;
    dst.compactHashSlots = src.compactHashSlots;
    dst.compactHashMask = src.compactHashMask;
    dst.compactMapBase = src.compactMapBase;
    dst.compactMapSize = src.compactMapSize;
    dst.compactPathBlobSize = src.compactPathBlobSize;
    dst.compactAvailable = src.compactAvailable;

    src.compactEntries = nullptr;
    src.compactEntryCount = 0;
    src.compactPathBlob = nullptr;
    src.compactHashSlots = nullptr;
    src.compactHashMask = 0;
    src.compactMapBase = nullptr;
    src.compactMapSize = 0;
    src.compactPathBlobSize = 0;
    src.compactAvailable = false;
}

static const char* compact_index_path_ptr(const FileIndexState& idx, const CompactFileIndexEntry& e) {
    const uint64_t begin = e.pathOffset;
    const uint64_t end = begin + e.pathLength;
    if (!idx.compactPathBlob || begin >= idx.compactPathBlobSize || end >= idx.compactPathBlobSize) {
        return nullptr;
    }
    const char* path = idx.compactPathBlob + begin;
    if (path[e.pathLength] != '\0') {
        return nullptr;
    }
    return path;
}

static bool compact_index_copy_path(const FileIndexState& idx,
                                    const CompactFileIndexEntry& e,
                                    char* dst,
                                    size_t dstSize) {
    if (!dst || dstSize == 0) return false;
    dst[0] = '\0';
    if ((size_t)e.pathLength + 1u > dstSize) return false;

    if (const char* path = compact_index_path_ptr(idx, e)) {
        std::memcpy(dst, path, (size_t)e.pathLength + 1u);
        return true;
    }

    return false;
}

static uint64_t compact_index_hash_key(const char* path) {
    uint64_t hash = 1469598103934665603ull;
    const unsigned char* p = reinterpret_cast<const unsigned char*>(path ? path : "");
    while (*p) {
        unsigned char ch = *p++;
        if (ch == '\\') ch = '/';
        ch = static_cast<unsigned char>(ampr_ascii_lower(static_cast<char>(ch)));
        hash ^= ch;
        hash *= 1099511628211ull;
    }
    return hash ? hash : 1ull;
}

static bool compact_index_hash_slot_count(size_t entryCount, size_t* outSlots) {
    if (!outSlots || entryCount == 0 || entryCount >= SCE_AMPR_APR_FILEID_INVALID) {
        return false;
    }
    size_t slots = 2;
    const size_t target = entryCount > (SIZE_MAX / 2u) ? SIZE_MAX : entryCount * 2u;
    while (slots < target) {
        if (slots > (SIZE_MAX / 2u)) {
            return false;
        }
        slots <<= 1u;
    }
    *outSlots = slots;
    return true;
}

static bool compact_index_hash_insert(CompactFileIndexHashSlot* slots,
                                      size_t mask,
                                      uint64_t hash,
                                      uint32_t indexPlusOne,
                                      size_t* outProbeSteps,
                                      size_t* outMaxProbe) {
    if (!slots || mask == 0 || indexPlusOne == 0 || indexPlusOne == SCE_AMPR_APR_FILEID_INVALID) {
        return false;
    }
    size_t pos = (size_t)hash & mask;
    bool duplicateHash = false;
    size_t probe = 0;
    while (slots[pos].indexPlusOne != 0) {
        if (slots[pos].hash == hash) {
            slots[pos].reserved |= kCompactIndexHashDuplicate;
            duplicateHash = true;
        }
        pos = (pos + 1u) & mask;
        ++probe;
        if (probe > mask) return false;
    }
    slots[pos].hash = hash;
    slots[pos].indexPlusOne = indexPlusOne;
    slots[pos].reserved = duplicateHash ? kCompactIndexHashDuplicate : 0u;
    if (outProbeSteps) *outProbeSteps += probe;
    if (outMaxProbe && *outMaxProbe < probe) *outMaxProbe = probe;
    return true;
}

static bool ampr_sce_write_all(int fd, const void* data, size_t size) {
    const char* p = static_cast<const char*>(data);
    size_t done = 0;
    while (done < size) {
        const ssize_t written = sceKernelWrite(fd, p + done, size - done);
        if (written <= 0) {
            return false;
        }
        done += static_cast<size_t>(written);
    }
    return true;
}

class AmprSceBufferedWriter {
public:
    AmprSceBufferedWriter() = default;
    explicit AmprSceBufferedWriter(int fd) {
        (void)open(fd);
    }
    ~AmprSceBufferedWriter() {
        reset();
    }

    AmprSceBufferedWriter(const AmprSceBufferedWriter&) = delete;
    AmprSceBufferedWriter& operator=(const AmprSceBufferedWriter&) = delete;

    bool open(int fd) {
        reset();
        fd_ = fd;
        if (fd_ < 0 || !buffer_.allocate(kBufferSize)) {
            fd_ = -1;
            return false;
        }
        return true;
    }

    void reset() {
        buffer_.reset();
        used_ = 0;
        fd_ = -1;
    }

    bool valid() const {
        return fd_ >= 0 && buffer_.valid();
    }

    bool write(const void* data, size_t size) {
        if (!valid() || (!data && size != 0)) {
            return false;
        }
        const char* p = static_cast<const char*>(data);
        while (size != 0) {
            if (used_ == kBufferSize && !flush()) {
                return false;
            }
            if (used_ == 0 && size >= kBufferSize) {
                if (!ampr_sce_write_all(fd_, p, size)) {
                    return false;
                }
                return true;
            }
            const size_t take = std::min<size_t>(kBufferSize - used_, size);
            std::memcpy(buffer_.data() + used_, p, take);
            used_ += take;
            p += take;
            size -= take;
        }
        return true;
    }

    bool flush() {
        if (!valid()) {
            return false;
        }
        if (used_ == 0) {
            return true;
        }
        const bool ok = ampr_sce_write_all(fd_, buffer_.data(), used_);
        if (ok) {
            used_ = 0;
        }
        return ok;
    }

private:
    static constexpr size_t kBufferSize = 256 * 1024;
    int fd_{-1};
    AmprSdkCpuScratchBuffer buffer_;
    size_t used_{0};
};

class AmprRuntimeIndexBuilder {
public:
    bool open() {
        (void)ampr_real_sceKernelUnlink(kAmprApp0IndexTempPath);
        AMPR_LOGF("apr.index build.memory open ok tmp=%s", kAmprApp0IndexTempPath);
        return true;
    }

    bool add_file(const char* path, size_t size, int64_t mtime) {
        if (!path) return false;
        const size_t pathLen = std::strlen(path);
        if (pathLen == 0 || pathLen > UINT32_MAX || pathBytes_ > UINT32_MAX ||
            pathBytes_ + (uint64_t)pathLen + 1u > UINT32_MAX ||
            entryCount_ >= (uint64_t)SCE_AMPR_APR_FILEID_INVALID - 1ull) {
            AMPR_CRITICAL_LOGF("apr.index build.add fail path=%s reason=format-limit entries=%llu pathBytes=0x%llx len=0x%llx",
                      path,
                      (unsigned long long)entryCount_,
                      (unsigned long long)pathBytes_,
                      (unsigned long long)pathLen);
            failed_ = true;
            return false;
        }

        if (!ensure_record_capacity((size_t)entryCount_ + 1u) ||
            !ensure_path_capacity((size_t)pathBytes_ + pathLen + 1u)) {
            AMPR_CRITICAL_LOGF("apr.index build.add fail path=%s reason=memory entries=%llu pathBytes=0x%llx len=0x%llx",
                      path,
                      (unsigned long long)entryCount_,
                      (unsigned long long)pathBytes_,
                      (unsigned long long)pathLen);
            failed_ = true;
            return false;
        }

        CompactFileIndexEntry& ce = records_[(size_t)entryCount_];
        ce.pathOffset = static_cast<uint32_t>(pathBytes_);
        ce.pathLength = static_cast<uint32_t>(pathLen);
        ce.size = size;
        ce.mtime = mtime;
        std::memcpy(paths_ + (size_t)pathBytes_, path, pathLen + 1u);

        ++entryCount_;
        pathBytes_ += (uint64_t)pathLen + 1u;
        if (maxPathLen_ < pathLen) {
            maxPathLen_ = pathLen;
        }
        return true;
    }

    bool save_final() {
        if (failed_ || entryCount_ == 0) {
            AMPR_CRITICAL_LOGF("apr.index save skip reason=build-state failed=%u entries=%llu",
                      failed_ ? 1u : 0u, (unsigned long long)entryCount_);
            release_buffers();
            return false;
        }

        size_t hashSlotCount = 0;
        if (!compact_index_hash_slot_count((size_t)entryCount_, &hashSlotCount) ||
            hashSlotCount > UINT32_MAX ||
            hashSlotCount > SIZE_MAX / sizeof(CompactFileIndexHashSlot)) {
            AMPR_CRITICAL_LOGF("apr.index save fail reason=hash-size entries=%llu pathBytes=0x%llx",
                      (unsigned long long)entryCount_, (unsigned long long)pathBytes_);
            release_buffers();
            return false;
        }

        const uint64_t recordsBytes = entryCount_ * (uint64_t)sizeof(CompactFileIndexEntry);
        const uint64_t pathFileOffset = (uint64_t)sizeof(CompactFileIndexHeader) + recordsBytes;
        const uint64_t hashOffset = ampr_align_up_u64(pathFileOffset + pathBytes_, alignof(CompactFileIndexHashSlot));
        const uint64_t hashBytes = (uint64_t)hashSlotCount * (uint64_t)sizeof(CompactFileIndexHashSlot);
        const uint64_t fileBytes = hashOffset + hashBytes;
        if (recordsBytes / sizeof(CompactFileIndexEntry) != entryCount_ ||
            hashBytes / sizeof(CompactFileIndexHashSlot) != hashSlotCount ||
            hashOffset < pathFileOffset ||
            fileBytes < hashOffset ||
            fileBytes > (uint64_t)SIZE_MAX) {
            AMPR_CRITICAL_LOGF("apr.index save fail reason=size-overflow entries=%llu pathBytes=0x%llx hashSlots=%zu",
                      (unsigned long long)entryCount_, (unsigned long long)pathBytes_, hashSlotCount);
            release_buffers();
            return false;
        }

        const size_t imageMapBytes = ampr_round_up_page_size((size_t)fileBytes);
        if (imageMapBytes == SIZE_MAX) {
            AMPR_CRITICAL_LOGF("apr.index save fail reason=image-size-overflow entries=%llu bytes=0x%llx",
                      (unsigned long long)entryCount_, (unsigned long long)fileBytes);
            release_buffers();
            return false;
        }
        ampr_log_kernel_memory_status("apr.index.image.before", imageMapBytes);
        void* imageMap = ampr_alloc_sdk_cpu_memory(imageMapBytes,
                                                   AmprSharedSdkCpuMemoryClass::Transient);
        if (!imageMap) {
            AMPR_CRITICAL_LOGF("apr.index save fail reason=image-alloc entries=%llu bytes=0x%llx",
                      (unsigned long long)entryCount_, (unsigned long long)fileBytes);
            release_buffers();
            return false;
        }
        std::memset(imageMap, 0, imageMapBytes);
        char* image = static_cast<char*>(imageMap);

        CompactFileIndexHeader header{};
        std::memcpy(header.magic, kAmprIndexMagic, sizeof(header.magic));
        header.version = kAmprIndexVersion;
        header.entrySize = sizeof(CompactFileIndexEntry);
        header.entryCount = entryCount_;
        header.pathBytes = pathBytes_;
        header.hashOffset = hashOffset;
        header.hashSlotSize = sizeof(CompactFileIndexHashSlot);
        header.hashSlotCount = static_cast<uint32_t>(hashSlotCount);
        std::memcpy(image, &header, sizeof(header));
        std::memcpy(image + sizeof(header), records_, (size_t)recordsBytes);
        std::memcpy(image + pathFileOffset, paths_, (size_t)pathBytes_);

        CompactFileIndexHashSlot* hashSlots =
            reinterpret_cast<CompactFileIndexHashSlot*>(image + (size_t)hashOffset);

        bool ok = true;
        size_t probeSteps = 0;
        size_t maxProbe = 0;
        for (uint64_t i = 0; ok && i < entryCount_; ++i) {
            const CompactFileIndexEntry& ce = records_[(size_t)i];
            if (ce.pathLength > maxPathLen_ ||
                ce.pathOffset + (uint64_t)ce.pathLength + 1u > pathBytes_) {
                AMPR_CRITICAL_LOGF("apr.index save fail reason=record idx=%llu pathOff=0x%x pathLen=0x%x",
                          (unsigned long long)i, ce.pathOffset, ce.pathLength);
                ok = false;
                break;
            }
            const char* path = paths_ + ce.pathOffset;
            if (path[ce.pathLength] != '\0') {
                AMPR_CRITICAL_LOGF("apr.index save fail reason=path idx=%llu pathOff=0x%x pathLen=0x%x",
                          (unsigned long long)i, ce.pathOffset, ce.pathLength);
                ok = false;
                break;
            }
            const uint64_t hash = compact_index_hash_key(path);
            ok = compact_index_hash_insert(hashSlots,
                                           hashSlotCount - 1u,
                                           hash,
                                           static_cast<uint32_t>(i + 1u),
                                           &probeSteps,
                                           &maxProbe);
        }
        AMPR_LOGF("apr.index save.plan entries=%llu pathBytes=0x%llx records=0x%llx hashSlots=%zu hashBytes=0x%llx imageBytes=0x%llx probeSteps=%zu maxProbe=%zu memory=1",
                  (unsigned long long)entryCount_,
                  (unsigned long long)pathBytes_,
                  (unsigned long long)recordsBytes,
                  hashSlotCount,
                  (unsigned long long)hashBytes,
                  (unsigned long long)fileBytes,
                  probeSteps,
                  maxProbe);
        if (!ok) {
            ampr_release_sdk_cpu_memory(imageMap,
                                        imageMapBytes,
                                        AmprSharedSdkCpuMemoryClass::Transient);
            release_buffers();
            return false;
        }

        const int outFd = ampr_real_sceKernelOpen(kAmprApp0IndexTempPath,
                                                  SCE_KERNEL_O_WRONLY | SCE_KERNEL_O_CREAT | SCE_KERNEL_O_TRUNC,
                                                  SCE_KERNEL_S_IRWU);
        if (outFd < 0) {
            AMPR_LOGF("apr.index save skip path=%s rc=0x%x", kAmprApp0IndexTempPath, outFd);
            ampr_release_sdk_cpu_memory(imageMap,
                                        imageMapBytes,
                                        AmprSharedSdkCpuMemoryClass::Transient);
            release_buffers();
            return false;
        }

        AmprSceBufferedWriter writer(outFd);
        ok = writer.valid() && writer.write(image, (size_t)fileBytes) && writer.flush();
        const int closeRc = sceKernelClose(outFd);
        if (closeRc < 0) ok = false;

        ampr_release_sdk_cpu_memory(imageMap,
                                    imageMapBytes,
                                    AmprSharedSdkCpuMemoryClass::Transient);

        if (!ok) {
            (void)ampr_real_sceKernelUnlink(kAmprApp0IndexTempPath);
            AMPR_CRITICAL_LOGF("apr.index save fail path=%s closeRc=0x%x", kAmprApp0IndexTempPath, closeRc);
            release_buffers();
            return false;
        }
        int renameRc = ampr_real_sceKernelRename(kAmprApp0IndexTempPath, kAmprApp0IndexPath);
        if (renameRc < 0) {
            // Fallback for filesystems that do not replace an existing target:
            // retain the old index as a backup until the new rename succeeds.
            // If the destination is absent, a stale backup may be the only
            // recoverable copy and must remain untouched after a failed install.
            SceKernelStat destinationStat{};
            const bool destinationExists =
                ampr_real_sceKernelStat(kAmprApp0IndexPath, &destinationStat) == 0;
            bool oldMoved = false;
            if (destinationExists) {
                (void)ampr_real_sceKernelUnlink(kAmprApp0IndexBackupPath);
                oldMoved = ampr_real_sceKernelRename(
                    kAmprApp0IndexPath, kAmprApp0IndexBackupPath) >= 0;
            }
            renameRc = ampr_real_sceKernelRename(kAmprApp0IndexTempPath, kAmprApp0IndexPath);
            if (renameRc < 0 && oldMoved) {
                const int restoreRc =
                    ampr_real_sceKernelRename(kAmprApp0IndexBackupPath, kAmprApp0IndexPath);
                if (restoreRc < 0) {
                    AMPR_CRITICAL_LOGF("apr.index save restore fail backup=%s dst=%s rc=0x%x",
                                       kAmprApp0IndexBackupPath,
                                       kAmprApp0IndexPath,
                                       restoreRc);
                }
            } else if (renameRc >= 0 && oldMoved) {
                (void)ampr_real_sceKernelUnlink(kAmprApp0IndexBackupPath);
            }
        }
        if (renameRc < 0) {
            (void)ampr_real_sceKernelUnlink(kAmprApp0IndexTempPath);
            AMPR_CRITICAL_LOGF("apr.index save rename fail tmp=%s dst=%s rc=0x%x",
                      kAmprApp0IndexTempPath, kAmprApp0IndexPath, renameRc);
            release_buffers();
            return false;
        }
        // A previous interrupted replacement may have left a backup behind.
        // Once the new destination is installed, that stale recovery copy is no
        // longer needed and must not accumulate across successful rebuilds.
        (void)ampr_real_sceKernelUnlink(kAmprApp0IndexBackupPath);

        AMPR_LOGF("apr.index saved path=%s format=AMPRIDX3 entries=%llu pathBytes=0x%llx hashSlots=%zu hashOffset=0x%llx memory=1",
                  kAmprApp0IndexPath,
                  (unsigned long long)entryCount_,
                  (unsigned long long)pathBytes_,
                  hashSlotCount,
                  (unsigned long long)hashOffset);
        release_buffers();
        return true;
    }

    uint64_t entry_count() const { return entryCount_; }
    uint64_t path_bytes() const { return pathBytes_; }

    ~AmprRuntimeIndexBuilder() {
        release_buffers();
    }

private:
    bool ensure_record_capacity(size_t minCapacity) {
        if (minCapacity <= recordCapacity_) return true;
        size_t newCapacity = recordCapacity_ != 0 ? recordCapacity_ : 4096u;
        while (newCapacity < minCapacity) {
            if (newCapacity > SIZE_MAX / 2u) return false;
            newCapacity *= 2u;
        }
        if (newCapacity > SIZE_MAX / sizeof(CompactFileIndexEntry)) return false;
        const size_t newBytes = newCapacity * sizeof(CompactFileIndexEntry);
        void* newBase = ampr_alloc_sdk_cpu_memory(newBytes,
                                                  AmprSharedSdkCpuMemoryClass::Transient);
        if (!newBase) {
            AMPR_CRITICAL_LOGF("apr.index build.records alloc fail capacity=%zu bytes=0x%llx",
                               newCapacity, (unsigned long long)newBytes);
            return false;
        }
        if (records_ && entryCount_ != 0) {
            std::memcpy(newBase, records_, (size_t)entryCount_ * sizeof(CompactFileIndexEntry));
        }
        release_records();
        records_ = static_cast<CompactFileIndexEntry*>(newBase);
        recordBytes_ = newBytes;
        recordCapacity_ = newCapacity;
        return true;
    }

    bool ensure_path_capacity(size_t minBytes) {
        if (minBytes <= pathCapacity_) return true;
        size_t newCapacity = pathCapacity_ != 0 ? pathCapacity_ : 1024u * 1024u;
        while (newCapacity < minBytes) {
            if (newCapacity > SIZE_MAX / 2u) return false;
            newCapacity *= 2u;
        }
        void* newBase = ampr_alloc_sdk_cpu_memory(newCapacity,
                                                  AmprSharedSdkCpuMemoryClass::Transient);
        if (!newBase) {
            AMPR_CRITICAL_LOGF("apr.index build.paths alloc fail bytes=0x%llx",
                               (unsigned long long)newCapacity);
            return false;
        }
        if (paths_ && pathBytes_ != 0) {
            std::memcpy(newBase, paths_, (size_t)pathBytes_);
        }
        release_paths();
        paths_ = static_cast<char*>(newBase);
        pathCapacity_ = newCapacity;
        return true;
    }

    void release_records() {
        if (!records_) return;
        ampr_release_sdk_cpu_memory(records_,
                                    recordBytes_,
                                    AmprSharedSdkCpuMemoryClass::Transient);
        records_ = nullptr;
        recordBytes_ = 0;
        recordCapacity_ = 0;
    }

    void release_paths() {
        if (!paths_) return;
        ampr_release_sdk_cpu_memory(paths_,
                                    pathCapacity_,
                                    AmprSharedSdkCpuMemoryClass::Transient);
        paths_ = nullptr;
        pathCapacity_ = 0;
    }

    void release_buffers() {
        release_records();
        release_paths();
    }

    CompactFileIndexEntry* records_{nullptr};
    size_t recordBytes_{0};
    size_t recordCapacity_{0};
    char* paths_{nullptr};
    size_t pathCapacity_{0};
    uint64_t entryCount_{0};
    uint64_t pathBytes_{0};
    size_t maxPathLen_{0};
    bool failed_{false};
};

static bool ampr_path_name_is_dot_or_dotdot(const char* name, size_t nameLen) {
    return (nameLen == 1u && name[0] == '.') ||
           (nameLen == 2u && name[0] == '.' && name[1] == '.');
}

static bool ampr_path_has_unsupported_index_char(const char* path) {
    if (!path) return true;
    for (const char* p = path; *p; ++p) {
        if (*p == '\t' || *p == '\n' || *p == '\r') {
            return true;
        }
    }
    return false;
}

static bool ampr_join_dirent_path(const char* dir,
                                  const char* name,
                                  size_t nameLen,
                                  char* out,
                                  size_t outSize) {
    if (!dir || !name || !out || outSize == 0) return false;
    const size_t dirLen = std::strlen(dir);
    const bool needsSlash = dirLen != 0 && dir[dirLen - 1u] != '/';
    if (dirLen == 0 || nameLen == 0 ||
        dirLen + (needsSlash ? 1u : 0u) + nameLen + 1u > outSize) {
        if (outSize != 0) out[0] = '\0';
        return false;
    }
    std::memcpy(out, dir, dirLen);
    size_t used = dirLen;
    if (needsSlash) {
        out[used++] = '/';
    }
    std::memcpy(out + used, name, nameLen);
    used += nameLen;
    out[used] = '\0';
    return true;
}

[[maybe_unused]] __attribute__((noinline)) static void build_app0_index_locked(FileIndexState& idx) {
    idx.available = false;

    if (!ampr_internal_amm_pool_prepare_static_storage("app0-index.build")) {
        AMPR_CRITICAL_LOGF("apr.index build fail reason=static-pool root=%s", kAmprApp0Root);
        return;
    }

    AmprRuntimeIndexBuilder builder;
    if (!builder.open()) {
        AMPR_CRITICAL_LOGF("apr.index build fail reason=builder-open root=%s", kAmprApp0Root);
        return;
    }

    AmprIndexPathStack dirs;
    if (!dirs.push(kAmprApp0Root)) {
        AMPR_CRITICAL_LOGF("apr.index build fail reason=dir-stack-root root=%s", kAmprApp0Root);
        return;
    }
    auto& workspace = g_app0_index_build_workspace;
    auto& indexKey = workspace.indexKey;
    auto& tempIndexKey = workspace.tempIndexKey;
    auto& backupIndexKey = workspace.backupIndexKey;
    auto& dir = workspace.dir;
    auto& path = workspace.path;
    auto& pathKey = workspace.pathKey;
    if (!normalize_app0_path_key(kAmprApp0IndexPath, indexKey, sizeof(indexKey)) ||
        !normalize_app0_path_key(kAmprApp0IndexTempPath, tempIndexKey, sizeof(tempIndexKey)) ||
        !normalize_app0_path_key(kAmprApp0IndexBackupPath, backupIndexKey, sizeof(backupIndexKey))) {
        AMPR_CRITICAL_LOGF("apr.index build fail reason=internal-temp-key");
        return;
    }

    size_t dirCount = 0;
    (void)dirCount;
    size_t fileCount = 0;
    size_t nextProgressFileCount = 1000;
    while (!dirs.empty()) {
        if (!dirs.pop(dir, sizeof(dir))) {
            AMPR_CRITICAL_LOGF("apr.index scan.dir-stack pop fail pendingDirs=%zu", dirs.size());
            break;
        }
        ++dirCount;

        int fd = ampr_real_sceKernelOpen(dir, SCE_KERNEL_O_RDONLY | SCE_KERNEL_O_DIRECTORY, 0);
        if (fd < 0) {
            AMPR_CRITICAL_LOGF("apr.index scan.open-dir fail path=%s rc=0x%x", dir, fd);
            continue;
        }

        size_t dentsSize = 16 * 1024;
        struct stat dirStat{};
        const int fstatRc = sceKernelFstat(fd, &dirStat);
        if (fstatRc == 0 && dirStat.st_blksize > 0) {
            dentsSize = std::max(dentsSize, static_cast<size_t>(dirStat.st_blksize));
        }
        AmprSdkCpuScratchBuffer dents(dentsSize);
        if (!dents.valid()) {
            AMPR_CRITICAL_LOGF("apr.index scan.getdents alloc fail path=%s size=0x%llx fstatRc=0x%x blksize=0x%llx",
                      dir, (unsigned long long)dentsSize, fstatRc,
                      (unsigned long long)(fstatRc == 0 ? dirStat.st_blksize : 0));
            (void)sceKernelClose(fd);
            continue;
        }

        for (;;) {
            const int nread = sceKernelGetdents(fd, dents.data(), static_cast<int>(dentsSize));
            if (nread < 0) {
                AMPR_CRITICAL_LOGF("apr.index scan.getdents fail path=%s rc=0x%x size=0x%llx fstatRc=0x%x blksize=0x%llx",
                          dir, nread, (unsigned long long)dentsSize, fstatRc,
                          (unsigned long long)(fstatRc == 0 ? dirStat.st_blksize : 0));
                break;
            }
            if (static_cast<size_t>(nread) > dentsSize) {
                AMPR_LOGF("apr.index scan.getdents malformed path=%s bytes=%d buffer=0x%llx",
                          dir, nread, (unsigned long long)dentsSize);
                break;
            }
            if (nread == 0) break;

            char* p = dents.data();
            char* end = dents.data() + nread;
            static constexpr size_t kDirentHeaderSize = offsetof(struct dirent, d_name);
            while (p + kDirentHeaderSize <= end) {
                struct dirent* ent = reinterpret_cast<struct dirent*>(p);
                const size_t remaining = static_cast<size_t>(end - p);
                if (ent->d_reclen < kDirentHeaderSize + 1 || ent->d_reclen > remaining) {
                    AMPR_LOGF("apr.index scan.getdents malformed path=%s reason=reclen reclen=%u left=%llu",
                              dir, (unsigned)ent->d_reclen, (unsigned long long)remaining);
                    break;
                }
                if (ent->d_namlen != 0 && ent->d_namlen > ent->d_reclen - kDirentHeaderSize - 1u) {
                    AMPR_LOGF("apr.index scan.getdents malformed path=%s reason=namlen reclen=%u namlen=%u left=%llu",
                              dir, (unsigned)ent->d_reclen, (unsigned)ent->d_namlen,
                              (unsigned long long)remaining);
                    break;
                }
                p += ent->d_reclen;

                size_t nameLen = ent->d_namlen;
                if (nameLen == 0) continue;
                if (ent->d_fileno == 0) continue;
                if (ampr_path_name_is_dot_or_dotdot(ent->d_name, nameLen)) continue;

                if (!ampr_join_dirent_path(dir, ent->d_name, nameLen, path, sizeof(path))) {
                    AMPR_LOGF("apr.index scan.skip unsupported-path path=%s nameLen=0x%llx reason=too-long",
                              dir, (unsigned long long)nameLen);
                    continue;
                }
                if (ampr_path_has_unsupported_index_char(path)) {
                    AMPR_LOGF("apr.index scan.skip unsupported-path path=%s", path);
                    continue;
                }

                if (!normalize_app0_path_key(path, pathKey, sizeof(pathKey))) {
                    AMPR_LOGF("apr.index scan.skip unsupported-path path=%s reason=key-too-long", path);
                    continue;
                }
                if (compare_index_path_key(pathKey, indexKey) == 0 ||
                    compare_index_path_key(pathKey, tempIndexKey) == 0 ||
                    compare_index_path_key(pathKey, backupIndexKey) == 0) {
                    continue;
                }

                const uint8_t dtype = ent->d_type;
                if (dtype == DT_DIR) {
                    if (!dirs.push(path)) {
                        AMPR_CRITICAL_LOGF("apr.index scan.dir-stack push fail path=%s pendingDirs=%zu",
                                           path, dirs.size());
                    }
                    continue;
                }
                if (dtype != DT_REG && dtype != DT_UNKNOWN) {
                    continue;
                }

                struct stat st{};
                if (ampr_real_sceKernelStat(path, &st) != 0) {
                    AMPR_CRITICAL_LOGF("apr.index scan.stat fail path=%s dtype=%u errno=%d",
                              path, (unsigned)dtype, errno);
                    continue;
                }
                if (dtype == DT_UNKNOWN && S_ISDIR(st.st_mode)) {
                    if (!dirs.push(path)) {
                        AMPR_CRITICAL_LOGF("apr.index scan.dir-stack push fail path=%s pendingDirs=%zu",
                                           path, dirs.size());
                    }
                    continue;
                }
                if (!S_ISREG(st.st_mode)) {
                    continue;
                }

                if (builder.add_file(path,
                                     static_cast<size_t>(st.st_size),
                                     static_cast<int64_t>(st.st_mtime))) {
                    ++fileCount;
                }
                if (fileCount >= nextProgressFileCount) {
                    AMPR_LOGF("apr.index scan.progress dirs=%zu files=%zu pendingDirs=%zu entries=%llu pathBytes=0x%llx memory=1",
                              dirCount, fileCount, dirs.size(),
                              (unsigned long long)builder.entry_count(),
                              (unsigned long long)builder.path_bytes());
                    nextProgressFileCount += 1000;
                }
            }
        }
        (void)sceKernelClose(fd);
    }

    AMPR_LOGF("apr.index built root=%s dirs=%zu files=%zu entries=%llu pathBytes=0x%llx memory=1",
              kAmprApp0Root, dirCount, fileCount,
              (unsigned long long)builder.entry_count(),
              (unsigned long long)builder.path_bytes());
    const bool saved = builder.save_final();
    ampr_sdk_cpu_memory_log_summary(saved ? "apr.index.build.saved" : "apr.index.build.save-failed");
    ampr_internal_amm_pool_log_summary(saved ? "apr.index.build.saved" : "apr.index.build.save-failed");
    if (saved) {
        AMPR_LOGF("apr.index reload enter reason=post-build entries=%llu pathBytes=0x%llx",
                  (unsigned long long)builder.entry_count(),
                  (unsigned long long)builder.path_bytes());
        const CompactIndexLoadResult reloadResult = load_compact_app0_index_locked(idx);
        if (reloadResult == CompactIndexLoadResult::Loaded) {
            AMPR_LOGF("apr.index reload ok reason=post-build compactEntries=%zu",
                      idx.compactEntryCount);
            ampr_sdk_cpu_memory_log_summary("apr.index.reload.loaded");
            ampr_internal_amm_pool_log_summary("apr.index.reload.loaded");
        } else {
            idx.available = false;
            AMPR_CRITICAL_LOGF("apr.index reload fail reason=post-build result=%s no-heap-fallback entries=%llu",
                      compact_index_load_result_name(reloadResult),
                      (unsigned long long)builder.entry_count());
        }
    }
}

static bool pread_exact_logged(int fd, void* dst, size_t size, off_t offset, const char* label) {
    (void)label;
    char* out = static_cast<char*>(dst);
    size_t done = 0;
    while (done < size) {
        const size_t want = std::min<size_t>(1024 * 1024, size - done);
        const ssize_t nread = sceKernelPread(fd, out + done, want, offset + (off_t)done);
        if (nread <= 0) {
            AMPR_CRITICAL_LOGF("apr.index read.%s fail off=0x%llx want=0x%llx rc=0x%llx",
                      label, (unsigned long long)(offset + (off_t)done),
                      (unsigned long long)want, (unsigned long long)nread);
            return false;
        }
        done += (size_t)nread;
    }
    return true;
}

__attribute__((noinline)) static CompactIndexLoadResult load_compact_app0_index_locked(FileIndexState& idx) {
    clear_compact_file_index_locked(idx);

    AMPR_LOGF("apr.index open enter path=%s format=AMPRIDX3", kAmprApp0IndexPath);
    int fd = ampr_real_sceKernelOpen(kAmprApp0IndexPath, SCE_KERNEL_O_RDONLY, 0);
    if (fd < 0) {
        AMPR_LOGF("apr.index open miss path=%s rc=0x%x", kAmprApp0IndexPath, fd);
        return CompactIndexLoadResult::Missing;
    }

    SceKernelStat indexStat{};
    const int statRc = sceKernelFstat(fd, &indexStat);
    AMPR_LOGF("apr.index fstat path=%s fd=%d rc=0x%x size=0x%llx",
              kAmprApp0IndexPath, fd, statRc, statRc == 0 ? (unsigned long long)indexStat.st_size : 0ull);
    if (statRc != 0 || indexStat.st_size < (off_t)sizeof(CompactFileIndexHeader)) {
        (void)sceKernelClose(fd);
        return CompactIndexLoadResult::Invalid;
    }

    CompactFileIndexHeader header{};
    if (!pread_exact_logged(fd, &header, sizeof(header), 0, "header")) {
        (void)sceKernelClose(fd);
        return CompactIndexLoadResult::Invalid;
    }

    if (std::memcmp(header.magic, kAmprIndexMagic, sizeof(header.magic)) != 0 ||
        header.version != kAmprIndexVersion ||
        header.entrySize != sizeof(CompactFileIndexEntry) ||
        header.hashSlotSize != sizeof(CompactFileIndexHashSlot)) {
        AMPR_LOGF("apr.index invalid-header path=%s format=AMPRIDX3 version=%u entrySize=%u hashSlotSize=%u",
                  kAmprApp0IndexPath, header.version, header.entrySize, header.hashSlotSize);
        (void)sceKernelClose(fd);
        return CompactIndexLoadResult::Invalid;
    }

    static constexpr uint64_t kMaxEntries = 2000000ull;
    static constexpr uint64_t kMaxPathBytes = 256ull * 1024ull * 1024ull;
    const uint64_t headerBytes = sizeof(CompactFileIndexHeader);
    const uint64_t entryCount = header.entryCount;
    const uint64_t pathBytes = header.pathBytes;
    const uint64_t hashFileOffset = header.hashOffset;
    const uint32_t hashSlotCount = header.hashSlotCount;
    if (entryCount == 0 || entryCount > kMaxEntries ||
        pathBytes == 0 || pathBytes > kMaxPathBytes ||
        hashSlotCount == 0 ||
        (hashSlotCount & (hashSlotCount - 1u)) != 0 ||
        static_cast<uint64_t>(hashSlotCount) < entryCount) {
        AMPR_LOGF("apr.index invalid-counts entries=%llu pathBytes=0x%llx hashSlots=%u",
                  (unsigned long long)entryCount,
                  (unsigned long long)pathBytes,
                  hashSlotCount);
        (void)sceKernelClose(fd);
        return CompactIndexLoadResult::Invalid;
    }
    const uint64_t recordsBytes = entryCount * (uint64_t)sizeof(CompactFileIndexEntry);
    const uint64_t pathFileOffset = headerBytes + recordsBytes;
    const uint64_t hashBytes = (uint64_t)hashSlotCount * (uint64_t)sizeof(CompactFileIndexHashSlot);
    const uint64_t minHashOffset = ampr_align_up_u64(pathFileOffset + pathBytes, alignof(CompactFileIndexHashSlot));
    if (hashBytes / sizeof(CompactFileIndexHashSlot) != hashSlotCount ||
        hashFileOffset < minHashOffset ||
        (hashFileOffset % alignof(CompactFileIndexHashSlot)) != 0 ||
        hashFileOffset + hashBytes < hashFileOffset) {
        AMPR_LOGF("apr.index invalid-hash-header entries=%llu hashSlots=%u hashOffset=0x%llx pathEnd=0x%llx",
                  (unsigned long long)entryCount,
                  hashSlotCount,
                  (unsigned long long)hashFileOffset,
                  (unsigned long long)(pathFileOffset + pathBytes));
        (void)sceKernelClose(fd);
        return CompactIndexLoadResult::Invalid;
    }
    const uint64_t payloadBytes = (hashFileOffset - headerBytes) + hashBytes;
    const uint64_t totalBytes = hashFileOffset + hashBytes;
    if (recordsBytes / sizeof(CompactFileIndexEntry) != entryCount ||
        payloadBytes < recordsBytes || totalBytes < payloadBytes || totalBytes > (uint64_t)indexStat.st_size) {
        AMPR_LOGF("apr.index invalid-size format=AMPRIDX3 entries=%llu pathBytes=0x%llx fileSize=0x%llx",
                  (unsigned long long)entryCount,
                  (unsigned long long)pathBytes,
                  (unsigned long long)indexStat.st_size);
        (void)sceKernelClose(fd);
        return CompactIndexLoadResult::Invalid;
    }

    AMPR_LOGF("apr.index alloc enter format=AMPRIDX3 entries=%llu records=0x%llx pathBytes=0x%llx hashSlots=%u",
              (unsigned long long)entryCount,
              (unsigned long long)recordsBytes,
              (unsigned long long)pathBytes,
              hashSlotCount);
    size_t mappedBytes = ampr_round_up_page_size((size_t)payloadBytes);
    ampr_log_kernel_memory_status("apr.index.full.before", mappedBytes);
    (void)ampr_internal_amm_pool_ensure(mappedBytes, "apr.index.full");
    void* mapped = ampr_alloc_sdk_cpu_memory(mappedBytes);
    if (!mapped) {
        AMPR_CRITICAL_LOGF("apr.index full-map fail errno=%d format=AMPRIDX3 entries=%llu records=0x%llx pathBytes=0x%llx mapSize=0x%llx reason=no-memory-fallback",
                  errno,
                  (unsigned long long)entryCount,
                  (unsigned long long)recordsBytes,
                  (unsigned long long)pathBytes,
                  (unsigned long long)mappedBytes);
        clear_compact_file_index_locked(idx);
        (void)sceKernelClose(fd);
        return CompactIndexLoadResult::Memory;
    }
    idx.compactMapBase = mapped;
    idx.compactMapSize = mappedBytes;
    idx.compactEntries = static_cast<CompactFileIndexEntry*>(mapped);
    idx.compactPathBlob = static_cast<const char*>(mapped) + recordsBytes;
    idx.compactHashSlots = reinterpret_cast<CompactFileIndexHashSlot*>(
        static_cast<char*>(mapped) + (hashFileOffset - headerBytes));
    idx.compactHashMask = (size_t)hashSlotCount - 1u;
    if (!idx.compactEntries) {
        AMPR_CRITICAL_LOGF("apr.index map pointer fail entries=%llu pathBytes=0x%llx",
                  (unsigned long long)entryCount,
                  (unsigned long long)pathBytes);
        clear_compact_file_index_locked(idx);
        (void)sceKernelClose(fd);
        return CompactIndexLoadResult::Invalid;
    }
    idx.compactEntryCount = (size_t)entryCount;
    idx.compactPathBlobSize = (size_t)pathBytes;
    AMPR_LOGF("apr.index alloc leave format=AMPRIDX3 entries=%zu pathBytes=0x%llx mapSize=0x%llx pathResident=1 hashResident=1",
              idx.compactEntryCount,
              (unsigned long long)idx.compactPathBlobSize,
              (unsigned long long)idx.compactMapSize);

    const bool recordsOk = pread_exact_logged(fd, idx.compactEntries, (size_t)recordsBytes,
                                              (off_t)headerBytes, "records");
    if (!recordsOk) {
        clear_compact_file_index_locked(idx);
        (void)sceKernelClose(fd);
        return CompactIndexLoadResult::Invalid;
    }

    const bool pathBlobOk = pread_exact_logged(fd, const_cast<char*>(idx.compactPathBlob),
                                               (size_t)pathBytes,
                                               (off_t)pathFileOffset,
                                               "pathblob");
    const bool hashSlotsOk = pread_exact_logged(fd,
                                                idx.compactHashSlots,
                                                (size_t)hashBytes,
                                                (off_t)hashFileOffset,
                                                "hashslots");
    (void)sceKernelClose(fd);
    fd = -1;
    if (!pathBlobOk || !hashSlotsOk) {
        clear_compact_file_index_locked(idx);
        return CompactIndexLoadResult::Invalid;
    }

    bool valid = true;
    const size_t validationIndexes[] = {0, idx.compactEntryCount / 2, idx.compactEntryCount - 1};
    for (size_t vi = 0; vi < sizeof(validationIndexes) / sizeof(validationIndexes[0]); ++vi) {
        const size_t i = validationIndexes[vi];
        const auto& e = idx.compactEntries[i];
        const uint64_t begin = e.pathOffset;
        const uint64_t end = begin + e.pathLength;
        char pathBuf[4096];
        if (begin >= idx.compactPathBlobSize || end >= idx.compactPathBlobSize ||
            !compact_index_copy_path(idx, e, pathBuf, sizeof(pathBuf))) {
            AMPR_LOGF("apr.index invalid-record idx=%zu off=0x%x len=0x%x pathBytes=0x%llx",
                      i, e.pathOffset, e.pathLength, (unsigned long long)idx.compactPathBlobSize);
            valid = false;
            break;
        }
    }
    if (!valid) {
        clear_compact_file_index_locked(idx);
        return CompactIndexLoadResult::Invalid;
    }

    idx.compactAvailable = true;
    idx.available = true;
    AMPR_LOGF("apr.index loaded path=%s format=AMPRIDX3 entries=%zu pathBytes=0x%llx hashSlots=%zu",
              kAmprApp0IndexPath, idx.compactEntryCount,
              (unsigned long long)idx.compactPathBlobSize,
              idx.compactHashMask != 0 ? idx.compactHashMask + 1u : 0u);
    return CompactIndexLoadResult::Loaded;
}

__attribute__((noinline)) static bool ensure_app0_index_ready_slow(FileIndexState& idx, bool allowRuntimeBuild) {
    sce::Ampr::Emu::startDebugLogWriter();
    for (;;) {
        {
            AmprUniqueLock lk(idx.m);
            if (idx.loaded) {
                return idx.available;
            }
            if (idx.loading) {
                idx.cv.wait_for(lk, std::chrono::microseconds(kAmprIndexLoadWaitUs));
                if (idx.loading) {
                    AMPR_LOGF("apr.index wait path=%s reason=load-in-progress waitUs=%llu",
                              kAmprApp0IndexPath,
                              (unsigned long long)kAmprIndexLoadWaitUs);
                }
                continue;
            }
            if (idx.loadAttempted && (!allowRuntimeBuild || AMPR_EMU_APP0_INDEX_AUTOBUILD == 0)) {
                return idx.available;
            }
            idx.loadAttempted = true;
            idx.loading = true;
            idx.available = false;
        }

        FileIndexState work;
        CompactIndexLoadResult loadResult = load_compact_app0_index_locked(work);
        bool finalLoaded = false;
        if (loadResult == CompactIndexLoadResult::Loaded) {
            finalLoaded = true;
        } else if (loadResult == CompactIndexLoadResult::Memory) {
            finalLoaded = true;
            work.available = false;
            AMPR_LOGF("apr.index unavailable path=%s; skip runtime build reason=valid-index-memory-load-failed",
                      kAmprApp0IndexPath);
        } else {

#if !AMPR_EMU_APP0_INDEX_AUTOBUILD
            (void)allowRuntimeBuild;
            AMPR_LOGF("apr.index unavailable path=%s result=%s; runtime autobuild disabled",
                      kAmprApp0IndexPath,
                      compact_index_load_result_name(loadResult));
#else
            if (!allowRuntimeBuild) {
                AMPR_LOGF("apr.index unavailable path=%s result=%s; defer runtime build",
                          kAmprApp0IndexPath,
                          compact_index_load_result_name(loadResult));
            } else {
                AMPR_LOGF("apr.index unavailable path=%s result=%s; building runtime index",
                          kAmprApp0IndexPath,
                          compact_index_load_result_name(loadResult));
                build_app0_index_locked(work);
                finalLoaded = true;
            }
#endif
        }

        {
            AmprLockGuard lk(idx.m);
            const bool finalAvailable = work.available;
            move_compact_file_index_locked(idx, work);
            idx.available = finalAvailable;
            idx.loaded = finalLoaded;
            idx.loading = false;
            if (finalLoaded) {
                g_file_index_publish_state.store(
                    finalAvailable ? FileIndexPublishState::Available
                                   : FileIndexPublishState::Unavailable,
                    std::memory_order_release);
            }
            idx.cv.notify_all();
            return idx.available;
        }
    }
}

static bool ensure_app0_index_ready(FileIndexState& idx, bool allowRuntimeBuild) {
    const FileIndexPublishState published =
        g_file_index_publish_state.load(std::memory_order_acquire);
    if (published != FileIndexPublishState::Pending) {
        return published == FileIndexPublishState::Available;
    }
    {
        AmprLockGuard lk(idx.m);
        if (idx.loaded) {
            return idx.available;
        }
    }
    return ensure_app0_index_ready_slow(idx, allowRuntimeBuild);
}

static bool lookup_app0_index_key_view(const char* key,
                                       size_t keyLen,
                                       FileEntryView* out,
                                       uint32_t* outId,
                                       bool allowRuntimeBuild) {
    if (!key || !out) return false;
    auto& idx = file_index_state();
    if (!ensure_app0_index_ready(idx, allowRuntimeBuild)) return false;

    if (idx.compactAvailable) {
        if (!idx.compactHashSlots || idx.compactHashMask == 0) {
            AMPR_LOGF("apr.index lookup.hash-missing key=%s entries=%zu",
                      key, idx.compactEntryCount);
            return false;
        }

        const uint64_t hash = compact_index_hash_key(key);
        const size_t slotCount = idx.compactHashMask + 1u;
        size_t pos = (size_t)hash & idx.compactHashMask;
        size_t probes = 0;
        while (idx.compactHashSlots[pos].indexPlusOne != 0 && probes < slotCount) {
            const CompactFileIndexHashSlot& slot = idx.compactHashSlots[pos];
            if (slot.hash == hash) {
                const size_t entryIndex = (size_t)slot.indexPlusOne - 1u;
                if (entryIndex < idx.compactEntryCount) {
                    const auto& e = idx.compactEntries[entryIndex];
                    const char* pathPtr = compact_index_path_ptr(idx, e);
                    const bool trustUniqueHash =
                        AMPR_EMU_APP0_INDEX_TRUST_UNIQUE_HASH != 0 &&
                        (slot.reserved & kCompactIndexHashDuplicate) == 0 &&
                        e.pathLength == keyLen;
                    if (pathPtr &&
                        (trustUniqueHash || compare_index_path_key(pathPtr, key) == 0)) {
                        out->path = pathPtr;
                        out->pathLength = e.pathLength;
                        out->size = static_cast<size_t>(e.size);
                        out->mtime = e.mtime;
                        const uint32_t fileId = static_cast<uint32_t>(entryIndex + 1u);
                        if (fileId == 0 || fileId == SCE_AMPR_APR_FILEID_INVALID) {
                            AMPR_CRITICAL_LOGF("apr.index lookup.invalid-id key=%s entryIndex=%zu fileId=%u",
                                               key, entryIndex, fileId);
                            return false;
                        }
                        if (outId) {
                            *outId = fileId;
                        }
                        return true;
                    }
                }
            }
            pos = (pos + 1u) & idx.compactHashMask;
            ++probes;
        }
        if (probes >= slotCount) {
            AMPR_LOGF("apr.index lookup.hash-full key=%s slots=%zu entries=%zu",
                      key, slotCount, idx.compactEntryCount);
        }
        return false;
    }

    return false;
}

static bool is_normalized_app0_key(const char* key, size_t keyLen) {
    if (!key) return false;
    return (keyLen == 5u && std::memcmp(key, "/app0", 5u) == 0) ||
           (keyLen > 6u && std::memcmp(key, "/app0/", 6u) == 0);
}

__attribute__((noinline)) static const char* maybe_resolve_app0_path_arg(const char* path) {
    AMPR_FILE_WRAPPER_LOGF("fs.resolve_app0 enter path=%s", ampr_log_path_arg(path));
    char key[kAmprIndexMaxPath];
    size_t keyLen = 0;
    if (normalize_app0_path_key(path, key, sizeof(key), &keyLen) &&
        is_normalized_app0_key(key, keyLen) &&
        keyLen > 6u) {
        FileEntryView indexed{};
        if (lookup_app0_index_key_view(key,
                                       keyLen,
                                       &indexed,
                                       nullptr,
                                       AMPR_EMU_APP0_INDEX_AUTOBUILD != 0)) {
            AMPR_FILE_WRAPPER_LOGF("fs.resolve_app0 hit path=%s real=%s",
                                   ampr_log_path_arg(path), indexed.path);
            return indexed.path;
        }
    }
    AMPR_FILE_WRAPPER_LOGF("fs.resolve_app0 miss path=%s", ampr_log_path_arg(path));
    return path;
}

int ampr_index_get_entry_view(uint32_t id, FileEntryView* out);

int ampr_index_resolve_path_to_id(const char* path, uint32_t* outId, size_t* outSize) {
    AMPR_TLOGF("[apr-rp-01] resolve_path_to_id enter path=%s", ampr_log_path_arg(path));
    if (!path || !outId) {
        AMPR_LOGF("[apr-rp-02] resolve_path_to_id status=failed reason=bad-args path=%s outId=%p", ampr_log_path_arg(path), outId);
        return -EFAULT;
    }

    char key[kAmprIndexMaxPath];
    size_t keyLen = 0;
    bool hadTrailingSeparator = false;
    const int normalizeRc = normalize_app0_path_key_result(path,
                                                           key,
                                                           sizeof(key),
                                                           &keyLen,
                                                           &hadTrailingSeparator);
    if (normalizeRc != 0) {
        AMPR_LOGF("[apr-rp-03] resolve_path_to_id status=failed reason=bad-key path=%s rc=%d",
                  ampr_log_path_arg(path), normalizeRc);
        return -normalizeRc;
    }
    if (!is_normalized_app0_key(key, keyLen)) {
        AMPR_LOGF("[apr-rp-03] resolve_path_to_id status=failed reason=not-app0 path=%s key=%s",
                  ampr_log_path_arg(path), key);
        return -ENOENT;
    }
    if (keyLen == 5u || hadTrailingSeparator) {
        AMPR_LOGF("[apr-rp-03] resolve_path_to_id status=failed reason=directory path=%s key=%s",
                  ampr_log_path_arg(path), key);
        return -EOPNOTSUPP;
    }
    FileEntryView indexed{};
    uint32_t id = 0;
    if (!lookup_app0_index_key_view(key,
                                    keyLen,
                                    &indexed,
                                    &id,
                                    AMPR_EMU_APP0_INDEX_AUTOBUILD != 0) ||
        id == 0) {
        AMPR_LOGF("[apr-rp-03] resolve_path_to_id status=failed reason=index-miss path=%s key=%s", path, key);
        return -ENOENT;
    }

    if (outSize) *outSize = indexed.size;
    *outId = id;
    AMPR_TLOGF("[apr-rp-06] resolve_path_to_id index path=%s key=%s fileId=%u size=0x%llx",
              indexed.path, key, id, (unsigned long long)indexed.size);
    AMPR_FILE_STATUS_LOGF("apr.file.resolve status=resolved path=%s real=%s key=%s fileId=%u size=0x%llx",
                          path,
                          indexed.path,
                          key,
                          id,
                          (unsigned long long)indexed.size);
    return 0;
}

__attribute__((noinline)) static bool is_app0_path_arg(const char* path) {
    char key[kAmprIndexMaxPath];
    size_t keyLen = 0;
    return normalize_app0_path_key(path, key, sizeof(key), &keyLen) &&
           is_normalized_app0_key(key, keyLen);
}

static bool app0_file_hook_should_try_index_fallback(int directRc) {
    if (directRc == 0) {
        return false;
    }
    int err = 0;
    if (directRc == -1) {
        err = errno;
    } else if ((static_cast<uint32_t>(directRc) & 0xFFFF0000u) == 0x80020000u) {
        err = ampr_posix_errno_from_sce(directRc);
    } else {
        err = directRc < 0 ? -directRc : directRc;
    }
    return err == ENOENT || err == ENOTDIR;
}

// Retry failed /app0 path operations with the canonical indexed spelling.
extern "C" int sceKernelOpen_emul(const char* path, int flags, SceKernelMode mode) {
    const int direct = ampr_real_sceKernelOpen(path, flags, mode);
    const bool isApp0 = is_app0_path_arg(path);
    if (direct >= 0 ||
        !isApp0 ||
        (flags & SCE_KERNEL_O_DIRECTORY) != 0 ||
        !app0_file_hook_should_try_index_fallback(direct)) {
        AMPR_FILE_WRAPPER_LOGF("fs.open.emu status=%s path=%s directRc=0x%x flags=0x%x mode=0x%x indexed=0",
                               direct >= 0 ? "opened" : "failed",
                               ampr_log_path_arg(path), direct, flags, (unsigned)mode);
        return direct;
    }

    const char* realPath = maybe_resolve_app0_path_arg(path);
    if (realPath == path) {
        AMPR_FILE_WRAPPER_LOGF("fs.open.emu status=failed path=%s directRc=0x%x flags=0x%x mode=0x%x indexed=0",
                               ampr_log_path_arg(path), direct, flags, (unsigned)mode);
        return direct;
    }
    const int rc = ampr_real_sceKernelOpen(realPath, flags, mode);
    AMPR_FILE_WRAPPER_LOGF("fs.open.emu status=%s path=%s real=%s rc=0x%x flags=0x%x mode=0x%x indexed=1",
                           rc >= 0 ? "opened" : "failed",
                           ampr_log_path_arg(path), ampr_log_path_arg(realPath), rc, flags, (unsigned)mode);
    return rc;
}

extern "C" int sceKernelStat_emul(const char* path, SceKernelStat* sb) {
    const int direct = ampr_real_sceKernelStat(path, sb);
    const bool isApp0 = is_app0_path_arg(path);
    if (direct == 0 || !isApp0 || !app0_file_hook_should_try_index_fallback(direct)) {
        AMPR_FILE_WRAPPER_LOGF("fs.stat.emu path=%s directRc=0x%x out=%p indexed=0",
                               ampr_log_path_arg(path), direct, sb);
        return direct;
    }

    const char* realPath = maybe_resolve_app0_path_arg(path);
    if (realPath == path) {
        AMPR_FILE_WRAPPER_LOGF("fs.stat.emu path=%s directRc=0x%x out=%p indexed=0",
                               ampr_log_path_arg(path), direct, sb);
        return direct;
    }
    const int rc = ampr_real_sceKernelStat(realPath, sb);
    AMPR_FILE_WRAPPER_LOGF("fs.stat.emu path=%s real=%s rc=0x%x out=%p indexed=1",
                           ampr_log_path_arg(path), ampr_log_path_arg(realPath), rc, sb);
    return rc;
}

extern "C" int sceKernelCheckReachability_emul(const char* path) {
    const int direct = ampr_real_sceKernelCheckReachability(path);
    const bool isApp0 = is_app0_path_arg(path);
    if (direct == 0 || !isApp0 || !app0_file_hook_should_try_index_fallback(direct)) {
        AMPR_FILE_WRAPPER_LOGF("fs.checkReachability.emu path=%s directRc=0x%x indexed=0",
                               ampr_log_path_arg(path), direct);
        return direct;
    }

    const char* realPath = maybe_resolve_app0_path_arg(path);
    if (realPath == path) {
        AMPR_FILE_WRAPPER_LOGF("fs.checkReachability.emu path=%s directRc=0x%x indexed=0",
                               ampr_log_path_arg(path), direct);
        return direct;
    }
    const int rc = ampr_real_sceKernelCheckReachability(realPath);
    AMPR_FILE_WRAPPER_LOGF("fs.checkReachability.emu path=%s real=%s rc=0x%x indexed=1",
                           ampr_log_path_arg(path), ampr_log_path_arg(realPath), rc);
    return rc;
}

extern "C" int sceKernelUnlink_emul(const char* path) {
    const int direct = ampr_real_sceKernelUnlink(path);
    const bool isApp0 = is_app0_path_arg(path);
    if (direct == 0 || !isApp0 || !app0_file_hook_should_try_index_fallback(direct)) {
        AMPR_FILE_WRAPPER_LOGF("fs.unlink.emu path=%s directRc=0x%x indexed=0",
                               ampr_log_path_arg(path), direct);
        return direct;
    }

    const char* realPath = maybe_resolve_app0_path_arg(path);
    if (realPath == path) {
        AMPR_FILE_WRAPPER_LOGF("fs.unlink.emu path=%s directRc=0x%x indexed=0",
                               ampr_log_path_arg(path), direct);
        return direct;
    }
    const int rc = ampr_real_sceKernelUnlink(realPath);
    AMPR_FILE_WRAPPER_LOGF("fs.unlink.emu path=%s real=%s rc=0x%x indexed=1",
                           ampr_log_path_arg(path), ampr_log_path_arg(realPath), rc);
    return rc;
}

extern "C" int sceKernelRename_emul(const char* from, const char* to) {
    const int direct = ampr_real_sceKernelRename(from, to);
    if (direct == 0) {
        AMPR_FILE_WRAPPER_LOGF("fs.rename.emu from=%s to=%s directRc=0x%x indexedFrom=0 indexedTo=0",
                               ampr_log_path_arg(from), ampr_log_path_arg(to), direct);
        return direct;
    }
    if (!app0_file_hook_should_try_index_fallback(direct)) {
        AMPR_FILE_WRAPPER_LOGF("fs.rename.emu from=%s to=%s directRc=0x%x indexedFrom=0 indexedTo=0",
                               ampr_log_path_arg(from), ampr_log_path_arg(to), direct);
        return direct;
    }

    const bool fromIsApp0 = is_app0_path_arg(from);
    const bool toIsApp0 = is_app0_path_arg(to);
    if (!fromIsApp0 && !toIsApp0) {
        AMPR_FILE_WRAPPER_LOGF("fs.rename.emu from=%s to=%s directRc=0x%x indexedFrom=0 indexedTo=0",
                               ampr_log_path_arg(from), ampr_log_path_arg(to), direct);
        return direct;
    }
    const char* realFrom = maybe_resolve_app0_path_arg(from);
    const char* realTo = maybe_resolve_app0_path_arg(to);
    if (realFrom == from && realTo == to) {
        AMPR_FILE_WRAPPER_LOGF("fs.rename.emu from=%s to=%s directRc=0x%x indexedFrom=0 indexedTo=0",
                               ampr_log_path_arg(from), ampr_log_path_arg(to), direct);
        return direct;
    }
    const int rc = ampr_real_sceKernelRename(realFrom, realTo);
    AMPR_FILE_WRAPPER_LOGF("fs.rename.emu from=%s realFrom=%s to=%s realTo=%s rc=0x%x indexedFrom=%u indexedTo=%u",
                           ampr_log_path_arg(from), ampr_log_path_arg(realFrom),
                           ampr_log_path_arg(to), ampr_log_path_arg(realTo), rc,
                           realFrom != from ? 1u : 0u, realTo != to ? 1u : 0u);
    return rc;
}

int ampr_index_get_entry_view(uint32_t id, FileEntryView* out) {
    if (id == 0 || id == SCE_AMPR_APR_FILEID_INVALID) return -ENOENT;
    const size_t entryIndex = static_cast<size_t>(id - 1u);

    auto& idx = file_index_state();
    if (!ensure_app0_index_ready(idx, AMPR_EMU_APP0_INDEX_AUTOBUILD != 0)) return -ENOENT;

    FileEntryView view{};
    if (idx.compactAvailable) {
        if (entryIndex >= idx.compactEntryCount) return -ENOENT;
        const auto& ce = idx.compactEntries[entryIndex];
        const char* pathPtr = compact_index_path_ptr(idx, ce);
        if (!pathPtr) return -ENOENT;
        view.path = pathPtr;
        view.pathLength = ce.pathLength;
        view.size = static_cast<size_t>(ce.size);
        view.mtime = ce.mtime;
    } else {
        return -ENOENT;
    }

    if (out) *out = view;
    return 0;
}

