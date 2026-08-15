/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Runtime memory and SDK CPU allocation module.
 */

#define AMPR_EMU_RUNTIME_IMPL 1
#include "ampr_emu_runtime_memory.h"
#include "ampr_emu_kernel_memory.h"
#include "ampr_emu_log.h"
#include "ampr_emu_sync.h"

#include <atomic>
#include <cstring>

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
#pragma clang diagnostic ignored "-Wunused-const-variable"
#pragma clang diagnostic ignored "-Wunneeded-internal-declaration"
#endif
namespace {
static constexpr size_t kAmprInternalAmmPoolSize =
    static_cast<size_t>(AMPR_EMU_INTERNAL_AMM_POOL_SIZE);
static_assert(kAmprInternalAmmPoolSize != 0, "internal AMM pool must not be empty");
static_assert(kAmprInternalAmmPoolSize <= SIZE_MAX - (SCE_KERNEL_PAGE_SIZE - 1u),
              "internal AMM pool size overflows page alignment");
static constexpr size_t kAmprInternalAmmStaticPoolSize =
    ((kAmprInternalAmmPoolSize + SCE_KERNEL_PAGE_SIZE - 1u) / SCE_KERNEL_PAGE_SIZE) *
    SCE_KERNEL_PAGE_SIZE;
static_assert((kAmprInternalAmmStaticPoolSize % SCE_KERNEL_PAGE_SIZE) == 0,
              "internal AMM static pool must be page aligned");

static std::atomic<uint32_t> g_internal_amm_pool_lock{0};
static bool g_internal_amm_pool_ready = false;
static bool g_internal_amm_pool_initializing = false;
alignas(SCE_KERNEL_PAGE_SIZE) static uint8_t
    g_internal_amm_static_pool[kAmprInternalAmmStaticPoolSize];
static uint8_t* g_internal_amm_pool_base = nullptr;
static size_t g_internal_amm_pool_size = 0;
static size_t g_internal_amm_pool_used = 0;
static size_t g_internal_amm_pool_peak_used = 0;
static bool g_internal_amm_pool_apr_visible = false;

static constexpr int kAmprInternalAmmPoolMaxChunks = 512;

struct AmprInternalAmmPoolChunk {
    size_t offset{};
    size_t size{};
    int prev{-1};
    int next{-1};
    bool active{false};
    bool free{false};
};

static AmprInternalAmmPoolChunk g_internal_amm_pool_chunks[kAmprInternalAmmPoolMaxChunks];
static int g_internal_amm_pool_head = -1;

#if AMPR_EMU_DEBUG_LOG
struct AmprInternalAmmPoolStats {
    size_t freeBytes{};
    size_t largestFree{};
    size_t activeChunks{};
    size_t freeChunks{};
    size_t usedChunks{};
};

struct AmprInternalAmmPoolSnapshot {
    bool ready{};
    void* base{};
    size_t total{};
    size_t used{};
    size_t peak{};
    bool aprVisible{};
    AmprInternalAmmPoolStats stats{};
};
#endif

static size_t ampr_internal_align_up_size_impl(size_t value, size_t alignment) {
    if (alignment == 0) {
        return value;
    }
    if ((alignment & (alignment - 1u)) != 0) {
        return SIZE_MAX;
    }
    const size_t mask = alignment - 1u;
    if (value > SIZE_MAX - mask) {
        return SIZE_MAX;
    }
    return (value + mask) & ~mask;
}

static size_t ampr_internal_amm_pool_alignment(size_t alignment) {
    if (alignment == 0 || alignment < SCE_KERNEL_PAGE_SIZE) {
        return SCE_KERNEL_PAGE_SIZE;
    }
    return ((alignment & (alignment - 1u)) == 0) ? alignment : SIZE_MAX;
}

static int ampr_internal_amm_pool_new_chunk_locked() {
    for (int i = 0; i < kAmprInternalAmmPoolMaxChunks; ++i) {
        if (!g_internal_amm_pool_chunks[i].active) {
            g_internal_amm_pool_chunks[i] = {};
            g_internal_amm_pool_chunks[i].active = true;
            g_internal_amm_pool_chunks[i].prev = -1;
            g_internal_amm_pool_chunks[i].next = -1;
            return i;
        }
    }
    return -1;
}

static void ampr_internal_amm_pool_reset_chunks_locked() {
    for (int i = 0; i < kAmprInternalAmmPoolMaxChunks; ++i) {
        g_internal_amm_pool_chunks[i] = {};
        g_internal_amm_pool_chunks[i].prev = -1;
        g_internal_amm_pool_chunks[i].next = -1;
    }
    g_internal_amm_pool_head = -1;
    g_internal_amm_pool_used = 0;
    g_internal_amm_pool_peak_used = 0;
}

static bool ampr_internal_amm_pool_init_chunks_locked(size_t poolSize) {
    ampr_internal_amm_pool_reset_chunks_locked();
    if (poolSize == 0) {
        return false;
    }
    const int head = ampr_internal_amm_pool_new_chunk_locked();
    if (head < 0) {
        return false;
    }
    g_internal_amm_pool_chunks[head].offset = 0;
    g_internal_amm_pool_chunks[head].size = poolSize;
    g_internal_amm_pool_chunks[head].free = true;
    g_internal_amm_pool_head = head;
    return true;
}

static bool ampr_internal_amm_pool_chunk_can_fit_locked(const AmprInternalAmmPoolChunk& chunk,
                                                        size_t size,
                                                        size_t alignment) {
    if (!chunk.active || !chunk.free || size == 0) {
        return false;
    }
    const size_t alignedOffset = ampr_internal_align_up_size_impl(chunk.offset, alignment);
    if (alignedOffset == SIZE_MAX || alignedOffset < chunk.offset) {
        return false;
    }
    const size_t chunkEnd = chunk.offset + chunk.size;
    if (chunkEnd < chunk.offset || alignedOffset > chunkEnd) {
        return false;
    }
    return size <= chunkEnd - alignedOffset;
}

static bool ampr_internal_amm_pool_has_capacity_locked(size_t size,
                                                       size_t alignment = SCE_KERNEL_PAGE_SIZE) {
    alignment = ampr_internal_amm_pool_alignment(alignment);
    if (alignment == SIZE_MAX) {
        return false;
    }
    for (int i = g_internal_amm_pool_head; i >= 0; i = g_internal_amm_pool_chunks[i].next) {
        if (ampr_internal_amm_pool_chunk_can_fit_locked(g_internal_amm_pool_chunks[i],
                                                        size,
                                                        alignment)) {
            return true;
        }
    }
    return false;
}

static bool ampr_internal_amm_pool_ready_has_capacity_impl(size_t size,
                                                      size_t alignment = SCE_KERNEL_PAGE_SIZE) {
    AmprSpinLock poolLock(&g_internal_amm_pool_lock);
    return g_internal_amm_pool_ready &&
           g_internal_amm_pool_base &&
           ampr_internal_amm_pool_has_capacity_locked(size, alignment);
}

#if AMPR_EMU_DEBUG_LOG
static AmprInternalAmmPoolStats ampr_internal_amm_pool_stats_locked(
    size_t alignment = SCE_KERNEL_PAGE_SIZE) {
    alignment = ampr_internal_amm_pool_alignment(alignment);
    if (alignment == SIZE_MAX) {
        alignment = SCE_KERNEL_PAGE_SIZE;
    }
    AmprInternalAmmPoolStats stats{};
    for (int i = g_internal_amm_pool_head; i >= 0; i = g_internal_amm_pool_chunks[i].next) {
        const AmprInternalAmmPoolChunk& chunk = g_internal_amm_pool_chunks[i];
        if (!chunk.active) {
            continue;
        }
        ++stats.activeChunks;
        if (!chunk.free) {
            ++stats.usedChunks;
            continue;
        }
        ++stats.freeChunks;
        stats.freeBytes = stats.freeBytes <= SIZE_MAX - chunk.size
                              ? stats.freeBytes + chunk.size
                              : SIZE_MAX;
        const size_t alignedOffset = ampr_internal_align_up_size_impl(chunk.offset, alignment);
        const size_t chunkEnd = chunk.offset + chunk.size;
        if (alignedOffset == SIZE_MAX || chunkEnd < chunk.offset || alignedOffset > chunkEnd) {
            continue;
        }
        const size_t usable = chunkEnd - alignedOffset;
        if (usable > stats.largestFree) {
            stats.largestFree = usable;
        }
    }
    return stats;
}
#endif

#if AMPR_EMU_DEBUG_LOG
static AmprInternalAmmPoolSnapshot ampr_internal_amm_pool_snapshot() {
    AmprInternalAmmPoolSnapshot snapshot{};
    {
        AmprSpinLock poolLock(&g_internal_amm_pool_lock);
        snapshot.ready = g_internal_amm_pool_ready;
        snapshot.base = g_internal_amm_pool_base;
        snapshot.total = g_internal_amm_pool_size;
        snapshot.used = g_internal_amm_pool_used;
        snapshot.peak = g_internal_amm_pool_peak_used;
        snapshot.aprVisible = g_internal_amm_pool_apr_visible;
        snapshot.stats = ampr_internal_amm_pool_stats_locked();
    }
    return snapshot;
}
#endif

static void ampr_internal_amm_pool_log_summary_impl(const char* reason) {
#if AMPR_EMU_DEBUG_LOG
    if (!ampr_debug_log_runtime_enabled()) {
        return;
    }
    const AmprInternalAmmPoolSnapshot snapshot = ampr_internal_amm_pool_snapshot();
    AMPR_LOGF("mem.internal_pool.summary reason=%s ready=%u aprVisible=%u base=%p total=0x%llx used=0x%llx peak=0x%llx free=0x%llx largestFree=0x%llx chunks=%llu usedChunks=%llu freeChunks=%llu owner=bss",
              reason ? reason : "(null)",
              snapshot.ready ? 1u : 0u,
              snapshot.aprVisible ? 1u : 0u,
              snapshot.base,
              (unsigned long long)snapshot.total,
              (unsigned long long)snapshot.used,
              (unsigned long long)snapshot.peak,
              (unsigned long long)snapshot.stats.freeBytes,
              (unsigned long long)snapshot.stats.largestFree,
              (unsigned long long)snapshot.stats.activeChunks,
              (unsigned long long)snapshot.stats.usedChunks,
              (unsigned long long)snapshot.stats.freeChunks);
#else
    (void)reason;
#endif
}

static void ampr_prewarm_late_runtime_state();
static void prewarm_apr_submit_runtime(bool flushRuntimeLogs = true);

static bool ampr_internal_amm_pool_ensure_impl(size_t requiredSize, const char* reason) {
    const size_t requiredPoolSize = ampr_internal_align_up_size_impl(requiredSize,
                                                                SCE_KERNEL_PAGE_SIZE);
    if (requiredPoolSize == 0 || requiredPoolSize == SIZE_MAX) {
        return false;
    }
    {
        AmprSpinLock poolLock(&g_internal_amm_pool_lock);
        if (g_internal_amm_pool_ready) {
            return ampr_internal_amm_pool_has_capacity_locked(requiredPoolSize);
        }
    }
    if (requiredPoolSize > kAmprInternalAmmStaticPoolSize) {
        AMPR_CRITICAL_LOGF("mem.internal_pool.static.capacity fail reason=%s requested=0x%llx pool=0x%llx fallback=none",
                           reason ? reason : "(null)",
                           (unsigned long long)requiredPoolSize,
                           (unsigned long long)kAmprInternalAmmStaticPoolSize);
        return false;
    }

    uint32_t spins = 0;
    for (;;) {
        {
            AmprSpinLock poolLock(&g_internal_amm_pool_lock);
            if (g_internal_amm_pool_ready) {
                return ampr_internal_amm_pool_has_capacity_locked(requiredPoolSize);
            }
            if (!g_internal_amm_pool_initializing) {
                g_internal_amm_pool_initializing = true;
                break;
            }
        }
        ampr_spin_pause_or_yield(spins);
    }

    constexpr int kStaticPoolProt = SCE_KERNEL_PROT_CPU_RW | SCE_KERNEL_PROT_AMPR_ALL;
    void* const pool = g_internal_amm_static_pool;
    const int protectRc = ampr_real_sceKernelMprotect(pool,
                                                      kAmprInternalAmmStaticPoolSize,
                                                      kStaticPoolProt);
    if (protectRc != 0) {
        {
            AmprSpinLock poolLock(&g_internal_amm_pool_lock);
            g_internal_amm_pool_initializing = false;
        }
        AMPR_CRITICAL_LOGF("mem.internal_pool.static.protect fail reason=%s rc=0x%x ptr=%p size=0x%llx prot=0x%x fallback=none",
                           reason ? reason : "(null)",
                           protectRc,
                           pool,
                           (unsigned long long)kAmprInternalAmmStaticPoolSize,
                           kStaticPoolProt);
        return false;
    }

    bool publishFailed = false;
    bool logChunkTableInitFail = false;
    {
        AmprSpinLock poolLock(&g_internal_amm_pool_lock);
        if (!ampr_internal_amm_pool_init_chunks_locked(kAmprInternalAmmStaticPoolSize)) {
            g_internal_amm_pool_initializing = false;
            publishFailed = true;
            logChunkTableInitFail = true;
        } else {
            g_internal_amm_pool_base = g_internal_amm_static_pool;
            g_internal_amm_pool_size = kAmprInternalAmmStaticPoolSize;
            g_internal_amm_pool_apr_visible = true;
            g_internal_amm_pool_ready = true;
            g_internal_amm_pool_initializing = false;
        }
    }
    if (logChunkTableInitFail) {
        AMPR_CRITICAL_LOGF("mem.internal_pool.init fail reason=%s owner=bss size=0x%llx cause=chunk-table",
                           reason ? reason : "(null)",
                           (unsigned long long)kAmprInternalAmmStaticPoolSize);
    }
    if (publishFailed) {
        return false;
    }

    AMPR_LOGF("mem.internal_pool.init ok reason=%s owner=bss ptr=%p size=0x%llx requested=0x%llx prot=0x%x",
              reason ? reason : "(null)",
              pool,
              (unsigned long long)kAmprInternalAmmStaticPoolSize,
              (unsigned long long)requiredSize,
              kStaticPoolProt);
    ampr_internal_amm_pool_log_summary_impl("init.bss");
    return true;
}

static bool ampr_internal_amm_pool_prepare_static_storage_impl(const char* reason) {
    {
        AmprSpinLock poolLock(&g_internal_amm_pool_lock);
        if (g_internal_amm_pool_ready) {
            return g_internal_amm_pool_base == g_internal_amm_static_pool &&
                   g_internal_amm_pool_apr_visible;
        }
    }
    return ampr_internal_amm_pool_ensure_impl(SCE_KERNEL_PAGE_SIZE,
                                         reason ? reason : "mem.static_pool");
}

static void* ampr_internal_amm_pool_alloc_impl(size_t size,
                                           size_t* outMappedSize,
                                           const char* tag,
                                           bool criticalOnFail = true,
                                           size_t alignment = SCE_KERNEL_PAGE_SIZE) {
#if !AMPR_EMU_DEBUG_LOG
    (void)tag;
    (void)criticalOnFail;
#endif
    if (outMappedSize) {
        *outMappedSize = 0;
    }
    if (size == 0) {
        return nullptr;
    }
    const size_t allocAlignment = ampr_internal_amm_pool_alignment(alignment);
    const size_t mappedSize = allocAlignment != SIZE_MAX
        ? ampr_internal_align_up_size_impl(size, allocAlignment)
        : SIZE_MAX;
    if (mappedSize == SIZE_MAX) {
        AMPR_CRITICAL_LOGF("mem.internal_pool.alloc fail tag=%s reason=size-or-alignment-overflow requested=0x%llx alignment=0x%llx",
                           tag ? tag : "(null)",
                           (unsigned long long)size,
                           (unsigned long long)alignment);
        return nullptr;
    }

    void* ptr = nullptr;
    bool ok = false;
    const char* failReason = nullptr;
#if AMPR_EMU_DEBUG_LOG
    bool readySnapshot = false;
    size_t usedSnapshot = 0;
    size_t peakSnapshot = 0;
    size_t totalSnapshot = 0;
    AmprInternalAmmPoolStats stats{};
#endif

    {
        AmprSpinLock poolLock(&g_internal_amm_pool_lock);
        if (!g_internal_amm_pool_ready || !g_internal_amm_pool_base) {
#if AMPR_EMU_DEBUG_LOG
            failReason = "not-ready";
#endif
        } else {
            int selected = -1;
            size_t selectedAlignedOffset = 0;
            size_t selectedUsable = SIZE_MAX;
            for (int i = g_internal_amm_pool_head; i >= 0; i = g_internal_amm_pool_chunks[i].next) {
                AmprInternalAmmPoolChunk& candidate = g_internal_amm_pool_chunks[i];
                if (!ampr_internal_amm_pool_chunk_can_fit_locked(candidate,
                                                                 mappedSize,
                                                                 allocAlignment)) {
                    continue;
                }
                const size_t alignedOffset = ampr_internal_align_up_size_impl(candidate.offset,
                                                                         allocAlignment);
                const size_t usable = candidate.offset + candidate.size - alignedOffset;
                if (usable < selectedUsable) {
                    selected = i;
                    selectedAlignedOffset = alignedOffset;
                    selectedUsable = usable;
                }
            }
            if (selected < 0) {
#if AMPR_EMU_DEBUG_LOG
                failReason = "capacity";
#endif
            } else {
                AmprInternalAmmPoolChunk& chunk = g_internal_amm_pool_chunks[selected];
                const size_t oldOffset = chunk.offset;
                const size_t oldSize = chunk.size;
                const size_t oldEnd = oldOffset + oldSize;
                const size_t allocEnd = selectedAlignedOffset + mappedSize;
                const size_t prefixSize = selectedAlignedOffset - oldOffset;
                const size_t suffixSize = oldEnd - allocEnd;
                const int oldNext = chunk.next;
                int allocChunk = selected;
                int suffixChunk = -1;

                if (prefixSize != 0) {
                    allocChunk = ampr_internal_amm_pool_new_chunk_locked();
                    if (allocChunk < 0) {
                        failReason = "chunk-table-full";
                    } else {
                        chunk.size = prefixSize;
                        chunk.free = true;
                        g_internal_amm_pool_chunks[allocChunk].prev = selected;
                        g_internal_amm_pool_chunks[allocChunk].next = oldNext;
                        chunk.next = allocChunk;
                        if (oldNext >= 0) {
                            g_internal_amm_pool_chunks[oldNext].prev = allocChunk;
                        }
                    }
                }

                if (!failReason && suffixSize != 0) {
                    suffixChunk = ampr_internal_amm_pool_new_chunk_locked();
                    if (suffixChunk < 0) {
                        if (prefixSize != 0) {
                            chunk.next = oldNext;
                            chunk.size = oldSize;
                            if (oldNext >= 0) {
                                g_internal_amm_pool_chunks[oldNext].prev = selected;
                            }
                            g_internal_amm_pool_chunks[allocChunk] = {};
                        }
                        failReason = "chunk-table-full";
                    }
                }

                if (!failReason) {
                    AmprInternalAmmPoolChunk& allocated = g_internal_amm_pool_chunks[allocChunk];
                    allocated.offset = selectedAlignedOffset;
                    allocated.size = mappedSize;
                    allocated.free = false;
                    if (prefixSize == 0) {
                        allocated.prev = chunk.prev;
                        allocated.next = oldNext;
                    }

                    if (suffixChunk >= 0) {
                        AmprInternalAmmPoolChunk& suffix = g_internal_amm_pool_chunks[suffixChunk];
                        suffix.offset = allocEnd;
                        suffix.size = suffixSize;
                        suffix.free = true;
                        suffix.prev = allocChunk;
                        suffix.next = oldNext;
                        allocated.next = suffixChunk;
                        if (oldNext >= 0) {
                            g_internal_amm_pool_chunks[oldNext].prev = suffixChunk;
                        }
                    }

                    ptr = g_internal_amm_pool_base + selectedAlignedOffset;
                    g_internal_amm_pool_used += mappedSize;
                    if (g_internal_amm_pool_used > g_internal_amm_pool_peak_used) {
                        g_internal_amm_pool_peak_used = g_internal_amm_pool_used;
                    }
                    ok = true;
                }
            }
        }
#if AMPR_EMU_DEBUG_LOG
        readySnapshot = g_internal_amm_pool_ready;
        usedSnapshot = g_internal_amm_pool_used;
        peakSnapshot = g_internal_amm_pool_peak_used;
        totalSnapshot = g_internal_amm_pool_size;
        stats = ampr_internal_amm_pool_stats_locked();
#endif
    }

    if (!ok) {
        if (criticalOnFail) {
            AMPR_CRITICAL_LOGF("mem.internal_pool.alloc fail tag=%s reason=%s ready=%u used=0x%llx peak=0x%llx total=0x%llx free=0x%llx largestFree=0x%llx chunks=%llu usedChunks=%llu freeChunks=%llu request=0x%llx",
                               tag ? tag : "(null)",
                               failReason ? failReason : "unknown",
                               readySnapshot ? 1u : 0u,
                               (unsigned long long)usedSnapshot,
                               (unsigned long long)peakSnapshot,
                               (unsigned long long)totalSnapshot,
                               (unsigned long long)stats.freeBytes,
                               (unsigned long long)stats.largestFree,
                               (unsigned long long)stats.activeChunks,
                               (unsigned long long)stats.usedChunks,
                               (unsigned long long)stats.freeChunks,
                               (unsigned long long)mappedSize);
        } else {
            AMPR_LOGF("mem.internal_pool.alloc miss tag=%s reason=%s ready=%u used=0x%llx peak=0x%llx total=0x%llx free=0x%llx largestFree=0x%llx chunks=%llu usedChunks=%llu freeChunks=%llu request=0x%llx",
                      tag ? tag : "(null)",
                      failReason ? failReason : "unknown",
                      readySnapshot ? 1u : 0u,
                      (unsigned long long)usedSnapshot,
                      (unsigned long long)peakSnapshot,
                      (unsigned long long)totalSnapshot,
                      (unsigned long long)stats.freeBytes,
                      (unsigned long long)stats.largestFree,
                      (unsigned long long)stats.activeChunks,
                      (unsigned long long)stats.usedChunks,
                      (unsigned long long)stats.freeChunks,
                      (unsigned long long)mappedSize);
        }
        return nullptr;
    }
    if (outMappedSize) {
        *outMappedSize = mappedSize;
    }
    AMPR_LOGF("mem.internal_pool.alloc ok tag=%s ptr=%p size=0x%llx requested=0x%llx used=0x%llx peak=0x%llx total=0x%llx free=0x%llx largestFree=0x%llx chunks=%llu",
              tag ? tag : "(null)",
              ptr,
              (unsigned long long)mappedSize,
              (unsigned long long)size,
              (unsigned long long)usedSnapshot,
              (unsigned long long)peakSnapshot,
              (unsigned long long)totalSnapshot,
              (unsigned long long)stats.freeBytes,
              (unsigned long long)stats.largestFree,
              (unsigned long long)stats.activeChunks);
    return ptr;
}

static bool ampr_internal_amm_pool_free_impl(void* ptr, const char* tag) {
#if !AMPR_EMU_DEBUG_LOG
    (void)tag;
#endif
    if (!ptr) {
        return false;
    }
    bool ok = false;
#if AMPR_EMU_DEBUG_LOG
    const char* failReason = nullptr;
#endif
    size_t freedSize = 0;
#if AMPR_EMU_DEBUG_LOG
    size_t usedSnapshot = 0;
    size_t peakSnapshot = 0;
    size_t totalSnapshot = 0;
    AmprInternalAmmPoolStats stats{};
#endif
    {
        AmprSpinLock poolLock(&g_internal_amm_pool_lock);
        uint8_t* bytePtr = static_cast<uint8_t*>(ptr);
        const uintptr_t poolBase = reinterpret_cast<uintptr_t>(g_internal_amm_pool_base);
        const uintptr_t poolEnd = poolBase + g_internal_amm_pool_size;
        const uintptr_t byteAddr = reinterpret_cast<uintptr_t>(bytePtr);
        if (!g_internal_amm_pool_ready || !g_internal_amm_pool_base ||
            poolEnd < poolBase || byteAddr < poolBase || byteAddr >= poolEnd) {
#if AMPR_EMU_DEBUG_LOG
            failReason = "outside-pool";
#endif
        } else {
            const size_t offset = static_cast<size_t>(byteAddr - poolBase);
            int cur = -1;
            for (int i = g_internal_amm_pool_head; i >= 0; i = g_internal_amm_pool_chunks[i].next) {
                const AmprInternalAmmPoolChunk& candidate = g_internal_amm_pool_chunks[i];
                if (candidate.active && !candidate.free && candidate.offset == offset) {
                    cur = i;
                    break;
                }
            }
            if (cur < 0) {
#if AMPR_EMU_DEBUG_LOG
                failReason = "not-allocated";
#endif
            } else {
                AmprInternalAmmPoolChunk& chunk = g_internal_amm_pool_chunks[cur];
                freedSize = chunk.size;
                chunk.free = true;
                g_internal_amm_pool_used =
                    freedSize <= g_internal_amm_pool_used ? g_internal_amm_pool_used - freedSize : 0;

                if (chunk.prev >= 0 && g_internal_amm_pool_chunks[chunk.prev].active &&
                    g_internal_amm_pool_chunks[chunk.prev].free) {
                    const int prev = chunk.prev;
                    AmprInternalAmmPoolChunk& prevChunk = g_internal_amm_pool_chunks[prev];
                    prevChunk.size += chunk.size;
                    prevChunk.next = chunk.next;
                    if (chunk.next >= 0) {
                        g_internal_amm_pool_chunks[chunk.next].prev = prev;
                    }
                    g_internal_amm_pool_chunks[cur] = {};
                    cur = prev;
                }

                AmprInternalAmmPoolChunk& merged = g_internal_amm_pool_chunks[cur];
                if (merged.next >= 0 && g_internal_amm_pool_chunks[merged.next].active &&
                    g_internal_amm_pool_chunks[merged.next].free) {
                    const int next = merged.next;
                    AmprInternalAmmPoolChunk& nextChunk = g_internal_amm_pool_chunks[next];
                    merged.size += nextChunk.size;
                    merged.next = nextChunk.next;
                    if (nextChunk.next >= 0) {
                        g_internal_amm_pool_chunks[nextChunk.next].prev = cur;
                    }
                    g_internal_amm_pool_chunks[next] = {};
                }

                ok = true;
            }
        }
#if AMPR_EMU_DEBUG_LOG
        usedSnapshot = g_internal_amm_pool_used;
        peakSnapshot = g_internal_amm_pool_peak_used;
        totalSnapshot = g_internal_amm_pool_size;
        stats = ampr_internal_amm_pool_stats_locked();
#endif
    }

    if (!ok) {
        AMPR_LOGF("mem.internal_pool.free skip tag=%s ptr=%p reason=%s",
                  tag ? tag : "(null)",
                  ptr,
                  failReason ? failReason : "unknown");
        return false;
    }

    AMPR_LOGF("mem.internal_pool.free ok tag=%s ptr=%p size=0x%llx used=0x%llx peak=0x%llx total=0x%llx free=0x%llx largestFree=0x%llx chunks=%llu",
              tag ? tag : "(null)",
              ptr,
              (unsigned long long)freedSize,
              (unsigned long long)usedSnapshot,
              (unsigned long long)peakSnapshot,
              (unsigned long long)totalSnapshot,
              (unsigned long long)stats.freeBytes,
              (unsigned long long)stats.largestFree,
              (unsigned long long)stats.activeChunks);
    return true;
}

enum class AmprRuntimeMemoryOwner : uint8_t {
    None,
    Pool,
    SmallSlab,
    Flexible,
};

struct AmprRuntimeMemoryBlock {
    void* base{};
    size_t size{};
    AmprRuntimeMemoryOwner owner{AmprRuntimeMemoryOwner::None};
};

enum class AmprSdkCpuMemoryClass : uint8_t {
    Persistent,
    Transient,
};

static std::atomic<uint32_t> g_sdk_cpu_memory_stats_lock{0};
static size_t g_sdk_cpu_persistent_live = 0;
static size_t g_sdk_cpu_persistent_peak = 0;
static size_t g_sdk_cpu_transient_live = 0;
static size_t g_sdk_cpu_transient_peak = 0;

static const char* ampr_sdk_cpu_memory_class_name_impl(AmprSdkCpuMemoryClass memoryClass) {
    return memoryClass == AmprSdkCpuMemoryClass::Transient ? "transient" : "persistent";
}

static void ampr_sdk_cpu_memory_note_alloc_impl(AmprSdkCpuMemoryClass memoryClass, size_t size) {
    AmprSpinLock lock(&g_sdk_cpu_memory_stats_lock);
    size_t* live = memoryClass == AmprSdkCpuMemoryClass::Transient
        ? &g_sdk_cpu_transient_live
        : &g_sdk_cpu_persistent_live;
    size_t* peak = memoryClass == AmprSdkCpuMemoryClass::Transient
        ? &g_sdk_cpu_transient_peak
        : &g_sdk_cpu_persistent_peak;
    if (*live <= SIZE_MAX - size) {
        *live += size;
    } else {
        *live = SIZE_MAX;
    }
    if (*peak < *live) {
        *peak = *live;
    }
}

static void ampr_sdk_cpu_memory_note_free_impl(AmprSdkCpuMemoryClass memoryClass, size_t size) {
    AmprSpinLock lock(&g_sdk_cpu_memory_stats_lock);
    size_t* live = memoryClass == AmprSdkCpuMemoryClass::Transient
        ? &g_sdk_cpu_transient_live
        : &g_sdk_cpu_persistent_live;
    *live = size <= *live ? *live - size : 0;
}

static void ampr_sdk_cpu_memory_log_summary_impl(const char* reason) {
#if AMPR_EMU_DEBUG_LOG
    if (!ampr_debug_log_runtime_enabled()) {
        return;
    }
    size_t persistentLive = 0;
    size_t persistentPeak = 0;
    size_t transientLive = 0;
    size_t transientPeak = 0;
    {
        AmprSpinLock lock(&g_sdk_cpu_memory_stats_lock);
        persistentLive = g_sdk_cpu_persistent_live;
        persistentPeak = g_sdk_cpu_persistent_peak;
        transientLive = g_sdk_cpu_transient_live;
        transientPeak = g_sdk_cpu_transient_peak;
    }
    AMPR_LOGF("mem.sdk_cpu.summary reason=%s persistentLive=0x%llx persistentPeak=0x%llx transientLive=0x%llx transientPeak=0x%llx",
              reason ? reason : "(null)",
              (unsigned long long)persistentLive,
              (unsigned long long)persistentPeak,
              (unsigned long long)transientLive,
              (unsigned long long)transientPeak);
#else
    (void)reason;
#endif
}

static constexpr size_t kAmprSmallSlabClassCount = 4;
static constexpr size_t kAmprSmallSlabMaxPages = 64;
static constexpr size_t kAmprSmallSlabClassSizes[kAmprSmallSlabClassCount] = {
    256u,
    1024u,
    2048u,
    SCE_KERNEL_PAGE_SIZE,
};

static AmprSharedExactSlabBlock g_small_slab_blocks[kAmprSmallSlabMaxPages]{};
static AmprSharedExactSlabPool g_small_slab_pool{};

static size_t ampr_small_slab_class_index(size_t size, size_t alignment) {
    if (size == 0) {
        return SIZE_MAX;
    }
    if (alignment == 0) {
        alignment = 1;
    }
    if ((alignment & (alignment - 1u)) != 0) {
        return SIZE_MAX;
    }
    for (size_t i = 0; i < kAmprSmallSlabClassCount; ++i) {
        const size_t slotSize = kAmprSmallSlabClassSizes[i];
        if (size <= slotSize && alignment <= slotSize) {
            return i;
        }
    }
    return SIZE_MAX;
}

static bool ampr_small_slab_eligible_impl(size_t size, size_t alignment) {
    return ampr_small_slab_class_index(size, alignment) != SIZE_MAX;
}

static AmprSharedExactSlabPool* ampr_small_slab_pool() {
    ampr_exact_slab_pool_init(&g_small_slab_pool,
                                     g_small_slab_blocks,
                                     kAmprSmallSlabMaxPages);
    return &g_small_slab_pool;
}

static void* ampr_small_slab_alloc_impl(size_t size,
                                   size_t alignment,
                                   size_t* outSlotSize,
                                   const char* tag,
                                   bool mayCreatePool) {
    if (outSlotSize) {
        *outSlotSize = 0;
    }
    const size_t classIndex = ampr_small_slab_class_index(size, alignment);
    if (classIndex == SIZE_MAX) {
        return nullptr;
    }
    const size_t slotSize = kAmprSmallSlabClassSizes[classIndex];
    return ampr_exact_slab_alloc(ampr_small_slab_pool(),
                                        slotSize,
                                        slotSize,
                                        SCE_KERNEL_PAGE_SIZE,
                                        outSlotSize,
                                        tag,
                                        mayCreatePool,
                                        false);
}

static bool ampr_small_slab_free_impl(void* ptr, const char* tag, size_t* outSlotSize = nullptr) {
    return ampr_exact_slab_free(ampr_small_slab_pool(), ptr, tag, outSlotSize, true);
}

static size_t ampr_exact_slab_block_bytes(size_t slotSize, size_t minBlockBytes) {
    const size_t minBytes = slotSize > minBlockBytes ? slotSize : minBlockBytes;
    return ampr_internal_align_up_size_impl(minBytes, SCE_KERNEL_PAGE_SIZE);
}

static AmprSharedExactSlabBlock* ampr_exact_slab_find_block_locked(
    AmprSharedExactSlabPool& pool,
    size_t slotSize) {
    for (size_t i = 0; i < pool.blockCapacity; ++i) {
        AmprSharedExactSlabBlock& block = pool.blocks[i];
        if (block.active && block.slotSize == slotSize &&
            block.freeHead != kAmprSharedExactSlabInvalid) {
            return &block;
        }
    }
    return nullptr;
}

static AmprSharedExactSlabBlock* ampr_exact_slab_publish_block_locked(
    AmprSharedExactSlabPool& pool,
    size_t slotSize,
    void* base,
    size_t bytes,
    const char* tag) {
    AmprSharedExactSlabBlock* meta = nullptr;
    for (size_t i = 0; i < pool.blockCapacity; ++i) {
        AmprSharedExactSlabBlock& block = pool.blocks[i];
        if (!block.active && !block.base) {
            meta = &block;
            break;
        }
    }
    if (!meta || !base || bytes < slotSize) {
        AMPR_CRITICAL_LOGF("mem.exact_slab.block fail tag=%s reason=metadata-full slot=0x%llx bytes=0x%llx blocks=%llu capacity=%llu",
                           tag ? tag : "(null)",
                           (unsigned long long)slotSize,
                           (unsigned long long)bytes,
                           (unsigned long long)pool.blockCount,
                           (unsigned long long)pool.blockCapacity);
        return nullptr;
    }

    const size_t slotCountSize = bytes / slotSize;
    if (slotCountSize == 0 || slotCountSize > static_cast<size_t>(UINT32_MAX)) {
        return nullptr;
    }

    meta->base = static_cast<uint8_t*>(base);
    meta->slotSize = slotSize;
    meta->slotCount = static_cast<uint32_t>(slotCountSize);
    meta->freeCount = meta->slotCount;
    meta->freeHead = 0;
    meta->active = true;
    for (uint32_t i = 0; i < meta->slotCount; ++i) {
        uint32_t* next = reinterpret_cast<uint32_t*>(meta->base + static_cast<size_t>(i) * slotSize);
        *next = (i + 1u < meta->slotCount) ? i + 1u : kAmprSharedExactSlabInvalid;
    }
    ++pool.blockCount;
    AMPR_LOGF("mem.exact_slab.block ok tag=%s slot=0x%llx slots=%u bytes=0x%llx base=%p blocks=%llu",
              tag ? tag : "(null)",
              (unsigned long long)slotSize,
              static_cast<unsigned>(meta->slotCount),
              (unsigned long long)bytes,
              base,
              (unsigned long long)pool.blockCount);
    return meta;
}

static void* ampr_exact_slab_take_slot_locked(AmprSharedExactSlabBlock& block,
                                              size_t* outSlotSize) {
    const uint32_t slotIndex = block.freeHead;
    if (slotIndex == kAmprSharedExactSlabInvalid || slotIndex >= block.slotCount) {
        return nullptr;
    }
    uint8_t* slot = block.base + static_cast<size_t>(slotIndex) * block.slotSize;
    block.freeHead = *reinterpret_cast<uint32_t*>(slot);
    --block.freeCount;
    if (outSlotSize) {
        *outSlotSize = block.slotSize;
    }
    return slot;
}

static bool ampr_exact_slab_slot_is_free_locked(const AmprSharedExactSlabBlock& block,
                                                uint32_t slotIndex) {
    uint32_t current = block.freeHead;
    for (uint32_t steps = 0;
         current != kAmprSharedExactSlabInvalid && steps < block.slotCount;
         ++steps) {
        if (current == slotIndex) {
            return true;
        }
        if (current >= block.slotCount) {
            return false;
        }
        const uint8_t* slot = block.base + static_cast<size_t>(current) * block.slotSize;
        current = *reinterpret_cast<const uint32_t*>(slot);
    }
    return false;
}

static void* ampr_exact_slab_alloc_block(size_t slotSize,
                                         size_t minBlockBytes,
                                         const char* tag,
                                         bool mayCreatePool,
                                         bool requireAprVisible,
                                         size_t* outBytes) {
    if (outBytes) {
        *outBytes = 0;
    }
    const size_t blockBytes = ampr_exact_slab_block_bytes(slotSize, minBlockBytes);
    if (blockBytes == 0 || blockBytes == SIZE_MAX) {
        return nullptr;
    }
    if (mayCreatePool) {
        if (!ampr_internal_amm_pool_ensure_impl(blockBytes, tag)) {
            return nullptr;
        }
    } else if (!ampr_internal_amm_pool_ready_has_capacity_impl(blockBytes)) {
        return nullptr;
    }
    if (requireAprVisible) {
        AmprSpinLock poolLock(&g_internal_amm_pool_lock);
        if (!g_internal_amm_pool_ready || !g_internal_amm_pool_apr_visible) {
            return nullptr;
        }
    }

    size_t actualBytes = 0;
    void* block = ampr_internal_amm_pool_alloc_impl(blockBytes,
                                               &actualBytes,
                                               tag,
                                               false,
                                               SCE_KERNEL_PAGE_SIZE);
    if (!block || actualBytes < blockBytes) {
        if (block) {
            (void)ampr_internal_amm_pool_free_impl(block, tag);
        }
        return nullptr;
    }
    if (outBytes) {
        *outBytes = actualBytes;
    }
    return block;
}

static void* ampr_runtime_alloc_from_pool_only_impl(const char* tag,
                                               size_t size,
                                               AmprRuntimeMemoryBlock* out,
                                               size_t alignment = alignof(std::max_align_t)) {
    if (out) *out = {};
    size_t slabSize = 0;
    void* slab = ampr_small_slab_alloc_impl(size, alignment, &slabSize, tag, true);
    if (slab) {
        std::memset(slab, 0, slabSize);
        if (out) {
            out->base = slab;
            out->size = slabSize;
            out->owner = AmprRuntimeMemoryOwner::SmallSlab;
        }
        return slab;
    }

    size_t poolSize = 0;
    void* pool = ampr_internal_amm_pool_alloc_impl(size, &poolSize, tag, true, alignment);
    if (!pool) {
        return nullptr;
    }
    std::memset(pool, 0, poolSize);
    if (out) {
        out->base = pool;
        out->size = poolSize;
        out->owner = AmprRuntimeMemoryOwner::Pool;
    }
    return pool;
}

static std::atomic<uint32_t> g_lazy_state_init_lock{0};

struct AmprLazyStateInitLock {
    explicit AmprLazyStateInitLock(std::atomic<uint32_t>& state) : state_(state) {
        for (;;) {
            uint32_t expected = 0;
            if (state_.compare_exchange_weak(expected,
                                             1u,
                                             std::memory_order_acquire,
                                             std::memory_order_relaxed)) {
                return;
            }
            uint32_t spins = 0;
            while (state_.load(std::memory_order_relaxed) != 0) {
                ampr_spin_pause_or_yield(spins);
            }
        }
    }

    ~AmprLazyStateInitLock() {
        state_.store(0, std::memory_order_release);
    }

    AmprLazyStateInitLock(const AmprLazyStateInitLock&) = delete;
    AmprLazyStateInitLock& operator=(const AmprLazyStateInitLock&) = delete;

private:
    std::atomic<uint32_t>& state_;
};

template <typename T>
static T* ampr_lazy_state_ptr(std::atomic<T*>* slot) {
    // Lazy state avoids global ctor/dtor ordering in the PRX.
    T* p = slot->load(std::memory_order_acquire);
    if (p) return p;

    AmprLazyStateInitLock initLock(g_lazy_state_init_lock);
    p = slot->load(std::memory_order_acquire);
    if (p) return p;

    void* storage = ampr_runtime_alloc_from_pool_only_impl("lazy.state",
                                                      sizeof(T),
                                                      nullptr,
                                                      alignof(T));
    if (!storage) {
        alignas(T) static unsigned char staticStorage[sizeof(T)];
        static bool staticUsed = false;
        if (staticUsed) {
            return nullptr;
        }
        storage = staticStorage;
        staticUsed = true;
        std::memset(storage, 0, sizeof(T));
        AMPR_CRITICAL_LOGF("mem.lazy.static tag=lazy.state typeSize=0x%llx",
                           (unsigned long long)sizeof(T));
    }
    T* np = new (storage) T();
    slot->store(np, std::memory_order_release);
    return np;
}

template <typename T>
static T& ampr_lazy_state_ref(std::atomic<T*>* slot) {
    T* p = ampr_lazy_state_ptr(slot);
    if (!p) __builtin_trap();
    return *p;
}
} // namespace


#if defined(__clang__)
#pragma clang diagnostic pop
#endif

static AmprSdkCpuMemoryClass ampr_memory_class_to_runtime(AmprSharedSdkCpuMemoryClass memoryClass) {
    return memoryClass == AmprSharedSdkCpuMemoryClass::Transient
        ? AmprSdkCpuMemoryClass::Transient
        : AmprSdkCpuMemoryClass::Persistent;
}

size_t ampr_internal_align_up_size(size_t value, size_t alignment) {
    return ampr_internal_align_up_size_impl(value, alignment);
}

bool ampr_internal_amm_pool_ensure(size_t requiredSize, const char* reason) {
    return ampr_internal_amm_pool_ensure_impl(requiredSize, reason);
}

bool ampr_internal_amm_pool_ready_has_capacity(size_t size, size_t alignment) {
    return ampr_internal_amm_pool_ready_has_capacity_impl(size, alignment);
}

bool ampr_internal_amm_pool_apr_visible() {
    AmprSpinLock poolLock(&g_internal_amm_pool_lock);
    return g_internal_amm_pool_ready && g_internal_amm_pool_apr_visible;
}

void* ampr_internal_amm_pool_alloc(size_t size,
                                          size_t* outSize,
                                          const char* tag,
                                          bool mayCreatePool,
                                          size_t alignment) {
    return ampr_internal_amm_pool_alloc_impl(size, outSize, tag, mayCreatePool, alignment);
}

bool ampr_internal_amm_pool_free(void* ptr, const char* tag) {
    return ampr_internal_amm_pool_free_impl(ptr, tag);
}

void ampr_internal_amm_pool_log_summary(const char* reason) {
    ampr_internal_amm_pool_log_summary_impl(reason);
}

bool ampr_internal_amm_pool_prepare_static_storage(const char* reason) {
    return ampr_internal_amm_pool_prepare_static_storage_impl(reason);
}

void ampr_runtime_memory_log_heartbeat(const char* reason) {
#if AMPR_EMU_DEBUG_LOG
    if (!ampr_debug_log_runtime_enabled()) {
        return;
    }
    const char* const tag = reason ? reason : "heartbeat";
    ampr_internal_amm_pool_log_summary_impl(tag);
    ampr_sdk_cpu_memory_log_summary_impl(tag);
#else
    (void)reason;
#endif
}

bool ampr_small_slab_eligible(size_t size, size_t alignment) {
    return ampr_small_slab_eligible_impl(size, alignment);
}

void* ampr_small_slab_alloc(size_t size,
                                   size_t alignment,
                                   size_t* outSlotSize,
                                   const char* tag,
                                   bool mayCreatePool) {
    return ampr_small_slab_alloc_impl(size, alignment, outSlotSize, tag, mayCreatePool);
}

bool ampr_small_slab_free(void* ptr, const char* tag, size_t* outSlotSize) {
    return ampr_small_slab_free_impl(ptr, tag, outSlotSize);
}

void ampr_exact_slab_pool_init(AmprSharedExactSlabPool* pool,
                                      AmprSharedExactSlabBlock* blocks,
                                      size_t blockCapacity) {
    if (!pool || !blocks || blockCapacity == 0) {
        return;
    }
    AmprSpinLock lock(&pool->lock);
    if (!pool->blocks) {
        pool->blocks = blocks;
        pool->blockCapacity = blockCapacity;
        pool->blockCount = 0;
        std::memset(blocks, 0, sizeof(AmprSharedExactSlabBlock) * blockCapacity);
    }
}

void* ampr_exact_slab_alloc(AmprSharedExactSlabPool* pool,
                                   size_t size,
                                   size_t alignment,
                                   size_t minBlockBytes,
                                   size_t* outSlotSize,
                                   const char* tag,
                                   bool mayCreatePool,
                                   bool requireAprVisible) {
    if (outSlotSize) {
        *outSlotSize = 0;
    }
    if (!pool || !pool->blocks || pool->blockCapacity == 0) {
        return nullptr;
    }
    const size_t slotSize = ampr_internal_align_up_size_impl(size, alignment);
    if (slotSize == 0 || slotSize == SIZE_MAX || slotSize < sizeof(uint32_t)) {
        return nullptr;
    }

    for (;;) {
        {
            AmprSpinLock lock(&pool->lock);
            if (AmprSharedExactSlabBlock* block =
                    ampr_exact_slab_find_block_locked(*pool, slotSize)) {
                return ampr_exact_slab_take_slot_locked(*block, outSlotSize);
            }
        }

        size_t blockBytes = 0;
        void* newBlock = ampr_exact_slab_alloc_block(slotSize,
                                                     minBlockBytes,
                                                     tag,
                                                     mayCreatePool,
                                                     requireAprVisible,
                                                     &blockBytes);
        if (!newBlock) {
            AmprSpinLock lock(&pool->lock);
            if (AmprSharedExactSlabBlock* block =
                    ampr_exact_slab_find_block_locked(*pool, slotSize)) {
                return ampr_exact_slab_take_slot_locked(*block, outSlotSize);
            }
            return nullptr;
        }

        void* extraBlock = nullptr;
        void* result = nullptr;
        {
            AmprSpinLock lock(&pool->lock);
            AmprSharedExactSlabBlock* block =
                ampr_exact_slab_find_block_locked(*pool, slotSize);
            if (block) {
                extraBlock = newBlock;
            } else {
                block = ampr_exact_slab_publish_block_locked(*pool,
                                                             slotSize,
                                                             newBlock,
                                                             blockBytes,
                                                             tag);
                if (block) {
                    newBlock = nullptr;
                }
            }
            if (block) {
                result = ampr_exact_slab_take_slot_locked(*block, outSlotSize);
            }
        }
        if (extraBlock) {
            (void)ampr_internal_amm_pool_free_impl(extraBlock, tag);
            newBlock = nullptr;
        }
        if (result) {
            return result;
        }
        if (newBlock) {
            (void)ampr_internal_amm_pool_free_impl(newBlock, tag);
        }
        return nullptr;
    }
}

bool ampr_exact_slab_free(AmprSharedExactSlabPool* pool,
                                 void* ptr,
                                 const char* tag,
                                 size_t* outSlotSize,
                                 bool releaseRedundantEmptyBlocks,
                                 bool releaseEmptyBlocksAlways) {
    if (outSlotSize) {
        *outSlotSize = 0;
    }
    if (!pool || !ptr || !pool->blocks || pool->blockCapacity == 0) {
        return false;
    }
    const uintptr_t addr = reinterpret_cast<uintptr_t>(ptr);
    void* blockToRelease = nullptr;
    bool found = false;
    {
        AmprSpinLock lock(&pool->lock);
        for (size_t i = 0; i < pool->blockCapacity; ++i) {
            AmprSharedExactSlabBlock& block = pool->blocks[i];
            if (!block.active || !block.base || block.slotSize == 0) {
                continue;
            }
            const uintptr_t base = reinterpret_cast<uintptr_t>(block.base);
            const uintptr_t end = base + static_cast<uintptr_t>(block.slotSize) * block.slotCount;
            if (addr < base || addr >= end) {
                continue;
            }
            const size_t offset = static_cast<size_t>(addr - base);
            if ((offset % block.slotSize) != 0 || block.freeCount >= block.slotCount) {
                AMPR_LOGF("mem.exact_slab.free skip tag=%s ptr=%p slot=0x%llx reason=invalid",
                          tag ? tag : "(null)",
                          ptr,
                          (unsigned long long)block.slotSize);
                return false;
            }
            const uint32_t slotIndex = static_cast<uint32_t>(offset / block.slotSize);
            if (ampr_exact_slab_slot_is_free_locked(block, slotIndex)) {
                AMPR_LOGF("mem.exact_slab.free skip tag=%s ptr=%p slot=0x%llx reason=already-free",
                          tag ? tag : "(null)",
                          ptr,
                          (unsigned long long)block.slotSize);
                return false;
            }
            *reinterpret_cast<uint32_t*>(ptr) = block.freeHead;
            block.freeHead = slotIndex;
            ++block.freeCount;
            if (outSlotSize) {
                *outSlotSize = block.slotSize;
            }

            if (releaseRedundantEmptyBlocks && block.freeCount == block.slotCount) {
                bool releaseEmptyBlock = releaseEmptyBlocksAlways;
                if (!releaseEmptyBlock) {
                    for (size_t otherIndex = 0; otherIndex < pool->blockCapacity; ++otherIndex) {
                        const AmprSharedExactSlabBlock& other = pool->blocks[otherIndex];
                        if (otherIndex != i &&
                            other.active &&
                            other.slotSize == block.slotSize &&
                            other.freeCount == other.slotCount) {
                            releaseEmptyBlock = true;
                            break;
                        }
                    }
                }
                if (releaseEmptyBlock) {
                    blockToRelease = block.base;
                    block = {};
                    if (pool->blockCount != 0) {
                        --pool->blockCount;
                    }
                }
            }
            found = true;
            break;
        }
    }
    if (blockToRelease) {
        (void)ampr_internal_amm_pool_free_impl(blockToRelease, tag);
    }
    if (!found) {
        AMPR_LOGF("mem.exact_slab.free skip tag=%s ptr=%p reason=not-owned",
                  tag ? tag : "(null)",
                  ptr);
    }
    return found;
}

const char* ampr_sdk_cpu_memory_class_name(AmprSharedSdkCpuMemoryClass memoryClass) {
    return ampr_sdk_cpu_memory_class_name_impl(ampr_memory_class_to_runtime(memoryClass));
}

void ampr_sdk_cpu_memory_note_alloc(AmprSharedSdkCpuMemoryClass memoryClass, size_t size) {
    ampr_sdk_cpu_memory_note_alloc_impl(ampr_memory_class_to_runtime(memoryClass), size);
}

void ampr_sdk_cpu_memory_note_free(AmprSharedSdkCpuMemoryClass memoryClass, size_t size) {
    ampr_sdk_cpu_memory_note_free_impl(ampr_memory_class_to_runtime(memoryClass), size);
}

void ampr_sdk_cpu_memory_log_summary(const char* reason) {
    ampr_sdk_cpu_memory_log_summary_impl(reason);
}

void* ampr_runtime_alloc_from_pool_only(const char* tag,
                                               size_t size,
                                               AmprSharedRuntimeMemoryBlock* out,
                                               size_t alignment) {
    if (out) *out = {};

    size_t slabSize = 0;
    void* slab = ampr_small_slab_alloc_impl(size, alignment, &slabSize, tag, true);
    if (slab) {
        std::memset(slab, 0, slabSize);
        if (out) {
            out->base = slab;
            out->size = slabSize;
            out->owner = AmprSharedRuntimeMemoryOwner::SmallSlab;
        }
        return slab;
    }

    size_t poolSize = 0;
    void* pool = ampr_internal_amm_pool_alloc_impl(size, &poolSize, tag, true, alignment);
    if (!pool) {
        return nullptr;
    }
    std::memset(pool, 0, poolSize);
    if (out) {
        out->base = pool;
        out->size = poolSize;
        out->owner = AmprSharedRuntimeMemoryOwner::Pool;
    }
    return pool;
}
