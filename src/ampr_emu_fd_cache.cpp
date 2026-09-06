/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Internal APR fd-cache runtime module.
 */

#include "ampr_emu_fd_cache.h"
#include "ampr_emu_index.h"
#include "ampr_emu_kernel_file.h"
#include "ampr_emu_log.h"
#include "ampr_emu_sync.h"
#include "ampr_emu_errno.h"

#include <atomic>
#include <cstdlib>
#include <new>

[[maybe_unused]] static inline const char* ampr_log_path_arg(const char* path) {
    return path ? path : "(null)";
}
namespace {
static_assert(AMPR_EMU_FD_CACHE_PROTECTED_PERCENT <= 100u,
              "FD-cache protected SLRU percentage must be <= 100");

static void fd_cache_invariant_violation(const char* reason,
                                         size_t value = 0,
                                         size_t expected = 0) {
    (void)reason;
    (void)value;
    (void)expected;
    AMPR_CRITICAL_LOGF("apr.fdcache.invariant reason=%s value=%zu expected=%zu",
                       reason ? reason : "unknown",
                       value,
                       expected);
}

struct FileState {
    AmprMutex m;
    static constexpr uint32_t kInvalidRuntimeIndex = UINT32_MAX;
    enum class Segment : uint8_t {
        Probationary = 0,
        Protected = 1,
        Count = 2,
    };
    struct RuntimeFile {
        uint32_t id{0};
        int fd{-1};
        uint64_t lastUseTick{0};
        uint64_t lastUseNs{0};
        uint32_t pinCount{0};
        uint32_t lruPrev{kInvalidRuntimeIndex};
        uint32_t lruNext{kInvalidRuntimeIndex};
        uint32_t hashNextPlusOne{0};
        uint32_t freeNext{kInvalidRuntimeIndex};
        uint32_t closedNext{kInvalidRuntimeIndex};
        Segment segment{Segment::Probationary};
        bool active{false};
        bool physicalFd{false};
        bool onUnpinnedOpenList{false};
        bool onClosedList{false};
    };
    static constexpr size_t kRuntimeCapacity =
        AMPR_EMU_FD_CACHE_CAP > 0 ? AMPR_EMU_FD_CACHE_CAP : 1;
    static constexpr size_t kRuntimeHashBucketCount = kRuntimeCapacity * 2u + 1u;
    RuntimeFile runtime[kRuntimeCapacity]{};
    uint32_t runtimeHashHeads[kRuntimeHashBucketCount]{};
    std::atomic<uint64_t> tick{1};
    size_t activeCount{0};
    size_t openCount{0};
    size_t pinnedOpenCount{0};
    size_t openPinCount{0};
    size_t evictableOpenCount{0};
    size_t physicalOpenCount{0};
    size_t physicalPinnedOpenCount{0};
    size_t physicalOpenPinCount{0};
    size_t physicalEvictableOpenCount{0};
    uint32_t segmentHead[static_cast<size_t>(Segment::Count)]{
        kInvalidRuntimeIndex, kInvalidRuntimeIndex};
    uint32_t segmentTail[static_cast<size_t>(Segment::Count)]{
        kInvalidRuntimeIndex, kInvalidRuntimeIndex};
    size_t segmentCount[static_cast<size_t>(Segment::Count)]{};
    uint64_t slruPromotions{};
    uint64_t slruDemotions{};
    uint64_t slruProbationaryEvictions{};
    uint64_t slruProtectedEvictions{};
    uint32_t freeHead{kInvalidRuntimeIndex};
    uint32_t closedHead{kInvalidRuntimeIndex};
    size_t freeCount{0};
    size_t closedCount{0};
    bool listsReady{false};
};
static std::atomic<FileState*> g_file_state{nullptr};
alignas(FileState) static unsigned char g_file_state_storage[sizeof(FileState)];
static std::atomic<uint32_t> g_file_state_init{0};

static FileState* file_state_create() {
    FileState* p = g_file_state.load(std::memory_order_acquire);
    if (p) return p;

    uint32_t expected = 0;
    if (g_file_state_init.compare_exchange_strong(expected,
                                                  1u,
                                                  std::memory_order_acq_rel,
                                                  std::memory_order_acquire)) {
        p = new (g_file_state_storage) FileState();
        g_file_state.store(p, std::memory_order_release);
        g_file_state_init.store(2u, std::memory_order_release);
        return p;
    }

    uint32_t spins = 0;
    while (g_file_state_init.load(std::memory_order_acquire) != 2u) {
        ampr_spin_pause_or_yield(spins);
    }
    p = g_file_state.load(std::memory_order_acquire);
    if (!p) {
        AMPR_KLOGF("ampr.abort reason=apr.fdcache.state-init.null file=%s line=%d", __FILE__, __LINE__);
        std::abort();
    }
    return p;
}

static FileState& file_state() { return *file_state_create(); }

static size_t fd_runtime_hash_bucket(uint32_t id) {
    return (static_cast<uint64_t>(id) * 2654435761ull) % FileState::kRuntimeHashBucketCount;
}

static uint32_t fd_runtime_index_locked(FileState& fs, const FileState::RuntimeFile* entry) {
    if (!entry) {
        return FileState::kInvalidRuntimeIndex;
    }
    const auto* base = fs.runtime;
    if (entry < base || entry >= base + FileState::kRuntimeCapacity) {
        return FileState::kInvalidRuntimeIndex;
    }
    return static_cast<uint32_t>(entry - base);
}

static void fd_runtime_closed_unlink_locked(FileState& fs, FileState::RuntimeFile& entry) {
    if (!entry.onClosedList) {
        entry.closedNext = FileState::kInvalidRuntimeIndex;
        return;
    }
    const uint32_t index = fd_runtime_index_locked(fs, &entry);
    uint32_t* link = &fs.closedHead;
    while (*link != FileState::kInvalidRuntimeIndex) {
        if (*link == index) {
            *link = entry.closedNext;
            if (fs.closedCount != 0) {
                --fs.closedCount;
            }
            break;
        }
        link = &fs.runtime[*link].closedNext;
    }
    entry.closedNext = FileState::kInvalidRuntimeIndex;
    entry.onClosedList = false;
}

static void fd_runtime_closed_push_locked(FileState& fs, FileState::RuntimeFile& entry) {
    if (!entry.active || entry.fd >= 0 || entry.pinCount != 0 || entry.onClosedList) {
        return;
    }
    const uint32_t index = fd_runtime_index_locked(fs, &entry);
    if (index == FileState::kInvalidRuntimeIndex) {
        return;
    }
    entry.closedNext = fs.closedHead;
    entry.onClosedList = true;
    fs.closedHead = index;
    ++fs.closedCount;
}

static void fd_runtime_lists_ensure_locked(FileState& fs) {
    if (fs.listsReady) {
        return;
    }
    fs.freeHead = FileState::kInvalidRuntimeIndex;
    fs.closedHead = FileState::kInvalidRuntimeIndex;
    fs.freeCount = 0;
    fs.closedCount = 0;
    for (size_t segment = 0;
         segment < static_cast<size_t>(FileState::Segment::Count);
         ++segment) {
        fs.segmentHead[segment] = FileState::kInvalidRuntimeIndex;
        fs.segmentTail[segment] = FileState::kInvalidRuntimeIndex;
        fs.segmentCount[segment] = 0;
    }
    for (uint32_t i = 0; i < FileState::kRuntimeCapacity; ++i) {
        FileState::RuntimeFile& entry = fs.runtime[i];
        entry.freeNext = FileState::kInvalidRuntimeIndex;
        entry.closedNext = FileState::kInvalidRuntimeIndex;
        entry.onClosedList = false;
        entry.onUnpinnedOpenList = false;
        entry.lruPrev = FileState::kInvalidRuntimeIndex;
        entry.lruNext = FileState::kInvalidRuntimeIndex;
        if (!entry.active) {
            entry.freeNext = fs.freeHead;
            fs.freeHead = i;
            ++fs.freeCount;
        } else if (entry.fd < 0 && entry.pinCount == 0) {
            fd_runtime_closed_push_locked(fs, entry);
        }
    }
    fs.listsReady = true;
}

static FileState::RuntimeFile* fd_runtime_pop_free_locked(FileState& fs) {
    fd_runtime_lists_ensure_locked(fs);
    if (fs.freeHead == FileState::kInvalidRuntimeIndex) {
        return nullptr;
    }
    const uint32_t index = fs.freeHead;
    FileState::RuntimeFile& entry = fs.runtime[index];
    fs.freeHead = entry.freeNext;
    entry.freeNext = FileState::kInvalidRuntimeIndex;
    if (fs.freeCount != 0) {
        --fs.freeCount;
    }
    return &entry;
}

static FileState::RuntimeFile* fd_runtime_pop_closed_locked(FileState& fs) {
    fd_runtime_lists_ensure_locked(fs);
    while (fs.closedHead != FileState::kInvalidRuntimeIndex) {
        const uint32_t index = fs.closedHead;
        FileState::RuntimeFile& entry = fs.runtime[index];
        fd_runtime_closed_unlink_locked(fs, entry);
        if (entry.active && entry.fd < 0 && entry.pinCount == 0) {
            return &entry;
        }
    }
    return nullptr;
}

static void fd_runtime_hash_unlink_locked(FileState& fs, FileState::RuntimeFile& entry) {
    if (!entry.active || entry.id == 0) {
        entry.hashNextPlusOne = 0;
        return;
    }
    const uint32_t index = fd_runtime_index_locked(fs, &entry);
    if (index == FileState::kInvalidRuntimeIndex) {
        entry.hashNextPlusOne = 0;
        return;
    }
    const size_t bucket = fd_runtime_hash_bucket(entry.id);
    uint32_t* link = &fs.runtimeHashHeads[bucket];
    while (*link != 0) {
        const uint32_t current = *link - 1u;
        if (current == index) {
            *link = entry.hashNextPlusOne;
            entry.hashNextPlusOne = 0;
            return;
        }
        link = &fs.runtime[current].hashNextPlusOne;
    }
    entry.hashNextPlusOne = 0;
}

static void fd_runtime_hash_link_locked(FileState& fs, FileState::RuntimeFile& entry) {
    if (!entry.active || entry.id == 0) {
        return;
    }
    const uint32_t index = fd_runtime_index_locked(fs, &entry);
    if (index == FileState::kInvalidRuntimeIndex) {
        return;
    }
    const size_t bucket = fd_runtime_hash_bucket(entry.id);
    entry.hashNextPlusOne = fs.runtimeHashHeads[bucket];
    fs.runtimeHashHeads[bucket] = index + 1u;
}

static constexpr size_t fd_runtime_segment_index(FileState::Segment segment) {
    return static_cast<size_t>(segment);
}

static void fd_runtime_lru_unlink_locked(FileState& fs, FileState::RuntimeFile& entry) {
    if (!entry.onUnpinnedOpenList) {
        entry.lruPrev = FileState::kInvalidRuntimeIndex;
        entry.lruNext = FileState::kInvalidRuntimeIndex;
        return;
    }
    const uint32_t index = fd_runtime_index_locked(fs, &entry);
    const size_t segment = fd_runtime_segment_index(entry.segment);
    if (entry.lruPrev != FileState::kInvalidRuntimeIndex) {
        fs.runtime[entry.lruPrev].lruNext = entry.lruNext;
    } else if (fs.segmentHead[segment] == index) {
        fs.segmentHead[segment] = entry.lruNext;
    }
    if (entry.lruNext != FileState::kInvalidRuntimeIndex) {
        fs.runtime[entry.lruNext].lruPrev = entry.lruPrev;
    } else if (fs.segmentTail[segment] == index) {
        fs.segmentTail[segment] = entry.lruPrev;
    }
    if (fs.segmentCount[segment] == 0) {
        fd_cache_invariant_violation("segment-count-underflow", 0, 1);
    } else {
        --fs.segmentCount[segment];
    }
    entry.lruPrev = FileState::kInvalidRuntimeIndex;
    entry.lruNext = FileState::kInvalidRuntimeIndex;
    entry.onUnpinnedOpenList = false;
}

static void fd_runtime_lru_append_locked(FileState& fs, FileState::RuntimeFile& entry) {
    if (!entry.active || entry.fd < 0 || entry.pinCount != 0) {
        return;
    }
    const uint32_t index = fd_runtime_index_locked(fs, &entry);
    if (index == FileState::kInvalidRuntimeIndex) {
        return;
    }
    fd_runtime_lru_unlink_locked(fs, entry);
    const size_t segment = fd_runtime_segment_index(entry.segment);
    entry.lruPrev = fs.segmentTail[segment];
    entry.lruNext = FileState::kInvalidRuntimeIndex;
    if (fs.segmentTail[segment] != FileState::kInvalidRuntimeIndex) {
        fs.runtime[fs.segmentTail[segment]].lruNext = index;
    } else {
        fs.segmentHead[segment] = index;
    }
    fs.segmentTail[segment] = index;
    ++fs.segmentCount[segment];
    entry.onUnpinnedOpenList = true;
}

static size_t fd_runtime_protected_target_locked(const FileState& fs) {
#if !AMPR_EMU_FD_CACHE_SLRU
    (void)fs;
    return SIZE_MAX;
#else
    if (fs.evictableOpenCount == 0 || AMPR_EMU_FD_CACHE_PROTECTED_PERCENT == 0) {
        return 0;
    }
    size_t target =
        (fs.evictableOpenCount * AMPR_EMU_FD_CACHE_PROTECTED_PERCENT) / 100u;
    if (target == 0) target = 1;
    if (AMPR_EMU_FD_CACHE_PROTECTED_PERCENT < 100u &&
        fs.evictableOpenCount > 1u && target >= fs.evictableOpenCount) {
        target = fs.evictableOpenCount - 1u;
    }
    if (target > fs.evictableOpenCount) target = fs.evictableOpenCount;
    return target;
#endif
}

static void fd_runtime_balance_segments_locked(FileState& fs) {
#if AMPR_EMU_FD_CACHE_SLRU
    const size_t protectedIndex =
        fd_runtime_segment_index(FileState::Segment::Protected);
    const size_t target = fd_runtime_protected_target_locked(fs);
    while (fs.segmentCount[protectedIndex] > target &&
           fs.segmentHead[protectedIndex] != FileState::kInvalidRuntimeIndex) {
        FileState::RuntimeFile& demoted =
            fs.runtime[fs.segmentHead[protectedIndex]];
        fd_runtime_lru_unlink_locked(fs, demoted);
        demoted.segment = FileState::Segment::Probationary;
        fd_runtime_lru_append_locked(fs, demoted);
        ++fs.slruDemotions;
    }
#else
    (void)fs;
#endif
}

static void fd_runtime_promote_locked(FileState& fs, FileState::RuntimeFile& entry) {
#if AMPR_EMU_FD_CACHE_SLRU
    if (entry.segment == FileState::Segment::Protected) {
        return;
    }
    const bool relink = entry.onUnpinnedOpenList;
    if (relink) fd_runtime_lru_unlink_locked(fs, entry);
    entry.segment = FileState::Segment::Protected;
    if (relink) fd_runtime_lru_append_locked(fs, entry);
    ++fs.slruPromotions;
    fd_runtime_balance_segments_locked(fs);
#else
    (void)fs;
    (void)entry;
#endif
}

static FileState::RuntimeFile* fd_runtime_evict_candidate_locked(
    FileState& fs,
    bool physicalOnly = false) {
    const size_t probationary =
        fd_runtime_segment_index(FileState::Segment::Probationary);
    const size_t protectedIndex =
        fd_runtime_segment_index(FileState::Segment::Protected);
    uint32_t index = fs.segmentHead[probationary];
    while (index != FileState::kInvalidRuntimeIndex &&
           physicalOnly && !fs.runtime[index].physicalFd) {
        index = fs.runtime[index].lruNext;
    }
    if (index == FileState::kInvalidRuntimeIndex) {
        index = fs.segmentHead[protectedIndex];
        while (index != FileState::kInvalidRuntimeIndex &&
               physicalOnly && !fs.runtime[index].physicalFd) {
            index = fs.runtime[index].lruNext;
        }
    }
    return index != FileState::kInvalidRuntimeIndex ? &fs.runtime[index] : nullptr;
}

static FileState::RuntimeFile* fd_runtime_oldest_idle_locked(FileState& fs) {
    const size_t probationary =
        fd_runtime_segment_index(FileState::Segment::Probationary);
    const size_t protectedIndex =
        fd_runtime_segment_index(FileState::Segment::Protected);
    FileState::RuntimeFile* a = fs.segmentHead[probationary] != FileState::kInvalidRuntimeIndex
        ? &fs.runtime[fs.segmentHead[probationary]] : nullptr;
    FileState::RuntimeFile* b = fs.segmentHead[protectedIndex] != FileState::kInvalidRuntimeIndex
        ? &fs.runtime[fs.segmentHead[protectedIndex]] : nullptr;
    if (!a) return b;
    if (!b) return a;
    if (a->lastUseNs == 0) return a;
    if (b->lastUseNs == 0) return b;
    return a->lastUseNs <= b->lastUseNs ? a : b;
}

static int fd_runtime_detach_fd_locked(FileState& fs,
                                       FileState::RuntimeFile& entry);

static int fd_runtime_detach_eviction_locked(FileState& fs,
                                             FileState::RuntimeFile& entry) {
    const bool protectedVictim =
        entry.segment == FileState::Segment::Protected;
    const int fd = fd_runtime_detach_fd_locked(fs, entry);
#if AMPR_EMU_FD_CACHE_SLRU
    if (fd >= 0) {
        if (protectedVictim) {
            ++fs.slruProtectedEvictions;
        } else {
            ++fs.slruProbationaryEvictions;
        }
    }
#else
    (void)protectedVictim;
#endif
    return fd;
}

static void fd_runtime_note_open_locked(FileState& fs,
                                        FileState::RuntimeFile& entry,
                                        int fd,
                                        bool physicalFd) {
    if (entry.fd >= 0) {
        return;
    }
    fd_runtime_closed_unlink_locked(fs, entry);
    entry.fd = fd;
    entry.physicalFd = physicalFd;
    ++fs.openCount;
    if (entry.pinCount != 0) {
        ++fs.pinnedOpenCount;
        fs.openPinCount += entry.pinCount;
    } else {
        ++fs.evictableOpenCount;
        fd_runtime_lru_append_locked(fs, entry);
    }
    if (physicalFd) {
        ++fs.physicalOpenCount;
        if (entry.pinCount != 0) {
            ++fs.physicalPinnedOpenCount;
            fs.physicalOpenPinCount += entry.pinCount;
        } else {
            ++fs.physicalEvictableOpenCount;
        }
    }
}

static int fd_runtime_detach_fd_locked(FileState& fs, FileState::RuntimeFile& entry) {
    if (entry.fd < 0) {
        return -1;
    }
    const int fd = entry.fd;
    const bool physicalFd = entry.physicalFd;
    if (entry.pinCount != 0) {
        if (fs.pinnedOpenCount == 0) {
            fd_cache_invariant_violation("detach-pinned-open-underflow",
                                         fs.pinnedOpenCount, 1);
        } else {
            --fs.pinnedOpenCount;
        }
        if (fs.openPinCount < entry.pinCount) {
            fd_cache_invariant_violation("detach-open-pin-underflow",
                                         fs.openPinCount, entry.pinCount);
            fs.openPinCount = 0;
        } else {
            fs.openPinCount -= entry.pinCount;
        }
    } else {
        fd_runtime_lru_unlink_locked(fs, entry);
        if (fs.evictableOpenCount == 0) {
            fd_cache_invariant_violation("detach-evictable-underflow",
                                         fs.evictableOpenCount, 1);
        } else {
            --fs.evictableOpenCount;
        }
    }
    if (fs.openCount == 0) {
        fd_cache_invariant_violation("detach-open-underflow", fs.openCount, 1);
    } else {
        --fs.openCount;
    }
    if (physicalFd) {
        if (fs.physicalOpenCount == 0) {
            fd_cache_invariant_violation(
                "detach-physical-open-underflow", fs.physicalOpenCount, 1);
        } else {
            --fs.physicalOpenCount;
        }
        if (entry.pinCount != 0) {
            if (fs.physicalPinnedOpenCount == 0) {
                fd_cache_invariant_violation(
                    "detach-physical-pinned-underflow",
                    fs.physicalPinnedOpenCount, 1);
            } else {
                --fs.physicalPinnedOpenCount;
            }
            if (fs.physicalOpenPinCount < entry.pinCount) {
                fd_cache_invariant_violation(
                    "detach-physical-pin-underflow",
                    fs.physicalOpenPinCount, entry.pinCount);
                fs.physicalOpenPinCount = 0;
            } else {
                fs.physicalOpenPinCount -= entry.pinCount;
            }
        } else if (fs.physicalEvictableOpenCount == 0) {
            fd_cache_invariant_violation(
                "detach-physical-evictable-underflow",
                fs.physicalEvictableOpenCount, 1);
        } else {
            --fs.physicalEvictableOpenCount;
        }
    }
    entry.fd = -1;
    entry.physicalFd = false;
    if (entry.pinCount == 0) {
        fd_runtime_closed_push_locked(fs, entry);
    }
    return fd;
}

static void fd_runtime_activate_locked(FileState& fs, FileState::RuntimeFile& entry, uint32_t id) {
    fd_runtime_lists_ensure_locked(fs);
    const bool wasActive = entry.active;
    if (wasActive) {
        fd_runtime_closed_unlink_locked(fs, entry);
        fd_runtime_hash_unlink_locked(fs, entry);
    } else {
        ++fs.activeCount;
    }
    entry = FileState::RuntimeFile{};
    entry.id = id;
    entry.fd = -1;
    entry.active = true;
    entry.lastUseTick = fs.tick.fetch_add(1, std::memory_order_relaxed);
    fd_runtime_hash_link_locked(fs, entry);
}

static void fd_runtime_note_pin_locked(FileState& fs, FileState::RuntimeFile& entry) {
    const uint32_t oldPins = entry.pinCount;
    if (oldPins == UINT32_MAX) {
        fd_cache_invariant_violation("pin-count-overflow", oldPins, UINT32_MAX - 1u);
        return;
    }
    ++entry.pinCount;
    if (entry.fd < 0) {
        if (oldPins == 0) {
            fd_runtime_closed_unlink_locked(fs, entry);
        }
        return;
    }
    if (fs.openPinCount == SIZE_MAX) {
        fd_cache_invariant_violation("open-pin-count-overflow", fs.openPinCount, SIZE_MAX - 1u);
    } else {
        ++fs.openPinCount;
    }
    if (oldPins == 0) {
        fd_runtime_lru_unlink_locked(fs, entry);
        if (fs.evictableOpenCount == 0) {
            fd_cache_invariant_violation("pin-evictable-underflow",
                                         fs.evictableOpenCount, 1);
        } else {
            --fs.evictableOpenCount;
        }
        ++fs.pinnedOpenCount;
        if (entry.physicalFd) {
            if (fs.physicalEvictableOpenCount == 0) {
                fd_cache_invariant_violation(
                    "pin-physical-evictable-underflow",
                    fs.physicalEvictableOpenCount, 1);
            } else {
                --fs.physicalEvictableOpenCount;
            }
            ++fs.physicalPinnedOpenCount;
        }
    }
    if (entry.physicalFd) {
        ++fs.physicalOpenPinCount;
    }
}

static void fd_runtime_note_unpin_locked(FileState& fs, FileState::RuntimeFile& entry) {
    if (entry.pinCount == 0) {
        fd_cache_invariant_violation("unpin-pin-count-underflow", entry.pinCount, 1);
        return;
    }
    const uint32_t oldPins = entry.pinCount;
    --entry.pinCount;
    if (entry.fd < 0) {
        if (oldPins == 1) {
            fd_runtime_closed_push_locked(fs, entry);
        }
        return;
    }
    if (fs.openPinCount == 0) {
        fd_cache_invariant_violation("unpin-open-pin-underflow", fs.openPinCount, 1);
    } else {
        --fs.openPinCount;
    }
    if (entry.physicalFd) {
        if (fs.physicalOpenPinCount == 0) {
            fd_cache_invariant_violation(
                "unpin-physical-pin-underflow", fs.physicalOpenPinCount, 1);
        } else {
            --fs.physicalOpenPinCount;
        }
    }
    if (oldPins == 1) {
        if (fs.pinnedOpenCount == 0) {
            fd_cache_invariant_violation("unpin-pinned-open-underflow",
                                         fs.pinnedOpenCount, 1);
        } else {
            --fs.pinnedOpenCount;
        }
        ++fs.evictableOpenCount;
        if (entry.physicalFd) {
            if (fs.physicalPinnedOpenCount == 0) {
                fd_cache_invariant_violation(
                    "unpin-physical-pinned-underflow",
                    fs.physicalPinnedOpenCount, 1);
            } else {
                --fs.physicalPinnedOpenCount;
            }
            ++fs.physicalEvictableOpenCount;
        }
        fd_runtime_lru_append_locked(fs, entry);
        fd_runtime_balance_segments_locked(fs);
    }
}

} // namespace

struct FdPressureCaps {
    size_t fdBudget{};
    size_t cacheCap{};
};

static constexpr size_t kFdOpenBudgetBaseCap =
    AMPR_EMU_FD_OPEN_BUDGET_CAP > 0 ? AMPR_EMU_FD_OPEN_BUDGET_CAP : 1;
static constexpr size_t kFdOpenBudgetMinCap =
    AMPR_EMU_FD_OPEN_BUDGET_MIN_CAP > 0 ? AMPR_EMU_FD_OPEN_BUDGET_MIN_CAP : 1;

static std::atomic<size_t> g_fd_open_budget_effective_cap{kFdOpenBudgetBaseCap};
static std::atomic<size_t> g_fd_cache_effective_cap{AMPR_EMU_FD_CACHE_CAP};
static std::atomic<size_t> g_fd_direct_open_count{0};
static std::atomic<size_t> g_fd_pack_open_count{0};
static std::atomic<uint64_t> g_fd_budget_progress_generation{1};
static std::atomic<uint64_t> g_fd_cache_open_pressure_generation{0};
static std::atomic<uint64_t> g_fd_cache_last_idle_scan_ns{0};
#if AMPR_EMU_DEBUG_LOG
static std::atomic<uint64_t> g_fd_cache_diag_hits{0};
static std::atomic<uint64_t> g_fd_cache_diag_misses{0};
static std::atomic<uint64_t> g_fd_cache_diag_emfile{0};
#endif

static uint64_t fd_cache_time_now_ns() {
    timespec ts{};
    if (::sceKernelClockGettime(SCE_KERNEL_CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return uint64_t(ts.tv_sec) * 1000000000ull + uint64_t(ts.tv_nsec);
}

static void fd_runtime_note_use_time_locked(FileState::RuntimeFile& entry, uint64_t nowNs) {
    if (nowNs != 0) {
        entry.lastUseNs = nowNs;
    }
}

static size_t fd_open_budget_min_cap() {
    return kFdOpenBudgetMinCap < kFdOpenBudgetBaseCap
               ? kFdOpenBudgetMinCap
               : kFdOpenBudgetBaseCap;
}

size_t ampr_index_fd_open_budget_effective_cap() {
    size_t cap = g_fd_open_budget_effective_cap.load(std::memory_order_relaxed);
    if (cap == 0 || cap > kFdOpenBudgetBaseCap) {
        cap = kFdOpenBudgetBaseCap;
    }
    return cap;
}

void ampr_index_fd_open_budget_set_effective_cap(size_t cap) {
    if (cap == 0 || cap > kFdOpenBudgetBaseCap) {
        cap = kFdOpenBudgetBaseCap;
    }
    const size_t minCap = fd_open_budget_min_cap();
    if (cap < minCap) {
        cap = minCap;
    }
    const size_t oldCap = g_fd_open_budget_effective_cap.exchange(
        cap, std::memory_order_acq_rel);
    if (cap > oldCap) {
        g_fd_budget_progress_generation.fetch_add(
            1, std::memory_order_release);
#if AMPR_EMU_PACK_ENABLE
        ampr_pack_notify_fd_budget_progress();
#endif
    }
}

static FdPressureCaps fd_pressure_caps_for_budget(size_t fdBudget) {
    if (fdBudget == 0 || fdBudget > kFdOpenBudgetBaseCap) {
        fdBudget = kFdOpenBudgetBaseCap;
    }
    const size_t minBudget = fd_open_budget_min_cap();
    if (fdBudget < minBudget) {
        fdBudget = minBudget;
    }

    size_t cacheCap = (fdBudget * AMPR_EMU_FD_CACHE_CAP) / kFdOpenBudgetBaseCap;
    if (cacheCap == 0 && AMPR_EMU_FD_CACHE_CAP != 0) {
        cacheCap = 1;
    }
#if AMPR_EMU_FD_CACHE_PRESSURE_MIN_CAP != 0
    if (cacheCap < AMPR_EMU_FD_CACHE_PRESSURE_MIN_CAP &&
        fdBudget >= AMPR_EMU_FD_CACHE_PRESSURE_MIN_CAP) {
        cacheCap = AMPR_EMU_FD_CACHE_PRESSURE_MIN_CAP;
    }
#endif
    if (cacheCap > AMPR_EMU_FD_CACHE_CAP) {
        cacheCap = AMPR_EMU_FD_CACHE_CAP;
    }
    if (cacheCap >= fdBudget && fdBudget > 1) {
        cacheCap = fdBudget - 1;
    }

    return FdPressureCaps{fdBudget, cacheCap};
}

static FdPressureCaps fd_pressure_current_caps() {
    return fd_pressure_caps_for_budget(ampr_index_fd_open_budget_effective_cap());
}

static FileState::RuntimeFile* fd_runtime_find_locked(FileState& fs, uint32_t id) {
    if (id == 0) return nullptr;
    uint32_t indexPlusOne = fs.runtimeHashHeads[fd_runtime_hash_bucket(id)];
    while (indexPlusOne != 0) {
        FileState::RuntimeFile& entry = fs.runtime[indexPlusOne - 1u];
        if (entry.active && entry.id == id) {
            return &entry;
        }
        indexPlusOne = entry.hashNextPlusOne;
    }
    return nullptr;
}

static FileState::RuntimeFile* fd_runtime_create_locked(FileState& fs, uint32_t id, int* outFdToClose = nullptr) {
    if (id == 0) return nullptr;
    if (outFdToClose) {
        *outFdToClose = -1;
    }
    if (FileState::RuntimeFile* existing = fd_runtime_find_locked(fs, id)) {
        return existing;
    }
    FileState::RuntimeFile* reusable = fd_runtime_pop_free_locked(fs);
    if (!reusable) {
        reusable = fd_runtime_pop_closed_locked(fs);
    }
    if (!reusable) {
        reusable = fd_runtime_evict_candidate_locked(fs);
    }
    if (reusable && reusable->fd >= 0) {
        const int fd = fd_runtime_detach_eviction_locked(fs, *reusable);
        if (outFdToClose) {
            *outFdToClose = fd;
        }
        fd_runtime_closed_unlink_locked(fs, *reusable);
    }
    if (!reusable) {
        return nullptr;
    }
    fd_runtime_activate_locked(fs, *reusable, id);
    return reusable;
}

struct FdCacheStats {
    size_t entries{};
    size_t handles{};
    size_t open{};
    size_t pinnedOpen{};
    size_t pins{};
    size_t evictable{};
    size_t probationary{};
    size_t protectedEntries{};
};

class FdCloseList {
public:
    void push_back(int fd) {
        if (count_ >= kCapacity) {
            AMPR_KLOGF("ampr.abort reason=apr.fdcache.close-list.capacity-exhausted count=%zu capacity=%zu fd=%d file=%s line=%d",
                       count_,
                       kCapacity,
                       fd,
                       __FILE__,
                       __LINE__);
            std::abort();
        }
        fds_[count_++] = fd;
    }

    bool empty() const {
        return count_ == 0;
    }

    size_t size() const {
        return count_;
    }

    const int* begin() const {
        return fds_;
    }

    const int* end() const {
        return fds_ + count_;
    }

    void clear() {
        count_ = 0;
    }

private:
    static constexpr size_t kCapacity =
        AMPR_EMU_FD_CACHE_CAP > 0 ? AMPR_EMU_FD_CACHE_CAP : 1;
    int fds_[kCapacity]{};
    size_t count_{0};
};

size_t ampr_index_fd_direct_open_count() {
    return g_fd_direct_open_count.load(std::memory_order_relaxed);
}

size_t ampr_index_fd_pack_open_count() {
    return g_fd_pack_open_count.load(std::memory_order_relaxed);
}

size_t ampr_index_fd_uncached_open_count() {
    return ampr_index_fd_direct_open_count() + ampr_index_fd_pack_open_count();
}

uint64_t ampr_index_fd_open_budget_progress_generation() {
    return g_fd_budget_progress_generation.load(std::memory_order_acquire);
}

void ampr_index_fd_direct_note_open() {
    g_fd_direct_open_count.fetch_add(1, std::memory_order_relaxed);
}

void ampr_index_fd_direct_note_close() {
    size_t oldValue = g_fd_direct_open_count.load(std::memory_order_relaxed);
    for (;;) {
        if (oldValue == 0) {
            fd_cache_invariant_violation("direct-open-count-underflow", oldValue, 1);
            return;
        }
        if (g_fd_direct_open_count.compare_exchange_weak(oldValue,
                                                         oldValue - 1,
                                                         std::memory_order_relaxed,
                                                         std::memory_order_relaxed)) {
            g_fd_budget_progress_generation.fetch_add(1, std::memory_order_release);
#if AMPR_EMU_PACK_ENABLE
            ampr_pack_notify_fd_budget_progress();
#endif
            return;
        }
    }
}

void ampr_index_fd_pack_note_open() {
    g_fd_pack_open_count.fetch_add(1, std::memory_order_relaxed);
}

void ampr_index_fd_pack_note_close() {
    size_t oldValue = g_fd_pack_open_count.load(std::memory_order_relaxed);
    for (;;) {
        if (oldValue == 0) {
            fd_cache_invariant_violation("pack-open-count-underflow", oldValue, 1);
            return;
        }
        if (g_fd_pack_open_count.compare_exchange_weak(
                oldValue,
                oldValue - 1,
                std::memory_order_relaxed,
                std::memory_order_relaxed)) {
            g_fd_budget_progress_generation.fetch_add(1, std::memory_order_release);
#if AMPR_EMU_PACK_ENABLE
            ampr_pack_notify_fd_budget_progress();
#endif
            return;
        }
    }
}

static size_t fd_observed_open_count(const FdCacheStats& cacheStats) {
    return cacheStats.open + ampr_index_fd_uncached_open_count();
}

static FdPressureCaps fd_open_budget_mark_emfile(size_t observedOpen) {
    const size_t oldBudget = ampr_index_fd_open_budget_effective_cap();
    if (observedOpen == 0) {
        observedOpen = oldBudget;
    }
    size_t reduce = (observedOpen * AMPR_EMU_FD_OPEN_BUDGET_EMFILE_REDUCE_PERCENT + 99u) / 100u;
    if (reduce == 0) {
        reduce = 1;
    }
    size_t newBudget = observedOpen > reduce ? observedOpen - reduce : 1;
    if (newBudget > oldBudget) {
        newBudget = oldBudget;
    }
    const size_t minBudget = fd_open_budget_min_cap();
    if (newBudget < minBudget) {
        newBudget = minBudget;
    }
    ampr_index_fd_open_budget_set_effective_cap(newBudget);
    return fd_pressure_caps_for_budget(newBudget);
}

static size_t fd_cache_effective_cap() {
    size_t cap = g_fd_cache_effective_cap.load(std::memory_order_relaxed);
    if (cap == 0 || cap > AMPR_EMU_FD_CACHE_CAP) {
        cap = AMPR_EMU_FD_CACHE_CAP;
    }
    return cap;
}

void ampr_index_fd_cache_set_effective_cap(size_t cap) {
    if (cap == 0 || cap > AMPR_EMU_FD_CACHE_CAP) {
        cap = AMPR_EMU_FD_CACHE_CAP;
    }
    g_fd_cache_effective_cap.store(cap, std::memory_order_relaxed);
}

static size_t fd_cache_budget_cap_for_uncached_count(size_t uncachedOpen) {
    const size_t budget = ampr_index_fd_open_budget_effective_cap();
    return uncachedOpen < budget ? budget - uncachedOpen : 0;
}

static FdCacheStats fd_cache_stats_locked() {
    FdCacheStats stats{};
    const auto& fs = file_state();
    stats.entries = fs.activeCount;
    stats.handles = fs.openCount;
    stats.open = fs.physicalOpenCount;
    stats.pinnedOpen = fs.physicalPinnedOpenCount;
    stats.pins = fs.physicalOpenPinCount;
    stats.evictable = fs.physicalEvictableOpenCount;
    stats.probationary = fs.segmentCount[
        fd_runtime_segment_index(FileState::Segment::Probationary)];
    stats.protectedEntries = fs.segmentCount[
        fd_runtime_segment_index(FileState::Segment::Protected)];
    return stats;
}

static FdCacheStats fd_cache_stats() {
    auto& fs = file_state();
    AmprLockGuard lk(fs.m);
    return fd_cache_stats_locked();
}

static FdPressureCaps fd_cache_mark_open_pressure(size_t observedOpen) {
    const FdPressureCaps caps = fd_open_budget_mark_emfile(observedOpen);
    ampr_index_fd_cache_set_effective_cap(caps.cacheCap);
    g_fd_cache_open_pressure_generation.fetch_add(1, std::memory_order_relaxed);
    return caps;
}

static void fd_cache_collect_evictions_locked(FdCloseList& fdsToClose,
                                              size_t reserve = 0,
                                              size_t cap = SIZE_MAX) {
    if (cap == SIZE_MAX) {
        cap = fd_cache_effective_cap();
    }
    auto& fs = file_state();
    while (fs.openCount + reserve > cap) {
        FileState::RuntimeFile* victim = fd_runtime_evict_candidate_locked(fs);
        if (!victim) break;
        const int fd = fd_runtime_detach_eviction_locked(fs, *victim);
        if (fd < 0) {
            break;
        }
        fdsToClose.push_back(fd);
    }
}

static size_t fd_cache_collect_stale_locked(FileState& fs, FdCloseList& fdsToClose, uint64_t nowNs) {
#if AMPR_EMU_FD_CACHE_IDLE_CLOSE_NS == 0
    (void)fs;
    (void)fdsToClose;
    (void)nowNs;
    return 0;
#else
    if (nowNs == 0) {
        return 0;
    }

    size_t closed = 0;
    const size_t scanLimit = fs.evictableOpenCount;
    for (size_t scanned = 0; scanned < scanLimit; ++scanned) {
        FileState::RuntimeFile* victim = fd_runtime_oldest_idle_locked(fs);
        if (!victim) break;
        if (victim->lastUseNs == 0) {
            fd_runtime_note_use_time_locked(*victim, nowNs);
            fd_runtime_lru_append_locked(fs, *victim);
            continue;
        }
        if (nowNs < victim->lastUseNs ||
            nowNs - victim->lastUseNs < AMPR_EMU_FD_CACHE_IDLE_CLOSE_NS) {
            break;
        }
        const int fd = fd_runtime_detach_eviction_locked(fs, *victim);
        if (fd < 0) {
            break;
        }
        fdsToClose.push_back(fd);
        ++closed;
    }
    return closed;
#endif
}

static void fd_cache_collect_current_limit_evictions_locked(FdCloseList& fdsToClose,
                                                            size_t reserve = 0) {
    fd_cache_collect_evictions_locked(fdsToClose,
                                      reserve,
                                      fd_cache_effective_cap());
}

static void fd_cache_collect_budget_headroom_locked(FdCloseList& fdsToClose,
                                                    size_t reserve = 0) {
    auto& fs = file_state();
    const size_t cap = fd_cache_budget_cap_for_uncached_count(
        ampr_index_fd_uncached_open_count());
    while (fs.physicalOpenCount + reserve > cap) {
        FileState::RuntimeFile* victim = fd_runtime_evict_candidate_locked(
            fs, true);
        if (!victim) break;
        const int fd = fd_runtime_detach_eviction_locked(fs, *victim);
        if (fd < 0) break;
        fdsToClose.push_back(fd);
    }
}

static size_t fd_cache_collect_idle_percent_locked(FdCloseList& fdsToClose,
                                                   unsigned percent) {
    if (percent == 0) {
        return 0;
    }

    auto& fs = file_state();
    const size_t evictable = fs.physicalEvictableOpenCount;
    if (evictable == 0) {
        return 0;
    }

    size_t toClose = (evictable * percent + 99u) / 100u;
    if (toClose == 0) {
        toClose = 1;
    } else if (toClose > evictable) {
        toClose = evictable;
    }

    size_t closed = 0;
    while (closed < toClose) {
        FileState::RuntimeFile* victim = fd_runtime_evict_candidate_locked(
            fs, true);
        if (!victim) break;
        const int fd = fd_runtime_detach_eviction_locked(fs, *victim);
        if (fd < 0) {
            break;
        }
        fdsToClose.push_back(fd);
        ++closed;
    }
    return closed;
}

static size_t fd_cache_watermark_value(size_t budget, unsigned percent) {
    if (budget == 0) {
        return 0;
    }
    size_t value = (budget * percent + 99u) / 100u;
    if (value == 0) {
        value = 1;
    }
    return value < budget ? value : budget;
}

static size_t fd_cache_collect_watermark_evictions_locked(FdCloseList& fdsToClose,
                                                          size_t reserve) {
    constexpr unsigned kHighWatermarkPercent = 85;
    constexpr unsigned kCriticalWatermarkPercent = 95;
    constexpr unsigned kHighClosePercent =
        AMPR_EMU_FD_CACHE_EMFILE_IDLE_CLOSE_PERCENT < 25
            ? 25
            : AMPR_EMU_FD_CACHE_EMFILE_IDLE_CLOSE_PERCENT;
    constexpr unsigned kCriticalClosePercent =
        AMPR_EMU_FD_CACHE_EMFILE_IDLE_CLOSE_PERCENT < 50
            ? 50
            : AMPR_EMU_FD_CACHE_EMFILE_IDLE_CLOSE_PERCENT;

    const FdCacheStats stats = fd_cache_stats_locked();
    if (stats.evictable == 0) {
        return 0;
    }
    const size_t budget = ampr_index_fd_open_budget_effective_cap();
    if (budget == 0) {
        return 0;
    }
    const size_t observed = fd_observed_open_count(stats);
    const size_t projected = observed + reserve;
    const size_t high = fd_cache_watermark_value(budget, kHighWatermarkPercent);
    if (projected < high) {
        return 0;
    }
    const size_t critical = fd_cache_watermark_value(budget, kCriticalWatermarkPercent);
    const bool criticalPressure = projected >= critical || projected > budget;
    const unsigned closePercent = criticalPressure ? kCriticalClosePercent : kHighClosePercent;
    return fd_cache_collect_idle_percent_locked(fdsToClose, closePercent);
}

static void fd_cache_close_list(FdCloseList& fdsToClose, const char* reason = "fdcache") {
    (void)reason;
    if (!fdsToClose.empty()) {
        AMPR_TLOGF("apr.fdcache.close-list.enter reason=%s count=%zu",
                  reason ? reason : "unknown",
                  fdsToClose.size());
    }
    for (int fd : fdsToClose) {
        if (fd >= 0) {
            AMPR_TLOGF("apr.fdcache.close.enter reason=%s fd=%d",
                      reason ? reason : "unknown",
                      fd);
            ::sceKernelClose(fd);
            AMPR_TLOGF("apr.fdcache.close.leave reason=%s fd=%d",
                      reason ? reason : "unknown",
                      fd);
        }
    }
    if (!fdsToClose.empty()) {
        AMPR_TLOGF("apr.fdcache.close-list.leave reason=%s",
                  reason ? reason : "unknown");
    }
    const bool madeBudgetProgress = !fdsToClose.empty();
    fdsToClose.clear();
    if (madeBudgetProgress) {
        g_fd_budget_progress_generation.fetch_add(1, std::memory_order_release);
#if AMPR_EMU_PACK_ENABLE
        ampr_pack_notify_fd_budget_progress();
#endif
    }
}

void ampr_index_fd_cache_release_open_fd_headroom(size_t reserve, size_t cap) {
    FdCloseList fdsToClose;
    {
        auto& fs = file_state();
        AmprLockGuard lk(fs.m);
        fd_cache_collect_evictions_locked(fdsToClose, reserve, cap);
    }
    fd_cache_close_list(fdsToClose);
}

bool ampr_index_fd_cache_release_open_fd_budget_headroom(size_t reserve) {
    FdCloseList fdsToClose;
    bool available = false;
    {
        auto& fs = file_state();
        AmprLockGuard lk(fs.m);
        fd_cache_collect_budget_headroom_locked(fdsToClose, reserve);
        const FdCacheStats stats = fd_cache_stats_locked();
        const size_t budget = ampr_index_fd_open_budget_effective_cap();
        available = fd_observed_open_count(stats) + reserve <= budget;
    }
    fd_cache_close_list(fdsToClose, "fd-budget");
    return available;
}

bool ampr_index_fd_common_open_budget_headroom_available(size_t reserve,
                                                         size_t* outObserved,
                                                         size_t* outBudget,
                                                         size_t* outEvictable) {
    auto& fs = file_state();
    AmprLockGuard lk(fs.m);
    const FdCacheStats stats = fd_cache_stats_locked();
    const size_t budget = ampr_index_fd_open_budget_effective_cap();
    const size_t observed = fd_observed_open_count(stats);
    if (outObserved) {
        *outObserved = observed;
    }
    if (outBudget) {
        *outBudget = budget;
    }
    if (outEvictable) {
        *outEvictable = stats.evictable;
    }
    if (observed + reserve <= budget) {
        return true;
    }
    return stats.evictable >= observed + reserve - budget;
}

size_t ampr_index_fd_cache_release_idle_percent(unsigned percent) {
    FdCloseList fdsToClose;
    size_t closed = 0;
    {
        auto& fs = file_state();
        AmprLockGuard lk(fs.m);
        closed = fd_cache_collect_idle_percent_locked(fdsToClose, percent);
    }
    fd_cache_close_list(fdsToClose);
    return closed;
}

static bool fd_cache_idle_scan_allowed(uint64_t nowNs, bool forceScan) {
#if AMPR_EMU_FD_CACHE_IDLE_SCAN_NS == 0
    (void)nowNs;
    (void)forceScan;
    return true;
#else
    if (forceScan) {
        g_fd_cache_last_idle_scan_ns.store(nowNs, std::memory_order_relaxed);
        return true;
    }

    uint64_t lastScan = g_fd_cache_last_idle_scan_ns.load(std::memory_order_relaxed);
    for (;;) {
        if (lastScan != 0 && nowNs >= lastScan &&
            nowNs - lastScan < AMPR_EMU_FD_CACHE_IDLE_SCAN_NS) {
            return false;
        }
        if (g_fd_cache_last_idle_scan_ns.compare_exchange_weak(
                lastScan,
                nowNs,
                std::memory_order_relaxed,
                std::memory_order_relaxed)) {
            return true;
        }
    }
#endif
}

static size_t fd_cache_release_stale_impl(bool forceScan, uint64_t nowNs = 0) {
#if AMPR_EMU_FD_CACHE_IDLE_CLOSE_NS == 0
    (void)forceScan;
    (void)nowNs;
    return 0;
#else
    if (nowNs == 0) {
        nowNs = fd_cache_time_now_ns();
    }
    if (nowNs == 0) {
        return 0;
    }

    if (!fd_cache_idle_scan_allowed(nowNs, forceScan)) {
        return 0;
    }

    FdCloseList fdsToClose;
    size_t closed = 0;
    {
        auto& fs = file_state();
        AmprLockGuard lk(fs.m);
        closed = fd_cache_collect_stale_locked(fs, fdsToClose, nowNs);
    }
    fd_cache_close_list(fdsToClose, "idle-timeout");
    if (closed != 0) {
        AMPR_TLOGF("apr.fdcache.idle-timeout closed=%zu timeoutNs=%llu",
                  closed,
                  (unsigned long long)AMPR_EMU_FD_CACHE_IDLE_CLOSE_NS);
    }
    return closed;
#endif
}

size_t ampr_index_fd_cache_release_stale(uint64_t nowNs) {
    return fd_cache_release_stale_impl(false, nowNs);
}

static size_t fd_cache_release_stale_for_pressure() {
    return fd_cache_release_stale_impl(true);
}

int ampr_index_acquire_cached_fd(uint64_t jobId,
                                 uint32_t id,
                                 const FileEntryView& entry,
                                 int flags,
                                 int mode,
                                 bool allowOpen) {
    (void)jobId;
    if (!entry.path) {
        AMPR_LOGF("apr.fdcache.acquire miss job=0x%llx fileId=%u",
                  (unsigned long long)jobId,
                  id);
        return -ENOENT;
    }

    const char* pathToOpen = nullptr;
    FdCloseList fdsToClose;
    int fd = -1;

    AMPR_TLOGF("apr.fdcache.acquire.enter job=0x%llx fileId=%u path=%s size=0x%llx budget=%zu cacheCap=%zu uncachedOpen=%zu packOpen=%zu",
              (unsigned long long)jobId,
              id,
              ampr_log_path_arg(entry.path),
              (unsigned long long)entry.size,
              ampr_index_fd_open_budget_effective_cap(),
              fd_cache_effective_cap(),
              ampr_index_fd_uncached_open_count(),
              ampr_index_fd_pack_open_count());

    {
        auto& fs = file_state();
        AMPR_TLOGF("apr.fdcache.lock.enter job=0x%llx fileId=%u stage=lookup",
                  (unsigned long long)jobId,
                  id);
        AmprLockGuard lk(fs.m);
        FileState::RuntimeFile* e = fd_runtime_find_locked(fs, id);
        if (e && e->fd >= 0) {
#if AMPR_EMU_DEBUG_LOG
            if (ampr_debug_log_runtime_enabled()) {
                g_fd_cache_diag_hits.fetch_add(1, std::memory_order_relaxed);
            }
#endif
            e->lastUseTick = fs.tick.fetch_add(1, std::memory_order_relaxed);
            fd_runtime_promote_locked(fs, *e);
            fd_runtime_note_pin_locked(fs, *e);
            fd = e->fd;
            fd_cache_collect_current_limit_evictions_locked(fdsToClose);
            (void)fd_cache_collect_watermark_evictions_locked(fdsToClose, 0);
#if AMPR_EMU_DEBUG_LOG && AMPR_EMU_DEBUG_LOG_TRACE
            if (ampr_debug_log_runtime_enabled()) {
                const FdCacheStats stats = fd_cache_stats_locked();
                AMPR_TLOGF("apr.fdcache.lock.leave job=0x%llx fileId=%u stage=hit fd=%d pinCount=%zu evictClose=%zu open=%zu entries=%zu pinned=%zu pins=%zu evictable=%zu",
                          (unsigned long long)jobId,
                          id,
                          fd,
                          e->pinCount,
                          fdsToClose.size(),
                          stats.open,
                          stats.entries,
                          stats.pinnedOpen,
                          stats.pins,
                          stats.evictable);
            }
#endif
        } else {
#if AMPR_EMU_DEBUG_LOG
            if (ampr_debug_log_runtime_enabled()) {
                g_fd_cache_diag_misses.fetch_add(1, std::memory_order_relaxed);
            }
#endif
            if (e) {
                e->lastUseTick = fs.tick.fetch_add(1, std::memory_order_relaxed);
            }
            if (allowOpen) {
                fd_cache_collect_current_limit_evictions_locked(fdsToClose, 1);
                (void)fd_cache_collect_watermark_evictions_locked(fdsToClose, 1);
                if (fs.openCount < fd_cache_effective_cap()) {
                    pathToOpen = entry.path;
                }
            }
#if AMPR_EMU_DEBUG_LOG && AMPR_EMU_DEBUG_LOG_TRACE
            if (ampr_debug_log_runtime_enabled()) {
                const FdCacheStats stats = fd_cache_stats_locked();
                AMPR_TLOGF("apr.fdcache.lock.leave job=0x%llx fileId=%u stage=miss allowOpen=%u openAdmitted=%u reserve=%u evictClose=%zu open=%zu entries=%zu pinned=%zu pins=%zu evictable=%zu",
                          (unsigned long long)jobId,
                          id,
                          allowOpen ? 1u : 0u,
                          pathToOpen ? 1u : 0u,
                          allowOpen ? 1u : 0u,
                          fdsToClose.size(),
                          stats.open,
                          stats.entries,
                          stats.pinnedOpen,
                          stats.pins,
                          stats.evictable);
            }
#endif
        }
    }

    fd_cache_close_list(fdsToClose, "acquire-pre-open");
    if (fd >= 0) {
        AMPR_TLOGF("apr.fdcache.acquire.leave job=0x%llx fileId=%u result=hit fd=%d",
                  (unsigned long long)jobId,
                  id,
                  fd);
        AMPR_FILE_STATUS_LOGF("apr.file.open status=cache-hit job=0x%llx fileId=%u path=%s fd=%d",
                              (unsigned long long)jobId,
                              id,
                              entry.path,
                              fd);
        return fd;
    }
    if (!pathToOpen) {
        AMPR_TLOGF("apr.fdcache.acquire.defer job=0x%llx fileId=%u reason=new-fd-blocked",
                  (unsigned long long)jobId,
                  id);
        return -EAGAIN;
    }

    AMPR_TLOGF("apr.fdcache.open.enter job=0x%llx fileId=%u path=%s flags=0x%x",
              (unsigned long long)jobId,
              id,
              pathToOpen,
              flags);
    bool openedPhysical = false;
    int opened = ampr_open_indexed_or_real(
        id, entry, flags, static_cast<SceKernelMode>(mode), &openedPhysical);
    if (opened >= 0 && openedPhysical &&
        !ampr_index_fd_cache_release_open_fd_budget_headroom(1u)) {
        (void)::sceKernelClose(opened);
        opened = SCE_KERNEL_ERROR_EAGAIN;
        openedPhysical = false;
    }
    // The indexed helper returns either a packed virtual FD or a real fd and
    // preserves the SCE error domain for both backends. Derive POSIX errno only
    // for local pressure/error classes.
    const int openErrno = opened < 0 ? ampr_posix_errno_from_sce(opened) : 0;
    const bool openPressure =
        opened < 0 && ampr_posix_errno_is_fd_open_pressure(openErrno);
    AMPR_TLOGF("apr.fdcache.open.leave job=0x%llx fileId=%u path=%s fd=%d rawRc=0x%x errno=%d pressure=%u",
              (unsigned long long)jobId,
              id,
              pathToOpen,
              opened,
              opened,
              openErrno,
              openPressure ? 1u : 0u);
    if (openPressure) {
#if AMPR_EMU_DEBUG_LOG
        if (openErrno == EMFILE && ampr_debug_log_runtime_enabled()) {
            g_fd_cache_diag_emfile.fetch_add(1, std::memory_order_relaxed);
        }
#endif
        const FdCacheStats beforeStats = fd_cache_stats();
        const size_t observedOpen = fd_observed_open_count(beforeStats);
        const FdPressureCaps pressureCaps = fd_cache_mark_open_pressure(observedOpen);
        const size_t closedStale = fd_cache_release_stale_for_pressure();
        const size_t closedIdle = ampr_index_fd_cache_release_idle_percent(
            AMPR_EMU_FD_CACHE_OPEN_PRESSURE_IDLE_CLOSE_PERCENT);
        const FdCacheStats afterStats = fd_cache_stats();
        (void)pressureCaps;
        (void)closedStale;
        (void)closedIdle;
        (void)afterStats;
        AMPR_LOGF("apr.fdcache.acquire.open defer-pressure job=0x%llx fileId=%u path=%s rawRc=0x%x errno=%d observedOpen=%zu fdBudget=%zu cacheCap=%zu closedStale=%zu closedIdle=%zu cacheBefore=%zu/%zu uncachedBefore=%zu pinned=%zu pins=%zu evictable=%zu cacheAfter=%zu/%zu uncachedAfter=%zu pinnedAfter=%zu pinsAfter=%zu evictableAfter=%zu",
                  (unsigned long long)jobId,
                  id,
                  pathToOpen,
                  opened,
                  openErrno,
                  observedOpen,
                  pressureCaps.fdBudget,
                  pressureCaps.cacheCap,
                  closedStale,
                  closedIdle,
                  beforeStats.open,
                  beforeStats.entries,
                  observedOpen >= beforeStats.open ? observedOpen - beforeStats.open : 0,
                  beforeStats.pinnedOpen,
                  beforeStats.pins,
                  beforeStats.evictable,
                  afterStats.open,
                  afterStats.entries,
                  ampr_index_fd_uncached_open_count(),
                  afterStats.pinnedOpen,
                  afterStats.pins,
                  afterStats.evictable);
    }
    if (opened < 0) {
        if (!openPressure) {
            AMPR_CRITICAL_LOGF("apr.fdcache.acquire.open status=failed job=0x%llx fileId=%u path=%s rawRc=0x%x errno=%d rc=0x%x",
                      (unsigned long long)jobId,
                      id,
                      pathToOpen,
                      opened,
                      openErrno,
                      -openErrno);
        }
        AMPR_FILE_STATUS_LOGF("apr.file.open status=%s reason=fd-cache-open job=0x%llx fileId=%u path=%s rawRc=0x%x errno=%d rc=0x%x",
                              openPressure ? "deferred" : "failed",
                              (unsigned long long)jobId,
                              id,
                              pathToOpen,
                              opened,
                              openErrno,
                              -openErrno);
        return -openErrno;
    }

    int fdToClose = -1;
    {
        auto& fs = file_state();
        AMPR_TLOGF("apr.fdcache.lock.enter job=0x%llx fileId=%u stage=install opened=%d",
                  (unsigned long long)jobId,
                  id,
                  opened);
        AmprLockGuard lk(fs.m);
        int reclaimedFd = -1;
        FileState::RuntimeFile* e = fd_runtime_create_locked(fs, id, &reclaimedFd);
        if (reclaimedFd >= 0) {
            fdsToClose.push_back(reclaimedFd);
        }
        if (!e) {
            fdToClose = opened;
            // Opening succeeded, but every cache slot is still pinned by active
            // AIO. Treat this as transient admission pressure so the reactor
            // retries after a completed request makes a slot reusable.
            fd = -EAGAIN;
            AMPR_LOGF("apr.fdcache.acquire install-defer job=0x%llx fileId=%u opened=%d reason=cache-capacity-pinned",
                      (unsigned long long)jobId,
                      id,
                      opened);
        } else {
            e->lastUseTick = fs.tick.fetch_add(1, std::memory_order_relaxed);
            if (e->fd >= 0) {
                fd_runtime_promote_locked(fs, *e);
                fd_runtime_note_pin_locked(fs, *e);
                fd = e->fd;
                fdToClose = opened;
                AMPR_TLOGF("apr.fdcache.acquire race-hit job=0x%llx fileId=%u path=%s fd=%d opened=%d pinCount=%zu",
                          (unsigned long long)jobId,
                          id,
                          entry.path,
                          fd,
                          opened,
                          e->pinCount);
            } else {
                fd_runtime_note_pin_locked(fs, *e);
                fd_runtime_note_open_locked(fs, *e, opened, openedPhysical);
                fd = opened;
                AMPR_TLOGF("apr.fdcache.acquire.open job=0x%llx fileId=%u path=%s fd=%d pinCount=%zu",
                          (unsigned long long)jobId,
                          id,
                          entry.path,
                          fd,
                          e->pinCount);
            }
            fd_cache_collect_current_limit_evictions_locked(fdsToClose);
#if AMPR_EMU_DEBUG_LOG && AMPR_EMU_DEBUG_LOG_TRACE
            if (ampr_debug_log_runtime_enabled()) {
                const FdCacheStats stats = fd_cache_stats_locked();
                AMPR_TLOGF("apr.fdcache.lock.leave job=0x%llx fileId=%u stage=install fd=%d fdToClose=%d evictClose=%zu open=%zu entries=%zu pinned=%zu pins=%zu evictable=%zu",
                          (unsigned long long)jobId,
                          id,
                          fd,
                          fdToClose,
                          fdsToClose.size(),
                          stats.open,
                          stats.entries,
                          stats.pinnedOpen,
                          stats.pins,
                          stats.evictable);
            }
#endif
        }
    }

    if (fdToClose >= 0) {
        AMPR_TLOGF("apr.fdcache.close.enter reason=acquire-race fd=%d", fdToClose);
        ::sceKernelClose(fdToClose);
        AMPR_TLOGF("apr.fdcache.close.leave reason=acquire-race fd=%d", fdToClose);
    }
    fd_cache_close_list(fdsToClose, "acquire-post-open");
    AMPR_TLOGF("apr.fdcache.acquire.leave job=0x%llx fileId=%u result=%s fd=%d",
              (unsigned long long)jobId,
              id,
              fd >= 0 ? "open" : "error",
              fd);
    AMPR_FILE_STATUS_LOGF("apr.file.open status=%s job=0x%llx fileId=%u path=%s fd=%d opened=%d",
                          fd >= 0 ? (fd == opened ? "opened" : "race-hit") : "failed",
                          (unsigned long long)jobId,
                          id,
                          entry.path,
                          fd,
                          opened);
    return fd;
}

void ampr_index_release_cached_fd_pin(uint32_t fileId) {
    if (fileId == 0) {
        return;
    }

    FdCloseList fdsToClose;
    // A cached descriptor cannot become idle while pinned. Timestamp the
    // completed use here, so acquire/install needs no monotonic-clock syscall.
    const uint64_t nowNs = fd_cache_time_now_ns();
    {
        auto& fs = file_state();
        AmprLockGuard lk(fs.m);
        FileState::RuntimeFile* e = fd_runtime_find_locked(fs, fileId);
        if (!e) {
            return;
        }
        fd_runtime_note_use_time_locked(*e, nowNs);
        fd_runtime_note_unpin_locked(fs, *e);
        e->lastUseTick = fs.tick.fetch_add(1, std::memory_order_relaxed);
        fd_cache_collect_evictions_locked(fdsToClose);
    }

    fd_cache_close_list(fdsToClose);
}

AmprIndexFdPressureCaps ampr_index_fd_pressure_current_caps() {
    const FdPressureCaps caps = fd_pressure_current_caps();
    return AmprIndexFdPressureCaps{caps.fdBudget, caps.cacheCap};
}

AmprIndexFdPressureCaps ampr_index_fd_cache_mark_open_pressure(size_t observedOpen) {
    const FdPressureCaps caps = fd_cache_mark_open_pressure(observedOpen);
    return AmprIndexFdPressureCaps{caps.fdBudget, caps.cacheCap};
}

uint64_t ampr_index_fd_cache_open_pressure_generation() {
    return g_fd_cache_open_pressure_generation.load(std::memory_order_relaxed);
}

AmprIndexFdCacheStats ampr_index_fd_cache_stats() {
    const FdCacheStats stats = fd_cache_stats();
    return AmprIndexFdCacheStats{
        stats.entries,
        stats.handles,
        stats.open,
        stats.pinnedOpen,
        stats.pins,
        stats.evictable,
        stats.probationary,
        stats.protectedEntries,
    };
}

AmprIndexFdCacheDiagCounters ampr_index_fd_cache_diag_counters(bool reset) {
#if AMPR_EMU_DEBUG_LOG
    if (!ampr_debug_log_runtime_enabled()) {
        return AmprIndexFdCacheDiagCounters{};
    }
    uint64_t promotions = 0;
    uint64_t demotions = 0;
    uint64_t probationaryEvictions = 0;
    uint64_t protectedEvictions = 0;
    {
        auto& fs = file_state();
        AmprLockGuard lk(fs.m);
        promotions = fs.slruPromotions;
        demotions = fs.slruDemotions;
        probationaryEvictions = fs.slruProbationaryEvictions;
        protectedEvictions = fs.slruProtectedEvictions;
        if (reset) {
            fs.slruPromotions = 0;
            fs.slruDemotions = 0;
            fs.slruProbationaryEvictions = 0;
            fs.slruProtectedEvictions = 0;
        }
    }
    if (reset) {
        return AmprIndexFdCacheDiagCounters{
            g_fd_cache_diag_hits.exchange(0, std::memory_order_relaxed),
            g_fd_cache_diag_misses.exchange(0, std::memory_order_relaxed),
            g_fd_cache_diag_emfile.exchange(0, std::memory_order_relaxed),
            promotions,
            demotions,
            probationaryEvictions,
            protectedEvictions,
        };
    }
    return AmprIndexFdCacheDiagCounters{
        g_fd_cache_diag_hits.load(std::memory_order_relaxed),
        g_fd_cache_diag_misses.load(std::memory_order_relaxed),
        g_fd_cache_diag_emfile.load(std::memory_order_relaxed),
        promotions,
        demotions,
        probationaryEvictions,
        protectedEvictions,
    };
#else
    (void)reset;
    return AmprIndexFdCacheDiagCounters{};
#endif
}

