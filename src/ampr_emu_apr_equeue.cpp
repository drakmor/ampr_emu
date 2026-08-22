/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * APR-only fixed-storage equeue overlay. Native AMM packets are never routed
 * through this module.
 */

#include "ampr_emu_apr_equeue.h"

#if AMPR_EMU_APR_LOCAL_EQUEUE

#include "ampr_emu_apr_reactor.h"
#include "ampr_emu_kernel_lookup.h"
#include "ampr_emu_log.h"
#include "ampr_emu_sync.h"

#include <_kernel.h>
#include <atomic>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <sys/event.h>
#include <sys/sce_errno.h>

namespace {

using WaitEqueueFn = int (*)(SceKernelEqueue, SceKernelEvent*, int, int*, SceKernelUseconds*);
using DeleteEqueueFn = int (*)(SceKernelEqueue);
using AddAmprEventFn = int (*)(SceKernelEqueue, int, void*);
using DeleteAmprEventFn = int (*)(SceKernelEqueue, int);

constexpr uint32_t kInvalidIndex = UINT32_MAX;
constexpr uint32_t kHashTombstone = UINT32_MAX;
constexpr uint32_t kQueueCapacity = AMPR_EMU_APR_LOCAL_EQUEUE_QUEUE_CAPACITY;
constexpr uint32_t kRegistrationCapacity = AMPR_EMU_APR_LOCAL_EQUEUE_REG_CAPACITY;
constexpr uint32_t kPendingCapacity = AMPR_EMU_APR_LOCAL_EQUEUE_PENDING_CAPACITY;
constexpr uint32_t kQueueHashCapacity = kQueueCapacity * 2u;
constexpr uint32_t kRegistrationHashCapacity = kRegistrationCapacity * 2u;
constexpr uint32_t kWakeIdBase = 0x5a4d5000u;
constexpr uint32_t kWakeAttachAttempts = 64u;
constexpr uint16_t kRegistrationHashTombstone = UINT16_MAX;
constexpr uint64_t kUsecondsPerSecond = 1000000ull;
constexpr uint64_t kNanosecondsPerSecond = 1000000000ull;
constexpr uint64_t kMaxScaledCounterFrequency = UINT64_MAX / kUsecondsPerSecond;
constexpr SceKernelUseconds kWaitGraceUseconds =
    static_cast<SceKernelUseconds>(AMPR_EMU_APR_LOCAL_EQUEUE_WAIT_GRACE_US);
constexpr bool kWaitGraceAdaptive =
    AMPR_EMU_APR_LOCAL_EQUEUE_WAIT_GRACE_ADAPTIVE != 0;
constexpr uint8_t kWaitGraceInitialLevel = 2u;
constexpr uint8_t kWaitGraceMaxLevel = 3u;
constexpr int8_t kWaitGraceHitsToGrow = 2;
constexpr int8_t kWaitGraceMissesToCooldown = 4;
constexpr uint8_t kWaitGraceCooldownEvents = 32u;
constexpr SceKernelUseconds kWaitGraceMinUseconds =
    kWaitGraceUseconds == 0
        ? 0
        : (kWaitGraceUseconds / 4u != 0 ? kWaitGraceUseconds / 4u : 1u);
constexpr SceKernelUseconds kWaitGraceLowUseconds =
    kWaitGraceUseconds == 0
        ? 0
        : (kWaitGraceUseconds / 2u != 0 ? kWaitGraceUseconds / 2u : 1u);
constexpr SceKernelUseconds kWaitGraceMaxUseconds =
    kWaitGraceUseconds > UINT32_MAX / 2u
        ? UINT32_MAX
        : kWaitGraceUseconds * 2u;
constexpr SceKernelUseconds kWaitGraceLevels[kWaitGraceMaxLevel + 1u] = {
    kWaitGraceMinUseconds,
    kWaitGraceLowUseconds,
    kWaitGraceUseconds,
    kWaitGraceMaxUseconds,
};

static_assert(kQueueCapacity != 0 && kRegistrationCapacity != 0 && kPendingCapacity != 0,
              "APR local equeue pools must not be empty");
static_assert(AMPR_EMU_APR_LOCAL_EQUEUE_WAIT_GRACE_US <= UINT32_MAX,
              "APR local equeue wait grace does not fit SceKernelUseconds");
static_assert(AMPR_EMU_APR_LOCAL_EQUEUE_WAIT_GRACE_ADAPTIVE == 0 ||
                  AMPR_EMU_APR_LOCAL_EQUEUE_WAIT_GRACE_ADAPTIVE == 1,
              "APR local equeue adaptive wait grace must be 0 or 1");
static_assert(kWaitGraceInitialLevel <= kWaitGraceMaxLevel,
              "APR local equeue initial wait grace level is out of range");
static_assert(kWaitGraceMinUseconds <= kWaitGraceLowUseconds &&
                  kWaitGraceLowUseconds <= kWaitGraceUseconds &&
                  kWaitGraceUseconds <= kWaitGraceMaxUseconds,
              "APR local equeue wait grace levels must be monotonic");
static_assert((kQueueHashCapacity & (kQueueHashCapacity - 1u)) == 0,
              "APR local equeue hash capacity must be a power of two");
static_assert((kRegistrationHashCapacity & (kRegistrationHashCapacity - 1u)) == 0,
              "APR local equeue registration hash capacity must be a power of two");
static_assert(kQueueCapacity <= UINT16_MAX - 1u,
              "APR local equeue queue owner does not fit fixed registration metadata");
static_assert(kRegistrationCapacity <= UINT16_MAX - 1u,
              "APR local equeue registration index does not fit fixed hash storage");
static_assert(std::atomic<uint8_t>::is_always_lock_free,
              "APR local equeue wake state must use lock-free byte atomics");

struct MirroredRegistration {
    uint32_t next{};
    int32_t id{};
    void* udata{};
    uint64_t generation{};
};

struct PendingEvent {
    uint32_t next{};
    SceKernelEvent event{};
    uint64_t registrationGeneration{};
};

struct TrackedEqueue {
    SceKernelEqueue eq{};
    uint32_t nextFree{};
    uint32_t registrationHead{};
    uint32_t registrationCache{};
    uint32_t pendingHead{};
    uint32_t pendingTail{};
    uint32_t pendingCount{};
    uint32_t wakeId{};
    uint64_t lifetimeGeneration{};
    uint32_t nativeWaitIntent{};
    uint8_t waitGraceLevel{};
    int8_t waitGraceTrend{};
    uint8_t waitGraceCooldownEvents{};
    bool used : 1;
    bool wakeRegistered : 1;
    bool wakeReady : 1;
    bool wakeArmed : 1;
    bool wakeTriggering : 1;
    bool waitGraceEligible : 1;
    bool waitGraceActive : 1;
};
static_assert(sizeof(TrackedEqueue) == 56u,
              "APR local equeue flag packing changed fixed .bss storage");

struct OverlayState {
    std::atomic<uint32_t> lock{0};
    std::atomic<bool> hooksAvailable{false};
    std::atomic<uint64_t> publishEpoch{0};
    bool initialized{};
    uint32_t queueFreeHead{};
    uint32_t registrationFreeHead{};
    uint32_t pendingFreeHead{};
    uint32_t nextWakeId{};
    uint64_t nextLifetimeGeneration{};
    uint64_t nextRegistrationGeneration{};
    uint64_t nextPublishEpoch{};
    uint64_t processTimeCounterFrequency{};
    uint32_t liveQueues{};
    uint32_t liveRegistrations{};
    uint32_t livePending{};
    uint32_t queueHashTombstones{};
    uint32_t registrationHashTombstones{};
    bool pendingPoolBackpressured{};
#if AMPR_EMU_DEBUG_LOG
    uint32_t pendingPeak{};
    uint32_t liveWaitIntents{};
    uint32_t waitIntentPeak{};
    uint64_t waitGraceIncreases{};
    uint64_t waitGraceDecreases{};
    uint64_t waitGraceCooldowns{};
    uint64_t waitGraceCooldownEvents{};
    uint64_t waitGraceRearms{};
#endif
    // The bit in TrackedEqueue is the lock-protected hot-path predicate. This
    // slot-local atomic exists only for waiting after the overlay lock is
    // released, so completion on another queue cannot cause a false retry.
    alignas(64) std::atomic<uint8_t> wakeTriggerState[kQueueCapacity]{};
    TrackedEqueue queues[kQueueCapacity]{};
    MirroredRegistration registrations[kRegistrationCapacity]{};
    PendingEvent pending[kPendingCapacity]{};
    uint32_t queueHash[kQueueHashCapacity]{};
    uint16_t registrationHash[kRegistrationHashCapacity]{};
    uint16_t registrationOwners[kRegistrationCapacity]{};
};

// Keep the large fixed pools zero-initialized in .bss. initialize_locked()
// installs every nonzero free-list sentinel and generation seed before use.
OverlayState g_overlay{};

struct PrivateWakeRequest {
    SceKernelEqueue eq{};
    uint32_t queueIndex{kInvalidIndex};
    uint32_t wakeId{};
    uint32_t pendingIndex{kInvalidIndex};
    uint64_t queueGeneration{};
    bool disableWakeOnFailure{};
};

struct PrivateWakeCompletion {
    int rc{};
    bool pendingPublished{};
    uint32_t pendingCount{};
};

#if AMPR_EMU_DEBUG_LOG
struct OverlayCounters {
    std::atomic<uint64_t> publishAttempts{0};
    std::atomic<uint64_t> published{0};
    std::atomic<uint64_t> backpressure{0};
    std::atomic<uint64_t> fallbackHooks{0};
    std::atomic<uint64_t> fallbackQueue{0};
    std::atomic<uint64_t> fallbackRegistration{0};
    std::atomic<uint64_t> fallbackWake{0};
    std::atomic<uint64_t> wakeTriggers{0};
    std::atomic<uint64_t> wakeElisions{0};
    std::atomic<uint64_t> wakeNoWaiterSkips{0};
    std::atomic<uint64_t> wakeFailures{0};
    std::atomic<uint64_t> trackedWaits{0};
    std::atomic<uint64_t> directWaits{0};
    std::atomic<uint64_t> nativeWaits{0};
    std::atomic<uint64_t> nativeWaitZero{0};
    std::atomic<uint64_t> nativeWaitFinite{0};
    std::atomic<uint64_t> nativeWaitInfinite{0};
    std::atomic<uint64_t> nativeEvents{0};
    std::atomic<uint64_t> hiddenFiltered{0};
    std::atomic<uint64_t> staleWakes{0};
    std::atomic<uint64_t> syntheticEvents{0};
    std::atomic<uint64_t> syntheticDirectReturns{0};
    std::atomic<uint64_t> waitGraceAttempts{0};
    std::atomic<uint64_t> waitGraceHits{0};
    std::atomic<uint64_t> waitGraceMisses{0};
    std::atomic<uint64_t> waitGraceEvents{0};
    std::atomic<uint64_t> waitGraceSpinIterations{0};
    std::atomic<uint64_t> waitGraceElapsedUs{0};
    std::atomic<uint64_t> addRegistrations{0};
    std::atomic<uint64_t> deleteRegistrations{0};
    std::atomic<uint64_t> queueCapacityFailures{0};
    std::atomic<uint64_t> registrationCapacityFailures{0};
    std::atomic<uint64_t> queueHashRebuilds{0};
    std::atomic<uint64_t> registrationHashRebuilds{0};
    std::atomic<uint64_t> registrationCacheHits{0};
    std::atomic<uint64_t> registrationCacheMisses{0};
};

OverlayCounters g_counters;
#define APR_EQ_COUNT(name) g_counters.name.fetch_add(1u, std::memory_order_relaxed)
#define APR_EQ_ADD(name, value) \
    g_counters.name.fetch_add(static_cast<uint64_t>(value), std::memory_order_relaxed)
#define APR_EQ_LOCKED_COUNT(name) (++g_overlay.name)
#define APR_EQ_LOCKED_ADD(name, value) \
    (g_overlay.name += static_cast<uint64_t>(value))
#else
#define APR_EQ_COUNT(name) ((void)0)
#define APR_EQ_ADD(name, value) ((void)0)
#define APR_EQ_LOCKED_COUNT(name) ((void)0)
#define APR_EQ_LOCKED_ADD(name, value) ((void)0)
#endif

static SceKernelUseconds current_wait_grace_useconds_locked(
    const TrackedEqueue& queue) {
    return kWaitGraceAdaptive
               ? kWaitGraceLevels[queue.waitGraceLevel]
               : kWaitGraceUseconds;
}

static void note_wait_grace_delivery_locked(TrackedEqueue& queue,
                                            uint32_t delivered) {
    if (kWaitGraceUseconds == 0) {
        queue.waitGraceEligible = false;
        return;
    }
    if (!kWaitGraceAdaptive || queue.waitGraceCooldownEvents == 0) {
        queue.waitGraceEligible = true;
        return;
    }

    const uint32_t cooldown = queue.waitGraceCooldownEvents;
    APR_EQ_LOCKED_ADD(waitGraceCooldownEvents,
                      delivered < cooldown ? delivered : cooldown);
    if (delivered < cooldown) {
        queue.waitGraceCooldownEvents =
            static_cast<uint8_t>(cooldown - delivered);
        return;
    }

    queue.waitGraceCooldownEvents = 0;
    queue.waitGraceLevel = 0;
    queue.waitGraceTrend = 0;
    queue.waitGraceEligible = true;
    APR_EQ_LOCKED_COUNT(waitGraceRearms);
}

static void note_wait_grace_result_locked(TrackedEqueue& queue,
                                          bool hit,
                                          uint32_t delivered) {
    queue.waitGraceActive = false;
    if (!kWaitGraceAdaptive) {
        queue.waitGraceEligible = hit && kWaitGraceUseconds != 0;
        return;
    }

    if (hit) {
        queue.waitGraceTrend =
            queue.waitGraceTrend > 0 ? queue.waitGraceTrend + 1 : 1;
        if (queue.waitGraceTrend >= kWaitGraceHitsToGrow) {
            if (queue.waitGraceLevel < kWaitGraceMaxLevel) {
                ++queue.waitGraceLevel;
                APR_EQ_LOCKED_COUNT(waitGraceIncreases);
            }
            queue.waitGraceTrend = 0;
        }
        note_wait_grace_delivery_locked(queue, delivered);
        return;
    }

    queue.waitGraceEligible = false;
    queue.waitGraceTrend =
        queue.waitGraceTrend < 0 ? queue.waitGraceTrend - 1 : -1;
    if (queue.waitGraceLevel != 0) {
        --queue.waitGraceLevel;
        APR_EQ_LOCKED_COUNT(waitGraceDecreases);
    }
    if (queue.waitGraceTrend <= -kWaitGraceMissesToCooldown) {
        queue.waitGraceCooldownEvents = kWaitGraceCooldownEvents;
        queue.waitGraceTrend = 0;
        APR_EQ_LOCKED_COUNT(waitGraceCooldowns);
    }
}

class OverlayLock {
public:
    OverlayLock() : lock_(&g_overlay.lock) {
        uint32_t spins = 0;
        while (lock_->exchange(1u, std::memory_order_acquire) != 0u) {
            ampr_spin_pause_or_yield(spins);
        }
    }
    ~OverlayLock() { lock_->store(0u, std::memory_order_release); }
    OverlayLock(const OverlayLock&) = delete;
    OverlayLock& operator=(const OverlayLock&) = delete;
private:
    std::atomic<uint32_t>* lock_{};
};

static WaitEqueueFn original_wait_equeue() {
    return ampr_fixed_kernel_slot<WaitEqueueFn>(kAmprLibkernelHook_sceKernelWaitEqueue);
}

static DeleteEqueueFn original_delete_equeue() {
    return ampr_fixed_kernel_slot<DeleteEqueueFn>(kAmprLibkernelHook_sceKernelDeleteEqueue);
}

static AddAmprEventFn original_add_ampr_event() {
    return ampr_fixed_kernel_slot<AddAmprEventFn>(kAmprLibkernelHook_sceKernelAddAmprEvent);
}

static DeleteAmprEventFn original_delete_ampr_event() {
    return ampr_fixed_kernel_slot<DeleteAmprEventFn>(kAmprLibkernelHook_sceKernelDeleteAmprEvent);
}

static uint64_t monotonic_ns() {
    SceKernelTimespec ts{};
    if (sceKernelClockGettime(SCE_KERNEL_CLOCK_MONOTONIC, &ts) != 0 ||
        ts.tv_sec < 0 || ts.tv_nsec < 0) {
        return 0;
    }
    return static_cast<uint64_t>(ts.tv_sec) * kNanosecondsPerSecond +
           static_cast<uint64_t>(ts.tv_nsec);
}

struct NativeWaitDeadline {
    uint64_t expires{};
    // Nonzero selects the fast process-time-counter domain. Zero is the rare
    // validation fallback to CLOCK_MONOTONIC nanoseconds.
    uint64_t counterFrequency{};
};

static uint64_t timeout_to_counter_ticks(SceKernelUseconds timeout,
                                         uint64_t frequency) {
    const uint64_t timeout64 = static_cast<uint64_t>(timeout);
    const uint64_t wholeSeconds = timeout64 / kUsecondsPerSecond;
    const uint64_t partialUseconds = timeout64 % kUsecondsPerSecond;
    if (wholeSeconds != 0 && frequency > UINT64_MAX / wholeSeconds) {
        return UINT64_MAX;
    }
    uint64_t ticks = wholeSeconds * frequency;
    const uint64_t partialNumerator = partialUseconds * frequency;
    const uint64_t partialTicks = partialNumerator / kUsecondsPerSecond +
                                  (partialNumerator % kUsecondsPerSecond != 0);
    if (partialTicks > UINT64_MAX - ticks) {
        return UINT64_MAX;
    }
    return ticks + partialTicks;
}

static NativeWaitDeadline make_native_wait_deadline(
    SceKernelUseconds timeout,
    uint64_t counterFrequency) {
    NativeWaitDeadline deadline{};
    uint64_t start = 0;
    uint64_t duration = 0;
    if (counterFrequency != 0) {
        deadline.counterFrequency = counterFrequency;
        start = sceKernelGetProcessTimeCounter();
        duration = timeout_to_counter_ticks(timeout, counterFrequency);
    } else {
        start = monotonic_ns();
        if (start == 0) {
            return {};
        }
        duration = static_cast<uint64_t>(timeout) * 1000ull;
    }
    deadline.expires = duration > UINT64_MAX - start ? UINT64_MAX
                                                     : start + duration;
    return deadline;
}

static uint64_t next_generation64(uint64_t& value) {
    uint64_t out = value++;
    if (out == 0) {
        out = value++;
    }
    return out;
}

static void initialize_locked() {
    if (g_overlay.initialized) {
        return;
    }
    const uint64_t counterFrequency = sceKernelGetProcessTimeCounterFrequency();
    g_overlay.processTimeCounterFrequency =
        counterFrequency <= kMaxScaledCounterFrequency ? counterFrequency : 0;
    for (uint32_t i = 0; i < kQueueCapacity; ++i) {
        g_overlay.wakeTriggerState[i].store(0, std::memory_order_relaxed);
        g_overlay.queues[i] = {};
        g_overlay.queues[i].nextFree = i + 1u < kQueueCapacity ? i + 1u : kInvalidIndex;
    }
    for (uint32_t i = 0; i < kRegistrationCapacity; ++i) {
        g_overlay.registrations[i] = {};
        g_overlay.registrations[i].next =
            i + 1u < kRegistrationCapacity ? i + 1u : kInvalidIndex;
        g_overlay.registrationOwners[i] = 0;
    }
    for (uint32_t i = 0; i < kPendingCapacity; ++i) {
        g_overlay.pending[i] = {};
        g_overlay.pending[i].next = i + 1u < kPendingCapacity ? i + 1u : kInvalidIndex;
    }
    for (uint32_t& slot : g_overlay.queueHash) {
        slot = 0;
    }
    for (uint16_t& slot : g_overlay.registrationHash) {
        slot = 0;
    }
    g_overlay.queueFreeHead = 0;
    g_overlay.registrationFreeHead = 0;
    g_overlay.pendingFreeHead = 0;
    g_overlay.nextWakeId = kWakeIdBase;
    g_overlay.nextLifetimeGeneration = 1;
    g_overlay.nextRegistrationGeneration = 1;
    g_overlay.nextPublishEpoch = 1;
    g_overlay.liveQueues = 0;
    g_overlay.liveRegistrations = 0;
    g_overlay.livePending = 0;
    g_overlay.queueHashTombstones = 0;
    g_overlay.registrationHashTombstones = 0;
    g_overlay.pendingPoolBackpressured = false;
    g_overlay.publishEpoch.store(0, std::memory_order_relaxed);
#if AMPR_EMU_DEBUG_LOG
    g_overlay.pendingPeak = 0;
    g_overlay.liveWaitIntents = 0;
    g_overlay.waitIntentPeak = 0;
#endif
    g_overlay.initialized = true;
}

static uint32_t hash_queue(SceKernelEqueue eq) {
    uintptr_t value = reinterpret_cast<uintptr_t>(eq);
    value >>= 4u;
    value ^= value >> 17u;
    value *= static_cast<uintptr_t>(0x9e3779b97f4a7c15ull);
    return static_cast<uint32_t>(value) & (kQueueHashCapacity - 1u);
}

static uint32_t find_queue_index_locked(SceKernelEqueue eq) {
    if (!eq || !g_overlay.initialized) {
        return kInvalidIndex;
    }
    uint32_t slot = hash_queue(eq);
    for (uint32_t probe = 0; probe < kQueueHashCapacity; ++probe) {
        const uint32_t value = g_overlay.queueHash[slot];
        if (value == 0) {
            return kInvalidIndex;
        }
        if (value != kHashTombstone) {
            const uint32_t index = value - 1u;
            if (index < kQueueCapacity && g_overlay.queues[index].used &&
                g_overlay.queues[index].eq == eq) {
                return index;
            }
        }
        slot = (slot + 1u) & (kQueueHashCapacity - 1u);
    }
    return kInvalidIndex;
}

static bool insert_queue_hash_raw_locked(SceKernelEqueue eq,
                                         uint32_t queueIndex) {
    uint32_t slot = hash_queue(eq);
    uint32_t tombstone = kInvalidIndex;
    for (uint32_t probe = 0; probe < kQueueHashCapacity; ++probe) {
        const uint32_t value = g_overlay.queueHash[slot];
        if (value == kHashTombstone && tombstone == kInvalidIndex) {
            tombstone = slot;
        } else if (value == 0) {
            const bool reuseTombstone = tombstone != kInvalidIndex;
            g_overlay.queueHash[reuseTombstone ? tombstone : slot] = queueIndex + 1u;
            if (reuseTombstone && g_overlay.queueHashTombstones != 0) {
                --g_overlay.queueHashTombstones;
            }
            return true;
        }
        slot = (slot + 1u) & (kQueueHashCapacity - 1u);
    }
    if (tombstone != kInvalidIndex) {
        g_overlay.queueHash[tombstone] = queueIndex + 1u;
        if (g_overlay.queueHashTombstones != 0) {
            --g_overlay.queueHashTombstones;
        }
        return true;
    }
    return false;
}

static bool rebuild_queue_hash_locked() {
    for (uint32_t& slot : g_overlay.queueHash) {
        slot = 0;
    }
    g_overlay.queueHashTombstones = 0;
    for (uint32_t index = 0; index < kQueueCapacity; ++index) {
        const TrackedEqueue& queue = g_overlay.queues[index];
        if (queue.used && !insert_queue_hash_raw_locked(queue.eq, index)) {
            return false;
        }
    }
    APR_EQ_COUNT(queueHashRebuilds);
    return true;
}

static bool insert_queue_hash_locked(SceKernelEqueue eq, uint32_t queueIndex) {
    if (g_overlay.queueHashTombstones >= kQueueCapacity / 2u) {
        // Queue adoption/deletion is cold. Rebuild here so missing-queue waits
        // and APR publication do not degrade toward a full-table probe after
        // long-running create/delete churn.
        if (!rebuild_queue_hash_locked()) {
            return false;
        }
        return find_queue_index_locked(eq) == queueIndex;
    }
    return insert_queue_hash_raw_locked(eq, queueIndex);
}

static void erase_queue_hash_locked(SceKernelEqueue eq) {
    uint32_t slot = hash_queue(eq);
    for (uint32_t probe = 0; probe < kQueueHashCapacity; ++probe) {
        const uint32_t value = g_overlay.queueHash[slot];
        if (value == 0) {
            return;
        }
        if (value != kHashTombstone) {
            const uint32_t index = value - 1u;
            if (index < kQueueCapacity && g_overlay.queues[index].used &&
                g_overlay.queues[index].eq == eq) {
                g_overlay.queueHash[slot] = kHashTombstone;
                ++g_overlay.queueHashTombstones;
                return;
            }
        }
        slot = (slot + 1u) & (kQueueHashCapacity - 1u);
    }
}

static uint32_t allocate_queue_locked(SceKernelEqueue eq) {
    initialize_locked();
    const uint32_t index = g_overlay.queueFreeHead;
    if (index >= kQueueCapacity) {
        APR_EQ_COUNT(queueCapacityFailures);
        return kInvalidIndex;
    }
    TrackedEqueue& queue = g_overlay.queues[index];
    g_overlay.queueFreeHead = queue.nextFree;
    queue = {};
    queue.eq = eq;
    queue.used = true;
    queue.registrationHead = kInvalidIndex;
    queue.registrationCache = kInvalidIndex;
    queue.pendingHead = kInvalidIndex;
    queue.pendingTail = kInvalidIndex;
    queue.nextFree = kInvalidIndex;
    queue.waitGraceLevel = kWaitGraceInitialLevel;
    queue.lifetimeGeneration = next_generation64(g_overlay.nextLifetimeGeneration);
    if (!insert_queue_hash_locked(eq, index)) {
        queue = {};
        queue.nextFree = g_overlay.queueFreeHead;
        g_overlay.queueFreeHead = index;
        APR_EQ_COUNT(queueCapacityFailures);
        return kInvalidIndex;
    }
    ++g_overlay.liveQueues;
    return index;
}

static uint32_t hash_registration(uint32_t queueIndex, int32_t id) {
    uint32_t value = static_cast<uint32_t>(id);
    value ^= queueIndex * 0x9e3779b9u;
    value ^= value >> 16u;
    value *= 0x85ebca6bu;
    value ^= value >> 13u;
    return value & (kRegistrationHashCapacity - 1u);
}

static bool registration_hash_entry_matches_locked(uint16_t value,
                                                   uint32_t queueIndex,
                                                   int32_t id) {
    if (value == 0 || value == kRegistrationHashTombstone) {
        return false;
    }
    const uint32_t registrationIndex = static_cast<uint32_t>(value - 1u);
    return registrationIndex < kRegistrationCapacity &&
           g_overlay.registrationOwners[registrationIndex] == queueIndex + 1u &&
           g_overlay.registrations[registrationIndex].id == id;
}

static bool insert_registration_hash_raw_locked(uint32_t queueIndex,
                                                int32_t id,
                                                uint32_t registrationIndex) {
    uint32_t slot = hash_registration(queueIndex, id);
    uint32_t tombstone = kInvalidIndex;
    for (uint32_t probe = 0; probe < kRegistrationHashCapacity; ++probe) {
        const uint16_t value = g_overlay.registrationHash[slot];
        if (value == kRegistrationHashTombstone && tombstone == kInvalidIndex) {
            tombstone = slot;
        } else if (value == 0) {
            const bool reuseTombstone = tombstone != kInvalidIndex;
            g_overlay.registrationHash[reuseTombstone ? tombstone : slot] =
                static_cast<uint16_t>(registrationIndex + 1u);
            if (reuseTombstone && g_overlay.registrationHashTombstones != 0) {
                --g_overlay.registrationHashTombstones;
            }
            return true;
        }
        slot = (slot + 1u) & (kRegistrationHashCapacity - 1u);
    }
    if (tombstone != kInvalidIndex) {
        g_overlay.registrationHash[tombstone] =
            static_cast<uint16_t>(registrationIndex + 1u);
        if (g_overlay.registrationHashTombstones != 0) {
            --g_overlay.registrationHashTombstones;
        }
        return true;
    }
    return false;
}

static bool rebuild_registration_hash_locked() {
    for (uint16_t& slot : g_overlay.registrationHash) {
        slot = 0;
    }
    g_overlay.registrationHashTombstones = 0;
    for (uint32_t registrationIndex = 0;
         registrationIndex < kRegistrationCapacity;
         ++registrationIndex) {
        const uint16_t owner = g_overlay.registrationOwners[registrationIndex];
        if (owner != 0 &&
            !insert_registration_hash_raw_locked(
                static_cast<uint32_t>(owner - 1u),
                g_overlay.registrations[registrationIndex].id,
                registrationIndex)) {
            return false;
        }
    }
    APR_EQ_COUNT(registrationHashRebuilds);
    return true;
}

static bool insert_registration_hash_locked(uint32_t queueIndex,
                                            int32_t id,
                                            uint32_t registrationIndex) {
    if (g_overlay.registrationHashTombstones >= kRegistrationCapacity / 2u &&
        !rebuild_registration_hash_locked()) {
        return false;
    }
    return insert_registration_hash_raw_locked(queueIndex, id, registrationIndex);
}

static void erase_registration_hash_locked(uint32_t queueIndex, int32_t id) {
    uint32_t slot = hash_registration(queueIndex, id);
    for (uint32_t probe = 0; probe < kRegistrationHashCapacity; ++probe) {
        const uint16_t value = g_overlay.registrationHash[slot];
        if (value == 0) {
            return;
        }
        if (registration_hash_entry_matches_locked(value, queueIndex, id)) {
            g_overlay.registrationHash[slot] = kRegistrationHashTombstone;
            ++g_overlay.registrationHashTombstones;
            return;
        }
        slot = (slot + 1u) & (kRegistrationHashCapacity - 1u);
    }
}

static uint32_t find_registration_locked(uint32_t queueIndex,
                                         TrackedEqueue& queue,
                                         int32_t id) {
    if (queue.registrationCache < kRegistrationCapacity &&
        g_overlay.registrationOwners[queue.registrationCache] == queueIndex + 1u &&
        g_overlay.registrations[queue.registrationCache].id == id) {
        APR_EQ_COUNT(registrationCacheHits);
        return queue.registrationCache;
    }
    APR_EQ_COUNT(registrationCacheMisses);
    uint32_t slot = hash_registration(queueIndex, id);
    for (uint32_t probe = 0; probe < kRegistrationHashCapacity; ++probe) {
        const uint16_t value = g_overlay.registrationHash[slot];
        if (value == 0) {
            return kInvalidIndex;
        }
        if (registration_hash_entry_matches_locked(value, queueIndex, id)) {
            const uint32_t registrationIndex = static_cast<uint32_t>(value - 1u);
            queue.registrationCache = registrationIndex;
            return registrationIndex;
        }
        slot = (slot + 1u) & (kRegistrationHashCapacity - 1u);
    }
    return kInvalidIndex;
}

static uint32_t allocate_registration_locked(uint32_t queueIndex,
                                             TrackedEqueue& queue,
                                             int32_t id,
                                             void* udata) {
    uint32_t index = find_registration_locked(queueIndex, queue, id);
    if (index < kRegistrationCapacity) {
        MirroredRegistration& registration = g_overlay.registrations[index];
        registration.udata = udata;
        registration.generation = next_generation64(g_overlay.nextRegistrationGeneration);
        return index;
    }
    index = g_overlay.registrationFreeHead;
    if (index >= kRegistrationCapacity) {
        APR_EQ_COUNT(registrationCapacityFailures);
        return kInvalidIndex;
    }
    MirroredRegistration& registration = g_overlay.registrations[index];
    g_overlay.registrationFreeHead = registration.next;
    registration = {};
    registration.id = id;
    registration.udata = udata;
    registration.generation = next_generation64(g_overlay.nextRegistrationGeneration);
    registration.next = queue.registrationHead;
    if (!insert_registration_hash_locked(queueIndex, id, index)) {
        registration = {};
        registration.next = g_overlay.registrationFreeHead;
        g_overlay.registrationFreeHead = index;
        APR_EQ_COUNT(registrationCapacityFailures);
        return kInvalidIndex;
    }
    // Publish ownership only after insertion. A tombstone-driven rebuild runs
    // inside insert_registration_hash_locked(); publishing it earlier would
    // make that rebuild insert this new slot once, followed by a duplicate
    // insertion when control returns here.
    g_overlay.registrationOwners[index] = static_cast<uint16_t>(queueIndex + 1u);
    queue.registrationHead = index;
    queue.registrationCache = index;
    ++g_overlay.liveRegistrations;
    return index;
}

static void remove_registration_locked(uint32_t queueIndex,
                                       TrackedEqueue& queue,
                                       int32_t id) {
    uint32_t previous = kInvalidIndex;
    uint32_t index = queue.registrationHead;
    while (index < kRegistrationCapacity) {
        MirroredRegistration& registration = g_overlay.registrations[index];
        const uint32_t next = registration.next;
        if (registration.id == id) {
            erase_registration_hash_locked(queueIndex, id);
            if (previous < kRegistrationCapacity) {
                g_overlay.registrations[previous].next = next;
            } else {
                queue.registrationHead = next;
            }
            if (queue.registrationCache == index) {
                queue.registrationCache = kInvalidIndex;
            }
            g_overlay.registrationOwners[index] = 0;
            registration = {};
            registration.next = g_overlay.registrationFreeHead;
            g_overlay.registrationFreeHead = index;
            if (g_overlay.liveRegistrations != 0) {
                --g_overlay.liveRegistrations;
            }
            if (g_overlay.liveRegistrations == 0) {
                for (uint16_t& slot : g_overlay.registrationHash) {
                    slot = 0;
                }
                g_overlay.registrationHashTombstones = 0;
            }
            (void)next_generation64(g_overlay.nextRegistrationGeneration);
            return;
        }
        previous = index;
        index = next;
    }
}

static uint32_t allocate_pending_locked() {
    const uint32_t index = g_overlay.pendingFreeHead;
    if (index >= kPendingCapacity) {
        return kInvalidIndex;
    }
    g_overlay.pendingFreeHead = g_overlay.pending[index].next;
    g_overlay.pending[index] = {};
    g_overlay.pending[index].next = kInvalidIndex;
    ++g_overlay.livePending;
#if AMPR_EMU_DEBUG_LOG
    if (g_overlay.pendingPeak < g_overlay.livePending) {
        g_overlay.pendingPeak = g_overlay.livePending;
    }
#endif
    return index;
}

static void release_pending_locked(uint32_t index) {
    if (index >= kPendingCapacity) {
        return;
    }
    g_overlay.pending[index] = {};
    g_overlay.pending[index].next = g_overlay.pendingFreeHead;
    g_overlay.pendingFreeHead = index;
    if (g_overlay.livePending != 0) {
        --g_overlay.livePending;
    }
}

static bool take_pending_backpressure_progress_locked() {
    if (!g_overlay.pendingPoolBackpressured ||
        g_overlay.pendingFreeHead >= kPendingCapacity) {
        return false;
    }
    g_overlay.pendingPoolBackpressured = false;
    return true;
}

static void append_pending_locked(TrackedEqueue& queue, uint32_t index) {
    if (queue.pendingTail < kPendingCapacity) {
        g_overlay.pending[queue.pendingTail].next = index;
    } else {
        queue.pendingHead = index;
    }
    queue.pendingTail = index;
    ++queue.pendingCount;
}

static int drain_pending_locked(TrackedEqueue& queue,
                                SceKernelEvent* events,
                                int capacity,
                                bool* outNotifyReactor) {
    int count = 0;
    while (count < capacity && queue.pendingHead < kPendingCapacity) {
        const uint32_t index = queue.pendingHead;
        PendingEvent& pending = g_overlay.pending[index];
        queue.pendingHead = pending.next;
        if (queue.pendingHead >= kPendingCapacity) {
            queue.pendingTail = kInvalidIndex;
        }
        if (queue.pendingCount != 0) {
            --queue.pendingCount;
        }
        events[count++] = pending.event;
        release_pending_locked(index);
    }
    if (count != 0 && outNotifyReactor &&
        take_pending_backpressure_progress_locked()) {
        *outNotifyReactor = true;
    }
    return count;
}

enum class BeginPrivateWakeResult : uint8_t {
    AlreadyArmed,
    Scheduled,
    Unavailable,
};

static bool private_wake_in_flight_locked(const TrackedEqueue& queue) {
    return queue.wakeTriggering;
}

static BeginPrivateWakeResult begin_private_wake_locked(
    uint32_t queueIndex,
    TrackedEqueue& queue,
    uint32_t pendingIndex,
    bool disableWakeOnFailure,
    PrivateWakeRequest* request) {
    if (queue.wakeArmed) {
        APR_EQ_COUNT(wakeElisions);
        return BeginPrivateWakeResult::AlreadyArmed;
    }
    if (!queue.wakeReady || private_wake_in_flight_locked(queue) || !request) {
        return BeginPrivateWakeResult::Unavailable;
    }

    queue.wakeTriggering = true;
    g_overlay.wakeTriggerState[queueIndex].store(1u, std::memory_order_relaxed);
    request->eq = queue.eq;
    request->queueIndex = queueIndex;
    request->wakeId = queue.wakeId;
    request->pendingIndex = pendingIndex;
    request->queueGeneration = queue.lifetimeGeneration;
    request->disableWakeOnFailure = disableWakeOnFailure;
    return BeginPrivateWakeResult::Scheduled;
}

static void wait_for_private_wake(uint32_t queueIndex) {
    uint32_t spins = 0;
    while (queueIndex < kQueueCapacity &&
           g_overlay.wakeTriggerState[queueIndex].load(
               std::memory_order_acquire) != 0) {
        ampr_spin_pause_or_yield(spins);
    }
}

static PrivateWakeCompletion execute_private_wake(
    const PrivateWakeRequest& request) {
    PrivateWakeCompletion result{};
    result.rc = sceKernelTriggerUserEvent(
        request.eq,
        static_cast<int>(request.wakeId),
        static_cast<void*>(&g_overlay.queues[request.queueIndex]));

    {
        OverlayLock lock;
        if (result.rc == 0) {
            APR_EQ_COUNT(wakeTriggers);
        } else {
            APR_EQ_COUNT(wakeFailures);
        }

        if (request.queueIndex < kQueueCapacity) {
            TrackedEqueue& queue = g_overlay.queues[request.queueIndex];
            if (queue.used &&
                queue.lifetimeGeneration == request.queueGeneration &&
                private_wake_in_flight_locked(queue)) {
                queue.wakeArmed = result.rc == 0;
                if (result.rc == 0 &&
                    request.pendingIndex < kPendingCapacity) {
                    append_pending_locked(queue, request.pendingIndex);
                    if (queue.waitGraceActive) {
                        g_overlay.publishEpoch.store(
                            next_generation64(g_overlay.nextPublishEpoch),
                            std::memory_order_release);
                    }
                    result.pendingPublished = true;
                    result.pendingCount = queue.pendingCount;
                } else if (result.rc != 0 &&
                           request.disableWakeOnFailure) {
                    queue.wakeReady = false;
                }
                queue.wakeTriggering = false;
            }
        }

        if (request.pendingIndex < kPendingCapacity &&
            !result.pendingPublished) {
            release_pending_locked(request.pendingIndex);
        }
        if (request.queueIndex < kQueueCapacity) {
            g_overlay.wakeTriggerState[request.queueIndex].store(
                0u, std::memory_order_release);
        }
    }
    return result;
}

static bool attach_hidden_wake_locked(TrackedEqueue& queue) {
    for (uint32_t attempt = 0; attempt < kWakeAttachAttempts; ++attempt) {
        uint32_t candidate = g_overlay.nextWakeId++;
        if (candidate < kWakeIdBase || candidate == 0 || candidate > INT_MAX) {
            g_overlay.nextWakeId = kWakeIdBase + 1u;
            candidate = kWakeIdBase;
        }
        const int rc = sceKernelAddUserEventEdge(queue.eq, static_cast<int>(candidate));
        if (rc == 0) {
            queue.wakeId = candidate;
            queue.wakeRegistered = true;
            queue.wakeReady = true;
            return true;
        }
        if (rc != SCE_KERNEL_ERROR_EEXIST) {
            return false;
        }
    }
    return false;
}

static inline void note_wait_intent_added_locked() {
#if AMPR_EMU_DEBUG_LOG
    ++g_overlay.liveWaitIntents;
    if (g_overlay.waitIntentPeak < g_overlay.liveWaitIntents) {
        g_overlay.waitIntentPeak = g_overlay.liveWaitIntents;
    }
#endif
}

static inline void note_wait_intents_removed_locked(uint32_t count) {
#if AMPR_EMU_DEBUG_LOG
    g_overlay.liveWaitIntents =
        count < g_overlay.liveWaitIntents
            ? g_overlay.liveWaitIntents - count
            : 0u;
#else
    (void)count;
#endif
}

static bool release_queue_locked(uint32_t queueIndex) {
    if (queueIndex >= kQueueCapacity || !g_overlay.queues[queueIndex].used) {
        return false;
    }
    TrackedEqueue& queue = g_overlay.queues[queueIndex];
    while (queue.registrationHead < kRegistrationCapacity) {
        const uint32_t index = queue.registrationHead;
        queue.registrationHead = g_overlay.registrations[index].next;
        erase_registration_hash_locked(
            queueIndex, g_overlay.registrations[index].id);
        g_overlay.registrationOwners[index] = 0;
        g_overlay.registrations[index] = {};
        g_overlay.registrations[index].next = g_overlay.registrationFreeHead;
        g_overlay.registrationFreeHead = index;
        if (g_overlay.liveRegistrations != 0) {
            --g_overlay.liveRegistrations;
        }
    }
    while (queue.pendingHead < kPendingCapacity) {
        const uint32_t index = queue.pendingHead;
        queue.pendingHead = g_overlay.pending[index].next;
        release_pending_locked(index);
    }
    const bool notifyReactor = take_pending_backpressure_progress_locked();
    note_wait_intents_removed_locked(queue.nativeWaitIntent);
    erase_queue_hash_locked(queue.eq);
    queue = {};
    queue.nextFree = g_overlay.queueFreeHead;
    g_overlay.queueFreeHead = queueIndex;
    if (g_overlay.liveQueues != 0) {
        --g_overlay.liveQueues;
    }
    if (g_overlay.liveQueues == 0) {
        for (uint32_t& slot : g_overlay.queueHash) {
            slot = 0;
        }
        g_overlay.queueHashTombstones = 0;
    } else if (g_overlay.queueHashTombstones >= kQueueCapacity / 2u) {
        (void)rebuild_queue_hash_locked();
    }
    if (g_overlay.liveRegistrations == 0) {
        for (uint16_t& slot : g_overlay.registrationHash) {
            slot = 0;
        }
        g_overlay.registrationHashTombstones = 0;
    }
    return notifyReactor;
}

static void release_native_wait_intent(uint32_t queueIndex,
                                       uint64_t queueGeneration) {
    OverlayLock lock;
    if (queueIndex >= kQueueCapacity) {
        return;
    }
    TrackedEqueue& queue = g_overlay.queues[queueIndex];
    if (queue.used && queue.lifetimeGeneration == queueGeneration &&
        queue.nativeWaitIntent != 0) {
        --queue.nativeWaitIntent;
        note_wait_intents_removed_locked(1u);
    }
}

struct NativeWaitTransition {
    int syntheticCount{};
    bool notifyReactor{};
    bool nativeWaitIntentInstalled{};
};

static NativeWaitTransition prepare_native_wait(
    uint32_t queueIndex,
    uint64_t queueGeneration,
    SceKernelEvent* events,
    int num,
    bool leavingWaitGrace) {
    for (;;) {
        NativeWaitTransition result{};
        {
            OverlayLock lock;
            if (queueIndex >= kQueueCapacity ||
                !g_overlay.queues[queueIndex].used ||
                g_overlay.queues[queueIndex].lifetimeGeneration !=
                    queueGeneration) {
                return result;
            }
            TrackedEqueue& queue = g_overlay.queues[queueIndex];
            if (!private_wake_in_flight_locked(queue)) {
                result.syntheticCount =
                    drain_pending_locked(queue, events, num, &result.notifyReactor);
                if (result.syntheticCount != 0) {
                    if (leavingWaitGrace) {
                        note_wait_grace_result_locked(
                            queue, true, static_cast<uint32_t>(result.syntheticCount));
                    } else {
                        note_wait_grace_delivery_locked(
                            queue, static_cast<uint32_t>(result.syntheticCount));
                    }
                } else {
                    if (leavingWaitGrace) {
                        note_wait_grace_result_locked(queue, false, 0);
                    }
                    ++queue.nativeWaitIntent;
                    note_wait_intent_added_locked();
                    result.nativeWaitIntentInstalled = true;
                }
                return result;
            }
        }
        wait_for_private_wake(queueIndex);
    }
}

static bool is_hidden_wake(const SceKernelEvent& event,
                           uint32_t wakeId,
                           const TrackedEqueue* token) {
    return event.filter == SCE_KERNEL_EVFILT_USER &&
           static_cast<uint32_t>(event.ident) == wakeId &&
           event.udata == static_cast<const void*>(token);
}

static SceKernelUseconds remaining_timeout_us(const NativeWaitDeadline& deadline) {
    if (deadline.expires == 0) {
        return 0;
    }
    if (deadline.counterFrequency != 0) {
        const uint64_t now = sceKernelGetProcessTimeCounter();
        if (now >= deadline.expires) {
            return 0;
        }
        const uint64_t remainingTicks = deadline.expires - now;
        const uint64_t wholeSeconds = remainingTicks / deadline.counterFrequency;
        if (wholeSeconds > UINT32_MAX / kUsecondsPerSecond) {
            return UINT32_MAX;
        }
        const uint64_t partialTicks = remainingTicks % deadline.counterFrequency;
        const uint64_t partialNumerator = partialTicks * kUsecondsPerSecond;
        const uint64_t partialUseconds =
            partialNumerator / deadline.counterFrequency +
            (partialNumerator % deadline.counterFrequency != 0);
        const uint64_t remainingUs = wholeSeconds * kUsecondsPerSecond +
                                     partialUseconds;
        return static_cast<SceKernelUseconds>(
            remainingUs > UINT32_MAX ? UINT32_MAX : remainingUs);
    }

    const uint64_t now = monotonic_ns();
    if (now == 0 || now >= deadline.expires) {
        return 0;
    }
    const uint64_t remainingNs = deadline.expires - now;
    uint64_t remainingUs = remainingNs / 1000u + (remainingNs % 1000u != 0);
    if (remainingUs > UINT32_MAX) {
        remainingUs = UINT32_MAX;
    }
    return static_cast<SceKernelUseconds>(remainingUs);
}

#if AMPR_EMU_DEBUG_LOG
static uint64_t counter_ticks_to_useconds(uint64_t ticks,
                                          uint64_t frequency) {
    if (frequency == 0) {
        return 0;
    }
    const uint64_t wholeSeconds = ticks / frequency;
    const uint64_t partialTicks = ticks % frequency;
    if (wholeSeconds > UINT64_MAX / kUsecondsPerSecond) {
        return UINT64_MAX;
    }
    const uint64_t wholeUseconds = wholeSeconds * kUsecondsPerSecond;
    const uint64_t partialUseconds =
        (partialTicks * kUsecondsPerSecond) / frequency;
    return partialUseconds > UINT64_MAX - wholeUseconds
               ? UINT64_MAX
               : wholeUseconds + partialUseconds;
}
#endif

static NativeWaitTransition wait_for_recent_apr_event(
    uint32_t queueIndex,
    uint64_t queueGeneration,
    uint64_t observedPublishEpoch,
    uint64_t counterFrequency,
    SceKernelUseconds waitGraceUseconds,
    SceKernelEvent* events,
    int num) {
    NativeWaitTransition result{};
    APR_EQ_COUNT(waitGraceAttempts);

    const uint64_t start = sceKernelGetProcessTimeCounter();
    const uint64_t duration =
        timeout_to_counter_ticks(waitGraceUseconds, counterFrequency);
    const uint64_t expires = duration > UINT64_MAX - start
                                 ? UINT64_MAX
                                 : start + duration;
    uint64_t currentEpoch = observedPublishEpoch;
    uint32_t spins = 0;
    for (;;) {
        const uint64_t published =
            g_overlay.publishEpoch.load(std::memory_order_acquire);
        if (published != currentEpoch) {
            OverlayLock lock;
            if (queueIndex >= kQueueCapacity ||
                !g_overlay.queues[queueIndex].used ||
                g_overlay.queues[queueIndex].lifetimeGeneration !=
                    queueGeneration) {
                break;
            }
            TrackedEqueue& queue = g_overlay.queues[queueIndex];
            if (!private_wake_in_flight_locked(queue)) {
                result.syntheticCount = drain_pending_locked(
                    queue, events, num, &result.notifyReactor);
                if (result.syntheticCount != 0) {
                    note_wait_grace_result_locked(
                        queue, true, static_cast<uint32_t>(result.syntheticCount));
                    break;
                }
            }
            currentEpoch =
                g_overlay.publishEpoch.load(std::memory_order_relaxed);
        }

        __builtin_ia32_pause();
        ++spins;
        if ((spins & 31u) == 0 &&
            sceKernelGetProcessTimeCounter() >= expires) {
            break;
        }
    }

#if AMPR_EMU_DEBUG_LOG
    const uint64_t finish = sceKernelGetProcessTimeCounter();
    APR_EQ_ADD(waitGraceSpinIterations, spins);
    APR_EQ_ADD(waitGraceElapsedUs,
               counter_ticks_to_useconds(finish - start, counterFrequency));
#endif

    // This final pending check and native-intent transition share the overlay
    // lock with publication. An event therefore either drains here or observes
    // nativeWaitIntent and triggers the private wake after this lock is released.
    if (result.syntheticCount == 0) {
        result = prepare_native_wait(
            queueIndex, queueGeneration, events, num, true);
    }

#if AMPR_EMU_DEBUG_LOG
    if (result.syntheticCount != 0) {
        APR_EQ_COUNT(waitGraceHits);
        APR_EQ_ADD(waitGraceEvents, result.syntheticCount);
    } else {
        APR_EQ_COUNT(waitGraceMisses);
    }
#endif
    return result;
}

} // namespace

AprEqueuePublishResult apr_equeue_try_publish(SceKernelEqueue eq,
                                               int32_t id,
                                               uint64_t data) {
    APR_EQ_COUNT(publishAttempts);
    if (!g_overlay.hooksAvailable.load(std::memory_order_acquire)) {
        APR_EQ_COUNT(fallbackHooks);
        return AprEqueuePublishResult::NativeFallback;
    }

    [[maybe_unused]] void* registrationUdata = nullptr;
    [[maybe_unused]] uint64_t registrationGeneration = 0;
    [[maybe_unused]] uint32_t pendingCount = 0;
    for (;;) {
        PrivateWakeRequest wakeRequest{};
        uint32_t waitQueueIndex = kInvalidIndex;
        bool waitForWakeCompletion = false;
        bool executeWake = false;
        {
            OverlayLock lock;
            if (!g_overlay.hooksAvailable.load(std::memory_order_relaxed)) {
                APR_EQ_COUNT(fallbackHooks);
                return AprEqueuePublishResult::NativeFallback;
            }
            const uint32_t queueIndex = find_queue_index_locked(eq);
            if (queueIndex >= kQueueCapacity) {
                APR_EQ_COUNT(fallbackQueue);
                return AprEqueuePublishResult::NativeFallback;
            }
            TrackedEqueue& queue = g_overlay.queues[queueIndex];
            if (private_wake_in_flight_locked(queue)) {
                waitQueueIndex = queueIndex;
                waitForWakeCompletion = true;
            } else {
                const uint32_t registrationIndex =
                    find_registration_locked(queueIndex, queue, id);
                if (registrationIndex >= kRegistrationCapacity) {
                    APR_EQ_COUNT(fallbackRegistration);
                    return AprEqueuePublishResult::NativeFallback;
                }
                if (!queue.wakeReady) {
                    APR_EQ_COUNT(fallbackWake);
                    return AprEqueuePublishResult::NativeFallback;
                }

                const uint32_t pendingIndex = allocate_pending_locked();
                if (pendingIndex >= kPendingCapacity) {
                    g_overlay.pendingPoolBackpressured = true;
                    APR_EQ_COUNT(backpressure);
                    return AprEqueuePublishResult::Backpressure;
                }
                const MirroredRegistration& registration =
                    g_overlay.registrations[registrationIndex];
                PendingEvent& pending = g_overlay.pending[pendingIndex];
                pending.event.ident =
                    static_cast<uintptr_t>(static_cast<uint32_t>(id));
                pending.event.filter = SCE_KERNEL_EVFILT_AMPR;
                pending.event.flags = static_cast<uint16_t>(EV_ADD | EV_CLEAR);
                pending.event.fflags = 0;
                pending.event.data = static_cast<intptr_t>(data);
                pending.event.udata = registration.udata;
                pending.registrationGeneration = registration.generation;
                registrationUdata = registration.udata;
                registrationGeneration = registration.generation;

                // A future waiter drains an already-pending event directly.
                // A waiter committed to the native call needs the private
                // edge, but the syscall itself runs after this lock is
                // released. The reserved node is published only by the wake
                // completion transaction, preserving trigger-failure fallback.
                if (queue.nativeWaitIntent != 0) {
                    const BeginPrivateWakeResult wakeResult =
                        begin_private_wake_locked(
                            queueIndex,
                            queue,
                            pendingIndex,
                            true,
                            &wakeRequest);
                    if (wakeResult == BeginPrivateWakeResult::Scheduled) {
                        executeWake = true;
                    } else if (wakeResult ==
                               BeginPrivateWakeResult::AlreadyArmed) {
                        append_pending_locked(queue, pendingIndex);
                    } else {
                        release_pending_locked(pendingIndex);
                        APR_EQ_COUNT(fallbackWake);
                        return AprEqueuePublishResult::NativeFallback;
                    }
                } else {
                    APR_EQ_COUNT(wakeNoWaiterSkips);
                    append_pending_locked(queue, pendingIndex);
                }

                if (!executeWake) {
                    if (queue.waitGraceActive) {
                        g_overlay.publishEpoch.store(
                            next_generation64(g_overlay.nextPublishEpoch),
                            std::memory_order_release);
                    }
                    pendingCount = queue.pendingCount;
                    APR_EQ_COUNT(published);
                }
            }
        }

        if (waitForWakeCompletion) {
            wait_for_private_wake(waitQueueIndex);
            continue;
        }
        if (executeWake) {
            const PrivateWakeCompletion completion =
                execute_private_wake(wakeRequest);
            if (!completion.pendingPublished) {
                APR_EQ_COUNT(fallbackWake);
                [[maybe_unused]] const int wakeRc =
                    completion.rc != 0 ? completion.rc
                                       : SCE_KERNEL_ERROR_ENXIO;
                AMPR_LOGF("apr.equeue.publish.fallback eq=%p id=%d reason=wake-trigger rc=0x%x",
                          eq, id, wakeRc);
                return AprEqueuePublishResult::NativeFallback;
            }
            pendingCount = completion.pendingCount;
            APR_EQ_COUNT(published);
        }
        break;
    }
    AMPR_TLOGF("apr.equeue.publish eq=%p id=%d data=0x%llx udata=%p regGeneration=%llu pending=%u",
               eq,
               id,
               (unsigned long long)data,
               registrationUdata,
               (unsigned long long)registrationGeneration,
               pendingCount);
    return AprEqueuePublishResult::Published;
}

void apr_equeue_overlay_set_hooks_available(bool available) {
    g_overlay.hooksAvailable.store(available, std::memory_order_release);
}

void apr_equeue_overlay_shutdown() {
    g_overlay.hooksAvailable.store(false, std::memory_order_release);
    bool notifyReactor = false;
    {
        OverlayLock lock;
        if (!g_overlay.initialized) {
            return;
        }
        // Prevent an in-flight hook that observed the old capability state from
        // finding or reusing a slot while private wake syscalls run unlocked.
        g_overlay.initialized = false;
    }

    uint32_t queueIndex = 0;
    for (;;) {
        SceKernelEqueue wakeEq = nullptr;
        uint32_t wakeId = 0;
        bool deleteWake = false;
        bool waitForWakeCompletion = false;
        {
            OverlayLock lock;
            while (queueIndex < kQueueCapacity &&
                   !g_overlay.queues[queueIndex].used) {
                ++queueIndex;
            }
            if (queueIndex >= kQueueCapacity) {
                break;
            }

            const TrackedEqueue& queue = g_overlay.queues[queueIndex];
            if (private_wake_in_flight_locked(queue)) {
                waitForWakeCompletion = true;
            } else {
                wakeEq = queue.eq;
                wakeId = queue.wakeId;
                deleteWake = queue.wakeRegistered;
                notifyReactor |= release_queue_locked(queueIndex);
                ++queueIndex;
            }
        }
        if (waitForWakeCompletion) {
            wait_for_private_wake(queueIndex);
            continue;
        }
        if (deleteWake) {
            (void)sceKernelDeleteUserEvent(wakeEq, static_cast<int>(wakeId));
        }
    }
    if (notifyReactor) {
        apr_reactor_notify_external_progress();
    }
}

extern "C" int sceKernelAddAmprEvent_emul(SceKernelEqueue eq,
                                           int id,
                                           void* udata) {
    AddAmprEventFn const original = original_add_ampr_event();
    if (!original) {
        return SCE_KERNEL_ERROR_ENOSYS;
    }
    if (!g_overlay.hooksAvailable.load(std::memory_order_acquire)) {
        return original(eq, id, udata);
    }

    SceKernelEqueue cleanupWakeEq = nullptr;
    uint32_t cleanupWakeId = 0;
    int rc = 0;
    {
        OverlayLock lock;
        if (!g_overlay.hooksAvailable.load(std::memory_order_relaxed)) {
            return original(eq, id, udata);
        }
        rc = original(eq, id, udata);
        if (rc != 0) {
            return rc;
        }

        uint32_t queueIndex = find_queue_index_locked(eq);
        bool allocatedQueue = false;
        if (queueIndex >= kQueueCapacity) {
            queueIndex = allocate_queue_locked(eq);
            allocatedQueue = queueIndex < kQueueCapacity;
            if (!allocatedQueue) {
                return rc;
            }
            if (!attach_hidden_wake_locked(g_overlay.queues[queueIndex])) {
                release_queue_locked(queueIndex);
                return rc;
            }
        }

        TrackedEqueue& queue = g_overlay.queues[queueIndex];
        if (allocate_registration_locked(queueIndex, queue, id, udata) >=
            kRegistrationCapacity) {
            if (allocatedQueue) {
                cleanupWakeEq = queue.eq;
                cleanupWakeId = queue.wakeId;
                release_queue_locked(queueIndex);
            }
        } else {
            APR_EQ_COUNT(addRegistrations);
            AMPR_TLOGF("apr.equeue.registration.add eq=%p id=%d udata=%p queueGeneration=%llu",
                       eq,
                       id,
                       udata,
                       (unsigned long long)queue.lifetimeGeneration);
        }
    }
    if (cleanupWakeEq) {
        (void)sceKernelDeleteUserEvent(
            cleanupWakeEq, static_cast<int>(cleanupWakeId));
    }
    return rc;
}

extern "C" int sceKernelDeleteAmprEvent_emul(SceKernelEqueue eq, int id) {
    DeleteAmprEventFn const original = original_delete_ampr_event();
    if (!original) {
        return SCE_KERNEL_ERROR_ENOSYS;
    }
    if (!g_overlay.hooksAvailable.load(std::memory_order_acquire)) {
        return original(eq, id);
    }

    OverlayLock lock;
    if (!g_overlay.hooksAvailable.load(std::memory_order_relaxed)) {
        return original(eq, id);
    }
    const int rc = original(eq, id);
    if (rc == 0) {
        const uint32_t queueIndex = find_queue_index_locked(eq);
        if (queueIndex < kQueueCapacity) {
            remove_registration_locked(queueIndex, g_overlay.queues[queueIndex], id);
            APR_EQ_COUNT(deleteRegistrations);
        }
    }
    return rc;
}

extern "C" int sceKernelDeleteEqueue_emul(SceKernelEqueue eq) {
    DeleteEqueueFn const original = original_delete_equeue();
    if (!original) {
        return SCE_KERNEL_ERROR_ENOSYS;
    }
    if (!g_overlay.hooksAvailable.load(std::memory_order_acquire)) {
        return original(eq);
    }

    bool notifyReactor = false;
    int rc = 0;
    for (;;) {
        uint32_t waitQueueIndex = kInvalidIndex;
        bool waitForWakeCompletion = false;
        {
            OverlayLock lock;
            if (!g_overlay.hooksAvailable.load(std::memory_order_relaxed)) {
                return original(eq);
            }
            const uint32_t queueIndex = find_queue_index_locked(eq);
            if (queueIndex < kQueueCapacity &&
                private_wake_in_flight_locked(g_overlay.queues[queueIndex])) {
                waitQueueIndex = queueIndex;
                waitForWakeCompletion = true;
            } else {
                rc = original(eq);
                if (rc == 0 && queueIndex < kQueueCapacity) {
                    // The successful real equeue deletion already removed the
                    // private EVFILT_USER registration.
                    notifyReactor = release_queue_locked(queueIndex);
                }
            }
        }
        if (waitForWakeCompletion) {
            wait_for_private_wake(waitQueueIndex);
            continue;
        }
        break;
    }
    if (notifyReactor) {
        apr_reactor_notify_external_progress();
    }
    return rc;
}

extern "C" int sceKernelWaitEqueue_emul(SceKernelEqueue eq,
                                         SceKernelEvent* events,
                                         int num,
                                         int* out,
                                         SceKernelUseconds* timeout) {
    WaitEqueueFn const original = original_wait_equeue();
    if (!original) {
        return SCE_KERNEL_ERROR_ENOSYS;
    }
    if (!g_overlay.hooksAvailable.load(std::memory_order_acquire)) {
        APR_EQ_COUNT(directWaits);
        return original(eq, events, num, out, timeout);
    }
    if (!events || !out || num <= 0) {
        // Preserve libkernel's exact validation/error behavior and avoid the
        // overlay lock for calls that cannot consume synthetic events.
        APR_EQ_COUNT(directWaits);
        return original(eq, events, num, out, timeout);
    }

    uint32_t wakeId = 0;
    uint32_t trackedQueueIndex = kInvalidIndex;
    uint64_t queueGeneration = 0;
    uint64_t counterFrequency = 0;
    TrackedEqueue* wakeToken = nullptr;
    SceKernelUseconds requestedTimeout = 0;
    bool trackedQueue = false;
    bool notifyReactor = false;
    bool waitGraceAttempted = false;
    bool nativeWaitIntentInstalled = false;
    uint64_t observedPublishEpoch = 0;
    SceKernelUseconds waitGraceUseconds = 0;
    PrivateWakeRequest replacementWake{};
    bool executeReplacementWake = false;
    for (;;) {
        uint32_t waitQueueIndex = kInvalidIndex;
        bool waitForWakeCompletion = false;
        {
            OverlayLock lock;
            const uint32_t queueIndex = find_queue_index_locked(eq);
            if (queueIndex < kQueueCapacity) {
                TrackedEqueue& queue = g_overlay.queues[queueIndex];
                if (private_wake_in_flight_locked(queue)) {
                    waitQueueIndex = queueIndex;
                    waitForWakeCompletion = true;
                } else {
                    trackedQueue = true;
                    trackedQueueIndex = queueIndex;
                    wakeId = queue.wakeId;
                    queueGeneration = queue.lifetimeGeneration;
                    counterFrequency = g_overlay.processTimeCounterFrequency;
                    wakeToken = &g_overlay.queues[queueIndex];
                    *out = 0;
                    const int synthetic =
                        drain_pending_locked(queue, events, num, &notifyReactor);
                    if (synthetic != 0) {
                        *out = synthetic;
                        note_wait_grace_delivery_locked(
                            queue, static_cast<uint32_t>(synthetic));
                        APR_EQ_COUNT(syntheticDirectReturns);
                        APR_EQ_ADD(syntheticEvents, synthetic);
                        if (queue.pendingCount != 0 &&
                            queue.nativeWaitIntent != 0) {
                            executeReplacementWake =
                                begin_private_wake_locked(
                                    queueIndex,
                                    queue,
                                    kInvalidIndex,
                                    false,
                                    &replacementWake) ==
                                BeginPrivateWakeResult::Scheduled;
                        }
                    } else {
                        if (timeout) {
                            requestedTimeout = *timeout;
                        }
                        const bool nonPollingWait =
                            !timeout || requestedTimeout != 0;
                        SceKernelUseconds candidateGraceUseconds = 0;
                        if (counterFrequency != 0 && nonPollingWait &&
                            queue.waitGraceEligible &&
                            queue.nativeWaitIntent == 0) {
                            candidateGraceUseconds =
                                current_wait_grace_useconds_locked(queue);
                        }
                        if (candidateGraceUseconds != 0 &&
                            (!timeout ||
                             requestedTimeout > candidateGraceUseconds)) {
                            queue.waitGraceEligible = false;
                            queue.waitGraceActive = true;
                            waitGraceAttempted = true;
                            waitGraceUseconds = candidateGraceUseconds;
                            observedPublishEpoch = g_overlay.publishEpoch.load(
                                std::memory_order_relaxed);
                        } else {
                            ++queue.nativeWaitIntent;
                            note_wait_intent_added_locked();
                            nativeWaitIntentInstalled = true;
                        }
                    }
                }
            }
        }
        if (waitForWakeCompletion) {
            wait_for_private_wake(waitQueueIndex);
            continue;
        }
        break;
    }
    if (executeReplacementWake) {
        (void)execute_private_wake(replacementWake);
    }
    if (!trackedQueue) {
        APR_EQ_COUNT(directWaits);
        return original(eq, events, num, out, timeout);
    }
    APR_EQ_COUNT(trackedWaits);
    if (*out != 0) {
        if (notifyReactor) {
            apr_reactor_notify_external_progress();
        }
        return 0;
    }

    // Start a finite deadline before the optional userspace grace so the grace
    // consumes, rather than extends, the application's timeout.
    const NativeWaitDeadline deadline = timeout && requestedTimeout != 0
                                            ? make_native_wait_deadline(
                                                  requestedTimeout,
                                                  counterFrequency)
                                            : NativeWaitDeadline{};
    if (waitGraceAttempted) {
        const NativeWaitTransition grace = wait_for_recent_apr_event(
            trackedQueueIndex,
            queueGeneration,
            observedPublishEpoch,
            counterFrequency,
            waitGraceUseconds,
            events,
            num);
        nativeWaitIntentInstalled = grace.nativeWaitIntentInstalled;
        if (grace.notifyReactor) {
            apr_reactor_notify_external_progress();
        }
        if (grace.syntheticCount != 0) {
            *out = grace.syntheticCount;
            APR_EQ_ADD(syntheticEvents, grace.syntheticCount);
            APR_EQ_COUNT(syntheticDirectReturns);
            return 0;
        }
    }
    if (!timeout) {
        APR_EQ_COUNT(nativeWaitInfinite);
    } else if (requestedTimeout == 0) {
        APR_EQ_COUNT(nativeWaitZero);
    } else {
        APR_EQ_COUNT(nativeWaitFinite);
    }

    bool firstNativeWait = !waitGraceAttempted;
    bool nativeWaitAttempted = false;
    for (;;) {
        if (!nativeWaitIntentInstalled) {
            const NativeWaitTransition transition = prepare_native_wait(
                trackedQueueIndex, queueGeneration, events, num, false);
            nativeWaitIntentInstalled =
                transition.nativeWaitIntentInstalled;
            if (transition.notifyReactor) {
                apr_reactor_notify_external_progress();
            }
            if (transition.syntheticCount != 0) {
                *out = transition.syntheticCount;
                APR_EQ_ADD(syntheticEvents, transition.syntheticCount);
                APR_EQ_COUNT(syntheticDirectReturns);
                return 0;
            }
        }

        SceKernelUseconds localTimeout = 0;
        SceKernelUseconds* localTimeoutPtr = nullptr;
        if (timeout) {
            if (firstNativeWait || deadline.expires == 0) {
                localTimeout = requestedTimeout;
            } else {
                localTimeout = remaining_timeout_us(deadline);
            }
            if (!firstNativeWait && localTimeout == 0 && nativeWaitAttempted) {
                if (nativeWaitIntentInstalled) {
                    release_native_wait_intent(
                        trackedQueueIndex, queueGeneration);
                }
                return SCE_KERNEL_ERROR_ETIMEDOUT;
            }
            localTimeoutPtr = &localTimeout;
        }
        firstNativeWait = false;

        int nativeCount = 0;
        APR_EQ_COUNT(nativeWaits);
        nativeWaitAttempted = true;
        const int rc = original(eq, events, num, &nativeCount, localTimeoutPtr);
        if (nativeWaitIntentInstalled) {
            release_native_wait_intent(trackedQueueIndex, queueGeneration);
            nativeWaitIntentInstalled = false;
        }
        if (rc != 0) {
            return rc;
        }
        if (nativeCount < 0 || nativeCount > num) {
            return SCE_KERNEL_ERROR_EIO;
        }

        int realCount = 0;
        bool sawHidden = false;
        for (int i = 0; i < nativeCount; ++i) {
            if (is_hidden_wake(events[i], wakeId, wakeToken)) {
                sawHidden = true;
                APR_EQ_COUNT(hiddenFiltered);
                continue;
            }
            if (realCount != i) {
                events[realCount] = events[i];
            }
            ++realCount;
            APR_EQ_COUNT(nativeEvents);
        }

        int syntheticCount = 0;
        bool notifyReactorAfterDrain = false;
        PrivateWakeRequest replacementWake{};
        bool executeReplacementWake = false;
        for (;;) {
            bool waitForWakeCompletion = false;
            {
                OverlayLock lock;
                if (trackedQueueIndex < kQueueCapacity &&
                    g_overlay.queues[trackedQueueIndex].used &&
                    g_overlay.queues[trackedQueueIndex].lifetimeGeneration ==
                        queueGeneration) {
                    TrackedEqueue& queue =
                        g_overlay.queues[trackedQueueIndex];
                    if (private_wake_in_flight_locked(queue)) {
                        waitForWakeCompletion = true;
                    } else {
                        if (sawHidden) {
                            queue.wakeArmed = false;
                        }
                        syntheticCount = drain_pending_locked(
                            queue,
                            events + realCount,
                            num - realCount,
                            &notifyReactorAfterDrain);
                        if (syntheticCount != 0) {
                            note_wait_grace_delivery_locked(
                                queue, static_cast<uint32_t>(syntheticCount));
                        }
                        APR_EQ_ADD(syntheticEvents, syntheticCount);
                        if (queue.pendingCount != 0 &&
                            queue.nativeWaitIntent != 0) {
                            executeReplacementWake =
                                begin_private_wake_locked(
                                    trackedQueueIndex,
                                    queue,
                                    kInvalidIndex,
                                    false,
                                    &replacementWake) ==
                                BeginPrivateWakeResult::Scheduled;
                        }
                    }
                }
            }
            if (waitForWakeCompletion) {
                wait_for_private_wake(trackedQueueIndex);
                continue;
            }
            break;
        }
        if (executeReplacementWake) {
            (void)execute_private_wake(replacementWake);
        }

        const int total = realCount + syntheticCount;
        if (notifyReactorAfterDrain) {
            apr_reactor_notify_external_progress();
        }
        if (total != 0) {
            *out = total;
            return 0;
        }
        if (sawHidden) {
            APR_EQ_COUNT(staleWakes);
        }
        // A stale private edge is invisible to the application. The next loop
        // first performs one locked pending-drain/native-intent transition, then
        // derives a new relative timeout from the original absolute deadline.
    }
}

void apr_equeue_log_counters(const char* reason, bool reset) {
#if AMPR_EMU_DEBUG_LOG
#define APR_EQ_READ(name) (reset ? g_counters.name.exchange(0, std::memory_order_relaxed) : \
                                   g_counters.name.load(std::memory_order_relaxed))
    const uint64_t publishAttempts = APR_EQ_READ(publishAttempts);
    const uint64_t published = APR_EQ_READ(published);
    const uint64_t backpressure = APR_EQ_READ(backpressure);
    const uint64_t fallbackHooks = APR_EQ_READ(fallbackHooks);
    const uint64_t fallbackQueue = APR_EQ_READ(fallbackQueue);
    const uint64_t fallbackRegistration = APR_EQ_READ(fallbackRegistration);
    const uint64_t fallbackWake = APR_EQ_READ(fallbackWake);
    const uint64_t wakeTriggers = APR_EQ_READ(wakeTriggers);
    const uint64_t wakeElisions = APR_EQ_READ(wakeElisions);
    const uint64_t wakeNoWaiterSkips = APR_EQ_READ(wakeNoWaiterSkips);
    const uint64_t wakeFailures = APR_EQ_READ(wakeFailures);
    const uint64_t trackedWaits = APR_EQ_READ(trackedWaits);
    const uint64_t directWaits = APR_EQ_READ(directWaits);
    const uint64_t nativeWaits = APR_EQ_READ(nativeWaits);
    const uint64_t nativeWaitZero = APR_EQ_READ(nativeWaitZero);
    const uint64_t nativeWaitFinite = APR_EQ_READ(nativeWaitFinite);
    const uint64_t nativeWaitInfinite = APR_EQ_READ(nativeWaitInfinite);
    const uint64_t nativeEvents = APR_EQ_READ(nativeEvents);
    const uint64_t hiddenFiltered = APR_EQ_READ(hiddenFiltered);
    const uint64_t staleWakes = APR_EQ_READ(staleWakes);
    const uint64_t syntheticEvents = APR_EQ_READ(syntheticEvents);
    const uint64_t syntheticDirectReturns = APR_EQ_READ(syntheticDirectReturns);
    const uint64_t waitGraceAttempts = APR_EQ_READ(waitGraceAttempts);
    const uint64_t waitGraceHits = APR_EQ_READ(waitGraceHits);
    const uint64_t waitGraceMisses = APR_EQ_READ(waitGraceMisses);
    const uint64_t waitGraceEvents = APR_EQ_READ(waitGraceEvents);
    const uint64_t waitGraceSpinIterations = APR_EQ_READ(waitGraceSpinIterations);
    const uint64_t waitGraceElapsedUs = APR_EQ_READ(waitGraceElapsedUs);
    const uint64_t addRegistrations = APR_EQ_READ(addRegistrations);
    const uint64_t deleteRegistrations = APR_EQ_READ(deleteRegistrations);
    const uint64_t queueCapacityFailures = APR_EQ_READ(queueCapacityFailures);
    const uint64_t registrationCapacityFailures = APR_EQ_READ(registrationCapacityFailures);
    const uint64_t queueHashRebuilds = APR_EQ_READ(queueHashRebuilds);
    const uint64_t registrationHashRebuilds = APR_EQ_READ(registrationHashRebuilds);
    const uint64_t registrationCacheHits = APR_EQ_READ(registrationCacheHits);
    const uint64_t registrationCacheMisses = APR_EQ_READ(registrationCacheMisses);
#undef APR_EQ_READ
    uint64_t pendingPeak = 0;
    uint64_t liveWaitIntents = 0;
    uint64_t waitIntentPeak = 0;
    uint32_t liveQueues = 0;
    uint32_t liveRegistrations = 0;
    uint32_t livePending = 0;
    uint64_t waitGraceIncreases = 0;
    uint64_t waitGraceDecreases = 0;
    uint64_t waitGraceCooldowns = 0;
    uint64_t waitGraceCooldownEvents = 0;
    uint64_t waitGraceRearms = 0;
    {
        OverlayLock lock;
        liveQueues = g_overlay.liveQueues;
        liveRegistrations = g_overlay.liveRegistrations;
        livePending = g_overlay.livePending;
        liveWaitIntents = g_overlay.liveWaitIntents;
        // Serialize peak resets with their hot-path updates. Current occupancy
        // is the new interval's baseline, so an in-flight high-water update
        // cannot be overwritten by a later store.
        pendingPeak = g_overlay.pendingPeak;
        waitIntentPeak = g_overlay.waitIntentPeak;
        waitGraceIncreases = g_overlay.waitGraceIncreases;
        waitGraceDecreases = g_overlay.waitGraceDecreases;
        waitGraceCooldowns = g_overlay.waitGraceCooldowns;
        waitGraceCooldownEvents = g_overlay.waitGraceCooldownEvents;
        waitGraceRearms = g_overlay.waitGraceRearms;
        if (reset) {
            g_overlay.pendingPeak = livePending;
            g_overlay.waitIntentPeak = static_cast<uint32_t>(liveWaitIntents);
            g_overlay.waitGraceIncreases = 0;
            g_overlay.waitGraceDecreases = 0;
            g_overlay.waitGraceCooldowns = 0;
            g_overlay.waitGraceCooldownEvents = 0;
            g_overlay.waitGraceRearms = 0;
        }
    }
    AMPR_LOGF("apr.equeue.counters reason=%s hooks=%u publishAttempts=%llu published=%llu backpressure=%llu fallbackHooks=%llu fallbackQueue=%llu fallbackRegistration=%llu fallbackWake=%llu wakeTriggers=%llu wakeElisions=%llu wakeNoWaiterSkips=%llu wakeFailures=%llu",
              reason ? reason : "unknown",
              g_overlay.hooksAvailable.load(std::memory_order_acquire) ? 1u : 0u,
              (unsigned long long)publishAttempts,
              (unsigned long long)published,
              (unsigned long long)backpressure,
              (unsigned long long)fallbackHooks,
              (unsigned long long)fallbackQueue,
              (unsigned long long)fallbackRegistration,
              (unsigned long long)fallbackWake,
              (unsigned long long)wakeTriggers,
              (unsigned long long)wakeElisions,
              (unsigned long long)wakeNoWaiterSkips,
              (unsigned long long)wakeFailures);
    AMPR_LOGF("apr.equeue.wait.counters reason=%s trackedWaits=%llu directWaits=%llu nativeWaits=%llu nativeWaitZero=%llu nativeWaitFinite=%llu nativeWaitInfinite=%llu liveWaitIntents=%llu waitIntentPeak=%llu nativeEvents=%llu hiddenFiltered=%llu staleWakes=%llu syntheticEvents=%llu syntheticDirectReturns=%llu",
              reason ? reason : "unknown",
              (unsigned long long)trackedWaits,
              (unsigned long long)directWaits,
              (unsigned long long)nativeWaits,
              (unsigned long long)nativeWaitZero,
              (unsigned long long)nativeWaitFinite,
              (unsigned long long)nativeWaitInfinite,
              (unsigned long long)liveWaitIntents,
              (unsigned long long)waitIntentPeak,
              (unsigned long long)nativeEvents,
              (unsigned long long)hiddenFiltered,
              (unsigned long long)staleWakes,
              (unsigned long long)syntheticEvents,
              (unsigned long long)syntheticDirectReturns);
    AMPR_LOGF("apr.equeue.grace.counters reason=%s configuredUs=%u adaptive=%u minUs=%u maxUs=%u attempts=%llu hits=%llu misses=%llu events=%llu spinIterations=%llu elapsedUs=%llu increases=%llu decreases=%llu cooldowns=%llu cooldownEvents=%llu rearms=%llu",
              reason ? reason : "unknown",
              static_cast<unsigned>(kWaitGraceUseconds),
              kWaitGraceAdaptive ? 1u : 0u,
              static_cast<unsigned>(
                  kWaitGraceAdaptive ? kWaitGraceMinUseconds
                                     : kWaitGraceUseconds),
              static_cast<unsigned>(
                  kWaitGraceAdaptive ? kWaitGraceMaxUseconds
                                     : kWaitGraceUseconds),
              (unsigned long long)waitGraceAttempts,
              (unsigned long long)waitGraceHits,
              (unsigned long long)waitGraceMisses,
              (unsigned long long)waitGraceEvents,
              (unsigned long long)waitGraceSpinIterations,
              (unsigned long long)waitGraceElapsedUs,
              (unsigned long long)waitGraceIncreases,
              (unsigned long long)waitGraceDecreases,
              (unsigned long long)waitGraceCooldowns,
              (unsigned long long)waitGraceCooldownEvents,
              (unsigned long long)waitGraceRearms);
    AMPR_LOGF("apr.equeue.storage.counters reason=%s addRegistrations=%llu deleteRegistrations=%llu queueCapacityFailures=%llu registrationCapacityFailures=%llu queueHashRebuilds=%llu registrationHashRebuilds=%llu registrationCacheHits=%llu registrationCacheMisses=%llu pendingPeak=%llu liveQueues=%u liveRegistrations=%u livePending=%u",
              reason ? reason : "unknown",
              (unsigned long long)addRegistrations,
              (unsigned long long)deleteRegistrations,
              (unsigned long long)queueCapacityFailures,
              (unsigned long long)registrationCapacityFailures,
              (unsigned long long)queueHashRebuilds,
              (unsigned long long)registrationHashRebuilds,
              (unsigned long long)registrationCacheHits,
              (unsigned long long)registrationCacheMisses,
              (unsigned long long)pendingPeak,
              liveQueues,
              liveRegistrations,
              livePending);
#else
    (void)reason;
    (void)reset;
#endif
}

#endif // AMPR_EMU_APR_LOCAL_EQUEUE
