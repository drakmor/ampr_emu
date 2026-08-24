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
#include "ampr_libkernel_hook.h"

#include <_kernel.h>
#include <atomic>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <sys/event.h>
#include <sys/sce_errno.h>

namespace {

using WaitEqueueFn = int (*)(SceKernelEqueue, SceKernelEvent*, int, int*, SceKernelUseconds*);
using CreateEqueueFn = int (*)(SceKernelEqueue*, const char*);
using DeleteEqueueFn = int (*)(SceKernelEqueue);
using AddAmprEventFn = int (*)(SceKernelEqueue, int, void*);
using DeleteAmprEventFn = int (*)(SceKernelEqueue, int);
using AddAmprSystemEventFn = int (*)(SceKernelEqueue, int, int, void*);
using AddTimerEventFn = int (*)(SceKernelEqueue, int, SceKernelUseconds, void*);
using AddFdEventFn = int (*)(SceKernelEqueue, int, size_t, void*);
using AddFileEventFn = int (*)(SceKernelEqueue, int, int, void*);
using AddUserEventFn = int (*)(SceKernelEqueue, int);
using AddHRTimerEventFn = int (*)(SceKernelEqueue, int, SceKernelTimespec*, void*);
template <typename Value>
using ExternalAddEventFn = int (*)(SceKernelEqueue, Value, void*);

constexpr uint32_t kInvalidIndex = UINT32_MAX;
constexpr uint32_t kHashTombstone = UINT32_MAX;
constexpr uint32_t kQueueCapacity = AMPR_EMU_APR_LOCAL_EQUEUE_QUEUE_CAPACITY;
constexpr uint32_t kRegistrationCapacity = AMPR_EMU_APR_LOCAL_EQUEUE_REG_CAPACITY;
constexpr uint32_t kPendingCapacity = AMPR_EMU_APR_LOCAL_EQUEUE_PENDING_CAPACITY;
constexpr uint32_t kQueueHashCapacity = kQueueCapacity * 2u;
constexpr uint32_t kAmmBufferHashCapacity = kQueueHashCapacity;
constexpr uint32_t kRegistrationHashCapacity = kRegistrationCapacity * 2u;
constexpr uint32_t kWakeIdBase = 0x5a4d5000u;
constexpr uint32_t kWakeAttachAttempts = 64u;
constexpr uint16_t kRegistrationHashTombstone = UINT16_MAX;
constexpr uint64_t kUsecondsPerSecond = 1000000ull;
constexpr uint64_t kNanosecondsPerSecond = 1000000000ull;
constexpr uint64_t kMaxScaledCounterFrequency = UINT64_MAX / kUsecondsPerSecond;
#ifdef SCE_KERNEL_EVFILT_AMPR_SYSTEM
constexpr int16_t kAmprSystemEventFilter = SCE_KERNEL_EVFILT_AMPR_SYSTEM;
#else
// SDK 10.000 sys/event.h assigns EVFILT_AMPR_SYSTEM the stable ABI value -30.
constexpr int16_t kAmprSystemEventFilter = -30;
#endif

static_assert(kQueueCapacity != 0 && kRegistrationCapacity != 0 && kPendingCapacity != 0,
              "APR local equeue pools must not be empty");
static_assert((kQueueHashCapacity & (kQueueHashCapacity - 1u)) == 0,
              "APR local equeue hash capacity must be a power of two");
static_assert((kAmmBufferHashCapacity & (kAmmBufferHashCapacity - 1u)) == 0,
              "AMM command-buffer hash capacity must be a power of two");
static_assert((kRegistrationHashCapacity & (kRegistrationHashCapacity - 1u)) == 0,
              "APR local equeue registration hash capacity must be a power of two");
static_assert(kQueueCapacity <= UINT16_MAX - 1u,
              "APR local equeue queue owner does not fit fixed registration metadata");
static_assert(kRegistrationCapacity <= UINT16_MAX - 1u,
              "APR local equeue registration index does not fit fixed hash storage");
static_assert(std::atomic<uint8_t>::is_always_lock_free,
              "APR local equeue wake state must use lock-free byte atomics");
static_assert(std::atomic<uintptr_t>::is_always_lock_free,
              "AMM-classified equeue cache must use lock-free pointer atomics");

struct MirroredRegistration {
    uint32_t next{};
    int32_t id{};
    void* udata{};
    uint64_t generation{};
};

struct PendingEvent {
    uint32_t next{};
    uint32_t registrationIndex{};
    SceKernelEvent event{};
    uint64_t registrationGeneration{};
};
static_assert(sizeof(PendingEvent) == sizeof(SceKernelEvent) + 16u,
              "APR local equeue pending metadata grew fixed .bss storage");

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
    uint8_t controlDepth{};
    bool used : 1;
    bool wakeRegistered : 1;
    bool wakeReady : 1;
    bool wakeArmed : 1;
    bool wakeTriggering : 1;
    bool amprSourceSeen : 1;
    bool mixedSourceSeen : 1;
    bool ammSourceSeen : 1;
};
static_assert(sizeof(TrackedEqueue) == 56u,
              "APR local equeue flag packing changed fixed .bss storage");

struct OverlayState {
    std::atomic<uint32_t> lock{0};
    std::atomic<bool> hooksAvailable{false};
    std::atomic<bool> classificationHooksAvailable{false};
    std::atomic<bool> localWaitSyncReady{false};
    bool initialized{};
    ScePthreadMutex localWaitMutex{};
    ScePthreadCond localWaitCond{};
    uint32_t queueFreeHead{};
    uint32_t registrationFreeHead{};
    uint32_t pendingFreeHead{};
    uint32_t nextWakeId{};
    uint64_t nextLifetimeGeneration{};
    uint64_t nextRegistrationGeneration{};
    uint64_t processTimeCounterFrequency{};
    uint32_t liveQueues{};
    uint32_t liveRegistrations{};
    uint32_t livePending{};
    uint32_t queueHashTombstones{};
    uint32_t registrationHashTombstones{};
    uint32_t ammQueueHashTombstones{};
    bool pendingPoolBackpressured{};
#if AMPR_EMU_DEBUG_LOG
    uint32_t pendingPeak{};
    uint32_t liveWaitIntents{};
    uint32_t waitIntentPeak{};
#endif
    // The bit in TrackedEqueue is the lock-protected hot-path predicate. This
    // slot-local atomic exists only for waiting after the overlay lock is
    // released, so completion on another queue cannot cause a false retry.
    alignas(64) std::atomic<uint8_t> wakeTriggerState[kQueueCapacity]{};
    alignas(64) std::atomic<uint64_t> localWakeEpoch[kQueueCapacity]{};
    alignas(64) std::atomic<uintptr_t> ammQueueHash[kQueueHashCapacity]{};
    TrackedEqueue queues[kQueueCapacity]{};
    MirroredRegistration registrations[kRegistrationCapacity]{};
    PendingEvent pending[kPendingCapacity]{};
    uint32_t queueHash[kQueueHashCapacity]{};
    uint16_t registrationHash[kRegistrationHashCapacity]{};
    uint16_t registrationOwners[kRegistrationCapacity]{};
    int16_t registrationFilters[kRegistrationCapacity]{};
};

// Keep the large fixed pools zero-initialized in .bss. initialize_locked()
// installs every nonzero free-list sentinel and generation seed before use.
OverlayState g_overlay{};

ScePthreadOnce g_controlOnce = SCE_PTHREAD_ONCE_INIT;
ScePthreadMutex g_controlMutex{};
std::atomic<int> g_controlInitRc{SCE_KERNEL_ERROR_EAGAIN};

struct AmmCommandBufferRegistry {
    std::atomic<uint32_t> lock{0};
    std::atomic<bool> trackingLost{false};
    uintptr_t slots[kAmmBufferHashCapacity]{};
};

// Address 0 is empty and 1 is a tombstone. Retail command-buffer objects are
// naturally aligned, so neither value can name a live object.
AmmCommandBufferRegistry g_ammCommandBuffers{};

struct PrivateWakeRequest {
    SceKernelEqueue eq{};
    uint32_t queueIndex{kInvalidIndex};
    uint32_t wakeId{};
    uint32_t pendingIndex{kInvalidIndex};
    uint64_t queueGeneration{};
};

struct PrivateWakeCompletion {
    int rc{};
    bool pendingPublished{};
    bool replacementStillRequired{};
    uint32_t pendingCount{};
    uint32_t nativeWaitIntent{};
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
    std::atomic<uint64_t> staleRegistrationDrops{0};
    std::atomic<uint64_t> syntheticEvents{0};
    std::atomic<uint64_t> syntheticDirectReturns{0};
    std::atomic<uint64_t> localWaits{0};
    std::atomic<uint64_t> localWakeups{0};
    std::atomic<uint64_t> localTimeouts{0};
    std::atomic<uint64_t> localEntries{0};
    std::atomic<uint64_t> localExits{0};
    std::atomic<uint64_t> mixedPromotions{0};
    std::atomic<uint64_t> ammEventQueues{0};
    std::atomic<uint64_t> ammBufferRegistrations{0};
    std::atomic<uint64_t> ammTrackingFailures{0};
    std::atomic<uint64_t> silentUnclassifiedDeletes{0};
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
#else
#define APR_EQ_COUNT(name) ((void)0)
#define APR_EQ_ADD(name, value) ((void)0)
#endif

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

[[noreturn]] static void abort_control_sync(const char* operation, int rc) {
    AMPR_CRITICAL_LOGF("apr.equeue.control.sync-fail operation=%s rc=0x%x action=abort",
                       operation ? operation : "unknown",
                       rc);
    AMPR_KLOGF("ampr.abort reason=apr.equeue.control.sync-fail file=%s line=%d",
               __FILE__,
               __LINE__);
    std::abort();
}

static void initialize_control_once() {
    int controlRc = 0;
    ScePthreadMutexattr attr{};
    controlRc = scePthreadMutexattrInit(&attr);
    if (controlRc == 0) {
        controlRc = scePthreadMutexattrSettype(
            &attr, SCE_PTHREAD_MUTEX_RECURSIVE);
        if (controlRc == 0) {
            controlRc = scePthreadMutexInit(
                &g_controlMutex, &attr, "ampr_eq_control");
        }
        (void)scePthreadMutexattrDestroy(&attr);
    }

    const uint64_t counterFrequency = sceKernelGetProcessTimeCounterFrequency();
    g_overlay.processTimeCounterFrequency =
        counterFrequency <= kMaxScaledCounterFrequency ? counterFrequency : 0;
    if (!g_overlay.localWaitSyncReady.load(std::memory_order_relaxed)) {
        const int mutexRc = scePthreadMutexInit(
            &g_overlay.localWaitMutex, nullptr, "ampr_eq_local");
        if (mutexRc == 0) {
            const int condRc = scePthreadCondInit(
                &g_overlay.localWaitCond, nullptr, "ampr_eq_local");
            if (condRc == 0) {
                g_overlay.localWaitSyncReady.store(
                    true, std::memory_order_release);
            } else {
                (void)scePthreadMutexDestroy(&g_overlay.localWaitMutex);
            }
        }
    }
    g_controlInitRc.store(controlRc, std::memory_order_release);
}

static void ensure_control_initialized() {
    const int onceRc = scePthreadOnce(&g_controlOnce, initialize_control_once);
    if (onceRc != 0) {
        abort_control_sync("once", onceRc);
    }
    const int initRc = g_controlInitRc.load(std::memory_order_acquire);
    if (initRc != 0) {
        abort_control_sync("init", initRc);
    }
}

class ControlLock {
public:
    ControlLock() {
        ensure_control_initialized();
        const int rc = scePthreadMutexLock(&g_controlMutex);
        if (rc != 0) {
            abort_control_sync("lock", rc);
        }
    }
    ~ControlLock() {
        const int rc = scePthreadMutexUnlock(&g_controlMutex);
        if (rc != 0) {
            abort_control_sync("unlock", rc);
        }
    }
    ControlLock(const ControlLock&) = delete;
    ControlLock& operator=(const ControlLock&) = delete;
};

class AmmCommandBufferLock {
public:
    AmmCommandBufferLock() : lock_(&g_ammCommandBuffers.lock) {
        uint32_t spins = 0;
        while (lock_->exchange(1u, std::memory_order_acquire) != 0u) {
            ampr_spin_pause_or_yield(spins);
        }
    }
    ~AmmCommandBufferLock() { lock_->store(0u, std::memory_order_release); }
    AmmCommandBufferLock(const AmmCommandBufferLock&) = delete;
    AmmCommandBufferLock& operator=(const AmmCommandBufferLock&) = delete;
private:
    std::atomic<uint32_t>* lock_{};
};

static WaitEqueueFn original_wait_equeue() {
    return ampr_fixed_kernel_slot<WaitEqueueFn>(kAmprLibkernelHook_sceKernelWaitEqueue);
}

static CreateEqueueFn original_create_equeue() {
    return ampr_fixed_kernel_slot<CreateEqueueFn>(
        kAmprLibkernelHook_sceKernelCreateEqueue);
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

template <typename Fn>
static Fn original_event_hook(AmprLibkernelHookId id) {
    return ampr_fixed_kernel_slot<Fn>(id);
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
    for (uint32_t i = 0; i < kQueueCapacity; ++i) {
        g_overlay.wakeTriggerState[i].store(0, std::memory_order_relaxed);
        g_overlay.localWakeEpoch[i].store(0, std::memory_order_relaxed);
        g_overlay.queues[i] = {};
        g_overlay.queues[i].nextFree = i + 1u < kQueueCapacity ? i + 1u : kInvalidIndex;
    }
    for (uint32_t i = 0; i < kRegistrationCapacity; ++i) {
        g_overlay.registrations[i] = {};
        g_overlay.registrations[i].next =
            i + 1u < kRegistrationCapacity ? i + 1u : kInvalidIndex;
        g_overlay.registrationOwners[i] = 0;
        g_overlay.registrationFilters[i] = 0;
    }
    for (uint32_t i = 0; i < kPendingCapacity; ++i) {
        g_overlay.pending[i] = {};
        g_overlay.pending[i].next = i + 1u < kPendingCapacity ? i + 1u : kInvalidIndex;
        g_overlay.pending[i].registrationIndex = kInvalidIndex;
    }
    for (uint32_t& slot : g_overlay.queueHash) {
        slot = 0;
    }
    for (std::atomic<uintptr_t>& slot : g_overlay.ammQueueHash) {
        slot.store(0, std::memory_order_relaxed);
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
    g_overlay.liveQueues = 0;
    g_overlay.liveRegistrations = 0;
    g_overlay.livePending = 0;
    g_overlay.queueHashTombstones = 0;
    g_overlay.registrationHashTombstones = 0;
    g_overlay.ammQueueHashTombstones = 0;
    g_overlay.pendingPoolBackpressured = false;
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

static bool amm_queue_classified_fast(SceKernelEqueue eq) {
    if (!eq) {
        return false;
    }
    const uintptr_t key = reinterpret_cast<uintptr_t>(eq);
    uint32_t slot = hash_queue(eq);
    for (uint32_t probe = 0; probe < kQueueHashCapacity; ++probe) {
        const uintptr_t value = g_overlay.ammQueueHash[slot].load(
            std::memory_order_acquire);
        if (value == 0) {
            return false;
        }
        if (value == key) {
            return true;
        }
        slot = (slot + 1u) & (kQueueHashCapacity - 1u);
    }
    return false;
}

static bool insert_amm_queue_hash_raw_locked(SceKernelEqueue eq) {
    const uintptr_t key = reinterpret_cast<uintptr_t>(eq);
    uint32_t slot = hash_queue(eq);
    uint32_t tombstone = kInvalidIndex;
    for (uint32_t probe = 0; probe < kQueueHashCapacity; ++probe) {
        const uintptr_t value = g_overlay.ammQueueHash[slot].load(
            std::memory_order_relaxed);
        if (value == key) {
            return true;
        }
        if (value == 1 && tombstone == kInvalidIndex) {
            tombstone = slot;
        } else if (value == 0) {
            const uint32_t target =
                tombstone != kInvalidIndex ? tombstone : slot;
            g_overlay.ammQueueHash[target].store(
                key, std::memory_order_release);
            if (tombstone != kInvalidIndex &&
                g_overlay.ammQueueHashTombstones != 0) {
                --g_overlay.ammQueueHashTombstones;
            }
            return true;
        }
        slot = (slot + 1u) & (kQueueHashCapacity - 1u);
    }
    if (tombstone != kInvalidIndex) {
        g_overlay.ammQueueHash[tombstone].store(
            key, std::memory_order_release);
        if (g_overlay.ammQueueHashTombstones != 0) {
            --g_overlay.ammQueueHashTombstones;
        }
        return true;
    }
    return false;
}

static bool rebuild_amm_queue_hash_locked() {
    for (std::atomic<uintptr_t>& slot : g_overlay.ammQueueHash) {
        slot.store(0, std::memory_order_release);
    }
    g_overlay.ammQueueHashTombstones = 0;
    for (const TrackedEqueue& queue : g_overlay.queues) {
        if (queue.used && queue.ammSourceSeen &&
            !insert_amm_queue_hash_raw_locked(queue.eq)) {
            return false;
        }
    }
    return true;
}

static bool insert_amm_queue_hash_locked(SceKernelEqueue eq) {
    if (g_overlay.ammQueueHashTombstones >= kQueueCapacity / 2u &&
        !rebuild_amm_queue_hash_locked()) {
        return false;
    }
    return insert_amm_queue_hash_raw_locked(eq);
}

static void erase_amm_queue_hash_locked(SceKernelEqueue eq) {
    const uintptr_t key = reinterpret_cast<uintptr_t>(eq);
    uint32_t slot = hash_queue(eq);
    for (uint32_t probe = 0; probe < kQueueHashCapacity; ++probe) {
        const uintptr_t value = g_overlay.ammQueueHash[slot].load(
            std::memory_order_relaxed);
        if (value == 0) {
            return;
        }
        if (value == key) {
            g_overlay.ammQueueHash[slot].store(1, std::memory_order_release);
            ++g_overlay.ammQueueHashTombstones;
            return;
        }
        slot = (slot + 1u) & (kQueueHashCapacity - 1u);
    }
}

static uint32_t hash_amm_command_buffer(uintptr_t value) {
    value >>= 3u;
    value ^= value >> 17u;
    value *= static_cast<uintptr_t>(0x9e3779b97f4a7c15ull);
    return static_cast<uint32_t>(value) & (kAmmBufferHashCapacity - 1u);
}

static bool is_registered_amm_command_buffer(const void* commandBuffer) {
    if (!commandBuffer ||
        g_ammCommandBuffers.trackingLost.load(std::memory_order_acquire)) {
        return false;
    }
    const uintptr_t key = reinterpret_cast<uintptr_t>(commandBuffer);
    AmmCommandBufferLock lock;
    uint32_t slot = hash_amm_command_buffer(key);
    for (uint32_t probe = 0; probe < kAmmBufferHashCapacity; ++probe) {
        const uintptr_t value = g_ammCommandBuffers.slots[slot];
        if (value == 0) {
            return false;
        }
        if (value == key) {
            return true;
        }
        slot = (slot + 1u) & (kAmmBufferHashCapacity - 1u);
    }
    return false;
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

static constexpr bool ownership_allows_local_wait(bool amprSourceSeen,
                                                  bool mixedSourceSeen,
                                                  bool ammSourceSeen) {
    return amprSourceSeen && !mixedSourceSeen && !ammSourceSeen;
}
static_assert(ownership_allows_local_wait(true, false, false));
static_assert(!ownership_allows_local_wait(false, false, false));
static_assert(!ownership_allows_local_wait(true, true, false));
static_assert(!ownership_allows_local_wait(true, false, true));

static bool queue_would_be_exclusive_local_ignoring_amm_health_locked(
    const TrackedEqueue& queue) {
    return g_overlay.hooksAvailable.load(std::memory_order_relaxed) &&
           ownership_allows_local_wait(
               queue.amprSourceSeen,
               queue.mixedSourceSeen,
               queue.ammSourceSeen) &&
           queue.registrationHead < kRegistrationCapacity &&
           g_overlay.classificationHooksAvailable.load(
               std::memory_order_relaxed) &&
           g_overlay.localWaitSyncReady.load(std::memory_order_relaxed);
}

static bool queue_would_be_exclusive_local_locked(const TrackedEqueue& queue) {
    return !g_ammCommandBuffers.trackingLost.load(
               std::memory_order_relaxed) &&
           queue_would_be_exclusive_local_ignoring_amm_health_locked(queue);
}

static bool queue_is_exclusive_local_locked(const TrackedEqueue& queue) {
    return queue.controlDepth == 0 &&
           queue_would_be_exclusive_local_locked(queue);
}

static constexpr bool queue_has_meaningful_classification(
    bool amprSourceSeen,
    bool mixedSourceSeen,
    bool ammSourceSeen) {
    return amprSourceSeen || mixedSourceSeen || ammSourceSeen;
}
static_assert(!queue_has_meaningful_classification(
                  false, false, false),
              "a filterless queue must delete silently");
static_assert(queue_has_meaningful_classification(
                  true, false, false),
              "an AMPR queue must retain diagnostics");

[[noreturn]] static void abort_local_wait_sync(const char* operation, int rc) {
    AMPR_CRITICAL_LOGF("apr.equeue.local-wait.sync-fail operation=%s rc=0x%x action=abort",
                       operation ? operation : "unknown",
                       rc);
    AMPR_KLOGF("ampr.abort reason=apr.equeue.local-wait.sync-fail file=%s line=%d",
               __FILE__,
               __LINE__);
    std::abort();
}

static void notify_local_waiters() {
    if (!g_overlay.localWaitSyncReady.load(std::memory_order_acquire)) {
        return;
    }
    const int lockRc = scePthreadMutexLock(&g_overlay.localWaitMutex);
    if (lockRc != 0) {
        abort_local_wait_sync("notify-lock", lockRc);
    }
    const int broadcastRc = scePthreadCondBroadcast(&g_overlay.localWaitCond);
    if (broadcastRc != 0) {
        abort_local_wait_sync("notify-broadcast", broadcastRc);
    }
    const int unlockRc = scePthreadMutexUnlock(&g_overlay.localWaitMutex);
    if (unlockRc != 0) {
        abort_local_wait_sync("notify-unlock", unlockRc);
    }
}

struct QueuePromotion {
    bool changed{};
    bool wasExclusive{};
};

static void log_queue_classification_change(SceKernelEqueue eq,
                                            const char* from,
                                            const char* to,
                                            const char* reason) {
    AMPR_LOGF("apr.equeue.classification.change eq=%p from=%s to=%s reason=%s",
              eq,
              from ? from : "unknown",
              to ? to : "unknown",
              reason ? reason : "unknown");
}

static QueuePromotion mark_queue_mixed_locked(
    uint32_t queueIndex,
    TrackedEqueue& queue) {
    QueuePromotion result{};
    if (queue.mixedSourceSeen) {
        return result;
    }
    result.wasExclusive = queue_would_be_exclusive_local_locked(queue);
    queue.mixedSourceSeen = true;
    if (result.wasExclusive) {
        APR_EQ_COUNT(localExits);
    }
    g_overlay.localWakeEpoch[queueIndex].fetch_add(
        1u, std::memory_order_release);
    APR_EQ_COUNT(mixedPromotions);
    result.changed = true;
    return result;
}

struct QueueControlTransaction {
    uint32_t queueIndex{kInvalidIndex};
    uint64_t queueGeneration{};
    bool wasExclusive{};
    bool wakeLocalWaiter{};

    explicit operator bool() const {
        return queueIndex < kQueueCapacity;
    }
};

static QueueControlTransaction begin_queue_control(SceKernelEqueue eq) {
    QueueControlTransaction transaction{};
    OverlayLock lock;
    if (!g_overlay.hooksAvailable.load(std::memory_order_relaxed)) {
        return transaction;
    }
    transaction.queueIndex = find_queue_index_locked(eq);
    if (transaction.queueIndex >= kQueueCapacity) {
        return transaction;
    }

    TrackedEqueue& queue = g_overlay.queues[transaction.queueIndex];
    transaction.queueGeneration = queue.lifetimeGeneration;
    transaction.wasExclusive = queue_is_exclusive_local_locked(queue);
    ++queue.controlDepth;
    if (transaction.wasExclusive) {
        g_overlay.localWakeEpoch[transaction.queueIndex].fetch_add(
            1u, std::memory_order_release);
        transaction.wakeLocalWaiter = true;
    }
    return transaction;
}

static TrackedEqueue* find_queue_control_locked(
    const QueueControlTransaction& transaction) {
    if (!transaction || !g_overlay.queues[transaction.queueIndex].used ||
        g_overlay.queues[transaction.queueIndex].lifetimeGeneration !=
            transaction.queueGeneration) {
        return nullptr;
    }
    return &g_overlay.queues[transaction.queueIndex];
}

static void finish_queue_control_locked(TrackedEqueue& queue) {
    if (queue.controlDepth != 0) {
        --queue.controlDepth;
    }
}

static void disable_exclusive_local_waits_for_amm_tracking_loss() {
    bool notify = false;
    uint32_t promoted = 0;
    {
        OverlayLock lock;
        if (g_overlay.initialized) {
            for (uint32_t i = 0; i < kQueueCapacity; ++i) {
                TrackedEqueue& queue = g_overlay.queues[i];
                if (!queue.used) {
                    continue;
                }
                const bool wasExclusiveBeforeTrackingLoss =
                    queue_would_be_exclusive_local_ignoring_amm_health_locked(
                        queue);
                if (mark_queue_mixed_locked(i, queue).changed) {
                    if (wasExclusiveBeforeTrackingLoss) {
                        // trackingLost was published before this conservative
                        // promotion, so mark_queue_mixed_locked cannot observe
                        // the immediately preceding local-only state itself.
                        APR_EQ_COUNT(localExits);
                    }
                    notify = true;
                    ++promoted;
                }
            }
        }
    }
    if (notify) {
        notify_local_waiters();
        AMPR_LOGF("apr.equeue.classification.change eq=* from=apr-candidate to=mixed reason=amm-buffer-tracking-lost queues=%u",
                  promoted);
    }
}

template <typename Call>
static int forward_non_ampr_add(SceKernelEqueue eq,
                                const char* reason,
                                Call&& call) {
    if (!g_overlay.hooksAvailable.load(std::memory_order_acquire)) {
        return call();
    }
    QueuePromotion promotion{};
    {
        OverlayLock lock;
        const uint32_t queueIndex = find_queue_index_locked(eq);
        if (queueIndex < kQueueCapacity) {
            promotion = mark_queue_mixed_locked(
                queueIndex, g_overlay.queues[queueIndex]);
        }
    }
    if (promotion.changed) {
        notify_local_waiters();
        log_queue_classification_change(
            eq,
            promotion.wasExclusive ? "apr-local" : "apr-candidate",
            "mixed",
            reason);
    }
    return call();
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

static uint32_t hash_registration(uint32_t queueIndex,
                                  int16_t filter,
                                  int32_t id) {
    uint32_t value = static_cast<uint32_t>(id);
    value ^= queueIndex * 0x9e3779b9u;
    value ^= static_cast<uint32_t>(static_cast<uint16_t>(filter)) * 0x27d4eb2du;
    value ^= value >> 16u;
    value *= 0x85ebca6bu;
    value ^= value >> 13u;
    return value & (kRegistrationHashCapacity - 1u);
}

static bool registration_hash_entry_matches_locked(uint16_t value,
                                                   uint32_t queueIndex,
                                                   int16_t filter,
                                                   int32_t id) {
    if (value == 0 || value == kRegistrationHashTombstone) {
        return false;
    }
    const uint32_t registrationIndex = static_cast<uint32_t>(value - 1u);
    return registrationIndex < kRegistrationCapacity &&
           g_overlay.registrationOwners[registrationIndex] == queueIndex + 1u &&
           g_overlay.registrationFilters[registrationIndex] == filter &&
           g_overlay.registrations[registrationIndex].id == id;
}

static bool insert_registration_hash_raw_locked(uint32_t queueIndex,
                                                int16_t filter,
                                                int32_t id,
                                                uint32_t registrationIndex) {
    uint32_t slot = hash_registration(queueIndex, filter, id);
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
                g_overlay.registrationFilters[registrationIndex],
                g_overlay.registrations[registrationIndex].id,
                registrationIndex)) {
            return false;
        }
    }
    APR_EQ_COUNT(registrationHashRebuilds);
    return true;
}

static bool insert_registration_hash_locked(uint32_t queueIndex,
                                            int16_t filter,
                                            int32_t id,
                                            uint32_t registrationIndex) {
    if (g_overlay.registrationHashTombstones >= kRegistrationCapacity / 2u &&
        !rebuild_registration_hash_locked()) {
        return false;
    }
    return insert_registration_hash_raw_locked(
        queueIndex, filter, id, registrationIndex);
}

static void erase_registration_hash_locked(uint32_t queueIndex,
                                           int16_t filter,
                                           int32_t id) {
    uint32_t slot = hash_registration(queueIndex, filter, id);
    for (uint32_t probe = 0; probe < kRegistrationHashCapacity; ++probe) {
        const uint16_t value = g_overlay.registrationHash[slot];
        if (value == 0) {
            return;
        }
        if (registration_hash_entry_matches_locked(
                value, queueIndex, filter, id)) {
            g_overlay.registrationHash[slot] = kRegistrationHashTombstone;
            ++g_overlay.registrationHashTombstones;
            return;
        }
        slot = (slot + 1u) & (kRegistrationHashCapacity - 1u);
    }
}

static uint32_t find_registration_locked(uint32_t queueIndex,
                                         TrackedEqueue& queue,
                                         int16_t filter,
                                         int32_t id) {
    if (queue.registrationCache < kRegistrationCapacity &&
        g_overlay.registrationOwners[queue.registrationCache] == queueIndex + 1u &&
        g_overlay.registrationFilters[queue.registrationCache] == filter &&
        g_overlay.registrations[queue.registrationCache].id == id) {
        APR_EQ_COUNT(registrationCacheHits);
        return queue.registrationCache;
    }
    APR_EQ_COUNT(registrationCacheMisses);
    uint32_t slot = hash_registration(queueIndex, filter, id);
    for (uint32_t probe = 0; probe < kRegistrationHashCapacity; ++probe) {
        const uint16_t value = g_overlay.registrationHash[slot];
        if (value == 0) {
            return kInvalidIndex;
        }
        if (registration_hash_entry_matches_locked(
                value, queueIndex, filter, id)) {
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
                                             int16_t filter,
                                             int32_t id,
                                             void* udata) {
    uint32_t index = find_registration_locked(queueIndex, queue, filter, id);
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
    g_overlay.registrationFilters[index] = filter;
    if (!insert_registration_hash_locked(queueIndex, filter, id, index)) {
        registration = {};
        g_overlay.registrationFilters[index] = 0;
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
                                       int16_t filter,
                                       int32_t id) {
    uint32_t previous = kInvalidIndex;
    uint32_t index = queue.registrationHead;
    while (index < kRegistrationCapacity) {
        MirroredRegistration& registration = g_overlay.registrations[index];
        const uint32_t next = registration.next;
        if (registration.id == id &&
            g_overlay.registrationFilters[index] == filter) {
            erase_registration_hash_locked(queueIndex, filter, id);
            if (previous < kRegistrationCapacity) {
                g_overlay.registrations[previous].next = next;
            } else {
                queue.registrationHead = next;
            }
            if (queue.registrationCache == index) {
                queue.registrationCache = kInvalidIndex;
            }
            g_overlay.registrationOwners[index] = 0;
            g_overlay.registrationFilters[index] = 0;
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
    g_overlay.pending[index].registrationIndex = kInvalidIndex;
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
    g_overlay.pending[index].registrationIndex = kInvalidIndex;
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

static bool pending_registration_is_current_locked(
    uint32_t queueIndex,
    const PendingEvent& pending) {
    const uint32_t registrationIndex = pending.registrationIndex;
    return registrationIndex < kRegistrationCapacity &&
           g_overlay.registrationOwners[registrationIndex] == queueIndex + 1u &&
           g_overlay.registrations[registrationIndex].generation ==
               pending.registrationGeneration;
}

static int drain_pending_locked(uint32_t queueIndex,
                                TrackedEqueue& queue,
                                SceKernelEvent* events,
                                int capacity,
                                bool* outNotifyReactor) {
    int count = 0;
    bool releasedPending = false;
    while (queue.pendingHead < kPendingCapacity) {
        const uint32_t index = queue.pendingHead;
        PendingEvent& pending = g_overlay.pending[index];
        const bool registrationCurrent =
            pending_registration_is_current_locked(queueIndex, pending);
        if (registrationCurrent && count >= capacity) {
            break;
        }
        queue.pendingHead = pending.next;
        if (queue.pendingHead >= kPendingCapacity) {
            queue.pendingTail = kInvalidIndex;
        }
        if (queue.pendingCount != 0) {
            --queue.pendingCount;
        }
        if (registrationCurrent) {
            events[count++] = pending.event;
        } else {
            APR_EQ_COUNT(staleRegistrationDrops);
        }
        release_pending_locked(index);
        releasedPending = true;
    }
    if (releasedPending && outNotifyReactor &&
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
                    result.pendingPublished = true;
                } else if (result.rc != 0) {
                    // Documented trigger failures are permanent for this
                    // (equeue, id) pair. Keep existing FIFO nodes drainable,
                    // but route later publications through native fallback.
                    queue.wakeReady = false;
                }
                queue.wakeTriggering = false;
                result.pendingCount = queue.pendingCount;
                result.nativeWaitIntent = queue.nativeWaitIntent;
                result.replacementStillRequired =
                    result.rc != 0 &&
                    request.pendingIndex >= kPendingCapacity &&
                    queue.pendingCount != 0 &&
                    queue.nativeWaitIntent != 0;
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

static void execute_replacement_wake_or_abort(
    const PrivateWakeRequest& request) {
    const PrivateWakeCompletion completion = execute_private_wake(request);
    if (completion.rc == 0 || !completion.replacementStillRequired) {
        return;
    }

    // A publication wake can fall back before its reserved node becomes
    // visible. Replacement wakes cover nodes already in the synthetic FIFO,
    // so returning after a permanent EBADF/ENOENT trigger failure would strand
    // those nodes behind an infinite native waiter with no armed edge.
    AMPR_CRITICAL_LOGF("apr.equeue.replacement-wake.fail eq=%p wakeId=%u queue=%u generation=%llu pending=%u nativeWaitIntent=%u rc=0x%x action=abort",
                       request.eq,
                       request.wakeId,
                       request.queueIndex,
                       (unsigned long long)request.queueGeneration,
                       completion.pendingCount,
                       completion.nativeWaitIntent,
                       completion.rc);
    AMPR_KLOGF("ampr.abort reason=apr.equeue.replacement-wake.fail file=%s line=%d",
               __FILE__,
               __LINE__);
    std::abort();
}

static bool attach_hidden_wake_unlocked(uint32_t queueIndex,
                                        uint64_t queueGeneration) {
    AddUserEventFn const addUserEventEdge =
        original_event_hook<AddUserEventFn>(
            kAmprLibkernelHook_sceKernelAddUserEventEdge);
    if (!addUserEventEdge) {
        return false;
    }
    for (uint32_t attempt = 0; attempt < kWakeAttachAttempts; ++attempt) {
        SceKernelEqueue eq = nullptr;
        uint32_t candidate = 0;
        {
            OverlayLock lock;
            if (queueIndex >= kQueueCapacity ||
                !g_overlay.queues[queueIndex].used ||
                g_overlay.queues[queueIndex].lifetimeGeneration !=
                    queueGeneration) {
                return false;
            }
            TrackedEqueue& queue = g_overlay.queues[queueIndex];
            if (queue.wakeRegistered) {
                return true;
            }
            eq = queue.eq;
            candidate = g_overlay.nextWakeId++;
            if (candidate < kWakeIdBase || candidate == 0 ||
                candidate > INT_MAX) {
                g_overlay.nextWakeId = kWakeIdBase + 1u;
                candidate = kWakeIdBase;
            }
        }

        const int rc = addUserEventEdge(eq, static_cast<int>(candidate));
        if (rc == 0) {
            bool committed = false;
            bool duplicate = false;
            {
                OverlayLock lock;
                if (queueIndex < kQueueCapacity &&
                    g_overlay.queues[queueIndex].used &&
                    g_overlay.queues[queueIndex].lifetimeGeneration ==
                        queueGeneration) {
                    TrackedEqueue& queue = g_overlay.queues[queueIndex];
                    if (!queue.wakeRegistered) {
                        queue.wakeId = candidate;
                        queue.wakeRegistered = true;
                        queue.wakeReady = true;
                        committed = true;
                    } else {
                        duplicate = true;
                    }
                }
            }
            if (duplicate) {
                (void)sceKernelDeleteUserEvent(
                    eq, static_cast<int>(candidate));
                return true;
            }
            return committed;
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
            queueIndex,
            g_overlay.registrationFilters[index],
            g_overlay.registrations[index].id);
        g_overlay.registrationOwners[index] = 0;
        g_overlay.registrationFilters[index] = 0;
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
    g_overlay.localWakeEpoch[queueIndex].fetch_add(
        1u, std::memory_order_release);
    if (queue.ammSourceSeen) {
        erase_amm_queue_hash_locked(queue.eq);
    }
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
        for (std::atomic<uintptr_t>& slot : g_overlay.ammQueueHash) {
            slot.store(0, std::memory_order_release);
        }
        g_overlay.ammQueueHashTombstones = 0;
    } else if (g_overlay.queueHashTombstones >= kQueueCapacity / 2u) {
        (void)rebuild_queue_hash_locked();
    }
    if (g_overlay.liveQueues != 0 &&
        g_overlay.ammQueueHashTombstones >= kQueueCapacity / 2u) {
        (void)rebuild_amm_queue_hash_locked();
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
    int num) {
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
                    drain_pending_locked(
                        queueIndex, queue, events, num, &result.notifyReactor);
                if (result.syntheticCount == 0) {
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

static void wait_for_local_change(uint32_t queueIndex,
                                  uint64_t observedEpoch,
                                  const SceKernelUseconds* timeout) {
    if (queueIndex >= kQueueCapacity ||
        !g_overlay.localWaitSyncReady.load(std::memory_order_acquire)) {
        return;
    }
    const int lockRc = scePthreadMutexLock(&g_overlay.localWaitMutex);
    if (lockRc != 0) {
        abort_local_wait_sync("wait-lock", lockRc);
    }
    if (g_overlay.localWakeEpoch[queueIndex].load(
            std::memory_order_acquire) == observedEpoch) {
        APR_EQ_COUNT(localWaits);
        int waitRc = 0;
        if (timeout) {
            waitRc = scePthreadCondTimedwait(
                &g_overlay.localWaitCond,
                &g_overlay.localWaitMutex,
                *timeout);
        } else {
            waitRc = scePthreadCondWait(
                &g_overlay.localWaitCond,
                &g_overlay.localWaitMutex);
        }
        if (waitRc != 0 && waitRc != SCE_KERNEL_ERROR_ETIMEDOUT &&
            waitRc != ETIMEDOUT) {
            abort_local_wait_sync("wait-cond", waitRc);
        }
        APR_EQ_COUNT(localWakeups);
    }
    const int unlockRc = scePthreadMutexUnlock(&g_overlay.localWaitMutex);
    if (unlockRc != 0) {
        abort_local_wait_sync("wait-unlock", unlockRc);
    }
}

template <typename Call>
static int forward_ampr_registration_add(SceKernelEqueue eq,
                                         int16_t filter,
                                         int id,
                                         void* udata,
                                         Call&& call) {
    if (!g_overlay.hooksAvailable.load(std::memory_order_acquire)) {
        return call();
    }

    ControlLock control;
    const QueueControlTransaction transaction = begin_queue_control(eq);
    if (transaction.wakeLocalWaiter) {
        notify_local_waiters();
    }

    bool classificationChanged = false;
    QueuePromotion forcedMixed{};
    const int rc = call();
    if (!transaction) {
        return rc;
    }

    bool wakeAvailable = rc == 0;
    if (rc == 0) {
        bool needsWake = false;
        {
            OverlayLock lock;
            if (TrackedEqueue* queue =
                    find_queue_control_locked(transaction)) {
                needsWake = !queue->wakeRegistered;
            }
        }
        if (needsWake) {
            wakeAvailable = attach_hidden_wake_unlocked(
                transaction.queueIndex, transaction.queueGeneration);
        }
    }

    uint64_t committedGeneration = 0;
    {
        OverlayLock lock;
        TrackedEqueue* const queuePtr =
            find_queue_control_locked(transaction);
        if (!queuePtr) {
            return rc;
        }
        TrackedEqueue& queue = *queuePtr;
        if (rc == 0) {
            if (!wakeAvailable || !queue.wakeRegistered) {
                forcedMixed = mark_queue_mixed_locked(
                    transaction.queueIndex, queue);
            } else if (allocate_registration_locked(
                           transaction.queueIndex,
                           queue,
                           filter,
                           id,
                           udata) >=
                       kRegistrationCapacity) {
                forcedMixed = mark_queue_mixed_locked(
                    transaction.queueIndex, queue);
            } else {
                queue.amprSourceSeen = true;
                APR_EQ_COUNT(addRegistrations);
                committedGeneration = transaction.queueGeneration;
            }
        }
        finish_queue_control_locked(queue);
        const bool isExclusive = queue_is_exclusive_local_locked(queue);
        classificationChanged = !transaction.wasExclusive && isExclusive;
        if (classificationChanged) {
            APR_EQ_COUNT(localEntries);
        }
    }
    if (forcedMixed.changed) {
        notify_local_waiters();
        log_queue_classification_change(
            eq,
            forcedMixed.wasExclusive ? "apr-local" : "apr-candidate",
            "mixed",
            "ampr-registration-overlay-unavailable");
    }
    if (classificationChanged) {
        AMPR_TLOGF("apr.equeue.classification.change eq=%p from=apr-candidate to=apr-local reason=%s",
                   eq,
                   filter == kAmprSystemEventFilter
                       ? "ampr-system-registration-add"
                       : "ampr-registration-add");
    }
    if (committedGeneration != 0) {
        AMPR_TLOGF("apr.equeue.registration.add eq=%p filter=%d id=%d udata=%p queueGeneration=%llu",
                   eq,
                   static_cast<int>(filter),
                   id,
                   udata,
                   (unsigned long long)committedGeneration);
    }
    return rc;
}

template <typename Call>
static int forward_ampr_registration_delete(SceKernelEqueue eq,
                                            int16_t filter,
                                            int id,
                                            Call&& call) {
    if (!g_overlay.hooksAvailable.load(std::memory_order_acquire)) {
        return call();
    }

    ControlLock control;
    const QueueControlTransaction transaction = begin_queue_control(eq);
    if (transaction.wakeLocalWaiter) {
        notify_local_waiters();
    }

    bool classificationChanged = false;
    const int rc = call();
    if (!transaction) {
        return rc;
    }

    {
        OverlayLock lock;
        if (TrackedEqueue* queue =
                find_queue_control_locked(transaction)) {
            if (rc == 0) {
                remove_registration_locked(
                    transaction.queueIndex, *queue, filter, id);
                queue->amprSourceSeen =
                    queue->registrationHead < kRegistrationCapacity;
                APR_EQ_COUNT(deleteRegistrations);
            }
            finish_queue_control_locked(*queue);
            classificationChanged =
                rc == 0 && transaction.wasExclusive &&
                !queue->amprSourceSeen && !queue->mixedSourceSeen &&
                !queue->ammSourceSeen;
            if (classificationChanged) {
                APR_EQ_COUNT(localExits);
            }
        }
    }
    if (classificationChanged) {
        AMPR_TLOGF("apr.equeue.classification.change eq=%p from=apr-local to=apr-candidate reason=%s",
                   eq,
                   filter == kAmprSystemEventFilter
                       ? "ampr-system-registration-delete"
                       : "ampr-registration-delete");
    }
    return rc;
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
    bool notifyLocal = false;
    for (;;) {
        PrivateWakeRequest wakeRequest{};
        QueuePromotion controlPromotion{};
        uint32_t waitQueueIndex = kInvalidIndex;
        bool waitForWakeCompletion = false;
        bool executeWake = false;
        bool controlFallback = false;
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
            if (queue.controlDepth != 0) {
                controlPromotion = mark_queue_mixed_locked(queueIndex, queue);
                controlFallback = true;
                APR_EQ_COUNT(fallbackRegistration);
            } else if (private_wake_in_flight_locked(queue)) {
                waitQueueIndex = queueIndex;
                waitForWakeCompletion = true;
            } else {
                const uint32_t registrationIndex =
                    find_registration_locked(
                        queueIndex, queue, SCE_KERNEL_EVFILT_AMPR, id);
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
                pending.registrationIndex = registrationIndex;
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
                    if (queue_is_exclusive_local_locked(queue)) {
                        g_overlay.localWakeEpoch[queueIndex].fetch_add(
                            1u, std::memory_order_release);
                        notifyLocal = true;
                    }
                    pendingCount = queue.pendingCount;
                    APR_EQ_COUNT(published);
                }
            }
        }

        if (controlFallback) {
            if (controlPromotion.changed) {
                notify_local_waiters();
                log_queue_classification_change(
                    eq,
                    controlPromotion.wasExclusive
                        ? "apr-local"
                        : "apr-candidate",
                    "mixed",
                    "ampr-control-in-flight");
            }
            return AprEqueuePublishResult::NativeFallback;
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
    if (notifyLocal) {
        notify_local_waiters();
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

void apr_equeue_overlay_set_hook_availability(bool hooksAvailable,
                                               bool classificationAvailable) {
    bool wakeLocal = false;
    bool availabilityChanged = false;
    {
        OverlayLock lock;
        const bool wasComplete =
            g_overlay.hooksAvailable.load(std::memory_order_relaxed) &&
            g_overlay.classificationHooksAvailable.load(
                std::memory_order_relaxed);
        availabilityChanged =
            wasComplete != (hooksAvailable && classificationAvailable);
        if (wasComplete && (!hooksAvailable || !classificationAvailable) &&
            g_overlay.initialized) {
            for (uint32_t i = 0; i < kQueueCapacity; ++i) {
                if (g_overlay.queues[i].used) {
                    if (queue_would_be_exclusive_local_locked(
                            g_overlay.queues[i])) {
                        APR_EQ_COUNT(localExits);
                    }
                    g_overlay.localWakeEpoch[i].fetch_add(
                        1u, std::memory_order_release);
                    wakeLocal = true;
                }
            }
        }
        g_overlay.classificationHooksAvailable.store(
            classificationAvailable, std::memory_order_relaxed);
        g_overlay.hooksAvailable.store(
            hooksAvailable, std::memory_order_release);
    }
    if (wakeLocal) {
        notify_local_waiters();
    }
    if (availabilityChanged) {
        AMPR_LOGF("apr.equeue.classifier.availability core=%u complete=%u",
                  hooksAvailable ? 1u : 0u,
                  classificationAvailable ? 1u : 0u);
    }
}

void apr_equeue_register_amm_command_buffer(const void* commandBuffer) {
    if (!commandBuffer ||
        g_ammCommandBuffers.trackingLost.load(std::memory_order_acquire)) {
        return;
    }

    const uintptr_t key = reinterpret_cast<uintptr_t>(commandBuffer);
    bool inserted = false;
    bool trackingLost = false;
    {
        AmmCommandBufferLock lock;
        uint32_t slot = hash_amm_command_buffer(key);
        uint32_t tombstone = kInvalidIndex;
        for (uint32_t probe = 0; probe < kAmmBufferHashCapacity; ++probe) {
            const uintptr_t value = g_ammCommandBuffers.slots[slot];
            if (value == key) {
                return;
            }
            if (value == 1 && tombstone == kInvalidIndex) {
                tombstone = slot;
            } else if (value == 0) {
                g_ammCommandBuffers.slots[
                    tombstone != kInvalidIndex ? tombstone : slot] = key;
                inserted = true;
                break;
            }
            slot = (slot + 1u) & (kAmmBufferHashCapacity - 1u);
        }
        if (!inserted && tombstone != kInvalidIndex) {
            g_ammCommandBuffers.slots[tombstone] = key;
            inserted = true;
        }
        if (!inserted) {
            trackingLost = !g_ammCommandBuffers.trackingLost.exchange(
                true, std::memory_order_acq_rel);
        }
    }
    if (inserted) {
        APR_EQ_COUNT(ammBufferRegistrations);
    } else if (trackingLost) {
        APR_EQ_COUNT(ammTrackingFailures);
        disable_exclusive_local_waits_for_amm_tracking_loss();
    }
}

void apr_equeue_unregister_amm_command_buffer(const void* commandBuffer) {
    if (!commandBuffer ||
        g_ammCommandBuffers.trackingLost.load(std::memory_order_acquire)) {
        return;
    }
    const uintptr_t key = reinterpret_cast<uintptr_t>(commandBuffer);
    AmmCommandBufferLock lock;
    uint32_t slot = hash_amm_command_buffer(key);
    for (uint32_t probe = 0; probe < kAmmBufferHashCapacity; ++probe) {
        const uintptr_t value = g_ammCommandBuffers.slots[slot];
        if (value == 0) {
            return;
        }
        if (value == key) {
            g_ammCommandBuffers.slots[slot] = 1;
            return;
        }
        slot = (slot + 1u) & (kAmmBufferHashCapacity - 1u);
    }
}

void apr_equeue_note_command_buffer_event(const void* commandBuffer,
                                          SceKernelEqueue eq) {
    if (!eq || amm_queue_classified_fast(eq)) {
        return;
    }
    if (!is_registered_amm_command_buffer(commandBuffer)) {
        return;
    }
    APR_EQ_COUNT(ammEventQueues);
    QueuePromotion promotion{};
    {
        OverlayLock lock;
        const uint32_t queueIndex = find_queue_index_locked(eq);
        if (queueIndex >= kQueueCapacity) {
            return;
        }
        TrackedEqueue& queue = g_overlay.queues[queueIndex];
        queue.ammSourceSeen = true;
        promotion = mark_queue_mixed_locked(queueIndex, queue);
        // Publish the lock-free fast-path key only after mixed classification
        // is committed. A concurrent recorder that observes the key may then
        // return without taking either registry or overlay lock.
        (void)insert_amm_queue_hash_locked(eq);
    }
    if (promotion.changed) {
        notify_local_waiters();
        log_queue_classification_change(
            eq,
            promotion.wasExclusive ? "apr-local" : "apr-candidate",
            "mixed",
            "amm-write-equeue-record");
    }
}

void apr_equeue_overlay_shutdown() {
    apr_equeue_overlay_set_hook_availability(false, false);
    ControlLock control;
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
    notify_local_waiters();
}

extern "C" int sceKernelCreateEqueue_emul(SceKernelEqueue* eq,
                                             const char* name) {
    CreateEqueueFn const original = original_create_equeue();
    if (!original) {
        return SCE_KERNEL_ERROR_ENOSYS;
    }
    if (!g_overlay.hooksAvailable.load(std::memory_order_acquire)) {
        return original(eq, name);
    }

    ControlLock control;
    const int rc = original(eq, name);
    if (rc == 0 && eq && *eq) {
        OverlayLock lock;
        if (g_overlay.hooksAvailable.load(std::memory_order_relaxed) &&
            g_overlay.classificationHooksAvailable.load(
                std::memory_order_relaxed) &&
            find_queue_index_locked(*eq) >= kQueueCapacity) {
            (void)allocate_queue_locked(*eq);
        }
    }
    return rc;
}

extern "C" int sceKernelAddTimerEvent_emul(SceKernelEqueue eq, int id,
                                             SceKernelUseconds usec,
                                             void* udata) {
    AddTimerEventFn const original = original_event_hook<AddTimerEventFn>(
        kAmprLibkernelHook_sceKernelAddTimerEvent);
    return original
               ? forward_non_ampr_add(
                     eq,
                     "timer-registration",
                     [&]() { return original(eq, id, usec, udata); })
               : SCE_KERNEL_ERROR_ENOSYS;
}

extern "C" int sceKernelAddReadEvent_emul(SceKernelEqueue eq, int fd,
                                            size_t size, void* udata) {
    AddFdEventFn const original = original_event_hook<AddFdEventFn>(
        kAmprLibkernelHook_sceKernelAddReadEvent);
    return original
               ? forward_non_ampr_add(
                     eq,
                     "read-registration",
                     [&]() { return original(eq, fd, size, udata); })
               : SCE_KERNEL_ERROR_ENOSYS;
}

extern "C" int sceKernelAddWriteEvent_emul(SceKernelEqueue eq, int fd,
                                             size_t size, void* udata) {
    AddFdEventFn const original = original_event_hook<AddFdEventFn>(
        kAmprLibkernelHook_sceKernelAddWriteEvent);
    return original
               ? forward_non_ampr_add(
                     eq,
                     "write-registration",
                     [&]() { return original(eq, fd, size, udata); })
               : SCE_KERNEL_ERROR_ENOSYS;
}

extern "C" int sceKernelAddFileEvent_emul(SceKernelEqueue eq, int fd,
                                            int watch, void* udata) {
    AddFileEventFn const original = original_event_hook<AddFileEventFn>(
        kAmprLibkernelHook_sceKernelAddFileEvent);
    return original
               ? forward_non_ampr_add(
                     eq,
                     "file-registration",
                     [&]() { return original(eq, fd, watch, udata); })
               : SCE_KERNEL_ERROR_ENOSYS;
}

extern "C" int sceKernelAddUserEvent_emul(SceKernelEqueue eq, int id) {
    AddUserEventFn const original = original_event_hook<AddUserEventFn>(
        kAmprLibkernelHook_sceKernelAddUserEvent);
    return original
               ? forward_non_ampr_add(
                     eq,
                     "user-registration",
                     [&]() { return original(eq, id); })
               : SCE_KERNEL_ERROR_ENOSYS;
}

extern "C" int sceKernelAddUserEventEdge_emul(SceKernelEqueue eq, int id) {
    AddUserEventFn const original = original_event_hook<AddUserEventFn>(
        kAmprLibkernelHook_sceKernelAddUserEventEdge);
    return original
               ? forward_non_ampr_add(
                     eq,
                     "user-edge-registration",
                     [&]() { return original(eq, id); })
               : SCE_KERNEL_ERROR_ENOSYS;
}

extern "C" int sceKernelAddHRTimerEvent_emul(SceKernelEqueue eq, int id,
                                               SceKernelTimespec* ts,
                                               void* udata) {
    AddHRTimerEventFn const original =
        original_event_hook<AddHRTimerEventFn>(
            kAmprLibkernelHook_sceKernelAddHRTimerEvent);
    return original
               ? forward_non_ampr_add(
                     eq,
                     "hrtimer-registration",
                     [&]() { return original(eq, id, ts, udata); })
               : SCE_KERNEL_ERROR_ENOSYS;
}

template <typename Value>
static int forward_external_event_add(AmprExternalEqueueHookId hookId,
                                      SceKernelEqueue eq,
                                      Value value,
                                      void* udata,
                                      const char* reason) {
    auto* const original =
        ampr_fixed_external_equeue_slot<ExternalAddEventFn<Value>>(hookId);
    return original
               ? forward_non_ampr_add(
                     eq,
                     reason,
                     [&]() { return original(eq, value, udata); })
               : SCE_KERNEL_ERROR_ENOSYS;
}

extern "C" int sceAgcDriverAddEqEvent_emul(SceKernelEqueue eq,
                                             uint32_t type,
                                             void* udata) {
    return forward_external_event_add(
        kAmprExternalEqueueHook_sceAgcDriverAddEqEvent,
        eq,
        type,
        udata,
        "agc-registration");
}

extern "C" int sceVideoOutAddFlipEvent_emul(SceKernelEqueue eq,
                                              int32_t handle,
                                              void* udata) {
    return forward_external_event_add(
        kAmprExternalEqueueHook_sceVideoOutAddFlipEvent,
        eq,
        handle,
        udata,
        "videoout-flip-registration");
}

extern "C" int sceVideoOutAddVblankEvent_emul(SceKernelEqueue eq,
                                                int32_t handle,
                                                void* udata) {
    return forward_external_event_add(
        kAmprExternalEqueueHook_sceVideoOutAddVblankEvent,
        eq,
        handle,
        udata,
        "videoout-vblank-registration");
}

extern "C" int sceVideoOutAddPreVblankStartEvent_emul(
    SceKernelEqueue eq,
    int32_t handle,
    void* udata) {
    return forward_external_event_add(
        kAmprExternalEqueueHook_sceVideoOutAddPreVblankStartEvent,
        eq,
        handle,
        udata,
        "videoout-pre-vblank-start-registration");
}

extern "C" int sceVideoOutAddOutputModeEvent_emul(SceKernelEqueue eq,
                                                    int32_t handle,
                                                    void* udata) {
    return forward_external_event_add(
        kAmprExternalEqueueHook_sceVideoOutAddOutputModeEvent,
        eq,
        handle,
        udata,
        "videoout-output-mode-registration");
}

extern "C" int sceKernelAddAmprEvent_emul(SceKernelEqueue eq,
                                           int id,
                                           void* udata) {
    AddAmprEventFn const original = original_add_ampr_event();
    return original
               ? forward_ampr_registration_add(
                     eq,
                     SCE_KERNEL_EVFILT_AMPR,
                     id,
                     udata,
                     [&]() { return original(eq, id, udata); })
               : SCE_KERNEL_ERROR_ENOSYS;
}

extern "C" int sceKernelDeleteAmprEvent_emul(SceKernelEqueue eq, int id) {
    DeleteAmprEventFn const original = original_delete_ampr_event();
    return original
               ? forward_ampr_registration_delete(
                     eq,
                     SCE_KERNEL_EVFILT_AMPR,
                     id,
                     [&]() { return original(eq, id); })
               : SCE_KERNEL_ERROR_ENOSYS;
}

extern "C" int sceKernelAddAmprSystemEvent_emul(SceKernelEqueue eq,
                                                 int id,
                                                 int watch,
                                                 void* udata) {
    AddAmprSystemEventFn const original =
        original_event_hook<AddAmprSystemEventFn>(
            kAmprLibkernelHook_sceKernelAddAmprSystemEvent);
    return original
               ? forward_ampr_registration_add(
                     eq,
                     kAmprSystemEventFilter,
                     id,
                     udata,
                     [&]() { return original(eq, id, watch, udata); })
               : SCE_KERNEL_ERROR_ENOSYS;
}

extern "C" int sceKernelDeleteAmprSystemEvent_emul(SceKernelEqueue eq,
                                                    int id) {
    DeleteAmprEventFn const original =
        original_event_hook<DeleteAmprEventFn>(
            kAmprLibkernelHook_sceKernelDeleteAmprSystemEvent);
    return original
               ? forward_ampr_registration_delete(
                     eq,
                     kAmprSystemEventFilter,
                     id,
                     [&]() { return original(eq, id); })
               : SCE_KERNEL_ERROR_ENOSYS;
}

extern "C" int sceKernelDeleteEqueue_emul(SceKernelEqueue eq) {
    DeleteEqueueFn const original = original_delete_equeue();
    if (!original) {
        return SCE_KERNEL_ERROR_ENOSYS;
    }
    if (!g_overlay.hooksAvailable.load(std::memory_order_acquire)) {
        return original(eq);
    }

    for (;;) {
        uint32_t waitQueueIndex = kInvalidIndex;
        {
            ControlLock control;
            QueueControlTransaction transaction{};
            bool forwardDirect = false;
            {
                OverlayLock lock;
                if (!g_overlay.hooksAvailable.load(
                        std::memory_order_relaxed)) {
                    forwardDirect = true;
                } else {
                    const uint32_t queueIndex =
                        find_queue_index_locked(eq);
                    if (queueIndex >= kQueueCapacity) {
                        forwardDirect = true;
                    } else if (private_wake_in_flight_locked(
                                   g_overlay.queues[queueIndex])) {
                        waitQueueIndex = queueIndex;
                    } else {
                        TrackedEqueue& queue =
                            g_overlay.queues[queueIndex];
                        transaction.queueIndex = queueIndex;
                        transaction.queueGeneration =
                            queue.lifetimeGeneration;
                        transaction.wasExclusive =
                            queue_is_exclusive_local_locked(queue);
                        ++queue.controlDepth;
                        if (transaction.wasExclusive) {
                            g_overlay.localWakeEpoch[queueIndex].fetch_add(
                                1u, std::memory_order_release);
                            transaction.wakeLocalWaiter = true;
                        }
                    }
                }
            }
            if (waitQueueIndex >= kQueueCapacity) {
                if (transaction.wakeLocalWaiter) {
                    notify_local_waiters();
                }
                if (forwardDirect) {
                    return original(eq);
                }

                const int rc = original(eq);
                bool notifyReactor = false;
                bool notifyLocal = false;
                bool classificationRemoved = false;
                bool removedWasExclusive = false;
                bool removedWasMixed = false;
                {
                    OverlayLock lock;
                    if (TrackedEqueue* queue =
                            find_queue_control_locked(transaction)) {
                        if (rc == 0) {
                            // The successful real equeue deletion already
                            // removed the private EVFILT_USER registration.
                            removedWasExclusive =
                                queue_would_be_exclusive_local_locked(*queue);
                            if (removedWasExclusive) {
                                APR_EQ_COUNT(localExits);
                            }
                            removedWasMixed =
                                queue->mixedSourceSeen || queue->ammSourceSeen;
                            classificationRemoved =
                                queue_has_meaningful_classification(
                                    queue->amprSourceSeen,
                                    queue->mixedSourceSeen,
                                    queue->ammSourceSeen);
                            if (!classificationRemoved) {
                                APR_EQ_COUNT(silentUnclassifiedDeletes);
                            }
                            notifyReactor = release_queue_locked(
                                transaction.queueIndex);
                            notifyLocal = true;
                        } else {
                            finish_queue_control_locked(*queue);
                        }
                    }
                }
                if (notifyReactor) {
                    apr_reactor_notify_external_progress();
                }
                if (notifyLocal) {
                    notify_local_waiters();
                }
                if (classificationRemoved) {
                    log_queue_classification_change(
                        eq,
                        removedWasMixed
                            ? "mixed"
                            : (removedWasExclusive
                                   ? "apr-local"
                                   : "apr-candidate"),
                        "untracked",
                        "equeue-delete");
                }
                return rc;
            }
        }
        // Do not hold the lifecycle mutex while the trigger owner completes.
        // Its libkernel call may synchronously enter another lifecycle hook.
        wait_for_private_wake(waitQueueIndex);
    }
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
    const SceKernelUseconds requestedTimeout = timeout ? *timeout : 0;
    NativeWaitDeadline deadline{};
    bool trackedQueue = false;
    bool countedTrackedWait = false;
    bool notifyReactor = false;
    bool localWaitAttempted = false;
    bool nativeWaitIntentInstalled = false;
    for (;;) {
        trackedQueue = false;
        notifyReactor = false;
        PrivateWakeRequest replacementWake{};
        bool executeReplacementWake = false;
        uint32_t waitQueueIndex = kInvalidIndex;
        bool waitForWakeCompletion = false;
        bool useLocalWait = false;
        bool localPollTimeout = false;
        uint64_t observedLocalEpoch = 0;
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
                        drain_pending_locked(
                            queueIndex, queue, events, num, &notifyReactor);
                    if (synthetic != 0) {
                        *out = synthetic;
                        APR_EQ_COUNT(syntheticDirectReturns);
                        APR_EQ_ADD(syntheticEvents, synthetic);
                        if (queue.pendingCount != 0 &&
                            queue.nativeWaitIntent != 0) {
                            executeReplacementWake =
                                begin_private_wake_locked(
                                    queueIndex,
                                    queue,
                                    kInvalidIndex,
                                    &replacementWake) ==
                                BeginPrivateWakeResult::Scheduled;
                        }
                    } else if (queue_is_exclusive_local_locked(queue)) {
                        if (timeout && requestedTimeout == 0) {
                            localPollTimeout = true;
                        } else {
                            useLocalWait = true;
                            observedLocalEpoch =
                                g_overlay.localWakeEpoch[queueIndex].load(
                                    std::memory_order_relaxed);
                        }
                    } else {
                        ++queue.nativeWaitIntent;
                        note_wait_intent_added_locked();
                        nativeWaitIntentInstalled = true;
                    }
                }
            }
        }
        if (waitForWakeCompletion) {
            wait_for_private_wake(waitQueueIndex);
            continue;
        }
        if (executeReplacementWake) {
            execute_replacement_wake_or_abort(replacementWake);
        }
        if (!trackedQueue) {
            APR_EQ_COUNT(directWaits);
            SceKernelUseconds remaining = requestedTimeout;
            SceKernelUseconds* remainingPtr = timeout;
            if (localWaitAttempted && timeout && requestedTimeout != 0 &&
                deadline.expires != 0) {
                remaining = remaining_timeout_us(deadline);
                remainingPtr = &remaining;
            }
            return original(eq, events, num, out, remainingPtr);
        }
        if (!countedTrackedWait) {
            APR_EQ_COUNT(trackedWaits);
            countedTrackedWait = true;
        }
        if (*out != 0) {
            if (notifyReactor) {
                apr_reactor_notify_external_progress();
            }
            return 0;
        }
        if (localPollTimeout) {
            APR_EQ_COUNT(localTimeouts);
            return SCE_KERNEL_ERROR_ETIMEDOUT;
        }
        if (!useLocalWait) {
            break;
        }

        if (timeout && requestedTimeout != 0 && deadline.expires == 0) {
            deadline = make_native_wait_deadline(
                requestedTimeout, counterFrequency);
            if (deadline.expires == 0) {
                const NativeWaitTransition transition = prepare_native_wait(
                    trackedQueueIndex, queueGeneration, events, num);
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
                break;
            }
        }

        SceKernelUseconds localTimeout = 0;
        const SceKernelUseconds* localTimeoutPtr = nullptr;
        if (timeout) {
            localTimeout = remaining_timeout_us(deadline);
            if (localTimeout == 0) {
                APR_EQ_COUNT(localTimeouts);
                return SCE_KERNEL_ERROR_ETIMEDOUT;
            }
            localTimeoutPtr = &localTimeout;
        }
        localWaitAttempted = true;
        wait_for_local_change(
            trackedQueueIndex, observedLocalEpoch, localTimeoutPtr);
    }

    if (timeout && requestedTimeout != 0 && deadline.expires == 0) {
        deadline = make_native_wait_deadline(
            requestedTimeout, counterFrequency);
    }
    if (!timeout) {
        APR_EQ_COUNT(nativeWaitInfinite);
    } else if (requestedTimeout == 0) {
        APR_EQ_COUNT(nativeWaitZero);
    } else {
        APR_EQ_COUNT(nativeWaitFinite);
    }

    bool firstNativeWait = !localWaitAttempted;
    bool nativeWaitAttempted = false;
    for (;;) {
        if (!nativeWaitIntentInstalled) {
            const NativeWaitTransition transition = prepare_native_wait(
                trackedQueueIndex, queueGeneration, events, num);
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
                            trackedQueueIndex,
                            queue,
                            events + realCount,
                            num - realCount,
                            &notifyReactorAfterDrain);
                        APR_EQ_ADD(syntheticEvents, syntheticCount);
                        if (queue.pendingCount != 0 &&
                            queue.nativeWaitIntent != 0) {
                            executeReplacementWake =
                                begin_private_wake_locked(
                                    trackedQueueIndex,
                                    queue,
                                    kInvalidIndex,
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
            execute_replacement_wake_or_abort(replacementWake);
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
    const uint64_t staleRegistrationDrops = APR_EQ_READ(staleRegistrationDrops);
    const uint64_t syntheticEvents = APR_EQ_READ(syntheticEvents);
    const uint64_t syntheticDirectReturns = APR_EQ_READ(syntheticDirectReturns);
    const uint64_t localWaits = APR_EQ_READ(localWaits);
    const uint64_t localWakeups = APR_EQ_READ(localWakeups);
    const uint64_t localTimeouts = APR_EQ_READ(localTimeouts);
    const uint64_t localEntries = APR_EQ_READ(localEntries);
    const uint64_t localExits = APR_EQ_READ(localExits);
    const uint64_t mixedPromotions = APR_EQ_READ(mixedPromotions);
    const uint64_t ammEventQueues = APR_EQ_READ(ammEventQueues);
    const uint64_t ammBufferRegistrations = APR_EQ_READ(ammBufferRegistrations);
    const uint64_t ammTrackingFailures = APR_EQ_READ(ammTrackingFailures);
    const uint64_t silentUnclassifiedDeletes =
        APR_EQ_READ(silentUnclassifiedDeletes);
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
        if (reset) {
            g_overlay.pendingPeak = livePending;
            g_overlay.waitIntentPeak = static_cast<uint32_t>(liveWaitIntents);
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
    AMPR_LOGF("apr.equeue.wait.counters reason=%s trackedWaits=%llu directWaits=%llu nativeWaits=%llu nativeWaitZero=%llu nativeWaitFinite=%llu nativeWaitInfinite=%llu liveWaitIntents=%llu waitIntentPeak=%llu nativeEvents=%llu hiddenFiltered=%llu staleWakes=%llu staleRegistrationDrops=%llu syntheticEvents=%llu syntheticDirectReturns=%llu",
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
              (unsigned long long)staleRegistrationDrops,
              (unsigned long long)syntheticEvents,
              (unsigned long long)syntheticDirectReturns);
    AMPR_LOGF("apr.equeue.local-wait.counters reason=%s classifiers=%u sync=%u waits=%llu wakeups=%llu timeouts=%llu localEntries=%llu localExits=%llu mixedPromotions=%llu ammEventQueues=%llu ammBufferRegistrations=%llu ammTrackingFailures=%llu silentUnclassifiedDeletes=%llu",
              reason ? reason : "unknown",
              g_overlay.classificationHooksAvailable.load(
                  std::memory_order_acquire) ? 1u : 0u,
              g_overlay.localWaitSyncReady.load(
                  std::memory_order_acquire) ? 1u : 0u,
              (unsigned long long)localWaits,
              (unsigned long long)localWakeups,
              (unsigned long long)localTimeouts,
              (unsigned long long)localEntries,
              (unsigned long long)localExits,
              (unsigned long long)mixedPromotions,
              (unsigned long long)ammEventQueues,
              (unsigned long long)ammBufferRegistrations,
              (unsigned long long)ammTrackingFailures,
              (unsigned long long)silentUnclassifiedDeletes);
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
