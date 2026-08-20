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
constexpr uint32_t kWakeIdBase = 0x5a4d5000u;
constexpr uint32_t kWakeAttachAttempts = 64u;
static_assert(kQueueCapacity != 0 && kRegistrationCapacity != 0 && kPendingCapacity != 0,
              "APR local equeue pools must not be empty");
static_assert((kQueueHashCapacity & (kQueueHashCapacity - 1u)) == 0,
              "APR local equeue hash capacity must be a power of two");

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
    bool used{};
    bool wakeRegistered{};
    bool wakeReady{};
    bool wakeArmed{};
};

struct OverlayState {
    std::atomic<uint32_t> lock{0};
    std::atomic<bool> hooksAvailable{false};
    bool initialized{};
    uint32_t queueFreeHead{};
    uint32_t registrationFreeHead{};
    uint32_t pendingFreeHead{};
    uint32_t nextWakeId{};
    uint64_t nextLifetimeGeneration{};
    uint64_t nextRegistrationGeneration{};
    uint32_t liveQueues{};
    uint32_t liveRegistrations{};
    uint32_t livePending{};
    uint32_t queueHashTombstones{};
    TrackedEqueue queues[kQueueCapacity]{};
    MirroredRegistration registrations[kRegistrationCapacity]{};
    PendingEvent pending[kPendingCapacity]{};
    uint32_t queueHash[kQueueHashCapacity]{};
};

// Keep the large fixed pools zero-initialized in .bss. initialize_locked()
// installs every nonzero free-list sentinel and generation seed before use.
OverlayState g_overlay{};

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
    std::atomic<uint64_t> wakeFailures{0};
    std::atomic<uint64_t> trackedWaits{0};
    std::atomic<uint64_t> directWaits{0};
    std::atomic<uint64_t> nativeWaits{0};
    std::atomic<uint64_t> nativeEvents{0};
    std::atomic<uint64_t> hiddenFiltered{0};
    std::atomic<uint64_t> staleWakes{0};
    std::atomic<uint64_t> syntheticEvents{0};
    std::atomic<uint64_t> syntheticDirectReturns{0};
    std::atomic<uint64_t> addRegistrations{0};
    std::atomic<uint64_t> deleteRegistrations{0};
    std::atomic<uint64_t> queueCapacityFailures{0};
    std::atomic<uint64_t> registrationCapacityFailures{0};
    std::atomic<uint64_t> queueHashRebuilds{0};
    std::atomic<uint64_t> registrationCacheHits{0};
    std::atomic<uint64_t> registrationCacheMisses{0};
    std::atomic<uint64_t> pendingPeak{0};
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
    return static_cast<uint64_t>(ts.tv_sec) * 1000000000ull +
           static_cast<uint64_t>(ts.tv_nsec);
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
        g_overlay.queues[i] = {};
        g_overlay.queues[i].nextFree = i + 1u < kQueueCapacity ? i + 1u : kInvalidIndex;
    }
    for (uint32_t i = 0; i < kRegistrationCapacity; ++i) {
        g_overlay.registrations[i] = {};
        g_overlay.registrations[i].next =
            i + 1u < kRegistrationCapacity ? i + 1u : kInvalidIndex;
    }
    for (uint32_t i = 0; i < kPendingCapacity; ++i) {
        g_overlay.pending[i] = {};
        g_overlay.pending[i].next = i + 1u < kPendingCapacity ? i + 1u : kInvalidIndex;
    }
    for (uint32_t& slot : g_overlay.queueHash) {
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

static uint32_t find_registration_locked(TrackedEqueue& queue, int32_t id) {
    if (queue.registrationCache < kRegistrationCapacity &&
        g_overlay.registrations[queue.registrationCache].id == id) {
        APR_EQ_COUNT(registrationCacheHits);
        return queue.registrationCache;
    }
    APR_EQ_COUNT(registrationCacheMisses);
    uint32_t index = queue.registrationHead;
    while (index < kRegistrationCapacity) {
        const MirroredRegistration& registration = g_overlay.registrations[index];
        if (registration.id == id) {
            queue.registrationCache = index;
            return index;
        }
        index = registration.next;
    }
    return kInvalidIndex;
}

static uint32_t allocate_registration_locked(TrackedEqueue& queue,
                                             int32_t id,
                                             void* udata) {
    uint32_t index = find_registration_locked(queue, id);
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
    queue.registrationHead = index;
    queue.registrationCache = index;
    ++g_overlay.liveRegistrations;
    return index;
}

static void remove_registration_locked(TrackedEqueue& queue, int32_t id) {
    uint32_t previous = kInvalidIndex;
    uint32_t index = queue.registrationHead;
    while (index < kRegistrationCapacity) {
        MirroredRegistration& registration = g_overlay.registrations[index];
        const uint32_t next = registration.next;
        if (registration.id == id) {
            if (previous < kRegistrationCapacity) {
                g_overlay.registrations[previous].next = next;
            } else {
                queue.registrationHead = next;
            }
            if (queue.registrationCache == index) {
                queue.registrationCache = kInvalidIndex;
            }
            registration = {};
            registration.next = g_overlay.registrationFreeHead;
            g_overlay.registrationFreeHead = index;
            if (g_overlay.liveRegistrations != 0) {
                --g_overlay.liveRegistrations;
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
    uint64_t peak = g_counters.pendingPeak.load(std::memory_order_relaxed);
    while (peak < g_overlay.livePending &&
           !g_counters.pendingPeak.compare_exchange_weak(
               peak, g_overlay.livePending, std::memory_order_relaxed)) {}
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
                                int capacity) {
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
    return count;
}

static int trigger_wake_locked(TrackedEqueue& queue) {
    if (!queue.wakeReady) {
        return SCE_KERNEL_ERROR_ENXIO;
    }
    const int rc = sceKernelTriggerUserEvent(
        queue.eq, static_cast<int>(queue.wakeId), static_cast<void*>(&queue));
    if (rc == 0) {
        queue.wakeArmed = true;
        APR_EQ_COUNT(wakeTriggers);
    } else {
        queue.wakeArmed = false;
        APR_EQ_COUNT(wakeFailures);
    }
    return rc;
}

static int ensure_wake_locked(TrackedEqueue& queue) {
    if (queue.wakeArmed) {
        APR_EQ_COUNT(wakeElisions);
        return 0;
    }
    return trigger_wake_locked(queue);
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

static void release_queue_locked(uint32_t queueIndex, bool deleteWake) {
    if (queueIndex >= kQueueCapacity || !g_overlay.queues[queueIndex].used) {
        return;
    }
    TrackedEqueue& queue = g_overlay.queues[queueIndex];
    if (deleteWake && queue.wakeRegistered) {
        (void)sceKernelDeleteUserEvent(queue.eq, static_cast<int>(queue.wakeId));
    }
    while (queue.registrationHead < kRegistrationCapacity) {
        const uint32_t index = queue.registrationHead;
        queue.registrationHead = g_overlay.registrations[index].next;
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
}

static bool is_hidden_wake(const SceKernelEvent& event,
                           uint32_t wakeId,
                           const TrackedEqueue* token) {
    return event.filter == SCE_KERNEL_EVFILT_USER &&
           static_cast<uint32_t>(event.ident) == wakeId &&
           event.udata == static_cast<const void*>(token);
}

static SceKernelUseconds remaining_timeout_us(uint64_t deadlineNs) {
    const uint64_t now = monotonic_ns();
    if (now == 0 || now >= deadlineNs) {
        return 0;
    }
    const uint64_t remainingNs = deadlineNs - now;
    uint64_t remainingUs = (remainingNs + 999u) / 1000u;
    if (remainingUs > UINT32_MAX) {
        remainingUs = UINT32_MAX;
    }
    return static_cast<SceKernelUseconds>(remainingUs);
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
    const uint32_t registrationIndex = find_registration_locked(queue, id);
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
        APR_EQ_COUNT(backpressure);
        return AprEqueuePublishResult::Backpressure;
    }
    const MirroredRegistration& registration =
        g_overlay.registrations[registrationIndex];
    PendingEvent& pending = g_overlay.pending[pendingIndex];
    pending.event.ident = static_cast<uintptr_t>(static_cast<uint32_t>(id));
    pending.event.filter = SCE_KERNEL_EVFILT_AMPR;
    pending.event.flags = static_cast<uint16_t>(EV_ADD | EV_CLEAR);
    pending.event.fflags = 0;
    pending.event.data = static_cast<intptr_t>(data);
    pending.event.udata = registration.udata;
    pending.registrationGeneration = registration.generation;

    // Keep at most one private edge outstanding. Trigger before linking the
    // first node while holding the overlay lock; a waiter that consumes that
    // edge blocks on the same lock and cannot observe it without pending APR
    // work. Further FIFO nodes reuse the armed edge until a waiter consumes it.
    const int wakeRc = ensure_wake_locked(queue);
    if (wakeRc != 0) {
        release_pending_locked(pendingIndex);
        queue.wakeReady = false;
        APR_EQ_COUNT(fallbackWake);
        AMPR_LOGF("apr.equeue.publish.fallback eq=%p id=%d reason=wake-trigger rc=0x%x",
                  eq, id, wakeRc);
        return AprEqueuePublishResult::NativeFallback;
    }
    append_pending_locked(queue, pendingIndex);
    APR_EQ_COUNT(published);
    AMPR_TLOGF("apr.equeue.publish eq=%p id=%d data=0x%llx udata=%p regGeneration=%llu pending=%u",
               eq,
               id,
               (unsigned long long)data,
               registration.udata,
               (unsigned long long)registration.generation,
               queue.pendingCount);
    return AprEqueuePublishResult::Published;
}

void apr_equeue_overlay_set_hooks_available(bool available) {
    g_overlay.hooksAvailable.store(available, std::memory_order_release);
}

void apr_equeue_overlay_shutdown() {
    g_overlay.hooksAvailable.store(false, std::memory_order_release);
    bool releasedPending = false;
    {
        OverlayLock lock;
        if (!g_overlay.initialized) {
            return;
        }
        releasedPending = g_overlay.livePending != 0;
        // Prevent an in-flight hook that observed the old capability state from
        // finding or reusing a slot while private wake syscalls run unlocked.
        g_overlay.initialized = false;
    }

    uint32_t queueIndex = 0;
    for (;;) {
        SceKernelEqueue wakeEq = nullptr;
        uint32_t wakeId = 0;
        bool deleteWake = false;
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
            wakeEq = queue.eq;
            wakeId = queue.wakeId;
            deleteWake = queue.wakeRegistered;
            release_queue_locked(queueIndex, false);
            ++queueIndex;
        }
        if (deleteWake) {
            (void)sceKernelDeleteUserEvent(wakeEq, static_cast<int>(wakeId));
        }
    }
    if (releasedPending) {
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

    OverlayLock lock;
    if (!g_overlay.hooksAvailable.load(std::memory_order_relaxed)) {
        return original(eq, id, udata);
    }
    const int rc = original(eq, id, udata);
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
            release_queue_locked(queueIndex, false);
            return rc;
        }
    }

    TrackedEqueue& queue = g_overlay.queues[queueIndex];
    if (allocate_registration_locked(queue, id, udata) >= kRegistrationCapacity) {
        if (allocatedQueue) {
            release_queue_locked(queueIndex, true);
        }
        return rc;
    }
    APR_EQ_COUNT(addRegistrations);
    AMPR_TLOGF("apr.equeue.registration.add eq=%p id=%d udata=%p queueGeneration=%llu",
               eq, id, udata, (unsigned long long)queue.lifetimeGeneration);
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
            remove_registration_locked(g_overlay.queues[queueIndex], id);
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

    bool releasedPending = false;
    int rc = 0;
    {
        OverlayLock lock;
        if (!g_overlay.hooksAvailable.load(std::memory_order_relaxed)) {
            return original(eq);
        }
        rc = original(eq);
        if (rc == 0) {
            const uint32_t queueIndex = find_queue_index_locked(eq);
            if (queueIndex < kQueueCapacity) {
                releasedPending = g_overlay.queues[queueIndex].pendingCount != 0;
                // The successful real equeue deletion already removed the
                // private EVFILT_USER registration.
                release_queue_locked(queueIndex, false);
            }
        }
    }
    if (releasedPending) {
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

    uint32_t queueIndex = kInvalidIndex;
    uint32_t wakeId = 0;
    uint64_t queueGeneration = 0;
    TrackedEqueue* wakeToken = nullptr;
    {
        OverlayLock lock;
        queueIndex = find_queue_index_locked(eq);
        if (queueIndex < kQueueCapacity) {
            const TrackedEqueue& queue = g_overlay.queues[queueIndex];
            wakeId = queue.wakeId;
            queueGeneration = queue.lifetimeGeneration;
            wakeToken = &g_overlay.queues[queueIndex];
        }
    }
    if (queueIndex >= kQueueCapacity) {
        APR_EQ_COUNT(directWaits);
        return original(eq, events, num, out, timeout);
    }
    APR_EQ_COUNT(trackedWaits);
    *out = 0;

    {
        bool consumed = false;
        OverlayLock lock;
        const uint32_t currentIndex = find_queue_index_locked(eq);
        if (currentIndex < kQueueCapacity &&
            g_overlay.queues[currentIndex].lifetimeGeneration == queueGeneration) {
            TrackedEqueue& queue = g_overlay.queues[currentIndex];
            const int synthetic = drain_pending_locked(queue, events, num);
            if (synthetic != 0) {
                consumed = true;
                *out = synthetic;
                APR_EQ_COUNT(syntheticDirectReturns);
                APR_EQ_ADD(syntheticEvents, synthetic);
                if (queue.pendingCount != 0) {
                    (void)ensure_wake_locked(queue);
                }
            }
        }
        if (consumed) {
            // Unlock before entering the reactor wait domain.
        } else {
            queueIndex = currentIndex;
        }
    }
    if (*out != 0) {
        apr_reactor_notify_external_progress();
        return 0;
    }

    // Delay the clock read until a real native wait is necessary. Already
    // pending synthetic events take the direct path above without a syscall.
    const uint64_t startNs = timeout ? monotonic_ns() : 0;
    uint64_t deadlineNs = 0;
    if (timeout && startNs != 0) {
        const uint64_t durationNs = static_cast<uint64_t>(*timeout) * 1000ull;
        deadlineNs = UINT64_MAX - startNs < durationNs
                         ? UINT64_MAX
                         : startNs + durationNs;
    }

    bool firstNativeWait = true;
    for (;;) {
        SceKernelUseconds localTimeout = 0;
        SceKernelUseconds* localTimeoutPtr = nullptr;
        if (timeout) {
            if (deadlineNs == 0) {
                localTimeout = *timeout;
            } else {
                localTimeout = remaining_timeout_us(deadlineNs);
            }
            if (!firstNativeWait && localTimeout == 0) {
                return SCE_KERNEL_ERROR_ETIMEDOUT;
            }
            localTimeoutPtr = &localTimeout;
        }
        firstNativeWait = false;

        int nativeCount = 0;
        APR_EQ_COUNT(nativeWaits);
        const int rc = original(eq, events, num, &nativeCount, localTimeoutPtr);
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
        {
            OverlayLock lock;
            const uint32_t currentIndex = find_queue_index_locked(eq);
            if (currentIndex < kQueueCapacity &&
                g_overlay.queues[currentIndex].lifetimeGeneration == queueGeneration) {
                TrackedEqueue& queue = g_overlay.queues[currentIndex];
                if (sawHidden) {
                    queue.wakeArmed = false;
                }
                syntheticCount = drain_pending_locked(
                    queue, events + realCount, num - realCount);
                APR_EQ_ADD(syntheticEvents, syntheticCount);
                if (queue.pendingCount != 0) {
                    (void)ensure_wake_locked(queue);
                }
            }
        }

        const int total = realCount + syntheticCount;
        if (syntheticCount != 0) {
            apr_reactor_notify_external_progress();
        }
        if (total != 0) {
            *out = total;
            return 0;
        }
        if (sawHidden) {
            APR_EQ_COUNT(staleWakes);
        }
        // A stale private edge is invisible to the application. Retry against
        // the same absolute deadline instead of restarting the relative timeout.
        if (timeout && deadlineNs != 0 && remaining_timeout_us(deadlineNs) == 0) {
            return SCE_KERNEL_ERROR_ETIMEDOUT;
        }
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
    const uint64_t wakeFailures = APR_EQ_READ(wakeFailures);
    const uint64_t trackedWaits = APR_EQ_READ(trackedWaits);
    const uint64_t directWaits = APR_EQ_READ(directWaits);
    const uint64_t nativeWaits = APR_EQ_READ(nativeWaits);
    const uint64_t nativeEvents = APR_EQ_READ(nativeEvents);
    const uint64_t hiddenFiltered = APR_EQ_READ(hiddenFiltered);
    const uint64_t staleWakes = APR_EQ_READ(staleWakes);
    const uint64_t syntheticEvents = APR_EQ_READ(syntheticEvents);
    const uint64_t syntheticDirectReturns = APR_EQ_READ(syntheticDirectReturns);
    const uint64_t addRegistrations = APR_EQ_READ(addRegistrations);
    const uint64_t deleteRegistrations = APR_EQ_READ(deleteRegistrations);
    const uint64_t queueCapacityFailures = APR_EQ_READ(queueCapacityFailures);
    const uint64_t registrationCapacityFailures = APR_EQ_READ(registrationCapacityFailures);
    const uint64_t queueHashRebuilds = APR_EQ_READ(queueHashRebuilds);
    const uint64_t registrationCacheHits = APR_EQ_READ(registrationCacheHits);
    const uint64_t registrationCacheMisses = APR_EQ_READ(registrationCacheMisses);
#undef APR_EQ_READ
    uint64_t pendingPeak = 0;
    uint32_t liveQueues = 0;
    uint32_t liveRegistrations = 0;
    uint32_t livePending = 0;
    {
        OverlayLock lock;
        liveQueues = g_overlay.liveQueues;
        liveRegistrations = g_overlay.liveRegistrations;
        livePending = g_overlay.livePending;
        // Serialize the peak reset with allocation/drain. The current occupancy
        // is the baseline of the new interval, and no concurrent high-water
        // update can be overwritten by a later store.
        pendingPeak = reset
            ? g_counters.pendingPeak.exchange(livePending, std::memory_order_relaxed)
            : g_counters.pendingPeak.load(std::memory_order_relaxed);
    }
    AMPR_LOGF("apr.equeue.counters reason=%s hooks=%u publishAttempts=%llu published=%llu backpressure=%llu fallbackHooks=%llu fallbackQueue=%llu fallbackRegistration=%llu fallbackWake=%llu wakeTriggers=%llu wakeElisions=%llu wakeFailures=%llu",
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
              (unsigned long long)wakeFailures);
    AMPR_LOGF("apr.equeue.wait.counters reason=%s trackedWaits=%llu directWaits=%llu nativeWaits=%llu nativeEvents=%llu hiddenFiltered=%llu staleWakes=%llu syntheticEvents=%llu syntheticDirectReturns=%llu",
              reason ? reason : "unknown",
              (unsigned long long)trackedWaits,
              (unsigned long long)directWaits,
              (unsigned long long)nativeWaits,
              (unsigned long long)nativeEvents,
              (unsigned long long)hiddenFiltered,
              (unsigned long long)staleWakes,
              (unsigned long long)syntheticEvents,
              (unsigned long long)syntheticDirectReturns);
    AMPR_LOGF("apr.equeue.storage.counters reason=%s addRegistrations=%llu deleteRegistrations=%llu queueCapacityFailures=%llu registrationCapacityFailures=%llu queueHashRebuilds=%llu registrationCacheHits=%llu registrationCacheMisses=%llu pendingPeak=%llu liveQueues=%u liveRegistrations=%u livePending=%u",
              reason ? reason : "unknown",
              (unsigned long long)addRegistrations,
              (unsigned long long)deleteRegistrations,
              (unsigned long long)queueCapacityFailures,
              (unsigned long long)registrationCapacityFailures,
              (unsigned long long)queueHashRebuilds,
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
