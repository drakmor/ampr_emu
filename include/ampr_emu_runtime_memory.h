/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Shared runtime-memory allocation boundary.
 */

#pragma once

#include "ampr_emu_config.h"
#include "ampr_emu_log.h"

#ifndef AMPR_EMU_RUNTIME_IMPL
#include "ampr_emu_sync.h"
#endif

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <type_traits>

enum class AmprSharedRuntimeMemoryOwner : uint8_t {
    None,
    Pool,
    Flexible,
    Heap,
    SmallSlab,
};

struct AmprSharedRuntimeMemoryBlock {
    void* base{};
    size_t size{};
    AmprSharedRuntimeMemoryOwner owner{AmprSharedRuntimeMemoryOwner::None};
};

static constexpr uint32_t kAmprSharedExactSlabInvalid = UINT32_MAX;

struct AmprSharedExactSlabBlock {
    uint8_t* base{};
    size_t slotSize{};
    uint32_t slotCount{};
    uint32_t freeHead{kAmprSharedExactSlabInvalid};
    uint32_t freeCount{};
    bool active{};
};

struct AmprSharedExactSlabPool {
    std::atomic<uint32_t> lock{0};
    AmprSharedExactSlabBlock* blocks{};
    size_t blockCapacity{};
    size_t blockCount{};
};

struct AmprIndexFreeList {
    uint32_t head{UINT32_MAX};
    uint32_t count{};
    uint32_t capacity{};
    uint32_t invalid{UINT32_MAX};
};

static inline void ampr_index_free_list_reset(AmprIndexFreeList& list,
                                              uint32_t capacity,
                                              uint32_t invalid,
                                              bool hasStorage) {
    list.head = (hasStorage && capacity != 0) ? 0 : invalid;
    list.count = hasStorage ? capacity : 0;
    list.capacity = hasStorage ? capacity : 0;
    list.invalid = invalid;
}

static inline void ampr_index_free_list_init_next(AmprIndexFreeList& list,
                                                  uint32_t* next,
                                                  uint32_t capacity,
                                                  uint32_t invalid) {
    ampr_index_free_list_reset(list, capacity, invalid, next != nullptr);
    if (!next) {
        return;
    }
    for (uint32_t i = 0; i < capacity; ++i) {
        next[i] = (i + 1u < capacity) ? i + 1u : invalid;
    }
}

static inline uint32_t ampr_index_free_list_take_next(AmprIndexFreeList& list,
                                                      uint32_t* next) {
    if (!next || list.head == list.invalid || list.head >= list.capacity) {
        return list.invalid;
    }
    const uint32_t index = list.head;
    list.head = next[index];
    next[index] = list.invalid;
    if (list.count != 0) {
        --list.count;
    }
    return index;
}

static inline bool ampr_index_free_list_put_next(AmprIndexFreeList& list,
                                                 uint32_t* next,
                                                 uint32_t index) {
    if (!next || index >= list.capacity || list.count >= list.capacity) {
        return false;
    }
    next[index] = list.head;
    list.head = index;
    ++list.count;
    return true;
}

template <typename Node>
static inline void ampr_index_free_list_init_nodes(AmprIndexFreeList& list,
                                                   Node* nodes,
                                                   uint32_t capacity,
                                                   uint32_t invalid) {
    ampr_index_free_list_reset(list, capacity, invalid, nodes != nullptr);
    if (!nodes) {
        return;
    }
    for (uint32_t i = 0; i < capacity; ++i) {
        nodes[i] = {};
        nodes[i].next = (i + 1u < capacity) ? i + 1u : invalid;
    }
}

template <typename Node>
static inline uint32_t ampr_index_free_list_take_node(AmprIndexFreeList& list,
                                                      Node* nodes) {
    if (!nodes || list.head == list.invalid || list.head >= list.capacity) {
        return list.invalid;
    }
    const uint32_t index = list.head;
    list.head = nodes[index].next;
    if (list.count != 0) {
        --list.count;
    }
    return index;
}

template <typename Node>
static inline bool ampr_index_free_list_put_node(AmprIndexFreeList& list,
                                                 Node* nodes,
                                                 uint32_t index) {
    if (!nodes || index >= list.capacity || list.count >= list.capacity) {
        return false;
    }
    nodes[index].next = list.head;
    list.head = index;
    ++list.count;
    return true;
}

enum class AmprSharedSdkCpuMemoryClass : uint8_t {
    Persistent,
    Transient,
};

size_t ampr_internal_align_up_size(size_t value, size_t alignment);
bool ampr_internal_amm_pool_ensure(size_t requiredSize, const char* reason);
bool ampr_internal_amm_pool_ready_has_capacity(size_t size, size_t alignment = alignof(std::max_align_t));
bool ampr_internal_amm_pool_apr_visible();
void* ampr_internal_amm_pool_alloc(size_t size,
                                          size_t* outSize,
                                          const char* tag,
                                          bool mayCreatePool = true,
                                          size_t alignment = alignof(std::max_align_t));
bool ampr_internal_amm_pool_free(void* ptr, const char* tag);
void ampr_internal_amm_pool_log_summary(const char* reason);
bool ampr_internal_amm_pool_prepare_static_storage(const char* reason);
void ampr_runtime_memory_log_heartbeat(const char* reason);
bool ampr_small_slab_eligible(size_t size, size_t alignment);
void* ampr_small_slab_alloc(size_t size,
                                   size_t alignment,
                                   size_t* outSlotSize,
                                   const char* tag,
                                   bool mayCreatePool);
bool ampr_small_slab_free(void* ptr, const char* tag, size_t* outSlotSize = nullptr);
void ampr_exact_slab_pool_init(AmprSharedExactSlabPool* pool,
                                      AmprSharedExactSlabBlock* blocks,
                                      size_t blockCapacity);
void* ampr_exact_slab_alloc(AmprSharedExactSlabPool* pool,
                                   size_t size,
                                   size_t alignment,
                                   size_t minBlockBytes,
                                   size_t* outSlotSize,
                                   const char* tag,
                                   bool mayCreatePool,
                                   bool requireAprVisible);
bool ampr_exact_slab_free(AmprSharedExactSlabPool* pool,
                                 void* ptr,
                                 const char* tag,
                                 size_t* outSlotSize = nullptr,
                                 bool releaseRedundantEmptyBlocks = false,
                                 bool releaseEmptyBlocksAlways = false);
const char* ampr_sdk_cpu_memory_class_name(AmprSharedSdkCpuMemoryClass memoryClass);
void ampr_sdk_cpu_memory_note_alloc(AmprSharedSdkCpuMemoryClass memoryClass, size_t size);
void ampr_sdk_cpu_memory_note_free(AmprSharedSdkCpuMemoryClass memoryClass, size_t size);
void ampr_sdk_cpu_memory_log_summary(const char* reason);
void* ampr_runtime_alloc_from_pool_only(const char* tag,
                                               size_t size,
                                               AmprSharedRuntimeMemoryBlock* out,
                                               size_t alignment = alignof(std::max_align_t));

#ifndef AMPR_EMU_RUNTIME_IMPL

static constexpr size_t kAmprAprReactorArenaSize = 8u * 1024u * 1024u;
static constexpr size_t kAprCommandBufferLiveMax =
    static_cast<size_t>(AMPR_EMU_APR_COMMAND_BUFFER_LIVE_MAX);

static inline bool ampr_should_log_queue_growth(size_t size, size_t threshold) {
    if (threshold == 0 || size < threshold) {
        return false;
    }
    if (size == threshold) {
        return true;
    }
    return (size & (size - 1u)) == 0;
}

static std::atomic<uint32_t> g_ampr_lazy_state_init_lock{0};

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
    T* p = slot->load(std::memory_order_acquire);
    if (p) return p;

    AmprLazyStateInitLock init(g_ampr_lazy_state_init_lock);
    p = slot->load(std::memory_order_acquire);
    if (p) return p;

    void* storage = ampr_runtime_alloc_from_pool_only("lazy.state",
                                                            sizeof(T),
                                                            nullptr,
                                                            alignof(T));
    if (!storage) {
        alignas(T) static unsigned char fallback[sizeof(T)];
        static bool fallbackUsed = false;
        if (fallbackUsed) {
            return nullptr;
        }
        fallbackUsed = true;
        storage = fallback;
        AMPR_CRITICAL_LOGF("lazy.state fallback typeSize=0x%llx align=0x%llx",
                           (unsigned long long)sizeof(T),
                           (unsigned long long)alignof(T));
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

#endif // !AMPR_EMU_RUNTIME_IMPL
