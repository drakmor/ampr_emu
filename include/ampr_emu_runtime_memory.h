/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Shared runtime-memory allocation boundary.
 */

#pragma once

#include "ampr_emu_config.h"

#include <atomic>
#include <cstddef>
#include <cstdint>

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

bool ampr_internal_amm_pool_ensure(size_t requiredSize, const char* reason);
bool ampr_internal_amm_pool_ready_has_capacity(size_t size, size_t alignment = alignof(std::max_align_t));
void* ampr_internal_amm_pool_alloc(size_t size,
                                          size_t* outSize,
                                          const char* tag,
                                          bool mayCreatePool = true,
                                          size_t alignment = alignof(std::max_align_t));
bool ampr_internal_amm_pool_free(void* ptr, const char* tag);
void ampr_internal_amm_pool_log_summary(const char* reason);
bool ampr_internal_amm_pool_prepare_static_storage(const char* reason);
void ampr_runtime_memory_log_heartbeat(const char* reason);
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
static constexpr size_t kAprCommandBufferLiveMax =
    static_cast<size_t>(AMPR_EMU_APR_COMMAND_BUFFER_LIVE_MAX);
