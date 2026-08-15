/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * APR reactor arena allocator.
 */

#define AMPR_EMU_CORE_IMPL 1
#include "ampr_emu_apr_reactor_arena.h"
#include "ampr_emu_log.h"
#include "ampr_emu_runtime_memory.h"
#include "ampr_emu_sync.h"

#include <atomic>

namespace {
static constexpr size_t kAmprReactorArenaAlignment = alignof(std::max_align_t);

struct AmprReactorArenaBlock {
    size_t size{};
    AmprReactorArenaBlock* next{};
    bool free{};
};

static std::atomic<uint32_t> g_apr_reactor_arena_lock{0};
static uint8_t* g_apr_reactor_arena_base = nullptr;
static size_t g_apr_reactor_arena_size = 0;
static size_t g_apr_reactor_arena_used = 0;
static size_t g_apr_reactor_arena_peak = 0;
static bool g_apr_reactor_arena_initializing = false;
static AmprReactorArenaBlock* g_apr_reactor_arena_head = nullptr;

static size_t ampr_reactor_arena_header_size() {
    return ampr_internal_align_up_size(sizeof(AmprReactorArenaBlock),
                                              kAmprReactorArenaAlignment);
}

static bool ampr_reactor_arena_contains(void* ptr) {
    if (!ptr || !g_apr_reactor_arena_base || g_apr_reactor_arena_size == 0) {
        return false;
    }
    const uintptr_t base = reinterpret_cast<uintptr_t>(g_apr_reactor_arena_base);
    const uintptr_t end = base + g_apr_reactor_arena_size;
    const uintptr_t addr = reinterpret_cast<uintptr_t>(ptr);
    return end >= base && addr >= base && addr < end;
}

static bool ampr_reactor_arena_init() {
    uint32_t spins = 0;
    for (;;) {
        {
            AmprSpinLock lock(&g_apr_reactor_arena_lock);
            if (g_apr_reactor_arena_head) {
                return true;
            }
            if (!g_apr_reactor_arena_initializing) {
                g_apr_reactor_arena_initializing = true;
                break;
            }
        }
        ampr_spin_pause_or_yield(spins);
    }

    if (!ampr_internal_amm_pool_ensure(kAmprAprReactorArenaSize, "app0-core")) {
        {
            AmprSpinLock lock(&g_apr_reactor_arena_lock);
            g_apr_reactor_arena_initializing = false;
        }
        AMPR_CRITICAL_LOGF("apr.reactor.arena init fail reason=pool-ensure size=0x%llx",
                           (unsigned long long)kAmprAprReactorArenaSize);
        return false;
    }

    size_t mappedSize = 0;
    void* base = ampr_internal_amm_pool_alloc(kAmprAprReactorArenaSize,
                                                     &mappedSize,
                                                     "apr.reactor.arena");
    if (!base || mappedSize <= ampr_reactor_arena_header_size()) {
        {
            AmprSpinLock lock(&g_apr_reactor_arena_lock);
            g_apr_reactor_arena_initializing = false;
        }
        if (base) {
            (void)ampr_internal_amm_pool_free(base, "apr.reactor.arena.invalid");
        }
        AMPR_CRITICAL_LOGF("apr.reactor.arena init fail reason=pool-alloc ptr=%p size=0x%llx",
                           base,
                           (unsigned long long)mappedSize);
        return false;
    }

    {
        AmprSpinLock lock(&g_apr_reactor_arena_lock);
        g_apr_reactor_arena_base = static_cast<uint8_t*>(base);
        g_apr_reactor_arena_size = mappedSize;
        g_apr_reactor_arena_used = 0;
        g_apr_reactor_arena_peak = 0;
        g_apr_reactor_arena_head = reinterpret_cast<AmprReactorArenaBlock*>(base);
        g_apr_reactor_arena_head->size = mappedSize - ampr_reactor_arena_header_size();
        g_apr_reactor_arena_head->next = nullptr;
        g_apr_reactor_arena_head->free = true;
        g_apr_reactor_arena_initializing = false;
    }

    AMPR_LOGF("apr.reactor.arena init ok base=%p size=0x%llx usable=0x%llx",
              base,
              (unsigned long long)mappedSize,
              (unsigned long long)(mappedSize - ampr_reactor_arena_header_size()));
    return true;
}

} // namespace

void* ampr_reactor_arena_alloc(size_t size, size_t alignment) {
    if (size == 0) {
        return nullptr;
    }
    if (alignment > kAmprReactorArenaAlignment) {
        if (!ampr_reactor_arena_init()) {
            __builtin_trap();
        }
        size_t mappedSize = 0;
        void* pool = ampr_internal_amm_pool_alloc(size,
                                                         &mappedSize,
                                                         "apr.reactor.overalign",
                                                         true,
                                                         alignment);
        if (!pool) {
            __builtin_trap();
        }
        return pool;
    }
    const size_t alignedSize = ampr_internal_align_up_size(size, kAmprReactorArenaAlignment);
    const size_t headerSize = ampr_reactor_arena_header_size();
    if (alignedSize == SIZE_MAX || headerSize == SIZE_MAX || !ampr_reactor_arena_init()) {
        __builtin_trap();
    }

    size_t arenaUsedSnapshot = 0;
    size_t arenaPeakSnapshot = 0;
    size_t arenaTotalSnapshot = 0;
    {
        AmprSpinLock lock(&g_apr_reactor_arena_lock);
        for (AmprReactorArenaBlock* block = g_apr_reactor_arena_head; block; block = block->next) {
            if (!block->free || block->size < alignedSize) {
                continue;
            }
            const size_t remaining = block->size - alignedSize;
            if (remaining > headerSize + kAmprReactorArenaAlignment) {
                uint8_t* nextAddr = reinterpret_cast<uint8_t*>(block) + headerSize + alignedSize;
                AmprReactorArenaBlock* next = reinterpret_cast<AmprReactorArenaBlock*>(nextAddr);
                next->size = remaining - headerSize;
                next->next = block->next;
                next->free = true;
                block->size = alignedSize;
                block->next = next;
            }
            block->free = false;
            if (g_apr_reactor_arena_used <= SIZE_MAX - block->size) {
                g_apr_reactor_arena_used += block->size;
            } else {
                g_apr_reactor_arena_used = SIZE_MAX;
            }
            if (g_apr_reactor_arena_peak < g_apr_reactor_arena_used) {
                g_apr_reactor_arena_peak = g_apr_reactor_arena_used;
            }
            return reinterpret_cast<uint8_t*>(block) + headerSize;
        }
        arenaUsedSnapshot = g_apr_reactor_arena_used;
        arenaPeakSnapshot = g_apr_reactor_arena_peak;
        arenaTotalSnapshot = g_apr_reactor_arena_size;
    }

    size_t mappedSize = 0;
    void* overflow = ampr_internal_amm_pool_alloc(alignedSize,
                                                        &mappedSize,
                                                        "apr.reactor.overflow");
    AMPR_CRITICAL_LOGF("apr.reactor.arena overflow request=0x%llx mapped=0x%llx ptr=%p arenaUsed=0x%llx arenaPeak=0x%llx arenaTotal=0x%llx",
                       (unsigned long long)alignedSize,
                       (unsigned long long)mappedSize,
                       overflow,
                       (unsigned long long)arenaUsedSnapshot,
                       (unsigned long long)arenaPeakSnapshot,
                       (unsigned long long)arenaTotalSnapshot);
    if (!overflow) {
        __builtin_trap();
    }
    return overflow;
}

void ampr_reactor_arena_free(void* ptr, size_t) {
    if (!ptr) {
        return;
    }
    if (!ampr_reactor_arena_contains(ptr)) {
        (void)ampr_internal_amm_pool_free(ptr, "apr.reactor.overflow");
        return;
    }

    const size_t headerSize = ampr_reactor_arena_header_size();
    AmprSpinLock lock(&g_apr_reactor_arena_lock);
    AmprReactorArenaBlock* block =
        reinterpret_cast<AmprReactorArenaBlock*>(static_cast<uint8_t*>(ptr) - headerSize);
    if (block->free) {
        AMPR_LOGF("apr.reactor.arena free skip ptr=%p reason=double-free", ptr);
        return;
    }
    g_apr_reactor_arena_used =
        block->size <= g_apr_reactor_arena_used ? g_apr_reactor_arena_used - block->size : 0;
    block->free = true;

    if (block->next && block->next->free) {
        AmprReactorArenaBlock* next = block->next;
        block->size += headerSize + next->size;
        block->next = next->next;
    }

    AmprReactorArenaBlock* prev = nullptr;
    for (AmprReactorArenaBlock* cur = g_apr_reactor_arena_head; cur && cur != block; cur = cur->next) {
        prev = cur;
    }
    if (prev && prev->free) {
        prev->size += headerSize + block->size;
        prev->next = block->next;
    }
}


