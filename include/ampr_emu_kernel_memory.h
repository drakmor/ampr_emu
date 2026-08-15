/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Internal direct-memory and mapper libkernel wrappers.
 */

#pragma once

#include "ampr_emu_kernel_lookup.h"

#include <_kernel.h>
#include <kernel.h>
#include <stdint.h>
#include <sys/dmem.h>
#include <sys/sce_errno.h>

static inline size_t ampr_real_sceKernelGetDirectMemorySize() {
    using Fn = size_t (*)();
    Fn fn = ampr_fixed_kernel_slot<Fn>(kAmprLibkernelHook_sceKernelGetDirectMemorySize);
    return fn();
}

static inline int ampr_real_sceKernelAvailableDirectMemorySize(off_t searchStart,
                                                               off_t searchEnd,
                                                               size_t alignment,
                                                               off_t* physAddrOut,
                                                               size_t* sizeOut) {
    using Fn = int (*)(off_t, off_t, size_t, off_t*, size_t*);
    Fn fn = ampr_fixed_kernel_slot<Fn>(kAmprLibkernelHook_sceKernelAvailableDirectMemorySize);
    return fn(searchStart, searchEnd, alignment, physAddrOut, sizeOut);
}

static inline int ampr_real_sceKernelMprotect(const void* addr, size_t len, int prot) {
    using Fn = int (*)(const void*, size_t, int);
    Fn fn = ampr_fixed_kernel_slot<Fn>(kAmprLibkernelHook_sceKernelMprotect);
    return fn(addr, len, prot);
}

static inline int ampr_real_sceKernelMapperGetUsageStatsData(uint64_t* data) {
    using Fn = int (*)(uint64_t*);
    static Fn cached = ampr_dynamic_kernel_func_or_null<Fn>("sceKernelMapperGetUsageStatsData");
    if (Fn fn = cached) {
        return fn(data);
    }
    return SCE_KERNEL_ERROR_ENXIO;
}
