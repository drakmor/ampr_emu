/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Internal file/path libkernel wrappers.
 */

#pragma once

#include "ampr_emu_kernel_lookup.h"

#include <_kernel.h>
#include <fcntl.h>
#include <kernel.h>
#include <sys/stat.h>

static inline int ampr_real_sceKernelOpen(const char* path, int flags, SceKernelMode mode) {
    using Fn = int (*)(const char*, int, SceKernelMode);
    Fn fn = ampr_fixed_kernel_slot<Fn>(kAmprLibkernelHook_sceKernelOpen);
    return fn(path, flags, mode);
}

static inline int ampr_real_sceKernelStat(const char* path, SceKernelStat* st) {
    using Fn = int (*)(const char*, SceKernelStat*);
    Fn fn = ampr_fixed_kernel_slot<Fn>(kAmprLibkernelHook_sceKernelStat);
    return fn(path, st);
}

static inline int ampr_real_sceKernelCheckReachability(const char* path) {
    using Fn = int (*)(const char*);
    Fn fn = ampr_fixed_kernel_slot<Fn>(kAmprLibkernelHook_sceKernelCheckReachability);
    return fn(path);
}

static inline int ampr_real_sceKernelUnlink(const char* path) {
    using Fn = int (*)(const char*);
    Fn fn = ampr_fixed_kernel_slot<Fn>(kAmprLibkernelHook_sceKernelUnlink);
    return fn(path);
}

static inline int ampr_real_sceKernelRename(const char* from, const char* to) {
    using Fn = int (*)(const char*, const char*);
    Fn fn = ampr_fixed_kernel_slot<Fn>(kAmprLibkernelHook_sceKernelRename);
    return fn(from, to);
}
