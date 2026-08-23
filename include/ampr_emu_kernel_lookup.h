/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Internal libkernel symbol lookup helpers.
 */

#pragma once

#include "ampr_libkernel_hook.h"

template <typename Fn>
static inline Fn ampr_fixed_kernel_slot(AmprLibkernelHookId hookId) {
    return reinterpret_cast<Fn>(__atomic_load_n(
        &g_amprOriginalLibkernelById[hookId], __ATOMIC_ACQUIRE));
}

#if AMPR_EMU_APR_LOCAL_EQUEUE
template <typename Fn>
static inline Fn ampr_fixed_external_equeue_slot(
    AmprExternalEqueueHookId hookId) {
    return reinterpret_cast<Fn>(__atomic_load_n(
        &g_amprOriginalExternalEqueueById[hookId], __ATOMIC_ACQUIRE));
}
#endif

template <typename Fn>
static Fn ampr_dynamic_kernel_func_or_null(const char* symbol) {
    void* resolved = amprResolveLibkernelFunction(symbol);
    if (resolved) return reinterpret_cast<Fn>(resolved);
    return nullptr;
}
