/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Internal libkernel symbol lookup helpers.
 */

#pragma once

#include "ampr_libkernel_hook.h"

template <typename Fn>
static inline Fn ampr_fixed_kernel_slot(AmprLibkernelHookId hookId) {
    return reinterpret_cast<Fn>(g_amprOriginalLibkernelById[hookId]);
}

template <typename Fn>
static Fn ampr_dynamic_kernel_func_or_null(const char* symbol) {
    void* resolved = amprResolveLibkernelFunction(symbol);
    if (resolved) return reinterpret_cast<Fn>(resolved);
    return nullptr;
}
