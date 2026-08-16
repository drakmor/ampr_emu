/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Shared APR reactor helpers.
 */

#pragma once

#include "ampr_emu_apr_reactor.h"
#include "ampr_emu_command_buffer_types.h"
#include "ampr_emu_command_packing.h"
#include "ampr_emu_errno.h"
#include "ampr_emu_fd_cache.h"
#include "ampr_emu_index.h"
#include "ampr_emu_kernel_file.h"
#include "ampr_emu_kernel_lookup.h"
#include "ampr_emu_kernel_memory.h"

#include <_fs.h>

const char* ampr_log_path_arg(const char* path);
uint64_t time_counter_now();

inline constexpr size_t kFdOpenBudgetBaseCap =
    AMPR_EMU_FD_OPEN_BUDGET_CAP > 0 ? AMPR_EMU_FD_OPEN_BUDGET_CAP : 1;

void fd_cache_release_watermark_headroom(size_t reserve, const char* reason);

int apr_libkernel_rc_to_sce(int rc);

using AprNativeSubmitAndGetIdFn = int (*)(sce::Ampr::AprCommandBuffer*, uint32_t, SceAprSubmitId*);
using AprNativeSubmitFn = int (*)(sce::Ampr::AprCommandBuffer*, uint32_t);
using AprNativeSubmitAndGetResultFn =
    int (*)(sce::Ampr::AprCommandBuffer*, uint32_t, SceAprResultBuffer*, SceAprSubmitId*);
using AprNativeWaitFn = int (*)(SceAprSubmitId);

static inline int apr_native_submit_dispatch(sce::Ampr::AprCommandBuffer* commandBuffer,
                                             uint32_t prio,
                                             AprSubmitMode mode,
                                             SceAprResultBuffer* result,
                                             SceAprSubmitId* id,
                                             int* rawRcOut) {
    switch (mode) {
        case AprSubmitMode::kSubmit: {
            if (AprNativeSubmitFn submit =
                    ampr_fixed_kernel_slot<AprNativeSubmitFn>(kAmprLibkernelHook_sceKernelAprSubmitCommandBuffer)) {
                *rawRcOut = submit(commandBuffer, prio);
                return 0;
            }
            return SCE_KERNEL_ERROR_ENXIO;
        }
        case AprSubmitMode::kSubmitAndGetResult: {
            if (AprNativeSubmitAndGetResultFn submit =
                    ampr_fixed_kernel_slot<AprNativeSubmitAndGetResultFn>(
                        kAmprLibkernelHook_sceKernelAprSubmitCommandBufferAndGetResult)) {
                *rawRcOut = submit(commandBuffer, prio, result, id);
                return 0;
            }
            return SCE_KERNEL_ERROR_ENXIO;
        }
        case AprSubmitMode::kSubmitAndGetId: {
            if (AprNativeSubmitAndGetIdFn submit =
                    ampr_fixed_kernel_slot<AprNativeSubmitAndGetIdFn>(
                        kAmprLibkernelHook_sceKernelAprSubmitCommandBufferAndGetId)) {
                *rawRcOut = submit(commandBuffer, prio, id);
                return 0;
            }
            return SCE_KERNEL_ERROR_ENXIO;
        }
        default:
            return SCE_KERNEL_ERROR_EINVAL;
    }
}

static inline int apr_native_wait_dispatch(SceAprSubmitId id, int* rawRcOut) {
    if (!rawRcOut) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    if (AprNativeWaitFn wait =
            ampr_fixed_kernel_slot<AprNativeWaitFn>(
                kAmprLibkernelHook_sceKernelAprWaitCommandBuffer)) {
        *rawRcOut = wait(id);
        return 0;
    }
    return SCE_KERNEL_ERROR_ENXIO;
}

struct alignas(sce::Ampr::AprCommandBuffer) NativeAprCommandBufferView {
    SceAmprCommandBuffer m_commandBuffer{};
    __SceAprMapState m_mapState{};
    __SceAprScatterGatherState m_scatterGatherState{};
};
static_assert(sizeof(NativeAprCommandBufferView) == sizeof(sce::Ampr::AprCommandBuffer),
              "native APR view must match retail AprCommandBuffer layout");
static_assert(alignof(NativeAprCommandBufferView) == alignof(sce::Ampr::AprCommandBuffer),
              "native APR view alignment must match retail AprCommandBuffer layout");
