/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include "ampr_emu_config.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef AMPR_LIBKERNEL_HOOK_EXPORT
#define AMPR_LIBKERNEL_HOOK_EXPORT __attribute__((visibility("hidden")))
#endif

typedef enum AmprLibkernelHookId {
    kAmprLibkernelHook_sceKernelOpen = 0,
    kAmprLibkernelHook_sceKernelStat,
    kAmprLibkernelHook_sceKernelCheckReachability,
    kAmprLibkernelHook_sceKernelUnlink,
    kAmprLibkernelHook_sceKernelRename,
    kAmprLibkernelHook_sceKernelMprotect,
    kAmprLibkernelHook_sceKernelMtypeprotect,
    kAmprLibkernelHook_sceKernelMapFlexibleMemory,
    kAmprLibkernelHook_sceKernelMapDirectMemory,
    kAmprLibkernelHook_sceKernelMapDirectMemory2,
    kAmprLibkernelHook_sceKernelBatchMap,
    kAmprLibkernelHook_sceKernelBatchMap2,
    kAmprLibkernelHook_sceKernelJitMapSharedMemory,
    kAmprLibkernelHook_sceKernelMemoryPoolBatch,
    kAmprLibkernelHook_sceKernelMemoryPoolCommit,
    kAmprLibkernelHook_sceKernelMapNamedFlexibleMemory,
    kAmprLibkernelHook_sceKernelMapNamedDirectMemory,
    kAmprLibkernelHook_sceKernelAprResolveFilepathsToIds,
    kAmprLibkernelHook_sceKernelAprResolveFilepathsToIdsAndFileSizes,
    kAmprLibkernelHook_sceKernelAprResolveFilepathsWithPrefixToIds,
    kAmprLibkernelHook_sceKernelAprResolveFilepathsWithPrefixToIdsAndFileSizes,
    kAmprLibkernelHook_sceKernelAprResolveFilepathsToIdsForEach,
    kAmprLibkernelHook_sceKernelAprResolveFilepathsToIdsAndFileSizesForEach,
    kAmprLibkernelHook_sceKernelAprResolveFilepathsWithPrefixToIdsForEach,
    kAmprLibkernelHook_sceKernelAprResolveFilepathsWithPrefixToIdsAndFileSizesForEach,
    kAmprLibkernelHook_sceKernelAprGetFileSize,
    kAmprLibkernelHook_sceKernelAprGetFileStat,
    kAmprLibkernelHook_sceKernelAprSubmitCommandBuffer,
    kAmprLibkernelHook_sceKernelAprSubmitCommandBuffer_TEST,
    kAmprLibkernelHook_sceKernelAprSubmitCommandBufferAndGetResult,
    kAmprLibkernelHook_sceKernelAprSubmitCommandBufferAndGetResult_TEST,
    kAmprLibkernelHook_sceKernelAprSubmitCommandBufferAndGetId,
    kAmprLibkernelHook_sceKernelAprWaitCommandBuffer,
    kAmprLibkernelHook_sceKernelWaitCommandBufferCompletion,
    kAmprLibkernelHook_sceKernelGetDirectMemorySize,
    kAmprLibkernelHook_sceKernelAvailableDirectMemorySize,
    kAmprLibkernelHook_sceKernelWriteMapCommand,
    kAmprLibkernelHook_sceKernelWriteMapCommand2,
    kAmprLibkernelHook_sceKernelWriteMapWithGpuMaskIdCommand,
    kAmprLibkernelHook_sceKernelWriteMapDirectCommand,
    kAmprLibkernelHook_sceKernelWriteMapDirectWithGpuMaskIdCommand,
    kAmprLibkernelHook_sceKernelWriteRemapCommand,
    kAmprLibkernelHook_sceKernelWriteRemapWithGpuMaskIdCommand,
    kAmprLibkernelHook_sceKernelWriteMultiMapCommand,
    kAmprLibkernelHook_sceKernelWriteMultiMapWithGpuMaskIdCommand,
    kAmprLibkernelHook_sceKernelWriteModifyProtectCommand,
    kAmprLibkernelHook_sceKernelWriteModifyProtectWithGpuMaskIdCommand,
    kAmprLibkernelHook_sceKernelWriteModifyMtypeProtectCommand,
    kAmprLibkernelHook_sceKernelWriteModifyMtypeProtectWithGpuMaskIdCommand,
    kAmprLibkernelHook_sceKernelWriteRemapIntoPrtCommand,
#if AMPR_EMU_APR_LOCAL_EQUEUE
    kAmprLibkernelHook_sceKernelWaitEqueue,
    kAmprLibkernelHook_sceKernelDeleteEqueue,
    kAmprLibkernelHook_sceKernelAddAmprEvent,
    kAmprLibkernelHook_sceKernelDeleteAmprEvent,
#endif
    kAmprLibkernelHook_Count
} AmprLibkernelHookId;

/*
 * Process-wide libkernel detour control.
 *
 * These APIs patch the real loaded libkernel function bodies, not a fake
 * libkernel module and not just libSceAmpr's own imports. They are
 * intentionally hidden from the PRX export surface; the hook-enabled build
 * starts them internally.
 */
AMPR_LIBKERNEL_HOOK_EXPORT int amprInstallLibkernelHooks(void);
AMPR_LIBKERNEL_HOOK_EXPORT int amprUninstallLibkernelHooks(void);
AMPR_LIBKERNEL_HOOK_EXPORT int amprLibkernelHooksInstalled(void);

#if AMPR_EMU_LIBKERNEL_HOOK_DIAGNOSTICS
AMPR_LIBKERNEL_HOOK_EXPORT void amprFlushLibkernelHookLog(void);
AMPR_LIBKERNEL_HOOK_EXPORT int amprFormatLibkernelHookStatus(char* out, unsigned long long outSize);
#else
static inline void amprFlushLibkernelHookLog(void) {}
static inline int amprFormatLibkernelHookStatus(char*, unsigned long long) { return 0; }
#endif

/*
 * Resolve a real libkernel symbol without installing a detour. This is used for
 * optional SDK-newer helpers that the SDK 2.000 import set does not expose as
 * linkable static imports.
 */
AMPR_LIBKERNEL_HOOK_EXPORT void* amprResolveLibkernelFunction(const char* symbol);

extern AMPR_LIBKERNEL_HOOK_EXPORT void* g_amprOriginalLibkernelById[kAmprLibkernelHook_Count];

#ifdef __cplusplus
} // extern "C"
#endif
