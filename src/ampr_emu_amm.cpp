/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * AMM runtime, mapper helper, and AMM service implementation.
 */

#include "ampr_emu_amm.h"
#include "ampr_emu_kernel_amm.h"
#include "ampr_emu_kernel_lookup.h"
#include "ampr_emu_kernel_memory.h"
#include "ampr_emu_log.h"
#include "ampr_emu_runtime_memory.h"
#include "ampr_emu_sync.h"
#if AMPR_EMU_DEBUG_LOG && (AMPR_EMU_SUBMIT_COMMAND_BUFFER_DUMP & 1)
#include "ampr_emu_command_buffer_dump.h"
#endif
#include "ampr_emu_prot.h"

#include <atomic>

namespace {

using AmmGiveDirectMemoryToMapperFn = int (*)(off_t, off_t, size_t, size_t, int, off_t*);
using AmmCallIndirectBufferFn = int (*)(unsigned int, uint64_t, uint64_t);
using AmmCallIndirectBuffer2Fn = int (*)(unsigned int, uint64_t, uint64_t, SceAmmResultBuffer*, SceAmmSubmitId*);
using AmmCallIndirectBuffer3Fn = int (*)(unsigned int, uint64_t, uint64_t, SceAmmSubmitId*);
using AmmWaitCommandBufferCompletionFn = int (*)(SceAmmSubmitId);
using AmmWriteMapCommandFn = int (*)(void*, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t*);
using AmmWriteMapCommand2Fn = int (*)(void*, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t*);
using AmmWriteMapWithGpuMaskIdCommandFn = int (*)(void*, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t*);
using AmmWriteMapDirectCommandFn = int (*)(void*, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t*);
using AmmWriteMapDirectWithGpuMaskIdCommandFn = int (*)(void*, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t*);
using AmmWriteUnmapCommandFn = int (*)(void*, uint64_t, uint64_t, uint64_t*);
using AmmWriteRemapCommandFn = int (*)(void*, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t*);
using AmmWriteRemapWithGpuMaskIdCommandFn = int (*)(void*, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t*);
using AmmWriteMultiMapCommandFn = int (*)(void*, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t*);
using AmmWriteMultiMapWithGpuMaskIdCommandFn = int (*)(void*, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t*);
using AmmWriteModifyProtectCommandFn = int (*)(void*, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t*);
using AmmWriteModifyProtectWithGpuMaskIdCommandFn = int (*)(void*, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t*);
using AmmWriteModifyMtypeProtectCommandFn = int (*)(void*, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t*);
using AmmWriteModifyMtypeProtectWithGpuMaskIdCommandFn = int (*)(void*, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t*);

static constexpr int kAmmSubmitRetryRc = -2147352541;
static constexpr unsigned int kAmmSubmitRetrySleepUsec = 0xC8u;
static constexpr unsigned int kAmmSubmitMaxPriority = 2u;

static constexpr AmmGiveDirectMemoryToMapperFn kRealGiveDirectMemoryToMapper =
    static_cast<AmmGiveDirectMemoryToMapperFn>(&::sceKernelGiveDirectMemoryToMapper);
static constexpr AmmCallIndirectBufferFn kRealCallIndirectBuffer =
    static_cast<AmmCallIndirectBufferFn>(&::sceKernelCallIndirectBuffer);
static constexpr AmmCallIndirectBuffer2Fn kRealCallIndirectBuffer2 =
    static_cast<AmmCallIndirectBuffer2Fn>(&::sceKernelCallIndirectBuffer2);
static constexpr AmmWaitCommandBufferCompletionFn kRealWaitCommandBufferCompletion =
    static_cast<AmmWaitCommandBufferCompletionFn>(&::sceKernelWaitCommandBufferCompletion);
static constexpr AmmWriteUnmapCommandFn kRealWriteUnmapCommand =
    static_cast<AmmWriteUnmapCommandFn>(&::sceKernelWriteUnmapCommand);

template <typename Fn, typename... Args>
static inline int ampr_amm_call_writer(AmprLibkernelHookId hookId, Args... args) {
    return ampr_fixed_kernel_slot<Fn>(hookId)(args...);
}

static int ampr_kernel_write_map_command(void* dst,
                                         uint64_t va,
                                         uint64_t size,
                                         uint64_t type,
                                         uint64_t prot,
                                         uint64_t* outSize) {
    if (AmmWriteMapCommandFn fn =
            ampr_fixed_kernel_slot<AmmWriteMapCommandFn>(kAmprLibkernelHook_sceKernelWriteMapCommand)) {
        return fn(dst, va, size, type, prot, outSize);
    }
    return ampr_amm_call_writer<AmmWriteMapCommand2Fn>(kAmprLibkernelHook_sceKernelWriteMapCommand2,
                                                       dst,
                                                       va,
                                                       size,
                                                       type,
                                                       prot,
                                                       0,
                                                       outSize);
}

static int ampr_kernel_call_indirect_buffer3_compat(unsigned int priority,
                                                    uint64_t bufferBase,
                                                    uint64_t currentOffset,
                                                    SceAmmSubmitId* submitId) {
    static AmmCallIndirectBuffer3Fn cached =
        ampr_dynamic_kernel_func_or_null<AmmCallIndirectBuffer3Fn>("sceKernelCallIndirectBuffer3");
    if (AmmCallIndirectBuffer3Fn fn = cached) {
        return fn(priority, bufferBase, currentOffset, submitId);
    }
    (void)priority;
    (void)bufferBase;
    (void)currentOffset;
    (void)submitId;
    return SCE_KERNEL_ERROR_ENXIO;
}

static int amm_call_indirect_buffer_retry(unsigned int priority,
                                          uint64_t bufferBase,
                                          uint64_t currentOffset,
                                          uint32_t* retries) {
    uint32_t retryCount = 0;
    int rc = 0;
    for (;;) {
        rc = kRealCallIndirectBuffer(priority, bufferBase, currentOffset);
        if (rc != kAmmSubmitRetryRc) {
            break;
        }
        if (retryCount == 0) {
            AMPR_CRITICAL_LOGF("amm.leaf.submit.retry.first buffer=%p currentOffset=0x%llx prio=%u rc=0x%x",
                               (void*)(uintptr_t)bufferBase,
                               (unsigned long long)currentOffset,
                               priority,
                               rc);
        }
        ++retryCount;
        sceKernelUsleep(kAmmSubmitRetrySleepUsec);
    }
    if (retries) {
        *retries = retryCount;
    }
    return rc;
}

static int amm_call_indirect_buffer2_retry(unsigned int priority,
                                           uint64_t bufferBase,
                                           uint64_t currentOffset,
                                           SceAmmResultBuffer* result,
                                           SceAmmSubmitId* submitId,
                                           uint32_t* retries) {
    uint32_t retryCount = 0;
    int rc = 0;
    for (;;) {
        rc = kRealCallIndirectBuffer2(priority, bufferBase, currentOffset, result, submitId);
        if (rc != kAmmSubmitRetryRc) {
            break;
        }
        if (retryCount == 0) {
            AMPR_CRITICAL_LOGF("amm.leaf.submit.result.retry.first buffer=%p currentOffset=0x%llx prio=%u rc=0x%x res=%p id=%p sid=0x%x",
                               (void*)(uintptr_t)bufferBase,
                               (unsigned long long)currentOffset,
                               priority,
                               rc,
                               result,
                               submitId,
                               submitId ? *submitId : 0u);
        }
        ++retryCount;
        sceKernelUsleep(kAmmSubmitRetrySleepUsec);
    }
    if (retries) {
        *retries = retryCount;
    }
    return rc;
}

static int amm_call_indirect_buffer3_retry(unsigned int priority,
                                           uint64_t bufferBase,
                                           uint64_t currentOffset,
                                           SceAmmSubmitId* submitId,
                                           uint32_t* retries) {
    uint32_t retryCount = 0;
    int rc = 0;
    for (;;) {
        rc = ampr_kernel_call_indirect_buffer3_compat(priority, bufferBase, currentOffset, submitId);
        if (rc != kAmmSubmitRetryRc) {
            break;
        }
        if (retryCount == 0) {
            AMPR_CRITICAL_LOGF("amm.leaf.submit.id.retry.first buffer=%p currentOffset=0x%llx prio=%u rc=0x%x id=%p sid=0x%x",
                               (void*)(uintptr_t)bufferBase,
                               (unsigned long long)currentOffset,
                               priority,
                               rc,
                               submitId,
                               submitId ? *submitId : 0u);
        }
        ++retryCount;
        sceKernelUsleep(kAmmSubmitRetrySleepUsec);
    }
    if (retries) {
        *retries = retryCount;
    }
    return rc;
}

static int amm_validate_submit_args(uint64_t bufferBase, uint32_t priority) {
    if (priority > kAmmSubmitMaxPriority) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    if (bufferBase == 0) {
        return SCE_KERNEL_ERROR_EPERM;
    }
    return 0;
}

static int ampr_kernel_write_remap_into_prt_command(uint32_t* dst,
                                                    uint64_t va,
                                                    uint64_t remapVa,
                                                    uint64_t size,
                                                    int prot,
                                                    int opcode,
                                                    uint64_t* outSize) {
    using Fn = int (*)(uint32_t*, uint64_t, uint64_t, uint64_t, int, int, uint64_t*);
    if (Fn fn = ampr_fixed_kernel_slot<Fn>(kAmprLibkernelHook_sceKernelWriteRemapIntoPrtCommand)) {
        return fn(dst, va, remapVa, size, prot, opcode, outSize);
    }
    (void)dst;
    (void)va;
    (void)remapVa;
    (void)size;
    (void)prot;
    (void)opcode;
    (void)outSize;
    return SCE_KERNEL_ERROR_ENXIO;
}

static int ampr_kernel_write_unmap_to_prt_command(uint32_t* dst,
                                                  uint64_t va,
                                                  uint64_t size,
                                                  uint64_t* outSize) {
    using Fn = int (*)(uint32_t*, uint64_t, uint64_t, uint64_t*);
    static Fn cached = ampr_dynamic_kernel_func_or_null<Fn>("sceKernelWriteUnmapToPrtCommand");
    if (Fn fn = cached) {
        return fn(dst, va, size, outSize);
    }
    (void)dst;
    (void)va;
    (void)size;
    (void)outSize;
    return SCE_KERNEL_ERROR_ENXIO;
}

} // namespace

/*
 * libkernel direct-memory compatibility hooks.
 *
 * These are kept in the hook layer so Direct Memory budget queries can prepare
 * the emulator's static APR-visible pool before forwarding the real libkernel
 * result. The pool itself is PRX .bss storage and does not consume Direct
 * Memory.
 */
static uint64_t ampr_adjust_kernel_writer_prot_for_ampr_write(const char* op,
                                                              uint64_t va,
                                                              uint64_t size,
                                                              uint64_t arg,
                                                              uint64_t prot) {
    const uint64_t adjustedProt = sce::Ampr::Emu::protWithCpuRwForAmprWrite(prot);
    if (adjustedProt != prot) {
        AMPR_CRITICAL_LOGF("amm.kernel.prot.substitute op=%s va=0x%llx size=0x%llx arg=0x%llx prot=0x%llx adjustedProt=0x%llx",
                           op ? op : "?",
                           (unsigned long long)va,
                           (unsigned long long)size,
                           (unsigned long long)arg,
                           (unsigned long long)prot,
                           (unsigned long long)adjustedProt);
    }
    return adjustedProt;
}

static uint64_t ampr_adjust_kernel_writer_mask_for_adjusted_prot(const char* op,
                                                                 uint64_t va,
                                                                 uint64_t size,
                                                                 uint64_t arg,
                                                                 uint64_t prot,
                                                                 uint64_t adjustedProt,
                                                                 uint64_t protMask) {
    const uint64_t adjustedMask =
        sce::Ampr::Emu::protMaskWithCpuRwForAdjustedProt(prot, adjustedProt, protMask);
    if (adjustedMask != protMask) {
        AMPR_CRITICAL_LOGF("amm.kernel.prot.substitute op=%s va=0x%llx size=0x%llx arg=0x%llx prot=0x%llx adjustedProt=0x%llx",
                           op ? op : "?",
                           (unsigned long long)va,
                           (unsigned long long)size,
                           (unsigned long long)arg,
                           (unsigned long long)protMask,
                           (unsigned long long)adjustedMask);
    }
    return adjustedMask;
}

struct AmmAdjustedProtMask {
    uint64_t prot;
    uint64_t mask;
};

static inline AmmAdjustedProtMask ampr_adjust_kernel_writer_prot_mask_for_ampr_write(const char* protOp,
                                                                                     const char* maskOp,
                                                                                     uint64_t va,
                                                                                     uint64_t size,
                                                                                     uint64_t arg,
                                                                                     uint64_t prot,
                                                                                     uint64_t protMask) {
    const uint64_t adjustedProt =
        ampr_adjust_kernel_writer_prot_for_ampr_write(protOp, va, size, arg, prot);
    const uint64_t adjustedMask =
        ampr_adjust_kernel_writer_mask_for_adjusted_prot(maskOp, va, size, arg, prot, adjustedProt, protMask);
    return {adjustedProt, adjustedMask};
}

extern "C" size_t sceKernelGetDirectMemorySize_emul() {
    [[maybe_unused]] const bool poolReady =
        ampr_internal_amm_pool_prepare_static_storage("mem.direct.size");
    const size_t realSize = ampr_real_sceKernelGetDirectMemorySize();
    AMPR_TLOGF("mem.direct.size poolReady=%u real=0x%llx",
               poolReady ? 1u : 0u,
               (unsigned long long)realSize);
    return realSize;
}

extern "C" int sceKernelAvailableDirectMemorySize_emul(off_t searchStart,
                                                        off_t searchEnd,
                                                        size_t alignment,
                                                        off_t* physAddrOut,
                                                        size_t* sizeOut) {
    [[maybe_unused]] const bool poolReady =
        ampr_internal_amm_pool_prepare_static_storage("mem.direct.available");
    const int rc = ampr_real_sceKernelAvailableDirectMemorySize(searchStart,
                                                                searchEnd,
                                                                alignment,
                                                                physAddrOut,
                                                                sizeOut);
    AMPR_TLOGF("mem.direct.available poolReady=%u start=0x%llx end=0x%llx align=0x%llx rc=0x%x outStart=0x%llx outSize=0x%llx",
               poolReady ? 1u : 0u,
               (unsigned long long)searchStart,
               (unsigned long long)searchEnd,
               (unsigned long long)alignment,
               rc,
               (unsigned long long)((rc == 0 && physAddrOut) ? *physAddrOut : 0),
               (unsigned long long)((rc == 0 && sizeOut) ? *sizeOut : 0));
    return rc;
}

extern "C" int sceKernelWriteMapCommand_emul(void* dst,
                                              uint64_t va,
                                              uint64_t size,
                                              uint64_t type,
                                              uint64_t prot,
                                              uint64_t* outSize) {
    const uint64_t adjustedProt =
        ampr_adjust_kernel_writer_prot_for_ampr_write("WriteMap", va, size, type, prot);
    return ampr_kernel_write_map_command(dst, va, size, type, adjustedProt, outSize);
}

extern "C" int sceKernelWriteMapCommand2_emul(void* dst,
                                               uint64_t va,
                                               uint64_t size,
                                               uint64_t type,
                                               uint64_t prot,
                                               uint64_t prt,
                                               uint64_t* outSize) {
    const uint64_t adjustedProt = prt
        ? prot
        : ampr_adjust_kernel_writer_prot_for_ampr_write("WriteMap2", va, size, type, prot);
    return ampr_amm_call_writer<AmmWriteMapCommand2Fn>(kAmprLibkernelHook_sceKernelWriteMapCommand2,
                                                       dst,
                                                       va,
                                                       size,
                                                       type,
                                                       adjustedProt,
                                                       prt,
                                                       outSize);
}

extern "C" int sceKernelWriteMapWithGpuMaskIdCommand_emul(void* dst,
                                                           uint64_t va,
                                                           uint64_t size,
                                                           uint64_t type,
                                                           uint64_t prot,
                                                           uint64_t gpuMaskId,
                                                           uint64_t* outSize) {
    const uint64_t adjustedProt =
        ampr_adjust_kernel_writer_prot_for_ampr_write("WriteMapWithGpuMaskId", va, size, type, prot);
    return ampr_amm_call_writer<AmmWriteMapWithGpuMaskIdCommandFn>(
        kAmprLibkernelHook_sceKernelWriteMapWithGpuMaskIdCommand,
        dst,
        va,
        size,
        type,
        adjustedProt,
        gpuMaskId,
        outSize);
}

extern "C" int sceKernelWriteMapDirectCommand_emul(void* dst,
                                                    uint64_t va,
                                                    uint64_t dmemOffset,
                                                    uint64_t size,
                                                    uint64_t type,
                                                    uint64_t prot,
                                                    uint64_t* outSize) {
    const uint64_t adjustedProt =
        ampr_adjust_kernel_writer_prot_for_ampr_write("WriteMapDirect", va, size, type, prot);
    return ampr_amm_call_writer<AmmWriteMapDirectCommandFn>(kAmprLibkernelHook_sceKernelWriteMapDirectCommand,
                                                            dst,
                                                            va,
                                                            dmemOffset,
                                                            size,
                                                            type,
                                                            adjustedProt,
                                                            outSize);
}

extern "C" int sceKernelWriteMapDirectWithGpuMaskIdCommand_emul(void* dst,
                                                                 uint64_t va,
                                                                 uint64_t dmemOffset,
                                                                 uint64_t size,
                                                                 uint64_t type,
                                                                 uint64_t prot,
                                                                 uint64_t gpuMaskId,
                                                                 uint64_t* outSize) {
    const uint64_t adjustedProt =
        ampr_adjust_kernel_writer_prot_for_ampr_write("WriteMapDirectWithGpuMaskId", va, size, type, prot);
    return ampr_amm_call_writer<AmmWriteMapDirectWithGpuMaskIdCommandFn>(
        kAmprLibkernelHook_sceKernelWriteMapDirectWithGpuMaskIdCommand,
        dst,
        va,
        dmemOffset,
        size,
        type,
        adjustedProt,
        gpuMaskId,
        outSize);
}

extern "C" int sceKernelWriteRemapCommand_emul(void* dst,
                                                uint64_t vaNewStart,
                                                uint64_t vaOldStart,
                                                uint64_t size,
                                                uint64_t prot,
                                                uint64_t* outSize) {
    const uint64_t adjustedProt =
        ampr_adjust_kernel_writer_prot_for_ampr_write("WriteRemap", vaNewStart, size, vaOldStart, prot);
    return ampr_amm_call_writer<AmmWriteRemapCommandFn>(kAmprLibkernelHook_sceKernelWriteRemapCommand,
                                                        dst,
                                                        vaNewStart,
                                                        vaOldStart,
                                                        size,
                                                        adjustedProt,
                                                        outSize);
}

extern "C" int sceKernelWriteRemapWithGpuMaskIdCommand_emul(void* dst,
                                                             uint64_t vaNewStart,
                                                             uint64_t vaOldStart,
                                                             uint64_t size,
                                                             uint64_t prot,
                                                             uint64_t gpuMaskId,
                                                             uint64_t* outSize) {
    const uint64_t adjustedProt =
        ampr_adjust_kernel_writer_prot_for_ampr_write("WriteRemapWithGpuMaskId", vaNewStart, size, vaOldStart, prot);
    return ampr_amm_call_writer<AmmWriteRemapWithGpuMaskIdCommandFn>(
        kAmprLibkernelHook_sceKernelWriteRemapWithGpuMaskIdCommand,
        dst,
        vaNewStart,
        vaOldStart,
        size,
        adjustedProt,
        gpuMaskId,
        outSize);
}

extern "C" int sceKernelWriteMultiMapCommand_emul(void* dst,
                                                   uint64_t vaNewStart,
                                                   uint64_t vaAliasStart,
                                                   uint64_t size,
                                                   uint64_t prot,
                                                   uint64_t* outSize) {
    const uint64_t adjustedProt =
        ampr_adjust_kernel_writer_prot_for_ampr_write("WriteMultiMap", vaNewStart, size, vaAliasStart, prot);
    return ampr_amm_call_writer<AmmWriteMultiMapCommandFn>(kAmprLibkernelHook_sceKernelWriteMultiMapCommand,
                                                           dst,
                                                           vaNewStart,
                                                           vaAliasStart,
                                                           size,
                                                           adjustedProt,
                                                           outSize);
}

extern "C" int sceKernelWriteMultiMapWithGpuMaskIdCommand_emul(void* dst,
                                                                uint64_t vaNewStart,
                                                                uint64_t vaAliasStart,
                                                                uint64_t size,
                                                                uint64_t prot,
                                                                uint64_t gpuMaskId,
                                                                uint64_t* outSize) {
    const uint64_t adjustedProt =
        ampr_adjust_kernel_writer_prot_for_ampr_write("WriteMultiMapWithGpuMaskId", vaNewStart, size, vaAliasStart, prot);
    return ampr_amm_call_writer<AmmWriteMultiMapWithGpuMaskIdCommandFn>(
        kAmprLibkernelHook_sceKernelWriteMultiMapWithGpuMaskIdCommand,
        dst,
        vaNewStart,
        vaAliasStart,
        size,
        adjustedProt,
        gpuMaskId,
        outSize);
}

extern "C" int sceKernelWriteModifyProtectCommand_emul(void* dst,
                                                        uint64_t va,
                                                        uint64_t size,
                                                        uint64_t prot,
                                                        uint64_t protMask,
                                                        uint64_t* outSize) {
    const AmmAdjustedProtMask adjusted =
        ampr_adjust_kernel_writer_prot_mask_for_ampr_write("WriteModifyProtect",
                                                           "WriteModifyProtectMask",
                                                           va,
                                                           size,
                                                           0,
                                                           prot,
                                                           protMask);
    return ampr_amm_call_writer<AmmWriteModifyProtectCommandFn>(
        kAmprLibkernelHook_sceKernelWriteModifyProtectCommand,
        dst,
        va,
        size,
        adjusted.prot,
        adjusted.mask,
        outSize);
}

extern "C" int sceKernelWriteModifyProtectWithGpuMaskIdCommand_emul(void* dst,
                                                                     uint64_t va,
                                                                     uint64_t size,
                                                                     uint64_t prot,
                                                                     uint64_t protMask,
                                                                     uint64_t gpuMaskId,
                                                                     uint64_t* outSize) {
    const AmmAdjustedProtMask adjusted =
        ampr_adjust_kernel_writer_prot_mask_for_ampr_write("WriteModifyProtectWithGpuMaskId",
                                                           "WriteModifyProtectWithGpuMaskIdMask",
                                                           va,
                                                           size,
                                                           0,
                                                           prot,
                                                           protMask);
    return ampr_amm_call_writer<AmmWriteModifyProtectWithGpuMaskIdCommandFn>(
        kAmprLibkernelHook_sceKernelWriteModifyProtectWithGpuMaskIdCommand,
        dst,
        va,
        size,
        adjusted.prot,
        adjusted.mask,
        gpuMaskId,
        outSize);
}

extern "C" int sceKernelWriteModifyMtypeProtectCommand_emul(void* dst,
                                                             uint64_t va,
                                                             uint64_t size,
                                                             uint64_t type,
                                                             uint64_t prot,
                                                             uint64_t protMask,
                                                             uint64_t* outSize) {
    const AmmAdjustedProtMask adjusted =
        ampr_adjust_kernel_writer_prot_mask_for_ampr_write("WriteModifyMtypeProtect",
                                                           "WriteModifyMtypeProtectMask",
                                                           va,
                                                           size,
                                                           type,
                                                           prot,
                                                           protMask);
    return ampr_amm_call_writer<AmmWriteModifyMtypeProtectCommandFn>(
        kAmprLibkernelHook_sceKernelWriteModifyMtypeProtectCommand,
        dst,
        va,
        size,
        type,
        adjusted.prot,
        adjusted.mask,
        outSize);
}

extern "C" int sceKernelWriteModifyMtypeProtectWithGpuMaskIdCommand_emul(void* dst,
                                                                          uint64_t va,
                                                                          uint64_t size,
                                                                          uint64_t type,
                                                                          uint64_t prot,
                                                                          uint64_t protMask,
                                                                          uint64_t gpuMaskId,
                                                                          uint64_t* outSize) {
    const AmmAdjustedProtMask adjusted =
        ampr_adjust_kernel_writer_prot_mask_for_ampr_write("WriteModifyMtypeProtectWithGpuMaskId",
                                                           "WriteModifyMtypeProtectWithGpuMaskIdMask",
                                                           va,
                                                           size,
                                                           type,
                                                           prot,
                                                           protMask);
    return ampr_amm_call_writer<AmmWriteModifyMtypeProtectWithGpuMaskIdCommandFn>(
        kAmprLibkernelHook_sceKernelWriteModifyMtypeProtectWithGpuMaskIdCommand,
        dst,
        va,
        size,
        type,
        adjusted.prot,
        adjusted.mask,
        gpuMaskId,
        outSize);
}

extern "C" int sceKernelWriteRemapIntoPrtCommand_emul(uint32_t* dst,
                                                       uint64_t va,
                                                       uint64_t remapVa,
                                                       uint64_t size,
                                                       int prot,
                                                       int opcode,
                                                       uint64_t* outSize) {
    const uint64_t adjustedProt =
        ampr_adjust_kernel_writer_prot_for_ampr_write("WriteRemapIntoPrt", va, size, remapVa, static_cast<uint32_t>(prot));
    return ampr_kernel_write_remap_into_prt_command(dst, va, remapVa, size, static_cast<int>(adjustedProt), opcode, outSize);
}

namespace sce::Ampr::Emu {

uint32_t ammKernelProt(uint32_t prot) {
    return prot | ((prot >> 1) & 0x141u);
}

int ammWriteMapCommand2(void* dst,
                        uint64_t va,
                        uint64_t size,
                        uint64_t type,
                        uint64_t prot,
                        uint64_t prt,
                        uint64_t* outSize) {
    return ampr_amm_call_writer<AmmWriteMapCommand2Fn>(kAmprLibkernelHook_sceKernelWriteMapCommand2,
                                                       dst,
                                                       va,
                                                       size,
                                                       type,
                                                       prot,
                                                       prt,
                                                       outSize);
}

int ammWriteMapCommand(void* dst,
                       uint64_t va,
                       uint64_t size,
                       uint64_t type,
                       uint64_t prot,
                       uint64_t* outSize) {
    return ampr_kernel_write_map_command(dst, va, size, type, prot, outSize);
}

int ammWriteMapWithGpuMaskIdCommand(void* dst,
                                    uint64_t va,
                                    uint64_t size,
                                    uint64_t type,
                                    uint64_t prot,
                                    uint64_t gpuMaskId,
                                    uint64_t* outSize) {
    return ampr_amm_call_writer<AmmWriteMapWithGpuMaskIdCommandFn>(
        kAmprLibkernelHook_sceKernelWriteMapWithGpuMaskIdCommand,
        dst,
        va,
        size,
        type,
        prot,
        gpuMaskId,
        outSize);
}

int ammWriteMapDirectCommand(void* dst,
                             uint64_t va,
                             uint64_t dmemOffset,
                             uint64_t size,
                             uint64_t type,
                             uint64_t prot,
                             uint64_t* outSize) {
    return ampr_amm_call_writer<AmmWriteMapDirectCommandFn>(kAmprLibkernelHook_sceKernelWriteMapDirectCommand,
                                                            dst,
                                                            va,
                                                            dmemOffset,
                                                            size,
                                                            type,
                                                            prot,
                                                            outSize);
}

int ammWriteMapDirectWithGpuMaskIdCommand(void* dst,
                                          uint64_t va,
                                          uint64_t dmemOffset,
                                          uint64_t size,
                                          uint64_t type,
                                          uint64_t prot,
                                          uint64_t gpuMaskId,
                                          uint64_t* outSize) {
    return ampr_amm_call_writer<AmmWriteMapDirectWithGpuMaskIdCommandFn>(
        kAmprLibkernelHook_sceKernelWriteMapDirectWithGpuMaskIdCommand,
        dst,
        va,
        dmemOffset,
        size,
        type,
        prot,
        gpuMaskId,
        outSize);
}

int ammWriteUnmapCommand(void* dst, uint64_t va, uint64_t size, uint64_t* outSize) {
    return kRealWriteUnmapCommand(dst, va, size, outSize);
}

int ammWriteRemapCommand(void* dst,
                         uint64_t vaNewStart,
                         uint64_t vaOldStart,
                         uint64_t size,
                         uint64_t prot,
                         uint64_t* outSize) {
    return ampr_amm_call_writer<AmmWriteRemapCommandFn>(kAmprLibkernelHook_sceKernelWriteRemapCommand,
                                                        dst,
                                                        vaNewStart,
                                                        vaOldStart,
                                                        size,
                                                        prot,
                                                        outSize);
}

int ammWriteRemapWithGpuMaskIdCommand(void* dst,
                                      uint64_t vaNewStart,
                                      uint64_t vaOldStart,
                                      uint64_t size,
                                      uint64_t prot,
                                      uint64_t gpuMaskId,
                                      uint64_t* outSize) {
    return ampr_amm_call_writer<AmmWriteRemapWithGpuMaskIdCommandFn>(
        kAmprLibkernelHook_sceKernelWriteRemapWithGpuMaskIdCommand,
        dst,
        vaNewStart,
        vaOldStart,
        size,
        prot,
        gpuMaskId,
        outSize);
}

int ammWriteMultiMapCommand(void* dst,
                            uint64_t vaNewStart,
                            uint64_t vaAliasStart,
                            uint64_t size,
                            uint64_t prot,
                            uint64_t* outSize) {
    return ampr_amm_call_writer<AmmWriteMultiMapCommandFn>(kAmprLibkernelHook_sceKernelWriteMultiMapCommand,
                                                           dst,
                                                           vaNewStart,
                                                           vaAliasStart,
                                                           size,
                                                           prot,
                                                           outSize);
}

int ammWriteMultiMapWithGpuMaskIdCommand(void* dst,
                                         uint64_t vaNewStart,
                                         uint64_t vaAliasStart,
                                         uint64_t size,
                                         uint64_t prot,
                                         uint64_t gpuMaskId,
                                         uint64_t* outSize) {
    return ampr_amm_call_writer<AmmWriteMultiMapWithGpuMaskIdCommandFn>(
        kAmprLibkernelHook_sceKernelWriteMultiMapWithGpuMaskIdCommand,
        dst,
        vaNewStart,
        vaAliasStart,
        size,
        prot,
        gpuMaskId,
        outSize);
}

int ammWriteModifyProtectCommand(void* dst,
                                 uint64_t va,
                                 uint64_t size,
                                 uint64_t prot,
                                 uint64_t protMask,
                                 uint64_t* outSize) {
    return ampr_amm_call_writer<AmmWriteModifyProtectCommandFn>(
        kAmprLibkernelHook_sceKernelWriteModifyProtectCommand,
        dst,
        va,
        size,
        prot,
        protMask,
        outSize);
}

int ammWriteModifyProtectWithGpuMaskIdCommand(void* dst,
                                              uint64_t va,
                                              uint64_t size,
                                              uint64_t prot,
                                              uint64_t protMask,
                                              uint64_t gpuMaskId,
                                              uint64_t* outSize) {
    return ampr_amm_call_writer<AmmWriteModifyProtectWithGpuMaskIdCommandFn>(
        kAmprLibkernelHook_sceKernelWriteModifyProtectWithGpuMaskIdCommand,
        dst,
        va,
        size,
        prot,
        protMask,
        gpuMaskId,
        outSize);
}

int ammWriteModifyMtypeProtectCommand(void* dst,
                                      uint64_t va,
                                      uint64_t size,
                                      uint64_t type,
                                      uint64_t prot,
                                      uint64_t protMask,
                                      uint64_t* outSize) {
    return ampr_amm_call_writer<AmmWriteModifyMtypeProtectCommandFn>(
        kAmprLibkernelHook_sceKernelWriteModifyMtypeProtectCommand,
        dst,
        va,
        size,
        type,
        prot,
        protMask,
        outSize);
}

int ammWriteModifyMtypeProtectWithGpuMaskIdCommand(void* dst,
                                                   uint64_t va,
                                                   uint64_t size,
                                                   uint64_t type,
                                                   uint64_t prot,
                                                   uint64_t protMask,
                                                   uint64_t gpuMaskId,
                                                   uint64_t* outSize) {
    return ampr_amm_call_writer<AmmWriteModifyMtypeProtectWithGpuMaskIdCommandFn>(
        kAmprLibkernelHook_sceKernelWriteModifyMtypeProtectWithGpuMaskIdCommand,
        dst,
        va,
        size,
        type,
        prot,
        protMask,
        gpuMaskId,
        outSize);
}

int ammWriteRemapIntoPrtCommand(uint32_t* dst,
                                uint64_t va,
                                uint64_t remapVa,
                                uint64_t size,
                                int prot,
                                int opcode,
                                uint64_t* outSize) {
    return ampr_kernel_write_remap_into_prt_command(dst, va, remapVa, size, prot, opcode, outSize);
}

int ammWriteUnmapToPrtCommand(uint32_t* dst, uint64_t va, uint64_t size, uint64_t* outSize) {
    return ampr_kernel_write_unmap_to_prt_command(dst, va, size, outSize);
}

int mapperGetUsageStatsData(uint64_t* data) {
    return ampr_real_sceKernelMapperGetUsageStatsData(data);
}

int mapperSetPageTablePoolOccupancyNotificationThreshold(int threshold) {
    using Fn = int (*)(int);
    static Fn cached =
        ampr_dynamic_kernel_func_or_null<Fn>("sceKernelMapperSetPageTablePoolOccupancyNotificationThreshold");
    if (Fn fn = cached) {
        return fn(threshold);
    }
    (void)threshold;
    return SCE_KERNEL_ERROR_ENXIO;
}

} // namespace sce::Ampr::Emu

// ---------------- AMM service ----------------
namespace sce::Ampr::Emu {

int ammGetVirtualAddressRangesLeaf(uint64_t* vaStart,
                                   uint64_t* vaEnd,
                                   uint64_t* multimapVaStart,
                                   uint64_t* multimapVaEnd) {
    uint64_t params[7]{};
    params[0] = sizeof(params);
    const int rc = sceKernelMapperGetParam(params);
    AMPR_LOGF("amm.leaf.getVirtualAddressRanges.mapper rc=0x%x raw=[0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx]",
              rc,
              (unsigned long long)params[0],
              (unsigned long long)params[1],
              (unsigned long long)params[2],
              (unsigned long long)params[3],
              (unsigned long long)params[4],
              (unsigned long long)params[5],
              (unsigned long long)params[6]);
    if (rc != 0) {
        AMPR_KLOGF("ampr.abort reason=amm.leaf.getVirtualAddressRanges.mapper-failed rc=0x%x file=%s line=%d", rc, __FILE__, __LINE__);
        abort();
    }

    *vaStart = params[1];
    *vaEnd = params[2];
    *multimapVaStart = params[3];
    *multimapVaEnd = params[4];
    AMPR_LOGF("amm.leaf.getVirtualAddressRanges out=[%p,%p,%p,%p]",
              (void*)(uintptr_t)*vaStart,
              (void*)(uintptr_t)*vaEnd,
              (void*)(uintptr_t)*multimapVaStart,
              (void*)(uintptr_t)*multimapVaEnd);
    return 0;
}

static bool amm_trace_sample(std::atomic<uint64_t>& counter) {
#if AMPR_EMU_DEBUG_LOG
    if (!::ampr_debug_log_runtime_enabled()) {
        return false;
    }
    const uint64_t n = counter.fetch_add(1u, std::memory_order_relaxed) + 1u;
    return n <= 16u || (n & 0xfffu) == 0u;
#else
    (void)counter;
    return false;
#endif
}

#if AMPR_EMU_DEBUG_LOG && (AMPR_EMU_SUBMIT_COMMAND_BUFFER_DUMP & 1)
static uint64_t amm_next_dump_submit_id() {
    static std::atomic<uint64_t> s_dumpSubmitId{1};
    return s_dumpSubmitId.fetch_add(1u, std::memory_order_relaxed);
}

static void amm_dump_submit_command_buffers(uint64_t bufferBase,
                                            uint32_t currentOffset,
                                            uint32_t prio,
                                            uint64_t dumpSubmitId) {
    void* sourceBuffer = reinterpret_cast<void*>(static_cast<uintptr_t>(bufferBase));
    ampr_dump_decoded_command_buffer("amm",
                                     "source",
                                     dumpSubmitId,
                                     sourceBuffer,
                                     currentOffset,
                                     currentOffset,
                                     0,
                                     prio,
                                     0);
}
#endif

int ammSubmitCommandBufferAndGetResultLeaf(uint64_t bufferBase,
                                           uint32_t currentOffset,
                                           uint32_t prio,
                                           SceAmmResultBuffer* res,
                                           SceAmmSubmitId* id) {
    static std::atomic<uint64_t> s_submit2Calls{0};
    const bool trace = amm_trace_sample(s_submit2Calls);
    if (trace) {
        AMPR_LOGF("amm.leaf.submit enter buffer=%p currentOffset=0x%x prio=%u res=%p id=%p",
                  (void*)(uintptr_t)bufferBase,
                  currentOffset,
                  (unsigned)prio,
                  res,
                  id);
    }
    AMPR_TLOGF("amm.leaf.submit enter buffer=%p currentOffset=0x%x prio=%u res=%p id=%p",
              (void*)(uintptr_t)bufferBase,
              currentOffset,
              (unsigned)prio,
              res,
              id);

    const int validateRc = amm_validate_submit_args(bufferBase, prio);
    if (validateRc != 0) {
        return validateRc;
    }

#if AMPR_EMU_DEBUG_LOG && (AMPR_EMU_SUBMIT_COMMAND_BUFFER_DUMP & 1)
    if (::ampr_debug_log_runtime_enabled()) {
        amm_dump_submit_command_buffers(bufferBase,
                                        currentOffset,
                                        static_cast<uint32_t>(prio),
                                        amm_next_dump_submit_id());
    }
#endif

    uint32_t retries = 0;
    const int rc = amm_call_indirect_buffer2_retry((unsigned)prio,
                                                   bufferBase,
                                                   currentOffset,
                                                   res,
                                                   id,
                                                   &retries);

    AMPR_TLOGF("amm.leaf.submit leave buffer=%p currentOffset=0x%x rc=0x%x retries=%u res=%p idOut=%p sid=0x%x",
              (void*)(uintptr_t)bufferBase,
              currentOffset,
              rc,
              retries,
              res,
              id,
              id ? *id : 0u);
    if (trace) {
        AMPR_LOGF("amm.leaf.submit leave buffer=%p currentOffset=0x%x rc=0x%x retries=%u res=%p idOut=%p sid=0x%x",
                  (void*)(uintptr_t)bufferBase,
                  currentOffset,
                  rc,
                  retries,
                  res,
                  id,
                  id ? *id : 0u);
    } else if (retries != 0) {
        AMPR_CRITICAL_LOGF("amm.leaf.submit.retry buffer=%p currentOffset=0x%x prio=%u retries=%u rc=0x%x sid=0x%x",
                           (void*)(uintptr_t)bufferBase,
                           currentOffset,
                           (unsigned)prio,
                           retries,
                           rc,
                           id ? *id : 0u);
    }
    return rc;
}

int ammSubmitCommandBufferLeaf(uint64_t bufferBase,
                               uint32_t currentOffset,
                               uint32_t prio,
                               SceAmmSubmitId* id) {
    static std::atomic<uint64_t> s_submitCalls{0};
    const bool trace = amm_trace_sample(s_submitCalls);
    if (trace) {
        AMPR_LOGF("amm.leaf.submit.id enter buffer=%p currentOffset=0x%x prio=%u id=%p",
                  (void*)(uintptr_t)bufferBase,
                  currentOffset,
                  (unsigned)prio,
                  id);
    }
    AMPR_TLOGF("amm.leaf.submit.id enter buffer=%p currentOffset=0x%x prio=%u id=%p",
              (void*)(uintptr_t)bufferBase,
              currentOffset,
              (unsigned)prio,
              id);

    const int validateRc = amm_validate_submit_args(bufferBase, prio);
    if (validateRc != 0) {
        return validateRc;
    }

#if AMPR_EMU_DEBUG_LOG && (AMPR_EMU_SUBMIT_COMMAND_BUFFER_DUMP & 1)
    if (::ampr_debug_log_runtime_enabled()) {
        amm_dump_submit_command_buffers(bufferBase,
                                        currentOffset,
                                        static_cast<uint32_t>(prio),
                                        amm_next_dump_submit_id());
    }
#endif

    uint32_t retries = 0;
    const int rc = id
        ? amm_call_indirect_buffer3_retry((unsigned)prio, bufferBase, currentOffset, id, &retries)
        : amm_call_indirect_buffer_retry((unsigned)prio, bufferBase, currentOffset, &retries);

    AMPR_TLOGF("amm.leaf.submit.id leave buffer=%p currentOffset=0x%x rc=0x%x retries=%u id=%p sid=0x%x",
              (void*)(uintptr_t)bufferBase,
              currentOffset,
              rc,
              retries,
              id,
              id ? *id : 0u);
    if (trace) {
        AMPR_LOGF("amm.leaf.submit.id leave buffer=%p currentOffset=0x%x rc=0x%x retries=%u id=%p sid=0x%x",
                  (void*)(uintptr_t)bufferBase,
                  currentOffset,
                  rc,
                  retries,
                  id,
                  id ? *id : 0u);
    } else if (retries != 0) {
        AMPR_CRITICAL_LOGF("amm.leaf.submit.id.retry buffer=%p currentOffset=0x%x prio=%u retries=%u rc=0x%x sid=0x%x",
                           (void*)(uintptr_t)bufferBase,
                           currentOffset,
                           (unsigned)prio,
                           retries,
                           rc,
                           id ? *id : 0u);
    }
    return rc;
}

int ammGiveDirectMemory(off_t searchStart, off_t searchEnd, size_t size, size_t align, int usage, off_t* dmemOffset) {
    AMPR_LOGF("amm.giveDirectMemory start=0x%llx end=0x%llx size=0x%llx align=0x%llx usage=%u out=%p",
              (unsigned long long)searchStart, (unsigned long long)searchEnd,
              (unsigned long long)size, (unsigned long long)align, (unsigned)usage, dmemOffset);
    const int rc = kRealGiveDirectMemoryToMapper(searchStart, searchEnd, size, align, usage, dmemOffset);
    AMPR_LOGF("amm.giveDirectMemory rc=0x%x outOff=0x%llx adjusted=%u realStart=0x%llx realEnd=0x%llx realSize=0x%llx",
              rc,
              (unsigned long long)((rc == 0 && dmemOffset) ? *dmemOffset : 0),
              0u,
              (unsigned long long)searchStart,
              (unsigned long long)searchEnd,
              (unsigned long long)size);
    return rc;
}


int ammWaitCommandBufferCompletion(SceAmmSubmitId id) {
    static std::atomic<uint64_t> s_waitCalls{0};
    const bool trace = amm_trace_sample(s_waitCalls);
    if (trace) {
        AMPR_LOGF("amm.wait submitId=0x%llx", (unsigned long long)id);
    }
    AMPR_TLOGF("amm.wait submitId=0x%llx", (unsigned long long)id);
    if (trace) {
        AMPR_LOGF("amm.wait submitId=0x%llx action=kernel-wait",
                  (unsigned long long)id);
    }
    const int rc = kRealWaitCommandBufferCompletion(id);
    AMPR_TLOGF("amm.wait submitId=0x%llx rc=0x%x", (unsigned long long)id, rc);
    if (trace) {
        AMPR_LOGF("amm.wait submitId=0x%llx rc=0x%x", (unsigned long long)id, rc);
    }
    return rc;
}

} // namespace sce::Ampr::Emu
