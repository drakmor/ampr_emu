/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

// C exports for the emulated libSceAmpr PRX.
#include <cstdarg>
#include <cstdio>
#include <cstdint>
#include <cstddef>
#include <new>
#include "ampr.h"
#include "ampr_emu_config.h"
#include "ampr_debug_log.h"
#include "ampr_emu_extra.h"
#include "ampr_emu_amm.h"
#include "ampr_emu_apr_reactor.h"
#include "ampr_emu_command_buffer_types.h"
#include "ampr_emu_measure_commands.h"
#include "ampr_libkernel_hook.h"

using u64 = uint64_t;

extern "C" {
int module_start(size_t args, const void* argp) {
    (void)args;
    (void)argp;
    return amprInstallLibkernelHooks();
}

int module_stop(size_t args, const void* argp) {
    (void)args;
    (void)argp;
    const int reactorRc = apr_reactor_shutdown();
    if (reactorRc != 0) {
        return -1;
    }
    const int rc = amprUninstallLibkernelHooks();
    sce::Ampr::Emu::shutdownDebugLog();
    return rc;
}
}

namespace sce::Ampr::Emu {
int aprValidateMapBeginArgs(uint64_t va, uint64_t size, int type, int prot);
int aprValidateMapDirectBeginArgs(uint64_t va, uint64_t dmemOffset, uint64_t size, int type, int prot);
}

/*
 * Export-layer ABI documentation
 * ------------------------------
 *
 * This file is the public PRX surface. The exported symbols use the narrowest
 * confirmed ABI signature from the SDK headers and retail reference dumps.
 * Earlier revisions kept defensive `u64 a1..a8` placeholders on most exports;
 * that made review harder and hid real argument order. Keep raw/placeholder
 * names only when an older wrapper variant has no confirmed semantic name.
 *
 * Common parameter convention:
 *   - `self` is normally `this` for command-buffer member functions.
 *   - Additional parameters follow the SysV/Prospero integer-register order.
 *   - Return values are narrowed with ampr_export_rc32() when retail returns a
 *     32-bit SDK error code in a 64-bit register.
 *
 * Function groups:
 *   - sceAmprCommandBuffer* maintains the shared command-buffer header:
 *     backing buffer pointer, byte size, current write offset, command count,
 *     and type marker. These functions only describe command records; execution
 *     happens later through AMM/APR submit paths.
 *   - sceAmprAmmCommandBuffer* appends retail AMM command records by delegating
 *     packing/measurement to SDK/libkernel writer helpers when possible. Submit
 *     exports forward the already packed indirect buffer to the kernel mapper.
 *   - sceAmprAprCommandBuffer* appends APR read/map/scatter-gather records.
 *     APR execution is emulated in src/ampr_emu_core.cpp through SDK AIO and
 *     the APR index; the export layer only validates retail argument ranges
 *     and records the requested operation.
 *   - sceAmprMeasure* mirrors the SDK static-wrapper measurements. They return
 *     the number of command bytes a corresponding append function would emit.
 *   - `_04_00` names preserve legacy ABI variants observed in older SDK/static
 *     wrappers. They are not aliases when the older ABI carries extra mode or
 *     width bits, so do not collapse them without checking the reference dumps.
 */

#if AMPR_EMU_DEBUG_LOG
[[maybe_unused]] static inline void ampr_export_log(const char* s) {
    sce::Ampr::Emu::debugLogLine(s);
}

[[maybe_unused]] static inline void ampr_export_logf(const char* fmt, ...) {
    if (!fmt || !*fmt || !sce::Ampr::Emu::getDebugLogEnabled()) {
        return;
    }
    char buf[640]{};
    va_list args;
    va_start(args, fmt);
    (void)::vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    ampr_export_log(buf);
}
#else
#define ampr_export_log(s) ((void)0)
#define ampr_export_logf(...) ((void)0)
#endif

#if AMPR_EMU_DEBUG_LOG && AMPR_EMU_DEBUG_LOG_TRACE
#define ampr_export_vlogf(...) ampr_export_logf(__VA_ARGS__)
#else
#define ampr_export_vlogf(...) ((void)0)
#endif

#if AMPR_EMU_DEBUG_LOG && AMPR_EMU_DEBUG_LOG_TRACE
#define ampr_export_tlogf(...) ampr_export_logf(__VA_ARGS__)
#else
#define ampr_export_tlogf(...) ((void)0)
#endif

static inline void ampr_flush_hook_log_from_export() {
    amprFlushLibkernelHookLog();
}

static inline int64_t ampr_export_rc32(int64_t rc) {
    return static_cast<int64_t>(static_cast<uint32_t>(rc));
}

#define AMPR_EXPORT __declspec(dllexport)
#include <cstring>

static inline uint64_t ampr_marker_size(unsigned int n5, const char *a2) {
    // computes marker command size in uint32 words.
    int v2 = (int)std::strlen(a2) + 1;
    int v3 = 4 * (n5 < 5) + 56;
    int v4 = 1 - ((int)(n5 < 5) - 1);
    if (v2 <= v3) {
        return (uint64_t)(v4 + (unsigned int)(((uint64_t)(v2 + 3)) >> 2));
    }
    uint64_t result = (unsigned int)(v3 >> 2) + (unsigned int)v4;
    bool v6 = v2 <= v3;
    for (unsigned int i = (unsigned int)(v2 - v3); !v6; ) {
        int n60 = 60;
        if (i < 0x3C) n60 = (int)i;
        v6 = (int)i <= n60;
        result = (unsigned int)result + ((unsigned int)(n60 + 3) >> 2) + 1;
        i -= (unsigned int)n60;
    }
    return result;
}

static inline int64_t ampr_measure_marker_bytes(unsigned int n5, const char *msg) {
    if (!msg) return ampr_export_rc32(SCE_KERNEL_ERROR_EINVAL);
    return (int64_t)(4 * ampr_marker_size(n5, msg));
}

static constexpr uint64_t kAmprRefVaMin = 0ull;
static constexpr uint64_t kAmprRefVaMax = 0xF00000000000ull;
static constexpr uint64_t kAmprRefAprReadMax = 0x100000000ull;
static constexpr uint64_t kAmprRefAprOffsetMax = 0x10000000000ull;

static inline int64_t ampr_ref_validate_user_range(uint64_t buffer, uint64_t length) {
    if (length == 0 || length > kAmprRefAprReadMax) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    if (buffer < kAmprRefVaMin || buffer > kAmprRefVaMax || length > (kAmprRefVaMax - buffer)) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    return 0;
}

static inline bool ampr_ref_valid_wait_address(uint64_t address) {
    return (address & 7ull) == 0ull &&
           address <= kAmprRefVaMax &&
           8ull <= (kAmprRefVaMax - address);
}

static inline bool ampr_ref_valid_write_address(uint64_t address) {
    return address != 0ull && ampr_ref_valid_wait_address(address);
}

static inline int64_t ampr_ref_validate_wait_address_04_00(uint64_t address, uint32_t compare, uint32_t flush) {
    if (address == 0 || !ampr_ref_valid_wait_address(address) || compare >= 7u || flush >= 2u) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    return 0;
}

static inline int64_t ampr_ref_validate_wait_address(uint64_t address, uint32_t compare, uint32_t flush) {
    if (!ampr_ref_valid_wait_address(address) || compare >= 4u || flush >= 2u) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    return 0;
}

static inline int64_t ampr_ref_validate_wait_counter_04_00(uint32_t valueWidth,
                                                           uint32_t compare,
                                                           uint32_t extraFlag,
                                                           uint32_t flush) {
    if (valueWidth >= 8u || compare >= 7u || extraFlag >= 2u || flush >= 2u) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    return 0;
}

static inline int64_t ampr_ref_validate_wait_counter(uint32_t counterIndex, uint32_t compare, uint32_t flush) {
    if (counterIndex >= 0x80u || compare >= 4u || flush >= 2u) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    return 0;
}

static inline int64_t ampr_ref_validate_write_address(uint64_t address, uint32_t mode, uint64_t value) {
    if (!ampr_ref_valid_write_address(address)) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    switch (mode) {
        case 0u:
            return 0;
        case 1u:
            return value == 0 ? 0 : SCE_KERNEL_ERROR_EINVAL;
        case 2u:
            return value < 0x100ull ? 0 : SCE_KERNEL_ERROR_EINVAL;
        case 3u:
            return (value < 0x100ull && (value & 1ull) == 0ull) ? 0 : SCE_KERNEL_ERROR_EINVAL;
        default:
            return SCE_KERNEL_ERROR_EINVAL;
    }
}

static inline int64_t ampr_ref_validate_write_counter_04_00(uint32_t counterIndex,
                                                            uint32_t valueWidth,
                                                            uint32_t counterMode) {
    if (counterIndex >= 0x80u || valueWidth >= 8u || counterMode >= 5u) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    return 0;
}

static inline int64_t ampr_ref_validate_write_counter(uint32_t counterIndex) {
    return counterIndex < 0x80u ? 0 : SCE_KERNEL_ERROR_EINVAL;
}

static inline int64_t ampr_ref_validate_nop_measure(uint32_t numU32) {
    return (numU32 >= 1u && numU32 <= 16u) ? 0 : SCE_KERNEL_ERROR_EINVAL;
}

static inline int64_t ampr_ref_validate_read_file(uint64_t buffer,
                                                  int64_t length,
                                                  uint32_t fileId,
                                                  uint64_t offset) {
    (void)fileId;
    int64_t rc = ampr_ref_validate_user_range(buffer, (uint64_t)length);
    if (rc != 0) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    if (offset >= kAmprRefAprOffsetMax) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    return 0;
}

static inline int64_t ampr_ref_validate_read_file_gather(int64_t length, uint64_t offset) {
    if (length <= 0 || (uint64_t)length > kAmprRefAprReadMax) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    if (offset >= kAmprRefAprOffsetMax) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    return 0;
}

static inline int64_t ampr_ref_validate_read_file_scatter(uint64_t buffer, int64_t length) {
    return ampr_ref_validate_user_range(buffer, (uint64_t)length);
}

static inline int64_t ampr_ref_validate_read_file_gather_scatter(uint64_t buffer,
                                                                 int64_t length,
                                                                 uint64_t offset) {
    int64_t rc = ampr_ref_validate_user_range(buffer, (uint64_t)length);
    if (rc != 0) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    if (offset >= kAmprRefAprOffsetMax) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    return 0;
}

extern "C" AMPR_EXPORT int64_t sceAmprAmmCommandBufferConstructor(sce::Ampr::AmmCommandBuffer* self) {
    ampr_export_vlogf("exp.amm.cb.ctor this=%p no-op-derived-init", (void*)self);
    return 0;
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmCommandBufferDestructor(sce::Ampr::AmmCommandBuffer* self) {
    ampr_export_vlogf("exp.amm.cb.dtor this=%p no-op-derived-dtor", (void*)self);
    return 0;
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmCommandBufferMap(sce::Ampr::AmmCommandBuffer* self, uint64_t va, uint64_t size, int type, int prot) {
    return ampr_export_rc32(self->map(va, size, type, prot));
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmCommandBufferMapWithGpuMaskId(sce::Ampr::AmmCommandBuffer* self, uint64_t va, uint64_t size, int type, int prot, uint8_t gpuMaskId) {
    return ampr_export_rc32(self->mapWithGpuMaskId(va, size, type, prot, gpuMaskId));
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmCommandBufferMapDirect(sce::Ampr::AmmCommandBuffer* self, uint64_t va, uint64_t dmemOffset, size_t size, int type, int prot) {
    return ampr_export_rc32(self->mapDirect(va, dmemOffset, size, type, prot));
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmCommandBufferMapDirectWithGpuMaskId(sce::Ampr::AmmCommandBuffer* self, uint64_t va, uint64_t dmemOffset, uint64_t size, int type, int prot, uint8_t gpuMaskId) {
    return ampr_export_rc32(self->mapDirectWithGpuMaskId(va, dmemOffset, size, type, prot, gpuMaskId));
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmCommandBufferUnmap(sce::Ampr::AmmCommandBuffer* self, uint64_t va, size_t size) {
    return ampr_export_rc32(self->unmap(va, size));
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmCommandBufferRemap(sce::Ampr::AmmCommandBuffer* self, uint64_t vaNewStart, uint64_t vaOldStart, uint64_t vaSize, int prot) {
    return ampr_export_rc32(self->remap(vaNewStart, vaOldStart, vaSize, prot));
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmCommandBufferRemapWithGpuMaskId(sce::Ampr::AmmCommandBuffer* self, uint64_t vaNewStart, uint64_t vaOldStart, uint64_t vaSize, int prot, uint8_t gpuMaskId) {
    return ampr_export_rc32(self->remapWithGpuMaskId(vaNewStart, vaOldStart, vaSize, prot, gpuMaskId));
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmCommandBufferMultiMap(sce::Ampr::AmmCommandBuffer* self, uint64_t vaStart, uint64_t vaAliasStart, uint64_t vaSize, int prot) {
    return ampr_export_rc32(self->multiMap(vaStart, vaAliasStart, vaSize, prot));
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmCommandBufferMultiMapWithGpuMaskId(sce::Ampr::AmmCommandBuffer* self, uint64_t vaStart, uint64_t vaAliasStart, uint64_t vaSize, int prot, uint8_t gpuMaskId) {
    return ampr_export_rc32(self->multiMapWithGpuMaskId(vaStart, vaAliasStart, vaSize, prot, gpuMaskId));
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmCommandBufferModifyProtect(sce::Ampr::AmmCommandBuffer* self, uint64_t va, uint64_t size, int prot, int protMask) {
    return ampr_export_rc32(self->modifyProtect(va, size, prot, protMask));
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmCommandBufferModifyProtectWithGpuMaskId(sce::Ampr::AmmCommandBuffer* self, uint64_t va, uint64_t size, int prot, int protMask, uint8_t gpuMaskId) {
    return ampr_export_rc32(self->modifyProtectWithGpuMaskId(va, size, prot, protMask, gpuMaskId));
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmCommandBufferModifyMtypeProtect(sce::Ampr::AmmCommandBuffer* self, uint64_t va, uint64_t size, int type, int prot, int protMask) {
    return ampr_export_rc32(self->modifyMtypeProtect(va, size, type, prot, protMask));
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmCommandBufferModifyMtypeProtectWithGpuMaskId(sce::Ampr::AmmCommandBuffer* self, uint64_t va, uint64_t size, int type, int prot, int protMask, uint8_t gpuMaskId) {
    return ampr_export_rc32(self->modifyMtypeProtectWithGpuMaskId(va, size, type, prot, protMask, gpuMaskId));
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmCommandBufferMapAsPrt(sce::Ampr::AmmCommandBuffer* self, uint64_t va, uint64_t size) {
    return ampr_export_rc32(self->mapAsPrt(va, size));
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmCommandBufferAllocatePaForPrt(sce::Ampr::AmmCommandBuffer* self, uint64_t va, uint64_t size, int type, int prot) {
    return ampr_export_rc32(self->allocatePaForPrt(va, size, type, prot));
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmCommandBufferRemapIntoPrt(sce::Ampr::AmmCommandBuffer* self, uint64_t vaPrtStart, uint64_t vaOldStart, uint64_t size, int prot, uint32_t opcode) {
    return ampr_export_rc32(self->remapIntoPrt(vaPrtStart, vaOldStart, size, prot, opcode));
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmCommandBufferUnmapToPrt(sce::Ampr::AmmCommandBuffer* self, uint64_t va, uint64_t size) {
    return ampr_export_rc32(self->unmapToPrt(va, size));
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmGetVirtualAddressRanges(uint64_t* vaStart,
                                                                 uint64_t* vaEnd,
                                                                 uint64_t* multimapVaStart,
                                                                 uint64_t* multimapVaEnd) {
    ampr_export_vlogf("exp.amm.vaRanges out0=%p out1=%p out2=%p out3=%p",
                     (void*)vaStart, (void*)vaEnd, (void*)multimapVaStart, (void*)multimapVaEnd);
    const int64_t rc = sce::Ampr::Emu::ammGetVirtualAddressRangesLeaf(
        vaStart,
        vaEnd,
        multimapVaStart,
        multimapVaEnd);
    const int64_t outRc = ampr_export_rc32(rc);
    ampr_export_vlogf("exp.amm.vaRanges leave rc=0x%llx v0=0x%llx v1=0x%llx v2=0x%llx v3=0x%llx",
                     (unsigned long long)outRc,
                     vaStart ? *vaStart : 0ull,
                     vaEnd ? *vaEnd : 0ull,
                     multimapVaStart ? *multimapVaStart : 0ull,
                     multimapVaEnd ? *multimapVaEnd : 0ull);
    return outRc;
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmGiveDirectMemory(off_t searchStart,
                                                          off_t searchEnd,
                                                          size_t size,
                                                          size_t alignment,
                                                          int usage,
                                                          off_t* dmemOffset) {
    return ampr_export_rc32(sce::Ampr::Emu::ammGiveDirectMemory(searchStart, searchEnd, size, alignment, usage, dmemOffset));
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmSubmitCommandBuffer(uint64_t bufferBase,
                                                             uint32_t currentOffset,
                                                             uint32_t priority) {
    ampr_export_vlogf("exp.amm.submit1 buffer=%p currentOffset=0x%x prio=%u",
                     (void*)bufferBase, (unsigned)currentOffset, (unsigned)priority);
    const int64_t rc = sce::Ampr::Emu::ammSubmitCommandBufferLeaf(
        bufferBase,
        currentOffset,
        priority,
        nullptr);
    const int64_t outRc = ampr_export_rc32(rc);
    ampr_export_vlogf("exp.amm.submit1 leave buffer=%p currentOffset=0x%x prio=%u rc=0x%llx",
                     (void*)bufferBase, (unsigned)currentOffset, (unsigned)priority, (unsigned long long)outRc);
    return outRc;
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmSubmitCommandBuffer2(uint64_t bufferBase,
                                                              uint32_t currentOffset,
                                                              uint32_t priority,
                                                              SceAmmResultBuffer* result,
                                                              SceAmmSubmitId* submitId) {
    // SDK 2.000 wrapper calls:
    //   sceAmprAmmSubmitCommandBuffer2(bufferBase, currentOffset, prio, resultPtr, submitIdPtr)
    ampr_export_vlogf("exp.amm.submit2 buffer=%p currentOffset=0x%x prio=%u res=%p outId=%p",
                     (void*)bufferBase, (unsigned)currentOffset, (unsigned)priority, (void*)result, (void*)submitId);
    const int64_t rc = sce::Ampr::Emu::ammSubmitCommandBufferAndGetResultLeaf(
        bufferBase,
        currentOffset,
        priority,
        result,
        submitId);
    const int64_t outRc = ampr_export_rc32(rc);
    ampr_export_vlogf("exp.amm.submit2 leave buffer=%p currentOffset=0x%x rc=0x%llx result=0x%x errorOffset=0x%x submitId=0x%x",
                     (void*)bufferBase,
                     (unsigned)currentOffset,
                     (unsigned long long)outRc,
                     result ? result->result : 0,
                     result ? result->errorOffset : 0u,
                     submitId ? *submitId : 0u);
    return outRc;
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmSubmitCommandBuffer3(uint64_t bufferBase,
                                                              uint32_t currentOffset,
                                                              uint32_t priority,
                                                              SceAmmSubmitId* submitId) {
    // SDK 2.000 wrapper calls:
    //   sceAmprAmmSubmitCommandBuffer3(bufferBase, currentOffset, prio, submitIdPtr)
    ampr_export_vlogf("exp.amm.submit3 buffer=%p currentOffset=0x%x prio=%u outId=%p",
                     (void*)bufferBase, (unsigned)currentOffset, (unsigned)priority, (void*)submitId);
    const int64_t rc = sce::Ampr::Emu::ammSubmitCommandBufferLeaf(
        bufferBase,
        currentOffset,
        priority,
        submitId);
    const int64_t outRc = ampr_export_rc32(rc);
    ampr_export_vlogf("exp.amm.submit3 leave buffer=%p currentOffset=0x%x rc=0x%llx submitId=0x%x",
                     (void*)bufferBase,
                     (unsigned)currentOffset,
                     (unsigned long long)outRc,
                     submitId ? *submitId : 0u);
    return outRc;
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmWaitCommandBufferCompletion(SceAmmSubmitId submitId) {
    ampr_export_vlogf("exp.amm.wait submitId=0x%x", (unsigned)submitId);
    const int64_t rc = sce::Ampr::Emu::ammWaitCommandBufferCompletion(submitId);
    const int64_t outRc = ampr_export_rc32(rc);
    ampr_export_vlogf("exp.amm.wait leave submitId=0x%x rc=0x%llx", (unsigned)submitId, (unsigned long long)outRc);
    return outRc;
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmGetUsageStatsData(uint64_t* usageStatsData) {
    return ampr_export_rc32(sce::Ampr::Emu::mapperGetUsageStatsData(usageStatsData));
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmSetPageTablePoolOccupancyNotificationThreshold(int threshold) {
    return ampr_export_rc32(sce::Ampr::Emu::mapperSetPageTablePoolOccupancyNotificationThreshold(threshold));
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmMeasureAmmCommandSizeMap(uint64_t va, uint64_t size, int type, int prot) {
    return (int64_t)sce::Ampr::Emu::measureAmmMap(va, size, type, prot);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmMeasureAmmCommandSizeMapDirect(uint64_t va, uint64_t dmemOffset, size_t size, int type, int prot) {
    return (int64_t)sce::Ampr::Emu::measureAmmMapDirect(va, dmemOffset, size, type, prot);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmMeasureAmmCommandSizeMapWithGpuMaskId(uint64_t va, uint64_t size, int type, int prot, uint8_t gpuMaskId) {
    return (int64_t)sce::Ampr::Emu::measureAmmMapWithGpuMaskId(va, size, type, prot, gpuMaskId);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmMeasureAmmCommandSizeMapDirectWithGpuMaskId(uint64_t va, uint64_t dmemOffset, uint64_t size, int type, int prot, uint8_t gpuMaskId) {
    return (int64_t)sce::Ampr::Emu::measureAmmMapDirectWithGpuMaskId(va, dmemOffset, size, type, prot, gpuMaskId);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmMeasureAmmCommandSizeUnmap(uint64_t va, size_t size) {
    return (int64_t)sce::Ampr::Emu::measureAmmUnmap(va, size);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmMeasureAmmCommandSizeRemap(uint64_t vaNewStart, uint64_t vaOldStart, uint64_t vaSize, int prot) {
    return (int64_t)sce::Ampr::Emu::measureAmmRemap(vaNewStart, vaOldStart, vaSize, prot);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmMeasureAmmCommandSizeRemapWithGpuMaskId(uint64_t vaNewStart, uint64_t vaOldStart, uint64_t vaSize, int prot, uint8_t gpuMaskId) {
    return (int64_t)sce::Ampr::Emu::measureAmmRemapWithGpuMaskId(vaNewStart, vaOldStart, vaSize, prot, gpuMaskId);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmMeasureAmmCommandSizeMultiMap(uint64_t vaStart, uint64_t vaAliasStart, uint64_t vaSize, int prot) {
    return (int64_t)sce::Ampr::Emu::measureAmmMultiMap(vaStart, vaAliasStart, vaSize, prot);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmMeasureAmmCommandSizeMultiMapWithGpuMaskId(uint64_t vaStart, uint64_t vaAliasStart, uint64_t vaSize, int prot, uint8_t gpuMaskId) {
    return (int64_t)sce::Ampr::Emu::measureAmmMultiMapWithGpuMaskId(vaStart, vaAliasStart, vaSize, prot, gpuMaskId);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmMeasureAmmCommandSizeModifyProtect(uint64_t va, uint64_t size, int prot, int protMask) {
    return (int64_t)sce::Ampr::Emu::measureAmmModifyProtect(va, size, prot, protMask);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmMeasureAmmCommandSizeModifyMtypeProtect(uint64_t va, uint64_t size, int type, int prot, int protMask) {
    return (int64_t)sce::Ampr::Emu::measureAmmModifyMtypeProtect(va, size, type, prot, protMask);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmMeasureAmmCommandSizeModifyProtectWithGpuMaskId(uint64_t va, uint64_t size, int prot, int protMask, uint8_t gpuMaskId) {
    return (int64_t)sce::Ampr::Emu::measureAmmModifyProtectWithGpuMaskId(va, size, prot, protMask, gpuMaskId);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmMeasureAmmCommandSizeModifyMtypeProtectWithGpuMaskId(uint64_t va, uint64_t size, int type, int prot, int protMask, uint8_t gpuMaskId) {
    return (int64_t)sce::Ampr::Emu::measureAmmModifyMtypeProtectWithGpuMaskId(va, size, type, prot, protMask, gpuMaskId);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmMeasureAmmCommandSizeMapAsPrt(uint64_t va, uint64_t size) {
    return (int64_t)sce::Ampr::Emu::measureAmmMapAsPrt(va, size);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmMeasureAmmCommandSizeAllocatePaForPrt(uint64_t va, uint64_t size, int type, int prot) {
    return (int64_t)sce::Ampr::Emu::measureAmmAllocatePaForPrt(va, size, type, prot);
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferConstructor(sce::Ampr::CommandBuffer* self) {
    ampr_flush_hook_log_from_export();
    ampr_export_vlogf("exp.cb.ctor this=%p", (void*)self);
    auto* cb = reinterpret_cast<SceAmprCommandBuffer*>(self);
    if (cb) {
        // Retail clears only the 24-byte header.
        cb->type = 0;
        cb->offset = 0;
        cb->num = 0;
        cb->bufsize = 0;
        cb->buffer = nullptr;
    }
    ampr_export_vlogf("exp.cb.ctor leave this=%p", (void*)self);
    return 0;
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferDestructor(sce::Ampr::CommandBuffer* self) {
    ampr_export_vlogf("exp.cb.dtor this=%p", (void*)self);
    ampr_export_vlogf("exp.cb.dtor leave this=%p", (void*)self);
    return 0;
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferReset(sce::Ampr::CommandBuffer* self) {
    ampr_export_vlogf("exp.cb.reset this=%p", (void*)self);
    const int64_t rc = self ? self->reset() : SCE_KERNEL_ERROR_EPERM;
    const int64_t outRc = ampr_export_rc32(rc);
    ampr_export_vlogf("exp.cb.reset leave this=%p rc=0x%llx", (void*)self, (unsigned long long)outRc);
    return outRc;
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferSetBuffer(sce::Ampr::CommandBuffer* self, void* buffer, uint32_t size) {
    const int64_t rc = self ? self->setBuffer(buffer, size) : SCE_KERNEL_ERROR_EINVAL;
    const int64_t outRc = ampr_export_rc32(rc);
    if (outRc != 0) {
        ampr_export_vlogf("exp.cb.setBuffer reject this=%p buffer=%p size=0x%x rc=0x%llx",
                          (void*)self,
                          buffer,
                          (unsigned)size,
                          (unsigned long long)outRc);
    }
    return outRc;
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferClearBuffer(sce::Ampr::CommandBuffer* self) {
    ampr_export_vlogf("exp.cb.clearBuffer this=%p", (void*)self);
    const int64_t rc = (int64_t)(uintptr_t)self->clearBuffer();
    ampr_export_vlogf("exp.cb.clearBuffer leave this=%p buffer=%p", (void*)self, (void*)(uintptr_t)rc);
    return rc;
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferGetType(sce::Ampr::CommandBuffer* self) {
    return self->getType();
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferGetSize(sce::Ampr::CommandBuffer* self) {
    return self->getSize();
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferGetBufferBaseAddress(sce::Ampr::CommandBuffer* self) {
    return (int64_t)(uintptr_t)self->getBufferBaseAddress();
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferGetNumCommands(sce::Ampr::CommandBuffer* self) {
    return self->getNumCommands();
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferGetCurrentOffset(sce::Ampr::CommandBuffer* self) {
    return self->getCurrentOffset();
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferWaitOnAddress_04_00(sce::Ampr::CommandBuffer* self,
                                                                        volatile uint64_t* address,
                                                                        uint64_t refValue,
                                                                        sce::Ampr::WaitCompare compare,
                                                                        sce::Ampr::WaitFlush flush) {
    return ampr_export_rc32(self->waitOnAddress_04_00(address, refValue, compare, flush));
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferWaitOnAddress(sce::Ampr::CommandBuffer* self,
                                                                 volatile uint64_t* address,
                                                                 uint64_t refValue,
                                                                 sce::Ampr::WaitCompare compare,
                                                                 sce::Ampr::WaitFlush flush) {
    return ampr_export_rc32(self->waitOnAddress(address, refValue, compare, flush));
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferWaitOnCounter_04_00(
        sce::Ampr::CommandBuffer* self,
        uint8_t counterIndex,
        uint8_t valueWidth,
        u64 refValue,
        uint8_t compare,
        uint8_t legacyExtraFlag,
        u64 legacyExtraValue,
        uint8_t flush) {
    ampr_export_vlogf("exp.cb.waitCounter04 this=%p idx=%u n8=%u ref=0x%llx cmp=%u extraFlag=%u extraValue=0x%llx flush=%u",
                     (void*)self, (unsigned)counterIndex, (unsigned)valueWidth, (unsigned long long)refValue,
                     (unsigned)compare, (unsigned)legacyExtraFlag, (unsigned long long)legacyExtraValue,
                     (unsigned)flush);
    return ampr_export_rc32(self->waitOnCounter_04_00(
        counterIndex, valueWidth, refValue, (sce::Ampr::WaitCompare)compare,
        legacyExtraFlag, legacyExtraValue, (sce::Ampr::WaitFlush)flush));
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferWaitOnCounter(sce::Ampr::CommandBuffer* self,
                                                                 uint8_t counterIndex,
                                                                 uint32_t refValue,
                                                                 sce::Ampr::WaitCompare compare,
                                                                 sce::Ampr::WaitFlush flush) {
    return ampr_export_rc32(self->waitOnCounter(counterIndex, refValue, compare, flush));
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferWriteAddress_04_00(sce::Ampr::CommandBuffer* self,
                                                                       volatile uint64_t* address,
                                                                       uint64_t value,
                                                                       uint64_t atSop) {
    ampr_export_vlogf("exp.cb.writeAddress04 this=%p addr=%p value=0x%llx mode=%u",
                     (void*)self, (void*)address, (unsigned long long)value, (unsigned)(uint8_t)atSop);
    return ampr_export_rc32(self->writeAddress_04_00(address, value, atSop != 0));
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferWriteAddressOnCompletion(sce::Ampr::CommandBuffer* self,
                                                                            volatile uint64_t* address,
                                                                            uint64_t value) {
    return ampr_export_rc32(self->writeAddressOnCompletion(address, value));
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferWriteCounter_04_00(
        sce::Ampr::CommandBuffer* self,
        uint8_t counterIndex,
        uint8_t valueWidth,
        u64 value,
        uint8_t counterMode,
        uint8_t mode) {
    ampr_export_vlogf("exp.cb.writeCounter04 this=%p idx=%u n8=%u value=0x%llx n5=%u mode=%u",
                     (void*)self, (unsigned)counterIndex, (unsigned)valueWidth, (unsigned long long)value,
                     (unsigned)counterMode, (unsigned)mode);
    return ampr_export_rc32(self->writeCounter_04_00(counterIndex, valueWidth, value, counterMode, mode != 0));
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferWriteCounterOnCompletion(sce::Ampr::CommandBuffer* self,
                                                                            uint8_t counterIndex,
                                                                            uint32_t value) {
    return ampr_export_rc32(self->writeCounterOnCompletion(counterIndex, value));
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferWriteKernelEventQueue_04_00(sce::Ampr::CommandBuffer* self,
                                                                               SceKernelEqueue eq,
                                                                               int32_t id,
                                                                               uint64_t data,
                                                                               uint64_t atSop) {
    return ampr_export_rc32(self->writeKernelEventQueue_04_00(eq, id, data, atSop != 0));
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferWriteKernelEventQueueOnCompletion(sce::Ampr::CommandBuffer* self,
                                                                                    SceKernelEqueue eq,
                                                                                    int32_t id,
                                                                                    uint64_t data) {
    return ampr_export_rc32(self->writeKernelEventQueueOnCompletion(eq, id, data));
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferWriteAddressFromTimeCounter_04_00(sce::Ampr::CommandBuffer* self,
                                                                                     volatile uint64_t* address,
                                                                                     uint64_t atSop) {
    return ampr_export_rc32(self->writeAddressFromTimeCounter_04_00(address, atSop != 0));
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferWriteAddressFromTimeCounterOnCompletion(sce::Ampr::CommandBuffer* self,
                                                                                          volatile uint64_t* address) {
    return ampr_export_rc32(self->writeAddressFromTimeCounterOnCompletion(address));
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferWriteAddressFromCounter_04_00(sce::Ampr::CommandBuffer* self,
                                                                                 volatile uint64_t* address,
                                                                                 uint8_t counterIndex,
                                                                                 uint64_t atSop) {
    return ampr_export_rc32(self->writeAddressFromCounter_04_00(address, counterIndex, atSop != 0));
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferWriteAddressFromCounterOnCompletion(sce::Ampr::CommandBuffer* self,
                                                                                      volatile uint64_t* address,
                                                                                      uint8_t counterIndex) {
    return ampr_export_rc32(self->writeAddressFromCounterOnCompletion(address, counterIndex));
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferWriteAddressFromCounterPair_04_00(sce::Ampr::CommandBuffer* self,
                                                                                     volatile uint64_t* address,
                                                                                     uint8_t counterIndex,
                                                                                     uint64_t atSop) {
    return ampr_export_rc32(self->writeAddressFromCounterPair_04_00(address, counterIndex, atSop != 0));
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferWriteAddressFromCounterPairOnCompletion(sce::Ampr::CommandBuffer* self,
                                                                                          volatile uint64_t* address,
                                                                                          uint8_t counterIndex) {
    return ampr_export_rc32(self->writeAddressFromCounterPairOnCompletion(address, counterIndex));
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferConstructNop(
        sce::Ampr::CommandBuffer* self,
        int16_t nopType,
        const void* payload,
        uint32_t payloadSize,
        const uint32_t* optWord) {
    ampr_export_vlogf("exp.cb.constructNop this=%p type=%d payload=%p payloadSize=0x%x opt=%p",
                     (void*)self, (int)nopType, payload, payloadSize, (const void*)optWord);
    return ampr_export_rc32(self->constructNop(static_cast<uint32_t>(nopType), payload, payloadSize, optWord));
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferNop(sce::Ampr::CommandBuffer* self, uint32_t numU32) {
    // FW10 signature: (this, int numU32)
    return ampr_export_rc32(self->nop(numU32));
}



extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferNopWithData(sce::Ampr::CommandBuffer* self,
                                                               uint32_t numU32,
                                                               const uint32_t* data) {
    // FW10 signature: (this, int numU32, const uint32_t* data)
    return ampr_export_rc32(self->nop(numU32, data));
}



extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferConstructMarker(sce::Ampr::CommandBuffer* self,
                                                                   uint32_t markerType,
                                                                   const char* msg,
                                                                   const uint32_t* opt) {
    // FW10 signature: (this, unsigned int type, const char* msg, uint32_t* opt)
    // type values seen in FW10: 1=set,2=push,3=pop,5=setWithColor,6=pushWithColor
    switch (markerType) {
        case 1: return ampr_export_rc32(self->setMarker(msg));
        case 2: return ampr_export_rc32(self->pushMarker(msg));
        case 3: return ampr_export_rc32(self->popMarker());
        case 5: return opt ? ampr_export_rc32(self->setMarker(msg, *opt)) : ampr_export_rc32(SCE_KERNEL_ERROR_EINVAL);
        case 6: return opt ? ampr_export_rc32(self->pushMarker(msg, *opt)) : ampr_export_rc32(SCE_KERNEL_ERROR_EINVAL);
        default: return ampr_export_rc32(SCE_KERNEL_ERROR_EINVAL);
    }
}



extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferSetMarkerWithColor(sce::Ampr::CommandBuffer* self,
                                                                      const char* msg,
                                                                      const uint32_t* colorPtr) {
    // FW10 signature: (this, char* msg, uint32_t* colorPtr)
    return colorPtr ? ampr_export_rc32(self->setMarker(msg, *colorPtr)) : ampr_export_rc32(SCE_KERNEL_ERROR_EINVAL);
}



extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferSetMarker(sce::Ampr::CommandBuffer* self, const char* msg) {
    return ampr_export_rc32(self->setMarker(msg));
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferPushMarkerWithColor(sce::Ampr::CommandBuffer* self,
                                                                       const char* msg,
                                                                       uint32_t color) {
    // FW10 signature: (this, char* msg, int color)
    return ampr_export_rc32(self->pushMarker(msg, color));
}



extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferPushMarker(sce::Ampr::CommandBuffer* self, const char* msg) {
    // FW10 signature: (this, char* msg)
    return ampr_export_rc32(self->pushMarker(msg));
}



extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferPopMarker(sce::Ampr::CommandBuffer* self) {
    return ampr_export_rc32(self->popMarker());
}


extern "C" AMPR_EXPORT int64_t sceAmprAprCommandBufferConstructor(sce::Ampr::AprCommandBuffer* self,
                                                                  __SceAprMapState* mapState,
                                                                  __SceAprScatterGatherState* scatterGatherState) {
    ampr_export_vlogf("[apr-cb-20] sceAmprAprCommandBufferConstructor enter this=%p mapStateArg=%p sgStateArg=%p",
                     (void*)self, (void*)mapState, (void*)scatterGatherState);
    // SDK wrapper call sequence:
    //   sceAmprCommandBufferConstructor(this);
    //   sceAmprAprCommandBufferConstructor(this, this+24, this+32);
    // Initialize only the APR tail.
    if (mapState) {
        mapState->asU64 = 0;
    }
    if (scatterGatherState) {
        scatterGatherState->asU64 = 0;
    }
    ampr_export_vlogf("[apr-cb-21] sceAmprAprCommandBufferConstructor leave this=%p mapState=0x%llx sgState=0x%llx",
                     (void*)self,
                     (unsigned long long)(mapState ? mapState->asU64 : 0ull),
                     (unsigned long long)(scatterGatherState ? scatterGatherState->asU64 : 0ull));
    return 0;
}


extern "C" AMPR_EXPORT int64_t sceAmprAprCommandBufferDestructor(sce::Ampr::AprCommandBuffer* self,
                                                                 __SceAprMapState* mapState,
                                                                 __SceAprScatterGatherState* scatterGatherState) {
    ampr_export_vlogf("exp.apr.cb.dtor this=%p mapStateArg=%p sgStateArg=%p no-op-derived-dtor",
                     (void*)self, (void*)mapState, (void*)scatterGatherState);
    return 0;
}


extern "C" AMPR_EXPORT int64_t sceAmprAprCommandBufferReadFile(
        sce::Ampr::AprCommandBuffer* self,
        __SceAprMapState* mapState,
        __SceAprScatterGatherState* scatterGatherState,
        uint32_t fileId,
        void* buffer,
        uint64_t length,
        uint64_t offset) {
    ampr_export_vlogf("[apr-cb-30] sceAmprAprCommandBufferReadFile enter this=%p hiddenA2=%p hiddenA3=%p fileId=%u buffer=%p len=0x%llx off=0x%llx",
                     (void*)self, (void*)mapState, (void*)scatterGatherState, (unsigned)fileId, buffer,
                     (unsigned long long)length, (unsigned long long)offset);
    const int64_t rc = self->readFile((SceAprFileId)fileId, buffer, length, offset);
    const int64_t outRc = ampr_export_rc32(rc);
    ampr_export_vlogf("[apr-cb-31] sceAmprAprCommandBufferReadFile leave this=%p rc=0x%llx",
                     (void*)self, (unsigned long long)outRc);
    return outRc;
}


extern "C" AMPR_EXPORT int64_t sceAmprAprCommandBufferReadFileGather(sce::Ampr::AprCommandBuffer* self,
                                                                     __SceAprMapState* mapState,
                                                                     __SceAprScatterGatherState* scatterGatherState,
                                                                     uint64_t length,
                                                                     uint64_t offset) {
    ampr_export_vlogf("[apr-cb-40] sceAmprAprCommandBufferReadFileGather enter this=%p hiddenA2=%p hiddenA3=%p len=0x%llx off=0x%llx",
                     (void*)self, (void*)mapState, (void*)scatterGatherState, (unsigned long long)length, (unsigned long long)offset);
    const int64_t rc = self->readFileGather(length, offset);
    const int64_t outRc = ampr_export_rc32(rc);
    ampr_export_vlogf("[apr-cb-41] sceAmprAprCommandBufferReadFileGather leave this=%p rc=0x%llx",
                     (void*)self, (unsigned long long)outRc);
    return outRc;
}


extern "C" AMPR_EXPORT int64_t sceAmprAprCommandBufferReadFileScatter(sce::Ampr::AprCommandBuffer* self,
                                                                      __SceAprMapState* mapState,
                                                                      __SceAprScatterGatherState* scatterGatherState,
                                                                      void* buffer,
                                                                      uint64_t length) {
    ampr_export_vlogf("[apr-cb-50] sceAmprAprCommandBufferReadFileScatter enter this=%p hiddenA2=%p hiddenA3=%p buffer=%p len=0x%llx",
                     (void*)self, (void*)mapState, (void*)scatterGatherState, buffer, (unsigned long long)length);
    const int64_t rc = self->readFileScatter(buffer, length);
    const int64_t outRc = ampr_export_rc32(rc);
    ampr_export_vlogf("[apr-cb-51] sceAmprAprCommandBufferReadFileScatter leave this=%p rc=0x%llx",
                     (void*)self, (unsigned long long)outRc);
    return outRc;
}


extern "C" AMPR_EXPORT int64_t sceAmprAprCommandBufferReadFileGatherScatter(sce::Ampr::AprCommandBuffer* self,
                                                                            __SceAprMapState* mapState,
                                                                            __SceAprScatterGatherState* scatterGatherState,
                                                                            void* buffer,
                                                                            uint64_t length,
                                                                            uint64_t offset) {
    ampr_export_vlogf("[apr-cb-60] sceAmprAprCommandBufferReadFileGatherScatter enter this=%p hiddenA2=%p hiddenA3=%p buffer=%p len=0x%llx off=0x%llx",
                     (void*)self, (void*)mapState, (void*)scatterGatherState, buffer,
                     (unsigned long long)length, (unsigned long long)offset);
    const int64_t rc = self->readFileGatherScatter(buffer, length, offset);
    const int64_t outRc = ampr_export_rc32(rc);
    ampr_export_vlogf("[apr-cb-61] sceAmprAprCommandBufferReadFileGatherScatter leave this=%p rc=0x%llx",
                     (void*)self, (unsigned long long)outRc);
    return outRc;
}


extern "C" AMPR_EXPORT int64_t sceAmprAprCommandBufferResetGatherScatterState(sce::Ampr::AprCommandBuffer* self) {
    ampr_export_vlogf("exp.apr.cb.resetGs this=%p", (void*)self);
    const int64_t rc = self->resetGatherScatterState();
    const int64_t outRc = ampr_export_rc32(rc);
    ampr_export_vlogf("exp.apr.cb.resetGs leave this=%p rc=0x%llx", (void*)self, (unsigned long long)outRc);
    return outRc;
}


extern "C" AMPR_EXPORT int64_t sceAmprAprCommandBufferMapBegin(sce::Ampr::AprCommandBuffer* self,
                                                               uint64_t va,
                                                               uint64_t size,
                                                               int type,
                                                               int prot) {
    ampr_export_vlogf("exp.apr.cb.mapBegin this=%p va=0x%llx size=0x%llx type=%d prot=0x%x",
                     (void*)self, (unsigned long long)va, (unsigned long long)size, type, prot);
    const int64_t rc = self->mapBegin(va, size, type, prot);
    const int64_t outRc = ampr_export_rc32(rc);
    ampr_export_vlogf("exp.apr.cb.mapBegin leave this=%p rc=0x%llx", (void*)self, (unsigned long long)outRc);
    return outRc;
}


extern "C" AMPR_EXPORT int64_t sceAmprAprCommandBufferMapDirectBegin(sce::Ampr::AprCommandBuffer* self,
                                                                     uint64_t va,
                                                                     uint64_t dmemOffset,
                                                                     size_t size,
                                                                     int type,
                                                                     int prot) {
    ampr_export_vlogf("exp.apr.cb.mapDirectBegin this=%p va=0x%llx dmemOffset=0x%llx size=0x%llx type=%d prot=0x%x",
                     (void*)self,
                     (unsigned long long)va, (unsigned long long)dmemOffset, (unsigned long long)size,
                     type, prot);
    const int64_t rc = self->mapDirectBegin(va, dmemOffset, size, type, prot);
    const int64_t outRc = ampr_export_rc32(rc);
    ampr_export_vlogf("exp.apr.cb.mapDirectBegin leave this=%p rc=0x%llx", (void*)self, (unsigned long long)outRc);
    return outRc;
}


extern "C" AMPR_EXPORT int64_t sceAmprAprCommandBufferMapEnd(sce::Ampr::AprCommandBuffer* self) {
    ampr_export_vlogf("exp.apr.cb.mapEnd this=%p", (void*)self);
    const int64_t rc = self->mapEnd();
    const int64_t outRc = ampr_export_rc32(rc);
    ampr_export_vlogf("exp.apr.cb.mapEnd leave this=%p rc=0x%llx", (void*)self, (unsigned long long)outRc);
    return outRc;
}


extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeWaitOnAddress_04_00(volatile uint64_t* address,
                                                                            uint64_t refValue,
                                                                            sce::Ampr::WaitCompare compare,
                                                                            sce::Ampr::WaitFlush flush) {
    const int64_t rc = ampr_ref_validate_wait_address_04_00((uint64_t)address, (uint32_t)compare, (uint32_t)flush);
    if (rc != 0) {
        return ampr_export_rc32(rc);
    }
    return ((refValue >> 32) == 0) ? (int64_t)(4 * (unsigned int)(refValue != 0) + 8) : 16;
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeWaitOnAddress(volatile uint64_t* address,
                                                                      uint64_t refValue,
                                                                      sce::Ampr::WaitCompare compare,
                                                                      sce::Ampr::WaitFlush flush) {
    const int64_t rc = ampr_ref_validate_wait_address((uint64_t)address, (uint32_t)compare, (uint32_t)flush);
    if (rc != 0) {
        return ampr_export_rc32(rc);
    }
    return ((refValue >> 32) == 0) ? (int64_t)(4 * (unsigned int)(refValue != 0) + 8) : 16;
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeWaitOnCounter_04_00(uint8_t counterIndex,
                                                                            uint8_t valueWidth,
                                                                            uint64_t refValue,
                                                                            uint8_t compare,
                                                                            uint8_t legacyExtraFlag,
                                                                            uint64_t legacyExtraValue,
                                                                            uint8_t flush) {
    (void)counterIndex;
    const int64_t rc = ampr_ref_validate_wait_counter_04_00(valueWidth, compare, legacyExtraFlag, flush);
    if (rc != 0) {
        return ampr_export_rc32(rc);
    }
    uint8_t n8 = valueWidth;
    uint64_t n0xFFFF = refValue;
    uint8_t n2_1 = legacyExtraFlag;
    uint64_t n0xFFFF_1 = legacyExtraValue;

    if (n8 == 1 && n0xFFFF <= 0xFF && n2_1 == 0) return 4;

    if (n0xFFFF > 0xFFFF) {
        uint64_t hi1 = n0xFFFF_1 >> 32;
        if ((n0xFFFF >> 32) != 0 || (hi1 != 0 && n2_1 != 0))
            return (int64_t)(8 * (unsigned int)(n2_1 != 0) + 12);
        return (int64_t)(4 * (unsigned int)(n2_1 != 0) + 8);
    }

    // Extended legacy form.
    if (n2_1 && n0xFFFF_1 >= 0x10000ULL) {
        if ((n0xFFFF_1 >> 32) != 0)
            return (int64_t)(8 * (unsigned int)(n2_1 != 0) + 12);
        return (int64_t)(4 * (unsigned int)(n2_1 != 0) + 8);
    }

    return 8;
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeWaitOnCounter(uint8_t counterIndex,
                                                                      uint32_t refValue,
                                                                      sce::Ampr::WaitCompare compare,
                                                                      sce::Ampr::WaitFlush flush) {
    const int64_t rc = ampr_ref_validate_wait_counter(counterIndex, (uint32_t)compare, (uint32_t)flush);
    if (rc != 0) {
        return ampr_export_rc32(rc);
    }
    return (int64_t)(4 * (unsigned int)(refValue >= 0x100) + 4);
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeWriteAddress_04_00(volatile uint64_t* address, uint64_t value) {
    const int64_t rc = ampr_ref_validate_write_address((uint64_t)address, 0u, value);
    if (rc != 0) {
        return ampr_export_rc32(rc);
    }
    return ((value >> 34) == 0) ? (int64_t)(4 * (unsigned int)(value >= 4) + 8) : 16;
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeWriteAddressOnCompletion(volatile uint64_t* address, uint64_t value) {
    const int64_t rc = ampr_ref_validate_write_address((uint64_t)address, 0u, value);
    if (rc != 0) {
        return ampr_export_rc32(rc);
    }
    return ((value >> 34) == 0) ? (int64_t)(4 * (unsigned int)(value >= 4) + 8) : 16;
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeWriteAddressFromTimeCounter_04_00(volatile uint64_t* address) {
    const int64_t rc = ampr_ref_validate_write_address((uint64_t)address, 1u, 0);
    if (rc != 0) {
        return ampr_export_rc32(rc);
    }
    return 8;
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeWriteAddressFromTimeCounterOnCompletion(volatile uint64_t* address) {
    const int64_t rc = ampr_ref_validate_write_address((uint64_t)address, 1u, 0);
    if (rc != 0) {
        return ampr_export_rc32(rc);
    }
    return 8;
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeWriteAddressFromCounter_04_00(volatile uint64_t* address, uint8_t counterIndex) {
    const int64_t rc = ampr_ref_validate_write_address((uint64_t)address, 2u, counterIndex);
    if (rc != 0) {
        return ampr_export_rc32(rc);
    }
    return (int64_t)(4 * (unsigned int)(counterIndex >= 4) + 8);
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeWriteAddressFromCounterOnCompletion(volatile uint64_t* address, uint8_t counterIndex) {
    const int64_t rc = ampr_ref_validate_write_address((uint64_t)address, 2u, counterIndex);
    if (rc != 0) {
        return ampr_export_rc32(rc);
    }
    return (int64_t)(4 * (unsigned int)(counterIndex >= 4) + 8);
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeWriteAddressFromCounterPair_04_00(volatile uint64_t* address, uint8_t counterIndex) {
    const int64_t rc = ampr_ref_validate_write_address((uint64_t)address, 3u, counterIndex);
    if (rc != 0) {
        return ampr_export_rc32(rc);
    }
    return (int64_t)(4 * (unsigned int)(counterIndex >= 4) + 8);
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeWriteAddressFromCounterPairOnCompletion(volatile uint64_t* address, uint8_t counterIndex) {
    const int64_t rc = ampr_ref_validate_write_address((uint64_t)address, 3u, counterIndex);
    if (rc != 0) {
        return ampr_export_rc32(rc);
    }
    return (int64_t)(4 * (unsigned int)(counterIndex >= 4) + 8);
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeWriteCounter_04_00(uint8_t counterIndex,
                                                                           uint8_t valueWidth,
                                                                           uint64_t value,
                                                                           uint8_t counterMode) {
    const int64_t rc = ampr_ref_validate_write_counter_04_00(counterIndex, valueWidth, counterMode);
    if (rc != 0) {
        return ampr_export_rc32(rc);
    }
    const uint32_t bits = valueWidth == 0 ? 64u : (valueWidth == 1 ? 32u : (valueWidth < 4 ? 16u : 8u));
    const uint64_t masked = bits >= 64u ? value : (value & ((1ull << bits) - 1ull));
    const uint32_t wideDwords = ((masked >> 32) != 0) ? 3u : 2u;
    const uint32_t dwords = (((((uint32_t)valueWidth & 7u) ^ 1u) | ((uint32_t)counterMode & 7u)) != 0 || masked >= 0x1000ull) ? wideDwords : 1u;
    return (int64_t)(dwords * 4u);
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeWriteCounterOnCompletion(uint8_t counterIndex, uint32_t value) {
    const int64_t rc = ampr_ref_validate_write_counter(counterIndex);
    if (rc != 0) {
        return ampr_export_rc32(rc);
    }
    return (int64_t)(4 * (unsigned int)(value >= 0x1000) + 4);
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeWriteKernelEventQueue_04_00(SceKernelEqueue eq, int32_t id, uint64_t data) {
    (void)eq; (void)id; (void)data;
    return 20;
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeWriteKernelEventQueueOnCompletion(SceKernelEqueue eq, int32_t id, uint64_t data) {
    (void)eq; (void)id; (void)data;
    return 20;
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeNop(uint32_t numU32) {
    const int64_t rc = ampr_ref_validate_nop_measure(numU32);
    if (rc != 0) {
        return ampr_export_rc32(rc);
    }
    return (int64_t)(4 * numU32);
}


extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeNopWithData(uint32_t numU32) {
    const int64_t rc = ampr_ref_validate_nop_measure(numU32);
    if (rc != 0) {
        return ampr_export_rc32(rc);
    }
    return (int64_t)(4 * numU32);
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeReadFile(SceAprFileId fileId, void* buffer, uint64_t length, uint64_t offset) {
    const int64_t rc = ampr_ref_validate_read_file((uint64_t)buffer, (int64_t)length, fileId, offset);
    if (rc != 0) {
        return ampr_export_rc32(rc);
    }
    return (int64_t)(4 * (unsigned int)((offset >> 32) != 0) + 20);
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeReadFileGather(uint64_t length, uint64_t offset) {
    const int64_t rc = ampr_ref_validate_read_file_gather((int64_t)length, offset);
    if (rc != 0) {
        return ampr_export_rc32(rc);
    }
    return (int64_t)(4 * (unsigned int)(offset >= 0x40000ULL) + 8);
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeReadFileScatter(void* buffer, uint64_t length) {
    const int64_t rc = ampr_ref_validate_read_file_scatter((uint64_t)buffer, (int64_t)length);
    if (rc != 0) {
        return ampr_export_rc32(rc);
    }
    return 12;
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeReadFileGatherScatter(void* buffer, uint64_t length, uint64_t offset) {
    const int64_t rc = ampr_ref_validate_read_file_gather_scatter((uint64_t)buffer, (int64_t)length, offset);
    if (rc != 0) {
        return ampr_export_rc32(rc);
    }
    return (int64_t)(4 * (unsigned int)((offset >> 32) != 0) + 16);
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeResetGatherScatterState() {
    return 4;
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeMapBegin(uint64_t va,
                                                                 uint64_t size,
                                                                 uint32_t type,
                                                                 uint32_t prot) {
    const int64_t rc = sce::Ampr::Emu::aprValidateMapBeginArgs(va, size, static_cast<int>(type), static_cast<int>(prot));
    if (rc != 0) {
        return ampr_export_rc32(rc);
    }
    return 12;
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeMapDirectBegin(uint64_t va,
                                                                       uint64_t dmemOffset,
                                                                       uint64_t size,
                                                                       uint32_t type,
                                                                       uint32_t prot) {
    const int64_t rc = sce::Ampr::Emu::aprValidateMapDirectBeginArgs(va, dmemOffset, size, static_cast<int>(type), static_cast<int>(prot));
    if (rc != 0) {
        return ampr_export_rc32(rc);
    }
    return 16;
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeMapEnd() {
    return 4;
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeSetMarkerWithColor(const char* msg, uint32_t color) {
    // signature in FW10: (char* msg, int color)
    (void)color;
    return ampr_measure_marker_bytes(5u, msg);
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeSetMarker(const char* msg) {
    return ampr_measure_marker_bytes(1u, msg);
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizePushMarkerWithColor(const char* msg, uint32_t color) {
    (void)color;
    return ampr_measure_marker_bytes(6u, msg);
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizePushMarker(const char* msg) {
    return ampr_measure_marker_bytes(2u, msg);
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizePopMarker() {
    return 4;
}
