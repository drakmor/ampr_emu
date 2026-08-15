/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * AMM-only runtime helpers.
 */

#pragma once

#include "ampr.h"

#include <cstdint>
#include <climits>
#include <sys/sce_errno.h>
#include <sys/types.h>

namespace sce::Ampr::Emu {

inline int ammCommandSizeToInt(int rc, uint64_t bytes64, uint32_t* outBytes = nullptr) {
    if (rc != 0) {
        return rc;
    }
    if (bytes64 == 0 || bytes64 > UINT32_MAX) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    if (outBytes) {
        *outBytes = static_cast<uint32_t>(bytes64);
    }
    return static_cast<int>(bytes64);
}

inline int ammMeasureSizeToInt(int rc, uint64_t bytes64) {
    if (rc < 0) {
        return rc;
    }
    if (bytes64 == 0 || bytes64 > UINT32_MAX) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    return static_cast<int>(bytes64);
}

template <typename MeasureFn>
inline int measureAmmKernelRecord(MeasureFn measure) {
    uint64_t bytes64 = 0;
    return ammMeasureSizeToInt(measure(&bytes64), bytes64);
}

uint32_t ammKernelProt(uint32_t prot);

inline constexpr uint32_t kAmmRetailProtInvalidMask = 0xFFFFFC0Cu;

inline int ammValidateRetailProt(uint32_t prot) {
    return (prot & kAmmRetailProtInvalidMask) == 0 ? 0 : SCE_KERNEL_ERROR_EINVAL;
}

int ammWriteMapCommand2(void* dst,
                        uint64_t va,
                        uint64_t size,
                        uint64_t type,
                        uint64_t prot,
                        uint64_t prt,
                        uint64_t* outSize);
int ammWriteMapCommand(void* dst,
                       uint64_t va,
                       uint64_t size,
                       uint64_t type,
                       uint64_t prot,
                       uint64_t* outSize);
int ammWriteMapWithGpuMaskIdCommand(void* dst,
                                    uint64_t va,
                                    uint64_t size,
                                    uint64_t type,
                                    uint64_t prot,
                                    uint64_t gpuMaskId,
                                    uint64_t* outSize);
int ammWriteMapDirectCommand(void* dst,
                             uint64_t va,
                             uint64_t dmemOffset,
                             uint64_t size,
                             uint64_t type,
                             uint64_t prot,
                             uint64_t* outSize);
int ammWriteMapDirectWithGpuMaskIdCommand(void* dst,
                                          uint64_t va,
                                          uint64_t dmemOffset,
                                          uint64_t size,
                                          uint64_t type,
                                          uint64_t prot,
                                          uint64_t gpuMaskId,
                                          uint64_t* outSize);
int ammWriteUnmapCommand(void* dst, uint64_t va, uint64_t size, uint64_t* outSize);
int ammWriteRemapCommand(void* dst,
                         uint64_t vaNewStart,
                         uint64_t vaOldStart,
                         uint64_t size,
                         uint64_t prot,
                         uint64_t* outSize);
int ammWriteRemapWithGpuMaskIdCommand(void* dst,
                                      uint64_t vaNewStart,
                                      uint64_t vaOldStart,
                                      uint64_t size,
                                      uint64_t prot,
                                      uint64_t gpuMaskId,
                                      uint64_t* outSize);
int ammWriteMultiMapCommand(void* dst,
                            uint64_t vaNewStart,
                            uint64_t vaAliasStart,
                            uint64_t size,
                            uint64_t prot,
                            uint64_t* outSize);
int ammWriteMultiMapWithGpuMaskIdCommand(void* dst,
                                         uint64_t vaNewStart,
                                         uint64_t vaAliasStart,
                                         uint64_t size,
                                         uint64_t prot,
                                         uint64_t gpuMaskId,
                                         uint64_t* outSize);
int ammWriteModifyProtectCommand(void* dst,
                                 uint64_t va,
                                 uint64_t size,
                                 uint64_t prot,
                                 uint64_t protMask,
                                 uint64_t* outSize);
int ammWriteModifyProtectWithGpuMaskIdCommand(void* dst,
                                              uint64_t va,
                                              uint64_t size,
                                              uint64_t prot,
                                              uint64_t protMask,
                                              uint64_t gpuMaskId,
                                              uint64_t* outSize);
int ammWriteModifyMtypeProtectCommand(void* dst,
                                      uint64_t va,
                                      uint64_t size,
                                      uint64_t type,
                                      uint64_t prot,
                                      uint64_t protMask,
                                      uint64_t* outSize);
int ammWriteModifyMtypeProtectWithGpuMaskIdCommand(void* dst,
                                                   uint64_t va,
                                                   uint64_t size,
                                                   uint64_t type,
                                                   uint64_t prot,
                                                   uint64_t protMask,
                                                   uint64_t gpuMaskId,
                                                   uint64_t* outSize);
int ammWriteRemapIntoPrtCommand(uint32_t* dst,
                                uint64_t va,
                                uint64_t remapVa,
                                uint64_t size,
                                int prot,
                                int opcode,
                                uint64_t* outSize);
int ammWriteUnmapToPrtCommand(uint32_t* dst, uint64_t va, uint64_t size, uint64_t* outSize);

int ammGetVirtualAddressRangesLeaf(uint64_t* vaStart,
                                   uint64_t* vaEnd,
                                   uint64_t* multimapVaStart,
                                   uint64_t* multimapVaEnd);
int ammGiveDirectMemory(off_t searchStart,
                        off_t searchEnd,
                        size_t size,
                        size_t align,
                        int usage,
                        off_t* dmemOffset);
int ammSubmitCommandBufferLeaf(uint64_t bufferBase,
                               uint32_t currentOffset,
                               uint32_t prio,
                               SceAmmSubmitId* id);
int ammSubmitCommandBufferAndGetResultLeaf(uint64_t bufferBase,
                                           uint32_t currentOffset,
                                           uint32_t prio,
                                           SceAmmResultBuffer* res,
                                           SceAmmSubmitId* id);
int ammWaitCommandBufferCompletion(SceAmmSubmitId id);

int mapperGetUsageStatsData(uint64_t* data);
int mapperSetPageTablePoolOccupancyNotificationThreshold(int threshold);

} // namespace sce::Ampr::Emu
