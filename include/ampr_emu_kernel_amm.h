/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Internal AMM libkernel declarations.
 */

#pragma once

#include "ampr.h"
#include "ampr_emu_kernel_lookup.h"

#include <_kernel.h>
#include <kernel.h>
#include <stdint.h>
#include <sys/dmem.h>

extern "C" int sceKernelGiveDirectMemoryToMapper(off_t searchStart,
                                                  off_t searchEnd,
                                                  size_t size,
                                                  size_t align,
                                                  int usage,
                                                  off_t* dmemOffset);
extern "C" int sceKernelMapperGetParam(uint64_t* param);
extern "C" int sceKernelCallIndirectBuffer(unsigned int priority,
                                            uint64_t bufferBase,
                                            uint64_t currentOffset);
extern "C" int sceKernelCallIndirectBuffer2(unsigned int priority,
                                             uint64_t bufferBase,
                                             uint64_t currentOffset,
                                             SceAmmResultBuffer* result,
                                             SceAmmSubmitId* submitId);
extern "C" int sceKernelWaitCommandBufferCompletion(SceAmmSubmitId submitId);
extern "C" int sceKernelUsleep(unsigned int usec);
extern "C" int sceKernelWriteMapCommand2(void* dst,
                                          uint64_t va,
                                          uint64_t size,
                                          uint64_t type,
                                          uint64_t prot,
                                          uint64_t prt,
                                          uint64_t* outSize);
extern "C" int sceKernelWriteMapWithGpuMaskIdCommand(void* dst,
                                                      uint64_t va,
                                                      uint64_t size,
                                                      uint64_t type,
                                                      uint64_t prot,
                                                      uint64_t gpuMaskId,
                                                      uint64_t* outSize);
extern "C" int sceKernelWriteMapDirectCommand(void* dst,
                                               uint64_t va,
                                               uint64_t dmemOffset,
                                               uint64_t size,
                                               uint64_t type,
                                               uint64_t prot,
                                               uint64_t* outSize);
extern "C" int sceKernelWriteMapDirectWithGpuMaskIdCommand(void* dst,
                                                            uint64_t va,
                                                            uint64_t dmemOffset,
                                                            uint64_t size,
                                                            uint64_t type,
                                                            uint64_t prot,
                                                            uint64_t gpuMaskId,
                                                            uint64_t* outSize);
extern "C" int sceKernelWriteUnmapCommand(void* dst,
                                           uint64_t va,
                                           uint64_t size,
                                           uint64_t* outSize);
extern "C" int sceKernelWriteRemapCommand(void* dst,
                                           uint64_t vaNewStart,
                                           uint64_t vaOldStart,
                                           uint64_t size,
                                           uint64_t prot,
                                           uint64_t* outSize);
extern "C" int sceKernelWriteRemapWithGpuMaskIdCommand(void* dst,
                                                        uint64_t vaNewStart,
                                                        uint64_t vaOldStart,
                                                        uint64_t size,
                                                        uint64_t prot,
                                                        uint64_t gpuMaskId,
                                                        uint64_t* outSize);
extern "C" int sceKernelWriteMultiMapCommand(void* dst,
                                              uint64_t vaNewStart,
                                              uint64_t vaAliasStart,
                                              uint64_t size,
                                              uint64_t prot,
                                              uint64_t* outSize);
extern "C" int sceKernelWriteMultiMapWithGpuMaskIdCommand(void* dst,
                                                           uint64_t vaNewStart,
                                                           uint64_t vaAliasStart,
                                                           uint64_t size,
                                                           uint64_t prot,
                                                           uint64_t gpuMaskId,
                                                           uint64_t* outSize);
extern "C" int sceKernelWriteModifyProtectCommand(void* dst,
                                                   uint64_t va,
                                                   uint64_t size,
                                                   uint64_t prot,
                                                   uint64_t protMask,
                                                   uint64_t* outSize);
extern "C" int sceKernelWriteModifyProtectWithGpuMaskIdCommand(void* dst,
                                                                uint64_t va,
                                                                uint64_t size,
                                                                uint64_t prot,
                                                                uint64_t protMask,
                                                                uint64_t gpuMaskId,
                                                                uint64_t* outSize);
extern "C" int sceKernelWriteModifyMtypeProtectCommand(void* dst,
                                                        uint64_t va,
                                                        uint64_t size,
                                                        uint64_t type,
                                                        uint64_t prot,
                                                        uint64_t protMask,
                                                        uint64_t* outSize);
extern "C" int sceKernelWriteModifyMtypeProtectWithGpuMaskIdCommand(void* dst,
                                                                     uint64_t va,
                                                                     uint64_t size,
                                                                     uint64_t type,
                                                                     uint64_t prot,
                                                                     uint64_t protMask,
                                                                     uint64_t gpuMaskId,
                                                                     uint64_t* outSize);
