/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * APR command-buffer private bridge.
 */

#pragma once

#include "ampr.h"
#include "ampr_emu_command_packing.h"

#include <cstddef>
#include <cstdint>

namespace sce::Ampr::Emu {

bool aprCommandBufferHasScatterGatherState(SceAmprCommandBuffer* cb);
bool aprCommandBufferHasMapState(SceAmprCommandBuffer* cb);

int aprValidateReadLength(uint64_t length);
int aprValidateReadOffset(uint64_t offset);
int aprValidateReadArgs(const void* buffer, uint64_t length, uint64_t offset);
int aprValidateMapBeginArgs(uint64_t va, uint64_t size, int type, int prot);
int aprValidateMapDirectBeginArgs(uint64_t va, uint64_t dmemOffset, uint64_t size, int type, int prot);
int aprCommandMapProt(int prot);

int aprCommandBufferAppendReadFile(SceAmprCommandBuffer* cb,
                                   SceAprFileId fileId,
                                   void* buffer,
                                   uint64_t length,
                                   uint64_t offset);
int aprCommandBufferAppendReadGather(SceAmprCommandBuffer* cb, uint64_t length, uint64_t offset);
int aprCommandBufferAppendReadScatter(SceAmprCommandBuffer* cb, void* buffer, uint64_t length);
int aprCommandBufferAppendReadGatherScatter(SceAmprCommandBuffer* cb,
                                            void* buffer,
                                            uint64_t length,
                                            uint64_t offset);
int aprCommandBufferAppendResetGatherScatterState(SceAmprCommandBuffer* cb);
int aprCommandBufferAppendMapBegin(SceAmprCommandBuffer* cb,
                                   uint64_t va,
                                   uint64_t size,
                                   int type,
                                   int commandProt);
int aprCommandBufferAppendMapDirectBegin(SceAmprCommandBuffer* cb,
                                         uint64_t va,
                                         uint64_t dmemOffset,
                                         size_t size,
                                         int type,
                                         int commandProt);
int aprCommandBufferAppendMapEnd(SceAmprCommandBuffer* cb);

} // namespace sce::Ampr::Emu
