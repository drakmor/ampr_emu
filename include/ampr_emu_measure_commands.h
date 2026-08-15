/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Internal command-size measurement helpers.
 */

#pragma once

#include "ampr_emu_command_types.h"

#include <kernel.h>

namespace sce::Ampr::Emu {

int measureCommandWaitOnAddress(volatile uint64_t*, uint64_t, WaitCompare, WaitFlush);
int measureCommandWaitOnCounter(uint8_t, uint32_t, WaitCompare, WaitFlush);
int measureCommandWaitOnCounter(uint8_t, CounterAccessSizeAndOffset, uint64_t, WaitCompare, WaitOnCounterMaskOperation, uint64_t, WaitFlush);
int measureCommandWaitOnCounter(uint8_t, CounterAccessSizeAndOffset, uint64_t, WaitCompare, WaitFlush);
int measureCommandWaitOnCounter(uint8_t, uint32_t, WaitCompare, WaitOnCounterMaskOperation, uint32_t, WaitFlush);
int measureCommandWriteAddressOnCompletion(volatile uint64_t*, uint64_t);
int measureCommandWriteAddressImmediately(volatile uint64_t*, uint64_t);
int measureCommandWriteCounterOnCompletion(uint8_t, uint32_t);
int measureCommandWriteCounterOnCompletion(uint8_t, CounterAccessSizeAndOffset, uint64_t, WriteCounterOperation);
int measureCommandWriteCounterOnCompletion(uint8_t, uint32_t, WriteCounterOperation);
int measureCommandWriteCounterImmediately(uint8_t, CounterAccessSizeAndOffset, uint64_t, WriteCounterOperation);
int measureCommandWriteCounterImmediately(uint8_t, uint32_t, WriteCounterOperation);
int measureCommandWriteCounterImmediately(uint8_t, uint32_t);
int measureCommandWriteKernelEventQueueOnCompletion(SceKernelEqueue, int32_t, uint64_t);
int measureCommandWriteKernelEventQueueImmediately(SceKernelEqueue, int32_t, uint64_t);
int measureCommandWriteAddressFromTimeCounterOnCompletion(volatile uint64_t*);
int measureCommandWriteAddressFromTimeCounterImmediately(volatile uint64_t*);
int measureCommandWriteAddressFromCounterOnCompletion(volatile uint64_t*, uint8_t);
int measureCommandWriteAddressFromCounterImmediately(volatile uint64_t*, uint8_t);
int measureCommandWriteAddressFromCounterPairOnCompletion(volatile uint64_t*, uint8_t);
int measureCommandWriteAddressFromCounterPairImmediately(volatile uint64_t*, uint8_t);
int measureCommandNop(uint32_t);
int measureCommandNop(uint32_t, const uint32_t*);

int measureAmmMap(uint64_t, uint64_t, int, int);
int measureAmmMapWithGpuMaskId(uint64_t, uint64_t, int, int, uint8_t);
int measureAmmMapDirect(uint64_t, uint64_t, size_t, int, int);
int measureAmmMapDirectWithGpuMaskId(uint64_t, uint64_t, uint64_t, int, int, uint8_t);
int measureAmmUnmap(uint64_t, size_t);
int measureAmmRemap(uint64_t, uint64_t, uint64_t, int);
int measureAmmRemapWithGpuMaskId(uint64_t, uint64_t, uint64_t, int, uint8_t);
int measureAmmMultiMap(uint64_t, uint64_t, uint64_t, int);
int measureAmmMultiMapWithGpuMaskId(uint64_t, uint64_t, uint64_t, int, uint8_t);
int measureAmmModifyProtect(uint64_t, uint64_t, int, int);
int measureAmmModifyProtectWithGpuMaskId(uint64_t, uint64_t, int, int, uint8_t);
int measureAmmModifyMtypeProtect(uint64_t, uint64_t, int, int, int);
int measureAmmModifyMtypeProtectWithGpuMaskId(uint64_t, uint64_t, int, int, int, uint8_t);
int measureAmmMapAsPrt(uint64_t, uint64_t);
int measureAmmAllocatePaForPrt(uint64_t, uint64_t, int, int);
int measureAmmRemapIntoPrt(uint64_t, uint64_t, uint64_t, int);

int measureAprReadFile(SceAprFileId, void*, uint64_t, uint64_t);
int measureAprReadFileGather(uint64_t, uint64_t);
int measureAprReadFileScatter(void*, uint64_t);
int measureAprReadFileGatherScatter(void*, uint64_t, uint64_t);
int measureAprResetGatherScatterState();
int measureAprMapBegin(uint64_t, uint64_t, int, int);
int measureAprMapDirectBegin(uint64_t, uint64_t, size_t, int, int);
int measureAprMapEnd();
int measureAprSetMarker(const char*, uint32_t);
int measureAprSetMarker(const char*);
int measureAprPushMarker(const char*, uint32_t);
int measureAprPushMarker(const char*);
int measureAprPopMarker();

} // namespace sce::Ampr::Emu
