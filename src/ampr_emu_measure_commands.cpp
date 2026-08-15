/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * AMPR command-size measurement implementation.
 */

#include "ampr_emu_measure_commands.h"
#include "ampr_emu_amm.h"
#include "ampr_emu_command_buffer_apr.h"
#include "ampr_emu_errno.h"

#include <cstring>

namespace {

static uint32_t measure_write_counter_dwords(uint64_t value, uint8_t valueWidth, uint8_t counterMode) {
    if (valueWidth == 1u && counterMode == 0u && value < 0x1000u) {
        return 1u;
    }
    if ((value >> 32) == 0) {
        return 2u;
    }
    return 3u;
}

static uint32_t measure_wait_counter_dwords(uint8_t valueWidth, uint64_t refValue, uint8_t extraFlag, uint64_t extraValue) {
    uint32_t dwords = 1u;
    if (refValue >= 0x100ull || (extraFlag | (valueWidth ^ 1u)) != 0u) {
        if (refValue > 0xFFFFull) {
            if ((refValue >> 32) != 0 || (extraFlag != 0u && (extraValue >> 32) != 0)) {
                return 2u * (extraFlag != 0u) + 3u;
            }
            return (extraFlag != 0u) ? 3u : 2u;
        }
        dwords = 2u;
        if (extraFlag != 0u && extraValue >= 0x10000ull) {
            if ((extraValue >> 32) != 0) {
                return 5u;
            }
            return 3u;
        }
    }
    return dwords;
}

} // namespace
// ---------------- Measure*CommandSize (retail byte-size formulas for encoded records)
namespace sce::Ampr::Emu {
int measureCommandWaitOnAddress(volatile uint64_t*, uint64_t refValue, WaitCompare, WaitFlush) {
    uint32_t dwords = 4;
    if ((refValue >> 32) == 0) dwords = 3u - (refValue == 0 ? 1u : 0u);
    return (int)(dwords * 4u);
}

int measureCommandWaitOnCounter(uint8_t, uint32_t refValue, WaitCompare, WaitFlush) {
    uint32_t dwords = (refValue < 0x100u) ? 1u : 2u;
    return (int)(dwords * 4u);
}

int measureCommandWaitOnCounter(uint8_t, CounterAccessSizeAndOffset eAccessSizeAndOffset, uint64_t refValue, WaitCompare, WaitOnCounterMaskOperation eMaskOp, uint64_t mask, WaitFlush) {
    return (int)(measure_wait_counter_dwords((uint8_t)eAccessSizeAndOffset, refValue, (uint8_t)eMaskOp, mask) * 4u);
}

int measureCommandWaitOnCounter(uint8_t counterIndex, CounterAccessSizeAndOffset eAccessSizeAndOffset, uint64_t refValue, WaitCompare eCmp, WaitFlush eFlush) {
    return measureCommandWaitOnCounter(counterIndex, eAccessSizeAndOffset, refValue, eCmp, WaitOnCounterMaskOperation::kDisabled, 0, eFlush);
}

int measureCommandWaitOnCounter(uint8_t counterIndex, uint32_t refValue, WaitCompare eCmp, WaitOnCounterMaskOperation eMaskOp, uint32_t mask, WaitFlush eFlush) {
    return measureCommandWaitOnCounter(counterIndex, CounterAccessSizeAndOffset::kSize4, refValue, eCmp, eMaskOp, mask, eFlush);
}

int measureCommandWriteAddressOnCompletion(volatile uint64_t*, uint64_t value) {
    uint32_t dwords = 4;
    if (value < 0x400000000ull) dwords = (value < 4ull) ? 2u : 3u;
    return (int)(dwords * 4u);
}

int measureCommandWriteAddressImmediately(volatile uint64_t* address, uint64_t value) {
    return measureCommandWriteAddressOnCompletion(address, value);
}

int measureCommandWriteCounterOnCompletion(uint8_t, uint32_t value) {
    uint32_t dwords = (value < 0x1000u) ? 1u : 2u;
    return (int)(dwords * 4u);
}

int measureCommandWriteCounterOnCompletion(uint8_t, CounterAccessSizeAndOffset eAccessSizeAndOffset, uint64_t value, WriteCounterOperation eWriteOp) {
    return (int)(measure_write_counter_dwords(value, (uint8_t)eAccessSizeAndOffset, (uint8_t)eWriteOp) * 4u);
}

int measureCommandWriteCounterOnCompletion(uint8_t counterIndex, uint32_t value, WriteCounterOperation eWriteOp) {
    return measureCommandWriteCounterOnCompletion(counterIndex, CounterAccessSizeAndOffset::kSize4, value, eWriteOp);
}

int measureCommandWriteCounterImmediately(uint8_t counterIndex, CounterAccessSizeAndOffset eAccessSizeAndOffset, uint64_t value, WriteCounterOperation eWriteOp) {
    return measureCommandWriteCounterOnCompletion(counterIndex, eAccessSizeAndOffset, value, eWriteOp);
}

int measureCommandWriteCounterImmediately(uint8_t counterIndex, uint32_t value, WriteCounterOperation eWriteOp) {
    return measureCommandWriteCounterOnCompletion(counterIndex, value, eWriteOp);
}

int measureCommandWriteCounterImmediately(uint8_t counterIndex, uint32_t value) {
    return measureCommandWriteCounterOnCompletion(counterIndex, value);
}

int measureCommandWriteKernelEventQueueOnCompletion(SceKernelEqueue, int32_t, uint64_t) { return 20; }
int measureCommandWriteKernelEventQueueImmediately(SceKernelEqueue eq, int32_t id, uint64_t data) { return measureCommandWriteKernelEventQueueOnCompletion(eq, id, data); }
int measureCommandWriteAddressFromTimeCounterOnCompletion(volatile uint64_t*) { return 8; }
int measureCommandWriteAddressFromTimeCounterImmediately(volatile uint64_t* address) { return measureCommandWriteAddressFromTimeCounterOnCompletion(address); }
int measureCommandWriteAddressFromCounterOnCompletion(volatile uint64_t*, uint8_t counterIndex) { return (int)(4 * (unsigned int)(counterIndex >= 4) + 8); }
int measureCommandWriteAddressFromCounterImmediately(volatile uint64_t* address, uint8_t counterIndex) { return measureCommandWriteAddressFromCounterOnCompletion(address, counterIndex); }
int measureCommandWriteAddressFromCounterPairOnCompletion(volatile uint64_t*, uint8_t counterIndex) { return (int)(4 * (unsigned int)(counterIndex >= 4) + 8); }
int measureCommandWriteAddressFromCounterPairImmediately(volatile uint64_t* address, uint8_t counterIndex) { return measureCommandWriteAddressFromCounterPairOnCompletion(address, counterIndex); }
int measureCommandNop(uint32_t numU32) { return (int)(numU32 * 4u); }
int measureCommandNop(uint32_t numU32, const uint32_t*) { return (int)((numU32 + 1u) * 4u); }

int measureAmmMap(uint64_t va, uint64_t size, int type, int prot) {
    return measureAmmKernelRecord(
        [&](uint64_t* out) { return ammWriteMapCommand(nullptr, va, size, static_cast<uint32_t>(type), static_cast<uint32_t>(prot), out); });
}
int measureAmmMapWithGpuMaskId(uint64_t va, uint64_t size, int type, int prot, uint8_t gpuMaskId) {
    return measureAmmKernelRecord(
        [&](uint64_t* out) { return ammWriteMapWithGpuMaskIdCommand(nullptr, va, size, static_cast<uint32_t>(type), static_cast<uint32_t>(prot), gpuMaskId, out); });
}
int measureAmmMapDirect(uint64_t va, uint64_t dmemOffset, size_t size, int type, int prot) {
    return measureAmmKernelRecord(
        [&](uint64_t* out) { return ammWriteMapDirectCommand(nullptr, va, dmemOffset, size, static_cast<uint32_t>(type), static_cast<uint32_t>(prot), out); });
}
int measureAmmMapDirectWithGpuMaskId(uint64_t va, uint64_t dmemOffset, uint64_t size, int type, int prot, uint8_t gpuMaskId) {
    return measureAmmKernelRecord(
        [&](uint64_t* out) { return ammWriteMapDirectWithGpuMaskIdCommand(nullptr, va, dmemOffset, size, static_cast<uint32_t>(type), static_cast<uint32_t>(prot), gpuMaskId, out); });
}
int measureAmmUnmap(uint64_t va, size_t size) {
    return measureAmmKernelRecord([&](uint64_t* out) { return ammWriteUnmapCommand(nullptr, va, size, out); });
}
int measureAmmRemap(uint64_t vaNewStart, uint64_t vaOldStart, uint64_t vaSize, int prot) {
    return measureAmmKernelRecord(
        [&](uint64_t* out) { return ammWriteRemapCommand(nullptr, vaNewStart, vaOldStart, vaSize, static_cast<uint32_t>(prot), out); });
}
int measureAmmRemapWithGpuMaskId(uint64_t vaNewStart, uint64_t vaOldStart, uint64_t vaSize, int prot, uint8_t gpuMaskId) {
    return measureAmmKernelRecord(
        [&](uint64_t* out) { return ammWriteRemapWithGpuMaskIdCommand(nullptr, vaNewStart, vaOldStart, vaSize, static_cast<uint32_t>(prot), gpuMaskId, out); });
}
int measureAmmMultiMap(uint64_t vaNewStart, uint64_t vaAliasStart, uint64_t vaSize, int prot) {
    return measureAmmKernelRecord(
        [&](uint64_t* out) { return ammWriteMultiMapCommand(nullptr, vaNewStart, vaAliasStart, vaSize, static_cast<uint32_t>(prot), out); });
}
int measureAmmMultiMapWithGpuMaskId(uint64_t vaNewStart, uint64_t vaAliasStart, uint64_t vaSize, int prot, uint8_t gpuMaskId) {
    return measureAmmKernelRecord(
        [&](uint64_t* out) { return ammWriteMultiMapWithGpuMaskIdCommand(nullptr, vaNewStart, vaAliasStart, vaSize, static_cast<uint32_t>(prot), gpuMaskId, out); });
}
int measureAmmModifyProtect(uint64_t va, uint64_t size, int prot, int protMask) {
    return measureAmmKernelRecord(
        [&](uint64_t* out) { return ammWriteModifyProtectCommand(nullptr, va, size, static_cast<uint32_t>(prot), static_cast<uint32_t>(protMask), out); });
}
int measureAmmModifyProtectWithGpuMaskId(uint64_t va, uint64_t size, int prot, int protMask, uint8_t gpuMaskId) {
    return measureAmmKernelRecord(
        [&](uint64_t* out) { return ammWriteModifyProtectWithGpuMaskIdCommand(nullptr, va, size, static_cast<uint32_t>(prot), static_cast<uint32_t>(protMask), gpuMaskId, out); });
}
int measureAmmModifyMtypeProtect(uint64_t va, uint64_t size, int type, int prot, int protMask) {
    return measureAmmKernelRecord(
        [&](uint64_t* out) { return ammWriteModifyMtypeProtectCommand(nullptr, va, size, static_cast<uint32_t>(type), static_cast<uint32_t>(prot), static_cast<uint32_t>(protMask), out); });
}
int measureAmmModifyMtypeProtectWithGpuMaskId(uint64_t va, uint64_t size, int type, int prot, int protMask, uint8_t gpuMaskId) {
    return measureAmmKernelRecord(
        [&](uint64_t* out) { return ammWriteModifyMtypeProtectWithGpuMaskIdCommand(nullptr, va, size, static_cast<uint32_t>(type), static_cast<uint32_t>(prot), static_cast<uint32_t>(protMask), gpuMaskId, out); });
}
int measureAmmMapAsPrt(uint64_t va, uint64_t size) {
    return measureAmmKernelRecord([&](uint64_t* out) { return ammWriteMapCommand2(nullptr, va, size, 0, 0, 1, out); });
}
int measureAmmAllocatePaForPrt(uint64_t va, uint64_t size, int type, int prot) {
    return measureAmmKernelRecord(
        [&](uint64_t* out) { return ammWriteModifyMtypeProtectCommand(nullptr, va, size, static_cast<uint32_t>(type), static_cast<uint32_t>(prot), 1019, out); });
}
int measureAmmRemapIntoPrt(uint64_t vaPrtStart, uint64_t vaOldStart, uint64_t vaSize, int prot) {
    return measureAmmKernelRecord(
        [&](uint64_t* out) { return ammWriteRemapIntoPrtCommand(nullptr, vaPrtStart, vaOldStart, vaSize, prot, 1011, out); });
}

static int measure_marker_bytes(unsigned int n5, const char* msg) {
    if (!msg) {
        return SCE_KERNEL_ERROR_EINVAL;
    }

    const int len = (int)std::strlen(msg) + 1;
    const int firstPayloadBytes = 4 * (n5 < 5) + 56;
    const int firstPayloadDwords = 1 - ((int)(n5 < 5) - 1);
    if (len <= firstPayloadBytes) {
        return (int)(4u * (uint32_t)(firstPayloadDwords + (unsigned int)(((uint64_t)(len + 3)) >> 2)));
    }

    uint32_t dwords = (uint32_t)(firstPayloadBytes >> 2) + (uint32_t)firstPayloadDwords;
    for (uint32_t remaining = (uint32_t)(len - firstPayloadBytes); remaining != 0; ) {
        uint32_t chunk = remaining < 60u ? remaining : 60u;
        dwords += ((chunk + 3u) >> 2) + 1u;
        remaining -= chunk;
    }
    return (int)(dwords * 4u);
}

int measureAprReadFile(SceAprFileId, void* buffer, uint64_t length, uint64_t offset) {
    const int rc = aprValidateReadArgs(buffer, length, offset);
    if (rc != 0) {
        return rc;
    }
    return ((offset >> 32) != 0) ? 24 : 20;
}
int measureAprReadFileGather(uint64_t length, uint64_t offset) {
    int rc = aprValidateReadLength(length);
    if (rc != 0) {
        return rc;
    }
    rc = aprValidateReadOffset(offset);
    if (rc != 0) {
        return rc;
    }
    return (offset >= 0x40000ull) ? 12 : 8;
}
int measureAprReadFileScatter(void* buffer, uint64_t length) {
    const int rc = aprValidateReadArgs(buffer, length, 0);
    if (rc != 0) {
        return rc;
    }
    return 12;
}
int measureAprReadFileGatherScatter(void* buffer, uint64_t length, uint64_t offset) {
    const int rc = aprValidateReadArgs(buffer, length, offset);
    if (rc != 0) {
        return rc;
    }
    return ((offset >> 32) != 0) ? 20 : 16;
}
int measureAprResetGatherScatterState() { return 4; }
int measureAprMapBegin(uint64_t va, uint64_t size, int type, int prot) {
    const int rc = aprValidateMapBeginArgs(va, size, type, prot);
    if (rc != 0) {
        return rc;
    }
    return 12;
}
int measureAprMapDirectBegin(uint64_t va, uint64_t dmemOffset, size_t size, int type, int prot) {
    const int rc = aprValidateMapDirectBeginArgs(va, dmemOffset, size, type, prot);
    if (rc != 0) {
        return rc;
    }
    return 16;
}
int measureAprMapEnd() { return 4; }
int measureAprSetMarker(const char* msg, uint32_t) { return measure_marker_bytes(5u, msg); }
int measureAprSetMarker(const char* msg) { return measure_marker_bytes(1u, msg); }
int measureAprPushMarker(const char* msg, uint32_t) { return measure_marker_bytes(6u, msg); }
int measureAprPushMarker(const char* msg) { return measure_marker_bytes(2u, msg); }
int measureAprPopMarker() { return 4; }

} // namespace sce::Ampr::Emu
