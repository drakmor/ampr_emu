/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * AMPR command-size measurement implementation.
 */

#include "ampr_emu_measure_commands.h"
#include "ampr_emu_amm.h"

namespace sce::Ampr::Emu {
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
} // namespace sce::Ampr::Emu
