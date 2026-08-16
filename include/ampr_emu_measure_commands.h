/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Internal command-size measurement helpers.
 */

#pragma once

#include <cstddef>
#include <cstdint>

namespace sce::Ampr::Emu {

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
} // namespace sce::Ampr::Emu
