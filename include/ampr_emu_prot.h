/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Shared protection-mask helpers.
 */

#pragma once

#include <kernel.h>

#include <cstdint>

namespace sce::Ampr::Emu {

inline constexpr uint64_t protWithCpuRwForAmprWrite(uint64_t prot) {
    if ((prot & SCE_KERNEL_PROT_AMPR_WRITE) == 0 ||
        (prot & SCE_KERNEL_PROT_CPU_RW) != 0) {
        return prot;
    }
    return (prot & ~static_cast<uint64_t>(SCE_KERNEL_PROT_CPU_READ)) |
           SCE_KERNEL_PROT_CPU_RW;
}

inline constexpr uint64_t protMaskWithCpuRwForAdjustedProt(uint64_t originalProt,
                                                           uint64_t adjustedProt,
                                                           uint64_t protMask) {
    const uint64_t changedCpuProtBits =
        (originalProt ^ adjustedProt) & SCE_KERNEL_PROT_CPU_ALL;
    return changedCpuProtBits != 0
        ? (protMask | changedCpuProtBits)
        : protMask;
}

static_assert(protWithCpuRwForAmprWrite(SCE_KERNEL_PROT_CPU_READ |
                                        SCE_KERNEL_PROT_AMPR_ALL) ==
              (SCE_KERNEL_PROT_CPU_RW | SCE_KERNEL_PROT_AMPR_ALL),
              "AMPR write promotion must replace CPU_READ with CPU_RW");
static_assert(protMaskWithCpuRwForAdjustedProt(
                  SCE_KERNEL_PROT_CPU_READ | SCE_KERNEL_PROT_AMPR_ALL,
                  SCE_KERNEL_PROT_CPU_RW | SCE_KERNEL_PROT_AMPR_ALL,
                  SCE_KERNEL_PROT_AMPR_ALL) ==
              (SCE_KERNEL_PROT_CPU_READ |
               SCE_KERNEL_PROT_CPU_RW |
               SCE_KERNEL_PROT_AMPR_ALL),
              "AMPR write promotion mask must cover removed and added CPU bits");

} // namespace sce::Ampr::Emu
