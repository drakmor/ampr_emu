/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (C) 2026 Roman Tarasov
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

// Auto-generated: C export layer for libSceAmpr drop-in replacement
#include <cstdint>
#include <cstddef>
#include <new>
#include "ampr.h"

using u64 = uint64_t;

#if defined(AMPR_EXPORT_NID_ONLY)
#define AMPR_EXPORT __attribute__((visibility("hidden")))
#else
#define AMPR_EXPORT __attribute__((visibility("default")))
#endif
#include <cstring>

static inline uint64_t ampr_sub_490(unsigned int n5, const char *a2) {
    // Ported from FW10 libSceAmpr.sprx decompilation: computes marker command size in uint32 words.
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
    if (!msg) return -22; // -EINVAL (we keep POSIX-style here)
    return (int64_t)(4 * ampr_sub_490(n5, msg));
}



extern "C" AMPR_EXPORT int64_t sceAmprAmmCommandBufferConstructor(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    new ((void*)a1) sce::Ampr::AmmCommandBuffer();
        return 0;
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmCommandBufferDestructor(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    ((sce::Ampr::AmmCommandBuffer*)a1)->~AmmCommandBuffer();
        return 0;
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmCommandBufferMap(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::AmmCommandBuffer*)a1)->map((uint64_t)a2, (uint64_t)a3, (int)a4, (int)a5);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmCommandBufferMapWithGpuMaskId(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::AmmCommandBuffer*)a1)->mapWithGpuMaskId((uint64_t)a2, (uint64_t)a3, (int)a4, (int)a5, (uint8_t)a6);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmCommandBufferMapDirect(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::AmmCommandBuffer*)a1)->mapDirect((uint64_t)a2, (uint64_t)a3, (size_t)a4, (int)a5, (int)a6);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmCommandBufferMapDirectWithGpuMaskId(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::AmmCommandBuffer*)a1)->mapDirectWithGpuMaskId((uint64_t)a2, (uint64_t)a3, (uint64_t)a4, (int)a5, (int)a6, (uint8_t)a7);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmCommandBufferUnmap(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::AmmCommandBuffer*)a1)->unmap((uint64_t)a2, (size_t)a3);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmCommandBufferRemap(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::AmmCommandBuffer*)a1)->remap((uint64_t)a2, (uint64_t)a3, (uint64_t)a4, (int)a5);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmCommandBufferRemapWithGpuMaskId(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::AmmCommandBuffer*)a1)->remapWithGpuMaskId((uint64_t)a2, (uint64_t)a3, (uint64_t)a4, (int)a5, (uint8_t)a6);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmCommandBufferMultiMap(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
        return ((sce::Ampr::AmmCommandBuffer*)a1)->multiMap((uint64_t)a2,(uint64_t)a3,(uint64_t)a4,(int)a5);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmCommandBufferMultiMapWithGpuMaskId(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
        return ((sce::Ampr::AmmCommandBuffer*)a1)->multiMapWithGpuMaskId((uint64_t)a2,(uint64_t)a3,(uint64_t)a4,(int)a5,(uint8_t)a6);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmCommandBufferModifyProtect(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::AmmCommandBuffer*)a1)->modifyProtect((uint64_t)a2, (uint64_t)a3, (int)a4, (int)a5);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmCommandBufferModifyProtectWithGpuMaskId(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::AmmCommandBuffer*)a1)->modifyProtectWithGpuMaskId((uint64_t)a2, (uint64_t)a3, (int)a4, (int)a5, (uint8_t)a6);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmCommandBufferModifyMtypeProtect(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::AmmCommandBuffer*)a1)->modifyMtypeProtect((uint64_t)a2, (uint64_t)a3, (int)a4, (int)a5, (int)a6);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmCommandBufferModifyMtypeProtectWithGpuMaskId(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::AmmCommandBuffer*)a1)->modifyMtypeProtectWithGpuMaskId((uint64_t)a2, (uint64_t)a3, (int)a4, (int)a5, (int)a6, (uint8_t)a7);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmCommandBufferMapAsPrt(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::AmmCommandBuffer*)a1)->mapAsPrt((uint64_t)a2, (uint64_t)a3);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmCommandBufferAllocatePaForPrt(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::AmmCommandBuffer*)a1)->allocatePaForPrt((uint64_t)a2, (uint64_t)a3, (int)a4, (int)a5);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmCommandBufferRemapIntoPrt(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::AmmCommandBuffer*)a1)->remapIntoPrt((uint64_t)a2, (uint64_t)a3, (uint64_t)a4, (int)a5);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmCommandBufferUnmapToPrt(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::AmmCommandBuffer*)a1)->unmapToPrt((uint64_t)a2, (uint64_t)a3);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmGetVirtualAddressRanges(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    sce::Ampr::Amm::getVirtualAddressRanges(*((sce::Ampr::AmmVirtualAddressRanges*)a1)); return 0;
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmGiveDirectMemory(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return sce::Ampr::Amm::giveDirectMemory((off_t)a1, (off_t)a2, (size_t)a3, (size_t)a4, (sce::Ampr::Amm::Usage)a5, (off_t*)a6);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmSubmitCommandBuffer(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return sce::Ampr::Amm::submitCommandBuffer((const sce::Ampr::AmmCommandBuffer*)a1, (sce::Ampr::Amm::Priority)a2);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmSubmitCommandBuffer2(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return sce::Ampr::Amm::submitCommandBuffer((sce::Ampr::AmmCommandBuffer*)a1, (sce::Ampr::Amm::Priority)a2, (SceAmmSubmitId*)a3);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmSubmitCommandBuffer3(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return sce::Ampr::Amm::submitCommandBufferAndGetResult((sce::Ampr::AmmCommandBuffer*)a1, (sce::Ampr::Amm::Priority)a2, (SceAmmResultBuffer*)a3, (SceAmmSubmitId*)a4);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmWaitCommandBufferCompletion(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return sce::Ampr::Amm::waitCommandBufferCompletion((SceAmmSubmitId)a1);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmGetUsageStatsData(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return 0;
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmSetPageTablePoolOccupancyNotificationThreshold(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return 0;
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmMeasureAmmCommandSizeMap(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    (void)a1;(void)a6;(void)a7;(void)a8;
    return (int64_t)sce::Ampr::MeasureAmmCommandSize::map(a2,a3,(int)a4,(int)a5);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmMeasureAmmCommandSizeMapDirect(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    (void)a1;(void)a7;(void)a8;
    return (int64_t)sce::Ampr::MeasureAmmCommandSize::mapDirect(a2,a3,(size_t)a4,(int)a5,(int)a6);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmMeasureAmmCommandSizeMapWithGpuMaskId(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    (void)a1;(void)a7;(void)a8;
    return (int64_t)sce::Ampr::MeasureAmmCommandSize::mapWithGpuMaskId(a2,a3,(int)a4,(int)a5,(uint8_t)a6);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmMeasureAmmCommandSizeMapDirectWithGpuMaskId(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    (void)a1;(void)a8;
    return (int64_t)sce::Ampr::MeasureAmmCommandSize::mapDirectWithGpuMaskId(a2,a3,(size_t)a4,(int)a5,(int)a6,(uint8_t)a7);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmMeasureAmmCommandSizeUnmap(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    (void)a1;(void)a4;(void)a5;(void)a6;(void)a7;(void)a8;
    return (int64_t)sce::Ampr::MeasureAmmCommandSize::unmap(a2,(size_t)a3);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmMeasureAmmCommandSizeRemap(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    (void)a1;(void)a8;
    return (int64_t)sce::Ampr::MeasureAmmCommandSize::remap(a2,a3,a4,(int)a5);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmMeasureAmmCommandSizeRemapWithGpuMaskId(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    (void)a1;
    return (int64_t)sce::Ampr::MeasureAmmCommandSize::remapWithGpuMaskId(a2,a3,a4,(int)a5,(uint8_t)a6);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmMeasureAmmCommandSizeMultiMap(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    (void)a1;(void)a7;(void)a8;
    return (int64_t)sce::Ampr::MeasureAmmCommandSize::multiMap(a2,a3,a4,(int)a5);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmMeasureAmmCommandSizeMultiMapWithGpuMaskId(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    (void)a1;(void)a8;
    return (int64_t)sce::Ampr::MeasureAmmCommandSize::multiMapWithGpuMaskId(a2,a3,a4,(int)a5,(uint8_t)a6);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmMeasureAmmCommandSizeModifyProtect(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    (void)a1;(void)a6;(void)a7;(void)a8;
    return (int64_t)sce::Ampr::MeasureAmmCommandSize::modifyProtect(a2,a3,(int)a4,(int)a5);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmMeasureAmmCommandSizeModifyMtypeProtect(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    (void)a1;(void)a7;(void)a8;
    return (int64_t)sce::Ampr::MeasureAmmCommandSize::modifyMtypeProtect(a2,a3,(int)a4,(int)a5,(int)a6);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmMeasureAmmCommandSizeModifyProtectWithGpuMaskId(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    (void)a1;(void)a8;
    return (int64_t)sce::Ampr::MeasureAmmCommandSize::modifyProtectWithGpuMaskId(a2,a3,(int)a4,(int)a5,(uint8_t)a6);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmMeasureAmmCommandSizeModifyMtypeProtectWithGpuMaskId(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    (void)a1;(void)a8;
    return (int64_t)sce::Ampr::MeasureAmmCommandSize::modifyMtypeProtectWithGpuMaskId(a2,a3,(int)a4,(int)a5,(int)a6,(uint8_t)a7);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmMeasureAmmCommandSizeMapAsPrt(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    (void)a1;(void)a4;(void)a5;(void)a6;(void)a7;(void)a8;
    return (int64_t)sce::Ampr::MeasureAmmCommandSize::mapAsPrt(a2,a3);
}


extern "C" AMPR_EXPORT int64_t sceAmprAmmMeasureAmmCommandSizeAllocatePaForPrt(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    (void)a1;(void)a7;(void)a8;
    return (int64_t)sce::Ampr::MeasureAmmCommandSize::allocatePaForPrt(a2,a3,(int)a4,(int)a5);
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferConstructor(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    new ((void*)a1) sce::Ampr::CommandBuffer();
        return 0;
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferDestructor(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    ((sce::Ampr::CommandBuffer*)a1)->~CommandBuffer();
        return 0;
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferReset(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::CommandBuffer*)a1)->reset();
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferSetBuffer(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::CommandBuffer*)a1)->setBuffer((void*)a2, (uint32_t)a3);
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferClearBuffer(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return (int64_t)(uintptr_t)((sce::Ampr::CommandBuffer*)a1)->clearBuffer();
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferGetType(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::CommandBuffer*)a1)->getType();
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferGetSize(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::CommandBuffer*)a1)->getSize();
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferGetBufferBaseAddress(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return (int64_t)(uintptr_t)((sce::Ampr::CommandBuffer*)a1)->getBufferBaseAddress();
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferGetNumCommands(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::CommandBuffer*)a1)->getNumCommands();
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferGetCurrentOffset(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::CommandBuffer*)a1)->getCurrentOffset();
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferWaitOnAddress_04_00(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    auto* cb = (sce::Ampr::CommandBuffer*)a1;
    return cb->waitOnAddress((volatile uint64_t*)a2,(uint64_t)a3,(sce::Ampr::WaitCompare)a4,(sce::Ampr::WaitFlush)a5);
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferWaitOnAddress(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::CommandBuffer*)a1)->waitOnAddress((volatile uint64_t*)a2, (uint64_t)a3, (sce::Ampr::WaitCompare)a4, (sce::Ampr::WaitFlush)a5);
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferWaitOnCounter_04_00(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    auto* cb = (sce::Ampr::CommandBuffer*)a1;
    // Best-effort mapping to FW10 WaitOnCounter.
    return cb->waitOnCounter((uint8_t)a2,(uint32_t)a3,(sce::Ampr::WaitCompare)a4,(sce::Ampr::WaitFlush)a5);
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferWaitOnCounter(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::CommandBuffer*)a1)->waitOnCounter((uint8_t)a2, (uint32_t)a3, (sce::Ampr::WaitCompare)a4, (sce::Ampr::WaitFlush)a5);
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferWriteAddress_04_00(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    auto* cb = (sce::Ampr::CommandBuffer*)a1;
    // a4 in FW10 selects opcode flavour; we only expose the OnCompletion variant.
    (void)a4;
    return cb->writeAddressOnCompletion((volatile uint64_t*)a2,(uint64_t)a3);
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferWriteAddressOnCompletion(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::CommandBuffer*)a1)->writeAddressOnCompletion((volatile uint64_t*)a2, (uint64_t)a3);
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferWriteCounter_04_00(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    auto* cb = (sce::Ampr::CommandBuffer*)a1;
    // Map legacy signature to OnCompletion.
    return cb->writeCounterOnCompletion((uint8_t)a2,(uint32_t)a3);
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferWriteCounterOnCompletion(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::CommandBuffer*)a1)->writeCounterOnCompletion((uint8_t)a2, (uint32_t)a3);
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferWriteKernelEventQueue_04_00(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    auto* cb = (sce::Ampr::CommandBuffer*)a1;
    // a5 selects completion flavour in FW10; we implement completion behaviour.
    (void)a5;
    return cb->writeKernelEventQueueOnCompletion((SceKernelEqueue)a2,(int32_t)a3,(uint64_t)a4);
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferWriteKernelEventQueueOnCompletion(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::CommandBuffer*)a1)->writeKernelEventQueueOnCompletion((SceKernelEqueue)(uintptr_t)a2, (int32_t)a3, (uint64_t)a4);
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferWriteAddressFromTimeCounter_04_00(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    auto* cb = (sce::Ampr::CommandBuffer*)a1;
    return cb->writeAddressFromTimeCounterOnCompletion((volatile uint64_t*)a2);
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferWriteAddressFromTimeCounterOnCompletion(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::CommandBuffer*)a1)->writeAddressFromTimeCounterOnCompletion((volatile uint64_t*)a2);
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferWriteAddressFromCounter_04_00(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    auto* cb = (sce::Ampr::CommandBuffer*)a1;
    return cb->writeAddressFromCounterOnCompletion((volatile uint64_t*)a2,(uint8_t)a3);
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferWriteAddressFromCounterOnCompletion(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::CommandBuffer*)a1)->writeAddressFromCounterOnCompletion((volatile uint64_t*)a2, (uint8_t)a3);
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferWriteAddressFromCounterPair_04_00(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    auto* cb = (sce::Ampr::CommandBuffer*)a1;
    return cb->writeAddressFromCounterPairOnCompletion((volatile uint64_t*)a2,(uint8_t)a3);
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferWriteAddressFromCounterPairOnCompletion(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::CommandBuffer*)a1)->writeAddressFromCounterPairOnCompletion((volatile uint64_t*)a2, (uint8_t)a3);
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferConstructNop(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    auto* cb = (sce::Ampr::CommandBuffer*)a1;
    // FW10 helper that forwards to nop.
    return cb->nop((uint32_t)a2);
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferNop(u64 a1,u64 a2,u64,u64,u64,u64,u64,u64) {
    // FW10 signature: (this, int numU32)
    return ((sce::Ampr::CommandBuffer*)a1)->nop((uint32_t)a2);
}



extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferNopWithData(u64 a1,u64 a2,u64 a3,u64,u64,u64,u64,u64) {
    // FW10 signature: (this, int numU32, const uint32_t* data)
    return ((sce::Ampr::CommandBuffer*)a1)->nop((uint32_t)a2, (const uint32_t*)a3);
}



extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferConstructMarker(u64 a1,u64 a2,u64 a3,u64 a4,u64,u64,u64,u64) {
    // FW10 signature: (this, unsigned int type, const char* msg, uint32_t* opt)
    // type values seen in FW10: 1=set,2=push,3=pop,5=setWithColor,6=pushWithColor
    const unsigned int type = (unsigned int)a2;
    const char* msg = (const char*)a3;
    const uint32_t* opt = (const uint32_t*)a4;

    auto* cb = (sce::Ampr::CommandBuffer*)a1;

    switch (type) {
        case 1: return cb->setMarker(msg);
        case 2: return cb->pushMarker(msg);
        case 3: return cb->popMarker();
        case 5: return cb->setMarker(msg, opt ? *opt : 0);
        case 6: return cb->pushMarker(msg, opt ? *opt : 0);
        default: return -38; // -ENOSYS for unknown marker types
    }
}



extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferSetMarkerWithColor(u64 a1,u64 a2,u64 a3,u64,u64,u64,u64,u64) {
    // FW10 signature: (this, char* msg, uint32_t* colorPtr)
    const char* msg = (const char*)a2;
    const uint32_t* colorPtr = (const uint32_t*)a3;
    const uint32_t color = colorPtr ? *colorPtr : 0;
    return ((sce::Ampr::CommandBuffer*)a1)->setMarker(msg, color);
}



extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferSetMarker(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::CommandBuffer*)a1)->setMarker((const char*)a2);
}


extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferPushMarkerWithColor(u64 a1,u64 a2,u64 a3,u64,u64,u64,u64,u64) {
    // FW10 signature: (this, char* msg, int color)
    return ((sce::Ampr::CommandBuffer*)a1)->pushMarker((const char*)a2, (uint32_t)a3);
}



extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferPushMarker(u64 a1,u64 a2,u64,u64,u64,u64,u64,u64) {
    // FW10 signature: (this, char* msg)
    return ((sce::Ampr::CommandBuffer*)a1)->pushMarker((const char*)a2);
}



extern "C" AMPR_EXPORT int64_t sceAmprCommandBufferPopMarker(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::CommandBuffer*)a1)->popMarker();
}


extern "C" AMPR_EXPORT int64_t sceAmprAprCommandBufferConstructor(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    new ((void*)a1) sce::Ampr::AprCommandBuffer();
        return 0;
}


extern "C" AMPR_EXPORT int64_t sceAmprAprCommandBufferDestructor(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    ((sce::Ampr::AprCommandBuffer*)a1)->~AprCommandBuffer();
        return 0;
}


extern "C" AMPR_EXPORT int64_t sceAmprAprCommandBufferReadFile(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::AprCommandBuffer*)a1)->readFile((SceAprFileId)a2, (void*)a3, (uint64_t)a4, (uint64_t)a5);
}


extern "C" AMPR_EXPORT int64_t sceAmprAprCommandBufferReadFileGather(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::AprCommandBuffer*)a1)->readFile((SceAprFileId)a2, (void*)a3, (uint64_t)a4, (uint64_t)a5);
}


extern "C" AMPR_EXPORT int64_t sceAmprAprCommandBufferReadFileScatter(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::AprCommandBuffer*)a1)->readFile((SceAprFileId)a2, (void*)a3, (uint64_t)a4, (uint64_t)a5);
}


extern "C" AMPR_EXPORT int64_t sceAmprAprCommandBufferReadFileGatherScatter(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::AprCommandBuffer*)a1)->readFile((SceAprFileId)a2, (void*)a3, (uint64_t)a4, (uint64_t)a5);
}


extern "C" AMPR_EXPORT int64_t sceAmprAprCommandBufferResetGatherScatterState(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::AprCommandBuffer*)a1)->resetGatherScatterState();
}


extern "C" AMPR_EXPORT int64_t sceAmprAprCommandBufferMapBegin(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::AprCommandBuffer*)a1)->mapBegin((uint64_t)a2,(uint64_t)a3,(uint64_t)a4,(uint64_t)a5);
}


extern "C" AMPR_EXPORT int64_t sceAmprAprCommandBufferMapDirectBegin(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::AprCommandBuffer*)a1)->mapDirectBegin((uint64_t)a2,(uint64_t)a3,(uint64_t)a4,(uint64_t)a5,(uint64_t)a6);
}


extern "C" AMPR_EXPORT int64_t sceAmprAprCommandBufferMapEnd(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    return ((sce::Ampr::AprCommandBuffer*)a1)->mapEnd();
}


extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeWaitOnAddress_04_00(u64 a1,u64 a2,u64,u64,u64,u64,u64,u64) {
    // FW10: returns size in bytes (8/12/16) based on whether value fits in 32-bit.
    (void)a1;
    return ((a2 >> 32) == 0) ? (int64_t)(4 * (unsigned int)(a2 != 0) + 8) : 16;
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeWaitOnAddress(u64 a1,u64 a2,u64,u64,u64,u64,u64,u64) {
    (void)a1;
    return ((a2 >> 32) == 0) ? (int64_t)(4 * (unsigned int)(a2 != 0) + 8) : 16;
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeWaitOnCounter_04_00(u64 a1,u64 a2,u64 a3,u64 a4,u64 a5,u64 a6,u64 a7,u64 a8) {
    // Port of FW10 decision tree (size in bytes). We keep it conservative if args are odd.
    (void)a1; (void)a4; (void)a7; (void)a8;
    uint8_t n8 = (uint8_t)a2;
    uint64_t n0xFFFF = (uint64_t)a3;
    uint8_t n2_1 = (uint8_t)a5;
    uint64_t n0xFFFF_1 = (uint64_t)a6;

    if (n8 == 1 && n0xFFFF <= 0xFF && n2_1 == 0) return 4;

    if (n0xFFFF > 0xFFFF) {
        uint64_t hi1 = n0xFFFF_1 >> 32;
        if ((n0xFFFF >> 32) != 0 || (hi1 != 0 && n2_1 != 0))
            return (int64_t)(8 * (unsigned int)(n2_1 != 0) + 12);
        return (int64_t)(4 * (unsigned int)(n2_1 != 0) + 8);
    }

    // Default: 8 bytes, but if n2_1 and n0xFFFF_1 looks like a "big" pointer, may expand.
    if (n2_1 && n0xFFFF_1 >= 0x10000ULL) {
        if ((n0xFFFF_1 >> 32) != 0)
            return (int64_t)(8 * (unsigned int)(n2_1 != 0) + 12);
        return (int64_t)(4 * (unsigned int)(n2_1 != 0) + 8);
    }

    return 8;
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeWaitOnCounter(u64 a1,u64 a2,u64,u64,u64,u64,u64,u64) {
    // FW10: 4 or 8 bytes depending on whether refValue >= 0x100.
    (void)a1;
    return (int64_t)(4 * (unsigned int)(a2 >= 0x100) + 4);
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeWriteAddress_04_00(u64 a1,u64 a2,u64,u64,u64,u64,u64,u64) {
    // FW10: 8/12 if immediate small, else 16.
    (void)a1;
    return ((a2 >> 34) == 0) ? (int64_t)(4 * (unsigned int)(a2 >= 4) + 8) : 16;
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeWriteAddressOnCompletion(u64 a1,u64 a2,u64,u64,u64,u64,u64,u64) {
    (void)a1;
    return ((a2 >> 34) == 0) ? (int64_t)(4 * (unsigned int)(a2 >= 4) + 8) : 16;
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeWriteAddressFromTimeCounter_04_00(u64,u64,u64,u64,u64,u64,u64,u64) {
    return 8;
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeWriteAddressFromTimeCounterOnCompletion(u64,u64,u64,u64,u64,u64,u64,u64) {
    return 8;
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeWriteAddressFromCounter_04_00(u64 a1,u64 a2,u64,u64,u64,u64,u64,u64) {
    (void)a1;
    return (int64_t)(4 * (unsigned int)(((uint8_t)a2) >= 4) + 8);
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeWriteAddressFromCounterOnCompletion(u64 a1,u64 a2,u64,u64,u64,u64,u64,u64) {
    (void)a1;
    return (int64_t)(4 * (unsigned int)(((uint8_t)a2) >= 4) + 8);
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeWriteAddressFromCounterPair_04_00(u64 a1,u64 a2,u64,u64,u64,u64,u64,u64) {
    (void)a1;
    return (int64_t)(4 * (unsigned int)(((uint8_t)a2) >= 4) + 8);
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeWriteAddressFromCounterPairOnCompletion(u64 a1,u64 a2,u64,u64,u64,u64,u64,u64) {
    (void)a1;
    return (int64_t)(4 * (unsigned int)(((uint8_t)a2) >= 4) + 8);
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeWriteCounter_04_00(u64,u64 a2,u64 a3,u64 a4,u64,u64,u64,u64) {
    // Simplified but safe: matches the "expanded" size path.
    (void)a2; (void)a4;
    return (int64_t)(4 * (unsigned int)((a3 >> 32) != 0) + 8);
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeWriteCounterOnCompletion(u64,u64 a2,u64,u64,u64,u64,u64,u64) {
    return (int64_t)(4 * (unsigned int)(a2 >= 0x1000) + 4);
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeWriteKernelEventQueue_04_00(u64,u64,u64,u64,u64,u64,u64,u64) {
    return 20;
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeWriteKernelEventQueueOnCompletion(u64,u64,u64,u64,u64,u64,u64,u64) {
    return 20;
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeNop(u64 a1,u64,u64,u64,u64,u64,u64,u64) {
    // FW10: returns 4 * numU32 bytes
    return (int64_t)(4 * (uint32_t)a1);
}


extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeNopWithData(u64 a1,u64,u64,u64,u64,u64,u64,u64) {
    // FW10: same as nop in bytes
    return (int64_t)(4 * (uint32_t)a1);
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeReadFile(u64 a1,u64 a2,u64 a3,u64 a4,u64,u64,u64,u64) {
    (void)a1; (void)a2; (void)a3;
    return (int64_t)(4 * (unsigned int)((a4 >> 32) != 0) + 20);
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeReadFileGather(u64 a1,u64 a2,u64,u64,u64,u64,u64,u64) {
    (void)a1;
    return (int64_t)(4 * (unsigned int)(a2 >= 0x40000ULL) + 8);
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeReadFileScatter(u64,u64,u64,u64,u64,u64,u64,u64) {
    return 12;
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeReadFileGatherScatter(u64,u64,u64,u64 a4,u64,u64,u64,u64) {
    // a4 corresponds to size (uint64_t) in FW10 decomp.
    return (int64_t)(4 * (unsigned int)((a4 >> 32) != 0) + 16);
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeResetGatherScatterState(u64,u64,u64,u64,u64,u64,u64,u64) {
    return 4;
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeMapBegin(u64,u64,u64,u64,u64,u64,u64,u64) {
    return 12;
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeMapDirectBegin(u64,u64,u64,u64,u64,u64,u64,u64) {
    return 16;
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeMapEnd(u64,u64,u64,u64,u64,u64,u64,u64) {
    return 4;
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeSetMarkerWithColor(u64 a1,u64 a2,u64,u64,u64,u64,u64,u64) {
    // signature in FW10: (char* msg, int color)
    (void)a2;
    return ampr_measure_marker_bytes(5u, (const char*)a1);
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizeSetMarker(u64 a1,u64,u64,u64,u64,u64,u64,u64) {
    return ampr_measure_marker_bytes(1u, (const char*)a1);
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizePushMarkerWithColor(u64 a1,u64 a2,u64,u64,u64,u64,u64,u64) {
    (void)a2;
    return ampr_measure_marker_bytes(6u, (const char*)a1);
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizePushMarker(u64 a1,u64,u64,u64,u64,u64,u64,u64) {
    return ampr_measure_marker_bytes(2u, (const char*)a1);
}



extern "C" AMPR_EXPORT int64_t sceAmprMeasureCommandSizePopMarker(u64,u64,u64,u64,u64,u64,u64,u64) {
    return 4;
}
