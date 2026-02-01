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

#include "ampr.h"
#include <kernel.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>

using namespace sce::Ampr;

static int get_iters(int argc, char** argv) {
    if (argc < 2 || !argv || !argv[1]) return 200;
    int v = std::atoi(argv[1]);
    return v > 0 ? v : 200;
}

int main(int argc, char** argv) {
    const int iters = get_iters(argc, argv);
    std::printf("AMPR stress (%d iters)\n", iters);

    // Stress DMEM allocate/map/unmap/release.
    for (int i = 0; i < iters; ++i) {
        const size_t len = PAGE_SIZE * 4;
        off_t off = 0;
        int rc = sceKernelAllocateDirectMemory(0, SCE_KERNEL_MAIN_DMEM_SIZE, len, PAGE_SIZE, SCE_KERNEL_MTYPE_C, &off);
        if (rc != 0) {
            std::printf("FAIL dmem alloc i=%d rc=0x%x\n", i, rc);
            return 1;
        }
        void* p = nullptr;
        rc = sceKernelMapDirectMemory(&p, len, SCE_KERNEL_PROT_CPU_RW | SCE_KERNEL_PROT_AMPR_RW, 0, off, PAGE_SIZE);
        if (rc != 0) {
            std::printf("FAIL dmem map i=%d rc=0x%x\n", i, rc);
            return 1;
        }
        std::memset(p, (i & 0xFF), len);
        rc = sceKernelMunmap(p, len);
        if (rc != 0) {
            std::printf("FAIL dmem unmap i=%d rc=0x%x\n", i, rc);
            return 1;
        }
        rc = sceKernelReleaseDirectMemory(off, len);
        if (rc != 0) {
            std::printf("FAIL dmem release i=%d rc=0x%x\n", i, rc);
            return 1;
        }
    }
    std::printf("[ok] dmem alloc/map/unmap/release\n");

    // Stress AMM->equeue completion signal path.
    SceKernelEqueue eq = nullptr;
    int rc = sceKernelCreateEqueue(&eq, "ampr.stress");
    if (rc != 0) {
        std::printf("FAIL sceKernelCreateEqueue rc=0x%x\n", rc);
        return 1;
    }
    rc = sceKernelAddAmprEvent(eq, 0x900, (void*)0x1234);
    if (rc != 0) {
        std::printf("FAIL sceKernelAddAmprEvent rc=0x%x\n", rc);
        return 1;
    }

    AmmCommandBuffer cb;
    void* cmdbuf = std::aligned_alloc(64, 4096);
    if (!cmdbuf) return 1;
    std::memset(cmdbuf, 0, 4096);
    rc = cb.setBuffer(cmdbuf, 4096);
    if (rc != 0) {
        std::printf("FAIL cb.setBuffer rc=0x%x\n", rc);
        return 1;
    }

    for (int i = 0; i < iters; ++i) {
        rc = cb.reset();
        if (rc != 0) {
            std::printf("FAIL cb.reset i=%d rc=0x%x\n", i, rc);
            return 1;
        }
        rc = cb.writeKernelEventQueueOnCompletion(eq, 0x900, (uint64_t)i);
        if (rc != 0) {
            std::printf("FAIL writeKernelEventQueueOnCompletion i=%d rc=0x%x\n", i, rc);
            return 1;
        }

        SceAmmResultBuffer res{};
        SceAmmSubmitId sid{};
        rc = Amm::submitCommandBufferAndGetResult(&cb, Amm::Priority::kHigh, &res, &sid);
        if (rc != 0) {
            std::printf("FAIL Amm::submit i=%d rc=0x%x\n", i, rc);
            return 1;
        }
        rc = Amm::waitCommandBufferCompletion(sid);
        if (rc != 0) {
            std::printf("FAIL Amm::wait i=%d rc=0x%x\n", i, rc);
            return 1;
        }
        if (res.result != 0) {
            std::printf("FAIL Amm result i=%d result=0x%x off=0x%x\n", i, res.result, res.errorOffset);
            return 1;
        }

        SceKernelEvent ev{};
        int n = 0;
        SceKernelUseconds to = 1 * 1000 * 1000;
        rc = sceKernelWaitEqueue(eq, &ev, 1, &n, &to);
        if (rc != 0 || n != 1 || sceKernelGetEventId(&ev) != 0x900 || (uint64_t)sceKernelGetEventData(&ev) != (uint64_t)i) {
            std::printf("FAIL equeue i=%d rc=0x%x n=%d id=0x%lx data=0x%lx\n",
                        i, rc, n, (unsigned long)sceKernelGetEventId(&ev), (unsigned long)sceKernelGetEventData(&ev));
            return 1;
        }
    }

    rc = sceKernelDeleteAmprEvent(eq, 0x900);
    if (rc != 0) {
        std::printf("FAIL sceKernelDeleteAmprEvent rc=0x%x\n", rc);
        return 1;
    }
    rc = sceKernelDeleteEqueue(eq);
    if (rc != 0) {
        std::printf("FAIL sceKernelDeleteEqueue rc=0x%x\n", rc);
        return 1;
    }

    std::free(cmdbuf);
    std::printf("[ok] equeue completion path\n");
    std::printf("[ok] stress passed\n");
    return 0;
}
