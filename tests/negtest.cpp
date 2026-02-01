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
#include <thread>

using namespace sce::Ampr;

static uint64_t align_up_u64(uint64_t v, uint64_t a) {
    return (v + (a - 1)) & ~(a - 1);
}

static bool expect_eq_i(const char* what, int got, int expected) {
    if (got == expected) return true;
    std::printf("FAIL %s got=0x%x expected=0x%x\n", what, got, expected);
    return false;
}

static bool expect_ne_i(const char* what, int got, int not_expected) {
    if (got != not_expected) return true;
    std::printf("FAIL %s got=0x%x expected!=0x%x\n", what, got, not_expected);
    return false;
}

static bool expect_eq_u32(const char* what, uint32_t got, uint32_t expected) {
    if (got == expected) return true;
    std::printf("FAIL %s got=0x%x expected=0x%x\n", what, got, expected);
    return false;
}

static bool expect_eq_u64(const char* what, uint64_t got, uint64_t expected) {
    if (got == expected) return true;
    std::printf("FAIL %s got=0x%llx expected=0x%llx\n",
                what, (unsigned long long)got, (unsigned long long)expected);
    return false;
}

static int test_commandbuffer_validation() {
    // No buffer => EPERM for any command append.
    {
        AmmCommandBuffer cb;
        int rc = cb.map(0, PAGE_SIZE, 0, 0);
        if (!expect_eq_i("amm.map without setBuffer", rc, SCE_KERNEL_ERROR_EPERM)) return 1;
    }

    // With a buffer => validate parameters.
    void* buf = std::aligned_alloc(64, 256);
    if (!buf) {
        std::printf("FAIL aligned_alloc\n");
        return 1;
    }
    std::memset(buf, 0, 256);

    AmmCommandBuffer cb;
    int rc = cb.setBuffer(buf, 256);
    if (!expect_eq_i("amm.setBuffer", rc, 0)) return 1;

    volatile uint64_t label = 0;
    uint8_t misaligned[16]{};
    auto* bad_u64 = (volatile uint64_t*)(void*)(misaligned + 1);

    rc = cb.waitOnAddress(bad_u64, 0, WaitCompare::kEqual, WaitFlush::kDisable);
    if (!expect_eq_i("waitOnAddress misaligned", rc, SCE_KERNEL_ERROR_EINVAL)) return 1;

    rc = cb.waitOnAddress(&label, 0, (WaitCompare)99, WaitFlush::kDisable);
    if (!expect_eq_i("waitOnAddress bad WaitCompare", rc, SCE_KERNEL_ERROR_EINVAL)) return 1;

    rc = cb.waitOnAddress(&label, 0, WaitCompare::kEqual, (WaitFlush)99);
    if (!expect_eq_i("waitOnAddress bad WaitFlush", rc, SCE_KERNEL_ERROR_EINVAL)) return 1;

    rc = cb.writeKernelEventQueueOnCompletion(nullptr, 1, 0);
    if (!expect_eq_i("writeKernelEventQueueOnCompletion null eq", rc, SCE_KERNEL_ERROR_EINVAL)) return 1;

    // Overflow => EBUSY and offset/num unchanged.
    AmmCommandBuffer ov;
    void* ovbuf = std::aligned_alloc(64, 64);
    if (!ovbuf) return 1;
    std::memset(ovbuf, 0, 64);
    rc = ov.setBuffer(ovbuf, 64);
    if (!expect_eq_i("ov.setBuffer", rc, 0)) return 1;

    rc = ov.nop(16);
    if (!expect_eq_i("ov.nop(16)", rc, 0)) return 1;

    uint32_t off_before = ov.getCurrentOffset();
    uint32_t num_before = ov.getNumCommands();
    rc = ov.nop(1);
    if (!expect_eq_i("ov.nop overflow", rc, SCE_KERNEL_ERROR_EBUSY)) return 1;
    if (!expect_eq_u32("ov.offset unchanged", ov.getCurrentOffset(), off_before)) return 1;
    if (!expect_eq_u32("ov.num unchanged", ov.getNumCommands(), num_before)) return 1;

    std::free(ovbuf);
    std::free(buf);
    std::printf("[ok] command buffer validation\n");
    return 0;
}

static int test_submit_validation() {
    // AMM: submit without buffer => EPERM.
    {
        AmmCommandBuffer cb;
        SceAmmResultBuffer res{};
        SceAmmSubmitId sid{};
        int rc = Amm::submitCommandBufferAndGetResult(&cb, Amm::Priority::kMid, &res, &sid);
        if (!expect_eq_i("Amm::submit without buffer", rc, SCE_KERNEL_ERROR_EPERM)) return 1;
    }
    // AMM: submit with buffer but empty => EINVAL.
    {
        AmmCommandBuffer cb;
        void* buf = std::aligned_alloc(64, 256);
        if (!buf) return 1;
        std::memset(buf, 0, 256);
        int rc = cb.setBuffer(buf, 256);
        if (!expect_eq_i("amm.setBuffer", rc, 0)) return 1;
        SceAmmResultBuffer res{};
        SceAmmSubmitId sid{};
        rc = Amm::submitCommandBufferAndGetResult(&cb, Amm::Priority::kMid, &res, &sid);
        if (!expect_eq_i("Amm::submit empty", rc, SCE_KERNEL_ERROR_EINVAL)) return 1;
        std::free(buf);
    }
    // AMM: invalid priority => EINVAL.
    {
        AmmCommandBuffer cb;
        void* buf = std::aligned_alloc(64, 256);
        if (!buf) return 1;
        std::memset(buf, 0, 256);
        int rc = cb.setBuffer(buf, 256);
        if (!expect_eq_i("amm.setBuffer", rc, 0)) return 1;
        rc = cb.nop(16);
        if (!expect_eq_i("amm.nop", rc, 0)) return 1;
        SceAmmResultBuffer res{};
        SceAmmSubmitId sid{};
        rc = Amm::submitCommandBufferAndGetResult(&cb, (Amm::Priority)123, &res, &sid);
        if (!expect_eq_i("Amm::submit bad prio", rc, SCE_KERNEL_ERROR_EINVAL)) return 1;
        std::free(buf);
    }

    // APR: submit without buffer => EPERM.
    {
        AprCommandBuffer cb;
        SceAprResultBuffer res{};
        SceAprSubmitId sid{};
        int rc = Apr::submitCommandBufferAndGetResult(&cb, Apr::Priority::kPriority1, &res, &sid);
        if (!expect_eq_i("Apr::submit without buffer", rc, SCE_KERNEL_ERROR_EPERM)) return 1;
    }
    // APR: submit with buffer but empty => EINVAL.
    {
        AprCommandBuffer cb;
        void* buf = std::aligned_alloc(64, 256);
        if (!buf) return 1;
        std::memset(buf, 0, 256);
        int rc = cb.setBuffer(buf, 256);
        if (!expect_eq_i("apr.setBuffer", rc, 0)) return 1;
        SceAprResultBuffer res{};
        SceAprSubmitId sid{};
        rc = Apr::submitCommandBufferAndGetResult(&cb, Apr::Priority::kPriority1, &res, &sid);
        if (!expect_eq_i("Apr::submit empty", rc, SCE_KERNEL_ERROR_EINVAL)) return 1;
        std::free(buf);
    }
    // APR: invalid priority => EINVAL.
    {
        AprCommandBuffer cb;
        void* buf = std::aligned_alloc(64, 256);
        if (!buf) return 1;
        std::memset(buf, 0, 256);
        int rc = cb.setBuffer(buf, 256);
        if (!expect_eq_i("apr.setBuffer", rc, 0)) return 1;
        unsigned char tmp[16]{};
        rc = cb.readFile(0xFFFFFFFFu, tmp, sizeof(tmp), 0);
        if (!expect_eq_i("apr.readFile", rc, 0)) return 1;
        SceAprResultBuffer res{};
        SceAprSubmitId sid{};
        rc = Apr::submitCommandBufferAndGetResult(&cb, (Apr::Priority)123, &res, &sid);
        if (!expect_eq_i("Apr::submit bad prio", rc, SCE_KERNEL_ERROR_EINVAL)) return 1;
        std::free(buf);
    }

    std::printf("[ok] submit validation\n");
    return 0;
}

static int test_wait_semantics_and_error_offset() {
    // AMM: wait should return 0 even if command execution fails; res.result holds error.
    {
        AmmVirtualAddressRanges vr{};
        Amm::getVirtualAddressRanges(vr);
        uint64_t bogus_va = align_up_u64(vr.vaStart + 0x100000, PAGE_SIZE);
        uint64_t alias_va = align_up_u64(vr.multimapVaStart + 0x200000, PAGE_SIZE);

        AmmCommandBuffer cb;
        void* buf = std::aligned_alloc(64, 256);
        if (!buf) return 1;
        std::memset(buf, 0, 256);
        int rc = cb.setBuffer(buf, 256);
        if (!expect_eq_i("amm.setBuffer", rc, 0)) return 1;
        rc = cb.reset();
        if (!expect_eq_i("amm.reset", rc, 0)) return 1;

        uint32_t expectedOff = cb.getCurrentOffset();
        rc = cb.multiMap(bogus_va, alias_va, PAGE_SIZE,
                         SCE_KERNEL_PROT_CPU_RW | SCE_KERNEL_PROT_GPU_RW | SCE_KERNEL_PROT_AMPR_ALL);
        if (!expect_eq_i("amm.multiMap append", rc, 0)) return 1;

        SceAmmResultBuffer res{};
        SceAmmSubmitId sid{};
        rc = Amm::submitCommandBufferAndGetResult(&cb, Amm::Priority::kMid, &res, &sid);
        if (!expect_eq_i("amm.submit", rc, 0)) return 1;
        rc = Amm::waitCommandBufferCompletion(sid);
        if (!expect_eq_i("amm.wait", rc, 0)) return 1;
        if (!expect_ne_i("amm.res.result != 0", res.result, 0)) return 1;
        if (!expect_eq_i("amm.res.result", res.result, SCE_KERNEL_ERROR_ENOENT)) return 1;
        if (!expect_eq_u32("amm.res.errorOffset", res.errorOffset, expectedOff)) return 1;
        std::free(buf);
    }

    // APR: errorOffset should point to the failing read (even with batching).
    {
        const char* files[1] = { "/data/data.bin" };
        SceAprFileId ids[1]{};
        size_t fsizes[1]{};
        uint32_t erridx = 0;
        int rc = Apr::resolveFilepathsToIdsAndFileSizes(files, 1, ids, fsizes, &erridx);
        if (rc != 0) {
            std::printf("FAIL resolveFilepathsToIdsAndFileSizes rc=0x%x erridx=%u\n", rc, erridx);
            return 1;
        }

        unsigned char out1[16]{};
        unsigned char out2[16]{};

        AprCommandBuffer cb;
        void* buf = std::aligned_alloc(64, 256);
        if (!buf) return 1;
        std::memset(buf, 0, 256);
        rc = cb.setBuffer(buf, 256);
        if (!expect_eq_i("apr.setBuffer", rc, 0)) return 1;
        rc = cb.reset();
        if (!expect_eq_i("apr.reset", rc, 0)) return 1;

        rc = cb.readFile(ids[0], out1, sizeof(out1), 0);
        if (!expect_eq_i("apr.readFile good", rc, 0)) return 1;

        uint32_t expectedBadOff = cb.getCurrentOffset();
        rc = cb.readFile(0xDEADBEEFu, out2, sizeof(out2), 0);
        if (!expect_eq_i("apr.readFile bad", rc, 0)) return 1;

        SceAprResultBuffer res{};
        SceAprSubmitId sid{};
        rc = Apr::submitCommandBufferAndGetResult(&cb, Apr::Priority::kPriority1, &res, &sid);
        if (!expect_eq_i("apr.submit", rc, 0)) return 1;
        rc = Apr::waitCommandBufferCompletion(sid);
        if (!expect_eq_i("apr.wait", rc, 0)) return 1;
        if (!expect_eq_i("apr.res.result", res.result, SCE_KERNEL_ERROR_ENOENT)) return 1;
        if (!expect_eq_u32("apr.res.errorOffset", res.errorOffset, expectedBadOff)) return 1;
        std::free(buf);
    }

    std::printf("[ok] wait semantics + errorOffset\n");
    return 0;
}

static int test_dmem_release_semantics() {
    // Invalid params.
    {
        off_t off = 0;
        int rc = sceKernelAllocateDirectMemory(0, SCE_KERNEL_MAIN_DMEM_SIZE, 0x1234, 0, SCE_KERNEL_MTYPE_C, &off);
        if (!expect_eq_i("sceKernelAllocateDirectMemory bad size", rc, SCE_KERNEL_ERROR_EINVAL)) return 1;
    }
    {
        int rc = sceKernelAllocateDirectMemory(0, SCE_KERNEL_MAIN_DMEM_SIZE, PAGE_SIZE, 0, SCE_KERNEL_MTYPE_C, nullptr);
        if (!expect_eq_i("sceKernelAllocateDirectMemory null out", rc, SCE_KERNEL_ERROR_EFAULT)) return 1;
    }

    const size_t len = PAGE_SIZE * 4;
    off_t off = 0;
    int rc = sceKernelAllocateDirectMemory(0, SCE_KERNEL_MAIN_DMEM_SIZE, len, PAGE_SIZE, SCE_KERNEL_MTYPE_C, &off);
    if (!expect_eq_i("sceKernelAllocateDirectMemory", rc, 0)) return 1;

    void* p = nullptr;
    rc = sceKernelMapDirectMemory(&p, len,
                                  SCE_KERNEL_PROT_CPU_RW | SCE_KERNEL_PROT_AMPR_RW,
                                  0, off, PAGE_SIZE);
    if (!expect_eq_i("sceKernelMapDirectMemory", rc, 0)) return 1;

    // Release while mapped => EBUSY.
    rc = sceKernelReleaseDirectMemory(off, len);
    if (!expect_eq_i("sceKernelReleaseDirectMemory busy", rc, SCE_KERNEL_ERROR_EBUSY)) return 1;

    rc = sceKernelMunmap(p, len);
    if (!expect_eq_i("sceKernelMunmap", rc, 0)) return 1;

    rc = sceKernelReleaseDirectMemory(off, len);
    if (!expect_eq_i("sceKernelReleaseDirectMemory", rc, 0)) return 1;

    // Reuse the freed range.
    off_t off2 = 0;
    rc = sceKernelAllocateDirectMemory(0, SCE_KERNEL_MAIN_DMEM_SIZE, len, PAGE_SIZE, SCE_KERNEL_MTYPE_C, &off2);
    if (!expect_eq_i("sceKernelAllocateDirectMemory(2)", rc, 0)) return 1;
    if (!expect_eq_u64("dmem reuse offset", (uint64_t)off2, (uint64_t)off)) return 1;

    rc = sceKernelReleaseDirectMemory(off2, len);
    if (!expect_eq_i("sceKernelReleaseDirectMemory(2)", rc, 0)) return 1;

    std::printf("[ok] dmem release semantics\n");
    return 0;
}

static int test_equeue_errors() {
    // Invalid handle.
    {
        SceKernelEvent ev{};
        int n = 0;
        SceKernelUseconds to = 1000;
        int rc = sceKernelWaitEqueue((SceKernelEqueue)(uintptr_t)0x1234, &ev, 1, &n, &to);
        if (!expect_eq_i("sceKernelWaitEqueue bad handle", rc, SCE_KERNEL_ERROR_EBADF)) return 1;
    }

    // Timeout with no events.
    SceKernelEqueue eq = nullptr;
    int rc = sceKernelCreateEqueue(&eq, "ampr.negtest");
    if (!expect_eq_i("sceKernelCreateEqueue", rc, 0)) return 1;
    SceKernelEvent ev{};
    int n = 0;
    SceKernelUseconds to = 1000;
    rc = sceKernelWaitEqueue(eq, &ev, 1, &n, &to);
    if (!expect_eq_i("sceKernelWaitEqueue timeout", rc, SCE_KERNEL_ERROR_ETIMEDOUT)) return 1;

    // Delete while waiting => ECANCELED.
    SceKernelEqueue eq2 = nullptr;
    rc = sceKernelCreateEqueue(&eq2, "ampr.negtest2");
    if (!expect_eq_i("sceKernelCreateEqueue(2)", rc, 0)) return 1;
    int waiter_rc = 0;
    std::thread t([&]{
        SceKernelEvent wev{};
        int wn = 0;
        SceKernelUseconds wto = 5 * 1000 * 1000;
        waiter_rc = sceKernelWaitEqueue(eq2, &wev, 1, &wn, &wto);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    rc = sceKernelDeleteEqueue(eq2);
    if (!expect_eq_i("sceKernelDeleteEqueue(2)", rc, 0)) return 1;
    t.join();
    if (!expect_eq_i("sceKernelWaitEqueue canceled", waiter_rc, SCE_KERNEL_ERROR_ECANCELED)) return 1;

    rc = sceKernelDeleteEqueue(eq);
    if (!expect_eq_i("sceKernelDeleteEqueue", rc, 0)) return 1;

    std::printf("[ok] equeue errors\n");
    return 0;
}

int main() {
    std::printf("AMPR negtest\n");
    if (test_commandbuffer_validation() != 0) return 1;
    if (test_submit_validation() != 0) return 1;
    if (test_wait_semantics_and_error_offset() != 0) return 1;
    if (test_dmem_release_semantics() != 0) return 1;
    if (test_equeue_errors() != 0) return 1;
    std::printf("[ok] all negtests passed\n");
    return 0;
}
