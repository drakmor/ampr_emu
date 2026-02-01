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
#include "ampr_emu_extra.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

using namespace sce::Ampr;

static uint64_t align_up_u64(uint64_t v, uint64_t a) {
    return (v + (a - 1)) & ~(a - 1);
}

static bool expect_eq_i(const char* what, int got, int expected) {
    if (got == expected) return true;
    std::printf("FAIL %s got=0x%x expected=0x%x\n", what, got, expected);
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

static bool expect_true(const char* what, bool ok) {
    if (ok) return true;
    std::printf("FAIL %s\n", what);
    return false;
}

struct ScopedFree {
    void* p{nullptr};
    ~ScopedFree() {
        if (p) std::free(p);
    }
};

struct SmokeCtx {
    AmmVirtualAddressRanges vr{};
    uint64_t mapSize{PAGE_SIZE * 4};

    uint64_t auto_va{0};
    uint64_t direct_va{0};
    uint64_t alias_va{0};
    uint64_t remap_va{0};

    off_t auto_dmem_offset{0};
    off_t direct_dmem_offset{0};

    AmmCommandBuffer amm{};
    AprCommandBuffer apr{};

    ScopedFree ammBuf{};
    ScopedFree aprBuf{};
};

static bool amm_submit_wait_ok(const char* tag, AmmCommandBuffer& cb, Amm::Priority prio, SceAmmResultBuffer& res) {
    SceAmmSubmitId sid{};
    int rc = Amm::submitCommandBufferAndGetResult(&cb, prio, &res, &sid);
    if (!expect_eq_i(tag, rc, 0)) return false;
    rc = Amm::waitCommandBufferCompletion(sid);
    if (!expect_eq_i(tag, rc, 0)) return false;
    if (res.result != 0) {
        std::printf("FAIL %s result=0x%x errorOffset=0x%x\n", tag, res.result, res.errorOffset);
        return false;
    }
    return true;
}

static bool apr_submit_wait_ok(const char* tag, AprCommandBuffer& cb, Apr::Priority prio, SceAprResultBuffer& res) {
    SceAprSubmitId sid{};
    int rc = Apr::submitCommandBufferAndGetResult(&cb, prio, &res, &sid);
    if (!expect_eq_i(tag, rc, 0)) return false;
    rc = Apr::waitCommandBufferCompletion(sid);
    if (!expect_eq_i(tag, rc, 0)) return false;
    if (res.result != 0) {
        std::printf("FAIL %s result=0x%x errorOffset=0x%x\n", tag, res.result, res.errorOffset);
        return false;
    }
    return true;
}

static int group_setup_map_verify(SmokeCtx& ctx) {
    Amm::getVirtualAddressRanges(ctx.vr);
    ctx.auto_va = align_up_u64(ctx.vr.vaStart + 0x100000, PAGE_SIZE);
    ctx.direct_va = ctx.auto_va + ctx.mapSize;
    ctx.alias_va = align_up_u64(ctx.vr.multimapVaStart + 0x200000, PAGE_SIZE);
    ctx.remap_va = ctx.auto_va + 3 * ctx.mapSize;

    int rc = Amm::giveDirectMemory(0, SCE_KERNEL_MAIN_DMEM_SIZE,
                                   4ull * 1024 * 1024, 2ull * 1024 * 1024,
                                   Amm::Usage::kAuto, &ctx.auto_dmem_offset);
    if (!expect_eq_i("giveDirectMemory(auto)", rc, 0)) return 1;
    rc = Amm::giveDirectMemory(0, SCE_KERNEL_MAIN_DMEM_SIZE,
                               4ull * 1024 * 1024, 2ull * 1024 * 1024,
                               Amm::Usage::kDirect, &ctx.direct_dmem_offset);
    if (!expect_eq_i("giveDirectMemory(direct)", rc, 0)) return 1;

    size_t dmemTotal = sceKernelGetDirectMemorySize();
    std::printf("dmem total=0x%zx\n", dmemTotal);
    if (dmemTotal != 0) {
        off_t availStart = 0;
        size_t availSize = 0;
        int arc = sceKernelAvailableDirectMemorySize(0, (off_t)dmemTotal, PAGE_SIZE, &availStart, &availSize);
        std::printf("dmem available rc=%d start=0x%llx size=0x%zx\n",
                    arc, (unsigned long long)availStart, availSize);
    }

    ctx.ammBuf.p = std::aligned_alloc(64, 4096);
    if (!expect_true("aligned_alloc(ammBuf)", ctx.ammBuf.p != nullptr)) return 1;
    std::memset(ctx.ammBuf.p, 0, 4096);
    rc = ctx.amm.setBuffer(ctx.ammBuf.p, 4096);
    if (!expect_eq_i("amm.setBuffer", rc, 0)) return 1;

    rc = ctx.amm.map(ctx.auto_va, ctx.mapSize, SCE_KERNEL_MTYPE_C_SHARED,
                     SCE_KERNEL_PROT_CPU_RW | SCE_KERNEL_PROT_GPU_RW | SCE_KERNEL_PROT_AMPR_ALL);
    if (!expect_eq_i("amm.map(auto)", rc, 0)) return 1;
    rc = ctx.amm.mapDirect(ctx.direct_va, (uint64_t)ctx.direct_dmem_offset, ctx.mapSize,
                           SCE_KERNEL_MTYPE_C_SHARED,
                           SCE_KERNEL_PROT_CPU_RW | SCE_KERNEL_PROT_GPU_RW | SCE_KERNEL_PROT_AMPR_ALL);
    if (!expect_eq_i("amm.mapDirect(direct)", rc, 0)) return 1;

    SceAmmResultBuffer res{};
    if (!amm_submit_wait_ok("amm.submit(map+mapDirect)", ctx.amm, Amm::Priority::kMid, res)) return 1;
    std::printf("amm result=0x%x errorOffset=0x%x\n", res.result, res.errorOffset);

    unsigned char* auto_p = (unsigned char*)ctx.auto_va;
    for (uint64_t i = 0; i < 32; ++i) auto_p[i] = (unsigned char)(0xA0 + i);
    bool ok = true;
    for (uint64_t i = 0; i < 32; ++i) {
        if (auto_p[i] != (unsigned char)(0xA0 + i)) { ok = false; break; }
    }
    if (!expect_true("auto map verify", ok)) return 1;
    std::printf("[ok] auto map verify\n");

    unsigned char* direct_p = (unsigned char*)ctx.direct_va;
    for (uint64_t i = 0; i < 32; ++i) direct_p[i] = (unsigned char)(0xD0 + i);
    ok = true;
    for (uint64_t i = 0; i < 32; ++i) {
        if (direct_p[i] != (unsigned char)(0xD0 + i)) { ok = false; break; }
    }
    if (!expect_true("direct map verify", ok)) return 1;
    std::printf("[ok] direct map verify\n");

    return 0;
}

static int group_multimap_alias_verify(SmokeCtx& ctx) {
    int rc = ctx.amm.reset();
    if (!expect_eq_i("amm.reset(multimap)", rc, 0)) return 1;
    rc = ctx.amm.multiMap(ctx.auto_va, ctx.alias_va, ctx.mapSize,
                          SCE_KERNEL_PROT_CPU_RW | SCE_KERNEL_PROT_GPU_RW | SCE_KERNEL_PROT_AMPR_ALL);
    if (!expect_eq_i("amm.multiMap", rc, 0)) return 1;

    SceAmmResultBuffer res{};
    if (!amm_submit_wait_ok("amm.submit(multimap)", ctx.amm, Amm::Priority::kMid, res)) return 1;

    unsigned char* auto_p = (unsigned char*)ctx.auto_va;
    unsigned char* alias_p = (unsigned char*)ctx.alias_va;
    alias_p[0] = 0x5A;
    if (!expect_eq_u32("multimap alias reflect", (uint32_t)auto_p[0], 0x5A)) return 1;
    std::printf("[ok] multimap alias verify\n");
    return 0;
}

static int group_remap_verify(SmokeCtx& ctx) {
    int rc = ctx.amm.reset();
    if (!expect_eq_i("amm.reset(remap)", rc, 0)) return 1;
    rc = ctx.amm.remap(ctx.remap_va, ctx.auto_va, ctx.mapSize,
                       SCE_KERNEL_PROT_CPU_RW | SCE_KERNEL_PROT_GPU_RW | SCE_KERNEL_PROT_AMPR_ALL);
    if (!expect_eq_i("amm.remap", rc, 0)) return 1;

    SceAmmResultBuffer res{};
    if (!amm_submit_wait_ok("amm.submit(remap)", ctx.amm, Amm::Priority::kMid, res)) return 1;

    ctx.auto_va = ctx.remap_va;
    unsigned char* auto_p = (unsigned char*)ctx.auto_va;
    if (!expect_eq_u32("remap keeps data", (uint32_t)auto_p[0], 0x5A)) return 1;
    std::printf("[ok] remap verify\n");
    return 0;
}

static int group_wait_counter_equeue(SmokeCtx& ctx, SceKernelEqueue& eq, uint32_t* deleteIds, size_t& deleteN) {
    int rc = ctx.amm.reset();
    if (!expect_eq_i("amm.reset(wait/counter/eq)", rc, 0)) return 1;

    volatile uint64_t* label = (volatile uint64_t*)(ctx.auto_va + 128);
    volatile uint64_t* out_counter = (volatile uint64_t*)(ctx.auto_va + 256);
    volatile uint64_t* out_pair = (volatile uint64_t*)(ctx.auto_va + 264);
    *label = 0;
    *out_counter = 0;
    *out_pair = 0;

    rc = ctx.amm.waitOnAddress(label, 0xBEEF, WaitCompare::kEqual, WaitFlush::kDisable);
    if (!expect_eq_i("amm.waitOnAddress", rc, 0)) return 1;

    rc = ctx.amm.writeCounterOnCompletion(3, 0x1234);
    if (!expect_eq_i("amm.writeCounterOnCompletion(3)", rc, 0)) return 1;
    rc = ctx.amm.writeAddressFromCounterOnCompletion(out_counter, 3);
    if (!expect_eq_i("amm.writeAddressFromCounterOnCompletion(3)", rc, 0)) return 1;

    rc = ctx.amm.writeCounterOnCompletion(4, 0x55667788);
    if (!expect_eq_i("amm.writeCounterOnCompletion(4)", rc, 0)) return 1;
    rc = ctx.amm.writeCounterOnCompletion(5, 0x11223344);
    if (!expect_eq_i("amm.writeCounterOnCompletion(5)", rc, 0)) return 1;
    rc = ctx.amm.writeAddressFromCounterPairOnCompletion(out_pair, 4);
    if (!expect_eq_i("amm.writeAddressFromCounterPairOnCompletion(4)", rc, 0)) return 1;

    rc = sceKernelCreateEqueue(&eq, "ampr_smoke");
    if (!expect_eq_i("sceKernelCreateEqueue", rc, 0)) return 1;

    rc = sceKernelAddAmprEvent(eq, 0x321, (void*)0x1234);
    if (!expect_eq_i("sceKernelAddAmprEvent(0x321)", rc, 0)) return 1;
    deleteIds[deleteN++] = 0x321;

    rc = ctx.amm.writeKernelEventQueueOnCompletion(eq, 0x321, 0x0);
    if (!expect_eq_i("amm.writeKernelEventQueueOnCompletion", rc, 0)) return 1;

    SceAmmResultBuffer res{};
    SceAmmSubmitId sid{};
    rc = Amm::submitCommandBufferAndGetResult(&ctx.amm, Amm::Priority::kMid, &res, &sid);
    if (!expect_eq_i("amm.submit(wait/counter/eq)", rc, 0)) return 1;

    *label = 0xBEEF; // kick the wait

    SceKernelEvent ev{};
    int evn = 0;
    SceKernelUseconds to = 2 * 1000 * 1000;
    rc = sceKernelWaitEqueue(eq, &ev, 1, &evn, &to);
    if (!expect_eq_i("sceKernelWaitEqueue", rc, 0)) return 1;
    if (!expect_eq_i("sceKernelWaitEqueue evn", evn, 1)) return 1;
    if (!expect_eq_u64("event id", (uint64_t)sceKernelGetEventId(&ev), 0x321)) return 1;
    if (!expect_true("event udata", sceKernelGetEventUserData(&ev) == (void*)0x1234)) return 1;

    rc = Amm::waitCommandBufferCompletion(sid);
    if (!expect_eq_i("amm.wait(wait/counter/eq)", rc, 0)) return 1;
    if (res.result != 0) {
        std::printf("FAIL amm wait/counter/eq result=0x%x errorOffset=0x%x\n", res.result, res.errorOffset);
        return 1;
    }

    if (!expect_eq_u64("writeAddressFromCounter", (uint64_t)*out_counter, 0x1234)) return 1;
    if (!expect_eq_u64("writeAddressFromCounterPair", (uint64_t)*out_pair, 0x1122334455667788ull)) return 1;

    std::printf("[ok] wait/counter/equeue\n");
    return 0;
}

static int group_equeue_flags_filters(SmokeCtx& ctx, SceKernelEqueue eq, uint32_t* deleteIds, size_t& deleteN) {
    // This group is emu-only (kevent-style flags/filters); skip cleanly when not supported.
    SceKernelEventFilter ef{};
    ef.filter = SCE_KERNEL_EVFILT_AMPR;
    ef.flags = SCE_KERNEL_EV_ADD | SCE_KERNEL_EV_DISABLE;
    ef.fflags = 0;
    ef.udata = (void*)0x1234;

    int rc = Emu::addAmprEventWithFilter(eq, 0x400, &ef);
    if (rc == SCE_KERNEL_ERROR_EINVAL) {
        std::printf("[skip] equeue flags/filters (no emu extras)\n");
        return 0;
    }
    if (!expect_eq_i("addAmprEventWithFilter(disable)", rc, 0)) return 1;
    deleteIds[deleteN++] = 0x400;

    auto fire_event = [&](uint32_t id, uint64_t data) -> int {
        int rrc = ctx.amm.reset();
        if (rrc != 0) return rrc;
        rrc = ctx.amm.writeKernelEventQueueOnCompletion(eq, id, data);
        if (rrc != 0) return rrc;
        SceAmmResultBuffer res{};
        if (!amm_submit_wait_ok("amm.submit(fire_event)", ctx.amm, Amm::Priority::kMid, res)) return res.result ? res.result : -1;
        return 0;
    };

    SceKernelEvent ev{};
    int evn = 0;
    SceKernelUseconds to = 5000;

    // disabled -> timeout
    rc = fire_event(0x400, 0x1);
    if (!expect_eq_i("fire_event(disable)", rc, 0)) return 1;
    rc = sceKernelWaitEqueue(eq, &ev, 1, &evn, &to);
    if (!expect_eq_i("wait(disable) timeout", rc, SCE_KERNEL_ERROR_ETIMEDOUT)) return 1;

    // enable -> delivered
    ef.flags = SCE_KERNEL_EV_ENABLE;
    rc = Emu::addAmprEventWithFilter(eq, 0x400, &ef);
    if (!expect_eq_i("addAmprEventWithFilter(enable)", rc, 0)) return 1;
    rc = fire_event(0x400, 0x2);
    if (!expect_eq_i("fire_event(enable)", rc, 0)) return 1;
    rc = sceKernelWaitEqueue(eq, &ev, 1, &evn, &to);
    if (!expect_eq_i("wait(enable)", rc, 0)) return 1;
    if (!expect_eq_i("wait(enable) evn", evn, 1)) return 1;
    if (!expect_eq_u64("wait(enable) id", (uint64_t)sceKernelGetEventId(&ev), 0x400)) return 1;
    if (!expect_true("wait(enable) udata", sceKernelGetEventUserData(&ev) == (void*)0x1234)) return 1;

    // oneshot
    ef.flags = SCE_KERNEL_EV_ADD | SCE_KERNEL_EV_ONESHOT;
    ef.fflags = 0;
    ef.udata = (void*)0x55;
    rc = Emu::addAmprEventWithFilter(eq, 0x401, &ef);
    if (!expect_eq_i("addAmprEventWithFilter(oneshot)", rc, 0)) return 1;
    deleteIds[deleteN++] = 0x401;
    rc = fire_event(0x401, 0x3);
    if (!expect_eq_i("fire_event(oneshot)", rc, 0)) return 1;
    rc = sceKernelWaitEqueue(eq, &ev, 1, &evn, &to);
    if (!expect_eq_i("wait(oneshot)", rc, 0)) return 1;
    rc = fire_event(0x401, 0x4);
    if (!expect_eq_i("fire_event(oneshot2)", rc, 0)) return 1;
    rc = sceKernelWaitEqueue(eq, &ev, 1, &evn, &to);
    if (!expect_eq_i("wait(oneshot2) timeout", rc, SCE_KERNEL_ERROR_ETIMEDOUT)) return 1;

    // dispatch
    ef.flags = SCE_KERNEL_EV_ADD | SCE_KERNEL_EV_DISPATCH;
    ef.fflags = 0;
    ef.udata = (void*)0x66;
    rc = Emu::addAmprEventWithFilter(eq, 0x402, &ef);
    if (!expect_eq_i("addAmprEventWithFilter(dispatch)", rc, 0)) return 1;
    deleteIds[deleteN++] = 0x402;
    rc = fire_event(0x402, 0x5);
    if (!expect_eq_i("fire_event(dispatch)", rc, 0)) return 1;
    rc = sceKernelWaitEqueue(eq, &ev, 1, &evn, &to);
    if (!expect_eq_i("wait(dispatch)", rc, 0)) return 1;
    rc = fire_event(0x402, 0x6);
    if (!expect_eq_i("fire_event(dispatch2)", rc, 0)) return 1;
    rc = sceKernelWaitEqueue(eq, &ev, 1, &evn, &to);
    if (!expect_eq_i("wait(dispatch2) timeout", rc, SCE_KERNEL_ERROR_ETIMEDOUT)) return 1;
    ef.flags = SCE_KERNEL_EV_ENABLE;
    rc = Emu::addAmprEventWithFilter(eq, 0x402, &ef);
    if (!expect_eq_i("addAmprEventWithFilter(dispatch enable)", rc, 0)) return 1;
    rc = fire_event(0x402, 0x7);
    if (!expect_eq_i("fire_event(dispatch3)", rc, 0)) return 1;
    rc = sceKernelWaitEqueue(eq, &ev, 1, &evn, &to);
    if (!expect_eq_i("wait(dispatch3)", rc, 0)) return 1;

    // filter mismatch
    ef.filter = 7;
    ef.flags = SCE_KERNEL_EV_ADD;
    ef.fflags = 0;
    ef.udata = nullptr;
    rc = Emu::addAmprEventWithFilter(eq, 0x403, &ef);
    if (!expect_eq_i("addAmprEventWithFilter(filter mismatch)", rc, 0)) return 1;
    deleteIds[deleteN++] = 0x403;
    rc = fire_event(0x403, 0x8);
    if (!expect_eq_i("fire_event(filter mismatch)", rc, 0)) return 1;
    rc = sceKernelWaitEqueue(eq, &ev, 1, &evn, &to);
    if (!expect_eq_i("wait(filter mismatch) timeout", rc, SCE_KERNEL_ERROR_ETIMEDOUT)) return 1;

    // fflags filter
    ef.filter = SCE_KERNEL_EVFILT_AMPR;
    ef.flags = SCE_KERNEL_EV_ADD;
    ef.fflags = 0x1;
    ef.udata = nullptr;
    rc = Emu::addAmprEventWithFilter(eq, 0x404, &ef);
    if (!expect_eq_i("addAmprEventWithFilter(fflags)", rc, 0)) return 1;
    deleteIds[deleteN++] = 0x404;
    rc = fire_event(0x404, 0x9);
    if (!expect_eq_i("fire_event(fflags)", rc, 0)) return 1;
    rc = sceKernelWaitEqueue(eq, &ev, 1, &evn, &to);
    if (!expect_eq_i("wait(fflags)", rc, 0)) return 1;
    if (!expect_eq_u64("wait(fflags) id", (uint64_t)sceKernelGetEventId(&ev), 0x404)) return 1;
    if (!expect_eq_u32("wait(fflags) fflags", (uint32_t)sceKernelGetEventFflags(&ev), 0x1)) return 1;

    // Explicit push: mismatch should be filtered out.
    rc = Emu::pushEqueueEvent(eq, 0x404, 0xA, SCE_KERNEL_EVFILT_AMPR, 0x2);
    if (!expect_eq_i("pushEqueueEvent(fflags mismatch)", rc, 0)) return 1;
    rc = sceKernelWaitEqueue(eq, &ev, 1, &evn, &to);
    if (!expect_eq_i("wait(fflags mismatch) timeout", rc, SCE_KERNEL_ERROR_ETIMEDOUT)) return 1;

    // EV_CLEAR: coalesce queued events (deliver only the latest).
    ef.filter = SCE_KERNEL_EVFILT_AMPR;
    ef.flags = SCE_KERNEL_EV_ADD | SCE_KERNEL_EV_CLEAR;
    ef.fflags = 0;
    ef.udata = nullptr;
    rc = Emu::addAmprEventWithFilter(eq, 0x405, &ef);
    if (!expect_eq_i("addAmprEventWithFilter(clear)", rc, 0)) return 1;
    deleteIds[deleteN++] = 0x405;
    rc = Emu::pushEqueueEvent(eq, 0x405, 0x11, SCE_KERNEL_EVFILT_AMPR, 0);
    if (!expect_eq_i("pushEqueueEvent(clear1)", rc, 0)) return 1;
    rc = Emu::pushEqueueEvent(eq, 0x405, 0x22, SCE_KERNEL_EVFILT_AMPR, 0);
    if (!expect_eq_i("pushEqueueEvent(clear2)", rc, 0)) return 1;
    rc = sceKernelWaitEqueue(eq, &ev, 1, &evn, &to);
    if (!expect_eq_i("wait(clear)", rc, 0)) return 1;
    if (!expect_eq_u64("wait(clear) id", (uint64_t)sceKernelGetEventId(&ev), 0x405)) return 1;
    if (!expect_eq_u64("wait(clear) data", (uint64_t)sceKernelGetEventData(&ev), 0x22)) return 1;

    // Alternative: explicit filter/fflags via pushEqueueEvent (emu-only).
    ef.filter = SCE_KERNEL_EVFILT_AMPR;
    ef.flags = SCE_KERNEL_EV_ADD;
    ef.fflags = 0x4;
    ef.udata = (void*)0x7777;
    rc = Emu::addAmprEventWithFilter(eq, 0x406, &ef);
    if (!expect_eq_i("addAmprEventWithFilter(alt)", rc, 0)) return 1;
    deleteIds[deleteN++] = 0x406;
    rc = Emu::pushEqueueEvent(eq, 0x406, 0x44, SCE_KERNEL_EVFILT_AMPR, 0x4);
    if (!expect_eq_i("pushEqueueEvent(alt)", rc, 0)) return 1;
    rc = sceKernelWaitEqueue(eq, &ev, 1, &evn, &to);
    if (!expect_eq_i("wait(alt)", rc, 0)) return 1;
    if (!expect_eq_u64("wait(alt) id", (uint64_t)sceKernelGetEventId(&ev), 0x406)) return 1;
    if (!expect_true("wait(alt) udata", sceKernelGetEventUserData(&ev) == (void*)0x7777)) return 1;

    // Default sceKernelAddAmprEvent uses EV_CLEAR (coalesce).
    rc = sceKernelAddAmprEvent(eq, 0x407, (void*)0x8888);
    if (!expect_eq_i("sceKernelAddAmprEvent(default)", rc, 0)) return 1;
    deleteIds[deleteN++] = 0x407;
    rc = Emu::pushEqueueEvent(eq, 0x407, 0x55, SCE_KERNEL_EVFILT_AMPR, 0);
    if (!expect_eq_i("pushEqueueEvent(default1)", rc, 0)) return 1;
    rc = Emu::pushEqueueEvent(eq, 0x407, 0x66, SCE_KERNEL_EVFILT_AMPR, 0);
    if (!expect_eq_i("pushEqueueEvent(default2)", rc, 0)) return 1;
    rc = sceKernelWaitEqueue(eq, &ev, 1, &evn, &to);
    if (!expect_eq_i("wait(default)", rc, 0)) return 1;
    if (!expect_eq_u64("wait(default) data", (uint64_t)sceKernelGetEventData(&ev), 0x66)) return 1;
    rc = sceKernelWaitEqueue(eq, &ev, 1, &evn, &to);
    if (!expect_eq_i("wait(default2) timeout", rc, SCE_KERNEL_ERROR_ETIMEDOUT)) return 1;

    std::printf("[ok] equeue flags/filters\n");
    return 0;
}

static int group_modify_protect(SmokeCtx& ctx) {
    int rc = ctx.amm.reset();
    if (!expect_eq_i("amm.reset(modify)", rc, 0)) return 1;
    rc = ctx.amm.modifyProtect(ctx.auto_va, ctx.mapSize,
                               SCE_KERNEL_PROT_CPU_READ | SCE_KERNEL_PROT_AMPR_READ,
                               SCE_KERNEL_PROT_CPU_ALL | SCE_KERNEL_PROT_AMPR_ALL);
    if (!expect_eq_i("amm.modifyProtect", rc, 0)) return 1;
    rc = ctx.amm.modifyMtypeProtect(ctx.auto_va, ctx.mapSize, SCE_KERNEL_MTYPE_C_SHARED,
                                    SCE_KERNEL_PROT_CPU_RW | SCE_KERNEL_PROT_GPU_RW | SCE_KERNEL_PROT_AMPR_ALL,
                                    SCE_KERNEL_PROT_CPU_ALL | SCE_KERNEL_PROT_GPU_ALL | SCE_KERNEL_PROT_AMPR_ALL);
    if (!expect_eq_i("amm.modifyMtypeProtect", rc, 0)) return 1;

    SceAmmResultBuffer res{};
    if (!amm_submit_wait_ok("amm.submit(modifyProtect)", ctx.amm, Amm::Priority::kMid, res)) return 1;
    std::printf("[ok] modifyProtect/modifyMtypeProtect\n");
    return 0;
}

static int group_apr_read_and_gather_scatter(SmokeCtx& ctx) {
    const char* pathList[] = { "/data/data.bin" };
    SceAprFileId ids[1]{};
    uint32_t err = 0;
    int rc = Apr::resolveFilepathsToIds(pathList, 1, ids, &err);
    if (!expect_eq_i("Apr::resolveFilepathsToIds", rc, 0)) {
        std::printf("resolve erridx=%u\n", err);
        return 1;
    }

    ctx.aprBuf.p = std::aligned_alloc(64, 4096);
    if (!expect_true("aligned_alloc(aprBuf)", ctx.aprBuf.p != nullptr)) return 1;
    std::memset(ctx.aprBuf.p, 0, 4096);
    rc = ctx.apr.setBuffer(ctx.aprBuf.p, 4096);
    if (!expect_eq_i("apr.setBuffer", rc, 0)) return 1;

    rc = ctx.apr.reset();
    if (!expect_eq_i("apr.reset(read)", rc, 0)) return 1;
    rc = ctx.apr.readFile(ids[0], (void*)ctx.auto_va, 16, 0);
    if (!expect_eq_i("apr.readFile", rc, 0)) return 1;

    SceAprResultBuffer ares{};
    if (!apr_submit_wait_ok("apr.submit(readFile)", ctx.apr, Apr::Priority::kPriority3, ares)) return 1;

    unsigned char* p = (unsigned char*)ctx.auto_va;
    std::printf("read bytes: ");
    for (int i = 0; i < 16; i++) std::printf("%02x ", p[i]);
    std::printf("\n");
    std::printf("[ok] apr readFile\n");

    unsigned char ref[16]{};
    std::memcpy(ref, p, sizeof(ref));

    // gather/scatter (3 segments)
    rc = ctx.apr.reset();
    if (!expect_eq_i("apr.reset(gs)", rc, 0)) return 1;
    rc = ctx.apr.resetGatherScatterState();
    if (!expect_eq_i("apr.resetGatherScatterState", rc, 0)) return 1;

    uint64_t gs_base = ctx.auto_va + 0x800;
    rc = ctx.apr.readFile(ids[0], (void*)gs_base, 12, 0);
    if (!expect_eq_i("apr.readFile(gs seed)", rc, 0)) return 1;
    rc = ctx.apr.mapBegin(ids[0], 0, 0, 0);
    if (!expect_eq_i("apr.mapBegin", rc, 0)) return 1;
    rc = ctx.apr.readFileGatherScatter((void*)(gs_base + 0), 4, 0);
    if (!expect_eq_i("apr.readFileGatherScatter(0)", rc, 0)) return 1;
    rc = ctx.apr.readFileGatherScatter((void*)(gs_base + 4), 4, 4);
    if (!expect_eq_i("apr.readFileGatherScatter(4)", rc, 0)) return 1;
    rc = ctx.apr.readFileGatherScatter((void*)(gs_base + 8), 4, 8);
    if (!expect_eq_i("apr.readFileGatherScatter(8)", rc, 0)) return 1;
    rc = ctx.apr.mapEnd();
    if (!expect_eq_i("apr.mapEnd", rc, 0)) return 1;

    std::memset(&ares, 0, sizeof(ares));
    if (!apr_submit_wait_ok("apr.submit(gather/scatter)", ctx.apr, Apr::Priority::kPriority3, ares)) return 1;

    unsigned char* gs = (unsigned char*)gs_base;
    if (!expect_true("gather/scatter verify",
                     std::memcmp(gs + 0, ref + 0, 4) == 0 &&
                     std::memcmp(gs + 4, ref + 4, 4) == 0 &&
                     std::memcmp(gs + 8, ref + 8, 4) == 0)) {
        return 1;
    }
    std::printf("[ok] apr gather/scatter\n");
    return 0;
}

static int group_unmap_all(SmokeCtx& ctx) {
    int rc = ctx.amm.reset();
    if (!expect_eq_i("amm.reset(unmap)", rc, 0)) return 1;
    rc = ctx.amm.unmap(ctx.auto_va, ctx.mapSize);
    if (!expect_eq_i("amm.unmap(auto)", rc, 0)) return 1;
    rc = ctx.amm.unmap(ctx.direct_va, ctx.mapSize);
    if (!expect_eq_i("amm.unmap(direct)", rc, 0)) return 1;
    rc = ctx.amm.unmap(ctx.alias_va, ctx.mapSize);
    if (!expect_eq_i("amm.unmap(alias)", rc, 0)) return 1;

    SceAmmResultBuffer res{};
    if (!amm_submit_wait_ok("amm.submit(unmap)", ctx.amm, Amm::Priority::kMid, res)) return 1;
    std::printf("[ok] unmap\n");
    return 0;
}

int main() {
    std::printf("AMPR smoketest\n");

    SmokeCtx ctx{};

    if (group_setup_map_verify(ctx) != 0) return 1;
    if (group_multimap_alias_verify(ctx) != 0) return 1;
    if (group_remap_verify(ctx) != 0) return 1;

    // Equeue tests share a queue handle across groups.
    SceKernelEqueue eq = nullptr;
    uint32_t deleteIds[16]{};
    size_t deleteN = 0;

    if (group_wait_counter_equeue(ctx, eq, deleteIds, deleteN) != 0) return 1;
    if (group_equeue_flags_filters(ctx, eq, deleteIds, deleteN) != 0) return 1;

    // Cleanup event registrations (best-effort) and then the queue itself.
    for (size_t i = 0; i < deleteN; ++i) {
        (void)sceKernelDeleteAmprEvent(eq, deleteIds[i]);
    }
    if (eq) (void)sceKernelDeleteEqueue(eq);

    if (group_modify_protect(ctx) != 0) return 1;
    if (group_apr_read_and_gather_scatter(ctx) != 0) return 1;
    if (group_unmap_all(ctx) != 0) return 1;

    std::printf("[ok] smoketest passed\n");
    return 0;
}
