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

// PRX integration smoketest:
// - loads libkernel_sys_stub and libSceAmpr as modules,
// - resolves NID exports via sceKernelDlsym,
// - verifies that an AMM completion event is received on an equeue created via the stub.

#include <kernel.h>
#include <ampr.h>

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

using NidFn = int64_t (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

static bool dlsym_ok(SceKernelModule mod, const char* sym, void** out) {
    *out = nullptr;
    int rc = sceKernelDlsym(mod, sym, out);
    if (rc != 0 || !*out) {
        std::printf("dlsym failed sym=%s rc=0x%x addr=%p\n", sym, rc, *out);
        return false;
    }
    return true;
}

static NidFn dlsym_nid(SceKernelModule mod, const char* nid) {
    void* p = nullptr;
    if (!dlsym_ok(mod, nid, &p)) return nullptr;
    return reinterpret_cast<NidFn>(p);
}

static int64_t nid_call(NidFn f,
                        uint64_t a1 = 0,
                        uint64_t a2 = 0,
                        uint64_t a3 = 0,
                        uint64_t a4 = 0,
                        uint64_t a5 = 0,
                        uint64_t a6 = 0,
                        uint64_t a7 = 0,
                        uint64_t a8 = 0) {
    return f ? f(a1, a2, a3, a4, a5, a6, a7, a8) : (int64_t)SCE_KERNEL_ERROR_EINVAL;
}

int main(int argc, char** argv) {
    const char* kmod_path = (argc >= 2 && argv && argv[1]) ? argv[1] : "/data/libkernel_sys_stub.sprx";
    const char* ampr_path = (argc >= 3 && argv && argv[2]) ? argv[2] : "/data/libSceAmpr.sprx";

    std::printf("PRX smoketest\n");
    std::printf("  libkernel stub: %s\n", kmod_path);
    std::printf("  libSceAmpr:     %s\n", ampr_path);

    int mres = 0;
    SceKernelModule mod_k = sceKernelLoadStartModule(kmod_path, 0, nullptr, 0, nullptr, &mres);
    if (mod_k < 0) {
        std::printf("sceKernelLoadStartModule(stub) failed mod=0x%x res=0x%x\n", mod_k, mres);
        return 1;
    }

    mres = 0;
    SceKernelModule mod_a = sceKernelLoadStartModule(ampr_path, 0, nullptr, 0, nullptr, &mres);
    if (mod_a < 0) {
        std::printf("sceKernelLoadStartModule(ampr) failed mod=0x%x res=0x%x\n", mod_a, mres);
        return 1;
    }

    // --- Resolve libkernel_sys_stub NIDs (APR+equeue subset) ---
    using FnCreateEqueue = int (*)(SceKernelEqueue*, const char*);
    using FnAddAmprEvent = int (*)(SceKernelEqueue, uint32_t, void*);
    using FnDelAmprEvent = int (*)(SceKernelEqueue, uint32_t);
    using FnWaitEqueue = int (*)(SceKernelEqueue, SceKernelEvent*, int, int*, SceKernelUseconds*);
    using FnDelEqueue = int (*)(SceKernelEqueue);

    auto p_create = dlsym_nid(mod_k, "D0OdFMjp46I#C#A"); // sceKernelCreateEqueue
    auto p_add = dlsym_nid(mod_k, "bBfz7kMF2Ho#C#A");    // sceKernelAddAmprEvent
    auto p_del = dlsym_nid(mod_k, "bMmid3pfyjo#C#A");    // sceKernelDeleteAmprEvent
    auto p_wait = dlsym_nid(mod_k, "fzyMKs9kim0#C#A");   // sceKernelWaitEqueue
    auto p_deleq = dlsym_nid(mod_k, "jpFjmgAC5AE#C#A");  // sceKernelDeleteEqueue

    if (!p_create || !p_add || !p_del || !p_wait || !p_deleq) return 1;

    auto sceKernelCreateEqueue_ = reinterpret_cast<FnCreateEqueue>(p_create);
    auto sceKernelAddAmprEvent_ = reinterpret_cast<FnAddAmprEvent>(p_add);
    auto sceKernelDeleteAmprEvent_ = reinterpret_cast<FnDelAmprEvent>(p_del);
    auto sceKernelWaitEqueue_ = reinterpret_cast<FnWaitEqueue>(p_wait);
    auto sceKernelDeleteEqueue_ = reinterpret_cast<FnDelEqueue>(p_deleq);

    // --- Resolve libSceAmpr NIDs (subset needed for completion event) ---
    NidFn ampr_cb_ctor = dlsym_nid(mod_a, "EDq5bqCqYpA#C#A");   // sceAmprAmmCommandBufferConstructor
    NidFn ampr_cb_dtor = dlsym_nid(mod_a, "pvUFDOHilnE#C#A");   // sceAmprAmmCommandBufferDestructor
    NidFn cb_setbuf = dlsym_nid(mod_a, "N-FSPA4S3nI#C#A");       // sceAmprCommandBufferSetBuffer
    NidFn cb_reset = dlsym_nid(mod_a, "baQO9ez2gL4#C#A");        // sceAmprCommandBufferReset
    NidFn cb_write_eq = dlsym_nid(mod_a, "o67gODLFpls#C#A");     // sceAmprCommandBufferWriteKernelEventQueueOnCompletion
    NidFn amm_submit = dlsym_nid(mod_a, "lwS-7y3jcBI#C#A");      // sceAmprAmmSubmitCommandBuffer

    if (!ampr_cb_ctor || !ampr_cb_dtor || !cb_setbuf || !cb_reset || !cb_write_eq || !amm_submit) return 1;

    // Create equeue via stub and register AMPR event.
    constexpr uint32_t kEqId = 0x123;
    void* kUdata = (void*)0x1234;

    SceKernelEqueue eq{};
    int rc = sceKernelCreateEqueue_(&eq, "prx_smoketest");
    if (rc != 0) {
        std::printf("sceKernelCreateEqueue(stub) rc=0x%x\n", rc);
        return 1;
    }

    rc = sceKernelAddAmprEvent_(eq, kEqId, kUdata);
    if (rc != 0) {
        std::printf("sceKernelAddAmprEvent(stub) rc=0x%x\n", rc);
        return 1;
    }

    // Construct AMM command buffer inside libSceAmpr and submit a single completion event command.
    alignas(sce::Ampr::AmmCommandBuffer) uint8_t cb_storage[sizeof(sce::Ampr::AmmCommandBuffer)]{};
    void* cb_obj = cb_storage;

    (void)nid_call(ampr_cb_ctor, (uint64_t)(uintptr_t)cb_obj);

    void* cmdbuf = std::aligned_alloc(PAGE_SIZE, PAGE_SIZE);
    if (!cmdbuf) {
        std::printf("aligned_alloc failed\n");
        return 1;
    }
    std::memset(cmdbuf, 0, PAGE_SIZE);

    // Match sample expectation: command buffer memory is AMPR_READ.
    (void)sceKernelMprotect(cmdbuf, PAGE_SIZE, SCE_KERNEL_PROT_CPU_RW | SCE_KERNEL_PROT_AMPR_READ);

    int64_t irc = nid_call(cb_setbuf, (uint64_t)(uintptr_t)cb_obj, (uint64_t)(uintptr_t)cmdbuf, (uint64_t)PAGE_SIZE);
    if (irc != 0) {
        std::printf("cb.setBuffer rc=0x%llx\n", (long long)irc);
        return 1;
    }
    irc = nid_call(cb_reset, (uint64_t)(uintptr_t)cb_obj);
    if (irc != 0) {
        std::printf("cb.reset rc=0x%llx\n", (long long)irc);
        return 1;
    }

    irc = nid_call(cb_write_eq,
                   (uint64_t)(uintptr_t)cb_obj,
                   (uint64_t)(uintptr_t)eq,
                   (uint64_t)kEqId,
                   0);
    if (irc != 0) {
        std::printf("cb.writeKernelEventQueueOnCompletion rc=0x%llx\n", (long long)irc);
        return 1;
    }

    // AMM::Priority::kHigh == 0
    irc = nid_call(amm_submit, (uint64_t)(uintptr_t)cb_obj, 0);
    if (irc != 0) {
        std::printf("amm.submit rc=0x%llx\n", (long long)irc);
        return 1;
    }

    SceKernelEvent ev{};
    int outn = 0;
    SceKernelUseconds to = 2 * 1000 * 1000;
    rc = sceKernelWaitEqueue_(eq, &ev, 1, &outn, &to);
    if (rc != 0) {
        std::printf("sceKernelWaitEqueue(stub) rc=0x%x\n", rc);
        return 1;
    }
    if (outn != 1) {
        std::printf("unexpected outn=%d\n", outn);
        return 1;
    }

    const uint64_t gotId = (uint64_t)sceKernelGetEventId(&ev);
    void* gotUdata = sceKernelGetEventUserData(&ev);
    const int gotFilter = sceKernelGetEventFilter(&ev);

    std::printf("event: id=0x%llx filter=%d udata=%p\n",
                (unsigned long long)gotId, gotFilter, gotUdata);

    if (gotId != kEqId || gotUdata != kUdata) {
        std::printf("[fail] event mismatch\n");
        return 1;
    }

    std::printf("[ok] prx integration (equeue + completion)\n");

    // Cleanup (best-effort).
    (void)sceKernelDeleteAmprEvent_(eq, kEqId);
    (void)sceKernelDeleteEqueue_(eq);
    (void)nid_call(ampr_cb_dtor, (uint64_t)(uintptr_t)cb_obj);
    std::free(cmdbuf);

    return 0;
}

