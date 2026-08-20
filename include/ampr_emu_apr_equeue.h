/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * APR-only local equeue publication and libkernel hook bridge.
 */

#pragma once

#include "ampr_emu_config.h"

#include <kernel/equeue.h>
#include <cstdint>

enum class AprEqueuePublishResult : uint8_t {
    Published = 0,
    Backpressure = 1,
    NativeFallback = 2,
};

#if AMPR_EMU_APR_LOCAL_EQUEUE
AprEqueuePublishResult apr_equeue_try_publish(SceKernelEqueue eq,
                                               int32_t id,
                                               uint64_t data);
void apr_equeue_overlay_set_hooks_available(bool available);
void apr_equeue_overlay_shutdown();
void apr_equeue_log_counters(const char* reason, bool reset);

extern "C" {
int sceKernelWaitEqueue_emul(SceKernelEqueue eq,
                             SceKernelEvent* events,
                             int num,
                             int* out,
                             SceKernelUseconds* timeout);
int sceKernelDeleteEqueue_emul(SceKernelEqueue eq);
int sceKernelAddAmprEvent_emul(SceKernelEqueue eq, int id, void* udata);
int sceKernelDeleteAmprEvent_emul(SceKernelEqueue eq, int id);
}
#else
inline AprEqueuePublishResult apr_equeue_try_publish(SceKernelEqueue,
                                                      int32_t,
                                                      uint64_t) {
    return AprEqueuePublishResult::NativeFallback;
}
inline void apr_equeue_overlay_set_hooks_available(bool) {}
inline void apr_equeue_overlay_shutdown() {}
inline void apr_equeue_log_counters(const char*, bool) {}
#endif
