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
void apr_equeue_overlay_set_hook_availability(bool hooksAvailable,
                                               bool classificationAvailable);
void apr_equeue_register_amm_command_buffer(const void* commandBuffer);
void apr_equeue_unregister_amm_command_buffer(const void* commandBuffer);
void apr_equeue_note_command_buffer_event(const void* commandBuffer,
                                          SceKernelEqueue eq);
void apr_equeue_overlay_shutdown();
void apr_equeue_log_counters(const char* reason, bool reset);

extern "C" {
int sceKernelCreateEqueue_emul(SceKernelEqueue* eq, const char* name);
int sceKernelWaitEqueue_emul(SceKernelEqueue eq,
                             SceKernelEvent* events,
                             int num,
                             int* out,
                             SceKernelUseconds* timeout);
int sceKernelDeleteEqueue_emul(SceKernelEqueue eq);
int sceKernelAddAmprEvent_emul(SceKernelEqueue eq, int id, void* udata);
int sceKernelDeleteAmprEvent_emul(SceKernelEqueue eq, int id);
int sceKernelAddAmprSystemEvent_emul(SceKernelEqueue eq, int id,
                                     int watch, void* udata);
int sceKernelDeleteAmprSystemEvent_emul(SceKernelEqueue eq, int id);
int sceKernelAddTimerEvent_emul(SceKernelEqueue eq, int id,
                                SceKernelUseconds usec, void* udata);
int sceKernelAddReadEvent_emul(SceKernelEqueue eq, int fd,
                               size_t size, void* udata);
int sceKernelAddWriteEvent_emul(SceKernelEqueue eq, int fd,
                                size_t size, void* udata);
int sceKernelAddFileEvent_emul(SceKernelEqueue eq, int fd,
                               int watch, void* udata);
int sceKernelAddUserEvent_emul(SceKernelEqueue eq, int id);
int sceKernelAddUserEventEdge_emul(SceKernelEqueue eq, int id);
int sceKernelAddHRTimerEvent_emul(SceKernelEqueue eq, int id,
                                  SceKernelTimespec* ts, void* udata);
int sceAgcDriverAddEqEvent_emul(SceKernelEqueue eq, uint32_t type,
                                void* udata);
int sceVideoOutAddFlipEvent_emul(SceKernelEqueue eq, int32_t handle,
                                 void* udata);
int sceVideoOutAddVblankEvent_emul(SceKernelEqueue eq, int32_t handle,
                                   void* udata);
int sceVideoOutAddPreVblankStartEvent_emul(SceKernelEqueue eq,
                                           int32_t handle,
                                           void* udata);
int sceVideoOutAddOutputModeEvent_emul(SceKernelEqueue eq, int32_t handle,
                                       void* udata);
}
#else
inline AprEqueuePublishResult apr_equeue_try_publish(SceKernelEqueue,
                                                      int32_t,
                                                      uint64_t) {
    return AprEqueuePublishResult::NativeFallback;
}
inline void apr_equeue_overlay_set_hook_availability(bool, bool) {}
inline void apr_equeue_register_amm_command_buffer(const void*) {}
inline void apr_equeue_unregister_amm_command_buffer(const void*) {}
inline void apr_equeue_note_command_buffer_event(const void*, SceKernelEqueue) {}
inline void apr_equeue_overlay_shutdown() {}
inline void apr_equeue_log_counters(const char*, bool) {}
#endif
