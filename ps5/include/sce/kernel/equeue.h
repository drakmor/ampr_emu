#ifndef AMPR_PAYLOAD_SDK_SCE_EQUEUE_H
#define AMPR_PAYLOAD_SDK_SCE_EQUEUE_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/event.h>
#include "_types.h"

typedef struct _SceKernelEqueue *SceKernelEqueue;
typedef struct kevent SceKernelEvent;

#define SCE_KERNEL_EVFILT_USER EVFILT_USER
#define SCE_KERNEL_EVFILT_AMPR EVFILT_AMPR

#ifdef __cplusplus
extern "C" {
#endif

int sceKernelCreateEqueue(SceKernelEqueue *queue, const char *name);
int sceKernelDeleteEqueue(SceKernelEqueue queue);
int sceKernelWaitEqueue(SceKernelEqueue queue, SceKernelEvent *events,
                        int count, int *out, SceKernelUseconds *timeout);
int sceKernelAddTimerEvent(SceKernelEqueue queue, int id,
                           SceKernelUseconds usec, void *userData);
int sceKernelAddReadEvent(SceKernelEqueue queue, int fd, size_t size,
                          void *userData);
int sceKernelAddWriteEvent(SceKernelEqueue queue, int fd, size_t size,
                           void *userData);
int sceKernelAddFileEvent(SceKernelEqueue queue, int fd, int watch,
                          void *userData);
int sceKernelAddUserEvent(SceKernelEqueue queue, int id);
int sceKernelAddUserEventEdge(SceKernelEqueue queue, int id);
int sceKernelDeleteUserEvent(SceKernelEqueue queue, int id);
int sceKernelTriggerUserEvent(SceKernelEqueue queue, int id, void *userData);
int sceKernelAddHRTimerEvent(SceKernelEqueue queue, int id,
                             SceKernelTimespec *time, void *userData);
int sceKernelAddAmprEvent(SceKernelEqueue queue, int id, void *userData);
int sceKernelDeleteAmprEvent(SceKernelEqueue queue, int id);

#ifdef __cplusplus
}
#endif

#endif
