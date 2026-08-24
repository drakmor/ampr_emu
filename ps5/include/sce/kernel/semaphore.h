#ifndef AMPR_PAYLOAD_SDK_SCE_SEMAPHORE_H
#define AMPR_PAYLOAD_SDK_SCE_SEMAPHORE_H

#include <stdint.h>
#include "_types.h"

#define SCE_KERNEL_SEMA_ATTR_TH_FIFO 0x01

typedef struct _SceKernelSema *SceKernelSema;
#define SCE_KERNEL_SEMA_ID_INVALID ((SceKernelSema)-1)

#ifdef __cplusplus
extern "C" {
#endif

int sceKernelCreateSema(SceKernelSema *semaphore, const char *name,
                        uint32_t attributes, int initial, int maximum,
                        const void *options);
int sceKernelDeleteSema(SceKernelSema semaphore);
int sceKernelWaitSema(SceKernelSema semaphore, int count,
                      SceKernelUseconds *timeout);
int sceKernelSignalSema(SceKernelSema semaphore, int count);

#ifdef __cplusplus
}
#endif

#endif
