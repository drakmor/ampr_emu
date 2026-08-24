#ifndef AMPR_PAYLOAD_SDK_SCE_KERNEL_BASE_H
#define AMPR_PAYLOAD_SDK_SCE_KERNEL_BASE_H

#include <stddef.h>
#include <stdint.h>
#include "_types.h"

#define SCE_KERNEL_CLOCK_MONOTONIC CLOCK_MONOTONIC
#define SCE_KERNEL_PRIO_FIFO_HIGHEST 256
#define SCE_KERNEL_PRIO_FIFO_LOWEST 767

typedef struct {
    size_t size;
} SceKernelLoadModuleOpt;

#ifdef __cplusplus
extern "C" {
#endif

int sceKernelMprotect(const void *addr, size_t len, int prot);
int sceKernelUsleep(SceKernelUseconds microseconds);
int sceKernelNanosleep(const SceKernelTimespec *rqtp, SceKernelTimespec *rmtp);
int sceKernelClockGettime(SceKernelClockid clockId, SceKernelTimespec *tp);
int sceKernelGettimeofday(SceKernelTimeval *tp);
uint64_t sceKernelGetProcessTimeCounter(void);
uint64_t sceKernelGetProcessTimeCounterFrequency(void);
SceKernelModule sceKernelLoadStartModule(const char *moduleFileName,
    size_t args, const void *argp, uint32_t flags,
    const SceKernelLoadModuleOpt *opt, int *result);
int sceKernelDlsym(SceKernelModule handle, const char *symbol, void **address);

#ifdef __cplusplus
}
#endif

#endif
