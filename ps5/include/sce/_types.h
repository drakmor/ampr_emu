#ifndef AMPR_PAYLOAD_SDK_SCE_TYPES_H
#define AMPR_PAYLOAD_SDK_SCE_TYPES_H

#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <sys/param.h>

typedef struct timespec SceKernelTimespec;
typedef struct timeval SceKernelTimeval;
typedef clockid_t SceKernelClockid;
typedef uint64_t SceKernelCpumask;
typedef unsigned int SceKernelUseconds;
typedef int32_t SceKernelModule;

#endif
