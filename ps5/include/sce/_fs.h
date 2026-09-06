#ifndef AMPR_PAYLOAD_SDK_SCE_FS_H
#define AMPR_PAYLOAD_SDK_SCE_FS_H

#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/dirent.h>
#include <sys/types.h>
#include <sys/uio.h>
#include "_types.h"

#define SCE_KERNEL_NAME_MAX 255
#define SCE_KERNEL_PATH_MAX 1024
#define SCE_KERNEL_O_RDONLY O_RDONLY
#define SCE_KERNEL_O_WRONLY O_WRONLY
#define SCE_KERNEL_O_APPEND O_APPEND
#define SCE_KERNEL_O_CREAT O_CREAT
#define SCE_KERNEL_O_TRUNC O_TRUNC
#define SCE_KERNEL_O_DIRECTORY O_DIRECTORY
#define SCE_KERNEL_S_IRWU 0777

typedef struct stat SceKernelStat;
typedef mode_t SceKernelMode;
typedef struct iovec SceKernelIovec;

#ifndef SCE_KERNEL_IOV_MAX
#define SCE_KERNEL_IOV_MAX 1024
#endif

#define SCE_KERNEL_AIO_PRIORITY_LOW 1
#define SCE_KERNEL_AIO_PRIORITY_MID 2
#define SCE_KERNEL_AIO_PRIORITY_HIGH 3
#define SCE_KERNEL_AIO_STATE_NOTIFIED 0x10000
#define SCE_KERNEL_AIO_STATE_SUBMITTED 1
#define SCE_KERNEL_AIO_STATE_PROCESSING 2
#define SCE_KERNEL_AIO_STATE_COMPLETED 3
#define SCE_KERNEL_AIO_STATE_ABORTED 4

#define SCE_KERNEL_AIO_WAIT_AND 0x01
#define SCE_KERNEL_AIO_WAIT_OR 0x02
#define SCE_KERNEL_AIO_SCHED_WINDOW_MAX 128
#define SCE_KERNEL_AIO_DELAYED_COUNT_MAX 128
#define SCE_KERNEL_AIO_DISABLE_SPLIT 0
#define SCE_KERNEL_AIO_SPLIT_SIZE_DEFAULT 0x100000
#define SCE_KERNEL_AIO_SPLIT_CHUNK_SIZE_DEFAULT 0x100000
#define SCE_KERNEL_AIO_REQUEST_NUM_MAX 128
#define SCE_KERNEL_AIO_ID_NUM_MAX 128

typedef struct SceKernelAioResult {
    int64_t returnValue;
    uint32_t state;
} SceKernelAioResult;

typedef struct SceKernelAioSchedulingParam {
    int schedulingWindowSize;
    int delayedCountLimit;
    uint32_t enableSplit;
    uint32_t splitSize;
    uint32_t splitChunkSize;
} SceKernelAioSchedulingParam;

typedef struct SceKernelAioParam {
    SceKernelAioSchedulingParam low;
    SceKernelAioSchedulingParam mid;
    SceKernelAioSchedulingParam high;
} SceKernelAioParam;

typedef int SceKernelAioSubmitId;

typedef struct SceKernelAioRWRequest {
    off_t offset;
    size_t nbyte;
    void *buf;
    SceKernelAioResult *result;
    int fd;
} SceKernelAioRWRequest;

#ifdef __cplusplus
extern "C" {
#endif

ssize_t sceKernelWrite(int fd, const void *buffer, size_t size);
int sceKernelOpen(const char *path, int flags, SceKernelMode mode);
int sceKernelClose(int fd);
int sceKernelUnlink(const char *path);
int sceKernelCheckReachability(const char *path);
int sceKernelFsync(int fd);
int sceKernelRename(const char *from, const char *to);
int sceKernelStat(const char *path, SceKernelStat *stat);
int sceKernelFstat(int fd, SceKernelStat *stat);
int sceKernelGetdents(int fd, char *buffer, int size);
int sceKernelGetdirentries(int fd, char *buffer, int size, long *basep);
ssize_t sceKernelRead(int fd, void *buffer, size_t size);
ssize_t sceKernelReadv(int fd, const SceKernelIovec *iov, int iovcnt);
ssize_t sceKernelPread(int fd, void *buffer, size_t size, off_t offset);
ssize_t sceKernelPreadv(int fd, const SceKernelIovec *iov, int iovcnt,
                        off_t offset);

int sceKernelAioDeleteRequests(SceKernelAioSubmitId ids[], int count,
                               int results[]);
int sceKernelAioDeleteRequest(SceKernelAioSubmitId id, int *result);
int sceKernelAioInitializeImpl(void *param, int size);
#define sceKernelAioInitialize(param) \
    sceKernelAioInitializeImpl((void *)(param), sizeof(SceKernelAioParam))
int sceKernelAioPollRequests(SceKernelAioSubmitId ids[], int count,
                             int states[]);
int sceKernelAioPollRequest(SceKernelAioSubmitId id, int *state);
int sceKernelAioSubmitReadCommands(SceKernelAioRWRequest requests[],
                                    int count, int priority,
                                    SceKernelAioSubmitId *id);
int sceKernelAioSubmitReadCommandsMultiple(SceKernelAioRWRequest requests[],
                                            int count, int priority,
                                            SceKernelAioSubmitId ids[]);
void sceKernelAioInitializeParam(SceKernelAioParam *param);
int sceKernelAioSetParam(SceKernelAioSchedulingParam *param,
                         int schedulingWindowSize, int delayedCountLimit,
                         uint32_t enableSplit, uint32_t splitSize,
                         uint32_t splitChunkSize);

#ifdef __cplusplus
}
#endif

#endif
