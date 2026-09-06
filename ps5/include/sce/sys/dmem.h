#ifndef AMPR_PAYLOAD_SDK_SCE_DMEM_H
#define AMPR_PAYLOAD_SDK_SCE_DMEM_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define SCE_KERNEL_PROT_CPU_READ 0x01
#define SCE_KERNEL_PROT_CPU_RW 0x02
#define SCE_KERNEL_PROT_CPU_EXEC 0x04
#define SCE_KERNEL_PROT_CPU_ALL 0x07
#define SCE_KERNEL_PROT_AMPR_WRITE 0x80
#define SCE_KERNEL_PROT_AMPR_ALL 0xc0
#define SCE_KERNEL_PAGE_SIZE 16384

typedef enum SceKernelMapEntryOperation {
    SCE_KERNEL_MAP_OP_MAP_DIRECT,
    SCE_KERNEL_MAP_OP_UNMAP,
    SCE_KERNEL_MAP_OP_PROTECT,
    SCE_KERNEL_MAP_OP_MAP_FLEXIBLE,
    SCE_KERNEL_MAP_OP_TYPE_PROTECT,
} SceKernelMapEntryOperation;

typedef struct SceKernelBatchMapEntry {
    void *start;
    off_t offset;
    size_t length;
    char protection;
    char type;
    short pad1;
    int operation;
} SceKernelBatchMapEntry;

typedef struct SceKernelVirtualQueryInfo {
    void *start;
    void *end;
    off_t offset;
    int protection;
    int memoryType;
    unsigned isFlexibleMemory : 1;
    unsigned isDirectMemory : 1;
    unsigned isStack : 1;
    unsigned isPooledMemory : 1;
    unsigned isCommitted : 1;
    unsigned isGpuPrt : 1;
    unsigned ammUsage : 1;
    unsigned reserved : 1;
    char name[32];
    uint8_t gpuMaskId;
    uint8_t reserved2;
} SceKernelVirtualQueryInfo;

#define SCE_KERNEL_MEMORY_POOL_OP_COMMIT 1
#define SCE_KERNEL_MEMORY_POOL_OP_PROTECT 3
#define SCE_KERNEL_MEMORY_POOL_OP_TYPE_PROTECT 4

typedef struct SceKernelMemoryPoolBatchEntry {
    unsigned op;
    unsigned flags;
    union {
        struct { void *addr; size_t len; unsigned char prot; unsigned char type; } commit;
        struct { void *addr; size_t len; } decommit;
        struct { void *addr; size_t len; unsigned char prot; } protect;
        struct { void *addr; size_t len; unsigned char prot; unsigned char type; } typeProtect;
        struct { void *dst; void *src; size_t len; } move;
        uintptr_t padding[3];
    };
} SceKernelMemoryPoolBatchEntry;

#ifdef __cplusplus
extern "C" {
#endif

size_t sceKernelGetDirectMemorySize(void);
int32_t sceKernelMapFlexibleMemory(void **address, size_t length,
                                   int protection, int flags);
int32_t sceKernelMapDirectMemory(void **address, size_t length,
                                 int protection, int flags, off_t offset,
                                 size_t maxPageSize);
int32_t sceKernelMapDirectMemory2(void **address, size_t length, int type,
                                  int protection, int flags, off_t offset,
                                  size_t maxPageSize);
int32_t sceKernelBatchMap(SceKernelBatchMapEntry *entries, int count,
                          int *completed);
int32_t sceKernelBatchMap2(SceKernelBatchMapEntry *entries, int count,
                           int *completed, int flags);
int32_t sceKernelJitMapSharedMemory(int fd, int protection, void **address);
int32_t sceKernelVirtualQuery(const void *address, int flags,
                              SceKernelVirtualQueryInfo *info,
                              size_t infoSize);
int32_t sceKernelQueryMemoryProtection(void *address, void **start, void **end,
                                       int *protection);
int32_t sceKernelMtypeprotect(const void *address, size_t size, int type,
                              int protection);
int32_t sceKernelAvailableDirectMemorySize(off_t start, off_t end,
                                            size_t alignment, off_t *outStart,
                                            size_t *outSize);
int32_t sceKernelGetPageTableStats(int *cpuTotal, int *cpuAvailable,
                                   int *gpuTotal, int *gpuAvailable);
int32_t sceKernelMemoryPoolBatch(const SceKernelMemoryPoolBatchEntry *entries,
                                 int count, int *completed, int flags);
int32_t sceKernelMemoryPoolCommit(void *address, size_t length, int type,
                                  int protection, int flags);
int32_t sceKernelMapNamedFlexibleMemory(void **address, size_t length,
                                        int protection, int flags,
                                        const char *name);
int32_t sceKernelMapNamedDirectMemory(void **address, size_t length,
                                      int protection, int flags, off_t offset,
                                      size_t alignment, const char *name);

#ifdef __cplusplus
}
#endif

#endif
