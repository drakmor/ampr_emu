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

#pragma once

/*
 * Minimal stub of Sony's <kernel.h> used by the public AMPR header.
 *
 * Goal: allow building this userland AMPR emulation on standard POSIX systems.
 * Only the types referenced by the public AMPR header are defined here.
 *
 * When compiling for PS5 with the homebrew SDK, prefer the SDK headers and
 * ensure they are found before this file in your include path.
 */

#include <stdint.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/mman.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _SceKernelEqueue* SceKernelEqueue;
typedef int32_t SceKernelMemoryType;

/* Minimal kevent-compatible structure for emulation. */
typedef struct kevent {
    uintptr_t ident;
    int16_t   filter;
    uint16_t  flags;
    uint32_t  fflags;
    intptr_t  data;
    void*     udata;
} SceKernelEvent;

typedef uint32_t SceKernelUseconds;
typedef int32_t  SceKernelModule;

typedef struct {
    size_t size;
} SceKernelLoadModuleOpt;

typedef struct {
    size_t size;
} SceKernelUnloadModuleOpt;

typedef enum {
    SCE_KERNEL_MAP_OP_MAP_DIRECT = 0,
    SCE_KERNEL_MAP_OP_UNMAP = 1,
    SCE_KERNEL_MAP_OP_PROTECT = 2,
    SCE_KERNEL_MAP_OP_MAP_FLEXIBLE = 3,
    SCE_KERNEL_MAP_OP_TYPE_PROTECT = 4,
} SceKernelMapEntryOperation;

/*
 * The real SDK defines its own stat structure. For emulation we assume a
 * compatible layout and just alias to the host's struct stat.
 */
typedef struct stat SceKernelStat;


/*
 * Userland emulation of the event queue APIs used by the AMPR samples.
 * These are NOT PS5 kernel primitives; they are provided only so the
 * emulation can run without a kernel component.
 */
extern int sceKernelCreateEqueue(SceKernelEqueue* eq, const char* name);
extern int sceKernelAddAmprEvent(SceKernelEqueue eq, uint32_t id, void* udata);
extern int sceKernelDeleteAmprEvent(SceKernelEqueue eq, uint32_t id);
extern int sceKernelAddAmprSystemEvent(SceKernelEqueue eq, int id, unsigned int data, void* udata);
extern int sceKernelWaitEqueue(SceKernelEqueue eq, SceKernelEvent* ev, int evCount, int* outCount, SceKernelUseconds* timeout);
extern int sceKernelDeleteEqueue(SceKernelEqueue eq);

extern SceKernelModule sceKernelLoadStartModule(const char* moduleFileName,
                                               size_t args,
                                               const void* argp,
                                               uint32_t flags,
                                               const SceKernelLoadModuleOpt* pOpt,
                                               int* pRes);
extern int sceKernelStopUnloadModule(SceKernelModule handle,
                                     size_t args,
                                     const void* argp,
                                     uint32_t flags,
                                     const SceKernelUnloadModuleOpt* pOpt,
                                     int* pRes);
extern int sceKernelDlsym(SceKernelModule handle, const char* symbol, void** addrp) __attribute__((noinline));

extern int sceKernelMprotect(const void* addr, size_t len, int prot);
extern int sceKernelMapFlexibleMemory(void** addrInOut, size_t len, int prot, int flags);
extern int sceKernelReleaseFlexibleMemory(void* addr, size_t len);
extern int sceKernelAllocateDirectMemory(off_t searchStart, off_t searchEnd, size_t len, size_t alignment, SceKernelMemoryType type, off_t* outOffset);
extern int sceKernelReleaseDirectMemory(off_t start, size_t len);
extern int sceKernelCheckedReleaseDirectMemory(off_t start, size_t len);
extern int sceKernelMapDirectMemory(void** addr, size_t len, int prot, int flags, off_t offset, size_t alignment);
extern int sceKernelMapDirectMemory2(void** addr, size_t len, int type, int prot, int flags, off_t offset, size_t alignment);
extern int sceKernelMunmap(void* addr, size_t len);
extern size_t sceKernelGetDirectMemorySize(void);
extern int sceKernelAvailableDirectMemorySize(off_t start, off_t end, size_t alignment, off_t* startOut, size_t* sizeOut);
extern int sceKernelMtypeprotect(const void* addr, size_t size, int type, int prot);
extern int sceKernelReserveVirtualRange(void** addr, size_t len, int flags, size_t alignment);
extern int sceKernelAprGetFileSize(int fileId, uint64_t* outSize);
extern int sceKernelAprGetFileStat(int fileId, SceKernelStat* st);
extern int sceKernelAprResolveFilepathsToIds(const char* path[], uint32_t num, uint32_t ids[], uint32_t* errorIndex);
extern int sceKernelAprResolveFilepathsToIdsAndFileSizes(const char* path[], uint32_t num, uint32_t ids[], size_t fileSizes[], uint32_t* errorIndex);
extern int sceKernelAprResolveFilepathsWithPrefixToIds(const char* pathPrefix, const char* path[], uint32_t num, uint32_t ids[], uint32_t* errorIndex);
extern int sceKernelAprResolveFilepathsWithPrefixToIdsAndFileSizes(const char* pathPrefix, const char* path[], uint32_t num, uint32_t ids[], size_t fileSizes[], uint32_t* errorIndex);
extern int sceKernelAprResolveFilepathsToIdsForEach(const char* path[], uint32_t num, uint32_t ids[], int results[]);
extern int sceKernelAprResolveFilepathsToIdsAndFileSizesForEach(const char* path[], uint32_t num, uint32_t ids[], size_t fileSizes[], int results[]);
extern int sceKernelAprResolveFilepathsWithPrefixToIdsForEach(const char* pathPrefix, const char* path[], uint32_t num, uint32_t ids[], int results[]);
extern int sceKernelAprResolveFilepathsWithPrefixToIdsAndFileSizesForEach(const char* pathPrefix, const char* path[], uint32_t num, uint32_t ids[], size_t fileSizes[], int results[]);
extern int sceKernelAprSubmitCommandBuffer(void* submitParam);
extern int sceKernelAprSubmitCommandBuffer_TEST(void* submitParam);
extern int sceKernelAprSubmitCommandBufferAndGetResult(void* submitParam);
extern int sceKernelAprSubmitCommandBufferAndGetResult_TEST(void* submitParam);
extern int sceKernelAprSubmitCommandBufferAndGetId(void* submitParam);
extern int sceKernelAprWaitCommandBuffer(uint32_t id);


// Compatibility constants for SDK samples when building without the real PS5 headers.
#ifndef PAGE_SIZE
#define PAGE_SIZE 16384
#endif

#ifndef SCE_OK
#define SCE_OK 0
#endif

#ifndef SCE_KERNEL_ERROR_UNKNOWN
#define SCE_KERNEL_ERROR_UNKNOWN 0x80020000
#endif
#ifndef SCE_KERNEL_ERROR_EPERM
#define SCE_KERNEL_ERROR_EPERM   -2147352575 /* 0x80020001 */
#endif
#ifndef SCE_KERNEL_ERROR_ENOENT
#define SCE_KERNEL_ERROR_ENOENT  -2147352574 /* 0x80020002 */
#endif
#ifndef SCE_KERNEL_ERROR_ESRCH
#define SCE_KERNEL_ERROR_ESRCH   -2147352573 /* 0x80020003 */
#endif
#ifndef SCE_KERNEL_ERROR_EIO
#define SCE_KERNEL_ERROR_EIO     -2147352571 /* 0x80020005 */
#endif
#ifndef SCE_KERNEL_ERROR_EBADF
#define SCE_KERNEL_ERROR_EBADF   -2147352567 /* 0x80020009 */
#endif
#ifndef SCE_KERNEL_ERROR_ENOMEM
#define SCE_KERNEL_ERROR_ENOMEM  -2147352564 /* 0x8002000C */
#endif
#ifndef SCE_KERNEL_ERROR_EACCES
#define SCE_KERNEL_ERROR_EACCES  -2147352563 /* 0x8002000D */
#endif
#ifndef SCE_KERNEL_ERROR_EFAULT
#define SCE_KERNEL_ERROR_EFAULT  -2147352562 /* 0x8002000E */
#endif
#ifndef SCE_KERNEL_ERROR_EBUSY
#define SCE_KERNEL_ERROR_EBUSY   -2147352560 /* 0x80020010 */
#endif
#ifndef SCE_KERNEL_ERROR_EEXIST
#define SCE_KERNEL_ERROR_EEXIST  -2147352559 /* 0x80020011 */
#endif
#ifndef SCE_KERNEL_ERROR_EINVAL
#define SCE_KERNEL_ERROR_EINVAL  -2147352554 /* 0x80020016 */
#endif
#ifndef SCE_KERNEL_ERROR_EAGAIN
#define SCE_KERNEL_ERROR_EAGAIN  -2147352541 /* 0x80020023 */
#endif
#ifndef SCE_KERNEL_ERROR_ENOSPC
#define SCE_KERNEL_ERROR_ENOSPC  -2147352548 /* 0x8002001C */
#endif
#ifndef SCE_KERNEL_ERROR_EPIPE
#define SCE_KERNEL_ERROR_EPIPE   -2147352544 /* 0x80020020 */
#endif
#ifndef SCE_KERNEL_ERROR_ENOBUFS
#define SCE_KERNEL_ERROR_ENOBUFS -2147352521 /* 0x80020037 */
#endif
#ifndef SCE_KERNEL_ERROR_ETIMEDOUT
#define SCE_KERNEL_ERROR_ETIMEDOUT -2147352516 /* 0x8002003C */
#endif
#ifndef SCE_KERNEL_ERROR_ENOTEMPTY
#define SCE_KERNEL_ERROR_ENOTEMPTY -2147352510 /* 0x80020042 */
#endif
#ifndef SCE_KERNEL_ERROR_ECANCELED
#define SCE_KERNEL_ERROR_ECANCELED -2147352491 /* 0x80020055 */
#endif

// Minimal event flag constants for equeue emulation (kqueue-compatible subset).
#ifndef SCE_KERNEL_EVFILT_AMPR
#define SCE_KERNEL_EVFILT_AMPR (-25)
#endif
#ifndef SCE_KERNEL_EVFILT_AMPR_SYSTEM
#define SCE_KERNEL_EVFILT_AMPR_SYSTEM 0xFFE2
#endif
#ifndef SCE_KERNEL_EV_ADD
#define SCE_KERNEL_EV_ADD       0x0001
#endif
#ifndef SCE_KERNEL_EV_DELETE
#define SCE_KERNEL_EV_DELETE    0x0002
#endif
#ifndef SCE_KERNEL_EV_ENABLE
#define SCE_KERNEL_EV_ENABLE    0x0004
#endif
#ifndef SCE_KERNEL_EV_DISABLE
#define SCE_KERNEL_EV_DISABLE   0x0008
#endif
#ifndef SCE_KERNEL_EV_ONESHOT
#define SCE_KERNEL_EV_ONESHOT   0x0010
#endif
#ifndef SCE_KERNEL_EV_DISPATCH
#define SCE_KERNEL_EV_DISPATCH  0x0080
#endif
#ifndef SCE_KERNEL_EV_CLEAR
#define SCE_KERNEL_EV_CLEAR     0x0020
#endif
#ifndef SCE_KERNEL_EVFLAG_EOF
#define SCE_KERNEL_EVFLAG_EOF   0x8000
#endif
#ifndef SCE_KERNEL_EVFLAG_ERROR
#define SCE_KERNEL_EVFLAG_ERROR 0x4000
#endif

static inline int sceKernelGetEventFilter(const SceKernelEvent* ev) {
    return ev ? ev->filter : 0;
}
static inline uintptr_t sceKernelGetEventId(const SceKernelEvent* ev) {
    return ev ? ev->ident : 0;
}
static inline intptr_t sceKernelGetEventData(const SceKernelEvent* ev) {
    return ev ? ev->data : 0;
}
static inline unsigned int sceKernelGetEventFflags(const SceKernelEvent* ev) {
    return ev ? ev->fflags : 0;
}
static inline int sceKernelGetEventError(const SceKernelEvent* ev) {
    return ev ? ((ev->flags & SCE_KERNEL_EVFLAG_ERROR) ? (int)ev->data : 0) : 0;
}
static inline void* sceKernelGetEventUserData(const SceKernelEvent* ev) {
    return ev ? ev->udata : nullptr;
}
#ifndef SCE_KERNEL_MTYPE_C
#define SCE_KERNEL_MTYPE_C 11
#endif
#ifndef SCE_KERNEL_MTYPE_C_SHARED
#define SCE_KERNEL_MTYPE_C_SHARED 12
#endif

#ifndef SCE_KERNEL_MAIN_DMEM_SIZE
#define SCE_KERNEL_MAIN_DMEM_SIZE (sceKernelGetDirectMemorySize())
#endif

#ifndef SCE_KERNEL_PROT_CPU_READ
#define SCE_KERNEL_PROT_CPU_READ  0x01
#endif
#ifndef SCE_KERNEL_PROT_CPU_WRITE
#define SCE_KERNEL_PROT_CPU_WRITE 0x02
#endif
#ifndef SCE_KERNEL_PROT_CPU_EXEC
#define SCE_KERNEL_PROT_CPU_EXEC  0x04
#endif
#ifndef SCE_KERNEL_PROT_CPU_RW
#define SCE_KERNEL_PROT_CPU_RW    0x02
#endif
#ifndef SCE_KERNEL_PROT_CPU_ALL
#define SCE_KERNEL_PROT_CPU_ALL   0x07
#endif

#ifndef SCE_KERNEL_PROT_GPU_READ
#define SCE_KERNEL_PROT_GPU_READ  0x10
#endif
#ifndef SCE_KERNEL_PROT_GPU_WRITE
#define SCE_KERNEL_PROT_GPU_WRITE 0x20
#endif
#ifndef SCE_KERNEL_PROT_GPU_RW
#define SCE_KERNEL_PROT_GPU_RW    0x30
#endif
#ifndef SCE_KERNEL_PROT_GPU_ALL
#define SCE_KERNEL_PROT_GPU_ALL   0x30
#endif

#ifndef SCE_KERNEL_PROT_AMPR_READ
#define SCE_KERNEL_PROT_AMPR_READ 0x40
#endif
#ifndef SCE_KERNEL_PROT_AMPR_WRITE
#define SCE_KERNEL_PROT_AMPR_WRITE 0x80
#endif
#ifndef SCE_KERNEL_PROT_AMPR_RW
#define SCE_KERNEL_PROT_AMPR_RW   0xc0
#endif
#ifndef SCE_KERNEL_PROT_AMPR_ALL
#define SCE_KERNEL_PROT_AMPR_ALL  0xc0
#endif

#ifndef PROT_FIO_ALL
#define PROT_FIO_ALL 0
#endif

#ifndef SCE_KERNEL_MAP_FIXED
#define SCE_KERNEL_MAP_FIXED 0x0010
#endif

#ifdef __cplusplus
}
#endif
