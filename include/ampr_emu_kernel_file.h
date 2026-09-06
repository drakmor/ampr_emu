/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Internal file/path libkernel wrappers.
 */

#pragma once

#include <ampr_emu_kernel_lookup.h>
#include <ampr_emu_index.h>
#include <ampr_emu_errno.h>
#include "ampr_emu_pack.h"

#include <_kernel.h>
#include <fcntl.h>
#include <kernel.h>
#include <sys/stat.h>

static inline int ampr_real_posix_open(const char* path, int flags, SceKernelMode mode) {
    using Fn = int (*)(const char*, int, ...);
    Fn fn = ampr_fixed_kernel_slot<Fn>(kAmprLibkernelHook_open);
    if (fn) return fn(path, flags, mode);
    errno = EIO;
    return -1;
}

// APR callers already own an immutable AMPRIDX3 file id/view. Resolve packed
// storage through that boundary instead of recursively performing a path lookup
// from the common real-open wrapper. This avoids compiler TLS support in the
// PRX and keeps manifest/index opens on the immutable real libkernel slot.
static inline int ampr_open_indexed_or_real(uint32_t fileId,
                                            const FileEntryView& entry,
                                            int flags,
                                            SceKernelMode mode,
                                            bool* physicalFd = nullptr) {
    if (physicalFd) *physicalFd = false;
#if AMPR_EMU_PACK_ENABLE
    bool handled = false;
    const int packedFd = ampr_pack_try_open_indexed(fileId,
                                                    entry,
                                                    flags,
                                                    mode,
                                                    &handled);
    if (handled) {
        return packedFd;
    }
#else
    (void)fileId;
#endif
    const int fd = ampr_real_posix_open(entry.path, flags, mode);
    if (fd >= 0) {
        if (physicalFd) *physicalFd = true;
        return fd;
    }
    return fd == -1 ? ampr_sce_errno_from_posix(errno) : fd;
}

static inline int ampr_real_posix_stat(const char* path, struct stat* st) {
    using Fn = int (*)(const char*, struct stat*);
    Fn fn = ampr_fixed_kernel_slot<Fn>(kAmprLibkernelHook_stat);
    if (fn) return fn(path, st);
    errno = EIO;
    return -1;
}

static inline int ampr_real_sceKernelCheckReachability(const char* path) {
    using Fn = int (*)(const char*);
    Fn fn = ampr_fixed_kernel_slot<Fn>(kAmprLibkernelHook_sceKernelCheckReachability);
    return fn(path);
}

static inline int ampr_real_posix_unlink(const char* path) {
    using Fn = int (*)(const char*);
    Fn fn = ampr_fixed_kernel_slot<Fn>(kAmprLibkernelHook_unlink);
    if (fn) return fn(path);
    errno = EIO;
    return -1;
}

// Bootstrap/index descriptors are always physical. When a matching POSIX
// entry is intercepted, use its published original slot so these operations do
// not re-enter virtual-fd dispatch. In configurations where that interception
// is not compiled, the unchanged SCE wrapper remains a direct libkernel call.
static inline int ampr_real_physical_close(int fd) {
    using Fn = int (*)(int);
#if AMPR_EMU_PACK_ENABLE && (AMPR_EMU_PACK_DIRECTORY_OVERLAY_ENABLE || AMPR_EMU_PACK_PROCESS_OPEN_ENABLE)
    if (Fn fn = ampr_fixed_kernel_slot<Fn>(kAmprLibkernelHook_close)) {
        return fn(fd);
    }
#endif
    if (Fn fn = ampr_dynamic_kernel_func_or_null<Fn>("close")) return fn(fd);
    errno = EIO;
    return -1;
}

static inline int ampr_real_physical_fstat(int fd, struct stat* st) {
    using Fn = int (*)(int, struct stat*);
#if AMPR_EMU_PACK_ENABLE && (AMPR_EMU_PACK_DIRECTORY_OVERLAY_ENABLE || AMPR_EMU_PACK_PROCESS_OPEN_ENABLE)
    if (Fn fn = ampr_fixed_kernel_slot<Fn>(kAmprLibkernelHook_fstat)) {
        return fn(fd, st);
    }
#endif
    if (Fn fn = ampr_dynamic_kernel_func_or_null<Fn>("fstat")) {
        return fn(fd, st);
    }
    errno = EIO;
    return -1;
}

static inline ssize_t ampr_real_physical_pread(int fd,
                                               void* buffer,
                                               size_t size,
                                               off_t offset) {
    using Fn = ssize_t (*)(int, void*, size_t, off_t);
#if AMPR_EMU_PACK_ENABLE && AMPR_EMU_PACK_INTERCEPT_PROCESS_SYNC_READS
    if (Fn fn = ampr_fixed_kernel_slot<Fn>(kAmprLibkernelHook_pread)) {
        return fn(fd, buffer, size, offset);
    }
#endif
    if (Fn fn = ampr_dynamic_kernel_func_or_null<Fn>("pread")) {
        return fn(fd, buffer, size, offset);
    }
    errno = EIO;
    return -1;
}

static inline int ampr_real_physical_getdents(int fd,
                                              char* buffer,
                                              int size) {
    using Fn = int (*)(int, char*, int);
#if AMPR_EMU_PACK_ENABLE && AMPR_EMU_PACK_DIRECTORY_OVERLAY_ENABLE
    if (Fn fn = ampr_fixed_kernel_slot<Fn>(kAmprLibkernelHook_getdents)) {
        return fn(fd, buffer, size);
    }
#endif
    if (Fn fn = ampr_dynamic_kernel_func_or_null<Fn>("getdents")) {
        return fn(fd, buffer, size);
    }
    errno = EIO;
    return -1;
}

static inline int ampr_real_posix_rename(const char* from, const char* to) {
    using Fn = int (*)(const char*, const char*);
    Fn fn = ampr_fixed_kernel_slot<Fn>(kAmprLibkernelHook_rename);
    if (fn) return fn(from, to);
    errno = EIO;
    return -1;
}
