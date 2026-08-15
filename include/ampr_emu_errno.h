/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Internal POSIX/libkernel errno conversion helpers.
 */

#pragma once

#include <errno.h>
#include <stdint.h>
#include <sys/sce_errno.h>

static inline int ampr_sce_errno_from_posix(int err) {
    switch (err) {
        case EINTR: return SCE_KERNEL_ERROR_EINTR;
        case EPERM: return SCE_KERNEL_ERROR_EPERM;
        case ENOENT: return SCE_KERNEL_ERROR_ENOENT;
        case ESRCH: return SCE_KERNEL_ERROR_ESRCH;
        case EIO: return SCE_KERNEL_ERROR_EIO;
        case EBADF: return SCE_KERNEL_ERROR_EBADF;
        case EAGAIN: return SCE_KERNEL_ERROR_EAGAIN;
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
        case EWOULDBLOCK: return SCE_KERNEL_ERROR_EAGAIN;
#endif
        case ENOMEM: return SCE_KERNEL_ERROR_ENOMEM;
        case EACCES: return SCE_KERNEL_ERROR_EACCES;
        case EFAULT: return SCE_KERNEL_ERROR_EFAULT;
        case EBUSY: return SCE_KERNEL_ERROR_EBUSY;
        case EEXIST: return SCE_KERNEL_ERROR_EEXIST;
        case EINVAL: return SCE_KERNEL_ERROR_EINVAL;
        case ENOTDIR: return SCE_KERNEL_ERROR_ENOTDIR;
        case ENOSPC: return SCE_KERNEL_ERROR_ENOSPC;
        case EPIPE: return SCE_KERNEL_ERROR_EPIPE;
        case EOPNOTSUPP: return SCE_KERNEL_ERROR_EOPNOTSUPP;
        case ENOTEMPTY: return SCE_KERNEL_ERROR_ENOTEMPTY;
        case EMFILE: return SCE_KERNEL_ERROR_EMFILE;
        case ENFILE: return SCE_KERNEL_ERROR_ENFILE;
        case ENAMETOOLONG: return SCE_KERNEL_ERROR_ENAMETOOLONG;
        case ETIMEDOUT: return SCE_KERNEL_ERROR_ETIMEDOUT;
        case ECANCELED: return SCE_KERNEL_ERROR_ECANCELED;
        case ENOBUFS: return SCE_KERNEL_ERROR_ENOBUFS;
        default: return static_cast<int>(SCE_KERNEL_ERROR_UNKNOWN);
    }
}

static inline int ampr_posix_errno_from_sce(int rc) {
    const uint32_t u = static_cast<uint32_t>(rc);
    if ((u & 0xFFFF0000u) == 0x80020000u) {
        const int err = static_cast<int>(u & 0xFFFFu);
        if (err > 0 && err < 256) {
            return err;
        }
    }
    switch (rc) {
        case SCE_KERNEL_ERROR_EPERM: return EPERM;
        case SCE_KERNEL_ERROR_ENOENT: return ENOENT;
        case SCE_KERNEL_ERROR_EIO: return EIO;
        case SCE_KERNEL_ERROR_EBADF: return EBADF;
        case SCE_KERNEL_ERROR_EAGAIN: return EAGAIN;
        case SCE_KERNEL_ERROR_ENOMEM: return ENOMEM;
        case SCE_KERNEL_ERROR_EACCES: return EACCES;
        case SCE_KERNEL_ERROR_EFAULT: return EFAULT;
        case SCE_KERNEL_ERROR_EBUSY: return EBUSY;
        case SCE_KERNEL_ERROR_EINVAL: return EINVAL;
        case SCE_KERNEL_ERROR_ENOTDIR: return ENOTDIR;
        case SCE_KERNEL_ERROR_EMFILE: return EMFILE;
        case SCE_KERNEL_ERROR_ENFILE: return ENFILE;
        case SCE_KERNEL_ERROR_EOPNOTSUPP: return EOPNOTSUPP;
        case SCE_KERNEL_ERROR_ENAMETOOLONG: return ENAMETOOLONG;
        case SCE_KERNEL_ERROR_ETIMEDOUT: return ETIMEDOUT;
        default: return EIO;
    }
}

static inline int ampr_libkernel_return_from_sce(int rc) {
    if (rc == 0) {
        return 0;
    }
    errno = ampr_posix_errno_from_sce(rc);
    return -1;
}

static inline int ampr_libkernel_return_from_sce_count(int rc) {
    if (rc >= 0) {
        return rc;
    }
    errno = ampr_posix_errno_from_sce(rc);
    return errno ? ampr_sce_errno_from_posix(errno) : 0;
}
