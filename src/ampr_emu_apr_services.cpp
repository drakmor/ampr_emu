/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * APR service implementation.
 */

#define AMPR_EMU_CORE_IMPL 1
#include "ampr_emu_apr_services.h"
#include "ampr_emu_apr_reactor.h"
#include "ampr_emu_apr_reactor_common.h"
#include "ampr_emu_command_buffer_apr.h"
#include "ampr_emu_command_buffer_common.h"
#include "ampr_emu_command_buffer_types.h"
#include "ampr_emu_errno.h"
#include "ampr_emu_index.h"
#include "ampr_emu_log.h"
#include "ampr_emu_sync.h"

#include <atomic>
#include <cstring>

#ifndef SCE_KERNEL_PATH_MAX
#define SCE_KERNEL_PATH_MAX 1024
#endif

namespace {

static std::atomic<uint64_t> g_next_submit_id{1};

static uint64_t apr_next_submit_id() {
    return g_next_submit_id.fetch_add(1ull, std::memory_order_relaxed);
}

static int apr_submit_reject(SceAprResultBuffer* res, int rc, uint32_t errorOffset = 0) {
    if (res) {
        res->result = rc;
        res->errorOffset = errorOffset;
    }
    return rc;
}

} // namespace

// ---------------- APR service ----------------
namespace sce::Ampr::Emu {

int aprResolveFilepathsToIds(const char* path[], uint32_t num, SceAprFileId ids[], uint32_t* errorIndex) {
    const int countRc = validate_resolve_count(num);
    if (countRc != 0) return countRc;
    const int outputRc = validate_resolve_outputs(ids);
    if (outputRc != 0) return outputRc;
    const int pathRc = validate_resolve_path_array(path, num);
    if (pathRc != 0) return pathRc;
    if (errorIndex) *errorIndex = 0;
    for (uint32_t i=0;i<num;i++) {
        uint32_t id=0;
        AMPR_TLOGF("apr.resolveIds item enter idx=%u path=%s", (unsigned)i, ampr_log_path_arg(path[i]));
        int rc = ampr_index_resolve_path_to_id(path[i], &id, nullptr);
        if (rc!=0) {
            const int sceRc = ampr_sce_errno_from_posix(rc < 0 ? -rc : rc);
            AMPR_CRITICAL_LOGF("apr.resolveIds item fail idx=%u path=%s rc=0x%x",
                      (unsigned)i, ampr_log_path_arg(path[i]), sceRc);
            if (errorIndex) *errorIndex=i;
            return sceRc;
        }
        ids[i]=id;
        AMPR_TLOGF("apr.resolveIds item done idx=%u path=%s fileId=%u",
                  (unsigned)i, ampr_log_path_arg(path[i]), (unsigned)id);
    }
    return 0;
}

int aprResolveFilepathsToIdsAndFileSizes(const char* path[], uint32_t num, SceAprFileId ids[], size_t fileSizes[], uint32_t* errorIndex) {
    AMPR_TLOGF("[apr-rs-01] resolve ids+sizes enter");
    const int countRc = validate_resolve_count(num);
    if (countRc != 0) return countRc;
    const int outputRc = validate_resolve_outputs(ids, fileSizes);
    if (outputRc != 0) return outputRc;
    const int pathRc = validate_resolve_path_array(path, num);
    if (pathRc != 0) return pathRc;
    if (errorIndex) *errorIndex = 0;
    for (uint32_t i=0;i<num;i++) {
        AMPR_TLOGF("[apr-rs-02] resolve ids+sizes item begin idx=%u path=%s",
                  (unsigned)i, ampr_log_path_arg(path[i]));
        uint32_t id=0; size_t sz=0;
        int rc = ampr_index_resolve_path_to_id(path[i], &id, &sz);
        if (rc!=0) {
            const int sceRc = ampr_sce_errno_from_posix(rc < 0 ? -rc : rc);
            AMPR_CRITICAL_LOGF("[apr-rs-03] resolve ids+sizes item fail idx=%u path=%s rc=0x%x",
                      (unsigned)i, ampr_log_path_arg(path[i]), sceRc);
            if (errorIndex) *errorIndex=i;
            return sceRc;
        }
        ids[i]=id; fileSizes[i]=sz;
        AMPR_TLOGF("[apr-rs-04] resolve ids+sizes item done idx=%u path=%s fileId=%u size=0x%llx",
                  (unsigned)i, ampr_log_path_arg(path[i]), (unsigned)id, (unsigned long long)sz);
    }
    AMPR_TLOGF("[apr-rs-05] resolve ids+sizes done");
    return 0;
}
static constexpr size_t kAprResolveFullPathMax = SCE_KERNEL_PATH_MAX;

static int bounded_cstr_len(const char* s, size_t maxInputBytes, size_t* outLen) {
    if (!s || !outLen) {
        return EFAULT;
    }
    for (size_t i = 0; i < maxInputBytes; ++i) {
        if (s[i] == '\0') {
            *outLen = i;
            return 0;
        }
    }
    return ENAMETOOLONG;
}

static int join_prefix_path(const char* prefix, const char* path, char* out, size_t outSize) {
    if (!out || outSize == 0) {
        return EFAULT;
    }
    out[0] = '\0';
    if (!prefix || !path) {
        return EFAULT;
    }
    size_t prefixLen = 0;
    const int prefixRc = bounded_cstr_len(prefix, SCE_KERNEL_PATH_MAX, &prefixLen);
    if (prefixRc != 0) {
        return prefixRc;
    }
    size_t pathLen = 0;
    const int pathRc = bounded_cstr_len(path, SCE_KERNEL_PATH_MAX, &pathLen);
    if (pathRc != 0) {
        return pathRc;
    }
    const bool needsSlash = prefixLen != 0 && prefix[prefixLen - 1u] != '/' && prefix[prefixLen - 1u] != '\\';
    const size_t slashLen = needsSlash ? 1u : 0u;
    const size_t fixedLen = prefixLen + slashLen;
    if (fixedLen >= outSize || pathLen > outSize - fixedLen - 1u) {
        out[0] = '\0';
        return ENAMETOOLONG;
    }
    std::memcpy(out, prefix, prefixLen);
    size_t used = prefixLen;
    if (needsSlash) {
        out[used++] = '/';
    }
    std::memcpy(out + used, path, pathLen);
    out[used + pathLen] = '\0';
    return 0;
}

int aprResolveFilepathsWithPrefixToIds(const char* pathPrefix, const char* path[], uint32_t num, SceAprFileId ids[], uint32_t* errorIndex) {
    const int countRc = validate_resolve_count(num);
    if (countRc != 0) return countRc;
    const int prefixRc = validate_resolve_prefix(pathPrefix);
    if (prefixRc != 0) return prefixRc;
    const int outputRc = validate_resolve_outputs(ids);
    if (outputRc != 0) return outputRc;
    const int pathRc = validate_resolve_path_array(path, num);
    if (pathRc != 0) return pathRc;
    if (errorIndex) *errorIndex = 0;
    for (uint32_t i=0;i<num;i++) {
        char full[kAprResolveFullPathMax];
        const int joinRc = join_prefix_path(pathPrefix, path[i], full, sizeof(full));
        if (joinRc != 0) {
            if (errorIndex) *errorIndex=i;
            return ampr_sce_errno_from_posix(joinRc);
        }
        uint32_t id=0;
        AMPR_TLOGF("apr.resolvePrefixIds item enter idx=%u prefix=%s path=%s full=%s",
                  (unsigned)i, ampr_log_path_arg(pathPrefix), ampr_log_path_arg(path[i]), full);
        int rc = ampr_index_resolve_path_to_id(full, &id, nullptr);
        if (rc!=0) {
            const int sceRc = ampr_sce_errno_from_posix(rc < 0 ? -rc : rc);
            AMPR_CRITICAL_LOGF("apr.resolvePrefixIds item fail idx=%u full=%s rc=0x%x",
                      (unsigned)i, full, sceRc);
            if (errorIndex) *errorIndex=i;
            return sceRc;
        }
        ids[i]=id;
        AMPR_TLOGF("apr.resolvePrefixIds item done idx=%u full=%s fileId=%u",
                  (unsigned)i, full, (unsigned)id);
    }
    return 0;
}

int aprResolveFilepathsWithPrefixToIdsAndFileSizes(const char* pathPrefix, const char* path[], uint32_t num, SceAprFileId ids[], size_t fileSizes[], uint32_t* errorIndex) {
    const int countRc = validate_resolve_count(num);
    if (countRc != 0) return countRc;
    const int prefixRc = validate_resolve_prefix(pathPrefix);
    if (prefixRc != 0) return prefixRc;
    const int outputRc = validate_resolve_outputs(ids, fileSizes);
    if (outputRc != 0) return outputRc;
    const int pathRc = validate_resolve_path_array(path, num);
    if (pathRc != 0) return pathRc;
    if (errorIndex) *errorIndex = 0;
    for (uint32_t i=0;i<num;i++) {
        char full[kAprResolveFullPathMax];
        const int joinRc = join_prefix_path(pathPrefix, path[i], full, sizeof(full));
        if (joinRc != 0) {
            if (errorIndex) *errorIndex=i;
            return ampr_sce_errno_from_posix(joinRc);
        }
        uint32_t id=0; size_t sz=0;
        AMPR_TLOGF("apr.resolvePrefixIdsSizes item enter idx=%u prefix=%s path=%s full=%s",
                  (unsigned)i, ampr_log_path_arg(pathPrefix), ampr_log_path_arg(path[i]), full);
        int rc = ampr_index_resolve_path_to_id(full, &id, &sz);
        if (rc!=0) {
            const int sceRc = ampr_sce_errno_from_posix(rc < 0 ? -rc : rc);
            AMPR_CRITICAL_LOGF("apr.resolvePrefixIdsSizes item fail idx=%u full=%s rc=0x%x",
                      (unsigned)i, full, sceRc);
            if (errorIndex) *errorIndex=i;
            return sceRc;
        }
        ids[i]=id; fileSizes[i]=sz;
        AMPR_TLOGF("apr.resolvePrefixIdsSizes item done idx=%u full=%s fileId=%u size=0x%llx",
                  (unsigned)i, full, (unsigned)id, (unsigned long long)sz);
    }
    return 0;
}

// forEach variants: write per-item rc
int aprResolveFilepathsToIdsForEach(const char* path[], uint32_t num, SceAprFileId ids[], int results[]) {
    const int countRc = validate_resolve_count(num);
    if (countRc != 0) return countRc;
    const int outputRc = validate_resolve_outputs(ids, results);
    if (outputRc != 0) return outputRc;
    const int pathRc = validate_resolve_path_array(path, num);
    if (pathRc != 0) return pathRc;
    uint32_t resolved = 0;
    for (uint32_t i=0;i<num;i++) {
        uint32_t id=SCE_AMPR_APR_FILEID_INVALID;
        int rc = ampr_index_resolve_path_to_id(path[i], &id, nullptr);
        results[i] = (rc==0)?0:ampr_sce_errno_from_posix(rc < 0 ? -rc : rc);
        if (results[i] != 0) id = SCE_AMPR_APR_FILEID_INVALID;
        ids[i]=id;
        if (results[i] == 0) ++resolved;
        AMPR_TLOGF("apr.resolveIdsForEach item idx=%u path=%s fileId=%u result=0x%x",
                  (unsigned)i, ampr_log_path_arg(path[i]), (unsigned)id, results[i]);
    }
    return (int)resolved;
}

int aprResolveFilepathsToIdsAndFileSizesForEach(const char* path[], uint32_t num, SceAprFileId ids[], size_t fileSizes[], int results[]) {
    const int countRc = validate_resolve_count(num);
    if (countRc != 0) return countRc;
    const int outputRc = validate_resolve_outputs(ids, fileSizes, results);
    if (outputRc != 0) return outputRc;
    const int pathRc = validate_resolve_path_array(path, num);
    if (pathRc != 0) return pathRc;
    uint32_t resolved = 0;
    for (uint32_t i=0;i<num;i++) {
        uint32_t id=SCE_AMPR_APR_FILEID_INVALID; size_t sz=0;
        int rc = ampr_index_resolve_path_to_id(path[i], &id, &sz);
        results[i] = (rc==0)?0:ampr_sce_errno_from_posix(rc < 0 ? -rc : rc);
        if (results[i] != 0) {
            id = SCE_AMPR_APR_FILEID_INVALID;
            sz = 0;
        }
        ids[i]=id; fileSizes[i]=sz;
        if (results[i] == 0) ++resolved;
        AMPR_TLOGF("apr.resolveIdsSizesForEach item idx=%u path=%s fileId=%u size=0x%llx result=0x%x",
                  (unsigned)i, ampr_log_path_arg(path[i]), (unsigned)id,
                  (unsigned long long)sz, results[i]);
    }
    return (int)resolved;
}

int aprResolveFilepathsWithPrefixToIdsForEach(const char* pathPrefix, const char* path[], uint32_t num, SceAprFileId ids[], int results[]) {
    const int countRc = validate_resolve_count(num);
    if (countRc != 0) return countRc;
    const int prefixRc = validate_resolve_prefix(pathPrefix);
    if (prefixRc != 0) return prefixRc;
    const int outputRc = validate_resolve_outputs(ids, results);
    if (outputRc != 0) return outputRc;
    const int pathRc = validate_resolve_path_array(path, num);
    if (pathRc != 0) return pathRc;
    uint32_t resolved = 0;
    for (uint32_t i=0;i<num;i++) {
        uint32_t id=SCE_AMPR_APR_FILEID_INVALID;
        char full[kAprResolveFullPathMax];
        int rc = join_prefix_path(pathPrefix, path[i], full, sizeof(full));
        if (rc == 0) {
            rc = ampr_index_resolve_path_to_id(full, &id, nullptr);
        }
        results[i] = (rc==0)?0:ampr_sce_errno_from_posix(rc < 0 ? -rc : rc);
        if (results[i] != 0) id = SCE_AMPR_APR_FILEID_INVALID;
        ids[i]=id;
        if (results[i] == 0) ++resolved;
        AMPR_TLOGF("apr.resolvePrefixIdsForEach item idx=%u prefix=%s path=%s full=%s fileId=%u result=0x%x",
                  (unsigned)i, ampr_log_path_arg(pathPrefix), ampr_log_path_arg(path[i]),
                  full, (unsigned)id, results[i]);
    }
    return (int)resolved;
}

int aprResolveFilepathsWithPrefixToIdsAndFileSizesForEach(const char* pathPrefix, const char* path[], uint32_t num, SceAprFileId ids[], size_t fileSizes[], int results[]) {
    const int countRc = validate_resolve_count(num);
    if (countRc != 0) return countRc;
    const int prefixRc = validate_resolve_prefix(pathPrefix);
    if (prefixRc != 0) return prefixRc;
    const int outputRc = validate_resolve_outputs(ids, fileSizes, results);
    if (outputRc != 0) return outputRc;
    const int pathRc = validate_resolve_path_array(path, num);
    if (pathRc != 0) return pathRc;
    uint32_t resolved = 0;
    for (uint32_t i=0;i<num;i++) {
        uint32_t id=SCE_AMPR_APR_FILEID_INVALID; size_t sz=0;
        char full[kAprResolveFullPathMax];
        int rc = join_prefix_path(pathPrefix, path[i], full, sizeof(full));
        if (rc == 0) {
            rc = ampr_index_resolve_path_to_id(full, &id, &sz);
        }
        results[i] = (rc==0)?0:ampr_sce_errno_from_posix(rc < 0 ? -rc : rc);
        if (results[i] != 0) {
            id = SCE_AMPR_APR_FILEID_INVALID;
            sz = 0;
        }
        ids[i]=id; fileSizes[i]=sz;
        if (results[i] == 0) ++resolved;
        AMPR_TLOGF("apr.resolvePrefixIdsSizesForEach item idx=%u prefix=%s path=%s full=%s fileId=%u size=0x%llx result=0x%x",
                  (unsigned)i, ampr_log_path_arg(pathPrefix), ampr_log_path_arg(path[i]),
                  full, (unsigned)id, (unsigned long long)sz, results[i]);
    }
    return (int)resolved;
}


int aprGetFileSize(SceAprFileId fileId, size_t* size) {
    AMPR_TLOGF("apr.getFileSize fileId=%u out=%p", (unsigned)fileId, size);
    if (!size) return SCE_KERNEL_ERROR_EFAULT;
    FileEntryView e;
    int rc = ampr_index_get_entry_view((uint32_t)fileId, &e);
    if (rc!=0) return ampr_sce_errno_from_posix(rc < 0 ? -rc : rc);
    *size = e.size;
    AMPR_TLOGF("apr.getFileSize fileId=%u size=0x%llx",
              (unsigned)fileId, (unsigned long long)e.size);
    return 0;
}


int aprGetFileStat(SceAprFileId fileId, SceKernelStat* st) {
    AMPR_TLOGF("apr.getFileStat fileId=%u out=%p", (unsigned)fileId, st);
    if (!st) return SCE_KERNEL_ERROR_EFAULT;
    FileEntryView e;
    int rc = ampr_index_get_entry_view((uint32_t)fileId, &e);
    if (rc!=0) return ampr_sce_errno_from_posix(rc < 0 ? -rc : rc);
    struct stat s{};
    s.st_size = (off_t)e.size;
    s.st_mode = (mode_t)(S_IFREG | 0777);
    s.st_mtime = (time_t)e.mtime;
    // SceKernelStat layout is assumed compatible with struct stat in this header's environment.
    std::memset(st, 0, sizeof(*st));
    std::memcpy(st, &s, ampr_min(sizeof(*st), sizeof(s)));
    AMPR_TLOGF("apr.getFileStat fileId=%u rc=0", (unsigned)fileId);
    return 0;
}


static int apr_submit_command_buffer(AprCommandBuffer* commandBuffer,
                                     uint32_t rawPrio,
                                     AprSubmitMode mode,
                                     SceAprResultBuffer* res,
                                     SceAprSubmitId* id,
                                     const void* sourceOverride = nullptr,
                                     bool useSourceOverride = false) {
    if (!apr_submit_priority_valid(rawPrio)) {
        AMPR_CRITICAL_LOGF("apr.submit.priority.outOfRange cb=%p prio=%u validMin=%u validMax=%u action=reject",
                          commandBuffer,
                          (unsigned)rawPrio,
                          (unsigned)kAprPriorityMin,
                          (unsigned)kAprPriorityMax);
        return apr_submit_reject(res, SCE_KERNEL_ERROR_EINVAL);
    }
    if (!commandBuffer) {
        return SCE_KERNEL_ERROR_EINVAL;
    }

    SceAmprCommandBuffer* rawCb = &commandBuffer->m_commandBuffer;
    const void* const sourceBuffer = useSourceOverride ? sourceOverride : rawCb->buffer;
    const uint32_t logicalBytes = rawCb->offset;
    const int32_t rawCommandCount = rawCb->num;
    const uint32_t sourceCapacity = rawCb->bufsize;
    const int nativeSubmitType = cb_native_submit_type(rawCb);
    if (!sourceBuffer) {
        return apr_submit_reject(res, SCE_KERNEL_ERROR_EPERM);
    }
    if (logicalBytes == 0 || rawCommandCount <= 0 ||
        logicalBytes > sourceCapacity) {
        return apr_submit_reject(res, SCE_KERNEL_ERROR_EINVAL);
    }
    // Recording/mutation and object-lifetime isolation belong to the
    // application. Each caller snapshots the immutable stream independently;
    // the fixed reactor job owns everything needed after this call returns.
    const uint32_t logicalCommands = static_cast<uint32_t>(rawCommandCount);

    const uint64_t sid = apr_next_submit_id();
    Job j;
    j.id = sid;
    j.sourceBuffer = sourceBuffer;
    j.sourceBytes = logicalBytes;
    j.sourceCommandCount = logicalCommands;
    j.submitMode = mode;
    j.nativeSubmitType = nativeSubmitType;
    j.nativePrio = rawPrio;
    j.aprRes = res;
    SceAprSubmitId submitId = 0;
    uint32_t submitErrorOffset = 0;
    const int submitRc = apr_reactor_submit(j,
                                             id ? &submitId : nullptr,
                                             &submitErrorOffset);
    if (submitRc != 0) {
        return apr_submit_reject(res, submitRc, submitErrorOffset);
    }
    if (id) *id = submitId;
    return 0;
}

int aprSubmitCommandBuffer(AprCommandBuffer* commandBuffer, uint32_t rawPrio) {
    return apr_submit_command_buffer(commandBuffer, rawPrio, AprSubmitMode::kSubmit, nullptr, nullptr);
}

int aprSubmitCommandBuffer(AprCommandBuffer* commandBuffer, uint32_t rawPrio, SceAprSubmitId* id) {
    return apr_submit_command_buffer(commandBuffer, rawPrio, AprSubmitMode::kSubmitAndGetId, nullptr, id);
}

int aprSubmitCommandBufferAndGetResult(AprCommandBuffer* commandBuffer,
                                       uint32_t rawPrio,
                                       SceAprResultBuffer* res,
                                       SceAprSubmitId* id) {
    return apr_submit_command_buffer(commandBuffer, rawPrio, AprSubmitMode::kSubmitAndGetResult, res, id);
}

int aprSubmitCommandBufferTest(AprCommandBuffer* commandBuffer,
                               uint32_t rawPrio,
                               const void* testBuffer) {
    return apr_submit_command_buffer(commandBuffer,
                                     rawPrio,
                                     AprSubmitMode::kSubmit,
                                     nullptr,
                                     nullptr,
                                     testBuffer,
                                     true);
}

int aprSubmitCommandBufferAndGetResultTest(AprCommandBuffer* commandBuffer,
                                           uint32_t rawPrio,
                                           SceAprResultBuffer* res,
                                           SceAprSubmitId* id,
                                           const void* testBuffer) {
    return apr_submit_command_buffer(commandBuffer,
                                     rawPrio,
                                     AprSubmitMode::kSubmitAndGetResult,
                                     res,
                                     id,
                                     testBuffer,
                                     true);
}

} // namespace sce::Ampr::Emu
