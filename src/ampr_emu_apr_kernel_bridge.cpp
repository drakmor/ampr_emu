/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * APR libkernel hook bridge entrypoints.
 */

#include "ampr_emu_apr_reactor.h"
#include "ampr_emu_apr_services.h"
#include "ampr_emu_command_buffer_types.h"
#include "ampr_emu_errno.h"
#include "ampr_emu_kernel_lookup.h"
#include "ampr_emu_log.h"
#include "ampr_libkernel_hook.h"

namespace {

using AprWaitCommandBufferFn = int (*)(SceAprSubmitId);

static int apr_submit_lowlevel_sce(sce::Ampr::AprCommandBuffer* commandBuffer,
                                   uint32_t prio,
                                   SceAprResultBuffer* result,
                                   SceAprSubmitId* id,
                                   AprSubmitMode mode,
                                   const char* phase,
                                   const void* sourceOverride = nullptr,
                                   bool useSourceOverride = false) {
    if (!apr_submit_priority_valid(prio)) {
        AMPR_CRITICAL_LOGF("lk.apr.submit.priority.outOfRange phase=%s cb=%p prio=%u validMin=%u validMax=%u action=reject",
                          phase ? phase : "submit",
                          commandBuffer,
                          (unsigned)prio,
                          (unsigned)kAprPriorityMin,
                          (unsigned)kAprPriorityMax);
        if (result) {
            result->result = SCE_KERNEL_ERROR_EINVAL;
            result->errorOffset = 0;
        }
        return SCE_KERNEL_ERROR_EINVAL;
    }
    AMPR_VLOGF("lk.apr.submit enter phase=%s cb=%p prio=%u res=%p id=%p",
              phase ? phase : "submit", commandBuffer, (unsigned)prio, result, id);
    if (!commandBuffer) {
        return SCE_KERNEL_ERROR_EPERM;
    }
    const SceAmprCommandBuffer* rawCb = &commandBuffer->m_commandBuffer;
    if (!rawCb->buffer) {
        return SCE_KERNEL_ERROR_EPERM;
    }
    if (rawCb->offset == 0) {
        return SCE_KERNEL_ERROR_EINVAL;
    }

    int rc = 0;
    switch (mode) {
        case AprSubmitMode::kSubmit:
            rc = useSourceOverride
                     ? sce::Ampr::Emu::aprSubmitCommandBufferTest(commandBuffer, prio, sourceOverride)
                     : sce::Ampr::Emu::aprSubmitCommandBuffer(commandBuffer, prio);
            break;
        case AprSubmitMode::kSubmitAndGetId:
            rc = sce::Ampr::Emu::aprSubmitCommandBuffer(commandBuffer, prio, id);
            break;
        case AprSubmitMode::kSubmitAndGetResult:
            rc = useSourceOverride
                     ? sce::Ampr::Emu::aprSubmitCommandBufferAndGetResultTest(
                           commandBuffer, prio, result, id, sourceOverride)
                     : sce::Ampr::Emu::aprSubmitCommandBufferAndGetResult(commandBuffer, prio, result, id);
            break;
        default:
            rc = SCE_KERNEL_ERROR_EINVAL;
            break;
    }
    AMPR_VLOGF("lk.apr.submit leave phase=%s cb=%p rc=0x%x result=%p id=%p idValue=0x%x",
              phase ? phase : "submit", commandBuffer, rc, result, id, id ? (unsigned)*id : 0u);
    return rc;
}

static int apr_wait_lowlevel(SceAprSubmitId id,
                             AmprLibkernelHookId nativeHook,
                             const char* phase) {
    AMPR_VLOGF("lk.apr.wait enter phase=%s id=0x%x",
              phase ? phase : "wait",
              (unsigned)id);

    bool handled = false;
    const int syntheticRc = apr_reactor_wait_synthetic_submit_id(id, &handled);
    if (handled) {
        const int out = ampr_libkernel_return_from_sce(syntheticRc);
        AMPR_VLOGF("lk.apr.wait leave phase=%s id=0x%x route=synthetic rc=0x%x out=%d",
                  phase ? phase : "wait",
                  (unsigned)id,
                  syntheticRc,
                  out);
        return out;
    }

    auto* const original = ampr_fixed_kernel_slot<AprWaitCommandBufferFn>(nativeHook);
    if (!original) {
        const int out = ampr_libkernel_return_from_sce(SCE_KERNEL_ERROR_ENOSYS);
        AMPR_CRITICAL_LOGF("lk.apr.wait leave phase=%s id=0x%x route=native reason=missing-original out=%d",
                           phase ? phase : "wait",
                           (unsigned)id,
                           out);
        return out;
    }
    const int out = original(id);
    AMPR_VLOGF("lk.apr.wait leave phase=%s id=0x%x route=native out=%d errno=%d",
              phase ? phase : "wait",
              (unsigned)id,
              out,
              errno);
    return out;
}

} // namespace

extern "C" int sceKernelAprGetFileSize_emul(int fileId, uint64_t* outSize) {
    AMPR_TLOGF("lk.apr.getFileSize enter fileId=%d out=%p", fileId, outSize);
    if (!outSize) return ampr_libkernel_return_from_sce(SCE_KERNEL_ERROR_EFAULT);
    size_t sz = 0;
    int rc = sce::Ampr::Emu::aprGetFileSize((SceAprFileId)fileId, &sz);
    if (rc != 0) return ampr_libkernel_return_from_sce(rc);
    *outSize = (uint64_t)sz;
    AMPR_TLOGF("lk.apr.getFileSize leave fileId=%d size=0x%llx",
              fileId, (unsigned long long)*outSize);
    return 0;
}

extern "C" int sceKernelAprGetFileStat_emul(int fileId, SceKernelStat* st) {
    AMPR_TLOGF("lk.apr.getFileStat enter fileId=%d out=%p", fileId, st);
    const int rc = sce::Ampr::Emu::aprGetFileStat((SceAprFileId)fileId, st);
    AMPR_TLOGF("lk.apr.getFileStat leave fileId=%d rc=0x%x", fileId, rc);
    return ampr_libkernel_return_from_sce(rc);
}

extern "C" int sceKernelAprResolveFilepathsToIds_emul(const char* path[], uint32_t num, uint32_t ids[], uint32_t* errorIndex) {
    const int countRc = sce::Ampr::Emu::validate_resolve_count(num);
    if (countRc != 0) return ampr_libkernel_return_from_sce(countRc);
    const int outputRc = sce::Ampr::Emu::validate_resolve_outputs(reinterpret_cast<SceAprFileId*>(ids));
    if (outputRc != 0) return ampr_libkernel_return_from_sce(outputRc);
    const int pathRc = sce::Ampr::Emu::validate_resolve_path_array(path, num);
    if (pathRc != 0) return ampr_libkernel_return_from_sce(pathRc);
    AMPR_VLOGF("lk.apr.resolveIds enter paths=%p num=%u ids=%p errorIndex=%p", path, (unsigned)num, ids, errorIndex);
    const int rc = sce::Ampr::Emu::aprResolveFilepathsToIds(path, num, (SceAprFileId*)ids, errorIndex);
    AMPR_VLOGF("lk.apr.resolveIds leave rc=0x%x firstId=%u errorIndex=%u",
              rc, (ids && num) ? ids[0] : 0u, errorIndex ? *errorIndex : 0u);
    return ampr_libkernel_return_from_sce(rc);
}

extern "C" int sceKernelAprResolveFilepathsToIdsAndFileSizes_emul(const char* path[], uint32_t num, uint32_t ids[], size_t fileSizes[], uint32_t* errorIndex) {
    const int countRc = sce::Ampr::Emu::validate_resolve_count(num);
    if (countRc != 0) return ampr_libkernel_return_from_sce(countRc);
    const int outputRc = sce::Ampr::Emu::validate_resolve_outputs(reinterpret_cast<SceAprFileId*>(ids), fileSizes);
    if (outputRc != 0) return ampr_libkernel_return_from_sce(outputRc);
    const int pathRc = sce::Ampr::Emu::validate_resolve_path_array(path, num);
    if (pathRc != 0) return ampr_libkernel_return_from_sce(pathRc);
    AMPR_VLOGF("lk.apr.resolveIdsSizes enter paths=%p num=%u ids=%p sizes=%p errorIndex=%p",
              path, (unsigned)num, ids, fileSizes, errorIndex);
    int rc = sce::Ampr::Emu::aprResolveFilepathsToIdsAndFileSizes(path, num, (SceAprFileId*)ids, fileSizes, errorIndex);
    AMPR_VLOGF("lk.apr.resolveIdsSizes leave rc=0x%x firstId=%u firstSize=0x%llx errorIndex=%u",
              rc,
              (ids && num) ? ids[0] : 0u,
              (unsigned long long)((fileSizes && num) ? fileSizes[0] : 0u),
              errorIndex ? *errorIndex : 0u);
    return ampr_libkernel_return_from_sce(rc);
}

extern "C" int sceKernelAprResolveFilepathsWithPrefixToIds_emul(const char* pathPrefix, const char* path[], uint32_t num, uint32_t ids[], uint32_t* errorIndex) {
    const int countRc = sce::Ampr::Emu::validate_resolve_count(num);
    if (countRc != 0) return ampr_libkernel_return_from_sce(countRc);
    const int prefixRc = sce::Ampr::Emu::validate_resolve_prefix(pathPrefix);
    if (prefixRc != 0) return ampr_libkernel_return_from_sce(prefixRc);
    const int outputRc = sce::Ampr::Emu::validate_resolve_outputs(reinterpret_cast<SceAprFileId*>(ids));
    if (outputRc != 0) return ampr_libkernel_return_from_sce(outputRc);
    const int pathRc = sce::Ampr::Emu::validate_resolve_path_array(path, num);
    if (pathRc != 0) return ampr_libkernel_return_from_sce(pathRc);
    AMPR_VLOGF("lk.apr.resolvePrefixIds enter prefix=%s paths=%p num=%u ids=%p errorIndex=%p",
              pathPrefix ? pathPrefix : "(null)", path, (unsigned)num, ids, errorIndex);
    return ampr_libkernel_return_from_sce(
        sce::Ampr::Emu::aprResolveFilepathsWithPrefixToIds(pathPrefix, path, num, (SceAprFileId*)ids, errorIndex));
}

extern "C" int sceKernelAprResolveFilepathsWithPrefixToIdsAndFileSizes_emul(const char* pathPrefix, const char* path[], uint32_t num, uint32_t ids[], size_t fileSizes[], uint32_t* errorIndex) {
    const int countRc = sce::Ampr::Emu::validate_resolve_count(num);
    if (countRc != 0) return ampr_libkernel_return_from_sce(countRc);
    const int prefixRc = sce::Ampr::Emu::validate_resolve_prefix(pathPrefix);
    if (prefixRc != 0) return ampr_libkernel_return_from_sce(prefixRc);
    const int outputRc = sce::Ampr::Emu::validate_resolve_outputs(reinterpret_cast<SceAprFileId*>(ids), fileSizes);
    if (outputRc != 0) return ampr_libkernel_return_from_sce(outputRc);
    const int pathRc = sce::Ampr::Emu::validate_resolve_path_array(path, num);
    if (pathRc != 0) return ampr_libkernel_return_from_sce(pathRc);
    AMPR_VLOGF("lk.apr.resolvePrefixIdsSizes enter prefix=%s paths=%p num=%u ids=%p sizes=%p errorIndex=%p",
              pathPrefix ? pathPrefix : "(null)", path, (unsigned)num, ids, fileSizes, errorIndex);
    return ampr_libkernel_return_from_sce(
        sce::Ampr::Emu::aprResolveFilepathsWithPrefixToIdsAndFileSizes(pathPrefix, path, num, (SceAprFileId*)ids, fileSizes, errorIndex));
}

extern "C" int sceKernelAprResolveFilepathsToIdsForEach_emul(const char* path[], uint32_t num, uint32_t ids[], int results[]) {
    const int countRc = sce::Ampr::Emu::validate_resolve_count(num);
    if (countRc != 0) return ampr_libkernel_return_from_sce_count(countRc);
    const int outputRc = sce::Ampr::Emu::validate_resolve_outputs(reinterpret_cast<SceAprFileId*>(ids), results);
    if (outputRc != 0) return ampr_libkernel_return_from_sce_count(outputRc);
    const int pathRc = sce::Ampr::Emu::validate_resolve_path_array(path, num);
    if (pathRc != 0) return ampr_libkernel_return_from_sce_count(pathRc);
    AMPR_VLOGF("lk.apr.resolveIdsEach enter paths=%p num=%u ids=%p results=%p", path, (unsigned)num, ids, results);
    const int rc = sce::Ampr::Emu::aprResolveFilepathsToIdsForEach(path, num, (SceAprFileId*)ids, results);
    const int out = ampr_libkernel_return_from_sce_count(rc);
    AMPR_VLOGF("lk.apr.resolveIdsEach leave rc=0x%x out=%d firstId=%u firstResult=0x%x",
              rc, out, (ids && num) ? ids[0] : 0u, (results && num) ? results[0] : 0);
    return out;
}

extern "C" int sceKernelAprResolveFilepathsToIdsAndFileSizesForEach_emul(const char* path[], uint32_t num, uint32_t ids[], size_t fileSizes[], int results[]) {
    const int countRc = sce::Ampr::Emu::validate_resolve_count(num);
    if (countRc != 0) return ampr_libkernel_return_from_sce_count(countRc);
    const int outputRc = sce::Ampr::Emu::validate_resolve_outputs(reinterpret_cast<SceAprFileId*>(ids), fileSizes, results);
    if (outputRc != 0) return ampr_libkernel_return_from_sce_count(outputRc);
    const int pathRc = sce::Ampr::Emu::validate_resolve_path_array(path, num);
    if (pathRc != 0) return ampr_libkernel_return_from_sce_count(pathRc);
    AMPR_VLOGF("lk.apr.resolveIdsSizesEach enter paths=%p num=%u ids=%p sizes=%p results=%p",
              path, (unsigned)num, ids, fileSizes, results);
    const int rc = sce::Ampr::Emu::aprResolveFilepathsToIdsAndFileSizesForEach(path, num, (SceAprFileId*)ids, fileSizes, results);
    const int out = ampr_libkernel_return_from_sce_count(rc);
    AMPR_VLOGF("lk.apr.resolveIdsSizesEach leave rc=0x%x out=%d firstId=%u firstSize=0x%llx firstResult=0x%x",
              rc,
              out,
              (ids && num) ? ids[0] : 0u,
              (unsigned long long)((fileSizes && num) ? fileSizes[0] : 0u),
              (results && num) ? results[0] : 0);
    return out;
}

extern "C" int sceKernelAprResolveFilepathsWithPrefixToIdsForEach_emul(const char* pathPrefix, const char* path[], uint32_t num, uint32_t ids[], int results[]) {
    const int countRc = sce::Ampr::Emu::validate_resolve_count(num);
    if (countRc != 0) return ampr_libkernel_return_from_sce_count(countRc);
    const int prefixRc = sce::Ampr::Emu::validate_resolve_prefix(pathPrefix);
    if (prefixRc != 0) return ampr_libkernel_return_from_sce_count(prefixRc);
    const int outputRc = sce::Ampr::Emu::validate_resolve_outputs(reinterpret_cast<SceAprFileId*>(ids), results);
    if (outputRc != 0) return ampr_libkernel_return_from_sce_count(outputRc);
    const int pathRc = sce::Ampr::Emu::validate_resolve_path_array(path, num);
    if (pathRc != 0) return ampr_libkernel_return_from_sce_count(pathRc);
    AMPR_VLOGF("lk.apr.resolvePrefixIdsEach enter prefix=%s paths=%p num=%u ids=%p results=%p",
              pathPrefix ? pathPrefix : "(null)", path, (unsigned)num, ids, results);
    const int rc = sce::Ampr::Emu::aprResolveFilepathsWithPrefixToIdsForEach(pathPrefix, path, num, (SceAprFileId*)ids, results);
    const int out = ampr_libkernel_return_from_sce_count(rc);
    AMPR_VLOGF("lk.apr.resolvePrefixIdsEach leave rc=0x%x out=%d firstId=%u firstResult=0x%x",
              rc, out, (ids && num) ? ids[0] : 0u, (results && num) ? results[0] : 0);
    return out;
}

extern "C" int sceKernelAprResolveFilepathsWithPrefixToIdsAndFileSizesForEach_emul(const char* pathPrefix, const char* path[], uint32_t num, uint32_t ids[], size_t fileSizes[], int results[]) {
    const int countRc = sce::Ampr::Emu::validate_resolve_count(num);
    if (countRc != 0) return ampr_libkernel_return_from_sce_count(countRc);
    const int prefixRc = sce::Ampr::Emu::validate_resolve_prefix(pathPrefix);
    if (prefixRc != 0) return ampr_libkernel_return_from_sce_count(prefixRc);
    const int outputRc = sce::Ampr::Emu::validate_resolve_outputs(reinterpret_cast<SceAprFileId*>(ids), fileSizes, results);
    if (outputRc != 0) return ampr_libkernel_return_from_sce_count(outputRc);
    const int pathRc = sce::Ampr::Emu::validate_resolve_path_array(path, num);
    if (pathRc != 0) return ampr_libkernel_return_from_sce_count(pathRc);
    AMPR_VLOGF("lk.apr.resolvePrefixIdsSizesEach enter prefix=%s paths=%p num=%u ids=%p sizes=%p results=%p",
              pathPrefix ? pathPrefix : "(null)", path, (unsigned)num, ids, fileSizes, results);
    const int rc = sce::Ampr::Emu::aprResolveFilepathsWithPrefixToIdsAndFileSizesForEach(pathPrefix, path, num, (SceAprFileId*)ids, fileSizes, results);
    const int out = ampr_libkernel_return_from_sce_count(rc);
    AMPR_VLOGF("lk.apr.resolvePrefixIdsSizesEach leave rc=0x%x out=%d firstId=%u firstSize=0x%llx firstResult=0x%x",
              rc,
              out,
              (ids && num) ? ids[0] : 0u,
              (unsigned long long)((fileSizes && num) ? fileSizes[0] : 0u),
              (results && num) ? results[0] : 0);
    return out;
}

extern "C" int sceKernelAprSubmitCommandBuffer_emul(sce::Ampr::AprCommandBuffer* commandBuffer, uint32_t prio) {
    return ampr_libkernel_return_from_sce(
        apr_submit_lowlevel_sce(commandBuffer, prio, nullptr, nullptr, AprSubmitMode::kSubmit, "submit"));
}

extern "C" int sceKernelAprSubmitCommandBuffer_TEST_emul(sce::Ampr::AprCommandBuffer* commandBuffer,
                                                         uint32_t prio,
                                                         void* testBuffer) {
    return ampr_libkernel_return_from_sce(
        apr_submit_lowlevel_sce(commandBuffer,
                                prio,
                                nullptr,
                                nullptr,
                                AprSubmitMode::kSubmit,
                                "submit_test",
                                testBuffer,
                                true));
}

extern "C" int sceKernelAprSubmitCommandBufferAndGetResult_emul(sce::Ampr::AprCommandBuffer* commandBuffer,
                                                                 uint32_t prio,
                                                                 SceAprResultBuffer* result,
                                                                 SceAprSubmitId* id) {
    return ampr_libkernel_return_from_sce(
        apr_submit_lowlevel_sce(commandBuffer, prio, result, id, AprSubmitMode::kSubmitAndGetResult, "submit_result"));
}

extern "C" int sceKernelAprSubmitCommandBufferAndGetResult_TEST_emul(sce::Ampr::AprCommandBuffer* commandBuffer,
                                                                      uint32_t prio,
                                                                      SceAprResultBuffer* result,
                                                                      SceAprSubmitId* id,
                                                                      void* testBuffer) {
    return ampr_libkernel_return_from_sce(apr_submit_lowlevel_sce(
        commandBuffer,
        prio,
        result,
        id,
        AprSubmitMode::kSubmitAndGetResult,
        "submit_result_test",
        testBuffer,
        true));
}

extern "C" int sceKernelAprSubmitCommandBufferAndGetId_emul(sce::Ampr::AprCommandBuffer* commandBuffer,
                                                            uint32_t prio,
                                                            SceAprSubmitId* id) {
    return ampr_libkernel_return_from_sce(
        apr_submit_lowlevel_sce(commandBuffer, prio, nullptr, id, AprSubmitMode::kSubmitAndGetId, "submit_id"));
}

extern "C" int sceKernelAprWaitCommandBuffer_emul(SceAprSubmitId id) {
    return apr_wait_lowlevel(id,
                             kAmprLibkernelHook_sceKernelAprWaitCommandBuffer,
                             "apr-wait");
}

extern "C" int sceKernelWaitCommandBufferCompletion_emul(SceAprSubmitId id) {
    return apr_wait_lowlevel(id,
                             kAmprLibkernelHook_sceKernelWaitCommandBufferCompletion,
                             "generic-wait");
}
