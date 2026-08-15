/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * APR service shared helpers.
 */

#pragma once

#include "ampr.h"

#include <kernel.h>
#include <cstdint>

namespace sce::Ampr {
class AprCommandBuffer;
}

namespace sce::Ampr::Emu {

inline bool apr_resolve_count_valid(uint32_t num) {
    return num > 0 && num <= SCE_AMPR_APR_RESOLVE_MAX;
}

inline int validate_resolve_count(uint32_t num) {
    return apr_resolve_count_valid(num) ? 0 : SCE_KERNEL_ERROR_EINVAL;
}

inline int validate_resolve_path_array(const char* const path[], uint32_t num) {
    if (!path) return SCE_KERNEL_ERROR_EFAULT;
    for (uint32_t i = 0; i < num; ++i) {
        if (!path[i]) return SCE_KERNEL_ERROR_EFAULT;
    }
    return 0;
}

inline int validate_resolve_outputs(SceAprFileId ids[],
                                    const size_t* fileSizes,
                                    const int* results) {
    if (!ids || !fileSizes || !results) return SCE_KERNEL_ERROR_EFAULT;
    return 0;
}

inline int validate_resolve_outputs(SceAprFileId ids[], const size_t* fileSizes) {
    if (!ids || !fileSizes) return SCE_KERNEL_ERROR_EFAULT;
    return 0;
}

inline int validate_resolve_outputs(SceAprFileId ids[], const int* results) {
    if (!ids || !results) return SCE_KERNEL_ERROR_EFAULT;
    return 0;
}

inline int validate_resolve_outputs(SceAprFileId ids[]) {
    if (!ids) return SCE_KERNEL_ERROR_EFAULT;
    return 0;
}

inline int validate_resolve_prefix(const char* pathPrefix) {
    return pathPrefix ? 0 : SCE_KERNEL_ERROR_EFAULT;
}

int aprResolveFilepathsToIds(const char*[], uint32_t, SceAprFileId[], uint32_t*);
int aprResolveFilepathsToIdsAndFileSizes(const char*[], uint32_t, SceAprFileId[], size_t[], uint32_t*);
int aprResolveFilepathsWithPrefixToIds(const char*, const char*[], uint32_t, SceAprFileId[], uint32_t*);
int aprResolveFilepathsWithPrefixToIdsAndFileSizes(const char*, const char*[], uint32_t, SceAprFileId[], size_t[], uint32_t*);
int aprResolveFilepathsToIdsForEach(const char*[], uint32_t, SceAprFileId[], int[]);
int aprResolveFilepathsToIdsAndFileSizesForEach(const char*[], uint32_t, SceAprFileId[], size_t[], int[]);
int aprResolveFilepathsWithPrefixToIdsForEach(const char*, const char*[], uint32_t, SceAprFileId[], int[]);
int aprResolveFilepathsWithPrefixToIdsAndFileSizesForEach(const char*, const char*[], uint32_t, SceAprFileId[], size_t[], int[]);
int aprGetFileSize(SceAprFileId, size_t*);
int aprGetFileStat(SceAprFileId, SceKernelStat*);
int aprSubmitCommandBuffer(AprCommandBuffer*, uint32_t);
int aprSubmitCommandBuffer(AprCommandBuffer*, uint32_t, SceAprSubmitId*);
int aprSubmitCommandBufferAndGetResult(AprCommandBuffer*, uint32_t, SceAprResultBuffer*, SceAprSubmitId*);
int aprSubmitCommandBufferTest(AprCommandBuffer*, uint32_t, const void*);
int aprSubmitCommandBufferAndGetResultTest(AprCommandBuffer*, uint32_t, SceAprResultBuffer*, SceAprSubmitId*, const void*);

} // namespace sce::Ampr::Emu
