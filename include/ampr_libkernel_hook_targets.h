/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Private libkernel hook target declarations.
 */

#pragma once

#include "ampr.h"
#include "ampr_emu_apr_equeue.h"

#include <_kernel.h>
#include <kernel.h>
#include <stdint.h>
#include <sys/dmem.h>
#include <sys/types.h>

namespace sce::Ampr {
class AprCommandBuffer;
}

extern "C" {
int sceKernelOpen_emul(const char* path, int flags, SceKernelMode mode);
int sceKernelStat_emul(const char* path, SceKernelStat* sb);
int sceKernelCheckReachability_emul(const char* path);
int sceKernelUnlink_emul(const char* path);
int sceKernelRename_emul(const char* from, const char* to);
int sceKernelMprotect_emul(const void* addr, size_t len, int prot);
int sceKernelMtypeprotect_emul(const void* addr, size_t size, int type, int prot);
int sceKernelMapFlexibleMemory_emul(void** addrInOut, size_t len, int prot, int flags);
int sceKernelMapDirectMemory_emul(void** addr, size_t len, int prot, int flags, off_t directMemoryStart, size_t maxPageSize);
int sceKernelMapDirectMemory2_emul(void** addr, size_t len, int type, int prot, int flags, off_t directMemoryStart, size_t maxPageSize);
int sceKernelBatchMap_emul(SceKernelBatchMapEntry* entries, int numberOfEntries, int* numberOfEntriesOut);
int sceKernelBatchMap2_emul(SceKernelBatchMapEntry* entries, int numberOfEntries, int* numberOfEntriesOut, int flags);
int sceKernelJitMapSharedMemory_emul(int fd, int prot, void** startOut);
int sceKernelMemoryPoolBatch_emul(const SceKernelMemoryPoolBatchEntry* entries, int n, int* indexOut, int flags);
int sceKernelMemoryPoolCommit_emul(void* addr, size_t len, int type, int prot, int flags);
int sceKernelMapNamedFlexibleMemory_emul(void** addrInOut, size_t len, int prot, int flags, const char* name);
int sceKernelMapNamedDirectMemory_emul(void** addr, size_t len, int prot, int flags, off_t directMemoryStart, size_t alignment, const char* name);

int sceKernelAprGetFileSize_emul(int fileId, uint64_t* outSize);
int sceKernelAprGetFileStat_emul(int fileId, SceKernelStat* st);
int sceKernelAprResolveFilepathsToIds_emul(const char* path[], uint32_t num, uint32_t ids[], uint32_t* errorIndex);
int sceKernelAprResolveFilepathsToIdsAndFileSizes_emul(const char* path[], uint32_t num, uint32_t ids[], size_t fileSizes[], uint32_t* errorIndex);
int sceKernelAprResolveFilepathsWithPrefixToIds_emul(const char* pathPrefix, const char* path[], uint32_t num, uint32_t ids[], uint32_t* errorIndex);
int sceKernelAprResolveFilepathsWithPrefixToIdsAndFileSizes_emul(const char* pathPrefix, const char* path[], uint32_t num, uint32_t ids[], size_t fileSizes[], uint32_t* errorIndex);
int sceKernelAprResolveFilepathsToIdsForEach_emul(const char* path[], uint32_t num, uint32_t ids[], int results[]);
int sceKernelAprResolveFilepathsToIdsAndFileSizesForEach_emul(const char* path[], uint32_t num, uint32_t ids[], size_t fileSizes[], int results[]);
int sceKernelAprResolveFilepathsWithPrefixToIdsForEach_emul(const char* pathPrefix, const char* path[], uint32_t num, uint32_t ids[], int results[]);
int sceKernelAprResolveFilepathsWithPrefixToIdsAndFileSizesForEach_emul(const char* pathPrefix, const char* path[], uint32_t num, uint32_t ids[], size_t fileSizes[], int results[]);
int sceKernelAprSubmitCommandBuffer_emul(sce::Ampr::AprCommandBuffer* commandBuffer, uint32_t prio);
int sceKernelAprSubmitCommandBuffer_TEST_emul(sce::Ampr::AprCommandBuffer* commandBuffer, uint32_t prio, void* testBuffer);
int sceKernelAprSubmitCommandBufferAndGetResult_emul(sce::Ampr::AprCommandBuffer* commandBuffer, uint32_t prio, SceAprResultBuffer* result, SceAprSubmitId* id);
int sceKernelAprSubmitCommandBufferAndGetResult_TEST_emul(sce::Ampr::AprCommandBuffer* commandBuffer, uint32_t prio, SceAprResultBuffer* result, SceAprSubmitId* id, void* testBuffer);
int sceKernelAprSubmitCommandBufferAndGetId_emul(sce::Ampr::AprCommandBuffer* commandBuffer, uint32_t prio, SceAprSubmitId* id);
int sceKernelAprWaitCommandBuffer_emul(SceAprSubmitId id);
int sceKernelWaitCommandBufferCompletion_emul(SceAprSubmitId id);

size_t sceKernelGetDirectMemorySize_emul();
int sceKernelAvailableDirectMemorySize_emul(off_t searchStart, off_t searchEnd, size_t alignment, off_t* physAddrOut, size_t* sizeOut);
int sceKernelWriteMapCommand_emul(void* dst, uint64_t va, uint64_t size, uint64_t type, uint64_t prot, uint64_t* outSize);
int sceKernelWriteMapCommand2_emul(void* dst, uint64_t va, uint64_t size, uint64_t type, uint64_t prot, uint64_t prt, uint64_t* outSize);
int sceKernelWriteMapWithGpuMaskIdCommand_emul(void* dst, uint64_t va, uint64_t size, uint64_t type, uint64_t prot, uint64_t gpuMaskId, uint64_t* outSize);
int sceKernelWriteMapDirectCommand_emul(void* dst, uint64_t va, uint64_t dmemOffset, uint64_t size, uint64_t type, uint64_t prot, uint64_t* outSize);
int sceKernelWriteMapDirectWithGpuMaskIdCommand_emul(void* dst, uint64_t va, uint64_t dmemOffset, uint64_t size, uint64_t type, uint64_t prot, uint64_t gpuMaskId, uint64_t* outSize);
int sceKernelWriteRemapCommand_emul(void* dst, uint64_t vaNewStart, uint64_t vaOldStart, uint64_t size, uint64_t prot, uint64_t* outSize);
int sceKernelWriteRemapWithGpuMaskIdCommand_emul(void* dst, uint64_t vaNewStart, uint64_t vaOldStart, uint64_t size, uint64_t prot, uint64_t gpuMaskId, uint64_t* outSize);
int sceKernelWriteMultiMapCommand_emul(void* dst, uint64_t vaNewStart, uint64_t vaAliasStart, uint64_t size, uint64_t prot, uint64_t* outSize);
int sceKernelWriteMultiMapWithGpuMaskIdCommand_emul(void* dst, uint64_t vaNewStart, uint64_t vaAliasStart, uint64_t size, uint64_t prot, uint64_t gpuMaskId, uint64_t* outSize);
int sceKernelWriteModifyProtectCommand_emul(void* dst, uint64_t va, uint64_t size, uint64_t prot, uint64_t protMask, uint64_t* outSize);
int sceKernelWriteModifyProtectWithGpuMaskIdCommand_emul(void* dst, uint64_t va, uint64_t size, uint64_t prot, uint64_t protMask, uint64_t gpuMaskId, uint64_t* outSize);
int sceKernelWriteModifyMtypeProtectCommand_emul(void* dst, uint64_t va, uint64_t size, uint64_t type, uint64_t prot, uint64_t protMask, uint64_t* outSize);
int sceKernelWriteModifyMtypeProtectWithGpuMaskIdCommand_emul(void* dst, uint64_t va, uint64_t size, uint64_t type, uint64_t prot, uint64_t protMask, uint64_t gpuMaskId, uint64_t* outSize);
int sceKernelWriteRemapIntoPrtCommand_emul(uint32_t* dst, uint64_t va, uint64_t remapVa, uint64_t size, int prot, int opcode, uint64_t* outSize);
}
