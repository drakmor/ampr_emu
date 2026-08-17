/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "ampr_emu_config.h"

#include "ampr.h"
#include "ampr_debug_log.h"
#include "ampr_emu_kernel_amm.h"
#include "ampr_emu_kernel_lookup.h"
#include "ampr_emu_prot.h"
#include "ampr_libkernel_hook.h"
#include "ampr_libkernel_hook_targets.h"
#include "hde64.h"

#include <_kernel.h>
#include <sys/dmem.h>
#include <sys/types.h>

#include <atomic>
#include <cstdarg>
#include <cstdint>
#include <cstdio>

extern "C" int sceKernelAprGetFileSize(int fileId, uint64_t* outSize);
extern "C" int sceKernelAprGetFileStat(int fileId, SceKernelStat* st);
extern "C" int sceKernelAprResolveFilepathsToIds(const char* path[],
                                                  uint32_t num,
                                                  uint32_t ids[],
                                                  uint32_t* errorIndex);
extern "C" int sceKernelAprResolveFilepathsToIdsAndFileSizes(const char* path[],
                                                              uint32_t num,
                                                              uint32_t ids[],
                                                              size_t fileSizes[],
                                                              uint32_t* errorIndex);
extern "C" int sceKernelAprResolveFilepathsWithPrefixToIds(const char* pathPrefix,
                                                            const char* path[],
                                                            uint32_t num,
                                                            uint32_t ids[],
                                                            uint32_t* errorIndex);
extern "C" int sceKernelAprResolveFilepathsWithPrefixToIdsAndFileSizes(const char* pathPrefix,
                                                                        const char* path[],
                                                                        uint32_t num,
                                                                        uint32_t ids[],
                                                                        size_t fileSizes[],
                                                                        uint32_t* errorIndex);
extern "C" int sceKernelAprResolveFilepathsToIdsForEach(const char* path[],
                                                         uint32_t num,
                                                         uint32_t ids[],
                                                         int results[]);
extern "C" int sceKernelAprResolveFilepathsToIdsAndFileSizesForEach(const char* path[],
                                                                     uint32_t num,
                                                                     uint32_t ids[],
                                                                     size_t fileSizes[],
                                                                     int results[]);
extern "C" int sceKernelAprResolveFilepathsWithPrefixToIdsForEach(const char* pathPrefix,
                                                                   const char* path[],
                                                                   uint32_t num,
                                                                   uint32_t ids[],
                                                                   int results[]);
extern "C" int sceKernelAprResolveFilepathsWithPrefixToIdsAndFileSizesForEach(const char* pathPrefix,
                                                                               const char* path[],
                                                                               uint32_t num,
                                                                               uint32_t ids[],
                                                                               size_t fileSizes[],
                                                                               int results[]);
extern "C" int sceKernelAprSubmitCommandBuffer(sce::Ampr::AprCommandBuffer* commandBuffer, uint32_t prio);
extern "C" int sceKernelAprSubmitCommandBuffer_TEST(sce::Ampr::AprCommandBuffer* commandBuffer,
                                                     uint32_t prio,
                                                     void* testBuffer);
extern "C" int sceKernelAprSubmitCommandBufferAndGetResult(sce::Ampr::AprCommandBuffer* commandBuffer,
                                                            uint32_t prio,
                                                            SceAprResultBuffer* result,
                                                            SceAprSubmitId* id);
extern "C" int sceKernelAprSubmitCommandBufferAndGetResult_TEST(sce::Ampr::AprCommandBuffer* commandBuffer,
                                                                 uint32_t prio,
                                                                 SceAprResultBuffer* result,
                                                                 SceAprSubmitId* id,
                                                                 void* testBuffer);
extern "C" int sceKernelAprSubmitCommandBufferAndGetId(sce::Ampr::AprCommandBuffer* commandBuffer,
                                                        uint32_t prio,
                                                        SceAprSubmitId* id);
extern "C" int sceKernelAprWaitCommandBuffer(SceAprSubmitId id);
extern "C" int sceKernelWaitCommandBufferCompletion(SceAprSubmitId id);
extern "C" int sceKernelWriteMapCommand(void* dst,
                                         uint64_t va,
                                         uint64_t size,
                                         uint64_t type,
                                         uint64_t prot,
                                         uint64_t* outSize);

namespace {

constexpr size_t kJumpSize = 14;
constexpr size_t kMaxStolenBytes = 64;
constexpr size_t kTrampolinePageSize = SCE_KERNEL_PAGE_SIZE;
constexpr size_t kTrampolineSize = 512;
constexpr size_t kTrampolineSlotsPerPage = kTrampolinePageSize / kTrampolineSize;
constexpr size_t kHookMemoryPoolBatchCopyCapacity = 64u * SCE_KERNEL_PAGE_SIZE;
constexpr size_t kHookMemoryPoolBatchCopyPageCount =
    kHookMemoryPoolBatchCopyCapacity / SCE_KERNEL_PAGE_SIZE;
constexpr SceKernelModule kKnownLibkernelHandle = 0x2001;
static_assert((kTrampolinePageSize % kTrampolineSize) == 0, "trampoline slots must divide the page size");
static_assert(kTrampolineSlotsPerPage <= 32, "trampoline slot bitmap is uint32_t");
static_assert((kHookMemoryPoolBatchCopyCapacity % SCE_KERNEL_PAGE_SIZE) == 0,
              "memory-pool batch scratch buffer must be page sized");
static_assert(kHookMemoryPoolBatchCopyCapacity >= sizeof(SceKernelMemoryPoolBatchEntry),
              "memory-pool batch scratch buffer must hold at least one entry");
static_assert(kHookMemoryPoolBatchCopyPageCount <= 64u,
              "memory-pool batch scratch lease bitmap is uint64_t");

struct InlineDetour {
    void* target{};
    void* replacement{};
    void* trampoline{};
    size_t stolenLen{};
    uint8_t original[kMaxStolenBytes]{};
    bool installed{};
};

struct HookSpec {
    const char* symbol;
    void* replacement;
    bool mandatory;
    InlineDetour detour;
};

constexpr bool kHookMandatory = true;
constexpr bool kHookOptional = false;

enum HookLogStatus : uint8_t {
    kHookLogAlreadyInstalled = 1,
    kHookLogMissing = 2,
    kHookLogInstalled = 3,
    kHookLogFailed = 4,
};

enum HookFailReason : uint8_t {
    kHookFailNone = 0,
    kHookFailInvalidArgument = 1,
    kHookFailTrampolineAlloc = 2,
    kHookFailTargetProtect = 3,
    kHookFailDecode = 4,
    kHookFailUnsupportedRelative = 5,
    kHookFailRipRelativeRange = 6,
    kHookFailTrampolineOverflow = 7,
    kHookFailTrampolineProtect = 8,
    kHookFailInternalRelative = 9,
};

bool install_inline_detour(size_t hookIndex,
                           InlineDetour& detour,
                           void* target,
                           void* replacement,
                           HookFailReason& reason);
bool uninstall_inline_detour(InlineDetour& detour);
const char* hook_fail_reason_name(uint8_t reason);

#if AMPR_EMU_LIBKERNEL_HOOK_DIAGNOSTICS
struct HookLogRecord {
    const char* symbol;
    void* target;
    void* replacement;
    void* trampoline;
    size_t stolenLen;
    uint8_t status;
    uint8_t failReason;
    bool mandatory;
};
#endif

HookSpec g_hooks[] = {
    /*
     * Supported ReleaseHooks detours. Kernel equeues intentionally do not
     * appear here: event delivery stays native and command-buffer equeue writes
     * remain ordinary native APR/AMM records.
     */
    {"sceKernelOpen", reinterpret_cast<void*>(&sceKernelOpen_emul), kHookMandatory, {}},
    {"sceKernelStat", reinterpret_cast<void*>(&sceKernelStat_emul), kHookMandatory, {}},
    {"sceKernelCheckReachability", reinterpret_cast<void*>(&sceKernelCheckReachability_emul), kHookMandatory, {}},
    {"sceKernelUnlink", reinterpret_cast<void*>(&sceKernelUnlink_emul), kHookMandatory, {}},
    {"sceKernelRename", reinterpret_cast<void*>(&sceKernelRename_emul), kHookMandatory, {}},
    {"sceKernelMprotect", reinterpret_cast<void*>(&sceKernelMprotect_emul), kHookMandatory, {}},
    {"sceKernelMtypeprotect", reinterpret_cast<void*>(&sceKernelMtypeprotect_emul), kHookMandatory, {}},
    {"sceKernelMapFlexibleMemory", reinterpret_cast<void*>(&sceKernelMapFlexibleMemory_emul), kHookMandatory, {}},
    {"sceKernelMapDirectMemory", reinterpret_cast<void*>(&sceKernelMapDirectMemory_emul), kHookMandatory, {}},
    {"sceKernelMapDirectMemory2", reinterpret_cast<void*>(&sceKernelMapDirectMemory2_emul), kHookMandatory, {}},
    {"sceKernelBatchMap", reinterpret_cast<void*>(&sceKernelBatchMap_emul), kHookMandatory, {}},
    {"sceKernelBatchMap2", reinterpret_cast<void*>(&sceKernelBatchMap2_emul), kHookMandatory, {}},
    {"sceKernelJitMapSharedMemory", reinterpret_cast<void*>(&sceKernelJitMapSharedMemory_emul), kHookOptional, {}},
    {"sceKernelMemoryPoolBatch", reinterpret_cast<void*>(&sceKernelMemoryPoolBatch_emul), kHookMandatory, {}},
    {"sceKernelMemoryPoolCommit", reinterpret_cast<void*>(&sceKernelMemoryPoolCommit_emul), kHookMandatory, {}},
    {"sceKernelMapNamedFlexibleMemory", reinterpret_cast<void*>(&sceKernelMapNamedFlexibleMemory_emul), kHookMandatory, {}},
    {"sceKernelMapNamedDirectMemory", reinterpret_cast<void*>(&sceKernelMapNamedDirectMemory_emul), kHookMandatory, {}},

    {"sceKernelAprResolveFilepathsToIds", reinterpret_cast<void*>(&sceKernelAprResolveFilepathsToIds_emul), kHookMandatory, {}},
    {"sceKernelAprResolveFilepathsToIdsAndFileSizes", reinterpret_cast<void*>(&sceKernelAprResolveFilepathsToIdsAndFileSizes_emul), kHookMandatory, {}},
    {"sceKernelAprResolveFilepathsWithPrefixToIds", reinterpret_cast<void*>(&sceKernelAprResolveFilepathsWithPrefixToIds_emul), kHookMandatory, {}},
    {"sceKernelAprResolveFilepathsWithPrefixToIdsAndFileSizes", reinterpret_cast<void*>(&sceKernelAprResolveFilepathsWithPrefixToIdsAndFileSizes_emul), kHookMandatory, {}},
    {"sceKernelAprResolveFilepathsToIdsForEach", reinterpret_cast<void*>(&sceKernelAprResolveFilepathsToIdsForEach_emul), kHookMandatory, {}},
    {"sceKernelAprResolveFilepathsToIdsAndFileSizesForEach", reinterpret_cast<void*>(&sceKernelAprResolveFilepathsToIdsAndFileSizesForEach_emul), kHookMandatory, {}},
    {"sceKernelAprResolveFilepathsWithPrefixToIdsForEach", reinterpret_cast<void*>(&sceKernelAprResolveFilepathsWithPrefixToIdsForEach_emul), kHookMandatory, {}},
    {"sceKernelAprResolveFilepathsWithPrefixToIdsAndFileSizesForEach", reinterpret_cast<void*>(&sceKernelAprResolveFilepathsWithPrefixToIdsAndFileSizesForEach_emul), kHookMandatory, {}},
    {"sceKernelAprGetFileSize", reinterpret_cast<void*>(&sceKernelAprGetFileSize_emul), kHookMandatory, {}},
    {"sceKernelAprGetFileStat", reinterpret_cast<void*>(&sceKernelAprGetFileStat_emul), kHookMandatory, {}},
    {"sceKernelAprSubmitCommandBuffer", reinterpret_cast<void*>(&sceKernelAprSubmitCommandBuffer_emul), kHookMandatory, {}},
    {"sceKernelAprSubmitCommandBuffer_TEST", reinterpret_cast<void*>(&sceKernelAprSubmitCommandBuffer_TEST_emul), kHookMandatory, {}},
    {"sceKernelAprSubmitCommandBufferAndGetResult", reinterpret_cast<void*>(&sceKernelAprSubmitCommandBufferAndGetResult_emul), kHookMandatory, {}},
    {"sceKernelAprSubmitCommandBufferAndGetResult_TEST", reinterpret_cast<void*>(&sceKernelAprSubmitCommandBufferAndGetResult_TEST_emul), kHookMandatory, {}},
    {"sceKernelAprSubmitCommandBufferAndGetId", reinterpret_cast<void*>(&sceKernelAprSubmitCommandBufferAndGetId_emul), kHookMandatory, {}},
    {"sceKernelAprWaitCommandBuffer", reinterpret_cast<void*>(&sceKernelAprWaitCommandBuffer_emul), kHookMandatory, {}},
    {"sceKernelWaitCommandBufferCompletion", reinterpret_cast<void*>(&sceKernelWaitCommandBufferCompletion_emul), kHookMandatory, {}},

    {"sceKernelGetDirectMemorySize", reinterpret_cast<void*>(&sceKernelGetDirectMemorySize_emul), kHookMandatory, {}},
    {"sceKernelAvailableDirectMemorySize", reinterpret_cast<void*>(&sceKernelAvailableDirectMemorySize_emul), kHookMandatory, {}},
    {"sceKernelWriteMapCommand", reinterpret_cast<void*>(&sceKernelWriteMapCommand_emul), kHookMandatory, {}},
    {"sceKernelWriteMapCommand2", reinterpret_cast<void*>(&sceKernelWriteMapCommand2_emul), kHookMandatory, {}},
    {"sceKernelWriteMapWithGpuMaskIdCommand", reinterpret_cast<void*>(&sceKernelWriteMapWithGpuMaskIdCommand_emul), kHookMandatory, {}},
    {"sceKernelWriteMapDirectCommand", reinterpret_cast<void*>(&sceKernelWriteMapDirectCommand_emul), kHookMandatory, {}},
    {"sceKernelWriteMapDirectWithGpuMaskIdCommand", reinterpret_cast<void*>(&sceKernelWriteMapDirectWithGpuMaskIdCommand_emul), kHookMandatory, {}},
    {"sceKernelWriteRemapCommand", reinterpret_cast<void*>(&sceKernelWriteRemapCommand_emul), kHookMandatory, {}},
    {"sceKernelWriteRemapWithGpuMaskIdCommand", reinterpret_cast<void*>(&sceKernelWriteRemapWithGpuMaskIdCommand_emul), kHookMandatory, {}},
    {"sceKernelWriteMultiMapCommand", reinterpret_cast<void*>(&sceKernelWriteMultiMapCommand_emul), kHookMandatory, {}},
    {"sceKernelWriteMultiMapWithGpuMaskIdCommand", reinterpret_cast<void*>(&sceKernelWriteMultiMapWithGpuMaskIdCommand_emul), kHookMandatory, {}},
    {"sceKernelWriteModifyProtectCommand", reinterpret_cast<void*>(&sceKernelWriteModifyProtectCommand_emul), kHookMandatory, {}},
    {"sceKernelWriteModifyProtectWithGpuMaskIdCommand", reinterpret_cast<void*>(&sceKernelWriteModifyProtectWithGpuMaskIdCommand_emul), kHookMandatory, {}},
    {"sceKernelWriteModifyMtypeProtectCommand", reinterpret_cast<void*>(&sceKernelWriteModifyMtypeProtectCommand_emul), kHookMandatory, {}},
    {"sceKernelWriteModifyMtypeProtectWithGpuMaskIdCommand", reinterpret_cast<void*>(&sceKernelWriteModifyMtypeProtectWithGpuMaskIdCommand_emul), kHookMandatory, {}},
    {"sceKernelWriteRemapIntoPrtCommand", reinterpret_cast<void*>(&sceKernelWriteRemapIntoPrtCommand_emul), kHookOptional, {}},
};

constexpr size_t kHookCount = sizeof(g_hooks) / sizeof(g_hooks[0]);
static_assert(kHookCount == kAmprLibkernelHook_Count, "AmprLibkernelHookId must match g_hooks order");
static_assert(kHookCount <= 64, "hook capability mask is uint64_t-indexed by HookSpec order");
constexpr size_t kMaxTrampolinePages =
    (kHookCount + kTrampolineSlotsPerPage - 1u) / kTrampolineSlotsPerPage;

std::atomic<int> g_hookLock{0};
std::atomic<int> g_installed{0};
std::atomic<int> g_moduleIdentityLogged{0};
#if AMPR_EMU_LIBKERNEL_HOOK_DIAGNOSTICS
std::atomic<int> g_hookLogFlushed{0};
#endif
#if AMPR_EMU_DEBUG_LOG && (AMPR_EMU_DEBUG_LOG_VERBOSE || AMPR_EMU_DEBUG_LOG_TRACE)
std::atomic<int> g_hookRuntimeLogEnabled{0};
#endif
int g_hookInstallResult = 0;
std::atomic<int> g_hookInstallAttempted{0};
int g_hookInstalledCount = 0;
int g_hookMissingCount = 0;
int g_hookFailedCount = 0;
int g_hookMandatoryInstalledCount = 0;
int g_hookMandatoryMissingCount = 0;
int g_hookMandatoryFailedCount = 0;
uint64_t g_hookCapabilityMask = 0;
uint64_t g_hookMandatoryMask = 0;
uint64_t g_hookOptionalMask = 0;
uint64_t g_hookMandatoryCapabilityMask = 0;
#if AMPR_EMU_LIBKERNEL_HOOK_DIAGNOSTICS
size_t g_hookLogCount = 0;
HookLogRecord g_hookLogRecords[kHookCount]{};
#endif

#define AMPR_LIBKERNEL_SDK_FALLBACKS \
    reinterpret_cast<void*>(&::sceKernelOpen), \
    reinterpret_cast<void*>(&::sceKernelStat), \
    reinterpret_cast<void*>(&::sceKernelCheckReachability), \
    reinterpret_cast<void*>(&::sceKernelUnlink), \
    reinterpret_cast<void*>(&::sceKernelRename), \
    reinterpret_cast<void*>(&::sceKernelMprotect), \
    reinterpret_cast<void*>(&::sceKernelMtypeprotect), \
    reinterpret_cast<void*>(&::sceKernelMapFlexibleMemory), \
    reinterpret_cast<void*>(&::sceKernelMapDirectMemory), \
    reinterpret_cast<void*>(&::sceKernelMapDirectMemory2), \
    reinterpret_cast<void*>(&::sceKernelBatchMap), \
    reinterpret_cast<void*>(&::sceKernelBatchMap2), \
    nullptr, \
    reinterpret_cast<void*>(&::sceKernelMemoryPoolBatch), \
    reinterpret_cast<void*>(&::sceKernelMemoryPoolCommit), \
    reinterpret_cast<void*>(&::sceKernelMapNamedFlexibleMemory), \
    reinterpret_cast<void*>(&::sceKernelMapNamedDirectMemory), \
    reinterpret_cast<void*>(&::sceKernelAprResolveFilepathsToIds), \
    reinterpret_cast<void*>(&::sceKernelAprResolveFilepathsToIdsAndFileSizes), \
    reinterpret_cast<void*>(&::sceKernelAprResolveFilepathsWithPrefixToIds), \
    reinterpret_cast<void*>(&::sceKernelAprResolveFilepathsWithPrefixToIdsAndFileSizes), \
    reinterpret_cast<void*>(&::sceKernelAprResolveFilepathsToIdsForEach), \
    reinterpret_cast<void*>(&::sceKernelAprResolveFilepathsToIdsAndFileSizesForEach), \
    reinterpret_cast<void*>(&::sceKernelAprResolveFilepathsWithPrefixToIdsForEach), \
    reinterpret_cast<void*>(&::sceKernelAprResolveFilepathsWithPrefixToIdsAndFileSizesForEach), \
    reinterpret_cast<void*>(&::sceKernelAprGetFileSize), \
    reinterpret_cast<void*>(&::sceKernelAprGetFileStat), \
    reinterpret_cast<void*>(&::sceKernelAprSubmitCommandBuffer), \
    reinterpret_cast<void*>(&::sceKernelAprSubmitCommandBuffer_TEST), \
    reinterpret_cast<void*>(&::sceKernelAprSubmitCommandBufferAndGetResult), \
    reinterpret_cast<void*>(&::sceKernelAprSubmitCommandBufferAndGetResult_TEST), \
    reinterpret_cast<void*>(&::sceKernelAprSubmitCommandBufferAndGetId), \
    reinterpret_cast<void*>(&::sceKernelAprWaitCommandBuffer), \
    reinterpret_cast<void*>(&::sceKernelWaitCommandBufferCompletion), \
    reinterpret_cast<void*>(&::sceKernelGetDirectMemorySize), \
    reinterpret_cast<void*>(&::sceKernelAvailableDirectMemorySize), \
    reinterpret_cast<void*>(&::sceKernelWriteMapCommand), \
    reinterpret_cast<void*>(&::sceKernelWriteMapCommand2), \
    reinterpret_cast<void*>(&::sceKernelWriteMapWithGpuMaskIdCommand), \
    reinterpret_cast<void*>(&::sceKernelWriteMapDirectCommand), \
    reinterpret_cast<void*>(&::sceKernelWriteMapDirectWithGpuMaskIdCommand), \
    reinterpret_cast<void*>(&::sceKernelWriteRemapCommand), \
    reinterpret_cast<void*>(&::sceKernelWriteRemapWithGpuMaskIdCommand), \
    reinterpret_cast<void*>(&::sceKernelWriteMultiMapCommand), \
    reinterpret_cast<void*>(&::sceKernelWriteMultiMapWithGpuMaskIdCommand), \
    reinterpret_cast<void*>(&::sceKernelWriteModifyProtectCommand), \
    reinterpret_cast<void*>(&::sceKernelWriteModifyProtectWithGpuMaskIdCommand), \
    reinterpret_cast<void*>(&::sceKernelWriteModifyMtypeProtectCommand), \
    reinterpret_cast<void*>(&::sceKernelWriteModifyMtypeProtectWithGpuMaskIdCommand), \
    nullptr

void* const g_amprSdkLibkernelFallbackById[kAmprLibkernelHook_Count]{
    AMPR_LIBKERNEL_SDK_FALLBACKS,
};
static_assert((sizeof(g_amprSdkLibkernelFallbackById) / sizeof(g_amprSdkLibkernelFallbackById[0])) == kHookCount,
              "libkernel fallback table must match hook table");

extern "C" {
AMPR_LIBKERNEL_HOOK_EXPORT void* g_amprOriginalLibkernelById[kAmprLibkernelHook_Count]{
    AMPR_LIBKERNEL_SDK_FALLBACKS,
};
}
#undef AMPR_LIBKERNEL_SDK_FALLBACKS
alignas(SCE_KERNEL_PAGE_SIZE) uint8_t g_trampolineStorage[kMaxTrampolinePages][kTrampolinePageSize]{};
uint32_t g_trampolinePageUsed[kMaxTrampolinePages]{};
int g_trampolinePageProt[kMaxTrampolinePages]{};
alignas(SCE_KERNEL_PAGE_SIZE) uint8_t g_memoryPoolBatchCopyStorage[kHookMemoryPoolBatchCopyCapacity]{};
std::atomic<uint64_t> g_memoryPoolBatchCopyPages{0};

#if AMPR_EMU_DEBUG_LOG && (AMPR_EMU_DEBUG_LOG_VERBOSE || AMPR_EMU_DEBUG_LOG_TRACE)
constexpr size_t kRuntimeHookLogCapacity = 256;
constexpr size_t kRuntimeHookLogLineCapacity = 768;

struct RuntimeHookLogRecord {
    std::atomic<uint64_t> sequence{0};
    char text[kRuntimeHookLogLineCapacity]{};
};

RuntimeHookLogRecord g_runtimeHookLogRecords[kRuntimeHookLogCapacity]{};
std::atomic<uint64_t> g_runtimeHookLogWriteSequence{0};
std::atomic<uint64_t> g_runtimeHookLogFlushSequence{0};
std::atomic<uint64_t> g_runtimeHookLogDropped{0};
#endif

static inline void hook_spin_pause_or_yield(uint32_t& spins) {
    ++spins;
    if (spins < 4096u || (spins & 0xffu) != 0) {
        __builtin_ia32_pause();
        return;
    }
    (void)sceKernelUsleep(1u);
}

class HookLock {
public:
    HookLock() {
        uint32_t spins = 0;
        while (g_hookLock.exchange(1, std::memory_order_acquire) != 0) {
            hook_spin_pause_or_yield(spins);
        }
    }

    ~HookLock() {
        g_hookLock.store(0, std::memory_order_release);
    }

    HookLock(const HookLock&) = delete;
    HookLock& operator=(const HookLock&) = delete;
};

class MemoryPoolBatchScratchLease {
public:
    explicit MemoryPoolBatchScratchLease(size_t bytes) {
        const size_t pageCount =
            (bytes + SCE_KERNEL_PAGE_SIZE - 1u) / SCE_KERNEL_PAGE_SIZE;
        const uint64_t baseMask = pageCount == 64u
                                      ? UINT64_MAX
                                      : (uint64_t{1} << pageCount) - 1u;
        uint32_t spins = 0;
        for (;;) {
            uint64_t occupied =
                g_memoryPoolBatchCopyPages.load(std::memory_order_relaxed);
            for (size_t firstPage = 0;
                 firstPage + pageCount <= kHookMemoryPoolBatchCopyPageCount;
                 ++firstPage) {
                const uint64_t candidateMask = baseMask << firstPage;
                if ((occupied & candidateMask) != 0) {
                    continue;
                }
                if (g_memoryPoolBatchCopyPages.compare_exchange_weak(
                        occupied,
                        occupied | candidateMask,
                        std::memory_order_acquire,
                        std::memory_order_relaxed)) {
                    pages_ = candidateMask;
                    storage_ = g_memoryPoolBatchCopyStorage +
                        firstPage * SCE_KERNEL_PAGE_SIZE;
                    return;
                }
                break;
            }
            hook_spin_pause_or_yield(spins);
        }
    }

    ~MemoryPoolBatchScratchLease() {
        g_memoryPoolBatchCopyPages.fetch_and(~pages_, std::memory_order_release);
    }

    uint8_t* storage() const {
        return storage_;
    }

    MemoryPoolBatchScratchLease(const MemoryPoolBatchScratchLease&) = delete;
    MemoryPoolBatchScratchLease& operator=(const MemoryPoolBatchScratchLease&) = delete;

private:
    uint8_t* storage_{};
    uint64_t pages_{};
};

bool hooks_installed() {
    return g_installed.load(std::memory_order_acquire) != 0;
}

void set_hooks_installed(bool installed) {
    g_installed.store(installed ? 1 : 0, std::memory_order_release);
}

void publish_hook_original(size_t hookIndex) {
    if (hookIndex >= kHookCount) {
        return;
    }
    HookSpec& hook = g_hooks[hookIndex];
    if (hook.detour.installed) {
        g_amprOriginalLibkernelById[hookIndex] = hook.detour.trampoline;
    }
}

uint64_t hook_mask_bit(size_t index) {
    return uint64_t{1} << index;
}

void refresh_hook_runtime_state_from_detours() {
    int installed = 0;
    int mandatoryInstalled = 0;
    uint64_t capabilityMask = 0;
    uint64_t mandatoryMask = 0;
    uint64_t optionalMask = 0;
    uint64_t mandatoryCapabilityMask = 0;

    for (size_t index = 0; index < kHookCount; ++index) {
        HookSpec& hook = g_hooks[index];
        const uint64_t bit = hook_mask_bit(index);
        if (hook.mandatory) {
            mandatoryMask |= bit;
        } else {
            optionalMask |= bit;
        }

        if (hook.detour.installed) {
            ++installed;
            capabilityMask |= bit;
            if (hook.mandatory) {
                ++mandatoryInstalled;
                mandatoryCapabilityMask |= bit;
            }
            g_amprOriginalLibkernelById[index] = hook.detour.trampoline;
        } else {
            g_amprOriginalLibkernelById[index] = g_amprSdkLibkernelFallbackById[index];
        }
    }

    g_hookInstalledCount = installed;
    g_hookMandatoryInstalledCount = mandatoryInstalled;
    g_hookCapabilityMask = capabilityMask;
    g_hookMandatoryMask = mandatoryMask;
    g_hookOptionalMask = optionalMask;
    g_hookMandatoryCapabilityMask = mandatoryCapabilityMask;
    set_hooks_installed(mandatoryMask != 0 &&
                        mandatoryCapabilityMask == mandatoryMask);
}

void reset_deferred_hook_log() {
#if AMPR_EMU_LIBKERNEL_HOOK_DIAGNOSTICS
    g_hookLogCount = 0;
#endif
    g_hookInstallResult = 0;
    g_hookInstallAttempted.store(1, std::memory_order_release);
    g_hookInstalledCount = 0;
    g_hookMissingCount = 0;
    g_hookFailedCount = 0;
    g_hookMandatoryInstalledCount = 0;
    g_hookMandatoryMissingCount = 0;
    g_hookMandatoryFailedCount = 0;
    g_hookCapabilityMask = 0;
    g_hookMandatoryMask = 0;
    g_hookOptionalMask = 0;
    g_hookMandatoryCapabilityMask = 0;
#if AMPR_EMU_LIBKERNEL_HOOK_DIAGNOSTICS
    g_hookLogFlushed.store(0, std::memory_order_release);
#endif
#if AMPR_EMU_DEBUG_LOG && (AMPR_EMU_DEBUG_LOG_VERBOSE || AMPR_EMU_DEBUG_LOG_TRACE)
    g_hookRuntimeLogEnabled.store(0, std::memory_order_release);
#endif
}

#if AMPR_EMU_LIBKERNEL_HOOK_DIAGNOSTICS
void append_deferred_hook_log(const HookSpec& hook, HookLogStatus status, void* target, HookFailReason failReason) {
    if (g_hookLogCount >= sizeof(g_hookLogRecords) / sizeof(g_hookLogRecords[0])) {
        return;
    }
    HookLogRecord& record = g_hookLogRecords[g_hookLogCount++];
    record.symbol = hook.symbol;
    record.target = target ? target : hook.detour.target;
    record.replacement = hook.replacement;
    record.trampoline = hook.detour.trampoline;
    record.stolenLen = hook.detour.stolenLen;
    record.status = static_cast<uint8_t>(status);
    record.failReason = static_cast<uint8_t>(failReason);
    record.mandatory = hook.mandatory;
}
#else
#define append_deferred_hook_log(...) ((void)0)
#endif

#if AMPR_EMU_DEBUG_LOG && (AMPR_EMU_DEBUG_LOG_VERBOSE || AMPR_EMU_DEBUG_LOG_TRACE)
#define AMPR_HOOK_VERBOSE_LOG 1
void append_runtime_hook_log_line(const char* body) {
    if (!body || !*body) {
        return;
    }
    const uint64_t sequence = g_runtimeHookLogWriteSequence.fetch_add(1u, std::memory_order_acq_rel) + 1u;
    RuntimeHookLogRecord& record = g_runtimeHookLogRecords[(sequence - 1u) % kRuntimeHookLogCapacity];
    size_t pos = 0;
    while (pos + 1u < sizeof(record.text) && body[pos]) {
        record.text[pos] = body[pos];
        ++pos;
    }
    record.text[pos] = '\0';
    record.sequence.store(sequence, std::memory_order_release);
}

void hook_logf_enabled(const char* fmt, ...) {
    char body[kRuntimeHookLogLineCapacity]{};
    va_list ap;
    va_start(ap, fmt);
    const int bodyLen = std::vsnprintf(body, sizeof(body), fmt, ap);
    va_end(ap);
    if (bodyLen <= 0) {
        return;
    }
    append_runtime_hook_log_line(body);
}
#define hook_logf(...) \
    do { \
        if (g_hookRuntimeLogEnabled.load(std::memory_order_acquire) != 0) { \
            hook_logf_enabled(__VA_ARGS__); \
        } \
    } while (0)
#else
#define AMPR_HOOK_VERBOSE_LOG 0
#define hook_logf(...) ((void)0)
#endif

#define hook_log_criticalf(...) \
    do { \
        hook_logf(__VA_ARGS__); \
        sce::Ampr::Emu::debugLogCriticalf(__VA_ARGS__); \
    } while (0)

#if AMPR_HOOK_VERBOSE_LOG
[[maybe_unused]] void flush_runtime_hook_log_records() {
    uint64_t flushSequence = g_runtimeHookLogFlushSequence.load(std::memory_order_acquire);
    const uint64_t writeSequence = g_runtimeHookLogWriteSequence.load(std::memory_order_acquire);
    if (writeSequence <= flushSequence) {
        return;
    }

    if (writeSequence - flushSequence > kRuntimeHookLogCapacity) {
        const uint64_t newFlushSequence = writeSequence - kRuntimeHookLogCapacity;
        const uint64_t dropped = newFlushSequence - flushSequence;
        g_runtimeHookLogDropped.fetch_add(dropped, std::memory_order_acq_rel);
        flushSequence = newFlushSequence;
        sce::Ampr::Emu::debugLogf("libkernel.hook.runtime dropped=%llu",
                                  static_cast<unsigned long long>(dropped));
    }

    while (flushSequence < writeSequence) {
        const uint64_t nextSequence = flushSequence + 1u;
        const RuntimeHookLogRecord& record =
            g_runtimeHookLogRecords[(nextSequence - 1u) % kRuntimeHookLogCapacity];
        if (record.sequence.load(std::memory_order_acquire) != nextSequence) {
            break;
        }
        sce::Ampr::Emu::debugLogf("libkernel.hook %s", record.text);
        flushSequence = nextSequence;
    }
    g_runtimeHookLogFlushSequence.store(flushSequence, std::memory_order_release);
}
#endif

void copy_bytes(void* dst, const void* src, size_t len) {
    auto* d = static_cast<volatile uint8_t*>(dst);
    const auto* s = static_cast<const volatile uint8_t*>(src);
    for (size_t i = 0; i < len; ++i) {
        d[i] = s[i];
    }
}

void set_bytes(void* dst, uint8_t value, size_t len) {
    auto* d = static_cast<volatile uint8_t*>(dst);
    for (size_t i = 0; i < len; ++i) {
        d[i] = value;
    }
}

void store_i32_le(void* dst, int32_t value) {
    auto* p = static_cast<volatile uint8_t*>(dst);
    const uint32_t raw = static_cast<uint32_t>(value);
    for (size_t i = 0; i < sizeof(raw); ++i) {
        p[i] = static_cast<uint8_t>((raw >> (8u * i)) & 0xffu);
    }
}

int32_t load_i32_le(const void* src) {
    const auto* p = static_cast<const volatile uint8_t*>(src);
    uint32_t raw = 0;
    for (size_t i = 0; i < sizeof(raw); ++i) {
        raw |= static_cast<uint32_t>(p[i]) << (8u * i);
    }
    return static_cast<int32_t>(raw);
}

void store_u64_le(void* dst, uint64_t value) {
    auto* p = static_cast<volatile uint8_t*>(dst);
    for (size_t i = 0; i < sizeof(value); ++i) {
        p[i] = static_cast<uint8_t>((value >> (8u * i)) & 0xffu);
    }
}

[[maybe_unused]] const char* hook_fail_reason_name(uint8_t reason) {
    switch (reason) {
        case kHookFailNone: return "none";
        case kHookFailInvalidArgument: return "invalid-argument";
        case kHookFailTrampolineAlloc: return "trampoline-alloc";
        case kHookFailTargetProtect: return "target-protect";
        case kHookFailDecode: return "decode";
        case kHookFailUnsupportedRelative: return "unsupported-relative";
        case kHookFailRipRelativeRange: return "rip-relative-range";
        case kHookFailTrampolineOverflow: return "trampoline-overflow";
        case kHookFailTrampolineProtect: return "trampoline-protect";
        case kHookFailInternalRelative: return "internal-relative";
        default: return "unknown";
    }
}

void write_abs_jump(uint8_t* dst, void* target) {
    dst[0] = 0xFF;
    dst[1] = 0x25;
    dst[2] = 0x00;
    dst[3] = 0x00;
    dst[4] = 0x00;
    dst[5] = 0x00;
    store_u64_le(dst + 6, reinterpret_cast<uint64_t>(target));
}

uintptr_t page_floor(uintptr_t value) {
    return value & ~(static_cast<uintptr_t>(SCE_KERNEL_PAGE_SIZE) - 1u);
}

uintptr_t page_ceil(uintptr_t value) {
    return (value + SCE_KERNEL_PAGE_SIZE - 1u) & ~(static_cast<uintptr_t>(SCE_KERNEL_PAGE_SIZE) - 1u);
}

using SceKernelMprotectFn = int (*)(const void*, size_t, int);
using SceKernelMtypeprotectFn = int (*)(const void*, size_t, int, int);
using SceKernelMapFlexibleMemoryFn = int (*)(void**, size_t, int, int);
using SceKernelMapDirectMemoryFn = int (*)(void**, size_t, int, int, off_t, size_t);
using SceKernelMapDirectMemory2Fn = int (*)(void**, size_t, int, int, int, off_t, size_t);
using SceKernelBatchMapFn = int (*)(SceKernelBatchMapEntry*, int, int*);
using SceKernelBatchMap2Fn = int (*)(SceKernelBatchMapEntry*, int, int*, int);
using SceKernelJitMapSharedMemoryFn = int (*)(int, int, void**);
using SceKernelMemoryPoolBatchFn = int (*)(const SceKernelMemoryPoolBatchEntry*, int, int*, int);
using SceKernelMemoryPoolCommitFn = int (*)(void*, size_t, int, int, int);
using SceKernelMapNamedFlexibleMemoryFn = int (*)(void**, size_t, int, int, const char*);
using SceKernelMapNamedDirectMemoryFn = int (*)(void**, size_t, int, int, off_t, size_t, const char*);

struct AdjustedAmprWriteProt {
    int original;
    int adjusted;

    bool changed() const {
        return adjusted != original;
    }
};

template <typename Fn, typename... Args>
static inline int call_original_libkernel_slot(AmprLibkernelHookId hookId, Args... args) {
    return ampr_fixed_kernel_slot<Fn>(hookId)(args...);
}

template <typename Fn, typename... Args>
static inline int call_optional_original_libkernel_slot(AmprLibkernelHookId hookId, int missingRc, Args... args) {
    if (Fn original = ampr_fixed_kernel_slot<Fn>(hookId)) {
        return original(args...);
    }
    return missingRc;
}

static inline int adjusted_ampr_write_prot(int prot) {
    return static_cast<int>(sce::Ampr::Emu::protWithCpuRwForAmprWrite(static_cast<uint32_t>(prot)));
}

static inline AdjustedAmprWriteProt make_adjusted_ampr_write_prot(int prot) {
    return {prot, adjusted_ampr_write_prot(prot)};
}

int call_original_sceKernelMprotect(const void* addr, size_t len, int prot) {
    return call_original_libkernel_slot<SceKernelMprotectFn>(kAmprLibkernelHook_sceKernelMprotect,
                                                             addr,
                                                             len,
                                                             prot);
}

int call_original_sceKernelMtypeprotect(const void* addr, size_t size, int type, int prot) {
    return call_original_libkernel_slot<SceKernelMtypeprotectFn>(kAmprLibkernelHook_sceKernelMtypeprotect,
                                                                 addr,
                                                                 size,
                                                                 type,
                                                                 prot);
}

int call_original_sceKernelMapFlexibleMemory(void** addrInOut, size_t len, int prot, int flags) {
    return call_original_libkernel_slot<SceKernelMapFlexibleMemoryFn>(
        kAmprLibkernelHook_sceKernelMapFlexibleMemory,
        addrInOut,
        len,
        prot,
        flags);
}

int call_original_sceKernelMapDirectMemory(void** addr,
                                           size_t len,
                                           int prot,
                                           int flags,
                                           off_t directMemoryStart,
                                           size_t maxPageSize) {
    return call_original_libkernel_slot<SceKernelMapDirectMemoryFn>(kAmprLibkernelHook_sceKernelMapDirectMemory,
                                                                    addr,
                                                                    len,
                                                                    prot,
                                                                    flags,
                                                                    directMemoryStart,
                                                                    maxPageSize);
}

int call_original_sceKernelMapDirectMemory2(void** addr,
                                            size_t len,
                                            int type,
                                            int prot,
                                            int flags,
                                            off_t directMemoryStart,
                                            size_t maxPageSize) {
    return call_original_libkernel_slot<SceKernelMapDirectMemory2Fn>(kAmprLibkernelHook_sceKernelMapDirectMemory2,
                                                                     addr,
                                                                     len,
                                                                     type,
                                                                     prot,
                                                                     flags,
                                                                     directMemoryStart,
                                                                     maxPageSize);
}

int call_original_sceKernelBatchMap(SceKernelBatchMapEntry* entries, int numberOfEntries, int* numberOfEntriesOut) {
    return call_original_libkernel_slot<SceKernelBatchMapFn>(kAmprLibkernelHook_sceKernelBatchMap,
                                                             entries,
                                                             numberOfEntries,
                                                             numberOfEntriesOut);
}

int call_original_sceKernelBatchMap2(SceKernelBatchMapEntry* entries, int numberOfEntries, int* numberOfEntriesOut, int flags) {
    return call_original_libkernel_slot<SceKernelBatchMap2Fn>(kAmprLibkernelHook_sceKernelBatchMap2,
                                                              entries,
                                                              numberOfEntries,
                                                              numberOfEntriesOut,
                                                              flags);
}

int call_original_sceKernelJitMapSharedMemory(int fd, int prot, void** startOut) {
    return call_optional_original_libkernel_slot<SceKernelJitMapSharedMemoryFn>(
        kAmprLibkernelHook_sceKernelJitMapSharedMemory,
        SCE_KERNEL_ERROR_ENOSYS,
        fd,
        prot,
        startOut);
}

int call_original_sceKernelMemoryPoolBatch(const SceKernelMemoryPoolBatchEntry* entries, int n, int* indexOut, int flags) {
    return call_original_libkernel_slot<SceKernelMemoryPoolBatchFn>(kAmprLibkernelHook_sceKernelMemoryPoolBatch,
                                                                    entries,
                                                                    n,
                                                                    indexOut,
                                                                    flags);
}

int call_original_sceKernelMemoryPoolCommit(void* addr, size_t len, int type, int prot, int flags) {
    return call_original_libkernel_slot<SceKernelMemoryPoolCommitFn>(kAmprLibkernelHook_sceKernelMemoryPoolCommit,
                                                                     addr,
                                                                     len,
                                                                     type,
                                                                     prot,
                                                                     flags);
}

int call_original_sceKernelMapNamedFlexibleMemory(void** addrInOut, size_t len, int prot, int flags, const char* name) {
    return call_original_libkernel_slot<SceKernelMapNamedFlexibleMemoryFn>(
        kAmprLibkernelHook_sceKernelMapNamedFlexibleMemory,
        addrInOut,
        len,
        prot,
        flags,
        name);
}

int call_original_sceKernelMapNamedDirectMemory(void** addr,
                                                size_t len,
                                                int prot,
                                                int flags,
                                                off_t directMemoryStart,
                                                size_t alignment,
                                                const char* name) {
    return call_original_libkernel_slot<SceKernelMapNamedDirectMemoryFn>(
        kAmprLibkernelHook_sceKernelMapNamedDirectMemory,
        addr,
        len,
        prot,
        flags,
        directMemoryStart,
        alignment,
        name);
}

bool make_code_writable(void* addr, size_t len) {
    const uintptr_t begin = page_floor(reinterpret_cast<uintptr_t>(addr));
    const uintptr_t end = page_ceil(reinterpret_cast<uintptr_t>(addr) + len);
    return call_original_sceKernelMprotect(reinterpret_cast<void*>(begin),
                                           end - begin,
                                           SCE_KERNEL_PROT_CPU_ALL) == 0;
}

void restore_code_protection(void* addr, size_t len) {
    const uintptr_t begin = page_floor(reinterpret_cast<uintptr_t>(addr));
    const uintptr_t end = page_ceil(reinterpret_cast<uintptr_t>(addr) + len);
    (void)call_original_sceKernelMprotect(reinterpret_cast<void*>(begin),
                                          end - begin,
                                          SCE_KERNEL_PROT_CPU_READ | SCE_KERNEL_PROT_CPU_EXEC);
}

bool protect_trampoline_page(void* page, int prot) {
    for (size_t pageIndex = 0; pageIndex < kMaxTrampolinePages; ++pageIndex) {
        if (page != g_trampolineStorage[pageIndex]) {
            continue;
        }
        if (g_trampolinePageProt[pageIndex] == prot) {
            return true;
        }
        if (call_original_sceKernelMprotect(page, kTrampolinePageSize, prot) != 0) {
            return false;
        }
        g_trampolinePageProt[pageIndex] = prot;
        return true;
    }
    return false;
}

void* trampoline_page(size_t pageIndex) {
    return g_trampolineStorage[pageIndex];
}

void* allocate_trampoline() {
    for (size_t pageIndex = 0; pageIndex < kMaxTrampolinePages; ++pageIndex) {
        void* page = trampoline_page(pageIndex);
        uint32_t used = g_trampolinePageUsed[pageIndex];
        if (used == 0xffffffffu) {
            continue;
        }
        for (size_t slot = 0; slot < kTrampolineSlotsPerPage; ++slot) {
            const uint32_t bit = 1u << slot;
            if ((used & bit) != 0) {
                continue;
            }
            if (!protect_trampoline_page(page, SCE_KERNEL_PROT_CPU_ALL)) {
                return nullptr;
            }
            g_trampolinePageUsed[pageIndex] = used | bit;
            void* trampoline = static_cast<uint8_t*>(page) + slot * kTrampolineSize;
            set_bytes(trampoline, 0, kTrampolineSize);
            return trampoline;
        }
    }
    return nullptr;
}

bool make_trampoline_executable(void* trampoline) {
    if (!trampoline) {
        return false;
    }
    for (size_t pageIndex = 0; pageIndex < kMaxTrampolinePages; ++pageIndex) {
        void* page = trampoline_page(pageIndex);
        const uintptr_t pageBegin = reinterpret_cast<uintptr_t>(page);
        const uintptr_t slot = reinterpret_cast<uintptr_t>(trampoline);
        if (slot >= pageBegin && slot < pageBegin + kTrampolinePageSize) {
            return protect_trampoline_page(page, SCE_KERNEL_PROT_CPU_READ | SCE_KERNEL_PROT_CPU_EXEC);
        }
    }
    return false;
}

void release_trampoline(void* trampoline) {
    if (!trampoline) {
        return;
    }
    for (size_t pageIndex = 0; pageIndex < kMaxTrampolinePages; ++pageIndex) {
        void* page = trampoline_page(pageIndex);
        const uintptr_t pageBegin = reinterpret_cast<uintptr_t>(page);
        const uintptr_t slot = reinterpret_cast<uintptr_t>(trampoline);
        if (slot < pageBegin || slot >= pageBegin + kTrampolinePageSize) {
            continue;
        }

        const size_t slotIndex = (slot - pageBegin) / kTrampolineSize;
        g_trampolinePageUsed[pageIndex] &= ~(1u << slotIndex);
        (void)protect_trampoline_page(page, SCE_KERNEL_PROT_CPU_READ | SCE_KERNEL_PROT_CPU_EXEC);
        return;
    }
}

bool append_bytes(uint8_t* dst, size_t& dstLen, size_t dstCap, const void* src, size_t len) {
    if (dstLen + len > dstCap) {
        return false;
    }
    copy_bytes(dst + dstLen, src, len);
    dstLen += len;
    return true;
}

uint8_t choose_low_scratch_reg(const hde64s& hs) {
    constexpr uint8_t kCandidates[] = {3, 6, 7, 0, 1, 2};
    const uint8_t regOperand = static_cast<uint8_t>(hs.modrm_reg + (hs.rex_r ? 8u : 0u));
    for (uint8_t candidate : kCandidates) {
        if (candidate != regOperand) {
            return candidate;
        }
    }
    return 3;
}

bool append_push_reg(uint8_t* dst, size_t& dstLen, size_t dstCap, uint8_t reg) {
    if (reg >= 16 || dstLen + 2u > dstCap) {
        return false;
    }
    uint8_t* out = dst + dstLen;
    size_t pos = 0;
    if (reg >= 8) {
        out[pos++] = 0x41;
    }
    out[pos++] = static_cast<uint8_t>(0x50u + (reg & 7u));
    dstLen += pos;
    return true;
}

bool append_pop_reg(uint8_t* dst, size_t& dstLen, size_t dstCap, uint8_t reg) {
    if (reg >= 16 || dstLen + 2u > dstCap) {
        return false;
    }
    uint8_t* out = dst + dstLen;
    size_t pos = 0;
    if (reg >= 8) {
        out[pos++] = 0x41;
    }
    out[pos++] = static_cast<uint8_t>(0x58u + (reg & 7u));
    dstLen += pos;
    return true;
}

bool append_abs_jump(uint8_t* dst, size_t& dstLen, size_t dstCap, uintptr_t target) {
    if (dstLen + kJumpSize > dstCap) {
        return false;
    }
    write_abs_jump(dst + dstLen, reinterpret_cast<void*>(target));
    dstLen += kJumpSize;
    return true;
}

bool append_abs_call(uint8_t* dst, size_t& dstLen, size_t dstCap, uintptr_t target) {
    constexpr size_t kAbsCallSize = 16;
    if (dstLen + kAbsCallSize > dstCap) {
        return false;
    }
    uint8_t* out = dst + dstLen;
    out[0] = 0xFF;
    out[1] = 0x15;
    out[2] = 0x02;
    out[3] = 0x00;
    out[4] = 0x00;
    out[5] = 0x00;
    out[6] = 0xEB;
    out[7] = 0x08;
    store_u64_le(out + 8, target);
    dstLen += kAbsCallSize;
    return true;
}

bool append_mov_reg_imm64(uint8_t* dst, size_t& dstLen, size_t dstCap, uint8_t reg, uintptr_t value) {
    constexpr size_t kMovRegImm64Size = 10;
    if (reg >= 16 || dstLen + kMovRegImm64Size > dstCap) {
        return false;
    }
    uint8_t* out = dst + dstLen;
    out[0] = static_cast<uint8_t>(0x48u | ((reg >= 8) ? 0x01u : 0x00u));
    out[1] = static_cast<uint8_t>(0xB8u + (reg & 7u));
    store_u64_le(out + 2, value);
    dstLen += kMovRegImm64Size;
    return true;
}

bool append_mov_reg_abs_ptr64(uint8_t* dst, size_t& dstLen, size_t dstCap, uint8_t reg, uintptr_t address) {
    constexpr size_t kMovRegAbsPtrSize = 17;
    if (reg >= 16 || dstLen + kMovRegAbsPtrSize > dstCap) {
        return false;
    }

    const uint8_t scratch = reg == 11 ? 10 : 11;
    uint8_t* out = dst + dstLen;
    size_t pos = 0;
    if (scratch >= 8) {
        out[pos++] = 0x41;
    }
    out[pos++] = static_cast<uint8_t>(0x50u + (scratch & 7u));
    out[pos++] = static_cast<uint8_t>(0x48u | ((scratch >= 8) ? 0x01u : 0x00u));
    out[pos++] = static_cast<uint8_t>(0xB8u + (scratch & 7u));
    store_u64_le(out + pos, address);
    pos += sizeof(uint64_t);
    out[pos++] = static_cast<uint8_t>(0x48u | ((reg >= 8) ? 0x04u : 0x00u) | ((scratch >= 8) ? 0x01u : 0x00u));
    out[pos++] = 0x8B;
    out[pos++] = static_cast<uint8_t>(((reg & 7u) << 3) | (scratch & 7u));
    if (scratch >= 8) {
        out[pos++] = 0x41;
    }
    out[pos++] = static_cast<uint8_t>(0x58u + (scratch & 7u));
    dstLen += pos;
    return true;
}

bool append_cmp_abs_ptr64_reg(uint8_t* dst, size_t& dstLen, size_t dstCap, uint8_t reg, uintptr_t address) {
    constexpr size_t kCmpAbsPtrRegMaxSize = 18;
    if (reg >= 16 || dstLen + kCmpAbsPtrRegMaxSize > dstCap) {
        return false;
    }

    const uint8_t scratch = reg == 11 ? 10 : 11;
    uint8_t* out = dst + dstLen;
    size_t pos = 0;
    if (scratch >= 8) {
        out[pos++] = 0x41;
    }
    out[pos++] = static_cast<uint8_t>(0x50u + (scratch & 7u));
    out[pos++] = static_cast<uint8_t>(0x48u | ((scratch >= 8) ? 0x01u : 0x00u));
    out[pos++] = static_cast<uint8_t>(0xB8u + (scratch & 7u));
    store_u64_le(out + pos, address);
    pos += sizeof(uint64_t);
    out[pos++] = static_cast<uint8_t>(0x48u |
                                      ((reg >= 8) ? 0x04u : 0x00u) |
                                      ((scratch >= 8) ? 0x01u : 0x00u));
    out[pos++] = 0x39;
    out[pos++] = static_cast<uint8_t>(((reg & 7u) << 3) | (scratch & 7u));
    if (scratch >= 8) {
        out[pos++] = 0x41;
    }
    out[pos++] = static_cast<uint8_t>(0x58u + (scratch & 7u));
    dstLen += pos;
    return true;
}

bool clear_rex_b_for_copied_instruction(uint8_t* insn, const hde64s& hs) {
    if (!insn || hs.rex == 0) {
        return true;
    }
    for (size_t i = 0; i < hs.len; ++i) {
        if (insn[i] == hs.rex && insn[i] >= 0x40 && insn[i] <= 0x4f) {
            insn[i] = static_cast<uint8_t>(insn[i] & 0xfeu);
            return true;
        }
    }
    return false;
}

bool rip_relative_instruction_changes_stack(const hde64s& hs) {
    if (hs.opcode == 0x8f) {
        return true;
    }
    if (hs.opcode == 0xff) {
        const uint8_t group = hs.modrm_reg & 7u;
        // /2,/3 are calls: the callee would observe the scratch-register push
        // on its stack. /4,/5 are jumps: our trailing pop would never execute.
        // /6 is push itself. Only /0 (inc) and /1 (dec) are safe here.
        return group >= 2u && group <= 6u;
    }
    return false;
}

bool append_rip_relative_via_scratch(uint8_t* dst,
                                     size_t& dstLen,
                                     size_t dstCap,
                                     const uint8_t* src,
                                     const hde64s& hs,
                                     uintptr_t absolute,
                                     HookFailReason& reason) {
    if (!src || hs.disp_offset == 0 || rip_relative_instruction_changes_stack(hs)) {
        reason = kHookFailUnsupportedRelative;
        return false;
    }

    const uint8_t scratch = choose_low_scratch_reg(hs);
    const size_t needed = 1u + 10u + hs.len + 1u;
    if (dstLen + needed > dstCap) {
        reason = kHookFailTrampolineOverflow;
        return false;
    }
    if (!append_push_reg(dst, dstLen, dstCap, scratch) ||
        !append_mov_reg_imm64(dst, dstLen, dstCap, scratch, absolute)) {
        reason = kHookFailTrampolineOverflow;
        return false;
    }

    const size_t insnOffset = dstLen;
    if (!append_bytes(dst, dstLen, dstCap, src, hs.len)) {
        reason = kHookFailTrampolineOverflow;
        return false;
    }

    uint8_t* copied = dst + insnOffset;
    if (!clear_rex_b_for_copied_instruction(copied, hs)) {
        reason = kHookFailDecode;
        return false;
    }
    copied[hs.disp_offset] = 0;
    copied[hs.disp_offset + 1u] = 0;
    copied[hs.disp_offset + 2u] = 0;
    copied[hs.disp_offset + 3u] = 0;
    copied[hs.disp_offset - 1u] = static_cast<uint8_t>(0x80u | ((hs.modrm_reg & 7u) << 3u) | (scratch & 7u));

    if (!append_pop_reg(dst, dstLen, dstCap, scratch)) {
        reason = kHookFailTrampolineOverflow;
        return false;
    }
    return true;
}

bool append_abs_cond_jump(uint8_t* dst, size_t& dstLen, size_t dstCap, uint8_t opcode, uintptr_t target) {
    constexpr size_t kAbsCondJumpSize = 16;
    if (dstLen + kAbsCondJumpSize > dstCap) {
        return false;
    }
    uint8_t* out = dst + dstLen;
    out[0] = opcode ^ 1u;
    out[1] = static_cast<uint8_t>(kJumpSize);
    write_abs_jump(out + 2, reinterpret_cast<void*>(target));
    dstLen += kAbsCondJumpSize;
    return true;
}

bool relocate_relative_instruction(uint8_t* dst,
                                   size_t& dstLen,
                                   size_t dstCap,
                                   const uint8_t* src,
                                   uintptr_t srcBase,
                                   uintptr_t srcIp,
                                   const hde64s& hs,
                                   bool& terminal,
                                   uintptr_t& internalRelTarget,
                                   HookFailReason& reason) {
    uintptr_t target = 0;
    if (!hde64_relative_target(src, srcIp, &hs, &target)) {
        reason = kHookFailUnsupportedRelative;
        return false;
    }
    if (target >= srcBase && target < srcBase + kMaxStolenBytes &&
        (internalRelTarget == 0 || target < internalRelTarget)) {
        internalRelTarget = target;
    }

    if (hs.meta == HDE64_META_REL_CALL) {
        if (!append_abs_call(dst, dstLen, dstCap, target)) {
            reason = kHookFailTrampolineOverflow;
            return false;
        }
        return true;
    }

    if (hs.meta == HDE64_META_REL_JMP) {
        if (!append_abs_jump(dst, dstLen, dstCap, target)) {
            reason = kHookFailTrampolineOverflow;
            return false;
        }
        terminal = true;
        return true;
    }

    if (hs.meta == HDE64_META_REL_JCC) {
        if (!append_abs_cond_jump(dst, dstLen, dstCap, hs.branch_opcode, target)) {
            reason = kHookFailTrampolineOverflow;
            return false;
        }
        return true;
    }

    reason = kHookFailUnsupportedRelative;
    return false;
}

bool relocate_instruction(uint8_t* dst,
                          size_t& dstLen,
                          size_t dstCap,
                          const uint8_t* src,
                          uintptr_t srcBase,
                          uintptr_t srcIp,
                          uintptr_t dstIp,
                          const hde64s& hs,
                          bool& terminal,
                          uintptr_t& internalRelTarget,
                          HookFailReason& reason) {
    if (hs.flags & F_RELATIVE) {
        return relocate_relative_instruction(dst, dstLen, dstCap, src, srcBase, srcIp, hs, terminal, internalRelTarget, reason);
    }

    const bool ripRelative = (hs.flags & F_RIP_RELATIVE) != 0;
    uintptr_t absolute = 0;
    if (ripRelative) {
        if (!hde64_rip_absolute(src, srcIp, &hs, &absolute)) {
            reason = kHookFailDecode;
            return false;
        }
        if (hs.meta == HDE64_META_RIP_REL_LEA64) {
            if (!append_mov_reg_imm64(dst, dstLen, dstCap, hs.operand_reg, absolute)) {
                reason = kHookFailTrampolineOverflow;
                return false;
            }
            return true;
        }
        if (hs.meta == HDE64_META_RIP_REL_MOV_R64_PTR) {
            if (!append_mov_reg_abs_ptr64(dst, dstLen, dstCap, hs.operand_reg, absolute)) {
                reason = kHookFailTrampolineOverflow;
                return false;
            }
            return true;
        }
        if (hs.meta == HDE64_META_RIP_REL_CMP_PTR_R64) {
            if (!append_cmp_abs_ptr64_reg(dst, dstLen, dstCap, hs.operand_reg, absolute)) {
                reason = kHookFailTrampolineOverflow;
                return false;
            }
            return true;
        }
    }

    const size_t outOffset = dstLen;
    if (!append_bytes(dst, dstLen, dstCap, src, hs.len)) {
        reason = kHookFailTrampolineOverflow;
        return false;
    }

    if (!ripRelative) {
        return true;
    }

    const int64_t newDisp64 = static_cast<int64_t>(absolute) - static_cast<int64_t>(dstIp + hs.len);
    if (newDisp64 < INT32_MIN || newDisp64 > INT32_MAX) {
        dstLen = outOffset;
        return append_rip_relative_via_scratch(dst, dstLen, dstCap, src, hs, absolute, reason);
    }
    store_i32_le(dst + outOffset + hs.disp_offset, static_cast<int32_t>(newDisp64));
    return true;
}

enum class FixedWrapperDetourResult : uint8_t {
    kNotMatched,
    kInstalled,
    kFailed,
};

FixedWrapperDetourResult try_install_loader_status_wrapper_detour(InlineDetour& detour,
                                                                  uint8_t* src,
                                                                  void* replacement,
                                                                  uint8_t* trampoline,
                                                                  HookFailReason& reason) {
    if (!src || !replacement || !trampoline) {
        reason = kHookFailInvalidArgument;
        return FixedWrapperDetourResult::kFailed;
    }

    const bool isTestEcxEcx = src[0] == 0x85 && src[1] == 0xC9;
    const bool isShortJcc = src[2] >= 0x70 && src[2] <= 0x7F;
    const auto wrapperBase = reinterpret_cast<intptr_t>(src);
    const auto jccTarget = static_cast<uintptr_t>(wrapperBase + 4 + static_cast<intptr_t>(static_cast<int8_t>(src[3])));
    const bool returnsStatus = src[4] == 0xB8 && src[9] == 0xC3;
    const bool clearsEcx = (src[10] == 0x31 && src[11] == 0xC9) ||
                           (src[10] == 0x33 && src[11] == 0xC9);
    if (!isTestEcxEcx || !isShortJcc || jccTarget != reinterpret_cast<uintptr_t>(src + 10) ||
        !returnsStatus || !clearsEcx) {
        return FixedWrapperDetourResult::kNotMatched;
    }

    uintptr_t bodyTarget = 0;
    size_t stolen = 0;
    if (src[12] == 0xEB) {
        stolen = 14;
        bodyTarget = static_cast<uintptr_t>(wrapperBase + static_cast<intptr_t>(stolen) +
                                            static_cast<intptr_t>(static_cast<int8_t>(src[13])));
    } else if (src[12] == 0xE9) {
        stolen = 17;
        bodyTarget = static_cast<uintptr_t>(wrapperBase + static_cast<intptr_t>(stolen) +
                                            static_cast<intptr_t>(load_i32_le(src + 13)));
    } else {
        return FixedWrapperDetourResult::kNotMatched;
    }
    if (stolen < kJumpSize || stolen > kMaxStolenBytes) {
        reason = kHookFailDecode;
        return FixedWrapperDetourResult::kFailed;
    }

    size_t trampolineLen = 0;
    if (!append_bytes(trampoline, trampolineLen, kTrampolineSize, src, 12) ||
        !append_abs_jump(trampoline, trampolineLen, kTrampolineSize, bodyTarget)) {
        reason = kHookFailTrampolineOverflow;
        return FixedWrapperDetourResult::kFailed;
    }

    copy_bytes(detour.original, src, stolen);
    __builtin___clear_cache(reinterpret_cast<char*>(trampoline),
                            reinterpret_cast<char*>(trampoline + trampolineLen));
    if (!make_trampoline_executable(trampoline)) {
        reason = kHookFailTrampolineProtect;
        return FixedWrapperDetourResult::kFailed;
    }

    write_abs_jump(src, replacement);
    if (stolen > kJumpSize) {
        set_bytes(src + kJumpSize, 0x90, stolen - kJumpSize);
    }
    __builtin___clear_cache(reinterpret_cast<char*>(src), reinterpret_cast<char*>(src + stolen));

    detour.target = src;
    detour.replacement = replacement;
    detour.trampoline = trampoline;
    detour.stolenLen = stolen;
    detour.installed = true;
    return FixedWrapperDetourResult::kInstalled;
}

bool install_inline_detour(size_t hookIndex,
                           InlineDetour& detour,
                           void* target,
                           void* replacement,
                           HookFailReason& reason) {
    reason = kHookFailNone;
    if (detour.installed) {
        return true;
    }
    if (!target || !replacement || target == replacement) {
        reason = kHookFailInvalidArgument;
        return false;
    }

    uint8_t* trampoline = static_cast<uint8_t*>(allocate_trampoline());
    if (!trampoline) {
        reason = kHookFailTrampolineAlloc;
        return false;
    }

    auto* src = static_cast<uint8_t*>(target);

    if (!make_code_writable(target, kMaxStolenBytes)) {
        release_trampoline(trampoline);
        reason = kHookFailTargetProtect;
        return false;
    }

    auto fail_after_target_mprotect = [&]() {
        restore_code_protection(target, kMaxStolenBytes);
        release_trampoline(trampoline);
        return false;
    };

    switch (try_install_loader_status_wrapper_detour(detour, src, replacement, trampoline, reason)) {
        case FixedWrapperDetourResult::kInstalled:
            publish_hook_original(hookIndex);
            restore_code_protection(target, kMaxStolenBytes);
            return true;
        case FixedWrapperDetourResult::kFailed:
            return fail_after_target_mprotect();
        case FixedWrapperDetourResult::kNotMatched:
            break;
    }

    size_t stolen = 0;
    size_t trampolineLen = 0;
    bool terminal = false;
    uintptr_t internalRelTarget = 0;
    const uintptr_t srcBase = reinterpret_cast<uintptr_t>(src);
    while (stolen < kJumpSize && stolen < kMaxStolenBytes) {
        hde64s hs{};
        const unsigned int len = hde64_disasm(src + stolen, &hs);
        if (len == 0 || (hs.flags & F_ERROR) != 0 || stolen + len > kMaxStolenBytes) {
            reason = kHookFailDecode;
            return fail_after_target_mprotect();
        }
        if (!terminal) {
            const uintptr_t dstIp = reinterpret_cast<uintptr_t>(trampoline + trampolineLen);
            if (!relocate_instruction(trampoline,
                                      trampolineLen,
                                      kTrampolineSize,
                                      src + stolen,
                                      srcBase,
                                      reinterpret_cast<uintptr_t>(src + stolen),
                                      dstIp,
                                      hs,
                                      terminal,
                                      internalRelTarget,
                                      reason)) {
                return fail_after_target_mprotect();
            }
        }
        stolen += len;
    }
    if (stolen < kJumpSize) {
        reason = kHookFailDecode;
        return fail_after_target_mprotect();
    }
    if (internalRelTarget != 0 && internalRelTarget < reinterpret_cast<uintptr_t>(src + stolen)) {
        reason = kHookFailInternalRelative;
        return fail_after_target_mprotect();
    }
    if (!terminal && !append_abs_jump(trampoline, trampolineLen, kTrampolineSize, reinterpret_cast<uintptr_t>(src + stolen))) {
        reason = kHookFailTrampolineOverflow;
        return fail_after_target_mprotect();
    }

    copy_bytes(detour.original, target, stolen);
    __builtin___clear_cache(reinterpret_cast<char*>(trampoline),
                            reinterpret_cast<char*>(trampoline + trampolineLen));
    if (!make_trampoline_executable(trampoline)) {
        reason = kHookFailTrampolineProtect;
        return fail_after_target_mprotect();
    }
    write_abs_jump(src, replacement);
    if (stolen > kJumpSize) {
        set_bytes(src + kJumpSize, 0x90, stolen - kJumpSize);
    }
    __builtin___clear_cache(reinterpret_cast<char*>(src), reinterpret_cast<char*>(src + stolen));

    detour.target = target;
    detour.replacement = replacement;
    detour.trampoline = trampoline;
    detour.stolenLen = stolen;
    detour.installed = true;

    publish_hook_original(hookIndex);
    restore_code_protection(target, kMaxStolenBytes);
    return true;
}

bool uninstall_inline_detour(InlineDetour& detour) {
    if (!detour.installed) {
        return true;
    }
    if (!make_code_writable(detour.target, detour.stolenLen)) {
        return false;
    }
    copy_bytes(detour.target, detour.original, detour.stolenLen);
    __builtin___clear_cache(static_cast<char*>(detour.target),
                            static_cast<char*>(detour.target) + detour.stolenLen);
    restore_code_protection(detour.target, detour.stolenLen);
    release_trampoline(detour.trampoline);
    detour = InlineDetour{};
    return true;
}

void* resolve_libkernel_symbol(SceKernelModule libkernel, const char* symbol) {
    if (libkernel < 0 || !symbol) {
        return nullptr;
    }
    void* addr = nullptr;
    if (sceKernelDlsym(libkernel, symbol, &addr) != 0) {
        return nullptr;
    }
    return addr;
}

using KernelDebugOutTextFn = int (*)(int, const char*);

void emit_module_identity_system_log(SceKernelModule libkernel) {
    if (g_moduleIdentityLogged.load(std::memory_order_acquire) != 0) {
        return;
    }
    auto* const debugOut = reinterpret_cast<KernelDebugOutTextFn>(
        resolve_libkernel_symbol(libkernel, "sceKernelDebugOutText"));
    if (!debugOut) {
        return;
    }

    char line[256]{};
    const int length = std::snprintf(line,
                                     sizeof(line),
                                     "[AMPR_EMU] name=libSceAmpr version=%s build=%s %s\n",
                                     AMPR_EMU_VERSION,
                                     __DATE__,
                                     __TIME__);
    if (length <= 0) {
        return;
    }

    int expected = 0;
    if (!g_moduleIdentityLogged.compare_exchange_strong(
            expected,
            1,
            std::memory_order_acq_rel,
            std::memory_order_acquire)) {
        return;
    }
    if (debugOut(AMPR_EMU_DEBUG_LOG_KERNEL_OUT_CHANNEL, line) < 0) {
        // Permit a later explicit install attempt to retry a failed system-log
        // write without ever involving the file logger.
        g_moduleIdentityLogged.store(0, std::memory_order_release);
    }
}

} // namespace

extern "C" int sceKernelMprotect_emul(const void* addr, size_t len, int prot) {
    const AdjustedAmprWriteProt protAdjust = make_adjusted_ampr_write_prot(prot);
    if (protAdjust.changed()) {
        hook_log_criticalf("mprotect.ampr_write_cpu_rw addr=%p len=%zu prot=0x%x adjusted=0x%x",
                           addr,
                           len,
                           protAdjust.original,
                           protAdjust.adjusted);
    }
    return call_original_sceKernelMprotect(addr, len, protAdjust.adjusted);
}

extern "C" int sceKernelMtypeprotect_emul(const void* addr, size_t size, int type, int prot) {
    const AdjustedAmprWriteProt protAdjust = make_adjusted_ampr_write_prot(prot);
    if (protAdjust.changed()) {
        hook_log_criticalf("mtypeprotect.ampr_write_cpu_rw addr=%p len=%zu type=0x%x prot=0x%x adjusted=0x%x",
                           addr,
                           size,
                           type,
                           protAdjust.original,
                           protAdjust.adjusted);
    }
    return call_original_sceKernelMtypeprotect(addr, size, type, protAdjust.adjusted);
}

extern "C" int sceKernelMapFlexibleMemory_emul(void** addrInOut, size_t len, int prot, int flags) {
    const AdjustedAmprWriteProt protAdjust = make_adjusted_ampr_write_prot(prot);
    if (protAdjust.changed()) {
        hook_log_criticalf("mapFlexible.ampr_write_cpu_rw addr=%p len=%zu prot=0x%x adjusted=0x%x flags=0x%x",
                           addrInOut ? *addrInOut : nullptr,
                           len,
                           protAdjust.original,
                           protAdjust.adjusted,
                           flags);
    }
    return call_original_sceKernelMapFlexibleMemory(addrInOut, len, protAdjust.adjusted, flags);
}

extern "C" int sceKernelMapDirectMemory_emul(void** addr,
                                             size_t len,
                                             int prot,
                                             int flags,
                                             off_t directMemoryStart,
                                             size_t maxPageSize) {
    const AdjustedAmprWriteProt protAdjust = make_adjusted_ampr_write_prot(prot);
    if (protAdjust.changed()) {
        hook_log_criticalf("mapDirect.ampr_write_cpu_rw addr=%p len=%zu prot=0x%x adjusted=0x%x flags=0x%x dmem=0x%llx maxPage=0x%llx",
                           addr ? *addr : nullptr,
                           len,
                           protAdjust.original,
                           protAdjust.adjusted,
                           flags,
                           (unsigned long long)directMemoryStart,
                           (unsigned long long)maxPageSize);
    }
    return call_original_sceKernelMapDirectMemory(addr, len, protAdjust.adjusted, flags, directMemoryStart, maxPageSize);
}

extern "C" int sceKernelMapDirectMemory2_emul(void** addr,
                                              size_t len,
                                              int type,
                                              int prot,
                                              int flags,
                                              off_t directMemoryStart,
                                              size_t maxPageSize) {
    const AdjustedAmprWriteProt protAdjust = make_adjusted_ampr_write_prot(prot);
    if (protAdjust.changed()) {
        hook_log_criticalf("mapDirect2.ampr_write_cpu_rw addr=%p len=%zu type=0x%x prot=0x%x adjusted=0x%x flags=0x%x dmem=0x%llx maxPage=0x%llx",
                           addr ? *addr : nullptr,
                           len,
                           type,
                           protAdjust.original,
                           protAdjust.adjusted,
                           flags,
                           (unsigned long long)directMemoryStart,
                           (unsigned long long)maxPageSize);
    }
    return call_original_sceKernelMapDirectMemory2(addr, len, type, protAdjust.adjusted, flags, directMemoryStart, maxPageSize);
}

static bool batch_map_operation_has_protection(int operation) {
    return operation == SCE_KERNEL_MAP_OP_MAP_DIRECT ||
           operation == SCE_KERNEL_MAP_OP_PROTECT ||
           operation == SCE_KERNEL_MAP_OP_MAP_FLEXIBLE ||
           operation == SCE_KERNEL_MAP_OP_TYPE_PROTECT;
}

static int adjust_batch_map_entries_for_ampr_write(SceKernelBatchMapEntry* entries, int numberOfEntries, const char* apiName) {
    if (!entries || numberOfEntries <= 0) {
        return 0;
    }
    int adjustedCount = 0;
    for (int index = 0; index < numberOfEntries; ++index) {
        SceKernelBatchMapEntry& entry = entries[index];
        if (!batch_map_operation_has_protection(entry.operation)) {
            continue;
        }
        const auto prot = static_cast<uint8_t>(entry.protection);
        const auto adjustedProt = static_cast<uint8_t>(adjusted_ampr_write_prot(prot));
        if (adjustedProt == prot) {
            continue;
        }
        entry.protection = static_cast<char>(adjustedProt);
        ++adjustedCount;
        hook_log_criticalf("%s.ampr_write_cpu_rw index=%d addr=%p len=%zu op=%d type=0x%x prot=0x%x adjusted=0x%x",
                           apiName,
                           index,
                           entry.start,
                           entry.length,
                           entry.operation,
                           static_cast<int>(entry.type),
                           static_cast<unsigned>(prot),
                           static_cast<unsigned>(adjustedProt));
    }
    return adjustedCount;
}

extern "C" int sceKernelBatchMap_emul(SceKernelBatchMapEntry* entries, int numberOfEntries, int* numberOfEntriesOut) {
    (void)adjust_batch_map_entries_for_ampr_write(entries, numberOfEntries, "batchMap");
    return call_original_sceKernelBatchMap(entries, numberOfEntries, numberOfEntriesOut);
}

extern "C" int sceKernelBatchMap2_emul(SceKernelBatchMapEntry* entries, int numberOfEntries, int* numberOfEntriesOut, int flags) {
    (void)adjust_batch_map_entries_for_ampr_write(entries, numberOfEntries, "batchMap2");
    return call_original_sceKernelBatchMap2(entries, numberOfEntries, numberOfEntriesOut, flags);
}

extern "C" int sceKernelJitMapSharedMemory_emul(int fd, int prot, void** startOut) {
    const AdjustedAmprWriteProt protAdjust = make_adjusted_ampr_write_prot(prot);
    if (protAdjust.changed()) {
        hook_log_criticalf("jitMapShared.ampr_write_cpu_rw fd=%d addr=%p prot=0x%x adjusted=0x%x",
                           fd,
                           startOut ? *startOut : nullptr,
                           protAdjust.original,
                           protAdjust.adjusted);
    }
    return call_original_sceKernelJitMapSharedMemory(fd, protAdjust.adjusted, startOut);
}

static bool memory_pool_batch_entry_needs_adjustment(const SceKernelMemoryPoolBatchEntry& entry) {
    switch (entry.op) {
    case SCE_KERNEL_MEMORY_POOL_OP_COMMIT:
        return adjusted_ampr_write_prot(entry.commit.prot) != entry.commit.prot;
    case SCE_KERNEL_MEMORY_POOL_OP_PROTECT:
        return adjusted_ampr_write_prot(entry.protect.prot) != entry.protect.prot;
    case SCE_KERNEL_MEMORY_POOL_OP_TYPE_PROTECT:
        return adjusted_ampr_write_prot(entry.typeProtect.prot) != entry.typeProtect.prot;
    default:
        return false;
    }
}

static int memory_pool_batch_first_adjustment_index(const SceKernelMemoryPoolBatchEntry* entries, int n) {
    if (!entries || n <= 0) {
        return -1;
    }
    for (int index = 0; index < n; ++index) {
        if (memory_pool_batch_entry_needs_adjustment(entries[index])) {
            return index;
        }
    }
    return -1;
}

static void log_memory_pool_batch_adjustment(const SceKernelMemoryPoolBatchEntry& entry,
                                             int index,
                                             void* addr,
                                             size_t len,
                                             int type,
                                             uint8_t prot,
                                             uint8_t adjustedProt) {
    hook_log_criticalf("memoryPoolBatch.ampr_write_cpu_rw index=%d addr=%p len=%zu op=%u type=0x%x prot=0x%x adjusted=0x%x flags=0x%x",
                       index,
                       addr,
                       len,
                       entry.op,
                       type,
                       static_cast<unsigned>(prot),
                       static_cast<unsigned>(adjustedProt),
                       entry.flags);
}

static void adjust_memory_pool_batch_entry_for_ampr_write(SceKernelMemoryPoolBatchEntry& entry, int index) {
    switch (entry.op) {
    case SCE_KERNEL_MEMORY_POOL_OP_COMMIT: {
        const uint8_t prot = entry.commit.prot;
        const uint8_t adjustedProt = static_cast<uint8_t>(adjusted_ampr_write_prot(prot));
        if (adjustedProt != prot) {
            entry.commit.prot = adjustedProt;
            log_memory_pool_batch_adjustment(entry, index, entry.commit.addr, entry.commit.len, entry.commit.type, prot, adjustedProt);
        }
        break;
    }
    case SCE_KERNEL_MEMORY_POOL_OP_PROTECT: {
        const uint8_t prot = entry.protect.prot;
        const uint8_t adjustedProt = static_cast<uint8_t>(adjusted_ampr_write_prot(prot));
        if (adjustedProt != prot) {
            entry.protect.prot = adjustedProt;
            log_memory_pool_batch_adjustment(entry, index, entry.protect.addr, entry.protect.len, 0, prot, adjustedProt);
        }
        break;
    }
    case SCE_KERNEL_MEMORY_POOL_OP_TYPE_PROTECT: {
        const uint8_t prot = entry.typeProtect.prot;
        const uint8_t adjustedProt = static_cast<uint8_t>(adjusted_ampr_write_prot(prot));
        if (adjustedProt != prot) {
            entry.typeProtect.prot = adjustedProt;
            log_memory_pool_batch_adjustment(entry, index, entry.typeProtect.addr, entry.typeProtect.len, entry.typeProtect.type, prot, adjustedProt);
        }
        break;
    }
    default:
        break;
    }
}

static void adjust_memory_pool_batch_entries_for_ampr_write(SceKernelMemoryPoolBatchEntry* entries, int firstIndex, int n) {
    if (!entries || firstIndex < 0 || n <= firstIndex) {
        return;
    }
    for (int index = firstIndex; index < n; ++index) {
        adjust_memory_pool_batch_entry_for_ampr_write(entries[index], index);
    }
}

extern "C" int sceKernelMemoryPoolBatch_emul(const SceKernelMemoryPoolBatchEntry* entries, int n, int* indexOut, int flags) {
    const int firstAdjustmentIndex = memory_pool_batch_first_adjustment_index(entries, n);
    if (firstAdjustmentIndex < 0) {
        return call_original_sceKernelMemoryPoolBatch(entries, n, indexOut, flags);
    }

    const size_t count = static_cast<size_t>(n);
    if (count > static_cast<size_t>(-1) / sizeof(SceKernelMemoryPoolBatchEntry)) {
        hook_logf("memoryPoolBatch.copy.skip reason=overflow entries=%p n=%d flags=0x%x",
                  entries,
                  n,
                  flags);
        return call_original_sceKernelMemoryPoolBatch(entries, n, indexOut, flags);
    }

    const size_t bytes = count * sizeof(SceKernelMemoryPoolBatchEntry);
    if (bytes > kHookMemoryPoolBatchCopyCapacity) {
        hook_logf("memoryPoolBatch.copy.skip reason=bss-capacity entries=%p n=%d bytes=%zu capacity=%zu flags=0x%x",
                  entries,
                  n,
                  bytes,
                  kHookMemoryPoolBatchCopyCapacity,
                  flags);
        return call_original_sceKernelMemoryPoolBatch(entries, n, indexOut, flags);
    }

    MemoryPoolBatchScratchLease copyLease(bytes);
    copy_bytes(copyLease.storage(), entries, bytes);
    auto* copyEntries =
        reinterpret_cast<SceKernelMemoryPoolBatchEntry*>(copyLease.storage());
    adjust_memory_pool_batch_entries_for_ampr_write(copyEntries, firstAdjustmentIndex, n);
    const int rc = call_original_sceKernelMemoryPoolBatch(copyEntries, n, indexOut, flags);
    return rc;
}

extern "C" int sceKernelMemoryPoolCommit_emul(void* addr, size_t len, int type, int prot, int flags) {
    const AdjustedAmprWriteProt protAdjust = make_adjusted_ampr_write_prot(prot);
    if (protAdjust.changed()) {
        hook_log_criticalf("memoryPoolCommit.ampr_write_cpu_rw addr=%p len=%zu type=0x%x prot=0x%x adjusted=0x%x flags=0x%x",
                           addr,
                           len,
                           type,
                           protAdjust.original,
                           protAdjust.adjusted,
                           flags);
    }
    return call_original_sceKernelMemoryPoolCommit(addr, len, type, protAdjust.adjusted, flags);
}

extern "C" int sceKernelMapNamedFlexibleMemory_emul(void** addrInOut,
                                                    size_t len,
                                                    int prot,
                                                    int flags,
                                                    const char* name) {
    const AdjustedAmprWriteProt protAdjust = make_adjusted_ampr_write_prot(prot);
    if (protAdjust.changed()) {
        hook_log_criticalf("mapNamedFlexible.ampr_write_cpu_rw name=%s addr=%p len=%zu prot=0x%x adjusted=0x%x flags=0x%x",
                           name ? name : "(null)",
                           addrInOut ? *addrInOut : nullptr,
                           len,
                           protAdjust.original,
                           protAdjust.adjusted,
                           flags);
    }
    return call_original_sceKernelMapNamedFlexibleMemory(addrInOut, len, protAdjust.adjusted, flags, name);
}

extern "C" int sceKernelMapNamedDirectMemory_emul(void** addr,
                                                  size_t len,
                                                  int prot,
                                                  int flags,
                                                  off_t directMemoryStart,
                                                  size_t alignment,
                                                  const char* name) {
    const AdjustedAmprWriteProt protAdjust = make_adjusted_ampr_write_prot(prot);
    if (protAdjust.changed()) {
        hook_log_criticalf("mapNamedDirect.ampr_write_cpu_rw name=%s addr=%p len=%zu prot=0x%x adjusted=0x%x flags=0x%x dmem=0x%llx align=0x%llx",
                           name ? name : "(null)",
                           addr ? *addr : nullptr,
                           len,
                           protAdjust.original,
                           protAdjust.adjusted,
                           flags,
                           (unsigned long long)directMemoryStart,
                           (unsigned long long)alignment);
    }
    return call_original_sceKernelMapNamedDirectMemory(addr, len, protAdjust.adjusted, flags, directMemoryStart, alignment, name);
}

static int ampr_install_libkernel_hooks_for_module(int libkernelHandle) {
    HookLock lock;
    const SceKernelModule libkernel = static_cast<SceKernelModule>(libkernelHandle);
    emit_module_identity_system_log(libkernel);
    if (hooks_installed()) {
        hook_logf("install status=already-installed");
        return 0;
    }

    reset_deferred_hook_log();

    int installed = 0;
    int missing = 0;
    int failed = 0;
    int mandatoryInstalled = 0;
    int mandatoryMissing = 0;
    int mandatoryFailed = 0;
    uint64_t capabilityMask = 0;
    uint64_t mandatoryMask = 0;
    uint64_t optionalMask = 0;
    uint64_t mandatoryCapabilityMask = 0;
    for (size_t hookIndex = 0; hookIndex < kHookCount; ++hookIndex) {
        HookSpec& hook = g_hooks[hookIndex];
        const uint64_t hookBit = hook_mask_bit(hookIndex);
        if (hook.mandatory) {
            mandatoryMask |= hookBit;
        } else {
            optionalMask |= hookBit;
        }
        if (hook.detour.installed) {
            publish_hook_original(hookIndex);
            ++installed;
            capabilityMask |= hookBit;
            if (hook.mandatory) {
                ++mandatoryInstalled;
                mandatoryCapabilityMask |= hookBit;
            }
            hook_logf("symbol=%s status=already-installed target=%p trampoline=%p",
                      hook.symbol,
                      hook.detour.target,
                      hook.detour.trampoline);
            append_deferred_hook_log(hook, kHookLogAlreadyInstalled, hook.detour.target, kHookFailNone);
            continue;
        }
        void* target = resolve_libkernel_symbol(libkernel, hook.symbol);
        if (!target) {
            ++missing;
            if (hook.mandatory) {
                ++mandatoryMissing;
            }
            hook_logf("symbol=%s status=missing", hook.symbol);
            append_deferred_hook_log(hook, kHookLogMissing, nullptr, kHookFailNone);
            continue;
        }
        HookFailReason failReason = kHookFailNone;
        if (install_inline_detour(hookIndex, hook.detour, target, hook.replacement, failReason)) {
            ++installed;
            capabilityMask |= hookBit;
            if (hook.mandatory) {
                ++mandatoryInstalled;
                mandatoryCapabilityMask |= hookBit;
            }
            hook_logf("symbol=%s status=installed target=%p replacement=%p trampoline=%p stolen=%zu",
                      hook.symbol,
                      hook.detour.target,
                      hook.detour.replacement,
                      hook.detour.trampoline,
                      hook.detour.stolenLen);
            append_deferred_hook_log(hook, kHookLogInstalled, target, kHookFailNone);
        } else {
            ++failed;
            if (hook.mandatory) {
                ++mandatoryFailed;
            }
            hook_logf("symbol=%s status=failed target=%p replacement=%p",
                      hook.symbol,
                      target,
                      hook.replacement);
            append_deferred_hook_log(hook, kHookLogFailed, target, failReason);
        }
    }

    g_hookInstalledCount = installed;
    g_hookMissingCount = missing;
    g_hookFailedCount = failed;
    g_hookMandatoryInstalledCount = mandatoryInstalled;
    g_hookMandatoryMissingCount = mandatoryMissing;
    g_hookMandatoryFailedCount = mandatoryFailed;
    g_hookCapabilityMask = capabilityMask;
    g_hookMandatoryMask = mandatoryMask;
    g_hookOptionalMask = optionalMask;
    g_hookMandatoryCapabilityMask = mandatoryCapabilityMask;

    hook_logf("install status=summary installed=%d missing=%d failed=%d mandatoryInstalled=%d mandatoryMissing=%d mandatoryFailed=%d capability=0x%llx mandatoryMask=0x%llx optionalMask=0x%llx mandatoryCapability=0x%llx total=%zu",
              installed,
              missing,
              failed,
              mandatoryInstalled,
              mandatoryMissing,
              mandatoryFailed,
              static_cast<unsigned long long>(capabilityMask),
              static_cast<unsigned long long>(mandatoryMask),
              static_cast<unsigned long long>(optionalMask),
              static_cast<unsigned long long>(mandatoryCapabilityMask),
              kHookCount);

    if (installed == 0) {
        refresh_hook_runtime_state_from_detours();
        hook_logf("install status=failed reason=no-symbols-installed missing=%d failed=%d",
                  missing,
                  failed);
        g_hookInstallResult = -1;
        return -1;
    }

    if (mandatoryMissing != 0 || mandatoryFailed != 0) {
        bool rollbackOk = true;
        for (size_t index = kHookCount; index > 0; --index) {
            rollbackOk = uninstall_inline_detour(g_hooks[index - 1].detour) && rollbackOk;
        }
        // A failed restore must retain the corresponding trampoline/original
        // pointer and capability bit. Never advertise a fallback for a detour
        // that is still physically patched into libkernel.
        refresh_hook_runtime_state_from_detours();
        hook_logf("install status=failed reason=mandatory-hook-unavailable mandatoryMissing=%d mandatoryFailed=%d rollbackOk=%u residual=%d capability=0x%llx",
                  mandatoryMissing,
                  mandatoryFailed,
                  rollbackOk ? 1u : 0u,
                  g_hookInstalledCount,
                  static_cast<unsigned long long>(g_hookCapabilityMask));
        g_hookInstallResult = -1;
        return -1;
    }

    set_hooks_installed(true);
    g_hookInstallResult = 0;
    return 0;
}

/*
 * ReleaseHooks libkernel hook control exports.
 *
 * These are not fake libkernel entrypoints; they are diagnostic/control helpers
 * used by the supported ReleaseHooks build. Install resolves the real libkernel
 * module, patches only the configured APR/equeue/file/direct-memory helper set,
 * and records missing/failed symbols for later status reporting. Uninstall
 * removes installed detours in reverse order. The status/flush helpers expose
 * startup results without doing APR index or file-I/O work from module_start.
 */
extern "C" AMPR_LIBKERNEL_HOOK_EXPORT int amprInstallLibkernelHooks(void) {
    return ampr_install_libkernel_hooks_for_module(kKnownLibkernelHandle);
}

extern "C" AMPR_LIBKERNEL_HOOK_EXPORT int amprUninstallLibkernelHooks(void) {
    HookLock lock;
#if AMPR_EMU_DEBUG_LOG && (AMPR_EMU_DEBUG_LOG_VERBOSE || AMPR_EMU_DEBUG_LOG_TRACE)
    g_hookRuntimeLogEnabled.store(0, std::memory_order_release);
#endif
    bool ok = true;
    int removed = 0;
    int failed = 0;
    (void)removed;
    (void)failed;
    for (size_t index = kHookCount; index > 0; --index) {
        HookSpec& hook = g_hooks[index - 1];
        const bool wasInstalled = hook.detour.installed;
        const bool currentOk = uninstall_inline_detour(hook.detour);
        ok = currentOk && ok;
        if (wasInstalled && currentOk) {
            ++removed;
            hook_logf("symbol=%s status=uninstalled", hook.symbol);
        } else if (wasInstalled) {
            ++failed;
            hook_logf("symbol=%s status=uninstall-failed", hook.symbol);
        }
    }
    // Recompute originals/capabilities from what is actually still installed.
    // This keeps partial restore failures callable through their trampoline
    // instead of publishing an SDK fallback behind a still-active detour.
    refresh_hook_runtime_state_from_detours();
    hook_logf("uninstall status=summary removed=%d failed=%d residual=%d capability=0x%llx",
              removed,
              failed,
              g_hookInstalledCount,
              static_cast<unsigned long long>(g_hookCapabilityMask));
    return ok ? 0 : -1;
}

extern "C" AMPR_LIBKERNEL_HOOK_EXPORT int amprLibkernelHooksInstalled(void) {
    return hooks_installed() ? 1 : 0;
}

#if AMPR_EMU_LIBKERNEL_HOOK_DIAGNOSTICS
extern "C" AMPR_LIBKERNEL_HOOK_EXPORT int amprFormatLibkernelHookStatus(char* out, unsigned long long outSize) {
    if (!out || outSize == 0) {
        return -1;
    }
    const int attempted = g_hookInstallAttempted.load(std::memory_order_acquire) ? 1 : 0;
    const int installed = hooks_installed() ? 1 : 0;
    const int flushed = g_hookLogFlushed.load(std::memory_order_acquire) ? 1 : 0;
    return std::snprintf(out,
                         static_cast<size_t>(outSize),
                         "libkernel.hook.startup attempted=%d installed=%d flushed=%d rc=0x%x installedCount=%d missing=%d failed=%d mandatoryInstalled=%d mandatoryMissing=%d mandatoryFailed=%d capability=0x%llx mandatoryMask=0x%llx optionalMask=0x%llx mandatoryCapability=0x%llx total=%zu",
                         attempted,
                         installed,
                         flushed,
                         g_hookInstallResult,
                         g_hookInstalledCount,
                         g_hookMissingCount,
                         g_hookFailedCount,
                         g_hookMandatoryInstalledCount,
                         g_hookMandatoryMissingCount,
                         g_hookMandatoryFailedCount,
                         static_cast<unsigned long long>(g_hookCapabilityMask),
                         static_cast<unsigned long long>(g_hookMandatoryMask),
                         static_cast<unsigned long long>(g_hookOptionalMask),
                         static_cast<unsigned long long>(g_hookMandatoryCapabilityMask),
                         kHookCount);
}

extern "C" AMPR_LIBKERNEL_HOOK_EXPORT void amprFlushLibkernelHookLog(void) {
    const bool attempted = g_hookInstallAttempted.load(std::memory_order_acquire) != 0;
    [[maybe_unused]] const bool flushStartup =
        attempted && g_hookLogFlushed.exchange(1, std::memory_order_acq_rel) == 0;

#if AMPR_EMU_DEBUG_LOG
    sce::Ampr::Emu::startDebugLogWriter();
    if (flushStartup) {
    if (g_hookInstallResult != 0 || g_hookFailedCount != 0 || g_hookMandatoryMissingCount != 0 ||
        g_hookMandatoryFailedCount != 0) {
        sce::Ampr::Emu::debugLogCriticalf("libkernel.hook.deferred.summary rc=0x%x installed=%d missing=%d failed=%d mandatoryInstalled=%d mandatoryMissing=%d mandatoryFailed=%d capability=0x%llx mandatoryMask=0x%llx optionalMask=0x%llx mandatoryCapability=0x%llx total=%zu",
                                          g_hookInstallResult,
                                          g_hookInstalledCount,
                                          g_hookMissingCount,
                                          g_hookFailedCount,
                                          g_hookMandatoryInstalledCount,
                                          g_hookMandatoryMissingCount,
                                          g_hookMandatoryFailedCount,
                                          static_cast<unsigned long long>(g_hookCapabilityMask),
                                          static_cast<unsigned long long>(g_hookMandatoryMask),
                                          static_cast<unsigned long long>(g_hookOptionalMask),
                                          static_cast<unsigned long long>(g_hookMandatoryCapabilityMask),
                                          kHookCount);
    } else {
        sce::Ampr::Emu::debugLogf("libkernel.hook.deferred.summary rc=0x%x installed=%d missing=%d failed=%d mandatoryInstalled=%d mandatoryMissing=%d mandatoryFailed=%d capability=0x%llx mandatoryMask=0x%llx optionalMask=0x%llx mandatoryCapability=0x%llx total=%zu",
                                  g_hookInstallResult,
                                  g_hookInstalledCount,
                                  g_hookMissingCount,
                                  g_hookFailedCount,
                                  g_hookMandatoryInstalledCount,
                                  g_hookMandatoryMissingCount,
                                  g_hookMandatoryFailedCount,
                                  static_cast<unsigned long long>(g_hookCapabilityMask),
                                  static_cast<unsigned long long>(g_hookMandatoryMask),
                                  static_cast<unsigned long long>(g_hookOptionalMask),
                                  static_cast<unsigned long long>(g_hookMandatoryCapabilityMask),
                                  kHookCount);
    }

    for (size_t i = 0; i < g_hookLogCount; ++i) {
        const HookLogRecord& record = g_hookLogRecords[i];
        const bool mandatoryProblem =
            record.mandatory && (record.status == kHookLogMissing || record.status == kHookLogFailed);
        if (!AMPR_HOOK_VERBOSE_LOG && record.status != kHookLogFailed && !mandatoryProblem) {
            continue;
        }
        const char* status = "unknown";
        switch (record.status) {
            case kHookLogAlreadyInstalled: status = "already-installed"; break;
            case kHookLogMissing: status = "missing"; break;
            case kHookLogInstalled: status = "installed"; break;
            case kHookLogFailed: status = "failed"; break;
            default: break;
        }
        if (record.status == kHookLogFailed || mandatoryProblem) {
            sce::Ampr::Emu::debugLogCriticalf("libkernel.hook.symbol name=%s required=%d status=%s reason=%s target=%p replacement=%p trampoline=%p stolen=%zu",
                                              record.symbol ? record.symbol : "<null>",
                                              record.mandatory ? 1 : 0,
                                              status,
                                              hook_fail_reason_name(record.failReason),
                                              record.target,
                                              record.replacement,
                                              record.trampoline,
                                              record.stolenLen);
        } else {
            sce::Ampr::Emu::debugLogf("libkernel.hook.symbol name=%s required=%d status=%s reason=%s target=%p replacement=%p trampoline=%p stolen=%zu",
                                      record.symbol ? record.symbol : "<null>",
                                      record.mandatory ? 1 : 0,
                                      status,
                                      hook_fail_reason_name(record.failReason),
                                      record.target,
                                      record.replacement,
                                      record.trampoline,
                                      record.stolenLen);
        }
    }
    }
#if AMPR_HOOK_VERBOSE_LOG
    flush_runtime_hook_log_records();
#endif
#endif

#if AMPR_HOOK_VERBOSE_LOG
    if (flushStartup) {
        g_hookRuntimeLogEnabled.store(1, std::memory_order_release);
    }
#endif
}
#endif

extern "C" AMPR_LIBKERNEL_HOOK_EXPORT void* amprResolveLibkernelFunction(const char* symbol) {
    return resolve_libkernel_symbol(kKnownLibkernelHandle, symbol);
}
