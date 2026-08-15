#include "prospero_test_common.h"

#include <ampr/ampr_error.h>

#include <cerrno>
#include <cstdint>
#include <cstdlib>

#ifndef SCE_AMPR_APR_RESOLVE_MAX
#define SCE_AMPR_APR_RESOLVE_MAX (1024u)
#endif
#ifndef SCE_KERNEL_PATH_MAX
#define SCE_KERNEL_PATH_MAX (1024)
#endif

using namespace sce::Ampr;

extern "C" int sceKernelAprSubmitCommandBufferAndGetId(AprCommandBuffer* commandBuffer, uint32_t prio, SceAprSubmitId* id);
extern "C" int sceKernelAprWaitCommandBuffer(uint32_t id);
extern "C" int sceKernelAprCtrl_emul(int cmd, void* arg, size_t size, void* rsv1, int rsv2);
extern "C" int sceKernelGetAmprCounter_emul(unsigned int counterId, uint64_t* outValue);
extern "C" int64_t sceAmprAprCommandBufferMapBegin(AprCommandBuffer* cb, uint64_t va, uint64_t size, int type, int prot);
extern "C" int64_t sceAmprAprCommandBufferMapDirectBegin(AprCommandBuffer* cb, uint64_t va, uint64_t dmemOffset, size_t size, int type, int prot);
extern "C" int64_t sceAmprAprCommandBufferMapEnd(AprCommandBuffer* cb);

int main() {
    int failures = 0;

    CommandBuffer cb{};
    failures += !expect_rc("setBuffer(null)", cb.setBuffer(nullptr, 4096), SCE_KERNEL_ERROR_EINVAL);

    void* raw = std::malloc(4097);
    failures += !expect_true("malloc", raw != nullptr);
    if (!raw) {
        return 1;
    }

    void* misaligned = static_cast<void*>(static_cast<uint8_t*>(raw) + 1);
    failures += !expect_rc("setBuffer(misaligned)", cb.setBuffer(misaligned, 4096), SCE_KERNEL_ERROR_EINVAL);
    failures += !expect_rc("setBuffer(size=0)", cb.setBuffer(raw, 0), SCE_KERNEL_ERROR_EINVAL);

    ScopedAlignedBuffer aligned(4096);
    failures += !expect_true("aligned alloc", aligned.ptr != nullptr);
    if (!aligned.ptr) {
        std::free(raw);
        return 1;
    }

    failures += !expect_rc("setBuffer(valid)", cb.setBuffer(aligned.ptr, 4096), 0);
    failures += !expect_rc("writeAddressOnCompletion(null)", cb.writeAddressOnCompletion(nullptr, 1), SCE_KERNEL_ERROR_EINVAL);
    failures += !expect_rc("writeKernelEventQueueOnCompletion(null)", cb.writeKernelEventQueueOnCompletion(nullptr, 1, 0), SCE_KERNEL_ERROR_EINVAL);
    failures += !expect_rc("nop(0)", cb.nop(0), SCE_KERNEL_ERROR_EINVAL);

    ScopedAlignedBuffer aprMapNegBuf(4096);
    failures += !expect_true("apr map negative buffer alloc", aprMapNegBuf.ptr != nullptr);
    AprCommandBuffer aprMapNeg{};
    failures += !expect_rc("aprMapNeg.setBuffer", aprMapNeg.setBuffer(aprMapNegBuf.ptr, 4096), 0);
    failures += !expect_rc("apr.mapEnd.no-active", (int)sceAmprAprCommandBufferMapEnd(&aprMapNeg), SCE_KERNEL_ERROR_EPERM);
    failures += !expect_rc("apr.mapBegin.size0",
                           (int)sceAmprAprCommandBufferMapBegin(
                               &aprMapNeg,
                               0x300000,
                               0,
                               SCE_KERNEL_MTYPE_C_SHARED,
                               SCE_KERNEL_PROT_CPU_RW | SCE_KERNEL_PROT_AMPR_RW),
                           SCE_KERNEL_ERROR_EINVAL);
    failures += !expect_rc("apr.mapBegin.misaligned",
                           (int)sceAmprAprCommandBufferMapBegin(
                               &aprMapNeg,
                               0x300001,
                               PAGE_SIZE,
                               SCE_KERNEL_MTYPE_C_SHARED,
                               SCE_KERNEL_PROT_CPU_RW | SCE_KERNEL_PROT_AMPR_RW),
                           SCE_KERNEL_ERROR_EINVAL);
    failures += !expect_rc("apr.mapDirectBegin.misaligned-dmem",
                           (int)sceAmprAprCommandBufferMapDirectBegin(
                               &aprMapNeg,
                               0x300000,
                               1,
                               PAGE_SIZE,
                               SCE_KERNEL_MTYPE_C_SHARED,
                               SCE_KERNEL_PROT_CPU_RW | SCE_KERNEL_PROT_AMPR_RW),
                           SCE_KERNEL_ERROR_EINVAL);
    failures += !expect_rc("apr.mapBegin.valid",
                           (int)sceAmprAprCommandBufferMapBegin(
                               &aprMapNeg,
                               0x300000,
                               PAGE_SIZE,
                               SCE_KERNEL_MTYPE_C_SHARED,
                               SCE_KERNEL_PROT_CPU_RW | SCE_KERNEL_PROT_AMPR_RW),
                           0);
    failures += !expect_rc("apr.mapBegin.nested",
                           (int)sceAmprAprCommandBufferMapBegin(
                               &aprMapNeg,
                               0x310000,
                               PAGE_SIZE,
                               SCE_KERNEL_MTYPE_C_SHARED,
                               SCE_KERNEL_PROT_CPU_RW | SCE_KERNEL_PROT_AMPR_RW),
                           SCE_KERNEL_ERROR_EPERM);
    volatile uint64_t mapCompletion = 0;
    failures += !expect_rc("apr.writeCounterOnCompletion.in-map", aprMapNeg.writeCounterOnCompletion(1, 1), SCE_KERNEL_ERROR_EPERM);
    failures += !expect_rc("apr.writeAddressFromCounterOnCompletion.in-map",
                           aprMapNeg.writeAddressFromCounterOnCompletion(&mapCompletion, 1),
                           SCE_KERNEL_ERROR_EPERM);
    failures += !expect_rc("apr.mapEnd.valid", (int)sceAmprAprCommandBufferMapEnd(&aprMapNeg), 0);

    AprCommandBuffer apr{};
    failures += !expect_rc("apr.setBuffer", apr.setBuffer(aligned.ptr, 4096), 0);
    SceAprResultBuffer aprResult{};
    SceAprSubmitId aprId{};
    failures += !expect_rc("Apr::submit(empty)", Apr::submitCommandBufferAndGetResult(&apr, Apr::Priority::kPriority1, &aprResult, &aprId), SCE_KERNEL_ERROR_EINVAL);
    failures += !expect_rc("lk Apr::submit_id(empty prio=0)", sceKernelAprSubmitCommandBufferAndGetId(&apr, 0, &aprId), SCE_KERNEL_ERROR_EINVAL);
    failures += !expect_rc("apr.nop(priority0-valid)", apr.nop(1), 0);
    aprResult = {};
    aprId = 0;
    failures += !expect_rc("Apr::submit(prio=0)",
                           Apr::submitCommandBufferAndGetResult(&apr,
                                                                Apr::Priority::kPriority0,
                                                                &aprResult,
                                                                &aprId),
                           0);
    failures += !expect_rc("Apr::wait(prio=0)", Apr::waitCommandBufferCompletion(aprId), 0);
    failures += !expect_rc("Apr::result(prio=0)", aprResult.result, 0);
    failures += !expect_rc("Apr::submit(prio=99)",
                           Apr::submitCommandBufferAndGetResult(&apr,
                                                                static_cast<Apr::Priority>(99),
                                                                &aprResult,
                                                                &aprId),
                           SCE_KERNEL_ERROR_EINVAL);
    failures += !expect_rc("apr.reset(priority-range)", apr.reset(), 0);
    failures += !expect_rc("apr.nop(lk priority0-valid)", apr.nop(1), 0);
    aprId = 0;
    failures += !expect_rc("lk Apr::submit_id(prio=0)", sceKernelAprSubmitCommandBufferAndGetId(&apr, 0, &aprId), 0);
    failures += !expect_rc("lk Apr::wait(prio=0)", Apr::waitCommandBufferCompletion(aprId), 0);
    failures += !expect_rc("lk Apr::submit_id(prio=99)", sceKernelAprSubmitCommandBufferAndGetId(&apr, 99, &aprId), SCE_KERNEL_ERROR_EINVAL);

    SceAprFileId ids[1]{};
    uint32_t errorIndex = 0;
    static constexpr uint32_t kAprResolveTooMany = SCE_AMPR_APR_RESOLVE_MAX + 1u;
    static const char* tooManyPaths[kAprResolveTooMany]{};
    static const char* tooManyPrefixPaths[kAprResolveTooMany]{};
    static SceAprFileId tooManyIds[kAprResolveTooMany]{};
    static size_t tooManyFileSizes[kAprResolveTooMany]{};
    static int tooManyResults[kAprResolveTooMany]{};
    for (uint32_t i = 0; i < kAprResolveTooMany; ++i) {
        tooManyPaths[i] = "/app0/__ampr_missing__.bin";
        tooManyPrefixPaths[i] = "__ampr_missing__.bin";
    }
    failures += !expect_rc("Apr::resolveFilepathsToIds(num=0)",
                           Apr::resolveFilepathsToIds(tooManyPaths, 0, tooManyIds, &errorIndex),
                           SCE_KERNEL_ERROR_EINVAL);
    failures += !expect_rc("Apr::resolveFilepathsToIds(num=max+1)",
                           Apr::resolveFilepathsToIds(tooManyPaths, kAprResolveTooMany, tooManyIds, &errorIndex),
                           SCE_KERNEL_ERROR_EINVAL);
    failures += !expect_rc("Apr::resolveFilepathsToIdsAndFileSizes(num=0)",
                           Apr::resolveFilepathsToIdsAndFileSizes(tooManyPaths, 0, tooManyIds, tooManyFileSizes, &errorIndex),
                           SCE_KERNEL_ERROR_EINVAL);
    failures += !expect_rc("Apr::resolveFilepathsToIdsAndFileSizes(num=max+1)",
                           Apr::resolveFilepathsToIdsAndFileSizes(tooManyPaths, kAprResolveTooMany, tooManyIds, tooManyFileSizes, &errorIndex),
                           SCE_KERNEL_ERROR_EINVAL);
    failures += !expect_rc("Apr::resolveFilepathsWithPrefixToIds(num=0)",
                           Apr::resolveFilepathsWithPrefixToIds("/app0", tooManyPrefixPaths, 0, tooManyIds, &errorIndex),
                           SCE_KERNEL_ERROR_EINVAL);
    failures += !expect_rc("Apr::resolveFilepathsWithPrefixToIds(num=max+1)",
                           Apr::resolveFilepathsWithPrefixToIds("/app0", tooManyPrefixPaths, kAprResolveTooMany, tooManyIds, &errorIndex),
                           SCE_KERNEL_ERROR_EINVAL);
    failures += !expect_rc("Apr::resolveFilepathsWithPrefixToIdsAndFileSizes(num=0)",
                           Apr::resolveFilepathsWithPrefixToIdsAndFileSizes("/app0", tooManyPrefixPaths, 0, tooManyIds, tooManyFileSizes, &errorIndex),
                           SCE_KERNEL_ERROR_EINVAL);
    failures += !expect_rc("Apr::resolveFilepathsWithPrefixToIdsAndFileSizes(num=max+1)",
                           Apr::resolveFilepathsWithPrefixToIdsAndFileSizes("/app0", tooManyPrefixPaths, kAprResolveTooMany, tooManyIds, tooManyFileSizes, &errorIndex),
                           SCE_KERNEL_ERROR_EINVAL);
    failures += !expect_rc("Apr::resolveFilepathsToIdsForEach(num=0)",
                           Apr::resolveFilepathsToIdsForEach(tooManyPaths, 0, tooManyIds, tooManyResults),
                           SCE_KERNEL_ERROR_EINVAL);
    failures += !expect_rc("Apr::resolveFilepathsToIdsForEach(num=max+1)",
                           Apr::resolveFilepathsToIdsForEach(tooManyPaths, kAprResolveTooMany, tooManyIds, tooManyResults),
                           SCE_KERNEL_ERROR_EINVAL);
    failures += !expect_rc("Apr::resolveFilepathsToIdsAndFileSizesForEach(num=0)",
                           Apr::resolveFilepathsToIdsAndFileSizesForEach(tooManyPaths, 0, tooManyIds, tooManyFileSizes, tooManyResults),
                           SCE_KERNEL_ERROR_EINVAL);
    failures += !expect_rc("Apr::resolveFilepathsToIdsAndFileSizesForEach(num=max+1)",
                           Apr::resolveFilepathsToIdsAndFileSizesForEach(tooManyPaths, kAprResolveTooMany, tooManyIds, tooManyFileSizes, tooManyResults),
                           SCE_KERNEL_ERROR_EINVAL);
    failures += !expect_rc("Apr::resolveFilepathsWithPrefixToIdsForEach(num=0)",
                           Apr::resolveFilepathsWithPrefixToIdsForEach("/app0", tooManyPrefixPaths, 0, tooManyIds, tooManyResults),
                           SCE_KERNEL_ERROR_EINVAL);
    failures += !expect_rc("Apr::resolveFilepathsWithPrefixToIdsForEach(num=max+1)",
                           Apr::resolveFilepathsWithPrefixToIdsForEach("/app0", tooManyPrefixPaths, kAprResolveTooMany, tooManyIds, tooManyResults),
                           SCE_KERNEL_ERROR_EINVAL);
    failures += !expect_rc("Apr::resolveFilepathsWithPrefixToIdsAndFileSizesForEach(num=0)",
                           Apr::resolveFilepathsWithPrefixToIdsAndFileSizesForEach("/app0", tooManyPrefixPaths, 0, tooManyIds, tooManyFileSizes, tooManyResults),
                           SCE_KERNEL_ERROR_EINVAL);
    failures += !expect_rc("Apr::resolveFilepathsWithPrefixToIdsAndFileSizesForEach(num=max+1)",
                           Apr::resolveFilepathsWithPrefixToIdsAndFileSizesForEach("/app0", tooManyPrefixPaths, kAprResolveTooMany, tooManyIds, tooManyFileSizes, tooManyResults),
                           SCE_KERNEL_ERROR_EINVAL);

    failures += !expect_rc("Apr::resolveFilepathsToIds(null)", Apr::resolveFilepathsToIds(nullptr, 1, ids, &errorIndex), SCE_KERNEL_ERROR_EFAULT);
    const char* nullPaths[1]{nullptr};
    const char* prefixPaths[1]{"__ampr_missing__.bin"};
    const char* relativePaths[1]{"__ampr_missing__.bin"};
    static char tooLongPath[SCE_KERNEL_PATH_MAX + 64]{};
    tooLongPath[0] = '/';
    tooLongPath[1] = 'a';
    tooLongPath[2] = 'p';
    tooLongPath[3] = 'p';
    tooLongPath[4] = '0';
    tooLongPath[5] = '/';
    for (size_t i = 6; i < sizeof(tooLongPath) - 1u; ++i) {
        tooLongPath[i] = 'a';
    }
    tooLongPath[sizeof(tooLongPath) - 1u] = '\0';
    const char* tooLongPaths[1]{tooLongPath};
    size_t fileSizes[1]{};
    int results[1]{};
    failures += !expect_rc("Apr::resolveFilepathsToIds(relative)",
                           Apr::resolveFilepathsToIds(relativePaths, 1, ids, &errorIndex),
                           SCE_KERNEL_ERROR_EINVAL);
    failures += !expect_rc("Apr::resolveFilepathsToIds(too long)",
                           Apr::resolveFilepathsToIds(tooLongPaths, 1, ids, &errorIndex),
                           SCE_KERNEL_ERROR_ENAMETOOLONG);
    failures += !expect_rc("Apr::resolveFilepathsWithPrefixToIds(null prefix)",
                           Apr::resolveFilepathsWithPrefixToIds(nullptr, prefixPaths, 1, ids, &errorIndex),
                           SCE_KERNEL_ERROR_EFAULT);
    errorIndex = 0xBEEFu;
    failures += !expect_rc("Apr::resolveFilepathsWithPrefixToIds(null item)",
                           Apr::resolveFilepathsWithPrefixToIds("/app0", nullPaths, 1, ids, &errorIndex),
                           SCE_KERNEL_ERROR_EFAULT);
    failures += !expect_rc("Apr::resolveFilepathsWithPrefixToIds(null item errorIndex)", static_cast<int>(errorIndex), static_cast<int>(0xBEEFu));
    errorIndex = 0xBEEFu;
    failures += !expect_rc("Apr::resolveFilepathsWithPrefixToIdsAndFileSizes(null item)",
                           Apr::resolveFilepathsWithPrefixToIdsAndFileSizes("/app0", nullPaths, 1, ids, fileSizes, &errorIndex),
                           SCE_KERNEL_ERROR_EFAULT);
    failures += !expect_rc("Apr::resolveFilepathsWithPrefixToIdsAndFileSizes(null item errorIndex)", static_cast<int>(errorIndex), static_cast<int>(0xBEEFu));
    results[0] = 0;
    ids[0] = 0xDEADu;
    failures += !expect_rc("Apr::resolveFilepathsWithPrefixToIdsForEach(null item)",
                           Apr::resolveFilepathsWithPrefixToIdsForEach("/app0", nullPaths, 1, ids, results),
                           SCE_KERNEL_ERROR_EFAULT);
    results[0] = 0;
    ids[0] = 0xDEADu;
    fileSizes[0] = 0xBEEFu;
    failures += !expect_rc("Apr::resolveFilepathsWithPrefixToIdsAndFileSizesForEach(null item)",
                           Apr::resolveFilepathsWithPrefixToIdsAndFileSizesForEach("/app0", nullPaths, 1, ids, fileSizes, results),
                           SCE_KERNEL_ERROR_EFAULT);

    size_t invalidFileSize = 0xBEEFu;
    SceKernelStat invalidFileStat{};
    failures += !expect_rc("Apr::getFileSize(fileId=0)",
                           Apr::getFileSize(static_cast<SceAprFileId>(0), &invalidFileSize),
                           SCE_KERNEL_ERROR_ENOENT);
    failures += !expect_rc("Apr::getFileSize(fileId=invalid)",
                           Apr::getFileSize(SCE_AMPR_APR_FILEID_INVALID, &invalidFileSize),
                           SCE_KERNEL_ERROR_ENOENT);
    failures += !expect_rc("Apr::getFileStat(fileId=invalid)",
                           Apr::getFileStat(SCE_AMPR_APR_FILEID_INVALID, &invalidFileStat),
                           SCE_KERNEL_ERROR_ENOENT);

    ScopedAlignedBuffer aprWaitBuf(4096);
    failures += !expect_true("apr wait buffer alloc", aprWaitBuf.ptr != nullptr);
    if (aprWaitBuf.ptr) {
        AprCommandBuffer aprWait{};
        failures += !expect_rc("aprWait.setBuffer", aprWait.setBuffer(aprWaitBuf.ptr, 4096), 0);

        ScopedAlignedBuffer nativeCompletionReadBuf(4096);
        failures += !expect_true("native completion read buffer alloc",
                                 nativeCompletionReadBuf.ptr != nullptr);
        const char* nativeCompletionPaths[] = {"/app0/eboot.bin"};
        SceAprFileId nativeCompletionFileId = SCE_AMPR_APR_FILEID_INVALID;
        uint32_t nativeCompletionErrorIndex = UINT32_MAX;
        failures += !expect_rc("Apr::resolve(native completion source)",
                               Apr::resolveFilepathsToIds(nativeCompletionPaths,
                                                          1,
                                                          &nativeCompletionFileId,
                                                          &nativeCompletionErrorIndex),
                               0);
        if (nativeCompletionReadBuf.ptr &&
            nativeCompletionFileId != SCE_AMPR_APR_FILEID_INVALID) {
            volatile uint64_t nativeCompletionStamp = 0;
            failures += !expect_rc("aprWait.readFile(native completion)",
                                   aprWait.readFile(nativeCompletionFileId,
                                                    nativeCompletionReadBuf.ptr,
                                                    8,
                                                    0),
                                   0);
            failures += !expect_rc("aprWait.writeAddressOnCompletion(native)",
                                   aprWait.writeAddressOnCompletion(&nativeCompletionStamp,
                                                                    0xA55A5AA5u),
                                   0);
            SceAprResultBuffer nativeCompletionResult{};
            SceAprSubmitId nativeCompletionId{};
            failures += !expect_rc("Apr::submit(native completion)",
                                   Apr::submitCommandBufferAndGetResult(
                                       &aprWait,
                                       Apr::Priority::kPriority1,
                                       &nativeCompletionResult,
                                       &nativeCompletionId),
                                   0);
            failures += !expect_rc("Apr::wait(native completion)",
                                   Apr::waitCommandBufferCompletion(nativeCompletionId),
                                   0);
            failures += !expect_rc("Apr::result(native completion)",
                                   nativeCompletionResult.result,
                                   0);
            failures += !expect_true("aprWait.native completion published",
                                     nativeCompletionStamp == 0xA55A5AA5u);
            failures += !expect_rc("aprWait.reset(after native completion)",
                                   aprWait.reset(),
                                   0);

            ScopedAlignedBuffer gsHeadCommands(4096);
            ScopedAlignedBuffer gsTailCommands(4096);
            ScopedAlignedBuffer gsReferenceCommands(4096);
            ScopedAlignedBuffer gsOutput(4096);
            ScopedAlignedBuffer gsReference(4096);
            failures += !expect_true("cross-buffer gather allocations",
                                     gsHeadCommands.ptr && gsTailCommands.ptr &&
                                         gsReferenceCommands.ptr && gsOutput.ptr &&
                                         gsReference.ptr);
            if (gsHeadCommands.ptr && gsTailCommands.ptr &&
                gsReferenceCommands.ptr && gsOutput.ptr && gsReference.ptr) {
                AprCommandBuffer gsHead{};
                AprCommandBuffer gsTail{};
                AprCommandBuffer gsReferenceRead{};
                failures += !expect_rc("gsHead.setBuffer",
                                       gsHead.setBuffer(gsHeadCommands.ptr, 4096),
                                       0);
                failures += !expect_rc("gsTail.setBuffer",
                                       gsTail.setBuffer(gsTailCommands.ptr, 4096),
                                       0);
                failures += !expect_rc("gsReference.setBuffer",
                                       gsReferenceRead.setBuffer(gsReferenceCommands.ptr, 4096),
                                       0);
                failures += !expect_rc("gsHead.readFile",
                                       gsHead.readFile(nativeCompletionFileId,
                                                       gsOutput.ptr,
                                                       8,
                                                       0),
                                       0);
                failures += !expect_rc("gsTail.readFileGather(cross-buffer)",
                                       gsTail.readFileGather(8, 8),
                                       0);
                failures += !expect_rc("gsTail.resetGatherScatterState",
                                       gsTail.resetGatherScatterState(),
                                       0);
                failures += !expect_rc("gsReference.readFile",
                                       gsReferenceRead.readFile(nativeCompletionFileId,
                                                                gsReference.ptr,
                                                                16,
                                                                0),
                                       0);
                SceAprResultBuffer gsHeadResult{};
                SceAprResultBuffer gsTailResult{};
                SceAprResultBuffer gsReferenceResult{};
                SceAprSubmitId gsHeadId{};
                SceAprSubmitId gsTailId{};
                SceAprSubmitId gsReferenceId{};
                failures += !expect_rc("Apr::submit(gs head)",
                                       Apr::submitCommandBufferAndGetResult(
                                           &gsHead,
                                           Apr::Priority::kPriority2,
                                           &gsHeadResult,
                                           &gsHeadId),
                                       0);
                failures += !expect_rc("Apr::submit(gs tail)",
                                       Apr::submitCommandBufferAndGetResult(
                                           &gsTail,
                                           Apr::Priority::kPriority2,
                                           &gsTailResult,
                                           &gsTailId),
                                       0);
                failures += !expect_rc("Apr::submit(gs reference)",
                                       Apr::submitCommandBufferAndGetResult(
                                           &gsReferenceRead,
                                           Apr::Priority::kPriority3,
                                           &gsReferenceResult,
                                           &gsReferenceId),
                                       0);
                failures += !expect_rc("Apr::wait(gs head)",
                                       Apr::waitCommandBufferCompletion(gsHeadId),
                                       0);
                failures += !expect_rc("Apr::wait(gs tail)",
                                       Apr::waitCommandBufferCompletion(gsTailId),
                                       0);
                failures += !expect_rc("Apr::wait(gs reference)",
                                       Apr::waitCommandBufferCompletion(gsReferenceId),
                                       0);
                failures += !expect_rc("Apr::result(gs head)", gsHeadResult.result, 0);
                failures += !expect_rc("Apr::result(gs tail)", gsTailResult.result, 0);
                failures += !expect_rc("Apr::result(gs reference)",
                                       gsReferenceResult.result,
                                       0);
                failures += !expect_true("cross-buffer gather data",
                                         std::memcmp(gsOutput.ptr,
                                                     gsReference.ptr,
                                                     16) == 0);
            }
        }

        ScopedAlignedBuffer activeRebindBuf(4096);
        failures += !expect_true("active rebind buffer alloc",
                                 activeRebindBuf.ptr != nullptr);
        volatile uint64_t activeDetachGate = 0;
        failures += !expect_rc("aprWait.waitOnAddress(active detach)",
                               aprWait.waitOnAddress(&activeDetachGate,
                                                     1,
                                                     WaitCompare::kEqual,
                                                     WaitFlush::kDisable),
                               0);
        SceAprResultBuffer activeDetachResult{};
        SceAprSubmitId activeDetachId{};
        SceAprResultBuffer activeResubmitResult{};
        SceAprSubmitId activeResubmitId{};
        failures += !expect_rc("Apr::submit(active detach)",
                               Apr::submitCommandBufferAndGetResult(
                                   &aprWait,
                                   Apr::Priority::kPriority1,
                                   &activeDetachResult,
                                   &activeDetachId),
                               0);
        failures += !expect_rc("Apr::submit(active same-buffer resubmit)",
                               Apr::submitCommandBufferAndGetResult(
                                   &aprWait,
                                   Apr::Priority::kPriority1,
                                   &activeResubmitResult,
                                   &activeResubmitId),
                               0);
        failures += !expect_true("Apr::submit(active same-buffer distinct ids)",
                                 activeDetachId != activeResubmitId);
        failures += !expect_rc("aprWait.reset(active source retained)",
                               aprWait.reset(),
                               0);
        failures += !expect_true("aprWait.reset(active recording cleared)",
                                 aprWait.getCurrentOffset() == 0 &&
                                     aprWait.getNumCommands() == 0);
        failures += !expect_true("aprWait.clearBuffer(active source retained)",
                                 aprWait.clearBuffer() == aprWaitBuf.ptr);
        failures += !expect_rc("aprWait.setBuffer(active source retained)",
                               aprWait.setBuffer(activeRebindBuf.ptr, 4096),
                               0);
        activeDetachGate = 1;
        failures += !expect_rc("Apr::wait(active detach)",
                               Apr::waitCommandBufferCompletion(activeDetachId),
                               0);
        failures += !expect_rc("Apr::wait(active same-buffer resubmit)",
                               Apr::waitCommandBufferCompletion(activeResubmitId),
                               0);
        failures += !expect_rc("Apr::result(active detach)",
                               activeDetachResult.result,
                               0);
        failures += !expect_rc("Apr::result(active same-buffer resubmit)",
                               activeResubmitResult.result,
                               0);
        failures += !expect_true("aprWait.clearBuffer(active rebind)",
                                 aprWait.clearBuffer() == activeRebindBuf.ptr);
        failures += !expect_rc("aprWait.setBuffer(after active detach)",
                               aprWait.setBuffer(aprWaitBuf.ptr, 4096),
                               0);

        const uint32_t unavailableReadOffset = aprWait.getCurrentOffset();
        failures += !expect_rc("aprWait.readFile(invalid)", aprWait.readFile((SceAprFileId)0xDEADu, aprWaitBuf.ptr, 16, 0), 0);
        SceAprResultBuffer unavailableResult{};
        SceAprSubmitId waitId{};
        failures += !expect_rc("Apr::submit(unavailable file id)",
                               Apr::submitCommandBufferAndGetResult(
                                   &aprWait,
                                   Apr::Priority::kPriority1,
                                   &unavailableResult,
                                   &waitId),
                               0);
        failures += !expect_true("Apr::submit(unavailable file id synthetic id)",
                                 (static_cast<uint32_t>(waitId) & 0xFF000000u) ==
                                     0xA5000000u);
        SceAprSubmitId repeatId = 0;
        failures += !expect_rc("Apr::submit(repeat while active)",
                               Apr::submitCommandBuffer(
                                   &aprWait,
                                   Apr::Priority::kPriority1,
                                   &repeatId),
                               0);
        failures += !expect_rc("Apr::wait(unavailable file id)",
                               Apr::waitCommandBufferCompletion(waitId),
                               0);
        failures += !expect_rc("Apr::wait(repeat unavailable file id)",
                               Apr::waitCommandBufferCompletion(repeatId),
                               0);
        failures += !expect_rc("Apr::result(unavailable file id)",
                               unavailableResult.result,
                               SCE_AMPR_ERROR_APR_UNAVAILABLEFILEID);
        failures += !expect_true("Apr::errorOffset(unavailable file id)",
                                 unavailableResult.errorOffset == unavailableReadOffset);
        failures += !expect_rc("aprWait.readFile(after active detach)",
                               aprWait.readFile((SceAprFileId)0xDEADu,
                                                static_cast<unsigned char*>(aprWaitBuf.ptr) + 0x100,
                                                16,
                                                0),
                               0);
        SceAprResultBuffer extendedResult{};
        SceAprSubmitId extendedId{};
        failures += !expect_rc("Apr::submit(extended after wait)",
                               Apr::submitCommandBufferAndGetResult(
                                   &aprWait,
                                   Apr::Priority::kPriority1,
                                   &extendedResult,
                                   &extendedId),
                               0);
        failures += !expect_rc("Apr::wait(extended unavailable file id)",
                               Apr::waitCommandBufferCompletion(extendedId),
                               0);
        failures += !expect_rc("Apr::result(extended unavailable file id)",
                               extendedResult.result,
                               SCE_AMPR_ERROR_APR_UNAVAILABLEFILEID);

        volatile uint64_t betweenReadsCompletion = 0;
        failures += !expect_rc("aprWait.reset(before reactor completion write)", aprWait.reset(), 0);
        failures += !expect_rc("aprWait.readFile(before reactor completion write)",
                               aprWait.readFile((SceAprFileId)0xDEADu, aprWaitBuf.ptr, 16, 0),
                               0);
        failures += !expect_rc("aprWait.writeAddressOnCompletion(between reads)",
                               aprWait.writeAddressOnCompletion(&betweenReadsCompletion,
                                                                0x12345678u),
                               0);
        failures += !expect_rc("aprWait.readFile(after reactor completion write)",
                               aprWait.readFile((SceAprFileId)0xDEADu,
                                                static_cast<unsigned char*>(aprWaitBuf.ptr) + 0x100,
                                                16,
                                                0),
                               0);
        SceAprResultBuffer inlineWriteResult{};
        SceAprSubmitId inlineWriteId{};
        failures += !expect_rc("Apr::submit(reactor completion write)",
                               Apr::submitCommandBufferAndGetResult(
                                   &aprWait,
                                   Apr::Priority::kPriority1,
                                   &inlineWriteResult,
                                   &inlineWriteId),
                               0);
        failures += !expect_rc("Apr::wait(reactor completion write)",
                               Apr::waitCommandBufferCompletion(inlineWriteId),
                               0);
        failures += !expect_rc("Apr::result(reactor completion write)",
                               inlineWriteResult.result,
                               SCE_AMPR_ERROR_APR_UNAVAILABLEFILEID);
        failures += !expect_true("aprWait.aborted completion write between reads",
                                 betweenReadsCompletion == 0);

        failures += !expect_rc("aprWait.reset(before invalid zero file id)", aprWait.reset(), 0);
        ScopedAlignedBuffer zeroIdReadBuffer(0x1000);
        failures += !expect_true("invalid zero file id buffer alloc", zeroIdReadBuffer.ptr != nullptr);
        if (zeroIdReadBuffer.ptr) {
            auto* zeroIdDestination = static_cast<volatile uint64_t*>(zeroIdReadBuffer.ptr);
            *zeroIdDestination = 0xABCDEF0123456789ull;
            failures += !expect_rc("aprWait.readFile(invalid zero file id)",
                                   aprWait.readFile((SceAprFileId)0,
                                                    zeroIdReadBuffer.ptr,
                                                    16,
                                                    0),
                                   0);
            failures += !expect_rc("aprWait.readFile(after invalid zero file id)",
                                   aprWait.readFile(
                                       (SceAprFileId)0xDEADu,
                                       static_cast<unsigned char*>(zeroIdReadBuffer.ptr) + 0x100,
                                       16,
                                       0),
                                   0);
            SceAprResultBuffer zeroFileIdResult{};
            SceAprSubmitId zeroFileId{};
            failures += !expect_rc("Apr::submit(invalid zero file id)",
                                   Apr::submitCommandBufferAndGetResult(
                                       &aprWait,
                                       Apr::Priority::kPriority1,
                                       &zeroFileIdResult,
                                       &zeroFileId),
                                   0);
            failures += !expect_rc("Apr::wait(invalid zero file id)",
                                   Apr::waitCommandBufferCompletion(zeroFileId),
                                   0);
            failures += !expect_rc("Apr::result(invalid zero file id)",
                                   zeroFileIdResult.result,
                                   SCE_AMPR_ERROR_APR_INVALIDFILEID);
            failures += !expect_true("aprWait.invalid zero file id preserves destination",
                                     *zeroIdDestination == 0xABCDEF0123456789ull);
        }

        volatile uint64_t terminalCompletion = 0;
        failures += !expect_rc("aprWait.reset(before terminal completion write)", aprWait.reset(), 0);
        failures += !expect_rc("aprWait.readFile(before terminal completion write)",
                               aprWait.readFile((SceAprFileId)0xDEADu, aprWaitBuf.ptr, 16, 0),
                               0);
        failures += !expect_rc("aprWait.writeAddressOnCompletion(terminal)",
                               aprWait.writeAddressOnCompletion(&terminalCompletion, 0x87654321u),
                               0);
        SceAprResultBuffer terminalWriteResult{};
        SceAprSubmitId terminalWriteId{};
        failures += !expect_rc("Apr::submit(terminal completion write)",
                               Apr::submitCommandBufferAndGetResult(
                                   &aprWait,
                                   Apr::Priority::kPriority1,
                                   &terminalWriteResult,
                                   &terminalWriteId),
                               0);
        failures += !expect_rc("Apr::wait(terminal completion write)",
                               Apr::waitCommandBufferCompletion(terminalWriteId),
                               0);
        failures += !expect_rc("Apr::result(terminal completion write)",
                               terminalWriteResult.result,
                               SCE_AMPR_ERROR_APR_UNAVAILABLEFILEID);
        failures += !expect_true("aprWait.aborted terminal completion write",
                                 terminalCompletion == 0);

        volatile uint64_t laterBarrierCompletion = 0;
        failures += !expect_rc("aprWait.reset(before failed later barrier)", aprWait.reset(), 0);
        failures += !expect_rc("aprWait.readFile(failed first barrier)",
                               aprWait.readFile((SceAprFileId)0xDEADu, aprWaitBuf.ptr, 16, 0),
                               0);
        failures += !expect_rc("aprWait.nop(between failed barriers)", aprWait.nop(1), 0);
        failures += !expect_rc("aprWait.readFile(failed later barrier)",
                               aprWait.readFile((SceAprFileId)0xDEADu,
                                                static_cast<unsigned char*>(aprWaitBuf.ptr) + 0x100,
                                                16,
                                                0),
                               0);
        failures += !expect_rc("aprWait.writeAddressOnCompletion(failed later barrier)",
                               aprWait.writeAddressOnCompletion(&laterBarrierCompletion,
                                                                0xCAFEBABEu),
                               0);
        SceAprResultBuffer laterBarrierResult{};
        SceAprSubmitId laterBarrierId{};
        failures += !expect_rc("Apr::submit(failed later barrier)",
                               Apr::submitCommandBufferAndGetResult(
                                   &aprWait,
                                   Apr::Priority::kPriority1,
                                   &laterBarrierResult,
                                   &laterBarrierId),
                               0);
        failures += !expect_rc("Apr::wait(failed later barrier)",
                               Apr::waitCommandBufferCompletion(laterBarrierId),
                               0);
        failures += !expect_rc("Apr::result(failed later barrier)",
                               laterBarrierResult.result,
                               SCE_AMPR_ERROR_APR_UNAVAILABLEFILEID);
        failures += !expect_true("aprWait.aborted later barrier completion write",
                                 laterBarrierCompletion == 0);

        volatile uint64_t failedReadSuffixWrite = 0;
        failures += !expect_rc("aprWait.reset(before same-segment suffix abort)",
                               aprWait.reset(),
                               0);
        failures += !expect_rc("aprWait.readFile(before same-segment suffix abort)",
                               aprWait.readFile((SceAprFileId)0xDEADu,
                                                aprWaitBuf.ptr,
                                                16,
                                                0),
                               0);
        failures += !expect_rc("aprWait.writeAddressImmediately(after failed read)",
                               aprWait.writeAddressImmediately(&failedReadSuffixWrite,
                                                               0x10203040u),
                               0);
        SceAprResultBuffer failedReadSuffixResult{};
        SceAprSubmitId failedReadSuffixId{};
        failures += !expect_rc("Apr::submit(same-segment suffix abort)",
                               Apr::submitCommandBufferAndGetResult(
                                   &aprWait,
                                   Apr::Priority::kPriority1,
                                   &failedReadSuffixResult,
                                   &failedReadSuffixId),
                               0);
        failures += !expect_rc("Apr::wait(same-segment suffix abort)",
                               Apr::waitCommandBufferCompletion(failedReadSuffixId),
                               0);
        failures += !expect_rc("Apr::result(same-segment suffix abort)",
                               failedReadSuffixResult.result,
                               SCE_AMPR_ERROR_APR_UNAVAILABLEFILEID);
        failures += !expect_true("aprWait.same-segment suffix not executed",
                                 failedReadSuffixWrite == 0);

        failures += !expect_rc("aprWait.reset(before native error completion)",
                               aprWait.reset(),
                               0);
        const uint32_t nativeWriteErrorOffset = aprWait.getCurrentOffset();
        failures += !expect_rc("aprWait.writeAddressImmediately(unmapped)",
                               aprWait.writeAddressImmediately(
                                   reinterpret_cast<volatile uint64_t*>(0x1000),
                                   0x55667788u),
                               0);
        failures += !expect_rc("aprWait.readFile(after native error)",
                               aprWait.readFile((SceAprFileId)0xDEADu,
                                                aprWaitBuf.ptr,
                                                16,
                                                0),
                               0);
        SceAprResultBuffer nativeWriteErrorResult{};
        SceAprSubmitId nativeWriteErrorId{};
        failures += !expect_rc("Apr::submit(native error before read barrier)",
                               Apr::submitCommandBufferAndGetResult(
                                   &aprWait,
                                   Apr::Priority::kPriority1,
                                   &nativeWriteErrorResult,
                                   &nativeWriteErrorId),
                               0);
        failures += !expect_rc("Apr::wait(native error before read barrier)",
                               Apr::waitCommandBufferCompletion(nativeWriteErrorId),
                               0);
        failures += !expect_rc("Apr::result(native error before read barrier)",
                               nativeWriteErrorResult.result,
                               SCE_AMPR_ERROR_APR_MEMORYFAULTWRITEBUFFERADDRESS);
        failures += !expect_true("Apr::errorOffset(native error before read barrier)",
                                 nativeWriteErrorResult.errorOffset == nativeWriteErrorOffset);

        volatile uint64_t waitFlushWord = 1;
        volatile uint64_t waitFlushSuffixWrite = 0;
        failures += !expect_rc("aprWait.reset(before WaitFlush abort)", aprWait.reset(), 0);
        failures += !expect_rc("aprWait.readFile(before WaitFlush abort)",
                               aprWait.readFile((SceAprFileId)0xDEADu,
                                                aprWaitBuf.ptr,
                                                16,
                                                0),
                               0);
        failures += !expect_rc("aprWait.waitOnAddress(WaitFlush boundary)",
                               aprWait.waitOnAddress(&waitFlushWord,
                                                     1,
                                                     WaitCompare::kEqual,
                                                     WaitFlush::kEnable),
                               0);
        failures += !expect_rc("aprWait.writeAddressImmediately(after WaitFlush)",
                               aprWait.writeAddressImmediately(&waitFlushSuffixWrite,
                                                               0x11223344u),
                               0);
        SceAprResultBuffer waitFlushResult{};
        SceAprSubmitId waitFlushId{};
        failures += !expect_rc("Apr::submit(WaitFlush abort)",
                               Apr::submitCommandBufferAndGetResult(
                                   &aprWait,
                                   Apr::Priority::kPriority1,
                                   &waitFlushResult,
                                   &waitFlushId),
                               0);
        failures += !expect_true("Apr::submit(WaitFlush synthetic id)",
                                 (static_cast<uint32_t>(waitFlushId) & 0xFF000000u) ==
                                     0xA5000000u);
        failures += !expect_rc("sceKernelAprWaitCommandBuffer(WaitFlush abort)",
                               sceKernelAprWaitCommandBuffer(waitFlushId),
                               0);
        failures += !expect_rc("Apr::result(WaitFlush abort)",
                               waitFlushResult.result,
                               SCE_AMPR_ERROR_APR_UNAVAILABLEFILEID);
        failures += !expect_true("aprWait.WaitFlush suffix not executed",
                                 waitFlushSuffixWrite == 0);

        waitFlushSuffixWrite = 0;
        volatile uint64_t secondWaitFlushSuffixWrite = 0;
        failures += !expect_rc("aprWait.reset(before same-submit WaitFlush suffix)", aprWait.reset(), 0);
        failures += !expect_rc("aprWait.resetGatherScatterState(before WaitFlush)",
                               aprWait.resetGatherScatterState(),
                               0);
        failures += !expect_rc("aprWait.waitOnAddress(first same-submit WaitFlush)",
                               aprWait.waitOnAddress(&waitFlushWord,
                                                     1,
                                                     WaitCompare::kEqual,
                                                     WaitFlush::kEnable),
                               0);
        failures += !expect_rc("aprWait.writeAddressImmediately(continued suffix)",
                               aprWait.writeAddressImmediately(&waitFlushSuffixWrite,
                                                               0x55667788u),
                               0);
        failures += !expect_rc("aprWait.waitOnAddress(second same-submit WaitFlush)",
                               aprWait.waitOnAddress(&waitFlushWord,
                                                     1,
                                                     WaitCompare::kEqual,
                                                     WaitFlush::kEnable),
                               0);
        failures += !expect_rc("aprWait.writeAddressImmediately(second continued suffix)",
                               aprWait.writeAddressImmediately(&secondWaitFlushSuffixWrite,
                                                               0x99AABBCCu),
                               0);
        SceAprResultBuffer waitFlushSameSubmitResult{};
        SceAprSubmitId waitFlushSameSubmitId{};
        failures += !expect_rc("Apr::submit(same-submit WaitFlush suffixes)",
                               Apr::submitCommandBufferAndGetResult(
                                   &aprWait,
                                   Apr::Priority::kPriority1,
                                   &waitFlushSameSubmitResult,
                                   &waitFlushSameSubmitId),
                               0);
        failures += !expect_true("Apr::submit(same-submit WaitFlush synthetic id)",
                                 (static_cast<uint32_t>(waitFlushSameSubmitId) & 0xFF000000u) ==
                                     0xA5000000u);
        failures += !expect_rc("Apr::wait(same-submit WaitFlush suffixes)",
                               Apr::waitCommandBufferCompletion(waitFlushSameSubmitId),
                               0);
        failures += !expect_rc("Apr::result(same-submit WaitFlush suffixes)",
                               waitFlushSameSubmitResult.result,
                               0);
        failures += !expect_true("aprWait.first WaitFlush suffix executed after refetch",
                                 waitFlushSuffixWrite == 0x55667788u);
        failures += !expect_true("aprWait.second WaitFlush suffix executed after refetch",
                                 secondWaitFlushSuffixWrite == 0x99AABBCCu);
    }

    off_t dmemOffset = 0;
    failures += !expect_rc("Amm::giveDirectMemory(size=0)", Amm::giveDirectMemory(0, 0, 0, 0, Amm::Usage::kAuto, &dmemOffset), SCE_KERNEL_ERROR_EINVAL);

    errno = 0;
    failures += !expect_rc("sceKernelAprCtrl_emul.noop", sceKernelAprCtrl_emul(0, nullptr, 0, nullptr, 0), 0);
    errno = 0;
    failures += !expect_rc("sceKernelAprCtrl_emul.unsupported", sceKernelAprCtrl_emul(1, nullptr, 0, nullptr, 0), -1);
    failures += !expect_rc("sceKernelAprCtrl_emul.unsupported.errno", errno, EINVAL);
    errno = 0;
    failures += !expect_rc("sceKernelAprCtrl_emul.bad-rsv", sceKernelAprCtrl_emul(0, nullptr, 0, raw, 0), -1);
    failures += !expect_rc("sceKernelAprCtrl_emul.bad-rsv.errno", errno, EINVAL);

    uint64_t counterValue = 0xBADC0FFEEull;
    failures += !expect_rc("sceKernelGetAmprCounter_emul.0", sceKernelGetAmprCounter_emul(0, &counterValue), 0);
    errno = 0;
    failures += !expect_rc("sceKernelGetAmprCounter_emul.null", sceKernelGetAmprCounter_emul(0, nullptr), -1);
    failures += !expect_rc("sceKernelGetAmprCounter_emul.null.errno", errno, EFAULT);
    errno = 0;
    failures += !expect_rc("sceKernelGetAmprCounter_emul.unsupported", sceKernelGetAmprCounter_emul(0x20000, &counterValue), -1);
    failures += !expect_rc("sceKernelGetAmprCounter_emul.unsupported.errno", errno, EINVAL);

    std::free(raw);
    std::printf("prospero_negtest failures=%d\n", failures);
    return failures == 0 ? 0 : 1;
}
