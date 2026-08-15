#include "prospero_test_common.h"

#include <cstdio>
#include <cstring>

using namespace sce::Ampr;

extern "C" {
int64_t sceAmprCommandBufferConstructor(CommandBuffer* cb);
int64_t sceAmprCommandBufferDestructor(CommandBuffer* cb);
int64_t sceAmprAprCommandBufferConstructor(
    AprCommandBuffer* cb,
    void* hiddenMapState,
    void* hiddenScatterGatherState);
int64_t sceAmprAprCommandBufferDestructor(
    AprCommandBuffer* cb,
    void* hiddenMapState,
    void* hiddenScatterGatherState);
int64_t sceAmprCommandBufferWaitOnCounter_04_00(
    CommandBuffer* cb,
    uint8_t counterIndex,
    uint8_t n8,
    uint64_t refValue,
    uint8_t compare,
    uint8_t legacyExtraFlag,
    uint64_t legacyExtraValue,
    uint8_t flush);
int64_t sceAmprCommandBufferWriteCounter_04_00(
    CommandBuffer* cb,
    uint8_t counterIndex,
    uint8_t n8,
    uint64_t value,
    uint8_t n5,
    uint8_t mode);
int64_t sceAmprCommandBufferWriteAddressFromCounterOnCompletion(
    CommandBuffer* cb,
    volatile uint64_t* address,
    uint8_t counterIndex);
int64_t sceAmprCommandBufferConstructNop(
    CommandBuffer* cb,
    int16_t nopType,
    const void* payload,
    uint32_t payloadSize,
    const uint32_t* optWord);
int64_t sceAmprAprCommandBufferReadFile(
    AprCommandBuffer* cb,
    void* hiddenMapState,
    void* hiddenScatterGatherState,
    uint32_t fileId,
    void* buffer,
    uint64_t length,
    uint64_t offset);
int64_t sceAmprAprCommandBufferReadFileGather(
    AprCommandBuffer* cb,
    void* hiddenMapState,
    void* hiddenScatterGatherState,
    uint64_t length,
    uint64_t offset);
int64_t sceAmprAprCommandBufferResetGatherScatterState(
    AprCommandBuffer* cb,
    void* hiddenMapState,
    void* hiddenScatterGatherState);
int64_t sceAmprAprCommandBufferMapBegin(
    AprCommandBuffer* cb,
    uint64_t va,
    uint64_t size,
    int type,
    int prot);
int64_t sceAmprAprCommandBufferMapDirectBegin(
    AprCommandBuffer* cb,
    uint64_t va,
    uint64_t dmemOffset,
    size_t size,
    int type,
    int prot);
int64_t sceAmprAprCommandBufferMapEnd(AprCommandBuffer* cb);
int64_t sceAmprMeasureCommandSizeMapBegin(
    uint64_t va,
    uint64_t size,
    int type,
    int prot);
int64_t sceAmprMeasureCommandSizeMapDirectBegin(
    uint64_t va,
    uint64_t dmemOffset,
    uint64_t size,
    int type,
    int prot);
int64_t sceAmprMeasureCommandSizeMapEnd();
int64_t sceAmprAmmCommandBufferModifyMtypeProtect(
    AmmCommandBuffer* cb,
    uint64_t va,
    uint64_t size,
    int type,
    int prot,
    int protMask);
int64_t sceAmprAmmCommandBufferModifyMtypeProtectWithGpuMaskId(
    AmmCommandBuffer* cb,
    uint64_t va,
    uint64_t size,
    int type,
    int prot,
    int protMask,
    uint8_t gpuMaskId);
int64_t sceAmprAmmCommandBufferMapAsPrt(AmmCommandBuffer* cb, uint64_t va, uint64_t size);
int64_t sceAmprAmmCommandBufferAllocatePaForPrt(
    AmmCommandBuffer* cb,
    uint64_t va,
    uint64_t size,
    int type,
    int prot);
int64_t sceAmprAmmCommandBufferRemapIntoPrt(
    AmmCommandBuffer* cb,
    uint64_t va,
    uint64_t remapVa,
    uint64_t size,
    int prot,
    uint32_t opcode);
int64_t sceAmprAmmCommandBufferUnmapToPrt(
    AmmCommandBuffer* cb,
    uint64_t va,
    uint64_t size);
}

int main() {
    int failures = 0;

    auto expect_bytes = [&failures](const char* name, const unsigned char* bytes, size_t begin, size_t end, unsigned char expected) {
        size_t mismatch = end;
        for (size_t i = begin; i < end; ++i) {
            if (bytes[i] != expected) {
                mismatch = i;
                break;
            }
        }
        char label[96]{};
        std::snprintf(label, sizeof(label), "%s[first-mismatch=%zu]", name, mismatch);
        failures += !expect_true(label, mismatch == end);
    };

    failures += !expect_true("MeasureCommandSize::writeCounterOnCompletion", MeasureCommandSize::writeCounterOnCompletion(1, 0x1234) > 0);
    failures += !expect_true("MeasureAmmCommandSize::mapDirect", MeasureAmmCommandSize::mapDirect(0x100000, 0, PAGE_SIZE, SCE_KERNEL_MTYPE_C_SHARED, SCE_KERNEL_PROT_CPU_RW) > 0);
    failures += !expect_true("MeasureAmmCommandSize::modifyMtypeProtect",
                             MeasureAmmCommandSize::modifyMtypeProtect(
                                 0x200000,
                                 PAGE_SIZE,
                                 SCE_KERNEL_MTYPE_C_SHARED,
                                 SCE_KERNEL_PROT_CPU_RW,
                                 SCE_KERNEL_PROT_CPU_READ | SCE_KERNEL_PROT_CPU_RW | SCE_KERNEL_PROT_GPU_RW) > 0);
    failures += !expect_true("MeasureAmmCommandSize::modifyMtypeProtectWithGpuMaskId",
                             MeasureAmmCommandSize::modifyMtypeProtectWithGpuMaskId(
                                 0x210000,
                                 PAGE_SIZE,
                                 SCE_KERNEL_MTYPE_C_SHARED,
                                 SCE_KERNEL_PROT_CPU_RW,
                                 SCE_KERNEL_PROT_CPU_READ | SCE_KERNEL_PROT_CPU_RW | SCE_KERNEL_PROT_GPU_RW,
                                 1) > 0);
    failures += !expect_true("MeasureAmmCommandSize::mapAsPrt", MeasureAmmCommandSize::mapAsPrt(0x220000, PAGE_SIZE) > 0);
    failures += !expect_true("MeasureAmmCommandSize::allocatePaForPrt",
                             MeasureAmmCommandSize::allocatePaForPrt(
                                 0x220000,
                                 PAGE_SIZE,
                                 SCE_KERNEL_MTYPE_C_SHARED,
                                 SCE_KERNEL_PROT_CPU_RW | SCE_KERNEL_PROT_GPU_RW) > 0);
    failures += !expect_true("MeasureAprCommandSize::readFile", MeasureAprCommandSize::readFile(Apr::kFileIdInvalid, reinterpret_cast<void*>(0x10000), 0x1000, 0) > 0);
    failures += !expect_true("MeasureAprCommandSize::readFile.max-valid",
                             MeasureAprCommandSize::readFile(Apr::kFileIdInvalid, reinterpret_cast<void*>(0x10000), 0x100000000ull, 0) > 0);
    failures += !expect_true("sceAmprMeasureCommandSizeReadFile.max-valid",
                             sceAmprMeasureCommandSizeReadFile(Apr::kFileIdInvalid, reinterpret_cast<void*>(0x10000), 0x100000000ull, 0) > 0);
    failures += !expect_true("sceAmprMeasureCommandSizeMapBegin",
                             sceAmprMeasureCommandSizeMapBegin(
                                 0x300000,
                                 PAGE_SIZE,
                                 SCE_KERNEL_MTYPE_C_SHARED,
                                 SCE_KERNEL_PROT_CPU_RW | SCE_KERNEL_PROT_AMPR_RW) == 12);
    failures += !expect_true("sceAmprMeasureCommandSizeMapDirectBegin",
                             sceAmprMeasureCommandSizeMapDirectBegin(
                                 0x310000,
                                 0,
                                 PAGE_SIZE,
                                 SCE_KERNEL_MTYPE_C_SHARED,
                                 SCE_KERNEL_PROT_CPU_RW | SCE_KERNEL_PROT_AMPR_RW) == 16);
    failures += !expect_true("sceAmprMeasureCommandSizeMapEnd", sceAmprMeasureCommandSizeMapEnd() == 4);

    ScopedAlignedBuffer cbBuf(4096);
    failures += !expect_true("buffer alloc", cbBuf.ptr != nullptr);
    if (failures != 0) {
        return 1;
    }

    alignas(AprCommandBuffer) unsigned char retailCtorStorage[sizeof(AprCommandBuffer)];
    std::memset(retailCtorStorage, 0xA5, sizeof(retailCtorStorage));
    auto* retailApr = reinterpret_cast<AprCommandBuffer*>(retailCtorStorage);
    failures += !expect_rc("sceAmprCommandBufferConstructor(retail-layout)", (int)sceAmprCommandBufferConstructor(reinterpret_cast<CommandBuffer*>(retailApr)), 0);
    expect_bytes("sceAmprCommandBufferConstructor.zero", retailCtorStorage, 0, sizeof(CommandBuffer), 0x00);
    expect_bytes("sceAmprCommandBufferConstructor.keep-tail", retailCtorStorage, sizeof(CommandBuffer), sizeof(retailCtorStorage), 0xA5);
    failures += !expect_rc("sceAmprAprCommandBufferConstructor(retail-tail)",
                           (int)sceAmprAprCommandBufferConstructor(
                               retailApr,
                               retailCtorStorage + sizeof(CommandBuffer),
                               retailCtorStorage + sizeof(CommandBuffer) + sizeof(uint64_t)),
                           0);
    expect_bytes("sceAmprAprCommandBufferConstructor.zero-tail", retailCtorStorage, sizeof(CommandBuffer), sizeof(retailCtorStorage), 0x00);

    ScopedAlignedBuffer rawAprBuf(4096);
    ScopedAlignedBuffer rawAprReadScratch(0x1000);
    failures += !expect_true("raw APR buffer alloc", rawAprBuf.ptr != nullptr && rawAprReadScratch.ptr != nullptr);
    std::memset(rawAprBuf.ptr, 0xA5, 4096);
    failures += !expect_rc("retailApr.setBuffer", retailApr->setBuffer(rawAprBuf.ptr, 4096), 0);
    failures += !expect_rc("retailApr.readFile.after-export-ctor",
                           (int)sceAmprAprCommandBufferReadFile(
                               retailApr,
                               retailCtorStorage + sizeof(CommandBuffer),
                               retailCtorStorage + sizeof(CommandBuffer) + sizeof(uint64_t),
                               1u,
                               rawAprReadScratch.ptr,
                               0x1000,
                               0),
                           0);
    failures += !expect_true("retailApr.readFile.after-export-ctor.offset", retailApr->getCurrentOffset() == 20u);
    failures += !expect_true("retailApr.readFile.after-export-ctor.num", retailApr->getNumCommands() == 1u);
    failures += !expect_true("retailApr.readFile.native-source-recorded",
                             static_cast<unsigned char*>(rawAprBuf.ptr)[0] != 0xA5);
    expect_bytes("retailApr.readFile.native-source-tail",
                 static_cast<unsigned char*>(rawAprBuf.ptr), 20, 4096, 0xA5);

    std::memset(retailCtorStorage, 0x5A, sizeof(retailCtorStorage));
    failures += !expect_rc("sceAmprCommandBufferDestructor(no-op)", (int)sceAmprCommandBufferDestructor(reinterpret_cast<CommandBuffer*>(retailApr)), 0);
    expect_bytes("sceAmprCommandBufferDestructor.keep-bytes", retailCtorStorage, 0, sizeof(retailCtorStorage), 0x5A);
    failures += !expect_rc("sceAmprAprCommandBufferDestructor(no-op)",
                           (int)sceAmprAprCommandBufferDestructor(
                               retailApr,
                               retailCtorStorage + sizeof(CommandBuffer),
                               retailCtorStorage + sizeof(CommandBuffer) + sizeof(uint64_t)),
                           0);
    expect_bytes("sceAmprAprCommandBufferDestructor.keep-bytes", retailCtorStorage, 0, sizeof(retailCtorStorage), 0x5A);

    CommandBuffer cb{};
    failures += !expect_rc("cb.setBuffer", cb.setBuffer(cbBuf.ptr, 4096), 0);
    failures += !expect_rc("cb.nop", cb.nop(4), 0);
    failures += !expect_rc("cb.pushMarker", cb.pushMarker("boundary"), 0);
    failures += !expect_rc("cb.popMarker", cb.popMarker(), 0);
    const uint32_t cbFirstOffset = cb.getCurrentOffset();
    const uint32_t cbFirstNum = cb.getNumCommands();
    const int cbFirstType = cb.getType();
    ScopedAlignedBuffer cbBuf2(4096);
    failures += !expect_true("buffer2 alloc", cbBuf2.ptr != nullptr);
    failures += !expect_true("cb.clearBuffer.ptr", cb.clearBuffer() == cbBuf.ptr);
    failures += !expect_true("cb.clearBuffer.base", cb.getBufferBaseAddress() == nullptr);
    failures += !expect_true("cb.clearBuffer.size", cb.getSize() == 0u);
    failures += !expect_true("cb.clearBuffer.offset-preserved",
                             cb.getCurrentOffset() == cbFirstOffset);
    failures += !expect_true("cb.clearBuffer.num-preserved",
                             cb.getNumCommands() == cbFirstNum);
    failures += !expect_true("cb.clearBuffer.type-preserved",
                             cb.getType() == cbFirstType);
    failures += !expect_rc("cb.setBuffer.reuse", cb.setBuffer(cbBuf2.ptr, 4096), 0);
    failures += !expect_true("cb.setBuffer.reuse.offset",
                             cb.getCurrentOffset() == cbFirstOffset);
    failures += !expect_true("cb.setBuffer.reuse.num",
                             cb.getNumCommands() == cbFirstNum);
    failures += !expect_true("cb.setBuffer.reuse.type",
                             cb.getType() == cbFirstType);
    failures += !expect_rc("cb.nop.before-rebind", cb.nop(4), 0);
    const uint32_t cbSecondOffset = cb.getCurrentOffset();
    const uint32_t cbSecondNum = cb.getNumCommands();
    const int cbSecondType = cb.getType();
    ScopedAlignedBuffer cbBuf3(4096);
    failures += !expect_true("buffer3 alloc", cbBuf3.ptr != nullptr);
    failures += !expect_rc("cb.setBuffer.bound", cb.setBuffer(cbBuf3.ptr, 4096), SCE_KERNEL_ERROR_EBUSY);
    failures += !expect_true("cb.setBuffer.bound.ptr", cb.getBufferBaseAddress() == cbBuf2.ptr);
    failures += !expect_true("cb.clearBuffer.rebind", cb.clearBuffer() == cbBuf2.ptr);
    failures += !expect_rc("cb.setBuffer.rebind", cb.setBuffer(cbBuf3.ptr, 4096), 0);
    failures += !expect_true("cb.setBuffer.rebind.ptr", cb.getBufferBaseAddress() == cbBuf3.ptr);
    failures += !expect_true("cb.setBuffer.rebind.offset",
                             cb.getCurrentOffset() == cbSecondOffset);
    failures += !expect_true("cb.setBuffer.rebind.num",
                             cb.getNumCommands() == cbSecondNum);
    failures += !expect_true("cb.setBuffer.rebind.type",
                             cb.getType() == cbSecondType);

    ScopedAlignedBuffer legacyCounterBuf(4096);
    CommandBuffer legacyCounterCb{};
    failures += !expect_rc("legacyCounterCb.setBuffer", legacyCounterCb.setBuffer(legacyCounterBuf.ptr, 4096), 0);
    failures += !expect_rc("sceAmprCommandBufferWriteCounter_04_00",
                           (int)sceAmprCommandBufferWriteCounter_04_00(&legacyCounterCb, 1, 1, 0x1234u, 0, 0),
                           0);
    failures += !expect_true("sceAmprCommandBufferWriteCounter_04_00.offset", legacyCounterCb.getCurrentOffset() == 8u);

    ScopedAlignedBuffer legacyWaitBuf(4096);
    CommandBuffer legacyWaitCb{};
    failures += !expect_rc("legacyWaitCb.setBuffer", legacyWaitCb.setBuffer(legacyWaitBuf.ptr, 4096), 0);
    failures += !expect_rc("sceAmprCommandBufferWaitOnCounter_04_00",
                           (int)sceAmprCommandBufferWaitOnCounter_04_00(
                               &legacyWaitCb,
                               1,
                               1,
                               0x1234u,
                               (uint8_t)WaitCompare::kEqual,
                               0,
                               0,
                               (uint8_t)WaitFlush::kDisable),
                           0);
    failures += !expect_true("sceAmprCommandBufferWaitOnCounter_04_00.offset", legacyWaitCb.getCurrentOffset() == 8u);

    ScopedAlignedBuffer legacyEqueueBuf(4096);
    CommandBuffer legacyEqueueCb{};
    const uint64_t fakeEq = 0x1234000012340000ull;
    const uint64_t fakeData = 0x1122334455667788ull;
    failures += !expect_rc("legacyEqueueCb.setBuffer", legacyEqueueCb.setBuffer(legacyEqueueBuf.ptr, 4096), 0);
    failures += !expect_rc("legacyEqueueCb.writeKernelEventQueueOnCompletion",
                           legacyEqueueCb.writeKernelEventQueueOnCompletion(
                               reinterpret_cast<SceKernelEqueue>(fakeEq),
                               0x123,
                               fakeData),
                           0);
    const uint32_t* equeueWords = reinterpret_cast<const uint32_t*>(legacyEqueueBuf.ptr);
    failures += !expect_true("legacyEqueueCb.writeKernelEventQueueOnCompletion.offset", legacyEqueueCb.getCurrentOffset() == 20u);
    failures += !expect_true("legacyEqueueCb.writeKernelEventQueueOnCompletion.w0",
                             equeueWords[0] == (0x408u | static_cast<uint32_t>((fakeEq >> 16) & 0xFFFF0000ull)));
    failures += !expect_true("legacyEqueueCb.writeKernelEventQueueOnCompletion.w1", equeueWords[1] == static_cast<uint32_t>(fakeEq));
    failures += !expect_true("legacyEqueueCb.writeKernelEventQueueOnCompletion.w2", equeueWords[2] == 0x123u);
    failures += !expect_true("legacyEqueueCb.writeKernelEventQueueOnCompletion.w3", equeueWords[3] == static_cast<uint32_t>(fakeData));
    failures += !expect_true("legacyEqueueCb.writeKernelEventQueueOnCompletion.w4", equeueWords[4] == static_cast<uint32_t>(fakeData >> 32));

    ScopedAlignedBuffer legacyNopBuf(4096);
    CommandBuffer legacyNopCb{};
    const uint32_t nopPayload[4] = {0x11111111u, 0x22222222u, 0x33333333u, 0x44444444u};
    failures += !expect_rc("legacyNopCb.setBuffer", legacyNopCb.setBuffer(legacyNopBuf.ptr, 4096), 0);
    failures += !expect_rc("sceAmprCommandBufferConstructNop",
                           (int)sceAmprCommandBufferConstructNop(&legacyNopCb, 5, nopPayload, sizeof(nopPayload), nullptr),
                           0);
    const uint32_t* legacyNopWords = reinterpret_cast<const uint32_t*>(legacyNopBuf.ptr);
    failures += !expect_true("sceAmprCommandBufferConstructNop.offset", legacyNopCb.getCurrentOffset() == 20u);
    failures += !expect_true("sceAmprCommandBufferConstructNop.header", legacyNopWords[0] == 0x5452540Fu);
    failures += !expect_true("sceAmprCommandBufferConstructNop.payload",
                             std::memcmp(&legacyNopWords[1], nopPayload, sizeof(nopPayload)) == 0);

    ScopedAlignedBuffer nullNopBuf(4096);
    std::memset(nullNopBuf.ptr, 0xA5, 4096);
    CommandBuffer nullNopCb{};
    failures += !expect_rc("nullNopCb.setBuffer", nullNopCb.setBuffer(nullNopBuf.ptr, 4096), 0);
    failures += !expect_rc("sceAmprCommandBufferConstructNop.nullPayload",
                           (int)sceAmprCommandBufferConstructNop(&nullNopCb, 6, nullptr, 8, nullptr),
                           0);
    const uint32_t* nullNopWords = reinterpret_cast<const uint32_t*>(nullNopBuf.ptr);
    failures += !expect_true("sceAmprCommandBufferConstructNop.nullPayload.offset", nullNopCb.getCurrentOffset() == 12u);
    failures += !expect_true("sceAmprCommandBufferConstructNop.nullPayload.header", nullNopWords[0] == 0x5452620Fu);
    failures += !expect_true("sceAmprCommandBufferConstructNop.nullPayload.reserved0",
                             nullNopWords[1] == 0xA5A5A5A5u);
    failures += !expect_true("sceAmprCommandBufferConstructNop.nullPayload.reserved1",
                             nullNopWords[2] == 0xA5A5A5A5u);

    ScopedAlignedBuffer markerBuf(4096);
    CommandBuffer markerCb{};
    failures += !expect_rc("markerCb.setBuffer", markerCb.setBuffer(markerBuf.ptr, 4096), 0);
    failures += !expect_true("MeasureAprCommandSize::setMarker.short", MeasureAprCommandSize::setMarker("abc") == 8);
    failures += !expect_rc("markerCb.setMarker.short", markerCb.setMarker("abc"), 0);
    const uint32_t* markerWords = reinterpret_cast<const uint32_t*>(markerBuf.ptr);
    failures += !expect_true("markerCb.setMarker.short.offset", markerCb.getCurrentOffset() == 8u);
    failures += !expect_true("markerCb.setMarker.short.num", markerCb.getNumCommands() == 1u);
    failures += !expect_true("markerCb.setMarker.short.w0", markerWords[0] == 0x5452110Fu);
    failures += !expect_true("markerCb.setMarker.short.w1", markerWords[1] == 0x00636261u);

    ScopedAlignedBuffer markerColorBuf(4096);
    CommandBuffer markerColorCb{};
    failures += !expect_rc("markerColorCb.setBuffer", markerColorCb.setBuffer(markerColorBuf.ptr, 4096), 0);
    failures += !expect_true("MeasureAprCommandSize::setMarker.color", MeasureAprCommandSize::setMarker("abc", 0x11223344u) == 12);
    failures += !expect_rc("markerColorCb.setMarker.color", markerColorCb.setMarker("abc", 0x11223344u), 0);
    const uint32_t* markerColorWords = reinterpret_cast<const uint32_t*>(markerColorBuf.ptr);
    failures += !expect_true("markerColorCb.setMarker.color.offset", markerColorCb.getCurrentOffset() == 12u);
    failures += !expect_true("markerColorCb.setMarker.color.w0", markerColorWords[0] == 0x5452520Fu);
    failures += !expect_true("markerColorCb.setMarker.color.w1", markerColorWords[1] == 0x11223344u);
    failures += !expect_true("markerColorCb.setMarker.color.w2", markerColorWords[2] == 0x00636261u);

    ScopedAlignedBuffer longMarkerBuf(4096);
    CommandBuffer longMarkerCb{};
    char longMarker[65]{};
    std::memset(longMarker, 'A', sizeof(longMarker) - 1u);
    failures += !expect_rc("longMarkerCb.setBuffer", longMarkerCb.setBuffer(longMarkerBuf.ptr, 4096), 0);
    failures += !expect_true("MeasureAprCommandSize::pushMarker.long", MeasureAprCommandSize::pushMarker(longMarker) == 76);
    failures += !expect_rc("longMarkerCb.pushMarker.long", longMarkerCb.pushMarker(longMarker), 0);
    const uint32_t* longMarkerWords = reinterpret_cast<const uint32_t*>(longMarkerBuf.ptr);
    failures += !expect_true("longMarkerCb.pushMarker.long.offset", longMarkerCb.getCurrentOffset() == 76u);
    failures += !expect_true("longMarkerCb.pushMarker.long.num", longMarkerCb.getNumCommands() == 2u);
    failures += !expect_true("longMarkerCb.pushMarker.long.w0", longMarkerWords[0] == 0x54522F0Fu);
    failures += !expect_true("longMarkerCb.pushMarker.long.cont", longMarkerWords[16] == 0x5452420Fu);

    ScopedAlignedBuffer popMarkerBuf(4096);
    CommandBuffer popMarkerCb{};
    failures += !expect_rc("popMarkerCb.setBuffer", popMarkerCb.setBuffer(popMarkerBuf.ptr, 4096), 0);
    failures += !expect_true("MeasureAprCommandSize::popMarker", MeasureAprCommandSize::popMarker() == 4);
    failures += !expect_rc("popMarkerCb.popMarker", popMarkerCb.popMarker(), 0);
    const uint32_t* popMarkerWords = reinterpret_cast<const uint32_t*>(popMarkerBuf.ptr);
    failures += !expect_true("popMarkerCb.popMarker.offset", popMarkerCb.getCurrentOffset() == 4u);
    failures += !expect_true("popMarkerCb.popMarker.w0", popMarkerWords[0] == 0x5452300Fu);

    ScopedAlignedBuffer aprPromoteBuf(4096);
    ScopedAlignedBuffer aprPromoteScratch(0x1000);
    CommandBuffer aprPromote{};
    volatile uint64_t aprPromoteWaitWord = 0x1234u;
    std::memset(aprPromoteBuf.ptr, 0xA5, 4096);
    failures += !expect_rc("aprPromote.setBuffer", aprPromote.setBuffer(aprPromoteBuf.ptr, 4096), 0);
    failures += !expect_rc("aprPromote.waitOnAddress.prefix",
                           aprPromote.waitOnAddress(
                               &aprPromoteWaitWord,
                               0x1234u,
                               WaitCompare::kEqual,
                               WaitFlush::kDisable),
                           0);
    const uint32_t aprPromotePrefixBytes = aprPromote.getCurrentOffset();
    const uint32_t aprPromotePrefixCommands = aprPromote.getNumCommands();
    failures += !expect_rc("aprPromote.readFile.seed-native-prefix",
                           (int)sceAmprAprCommandBufferReadFile(
                               reinterpret_cast<AprCommandBuffer*>(&aprPromote),
                               reinterpret_cast<char*>(&aprPromote) + 24,
                               reinterpret_cast<char*>(&aprPromote) + 32,
                               7u,
                               aprPromoteScratch.ptr,
                               0x1000u,
                               0x40u),
                           0);
    failures += !expect_true("aprPromote.readFile.offset",
                             aprPromote.getCurrentOffset() == aprPromotePrefixBytes + 20u);
    failures += !expect_true("aprPromote.readFile.num",
                             aprPromote.getNumCommands() == aprPromotePrefixCommands + 1u);
    failures += !expect_true("aprPromote.readFile.type-sg",
                             (aprPromote.getType() & 0x00010000) != 0);
    failures += !expect_true("aprPromote.readFile.native-source-recorded",
                             static_cast<unsigned char*>(aprPromoteBuf.ptr)[aprPromotePrefixBytes] != 0xA5);
    expect_bytes("aprPromote.readFile.native-source-tail",
                 static_cast<unsigned char*>(aprPromoteBuf.ptr),
                 aprPromotePrefixBytes + 20u,
                 4096,
                 0xA5);

    ScopedAlignedBuffer aprLazyBuf(4096);
    ScopedAlignedBuffer aprLazyScratch(0x1000);
    CommandBuffer aprLazy{};
    std::memset(aprLazyBuf.ptr, 0xA5, 4096);
    failures += !expect_rc("aprLazy.setBuffer", aprLazy.setBuffer(aprLazyBuf.ptr, 4096), 0);
    failures += !expect_rc("aprLazy.readFile.lazy-apr-state",
                           (int)sceAmprAprCommandBufferReadFile(
                               reinterpret_cast<AprCommandBuffer*>(&aprLazy),
                               reinterpret_cast<char*>(&aprLazy) + 24,
                               reinterpret_cast<char*>(&aprLazy) + 32,
                               7u,
                               aprLazyScratch.ptr,
                               0x1000u,
                               0x40u),
                           0);
    failures += !expect_true("aprLazy.readFile.offset", aprLazy.getCurrentOffset() == 20u);
    failures += !expect_true("aprLazy.readFile.num", aprLazy.getNumCommands() == 1u);
    failures += !expect_true("aprLazy.readFile.type-sg",
                             (aprLazy.getType() & 0x00010000) != 0);
    failures += !expect_rc("aprLazy.setBuffer.same-binding",
                           aprLazy.setBuffer(aprLazyBuf.ptr, 4096),
                           SCE_KERNEL_ERROR_EBUSY);
    failures += !expect_rc("aprLazy.readFile.second-after-same-binding",
                           (int)sceAmprAprCommandBufferReadFile(
                               reinterpret_cast<AprCommandBuffer*>(&aprLazy),
                               reinterpret_cast<char*>(&aprLazy) + 24,
                               reinterpret_cast<char*>(&aprLazy) + 32,
                               8u,
                               aprLazyScratch.ptr,
                               0x800u,
                               0x80u),
                           0);
    failures += !expect_true("aprLazy.readFile.second.offset", aprLazy.getCurrentOffset() == 40u);
    failures += !expect_true("aprLazy.readFile.second.num", aprLazy.getNumCommands() == 2u);
    failures += !expect_true("aprLazy.readFile.second.native-source-recorded",
                             static_cast<unsigned char*>(aprLazyBuf.ptr)[0] != 0xA5);
    expect_bytes("aprLazy.readFile.second.native-source-tail",
                 static_cast<unsigned char*>(aprLazyBuf.ptr), 40, 4096, 0xA5);

    ScopedAlignedBuffer aprMaxReadBuf(4096);
    ScopedAlignedBuffer aprMaxReadScratch(0x1000);
    AprCommandBuffer aprMaxRead{};
    std::memset(aprMaxReadBuf.ptr, 0xA5, 4096);
    failures += !expect_rc("aprMaxRead.setBuffer",
                           aprMaxRead.setBuffer(aprMaxReadBuf.ptr, 4096),
                           0);
    failures += !expect_rc("aprMaxRead.readFile.max",
                           aprMaxRead.readFile(7u, aprMaxReadScratch.ptr, 0x100000000ull, 0),
                           0);
    failures += !expect_true("aprMaxRead.offset", aprMaxRead.getCurrentOffset() == 20u);
    failures += !expect_true("aprMaxRead.num", aprMaxRead.getNumCommands() == 1u);
    failures += !expect_true("aprMaxRead.native-source-recorded",
                             static_cast<unsigned char*>(aprMaxReadBuf.ptr)[0] != 0xA5);
    expect_bytes("aprMaxRead.native-source-tail",
                 static_cast<unsigned char*>(aprMaxReadBuf.ptr), 20, 4096, 0xA5);

    ScopedAlignedBuffer aprGrowBuf(64);
    ScopedAlignedBuffer aprGrowScratch(0x1000);
    AprCommandBuffer aprGrow{};
    failures += !expect_rc("aprGrow.setBuffer", aprGrow.setBuffer(aprGrowBuf.ptr, 64), 0);
    failures += !expect_rc("aprGrow.readFile",
                           aprGrow.readFile(7u, aprGrowScratch.ptr, 0x100u, 0),
                           0);
    failures += !expect_rc("aprGrow.nop.0", aprGrow.nop(1), 0);
    failures += !expect_rc("aprGrow.readGather.0", aprGrow.readFileGather(0x100u, 0x100u), 0);
    failures += !expect_rc("aprGrow.nop.1", aprGrow.nop(1), 0);
    failures += !expect_rc("aprGrow.readGather.1", aprGrow.readFileGather(0x100u, 0x200u), 0);
    failures += !expect_rc("aprGrow.nop.promote", aprGrow.nop(1), 0);
    failures += !expect_true("aprGrow.logical-offset", aprGrow.getCurrentOffset() == 56u);
    const uint32_t aprGrowNum = aprGrow.getNumCommands();
    const int aprGrowType = aprGrow.getType();
    ScopedAlignedBuffer aprGrowRebindBuf(64);
    failures += !expect_true("aprGrow.rebind-buffer.alloc", aprGrowRebindBuf.ptr != nullptr);
    failures += !expect_true("aprGrow.clearBuffer.ptr",
                             aprGrow.clearBuffer() == aprGrowBuf.ptr);
    failures += !expect_true("aprGrow.clearBuffer.offset-preserved",
                             aprGrow.getCurrentOffset() == 56u);
    failures += !expect_true("aprGrow.clearBuffer.num-preserved",
                             aprGrow.getNumCommands() == aprGrowNum);
    failures += !expect_true("aprGrow.clearBuffer.type-preserved",
                             aprGrow.getType() == aprGrowType);
    failures += !expect_rc("aprGrow.setBuffer.rebind",
                           aprGrow.setBuffer(aprGrowRebindBuf.ptr, 64),
                           0);
    failures += !expect_rc("aprGrow.nop.after-rebind", aprGrow.nop(1), 0);
    failures += !expect_true("aprGrow.nop.after-rebind.offset",
                             aprGrow.getCurrentOffset() == 60u);

    ScopedAlignedBuffer aprInlineWriteBuf(4096);
    ScopedAlignedBuffer aprInlineWriteScratch(0x1000);
    AprCommandBuffer aprInlineWrite{};
    volatile uint64_t aprInlineWriteValue = 0;
    std::memset(aprInlineWriteBuf.ptr, 0xA5, 4096);
    failures += !expect_rc("aprInlineWrite.setBuffer",
                           aprInlineWrite.setBuffer(aprInlineWriteBuf.ptr, 4096),
                           0);
    failures += !expect_rc("aprInlineWrite.read.0",
                           aprInlineWrite.readFile(7u, aprInlineWriteScratch.ptr, 0x100u, 0),
                           0);
    failures += !expect_rc("aprInlineWrite.writeAddressOnCompletion",
                           aprInlineWrite.writeAddressOnCompletion(&aprInlineWriteValue, 0x1234u),
                           0);
    failures += !expect_rc("aprInlineWrite.read.1",
                           aprInlineWrite.readFile(
                               7u,
                               static_cast<unsigned char*>(aprInlineWriteScratch.ptr) + 0x100,
                               0x100u,
                               0x100u),
                           0);
    failures += !expect_true("aprInlineWrite.complete-native-source",
                             static_cast<unsigned char*>(aprInlineWriteBuf.ptr)[0] != 0xA5);
    failures += !expect_rc("aprInlineWrite.nop.native-source", aprInlineWrite.nop(1), 0);
    expect_bytes("aprInlineWrite.native-source-tail",
                 static_cast<unsigned char*>(aprInlineWriteBuf.ptr), 56, 4096, 0xA5);
    failures += !expect_true("aprInlineWrite.logical-offset",
                             aprInlineWrite.getCurrentOffset() == 56u);

    ScopedAlignedBuffer aprQueuedWriteBuf(4096);
    ScopedAlignedBuffer aprQueuedWriteScratch(0x1000);
    AprCommandBuffer aprQueuedWrite{};
    volatile uint64_t aprQueuedWriteValue0 = 0;
    volatile uint64_t aprQueuedWriteValue1 = 0;
    std::memset(aprQueuedWriteBuf.ptr, 0xA5, 4096);
    failures += !expect_rc("aprQueuedWrite.setBuffer",
                           aprQueuedWrite.setBuffer(aprQueuedWriteBuf.ptr, 4096),
                           0);
    failures += !expect_rc("aprQueuedWrite.read",
                           aprQueuedWrite.readFile(7u, aprQueuedWriteScratch.ptr, 0x100u, 0),
                           0);
    failures += !expect_rc("aprQueuedWrite.writeAddressOnCompletion.0",
                           aprQueuedWrite.writeAddressOnCompletion(&aprQueuedWriteValue0, 0x1234u),
                           0);
    failures += !expect_rc("aprQueuedWrite.writeAddressOnCompletion.1",
                           aprQueuedWrite.writeAddressOnCompletion(&aprQueuedWriteValue1, 0x5678u),
                           0);
    failures += !expect_true("aprQueuedWrite.complete-native-source",
                             static_cast<unsigned char*>(aprQueuedWriteBuf.ptr)[0] != 0xA5);
    failures += !expect_rc("aprQueuedWrite.nop.native-source", aprQueuedWrite.nop(1), 0);
    expect_bytes("aprQueuedWrite.native-source-tail",
                 static_cast<unsigned char*>(aprQueuedWriteBuf.ptr), 48, 4096, 0xA5);
    failures += !expect_true("aprQueuedWrite.logical-offset",
                             aprQueuedWrite.getCurrentOffset() == 48u);

    ScopedAlignedBuffer aprResetStorageBuf(4096);
    ScopedAlignedBuffer aprResetStorageScratch(0x1000);
    AprCommandBuffer aprResetStorage{};
    std::memset(aprResetStorageBuf.ptr, 0xA5, 4096);
    failures += !expect_rc("aprResetStorage.setBuffer",
                           aprResetStorage.setBuffer(aprResetStorageBuf.ptr, 4096),
                           0);
    failures += !expect_rc("aprResetStorage.readFile",
                           aprResetStorage.readFile(7u, aprResetStorageScratch.ptr, 0x100u, 0),
                           0);
    failures += !expect_rc("aprResetStorage.nop.materialize", aprResetStorage.nop(1), 0);
    failures += !expect_true("aprResetStorage.materialized",
                             static_cast<unsigned char*>(aprResetStorageBuf.ptr)[0] != 0xA5);
    const int aprResetStorageType = aprResetStorage.getType();
    unsigned char aprResetStoragePrefix[64]{};
    std::memcpy(aprResetStoragePrefix, aprResetStorageBuf.ptr, sizeof(aprResetStoragePrefix));
    failures += !expect_rc("aprResetStorage.reset", aprResetStorage.reset(), 0);
    failures += !expect_true("aprResetStorage.reset.offset", aprResetStorage.getCurrentOffset() == 0u);
    failures += !expect_true("aprResetStorage.reset.num", aprResetStorage.getNumCommands() == 0u);
    failures += !expect_true("aprResetStorage.reset.type-preserved",
                             aprResetStorage.getType() == aprResetStorageType);
    failures += !expect_true("aprResetStorage.reset.storage-preserved",
                             std::memcmp(aprResetStorageBuf.ptr,
                                         aprResetStoragePrefix,
                                         sizeof(aprResetStoragePrefix)) == 0);
    failures += !expect_rc("aprResetStorage.nop.after-reset", aprResetStorage.nop(1), 0);
    failures += !expect_true("aprResetStorage.nop.after-reset.offset",
                             aprResetStorage.getCurrentOffset() == 4u);
    failures += !expect_true("aprResetStorage.nop.after-reset.num",
                             aprResetStorage.getNumCommands() == 1u);

    ScopedAlignedBuffer aprBuf(4096);
    ScopedAlignedBuffer aprReadScratch(0x1000);
    AprCommandBuffer apr{};
    std::memset(aprBuf.ptr, 0xA5, 4096);
    failures += !expect_rc("apr.setBuffer", apr.setBuffer(aprBuf.ptr, 4096), 0);
    failures += !expect_rc("sceAmprAprCommandBufferReadFile",
                           (int)sceAmprAprCommandBufferReadFile(
                               &apr,
                               reinterpret_cast<char*>(&apr) + 24,
                               reinterpret_cast<char*>(&apr) + 32,
                               7u,
                               aprReadScratch.ptr,
                               0x1000u,
                               0x40u),
                           0);
    failures += !expect_true("sceAmprAprCommandBufferReadFile.offset", apr.getCurrentOffset() == 20u);
    failures += !expect_true("sceAmprAprCommandBufferReadFile.type-sg", (apr.getType() & 0x00010000) != 0);
    failures += !expect_true("sceAmprAprCommandBufferReadFile.native-source-recorded",
                             static_cast<unsigned char*>(aprBuf.ptr)[0] != 0xA5);
    expect_bytes("sceAmprAprCommandBufferReadFile.native-source-tail",
                 static_cast<unsigned char*>(aprBuf.ptr), 20, 4096, 0xA5);
    failures += !expect_rc("sceAmprAprCommandBufferReadFileGather",
                           (int)sceAmprAprCommandBufferReadFileGather(
                               &apr,
                               reinterpret_cast<char*>(&apr) + 24,
                               reinterpret_cast<char*>(&apr) + 32,
                               0x100u,
                               0x40000u),
                           0);
    failures += !expect_true("sceAmprAprCommandBufferReadFileGather.offset", apr.getCurrentOffset() == 32u);
    expect_bytes("sceAmprAprCommandBufferReadFileGather.native-source-tail",
                 static_cast<unsigned char*>(aprBuf.ptr), 32, 4096, 0xA5);
    failures += !expect_rc("sceAmprAprCommandBufferResetGatherScatterState",
                           (int)sceAmprAprCommandBufferResetGatherScatterState(
                               &apr,
                               reinterpret_cast<char*>(&apr) + 24,
                               reinterpret_cast<char*>(&apr) + 32),
                           0);
    failures += !expect_true("sceAmprAprCommandBufferResetGatherScatterState.offset", apr.getCurrentOffset() == 36u);
    failures += !expect_true("sceAmprAprCommandBufferResetGatherScatterState.type-sg-clear", (apr.getType() & 0x00010000) == 0);
    expect_bytes("sceAmprAprCommandBufferResetGatherScatterState.native-source-tail",
                 static_cast<unsigned char*>(aprBuf.ptr), 36, 4096, 0xA5);

    ScopedAlignedBuffer aprResetOnlyBuf(4096);
    AprCommandBuffer aprResetOnly{};
    std::memset(aprResetOnlyBuf.ptr, 0xA5, 4096);
    failures += !expect_rc("aprResetOnly.setBuffer", aprResetOnly.setBuffer(aprResetOnlyBuf.ptr, 4096), 0);
    failures += !expect_rc("aprResetOnly.resetGatherScatterState",
                           aprResetOnly.resetGatherScatterState(),
                           0);
    failures += !expect_true("aprResetOnly.native-source-recorded",
                             static_cast<unsigned char*>(aprResetOnlyBuf.ptr)[0] != 0xA5);
    expect_bytes("aprResetOnly.native-source-tail",
                 static_cast<unsigned char*>(aprResetOnlyBuf.ptr), 4, 4096, 0xA5);
    SceAprSubmitId aprResetOnlyId = 0;
    SceAprResultBuffer aprResetOnlyResult{};
    failures += !expect_rc("aprResetOnly.submit",
                           Apr::submitCommandBufferAndGetResult(
                               &aprResetOnly,
                               Apr::Priority::kPriority1,
                               &aprResetOnlyResult,
                               &aprResetOnlyId),
                           0);
    failures += !expect_rc("aprResetOnly.wait",
                           Apr::waitCommandBufferCompletion(aprResetOnlyId),
                           0);
    failures += !expect_true("aprResetOnly.result", aprResetOnlyResult.result == 0);

    ScopedAlignedBuffer ammExtendedBuf(4096);
    AmmCommandBuffer ammExtended{};
    const int ammProt = SCE_KERNEL_PROT_CPU_RW;
    const int ammProtMask = SCE_KERNEL_PROT_CPU_READ | SCE_KERNEL_PROT_CPU_RW | SCE_KERNEL_PROT_GPU_RW;
    const int mtypeBytes = MeasureAmmCommandSize::modifyMtypeProtect(
        0x200000,
        PAGE_SIZE,
        SCE_KERNEL_MTYPE_C_SHARED,
        ammProt,
        ammProtMask);
    const int mtypeGpuBytes = MeasureAmmCommandSize::modifyMtypeProtectWithGpuMaskId(
        0x210000,
        PAGE_SIZE,
        SCE_KERNEL_MTYPE_C_SHARED,
        ammProt,
        ammProtMask,
        2);
    const int prtMapBytes = MeasureAmmCommandSize::mapAsPrt(0x220000, PAGE_SIZE);
    const int prtAllocBytes = MeasureAmmCommandSize::allocatePaForPrt(
        0x220000,
        PAGE_SIZE,
        SCE_KERNEL_MTYPE_C_SHARED,
        SCE_KERNEL_PROT_CPU_RW | SCE_KERNEL_PROT_GPU_RW);
    failures += !expect_true("ammExtended buffer alloc", ammExtendedBuf.ptr != nullptr);
    failures += !expect_true("ammExtended measured bytes", mtypeBytes > 0 && mtypeGpuBytes > 0 && prtMapBytes > 0 && prtAllocBytes > 0);
    failures += !expect_rc("ammExtended.setBuffer", ammExtended.setBuffer(ammExtendedBuf.ptr, 4096), 0);
    failures += !expect_rc("sceAmprAmmCommandBufferModifyMtypeProtect",
                           (int)sceAmprAmmCommandBufferModifyMtypeProtect(
                               &ammExtended,
                               0x200000,
                               PAGE_SIZE,
                               SCE_KERNEL_MTYPE_C_SHARED,
                               ammProt,
                               ammProtMask),
                           0);
    failures += !expect_rc("sceAmprAmmCommandBufferModifyMtypeProtectWithGpuMaskId",
                           (int)sceAmprAmmCommandBufferModifyMtypeProtectWithGpuMaskId(
                               &ammExtended,
                               0x210000,
                               PAGE_SIZE,
                               SCE_KERNEL_MTYPE_C_SHARED,
                               ammProt,
                               ammProtMask,
                               2),
                           0);
    failures += !expect_rc("sceAmprAmmCommandBufferMapAsPrt",
                           (int)sceAmprAmmCommandBufferMapAsPrt(&ammExtended, 0x220000, PAGE_SIZE),
                           0);
    failures += !expect_rc("sceAmprAmmCommandBufferAllocatePaForPrt",
                           (int)sceAmprAmmCommandBufferAllocatePaForPrt(
                               &ammExtended,
                               0x220000,
                               PAGE_SIZE,
                               SCE_KERNEL_MTYPE_C_SHARED,
                               SCE_KERNEL_PROT_CPU_RW | SCE_KERNEL_PROT_GPU_RW),
                           0);
    uint32_t expectedAmmExtendedOffset = 0;
    if (mtypeBytes > 0) expectedAmmExtendedOffset += static_cast<uint32_t>(mtypeBytes);
    if (mtypeGpuBytes > 0) expectedAmmExtendedOffset += static_cast<uint32_t>(mtypeGpuBytes);
    if (prtMapBytes > 0) expectedAmmExtendedOffset += static_cast<uint32_t>(prtMapBytes);
    if (prtAllocBytes > 0) expectedAmmExtendedOffset += static_cast<uint32_t>(prtAllocBytes);
    failures += !expect_true("ammExtended.offset", ammExtended.getCurrentOffset() == expectedAmmExtendedOffset);
    failures += !expect_true("ammExtended.num", ammExtended.getNumCommands() == 4u);
    const uint32_t beforePrtRemapOffset = ammExtended.getCurrentOffset();
    const uint32_t beforePrtRemapNum = ammExtended.getNumCommands();
    const int prtRemapRc = (int)sceAmprAmmCommandBufferRemapIntoPrt(
        &ammExtended,
        0x230000,
        0x240000,
        PAGE_SIZE,
        SCE_KERNEL_PROT_CPU_RW | SCE_KERNEL_PROT_GPU_RW,
        1011u);
    failures += !expect_true("sceAmprAmmCommandBufferRemapIntoPrt.rc",
                             prtRemapRc == 0 || prtRemapRc == SCE_KERNEL_ERROR_ENXIO);
    if (prtRemapRc == 0) {
        failures += !expect_true("sceAmprAmmCommandBufferRemapIntoPrt.offset",
                                 ammExtended.getCurrentOffset() > beforePrtRemapOffset);
        failures += !expect_true("sceAmprAmmCommandBufferRemapIntoPrt.num",
                                 ammExtended.getNumCommands() == beforePrtRemapNum + 1u);
    } else {
        failures += !expect_true("sceAmprAmmCommandBufferRemapIntoPrt.enxio.offset",
                                 ammExtended.getCurrentOffset() == beforePrtRemapOffset);
        failures += !expect_true("sceAmprAmmCommandBufferRemapIntoPrt.enxio.num",
                                 ammExtended.getNumCommands() == beforePrtRemapNum);
    }
    const uint32_t beforePrtUnmapOffset = ammExtended.getCurrentOffset();
    const uint32_t beforePrtUnmapNum = ammExtended.getNumCommands();
    const int prtUnmapRc = (int)sceAmprAmmCommandBufferUnmapToPrt(&ammExtended, 0x230000, PAGE_SIZE);
    failures += !expect_true("sceAmprAmmCommandBufferUnmapToPrt.rc",
                             prtUnmapRc == 0 || prtUnmapRc == SCE_KERNEL_ERROR_ENXIO);
    if (prtUnmapRc == 0) {
        failures += !expect_true("sceAmprAmmCommandBufferUnmapToPrt.offset",
                                 ammExtended.getCurrentOffset() > beforePrtUnmapOffset);
        failures += !expect_true("sceAmprAmmCommandBufferUnmapToPrt.num",
                                 ammExtended.getNumCommands() == beforePrtUnmapNum + 1u);
    } else {
        failures += !expect_true("sceAmprAmmCommandBufferUnmapToPrt.enxio.offset",
                                 ammExtended.getCurrentOffset() == beforePrtUnmapOffset);
        failures += !expect_true("sceAmprAmmCommandBufferUnmapToPrt.enxio.num",
                                 ammExtended.getNumCommands() == beforePrtUnmapNum);
    }

    ScopedAlignedBuffer aprMapBuf(4096);
    ScopedAlignedBuffer aprMapReadScratch(0x1000);
    AprCommandBuffer aprMap{};
    volatile uint64_t aprMapCompletion = 0;
    const uint64_t aprMapVa = 0x300000ull;
    const uint64_t aprMapSize = PAGE_SIZE;
    const int aprMapType = SCE_KERNEL_MTYPE_C_SHARED;
    const int aprMapProt = SCE_KERNEL_PROT_AMPR_WRITE;
    failures += !expect_true("aprMap buffers alloc", aprMapBuf.ptr != nullptr && aprMapReadScratch.ptr != nullptr);
    std::memset(aprMapBuf.ptr, 0xA5, 4096);
    failures += !expect_rc("aprMap.setBuffer", aprMap.setBuffer(aprMapBuf.ptr, 4096), 0);
    failures += !expect_rc("sceAmprAprCommandBufferMapEnd.no-active",
                           (int)sceAmprAprCommandBufferMapEnd(&aprMap),
                           SCE_KERNEL_ERROR_EPERM);
    failures += !expect_rc("sceAmprAprCommandBufferMapBegin",
                           (int)sceAmprAprCommandBufferMapBegin(&aprMap, aprMapVa, aprMapSize, aprMapType, aprMapProt),
                           0);
    failures += !expect_true("sceAmprAprCommandBufferMapBegin.offset", aprMap.getCurrentOffset() == 12u);
    failures += !expect_true("sceAmprAprCommandBufferMapBegin.native-buffer",
                             static_cast<unsigned char*>(aprMapBuf.ptr)[0] != 0xA5);
    failures += !expect_rc("sceAmprAprCommandBufferMapBegin.nested",
                           (int)sceAmprAprCommandBufferMapBegin(&aprMap, aprMapVa + PAGE_SIZE, aprMapSize, aprMapType, aprMapProt),
                           SCE_KERNEL_ERROR_EPERM);
    failures += !expect_rc("aprMap.writeAddressOnCompletion.in-map",
                           aprMap.writeAddressOnCompletion(&aprMapCompletion, 1),
                           SCE_KERNEL_ERROR_EPERM);
    failures += !expect_rc("aprMap.readFile.in-map",
                           aprMap.readFile(3u, aprMapReadScratch.ptr, 0x1000u, 0),
                           0);
    failures += !expect_rc("sceAmprAprCommandBufferMapEnd",
                           (int)sceAmprAprCommandBufferMapEnd(&aprMap),
                           0);
    failures += !expect_true("sceAmprAprCommandBufferMapEnd.offset", aprMap.getCurrentOffset() == 36u);
    failures += !expect_true("sceAmprAprCommandBufferMapEnd.transformed-buffer",
                             static_cast<unsigned char*>(aprMapBuf.ptr)[0] != 0xA5);
    failures += !expect_rc("sceAmprAprCommandBufferMapEnd.second",
                           (int)sceAmprAprCommandBufferMapEnd(&aprMap),
                           SCE_KERNEL_ERROR_EPERM);
    failures += !expect_rc("aprMap.writeAddressOnCompletion.after-map",
                           aprMap.writeAddressOnCompletion(&aprMapCompletion, 2),
                           0);

    ScopedAlignedBuffer aprMapDirectBuf(4096);
    AprCommandBuffer aprMapDirect{};
    const uint64_t aprDirectVa = 0x310000ull;
    const uint64_t aprDirectDmemOffset = 0;
    failures += !expect_true("aprMapDirect buffer alloc", aprMapDirectBuf.ptr != nullptr);
    std::memset(aprMapDirectBuf.ptr, 0xA5, 4096);
    failures += !expect_rc("aprMapDirect.setBuffer", aprMapDirect.setBuffer(aprMapDirectBuf.ptr, 4096), 0);
    failures += !expect_rc("sceAmprAprCommandBufferMapDirectBegin",
                           (int)sceAmprAprCommandBufferMapDirectBegin(
                               &aprMapDirect,
                               aprDirectVa,
                               aprDirectDmemOffset,
                               PAGE_SIZE,
                               aprMapType,
                               aprMapProt),
                           0);
    failures += !expect_rc("sceAmprAprCommandBufferMapDirectEnd",
                           (int)sceAmprAprCommandBufferMapEnd(&aprMapDirect),
                           0);
    failures += !expect_true("sceAmprAprCommandBufferMapDirectBegin.offset", aprMapDirect.getCurrentOffset() == 20u);
    failures += !expect_true("sceAmprAprCommandBufferMapDirect.native-buffer",
                             static_cast<unsigned char*>(aprMapDirectBuf.ptr)[0] != 0xA5);

    ScopedAlignedBuffer aprManyBuf(4096);
    AprCommandBuffer aprMany{};
    std::memset(aprManyBuf.ptr, 0xA5, 4096);
    failures += !expect_rc("aprMany.setBuffer", aprMany.setBuffer(aprManyBuf.ptr, 4096), 0);
    for (uint32_t i = 0; i < 160u; ++i) {
        char label[64]{};
        std::snprintf(label, sizeof(label), "aprMany.nop.%u", i);
        failures += !expect_rc(label, aprMany.nop(1), 0);
    }
    failures += !expect_true("aprMany.nop.offset", aprMany.getCurrentOffset() == 640u);
    failures += !expect_true("aprMany.nop.num", aprMany.getNumCommands() == 160u);
    failures += !expect_true("aprMany.nop.native-buffer",
                             static_cast<unsigned char*>(aprManyBuf.ptr)[0] != 0xA5);
    SceAprSubmitId aprManyId = 0;
    SceAprResultBuffer aprManyResult{};
    failures += !expect_rc("aprMany.submit.decode-packed",
                           Apr::submitCommandBufferAndGetResult(
                               &aprMany,
                               Apr::Priority::kPriority1,
                               &aprManyResult,
                               &aprManyId),
                           0);
    failures += !expect_rc("aprMany.wait.decode-packed", Apr::waitCommandBufferCompletion(aprManyId), 0);
    failures += !expect_true("aprMany.result.decode-packed", aprManyResult.result == 0);

    ScopedAlignedBuffer aprCommonBuf(4096);
    AprCommandBuffer aprCommon{};
    volatile uint64_t aprWaitWord = 0x44u;
    volatile uint64_t aprWriteWord = 0;
    volatile uint64_t aprCounterWord = 0;
    std::memset(aprCommonBuf.ptr, 0xA5, 4096);
    failures += !expect_rc("aprCommon.setBuffer", aprCommon.setBuffer(aprCommonBuf.ptr, 4096), 0);
    failures += !expect_rc("aprCommon.waitOnAddress.decode-packed",
                           aprCommon.waitOnAddress(&aprWaitWord, 0x44u, WaitCompare::kEqual, WaitFlush::kDisable),
                           0);
    failures += !expect_rc("aprCommon.writeCounterImmediately.decode-packed",
                           (int)sceAmprCommandBufferWriteCounter_04_00(
                               reinterpret_cast<CommandBuffer*>(&aprCommon),
                               3,
                               1,
                               0x1234u,
                               0,
                               1),
                           0);
    failures += !expect_rc("aprCommon.writeAddressFromCounterOnCompletion.decode-packed",
                           (int)sceAmprCommandBufferWriteAddressFromCounterOnCompletion(
                               reinterpret_cast<CommandBuffer*>(&aprCommon),
                               &aprCounterWord,
                               3),
                           0);
    failures += !expect_rc("aprCommon.writeAddressOnCompletion.decode-packed",
                           aprCommon.writeAddressOnCompletion(&aprWriteWord, 0x55667788u),
                           0);
    failures += !expect_true("aprCommon.native-buffer",
                             static_cast<unsigned char*>(aprCommonBuf.ptr)[0] != 0xA5);
    SceAprSubmitId aprCommonId = 0;
    SceAprResultBuffer aprCommonResult{};
    failures += !expect_rc("aprCommon.submit.decode-packed",
                           Apr::submitCommandBufferAndGetResult(
                               &aprCommon,
                               Apr::Priority::kPriority1,
                               &aprCommonResult,
                               &aprCommonId),
                           0);
    failures += !expect_rc("aprCommon.wait.decode-packed", Apr::waitCommandBufferCompletion(aprCommonId), 0);
    failures += !expect_true("aprCommon.result.decode-packed", aprCommonResult.result == 0);
    failures += !expect_true("aprCommon.counter.decode-packed", aprCounterWord == 0x1234u);
    failures += !expect_true("aprCommon.write.decode-packed", aprWriteWord == 0x55667788u);

    std::printf("prospero_prx_boundary failures=%d\n", failures);
    std::printf("This harness uses the public SDK-visible surface plus direct ABI probes for the libSceAmpr compatibility exports.\n");
    return failures == 0 ? 0 : 1;
}
