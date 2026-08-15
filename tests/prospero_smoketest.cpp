#include "prospero_test_common.h"

#include <cstdio>

using namespace sce::Ampr;

int main() {
    int failures = 0;

    AmmVirtualAddressRanges ranges{};
    Amm::getVirtualAddressRanges(ranges);
    failures += !expect_true("Amm::getVirtualAddressRanges", ranges.vaStart != 0 && ranges.vaEnd > ranges.vaStart);

    ScopedAlignedBuffer ammBuf(4096);
    ScopedAlignedBuffer aprBuf(4096);
    failures += !expect_true("amm buffer alloc", ammBuf.ptr != nullptr);
    failures += !expect_true("apr buffer alloc", aprBuf.ptr != nullptr);
    if (failures != 0) {
        return 1;
    }

    volatile uint64_t stamp = 0;
    AmmCommandBuffer amm{};
    failures += !expect_rc("amm.setBuffer", amm.setBuffer(ammBuf.ptr, 4096), 0);
    failures += !expect_rc("amm.writeAddressOnCompletion", amm.writeAddressOnCompletion(&stamp, 0x1122334455667788ull), 0);

    SceAmmResultBuffer ammResult{};
    SceAmmSubmitId ammId{};
    failures += !expect_rc("Amm::submitCommandBufferAndGetResult", Amm::submitCommandBufferAndGetResult(&amm, Amm::Priority::kMid, &ammResult, &ammId), 0);
    failures += !expect_rc("Amm::waitCommandBufferCompletion", Amm::waitCommandBufferCompletion(ammId), 0);
    failures += !expect_rc("amm result", ammResult.result, 0);
    failures += !expect_true("completion store", stamp == 0x1122334455667788ull);

    AprCommandBuffer apr{};
    failures += !expect_rc("apr.setBuffer", apr.setBuffer(aprBuf.ptr, 4096), 0);
    failures += !expect_rc("apr.setMarker", apr.setMarker("prospero_smoke"), 0);
    failures += !expect_rc("apr.pushMarker", apr.pushMarker("prospero_smoke_scope"), 0);
    failures += !expect_rc("apr.popMarker", apr.popMarker(), 0);

    SceAprResultBuffer aprResult{};
    SceAprSubmitId aprId{};
    failures += !expect_rc("Apr::submitCommandBufferAndGetResult(priority0)", Apr::submitCommandBufferAndGetResult(&apr, Apr::Priority::kPriority0, &aprResult, &aprId), 0);
    failures += !expect_rc("Apr::waitCommandBufferCompletion", Apr::waitCommandBufferCompletion(aprId), 0);
    failures += !expect_rc("apr result", aprResult.result, 0);

    SceKernelEqueue eq{};
    failures += !expect_rc("sceKernelCreateEqueue", sceKernelCreateEqueue(&eq, "ampr_smoke"), 0);
    failures += !expect_rc("amm.reset", amm.reset(), 0);
    failures += !expect_rc("amm.writeKernelEventQueueOnCompletion", amm.writeKernelEventQueueOnCompletion(eq, 0x123, 0), 0);
    failures += !expect_rc("amm.writeAddressOnCompletion(2)", amm.writeAddressOnCompletion(&stamp, 0x8877665544332211ull), 0);
    failures += !expect_rc("Amm::submitCommandBufferAndGetResult(2)", Amm::submitCommandBufferAndGetResult(&amm, Amm::Priority::kLow, &ammResult, &ammId), 0);
    failures += !expect_rc("Amm::waitCommandBufferCompletion(2)", Amm::waitCommandBufferCompletion(ammId), 0);
    failures += !expect_rc("sceKernelDeleteEqueue", sceKernelDeleteEqueue(eq), 0);
    failures += !expect_true("completion store 2", stamp == 0x8877665544332211ull);

    std::printf("prospero_smoketest failures=%d\n", failures);
    return failures == 0 ? 0 : 1;
}
