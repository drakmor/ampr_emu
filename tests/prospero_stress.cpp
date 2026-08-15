#include "prospero_test_common.h"

#include <cstdio>

using namespace sce::Ampr;

int main() {
    int failures = 0;
    constexpr int kIterations = 64;

    ScopedAlignedBuffer ammBuf(4096);
    ScopedAlignedBuffer aprBuf(4096);
    failures += !expect_true("amm buffer alloc", ammBuf.ptr != nullptr);
    failures += !expect_true("apr buffer alloc", aprBuf.ptr != nullptr);
    if (failures != 0) {
        return 1;
    }

    AmmCommandBuffer amm{};
    AprCommandBuffer apr{};
    failures += !expect_rc("amm.setBuffer", amm.setBuffer(ammBuf.ptr, 4096), 0);
    failures += !expect_rc("apr.setBuffer", apr.setBuffer(aprBuf.ptr, 4096), 0);
    if (failures != 0) {
        return 1;
    }

    for (int i = 0; i < kIterations; ++i) {
        volatile uint64_t stamp = 0;
        SceAmmResultBuffer ammResult{};
        SceAmmSubmitId ammId{};

        failures += !expect_rc("amm.reset", amm.reset(), 0);
        failures += !expect_rc("amm.writeCounterOnCompletion", amm.writeCounterOnCompletion((uint8_t)(i & 0x0F), (uint32_t)i), 0);
        failures += !expect_rc("amm.writeAddressOnCompletion", amm.writeAddressOnCompletion(&stamp, (uint64_t)i + 1ull), 0);
        failures += !expect_rc("Amm::submit", Amm::submitCommandBufferAndGetResult(&amm, Amm::Priority::kMid, &ammResult, &ammId), 0);
        failures += !expect_rc("Amm::wait", Amm::waitCommandBufferCompletion(ammId), 0);
        failures += !expect_rc("amm result", ammResult.result, 0);
        failures += !expect_true("amm stamp", stamp == (uint64_t)i + 1ull);

        SceAprResultBuffer aprResult{};
        SceAprSubmitId aprId{};
        failures += !expect_rc("apr.reset", apr.reset(), 0);
        failures += !expect_rc("apr.setMarker", apr.setMarker("stress"), 0);
        failures += !expect_rc("apr.pushMarker", apr.pushMarker("stress_scope"), 0);
        failures += !expect_rc("apr.popMarker", apr.popMarker(), 0);
        failures += !expect_rc("Apr::submit", Apr::submitCommandBufferAndGetResult(&apr, Apr::Priority::kPriority2, &aprResult, &aprId), 0);
        failures += !expect_rc("Apr::wait", Apr::waitCommandBufferCompletion(aprId), 0);
        failures += !expect_rc("apr result", aprResult.result, 0);
    }

    std::printf("prospero_stress failures=%d iterations=%d\n", failures, kIterations);
    return failures == 0 ? 0 : 1;
}
