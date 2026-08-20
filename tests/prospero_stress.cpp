#include "prospero_test_common.h"

#include <cstdio>

using namespace sce::Ampr;

extern "C" int sceKernelUsleep(unsigned int usec);

static bool wait_for_completion_word(volatile uint64_t* word, uint64_t expected) {
    constexpr uint32_t kPollLimit = 5000000u;
    for (uint32_t poll = 0; poll < kPollLimit; ++poll) {
        if (*word == expected) {
            return true;
        }
        (void)sceKernelUsleep(1u);
    }
    return false;
}

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

    // Match the title's completion-word retirement pattern: it reuses one of
    // 512 command-buffer slots after EOP writes the slot state, and only waits
    // when it must force an in-flight slot. Completed ids therefore must not
    // occupy the live request pool indefinitely.
    constexpr uint32_t kAprRingSize = 512u;
    constexpr uint32_t kAprRingTurns = 9u;
    constexpr uint32_t kAprNoWaitSubmits = kAprRingSize * kAprRingTurns;
    ScopedAlignedBuffer aprRingStorage(4096u * kAprRingSize);
    AprCommandBuffer aprRing[kAprRingSize];
    SceAprResultBuffer aprRingResults[kAprRingSize]{};
    SceAprSubmitId aprRingIds[kAprRingSize]{};
    volatile uint64_t aprRingCompletion[kAprRingSize]{};

    failures += !expect_true("apr ring storage alloc", aprRingStorage.ptr != nullptr);
    if (aprRingStorage.ptr) {
        auto* const storage = static_cast<uint8_t*>(aprRingStorage.ptr);
        for (uint32_t slot = 0; slot < kAprRingSize; ++slot) {
            failures += !expect_rc("apr ring setBuffer",
                                   aprRing[slot].setBuffer(storage + 4096u * slot, 4096u),
                                   0);
        }

        bool ringReady = failures == 0;
        for (uint32_t submit = 0; ringReady && submit < kAprNoWaitSubmits; ++submit) {
            const uint32_t slot = submit % kAprRingSize;
            if (submit >= kAprRingSize) {
                const uint64_t priorCompletion =
                    static_cast<uint64_t>(submit - kAprRingSize) + 1ull;
                ringReady = expect_true(
                    "apr ring prior EOP completion",
                    wait_for_completion_word(&aprRingCompletion[slot], priorCompletion));
                failures += !ringReady;
                if (!ringReady) {
                    break;
                }
                failures += !expect_rc("apr ring prior result",
                                       aprRingResults[slot].result,
                                       0);
            }

            aprRingResults[slot] = {};
            failures += !expect_rc("apr ring reset", aprRing[slot].reset(), 0);
            failures += !expect_rc(
                "apr ring writeAddressOnCompletion",
                aprRing[slot].writeAddressOnCompletion(
                    &aprRingCompletion[slot],
                    static_cast<uint64_t>(submit) + 1ull),
                0);
            failures += !expect_rc(
                "apr ring submit without wait",
                Apr::submitCommandBufferAndGetResult(&aprRing[slot],
                                                     Apr::Priority::kPriority2,
                                                     &aprRingResults[slot],
                                                     &aprRingIds[slot]),
                0);
            ringReady = failures == 0;
        }

        for (uint32_t slot = 0; ringReady && slot < kAprRingSize; ++slot) {
            const uint64_t finalCompletion =
                static_cast<uint64_t>(kAprNoWaitSubmits - kAprRingSize + slot) + 1ull;
            ringReady = expect_true(
                "apr ring final EOP completion",
                wait_for_completion_word(&aprRingCompletion[slot], finalCompletion));
            failures += !ringReady;
            if (!ringReady) {
                break;
            }
            failures += !expect_rc("apr ring late wait",
                                   Apr::waitCommandBufferCompletion(aprRingIds[slot]),
                                   0);
            failures += !expect_rc("apr ring final result",
                                   aprRingResults[slot].result,
                                   0);
            ringReady = failures == 0;
        }
    }

    std::printf("prospero_stress failures=%d iterations=%d noWaitSubmits=%u\n",
                failures,
                kIterations,
                (unsigned)kAprNoWaitSubmits);
    return failures == 0 ? 0 : 1;
}
