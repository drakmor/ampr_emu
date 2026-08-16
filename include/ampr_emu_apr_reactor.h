/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * APR AIO reactor interface.
 */

#pragma once

#include "ampr_emu_command_packing.h"

#include <cstdint>

inline constexpr uint8_t kAprPriorityMin = 0;
inline constexpr uint8_t kAprPriorityMax = 6;
// Arrays are indexed by the public APR priority value; every slot 0..6 is a lane.
inline constexpr uint8_t kAprPriorityArrayCount = kAprPriorityMax + 1;
[[maybe_unused]] inline constexpr uint8_t kAprPriorityLaneCount =
    kAprPriorityMax - kAprPriorityMin + 1;
static_assert(kAprPriorityLaneCount == kAprPriorityArrayCount,
              "APR priorities 0..6 require one independent lane each");

inline bool apr_submit_priority_valid(uint32_t prio) {
    return prio <= kAprPriorityMax;
}

inline uint8_t apr_clamp_priority(uint32_t prio) {
    if (prio > kAprPriorityMax) {
        return kAprPriorityMax;
    }
    return static_cast<uint8_t>(prio);
}

inline size_t apr_clamp_priority_index(size_t prio) {
    return prio > kAprPriorityMax ? kAprPriorityMax : prio;
}

inline uint8_t apr_scheduler_priority_lane(uint32_t prio) {
    return apr_clamp_priority(prio);
}

enum class AprSubmitMode : uint8_t {
    kSubmit = 0,
    kSubmitAndGetResult = 1,
    kSubmitAndGetId = 2,
};

struct Job {
    uint64_t id{};
    const void* sourceBuffer{};
    uint32_t sourceBytes{};
    uint32_t sourceCommandCount{};
    AprSubmitMode submitMode{AprSubmitMode::kSubmit};
    int nativeSubmitType{};
    uint32_t nativePrio{kAprPriorityMin};
    SceAprResultBuffer* aprRes{};
};

int apr_reactor_shutdown();
int apr_reactor_wait_synthetic_submit_id(SceAprSubmitId id, bool* outHandled);
int apr_reactor_submit(const Job& j,
                       SceAprSubmitId* outSubmitId,
                       uint32_t* outErrorOffset);
