/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Optional raw submit-time AMPR command journal.
 */

#pragma once

#include "ampr_emu_config.h"

#include <cstdint>

namespace sce::Ampr::Emu {

enum class AmprCommandLogDomain : uint32_t {
    Apr = 1u,
    Amm = 2u,
};

enum class AmprCommandLogSubmitMode : uint32_t {
    Submit = 0u,
    SubmitAndGetResult = 1u,
    SubmitAndGetId = 2u,
};

enum : uint32_t {
    kAmprCommandLogFlagSourceOverride = 1u << 0,
};

struct AmprCommandLogSubmitInfo {
    AmprCommandLogDomain domain{AmprCommandLogDomain::Apr};
    AmprCommandLogSubmitMode mode{AmprCommandLogSubmitMode::Submit};
    uint32_t priority{};
    uint32_t submitType{};
    uint32_t commandCount{};
    uint32_t sourceCapacity{};
    uint32_t flags{};
    uint64_t submitCookie{};
    const void* buffer{};
    uint32_t bytes{};
};

#if AMPR_EMU_COMMAND_LOG
void startCommandLog();
void commandLogSubmit(const AmprCommandLogSubmitInfo& info);
void shutdownCommandLog();
#else
inline void startCommandLog() {}
inline void commandLogSubmit(const AmprCommandLogSubmitInfo&) {}
inline void shutdownCommandLog() {}
#endif

} // namespace sce::Ampr::Emu
