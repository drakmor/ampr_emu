/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Shared command-buffer append helpers.
 */

#pragma once

#include "ampr.h"
#include "ampr_emu_command_packing.h"

#include <cstdint>

inline constexpr uint32_t kAprScatterGatherValidTypeMask = 0x00010000u;
inline constexpr uint32_t kAprMapActiveTypeMask = 0x00020000u;

inline bool ampr_cb_has_type_mask(const SceAmprCommandBuffer* cb, uint32_t mask) {
    return cb && (static_cast<uint32_t>(cb->type) & mask) != 0u;
}

inline uint32_t cb_native_submit_type(uint32_t type) {
    return type & ~(kAprScatterGatherValidTypeMask | kAprMapActiveTypeMask);
}

inline int cb_native_submit_type(const SceAmprCommandBuffer* cb) {
    return cb ? static_cast<int>(cb_native_submit_type(static_cast<uint32_t>(cb->type))) : 0;
}

inline bool cb_op_is_apr_read(OpType type) {
    switch (type) {
        case OpType::AprReadFile:
        case OpType::AprReadGather:
        case OpType::AprReadScatter:
        case OpType::AprReadGatherScatter:
            return true;
        default:
            return false;
    }
}

namespace sce::Ampr {

int cb_append_with_type_mask(SceAmprCommandBuffer* cb, Op&& op, uint32_t setMask, uint32_t clearMask);
int cb_append(SceAmprCommandBuffer* cb, Op&& op);

} // namespace sce::Ampr
