/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Internal typed views of AMPR command encodings.
 */

#pragma once

#include "ampr.h"

namespace sce::Ampr {

enum class WaitCompare : SceAmprWaitCompare {
    kEqual                     = __SCE_AMPR_WAIT_COMPARE_EQUAL,
    kGreaterThanUnsigned       = __SCE_AMPR_WAIT_COMPARE_GREATER_THAN_UNSIGNED,
    kLessThanUnsigned          = __SCE_AMPR_WAIT_COMPARE_LESS_THAN_UNSIGNED,
    kNotEqual                  = __SCE_AMPR_WAIT_COMPARE_NOT_EQUAL,
    kGreaterThanOrEqualWrapped = __SCE_AMPR_WAIT_COMPARE_GREATER_THAN_OR_EQUAL_WRAPPED,
    kGreaterThanSigned         = __SCE_AMPR_WAIT_COMPARE_GREATER_THAN_SIGNED,
    kLessThanSigned            = __SCE_AMPR_WAIT_COMPARE_LESS_THAN_SIGNED,
    kGreaterThan               = kGreaterThanUnsigned,
    kLessThan                  = kLessThanUnsigned,
};

enum class WaitFlush : SceAmprWaitFlush {
    kDisable = __SCE_AMPR_WAIT_COMMAND_FETCH_FLUSH_DISABLE,
    kEnable  = __SCE_AMPR_WAIT_COMMAND_FETCH_FLUSH_ENABLE,
};

enum class CounterAccessSizeAndOffset : SceAmprCounterAccessSizeAndOffset {
    kSize8        = __SCE_AMPR_COUNTER_ACCESS_SIZE_8,
    kSize4        = __SCE_AMPR_COUNTER_ACCESS_SIZE_4,
    kSize2Offset0 = __SCE_AMPR_COUNTER_ACCESS_SIZE_2_OFFSET_0,
    kSize2Offset1 = __SCE_AMPR_COUNTER_ACCESS_SIZE_2_OFFSET_1,
    kSize1Offset0 = __SCE_AMPR_COUNTER_ACCESS_SIZE_1_OFFSET_0,
    kSize1Offset1 = __SCE_AMPR_COUNTER_ACCESS_SIZE_1_OFFSET_1,
    kSize1Offset2 = __SCE_AMPR_COUNTER_ACCESS_SIZE_1_OFFSET_2,
    kSize1Offset3 = __SCE_AMPR_COUNTER_ACCESS_SIZE_1_OFFSET_3,
};

enum class WaitOnCounterMaskOperation : SceAmprWaitOnCounterMaskOperation {
    kDisabled = __SCE_AMPR_WAIT_ON_COUNTER_MASK_DISABLED,
    kAnd      = __SCE_AMPR_WAIT_ON_COUNTER_MASK_AND,
};

enum class WriteCounterOperation : SceAmprWriteCounterOperation {
    kStore               = __SCE_AMPR_WRITE_COUNTER_STORE,
    kAtomicOr            = __SCE_AMPR_WRITE_COUNTER_ATOMIC_OR,
    kAtomicAndComplement = __SCE_AMPR_WRITE_COUNTER_ATOMIC_AND_COMPLEMENT,
    kAtomicXor           = __SCE_AMPR_WRITE_COUNTER_ATOMIC_XOR,
    kAtomicAdd           = __SCE_AMPR_WRITE_COUNTER_ATOMIC_ADD,
};

} // namespace sce::Ampr
