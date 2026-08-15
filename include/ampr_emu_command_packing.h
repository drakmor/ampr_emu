/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * AMPR packed command encode/decode helpers.
 */

#pragma once

#include "ampr_emu_command_types.h"

#include <cstdint>
#include <type_traits>

enum class OpType : uint8_t {
    WaitOnAddress,
    WaitOnCounter,
    WriteAddress,
    WriteCounter,
    WriteEqueue,
    WriteAddressFromTimeCounter,
    WriteAddressFromCounter,
    WriteAddressFromCounterPair,
    Nop,
    MarkerSet,
    MarkerPush,
    MarkerPop,

    // AMM
    AmmMap,
    AmmMapDirect,
    AmmUnmap,
    AmmRemap,
    AmmMultiMap,
    AmmModifyProtect,
    AmmModifyMtypeProtect,
    AmmMapAsPrt,
    AmmAllocPaForPrt,
    AmmRemapIntoPrt,
    AmmUnmapToPrt,

    // APR
    AprReadFile,
    AprReadGather,
    AprReadScatter,
    AprReadGatherScatter,
    AprResetGatherScatter,
    AprMapBegin,
    AprMapDirectBegin,
    AprMapEnd
};

struct Op {
    OpType type{};
    uint32_t bufOffsetBytes{}; // for debugging / errorOffset
    uint64_t u64a{}, u64b{}, u64c{};
    uint32_t u32a{}, u32b{}, u32c{};
    uint8_t u8a{}, u8b{};
    void* ptra{};
    const void* cptr{};
    const char* text{};       // borrowed only by synchronous marker packing
    uint32_t textLength{};    // excludes the terminating NUL
};
static_assert(std::is_trivially_copyable<Op>::value,
              "runtime opcode representation must not own resources");
static_assert(std::is_trivially_destructible<Op>::value,
              "runtime opcode destruction must remain free");
static_assert(sizeof(Op) <= 80u,
              "runtime opcode representation unexpectedly grew");

struct PackedOpView {
    OpType type{};
    uint32_t bytes{};
    bool waitFlush{};
};

namespace sce::Ampr {

const char* ampr_op_name(OpType type);
bool ampr_valid_wait_compare(WaitCompare c);
bool ampr_valid_wait_flush(WaitFlush f);
bool ampr_valid_u64_addr(const volatile uint64_t* p);
int ampr_op_size_bytes_checked(const Op& op, uint32_t* outBytes);
uint32_t ampr_native_op_command_count(const Op& op);
int ampr_strict_write_op(SceAmprCommandBuffer* cb, uint32_t offBytes, const Op& op, uint32_t bytes);
int ampr_decode_packed_op(const void* buffer,
                          uint32_t bytes,
                          uint32_t off,
                          Op* outOp,
                          uint32_t* outBytes,
                          uint32_t* errorOffset);
int ampr_decode_apr_packed_op(const void* buffer,
                              uint32_t bytes,
                              uint32_t off,
                              Op* outOp,
                              uint32_t* outBytes,
                              uint32_t* errorOffset);
int ampr_decode_apr_packed_op_view(const void* buffer,
                                   uint32_t bytes,
                                   uint32_t off,
                                   PackedOpView* outView,
                                   uint32_t* errorOffset);

} // namespace sce::Ampr
