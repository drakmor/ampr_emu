/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * AMPR packed command encode/decode implementation.
 */

#include "ampr_emu_command_packing.h"
#include "ampr_emu_errno.h"
#include "ampr_emu_log.h"
#include "ampr_emu_sync.h"

#include <cstring>

static inline uint32_t ampr_align4(uint32_t x) { return (x + 3u) & ~3u; }

namespace sce::Ampr {

const char* ampr_op_name(OpType type) {
    switch (type) {
        case OpType::WaitOnAddress: return "WaitOnAddress";
        case OpType::WaitOnCounter: return "WaitOnCounter";
        case OpType::WriteAddress: return "WriteAddressOnCompletion";
        case OpType::WriteCounter: return "WriteCounterOnCompletion";
        case OpType::WriteEqueue: return "WriteKernelEventQueueOnCompletion";
        case OpType::WriteAddressFromTimeCounter: return "WriteAddressFromTimeCounterOnCompletion";
        case OpType::WriteAddressFromCounter: return "WriteAddressFromCounterOnCompletion";
        case OpType::WriteAddressFromCounterPair: return "WriteAddressFromCounterPairOnCompletion";
        case OpType::Nop: return "Nop";
        case OpType::MarkerSet: return "SetMarker";
        case OpType::MarkerPush: return "PushMarker";
        case OpType::MarkerPop: return "PopMarker";
        case OpType::AmmMap: return "AmmMap";
        case OpType::AmmMapDirect: return "AmmMapDirect";
        case OpType::AmmUnmap: return "AmmUnmap";
        case OpType::AmmRemap: return "AmmRemap";
        case OpType::AmmMultiMap: return "AmmMultiMap";
        case OpType::AmmModifyProtect: return "AmmModifyProtect";
        case OpType::AmmModifyMtypeProtect: return "AmmModifyMtypeProtect";
        case OpType::AmmMapAsPrt: return "AmmMapAsPrt";
        case OpType::AmmAllocPaForPrt: return "AmmAllocatePaForPrt";
        case OpType::AmmRemapIntoPrt: return "AmmRemapIntoPrt";
        case OpType::AmmUnmapToPrt: return "AmmUnmapToPrt";
        case OpType::AprReadFile: return "AprReadFile";
        case OpType::AprReadGather: return "AprReadFileGather";
        case OpType::AprReadScatter: return "AprReadFileScatter";
        case OpType::AprReadGatherScatter: return "AprReadFileGatherScatter";
        case OpType::AprResetGatherScatter: return "AprResetGatherScatterState";
        case OpType::AprMapBegin: return "AprMapBegin";
        case OpType::AprMapDirectBegin: return "AprMapDirectBegin";
        case OpType::AprMapEnd: return "AprMapEnd";
        default: return "UnknownOp";
    }
}

} // namespace sce::Ampr

static uint32_t ampr_counter_value_width(uint8_t valueWidth) {
    if (valueWidth == 0) return 64u;
    if (valueWidth == 1) return 32u;
    if (valueWidth < 4) return 16u;
    return 8u;
}

static uint64_t ampr_mask_counter_value_for_pack(uint64_t value, uint8_t valueWidth) {
    const uint32_t bits = ampr_counter_value_width(valueWidth);
    if (bits >= 64u) return value;
    return value & ((1ull << bits) - 1ull);
}

static uint32_t ampr_write_counter_dwords(uint64_t value, uint8_t valueWidth, uint8_t counterMode) {
    const uint64_t masked = ampr_mask_counter_value_for_pack(value, valueWidth);
    const uint32_t wideDwords = ((masked >> 32) != 0) ? 3u : 2u;
    if (((((uint32_t)valueWidth & 7u) ^ 1u) | ((uint32_t)counterMode & 7u)) != 0 || masked >= 0x1000ull) {
        return wideDwords;
    }
    return 1u;
}

static uint32_t ampr_wait_counter_dwords(uint8_t valueWidth, uint64_t refValue, uint8_t extraFlag, uint64_t extraValue) {
    if (valueWidth == 1u && refValue <= 0xFFull && extraFlag == 0u) {
        return 1u;
    }
    if (refValue > 0xFFFFull) {
        if ((refValue >> 32) != 0 || (((extraValue >> 32) != 0) && extraFlag != 0u)) {
            return 2u * (extraFlag != 0u) + 3u;
        }
        return (extraFlag != 0u) ? 3u : 2u;
    }
    if (extraFlag == 0u || extraValue < 0x10000ull) {
        return 2u;
    }
    if ((extraValue >> 32) != 0) {
        return 5u;
    }
    return 3u;
}

static void ampr_pack_wait_counter_words(
    uint32_t* words,
    uint8_t counterIndex,
    uint8_t valueWidth,
    uint64_t refValue,
    uint8_t compare,
    uint8_t extraFlag,
    uint64_t extraValue,
    uint8_t flush) {
    const uint32_t dwords = ampr_wait_counter_dwords(valueWidth, refValue, extraFlag, extraValue);
    words[0] = ((uint32_t)(uint8_t)refValue << 16)
             | (((static_cast<uint32_t>(dwords) << 8) + 3840u) & 0xF00u)
             | (((uint32_t)compare & 7u) << 13)
             | (((uint32_t)flush & 1u) << 12)
             | ((uint32_t)counterIndex << 24)
             | 2u;
    if (dwords < 2u) {
        return;
    }

    words[1] = ((uint32_t)refValue >> 8)
             | (((((uint32_t)valueWidth & 7u) ^ 1u) << 24))
             | (((uint32_t)extraFlag & 3u) << 28);
    if (refValue <= 0xFFFFull) {
        if (extraFlag == 0u) {
            return;
        }
        if (extraValue < 0x10000ull) {
            words[1] |= (uint32_t)(extraValue << 8) & 0xFFFF00u;
            return;
        }
    }

    words[2] = (uint32_t)(refValue >> 32);
    if (extraFlag != 0u) {
        words[3] = (uint32_t)extraValue;
        if (dwords >= 5u) {
            words[4] = (uint32_t)(extraValue >> 32);
        }
    }
}
namespace sce::Ampr {

// Common packed AMM/APR command encode/decode helpers.

bool ampr_valid_wait_flush(WaitFlush f) {
    switch (f) {
        case WaitFlush::kDisable:
        case WaitFlush::kEnable:
            return true;
        default:
            return false;
    }
}

bool ampr_set_marker_text(Op& op, const char* text) {
    if (!text) {
        return false;
    }
    const size_t length = std::strlen(text);
    if (length >= UINT32_MAX) {
        return false;
    }
    op.text = text;
    op.textLength = static_cast<uint32_t>(length);
    return true;
}

static uint32_t ampr_write_address_dwords(uint64_t value) {
    if (value < 4ull) return 2u;
    if (value < 0x400000000ull) return 3u;
    return 4u;
}

static void ampr_pack_write_address_words(
    uint32_t* words,
    uint64_t address,
    uint64_t value,
    uint8_t addressClass,
    bool atSop) {
    const uint32_t dwords = ampr_write_address_dwords(value);
    const uint32_t opcode = atSop ? 117u : 5u;
    const uint32_t lengthBits = static_cast<uint16_t>((dwords << 14) + 0x8000u);

    words[0] = (uint32_t)((address >> 16) & 0xFFFF0000ull)
             | (((static_cast<uint32_t>(dwords) << 8) + 3840u) & 0xF00u)
             | opcode
             | ((uint32_t)(value & 3ull) << 12)
             | lengthBits;
    words[1] = (uint32_t)(address & 0xFFFFFFF8ull) | ((uint32_t)addressClass & 7u);
    if (value >= 4ull) {
        words[2] = (uint32_t)(value >> 2);
        if (value - 4ull >= 0x3FFFFFFFCull) {
            words[3] = (uint32_t)(value >> 34);
        }
    }
}

static void ampr_pack_write_counter_words(
    uint32_t* words,
    uint8_t counterIndex,
    uint8_t valueWidth,
    uint64_t value,
    uint8_t counterMode,
    bool atSop) {
    const uint64_t masked = ampr_mask_counter_value_for_pack(value, valueWidth);
    const uint32_t dwords = ampr_write_counter_dwords(value, valueWidth, counterMode);
    const uint32_t opcode = atSop ? 118u : 6u;

    words[0] = opcode
             | (((static_cast<uint32_t>(dwords) << 8) + 3840u) & 0xF00u)
             | ((uint32_t)counterIndex << 24)
             | (((uint32_t)masked << 12) & 0xFFF000u);
    if (dwords >= 2u) {
        words[1] = (uint32_t)(masked >> 12)
                 | ((((uint32_t)valueWidth & 7u) ^ 1u) << 20)
                 | (((uint32_t)counterMode & 7u) << 24);
        if (dwords != 2u) {
            words[2] = (uint32_t)(masked >> 32);
        }
    }
}

static uint32_t ampr_marker_type(const Op& op) {
    const bool withColor = op.u32b != 0;
    if (op.type == OpType::MarkerSet) {
        return withColor ? 5u : 1u;
    }
    return withColor ? 6u : 2u;
}

struct AmprMarkerLayout {
    uint64_t dwords{};
    uint64_t commandCount{};
};

static AmprMarkerLayout ampr_marker_layout(uint32_t markerType, uint64_t lenWithNul) {
    const uint64_t firstPayloadBytes = 4ull * (markerType < 5u) + 56ull;
    const uint64_t firstDwords = (firstPayloadBytes >> 2) +
        (markerType >= 5u ? 1ull : 0ull) + 1ull;
    if (lenWithNul <= firstPayloadBytes) {
        return {
            ((lenWithNul + 3ull) >> 2) + (markerType >= 5u ? 1ull : 0ull) + 1ull,
            1ull,
        };
    }

    const uint64_t remaining = lenWithNul - firstPayloadBytes;
    const uint64_t fullChunks = remaining / 60ull;
    const uint64_t tailBytes = remaining % 60ull;
    AmprMarkerLayout layout{};
    layout.dwords = firstDwords + fullChunks * 16ull;
    layout.commandCount = 1ull + fullChunks;
    if (tailBytes != 0) {
        layout.dwords += ((tailBytes + 3ull) >> 2) + 1ull;
        ++layout.commandCount;
    }
    return layout;
}

static bool ampr_marker_layout_fits_native(const Op& op,
                                           AmprMarkerLayout* outLayout = nullptr) {
    if (!op.text || op.textLength == UINT32_MAX) {
        return false;
    }
    const uint64_t lenWithNul = static_cast<uint64_t>(op.textLength) + 1ull;
    const AmprMarkerLayout layout = ampr_marker_layout(ampr_marker_type(op), lenWithNul);
    if (layout.dwords == 0 ||
        layout.dwords > static_cast<uint64_t>(UINT32_MAX) / 4ull ||
        layout.commandCount == 0 ||
        layout.commandCount > static_cast<uint64_t>(INT32_MAX)) {
        return false;
    }
    if (outLayout) {
        *outLayout = layout;
    }
    return true;
}

static uint32_t ampr_fixed_op_size_bytes(const Op& op) {
    switch (op.type) {
        case OpType::WaitOnAddress: {
            uint64_t ref = op.u64a;
            uint32_t dwords = 4;
            if ((ref >> 32) == 0) dwords = 3u - (ref == 0 ? 1u : 0u);
            return dwords * 4u;
        }
        case OpType::WaitOnCounter: {
            return ampr_wait_counter_dwords(op.u8b, op.u64a, (uint8_t)((op.u32c >> 8) & 3u), op.u64b) * 4u;
        }
        case OpType::WriteAddress: {
            return ampr_write_address_dwords(op.u64a) * 4u;
        }
        case OpType::WriteCounter: {
            return ampr_write_counter_dwords(op.u64a, op.u8b, (uint8_t)op.u32b) * 4u;
        }
        case OpType::WriteEqueue: {
            return 5u * 4u;
        }
        case OpType::WriteAddressFromTimeCounter:
            return ampr_write_address_dwords(0) * 4u;
        case OpType::WriteAddressFromCounter:
        case OpType::WriteAddressFromCounterPair:
            return ampr_write_address_dwords(op.u8a) * 4u;
        case OpType::Nop: {
            // nop(data) includes the record header word.
            uint32_t n = op.u32a;
            if (op.u32b) return (n + 1u) * 4u;
            return n * 4u;
        }
        case OpType::MarkerPop:
            return 4u;

        case OpType::AprReadFile:
            return ((op.u64b >> 32) != 0) ? 24u : 20u;
        case OpType::AprReadGather:
            return (op.u64b >= 0x40000ull) ? 12u : 8u;
        case OpType::AprReadScatter:
            return 12u;
        case OpType::AprReadGatherScatter:
            return ((op.u64b >> 32) != 0) ? 20u : 16u;
        case OpType::AprResetGatherScatter:
        case OpType::AprMapEnd:
            return 4u;
        case OpType::AprMapBegin:
            return 12u;
        case OpType::AprMapDirectBegin:
            return 16u;
        default:
            return 0u;
    }
}

int ampr_op_layout_checked(const Op& op, PackedOpLayout* outLayout) {
    if (!outLayout) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    *outLayout = {};

    if (op.type == OpType::MarkerSet || op.type == OpType::MarkerPush) {
        AmprMarkerLayout markerLayout{};
        if (!ampr_marker_layout_fits_native(op, &markerLayout)) {
            return SCE_KERNEL_ERROR_EINVAL;
        }
        outLayout->bytes = static_cast<uint32_t>(markerLayout.dwords * 4ull);
        outLayout->commandCount = static_cast<uint32_t>(markerLayout.commandCount);
        return 0;
    }

    outLayout->bytes = ampr_fixed_op_size_bytes(op);
    if (outLayout->bytes == 0u) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    outLayout->commandCount = 1u;
    return 0;
}

int ampr_op_size_bytes_checked(const Op& op, uint32_t* outBytes) {
    if (!outBytes) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    PackedOpLayout layout{};
    const int rc = ampr_op_layout_checked(op, &layout);
    *outBytes = layout.bytes;
    return rc;
}

static void ampr_strict_write_words(SceAmprCommandBuffer* cb, uint32_t offBytes, const uint32_t* words, uint32_t dwords) {
    if (!cb || !cb->buffer) return;
    uint32_t bytes = dwords * 4u;
    if (offBytes + bytes > cb->bufsize) return;
    std::memcpy((uint8_t*)cb->buffer + offBytes, words, bytes);
    AMPR_TLOGF("cb.pack.words cb=%p off=0x%x dwords=%u w0=0x%08x w1=0x%08x w2=0x%08x w3=0x%08x w4=0x%08x w5=0x%08x",
              cb,
              offBytes,
              dwords,
              dwords > 0 ? words[0] : 0u,
              dwords > 1 ? words[1] : 0u,
              dwords > 2 ? words[2] : 0u,
              dwords > 3 ? words[3] : 0u,
              dwords > 4 ? words[4] : 0u,
              dwords > 5 ? words[5] : 0u);
}

int ampr_write_op_with_layout(SceAmprCommandBuffer* cb,
                              uint32_t offBytes,
                              const Op& op,
                              const PackedOpLayout& layout) {
    const uint32_t bytes = layout.bytes;
    if (bytes == 0u || layout.commandCount == 0u) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    if (!cb || !cb->buffer) {
        return SCE_KERNEL_ERROR_EPERM;
    }
    if (bytes > cb->bufsize || offBytes > cb->bufsize - bytes) {
        return SCE_KERNEL_ERROR_EBUSY;
    }
    void* dst = static_cast<uint8_t*>(cb->buffer) + offBytes;
    const bool needsPaddingClear =
        op.type == OpType::MarkerSet ||
        op.type == OpType::MarkerPush;
    if (needsPaddingClear) {
        std::memset(dst, 0, bytes);
    }

    uint32_t w[8]{}; // enough for all variable writers we implement here

    switch (op.type) {
        case OpType::WaitOnAddress: {
            uint64_t addr = (uint64_t)op.ptra;
            uint64_t ref  = op.u64a;
            uint32_t cmp  = (op.u32a & 7u);
            uint32_t flush = (op.u32c & 1u);

            uint32_t dwords = 4;
            if ((ref >> 32) == 0) dwords = 3u - (ref == 0 ? 1u : 0u);

            w[0] = (uint32_t)((addr >> 16) & 0xFFFF0000ull)
                 | (((static_cast<uint32_t>(dwords) << 8) + 3840u) & 0xEF00u)
                 | ((cmp & 7u) << 13)
                 | ((flush & 1u) << 12)
                 | 1u;
            w[1] = (uint32_t)(addr & 0xFFFFFFFFu);
            if (ref != 0) {
                w[2] = (uint32_t)(ref & 0xFFFFFFFFu);
                if (dwords == 4) w[3] = (uint32_t)(ref >> 32);
            }
            ampr_strict_write_words(cb, offBytes, w, dwords);
            break;
        }
        case OpType::WaitOnCounter: {
            uint8_t idx = op.u8a;
            uint32_t cmp = (op.u32b & 7u);
            uint32_t flush = (op.u32c & 1u);
            const uint8_t extraFlag = (uint8_t)((op.u32c >> 8) & 3u);
            const uint32_t dwords = ampr_wait_counter_dwords(op.u8b, op.u64a, extraFlag, op.u64b);
            ampr_pack_wait_counter_words(w, idx, op.u8b, op.u64a, (uint8_t)cmp, extraFlag, op.u64b, (uint8_t)flush);
            ampr_strict_write_words(cb, offBytes, w, dwords);
            break;
        }
        case OpType::WriteAddress: {
            uint64_t addr = (uint64_t)op.ptra;
            uint64_t val  = op.u64a;
            const uint32_t dwords = ampr_write_address_dwords(val);
            ampr_pack_write_address_words(w, addr, val, 0, op.u8a != 0);
            ampr_strict_write_words(cb, offBytes, w, dwords);
            break;
        }
        case OpType::WriteAddressFromTimeCounter: {
            const uint64_t addr = (uint64_t)op.ptra;
            const uint32_t dwords = ampr_write_address_dwords(0);
            ampr_pack_write_address_words(w, addr, 0, 1, op.u8b != 0);
            ampr_strict_write_words(cb, offBytes, w, dwords);
            break;
        }
        case OpType::WriteAddressFromCounter: {
            const uint64_t addr = (uint64_t)op.ptra;
            const uint64_t counter = (uint64_t)op.u8a;
            const uint32_t dwords = ampr_write_address_dwords(counter);
            ampr_pack_write_address_words(w, addr, counter, 2, op.u8b != 0);
            ampr_strict_write_words(cb, offBytes, w, dwords);
            break;
        }
        case OpType::WriteAddressFromCounterPair: {
            const uint64_t addr = (uint64_t)op.ptra;
            const uint64_t counter = (uint64_t)op.u8a;
            const uint32_t dwords = ampr_write_address_dwords(counter);
            ampr_pack_write_address_words(w, addr, counter, 3, op.u8b != 0);
            ampr_strict_write_words(cb, offBytes, w, dwords);
            break;
        }
        case OpType::WriteCounter: {
            uint8_t idx = op.u8a;
            const uint8_t valueWidth = op.u8b;
            const uint8_t counterMode = (uint8_t)op.u32b;
            const uint32_t dwords = ampr_write_counter_dwords(op.u64a, valueWidth, counterMode);
            ampr_pack_write_counter_words(w, idx, valueWidth, op.u64a, counterMode, op.u32c != 0);
            ampr_strict_write_words(cb, offBytes, w, dwords);
            break;
        }
        case OpType::WriteEqueue: {
            uint64_t eq = op.u64b;
            int32_t id = (int32_t)op.u32b;
            uint64_t data = op.u64a;
            const uint32_t opcode = op.u8a ? 1144u : 1032u;
            w[0] = opcode | (uint32_t)((eq >> 16) & 0xFFFF0000ull);
            w[1] = (uint32_t)eq;
            w[2] = (uint32_t)id;
            w[3] = (uint32_t)(data & 0xFFFFFFFFu);
            w[4] = (uint32_t)(data >> 32);
            ampr_strict_write_words(cb, offBytes, w, 5u);
            break;
        }
        case OpType::Nop: {
            uint32_t n = op.u32a;
            if (!op.u32b) {
                if (!n) break;
                uint32_t n0x3C = 4u * n - 4u;
                w[0] = (n0x3C << 6) | 0x5452000Fu;
                ampr_strict_write_words(cb, offBytes, w, 1u);
            } else {
                w[0] = ((op.u32c & 0xFu) << 12) | ((n & 0xFu) << 8) | 0x5452000Fu;
                ampr_strict_write_words(cb, offBytes, w, 1u);
                uint32_t payloadBytes = n * 4u;
                if (payloadBytes && offBytes + 4u + payloadBytes <= cb->bufsize) {
                    uint8_t* payloadOut = static_cast<uint8_t*>(cb->buffer) + offBytes + 4u;
                    uint32_t cursor = 0u;
                    if (op.u8a) {
                        const uint32_t optWord = static_cast<uint32_t>(op.u64b);
                        std::memcpy(payloadOut, &optWord, sizeof(optWord));
                        cursor += sizeof(optWord);
                    }
                    if (op.cptr) {
                        const bool typedNop = op.u32c != 0u || op.u8a != 0u || op.u64a != 0u;
                        const uint32_t copyBytes = typedNop
                            ? static_cast<uint32_t>(op.u64a)
                            : payloadBytes - cursor;
                        if (copyBytes != 0u && cursor < payloadBytes) {
                            const uint32_t boundedCopy = copyBytes < payloadBytes - cursor ? copyBytes : payloadBytes - cursor;
                            std::memcpy(payloadOut + cursor, op.cptr, boundedCopy);
                            cursor += boundedCopy;
                            const uint32_t padding = ampr_align4(cursor) - cursor;
                            if (padding != 0u && cursor + padding <= payloadBytes) {
                                std::memset(payloadOut + cursor, 0, padding);
                            }
                        }
                    }
                }
            }
            break;
        }
        case OpType::MarkerSet:
        case OpType::MarkerPush: {
            const uint32_t markerType = ampr_marker_type(op);
            const uint32_t lenWithNul = op.textLength + 1u;
            const uint32_t firstPayloadBytes = 4u * (markerType < 5u) + 56u;
            const bool withColor = markerType >= 5u;
            uint8_t* out = static_cast<uint8_t*>(dst);

            uint32_t firstBytes = lenWithNul <= firstPayloadBytes ? lenWithNul : firstPayloadBytes;
            uint32_t firstPayloadDwords = ((firstBytes + 3u) >> 2) + (withColor ? 1u : 0u);
            reinterpret_cast<uint32_t*>(out)[0] = 0x5452000Fu
                                                | ((markerType & 0xFFFFu) << 12)
                                                | ((firstPayloadDwords & 0xFu) << 8);
            uint32_t cursor = 4u;
            if (withColor) {
                reinterpret_cast<uint32_t*>(out + cursor)[0] = op.u32a;
                cursor += 4u;
            }
            std::memcpy(out + cursor, op.text, firstBytes);
            cursor += ampr_align4(firstBytes);

            uint32_t consumed = firstBytes;
            while (consumed < lenWithNul) {
                const uint32_t remaining = lenWithNul - consumed;
                const uint32_t chunk = remaining < 60u ? remaining : 60u;
                const uint32_t chunkDwords = (chunk + 3u) >> 2;
                reinterpret_cast<uint32_t*>(out + cursor)[0] = 0x5452400Fu | ((chunkDwords & 0xFu) << 8);
                cursor += 4u;
                std::memcpy(out + cursor, op.text + consumed, chunk);
                cursor += ampr_align4(chunk);
                consumed += chunk;
            }
            break;
        }
        case OpType::MarkerPop: {
            w[0] = 0x5452300Fu;
            ampr_strict_write_words(cb, offBytes, w, 1u);
            break;
        }
        case OpType::AprReadFile: {
            const uint64_t buffer = reinterpret_cast<uint64_t>(op.ptra);
            const uint64_t offset = op.u64b;
            const uint32_t dwords = ((offset >> 32) != 0) ? 6u : 5u;
            w[0] = ((static_cast<uint32_t>(offset) << 12) & 0x3FFFF000u)
                 | (((static_cast<uint32_t>(dwords) << 8) + 1792u) & 0x700u)
                 | 40u;
            w[1] = static_cast<uint32_t>(op.u64a - 1u);
            w[2] = op.u32a & 0x7FFFFFFFu;
            w[3] = static_cast<uint32_t>(buffer);
            w[4] = (static_cast<uint32_t>(buffer >> 32) & 0xFFFFu)
                 | (static_cast<uint32_t>(offset) & 0xFFFC0000u);
            if (dwords == 6u) {
                w[5] = static_cast<uint32_t>((offset >> 32) & 0xFFu);
            }
            ampr_strict_write_words(cb, offBytes, w, dwords);
            break;
        }
        case OpType::AprReadGather: {
            const uint64_t offset = op.u64b;
            const uint32_t dwords = (offset >= 0x40000ull) ? 3u : 2u;
            w[0] = ((static_cast<uint32_t>(offset) << 12) & 0x3FFFF000u)
                 | (((static_cast<uint32_t>(dwords) << 8) + 768u) & 0x300u)
                 | 41u;
            w[1] = static_cast<uint32_t>(op.u64a - 1u);
            if (dwords == 3u) {
                w[2] = static_cast<uint32_t>((offset >> 18) & 0x3FFFFFu);
            }
            ampr_strict_write_words(cb, offBytes, w, dwords);
            break;
        }
        case OpType::AprReadScatter: {
            const uint64_t buffer = reinterpret_cast<uint64_t>(op.ptra);
            w[0] = static_cast<uint32_t>((buffer >> 20) & 0x0FFFF000ull) | 0x22Au;
            w[1] = static_cast<uint32_t>(op.u64a - 1u);
            w[2] = static_cast<uint32_t>(buffer);
            ampr_strict_write_words(cb, offBytes, w, 3u);
            break;
        }
        case OpType::AprReadGatherScatter: {
            const uint64_t buffer = reinterpret_cast<uint64_t>(op.ptra);
            const uint64_t offset = op.u64b;
            const uint32_t dwords = ((offset >> 32) != 0) ? 5u : 4u;
            w[0] = ((static_cast<uint32_t>(offset) << 12) & 0x3FFFF000u)
                 | (((static_cast<uint32_t>(dwords) << 8) + 1792u) & 0x700u)
                 | 43u;
            w[1] = static_cast<uint32_t>(op.u64a - 1u);
            w[2] = static_cast<uint32_t>(buffer);
            w[3] = (static_cast<uint32_t>(buffer >> 32) & 0xFFFFu)
                 | (static_cast<uint32_t>(offset) & 0xFFFC0000u);
            if (dwords == 5u) {
                w[4] = static_cast<uint32_t>((offset >> 32) & 0xFFu);
            }
            ampr_strict_write_words(cb, offBytes, w, dwords);
            break;
        }
        case OpType::AprResetGatherScatter: {
            w[0] = 47u;
            ampr_strict_write_words(cb, offBytes, w, 1u);
            break;
        }
        case OpType::AprMapBegin: {
            const uint64_t va = op.u64a;
            const uint64_t size = op.u64b;
            const uint32_t type = static_cast<uint32_t>(op.u64c);
            const uint32_t prot = op.u32a;
            w[0] = ((prot << 12) & 0x07FFF000u)
                 | (type << 27)
                 | 557u;
            w[1] = static_cast<uint32_t>(va >> 14);
            w[2] = static_cast<uint32_t>(((va >> 46) & 3u) | ((size >> 12) & 0x1FFFFFFCull));
            ampr_strict_write_words(cb, offBytes, w, 3u);
            break;
        }
        case OpType::AprMapDirectBegin: {
            const uint64_t va = op.u64a;
            const uint64_t dmemOffset = op.u64b;
            const uint64_t size = op.u64c;
            const uint32_t type = op.u32a;
            const uint32_t prot = op.u32b;
            w[0] = ((prot << 12) & 0x07FFF000u)
                 | (type << 27)
                 | 813u;
            w[1] = static_cast<uint32_t>(va >> 14);
            w[2] = static_cast<uint32_t>(((va >> 46) & 3u) | ((size >> 12) & 0x1FFFFFFCull) | 0x80000000u);
            w[3] = static_cast<uint32_t>((dmemOffset >> 14) & 0x03FFFFFFu);
            ampr_strict_write_words(cb, offBytes, w, 4u);
            break;
        }
        case OpType::AprMapEnd: {
            w[0] = 46u;
            ampr_strict_write_words(cb, offBytes, w, 1u);
            break;
        }
        default:
            return SCE_KERNEL_ERROR_EINVAL;
    }
    return 0;
}

int ampr_strict_write_op(SceAmprCommandBuffer* cb,
                         uint32_t offBytes,
                         const Op& op,
                         uint32_t bytes) {
    PackedOpLayout layout{};
    const int layoutRc = ampr_op_layout_checked(op, &layout);
    if (layoutRc != 0 || bytes == 0u || bytes != layout.bytes) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    return ampr_write_op_with_layout(cb, offBytes, op, layout);
}

static uint32_t ampr_load_packed_u32(const uint8_t* p) {
    uint32_t v = 0;
    std::memcpy(&v, p, sizeof(v));
    return v;
}

static bool ampr_decode_need_dwords(uint32_t byteOffset,
                                    uint32_t totalBytes,
                                    uint32_t dwords,
                                    uint32_t* errorOffset) {
    const uint32_t bytes = dwords * 4u;
    if (dwords == 0 || bytes > totalBytes || byteOffset > totalBytes - bytes) {
        if (errorOffset) {
            *errorOffset = byteOffset;
        }
        return false;
    }
    return true;
}

static bool ampr_decode_need_dwords_range(uint32_t byteOffset,
                                          uint32_t totalBytes,
                                          uint32_t dwords,
                                          uint32_t minDwords,
                                          uint32_t maxDwords,
                                          uint32_t* errorOffset) {
    if (dwords < minDwords || dwords > maxDwords) {
        if (errorOffset) {
            *errorOffset = byteOffset;
        }
        return false;
    }
    return ampr_decode_need_dwords(byteOffset, totalBytes, dwords, errorOffset);
}

static uint64_t ampr_decode_packed_addr(uint32_t highWord, uint32_t lowWord) {
    return (static_cast<uint64_t>(highWord & 0xFFFF0000u) << 16) |
           static_cast<uint64_t>(lowWord);
}

static void ampr_decode_wait_counter_extra(const uint8_t* record, uint32_t dwords, Op& op) {
    if (dwords < 2u) {
        return;
    }

    const uint32_t w1 = ampr_load_packed_u32(record + 4u);
    const uint32_t extraFlag = (w1 >> 28) & 3u;
    op.u8b = static_cast<uint8_t>(((w1 >> 24) & 7u) ^ 1u);
    op.u32c |= extraFlag << 8;

    const uint64_t refLow8 = op.u64a & 0xFFu;
    if (extraFlag != 0u) {
        if (dwords == 2u) {
            op.u64a = refLow8 | (static_cast<uint64_t>(w1 & 0xFFu) << 8);
            op.u64b = (w1 >> 8) & 0xFFFFu;
            return;
        }
        const bool compactRef =
            (w1 & 0x00FFFF00u) == 0u &&
            (dwords < 5u || ampr_load_packed_u32(record + 8u) == 0u);
        if (compactRef) {
            op.u64a = refLow8 | (static_cast<uint64_t>(w1 & 0xFFu) << 8);
            if (dwords == 3u) {
                op.u64b = ampr_load_packed_u32(record + 8u);
            } else if (dwords >= 5u) {
                op.u64b = static_cast<uint64_t>(ampr_load_packed_u32(record + 12u)) |
                          (static_cast<uint64_t>(ampr_load_packed_u32(record + 16u)) << 32);
            }
            return;
        }
    }

    op.u64a = refLow8 | (static_cast<uint64_t>(w1 & 0x00FFFFFFu) << 8);
    if (dwords >= 3u) {
        const uint32_t w2 = ampr_load_packed_u32(record + 8u);
        if (extraFlag == 0u) {
            op.u64a |= static_cast<uint64_t>(w2) << 32;
        } else if (dwords >= 5u) {
            op.u64a |= static_cast<uint64_t>(w2) << 32;
            op.u64b = static_cast<uint64_t>(ampr_load_packed_u32(record + 12u)) |
                      (static_cast<uint64_t>(ampr_load_packed_u32(record + 16u)) << 32);
        } else {
            op.u64b = w2;
        }
    }
}

static uint64_t ampr_decode_amm_va(uint32_t lowWord, uint32_t highBitsWord, uint32_t highShift) {
    return (static_cast<uint64_t>(lowWord) << 14) |
           (static_cast<uint64_t>((highBitsWord >> highShift) & 3u) << 46);
}

static uint32_t ampr_decode_amm_prot(uint32_t w0) {
    return (w0 >> 12) & 0x7FFFu;
}

static uint32_t ampr_decode_amm_prot_without_prt_flag(uint32_t w0) {
    return ((w0 & ~0x8000u) >> 12) & 0x7FFFu;
}

static int ampr_decode_amm_packed_op(const void* buffer,
                                     uint32_t bytes,
                                     uint32_t off,
                                     Op* outOp,
                                     uint32_t* outBytes,
                                     uint32_t* errorOffset) {
    if (!buffer || !outOp || off >= bytes || (off & 3u) != 0) {
        return SCE_KERNEL_ERROR_EINVAL;
    }

    const uint8_t* base = static_cast<const uint8_t*>(buffer) + off;
    const uint32_t w0 = ampr_load_packed_u32(base);
    const uint32_t opcode12 = w0 & 0xFFFu;
    uint32_t dwords = 0;
    Op op{};
    op.bufOffsetBytes = off;

    switch (opcode12) {
        case 0x221u:
        case 0x321u: {
            dwords = (opcode12 == 0x321u) ? 4u : 3u;
            if (!ampr_decode_need_dwords(off, bytes, dwords, errorOffset)) return SCE_KERNEL_ERROR_EINVAL;
            const uint32_t w1 = ampr_load_packed_u32(base + 4u);
            const uint32_t w2 = ampr_load_packed_u32(base + 8u);
            const bool prt = (w0 & 0x8000u) != 0;
            const uint32_t prot = ampr_decode_amm_prot_without_prt_flag(w0);
            op.type = (prt && prot == 0 && ((w0 >> 27) & 0x1Fu) == 0) ? OpType::AmmMapAsPrt : OpType::AmmMap;
            op.u64a = ampr_decode_amm_va(w1, w2, 0);
            op.u64b = static_cast<uint64_t>(w2 & 0x1FFFFFFCu) << 12;
            op.u32a = prot;
            op.u32b = (w0 >> 27) & 0x1Fu;
            op.u32c = prt ? 1u : 0u;
            if (opcode12 == 0x321u) {
                op.u8a = static_cast<uint8_t>(ampr_load_packed_u32(base + 12u));
                op.u8b = 1u;
            }
            break;
        }
        case 0x325u:
        case 0x425u: {
            dwords = (opcode12 == 0x425u) ? 5u : 4u;
            if (!ampr_decode_need_dwords(off, bytes, dwords, errorOffset)) return SCE_KERNEL_ERROR_EINVAL;
            const uint32_t w1 = ampr_load_packed_u32(base + 4u);
            const uint32_t w2 = ampr_load_packed_u32(base + 8u);
            const uint32_t w3 = ampr_load_packed_u32(base + 12u);
            op.type = OpType::AmmMapDirect;
            op.u64a = ampr_decode_amm_va(w1, w2, 0);
            op.u64b = static_cast<uint64_t>(w3 & 0x03FFFFFFu) << 14;
            op.u64c = static_cast<uint64_t>(w2 & 0xFFFFFFFCu) << 9;
            op.u32a = ampr_decode_amm_prot(w0);
            op.u32b = (w0 >> 27) & 0x1Fu;
            if (opcode12 == 0x425u) {
                op.u8a = static_cast<uint8_t>(ampr_load_packed_u32(base + 16u));
                op.u8b = 1u;
            }
            break;
        }
        case 0x222u:
        case 0x228u: {
            dwords = 3u;
            if (!ampr_decode_need_dwords(off, bytes, dwords, errorOffset)) return SCE_KERNEL_ERROR_EINVAL;
            const uint32_t w1 = ampr_load_packed_u32(base + 4u);
            const uint32_t w2 = ampr_load_packed_u32(base + 8u);
            op.type = opcode12 == 0x228u ? OpType::AmmUnmapToPrt : OpType::AmmUnmap;
            op.u64a = ampr_decode_amm_va(w1, w2, 0);
            op.u64b = static_cast<uint64_t>(w2 & 0xFFFFFFFCu) << 9;
            break;
        }
        case 0x323u:
        case 0x423u:
        case 0x324u:
        case 0x424u:
        case 0x327u: {
            dwords = (opcode12 == 0x423u || opcode12 == 0x424u) ? 5u : 4u;
            if (!ampr_decode_need_dwords(off, bytes, dwords, errorOffset)) return SCE_KERNEL_ERROR_EINVAL;
            const uint32_t w1 = ampr_load_packed_u32(base + 4u);
            const uint32_t w2 = ampr_load_packed_u32(base + 8u);
            const uint32_t w3 = ampr_load_packed_u32(base + 12u);
            if (opcode12 == 0x327u) {
                op.type = OpType::AmmRemapIntoPrt;
                op.u32a = ampr_decode_amm_prot_without_prt_flag(w0);
                op.u32b = 1011u;
            } else {
                op.type = (opcode12 == 0x324u || opcode12 == 0x424u) ? OpType::AmmMultiMap : OpType::AmmRemap;
                op.u32a = ampr_decode_amm_prot(w0);
            }
            op.u64a = ampr_decode_amm_va(w1, w3, 0);
            op.u64b = ampr_decode_amm_va(w2, w3, 2);
            op.u64c = static_cast<uint64_t>(w3 & 0xFFFFFFF0u) << 9;
            if (opcode12 == 0x423u || opcode12 == 0x424u) {
                op.u8a = static_cast<uint8_t>(ampr_load_packed_u32(base + 16u));
                op.u8b = 1u;
            }
            break;
        }
        case 0x326u:
        case 0x426u: {
            dwords = (opcode12 == 0x426u) ? 5u : 4u;
            if (!ampr_decode_need_dwords(off, bytes, dwords, errorOffset)) return SCE_KERNEL_ERROR_EINVAL;
            const uint32_t w1 = ampr_load_packed_u32(base + 4u);
            const uint32_t w2 = ampr_load_packed_u32(base + 8u);
            const uint32_t w3 = ampr_load_packed_u32(base + 12u);
            const bool mtype = (w2 & 0x40000000u) != 0 || ((w0 >> 27) & 0x1Fu) != 0;
            op.type = mtype
                ? ((w3 == 1019u && opcode12 == 0x326u) ? OpType::AmmAllocPaForPrt : OpType::AmmModifyMtypeProtect)
                : OpType::AmmModifyProtect;
            op.u64a = ampr_decode_amm_va(w1, w2, 0);
            op.u64b = static_cast<uint64_t>(w2 & 0x1FFFFFFCu) << 12;
            op.u32a = ampr_decode_amm_prot(w0);
            if (mtype) {
                op.u32b = (w0 >> 27) & 0x1Fu;
                op.u32c = w3 & 0x7FFFu;
            } else {
                op.u32b = w3 & 0x7FFFu;
            }
            if (opcode12 == 0x426u) {
                op.u8a = static_cast<uint8_t>(ampr_load_packed_u32(base + 16u));
                op.u8b = 1u;
            }
            break;
        }
        default:
            if (errorOffset) {
                *errorOffset = off;
            }
            return SCE_KERNEL_ERROR_EINVAL;
    }

    *outOp = ampr_move(op);
    if (outBytes) {
        *outBytes = dwords * 4u;
    }
    return 0;
}

int ampr_decode_packed_op(const void* buffer,
                          uint32_t bytes,
                          uint32_t off,
                          Op* outOp,
                          uint32_t* outBytes,
                          uint32_t* errorOffset) {
    if (errorOffset) {
        *errorOffset = 0;
    }
    if (!buffer || !outOp || (bytes & 3u) != 0 || (off & 3u) != 0 || off >= bytes) {
        return SCE_KERNEL_ERROR_EINVAL;
    }

    const uint8_t* base = static_cast<const uint8_t*>(buffer);
    const uint32_t w0 = ampr_load_packed_u32(base + off);
    const uint32_t opcode8 = w0 & 0xFFu;
    const uint32_t opcode12 = w0 & 0xFFFu;
    uint32_t dwords = 0;
    Op op{};
    op.bufOffsetBytes = off;

    if (opcode8 == 1u) {
            dwords = ((w0 >> 8) & 0xFu) + 1u;
            if (!ampr_decode_need_dwords_range(off, bytes, dwords, 2u, 4u, errorOffset)) return SCE_KERNEL_ERROR_EINVAL;
            op.type = OpType::WaitOnAddress;
            op.ptra = reinterpret_cast<void*>(ampr_decode_packed_addr(w0, ampr_load_packed_u32(base + off + 4u)));
            op.u32a = (w0 >> 13) & 7u;
            op.u32c = (w0 >> 12) & 1u;
            if (dwords >= 3u) {
                op.u64a = ampr_load_packed_u32(base + off + 8u);
                if (dwords >= 4u) {
                    op.u64a |= static_cast<uint64_t>(ampr_load_packed_u32(base + off + 12u)) << 32;
                }
            }
        } else if (opcode8 == 2u) {
            dwords = ((w0 >> 8) & 0xFu) + 1u;
            if (!ampr_decode_need_dwords_range(off, bytes, dwords, 1u, 5u, errorOffset) || dwords == 4u) {
                if (errorOffset) *errorOffset = off;
                return SCE_KERNEL_ERROR_EINVAL;
            }
            op.type = OpType::WaitOnCounter;
            op.u8a = static_cast<uint8_t>(w0 >> 24);
            op.u32b = (w0 >> 13) & 7u;
            op.u32c = (w0 >> 12) & 1u;
            op.u64a = (w0 >> 16) & 0xFFu;
            op.u8b = 1u;
            if (dwords >= 2u) {
                ampr_decode_wait_counter_extra(base + off, dwords, op);
            }
        } else if (opcode8 == 5u || opcode8 == 117u) {
            dwords = ((w0 >> 8) & 3u) + 1u;
            if (!ampr_decode_need_dwords_range(off, bytes, dwords, 2u, 4u, errorOffset)) return SCE_KERNEL_ERROR_EINVAL;
            const uint32_t w1 = ampr_load_packed_u32(base + off + 4u);
            const uint32_t addressClass = w1 & 7u;
            const bool atSop = opcode8 == 117u;
            uint64_t value = (w0 >> 12) & 3u;
            if (dwords >= 3u) {
                value |= static_cast<uint64_t>(ampr_load_packed_u32(base + off + 8u)) << 2;
                if (dwords >= 4u) {
                    value |= static_cast<uint64_t>(ampr_load_packed_u32(base + off + 12u)) << 34;
                }
            }
            switch (addressClass) {
                case 1u:
                    op.type = OpType::WriteAddressFromTimeCounter;
                    op.u8b = atSop ? 1u : 0u;
                    break;
                case 2u:
                    op.type = OpType::WriteAddressFromCounter;
                    op.u8a = static_cast<uint8_t>(value);
                    op.u8b = atSop ? 1u : 0u;
                    break;
                case 3u:
                    op.type = OpType::WriteAddressFromCounterPair;
                    op.u8a = static_cast<uint8_t>(value);
                    op.u8b = atSop ? 1u : 0u;
                    break;
                default:
                    op.type = OpType::WriteAddress;
                    op.u64a = value;
                    op.u8a = atSop ? 1u : 0u;
                    break;
            }
            op.ptra = reinterpret_cast<void*>(ampr_decode_packed_addr(w0, w1 & 0xFFFFFFF8u));
        } else if (opcode8 == 6u || opcode8 == 118u) {
            dwords = ((w0 >> 8) & 0xFu) + 1u;
            if (!ampr_decode_need_dwords_range(off, bytes, dwords, 1u, 3u, errorOffset)) return SCE_KERNEL_ERROR_EINVAL;
            op.type = OpType::WriteCounter;
            op.u8a = static_cast<uint8_t>(w0 >> 24);
            op.u32c = opcode8 == 118u ? 1u : 0u;
            op.u64a = (w0 >> 12) & 0xFFFu;
            op.u8b = 1u;
            op.u32b = 0;
            if (dwords >= 2u) {
                const uint32_t w1 = ampr_load_packed_u32(base + off + 4u);
                op.u64a |= static_cast<uint64_t>(w1 & 0xFFFFFu) << 12;
                op.u8b = static_cast<uint8_t>(((w1 >> 20) & 7u) ^ 1u);
                op.u32b = (w1 >> 24) & 7u;
                if (dwords >= 3u) {
                    op.u64a |= static_cast<uint64_t>(ampr_load_packed_u32(base + off + 8u)) << 32;
                }
            }
        } else if (opcode12 == 1032u || opcode12 == 1144u) {
            dwords = 5u;
            if (!ampr_decode_need_dwords(off, bytes, dwords, errorOffset)) return SCE_KERNEL_ERROR_EINVAL;
            op.type = OpType::WriteEqueue;
            op.u8a = opcode12 == 1144u ? 1u : 0u;
            op.u64b = ampr_decode_packed_addr(w0, ampr_load_packed_u32(base + off + 4u));
            op.u32b = ampr_load_packed_u32(base + off + 8u);
            op.u64a = static_cast<uint64_t>(ampr_load_packed_u32(base + off + 12u)) |
                      (static_cast<uint64_t>(ampr_load_packed_u32(base + off + 16u)) << 32);
        } else if ((w0 & 0xFFFF000Fu) == 0x5452000Fu) {
            const uint32_t markerType = (w0 >> 12) & 0xFu;
            const uint32_t payloadDwords = (w0 >> 8) & 0xFu;
            dwords = payloadDwords + 1u;
            if (!ampr_decode_need_dwords(off, bytes, dwords, errorOffset)) return SCE_KERNEL_ERROR_EINVAL;
            if (w0 == 0x5452300Fu) {
                op.type = OpType::MarkerPop;
                dwords = 1u;
            } else if (markerType == 1u || markerType == 5u) {
                op.type = OpType::MarkerSet;
            } else if (markerType == 2u || markerType == 6u) {
                op.type = OpType::MarkerPush;
            } else {
                op.type = OpType::Nop;
                op.u32a = dwords;
            }
        } else if (opcode8 == 40u) {
            dwords = ((w0 >> 8) & 7u) + 1u;
            if (!ampr_decode_need_dwords_range(off, bytes, dwords, 5u, 6u, errorOffset)) return SCE_KERNEL_ERROR_EINVAL;
            const uint32_t w4 = ampr_load_packed_u32(base + off + 16u);
            op.type = OpType::AprReadFile;
            op.u64a = static_cast<uint64_t>(ampr_load_packed_u32(base + off + 4u)) + 1u;
            op.u32a = ampr_load_packed_u32(base + off + 8u) & 0x7FFFFFFFu;
            op.ptra = reinterpret_cast<void*>(
                static_cast<uint64_t>(ampr_load_packed_u32(base + off + 12u)) |
                (static_cast<uint64_t>(w4 & 0xFFFFu) << 32));
            op.u64b = ((w0 >> 12) & 0x3FFFFu) | (w4 & 0xFFFC0000u);
            if (dwords >= 6u) {
                op.u64b |= static_cast<uint64_t>(ampr_load_packed_u32(base + off + 20u) & 0xFFu) << 32;
            }
        } else if (opcode8 == 41u) {
            dwords = ((w0 >> 8) & 3u) + 1u;
            if (!ampr_decode_need_dwords_range(off, bytes, dwords, 2u, 3u, errorOffset)) return SCE_KERNEL_ERROR_EINVAL;
            op.type = OpType::AprReadGather;
            op.u64a = static_cast<uint64_t>(ampr_load_packed_u32(base + off + 4u)) + 1u;
            op.u64b = (w0 >> 12) & 0x3FFFFu;
            if (dwords >= 3u) {
                op.u64b |= static_cast<uint64_t>(ampr_load_packed_u32(base + off + 8u) & 0x3FFFFFu) << 18;
            }
        } else if (opcode12 == 0x22Au) {
            dwords = 3u;
            if (!ampr_decode_need_dwords(off, bytes, dwords, errorOffset)) return SCE_KERNEL_ERROR_EINVAL;
            op.type = OpType::AprReadScatter;
            op.u64a = static_cast<uint64_t>(ampr_load_packed_u32(base + off + 4u)) + 1u;
            op.ptra = reinterpret_cast<void*>(
                static_cast<uint64_t>(ampr_load_packed_u32(base + off + 8u)) |
                (static_cast<uint64_t>((w0 >> 12) & 0xFFFFu) << 32));
        } else if (opcode8 == 43u) {
            dwords = ((w0 >> 8) & 7u) + 1u;
            if (!ampr_decode_need_dwords_range(off, bytes, dwords, 4u, 5u, errorOffset)) return SCE_KERNEL_ERROR_EINVAL;
            const uint32_t w3 = ampr_load_packed_u32(base + off + 12u);
            op.type = OpType::AprReadGatherScatter;
            op.u64a = static_cast<uint64_t>(ampr_load_packed_u32(base + off + 4u)) + 1u;
            op.ptra = reinterpret_cast<void*>(
                static_cast<uint64_t>(ampr_load_packed_u32(base + off + 8u)) |
                (static_cast<uint64_t>(w3 & 0xFFFFu) << 32));
            op.u64b = ((w0 >> 12) & 0x3FFFFu) | (w3 & 0xFFFC0000u);
            if (dwords >= 5u) {
                op.u64b |= static_cast<uint64_t>(ampr_load_packed_u32(base + off + 16u) & 0xFFu) << 32;
            }
        } else if (w0 == 47u) {
            dwords = 1u;
            op.type = OpType::AprResetGatherScatter;
        } else if (opcode12 == 557u) {
            dwords = 3u;
            if (!ampr_decode_need_dwords(off, bytes, dwords, errorOffset)) return SCE_KERNEL_ERROR_EINVAL;
            const uint32_t w1 = ampr_load_packed_u32(base + off + 4u);
            const uint32_t w2 = ampr_load_packed_u32(base + off + 8u);
            op.type = OpType::AprMapBegin;
            op.u32a = (w0 >> 12) & 0x7FFFu;
            op.u32b = (w0 >> 27) & 0x1Fu;
            op.u64c = op.u32b;
            op.u64a = (static_cast<uint64_t>(w1) << 14) |
                      (static_cast<uint64_t>(w2 & 3u) << 46);
            op.u64b = static_cast<uint64_t>(w2 & 0x1FFFFFFCu) << 12;
        } else if (opcode12 == 813u) {
            dwords = 4u;
            if (!ampr_decode_need_dwords(off, bytes, dwords, errorOffset)) return SCE_KERNEL_ERROR_EINVAL;
            const uint32_t w1 = ampr_load_packed_u32(base + off + 4u);
            const uint32_t w2 = ampr_load_packed_u32(base + off + 8u);
            op.type = OpType::AprMapDirectBegin;
            op.u32b = (w0 >> 12) & 0x7FFFu;
            op.u32a = (w0 >> 27) & 0x1Fu;
            op.u64a = (static_cast<uint64_t>(w1) << 14) |
                      (static_cast<uint64_t>(w2 & 3u) << 46);
            op.u64c = static_cast<uint64_t>(w2 & 0x1FFFFFFCu) << 12;
            op.u64b = static_cast<uint64_t>(ampr_load_packed_u32(base + off + 12u) & 0x03FFFFFFu) << 14;
        } else if (w0 == 46u) {
            dwords = 1u;
            op.type = OpType::AprMapEnd;
        } else {
            return ampr_decode_amm_packed_op(buffer, bytes, off, outOp, outBytes, errorOffset);
        }

    *outOp = ampr_move(op);
    if (outBytes) {
        *outBytes = dwords * 4u;
    }
    return 0;
}

int ampr_decode_apr_packed_op(const void* buffer,
                              uint32_t bytes,
                              uint32_t off,
                              Op* outOp,
                              uint32_t* outBytes,
                              uint32_t* errorOffset) {
    return ampr_decode_packed_op(buffer, bytes, off, outOp, outBytes, errorOffset);
}

} // namespace sce::Ampr
