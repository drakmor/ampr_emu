/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Optional submit-time command-buffer dump helpers.
 */

#pragma once

#include "ampr_emu_command_packing.h"
#include "ampr_emu_log.h"

#include <cstdint>
#include <cstring>

#if AMPR_EMU_DEBUG_LOG && AMPR_EMU_SUBMIT_COMMAND_BUFFER_DUMP
static inline void ampr_dump_decoded_op(const char* domain,
                                        const char* label,
                                        uint64_t submitId,
                                        uint32_t ordinal,
                                        uint32_t commandBytes,
                                        const Op& op) {
    const char* d = domain ? domain : "ampr";
    const char* l = label ? label : "unknown";
    switch (op.type) {
        case OpType::WaitOnAddress:
            AMPR_LOGF("%s.cb.dump.%s submit=0x%llx cmd=%u off=0x%x bytes=0x%x type=%s addr=%p ref=0x%llx cmp=%u flush=%u",
                      d, l, static_cast<unsigned long long>(submitId), ordinal,
                      op.bufOffsetBytes, commandBytes, sce::Ampr::ampr_op_name(op.type), op.ptra,
                      static_cast<unsigned long long>(op.u64a), op.u32a, op.u32c);
            break;
        case OpType::WaitOnCounter:
            AMPR_LOGF("%s.cb.dump.%s submit=0x%llx cmd=%u off=0x%x bytes=0x%x type=%s idx=%u n8=%u ref=0x%llx cmp=%u extraFlag=%u extraValue=0x%llx flush=%u",
                      d, l, static_cast<unsigned long long>(submitId), ordinal,
                      op.bufOffsetBytes, commandBytes, sce::Ampr::ampr_op_name(op.type),
                      static_cast<unsigned>(op.u8a), static_cast<unsigned>(op.u8b),
                      static_cast<unsigned long long>(op.u64a), op.u32b,
                      static_cast<unsigned>((op.u32c >> 8) & 3u),
                      static_cast<unsigned long long>(op.u64b),
                      static_cast<unsigned>(op.u32c & 1u));
            break;
        case OpType::WriteAddress:
            AMPR_LOGF("%s.cb.dump.%s submit=0x%llx cmd=%u off=0x%x bytes=0x%x type=%s addr=%p value=0x%llx atSop=%u",
                      d, l, static_cast<unsigned long long>(submitId), ordinal,
                      op.bufOffsetBytes, commandBytes, sce::Ampr::ampr_op_name(op.type), op.ptra,
                      static_cast<unsigned long long>(op.u64a), static_cast<unsigned>(op.u8a));
            break;
        case OpType::WriteCounter:
            AMPR_LOGF("%s.cb.dump.%s submit=0x%llx cmd=%u off=0x%x bytes=0x%x type=%s idx=%u n8=%u value=0x%llx n5=%u atSop=%u",
                      d, l, static_cast<unsigned long long>(submitId), ordinal,
                      op.bufOffsetBytes, commandBytes, sce::Ampr::ampr_op_name(op.type),
                      static_cast<unsigned>(op.u8a), static_cast<unsigned>(op.u8b),
                      static_cast<unsigned long long>(op.u64a), op.u32b, op.u32c);
            break;
        case OpType::WriteEqueue:
            AMPR_LOGF("%s.cb.dump.%s submit=0x%llx cmd=%u off=0x%x bytes=0x%x type=%s eq=%p id=%d data=0x%llx atSop=%u",
                      d, l, static_cast<unsigned long long>(submitId), ordinal,
                      op.bufOffsetBytes, commandBytes, sce::Ampr::ampr_op_name(op.type),
                      reinterpret_cast<void*>(static_cast<uintptr_t>(op.u64b)),
                      static_cast<int32_t>(op.u32b), static_cast<unsigned long long>(op.u64a),
                      static_cast<unsigned>(op.u8a));
            break;
        case OpType::WriteAddressFromTimeCounter:
            AMPR_LOGF("%s.cb.dump.%s submit=0x%llx cmd=%u off=0x%x bytes=0x%x type=%s addr=%p atSop=%u",
                      d, l, static_cast<unsigned long long>(submitId), ordinal,
                      op.bufOffsetBytes, commandBytes, sce::Ampr::ampr_op_name(op.type), op.ptra,
                      static_cast<unsigned>(op.u8b));
            break;
        case OpType::WriteAddressFromCounter:
        case OpType::WriteAddressFromCounterPair:
            AMPR_LOGF("%s.cb.dump.%s submit=0x%llx cmd=%u off=0x%x bytes=0x%x type=%s addr=%p idx=%u atSop=%u",
                      d, l, static_cast<unsigned long long>(submitId), ordinal,
                      op.bufOffsetBytes, commandBytes, sce::Ampr::ampr_op_name(op.type), op.ptra,
                      static_cast<unsigned>(op.u8a), static_cast<unsigned>(op.u8b));
            break;
        case OpType::Nop:
            AMPR_LOGF("%s.cb.dump.%s submit=0x%llx cmd=%u off=0x%x bytes=0x%x type=%s numU32=%u hasData=%u data=%p",
                      d, l, static_cast<unsigned long long>(submitId), ordinal,
                      op.bufOffsetBytes, commandBytes, sce::Ampr::ampr_op_name(op.type),
                      op.u32a, op.u32b, op.cptr);
            break;
        case OpType::MarkerSet:
        case OpType::MarkerPush:
            AMPR_LOGF("%s.cb.dump.%s submit=0x%llx cmd=%u off=0x%x bytes=0x%x type=%s msg=%s",
                      d, l, static_cast<unsigned long long>(submitId), ordinal,
                      op.bufOffsetBytes, commandBytes, sce::Ampr::ampr_op_name(op.type),
                      op.text ? op.text : "");
            break;
        case OpType::MarkerPop:
        case OpType::AprResetGatherScatter:
        case OpType::AprMapEnd:
            AMPR_LOGF("%s.cb.dump.%s submit=0x%llx cmd=%u off=0x%x bytes=0x%x type=%s",
                      d, l, static_cast<unsigned long long>(submitId), ordinal,
                      op.bufOffsetBytes, commandBytes, sce::Ampr::ampr_op_name(op.type));
            break;
        case OpType::AmmMap:
            AMPR_LOGF("%s.cb.dump.%s submit=0x%llx cmd=%u off=0x%x bytes=0x%x type=%s va=0x%llx size=0x%llx typeId=0x%x prot=0x%x prt=%u gpuMaskSet=%u gpuMaskId=%u",
                      d, l, static_cast<unsigned long long>(submitId), ordinal,
                      op.bufOffsetBytes, commandBytes, sce::Ampr::ampr_op_name(op.type),
                      static_cast<unsigned long long>(op.u64a),
                      static_cast<unsigned long long>(op.u64b), op.u32b, op.u32a, op.u32c,
                      static_cast<unsigned>(op.u8b), static_cast<unsigned>(op.u8a));
            break;
        case OpType::AmmMapDirect:
            AMPR_LOGF("%s.cb.dump.%s submit=0x%llx cmd=%u off=0x%x bytes=0x%x type=%s va=0x%llx dmemOff=0x%llx size=0x%llx typeId=0x%x prot=0x%x gpuMaskSet=%u gpuMaskId=%u",
                      d, l, static_cast<unsigned long long>(submitId), ordinal,
                      op.bufOffsetBytes, commandBytes, sce::Ampr::ampr_op_name(op.type),
                      static_cast<unsigned long long>(op.u64a),
                      static_cast<unsigned long long>(op.u64b),
                      static_cast<unsigned long long>(op.u64c), op.u32b, op.u32a,
                      static_cast<unsigned>(op.u8b), static_cast<unsigned>(op.u8a));
            break;
        case OpType::AmmUnmap:
        case OpType::AmmUnmapToPrt:
        case OpType::AmmMapAsPrt:
            AMPR_LOGF("%s.cb.dump.%s submit=0x%llx cmd=%u off=0x%x bytes=0x%x type=%s va=0x%llx size=0x%llx",
                      d, l, static_cast<unsigned long long>(submitId), ordinal,
                      op.bufOffsetBytes, commandBytes, sce::Ampr::ampr_op_name(op.type),
                      static_cast<unsigned long long>(op.u64a),
                      static_cast<unsigned long long>(op.u64b));
            break;
        case OpType::AmmRemap:
        case OpType::AmmMultiMap:
            AMPR_LOGF("%s.cb.dump.%s submit=0x%llx cmd=%u off=0x%x bytes=0x%x type=%s vaNew=0x%llx vaOldOrAlias=0x%llx size=0x%llx prot=0x%x gpuMaskSet=%u gpuMaskId=%u",
                      d, l, static_cast<unsigned long long>(submitId), ordinal,
                      op.bufOffsetBytes, commandBytes, sce::Ampr::ampr_op_name(op.type),
                      static_cast<unsigned long long>(op.u64a),
                      static_cast<unsigned long long>(op.u64b),
                      static_cast<unsigned long long>(op.u64c), op.u32a,
                      static_cast<unsigned>(op.u8b), static_cast<unsigned>(op.u8a));
            break;
        case OpType::AmmModifyProtect:
            AMPR_LOGF("%s.cb.dump.%s submit=0x%llx cmd=%u off=0x%x bytes=0x%x type=%s va=0x%llx size=0x%llx prot=0x%x protMask=0x%x gpuMaskSet=%u gpuMaskId=%u",
                      d, l, static_cast<unsigned long long>(submitId), ordinal,
                      op.bufOffsetBytes, commandBytes, sce::Ampr::ampr_op_name(op.type),
                      static_cast<unsigned long long>(op.u64a),
                      static_cast<unsigned long long>(op.u64b), op.u32a, op.u32b,
                      static_cast<unsigned>(op.u8b), static_cast<unsigned>(op.u8a));
            break;
        case OpType::AmmModifyMtypeProtect:
        case OpType::AmmAllocPaForPrt:
            AMPR_LOGF("%s.cb.dump.%s submit=0x%llx cmd=%u off=0x%x bytes=0x%x type=%s va=0x%llx size=0x%llx typeId=0x%x prot=0x%x protMask=0x%x gpuMaskSet=%u gpuMaskId=%u",
                      d, l, static_cast<unsigned long long>(submitId), ordinal,
                      op.bufOffsetBytes, commandBytes, sce::Ampr::ampr_op_name(op.type),
                      static_cast<unsigned long long>(op.u64a),
                      static_cast<unsigned long long>(op.u64b), op.u32b, op.u32a, op.u32c,
                      static_cast<unsigned>(op.u8b), static_cast<unsigned>(op.u8a));
            break;
        case OpType::AmmRemapIntoPrt:
            AMPR_LOGF("%s.cb.dump.%s submit=0x%llx cmd=%u off=0x%x bytes=0x%x type=%s vaPrt=0x%llx vaOld=0x%llx size=0x%llx prot=0x%x opcode=0x%x",
                      d, l, static_cast<unsigned long long>(submitId), ordinal,
                      op.bufOffsetBytes, commandBytes, sce::Ampr::ampr_op_name(op.type),
                      static_cast<unsigned long long>(op.u64a),
                      static_cast<unsigned long long>(op.u64b),
                      static_cast<unsigned long long>(op.u64c), op.u32a, op.u32b);
            break;
        case OpType::AprMapBegin:
        case OpType::AprMapDirectBegin:
            AMPR_LOGF("%s.cb.dump.%s submit=0x%llx cmd=%u off=0x%x bytes=0x%x type=%s va=0x%llx size=0x%llx aux=0x%llx typeId=0x%x prot=0x%x",
                      d, l, static_cast<unsigned long long>(submitId), ordinal,
                      op.bufOffsetBytes, commandBytes, sce::Ampr::ampr_op_name(op.type),
                      static_cast<unsigned long long>(op.u64a),
                      static_cast<unsigned long long>(op.u64b),
                      static_cast<unsigned long long>(op.u64c), op.u32a, op.u32b);
            break;
        case OpType::AprReadFile:
            AMPR_LOGF("%s.cb.dump.%s submit=0x%llx cmd=%u off=0x%x bytes=0x%x type=%s fileId=%u buf=%p len=0x%llx fileOff=0x%llx",
                      d, l, static_cast<unsigned long long>(submitId), ordinal,
                      op.bufOffsetBytes, commandBytes, sce::Ampr::ampr_op_name(op.type),
                      op.u32a, op.ptra, static_cast<unsigned long long>(op.u64a),
                      static_cast<unsigned long long>(op.u64b));
            break;
        case OpType::AprReadGather:
            AMPR_LOGF("%s.cb.dump.%s submit=0x%llx cmd=%u off=0x%x bytes=0x%x type=%s len=0x%llx fileOff=0x%llx",
                      d, l, static_cast<unsigned long long>(submitId), ordinal,
                      op.bufOffsetBytes, commandBytes, sce::Ampr::ampr_op_name(op.type),
                      static_cast<unsigned long long>(op.u64a),
                      static_cast<unsigned long long>(op.u64b));
            break;
        case OpType::AprReadScatter:
            AMPR_LOGF("%s.cb.dump.%s submit=0x%llx cmd=%u off=0x%x bytes=0x%x type=%s buf=%p len=0x%llx",
                      d, l, static_cast<unsigned long long>(submitId), ordinal,
                      op.bufOffsetBytes, commandBytes, sce::Ampr::ampr_op_name(op.type),
                      op.ptra, static_cast<unsigned long long>(op.u64a));
            break;
        case OpType::AprReadGatherScatter:
            AMPR_LOGF("%s.cb.dump.%s submit=0x%llx cmd=%u off=0x%x bytes=0x%x type=%s buf=%p len=0x%llx fileOff=0x%llx",
                      d, l, static_cast<unsigned long long>(submitId), ordinal,
                      op.bufOffsetBytes, commandBytes, sce::Ampr::ampr_op_name(op.type),
                      op.ptra, static_cast<unsigned long long>(op.u64a),
                      static_cast<unsigned long long>(op.u64b));
            break;
        default:
            AMPR_LOGF("%s.cb.dump.%s submit=0x%llx cmd=%u off=0x%x bytes=0x%x type=%s a=0x%llx b=0x%llx c=0x%llx u32a=0x%x u32b=0x%x u32c=0x%x ptra=%p cptr=%p",
                      d, l, static_cast<unsigned long long>(submitId), ordinal,
                      op.bufOffsetBytes, commandBytes, sce::Ampr::ampr_op_name(op.type),
                      static_cast<unsigned long long>(op.u64a),
                      static_cast<unsigned long long>(op.u64b),
                      static_cast<unsigned long long>(op.u64c), op.u32a, op.u32b, op.u32c,
                      op.ptra, op.cptr);
            break;
    }
}

static inline uint32_t ampr_dump_load_u32_unaligned(const uint8_t* data, uint32_t bytes, uint32_t off) {
    uint32_t value = 0;
    if (data && off < bytes) {
        const uint32_t available = (bytes - off) < 4u ? (bytes - off) : 4u;
        std::memcpy(&value, data + off, available);
    }
    return value;
}

static inline void ampr_dump_decoded_command_buffer(const char* domain,
                                                    const char* label,
                                                    uint64_t submitId,
                                                    const void* buffer,
                                                    uint32_t bytes,
                                                    uint32_t capacity,
                                                    uint32_t commandCount,
                                                    uint32_t prio,
                                                    uint32_t type) {
    if (!ampr_debug_log_runtime_enabled()) {
        return;
    }
    const char* d = domain ? domain : "ampr";
    const char* l = label ? label : "unknown";

    AMPR_LOGF("%s.cb.dump.%s begin submit=0x%llx prio=%u cb=%p bytes=0x%x capacity=0x%x commands=%u type=0x%x decoded=ampr",
              d,
              l,
              static_cast<unsigned long long>(submitId),
              prio,
              buffer,
              bytes,
              capacity,
              commandCount,
              type);
    if (!buffer || bytes == 0) {
        AMPR_LOGF("%s.cb.dump.%s empty submit=0x%llx",
                  d,
                  l,
                  static_cast<unsigned long long>(submitId));
        AMPR_LOGF("%s.cb.dump.%s end submit=0x%llx",
                  d,
                  l,
                  static_cast<unsigned long long>(submitId));
        return;
    }

    uint32_t off = 0;
    uint32_t ordinal = 0;
    const auto* data = static_cast<const uint8_t*>(buffer);
    while (off < bytes) {
        Op op{};
        uint32_t commandBytes = 0;
        uint32_t errorOffset = 0;
        const int rc = sce::Ampr::ampr_decode_packed_op(buffer,
                                                        bytes,
                                                        off,
                                                        &op,
                                                        &commandBytes,
                                                        &errorOffset);
        if (rc != 0 || commandBytes == 0) {
            AMPR_LOGF("%s.cb.dump.%s submit=0x%llx decode-fail cmd=%u off=0x%x errorOff=0x%x rc=0x%x word0=0x%x",
                      d,
                      l,
                      static_cast<unsigned long long>(submitId),
                      ordinal,
                      off,
                      errorOffset,
                      rc,
                      ampr_dump_load_u32_unaligned(data, bytes, off));
            break;
        }
        ampr_dump_decoded_op(d, l, submitId, ordinal, commandBytes, op);
        off += commandBytes;
        ++ordinal;
    }
    if (off != bytes) {
        AMPR_LOGF("%s.cb.dump.%s submit=0x%llx trailing=0x%x decodedBytes=0x%x totalBytes=0x%x",
                  d,
                  l,
                  static_cast<unsigned long long>(submitId),
                  bytes - off,
                  off,
                  bytes);
    }
    AMPR_LOGF("%s.cb.dump.%s end submit=0x%llx",
              d,
              l,
              static_cast<unsigned long long>(submitId));
}
#else
[[maybe_unused]] static inline void ampr_dump_decoded_command_buffer(const char*,
                                                                     const char*,
                                                                     uint64_t,
                                                                     const void*,
                                                                     uint32_t,
                                                                     uint32_t,
                                                                     uint32_t,
                                                                     uint32_t,
                                                                     uint32_t) {}
#endif
