/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Shared AMM/APR command-buffer API implementation.
 */

#define AMPR_EMU_CORE_IMPL 1
#include "ampr_emu_command_buffer_types.h"
#include "ampr_emu_command_buffer_common.h"
#include "ampr_emu_command_buffer_apr.h"
#include "ampr_emu_command_packing.h"
#include "ampr_emu_errno.h"
#include "ampr_emu_log.h"
#include "ampr_emu_sync.h"

#include <cstring>

namespace {

constexpr uint64_t kRetailVaMax = 0xF00000000000ull;

static inline void ampr_cb_set_type_mask(SceAmprCommandBuffer& cb, uint32_t mask) {
    cb.type = static_cast<int>(static_cast<uint32_t>(cb.type) | mask);
}

static inline void ampr_cb_clear_type_mask(SceAmprCommandBuffer& cb, uint32_t mask) {
    cb.type = static_cast<int>(static_cast<uint32_t>(cb.type) & ~mask);
}

static int ampr_reject_completion_write_in_apr_map(SceAmprCommandBuffer* cb) {
    if (!ampr_cb_has_type_mask(cb, kAprMapActiveTypeMask)) {
        return 0;
    }
    return SCE_KERNEL_ERROR_EPERM;
}

static bool ampr_set_marker_text(Op& op, const char* text) {
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

#if AMPR_EMU_DEBUG_LOG && AMPR_EMU_DEBUG_LOG_TRACE
static void ampr_log_op_detail(const char* phase, const Op& op) {
    const char* p = phase ? phase : "op";
    switch (op.type) {
        case OpType::WaitOnAddress:
            AMPR_LOGF("%s type=%s off=0x%x addr=%p ref=0x%llx cmp=%u flush=%u",
                      p, sce::Ampr::ampr_op_name(op.type), op.bufOffsetBytes, op.ptra,
                      (unsigned long long)op.u64a, op.u32a, op.u32c);
            break;
        case OpType::WaitOnCounter:
            AMPR_LOGF("%s type=%s off=0x%x idx=%u n8=%u ref=0x%llx cmp=%u extraFlag=%u extraValue=0x%llx flush=%u",
                      p, sce::Ampr::ampr_op_name(op.type), op.bufOffsetBytes, (unsigned)op.u8a,
                      (unsigned)op.u8b, (unsigned long long)op.u64a, op.u32b,
                      (unsigned)((op.u32c >> 8) & 3u), (unsigned long long)op.u64b,
                      (unsigned)(op.u32c & 1u));
            break;
        case OpType::WriteAddress:
            AMPR_LOGF("%s type=%s off=0x%x addr=%p value=0x%llx atSop=%u opcode=0x%x",
                      p, sce::Ampr::ampr_op_name(op.type), op.bufOffsetBytes, op.ptra,
                      (unsigned long long)op.u64a, (unsigned)op.u8a, op.u8a ? 117u : 5u);
            break;
        case OpType::WriteCounter:
            AMPR_LOGF("%s type=%s off=0x%x idx=%u n8=%u value=0x%llx n5=%u atSop=%u opcode=0x%x",
                      p, sce::Ampr::ampr_op_name(op.type), op.bufOffsetBytes, (unsigned)op.u8a,
                      (unsigned)op.u8b, (unsigned long long)op.u64a, op.u32b, op.u32c,
                      op.u32c ? 118u : 6u);
            break;
        case OpType::WriteEqueue:
            AMPR_LOGF("%s type=%s off=0x%x eq=%p id=%d data=0x%llx atSop=%u opcode=0x%x",
                      p, sce::Ampr::ampr_op_name(op.type), op.bufOffsetBytes, (void*)(uintptr_t)op.u64b,
                      (int32_t)op.u32b, (unsigned long long)op.u64a, (unsigned)op.u8a,
                      op.u8a ? 1144u : 1032u);
            break;
        case OpType::WriteAddressFromTimeCounter:
            AMPR_LOGF("%s type=%s off=0x%x addr=%p atSop=%u opcode=0x%x",
                      p, sce::Ampr::ampr_op_name(op.type), op.bufOffsetBytes, op.ptra,
                      (unsigned)op.u8b, op.u8b ? 117u : 5u);
            break;
        case OpType::WriteAddressFromCounter:
        case OpType::WriteAddressFromCounterPair:
            AMPR_LOGF("%s type=%s off=0x%x addr=%p idx=%u atSop=%u opcode=0x%x",
                      p, sce::Ampr::ampr_op_name(op.type), op.bufOffsetBytes, op.ptra, (unsigned)op.u8a,
                      (unsigned)op.u8b, op.u8b ? 117u : 5u);
            break;
        case OpType::Nop:
            AMPR_LOGF("%s type=%s off=0x%x numU32=%u hasData=%u data=%p",
                      p, sce::Ampr::ampr_op_name(op.type), op.bufOffsetBytes, op.u32a, op.u32b, op.cptr);
            break;
        case OpType::MarkerSet:
        case OpType::MarkerPush:
            AMPR_LOGF("%s type=%s off=0x%x msg=%s",
                      p, sce::Ampr::ampr_op_name(op.type), op.bufOffsetBytes,
                      op.text ? op.text : "");
            break;
        case OpType::MarkerPop:
        case OpType::AprResetGatherScatter:
        case OpType::AprMapEnd:
            AMPR_LOGF("%s type=%s off=0x%x",
                      p, sce::Ampr::ampr_op_name(op.type), op.bufOffsetBytes);
            break;
        case OpType::AprMapBegin:
            AMPR_LOGF("%s type=%s off=0x%x a=0x%llx b=0x%llx c=0x%llx u32a=0x%x u32b=0x%x",
                      p, sce::Ampr::ampr_op_name(op.type), op.bufOffsetBytes,
                      (unsigned long long)op.u64a, (unsigned long long)op.u64b,
                      (unsigned long long)op.u64c, op.u32a, op.u32b);
            break;
        case OpType::AprMapDirectBegin:
            AMPR_LOGF("%s type=%s off=0x%x a=0x%llx b=0x%llx c=0x%llx u32a=0x%x u32b=0x%x",
                      p, sce::Ampr::ampr_op_name(op.type), op.bufOffsetBytes,
                      (unsigned long long)op.u64a, (unsigned long long)op.u64b,
                      (unsigned long long)op.u64c, op.u32a, op.u32b);
            break;
        case OpType::AprReadFile:
            AMPR_LOGF("%s type=%s off=0x%x fileId=%u buf=%p len=0x%llx offFile=0x%llx",
                      p, sce::Ampr::ampr_op_name(op.type), op.bufOffsetBytes, op.u32a,
                      op.ptra, (unsigned long long)op.u64a, (unsigned long long)op.u64b);
            break;
        case OpType::AprReadGather:
            AMPR_LOGF("%s type=%s off=0x%x len=0x%llx offFile=0x%llx",
                      p, sce::Ampr::ampr_op_name(op.type), op.bufOffsetBytes,
                      (unsigned long long)op.u64a, (unsigned long long)op.u64b);
            break;
        case OpType::AprReadScatter:
            AMPR_LOGF("%s type=%s off=0x%x buf=%p len=0x%llx",
                      p, sce::Ampr::ampr_op_name(op.type), op.bufOffsetBytes, op.ptra,
                      (unsigned long long)op.u64a);
            break;
        case OpType::AprReadGatherScatter:
            AMPR_LOGF("%s type=%s off=0x%x buf=%p len=0x%llx offFile=0x%llx",
                      p, sce::Ampr::ampr_op_name(op.type), op.bufOffsetBytes, op.ptra,
                      (unsigned long long)op.u64a, (unsigned long long)op.u64b);
            break;
        default:
            AMPR_LOGF("%s type=%s off=0x%x a=0x%llx b=0x%llx c=0x%llx u32a=0x%x u32b=0x%x u32c=0x%x ptra=%p cptr=%p",
                      p, sce::Ampr::ampr_op_name(op.type), op.bufOffsetBytes,
                      (unsigned long long)op.u64a, (unsigned long long)op.u64b,
                      (unsigned long long)op.u64c, op.u32a, op.u32b, op.u32c, op.ptra, op.cptr);
            break;
    }
}
#else
#define ampr_log_op_detail(...) ((void)0)
#endif

static bool ampr_valid_wait_compare_04_00(sce::Ampr::WaitCompare c) {
    return (uint32_t)c <= 6u;
}

static bool ampr_valid_wait_compare_modern(sce::Ampr::WaitCompare c) {
    return (uint32_t)c < 4u;
}

static bool ampr_valid_u64_wait_addr(uint64_t addr) {
    return ((addr & 7ull) == 0ull) && addr <= kRetailVaMax && 8ull <= (kRetailVaMax - addr);
}

static bool ampr_valid_u64_wait_addr_04_00(uint64_t addr) {
    return addr != 0ull && ampr_valid_u64_wait_addr(addr);
}

static bool ampr_valid_u64_write_addr(uint64_t addr) {
    return addr != 0ull && ampr_valid_u64_wait_addr(addr);
}

static bool ampr_valid_counter_index_signed7(uint8_t counterIndex) {
    return (counterIndex & 0x80u) == 0u;
}

static bool ampr_valid_wait_counter_04_00(uint8_t valueWidth,
                                          sce::Ampr::WaitCompare eCmp,
                                          uint8_t extraFlag,
                                          sce::Ampr::WaitFlush eFlush) {
    return valueWidth < 8u &&
           ampr_valid_wait_compare_04_00(eCmp) &&
           extraFlag < 2u &&
           sce::Ampr::ampr_valid_wait_flush(eFlush);
}

static bool ampr_valid_wait_counter_modern(uint8_t counterIndex,
                                           sce::Ampr::WaitCompare eCmp,
                                           sce::Ampr::WaitFlush eFlush) {
    return ampr_valid_counter_index_signed7(counterIndex) &&
           ampr_valid_wait_compare_modern(eCmp) &&
           sce::Ampr::ampr_valid_wait_flush(eFlush);
}

static bool ampr_valid_write_counter_04_00(uint8_t counterIndex, uint8_t valueWidth, uint8_t counterMode) {
    return ampr_valid_counter_index_signed7(counterIndex) &&
           valueWidth < 8u &&
           counterMode < 5u;
}

} // namespace
namespace sce::Ampr {

static void cb_reset_recording_position(SceAmprCommandBuffer& cb) {
    cb.offset = 0;
    cb.num = 0;
}

CommandBuffer::CommandBuffer(void) {
    AMPR_TLOGF("[apr-cb-00] CommandBuffer ctor enter this=%p cb=%p", this, &m_commandBuffer);
    // Avoid libc mem* during early PRX construction.
    m_commandBuffer.type = 0;
    m_commandBuffer.offset = 0;
    m_commandBuffer.num = 0;
    m_commandBuffer.bufsize = 0;
    m_commandBuffer.buffer = nullptr;
    AMPR_TLOGF("[apr-cb-01] CommandBuffer ctor leave this=%p cb=%p", this, &m_commandBuffer);
}
CommandBuffer::~CommandBuffer(void) {
    AMPR_TLOGF("cb.dtor this=%p cb=%p", this, &m_commandBuffer);
}


int CommandBuffer::setBuffer(void* buffer, uint32_t size) {
    if (!buffer) {
        AMPR_LOGF("cb.setBuffer reject cb=%p rc=0x%x reason=null-buffer", &m_commandBuffer, SCE_KERNEL_ERROR_EINVAL);
        return SCE_KERNEL_ERROR_EINVAL;
    }
    if (m_commandBuffer.buffer) {
        if (m_commandBuffer.buffer == buffer && m_commandBuffer.bufsize == size) {
            AMPR_TLOGF("cb.setBuffer reject cb=%p rc=0x%x reason=same-binding",
                       &m_commandBuffer, SCE_KERNEL_ERROR_EBUSY);
        } else {
            AMPR_LOGF("cb.setBuffer reject cb=%p rc=0x%x reason=already-bound",
                      &m_commandBuffer, SCE_KERNEL_ERROR_EBUSY);
        }
        return SCE_KERNEL_ERROR_EBUSY;
    }
    if (((uintptr_t)buffer & 3u) != 0) {
        AMPR_LOGF("cb.setBuffer reject cb=%p rc=0x%x reason=unaligned-buffer align=0x%llx",
                  &m_commandBuffer, SCE_KERNEL_ERROR_EINVAL, (unsigned long long)((uintptr_t)buffer & 3u));
        return SCE_KERNEL_ERROR_EINVAL;
    }
    if (size == 0 || (size & 3u) != 0) {
        AMPR_LOGF("cb.setBuffer reject cb=%p rc=0x%x reason=bad-size size=0x%x",
                  &m_commandBuffer, SCE_KERNEL_ERROR_EINVAL, size);
        return SCE_KERNEL_ERROR_EINVAL;
    }
    if (size > (uint32_t)SCE_AMPR_APR_BUFFER_MAX) {
        AMPR_LOGF("cb.setBuffer reject cb=%p rc=0x%x reason=size-too-big size=0x%x max=0x%x",
                  &m_commandBuffer, SCE_KERNEL_ERROR_EINVAL, size, (uint32_t)SCE_AMPR_APR_BUFFER_MAX);
        return SCE_KERNEL_ERROR_EINVAL;
    }
    m_commandBuffer.buffer = buffer;
    m_commandBuffer.bufsize = size;
    return 0;
}


void* CommandBuffer::clearBuffer(void) {
    AMPR_TLOGF("cb.clearBuffer enter this=%p cb=%p", this, &m_commandBuffer);
    if (!m_commandBuffer.bufsize || !m_commandBuffer.buffer) {
        AMPR_TLOGF("cb.clearBuffer leave this=%p cb=%p result=null reason=no-buffer", this, &m_commandBuffer);
        return nullptr;
    }
    void* const p = m_commandBuffer.buffer;
    m_commandBuffer.buffer = nullptr;
    m_commandBuffer.bufsize = 0;
    AMPR_TLOGF("cb.clearBuffer leave this=%p cb=%p result=%p", this, &m_commandBuffer, p);
    return p;
}

int CommandBuffer::getType() const { return m_commandBuffer.type; }
uint32_t CommandBuffer::getSize() const { return m_commandBuffer.bufsize; }
caddr_t CommandBuffer::getBufferBaseAddress() const { return (caddr_t)m_commandBuffer.buffer; }
uint32_t CommandBuffer::getNumCommands() const { return (uint32_t)m_commandBuffer.num; }
uint32_t CommandBuffer::getCurrentOffset() const { return m_commandBuffer.offset; }

int cb_append_with_type_mask(SceAmprCommandBuffer* cb, Op&& op, uint32_t setMask, uint32_t clearMask) {
    if (!cb) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    if (!cb->buffer) {
        return SCE_KERNEL_ERROR_EPERM;
    }

    uint32_t sz = 0;
    int sizeRc = ampr_op_size_bytes_checked(op, &sz);
    if (sizeRc != 0 || sz == 0) {
        return sizeRc ? sizeRc : SCE_KERNEL_ERROR_EINVAL;
    }
    const uint32_t commandCount = ampr_native_op_command_count(op);
    const uint32_t off = cb->offset;
    op.bufOffsetBytes = off;
    // Match the SDK EBUSY path for full command buffers.
    if (sz > cb->bufsize || off > cb->bufsize - sz) {
        return SCE_KERNEL_ERROR_EBUSY;
    }
    if (cb->num < 0 ||
        commandCount > static_cast<uint32_t>(INT32_MAX) ||
        cb->num > static_cast<int>(static_cast<uint32_t>(INT32_MAX) - commandCount)) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    const int writeRc = ampr_strict_write_op(cb, off, op, sz);
    if (writeRc != 0) {
        return writeRc;
    }
    const uint32_t nextOff = off + sz;
    cb->num += static_cast<int32_t>(commandCount);
    cb->offset = nextOff;
    if (setMask) {
        ampr_cb_set_type_mask(*cb, setMask);
    }
    if (clearMask) {
        ampr_cb_clear_type_mask(*cb, clearMask);
    }
    AMPR_TLOGF("cb.append.size cb=%p type=%s off=0x%x size=0x%x next=0x%x bufsize=0x%x",
              cb, sce::Ampr::ampr_op_name(op.type), off, sz, nextOff, cb->bufsize);
    ampr_log_op_detail("cb.append.op", op);
    return 0;
}

int cb_append(SceAmprCommandBuffer* cb, Op&& op) {
    return cb_append_with_type_mask(cb, ampr_move(op), 0u, 0u);
}

int CommandBuffer::waitOnAddress(volatile uint64_t* address, uint64_t refValue, WaitCompare eCmp, WaitFlush eFlush) {
    if (!ampr_valid_u64_wait_addr(reinterpret_cast<uint64_t>(address)) ||
        !ampr_valid_wait_compare_modern(eCmp) ||
        !ampr_valid_wait_flush(eFlush)) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    Op op{};
    op.type = OpType::WaitOnAddress;
    op.ptra = const_cast<uint64_t*>(address);
    op.u64a = refValue;
    op.u32a = static_cast<uint32_t>(eCmp);
    op.u32c = static_cast<uint32_t>(eFlush);
    return cb_append(&m_commandBuffer, ampr_move(op));
}

int CommandBuffer::waitOnAddress_04_00(volatile uint64_t* address, uint64_t refValue, WaitCompare eCmp, WaitFlush eFlush) {
    if (!ampr_valid_u64_wait_addr_04_00(reinterpret_cast<uint64_t>(address)) ||
        !ampr_valid_wait_compare_04_00(eCmp) ||
        !ampr_valid_wait_flush(eFlush)) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    Op op{};
    op.type = OpType::WaitOnAddress;
    op.ptra = const_cast<uint64_t*>(address);
    op.u64a = refValue;
    op.u32a = static_cast<uint32_t>(eCmp);
    op.u32c = static_cast<uint32_t>(eFlush);
    return cb_append(&m_commandBuffer, ampr_move(op));
}

int CommandBuffer::waitOnCounter_04_00(uint8_t counterIndex, uint8_t valueWidth, uint64_t refValue, WaitCompare eCmp, uint8_t extraFlag, uint64_t extraValue, WaitFlush eFlush) {
    if (!ampr_valid_wait_counter_04_00(valueWidth, eCmp, extraFlag, eFlush)) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    Op op{};
    op.type = OpType::WaitOnCounter;
    op.u8a = counterIndex;
    op.u8b = valueWidth;
    op.u32a = static_cast<uint32_t>(refValue);
    op.u64a = refValue;
    op.u64b = extraValue;
    op.u32b = static_cast<uint32_t>(eCmp);
    op.u32c = (static_cast<uint32_t>(eFlush) & 1u) |
              ((static_cast<uint32_t>(extraFlag) & 3u) << 8);
    return cb_append(&m_commandBuffer, ampr_move(op));
}

int CommandBuffer::waitOnCounter(uint8_t counterIndex, uint32_t refValue, WaitCompare eCmp, WaitFlush eFlush) {
    if (!ampr_valid_wait_counter_modern(counterIndex, eCmp, eFlush)) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    Op op{};
    op.type = OpType::WaitOnCounter;
    op.u8a = counterIndex;
    op.u8b = 1;
    op.u32a = refValue;
    op.u64a = refValue;
    op.u64b = 0;
    op.u32b = static_cast<uint32_t>(eCmp);
    op.u32c = static_cast<uint32_t>(eFlush) & 1u;
    return cb_append(&m_commandBuffer, ampr_move(op));
}

int CommandBuffer::waitOnCounter(uint8_t counterIndex, CounterAccessSizeAndOffset eAccessSizeAndOffset, uint64_t refValue, WaitCompare eCmp, WaitOnCounterMaskOperation eMaskOp, uint64_t mask, WaitFlush eFlush) {
    return waitOnCounter_04_00(counterIndex, (uint8_t)eAccessSizeAndOffset, refValue, eCmp, (uint8_t)eMaskOp, mask, eFlush);
}

int CommandBuffer::waitOnCounter(uint8_t counterIndex, CounterAccessSizeAndOffset eAccessSizeAndOffset, uint64_t refValue, WaitCompare eCmp, WaitFlush eFlush) {
    return waitOnCounter_04_00(counterIndex, (uint8_t)eAccessSizeAndOffset, refValue, eCmp, (uint8_t)WaitOnCounterMaskOperation::kDisabled, 0, eFlush);
}

int CommandBuffer::waitOnCounter(uint8_t counterIndex, uint32_t refValue, WaitCompare eCmp, WaitOnCounterMaskOperation eMaskOp, uint32_t mask, WaitFlush eFlush) {
    return waitOnCounter_04_00(counterIndex, (uint8_t)CounterAccessSizeAndOffset::kSize4, refValue, eCmp, (uint8_t)eMaskOp, mask, eFlush);
}

int CommandBuffer::writeAddress_04_00(volatile uint64_t* address, uint64_t value, bool atSop) {
    if (!ampr_valid_u64_write_addr(reinterpret_cast<uint64_t>(address))) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    if (!atSop) {
        const int mapRc = ampr_reject_completion_write_in_apr_map(&m_commandBuffer);
        if (mapRc != 0) {
            return mapRc;
        }
    }
    Op op{};
    op.type = OpType::WriteAddress;
    op.ptra = const_cast<uint64_t*>(address);
    op.u64a = value;
    op.u8a = atSop ? 1u : 0u;
    return cb_append(&m_commandBuffer, ampr_move(op));
}

int CommandBuffer::writeAddressOnCompletion(volatile uint64_t* address, uint64_t value) {
    return writeAddress_04_00(address, value, false);
}

int CommandBuffer::writeAddressImmediately(volatile uint64_t* address, uint64_t value) {
    return writeAddress_04_00(address, value, true);
}

int CommandBuffer::writeCounter_04_00(uint8_t counterIndex, uint8_t valueWidth, uint64_t value, uint8_t counterMode, bool atSop) {
    if (!ampr_valid_write_counter_04_00(counterIndex, valueWidth, counterMode)) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    if (!atSop) {
        const int mapRc = ampr_reject_completion_write_in_apr_map(&m_commandBuffer);
        if (mapRc != 0) {
            return mapRc;
        }
    }
    Op op{};
    op.type = OpType::WriteCounter;
    op.u8a = counterIndex;
    op.u8b = valueWidth;
    op.u64a = value;
    op.u32a = static_cast<uint32_t>(value);
    op.u32b = counterMode;
    op.u32c = atSop ? 1u : 0u;
    return cb_append(&m_commandBuffer, ampr_move(op));
}

int CommandBuffer::writeCounterOnCompletion(uint8_t counterIndex, uint32_t value) {
    return writeCounter_04_00(counterIndex, 1, value, 0, false);
}

int CommandBuffer::writeCounterOnCompletion(uint8_t counterIndex, CounterAccessSizeAndOffset eAccessSizeAndOffset, uint64_t value, WriteCounterOperation eWriteOp) {
    return writeCounter_04_00(counterIndex, (uint8_t)eAccessSizeAndOffset, value, (uint8_t)eWriteOp, false);
}

int CommandBuffer::writeCounterOnCompletion(uint8_t counterIndex, uint32_t value, WriteCounterOperation eWriteOp) {
    return writeCounter_04_00(counterIndex, (uint8_t)CounterAccessSizeAndOffset::kSize4, value, (uint8_t)eWriteOp, false);
}

int CommandBuffer::writeCounterImmediately(uint8_t counterIndex, CounterAccessSizeAndOffset eAccessSizeAndOffset, uint64_t value, WriteCounterOperation eWriteOp) {
    return writeCounter_04_00(counterIndex, (uint8_t)eAccessSizeAndOffset, value, (uint8_t)eWriteOp, true);
}

int CommandBuffer::writeCounterImmediately(uint8_t counterIndex, uint32_t value, WriteCounterOperation eWriteOp) {
    return writeCounter_04_00(counterIndex, (uint8_t)CounterAccessSizeAndOffset::kSize4, value, (uint8_t)eWriteOp, true);
}

int CommandBuffer::writeCounterImmediately(uint8_t counterIndex, uint32_t value) {
    return writeCounter_04_00(counterIndex, (uint8_t)CounterAccessSizeAndOffset::kSize4, value, (uint8_t)WriteCounterOperation::kStore, true);
}

int CommandBuffer::writeKernelEventQueue_04_00(SceKernelEqueue eq, int32_t id, uint64_t data, bool atSop) {
    if (!atSop) {
        const int mapRc = ampr_reject_completion_write_in_apr_map(&m_commandBuffer);
        if (mapRc != 0) {
            return mapRc;
        }
    }
    Op op{};
    op.type = OpType::WriteEqueue;
    op.u64b = reinterpret_cast<uintptr_t>(eq);
    op.u32b = static_cast<uint32_t>(id);
    op.u64a = data;
    op.u8a = atSop ? 1u : 0u;
    return cb_append(&m_commandBuffer, ampr_move(op));
}

int CommandBuffer::writeKernelEventQueueOnCompletion(SceKernelEqueue eq, int32_t id, uint64_t data) {
    return writeKernelEventQueue_04_00(eq, id, data, false);
}

int CommandBuffer::writeKernelEventQueueImmediately(SceKernelEqueue eq, int32_t id, uint64_t data) {
    return writeKernelEventQueue_04_00(eq, id, data, true);
}

int CommandBuffer::writeAddressFromTimeCounter_04_00(volatile uint64_t* address, bool atSop) {
    if (!ampr_valid_u64_write_addr(reinterpret_cast<uint64_t>(address))) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    if (!atSop) {
        const int mapRc = ampr_reject_completion_write_in_apr_map(&m_commandBuffer);
        if (mapRc != 0) {
            return mapRc;
        }
    }
    Op op{};
    op.type = OpType::WriteAddressFromTimeCounter;
    op.ptra = const_cast<uint64_t*>(address);
    op.u8b = atSop ? 1u : 0u;
    return cb_append(&m_commandBuffer, ampr_move(op));
}

int CommandBuffer::writeAddressFromTimeCounterOnCompletion(volatile uint64_t* address) {
    return writeAddressFromTimeCounter_04_00(address, false);
}

int CommandBuffer::writeAddressFromTimeCounterImmediately(volatile uint64_t* address) {
    return writeAddressFromTimeCounter_04_00(address, true);
}

int CommandBuffer::writeAddressFromCounter_04_00(volatile uint64_t* address, uint8_t counterIndex, bool atSop) {
    if (!ampr_valid_u64_write_addr(reinterpret_cast<uint64_t>(address)) ||
        !ampr_valid_counter_index_signed7(counterIndex)) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    if (!atSop) {
        const int mapRc = ampr_reject_completion_write_in_apr_map(&m_commandBuffer);
        if (mapRc != 0) {
            return mapRc;
        }
    }
    Op op{};
    op.type = OpType::WriteAddressFromCounter;
    op.ptra = const_cast<uint64_t*>(address);
    op.u8a = counterIndex;
    op.u8b = atSop ? 1u : 0u;
    return cb_append(&m_commandBuffer, ampr_move(op));
}

int CommandBuffer::writeAddressFromCounterOnCompletion(volatile uint64_t* address, uint8_t counterIndex) {
    return writeAddressFromCounter_04_00(address, counterIndex, false);
}

int CommandBuffer::writeAddressFromCounterImmediately(volatile uint64_t* address, uint8_t counterIndex) {
    return writeAddressFromCounter_04_00(address, counterIndex, true);
}

int CommandBuffer::writeAddressFromCounterPair_04_00(volatile uint64_t* address, uint8_t counterIndex, bool atSop) {
    if (!ampr_valid_u64_write_addr(reinterpret_cast<uint64_t>(address))) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    // Retail accepts only even 7-bit counter starts: (index & 0x81) == 0.
    if ((counterIndex & 0x81u) != 0) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    if (!atSop) {
        const int mapRc = ampr_reject_completion_write_in_apr_map(&m_commandBuffer);
        if (mapRc != 0) {
            return mapRc;
        }
    }
    Op op{};
    op.type = OpType::WriteAddressFromCounterPair;
    op.ptra = const_cast<uint64_t*>(address);
    op.u8a = counterIndex;
    op.u8b = atSop ? 1u : 0u;
    return cb_append(&m_commandBuffer, ampr_move(op));
}

int CommandBuffer::writeAddressFromCounterPairOnCompletion(volatile uint64_t* address, uint8_t counterIndex) {
    return writeAddressFromCounterPair_04_00(address, counterIndex, false);
}

int CommandBuffer::writeAddressFromCounterPairImmediately(volatile uint64_t* address, uint8_t counterIndex) {
    return writeAddressFromCounterPair_04_00(address, counterIndex, true);
}

int CommandBuffer::nop(uint32_t numU32) {
    if (numU32 == 0 || numU32 > 16) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    Op op{};
    op.type = OpType::Nop;
    op.u32a = numU32;
    return cb_append(&m_commandBuffer, ampr_move(op));
}

int CommandBuffer::nop(uint32_t numU32, const uint32_t* data) {
    if (numU32 > 15) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    Op op{};
    op.type = OpType::Nop;
    op.u32a = numU32;
    op.u32b = 1;
    op.cptr = data;
    return cb_append(&m_commandBuffer, ampr_move(op));
}

int CommandBuffer::constructNop(uint32_t nopType, const void* payload, uint32_t payloadSize, const uint32_t* optWord) {
    const uint32_t maxPayloadBytes = optWord ? 56u : 60u;
    if (payloadSize > maxPayloadBytes) {
        return SCE_KERNEL_ERROR_EINVAL;
    }

    uint32_t payloadWords = (payloadSize + 3u) >> 2;
    if (optWord) {
        ++payloadWords;
    }

    Op op{};
    op.type = OpType::Nop;
    op.u32a = payloadWords;
    op.u32b = 1u;
    op.u32c = nopType;
    op.u64a = payloadSize;
    op.u64b = optWord ? *optWord : 0u;
    op.u8a = optWord ? 1u : 0u;
    op.cptr = payload;
    return cb_append(&m_commandBuffer, ampr_move(op));
}

int CommandBuffer::setMarker(const char* msg) {
    Op op{};
    op.type = OpType::MarkerSet;
    if (!ampr_set_marker_text(op, msg)) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    return cb_append(&m_commandBuffer, ampr_move(op));
}

int CommandBuffer::setMarker(const char* msg, uint32_t color) {
    Op op{};
    op.type = OpType::MarkerSet;
    if (!ampr_set_marker_text(op, msg)) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    op.u32a = color;
    op.u32b = 1u;
    return cb_append(&m_commandBuffer, ampr_move(op));
}

int CommandBuffer::pushMarker(const char* msg) {
    Op op{};
    op.type = OpType::MarkerPush;
    if (!ampr_set_marker_text(op, msg)) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    return cb_append(&m_commandBuffer, ampr_move(op));
}

int CommandBuffer::pushMarker(const char* msg, uint32_t color) {
    Op op{};
    op.type = OpType::MarkerPush;
    if (!ampr_set_marker_text(op, msg)) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    op.u32a = color;
    op.u32b = 1u;
    return cb_append(&m_commandBuffer, ampr_move(op));
}

int CommandBuffer::popMarker() {
    Op op{};
    op.type = OpType::MarkerPop;
    return cb_append(&m_commandBuffer, ampr_move(op));
}

int CommandBuffer::reset(void) {
    AMPR_TLOGF("cb.reset enter this=%p cb=%p", this, &m_commandBuffer);
    if (!m_commandBuffer.buffer) {
        AMPR_TLOGF("cb.reset reject cb=%p rc=0x%x reason=no-buffer", &m_commandBuffer, SCE_KERNEL_ERROR_EPERM);
        return SCE_KERNEL_ERROR_EPERM;
    }
    cb_reset_recording_position(m_commandBuffer);
    AMPR_TLOGF("cb.reset.after cb=%p type=%d buf=%p bufsize=0x%x offset=0x%x num=%d",
              &m_commandBuffer,
              m_commandBuffer.type,
              m_commandBuffer.buffer,
              m_commandBuffer.bufsize,
              m_commandBuffer.offset,
              m_commandBuffer.num);
    return 0;
}

} // namespace sce::Ampr


