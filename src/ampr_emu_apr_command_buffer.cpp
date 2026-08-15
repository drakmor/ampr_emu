/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * APR command-buffer validation and append helpers.
 */

#define AMPR_EMU_CORE_IMPL 1
#include "ampr_emu_command_buffer_apr.h"
#include "ampr_emu_command_buffer_common.h"
#include "ampr_emu_command_packing.h"
#include "ampr_emu_amm.h"
#include "ampr_emu_prot.h"
#include "ampr_emu_runtime_memory.h"

namespace {
static constexpr uint64_t kAprUserVaMax = 0xF00000000000ull;
static constexpr uint64_t kAprMaxReadLength = 0x100000000ull;

static int apr_validate_user_range(uint64_t va, uint64_t size) {
    return va > kAprUserVaMax || size > kAprUserVaMax - va
               ? SCE_KERNEL_ERROR_EINVAL
               : 0;
}

static int apr_validate_map_begin_shape(uint64_t va, uint64_t size) {
    if (size == 0 || ((va | size) % PAGE_SIZE) != 0 || va + size < va) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    return apr_validate_user_range(va, size);
}

static int apr_validate_map_begin_args(uint64_t va, uint64_t size, int type, int prot) {
    const int shapeRc = apr_validate_map_begin_shape(va, size);
    if (shapeRc != 0) {
        return shapeRc;
    }
    uint64_t ignoredSize = 0;
    const int rc = sce::Ampr::Emu::ammWriteMapCommand2(nullptr, va, size,
        static_cast<uint32_t>(type), static_cast<uint32_t>(prot), 0, &ignoredSize);
    return rc < 0 ? rc : 0;
}

static int apr_validate_map_direct_begin_shape(uint64_t va,
                                                uint64_t dmemOffset,
                                                uint64_t size) {
    return (dmemOffset % PAGE_SIZE) != 0
               ? SCE_KERNEL_ERROR_EINVAL
               : apr_validate_map_begin_shape(va, size);
}

static int apr_validate_map_direct_begin_args(uint64_t va,
                                               uint64_t dmemOffset,
                                               uint64_t size,
                                               int type,
                                               int prot) {
    const int shapeRc = apr_validate_map_direct_begin_shape(va, dmemOffset, size);
    if (shapeRc != 0) {
        return shapeRc;
    }
    uint64_t ignoredSize = 0;
    const int rc = sce::Ampr::Emu::ammWriteMapDirectCommand(nullptr, va, dmemOffset,
        size, static_cast<uint32_t>(type), static_cast<uint32_t>(prot), &ignoredSize);
    return rc < 0 ? rc : 0;
}

static int apr_validate_read_length(uint64_t length) {
    return length == 0 || length > kAprMaxReadLength
               ? SCE_KERNEL_ERROR_EINVAL
               : 0;
}

static int apr_validate_read_offset(uint64_t offset) {
    return offset >= 0x10000000000ull ? SCE_KERNEL_ERROR_EINVAL : 0;
}

static int apr_validate_read_args(const void* buffer,
                                  uint64_t length,
                                  uint64_t offset) {
    int rc = apr_validate_read_length(length);
    if (rc == 0) {
        rc = apr_validate_user_range(reinterpret_cast<uint64_t>(buffer), length);
    }
    return rc == 0 ? apr_validate_read_offset(offset) : rc;
}

static int apr_command_map_prot(int prot) {
    return static_cast<int>(sce::Ampr::Emu::protWithCpuRwForAmprWrite(
        static_cast<uint32_t>(prot)));
}
} // namespace

namespace sce::Ampr::Emu {

bool aprCommandBufferHasScatterGatherState(SceAmprCommandBuffer* cb) {
    return ampr_cb_has_type_mask(cb, kAprScatterGatherValidTypeMask);
}

bool aprCommandBufferHasMapState(SceAmprCommandBuffer* cb) {
    return ampr_cb_has_type_mask(cb, kAprMapActiveTypeMask);
}

int aprValidateReadLength(uint64_t length) { return apr_validate_read_length(length); }
int aprValidateReadOffset(uint64_t offset) { return apr_validate_read_offset(offset); }
int aprValidateReadArgs(const void* buffer, uint64_t length, uint64_t offset) {
    return apr_validate_read_args(buffer, length, offset);
}
int aprValidateMapBeginShape(uint64_t va, uint64_t size) {
    return apr_validate_map_begin_shape(va, size);
}
int aprValidateMapBeginArgs(uint64_t va, uint64_t size, int type, int prot) {
    return apr_validate_map_begin_args(va, size, type, prot);
}
int aprValidateMapDirectBeginShape(uint64_t va, uint64_t dmemOffset, uint64_t size) {
    return apr_validate_map_direct_begin_shape(va, dmemOffset, size);
}
int aprValidateMapDirectBeginArgs(uint64_t va, uint64_t dmemOffset, uint64_t size,
                                  int type, int prot) {
    return apr_validate_map_direct_begin_args(va, dmemOffset, size, type, prot);
}
int aprCommandMapProt(int prot) { return apr_command_map_prot(prot); }

int aprCommandBufferAppendReadFile(SceAmprCommandBuffer* cb, SceAprFileId fileId,
                                   void* buffer, uint64_t length, uint64_t offset) {
    Op op{};
    op.type = OpType::AprReadFile;
    op.u32a = static_cast<uint32_t>(fileId);
    op.ptra = buffer;
    op.u64a = length;
    op.u64b = offset;
    return cb_append_with_type_mask(cb, ampr_move(op),
                                    kAprScatterGatherValidTypeMask, 0u);
}

int aprCommandBufferAppendReadGather(SceAmprCommandBuffer* cb,
                                     uint64_t length, uint64_t offset) {
    Op op{};
    op.type = OpType::AprReadGather;
    op.u64a = length;
    op.u64b = offset;
    return cb_append(cb, ampr_move(op));
}

int aprCommandBufferAppendReadScatter(SceAmprCommandBuffer* cb,
                                      void* buffer, uint64_t length) {
    Op op{};
    op.type = OpType::AprReadScatter;
    op.ptra = buffer;
    op.u64a = length;
    return cb_append(cb, ampr_move(op));
}

int aprCommandBufferAppendReadGatherScatter(SceAmprCommandBuffer* cb,
                                            void* buffer, uint64_t length,
                                            uint64_t offset) {
    Op op{};
    op.type = OpType::AprReadGatherScatter;
    op.ptra = buffer;
    op.u64a = length;
    op.u64b = offset;
    return cb_append(cb, ampr_move(op));
}

int aprCommandBufferAppendResetGatherScatterState(SceAmprCommandBuffer* cb) {
    Op op{};
    op.type = OpType::AprResetGatherScatter;
    return cb_append_with_type_mask(cb, ampr_move(op), 0u,
                                    kAprScatterGatherValidTypeMask);
}

int aprCommandBufferAppendMapBegin(SceAmprCommandBuffer* cb, uint64_t va,
                                   uint64_t size, int type, int commandProt) {
    Op op{};
    op.type = OpType::AprMapBegin;
    op.u64a = va;
    op.u64b = size;
    op.u64c = static_cast<uint64_t>(static_cast<uint32_t>(type));
    op.u32a = static_cast<uint32_t>(commandProt);
    op.u32b = static_cast<uint32_t>(type);
    return cb_append_with_type_mask(cb, ampr_move(op), kAprMapActiveTypeMask, 0u);
}

int aprCommandBufferAppendMapDirectBegin(SceAmprCommandBuffer* cb, uint64_t va,
                                         uint64_t dmemOffset, size_t size,
                                         int type, int commandProt) {
    Op op{};
    op.type = OpType::AprMapDirectBegin;
    op.u64a = va;
    op.u64b = dmemOffset;
    op.u64c = static_cast<uint64_t>(size);
    op.u32a = static_cast<uint32_t>(type);
    op.u32b = static_cast<uint32_t>(commandProt);
    return cb_append_with_type_mask(cb, ampr_move(op), kAprMapActiveTypeMask, 0u);
}

int aprCommandBufferAppendMapEnd(SceAmprCommandBuffer* cb) {
    Op op{};
    op.type = OpType::AprMapEnd;
    return cb_append_with_type_mask(cb, ampr_move(op), 0u, kAprMapActiveTypeMask);
}

} // namespace sce::Ampr::Emu
