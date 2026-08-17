/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * AMM command-buffer public C++ implementation.
 */

#include "ampr_emu_command_buffer_types.h"
#include "ampr_emu_amm.h"
#include "ampr_emu_errno.h"
#include "ampr_emu_log.h"
#include "ampr_emu_prot.h"

namespace sce::Ampr {

template <typename MeasureFn, typename WriteFn>
static int cb_append_amm_kernel_record(SceAmprCommandBuffer* cb,
                                       const char* typeName,
                                       MeasureFn measure,
                                       WriteFn write,
                                       bool requireBuffer = true) {
    (void)typeName;
    if (!cb) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    if (requireBuffer && !cb->buffer) {
        return SCE_KERNEL_ERROR_EPERM;
    }

    uint64_t bytes64 = 0;
    uint32_t bytes = 0;
    const int measureRc = Emu::ammCommandSizeToInt(measure(&bytes64), bytes64, &bytes);
    if (measureRc < 0) {
        return measureRc;
    }

    const uint32_t oldOffset = cb->offset;
    if (bytes > cb->bufsize || oldOffset > cb->bufsize - bytes) {
        return SCE_KERNEL_ERROR_EBUSY;
    }
    // A few compatibility writers defer the buffer check until after their
    // measure call so an unavailable kernel helper can still report ENXIO.
    if (!cb->buffer) {
        return SCE_KERNEL_ERROR_EPERM;
    }
    if (cb->num < 0 || cb->num == INT32_MAX) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    const uint32_t nextOffset = oldOffset + bytes;
    void* dst = static_cast<uint8_t*>(cb->buffer) + oldOffset;
    const int writeRc = write(dst);
    if (writeRc != 0) {
        return writeRc;
    }

    // Commit metadata only after the kernel-format writer has succeeded.
    cb->offset = nextOffset;
    ++cb->num;
    AMPR_TLOGF("cb.append.amm.kernel cb=%p type=%s off=0x%x size=0x%x next=0x%x bufsize=0x%x",
              cb,
              typeName ? typeName : "?",
              oldOffset,
              bytes,
              cb->offset,
              cb->bufsize);
    return 0;
}

static void amm_log_cpu_visible_prot_substitution(const char* op,
                                                  const SceAmprCommandBuffer* cb,
                                                  int prot,
                                                  uint64_t kernelProt,
                                                  uint64_t adjustedProt) {
    (void)op;
    (void)cb;
    (void)prot;
    if (adjustedProt == kernelProt) {
        return;
    }
    AMPR_CRITICAL_LOGF("amm.cb.prot.substitute op=%s cb=%p prot=0x%x kernelProt=0x%llx adjustedProt=0x%llx",
                       op ? op : "?",
                       cb,
                       prot,
                       (unsigned long long)kernelProt,
                       (unsigned long long)adjustedProt);
}

static int amm_prepare_cpu_visible_kernel_prot(const char* op,
                                               const SceAmprCommandBuffer* cb,
                                               int prot,
                                               uint64_t& kernelProt) {
    const uint32_t rawProt = static_cast<uint32_t>(prot);
    const int rc = Emu::ammValidateRetailProt(rawProt);
    if (rc == 0) {
        const uint64_t adjustedRawProt = Emu::protWithCpuRwForAmprWrite(rawProt);
        kernelProt = Emu::ammKernelProt(static_cast<uint32_t>(adjustedRawProt));
        amm_log_cpu_visible_prot_substitution(op, cb, prot, Emu::ammKernelProt(rawProt), kernelProt);
    }
    return rc;
}

static int amm_prepare_cpu_visible_kernel_prot_pair(const char* op,
                                                    const char* maskOp,
                                                    const SceAmprCommandBuffer* cb,
                                                    int prot,
                                                    int protMask,
                                                    uint64_t& kernelProt,
                                                    uint64_t& kernelMask) {
    const uint32_t rawProt = static_cast<uint32_t>(prot);
    int rc = Emu::ammValidateRetailProt(rawProt);
    if (rc != 0) {
        return rc;
    }
    const uint32_t rawMask = static_cast<uint32_t>(protMask);
    rc = Emu::ammValidateRetailProt(rawMask);
    if (rc != 0) {
        return rc;
    }
    const uint64_t adjustedRawProt = Emu::protWithCpuRwForAmprWrite(rawProt);
    const uint64_t adjustedRawMask = Emu::protMaskWithCpuRwForAdjustedProt(rawProt, adjustedRawProt, rawMask);
    const uint64_t rawKernelProt = Emu::ammKernelProt(rawProt);
    const uint64_t rawKernelMask = Emu::ammKernelProt(rawMask);
    kernelProt = Emu::ammKernelProt(static_cast<uint32_t>(adjustedRawProt));
    kernelMask = Emu::ammKernelProt(static_cast<uint32_t>(adjustedRawMask));
    amm_log_cpu_visible_prot_substitution(op, cb, prot, rawKernelProt, kernelProt);
    amm_log_cpu_visible_prot_substitution(maskOp, cb, protMask, rawKernelMask, kernelMask);
    return 0;
}

static int amm_prevalidate_command_buffer(const SceAmprCommandBuffer* cb) {
    if (!cb) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    if (!cb->buffer) {
        return SCE_KERNEL_ERROR_EPERM;
    }
    return 0;
}

static int amm_prepare_cpu_visible_kernel_prot_for_cb(const char* op,
                                                      const SceAmprCommandBuffer* cb,
                                                      int prot,
                                                      uint64_t& kernelProt) {
    const int cbRc = amm_prevalidate_command_buffer(cb);
    if (cbRc != 0) {
        return cbRc;
    }
    return amm_prepare_cpu_visible_kernel_prot(op, cb, prot, kernelProt);
}

static int amm_prepare_cpu_visible_kernel_prot_pair_for_cb(const SceAmprCommandBuffer* cb,
                                                           const char* op,
                                                           const char* maskOp,
                                                           int prot,
                                                           int protMask,
                                                           uint64_t& kernelProt,
                                                           uint64_t& kernelMask) {
    const int cbRc = amm_prevalidate_command_buffer(cb);
    if (cbRc != 0) {
        return cbRc;
    }
    return amm_prepare_cpu_visible_kernel_prot_pair(op, maskOp, cb, prot, protMask, kernelProt, kernelMask);
}

AmmCommandBuffer::AmmCommandBuffer(void) : CommandBuffer() {}
AmmCommandBuffer::~AmmCommandBuffer(void) = default;

int AmmCommandBuffer::map(uint64_t va, uint64_t size, int type, int prot) {
    uint64_t kernelProt = 0;
    const int rc = amm_prepare_cpu_visible_kernel_prot_for_cb("AmmMap", &m_commandBuffer, prot, kernelProt);
    if (rc != 0) {
        return rc;
    }
    return cb_append_amm_kernel_record(
        &m_commandBuffer,
        "AmmMap",
        [&](uint64_t* out) { return Emu::ammWriteMapCommand2(nullptr, va, size, static_cast<uint32_t>(type), kernelProt, 0, out); },
        [&](void* dst) { return Emu::ammWriteMapCommand2(dst, va, size, static_cast<uint32_t>(type), kernelProt, 0, nullptr); });
}

int AmmCommandBuffer::mapWithGpuMaskId(uint64_t va, uint64_t size, int type, int prot, uint8_t gpuMaskId) {
    uint64_t kernelProt = 0;
    const int rc = amm_prepare_cpu_visible_kernel_prot_for_cb("AmmMapWithGpuMaskId", &m_commandBuffer, prot, kernelProt);
    if (rc != 0) {
        return rc;
    }
    return cb_append_amm_kernel_record(
        &m_commandBuffer,
        "AmmMap",
        [&](uint64_t* out) { return Emu::ammWriteMapWithGpuMaskIdCommand(nullptr, va, size, static_cast<uint32_t>(type), kernelProt, gpuMaskId, out); },
        [&](void* dst) { return Emu::ammWriteMapWithGpuMaskIdCommand(dst, va, size, static_cast<uint32_t>(type), kernelProt, gpuMaskId, nullptr); });
}

int AmmCommandBuffer::mapDirect(uint64_t va, uint64_t dmemOffset, size_t size, int type, int prot) {
    uint64_t kernelProt = 0;
    const int rc = amm_prepare_cpu_visible_kernel_prot_for_cb("AmmMapDirect", &m_commandBuffer, prot, kernelProt);
    if (rc != 0) {
        return rc;
    }
    return cb_append_amm_kernel_record(
        &m_commandBuffer,
        "AmmMapDirect",
        [&](uint64_t* out) { return Emu::ammWriteMapDirectCommand(nullptr, va, dmemOffset, size, static_cast<uint32_t>(type), kernelProt, out); },
        [&](void* dst) { return Emu::ammWriteMapDirectCommand(dst, va, dmemOffset, size, static_cast<uint32_t>(type), kernelProt, nullptr); });
}

int AmmCommandBuffer::mapDirectWithGpuMaskId(uint64_t va, uint64_t dmemOffset, uint64_t size, int type, int prot, uint8_t gpuMaskId) {
    uint64_t kernelProt = 0;
    const int rc = amm_prepare_cpu_visible_kernel_prot_for_cb("AmmMapDirectWithGpuMaskId", &m_commandBuffer, prot, kernelProt);
    if (rc != 0) {
        return rc;
    }
    return cb_append_amm_kernel_record(
        &m_commandBuffer,
        "AmmMapDirect",
        [&](uint64_t* out) { return Emu::ammWriteMapDirectWithGpuMaskIdCommand(nullptr, va, dmemOffset, size, static_cast<uint32_t>(type), kernelProt, gpuMaskId, out); },
        [&](void* dst) { return Emu::ammWriteMapDirectWithGpuMaskIdCommand(dst, va, dmemOffset, size, static_cast<uint32_t>(type), kernelProt, gpuMaskId, nullptr); });
}

int AmmCommandBuffer::unmap(uint64_t va, size_t size) {
    return cb_append_amm_kernel_record(
        &m_commandBuffer,
        "AmmUnmap",
        [&](uint64_t* out) { return Emu::ammWriteUnmapCommand(nullptr, va, size, out); },
        [&](void* dst) { return Emu::ammWriteUnmapCommand(dst, va, size, nullptr); });
}

int AmmCommandBuffer::remap(uint64_t vaNewStart, uint64_t vaOldStart, uint64_t vaSize, int prot) {
    uint64_t kernelProt = 0;
    const int rc = amm_prepare_cpu_visible_kernel_prot_for_cb("AmmRemap", &m_commandBuffer, prot, kernelProt);
    if (rc != 0) {
        return rc;
    }
    return cb_append_amm_kernel_record(
        &m_commandBuffer,
        "AmmRemap",
        [&](uint64_t* out) { return Emu::ammWriteRemapCommand(nullptr, vaNewStart, vaOldStart, vaSize, kernelProt, out); },
        [&](void* dst) { return Emu::ammWriteRemapCommand(dst, vaNewStart, vaOldStart, vaSize, kernelProt, nullptr); });
}

int AmmCommandBuffer::remapWithGpuMaskId(uint64_t vaNewStart, uint64_t vaOldStart, uint64_t vaSize, int prot, uint8_t gpuMaskId) {
    uint64_t kernelProt = 0;
    const int rc = amm_prepare_cpu_visible_kernel_prot_for_cb("AmmRemapWithGpuMaskId", &m_commandBuffer, prot, kernelProt);
    if (rc != 0) {
        return rc;
    }
    return cb_append_amm_kernel_record(
        &m_commandBuffer,
        "AmmRemap",
        [&](uint64_t* out) { return Emu::ammWriteRemapWithGpuMaskIdCommand(nullptr, vaNewStart, vaOldStart, vaSize, kernelProt, gpuMaskId, out); },
        [&](void* dst) { return Emu::ammWriteRemapWithGpuMaskIdCommand(dst, vaNewStart, vaOldStart, vaSize, kernelProt, gpuMaskId, nullptr); });
}

int AmmCommandBuffer::multiMap(uint64_t vaNewStart, uint64_t vaAliasStart, uint64_t vaSize, int prot) {
    uint64_t kernelProt = 0;
    const int rc = amm_prepare_cpu_visible_kernel_prot_for_cb("AmmMultiMap", &m_commandBuffer, prot, kernelProt);
    if (rc != 0) {
        return rc;
    }
    return cb_append_amm_kernel_record(
        &m_commandBuffer,
        "AmmMultiMap",
        [&](uint64_t* out) { return Emu::ammWriteMultiMapCommand(nullptr, vaNewStart, vaAliasStart, vaSize, kernelProt, out); },
        [&](void* dst) { return Emu::ammWriteMultiMapCommand(dst, vaNewStart, vaAliasStart, vaSize, kernelProt, nullptr); });
}

int AmmCommandBuffer::multiMapWithGpuMaskId(uint64_t vaNewStart, uint64_t vaAliasStart, uint64_t vaSize, int prot, uint8_t gpuMaskId) {
    uint64_t kernelProt = 0;
    const int rc = amm_prepare_cpu_visible_kernel_prot_for_cb("AmmMultiMapWithGpuMaskId", &m_commandBuffer, prot, kernelProt);
    if (rc != 0) {
        return rc;
    }
    return cb_append_amm_kernel_record(
        &m_commandBuffer,
        "AmmMultiMap",
        [&](uint64_t* out) { return Emu::ammWriteMultiMapWithGpuMaskIdCommand(nullptr, vaNewStart, vaAliasStart, vaSize, kernelProt, gpuMaskId, out); },
        [&](void* dst) { return Emu::ammWriteMultiMapWithGpuMaskIdCommand(dst, vaNewStart, vaAliasStart, vaSize, kernelProt, gpuMaskId, nullptr); });
}

int AmmCommandBuffer::modifyProtect(uint64_t va, uint64_t size, int prot, int protMask) {
    uint64_t kernelProt = 0;
    uint64_t kernelMask = 0;
    const int rc = amm_prepare_cpu_visible_kernel_prot_pair_for_cb(&m_commandBuffer,
                                                                   "AmmModifyProtect",
                                                                   "AmmModifyProtectMask",
                                                                   prot,
                                                                   protMask,
                                                                   kernelProt,
                                                                   kernelMask);
    if (rc != 0) {
        return rc;
    }
    return cb_append_amm_kernel_record(
        &m_commandBuffer,
        "AmmModifyProtect",
        [&](uint64_t* out) { return Emu::ammWriteModifyProtectCommand(nullptr, va, size, kernelProt, kernelMask, out); },
        [&](void* dst) { return Emu::ammWriteModifyProtectCommand(dst, va, size, kernelProt, kernelMask, nullptr); });
}

int AmmCommandBuffer::modifyProtectWithGpuMaskId(uint64_t va, uint64_t size, int prot, int protMask, uint8_t gpuMaskId) {
    uint64_t kernelProt = 0;
    uint64_t kernelMask = 0;
    const int rc = amm_prepare_cpu_visible_kernel_prot_pair_for_cb(&m_commandBuffer,
                                                                   "AmmModifyProtectWithGpuMaskId",
                                                                   "AmmModifyProtectWithGpuMaskIdMask",
                                                                   prot,
                                                                   protMask,
                                                                   kernelProt,
                                                                   kernelMask);
    if (rc != 0) {
        return rc;
    }
    return cb_append_amm_kernel_record(
        &m_commandBuffer,
        "AmmModifyProtect",
        [&](uint64_t* out) { return Emu::ammWriteModifyProtectWithGpuMaskIdCommand(nullptr, va, size, kernelProt, kernelMask, gpuMaskId, out); },
        [&](void* dst) { return Emu::ammWriteModifyProtectWithGpuMaskIdCommand(dst, va, size, kernelProt, kernelMask, gpuMaskId, nullptr); });
}

int AmmCommandBuffer::modifyMtypeProtect(uint64_t va, uint64_t size, int type, int prot, int protMask) {
    uint64_t kernelProt = 0;
    uint64_t kernelMask = 0;
    const int rc = amm_prepare_cpu_visible_kernel_prot_pair_for_cb(&m_commandBuffer,
                                                                   "AmmModifyMtypeProtect",
                                                                   "AmmModifyMtypeProtectMask",
                                                                   prot,
                                                                   protMask,
                                                                   kernelProt,
                                                                   kernelMask);
    if (rc != 0) {
        return rc;
    }
    return cb_append_amm_kernel_record(
        &m_commandBuffer,
        "AmmModifyMtypeProtect",
        [&](uint64_t* out) { return Emu::ammWriteModifyMtypeProtectCommand(nullptr, va, size, static_cast<uint32_t>(type), kernelProt, kernelMask, out); },
        [&](void* dst) { return Emu::ammWriteModifyMtypeProtectCommand(dst, va, size, static_cast<uint32_t>(type), kernelProt, kernelMask, nullptr); });
}

int AmmCommandBuffer::modifyMtypeProtectWithGpuMaskId(uint64_t va, uint64_t size, int type, int prot, int protMask, uint8_t gpuMaskId) {
    uint64_t kernelProt = 0;
    uint64_t kernelMask = 0;
    const int rc = amm_prepare_cpu_visible_kernel_prot_pair_for_cb(&m_commandBuffer,
                                                                   "AmmModifyMtypeProtectWithGpuMaskId",
                                                                   "AmmModifyMtypeProtectWithGpuMaskIdMask",
                                                                   prot,
                                                                   protMask,
                                                                   kernelProt,
                                                                   kernelMask);
    if (rc != 0) {
        return rc;
    }
    return cb_append_amm_kernel_record(
        &m_commandBuffer,
        "AmmModifyMtypeProtect",
        [&](uint64_t* out) { return Emu::ammWriteModifyMtypeProtectWithGpuMaskIdCommand(nullptr, va, size, static_cast<uint32_t>(type), kernelProt, kernelMask, gpuMaskId, out); },
        [&](void* dst) { return Emu::ammWriteModifyMtypeProtectWithGpuMaskIdCommand(dst, va, size, static_cast<uint32_t>(type), kernelProt, kernelMask, gpuMaskId, nullptr); });
}

int AmmCommandBuffer::mapAsPrt(uint64_t va, uint64_t size) {
    return cb_append_amm_kernel_record(
        &m_commandBuffer,
        "AmmMapAsPrt",
        [&](uint64_t* out) { return Emu::ammWriteMapCommand2(nullptr, va, size, 0, 0, 1, out); },
        [&](void* dst) { return Emu::ammWriteMapCommand2(dst, va, size, 0, 0, 1, nullptr); },
        false);
}

int AmmCommandBuffer::allocatePaForPrt(uint64_t va, uint64_t size, int type, int prot) {
    uint64_t kernelProt = 0;
    const int rc = amm_prepare_cpu_visible_kernel_prot("AmmAllocatePaForPrt", &m_commandBuffer, prot, kernelProt);
    if (rc != 0) {
        return rc;
    }
    return cb_append_amm_kernel_record(
        &m_commandBuffer,
        "AmmAllocatePaForPrt",
        [&](uint64_t* out) { return Emu::ammWriteModifyMtypeProtectCommand(nullptr, va, size, static_cast<uint32_t>(type), kernelProt, 1019, out); },
        [&](void* dst) { return Emu::ammWriteModifyMtypeProtectCommand(dst, va, size, static_cast<uint32_t>(type), kernelProt, 1019, nullptr); },
        false);
}

int AmmCommandBuffer::remapIntoPrt(uint64_t vaPrtStart, uint64_t vaOldStart, uint64_t size, int prot, uint32_t opcode) {
    uint64_t kernelProtValue = 0;
    const int rc = amm_prepare_cpu_visible_kernel_prot_for_cb("AmmRemapIntoPrt", &m_commandBuffer, prot, kernelProtValue);
    if (rc != 0) {
        return rc;
    }
    const int kernelProt = static_cast<int>(kernelProtValue);
    const int kernelOpcode = static_cast<int>(opcode ? opcode : 1011u);
    return cb_append_amm_kernel_record(
        &m_commandBuffer,
        "AmmRemapIntoPrt",
        [&](uint64_t* out) { return Emu::ammWriteRemapIntoPrtCommand(nullptr, vaPrtStart, vaOldStart, size, kernelProt, kernelOpcode, out); },
        [&](void* dst) { return Emu::ammWriteRemapIntoPrtCommand(static_cast<uint32_t*>(dst), vaPrtStart, vaOldStart, size, kernelProt, kernelOpcode, nullptr); });
}

int AmmCommandBuffer::unmapToPrt(uint64_t va, uint64_t size) {
    return cb_append_amm_kernel_record(
        &m_commandBuffer,
        "AmmUnmapToPrt",
        [&](uint64_t* out) { return Emu::ammWriteUnmapToPrtCommand(nullptr, va, size, out); },
        [&](void* dst) { return Emu::ammWriteUnmapToPrtCommand(static_cast<uint32_t*>(dst), va, size, nullptr); });
}

} // namespace sce::Ampr
