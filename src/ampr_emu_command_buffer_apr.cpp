/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * APR command-buffer public C++ implementation.
 */

#include "ampr_emu_command_buffer_types.h"
#include "ampr_emu_command_buffer_apr.h"
#include "ampr_emu_errno.h"
#include "ampr_emu_log.h"

namespace sce::Ampr {

AprCommandBuffer::AprCommandBuffer(void) : CommandBuffer() {
    AMPR_TLOGF("[apr-cb-10] AprCommandBuffer ctor enter this=%p cb=%p mapState=%p sgState=%p",
              this, &m_commandBuffer, &m_mapState, &m_scatterGatherState);
    m_mapState.asU64 = 0;
    m_scatterGatherState.asU64 = 0;
    AMPR_TLOGF("[apr-cb-11] AprCommandBuffer ctor leave this=%p mapState=0x%llx sgState=0x%llx",
              this,
              (unsigned long long)m_mapState.asU64,
              (unsigned long long)m_scatterGatherState.asU64);
}
AprCommandBuffer::~AprCommandBuffer(void) = default;


int AprCommandBuffer::readFile(SceAprFileId fileId, void* buffer, uint64_t length, uint64_t offset) {
    if (Emu::aprValidateReadArgs(buffer, length, offset) != 0) {
        AMPR_LOGF("[apr-rf-00] AprCommandBuffer::readFile status=rejected this=%p rc=0x%x reason=bad-args",
                  this, SCE_KERNEL_ERROR_EINVAL);
        AMPR_FILE_STATUS_LOGF("apr.file.request status=rejected phase=append this=%p fileId=%u buf=%p len=0x%llx off=0x%llx reason=bad-args rc=0x%x",
                              this,
                              (unsigned)fileId,
                              buffer,
                              (unsigned long long)length,
                              (unsigned long long)offset,
                              SCE_KERNEL_ERROR_EINVAL);
        return SCE_KERNEL_ERROR_EINVAL;
    }
    const int rc = Emu::aprCommandBufferAppendReadFile(&m_commandBuffer, fileId, buffer, length, offset);
    AMPR_FILE_STATUS_LOGF("apr.file.request status=%s phase=append this=%p fileId=%u buf=%p len=0x%llx off=0x%llx rc=0x%x",
                          rc == 0 ? "appended" : "rejected",
                          this,
                          (unsigned)fileId,
                          buffer,
                          (unsigned long long)length,
                          (unsigned long long)offset,
                          rc);
    return rc;
}

int AprCommandBuffer::readFileGather(uint64_t length, uint64_t offset) {
    AMPR_TLOGF("apr.cb.readFileGather enter this=%p cb=%p len=0x%llx off=0x%llx",
              this, &m_commandBuffer, (unsigned long long)length, (unsigned long long)offset);
    if (Emu::aprValidateReadLength(length) != 0 || Emu::aprValidateReadOffset(offset) != 0) {
        AMPR_LOGF("apr.cb.readFileGather reject this=%p rc=0x%x reason=bad-args",
                  this, SCE_KERNEL_ERROR_EINVAL);
        return SCE_KERNEL_ERROR_EINVAL;
    }
    if (!Emu::aprCommandBufferHasScatterGatherState(&m_commandBuffer)) {
        AMPR_LOGF("apr.cb.readFileGather reject this=%p rc=0x%x reason=no-gather-state type=0x%x",
                  this, SCE_KERNEL_ERROR_EINVAL, (unsigned)m_commandBuffer.type);
        return SCE_KERNEL_ERROR_EINVAL;
    }
    const int rc = Emu::aprCommandBufferAppendReadGather(&m_commandBuffer, length, offset);
    AMPR_TLOGF("apr.cb.readFileGather leave this=%p rc=0x%x", this, rc);
    return rc;
}

int AprCommandBuffer::readFileScatter(void* buffer, uint64_t length) {
    AMPR_TLOGF("apr.cb.readFileScatter enter this=%p cb=%p buffer=%p len=0x%llx",
              this, &m_commandBuffer, buffer, (unsigned long long)length);
    if (Emu::aprValidateReadArgs(buffer, length, 0) != 0) {
        AMPR_LOGF("apr.cb.readFileScatter reject this=%p rc=0x%x reason=bad-args",
                  this, SCE_KERNEL_ERROR_EINVAL);
        return SCE_KERNEL_ERROR_EINVAL;
    }
    if (!Emu::aprCommandBufferHasScatterGatherState(&m_commandBuffer)) {
        AMPR_LOGF("apr.cb.readFileScatter reject this=%p rc=0x%x reason=no-gather-state type=0x%x",
                  this, SCE_KERNEL_ERROR_EINVAL, (unsigned)m_commandBuffer.type);
        return SCE_KERNEL_ERROR_EINVAL;
    }
    const int rc = Emu::aprCommandBufferAppendReadScatter(&m_commandBuffer, buffer, length);
    AMPR_TLOGF("apr.cb.readFileScatter leave this=%p rc=0x%x", this, rc);
    return rc;
}

int AprCommandBuffer::readFileGatherScatter(void* buffer, uint64_t length, uint64_t offset) {
    AMPR_TLOGF("apr.cb.readFileGatherScatter enter this=%p cb=%p buffer=%p len=0x%llx off=0x%llx",
              this, &m_commandBuffer, buffer,
              (unsigned long long)length, (unsigned long long)offset);
    if (Emu::aprValidateReadArgs(buffer, length, offset) != 0) {
        AMPR_LOGF("apr.cb.readFileGatherScatter reject this=%p rc=0x%x reason=bad-args",
                  this, SCE_KERNEL_ERROR_EINVAL);
        return SCE_KERNEL_ERROR_EINVAL;
    }
    if (!Emu::aprCommandBufferHasScatterGatherState(&m_commandBuffer)) {
        AMPR_LOGF("apr.cb.readFileGatherScatter reject this=%p rc=0x%x reason=no-gather-state type=0x%x",
                  this, SCE_KERNEL_ERROR_EINVAL, (unsigned)m_commandBuffer.type);
        return SCE_KERNEL_ERROR_EINVAL;
    }
    const int rc = Emu::aprCommandBufferAppendReadGatherScatter(&m_commandBuffer, buffer, length, offset);
    AMPR_TLOGF("apr.cb.readFileGatherScatter leave this=%p rc=0x%x", this, rc);
    return rc;
}

int AprCommandBuffer::resetGatherScatterState() {
    AMPR_TLOGF("apr.cb.resetGatherScatterState enter this=%p cb=%p", this, &m_commandBuffer);
    const int rc = Emu::aprCommandBufferAppendResetGatherScatterState(&m_commandBuffer);
    AMPR_TLOGF("apr.cb.resetGatherScatterState leave this=%p rc=0x%x", this, rc);
    return rc;
}



int AprCommandBuffer::mapBegin(uint64_t va, uint64_t size, int type, int prot) {
    AMPR_TLOGF("apr.cb.mapBegin enter this=%p cb=%p va=0x%llx size=0x%llx type=%d prot=0x%x",
              this, &m_commandBuffer,
              (unsigned long long)va, (unsigned long long)size, type, prot);
    const int validateRc = Emu::aprValidateMapBeginArgs(va, size, type, prot);
    if (validateRc != 0) {
        AMPR_LOGF("apr.cb.mapBegin reject this=%p rc=0x%x reason=invalid-range va=0x%llx size=0x%llx type=%d prot=0x%x",
                  this,
                  validateRc,
                  (unsigned long long)va,
                  (unsigned long long)size,
                  type,
                  prot);
        return validateRc;
    }
    if (Emu::aprCommandBufferHasMapState(&m_commandBuffer)) {
        AMPR_LOGF("apr.cb.mapBegin reject this=%p rc=0x%x reason=already-in-map type=0x%x",
                  this, SCE_KERNEL_ERROR_EPERM, (unsigned)m_commandBuffer.type);
        return SCE_KERNEL_ERROR_EPERM;
    }
    const int commandProt = Emu::aprCommandMapProt(prot);
    if (commandProt != prot) {
        AMPR_CRITICAL_LOGF("apr.cb.prot.substitute op=MapBegin this=%p cb=%p va=0x%llx size=0x%llx type=%d prot=0x%x adjustedProt=0x%x",
                           this,
                           &m_commandBuffer,
                           (unsigned long long)va,
                           (unsigned long long)size,
                           type,
                           prot,
                           commandProt);
    }
    const int rc = Emu::aprCommandBufferAppendMapBegin(&m_commandBuffer, va, size, type, commandProt);
    AMPR_LOGF("apr.cb.mapBegin event=this=%p cb=%p rc=0x%x va=0x%llx size=0x%llx type=%d prot=0x%x commandProt=0x%x offset=0x%x commands=%d",
              this,
              &m_commandBuffer,
              rc,
              (unsigned long long)va,
              (unsigned long long)size,
              type,
              prot,
              commandProt,
              m_commandBuffer.offset,
              m_commandBuffer.num);
    AMPR_TLOGF("apr.cb.mapBegin leave this=%p rc=0x%x prot=0x%x commandProt=0x%x",
               this,
               rc,
               prot,
               commandProt);
    return rc;
}


int AprCommandBuffer::mapDirectBegin(uint64_t va, uint64_t dmemOffset, size_t size, int type, int prot) {
    AMPR_TLOGF("apr.cb.mapDirectBegin enter this=%p cb=%p va=0x%llx dmemOffset=0x%llx size=0x%llx type=%d prot=0x%x",
              this, &m_commandBuffer,
              (unsigned long long)va, (unsigned long long)dmemOffset, (unsigned long long)size,
              type, prot);
    const int validateRc = Emu::aprValidateMapDirectBeginArgs(va, dmemOffset, static_cast<uint64_t>(size), type, prot);
    if (validateRc != 0) {
        AMPR_LOGF("apr.cb.mapDirectBegin reject this=%p rc=0x%x reason=invalid-range va=0x%llx dmemOffset=0x%llx size=0x%llx type=%d prot=0x%x",
                  this,
                  validateRc,
                  (unsigned long long)va,
                  (unsigned long long)dmemOffset,
                  (unsigned long long)size,
                  type,
                  prot);
        return validateRc;
    }
    if (Emu::aprCommandBufferHasMapState(&m_commandBuffer)) {
        AMPR_LOGF("apr.cb.mapDirectBegin reject this=%p rc=0x%x reason=already-in-map type=0x%x",
                  this, SCE_KERNEL_ERROR_EPERM, (unsigned)m_commandBuffer.type);
        return SCE_KERNEL_ERROR_EPERM;
    }
    const int commandProt = Emu::aprCommandMapProt(prot);
    if (commandProt != prot) {
        AMPR_CRITICAL_LOGF("apr.cb.prot.substitute op=MapDirectBegin this=%p cb=%p va=0x%llx dmemOffset=0x%llx size=0x%llx type=%d prot=0x%x adjustedProt=0x%x",
                           this,
                           &m_commandBuffer,
                           (unsigned long long)va,
                           (unsigned long long)dmemOffset,
                           (unsigned long long)size,
                           type,
                           prot,
                           commandProt);
    }
    const int rc = Emu::aprCommandBufferAppendMapDirectBegin(&m_commandBuffer, va, dmemOffset, size, type, commandProt);
    AMPR_LOGF("apr.cb.mapDirectBegin event=this=%p cb=%p rc=0x%x va=0x%llx dmemOffset=0x%llx size=0x%llx type=%d prot=0x%x commandProt=0x%x offset=0x%x commands=%d",
              this,
              &m_commandBuffer,
              rc,
              (unsigned long long)va,
              (unsigned long long)dmemOffset,
              (unsigned long long)size,
              type,
              prot,
              commandProt,
              m_commandBuffer.offset,
              m_commandBuffer.num);
    AMPR_TLOGF("apr.cb.mapDirectBegin leave this=%p rc=0x%x prot=0x%x commandProt=0x%x",
               this,
               rc,
               prot,
               commandProt);
    return rc;
}


int AprCommandBuffer::mapEnd() {
    AMPR_TLOGF("apr.cb.mapEnd enter this=%p cb=%p", this, &m_commandBuffer);
    if (!Emu::aprCommandBufferHasMapState(&m_commandBuffer)) {
        AMPR_LOGF("apr.cb.mapEnd reject this=%p rc=0x%x reason=not-in-map type=0x%x",
                  this, SCE_KERNEL_ERROR_EPERM, (unsigned)m_commandBuffer.type);
        return SCE_KERNEL_ERROR_EPERM;
    }
    const int rc = Emu::aprCommandBufferAppendMapEnd(&m_commandBuffer);
    AMPR_TLOGF("apr.cb.mapEnd leave this=%p rc=0x%x", this, rc);
    return rc;
}


} // namespace sce::Ampr
