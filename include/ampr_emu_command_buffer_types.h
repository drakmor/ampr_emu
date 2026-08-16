/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Internal SDK-compatible command-buffer object types.
 */

#pragma once

#include "ampr_emu_command_types.h"

#include <cstddef>
#include <kernel.h>
#include <sys/types.h>

namespace sce::Ampr {
// C++ wrapper around the retail command-buffer header.
class CommandBuffer {
public:
    SceAmprCommandBuffer m_commandBuffer;

public:
    explicit CommandBuffer(void);
    ~CommandBuffer(void);

private:
    CommandBuffer(const CommandBuffer&) = delete;
    CommandBuffer& operator=(const CommandBuffer&) = delete;

public:
    int reset(void);
    int setBuffer(void* buffer, uint32_t size);
    void* clearBuffer(void);

    int      getType() const;
    uint32_t getSize() const;
    caddr_t  getBufferBaseAddress() const;
    uint32_t getNumCommands() const;
    uint32_t getCurrentOffset() const;

    int waitOnAddress(volatile uint64_t* address, uint64_t refValue, WaitCompare eCmp, WaitFlush eFlush);
    int waitOnAddress_04_00(volatile uint64_t* address, uint64_t refValue, WaitCompare eCmp, WaitFlush eFlush);
    int waitOnCounter_04_00(uint8_t counterIndex, uint8_t valueWidth, uint64_t refValue, WaitCompare eCmp, uint8_t extraFlag, uint64_t extraValue, WaitFlush eFlush);
    int waitOnCounter(uint8_t counterIndex, CounterAccessSizeAndOffset eAccessSizeAndOffset, uint64_t refValue, WaitCompare eCmp, WaitOnCounterMaskOperation eMaskOp, uint64_t mask, WaitFlush eFlush);
    int waitOnCounter(uint8_t counterIndex, CounterAccessSizeAndOffset eAccessSizeAndOffset, uint64_t refValue, WaitCompare eCmp, WaitFlush eFlush);
    int waitOnCounter(uint8_t counterIndex, uint32_t refValue, WaitCompare eCmp, WaitOnCounterMaskOperation eMaskOp, uint32_t mask, WaitFlush eFlush);
    int waitOnCounter(uint8_t counterIndex, uint32_t refValue, WaitCompare eCmp, WaitFlush eFlush);

    int writeAddress_04_00(volatile uint64_t* address, uint64_t value, bool atSop);
    int writeAddressOnCompletion(volatile uint64_t* address, uint64_t value);
    int writeAddressImmediately(volatile uint64_t* address, uint64_t value);
    int writeCounter_04_00(uint8_t counterIndex, uint8_t valueWidth, uint64_t value, uint8_t counterMode, bool atSop);
    int writeCounterOnCompletion(uint8_t counterIndex, CounterAccessSizeAndOffset eAccessSizeAndOffset, uint64_t value, WriteCounterOperation eWriteOp);
    int writeCounterOnCompletion(uint8_t counterIndex, uint32_t value, WriteCounterOperation eWriteOp);
    int writeCounterOnCompletion(uint8_t counterIndex, uint32_t value);
    int writeKernelEventQueue_04_00(SceKernelEqueue eq, int32_t id, uint64_t data, bool atSop);
    int writeKernelEventQueueOnCompletion(SceKernelEqueue eq, int32_t id, uint64_t data);

    int writeAddressFromTimeCounter_04_00(volatile uint64_t* address, bool atSop);
    int writeAddressFromCounter_04_00(volatile uint64_t* address, uint8_t counterIndex, bool atSop);
    int writeAddressFromCounterPair_04_00(volatile uint64_t* address, uint8_t counterIdxStartAlign2, bool atSop);
    int writeAddressFromTimeCounterOnCompletion(volatile uint64_t* address);
    int writeAddressFromCounterOnCompletion(volatile uint64_t* address, uint8_t counterIndex);
    int writeAddressFromCounterPairOnCompletion(volatile uint64_t* address, uint8_t counterIdxStartAlign2);

    int nop(uint32_t num);
    int nop(uint32_t numU32, const uint32_t* aData /*[numU32]*/);
    int constructNop(uint32_t nopType, const void* payload, uint32_t payloadSize, const uint32_t* optWord);

    int setMarker(const char* msg, uint32_t color);
    int setMarker(const char* msg);
    int pushMarker(const char* msg, uint32_t color);
    int pushMarker(const char* msg);
    int popMarker();
};

class AmmCommandBuffer : public CommandBuffer {
public:
    explicit AmmCommandBuffer(void);
    ~AmmCommandBuffer(void);

private:
    AmmCommandBuffer(const AmmCommandBuffer&) = delete;
    AmmCommandBuffer& operator=(const AmmCommandBuffer&) = delete;

public:
    int map(uint64_t va, uint64_t size, int type, int prot);
    int mapWithGpuMaskId(uint64_t va, uint64_t size, int type, int prot, uint8_t gpuMaskId);

    int mapDirect(uint64_t va, uint64_t dmemOffset, size_t size, int type, int prot);
    int mapDirectWithGpuMaskId(uint64_t va, uint64_t dmemOffset, uint64_t size, int type, int prot, uint8_t gpuMaskId);

    int unmap(uint64_t va, size_t size);

    int remap(uint64_t vaNewStart, uint64_t vaOldStart, uint64_t vaSize, int prot);
    int remapWithGpuMaskId(uint64_t vaNewStart, uint64_t vaOldStart, uint64_t vaSize, int prot, uint8_t gpuMaskId);

    int multiMap(uint64_t vaStart, uint64_t vaAliasStart, uint64_t vaSize, int prot);
    int multiMapWithGpuMaskId(uint64_t vaStart, uint64_t vaAliasStart, uint64_t vaSize, int prot, uint8_t gpuMaskId);

    int modifyProtect(uint64_t va, uint64_t size, int prot, int protMask);
    int modifyProtectWithGpuMaskId(uint64_t va, uint64_t size, int prot, int protMask, uint8_t gpuMaskId);

    int modifyMtypeProtect(uint64_t va, uint64_t size, int type, int prot, int protMask);
    int modifyMtypeProtectWithGpuMaskId(uint64_t va, uint64_t size, int type, int prot, int protMask, uint8_t gpuMaskId);

    int mapAsPrt(uint64_t va, uint64_t size);
    int allocatePaForPrt(uint64_t va, uint64_t size, int type, int prot);

    // Raw opcode form used by the PRX export layer.
    int remapIntoPrt(uint64_t vaPrtStart, uint64_t vaOldStart, uint64_t size, int prot, uint32_t opcode);
    int unmapToPrt(uint64_t va, uint64_t size);
};

class AprCommandBuffer : public CommandBuffer {
public:
    explicit AprCommandBuffer(void);
    ~AprCommandBuffer(void);

private:
    __SceAprMapState           m_mapState;
    __SceAprScatterGatherState m_scatterGatherState;

    AprCommandBuffer(const AprCommandBuffer&) = delete;
    AprCommandBuffer& operator=(const AprCommandBuffer&) = delete;

public:
    int readFile(SceAprFileId fileId, void* buffer, uint64_t length, uint64_t offset);
    int readFileGather(uint64_t length, uint64_t offset);
    int readFileScatter(void* buffer, uint64_t length);
    int readFileGatherScatter(void* buffer, uint64_t length, uint64_t offset);
    int resetGatherScatterState();

    int mapBegin(uint64_t va, uint64_t size, int type, int prot);
    int mapDirectBegin(uint64_t va, uint64_t dmemOffset, size_t size, int type, int prot);
    int mapEnd();
};

static_assert(sizeof(SceAmprCommandBuffer) == 24, "Retail SceAmprCommandBuffer must stay 24 bytes");
static_assert(offsetof(SceAmprCommandBuffer, type) == 0, "SceAmprCommandBuffer type offset drifted");
static_assert(offsetof(SceAmprCommandBuffer, offset) == 4, "SceAmprCommandBuffer offset field drifted");
static_assert(offsetof(SceAmprCommandBuffer, num) == 8, "SceAmprCommandBuffer num offset drifted");
static_assert(offsetof(SceAmprCommandBuffer, bufsize) == 12, "SceAmprCommandBuffer bufsize offset drifted");
static_assert(offsetof(SceAmprCommandBuffer, buffer) == 16, "SceAmprCommandBuffer buffer offset drifted");
static_assert(sizeof(CommandBuffer) == sizeof(SceAmprCommandBuffer), "CommandBuffer layout drifted from retail");
static_assert(alignof(CommandBuffer) == alignof(SceAmprCommandBuffer), "CommandBuffer alignment drifted from retail");
static_assert(sizeof(AmmCommandBuffer) == sizeof(CommandBuffer), "AmmCommandBuffer ctor must stay no-op");
static_assert(sizeof(__SceAprMapState) == 8, "APR map state ABI drifted");
static_assert(sizeof(__SceAprScatterGatherState) == 8, "APR scatter/gather state ABI drifted");
static_assert(sizeof(AprCommandBuffer) == 40, "AprCommandBuffer layout drifted from retail");
static_assert(alignof(AprCommandBuffer) == alignof(uint64_t), "AprCommandBuffer alignment drifted from retail");

} // namespace sce::Ampr
