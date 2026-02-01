/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (C) 2026 Roman Tarasov
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

/*
 * SDK-compatible AMPR public header
 *
 * This project needs the original ABI (class/layout + signatures) so that SDK
 * tests can be compiled with minimal/no changes and so the resulting binaries
 * remain drop-in compatible.
 *
 * We keep this header self-contained and ordered correctly for non-SDK toolchains.
 */

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "kernel.h" // SceKernelEqueue, SceKernelStat, protection flags, ...

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t SceAmmSubmitId;
typedef uint32_t SceAprSubmitId;
typedef uint32_t SceAprFileId;

typedef struct SceAmmResultBuffer {
    int      result;
    uint32_t errorOffset;
} SceAmmResultBuffer;

typedef struct SceAprResultBuffer {
    int      result;
    uint32_t errorOffset;
} SceAprResultBuffer;

typedef struct SceAmprCommandBuffer {
    int              type;
    uint32_t         offset;
    volatile int32_t num;
    uint32_t         bufsize;
    void*            buffer;
} SceAmprCommandBuffer;

typedef union __SceAprMapState {
    struct {
        uint64_t m_isInMapBegin : 1;
        uint64_t m_numPages16K  : 21;
        uint64_t m_vaMap_b14_47 : 34;
        uint64_t m_reserved     : 8;
    };
    uint64_t asU64;
} __SceAprMapState;

typedef union __SceAprScatterGatherState {
    struct {
        uint64_t m_vaOutputBufferEnd : 48;
        uint64_t rsv                 : 15;
        uint64_t m_isValid           : 1;
    };
    uint64_t asU64;
} __SceAprScatterGatherState;

/* AMPR limits (SDK 2.00) */
#ifndef SCE_AMPR_COMMAND_BUFFER_SIZE_MAX
#define SCE_AMPR_COMMAND_BUFFER_SIZE_MAX (64u * 1024u * 1024u)
#endif
#ifndef SCE_AMPR_APR_BUFFER_MAX
#define SCE_AMPR_APR_BUFFER_MAX SCE_AMPR_COMMAND_BUFFER_SIZE_MAX
#endif

/* APR limits */
#ifndef SCE_AMPR_APR_FILEID_INVALID
#define SCE_AMPR_APR_FILEID_INVALID (0xFFFFFFFFu)
#endif

/* C-facing encodings for enum classes. */
typedef uint8_t SceAmprWaitCompare;
typedef uint8_t SceAmprWaitFlush;

#define __SCE_AMPR_WAIT_COMPARE_EQUAL        (0)
#define __SCE_AMPR_WAIT_COMPARE_GREATER_THAN (1)
#define __SCE_AMPR_WAIT_COMPARE_LESS_THAN    (2)
#define __SCE_AMPR_WAIT_COMPARE_NOT_EQUAL    (3)

#define __SCE_AMPR_WAIT_COMMAND_FETCH_FLUSH_DISABLE (0)
#define __SCE_AMPR_WAIT_COMMAND_FETCH_FLUSH_ENABLE  (1)

#define __SCE_AMPR_APR_PRIORITY_0 (0)
#define __SCE_AMPR_APR_PRIORITY_1 (1)
#define __SCE_AMPR_APR_PRIORITY_2 (2)
#define __SCE_AMPR_APR_PRIORITY_3 (3)
#define __SCE_AMPR_APR_PRIORITY_4 (4)
#define __SCE_AMPR_APR_PRIORITY_5 (5)
#define __SCE_AMPR_APR_PRIORITY_6 (6)

#ifdef __cplusplus
} // extern "C"
#endif

#ifdef __cplusplus

namespace sce {
namespace Ampr {

enum class WaitCompare : SceAmprWaitCompare {
    kEqual       = __SCE_AMPR_WAIT_COMPARE_EQUAL,
    kGreaterThan = __SCE_AMPR_WAIT_COMPARE_GREATER_THAN,
    kLessThan    = __SCE_AMPR_WAIT_COMPARE_LESS_THAN,
    kNotEqual    = __SCE_AMPR_WAIT_COMPARE_NOT_EQUAL,
};

enum class WaitFlush : SceAmprWaitFlush {
    kDisable = __SCE_AMPR_WAIT_COMMAND_FETCH_FLUSH_DISABLE,
    kEnable  = __SCE_AMPR_WAIT_COMMAND_FETCH_FLUSH_ENABLE,
};

struct AmmVirtualAddressRanges {
    uint64_t vaStart;
    uint64_t vaEnd;
    uint64_t multimapVaStart;
    uint64_t multimapVaEnd;
};

class CommandBuffer {
public:
    SceAmprCommandBuffer m_commandBuffer;

public:
    explicit CommandBuffer(void);
    ~CommandBuffer(void);

private:
    CommandBuffer(const CommandBuffer& x);
    CommandBuffer& operator=(const CommandBuffer& x);

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
    int waitOnCounter(uint8_t counterIndex, uint32_t refValue, WaitCompare eCmp, WaitFlush eFlush);

    int writeAddressOnCompletion(volatile uint64_t* address, uint64_t value);
    int writeCounterOnCompletion(uint8_t counterIndex, uint32_t value);
    int writeKernelEventQueueOnCompletion(SceKernelEqueue eq, int32_t id, uint64_t data);

    int writeAddressFromTimeCounterOnCompletion(volatile uint64_t* address);
    int writeAddressFromCounterOnCompletion(volatile uint64_t* address, uint8_t counterIndex);
    int writeAddressFromCounterPairOnCompletion(volatile uint64_t* address, uint8_t counterIdxStartAlign2);

    int nop(uint32_t num);
    int nop(uint32_t numU32, const uint32_t* aData /*[numU32]*/);

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
    AmmCommandBuffer(const AmmCommandBuffer& x);
    AmmCommandBuffer& operator=(const AmmCommandBuffer& x);

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

    int remapIntoPrt(uint64_t va, uint64_t size, uint64_t arg4, int prot);
    int unmapToPrt(uint64_t va, uint64_t size);
};

class AprCommandBuffer : public CommandBuffer {
public:
    explicit AprCommandBuffer(void);
    ~AprCommandBuffer(void);

private:
    __SceAprMapState           m_mapState;
    __SceAprScatterGatherState m_scatterGatherState;

    AprCommandBuffer(const AprCommandBuffer& x);
    AprCommandBuffer& operator=(const AprCommandBuffer& x);

public:
    int readFile(SceAprFileId fileId, void* buffer, uint64_t length, uint64_t offset);
    int readFileGather(uint64_t length, uint64_t offset);
    int readFileScatter(void* buffer, uint64_t length);
    int readFileGatherScatter(void* buffer, uint64_t length, uint64_t offset);
    int resetGatherScatterState();

    int mapBegin(uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5);
    int mapDirectBegin(uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6);
    int mapEnd();
};

class Amm {
private:
    Amm();
    ~Amm();
    Amm(const Amm&);
    Amm& operator=(const Amm&);

public:
    enum class Usage {
        kDirect,
        kAuto,
    };
    enum class Priority {
        kHigh,
        kMid,
        kLow,
    };

    static void getVirtualAddressRanges(AmmVirtualAddressRanges& ranges);
    static int giveDirectMemory(off_t searchStart, off_t searchEnd, size_t size, size_t alignment, Usage usage, off_t* dmemOffset);

    static int submitCommandBuffer(const AmmCommandBuffer* commandBuffer, Priority pri);
    static int submitCommandBuffer(AmmCommandBuffer* commandBuffer, Priority pri, SceAmmSubmitId* sid);
    static int submitCommandBufferAndGetResult(AmmCommandBuffer* commandBuffer, Priority prio, SceAmmResultBuffer* res, SceAmmSubmitId* id);
    static int waitCommandBufferCompletion(SceAmmSubmitId id);
};

class Apr {
private:
    Apr();
    ~Apr();
    Apr(const Apr&);
    Apr& operator=(const Apr&);

public:
    enum class Priority {
        kPriority0 = __SCE_AMPR_APR_PRIORITY_0,
        kPriority1 = __SCE_AMPR_APR_PRIORITY_1,
        kPriority2 = __SCE_AMPR_APR_PRIORITY_2,
        kPriority3 = __SCE_AMPR_APR_PRIORITY_3,
        kPriority4 = __SCE_AMPR_APR_PRIORITY_4,
        kPriority5 = __SCE_AMPR_APR_PRIORITY_5,
        kPriority6 = __SCE_AMPR_APR_PRIORITY_6,
    };

    static const SceAprFileId kFileIdInvalid = SCE_AMPR_APR_FILEID_INVALID;

    static int resolveFilepathsToIds(const char* path[], uint32_t num, SceAprFileId ids[], uint32_t* errorIndex);
    static int resolveFilepathsToIdsAndFileSizes(const char* path[], uint32_t num, SceAprFileId ids[], size_t fileSizes[], uint32_t* errorIndex);
    static int resolveFilepathsWithPrefixToIds(const char* pathPrefix, const char* path[], uint32_t num, SceAprFileId ids[], uint32_t* errorIndex);
    static int resolveFilepathsWithPrefixToIdsAndFileSizes(const char* pathPrefix, const char* path[], uint32_t num, SceAprFileId ids[], size_t fileSizes[], uint32_t* errorIndex);

    static int resolveFilepathsToIdsForEach(const char* path[], uint32_t num, SceAprFileId ids[], int results[]);
    static int resolveFilepathsToIdsAndFileSizesForEach(const char* path[], uint32_t num, SceAprFileId ids[], size_t fileSizes[], int results[]);
    static int resolveFilepathsWithPrefixToIdsForEach(const char* pathPrefix, const char* path[], uint32_t num, SceAprFileId ids[], int results[]);
    static int resolveFilepathsWithPrefixToIdsAndFileSizesForEach(const char* pathPrefix, const char* path[], uint32_t num, SceAprFileId ids[], size_t fileSizes[], int results[]);

    static int getFileSize(SceAprFileId fileId, size_t* size);
    static int getFileStat(SceAprFileId fileId, SceKernelStat* st);

    static int submitCommandBuffer(AprCommandBuffer* commandBuffer, Priority prio);
    static int submitCommandBuffer(AprCommandBuffer* commandBuffer, Priority prio, SceAprSubmitId* id);
    static int submitCommandBufferAndGetResult(AprCommandBuffer* commandBuffer, Priority prio, SceAprResultBuffer* res, SceAprSubmitId* id);
    static int waitCommandBufferCompletion(SceAprSubmitId id);
};

class MeasureCommandSize {
public:
    static int waitOnAddress(volatile uint64_t* address, uint64_t refValue, WaitCompare eCmp, WaitFlush eFlush);
    static int waitOnCounter(uint8_t counterIndex, uint32_t refValue, WaitCompare eCmp, WaitFlush eFlush);
    static int writeAddressOnCompletion(volatile uint64_t* address, uint64_t value);
    static int writeCounterOnCompletion(uint8_t counterIndex, uint32_t value);
    static int writeKernelEventQueueOnCompletion(SceKernelEqueue eq, int32_t id, uint64_t data);
    static int nop(uint32_t num);
    static int nop(uint32_t numU32, const uint32_t* aData);
};

class MeasureAmmCommandSize {
public:
    static int map(uint64_t va, uint64_t size, int type, int prot);
    static int mapWithGpuMaskId(uint64_t va, uint64_t size, int type, int prot, uint8_t gpuMaskId);
    static int mapDirect(uint64_t va, uint64_t dmemOffset, size_t size, int type, int prot);
    static int mapDirectWithGpuMaskId(uint64_t va, uint64_t dmemOffset, uint64_t size, int type, int prot, uint8_t gpuMaskId);
    static int unmap(uint64_t va, size_t size);
    static int remap(uint64_t vaNewStart, uint64_t vaOldStart, uint64_t vaSize, int prot);
    static int remapWithGpuMaskId(uint64_t vaNewStart, uint64_t vaOldStart, uint64_t vaSize, int prot, uint8_t gpuMaskId);
    static int multiMap(uint64_t vaStart, uint64_t vaAliasStart, uint64_t vaSize, int prot);
    static int multiMapWithGpuMaskId(uint64_t vaStart, uint64_t vaAliasStart, uint64_t vaSize, int prot, uint8_t gpuMaskId);
    static int modifyProtect(uint64_t va, uint64_t size, int prot, int protMask);
    static int modifyProtectWithGpuMaskId(uint64_t va, uint64_t size, int prot, int protMask, uint8_t gpuMaskId);
    static int modifyMtypeProtect(uint64_t va, uint64_t size, int type, int prot, int protMask);
    static int modifyMtypeProtectWithGpuMaskId(uint64_t va, uint64_t size, int type, int prot, int protMask, uint8_t gpuMaskId);
    static int mapAsPrt(uint64_t va, uint64_t size);
    static int allocatePaForPrt(uint64_t va, uint64_t size, int type, int prot);
};

class MeasureAprCommandSize {
public:
    static int readFile(SceAprFileId fileId, void* buffer, uint64_t length, uint64_t offset);
    static int readFileGather(uint64_t length, uint64_t offset);
    static int readFileScatter(void* buffer, uint64_t length);
    static int readFileGatherScatter(void* buffer, uint64_t length, uint64_t offset);
    static int resetGatherScatterState();

    static int setMarker(const char* msg, uint32_t color);
    static int setMarker(const char* msg);
    static int pushMarker(const char* msg, uint32_t color);
    static int pushMarker(const char* msg);
    static int popMarker();
};

} // namespace Ampr
} // namespace sce

#endif // __cplusplus
