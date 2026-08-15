/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#if !defined(LIBSCEAMPR_IMPL)

#include_next <ampr.h>

#else

/*
 * Internal SDK-compatible AMPR leaf ABI model.
 *
 * Retail libSceAmpr exports only flat sceAmpr* C entrypoints. Keep this header
 * limited to the C-compatible ids, result buffers, command-buffer storage
 * layout, and encoded-value constants used by those leaf entrypoints.
 */

#include <stdint.h>

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
#ifndef SCE_AMPR_APR_RESOLVE_MAX
#define SCE_AMPR_APR_RESOLVE_MAX (1024u)
#endif

/* Command encoding domains. */
typedef uint8_t SceAmprWaitCompare;
typedef uint8_t SceAmprWaitFlush;
typedef uint8_t SceAmprCounterAccessSizeAndOffset;
typedef uint8_t SceAmprWaitOnCounterMaskOperation;
typedef uint8_t SceAmprWriteCounterOperation;

#define __SCE_AMPR_WAIT_COMPARE_EQUAL                         (0)
#define __SCE_AMPR_WAIT_COMPARE_GREATER_THAN_UNSIGNED         (1)
#define __SCE_AMPR_WAIT_COMPARE_LESS_THAN_UNSIGNED            (2)
#define __SCE_AMPR_WAIT_COMPARE_NOT_EQUAL                     (3)
#define __SCE_AMPR_WAIT_COMPARE_GREATER_THAN_OR_EQUAL_WRAPPED (4)
#define __SCE_AMPR_WAIT_COMPARE_GREATER_THAN_SIGNED           (5)
#define __SCE_AMPR_WAIT_COMPARE_LESS_THAN_SIGNED              (6)
#define __SCE_AMPR_WAIT_COMPARE_GREATER_THAN                  __SCE_AMPR_WAIT_COMPARE_GREATER_THAN_UNSIGNED
#define __SCE_AMPR_WAIT_COMPARE_LESS_THAN                     __SCE_AMPR_WAIT_COMPARE_LESS_THAN_UNSIGNED

#define __SCE_AMPR_COUNTER_ACCESS_SIZE_8          (0)
#define __SCE_AMPR_COUNTER_ACCESS_SIZE_4          (1)
#define __SCE_AMPR_COUNTER_ACCESS_SIZE_2_OFFSET_0 (2)
#define __SCE_AMPR_COUNTER_ACCESS_SIZE_2_OFFSET_1 (3)
#define __SCE_AMPR_COUNTER_ACCESS_SIZE_1_OFFSET_0 (4)
#define __SCE_AMPR_COUNTER_ACCESS_SIZE_1_OFFSET_1 (5)
#define __SCE_AMPR_COUNTER_ACCESS_SIZE_1_OFFSET_2 (6)
#define __SCE_AMPR_COUNTER_ACCESS_SIZE_1_OFFSET_3 (7)

#define __SCE_AMPR_WAIT_ON_COUNTER_MASK_DISABLED (0)
#define __SCE_AMPR_WAIT_ON_COUNTER_MASK_AND      (1)

#define __SCE_AMPR_WRITE_COUNTER_STORE                 (0)
#define __SCE_AMPR_WRITE_COUNTER_ATOMIC_OR             (1)
#define __SCE_AMPR_WRITE_COUNTER_ATOMIC_AND_COMPLEMENT (2)
#define __SCE_AMPR_WRITE_COUNTER_ATOMIC_XOR            (3)
#define __SCE_AMPR_WRITE_COUNTER_ATOMIC_ADD            (4)

#define __SCE_AMPR_WAIT_COMMAND_FETCH_FLUSH_DISABLE (0)
#define __SCE_AMPR_WAIT_COMMAND_FETCH_FLUSH_ENABLE  (1)

#ifdef __cplusplus
} // extern "C"
#endif

#endif
