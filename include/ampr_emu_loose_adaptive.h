/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Zero-configuration adaptive policy for ordinary AMPR loose-file reads.
 */
#pragma once

#include "ampr_emu_config.h"

#include <cstddef>
#include <cstdint>

enum class AmprLooseReadClass : uint8_t {
    Latency = 0,
    Balanced = 1,
    Bulk = 2,
    Count = 3,
};

struct AmprLooseAdaptiveDecision {
    AmprLooseReadClass readClass{AmprLooseReadClass::Balanced};
    uint16_t sequentialStreak{};
    uint16_t randomScore{};
    uint16_t fullFileReadScore{};
    bool promoteFullFile{};
    bool sequential{};
};

struct AmprLooseAdaptiveStats {
    uint64_t observations{};
    uint64_t latencyClassifications{};
    uint64_t balancedClassifications{};
    uint64_t bulkClassifications{};
    uint64_t fullFilePromotions{};
    uint64_t idleResets{};
    uint64_t stateReplacements{};
};

constexpr uint32_t ampr_loose_read_class_index(AmprLooseReadClass readClass) {
    return static_cast<uint32_t>(readClass);
}

constexpr uint8_t ampr_loose_read_class_rank(AmprLooseReadClass readClass) {
    return static_cast<uint8_t>(readClass);
}

constexpr bool ampr_loose_read_class_is_latency(AmprLooseReadClass readClass) {
    return readClass == AmprLooseReadClass::Latency;
}

constexpr bool ampr_loose_read_class_is_bulk(AmprLooseReadClass readClass) {
    return readClass == AmprLooseReadClass::Bulk;
}

constexpr uint32_t ampr_loose_latency_reserve(uint32_t effectiveLimit,
                                               bool waitingLatency) {
#if AMPR_EMU_LOOSE_AIO_RESERVE_ENABLE
    if (!waitingLatency || effectiveLimit <= 2u ||
        AMPR_EMU_LOOSE_LATENCY_RESERVED_MAX == 0u) {
        return 0u;
    }
    uint32_t reserve = effectiveLimit / 8u;
    if (reserve == 0u) {
        reserve = 1u;
    }
    const uint32_t configured =
        static_cast<uint32_t>(AMPR_EMU_LOOSE_LATENCY_RESERVED_MAX);
    if (reserve > configured) {
        reserve = configured;
    }
    if (reserve >= effectiveLimit) {
        reserve = effectiveLimit - 1u;
    }
    return reserve;
#else
    (void)effectiveLimit;
    (void)waitingLatency;
    return 0u;
#endif
}

constexpr bool ampr_loose_bulk_reserve_allows(uint32_t activeCount,
                                               uint32_t effectiveLimit,
                                               uint32_t reserve,
                                               AmprLooseReadClass readClass) {
    if (activeCount >= effectiveLimit) {
        return false;
    }
    if (!ampr_loose_read_class_is_bulk(readClass) || reserve == 0u) {
        return true;
    }
    return activeCount < effectiveLimit - reserve;
}

constexpr uint32_t ampr_loose_chain_chunk_limit(
    AmprLooseReadClass readClass,
    bool waitingLatency,
    bool constrained,
    bool shared,
    uint32_t hardLimit) {
    if (hardLimit == 0u) {
        return 0u;
    }
    if (waitingLatency || constrained ||
        ampr_loose_read_class_is_latency(readClass)) {
        return 1u;
    }
    if (shared) {
        return hardLimit < 2u ? hardLimit : 2u;
    }
    if (ampr_loose_read_class_is_bulk(readClass)) {
        return hardLimit;
    }
    return hardLimit < 2u ? hardLimit : 2u;
}

constexpr bool ampr_loose_pending_observation_blocks_coalescing(
    bool observationValid,
    uint32_t observationSourceOffset,
    uint32_t candidateSourceOffset) {
    return observationValid &&
           observationSourceOffset == candidateSourceOffset;
}

constexpr bool ampr_loose_pending_observation_is_in_failed_suffix(
    bool observationValid,
    uint32_t observationSourceOffset,
    uint32_t errorSourceOffset) {
    return observationValid && observationSourceOffset >= errorSourceOffset;
}

constexpr bool ampr_loose_contiguous_read(
    uint32_t firstFileId,
    uint64_t firstOffset,
    uint64_t currentCombinedLength,
    uintptr_t firstBuffer,
    uint32_t nextFileId,
    uint64_t nextOffset,
    uint64_t nextLength,
    uintptr_t nextBuffer,
    uint64_t maxCombinedLength) {
#if AMPR_EMU_LOOSE_COALESCE_ENABLE
    if (firstFileId == 0u || firstFileId != nextFileId ||
        nextLength == 0u ||
        currentCombinedLength == 0u || maxCombinedLength == 0u ||
        currentCombinedLength > maxCombinedLength ||
        nextLength > maxCombinedLength - currentCombinedLength) {
        return false;
    }
    if (firstOffset > UINT64_MAX - currentCombinedLength ||
        firstBuffer > UINTPTR_MAX - static_cast<uintptr_t>(currentCombinedLength)) {
        return false;
    }
    return nextOffset == firstOffset + currentCombinedLength &&
           nextBuffer == firstBuffer + static_cast<uintptr_t>(currentCombinedLength);
#else
    (void)firstFileId;
    (void)firstOffset;
    (void)firstBuffer;
    (void)nextFileId;
    (void)nextOffset;
    (void)nextLength;
    (void)nextBuffer;
    (void)currentCombinedLength;
    (void)maxCombinedLength;
    return false;
#endif
}

enum class AmprLooseGsReadKind : uint8_t {
    File = 0,
    Gather = 1,
    Scatter = 2,
    GatherScatter = 3,
};

struct AmprLooseGsState {
    uint64_t nextOffset{};
    uintptr_t nextBuffer{};
    uint32_t fileId{};
};

struct AmprLooseGsCommand {
    AmprLooseGsReadKind kind{AmprLooseGsReadKind::File};
    uint32_t fileId{};
    uintptr_t buffer{};
    uint64_t length{};
    uint64_t offset{};
};

struct AmprLooseGsResolvedRead {
    uint32_t fileId{};
    uintptr_t buffer{};
    uint64_t length{};
    uint64_t offset{};
    bool valid{};
};

constexpr bool ampr_loose_gs_kind_is_stateful(AmprLooseGsReadKind kind) {
    return kind != AmprLooseGsReadKind::File;
}

constexpr AmprLooseGsResolvedRead ampr_loose_gs_resolve(
    const AmprLooseGsState& state,
    const AmprLooseGsCommand& command) {
    AmprLooseGsResolvedRead read{};
    read.length = command.length;
    switch (command.kind) {
        case AmprLooseGsReadKind::File:
            read.fileId = command.fileId;
            read.buffer = command.buffer;
            read.offset = command.offset;
            break;
        case AmprLooseGsReadKind::Gather:
            if (state.fileId == 0u || state.nextBuffer == 0u) {
                return read;
            }
            read.fileId = state.fileId;
            read.buffer = state.nextBuffer;
            read.offset = command.offset;
            break;
        case AmprLooseGsReadKind::Scatter:
            if (state.fileId == 0u || state.nextOffset == 0u) {
                return read;
            }
            read.fileId = state.fileId;
            read.buffer = command.buffer;
            read.offset = state.nextOffset;
            break;
        case AmprLooseGsReadKind::GatherScatter:
            if (state.fileId == 0u) {
                return read;
            }
            read.fileId = state.fileId;
            read.buffer = command.buffer;
            read.offset = command.offset;
            break;
        default:
            return read;
    }
    // `valid` represents successful gather/scatter state resolution only.
    // File IDs, buffers, lengths and ranges are validated later by the APR
    // reactor so existing error codes and error offsets remain unchanged.
    read.valid = true;
    return read;
}

constexpr AmprLooseGsState ampr_loose_gs_advance(
    const AmprLooseGsResolvedRead& read,
    uint64_t offsetMaxExclusive) {
    AmprLooseGsState state{};
    if (!read.valid || offsetMaxExclusive == 0u) {
        return state;
    }
    state.fileId = read.fileId;
    const uint64_t maximumOffset = offsetMaxExclusive - 1u;
    state.nextOffset =
        read.offset < offsetMaxExclusive &&
                read.length < offsetMaxExclusive - read.offset
            ? read.offset + read.length
            : maximumOffset;
    state.nextBuffer =
        read.buffer <= UINTPTR_MAX - static_cast<uintptr_t>(read.length)
            ? read.buffer + static_cast<uintptr_t>(read.length)
            : UINTPTR_MAX;
    return state;
}

constexpr bool ampr_loose_gs_state_equal(const AmprLooseGsState& lhs,
                                         const AmprLooseGsState& rhs) {
    return lhs.nextOffset == rhs.nextOffset &&
           lhs.nextBuffer == rhs.nextBuffer &&
           lhs.fileId == rhs.fileId;
}

AmprLooseAdaptiveDecision ampr_loose_adaptive_observe(
    uint32_t fileId,
    uint64_t offset,
    uint64_t length,
    uint64_t fileSize,
    uint64_t nowNs,
    bool completionCritical);

AmprLooseAdaptiveStats ampr_loose_adaptive_stats(bool reset);

#if defined(AMPR_EMU_HOST_TEST)
void ampr_loose_adaptive_reset_for_tests();
#endif
