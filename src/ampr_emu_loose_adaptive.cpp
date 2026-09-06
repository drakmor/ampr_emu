/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Zero-configuration adaptive policy for ordinary AMPR loose-file reads.
 */

#include "ampr_emu_loose_adaptive.h"
#include "ampr_emu_sync.h"

#include <atomic>
#include <cstddef>
#include <cstdint>

namespace {
static_assert(AMPR_EMU_LOOSE_ADAPTIVE_FILE_CAPACITY >= 4u,
              "loose adaptive state needs at least four entries");
static_assert(AMPR_EMU_LOOSE_ADAPTIVE_FILE_WAYS >= 1u,
              "loose adaptive state associativity must be non-zero");
static_assert(AMPR_EMU_LOOSE_ADAPTIVE_FILE_CAPACITY >=
                  AMPR_EMU_LOOSE_ADAPTIVE_FILE_WAYS,
              "loose adaptive state capacity must cover every way");
static_assert(AMPR_EMU_LOOSE_ADAPTIVE_FILE_CAPACITY %
                      AMPR_EMU_LOOSE_ADAPTIVE_FILE_WAYS ==
                  0u,
              "loose adaptive state capacity must divide by associativity");
static_assert(AMPR_EMU_LOOSE_TINY_READ_MAX_BYTES <=
                  AMPR_EMU_LOOSE_SMALL_READ_MAX_BYTES,
              "tiny read threshold exceeds small read threshold");
static_assert(AMPR_EMU_LOOSE_SMALL_READ_MAX_BYTES <=
                  AMPR_EMU_LOOSE_BULK_READ_MIN_BYTES,
              "small read threshold exceeds bulk threshold");

constexpr uint32_t kStateCapacity =
    static_cast<uint32_t>(AMPR_EMU_LOOSE_ADAPTIVE_FILE_CAPACITY);
constexpr uint32_t kStateWays =
    static_cast<uint32_t>(AMPR_EMU_LOOSE_ADAPTIVE_FILE_WAYS);
constexpr uint32_t kStateSetCount = kStateCapacity / kStateWays;

struct LooseFileState {
    uint32_t fileId{};
    uint32_t accessCount{};
    uint64_t lastOffset{};
    uint64_t lastEnd{};
    uint64_t lastUseNs{};
    uint64_t lastTouch{};
    uint16_t sequentialStreak{};
    uint16_t randomScore{};
    uint16_t fullFileReadScore{};
    bool active{};
};

alignas(64) static LooseFileState g_states[kStateCapacity]{};
static std::atomic<uint32_t> g_state_lock{0};
static uint64_t g_touch_clock{1};

#if AMPR_EMU_DEBUG_LOG
static std::atomic<uint64_t> g_observations{0};
static std::atomic<uint64_t> g_latency_classifications{0};
static std::atomic<uint64_t> g_balanced_classifications{0};
static std::atomic<uint64_t> g_bulk_classifications{0};
static std::atomic<uint64_t> g_full_file_promotions{0};
static std::atomic<uint64_t> g_idle_resets{0};
static std::atomic<uint64_t> g_state_replacements{0};
#endif

static uint16_t saturating_increment(uint16_t value) {
    return value == UINT16_MAX ? value : static_cast<uint16_t>(value + 1u);
}

static uint32_t state_set(uint32_t fileId) {
    return static_cast<uint32_t>(
        (static_cast<uint64_t>(fileId) * 2654435761ull) % kStateSetCount);
}

static void reset_dynamic_state(LooseFileState& state) {
    state.accessCount = 0;
    state.lastOffset = 0;
    state.lastEnd = 0;
    state.sequentialStreak = 0;
    state.randomScore = 0;
    state.fullFileReadScore = 0;
}

static LooseFileState& find_or_replace_state_locked(uint32_t fileId) {
    const uint32_t base = state_set(fileId) * kStateWays;
    LooseFileState* replacement = nullptr;
    for (uint32_t way = 0; way < kStateWays; ++way) {
        LooseFileState& state = g_states[base + way];
        if (state.active && state.fileId == fileId) {
            return state;
        }
        if (!state.active) {
            replacement = &state;
            break;
        }
        if (!replacement || state.lastTouch < replacement->lastTouch) {
            replacement = &state;
        }
    }
    if (replacement->active) {
#if AMPR_EMU_DEBUG_LOG
        g_state_replacements.fetch_add(1u, std::memory_order_relaxed);
#endif
    }
    *replacement = {};
    replacement->active = true;
    replacement->fileId = fileId;
    return *replacement;
}

static AmprLooseReadClass classify_read(const LooseFileState& state,
                                         uint64_t length,
                                         bool completionCritical) {
    if (completionCritical ||
        length <= static_cast<uint64_t>(AMPR_EMU_LOOSE_TINY_READ_MAX_BYTES)) {
        return AmprLooseReadClass::Latency;
    }
    if (length <= static_cast<uint64_t>(AMPR_EMU_LOOSE_SMALL_READ_MAX_BYTES) &&
        state.sequentialStreak <
            static_cast<uint16_t>(AMPR_EMU_LOOSE_SEQUENTIAL_STREAK)) {
        return AmprLooseReadClass::Latency;
    }
    if (length >= static_cast<uint64_t>(AMPR_EMU_LOOSE_BULK_READ_MIN_BYTES) ||
        (state.sequentialStreak >=
             static_cast<uint16_t>(AMPR_EMU_LOOSE_SEQUENTIAL_STREAK) &&
         length >= static_cast<uint64_t>(
             AMPR_EMU_APR_READ_CREDIT_GRANULE_BYTES / 2u))) {
        return AmprLooseReadClass::Bulk;
    }
    return AmprLooseReadClass::Balanced;
}

static void note_classification(AmprLooseReadClass readClass) {
#if AMPR_EMU_DEBUG_LOG
    switch (readClass) {
        case AmprLooseReadClass::Latency:
            g_latency_classifications.fetch_add(1u, std::memory_order_relaxed);
            break;
        case AmprLooseReadClass::Balanced:
            g_balanced_classifications.fetch_add(1u, std::memory_order_relaxed);
            break;
        case AmprLooseReadClass::Bulk:
            g_bulk_classifications.fetch_add(1u, std::memory_order_relaxed);
            break;
        default:
            break;
    }
#else
    (void)readClass;
#endif
}
} // namespace

AmprLooseAdaptiveDecision ampr_loose_adaptive_observe(
    uint32_t fileId,
    uint64_t offset,
    uint64_t length,
    uint64_t fileSize,
    uint64_t nowNs,
    bool completionCritical) {
    AmprLooseAdaptiveDecision observation{};
#if !AMPR_EMU_LOOSE_ADAPTIVE_ENABLE
    (void)fileId;
    (void)offset;
    (void)fileSize;
    (void)nowNs;
    observation.readClass = completionCritical ||
                                    length <= AMPR_EMU_LOOSE_SMALL_READ_MAX_BYTES
                                ? AmprLooseReadClass::Latency
                                : (length >= AMPR_EMU_LOOSE_BULK_READ_MIN_BYTES
                                       ? AmprLooseReadClass::Bulk
                                       : AmprLooseReadClass::Balanced);
    return observation;
#else
    if (fileId == 0u || length == 0u) {
        observation.readClass = completionCritical
            ? AmprLooseReadClass::Latency
            : AmprLooseReadClass::Balanced;
        return observation;
    }

    AmprSpinLock lock(&g_state_lock);
    LooseFileState& state = find_or_replace_state_locked(fileId);
    if (AMPR_EMU_LOOSE_ADAPTIVE_IDLE_RESET_NS != 0ull &&
        state.lastUseNs != 0ull && nowNs >= state.lastUseNs &&
        nowNs - state.lastUseNs >=
            static_cast<uint64_t>(AMPR_EMU_LOOSE_ADAPTIVE_IDLE_RESET_NS)) {
        reset_dynamic_state(state);
#if AMPR_EMU_DEBUG_LOG
        g_idle_resets.fetch_add(1u, std::memory_order_relaxed);
#endif
    }

    const bool hasPrevious = state.accessCount != 0u;
    const bool contiguous = hasPrevious && offset == state.lastEnd;
    const bool overlapOrRewind = hasPrevious && offset < state.lastEnd;
    if (contiguous) {
        state.sequentialStreak = saturating_increment(state.sequentialStreak);
        if (state.randomScore != 0u) {
            --state.randomScore;
        }
    } else {
        state.sequentialStreak = 0u;
        if (hasPrevious && (overlapOrRewind || offset != state.lastEnd)) {
            state.randomScore = saturating_increment(state.randomScore);
        }
    }

    const bool fullFile = fileSize != 0u && offset == 0u && length == fileSize;
    const bool wasPromoted =
        state.fullFileReadScore >=
        static_cast<uint16_t>(AMPR_EMU_LOOSE_FULL_FILE_PROMOTE_HITS);
    if (fullFile) {
        state.fullFileReadScore =
            saturating_increment(state.fullFileReadScore);
    }
    const bool promoted =
        AMPR_EMU_LOOSE_FD_PROMOTION_ENABLE && fullFile &&
        AMPR_EMU_LOOSE_FULL_FILE_PROMOTE_HITS != 0u &&
        state.fullFileReadScore >=
            static_cast<uint16_t>(AMPR_EMU_LOOSE_FULL_FILE_PROMOTE_HITS);
    if (promoted && !wasPromoted) {
#if AMPR_EMU_DEBUG_LOG
        g_full_file_promotions.fetch_add(1u, std::memory_order_relaxed);
#endif
    }

    state.lastOffset = offset;
    state.lastEnd = offset <= UINT64_MAX - length
        ? offset + length
        : UINT64_MAX;
    state.lastUseNs = nowNs;
    state.lastTouch = g_touch_clock++;
    if (state.accessCount != UINT32_MAX) {
        ++state.accessCount;
    }
    if ((state.accessCount & 63u) == 0u) {
        state.randomScore = static_cast<uint16_t>(state.randomScore / 2u);
    }

    observation.readClass = classify_read(state, length, completionCritical);
    observation.sequentialStreak = state.sequentialStreak;
    observation.randomScore = state.randomScore;
    observation.fullFileReadScore = state.fullFileReadScore;
    observation.promoteFullFile = promoted;
    observation.sequential = contiguous;

#if AMPR_EMU_DEBUG_LOG
    g_observations.fetch_add(1u, std::memory_order_relaxed);
#endif
    note_classification(observation.readClass);
    return observation;
#endif
}

AmprLooseAdaptiveStats ampr_loose_adaptive_stats(bool reset) {
#if AMPR_EMU_DEBUG_LOG
    const auto loadOrReset = [reset](std::atomic<uint64_t>& value) {
        return reset ? value.exchange(0u, std::memory_order_relaxed)
                     : value.load(std::memory_order_relaxed);
    };
    return AmprLooseAdaptiveStats{
        loadOrReset(g_observations),
        loadOrReset(g_latency_classifications),
        loadOrReset(g_balanced_classifications),
        loadOrReset(g_bulk_classifications),
        loadOrReset(g_full_file_promotions),
        loadOrReset(g_idle_resets),
        loadOrReset(g_state_replacements),
    };
#else
    (void)reset;
    return {};
#endif
}

#if defined(AMPR_EMU_HOST_TEST)
void ampr_loose_adaptive_reset_for_tests() {
    AmprSpinLock lock(&g_state_lock);
    for (LooseFileState& state : g_states) {
        state = {};
    }
    g_touch_clock = 1;
    (void)ampr_loose_adaptive_stats(true);
}
#endif
