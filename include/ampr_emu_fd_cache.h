/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Internal APR fd-cache runtime boundary.
 */

#pragma once

#include <cstddef>
#include <cstdint>

struct FileEntryView;

struct AmprIndexFdPressureCaps {
    size_t fdBudget{};
    size_t cacheCap{};
    size_t directCap{};
};

struct AmprIndexFdCacheStats {
    size_t entries{};
    size_t open{};
    size_t pinnedOpen{};
    size_t pins{};
    size_t evictable{};
};

struct AmprIndexFdCacheDiagCounters {
    uint64_t hits{};
    uint64_t misses{};
    uint64_t emfile{};
};

void ampr_fd_cache_prewarm_runtime_state();

int ampr_index_acquire_cached_fd(uint64_t jobId,
                                 uint32_t id,
                                 const FileEntryView& entry,
                                 int flags,
                                 int mode);
void ampr_index_release_cached_fd_pin(uint32_t fileId);
int ampr_index_pin_file_id(uint32_t fileId, uint32_t* outPinCount);
int ampr_index_unpin_file_id(uint32_t fileId, uint32_t* outPinCount);
void ampr_index_fd_direct_note_open();
void ampr_index_fd_direct_note_close();
size_t ampr_index_fd_direct_open_count();
size_t ampr_index_fd_open_budget_effective_cap();
void ampr_index_fd_open_budget_set_effective_cap(size_t cap);
AmprIndexFdPressureCaps ampr_index_fd_pressure_current_caps();
AmprIndexFdPressureCaps ampr_index_fd_cache_mark_open_pressure(size_t observedOpen);
uint64_t ampr_index_fd_cache_open_pressure_generation();
void ampr_index_fd_cache_set_effective_cap(size_t cap);
AmprIndexFdCacheStats ampr_index_fd_cache_stats();
AmprIndexFdCacheDiagCounters ampr_index_fd_cache_diag_counters(bool reset);
size_t ampr_index_fd_cache_release_stale(uint64_t nowNs);
void ampr_index_fd_cache_release_open_fd_headroom(size_t reserve, size_t cap);
bool ampr_index_fd_cache_release_open_fd_budget_headroom(size_t reserve);
size_t ampr_index_fd_cache_release_idle_percent(unsigned percent);
bool ampr_index_fd_common_open_budget_headroom_available(size_t reserve,
                                                         size_t* outObserved = nullptr,
                                                         size_t* outBudget = nullptr,
                                                         size_t* outEvictable = nullptr);
bool ampr_index_fd_cached_open_budget_headroom_available(uint32_t fileId,
                                                         size_t* outObserved = nullptr,
                                                         size_t* outBudget = nullptr,
                                                         size_t* outEvictable = nullptr);
