/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Internal APR file index boundary.
 */

#pragma once

#include <cstddef>
#include <cstdint>

struct FileEntryView {
    const char* path{};
    uint32_t pathLength{};
    size_t size{};
    int64_t mtime{};
};


int ampr_index_get_entry_view(uint32_t id, FileEntryView* out);
int ampr_index_resolve_path_to_id(const char* path, uint32_t* outId, size_t* outSize);

// AMPR service calls that are known not to run under a libkernel nonsleeping
// lock may complete the lazy index/manifest publication before returning.
bool ampr_index_ensure_ready_safe();

// Process-wide file hooks run while libkernel may hold a nonsleeping lock.
// These probes perform no allocation, locking, or lazy index construction.
bool ampr_index_path_has_app0_root_fast(const char* path);
bool ampr_index_is_resident_ready();
