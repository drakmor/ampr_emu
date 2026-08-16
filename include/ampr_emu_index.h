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
