/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Portable validation/planning core for AMPRPAK4. The PS5 runtime and host
 * tests use the same parser, metadata CRC implementation and raw-LZ4 decode
 * boundary.
 */
#pragma once

#include "ampr_emu_pack_format.h"

#include <cstddef>
#include <cstdint>

struct AmprPackCoreView {
    const uint8_t* base{};
    size_t size{};
    const AmprPackIndexHeader* header{};
    const AmprPackFileRecord* files{};
    const AmprPackChunkRecord* chunks{};
    const AmprPackDataRecord* packs{};
    const char* strings{};
    size_t stringsSize{};
};

// Fully decoded chunk descriptor used by the runtime. AMPRPAK4 derives rawSize
// from the owning file's block geometry and keeps only compact physical fields
// on disk.
struct AmprPackChunkView {
    uint64_t offset{};
    uint32_t storedSize{};
    uint32_t rawSize{};
    uint16_t packId{};
    uint8_t codec{};
    uint8_t flags{};
};

struct AmprPackBlockReadTask {
    uint32_t chunkIndex{};
    uint32_t sourceOffset{};
    uint32_t copyLength{};
    uint32_t destinationOffset{};
    AmprPackChunkView chunk{};
};

enum AmprPackCoreResult : int {
    kAmprPackCoreOk = 0,
    kAmprPackCoreInvalidArgument = -1,
    kAmprPackCoreInvalidFormat = -2,
    kAmprPackCoreChecksumMismatch = -3,
    kAmprPackCoreOutOfRange = -4,
    kAmprPackCoreUnsupported = -5,
    kAmprPackCoreDestinationTooSmall = -6,
};

uint32_t ampr_pack_crc32(const void* data, size_t size, uint32_t seed = 0);
uint64_t ampr_pack_path_hash(const char* path, size_t length);

int ampr_pack_core_mount(const void* data, size_t size, AmprPackCoreView* out);
const char* ampr_pack_core_string(const AmprPackCoreView& view,
                                  uint32_t offset,
                                  uint32_t length);
const AmprPackFileRecord* ampr_pack_core_file(const AmprPackCoreView& view,
                                              uint32_t fileId);
bool ampr_pack_core_file_is_packed(const AmprPackCoreView& view,
                                   uint32_t fileId);
int ampr_pack_core_validate_logical_file(const AmprPackCoreView& view,
                                         uint32_t fileId,
                                         const char* path,
                                         size_t pathLength,
                                         uint64_t logicalSize);

int ampr_pack_core_chunk(const AmprPackCoreView& view,
                         const AmprPackFileRecord& file,
                         uint32_t localChunkIndex,
                         AmprPackChunkView* out);

size_t ampr_pack_core_task_count(const AmprPackFileRecord& file,
                                 uint64_t offset,
                                 uint64_t length);
int ampr_pack_core_make_task(const AmprPackCoreView& view,
                             const AmprPackFileRecord& file,
                             uint64_t offset,
                             uint64_t length,
                             size_t taskIndex,
                             AmprPackBlockReadTask* out);

bool ampr_pack_core_chunk_page_safe(const AmprPackDataRecord& pack,
                                    const AmprPackChunkView& chunk);

int ampr_pack_core_validate_data_header(const void* data,
                                        size_t size,
                                        uint32_t expectedPackId,
                                        const uint8_t expectedBuildId[16],
                                        uint32_t expectedFlags,
                                        uint64_t expectedFileSize,
                                        uint64_t expectedPayloadBytes,
                                        uint64_t* outPayloadOffset,
                                        uint64_t* outPayloadEnd);

int ampr_pack_core_decode_chunk(const AmprPackChunkView& chunk,
                                const void* stored,
                                size_t storedSize,
                                void* raw,
                                size_t rawCapacity);
