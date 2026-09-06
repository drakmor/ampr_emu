/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Seekable AMPR asset-pack on-disk format. All integer fields are little-endian.
 *
 * AMPRPAK4 keeps AMPRDAT3 volumes unchanged while compacting every resident
 * chunk record from 16 to 12 bytes. Raw size is derived from the owning file's
 * block geometry. Decoded CRCs are stored only in an offline sidecar and are
 * deliberately absent from the runtime manifest and decode path.
 */
#pragma once

#include <cstddef>
#include <cstdint>

static constexpr char kAmprPackIndexMagic[8] = {'A','M','P','R','P','A','K','4'};
static constexpr char kAmprPackDataMagic[8]  = {'A','M','P','R','D','A','T','3'};
static constexpr uint32_t kAmprPackIndexVersion = 4;
static constexpr uint32_t kAmprPackDataVersion = 3;
static constexpr uint32_t kAmprPackEndianMarker = 0x01020304u;
static constexpr uint8_t kAmprPackBlockShiftMin = 14u; // 16 KiB
static constexpr uint8_t kAmprPackBlockShiftMax = 20u; // 1 MiB
static constexpr uint8_t kAmprPackIoPageShiftMin = 12u; // 4 KiB
static constexpr uint8_t kAmprPackIoPageShiftMax = 20u; // 1 MiB

static constexpr uint32_t kAmprPackFilePacked       = 1u << 0;
static constexpr uint32_t kAmprPackFileStoreOnly    = 1u << 1;
static constexpr uint32_t kAmprPackFileStreaming    = 1u << 2;
static constexpr uint32_t kAmprPackFileHot          = 1u << 3;
static constexpr uint32_t kAmprPackFileRandomAccess = 1u << 4;
static constexpr uint32_t kAmprPackFileKnownFlags =
    kAmprPackFilePacked | kAmprPackFileStoreOnly |
    kAmprPackFileStreaming | kAmprPackFileHot |
    kAmprPackFileRandomAccess;

static constexpr uint8_t kAmprPackChunkRaw = 0u;
static constexpr uint8_t kAmprPackChunkLz4 = 1u;
static constexpr uint8_t kAmprPackChunkShared        = 1u << 0;
static constexpr uint8_t kAmprPackChunkStreaming     = 1u << 1;
static constexpr uint8_t kAmprPackChunkPageContained = 1u << 2;
static constexpr uint8_t kAmprPackChunkPageAligned   = 1u << 3;
static constexpr uint8_t kAmprPackChunkKnownFlags =
    kAmprPackChunkShared | kAmprPackChunkStreaming |
    kAmprPackChunkPageContained | kAmprPackChunkPageAligned;

static constexpr uint32_t kAmprPackDataStriped = 1u << 0;
static constexpr uint32_t kAmprPackDataIoPageLayout = 1u << 1;
static constexpr uint32_t kAmprPackDataKnownFlags =
    kAmprPackDataStriped | kAmprPackDataIoPageLayout;
static constexpr uint32_t kAmprPackIndexKnownFlags = 0u;
static constexpr uint32_t kAmprPackPhysicalChunkAlignment = 64u;

// Compact chunk encoding.
static constexpr uint64_t kAmprPackChunkOffsetMask = (1ull << 48u) - 1ull;
static constexpr uint32_t kAmprPackChunkStoredBits = 20u;
static constexpr uint32_t kAmprPackChunkStoredMask =
    (1u << kAmprPackChunkStoredBits) - 1u;
static constexpr uint32_t kAmprPackChunkCodecShift = 20u;
static constexpr uint32_t kAmprPackChunkCodecMask = 0x3u;
static constexpr uint32_t kAmprPackChunkFlagsShift = 22u;
static constexpr uint32_t kAmprPackChunkFlagsMask = 0xffu;
static constexpr uint32_t kAmprPackChunkDescriptorKnownMask =
    kAmprPackChunkStoredMask |
    (kAmprPackChunkCodecMask << kAmprPackChunkCodecShift) |
    (kAmprPackChunkFlagsMask << kAmprPackChunkFlagsShift);

#pragma pack(push, 1)
struct AmprPackIndexHeader {
    char magic[8];
    uint32_t version;
    uint32_t headerSize;
    uint32_t flags;
    uint32_t endianMarker;
    uint8_t buildId[16];
    uint64_t fileCount;
    uint64_t chunkCount;
    uint32_t packCount;
    uint32_t fileRecordSize;
    uint32_t chunkRecordSize;
    uint32_t packRecordSize;
    uint64_t filesOffset;
    uint64_t chunksOffset;
    uint64_t packsOffset;
    uint64_t stringsOffset;
    uint64_t stringsSize;
    uint32_t payloadCrc32;
    uint32_t headerCrc32;
    uint64_t reserved;
};

// Optional <manifest>.runtime companion; little-endian, CRC over all 64 bytes
// with crc32 zeroed. Missing files select compiled defaults.
struct AmprPackRuntimeProfile {
    char magic[8]; // "AMPRCFG1"
    uint32_t version;
    uint32_t size;
    uint8_t buildId[16];
    uint64_t decodedCacheBytes;
    uint64_t physicalCacheBytes;
    uint32_t workers;
    uint32_t latencyReserveWorkers;
    uint32_t crc32;
    uint32_t reserved;
};
static_assert(sizeof(AmprPackRuntimeProfile) == 64, "runtime profile layout");

struct AmprPackFileRecord {
    uint64_t pathHash;
    uint64_t logicalSize;
    int64_t mtime;
    uint32_t firstChunk;
    uint32_t chunkCount;
    uint32_t pathOffset;
    uint32_t pathLength;
    uint32_t flags;
    uint8_t blockShift;
    uint8_t packingClass;
    uint16_t reserved;
};

// location: bits 0..47 = absolute byte offset in pack, bits 48..63 = pack id.
// descriptor: bits 0..19 = storedSize - 1, 20..21 = codec,
//             bits 22..29 = flags, bits 30..31 reserved and must be zero.
struct AmprPackChunkRecord {
    uint64_t location;
    uint32_t descriptor;
};

struct AmprPackDataRecord {
    uint64_t payloadBytes;
    uint64_t fileSize;
    uint32_t nameOffset;
    uint32_t nameLength;
    uint32_t flags;
    uint32_t ioPageSize;
};

struct AmprPackDataHeader {
    char magic[8];
    uint32_t version;
    uint32_t headerSize;
    uint32_t packId;
    uint32_t flags;
    uint8_t buildId[16];
    uint64_t payloadOffset;
    uint64_t payloadBytes;
    uint32_t headerCrc32;
    uint32_t reserved;
};
#pragma pack(pop)

static_assert(sizeof(AmprPackIndexHeader) == 128, "AMPR pack index header ABI drifted");
static_assert(sizeof(AmprPackFileRecord) == 48, "AMPR pack file record ABI drifted");
static_assert(sizeof(AmprPackChunkRecord) == 12, "AMPR pack chunk record ABI drifted");
static_assert(sizeof(AmprPackDataRecord) == 32, "AMPR pack data record ABI drifted");
static_assert(sizeof(AmprPackDataHeader) == 64, "AMPR pack data header ABI drifted");

inline constexpr uint64_t ampr_pack_chunk_offset(
    const AmprPackChunkRecord& record) {
    return record.location & kAmprPackChunkOffsetMask;
}

inline constexpr uint16_t ampr_pack_chunk_pack_id(
    const AmprPackChunkRecord& record) {
    return static_cast<uint16_t>(record.location >> 48u);
}

inline constexpr uint32_t ampr_pack_chunk_stored_size(
    const AmprPackChunkRecord& record) {
    return (record.descriptor & kAmprPackChunkStoredMask) + 1u;
}

inline constexpr uint8_t ampr_pack_chunk_codec(
    const AmprPackChunkRecord& record) {
    return static_cast<uint8_t>(
        (record.descriptor >> kAmprPackChunkCodecShift) &
        kAmprPackChunkCodecMask);
}

inline constexpr uint8_t ampr_pack_chunk_flags(
    const AmprPackChunkRecord& record) {
    return static_cast<uint8_t>(
        (record.descriptor >> kAmprPackChunkFlagsShift) &
        kAmprPackChunkFlagsMask);
}

inline constexpr bool ampr_pack_chunk_descriptor_valid(
    const AmprPackChunkRecord& record) {
    return (record.descriptor & ~kAmprPackChunkDescriptorKnownMask) == 0u;
}
