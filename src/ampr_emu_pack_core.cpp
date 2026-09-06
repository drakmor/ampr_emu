/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 */
#include "ampr_emu_pack_core.h"

#include <lz4.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <limits>

namespace {
static uint32_t g_crc_table[256]{};
static std::atomic<uint32_t> g_crc_state{0};

static void crc_table_ensure() {
    const uint32_t state = g_crc_state.load(std::memory_order_acquire);
    if (state == 2u) return;
    uint32_t expected = 0;
    if (g_crc_state.compare_exchange_strong(expected, 1u,
                                            std::memory_order_acq_rel,
                                            std::memory_order_acquire)) {
        for (uint32_t i = 0; i < 256u; ++i) {
            uint32_t value = i;
            for (unsigned bit = 0; bit < 8u; ++bit) {
                value = (value >> 1u) ^
                        (0xedb88320u & (0u - (value & 1u)));
            }
            g_crc_table[i] = value;
        }
        g_crc_state.store(2u, std::memory_order_release);
        return;
    }
    while (g_crc_state.load(std::memory_order_acquire) != 2u) {
#if defined(__x86_64__) || defined(_M_X64)
        __builtin_ia32_pause();
#endif
    }
}

static bool bytes_equal(const void* a, const void* b, size_t size) {
    return size == 0 || std::memcmp(a, b, size) == 0;
}

static bool add_u64(uint64_t a, uint64_t b, uint64_t* out) {
    if (!out || a > (std::numeric_limits<uint64_t>::max)() - b) return false;
    *out = a + b;
    return true;
}

static bool mul_u64(uint64_t a, uint64_t b, uint64_t* out) {
    if (!out || (a != 0 && b > (std::numeric_limits<uint64_t>::max)() / a)) {
        return false;
    }
    *out = a * b;
    return true;
}

static bool range_in_size(uint64_t offset, uint64_t length, size_t size) {
    uint64_t end = 0;
    return add_u64(offset, length, &end) && end <= static_cast<uint64_t>(size);
}

static bool string_valid(const AmprPackCoreView& view,
                         uint32_t offset,
                         uint32_t length) {
    const uint64_t end = static_cast<uint64_t>(offset) + length;
    return view.strings && end < view.stringsSize && view.strings[end] == '\0' &&
           std::memchr(view.strings + offset, '\0', length) == nullptr;
}

static bool power_of_two(uint32_t value) {
    return value != 0 && (value & (value - 1u)) == 0;
}

static uint64_t align_down_u64(uint64_t value, uint64_t alignment) {
    return value & ~(alignment - 1u);
}

static bool align_up_u64(uint64_t value,
                         uint64_t alignment,
                         uint64_t* out) {
    if (!out || alignment == 0 ||
        (alignment & (alignment - 1u)) != 0 ||
        value > (std::numeric_limits<uint64_t>::max)() -
                    (alignment - 1u)) {
        return false;
    }
    *out = (value + alignment - 1u) & ~(alignment - 1u);
    return true;
}

static bool chunk_page_flags_valid(const AmprPackDataRecord& pack,
                                   const AmprPackChunkView& chunk) {
    const uint64_t pageSize = pack.ioPageSize;
    if (pageSize == 0 || chunk.storedSize == 0) return false;
    const bool contained =
        (chunk.flags & kAmprPackChunkPageContained) != 0;
    const bool aligned =
        (chunk.flags & kAmprPackChunkPageAligned) != 0;
    uint64_t storedEnd = 0;
    if (!add_u64(chunk.offset, chunk.storedSize, &storedEnd)) return false;

    if (contained) {
        if (chunk.storedSize > pageSize ||
            align_down_u64(chunk.offset, pageSize) !=
                align_down_u64(storedEnd - 1u, pageSize)) {
            return false;
        }
    }
    if (aligned && (chunk.offset & (pageSize - 1u)) != 0) {
        return false;
    }
    if (chunk.storedSize <= pageSize && aligned && !contained) {
        return false;
    }
    return true;
}


// Private helper: the caller has checked the view, block shift and chunk range.
static int decode_chunk_record_in_range(const AmprPackCoreView& view,
                               const AmprPackFileRecord& file,
                               uint32_t localChunkIndex,
                               AmprPackChunkView* out) {
    const AmprPackChunkRecord& record =
        view.chunks[file.firstChunk + localChunkIndex];
    if (!ampr_pack_chunk_descriptor_valid(record)) {
        return kAmprPackCoreInvalidFormat;
    }
    const uint64_t blockSize = 1ull << file.blockShift;
    const uint64_t blockBegin =
        static_cast<uint64_t>(localChunkIndex) * blockSize;
    if (blockBegin >= file.logicalSize) {
        return kAmprPackCoreInvalidFormat;
    }
    const uint64_t remaining = file.logicalSize - blockBegin;
    const uint64_t rawSize64 = remaining < blockSize ? remaining : blockSize;
    if (rawSize64 == 0 || rawSize64 > UINT32_MAX) {
        return kAmprPackCoreInvalidFormat;
    }
    out->offset = ampr_pack_chunk_offset(record);
    out->storedSize = ampr_pack_chunk_stored_size(record);
    out->rawSize = static_cast<uint32_t>(rawSize64);
    out->packId = ampr_pack_chunk_pack_id(record);
    out->codec = ampr_pack_chunk_codec(record);
    out->flags = ampr_pack_chunk_flags(record);
    return kAmprPackCoreOk;
}

static int decode_chunk_record(const AmprPackCoreView& view,
                               const AmprPackFileRecord& file,
                               uint32_t localChunkIndex,
                               AmprPackChunkView* out) {
    if (out) *out = {};
    if (!out || !view.header || !view.chunks ||
        (file.flags & kAmprPackFilePacked) == 0 ||
        file.blockShift < kAmprPackBlockShiftMin ||
        file.blockShift > kAmprPackBlockShiftMax ||
        localChunkIndex >= file.chunkCount ||
        static_cast<uint64_t>(file.firstChunk) + localChunkIndex >=
            view.header->chunkCount) {
        return kAmprPackCoreInvalidArgument;
    }
    return decode_chunk_record_in_range(view, file, localChunkIndex, out);
}

static unsigned char ascii_lower(unsigned char ch) {
    return ch >= 'A' && ch <= 'Z' ? static_cast<unsigned char>(ch + 0x20u) : ch;
}

static bool safe_relative_pack_name(const char* value, uint32_t length) {
    if (!value || length == 0 || value[0] == '/' || value[0] == '\\') {
        return false;
    }
    uint32_t componentStart = 0;
    for (uint32_t i = 0; i <= length; ++i) {
        const bool atEnd = i == length;
        const char ch = atEnd ? '/' : value[i];
        if (!atEnd && (ch == '\0' || ch == '\\')) return false;
        if (ch != '/') continue;
        const uint32_t componentLength = i - componentStart;
        if (componentLength == 0 ||
            (componentLength == 1u && value[componentStart] == '.') ||
            (componentLength == 2u && value[componentStart] == '.' &&
             value[componentStart + 1u] == '.')) {
            return false;
        }
        componentStart = i + 1u;
    }
    return true;
}

static bool safe_logical_asset_path(const char* value, uint32_t length) {
    if (!value || length <= 6u || value[0] != '/' || value[5] != '/') {
        return false;
    }
    static constexpr char prefix[] = "app0";
    for (uint32_t i = 0; i < 4u; ++i) {
        if (ascii_lower(static_cast<unsigned char>(value[i + 1u])) !=
            static_cast<unsigned char>(prefix[i])) {
            return false;
        }
    }
    uint32_t componentStart = 1u;
    for (uint32_t i = 1u; i <= length; ++i) {
        const bool atEnd = i == length;
        const char ch = atEnd ? '/' : value[i];
        if (!atEnd && (ch == '\0' || ch == '\\')) return false;
        if (ch != '/') continue;
        const uint32_t componentLength = i - componentStart;
        if (componentLength == 0 ||
            (componentLength == 1u && value[componentStart] == '.') ||
            (componentLength == 2u && value[componentStart] == '.' &&
             value[componentStart + 1u] == '.')) {
            return false;
        }
        componentStart = i + 1u;
    }
    return true;
}

static bool folded_path_equal(const char* a, size_t aLength,
                              const char* b, size_t bLength) {
    if (!a || !b || aLength != bLength) return false;
    for (size_t i = 0; i < aLength; ++i) {
        unsigned char left = static_cast<unsigned char>(a[i]);
        unsigned char right = static_cast<unsigned char>(b[i]);
        if (left == '\\') left = '/';
        if (right == '\\') right = '/';
        if (ascii_lower(left) != ascii_lower(right)) return false;
    }
    return true;
}
} // namespace

uint32_t ampr_pack_crc32(const void* data, size_t size, uint32_t seed) {
    if (!data && size != 0) return 0;
    crc_table_ensure();
    uint32_t value = seed ^ 0xffffffffu;
    const auto* input = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < size; ++i) {
        value = g_crc_table[(value ^ input[i]) & 0xffu] ^ (value >> 8u);
    }
    return value ^ 0xffffffffu;
}

uint64_t ampr_pack_path_hash(const char* path, size_t length) {
    if (!path && length != 0) return 0;
    uint64_t hash = 14695981039346656037ull;
    for (size_t i = 0; i < length; ++i) {
        unsigned char ch = static_cast<unsigned char>(path[i]);
        if (ch == '\\') ch = '/';
        ch = ascii_lower(ch);
        hash ^= ch;
        hash *= 1099511628211ull;
    }
    return hash ? hash : 1ull;
}

int ampr_pack_core_mount(const void* data, size_t size, AmprPackCoreView* out) {
    if (out) *out = {};
    if (!data || !out || size < sizeof(AmprPackIndexHeader)) {
        return kAmprPackCoreInvalidArgument;
    }
    const auto* base = static_cast<const uint8_t*>(data);
    const auto* header = reinterpret_cast<const AmprPackIndexHeader*>(base);
    if (!bytes_equal(header->magic, kAmprPackIndexMagic, sizeof(header->magic)) ||
        header->version != kAmprPackIndexVersion ||
        header->headerSize != sizeof(AmprPackIndexHeader) ||
        header->endianMarker != kAmprPackEndianMarker ||
        header->fileRecordSize != sizeof(AmprPackFileRecord) ||
        header->chunkRecordSize != sizeof(AmprPackChunkRecord) ||
        header->packRecordSize != sizeof(AmprPackDataRecord) ||
        (header->flags & ~kAmprPackIndexKnownFlags) != 0 ||
        header->reserved != 0) {
        return kAmprPackCoreInvalidFormat;
    }

    AmprPackIndexHeader headerCopy = *header;
    headerCopy.headerCrc32 = 0;
    if (ampr_pack_crc32(&headerCopy, sizeof(headerCopy)) != header->headerCrc32 ||
        ampr_pack_crc32(base + sizeof(AmprPackIndexHeader),
                        size - sizeof(AmprPackIndexHeader)) !=
            header->payloadCrc32) {
        return kAmprPackCoreChecksumMismatch;
    }

    uint64_t filesBytes = 0;
    uint64_t chunksBytes = 0;
    uint64_t packsBytes = 0;
    if (!mul_u64(header->fileCount, sizeof(AmprPackFileRecord), &filesBytes) ||
        !mul_u64(header->chunkCount, sizeof(AmprPackChunkRecord), &chunksBytes) ||
        !mul_u64(header->packCount, sizeof(AmprPackDataRecord), &packsBytes)) {
        return kAmprPackCoreInvalidFormat;
    }
    uint64_t expectedChunks = 0;
    uint64_t expectedPacks = 0;
    uint64_t expectedStrings = 0;
    uint64_t expectedEnd = 0;
    if (header->filesOffset != sizeof(AmprPackIndexHeader) ||
        !add_u64(header->filesOffset, filesBytes, &expectedChunks) ||
        !add_u64(expectedChunks, chunksBytes, &expectedPacks) ||
        !add_u64(expectedPacks, packsBytes, &expectedStrings) ||
        !add_u64(expectedStrings, header->stringsSize, &expectedEnd) ||
        header->chunksOffset != expectedChunks ||
        header->packsOffset != expectedPacks ||
        header->stringsOffset != expectedStrings ||
        expectedEnd != static_cast<uint64_t>(size) ||
        !range_in_size(header->filesOffset, filesBytes, size) ||
        !range_in_size(header->chunksOffset, chunksBytes, size) ||
        !range_in_size(header->packsOffset, packsBytes, size) ||
        !range_in_size(header->stringsOffset, header->stringsSize, size)) {
        return kAmprPackCoreInvalidFormat;
    }
    if (header->fileCount > 0xffffffffull ||
        header->chunkCount > 0xffffffffull ||
        header->packCount > 0xffffu ||
        header->stringsSize > static_cast<uint64_t>((std::numeric_limits<size_t>::max)())) {
        return kAmprPackCoreUnsupported;
    }

    AmprPackCoreView view{};
    view.base = base;
    view.size = size;
    view.header = header;
    view.files = reinterpret_cast<const AmprPackFileRecord*>(
        base + header->filesOffset);
    view.chunks = reinterpret_cast<const AmprPackChunkRecord*>(
        base + header->chunksOffset);
    view.packs = reinterpret_cast<const AmprPackDataRecord*>(
        base + header->packsOffset);
    view.strings = reinterpret_cast<const char*>(base + header->stringsOffset);
    view.stringsSize = static_cast<size_t>(header->stringsSize);

    for (uint32_t packId = 0; packId < header->packCount; ++packId) {
        const AmprPackDataRecord& pack = view.packs[packId];
        if (!string_valid(view, pack.nameOffset, pack.nameLength) ||
            !power_of_two(pack.ioPageSize) ||
            pack.ioPageSize < (1u << kAmprPackIoPageShiftMin) ||
            pack.ioPageSize > (1u << kAmprPackIoPageShiftMax) ||
            (pack.ioPageSize % kAmprPackPhysicalChunkAlignment) != 0 ||
            pack.fileSize < sizeof(AmprPackDataHeader) ||
            pack.payloadBytes > pack.fileSize ||
            (pack.flags & ~kAmprPackDataKnownFlags) != 0 ||
            (pack.flags & kAmprPackDataIoPageLayout) == 0) {
            return kAmprPackCoreInvalidFormat;
        }
        const uint64_t payloadOffset = pack.fileSize - pack.payloadBytes;
        if (payloadOffset < sizeof(AmprPackDataHeader) ||
            (payloadOffset & (pack.ioPageSize - 1u)) != 0 ||
            (pack.fileSize & (pack.ioPageSize - 1u)) != 0 ||
            !safe_relative_pack_name(view.strings + pack.nameOffset,
                                     pack.nameLength)) {
            return kAmprPackCoreInvalidFormat;
        }
    }

    for (uint32_t fileIndex = 0; fileIndex < header->fileCount; ++fileIndex) {
        const AmprPackFileRecord& file = view.files[fileIndex];
        if (file.reserved != 0 ||
            !string_valid(view, file.pathOffset, file.pathLength) ||
            (file.flags & ~kAmprPackFileKnownFlags) != 0 ||
            !safe_logical_asset_path(view.strings + file.pathOffset,
                                     file.pathLength)) {
            return kAmprPackCoreInvalidFormat;
        }
        const char* path = view.strings + file.pathOffset;
        if (ampr_pack_path_hash(path, file.pathLength) != file.pathHash) {
            return kAmprPackCoreChecksumMismatch;
        }
        if ((file.flags & kAmprPackFilePacked) == 0) {
            if (file.firstChunk != 0 || file.chunkCount != 0 ||
                file.blockShift != 0 || file.packingClass != 0 ||
                file.flags != 0) {
                return kAmprPackCoreInvalidFormat;
            }
            continue;
        }
        if (file.blockShift < kAmprPackBlockShiftMin ||
            file.blockShift > kAmprPackBlockShiftMax ||
            ((file.flags & kAmprPackFileStreaming) != 0 &&
             (file.flags & kAmprPackFileRandomAccess) != 0) ||
            static_cast<uint64_t>(file.firstChunk) + file.chunkCount >
                header->chunkCount) {
            return kAmprPackCoreInvalidFormat;
        }
        const uint32_t blockSize = 1u << file.blockShift;
        const uint64_t expectedChunkCount = file.logicalSize == 0
            ? 0
            : (file.logicalSize + blockSize - 1u) / blockSize;
        if (file.chunkCount != expectedChunkCount) {
            return kAmprPackCoreInvalidFormat;
        }
        uint64_t logicalSize = 0;
        for (uint32_t local = 0; local < file.chunkCount; ++local) {
            AmprPackChunkView chunk{};
            if (decode_chunk_record(view, file, local, &chunk) !=
                    kAmprPackCoreOk ||
                chunk.packId >= header->packCount ||
                chunk.rawSize == 0 || chunk.rawSize > blockSize ||
                chunk.storedSize == 0 || chunk.storedSize > blockSize ||
                (local + 1u != file.chunkCount &&
                 chunk.rawSize != blockSize) ||
                (chunk.codec != kAmprPackChunkRaw &&
                 chunk.codec != kAmprPackChunkLz4) ||
                (chunk.flags & ~kAmprPackChunkKnownFlags) != 0 ||
                (chunk.codec == kAmprPackChunkRaw &&
                 chunk.storedSize != chunk.rawSize) ||
                ((file.flags & kAmprPackFileStoreOnly) != 0 &&
                 chunk.codec != kAmprPackChunkRaw)) {
                return kAmprPackCoreInvalidFormat;
            }
            const AmprPackDataRecord& pack = view.packs[chunk.packId];
            const uint64_t payloadOffset = pack.fileSize - pack.payloadBytes;
            uint64_t storedEnd = 0;
            if (!add_u64(chunk.offset, chunk.storedSize, &storedEnd) ||
                chunk.offset < payloadOffset || storedEnd > pack.fileSize ||
                (chunk.offset &
                 (kAmprPackPhysicalChunkAlignment - 1u)) != 0 ||
                !chunk_page_flags_valid(pack, chunk)) {
                return kAmprPackCoreInvalidFormat;
            }
            const bool pageContained =
                (chunk.flags & kAmprPackChunkPageContained) != 0;
            const bool pageAligned =
                (chunk.flags & kAmprPackChunkPageAligned) != 0;
            const bool streaming =
                (file.flags & kAmprPackFileStreaming) != 0;
            if (streaming !=
                ((chunk.flags & kAmprPackChunkStreaming) != 0)) {
                return kAmprPackCoreInvalidFormat;
            }
            if (!streaming &&
                ((chunk.storedSize <= pack.ioPageSize && !pageContained) ||
                 (chunk.storedSize > pack.ioPageSize && !pageAligned))) {
                return kAmprPackCoreInvalidFormat;
            }
            if (!streaming && chunk.codec == kAmprPackChunkRaw &&
                chunk.storedSize >= pack.ioPageSize && !pageAligned) {
                return kAmprPackCoreInvalidFormat;
            }
            const uint64_t ioBegin =
                align_down_u64(chunk.offset, pack.ioPageSize);
            uint64_t ioEnd = 0;
            if (!align_up_u64(storedEnd, pack.ioPageSize, &ioEnd) ||
                ioBegin < payloadOffset || ioEnd > pack.fileSize) {
                return kAmprPackCoreInvalidFormat;
            }
            if (!add_u64(logicalSize, chunk.rawSize, &logicalSize)) {
                return kAmprPackCoreInvalidFormat;
            }
        }
        if (logicalSize != file.logicalSize) {
            return kAmprPackCoreInvalidFormat;
        }
    }

    *out = view;
    return kAmprPackCoreOk;
}

const char* ampr_pack_core_string(const AmprPackCoreView& view,
                                  uint32_t offset,
                                  uint32_t length) {
    return string_valid(view, offset, length) ? view.strings + offset : nullptr;
}

const AmprPackFileRecord* ampr_pack_core_file(const AmprPackCoreView& view,
                                              uint32_t fileId) {
    if (!view.header || fileId == 0 || fileId > view.header->fileCount) {
        return nullptr;
    }
    return &view.files[fileId - 1u];
}

bool ampr_pack_core_file_is_packed(const AmprPackCoreView& view,
                                   uint32_t fileId) {
    const AmprPackFileRecord* file = ampr_pack_core_file(view, fileId);
    return file && (file->flags & kAmprPackFilePacked) != 0;
}

int ampr_pack_core_validate_logical_file(const AmprPackCoreView& view,
                                         uint32_t fileId,
                                         const char* path,
                                         size_t pathLength,
                                         uint64_t logicalSize) {
    const AmprPackFileRecord* file = ampr_pack_core_file(view, fileId);
    if (!file || !path) return kAmprPackCoreInvalidArgument;
    const char* storedPath = ampr_pack_core_string(
        view, file->pathOffset, file->pathLength);
    if (!storedPath || file->logicalSize != logicalSize ||
        file->pathHash != ampr_pack_path_hash(path, pathLength) ||
        !folded_path_equal(storedPath, file->pathLength, path, pathLength)) {
        return kAmprPackCoreChecksumMismatch;
    }
    return kAmprPackCoreOk;
}

int ampr_pack_core_chunk(const AmprPackCoreView& view,
                         const AmprPackFileRecord& file,
                         uint32_t localChunkIndex,
                         AmprPackChunkView* out) {
    return decode_chunk_record(view, file, localChunkIndex, out);
}

size_t ampr_pack_core_task_count(const AmprPackFileRecord& file,
                                 uint64_t offset,
                                 uint64_t length) {
    if ((file.flags & kAmprPackFilePacked) == 0 || length == 0 ||
        file.blockShift < kAmprPackBlockShiftMin ||
        file.blockShift > kAmprPackBlockShiftMax ||
        offset > file.logicalSize || length > file.logicalSize - offset) {
        return 0;
    }
    const uint64_t blockSize = 1ull << file.blockShift;
    const uint64_t first = offset / blockSize;
    const uint64_t last = (offset + length - 1u) / blockSize;
    const uint64_t count = last - first + 1u;
    return count <= static_cast<uint64_t>((std::numeric_limits<size_t>::max)())
        ? static_cast<size_t>(count)
        : 0;
}

int ampr_pack_core_make_task(const AmprPackCoreView& view,
                             const AmprPackFileRecord& file,
                             uint64_t offset,
                             uint64_t length,
                             size_t taskIndex,
                             AmprPackBlockReadTask* out) {
    if (out) *out = {};
    if (!out || !view.header || !view.chunks ||
        (file.flags & kAmprPackFilePacked) == 0 ||
        file.blockShift < kAmprPackBlockShiftMin ||
        file.blockShift > kAmprPackBlockShiftMax || length == 0 ||
        offset > file.logicalSize || length > file.logicalSize - offset ||
        static_cast<uint64_t>(file.firstChunk) + file.chunkCount >
            view.header->chunkCount) {
        return kAmprPackCoreInvalidArgument;
    }
    const uint64_t blockSize = 1ull << file.blockShift;
    const uint64_t firstBlock = offset / blockSize;
    // The public request validation above already proved this sum and shift.
    const uint64_t requestEnd = offset + length;
    const uint64_t taskCount = ((requestEnd - 1u) >> file.blockShift) - firstBlock + 1u;
    if (taskIndex >= taskCount || firstBlock + taskIndex >= file.chunkCount) {
        return kAmprPackCoreOutOfRange;
    }
    const uint64_t blockIndex = firstBlock + taskIndex;
    const uint64_t blockBegin = blockIndex * blockSize;
    AmprPackChunkView chunk{};
    const int chunkRc = decode_chunk_record_in_range(
        view, file, static_cast<uint32_t>(blockIndex), &chunk);
    if (chunkRc != kAmprPackCoreOk) return chunkRc;
    const uint64_t blockEnd = blockBegin + chunk.rawSize;
    const uint64_t copyBegin = offset > blockBegin ? offset : blockBegin;
    const uint64_t copyEnd = requestEnd < blockEnd ? requestEnd : blockEnd;
    if (copyEnd <= copyBegin || copyEnd - copyBegin > 0xffffffffull ||
        copyBegin - blockBegin > 0xffffffffull ||
        copyBegin - offset > 0xffffffffull) {
        return kAmprPackCoreInvalidFormat;
    }
    out->chunkIndex = file.firstChunk + static_cast<uint32_t>(blockIndex);
    out->sourceOffset = static_cast<uint32_t>(copyBegin - blockBegin);
    out->copyLength = static_cast<uint32_t>(copyEnd - copyBegin);
    out->destinationOffset = static_cast<uint32_t>(copyBegin - offset);
    out->chunk = chunk;
    return kAmprPackCoreOk;
}

bool ampr_pack_core_chunk_page_safe(const AmprPackDataRecord& pack,
                                    const AmprPackChunkView& chunk) {
    if (!chunk_page_flags_valid(pack, chunk)) return false;
    if (chunk.storedSize <= pack.ioPageSize) {
        return (chunk.flags & kAmprPackChunkPageContained) != 0;
    }
    return (chunk.flags & kAmprPackChunkPageAligned) != 0;
}

int ampr_pack_core_validate_data_header(const void* data,
                                        size_t size,
                                        uint32_t expectedPackId,
                                        const uint8_t expectedBuildId[16],
                                        uint32_t expectedFlags,
                                        uint64_t expectedFileSize,
                                        uint64_t expectedPayloadBytes,
                                        uint64_t* outPayloadOffset,
                                        uint64_t* outPayloadEnd) {
    if (outPayloadOffset) *outPayloadOffset = 0;
    if (outPayloadEnd) *outPayloadEnd = 0;
    if (!data || size < sizeof(AmprPackDataHeader) || !expectedBuildId ||
        !outPayloadOffset || !outPayloadEnd) {
        return kAmprPackCoreInvalidArgument;
    }
    const auto* header = static_cast<const AmprPackDataHeader*>(data);
    if (!bytes_equal(header->magic, kAmprPackDataMagic,
                     sizeof(header->magic)) ||
        header->version != kAmprPackDataVersion ||
        header->headerSize != sizeof(AmprPackDataHeader) ||
        header->packId != expectedPackId ||
        header->flags != expectedFlags ||
        (header->flags & ~kAmprPackDataKnownFlags) != 0 ||
        header->reserved != 0 ||
        !bytes_equal(header->buildId, expectedBuildId, 16u)) {
        return kAmprPackCoreInvalidFormat;
    }
    AmprPackDataHeader copy = *header;
    copy.headerCrc32 = 0;
    if (ampr_pack_crc32(&copy, sizeof(copy)) != header->headerCrc32) {
        return kAmprPackCoreChecksumMismatch;
    }
    uint64_t payloadEnd = 0;
    if (!add_u64(header->payloadOffset, header->payloadBytes, &payloadEnd) ||
        header->payloadOffset < sizeof(AmprPackDataHeader) ||
        header->payloadBytes != expectedPayloadBytes ||
        payloadEnd != expectedFileSize ||
        expectedFileSize != static_cast<uint64_t>(size)) {
        return kAmprPackCoreInvalidFormat;
    }
    *outPayloadOffset = header->payloadOffset;
    *outPayloadEnd = payloadEnd;
    return kAmprPackCoreOk;
}

int ampr_pack_core_decode_chunk(const AmprPackChunkView& chunk,
                                const void* stored,
                                size_t storedSize,
                                void* raw,
                                size_t rawCapacity) {
    if ((!stored && storedSize != 0) || !raw ||
        storedSize != chunk.storedSize || rawCapacity < chunk.rawSize ||
        chunk.storedSize == 0 || chunk.rawSize == 0 ||
        chunk.rawSize > (1u << kAmprPackBlockShiftMax) ||
        chunk.storedSize > (1u << kAmprPackBlockShiftMax) ||
        (chunk.flags & ~kAmprPackChunkKnownFlags) != 0) {
        return kAmprPackCoreInvalidArgument;
    }
    if (chunk.codec == kAmprPackChunkRaw) {
        if (storedSize != chunk.rawSize) return kAmprPackCoreInvalidFormat;
        if (raw == stored) return kAmprPackCoreOk;
        std::memcpy(raw, stored, storedSize);
        return kAmprPackCoreOk;
    } else if (chunk.codec == kAmprPackChunkLz4) {
        // Validation above bounds both sizes to 1 MiB, so liblz4's int API is
        // safe here. Limit output to the declared raw size and require an exact
        // result. Payload-integrity verification belongs to the offline CRC
        // sidecar and is intentionally absent from runtime decode.
        const int decodedSize = LZ4_decompress_safe(
            static_cast<const char*>(stored),
            static_cast<char*>(raw),
            static_cast<int>(storedSize),
            static_cast<int>(chunk.rawSize));
        if (decodedSize != static_cast<int>(chunk.rawSize)) {
            return kAmprPackCoreInvalidFormat;
        }
    } else {
        return kAmprPackCoreUnsupported;
    }
    return kAmprPackCoreOk;
}
