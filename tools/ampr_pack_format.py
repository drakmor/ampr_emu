#!/usr/bin/env python3
"""Binary format and shared helpers for AMPR seekable asset packs.

The runtime format intentionally stores independent raw-LZ4 blocks.  It is not
an LZ4 frame: random access, block placement and sharding are owned by
AMPRPAK4. Decoded-block CRCs live in a separate offline-only sidecar.
"""
from __future__ import annotations

from array import array
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import binascii
import ctypes
import ctypes.util
import fnmatch
import hashlib
import math
import os
import struct
import sys
from typing import BinaryIO, Iterable, Iterator, Sequence

INDEX_MAGIC = b"AMPRPAK4"
DATA_MAGIC = b"AMPRDAT3"
CRC_MAGIC = b"AMPRCRC1"
INDEX_VERSION = 4
DATA_VERSION = 3
CRC_VERSION = 1
ENDIAN_MARKER = 0x01020304
INDEX_HEADER_SIZE = 128
DATA_HEADER_SIZE = 64
CRC_HEADER_SIZE = 48

INDEX_HEADER = struct.Struct("<8sIIII16sQQIIIIQQQQQIIQ")
FILE_RECORD = struct.Struct("<QQqIIIIIBBH")
CHUNK_RECORD = struct.Struct("<QI")
PACK_RECORD = struct.Struct("<QQIIII")
DATA_HEADER = struct.Struct("<8sIIII16sQQII")
CRC_HEADER = struct.Struct("<8sII16sQII")

assert INDEX_HEADER.size == INDEX_HEADER_SIZE
assert FILE_RECORD.size == 48
assert CHUNK_RECORD.size == 12
assert PACK_RECORD.size == 32
assert DATA_HEADER.size == DATA_HEADER_SIZE
assert CRC_HEADER.size == CRC_HEADER_SIZE

FILE_FLAG_PACKED = 1 << 0
FILE_FLAG_STORE_ONLY = 1 << 1
FILE_FLAG_STREAMING = 1 << 2
FILE_FLAG_HOT = 1 << 3
FILE_FLAG_RANDOM_ACCESS = 1 << 4
FILE_KNOWN_FLAGS = (
    FILE_FLAG_PACKED
    | FILE_FLAG_STORE_ONLY
    | FILE_FLAG_STREAMING
    | FILE_FLAG_HOT
    | FILE_FLAG_RANDOM_ACCESS
)

CHUNK_CODEC_RAW = 0
CHUNK_CODEC_LZ4 = 1
CHUNK_FLAG_SHARED = 1 << 0
CHUNK_FLAG_STREAMING = 1 << 1
CHUNK_FLAG_PAGE_CONTAINED = 1 << 2
CHUNK_FLAG_PAGE_ALIGNED = 1 << 3
CHUNK_KNOWN_FLAGS = (
    CHUNK_FLAG_SHARED
    | CHUNK_FLAG_STREAMING
    | CHUNK_FLAG_PAGE_CONTAINED
    | CHUNK_FLAG_PAGE_ALIGNED
)

PACK_FLAG_STRIPED = 1 << 0
PACK_FLAG_IO_PAGE_LAYOUT = 1 << 1
PACK_KNOWN_FLAGS = PACK_FLAG_STRIPED | PACK_FLAG_IO_PAGE_LAYOUT
INDEX_KNOWN_FLAGS = 0

MIN_BLOCK_SHIFT = 14  # 16 KiB
MAX_BLOCK_SHIFT = 20  # 1 MiB
MIN_IO_PAGE_SHIFT = 12  # 4 KiB
MAX_IO_PAGE_SHIFT = 20  # 1 MiB
PHYSICAL_CHUNK_ALIGNMENT = 64
CHUNK_OFFSET_MASK = (1 << 48) - 1
CHUNK_STORED_BITS = 20
CHUNK_STORED_MASK = (1 << CHUNK_STORED_BITS) - 1
CHUNK_CODEC_SHIFT = 20
CHUNK_CODEC_MASK = 0x3
CHUNK_FLAGS_SHIFT = 22
CHUNK_FLAGS_MASK = 0xFF
CHUNK_DESCRIPTOR_KNOWN_MASK = (
    CHUNK_STORED_MASK
    | (CHUNK_CODEC_MASK << CHUNK_CODEC_SHIFT)
    | (CHUNK_FLAGS_MASK << CHUNK_FLAGS_SHIFT)
)


def crc32(data: bytes | bytearray | memoryview, seed: int = 0) -> int:
    return binascii.crc32(data, seed) & 0xFFFFFFFF


def align_up(value: int, alignment: int) -> int:
    if alignment <= 0 or alignment & (alignment - 1):
        raise ValueError(f"alignment must be a power of two, got {alignment}")
    return (value + alignment - 1) & ~(alignment - 1)


def align_down(value: int, alignment: int) -> int:
    if alignment <= 0 or alignment & (alignment - 1):
        raise ValueError(f"alignment must be a power of two, got {alignment}")
    return value & ~(alignment - 1)


def parse_size(value: str | int) -> int:
    if isinstance(value, int):
        if value < 0:
            raise ValueError("size must be non-negative")
        return value
    text = value.strip().replace("_", "")
    if not text:
        raise ValueError("empty size")
    units = {
        "b": 1,
        "k": 1000,
        "kb": 1000,
        "kib": 1024,
        "m": 1000**2,
        "mb": 1000**2,
        "mib": 1024**2,
        "g": 1000**3,
        "gb": 1000**3,
        "gib": 1024**3,
        "t": 1000**4,
        "tb": 1000**4,
        "tib": 1024**4,
    }
    split = len(text)
    while split and (text[split - 1].isalpha()):
        split -= 1
    number = text[:split]
    suffix = text[split:].lower() or "b"
    if suffix not in units:
        raise ValueError(f"unknown size suffix: {suffix}")
    try:
        numeric = float(number)
    except ValueError as exc:
        raise ValueError(f"invalid size: {value}") from exc
    if not math.isfinite(numeric):
        raise ValueError(f"invalid size: {value}")
    result = int(numeric * units[suffix])
    if result < 0:
        raise ValueError("size must be non-negative")
    return result


def block_shift(block_size: str | int) -> int:
    size = parse_size(block_size)
    if size == 0 or size & (size - 1):
        raise ValueError(f"block size must be a power of two, got {size}")
    shift = size.bit_length() - 1
    if shift < MIN_BLOCK_SHIFT or shift > MAX_BLOCK_SHIFT:
        raise ValueError(
            f"block size must be between {1 << MIN_BLOCK_SHIFT} and "
            f"{1 << MAX_BLOCK_SHIFT} bytes"
        )
    return shift


def fnv1a64(data: bytes) -> int:
    value = 0xCBF29CE484222325
    for byte in data:
        value ^= byte
        value = (value * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return value or 1


def ascii_fold_path_bytes(path: str) -> bytes:
    """Match AMPRIDX3: normalize separators and fold ASCII A..Z only."""
    raw = path.replace("\\", "/").encode("utf-8")
    return bytes((byte + 0x20) if 0x41 <= byte <= 0x5A else byte for byte in raw)


def asset_path_hash(path: str) -> int:
    return fnv1a64(ascii_fold_path_bytes(canonical_asset_path(path)))


def canonical_asset_path(path: str) -> str:
    """Return a canonical, absolute /app0 path suitable for hashing."""
    path = path.replace("\\", "/")
    if not path.startswith("/"):
        path = "/" + path
    parts: list[str] = []
    for component in path.split("/"):
        if not component or component == ".":
            continue
        if component == "..":
            if not parts:
                raise ValueError(f"path escapes root: {path}")
            parts.pop()
            continue
        if "\x00" in component:
            raise ValueError("NUL in path")
        parts.append(component)
    normalized = "/" + "/".join(parts)
    if normalized.lower() == "/app0":
        return "/app0"
    if not normalized.lower().startswith("/app0/"):
        raise ValueError(f"asset is outside /app0: {path}")
    # The existing AMPRIDX3 lookup is case-insensitive.  Preserve the deployed
    # spelling for extraction, but use a lower-case hash for validation.
    return normalized


def asset_relative_path(path: str) -> str:
    canonical = canonical_asset_path(path)
    if canonical.lower() == "/app0":
        return ""
    return canonical[6:]


def safe_output_path(root: Path, relative: str) -> Path:
    if (
        not relative
        or "\\" in relative
        or relative.startswith("/")
        or relative.endswith("/")
        or any(component in ("", ".", "..") for component in relative.split("/"))
    ):
        raise ValueError(f"unsafe output path: {relative!r}")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or any(part in ("", ".", "..") for part in pure.parts):
        raise ValueError(f"unsafe output path: {relative!r}")
    candidate = root.joinpath(*pure.parts)
    root_resolved = root.resolve()
    parent_resolved = candidate.parent.resolve()
    if os.path.commonpath((str(root_resolved), str(parent_resolved))) != str(root_resolved):
        raise ValueError(f"output path escapes root: {relative!r}")
    return candidate


@dataclass(frozen=True)
class AmprIndexEntry:
    path: str
    size: int
    mtime: int


AMPRIDX3_HEADER = struct.Struct("<8sIIQQQII")
AMPRIDX3_ENTRY = struct.Struct("<IIQq")


def read_ampridx3(path: Path) -> list[AmprIndexEntry]:
    data = path.read_bytes()
    if len(data) < AMPRIDX3_HEADER.size:
        raise ValueError("AMPRIDX3 is truncated")
    (
        magic,
        version,
        entry_size,
        entry_count,
        path_bytes,
        hash_offset,
        hash_slot_size,
        hash_slot_count,
    ) = AMPRIDX3_HEADER.unpack_from(data)
    if magic != b"AMPRIDX3" or version != 3:
        raise ValueError("unsupported AMPR index")
    if entry_size != AMPRIDX3_ENTRY.size:
        raise ValueError("unexpected AMPRIDX3 entry size")
    records_offset = AMPRIDX3_HEADER.size
    records_size = entry_count * entry_size
    path_offset = records_offset + records_size
    if path_offset + path_bytes > len(data):
        raise ValueError("AMPRIDX3 records/path blob are truncated")
    if hash_offset < path_offset + path_bytes or hash_offset > len(data):
        raise ValueError("invalid AMPRIDX3 hash offset")
    if hash_slot_count and hash_slot_size == 0:
        raise ValueError("invalid AMPRIDX3 hash table")

    result: list[AmprIndexEntry] = []
    for index in range(entry_count):
        record_at = records_offset + index * entry_size
        path_at, path_len, size, mtime = AMPRIDX3_ENTRY.unpack_from(data, record_at)
        if path_at + path_len >= path_bytes:
            raise ValueError(f"AMPRIDX3 path {index} is out of range")
        start = path_offset + path_at
        end = start + path_len
        if data[end] != 0:
            raise ValueError(f"AMPRIDX3 path {index} is not NUL terminated")
        try:
            decoded = data[start:end].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"AMPRIDX3 path {index} is not UTF-8") from exc
        result.append(AmprIndexEntry(canonical_asset_path(decoded), size, mtime))
    return result


@dataclass
class FileRecord:
    path_hash: int
    logical_size: int
    mtime: int
    first_chunk: int
    chunk_count: int
    path_offset: int
    path_length: int
    flags: int
    block_shift: int
    packing_class: int = 0
    reserved: int = 0

    def pack(self) -> bytes:
        return FILE_RECORD.pack(
            self.path_hash,
            self.logical_size,
            self.mtime,
            self.first_chunk,
            self.chunk_count,
            self.path_offset,
            self.path_length,
            self.flags,
            self.block_shift,
            self.packing_class,
            self.reserved,
        )

    @classmethod
    def unpack_from(cls, data: bytes, offset: int) -> "FileRecord":
        return cls(*FILE_RECORD.unpack_from(data, offset))


@dataclass
class ChunkRecord:
    offset: int
    stored_size: int
    raw_size: int
    pack_id: int
    codec: int
    flags: int = 0

    def pack(self) -> bytes:
        if not 0 <= self.offset <= CHUNK_OFFSET_MASK:
            raise ValueError("chunk offset exceeds the 48-bit AMPRPAK4 domain")
        if not 0 <= self.pack_id <= 0xFFFF:
            raise ValueError("chunk pack id exceeds uint16")
        if not 1 <= self.stored_size <= 1 << MAX_BLOCK_SHIFT:
            raise ValueError("chunk stored size is outside the AMPRPAK4 domain")
        if not 0 <= self.codec <= CHUNK_CODEC_MASK:
            raise ValueError("chunk codec is outside the compact descriptor domain")
        if self.flags & ~CHUNK_KNOWN_FLAGS:
            raise ValueError("chunk contains unknown flags")
        location = self.offset | (self.pack_id << 48)
        descriptor = (
            (self.stored_size - 1)
            | (self.codec << CHUNK_CODEC_SHIFT)
            | (self.flags << CHUNK_FLAGS_SHIFT)
        )
        return CHUNK_RECORD.pack(location, descriptor)

    @classmethod
    def unpack_from(cls, data: bytes, offset: int) -> "ChunkRecord":
        location, descriptor = CHUNK_RECORD.unpack_from(data, offset)
        if descriptor & ~CHUNK_DESCRIPTOR_KNOWN_MASK:
            raise ValueError("chunk descriptor contains reserved bits")
        return cls(
            offset=location & CHUNK_OFFSET_MASK,
            stored_size=(descriptor & CHUNK_STORED_MASK) + 1,
            raw_size=0,
            pack_id=(location >> 48) & 0xFFFF,
            codec=(descriptor >> CHUNK_CODEC_SHIFT) & CHUNK_CODEC_MASK,
            flags=(descriptor >> CHUNK_FLAGS_SHIFT) & CHUNK_FLAGS_MASK,
        )


def chunk_crc_path(index_path: Path) -> Path:
    return Path(str(index_path) + ".crc")


def _crc_header(
    build_id: bytes,
    chunk_count: int,
    payload_crc: int,
    header_crc: int,
) -> bytes:
    if len(build_id) != 16:
        raise ValueError("CRC sidecar build ID must contain 16 bytes")
    return CRC_HEADER.pack(
        CRC_MAGIC,
        CRC_VERSION,
        CRC_HEADER_SIZE,
        build_id,
        chunk_count,
        payload_crc,
        header_crc,
    )


def build_chunk_crc_header(
    build_id: bytes,
    chunk_count: int,
    payload_crc: int,
) -> bytes:
    header_zero = _crc_header(build_id, chunk_count, payload_crc, 0)
    return _crc_header(
        build_id,
        chunk_count,
        payload_crc,
        crc32(header_zero),
    )


def encode_chunk_crcs(checksums: Sequence[int]) -> bytes:
    values = array("I")
    values.extend(checksums)
    if values.itemsize != 4:
        raise RuntimeError("uint32 array does not use four-byte items")
    if any(value < 0 or value > 0xFFFFFFFF for value in values):
        raise ValueError("chunk CRC is outside uint32")
    if sys.byteorder != "little":
        values.byteswap()
    return values.tobytes()


def build_chunk_crc_bytes(build_id: bytes, checksums: Sequence[int]) -> bytes:
    payload = encode_chunk_crcs(checksums)
    payload_crc = crc32(payload)
    return build_chunk_crc_header(build_id, len(checksums), payload_crc) + payload


def load_chunk_crcs(
    path: Path,
    expected_build_id: bytes,
    expected_chunk_count: int,
) -> array[int]:
    data = path.read_bytes()
    if len(data) < CRC_HEADER_SIZE:
        raise ValueError("chunk CRC sidecar is truncated")
    magic, version, header_size, build_id, chunk_count, payload_crc, header_crc = (
        CRC_HEADER.unpack_from(data)
    )
    if magic != CRC_MAGIC or version != CRC_VERSION or header_size != CRC_HEADER_SIZE:
        raise ValueError("unsupported chunk CRC sidecar")
    if build_id != expected_build_id or chunk_count != expected_chunk_count:
        raise ValueError("chunk CRC sidecar build ID or chunk count mismatch")
    header_copy = bytearray(data[:CRC_HEADER_SIZE])
    struct.pack_into("<I", header_copy, 44, 0)
    if crc32(header_copy) != header_crc:
        raise ValueError("chunk CRC sidecar header CRC mismatch")
    payload = data[CRC_HEADER_SIZE:]
    if len(payload) != chunk_count * 4 or crc32(payload) != payload_crc:
        raise ValueError("chunk CRC sidecar payload CRC mismatch")
    values = array("I")
    values.frombytes(payload)
    if sys.byteorder != "little":
        values.byteswap()
    return values


@dataclass
class PackRecord:
    payload_bytes: int
    file_size: int
    name_offset: int
    name_length: int
    flags: int
    io_page_size: int

    def pack(self) -> bytes:
        return PACK_RECORD.pack(
            self.payload_bytes,
            self.file_size,
            self.name_offset,
            self.name_length,
            self.flags,
            self.io_page_size,
        )

    @classmethod
    def unpack_from(cls, data: bytes, offset: int) -> "PackRecord":
        return cls(*PACK_RECORD.unpack_from(data, offset))


@dataclass
class PackManifest:
    path: Path
    build_id: bytes
    flags: int
    files: list[FileRecord]
    chunks: list[ChunkRecord]
    packs: list[PackRecord]
    strings: bytes

    def string_at(self, offset: int, length: int) -> str:
        if offset < 0 or length < 0 or offset + length >= len(self.strings):
            raise ValueError("string is out of bounds")
        if self.strings[offset + length] != 0:
            raise ValueError("string is not NUL terminated")
        return self.strings[offset : offset + length].decode("utf-8")

    def file_path(self, file_id: int) -> str:
        if file_id <= 0 or file_id > len(self.files):
            raise IndexError("invalid file id")
        record = self.files[file_id - 1]
        return self.string_at(record.path_offset, record.path_length)

    def pack_name(self, pack_id: int) -> str:
        if pack_id < 0 or pack_id >= len(self.packs):
            raise IndexError("invalid pack id")
        record = self.packs[pack_id]
        return self.string_at(record.name_offset, record.name_length)


def _header_with_crc(
    *,
    flags: int,
    build_id: bytes,
    file_count: int,
    chunk_count: int,
    pack_count: int,
    files_offset: int,
    chunks_offset: int,
    packs_offset: int,
    strings_offset: int,
    strings_size: int,
    payload_crc: int,
    header_crc: int,
) -> bytes:
    if len(build_id) != 16:
        raise ValueError("build id must contain 16 bytes")
    return INDEX_HEADER.pack(
        INDEX_MAGIC,
        INDEX_VERSION,
        INDEX_HEADER_SIZE,
        flags,
        ENDIAN_MARKER,
        build_id,
        file_count,
        chunk_count,
        pack_count,
        FILE_RECORD.size,
        CHUNK_RECORD.size,
        PACK_RECORD.size,
        files_offset,
        chunks_offset,
        packs_offset,
        strings_offset,
        strings_size,
        payload_crc,
        header_crc,
        0,
    )


def build_manifest_header(
    *,
    flags: int,
    build_id: bytes,
    file_count: int,
    chunk_count: int,
    pack_count: int,
    files_offset: int,
    chunks_offset: int,
    packs_offset: int,
    strings_offset: int,
    strings_size: int,
    payload_crc: int,
) -> bytes:
    header_zero = _header_with_crc(
        flags=flags,
        build_id=build_id,
        file_count=file_count,
        chunk_count=chunk_count,
        pack_count=pack_count,
        files_offset=files_offset,
        chunks_offset=chunks_offset,
        packs_offset=packs_offset,
        strings_offset=strings_offset,
        strings_size=strings_size,
        payload_crc=payload_crc,
        header_crc=0,
    )
    return _header_with_crc(
        flags=flags,
        build_id=build_id,
        file_count=file_count,
        chunk_count=chunk_count,
        pack_count=pack_count,
        files_offset=files_offset,
        chunks_offset=chunks_offset,
        packs_offset=packs_offset,
        strings_offset=strings_offset,
        strings_size=strings_size,
        payload_crc=payload_crc,
        header_crc=crc32(header_zero),
    )


def build_manifest_bytes(
    build_id: bytes,
    files: Sequence[FileRecord],
    chunks: Sequence[ChunkRecord],
    packs: Sequence[PackRecord],
    strings: bytes,
    flags: int = 0,
) -> bytes:
    if len(build_id) != 16:
        raise ValueError("build id must contain 16 bytes")
    if len(files) > 0xFFFFFFFE:
        raise ValueError("file count exceeds the file-id domain")
    if len(chunks) > 0xFFFFFFFF:
        raise ValueError("chunk count exceeds uint32 file-record limits")
    if len(packs) > 0xFFFF:
        raise ValueError("pack count exceeds uint16 chunk-record limits")
    if len(strings) > 0xFFFFFFFF:
        raise ValueError("string table exceeds uint32 record offsets")
    files_offset = INDEX_HEADER_SIZE
    chunks_offset = files_offset + len(files) * FILE_RECORD.size
    packs_offset = chunks_offset + len(chunks) * CHUNK_RECORD.size
    strings_offset = packs_offset + len(packs) * PACK_RECORD.size
    payload = b"".join(record.pack() for record in files)
    payload += b"".join(record.pack() for record in chunks)
    payload += b"".join(record.pack() for record in packs)
    payload += strings
    payload_crc = crc32(payload)
    header = build_manifest_header(
        flags=flags,
        build_id=build_id,
        file_count=len(files),
        chunk_count=len(chunks),
        pack_count=len(packs),
        files_offset=files_offset,
        chunks_offset=chunks_offset,
        packs_offset=packs_offset,
        strings_offset=strings_offset,
        strings_size=len(strings),
        payload_crc=payload_crc,
    )
    return header + payload


def load_manifest(path: Path) -> PackManifest:
    data = path.read_bytes()
    if len(data) < INDEX_HEADER_SIZE:
        raise ValueError("pack index is truncated")
    values = list(INDEX_HEADER.unpack_from(data))
    (
        magic,
        version,
        header_size,
        flags,
        endian,
        build_id,
        file_count,
        chunk_count,
        pack_count,
        file_record_size,
        chunk_record_size,
        pack_record_size,
        files_offset,
        chunks_offset,
        packs_offset,
        strings_offset,
        strings_size,
        payload_crc,
        header_crc,
        reserved,
    ) = values
    if magic != INDEX_MAGIC or version != INDEX_VERSION:
        raise ValueError("unsupported AMPR pack index")
    if (
        header_size != INDEX_HEADER_SIZE
        or endian != ENDIAN_MARKER
        or flags & ~INDEX_KNOWN_FLAGS
        or reserved != 0
    ):
        raise ValueError("invalid AMPR pack header")
    if (
        file_record_size != FILE_RECORD.size
        or chunk_record_size != CHUNK_RECORD.size
        or pack_record_size != PACK_RECORD.size
    ):
        raise ValueError("unsupported AMPR pack record size")
    header_copy = bytearray(data[:INDEX_HEADER_SIZE])
    # header_crc is the penultimate uint32, at byte 116.
    struct.pack_into("<I", header_copy, 116, 0)
    if crc32(header_copy) != header_crc:
        raise ValueError("pack index header CRC mismatch")
    if crc32(data[INDEX_HEADER_SIZE:]) != payload_crc:
        raise ValueError("pack index payload CRC mismatch")
    expected_files = INDEX_HEADER_SIZE
    expected_chunks = expected_files + file_count * FILE_RECORD.size
    expected_packs = expected_chunks + chunk_count * CHUNK_RECORD.size
    expected_strings = expected_packs + pack_count * PACK_RECORD.size
    if (
        files_offset != expected_files
        or chunks_offset != expected_chunks
        or packs_offset != expected_packs
        or strings_offset != expected_strings
        or strings_offset + strings_size != len(data)
    ):
        raise ValueError("invalid pack index section layout")

    files = [
        FileRecord.unpack_from(data, files_offset + i * FILE_RECORD.size)
        for i in range(file_count)
    ]
    chunks = [
        ChunkRecord.unpack_from(data, chunks_offset + i * CHUNK_RECORD.size)
        for i in range(chunk_count)
    ]
    # AMPRPAK4 derives raw chunk size from the owning file's block geometry.
    for file in files:
        if not file.flags & FILE_FLAG_PACKED:
            continue
        block_size = 1 << file.block_shift
        for local_index in range(file.chunk_count):
            chunk_index = file.first_chunk + local_index
            if chunk_index >= len(chunks):
                raise ValueError("chunk range is invalid while decoding AMPRPAK4")
            block_begin = local_index * block_size
            remaining = file.logical_size - block_begin
            if remaining <= 0:
                raise ValueError("AMPRPAK4 file has too many chunks")
            chunks[chunk_index].raw_size = min(block_size, remaining)
    packs = [
        PackRecord.unpack_from(data, packs_offset + i * PACK_RECORD.size)
        for i in range(pack_count)
    ]
    strings = data[strings_offset:]
    manifest = PackManifest(path, build_id, flags, files, chunks, packs, strings)
    validate_manifest(manifest)
    return manifest


def validate_manifest(manifest: PackManifest) -> None:
    if manifest.flags & ~INDEX_KNOWN_FLAGS:
        raise ValueError("unknown pack index flags")

    for pack_id, record in enumerate(manifest.packs):
        name = manifest.string_at(record.name_offset, record.name_length)
        try:
            safe_output_path(Path("."), name)
        except ValueError as exc:
            raise ValueError(f"unsafe pack name {pack_id}: {name!r}") from exc
        if record.flags & ~PACK_KNOWN_FLAGS:
            raise ValueError(f"unknown flags for pack {pack_id}")
        if (
            record.io_page_size < 1 << MIN_IO_PAGE_SHIFT
            or record.io_page_size > 1 << MAX_IO_PAGE_SHIFT
            or record.io_page_size & (record.io_page_size - 1)
            or record.io_page_size % PHYSICAL_CHUNK_ALIGNMENT
        ):
            raise ValueError(f"invalid I/O page size for pack {pack_id}")
        if not record.flags & PACK_FLAG_IO_PAGE_LAYOUT:
            raise ValueError(f"pack {pack_id} does not declare page-aware layout")
        if record.file_size < DATA_HEADER_SIZE or record.payload_bytes > record.file_size:
            raise ValueError(f"invalid size for pack {pack_id}")
        payload_offset = record.file_size - record.payload_bytes
        if (
            payload_offset < DATA_HEADER_SIZE
            or payload_offset % record.io_page_size
            or record.file_size % record.io_page_size
        ):
            raise ValueError(f"invalid payload offset for pack {pack_id}")

    for file_id, record in enumerate(manifest.files, 1):
        path = manifest.string_at(record.path_offset, record.path_length)
        canonical = canonical_asset_path(path)
        if canonical != path or canonical == "/app0":
            raise ValueError(f"non-canonical path for file id {file_id}")
        if record.reserved or record.flags & ~FILE_KNOWN_FLAGS:
            raise ValueError(f"unknown flags for file id {file_id}")
        expected_hash = asset_path_hash(canonical)
        if expected_hash != record.path_hash:
            raise ValueError(f"path hash mismatch for file id {file_id}")
        packed = bool(record.flags & FILE_FLAG_PACKED)
        if not packed:
            if (
                record.first_chunk
                or record.chunk_count
                or record.block_shift
                or record.packing_class
                or record.flags
            ):
                raise ValueError(f"loose file id {file_id} references chunks")
            continue
        if record.block_shift < MIN_BLOCK_SHIFT or record.block_shift > MAX_BLOCK_SHIFT:
            raise ValueError(f"invalid block shift for file id {file_id}")
        if (record.flags & FILE_FLAG_STREAMING) and (
            record.flags & FILE_FLAG_RANDOM_ACCESS
        ):
            raise ValueError(
                f"file id {file_id} cannot be both streaming and random-access"
            )
        if record.first_chunk + record.chunk_count > len(manifest.chunks):
            raise ValueError(f"chunk range is invalid for file id {file_id}")
        total = 0
        block_size = 1 << record.block_shift
        for local_index in range(record.chunk_count):
            chunk = manifest.chunks[record.first_chunk + local_index]
            if chunk.raw_size == 0 or chunk.raw_size > block_size:
                raise ValueError(f"invalid raw chunk size for file id {file_id}")
            if chunk.stored_size == 0 or chunk.stored_size > block_size:
                raise ValueError(f"invalid stored chunk size for file id {file_id}")
            if local_index + 1 != record.chunk_count and chunk.raw_size != block_size:
                raise ValueError(f"short non-final chunk for file id {file_id}")
            if chunk.codec not in (CHUNK_CODEC_RAW, CHUNK_CODEC_LZ4):
                raise ValueError(f"unknown chunk codec for file id {file_id}")
            if chunk.codec == CHUNK_CODEC_RAW and chunk.stored_size != chunk.raw_size:
                raise ValueError(f"raw chunk size mismatch for file id {file_id}")
            if chunk.pack_id >= len(manifest.packs):
                raise ValueError(f"invalid pack id for file id {file_id}")
            if chunk.flags & ~CHUNK_KNOWN_FLAGS:
                raise ValueError(f"invalid chunk flags/reserved for file id {file_id}")
            streaming = bool(record.flags & FILE_FLAG_STREAMING)
            if streaming != bool(chunk.flags & CHUNK_FLAG_STREAMING):
                raise ValueError(
                    f"streaming flag mismatch for file id {file_id}"
                )
            if (record.flags & FILE_FLAG_STORE_ONLY) and chunk.codec != CHUNK_CODEC_RAW:
                raise ValueError(
                    f"store-only file id {file_id} contains a compressed chunk"
                )
            pack = manifest.packs[chunk.pack_id]
            payload_offset = pack.file_size - pack.payload_bytes
            if (
                chunk.offset < payload_offset
                or chunk.offset + chunk.stored_size > pack.file_size
                or chunk.offset % PHYSICAL_CHUNK_ALIGNMENT
            ):
                raise ValueError(
                    f"chunk range/alignment is invalid for file id {file_id}"
                )
            page_size = pack.io_page_size
            page_begin = align_down(chunk.offset, page_size)
            page_end = align_up(chunk.offset + chunk.stored_size, page_size)
            page_contained = bool(chunk.flags & CHUNK_FLAG_PAGE_CONTAINED)
            page_aligned = bool(chunk.flags & CHUNK_FLAG_PAGE_ALIGNED)
            if page_contained:
                if chunk.stored_size > page_size or page_begin != align_down(
                    chunk.offset + chunk.stored_size - 1, page_size
                ):
                    raise ValueError(
                        f"page-contained chunk crosses an I/O page for file id {file_id}"
                    )
            if page_aligned and chunk.offset % page_size:
                raise ValueError(
                    f"page-aligned chunk is not page aligned for file id {file_id}"
                )
            page_safe = page_contained or page_aligned
            if chunk.stored_size <= page_size and page_aligned and not page_contained:
                # Small page-aligned extents are also page-contained. Requiring
                # both bits catches packers that accidentally omit the stronger
                # invariant used by the random-access planner.
                raise ValueError(
                    f"small page-aligned chunk lacks containment flag for file id {file_id}"
                )
            if record.flags & FILE_FLAG_RANDOM_ACCESS and not page_safe:
                raise ValueError(
                    f"random-access file uses a non-page-safe chunk for file id {file_id}"
                )
            if not record.flags & FILE_FLAG_STREAMING and not page_safe:
                raise ValueError(
                    f"non-streaming file uses a non-page-safe chunk for file id {file_id}"
                )
            if page_begin < payload_offset or page_end > pack.file_size:
                raise ValueError(
                    f"aligned I/O range is outside the pack for file id {file_id}"
                )
            total += chunk.raw_size
        if total != record.logical_size:
            raise ValueError(f"logical size mismatch for file id {file_id}")

def build_data_header(
    pack_id: int,
    build_id: bytes,
    payload_offset: int,
    payload_bytes: int,
    flags: int = 0,
) -> bytes:
    if len(build_id) != 16:
        raise ValueError("build id must contain 16 bytes")
    zero = DATA_HEADER.pack(
        DATA_MAGIC,
        DATA_VERSION,
        DATA_HEADER_SIZE,
        pack_id,
        flags,
        build_id,
        payload_offset,
        payload_bytes,
        0,
        0,
    )
    header_crc = crc32(zero)
    return DATA_HEADER.pack(
        DATA_MAGIC,
        DATA_VERSION,
        DATA_HEADER_SIZE,
        pack_id,
        flags,
        build_id,
        payload_offset,
        payload_bytes,
        header_crc,
        0,
    )


def validate_data_header(
    header: bytes,
    *,
    expected_pack_id: int | None = None,
    expected_build_id: bytes | None = None,
    expected_flags: int | None = None,
) -> tuple[int, bytes, int, int, int]:
    if len(header) != DATA_HEADER_SIZE:
        raise ValueError("pack data header is truncated")
    (
        magic,
        version,
        header_size,
        pack_id,
        flags,
        build_id,
        payload_offset,
        payload_bytes,
        header_crc,
        reserved,
    ) = DATA_HEADER.unpack(header)
    if magic != DATA_MAGIC or version != DATA_VERSION or header_size != DATA_HEADER_SIZE:
        raise ValueError("unsupported pack data header")
    if reserved != 0:
        raise ValueError("invalid pack data header")
    if flags & ~PACK_KNOWN_FLAGS:
        raise ValueError("unknown pack data flags")
    copy = bytearray(header)
    struct.pack_into("<I", copy, 56, 0)
    if crc32(copy) != header_crc:
        raise ValueError("pack data header CRC mismatch")
    if expected_pack_id is not None and pack_id != expected_pack_id:
        raise ValueError("pack id mismatch")
    if expected_build_id is not None and build_id != expected_build_id:
        raise ValueError("pack build id mismatch")
    if expected_flags is not None and flags != expected_flags:
        raise ValueError("pack flags mismatch")
    return pack_id, build_id, payload_offset, payload_bytes, flags


class StringTable:
    def __init__(self) -> None:
        self._data = bytearray()
        self._offsets: dict[str, tuple[int, int]] = {}

    def add(self, value: str) -> tuple[int, int]:
        prior = self._offsets.get(value)
        if prior is not None:
            return prior
        encoded = value.encode("utf-8")
        if b"\x00" in encoded:
            raise ValueError("NUL in string table value")
        offset = len(self._data)
        if (
            offset > 0xFFFFFFFF
            or len(encoded) > 0xFFFFFFFF
            or offset + len(encoded) + 1 > 0x100000000
        ):
            raise ValueError("string table exceeds uint32 format limits")
        self._data.extend(encoded)
        self._data.append(0)
        result = (offset, len(encoded))
        self._offsets[value] = result
        return result

    def bytes(self) -> bytes:
        return bytes(self._data)


class Lz4Codec:
    """Raw LZ4 block codec with python-lz4 and system-lib fallbacks."""

    def __init__(self) -> None:
        self._py = None
        self._lib = None
        try:
            import lz4.block as py_lz4  # type: ignore

            self._py = py_lz4
            return
        except ImportError:
            pass
        name = ctypes.util.find_library("lz4")
        if not name:
            raise RuntimeError(
                "LZ4 compressor is unavailable. Install 'lz4' for Python "
                "(python -m pip install lz4) or provide liblz4."
            )
        lib = ctypes.CDLL(name)
        lib.LZ4_compressBound.argtypes = [ctypes.c_int]
        lib.LZ4_compressBound.restype = ctypes.c_int
        lib.LZ4_compress_default.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_int,
        ]
        lib.LZ4_compress_default.restype = ctypes.c_int
        if hasattr(lib, "LZ4_compress_fast"):
            lib.LZ4_compress_fast.argtypes = [
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_int,
            ]
            lib.LZ4_compress_fast.restype = ctypes.c_int
        lib.LZ4_decompress_safe.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_int,
        ]
        lib.LZ4_decompress_safe.restype = ctypes.c_int
        if hasattr(lib, "LZ4_compress_HC"):
            lib.LZ4_compress_HC.argtypes = [
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_int,
            ]
            lib.LZ4_compress_HC.restype = ctypes.c_int
        self._lib = lib

    def compress(
        self,
        data: bytes,
        *,
        mode: str = "hc",
        level: int = 12,
        acceleration: int = 1,
    ) -> bytes:
        if not data:
            return b""
        if len(data) > 0x7FFFFFFF:
            raise ValueError("LZ4 block exceeds INT_MAX")
        if self._py is not None:
            if mode == "hc":
                return self._py.compress(
                    data,
                    mode="high_compression",
                    compression=max(1, min(level, 12)),
                    store_size=False,
                )
            if mode != "fast":
                raise ValueError(f"unsupported compression mode: {mode}")
            return self._py.compress(
                data,
                mode="fast",
                acceleration=max(1, acceleration),
                store_size=False,
            )
        assert self._lib is not None
        source = ctypes.create_string_buffer(data, len(data))
        capacity = self._lib.LZ4_compressBound(len(data))
        destination = ctypes.create_string_buffer(capacity)
        if mode == "hc" and hasattr(self._lib, "LZ4_compress_HC"):
            written = self._lib.LZ4_compress_HC(
                source, destination, len(data), capacity, max(1, min(level, 12))
            )
        elif mode == "fast":
            if hasattr(self._lib, "LZ4_compress_fast"):
                written = self._lib.LZ4_compress_fast(
                    source, destination, len(data), capacity, max(1, acceleration)
                )
            else:
                written = self._lib.LZ4_compress_default(
                    source, destination, len(data), capacity
                )
        elif mode == "hc":
            raise RuntimeError(
                "the installed liblz4 does not export LZ4_compress_HC"
            )
        else:
            raise ValueError(f"unsupported compression mode: {mode}")
        if written <= 0:
            raise RuntimeError("LZ4 compression failed")
        return destination.raw[:written]

    def decompress(self, data: bytes, raw_size: int) -> bytes:
        if raw_size < 0 or raw_size > 0x7FFFFFFF or len(data) > 0x7FFFFFFF:
            raise ValueError("LZ4 size exceeds INT_MAX")
        if self._py is not None:
            result = self._py.decompress(data, uncompressed_size=raw_size)
            if len(result) != raw_size:
                raise ValueError("LZ4 output size mismatch")
            return result
        assert self._lib is not None
        source = ctypes.create_string_buffer(data, len(data))
        destination = ctypes.create_string_buffer(raw_size)
        written = self._lib.LZ4_decompress_safe(
            source, destination, len(data), raw_size
        )
        if written != raw_size:
            raise ValueError("LZ4 decompression failed or output size mismatched")
        return destination.raw[:written]


def glob_matches(path: str, patterns: Sequence[str]) -> bool:
    normalized = path.replace("\\", "/").lstrip("/")
    return any(fnmatch.fnmatchcase(normalized, pattern.replace("\\", "/").lstrip("/")) for pattern in patterns)


def deterministic_build_id(parts: Iterable[bytes]) -> bytes:
    digest = hashlib.sha256()
    digest.update(b"AMPRPACK4\0")
    for part in parts:
        digest.update(struct.pack("<Q", len(part)))
        digest.update(part)
    return digest.digest()[:16]


RUNTIME_PROFILE = struct.Struct("<8sII16sQQIIII")


@dataclass(frozen=True)
class RuntimeSettings:
    decoded_cache_bytes: int
    physical_cache_bytes: int
    workers: int
    latency_reserve_workers: int

    def validate(self) -> None:
        values = (self.decoded_cache_bytes, self.physical_cache_bytes,
                  self.workers, self.latency_reserve_workers)
        if any(type(value) is not int for value in values):
            raise ValueError("runtime settings must be integers")
        if not 1 <= self.workers <= 16 or not 0 <= self.latency_reserve_workers < self.workers:
            raise ValueError("runtime workers must be 1..16 and reserve must be smaller")
        for value in values[:2]:
            if value < 0 or value >= 1 << 64 or value % 16384:
                raise ValueError("runtime cache sizes must be nonnegative 16 KiB multiples")

    def encode(self, build_id: bytes) -> bytes:
        self.validate()
        if len(build_id) != 16:
            raise ValueError("runtime profile needs a 16-byte build ID")
        data = bytearray(RUNTIME_PROFILE.pack(
            b"AMPRCFG1", 1, RUNTIME_PROFILE.size, build_id,
            self.decoded_cache_bytes, self.physical_cache_bytes,
            self.workers, self.latency_reserve_workers, 0, 0))
        struct.pack_into("<I", data, 56, crc32(data))
        return bytes(data)


def read_runtime_settings(path: Path, build_id: bytes) -> RuntimeSettings | None:
    try:
        with path.open("rb") as handle:
            data = bytearray(handle.read(RUNTIME_PROFILE.size + 1))
    except FileNotFoundError:
        return None
    if len(data) != RUNTIME_PROFILE.size:
        raise ValueError("invalid runtime profile size")
    magic, version, size, bound_id, decoded, physical, workers, reserve, checksum, flags = RUNTIME_PROFILE.unpack(data)
    struct.pack_into("<I", data, 56, 0)
    if (magic != b"AMPRCFG1" or version != 1 or size != len(data) or
            bound_id != build_id or flags or crc32(data) != checksum):
        raise ValueError("invalid runtime profile header, build ID or CRC")
    result = RuntimeSettings(decoded, physical, workers, reserve)
    result.validate()
    return result
