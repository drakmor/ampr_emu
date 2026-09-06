#!/usr/bin/env python3
"""Convert an AMPRPAK3 manifest to AMPRPAK4 without rebuilding data volumes."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import struct
import tempfile
from typing import BinaryIO, Sequence

from ampr_pack_format import (
    CHUNK_DESCRIPTOR_KNOWN_MASK,
    CHUNK_RECORD,
    CRC_HEADER_SIZE,
    ENDIAN_MARKER,
    FILE_RECORD,
    INDEX_HEADER,
    INDEX_HEADER_SIZE,
    INDEX_KNOWN_FLAGS,
    PACK_RECORD,
    build_chunk_crc_header,
    build_manifest_header,
    chunk_crc_path,
    crc32,
)

LEGACY_MAGIC = b"AMPRPAK3"
LEGACY_VERSION = 3
LEGACY_CHUNK_RECORD = struct.Struct("<QII")
COPY_BYTES = 4 * 1024 * 1024
CHUNK_BATCH = 65536


class ConversionError(RuntimeError):
    pass


def _read_exact(handle: BinaryIO, size: int) -> bytes:
    data = handle.read(size)
    if len(data) != size:
        raise ConversionError("legacy manifest is truncated")
    return data


def _copy_section(
    source: BinaryIO,
    destination: BinaryIO,
    size: int,
    source_crc: int,
    destination_crc: int,
) -> tuple[int, int]:
    remaining = size
    while remaining:
        data = _read_exact(source, min(remaining, COPY_BYTES))
        source_crc = crc32(data, source_crc)
        destination_crc = crc32(data, destination_crc)
        destination.write(data)
        remaining -= len(data)
    return source_crc, destination_crc


def _legacy_header(path: Path) -> tuple[tuple[object, ...], int]:
    with path.open("rb") as source:
        raw = _read_exact(source, INDEX_HEADER_SIZE)
    values = INDEX_HEADER.unpack(raw)
    (
        magic,
        version,
        header_size,
        flags,
        endian,
        _build_id,
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
        _payload_crc,
        header_crc,
        reserved,
    ) = values
    if magic != LEGACY_MAGIC or version != LEGACY_VERSION:
        raise ConversionError("input is not an AMPRPAK3 manifest")
    if (
        header_size != INDEX_HEADER_SIZE
        or endian != ENDIAN_MARKER
        or flags & ~INDEX_KNOWN_FLAGS
        or reserved != 0
        or file_record_size != FILE_RECORD.size
        or chunk_record_size != LEGACY_CHUNK_RECORD.size
        or pack_record_size != PACK_RECORD.size
    ):
        raise ConversionError("unsupported AMPRPAK3 header or record geometry")
    expected_chunks = INDEX_HEADER_SIZE + file_count * FILE_RECORD.size
    expected_packs = expected_chunks + chunk_count * LEGACY_CHUNK_RECORD.size
    expected_strings = expected_packs + pack_count * PACK_RECORD.size
    expected_size = expected_strings + strings_size
    if (
        files_offset != INDEX_HEADER_SIZE
        or chunks_offset != expected_chunks
        or packs_offset != expected_packs
        or strings_offset != expected_strings
        or path.stat().st_size != expected_size
    ):
        raise ConversionError("invalid AMPRPAK3 section layout")
    copy = bytearray(raw)
    struct.pack_into("<I", copy, 116, 0)
    if crc32(copy) != header_crc:
        raise ConversionError("AMPRPAK3 header CRC mismatch")
    return values, expected_size


def _temporary_path(destination: Path, suffix: str) -> Path:
    handle = tempfile.NamedTemporaryFile(
        mode="wb",
        dir=destination.parent,
        prefix=f".{destination.name}.",
        suffix=suffix,
        delete=False,
    )
    path = Path(handle.name)
    handle.close()
    return path


def _publish_pair(
    temp_crc: Path,
    crc_path: Path,
    temp_index: Path,
    index_path: Path,
) -> None:
    replacements: list[tuple[Path, Path | None]] = []
    try:
        for temporary, final in ((temp_crc, crc_path), (temp_index, index_path)):
            backup = None
            if final.exists():
                backup = final.with_name(f".{final.name}.backup-{os.getpid()}")
                backup.unlink(missing_ok=True)
                os.replace(final, backup)
            replacements.append((final, backup))
            os.replace(temporary, final)
    except BaseException:
        for final, backup in reversed(replacements):
            final.unlink(missing_ok=True)
            if backup is not None and backup.exists():
                os.replace(backup, final)
        raise
    else:
        for _final, backup in replacements:
            if backup is not None:
                backup.unlink(missing_ok=True)


def convert_manifest(
    source_path: Path,
    output_path: Path,
    *,
    overwrite: bool = False,
) -> dict[str, object]:
    source_path = source_path.resolve(strict=True)
    output_path = output_path.resolve()
    if source_path == output_path:
        raise ConversionError("source and output must differ; convert beside the original")
    if source_path.parent != output_path.parent:
        raise ConversionError("output must be beside the source so existing pack names still resolve")
    output_crc = chunk_crc_path(output_path)
    if not overwrite and (output_path.exists() or output_crc.exists()):
        raise ConversionError("output index or CRC sidecar already exists; use --overwrite")

    values, _source_size = _legacy_header(source_path)
    (
        _magic,
        _version,
        _header_size,
        flags,
        _endian,
        build_id,
        file_count,
        chunk_count,
        pack_count,
        _file_record_size,
        _chunk_record_size,
        _pack_record_size,
        _files_offset,
        _chunks_offset,
        _packs_offset,
        _strings_offset,
        strings_size,
        source_payload_crc,
        _header_crc,
        _reserved,
    ) = values

    files_bytes = file_count * FILE_RECORD.size
    packs_and_strings_bytes = pack_count * PACK_RECORD.size + strings_size
    files_offset = INDEX_HEADER_SIZE
    chunks_offset = files_offset + files_bytes
    packs_offset = chunks_offset + chunk_count * CHUNK_RECORD.size
    strings_offset = packs_offset + pack_count * PACK_RECORD.size

    temp_index = _temporary_path(output_path, ".index.tmp")
    temp_crc = _temporary_path(output_crc, ".crc.tmp")
    try:
        source_crc = 0
        output_payload_crc = 0
        crc_payload_crc = 0
        with source_path.open("rb") as source, temp_index.open("w+b") as index_out, temp_crc.open("w+b") as crc_out:
            source.seek(INDEX_HEADER_SIZE)
            index_out.write(b"\0" * INDEX_HEADER_SIZE)
            crc_out.write(b"\0" * CRC_HEADER_SIZE)
            source_crc, output_payload_crc = _copy_section(
                source,
                index_out,
                files_bytes,
                source_crc,
                output_payload_crc,
            )

            remaining_chunks = chunk_count
            while remaining_chunks:
                count = min(remaining_chunks, CHUNK_BATCH)
                legacy = _read_exact(source, count * LEGACY_CHUNK_RECORD.size)
                source_crc = crc32(legacy, source_crc)
                compact = bytearray(count * CHUNK_RECORD.size)
                checksums = bytearray(count * 4)
                for index in range(count):
                    location, descriptor, raw_crc = LEGACY_CHUNK_RECORD.unpack_from(
                        legacy, index * LEGACY_CHUNK_RECORD.size
                    )
                    if descriptor & ~CHUNK_DESCRIPTOR_KNOWN_MASK:
                        raise ConversionError("legacy chunk descriptor contains reserved bits")
                    CHUNK_RECORD.pack_into(
                        compact,
                        index * CHUNK_RECORD.size,
                        location,
                        descriptor,
                    )
                    struct.pack_into("<I", checksums, index * 4, raw_crc)
                index_out.write(compact)
                crc_out.write(checksums)
                output_payload_crc = crc32(compact, output_payload_crc)
                crc_payload_crc = crc32(checksums, crc_payload_crc)
                remaining_chunks -= count

            source_crc, output_payload_crc = _copy_section(
                source,
                index_out,
                packs_and_strings_bytes,
                source_crc,
                output_payload_crc,
            )
            if source.read(1):
                raise ConversionError("legacy manifest has trailing bytes")
            if source_crc != source_payload_crc:
                raise ConversionError("AMPRPAK3 payload CRC mismatch")

            index_header = build_manifest_header(
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
                payload_crc=output_payload_crc,
            )
            index_out.seek(0)
            index_out.write(index_header)
            index_out.flush()
            os.fsync(index_out.fileno())

            crc_out.seek(0)
            crc_out.write(
                build_chunk_crc_header(build_id, chunk_count, crc_payload_crc)
            )
            crc_out.flush()
            os.fsync(crc_out.fileno())

        _publish_pair(temp_crc, output_crc, temp_index, output_path)
    except BaseException:
        temp_index.unlink(missing_ok=True)
        temp_crc.unlink(missing_ok=True)
        raise

    return {
        "source": str(source_path),
        "index": str(output_path),
        "crc": str(output_crc),
        "build_id": build_id.hex(),
        "files": file_count,
        "chunks": chunk_count,
        "packs": pack_count,
        "resident_bytes_saved": chunk_count * 4,
    }


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Convert AMPRPAK3 to AMPRPAK4 and an offline CRC sidecar without repacking .pak volumes"
    )
    parser.add_argument("--index", type=Path, required=True, help="source AMPRPAK3 index")
    parser.add_argument("--output", type=Path, required=True, help="new AMPRPAK4 index beside the source")
    parser.add_argument("--overwrite", action="store_true", help="replace an existing converted output set")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = create_parser().parse_args(argv)
    try:
        result = convert_manifest(args.index, args.output, overwrite=args.overwrite)
    except (ConversionError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=os.sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
