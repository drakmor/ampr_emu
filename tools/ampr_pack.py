#!/usr/bin/env python3
"""Build, inspect, verify, extract and prune AMPR seekable LZ4 asset packs."""
from __future__ import annotations

import argparse
from array import array
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import asdict, dataclass, field, replace
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import struct
from string import Formatter
import sys
import tempfile
import time
import tomllib
from typing import BinaryIO, Callable, Iterable, Iterator, Sequence, TextIO

from ampr_pack_format import (
    CHUNK_CODEC_LZ4,
    CHUNK_CODEC_RAW,
    CHUNK_FLAG_PAGE_ALIGNED,
    CHUNK_FLAG_PAGE_CONTAINED,
    CHUNK_FLAG_SHARED,
    CHUNK_FLAG_STREAMING,
    DATA_HEADER_SIZE,
    FILE_FLAG_HOT,
    FILE_FLAG_RANDOM_ACCESS,
    FILE_FLAG_PACKED,
    FILE_FLAG_STORE_ONLY,
    FILE_FLAG_STREAMING,
    MAX_IO_PAGE_SHIFT,
    MAX_BLOCK_SHIFT,
    MIN_IO_PAGE_SHIFT,
    MIN_BLOCK_SHIFT,
    PACK_FLAG_STRIPED,
    PACK_FLAG_IO_PAGE_LAYOUT,
    PHYSICAL_CHUNK_ALIGNMENT,
    AmprIndexEntry,
    RuntimeSettings,
    read_runtime_settings,
    ChunkRecord,
    FileRecord,
    Lz4Codec,
    PackManifest,
    PackRecord,
    StringTable,
    align_up,
    asset_path_hash,
    asset_relative_path,
    ascii_fold_path_bytes,
    block_shift,
    build_chunk_crc_header,
    build_data_header,
    build_manifest_bytes,
    canonical_asset_path,
    crc32,
    deterministic_build_id,
    encode_chunk_crcs,
    fnv1a64,
    glob_matches,
    load_manifest,
    load_chunk_crcs,
    parse_size,
    read_ampridx3,
    safe_output_path,
    chunk_crc_path,
    validate_data_header,
)

TOOL_VERSION = "4.0"
DEFAULT_INDEX_NAME = "ampr_assets.index"
DEFAULT_PACK_PATTERN = "ampr_assets-{id:03d}.pak"


class PackError(RuntimeError):
    pass


@dataclass(frozen=True)
class GroupConfig:
    name: str
    pack_count: int = 1
    assignment: str = "balanced"
    max_pack_size: int = 0
    stripe_large_files: bool = False
    stripe_threshold: int = 256 * 1024 * 1024
    stripe_group_blocks: int = 8
    io_page_size: int = 0


@dataclass(frozen=True)
class Rule:
    action: str
    include: tuple[str, ...] = ("**",)
    exclude: tuple[str, ...] = ()
    block_shift: int = 16
    group: str = "default"
    mode: str = "hc"
    level: int = 12
    acceleration: int = 1
    min_savings_bytes: int = 64
    min_savings_ratio: float = 0.01
    io_neutral_min_savings_bytes: int = 8192
    io_neutral_min_savings_ratio: float = 0.125
    layout: str = "auto"
    streaming: bool = False
    hot: bool = False
    force_pack: bool = False

    def matches(self, relative_path: str) -> bool:
        return glob_matches(relative_path, self.include) and not glob_matches(
            relative_path, self.exclude
        )

    def resolved_layout(self) -> str:
        if self.layout != "auto":
            return self.layout
        if self.streaming:
            return "streaming"
        if self.hot:
            return "random"
        return "mixed"


@dataclass
class BuildConfig:
    runtime: RuntimeSettings | None = None
    index_name: str = DEFAULT_INDEX_NAME
    pack_pattern: str = DEFAULT_PACK_PATTERN
    default_action: str = "loose"
    default_block_shift: int = 16
    io_page_size: int = 64 * 1024
    payload_alignment: int = 64 * 1024
    chunk_alignment: int = 64
    workers: int = max(1, min(8, os.cpu_count() or 1))
    compression_mode: str = "hc"
    compression_level: int = 12
    acceleration: int = 1
    min_savings_bytes: int = 64
    min_savings_ratio: float = 0.01
    io_neutral_min_savings_bytes: int = 8 * 1024
    io_neutral_min_savings_ratio: float = 0.125
    deduplicate: bool = True
    deduplicate_scope: str = "lane"
    deduplicate_streaming: bool = False
    preserve_mtime: bool = True
    validate_index_metadata: bool = True
    # When enabled, compression heuristics may fall back to RAW chunks but may
    # not silently turn an explicitly packed file back into a loose dependency.
    self_contained: bool = False
    required_packed: tuple[str, ...] = ()
    auto_loose_large_files: bool = True
    # A trace-derived hot rule is explicit evidence that decoded-cache reuse can
    # justify keeping an otherwise incompressible file in the pack. Leave those
    # files alone by default; callers can opt in when they prefer a pure size
    # policy over cache locality.
    auto_loose_hot_files: bool = False
    auto_loose_min_file_size: int = 64 * 1024 * 1024
    auto_loose_sample_blocks: int = 32
    auto_loose_sample_bytes: int = 16 * 1024 * 1024
    auto_loose_min_savings_ratio: float = 0.05
    auto_loose_max_raw_ratio: float = 0.90
    groups: dict[str, GroupConfig] = field(default_factory=dict)
    rules: list[Rule] = field(default_factory=list)


@dataclass(frozen=True)
class SelectedFile:
    file_id: int
    index_entry: AmprIndexEntry
    source: Path
    relative: str
    rule: Rule
    size: int
    mtime: int
    lane: int


@dataclass
class BuildStats:
    files_total: int = 0
    files_packed: int = 0
    files_loose: int = 0
    loose_paths: list[str] = field(default_factory=list)
    files_auto_loose: int = 0
    auto_loose_logical_bytes: int = 0
    auto_loose_sampled_bytes: int = 0
    chunks: int = 0
    chunks_lz4: int = 0
    chunks_raw: int = 0
    chunks_shared: int = 0
    logical_bytes: int = 0
    stored_bytes: int = 0
    padding_bytes: int = 0
    io_pages_touched: int = 0
    io_page_safe_chunks: int = 0
    dense_streaming_chunks: int = 0


@dataclass(frozen=True)
class BuildProgress:
    phase: str
    files_done: int
    files_total: int
    logical_bytes_done: int
    logical_bytes_total: int
    current_path: str = ""


ProgressCallback = Callable[[BuildProgress], None]


def _progress_size(value: int) -> str:
    amount = float(value)
    for suffix in ("B", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024.0 or suffix == "TiB":
            return f"{amount:.0f} {suffix}" if suffix == "B" else f"{amount:.1f} {suffix}"
        amount /= 1024.0
    raise AssertionError("unreachable")


class ConsoleBuildProgress:
    """Throttled line-oriented progress suitable for terminals, CI and the GUI."""

    def __init__(
        self,
        stream: TextIO | None = None,
        min_interval: float = 0.5,
        heartbeat_interval: float = 5.0,
    ) -> None:
        self.stream = sys.stderr if stream is None else stream
        self.min_interval = min_interval
        self.heartbeat_interval = heartbeat_interval
        self.started = time.monotonic()
        self.last_output = 0.0
        self.last_percent = -1
        self.last_phase = ""
        self.packing_started: float | None = None

    @staticmethod
    def _percent(progress: BuildProgress) -> int:
        if progress.phase == "planning":
            fraction = progress.files_done / progress.files_total if progress.files_total else 1.0
            return min(10, int(fraction * 10))
        if progress.phase == "packing":
            if progress.logical_bytes_total:
                fraction = progress.logical_bytes_done / progress.logical_bytes_total
            else:
                fraction = progress.files_done / progress.files_total if progress.files_total else 1.0
            return min(95, 10 + int(fraction * 85))
        return {"finalizing": 96, "publishing": 99, "complete": 100}.get(progress.phase, 0)

    def __call__(self, progress: BuildProgress) -> None:
        now = time.monotonic()
        percent = self._percent(progress)
        phase_changed = progress.phase != self.last_phase
        complete = progress.phase == "complete"
        if progress.phase == "packing" and self.packing_started is None:
            self.packing_started = now
        if not phase_changed and not complete:
            since_output = now - self.last_output
            if since_output < self.min_interval:
                return
            if percent <= self.last_percent and since_output < self.heartbeat_interval:
                return
        elapsed_seconds = now - self.started
        elapsed = int(elapsed_seconds)
        elapsed_text = f"{elapsed // 3600:02d}:{elapsed // 60 % 60:02d}:{elapsed % 60:02d}"
        details = f"files {progress.files_done}/{progress.files_total}"
        if progress.phase == "packing":
            details += (
                f", {_progress_size(progress.logical_bytes_done)}"
                f"/{_progress_size(progress.logical_bytes_total)}"
            )
            packing_seconds = now - self.packing_started if self.packing_started is not None else 0.0
            if packing_seconds > 0 and progress.logical_bytes_done > 0:
                rate = progress.logical_bytes_done / packing_seconds
                remaining = max(0, progress.logical_bytes_total - progress.logical_bytes_done)
                eta = int(remaining / rate) if rate > 0 else 0
                details += (
                    f", {_progress_size(int(rate))}/s"
                    f", ETA {eta // 3600:02d}:{eta // 60 % 60:02d}:{eta % 60:02d}"
                )
        if progress.current_path:
            details += f", current={progress.current_path}"
        print(
            f"[pack {percent:3d}%] {progress.phase}: {details}, elapsed {elapsed_text}",
            file=self.stream,
            flush=True,
        )
        self.last_output = now
        self.last_percent = percent
        self.last_phase = progress.phase


@dataclass
class CompressedBlock:
    raw: bytes
    stored: bytes
    codec: int
    raw_crc: int
    stored_crc: int
    raw_fingerprint: bytes


class PackVolumeWriter:
    def __init__(
        self,
        *,
        pack_id: int,
        name: str,
        output_dir: Path,
        payload_alignment: int,
        chunk_alignment: int,
        io_page_size: int,
        group: str,
        lane: int,
        volume: int,
        max_pack_size: int,
        flags: int,
    ) -> None:
        self.pack_id = pack_id
        self.name = name
        self.output_dir = output_dir
        self.final_path = safe_output_path(output_dir, name)
        self.final_path.parent.mkdir(parents=True, exist_ok=True)
        self.temp_path = self.final_path.with_name(
            f".{self.final_path.name}.tmp-{os.getpid()}-{pack_id}"
        )
        self.payload_alignment = payload_alignment
        self.chunk_alignment = chunk_alignment
        self.io_page_size = io_page_size
        self.payload_offset = align_up(DATA_HEADER_SIZE, payload_alignment)
        self.group = group
        self.lane = lane
        self.volume = volume
        self.max_pack_size = max_pack_size
        self.flags = flags | PACK_FLAG_IO_PAGE_LAYOUT
        self.handle = self.temp_path.open("w+b")
        self.handle.write(b"\0" * self.payload_offset)
        self.position = self.payload_offset
        self.padding_bytes = self.payload_offset - DATA_HEADER_SIZE
        self.closed = False

    def placement_for(
        self,
        stored_size: int,
        *,
        layout: str,
        extent_start: bool = False,
    ) -> tuple[int, int]:
        if stored_size <= 0:
            raise PackError("cannot place an empty physical chunk")
        position = self.position
        if extent_start:
            position = align_up(position, self.io_page_size)

        if layout == "streaming":
            # Streaming extents stay dense. The runtime merges adjacent ranges,
            # so page isolation would only add padding and reduce throughput.
            offset = align_up(position, self.chunk_alignment)
        elif stored_size >= self.io_page_size:
            # Large random/mixed chunks start on an I/O-page boundary. Their
            # cold-read footprint is therefore ceil(size / io_page_size), never
            # one page larger merely because of an unlucky offset.
            offset = align_up(position, self.io_page_size)
        else:
            # Small random/mixed chunks share pages but never straddle them.
            offset = align_up(position, self.chunk_alignment)
            page_end = align_up(offset + 1, self.io_page_size)
            if offset + stored_size > page_end:
                offset = align_up(offset, self.io_page_size)

        placement_flags = 0
        if stored_size <= self.io_page_size:
            first_page = offset // self.io_page_size
            last_page = (offset + stored_size - 1) // self.io_page_size
            if first_page == last_page:
                placement_flags |= CHUNK_FLAG_PAGE_CONTAINED
        if offset % self.io_page_size == 0:
            placement_flags |= CHUNK_FLAG_PAGE_ALIGNED
        return offset, placement_flags

    def projected_end(
        self,
        stored_size: int,
        *,
        layout: str,
        extent_start: bool = False,
    ) -> int:
        offset, _placement_flags = self.placement_for(
            stored_size, layout=layout, extent_start=extent_start
        )
        return offset + stored_size

    def can_fit(
        self,
        stored_size: int,
        *,
        layout: str,
        extent_start: bool = False,
    ) -> bool:
        projected = self.projected_end(
            stored_size, layout=layout, extent_start=extent_start
        )
        projected = align_up(projected, self.io_page_size)
        return self.max_pack_size <= 0 or projected <= self.max_pack_size

    def write(
        self,
        payload: bytes,
        *,
        layout: str,
        extent_start: bool = False,
    ) -> tuple[int, int, int]:
        offset, placement_flags = self.placement_for(
            len(payload), layout=layout, extent_start=extent_start
        )
        padding = offset - self.position
        if padding:
            self.handle.write(b"\0" * padding)
            self.padding_bytes += padding
        self.handle.write(payload)
        self.position = offset + len(payload)
        return offset, padding, placement_flags

    def projected_final_size(self) -> int:
        return align_up(self.position, self.io_page_size)

    def finalize(self, build_id: bytes) -> PackRecord:
        if self.closed:
            raise PackError("pack was already finalized")
        final_size = self.projected_final_size()
        tail_padding = final_size - self.position
        if tail_padding:
            self.handle.write(b"\0" * tail_padding)
            self.padding_bytes += tail_padding
            self.position = final_size
        payload_bytes = self.position - self.payload_offset
        header = build_data_header(
            self.pack_id,
            build_id,
            self.payload_offset,
            payload_bytes,
            self.flags,
        )
        self.handle.seek(0)
        self.handle.write(header)
        self.handle.flush()
        os.fsync(self.handle.fileno())
        self.handle.close()
        self.closed = True
        file_size = self.temp_path.stat().st_size
        if file_size != self.position:
            raise PackError(f"unexpected size for {self.name}")
        return PackRecord(
            payload_bytes=payload_bytes,
            file_size=file_size,
            name_offset=0,
            name_length=0,
            flags=self.flags,
            io_page_size=self.io_page_size,
        )

    def publish(self) -> None:
        if not self.closed:
            raise PackError("cannot publish an open pack")
        os.replace(self.temp_path, self.final_path)

    def abort(self) -> None:
        try:
            if not self.closed:
                self.handle.close()
        finally:
            self.closed = True
            try:
                self.temp_path.unlink()
            except FileNotFoundError:
                pass


class PackLayout:
    def __init__(self, config: BuildConfig, output_dir: Path) -> None:
        self.config = config
        self.output_dir = output_dir
        self.volumes: list[PackVolumeWriter] = []
        self.current: dict[tuple[str, int], PackVolumeWriter] = {}
        self.volume_numbers: dict[tuple[str, int], int] = {}
        self._names: set[str] = set()

    def _render_name(self, group: str, lane: int, volume: int, pack_id: int) -> str:
        try:
            name = self.config.pack_pattern.format(
                group=group,
                lane=lane,
                volume=volume,
                id=pack_id,
            )
        except (KeyError, ValueError) as exc:
            raise PackError(f"invalid pack_pattern: {self.config.pack_pattern!r}") from exc
        name = name.replace("\\", "/")
        # Default runtime root is /app0. Keep enough room for root, slash and NUL
        # in SCE_KERNEL_PATH_MAX (1024) even with multibyte UTF-8 names.
        if len(name.encode("utf-8")) > 1017:
            raise PackError("pack_pattern produced a name longer than the runtime path limit")
        if name in self._names:
            raise PackError(f"pack_pattern produced duplicate name: {name}")
        # safe_output_path performs traversal/absolute checks.
        safe_output_path(self.output_dir, name)
        self._names.add(name)
        return name

    def _new_volume(self, group: GroupConfig, lane: int, flags: int) -> PackVolumeWriter:
        pack_id = len(self.volumes)
        if pack_id > 0xFFFF:
            raise PackError("pack count exceeds uint16 format limit")
        key = (group.name, lane)
        volume_number = self.volume_numbers.get(key, 0)
        self.volume_numbers[key] = volume_number + 1
        name = self._render_name(group.name, lane, volume_number, pack_id)
        writer = PackVolumeWriter(
            pack_id=pack_id,
            name=name,
            output_dir=self.output_dir,
            payload_alignment=max(
                self.config.payload_alignment,
                group.io_page_size or self.config.io_page_size,
            ),
            chunk_alignment=self.config.chunk_alignment,
            io_page_size=group.io_page_size or self.config.io_page_size,
            group=group.name,
            lane=lane,
            volume=volume_number,
            max_pack_size=group.max_pack_size,
            flags=flags,
        )
        self.volumes.append(writer)
        self.current[key] = writer
        return writer

    def writer_for(
        self,
        group: GroupConfig,
        lane: int,
        stored_size: int,
        *,
        striped: bool,
        layout: str,
        extent_start: bool,
    ) -> PackVolumeWriter:
        key = (group.name, lane)
        writer = self.current.get(key)
        flags = PACK_FLAG_IO_PAGE_LAYOUT | (PACK_FLAG_STRIPED if striped else 0)
        if writer is None:
            writer = self._new_volume(group, lane, flags)
        if not writer.can_fit(
            stored_size, layout=layout, extent_start=extent_start
        ):
            writer = self._new_volume(group, lane, flags)
            if not writer.can_fit(
                stored_size, layout=layout, extent_start=True
            ):
                raise PackError(
                    f"one block ({stored_size} bytes) exceeds max pack size for group {group.name}"
                )
        if striped:
            writer.flags |= PACK_FLAG_STRIPED
        return writer

    def abort(self) -> None:
        for writer in self.volumes:
            writer.abort()


def _list_of_strings(value: object, key: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise PackError(f"{key} must be a string or list of strings")
    return tuple(value)


def _action(value: object) -> str:
    result = str(value).lower()
    if result not in ("compress", "store", "loose"):
        raise PackError(f"action must be compress, store or loose; got {result!r}")
    return result



def _layout(value: object) -> str:
    result = str(value).lower()
    if result not in ("auto", "random", "mixed", "streaming"):
        raise PackError(
            f"layout must be auto, random, mixed or streaming; got {result!r}"
        )
    return result

def _assignment(value: object) -> str:
    result = str(value).lower()
    if result not in ("balanced", "hash", "round_robin"):
        raise PackError(
            f"assignment must be balanced, hash or round_robin; got {result!r}"
        )
    return result


def _pack_output_glob(pattern: str) -> str:
    """Convert a format pattern into the glob used to exclude old outputs."""
    allowed = {"group", "lane", "volume", "id"}
    parts: list[str] = []
    try:
        parsed = list(Formatter().parse(pattern))
    except ValueError as exc:
        raise PackError(f"invalid pack_pattern: {pattern!r}") from exc
    for literal, field_name, _format_spec, _conversion in parsed:
        parts.append(literal)
        if field_name is not None:
            if field_name not in allowed:
                raise PackError(
                    f"pack_pattern uses unsupported field {field_name!r}; "
                    "allowed fields are group, lane, volume and id"
                )
            parts.append("*")
    result = "".join(parts).replace("\\", "/").lstrip("/")
    if not result:
        raise PackError("pack_pattern cannot be empty")
    # A concrete rendering catches absolute paths and traversal before any data
    # is written. The output glob itself may contain wildcard characters.
    try:
        rendered = pattern.format(group="g", lane=0, volume=0, id=0)
        safe_output_path(Path("."), rendered.replace("\\", "/"))
    except (KeyError, ValueError) as exc:
        raise PackError(f"unsafe or invalid pack_pattern: {pattern!r}") from exc
    return result


def load_config(path: Path | None) -> BuildConfig:
    raw: dict[str, object] = {}
    config_dir = Path.cwd()
    if path is not None:
        resolved_config = path.resolve()
        config_dir = resolved_config.parent
        with resolved_config.open("rb") as handle:
            parsed = tomllib.load(handle)
        if not isinstance(parsed, dict):
            raise PackError("configuration root must be a TOML table")
        raw = parsed

    def load_rule_pattern_files(value: object, field: str) -> tuple[str, ...]:
        names = _list_of_strings(value, field)
        patterns: list[str] = []
        for name in names:
            relative = Path(name)
            if relative.is_absolute():
                raise PackError(f"{field} entries must be relative to the TOML file")
            candidate = (config_dir / relative).resolve()
            try:
                inside = os.path.commonpath((str(config_dir), str(candidate))) == str(config_dir)
            except ValueError:
                inside = False
            if not inside:
                raise PackError(f"{field} entry escapes the TOML directory: {name}")
            try:
                patterns.extend(_load_pattern_file(candidate))
            except OSError as exc:
                raise PackError(f"cannot read {field} file {name}: {exc}") from exc
        return tuple(patterns)
    pack = raw.get("pack", {})
    if not isinstance(pack, dict):
        raise PackError("[pack] must be a table")

    runtime = raw.get("runtime")
    settings = None
    if runtime is not None:
        keys = {"decoded_cache_bytes", "physical_cache_bytes", "workers", "latency_reserve_workers"}
        if not isinstance(runtime, dict) or set(runtime) != keys:
            raise PackError("[runtime] requires exactly decoded_cache_bytes, physical_cache_bytes, workers, latency_reserve_workers")
        settings = RuntimeSettings(parse_size(runtime["decoded_cache_bytes"]),
                                   parse_size(runtime["physical_cache_bytes"]),
                                   runtime["workers"], runtime["latency_reserve_workers"])
        settings.validate()

    default_block = block_shift(pack.get("default_block_size", "64KiB"))
    io_page_size = parse_size(pack.get("io_page_size", "64KiB"))
    config = BuildConfig(
        runtime=settings,
        index_name=str(pack.get("index_name", DEFAULT_INDEX_NAME)),
        pack_pattern=str(pack.get("pack_pattern", DEFAULT_PACK_PATTERN)),
        default_action=_action(pack.get("default_action", "loose")),
        default_block_shift=default_block,
        io_page_size=io_page_size,
        payload_alignment=parse_size(
            pack.get("payload_alignment", io_page_size)
        ),
        chunk_alignment=parse_size(pack.get("chunk_alignment", "64B")),
        workers=int(pack.get("workers", max(1, min(8, os.cpu_count() or 1)))),
        compression_mode=str(pack.get("compression_mode", "hc")).lower(),
        compression_level=int(pack.get("compression_level", 12)),
        acceleration=int(pack.get("acceleration", 1)),
        min_savings_bytes=parse_size(pack.get("min_savings_bytes", 64)),
        min_savings_ratio=float(pack.get("min_savings_ratio", 0.01)),
        io_neutral_min_savings_bytes=parse_size(
            pack.get("io_neutral_min_savings_bytes", "8KiB")
        ),
        io_neutral_min_savings_ratio=float(
            pack.get("io_neutral_min_savings_ratio", 0.125)
        ),
        deduplicate=bool(pack.get("deduplicate", True)),
        deduplicate_scope=str(pack.get("deduplicate_scope", "lane")).lower(),
        deduplicate_streaming=bool(pack.get("deduplicate_streaming", False)),
        preserve_mtime=bool(pack.get("preserve_mtime", True)),
        validate_index_metadata=bool(pack.get("validate_index_metadata", True)),
        self_contained=bool(pack.get("self_contained", False)),
        required_packed=_list_of_strings(
            pack.get("required_packed", []), "pack.required_packed"
        ),
        auto_loose_large_files=bool(pack.get("auto_loose_large_files", True)),
        auto_loose_hot_files=bool(pack.get("auto_loose_hot_files", False)),
        auto_loose_min_file_size=parse_size(
            pack.get("auto_loose_min_file_size", "64MiB")
        ),
        auto_loose_sample_blocks=int(pack.get("auto_loose_sample_blocks", 32)),
        auto_loose_sample_bytes=parse_size(
            pack.get("auto_loose_sample_bytes", "16MiB")
        ),
        auto_loose_min_savings_ratio=float(
            pack.get("auto_loose_min_savings_ratio", 0.05)
        ),
        auto_loose_max_raw_ratio=float(
            pack.get("auto_loose_max_raw_ratio", 0.90)
        ),
    )
    if config.workers < 1 or config.workers > 256:
        raise PackError("workers must be between 1 and 256")
    if (
        config.io_page_size < (1 << MIN_IO_PAGE_SHIFT)
        or config.io_page_size & (config.io_page_size - 1)
        or config.io_page_size > (1 << MAX_IO_PAGE_SHIFT)
    ):
        raise PackError(
            "io_page_size must be a power of two between 4 KiB and 1 MiB"
        )
    if (
        config.payload_alignment < DATA_HEADER_SIZE
        or config.payload_alignment & (config.payload_alignment - 1)
        or config.payload_alignment > (1 << MAX_BLOCK_SHIFT)
    ):
        raise PackError(
            "payload_alignment must be a power of two between 64 B and 1 MiB; "
            "the writer automatically raises it to the selected io_page_size"
        )
    if (
        config.chunk_alignment < PHYSICAL_CHUNK_ALIGNMENT
        or config.chunk_alignment & (config.chunk_alignment - 1)
        or config.chunk_alignment > config.io_page_size
        or config.io_page_size % config.chunk_alignment
    ):
        raise PackError(
            "chunk_alignment must be a power of two between 64 B and io_page_size"
        )
    if config.compression_mode not in ("fast", "hc"):
        raise PackError("compression_mode must be fast or hc")
    if config.deduplicate_scope not in ("lane", "group"):
        raise PackError("deduplicate_scope must be lane or group")
    if not 1 <= config.compression_level <= 12:
        raise PackError("compression_level must be between 1 and 12")
    if config.acceleration < 1:
        raise PackError("acceleration must be at least 1")
    if not (0.0 <= config.min_savings_ratio < 1.0):
        raise PackError("min_savings_ratio must be in [0, 1)")
    if not (0.0 <= config.io_neutral_min_savings_ratio < 1.0):
        raise PackError("io_neutral_min_savings_ratio must be in [0, 1)")
    if config.auto_loose_sample_blocks < 1 or config.auto_loose_sample_blocks > 4096:
        raise PackError("auto_loose_sample_blocks must be between 1 and 4096")
    if config.auto_loose_sample_bytes < 1:
        raise PackError("auto_loose_sample_bytes must be at least 1 byte")
    if not (0.0 <= config.auto_loose_min_savings_ratio < 1.0):
        raise PackError("auto_loose_min_savings_ratio must be in [0, 1)")
    if not (0.0 <= config.auto_loose_max_raw_ratio <= 1.0):
        raise PackError("auto_loose_max_raw_ratio must be in [0, 1]")
    try:
        safe_output_path(Path("."), config.index_name.replace("\\", "/"))
    except ValueError as exc:
        raise PackError(f"unsafe index_name: {config.index_name!r}") from exc
    _pack_output_glob(config.pack_pattern)

    groups_raw = raw.get("groups", {})
    if groups_raw and not isinstance(groups_raw, dict):
        raise PackError("[groups] must be a table")
    groups: dict[str, GroupConfig] = {}
    if isinstance(groups_raw, dict):
        for name, value in groups_raw.items():
            if not isinstance(value, dict):
                raise PackError(f"[groups.{name}] must be a table")
            group = GroupConfig(
                name=name,
                pack_count=int(value.get("pack_count", 1)),
                assignment=_assignment(value.get("assignment", "balanced")),
                max_pack_size=parse_size(value.get("max_pack_size", 0)),
                stripe_large_files=bool(value.get("stripe_large_files", False)),
                stripe_threshold=parse_size(value.get("stripe_threshold", "256MiB")),
                stripe_group_blocks=int(value.get("stripe_group_blocks", 8)),
                io_page_size=parse_size(value.get("io_page_size", 0)),
            )
            if group.pack_count < 1 or group.pack_count > 0xFFFF:
                raise PackError(
                    f"groups.{name}.pack_count must be between 1 and 65535"
                )
            group_page = group.io_page_size or config.io_page_size
            if (
                group_page < (1 << MIN_IO_PAGE_SHIFT)
                or group_page > (1 << MAX_IO_PAGE_SHIFT)
                or group_page & (group_page - 1)
                or group_page % config.chunk_alignment
            ):
                raise PackError(
                    f"groups.{name}.io_page_size must be a power of two between "
                    "4 KiB and 1 MiB and a multiple of chunk_alignment"
                )
            minimum_payload_offset = align_up(
                DATA_HEADER_SIZE, max(config.payload_alignment, group_page)
            )
            minimum_volume_size = minimum_payload_offset + group_page
            if (
                group.max_pack_size
                and group.max_pack_size < minimum_volume_size
            ):
                raise PackError(
                    f"groups.{name}.max_pack_size must be at least one complete "
                    f"I/O page beyond the payload offset ({minimum_volume_size} bytes)"
                )
            if group.stripe_group_blocks < 1:
                raise PackError(f"groups.{name}.stripe_group_blocks must be at least 1")
            groups[name] = group
    if "default" not in groups:
        groups["default"] = GroupConfig(name="default")
    if len(groups) > 256:
        raise PackError("the binary format supports at most 256 packing groups")
    config.groups = groups

    rules_raw = raw.get("rule", [])
    if not isinstance(rules_raw, list):
        raise PackError("[[rule]] entries must form an array")
    rules: list[Rule] = []
    for index, value in enumerate(rules_raw):
        if not isinstance(value, dict):
            raise PackError(f"rule {index} must be a table")
        group = str(value.get("group", "default"))
        if group not in groups:
            raise PackError(f"rule {index} references unknown group {group!r}")
        shift = block_shift(value.get("block_size", 1 << default_block))
        include_from = load_rule_pattern_files(
            value.get("include_from", []), "include_from"
        )
        exclude_from = load_rule_pattern_files(
            value.get("exclude_from", []), "exclude_from"
        )
        include_default: object = [] if include_from else ["**"]
        include = tuple(
            _list_of_strings(value.get("include", include_default), "include")
        ) + include_from
        exclude = tuple(
            _list_of_strings(value.get("exclude", []), "exclude")
        ) + exclude_from
        rule = Rule(
            action=_action(value.get("action", "compress")),
            include=include,
            exclude=exclude,
            block_shift=shift,
            group=group,
            mode=str(value.get("compression_mode", config.compression_mode)).lower(),
            level=int(value.get("compression_level", config.compression_level)),
            acceleration=int(value.get("acceleration", config.acceleration)),
            min_savings_bytes=parse_size(
                value.get("min_savings_bytes", config.min_savings_bytes)
            ),
            min_savings_ratio=float(
                value.get("min_savings_ratio", config.min_savings_ratio)
            ),
            io_neutral_min_savings_bytes=parse_size(
                value.get(
                    "io_neutral_min_savings_bytes",
                    config.io_neutral_min_savings_bytes,
                )
            ),
            io_neutral_min_savings_ratio=float(
                value.get(
                    "io_neutral_min_savings_ratio",
                    config.io_neutral_min_savings_ratio,
                )
            ),
            layout=_layout(value.get("layout", "auto")),
            streaming=bool(value.get("streaming", False)),
            hot=bool(value.get("hot", False)),
            force_pack=bool(value.get("force_pack", False)),
        )
        if not rule.include:
            raise PackError(f"rule {index} include list cannot be empty")
        if rule.mode not in ("fast", "hc"):
            raise PackError(f"rule {index} compression_mode must be fast or hc")
        if not 1 <= rule.level <= 12:
            raise PackError(f"rule {index} compression_level must be between 1 and 12")
        if rule.acceleration < 1:
            raise PackError(f"rule {index} acceleration must be at least 1")
        if not (0.0 <= rule.min_savings_ratio < 1.0):
            raise PackError(f"rule {index} min_savings_ratio must be in [0, 1)")
        if not (0.0 <= rule.io_neutral_min_savings_ratio < 1.0):
            raise PackError(
                f"rule {index} io_neutral_min_savings_ratio must be in [0, 1)"
            )
        rules.append(rule)
    config.rules = rules
    return config


def _default_rule(config: BuildConfig) -> Rule:
    return Rule(
        action=config.default_action,
        block_shift=config.default_block_shift,
        mode=config.compression_mode,
        level=config.compression_level,
        acceleration=config.acceleration,
        min_savings_bytes=config.min_savings_bytes,
        min_savings_ratio=config.min_savings_ratio,
        io_neutral_min_savings_bytes=config.io_neutral_min_savings_bytes,
        io_neutral_min_savings_ratio=config.io_neutral_min_savings_ratio,
    )


def select_rule(config: BuildConfig, relative: str) -> Rule:
    selected = _default_rule(config)
    # Last matching rule wins. This permits broad rules followed by narrow
    # exceptions without duplicating every earlier include expression.
    for rule in config.rules:
        if rule.matches(relative):
            selected = rule
    return selected


def _load_pattern_file(path: Path | None) -> list[str]:
    if path is None:
        return []
    patterns: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            patterns.append(line)
    return patterns


def _source_path(root: Path, relative: str) -> Path:
    candidate = safe_output_path(root, relative)
    root_real = root.resolve()
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        # Some Windows virtual filesystems can stat and open regular files but
        # do not implement the final-path query used by pathlib.resolve().
        # Keep the fallback narrow and reject a final reparse point because its
        # target cannot be checked for escape from root without that query.
        if getattr(exc, "winerror", None) != 1:  # ERROR_INVALID_FUNCTION
            raise
        source_stat = candidate.lstat()
        if getattr(source_stat, "st_file_attributes", 0) & 0x400:
            raise PackError(
                f"source reparse point cannot be validated on this filesystem: {relative}"
            ) from exc
        resolved = Path(os.path.abspath(candidate))
    if os.path.commonpath((str(root_real), str(resolved))) != str(root_real):
        raise PackError(f"source symlink escapes root: {relative}")
    return candidate


def _assign_lanes(
    candidates: list[tuple[int, AmprIndexEntry, Path, str, Rule, int, int]],
    config: BuildConfig,
) -> dict[int, int]:
    by_group: dict[str, list[tuple[int, int, str]]] = {}
    for file_id, _entry, _source, relative, rule, size, _mtime in candidates:
        if rule.action == "loose":
            continue
        by_group.setdefault(rule.group, []).append((file_id, size, relative))
    result: dict[int, int] = {}
    for group_name, files in by_group.items():
        group = config.groups[group_name]
        if group.assignment == "balanced":
            loads = [0] * group.pack_count
            for file_id, size, relative in sorted(
                files, key=lambda item: (-item[1], item[2].lower(), item[0])
            ):
                lane = min(range(group.pack_count), key=lambda lane: (loads[lane], lane))
                result[file_id] = lane
                loads[lane] += size
        elif group.assignment == "hash":
            for file_id, _size, relative in files:
                result[file_id] = fnv1a64(ascii_fold_path_bytes(relative)) % group.pack_count
        else:
            for file_id, _size, _relative in files:
                result[file_id] = (file_id - 1) % group.pack_count
    return result


def plan_files(
    entries: Sequence[AmprIndexEntry],
    root: Path,
    config: BuildConfig,
    codec: Lz4Codec,
    stats: BuildStats,
    include_patterns: Sequence[str],
    exclude_patterns: Sequence[str],
    allow_missing: bool,
    progress: ProgressCallback | None = None,
) -> tuple[list[SelectedFile | None], list[str]]:
    candidates: list[tuple[int, AmprIndexEntry, Path, str, Rule, int, int]] = []
    warnings: list[str] = []
    index_name = config.index_name.replace("\\", "/").lstrip("/")
    pack_output_glob = _pack_output_glob(config.pack_pattern)
    for file_id, entry in enumerate(entries, 1):
        relative = asset_relative_path(entry.path)
        if progress is not None:
            progress(BuildProgress("planning", file_id - 1, len(entries), 0, 0, relative))
        rule = select_rule(config, relative)
        if include_patterns and not glob_matches(relative, include_patterns):
            rule = Rule(action="loose", block_shift=rule.block_shift)
        if exclude_patterns and glob_matches(relative, exclude_patterns):
            rule = Rule(action="loose", block_shift=rule.block_shift)
        # Never recursively consume an index or pack left by an earlier build,
        # including custom nested pack naming patterns.
        normalized_relative = relative.replace("\\", "/").lstrip("/")
        if (
            normalized_relative in (
                index_name,
                index_name + ".crc",
                index_name + ".runtime",
            )
            or glob_matches(normalized_relative, (pack_output_glob,))
        ):
            rule = Rule(action="loose", block_shift=rule.block_shift)
        source = root.joinpath(*Path(relative).parts)
        if rule.action == "loose":
            candidates.append((file_id, entry, source, relative, rule, entry.size, entry.mtime))
            continue
        try:
            source = _source_path(root, relative)
        except (FileNotFoundError, ValueError) as exc:
            if allow_missing:
                warnings.append(f"file id {file_id} left loose because source is missing: {relative}")
                rule = Rule(action="loose", block_shift=rule.block_shift)
                candidates.append((file_id, entry, source, relative, rule, entry.size, entry.mtime))
                continue
            raise PackError(f"source is missing or unsafe for file id {file_id}: {relative}") from exc
        stat = source.stat()
        if not source.is_file():
            raise PackError(f"source is not a regular file: {relative}")
        if config.validate_index_metadata and stat.st_size != entry.size:
            raise PackError(
                f"AMPRIDX3 size mismatch for {relative}: index={entry.size}, disk={stat.st_size}"
            )
        candidate = SelectedFile(
            file_id=file_id,
            index_entry=entry,
            source=source,
            relative=relative,
            rule=rule,
            size=stat.st_size,
            mtime=int(stat.st_mtime),
            lane=0,
        )
        group = config.groups[rule.group]
        auto_loose = _auto_loose_decision(
            candidate,
            config,
            codec,
            group.io_page_size or config.io_page_size,
        )
        stats.auto_loose_sampled_bytes += auto_loose.sampled_bytes
        if auto_loose.use_loose:
            if config.self_contained:
                warnings.append(
                    "self-contained: auto-loose suppressed for "
                    f"{relative} size={candidate.size} "
                    f"sampled={auto_loose.sampled_bytes} "
                    f"saving={auto_loose.savings_ratio:.2%} "
                    f"rawBlocks={auto_loose.raw_ratio:.2%}; "
                    "incompressible blocks will be stored RAW"
                )
            else:
                stats.files_auto_loose += 1
                stats.auto_loose_logical_bytes += candidate.size
                warnings.append(
                    "auto-loose: "
                    f"{relative} size={candidate.size} "
                    f"sampled={auto_loose.sampled_bytes} "
                    f"saving={auto_loose.savings_ratio:.2%} "
                    f"rawBlocks={auto_loose.raw_ratio:.2%}; "
                    "use force_pack=true or self_contained=true to override"
                )
                rule = replace(
                    rule,
                    action="loose",
                    hot=False,
                    streaming=False,
                    layout="mixed",
                )
        candidates.append(
            (file_id, entry, source, relative, rule, stat.st_size, int(stat.st_mtime))
        )
    lanes = _assign_lanes(candidates, config)
    result: list[SelectedFile | None] = [None] * len(entries)
    for file_id, entry, source, relative, rule, size, mtime in candidates:
        result[file_id - 1] = SelectedFile(
            file_id=file_id,
            index_entry=entry,
            source=source,
            relative=relative,
            rule=rule,
            size=size,
            mtime=mtime,
            lane=lanes.get(file_id, 0),
        )
    if config.required_packed:
        missing_required = [
            item.relative
            for item in result
            if item is not None
            and glob_matches(item.relative, config.required_packed)
            and item.rule.action == "loose"
        ]
        if missing_required:
            preview = ", ".join(missing_required[:8])
            suffix = "" if len(missing_required) <= 8 else f" (+{len(missing_required) - 8} more)"
            raise PackError(
                "required_packed matched files that would remain loose: "
                f"{preview}{suffix}"
            )
    if progress is not None:
        progress(BuildProgress("planning", len(entries), len(entries), 0, 0))
    return result, warnings


def _compress_block(
    codec: Lz4Codec,
    raw: bytes,
    rule: Rule,
    io_page_size: int,
) -> CompressedBlock:
    raw_crc = crc32(raw)
    fingerprint = struct.pack("<IQ", raw_crc, len(raw)) + __import__("hashlib").blake2b(
        raw, digest_size=16
    ).digest()
    if rule.action == "store":
        return CompressedBlock(raw, raw, CHUNK_CODEC_RAW, raw_crc, raw_crc, fingerprint)
    compressed = codec.compress(
        raw,
        mode=rule.mode,
        level=rule.level,
        acceleration=rule.acceleration,
    )
    saved = len(raw) - len(compressed)
    ratio = saved / len(raw) if raw else 0.0
    required_bytes = rule.min_savings_bytes
    required_ratio = rule.min_savings_ratio
    # For random/mixed data, an isolated cold read often costs one complete
    # filesystem I/O page whether the chunk stores 60 KiB or 64 KiB. Require a
    # stronger gain when compression does not reduce the chunk's page count.
    if rule.resolved_layout() != "streaming":
        raw_pages = (len(raw) + io_page_size - 1) // io_page_size
        compressed_pages = (len(compressed) + io_page_size - 1) // io_page_size
        if compressed_pages >= raw_pages:
            required_bytes = max(required_bytes, rule.io_neutral_min_savings_bytes)
            required_ratio = max(required_ratio, rule.io_neutral_min_savings_ratio)
    if saved < required_bytes or ratio < required_ratio:
        return CompressedBlock(raw, raw, CHUNK_CODEC_RAW, raw_crc, raw_crc, fingerprint)
    return CompressedBlock(
        raw,
        compressed,
        CHUNK_CODEC_LZ4,
        raw_crc,
        crc32(compressed),
        fingerprint,
    )


@dataclass(frozen=True)
class AutoLooseDecision:
    use_loose: bool
    sampled_bytes: int
    stored_bytes: int
    raw_blocks: int
    sampled_blocks: int

    @property
    def savings_ratio(self) -> float:
        if self.sampled_bytes == 0:
            return 0.0
        return 1.0 - self.stored_bytes / self.sampled_bytes

    @property
    def raw_ratio(self) -> float:
        if self.sampled_blocks == 0:
            return 0.0
        return self.raw_blocks / self.sampled_blocks


def _sample_block_indices(total_blocks: int, sample_blocks: int) -> tuple[int, ...]:
    if total_blocks <= 0 or sample_blocks <= 0:
        return ()
    if total_blocks <= sample_blocks:
        return tuple(range(total_blocks))
    if sample_blocks == 1:
        return (total_blocks // 2,)
    # Deterministic, extent-wide sampling. Using integer interpolation avoids
    # floating-point drift in the build id and always includes first/last data.
    indices = {
        (sample * (total_blocks - 1)) // (sample_blocks - 1)
        for sample in range(sample_blocks)
    }
    return tuple(sorted(indices))


def _auto_loose_decision(
    item: SelectedFile,
    config: BuildConfig,
    codec: Lz4Codec,
    io_page_size: int,
) -> AutoLooseDecision:
    rule = item.rule
    if (
        not config.auto_loose_large_files
        or rule.action != "compress"
        or rule.force_pack
        or (rule.hot and not config.auto_loose_hot_files)
        or item.size < config.auto_loose_min_file_size
        or item.size == 0
    ):
        return AutoLooseDecision(False, 0, 0, 0, 0)

    block_size = 1 << rule.block_shift
    total_blocks = (item.size + block_size - 1) // block_size
    byte_limited_blocks = max(1, config.auto_loose_sample_bytes // block_size)
    sample_count = min(config.auto_loose_sample_blocks, byte_limited_blocks)
    indices = _sample_block_indices(total_blocks, sample_count)
    sampled_bytes = 0
    stored_bytes = 0
    raw_blocks = 0
    with item.source.open("rb") as handle:
        before = os.fstat(handle.fileno())
        for block_index in indices:
            offset = block_index * block_size
            expected = min(block_size, item.size - offset)
            handle.seek(offset)
            raw = handle.read(expected)
            if len(raw) != expected:
                raise PackError(
                    f"source was truncated while sampling compression: {item.relative}"
                )
            block = _compress_block(codec, raw, rule, io_page_size)
            sampled_bytes += len(raw)
            stored_bytes += len(block.stored)
            raw_blocks += int(block.codec == CHUNK_CODEC_RAW)
        after = os.fstat(handle.fileno())
        if (
            after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
            or after.st_ino != before.st_ino
            or after.st_dev != before.st_dev
        ):
            raise PackError(
                f"source changed while sampling compression: {item.relative}"
            )

    decision = AutoLooseDecision(
        False, sampled_bytes, stored_bytes, raw_blocks, len(indices)
    )
    use_loose = (
        decision.savings_ratio < config.auto_loose_min_savings_ratio
        or decision.raw_ratio >= config.auto_loose_max_raw_ratio
    )
    return AutoLooseDecision(
        use_loose,
        sampled_bytes,
        stored_bytes,
        raw_blocks,
        len(indices),
    )


def _iter_compressed_blocks(
    handle: BinaryIO,
    size: int,
    block_size: int,
    executor: ThreadPoolExecutor,
    codec: Lz4Codec,
    rule: Rule,
    workers: int,
    io_page_size: int,
) -> Iterator[CompressedBlock]:
    pending: list[Future[CompressedBlock]] = []
    remaining = size
    window = max(2, workers * 2)
    while remaining or pending:
        while remaining and len(pending) < window:
            raw = handle.read(min(block_size, remaining))
            if not raw:
                raise PackError("source file was truncated while packing")
            remaining -= len(raw)
            pending.append(
                executor.submit(_compress_block, codec, raw, rule, io_page_size)
            )
        future = pending.pop(0)
        yield future.result()
    if handle.read(1):
        raise PackError("source file grew while packing")


def _canonical_config_bytes(config: BuildConfig) -> bytes:
    payload = {
        "tool_version": TOOL_VERSION,
        "index_name": config.index_name,
        "pack_pattern": config.pack_pattern,
        "default_action": config.default_action,
        "default_block_shift": config.default_block_shift,
        "io_page_size": config.io_page_size,
        "payload_alignment": config.payload_alignment,
        "chunk_alignment": config.chunk_alignment,
        "compression_mode": config.compression_mode,
        "compression_level": config.compression_level,
        "acceleration": config.acceleration,
        "min_savings_bytes": config.min_savings_bytes,
        "min_savings_ratio": config.min_savings_ratio,
        "io_neutral_min_savings_bytes": config.io_neutral_min_savings_bytes,
        "io_neutral_min_savings_ratio": config.io_neutral_min_savings_ratio,
        "deduplicate": config.deduplicate,
        "deduplicate_scope": config.deduplicate_scope,
        "deduplicate_streaming": config.deduplicate_streaming,
        "auto_loose_large_files": config.auto_loose_large_files,
        "auto_loose_hot_files": config.auto_loose_hot_files,
        "auto_loose_min_file_size": config.auto_loose_min_file_size,
        "auto_loose_sample_blocks": config.auto_loose_sample_blocks,
        "auto_loose_sample_bytes": config.auto_loose_sample_bytes,
        "auto_loose_min_savings_ratio": config.auto_loose_min_savings_ratio,
        "auto_loose_max_raw_ratio": config.auto_loose_max_raw_ratio,
        "groups": [asdict(config.groups[name]) for name in sorted(config.groups)],
        "rules": [asdict(rule) for rule in config.rules],
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _publish_transaction(
    layout: PackLayout,
    temp_index: Path,
    index_path: Path,
    temp_crc: Path,
    temp_runtime: Path | None = None,
) -> None:
    """Publish data volumes first and the matching index last, with rollback."""
    replacements: list[tuple[Path, Path | None]] = []
    try:
        for writer in layout.volumes:
            final_path = writer.final_path
            backup: Path | None = None
            if final_path.exists():
                backup = final_path.with_name(
                    f".{final_path.name}.backup-{os.getpid()}-{writer.pack_id}"
                )
                try:
                    backup.unlink()
                except FileNotFoundError:
                    pass
                os.replace(final_path, backup)
            replacements.append((final_path, backup))
            writer.publish()
        crc_path = chunk_crc_path(index_path)
        crc_backup = None
        if crc_path.exists():
            crc_backup = crc_path.with_name(f".{crc_path.name}.backup-{os.getpid()}")
            os.replace(crc_path, crc_backup)
        replacements.append((crc_path, crc_backup))
        os.replace(temp_crc, crc_path)
        runtime_path = Path(str(index_path) + ".runtime")
        runtime_backup = None
        if runtime_path.exists():
            runtime_backup = runtime_path.with_name(f".{runtime_path.name}.backup-{os.getpid()}")
            os.replace(runtime_path, runtime_backup)
        replacements.append((runtime_path, runtime_backup))
        if temp_runtime is not None:
            os.replace(temp_runtime, runtime_path)
        # An old index remains valid until every new data volume is in place.
        # The build id in both headers makes partial/stale combinations fail
        # closed even across a process crash.
        os.replace(temp_index, index_path)
    except BaseException:
        for final_path, backup in reversed(replacements):
            try:
                final_path.unlink()
            except FileNotFoundError:
                pass
            if backup is not None and backup.exists():
                os.replace(backup, final_path)
        raise
    else:
        for _final_path, backup in replacements:
            if backup is not None:
                try:
                    backup.unlink()
                except FileNotFoundError:
                    pass


def build_packs(
    *,
    root: Path,
    ampr_index: Path,
    output_dir: Path,
    config: BuildConfig,
    include_patterns: Sequence[str] = (),
    exclude_patterns: Sequence[str] = (),
    allow_missing: bool = False,
    progress: ProgressCallback | None = None,
) -> tuple[Path, BuildStats, list[str]]:
    root = root.resolve()
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    if progress is not None:
        progress(BuildProgress("reading-index", 0, 0, 0, 0, str(ampr_index)))
    entries = read_ampridx3(ampr_index)
    codec = Lz4Codec()
    stats = BuildStats(files_total=len(entries))
    selected, warnings = plan_files(
        entries,
        root,
        config,
        codec,
        stats,
        include_patterns,
        exclude_patterns,
        allow_missing,
        progress,
    )
    packed_items = [item for item in selected if item is not None and item.rule.action != "loose"]
    packed_files_total = len(packed_items)
    packed_bytes_total = sum(item.size for item in packed_items)
    packed_files_done = 0
    packed_bytes_done = 0
    if progress is not None:
        progress(BuildProgress("packing", 0, packed_files_total, 0, packed_bytes_total))
    layout = PackLayout(config, output_dir)
    strings = StringTable()
    files: list[FileRecord] = []
    chunks: list[ChunkRecord] = []
    chunk_crcs = array("I")
    dedupe: dict[tuple[str, int, bytes], ChunkRecord] = {}
    temp_index: Path | None = None
    temp_crc: Path | None = None
    temp_runtime: Path | None = None

    try:
        with ThreadPoolExecutor(max_workers=config.workers, thread_name_prefix="ampr-lz4") as executor:
            for item in selected:
                assert item is not None
                path = canonical_asset_path(item.index_entry.path)
                path_offset, path_length = strings.add(path)
                path_hash = asset_path_hash(path)
                if item.rule.action == "loose":
                    stats.loose_paths.append(item.relative)
                    files.append(
                        FileRecord(
                            path_hash=path_hash,
                            logical_size=item.index_entry.size,
                            mtime=item.index_entry.mtime,
                            first_chunk=0,
                            chunk_count=0,
                            path_offset=path_offset,
                            path_length=path_length,
                            flags=0,
                            block_shift=0,
                        )
                    )
                    stats.files_loose += 1
                    continue

                if progress is not None:
                    progress(BuildProgress(
                        "packing", packed_files_done, packed_files_total,
                        packed_bytes_done, packed_bytes_total, item.relative,
                    ))

                group = config.groups[item.rule.group]
                first_chunk = len(chunks)
                if first_chunk > 0xFFFFFFFF:
                    raise PackError("chunk count exceeds uint32 file-record limits")
                file_flags = FILE_FLAG_PACKED
                if item.rule.action == "store":
                    file_flags |= FILE_FLAG_STORE_ONLY
                layout_mode = item.rule.resolved_layout()
                if layout_mode == "streaming":
                    file_flags |= FILE_FLAG_STREAMING
                elif layout_mode == "random":
                    file_flags |= FILE_FLAG_RANDOM_ACCESS
                if item.rule.hot:
                    file_flags |= FILE_FLAG_HOT
                block_size = 1 << item.rule.block_shift
                striped = (
                    group.stripe_large_files
                    and group.pack_count > 1
                    and item.size >= group.stripe_threshold
                )
                chunk_count = 0
                with item.source.open("rb") as source_handle:
                    source_before = os.fstat(source_handle.fileno())
                    for chunk_index, block in enumerate(
                        _iter_compressed_blocks(
                            source_handle,
                            item.size,
                            block_size,
                            executor,
                            codec,
                            item.rule,
                            config.workers,
                            group.io_page_size or config.io_page_size,
                        )
                    ):
                        lane = item.lane
                        if striped:
                            stripe_group = chunk_index // group.stripe_group_blocks
                            lane = (item.lane + stripe_group) % group.pack_count
                        dedupe_domain = (
                            item.rule.group
                            if config.deduplicate_scope == "group"
                            else f"{item.rule.group}:{lane}"
                        )
                        physical_layout = (
                            "dense" if layout_mode == "streaming" else "isolated"
                        )
                        dedupe_key = (
                            dedupe_domain,
                            physical_layout,
                            block.codec,
                            block.raw_fingerprint,
                        )
                        allow_deduplicate = config.deduplicate and (
                            layout_mode != "streaming"
                            or config.deduplicate_streaming
                        )
                        prior = dedupe.get(dedupe_key) if allow_deduplicate else None
                        if prior is not None:
                            record = ChunkRecord(
                                offset=prior.offset,
                                stored_size=prior.stored_size,
                                raw_size=prior.raw_size,
                                pack_id=prior.pack_id,
                                codec=prior.codec,
                                flags=(
                                    CHUNK_FLAG_SHARED
                                    | (prior.flags & (CHUNK_FLAG_PAGE_CONTAINED | CHUNK_FLAG_PAGE_ALIGNED))
                                    | (
                                        CHUNK_FLAG_STREAMING
                                        if layout_mode == "streaming"
                                        else 0
                                    )
                                ),
                            )
                            stats.chunks_shared += 1
                        else:
                            # Only dense streaming extents need a page-aligned
                            # beginning. Random/mixed small files deliberately
                            # share an I/O page, while every individual chunk is
                            # still prevented from straddling a page boundary.
                            extent_start = layout_mode == "streaming" and (
                                chunk_index == 0
                                or (
                                    striped
                                    and chunk_index % group.stripe_group_blocks == 0
                                )
                            )
                            writer = layout.writer_for(
                                group,
                                lane,
                                len(block.stored),
                                striped=striped,
                                layout=layout_mode,
                                extent_start=extent_start,
                            )
                            offset, _padding, placement_flags = writer.write(
                                block.stored,
                                layout=layout_mode,
                                extent_start=extent_start,
                            )
                            chunk_flags = 0
                            if layout_mode == "streaming":
                                chunk_flags |= CHUNK_FLAG_STREAMING
                            chunk_flags |= placement_flags
                            page_safe = (
                                bool(placement_flags & CHUNK_FLAG_PAGE_CONTAINED)
                                if len(block.stored) <= writer.io_page_size
                                else bool(placement_flags & CHUNK_FLAG_PAGE_ALIGNED)
                            )
                            if layout_mode != "streaming" and not page_safe:
                                raise PackError(
                                    "non-streaming chunk was not placed page-safely"
                                )
                            record = ChunkRecord(
                                offset=offset,
                                stored_size=len(block.stored),
                                raw_size=len(block.raw),
                                pack_id=writer.pack_id,
                                codec=block.codec,
                                flags=chunk_flags,
                            )
                            if allow_deduplicate:
                                dedupe[dedupe_key] = record
                            stats.stored_bytes += len(block.stored)
                            if layout_mode == "streaming":
                                stats.dense_streaming_chunks += 1
                        page_safe = (
                            bool(record.flags & CHUNK_FLAG_PAGE_CONTAINED)
                            if record.stored_size <=
                            layout.volumes[record.pack_id].io_page_size
                            else bool(record.flags & CHUNK_FLAG_PAGE_ALIGNED)
                        )
                        if page_safe:
                            stats.io_page_safe_chunks += 1
                        chunks.append(record)
                        chunk_crcs.append(block.raw_crc)
                        chunk_count += 1
                        stats.chunks += 1
                        stats.logical_bytes += len(block.raw)
                        packed_bytes_done += len(block.raw)
                        if progress is not None:
                            progress(BuildProgress(
                                "packing", packed_files_done, packed_files_total,
                                packed_bytes_done, packed_bytes_total, item.relative,
                            ))
                        if record.codec == CHUNK_CODEC_LZ4:
                            stats.chunks_lz4 += 1
                        else:
                            stats.chunks_raw += 1
                    source_after = os.fstat(source_handle.fileno())
                    if (
                        source_after.st_size != source_before.st_size
                        or source_after.st_mtime_ns != source_before.st_mtime_ns
                        or source_after.st_ino != source_before.st_ino
                        or source_after.st_dev != source_before.st_dev
                    ):
                        raise PackError(
                            f"source changed while packing: {item.relative}"
                        )
                if chunk_count > 0xFFFFFFFF:
                    raise PackError("one file exceeds uint32 chunk-count limits")
                files.append(
                    FileRecord(
                        path_hash=path_hash,
                        logical_size=item.size,
                        mtime=item.mtime if config.preserve_mtime else item.index_entry.mtime,
                        first_chunk=first_chunk,
                        chunk_count=chunk_count,
                        path_offset=path_offset,
                        path_length=path_length,
                        flags=file_flags,
                        block_shift=item.rule.block_shift,
                        packing_class=sorted(config.groups).index(item.rule.group),
                    )
                )
                stats.files_packed += 1
                packed_files_done += 1
                if progress is not None:
                    progress(BuildProgress(
                        "packing", packed_files_done, packed_files_total,
                        packed_bytes_done, packed_bytes_total, item.relative,
                    ))

        # Add names before the deterministic build id is calculated. Pack sizes
        # and chunk placement are now final; only the build id/header CRC remain.
        if progress is not None:
            progress(BuildProgress(
                "finalizing", packed_files_done, packed_files_total,
                packed_bytes_done, packed_bytes_total,
            ))
        provisional_pack_records: list[PackRecord] = []
        for writer in layout.volumes:
            name_offset, name_length = strings.add(writer.name)
            provisional_pack_records.append(
                PackRecord(
                    payload_bytes=writer.projected_final_size() - writer.payload_offset,
                    file_size=writer.projected_final_size(),
                    name_offset=name_offset,
                    name_length=name_length,
                    flags=writer.flags,
                    io_page_size=writer.io_page_size,
                )
            )
        if len(chunks) > 0xFFFFFFFF:
            raise PackError("chunk count exceeds uint32 format limit")
        chunk_crc_payload = encode_chunk_crcs(chunk_crcs)
        build_id = deterministic_build_id(
            (
                _canonical_config_bytes(config),
                b"".join(record.pack() for record in files),
                b"".join(record.pack() for record in chunks),
                chunk_crc_payload,
                b"".join(record.pack() for record in provisional_pack_records),
                strings.bytes(),
            )
        )

        final_pack_records: list[PackRecord] = []
        for writer, provisional in zip(layout.volumes, provisional_pack_records):
            actual = writer.finalize(build_id)
            actual.name_offset = provisional.name_offset
            actual.name_length = provisional.name_length
            final_pack_records.append(actual)
            stats.padding_bytes += writer.padding_bytes
            stats.io_pages_touched += (
                actual.payload_bytes + writer.io_page_size - 1
            ) // writer.io_page_size

        index_data = build_manifest_bytes(
            build_id,
            files,
            chunks,
            final_pack_records,
            strings.bytes(),
        )
        index_path = safe_output_path(output_dir, config.index_name)
        index_path.parent.mkdir(parents=True, exist_ok=True)
        temp_index = index_path.with_name(f".{index_path.name}.tmp-{os.getpid()}")
        with temp_index.open("wb") as handle:
            handle.write(index_data)
            handle.flush()
            os.fsync(handle.fileno())
        temp_crc = temp_index.with_name(temp_index.name + ".crc")
        with temp_crc.open("wb") as handle:
            handle.write(
                build_chunk_crc_header(
                    build_id,
                    len(chunk_crcs),
                    crc32(chunk_crc_payload),
                )
            )
            handle.write(chunk_crc_payload)
            handle.flush()
            os.fsync(handle.fileno())
        if config.runtime is not None:
            temp_runtime = temp_index.with_name(temp_index.name + ".runtime")
            with temp_runtime.open("wb") as handle:
                handle.write(config.runtime.encode(build_id))
                handle.flush()
                os.fsync(handle.fileno())
        if progress is not None:
            progress(BuildProgress(
                "publishing", packed_files_done, packed_files_total,
                packed_bytes_done, packed_bytes_total,
            ))
        _publish_transaction(layout, temp_index, index_path, temp_crc, temp_runtime)
        temp_crc = None
        temp_runtime = None
        temp_index = None
        if progress is not None:
            progress(BuildProgress(
                "complete", packed_files_done, packed_files_total,
                packed_bytes_done, packed_bytes_total,
            ))
        return index_path, stats, warnings
    except BaseException:
        layout.abort()
        if temp_runtime is not None:
            temp_runtime.unlink(missing_ok=True)
        if temp_crc is not None:
            temp_crc.unlink(missing_ok=True)
        if temp_index is not None:
            try:
                temp_index.unlink()
            except FileNotFoundError:
                pass
        raise


class PackReader:
    def __init__(self, manifest: PackManifest) -> None:
        self.manifest = manifest
        try:
            self.chunk_crcs = load_chunk_crcs(
                chunk_crc_path(manifest.path),
                manifest.build_id,
                len(manifest.chunks),
            )
        except (OSError, ValueError) as exc:
            raise PackError(f"invalid or missing chunk CRC sidecar: {exc}") from exc
        self.handles: list[BinaryIO] = []
        self.payload_ranges: list[tuple[int, int]] = []
        base = manifest.path.parent
        try:
            for pack_id, record in enumerate(manifest.packs):
                name = manifest.pack_name(pack_id)
                path = safe_output_path(base, name)
                handle = path.open("rb")
                header = handle.read(DATA_HEADER_SIZE)
                _, _, payload_offset, payload_bytes, _ = validate_data_header(
                    header,
                    expected_pack_id=pack_id,
                    expected_build_id=manifest.build_id,
                    expected_flags=record.flags,
                )
                actual_size = path.stat().st_size
                if actual_size != record.file_size:
                    raise PackError(f"pack size mismatch: {name}")
                if payload_bytes != record.payload_bytes:
                    raise PackError(f"pack payload size mismatch: {name}")
                if payload_offset + payload_bytes != actual_size:
                    raise PackError(f"pack payload range mismatch: {name}")
                self.handles.append(handle)
                self.payload_ranges.append((payload_offset, payload_offset + payload_bytes))
        except BaseException:
            self.close()
            raise
        self.codec = Lz4Codec()

    def close(self) -> None:
        for handle in self.handles:
            handle.close()
        self.handles.clear()

    def __enter__(self) -> "PackReader":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def read_chunk(self, chunk_index: int, chunk: ChunkRecord) -> bytes:
        if chunk_index < 0 or chunk_index >= len(self.chunk_crcs):
            raise PackError("chunk CRC index is out of range")
        if chunk.pack_id >= len(self.handles):
            raise PackError("chunk references an invalid pack")
        begin, end = self.payload_ranges[chunk.pack_id]
        if chunk.offset < begin or chunk.offset + chunk.stored_size > end:
            raise PackError("chunk is outside pack payload")
        handle = self.handles[chunk.pack_id]
        handle.seek(chunk.offset)
        stored = handle.read(chunk.stored_size)
        if len(stored) != chunk.stored_size:
            raise PackError("chunk is truncated")
        if chunk.codec == CHUNK_CODEC_RAW:
            raw = stored
        elif chunk.codec == CHUNK_CODEC_LZ4:
            try:
                raw = self.codec.decompress(stored, chunk.raw_size)
            except Exception as exc:
                raise PackError("LZ4 chunk decompression failed") from exc
        else:
            raise PackError(f"unsupported chunk codec: {chunk.codec}")
        if len(raw) != chunk.raw_size or crc32(raw) != self.chunk_crcs[chunk_index]:
            raise PackError("raw chunk CRC/size mismatch")
        return raw

    def iter_file_data(self, file_id: int) -> Iterator[bytes]:
        if file_id <= 0 or file_id > len(self.manifest.files):
            raise PackError(f"invalid file id: {file_id}")
        record = self.manifest.files[file_id - 1]
        if not record.flags & FILE_FLAG_PACKED:
            raise PackError(f"file id {file_id} is loose and has no packed data")
        total = 0
        for index in range(record.chunk_count):
            chunk_index = record.first_chunk + index
            chunk = self.manifest.chunks[chunk_index]
            raw = self.read_chunk(chunk_index, chunk)
            total += len(raw)
            yield raw
        if total != record.logical_size:
            raise PackError(f"file id {file_id} logical size mismatch")


def _selected_file_ids(manifest: PackManifest, patterns: Sequence[str]) -> list[int]:
    selected: list[int] = []
    for file_id, record in enumerate(manifest.files, 1):
        path = manifest.file_path(file_id)
        relative = asset_relative_path(path)
        if patterns and not glob_matches(relative, patterns):
            continue
        selected.append(file_id)
    return selected


def verify_packs(index_path: Path, patterns: Sequence[str] = ()) -> dict[str, int]:
    manifest = load_manifest(index_path)
    read_runtime_settings(Path(str(index_path) + ".runtime"), manifest.build_id)
    ids = _selected_file_ids(manifest, patterns)
    physical_seen: dict[
        tuple[int, int, int], tuple[int, int, int]
    ] = {}
    verified_files = 0
    verified_chunks = 0
    verified_stored = 0
    verified_raw = 0
    with PackReader(manifest) as reader:
        for file_id in ids:
            record = manifest.files[file_id - 1]
            if not record.flags & FILE_FLAG_PACKED:
                continue
            total = 0
            for local in range(record.chunk_count):
                chunk_index = record.first_chunk + local
                chunk = manifest.chunks[chunk_index]
                physical_key = (chunk.pack_id, chunk.offset, chunk.stored_size)
                descriptor = (
                    chunk.codec,
                    chunk.raw_size,
                    reader.chunk_crcs[chunk_index],
                )
                prior = physical_seen.get(physical_key)
                if prior is not None:
                    if prior != descriptor:
                        raise PackError(
                            "one physical chunk has conflicting metadata"
                        )
                    total += chunk.raw_size
                    continue
                raw = reader.read_chunk(chunk_index, chunk)
                total += len(raw)
                physical_seen[physical_key] = descriptor
                verified_chunks += 1
                verified_stored += chunk.stored_size
                verified_raw += chunk.raw_size
            if total != record.logical_size:
                raise PackError(f"logical size mismatch for file id {file_id}")
            verified_files += 1
    return {
        "files": verified_files,
        "physical_chunks": verified_chunks,
        "stored_bytes": verified_stored,
        "raw_bytes": verified_raw,
    }



def verify_packs_against_root(
    index_path: Path,
    root: Path,
    patterns: Sequence[str] = (),
) -> dict[str, int]:
    """Reconstruct packed files and compare them byte-for-byte with root."""
    manifest = load_manifest(index_path)
    ids = _selected_file_ids(manifest, patterns)
    compared_files = 0
    compared_bytes = 0
    compared_chunks = 0
    root = root.resolve()
    with PackReader(manifest) as reader:
        for file_id in ids:
            record = manifest.files[file_id - 1]
            if not record.flags & FILE_FLAG_PACKED:
                continue
            relative = asset_relative_path(manifest.file_path(file_id))
            source_path = safe_output_path(root, relative)
            try:
                stat = source_path.stat()
            except FileNotFoundError as exc:
                raise PackError(
                    f"source file missing while comparing packed data: {relative}"
                ) from exc
            if stat.st_size != record.logical_size:
                raise PackError(
                    f"source size mismatch for {relative}: "
                    f"manifest={record.logical_size}, disk={stat.st_size}"
                )
            logical_offset = 0
            with source_path.open("rb") as source:
                for local, packed_raw in enumerate(reader.iter_file_data(file_id)):
                    source_raw = source.read(len(packed_raw))
                    if len(source_raw) != len(packed_raw):
                        raise PackError(
                            f"source truncated for {relative} at 0x{logical_offset:x}"
                        )
                    if source_raw != packed_raw:
                        mismatch = next(
                            i for i, (a, b) in enumerate(zip(source_raw, packed_raw))
                            if a != b
                        )
                        chunk = manifest.chunks[record.first_chunk + local]
                        raise PackError(
                            f"packed/source mismatch for {relative}: "
                            f"logical=0x{logical_offset + mismatch:x}, "
                            f"chunk={local}, pack={chunk.pack_id}, "
                            f"physical=0x{chunk.offset:x}, "
                            f"source=0x{source_raw[mismatch]:02x}, "
                            f"packed=0x{packed_raw[mismatch]:02x}"
                        )
                    logical_offset += len(packed_raw)
                    compared_bytes += len(packed_raw)
                    compared_chunks += 1
                if source.read(1):
                    raise PackError(f"source grew while comparing: {relative}")
            if logical_offset != record.logical_size:
                raise PackError(
                    f"reconstructed size mismatch for {relative}: "
                    f"expected={record.logical_size}, got={logical_offset}"
                )
            compared_files += 1
    return {
        "files": compared_files,
        "chunks": compared_chunks,
        "bytes": compared_bytes,
    }


_REMOVAL_PROTECTED_DIRECTORIES = {
    "mods",
    "save",
    "sce_module",
    "sce_sys",
    "system",
}
_REMOVAL_PROTECTED_NAMES = {
    "ampr_assets.index",
    "ampr_assets.index.crc",
    "ampr_assets.index.runtime",
    "ampr_emu.index",
    "eboot.bin",
    "nptitle.dat",
    "param.sfo",
}
_REMOVAL_PROTECTED_SUFFIXES = {".elf", ".prx", ".self", ".sprx"}


def _removal_path_is_protected(relative: str) -> bool:
    pure = PurePosixPath(relative)
    lowered = tuple(part.lower() for part in pure.parts)
    name = pure.name.lower()
    return (
        bool(lowered and lowered[0] in _REMOVAL_PROTECTED_DIRECTORIES)
        or name in _REMOVAL_PROTECTED_NAMES
        or PurePosixPath(name).suffix in _REMOVAL_PROTECTED_SUFFIXES
        or (name.startswith("ampr_assets-") and name.endswith(".pak"))
    )


def _validated_removal_source(
    root: Path,
    relative: str,
    expected_size: int,
    *,
    allow_missing: bool,
) -> Path | None:
    candidate = safe_output_path(root, relative)
    try:
        source_stat = candidate.lstat()
    except FileNotFoundError:
        if allow_missing:
            return None
        raise PackError(f"packed source is missing: {relative}")
    if stat.S_ISLNK(source_stat.st_mode) or (
        getattr(source_stat, "st_file_attributes", 0) & 0x400
    ):
        raise PackError(f"refusing to remove a symlink/reparse point: {relative}")
    if not stat.S_ISREG(source_stat.st_mode):
        raise PackError(f"packed source is not a regular file: {relative}")
    resolved = candidate.resolve(strict=True)
    root_resolved = root.resolve(strict=True)
    try:
        inside = os.path.commonpath((str(root_resolved), str(resolved))) == str(root_resolved)
    except ValueError:
        inside = False
    if not inside:
        raise PackError(f"packed source resolves outside /app0: {relative}")
    if source_stat.st_size != expected_size:
        raise PackError(
            f"packed source size changed for {relative}: "
            f"manifest={expected_size}, disk={source_stat.st_size}"
        )
    return candidate


def packed_source_removal_plan(index_path: Path, root: Path) -> dict[str, object]:
    """Return the exact safe source set selected as PACK by a manifest."""
    manifest = load_manifest(index_path)
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise PackError(f"source root is not a directory: {root}")
    paths: list[str] = []
    present_bytes = 0
    missing = 0
    for file_id, record in enumerate(manifest.files, 1):
        if not record.flags & FILE_FLAG_PACKED:
            continue
        relative = asset_relative_path(manifest.file_path(file_id))
        if _removal_path_is_protected(relative):
            raise PackError(
                f"manifest marks a protected game/runtime file as packed: {relative}"
            )
        candidate = _validated_removal_source(
            root, relative, record.logical_size, allow_missing=True
        )
        paths.append(relative)
        if candidate is None:
            missing += 1
        else:
            present_bytes += record.logical_size
    return {
        "files": len(paths),
        "present_files": len(paths) - missing,
        "missing_files": missing,
        "bytes": present_bytes,
        "paths": paths,
    }


def remove_packed_sources(
    index_path: Path,
    root: Path,
    *,
    remove_empty_dirs: bool = False,
) -> dict[str, object]:
    """Verify and permanently remove source files represented by PACK records."""
    initial = packed_source_removal_plan(index_path, root)
    if initial["missing_files"]:
        raise PackError(
            f"cannot verify before removal: {initial['missing_files']} packed source files are missing"
        )
    # Validate both the pack payload and every source byte immediately before
    # the irreversible phase.  Offline verification does not establish that a
    # title uses no unhooked access path; the caller must make that decision.
    verify_packs(index_path)
    verify_packs_against_root(index_path, root)

    manifest = load_manifest(index_path)
    root = root.resolve(strict=True)
    candidates: list[tuple[Path, str, int]] = []
    for file_id, record in enumerate(manifest.files, 1):
        if not record.flags & FILE_FLAG_PACKED:
            continue
        relative = asset_relative_path(manifest.file_path(file_id))
        if _removal_path_is_protected(relative):
            raise PackError(f"refusing to remove protected path: {relative}")
        candidate = _validated_removal_source(
            root, relative, record.logical_size, allow_missing=False
        )
        assert candidate is not None
        candidates.append((candidate, relative, record.logical_size))

    removed_bytes = 0
    parent_dirs: set[Path] = set()
    for candidate, _relative, logical_size in candidates:
        candidate.unlink()
        removed_bytes += logical_size
        parent_dirs.add(candidate.parent)

    removed_dirs = 0
    if remove_empty_dirs:
        expanded: set[Path] = set()
        for directory in parent_dirs:
            current = directory
            while current != root:
                expanded.add(current)
                current = current.parent
        for directory in sorted(expanded, key=lambda item: len(item.parts), reverse=True):
            try:
                directory.rmdir()
                removed_dirs += 1
            except OSError:
                # Non-empty directories and directories concurrently reused by
                # the caller are deliberately retained.
                pass
    return {
        "files": len(candidates),
        "bytes": removed_bytes,
        "directories": removed_dirs,
        "verified": True,
    }


def extract_packs(
    index_path: Path,
    output_dir: Path,
    patterns: Sequence[str] = (),
    overwrite: bool = False,
    preserve_mtime: bool = True,
) -> dict[str, int]:
    manifest = load_manifest(index_path)
    ids = _selected_file_ids(manifest, patterns)
    output_dir.mkdir(parents=True, exist_ok=True)
    extracted = 0
    bytes_written = 0
    with PackReader(manifest) as reader:
        for file_id in ids:
            record = manifest.files[file_id - 1]
            if not record.flags & FILE_FLAG_PACKED:
                continue
            relative = asset_relative_path(manifest.file_path(file_id))
            destination = safe_output_path(output_dir, relative)
            destination.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists() and not overwrite:
                raise PackError(f"destination exists: {destination}")
            temp = destination.with_name(f".{destination.name}.tmp-{os.getpid()}")
            try:
                with temp.open("wb") as handle:
                    for raw in reader.iter_file_data(file_id):
                        handle.write(raw)
                        bytes_written += len(raw)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temp, destination)
                if preserve_mtime:
                    os.utime(destination, (record.mtime, record.mtime))
                extracted += 1
            finally:
                try:
                    temp.unlink()
                except FileNotFoundError:
                    pass
    return {"files": extracted, "bytes": bytes_written}


def list_manifest(index_path: Path, patterns: Sequence[str] = ()) -> list[dict[str, object]]:
    manifest = load_manifest(index_path)
    result: list[dict[str, object]] = []
    for file_id in _selected_file_ids(manifest, patterns):
        record = manifest.files[file_id - 1]
        stored = 0
        codecs: set[str] = set()
        pack_ids: set[int] = set()
        for local in range(record.chunk_count):
            chunk = manifest.chunks[record.first_chunk + local]
            stored += chunk.stored_size
            codecs.add("lz4" if chunk.codec == CHUNK_CODEC_LZ4 else "raw")
            pack_ids.add(chunk.pack_id)
        packed = bool(record.flags & FILE_FLAG_PACKED)
        if not packed:
            layout = "loose"
        elif record.flags & FILE_FLAG_STREAMING:
            layout = "streaming"
        elif record.flags & FILE_FLAG_RANDOM_ACCESS:
            layout = "random"
        else:
            layout = "mixed"
        result.append(
            {
                "file_id": file_id,
                "path": manifest.file_path(file_id),
                "packed": packed,
                "logical_size": record.logical_size,
                "stored_size": stored,
                "block_size": (1 << record.block_shift) if record.block_shift else 0,
                "chunks": record.chunk_count,
                "codecs": sorted(codecs),
                "packs": sorted(pack_ids),
                "io_page_sizes": sorted(
                    {manifest.packs[pack_id].io_page_size for pack_id in pack_ids}
                ),
                "layout": layout,
                "streaming": bool(record.flags & FILE_FLAG_STREAMING),
                "random_access": bool(record.flags & FILE_FLAG_RANDOM_ACCESS),
                "hot": bool(record.flags & FILE_FLAG_HOT),
            }
        )
    return result


def _print_json(value: object) -> None:
    print(json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True))


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build and manage seekable AMPR LZ4 asset packs"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {TOOL_VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    pack = sub.add_parser("pack", help="build pack index and data volumes")
    pack.add_argument("--root", type=Path, required=True, help="deployed /app0 directory")
    pack.add_argument("--ampr-index", type=Path, required=True, help="AMPRIDX3 file")
    pack.add_argument("--output", type=Path, required=True, help="output directory")
    pack.add_argument("--config", type=Path, help="TOML pack configuration")
    pack.add_argument("--include", action="append", default=[], help="additional include glob")
    pack.add_argument("--exclude", action="append", default=[], help="force-loose glob")
    pack.add_argument("--include-from", type=Path, help="newline-delimited include globs")
    pack.add_argument("--exclude-from", type=Path, help="newline-delimited exclude globs")
    pack.add_argument("--workers", type=int, help="compression workers")
    pack.add_argument(
        "--self-contained", action="store_true",
        help="do not auto-loose explicitly packed files; store incompressible blocks RAW"
    )
    pack.add_argument(
        "--require-packed", action="append", default=[], metavar="GLOB",
        help="fail if a matching logical file would remain loose (repeatable)"
    )
    pack.add_argument("--allow-missing", action="store_true", help="leave missing selected files loose")
    pack.add_argument(
        "--no-progress",
        action="store_true",
        help="suppress build progress on stderr; final JSON still goes to stdout",
    )

    unpack = sub.add_parser("unpack", help="extract packed files")
    unpack.add_argument("--index", type=Path, required=True)
    unpack.add_argument("--output", type=Path, required=True)
    unpack.add_argument("--file", action="append", default=[], help="file glob")
    unpack.add_argument("--overwrite", action="store_true")
    unpack.add_argument("--no-preserve-mtime", action="store_true")

    verify = sub.add_parser("verify", help="validate every selected packed block")
    verify.add_argument("--index", type=Path, required=True)
    verify.add_argument("--file", action="append", default=[], help="file glob")
    verify.add_argument(
        "--root", type=Path,
        help="also reconstruct packed files and compare byte-for-byte with this /app0 root",
    )

    remove_sources = sub.add_parser(
        "remove-packed-sources",
        help="verify, then remove local /app0 sources represented by PACK records",
    )
    remove_sources.add_argument("--index", type=Path, required=True)
    remove_sources.add_argument("--root", type=Path, required=True)
    remove_sources.add_argument(
        "--confirm",
        action="store_true",
        help="perform permanent removal; without it, print a read-only plan",
    )
    remove_sources.add_argument(
        "--remove-empty-dirs",
        action="store_true",
        help="remove directories left empty by source removal, never the /app0 root",
    )

    listing = sub.add_parser("list", help="list logical files and placement")
    listing.add_argument("--index", type=Path, required=True)
    listing.add_argument("--file", action="append", default=[], help="file glob")
    listing.add_argument("--json", action="store_true")

    inspect = sub.add_parser("inspect", help="show manifest-level summary")
    inspect.add_argument("--index", type=Path, required=True)
    runtime = sub.add_parser("runtime-config", help="atomically update per-pack runtime settings without repacking")
    runtime.add_argument("--index", type=Path, required=True)
    runtime.add_argument("--config", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = create_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "pack":
            config = load_config(args.config)
            if args.workers is not None:
                if args.workers < 1 or args.workers > 256:
                    raise PackError("--workers must be between 1 and 256")
                config.workers = args.workers
            if args.self_contained:
                config.self_contained = True
            if args.require_packed:
                config.required_packed = tuple(config.required_packed) + tuple(args.require_packed)
            includes = list(args.include) + _load_pattern_file(args.include_from)
            excludes = list(args.exclude) + _load_pattern_file(args.exclude_from)
            index_path, stats, warnings = build_packs(
                root=args.root,
                ampr_index=args.ampr_index,
                output_dir=args.output,
                config=config,
                include_patterns=includes,
                exclude_patterns=excludes,
                allow_missing=args.allow_missing,
                progress=None if args.no_progress else ConsoleBuildProgress(),
            )
            result = asdict(stats)
            result["index"] = str(index_path)
            result["crc"] = str(chunk_crc_path(index_path))
            result["compression_ratio"] = (
                stats.stored_bytes / stats.logical_bytes if stats.logical_bytes else 1.0
            )
            result["warnings"] = warnings
            _print_json(result)
        elif args.command == "unpack":
            _print_json(
                extract_packs(
                    args.index,
                    args.output,
                    args.file,
                    args.overwrite,
                    not args.no_preserve_mtime,
                )
            )
        elif args.command == "verify":
            result = verify_packs(args.index, args.file)
            if args.root is not None:
                result["source_compare"] = verify_packs_against_root(
                    args.index, args.root, args.file
                )
            _print_json(result)
        elif args.command == "remove-packed-sources":
            if args.confirm:
                _print_json(
                    remove_packed_sources(
                        args.index,
                        args.root,
                        remove_empty_dirs=args.remove_empty_dirs,
                    )
                )
            else:
                result = packed_source_removal_plan(args.index, args.root)
                result["dry_run"] = True
                _print_json(result)
        elif args.command == "list":
            rows = list_manifest(args.index, args.file)
            if args.json:
                _print_json(rows)
            else:
                for row in rows:
                    print(
                        f"{row['file_id']:8d} "
                        f"{'PACK' if row['packed'] else 'LOOSE':5s} "
                        f"{row['logical_size']:12d} {row['stored_size']:12d} "
                        f"{row['block_size']:8d} {row['path']}"
                    )
        elif args.command == "runtime-config":
            manifest = load_manifest(args.index)
            settings = load_config(args.config).runtime
            if settings is None:
                raise PackError("configuration must contain [runtime]")
            destination = Path(str(args.index) + ".runtime")
            temporary = None
            try:
                with tempfile.NamedTemporaryFile(mode="wb", dir=destination.parent,
                                                 prefix=".runtime-", delete=False) as handle:
                    temporary = Path(handle.name)
                    handle.write(settings.encode(manifest.build_id))
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, destination)
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
            _print_json({"path": str(destination), "build_id": manifest.build_id.hex(),
                         "runtime": asdict(settings)})
        elif args.command == "inspect":
            manifest = load_manifest(args.index)
            settings = read_runtime_settings(Path(str(args.index) + ".runtime"), manifest.build_id)
            packed = sum(1 for record in manifest.files if record.flags & FILE_FLAG_PACKED)
            _print_json(
                {
                    "build_id": manifest.build_id.hex(),
                    "runtime": asdict(settings) if settings is not None else None,
                    "files": len(manifest.files),
                    "packed_files": packed,
                    "loose_files": len(manifest.files) - packed,
                    "chunks": len(manifest.chunks),
                    "packs": [
                        {
                            "id": pack_id,
                            "name": manifest.pack_name(pack_id),
                            "file_size": record.file_size,
                            "payload_bytes": record.payload_bytes,
                            "io_page_size": record.io_page_size,
                            "io_pages": record.file_size // record.io_page_size,
                            "flags": record.flags,
                        }
                        for pack_id, record in enumerate(manifest.packs)
                    ],
                }
            )
        return 0
    except (PackError, ValueError, OSError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
