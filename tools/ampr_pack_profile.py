#!/usr/bin/env python3
"""Generate AMPR asset-pack TOML profiles from APR command journals.

The profiler consumes the lossless ``AMPRCMD1`` submit journal together with
its matching ``AMPRIDX3`` file index.  It reconstructs logical APR reads,
measures per-file access patterns, evaluates supported block sizes, enforces a
resident pack-index budget, simulates the decoded cache, and writes a ready to
use ``ampr_pack.py`` TOML configuration plus an explainable report.

Examples::

    python tools/ampr_pack_profile.py generate game_trace \
        --output ampr_pack.auto.toml --report ampr_pack.auto.md

    python tools/ampr_pack_profile.py generate \
        --trace run1/ampr_commands.bin run1/ampr_emu.index \
        --trace run2/ampr_commands.bin run2/ampr_emu.index \
        --name my_game --output my_game.toml

    python tools/ampr_pack_profile.py batch adaptive.zip \
        --output-dir generated_profiles

The tool is intentionally conservative: files that were not observed remain
loose unless directory generalisation is explicitly requested.  Access traces
cannot reveal data entropy, so the generated profile normally uses ``compress``
with the packer's per-block RAW fallback.  Optional content sampling can turn
known incompressible files into ``store`` rules.
"""

from __future__ import annotations

import argparse
from array import array
import bisect
from concurrent.futures import ProcessPoolExecutor
from collections import Counter, OrderedDict, defaultdict
from dataclasses import asdict, dataclass, field
import hashlib
import heapq
import json
import math
import os
from pathlib import Path, PurePosixPath
import shutil
import statistics
import sys
import tempfile
import tomllib
from typing import Any, Iterable, Iterator, Mapping, MutableMapping, Sequence
import zipfile

from ampr_pack_format import Lz4Codec, parse_size
from parse_ampr_command_log import (
    COMMAND_LOG_HEADER,
    COMMAND_LOG_HEADER_SIZE,
    COMMAND_LOG_MAGIC,
    COMMAND_LOG_VERSION,
    IndexEntry,
    decode_command,
    fnv1a64,
    load_index,
)

TOOL_VERSION = "4.1"
CHUNK_RECORD_BYTES = 12
FILE_RECORD_BYTES = 48
PACK_RECORD_BYTES = 32
DEFAULT_IO_PAGE = 64 * 1024
DEFAULT_INDEX_BUDGET = 96 * 1024 * 1024
RUNTIME_PIPELINE_SLOTS = 32
RUNTIME_PIPELINE_IO_BYTES = 2 * 1024 * 1024
RUNTIME_WORKER_SCRATCH_BYTES = 1 * 1024 * 1024
RUNTIME_POST_CACHE_RESERVE_BYTES = 32 * 1024 * 1024
DEFAULT_CACHE_MAX_TOUCHES = 5_000_000
DEFAULT_BATCH_JOBS = min(4, max(1, (os.cpu_count() or 2) // 2))
DEFAULT_CACHE_CANDIDATES = (
    32 * 1024 * 1024,
    64 * 1024 * 1024,
    128 * 1024 * 1024,
    256 * 1024 * 1024,
    512 * 1024 * 1024,
)
BLOCK_SIZES = (
    16 * 1024,
    32 * 1024,
    64 * 1024,
    128 * 1024,
    256 * 1024,
    512 * 1024,
    1024 * 1024,
)
READ_NAMES = {
    "AprReadFile",
    "AprReadGather",
    "AprReadScatter",
    "AprReadGatherScatter",
}
KNOWN_LOOSE_BASENAMES = {
    "eboot.bin",
    "ampr_emu.index",
    "ampr_assets.index",
    "ampr_assets.index.crc",
    "ampr_assets.index.runtime",
    "param.sfo",
    "nptitle.dat",
}
KNOWN_LOOSE_SUFFIXES = {".prx", ".sprx", ".self", ".elf"}
KNOWN_STREAM_STORE_SUFFIXES = {
    ".bik",
    ".bk2",
    ".mp4",
    ".m4v",
    ".webm",
    ".m2v",
    ".mpg",
    ".mpeg",
    ".avi",
    ".wem",
    ".opus",
    ".ogg",
    ".mp3",
    ".aac",
    ".flac",
}
STANDARD_LOOSE_PATTERNS = (
    "sce_module/**",
    "system/**",
    "mods/**",
    "save/**",
    "**/*.prx",
    "**/*.sprx",
    "eboot.bin",
    "ampr_emu.index",
    "ampr_assets.index",
    "ampr_assets.index.crc",
    "ampr_assets.index.runtime",
    "ampr_assets-*.pak",
)


class ProfileError(RuntimeError):
    pass


@dataclass(frozen=True)
class TraceSpec:
    name: str
    commands: Path
    index: Path


@dataclass(frozen=True)
class ReadEvent:
    trace_ordinal: int
    sequence: int
    command_ordinal: int
    monotonic_ns: int
    priority: int
    path: str
    relative: str
    file_id: int
    file_size: int
    offset: int
    length: int

    @property
    def end(self) -> int:
        return self.offset + self.length

    @property
    def order_key(self) -> tuple[int, int, int]:
        return (self.trace_ordinal, self.sequence, self.command_ordinal)


@dataclass
class TraceSummary:
    name: str
    commands: str
    index: str
    command_sha256: str
    index_sha256: str
    records: int
    reads: int
    warnings: list[str] = field(default_factory=list)
    decode_errors: int = 0
    duration_ns: int = 0


@dataclass(frozen=True)
class CandidateMetrics:
    block_size: int
    touched_bytes: int
    total_block_touches: int
    unique_blocks: int
    amplification: float
    average_blocks_per_read: float
    repeat_ratio: float
    offset_alignment_ratio: float
    length_alignment_ratio: float
    metadata_bytes: int
    local_score: float


@dataclass
class FileMetrics:
    path: str
    relative: str
    file_size: int
    file_ids: set[int]
    trace_count: int
    events: list[ReadEvent]
    read_count: int
    requested_bytes: int
    unique_requested_bytes: int
    coverage_ratio: float
    p50: float
    p75: float
    p90: float
    p95: float
    p99: float
    min_read: int
    max_read: int
    tiny_4k_ratio: float
    small_16k_ratio: float
    small_64k_ratio: float
    large_256k_ratio: float
    exact_sequential_ratio: float
    near_sequential_ratio: float
    random_seek_ratio: float
    backward_seek_ratio: float
    overlap_ratio: float
    candidates: dict[int, CandidateMetrics] = field(default_factory=dict)
    confidence: float = 0.0
    confidence_label: str = "low"


@dataclass
class FileRecommendation:
    metrics: FileMetrics
    action: str
    layout: str
    block_size: int
    hot: bool
    group: str
    reason: str
    sampled_ratio: float | None = None
    sampled_bytes: int = 0

    @property
    def profile_key(self) -> tuple[str, str, int, bool, str]:
        return (self.action, self.layout, self.block_size, self.hot, self.group)

    @property
    def metadata_bytes(self) -> int:
        if self.action == "loose":
            return 0
        return math.ceil(self.metrics.file_size / self.block_size) * CHUNK_RECORD_BYTES


@dataclass
class CacheSimulation:
    capacity: int
    requested_bytes: int
    hit_bytes: int
    misses: int
    hits: int
    sampled_touches: int = 0
    total_touches: int = 0
    sampled_windows: int = 1

    @property
    def hit_ratio(self) -> float:
        return self.hit_bytes / self.requested_bytes if self.requested_bytes else 0.0


@dataclass
class ProfileOptions:
    name: str
    io_page_size: int = DEFAULT_IO_PAGE
    index_budget: int = DEFAULT_INDEX_BUDGET
    cache_candidates: tuple[int, ...] = DEFAULT_CACHE_CANDIDATES
    lanes: int = 0
    workers: int = 8
    runtime_workers: int = 0
    strategy: str = "balanced"
    pattern_mode: str = "exact"
    min_reads: int = 1
    min_requested_bytes: int = 1
    max_rule_files: int = 256
    # Exact include lists larger than this are written beside the TOML and
    # referenced through include_from. Zero keeps every path inline.
    externalize_paths: int = 128
    generalize_coverage: float = 0.80
    generalize_min_files: int = 4
    cache_simulation: bool = True
    cache_max_touches: int = DEFAULT_CACHE_MAX_TOUCHES
    content_root: Path | None = None
    sample_budget: int = 0
    sample_blocks_per_file: int = 4
    sample_mode: str = "hc"
    sample_level: int = 12
    sample_acceleration: int = 1


@dataclass
class ProfileResult:
    name: str
    traces: list[TraceSummary]
    files: list[FileMetrics]
    recommendations: list[FileRecommendation]
    index_entries: dict[str, IndexEntry]
    projected_index_bytes: int
    index_budget: int
    cache_simulations: list[CacheSimulation]
    recommended_cache_bytes: int
    recommended_physical_cache_bytes: int
    recommended_runtime_workers: int
    recommended_latency_reserve_workers: int
    recommended_pool_bytes: int
    warnings: list[str]
    groups: dict[str, dict[str, Any]]


@dataclass(frozen=True)
class RuleEmission:
    profile_key: tuple[str, str, int, bool, str]
    include: tuple[str, ...]
    comments: tuple[str, ...] = ()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_relative(path: str) -> str:
    value = path.replace("\\", "/")
    if value.lower().startswith("/app0/"):
        value = value[6:]
    elif value.lower() == "/app0":
        value = ""
    value = value.lstrip("/")
    parts = PurePosixPath(value).parts
    if any(part in ("", ".", "..") for part in parts):
        raise ProfileError(f"unsafe indexed path: {path!r}")
    return PurePosixPath(*parts).as_posix()


def _percentile(values: Sequence[int], pct: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return float(values[0])
    ordered = sorted(values)
    position = (len(ordered) - 1) * pct / 100.0
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(ordered[lower])
    fraction = position - lower
    return ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction


def _union_length(ranges: Iterable[tuple[int, int]]) -> int:
    total = 0
    current_start: int | None = None
    current_end: int | None = None
    for start, end in sorted(ranges):
        if end <= start:
            continue
        if current_start is None:
            current_start, current_end = start, end
            continue
        assert current_end is not None
        if start <= current_end:
            current_end = max(current_end, end)
        else:
            total += current_end - current_start
            current_start, current_end = start, end
    if current_start is not None and current_end is not None:
        total += current_end - current_start
    return total


def _merged_block_count(ranges: Iterable[tuple[int, int]]) -> int:
    return _union_length(ranges)


def _human_size(value: float | int) -> str:
    size = float(value)
    for suffix in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(size) < 1024.0 or suffix == "TiB":
            if suffix == "B":
                return f"{int(round(size))} B"
            return f"{size:.2f} {suffix}"
        size /= 1024.0
    return f"{size:.2f} TiB"


def _size_literal(value: int) -> str:
    for divisor, suffix in (
        (1024**3, "GiB"),
        (1024**2, "MiB"),
        (1024, "KiB"),
    ):
        if value and value % divisor == 0:
            return f"{value // divisor}{suffix}"
    return f"{value}B"


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def _parse_cache_candidates(value: str) -> tuple[int, ...]:
    result: list[int] = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        parsed = parse_size(item)
        if parsed <= 0:
            raise argparse.ArgumentTypeError("cache capacities must be positive")
        result.append(parsed)
    if not result:
        raise argparse.ArgumentTypeError("at least one cache capacity is required")
    return tuple(sorted(set(result)))


def discover_trace_pairs(root: Path) -> list[TraceSpec]:
    pairs: list[TraceSpec] = []
    if root.is_file():
        raise ProfileError(f"expected a directory, got file: {root}")
    direct_commands = root / "ampr_commands.bin"
    direct_index = root / "ampr_emu.index"
    if direct_commands.is_file() and direct_index.is_file():
        return [TraceSpec(root.name or "trace", direct_commands, direct_index)]
    for commands in sorted(root.rglob("ampr_commands.bin")):
        index = commands.with_name("ampr_emu.index")
        if index.is_file():
            relative_parent = commands.parent.relative_to(root)
            name = relative_parent.as_posix().replace("/", "-") or commands.parent.name
            pairs.append(TraceSpec(name, commands, index))
    return pairs


def _extract_trace_archive(path: Path, temp_root: Path) -> Path:
    if not zipfile.is_zipfile(path):
        raise ProfileError(f"unsupported archive (only ZIP is accepted): {path}")
    destination = temp_root / "traces"
    destination.mkdir(parents=True, exist_ok=True)
    wanted = {"ampr_commands.bin", "ampr_emu.index"}
    extracted = 0
    with zipfile.ZipFile(path) as archive:
        for member in archive.infolist():
            member_path = PurePosixPath(member.filename)
            if member_path.is_absolute() or ".." in member_path.parts:
                raise ProfileError(f"unsafe archive member: {member.filename!r}")
            if member.is_dir() or member_path.name not in wanted:
                # Real trace bundles commonly contain multi-gigabyte decoded
                # JSON/text logs.  The profiler needs only the lossless binary
                # journal and AMPRIDX3; skipping everything else makes batch
                # generation bounded by actual analysis rather than ZIP I/O.
                continue
            target = destination.joinpath(*member_path.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member, "r") as source, target.open("wb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
            extracted += 1
    if extracted == 0:
        raise ProfileError(f"archive contains no AMPR trace inputs: {path}")
    return destination


def _append_trace_warning(warnings: list[str], message: str, limit: int = 200) -> None:
    if len(warnings) < limit:
        warnings.append(message)
    elif len(warnings) == limit:
        warnings.append("additional trace warnings omitted")


def _stream_one_trace(
    spec: TraceSpec,
    trace_ordinal: int,
    index: Mapping[int, IndexEntry],
) -> tuple[list[ReadEvent], TraceSummary, dict[str, IndexEntry], list[str]]:
    """Decode one command journal without retaining records or command dicts.

    ``parse_ampr_command_log.py`` intentionally builds a complete annotated
    timeline.  That is useful for diagnostics but can consume more than a
    gigabyte for very chatty titles.  The profile generator needs only APR read
    commands, so this reader keeps one submit payload and seven gather/scatter
    states resident at a time.
    """

    events: list[ReadEvent] = []
    path_entries: dict[str, IndexEntry] = {}
    warnings: list[str] = []
    gather_state: dict[int, dict[str, Any]] = {}
    records = 0
    read_count = 0
    decode_errors = 0
    previous_sequence: int | None = None
    min_monotonic = 0
    max_monotonic = 0

    with spec.commands.open("rb") as handle:
        file_offset = 0
        while True:
            raw_header = handle.read(COMMAND_LOG_HEADER_SIZE)
            if not raw_header:
                break
            if len(raw_header) != COMMAND_LOG_HEADER_SIZE:
                _append_trace_warning(
                    warnings,
                    f"truncated header at 0x{file_offset:x}: "
                    f"{len(raw_header)}/{COMMAND_LOG_HEADER_SIZE}",
                )
                break
            (
                magic,
                version,
                header_bytes,
                record_bytes,
                sequence,
                _utc_ns,
                monotonic_ns,
                _submit_cookie,
                _source_address,
                payload_hash,
                payload_bytes,
                _source_capacity,
                command_count,
                priority,
                domain,
                _submit_mode,
                _submit_type,
                _flags,
            ) = COMMAND_LOG_HEADER.unpack(raw_header)
            if magic != COMMAND_LOG_MAGIC:
                raise ProfileError(
                    f"{spec.name}: invalid command-log magic at 0x{file_offset:x}"
                )
            if version != COMMAND_LOG_VERSION:
                raise ProfileError(
                    f"{spec.name}: unsupported command-log version {version}"
                )
            if header_bytes < COMMAND_LOG_HEADER_SIZE:
                raise ProfileError(
                    f"{spec.name}: invalid header size {header_bytes} at 0x{file_offset:x}"
                )
            if record_bytes < header_bytes or record_bytes - header_bytes != payload_bytes:
                raise ProfileError(
                    f"{spec.name}: inconsistent record sizes at 0x{file_offset:x}"
                )
            extra_bytes = header_bytes - COMMAND_LOG_HEADER_SIZE
            if extra_bytes:
                extra = handle.read(extra_bytes)
                if len(extra) != extra_bytes:
                    _append_trace_warning(warnings, "truncated extended header")
                    break
            payload = handle.read(payload_bytes)
            if len(payload) != payload_bytes:
                _append_trace_warning(
                    warnings,
                    f"truncated payload for seq={sequence}: {len(payload)}/{payload_bytes}",
                )
                break

            records += 1
            if previous_sequence is None:
                if sequence != 1:
                    _append_trace_warning(
                        warnings,
                        f"sequence starts at {sequence}, expected 1",
                    )
            elif sequence != previous_sequence + 1:
                _append_trace_warning(
                    warnings,
                    f"sequence gap/non-monotonic: previous={previous_sequence}, current={sequence}",
                )
            previous_sequence = sequence
            if fnv1a64(payload) != payload_hash:
                _append_trace_warning(
                    warnings,
                    f"payload hash mismatch for seq={sequence}",
                )
            if monotonic_ns:
                min_monotonic = monotonic_ns if min_monotonic == 0 else min(min_monotonic, monotonic_ns)
                max_monotonic = max(max_monotonic, monotonic_ns)

            if domain != 1:
                file_offset += record_bytes
                continue

            offset = 0
            ordinal = 0
            while offset < len(payload):
                try:
                    command = decode_command(payload, offset)
                except Exception as exc:
                    decode_errors += 1
                    _append_trace_warning(
                        warnings,
                        f"seq={sequence} decode error at 0x{offset:x}: {exc}",
                    )
                    break
                dwords = int(command.get("dwords", 0))
                command_bytes = dwords * 4
                if command_bytes <= 0 or offset + command_bytes > len(payload):
                    decode_errors += 1
                    _append_trace_warning(
                        warnings,
                        f"seq={sequence} decoder returned invalid size {command_bytes}",
                    )
                    break
                name = str(command.get("name", "Unknown"))

                def emit(
                    file_id: int,
                    file_read_offset: int,
                    length: int,
                ) -> None:
                    nonlocal read_count
                    entry = index.get(file_id)
                    if entry is None:
                        _append_trace_warning(
                            warnings,
                            f"fileId {file_id} absent from AMPRIDX3 at seq={sequence}",
                        )
                        return
                    try:
                        relative = _canonical_relative(entry.path)
                    except ProfileError as exc:
                        _append_trace_warning(warnings, str(exc))
                        return
                    if length <= 0 or file_read_offset < 0:
                        return
                    if file_read_offset >= entry.size:
                        _append_trace_warning(
                            warnings,
                            f"read beyond {relative}: offset=0x{file_read_offset:x} "
                            f"size=0x{entry.size:x}",
                        )
                        return
                    if length > entry.size - file_read_offset:
                        _append_trace_warning(
                            warnings,
                            f"clamped read for {relative}: offset=0x{file_read_offset:x} "
                            f"length=0x{length:x} size=0x{entry.size:x}",
                        )
                        length = entry.size - file_read_offset
                    path_entries.setdefault(relative, entry)
                    events.append(
                        ReadEvent(
                            trace_ordinal=trace_ordinal,
                            sequence=int(sequence),
                            command_ordinal=ordinal,
                            monotonic_ns=int(monotonic_ns),
                            priority=int(priority),
                            path=entry.path,
                            relative=relative,
                            file_id=file_id,
                            file_size=int(entry.size),
                            offset=int(file_read_offset),
                            length=int(length),
                        )
                    )
                    read_count += 1

                if name == "AprReadFile":
                    file_id = int(command["file_id"])
                    file_read_offset = int(command["file_offset"])
                    length = int(command["length"])
                    entry = index.get(file_id)
                    gather_state[int(priority)] = {
                        "file_id": file_id,
                        "next_file_offset": file_read_offset + length,
                        "file_size": int(entry.size) if entry is not None else 0,
                    }
                    emit(file_id, file_read_offset, length)
                elif name == "AprReadGather":
                    state = gather_state.get(int(priority))
                    if state is None:
                        _append_trace_warning(
                            warnings,
                            f"AprReadGather without active state at seq={sequence}",
                        )
                    else:
                        file_read_offset = int(command["file_offset"])
                        length = int(command["length"])
                        emit(int(state["file_id"]), file_read_offset, length)
                        state["next_file_offset"] = file_read_offset + length
                elif name == "AprReadScatter":
                    state = gather_state.get(int(priority))
                    if state is None:
                        _append_trace_warning(
                            warnings,
                            f"AprReadScatter without active state at seq={sequence}",
                        )
                    else:
                        file_read_offset = int(state["next_file_offset"])
                        length = int(command["length"])
                        emit(int(state["file_id"]), file_read_offset, length)
                        state["next_file_offset"] = file_read_offset + length
                elif name == "AprReadGatherScatter":
                    state = gather_state.get(int(priority))
                    if state is None:
                        _append_trace_warning(
                            warnings,
                            f"AprReadGatherScatter without active state at seq={sequence}",
                        )
                    else:
                        file_read_offset = int(command["file_offset"])
                        length = int(command["length"])
                        emit(int(state["file_id"]), file_read_offset, length)
                        state["next_file_offset"] = file_read_offset + length
                elif name == "AprResetGatherScatterState":
                    gather_state.pop(int(priority), None)

                offset += command_bytes
                ordinal += 1
            if command_count and ordinal != command_count:
                decode_errors += 1
                _append_trace_warning(
                    warnings,
                    f"seq={sequence} header command_count={command_count}, decoded={ordinal}",
                )
            file_offset += record_bytes

    summary = TraceSummary(
        name=spec.name,
        commands=str(spec.commands),
        index=str(spec.index),
        command_sha256=_sha256(spec.commands),
        index_sha256=_sha256(spec.index),
        records=records,
        reads=read_count,
        warnings=list(warnings),
        decode_errors=decode_errors,
        duration_ns=max_monotonic - min_monotonic if min_monotonic and max_monotonic >= min_monotonic else 0,
    )
    return events, summary, path_entries, warnings


def load_trace_events(
    traces: Sequence[TraceSpec],
) -> tuple[list[ReadEvent], list[TraceSummary], dict[str, IndexEntry], list[str]]:
    all_events: list[ReadEvent] = []
    summaries: list[TraceSummary] = []
    path_entries: dict[str, IndexEntry] = {}
    warnings: list[str] = []

    for trace_ordinal, spec in enumerate(traces):
        index = load_index(spec.index)
        events, summary, trace_entries, trace_warnings = _stream_one_trace(
            spec, trace_ordinal, index
        )
        all_events.extend(events)
        summaries.append(summary)
        for relative, entry in trace_entries.items():
            existing = path_entries.get(relative)
            if existing is not None and existing.size != entry.size:
                warnings.append(
                    f"{spec.name}: indexed size changed for {relative}: "
                    f"{existing.size} -> {entry.size}; using the larger entry"
                )
                if entry.size > existing.size:
                    path_entries[relative] = entry
            else:
                path_entries.setdefault(relative, entry)
        warnings.extend(f"{spec.name}: {warning}" for warning in trace_warnings)

    all_events.sort(key=lambda event: event.order_key)
    return all_events, summaries, path_entries, warnings


def _candidate_metrics(
    events: Sequence[ReadEvent],
    file_size: int,
    block_size: int,
    layout: str,
    randomness: float,
) -> CandidateMetrics:
    requested_bytes = sum(event.length for event in events)
    touched_bytes = 0
    total_touches = 0
    block_ranges: list[tuple[int, int]] = []
    offset_aligned = 0
    length_aligned = 0
    for event in events:
        first = event.offset // block_size
        last_exclusive = (event.end + block_size - 1) // block_size
        start = first * block_size
        end = min(last_exclusive * block_size, file_size)
        touched_bytes += max(0, end - start)
        total_touches += max(0, last_exclusive - first)
        block_ranges.append((first, last_exclusive))
        offset_aligned += int(event.offset % block_size == 0)
        length_aligned += int(event.length % block_size == 0)
    unique_blocks = _merged_block_count(block_ranges)
    amplification = touched_bytes / requested_bytes if requested_bytes else 1.0
    average_blocks = total_touches / len(events) if events else 0.0
    repeat_ratio = (
        max(0.0, 1.0 - unique_blocks / total_touches) if total_touches else 0.0
    )
    metadata_bytes = math.ceil(file_size / block_size) * CHUNK_RECORD_BYTES

    log_amp = math.log2(max(1.0, amplification))
    log_ops = math.log2(max(1.0, average_blocks))
    size_log = math.log2(block_size / (64 * 1024))
    if layout == "random":
        score = 3.8 * log_amp + 0.12 * log_ops
        if block_size > 64 * 1024:
            score += 0.55 * math.log2(block_size / (64 * 1024))
        if block_size < 16 * 1024:
            score += 10.0
    elif layout == "streaming":
        score = 0.65 * log_amp + 0.95 * log_ops
        if block_size < 128 * 1024:
            score += 0.35 * math.log2((128 * 1024) / block_size)
        if block_size > 512 * 1024:
            score += 0.15 * math.log2(block_size / (512 * 1024))
    else:
        score = 2.15 * log_amp + 0.38 * log_ops
        score += abs(size_log) * 0.06
        if block_size > 128 * 1024:
            score += 0.28 * math.log2(block_size / (128 * 1024))
        if block_size > 64 * 1024:
            score += randomness * 0.42 * math.log2(block_size / (64 * 1024))
        if block_size < 32 * 1024:
            score += 0.20 * math.log2((32 * 1024) / block_size)

    # A tiny absolute metadata term makes ties deterministic without replacing
    # the global budget pass that performs the real memory trade-off.
    score += (metadata_bytes / max(file_size, 1)) * 3.0
    return CandidateMetrics(
        block_size=block_size,
        touched_bytes=touched_bytes,
        total_block_touches=total_touches,
        unique_blocks=unique_blocks,
        amplification=amplification,
        average_blocks_per_read=average_blocks,
        repeat_ratio=repeat_ratio,
        offset_alignment_ratio=offset_aligned / len(events) if events else 0.0,
        length_alignment_ratio=length_aligned / len(events) if events else 0.0,
        metadata_bytes=metadata_bytes,
        local_score=score,
    )


def _classify_layout_preliminary(
    *,
    p50: float,
    p90: float,
    tiny_4k_ratio: float,
    small_16k_ratio: float,
    small_64k_ratio: float,
    large_256k_ratio: float,
    exact_sequential_ratio: float,
    near_sequential_ratio: float,
    random_seek_ratio: float,
    repeat_64k: float,
    read_count: int,
) -> str:
    sequential = exact_sequential_ratio + near_sequential_ratio
    micro_index = (
        p50 <= 256
        and read_count >= 64
        and (repeat_64k >= 0.10 or sequential >= 0.70)
    )
    if micro_index:
        return "random"
    if (
        p50 >= 64 * 1024
        and sequential >= 0.76
        and random_seek_ratio <= 0.20
        and repeat_64k <= 0.18
    ):
        return "streaming"
    if (
        p90 >= 256 * 1024
        and large_256k_ratio >= 0.65
        and sequential >= 0.86
        and repeat_64k <= 0.12
    ):
        return "streaming"
    if (
        tiny_4k_ratio >= 0.50
        or small_16k_ratio >= 0.70
        or (small_64k_ratio >= 0.82 and random_seek_ratio >= 0.30)
        or (repeat_64k >= 0.28 and p50 <= 64 * 1024)
    ):
        return "random"
    return "mixed"


def build_file_metrics(events: Sequence[ReadEvent]) -> list[FileMetrics]:
    grouped: dict[str, list[ReadEvent]] = defaultdict(list)
    for event in events:
        grouped[event.relative].append(event)

    results: list[FileMetrics] = []
    for relative, file_events in sorted(grouped.items()):
        file_events.sort(key=lambda event: event.order_key)
        lengths = [event.length for event in file_events]
        requested = sum(lengths)
        file_size = max(event.file_size for event in file_events)
        unique_requested = _union_length((event.offset, event.end) for event in file_events)

        transition_bytes = 0
        exact_bytes = 0
        near_bytes = 0
        random_bytes = 0
        backward_bytes = 0
        overlap_bytes = 0
        previous_by_trace: dict[int, ReadEvent] = {}
        for event in file_events:
            previous = previous_by_trace.get(event.trace_ordinal)
            previous_by_trace[event.trace_ordinal] = event
            if previous is None:
                continue
            weight = event.length
            transition_bytes += weight
            if event.offset == previous.end:
                exact_bytes += weight
                continue
            gap = event.offset - previous.end
            near_limit = max(DEFAULT_IO_PAGE, min(previous.length, 512 * 1024))
            if 0 <= gap <= near_limit:
                near_bytes += weight
            elif event.offset < previous.offset:
                backward_bytes += weight
                random_bytes += weight
            elif event.offset < previous.end:
                overlap_bytes += weight
            else:
                random_bytes += weight

        tiny_4k = sum(length for length in lengths if length <= 4 * 1024) / requested
        small_16k = sum(length for length in lengths if length <= 16 * 1024) / requested
        small_64k = sum(length for length in lengths if length <= 64 * 1024) / requested
        large_256k = sum(length for length in lengths if length >= 256 * 1024) / requested
        exact_ratio = exact_bytes / transition_bytes if transition_bytes else 0.0
        near_ratio = near_bytes / transition_bytes if transition_bytes else 0.0
        random_ratio = random_bytes / transition_bytes if transition_bytes else 0.0
        backward_ratio = backward_bytes / transition_bytes if transition_bytes else 0.0
        overlap_ratio = overlap_bytes / transition_bytes if transition_bytes else 0.0

        provisional_64 = _candidate_metrics(
            file_events, file_size, 64 * 1024, "mixed", random_ratio
        )
        layout = _classify_layout_preliminary(
            p50=_percentile(lengths, 50),
            p90=_percentile(lengths, 90),
            tiny_4k_ratio=tiny_4k,
            small_16k_ratio=small_16k,
            small_64k_ratio=small_64k,
            large_256k_ratio=large_256k,
            exact_sequential_ratio=exact_ratio,
            near_sequential_ratio=near_ratio,
            random_seek_ratio=random_ratio,
            repeat_64k=provisional_64.repeat_ratio,
            read_count=len(file_events),
        )
        candidates = {
            size: _candidate_metrics(
                file_events, file_size, size, layout, random_ratio
            )
            for size in BLOCK_SIZES
        }

        evidence_reads = min(1.0, math.log10(len(file_events) + 1) / 3.0)
        evidence_bytes = min(1.0, requested / (64 * 1024 * 1024))
        trace_count = len({event.trace_ordinal for event in file_events})
        multi_trace = min(1.0, max(0, trace_count - 1) / 2.0)
        confidence = 0.45 * evidence_reads + 0.35 * evidence_bytes + 0.20 * multi_trace
        if confidence >= 0.72:
            confidence_label = "high"
        elif confidence >= 0.42:
            confidence_label = "medium"
        else:
            confidence_label = "low"

        results.append(
            FileMetrics(
                path=file_events[0].path,
                relative=relative,
                file_size=file_size,
                file_ids={event.file_id for event in file_events},
                trace_count=trace_count,
                events=file_events,
                read_count=len(file_events),
                requested_bytes=requested,
                unique_requested_bytes=unique_requested,
                coverage_ratio=unique_requested / file_size if file_size else 0.0,
                p50=_percentile(lengths, 50),
                p75=_percentile(lengths, 75),
                p90=_percentile(lengths, 90),
                p95=_percentile(lengths, 95),
                p99=_percentile(lengths, 99),
                min_read=min(lengths),
                max_read=max(lengths),
                tiny_4k_ratio=tiny_4k,
                small_16k_ratio=small_16k,
                small_64k_ratio=small_64k,
                large_256k_ratio=large_256k,
                exact_sequential_ratio=exact_ratio,
                near_sequential_ratio=near_ratio,
                random_seek_ratio=random_ratio,
                backward_seek_ratio=backward_ratio,
                overlap_ratio=overlap_ratio,
                candidates=candidates,
                confidence=confidence,
                confidence_label=confidence_label,
            )
        )
    return results


def _known_action(relative: str, layout: str) -> str:
    path = PurePosixPath(relative)
    lower_name = path.name.lower()
    suffix = path.suffix.lower()
    if lower_name in KNOWN_LOOSE_BASENAMES or suffix in KNOWN_LOOSE_SUFFIXES:
        return "loose"
    if suffix in KNOWN_STREAM_STORE_SUFFIXES:
        return "store"
    return "compress"


def _initial_recommendations(
    files: Sequence[FileMetrics], options: ProfileOptions
) -> list[FileRecommendation]:
    if not files:
        return []
    read_counts = sorted(file.read_count for file in files)
    requested_sizes = sorted(file.requested_bytes for file in files)
    read_hot_threshold = max(32, int(_percentile(read_counts, 90)))
    byte_hot_threshold = max(16 * 1024 * 1024, int(_percentile(requested_sizes, 90)))

    recommendations: list[FileRecommendation] = []
    for metrics in files:
        if (
            metrics.read_count < options.min_reads
            or metrics.requested_bytes < options.min_requested_bytes
        ):
            continue
        layout = _classify_layout_preliminary(
            p50=metrics.p50,
            p90=metrics.p90,
            tiny_4k_ratio=metrics.tiny_4k_ratio,
            small_16k_ratio=metrics.small_16k_ratio,
            small_64k_ratio=metrics.small_64k_ratio,
            large_256k_ratio=metrics.large_256k_ratio,
            exact_sequential_ratio=metrics.exact_sequential_ratio,
            near_sequential_ratio=metrics.near_sequential_ratio,
            random_seek_ratio=metrics.random_seek_ratio,
            repeat_64k=metrics.candidates[64 * 1024].repeat_ratio,
            read_count=metrics.read_count,
        )
        action = _known_action(metrics.relative, layout)
        if action == "store":
            layout = "streaming"
        repeat_64k = metrics.candidates[64 * 1024].repeat_ratio
        hot = (
            layout != "streaming"
            and (
                (metrics.read_count >= 16 and repeat_64k >= 0.22)
                or metrics.read_count >= read_hot_threshold
                or (metrics.read_count >= 8 and metrics.requested_bytes >= byte_hot_threshold)
            )
        )

        allowed = list(BLOCK_SIZES)
        if layout == "random":
            allowed = [size for size in allowed if size <= 128 * 1024]
        elif layout == "mixed":
            allowed = [size for size in allowed if 32 * 1024 <= size <= 256 * 1024]
        else:
            allowed = [size for size in allowed if size >= 64 * 1024]

        selected = min(
            allowed,
            key=lambda size: (
                metrics.candidates[size].local_score,
                abs(math.log2(size / (64 * 1024))),
                size,
            ),
        )
        if metrics.p50 <= 256 and metrics.read_count >= 64:
            selected = 16 * 1024
            layout = "random"
            hot = True
        if action == "loose":
            group = "loose"
        elif action == "store" or layout == "streaming":
            group = "stream"
        elif layout == "random":
            group = "metadata"
        else:
            # A mixed archive can be cache-hot while still benefiting from the
            # bulk lane topology.  Do not move multi-gigabyte opaque containers
            # into the metadata group merely because their blocks repeat.
            group = "bulk"

        chosen = metrics.candidates[selected]
        reason = (
            f"{layout}; p50={_human_size(metrics.p50)}, "
            f"sequential={(metrics.exact_sequential_ratio + metrics.near_sequential_ratio):.0%}, "
            f"repeat64={metrics.candidates[64 * 1024].repeat_ratio:.0%}, "
            f"amp={chosen.amplification:.2f}x"
        )
        recommendations.append(
            FileRecommendation(
                metrics=metrics,
                action=action,
                layout=layout,
                block_size=selected,
                hot=hot,
                group=group,
                reason=reason,
            )
        )
    return recommendations


def _enforce_index_budget(
    recommendations: list[FileRecommendation], budget: int, strategy: str
) -> None:
    packed = [recommendation for recommendation in recommendations if recommendation.action != "loose"]
    if not packed:
        return

    strategy_weight = {
        "conservative": 1.35,
        "balanced": 1.0,
        "aggressive": 0.70,
    }[strategy]

    def total_metadata() -> int:
        return sum(recommendation.metadata_bytes for recommendation in packed)

    heap: list[tuple[float, int, int, int]] = []
    generations = [0] * len(packed)

    def push(index: int) -> None:
        recommendation = packed[index]
        try:
            current_pos = BLOCK_SIZES.index(recommendation.block_size)
        except ValueError:
            return
        if current_pos + 1 >= len(BLOCK_SIZES):
            return
        next_size = BLOCK_SIZES[current_pos + 1]
        current = recommendation.metrics.candidates[recommendation.block_size]
        next_candidate = recommendation.metrics.candidates[next_size]
        saved = current.metadata_bytes - next_candidate.metadata_bytes
        if saved <= 0:
            return
        score_cost = max(0.0, next_candidate.local_score - current.local_score)
        importance = 1.0
        if recommendation.hot:
            importance *= 2.5
        if recommendation.layout == "random":
            importance *= 1.8
        elif recommendation.layout == "streaming":
            importance *= 0.55
        importance *= 0.75 + 0.5 * recommendation.metrics.confidence
        ratio = score_cost * importance * strategy_weight / saved
        heapq.heappush(heap, (ratio, generations[index], index, next_size))

    for index in range(len(packed)):
        push(index)

    while total_metadata() > budget and heap:
        _ratio, generation, index, next_size = heapq.heappop(heap)
        if generation != generations[index]:
            continue
        recommendation = packed[index]
        if next_size <= recommendation.block_size:
            continue
        recommendation.block_size = next_size
        generations[index] += 1
        push(index)


def _sample_positions(file_size: int, block_size: int, count: int) -> list[int]:
    if file_size <= 0 or count <= 0:
        return []
    if file_size <= block_size:
        return [0]
    max_start = max(0, file_size - block_size)
    if count == 1:
        return [0]
    positions = {
        int(round(max_start * index / (count - 1)))
        for index in range(count)
    }
    return sorted(position - (position % block_size) for position in positions)


def sample_compressibility(
    recommendations: list[FileRecommendation], options: ProfileOptions, warnings: list[str]
) -> None:
    if options.content_root is None or options.sample_budget <= 0:
        return
    try:
        codec = Lz4Codec()
    except Exception as exc:  # pragma: no cover - environment dependent
        warnings.append(f"content sampling disabled: {exc}")
        return
    root = options.content_root.resolve()
    remaining = options.sample_budget
    ordered = sorted(
        (rec for rec in recommendations if rec.action == "compress"),
        key=lambda rec: (rec.metrics.requested_bytes, rec.metrics.read_count),
        reverse=True,
    )
    for recommendation in ordered:
        if remaining <= 0:
            break
        source = (root / recommendation.metrics.relative).resolve()
        try:
            source.relative_to(root)
        except ValueError:
            warnings.append(f"content sample escaped root: {source}")
            continue
        if not source.is_file():
            continue
        raw_total = 0
        stored_total = 0
        try:
            with source.open("rb") as handle:
                for position in _sample_positions(
                    recommendation.metrics.file_size,
                    recommendation.block_size,
                    options.sample_blocks_per_file,
                ):
                    if remaining <= 0:
                        break
                    length = min(recommendation.block_size, remaining)
                    handle.seek(position)
                    raw = handle.read(length)
                    if not raw:
                        continue
                    compressed = codec.compress(
                        raw,
                        mode=options.sample_mode,
                        level=options.sample_level,
                        acceleration=options.sample_acceleration,
                    )
                    raw_total += len(raw)
                    stored_total += min(len(raw), len(compressed))
                    remaining -= len(raw)
        except OSError as exc:
            warnings.append(f"cannot sample {recommendation.metrics.relative}: {exc}")
            continue
        if raw_total:
            ratio = stored_total / raw_total
            recommendation.sampled_ratio = ratio
            recommendation.sampled_bytes = raw_total
            if ratio >= 0.94:
                # Large already-compressed game archives should stay loose: a
                # second userspace container adds indirection without reducing
                # physical traffic. Small files may still benefit from one pack
                # FD even when their blocks remain RAW.
                if recommendation.metrics.file_size >= 64 * 1024 * 1024:
                    recommendation.action = "loose"
                    recommendation.hot = False
                    recommendation.reason += (
                        f"; sampled LZ4 ratio={ratio:.1%}, auto-loose"
                    )
                else:
                    recommendation.action = "store"
                    recommendation.layout = (
                        "streaming"
                        if recommendation.layout == "streaming"
                        else "mixed"
                    )
                    recommendation.group = (
                        "stream"
                        if recommendation.layout == "streaming"
                        else "bulk"
                    )
                    recommendation.hot = (
                        False
                        if recommendation.layout == "streaming"
                        else recommendation.hot
                    )
                    recommendation.reason += (
                        f"; sampled LZ4 ratio={ratio:.1%}, store"
                    )
            else:
                recommendation.reason += f"; sampled LZ4 ratio={ratio:.1%}"


def _estimate_index_bytes(
    recommendations: Sequence[FileRecommendation],
    pack_count: int,
    index_entries: Mapping[str, IndexEntry] | None = None,
) -> int:
    packed = [
        recommendation
        for recommendation in recommendations
        if recommendation.action != "loose"
    ]
    chunk_bytes = sum(recommendation.metadata_bytes for recommendation in packed)
    # AMPRPAK4 preserves one file record and one path for every AMPRIDX3 file ID,
    # including loose/unobserved files, so resolver IDs remain stable.
    if index_entries is not None:
        file_bytes = len(index_entries) * FILE_RECORD_BYTES
        string_bytes = sum(
            len(path.encode("utf-8")) + 1 for path in index_entries
        )
    else:
        file_bytes = len(recommendations) * FILE_RECORD_BYTES
        string_bytes = sum(
            len(rec.metrics.path.encode("utf-8")) + 1
            for rec in recommendations
        )
    pack_bytes = pack_count * PACK_RECORD_BYTES
    return chunk_bytes + file_bytes + pack_bytes + string_bytes + 4096


def _choose_lanes(recommendations: Sequence[FileRecommendation], requested: int) -> int:
    if requested > 0:
        return requested
    packed = [rec for rec in recommendations if rec.action != "loose"]
    total_size = sum(rec.metrics.file_size for rec in packed)
    file_count = len(packed)
    if file_count <= 1:
        return 1
    if total_size < 2 * 1024**3 and file_count < 64:
        return 2
    if total_size < 16 * 1024**3 and file_count < 1024:
        return 3
    return 4


def _build_groups(
    recommendations: Sequence[FileRecommendation], lanes: int
) -> dict[str, dict[str, Any]]:
    grouped: dict[str, list[FileRecommendation]] = defaultdict(list)
    for recommendation in recommendations:
        if recommendation.action != "loose":
            grouped[recommendation.group].append(recommendation)
    result: dict[str, dict[str, Any]] = {}
    for group_name in ("metadata", "bulk", "stream"):
        items = grouped.get(group_name, [])
        if not items:
            continue
        total_size = sum(item.metrics.file_size for item in items)
        if group_name == "bulk":
            pack_count = min(lanes, max(1, len(items)))
            max_pack_size = 16 * 1024**3
        elif group_name == "metadata":
            pack_count = min(max(1, min(lanes, 2 if total_size < 8 * 1024**3 else 4)), len(items))
            max_pack_size = 8 * 1024**3
        else:
            pack_count = min(max(1, min(lanes, 2)), len(items))
            max_pack_size = 16 * 1024**3
        result[group_name] = {
            "pack_count": pack_count,
            "assignment": "balanced",
            "max_pack_size": max_pack_size,
            "stripe_large_files": False,
        }
    return result


def _iter_block_overlaps(event: ReadEvent, block_size: int) -> Iterator[tuple[int, int, int]]:
    first = event.offset // block_size
    last = (event.end - 1) // block_size
    for block_index in range(first, last + 1):
        block_start = block_index * block_size
        block_end = min(block_start + block_size, event.file_size)
        overlap = max(0, min(event.end, block_end) - max(event.offset, block_start))
        if overlap:
            yield block_index, block_end - block_start, overlap


@dataclass
class _CacheAccessStream:
    keys: array
    raw_sizes: array
    overlaps: array
    hot: bytearray
    reset_before: bytearray
    total_touches: int
    sampled_windows: int


def _event_block_touch_count(event: ReadEvent, block_size: int) -> int:
    if event.length <= 0 or block_size <= 0:
        return 0
    return (event.end - 1) // block_size - event.offset // block_size + 1


def _build_cache_access_stream(
    events: Sequence[ReadEvent],
    recommendation_by_path: Mapping[str, FileRecommendation],
    max_touches: int,
) -> _CacheAccessStream:
    """Build one compact access stream shared by all cache capacities.

    Normal traces are simulated exactly.  When a journal would create more
    than ``max_touches`` block references, uniformly distributed contiguous
    windows are selected.  Each window keeps local ordering/reuse intact and
    starts with an empty cache, avoiding artificial hits between distant
    samples.  The report exposes both sampled and total touch counts.
    """

    eligible: list[tuple[ReadEvent, FileRecommendation, int]] = []
    cumulative_ends: list[int] = []
    total_touches = 0
    file_ordinals: dict[str, int] = {}
    for event in events:
        recommendation = recommendation_by_path.get(event.relative)
        if (
            recommendation is None
            or recommendation.action == "loose"
            or recommendation.layout == "streaming"
        ):
            continue
        touches = _event_block_touch_count(event, recommendation.block_size)
        if touches <= 0:
            continue
        if event.relative not in file_ordinals:
            file_ordinals[event.relative] = len(file_ordinals) + 1
        total_touches += touches
        eligible.append((event, recommendation, touches))
        cumulative_ends.append(total_touches)

    keys = array("Q")
    raw_sizes = array("I")
    overlaps = array("I")
    hot = bytearray()
    reset_before = bytearray()
    if not eligible:
        return _CacheAccessStream(
            keys, raw_sizes, overlaps, hot, reset_before, 0, 0
        )

    def append_slice(
        event: ReadEvent,
        recommendation: FileRecommendation,
        first_touch: int,
        touch_count: int,
        reset: bool,
    ) -> int:
        appended = 0
        file_ordinal = file_ordinals[event.relative]
        stop_touch = first_touch + touch_count
        for local_index, (block_index, raw_size, overlap) in enumerate(
            _iter_block_overlaps(event, recommendation.block_size)
        ):
            if local_index < first_touch:
                continue
            if local_index >= stop_touch:
                break
            if block_index >= (1 << 48):
                raise ProfileError(
                    f"cache simulation block index is too large: "
                    f"{event.relative} block={block_index}"
                )
            keys.append((file_ordinal << 48) | block_index)
            raw_sizes.append(raw_size)
            overlaps.append(overlap)
            hot.append(1 if recommendation.hot else 0)
            reset_before.append(1 if reset and appended == 0 else 0)
            appended += 1
        return appended

    if max_touches <= 0 or total_touches <= max_touches:
        first = True
        for event, recommendation, touches in eligible:
            append_slice(event, recommendation, 0, touches, first)
            first = False
        sampled_windows = 1
    else:
        # Sixty-four windows give stable coverage of long startup/gameplay
        # traces while preserving enough adjacent references to model cache
        # admission and reuse.  Very small caps use fewer, larger windows.
        window_count = min(64, max(1, max_touches // 4096))
        window_budget = max(1, max_touches // window_count)
        sampled_windows = 0
        for window_index in range(window_count):
            segment_start = (total_touches * window_index) // window_count
            segment_end = (total_touches * (window_index + 1)) // window_count
            segment_size = max(0, segment_end - segment_start)
            if segment_size == 0:
                continue
            budget = min(window_budget, segment_size)
            start_touch = segment_start + (segment_size - budget) // 2
            end_touch = start_touch + budget
            event_index = bisect.bisect_right(cumulative_ends, start_touch)
            window_first = True
            while event_index < len(eligible):
                event_end = cumulative_ends[event_index]
                event_start = (
                    cumulative_ends[event_index - 1]
                    if event_index != 0
                    else 0
                )
                if event_start >= end_touch:
                    break
                event, recommendation, touches = eligible[event_index]
                local_start = max(0, start_touch - event_start)
                local_end = min(touches, end_touch - event_start)
                if local_end > local_start:
                    appended = append_slice(
                        event,
                        recommendation,
                        local_start,
                        local_end - local_start,
                        window_first,
                    )
                    if appended:
                        window_first = False
                event_index += 1
            if not window_first:
                sampled_windows += 1

    return _CacheAccessStream(
        keys=keys,
        raw_sizes=raw_sizes,
        overlaps=overlaps,
        hot=hot,
        reset_before=reset_before,
        total_touches=total_touches,
        sampled_windows=sampled_windows,
    )


def simulate_cache(
    events: Sequence[ReadEvent],
    recommendation_by_path: Mapping[str, FileRecommendation],
    capacities: Sequence[int],
    max_touches: int = DEFAULT_CACHE_MAX_TOUCHES,
) -> list[CacheSimulation]:
    stream = _build_cache_access_stream(
        events, recommendation_by_path, max_touches
    )
    simulations: list[CacheSimulation] = []
    sampled_touches = len(stream.keys)
    for capacity in capacities:
        cache: OrderedDict[int, int] = OrderedDict()
        seen_once: set[int] = set()
        resident = 0
        requested = 0
        hit_bytes = 0
        hits = 0
        misses = 0
        for index in range(sampled_touches):
            if stream.reset_before[index]:
                cache.clear()
                seen_once.clear()
                resident = 0
            key = stream.keys[index]
            raw_size = stream.raw_sizes[index]
            overlap = stream.overlaps[index]
            requested += overlap
            cached_size = cache.pop(key, None)
            if cached_size is not None:
                cache[key] = cached_size
                hit_bytes += overlap
                hits += 1
                continue
            misses += 1
            admit = bool(stream.hot[index]) or key in seen_once
            if not admit:
                seen_once.add(key)
                continue
            seen_once.discard(key)
            if raw_size > capacity:
                continue
            while resident + raw_size > capacity and cache:
                _victim, victim_size = cache.popitem(last=False)
                resident -= victim_size
            if resident + raw_size <= capacity:
                cache[key] = raw_size
                resident += raw_size
        simulations.append(
            CacheSimulation(
                capacity=capacity,
                requested_bytes=requested,
                hit_bytes=hit_bytes,
                misses=misses,
                hits=hits,
                sampled_touches=sampled_touches,
                total_touches=stream.total_touches,
                sampled_windows=stream.sampled_windows,
            )
        )
    return simulations

def choose_cache_size(simulations: Sequence[CacheSimulation]) -> int:
    if not simulations:
        return 64 * 1024 * 1024
    best_ratio = max(simulation.hit_ratio for simulation in simulations)
    if best_ratio < 0.08:
        return min(
            (simulation.capacity for simulation in simulations if simulation.capacity >= 64 * 1024 * 1024),
            default=simulations[0].capacity,
        )
    # When even the largest candidate has modest reuse, prefer a bounded cache
    # instead of consuming hundreds of MiB for a small absolute latency win.
    # The physical-page cache still captures short-range reuse underneath it.
    if best_ratio < 0.15:
        target = 128 * 1024 * 1024
        return min(
            simulations,
            key=lambda simulation: (
                abs(simulation.capacity - target), simulation.capacity
            ),
        ).capacity
    if best_ratio < 0.25:
        target = 256 * 1024 * 1024
        return min(
            simulations,
            key=lambda simulation: (
                abs(simulation.capacity - target), simulation.capacity
            ),
        ).capacity
    previous: CacheSimulation | None = None
    for simulation in simulations:
        if simulation.capacity < 64 * 1024 * 1024:
            previous = simulation
            continue
        within_best = best_ratio - simulation.hit_ratio <= 0.03
        marginal = (
            simulation.hit_ratio - previous.hit_ratio if previous is not None else simulation.hit_ratio
        )
        if within_best or (simulation.hit_ratio >= 0.30 and marginal < 0.05):
            return simulation.capacity
        previous = simulation
    return simulations[-1].capacity


def choose_physical_page_cache_size(
    recommendations: Sequence[FileRecommendation],
) -> int:
    eligible = [
        recommendation
        for recommendation in recommendations
        if recommendation.action != "loose"
        and recommendation.layout != "streaming"
    ]
    if not eligible:
        return 8 * 1024 * 1024
    requested = sum(item.metrics.requested_bytes for item in eligible)
    if requested <= 0:
        return 8 * 1024 * 1024
    weighted_repeat = sum(
        item.metrics.requested_bytes
        * item.metrics.candidates[64 * 1024].repeat_ratio
        for item in eligible
    ) / requested
    weighted_small = sum(
        item.metrics.requested_bytes * item.metrics.small_64k_ratio
        for item in eligible
    ) / requested
    weighted_random = sum(
        item.metrics.requested_bytes * item.metrics.random_seek_ratio
        for item in eligible
    ) / requested
    pressure = weighted_repeat + 0.5 * weighted_small * weighted_random
    if requested >= 16 * 1024**3 and pressure >= 0.20:
        return 64 * 1024 * 1024
    if requested >= 2 * 1024**3 or pressure >= 0.10:
        return 32 * 1024 * 1024
    return 16 * 1024 * 1024


def choose_runtime_workers(
    events: Sequence[ReadEvent],
    recommendations: Sequence[FileRecommendation],
    requested: int,
) -> int:
    if requested > 0:
        return requested
    selected_paths = {
        recommendation.metrics.relative
        for recommendation in recommendations
        if recommendation.action != "loose"
    }
    selected_events = [
        event for event in sorted(events, key=lambda event: event.order_key)
        if event.relative in selected_paths
    ]
    if not selected_events:
        return 2
    bytes_by_path: Counter[str] = Counter()
    switches = 0
    previous: str | None = None
    for event in selected_events:
        bytes_by_path[event.relative] += event.length
        if previous is not None and previous != event.relative:
            switches += 1
        previous = event.relative
    total_bytes = sum(bytes_by_path.values())
    dominant_share = (
        max(bytes_by_path.values()) / total_bytes if total_bytes else 1.0
    )
    switch_ratio = switches / max(1, len(selected_events) - 1)
    file_count = len(bytes_by_path)
    if file_count >= 1000 and switch_ratio >= 0.70:
        return 8
    if file_count >= 128 and switch_ratio >= 0.50:
        return 6
    if dominant_share >= 0.85 and file_count <= 8:
        return 2
    return 4


def choose_latency_reserve_workers(
    events: Sequence[ReadEvent],
    recommendations: Sequence[FileRecommendation],
    runtime_workers: int,
) -> int:
    """Reserve one worker when the title has latency-sensitive metadata I/O.

    A hard reserve is intentionally conservative: large streaming requests can
    use every general worker, while one worker remains available for tiny
    random/hot requests. Pure bulk profiles keep the reserve at zero.
    """
    if runtime_workers <= 1:
        return 0
    selected = {
        recommendation.metrics.relative: recommendation
        for recommendation in recommendations
        if recommendation.action != "loose"
    }
    selected_events = [event for event in events if event.relative in selected]
    if not selected_events:
        return 0
    total = len(selected_events)
    small = sum(event.length <= 64 * 1024 for event in selected_events)
    tiny = sum(event.length <= 16 * 1024 for event in selected_events)
    bulk = sum(event.length >= 256 * 1024 for event in selected_events)
    small_ratio = small / total
    tiny_ratio = tiny / total
    bulk_ratio = bulk / total
    if (
        small_ratio >= 0.45
        or tiny_ratio >= 0.20
        or (small_ratio >= 0.25 and bulk_ratio >= 0.20)
    ):
        return 1
    return 0


def _round_pool_size(required: int) -> int:
    quantum = 128 * 1024 * 1024
    return max(256 * 1024 * 1024, math.ceil(required / quantum) * quantum)


def _runtime_pool_required_bytes(
    *,
    projected_index_bytes: int,
    ampr_index_bytes: int,
    decoded_cache_bytes: int,
    physical_cache_bytes: int,
    runtime_workers: int,
) -> int:
    return (
        projected_index_bytes
        + ampr_index_bytes
        + decoded_cache_bytes
        + physical_cache_bytes
        + RUNTIME_PIPELINE_SLOTS * RUNTIME_PIPELINE_IO_BYTES
        + runtime_workers * RUNTIME_WORKER_SCRATCH_BYTES
        + RUNTIME_POST_CACHE_RESERVE_BYTES
    )


def build_profile(
    traces: Sequence[TraceSpec], options: ProfileOptions
) -> ProfileResult:
    events, summaries, index_entries, warnings = load_trace_events(traces)
    files = build_file_metrics(events)
    recommendations = _initial_recommendations(files, options)
    # Entropy sampling can remove large already-compressed archives before the
    # resident-index budget is applied.  Budget only the compact chunk table
    # after reserving the mandatory one-record-per-AMPRIDX3-file base index.
    sample_compressibility(recommendations, options, warnings)
    provisional_lanes = _choose_lanes(recommendations, options.lanes)
    provisional_groups = _build_groups(recommendations, provisional_lanes)
    provisional_pack_count = sum(
        int(group["pack_count"]) for group in provisional_groups.values()
    )
    mandatory_index_bytes = _estimate_index_bytes(
        [], provisional_pack_count, index_entries
    )
    chunk_budget = max(0, options.index_budget - mandatory_index_bytes)
    _enforce_index_budget(recommendations, chunk_budget, options.strategy)
    lanes = _choose_lanes(recommendations, options.lanes)
    groups = _build_groups(recommendations, lanes)
    pack_count = sum(int(group["pack_count"]) for group in groups.values())
    projected_index = _estimate_index_bytes(recommendations, pack_count, index_entries)
    if mandatory_index_bytes > options.index_budget:
        warnings.append(
            f"mandatory AMPRPAK4 file/string tables "
            f"{_human_size(mandatory_index_bytes)} exceed index budget "
            f"{_human_size(options.index_budget)} before any packed chunks"
        )
    if projected_index > options.index_budget:
        warnings.append(
            f"projected pack index {_human_size(projected_index)} still exceeds "
            f"budget {_human_size(options.index_budget)}"
        )
    recommendation_by_path = {rec.metrics.relative: rec for rec in recommendations}
    cache_simulations = (
        simulate_cache(
            events,
            recommendation_by_path,
            options.cache_candidates,
            options.cache_max_touches,
        )
        if options.cache_simulation
        else []
    )
    cache_size = choose_cache_size(cache_simulations)
    physical_page_cache = choose_physical_page_cache_size(recommendations)
    runtime_workers = choose_runtime_workers(
        events, recommendations, options.runtime_workers
    )
    latency_reserve_workers = choose_latency_reserve_workers(
        events, recommendations, runtime_workers
    )
    ampr_index_bytes = max(
        (
            Path(summary.index).stat().st_size
            for summary in summaries
            if summary.index
        ),
        default=0,
    )
    pool_size = _round_pool_size(
        _runtime_pool_required_bytes(
            projected_index_bytes=projected_index,
            ampr_index_bytes=ampr_index_bytes,
            decoded_cache_bytes=cache_size,
            physical_cache_bytes=physical_page_cache,
            runtime_workers=runtime_workers,
        )
    )
    return ProfileResult(
        name=options.name,
        traces=summaries,
        files=files,
        recommendations=recommendations,
        index_entries=index_entries,
        projected_index_bytes=projected_index,
        index_budget=options.index_budget,
        cache_simulations=cache_simulations,
        recommended_cache_bytes=cache_size,
        recommended_physical_cache_bytes=physical_page_cache,
        recommended_runtime_workers=runtime_workers,
        recommended_latency_reserve_workers=latency_reserve_workers,
        recommended_pool_bytes=pool_size,
        warnings=warnings,
        groups=groups,
    )


def _profile_comment(recommendations: Sequence[FileRecommendation]) -> tuple[str, ...]:
    reads = sum(rec.metrics.read_count for rec in recommendations)
    requested = sum(rec.metrics.requested_bytes for rec in recommendations)
    files = len(recommendations)
    confidence = Counter(rec.metrics.confidence_label for rec in recommendations)
    return (
        f"observed files={files}, reads={reads}, submitted={_human_size(requested)}",
        "confidence=" + ", ".join(f"{key}:{value}" for key, value in sorted(confidence.items())),
    )


def _directory_generalization(
    recommendations: Sequence[FileRecommendation],
    all_index_paths: Iterable[str],
    options: ProfileOptions,
) -> list[RuleEmission]:
    def append_paths(
        emissions: list[RuleEmission],
        profile_key: tuple[str, str, int, bool, str],
        paths: list[str],
        by_path: dict[str, FileRecommendation],
    ) -> None:
        if options.externalize_paths and len(paths) > options.externalize_paths:
            emissions.append(
                RuleEmission(
                    profile_key,
                    tuple(paths),
                    _profile_comment([by_path[path] for path in paths]),
                )
            )
            return
        for start in range(0, len(paths), options.max_rule_files):
            subset_paths = tuple(paths[start:start + options.max_rule_files])
            subset_recs = [by_path[path] for path in subset_paths]
            emissions.append(
                RuleEmission(profile_key, subset_paths, _profile_comment(subset_recs))
            )

    by_path = {recommendation.metrics.relative: recommendation for recommendation in recommendations if recommendation.action != "loose"}
    if options.pattern_mode == "exact":
        emissions: list[RuleEmission] = []
        by_profile: dict[tuple[str, str, int, bool, str], list[FileRecommendation]] = defaultdict(list)
        for recommendation in by_path.values():
            by_profile[recommendation.profile_key].append(recommendation)
        for profile_key, items in sorted(by_profile.items(), key=lambda item: item[0]):
            paths = sorted(rec.metrics.relative for rec in items)
            append_paths(emissions, profile_key, paths, by_path)
        return emissions

    total_by_prefix: Counter[str] = Counter()
    for relative in all_index_paths:
        parts = PurePosixPath(relative).parts
        for depth in range(1, len(parts)):
            total_by_prefix[PurePosixPath(*parts[:depth]).as_posix()] += 1

    profile_by_prefix: dict[str, Counter[tuple[str, str, int, bool, str]]] = defaultdict(Counter)
    paths_by_prefix_profile: dict[tuple[str, tuple[str, str, int, bool, str]], list[str]] = defaultdict(list)
    for relative, recommendation in by_path.items():
        parts = PurePosixPath(relative).parts
        for depth in range(1, len(parts)):
            prefix = PurePosixPath(*parts[:depth]).as_posix()
            profile_by_prefix[prefix][recommendation.profile_key] += 1
            paths_by_prefix_profile[(prefix, recommendation.profile_key)].append(relative)

    threshold = options.generalize_coverage
    if options.pattern_mode == "directory":
        threshold = min(threshold, 0.50)
    candidates: list[tuple[int, int, str, tuple[str, str, int, bool, str], set[str]]] = []
    for prefix, counts in profile_by_prefix.items():
        total = total_by_prefix.get(prefix, 0)
        if total <= 0:
            continue
        profile_key, matching = counts.most_common(1)[0]
        observed = sum(counts.values())
        coverage = observed / total
        purity = matching / observed
        if (
            matching >= options.generalize_min_files
            and coverage >= threshold
            and purity >= 0.90
        ):
            covered = set(paths_by_prefix_profile[(prefix, profile_key)])
            savings = len(covered) - 1
            depth = len(PurePosixPath(prefix).parts)
            candidates.append((savings, depth, prefix, profile_key, covered))

    candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
    covered_paths: set[str] = set()
    emissions: list[RuleEmission] = []
    for _savings, _depth, prefix, profile_key, covered in candidates:
        remaining = covered - covered_paths
        if len(remaining) < options.generalize_min_files:
            continue
        emissions.append(
            RuleEmission(
                profile_key,
                (f"{prefix}/**",),
                (
                    f"generalised from {len(remaining)} observed files under {prefix}",
                    f"indexed coverage={len(remaining) / max(1, total_by_prefix[prefix]):.0%}",
                ),
            )
        )
        covered_paths.update(remaining)

    remaining_by_profile: dict[tuple[str, str, int, bool, str], list[FileRecommendation]] = defaultdict(list)
    for path, recommendation in by_path.items():
        if path not in covered_paths:
            remaining_by_profile[recommendation.profile_key].append(recommendation)
    for profile_key, items in sorted(remaining_by_profile.items(), key=lambda item: item[0]):
        paths = sorted(rec.metrics.relative for rec in items)
        append_paths(emissions, profile_key, paths, by_path)
    return emissions


def render_toml(
    result: ProfileResult,
    options: ProfileOptions,
    *,
    external_lists: dict[str, str] | None = None,
    profile_stem: str = "profile",
) -> str:
    emissions = _directory_generalization(
        result.recommendations, result.index_entries.keys(), options
    )
    lines: list[str] = [
        f"# Generated by ampr_pack_profile.py {TOOL_VERSION} from APR traces.",
        "# IMPORTANT: traces contain only APR reads observed in recorded scenarios.",
        "# Adapt this config to the real game by adding remaining files/directories",
        "# or deliberately keep them loose. A trace cannot prove complete coverage.",
        f"# Projected resident pack index: {_human_size(result.projected_index_bytes)}.",
        f"# Recommended decoded cache: {_human_size(result.recommended_cache_bytes)}.",
        f"# Recommended physical-page cache: {_human_size(result.recommended_physical_cache_bytes)}.",
        f"# Recommended runtime workers: {result.recommended_runtime_workers}.",
        f"# Recommended latency-reserved workers: {result.recommended_latency_reserve_workers}.",
        f"# Recommended AMPR internal pool: {_human_size(result.recommended_pool_bytes)}.",
        "",
        "[pack]",
        'index_name = "ampr_assets.index"',
        'pack_pattern = "ampr_assets-{group}-lane{lane:02d}-vol{volume:02d}-{id:03d}.pak"',
        'default_action = "loose"',
        'default_block_size = "64KiB"',
        f'io_page_size = "{_size_literal(options.io_page_size)}"',
        f'payload_alignment = "{_size_literal(options.io_page_size)}"',
        'chunk_alignment = "64B"',
        f"workers = {options.workers}",
        'compression_mode = "hc"',
        "compression_level = 12",
        "acceleration = 1",
        "deduplicate = true",
        'deduplicate_scope = "lane"',
        "deduplicate_streaming = false",
        "min_savings_bytes = 64",
        "min_savings_ratio = 0.01",
        'io_neutral_min_savings_bytes = "8KiB"',
        "io_neutral_min_savings_ratio = 0.125",
        "auto_loose_large_files = true",
        "auto_loose_hot_files = false",
        'auto_loose_min_file_size = "64MiB"',
        "auto_loose_sample_blocks = 32",
        'auto_loose_sample_bytes = "16MiB"',
        "auto_loose_min_savings_ratio = 0.05",
        "auto_loose_max_raw_ratio = 0.90",
        "preserve_mtime = true",
        "validate_index_metadata = true",
        "",
    ]
    lines.extend([
        "[runtime]",
        f"decoded_cache_bytes = {result.recommended_cache_bytes}",
        f"physical_cache_bytes = {result.recommended_physical_cache_bytes}",
        f"workers = {result.recommended_runtime_workers}",
        f"latency_reserve_workers = {result.recommended_latency_reserve_workers}",
        "",
    ])
    for name, group in result.groups.items():
        lines.extend(
            [
                f"[groups.{name}]",
                f"pack_count = {group['pack_count']}",
                f"assignment = {_toml_string(str(group['assignment']))}",
                f"max_pack_size = {_toml_string(_size_literal(int(group['max_pack_size'])))}",
                "stripe_large_files = false",
                f"io_page_size = {_toml_string(_size_literal(options.io_page_size))}",
                "",
            ]
        )

    for emission_index, emission in enumerate(emissions, 1):
        action, layout, block_size, hot, group = emission.profile_key
        for comment in emission.comments:
            lines.append(f"# {comment}")
        lines.append("[[rule]]")
        lines.append(f"action = {_toml_string(action)}")
        is_exact_list = all(
            not any(marker in pattern for marker in "*?[")
            for pattern in emission.include
        )
        should_externalize = (
            external_lists is not None
            and options.externalize_paths > 0
            and len(emission.include) > options.externalize_paths
            and is_exact_list
        )
        if should_externalize:
            list_name = f"{profile_stem}.rule-{emission_index:03d}.include.txt"
            external_lists[list_name] = "".join(
                f"{path}\n" for path in emission.include
            )
            lines.append(f"include_from = [{_toml_string(list_name)}]")
        elif len(emission.include) == 1:
            lines.append(f"include = [{_toml_string(emission.include[0])}]")
        else:
            lines.append("include = [")
            for path in emission.include:
                lines.append(f"  {_toml_string(path)},")
            lines.append("]")
        lines.append(f"block_size = {_toml_string(_size_literal(block_size))}")
        lines.append(f"group = {_toml_string(group)}")
        lines.append(f"layout = {_toml_string(layout)}")
        if hot:
            lines.append("hot = true")
            if block_size <= 32 * 1024:
                lines.extend(
                    [
                        "min_savings_bytes = 16",
                        "min_savings_ratio = 0.0025",
                        'io_neutral_min_savings_bytes = "2KiB"',
                        "io_neutral_min_savings_ratio = 0.125",
                    ]
                )
        if layout == "streaming":
            lines.append("streaming = true")
        lines.append("")

    lines.extend(
        [
            "# Safety exclusions. The last matching rule wins.",
            "[[rule]]",
            'action = "loose"',
            "include = [",
        ]
    )
    for pattern in STANDARD_LOOSE_PATTERNS:
        lines.append(f"  {_toml_string(pattern)},")
    lines.extend(["]", ""])
    return "\n".join(lines)


def _recommendation_json(
    recommendation: FileRecommendation, *, full_candidates: bool = False
) -> dict[str, Any]:
    metrics = recommendation.metrics
    selected = metrics.candidates[recommendation.block_size]
    result = {
        "path": metrics.path,
        "relative": metrics.relative,
        "file_size": metrics.file_size,
        "read_count": metrics.read_count,
        "requested_bytes": metrics.requested_bytes,
        "unique_requested_bytes": metrics.unique_requested_bytes,
        "coverage_ratio": metrics.coverage_ratio,
        "request_percentiles": {
            "p50": metrics.p50,
            "p75": metrics.p75,
            "p90": metrics.p90,
            "p95": metrics.p95,
            "p99": metrics.p99,
        },
        "sequential_ratio": metrics.exact_sequential_ratio + metrics.near_sequential_ratio,
        "random_seek_ratio": metrics.random_seek_ratio,
        "repeat_ratio_64k": metrics.candidates[64 * 1024].repeat_ratio,
        "confidence": metrics.confidence,
        "confidence_label": metrics.confidence_label,
        "recommendation": {
            "action": recommendation.action,
            "layout": recommendation.layout,
            "block_size": recommendation.block_size,
            "hot": recommendation.hot,
            "group": recommendation.group,
            "reason": recommendation.reason,
            "metadata_bytes": recommendation.metadata_bytes,
            "amplification": selected.amplification,
            "average_blocks_per_read": selected.average_blocks_per_read,
            "sampled_ratio": recommendation.sampled_ratio,
            "sampled_bytes": recommendation.sampled_bytes,
        },
    }
    if full_candidates:
        result["candidates"] = {
            str(size): asdict(candidate)
            for size, candidate in sorted(metrics.candidates.items())
        }
    return result


def result_as_json(
    result: ProfileResult, *, full_candidates: bool = False
) -> dict[str, Any]:
    return {
        "tool_version": TOOL_VERSION,
        "name": result.name,
        "traces": [asdict(trace) for trace in result.traces],
        "projected_index_bytes": result.projected_index_bytes,
        "index_budget": result.index_budget,
        "recommended_cache_bytes": result.recommended_cache_bytes,
        "recommended_physical_cache_bytes": result.recommended_physical_cache_bytes,
        "recommended_runtime_workers": result.recommended_runtime_workers,
        "recommended_latency_reserve_workers": result.recommended_latency_reserve_workers,
        "recommended_pool_bytes": result.recommended_pool_bytes,
        "groups": result.groups,
        "cache_simulations": [
            {
                **asdict(simulation),
                "hit_ratio": simulation.hit_ratio,
            }
            for simulation in result.cache_simulations
        ],
        "warnings": result.warnings,
        "files": [
            _recommendation_json(
                recommendation, full_candidates=full_candidates
            )
            for recommendation in sorted(
                result.recommendations,
                key=lambda rec: rec.metrics.requested_bytes,
                reverse=True,
            )
        ],
    }


def render_report(result: ProfileResult, options: ProfileOptions) -> str:
    selected = [rec for rec in result.recommendations if rec.action != "loose"]
    total_reads = sum(rec.metrics.read_count for rec in selected)
    submitted = sum(rec.metrics.requested_bytes for rec in selected)
    file_size = sum(rec.metrics.file_size for rec in selected)
    layout_counts = Counter(rec.layout for rec in selected)
    block_counts = Counter(rec.block_size for rec in selected)
    action_counts = Counter(rec.action for rec in selected)
    lines = [
        f"# AMPR trace-derived pack profile: {result.name}",
        "",
        "## Summary",
        "",
        f"- Trace files: **{len(result.traces)}**",
        f"- Selected files: **{len(selected)}**",
        f"- Read commands: **{total_reads:,}**",
        f"- Submitted bytes: **{_human_size(submitted)}**",
        f"- Selected logical file size: **{_human_size(file_size)}**",
        f"- Projected pack index: **{_human_size(result.projected_index_bytes)}** "
        f"of {_human_size(result.index_budget)} budget",
        f"- Recommended decoded cache: **{_human_size(result.recommended_cache_bytes)}**",
        f"- Recommended physical-page cache: **{_human_size(result.recommended_physical_cache_bytes)}**",
        f"- Runtime workers: **{result.recommended_runtime_workers}**",
        f"- Latency-reserved workers: **{result.recommended_latency_reserve_workers}**",
        f"- Recommended AMPR internal pool: **{_human_size(result.recommended_pool_bytes)}**",
        "",
        "The recommendation describes access behaviour, not entropy. Unless content "
        "sampling was enabled, `compress` relies on the packer's per-block RAW fallback.",
        "",
        "## Profile distribution",
        "",
        "| Dimension | Distribution |",
        "|---|---|",
        "| Actions | " + ", ".join(f"{key}: {value}" for key, value in sorted(action_counts.items())) + " |",
        "| Layouts | " + ", ".join(f"{key}: {value}" for key, value in sorted(layout_counts.items())) + " |",
        "| Block sizes | " + ", ".join(f"{_size_literal(key)}: {value}" for key, value in sorted(block_counts.items())) + " |",
        "",
        "## Decoded-cache model",
        "",
        "The model uses byte-weighted LRU with second-touch admission; streaming rules bypass "
        "the main cache, matching the runtime policy.",
        "",
        "| Capacity | Hit bytes | Hit ratio | Block hits | Misses | Touches |",
        "|---:|---:|---:|---:|---:|---:|",
    ]
    if result.cache_simulations:
        first_simulation = result.cache_simulations[0]
        if first_simulation.sampled_touches < first_simulation.total_touches:
            lines.extend(
                [
                    f"Cache simulation sampled {first_simulation.sampled_touches:,} of "
                    f"{first_simulation.total_touches:,} block touches in "
                    f"{first_simulation.sampled_windows} contiguous windows.",
                    "",
                ]
            )
        for simulation in result.cache_simulations:
            lines.append(
                f"| {_human_size(simulation.capacity)} | {_human_size(simulation.hit_bytes)} | "
                f"{simulation.hit_ratio:.1%} | {simulation.hits:,} | {simulation.misses:,} | "
                f"{simulation.sampled_touches:,}/{simulation.total_touches:,} |"
            )
    else:
        lines.append("| disabled | — | — | — | — | — |")

    lines.extend(
        [
            "",
            "## Highest-impact files",
            "",
            "| Path | Reads | Submitted | p50 | Seq. | Repeat 64K | Recommendation | "
            "Amplification | Index | Confidence |",
            "|---|---:|---:|---:|---:|---:|---|---:|---:|---|",
        ]
    )
    for recommendation in sorted(
        selected,
        key=lambda rec: (rec.metrics.requested_bytes, rec.metrics.read_count),
        reverse=True,
    )[:80]:
        metrics = recommendation.metrics
        candidate = metrics.candidates[recommendation.block_size]
        path = metrics.relative.replace("|", "\\|")
        lines.append(
            f"| `{path}` | {metrics.read_count:,} | {_human_size(metrics.requested_bytes)} | "
            f"{_human_size(metrics.p50)} | "
            f"{(metrics.exact_sequential_ratio + metrics.near_sequential_ratio):.0%} | "
            f"{metrics.candidates[64 * 1024].repeat_ratio:.0%} | "
            f"{recommendation.action}/{recommendation.layout}/{_size_literal(recommendation.block_size)}"
            f"{'/hot' if recommendation.hot else ''} | {candidate.amplification:.2f}x | "
            f"{_human_size(recommendation.metadata_bytes)} | {metrics.confidence_label} |"
        )

    lines.extend(["", "## Trace inputs", ""])
    for trace in result.traces:
        lines.extend(
            [
                f"### {trace.name}",
                "",
                f"- Commands: `{trace.commands}`",
                f"- Index: `{trace.index}`",
                f"- Records: {trace.records:,}; reads: {trace.reads:,}; "
                f"duration: {trace.duration_ns / 1e9:.1f} s",
                f"- Sequence/parser warnings: {len(trace.warnings)}; decode issues: {trace.decode_errors}",
                f"- Command SHA-256: `{trace.command_sha256}`",
                f"- Index SHA-256: `{trace.index_sha256}`",
                "",
            ]
        )
    if result.warnings:
        lines.extend(["## Warnings", ""])
        for warning in result.warnings[:200]:
            lines.append(f"- {warning}")
        if len(result.warnings) > 200:
            lines.append(f"- {len(result.warnings) - 200} additional warnings omitted")
        lines.append("")
    lines.extend(
        [
            "## Operational guidance",
            "",
            "1. Treat this profile as a starting point: traces contain only observed APR reads. "
            "Review the real game and add required files/directories from unrecorded levels, "
            "modes, languages and DLC, or deliberately keep them loose.",
            "2. Build packs, run `ampr_pack.py verify`, then test with loose source files still "
            "available.",
            "3. Measure LZ4 ratio. Archives that remain almost entirely RAW and show little cache "
            "reuse may be better left loose.",
            "4. Re-run this profiler when the game or resource layout changes.",
            "",
        ]
    )
    return "\n".join(lines)


def render_runtime_header(result: ProfileResult) -> str:
    trace_lines = [
        f" *   {trace.name}: commands={trace.command_sha256} index={trace.index_sha256}"
        for trace in result.traces
    ]
    lines = [
        "/*",
        f" * Generated by ampr_pack_profile.py {TOOL_VERSION}.",
        f" * Profile: {result.name}",
        " * Inputs:",
        *trace_lines,
        " */",
        "#pragma once",
        "",
        f"#define AMPR_EMU_INTERNAL_AMM_POOL_SIZE 0x{result.recommended_pool_bytes:x}ull",
        f"#define AMPR_EMU_PACK_DECODED_CACHE_BYTES 0x{result.recommended_cache_bytes:x}ull",
        f"#define AMPR_EMU_PACK_PHYSICAL_CACHE_BYTES 0x{result.recommended_physical_cache_bytes:x}ull",
        f"#define AMPR_EMU_PACK_WORKERS {result.recommended_runtime_workers}u",
        f"#define AMPR_EMU_PACK_LATENCY_RESERVE_WORKERS {result.recommended_latency_reserve_workers}u",
        "",
    ]
    return "\n".join(lines)


def validate_generated_toml(text: str) -> None:
    parsed = tomllib.loads(text)
    if not isinstance(parsed.get("pack"), dict):
        raise ProfileError("generated TOML has no [pack] table")
    rules = parsed.get("rule")
    if not isinstance(rules, list) or not rules:
        raise ProfileError("generated TOML has no [[rule]] entries")


def _write_text(path: Path, text: str, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise ProfileError(f"refusing to overwrite existing file: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temp.write_text(text, encoding="utf-8", newline="\n")
    os.replace(temp, path)


def _write_profile_bundle(
    toml_path: Path,
    toml_text: str,
    sidecars: dict[str, str],
    overwrite: bool,
) -> None:
    outputs = [toml_path]
    outputs.extend(toml_path.parent / name for name in sidecars)
    if not overwrite:
        existing = next((path for path in outputs if path.exists()), None)
        if existing is not None:
            raise ProfileError(f"refusing to overwrite existing file: {existing}")
    # Publish pattern lists first and the TOML last so a reader never observes
    # a profile that references files which have not been written yet.
    for name, text in sidecars.items():
        _write_text(toml_path.parent / name, text, True)
    _write_text(toml_path, toml_text, True)


def _profile_options_from_args(args: argparse.Namespace, name: str) -> ProfileOptions:
    content_root = Path(args.content_root).resolve() if args.content_root else None
    return ProfileOptions(
        name=name,
        io_page_size=parse_size(args.io_page_size),
        index_budget=parse_size(args.pack_index_budget),
        cache_candidates=args.cache_candidates,
        lanes=args.lanes,
        workers=args.workers,
        runtime_workers=args.runtime_workers,
        strategy=args.strategy,
        pattern_mode=args.pattern_mode,
        min_reads=args.min_reads,
        min_requested_bytes=parse_size(args.min_requested_bytes),
        max_rule_files=args.max_rule_files,
        externalize_paths=args.externalize_paths,
        generalize_coverage=args.generalize_coverage,
        generalize_min_files=args.generalize_min_files,
        cache_simulation=args.cache_simulation,
        cache_max_touches=args.cache_max_touches,
        content_root=content_root,
        sample_budget=parse_size(args.sample_budget),
        sample_blocks_per_file=args.sample_blocks_per_file,
        sample_mode=args.sample_mode,
        sample_level=args.sample_level,
        sample_acceleration=args.sample_acceleration,
    )


def _add_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--io-page-size", default="64KiB")
    parser.add_argument("--pack-index-budget", default="96MiB")
    parser.add_argument(
        "--cache-candidates",
        type=_parse_cache_candidates,
        default=DEFAULT_CACHE_CANDIDATES,
        metavar="LIST",
        help="comma-separated capacities, e.g. 64MiB,128MiB,256MiB,512MiB",
    )
    parser.add_argument("--lanes", type=int, default=0, help="0 selects 1-4 lanes automatically")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument(
        "--runtime-workers",
        type=int,
        default=0,
        help="0 selects 2-8 runtime decode/I/O workers from the trace",
    )
    parser.add_argument(
        "--strategy",
        choices=("conservative", "balanced", "aggressive"),
        default="balanced",
        help="trade read amplification against resident index size",
    )
    parser.add_argument(
        "--pattern-mode",
        choices=("exact", "hybrid", "directory"),
        default="exact",
        help="exact is safest; hybrid generalises only high-coverage directories",
    )
    parser.add_argument("--min-reads", type=int, default=1)
    parser.add_argument("--min-requested-bytes", default="1B")
    parser.add_argument("--max-rule-files", type=int, default=256)
    parser.add_argument(
        "--externalize-paths",
        type=int,
        default=128,
        help=(
            "write larger exact include lists to portable include_from sidecars "
            "(0 keeps paths inline)"
        ),
    )
    parser.add_argument("--generalize-coverage", type=float, default=0.80)
    parser.add_argument("--generalize-min-files", type=int, default=4)
    cache_mode = parser.add_mutually_exclusive_group()
    cache_mode.add_argument(
        "--cache-sim",
        dest="cache_simulation",
        action="store_true",
        help="simulate decoded-cache reuse (default for generate)",
    )
    cache_mode.add_argument(
        "--no-cache-sim",
        dest="cache_simulation",
        action="store_false",
        help="skip the expensive decoded-cache simulation",
    )
    parser.set_defaults(cache_simulation=True)
    parser.add_argument(
        "--cache-max-touches",
        type=int,
        default=DEFAULT_CACHE_MAX_TOUCHES,
        help=(
            "simulate all decoded-cache block touches up to this limit; "
            "larger traces use deterministic contiguous windows (0 = exact)"
        ),
    )
    parser.add_argument("--content-root", help="optional extracted /app0 root for LZ4 sampling")
    parser.add_argument("--sample-budget", default="0B")
    parser.add_argument("--sample-blocks-per-file", type=int, default=4)
    parser.add_argument("--sample-mode", choices=("fast", "hc"), default="hc")
    parser.add_argument("--sample-level", type=int, default=12)
    parser.add_argument("--sample-acceleration", type=int, default=1)
    parser.add_argument(
        "--full-metrics",
        action="store_true",
        help="include all seven block-size candidates for every file in JSON",
    )
    parser.add_argument("--overwrite", action="store_true")


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate = subparsers.add_parser("generate", help="generate one profile")
    generate.add_argument(
        "input",
        nargs="?",
        help="directory containing ampr_commands.bin and ampr_emu.index",
    )
    generate.add_argument(
        "--trace",
        action="append",
        nargs=2,
        metavar=("COMMANDS", "INDEX"),
        help="repeat to merge several gameplay traces",
    )
    generate.add_argument("--name")
    generate.add_argument("--output", required=True)
    generate.add_argument("--report")
    generate.add_argument("--metrics")
    generate.add_argument(
        "--runtime-header",
        help="optional force-include header with runtime cache/pool/coalescing defines",
    )
    _add_common_options(generate)

    batch = subparsers.add_parser("batch", help="scan a directory or ZIP and generate one profile per subdirectory")
    batch.add_argument("input")
    batch.add_argument("--output-dir", required=True)
    batch.add_argument("--summary")
    batch.add_argument(
        "--batch-jobs",
        type=int,
        default=0,
        help=(
            "parallel title profiles (0 = auto, currently "
            f"{DEFAULT_BATCH_JOBS}); reduce this for memory-constrained hosts"
        ),
    )
    _add_common_options(batch)
    # A batch normally contains several large title traces. Prefer concise,
    # directory-generalised TOML and bounded heuristic cache sizing so the
    # command completes predictably. Users can opt back into exact rules and
    # full simulation with --pattern-mode exact --cache-sim.
    batch.set_defaults(pattern_mode="hybrid", cache_simulation=False)
    return parser


def _validate_options(options: ProfileOptions) -> None:
    if options.io_page_size < 4096 or options.io_page_size & (options.io_page_size - 1):
        raise ProfileError("io-page-size must be a power of two and at least 4 KiB")
    if options.index_budget < 1024 * 1024:
        raise ProfileError("pack-index-budget must be at least 1 MiB")
    if not 0 <= options.lanes <= 64:
        raise ProfileError("lanes must be between 0 and 64")
    if not 1 <= options.workers <= 256:
        raise ProfileError("workers must be between 1 and 256")
    if not 0 <= options.runtime_workers <= 16:
        raise ProfileError("runtime-workers must be between 0 and 16")
    if options.min_reads < 1:
        raise ProfileError("min-reads must be at least 1")
    if options.max_rule_files < 1:
        raise ProfileError("max-rule-files must be at least 1")
    if options.externalize_paths < 0:
        raise ProfileError("externalize-paths must be non-negative")
    if not 0.0 <= options.generalize_coverage <= 1.0:
        raise ProfileError("generalize-coverage must be in [0,1]")
    if options.generalize_min_files < 2:
        raise ProfileError("generalize-min-files must be at least 2")


def _run_generate(args: argparse.Namespace) -> int:
    traces: list[TraceSpec] = []
    if args.input:
        input_path = Path(args.input).resolve()
        discovered = discover_trace_pairs(input_path)
        if len(discovered) != 1:
            raise ProfileError(
                f"generate input must contain exactly one trace pair; found {len(discovered)}"
            )
        traces.extend(discovered)
    for ordinal, pair in enumerate(args.trace or []):
        commands = Path(pair[0]).resolve()
        index = Path(pair[1]).resolve()
        traces.append(TraceSpec(f"trace-{ordinal + 1}", commands, index))
    if not traces:
        raise ProfileError("provide an input directory or at least one --trace pair")
    for trace in traces:
        if not trace.commands.is_file() or not trace.index.is_file():
            raise ProfileError(f"missing trace input: {trace.commands} / {trace.index}")
    name = args.name or traces[0].name
    options = _profile_options_from_args(args, name)
    _validate_options(options)
    result = build_profile(traces, options)
    output_path = Path(args.output)
    sidecars: dict[str, str] = {}
    toml_text = render_toml(
        result,
        options,
        external_lists=sidecars,
        profile_stem=output_path.stem,
    )
    validate_generated_toml(toml_text)
    _write_profile_bundle(output_path, toml_text, sidecars, args.overwrite)
    if args.report:
        _write_text(Path(args.report), render_report(result, options), args.overwrite)
    if args.metrics:
        _write_text(
            Path(args.metrics),
            json.dumps(
                result_as_json(result, full_candidates=args.full_metrics),
                ensure_ascii=False,
                indent=2,
            ) + "\n",
            args.overwrite,
        )
    if args.runtime_header:
        _write_text(
            Path(args.runtime_header),
            render_runtime_header(result),
            args.overwrite,
        )
    print(
        f"generated {args.output}: files={len(result.recommendations)} "
        f"index={_human_size(result.projected_index_bytes)} "
        f"cache={_human_size(result.recommended_cache_bytes)} "
        f"pool={_human_size(result.recommended_pool_bytes)}"
    )
    return 0


def _build_batch_profile(
    task: tuple[
        TraceSpec,
        ProfileOptions,
        Path,
        bool,
        bool,
    ]
) -> tuple[str, dict[str, Any]]:
    pair, options, output_dir, full_metrics, overwrite = task
    result = build_profile([pair], options)
    name = options.name
    toml_path = output_dir / f"{name}.toml"
    sidecars: dict[str, str] = {}
    toml_text = render_toml(
        result,
        options,
        external_lists=sidecars,
        profile_stem=toml_path.stem,
    )
    validate_generated_toml(toml_text)
    report_path = output_dir / f"{name}.md"
    metrics_path = output_dir / f"{name}.json"
    runtime_header_path = output_dir / f"{name}.runtime.h"
    _write_profile_bundle(toml_path, toml_text, sidecars, overwrite)
    _write_text(report_path, render_report(result, options), overwrite)
    _write_text(
        metrics_path,
        json.dumps(
            result_as_json(result, full_candidates=full_metrics),
            ensure_ascii=False,
            indent=2,
        ) + "\n",
        overwrite,
    )
    _write_text(
        runtime_header_path,
        render_runtime_header(result),
        overwrite,
    )
    first_simulation = result.cache_simulations[0] if result.cache_simulations else None
    row = {
        "name": name,
        "files": len(result.recommendations),
        "reads": sum(rec.metrics.read_count for rec in result.recommendations),
        "submitted_bytes": sum(rec.metrics.requested_bytes for rec in result.recommendations),
        "selected_file_bytes": sum(rec.metrics.file_size for rec in result.recommendations),
        "projected_index_bytes": result.projected_index_bytes,
        "recommended_cache_bytes": result.recommended_cache_bytes,
        "recommended_physical_cache_bytes": result.recommended_physical_cache_bytes,
        "recommended_runtime_workers": result.recommended_runtime_workers,
        "recommended_latency_reserve_workers": result.recommended_latency_reserve_workers,
        "recommended_pool_bytes": result.recommended_pool_bytes,
        "cache_sampled_touches": (
            first_simulation.sampled_touches if first_simulation else 0
        ),
        "cache_total_touches": (
            first_simulation.total_touches if first_simulation else 0
        ),
        "warnings": len(result.warnings),
    }
    return name, row


def _run_batch(args: argparse.Namespace) -> int:
    input_path = Path(args.input).resolve()
    output_dir = Path(args.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ampr-profile-") as temp_name:
        scan_root = input_path
        if input_path.is_file():
            scan_root = _extract_trace_archive(input_path, Path(temp_name))
        pairs = discover_trace_pairs(scan_root)
        if not pairs:
            raise ProfileError(f"no trace pairs found under {input_path}")

        used_names: Counter[str] = Counter()
        tasks: list[
            tuple[TraceSpec, ProfileOptions, Path, bool, bool]
        ] = []
        for pair in pairs:
            base_name = pair.name or pair.commands.parent.name or "profile"
            used_names[base_name] += 1
            name = (
                base_name
                if used_names[base_name] == 1
                else f"{base_name}-{used_names[base_name]}"
            )
            options = _profile_options_from_args(args, name)
            # Batch content roots are ambiguous; disable sampling unless the
            # caller processes a single trace with generate.
            options.content_root = None
            options.sample_budget = 0
            _validate_options(options)
            tasks.append(
                (pair, options, output_dir, args.full_metrics, args.overwrite)
            )

        batch_jobs = args.batch_jobs
        if batch_jobs <= 0:
            batch_jobs = DEFAULT_BATCH_JOBS
        batch_jobs = min(batch_jobs, len(tasks))
        rows_by_name: dict[str, dict[str, Any]] = {}
        if batch_jobs <= 1:
            results = map(_build_batch_profile, tasks)
            for name, row in results:
                rows_by_name[name] = row
                print(f"generated {name}.toml", flush=True)
        else:
            # Each trace is independent.  Processes avoid the Python GIL and,
            # just as importantly, release large event/index objects as soon as
            # one title finishes instead of retaining allocator arenas for the
            # rest of a support bundle.
            with ProcessPoolExecutor(max_workers=batch_jobs) as executor:
                for name, row in executor.map(_build_batch_profile, tasks):
                    rows_by_name[name] = row
                    print(f"generated {name}.toml", flush=True)

        rows = [rows_by_name[task[1].name] for task in tasks]
        summary_path = (
            Path(args.summary).resolve()
            if args.summary
            else output_dir / "summary.json"
        )
        _write_text(
            summary_path,
            json.dumps(rows, ensure_ascii=False, indent=2) + "\n",
            args.overwrite,
        )
    return 0

def main(argv: Sequence[str] | None = None) -> int:
    parser = create_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "generate":
            return _run_generate(args)
        if args.command == "batch":
            return _run_batch(args)
        raise ProfileError(f"unsupported command: {args.command}")
    except (ProfileError, ValueError, OSError, zipfile.BadZipFile) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
