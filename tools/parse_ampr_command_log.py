#!/usr/bin/env python3
"""Decode and analyze the binary AMPR submit command journal.

The journal is emitted by AMPR_EMU_COMMAND_LOG and contains the exact packed
command bytes observed at APR/AMM submit time.  This tool combines the journal
with an AMPRIDX3 file index to produce:

* a human-readable command timeline;
* a machine-readable JSON timeline;
* command/read/priority/submit statistics;
* APR gather/scatter-state reconstruction across submit boundaries;
* FD-cache policy classification for the current 512 KiB direct-read rule;
* optimization candidates derived from the observed workload.

Usage:
    python parse_ampr_command_log.py ampr_commands.bin ampr_emu.index
    python parse_ampr_command_log.py ampr_commands.bin ampr_emu.index \
        --text commands.txt --json commands.json
"""

from __future__ import annotations

import argparse
import json
import math
import struct
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

COMMAND_LOG_MAGIC = b"AMPRCMD1"
COMMAND_LOG_VERSION = 1
COMMAND_LOG_HEADER = struct.Struct("<8sHHIQQQQQQIIIIIIII")
COMMAND_LOG_HEADER_SIZE = COMMAND_LOG_HEADER.size

INDEX_MAGIC = b"AMPRIDX3"
INDEX_HEADER = struct.Struct("<8sIIQQQII")
INDEX_RECORD = struct.Struct("<IIQq")
INDEX_HASH_SLOT = struct.Struct("<QII")

DOMAIN_NAMES = {1: "APR", 2: "AMM"}
MODE_NAMES = {0: "submit", 1: "submit+result", 2: "submit+id"}
WAIT_COMPARE_NAMES = {
    0: "equal",
    1: "greater",
    2: "less",
    3: "not-equal",
    4: "greater-or-equal-wrapped",
    5: "signed-greater",
    6: "signed-less",
    7: "reserved",
}
WRITE_COUNTER_OP_NAMES = {
    0: "store",
    1: "or",
    2: "and-not",
    3: "xor",
    4: "add",
}

APR_DISPATCH_QUANTUM = 512 * 1024
TINY_READ = 64 * 1024


@dataclass
class IndexEntry:
    file_id: int
    path: str
    size: int
    mtime: int


@dataclass
class SubmitRecord:
    sequence: int
    utc_ns: int
    monotonic_ns: int
    submit_cookie: int
    source_address: int
    payload_hash: int
    payload_bytes: int
    source_capacity: int
    command_count: int
    priority: int
    domain: int
    submit_mode: int
    submit_type: int
    flags: int
    payload: bytes
    file_offset: int
    commands: list[dict[str, Any]] = field(default_factory=list)
    decode_errors: list[str] = field(default_factory=list)


@dataclass
class GatherState:
    logical_read_id: str
    file_id: int
    path: Optional[str]
    file_size: Optional[int]
    next_file_offset: int
    next_output_address: int


@dataclass
class LogicalRead:
    logical_read_id: str
    priority: int
    first_sequence: int
    file_id: int
    path: Optional[str]
    file_size: Optional[int]
    segments: list[dict[str, Any]] = field(default_factory=list)

    @property
    def total_bytes(self) -> int:
        return sum(int(segment.get("length", 0)) for segment in self.segments)


def fnv1a64(data: bytes) -> int:
    h = 1469598103934665603
    for byte in data:
        h ^= byte
        h = (h * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return h or 1


def load_index(path: Path) -> dict[int, IndexEntry]:
    data = path.read_bytes()
    if len(data) < INDEX_HEADER.size:
        raise ValueError(f"index is too small: {path}")
    magic, version, entry_size, entry_count, path_bytes, hash_offset, hash_slot_size, hash_slot_count = INDEX_HEADER.unpack_from(data)
    if magic != INDEX_MAGIC:
        raise ValueError(f"unsupported index magic {magic!r}; expected AMPRIDX3")
    if version != 3:
        raise ValueError(f"unsupported AMPRIDX3 version {version}; expected 3")
    if entry_size != INDEX_RECORD.size:
        raise ValueError(f"unsupported AMPRIDX3 entry size {entry_size}; expected {INDEX_RECORD.size}")
    records_start = INDEX_HEADER.size
    records_bytes = entry_count * entry_size
    path_start = records_start + records_bytes
    path_end = path_start + path_bytes
    if path_end > len(data):
        raise ValueError("AMPRIDX3 path blob exceeds file size")
    if hash_offset < path_end or hash_offset > len(data):
        raise ValueError("AMPRIDX3 hash offset is invalid")
    if hash_slot_size != INDEX_HASH_SLOT.size:
        raise ValueError(f"unsupported AMPRIDX3 hash slot size {hash_slot_size}")
    if hash_offset + hash_slot_count * hash_slot_size > len(data):
        raise ValueError("AMPRIDX3 hash table exceeds file size")

    path_blob = data[path_start:path_end]
    entries: dict[int, IndexEntry] = {}
    for index in range(entry_count):
        record_off = records_start + index * entry_size
        path_off, path_len, size, mtime = INDEX_RECORD.unpack_from(data, record_off)
        if path_off + path_len > len(path_blob):
            raise ValueError(f"AMPRIDX3 entry {index} path is out of bounds")
        raw_path = path_blob[path_off:path_off + path_len]
        try:
            decoded = raw_path.decode("utf-8")
        except UnicodeDecodeError:
            decoded = raw_path.decode("utf-8", errors="replace")
        file_id = index + 1
        entries[file_id] = IndexEntry(file_id=file_id, path=decoded, size=size, mtime=mtime)
    return entries


def read_command_log(path: Path) -> tuple[list[SubmitRecord], list[str]]:
    records: list[SubmitRecord] = []
    warnings: list[str] = []
    with path.open("rb") as f:
        offset = 0
        previous_sequence: int | None = None
        while True:
            raw_header = f.read(COMMAND_LOG_HEADER_SIZE)
            if not raw_header:
                break
            if len(raw_header) != COMMAND_LOG_HEADER_SIZE:
                warnings.append(
                    f"truncated header at file offset 0x{offset:x}: got {len(raw_header)} of {COMMAND_LOG_HEADER_SIZE} bytes"
                )
                break
            values = COMMAND_LOG_HEADER.unpack(raw_header)
            (
                magic,
                version,
                header_bytes,
                record_bytes,
                sequence,
                utc_ns,
                monotonic_ns,
                submit_cookie,
                source_address,
                payload_hash,
                payload_bytes,
                source_capacity,
                command_count,
                priority,
                domain,
                submit_mode,
                submit_type,
                flags,
            ) = values
            if magic != COMMAND_LOG_MAGIC:
                raise ValueError(f"invalid command-log magic at 0x{offset:x}: {magic!r}")
            if version != COMMAND_LOG_VERSION:
                raise ValueError(f"unsupported command-log version {version} at 0x{offset:x}")
            if header_bytes < COMMAND_LOG_HEADER_SIZE:
                raise ValueError(f"invalid header size {header_bytes} at 0x{offset:x}")
            if record_bytes < header_bytes or record_bytes - header_bytes != payload_bytes:
                raise ValueError(
                    f"invalid record/payload sizes at 0x{offset:x}: record={record_bytes} header={header_bytes} payload={payload_bytes}"
                )
            if header_bytes > COMMAND_LOG_HEADER_SIZE:
                extra = f.read(header_bytes - COMMAND_LOG_HEADER_SIZE)
                if len(extra) != header_bytes - COMMAND_LOG_HEADER_SIZE:
                    warnings.append(f"truncated extended header at 0x{offset:x}")
                    break
            payload = f.read(payload_bytes)
            if len(payload) != payload_bytes:
                warnings.append(
                    f"truncated payload for record seq={sequence} at 0x{offset:x}: got {len(payload)} of {payload_bytes} bytes"
                )
                break
            if previous_sequence is None:
                if sequence != 1:
                    warnings.append(
                        f"sequence gap before first stored record seq={sequence}: expected 1; "
                        f"{sequence - 1 if sequence > 1 else 0} record(s) were dropped or are missing"
                    )
            elif sequence != previous_sequence + 1:
                if sequence > previous_sequence + 1:
                    warnings.append(
                        f"sequence gap before seq={sequence}: expected {previous_sequence + 1}; "
                        f"{sequence - previous_sequence - 1} record(s) were dropped or are missing"
                    )
                else:
                    warnings.append(
                        f"non-monotonic sequence at seq={sequence}: previous={previous_sequence}"
                    )
            previous_sequence = sequence

            actual_hash = fnv1a64(payload)
            if actual_hash != payload_hash:
                warnings.append(
                    f"payload hash mismatch for seq={sequence}: header=0x{payload_hash:016x} actual=0x{actual_hash:016x}"
                )
            records.append(
                SubmitRecord(
                    sequence=sequence,
                    utc_ns=utc_ns,
                    monotonic_ns=monotonic_ns,
                    submit_cookie=submit_cookie,
                    source_address=source_address,
                    payload_hash=payload_hash,
                    payload_bytes=payload_bytes,
                    source_capacity=source_capacity,
                    command_count=command_count,
                    priority=priority,
                    domain=domain,
                    submit_mode=submit_mode,
                    submit_type=submit_type,
                    flags=flags,
                    payload=payload,
                    file_offset=offset,
                )
            )
            offset += record_bytes
    return records, warnings


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def need(data: bytes, off: int, dwords: int) -> bool:
    return dwords > 0 and off >= 0 and off + dwords * 4 <= len(data)


def packed_addr(high_word: int, low_word: int) -> int:
    return ((high_word & 0xFFFF0000) << 16) | low_word


def counter_width_bits(value_width: int) -> int:
    if value_width == 0:
        return 64
    if value_width == 1:
        return 32
    if value_width < 4:
        return 16
    return 8


def decode_wait_counter_extra(data: bytes, off: int, dwords: int, command: dict[str, Any]) -> None:
    if dwords < 2:
        return
    w1 = u32(data, off + 4)
    extra_flag = (w1 >> 28) & 3
    value_width = ((w1 >> 24) & 7) ^ 1
    command["value_width_selector"] = value_width
    command["value_width_bits"] = counter_width_bits(value_width)
    command["extra_flag"] = extra_flag
    ref_low8 = int(command["reference_value"]) & 0xFF
    if extra_flag:
        if dwords == 2:
            command["reference_value"] = ref_low8 | ((w1 & 0xFF) << 8)
            command["extra_value"] = (w1 >> 8) & 0xFFFF
            return
        compact_ref = (w1 & 0x00FFFF00) == 0 and (dwords < 5 or u32(data, off + 8) == 0)
        if compact_ref:
            command["reference_value"] = ref_low8 | ((w1 & 0xFF) << 8)
            if dwords == 3:
                command["extra_value"] = u32(data, off + 8)
            elif dwords >= 5:
                command["extra_value"] = u32(data, off + 12) | (u32(data, off + 16) << 32)
            return
    command["reference_value"] = ref_low8 | ((w1 & 0x00FFFFFF) << 8)
    if dwords >= 3:
        w2 = u32(data, off + 8)
        if extra_flag == 0:
            command["reference_value"] |= w2 << 32
        elif dwords >= 5:
            command["reference_value"] |= w2 << 32
            command["extra_value"] = u32(data, off + 12) | (u32(data, off + 16) << 32)
        else:
            command["extra_value"] = w2


def decode_amm_va(low_word: int, high_bits_word: int, high_shift: int) -> int:
    return (low_word << 14) | (((high_bits_word >> high_shift) & 3) << 46)


def decode_amm(data: bytes, off: int, w0: int) -> Optional[dict[str, Any]]:
    opcode12 = w0 & 0xFFF
    cmd: dict[str, Any]
    if opcode12 in (0x221, 0x321):
        dwords = 4 if opcode12 == 0x321 else 3
        if not need(data, off, dwords):
            return None
        w1, w2 = u32(data, off + 4), u32(data, off + 8)
        prt = bool(w0 & 0x8000)
        prot = ((w0 & ~0x8000) >> 12) & 0x7FFF
        type_id = (w0 >> 27) & 0x1F
        name = "AmmMapAsPrt" if prt and prot == 0 and type_id == 0 else "AmmMap"
        cmd = {
            "name": name,
            "dwords": dwords,
            "va": decode_amm_va(w1, w2, 0),
            "size": (w2 & 0x1FFFFFFC) << 12,
            "prot": prot,
            "memory_type": type_id,
            "prt": prt,
        }
        if opcode12 == 0x321:
            cmd["gpu_mask_id"] = u32(data, off + 12) & 0xFF
        return cmd
    if opcode12 in (0x325, 0x425):
        dwords = 5 if opcode12 == 0x425 else 4
        if not need(data, off, dwords):
            return None
        w1, w2, w3 = u32(data, off + 4), u32(data, off + 8), u32(data, off + 12)
        cmd = {
            "name": "AmmMapDirect",
            "dwords": dwords,
            "va": decode_amm_va(w1, w2, 0),
            "direct_memory_offset": (w3 & 0x03FFFFFF) << 14,
            "size": (w2 & 0xFFFFFFFC) << 9,
            "prot": (w0 >> 12) & 0x7FFF,
            "memory_type": (w0 >> 27) & 0x1F,
        }
        if opcode12 == 0x425:
            cmd["gpu_mask_id"] = u32(data, off + 16) & 0xFF
        return cmd
    if opcode12 in (0x222, 0x228):
        dwords = 3
        if not need(data, off, dwords):
            return None
        w1, w2 = u32(data, off + 4), u32(data, off + 8)
        return {
            "name": "AmmUnmapToPrt" if opcode12 == 0x228 else "AmmUnmap",
            "dwords": dwords,
            "va": decode_amm_va(w1, w2, 0),
            "size": (w2 & 0xFFFFFFFC) << 9,
        }
    if opcode12 in (0x323, 0x423, 0x324, 0x424, 0x327):
        dwords = 5 if opcode12 in (0x423, 0x424) else 4
        if not need(data, off, dwords):
            return None
        w1, w2, w3 = u32(data, off + 4), u32(data, off + 8), u32(data, off + 12)
        if opcode12 == 0x327:
            name = "AmmRemapIntoPrt"
            prot = ((w0 & ~0x8000) >> 12) & 0x7FFF
        else:
            name = "AmmMultiMap" if opcode12 in (0x324, 0x424) else "AmmRemap"
            prot = (w0 >> 12) & 0x7FFF
        cmd = {
            "name": name,
            "dwords": dwords,
            "va_new": decode_amm_va(w1, w3, 0),
            "va_old_or_alias": decode_amm_va(w2, w3, 2),
            "size": (w3 & 0xFFFFFFF0) << 9,
            "prot": prot,
        }
        if opcode12 == 0x327:
            cmd["writer_opcode"] = 1011
        if dwords == 5:
            cmd["gpu_mask_id"] = u32(data, off + 16) & 0xFF
        return cmd
    if opcode12 in (0x326, 0x426):
        dwords = 5 if opcode12 == 0x426 else 4
        if not need(data, off, dwords):
            return None
        w1, w2, w3 = u32(data, off + 4), u32(data, off + 8), u32(data, off + 12)
        mtype = bool(w2 & 0x40000000) or ((w0 >> 27) & 0x1F) != 0
        if mtype:
            name = "AmmAllocPaForPrt" if w3 == 1019 and opcode12 == 0x326 else "AmmModifyMtypeProtect"
        else:
            name = "AmmModifyProtect"
        cmd = {
            "name": name,
            "dwords": dwords,
            "va": decode_amm_va(w1, w2, 0),
            "size": (w2 & 0x1FFFFFFC) << 12,
            "prot": (w0 >> 12) & 0x7FFF,
        }
        if mtype:
            cmd["memory_type"] = (w0 >> 27) & 0x1F
            cmd["prot_mask"] = w3 & 0x7FFF
        else:
            cmd["prot_mask"] = w3 & 0x7FFF
        if dwords == 5:
            cmd["gpu_mask_id"] = u32(data, off + 16) & 0xFF
        return cmd
    return None


def decode_command(data: bytes, off: int) -> dict[str, Any]:
    if off & 3 or off + 4 > len(data):
        raise ValueError("unaligned or truncated command")
    w0 = u32(data, off)
    opcode8 = w0 & 0xFF
    opcode12 = w0 & 0xFFF
    cmd: dict[str, Any]

    if opcode8 == 1:
        dwords = ((w0 >> 8) & 0xF) + 1
        if not (2 <= dwords <= 4 and need(data, off, dwords)):
            raise ValueError("invalid WaitOnAddress length")
        ref = 0
        if dwords >= 3:
            ref = u32(data, off + 8)
            if dwords >= 4:
                ref |= u32(data, off + 12) << 32
        cmd = {
            "name": "WaitOnAddress",
            "dwords": dwords,
            "address": packed_addr(w0, u32(data, off + 4)),
            "reference_value": ref,
            "compare": (w0 >> 13) & 7,
            "flush": bool((w0 >> 12) & 1),
        }
        cmd["compare_name"] = WAIT_COMPARE_NAMES.get(cmd["compare"], "unknown")
        return cmd

    if opcode8 == 2:
        dwords = ((w0 >> 8) & 0xF) + 1
        if dwords == 4 or not (1 <= dwords <= 5 and need(data, off, dwords)):
            raise ValueError("invalid WaitOnCounter length")
        cmd = {
            "name": "WaitOnCounter",
            "dwords": dwords,
            "counter_index": (w0 >> 24) & 0xFF,
            "compare": (w0 >> 13) & 7,
            "flush": bool((w0 >> 12) & 1),
            "reference_value": (w0 >> 16) & 0xFF,
            "value_width_selector": 1,
            "value_width_bits": 32,
        }
        cmd["compare_name"] = WAIT_COMPARE_NAMES.get(cmd["compare"], "unknown")
        if dwords >= 2:
            decode_wait_counter_extra(data, off, dwords, cmd)
        return cmd

    if opcode8 in (5, 117):
        dwords = ((w0 >> 8) & 3) + 1
        if not (2 <= dwords <= 4 and need(data, off, dwords)):
            raise ValueError("invalid WriteAddress length")
        w1 = u32(data, off + 4)
        address_class = w1 & 7
        immediate = opcode8 == 117
        value = (w0 >> 12) & 3
        if dwords >= 3:
            value |= u32(data, off + 8) << 2
            if dwords >= 4:
                value |= u32(data, off + 12) << 34
        names = {
            1: "WriteAddressFromTimeCounter",
            2: "WriteAddressFromCounter",
            3: "WriteAddressFromCounterPair",
        }
        name = names.get(address_class, "WriteAddress")
        cmd = {
            "name": name,
            "dwords": dwords,
            "address": packed_addr(w0, w1 & 0xFFFFFFF8),
            "timing": "immediate" if immediate else "on-completion",
        }
        if address_class in (2, 3):
            cmd["counter_index"] = value & 0xFF
        elif address_class == 0:
            cmd["value"] = value
        return cmd

    if opcode8 in (6, 118):
        dwords = ((w0 >> 8) & 0xF) + 1
        if not (1 <= dwords <= 3 and need(data, off, dwords)):
            raise ValueError("invalid WriteCounter length")
        value = (w0 >> 12) & 0xFFF
        value_width = 1
        op = 0
        if dwords >= 2:
            w1 = u32(data, off + 4)
            value |= (w1 & 0xFFFFF) << 12
            value_width = ((w1 >> 20) & 7) ^ 1
            op = (w1 >> 24) & 7
            if dwords >= 3:
                value |= u32(data, off + 8) << 32
        return {
            "name": "WriteCounter",
            "dwords": dwords,
            "counter_index": (w0 >> 24) & 0xFF,
            "value": value,
            "value_width_selector": value_width,
            "value_width_bits": counter_width_bits(value_width),
            "operation": op,
            "operation_name": WRITE_COUNTER_OP_NAMES.get(op, "unknown"),
            "timing": "immediate" if opcode8 == 118 else "on-completion",
        }

    if opcode12 in (1032, 1144):
        dwords = 5
        if not need(data, off, dwords):
            raise ValueError("truncated WriteKernelEventQueue")
        return {
            "name": "WriteKernelEventQueue",
            "dwords": dwords,
            "equeue": packed_addr(w0, u32(data, off + 4)),
            "event_id": u32(data, off + 8),
            "data": u32(data, off + 12) | (u32(data, off + 16) << 32),
            "timing": "immediate" if opcode12 == 1144 else "on-completion",
        }

    if (w0 & 0xFFFF000F) == 0x5452000F:
        marker_type = (w0 >> 12) & 0xF
        payload_dwords = (w0 >> 8) & 0xF
        dwords = payload_dwords + 1
        if not need(data, off, dwords):
            raise ValueError("truncated NOP/marker packet")
        if w0 == 0x5452300F:
            return {"name": "MarkerPop", "dwords": 1}
        payload_start = off + 4
        payload_end = off + dwords * 4
        if marker_type in (1, 2, 5, 6):
            color = None
            if marker_type in (5, 6):
                if payload_dwords < 1:
                    raise ValueError("marker with color has no color dword")
                color = u32(data, payload_start)
                payload_start += 4
            raw = data[payload_start:payload_end]
            text_chunk = raw.split(b"\0", 1)[0].decode("utf-8", errors="replace")
            cmd = {
                "name": "MarkerSet" if marker_type in (1, 5) else "MarkerPush",
                "dwords": dwords,
                "text_chunk": text_chunk,
                "marker_type": marker_type,
            }
            if color is not None:
                cmd["color"] = color
            return cmd
        if marker_type == 4:
            raw = data[payload_start:payload_end]
            return {
                "name": "MarkerContinuation",
                "dwords": dwords,
                "text_chunk": raw.split(b"\0", 1)[0].decode("utf-8", errors="replace"),
            }
        return {
            "name": "Nop",
            "dwords": dwords,
            "payload_hex": data[payload_start:payload_end].hex(),
        }

    if opcode8 == 40:
        dwords = ((w0 >> 8) & 7) + 1
        if not (5 <= dwords <= 6 and need(data, off, dwords)):
            raise ValueError("invalid AprReadFile length")
        w4 = u32(data, off + 16)
        file_offset = ((w0 >> 12) & 0x3FFFF) | (w4 & 0xFFFC0000)
        if dwords >= 6:
            file_offset |= (u32(data, off + 20) & 0xFF) << 32
        return {
            "name": "AprReadFile",
            "dwords": dwords,
            "length": u32(data, off + 4) + 1,
            "file_id": u32(data, off + 8) & 0x7FFFFFFF,
            "buffer": u32(data, off + 12) | ((w4 & 0xFFFF) << 32),
            "file_offset": file_offset,
        }

    if opcode8 == 41:
        dwords = ((w0 >> 8) & 3) + 1
        if not (2 <= dwords <= 3 and need(data, off, dwords)):
            raise ValueError("invalid AprReadGather length")
        file_offset = (w0 >> 12) & 0x3FFFF
        if dwords >= 3:
            file_offset |= (u32(data, off + 8) & 0x3FFFFF) << 18
        return {
            "name": "AprReadGather",
            "dwords": dwords,
            "length": u32(data, off + 4) + 1,
            "file_offset": file_offset,
        }

    if opcode12 == 0x22A:
        dwords = 3
        if not need(data, off, dwords):
            raise ValueError("truncated AprReadScatter")
        return {
            "name": "AprReadScatter",
            "dwords": dwords,
            "length": u32(data, off + 4) + 1,
            "buffer": u32(data, off + 8) | (((w0 >> 12) & 0xFFFF) << 32),
        }

    if opcode8 == 43:
        dwords = ((w0 >> 8) & 7) + 1
        if not (4 <= dwords <= 5 and need(data, off, dwords)):
            raise ValueError("invalid AprReadGatherScatter length")
        w3 = u32(data, off + 12)
        file_offset = ((w0 >> 12) & 0x3FFFF) | (w3 & 0xFFFC0000)
        if dwords >= 5:
            file_offset |= (u32(data, off + 16) & 0xFF) << 32
        return {
            "name": "AprReadGatherScatter",
            "dwords": dwords,
            "length": u32(data, off + 4) + 1,
            "buffer": u32(data, off + 8) | ((w3 & 0xFFFF) << 32),
            "file_offset": file_offset,
        }

    if w0 == 47:
        return {"name": "AprResetGatherScatterState", "dwords": 1}

    if opcode12 == 557:
        dwords = 3
        if not need(data, off, dwords):
            raise ValueError("truncated AprMapBegin")
        w1, w2 = u32(data, off + 4), u32(data, off + 8)
        return {
            "name": "AprMapBegin",
            "dwords": dwords,
            "va": (w1 << 14) | ((w2 & 3) << 46),
            "size": (w2 & 0x1FFFFFFC) << 12,
            "prot": (w0 >> 12) & 0x7FFF,
            "memory_type": (w0 >> 27) & 0x1F,
        }

    if opcode12 == 813:
        dwords = 4
        if not need(data, off, dwords):
            raise ValueError("truncated AprMapDirectBegin")
        w1, w2 = u32(data, off + 4), u32(data, off + 8)
        return {
            "name": "AprMapDirectBegin",
            "dwords": dwords,
            "va": (w1 << 14) | ((w2 & 3) << 46),
            "size": (w2 & 0x1FFFFFFC) << 12,
            "direct_memory_offset": (u32(data, off + 12) & 0x03FFFFFF) << 14,
            "prot": (w0 >> 12) & 0x7FFF,
            "memory_type": (w0 >> 27) & 0x1F,
        }

    if w0 == 46:
        return {"name": "AprMapEnd", "dwords": 1}

    amm = decode_amm(data, off, w0)
    if amm is not None:
        return amm

    guessed_dwords = ((w0 >> 8) & 0xF) + 1
    if not need(data, off, guessed_dwords):
        guessed_dwords = 1
    return {
        "name": "Unknown",
        "dwords": guessed_dwords,
        "word0": w0,
        "raw_hex": data[off:off + guessed_dwords * 4].hex(),
    }


def decode_records(records: list[SubmitRecord]) -> None:
    for record in records:
        off = 0
        ordinal = 0
        while off < len(record.payload):
            try:
                command = decode_command(record.payload, off)
            except (ValueError, struct.error) as exc:
                record.decode_errors.append(f"offset 0x{off:x}: {exc}")
                break
            dwords = int(command.get("dwords", 0))
            size = dwords * 4
            if size <= 0 or off + size > len(record.payload):
                record.decode_errors.append(f"offset 0x{off:x}: decoder returned invalid size {size}")
                break
            command["ordinal"] = ordinal
            command["offset"] = off
            command["bytes"] = size
            command["word0"] = u32(record.payload, off)
            command["raw_hex"] = record.payload[off:off + size].hex()
            record.commands.append(command)
            off += size
            ordinal += 1
        if off != len(record.payload):
            record.decode_errors.append(
                f"decoded 0x{off:x} of 0x{len(record.payload):x} bytes; trailing=0x{len(record.payload) - off:x}"
            )
        active_marker: Optional[dict[str, Any]] = None
        for command in record.commands:
            if command["name"] in ("MarkerSet", "MarkerPush"):
                command["text"] = command.get("text_chunk", "")
                active_marker = command
            elif command["name"] == "MarkerContinuation" and active_marker is not None:
                active_marker["text"] += command.get("text_chunk", "")
                command["continuation_of"] = active_marker["ordinal"]
            else:
                active_marker = None

        if record.command_count and len(record.commands) != record.command_count:
            # Marker continuation records are counted as commands in the packed
            # stream, so a mismatch is still useful evidence of a decode gap.
            record.decode_errors.append(
                f"header command_count={record.command_count}, decoded={len(record.commands)}"
            )


def annotate_apr_state(
    records: list[SubmitRecord],
    index: dict[int, IndexEntry],
) -> list[LogicalRead]:
    gather_state: dict[int, GatherState] = {}
    map_depth: Counter[int] = Counter()
    logical_reads: list[LogicalRead] = []
    logical_by_id: dict[str, LogicalRead] = {}

    def start_read(record: SubmitRecord, command: dict[str, Any]) -> GatherState:
        file_id = int(command["file_id"])
        entry = index.get(file_id)
        logical_id = f"apr{record.priority}:seq{record.sequence}:cmd{command['ordinal']}"
        state = GatherState(
            logical_read_id=logical_id,
            file_id=file_id,
            path=entry.path if entry else None,
            file_size=entry.size if entry else None,
            next_file_offset=int(command["file_offset"]) + int(command["length"]),
            next_output_address=int(command["buffer"]) + int(command["length"]),
        )
        logical = LogicalRead(
            logical_read_id=logical_id,
            priority=record.priority,
            first_sequence=record.sequence,
            file_id=file_id,
            path=state.path,
            file_size=state.file_size,
        )
        logical_reads.append(logical)
        logical_by_id[logical_id] = logical
        return state

    def annotate_segment(
        record: SubmitRecord,
        command: dict[str, Any],
        state: GatherState,
        file_offset: int,
        buffer: int,
        inferred_source: bool,
        inferred_destination: bool,
    ) -> None:
        length = int(command["length"])
        command["logical_read_id"] = state.logical_read_id
        command["file_id"] = state.file_id
        command["path"] = state.path
        command["file_size"] = state.file_size
        command["effective_file_offset"] = file_offset
        command["effective_buffer"] = buffer
        command["source_offset_inferred"] = inferred_source
        command["destination_inferred"] = inferred_destination
        if state.file_size is not None:
            command["out_of_file_bounds"] = file_offset + length > state.file_size
            full = file_offset == 0 and length == state.file_size
            command["full_file_read"] = full
            command["dispatch_quanta"] = math.ceil(length / APR_DISPATCH_QUANTUM)
            command["fd_policy"] = "direct" if full and state.file_size <= APR_DISPATCH_QUANTUM else "cache"
            if not full:
                command["fd_policy_reason"] = "partial-read"
            elif state.file_size > APR_DISPATCH_QUANTUM:
                command["fd_policy_reason"] = "full-file-multi-quantum"
            else:
                command["fd_policy_reason"] = "full-file-single-quantum"
        else:
            command["fd_policy"] = "cache"
            command["fd_policy_reason"] = "unknown-file-size"
        logical_by_id[state.logical_read_id].segments.append(
            {
                "sequence": record.sequence,
                "command_ordinal": command["ordinal"],
                "kind": command["name"],
                "file_offset": file_offset,
                "buffer": buffer,
                "length": length,
                "source_offset_inferred": inferred_source,
                "destination_inferred": inferred_destination,
            }
        )

    for record in sorted(records, key=lambda r: r.sequence):
        if record.domain != 1:
            continue
        lane = record.priority
        for command in record.commands:
            name = command["name"]
            if name == "AprReadFile":
                state = start_read(record, command)
                gather_state[lane] = state
                if state.path is None:
                    command["index_missing"] = True
                annotate_segment(
                    record,
                    command,
                    state,
                    int(command["file_offset"]),
                    int(command["buffer"]),
                    False,
                    False,
                )
            elif name == "AprReadGather":
                state = gather_state.get(lane)
                if state is None:
                    command["state_error"] = "no-active-gather-scatter-state"
                    continue
                file_offset = int(command["file_offset"])
                buffer = state.next_output_address
                annotate_segment(record, command, state, file_offset, buffer, False, True)
                state.next_file_offset = file_offset + int(command["length"])
                state.next_output_address = buffer + int(command["length"])
            elif name == "AprReadScatter":
                state = gather_state.get(lane)
                if state is None:
                    command["state_error"] = "no-active-gather-scatter-state"
                    continue
                file_offset = state.next_file_offset
                buffer = int(command["buffer"])
                annotate_segment(record, command, state, file_offset, buffer, True, False)
                state.next_file_offset = file_offset + int(command["length"])
                state.next_output_address = buffer + int(command["length"])
            elif name == "AprReadGatherScatter":
                state = gather_state.get(lane)
                if state is None:
                    command["state_error"] = "no-active-gather-scatter-state"
                    continue
                file_offset = int(command["file_offset"])
                buffer = int(command["buffer"])
                annotate_segment(record, command, state, file_offset, buffer, False, False)
                state.next_file_offset = file_offset + int(command["length"])
                state.next_output_address = buffer + int(command["length"])
            elif name == "AprResetGatherScatterState":
                gather_state.pop(lane, None)
            elif name in ("AprMapBegin", "AprMapDirectBegin"):
                command["map_depth_before"] = map_depth[lane]
                map_depth[lane] += 1
                command["map_depth_after"] = map_depth[lane]
            elif name == "AprMapEnd":
                command["map_depth_before"] = map_depth[lane]
                if map_depth[lane] == 0:
                    command["state_error"] = "map-end-without-map-begin"
                else:
                    map_depth[lane] -= 1
                command["map_depth_after"] = map_depth[lane]

    for lane, depth in map_depth.items():
        if depth:
            # Attach a synthetic note to the final APR record of this lane.
            for record in reversed(records):
                if record.domain == 1 and record.priority == lane:
                    record.decode_errors.append(f"APR map section left open at end of trace: depth={depth}")
                    break
    return logical_reads


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    pos = (len(ordered) - 1) * pct / 100.0
    lo = math.floor(pos)
    hi = math.ceil(pos)
    if lo == hi:
        return float(ordered[lo])
    frac = pos - lo
    return float(ordered[lo] * (1.0 - frac) + ordered[hi] * frac)


def union_length(ranges: Iterable[tuple[int, int]]) -> int:
    merged = 0
    current_start: Optional[int] = None
    current_end: Optional[int] = None
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
            merged += current_end - current_start
            current_start, current_end = start, end
    if current_start is not None and current_end is not None:
        merged += current_end - current_start
    return merged


def build_statistics(
    records: list[SubmitRecord],
    logical_reads: list[LogicalRead],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    by_domain = Counter(DOMAIN_NAMES.get(r.domain, str(r.domain)) for r in records)
    by_mode = Counter(MODE_NAMES.get(r.submit_mode, str(r.submit_mode)) for r in records)
    by_priority = Counter(f"{DOMAIN_NAMES.get(r.domain, r.domain)}:{r.priority}" for r in records)
    command_mix = Counter(cmd["name"] for r in records for cmd in r.commands)
    decode_error_count = sum(len(r.decode_errors) for r in records)

    buffer_sizes = [r.payload_bytes for r in records]
    decoded_counts = [len(r.commands) for r in records]
    timed_records = sorted((r for r in records if r.monotonic_ns), key=lambda r: (r.monotonic_ns, r.sequence))
    gaps_us = [
        (b.monotonic_ns - a.monotonic_ns) / 1000.0
        for a, b in zip(timed_records, timed_records[1:])
        if a.monotonic_ns and b.monotonic_ns and b.monotonic_ns >= a.monotonic_ns
    ]

    hash_groups: dict[tuple[int, int, int], list[int]] = defaultdict(list)
    for record in records:
        hash_groups[(record.domain, record.payload_hash, record.payload_bytes)].append(record.sequence)
    duplicate_groups = [seqs for seqs in hash_groups.values() if len(seqs) > 1]

    file_stats: dict[str, dict[str, Any]] = {}
    direct_reads = 0
    direct_bytes = 0
    cached_reads = 0
    cached_bytes = 0
    cached_partial = 0
    cached_multi_quantum_full = 0
    tiny_read_commands = 0
    read_command_count = 0
    read_command_bytes = 0
    out_of_bounds = 0
    read_size_buckets = {
        "le_64k": {"commands": 0, "bytes": 0},
        "gt_64k_le_256k": {"commands": 0, "bytes": 0},
        "gt_256k_lt_512k": {"commands": 0, "bytes": 0},
        "eq_512k": {"commands": 0, "bytes": 0},
        "gt_512k": {"commands": 0, "bytes": 0},
    }

    for record in records:
        for cmd in record.commands:
            if cmd["name"] not in ("AprReadFile", "AprReadGather", "AprReadScatter", "AprReadGatherScatter"):
                continue
            read_command_count += 1
            length = int(cmd.get("length", 0))
            read_command_bytes += length
            if length <= TINY_READ:
                tiny_read_commands += 1
                bucket = read_size_buckets["le_64k"]
            elif length <= 256 * 1024:
                bucket = read_size_buckets["gt_64k_le_256k"]
            elif length < APR_DISPATCH_QUANTUM:
                bucket = read_size_buckets["gt_256k_lt_512k"]
            elif length == APR_DISPATCH_QUANTUM:
                bucket = read_size_buckets["eq_512k"]
            else:
                bucket = read_size_buckets["gt_512k"]
            bucket["commands"] += 1
            bucket["bytes"] += length
            if cmd.get("out_of_file_bounds"):
                out_of_bounds += 1
            policy = cmd.get("fd_policy")
            if policy == "direct":
                direct_reads += 1
                direct_bytes += length
            else:
                cached_reads += 1
                cached_bytes += length
                if cmd.get("fd_policy_reason") == "partial-read":
                    cached_partial += 1
                elif cmd.get("fd_policy_reason") == "full-file-multi-quantum":
                    cached_multi_quantum_full += 1

    for logical in logical_reads:
        key = logical.path or f"fileId:{logical.file_id}"
        stat = file_stats.setdefault(
            key,
            {
                "path": logical.path,
                "file_id": logical.file_id,
                "file_size": logical.file_size,
                "gather_scatter_groups": 0,
                "segments": 0,
                "submitted_bytes": 0,
                "ranges": [],
                "priorities": Counter(),
            },
        )
        stat["gather_scatter_groups"] += 1
        stat["segments"] += len(logical.segments)
        stat["submitted_bytes"] += logical.total_bytes
        stat["priorities"][logical.priority] += 1
        for segment in logical.segments:
            start = int(segment["file_offset"])
            stat["ranges"].append((start, start + int(segment["length"])))

    file_rows: list[dict[str, Any]] = []
    for stat in file_stats.values():
        covered = union_length(stat.pop("ranges"))
        stat["unique_file_bytes_touched"] = covered
        if stat["file_size"]:
            stat["coverage_ratio"] = min(1.0, covered / stat["file_size"])
        else:
            stat["coverage_ratio"] = None
        stat["priorities"] = {str(k): v for k, v in sorted(stat["priorities"].items())}
        file_rows.append(stat)
    file_rows.sort(key=lambda row: (row["submitted_bytes"], row["gather_scatter_groups"]), reverse=True)

    single_command_submits = sum(1 for r in records if len(r.commands) == 1)
    stats: dict[str, Any] = {
        "submits": {
            "count": len(records),
            "payload_bytes": sum(buffer_sizes),
            "by_domain": dict(by_domain),
            "by_mode": dict(by_mode),
            "by_priority": dict(sorted(by_priority.items())),
            "single_command_submits": single_command_submits,
            "single_command_ratio": single_command_submits / len(records) if records else 0.0,
            "buffer_bytes": {
                "min": min(buffer_sizes) if buffer_sizes else 0,
                "max": max(buffer_sizes) if buffer_sizes else 0,
                "mean": sum(buffer_sizes) / len(buffer_sizes) if buffer_sizes else 0.0,
                "p50": percentile([float(v) for v in buffer_sizes], 50),
                "p95": percentile([float(v) for v in buffer_sizes], 95),
                "p99": percentile([float(v) for v in buffer_sizes], 99),
            },
            "decoded_commands": {
                "total": sum(decoded_counts),
                "mean_per_submit": sum(decoded_counts) / len(decoded_counts) if decoded_counts else 0.0,
                "max_per_submit": max(decoded_counts) if decoded_counts else 0,
            },
            "inter_submit_gap_us": {
                "count": len(gaps_us),
                "p50": percentile(gaps_us, 50),
                "p95": percentile(gaps_us, 95),
                "p99": percentile(gaps_us, 99),
                "max": max(gaps_us) if gaps_us else 0.0,
            },
            "identical_payload_groups": len(duplicate_groups),
            "identical_payload_repeated_submits": sum(len(group) for group in duplicate_groups),
        },
        "commands": {
            "mix": dict(command_mix.most_common()),
            "decode_error_count": decode_error_count,
        },
        "apr_reads": {
            "gather_scatter_groups": len(logical_reads),
            "read_commands": read_command_count,
            "submitted_bytes": read_command_bytes,
            "tiny_le_64k_commands": tiny_read_commands,
            "tiny_le_64k_ratio": tiny_read_commands / read_command_count if read_command_count else 0.0,
            "out_of_file_bounds": out_of_bounds,
            "size_buckets": read_size_buckets,
            "fd_policy": {
                "direct_full_single_quantum_reads": direct_reads,
                "direct_bytes": direct_bytes,
                "cached_reads": cached_reads,
                "cached_bytes": cached_bytes,
                "cached_partial_reads": cached_partial,
                "cached_full_multi_quantum_reads": cached_multi_quantum_full,
            },
        },
        "files": {
            "unique": len(file_rows),
            "top_by_submitted_bytes": file_rows[:50],
        },
    }

    findings: list[dict[str, Any]] = []
    if records:
        single_ratio = stats["submits"]["single_command_ratio"]
        if single_ratio >= 0.50 and len(records) >= 20:
            findings.append({
                "severity": "info",
                "kind": "submit-fragmentation",
                "message": (
                    f"{single_ratio:.1%} of submits contain one decoded command. "
                    "If title-side ordering permits it, larger command buffers could reduce submit/wakeup overhead."
                ),
            })
    if read_command_count and tiny_read_commands / read_command_count >= 0.50:
        findings.append({
            "severity": "info",
            "kind": "small-read-density",
            "message": (
                f"{tiny_read_commands}/{read_command_count} APR read commands are <=64 KiB. "
                "Check whether adjacent ranges can be expressed as gather/scatter chains or benefit from retained cached FDs."
            ),
        })
    if cached_partial:
        findings.append({
            "severity": "info",
            "kind": "fd-cache-partial-reads",
            "message": (
                f"{cached_partial} APR read commands are partial-file reads and therefore correctly use the FD cache under the new policy."
            ),
        })
    if cached_multi_quantum_full:
        findings.append({
            "severity": "info",
            "kind": "fd-cache-large-full-reads",
            "message": (
                f"{cached_multi_quantum_full} full-file reads exceed 512 KiB and therefore retain cached FDs across multi-quantum chains. "
                "These are the best traces for measuring whether >1 active quantum per ReadChain improves throughput."
            ),
        })
    hot = [row for row in file_rows if row["gather_scatter_groups"] >= 4]
    if hot:
        top = hot[:5]
        findings.append({
            "severity": "info",
            "kind": "hot-files",
            "message": "Repeated APR access is concentrated in: " + ", ".join(
                f"{row['path'] or 'fileId:'+str(row['file_id'])} ({row['gather_scatter_groups']} gather/scatter groups)" for row in top
            ),
        })
    low_coverage_hot = [
        row for row in file_rows
        if row["gather_scatter_groups"] >= 4 and row["coverage_ratio"] is not None and row["coverage_ratio"] < 0.25
    ]
    if low_coverage_hot:
        findings.append({
            "severity": "info",
            "kind": "hot-low-coverage-files",
            "message": (
                f"{len(low_coverage_hot)} repeatedly accessed files touch <25% of file contents. "
                "Keeping their descriptors hot is likely more useful than full-file prefetching."
            ),
        })
    if duplicate_groups and sum(len(g) for g in duplicate_groups) >= max(10, len(records) // 4):
        findings.append({
            "severity": "info",
            "kind": "repeated-command-buffers",
            "message": (
                f"{sum(len(g) for g in duplicate_groups)} submits belong to identical packed-buffer groups. "
                "Consider measuring decode/cache reuse before adding more scheduler complexity."
            ),
        })
    if decode_error_count:
        findings.append({
            "severity": "warning",
            "kind": "decode-errors",
            "message": (
                f"The parser reported {decode_error_count} decode/state warnings. Optimization conclusions involving those records should be treated as incomplete."
            ),
        })
    return stats, findings


def iso_utc(ns: int) -> str:
    if not ns:
        return "unavailable"
    seconds, nanos = divmod(ns, 1_000_000_000)
    dt = datetime.fromtimestamp(seconds, timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{nanos:09d}Z"


def hex_or_none(value: Any) -> str:
    return "-" if value is None else f"0x{int(value):x}"


def format_command(cmd: dict[str, Any]) -> str:
    name = cmd["name"]
    prefix = f"    [{cmd['ordinal']:04d}] +0x{cmd['offset']:05x} {name} ({cmd['bytes']} B)"
    if name == "AprReadFile":
        path = cmd.get("path") or f"fileId={cmd.get('file_id')}"
        return (
            f"{prefix} {path} fileOff=0x{cmd['file_offset']:x} len=0x{cmd['length']:x} "
            f"dst=0x{cmd['buffer']:x} policy={cmd.get('fd_policy','?')} reason={cmd.get('fd_policy_reason','?')}"
        )
    if name in ("AprReadGather", "AprReadScatter", "AprReadGatherScatter"):
        return (
            f"{prefix} logical={cmd.get('logical_read_id','?')} path={cmd.get('path','?')} "
            f"fileOff={hex_or_none(cmd.get('effective_file_offset'))} len=0x{cmd.get('length',0):x} "
            f"dst={hex_or_none(cmd.get('effective_buffer'))}"
        )
    if name == "WaitOnAddress":
        return f"{prefix} addr=0x{cmd['address']:x} ref=0x{cmd['reference_value']:x} cmp={cmd['compare_name']} flush={int(cmd['flush'])}"
    if name == "WaitOnCounter":
        return f"{prefix} idx={cmd['counter_index']} ref=0x{cmd['reference_value']:x} cmp={cmd['compare_name']} width={cmd['value_width_bits']} flush={int(cmd['flush'])}"
    if name == "WriteAddress":
        return f"{prefix} addr=0x{cmd['address']:x} value=0x{cmd.get('value',0):x} timing={cmd['timing']}"
    if name == "WriteCounter":
        return f"{prefix} idx={cmd['counter_index']} value=0x{cmd['value']:x} op={cmd['operation_name']} width={cmd['value_width_bits']} timing={cmd['timing']}"
    if name == "WriteKernelEventQueue":
        return f"{prefix} eq=0x{cmd['equeue']:x} id={cmd['event_id']} data=0x{cmd['data']:x} timing={cmd['timing']}"
    if name.startswith("AprMap"):
        args = []
        for key in ("va", "size", "direct_memory_offset", "memory_type", "prot"):
            if key in cmd:
                args.append(f"{key}=0x{int(cmd[key]):x}")
        return prefix + (" " + " ".join(args) if args else "")
    if name.startswith("Amm"):
        args = []
        for key in ("va", "va_new", "va_old_or_alias", "size", "direct_memory_offset", "memory_type", "prot", "prot_mask", "gpu_mask_id"):
            if key in cmd:
                args.append(f"{key}=0x{int(cmd[key]):x}")
        return prefix + (" " + " ".join(args) if args else "")
    if name.startswith("Marker"):
        return prefix + (f" text={cmd.get('text_chunk','')!r}" if "text_chunk" in cmd else "")
    if name == "Unknown":
        return f"{prefix} word0=0x{cmd['word0']:08x} raw={cmd.get('raw_hex','')}"
    return prefix


def render_text(
    dump_path: Path,
    index_path: Path,
    records: list[SubmitRecord],
    warnings: list[str],
    logical_reads: list[LogicalRead],
    stats: dict[str, Any],
    findings: list[dict[str, Any]],
) -> str:
    lines: list[str] = []
    lines.append("AMPR command journal analysis")
    lines.append(f"dump:  {dump_path}")
    lines.append(f"index: {index_path}")
    lines.append("")
    lines.append("SUMMARY")
    lines.append(f"  submits: {stats['submits']['count']}")
    lines.append(f"  payload bytes: {stats['submits']['payload_bytes']}")
    lines.append(f"  decoded commands: {stats['submits']['decoded_commands']['total']}")
    lines.append(f"  APR gather/scatter groups: {stats['apr_reads']['gather_scatter_groups']}")
    lines.append(f"  APR submitted bytes: {stats['apr_reads']['submitted_bytes']}")
    lines.append(f"  domains: {stats['submits']['by_domain']}")
    lines.append(f"  modes: {stats['submits']['by_mode']}")
    lines.append(f"  priorities: {stats['submits']['by_priority']}")
    lines.append(
        "  command buffer bytes: "
        f"mean={stats['submits']['buffer_bytes']['mean']:.1f} "
        f"p50={stats['submits']['buffer_bytes']['p50']:.1f} "
        f"p95={stats['submits']['buffer_bytes']['p95']:.1f} "
        f"p99={stats['submits']['buffer_bytes']['p99']:.1f} "
        f"max={stats['submits']['buffer_bytes']['max']}"
    )
    lines.append(
        "  inter-submit gap us: "
        f"p50={stats['submits']['inter_submit_gap_us']['p50']:.1f} "
        f"p95={stats['submits']['inter_submit_gap_us']['p95']:.1f} "
        f"p99={stats['submits']['inter_submit_gap_us']['p99']:.1f} "
        f"max={stats['submits']['inter_submit_gap_us']['max']:.1f}"
    )
    fd = stats["apr_reads"]["fd_policy"]
    buckets = stats["apr_reads"]["size_buckets"]
    lines.append(
        "  APR read sizes: "
        f"<=64KiB={buckets['le_64k']['commands']}, "
        f">64..256KiB={buckets['gt_64k_le_256k']['commands']}, "
        f">256..<512KiB={buckets['gt_256k_lt_512k']['commands']}, "
        f"=512KiB={buckets['eq_512k']['commands']}, "
        f">512KiB={buckets['gt_512k']['commands']}"
    )
    lines.append(
        "  FD policy: "
        f"direct(full <=512KiB)={fd['direct_full_single_quantum_reads']} / {fd['direct_bytes']} B, "
        f"cached={fd['cached_reads']} / {fd['cached_bytes']} B "
        f"(partial={fd['cached_partial_reads']}, full>512KiB={fd['cached_full_multi_quantum_reads']})"
    )
    lines.append("")
    lines.append("COMMAND MIX")
    for name, count in stats["commands"]["mix"].items():
        lines.append(f"  {name}: {count}")

    lines.append("")
    lines.append("TOP FILES BY SUBMITTED APR BYTES")
    for row in stats["files"]["top_by_submitted_bytes"][:20]:
        coverage = "?" if row["coverage_ratio"] is None else f"{row['coverage_ratio']:.1%}"
        lines.append(
            f"  {row['submitted_bytes']:>12} B  groups={row['gather_scatter_groups']:<6} "
            f"segments={row['segments']:<6} coverage={coverage:<8} {row['path'] or 'fileId:'+str(row['file_id'])}"
        )

    lines.append("")
    lines.append("OPTIMIZATION CANDIDATES")
    if findings:
        for finding in findings:
            lines.append(f"  [{finding['severity']}] {finding['kind']}: {finding['message']}")
    else:
        lines.append("  no rule-based candidates triggered")

    if warnings:
        lines.append("")
        lines.append("JOURNAL WARNINGS")
        for warning in warnings:
            lines.append(f"  - {warning}")

    lines.append("")
    lines.append("COMMAND TIMELINE")
    for record in sorted(records, key=lambda r: r.sequence):
        lines.append("")
        lines.append(
            f"[{record.sequence:08d}] {iso_utc(record.utc_ns)} mono={record.monotonic_ns} "
            f"domain={DOMAIN_NAMES.get(record.domain,record.domain)} prio={record.priority} "
            f"mode={MODE_NAMES.get(record.submit_mode,record.submit_mode)} cookie=0x{record.submit_cookie:x} "
            f"src=0x{record.source_address:x} bytes=0x{record.payload_bytes:x} "
            f"commands={record.command_count or len(record.commands)} hash=0x{record.payload_hash:016x} flags=0x{record.flags:x}"
        )
        for command in record.commands:
            lines.append(format_command(command))
        for error in record.decode_errors:
            lines.append(f"    ! {error}")

    lines.append("")
    lines.append("APR GATHER/SCATTER GROUPS")
    for logical in logical_reads:
        lines.append(
            f"  {logical.logical_read_id} prio={logical.priority} fileId={logical.file_id} "
            f"bytes=0x{logical.total_bytes:x} segments={len(logical.segments)} path={logical.path or '?'}"
        )
        for segment in logical.segments:
            lines.append(
                f"      seq={segment['sequence']} cmd={segment['command_ordinal']} {segment['kind']} "
                f"fileOff=0x{segment['file_offset']:x} len=0x{segment['length']:x} dst=0x{segment['buffer']:x}"
            )
    lines.append("")
    return "\n".join(lines)


def json_command(command: dict[str, Any]) -> dict[str, Any]:
    return dict(command)


def build_json_document(
    dump_path: Path,
    index_path: Path,
    records: list[SubmitRecord],
    warnings: list[str],
    logical_reads: list[LogicalRead],
    stats: dict[str, Any],
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "format": "ampr-command-journal-analysis",
        "version": 1,
        "inputs": {"dump": str(dump_path), "index": str(index_path)},
        "warnings": warnings,
        "statistics": stats,
        "optimization_candidates": findings,
        "apr_gather_scatter_groups": [
            {
                "id": logical.logical_read_id,
                "priority": logical.priority,
                "first_sequence": logical.first_sequence,
                "file_id": logical.file_id,
                "path": logical.path,
                "file_size": logical.file_size,
                "total_bytes": logical.total_bytes,
                "segments": logical.segments,
            }
            for logical in logical_reads
        ],
        "records": [
            {
                "sequence": r.sequence,
                "timestamp_utc": iso_utc(r.utc_ns),
                "utc_ns": r.utc_ns,
                "monotonic_ns": r.monotonic_ns,
                "submit_cookie": r.submit_cookie,
                "source_address": r.source_address,
                "payload_hash": r.payload_hash,
                "payload_bytes": r.payload_bytes,
                "source_capacity": r.source_capacity,
                "command_count_header": r.command_count,
                "command_count_decoded": len(r.commands),
                "priority": r.priority,
                "domain": DOMAIN_NAMES.get(r.domain, str(r.domain)),
                "submit_mode": MODE_NAMES.get(r.submit_mode, str(r.submit_mode)),
                "submit_type": r.submit_type,
                "flags": r.flags,
                "file_offset": r.file_offset,
                "decode_errors": r.decode_errors,
                "commands": [json_command(cmd) for cmd in r.commands],
            }
            for r in records
        ],
    }


def default_output_path(dump: Path, suffix: str) -> Path:
    return dump.with_name(dump.name + suffix)


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dump", type=Path, help="binary AMPR command journal (AMPRCMD1)")
    parser.add_argument("index", type=Path, help="AMPRIDX3 file index used by the trace")
    parser.add_argument("--text", type=Path, help="human-readable output path")
    parser.add_argument("--json", dest="json_path", type=Path, help="JSON output path")
    parser.add_argument("--stdout", action="store_true", help="also print the text report to stdout")
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    text_path = args.text or default_output_path(args.dump, ".decoded.txt")
    json_path = args.json_path or default_output_path(args.dump, ".decoded.json")
    try:
        index = load_index(args.index)
        records, warnings = read_command_log(args.dump)
        decode_records(records)
        logical_reads = annotate_apr_state(records, index)
        stats, findings = build_statistics(records, logical_reads)
        text = render_text(args.dump, args.index, records, warnings, logical_reads, stats, findings)
        document = build_json_document(args.dump, args.index, records, warnings, logical_reads, stats, findings)
        text_path.write_text(text, encoding="utf-8")
        json_path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except (OSError, ValueError, struct.error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"decoded {len(records)} submit records")
    print(f"wrote {text_path}")
    print(f"wrote {json_path}")
    if warnings:
        print(f"warning: {len(warnings)} journal warning(s); see report", file=sys.stderr)
    if args.stdout:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
