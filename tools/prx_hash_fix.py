#!/usr/bin/env python3
"""Rebuild only the SysV .hash section of an already linked SCE PRX."""

from __future__ import annotations

import argparse
import re
import struct
from dataclasses import dataclass
from pathlib import Path


SCE_ID_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-"
PRX_SYMBOL_RE = re.compile(r"^([A-Za-z0-9+\-]{11})#([^#])#([^#])$")
DT_NULL = 0
DT_SCE_MODULE_INFO = 0x61000043
DT_SCE_EXPORT_LIB = 0x61000047


class PrxError(ValueError):
    pass


def elf_hash(value: str | bytes) -> int:
    data = value.encode("utf-8") if isinstance(value, str) else value
    result = 0
    for byte in data:
        result = ((result << 4) + byte) & 0xFFFFFFFF
        result ^= (result >> 24) & 0xF0
    return result & 0x0FFFFFFF


def id_char(value: int) -> str:
    if not 0 <= value < len(SCE_ID_ALPHABET):
        raise PrxError(f"unsupported SCE short id: {value}")
    return SCE_ID_ALPHABET[value]


@dataclass(frozen=True)
class Section:
    name: str
    offset: int
    size: int
    link: int
    entsize: int


@dataclass(frozen=True)
class DynSym:
    index: int
    name: str
    st_shndx: int

    @property
    def nid_parts(self) -> tuple[str, str, str] | None:
        match = PRX_SYMBOL_RE.fullmatch(self.name)
        return match.groups() if match else None


@dataclass(frozen=True)
class ExportGroup:
    library: str
    module: str

    def canonical(self, nid: str) -> str:
        return f"{nid}#{self.library}#{self.module}"


class Elf64LE:
    def __init__(self, data: bytes):
        self.data = data
        if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01":
            raise PrxError("expected a little-endian ELF64 image")
        if struct.unpack_from("<H", data, 0x10)[0] != 0xFE18:
            raise PrxError("expected an ET_SCE_DYNAMIC PRX")

        shoff = struct.unpack_from("<Q", data, 0x28)[0]
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
        if shentsize < 64 or shoff + shentsize * shnum > len(data):
            raise PrxError("invalid ELF section table")

        raw = [
            struct.unpack_from("<IIQQQQIIQQ", data, shoff + index * shentsize)
            for index in range(shnum)
        ]
        if not 0 <= shstrndx < len(raw):
            raise PrxError("invalid section-name table index")
        strings_offset, strings_size = raw[shstrndx][4:6]
        strings = data[strings_offset:strings_offset + strings_size]

        self.sections: list[Section] = []
        for values in raw:
            name_offset = values[0]
            end = strings.find(b"\0", name_offset)
            name = strings[name_offset:end].decode("ascii") if end >= 0 else ""
            self.sections.append(
                Section(name, values[4], values[5], values[6], values[9])
            )

    def section(self, name: str) -> Section:
        for section in self.sections:
            if section.name == name:
                return section
        raise PrxError(f"missing PRX section: {name}")

    def str_at(self, table: Section, offset: int) -> str:
        start = table.offset + offset
        end = self.data.find(b"\0", start, table.offset + table.size)
        if not table.offset <= start < table.offset + table.size or end < 0:
            raise PrxError(f"invalid string offset 0x{offset:x} in {table.name}")
        return self.data[start:end].decode("ascii")

    def dynsyms(self) -> list[DynSym]:
        symbols = self.section(".dynsym")
        strings = self.section(".dynstr")
        if symbols.entsize < 24 or symbols.size % symbols.entsize:
            raise PrxError("invalid .dynsym layout")
        result = []
        for index in range(symbols.size // symbols.entsize):
            offset = symbols.offset + index * symbols.entsize
            st_name, _info, _other, st_shndx, _value, _size = struct.unpack_from(
                "<IBBHQQ", self.data, offset
            )
            name = self.str_at(strings, st_name) if st_name else ""
            result.append(DynSym(index, name, st_shndx))
        return result

    def hash_table(self) -> tuple[Section, int, int, list[int], list[int]]:
        section = self.section(".hash")
        if section.size < 8 or section.size % 4:
            raise PrxError("invalid .hash layout")
        words = list(
            struct.unpack_from(f"<{section.size // 4}I", self.data, section.offset)
        )
        nbucket, nchain = words[:2]
        if 2 + nbucket + nchain != len(words):
            raise PrxError("unexpected padding or truncation in .hash")
        return (
            section,
            nbucket,
            nchain,
            words[2:2 + nbucket],
            words[2 + nbucket:],
        )

    def dynamic_entries(self) -> list[tuple[int, int]]:
        section = self.section(".dynamic")
        if section.entsize < 16 or section.size % section.entsize:
            raise PrxError("invalid .dynamic layout")
        result = []
        for index in range(section.size // section.entsize):
            entry = struct.unpack_from(
                "<QQ", self.data, section.offset + index * section.entsize
            )
            result.append(entry)
            if entry[0] == DT_NULL:
                break
        return result

    def export_groups(self) -> dict[tuple[str, str], ExportGroup]:
        strings = self.section(".dynstr")
        modules: dict[int, str] = {}
        libraries: dict[int, str] = {}
        for tag, value in self.dynamic_entries():
            if tag == DT_SCE_MODULE_INFO:
                modules[(value >> 48) & 0xFFFF] = self.str_at(strings, value & 0xFFFFFFFF)
            elif tag == DT_SCE_EXPORT_LIB:
                libraries[(value >> 48) & 0xFFFF] = self.str_at(strings, value & 0xFFFFFFFF)
        return {
            (id_char(library_id), id_char(module_id)): ExportGroup(library, module)
            for library_id, library in libraries.items()
            for module_id, module in modules.items()
        }


def buckets_to_symbol_map(buckets: list[int], chains: list[int]) -> dict[int, int]:
    result: dict[int, int] = {}
    for bucket_index, head in enumerate(buckets):
        seen: set[int] = set()
        symbol_index = head
        while symbol_index:
            if symbol_index in seen or symbol_index >= len(chains):
                raise PrxError(f"invalid .hash chain in bucket {bucket_index}")
            seen.add(symbol_index)
            result[symbol_index] = bucket_index
            symbol_index = chains[symbol_index]
    return result


def rebuild_hash(
    nbucket: int, nchain: int, symbol_buckets: dict[int, int]
) -> tuple[list[int], list[int]]:
    buckets = [0] * nbucket
    chains = [0] * nchain
    for symbol_index in range(1, nchain):
        if symbol_index not in symbol_buckets:
            continue
        bucket_index = symbol_buckets[symbol_index]
        chains[symbol_index] = buckets[bucket_index]
        buckets[bucket_index] = symbol_index
    return buckets, chains


def fix_hash(data: bytes, expected_name: str = "libSceAmpr") -> tuple[bytes, int, int, int]:
    elf = Elf64LE(data)
    hash_section, nbucket, nchain, buckets, chains = elf.hash_table()
    symbol_buckets = buckets_to_symbol_map(buckets, chains)
    groups = elf.export_groups()
    if not groups:
        raise PrxError("PRX has no SCE export group")

    corrected = 0
    moved = 0
    for symbol in elf.dynsyms()[1:]:
        parts = symbol.nid_parts
        if symbol.st_shndx == 0 or parts is None:
            continue
        nid, library_id, module_id = parts
        group = groups.get((library_id, module_id))
        if group is None:
            continue
        if group.library != expected_name or group.module != expected_name:
            raise PrxError(
                f"unexpected export group {group.library!r}/{group.module!r}"
            )
        if symbol.index >= nchain or symbol.index not in symbol_buckets:
            raise PrxError(f"export symbol {symbol.index} is absent from .hash")
        new_bucket = elf_hash(group.canonical(nid)) % nbucket
        moved += symbol_buckets[symbol.index] != new_bucket
        symbol_buckets[symbol.index] = new_bucket
        corrected += 1

    if corrected == 0:
        raise PrxError("PRX has no matching SCE exports")
    new_buckets, new_chains = rebuild_hash(nbucket, nchain, symbol_buckets)
    words = [nbucket, nchain, *new_buckets, *new_chains]
    result = bytearray(data)
    struct.pack_into(f"<{len(words)}I", result, hash_section.offset, *words)

    for index, (before, after) in enumerate(zip(data, result)):
        if before != after and not (
            hash_section.offset <= index < hash_section.offset + hash_section.size
        ):
            raise PrxError(f"post-link correction escaped .hash at 0x{index:x}")
    return bytes(result), corrected, moved, nbucket


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--module", default="libSceAmpr")
    args = parser.parse_args()

    original = args.input.read_bytes()
    fixed, exports, moved, buckets = fix_hash(original, args.module)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(fixed)
    print(
        f"prx_hash_fixed exports={exports} moved={moved} buckets={buckets} "
        f"changed_bytes={sum(a != b for a, b in zip(original, fixed))}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
