#!/usr/bin/env python3
"""Finalize SCE identity and string offsets on a repository-script LLD image."""

from __future__ import annotations

import argparse
import struct
from pathlib import Path


DT_SCE_NEEDED_MODULE = 0x61000045
DT_SCE_IMPORT_LIB = 0x61000049
DT_SCE_MODULE_INFO = 0x61000043
DT_SCE_MODULE_FILENAME = 0x61000041
DT_SCE_EXPORT_LIB = 0x61000047


def sections(data: bytes) -> dict[str, tuple[int, int, int]]:
    shoff = struct.unpack_from("<Q", data, 0x28)[0]
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    if shentsize < 64 or shoff + shentsize * shnum > len(data):
        raise ValueError("invalid ELF section table")
    raw = [
        struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize)
        for i in range(shnum)
    ]
    if not 0 <= shstrndx < len(raw):
        raise ValueError("invalid ELF section-name table index")
    names_header = raw[shstrndx]
    names = data[names_header[4]:names_header[4] + names_header[5]]
    result = {}
    for header in raw:
        end = names.find(b"\0", header[0])
        name = names[header[0]:end].decode("ascii") if end >= 0 else ""
        result[name] = (header[4], header[5], header[9])
    return result


def dynstr_offset(data: bytes, offset: int, size: int, name: str) -> int:
    needle = name.encode("ascii") + b"\0"
    table = data[offset:offset + size]
    matches = []
    start = 0
    while True:
        found = table.find(needle, start)
        if found < 0:
            break
        if found == 0 or table[found - 1] == 0:
            matches.append(found)
        start = found + 1
    if len(matches) != 1:
        raise ValueError(f"expected one exact .dynstr entry for {name!r}")
    return matches[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("prx", type=Path)
    args = parser.parse_args()

    data = bytearray(args.prx.read_bytes())
    if len(data) < 64 or data[:6] != b"\x7fELF\x02\x01":
        raise ValueError("expected a little-endian ELF64 image")
    if struct.unpack_from("<H", data, 0x10)[0] != 3:
        raise ValueError("payload LLD output is not ET_DYN")
    if struct.unpack_from("<H", data, 0x38)[0] != 14:
        raise ValueError("payload LLD output does not have the SDK PRX PHDR layout")

    section_map = sections(data)
    dynstr = section_map.get(".dynstr")
    dynamic = section_map.get(".dynamic")
    if dynstr is None or dynamic is None or dynamic[2] < 16:
        raise ValueError("payload LLD output lacks PRX dynamic sections")
    string_offsets = {
        name: dynstr_offset(data, dynstr[0], dynstr[1], name)
        for name in ("libSceLibcInternal", "libkernel", "libSceAmpr", "libSceAmpr.prx")
    }

    needed_index = 0
    import_index = 0
    for entry_offset in range(dynamic[0], dynamic[0] + dynamic[1], dynamic[2]):
        tag, value = struct.unpack_from("<QQ", data, entry_offset)
        name = None
        if tag == DT_SCE_NEEDED_MODULE:
            name = ("libSceLibcInternal", "libkernel")[needed_index]
            needed_index += 1
        elif tag == DT_SCE_IMPORT_LIB:
            name = ("libSceLibcInternal", "libkernel")[import_index]
            import_index += 1
        elif tag in (DT_SCE_MODULE_INFO, DT_SCE_EXPORT_LIB):
            name = "libSceAmpr"
        elif tag == DT_SCE_MODULE_FILENAME:
            name = "libSceAmpr.prx"
        if name is not None:
            struct.pack_into(
                "<Q", data, entry_offset + 8,
                (value & 0xFFFFFFFF00000000) | string_offsets[name],
            )
    if needed_index != 2 or import_index != 2:
        raise ValueError("unexpected SCE import metadata layout")

    data[7] = 9
    data[8] = 2
    struct.pack_into("<H", data, 0x10, 0xFE18)
    args.prx.write_bytes(data)
    print("finalized SCE_DYNAMIC FreeBSD ABI v2 header and dynamic string offsets")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
