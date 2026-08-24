#!/usr/bin/env python3
"""Audit the ps5-payload-sdk libSceAmpr PRX and corrected SysV hash."""

from __future__ import annotations

import argparse
import re
import struct
from pathlib import Path

from generate_payload_exports import METADATA_SYMBOLS, name_to_nid, source_exports
from ampr_export_reference_audit import reference_exports
from prx_hash_fix import Elf64LE, buckets_to_symbol_map, elf_hash


IMPORT_RE = re.compile(r"^[A-Za-z0-9+\-]{11}#[A-Za-z0-9+\-]#[A-Za-z0-9+\-]$")
EXPECTED_PHDR_TYPES = [
    1, 1, 1, 0x6474E552, 1, 0x61000002, 2, 7,
    0x6474E550, 1, 0x6FFFFF00, 0x6FFFFF01, 4, 4,
]
EXPECTED_MODULE_PARAM = bytes.fromhex(
    "2000000000000000 bff4133c03000000 0100050809000002 0100000000000000"
)
EXPECTED_SCEVERSION = bytes.fromhex(
    "0000160008637274693a02000009000000010200000900000001"
    "00001b0008637274626567696e533a02000009000000010200000900000001"
    "0000190008637274656e64533a02000009000000010200000900000001"
    "00001600086372746e3a02000009000000010200000900000001"
)
FSELF_MAGIC = b"\x4f\x15\x3d\x1d"


def fself_versions(data: bytes) -> tuple[int, int]:
    common_header_size = struct.calcsize("<4s4B")
    extended_header_size = struct.calcsize("<I2HQ2H4x")
    if data[:4] != FSELF_MAGIC:
        raise ValueError("SPRX is not a fake signed ELF image")
    _, _, _, _, num_entries, _ = struct.unpack_from(
        "<I2HQ2H4x", data, common_header_size
    )
    elf_offset = common_header_size + extended_header_size + num_entries * 32
    if data[elf_offset:elf_offset + 4] != b"\x7fELF":
        raise ValueError("SPRX does not contain an ELF header at the expected offset")
    phoff = struct.unpack_from("<Q", data, elf_offset + 0x20)[0]
    ehsize, phentsize, phnum = struct.unpack_from("<HHH", data, elf_offset + 0x34)
    elf_header_size = max(ehsize, phoff + phentsize * phnum)
    ex_info_offset = elf_offset + ((elf_header_size + 15) & ~15)
    _, _, app_version, fw_version = struct.unpack_from("<4Q", data, ex_info_offset)
    return app_version, fw_version


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prx", type=Path, required=True)
    parser.add_argument("--linked", type=Path, required=True)
    parser.add_argument("--libc-imports", type=Path, required=True)
    parser.add_argument("--kernel-imports", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--sprx", type=Path, required=True)
    parser.add_argument("--fself-version", type=lambda value: int(value, 0), required=True)
    args = parser.parse_args()

    data = args.prx.read_bytes()
    linked_data = args.linked.read_bytes()
    app_version, fw_version = fself_versions(args.sprx.read_bytes())
    if app_version != args.fself_version or fw_version != args.fself_version:
        raise ValueError(
            "unexpected FSELF versions: "
            f"app=0x{app_version:08x} fw=0x{fw_version:08x} "
            f"expected=0x{args.fself_version:08x}"
        )
    if data[:4] != b"\x7fELF" or data[7] != 9 or data[8] != 2:
        raise ValueError("PRX is not an ELF64 FreeBSD ABI v2 image")
    if struct.unpack_from("<H", data, 0x10)[0] != 0xFE18:
        raise ValueError("PRX e_type is not ET_SCE_DYNAMIC (0xfe18)")
    phoff = struct.unpack_from("<Q", data, 0x20)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    if phentsize < 56 or phnum != len(EXPECTED_PHDR_TYPES):
        raise ValueError(f"unexpected PRX program-header count: {phnum}")
    phdr_types = [
        struct.unpack_from("<I", data, phoff + index * phentsize)[0]
        for index in range(phnum)
    ]
    if phdr_types != EXPECTED_PHDR_TYPES:
        raise ValueError(f"PRX program-header layout mismatch: {phdr_types}")

    elf = Elf64LE(data)
    module_param = elf.section(".sce_module_param")
    if data[module_param.offset:module_param.offset + module_param.size] != EXPECTED_MODULE_PARAM:
        raise ValueError("repository CRT emitted an unexpected .sce_module_param")
    sceversion = elf.section(".sceversion")
    if data[sceversion.offset:sceversion.offset + sceversion.size] != EXPECTED_SCEVERSION:
        raise ValueError("repository CRT emitted unexpected .sceversion records")
    if not elf.section(".init").size or not elf.section(".fini").size:
        raise ValueError("repository CRT did not emit _init/_fini sections")
    if len(linked_data) != len(data):
        raise ValueError("hash correction changed the PRX size")
    hash_section = elf.section(".hash")
    changed = [
        index for index, pair in enumerate(zip(linked_data, data))
        if pair[0] != pair[1]
    ]
    if not changed:
        raise ValueError("hash correction did not change the linked PRX")
    escaped = [
        index for index in changed
        if not hash_section.offset <= index < hash_section.offset + hash_section.size
    ]
    if escaped:
        raise ValueError(f"hash correction changed byte outside .hash: 0x{escaped[0]:x}")
    dynstr = elf.section(".dynstr")
    dynsyms = elf.dynsyms()
    groups = elf.export_groups()
    matching_groups = {
        suffix: group
        for suffix, group in groups.items()
        if group.library == "libSceAmpr" and group.module == "libSceAmpr"
    }
    if len(matching_groups) != 1:
        raise ValueError("missing unique libSceAmpr SCE export group")
    (export_suffix, group), = matching_groups.items()

    source_names = set(source_exports(args.source))
    reference = reference_exports(args.reference)
    if source_names != set(reference):
        raise ValueError(
            "source/reference export mismatch: "
            f"missing={sorted(set(reference) - source_names)} "
            f"extra={sorted(source_names - set(reference))}"
        )
    bad_reference_nids = sorted(
        (name, nid, name_to_nid(name))
        for name, nid in reference.items()
        if nid != name_to_nid(name)
    )
    if bad_reference_nids:
        raise ValueError(f"reference NID mismatch: {bad_reference_nids}")

    expected = {
        f"{name_to_nid(name)}#{export_suffix[0]}#{export_suffix[1]}"
        for name in source_names
    }
    actual = {
        sym.name
        for sym in dynsyms[1:]
        if sym.st_shndx != 0 and sym.nid_parts and sym.nid_parts[1:] == export_suffix
    }
    missing = sorted(expected - actual)
    extra = sorted(actual - expected)
    if missing or extra:
        raise ValueError(f"payload export mismatch: missing={missing} extra={extra}")

    defined = {
        sym.name for sym in dynsyms[1:] if sym.st_shndx != 0 and sym.name
    }
    allowed_defined = expected | set(METADATA_SYMBOLS)
    unexpected_defined = sorted(defined - allowed_defined)
    missing_metadata = sorted(set(METADATA_SYMBOLS) - defined)
    if unexpected_defined or missing_metadata:
        raise ValueError(
            "unexpected dynamic definitions: "
            f"extra={unexpected_defined} missing_metadata={missing_metadata}"
        )

    imports = [sym.name for sym in dynsyms[1:] if sym.st_shndx == 0 and sym.name]
    bad_imports = sorted(name for name in imports if not IMPORT_RE.fullmatch(name))
    if bad_imports:
        raise ValueError(f"plain or malformed imports remain: {bad_imports}")
    libc_names = {
        line.strip()
        for line in args.libc_imports.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    expected_libc = {f"{name_to_nid(name)}#A#B" for name in libc_names}
    actual_libc = {name for name in imports if name.endswith("#A#B")}
    if actual_libc != expected_libc:
        raise ValueError(
            "libSceLibcInternal import mismatch: "
            f"missing={sorted(expected_libc - actual_libc)} "
            f"extra={sorted(actual_libc - expected_libc)}"
        )
    kernel_names = {
        line.strip()
        for line in args.kernel_imports.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    expected_kernel = {f"{name_to_nid(name)}#B#C" for name in kernel_names}
    actual_kernel = set(imports) - actual_libc
    if actual_kernel != expected_kernel:
        raise ValueError(
            "libkernel import mismatch: "
            f"missing={sorted(expected_kernel - actual_kernel)} "
            f"extra={sorted(actual_kernel - expected_kernel)}"
        )

    needed = []
    soname = None
    for tag, value in elf.dynamic_entries():
        if tag == 1:
            needed.append(elf.str_at(dynstr, value))
        elif tag == 14:
            soname = elf.str_at(dynstr, value)
    if needed != ["libSceLibcInternal.prx", "libkernel.prx"] or soname is not None:
        raise ValueError(f"unexpected dynamic libraries: needed={needed} soname={soname}")

    _, nbucket, _, buckets, chains = elf.hash_table()
    actual_buckets = buckets_to_symbol_map(buckets, chains)
    bad_buckets = []
    for sym in dynsyms[1:]:
        if sym.name not in actual:
            continue
        nid = sym.nid_parts[0]
        expected_bucket = elf_hash(group.canonical(nid)) % nbucket
        if actual_buckets.get(sym.index) != expected_bucket:
            bad_buckets.append((sym.name, actual_buckets.get(sym.index), expected_bucket))
    if bad_buckets:
        raise ValueError(f"incorrect export hash buckets: {bad_buckets}")

    print(
        f"payload_prx_ok exports={len(actual)} definitions={len(defined)} "
        f"imports={len(imports)} "
        f"libc_internal_imports={len(actual_libc)} "
        f"kernel_imports={len(actual_kernel)} "
        f"hash_buckets={nbucket} hash_changed_bytes={len(changed)} "
        f"fself_version=0x{fw_version:08x} "
        "needed=libSceLibcInternal.prx,libkernel.prx"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
