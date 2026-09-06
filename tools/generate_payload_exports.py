#!/usr/bin/env python3
"""Generate pre-link NID names and import providers for the Linux PRX link."""

from __future__ import annotations

import argparse
import base64
import hashlib
import re
import struct
from pathlib import Path


NID_SALT = bytes.fromhex("518D64A635DED8C1E6B039B1C3E55230")
EXPORT_RE = re.compile(
    r'extern\s+"C"\s+AMPR_EXPORT\s+int64_t\s+(sceAmpr[A-Za-z0-9_]+)\s*\('
)

LIBC_IMPORTS = {
    "__cxa_atexit",
    "__cxa_finalize",
    "__cxa_guard_acquire",
    "__cxa_guard_release",
    "abort",
    "calloc",
    "free",
    "gmtime_r",
    "malloc",
    "memchr",
    "memcpy",
    "memmove",
    "memset",
    "snprintf",
    "strftime",
    "strlen",
    "strnlen",
    "vsnprintf",
}

KERNEL_IMPORTS = {
    "__error",
}

METADATA_SYMBOLS = (
    "libSceLibcInternal",
    "libkernel",
    "libSceAmpr",
    "libSceAmpr.prx",
)

CRT_PROVIDED_SYMBOLS = {
    "__dso_handle",
}


def name_to_nid(name: str) -> str:
    digest = hashlib.sha1(name.encode("utf-8") + NID_SALT).digest()
    value = struct.unpack("<Q", digest[:8])[0]
    return base64.b64encode(
        value.to_bytes(8, "big"), altchars=b"+-"
    ).rstrip(b"=").decode("ascii")


def is_libc_import(name: str) -> bool:
    if name in LIBC_IMPORTS:
        return True
    if name in KERNEL_IMPORTS or name.startswith(("sceKernel", "scePthread")):
        return False
    raise ValueError(f"unclassified PRX import: {name}")


def source_exports(path: Path) -> list[str]:
    names = sorted(set(EXPORT_RE.findall(path.read_text(encoding="utf-8"))))
    if not names:
        raise ValueError(f"no AMPR exports found in {path}")
    return names


def render_response(names: list[str]) -> str:
    exports = "".join(
        f'"--export-dynamic-symbol={name_to_nid(name)}#D#A"\n'
        for name in names
    )
    metadata = "".join(
        f'"--export-dynamic-symbol={name}"\n' for name in METADATA_SYMBOLS
    )
    return exports + metadata


def render_version_script(names: list[str]) -> str:
    symbols = [
        *(f"{name_to_nid(name)}#D#A" for name in names),
        *METADATA_SYMBOLS,
    ]
    globals_ = "".join(f'    "{name}";\n' for name in symbols)
    return "{\n  global:\n" + globals_ + "  local: *;\n};\n"


def render_rename_map(exports: list[str], imports: list[str]) -> str:
    lines = [
        f'"--redefine-sym={name}={name_to_nid(name)}#D#A"'
        for name in exports
    ]
    for name in imports:
        suffix = "#A#B" if is_libc_import(name) else "#B#C"
        lines.append(f'"--redefine-sym={name}={name_to_nid(name)}{suffix}"')
    return "\n".join(lines) + "\n"


def render_stub_assembly(imports: list[str], suffix: str) -> str:
    lines = ["/* Auto-generated NID import provider. */", ".text"]
    for name in imports:
        symbol = f"{name_to_nid(name)}{suffix}"
        lines.extend(
            [
                f'.globl "{symbol}"',
                f'.type "{symbol}", @function',
                f'"{symbol}":',
                "    ret",
                f'.size "{symbol}", .-"{symbol}"',
            ]
        )
    lines.append('.section .note.GNU-stack,"",@progbits')
    return "\n".join(lines) + "\n"


def render_metadata_assembly() -> str:
    lines = ["/* Auto-generated link-only SCE dynamic string markers. */", ".data"]
    for name in METADATA_SYMBOLS:
        lines.extend(
            [
                f'.globl "{name}"',
                f'.protected "{name}"',
                f'.type "{name}", @object',
                f'"{name}":',
                "    .byte 0",
                f'.size "{name}", 1',
            ]
        )
    lines.extend(['.section .note.GNU-stack,"",@progbits', ""])
    return "\n".join(lines)


def write_if_changed(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_text(encoding="utf-8") == data:
        return
    path.write_text(data, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--response", type=Path, required=True)
    parser.add_argument("--version-script", type=Path, required=True)
    parser.add_argument("--undefined", type=Path, required=True)
    parser.add_argument("--rename-map", type=Path, required=True)
    parser.add_argument("--libc-asm", type=Path, required=True)
    parser.add_argument("--libc-list", type=Path, required=True)
    parser.add_argument("--kernel-asm", type=Path, required=True)
    parser.add_argument("--kernel-list", type=Path, required=True)
    parser.add_argument("--metadata-asm", type=Path, required=True)
    args = parser.parse_args()

    names = source_exports(args.source)
    undefined_names = {
        line.strip()
        for line in args.undefined.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    imports = sorted(
        (undefined_names - set(names) - CRT_PROVIDED_SYMBOLS)
        | {"__cxa_finalize"}
    )
    if not imports:
        raise ValueError("no unresolved PRX imports found")
    libc_imports = []
    kernel_imports = []
    for name in imports:
        (libc_imports if is_libc_import(name) else kernel_imports).append(name)
    write_if_changed(args.response, render_response(names))
    write_if_changed(args.version_script, render_version_script(names))
    write_if_changed(args.rename_map, render_rename_map(names, imports))
    write_if_changed(args.libc_asm, render_stub_assembly(libc_imports, "#A#B"))
    write_if_changed(args.libc_list, "\n".join(libc_imports) + "\n")
    write_if_changed(args.kernel_asm, render_stub_assembly(kernel_imports, "#B#C"))
    write_if_changed(args.kernel_list, "\n".join(kernel_imports) + "\n")
    write_if_changed(args.metadata_asm, render_metadata_assembly())
    print(
        f"generated NIDs: exports={len(names)} "
        f"libc_imports={len(libc_imports)} kernel_imports={len(kernel_imports)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
