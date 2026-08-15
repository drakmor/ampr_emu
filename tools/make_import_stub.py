#!/usr/bin/env python3
import argparse
import base64
import hashlib
import struct
from pathlib import Path


SALT = bytes.fromhex("518D64A635DED8C1E6B039B1C3E55230")

ET_SCE_STUBLIB = 0xFE0C
EM_X86_64 = 0x3E
SHT_NULL = 0
SHT_STRTAB = 3
SHT_DYNAMIC = 6
SHT_DYNSYM = 11
SHT_SCENID = 0x61000001

DT_NULL = 0
DT_SONAME = 14
SCE_EXPORT_LIB_ATTR = 0x61000017
SCE_STUB_MODULE_NAME = 0x6100001D
SCE_STUB_MODULE_VERSION = 0x6100001F
SCE_STUB_LIBRARY_NAME = 0x61000021
SCE_STUB_LIBRARY_VERSION = 0x61000023

STB_GLOBAL = 1
STT_FUNC = 2

STT_OBJECT = 1

STUBS = {
    "ipmi": {
        "soname": "libSceIpmi.prx",
        "module": "libSceIpmi",
        "library": "libSceIpmi",
        "symbols": [
            ("_ZN4IPMI6Client6ConfigC1Ev", STT_FUNC),
            ("_ZN4IPMI6Client6createEPPS0_PKNS0_6ConfigEPvS6_", STT_FUNC),
        ],
    },
    "libc-internal": {
        "soname": "libSceLibcInternal.prx",
        "module": "libSceLibcInternal",
        "library": "libSceLibcInternal",
        "symbols": [
            ("__cxa_finalize", STT_FUNC),
            ("__cxa_guard_acquire", STT_FUNC),
            ("__cxa_guard_release", STT_FUNC),
            ("_ZSt11_Xbad_allocv", STT_FUNC),
            ("_ZSt14_Xlength_errorPKc", STT_FUNC),
            ("_ZSt14_Xout_of_rangePKc", STT_FUNC),
            ("_ZdlPv", STT_FUNC),
            ("_Znwm", STT_FUNC),
            ("abort", STT_FUNC),
            ("snprintf", STT_FUNC),
            ("strlcpy", STT_FUNC),
            ("strcasecmp", STT_FUNC),
            ("strtoll", STT_FUNC),
            ("strcmp", STT_FUNC),
            ("strtoull", STT_FUNC),
            ("_Getpctype", STT_FUNC),
            ("_Stoul", STT_FUNC),
            ("memcmp", STT_FUNC),
            ("strlen", STT_FUNC),
            ("strrchr", STT_FUNC),
            ("strncmp", STT_FUNC),
            ("memchr", STT_FUNC),
            ("memcpy", STT_FUNC),
            ("memmove", STT_FUNC),
            ("memset", STT_FUNC),
        ],
    },
}


def align(value: int, boundary: int) -> int:
    return (value + boundary - 1) & ~(boundary - 1)


def nid_bytes(name: str) -> bytes:
    return hashlib.sha1(name.encode("utf-8") + SALT).digest()[:8]


def nid_string(name: str) -> str:
    return base64.b64encode(nid_bytes(name)[::-1], altchars=b"+-").decode("ascii").rstrip("=")


def add_string(blob: bytearray, offsets: dict[str, int], text: str) -> int:
    if text in offsets:
        return offsets[text]
    offsets[text] = len(blob)
    blob += text.encode("utf-8") + b"\0"
    return offsets[text]


def section_header(name: int,
                   sh_type: int,
                   flags: int,
                   addr: int,
                   offset: int,
                   size: int,
                   link: int,
                   info: int,
                   addralign: int,
                   entsize: int) -> bytes:
    return struct.pack("<IIQQQQIIQQ",
                       name,
                       sh_type,
                       flags,
                       addr,
                       offset,
                       size,
                       link,
                       info,
                       addralign,
                       entsize)


def build_stub(config: dict[str, object]) -> bytes:
    shstr = bytearray(b"\0.shstrtab\0.dynamic\0.scenid\0.dynstr\0.dynsym\0")
    sh_name = {
        ".shstrtab": shstr.index(b".shstrtab"),
        ".dynamic": shstr.index(b".dynamic"),
        ".scenid": shstr.index(b".scenid"),
        ".dynstr": shstr.index(b".dynstr"),
        ".dynsym": shstr.index(b".dynsym"),
    }

    dynstr = bytearray(b"\0")
    str_offsets: dict[str, int] = {"": 0}
    symbols = config["symbols"]
    symbol_offsets = [add_string(dynstr, str_offsets, name) for name, _ty in symbols]
    soname_offset = add_string(dynstr, str_offsets, config["soname"])
    module_offset = add_string(dynstr, str_offsets, config["module"])
    library_offset = add_string(dynstr, str_offsets, config["library"])

    dynamic = b"".join([
        struct.pack("<QQ", DT_SONAME, soname_offset),
        struct.pack("<QQ", SCE_STUB_MODULE_NAME, module_offset),
        struct.pack("<QQ", SCE_STUB_LIBRARY_NAME, library_offset),
        struct.pack("<QQ", SCE_STUB_MODULE_VERSION, 0x101),
        struct.pack("<QQ", SCE_STUB_LIBRARY_VERSION, 1),
        struct.pack("<QQ", SCE_EXPORT_LIB_ATTR, 3),
        struct.pack("<QQ", DT_NULL, 0),
    ])

    scenid = bytearray(b"\0" * 8)
    for name, _ty in symbols:
        scenid += nid_bytes(name)

    dynsym = bytearray(b"\0" * 24)
    for offset, (_name, ty) in zip(symbol_offsets, symbols):
        dynsym += struct.pack("<IBBHQQ", offset, (STB_GLOBAL << 4) | ty, 0, 0, 0, 0)

    sections: list[tuple[str, int, bytes, int, int, int, int]] = []
    sections.append((".shstrtab", SHT_STRTAB, bytes(shstr), 1, 0, 0, 0))
    sections.append((".dynamic", SHT_DYNAMIC, dynamic, 8, 4, 0, 16))
    sections.append((".scenid", SHT_SCENID, bytes(scenid), 8, 5, 0, 8))
    sections.append((".dynstr", SHT_STRTAB, bytes(dynstr), 1, 0, 0, 0))
    sections.append((".dynsym", SHT_DYNSYM, bytes(dynsym), 8, 4, 0, 24))

    out = bytearray(b"\0" * 64)
    layout = []
    cursor = 64
    for name, sh_type, payload, sh_align, link, info, entsize in sections:
        cursor = align(cursor, sh_align)
        layout.append((name, sh_type, cursor, len(payload), sh_align, link, info, entsize))
        out += b"\0" * (cursor - len(out))
        out += payload
        cursor += len(payload)

    shoff = align(len(out), 8)
    out += b"\0" * (shoff - len(out))

    headers = [section_header(0, SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0)]
    for name, sh_type, offset, size, sh_align, link, info, entsize in layout:
        headers.append(section_header(sh_name[name],
                                      sh_type,
                                      0,
                                      0,
                                      offset,
                                      size,
                                      link,
                                      info,
                                      sh_align,
                                      entsize))
    out += b"".join(headers)

    ident = bytearray(b"\x7fELF")
    ident += bytes([2, 1, 1, 0, 2])
    ident += b"\0" * 7
    struct.pack_into("<16sHHIQQQIHHHHHH",
                     out,
                     0,
                     bytes(ident),
                     ET_SCE_STUBLIB,
                     EM_X86_64,
                     1,
                     0,
                     0,
                     shoff,
                     0,
                     64,
                     0,
                     0,
                     64,
                     len(headers),
                     1)
    return bytes(out)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out")
    parser.add_argument("--library", choices=sorted(STUBS), default="ipmi")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    if args.check:
        for name, _ty in STUBS[args.library]["symbols"]:
            print(f"{name} {nid_string(name)}")
        return 0

    if not args.out:
        parser.error("--out is required unless --check is used")

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(build_stub(STUBS[args.library]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
