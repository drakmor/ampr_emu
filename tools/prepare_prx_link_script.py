#!/usr/bin/env python3
"""Adapt the repository PRX linker script for upstream LLVM LLD."""

from __future__ import annotations

import argparse
from pathlib import Path


PHDR_TYPES = {
    "PT_SCE_MODULEPARAM": "0x61000002",
    "PT_SCE_COMMENT": "0x6fffff00",
    "PT_SCE_LIBVERSION": "0x6fffff01",
}

DYNAMIC_INPUT = "        *(.dynamic)"
DYNAMIC_SCE = """        /* SCE entries supplied at link time; ordinary ELF entries follow. */
        QUAD (0x61000045); QUAD (0x0001010100000000)
        QUAD (0x61000049); QUAD (0x0000000100000000)
        QUAD (0x61000019); QUAD (0x0000000000000009)
        QUAD (0x61000045); QUAD (0x0002010100000000)
        QUAD (0x61000049); QUAD (0x0001000100000000)
        QUAD (0x61000019); QUAD (0x0001000000000009)
        QUAD (0x61000043); QUAD (0x0000010100000000)
        QUAD (0x61000011); QUAD (0x0000000000000000)
        QUAD (0x61000041); QUAD (0x0000000000000000)
        QUAD (0x61000047); QUAD (0x0003000100000000)
        QUAD (0x61000017); QUAD (0x0003000000000001)
        QUAD (0x6100003f); QUAD (SIZEOF (.dynsym))
        QUAD (0x6100003d); QUAD (SIZEOF (.hash))
        *(.dynamic)"""


def adapt(text: str) -> str:
    for name, value in PHDR_TYPES.items():
        count = text.count(name)
        if count != 1:
            raise ValueError(
                f"expected one {name} in repository prx.script, found {count}"
            )
        text = text.replace(name, value)

    if text.count(DYNAMIC_INPUT) != 1:
        raise ValueError("repository prx.script .dynamic rule changed")
    return text.replace(DYNAMIC_INPUT, DYNAMIC_SCE)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    output = adapt(args.input.read_text(encoding="utf-8"))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(output, encoding="utf-8")
    print(f"prepared PRX script from {args.input}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
