# liblz4 dependency

This directory vendors the raw-block library sources from
[lz4/lz4](https://github.com/lz4/lz4), release `v1.10.0`, commit
`ebb370ca83af193212df4dcbadcc5d87bc0de2f0`.

Imported upstream files:

- `lib/lz4.c`
- `lib/lz4.h`
- `LICENSE`

The files are compiled directly into `libSceAmpr`; validated runtime AMPR pack
chunks call `LZ4_decompress_safe` directly. LZ4 frame parsing is not part of the
AMPR pack format.
