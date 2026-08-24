# Payload-SDK compatibility headers

This directory contains the minimum Prospero ABI declarations required to
compile `libSceAmpr` with `ps5-payload-sdk` on Linux. The files preserve their
include paths so source includes remain unchanged.

`Makefile` adds this tree with `-idirafter`, after the payload SDK headers.
That order keeps the payload toolchain's libc and system definitions primary
while filling only declarations it does not provide. Extend this directory
only when compiler dependency output proves that another declaration is
required.

The Windows `ReleaseHooks|Prospero` solution does not use this directory.
