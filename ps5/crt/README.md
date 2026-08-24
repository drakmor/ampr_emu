# Repository PRX CRT

These sources implement the repository PRX startup/shutdown contract without
requiring prebuilt objects. `Makefile` compiles all four inputs with the
payload-SDK compiler and keeps their original link order:

- `crti.S`: `.sceversion` prologue record.
- `crtbeginS.c`: `_fini`, module parameters, DSO/libc anchors, and ctor/dtor
  start sentinels.
- `crtendS.c`: `_init` plus preinit/constructor dispatch and end sentinels.
- `crtn.S`: `.sceversion` epilogue record.

The C implementations preserve weak `module_start`, `module_stop`, and
`__cxa_finalize` behavior. `__cxa_finalize` is deliberately unresolved here
and becomes a `libSceLibcInternal.prx` NID import.
