# AMPR Pack Tools for Windows

## Start

Run `ampr_pack_gui.exe`. Python, LZ4, and Visual Studio are not required.
Working files are created next to the program in `work/title` by default; every
path can be changed in the window.

The GUI selects Russian for a Russian system locale and English for all other
locales. Use the language selector at the top of the window to change it.

The complete instructions are in `USER_GUIDE_EN.md`. Russian documentation is
also included as `README_RU.md` and `USER_GUIDE_RU.md`.

## What the program can do

- merge multiple `ampr_commands.bin` + `ampr_emu.index` pairs;
- generate a TOML profile and a trace report;
- add files, directories, and patterns that were not present in traces;
- build AMPRPAK4 packs and a separate `ampr_assets.index.crc`, then verify and
  inspect them;
- create `ampr_assets.index.runtime` from the `[runtime]` section;
- after another full verification, remove only files marked PACK from the
  selected `/app0`.

The `.crc` file is used by the Python/GUI offline verification and recovery
paths. Runtime never opens or loads it. Retain it with the matching index and
volume backup.

Traces contain only APR reads that actually occurred and never prove complete
game-data coverage. Before packing, add files and directories needed by other
levels, modes, languages, and DLC, or intentionally leave them loose. Keep a
backup of the original `/app0`.

The `python-tools` directory is a source-tool fallback. It is needed only for
manual use with Python 3.11+ and is not used by the standalone executable.
