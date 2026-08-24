# PRX linker layout

`prx.script` is the repository PRX section/program-header layout. The Linux
build reads only this checked-in file.

`tools/prepare_prx_link_script.py` replaces symbolic SCE-only PHDR constants
with their numeric values and injects the dynamic entries required by upstream
LLVM LLD. It does not replace or reorder the checked-in 14-segment layout.
