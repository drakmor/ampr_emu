# AMPR PAK Tools for macOS

macOS community front end by **Shambhala222**, based on **Drakmor's AMPR
emulator and PAK tools**. This contribution is a proposed macOS integration,
not an official upstream release. The existing Windows GUI remains available
as `tools/ampr_pack_gui.py`.

The Mac app adds an Auto Guide for recording or existing-TOML workflows,
saved projects with Continue and Step Back, PAK assembly, original-game
recovery, separate emulator/index operations, and English/German PDF help.
It calls the existing Python packer and profiler. It does not develop new
games or include any game assets.

## Run from source

Use Python 3.11 or newer with Tk support. The original Mac package was built
with Python 3.12 on Apple Silicon. From the repository root:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r tools/requirements-pack.txt
python tools/ampr_mac_gui.py
```

If your Python installation lacks Tk, install a Python distribution with
Tk support before creating the environment. The source checkout does not
include emulator binaries. Use **Emulator files…** in the app to select
appropriate versions, or place them in `tools/macos/emus/`.

The recording role needs command recording enabled. The final PAK-game role
needs PAK support with recording disabled. A `no-pack` version is not a
substitute for a non-recording PAK runtime. Unknown versions require the user
to confirm their capabilities and memory pool from their release notes.

## Build a standalone app

On macOS, in the same environment:

```sh
python -m pip install -r tools/requirements-pack-build.txt
python -m PyInstaller --noconfirm tools/macos/AMPRMac.spec
```

The result is `dist/AMPR Pack Tools.app`. Python and Tk are bundled in that
app. The build targets the architecture of the Python environment. Intel
and universal builds have not been validated. Signing and notarization are
not configured by this spec.

To include the same emulator defaults used by the manually tested package,
place the following files beside the spec **before building**:

| Local build filename | Original release filename | SHA-256 |
| --- | --- | --- |
| `recording-debug.sprx` | `libSceAmpr.sprx-0.4.2.1-test-debug-pack` | `b44a986f2fa9903e74a34cbbd4681e899cd99196613652cd073ed11f2ca947c2` |
| `runtime-pack.sprx` | `libSceAmpr.sprx-0.4.2.1-test-pack` | `69e6c4d5e4f5fb83c9e01815db5861c4c75734acbf4595cafa50d4c218116d1a` |

These binaries are optional build inputs and are ignored by Git. Only the
listed hashes receive automatic capability confirmation. A renamed or new
binary is not automatically trusted as a compatible replacement.

For the familiar distribution layout, put the app in
`ampr-pack-tools-macos-arm64/`, with an optional `emus/` folder next to that
folder. The app also supports browsing to files anywhere. This contribution
contains no compiled app, SPRX binary, project JSON, recording, or game file.

## Guides and icon

- [English guide](guide-source/USER_GUIDE_EN.md)
- [German guide](guide-source/USER_GUIDE_DE.md)
- [English PDF](help-resources/USER_GUIDE_EN.pdf)
- [German PDF](help-resources/USER_GUIDE_DE.pdf)
- [Original upstream Russian PDF](help-resources/UPSTREAM_USER_GUIDE_RU.pdf)

The Help menu opens the bundled PDFs. English and German PDF sources are
`guide-source/EN.json` and `DE.json`. Regenerate them with:

```sh
python -m pip install reportlab
python tools/macos/render_guides.py
```

Keep the Markdown guides in sync when editing those sources. The Russian
guide is the original upstream document, not a translation of this Mac UI.
The PNG icon was generated with AI assistance; its prompt is retained in
`assets/ICON_PROMPT.txt`. The ICNS is the macOS packaging derivative.

## Project and recovery behavior

The selected working folder contains the project JSON, control-file backups,
recordings, profile and PAK output. Completed operations and pending changes
are journalled. Finalization assembles a complete PAK game from the PAKs plus
unpacked files, preserves the original game in the working folder, and puts
the assembled game at its original location. Same-volume PAK transfers use
renames. Cross-volume transfers require copying.

Recovery restores the recorded original state and removes tracked generated
files when they still match the cleanup record. Changed or unknown files are
retained rather than deleted. A small recovered project JSON can remain.
Keep the original backup, project and working folders in their recorded
locations while recovery is needed. Only open your own project files: they
contain paths used for filesystem operations.

## Validation status

Shambhala222 reports successful manual use of the recording Auto Guide,
existing-TOML route, Step Back, PAK completion and Recovery. The manual
workflow has not been fully tested. Packaging integration and small source
adaptations in this contribution have not had a fresh end-to-end game test.
No additional game/PAK tests were run while preparing the contribution.

The emulator and PAK tools remain Drakmor's work. This modified version is
distributed under the repository's GPLv3 license. LZ4 retains its separate
license. See [credits](help-resources/CREDITS.txt) and the repository LICENSE.
