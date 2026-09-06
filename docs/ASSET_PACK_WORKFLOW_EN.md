# Building Asset Packs: End-User Guide

This guide explains how to produce asset packs for one specific game version,
verify them, and prepare a complete `/app0` set. The primary workflow uses the
`ampr_pack_gui.py` desktop application. Equivalent PowerShell commands are
provided at the end for recovery and diagnostics.

> **The main tracing limitation**
>
> Traces **do not contain all game data**. They show only APR reads that actually
> happened during the recorded scenarios. They omit unvisited levels, other
> modes and languages, some DLC and rare branches, as well as access through
> paths that were not intercepted, such as `mmap`.
>
> An automatically generated TOML profile is only a starting point. Before
> packing, adapt it to the real game: add the remaining required files and
> directories, or intentionally keep them as ordinary loose files. Even a long
> trace does not prove that an unobserved file will never be required.

## 1. What you need

- Windows and Python 3.11 or newer with Tcl/Tk. Tkinter is included in a normal
  Python installation from python.org.
- A complete, unchanged local copy of the game's `/app0` directory.
- `ampr_emu.index` built for that exact `/app0` copy.
- One or more traces. Each run directory must contain `ampr_commands.bin` and
  its matching `ampr_emu.index` next to each other.
- Enough free space for the original files, the previous pack set, and the new
  temporary set. Do not budget only for the final `.pak` size: old and new
  volumes can coexist until publication completes.

Install the packer's dependency from PowerShell in the repository root:

```powershell
python -m pip install -r tools/requirements-pack.txt
```

Do not combine a trace from one game version with an index from another.
`fileId` depends on AMPRIDX3 records, so retain the exact index used to record
each trace beside that trace.

If the complete local copy does not have an index yet, build it once and do not
change it until all traces and packs are complete:

```powershell
python tools/build_ampr_index.py "profiling/title/app0"
```

Recommended working-directory layout:

```text
profiling/title/
├── app0/                         complete source game
│   └── ampr_emu.index
├── traces/
│   ├── startup/
│   │   ├── ampr_commands.bin
│   │   └── ampr_emu.index
│   ├── level-and-combat/
│   │   ├── ampr_commands.bin
│   │   └── ampr_emu.index
│   └── travel/
│       ├── ampr_commands.bin
│       └── ampr_emu.index
├── profiles/
└── packed/
```

## 2. Recording useful traces

Trace recording uses a ready-made **debug emulator build** with APR command
recording enabled.

Record several separate scenarios:

1. Cold start through the main menu and loading a save.
2. Loading several different levels or large regions.
3. Fast travel, cutscenes, combat, and intensive streaming.
4. Revisiting a region.
5. Additional modes, languages, and installed DLC that the finished set must
   support.

After each normal exit, copy `ampr_commands.bin`, `ampr_emu.index`, and, for
diagnostics, `ampr_emu.log` into a separate run directory. A journal interrupted
by a crash may be incomplete.

More runs improve geometry and cache recommendations, but do not replace the
manual game-content review.

## 3. Starting the GUI

On Windows, double-click:

```text
tools\ampr_pack_gui.cmd
```

Or launch it from PowerShell:

```powershell
python tools/ampr_pack_gui.py
```

Fill in the five paths at the top of the window:

- **Trace directory** — a common directory below which the GUI finds all
  `ampr_commands.bin` + `ampr_emu.index` pairs.
- **Complete /app0 copy** — original game files, not a directory from which
  source files have already been removed.
- **ampr_emu.index file** — the index for this complete game copy.
- **TOML profile** — where generated rules are saved, for example
  `profiling/title/profiles/title.toml`.
- **Pack output directory** — a separate result directory, for example
  `profiling/title/packed`.

Click **“1. Generate profile from traces”**. The GUI merges all discovered runs
and saves these files next to the TOML:

- `title.report.md` — a human-readable report;
- `title.metrics.json` — detailed input metrics;
- `*.include.txt` lists when needed.

The JSON describes input access and recommendations. It is not a performance
measurement of the completed packed runtime.

### Reading the profiler report

In `title.report.md`, first review `Warnings` and each input run. Nonzero
`Sequence/parser warnings` or `decode issues` must be explained. Re-record a
damaged or truncated trace instead of deriving aggressive rules from it.

| Report field | How to use it |
| --- | --- |
| `Confidence` | With low confidence, do not make the rule more aggressive without more traces; `64KiB/mixed` is the safe starting point |
| `Amplification` | Estimates how much more data the chosen geometry touches than the game requested; compare candidates for the same file |
| `Seq.` | A high sequential share supports `streaming` and larger blocks |
| `Repeat 64K` | Shows region reuse and helps estimate whether a decoded cache is useful |
| `Projected pack index` | Resident-manifest projection for only the selection known at generation time |
| `Recommended internal pool` | Budget for the recommended caches, workers, and projected manifest, not an automatically changed PRX size |

After manually adding directories, the old `Projected pack index` and
`Recommended internal pool` are no longer final. Use the actual
`ampr_assets.index` after packing and recalculate the memory budget.

## 4. Adapting the profile to the real game is mandatory

After generation, click **“Load from profile”**. **“2. All paths selected for
packing”** then shows every explicit `include` and `include_from` from traced
`compress`/`store` rules together with previously saved manual additions. This
shows the generated selection instead of an empty manual-only list.

Compare this list with the actual `/app0` contents and required game scenarios,
then edit the selection:

- **“Add files…”** selects one or more individual files;
- **“Add directory…”** adds the entire directory as `path/**`;
- **“Add pattern…”** adds a relative path or glob manually, such as `dlc/**` or
  `localization/en/**`.
- **“Remove selected”** removes a path from the effective selection. For a
  trace-derived path, its original rule and parameters remain intact and the GUI
  writes a final loose override;
- **“Load from profile”** rebuilds the complete editable list from the selected
  TOML and its safe relative `include_from` files.

Selected paths must be inside the configured `/app0`. The GUI writes them to
`title.manual.include.txt` and adds a managed TOML rule. This does not override
hard exclusions for `eboot.bin`, PRX/SPRX files, indexes, and system directories.

### Parameters for new manual paths

| GUI parameter | Meaning | When to use it |
| --- | --- | --- |
| **Mode: `compress`** | Compresses independent blocks with LZ4 HC level 12 by default; an incompressible block is stored RAW | Initial choice for most game data; slower to build than `fast`, but usually smaller |
| **Mode: `store`** | Avoids LZ4 CPU work but places data in a seekable pack; decoded-block CRCs are written only to the offline sidecar | Already-compressed video, audio, and archives after testing |
| **Access: `mixed`** | Balances bounded random access and merging of adjacent reads | Recommended initial choice |
| **Access: `random`** | Optimizes small, non-sequential reads | Tables, scripts, configuration, and frequently used small files |
| **Access: `streaming`** | Places sequential blocks densely | Large video/audio or data proven to be sequential |
| **Block** | Independently readable and decodable block size from 16 KiB to 1 MiB | Start with `64KiB`; use larger blocks for streaming and smaller blocks for fine random reads |

**Mode**, **Access**, and **Block** apply only to new paths that were not part of
the loaded trace-derived rules. Existing rule geometry is preserved rather than
flattened; edit the corresponding `[[rule]]` in TOML to change those parameters.

The GUI adds `force_pack = true` to the new-path rule. Explicitly selected files
will not automatically return to loose because of weak compression; their
incompressible blocks remain RAW. Hard system exclusions still take priority.

### Choosing `compress`, `store`, or `loose`

| Action | Choose it when | Main risk |
| --- | --- | --- |
| `compress` | Data compresses or contains a mixture of compressible and RAW blocks | LZ4 uses CPU; weak savings may not justify decoding |
| `store` | Data is already compressed, but volume placement and fewer files/FDs are useful | Size barely decreases and reads still depend on the packed runtime |
| `loose` | `mmap` or another unintercepted path may be used, the file is rarely needed, or a large file is incompressible with no measured packing benefit | Ordinary filesystem load remains and the original must stay on disk |

`force_pack = true` prevents a selected large incompressible file from being
automatically returned to loose. Use it only when packed access is deliberate.
RAW fallback preserves the data but does not remove packed-runtime I/O and
bookkeeping costs.

Files sharing a prefix do not need the same policy. For example, keep a base
soundbank loose while packing localized variants:

```toml
[[rule]]
action = "compress"
include = ["d/soundbank.*"]
block_size = "64KiB"
layout = "mixed"
force_pack = true

[[rule]]
action = "loose"
include = ["d/soundbank"]
```

If sampling finds no useful gain in the localized banks, change them from
`compress` to `store` or leave them loose. Put exact exceptions after any
overlapping broad rules.

For already-compressed streaming video or audio, a reasonable starting point is
`store`, `streaming`, and `256KiB`, but change geometry only with a subsequent
in-game A/B test. If different groups need different parameters, save the main
list through the GUI, then add separate `[[rule]]` entries manually. Rules are
applied top to bottom; the last matching rule wins.

### Choosing the block size correctly

Choose the block size from traced access behavior rather than only from a file
extension or name. Consider typical request size, the random-read share, data
reuse, and the profiler report's read-amplification estimate.

| Block size | Reasonable starting point |
| ---: | --- |
| `16KiB` | Traces prove very small random reads of hot tables, configuration, or localization data |
| `32KiB` | Small random reads dominate, but the overhead of `16KiB` blocks is already undesirable |
| `64KiB` | Safe for unknown or mixed data and archives with arbitrary seeks; matches the APR accounting granule |
| `128KiB`–`256KiB` | Reads are mostly large or sequential, as confirmed by traces |
| `512KiB`–`1MiB` | Proven sequential streams and precompressed RAW media; usually too large for fine random reads |

A small block reduces excess reading and decoding under random access, but it is
not a free optimization. Every chunk consumes 12 bytes in the resident
`AMPRPAK4` manifest. A rough estimate for the chunk table alone is:

```text
chunk_count    ~= ceil(total_file_bytes / block_size)
chunk_metadata ~= chunk_count * 12 bytes
```

For example, for 100 GiB of packed logical data, the chunk table is approximately
75 MiB with `16KiB`, 37.5 MiB with `32KiB`, 18.75 MiB with `64KiB`, and 1.17 MiB
with `1MiB`. Small blocks also create more scheduling units and copy/decode
operations, and usually reduce compression efficiency. The offline CRC sidecar
also grows by four bytes per chunk, but runtime never loads it. Latency can still
increase even while read amplification decreases.

Do not apply `16KiB` or `32KiB` to a large directory with a broad pattern unless
traces justify it: tens of gigabytes of previously unaccounted data can consume
tens of megabytes of the internal pool in chunk records alone. Do not repeat the
same broad pattern in rules with different block sizes. The last match wins and
can silently override the profiler's exact recommendations.

### Hard format and runtime limits

Check record counts as well as manifest bytes. The current packed build has
these limits:

| Object | Limit |
| --- | ---: |
| Files in `AMPRPAK4` | 2,000,000 |
| Chunks across all packed files | 16,000,000 |
| `.pak` volumes in the complete manifest | 1,024 |
| Packing groups | 256 |
| Block size | 16 KiB through 1 MiB, power of two |
| Runtime workers | 1 through 16 |
| Decoded-cache request | at most 512 MiB |
| Physical-cache request | at most 128 MiB |

The volume limit applies to the complete manifest, not one `[groups.*]` table.
Even if the TOML parser accepts a larger `pack_count`, the runtime will not load
that set. For example, 250 GiB with `16KiB` blocks produces about 16.38 million
chunks before any other files and already exceeds the limit. Increase the block
size or leave some data loose.

### Groups, lanes, and striping

Start with one volume for a small set. For a large group containing several
files read concurrently, two to four lanes with `assignment = "balanced"` are
usually enough. More volumes do not accelerate one small request and can
increase FD turnover and seeks.

Keep `stripe_large_files = false` until a console A/B test demonstrates a
benefit from rotating parts of one large file. When enabling it, choose
`stripe_group_blocks` so that one stripe is about 512 KiB. Avoid striping a
strictly sequential single stream or storage that serializes every read.

When lanes exist for parallel physical I/O, keep
`deduplicate_scope = "lane"`. Group-wide deduplication can place identical data
in one volume and reduce parallelism. Do not set an unnecessarily small
`max_pack_size`, which creates excess volumes. Derive it from storage and
deployment constraints while keeping the total below 1,024.

Pay particular attention to:

- levels, maps, and biomes absent from recorded runs;
- every supported language, voice-over, and subtitle set;
- DLC, bonus modes, new-game paths, and final chapters;
- data used by cutscenes, menus, credits, and error recovery.

When the review is complete, click **“2. Save path changes”** and select the
coverage confirmation checkbox. The checkbox does not prove completeness; it
prevents accidental packing immediately after trace-profile generation.

## 5. Building and verifying packs

Click **“3. Pack and verify”**. The GUI performs, in order:

1. Build pack volumes, `ampr_assets.index`, and offline `ampr_assets.index.crc`.
2. Verify every block and decode operation using CRCs from the offline sidecar.
3. Compare every reconstructed packed file byte-for-byte with source `/app0`.
4. Print the manifest summary.

While packing, the GUI log shows `ampr_pack.py` progress lines with the current
phase, overall percentage, processed file count, processed source bytes, current
path, and elapsed time. Progress also updates within one large file, so an HC12
compression pass does not appear stuck.

The operation succeeds only if all four stages complete without an error. Use
**“Verify existing packs”** and **“Show summary”** to repeat those operations
separately. Full output remains in the bottom section of the window.

Do not remove source files after one successful `verify`. Verification proves
pack integrity, not full scenario coverage or interception of every read method.

### Readiness checklist

Before deployment, and especially before source removal, every condition must
hold:

- [ ] input-trace warnings and decode issues are absent or individually
  explained;
- [ ] manual coverage includes the required levels, modes, locales, and DLC;
- [ ] `pack`, `verify --root`, `inspect`, and `list --json` all finish without
  errors;
- [ ] `loose_paths` has been reviewed and every listed file remains in `/app0`;
- [ ] actual file, chunk, and volume counts stay below the hard limits;
- [ ] the actual manifest and runtime settings fit the internal pool with at
  least 8–16 MiB of headroom;
- [ ] the index, `.runtime`, and every volume share one build ID and are deployed
  as one runtime set;
- [ ] the matching `.crc` is retained with the PC/archive copy for `verify` and
  `unpack`;
- [ ] the complete console test was first run with source files retained;
- [ ] a backup and a tested rollback procedure are available.

If any item is not satisfied, the set is not ready for source-file removal. A
successful offline `verify` covers integrity only.

## 6. Removing originals that are stored in packs

After making a backup, the GUI can remove from the selected `/app0` only files
that the final manifest marks PACK. Click **“Remove PACK files from /app0…”**.

The GUI shows the file count and total size before removal. After confirmation,
it runs complete pack verification again and compares the packed content with
every original byte-for-byte. Removal does not begin if the manifest, a pack,
the source size, or source content does not match.

Removal parameters:

| Parameter | Purpose |
| --- | --- |
| **Complete /app0 copy** | Directory from which originals are removed; paths come only from PACK records in the selected manifest |
| **Pack output directory** | Contains the verified `ampr_assets.index` and volumes; LOOSE records are never removed |
| **Coverage review confirmation** | Required: offline verification does not prove that traces covered the whole game or that a file is not read through `mmap` |
| **Also remove directories that become empty** | Removes only directories that are actually empty after file removal; the `/app0` root is never removed |

The operation also refuses to remove `eboot.bin`, PRX/SPRX/SELF/ELF files, AMPR
indexes, system directories, symlinks/reparse points, or any path outside the
selected `/app0`, even if an incorrect custom TOML marked it PACK.

> Removal is permanent. Afterwards, `verify --root` can no longer compare packs
> with their source files. Keep a separate backup. Packed files can also be
> restored with `unpack` while the correct index, its `.crc`, and every volume
> remain intact.

Before launching the game, make sure `ampr_assets.index`, its `.runtime` file,
and every volume are already included in the final `/app0` set. Source removal
does not copy those files there.

## 7. Files to deploy with the game

Deploy one matching set to `/app0`:

- the source `ampr_emu.index`;
- `ampr_assets.index`;
- `ampr_assets.index.runtime`;
- every `.pak` named by the manifest;
- every file left loose.

Runtime does not need or load `ampr_assets.index.crc`. Keep it beside the archived
or PC copy of the index: Python `verify` and `unpack` require matching build IDs
and chunk counts. Deploying `.crc` to `/app0` is harmless and may be convenient
for maintenance, but does not affect the game.

Do not mix an index, `.runtime`, and volumes from different builds. Runtime
settings are bound to the manifest build ID. Replace the set only while the game
is not running.

Build a new set in a separate staging directory. Budget space for the source
game, the existing pack set, and the new set with temporary files. Safe
publication protects one output directory from an ordinary build failure, but
copying files to another device is not automatically atomic.

For an update, stop the game, copy the complete matching set, verify that every
named volume is present, and only then switch the set as a unit. Do not replace
the `.runtime`, index, or individual volumes while the game runs. Retain the
previous working set until console validation completes. For reproducibility,
archive the TOML, all `include_from` lists, report, source `ampr_emu.index`, and
`inspect` summary. Checksums of deployed files distinguish an incomplete copy
from a runtime defect.

For initial tests, retain all originals and use a debug emulator build with
packed-file support. Removing an original is acceptable only after testing all
required game paths and only for a PACK file that is not accessed through an
unintercepted method. Never remove modules, executables, indexes, or settings.

## 8. Runtime configuration parameters

The TOML profile contains a `[runtime]` section. Packing converts it into an
`ampr_assets.index.runtime` file bound to that manifest's build ID:

```toml
[runtime]
decoded_cache_bytes = "128MiB"
physical_cache_bytes = "32MiB"
workers = 4
latency_reserve_workers = 1
```

| Parameter | Purpose and valid values |
| --- | --- |
| `decoded_cache_bytes` | Cache for decoded blocks. Must be a multiple of 16 KiB; `0` disables it. A larger cache helps repeated reads but consumes the shared internal pool |
| `physical_cache_bytes` | Cache for physical pack pages. Must be a multiple of 16 KiB; `0` disables it. It helps when several blocks reuse the same page |
| `workers` | Packed-runtime worker threads: `1..16`. This is not `[pack].workers`, which controls PC-side compression |
| `latency_reserve_workers` | Workers reserved for latency-sensitive reads: from `0` through `workers - 1` |

The GUI uses these values when it builds packs. To change runtime settings only,
edit `[runtime]` in the TOML and update `.runtime` without recompressing:

```powershell
python tools/ampr_pack.py runtime-config --index "profiling/title/packed/ampr_assets.index" --config "profiling/title/profiles/title.toml"
```

Deploy the updated `ampr_assets.index.runtime` and restart the game. A damaged
`.runtime` or one from another build ID blocks manifest loading. A missing
`.runtime` means compiled defaults are used. This does not apply to `.crc`, which
runtime never opens.

### Checking the internal-pool limit

Packed MSBuild profiles use a fixed 384 MiB internal pool by default. The
`[runtime]` section does not resize this pool; it only requests cache sizes and a
worker count within the pool compiled into the PRX. Use this preliminary budget:

```text
required ~= ampr_assets.index size
           + resident AMPRIDX3 size
           + decoded_cache_bytes
           + physical_cache_bytes
           + 32 pipeline windows * 2 MiB
           + workers * 1 MiB
           + 32 MiB safety reserve
```

With four workers, the pipeline windows, worker scratch, and safety reserve use
100 MiB before the manifest, AMPRIDX3, and caches. For a 384 MiB pool:

```text
both caches <= 384 MiB - 100 MiB - manifest - AMPRIDX3 - headroom
```

Keep at least another 8–16 MiB of headroom for alignment, small auxiliary
allocations, and final-manifest growth. Check the actual `ampr_assets.index`
size after packing, not only its earlier projection. For example, with 7,439,926
chunks, moving from AMPRPAK3's 16-byte record to AMPRPAK4's 12-byte record reduces
the manifest from about 113.54 MiB to 85.16 MiB. With a 0.03 MiB AMPRIDX3, a
96 MiB decoded cache, a 64 MiB physical cache, and four workers, the total is
about 345.19 MiB, leaving 38.81 MiB. A 120 MiB decoded cache still totals about
369.19 MiB and leaves 14.81 MiB. The `.crc` file is excluded because runtime
does not load it.

At startup, the runtime first holds space for pipeline windows, worker scratch,
and the safety reserve, then allocates the physical and decoded caches. If a
requested cache does not fit, its candidate size is repeatedly halved down to
the allowed minimum. A profile close to the limit can therefore receive a much
smaller cache than requested. Read the actual sizes from
`apr.pack.physical-cache.init` and `apr.pack.cache.init` log entries.

If 384 MiB is demonstrably insufficient, change the build-time size, for example
with the MSBuild property `AmprInternalAmmPoolSize=0x20000000ull` for 512 MiB.
This increases the emulator PRX `.bss` and CPU-memory consumption. Prefer first
fixing unjustifiably small blocks or reducing caches, and validate any higher
limit on the console together with the title's own memory usage.

## 9. Console testing

At minimum, test startup, a new game, several saves, level transitions, fast
travel, cutscenes, streaming, language changes, DLC, revisits, load cancellation,
and normal game exit.

### Running a valid A/B test

Compare loose and packed on the same console, storage device, game version,
save, and action sequence. Measure the first cold pass separately from repeated
warm passes. Run at least three comparable trials of each variant: one result is
easily distorted by system cache state or background activity.

Do not select a profile from compression ratio alone. Compare load time and
frame-time outliers with these fields from the latest complete snapshot:

| Observation | Check before changing the profile |
| --- | --- |
| High `physical/delivered` | Blocks may be too large for random access; check layout and physical-cache effectiveness |
| Many decoded-cache evictions with proven reuse | Check the actually allocated decoded cache and whether tiny chunks consumed manifest memory |
| Low cache hit without repeated reads | A larger cache will not help; streaming and second-touch admission are expected to bypass it |
| High queue peaks and p95/p99 | Check workload class, workers actually active, backing-AIO latency, and lane contention |
| More LZ4 work without fewer physical bytes | Compare `store`/RAW and the weak-compression thresholds |

Change one major variable at a time: block geometry, layout, lanes, cache, or
workers. Otherwise the cause of a result cannot be isolated.

For diagnostic measurements, use a ready-made debug packed emulator build with
detailed binary tracing and verbose logs disabled.

Save each identical scenario's `ampr_emu.log` separately. Do not sum periodic
snapshots: they are cumulative. p50/p95/p99 values are histogram upper bounds,
and worker time is elapsed work time, not CPU time.

```powershell
python tools/analyze_ampr_log.py "profiling/title/runs/baseline/ampr_emu.log" --tail 0
```

Finally compare the completed set in the supplied release packed build against
the loose baseline for load time, frame time, memory, and correctness. The debug
build has its own overhead and is not suitable for final performance evaluation.

### Common failures and the first check

| Symptom or log entry | Likely cause | Action |
| --- | --- | --- |
| `fileId` and path disagree | The trace or profile uses an `ampr_emu.index` from another `/app0` version | Restore the complete source tree and regenerate the index and traces as one set |
| `apr.pack.index.missing` | `ampr_assets.index` is absent from the expected path | Check the deployed set and its location under `/app0` |
| `apr.pack.index.invalid` | The manifest is damaged, exceeds a runtime limit, or has an incompatible format | Repeat `verify`/`inspect`, check counts, and rebuild with the matching tools |
| `apr.pack.profile.invalid` | The `.runtime` sidecar is damaged or belongs to another build ID | Regenerate it from the same TOML and manifest, or remove it to use compiled defaults |
| A volume is missing or fails build-ID/CRC checks | Builds were mixed or copying was interrupted | Redeploy the index and every volume as one set and compare checksums |
| `apr.pack.caches.disabled reason=no-runtime-reserve` | Manifest and runtime budget do not fit the internal pool | Increase unjustifiably small blocks, reduce caches/workers, or deliberately raise the build-time pool |
| `apr.pack.physical-cache.init` or `apr.pack.cache.init` is below the TOML request | The runtime reduced a cache because contiguous memory was unavailable | Analyze the actually allocated sizes and increase headroom |
| A packed file exists but in-game reading fails | `mmap`, direct I/O, or another unintercepted path may be involved | Restore the original and add a final exact `loose` rule |
| A runtime LZ4/decode error | A volume is damaged, builds were mixed, or a descriptor/data block is corrupt | Stop testing, run offline `verify` with the matching `.crc`, and replace the complete set |
| `invalid or missing chunk CRC sidecar` in Python | `ampr_assets.index.crc` is missing, damaged, or belongs to another build ID | Restore the matching `.crc` from the same build, or rebuild/convert the set |

## 10. Equivalent commands without the GUI

This example uses two traces and runs from the repository root:

```powershell
$caseRoot = Join-Path (Get-Location) 'profiling/title'

python tools/ampr_pack_profile.py generate `
  --trace "$caseRoot/traces/startup/ampr_commands.bin" "$caseRoot/traces/startup/ampr_emu.index" `
  --trace "$caseRoot/traces/travel/ampr_commands.bin" "$caseRoot/traces/travel/ampr_emu.index" `
  --output "$caseRoot/profiles/title.toml" `
  --report "$caseRoot/profiles/title.report.md" `
  --metrics "$caseRoot/profiles/title.metrics.json" `
  --pattern-mode exact --cache-sim --cache-max-touches 250000 --overwrite
```

After generation, manually add rules for all remaining required files and
directories. For example:

```toml
[[rule]]
action = "compress"
include = ["dlc/**", "localization/en/**", "levels/not_visited/**"]
block_size = "64KiB"
layout = "mixed"
force_pack = true
```

Keep safety exclusions last because the last matching rule wins. Then build and
always verify with `--root`:

```powershell
python tools/ampr_pack.py pack --root "$caseRoot/app0" --ampr-index "$caseRoot/app0/ampr_emu.index" --output "$caseRoot/packed" --config "$caseRoot/profiles/title.toml"
python tools/ampr_pack.py verify --index "$caseRoot/packed/ampr_assets.index" --root "$caseRoot/app0"
python tools/ampr_pack.py inspect --index "$caseRoot/packed/ampr_assets.index"
python tools/ampr_pack.py list --index "$caseRoot/packed/ampr_assets.index" --json
```

The `pack` command writes progress to `stderr` and keeps the final JSON alone on
`stdout`, preserving scripts that parse that JSON. Its `crc` field names the
offline sidecar. Its `loose_paths` field lists
every file that was not placed in a pack and must remain physically available
under `/app0`, including default-loose, explicitly loose, and automatically
loosened paths. Add `--no-progress` to suppress progress output.

`list` shows what remains loose. `--self-contained` prevents explicitly selected
incompressible files from automatically returning to loose and stores their
blocks RAW, but it **does not select every game file automatically**.

Convert an existing AMPRPAK3 index without rewriting its `.pak` volumes:

```powershell
python tools/convert_ampr_pack_v3.py --index "$caseRoot/packed-v3/ampr_assets.index" --output "$caseRoot/packed-v3/ampr_assets-v4.index"
```

The converter streams a 12-byte AMPRPAK4 chunk table and a separate
`ampr_assets-v4.index.crc`, while validating the old manifest CRC. It preserves
the build ID and leaves AMPRDAT3 volumes unchanged. Run `verify` against the new
index before replacing a live index, and replace it only while the game is stopped.

Preview the removal plan first. Without `--confirm`, nothing is changed:

```powershell
python tools/ampr_pack.py remove-packed-sources --index "$caseRoot/packed/ampr_assets.index" --root "$caseRoot/app0"
```

After backing up and reviewing the list, perform removal. `--confirm` authorizes
the irreversible change; `--remove-empty-dirs` additionally removes only
directories that became empty:

```powershell
python tools/ampr_pack.py remove-packed-sources --index "$caseRoot/packed/ampr_assets.index" --root "$caseRoot/app0" --confirm --remove-empty-dirs
```

Changing block sizes, layout, or file selection requires repacking and another
`verify`. Changing only `[runtime]` does not require recompression:

```powershell
python tools/ampr_pack.py runtime-config --index "$caseRoot/packed/ampr_assets.index" --config "$caseRoot/profiles/title.toml"
python tools/ampr_pack.py inspect --index "$caseRoot/packed/ampr_assets.index"
```

Retain the final TOML, `*.include.txt`, `.runtime`, `.crc`, report, and test results as
the profile for this exact game version. After a game update or resource-layout
change, record new traces, repeat the manual coverage review, and rebuild packs.
