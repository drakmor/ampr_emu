# Seekable LZ4 asset packs

`ampr_emu` can expose selected `/app0` files through seekable, independently
compressed asset packs without changing the public APR command-buffer ABI. The
implementation is designed for both opaque game archives with their own
indexes and directories containing many small files.

## Per-game runtime settings

Per-game runtime settings are emitted as `<manifest>.runtime` when the packing
TOML contains `[runtime]`. `runtime-config --index ... --config ...` updates this
file atomically without repacking. The profiler emits this section automatically:

```toml
[runtime]
decoded_cache_bytes = "128MiB"
physical_cache_bytes = "32MiB"
workers = 4
latency_reserve_workers = 1
```

The loader reads it once, before cache allocation and worker startup. Missing
settings use compiled defaults; invalid settings fail manifest loading explicitly.
`inspect` validates and displays the requested `.runtime` values. Offline
`verify` separately validates the decoded-chunk `.crc` sidecar described below.
Workers must be 1..16, reserve smaller than workers, and cache sizes nonnegative
16 KiB multiples (zero disables a cache). The runtime clamps requests to compiled
ceilings: normally 16 workers, 512 MiB decoded cache and 128 MiB physical cache.
Available pool memory can reduce allocations further. This does not enlarge the
PRX `.bss` pool, descriptor tables or pipeline capacity. Restart the title after
replacing settings; live reload is unsupported.

The 64-byte little-endian AMPRCFG1 v1 record contains magic[8], version/size u32,
manifest buildId[16], decoded/physical cache bytes u64, workers/reserve u32,
CRC32 u32 and reserved-zero u32. CRC covers all bytes with its own field zeroed.
Packing publishes the `.runtime` sidecar with the pack set before publishing the manifest;
a rebuild without `[runtime]` removes a stale `.runtime`. Runtime settings are
excluded from the content build ID so tuning does not change the asset identity.
Do not update a running title's pack files during publication.

## Features

- independent raw-LZ4 blocks with random access;
- explicit filesystem I/O-page geometry per physical volume;
- page-contained random/mixed chunks and dense, aligned streaming extents;
- grouped SDK AIO submission of mandatory cache-miss pages;
- shared in-flight-deduplicated cache of compressed/raw filesystem I/O pages;
- inline AIO completion when every requested decoded block is already cached;
- per-file block sizes from **16 KiB through 1 MiB**;
- automatic RAW fallback when LZ4 does not save enough space;
- sampled file-level auto-loose policy for large, already-compressed archives;
- multiple pack lanes and volume rollover at block boundaries;
- optional striping of large opaque files across pack lanes;
- ordered include/exclude rules with last-match-wins semantics;
- `compress`, `store`, and `loose` actions;
- configurable block deduplication scoped to a lane or a complete packing group;
- deterministic manifests and pack data;
- CRC-32 for manifest/data headers and manifest payload, plus decoded-block
  CRCs in an offline-only sidecar that is never loaded by the runtime;
- offline `pack`, `unpack`, `verify`, `list`, and `inspect` commands;
- APR-trace profiler that emits TOML, runtime headers, reports and portable include lists;
- asynchronous runtime reads through virtual FDs and virtual SDK AIO IDs;
- priority-aware worker scheduling;
- bounded worker scratch memory and lazy pack-FD LRU;
- decoded-block cache with in-flight deduplication, CLOCK eviction, second-touch
  admission, immediate admission for hot/shared blocks, and streaming bypass;
- mixed packed and ordinary loose files in one AMPRIDX3 namespace.
- a read-only union directory overlay for packed-only files and synthetic
  parent directories;
- synthetic stat/reachability plus virtual/hybrid directory FD support;
- process-wide read-only `open/read/pread/lseek/fstat/close/AIO`
  interception enabled by the PackedStdio build profile;
- explicit logical-to-physical pack I/O logging and directory-overlay counters.

## Runtime architecture

The existing APR reactor continues to issue ordinary SDK-style reads:

```text
fileId -> APR asset open -> fd -> sceKernelAioSubmitReadCommandsMultiple()
```

APR callers already own the immutable AMPRIDX3 `fileId` and
`FileEntryView`. The reactor direct-open path and the shared APR FD cache call
`ampr_open_indexed_or_real()`, which first invokes
`ampr_pack_try_open_indexed(fileId, FileEntryView, ...)` and falls through to the
immutable real libkernel slot for loose records. APR uses
`O_RDONLY | O_NONBLOCK`, so the default policy intercepts only those asset
reads.

The generic `ampr_real_posix_open()` wrapper remains a real-slot-only
boundary. Keeping manifest/index opens out of the path-based pack resolver
eliminates recursive lookup and compiler TLS support from the PRX. The pack
runtime opens its manifest and physical data volumes through directly resolved
real POSIX libkernel functions.

For a virtual FD, module-local AIO submit/poll/delete wrappers preserve the SDK
array API and may mix real and virtual requests in one call. The retained pack
pipeline performs:

```text
logical offset
    -> AMPRPAK4 file record
    -> independent chunk tasks
    -> mandatory cache-miss page set
    -> complete set joins a bounded same-priority plural SDK AIO submit
    -> shared aligned physical-page cache
    -> raw copy or safe LZ4 block decode
    -> destination buffer
```

Each logical request retains its page leases across AIO completion and may
resume on any decode worker. The pack layer gathers only cache-miss pages needed
by the current task span. Within that bounded set, adjacent cold pages from the
same pack volume are coalesced into 128--512 KiB physical AIO requests. A
fragmented cache layout uses the retained staging window and scatters the
completed bytes into the independently published page leases; allocation
failure falls back to the original one-request-per-page path. The reactor can
place ordinary reads and several
complete logical sets of the same priority into one SDK request array of up to
64 entries and lets SDK AIO choose their physical execution order. No logical
set is split and every returned ID remains owned by its originating set. Ready
and newly loaded page-contained chunks decode directly from pinned cache pages.
Random/mixed
chunks are laid out so one small
chunk never straddles two filesystem I/O pages; dense streaming extents trade
that isolation for compact sequential placement. Cache pressure and chunks that
cross page boundaries use an exact aligned range containing the current chunk.
Its 2 MiB staging window is allocated lazily for a retained context and reused
until pack shutdown. No pack access class expands a request speculatively.
All physical pages completed by one set are published under one cache lock and
one publication epoch. Physical cache acquisition and lease release are also
batched per bounded page set; retained waiters observe the shared epoch without
a blocking physical-cache wait path.

The APR reactor still owns command ordering, priority lanes, fences, polling,
completion publication, retries, and cancellation. Physical pack ranges enter
the reactor through bounded external-read slots and share one native admission
snapshot, priority submit batch, poll array, and delete array with loose reads;
the pack module does not run a parallel AIO pump. Thirty-two retained contexts
cover the complete external broker pool, allowing backing reads to remain
queued or in flight while the bounded decode pool processes other completed
windows. This does not reserve 32 native IDs: global dynamic admission remains
shared with loose reads. Decode/cache work is never performed on the reactor
thread, and a cache loading join yields instead of occupying a worker.
No APR command encoding or public export is extended. Physical pack descriptors
participate in the existing common APR FD budget as well as the pack-specific
LRU/cap. A mandatory set never spans more volumes than the configured pack-FD
cap, so a low cap advances a striped read through smaller complete sets instead
of repeatedly pinning an unsatisfiable descriptor prefix.

The default production integration intercepts APR read-only opens and exposes a
read-only directory namespace overlay through `open(O_DIRECTORY)`, `getdents`,
`stat`, reachability, `fstat`, rewind and close. This lets a title discover a
packed file even after the original directory entry has been removed.

Ordinary title-side data reads remain unchanged unless the build explicitly
sets `AMPR_PROCESS_READ_INTERCEPT=1`. That experimental variant hooks read-only
`open`, `read`, `pread`, `lseek`, `fstat`, `close`, and the SDK AIO
submit/poll/delete family, reusing the same virtual FD/AIO backend. Writable
opens and `mmap` are not virtualized; executable modules and mmap-backed assets
must remain loose. See
`docs/ASSET_PACK_DIRECTORY_OVERLAY_RU.md` for deployment and diagnostics.

## On-disk files

Default deployment names are:

```text
/app0/ampr_emu.index          existing AMPRIDX3 path/fileId index
/app0/ampr_assets.index       AMPRPAK4 runtime storage manifest
/app0/ampr_assets-000.pak     AMPRDAT3 data volume
/app0/ampr_assets-001.pak     AMPRDAT3 data volume
...
```

The packer also writes `ampr_assets.index.crc` beside the manifest. It is bound
to the manifest build ID and contains one decoded CRC-32 per logical chunk.
Python `verify` and `unpack` require it, but the PRX never opens or loads it.
Keep it with the PC-side verification/backup set; deploying it to `/app0` is
optional and provides no runtime benefit.

The little-endian `AMPRCRC1` file starts with a 48-byte header containing its
magic/version/header size, manifest build ID, 64-bit chunk count, payload CRC,
and header CRC. Its payload is exactly `chunk_count` little-endian `uint32`
decoded CRCs in logical chunk order, so its total size is
`48 + chunk_count * 4` bytes.

The pack manifest contains one file record for every AMPRIDX3 file ID. A record
is either packed or loose, so the existing `fileId == record_index + 1` mapping
is preserved.

Each packed file references an ordered range of independent chunk records. The
compact 12-byte runtime chunk record stores:

- a 16-bit physical pack ID and 48-bit absolute offset;
- a 20-bit stored size, RAW/LZ4 codec and placement flags.

The decoded size is derived from the owning file record and block geometry.
The runtime uses bounded `LZ4_decompress_safe` output validation but performs no
decoded-payload CRC calculation. Offline tools load the CRC sidecar and validate
both compressed and RAW chunks. The runtime vendors and pins `lz4/lz4`
`v1.10.0` so the Prospero and host builds use the same raw-block decoder.

Every data-volume record stores its `io_page_size`; every data volume contains a
fixed header with pack ID, build ID, payload range, and header CRC. The runtime
rejects mixed manifests/volumes from different builds and rejects non-streaming
chunks whose declared placement is not page-safe before serving data.

AMPRPAK4 is not index-compatible with AMPRPAK1/2/3. Its data volumes remain
AMPRDAT3, so `tools/convert_ampr_pack_v3.py` can compact an existing AMPRPAK3
manifest and externalize its CRCs without recompressing or rewriting `.pak`
volumes. A newly packed set must still publish its manifest, CRC sidecar, volumes,
and (when configured) runtime sidecar as one build-ID-consistent set.

## Installing the packer

Python 3.11 or newer is required because the configuration parser uses the
standard-library `tomllib` module.

```bash
python -m pip install -r tools/requirements-pack.txt
```

If the Python `lz4` module is unavailable, the tools try the system `liblz4`.
The Python module is recommended for predictable fast/HC encoder options.
New configurations use LZ4 HC level 12 by default. Select `fast` explicitly
only when pack-build time matters more than maximum offline compression.
The `pack` command reports throttled planning, compression and publication
progress on stderr, including file/byte counts and elapsed time. Use
`--no-progress` for silent automation; the final JSON remains on stdout and its
`loose_paths` array lists every source path that must remain under `/app0`.

## Generating a profile from APR journals

`tools/ampr_pack_profile.py` consumes one or more `ampr_commands.bin` journals
and their matching `ampr_emu.index`. It derives per-file access geometry, block
size, layout, hot admission, pack groups, cache sizes and worker count.

Generate one title profile:

```bash
python tools/ampr_pack_profile.py generate ./trace-directory \
  --output ./profiles/title.toml \
  --report ./profiles/title.md \
  --metrics ./profiles/title.json \
  --runtime-header ./profiles/title.runtime.h
```

Generate a support bundle containing several titles:

```bash
python tools/ampr_pack_profile.py batch ./adaptive.zip \
  --output-dir ./profiles \
  --batch-jobs 4
```

Batch mode defaults to safe directory generalisation and bounded heuristic cache
sizing. Use `--cache-sim --cache-max-touches 250000` for a sampled decoded-cache
simulation, or `--pattern-mode exact` when no directory generalisation is
acceptable. Large exact path sets are stored in adjacent `*.include.txt` files
and referenced through `include_from`, keeping TOML readable without losing
path precision.

The runtime header is consumed directly by the payload build:

```bash
make clean verify PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk \
  PACK_PROFILE_HEADER=./profiles/title.runtime.h
```

The generated values are recommendations from the captured interval, not hard
platform limits. Merge startup, level loading, fast travel, combat and revisit
traces before deleting original loose files.

## Building packs

Start from an existing `ampr_emu.index` generated for the same `/app0` tree:

```bash
python tools/ampr_pack.py pack \
  --root /path/to/app0 \
  --ampr-index /path/to/app0/ampr_emu.index \
  --output /path/to/app0 \
  --config tools/ampr_pack.example.toml
```

The command writes data volumes to temporary files, fsyncs them, publishes the
volumes, and publishes the manifest last. Existing volume files are moved to
private backups during publication and restored if any later volume fails, so a
normal build error does not destroy the prior pack set. A process or power loss
mid-publication is detected by the build ID and fails closed. For a fully atomic
external deployment, build into a staging directory and switch the whole title
image/directory at once.

### Command-line include/exclude overrides

Patterns are relative to `/app0` and use shell-style glob matching:

```bash
python tools/ampr_pack.py pack \
  --root ./app0 \
  --ampr-index ./app0/ampr_emu.index \
  --output ./packed-app0 \
  --config ./pack.toml \
  --include 'assets/**' \
  --include 'data/**' \
  --exclude 'assets/debug/**' \
  --exclude '**/*.sprx'
```

Pattern files are also supported:

```bash
python tools/ampr_pack.py pack ... \
  --include-from include-assets.txt \
  --exclude-from exclude-assets.txt
```

Blank lines and lines beginning with `#` are ignored.

The configured manifest name and every path matching `pack_pattern` are
automatically forced loose when they appear in AMPRIDX3. This prevents recursive
packing even when custom nested output names or extensions are used.

## Rule configuration

Rules are evaluated in declaration order; the **last matching rule wins**.
This makes broad defaults followed by narrow exceptions straightforward.

```toml
[pack]
default_action = "loose"
default_block_size = "64KiB"
io_page_size = "64KiB"
payload_alignment = "64KiB" # keep volume payload boundaries I/O-page aligned
chunk_alignment = "64B"
workers = 8
deduplicate = true
deduplicate_streaming = false
min_savings_bytes = 64
min_savings_ratio = 0.01
io_neutral_min_savings_bytes = "8KiB"
io_neutral_min_savings_ratio = 0.125
auto_loose_large_files = true
auto_loose_hot_files = false
auto_loose_min_file_size = "64MiB"
auto_loose_sample_blocks = 32
auto_loose_sample_bytes = "16MiB"
auto_loose_min_savings_ratio = 0.05
auto_loose_max_raw_ratio = 0.90

[groups.assets]
pack_count = 4
assignment = "balanced"
max_pack_size = "8GiB"
io_page_size = "64KiB"       # optional per-group override

[[rule]]
action = "compress"
include = ["assets/**"]
exclude = ["assets/debug/**"]
block_size = "64KiB"
group = "assets"
layout = "mixed"

[[rule]]
action = "loose"
include = ["assets/user-mods/**"]
```


### External rule lists

Generated profiles can keep exact paths in files beside the TOML:

```toml
[[rule]]
action = "compress"
include_from = ["title.rule-003.include.txt"]
exclude_from = ["manual-exclusions.txt"]
block_size = "64KiB"
layout = "mixed"
```

List paths are relative to the TOML directory; absolute paths and `..` escapes
are rejected. Blank lines and comments beginning with `#` are ignored.

### File-level auto-loose

For files above `auto_loose_min_file_size`, the packer samples deterministic
blocks before lane assignment. A large archive is left loose when its sampled
LZ4 gain is below `auto_loose_min_savings_ratio` or too many samples would be
stored RAW. This avoids routing an already-compressed 100 GiB archive through
the userspace decoder and prevents it from distorting balanced lane placement.

A trace-derived hot rule is kept packed by default because decoded-cache reuse
may still justify the indirection. Set `auto_loose_hot_files = true` for a pure
size policy, or `force_pack = true` on an individual rule to override sampling.

### Actions

| Action | Result |
|---|---|
| `compress` | Test every block with LZ4; store RAW if the configured gain threshold is not met. |
| `store` | Put blocks in pack volumes without compression. Useful for already compressed media and FD/placement optimization. |
| `loose` | Keep the existing filesystem path and ordinary APR FD/AIO path. |

### Deduplication scope

`deduplicate_scope = "lane"` is the default. Identical blocks are reused only
inside the same physical lane, preserving the intended striped placement and
parallel pack-FD access. `deduplicate_scope = "group"` allows reuse across every
lane in the group and normally produces the smallest output, but repeated blocks
may collapse onto one volume and reduce read parallelism. Codec policy remains
part of the deduplication key, so `store` and `compress` records are never merged.

`deduplicate_streaming = false` is also the default. Reusing an earlier physical
block inside a streaming file breaks monotonic physical layout and may reduce
the kernel scheduler's opportunity to issue nearby pages efficiently. Enable it
only when size reduction is more important than sequential throughput or when
traces prove the repeated blocks remain hot in the decoded/system cache.

### Block sizes

Supported sizes are powers of two from 16 KiB to 1 MiB.

| Workload | Starting block size |
|---|---:|
| scripts, configuration, localization, tiny random reads | 16–32 KiB |
| unknown mixed assets | 64 KiB |
| large opaque archives with arbitrary internal seeks | 64 KiB |
| mostly sequential archives | 128–256 KiB after profiling |
| already compressed sequential media stored RAW | 256 KiB–1 MiB |

A 64 KiB default aligns naturally with the APR scheduler's 64 KiB accounting
granule. Eight blocks also form one 512 KiB APR dispatch quantum.

Smaller blocks reduce random-read amplification but increase chunk metadata and
system-call/decode scheduling overhead. Larger blocks improve compression and
sequential throughput but force more data to be read and decoded for small
random requests.

### Filesystem I/O pages and layout modes

`io_page_size` models the preferred filesystem transfer unit (`f_iosize`). On
the tested nullfs, bfs, and exfatfs mounts this is 64 KiB. It does not restrict
SDK AIO request sizes, but a cold small request can still populate a complete 64 KiB
filesystem/cache page. Version 3 therefore optimizes physical placement, resident manifest size,
and compressed byte count.

| Layout | Physical placement | Runtime physical reads | Intended use |
|---|---|---:|---|
| `random` | Stored chunks up to one I/O page may share a page but never cross it; larger chunks begin page-aligned. | Mandatory pages for the current task span. | hot/tiny files and strongly random access |
| `mixed` | Same page-safe placement as `random`. | Mandatory pages for the current task span. | opaque game archives and unknown workloads |
| `streaming` | Each extent starts page-aligned, then chunks remain densely 64-byte aligned. | Mandatory pages for the current task span. | traced sequential media/archive streams |
| `auto` | `streaming=true` selects streaming, `hot=true` selects random, otherwise mixed. | Same mandatory-page path. | compatibility/convenience |

For a 64 KiB RAW chunk in random or mixed layout, the offset is always a multiple
of 64 KiB, so a cold read never becomes two filesystem I/O pages merely because
of placement. Several smaller compressed chunks can occupy the same page; one
aligned SDK AIO request then supplies all chunks from that shared cache page.

Do not set `chunk_alignment = "64KiB"` merely to match `f_iosize`: that would
round every small compressed block to a full page and destroy most space savings.
Use `io_page_size = "64KiB"` with a dense alignment such as 64 bytes; the packer
adds padding only when the next random/mixed chunk would cross a page boundary.

For random/mixed data, `io_neutral_min_savings_bytes` and
`io_neutral_min_savings_ratio` reject weak LZ4 results that consume the same
number of physical I/O pages as RAW but add decode CPU cost. The default requires
at least 8 KiB and 12.5% savings for such same-page cases. Streaming data uses the
normal compression threshold because savings accumulate across sequential data.

The payload start and final volume size are rounded to `io_page_size`. exFAT may
report a larger allocation `f_bsize` (for example 1 MiB), but chunks are internal
extents of a large pack file, so only the pack file tail incurs allocation-unit
rounding; individual chunks do not become separate 1 MiB files.

## Runtime caches and fast completion

The runtime uses two independent caches:

1. **Decoded block cache** keyed by logical chunk. It avoids both physical I/O
   and LZ4 work. Requests whose complete range is already resident complete
   synchronously in the virtual AIO submission path without entering a worker
   queue.
2. **Physical I/O-page cache** keyed by build ID, pack ID and aligned physical
   offset. It deduplicates concurrent reads of the same compressed/raw 64 KiB
   page and captures short-range reuse even when decoded blocks are too numerous
   for the larger cache. Loading, ready and failed states prevent duplicate
   physical AIO requests.

Trace profiles size both caches separately. Typical starting points are 64–512
MiB decoded and 16–64 MiB physical. Streaming extents bypass unnecessary decoded
admission while SDK AIO receives the complete bounded set of required pages.

## Latency-aware worker scheduling

Virtual AIO jobs keep their SDK high/mid/low priority and are additionally
classified as latency, balanced or bulk work. Small requests and hot metadata
are latency jobs; streaming files and requests of at least 256 KiB are bulk.
Inside one SDK priority, latency precedes balanced and bulk work.

`AMPR_EMU_PACK_LATENCY_RESERVE_WORKERS` may reserve one worker that never takes
bulk jobs. This is useful for profiles such as Crimson, Nioh, Horizon and
Spider-Man, where thousands of tiny random reads coexist with large archive
slices. Bulk-oriented profiles such as Atlas, Mafia, SB, SMM and Starfield set
the reserve to zero so every worker remains available for throughput.

The profiler writes the reserve together with worker count and cache sizes into
the generated runtime header. Runtime summaries expose
per-class submit counts, queue-depth peaks and reserved-worker dispatches for
on-console validation.

## Multiple packs and striping

A group can own multiple logical lanes:

```toml
[groups.bulk]
pack_count = 4
assignment = "hash"
stripe_large_files = false # switch on only after an on-console A/B test
stripe_threshold = "256MiB"
stripe_group_blocks = 8
```

### File assignment

- `balanced`: largest files are assigned first to the currently lightest lane;
- `hash`: stable path-based lane selection;
- `round_robin`: stable file-ID rotation.

Keeping an ordinary file wholly on one lane minimizes seeks and metadata
crossing. Multiple lanes are still useful because different files can be read
concurrently through separate pack FDs.

### Large-file striping

For a file above `stripe_threshold`, groups of `stripe_group_blocks` consecutive
blocks rotate across lanes. With 64 KiB blocks and a group size of eight, each
512 KiB stripe stays contiguous in one volume while adjacent 512 KiB APR slices
can be in flight against different pack FDs. Choose the stripe group from the
reactor dispatch quantum divided by the selected block size; striping every tiny
block usually adds seeks without creating extra parallelism. The pack layer does
not add a second speculative prefetch policy.

Striping is useful only when the storage stack and workload can execute multiple
reads concurrently. It can be neutral or harmful for strictly sequential
single-request workloads, rotational media, or systems where all volume reads
collapse onto one serialized backend. Keep it opt-in and compare traces with and
without striping.

One virtual AIO request retains one pipeline context and its chunk tasks are
completed in logical order, but successive continuations may run on different
decode workers. Parallelism appears between simultaneously active logical
requests/slices, not by splitting one small request across workers. As a
starting point, use two to four lanes and do not create more lanes than the title
can keep busy through its AIO window. Keep `deduplicate_scope = "lane"` when the
purpose of multiple lanes is parallel physical I/O.

`max_pack_size` creates additional volumes for a lane at block boundaries. One
block must fit in the configured maximum.

## Inspecting and validating packs

```bash
python tools/ampr_pack.py inspect --index /app0/ampr_assets.index
python tools/ampr_pack.py list --index /app0/ampr_assets.index
python tools/ampr_pack.py list --index /app0/ampr_assets.index --file 'assets/**'
python tools/ampr_pack.py verify --index /app0/ampr_assets.index
```

`verify` opens every selected data volume, validates its build ID/header, reads
every unique physical chunk, decodes LZ4 where required, and validates the
derived decoded size and decoded CRC from `<manifest>.crc`. A missing, damaged,
or differently bound CRC sidecar is an explicit verification failure.

### Converting an existing AMPRPAK3 set

AMPRDAT3 volumes do not need to be repacked. Convert beside the old manifest so
its relative volume names continue to resolve:

```bash
python tools/convert_ampr_pack_v3.py \
  --index /app0/ampr_assets.index \
  --output /app0/ampr_assets-v4.index
python tools/ampr_pack.py verify --index /app0/ampr_assets-v4.index
```

The converter validates the complete AMPRPAK3 header/payload CRC, streams the
16-byte legacy chunk table into 12-byte AMPRPAK4 records, and writes
`ampr_assets-v4.index.crc`. It preserves the build ID, so existing AMPRDAT3
headers and the old `.runtime` contents remain compatible. Because sidecars are
named from the manifest, rename the verified v4 index and `.crc` together when
switching it to the original manifest name; the existing `.runtime` can then stay
in place. The converter refuses to overwrite the source; replace the deployed
manifest only while the title is stopped and retain the original for rollback.

## Unpacking

```bash
python tools/ampr_pack.py unpack \
  --index /app0/ampr_assets.index \
  --output ./unpacked \
  --overwrite
```

Selection patterns and mtime preservation are supported. Loose records are not
created by `unpack`, because their data is not present in the asset packs.

## Removing original files

A packed path may be removed from the deployed filesystem only after confirming
that every access uses supported APR or intercepted process-read paths. The
PackedStdio profile supports ordinary read-only file access; it does not
virtualize arbitrary mmap users. LooseStdio disables the pack integration.

A safe rollout is:

1. deploy packs while keeping original files;
2. enable file-status/pack diagnostics and exercise the complete title;
3. identify any direct filesystem or mmap users;
4. leave those paths `loose` with explicit final rules;
5. remove only verified APR-only packed source files.

Keep `ampr_emu.index`, `ampr_assets.index`, `ampr_assets.index.crc`,
`ampr_assets.index.runtime`, pack volumes, modules, executables, and runtime logs
excluded from recursive packing.

## Runtime memory defaults

Pack-enabled Makefile, legacy `ReleaseHooks`, and selectable `PackedStdio`
MSBuild configurations use a 384 MiB internal AMM pool. LooseStdio remains at
64 MiB, and a trace-generated runtime header can override the payload build.
The defaults are:

```text
decoded cache target     128 MiB
minimum decoded cache     16 MiB
post-cache memory reserve  32 MiB
workers                         4
retained pipeline contexts     32
lazy aligned I/O window/context up to 2 MiB
maximum decoded block/worker   1 MiB
physical I/O-page cache       32 MiB
mandatory pages/group             32
open physical pack FD cap      16
virtual FD slots               256
virtual AIO slots              256
```

The physical-page and decoded cache arenas are requested after the compact
manifest is resident. Before either cache is allocated, the runtime temporarily
reserves all 32 possible 2 MiB pipeline I/O windows, one maximum 1 MiB decoded
block per requested worker, and the 32 MiB post-cache safety margin. This keeps
cache admission from consuming memory needed after publication. Contexts using
only contiguous cache windows allocate no I/O scratch. Both caches contract
toward their configured minima when contiguous memory is unavailable; packed
reads remain functional without either cache. The trace profiler uses the same
pipeline, worker and safety budgets when recommending the fixed pool size. The
runtime sidecar tunes cache targets without recompilation; increasing the fixed
pool still requires a build property or a profile header. Budgets below the
compiled cache minimum use the smaller requested budget as their minimum.

Cache policy:

- `streaming` files bypass decoded caching;
- `hot` files and deduplicated/shared chunks enter immediately;
- normal chunks enter on the second observed access;
- concurrent readers of a loading cached chunk join the same decode;
- ready, unpinned entries use CLOCK eviction.

The cache uses 16 KiB pages internally, so all supported block sizes occupy an
integer number of contiguous cache pages.

AMPRPAK4 spends 12 resident bytes per logical chunk instead of AMPRPAK3's 16.
The separate four-byte CRC entry remains on disk for offline verification and is
not included in the runtime-pool calculation.

## Integrity and failure behavior

The runtime validates:

- manifest magic, version, endian marker, record sizes, section layout, bounds,
  header CRC, and payload CRC;
- every file/chunk relationship and logical-size sum;
- I/O-page size, page-aligned volume bounds, and page-safe non-streaming chunks;
- matching random/streaming file and chunk flags;
- safe relative pack names;
- data-volume magic, version, pack ID, build ID, size, payload range, and header
  CRC;
- exact LZ4 decoded size;
- logical read bounds;
- CPU-writable destination mappings when the query is supported.

Malformed metadata, missing volumes, short reads, metadata/header CRC
mismatches, invalid LZ4, or non-writable destinations complete the virtual AIO
request with an error; synthetic data is never silently returned. Runtime does
not calculate decoded-payload CRC. Offline `verify` and `unpack` require the
build-ID-bound CRC sidecar and retain decoded-content validation.

## Testing

Run all host tests:

```bash
make pack-tests
```

Run the C++ decoder/core/runtime tests under ASan and UBSan:

```bash
AMPR_PACK_TEST_SANITIZERS=1 \
ASAN_OPTIONS=detect_leaks=0:halt_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
python -m unittest -v \
  tests/test_pack_core_host.py \
  tests/test_pack_streaming_core_host.py \
  tests/test_pack_runtime_host.py
```

Coverage includes:

- mixed rules and block sizes;
- include/exclude overrides;
- multiple lanes and large-file striping;
- volume rollover;
- lane-scoped and group-scoped block deduplication, including separation of
  `store` and `compress` policy and opt-in streaming deduplication;
- deterministic output and rollback-safe publication;
- Unicode path hashing compatible with ASCII-only AMPR folding;
- corruption detection;
- pack/unpack round trips and complete subprocess CLI smoke coverage;
- LZ4 decode through the production core and runtime;
- complete host-mocked runtime flow: virtual open, asynchronous submit/poll/
  delete, cross-block reads, mixed real/virtual batches, concurrent reads from
  different pack lanes, cancellation, destination protection, LZ4 decode, and
  cache hits;
- 64 KiB page-contained random/mixed placement, page-aligned RAW blocks, dense
  streaming extents, per-group page-size overrides, weak same-page LZ4 fallback,
  mandatory-page grouping, exact cross-page fallback, dense streaming files
  that mix LZ4 and unaligned RAW chunks, plural native-AIO submission, and exact
  underlying physical-read counts.

The suite contains Python tool tests plus host-compiled C++ decoder, parser,
streaming and virtual-AIO integration tests. It also covers shared physical-page
reuse, inline decoded-cache completion, file-level auto-loose decisions,
external rule lists and trace-profile generation. The C++ parser/decoder
consumes manifests produced by the Python tool, which catches ABI drift between
both implementations. `make verify` passes with PS5 Payload SDK v0.42;
title-level performance and correctness still require a real console workload.

Pack counters and worker/AIO latency sampling are diagnostic-only. They compile
out with the default `AMPR_EMU_DEBUG_LOG=0`; define
`AMPR_EMU_PACK_TELEMETRY=1` explicitly only for profiling or tests that consume
`ampr_pack_runtime_stats()`.

## Tuning metrics

`apr.pack.metrics` and five `apr.pack.latency` records accompany the rate-limited
pack I/O snapshot (at most once per second during backing completions, and at
shutdown). `tools/analyze_ampr_log.py` exposes them as `pack_metrics` in JSON and
in the text report. Snapshots are cumulative: use the latest complete set, never
sum periodic counters. With exclusively warm/inline traffic, the final counters
are available at orderly shutdown; a crash may leave an older or partial snapshot.

Latency p50/p95/p99 are **upper bounds** from power-of-two microsecond buckets,
not exact order statistics. Bucket 0 covers 0..1 us; buckets 1..30 end at 2^i us;
bucket 31 is overflow. The analyzer returns null for empty/overflow percentiles
and flags incomplete snapshots. Logical latency includes submission preparation,
queueing, I/O, cache joins and decode through result publication, including
terminal errors/cancellation. `latency_class` is its latency-priority subset.
Physical samples use accepted backing-group completion latency, weighted by
request count; they are not independent device service times. Queue and worker
samples are per dispatch/resume. Worker duration is elapsed time, not thread CPU
time. In-flight concurrent snapshots are approximate; take comparisons only from
quiescent endpoints or equivalent workloads.

`delivered` counts successful logical result bytes, `physical` counts issued pack
bytes and `stored` counts consumed compressed/raw payload. The analyzer reports
physical/delivered and physical/stored ratios plus lookup hit rates. Cache hit
rates describe internal lookups, not the fraction of user requests served from
cache. Failed/cancelled I/O is counted separately. Allocated cache sizes may be
smaller than requested; they are allocation snapshots, not live used-byte gauges.
At shutdown `workers` is zero after joining; use periodic snapshots to check
actual concurrency and `requestedWorkers` for the configured limit.

Do not choose pack count, block size, or cache size from compression ratio alone.
Some items below require title/platform measurements or additional focused
instrumentation; the built-in worker timer does not measure decoder CPU time.
Compare at least:

- p50/p95/p99 logical read latency;
- physical bytes versus logical bytes;
- LZ4 decoded bytes and CPU time;
- decoded-cache hit, join, admission, eviction and inline-completion counts;
- physical-page cache hit, loading-join, admission and eviction counts;
- native backing-AIO batches, requests, `EAGAIN`, and submit/poll/delete errors;
- retained pipeline active/peak capacity, current phase occupancy, and I/O/cache
  yield counts;
- AIO queue occupancy and oldest request age;
- pack-FD reopen count;
- SDK-AIO batch width and page locality across adjacent pack stripes;
- startup time and frame-time outliers.

A larger cache helps only while it retains data that is reused. Streaming bypass
and second-touch admission are usually more important than increasing the cache
from 128 MiB to 256 MiB without profiling.
Public mixed/virtual AIO submissions retain a lifecycle lease from reservation
through native submission, inline copying, and ID/group publication. Shutdown
closes admission, rejects later submissions with `EBUSY`, and drains these
leases before stopping workers or releasing slots, caches, and the manifest.
An outer singular-group lease also covers child submission and rollback.
Infinite waits containing only virtual requests or virtual-only groups use
completion notifications. Groups record whether they contain native children;
mixed waits retain bounded native polling, and finite waits retain deadlines.
Real-only plural submit/poll/cancel/delete calls forward the original arrays
before constructing pack state or entering its locks. Native operations remain
available after virtual submission admission is closed.
