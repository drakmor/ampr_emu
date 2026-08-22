/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 */

#pragma once
/*
 * AMPR emulation configuration for the Prospero target branch.
 *
 * The only supported build target in this repository is Prospero. The active
 * implementation keeps the public `sce::Ampr` surface inside `libSceAmpr.prx`
 * while routing memory, queue, and APR service boundaries through the official
 * SDK / kernel interfaces required by the target runtime.
 */

#ifndef AMPR_EMU_MAX
#define AMPR_EMU_MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#ifndef AMPR_EMU_MIN
#define AMPR_EMU_MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifndef AMPR_EMU_PERCENT_CEIL
#define AMPR_EMU_PERCENT_CEIL(value, percent) (((value) * (percent) + 99) / 100)
#endif

#ifndef AMPR_EMU_PERCENT_FLOOR
#define AMPR_EMU_PERCENT_FLOOR(value, percent) (((value) * (percent)) / 100)
#endif

#ifndef AMPR_EMU_FD_OPEN_BUDGET_CAP
// Combined APR FD budget for cached descriptors plus direct single-quantum
// full-file AIO opens.
// Keep this below the process FD ceiling so title-side non-APR file I/O has
// headroom.
#define AMPR_EMU_FD_OPEN_BUDGET_CAP 50
#endif

#ifndef AMPR_EMU_FD_CACHE_BUDGET_PERCENT
// Soft share of the APR FD budget retained as idle cached archive descriptors.
// Direct and cached opens still draw from one common effective FD budget.
#define AMPR_EMU_FD_CACHE_BUDGET_PERCENT 90
#endif

#ifndef AMPR_EMU_FD_CACHE_CAP
#define AMPR_EMU_FD_CACHE_CAP \
    AMPR_EMU_MIN(AMPR_EMU_FD_OPEN_BUDGET_CAP, \
                 AMPR_EMU_MAX(AMPR_EMU_PERCENT_FLOOR(AMPR_EMU_FD_OPEN_BUDGET_CAP, \
                                                     AMPR_EMU_FD_CACHE_BUDGET_PERCENT), \
                              1))
#endif

#if AMPR_EMU_FD_CACHE_CAP < 1
#error "AMPR_EMU_FD_CACHE_CAP must be at least 1 because APR fd-cache is mandatory."
#endif

#ifndef AMPR_EMU_FD_CACHE_PRESSURE_MIN_CAP
// Lower bound for repeated FD-pressure backoff.
#define AMPR_EMU_FD_CACHE_PRESSURE_MIN_CAP \
    AMPR_EMU_MAX(AMPR_EMU_PERCENT_CEIL(AMPR_EMU_FD_CACHE_CAP, 25), 1)
#endif

#ifndef AMPR_EMU_FD_CACHE_EMFILE_IDLE_CLOSE_PERCENT
// Percentage used by the ordinary high/critical watermark reclaim policy.
// Active pinned FDs are never closed by this path.
#define AMPR_EMU_FD_CACHE_EMFILE_IDLE_CLOSE_PERCENT 10
#endif

#ifndef AMPR_EMU_FD_CACHE_IDLE_CLOSE_NS
// Close unpinned cached APR FDs after this much monotonic idle time. Active
// pinned FDs are never closed by this path. Set to 0 to keep idle FDs until
// pressure/watermark eviction.
#define AMPR_EMU_FD_CACHE_IDLE_CLOSE_NS 10000000000ull
#endif

#ifndef AMPR_EMU_FD_CACHE_IDLE_SCAN_NS
// Maximum delay before the APR reactor wakes while otherwise idle to enforce
// AMPR_EMU_FD_CACHE_IDLE_CLOSE_NS.
#define AMPR_EMU_FD_CACHE_IDLE_SCAN_NS 250000000ull
#endif

#ifndef AMPR_EMU_FD_OPEN_BUDGET_MIN_CAP
// Lower bound for repeated EMFILE backoff of the combined APR FD budget.
#define AMPR_EMU_FD_OPEN_BUDGET_MIN_CAP \
    (AMPR_EMU_FD_CACHE_PRESSURE_MIN_CAP + 1)
#endif

#ifndef AMPR_EMU_FD_OPEN_BUDGET_EMFILE_REDUCE_PERCENT
// Each EMFILE reduces the combined cached+direct FD budget by this percentage.
#define AMPR_EMU_FD_OPEN_BUDGET_EMFILE_REDUCE_PERCENT 5
#endif

#ifndef AMPR_EMU_APP0_INDEX_AUTOBUILD
// 1 -> on the first safe AMPR entrypoint, load /app0/ampr_emu.index or build it
// by recursively scanning /app0 once and trying to save the generated AMPRIDX3.
// 0 -> require a deployed index for case-insensitive lookup and use direct
// stat() for exact-case paths when the index is missing.
#define AMPR_EMU_APP0_INDEX_AUTOBUILD 1
#endif

#ifndef AMPR_EMU_APP0_INDEX_TRUST_UNIQUE_HASH
// 1 -> when an AMPRIDX3 hash appears exactly once in the loaded index, trust the
// hash plus path length and skip full path comparison. This is faster but can
// theoretically return a false positive if an absent path collides with a
// unique 64-bit index hash. The active default enables this fast path; set it
// to 0 for strict full path verification.
#define AMPR_EMU_APP0_INDEX_TRUST_UNIQUE_HASH 1
#endif

#ifndef AMPR_EMU_APR_AIO_INFLIGHT
// Normal/base number of per-read SDK AIO submit IDs owned by the APR reactor.
// Age-based backpressure may temporarily reduce this value, while the optional
// small-read boost below may temporarily increase it.
#define AMPR_EMU_APR_AIO_INFLIGHT 32
#endif

#ifndef AMPR_EMU_FD_DIRECT_CAP_RESERVE
// Effective APR-budget slots kept outside the direct full-file population for
// cached descriptors and process-wide safety headroom.
#define AMPR_EMU_FD_DIRECT_CAP_RESERVE 12u
#endif

#ifndef AMPR_EMU_FD_DIRECT_CAP_PRESSURE_PERCENT
// Temporary tighter share while the reactor is inside an FD-pressure cooldown.
#define AMPR_EMU_FD_DIRECT_CAP_PRESSURE_PERCENT 60u
#endif

#ifndef AMPR_EMU_FD_DIRECT_OPEN_SAFETY_RESERVE
// Keep this many APR-budget slots unused while admitting a new direct FD. This
// absorbs small process-wide FD races and gives title-side opens breathing
// room without reducing the idle cache cap.
#define AMPR_EMU_FD_DIRECT_OPEN_SAFETY_RESERVE 6u
#endif

#ifndef AMPR_EMU_FD_CACHE_OPEN_PRESSURE_IDLE_CLOSE_PERCENT
// A real open() resource-pressure failure is stronger evidence than the normal
// high-watermark heuristic. Drop this share of currently idle cache entries
// before retrying. Pinned descriptors are never closed.
#define AMPR_EMU_FD_CACHE_OPEN_PRESSURE_IDLE_CLOSE_PERCENT 100u
#endif

#ifndef AMPR_EMU_APR_READ_CHUNK_QUANTUM
// Maximum number of new host AIO requests one APR priority lane may admit in
// one scheduler pass. The byte budget below is applied at the same time, so
// eight request slots are shared across consecutive jobs in the same priority
// lane. The byte budget still prevents a large sequential burst.
#define AMPR_EMU_APR_READ_CHUNK_QUANTUM 8u
#endif

#ifndef AMPR_EMU_APR_READ_PASS_MAX_BYTES
// Execution-cursor reads and cross-EOP read-ahead share this charged-byte
// budget for one APR priority-lane scheduler pass. A request is never split
// merely to fit the unused tail of the budget.
#define AMPR_EMU_APR_READ_PASS_MAX_BYTES 0x80000u
#endif

#ifndef AMPR_EMU_APR_READ_CREDIT_GRANULE_BYTES
// Scheduler/admission byte accounting granule only. Actual AIO request lengths
// are unchanged: 1..64 KiB costs 64 KiB of credit, 64 KiB+1..128 KiB costs
// 128 KiB, and so on.
#define AMPR_EMU_APR_READ_CREDIT_GRANULE_BYTES 0x10000u
#endif

#ifndef AMPR_EMU_APR_PER_READ_ACTIVE_CHUNKS
// A logical ReadChain is sliced at up to 512 KiB and its charged-byte window is
// also 512 KiB, so only one slice can be live at a time. Small-file batching
// happens across read commands/jobs through the shared priority-lane budget.
#define AMPR_EMU_APR_PER_READ_ACTIVE_CHUNKS 4u //1u
#endif

#ifndef AMPR_EMU_APR_PER_READ_ACTIVE_BYTES
// Maximum charged in-flight bytes for one logical readFile. Each request is
// rounded up to AMPR_EMU_APR_READ_CREDIT_GRANULE_BYTES for admission only.
// Thus a full 512 KiB chunk consumes the complete per-read window. The separate
// priority-lane pass budget may still batch up to eight <=64 KiB read commands.
#define AMPR_EMU_APR_PER_READ_ACTIVE_BYTES  0x200000u // 0x80000u
#endif

#ifndef AMPR_EMU_APR_GROUP_SOFT_TARGETS
// Approximate A53's three NSID2 package-read groups over the single userspace
// AIO window: priority 0 -> U, priorities 1..3 -> H, priorities 4..6 -> N.
// Targets are soft: unused capacity is borrowable, but a group above target
// yields new admissions while another ready group is still below target.
#define AMPR_EMU_APR_GROUP_SOFT_TARGETS 1
#endif

#ifndef AMPR_EMU_APR_AIO_SMALL_READ_INFLIGHT
// Temporary active-read window used only when the already-active workload is
// dominated by small reads. Extra slots above AMPR_EMU_APR_AIO_INFLIGHT are
// filled with small requests only, so bulk traffic cannot consume the boost.
// Set to AMPR_EMU_APR_AIO_INFLIGHT (or 0) to disable the boost.
#define AMPR_EMU_APR_AIO_SMALL_READ_INFLIGHT 64
#endif

#ifndef AMPR_EMU_APR_AIO_SMALL_READ_MAX_BYTES
// A request at or below this size is considered small for dynamic AIO-window
// growth. The threshold applies to the actual SDK AIO slice, not file size.
#define AMPR_EMU_APR_AIO_SMALL_READ_MAX_BYTES 0x10000u
#endif

#ifndef AMPR_EMU_APR_AIO_SMALL_READ_MIN_PERCENT
// Minimum percentage of currently active requests that must be small before
// the reactor may grow from the base window to SMALL_READ_INFLIGHT.
#define AMPR_EMU_APR_AIO_SMALL_READ_MIN_PERCENT 75u
#endif

#ifndef AMPR_EMU_APR_AIO_SMALL_READ_MAX_OLDEST_MS
// Never enable the small-read boost when an already-submitted request is older
// than this value. Age-based backpressure always has priority over the boost.
#define AMPR_EMU_APR_AIO_SMALL_READ_MAX_OLDEST_MS 50u
#endif

#ifndef AMPR_EMU_APR_AIO_SMALL_READ_BOOST_RECOVERY_COOLDOWN_MS
// After age-based backpressure returns to Normal, keep the reactor at the base
// window for this long before small-read growth may be enabled again. This
// prevents short threshold excursions from immediately bouncing 24 -> 32 -> 48
// and feeding the SDK queue before it has stabilized.
#define AMPR_EMU_APR_AIO_SMALL_READ_BOOST_RECOVERY_COOLDOWN_MS 250u
#endif

#ifndef AMPR_EMU_APR_AIO_THROTTLE_MEDIUM_AGE_MS
// Live SDK-queue backpressure. When the oldest outstanding request reaches this
// age, admission stops refilling above the medium window.
#define AMPR_EMU_APR_AIO_THROTTLE_MEDIUM_AGE_MS 250u
#endif

#ifndef AMPR_EMU_APR_AIO_THROTTLE_SEVERE_AGE_MS
// Severe threshold for an outstanding AIO that is being starved/reordered.
#define AMPR_EMU_APR_AIO_THROTTLE_SEVERE_AGE_MS 500u
#endif

#ifndef AMPR_EMU_APR_AIO_THROTTLE_EMERGENCY_AGE_MS
// Emergency threshold. Once an already-submitted request has remained
// outstanding for this long, stop refilling above the emergency window and
// give the SDK/storage scheduler room to drain its oldest work.
#define AMPR_EMU_APR_AIO_THROTTLE_EMERGENCY_AGE_MS 1000u
#endif

#ifndef AMPR_EMU_APR_AIO_THROTTLE_MEDIUM_INFLIGHT
#define AMPR_EMU_APR_AIO_THROTTLE_MEDIUM_INFLIGHT 24u
#endif

#ifndef AMPR_EMU_APR_AIO_THROTTLE_SEVERE_INFLIGHT
#define AMPR_EMU_APR_AIO_THROTTLE_SEVERE_INFLIGHT 16u
#endif

#ifndef AMPR_EMU_APR_AIO_THROTTLE_EMERGENCY_INFLIGHT
#define AMPR_EMU_APR_AIO_THROTTLE_EMERGENCY_INFLIGHT 8u
#endif

#ifndef AMPR_EMU_APR_AIO_THROTTLE_RECOVER_NORMAL_MS
// Hysteresis: a medium throttle is released only after the oldest request has
// fallen below this age.
#define AMPR_EMU_APR_AIO_THROTTLE_RECOVER_NORMAL_MS 50u
#endif

#ifndef AMPR_EMU_APR_AIO_THROTTLE_RECOVER_MEDIUM_MS
// Hysteresis: a severe throttle steps back to medium below this age.
#define AMPR_EMU_APR_AIO_THROTTLE_RECOVER_MEDIUM_MS 100u
#endif

#ifndef AMPR_EMU_APR_AIO_THROTTLE_RECOVER_SEVERE_MS
// Hysteresis: an emergency throttle steps back to severe only after the oldest
// request falls below this age. This preserves a real 8 -> 16 -> 24 -> 32
// recovery ladder instead of jumping directly out of emergency mode.
#define AMPR_EMU_APR_AIO_THROTTLE_RECOVER_SEVERE_MS 250u
#endif

#ifndef AMPR_EMU_APR_AIO_SDK_SCHEDULING_WINDOW_SIZE
// Number of requests from the front of each SDK AIO priority queue considered
// for scheduling optimization. This does not reserve AIO ids.
#define AMPR_EMU_APR_AIO_SDK_SCHEDULING_WINDOW_SIZE 128
#endif

#ifndef AMPR_EMU_APR_AIO_SDK_DELAYED_COUNT_LIMIT
// Maximum number of times SDK scheduling optimization may skip an older AIO
// request. This is independent of the optimization-window size.
#define AMPR_EMU_APR_AIO_SDK_DELAYED_COUNT_LIMIT 128
#endif

#ifndef AMPR_EMU_APR_AIO_POLL_INITIAL_STEP_NS
// Initial exponential-backoff step used to derive the first background AIO
// observation deadline. Reactor sleeping itself is governed by unified deadlines.
#define AMPR_EMU_APR_AIO_POLL_INITIAL_STEP_NS 50000
#endif

#ifndef AMPR_EMU_APR_AIO_POLL_BACKGROUND_INITIAL_MIN_NS
// Delay the first observation of newly submitted background reads. A newly
// issued read is often only a provisional tail and may be superseded by more
// reads from the same command buffer before it can gate visible completion.
#define AMPR_EMU_APR_AIO_POLL_BACKGROUND_INITIAL_MIN_NS 250000
#endif

#ifndef AMPR_EMU_APR_AIO_POLL_BACKOFF_MAX_NS
// Maximum per-request poll backoff for reads that currently do not gate APR
// publication, an in-order completion frontier, or a native EOP read fence.
#define AMPR_EMU_APR_AIO_POLL_BACKOFF_MAX_NS 1000000
#endif

#ifndef AMPR_EMU_APR_AIO_POLL_PRESSURE_BACKOFF_MAX_NS
// Background cap while at least 75% of the base native AIO window is occupied.
// Keep this independent of the much tighter critical-path cap below: tying the
// two together makes every background read poll like a publication fence.
#define AMPR_EMU_APR_AIO_POLL_PRESSURE_BACKOFF_MAX_NS 500000
#endif

#ifndef AMPR_EMU_APR_AIO_CAPACITY_POLL_INTERVAL_NS
// If a scheduler pass reaches a ReadFile while the last-known AIO window is
// full, request a bounded capacity probe for a later reactor pass.  This is
// deliberately independent of per-request background deadlines: admission
// pressure may justify checking a few native requests sooner, but never every
// reactor iteration.
#define AMPR_EMU_APR_AIO_CAPACITY_POLL_INTERVAL_NS 100000
#endif

#ifndef AMPR_EMU_APR_AIO_CAPACITY_POLL_BATCH_LIMIT
// Maximum unique non-due submitted AIO IDs sampled by one array
// admission-pressure probe. Every selected ID is observed by the same SDK
// call; any newly freed slots are consumed by the following queue traversal.
#define AMPR_EMU_APR_AIO_CAPACITY_POLL_BATCH_LIMIT 4
#endif

#ifndef AMPR_EMU_APR_AIO_POLL_CRITICAL_INITIAL_NS
// First retry after an immediate poll misses on a completion-critical read.
// This preserves the pre-optimization 10 us critical-path response while the
// majority of background reads keep the delayed first-poll policy above.
#define AMPR_EMU_APR_AIO_POLL_CRITICAL_INITIAL_NS 10000
#endif

#ifndef AMPR_EMU_APR_AIO_POLL_DEPENDENT_BACKOFF_MAX_NS
// Maximum backoff for a short-lived publication-critical read. Keep this tight
// while the request is in the normal completion-latency range.
#define AMPR_EMU_APR_AIO_POLL_DEPENDENT_BACKOFF_MAX_NS 100000
#endif

#ifndef AMPR_EMU_APR_AIO_POLL_STAGED_EOP_BACKOFF_MAX_NS
// Tighter cap for the exact read sequence that releases a deferred/native EOP.
// Explicit release gates never use the age-relaxed critical policy below.
#define AMPR_EMU_APR_AIO_POLL_STAGED_EOP_BACKOFF_MAX_NS 50000
#endif

#ifndef AMPR_EMU_APR_AIO_POLL_LONG_REQUEST_AGE_NS
// After this age an ordinary critical frontier/tail is still critical, but
// polling it every 100 us no longer buys much. Relax only the polling cap; do
// not reclassify it as background or change publication/fence semantics.
#define AMPR_EMU_APR_AIO_POLL_LONG_REQUEST_AGE_NS 10000000ull
#endif

#ifndef AMPR_EMU_APR_AIO_POLL_CRITICAL_LONG_BACKOFF_MAX_NS
// Age-relaxed cap for ordinary critical reads older than 10 ms. This restores
// the useful long-request optimization from v2 without the v2 semantic bug.
#define AMPR_EMU_APR_AIO_POLL_CRITICAL_LONG_BACKOFF_MAX_NS 250000
#endif

#ifndef AMPR_EMU_APR_AIO_POLL_STALL_AGE_NS
// Requests older than this are storage/scheduler stalls. Background work may
// use the 5 ms cap below; ordinary critical work stays critical but can relax
// only to AMPR_EMU_APR_AIO_POLL_CRITICAL_STALL_BACKOFF_MAX_NS.
#define AMPR_EMU_APR_AIO_POLL_STALL_AGE_NS 100000000ull
#endif

#ifndef AMPR_EMU_APR_AIO_POLL_CRITICAL_STALL_BACKOFF_MAX_NS
// Maximum cap for an old ordinary critical frontier/tail. Explicit EOP/release
// gates and SubmitAndGetResult remain on their tighter caps regardless of age.
#define AMPR_EMU_APR_AIO_POLL_CRITICAL_STALL_BACKOFF_MAX_NS 500000
#endif

#ifndef AMPR_EMU_APR_AIO_POLL_STALL_BACKOFF_MAX_NS
#define AMPR_EMU_APR_AIO_POLL_STALL_BACKOFF_MAX_NS 5000000u
#endif

#ifndef AMPR_EMU_APR_AIO_CROSS_EOP_READAHEAD
// 1 -> allow the reactor to issue same-priority APR reads located after one or
// more *OnCompletion records within one submitted command buffer. Each completion
// retains the read-sequence fence that preceded it and still dispatches in source
// order. Priority-lane scheduling may continue into following FIFO jobs while the
// shared per-pass read budget remains available. A valid WaitOnAddress whose
// condition is already true is transparent; any other non-read/non-EOP record
// stops speculative read-ahead inside the current job.
// Enabled in the active cursor-direct configuration.
#define AMPR_EMU_APR_AIO_CROSS_EOP_READAHEAD 1
#endif

#ifndef AMPR_EMU_APR_AIO_CROSS_EOP_MAX_FENCES
// Maximum number of source-ordered completion fences retained by one job.
// Read-ahead itself is deliberately not depth-tunable: the reactor may execute
// at most one speculative command per priority lane in each reactor tick.
#define AMPR_EMU_APR_AIO_CROSS_EOP_MAX_FENCES 64
#endif

#ifndef AMPR_EMU_APR_AIO_SUBMIT_RETRY_DELAY_NS
// Avoid immediately resubmitting the same active read when the process-wide
// SDK AIO id/window pool reports transient exhaustion.
#define AMPR_EMU_APR_AIO_SUBMIT_RETRY_DELAY_NS 50000
#endif

#ifndef AMPR_EMU_APR_ACTIVE_LANE_IDLE_SLEEP_NS
// Reactor sleep when command-buffer lanes are active but no parser or
// completion progress happened.
#define AMPR_EMU_APR_ACTIVE_LANE_IDLE_SLEEP_NS 10000
#endif

#ifndef AMPR_EMU_APR_AIO_DISPATCH_QUANTUM_BYTES
// A53 package reads yield after eight 64 KiB NSID2 device operations. One
// software-visible AIO request represents that fixed 512 KiB yield quantum.
#define AMPR_EMU_APR_AIO_DISPATCH_QUANTUM_BYTES 0x80000u
#endif

#ifndef AMPR_EMU_APR_FD_PRESSURE_COOLDOWN_MS
// How long FD pressure keeps the reduced AIO/FD limits active.
#define AMPR_EMU_APR_FD_PRESSURE_COOLDOWN_MS 2000
#endif

#ifndef AMPR_EMU_APR_REACTOR_THREAD_PRIORITY
// Prospero FIFO priorities: lower numbers are higher priority; default is 700.
// Raise a default-priority APR AIO owner ahead of ordinary loader spin loops,
// but never lower an already higher inherited priority.
#define AMPR_EMU_APR_REACTOR_THREAD_PRIORITY 256
#endif

#ifndef AMPR_EMU_APR_REACTOR_THREAD_AFFINITY
// 0 keeps the process/default affinity. Nonzero values are SceKernelCpumask.
// 0x3f is the SDK user-CPU mask used here to avoid inheriting a narrow loader
// thread affinity.
#define AMPR_EMU_APR_REACTOR_THREAD_AFFINITY 0x3f
#endif

#ifndef AMPR_EMU_INTERNAL_AMM_POOL_SIZE
// Fixed 64 MiB emulator-owned CPU pool. The runtime publishes one page-aligned
// PRX .bss buffer of this size and suballocates the resident index and transient
// scratch buffers from it. The static pool does not
// consume Direct/Flexible Memory and does not change title GiveDirectMemory
// arguments.
#define AMPR_EMU_INTERNAL_AMM_POOL_SIZE 0x04000000ull
#endif

#ifndef AMPR_EMU_APR_COMMAND_BUFFER_LIVE_MAX
// Retail titles may keep thousands of APR command buffers live. Fixed emulator
// side tables that mirror command-buffer and reactor job state must be sized from
// this ceiling instead of smaller diagnostic defaults.
#define AMPR_EMU_APR_COMMAND_BUFFER_LIVE_MAX 4096
#endif

#ifndef AMPR_EMU_APR_LOCAL_EQUEUE
// Diagnostic/A-B fallback only. The production APR completion path keeps
// WriteKernelEventQueue native and pre-submits fixed gated sidecars to A53.
// Set to 1 only when explicitly testing the older userspace equeue overlay.
#define AMPR_EMU_APR_LOCAL_EQUEUE 1
#endif

#ifndef AMPR_EMU_APR_EAGER_NATIVE_EQUEUE
// Pre-scan APR submissions and immediately submit native APR packets on
// priorities 1..6 to A53 behind fixed private gates. Priority 0 shares native
// High with AMM and therefore uses a just-in-time APR micro-submit to avoid a
// closed eager gate blocking an older AMM map. The old persistent APR batch is
// not mixed into a lane while this path is enabled.
#define AMPR_EMU_APR_EAGER_NATIVE_EQUEUE 0
#endif

#ifndef AMPR_EMU_APR_EAGER_NATIVE_EQUEUE_MAX_EVENTS
// Maximum native APR records in one eager sidecar. Only the exact encoded
// command span is reserved from the shared circular arena; no per-record mirror
// or maximum-sized per-job command buffer is retained.
#define AMPR_EMU_APR_EAGER_NATIVE_EQUEUE_MAX_EVENTS 2048u
#endif

#ifndef AMPR_EMU_APR_EAGER_NATIVE_EQUEUE_ARENA_BYTES
// One native-visible circular arena. Each eager job reserves only its encoded
// gate/packet/checkpoint bytes plus one progress word. Wrap and overlap are
// checked; real exhaustion backpressures submit until older slices retire.
#define AMPR_EMU_APR_EAGER_NATIVE_EQUEUE_ARENA_BYTES 0x04000000u
#endif

#ifndef AMPR_EMU_APR_LOCAL_EQUEUE_QUEUE_CAPACITY
// One tracked real equeue per possible live APR command-buffer owner. Storage
// is static and queue slots are managed by an O(1) free list.
#define AMPR_EMU_APR_LOCAL_EQUEUE_QUEUE_CAPACITY AMPR_EMU_APR_COMMAND_BUFFER_LIVE_MAX
#endif

#ifndef AMPR_EMU_APR_LOCAL_EQUEUE_REG_CAPACITY
// Process-wide mirror of successful native (eq,id,udata) AMPR registrations.
#define AMPR_EMU_APR_LOCAL_EQUEUE_REG_CAPACITY AMPR_EMU_APR_COMMAND_BUFFER_LIVE_MAX
#endif

#ifndef AMPR_EMU_APR_LOCAL_EQUEUE_PENDING_CAPACITY
// Shared FIFO-node pool for published APR events. Exhaustion is reactor
// backpressure; it must never select native fallback for the blocked packet.
#define AMPR_EMU_APR_LOCAL_EQUEUE_PENDING_CAPACITY AMPR_EMU_APR_COMMAND_BUFFER_LIVE_MAX
#endif

#ifndef AMPR_EMU_APR_LOCAL_EQUEUE_WAIT_GRACE_US
// After a synthetic APR event was delivered, briefly keep the next blocking
// wait in userspace so a nearby APR completion can be consumed without a
// private EVFILT_USER trigger. This is the initial adaptive window, or the
// fixed window when adaptive mode is disabled. Polling waits never use it.
// Set to 0 to disable the wait optimization completely.
#define AMPR_EMU_APR_LOCAL_EQUEUE_WAIT_GRACE_US 10u // 10u
#endif

#ifndef AMPR_EMU_APR_LOCAL_EQUEUE_WAIT_GRACE_ADAPTIVE
// Adapt the grace independently for each tracked equeue. The controller uses
// four bounded levels derived from WAIT_GRACE_US (1/4, 1/2, 1x, and 2x), grows
// after two hits, shrinks after every miss, and cools down after repeated misses.
#define AMPR_EMU_APR_LOCAL_EQUEUE_WAIT_GRACE_ADAPTIVE 1
#endif

#ifndef AMPR_EMU_APR_REACTOR_STALL_WARN_NS
// Emit one asynchronous reactor-stall snapshot after this much *wall-clock*
// time without parser, submit, native-batch, or AIO completion progress while
// work is still outstanding.  Do not key diagnostics to loop iterations: the
// adaptive AIO/WaitOnAddress scheduler intentionally changes loop cadence.
#define AMPR_EMU_APR_REACTOR_STALL_WARN_NS 100000000ull
#endif


#ifndef AMPR_EMU_APR_REACTOR_HEARTBEAT_MS
// Low-rate reactor state sample while APR work is present, even if progress is
// still being made. This catches visual hangs that do not trip stall detection.
#define AMPR_EMU_APR_REACTOR_HEARTBEAT_MS 1000
#endif

#ifndef AMPR_EMU_SUBMIT_COMMAND_BUFFER_DUMP
// Optional text submit-time decoded command-buffer dump bitmask:
//   bit 0 (1) -> dump AMM source command buffers
//   bit 1 (2) -> dump APR source command buffers
//   3         -> dump both domains
// This is independent from AMPR_EMU_COMMAND_LOG, which records the raw binary
// submit journal for offline decoding.
#define AMPR_EMU_SUBMIT_COMMAND_BUFFER_DUMP 0
#endif

#ifndef AMPR_EMU_COMMAND_LOG
// Raw submit-time command journal bitmask. The binary journal is intentionally
// separate from apr_emu.log so every packed command byte can be decoded
// offline without making the ordinary text logger lossless or excessively
// verbose:
//   bit 0 (1) -> APR submits
//   bit 1 (2) -> AMM submits
// Enable 3 for a complete AMPR command trace. 
#define AMPR_EMU_COMMAND_LOG 3
#endif

#ifndef AMPR_EMU_COMMAND_LOG_PATH
#define AMPR_EMU_COMMAND_LOG_PATH "/app0/ampr_commands.bin"
#endif

#ifndef AMPR_EMU_COMMAND_LOG_QUEUE_BYTES
// Bounded producer/consumer queue used by the asynchronous binary command
// journal. Submit threads only copy into this RAM queue; all filesystem I/O is
// performed by the dedicated writer thread. Queue overflow drops whole records
// (visible as sequence gaps) instead of blocking APR/AMM execution.
#define AMPR_EMU_COMMAND_LOG_QUEUE_BYTES (4u * 1024u * 1024u)
#endif

#ifndef AMPR_EMU_COMMAND_LOG_MAX_RECORD_BYTES
// Hard upper bound for one asynchronously snapshotted record. Very large debug
// records are dropped instead of spending unbounded submit-thread time copying
// them or monopolizing the queue. Normal APR/AMM buffers are far below this.
#define AMPR_EMU_COMMAND_LOG_MAX_RECORD_BYTES (1u * 1024u * 1024u)
#endif

#ifndef AMPR_EMU_COMMAND_LOG_SLOW_WRITE_MS
// Writer-thread-only diagnostic threshold. Slow writes are reported without
// blocking APR/AMM submitters and help distinguish storage stalls from queue
// pressure if a tracing run still behaves differently.
#define AMPR_EMU_COMMAND_LOG_SLOW_WRITE_MS 25u
#endif

#ifndef AMPR_EMU_COMMAND_LOG_FSYNC_ON_SHUTDOWN
// The async writer keeps a persistent descriptor and relies on normal
// filesystem buffering while the title runs. Set to 1 when crash-tail
// durability is more important than shutdown latency.
#define AMPR_EMU_COMMAND_LOG_FSYNC_ON_SHUTDOWN 0
#endif

#ifndef AMPR_EMU_APR_AIO_SLOW_WARN_MS
// Emit sparse diagnostics for SDK AIO reads that stay active this long.
#define AMPR_EMU_APR_AIO_SLOW_WARN_MS 1000
#endif

#ifndef AMPR_EMU_APR_AIO_AMM_EFAULT_RETRY_LIMIT
// AMM mapper work can make sparse/PRT VA AIO-safe shortly after the APR read is
// decoded. If SDK AIO reports EFAULT for AMM VA, retry in reactor order instead
// of publishing a failed APR completion before the mapper catches up.
#define AMPR_EMU_APR_AIO_AMM_EFAULT_RETRY_LIMIT 64
#endif

#ifndef AMPR_EMU_APR_AIO_AMM_EFAULT_RETRY_DELAY_NS
// Delay between AMM-VA EFAULT retries. Keep this short enough for streaming but
// nonzero so the reactor does not spin while the kernel mapper drains.
#define AMPR_EMU_APR_AIO_AMM_EFAULT_RETRY_DELAY_NS 10000000ull
#endif

#ifndef AMPR_EMU_APR_AIO_COMPLETION_RETRY_DELAY_NS
// Delay between completion-error retries. APR jobs must wait for a real read
// instead of publishing failed, skipped, or synthetic completion data.
#define AMPR_EMU_APR_AIO_COMPLETION_RETRY_DELAY_NS 1000000ull
#endif

#ifndef AMPR_EMU_APR_AIO_COMPLETION_RETRY_LIMIT
// Retry cap for non-EFAULT completion errors. Once reached, the reactor records
// a command error and completes the read sequence so one bad read cannot pin a
// native APR micro-submit forever.
#define AMPR_EMU_APR_AIO_COMPLETION_RETRY_LIMIT 64
#endif

#ifndef AMPR_EMU_APR_AIO_DELETE_TIMEOUT_NS
// An SDK-accepted AIO id must be deleted before its read descriptor can be
// released. A persistent delete failure is an infrastructure fault, not a
// title-visible APR read error.
#define AMPR_EMU_APR_AIO_DELETE_TIMEOUT_NS 5000000000ull
#endif

#ifndef AMPR_EMU_APR_AIO_DELETE_RETRY_LIMIT
// Fallback bound for platforms whose monotonic counter is unavailable.
#define AMPR_EMU_APR_AIO_DELETE_RETRY_LIMIT 4096u
#endif

#ifndef AMPR_EMU_APR_AIO_SLOW_COOLDOWN_TRIGGER_MS
// A completed AIO at or above this age marks the disk as recently saturated.
#define AMPR_EMU_APR_AIO_SLOW_COOLDOWN_TRIGGER_MS 500
#endif

#ifndef AMPR_EMU_APR_AIO_SLOW_COOLDOWN_MS
// Keep adaptive pressure active for this long after a slow AIO completion.
#define AMPR_EMU_APR_AIO_SLOW_COOLDOWN_MS 2000
#endif

#ifndef AMPR_EMU_TIME_LIMIT_UNIX_SECONDS
// Optional wall-clock deadline, as UTC Unix seconds. 0 disables it.
#define AMPR_EMU_TIME_LIMIT_UNIX_SECONDS 0ull
#endif

// Version
#ifndef AMPR_EMU_VERSION
#define AMPR_EMU_VERSION "0.3.6.4 (public beta) (c) Drakmor"
#endif

#ifndef AMPR_EMU_DEBUG_LOG
// 1 -> write debug logs for AMPR operations/events to AMPR_EMU_DEBUG_LOG_PATH.
// The first log write in each process truncates the file; later writes in the
// same run continue on the open fd.
// 0 -> compile out log callsites and the logger backend.
#define AMPR_EMU_DEBUG_LOG 1
#endif

#if AMPR_EMU_COMMAND_LOG && !AMPR_EMU_DEBUG_LOG
#error "AMPR_EMU_COMMAND_LOG requires AMPR_EMU_DEBUG_LOG because the command journal follows the main logger lifecycle"
#endif

#ifndef AMPR_EMU_DEBUG_LOG_VERBOSE
// 1 -> enable moderate success-path diagnostics. This level is intended to be
// usable during real startup/hang investigation without export/AMM hot-call
// traces.
#define AMPR_EMU_DEBUG_LOG_VERBOSE 0
#endif

#ifndef AMPR_EMU_DEBUG_LOG_TRACE
// 1 -> enable maximum trace logging: export entry/leave calls, command-buffer
// packing, per-read AIO, per-path resolve, fd-cache hits, and other hot-loop
// diagnostics. This is too expensive for normal gameplay and can change timing
// enough to hide hangs.
#define AMPR_EMU_DEBUG_LOG_TRACE 0
#endif

#ifndef AMPR_EMU_DEBUG_LOG_FILE_STATUS
// 1 -> include per-file resolve/open/read status lines in the minimal log
// without enabling the broader VERBOSE or TRACE success-path diagnostics.
// Requires AMPR_EMU_DEBUG_LOG=1.
#define AMPR_EMU_DEBUG_LOG_FILE_STATUS 0
#endif

#ifndef AMPR_EMU_DEBUG_LOG_PATH
#define AMPR_EMU_DEBUG_LOG_PATH "/app0/ampr_emu.log"
#endif

#ifndef AMPR_EMU_DEBUG_LOG_KERNEL_OUT
// 1 -> duplicate each formatted debug log message to the kernel debug output
// channel immediately, before enqueueing it for the file writer.
#define AMPR_EMU_DEBUG_LOG_KERNEL_OUT 0
#endif

#ifndef AMPR_EMU_DEBUG_LOG_CRITICAL_KERNEL_OUT
// 1 -> duplicate AMPR_CRITICAL_LOGF/debugLogCritical* lines to the kernel debug
// output channel even when AMPR_EMU_DEBUG_LOG_KERNEL_OUT is 0. Requires
// AMPR_EMU_DEBUG_LOG=1.
#define AMPR_EMU_DEBUG_LOG_CRITICAL_KERNEL_OUT 1
#endif

#ifndef DGB_CHANNEL_TTYL
#define DGB_CHANNEL_TTYL 0
#endif

#ifndef AMPR_EMU_DEBUG_LOG_KERNEL_OUT_CHANNEL
#define AMPR_EMU_DEBUG_LOG_KERNEL_OUT_CHANNEL DGB_CHANNEL_TTYL
#endif

#ifndef AMPR_EMU_DEBUG_LOG_SYNC_FSYNC
// 1 -> synchronous log writes call sceKernelFsync after every line. Keep this
// off by default: sceKernelWrite already completes in the caller thread, while
// per-line fsync is too slow for real title startup.
#define AMPR_EMU_DEBUG_LOG_SYNC_FSYNC 0
#endif

#ifndef AMPR_EMU_DEBUG_LOG_CRITICAL_SYNC_FSYNC
// 1 -> log lines classified as critical wait until the writer has written and
// fsynced that line. This is intended for crash-tail diagnostics without paying
// the per-line fsync cost of AMPR_EMU_DEBUG_LOG_SYNC_FSYNC.
#define AMPR_EMU_DEBUG_LOG_CRITICAL_SYNC_FSYNC 1
#endif

#ifndef AMPR_EMU_DEBUG_LOG_CRITICAL_SYNC_WAIT_US
// Maximum producer wait for a critical log line to reach disk. 0 means wait
// indefinitely. The timeout prevents diagnostics from turning a stuck writer
// into a hard title hang.
#define AMPR_EMU_DEBUG_LOG_CRITICAL_SYNC_WAIT_US 500000
#endif

#ifndef AMPR_EMU_DEBUG_LOG_LOSSLESS
// 1 -> never drop queued log events. Producers spin when the queue lock or ring
// buffer is busy. Use for diagnostics where complete ordering matters; this can
// slow the title if logging is heavier than the writer thread can drain.
#define AMPR_EMU_DEBUG_LOG_LOSSLESS 0
#endif

#ifndef AMPR_EMU_DEBUG_LOG_LOSSLESS_SPIN_LIMIT
// Maximum queue-full spin iterations before a lossless producer gives up. This
// prevents a hard hang when the writer cannot open/drain the file or TRACE
// logging outpaces storage for too long. 0 means spin forever.
#define AMPR_EMU_DEBUG_LOG_LOSSLESS_SPIN_LIMIT 1000000
#endif

#ifndef AMPR_EMU_LIBKERNEL_HOOK_DIAGNOSTICS
// 1 -> compile hidden libkernel hook startup/status log helpers. Runtime hook
// forwarding and symbol resolution stay compiled independently of this flag.
#define AMPR_EMU_LIBKERNEL_HOOK_DIAGNOSTICS 1
#endif
