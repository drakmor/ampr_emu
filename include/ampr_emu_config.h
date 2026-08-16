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
// Combined APR FD budget for cached descriptors plus direct full-file AIO opens.
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
// On EMFILE/open pressure, close only this percentage of idle cached FDs before
// retrying the open. Active pinned FDs are never closed by this path.
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

#ifndef AMPR_EMU_APR_AIO_PER_FILE_INFLIGHT
// Soft number of active SDK AIO read IDs for one APR fileId. Files below this
// level are filled first; once no ready file remains below it, pending files may
// borrow the unused global window. 0 disables the per-file preference.
#define AMPR_EMU_APR_AIO_PER_FILE_INFLIGHT 16
#endif

#ifndef AMPR_EMU_APR_AIO_SMALL_READ_INFLIGHT
// Temporary active-read window used only when the already-active workload is
// dominated by small reads. Extra slots above AMPR_EMU_APR_AIO_INFLIGHT are
// filled with small requests only, so bulk traffic cannot consume the boost.
// Set to AMPR_EMU_APR_AIO_INFLIGHT (or 0) to disable the boost.
#define AMPR_EMU_APR_AIO_SMALL_READ_INFLIGHT 48
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

#ifndef AMPR_EMU_APR_AIO_SDK_SCHED_HEADROOM
// Extra SDK AIO scheduler/delayed slots above the reactor's maximum dynamic
// active-read window. The reactor clamps the final values to SDK caps.
#define AMPR_EMU_APR_AIO_SDK_SCHED_HEADROOM 32
#endif

#ifndef AMPR_EMU_APR_AIO_POLL_IDLE_SLEEP_NS
// Default reactor sleep after a poll-only pass where no active AIO completed.
#define AMPR_EMU_APR_AIO_POLL_IDLE_SLEEP_NS 50000
#endif

#ifndef AMPR_EMU_APR_AIO_POLL_BACKGROUND_SLEEP_NS
// Longer poll-only sleep when only already-submitted background AIOs are active
// and there are no queued APR reads to admit. This reduces no-log runtime wakeup
// cost during large pack reads.
#define AMPR_EMU_APR_AIO_POLL_BACKGROUND_SLEEP_NS 250000
#endif

#ifndef AMPR_EMU_APR_AIO_POLL_BATCH_LIMIT
// Maximum SDK AIO poll syscalls issued by one reactor worker iteration.
// The deadline heap retains every due request not reached in this iteration.
#define AMPR_EMU_APR_AIO_POLL_BATCH_LIMIT 24
#endif

#ifndef AMPR_EMU_APR_AIO_POLL_REGULAR_RESERVE
// Poll calls retained for deadline-ready heap selection after servicing the
// completion-gating hot queue. Clamped so a non-empty batch keeps one hot slot.
#define AMPR_EMU_APR_AIO_POLL_REGULAR_RESERVE 6
#endif

#ifndef AMPR_EMU_APR_AIO_GATING_SPIN_POLLS
// Extra immediate polls for the sole read that gates visible job completion.
// This avoids a nanosleep/context-switch round trip for short cached reads
// without busy-polling background or multi-request workloads.
#define AMPR_EMU_APR_AIO_GATING_SPIN_POLLS 1
#endif

#ifndef AMPR_EMU_APR_AIO_POLL_BACKOFF_MIN_NS
// First no-completion poll backoff for an active AIO request.
#define AMPR_EMU_APR_AIO_POLL_BACKOFF_MIN_NS 10000
#endif

#ifndef AMPR_EMU_APR_AIO_POLL_FAST_WINDOW_NS
// Request age window that keeps polling at the minimum backoff. After this
// likely-completion window, the per-request backoff grows adaptively.
#define AMPR_EMU_APR_AIO_POLL_FAST_WINDOW_NS 250000
#endif

#ifndef AMPR_EMU_APR_AIO_POLL_BACKOFF_MAX_NS
// Maximum per-request poll backoff when no title thread is synchronously
// waiting for an APR submit id.
#define AMPR_EMU_APR_AIO_POLL_BACKOFF_MAX_NS 1000000
#endif

#ifndef AMPR_EMU_APR_AIO_POLL_DEPENDENT_BACKOFF_MAX_NS
// Maximum per-request poll backoff for reads that can hold APR result/fence
// publication. Pure background reads may still use the larger max above.
#define AMPR_EMU_APR_AIO_POLL_DEPENDENT_BACKOFF_MAX_NS 100000
#endif

#ifndef AMPR_EMU_APR_AIO_POLL_STAGED_EOP_BACKOFF_MAX_NS
// Tighter local cap while a read is the final gate for an already-submitted
// native EOP packet. This does not increase polling for unrelated AIO work.
#define AMPR_EMU_APR_AIO_POLL_STAGED_EOP_BACKOFF_MAX_NS 50000
#endif

#ifndef AMPR_EMU_APR_AIO_CROSS_EOP_READAHEAD
// 1 -> allow the reactor to issue same-priority APR reads located after one or
// more *OnCompletion records, including across adjacent submitted buffers. Each
// completion retains the read-sequence fence that preceded it and still
// dispatches in source order. A valid WaitOnAddress whose condition is already
// true is transparent; any other non-read/non-EOP record stops read-ahead.
// Disabled by default to preserve the strict parser path.
#define AMPR_EMU_APR_AIO_CROSS_EOP_READAHEAD 1
#endif

#ifndef AMPR_EMU_APR_AIO_CROSS_EOP_MAX_FENCES
// Maximum number of source-ordered completion fences retained by one job.
// Read-ahead itself is deliberately not depth-tunable: the reactor may execute
// at most one speculative command per priority lane in each reactor tick.
#define AMPR_EMU_APR_AIO_CROSS_EOP_MAX_FENCES 64
#endif

#ifndef AMPR_EMU_APR_AIO_POLL_SMALL_BACKGROUND_BYTES
// Background reads up to this logical size use the smaller background backoff
// cap below. Tuned for 256 KiB..1 MiB streaming blocks.
#define AMPR_EMU_APR_AIO_POLL_SMALL_BACKGROUND_BYTES 0x100000ull
#endif

#ifndef AMPR_EMU_APR_AIO_POLL_SMALL_BACKGROUND_BACKOFF_MAX_NS
// Maximum poll backoff for small/medium background reads. Larger background
// reads may still use AMPR_EMU_APR_AIO_POLL_BACKOFF_MAX_NS.
#define AMPR_EMU_APR_AIO_POLL_SMALL_BACKGROUND_BACKOFF_MAX_NS 500000
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

#ifndef AMPR_EMU_APR_AIO_DIRECT_SMALL_FULL_FILE_BYTES
// Direct APR reads at or below this size are classified as small in logs.
#define AMPR_EMU_APR_AIO_DIRECT_SMALL_FULL_FILE_BYTES 0x200000ull
#endif

#ifndef AMPR_EMU_APR_FD_CACHE_MIN_FILE_BYTES
// Files at or below this size bypass the APR fd-cache and use short-lived direct
// fds. The cache is reserved for larger files that are more likely to be read
// repeatedly.
#define AMPR_EMU_APR_FD_CACHE_MIN_FILE_BYTES 0x200000ull
#endif

#ifndef AMPR_EMU_APR_AIO_BULK_FULL_FILE_BYTES
// Direct APR reads at or above this size are classified as bulk in logs.
#define AMPR_EMU_APR_AIO_BULK_FULL_FILE_BYTES 0x400000ull
#endif

#ifndef AMPR_EMU_APR_FD_PRESSURE_COOLDOWN_MS
// How long FD pressure keeps the reduced AIO/FD limits active.
#define AMPR_EMU_APR_FD_PRESSURE_COOLDOWN_MS 2000
#endif

#ifndef AMPR_EMU_APR_FD_PRESSURE_SCORE_MAX
// Repeated FD pressure events within the cooldown shrink limits further.
#define AMPR_EMU_APR_FD_PRESSURE_SCORE_MAX 4
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

#ifndef AMPR_EMU_APR_REACTOR_STALL_WARN_ITERATIONS
// Warn when the APR AIO reactor loops this many times without making parser,
// submit, or AIO completion progress while work is still outstanding.
#define AMPR_EMU_APR_REACTOR_STALL_WARN_ITERATIONS 1024
#endif

#ifndef AMPR_EMU_APR_REACTOR_HEARTBEAT_MS
// Low-rate reactor state sample while APR work is present, even if progress is
// still being made. This catches visual hangs that do not trip stall detection.
#define AMPR_EMU_APR_REACTOR_HEARTBEAT_MS 1000
#endif

#ifndef AMPR_EMU_APR_REACTOR_BACKLOG_WARN_THRESHOLD
// Emit sparse normal-log reactor heartbeats once queued APR reads grow this
// high. Detailed per-job/per-read progress remains behind VERBOSE/TRACE.
#define AMPR_EMU_APR_REACTOR_BACKLOG_WARN_THRESHOLD 64
#endif

#ifndef AMPR_EMU_APR_REACTOR_BACKLOG_WARN_INTERVAL_NS
// Minimum interval between unchanged backlog heartbeats.
#define AMPR_EMU_APR_REACTOR_BACKLOG_WARN_INTERVAL_NS 1000000000ull
#endif

#ifndef AMPR_EMU_APR_REACTOR_BACKLOG_FILE_SAMPLES
// Number of top file ids sampled when the reactor emits a backlog heartbeat.
// 0 disables the per-file snapshot and keeps only the aggregate heartbeat.*
#define AMPR_EMU_APR_REACTOR_BACKLOG_FILE_SAMPLES 4
#endif

#ifndef AMPR_EMU_SUBMIT_COMMAND_BUFFER_DUMP
// Optional submit-time decoded command-buffer dump bitmask:
//   bit 0 (1) -> dump the original game-visible command buffer
//   bit 1 (2) -> dump APR source and native micro-submit diagnostics
#define AMPR_EMU_SUBMIT_COMMAND_BUFFER_DUMP 0
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
#define AMPR_EMU_VERSION "0.3.2 (public beta) (c) Drakmor"
#endif

#ifndef AMPR_EMU_DEBUG_LOG
// 1 -> write debug logs for AMPR operations/events to AMPR_EMU_DEBUG_LOG_PATH.
// The first log write in each process truncates the file; later writes in the
// same run continue on the open fd.
// 0 -> compile out log callsites and the logger backend.
#define AMPR_EMU_DEBUG_LOG 0
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
#define AMPR_EMU_DEBUG_LOG_PATH "/app0/apr_emu.log"
#endif

#ifndef AMPR_EMU_DEBUG_LOG_KERNEL_OUT
// 1 -> duplicate each formatted debug log message to the kernel debug output
// channel immediately, before enqueueing it for the file writer.
#define AMPR_EMU_DEBUG_LOG_KERNEL_OUT 1
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
#define AMPR_EMU_LIBKERNEL_HOOK_DIAGNOSTICS 0
#endif
