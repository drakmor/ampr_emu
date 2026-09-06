/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Seekable AMPR asset-pack runtime. Packed logical files are exposed to the
 * existing APR reactor through process-local virtual FDs and virtual SDK AIO
 * submit IDs, so command-buffer ABI and scheduler semantics remain unchanged.
 */
#pragma once

#include "ampr_emu_config.h"
#include "ampr_emu_aio_broker.h"

#include <kernel.h>

#include <cstddef>
#include <cstdint>

struct FileEntryView;

#ifndef AMPR_EMU_PACK_INDEX_PATH
#define AMPR_EMU_PACK_INDEX_PATH "/app0/ampr_assets.index"
#endif

#ifndef AMPR_EMU_PACK_ROOT_PATH
#define AMPR_EMU_PACK_ROOT_PATH "/app0"
#endif

#ifndef AMPR_EMU_PACK_LOGICAL_ROOT_PATH
#define AMPR_EMU_PACK_LOGICAL_ROOT_PATH "/app0"
#endif

#ifndef AMPR_EMU_PACK_INTERCEPT_ALL_READ_ONLY
// Backward-compatible alias. Plain read-only packed opens are controlled by
// the process namespace switch; synchronous read/pread remains independent.
#define AMPR_EMU_PACK_INTERCEPT_ALL_READ_ONLY \
    AMPR_EMU_PACK_PROCESS_OPEN_ENABLE
#endif

#ifndef AMPR_EMU_PACK_VIRTUAL_DIRECTORY_SLOTS
#define AMPR_EMU_PACK_VIRTUAL_DIRECTORY_SLOTS 256u
#endif

#ifndef AMPR_EMU_PACK_WORKERS
#define AMPR_EMU_PACK_WORKERS 4u
#endif

#ifndef AMPR_EMU_PACK_WORKER_CAPACITY
#define AMPR_EMU_PACK_WORKER_CAPACITY 16u
#endif
#ifndef AMPR_EMU_PACK_DECODED_CACHE_MAX_BYTES
#define AMPR_EMU_PACK_DECODED_CACHE_MAX_BYTES (512ull * 1024ull * 1024ull)
#endif
#ifndef AMPR_EMU_PACK_PHYSICAL_CACHE_MAX_BYTES
#define AMPR_EMU_PACK_PHYSICAL_CACHE_MAX_BYTES (128ull * 1024ull * 1024ull)
#endif
static_assert(AMPR_EMU_PACK_WORKERS >= 1u &&
              AMPR_EMU_PACK_WORKER_CAPACITY >= AMPR_EMU_PACK_WORKERS &&
              AMPR_EMU_PACK_WORKER_CAPACITY <= 16u, "worker storage capacity");

#ifndef AMPR_EMU_PACK_PIPELINE_SLOTS
// Retained physical-window/AIO contexts. Keep more contexts than decode workers
// so backing reads remain in flight while workers decode completed windows.
// Cover the complete external broker pool; dynamic reactor admission still
// shares native capacity with loose reads.
#define AMPR_EMU_PACK_PIPELINE_SLOTS kAprExternalAioCapacity
#endif

#ifndef AMPR_EMU_PACK_WORKER_PRIORITY
#define AMPR_EMU_PACK_WORKER_PRIORITY 384
#endif

#ifndef AMPR_EMU_PACK_WORKER_AFFINITY
#define AMPR_EMU_PACK_WORKER_AFFINITY 0x3fu
#endif

#ifndef AMPR_EMU_PACK_LATENCY_RESERVE_WORKERS
// Reserve this many workers for latency-sensitive random/hot requests. A
// reserved worker may execute latency and balanced work, but never bulk work.
// Trace-derived profile headers set this to zero for pure streaming titles and
// to one for titles with large populations of tiny random reads.
#define AMPR_EMU_PACK_LATENCY_RESERVE_WORKERS 0u
#endif

#ifndef AMPR_EMU_PACK_LATENCY_READ_MAX_BYTES
// Any request at or below this size is latency-sensitive even when its file is
// not explicitly tagged hot/random. This prevents small metadata reads from
// waiting behind several 512 KiB streaming slices at the same SDK priority.
#define AMPR_EMU_PACK_LATENCY_READ_MAX_BYTES (64ull * 1024ull)
#endif

#ifndef AMPR_EMU_PACK_BULK_READ_MIN_BYTES
// Large requests use the bulk scheduler class. They still preserve SDK AIO
// priority, but latency-reserved workers do not take them.
#define AMPR_EMU_PACK_BULK_READ_MIN_BYTES (256ull * 1024ull)
#endif

#ifndef AMPR_EMU_PACK_IO_STAGING_BYTES
// Lazily allocated per-pipeline exact read window. It must hold the largest
// 1 MiB block plus alignment slack. Contiguous physical-cache windows do not
// allocate this scratch.
#define AMPR_EMU_PACK_IO_STAGING_BYTES (2ull * 1024ull * 1024ull)
#endif

#ifndef AMPR_EMU_PACK_PREAD_MAX_BYTES
// Upper bound for one underlying sceKernelPread call. Keep this at least as
// large as the staging arena to preserve one system call per exact range.
#define AMPR_EMU_PACK_PREAD_MAX_BYTES AMPR_EMU_PACK_IO_STAGING_BYTES
#endif

#ifndef AMPR_EMU_PACK_VIRTUAL_FD_SLOTS
#define AMPR_EMU_PACK_VIRTUAL_FD_SLOTS 256u
#endif

#ifndef AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS
#define AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS 256u
#endif

#ifndef AMPR_EMU_PACK_MAX_PACKS
#define AMPR_EMU_PACK_MAX_PACKS 1024u
#endif

#ifndef AMPR_EMU_PACK_OPEN_PACK_FD_CAP
#define AMPR_EMU_PACK_OPEN_PACK_FD_CAP 18u
#endif

#ifndef AMPR_EMU_PACK_DECODED_CACHE_BYTES
#define AMPR_EMU_PACK_DECODED_CACHE_BYTES (128ull * 1024ull * 1024ull)
#endif

#ifndef AMPR_EMU_PACK_DECODED_CACHE_MIN_BYTES
#define AMPR_EMU_PACK_DECODED_CACHE_MIN_BYTES (16ull * 1024ull * 1024ull)
#endif

#ifndef AMPR_EMU_PACK_MEMORY_RESERVE_BYTES
// Post-cache safety margin. Cache admission additionally reserves every retained
// pipeline I/O window and one maximum decoded block per requested worker before
// either cache is allocated.
#define AMPR_EMU_PACK_MEMORY_RESERVE_BYTES (32ull * 1024ull * 1024ull)
#endif

#ifndef AMPR_EMU_PACK_PHYSICAL_CACHE_BYTES
// Shared cache of aligned compressed/raw filesystem I/O pages. Trace-derived
// profiles show substantial reuse of 64 KiB pages even when decoded chunks do
// not survive in the larger decoded cache.
#define AMPR_EMU_PACK_PHYSICAL_CACHE_BYTES (32ull * 1024ull * 1024ull)
#endif
static_assert(AMPR_EMU_PACK_DECODED_CACHE_BYTES <= AMPR_EMU_PACK_DECODED_CACHE_MAX_BYTES,
              "decoded cache default exceeds bitmap capacity");
static_assert(AMPR_EMU_PACK_PHYSICAL_CACHE_BYTES <= AMPR_EMU_PACK_PHYSICAL_CACHE_MAX_BYTES,
              "physical cache default exceeds bitmap capacity");

#ifndef AMPR_EMU_PACK_PHYSICAL_CACHE_MIN_BYTES
#define AMPR_EMU_PACK_PHYSICAL_CACHE_MIN_BYTES (8ull * 1024ull * 1024ull)
#endif

#ifndef AMPR_EMU_PACK_PHYSICAL_CACHE_ENTRY_CAP
#define AMPR_EMU_PACK_PHYSICAL_CACHE_ENTRY_CAP 2048u
#endif

#ifndef AMPR_EMU_PACK_PHYSICAL_CACHE_HASH_BUCKETS
#define AMPR_EMU_PACK_PHYSICAL_CACHE_HASH_BUCKETS 4096u
#endif

#ifndef AMPR_EMU_PACK_INLINE_CACHE_MAX_TASKS
// One APR software slice is normally at most 512 KiB. 64 tasks therefore
// covers the worst supported 16 KiB geometry with headroom.
#define AMPR_EMU_PACK_INLINE_CACHE_MAX_TASKS 64u
#endif

#ifndef AMPR_EMU_PACK_CACHE_ENTRY_CAP
#define AMPR_EMU_PACK_CACHE_ENTRY_CAP 8192u
#endif

#ifndef AMPR_EMU_PACK_CACHE_PAGE_SHIFT
#define AMPR_EMU_PACK_CACHE_PAGE_SHIFT 14u
#endif

#ifndef AMPR_EMU_PACK_CACHE_HASH_BUCKETS
#define AMPR_EMU_PACK_CACHE_HASH_BUCKETS 16384u
#endif

#ifndef AMPR_EMU_PACK_TOUCH_TABLE_SIZE
#define AMPR_EMU_PACK_TOUCH_TABLE_SIZE 16384u
#endif

#ifndef AMPR_EMU_PACK_INDEX_MAX_BYTES
#define AMPR_EMU_PACK_INDEX_MAX_BYTES (512ull * 1024ull * 1024ull)
#endif

#ifndef AMPR_EMU_PACK_MAX_FILES
#define AMPR_EMU_PACK_MAX_FILES 2000000ull
#endif

#ifndef AMPR_EMU_PACK_MAX_CHUNKS
#define AMPR_EMU_PACK_MAX_CHUNKS 16000000ull
#endif

struct AmprPackRuntimeStats {
    // Upper bounds: 1, 2, ... 2^30 microseconds; bucket 31 is overflow.
    uint64_t logicalLatency[32]{};
    uint64_t latencyClassLatency[32]{};
    uint64_t physicalLatency[32]{};
    uint64_t queueLatency[32]{};
    uint64_t workerLatency[32]{};
    uint64_t deliveredBytes{};
    uint64_t logicalFailures{};
    uint64_t decodedCacheTargetBytes{};
    uint64_t physicalCacheTargetBytes{};
    uint64_t decodedCacheAllocatedBytes{};
    uint64_t physicalCacheAllocatedBytes{};
    uint32_t requestedWorkers{};
    uint32_t startedWorkers{};
    uint32_t latencyReserveWorkers{};
    bool runtimeProfileLoaded{};
    uint64_t virtualOpens{};
    uint64_t aioSubmitted{};
    uint64_t aioCompleted{};
    uint64_t logicalBytes{};
    // Actual bytes issued to the physical pack files. storedBytesConsumed is
    // the useful compressed/raw payload.
    uint64_t physicalBytes{};
    uint64_t physicalReadOps{};
    // One sample covers one backing-page request accepted by SDK AIO,
    // including a terminal failed or aborted request.
    uint64_t physicalReadSamples{};
    uint64_t physicalReadUsecTotal{};
    uint64_t physicalReadUsecMax{};
    uint64_t physicalReadSlow1ms{};
    uint64_t physicalReadSlow5ms{};
    uint64_t physicalReadSlow20ms{};
    uint64_t physicalReadLe64K{};
    uint64_t physicalReadLe512K{};
    uint64_t physicalReadGt512K{};
    uint64_t physicalReadsInFlight{};
    uint64_t physicalReadsInFlightPeak{};
    uint64_t backingAioSubmitBatches{};
    uint64_t backingAioSubmitRequests{};
    uint64_t backingAioSubmitEagain{};
    uint64_t backingAioSubmitFailures{};
    uint64_t backingAioPollFailures{};
    uint64_t backingAioDeleteFailures{};
    uint64_t pipelineContextsActive{};
    uint64_t pipelineContextsActivePeak{};
    uint64_t pipelineIoYields{};
    uint64_t pipelineCacheYields{};
    uint64_t pipelineFdYields{};
    uint64_t physicalWindowHits{};
    uint64_t physicalPageHits{};
    uint64_t physicalPageMisses{};
    uint64_t physicalPageLoadingJoins{};
    uint64_t physicalPageAdmissions{};
    uint64_t physicalPageEvictions{};
    uint64_t physicalPageBypasses{};
    uint64_t physicalCacheDirectReadWindows{};
    uint64_t physicalCacheDirectReadyWindows{};
    uint64_t physicalCacheScratchWindows{};
    uint64_t physicalCacheCopyBytesAvoided{};
    uint64_t inlineCacheCompletions{};
    uint64_t latencyJobsSubmitted{};
    uint64_t balancedJobsSubmitted{};
    uint64_t bulkJobsSubmitted{};
    uint64_t latencyWorkerDispatches{};
    uint64_t queueDepthPeakLatency{};
    uint64_t queueDepthPeakBalanced{};
    uint64_t queueDepthPeakBulk{};
    uint64_t workerJobs{};
    uint64_t workerJobUsecTotal{};
    uint64_t workerJobUsecMax{};
    uint64_t workersBusy{};
    uint64_t workersBusyPeak{};
    uint64_t workerQueueWaitUsecTotal{};
    uint64_t workerQueueWaitUsecMax{};
    uint64_t workerQueueWaitSlow1ms{};
    uint64_t workerQueueWaitSlow5ms{};
    uint64_t workerQueueWaitSlow20ms{};
    uint64_t storedBytesConsumed{};
    uint64_t lz4DecodedBytes{};
    uint64_t rawBytes{};
    uint64_t cacheHits{};
    uint64_t cacheMisses{};
    uint64_t cacheLoadingJoins{};
    uint64_t cacheAdmissions{};
    uint64_t cacheEvictions{};
    uint64_t ioFailures{};

    uint64_t processVirtualOpens{};
    uint64_t directoryOpens{};
    uint64_t directoryHybridOpens{};
    uint64_t directoryVirtualOpens{};
    uint64_t directoryGetdentsCalls{};
    uint64_t directoryPhysicalEntries{};
    uint64_t directoryVirtualEntries{};
    uint64_t directoryDuplicateEntries{};
    uint64_t directoryHiddenEntries{};
    uint64_t syntheticFileStats{};
    uint64_t syntheticDirectoryStats{};
    uint64_t syntheticReachability{};
    uint64_t synchronousPreads{};
    uint64_t synchronousReads{};
    uint64_t synchronousLseeks{};
};

// Fast integration path for callers that already own the immutable AMPRIDX3
// file ID/view, avoiding a second path lookup. Returns a synthetic FD and sets
// *handled when the file is packed or the manifest conflicts with the resident
// index. If handled remains false, the manifest authoritatively marks the file
// loose and the caller must invoke the real libkernel open implementation.
int ampr_pack_try_open_indexed(uint32_t fileId,
                               const FileEntryView& entry,
                               int flags,
                               SceKernelMode mode,
                               bool* handled);
int ampr_pack_try_process_open_indexed(uint32_t fileId,
                                       const FileEntryView& entry,
                                       int flags,
                                       SceKernelMode mode,
                                       bool* handled);

// Path-based compatibility boundary used by the host runtime harness. Process
// hooks use the indexed overload above after their authoritative lookup.
int ampr_pack_try_open(const char* path,
                       int flags,
                       SceKernelMode mode,
                       bool* handled);

// Lock-free readiness probe for process hooks. A cold hook must not load or
// wait for the manifest under a nonsleeping lock.
bool ampr_pack_manifest_is_resident_ready();
// True only after the safe loader has conclusively observed that the optional
// manifest path does not exist. Indexed files are ordinary loose files then.
bool ampr_pack_manifest_is_absent();

// Safe index-construction boundary: finish loading the manifest before
// publishing the authoritative AMPRIDX3 snapshot to process-file hooks.
bool ampr_pack_ensure_manifest_ready_safe();

// Directory namespace overlay. The open helper performs the real directory
// open itself and returns either a real fd or a synthetic hybrid/virtual fd.
int ampr_pack_open_directory(const char* path,
                             int flags,
                             SceKernelMode mode,
                             bool* handled);
// Resident-index miss path: expose a packed virtual directory without probing
// the physical filesystem.
int ampr_pack_open_virtual_directory(const char* path,
                                     int flags,
                                     SceKernelMode mode,
                                     bool* handled);
int ampr_pack_try_stat_path(const char* path,
                            SceKernelStat* stat,
                            bool* handled);
int ampr_pack_try_reachability(const char* path, bool* handled);

// Shared dispatch helpers used by process-wide libkernel hooks.
int ampr_pack_try_close_fd(int fd, bool* handled);
int ampr_pack_try_fstat_fd(int fd, SceKernelStat* stat, bool* handled);
int ampr_pack_try_getdents_fd(int fd, char* buffer, int size, bool* handled);
int ampr_pack_try_getdirentries_fd(int fd, char* buffer, int size, long* basep,
                                   bool* handled);
ssize_t ampr_pack_try_pread_fd(int fd, void* buffer, size_t size,
                               off_t offset, bool* handled);
ssize_t ampr_pack_try_preadv_fd(int fd, const SceKernelIovec* iov, int iovcnt,
                               off_t offset, bool* handled);
ssize_t ampr_pack_try_read_fd(int fd, void* buffer, size_t size,
                              bool* handled);
ssize_t ampr_pack_try_readv_fd(int fd, const SceKernelIovec* iov, int iovcnt,
                              bool* handled);
off_t ampr_pack_try_lseek_fd(int fd, off_t offset, int whence,
                             bool* handled);

bool ampr_pack_is_virtual_fd(int fd);
bool ampr_pack_is_virtual_directory_fd(int fd);
void ampr_pack_notify_fd_budget_progress();
AmprPackRuntimeStats ampr_pack_runtime_stats(bool reset);
void ampr_pack_log_summary(const char* reason);
int ampr_pack_shutdown();
