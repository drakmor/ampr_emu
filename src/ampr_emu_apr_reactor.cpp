/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Software APR scheduler and SDK AIO reactor. It advances the retained source
 * stream in priority order, splits reads at dispatch, and issues only bounded
 * native APR/AMM micro-submits for hardware-owned operations.
 */

#include "ampr_emu_apr_reactor.h"
#include "ampr_emu_apr_reactor_common.h"
#if AMPR_EMU_DEBUG_LOG && (AMPR_EMU_SUBMIT_COMMAND_BUFFER_DUMP || AMPR_EMU_APR_REACTOR_STALL_WARN_ITERATIONS != 0)
#include "ampr_emu_command_buffer_dump.h"
#endif
#include "ampr_emu_command_buffer_common.h"
#include "ampr_emu_command_buffer_apr.h"
#include "ampr_emu_command_packing.h"
#include "ampr_emu_amm.h"
#include "ampr_emu_index.h"
#include "ampr_emu_kernel_memory.h"
#include "ampr_emu_log.h"
#include "ampr_emu_runtime_memory.h"
#include "ampr_emu_sync.h"

#include <ampr/ampr_error.h>

#include <atomic>
#include <algorithm>
#include <cstdlib>
#include <limits>

namespace {
static constexpr uint32_t kPendingReadNodeInvalid = UINT32_MAX;
static constexpr uint64_t kAprNativeMicroCompletionDone = 0x4150524d444f4e45ull;
static constexpr uint32_t kAprNativeMicroCommandCapacity = 64u;
static constexpr uint32_t kAprNativeMicroCompletionBytes = 16u;
static constexpr uint32_t kAprNativeMicroSlotAlignment = 64u;

static constexpr bool apr_read_completion_window_exhausted(
    uint64_t latestSubmitted,
    uint64_t completed,
    uint64_t capacity) {
    return latestSubmitted >= completed &&
           latestSubmitted - completed >= capacity;
}

struct alignas(kAprNativeMicroSlotAlignment) AprNativeMicroSlot {
    uint8_t commands[kAprNativeMicroCommandCapacity]{};
    uint8_t completionTemplate[kAprNativeMicroCompletionBytes]{};
    alignas(8) volatile uint64_t completion{};
};
static constexpr size_t kAprNativeMicroRawBytes =
    sizeof(AprNativeMicroSlot) * kAprCommandBufferLiveMax;
static constexpr size_t kAprNativeMicroPoolBytes =
    ((kAprNativeMicroRawBytes + SCE_KERNEL_PAGE_SIZE - 1u) /
     SCE_KERNEL_PAGE_SIZE) * SCE_KERNEL_PAGE_SIZE;
alignas(SCE_KERNEL_PAGE_SIZE) static uint8_t
    g_apr_native_micro_pool[kAprNativeMicroPoolBytes];

// A submitted APR batch never changes its byte length or command count. Each
// group has one flush-enabled gate, eight fixed payload slots, and one
// checkpoint. A payload slot contains one native command (4..20 bytes) plus a
// padding NOP and is always 24 bytes. Publishing one group therefore releases
// up to eight useful packets with only one gate and one completion command.
static constexpr uint32_t kAprNativeBatchBufferCountPerLane = 2u;
static constexpr uint32_t kAprNativeBatchPacketCount = 1024u;
static constexpr uint32_t kAprNativeBatchPacketsPerGroup = 8u;
static constexpr uint32_t kAprNativeBatchPaddingHeaderCount = 5u;
static constexpr uint32_t kAprNativeBatchGroupCount =
    kAprNativeBatchPacketCount / kAprNativeBatchPacketsPerGroup;
static constexpr uint32_t kAprNativeBatchGateBytes = 16u;
static constexpr uint32_t kAprNativeBatchPayloadSlotBytes = 24u;
static constexpr uint32_t kAprNativeBatchPayloadRegionBytes =
    kAprNativeBatchPayloadSlotBytes * kAprNativeBatchPacketsPerGroup;
static constexpr uint32_t kAprNativeBatchCheckpointBytes = 16u;
static constexpr uint32_t kAprNativeBatchGroupBytes =
    kAprNativeBatchGateBytes + kAprNativeBatchPayloadRegionBytes +
    kAprNativeBatchCheckpointBytes;
static constexpr uint32_t kAprNativeBatchCommandCountPerGroup =
    2u + 2u * kAprNativeBatchPacketsPerGroup;
static constexpr uint32_t kAprNativeBatchBufferBytes =
    kAprNativeBatchGroupBytes * kAprNativeBatchGroupCount;
static constexpr uint32_t kAprNativeBatchCommandCount =
    kAprNativeBatchCommandCountPerGroup * kAprNativeBatchGroupCount;
static constexpr uint64_t kAprNativeBatchTokenBase = 0x4150524200000000ull;
static constexpr int kAprNativeBatchResultPending = INT32_MIN;
struct alignas(kAprNativeMicroSlotAlignment) AprNativeBatchSlot {
    uint8_t commands[kAprNativeBatchBufferBytes]{};
    uint8_t defaultPayload[kAprNativeBatchPayloadRegionBytes]{};
    alignas(8) volatile uint64_t release{};
    alignas(8) volatile uint64_t progress{};
    SceAprResultBuffer result{};
};
static constexpr uint32_t kAprNativeBatchSlotCount =
    kAprPriorityArrayCount * kAprNativeBatchBufferCountPerLane;
static constexpr size_t kAprNativeBatchRawBytes =
    sizeof(AprNativeBatchSlot) * kAprNativeBatchSlotCount;
static constexpr size_t kAprNativeBatchPoolBytes =
    ((kAprNativeBatchRawBytes + SCE_KERNEL_PAGE_SIZE - 1u) /
     SCE_KERNEL_PAGE_SIZE) * SCE_KERNEL_PAGE_SIZE;
alignas(SCE_KERNEL_PAGE_SIZE) static uint8_t
    g_apr_native_batch_pool[kAprNativeBatchPoolBytes];
static_assert(kAprNativeMicroCommandCapacity >= 40u,
              "native APR micro buffer must hold one command plus completion");
static_assert(kAprNativeMicroRawBytes <= kAprNativeMicroPoolBytes,
              "native APR micro pool rounding underflow");
static_assert(kAprNativeBatchPacketCount % kAprNativeBatchPacketsPerGroup == 0,
              "native APR batch packet count must contain complete groups");
static_assert(kAprNativeBatchPayloadSlotBytes ==
                  (kAprNativeBatchPaddingHeaderCount + 1u) * sizeof(uint32_t),
              "native APR padding templates must cover every packet size");
static_assert(kAprNativeBatchGroupBytes == 224u,
              "native APR batch group layout changed");
static_assert(kAprNativeBatchBufferCountPerLane == 2u,
              "native APR rollover requires exactly two backing buffers");
static_assert(kAprNativeBatchRawBytes <= kAprNativeBatchPoolBytes,
              "native APR batch pool rounding underflow");

static AprNativeMicroSlot* apr_native_micro_slot(size_t slot) {
    if (slot >= kAprCommandBufferLiveMax) {
        return nullptr;
    }
    return reinterpret_cast<AprNativeMicroSlot*>(g_apr_native_micro_pool) + slot;
}

static AprNativeBatchSlot* apr_native_batch_slot(size_t lane, size_t bufferIndex) {
    if (lane >= kAprPriorityArrayCount ||
        bufferIndex >= kAprNativeBatchBufferCountPerLane) {
        return nullptr;
    }
    const size_t slot = lane * kAprNativeBatchBufferCountPerLane + bufferIndex;
    return reinterpret_cast<AprNativeBatchSlot*>(g_apr_native_batch_pool) + slot;
}

static constexpr uint64_t apr_native_batch_token(uint32_t groupIndex) {
    return kAprNativeBatchTokenBase + static_cast<uint64_t>(groupIndex) + 1ull;
}

[[maybe_unused]] static const char* apr_submit_mode_name(AprSubmitMode mode) {
    switch (mode) {
        case AprSubmitMode::kSubmit:
            return "submit";
        case AprSubmitMode::kSubmitAndGetResult:
            return "submitAndGetResult";
        case AprSubmitMode::kSubmitAndGetId:
            return "submitAndGetId";
        default:
            return "unknown";
    }
}

// Job state / scheduling
// -----------------------------
struct JobResult {
    int rc{0};
    uint32_t errorOffset{0};
};

struct AprAioReadDesc {
    // Pending descriptors may hold a logical continuation. Active descriptors
    // are capped to one A53-sized dispatch quantum and own one SDK AIO id.
    uint32_t fileId{};
    int fd{-1};
    void* buffer{};
    uint64_t length{};
    uint64_t offset{};
    size_t fileSize{};
    const char* filePath{};
    uint32_t filePathLength{};
    uint32_t errorOff{};
    bool bypassFdCache{false};
    bool closeAfter{false};
    bool cachePinned{false};
    bool borrowedFd{false};
    bool fileMetadataValid{false};
    bool fullFileRead{false};
};

#if AMPR_EMU_DEBUG_LOG
static std::atomic<uint64_t> g_apr_direct_emfile_events{0};
#endif

static constexpr int kAprAioOpenFlags = O_RDONLY | O_NONBLOCK;
static constexpr uint64_t kAprAioRequestOffsetMax =
    static_cast<uint64_t>((std::numeric_limits<off_t>::max)());

// A53 keeps APR 0..6 in seven fixed request rings. SDK AIO exposes only three
// public levels, so preserve the fixed ordering without load- or size-based
// remapping. In particular, HIGH belongs exclusively to APR priority 0.
static int apr_aio_priority_from_apr(uint8_t prio) {
    if (prio == 0) return SCE_KERNEL_AIO_PRIORITY_HIGH;
    if (prio <= 3) return SCE_KERNEL_AIO_PRIORITY_MID;
    return SCE_KERNEL_AIO_PRIORITY_LOW;
}

static int apr_aio_api_rc_to_sce(int rc) {
    if (rc == 0) return 0;
    const uint32_t u = static_cast<uint32_t>(rc);
    if ((u & 0xFFFF0000u) == 0x80020000u) {
        return rc;
    }
    return ampr_sce_errno_from_posix(rc < 0 ? -rc : rc);
}

static bool apr_aio_submit_sce_rc_is_deferred(int rc) {
    return rc == SCE_KERNEL_ERROR_EAGAIN;
}

static bool apr_aio_completion_sce_rc_is_retryable(int rc) {
    return rc == SCE_KERNEL_ERROR_EAGAIN ||
           rc == SCE_KERNEL_ERROR_EBUSY ||
           rc == SCE_KERNEL_ERROR_EINTR;
}

static int apr_aio_result_to_sce(int64_t value) {
    if (value >= 0) return 0;
    const int rc = static_cast<int>(value);
    const uint32_t u = static_cast<uint32_t>(rc);
    if ((u & 0xFFFF0000u) == 0x80020000u) {
        return rc;
    }
    const int err = (value > -256) ? static_cast<int>(-value) : EIO;
    return ampr_sce_errno_from_posix(err);
}

static bool apr_file_id_is_invalid(uint32_t fileId) {
    return fileId == 0 || fileId == SCE_AMPR_APR_FILEID_INVALID;
}

static int apr_file_id_lookup_error(uint32_t fileId) {
    return apr_file_id_is_invalid(fileId)
               ? SCE_AMPR_ERROR_APR_INVALIDFILEID
               : SCE_AMPR_ERROR_APR_UNAVAILABLEFILEID;
}

static bool apr_result_is_ampr_error(int rc) {
    return (static_cast<uint32_t>(rc) & 0xffffff00u) == 0x81912000u;
}

static int apr_backend_read_error_to_apr(int rc) {
    if (rc == 0 || apr_result_is_ampr_error(rc)) {
        return rc;
    }
    if (rc == SCE_KERNEL_ERROR_EFAULT) {
        return SCE_AMPR_ERROR_APR_MEMORYFAULTWRITEBUFFERADDRESS;
    }
    return SCE_AMPR_ERROR_APR_UNAVAILABLEFILEID;
}

static bool apr_prepare_aio_read_desc(uint64_t jobId,
                                      uint32_t fileId,
                                      void* buffer,
                                      uint64_t length,
                                      uint64_t offset,
                                      uint32_t errorOff,
                                      bool bypassFdCache,
                                      AprAioReadDesc* out,
                                      int* outRc,
                                      uint32_t* outErrorOffset) {
    if (outRc) *outRc = 0;
    if (outErrorOffset) *outErrorOffset = errorOff;
    if (!out) {
        if (outRc) *outRc = SCE_KERNEL_ERROR_EINVAL;
        return false;
    }
    if (!buffer) {
        if (outRc) *outRc = SCE_AMPR_ERROR_APR_MEMORYFAULTWRITEBUFFERADDRESS;
        AMPR_CRITICAL_LOGF("apr.reactor.prepare.fail job=0x%llx reason=output-address fileId=%u buf=%p len=0x%llx off=0x%llx rc=0x%x",
                  (unsigned long long)jobId, fileId, buffer,
                  (unsigned long long)length, (unsigned long long)offset,
                  outRc ? *outRc : SCE_AMPR_ERROR_APR_MEMORYFAULTWRITEBUFFERADDRESS);
        return false;
    }
    if (length == 0) {
        if (outRc) *outRc = SCE_AMPR_ERROR_APR_INVALIDFILEOFFSET;
        AMPR_CRITICAL_LOGF("apr.reactor.prepare.fail job=0x%llx reason=bad-args fileId=%u buf=%p len=0x%llx off=0x%llx",
                  (unsigned long long)jobId, fileId, buffer,
                  (unsigned long long)length, (unsigned long long)offset);
        return false;
    }
    if (offset > kAprAioRequestOffsetMax) {
        if (outRc) *outRc = SCE_AMPR_ERROR_APR_INVALIDFILEOFFSET;
        AMPR_CRITICAL_LOGF("apr.reactor.prepare.fail job=0x%llx reason=offset-too-large fileId=%u buf=%p len=0x%llx off=0x%llx max=0x%llx",
                  (unsigned long long)jobId, fileId, buffer,
                  (unsigned long long)length,
                  (unsigned long long)offset,
                  (unsigned long long)kAprAioRequestOffsetMax);
        return false;
    }

    AprAioReadDesc rd{};
    rd.fileId = fileId;
    rd.buffer = buffer;
    rd.length = length;
    rd.offset = offset;
    rd.errorOff = errorOff;
    rd.bypassFdCache = bypassFdCache;
    FileEntryView entry{};
    if (ampr_index_get_entry_view(fileId, &entry) != 0) {
        if (outRc) *outRc = apr_file_id_lookup_error(fileId);
        AMPR_CRITICAL_LOGF("apr.reactor.prepare.fail job=0x%llx reason=file-id fileId=%u len=0x%llx off=0x%llx rc=0x%x",
                           (unsigned long long)jobId,
                           fileId,
                           (unsigned long long)length,
                           (unsigned long long)offset,
                           outRc ? *outRc : apr_file_id_lookup_error(fileId));
        return false;
    }
    const uint64_t fileSize = static_cast<uint64_t>(entry.size);
    if (offset > fileSize || length > fileSize - offset) {
        if (outRc) *outRc = SCE_AMPR_ERROR_APR_INVALIDFILEOFFSET;
        AMPR_CRITICAL_LOGF("apr.reactor.prepare.fail job=0x%llx reason=file-range fileId=%u len=0x%llx off=0x%llx fileSize=0x%llx rc=0x%x",
                           (unsigned long long)jobId,
                           fileId,
                           (unsigned long long)length,
                           (unsigned long long)offset,
                           (unsigned long long)fileSize,
                           outRc ? *outRc : SCE_AMPR_ERROR_APR_INVALIDFILEOFFSET);
        return false;
    }
    rd.fileSize = entry.size;
    rd.filePath = entry.path;
    rd.filePathLength = entry.pathLength;
    rd.fileMetadataValid = true;

    *out = ampr_move(rd);
    return true;
}

static bool apr_file_size_bypasses_fd_cache(uint64_t fileSize) {
#if AMPR_EMU_APR_FD_CACHE_MIN_FILE_BYTES != 0
    return fileSize != 0 && fileSize <= AMPR_EMU_APR_FD_CACHE_MIN_FILE_BYTES;
#else
    (void)fileSize;
    return false;
#endif
}

static bool apr_read_desc_is_full_file_for_size(const AprAioReadDesc& rd, uint64_t fileSize) {
    return fileSize != 0 && rd.offset == 0 && rd.length == fileSize;
}

static bool apr_read_desc_bypasses_fd_cache_for_size(const AprAioReadDesc& rd,
                                                     uint64_t fileSize,
                                                     bool* outFullFileRead) {
    const bool fullFileRead = apr_read_desc_is_full_file_for_size(rd, fileSize);
    if (outFullFileRead) {
        *outFullFileRead = fullFileRead;
    }
    return fullFileRead || apr_file_size_bypasses_fd_cache(fileSize);
}

static void apr_update_read_desc_fd_policy(AprAioReadDesc& rd) {
    if (!rd.fileMetadataValid) {
        return;
    }
    if (apr_read_desc_bypasses_fd_cache_for_size(rd,
                                                 static_cast<uint64_t>(rd.fileSize),
                                                 &rd.fullFileRead)) {
        rd.bypassFdCache = true;
    }
}

static bool apr_read_desc_entry(const AprAioReadDesc& rd, FileEntryView* out) {
    if (!out) {
        return false;
    }
    if (rd.fileMetadataValid) {
        out->path = rd.filePath;
        out->pathLength = rd.filePathLength;
        out->size = rd.fileSize;
        out->mtime = 0;
        return rd.filePath != nullptr;
    }
    return ampr_index_get_entry_view(rd.fileId, out) == 0;
}

static bool apr_acquire_aio_read_desc(uint64_t jobId,
                                      AprAioReadDesc& rd,
                                      int* outRc,
                                      uint32_t* outErrorOffset) {
    if (outRc) *outRc = 0;
    if (outErrorOffset) *outErrorOffset = rd.errorOff;
    if (rd.fd >= 0) {
        return true;
    }

    FileEntryView directEntry{};
    bool haveDirectEntry = false;
    if (!rd.bypassFdCache) {
        haveDirectEntry = apr_read_desc_entry(rd, &directEntry);
        if (haveDirectEntry &&
            apr_read_desc_bypasses_fd_cache_for_size(rd,
                                                     static_cast<uint64_t>(directEntry.size),
                                                     &rd.fullFileRead)) {
            rd.bypassFdCache = true;
        }
    }

    if (rd.bypassFdCache) {
        if (!haveDirectEntry) {
            haveDirectEntry = apr_read_desc_entry(rd, &directEntry);
        }
        const char* const directMode = rd.fullFileRead ? "full-file-direct" : "small-file-direct";
        if (!haveDirectEntry) {
            if (outRc) *outRc = apr_file_id_lookup_error(rd.fileId);
            AMPR_CRITICAL_LOGF("apr.reactor.acquire.fail status=failed job=0x%llx reason=no-entry fileId=%u mode=%s rc=0x%x",
                               (unsigned long long)jobId,
                               rd.fileId,
                               directMode,
                               outRc ? *outRc : apr_file_id_lookup_error(rd.fileId));
            AMPR_FILE_STATUS_LOGF("apr.file.open status=failed reason=no-entry job=0x%llx fileId=%u mode=%s rc=0x%x",
                                  (unsigned long long)jobId,
                                  rd.fileId,
                                  directMode,
                                  outRc ? *outRc : apr_file_id_lookup_error(rd.fileId));
            return false;
        }
        fd_cache_release_watermark_headroom(1, directMode);
        if (!ampr_index_fd_cache_release_open_fd_budget_headroom(1)) {
            if (outRc) *outRc = SCE_KERNEL_ERROR_EAGAIN;
            AMPR_LOGF("apr.reactor.acquire.direct.no-headroom job=0x%llx fileId=%u path=%s mode=%s rc=0x%x",
                      (unsigned long long)jobId,
                      rd.fileId,
                      ampr_log_path_arg(directEntry.path),
                      directMode,
                      SCE_KERNEL_ERROR_EAGAIN);
            return false;
        }
        AMPR_TLOGF("apr.reactor.acquire.direct.enter job=0x%llx fileId=%u path=%s mode=%s len=0x%llx off=0x%llx",
                  (unsigned long long)jobId,
                  rd.fileId,
                  ampr_log_path_arg(directEntry.path),
                  directMode,
                  (unsigned long long)rd.length,
                  (unsigned long long)rd.offset);
        int fd = ampr_real_sceKernelOpen(directEntry.path,
                                         kAprAioOpenFlags,
                                         static_cast<SceKernelMode>(0));
        int openErrno = fd < 0 ? errno : 0;
        AMPR_TLOGF("apr.reactor.acquire.direct.leave job=0x%llx fileId=%u mode=%s fd=%d errno=%d",
                  (unsigned long long)jobId,
                  rd.fileId,
                  directMode,
                  fd,
                  openErrno);
        if (fd < 0 && openErrno == EMFILE) {
#if AMPR_EMU_DEBUG_LOG
            g_apr_direct_emfile_events.fetch_add(1, std::memory_order_relaxed);
#endif
            const AmprIndexFdCacheStats beforeStats = ampr_index_fd_cache_stats();
            const size_t observedOpen = beforeStats.open + ampr_index_fd_direct_open_count();
            const AmprIndexFdPressureCaps pressureCaps = ampr_index_fd_cache_mark_open_pressure(observedOpen);
            const size_t closedIdle = ampr_index_fd_cache_release_idle_percent(AMPR_EMU_FD_CACHE_EMFILE_IDLE_CLOSE_PERCENT);
            const AmprIndexFdCacheStats afterStats = ampr_index_fd_cache_stats();
            (void)pressureCaps;
            (void)closedIdle;
            (void)afterStats;
            AMPR_TLOGF("apr.reactor.acquire.direct.retry.enter job=0x%llx fileId=%u path=%s mode=%s",
                      (unsigned long long)jobId,
                      rd.fileId,
                      ampr_log_path_arg(directEntry.path),
                      directMode);
            fd = ampr_real_sceKernelOpen(directEntry.path,
                                         kAprAioOpenFlags,
                                         static_cast<SceKernelMode>(0));
            openErrno = fd < 0 ? errno : 0;
            AMPR_TLOGF("apr.reactor.acquire.direct.retry.leave job=0x%llx fileId=%u mode=%s fd=%d errno=%d",
                      (unsigned long long)jobId,
                      rd.fileId,
                      directMode,
                      fd,
                      openErrno);
            if (fd >= 0) {
                AMPR_LOGF("apr.reactor.acquire.direct.retry-emfile job=0x%llx fileId=%u path=%s mode=%s fd=%d observedOpen=%zu fdBudget=%zu cacheCap=%zu directCap=%zu closedIdle=%zu cacheBefore=%zu/%zu directBefore=%zu pinned=%zu pins=%zu evictable=%zu cacheAfter=%zu/%zu directAfter=%zu pinnedAfter=%zu pinsAfter=%zu evictableAfter=%zu",
                          (unsigned long long)jobId,
                          rd.fileId,
                          ampr_log_path_arg(directEntry.path),
                          directMode,
                          fd,
                          observedOpen,
                          pressureCaps.fdBudget,
                          pressureCaps.cacheCap,
                          pressureCaps.directCap,
                          closedIdle,
                          beforeStats.open,
                          beforeStats.entries,
                          observedOpen >= beforeStats.open ? observedOpen - beforeStats.open : 0,
                          beforeStats.pinnedOpen,
                          beforeStats.pins,
                          beforeStats.evictable,
                          afterStats.open,
                          afterStats.entries,
                          ampr_index_fd_direct_open_count() + 1u,
                          afterStats.pinnedOpen,
                          afterStats.pins,
                          afterStats.evictable);
            }
        }
        if (fd < 0) {
            if (outRc) *outRc = ampr_sce_errno_from_posix(openErrno);
            AMPR_CRITICAL_LOGF("apr.reactor.acquire.fail status=failed job=0x%llx reason=open-direct fileId=%u path=%s mode=%s errno=%d rc=0x%x",
                      (unsigned long long)jobId,
                      rd.fileId,
                      ampr_log_path_arg(directEntry.path),
                      directMode,
                      openErrno,
                      outRc ? *outRc : 0);
            AMPR_FILE_STATUS_LOGF("apr.file.open status=failed reason=direct job=0x%llx fileId=%u path=%s mode=%s errno=%d rc=0x%x",
                                  (unsigned long long)jobId,
                                  rd.fileId,
                                  ampr_log_path_arg(directEntry.path),
                                  directMode,
                                  openErrno,
                                  outRc ? *outRc : 0);
            return false;
        }
        rd.fd = fd;
        rd.closeAfter = true;
        ampr_index_fd_direct_note_open();
        AMPR_FILE_STATUS_LOGF("apr.file.open status=opened mode=%s job=0x%llx fileId=%u path=%s fd=%d",
                              directMode,
                              (unsigned long long)jobId,
                              rd.fileId,
                              ampr_log_path_arg(directEntry.path),
                              fd);
        return true;
    }

    FileEntryView cachedEntry{};
    if (!apr_read_desc_entry(rd, &cachedEntry)) {
        if (outRc) *outRc = apr_file_id_lookup_error(rd.fileId);
        return false;
    }
    AMPR_TLOGF("apr.reactor.acquire.cached.enter job=0x%llx fileId=%u len=0x%llx off=0x%llx",
              (unsigned long long)jobId,
              rd.fileId,
              (unsigned long long)rd.length,
              (unsigned long long)rd.offset);
    const int fd = ampr_index_acquire_cached_fd(jobId,
                                                rd.fileId,
                                                cachedEntry,
                                                kAprAioOpenFlags,
                                                0);
    AMPR_TLOGF("apr.reactor.acquire.cached.leave job=0x%llx fileId=%u fd=%d fileSize=0x%llx",
              (unsigned long long)jobId,
              rd.fileId,
              fd,
              (unsigned long long)cachedEntry.size);
    if (fd < 0) {
        if (outRc) *outRc = ampr_sce_errno_from_posix(-fd);
        AMPR_CRITICAL_LOGF("apr.reactor.acquire.fail status=failed job=0x%llx reason=fd fileId=%u path=%s pathKnown=%u fdErr=%d rc=0x%x",
                  (unsigned long long)jobId,
                  rd.fileId,
                  ampr_log_path_arg(cachedEntry.path),
                  1u,
                  fd,
                  outRc ? *outRc : 0);
        AMPR_FILE_STATUS_LOGF("apr.file.open status=failed reason=fd-cache job=0x%llx fileId=%u fdErr=%d rc=0x%x",
                              (unsigned long long)jobId,
                              rd.fileId,
                              fd,
                              outRc ? *outRc : 0);
        return false;
    }
    rd.fd = fd;
    rd.cachePinned = true;
    return true;
}

static void apr_release_aio_read_desc(AprAioReadDesc& rd) {
    if (rd.fd < 0) {
        return;
    }
    if (rd.borrowedFd) {
        rd.fd = -1;
        rd.cachePinned = false;
        rd.borrowedFd = false;
        return;
    }
    if (rd.closeAfter) {
        ::sceKernelClose(rd.fd);
        ampr_index_fd_direct_note_close();
        rd.fd = -1;
        return;
    }
    if (rd.cachePinned) {
        ampr_index_release_cached_fd_pin(rd.fileId);
        rd.cachePinned = false;
    }
    rd.fd = -1;
}

class AprAioReactor {
    struct JobState;
    using JobPtr = JobState*;

public:
    AprAioReactor();

    int submit(const Job& j,
               SceAprSubmitId* outSubmitId,
               uint32_t* outErrorOffset) {
        if (outSubmitId) {
            *outSubmitId = 0;
        }
        if (outErrorOffset) {
            *outErrorOffset = 0;
        }

        auto job = allocate_job_state();
        if (!job) {
            return SCE_KERNEL_ERROR_ENOMEM;
        }
        job->id = j.id;
        job->commandCount = j.sourceCommandCount;
        job->nativePrio = j.nativePrio;
        job->prioIndex = apr_scheduler_priority_lane(j.nativePrio);
        job->submitMode = j.submitMode;
        job->aprRes = j.aprRes;
        if (!j.sourceBuffer || j.sourceBytes == 0 || j.sourceCommandCount == 0) {
            set_fail(*job, "software-source-state", SCE_KERNEL_ERROR_EINVAL, 0);
            const int rc = job->result.rc;
            release_job_state(job);
            return rc;
        }
        job->sourceBuffer = static_cast<const uint8_t*>(j.sourceBuffer);
        job->sourceBytes = j.sourceBytes;
        job->nativeSubmitType = j.nativeSubmitType;
        uint32_t parsedCommands = 0;
        uint32_t validateOffset = 0;
        bool validatedFastRead = false;
        if (j.sourceCommandCount == 1u && job->sourceBytes >= sizeof(uint32_t)) {
            uint32_t firstWord = 0;
            std::memcpy(&firstWord, job->sourceBuffer, sizeof(firstWord));
            if ((firstWord & 0xFFu) == 40u) {
                Op op{};
                uint32_t opBytes = 0;
                uint32_t errorOffset = 0;
                const int decodeRc = sce::Ampr::ampr_decode_apr_packed_op(
                    job->sourceBuffer,
                    job->sourceBytes,
                    0,
                    &op,
                    &opBytes,
                    &errorOffset);
                if (decodeRc != 0 || op.type != OpType::AprReadFile ||
                    opBytes == 0 || opBytes != job->sourceBytes) {
                    set_fail(*job,
                             "software-source-decode",
                             decodeRc != 0 ? decodeRc : SCE_KERNEL_ERROR_EINVAL,
                             errorOffset);
                    const int rc = job->result.rc;
                    if (outErrorOffset) {
                        *outErrorOffset = job->result.errorOffset;
                    }
                    release_job_state(job);
                    return rc;
                }
                cache_decoded_op(*job, op, opBytes);
                validateOffset = opBytes;
                parsedCommands = 1;
                validatedFastRead = true;
            }
        }
        if (!validatedFastRead) {
            while (validateOffset < job->sourceBytes) {
                PackedOpView view{};
                uint32_t errorOffset = validateOffset;
                const int decodeRc = sce::Ampr::ampr_decode_apr_packed_op_view(
                    job->sourceBuffer,
                    job->sourceBytes,
                    validateOffset,
                    &view,
                    &errorOffset);
                if (decodeRc != 0 || view.bytes == 0 ||
                    view.bytes > job->sourceBytes - validateOffset) {
                    set_fail(*job,
                             "software-source-decode",
                             decodeRc != 0 ? decodeRc : SCE_KERNEL_ERROR_EINVAL,
                             errorOffset);
                    const int rc = job->result.rc;
                    if (outErrorOffset) {
                        *outErrorOffset = job->result.errorOffset;
                    }
                    release_job_state(job);
                    return rc;
                }
                validateOffset += view.bytes;
                ++parsedCommands;
            }
        }
        if (parsedCommands != j.sourceCommandCount) {
            set_fail(*job, "source-command-count", SCE_KERNEL_ERROR_EINVAL, validateOffset);
            const int rc = job->result.rc;
            if (outErrorOffset) {
                *outErrorOffset = job->result.errorOffset;
            }
            release_job_state(job);
            return rc;
        }
        if (!start_worker()) {
            release_job_state(job);
            return SCE_KERNEL_ERROR_ENOMEM;
        }
        size_t queuedReads = 0;
        [[maybe_unused]] const uint32_t jobSlot = job->poolSlot;
        [[maybe_unused]] const uint8_t laneIndex = job->prioIndex;
        [[maybe_unused]] const bool singleReadFastPath = validatedFastRead;
        {
            AmprUniqueLock lk(m);
            if (stop || shutdownRequested.load(std::memory_order_acquire)) {
                lk.unlock();
                release_job_state(job);
                return SCE_KERNEL_ERROR_ECANCELED;
            }
            SceAprSubmitId syntheticId = 0;
            if (outSubmitId && !allocate_synthetic_wait_slot_locked(*job, &syntheticId)) {
                lk.unlock();
                release_job_state(job);
                return SCE_KERNEL_ERROR_EBUSY;
            }
            if (!add_active_job_locked(job)) {
                release_unpublished_synthetic_wait_slot_locked(*job);
                lk.unlock();
                release_job_state(job);
                return SCE_KERNEL_ERROR_ENOMEM;
            }
#if AMPR_EMU_DEBUG_LOG
            job->reactorEnqueueTimeNs = time_counter_now();
#endif
            queuedReads = pendingReadTotalAtomic.load(std::memory_order_relaxed);
            if (outSubmitId) {
                job->syntheticWaitPublished = true;
                *outSubmitId = job->syntheticSubmitId;
            }
            reactorWakeEpoch.fetch_add(1u, std::memory_order_release);
        }
        reactorCv.notify_one();
        AMPR_VLOGF("apr.reactor.submit job=0x%llx prio=%u lane=%u commands=%u bytes=0x%x mode=software-direct jobSlot=%u fastRead=%u pendingReads=%zu",
                  (unsigned long long)j.id,
                  (unsigned)j.nativePrio,
                  (unsigned)laneIndex,
                  j.sourceCommandCount,
                  j.sourceBytes,
                  jobSlot,
                  singleReadFastPath ? 1u : 0u,
                  queuedReads);
        return 0;
    }

    int wait_synthetic_submit_id(SceAprSubmitId id, bool* outHandled) {
        if (outHandled) {
            *outHandled = false;
        }
        uint32_t slot = 0;
        uint32_t generation = 0;
        if (!decode_synthetic_submit_id(id, &slot, &generation)) {
            return 0;
        }
        AmprUniqueLock lk(m);
        SyntheticWaitSlot& waitSlot = syntheticWaitSlots[slot];
        if (!waitSlot.active || waitSlot.generation != generation) {
            // A tag-shaped native APR/AMM id is not ours. Only an exact live
            // registry entry may consume a wait; everything else falls through
            // to the original libkernel wait implementation.
            return 0;
        }
        if (outHandled) {
            *outHandled = true;
        }
        const uint8_t laneIndex = waitSlot.prioIndex;
        syntheticWaitCvs[laneIndex].wait(lk, [&] {
            const SyntheticWaitSlot& current = syntheticWaitSlots[slot];
            return !current.active || current.generation != generation || current.done;
        });
        SyntheticWaitSlot& completed = syntheticWaitSlots[slot];
        if (!completed.active || completed.generation != generation) {
            return SCE_KERNEL_ERROR_ESRCH;
        }
        const int rc = completed.result;
        completed.active = false;
        completed.done = false;
        completed.result = 0;
        completed.prioIndex = 0;
        return rc;
    }

    int shutdown() {
        ScePthread thread{};
        {
            AmprLockGuard lk(m);
            if (!started.load(std::memory_order_acquire)) {
                stop = true;
                shutdownRequested = true;
                return 0;
            }
            if (has_active_lanes_locked() || has_pending_reads() ||
                has_live_synthetic_waits_locked()) {
                return SCE_KERNEL_ERROR_EBUSY;
            }
            shutdownRequested.store(true, std::memory_order_release);
            reactorWakeEpoch.fetch_add(1u, std::memory_order_release);
            thread = workerThread;
        }
        notify_all_wait_domains();
        const int joinRc = scePthreadJoin(thread, nullptr);
        if (joinRc != 0) {
            return SCE_KERNEL_ERROR_EIO;
        }
        started.store(false, std::memory_order_release);
        return 0;
    }


private:
    static constexpr uint32_t kPendingReadQueueCapacity =
#if AMPR_EMU_APR_PENDING_READ_QUEUE_LIMIT != 0
        AMPR_EMU_APR_PENDING_READ_QUEUE_LIMIT;
#else
        256u;
#endif
    static constexpr uint64_t kSoftwareReadChunkMax =
        static_cast<uint64_t>(AMPR_EMU_APR_AIO_DISPATCH_QUANTUM_BYTES);
    static constexpr uint64_t kSoftwareReadLengthMax = 0x100000000ull;
    static constexpr uint64_t kSoftwareReadOffsetMaxExclusive = 0x10000000000ull;
    static constexpr uint64_t kSoftwareReadUserVaMax = 0xF00000000000ull;
    static_assert(kSoftwareReadChunkMax != 0,
                  "APR AIO dispatch quantum must be non-zero");
    static_assert(kSoftwareReadChunkMax <=
                      static_cast<uint64_t>((std::numeric_limits<int>::max)()),
                  "APR AIO dispatch quantum exceeds the SDK request limit");
    static constexpr uint8_t kPriorityCount = kAprPriorityArrayCount;
    static constexpr unsigned kConfiguredActiveReads =
        AMPR_EMU_APR_AIO_INFLIGHT > 0 ? AMPR_EMU_APR_AIO_INFLIGHT : 1;
    static constexpr unsigned kMaxActiveReads =
        kConfiguredActiveReads < SCE_KERNEL_AIO_ID_NUM_MAX
            ? kConfiguredActiveReads
            : SCE_KERNEL_AIO_ID_NUM_MAX;
    static constexpr uint32_t kReadChainPoolCapacity =
        kPendingReadQueueCapacity + static_cast<uint32_t>(kMaxActiveReads);
    static constexpr size_t kAioPollBatchLimit =
        AMPR_EMU_APR_AIO_POLL_BATCH_LIMIT != 0
            ? static_cast<size_t>(AMPR_EMU_APR_AIO_POLL_BATCH_LIMIT)
            : static_cast<size_t>(kMaxActiveReads);
    static constexpr size_t kAioRegularPollReserveMax =
        kAioPollBatchLimit > 1u ? kAioPollBatchLimit - 1u : 0u;
    static_assert(AMPR_EMU_APR_AIO_POLL_REGULAR_RESERVE >= 0,
                  "APR AIO regular poll reserve must not be negative");
    static constexpr size_t kConfiguredAioRegularPollReserve =
        static_cast<size_t>(AMPR_EMU_APR_AIO_POLL_REGULAR_RESERVE);
    static constexpr size_t kAioRegularPollReserve =
        kConfiguredAioRegularPollReserve < kAioRegularPollReserveMax
            ? kConfiguredAioRegularPollReserve
            : kAioRegularPollReserveMax;
    static constexpr size_t kAioHotPollLimit =
        kAioPollBatchLimit - kAioRegularPollReserve;
    static constexpr uint32_t kHotPollQueueCapacity =
        static_cast<uint32_t>(kMaxActiveReads * 2u);
    static constexpr uint32_t kReadCompletionInitialBits =
        kPendingReadQueueCapacity + static_cast<uint32_t>(kMaxActiveReads) + 1u;
    static constexpr size_t kReadCompletionRingWords =
        (static_cast<size_t>(kReadCompletionInitialBits) + 63u) / 64u;
    static constexpr uint64_t kReadCompletionRingBits =
        static_cast<uint64_t>(kReadCompletionRingWords * 64u);
    static constexpr uint32_t kJobStatePoolCapacity =
        static_cast<uint32_t>(kAprCommandBufferLiveMax);
    static constexpr uint32_t kSyntheticWaitSlotCapacity = kJobStatePoolCapacity;
    static constexpr uint32_t kSyntheticSubmitIdTag = 0xA5000000u;
    static constexpr uint32_t kSyntheticSubmitIdTagMask = 0xFF000000u;
    static constexpr uint64_t kNativeCompletionTimeoutNs = 5000000000ull;
    static constexpr uint32_t kFdCacheMaintenanceBusyStride = 256u;
#if AMPR_EMU_FD_CACHE_IDLE_CLOSE_NS != 0
    static constexpr uint64_t kFdCacheMaintenanceIntervalNs =
        AMPR_EMU_FD_CACHE_IDLE_SCAN_NS != 0
            ? AMPR_EMU_FD_CACHE_IDLE_SCAN_NS
            : AMPR_EMU_FD_CACHE_IDLE_CLOSE_NS;
    static_assert(kFdCacheMaintenanceIntervalNs != 0,
                  "fd-cache maintenance interval must be non-zero");
#endif
    static constexpr uint32_t kSyntheticSubmitIdSlotMask = 0x00000FFFu;
    static constexpr uint32_t kSyntheticSubmitIdGenerationMask = 0x00FFF000u;
    static constexpr uint32_t kSyntheticSubmitIdGenerationShift = 12u;
    static_assert(kJobStatePoolCapacity != 0, "job state pool must be non-empty");
    static_assert(kSyntheticWaitSlotCapacity <= kSyntheticSubmitIdSlotMask + 1u,
                  "synthetic APR submit-id slot field is too small");
    static_assert(AMPR_EMU_APR_AIO_POLL_BACKOFF_MIN_NS != 0,
                  "APR AIO poll backoff minimum must be non-zero");
    static_assert(AMPR_EMU_APR_AIO_POLL_BACKOFF_MAX_NS >= AMPR_EMU_APR_AIO_POLL_BACKOFF_MIN_NS,
                  "APR AIO poll backoff maximum must cover the minimum");
    static_assert(AMPR_EMU_APR_AIO_POLL_DEPENDENT_BACKOFF_MAX_NS >= AMPR_EMU_APR_AIO_POLL_BACKOFF_MIN_NS,
                  "APR AIO dependent poll backoff maximum must cover the minimum");
    static_assert(AMPR_EMU_APR_AIO_POLL_STAGED_EOP_BACKOFF_MAX_NS >= AMPR_EMU_APR_AIO_POLL_BACKOFF_MIN_NS,
                  "APR AIO staged-EOP poll backoff maximum must cover the minimum");
    static_assert(AMPR_EMU_APR_AIO_POLL_STAGED_EOP_BACKOFF_MAX_NS <= AMPR_EMU_APR_AIO_POLL_DEPENDENT_BACKOFF_MAX_NS,
                  "APR AIO staged-EOP poll cap must not exceed the dependent cap");
#if AMPR_EMU_APR_AIO_CROSS_EOP_READAHEAD
    static_assert(AMPR_EMU_APR_AIO_CROSS_EOP_MAX_FENCES > 0,
                  "APR cross-EOP read-ahead needs at least one fence slot");
    static_assert(AMPR_EMU_APR_AIO_CROSS_EOP_READS_PER_PASS > 0,
                  "APR cross-EOP read-ahead needs a non-zero pass budget");
#endif
    static_assert(AMPR_EMU_APR_AIO_GATING_SPIN_POLLS <= kAioPollBatchLimit,
                  "APR AIO gating spin polls must fit the poll batch");
    static_assert(AMPR_EMU_APR_AIO_POLL_SMALL_BACKGROUND_BACKOFF_MAX_NS >= AMPR_EMU_APR_AIO_POLL_BACKOFF_MIN_NS,
                  "APR AIO small background poll backoff maximum must cover the minimum");

    struct ReadChain {
        JobPtr job{};
        // Owns the only direct fd/cache pin for the complete logical read.
        // Active descriptors borrow it and are independently tracked by AIO id.
        AprAioReadDesc ownerDesc{};
        void* nextBuffer{};
        uint64_t nextOffset{};
        uint64_t remaining{};
        uint64_t seq{};
        size_t commandIndex{};
        uint32_t pendingCount{};
        uint32_t activeCount{};
        uint32_t poolSlot{UINT32_MAX};
        bool allIssued{false};
#if AMPR_EMU_DEBUG_LOG
        uint64_t nativeTriggerTimeNs{};
#endif
    };

    struct ReadChainSlot {
        ReadChain value{};
        uint32_t nextFree{UINT32_MAX};
        bool active{false};
    };

    struct PendingRead {
        JobPtr job;
        AprAioReadDesc desc;
        ReadChain* chain{};
        uint64_t seq{};
        size_t commandIndex{};
        uint32_t ammEfaultRetries{};
        uint32_t aioCompletionRetries{};
        uint64_t notBeforeNs{};
        bool retrySlice{false};
#if AMPR_EMU_DEBUG_LOG
        uint64_t nativeTriggerTimeNs{};
        uint64_t pendingEnqueueTimeNs{};
#endif
    };

    struct PendingReadNode {
        PendingRead value{};
        uint32_t prev{kPendingReadNodeInvalid};
        uint32_t next{kPendingReadNodeInvalid};
        bool active{false};
    };

    class PendingReadQueue {
    public:
        class iterator {
        public:
            iterator() = default;
            iterator(PendingReadQueue* owner, uint32_t index) : owner_(owner), index_(index) {}

            PendingRead& operator*() const { return owner_->owner_->pendingReadNodes[index_].value; }
            PendingRead* operator->() const { return &owner_->owner_->pendingReadNodes[index_].value; }

            iterator& operator++() {
                index_ = (index_ == kPendingReadNodeInvalid)
                    ? kPendingReadNodeInvalid
                    : owner_->owner_->pendingReadNodes[index_].next;
                return *this;
            }

            iterator operator+(size_t count) const {
                iterator it = *this;
                while (count-- != 0 && it.index_ != kPendingReadNodeInvalid) {
                    ++it;
                }
                return it;
            }

            bool operator==(const iterator& other) const {
                return owner_ == other.owner_ && index_ == other.index_;
            }

            bool operator!=(const iterator& other) const {
                return !(*this == other);
            }

        private:
            friend class PendingReadQueue;
            PendingReadQueue* owner_{};
            uint32_t index_{kPendingReadNodeInvalid};
        };

        class const_iterator {
        public:
            const_iterator() = default;
            const_iterator(const PendingReadQueue* owner, uint32_t index) : owner_(owner), index_(index) {}

            const PendingRead& operator*() const { return owner_->owner_->pendingReadNodes[index_].value; }
            const PendingRead* operator->() const { return &owner_->owner_->pendingReadNodes[index_].value; }

            const_iterator& operator++() {
                index_ = (index_ == kPendingReadNodeInvalid)
                    ? kPendingReadNodeInvalid
                    : owner_->owner_->pendingReadNodes[index_].next;
                return *this;
            }

            bool operator==(const const_iterator& other) const {
                return owner_ == other.owner_ && index_ == other.index_;
            }

            bool operator!=(const const_iterator& other) const {
                return !(*this == other);
            }

        private:
            const PendingReadQueue* owner_{};
            uint32_t index_{kPendingReadNodeInvalid};
        };

        void set_owner(AprAioReactor* owner) { owner_ = owner; }
        bool empty() const { return count_ == 0; }
        size_t size() const { return count_; }

        iterator begin() { return iterator(this, head_); }
        iterator end() { return iterator(this, kPendingReadNodeInvalid); }
        const_iterator begin() const { return const_iterator(this, head_); }
        const_iterator end() const { return const_iterator(this, kPendingReadNodeInvalid); }

        iterator scan_begin() {
            if (count_ == 0) {
                scanCursor_ = kPendingReadNodeInvalid;
                return end();
            }
            if (scanCursor_ == kPendingReadNodeInvalid) {
                scanCursor_ = head_;
            }
            return iterator(this, scanCursor_);
        }

        iterator next_cyclic(iterator it) {
            if (it.owner_ != this || it.index_ == kPendingReadNodeInvalid || count_ == 0) {
                return end();
            }
            const uint32_t next = owner_->pendingReadNodes[it.index_].next;
            return iterator(this, next != kPendingReadNodeInvalid ? next : head_);
        }

        void set_scan_cursor_after(iterator it) {
            const iterator next = next_cyclic(it);
            scanCursor_ = next.index_;
        }

        PendingRead& front() { return owner_->pendingReadNodes[head_].value; }
        const PendingRead& front() const { return owner_->pendingReadNodes[head_].value; }

        bool push_front(PendingRead&& value) {
            const uint32_t index = insert_node_before(head_, ampr_move(value));
            if (index == kPendingReadNodeInvalid) {
                return false;
            }
            scanCursor_ = index;
            return true;
        }

        bool push_back(PendingRead&& value) {
            return insert_node_before(kPendingReadNodeInvalid, ampr_move(value)) != kPendingReadNodeInvalid;
        }

        iterator insert(iterator pos, PendingRead&& value) {
            if (pos.owner_ != this) {
                return end();
            }
            const uint32_t index = insert_node_before(pos.index_, ampr_move(value));
            return index == kPendingReadNodeInvalid ? end() : iterator(this, index);
        }

        iterator erase(iterator it) {
            if (it.owner_ != this || it.index_ == kPendingReadNodeInvalid) {
                return end();
            }
            return iterator(this, unlink_node(it.index_));
        }

        void pop_front() {
            if (head_ != kPendingReadNodeInvalid) {
                (void)unlink_node(head_);
            }
        }

    private:
        uint32_t insert_node_before(uint32_t before, PendingRead&& value) {
            if (!owner_) {
                return kPendingReadNodeInvalid;
            }
            const uint32_t index = owner_->pending_read_node_alloc(ampr_move(value));
            if (index == kPendingReadNodeInvalid) {
                return kPendingReadNodeInvalid;
            }

            PendingReadNode& node = owner_->pendingReadNodes[index];
            if (before == kPendingReadNodeInvalid) {
                node.prev = tail_;
                node.next = kPendingReadNodeInvalid;
                if (tail_ != kPendingReadNodeInvalid) {
                    owner_->pendingReadNodes[tail_].next = index;
                } else {
                    head_ = index;
                }
                tail_ = index;
            } else {
                PendingReadNode& beforeNode = owner_->pendingReadNodes[before];
                node.prev = beforeNode.prev;
                node.next = before;
                if (beforeNode.prev != kPendingReadNodeInvalid) {
                    owner_->pendingReadNodes[beforeNode.prev].next = index;
                } else {
                    head_ = index;
                }
                beforeNode.prev = index;
            }
            ++count_;
            return index;
        }

        uint32_t unlink_node(uint32_t index) {
            PendingReadNode& node = owner_->pendingReadNodes[index];
            const uint32_t next = node.next;
            const bool erasedScanCursor = scanCursor_ == index;
            if (node.prev != kPendingReadNodeInvalid) {
                owner_->pendingReadNodes[node.prev].next = node.next;
            } else {
                head_ = node.next;
            }
            if (node.next != kPendingReadNodeInvalid) {
                owner_->pendingReadNodes[node.next].prev = node.prev;
            } else {
                tail_ = node.prev;
            }
            owner_->pending_read_node_free(index);
            --count_;
            if (count_ == 0) {
                scanCursor_ = kPendingReadNodeInvalid;
            } else if (erasedScanCursor) {
                scanCursor_ = next != kPendingReadNodeInvalid ? next : head_;
            }
            return next;
        }

        AprAioReactor* owner_{};
        uint32_t head_{kPendingReadNodeInvalid};
        uint32_t tail_{kPendingReadNodeInvalid};
        uint32_t scanCursor_{kPendingReadNodeInvalid};
        size_t count_{0};
    };

    void pending_read_pool_init() {
        ampr_index_free_list_init_nodes(pendingReadFree,
                                        pendingReadNodes,
                                        kPendingReadQueueCapacity,
                                        kPendingReadNodeInvalid);
    }

    uint32_t pending_read_node_alloc(PendingRead&& value) {
        const uint32_t index = ampr_index_free_list_take_node(pendingReadFree,
                                                              pendingReadNodes);
        if (index == kPendingReadNodeInvalid) {
            invariantPendingReadPoolFull.fetch_add(1, std::memory_order_relaxed);
            return kPendingReadNodeInvalid;
        }
        PendingReadNode& node = pendingReadNodes[index];
        node = {};
        node.value = ampr_move(value);
        node.prev = kPendingReadNodeInvalid;
        node.next = kPendingReadNodeInvalid;
        node.active = true;
        return index;
    }

    void pending_read_node_free(uint32_t index) {
        if (index >= kPendingReadQueueCapacity) {
            return;
        }
        PendingReadNode& node = pendingReadNodes[index];
        node = {};
        (void)ampr_index_free_list_put_node(pendingReadFree, pendingReadNodes, index);
    }

    static size_t priority_lane_index(size_t priority) {
        return apr_clamp_priority_index(priority);
    }

    PendingReadQueue& pending_read_lane(size_t priority) {
        return pendingReadLanes[priority_lane_index(priority)];
    }

    const PendingReadQueue* highest_priority_pending_lane() const {
        for (size_t priority = kAprPriorityMin; priority <= kAprPriorityMax; ++priority) {
            const PendingReadQueue& lane = pendingReadLanes[priority];
            if (!lane.empty()) {
                return &lane;
            }
        }
        return nullptr;
    }

    struct SyntheticWaitSlot {
        uint32_t generation{};
        int result{};
        uint8_t prioIndex{};
        bool active{};
        bool done{};
    };

    enum class NativeMicroEngine : uint8_t {
        None,
        AprBatch,
        Amm,
    };

    enum class NativeBatchPhase : uint8_t {
        Free,
        Filling,
        Active,
    };

    struct NativeBatchState {
        NativeBatchPhase phase{NativeBatchPhase::Free};
        uint32_t generation{};
        uint32_t nextGroup{};
        uint32_t openGroupPackets{};
        uint32_t packetCount{};
        uint32_t nativeSubmitType{};
        uint64_t observedProgress{};
        uint64_t firstSequence{};
        uint64_t lastSequence{};
        uint64_t submitTimeNs{};
        uint64_t lastReleaseTimeNs{};
        uint64_t lastWatchdogTimeNs{};
        SceAprSubmitId submitId{};
    };

    struct NativeBatchLane {
        int8_t activeBuffer{-1};
        uint64_t issuedSequence{};
        uint64_t completedSequence{};
        uint64_t blockingWaitSequence{};
        uint64_t deferredReleaseSequence{};
        uint64_t deferredReleaseJobId{};
        uint32_t deferredReleaseBufferIndex{};
        uint32_t deferredReleaseGroupIndex{};
        NativeBatchState buffers[kAprNativeBatchBufferCountPerLane]{};
    };

    struct GatherScatterState {
        uint64_t nextOffset{};
        void* nextBuffer{};
        uint32_t fileId{};
    };
    static_assert(sizeof(GatherScatterState) == 24,
                  "APR priority-stream gather/scatter state must stay compact");

    struct JobState {
        uint64_t id{};
        const uint8_t* sourceBuffer{};
        uint32_t sourceBytes{};
        uint32_t sourceOffset{};
        uint32_t sourceCommandIndex{};
        // One non-owning decoded record at sourceOffset. A zero byte count is
        // invalid; the source allocation remains application-owned and immutable.
        Op decodedOpCache{};
        uint32_t decodedOpCacheBytes{};
        uint32_t poolSlot{UINT32_MAX};
        bool mapActive{};
        void* nativeCommandBuffer{};
        uint32_t nativeCommandBufferBytes{};
        uint32_t commandCount{};
        bool processingComplete{};
        uint32_t nativePrio{};
        uint8_t prioIndex{};
        AprSubmitMode submitMode{AprSubmitMode::kSubmit};
        SceAprResultBuffer* aprRes{};
        JobResult result{};

        uint64_t nextReadSeq{1};
        uint64_t latestSubmittedReadSeq{};
        uint64_t completedReadSeq{};
        uint64_t completedOutOfOrderWords[kReadCompletionRingWords]{};
        uint32_t pendingReadCount{};
        uint32_t activeReadCount{};
        uint32_t activeReadHead{UINT32_MAX};
        uint32_t activeReadTail{UINT32_MAX};
#if AMPR_EMU_APR_AIO_CROSS_EOP_READAHEAD
        uint32_t crossEopScanOffset{};
        uint32_t crossEopScanCommandIndex{};
        uint32_t crossEopFenceHead{};
        uint32_t crossEopFenceCount{};
        uint32_t crossEopDeferredErrorOffset{UINT32_MAX};
        int crossEopDeferredErrorRc{};
        const char* crossEopDeferredErrorReason{};
        bool crossEopScanActive{};
        uint64_t crossEopFenceReadSequences[
            AMPR_EMU_APR_AIO_CROSS_EOP_MAX_FENCES]{};
        uint32_t crossEopFenceSourceOffsets[
            AMPR_EMU_APR_AIO_CROSS_EOP_MAX_FENCES]{};
#endif
        std::atomic<bool> nativeSubmitted{false};
        volatile uint64_t* nativeCompletionAddress{};
        uint64_t nativeSubmitTimeNs{};
        NativeMicroEngine nativeMicroEngine{NativeMicroEngine::None};
        uint64_t nativeBatchSequence{};
        uint64_t nativeBatchLookaheadPriorSequence{};
        uint64_t nativeBatchReleaseReadSequence{};
        bool nativeBatchReleasePending{};
        bool nativeBatchReleaseAfterSoftwareAddress{};
        uint32_t nativeSourceOffset{};
        OpType nativeSourceType{OpType::Nop};
        SceAprSubmitId syntheticSubmitId{};
        uint32_t syntheticWaitSlot{UINT32_MAX};
        uint32_t syntheticWaitGeneration{};
        bool syntheticWaitPublished{false};
        uint32_t nativeSubmitBytes{};
        OpType nativeSubmitFirstType{OpType::Nop};
        int nativeSubmitType{};
        std::atomic<bool> failed{false};
        bool hasCommandError{false};
        bool activeListed{false};
        JobState* activePrev{nullptr};
        JobState* activeNext{nullptr};
        JobState* priorityPrev{nullptr};
        std::atomic<JobState*> priorityNext{nullptr};

#if AMPR_EMU_DEBUG_LOG
        uint64_t completionReadyNs{};
        uint64_t reactorEnqueueTimeNs{};
        uint64_t firstReadQueueTimeNs{};
        bool readCompletionWindowBlocked{};
#endif
#if AMPR_EMU_DEBUG_LOG && (AMPR_EMU_DEBUG_LOG_VERBOSE || AMPR_EMU_DEBUG_LOG_TRACE)
        size_t readOpCount{};
        size_t submittedReadCount{};
        size_t completedReadCount{};
        bool startLogged{false};
        uint64_t blockedLogCount{};
        size_t lastBlockedOpIndex{static_cast<size_t>(-1)};
        const char* lastBlockedReason{nullptr};
#endif
    };

    struct JobStateSlot {
        bool active{false};
        uint32_t nextFree{UINT32_MAX};
        alignas(JobState) unsigned char storage[sizeof(JobState)]{};
    };

    ReadChain* allocate_read_chain() {
        const uint32_t slotIndex = readChainFreeHead;
        if (slotIndex >= kReadChainPoolCapacity) {
            invariantReadChainPoolFull.fetch_add(1, std::memory_order_relaxed);
            return nullptr;
        }
        ReadChainSlot& slot = readChainSlots[slotIndex];
        readChainFreeHead = slot.nextFree;
        slot.nextFree = UINT32_MAX;
        slot.active = true;
        slot.value = {};
        slot.value.poolSlot = slotIndex;
        return &slot.value;
    }

    void release_read_chain_storage(ReadChain* chain) {
        if (!chain || chain->poolSlot >= kReadChainPoolCapacity) {
            return;
        }
        const uint32_t slotIndex = chain->poolSlot;
        ReadChainSlot& slot = readChainSlots[slotIndex];
        if (!slot.active || &slot.value != chain) {
            AMPR_CRITICAL_LOGF("apr.reactor.readChain.release.invalid slot=%u chain=%p",
                               slotIndex,
                               chain);
            ampr_debug_int3_trap();
            return;
        }
        slot.value = {};
        slot.active = false;
        slot.nextFree = readChainFreeHead;
        readChainFreeHead = slotIndex;
    }

    bool read_chain_is_live(const ReadChain* chain) const {
        if (!chain || chain->poolSlot >= kReadChainPoolCapacity) {
            return false;
        }
        const ReadChainSlot& slot = readChainSlots[chain->poolSlot];
        return slot.active && &slot.value == chain;
    }

    void release_job_state(JobState* job) noexcept {
        if (!job) {
            return;
        }
        const uint32_t slotIndex = job->poolSlot;
        if (slotIndex >= kJobStatePoolCapacity) {
            AMPR_CRITICAL_LOGF("apr.reactor.job.pool.foreignFree job=%p slot=%u",
                               job,
                               slotIndex);
            return;
        }
        AmprSpinLock lock(&jobStatePoolLock);
        JobStateSlot& slot = jobStateSlots[slotIndex];
        if (!slot.active || reinterpret_cast<JobState*>(slot.storage) != job) {
            AMPR_CRITICAL_LOGF("apr.reactor.job.pool.doubleFree job=%p slot=%u",
                               job,
                               slotIndex);
            return;
        }
        job->~JobState();
        slot.active = false;
        slot.nextFree = jobStateFreeHead;
        jobStateFreeHead = slotIndex;
    }

    JobPtr allocate_job_state() {
        AmprSpinLock lock(&jobStatePoolLock);
        const uint32_t slotIndex = jobStateFreeHead;
        if (slotIndex < kJobStatePoolCapacity) {
            JobStateSlot& slot = jobStateSlots[slotIndex];
            jobStateFreeHead = slot.nextFree;
            slot.nextFree = UINT32_MAX;
            slot.active = true;
            JobState* const job = new (slot.storage) JobState();
            job->poolSlot = slotIndex;
            return job;
        }
        invariantJobPoolFull.fetch_add(1, std::memory_order_relaxed);
        AMPR_CRITICAL_LOGF("apr.reactor.job.pool.full capacity=%u",
                          (unsigned)kJobStatePoolCapacity);
        ampr_debug_int3_trap();
        return nullptr;
    }

    enum class DirectReadClass : uint8_t {
        CachedOrPartial,
        Small,
        Normal,
        Bulk,
    };

    struct DirectReadCounts {
        size_t total{};
        size_t small{};
        size_t normal{};
        size_t bulk{};
    };

    struct ActiveRead {
        JobPtr job;
        AprAioReadDesc desc;
        ReadChain* chain{};
        SceKernelAioResult result{};
        SceKernelAioRWRequest request{};
        SceKernelAioSubmitId aioId{};
        int aioPrio{SCE_KERNEL_AIO_PRIORITY_MID};
        uint64_t seq{};
        size_t commandIndex{};
        uint64_t submitTimeNs{};
#if AMPR_EMU_DEBUG_LOG
        uint64_t nativeTriggerTimeNs{};
        uint64_t pendingEnqueueTimeNs{};
#endif
        uint64_t nextPollTimeNs{};
        uint32_t pollBackoffNs{};
        int lastPollState{};
        int lastPollRc{};
        uint32_t ammEfaultRetries{};
        uint32_t aioCompletionRetries{};
        uint32_t aioDeleteRetries{};
        uint64_t aioDeleteFirstFailureNs{};
        uint32_t gatingSpinPollsRemaining{};
        uint32_t listSlot{UINT32_MAX};
        uint32_t listGeneration{};
        uint32_t pollDeadlineHeapIndex{UINT32_MAX};
        uint32_t jobPrevSlot{UINT32_MAX};
        uint32_t jobNextSlot{UINT32_MAX};
        bool hotPollQueued{false};
        bool retrySlice{false};
        bool activeFileCounted{false};
    };

    struct HotPollEntry {
        uint32_t slot{UINT32_MAX};
        uint32_t generation{};
    };

    class ActiveReadList {
        static constexpr uint32_t kInvalid = UINT32_MAX;
        struct Slot {
            ActiveRead value{};
            uint32_t prev{kInvalid};
            uint32_t next{kInvalid};
            uint32_t generation{};
            bool active{false};
        };

    public:
        class iterator {
        public:
            iterator() = default;
            iterator(ActiveReadList* owner, uint32_t index) : owner_(owner), index_(index) {}

            ActiveRead& operator*() const { return owner_->slots_[index_].value; }
            ActiveRead* operator->() const { return &owner_->slots_[index_].value; }

            iterator& operator++() {
                index_ = (index_ == kInvalid) ? kInvalid : owner_->slots_[index_].next;
                return *this;
            }

            iterator& operator--() {
                index_ = (index_ == kInvalid) ? owner_->tail_ : owner_->slots_[index_].prev;
                return *this;
            }

            bool operator==(const iterator& other) const {
                return owner_ == other.owner_ && index_ == other.index_;
            }

            bool operator!=(const iterator& other) const {
                return !(*this == other);
            }

        private:
            friend class ActiveReadList;
            ActiveReadList* owner_{};
            uint32_t index_{kInvalid};
        };

        class const_iterator {
        public:
            const_iterator() = default;
            const_iterator(const ActiveReadList* owner, uint32_t index) : owner_(owner), index_(index) {}

            const ActiveRead& operator*() const { return owner_->slots_[index_].value; }
            const ActiveRead* operator->() const { return &owner_->slots_[index_].value; }

            const_iterator& operator++() {
                index_ = (index_ == kInvalid) ? kInvalid : owner_->slots_[index_].next;
                return *this;
            }

            bool operator==(const const_iterator& other) const {
                return owner_ == other.owner_ && index_ == other.index_;
            }

            bool operator!=(const const_iterator& other) const {
                return !(*this == other);
            }

        private:
            const ActiveReadList* owner_{};
            uint32_t index_{kInvalid};
        };

        bool empty() const { return count_ == 0; }
        size_t size() const { return count_; }

        iterator begin() { return iterator(this, head_); }
        iterator end() { return iterator(this, kInvalid); }
        const_iterator begin() const { return const_iterator(this, head_); }
        const_iterator end() const { return const_iterator(this, kInvalid); }
        iterator iterator_from_slot(uint32_t slot) {
            if (slot >= kMaxActiveReads || !slots_[slot].active) {
                return end();
            }
            return iterator(this, slot);
        }
        ActiveRead* active_at_slot(uint32_t slot) {
            if (slot >= kMaxActiveReads || !slots_[slot].active) {
                return nullptr;
            }
            return &slots_[slot].value;
        }
        ActiveRead* active_at_slot(uint32_t slot, uint32_t generation) {
            if (slot >= kMaxActiveReads ||
                !slots_[slot].active ||
                slots_[slot].generation != generation) {
                return nullptr;
            }
            return &slots_[slot].value;
        }

        ActiveRead& front() { return slots_[head_].value; }
        const ActiveRead& front() const { return slots_[head_].value; }

        iterator push_back(ActiveRead&& value) {
            uint32_t slot = kInvalid;
            for (uint32_t n = 0; n < kMaxActiveReads; ++n) {
                const uint32_t i = (freeCursor_ + n) % kMaxActiveReads;
                if (!slots_[i].active) {
                    slot = i;
                    break;
                }
            }
            if (slot == kInvalid) {
                __builtin_trap();
            }
            freeCursor_ = (slot + 1u) % kMaxActiveReads;
            Slot& node = slots_[slot];
            node.generation = node.generation == UINT32_MAX ? 1u : node.generation + 1u;
            node.value = ampr_move(value);
            node.value.listSlot = slot;
            node.value.listGeneration = node.generation;
            node.prev = tail_;
            node.next = kInvalid;
            node.active = true;
            if (tail_ != kInvalid) {
                slots_[tail_].next = slot;
            } else {
                head_ = slot;
            }
            tail_ = slot;
            ++count_;
            return iterator(this, slot);
        }

        iterator erase(iterator it) {
            if (it.owner_ != this || it.index_ == kInvalid || !slots_[it.index_].active) {
                return end();
            }
            const uint32_t index = it.index_;
            const uint32_t next = slots_[index].next;
            const uint32_t prev = slots_[index].prev;
            if (prev != kInvalid) {
                slots_[prev].next = next;
            } else {
                head_ = next;
            }
            if (next != kInvalid) {
                slots_[next].prev = prev;
            } else {
                tail_ = prev;
            }
            const uint32_t generation = slots_[index].generation;
            slots_[index].value = {};
            slots_[index].prev = kInvalid;
            slots_[index].next = kInvalid;
            slots_[index].active = false;
            slots_[index].generation = generation;
            --count_;
            freeCursor_ = index;
            return iterator(this, next);
        }

    private:
        Slot slots_[kMaxActiveReads]{};
        uint32_t head_{kInvalid};
        uint32_t tail_{kInvalid};
        uint32_t freeCursor_{0};
        size_t count_{0};
    };

    using ActiveReadIt = ActiveReadList::iterator;

    static bool poll_deadline_less(const ActiveRead* lhs,
                                   const ActiveRead* rhs) {
        if (lhs->nextPollTimeNs != rhs->nextPollTimeNs) {
            return lhs->nextPollTimeNs < rhs->nextPollTimeNs;
        }
        return lhs->listSlot < rhs->listSlot;
    }

    void swap_poll_deadlines(uint32_t lhsIndex, uint32_t rhsIndex) {
        if (lhsIndex == rhsIndex) {
            return;
        }
        ActiveRead* const lhs = activePollDeadlineHeap[lhsIndex];
        ActiveRead* const rhs = activePollDeadlineHeap[rhsIndex];
        activePollDeadlineHeap[lhsIndex] = rhs;
        activePollDeadlineHeap[rhsIndex] = lhs;
        rhs->pollDeadlineHeapIndex = lhsIndex;
        lhs->pollDeadlineHeapIndex = rhsIndex;
    }

    void sift_poll_deadline_up(uint32_t index) {
        while (index != 0) {
            const uint32_t parent = (index - 1u) / 2u;
            if (!poll_deadline_less(activePollDeadlineHeap[index],
                                    activePollDeadlineHeap[parent])) {
                break;
            }
            swap_poll_deadlines(index, parent);
            index = parent;
        }
    }

    void sift_poll_deadline_down(uint32_t index) {
        for (;;) {
            const uint32_t left = index * 2u + 1u;
            if (left >= activePollDeadlineHeapSize) {
                return;
            }
            const uint32_t right = left + 1u;
            uint32_t smallest = left;
            if (right < activePollDeadlineHeapSize &&
                poll_deadline_less(activePollDeadlineHeap[right],
                                   activePollDeadlineHeap[left])) {
                smallest = right;
            }
            if (!poll_deadline_less(activePollDeadlineHeap[smallest],
                                    activePollDeadlineHeap[index])) {
                return;
            }
            swap_poll_deadlines(index, smallest);
            index = smallest;
        }
    }

    void update_poll_deadline(ActiveRead& active, uint64_t oldDeadlineNs) {
        if (active.pollDeadlineHeapIndex == UINT32_MAX) {
            if (active.listSlot >= kMaxActiveReads ||
                activePollDeadlineHeapSize >= kMaxActiveReads) {
                AMPR_CRITICAL_LOGF("apr.reactor.pollDeadline.insert.full slot=%u size=%u limit=%u",
                                   active.listSlot,
                                   activePollDeadlineHeapSize,
                                   (unsigned)kMaxActiveReads);
                std::abort();
            }
            const uint32_t index = activePollDeadlineHeapSize++;
            activePollDeadlineHeap[index] = &active;
            active.pollDeadlineHeapIndex = index;
            sift_poll_deadline_up(index);
            return;
        }

        const uint32_t index = active.pollDeadlineHeapIndex;
        if (index >= activePollDeadlineHeapSize ||
            activePollDeadlineHeap[index] != &active) {
            AMPR_CRITICAL_LOGF("apr.reactor.pollDeadline.update.invalid slot=%u index=%u size=%u",
                               active.listSlot,
                               index,
                               activePollDeadlineHeapSize);
            std::abort();
        }
        if (active.nextPollTimeNs < oldDeadlineNs) {
            sift_poll_deadline_up(index);
        } else if (active.nextPollTimeNs > oldDeadlineNs) {
            sift_poll_deadline_down(index);
        }
    }

    void remove_poll_deadline(ActiveRead& active) {
        const uint32_t index = active.pollDeadlineHeapIndex;
        if (index == UINT32_MAX) {
            return;
        }
        if (index >= activePollDeadlineHeapSize ||
            activePollDeadlineHeap[index] != &active) {
            AMPR_CRITICAL_LOGF("apr.reactor.pollDeadline.remove.invalid slot=%u index=%u size=%u",
                               active.listSlot,
                               index,
                               activePollDeadlineHeapSize);
            std::abort();
        }

        const uint32_t lastIndex = --activePollDeadlineHeapSize;
        active.pollDeadlineHeapIndex = UINT32_MAX;
        if (index == lastIndex) {
            activePollDeadlineHeap[index] = nullptr;
            return;
        }

        ActiveRead* const replacement = activePollDeadlineHeap[lastIndex];
        if (!replacement) {
            AMPR_CRITICAL_LOGF("apr.reactor.pollDeadline.remove.replacement index=%u size=%u",
                               lastIndex,
                               activePollDeadlineHeapSize);
            std::abort();
        }
        activePollDeadlineHeap[index] = replacement;
        activePollDeadlineHeap[lastIndex] = nullptr;
        replacement->pollDeadlineHeapIndex = index;
        if (index != 0 &&
            poll_deadline_less(replacement,
                               activePollDeadlineHeap[(index - 1u) / 2u])) {
            sift_poll_deadline_up(index);
        } else {
            sift_poll_deadline_down(index);
        }
    }

    ActiveRead* first_poll_deadline_read() {
        if (activePollDeadlineHeapSize == 0) {
            return nullptr;
        }
        ActiveRead* const active = activePollDeadlineHeap[0];
        if (!active || active->pollDeadlineHeapIndex != 0) {
            AMPR_CRITICAL_LOGF("apr.reactor.pollDeadline.front.invalid read=%p index=%u size=%u",
                               active,
                               active ? active->pollDeadlineHeapIndex : UINT32_MAX,
                               activePollDeadlineHeapSize);
            std::abort();
        }
        return active;
    }

    uint64_t active_poll_deadline_ns() {
        ActiveRead* const active = first_poll_deadline_read();
        return active ? active->nextPollTimeNs : 0;
    }

    ActiveReadIt first_due_active_read(uint64_t now) {
        ActiveRead* const active = first_poll_deadline_read();
        if (!active ||
            (active->nextPollTimeNs != 0 && now < active->nextPollTimeNs)) {
            return activeReads.end();
        }
        ActiveReadIt it = activeReads.iterator_from_slot(active->listSlot);
        if (it == activeReads.end() || &*it != active) {
            AMPR_CRITICAL_LOGF("apr.reactor.pollDeadline.front.stale read=%p slot=%u generation=%u",
                               active,
                               active->listSlot,
                               active->listGeneration);
            std::abort();
        }
        return it;
    }

    ActiveReadIt erase_active_read(ActiveReadIt it) {
        if (it == activeReads.end()) {
            return activeReads.end();
        }
        if (it->activeFileCounted) {
            activeFileCounts.decrement(it->desc.fileId);
            it->activeFileCounted = false;
        }
        remove_poll_deadline(*it);
        unlink_active_read_from_job(*it);
        return activeReads.erase(it);
    }

    void link_active_read_to_job(ActiveRead& active, JobState& job) {
        const uint32_t slot = active.listSlot;
        if (slot == UINT32_MAX) {
            return;
        }
        active.job = &job;
        active.jobPrevSlot = job.activeReadTail;
        active.jobNextSlot = UINT32_MAX;
        if (job.activeReadTail != UINT32_MAX) {
            ActiveRead* tail = activeReads.active_at_slot(job.activeReadTail);
            if (tail && tail->job == &job) {
                tail->jobNextSlot = slot;
            } else {
                active.jobPrevSlot = UINT32_MAX;
                job.activeReadHead = slot;
            }
        } else {
            job.activeReadHead = slot;
        }
        job.activeReadTail = slot;
    }

    void unlink_active_read_from_job(ActiveRead& active) {
        JobPtr job = active.job;
        if (!job) {
            active.hotPollQueued = false;
            active.jobPrevSlot = UINT32_MAX;
            active.jobNextSlot = UINT32_MAX;
            return;
        }
        const uint32_t slot = active.listSlot;
        const uint32_t prevSlot = active.jobPrevSlot;
        const uint32_t nextSlot = active.jobNextSlot;
        if (job->activeReadHead == slot) {
            job->activeReadHead = nextSlot;
        }
        if (job->activeReadTail == slot) {
            job->activeReadTail = prevSlot;
        }
        if (prevSlot != UINT32_MAX) {
            ActiveRead* prev = activeReads.active_at_slot(prevSlot);
            if (prev && prev->job == job) {
                prev->jobNextSlot = nextSlot;
            }
        }
        if (nextSlot != UINT32_MAX) {
            ActiveRead* next = activeReads.active_at_slot(nextSlot);
            if (next && next->job == job) {
                next->jobPrevSlot = prevSlot;
            }
        }
        active.hotPollQueued = false;
        active.jobPrevSlot = UINT32_MAX;
        active.jobNextSlot = UINT32_MAX;
    }

    static void* worker_entry(void* arg) {
        auto* self = static_cast<AprAioReactor*>(arg);
        if (self) {
            self->worker();
        }
        return nullptr;
    }

    void notify_all_wait_domains() {
        reactorCv.notify_all();
        for (size_t lane = 0; lane < kPriorityCount; ++lane) {
            syntheticWaitCvs[lane].notify_all();
        }
    }

    bool start_worker() {
        ampr_call_once(startOnce, [this] {
            ScePthread thread{};
            const int rc = scePthreadCreate(&thread, nullptr, worker_entry, this, "ampr_apr_reactor");
            if (rc == 0) {
                workerThread = thread;
                started.store(true, std::memory_order_release);
            } else {
                AMPR_CRITICAL_LOGF("apr.reactor.thread.create.fail rc=0x%x", rc);
                {
                    AmprLockGuard lk(m);
                    stop = true;
                }
                notify_all_wait_domains();
            }
        });
        return started.load(std::memory_order_acquire);
    }

    static constexpr uint32_t kAioInitUninitialized = 0u;
    static constexpr uint32_t kAioInitInitializing = 1u;
    static constexpr uint32_t kAioInitReady = 2u;
    static constexpr uint32_t kAioInitExternalBusy = 3u;

    static constexpr uint32_t aio_active_read_limit() {
        return static_cast<uint32_t>(kMaxActiveReads);
    }

    void ensure_aio_initialized() {
        for (;;) {
            const uint32_t state = aioInitState.load(std::memory_order_acquire);
            if (state == kAioInitReady || state == kAioInitExternalBusy) {
                return;
            }
            uint32_t expected = kAioInitUninitialized;
            if (aioInitState.compare_exchange_strong(expected,
                                                     kAioInitInitializing,
                                                     std::memory_order_acq_rel,
                                                     std::memory_order_acquire)) {
                break;
            }
            uint32_t spins = 0;
            while (aioInitState.load(std::memory_order_acquire) == kAioInitInitializing) {
                ampr_spin_pause_or_yield(spins);
            }
        }

        aioInitAttemptCount.fetch_add(1u, std::memory_order_relaxed);
        const int initRc = initialize_aio_parameters();
        aioInitLastRc.store(initRc, std::memory_order_release);
        if (initRc == 0) {
            aioInitSuccessCount.fetch_add(1u, std::memory_order_relaxed);
            aioInitState.store(kAioInitReady, std::memory_order_release);
        } else if (initRc == SCE_KERNEL_ERROR_EBUSY) {
            aioInitBusyCount.fetch_add(1u, std::memory_order_relaxed);
            aioInitState.store(kAioInitExternalBusy, std::memory_order_release);
        } else {
            aioInitFailCount.fetch_add(1u, std::memory_order_relaxed);
            aioInitState.store(kAioInitUninitialized, std::memory_order_release);
        }
    }

    int initialize_aio_parameters() {
        static_assert(AMPR_EMU_APR_AIO_SDK_SCHED_HEADROOM >= 0,
                      "AMPR_EMU_APR_AIO_SDK_SCHED_HEADROOM must not be negative");

        SceKernelAioParam param{};
        sceKernelAioInitializeParam(&param);
        constexpr int kAioSchedulingWindowSize =
            kMaxActiveReads < SCE_KERNEL_AIO_SCHED_WINDOW_MAX
                ? static_cast<int>(kMaxActiveReads)
                : SCE_KERNEL_AIO_SCHED_WINDOW_MAX;
        constexpr int kAioDelayedCountLimit =
            kMaxActiveReads < SCE_KERNEL_AIO_DELAYED_COUNT_MAX
                ? static_cast<int>(kMaxActiveReads)
                : SCE_KERNEL_AIO_DELAYED_COUNT_MAX;
        constexpr int kAioSchedulingHeadroomLimit =
            SCE_KERNEL_AIO_SCHED_WINDOW_MAX - kAioSchedulingWindowSize;
        constexpr int kAioDelayedHeadroomLimit =
            SCE_KERNEL_AIO_DELAYED_COUNT_MAX - kAioDelayedCountLimit;
        constexpr int kAioSchedulingHeadroom =
            AMPR_EMU_APR_AIO_SDK_SCHED_HEADROOM < kAioSchedulingHeadroomLimit
                ? AMPR_EMU_APR_AIO_SDK_SCHED_HEADROOM
                : kAioSchedulingHeadroomLimit;
        constexpr int kAioDelayedHeadroom =
            AMPR_EMU_APR_AIO_SDK_SCHED_HEADROOM < kAioDelayedHeadroomLimit
                ? AMPR_EMU_APR_AIO_SDK_SCHED_HEADROOM
                : kAioDelayedHeadroomLimit;
        constexpr int kAioSchedulingWindowWithHeadroom =
            kAioSchedulingWindowSize + kAioSchedulingHeadroom;
        constexpr int kAioDelayedCountWithHeadroom =
            kAioDelayedCountLimit + kAioDelayedHeadroom;
        static_assert(kAioSchedulingWindowWithHeadroom <= SCE_KERNEL_AIO_SCHED_WINDOW_MAX,
                      "APR AIO scheduler window plus headroom exceeds SDK maximum");
        static_assert(kAioDelayedCountWithHeadroom <= SCE_KERNEL_AIO_DELAYED_COUNT_MAX,
                      "APR AIO delayed count plus headroom exceeds SDK maximum");
        const auto setParam = [](SceKernelAioSchedulingParam* sched) {
            return sceKernelAioSetParam(sched,
                                        kAioSchedulingWindowWithHeadroom,
                                        kAioDelayedCountWithHeadroom,
                                        SCE_KERNEL_AIO_DISABLE_SPLIT,
                                        SCE_KERNEL_AIO_SPLIT_SIZE_DEFAULT,
                                        SCE_KERNEL_AIO_SPLIT_CHUNK_SIZE_DEFAULT);
        };
        const int lowRc = setParam(&param.low);
        const int midRc = setParam(&param.mid);
        const int highRc = setParam(&param.high);
        if (lowRc != 0 || midRc != 0 || highRc != 0) {
            AMPR_CRITICAL_LOGF("apr.reactor.aio.initParam.fail lowRc=0x%x midRc=0x%x highRc=0x%x split=0 quantum=0x%x",
                      lowRc,
                      midRc,
                      highRc,
                      (unsigned)AMPR_EMU_APR_AIO_DISPATCH_QUANTUM_BYTES);
            return lowRc != 0 ? lowRc : (midRc != 0 ? midRc : highRc);
        }

        const int initRc = sceKernelAioInitialize(&param);
        if (initRc == 0) {
            AMPR_LOGF("apr.reactor.aio.init rc=0x0 window=%d delayed=%d headroomRequested=%d headroomWindow=%d headroomDelayed=%d splitLowMidHigh=0 quantum=0x%x",
                      kAioSchedulingWindowWithHeadroom,
                      kAioDelayedCountWithHeadroom,
                      (int)AMPR_EMU_APR_AIO_SDK_SCHED_HEADROOM,
                      kAioSchedulingHeadroom,
                      kAioDelayedHeadroom,
                      (unsigned)AMPR_EMU_APR_AIO_DISPATCH_QUANTUM_BYTES);
        } else if (initRc == SCE_KERNEL_ERROR_EBUSY) {
            AMPR_LOGF("apr.reactor.aio.init.already rc=0x%x split=unmodified activeReads=%u",
                      initRc,
                      (unsigned)kMaxActiveReads);
        } else {
            AMPR_CRITICAL_LOGF("apr.reactor.aio.init.fail rc=0x%x split=0 quantum=0x%x",
                      initRc,
                      (unsigned)AMPR_EMU_APR_AIO_DISPATCH_QUANTUM_BYTES);
        }
        return initRc;
    }

    void note_aio_submit_result(int sceRc) {
        if (sceRc == SCE_KERNEL_ERROR_EAGAIN) {
            aioSubmitEagainCount.fetch_add(1u, std::memory_order_relaxed);
        }
    }

    void configure_worker_thread() {
        ScePthread self = scePthreadSelf();
        (void)scePthreadRename(self, "ampr_apr_reactor");
#if AMPR_EMU_APR_REACTOR_THREAD_PRIORITY != 0
        int oldPrio = -1;
        const int getRc = scePthreadGetprio(self, &oldPrio);
        const int configuredPrio = (int)AMPR_EMU_APR_REACTOR_THREAD_PRIORITY;
        const int clampedPrio = configuredPrio < SCE_KERNEL_PRIO_FIFO_HIGHEST
            ? SCE_KERNEL_PRIO_FIFO_HIGHEST
            : (configuredPrio > SCE_KERNEL_PRIO_FIFO_LOWEST
                   ? SCE_KERNEL_PRIO_FIFO_LOWEST
                   : configuredPrio);
        const int targetPrio =
            getRc == 0 && oldPrio >= SCE_KERNEL_PRIO_FIFO_HIGHEST &&
                    oldPrio <= SCE_KERNEL_PRIO_FIFO_LOWEST && oldPrio < clampedPrio
                ? oldPrio
                : clampedPrio;
        int setRc = 0;
        if (getRc != 0 || oldPrio != targetPrio) {
            setRc = scePthreadSetprio(self, targetPrio);
        }
        int newPrio = -1;
        const int verifyRc = scePthreadGetprio(self, &newPrio);
        (void)getRc;
        (void)setRc;
        (void)verifyRc;
        AMPR_LOGF("apr.reactor.thread priority getRc=0x%x old=%d setRc=0x%x configured=%d clamped=%d target=%d verifyRc=0x%x new=%d",
                  getRc,
                  oldPrio,
                  setRc,
                  configuredPrio,
                  clampedPrio,
                  targetPrio,
                  verifyRc,
                  newPrio);
#endif
#if AMPR_EMU_APR_REACTOR_THREAD_AFFINITY != 0
        const SceKernelCpumask mask = (SceKernelCpumask)AMPR_EMU_APR_REACTOR_THREAD_AFFINITY;
        const int affinityRc = scePthreadSetaffinity(self, mask);
        (void)affinityRc;
        AMPR_LOGF("apr.reactor.thread affinity rc=0x%x mask=0x%llx",
                  affinityRc,
                  (unsigned long long)mask);
#endif
    }

    size_t active_lane_count_locked() const {
        return activeJobCountAtomic.load(std::memory_order_relaxed);
    }

    bool has_active_lanes_locked() const {
        return activeJobCountAtomic.load(std::memory_order_relaxed) != 0;
    }

    JobPtr first_active_job_locked() {
        AmprLockGuard lk(m);
        for (JobPtr job = activeJobHead; job; job = job->activeNext) {
            if (job) {
                return job;
            }
        }
        return {};
    }

    bool add_active_job_locked(JobState* job) {
        if (!job || job->activeListed || job->prioIndex >= kPriorityCount) {
            return false;
        }
        job->activePrev = activeJobTail;
        job->activeNext = nullptr;
        if (activeJobTail) {
            activeJobTail->activeNext = job;
        } else {
            activeJobHead = job;
        }
        activeJobTail = job;
        JobPtr& priorityTail = activePriorityTails[job->prioIndex];
        job->priorityPrev = priorityTail;
        job->priorityNext.store(nullptr, std::memory_order_relaxed);
        if (priorityTail) {
            priorityTail->priorityNext.store(job, std::memory_order_release);
        } else {
            activePriorityHeads[job->prioIndex] = job;
        }
        priorityTail = job;
        job->activeListed = true;
        activeJobCountAtomic.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    bool erase_active_job_locked(JobState* job) {
        if (!job || !job->activeListed) {
            if (job) {
                job->activeListed = false;
                job->activePrev = nullptr;
                job->activeNext = nullptr;
                job->priorityPrev = nullptr;
                job->priorityNext.store(nullptr, std::memory_order_relaxed);
            }
            return false;
        }
        if (job->activePrev) {
            job->activePrev->activeNext = job->activeNext;
        } else {
            activeJobHead = job->activeNext;
        }
        if (job->activeNext) {
            job->activeNext->activePrev = job->activePrev;
        } else {
            activeJobTail = job->activePrev;
        }
        JobPtr& priorityHead = activePriorityHeads[job->prioIndex];
        JobPtr& priorityTail = activePriorityTails[job->prioIndex];
        JobPtr const priorityNext =
            job->priorityNext.load(std::memory_order_acquire);
        if (job->priorityPrev) {
            job->priorityPrev->priorityNext.store(priorityNext,
                                                  std::memory_order_release);
        } else {
            priorityHead = priorityNext;
        }
        if (priorityNext) {
            priorityNext->priorityPrev = job->priorityPrev;
        } else {
            priorityTail = job->priorityPrev;
        }
        job->activeListed = false;
        job->activePrev = nullptr;
        job->activeNext = nullptr;
        job->priorityPrev = nullptr;
        job->priorityNext.store(nullptr, std::memory_order_relaxed);
        activeJobCountAtomic.fetch_sub(1, std::memory_order_relaxed);
        return true;
    }

    static SceAprSubmitId make_synthetic_submit_id(uint32_t slot, uint32_t generation) {
        return static_cast<SceAprSubmitId>(
            kSyntheticSubmitIdTag |
            ((generation << kSyntheticSubmitIdGenerationShift) &
             kSyntheticSubmitIdGenerationMask) |
            (slot & kSyntheticSubmitIdSlotMask));
    }

    static bool decode_synthetic_submit_id(SceAprSubmitId id,
                                           uint32_t* outSlot,
                                           uint32_t* outGeneration) {
        const uint32_t raw = static_cast<uint32_t>(id);
        if ((raw & kSyntheticSubmitIdTagMask) != kSyntheticSubmitIdTag) {
            return false;
        }
        const uint32_t slot = raw & kSyntheticSubmitIdSlotMask;
        const uint32_t generation =
            (raw & kSyntheticSubmitIdGenerationMask) >> kSyntheticSubmitIdGenerationShift;
        if (slot >= kSyntheticWaitSlotCapacity || generation == 0) {
            return false;
        }
        if (outSlot) {
            *outSlot = slot;
        }
        if (outGeneration) {
            *outGeneration = generation;
        }
        return true;
    }

    bool allocate_synthetic_wait_slot_locked(JobState& job, SceAprSubmitId* outId) {
        if (!outId) {
            return true;
        }
        constexpr uint32_t generationMax =
            kSyntheticSubmitIdGenerationMask >> kSyntheticSubmitIdGenerationShift;
        for (uint32_t attempt = 0; attempt < kSyntheticWaitSlotCapacity; ++attempt) {
            const uint32_t slot =
                (syntheticWaitAllocCursor + attempt) % kSyntheticWaitSlotCapacity;
            SyntheticWaitSlot& waitSlot = syntheticWaitSlots[slot];
            if (waitSlot.active) {
                continue;
            }
            uint32_t generation = waitSlot.generation + 1u;
            if (generation == 0 || generation > generationMax) {
                generation = 1u;
            }
            waitSlot.generation = generation;
            waitSlot.result = 0;
            waitSlot.prioIndex = job.prioIndex;
            waitSlot.done = false;
            waitSlot.active = true;
            job.syntheticSubmitId = make_synthetic_submit_id(slot, generation);
            job.syntheticWaitSlot = slot;
            job.syntheticWaitGeneration = generation;
            job.syntheticWaitPublished = false;
            syntheticWaitAllocCursor = (slot + 1u) % kSyntheticWaitSlotCapacity;
            *outId = job.syntheticSubmitId;
            return true;
        }
        AMPR_CRITICAL_LOGF("apr.reactor.synthetic.submitId.pool.full job=0x%llx capacity=%u",
                          (unsigned long long)job.id,
                          (unsigned)kSyntheticWaitSlotCapacity);
        return false;
    }

    void release_unpublished_synthetic_wait_slot_locked(JobState& job) {
        if (job.syntheticWaitSlot == UINT32_MAX || job.syntheticWaitPublished) {
            return;
        }
        SyntheticWaitSlot& waitSlot = syntheticWaitSlots[job.syntheticWaitSlot];
        if (waitSlot.active && waitSlot.generation == job.syntheticWaitGeneration) {
            waitSlot.active = false;
            waitSlot.done = false;
            waitSlot.result = 0;
            waitSlot.prioIndex = 0;
        }
        job.syntheticSubmitId = 0;
        job.syntheticWaitSlot = UINT32_MAX;
        job.syntheticWaitGeneration = 0;
    }

    void publish_synthetic_wait_completion(JobState& job) {
        if (!job.syntheticWaitPublished ||
            job.syntheticWaitSlot >= kSyntheticWaitSlotCapacity) {
            return;
        }
        {
            AmprLockGuard lk(m);
            SyntheticWaitSlot& waitSlot = syntheticWaitSlots[job.syntheticWaitSlot];
            if (!waitSlot.active || waitSlot.generation != job.syntheticWaitGeneration) {
                return;
            }
            // Native command errors stay in SceAprResultBuffer when the caller
            // requested one. Infrastructure failures and result-less submits
            // must remain observable through the synthetic wait itself.
            waitSlot.result = job_failed(job) && (!job.hasCommandError || !job.aprRes)
                ? job.result.rc
                : 0;
            waitSlot.done = true;
        }
        syntheticWaitCvs[job.prioIndex].notify_all();
    }

    static bool job_processing_complete(const JobState& job) {
        return job.processingComplete;
    }

    static uint32_t job_commands_for_log(const JobState& job) {
        return job.commandCount;
    }

    static size_t job_op_index_for_log(const JobState& job) {
        return static_cast<size_t>(job.sourceCommandIndex);
    }

    static bool job_failed(const JobState& job) {
        return job.failed.load(std::memory_order_acquire);
    }

    static bool job_has_outstanding_reads(const JobState& job) {
        return job.pendingReadCount != 0 ||
               job.activeReadCount != 0 ||
               job.latestSubmittedReadSeq != job.completedReadSeq;
    }

    static void clear_decoded_op(JobState& job) {
        job.decodedOpCacheBytes = 0;
    }

    static void cache_decoded_op(JobState& job, const Op& op, uint32_t opBytes) {
        if (&op != &job.decodedOpCache) {
            job.decodedOpCache = op;
        }
        job.decodedOpCacheBytes = opBytes;
    }

#if AMPR_EMU_APR_AIO_CROSS_EOP_READAHEAD
    static bool cross_eop_scan_reached_job_end(const JobState& job) {
        return job.crossEopScanActive &&
               job.crossEopDeferredErrorOffset == UINT32_MAX &&
               job.crossEopScanOffset == job.sourceBytes &&
               job.crossEopScanCommandIndex == job.commandCount;
    }

    static uint64_t cross_eop_read_fence_for_cursor(const JobState& job) {
        return job.crossEopFenceCount != 0 &&
                       job.crossEopFenceSourceOffsets[
                           job.crossEopFenceHead] == job.sourceOffset
            ? job.crossEopFenceReadSequences[job.crossEopFenceHead]
            : job.latestSubmittedReadSeq;
    }

    static bool push_cross_eop_fence(JobState& job,
                                     uint32_t sourceOffset,
                                     uint64_t readSequence) {
        if (job.crossEopFenceCount >=
            AMPR_EMU_APR_AIO_CROSS_EOP_MAX_FENCES) {
            return false;
        }
        const uint32_t tail =
            (job.crossEopFenceHead + job.crossEopFenceCount) %
            AMPR_EMU_APR_AIO_CROSS_EOP_MAX_FENCES;
        job.crossEopFenceSourceOffsets[tail] = sourceOffset;
        job.crossEopFenceReadSequences[tail] = readSequence;
        ++job.crossEopFenceCount;
        return true;
    }

    static void consume_cross_eop_fence_at_cursor(JobState& job) {
        if (job.crossEopFenceCount == 0 ||
            job.crossEopFenceSourceOffsets[job.crossEopFenceHead] !=
                job.sourceOffset) {
            return;
        }
        job.crossEopFenceHead =
            (job.crossEopFenceHead + 1u) %
            AMPR_EMU_APR_AIO_CROSS_EOP_MAX_FENCES;
        --job.crossEopFenceCount;
    }
#endif

    static void advance_job_source(JobState& job, uint32_t opBytes) {
#if AMPR_EMU_APR_AIO_CROSS_EOP_READAHEAD
        consume_cross_eop_fence_at_cursor(job);
#endif
        job.sourceOffset += opBytes;
        ++job.sourceCommandIndex;
        clear_decoded_op(job);
    }

    static bool job_allows_priority_successor(const JobState& job,
                                              bool nativeSubmitted) {
        bool sourceIssued = job.sourceOffset == job.sourceBytes;
#if AMPR_EMU_APR_AIO_CROSS_EOP_READAHEAD
        sourceIssued = sourceIssued ||
            cross_eop_scan_reached_job_end(job);
#endif
        if (job_failed(job) || !sourceIssued) {
            return false;
        }
        if (nativeSubmitted &&
            job.nativeMicroEngine != NativeMicroEngine::AprBatch) {
            return false;
        }
        if (job.sourceOffset != job.sourceBytes) {
            return true;
        }
        return job_has_outstanding_reads(job) || job_processing_complete(job);
    }

    static bool decode_first_native_op_const(const JobState& job,
                                             Op* outOp,
                                             uint32_t* outBytes = nullptr) {
        if (!job.nativeCommandBuffer || job.nativeSubmitBytes == 0) {
            return false;
        }
        uint32_t errorOffset = 0;
        return ::sce::Ampr::ampr_decode_packed_op(job.nativeCommandBuffer,
                                                  job.nativeSubmitBytes,
                                                  0,
                                                  outOp,
                                                  outBytes,
                                                  &errorOffset) == 0;
    }

    static void finish_job_processing(JobState& job) {
        clear_decoded_op(job);
        job.processingComplete = true;
    }

    bool initialize_native_batch_pool_storage() {
        for (uint32_t words = 1;
             words <= kAprNativeBatchPaddingHeaderCount;
             ++words) {
            uint8_t encodedNop[20]{};
            SceAmprCommandBuffer nopView{};
            nopView.buffer = encodedNop;
            nopView.bufsize = sizeof(encodedNop);
            Op nop{};
            nop.type = OpType::Nop;
            nop.u32a = words;
            const uint32_t bytes = words * 4u;
            if (sce::Ampr::ampr_strict_write_op(
                    &nopView, 0, nop, bytes) != 0) {
                AMPR_CRITICAL_LOGF("apr.reactor.native.batch.padding-template.fail bytes=0x%x",
                                   bytes);
                return false;
            }
            std::memcpy(&nativeBatchPaddingHeaders[words - 1u],
                        encodedNop,
                        sizeof(uint32_t));
        }

        for (uint32_t lane = 0; lane < kPriorityCount; ++lane) {
            for (uint32_t bufferIndex = 0;
                 bufferIndex < kAprNativeBatchBufferCountPerLane;
                 ++bufferIndex) {
                AprNativeBatchSlot* const slot =
                    apr_native_batch_slot(lane, bufferIndex);
                if (!slot) {
                    return false;
                }
                std::memset(slot, 0, sizeof(*slot));
                SceAmprCommandBuffer payloadView{};
                payloadView.buffer = slot->defaultPayload;
                payloadView.bufsize = sizeof(slot->defaultPayload);

                Op nop4{};
                nop4.type = OpType::Nop;
                nop4.u32a = 1u;
                Op nop20 = nop4;
                nop20.u32a = 5u;
                int payloadRc = 0;
                for (uint32_t packet = 0;
                     packet < kAprNativeBatchPacketsPerGroup;
                     ++packet) {
                    const uint32_t payloadOffset =
                        packet * kAprNativeBatchPayloadSlotBytes;
                    payloadRc |= sce::Ampr::ampr_strict_write_op(
                        &payloadView, payloadOffset, nop4, 4u);
                    payloadRc |= sce::Ampr::ampr_strict_write_op(
                        &payloadView, payloadOffset + 4u, nop20, 20u);
                }
                if (payloadRc != 0) {
                    AMPR_CRITICAL_LOGF("apr.reactor.native.batch.template.fail lane=%u buffer=%u payloadRc=0x%x",
                                       lane,
                                       bufferIndex,
                                       payloadRc);
                    return false;
                }
                for (uint32_t group = 0; group < kAprNativeBatchGroupCount;
                     ++group) {
                    const uint32_t groupOffset =
                        group * kAprNativeBatchGroupBytes;
                    std::memcpy(
                        slot->commands + groupOffset +
                            kAprNativeBatchGateBytes,
                        slot->defaultPayload,
                        kAprNativeBatchPayloadRegionBytes);
                    Op gate{};
                    gate.type = OpType::WaitOnAddress;
                    gate.ptra = const_cast<uint64_t*>(&slot->release);
                    gate.u64a = apr_native_batch_token(group);
                    gate.u32a = static_cast<uint32_t>(
                        sce::Ampr::WaitCompare::kGreaterThanOrEqualWrapped);
                    gate.u32c = static_cast<uint32_t>(
                        sce::Ampr::WaitFlush::kEnable);
                    SceAmprCommandBuffer commandsView{};
                    commandsView.buffer = slot->commands;
                    commandsView.bufsize = sizeof(slot->commands);
                    const int gateRc = sce::Ampr::ampr_strict_write_op(
                        &commandsView,
                        groupOffset,
                        gate,
                        kAprNativeBatchGateBytes);
                    Op checkpoint{};
                    checkpoint.type = OpType::WriteAddress;
                    checkpoint.ptra = const_cast<uint64_t*>(&slot->progress);
                    checkpoint.u64a = apr_native_batch_token(group);
                    checkpoint.u8a = 0;
                    const int checkpointRc = sce::Ampr::ampr_strict_write_op(
                        &commandsView,
                        groupOffset + kAprNativeBatchGateBytes +
                            kAprNativeBatchPayloadRegionBytes,
                        checkpoint,
                        kAprNativeBatchCheckpointBytes);
                    if (gateRc != 0 || checkpointRc != 0) {
                        AMPR_CRITICAL_LOGF("apr.reactor.native.batch.group-template.fail lane=%u buffer=%u group=%u gateRc=0x%x checkpointRc=0x%x",
                                           lane,
                                           bufferIndex,
                                           group,
                                           gateRc,
                                           checkpointRc);
                        return false;
                    }
                }
                slot->result.result = kAprNativeBatchResultPending;
            }
        }
        return true;
    }

    bool ensure_native_execution_pool() {
        for (;;) {
            bool shouldInit = false;
            {
                AmprSpinLock lock(&nativeExecutionPoolLock);
                if (nativeExecutionPoolReady) {
                    return true;
                }
                if (!nativeExecutionPoolInitAttempted) {
                    nativeExecutionPoolInitAttempted = true;
                    shouldInit = true;
                }
            }
            if (shouldInit) {
                break;
            }
            timespec ts{0, 1000000};
            (void)::sceKernelNanosleep(&ts, nullptr);
        }

        constexpr int kNativeMicroProt =
            SCE_KERNEL_PROT_CPU_RW | SCE_KERNEL_PROT_AMPR_ALL;
        const int microProtectRc = ampr_real_sceKernelMprotect(
            g_apr_native_micro_pool,
            kAprNativeMicroPoolBytes,
            kNativeMicroProt);
        if (microProtectRc != 0) {
            AMPR_CRITICAL_LOGF("apr.reactor.native.micro.protect.fail rc=0x%x ptr=%p size=0x%llx prot=0x%x",
                               microProtectRc,
                               g_apr_native_micro_pool,
                               (unsigned long long)kAprNativeMicroPoolBytes,
                               kNativeMicroProt);
            AmprSpinLock lock(&nativeExecutionPoolLock);
            nativeExecutionPoolInitAttempted = false;
            return false;
        }

        const int batchProtectRc = ampr_real_sceKernelMprotect(
            g_apr_native_batch_pool,
            kAprNativeBatchPoolBytes,
            kNativeMicroProt);
        if (batchProtectRc != 0) {
            AMPR_CRITICAL_LOGF("apr.reactor.native.batch.protect.fail rc=0x%x ptr=%p size=0x%llx prot=0x%x",
                               batchProtectRc,
                               g_apr_native_batch_pool,
                               (unsigned long long)kAprNativeBatchPoolBytes,
                               kNativeMicroProt);
            AmprSpinLock lock(&nativeExecutionPoolLock);
            nativeExecutionPoolInitAttempted = false;
            return false;
        }

        std::memset(g_apr_native_micro_pool, 0, kAprNativeMicroPoolBytes);
        if (!initialize_native_batch_pool_storage()) {
            AmprSpinLock lock(&nativeExecutionPoolLock);
            nativeExecutionPoolInitAttempted = false;
            return false;
        }

        {
            AmprSpinLock lock(&nativeExecutionPoolLock);
            nativeExecutionPoolReady = true;
        }
        AMPR_VLOGF("apr.reactor.native.pool.ready microBase=%p microBytes=0x%llx microSlots=%u batchBase=%p batchBytes=0x%llx batchSlots=%u batchBlocks=%u prot=0x%x microTemplates=lazy",
                   g_apr_native_micro_pool,
                   (unsigned long long)kAprNativeMicroPoolBytes,
                   (unsigned)kJobStatePoolCapacity,
                   g_apr_native_batch_pool,
                   (unsigned long long)kAprNativeBatchPoolBytes,
                   (unsigned)kAprNativeBatchSlotCount,
                   (unsigned)kAprNativeBatchGroupCount,
                   kNativeMicroProt);
        return true;
    }

    bool ensure_native_micro_slot(JobState& job, uint32_t errorOffset) {
        if (!ensure_native_execution_pool()) {
            set_fail(job, "native-micro-pool", SCE_KERNEL_ERROR_ENOMEM, errorOffset);
            return false;
        }
        const uint32_t slotIndex = job.poolSlot;
        AprNativeMicroSlot* const slot = apr_native_micro_slot(slotIndex);
        if (!slot || slotIndex >= kJobStatePoolCapacity) {
            set_fail(job, "native-micro-slot", SCE_KERNEL_ERROR_EINVAL, errorOffset);
            return false;
        }
        if (!nativeMicroTemplateReady[slotIndex]) {
            Op completion{};
            completion.type = OpType::WriteAddress;
            completion.ptra = const_cast<uint64_t*>(&slot->completion);
            completion.u64a = kAprNativeMicroCompletionDone;
            completion.u8a = 0;
            uint32_t completionBytes = 0;
            const int sizeRc = sce::Ampr::ampr_op_size_bytes_checked(
                completion,
                &completionBytes);
            if (sizeRc != 0 || completionBytes != kAprNativeMicroCompletionBytes) {
                AMPR_CRITICAL_LOGF("apr.reactor.native.micro.template.fail slot=%u reason=size rc=0x%x bytes=0x%x",
                                   slotIndex,
                                   sizeRc,
                                   completionBytes);
                set_fail(job,
                         "native-micro-template",
                         sizeRc != 0 ? sizeRc : SCE_KERNEL_ERROR_EINVAL,
                         errorOffset);
                return false;
            }
            SceAmprCommandBuffer view{};
            view.buffer = slot->completionTemplate;
            view.bufsize = kAprNativeMicroCompletionBytes;
            const int writeRc = sce::Ampr::ampr_strict_write_op(
                &view,
                0,
                completion,
                completionBytes);
            if (writeRc != 0) {
                AMPR_CRITICAL_LOGF("apr.reactor.native.micro.template.fail slot=%u reason=encode rc=0x%x",
                                   slotIndex,
                                   writeRc);
                set_fail(job, "native-micro-template", writeRc, errorOffset);
                return false;
            }
            nativeMicroTemplateReady[slotIndex] = true;
            AMPR_VLOGF("apr.reactor.native.micro.template.ready slot=%u completion=%p",
                       slotIndex,
                       (void*)const_cast<uint64_t*>(&slot->completion));
        }
        job.nativeCommandBuffer = slot->commands;
        job.nativeCommandBufferBytes = kAprNativeMicroCommandCapacity;
        job.nativeCompletionAddress = &slot->completion;
        return true;
    }

    void dec_pending_read_total(size_t count) {
        if (count == 0) {
            return;
        }
        pendingReadTotalAtomic.fetch_sub(count, std::memory_order_relaxed);
    }

    void requeue_pending_read_front(size_t priority,
                                    JobPtr job,
                                    AprAioReadDesc&& desc,
                                    ReadChain* chain,
                                    uint64_t seq,
                                    size_t commandIndex,
                                    uint32_t ammEfaultRetries = 0,
                                    uint64_t notBeforeNs = 0,
                                    uint32_t aioCompletionRetries = 0,
                                    bool retrySlice = false
#if AMPR_EMU_DEBUG_LOG
                                    ,
                                    uint64_t nativeTriggerTimeNs = 0,
                                    uint64_t pendingEnqueueTimeNs = 0
#endif
                                    ) {
        priority = apr_clamp_priority_index(priority);
        JobPtr pendingJob = job;
        PendingRead pending{};
        pending.job = pendingJob;
        pending.desc = ampr_move(desc);
        pending.chain = chain;
        pending.seq = seq;
        pending.commandIndex = commandIndex;
        pending.ammEfaultRetries = ammEfaultRetries;
        pending.aioCompletionRetries = aioCompletionRetries;
        pending.notBeforeNs = notBeforeNs;
        pending.retrySlice = retrySlice;
#if AMPR_EMU_DEBUG_LOG
        pending.nativeTriggerTimeNs = nativeTriggerTimeNs;
        pending.pendingEnqueueTimeNs =
            pendingEnqueueTimeNs != 0 ? pendingEnqueueTimeNs : time_counter_now();
#endif
        PendingReadQueue& lane = pending_read_lane(priority);
        if (!lane.push_front(ampr_move(pending))) {
            const uint32_t errorOff = pending.desc.errorOff;
            AMPR_CRITICAL_LOGF("apr.reactor.pendingRead.pool.full action=requeue prio=%zu job=0x%llx seq=0x%llx fileId=%u pendingReads=%zu activeReads=%zu free=%u capacity=%u",
                              priority,
                              pendingJob ? (unsigned long long)pendingJob->id : 0ull,
                              (unsigned long long)seq,
                              pending.desc.fileId,
                              pending_read_total(),
                              activeReads.size(),
                              pendingReadFree.count,
                              (unsigned)kPendingReadQueueCapacity);
            ampr_debug_int3_trap();
            if (pendingJob) {
                decrement_pending_read_count(pendingJob);
                decrement_read_chain_pending(chain);
                set_command_error(*pendingJob,
                                  "pending-read-pool-full",
                                  apr_backend_read_error_to_apr(SCE_KERNEL_ERROR_ENOMEM),
                                  errorOff);
            }
            maybe_finish_read_chain(chain);
            return;
        }
        const size_t total = pendingReadTotalAtomic.fetch_add(1, std::memory_order_relaxed) + 1u;
        note_pending_read_peak(total);
    }

    bool queue_pending_read(size_t priority, PendingRead&& pending) {
        priority = apr_clamp_priority_index(priority);
#if AMPR_EMU_DEBUG_LOG
        if (pending.pendingEnqueueTimeNs == 0) {
            pending.pendingEnqueueTimeNs = time_counter_now();
        }
#endif
        PendingReadQueue& lane = pending_read_lane(priority);
        if (!lane.push_back(ampr_move(pending))) {
            const uint32_t errorOff = pending.desc.errorOff;
            AMPR_CRITICAL_LOGF("apr.reactor.pendingRead.pool.full action=queue prio=%zu job=0x%llx seq=0x%llx fileId=%u pendingReads=%zu activeReads=%zu free=%u capacity=%u",
                              priority,
                              pending.job ? (unsigned long long)pending.job->id : 0ull,
                              (unsigned long long)pending.seq,
                              pending.desc.fileId,
                              pending_read_total(),
                              activeReads.size(),
                              pendingReadFree.count,
                              (unsigned)kPendingReadQueueCapacity);
            ampr_debug_int3_trap();
            if (pending.job) {
                set_command_error(*pending.job,
                                  "pending-read-pool-full",
                                  apr_backend_read_error_to_apr(SCE_KERNEL_ERROR_ENOMEM),
                                  errorOff);
            }
            return false;
        }
        const size_t total = pendingReadTotalAtomic.fetch_add(1, std::memory_order_relaxed) + 1u;
        note_pending_read_peak(total);
        return true;
    }

    bool drop_pending_read(PendingReadQueue& lane, PendingReadQueue::iterator it) {
        if (it == lane.end()) {
            return false;
        }
        PendingRead pending = ampr_move(*it);
        (void)lane.erase(it);
        dec_pending_read_total(1);
        ReadChain* const chain = pending.chain;
        JobPtr ownerJob = chain && chain->job ? chain->job : pending.job;
        const bool invalidOwner = !chain || !pending.job || chain->job != pending.job;
        decrement_pending_read_count(ownerJob);
        decrement_read_chain_pending(chain);
        if (invalidOwner && ownerJob && !job_failed(*ownerJob)) {
            set_command_error(*ownerJob,
                              "pending-read-owner",
                              SCE_KERNEL_ERROR_EINVAL,
                              pending.desc.errorOff);
        }
        maybe_finish_read_chain(chain);
        maybe_release_reactor_job(ownerJob);
        return true;
    }

    static uint64_t idle_wait_timeout_ns() {
        uint64_t waitNs = 0;
#if AMPR_EMU_FD_CACHE_IDLE_CLOSE_NS != 0
        waitNs = AMPR_EMU_FD_CACHE_IDLE_SCAN_NS != 0
            ? AMPR_EMU_FD_CACHE_IDLE_SCAN_NS
            : AMPR_EMU_FD_CACHE_IDLE_CLOSE_NS;
#endif
#if AMPR_EMU_DEBUG_LOG && AMPR_EMU_APR_REACTOR_HEARTBEAT_MS != 0
        const uint64_t heartbeatWaitNs =
            static_cast<uint64_t>(AMPR_EMU_APR_REACTOR_HEARTBEAT_MS) * 1000000ull;
        if (heartbeatWaitNs != 0 && (waitNs == 0 || heartbeatWaitNs < waitNs)) {
            waitNs = heartbeatWaitNs;
        }
#endif
        return waitNs;
    }

    void maybe_release_stale_fds(bool beforeIdleWait) {
#if AMPR_EMU_FD_CACHE_IDLE_CLOSE_NS != 0
        if (!beforeIdleWait &&
            ++fdCacheMaintenanceBusyLoops < kFdCacheMaintenanceBusyStride) {
            return;
        }
        fdCacheMaintenanceBusyLoops = 0;

        const uint64_t nowNs = time_counter_now();
        if (nowNs == 0) {
            return;
        }
        const uint64_t maxDeadline = (std::numeric_limits<uint64_t>::max)();
        const uint64_t deadline = nowNs <= maxDeadline - kFdCacheMaintenanceIntervalNs
            ? nowNs + kFdCacheMaintenanceIntervalNs
            : maxDeadline;
        if (nextFdCacheMaintenanceNs == 0) {
            nextFdCacheMaintenanceNs = deadline;
            return;
        }
        if (nowNs < nextFdCacheMaintenanceNs) {
            return;
        }

        (void)ampr_index_fd_cache_release_stale(nowNs);
        nextFdCacheMaintenanceNs = deadline;
#else
        (void)beforeIdleWait;
#endif
    }

    void drain_incoming(bool waitIfIdle) {
        AmprUniqueLock lk(m);
        if (waitIfIdle) {
            if (!stop &&
                !shutdownRequested.load(std::memory_order_acquire) &&
                !has_active_lanes_locked() &&
                activeReads.empty() && !has_pending_reads()) {
                const uint64_t idleWaitNs = idle_wait_timeout_ns();
                if (idleWaitNs != 0) {
                    reactorCv.wait_for(lk, std::chrono::nanoseconds(idleWaitNs));
                } else {
                    reactorCv.wait(lk, [&] {
                        return stop ||
                               shutdownRequested.load(std::memory_order_acquire) ||
                               has_active_lanes_locked() ||
                               !activeReads.empty() || has_pending_reads();
                    });
                }
#if AMPR_EMU_DEBUG_LOG
                note_worker_wakeup();
#endif
            }
        }
    }

    bool has_pending_reads() const {
        return pending_read_total() != 0;
    }

    size_t pending_read_total() const {
        return pendingReadTotalAtomic.load(std::memory_order_relaxed);
    }

    static uint64_t active_read_age_ms(const ActiveRead& active, uint64_t now) {
        return active.submitTimeNs != 0 && now >= active.submitTimeNs
                   ? (now - active.submitTimeNs) / 1000000ull
                   : 0;
    }

#if AMPR_EMU_DEBUG_LOG
    static bool collect_log_stats() {
        return ::ampr_debug_log_runtime_enabled();
    }

    static void note_log_peak(uint64_t& peak, uint64_t value) {
        if (value > peak && collect_log_stats()) {
            peak = value;
        }
    }

    static void note_log_counter(uint64_t& counter) {
        if (collect_log_stats()) {
            ++counter;
        }
    }
#endif

    void note_pending_read_peak(size_t total) {
#if AMPR_EMU_DEBUG_LOG
        note_log_peak(runtimePeakPendingReads, static_cast<uint64_t>(total));
#else
        (void)total;
#endif
    }

    void note_active_read_peak(size_t total) {
#if AMPR_EMU_DEBUG_LOG
        note_log_peak(runtimePeakActiveReads, static_cast<uint64_t>(total));
#else
        (void)total;
#endif
    }

    void note_aio_age_ms(uint64_t ageMs) {
#if AMPR_EMU_DEBUG_LOG
        note_log_peak(runtimeMaxAioAgeMs, ageMs);
#else
        (void)ageMs;
#endif
    }

#if AMPR_EMU_DEBUG_LOG
    static constexpr size_t kLatencyHistogramBuckets = 32;

    struct LatencyHistogram {
        uint64_t count{};
        uint64_t totalUs{};
        uint64_t maxUs{};
        uint64_t buckets[kLatencyHistogramBuckets]{};
    };

    static uint64_t latency_ns_to_us(uint64_t ns) {
        return (ns + 999ull) / 1000ull;
    }

    static size_t latency_bucket_for_us(uint64_t us) {
        size_t bucket = 0;
        uint64_t limit = 1;
        while (us > limit && bucket + 1u < kLatencyHistogramBuckets) {
            limit <<= 1u;
            ++bucket;
        }
        return bucket;
    }

    static uint64_t latency_bucket_upper_us(size_t bucket) {
        return bucket < 63u ? (1ull << bucket) : UINT64_MAX;
    }

    static void reset_latency_histogram(LatencyHistogram& hist) {
        hist.count = 0;
        hist.totalUs = 0;
        hist.maxUs = 0;
        for (uint64_t& bucket : hist.buckets) {
            bucket = 0;
        }
    }

    void note_latency_sample(LatencyHistogram& hist, uint64_t ns) {
        if (!collect_log_stats()) {
            return;
        }
        const uint64_t us = latency_ns_to_us(ns);
        ++hist.count;
        hist.totalUs += us;
        if (us > hist.maxUs) {
            hist.maxUs = us;
        }
        ++hist.buckets[latency_bucket_for_us(us)];
    }

    static uint64_t latency_percentile_us(const LatencyHistogram& hist, uint32_t percentile) {
        if (hist.count == 0) {
            return 0;
        }
        const uint64_t target =
            (hist.count * static_cast<uint64_t>(percentile) + 99ull) / 100ull;
        uint64_t seen = 0;
        for (size_t bucket = 0; bucket < kLatencyHistogramBuckets; ++bucket) {
            seen += hist.buckets[bucket];
            if (seen >= target) {
                return latency_bucket_upper_us(bucket);
            }
        }
        return latency_bucket_upper_us(kLatencyHistogramBuckets - 1u);
    }

    static uint64_t latency_average_us(const LatencyHistogram& hist) {
        return hist.count != 0 ? hist.totalUs / hist.count : 0;
    }

    static uint64_t counter_rate_per_sec(uint64_t count, uint64_t windowNs) {
        if (count == 0 || windowNs == 0) {
            return 0;
        }
        return (count * 1000000000ull) / windowNs;
    }

    void note_native_trigger_to_aio_submit(uint64_t triggerNs, uint64_t submitNs) {
        if (triggerNs != 0 && submitNs >= triggerNs) {
            note_latency_sample(runtimeNativeTriggerToSubmitLatency, submitNs - triggerNs);
        }
    }

    void note_job_queue_to_first_read_queue(JobState& job, uint64_t queuedNs) {
        if (job.reactorEnqueueTimeNs == 0 ||
            job.firstReadQueueTimeNs != 0 ||
            queuedNs < job.reactorEnqueueTimeNs) {
            return;
        }
        const size_t priority = apr_clamp_priority_index(job.prioIndex);
        note_latency_sample(runtimeJobQueueToFirstReadLatency,
                            queuedNs - job.reactorEnqueueTimeNs);
        note_latency_sample(runtimeJobQueueToFirstReadLatencyByPriority[priority],
                            queuedNs - job.reactorEnqueueTimeNs);
        job.firstReadQueueTimeNs = queuedNs;
    }

    void note_job_queue_to_first_aio_submit(JobState& job, uint64_t submitNs) {
        if (job.reactorEnqueueTimeNs != 0 && submitNs >= job.reactorEnqueueTimeNs) {
            const size_t priority = apr_clamp_priority_index(job.prioIndex);
            note_latency_sample(runtimeJobQueueToFirstAioLatency,
                                submitNs - job.reactorEnqueueTimeNs);
            note_latency_sample(runtimeJobQueueToFirstAioLatencyByPriority[priority],
                                submitNs - job.reactorEnqueueTimeNs);
            if (job.firstReadQueueTimeNs != 0 &&
                submitNs >= job.firstReadQueueTimeNs) {
                note_latency_sample(runtimeFirstReadQueueToFirstAioLatency,
                                    submitNs - job.firstReadQueueTimeNs);
                note_latency_sample(
                    runtimeFirstReadQueueToFirstAioLatencyByPriority[priority],
                    submitNs - job.firstReadQueueTimeNs);
            }
            job.reactorEnqueueTimeNs = 0;
            job.firstReadQueueTimeNs = 0;
        }
    }

    void note_pending_read_queue_to_aio_submit(uint64_t enqueueNs,
                                                uint64_t submitNs,
                                                size_t priority) {
        if (enqueueNs != 0 && submitNs >= enqueueNs) {
            note_latency_sample(runtimePendingReadQueueToAioLatency,
                                submitNs - enqueueNs);
            note_latency_sample(
                runtimePendingReadQueueToAioLatencyByPriority[
                    apr_clamp_priority_index(priority)],
                submitNs - enqueueNs);
        }
    }

    void note_reactor_active_loop_gap() {
        const uint64_t now = time_counter_now();
        if (runtimeReactorLoopGapArmed &&
            runtimeReactorLoopLastNs != 0 &&
            now >= runtimeReactorLoopLastNs) {
            note_latency_sample(runtimeReactorActiveLoopGapLatency,
                                now - runtimeReactorLoopLastNs);
        }
        runtimeReactorLoopLastNs = now;
        runtimeReactorLoopGapArmed =
            activeJobCountAtomic.load(std::memory_order_relaxed) != 0 ||
            pendingReadTotalAtomic.load(std::memory_order_relaxed) != 0 ||
            !activeReads.empty();
    }

    void note_accepted_aio_request(uint64_t bytes, size_t priority) {
        if (!collect_log_stats()) {
            return;
        }
        ++runtimeAioAcceptedRequestCount;
        runtimeAioAcceptedBytes += bytes;
        const size_t priorityIndex = apr_clamp_priority_index(priority);
        ++runtimeAioAcceptedRequestCountByPriority[priorityIndex];
        runtimeAioAcceptedBytesByPriority[priorityIndex] += bytes;
        if (bytes <= 0x10000ull) {
            ++runtimeAioAcceptedLe64K;
        } else if (bytes <= 0x40000ull) {
            ++runtimeAioAcceptedLe256K;
        } else if (bytes <
                   static_cast<uint64_t>(AMPR_EMU_APR_AIO_DISPATCH_QUANTUM_BYTES)) {
            ++runtimeAioAcceptedPartialQuantum;
        } else if (bytes ==
                   static_cast<uint64_t>(AMPR_EMU_APR_AIO_DISPATCH_QUANTUM_BYTES)) {
            ++runtimeAioAcceptedFullQuantum;
        } else {
            ++runtimeAioAcceptedOverQuantum;
        }
    }

    void note_aio_completion_latency(uint64_t ageNs) {
        if (collect_log_stats()) {
            const uint64_t ageUs = ageNs / 1000ull;
            ++runtimeAioCompletionCount;
            runtimeAioCompletionTotalUs += ageUs;
            if (ageUs > runtimeAioCompletionMaxUs) {
                runtimeAioCompletionMaxUs = ageUs;
            }
        }
        note_latency_sample(runtimeAioSubmitToCompletionLatency, ageNs);
    }

    void note_aio_poll_call(uint64_t elapsedNs) {
        if (collect_log_stats()) {
            ++runtimeAioPollCalls;
            runtimeAioPollWorkNs += elapsedNs;
        }
    }

    void note_aio_poll_backoff_skip() {
        note_log_counter(runtimeAioPollBackoffSkips);
    }

    void note_aio_poll_budget_yield() {
        note_log_counter(runtimeAioPollBudgetYields);
    }

    void note_aio_poll_sleep(uint32_t sleepNs) {
        if (collect_log_stats()) {
            runtimeAioPollSleepNs += sleepNs;
        }
    }

    void note_deadline_heap_pick() {
        note_log_counter(runtimeDeadlineHeapPicks);
    }

    void note_deadline_heap_future_stop() {
        note_log_counter(runtimeDeadlineHeapFutureStops);
    }

    void note_active_read_due_poll() {
        note_log_counter(runtimeActiveReadDuePolls);
    }

    void note_active_read_not_due_skip() {
        note_log_counter(runtimeActiveReadNotDueSkips);
    }

    void note_worker_wakeup() {
        note_log_counter(runtimeWorkerWakeups);
    }

    void note_idle_poll_pass() {
        note_log_counter(runtimeIdlePollPasses);
    }
#endif

    void note_emfile_event() {
#if AMPR_EMU_DEBUG_LOG
        note_log_counter(runtimeEmfileEvents);
#endif
    }

    void note_efault_retry_event() {
#if AMPR_EMU_DEBUG_LOG
        note_log_counter(runtimeEfaultRetryEvents);
#endif
    }

    void note_efault_retry_limit_event() {
#if AMPR_EMU_DEBUG_LOG
        note_log_counter(runtimeEfaultRetryLimitEvents);
#endif
    }

    const char* file_path_log_arg(uint32_t fileId) const {
        FileEntryView entry{};
        if (ampr_index_get_entry_view(fileId, &entry) == 0) {
            return ampr_log_path_arg(entry.path);
        }
        return "<unknown>";
    }

#if AMPR_EMU_DEBUG_LOG
    static uint64_t vq_ptr_value(const void* ptr) {
        return reinterpret_cast<uint64_t>(ptr);
    }

    void log_aio_buffer_memory_detail(const char* prefix,
                                      const char* reason,
                                      const ActiveRead& active,
                                      uint64_t now,
                                      int state,
                                      int pollRc) const {
        const uint64_t start = reinterpret_cast<uint64_t>(active.desc.buffer);
        const uint64_t len = active.desc.length;
        const bool rangeValid = len != 0 && start + len - 1 >= start;
        const uint64_t last = rangeValid ? start + len - 1 : start;

        SceKernelVirtualQueryInfo startInfo{};
        SceKernelVirtualQueryInfo lastInfo{};
        const int startRc = sceKernelVirtualQuery(active.desc.buffer,
                                                  0,
                                                  &startInfo,
                                                  sizeof(startInfo));
        const int lastRc = rangeValid
                               ? sceKernelVirtualQuery(reinterpret_cast<const void*>(last),
                                                       0,
                                                       &lastInfo,
                                                       sizeof(lastInfo))
                               : startRc;
        void* protStart = nullptr;
        void* protEnd = nullptr;
        int prot = 0;
        const int protRc = sceKernelQueryMemoryProtection(active.desc.buffer,
                                                          &protStart,
                                                          &protEnd,
                                                          &prot);
        auto job = active.job;
        const char* pathArg = file_path_log_arg(active.desc.fileId);

        AMPR_LOGF("%s reason=%s job=0x%llx seq=0x%llx aioId=%d fileId=%u path=%s fd=%d buf=%p len=0x%llx last=0x%llx off=0x%llx ageMs=%llu state=0x%x pollRc=0x%x return=0x%llx rangeValid=%u qprotRc=0x%x qprot=0x%x qprotStart=0x%llx qprotEnd=0x%llx vqStartRc=0x%x vqStart=0x%llx vqEnd=0x%llx vqProt=0x%x vqType=%d vqFlex=%u vqDirect=%u vqStack=%u vqPool=%u vqCommitted=%u vqAmm=%u vqLastRc=0x%x vqLastStart=0x%llx vqLastEnd=0x%llx vqLastProt=0x%x vqLastType=%d vqLastFlex=%u vqLastDirect=%u vqLastStack=%u vqLastPool=%u vqLastCommitted=%u vqLastAmm=%u bypass=%u closeAfter=%u",
                  prefix ? prefix : "apr.reactor.aio.bufVa",
                  reason ? reason : "unknown",
                  job ? (unsigned long long)job->id : 0ull,
                  (unsigned long long)active.seq,
                  active.aioId,
                  active.desc.fileId,
                  pathArg,
                  active.desc.fd,
                  active.desc.buffer,
                  (unsigned long long)active.desc.length,
                  (unsigned long long)last,
                  (unsigned long long)active.desc.offset,
                  (unsigned long long)active_read_age_ms(active, now),
                  state,
                  apr_aio_api_rc_to_sce(pollRc),
                  (unsigned long long)active.result.returnValue,
                  rangeValid ? 1u : 0u,
                  apr_aio_api_rc_to_sce(protRc),
                  prot,
                  (unsigned long long)vq_ptr_value(protStart),
                  (unsigned long long)vq_ptr_value(protEnd),
                  apr_aio_api_rc_to_sce(startRc),
                  (unsigned long long)vq_ptr_value(startInfo.start),
                  (unsigned long long)vq_ptr_value(startInfo.end),
                  startInfo.protection,
                  startInfo.memoryType,
                  startInfo.isFlexibleMemory ? 1u : 0u,
                  startInfo.isDirectMemory ? 1u : 0u,
                  startInfo.isStack ? 1u : 0u,
                  startInfo.isPooledMemory ? 1u : 0u,
                  startInfo.isCommitted ? 1u : 0u,
                  startInfo.ammUsage ? 1u : 0u,
                  apr_aio_api_rc_to_sce(lastRc),
                  (unsigned long long)vq_ptr_value(lastInfo.start),
                  (unsigned long long)vq_ptr_value(lastInfo.end),
                  lastInfo.protection,
                  lastInfo.memoryType,
                  lastInfo.isFlexibleMemory ? 1u : 0u,
                  lastInfo.isDirectMemory ? 1u : 0u,
                  lastInfo.isStack ? 1u : 0u,
                  lastInfo.isPooledMemory ? 1u : 0u,
                  lastInfo.isCommitted ? 1u : 0u,
                  lastInfo.ammUsage ? 1u : 0u,
                  active.desc.bypassFdCache ? 1u : 0u,
                  active.desc.closeAfter ? 1u : 0u);
    }

    void log_aio_efault_detail(const ActiveRead& active,
                               int rc,
                               int state,
                               int deleteRc,
                               uint32_t errorOff,
                               uint64_t finishTimeNs) const {
        log_aio_buffer_memory_detail("apr.reactor.aio.bufVa",
                                     "efault",
                                     active,
                                     finishTimeNs,
                                     state,
                                     0);
        const char* pathArg = file_path_log_arg(active.desc.fileId);
        const uint64_t readStart = reinterpret_cast<uint64_t>(active.desc.buffer);
        const uint64_t readLen = active.desc.length;
        const bool rangeValid = readLen != 0 && readStart + readLen >= readStart;
        const uint64_t readEnd = rangeValid ? readStart + readLen : readStart;
        const bool inAmmVa = false;
        const bool overlapsAmmVa = false;
        const bool inAmmMultiVa = false;
        const bool overlapsAmmMultiVa = false;

        AMPR_LOGF("apr.reactor.aio.efault.detail job=0x%llx seq=0x%llx aioId=%d rc=0x%x state=0x%x return=0x%llx deleteRc=0x%x fileId=%u path=%s fd=%d buf=%p len=0x%llx readEnd=0x%llx off=0x%llx ageMs=%llu errorOff=0x%x rangeValid=%u inAmmVa=%u overlapsAmmVa=%u inAmmMultiVa=%u overlapsAmmMultiVa=%u bypass=%u closeAfter=%u",
                  active.job ? (unsigned long long)active.job->id : 0ull,
                  (unsigned long long)active.seq,
                  active.aioId,
                  rc,
                  state,
                  (unsigned long long)active.result.returnValue,
                  apr_aio_api_rc_to_sce(deleteRc),
                  active.desc.fileId,
                  pathArg,
                  active.desc.fd,
                  active.desc.buffer,
                  (unsigned long long)active.desc.length,
                  (unsigned long long)readEnd,
                  (unsigned long long)active.desc.offset,
                  (unsigned long long)active_read_age_ms(active, finishTimeNs),
                  errorOff,
                  rangeValid ? 1u : 0u,
                  inAmmVa ? 1u : 0u,
                  overlapsAmmVa ? 1u : 0u,
                  inAmmMultiVa ? 1u : 0u,
                  overlapsAmmMultiVa ? 1u : 0u,
                  active.desc.bypassFdCache ? 1u : 0u,
                  active.desc.closeAfter ? 1u : 0u);
    }
#endif

#if AMPR_EMU_DEBUG_LOG
    void log_pending_backlog_detail(const char* reason, size_t pendingReadsTotal) {
        const PendingReadQueue* lane = highest_priority_pending_lane();
        if (!lane) {
            return;
        }
        const PendingRead& pending = lane->front();
        const size_t prio = pending.job ? pending.job->prioIndex : kAprPriorityMin;
        const char* pathArg = file_path_log_arg(pending.desc.fileId);
        size_t perFileActive = 0;
        for (const ActiveRead& active : activeReads) {
            if (active.desc.fileId == pending.desc.fileId) {
                ++perFileActive;
            }
        }
        AMPR_LOGF("apr.reactor.pending.detail reason=%s prio=%zu job=0x%llx seq=0x%llx fileId=%u path=%s buf=%p len=0x%llx off=0x%llx queueReads=%zu pendingReads=%zu activeReads=%zu perFileActive=%zu order=priority-lane",
                  reason ? reason : "unknown",
                  prio,
                  pending.job ? (unsigned long long)pending.job->id : 0ull,
                  (unsigned long long)pending.seq,
                  pending.desc.fileId,
                  pathArg,
                  pending.desc.buffer,
                  (unsigned long long)pending.desc.length,
                  (unsigned long long)pending.desc.offset,
                  lane->size(),
                  pendingReadsTotal,
                  activeReads.size(),
                  perFileActive);
    }

#if AMPR_EMU_APR_REACTOR_BACKLOG_WARN_THRESHOLD != 0 && \
    AMPR_EMU_APR_REACTOR_BACKLOG_FILE_SAMPLES != 0
    struct BacklogFileSample {
        uint32_t fileId{};
        size_t pending{};
        size_t active{};
        size_t pendingCached{};
        size_t pendingSmall{};
        size_t pendingNormal{};
        size_t pendingBulk{};
        size_t activeCached{};
        size_t activeSmall{};
        size_t activeNormal{};
        size_t activeBulk{};
        uint64_t pendingBytes{};
        uint64_t activeBytes{};
        uint64_t maxPendingLen{};
        uint64_t maxActiveLen{};
    };

    static constexpr size_t kBacklogFileSampleCapacity =
        static_cast<size_t>(kPendingReadQueueCapacity) + kMaxActiveReads;
    static_assert(kBacklogFileSampleCapacity != 0,
                  "APR backlog sample storage must not be empty");

    static void count_read_class(DirectReadClass cls,
                                 size_t* cached,
                                 size_t* small,
                                 size_t* normal,
                                 size_t* bulk) {
        switch (cls) {
        case DirectReadClass::CachedOrPartial:
            ++(*cached);
            break;
        case DirectReadClass::Small:
            ++(*small);
            break;
        case DirectReadClass::Normal:
            ++(*normal);
            break;
        case DirectReadClass::Bulk:
            ++(*bulk);
            break;
        default:
            break;
        }
    }

    BacklogFileSample& backlog_file_sample(size_t& sampleCount, uint32_t fileId) {
        for (size_t i = 0; i < sampleCount; ++i) {
            BacklogFileSample& sample = backlogFileSamples[i];
            if (sample.fileId == fileId) {
                return sample;
            }
        }
        if (sampleCount >= kBacklogFileSampleCapacity) {
            AMPR_CRITICAL_LOGF("apr.reactor.backlog.sample.full count=%zu capacity=%zu pendingReads=%zu activeReads=%zu",
                               sampleCount,
                               kBacklogFileSampleCapacity,
                               pending_read_total(),
                               activeReads.size());
            __builtin_trap();
        }
        BacklogFileSample& sample = backlogFileSamples[sampleCount++];
        sample = {};
        sample.fileId = fileId;
        return sample;
    }
#endif

    void log_backlog_file_snapshot(const char* reason, bool pressureActive) {
#if AMPR_EMU_APR_REACTOR_BACKLOG_WARN_THRESHOLD != 0 && \
    AMPR_EMU_APR_REACTOR_BACKLOG_FILE_SAMPLES != 0
        size_t sampleCount = 0;
        for (size_t priority = kAprPriorityMin; priority <= kAprPriorityMax; ++priority) {
            for (const PendingRead& pending : pendingReadLanes[priority]) {
                BacklogFileSample& sample = backlog_file_sample(sampleCount, pending.desc.fileId);
                ++sample.pending;
                sample.pendingBytes += pending.desc.length;
                sample.maxPendingLen = std::max<uint64_t>(sample.maxPendingLen, pending.desc.length);
                count_read_class(direct_read_class(pending.desc),
                                 &sample.pendingCached,
                                 &sample.pendingSmall,
                                 &sample.pendingNormal,
                                 &sample.pendingBulk);
            }
        }
        for (const ActiveRead& active : activeReads) {
            BacklogFileSample& sample = backlog_file_sample(sampleCount, active.desc.fileId);
            ++sample.active;
            sample.activeBytes += active.desc.length;
            sample.maxActiveLen = std::max<uint64_t>(sample.maxActiveLen, active.desc.length);
            count_read_class(active_direct_read_class(active),
                             &sample.activeCached,
                             &sample.activeSmall,
                             &sample.activeNormal,
                             &sample.activeBulk);
        }
        if (sampleCount == 0) {
            return;
        }
        const size_t count = std::min<size_t>(sampleCount,
                                              AMPR_EMU_APR_REACTOR_BACKLOG_FILE_SAMPLES);
        std::partial_sort(backlogFileSamples,
                          backlogFileSamples + count,
                          backlogFileSamples + sampleCount,
                          [](const BacklogFileSample& a, const BacklogFileSample& b) {
            if (a.pending != b.pending) return a.pending > b.pending;
            if (a.active != b.active) return a.active > b.active;
            return a.fileId < b.fileId;
        });
        for (size_t i = 0; i < count; ++i) {
            const BacklogFileSample& sample = backlogFileSamples[i];
            const char* pathArg = file_path_log_arg(sample.fileId);
            AMPR_LOGF("apr.reactor.backlog.file reason=%s rank=%zu fileId=%u path=%s pending=%zu active=%zu pendingBytes=0x%llx activeBytes=0x%llx maxPendingLen=0x%llx maxActiveLen=0x%llx pendingCached=%zu pendingSmall=%zu pendingNormal=%zu pendingBulk=%zu activeCached=%zu activeSmall=%zu activeNormal=%zu activeBulk=%zu pressure=%u",
                      reason ? reason : "unknown",
                      i + 1,
                      sample.fileId,
                      pathArg,
                      sample.pending,
                      sample.active,
                      (unsigned long long)sample.pendingBytes,
                      (unsigned long long)sample.activeBytes,
                      (unsigned long long)sample.maxPendingLen,
                      (unsigned long long)sample.maxActiveLen,
                      sample.pendingCached,
                      sample.pendingSmall,
                      sample.pendingNormal,
                      sample.pendingBulk,
                      sample.activeCached,
                      sample.activeSmall,
                      sample.activeNormal,
                      sample.activeBulk,
                      pressureActive ? 1u : 0u);
        }
#else
        (void)reason;
        (void)pressureActive;
#endif
    }

    void log_active_read_detail(const char* prefix,
                                const char* reason,
                                const ActiveRead& active,
                                uint64_t now,
                                int state,
                                int pollRc) const {
        log_aio_buffer_memory_detail("apr.reactor.aio.bufVa",
                                     reason,
                                     active,
                                     now,
                                     state,
                                     pollRc);
        const char* pathArg = file_path_log_arg(active.desc.fileId);
        auto job = active.job;
        AMPR_LOGF("%s reason=%s job=0x%llx seq=0x%llx aioId=%d fileId=%u path=%s fd=%d buf=%p len=0x%llx off=0x%llx ageMs=%llu state=0x%x pollRc=0x%x return=0x%llx bypass=%u closeAfter=%u",
                  prefix ? prefix : "apr.reactor.aio.detail",
                  reason ? reason : "unknown",
                  job ? (unsigned long long)job->id : 0ull,
                  (unsigned long long)active.seq,
                  active.aioId,
                  active.desc.fileId,
                  pathArg,
                  active.desc.fd,
                  active.desc.buffer,
                  (unsigned long long)active.desc.length,
                  (unsigned long long)active.desc.offset,
                  (unsigned long long)active_read_age_ms(active, now),
                  state,
                  apr_aio_api_rc_to_sce(pollRc),
                  (unsigned long long)active.result.returnValue,
                  active.desc.bypassFdCache ? 1u : 0u,
                  active.desc.closeAfter ? 1u : 0u);
    }

    void log_oldest_active_read_detail(const char* prefix, const char* reason, uint64_t now) const {
        const ActiveRead* oldest = nullptr;
        uint64_t oldestAgeMs = 0;
        for (const ActiveRead& active : activeReads) {
            const uint64_t ageMs = active_read_age_ms(active, now);
            if (!oldest || ageMs >= oldestAgeMs) {
                oldest = &active;
                oldestAgeMs = ageMs;
            }
        }
        if (!oldest) {
            return;
        }
        int state = 0;
        const int pollRc = sceKernelAioPollRequest(oldest->aioId, &state);
        log_active_read_detail(prefix, reason, *oldest, now, state, pollRc);
    }
#endif

#if AMPR_EMU_DEBUG_LOG && AMPR_EMU_APR_REACTOR_BACKLOG_WARN_THRESHOLD != 0
    void maybe_log_reactor_backlog(const char* reason, size_t pendingReadsTotal) {
        if (!collect_log_stats()) {
            return;
        }
        if (pendingReadsTotal < AMPR_EMU_APR_REACTOR_BACKLOG_WARN_THRESHOLD) {
            return;
        }
        const uint64_t now = time_counter_now();
        bool shouldLog = lastBacklogLogPending == 0;
        if (!shouldLog && lastBacklogLogPending <= (SIZE_MAX / 2)) {
            shouldLog = pendingReadsTotal >= (lastBacklogLogPending * 2);
        }
        if (!shouldLog && pendingReadsTotal + AMPR_EMU_APR_REACTOR_BACKLOG_WARN_THRESHOLD <= lastBacklogLogPending) {
            shouldLog = true;
        }
        if (!shouldLog &&
            now - lastBacklogLogTimeNs >= AMPR_EMU_APR_REACTOR_BACKLOG_WARN_INTERVAL_NS) {
            shouldLog = true;
        }
        if (!shouldLog) {
            return;
        }
        lastBacklogLogPending = pendingReadsTotal;
        lastBacklogLogTimeNs = now;
        size_t activeCached = 0;
        size_t activeSmall = 0;
        size_t activeNormal = 0;
        size_t activeBulk = 0;
        for (const ActiveRead& active : activeReads) {
            switch (active_direct_read_class(active)) {
            case DirectReadClass::CachedOrPartial:
                ++activeCached;
                break;
            case DirectReadClass::Small:
                ++activeSmall;
                break;
            case DirectReadClass::Normal:
                ++activeNormal;
                break;
            case DirectReadClass::Bulk:
                ++activeBulk;
                break;
            default:
                break;
            }
        }
        const uint64_t oldestAgeMs = oldest_active_read_age_ms(now);
        const bool slowCooldown = slow_aio_cooldown_active(now);
        AMPR_LOGF("apr.reactor.backlog reason=%s activeJobs=%zu pendingReads=%zu activeReads=%zu limit=%u pressure=%u slowCooldown=%u activeCached=%zu activeDirectSmall=%zu activeDirectNormal=%zu activeDirectBulk=%zu oldestAioAgeMs=%llu",
                  reason ? reason : "unknown",
                  active_lane_count_locked(),
                  pendingReadsTotal,
                  activeReads.size(),
                  (unsigned)aio_active_read_limit(),
                  0u,
                  slowCooldown ? 1u : 0u,
                  activeCached,
                  activeSmall,
                  activeNormal,
                  activeBulk,
                  (unsigned long long)oldestAgeMs);
        log_pending_backlog_detail(reason, pendingReadsTotal);
        log_backlog_file_snapshot(reason, false);
        log_oldest_active_read_detail("apr.reactor.aio.backlogActive", reason, now);
    }
#endif

    uint64_t oldest_active_read_age_ms(uint64_t now) const {
        uint64_t oldest = 0;
        for (const ActiveRead& active : activeReads) {
            const uint64_t ageMs = active_read_age_ms(active, now);
            if (ageMs > oldest) {
                oldest = ageMs;
            }
        }
        return oldest;
    }

    bool slow_aio_cooldown_active(uint64_t now) const {
#if AMPR_EMU_APR_AIO_SLOW_COOLDOWN_MS != 0
        return slowAioCooldownUntilNs != 0 && now < slowAioCooldownUntilNs;
#else
        (void)now;
        return false;
#endif
    }

    void note_slow_aio_completion(uint64_t now, uint64_t ageMs) {
#if AMPR_EMU_APR_AIO_SLOW_COOLDOWN_MS != 0 && AMPR_EMU_APR_AIO_SLOW_COOLDOWN_TRIGGER_MS != 0
        if (ageMs < AMPR_EMU_APR_AIO_SLOW_COOLDOWN_TRIGGER_MS) {
            return;
        }
        const uint64_t cooldownNs = static_cast<uint64_t>(AMPR_EMU_APR_AIO_SLOW_COOLDOWN_MS) * 1000000ull;
        const uint64_t until = now + cooldownNs;
        if (until > slowAioCooldownUntilNs) {
            slowAioCooldownUntilNs = until;
        }
#else
        (void)now;
        (void)ageMs;
#endif
    }

    static size_t fd_cache_cap_for_pressure_level(uint8_t level) {
        (void)level;
        return ampr_index_fd_pressure_current_caps().cacheCap;
    }

    void sync_fd_cache_open_pressure(uint64_t now) const {
        const uint64_t generation = ampr_index_fd_cache_open_pressure_generation();
        if (generation == fdCacheOpenPressureSeen) {
            return;
        }
        fdCacheOpenPressureSeen = generation;
        constexpr uint64_t kFdPressureCooldownNs = AMPR_EMU_APR_FD_PRESSURE_COOLDOWN_MS * 1000000ull;
        const uint64_t until = now + kFdPressureCooldownNs;
        if (fdPressureLevel < AMPR_EMU_APR_FD_PRESSURE_SCORE_MAX) {
            ++fdPressureLevel;
        }
        if (until > fdPressureUntilNs) {
            fdPressureUntilNs = until;
        }
        const size_t cap = fd_cache_cap_for_pressure_level(fdPressureLevel);
        ampr_index_fd_cache_set_effective_cap(cap);
        fdCachePressureCapApplied = true;
        ampr_index_fd_cache_release_open_fd_headroom(0, cap);
    }

    bool fd_pressure_active(uint64_t now) const {
        sync_fd_cache_open_pressure(now);
        if (fdPressureUntilNs == 0) {
            return false;
        }
        if (now < fdPressureUntilNs) {
            return true;
        }
        fdPressureUntilNs = 0;
        fdPressureLevel = 0;
        if (fdCachePressureCapApplied) {
            ampr_index_fd_open_budget_set_effective_cap(kFdOpenBudgetBaseCap);
            ampr_index_fd_cache_set_effective_cap(AMPR_EMU_FD_CACHE_CAP);
            fdCachePressureCapApplied = false;
        }
        return false;
    }

    void note_fd_pressure() {
        constexpr uint64_t kFdPressureCooldownNs = AMPR_EMU_APR_FD_PRESSURE_COOLDOWN_MS * 1000000ull;
        const uint64_t now = time_counter_now();
        const uint64_t until = now + kFdPressureCooldownNs;
        if (fdPressureLevel < AMPR_EMU_APR_FD_PRESSURE_SCORE_MAX) {
            ++fdPressureLevel;
        }
        if (until > fdPressureUntilNs) {
            fdPressureUntilNs = until;
        }
        const size_t cap = fd_cache_cap_for_pressure_level(fdPressureLevel);
        ampr_index_fd_cache_set_effective_cap(cap);
        fdCachePressureCapApplied = true;
        ampr_index_fd_cache_release_open_fd_headroom(0, cap);
    }

    static DirectReadClass classify_direct_read(bool directRead, uint64_t length) {
        if (!directRead) {
            return DirectReadClass::CachedOrPartial;
        }
#if AMPR_EMU_APR_AIO_DIRECT_SMALL_FULL_FILE_BYTES != 0
        if (length <= AMPR_EMU_APR_AIO_DIRECT_SMALL_FULL_FILE_BYTES) {
            return DirectReadClass::Small;
        }
#endif
#if AMPR_EMU_APR_AIO_BULK_FULL_FILE_BYTES != 0
        if (length >= AMPR_EMU_APR_AIO_BULK_FULL_FILE_BYTES) {
            return DirectReadClass::Bulk;
        }
#endif
        return DirectReadClass::Normal;
    }

    DirectReadClass direct_read_class(const AprAioReadDesc& rd) const {
        const bool directRead = read_would_bypass_fd_cache(rd);
        return classify_direct_read(directRead, rd.length);
    }

    bool fd_budget_available_for_read(const AprAioReadDesc& rd,
                                      const char** outReason,
                                      size_t* outObserved,
                                      size_t* outBudget,
                                      size_t* outEvictable) const {
        if (rd.fd >= 0) {
            return true;
        }
        const bool bypassFdCache = read_would_bypass_fd_cache(rd);
        if (outReason) {
            *outReason = bypassFdCache ? "fd-open-budget-direct" : "fd-open-budget-cached";
        }
        if (bypassFdCache) {
            return ampr_index_fd_common_open_budget_headroom_available(1,
                                                                       outObserved,
                                                                       outBudget,
                                                                       outEvictable);
        }
        return ampr_index_fd_cached_open_budget_headroom_available(rd.fileId,
                                                                   outObserved,
                                                                   outBudget,
                                                                   outEvictable);
    }

    static DirectReadClass active_direct_read_class(const ActiveRead& active) {
        return classify_direct_read(active.desc.bypassFdCache, active.desc.length);
    }

    DirectReadCounts active_direct_read_counts() const {
        DirectReadCounts counts{};
        for (const ActiveRead& active : activeReads) {
            switch (active_direct_read_class(active)) {
            case DirectReadClass::Small:
                ++counts.small;
                ++counts.total;
                break;
            case DirectReadClass::Normal:
                ++counts.normal;
                ++counts.total;
                break;
            case DirectReadClass::Bulk:
                ++counts.bulk;
                ++counts.total;
                break;
            case DirectReadClass::CachedOrPartial:
            default:
                break;
            }
        }
        return counts;
    }

    uint32_t poll_only_idle_sleep_ns() {
#if AMPR_EMU_APR_AIO_POLL_BACKGROUND_SLEEP_NS != AMPR_EMU_APR_AIO_POLL_IDLE_SLEEP_NS
        if (pendingReadTotalAtomic.load(std::memory_order_relaxed) == 0) {
            return AMPR_EMU_APR_AIO_POLL_BACKGROUND_SLEEP_NS;
        }
#endif
        return AMPR_EMU_APR_AIO_POLL_IDLE_SLEEP_NS;
    }

    static uint64_t active_read_age_ns(const ActiveRead& active, uint64_t now) {
        return active.submitTimeNs != 0 && now >= active.submitTimeNs
                   ? now - active.submitTimeNs
                   : 0;
    }

    void reset_active_read_poll_backoff(ActiveRead& active, uint64_t now) {
        const uint64_t oldDeadlineNs = active.nextPollTimeNs;
        active.nextPollTimeNs = now;
        active.pollBackoffNs = AMPR_EMU_APR_AIO_POLL_BACKOFF_MIN_NS;
        update_poll_deadline(active, oldDeadlineNs);
    }

    void queue_hot_active_read_poll(ActiveRead& active) {
        if (active.hotPollQueued || active.listSlot == UINT32_MAX) {
            return;
        }
        if (hotPollQueueCount >= kHotPollQueueCapacity) {
            return;
        }
        hotPollQueue[hotPollQueueTail] = HotPollEntry{active.listSlot, active.listGeneration};
        hotPollQueueTail = (hotPollQueueTail + 1u) % kHotPollQueueCapacity;
        ++hotPollQueueCount;
        active.hotPollQueued = true;
    }

    void reset_and_queue_hot_active_read_poll(ActiveRead& active, uint64_t now) {
        reset_active_read_poll_backoff(active, now);
        active.gatingSpinPollsRemaining = AMPR_EMU_APR_AIO_GATING_SPIN_POLLS;
        queue_hot_active_read_poll(active);
    }

    ActiveReadIt pop_hot_active_read_poll() {
        while (hotPollQueueCount != 0) {
            const HotPollEntry entry = hotPollQueue[hotPollQueueHead];
            hotPollQueueHead = (hotPollQueueHead + 1u) % kHotPollQueueCapacity;
            --hotPollQueueCount;
            ActiveRead* active = activeReads.active_at_slot(entry.slot, entry.generation);
            if (!active || !active->hotPollQueued) {
                continue;
            }
            active->hotPollQueued = false;
            return activeReads.iterator_from_slot(entry.slot);
        }
        return activeReads.end();
    }

    bool active_read_poll_due(const ActiveRead& active, uint64_t now) const {
        return active.nextPollTimeNs == 0 || now >= active.nextPollTimeNs;
    }

    bool active_read_can_gate_publish(const ActiveRead& active) const {
        const JobPtr& job = active.job;
        if (!job) {
            return false;
        }
        if (job->submitMode == AprSubmitMode::kSubmitAndGetResult) {
            return true;
        }
        return active.seq == job->completedReadSeq + 1u ||
               active.seq == job->latestSubmittedReadSeq;
    }

    static uint32_t active_lane_idle_sleep_ns() {
        return AMPR_EMU_APR_ACTIVE_LANE_IDLE_SLEEP_NS;
    }

    void reset_publish_gating_active_aio_poll_backoff_for_job(JobState& job, uint64_t now) {
        uint32_t slot = job.activeReadHead;
        bool chainBroken = false;
        for (uint32_t scanned = 0; slot != UINT32_MAX && scanned < kMaxActiveReads; ++scanned) {
            ActiveRead* active = activeReads.active_at_slot(slot);
            if (!active || active->job != &job) {
                chainBroken = true;
                break;
            }
            const uint32_t nextSlot = active->jobNextSlot;
            if (active_read_can_gate_publish(*active)) {
                reset_and_queue_hot_active_read_poll(*active, now);
            }
            slot = nextSlot;
        }
        if (!chainBroken && slot == UINT32_MAX) {
            return;
        }
        for (ActiveRead& active : activeReads) {
            if (active.job == &job && active_read_can_gate_publish(active)) {
                reset_and_queue_hot_active_read_poll(active, now);
            }
        }
    }

    void reset_publish_gating_active_aio_poll_backoff_for_lane(
        uint32_t laneIndex,
        uint64_t now) {
        if (laneIndex >= kPriorityCount) {
            return;
        }
        for (ActiveRead& active : activeReads) {
            if (active.job && active.job->prioIndex == laneIndex &&
                active_read_can_gate_publish(active)) {
                reset_and_queue_hot_active_read_poll(active, now);
            }
        }
    }

    uint32_t active_read_max_poll_backoff_ns(const ActiveRead& active) const {
        if (active_read_can_gate_publish(active)) {
            if (active.job && active.job->prioIndex < kPriorityCount &&
                nativeBatchLanes[active.job->prioIndex]
                        .deferredReleaseSequence != 0) {
                return AMPR_EMU_APR_AIO_POLL_STAGED_EOP_BACKOFF_MAX_NS;
            }
            return AMPR_EMU_APR_AIO_POLL_DEPENDENT_BACKOFF_MAX_NS;
        }
#if AMPR_EMU_APR_AIO_POLL_SMALL_BACKGROUND_BYTES != 0
        if (active.desc.length <=
            AMPR_EMU_APR_AIO_POLL_SMALL_BACKGROUND_BYTES) {
            return AMPR_EMU_APR_AIO_POLL_SMALL_BACKGROUND_BACKOFF_MAX_NS;
        }
#endif
        return AMPR_EMU_APR_AIO_POLL_BACKOFF_MAX_NS;
    }

    uint32_t next_active_read_poll_backoff_ns(const ActiveRead& active,
                                             uint64_t now) const {
        const uint64_t ageNs = active_read_age_ns(active, now);
        const uint32_t maxBackoffNs = active_read_max_poll_backoff_ns(active);
        uint32_t capNs = maxBackoffNs;
        if (ageNs <= AMPR_EMU_APR_AIO_POLL_FAST_WINDOW_NS) {
            capNs = AMPR_EMU_APR_AIO_POLL_BACKOFF_MIN_NS;
        } else if (ageNs <= 1000000ull) {
            capNs = AMPR_EMU_APR_AIO_POLL_IDLE_SLEEP_NS;
        } else if (ageNs <= 5000000ull) {
            capNs = maxBackoffNs / 2u;
        }
        if (capNs < AMPR_EMU_APR_AIO_POLL_BACKOFF_MIN_NS) {
            capNs = AMPR_EMU_APR_AIO_POLL_BACKOFF_MIN_NS;
        }

        uint32_t backoffNs = active.pollBackoffNs != 0
            ? active.pollBackoffNs
            : AMPR_EMU_APR_AIO_POLL_BACKOFF_MIN_NS;
        if (backoffNs < capNs) {
            backoffNs = backoffNs <= capNs / 2u ? backoffNs * 2u : capNs;
        }
        if (backoffNs > capNs) {
            backoffNs = capNs;
        }
        return backoffNs;
    }

    void schedule_next_active_read_poll(ActiveRead& active, uint64_t now) {
        const uint64_t oldDeadlineNs = active.nextPollTimeNs;
        const uint32_t backoffNs = next_active_read_poll_backoff_ns(active, now);
        active.pollBackoffNs = backoffNs;
        active.nextPollTimeNs = now + static_cast<uint64_t>(backoffNs);
        update_poll_deadline(active, oldDeadlineNs);
    }

    uint32_t active_aio_poll_sleep_ns(uint64_t now, bool budgetExhausted) {
        const uint32_t baseSleepNs = poll_only_idle_sleep_ns();
        if (activeReads.empty()) {
            return baseSleepNs;
        }
        const uint64_t deadlineNs = active_poll_deadline_ns();
        if (deadlineNs == 0 || now >= deadlineNs) {
            return budgetExhausted ? baseSleepNs : 0;
        }
        const uint64_t minWaitNs = deadlineNs - now;
        constexpr uint32_t kMaxTimedWaitNs = 999999999u;
        if (minWaitNs > kMaxTimedWaitNs) {
            return kMaxTimedWaitNs;
        }
        return static_cast<uint32_t>(minWaitNs);
    }

    void sleep_active_aio_poll(uint64_t now, bool budgetExhausted) {
        const uint32_t sleepNs = active_aio_poll_sleep_ns(now, budgetExhausted);
        if (sleepNs == 0) {
            return;
        }
#if AMPR_EMU_DEBUG_LOG
        note_idle_poll_pass();
        note_aio_poll_sleep(sleepNs);
#endif
        wait_for_reactor_wake(workerObservedWakeEpoch, sleepNs);
#if AMPR_EMU_DEBUG_LOG
        note_worker_wakeup();
#endif
    }

    void wait_for_reactor_wake(uint64_t observedEpoch, uint64_t timeoutNs) {
        if (timeoutNs == 0) {
            return;
        }
        AmprUniqueLock lk(m);
        if (stop || reactorWakeEpoch.load(std::memory_order_acquire) != observedEpoch) {
            return;
        }
#if AMPR_EMU_DEBUG_LOG
        const uint64_t waitStartNs = time_counter_now();
#endif
        reactorCv.wait_for(lk, std::chrono::nanoseconds(timeoutNs));
#if AMPR_EMU_DEBUG_LOG
        const uint64_t waitEndNs = time_counter_now();
        if (waitEndNs >= waitStartNs &&
            waitEndNs - waitStartNs > timeoutNs) {
            note_latency_sample(runtimeReactorWakeOvershootLatency,
                                waitEndNs - waitStartNs - timeoutNs);
        }
#endif
    }

    bool read_would_bypass_fd_cache(const AprAioReadDesc& rd) const {
        if (rd.bypassFdCache) {
            return true;
        }
        if (rd.fullFileRead) {
            return true;
        }
        FileEntryView entry{};
        if (!apr_read_desc_entry(rd, &entry)) {
            return false;
        }
        return apr_read_desc_bypasses_fd_cache_for_size(rd,
                                                        static_cast<uint64_t>(entry.size),
                                                        nullptr);
    }

    static void increment_pending_read_count(const JobPtr& job) {
        if (job && job->pendingReadCount != UINT32_MAX) {
            ++job->pendingReadCount;
        }
    }

    static void decrement_pending_read_count(const JobPtr& job) {
        if (job && job->pendingReadCount != 0) {
            --job->pendingReadCount;
        }
    }

    static void increment_read_chain_pending(ReadChain* chain) {
        if (chain && chain->pendingCount != UINT32_MAX) {
            ++chain->pendingCount;
        }
    }

    static void decrement_read_chain_pending(ReadChain* chain) {
        if (chain && chain->pendingCount != 0) {
            --chain->pendingCount;
        }
    }

    static void subtract_pending_read_count(JobState& job, uint32_t count) {
        job.pendingReadCount = job.pendingReadCount > count ? job.pendingReadCount - count : 0;
    }

    static void increment_active_read_count(const JobPtr& job) {
        if (job && job->activeReadCount != UINT32_MAX) {
            ++job->activeReadCount;
        }
    }

    static void decrement_active_read_count(const JobPtr& job) {
        if (job && job->activeReadCount != 0) {
            --job->activeReadCount;
        }
    }

    static void increment_read_chain_active(ReadChain* chain) {
        if (chain && chain->activeCount != UINT32_MAX) {
            ++chain->activeCount;
        }
    }

    static void decrement_read_chain_active(ReadChain* chain) {
        if (chain && chain->activeCount != 0) {
            --chain->activeCount;
        }
    }

    static void move_active_read_to_pending(const JobPtr& job, ReadChain* chain) {
        decrement_active_read_count(job);
        decrement_read_chain_active(chain);
        increment_pending_read_count(job);
        increment_read_chain_pending(chain);
    }

    void drop_pending_reads_for_job(JobState& job) {
        if (job.pendingReadCount == 0) {
            return;
        }
        uint32_t dropped = 0;
        for (size_t priority = kAprPriorityMin; priority <= kAprPriorityMax; ++priority) {
            PendingReadQueue& lane = pendingReadLanes[priority];
            for (auto it = lane.begin(); it != lane.end();) {
                if (it->job != &job) {
                    ++it;
                    continue;
                }
                ReadChain* const chain = it->chain;
                it = lane.erase(it);
                decrement_read_chain_pending(chain);
                maybe_finish_read_chain(chain);
                ++dropped;
            }
        }
        if (dropped != 0) {
            dec_pending_read_total(dropped);
            subtract_pending_read_count(job, dropped);
            AMPR_LOGF("apr.reactor.dropPending job=0x%llx dropped=%u remaining=%u active=%u",
                      (unsigned long long)job.id,
                      dropped,
                      job.pendingReadCount,
                      job.activeReadCount);
        }
    }

#if AMPR_EMU_APR_AIO_CROSS_EOP_READAHEAD
    void drop_pending_cross_eop_suffix(JobState& job,
                                       uint32_t errorOffset) {
        if (job.pendingReadCount == 0) {
            return;
        }
        uint32_t dropped = 0;
        for (size_t priority = kAprPriorityMin;
             priority <= kAprPriorityMax;
             ++priority) {
            PendingReadQueue& lane = pendingReadLanes[priority];
            for (auto it = lane.begin(); it != lane.end();) {
                if (it->job != &job ||
                    it->desc.errorOff < errorOffset) {
                    ++it;
                    continue;
                }
                ReadChain* const chain = it->chain;
                if (chain) {
                    chain->allIssued = true;
                }
                it = lane.erase(it);
                decrement_read_chain_pending(chain);
                maybe_finish_read_chain(chain);
                ++dropped;
            }
        }
        if (dropped == 0) {
            return;
        }
        dec_pending_read_total(dropped);
        subtract_pending_read_count(job, dropped);
        AMPR_LOGF("apr.reactor.crossEop.dropSuffix job=0x%llx errorOffset=0x%x dropped=%u remaining=%u active=%u",
                  (unsigned long long)job.id,
                  errorOffset,
                  dropped,
                  job.pendingReadCount,
                  job.activeReadCount);
    }
#endif

    void set_fail(JobState& job, const char* reason, int rc, uint32_t errorOffset) {
        if (job.failed.exchange(true, std::memory_order_acq_rel)) {
            return;
        }
        job.result.rc = rc ? rc : SCE_KERNEL_ERROR_EIO;
        job.result.errorOffset = errorOffset;
        finish_job_processing(job);
        drop_pending_reads_for_job(job);
        AMPR_CRITICAL_LOGF("apr.reactor.fail job=0x%llx reason=%s rc=0x%x errorOffset=0x%x pending=%u active=%u",
                  (unsigned long long)job.id,
                  reason ? reason : "unknown",
                  job.result.rc,
                  job.result.errorOffset,
                  job.pendingReadCount,
                  job.activeReadCount);
    }

    void set_command_error(JobState& job, const char* reason, int rc, uint32_t errorOffset) {
        if (job_failed(job) || job.hasCommandError) {
            return;
        }
        job.hasCommandError = true;
        set_fail(job, reason, rc, errorOffset);
        AMPR_CRITICAL_LOGF("apr.reactor.command.error job=0x%llx reason=%s rc=0x%x errorOffset=0x%x pending=%u active=%u action=stop-software-queue-drain",
                  (unsigned long long)job.id,
                  reason ? reason : "unknown",
                  job.result.rc,
                  job.result.errorOffset,
                  job.pendingReadCount,
                  job.activeReadCount);
    }

    void set_command_error_without_cancel(JobState& job,
                                          const char* reason,
                                          int rc,
                                          uint32_t errorOffset) {
        if (job_failed(job) || job.hasCommandError) {
            return;
        }
        job.hasCommandError = true;
        set_fail(job, reason, rc, errorOffset);
        AMPR_CRITICAL_LOGF("apr.reactor.command.error job=0x%llx reason=%s rc=0x%x errorOffset=0x%x pending=%u active=%u action=stop-chain",
                           (unsigned long long)job.id,
                           reason ? reason : "unknown",
                           job.result.rc,
                           job.result.errorOffset,
                           job.pendingReadCount,
                           job.activeReadCount);
    }

    bool set_or_defer_read_command_error(JobState& job,
                                         const char* reason,
                                         int rc,
                                         uint32_t errorOffset) {
#if AMPR_EMU_APR_AIO_CROSS_EOP_READAHEAD
        if (!job_failed(job) && job.crossEopScanActive &&
            errorOffset > job.sourceOffset &&
            errorOffset < job.crossEopScanOffset) {
            if (job.crossEopDeferredErrorOffset == UINT32_MAX ||
                errorOffset < job.crossEopDeferredErrorOffset) {
                job.crossEopDeferredErrorOffset = errorOffset;
                job.crossEopDeferredErrorRc = rc;
                job.crossEopDeferredErrorReason = reason;
                drop_pending_cross_eop_suffix(job, errorOffset);
                AMPR_CRITICAL_LOGF("apr.reactor.crossEop.error.defer job=0x%llx sourceOffset=0x%x errorOffset=0x%x rc=0x%x reason=%s",
                                   (unsigned long long)job.id,
                                   job.sourceOffset,
                                   errorOffset,
                                   rc,
                                   reason ? reason : "unknown");
            }
            return true;
        }
#endif
        set_command_error(job, reason, rc, errorOffset);
        return false;
    }

    bool publish_deferred_cross_eop_error(JobState& job) {
#if AMPR_EMU_APR_AIO_CROSS_EOP_READAHEAD
        if (job.crossEopDeferredErrorOffset == UINT32_MAX ||
            job.sourceOffset < job.crossEopDeferredErrorOffset) {
            return false;
        }
        const uint32_t errorOffset = job.crossEopDeferredErrorOffset;
        const int rc = job.crossEopDeferredErrorRc;
        const char* const reason = job.crossEopDeferredErrorReason;
        job.crossEopDeferredErrorOffset = UINT32_MAX;
        job.crossEopDeferredErrorRc = 0;
        job.crossEopDeferredErrorReason = nullptr;
        set_command_error(job,
                          reason ? reason : "cross-eop-read",
                          rc,
                          errorOffset);
        return true;
#else
        (void)job;
        return false;
#endif
    }

    static bool cross_eop_suffix_is_canceled(const JobState& job,
                                              uint32_t sourceOffset) {
#if AMPR_EMU_APR_AIO_CROSS_EOP_READAHEAD
        return job.crossEopDeferredErrorOffset != UINT32_MAX &&
               sourceOffset >= job.crossEopDeferredErrorOffset;
#else
        (void)job;
        (void)sourceOffset;
        return false;
#endif
    }

    void publish_job_result(JobState& job) {
        if (!job.aprRes) {
            return;
        }
        const int result = job_failed(job) ? job.result.rc : 0;
        const uint32_t errorOffset = job_failed(job) ? job.result.errorOffset : 0;
        job.aprRes->result = result;
        job.aprRes->errorOffset = errorOffset;
        std::atomic_thread_fence(std::memory_order_seq_cst);
        AMPR_TLOGF("apr.reactor.result job=0x%llx mode=%s result=0x%x errorOffset=0x%x commandError=%u res=%p",
                   (unsigned long long)job.id,
                   apr_submit_mode_name(job.submitMode),
                   result,
                   errorOffset,
                   job.hasCommandError ? 1u : 0u,
                   job.aprRes);
    }

    static size_t read_completion_word_index(uint64_t seq) {
        const uint64_t bit = (seq - 1u) % kReadCompletionRingBits;
        return static_cast<size_t>(bit / 64u);
    }

    static uint64_t read_completion_word_mask(uint64_t seq) {
        const uint64_t bit = (seq - 1u) % kReadCompletionRingBits;
        return 1ull << static_cast<unsigned>(bit & 63u);
    }

    static_assert(!apr_read_completion_window_exhausted(
                      kReadCompletionRingBits - 1u,
                      0,
                      kReadCompletionRingBits),
                  "APR completion window must retain its final free bit");
    static_assert(apr_read_completion_window_exhausted(
                      kReadCompletionRingBits,
                      0,
                      kReadCompletionRingBits),
                  "APR completion window must block before bitmap aliasing");

    void mark_seq_complete(JobState& job, uint64_t seq) {
        const uint64_t nextSeq = job.completedReadSeq + 1u;
        if (seq < nextSeq) {
            return;
        }
        if (seq == job.completedReadSeq + 1) {
            job.completedReadSeq = seq;
            for (;;) {
                const uint64_t nextCompleted = job.completedReadSeq + 1u;
                const size_t wordIndex = read_completion_word_index(nextCompleted);
                const uint64_t mask = read_completion_word_mask(nextCompleted);
                if ((job.completedOutOfOrderWords[wordIndex] & mask) == 0) {
                    break;
                }
                job.completedOutOfOrderWords[wordIndex] &= ~mask;
                ++job.completedReadSeq;
            }
        } else if (seq > job.completedReadSeq + 1) {
            if (seq - job.completedReadSeq > kReadCompletionRingBits) {
                AMPR_CRITICAL_LOGF("apr.reactor.read.completion.window job=0x%llx seq=0x%llx completed=0x%llx capacity=%llu",
                                   (unsigned long long)job.id,
                                   (unsigned long long)seq,
                                   (unsigned long long)job.completedReadSeq,
                                   (unsigned long long)kReadCompletionRingBits);
                set_command_error_without_cancel(
                    job,
                    "read-completion-window",
                    SCE_KERNEL_ERROR_EBUSY,
                    job.sourceOffset);
                return;
            }
            job.completedOutOfOrderWords[read_completion_word_index(seq)] |=
                read_completion_word_mask(seq);
        }
    }

    static AprAioReadDesc read_chain_next_desc(const ReadChain& chain) {
        AprAioReadDesc desc = chain.ownerDesc;
        desc.fd = -1;
        desc.cachePinned = false;
        desc.borrowedFd = false;
        desc.buffer = chain.nextBuffer;
        desc.offset = chain.nextOffset;
        desc.length = chain.remaining > kSoftwareReadChunkMax
            ? kSoftwareReadChunkMax
            : chain.remaining;
        return desc;
    }

    static void borrow_read_chain_fd(ReadChain& chain, AprAioReadDesc& desc) {
        desc.fd = chain.ownerDesc.fd;
        desc.bypassFdCache = chain.ownerDesc.bypassFdCache;
        desc.closeAfter = chain.ownerDesc.closeAfter;
        desc.cachePinned = chain.ownerDesc.cachePinned;
        desc.fullFileRead = chain.ownerDesc.fullFileRead;
        desc.borrowedFd = desc.fd >= 0;
    }

    static const AprAioReadDesc& pending_read_fd_desc(const PendingRead& pending) {
        return pending.chain ? pending.chain->ownerDesc : pending.desc;
    }

    void maybe_finish_read_chain(ReadChain* chain) {
        // Error handling can remove the last future slice and retire the chain
        // synchronously. Treat a repeated finish attempt as a no-op instead of
        // touching a slot that has already returned to the fixed pool.
        if (!read_chain_is_live(chain) ||
            chain->pendingCount != 0 || chain->activeCount != 0) {
            return;
        }
        JobPtr job = chain->job;
        if (job && !job_failed(*job) && !chain->allIssued) {
            return;
        }
        const uint64_t seq = chain->seq;
        apr_release_aio_read_desc(chain->ownerDesc);
        if (job && !job_failed(*job)) {
#if AMPR_EMU_DEBUG_LOG && (AMPR_EMU_DEBUG_LOG_VERBOSE || AMPR_EMU_DEBUG_LOG_TRACE)
            ++job->completedReadCount;
#endif
            mark_seq_complete(*job, seq);
        }
        release_read_chain_storage(chain);
    }

#if AMPR_EMU_DEBUG_LOG && (AMPR_EMU_DEBUG_LOG_VERBOSE || AMPR_EMU_DEBUG_LOG_TRACE)
    void log_job_start(JobState& job) {
        if (job.startLogged) {
            return;
        }
        job.startLogged = true;
        const char* firstType = sce::Ampr::ampr_op_name(job.nativeSubmitFirstType);
        AMPR_VLOGF("apr.reactor.start job=0x%llx prio=%u lane=%u commands=%u bytes=0x%x firstType=%s",
                  (unsigned long long)job.id,
                  (unsigned)job.nativePrio,
                  (unsigned)job.prioIndex,
                  job_commands_for_log(job),
                  job.sourceBytes,
                  firstType);
    }

    void log_blocked_job(JobState& job, const Op& op, const char* reason) {
        const size_t opIndex = job_op_index_for_log(job);
        if (job.lastBlockedOpIndex != opIndex || job.lastBlockedReason != reason) {
            job.lastBlockedOpIndex = opIndex;
            job.lastBlockedReason = reason;
            job.blockedLogCount = 0;
        }
        const uint64_t count = ++job.blockedLogCount;
#if AMPR_EMU_DEBUG_LOG_TRACE
        if (count > 4 && (count & 0xfffull) != 0) {
            return;
        }
#else
        if (count < 1024) {
            return;
        }
        if ((count & (count - 1u)) != 0 && (count & 0xffffull) != 0) {
            return;
        }
#endif
        uint64_t waitValue = 0;
        uint64_t waitRef = 0;
        uint32_t waitCmp = 0;
        uint32_t waitFlush = 0;
        uint32_t waitValueKnown = 0;
        uint32_t waitRangeValid = 0;
        uint32_t waitCpuReadable = 0;
        uint32_t waitAmprReadable = 0;
        int waitProtRc = 0;
        int waitProt = 0;
        if (op.type == OpType::WaitOnAddress) {
            waitRef = op.u64a;
            waitCmp = op.u32a;
            waitFlush = op.u32c;
            waitValue = __atomic_load_n(static_cast<const uint64_t*>(op.ptra),
                                        __ATOMIC_RELAXED);
            waitValueKnown = 1;
            waitRangeValid = 1;
            waitCpuReadable = 1;
            waitAmprReadable = 1;
        } else if (op.type == OpType::WaitOnCounter) {
            waitRef = op.u64a;
            waitCmp = op.u32b;
            waitFlush = op.u32c & 1u;
        }
        AMPR_VLOGF("apr.reactor.blocked job=0x%llx reason=%s opIndex=%zu commands=%u type=%s off=0x%x pending=%u active=%u completedSeq=0x%llx latestSeq=0x%llx addr=%p value=0x%llx valueKnown=%u rangeValid=%u cpuReadable=%u amprReadable=%u protRc=0x%x prot=0x%x ref=0x%llx cmp=%u flush=%u count=%llu",
                  (unsigned long long)job.id,
                  reason ? reason : "unknown",
                  opIndex,
                  job_commands_for_log(job),
                  sce::Ampr::ampr_op_name(op.type),
                  op.bufOffsetBytes,
                  job.pendingReadCount,
                  job.activeReadCount,
                  (unsigned long long)job.completedReadSeq,
                  (unsigned long long)job.latestSubmittedReadSeq,
                  op.ptra,
                  (unsigned long long)waitValue,
                  waitValueKnown,
                  waitRangeValid,
                  waitCpuReadable,
                  waitAmprReadable,
                  apr_aio_api_rc_to_sce(waitProtRc),
                  waitProt,
                  (unsigned long long)waitRef,
                  waitCmp,
                  waitFlush,
                  (unsigned long long)count);
    }
#else
    void log_job_start(JobState&) {}
    void log_blocked_job(JobState&, const Op&, const char*) {}
#endif

    bool queue_software_read(JobPtr& job,
                             AprAioReadDesc&& rd,
                             uint32_t errorOff,
                             size_t commandIndex,
                             uint64_t* outSeq = nullptr
#if AMPR_EMU_DEBUG_LOG
                                  ,
                                  uint64_t nativeTriggerTimeNs = 0
#endif
                                  ) {
        if (outSeq) {
            *outSeq = 0;
        }
#if AMPR_EMU_DEBUG_LOG && (AMPR_EMU_DEBUG_LOG_VERBOSE || AMPR_EMU_DEBUG_LOG_TRACE)
        ++job->readOpCount;
#endif
        ReadChain* const chain = allocate_read_chain();
        if (!chain) {
            AMPR_TLOGF("apr.reactor.queueRead.defer job=0x%llx sourceOffset=0x%x reason=read-chain-pool",
                       (unsigned long long)job->id,
                       errorOff);
            return false;
        }
        const uint64_t seq = job->nextReadSeq++;
        job->latestSubmittedReadSeq = seq;
        chain->job = job;
        chain->ownerDesc = ampr_move(rd);
        chain->nextBuffer = chain->ownerDesc.buffer;
        chain->nextOffset = chain->ownerDesc.offset;
        chain->remaining = chain->ownerDesc.length;
        chain->seq = seq;
        chain->commandIndex = commandIndex;
#if AMPR_EMU_DEBUG_LOG
        chain->nativeTriggerTimeNs = nativeTriggerTimeNs;
#endif
        PendingRead pending{};
        pending.job = job;
        pending.desc = read_chain_next_desc(*chain);
        pending.chain = chain;
        pending.seq = seq;
        pending.commandIndex = commandIndex;
#if AMPR_EMU_DEBUG_LOG
        pending.nativeTriggerTimeNs = nativeTriggerTimeNs;
        const uint64_t firstReadQueueTimeNs = time_counter_now();
        pending.pendingEnqueueTimeNs = firstReadQueueTimeNs;
#endif
        const uint64_t queuedLength = chain->ownerDesc.length;
        const uint64_t queuedOffset = chain->ownerDesc.offset;
        const uint32_t queuedFileId = chain->ownerDesc.fileId;
        (void)queuedLength;
        (void)queuedOffset;
        (void)queuedFileId;
#if AMPR_EMU_DEBUG_LOG && AMPR_EMU_DEBUG_LOG_FILE_STATUS
        void* queuedBuffer = chain->ownerDesc.buffer;
#endif
        if (!queue_pending_read(job->prioIndex, ampr_move(pending))) {
            maybe_finish_read_chain(chain);
            return false;
        }
#if AMPR_EMU_DEBUG_LOG
        note_job_queue_to_first_read_queue(*job,
                                           firstReadQueueTimeNs);
#endif
        if (outSeq) {
            *outSeq = seq;
        }
        increment_pending_read_count(job);
        increment_read_chain_pending(chain);
        AMPR_TLOGF("apr.reactor.queueRead job=0x%llx seq=0x%llx prio=%u fileId=%u len=0x%llx off=0x%llx pending=%u kind=direct",
                  (unsigned long long)job->id,
                  (unsigned long long)seq,
                  (unsigned)job->prioIndex,
                  queuedFileId,
                  (unsigned long long)queuedLength,
                  (unsigned long long)queuedOffset,
                  job->pendingReadCount);
#if AMPR_EMU_DEBUG_LOG && AMPR_EMU_DEBUG_LOG_FILE_STATUS
        const char* pathArg = file_path_log_arg(queuedFileId);
        AMPR_FILE_STATUS_LOGF("apr.file.request status=queued job=0x%llx seq=0x%llx prio=%u fileId=%u path=%s buf=%p len=0x%llx off=0x%llx pending=%u kind=direct",
                              (unsigned long long)job->id,
                              (unsigned long long)seq,
                              (unsigned)job->prioIndex,
                              queuedFileId,
                              pathArg,
                              queuedBuffer,
                              (unsigned long long)queuedLength,
                              (unsigned long long)queuedOffset,
                              job->pendingReadCount);
#endif
        return true;
    }

    struct SoftwareRead {
        uint32_t fileId{};
        void* buffer{};
        uint64_t length{};
        uint64_t offset{};
    };

    static bool software_op_is_marker_or_nop(OpType type) {
        return type == OpType::Nop ||
               type == OpType::MarkerSet ||
               type == OpType::MarkerPush ||
               type == OpType::MarkerPop;
    }

    static bool software_op_is_sop(const Op& op) {
        switch (op.type) {
            case OpType::WaitOnAddress:
            case OpType::WaitOnCounter:
                return true;
            case OpType::WriteAddress:
            case OpType::WriteEqueue:
                return op.u8a != 0;
            case OpType::WriteCounter:
                return op.u32c != 0;
            case OpType::WriteAddressFromTimeCounter:
            case OpType::WriteAddressFromCounter:
            case OpType::WriteAddressFromCounterPair:
                return op.u8b != 0;
            default:
                return false;
        }
    }

    static bool software_op_uses_amm(OpType type) {
        switch (type) {
            case OpType::AmmMap:
            case OpType::AmmMapDirect:
            case OpType::AmmUnmap:
            case OpType::AmmRemap:
            case OpType::AmmMultiMap:
            case OpType::AmmModifyProtect:
            case OpType::AmmModifyMtypeProtect:
            case OpType::AmmMapAsPrt:
            case OpType::AmmAllocPaForPrt:
            case OpType::AmmRemapIntoPrt:
            case OpType::AmmUnmapToPrt:
                return true;
            default:
                return false;
        }
    }

    static bool software_op_uses_native_apr_batch(OpType type) {
        switch (type) {
            case OpType::WaitOnCounter:
            case OpType::WriteCounter:
            case OpType::WriteEqueue:
            case OpType::WriteAddressFromTimeCounter:
            case OpType::WriteAddressFromCounter:
            case OpType::WriteAddressFromCounterPair:
                return true;
            default:
                return false;
        }
    }

    static bool software_op_is_native_apr_eop(const Op& op) {
        return software_op_uses_native_apr_batch(op.type) &&
               !software_op_is_sop(op);
    }

    static bool software_op_is_eop_completion(const Op& op) {
        return (op.type == OpType::WriteAddress ||
                software_op_uses_native_apr_batch(op.type)) &&
               !software_op_is_sop(op);
    }

    static bool software_wait_compare(uint64_t observed,
                                      uint64_t reference,
                                      uint32_t compare) {
        switch (static_cast<sce::Ampr::WaitCompare>(compare)) {
            case sce::Ampr::WaitCompare::kEqual:
                return observed == reference;
            case sce::Ampr::WaitCompare::kGreaterThanUnsigned:
                return observed > reference;
            case sce::Ampr::WaitCompare::kLessThanUnsigned:
                return observed < reference;
            case sce::Ampr::WaitCompare::kNotEqual:
                return observed != reference;
            case sce::Ampr::WaitCompare::kGreaterThanOrEqualWrapped:
                return observed - reference <=
                       static_cast<uint64_t>((std::numeric_limits<int64_t>::max)());
            case sce::Ampr::WaitCompare::kGreaterThanSigned:
                return (observed ^ (1ull << 63)) > (reference ^ (1ull << 63));
            case sce::Ampr::WaitCompare::kLessThanSigned:
                return (observed ^ (1ull << 63)) < (reference ^ (1ull << 63));
            default:
                return false;
        }
    }

    bool try_execute_software_address_op(JobState& job,
                                         const Op& op,
                                         bool* outHandled,
                                         bool* outComplete) {
        if (!outHandled || !outComplete) {
            return false;
        }
        *outHandled = false;
        *outComplete = false;
        if (op.type != OpType::WriteAddress &&
            op.type != OpType::WaitOnAddress) {
            return true;
        }
        const uintptr_t addr = reinterpret_cast<uintptr_t>(op.ptra);
        if (addr == 0 || (addr & (alignof(uint64_t) - 1u)) != 0) {
            set_command_error_without_cancel(
                job,
                op.type == OpType::WaitOnAddress
                    ? "software-wait-address-invalid"
                    : "software-write-address-invalid",
                op.type == OpType::WaitOnAddress
                    ? SCE_AMPR_ERROR_APR_INVALIDWAITONADDRESSADDRESS
                    : SCE_AMPR_ERROR_APR_INVALIDWRITEADDRESSSOURCE,
                op.bufOffsetBytes);
            *outHandled = true;
            return false;
        }
        if (op.type == OpType::WaitOnAddress && op.u32a > 6u) {
            set_command_error_without_cancel(job,
                                             "software-wait-compare-invalid",
                                             SCE_AMPR_ERROR_APR_INVALIDCOMMANDDATAFORMAT,
                                             op.bufOffsetBytes);
            *outHandled = true;
            return false;
        }
        auto* const address = static_cast<uint64_t*>(op.ptra);
        *outHandled = true;
        if (op.type == OpType::WriteAddress) {
            __atomic_store_n(address, op.u64a, __ATOMIC_SEQ_CST);
            *outComplete = true;
            AMPR_TLOGF("apr.reactor.software.writeAddress job=0x%llx sourceOffset=0x%x address=%p value=0x%llx mode=%s",
                       (unsigned long long)job.id,
                       op.bufOffsetBytes,
                       op.ptra,
                       (unsigned long long)op.u64a,
                       op.u8a ? "immediate" : "completion");
            return true;
        }
        const uint64_t observed = __atomic_load_n(address, __ATOMIC_ACQUIRE);
        *outComplete = software_wait_compare(observed, op.u64a, op.u32a);
        return true;
    }

    static int resolve_software_read(const GatherScatterState& gs,
                                     const Op& op,
                                     SoftwareRead* out) {
        if (!out) {
            return SCE_KERNEL_ERROR_EINVAL;
        }
        SoftwareRead read{};
        switch (op.type) {
            case OpType::AprReadFile:
                read.fileId = op.u32a;
                read.buffer = op.ptra;
                read.length = op.u64a;
                read.offset = op.u64b;
                break;
            case OpType::AprReadGather:
                if (gs.fileId == 0 || !gs.nextBuffer) {
                    return SCE_AMPR_ERROR_APR_INVALIDGATHERSCATTERSTATE;
                }
                read.fileId = gs.fileId;
                read.buffer = gs.nextBuffer;
                read.length = op.u64a;
                read.offset = op.u64b;
                break;
            case OpType::AprReadScatter:
                if (gs.fileId == 0 || gs.nextOffset == 0) {
                    return SCE_AMPR_ERROR_APR_INVALIDGATHERSCATTERSTATE;
                }
                read.fileId = gs.fileId;
                read.buffer = op.ptra;
                read.length = op.u64a;
                read.offset = gs.nextOffset;
                break;
            case OpType::AprReadGatherScatter:
                if (gs.fileId == 0) {
                    return SCE_AMPR_ERROR_APR_INVALIDGATHERSCATTERSTATE;
                }
                read.fileId = gs.fileId;
                read.buffer = op.ptra;
                read.length = op.u64a;
                read.offset = op.u64b;
                break;
            default:
                return SCE_KERNEL_ERROR_EINVAL;
        }
        *out = read;
        return 0;
    }

    static void update_software_gs_cursor(GatherScatterState& gs,
                                          const SoftwareRead& read) {
        gs.fileId = read.fileId;
        const uint64_t nextOffset = read.offset + read.length;
        gs.nextOffset = nextOffset < kSoftwareReadOffsetMaxExclusive
            ? nextOffset
            : 0;
        gs.nextBuffer = reinterpret_cast<void*>(
            reinterpret_cast<uintptr_t>(read.buffer) +
            static_cast<uintptr_t>(read.length));
    }

    bool issue_software_read(JobPtr& job,
                             GatherScatterState& gs,
                             const SoftwareRead& read,
                             uint32_t opBytes,
                             uint32_t opOffset,
                             size_t commandIndex,
                             bool advanceSource = true,
                             bool deferValidationError = false) {
        if (read.length == 0 || read.length > kSoftwareReadLengthMax) {
            if (!deferValidationError) {
                set_command_error_without_cancel(*job,
                                                 "software-read-length",
                                                 SCE_KERNEL_ERROR_EINVAL,
                                                 opOffset);
            }
            return false;
        }
        const uint64_t readBuffer = reinterpret_cast<uint64_t>(read.buffer);
        if (readBuffer > kSoftwareReadUserVaMax ||
            read.length > kSoftwareReadUserVaMax - readBuffer ||
            read.offset >= kSoftwareReadOffsetMaxExclusive) {
            if (!deferValidationError) {
                set_command_error_without_cancel(*job,
                                                 "software-read-range",
                                                 SCE_KERNEL_ERROR_EINVAL,
                                                 opOffset);
            }
            return false;
        }
        if (apr_read_completion_window_exhausted(
                job->latestSubmittedReadSeq,
                job->completedReadSeq,
                kReadCompletionRingBits)) {
#if AMPR_EMU_DEBUG_LOG
            if (!job->readCompletionWindowBlocked) {
                job->readCompletionWindowBlocked = true;
                AMPR_LOGF("apr.reactor.read.completion.backpressure job=0x%llx sourceOffset=0x%x nextSeq=0x%llx latest=0x%llx completed=0x%llx capacity=%llu pending=%u active=%u",
                          (unsigned long long)job->id,
                          opOffset,
                          (unsigned long long)job->nextReadSeq,
                          (unsigned long long)job->latestSubmittedReadSeq,
                          (unsigned long long)job->completedReadSeq,
                          (unsigned long long)kReadCompletionRingBits,
                          job->pendingReadCount,
                          job->activeReadCount);
            }
#endif
            return false;
        }
#if AMPR_EMU_DEBUG_LOG
        job->readCompletionWindowBlocked = false;
#endif
        if (pendingReadFree.count == 0 || readChainFreeHead == UINT32_MAX) {
            AMPR_TLOGF("apr.reactor.queueRead.defer job=0x%llx sourceOffset=0x%x free=%u pending=%zu",
                       (unsigned long long)job->id,
                       opOffset,
                       pendingReadFree.count,
                       pending_read_total());
            return false;
        }
        AprAioReadDesc logicalRead{};
        int prepareRc = 0;
        uint32_t prepareErrorOffset = opOffset;
        if (!apr_prepare_aio_read_desc(job->id,
                                       read.fileId,
                                       read.buffer,
                                       read.length,
                                       read.offset,
                                       opOffset,
                                       false,
                                       &logicalRead,
                                       &prepareRc,
                                       &prepareErrorOffset)) {
            if (!deferValidationError) {
                set_command_error_without_cancel(*job,
                                                 "software-read-prepare",
                                                 prepareRc,
                                                 prepareErrorOffset);
            }
            return false;
        }
        apr_update_read_desc_fd_policy(logicalRead);
        JobPtr queuedJob = job;
        if (!queue_software_read(queuedJob,
                                 ampr_move(logicalRead),
                                 opOffset,
                                 commandIndex)) {
            return false;
        }
        if (job_failed(*job)) {
            return false;
        }
        update_software_gs_cursor(gs, read);
        if (advanceSource) {
            advance_job_source(*job, opBytes);
        }
        return true;
    }

#if AMPR_EMU_APR_AIO_CROSS_EOP_READAHEAD
    bool issue_reads_across_eop(JobPtr& job, GatherScatterState& gs) {
        if (!job || job_failed(*job) ||
            job->crossEopDeferredErrorOffset != UINT32_MAX) {
            return false;
        }
        if (!job->crossEopScanActive ||
            job->crossEopScanOffset < job->sourceOffset) {
            if (job->crossEopFenceCount != 0) {
                AMPR_CRITICAL_LOGF("apr.reactor.crossEop.scan.reset.invalid job=0x%llx sourceOffset=0x%x scanOffset=0x%x fences=%u action=abort",
                                   (unsigned long long)job->id,
                                   job->sourceOffset,
                                   job->crossEopScanOffset,
                                   job->crossEopFenceCount);
                std::abort();
            }
            job->crossEopScanOffset = job->sourceOffset;
            job->crossEopScanCommandIndex = job->sourceCommandIndex;
            job->crossEopScanActive = true;
        }

        bool progressed = false;
        uint32_t issuedReads = 0;
        uint32_t crossedBoundaries = 0;
        while (job->crossEopScanOffset < job->sourceBytes &&
               job->crossEopScanCommandIndex < job->commandCount &&
               issuedReads < AMPR_EMU_APR_AIO_CROSS_EOP_READS_PER_PASS &&
               crossedBoundaries < AMPR_EMU_APR_AIO_CROSS_EOP_MAX_FENCES) {
            Op op{};
            uint32_t opBytes = 0;
            uint32_t errorOffset = job->crossEopScanOffset;
            const int decodeRc = sce::Ampr::ampr_decode_apr_packed_op(
                job->sourceBuffer,
                job->sourceBytes,
                job->crossEopScanOffset,
                &op,
                &opBytes,
                &errorOffset);
            if (decodeRc != 0 || opBytes == 0 ||
                opBytes > job->sourceBytes - job->crossEopScanOffset) {
                break;
            }
            op.bufOffsetBytes = job->crossEopScanOffset;

            if (software_op_is_eop_completion(op)) {
                if (!push_cross_eop_fence(*job,
                                          op.bufOffsetBytes,
                                          job->latestSubmittedReadSeq)) {
                    break;
                }
                job->crossEopScanOffset += opBytes;
                ++job->crossEopScanCommandIndex;
                ++crossedBoundaries;
                progressed = true;
                continue;
            }
            if (op.type == OpType::WaitOnAddress) {
                const uintptr_t address =
                    reinterpret_cast<uintptr_t>(op.ptra);
                if (address == 0 ||
                    (address & (alignof(uint64_t) - 1u)) != 0 ||
                    op.u32a > 6u) {
                    break;
                }
                const uint64_t observed = __atomic_load_n(
                    static_cast<const uint64_t*>(op.ptra),
                    __ATOMIC_ACQUIRE);
                if (!software_wait_compare(observed, op.u64a, op.u32a)) {
                    break;
                }
                job->crossEopScanOffset += opBytes;
                ++job->crossEopScanCommandIndex;
                ++crossedBoundaries;
                progressed = true;
                AMPR_TLOGF("apr.reactor.crossEop.waitAddress.pass job=0x%llx sourceOffset=0x%x commandIndex=%u observed=0x%llx reference=0x%llx compare=%u scanOffset=0x%x",
                           (unsigned long long)job->id,
                           op.bufOffsetBytes,
                           job->crossEopScanCommandIndex - 1u,
                           (unsigned long long)observed,
                           (unsigned long long)op.u64a,
                           op.u32a,
                           job->crossEopScanOffset);
                continue;
            }
            if (!cb_op_is_apr_read(op.type)) {
                break;
            }

            SoftwareRead read{};
            if (resolve_software_read(gs, op, &read) != 0 ||
                !issue_software_read(job,
                                     gs,
                                     read,
                                     opBytes,
                                     op.bufOffsetBytes,
                                     job->crossEopScanCommandIndex,
                                     false,
                                     true)) {
                break;
            }
            job->crossEopScanOffset += opBytes;
            ++job->crossEopScanCommandIndex;
            ++issuedReads;
            progressed = true;
            AMPR_TLOGF("apr.reactor.crossEop.read job=0x%llx sourceOffset=0x%x commandIndex=%u seq=0x%llx scanOffset=0x%x fences=%u",
                       (unsigned long long)job->id,
                       op.bufOffsetBytes,
                       job->crossEopScanCommandIndex - 1u,
                       (unsigned long long)job->latestSubmittedReadSeq,
                       job->crossEopScanOffset,
                       job->crossEopFenceCount);
        }
        return progressed;
    }
#endif

    static void reset_software_gs_cursor(GatherScatterState& gs) {
        gs = {};
    }

    static bool native_batch_token_reached(uint64_t observed, uint64_t target) {
        return observed - target <=
               static_cast<uint64_t>((std::numeric_limits<int64_t>::max)());
    }

    int native_batch_result(const AprNativeBatchSlot& slot) const {
        return __atomic_load_n(&slot.result.result, __ATOMIC_ACQUIRE);
    }

    void reset_native_batch_buffer(uint32_t laneIndex,
                                   uint32_t bufferIndex,
                                   uint32_t nativeSubmitType) {
        NativeBatchState& state = nativeBatchLanes[laneIndex].buffers[bufferIndex];
        AprNativeBatchSlot* const slot =
            apr_native_batch_slot(laneIndex, bufferIndex);
        if (!slot || state.phase != NativeBatchPhase::Free) {
            AMPR_CRITICAL_LOGF("apr.reactor.native.batch.reset.invalid lane=%u buffer=%u slot=%p phase=%u",
                               laneIndex,
                               bufferIndex,
                               slot,
                               static_cast<unsigned>(state.phase));
            std::abort();
        }
        __atomic_store_n(&slot->release, 0ull, __ATOMIC_RELAXED);
        __atomic_store_n(&slot->progress, 0ull, __ATOMIC_RELAXED);
        slot->result.errorOffset = 0;
        __atomic_store_n(&slot->result.result,
                         kAprNativeBatchResultPending,
                         __ATOMIC_RELAXED);
        ++state.generation;
        if (state.generation == 0) {
            state.generation = 1;
        }
        state.nextGroup = 0;
        state.openGroupPackets = 0;
        state.packetCount = 0;
        state.nativeSubmitType = nativeSubmitType;
        state.observedProgress = 0;
        state.firstSequence = 0;
        state.lastSequence = 0;
        state.submitTimeNs = 0;
        state.lastReleaseTimeNs = 0;
        state.lastWatchdogTimeNs = 0;
        state.submitId = 0;
        state.phase = NativeBatchPhase::Filling;
    }

    bool has_live_synthetic_waits_locked() const {
        for (const SyntheticWaitSlot& slot : syntheticWaitSlots) {
            if (slot.active) {
                return true;
            }
        }
        return false;
    }

    bool submit_native_batch_buffer(uint32_t laneIndex, uint32_t bufferIndex) {
        NativeBatchLane& lane = nativeBatchLanes[laneIndex];
        NativeBatchState& state = lane.buffers[bufferIndex];
        AprNativeBatchSlot* const slot =
            apr_native_batch_slot(laneIndex, bufferIndex);
        if (!slot || state.phase != NativeBatchPhase::Filling ||
            state.nextGroup == 0 || state.openGroupPackets != 0 ||
            lane.activeBuffer >= 0) {
            return false;
        }

        NativeAprCommandBufferView nativeCommandBuffer{};
        nativeCommandBuffer.m_commandBuffer.type =
            static_cast<int>(state.nativeSubmitType);
        nativeCommandBuffer.m_commandBuffer.offset = kAprNativeBatchBufferBytes;
        nativeCommandBuffer.m_commandBuffer.num =
            static_cast<int32_t>(kAprNativeBatchCommandCount);
        nativeCommandBuffer.m_commandBuffer.bufsize = kAprNativeBatchBufferBytes;
        nativeCommandBuffer.m_commandBuffer.buffer = slot->commands;
        slot->result.errorOffset = 0;
        __atomic_store_n(&slot->result.result,
                         kAprNativeBatchResultPending,
                         __ATOMIC_RELAXED);
        std::atomic_thread_fence(std::memory_order_seq_cst);

        int submitRcRaw = 0;
        SceAprSubmitId submitId = 0;
        auto* const nativeCommandBufferPtr =
            reinterpret_cast<sce::Ampr::AprCommandBuffer*>(&nativeCommandBuffer);
        const int dispatchRc = apr_native_submit_dispatch(
            nativeCommandBufferPtr,
            laneIndex,
            AprSubmitMode::kSubmitAndGetResult,
            &slot->result,
            &submitId,
            &submitRcRaw);
        const int submitRc = dispatchRc != 0
            ? dispatchRc
            : apr_libkernel_rc_to_sce(submitRcRaw);
        if (submitRc != 0) {
            AMPR_CRITICAL_LOGF("apr.reactor.native.batch.submit.fail lane=%u buffer=%u generation=%u groups=%u packets=%u bytes=0x%x commands=%u rc=0x%x raw=0x%x errno=%d",
                               laneIndex,
                               bufferIndex,
                               state.generation,
                               state.nextGroup,
                               state.packetCount,
                               kAprNativeBatchBufferBytes,
                               kAprNativeBatchCommandCount,
                               submitRc,
                               submitRcRaw,
                               errno);
            return false;
        }
        state.submitId = submitId;
        state.submitTimeNs = time_counter_now();
        if (state.lastReleaseTimeNs < state.submitTimeNs) {
            state.lastReleaseTimeNs = state.submitTimeNs;
        }
        state.phase = NativeBatchPhase::Active;
        lane.activeBuffer = static_cast<int8_t>(bufferIndex);
        AMPR_TLOGF("apr.reactor.native.batch.submit lane=%u buffer=%u generation=%u groups=%u packets=%u submitId=0x%x bytes=0x%x commands=%u release=0x%llx",
                   laneIndex,
                   bufferIndex,
                   state.generation,
                   state.nextGroup,
                   state.packetCount,
                   submitId,
                   kAprNativeBatchBufferBytes,
                   kAprNativeBatchCommandCount,
                   (unsigned long long)__atomic_load_n(&slot->release,
                                                       __ATOMIC_RELAXED));
        return true;
    }

    static bool native_batch_sequence_reached(uint64_t completed,
                                              uint64_t target) {
        return completed - target <=
               static_cast<uint64_t>((std::numeric_limits<int64_t>::max)());
    }

    bool native_batch_wait_pending(uint32_t laneIndex) {
        if (laneIndex >= kPriorityCount) {
            return false;
        }
        NativeBatchLane& lane = nativeBatchLanes[laneIndex];
        if (lane.blockingWaitSequence == 0) {
            return false;
        }
        if (!native_batch_sequence_reached(lane.completedSequence,
                                           lane.blockingWaitSequence)) {
            return true;
        }
        lane.blockingWaitSequence = 0;
        return false;
    }

    bool seal_native_apr_batch_group(uint32_t laneIndex,
                                     uint32_t bufferIndex,
                                     bool releaseGroup = true) {
        NativeBatchLane& lane = nativeBatchLanes[laneIndex];
        NativeBatchState& state = lane.buffers[bufferIndex];
        if (state.openGroupPackets == 0) {
            return true;
        }
        if (state.nextGroup >= kAprNativeBatchGroupCount ||
            state.openGroupPackets > kAprNativeBatchPacketsPerGroup) {
            return false;
        }

        AprNativeBatchSlot* const slot =
            apr_native_batch_slot(laneIndex, bufferIndex);
        if (!slot) {
            return false;
        }
        const uint32_t groupIndex = state.nextGroup;
        const uint32_t unusedPacketCount =
            kAprNativeBatchPacketsPerGroup - state.openGroupPackets;
        if (unusedPacketCount != 0) {
            const uint32_t usedPayloadBytes =
                state.openGroupPackets * kAprNativeBatchPayloadSlotBytes;
            std::memcpy(
                slot->commands + groupIndex * kAprNativeBatchGroupBytes +
                    kAprNativeBatchGateBytes + usedPayloadBytes,
                slot->defaultPayload + usedPayloadBytes,
                unusedPacketCount * kAprNativeBatchPayloadSlotBytes);
        }
        const uint64_t token = apr_native_batch_token(groupIndex);

        const uint64_t groupSequence = lane.issuedSequence + 1u;
        if (groupSequence == 0) {
            return false;
        }
        lane.issuedSequence = groupSequence;
        if (state.nextGroup == 0) {
            state.firstSequence = groupSequence;
        }
        state.lastSequence = groupSequence;
        ++state.nextGroup;
        state.openGroupPackets = 0;
        if (releaseGroup) {
            const uint64_t releaseTimeNs = time_counter_now();
            state.lastReleaseTimeNs = releaseTimeNs;
            std::atomic_thread_fence(std::memory_order_seq_cst);
            __atomic_store_n(&slot->release, token, __ATOMIC_RELEASE);
        }

        if (state.phase == NativeBatchPhase::Filling && lane.activeBuffer < 0 &&
            !submit_native_batch_buffer(laneIndex, bufferIndex)) {
            return false;
        }
        AMPR_TLOGF("apr.reactor.native.batch.group.seal lane=%u buffer=%u generation=%u group=%u packets=%u token=0x%llx sequence=%llu released=%u phase=%u",
                   laneIndex,
                   bufferIndex,
                   state.generation,
                   groupIndex,
                   state.packetCount,
                   (unsigned long long)token,
                   (unsigned long long)groupSequence,
                   releaseGroup ? 1u : 0u,
                   static_cast<unsigned>(state.phase));
        return true;
    }

    bool seal_open_native_apr_batch_group(uint32_t laneIndex) {
        NativeBatchLane& lane = nativeBatchLanes[laneIndex];
        for (uint32_t bufferIndex = 0;
             bufferIndex < kAprNativeBatchBufferCountPerLane;
             ++bufferIndex) {
            if (lane.buffers[bufferIndex].openGroupPackets != 0) {
                return seal_native_apr_batch_group(laneIndex, bufferIndex);
            }
        }
        return true;
    }

    bool release_deferred_native_eop(JobState& job, bool cancelPacket) {
        if (!job.nativeBatchReleasePending ||
            job.prioIndex >= kPriorityCount) {
            return false;
        }
        NativeBatchLane& lane = nativeBatchLanes[job.prioIndex];
        if (lane.deferredReleaseSequence == 0 ||
            lane.deferredReleaseSequence != job.nativeBatchSequence ||
            lane.deferredReleaseJobId != job.id ||
            lane.deferredReleaseBufferIndex >=
                kAprNativeBatchBufferCountPerLane) {
            AMPR_CRITICAL_LOGF("apr.reactor.native.batch.deferred.invalid job=0x%llx lane=%u jobSequence=%llu laneSequence=%llu owner=0x%llx buffer=%u group=%u action=abort",
                               (unsigned long long)job.id,
                               job.prioIndex,
                               (unsigned long long)job.nativeBatchSequence,
                               (unsigned long long)lane.deferredReleaseSequence,
                               (unsigned long long)lane.deferredReleaseJobId,
                               lane.deferredReleaseBufferIndex,
                               lane.deferredReleaseGroupIndex);
            std::abort();
        }

        const uint32_t bufferIndex = lane.deferredReleaseBufferIndex;
        const uint32_t groupIndex = lane.deferredReleaseGroupIndex;
        NativeBatchState& state = lane.buffers[bufferIndex];
        AprNativeBatchSlot* const slot =
            apr_native_batch_slot(job.prioIndex, bufferIndex);
        if (!slot || state.phase == NativeBatchPhase::Free ||
            groupIndex >= state.nextGroup ||
            groupIndex >= kAprNativeBatchGroupCount ||
            state.firstSequence + groupIndex !=
                lane.deferredReleaseSequence) {
            AMPR_CRITICAL_LOGF("apr.reactor.native.batch.deferred.state.invalid job=0x%llx lane=%u buffer=%u group=%u phase=%u groups=%u firstSequence=%llu sequence=%llu action=abort",
                               (unsigned long long)job.id,
                               job.prioIndex,
                               bufferIndex,
                               groupIndex,
                               static_cast<unsigned>(state.phase),
                               state.nextGroup,
                               (unsigned long long)state.firstSequence,
                               (unsigned long long)lane.deferredReleaseSequence);
            std::abort();
        }

        if (cancelPacket) {
            std::memcpy(slot->commands +
                            groupIndex * kAprNativeBatchGroupBytes +
                            kAprNativeBatchGateBytes,
                        slot->defaultPayload,
                        kAprNativeBatchPayloadRegionBytes);
        }
        const uint64_t token = apr_native_batch_token(groupIndex);
        const uint64_t releaseTimeNs = time_counter_now();
        state.lastReleaseTimeNs = releaseTimeNs;
        job.nativeSubmitTimeNs = releaseTimeNs;
        std::atomic_thread_fence(std::memory_order_seq_cst);
        __atomic_store_n(&slot->release, token, __ATOMIC_RELEASE);
        AMPR_TLOGF("apr.reactor.native.batch.deferred.release job=0x%llx lane=%u buffer=%u generation=%u group=%u token=0x%llx sequence=%llu canceled=%u",
                   (unsigned long long)job.id,
                   job.prioIndex,
                   bufferIndex,
                   state.generation,
                   groupIndex,
                   (unsigned long long)token,
                   (unsigned long long)lane.deferredReleaseSequence,
                   cancelPacket ? 1u : 0u);
        lane.deferredReleaseSequence = 0;
        lane.deferredReleaseJobId = 0;
        lane.deferredReleaseBufferIndex = 0;
        lane.deferredReleaseGroupIndex = 0;
        job.nativeBatchReleasePending = false;
        job.nativeBatchReleaseAfterSoftwareAddress = false;
        job.nativeBatchLookaheadPriorSequence = 0;
        job.nativeBatchReleaseReadSequence = 0;
        return true;
    }

    bool prepare_native_batches_for_shutdown() {
        if (!nativeExecutionPoolReady) {
            return true;
        }
        for (uint32_t laneIndex = 0; laneIndex < kPriorityCount; ++laneIndex) {
            NativeBatchLane& lane = nativeBatchLanes[laneIndex];
            if (lane.deferredReleaseSequence != 0) {
                continue;
            }
            if (!seal_open_native_apr_batch_group(laneIndex)) {
                return false;
            }
            for (uint32_t bufferIndex = 0;
                 bufferIndex < kAprNativeBatchBufferCountPerLane;
                 ++bufferIndex) {
                NativeBatchState& state = lane.buffers[bufferIndex];
                if (state.phase == NativeBatchPhase::Free) {
                    continue;
                }
                if (state.nextGroup == 0) {
                    if (state.packetCount != 0) {
                        return false;
                    }
                    state.phase = NativeBatchPhase::Free;
                    continue;
                }
                if (state.nextGroup > kAprNativeBatchGroupCount ||
                    state.openGroupPackets != 0) {
                    return false;
                }
                AprNativeBatchSlot* const slot =
                    apr_native_batch_slot(laneIndex, bufferIndex);
                if (!slot) {
                    return false;
                }
                if (state.nextGroup < kAprNativeBatchGroupCount) {
                    for (uint32_t group = state.nextGroup;
                         group < kAprNativeBatchGroupCount;
                         ++group) {
                        const uint32_t payloadOffset =
                            group * kAprNativeBatchGroupBytes +
                            kAprNativeBatchGateBytes;
                        std::memcpy(slot->commands + payloadOffset,
                                    slot->defaultPayload,
                                    kAprNativeBatchPayloadRegionBytes);
                        const uint64_t sequence = lane.issuedSequence + 1u;
                        if (sequence == 0) {
                            return false;
                        }
                        lane.issuedSequence = sequence;
                        state.lastSequence = sequence;
                    }
                    state.nextGroup = kAprNativeBatchGroupCount;
                    state.lastReleaseTimeNs = time_counter_now();
                    std::atomic_thread_fence(std::memory_order_seq_cst);
                    __atomic_store_n(
                        &slot->release,
                        apr_native_batch_token(kAprNativeBatchGroupCount - 1u),
                        __ATOMIC_RELEASE);
                }
                if (state.phase == NativeBatchPhase::Filling &&
                    lane.activeBuffer < 0 &&
                    !submit_native_batch_buffer(laneIndex, bufferIndex)) {
                    return false;
                }
            }
        }
        return true;
    }

    bool native_batches_idle() const {
        if (!nativeExecutionPoolReady) {
            return true;
        }
        for (const NativeBatchLane& lane : nativeBatchLanes) {
            if (lane.activeBuffer >= 0) {
                return false;
            }
            for (const NativeBatchState& state : lane.buffers) {
                if (state.phase != NativeBatchPhase::Free) {
                    return false;
                }
            }
        }
        return true;
    }

    bool append_native_apr_batch(JobState& job,
                                 const Op& op,
                                 const void* packedSource,
                                 uint32_t packedBytes,
                                 bool deferRelease = false,
                                 uint64_t releaseReadSequence = 0) {
        if (!ensure_native_execution_pool()) {
            set_fail(job, "native-batch-pool", SCE_KERNEL_ERROR_ENOMEM,
                     op.bufOffsetBytes);
            return false;
        }
        if (!packedSource || packedBytes < 4u || packedBytes > 20u ||
            (packedBytes & 3u) != 0) {
            set_fail(job, "native-batch-command-size", SCE_KERNEL_ERROR_EINVAL,
                     op.bufOffsetBytes);
            return false;
        }

        NativeBatchLane& lane = nativeBatchLanes[job.prioIndex];
        if (deferRelease) {
            if (!software_op_is_native_apr_eop(op) ||
                lane.deferredReleaseSequence != 0) {
                AMPR_CRITICAL_LOGF("apr.reactor.native.batch.deferred.append.invalid job=0x%llx lane=%u type=%s sop=%u pendingSequence=%llu readSequence=%llu action=abort",
                                   (unsigned long long)job.id,
                                   job.prioIndex,
                                   sce::Ampr::ampr_op_name(op.type),
                                   software_op_is_sop(op) ? 1u : 0u,
                                   (unsigned long long)lane.deferredReleaseSequence,
                                   (unsigned long long)releaseReadSequence);
                std::abort();
            }
            // Do not make earlier SOP packets share the read-dependent gate.
            // Release their open group before dedicating one gated group to
            // the completion packet.
            if (!seal_open_native_apr_batch_group(job.prioIndex)) {
                return false;
            }
        }
        int bufferIndex = lane.activeBuffer;
        if (bufferIndex >= 0) {
            NativeBatchState& active = lane.buffers[bufferIndex];
            if (active.phase != NativeBatchPhase::Active ||
                active.nextGroup >= kAprNativeBatchGroupCount) {
                bufferIndex = -1;
            }
        }
        if (bufferIndex < 0) {
            for (uint32_t candidate = 0;
                 candidate < kAprNativeBatchBufferCountPerLane;
                 ++candidate) {
                NativeBatchState& state = lane.buffers[candidate];
                if (state.phase == NativeBatchPhase::Filling &&
                    state.nextGroup < kAprNativeBatchGroupCount) {
                    bufferIndex = static_cast<int>(candidate);
                    break;
                }
            }
        }
        if (bufferIndex < 0) {
            for (uint32_t candidate = 0;
                 candidate < kAprNativeBatchBufferCountPerLane;
                 ++candidate) {
                NativeBatchState& state = lane.buffers[candidate];
                if (state.phase == NativeBatchPhase::Free) {
                    reset_native_batch_buffer(job.prioIndex,
                                              candidate,
                                              static_cast<uint32_t>(
                                                  job.nativeSubmitType));
                    bufferIndex = static_cast<int>(candidate);
                    break;
                }
            }
        }
        if (bufferIndex < 0) {
            return false;
        }

        NativeBatchState& state = lane.buffers[bufferIndex];
        if (state.nativeSubmitType !=
            static_cast<uint32_t>(job.nativeSubmitType)) {
            AMPR_CRITICAL_LOGF("apr.reactor.native.batch.type.mismatch lane=%u buffer=%d have=%u requested=%u",
                               job.prioIndex,
                               bufferIndex,
                               state.nativeSubmitType,
                               static_cast<uint32_t>(job.nativeSubmitType));
            std::abort();
        }
        AprNativeBatchSlot* const slot =
            apr_native_batch_slot(job.prioIndex,
                                  static_cast<uint32_t>(bufferIndex));
        if (!slot || state.nextGroup >= kAprNativeBatchGroupCount ||
            state.openGroupPackets >= kAprNativeBatchPacketsPerGroup ||
            (deferRelease && state.openGroupPackets != 0)) {
            return false;
        }

        const uint32_t groupIndex = state.nextGroup;
        const uint32_t packetIndex = state.openGroupPackets;
        const uint32_t groupOffset = groupIndex * kAprNativeBatchGroupBytes;
        const uint32_t payloadOffset =
            groupOffset + kAprNativeBatchGateBytes +
            packetIndex * kAprNativeBatchPayloadSlotBytes;
        const uint32_t paddingBytes =
            kAprNativeBatchPayloadSlotBytes - packedBytes;
        std::memcpy(slot->commands + payloadOffset, packedSource, packedBytes);
        const uint32_t paddingHeaderIndex = paddingBytes / 4u - 1u;
        std::memcpy(slot->commands + payloadOffset + packedBytes,
                    &nativeBatchPaddingHeaders[paddingHeaderIndex],
                    sizeof(uint32_t));

        ++state.openGroupPackets;
        ++state.packetCount;
        const uint64_t groupSequence = lane.issuedSequence + 1u;
        if (groupSequence == 0) {
            std::abort();
        }
        if (op.type == OpType::WaitOnCounter) {
            lane.blockingWaitSequence = groupSequence;
        }

        job.nativeMicroEngine = NativeMicroEngine::AprBatch;
        job.nativeBatchSequence = groupSequence;
        job.nativeCompletionAddress = nullptr;
        job.nativeCommandBuffer = nullptr;
        job.nativeCommandBufferBytes = 0;
        job.nativeSubmitBytes = packedBytes;
        job.nativeSubmitFirstType = op.type;
        job.nativeSourceOffset = op.bufOffsetBytes;
        job.nativeSourceType = op.type;
        job.nativeSubmitTimeNs = state.phase == NativeBatchPhase::Active
            ? time_counter_now()
            : 0;
        job.nativeSubmitted.store(true, std::memory_order_release);

        const bool mustSeal =
            state.openGroupPackets == kAprNativeBatchPacketsPerGroup ||
            op.type == OpType::WaitOnCounter || deferRelease;
        if (mustSeal &&
            !seal_native_apr_batch_group(job.prioIndex,
                                         static_cast<uint32_t>(bufferIndex),
                                         !deferRelease)) {
            AMPR_CRITICAL_LOGF("apr.reactor.native.batch.group.seal.fail job=0x%llx lane=%u buffer=%d sourceOffset=0x%x sourceType=%s deferred=%u",
                               (unsigned long long)job.id,
                               job.prioIndex,
                               bufferIndex,
                               op.bufOffsetBytes,
                               sce::Ampr::ampr_op_name(op.type),
                               deferRelease ? 1u : 0u);
            std::abort();
        }
        if (deferRelease) {
            lane.deferredReleaseSequence = groupSequence;
            lane.deferredReleaseJobId = job.id;
            lane.deferredReleaseBufferIndex =
                static_cast<uint32_t>(bufferIndex);
            lane.deferredReleaseGroupIndex = groupIndex;
            job.nativeBatchReleasePending = true;
            job.nativeBatchReleaseAfterSoftwareAddress = false;
            job.nativeBatchLookaheadPriorSequence = 0;
            job.nativeBatchReleaseReadSequence = releaseReadSequence;
            reset_publish_gating_active_aio_poll_backoff_for_lane(
                job.prioIndex, time_counter_now());
        }
        AMPR_TLOGF("apr.reactor.native.batch.append job=0x%llx lane=%u buffer=%d generation=%u group=%u packet=%u token=0x%llx sequence=%llu type=%s bytes=0x%x phase=%u",
                   (unsigned long long)job.id,
                   job.prioIndex,
                   bufferIndex,
                   state.generation,
                   groupIndex,
                   packetIndex,
                   (unsigned long long)apr_native_batch_token(groupIndex),
                   (unsigned long long)groupSequence,
                   sce::Ampr::ampr_op_name(op.type),
                   packedBytes,
                   static_cast<unsigned>(state.phase));
        return true;
    }

    bool prepare_native_micro_pair(JobState& job,
                                   const Op& firstOp,
                                   const void* packedSource,
                                   uint32_t packedBytes,
                                   bool encodeFirst) {
        if (!ensure_native_micro_slot(job, firstOp.bufOffsetBytes)) {
            return false;
        }
        AprNativeMicroSlot* const slot = apr_native_micro_slot(job.poolSlot);
        if (!slot || !job.nativeCommandBuffer ||
            job.nativeCommandBuffer != slot->commands) {
            set_fail(job, "native-micro-slot", SCE_KERNEL_ERROR_EINVAL,
                     firstOp.bufOffsetBytes);
            return false;
        }

        uint32_t firstBytes = packedBytes;
        if (encodeFirst) {
            uint64_t measuredBytes = 0;
            int sizeRc = SCE_KERNEL_ERROR_EINVAL;
            if (firstOp.type == OpType::AmmMap) {
                sizeRc = sce::Ampr::Emu::ammWriteMapCommand2(
                    nullptr,
                    firstOp.u64a,
                    firstOp.u64b,
                    firstOp.u32b,
                    firstOp.u32a,
                    0,
                    &measuredBytes);
            } else if (firstOp.type == OpType::AmmMapDirect) {
                sizeRc = sce::Ampr::Emu::ammWriteMapDirectCommand(
                    nullptr,
                    firstOp.u64a,
                    firstOp.u64b,
                    firstOp.u64c,
                    firstOp.u32b,
                    firstOp.u32a,
                    &measuredBytes);
            }
            if (sizeRc != 0 || measuredBytes == 0 || measuredBytes > UINT32_MAX) {
                set_fail(job,
                         "native-micro-size",
                         sizeRc != 0 ? sizeRc : SCE_KERNEL_ERROR_EINVAL,
                         firstOp.bufOffsetBytes);
                return false;
            }
            firstBytes = static_cast<uint32_t>(measuredBytes);
            if (firstBytes > sizeof(slot->commands)) {
                set_fail(job, "native-micro-size", SCE_KERNEL_ERROR_EBUSY,
                         firstOp.bufOffsetBytes);
                return false;
            }
            int writeRc = SCE_KERNEL_ERROR_EINVAL;
            if (firstOp.type == OpType::AmmMap) {
                writeRc = sce::Ampr::Emu::ammWriteMapCommand2(
                    slot->commands,
                    firstOp.u64a,
                    firstOp.u64b,
                    firstOp.u32b,
                    firstOp.u32a,
                    0,
                    nullptr);
            } else if (firstOp.type == OpType::AmmMapDirect) {
                writeRc = sce::Ampr::Emu::ammWriteMapDirectCommand(
                    slot->commands,
                    firstOp.u64a,
                    firstOp.u64b,
                    firstOp.u64c,
                    firstOp.u32b,
                    firstOp.u32a,
                    nullptr);
            }
            if (writeRc != 0) {
                set_fail(job, "native-micro-encode", writeRc,
                         firstOp.bufOffsetBytes);
                return false;
            }
        } else {
            if (!packedSource || firstBytes == 0 ||
                firstBytes > sizeof(slot->commands)) {
                set_fail(job, "native-micro-copy", SCE_KERNEL_ERROR_EINVAL,
                         firstOp.bufOffsetBytes);
                return false;
            }
            std::memcpy(slot->commands, packedSource, firstBytes);
        }

        if (firstBytes < 4u || firstBytes > 20u || (firstBytes & 3u) != 0 ||
            firstBytes > sizeof(slot->commands) - kAprNativeMicroCompletionBytes) {
            set_fail(job, "native-micro-template", SCE_KERNEL_ERROR_EINVAL,
                     firstOp.bufOffsetBytes);
            return false;
        }
        std::memcpy(slot->commands + firstBytes,
                    slot->completionTemplate,
                    kAprNativeMicroCompletionBytes);
        slot->completion = 0;
        std::atomic_thread_fence(std::memory_order_seq_cst);
        job.nativeCompletionAddress = &slot->completion;
        job.nativeSubmitBytes = firstBytes + kAprNativeMicroCompletionBytes;
        job.nativeSubmitFirstType = firstOp.type;
        job.nativeSourceOffset = firstOp.bufOffsetBytes;
        job.nativeSourceType = firstOp.type;
        job.nativeSubmitTimeNs = 0;
        return true;
    }

    bool submit_native_micro(JobState& job, NativeMicroEngine engine) {
        job.nativeMicroEngine = engine;
        bool submitted = false;
        if (engine == NativeMicroEngine::Amm) {
            const int submitRc = sce::Ampr::Emu::ammSubmitCommandBufferLeaf(
                reinterpret_cast<uint64_t>(job.nativeCommandBuffer),
                job.nativeSubmitBytes,
                0u,
                nullptr);
            if (submitRc == 0) {
                submitted = true;
            } else {
                set_fail(job, "native-amm-submit", submitRc, job.nativeSourceOffset);
            }
        }
        if (!submitted) {
            if (job_failed(job)) {
                job.result.errorOffset = job.nativeSourceOffset;
            }
            job.nativeMicroEngine = NativeMicroEngine::None;
            return false;
        }
        job.nativeSubmitTimeNs = time_counter_now();
        job.nativeSubmitted.store(true, std::memory_order_release);
        AMPR_TLOGF("apr.reactor.native.micro.submit job=0x%llx sourceOffset=0x%x sourceType=%s engine=%s aprPrio=%u nativePrio=%u bytes=0x%x completion=%p",
                   (unsigned long long)job.id,
                   job.nativeSourceOffset,
                   sce::Ampr::ampr_op_name(job.nativeSourceType),
                   "amm",
                   (unsigned)job.nativePrio,
                   0u,
                   job.nativeSubmitBytes,
                   (void*)const_cast<uint64_t*>(job.nativeCompletionAddress));
        return true;
    }

    bool progress_job(JobPtr& job,
                      bool priorReadFencePending,
                      bool priorNativeBatchPending,
                      bool priorCrossEopExecutionPending) {
        if (!job) {
            return false;
        }
#if !AMPR_EMU_APR_AIO_CROSS_EOP_READAHEAD
        (void)priorCrossEopExecutionPending;
#endif
        bool progressed = false;

        if (job->nativeSubmitted.load(std::memory_order_acquire)) {
            const bool nativeComplete = native_micro_completion_observed(*job);
            if (!nativeComplete) {
                if (job->nativeMicroEngine != NativeMicroEngine::AprBatch) {
                    return false;
                }
            } else {
                progressed = true;
            }
        }
        if (publish_deferred_cross_eop_error(*job)) {
            progressed = true;
        }
#if AMPR_EMU_APR_AIO_CROSS_EOP_READAHEAD
        if (priorCrossEopExecutionPending) {
            // An older execution cursor still owns this lane position. Extend
            // only the bounded speculative grammar into this job; do not let
            // the normal parser cross a wait/reset/map/marker boundary here.
            progressed |= issue_reads_across_eop(
                job, gatherScatterStates[job->prioIndex]);
            return progressed;
        }
        if (job->nativeBatchReleasePending && !job_failed(*job) &&
            (priorReadFencePending ||
             (job->nativeBatchReleaseReadSequence != 0 &&
              job->completedReadSeq <
                  job->nativeBatchReleaseReadSequence))) {
            progressed |= issue_reads_across_eop(
                job, gatherScatterStates[job->prioIndex]);
        }
#endif
        if (job->nativeBatchReleasePending) {
            if (job_failed(*job)) {
                if (!release_deferred_native_eop(*job, true)) {
                    std::abort();
                }
                progressed = true;
            } else if (!priorReadFencePending &&
                       (job->nativeBatchReleaseReadSequence == 0 ||
                        job->completedReadSeq >=
                            job->nativeBatchReleaseReadSequence)) {
                if (job->nativeBatchReleaseAfterSoftwareAddress) {
                    if (job->sourceOffset >= job->nativeSourceOffset ||
                        job->nativeSourceType != OpType::WriteEqueue ||
                        job->nativeSubmitBytes == 0) {
                        AMPR_CRITICAL_LOGF("apr.reactor.native.batch.lookahead.cursor.invalid job=0x%llx sourceOffset=0x%x nativeOffset=0x%x sourceType=%s bytes=0x%x action=abort",
                                           (unsigned long long)job->id,
                                           job->sourceOffset,
                                           job->nativeSourceOffset,
                                           sce::Ampr::ampr_op_name(
                                               job->nativeSourceType),
                                           job->nativeSubmitBytes);
                        std::abort();
                    }
                    if (job->nativeBatchLookaheadPriorSequence != 0 &&
                        !native_batch_sequence_reached(
                            nativeBatchLanes[job->prioIndex].completedSequence,
                            job->nativeBatchLookaheadPriorSequence)) {
                        return progressed;
                    }
                } else if (job->sourceOffset != job->nativeSourceOffset ||
                           job->decodedOpCacheBytes !=
                               job->nativeSubmitBytes ||
                           job->decodedOpCache.bufOffsetBytes !=
                               job->nativeSourceOffset ||
                           job->decodedOpCache.type !=
                               job->nativeSourceType ||
                           !software_op_is_native_apr_eop(
                               job->decodedOpCache) ||
                           job->nativeSubmitBytes == 0) {
                    AMPR_CRITICAL_LOGF("apr.reactor.native.batch.deferred.cursor.invalid job=0x%llx sourceOffset=0x%x nativeOffset=0x%x sourceType=%s bytes=0x%x action=abort",
                                       (unsigned long long)job->id,
                                       job->sourceOffset,
                                       job->nativeSourceOffset,
                                       sce::Ampr::ampr_op_name(
                                           job->nativeSourceType),
                                       job->nativeSubmitBytes);
                    std::abort();
                }
                if (!job->nativeBatchReleaseAfterSoftwareAddress) {
                    const uint32_t completedOpBytes = job->nativeSubmitBytes;
                    if (!release_deferred_native_eop(*job, false)) {
                        std::abort();
                    }
                    advance_job_source(*job, completedOpBytes);
                    progressed = true;
                }
            } else {
                return progressed;
            }
        }
        if (job_failed(*job)) {
            maybe_release_reactor_job(job);
            return progressed;
        }
        GatherScatterState& gs = gatherScatterStates[job->prioIndex];
        while (job->sourceOffset < job->sourceBytes) {
            if (publish_deferred_cross_eop_error(*job)) {
                progressed = true;
                break;
            }
            if (native_batch_wait_pending(job->prioIndex)) {
                break;
            }
            Op decodedOp{};
            uint32_t opBytes = 0;
            const Op* opPtr = nullptr;
            const uint32_t remainingBytes = job->sourceBytes - job->sourceOffset;
            if (job->decodedOpCacheBytes != 0 &&
                job->decodedOpCache.bufOffsetBytes == job->sourceOffset &&
                job->decodedOpCacheBytes <= remainingBytes) {
                opBytes = job->decodedOpCacheBytes;
                opPtr = &job->decodedOpCache;
            } else {
                clear_decoded_op(*job);
                uint32_t errorOffset = job->sourceOffset;
                const int decodeRc = sce::Ampr::ampr_decode_apr_packed_op(
                    job->sourceBuffer,
                    job->sourceBytes,
                    job->sourceOffset,
                    &decodedOp,
                    &opBytes,
                    &errorOffset);
                if (decodeRc != 0 || opBytes == 0 || opBytes > remainingBytes) {
                    set_command_error_without_cancel(
                        *job,
                        "software-decode",
                        decodeRc != 0 ? decodeRc : SCE_KERNEL_ERROR_EINVAL,
                        errorOffset);
                    break;
                }
                decodedOp.bufOffsetBytes = job->sourceOffset;
                opPtr = &decodedOp;
            }
            const Op& op = *opPtr;

            if (cb_op_is_apr_read(op.type)) {
#if AMPR_EMU_APR_AIO_CROSS_EOP_READAHEAD
                if (job->crossEopScanActive &&
                    job->sourceOffset < job->crossEopScanOffset) {
                    advance_job_source(*job, opBytes);
                    progressed = true;
                    AMPR_TLOGF("apr.reactor.crossEop.read.consume job=0x%llx sourceOffset=0x%x commandIndex=%u scanOffset=0x%x",
                               (unsigned long long)job->id,
                               op.bufOffsetBytes,
                               job->sourceCommandIndex - 1u,
                               job->crossEopScanOffset);
                    continue;
                }
#endif
                SoftwareRead read{};
                const int readRc = resolve_software_read(gs, op, &read);
                if (readRc != 0) {
                    set_command_error_without_cancel(*job,
                                                     "software-read-state",
                                                     readRc,
                                                     op.bufOffsetBytes);
                    break;
                }
                if (!issue_software_read(job,
                                         gs,
                                         read,
                                         opBytes,
                                         op.bufOffsetBytes,
                                         job->sourceCommandIndex)) {
                    if (!job_failed(*job)) {
                        cache_decoded_op(*job, op, opBytes);
                    }
                    break;
                }
                progressed = true;
                continue;
            }

            if (op.type == OpType::AprResetGatherScatter) {
                reset_software_gs_cursor(gs);
                advance_job_source(*job, opBytes);
                progressed = true;
                continue;
            }
            if (software_op_is_marker_or_nop(op.type)) {
                advance_job_source(*job, opBytes);
                progressed = true;
                continue;
            }

            // A53 dispatches SOP packets without waiting for preceding APR
            // reads to retire. Keep EOP packets and map state transitions behind
            // the software read fence, but let immediate writes and waits overlap
            // the single-threaded AIO reactor.
            const bool nativeBatchPending =
                job->nativeSubmitted.load(std::memory_order_acquire) &&
                job->nativeMicroEngine == NativeMicroEngine::AprBatch;
            const bool deferredAddressPrerequisite =
                job->nativeBatchReleasePending &&
                job->nativeBatchReleaseAfterSoftwareAddress &&
                op.type == OpType::WriteAddress &&
                !software_op_is_sop(op) &&
                job->sourceOffset + opBytes == job->nativeSourceOffset;
            uint64_t completionReadSequence = job->latestSubmittedReadSeq;
#if AMPR_EMU_APR_AIO_CROSS_EOP_READAHEAD
            if (software_op_is_eop_completion(op)) {
                completionReadSequence =
                    cross_eop_read_fence_for_cursor(*job);
                const bool softwareCompletionOrderingPending =
                    (priorNativeBatchPending || nativeBatchPending) &&
                    !software_op_uses_native_apr_batch(op.type) &&
                    !deferredAddressPrerequisite;
                if (priorReadFencePending ||
                    job->completedReadSeq < completionReadSequence ||
                    softwareCompletionOrderingPending) {
                    progressed |= issue_reads_across_eop(job, gs);
                    completionReadSequence =
                        cross_eop_read_fence_for_cursor(*job);
                }
            }
#endif
            const bool readFencePending = priorReadFencePending ||
                job->completedReadSeq < completionReadSequence;
            if (readFencePending && software_op_is_native_apr_eop(op)) {
                if (!append_native_apr_batch(*job,
                                             op,
                                             job->sourceBuffer +
                                             job->sourceOffset,
                                             opBytes,
                                             true,
                                             completionReadSequence)) {
                    if (!job_failed(*job)) {
                        cache_decoded_op(*job, op, opBytes);
                    }
                    break;
                }
                cache_decoded_op(*job, op, opBytes);
                progressed = true;
                break;
            }
            if (readFencePending && op.type == OpType::WriteAddress &&
                !software_op_is_sop(op) &&
                job->sourceCommandIndex + 1u < job->commandCount) {
                const uint32_t lookaheadOffset = job->sourceOffset + opBytes;
                Op lookaheadOp{};
                uint32_t lookaheadBytes = 0;
                uint32_t lookaheadErrorOffset = lookaheadOffset;
                const int lookaheadRc =
                    sce::Ampr::ampr_decode_apr_packed_op(
                        job->sourceBuffer,
                        job->sourceBytes,
                        lookaheadOffset,
                        &lookaheadOp,
                        &lookaheadBytes,
                        &lookaheadErrorOffset);
                if (lookaheadRc == 0 && lookaheadBytes != 0 &&
                    lookaheadOp.type == OpType::WriteEqueue &&
                    !software_op_is_sop(lookaheadOp)) {
                    lookaheadOp.bufOffsetBytes = lookaheadOffset;
                    if (!append_native_apr_batch(
                            *job,
                            lookaheadOp,
                            job->sourceBuffer + lookaheadOffset,
                            lookaheadBytes,
                            true,
                            completionReadSequence)) {
                        if (!job_failed(*job)) {
                            cache_decoded_op(*job, op, opBytes);
                        }
                        break;
                    }
                    job->nativeBatchReleaseAfterSoftwareAddress = true;
                    job->nativeBatchLookaheadPriorSequence =
                        job->nativeBatchSequence - 1u;
                    cache_decoded_op(*job, op, opBytes);
                    progressed = true;
                    break;
                }
            }
            if (readFencePending && !software_op_is_sop(op)) {
                cache_decoded_op(*job, op, opBytes);
                break;
            }
            if ((priorNativeBatchPending || nativeBatchPending) &&
                !software_op_is_sop(op) &&
                !software_op_uses_native_apr_batch(op.type) &&
                !deferredAddressPrerequisite) {
                cache_decoded_op(*job, op, opBytes);
                break;
            }
            if (op.type == OpType::AprMapEnd) {
                if (!job->mapActive) {
                    set_command_error_without_cancel(*job,
                                                     "software-map-end-state",
                                                     SCE_KERNEL_ERROR_EINVAL,
                                                     op.bufOffsetBytes);
                    break;
                }
                job->mapActive = false;
                advance_job_source(*job, opBytes);
                progressed = true;
                continue;
            }

#if AMPR_EMU_APR_AIO_CROSS_EOP_READAHEAD
            if (op.type == OpType::WaitOnAddress &&
                job->crossEopScanActive &&
                job->sourceOffset < job->crossEopScanOffset) {
                advance_job_source(*job, opBytes);
                progressed = true;
                AMPR_TLOGF("apr.reactor.crossEop.waitAddress.consume job=0x%llx sourceOffset=0x%x commandIndex=%u scanOffset=0x%x",
                           (unsigned long long)job->id,
                           op.bufOffsetBytes,
                           job->sourceCommandIndex - 1u,
                           job->crossEopScanOffset);
                continue;
            }
#endif

            bool softwareAddressHandled = false;
            bool softwareAddressComplete = false;
            if (!try_execute_software_address_op(*job,
                                                 op,
                                                 &softwareAddressHandled,
                                                 &softwareAddressComplete)) {
                break;
            }
            if (softwareAddressHandled) {
                if (!softwareAddressComplete) {
                    cache_decoded_op(*job, op, opBytes);
                    log_blocked_job(*job, op, "software-wait-address");
                    break;
                }
                const bool releaseLookaheadEvent =
                    deferredAddressPrerequisite;
                advance_job_source(*job, opBytes);
                if (releaseLookaheadEvent) {
                    if (job->sourceOffset != job->nativeSourceOffset ||
                        job->nativeSourceType != OpType::WriteEqueue ||
                        job->nativeSubmitBytes == 0) {
                        AMPR_CRITICAL_LOGF("apr.reactor.native.batch.lookahead.release.invalid job=0x%llx sourceOffset=0x%x nativeOffset=0x%x sourceType=%s bytes=0x%x action=abort",
                                           (unsigned long long)job->id,
                                           job->sourceOffset,
                                           job->nativeSourceOffset,
                                           sce::Ampr::ampr_op_name(
                                               job->nativeSourceType),
                                           job->nativeSubmitBytes);
                        std::abort();
                    }
                    const uint32_t stagedEventBytes =
                        job->nativeSubmitBytes;
                    if (!release_deferred_native_eop(*job, false)) {
                        std::abort();
                    }
                    advance_job_source(*job, stagedEventBytes);
                }
                progressed = true;
                continue;
            }

            Op nativeOp = op;
            NativeMicroEngine engine = NativeMicroEngine::None;
            bool encodeFirst = false;
            if (op.type == OpType::AprMapBegin ||
                op.type == OpType::AprMapDirectBegin) {
                if (job->mapActive) {
                    set_command_error_without_cancel(*job,
                                                     "software-map-begin-state",
                                                     SCE_KERNEL_ERROR_EINVAL,
                                                     op.bufOffsetBytes);
                    break;
                }
                nativeOp = {};
                nativeOp.bufOffsetBytes = op.bufOffsetBytes;
                if (op.type == OpType::AprMapBegin) {
                    nativeOp.type = OpType::AmmMap;
                    nativeOp.u64a = op.u64a;
                    nativeOp.u64b = op.u64b;
                    nativeOp.u32a = op.u32a;
                    nativeOp.u32b = op.u32b;
                } else {
                    nativeOp.type = OpType::AmmMapDirect;
                    nativeOp.u64a = op.u64a;
                    nativeOp.u64b = op.u64b;
                    nativeOp.u64c = op.u64c;
                    nativeOp.u32a = op.u32b;
                    nativeOp.u32b = op.u32a;
                }
                engine = NativeMicroEngine::Amm;
                encodeFirst = true;
            } else if (software_op_uses_amm(op.type)) {
                engine = NativeMicroEngine::Amm;
            }

            const void* const packedSource = job->sourceBuffer + job->sourceOffset;
            if (engine == NativeMicroEngine::None) {
                if (!software_op_uses_native_apr_batch(op.type)) {
                    set_command_error_without_cancel(*job,
                                                     "software-native-owner",
                                                     SCE_KERNEL_ERROR_EINVAL,
                                                     op.bufOffsetBytes);
                    break;
                }
                if (!append_native_apr_batch(*job,
                                             op,
                                             packedSource,
                                             opBytes)) {
                    if (!job_failed(*job)) {
                        cache_decoded_op(*job, op, opBytes);
                    }
                    break;
                }
                advance_job_source(*job, opBytes);
                progressed = true;
                continue;
            }
            if (!prepare_native_micro_pair(*job,
                                           nativeOp,
                                           packedSource,
                                           opBytes,
                                           encodeFirst)) {
                break;
            }
            if (!submit_native_micro(*job, engine)) {
                break;
            }
            if (op.type == OpType::AprMapBegin ||
                op.type == OpType::AprMapDirectBegin) {
                job->mapActive = true;
            }
            advance_job_source(*job, opBytes);
            progressed = true;
            break;
        }

        if (!job_failed(*job) &&
            job->sourceOffset == job->sourceBytes &&
            (!job->nativeSubmitted.load(std::memory_order_acquire) ||
             job->nativeMicroEngine == NativeMicroEngine::AprBatch) &&
            !job_processing_complete(*job)) {
            if (job->sourceCommandIndex != job->commandCount) {
                set_fail(*job,
                         "software-command-count",
                         SCE_KERNEL_ERROR_EINVAL,
                         job->sourceOffset);
            } else {
                finish_job_processing(*job);
            }
            progressed = true;
        }

        maybe_release_reactor_job(job);
        return progressed;
    }

    bool progress_all_jobs() {
        bool progressed = false;
        size_t progressedJobs = 0;
        size_t populatedLaneCount = 0;
        JobPtr laneHeads[kPriorityCount]{};
        {
            AmprLockGuard lk(m);
            for (size_t lane = 0; lane < kPriorityCount; ++lane) {
                laneHeads[lane] = activePriorityHeads[lane];
                populatedLaneCount += laneHeads[lane] ? 1u : 0u;
            }
        }
        bool batchLimitReached = false;
        for (size_t laneOffset = 0;
             laneOffset < kPriorityCount && !batchLimitReached;
             ++laneOffset) {
            const size_t lane =
                (static_cast<size_t>(jobProgressLaneCursor) + laneOffset) % kPriorityCount;
            bool priorReadFencePending = false;
            bool priorNativeBatchPending = false;
            bool priorCrossEopExecutionPending = false;
            JobPtr job = laneHeads[lane];
            while (job) {
                if (native_batch_wait_pending(static_cast<uint32_t>(lane))) {
                    break;
                }
                JobPtr const next =
                    job->priorityNext.load(std::memory_order_acquire);
                const bool jobProgressed = progress_job(job,
                                                        priorReadFencePending,
                                                        priorNativeBatchPending,
                                                        priorCrossEopExecutionPending);
                progressed |= jobProgressed;
                if (jobProgressed) {
                    ++progressedJobs;
                }
#if AMPR_EMU_APR_REACTOR_JOB_BATCH_LIMIT != 0
                if ((has_pending_reads() || populatedLaneCount > 1u ||
                     priorCrossEopExecutionPending) &&
                    progressedJobs >= AMPR_EMU_APR_REACTOR_JOB_BATCH_LIMIT) {
#if AMPR_EMU_DEBUG_LOG && AMPR_EMU_APR_REACTOR_BACKLOG_WARN_THRESHOLD != 0
                    maybe_log_reactor_backlog("job-batch-yield", pending_read_total());
#endif
                    AMPR_VLOGF("apr.reactor.jobBatch.yield progressed=%zu activeJobs=%zu pendingReads=%zu",
                              progressedJobs,
                              active_lane_count_locked(),
                              pending_read_total());
                    jobProgressLaneCursor = static_cast<uint8_t>((lane + 1u) % kPriorityCount);
                    batchLimitReached = true;
                    break;
                }
#endif
                if (job) {
                    // A53 flattens adjacent indirect buffers in one priority.
                    // Once a buffer has issued or safely scanned its complete
                    // command stream, let later buffers issue reads and SOP work
                    // without waiting for those reads to retire. The accumulated
                    // fence still blocks later EOP/map work, and priorityPrev
                    // keeps visible job completion FIFO through the per-priority
                    // head gate.
                    const bool nativeSubmitted =
                        job->nativeSubmitted.load(std::memory_order_acquire);
                    if (!job_allows_priority_successor(*job,
                                                       nativeSubmitted)) {
                        break;
                    }
                    priorReadFencePending |= job_has_outstanding_reads(*job);
                    priorNativeBatchPending |=
                        nativeSubmitted &&
                        job->nativeMicroEngine == NativeMicroEngine::AprBatch;
                    priorCrossEopExecutionPending |=
                        job->sourceOffset != job->sourceBytes;
                }
                job = next;
            }
            if (!seal_open_native_apr_batch_group(
                    static_cast<uint32_t>(lane))) {
                AMPR_CRITICAL_LOGF("apr.reactor.native.batch.group.flush.fail lane=%u action=abort",
                                   static_cast<unsigned>(lane));
                std::abort();
            }
        }
        return progressed;
    }

    void poll_active_aio_read(ActiveReadIt it, uint64_t pollNow, bool& completedAny) {
        it->hotPollQueued = false;
#if AMPR_EMU_DEBUG_LOG
        note_active_read_due_poll();
#endif
        int state = 0;
#if AMPR_EMU_DEBUG_LOG
        const uint64_t pollStartNs = time_counter_now();
#endif
        const int pollRc = sceKernelAioPollRequest(it->aioId, &state);
#if AMPR_EMU_DEBUG_LOG
        const uint64_t pollEndNs = time_counter_now();
        note_aio_poll_call(pollEndNs >= pollStartNs ? pollEndNs - pollStartNs : 0);
#else
        const uint64_t pollEndNs = pollNow;
#endif
        if (pollRc != 0) {
            auto job = it->job;
            if (job) {
                set_or_defer_read_command_error(
                    *job,
                    "aio-poll",
                    apr_backend_read_error_to_apr(
                        apr_aio_api_rc_to_sce(pollRc)),
                    it->desc.errorOff);
            }
            state = SCE_KERNEL_AIO_STATE_ABORTED;
        }
        it->lastPollState = state;
        it->lastPollRc = pollRc;

        const int finalState = state & ~SCE_KERNEL_AIO_STATE_NOTIFIED;
        if (finalState == SCE_KERNEL_AIO_STATE_COMPLETED ||
            finalState == SCE_KERNEL_AIO_STATE_ABORTED) {
            auto finishedJob = it->job;
            if (!finish_active_read(it, state)) {
                (void)erase_active_read(it);
                if (finishedJob && !activeReads.empty()) {
                    reset_publish_gating_active_aio_poll_backoff_for_job(*finishedJob, pollEndNs);
                }
                maybe_release_reactor_job(finishedJob);
                completedAny = true;
            } else {
                schedule_next_active_read_poll(*it, pollEndNs);
            }
        } else {
            schedule_next_active_read_poll(*it, pollEndNs);
        }
    }

    bool spin_poll_single_gating_read(size_t& pollCalls, bool& completedAny) {
        if (completedAny || has_pending_reads() || activeReads.size() != 1u ||
            pollCalls >= kAioPollBatchLimit) {
            return false;
        }
        bool polled = false;
        while (!activeReads.empty() && pollCalls < kAioPollBatchLimit) {
            auto it = activeReads.begin();
            if (it == activeReads.end() ||
                !active_read_can_gate_publish(*it) ||
                it->gatingSpinPollsRemaining == 0) {
                break;
            }
            --it->gatingSpinPollsRemaining;
            poll_active_aio_read(it, time_counter_now(), completedAny);
            ++pollCalls;
            polled = true;
            if (completedAny || activeReads.size() != 1u || has_pending_reads()) {
                break;
            }
        }
        return polled;
    }

    bool poll_active_aio_reads_once(bool sleepWhenIdle) {
        bool completedAny = false;
        bool budgetExhausted = false;
        size_t pollCalls = 0;
        while (pollCalls < kAioHotPollLimit) {
            auto hotIt = pop_hot_active_read_poll();
            if (hotIt == activeReads.end()) {
                break;
            }
            const uint64_t hotNow = time_counter_now();
            if (!active_read_poll_due(*hotIt, hotNow)) {
#if AMPR_EMU_DEBUG_LOG
                note_aio_poll_backoff_skip();
                note_active_read_not_due_skip();
#endif
                continue;
            }
            poll_active_aio_read(hotIt, hotNow, completedAny);
            ++pollCalls;
        }
        if (sleepWhenIdle && !completedAny) {
            (void)spin_poll_single_gating_read(pollCalls, completedAny);
        }
        if (activeReads.empty()) {
            return completedAny;
        }
        while (pollCalls < kAioPollBatchLimit && !activeReads.empty()) {
            const uint64_t pollNow = time_counter_now();
            auto dueIt = first_due_active_read(pollNow);
            if (dueIt == activeReads.end()) {
#if AMPR_EMU_DEBUG_LOG
                note_deadline_heap_future_stop();
#endif
                break;
            }
#if AMPR_EMU_DEBUG_LOG
            note_deadline_heap_pick();
#endif
            ++pollCalls;
            poll_active_aio_read(dueIt, pollNow, completedAny);
        }

        if (pollCalls >= kAioPollBatchLimit && !activeReads.empty()) {
            const uint64_t budgetNow = time_counter_now();
            budgetExhausted = first_due_active_read(budgetNow) != activeReads.end();
            if (budgetExhausted) {
#if AMPR_EMU_DEBUG_LOG
                note_aio_poll_budget_yield();
#endif
            }
        }
        if (completedAny || activeReads.empty() || !sleepWhenIdle) {
            return completedAny;
        }

        sleep_active_aio_poll(time_counter_now(), budgetExhausted);
        return completedAny;
    }

    bool drain_completed_aio_reads_budgeted(size_t passes) {
        bool progressed = false;
        while (passes != 0 && !activeReads.empty()) {
            --passes;
            if (!poll_active_aio_reads_once(false)) {
                break;
            }
            progressed = true;
        }
        return progressed;
    }

    struct PendingReadSelection {
        PendingReadQueue* lane{};
        PendingReadQueue::iterator read{};
        int priority{static_cast<int>(kAprPriorityMin)};
        bool progressed{};
    };

    struct ActiveFileCounts {
        static constexpr size_t kCapacity = kMaxActiveReads * 2u;
        struct Entry {
            uint32_t fileId{};
            uint32_t count{};
            bool occupied{};
        };

        Entry entries[kCapacity]{};

        static size_t first_slot(uint32_t fileId) {
            return static_cast<size_t>(fileId * 2654435761u) % kCapacity;
        }

        uint32_t get(uint32_t fileId) const {
            size_t slot = first_slot(fileId);
            for (size_t probe = 0; probe < kCapacity; ++probe) {
                const Entry& entry = entries[slot];
                if (!entry.occupied) {
                    return 0;
                }
                if (entry.fileId == fileId) {
                    return entry.count;
                }
                slot = (slot + 1u) % kCapacity;
            }
            return 0;
        }

        void increment(uint32_t fileId) {
            size_t slot = first_slot(fileId);
            size_t reusableSlot = kCapacity;
            for (size_t probe = 0; probe < kCapacity; ++probe) {
                Entry& entry = entries[slot];
                if (!entry.occupied) {
                    Entry& target = entries[reusableSlot != kCapacity ? reusableSlot : slot];
                    target.fileId = fileId;
                    target.count = 1;
                    target.occupied = true;
                    return;
                }
                if (entry.fileId == fileId) {
                    if (entry.count == UINT32_MAX) {
                        AMPR_CRITICAL_LOGF("apr.reactor.activeFileCounts.overflow fileId=%u",
                                           fileId);
                        ampr_debug_int3_trap();
                        return;
                    }
                    ++entry.count;
                    return;
                }
                if (entry.count == 0 && reusableSlot == kCapacity) {
                    reusableSlot = slot;
                }
                slot = (slot + 1u) % kCapacity;
            }
            if (reusableSlot != kCapacity) {
                Entry& entry = entries[reusableSlot];
                entry.fileId = fileId;
                entry.count = 1;
                return;
            }
            AMPR_CRITICAL_LOGF("apr.reactor.activeFileCounts.full fileId=%u capacity=%zu",
                               fileId,
                               kCapacity);
            ampr_debug_int3_trap();
        }

        void decrement(uint32_t fileId) {
            size_t slot = first_slot(fileId);
            for (size_t probe = 0; probe < kCapacity; ++probe) {
                Entry& entry = entries[slot];
                if (!entry.occupied) {
                    break;
                }
                if (entry.fileId == fileId) {
                    if (entry.count == 0) {
                        break;
                    }
                    --entry.count;
                    return;
                }
                slot = (slot + 1u) % kCapacity;
            }
            AMPR_CRITICAL_LOGF("apr.reactor.activeFileCounts.underflow fileId=%u",
                               fileId);
            ampr_debug_int3_trap();
        }
    };

    bool has_ready_file_below_per_file_limit(
        uint64_t nowNs,
        const ActiveFileCounts& activeFileCounts) const {
        if (AMPR_EMU_APR_AIO_PER_FILE_INFLIGHT == 0) {
            return false;
        }
        // This snapshot also protects a file that will remain below the soft
        // limit while another file reaches it later in this admission pass.
        for (size_t priority = 0; priority < kPriorityCount; ++priority) {
            const PendingReadQueue& lane = pendingReadLanes[priority];
            for (const PendingRead& pending : lane) {
                if (!pending.job || job_failed(*pending.job) ||
                    (pending.notBeforeNs != 0 && pending.notBeforeNs > nowNs) ||
                    activeFileCounts.get(pending.desc.fileId) >=
                        static_cast<uint32_t>(AMPR_EMU_APR_AIO_PER_FILE_INFLIGHT)) {
                    continue;
                }
                if (fd_budget_available_for_read(pending_read_fd_desc(pending),
                                                 nullptr,
                                                 nullptr,
                                                 nullptr,
                                                 nullptr)) {
                    return true;
                }
            }
        }
        return false;
    }

    PendingReadSelection select_ready_pending_read(uint64_t nowNs,
                                                   uint8_t startPriority,
                                                   uint8_t skippedPriorityMask,
                                                   bool protectUnderfilledFiles,
                                                   const ActiveFileCounts& activeFileCounts) {
        PendingReadSelection selection{};
        for (size_t laneOffset = 0; laneOffset < kPriorityCount; ++laneOffset) {
            const size_t priority =
                (static_cast<size_t>(startPriority) + laneOffset) % kPriorityCount;
            if ((skippedPriorityMask & static_cast<uint8_t>(1u << priority)) != 0) {
                continue;
            }
            PendingReadQueue& lane = pendingReadLanes[priority];
            const int lanePrio = static_cast<int>(priority);
            bool loggedLaneBlock = false;
            size_t laneScanRemaining = lane.size();
            auto laneIt = lane.scan_begin();
            while (laneScanRemaining-- != 0 && laneIt != lane.end()) {
                if (!laneIt->job || job_failed(*laneIt->job)) {
                    auto stale = laneIt;
                    (void)drop_pending_read(lane, stale);
                    selection.progressed = true;
                    // Error publication may synchronously remove other nodes
                    // from this lane. Resume only from the repaired queue cursor.
                    laneScanRemaining = lane.size();
                    laneIt = lane.scan_begin();
                    continue;
                }

                const PendingRead& pending = *laneIt;
                if (pending.notBeforeNs != 0 && pending.notBeforeNs > nowNs) {
                    if (!loggedLaneBlock) {
                        AMPR_TLOGF("apr.reactor.aio.defer-not-before job=0x%llx seq=0x%llx prio=%d retry=%u waitNs=%llu pendingReads=%zu activeReads=%zu",
                                  (unsigned long long)pending.job->id,
                                  (unsigned long long)pending.seq,
                                  lanePrio,
                                  pending.ammEfaultRetries,
                                  (unsigned long long)(pending.notBeforeNs - nowNs),
                                  pending_read_total(),
                                  activeReads.size());
                        loggedLaneBlock = true;
                    }
                    laneIt = lane.next_cyclic(laneIt);
                    continue;
                }

                const uint32_t activeForFile = activeFileCounts.get(pending.desc.fileId);
                if (AMPR_EMU_APR_AIO_PER_FILE_INFLIGHT != 0 &&
                    protectUnderfilledFiles &&
                    activeForFile >= static_cast<uint32_t>(AMPR_EMU_APR_AIO_PER_FILE_INFLIGHT)) {
                    if (!loggedLaneBlock) {
#if AMPR_EMU_DEBUG_LOG && AMPR_EMU_APR_REACTOR_BACKLOG_WARN_THRESHOLD != 0
                        maybe_log_reactor_backlog("aio-per-file-window", pending_read_total());
#endif
                        AMPR_VLOGF("apr.reactor.aio.perFile.cap prio=%d fileId=%u activeForFile=%zu limit=%u pendingReads=%zu activeReads=%zu",
                                  lanePrio,
                                  pending.desc.fileId,
                                  static_cast<size_t>(activeForFile),
                                  (unsigned)AMPR_EMU_APR_AIO_PER_FILE_INFLIGHT,
                                  pending_read_total(),
                                  activeReads.size());
                        loggedLaneBlock = true;
                    }
                    laneIt = lane.next_cyclic(laneIt);
                    continue;
                }

                const char* fdBlockReason = nullptr;
                size_t fdObserved = 0;
                size_t fdBudget = 0;
                size_t fdEvictable = 0;
                if (!fd_budget_available_for_read(pending_read_fd_desc(pending),
                                                  &fdBlockReason,
                                                  &fdObserved,
                                                  &fdBudget,
                                                  &fdEvictable)) {
                    if (!loggedLaneBlock) {
#if AMPR_EMU_DEBUG_LOG && AMPR_EMU_APR_REACTOR_BACKLOG_WARN_THRESHOLD != 0
                        maybe_log_reactor_backlog(fdBlockReason, pending_read_total());
#endif
                        AMPR_VLOGF("apr.reactor.fdBudget.cap reason=%s prio=%d fileId=%u observed=%zu budget=%zu evictable=%zu pendingReads=%zu activeReads=%zu",
                                  fdBlockReason ? fdBlockReason : "fd-open-budget",
                                  lanePrio,
                                  pending.desc.fileId,
                                  fdObserved,
                                  fdBudget,
                                  fdEvictable,
                                  pending_read_total(),
                                  activeReads.size());
                        loggedLaneBlock = true;
                    }
                    laneIt = lane.next_cyclic(laneIt);
                    continue;
                }

                lane.set_scan_cursor_after(laneIt);
                selection.lane = &lane;
                selection.read = laneIt;
                selection.priority = lanePrio;
                return selection;
            }
        }
        return selection;
    }

    bool submit_pending_reads() {
        constexpr SceKernelAioSubmitId kUnsetAioId =
            static_cast<SceKernelAioSubmitId>(-1);
        constexpr uint8_t kAllPriorityMask =
            static_cast<uint8_t>((1u << kPriorityCount) - 1u);

        bool progressed = false;
        if (activeReads.size() >= aio_active_read_limit()) {
            progressed |= drain_completed_aio_reads_budgeted(
                AMPR_EMU_APR_AIO_SUBMIT_PRE_DRAIN_PASSES);
            if (activeReads.size() >= aio_active_read_limit()) {
                return progressed;
            }
        }

        const uint64_t nowNs = time_counter_now();
        uint8_t deferredPriorityMask = 0;
        const bool protectUnderfilledFiles =
            has_ready_file_below_per_file_limit(nowNs, activeFileCounts);
        (void)fd_pressure_active(nowNs);
        bool aioInitializationReady = false;

        const auto prepareRead =
            [&](PendingReadSelection selection) -> ActiveReadIt {
            PendingReadQueue* const selectedLane = selection.lane;
            const int selected = selection.priority;
            auto pendingIt = selection.read;
            PendingRead pending = ampr_move(*pendingIt);
            (void)selectedLane->erase(pendingIt);
            dec_pending_read_total(1);

            JobPtr job = pending.job;
            ReadChain* const chain = pending.chain;
            if (!job || !chain || chain->job != job || job_failed(*job)) {
                JobPtr ownerJob = chain && chain->job ? chain->job : job;
                const bool invalidOwner = !job || !chain || chain->job != job;
                decrement_pending_read_count(ownerJob);
                decrement_read_chain_pending(chain);
                if (invalidOwner && ownerJob && !job_failed(*ownerJob)) {
                    set_command_error(*ownerJob,
                                      "pending-read-owner",
                                      SCE_KERNEL_ERROR_EINVAL,
                                      pending.desc.errorOff);
                }
                maybe_finish_read_chain(chain);
                maybe_release_reactor_job(ownerJob);
                progressed = true;
                return activeReads.end();
            }

            ActiveReadIt activeIt = activeReads.push_back(ActiveRead{});
            note_active_read_peak(activeReads.size());
            ActiveRead& active = *activeIt;
            active.job = job;
            active.desc = ampr_move(pending.desc);
            active.chain = chain;
            active.seq = pending.seq;
            active.commandIndex = pending.commandIndex;
            active.ammEfaultRetries = pending.ammEfaultRetries;
            active.aioCompletionRetries = pending.aioCompletionRetries;
            active.retrySlice = pending.retrySlice;
#if AMPR_EMU_DEBUG_LOG
            active.nativeTriggerTimeNs = pending.nativeTriggerTimeNs;
            active.pendingEnqueueTimeNs = pending.pendingEnqueueTimeNs;
#endif
            active.result = {};
            active.request = {};
            link_active_read_to_job(active, *job);
            increment_active_read_count(job);
            increment_read_chain_active(chain);

            int acquireRc = 0;
            uint32_t acquireErrorOff = chain->ownerDesc.errorOff;
            bool acquired = apr_acquire_aio_read_desc(job->id,
                                                      chain->ownerDesc,
                                                      &acquireRc,
                                                      &acquireErrorOff);
            if (!acquired && acquireRc == SCE_KERNEL_ERROR_EMFILE) {
                note_emfile_event();
                note_fd_pressure();
                const size_t closedIdle =
                    ampr_index_fd_cache_release_idle_percent(
                        AMPR_EMU_FD_CACHE_EMFILE_IDLE_CLOSE_PERCENT);
                (void)closedIdle;
                acquireRc = 0;
                acquireErrorOff = chain->ownerDesc.errorOff;
                acquired = apr_acquire_aio_read_desc(job->id,
                                                     chain->ownerDesc,
                                                     &acquireRc,
                                                     &acquireErrorOff);
                AMPR_LOGF("apr.reactor.acquire.retry-emfile job=0x%llx seq=0x%llx closedIdle=%zu rc=0x%x acquired=%u",
                          (unsigned long long)job->id,
                          (unsigned long long)active.seq,
                          closedIdle,
                          acquireRc,
                          acquired ? 1u : 0u);
            }
            if (!acquired) {
                const bool localHeadroomDefer =
                    acquireRc == SCE_KERNEL_ERROR_EAGAIN;
                if (acquireRc == SCE_KERNEL_ERROR_EMFILE ||
                    localHeadroomDefer) {
                    if (acquireRc == SCE_KERNEL_ERROR_EMFILE) {
                        note_emfile_event();
                        note_fd_pressure();
                    }
                    const uint64_t seq = active.seq;
                    const size_t commandIndex = active.commandIndex;
                    requeue_pending_read_front(
                        static_cast<size_t>(selected),
                        job,
                        ampr_move(active.desc),
                        chain,
                        seq,
                        commandIndex,
                        active.ammEfaultRetries,
                        0,
                        active.aioCompletionRetries,
                        active.retrySlice
#if AMPR_EMU_DEBUG_LOG
                        ,
                        active.nativeTriggerTimeNs,
                        active.pendingEnqueueTimeNs);
#else
                        );
#endif
                    decrement_active_read_count(job);
                    decrement_read_chain_active(chain);
                    maybe_finish_read_chain(chain);
                    erase_active_read(activeIt);
                    AMPR_LOGF("apr.reactor.acquire.defer job=0x%llx seq=0x%llx prio=%d reason=%s rc=0x%x pendingReads=%zu activeReads=%zu",
                              (unsigned long long)job->id,
                              (unsigned long long)seq,
                              selected,
                              localHeadroomDefer ? "fd-headroom" : "emfile",
                              acquireRc,
                              pending_read_total(),
                              activeReads.size());
                    deferredPriorityMask |= static_cast<uint8_t>(
                        1u << static_cast<unsigned>(selected));
                    return activeReads.end();
                }

                decrement_pending_read_count(job);
                decrement_read_chain_pending(chain);
                decrement_active_read_count(job);
                decrement_read_chain_active(chain);
                erase_active_read(activeIt);
                const bool deferredError = set_or_defer_read_command_error(
                    *job,
                    "aio-acquire-fd",
                    apr_backend_read_error_to_apr(acquireRc),
                    acquireErrorOff);
                if (deferredError) {
                    chain->allIssued = true;
                }
                maybe_finish_read_chain(chain);
                maybe_release_reactor_job(job);
                progressed = true;
                return activeReads.end();
            }

            borrow_read_chain_fd(*chain, active.desc);
            decrement_pending_read_count(job);
            decrement_read_chain_pending(chain);
            active.request.offset = static_cast<off_t>(active.desc.offset);
            active.request.nbyte = static_cast<size_t>(active.desc.length);
            active.request.buf = active.desc.buffer;
            active.request.result = &active.result;
            active.request.fd = active.desc.fd;
            active.activeFileCounted = true;
            activeFileCounts.increment(active.desc.fileId);
#if AMPR_EMU_DEBUG_LOG && AMPR_EMU_DEBUG_LOG_TRACE
            log_aio_buffer_memory_detail("apr.reactor.aio.bufVa",
                                         "submit",
                                         active,
                                         time_counter_now(),
                                         0,
                                         0);
#endif
            return activeIt;
        };

        const auto requeuePreparedRead =
            [&](ActiveReadIt activeIt,
                uint8_t aprPriority,
                int submitSceRc,
                uint64_t retryAtNs,
                const char* reason) {
            ActiveRead& active = *activeIt;
            JobPtr job = active.job;
            ReadChain* const chain = active.chain;
            const uint64_t seq = active.seq;
            const size_t commandIndex = active.commandIndex;
            const uint32_t fileId = active.desc.fileId;
            const uint64_t length = active.desc.length;
            const uint64_t offset = active.desc.offset;
            const uint32_t errorOff = active.desc.errorOff;
            const uint32_t ammEfaultRetries = active.ammEfaultRetries;
            const uint32_t aioCompletionRetries =
                active.aioCompletionRetries;
            const bool retrySlice = active.retrySlice;
            (void)fileId;
            (void)length;
            (void)offset;
#if AMPR_EMU_DEBUG_LOG
            const uint64_t nativeTriggerTimeNs =
                active.nativeTriggerTimeNs;
            const uint64_t pendingEnqueueTimeNs =
                active.pendingEnqueueTimeNs;
#endif
            // Keep the active descriptor intact until erase_active_read has
            // removed its prepared per-file reservation.
            AprAioReadDesc desc = active.desc;
            apr_release_aio_read_desc(desc);
            decrement_active_read_count(job);
            decrement_read_chain_active(chain);
            erase_active_read(activeIt);
            if (job && !job_failed(*job) &&
                !cross_eop_suffix_is_canceled(*job, errorOff)) {
                increment_pending_read_count(job);
                increment_read_chain_pending(chain);
                requeue_pending_read_front(
                    static_cast<size_t>(aprPriority),
                    job,
                    ampr_move(desc),
                    chain,
                    seq,
                    commandIndex,
                    ammEfaultRetries,
                    retryAtNs,
                    aioCompletionRetries,
                    retrySlice
#if AMPR_EMU_DEBUG_LOG
                    ,
                    nativeTriggerTimeNs,
                    pendingEnqueueTimeNs);
#else
                    );
#endif
                AMPR_LOGF("apr.reactor.aio.submit.defer job=0x%llx reason=%s rc=0x%x seq=0x%llx fileId=%u len=0x%llx off=0x%llx pendingReads=%zu activeReads=%zu",
                          (unsigned long long)job->id,
                          reason,
                          submitSceRc,
                          (unsigned long long)seq,
                          fileId,
                          (unsigned long long)length,
                          (unsigned long long)offset,
                          pending_read_total(),
                          activeReads.size());
            } else {
                if (chain && job &&
                    cross_eop_suffix_is_canceled(*job, errorOff)) {
                    chain->allIssued = true;
                }
                maybe_finish_read_chain(chain);
                maybe_release_reactor_job(job);
            }
            progressed = true;
        };

        const auto failPreparedRead =
            [&](ActiveReadIt activeIt, int submitSceRc) {
            ActiveRead& active = *activeIt;
            JobPtr job = active.job;
            ReadChain* const chain = active.chain;
            const uint32_t errorOff = active.desc.errorOff;
            apr_release_aio_read_desc(active.desc);
            decrement_active_read_count(job);
            decrement_read_chain_active(chain);
            erase_active_read(activeIt);
            if (job && !job_failed(*job)) {
                const bool deferredError = set_or_defer_read_command_error(
                    *job,
                    "aio-submit",
                    apr_backend_read_error_to_apr(submitSceRc),
                    errorOff);
                if (deferredError && chain) {
                    chain->allIssued = true;
                }
            }
            maybe_finish_read_chain(chain);
            maybe_release_reactor_job(job);
            progressed = true;
        };

        const auto acceptPreparedRead =
            [&](ActiveReadIt activeIt,
                uint8_t aprPriority,
                SceKernelAioSubmitId aioId,
                int aioPriority,
                uint64_t submitTimeNs) {
            ActiveRead& active = *activeIt;
            JobPtr job = active.job;
            ReadChain* const chain = active.chain;
            active.aioId = aioId;
            active.aioPrio = aioPriority;
            active.submitTimeNs = submitTimeNs;

            if (!active.retrySlice) {
                // Advance only after the SDK accepted this slice. Queue exactly
                // one future slice; later admission rounds may pipeline it
                // while this individual AIO id remains active.
                const uint64_t issuedLength = active.desc.length;
                if (issuedLength > chain->remaining) {
                    set_or_defer_read_command_error(
                        *job,
                        "aio-read-chain-range",
                        SCE_KERNEL_ERROR_EINVAL,
                        active.desc.errorOff);
                } else {
                    chain->remaining -= issuedLength;
                    chain->nextBuffer = reinterpret_cast<void*>(
                        reinterpret_cast<uintptr_t>(chain->nextBuffer) +
                        static_cast<uintptr_t>(issuedLength));
                    chain->nextOffset += issuedLength;
                    if (chain->remaining == 0) {
                        chain->allIssued = true;
                    } else {
                        PendingRead next{};
                        next.job = job;
                        next.desc = read_chain_next_desc(*chain);
                        next.chain = chain;
                        next.seq = chain->seq;
                        next.commandIndex = chain->commandIndex;
#if AMPR_EMU_DEBUG_LOG
                        next.nativeTriggerTimeNs =
                            chain->nativeTriggerTimeNs;
#endif
                        if (queue_pending_read(job->prioIndex,
                                               ampr_move(next))) {
                            increment_pending_read_count(job);
                            increment_read_chain_pending(chain);
                        }
                    }
                }
            }
#if AMPR_EMU_DEBUG_LOG
            note_native_trigger_to_aio_submit(active.nativeTriggerTimeNs,
                                              submitTimeNs);
            note_pending_read_queue_to_aio_submit(active.pendingEnqueueTimeNs,
                                                  submitTimeNs,
                                                  aprPriority);
            note_job_queue_to_first_aio_submit(*job, submitTimeNs);
            note_accepted_aio_request(active.desc.length,
                                      aprPriority);
#endif
            if (active_read_can_gate_publish(active)) {
                reset_and_queue_hot_active_read_poll(active, submitTimeNs);
            } else {
                reset_active_read_poll_backoff(active, submitTimeNs);
            }
            active.lastPollState = 0;
            active.lastPollRc = 0;
#if AMPR_EMU_DEBUG_LOG && (AMPR_EMU_DEBUG_LOG_VERBOSE || AMPR_EMU_DEBUG_LOG_TRACE)
            ++job->submittedReadCount;
#endif
            progressed = true;
        };

        bool stopAdmission = false;
        while (!stopAdmission &&
               activeReads.size() < aio_active_read_limit()) {
            uint8_t roundPriorityMask = deferredPriorityMask;
            bool selectedAny = false;

            while (activeReads.size() < aio_active_read_limit() &&
                   roundPriorityMask != kAllPriorityMask) {
                PendingReadSelection selection =
                    select_ready_pending_read(nowNs,
                                              aioAdmissionCursor,
                                              roundPriorityMask,
                                              protectUnderfilledFiles,
                                              activeFileCounts);
                progressed |= selection.progressed;
                if (!selection.lane) {
                    break;
                }
                selectedAny = true;

                const uint8_t selected =
                    static_cast<uint8_t>(selection.priority);
                roundPriorityMask |= static_cast<uint8_t>(1u << selected);
                aioAdmissionCursor = static_cast<uint8_t>(
                    (static_cast<size_t>(selected) + 1u) %
                    kPriorityCount);

                ActiveReadIt activeIt = prepareRead(selection);
                if (activeIt == activeReads.end()) {
                    continue;
                }

                const int aioPriority = apr_aio_priority_from_apr(selected);
                ActiveRead& active = *activeIt;
#if AMPR_EMU_DEBUG_LOG && AMPR_EMU_DEBUG_LOG_TRACE
                AMPR_TLOGF("apr.reactor.aio.submit.enter job=0x%llx seq=0x%llx prio=%d aprPrio=%u fileId=%u fd=%d len=0x%llx off=0x%llx active=%zu",
                          (unsigned long long)active.job->id,
                          (unsigned long long)active.seq,
                          aioPriority,
                          (unsigned)selected,
                          active.desc.fileId,
                          active.desc.fd,
                          (unsigned long long)active.desc.length,
                          (unsigned long long)active.desc.offset,
                          activeReads.size());
#endif

                if (!aioInitializationReady) {
                    ensure_aio_initialized();
                    const uint32_t initState =
                        aioInitState.load(std::memory_order_acquire);
                    aioInitializationReady =
                        initState == kAioInitReady ||
                        initState == kAioInitExternalBusy;
                }
                SceKernelAioSubmitId aioId = kUnsetAioId;
                const int submitRc = sceKernelAioSubmitReadCommands(
                    &active.request,
                    1,
                    aioPriority,
                    &aioId);
                const uint64_t submitTimeNs = time_counter_now();
                const int submitSceRc =
                    apr_aio_api_rc_to_sce(submitRc);
                note_aio_submit_result(submitSceRc);

#if AMPR_EMU_DEBUG_LOG && AMPR_EMU_DEBUG_LOG_TRACE
                AMPR_TLOGF("apr.reactor.aio.submit.leave job=0x%llx seq=0x%llx rc=0x%x aioId=%d fileId=%u",
                          (unsigned long long)active.job->id,
                          (unsigned long long)active.seq,
                          submitSceRc,
                          aioId,
                          active.desc.fileId);
#endif
                if ((submitRc == 0 && aioId == kUnsetAioId) ||
                    (submitRc != 0 && aioId != kUnsetAioId)) {
                    AMPR_CRITICAL_LOGF("apr.reactor.aio.submit.single.inconsistent rc=0x%x aioId=%d prio=%d action=abort",
                                       submitSceRc,
                                       aioId,
                                       aioPriority);
                    std::abort();
                }

                if (submitRc == 0) {
                    acceptPreparedRead(activeIt,
                                       selected,
                                       aioId,
                                       aioPriority,
                                       submitTimeNs);
                    continue;
                }

                if (apr_aio_submit_sce_rc_is_deferred(submitSceRc)) {
                    const uint64_t retryAtNs =
                        submitTimeNs +
                        AMPR_EMU_APR_AIO_SUBMIT_RETRY_DELAY_NS;
                    requeuePreparedRead(activeIt,
                                        selected,
                                        submitSceRc,
                                        retryAtNs,
                                        "aio-submit");
                    stopAdmission = true;
                    break;
                }

                failPreparedRead(activeIt, submitSceRc);
            }

            if (!selectedAny) {
                break;
            }
        }

        progressed |= drain_completed_aio_reads_budgeted(
            AMPR_EMU_APR_AIO_SUBMIT_POST_DRAIN_PASSES);
        return progressed;
    }

    bool finish_active_read(ActiveReadIt it, int state) {
        ActiveRead& active = *it;
        auto job = active.job;
        ReadChain* const chain = active.chain;
        const int finalState = state & ~SCE_KERNEL_AIO_STATE_NOTIFIED;
        int rc = 0;
        uint32_t errorOff = active.desc.errorOff;
        const uint64_t finishTimeNs = time_counter_now();
#if AMPR_EMU_DEBUG_LOG
        const uint64_t completeAgeNs = active_read_age_ns(active, finishTimeNs);
#endif
        const uint64_t completeAgeMs = active_read_age_ms(active, finishTimeNs);
        note_aio_age_ms(completeAgeMs);

        if (finalState == SCE_KERNEL_AIO_STATE_ABORTED) {
            rc = SCE_KERNEL_ERROR_ECANCELED;
        } else if (finalState != SCE_KERNEL_AIO_STATE_COMPLETED) {
            rc = SCE_KERNEL_ERROR_EIO;
        } else if (active.result.returnValue < 0) {
            rc = apr_aio_result_to_sce(active.result.returnValue);
        }
        const bool shortRead =
            finalState == SCE_KERNEL_AIO_STATE_COMPLETED &&
            active.result.returnValue >= 0 &&
            static_cast<uint64_t>(active.result.returnValue) != active.desc.length;

        int deleteResult = 0;
        const int deleteRc = sceKernelAioDeleteRequest(active.aioId, &deleteResult);
        const int deleteResultSceRc = apr_aio_api_rc_to_sce(deleteResult);
        const auto bumpDeleteRetry = [&active]() -> uint32_t {
            const uint32_t nextRetry =
                active.aioDeleteRetries == UINT32_MAX
                    ? UINT32_MAX
                    : active.aioDeleteRetries + 1u;
            active.aioDeleteRetries = nextRetry;
            return nextRetry;
        };
        const auto shouldLogDeleteRetry = [](uint32_t retry) -> bool {
            return retry <= 16u ||
                   (retry != 0 && (retry & (retry - 1u)) == 0);
        };
        const auto handleDeleteFailure = [&](int failureRc) {
            const uint32_t nextDeleteRetry = bumpDeleteRetry();
            if (active.aioDeleteFirstFailureNs == 0) {
                active.aioDeleteFirstFailureNs = finishTimeNs;
            }
            const uint64_t deleteFailureAgeNs =
                finishTimeNs >= active.aioDeleteFirstFailureNs
                    ? finishTimeNs - active.aioDeleteFirstFailureNs
                    : 0;
            const bool timedOut =
                (active.aioDeleteFirstFailureNs != 0 &&
                 deleteFailureAgeNs >= AMPR_EMU_APR_AIO_DELETE_TIMEOUT_NS) ||
                (finishTimeNs == 0 &&
                 nextDeleteRetry >= AMPR_EMU_APR_AIO_DELETE_RETRY_LIMIT);
            if (shouldLogDeleteRetry(nextDeleteRetry)) {
                AMPR_CRITICAL_LOGF("apr.reactor.aio.delete.pending job=0x%llx seq=0x%llx retry=%u ageMs=%llu aioId=%d deleteRc=0x%x deleteResult=0x%x deleteSce=0x%x state=0x%x return=0x%llx fileId=%u",
                               job ? (unsigned long long)job->id : 0ull,
                               (unsigned long long)active.seq,
                               nextDeleteRetry,
                               (unsigned long long)(deleteFailureAgeNs / 1000000ull),
                               active.aioId,
                               deleteRc,
                               deleteResult,
                               deleteResultSceRc,
                               state,
                               (unsigned long long)active.result.returnValue,
                               active.desc.fileId);
            }
            if (timedOut) {
                AMPR_CRITICAL_LOGF("apr.reactor.aio.delete.fatal job=0x%llx seq=0x%llx retry=%u ageMs=%llu aioId=%d rc=0x%x deleteRc=0x%x deleteResult=0x%x state=0x%x fileId=%u action=abort",
                                   job ? (unsigned long long)job->id : 0ull,
                                   (unsigned long long)active.seq,
                                   nextDeleteRetry,
                                   (unsigned long long)(deleteFailureAgeNs / 1000000ull),
                                   active.aioId,
                                   failureRc,
                                   deleteRc,
                                   deleteResult,
                                   state,
                                   active.desc.fileId);
                std::abort();
            }
            return true;
        };
        if (deleteRc != 0) {
            return handleDeleteFailure(apr_aio_api_rc_to_sce(deleteRc));
        }
        if (deleteResultSceRc != 0) {
            return handleDeleteFailure(deleteResultSceRc);
        }
        if (!job || !chain) {
            apr_release_aio_read_desc(active.desc);
            decrement_active_read_count(job);
            decrement_read_chain_active(chain);
            maybe_finish_read_chain(chain);
            return false;
        }
#if AMPR_EMU_DEBUG_LOG
        note_aio_completion_latency(completeAgeNs);
#endif
        const bool completionEfault = rc == SCE_KERNEL_ERROR_EFAULT;
        const bool completionRetryable =
            apr_aio_completion_sce_rc_is_retryable(rc);
        const uint32_t nextCompletionRetry =
            completionEfault || active.aioCompletionRetries == UINT32_MAX
                ? active.aioCompletionRetries
                : active.aioCompletionRetries + 1u;
        const bool logCompletionRetry =
            nextCompletionRetry <= 16u ||
            (nextCompletionRetry != 0 &&
             (nextCompletionRetry & (nextCompletionRetry - 1u)) == 0);

        if (rc != 0) {
#if AMPR_EMU_DEBUG_LOG && AMPR_EMU_DEBUG_LOG_FILE_STATUS
            {
                const char* pathArg = file_path_log_arg(active.desc.fileId);
                AMPR_FILE_STATUS_LOGF("apr.file.request status=failed job=0x%llx seq=0x%llx aioId=%d rc=0x%x state=0x%x return=0x%llx deleteRc=0x%x fileId=%u path=%s fd=%d buf=%p len=0x%llx off=0x%llx ageMs=%llu retry=%u",
                                      (unsigned long long)job->id,
                                      (unsigned long long)active.seq,
                                      active.aioId,
                                      rc,
                                      state,
                                      (unsigned long long)active.result.returnValue,
                                      deleteResultSceRc,
                                      active.desc.fileId,
                                      pathArg,
                                      active.desc.fd,
                                      active.desc.buffer,
                                      (unsigned long long)active.desc.length,
                                      (unsigned long long)active.desc.offset,
                                      (unsigned long long)completeAgeMs,
                                      nextCompletionRetry);
            }
#endif
#if AMPR_EMU_DEBUG_LOG
            if (logCompletionRetry) {
                const char* pathArg = file_path_log_arg(active.desc.fileId);
                AMPR_CRITICAL_LOGF("apr.reactor.aio.complete status=failed job=0x%llx seq=0x%llx aioId=%d rc=0x%x state=0x%x return=0x%llx deleteRc=0x%x fileId=%u path=%s fd=%d buf=%p len=0x%llx off=0x%llx ageMs=%llu bypass=%u closeAfter=%u errorOff=0x%x retry=%u",
                          (unsigned long long)job->id,
                          (unsigned long long)active.seq,
                          active.aioId,
                          rc,
                          state,
                          (unsigned long long)active.result.returnValue,
                          deleteResultSceRc,
                          active.desc.fileId,
                          pathArg,
                          active.desc.fd,
                          active.desc.buffer,
                          (unsigned long long)active.desc.length,
                          (unsigned long long)active.desc.offset,
                          (unsigned long long)completeAgeMs,
                          active.desc.bypassFdCache ? 1u : 0u,
                          active.desc.closeAfter ? 1u : 0u,
                          errorOff,
                          nextCompletionRetry);
            }
            if (rc == SCE_KERNEL_ERROR_EFAULT && logCompletionRetry) {
                log_aio_efault_detail(active, rc, state, deleteRc, errorOff, finishTimeNs);
            }
#endif
        }

#if AMPR_EMU_DEBUG_LOG && AMPR_EMU_APR_AIO_SLOW_WARN_MS != 0
        if (collect_log_stats() && rc == 0 && completeAgeMs >= AMPR_EMU_APR_AIO_SLOW_WARN_MS) {
            log_active_read_detail("apr.reactor.aio.slowComplete",
                                   "complete",
                                   active,
                                   finishTimeNs,
                                   state,
                                   0);
        }
#endif
        if (rc == 0) {
            note_slow_aio_completion(finishTimeNs, completeAgeMs);
        }

        if (rc == 0 && shortRead) {
            set_or_defer_read_command_error(
                *job,
                "aio-short-read",
                SCE_AMPR_ERROR_APR_INVALIDFILEOFFSET,
                errorOff);
#if AMPR_EMU_DEBUG_LOG && AMPR_EMU_DEBUG_LOG_FILE_STATUS
            {
                const char* pathArg = file_path_log_arg(active.desc.fileId);
                AMPR_FILE_STATUS_LOGF("apr.file.request status=short-read job=0x%llx seq=0x%llx aioId=%d fileId=%u path=%s fd=%d actual=0x%llx requested=0x%llx off=0x%llx",
                                      (unsigned long long)job->id,
                                      (unsigned long long)active.seq,
                                      active.aioId,
                                      active.desc.fileId,
                                      pathArg,
                                      active.desc.fd,
                                      (unsigned long long)active.result.returnValue,
                                      (unsigned long long)active.desc.length,
                                      (unsigned long long)active.desc.offset);
            }
#endif
            AMPR_CRITICAL_LOGF("apr.reactor.aio.complete status=short-read job=0x%llx seq=0x%llx aioId=%d actual=0x%llx requested=0x%llx fileId=%u fd=%d off=0x%llx aprResult=0x%x eofLikely=%u",
                      (unsigned long long)job->id,
                      (unsigned long long)active.seq,
                      active.aioId,
                      (unsigned long long)active.result.returnValue,
                      (unsigned long long)active.desc.length,
                      active.desc.fileId,
                      active.desc.fd,
                      (unsigned long long)active.desc.offset,
                      SCE_AMPR_ERROR_APR_INVALIDFILEOFFSET,
                      active.result.returnValue == 0 ? 1u : 0u);
        }

        const bool efaultRetryLimitReached =
            completionEfault &&
            static_cast<uint64_t>(active.ammEfaultRetries) >=
                static_cast<uint64_t>(AMPR_EMU_APR_AIO_AMM_EFAULT_RETRY_LIMIT);
        const bool completionRetryLimitReached =
            completionRetryable &&
            static_cast<uint64_t>(active.aioCompletionRetries) >=
                static_cast<uint64_t>(AMPR_EMU_APR_AIO_COMPLETION_RETRY_LIMIT);

        if (rc != 0 &&
            !job_failed(*job) &&
            !cross_eop_suffix_is_canceled(*job, errorOff) &&
            (completionEfault || completionRetryable) &&
            !efaultRetryLimitReached &&
            !completionRetryLimitReached) {
            const uint64_t retryDelayNs = completionEfault
                                              ? AMPR_EMU_APR_AIO_AMM_EFAULT_RETRY_DELAY_NS
                                              : AMPR_EMU_APR_AIO_COMPLETION_RETRY_DELAY_NS;
            const uint64_t retryAtNs = finishTimeNs + retryDelayNs;
            const size_t prio = apr_clamp_priority(job->prioIndex);
            move_active_read_to_pending(job, chain);
            const uint32_t fileId = active.desc.fileId;
            void* const buffer = active.desc.buffer;
            const uint64_t length = active.desc.length;
            const uint64_t offset = active.desc.offset;
            const uint64_t seq = active.seq;
            const size_t commandIndex = active.commandIndex;
            const uint32_t nextAmmEfaultRetries =
                completionEfault && active.ammEfaultRetries != UINT32_MAX
                    ? active.ammEfaultRetries + 1u
                    : active.ammEfaultRetries;
            if (completionEfault) {
                note_efault_retry_event();
            }
            AprAioReadDesc desc = ampr_move(active.desc);
            apr_release_aio_read_desc(desc);
            requeue_pending_read_front(prio,
                                       job,
                                       ampr_move(desc),
                                       chain,
                                       seq,
                                       commandIndex,
                                       nextAmmEfaultRetries,
                                       retryAtNs,
                                       nextCompletionRetry,
                                       true);
            if (logCompletionRetry) {
                AMPR_CRITICAL_LOGF("apr.reactor.aio.complete.retry job=0x%llx seq=0x%llx retry=%u ammRetry=%u delayNs=%llu rc=0x%x fileId=%u buf=%p len=0x%llx off=0x%llx pendingReads=%zu activeReads=%zu",
                                   (unsigned long long)job->id,
                                   (unsigned long long)seq,
                                   nextCompletionRetry,
                                   nextAmmEfaultRetries,
                                   (unsigned long long)retryDelayNs,
                                   rc,
                                   fileId,
                                   buffer,
                                   (unsigned long long)length,
                                   (unsigned long long)offset,
                                   pending_read_total(),
                                   activeReads.size());
            }
            (void)fileId;
            (void)buffer;
            (void)length;
            (void)offset;
            return false;
        }

        if (rc != 0 && !job_failed(*job) && completionRetryLimitReached) {
            AMPR_CRITICAL_LOGF("apr.reactor.aio.complete.retry-limit job=0x%llx seq=0x%llx retry=%u limit=%llu rc=0x%x state=0x%x return=0x%llx deleteRc=0x%x fileId=%u path=%s fd=%d buf=%p len=0x%llx off=0x%llx",
                               (unsigned long long)job->id,
                               (unsigned long long)active.seq,
                               active.aioCompletionRetries,
                               (unsigned long long)AMPR_EMU_APR_AIO_COMPLETION_RETRY_LIMIT,
                               rc,
                               state,
                               (unsigned long long)active.result.returnValue,
                               deleteResultSceRc,
                               active.desc.fileId,
                               file_path_log_arg(active.desc.fileId),
                               active.desc.fd,
                               active.desc.buffer,
                               (unsigned long long)active.desc.length,
                               (unsigned long long)active.desc.offset);
            set_or_defer_read_command_error(
                *job,
                "aio-completion-retry-limit",
                apr_backend_read_error_to_apr(rc),
                errorOff);
        }

        if (rc != 0 && !job_failed(*job) && efaultRetryLimitReached) {
            note_efault_retry_limit_event();
            AMPR_CRITICAL_LOGF("apr.reactor.aio.efault.retry-limit job=0x%llx seq=0x%llx retry=%u limit=%llu rc=0x%x fileId=%u buf=%p len=0x%llx off=0x%llx",
                               (unsigned long long)job->id,
                               (unsigned long long)active.seq,
                               active.ammEfaultRetries,
                               (unsigned long long)AMPR_EMU_APR_AIO_AMM_EFAULT_RETRY_LIMIT,
                               rc,
                               active.desc.fileId,
                               active.desc.buffer,
                               (unsigned long long)active.desc.length,
                               (unsigned long long)active.desc.offset);
            set_or_defer_read_command_error(
                *job,
                "aio-efault-retry-limit",
                apr_backend_read_error_to_apr(rc),
                errorOff);
        }

        if (rc != 0 && !job_failed(*job) &&
            !completionEfault && !completionRetryable) {
            AMPR_CRITICAL_LOGF("apr.reactor.aio.complete.nonretryable job=0x%llx seq=0x%llx rc=0x%x state=0x%x return=0x%llx fileId=%u fd=%d off=0x%llx",
                               (unsigned long long)job->id,
                               (unsigned long long)active.seq,
                               rc,
                               state,
                               (unsigned long long)active.result.returnValue,
                               active.desc.fileId,
                               active.desc.fd,
                               (unsigned long long)active.desc.offset);
            set_or_defer_read_command_error(
                *job,
                "aio-completion-nonretryable",
                apr_backend_read_error_to_apr(rc),
                errorOff);
        }

#if AMPR_EMU_APR_AIO_CROSS_EOP_READAHEAD
        if (job->crossEopDeferredErrorOffset != UINT32_MAX &&
            chain->ownerDesc.errorOff >=
                job->crossEopDeferredErrorOffset) {
            chain->allIssued = true;
        }
#endif

        decrement_active_read_count(job);
        decrement_read_chain_active(chain);
        maybe_finish_read_chain(chain);

        AMPR_TLOGF("apr.reactor.aio.complete job=0x%llx seq=0x%llx aioId=%d rc=0x%x state=0x%x return=0x%llx deleteRc=0x%x pending=%u active=%u completedSeq=0x%llx",
                  (unsigned long long)job->id,
                  (unsigned long long)active.seq,
                  active.aioId,
                  rc,
                  state,
                  (unsigned long long)active.result.returnValue,
                  deleteResultSceRc,
                  job->pendingReadCount,
                  job->activeReadCount,
                  (unsigned long long)job->completedReadSeq);
#if AMPR_EMU_DEBUG_LOG && AMPR_EMU_DEBUG_LOG_FILE_STATUS
        if (!shortRead) {
            const char* pathArg = file_path_log_arg(active.desc.fileId);
            AMPR_FILE_STATUS_LOGF("apr.file.request status=completed job=0x%llx seq=0x%llx aioId=%d fileId=%u path=%s fd=%d buf=%p len=0x%llx off=0x%llx bytes=0x%llx ageMs=%llu",
                                  (unsigned long long)job->id,
                                  (unsigned long long)active.seq,
                                  active.aioId,
                                  active.desc.fileId,
                                  pathArg,
                                  active.desc.fd,
                                  active.desc.buffer,
                                  (unsigned long long)active.desc.length,
                                  (unsigned long long)active.desc.offset,
                                  (unsigned long long)active.result.returnValue,
                                  (unsigned long long)completeAgeMs);
        }
#endif
        apr_release_aio_read_desc(active.desc);
        return false;
    }

    bool wait_aio_once() {
        if (activeReads.empty()) {
            return false;
        }
        return poll_active_aio_reads_once(true);
    }

    void note_reactor_progress(bool progressed) {
#if AMPR_EMU_DEBUG_LOG && AMPR_EMU_APR_REACTOR_STALL_WARN_ITERATIONS != 0
        if (progressed) {
            stallLoopCount = 0;
            stallStartTimeNs = 0;
            return;
        }
        if (++stallLoopCount == AMPR_EMU_APR_REACTOR_STALL_WARN_ITERATIONS) {
            const uint64_t now = time_counter_now();
            stallStartTimeNs = now;
            AMPR_CRITICAL_LOGF("apr.reactor.stall activeJobs=%zu pendingReads=%zu activeReads=%zu",
                               active_lane_count_locked(),
                               pending_read_total(),
                               activeReads.size());
            log_runtime_counters("stall", now, true);
            log_buffer_occupancy("stall", now);
        }
#else
        (void)progressed;
#endif
    }

#if AMPR_EMU_DEBUG_LOG
#if AMPR_EMU_APR_REACTOR_STALL_WARN_ITERATIONS != 0 || AMPR_EMU_APR_REACTOR_HEARTBEAT_MS != 0
    void log_runtime_counters(const char* reason, uint64_t now, bool reset) {
        if (!collect_log_stats()) {
            return;
        }
        const uint64_t currentOldestAgeMs = oldest_active_read_age_ms(now);
        const uint64_t maxAioAgeMs =
            currentOldestAgeMs > runtimeMaxAioAgeMs ? currentOldestAgeMs : runtimeMaxAioAgeMs;
        const AmprIndexFdCacheDiagCounters fdCounters = ampr_index_fd_cache_diag_counters(reset);
        const uint64_t directEmfile = reset
            ? g_apr_direct_emfile_events.exchange(0, std::memory_order_relaxed)
            : g_apr_direct_emfile_events.load(std::memory_order_relaxed);
        const DirectReadCounts directCounts = active_direct_read_counts();
        const uint64_t aioCompletionAvgUs =
            runtimeAioCompletionCount != 0
                ? runtimeAioCompletionTotalUs / runtimeAioCompletionCount
                : 0;
        const uint64_t windowStartNs =
            runtimeCounterWindowStartNs != 0 ? runtimeCounterWindowStartNs : now;
        const uint64_t counterWindowNs = now >= windowStartNs ? now - windowStartNs : 0;
        const uint64_t counterWindowMs = counterWindowNs / 1000000ull;
        const uint64_t workerWakeupsPerSec =
            counter_rate_per_sec(runtimeWorkerWakeups, counterWindowNs);
        const uint64_t idlePollPassesPerSec =
            counter_rate_per_sec(runtimeIdlePollPasses, counterWindowNs);

        AMPR_LOGF("apr.reactor.counters.latency reason=%s peakPending=%llu peakActive=%llu currentPending=%zu currentActive=%zu maxAioAgeMs=%llu currentOldestAioAgeMs=%llu aioCompleteCount=%llu aioCompleteAvgUs=%llu aioCompleteMaxUs=%llu aioSubmitCompleteP95Us=%llu aioSubmitCompleteP99Us=%llu nativeTriggerSubmitCount=%llu nativeTriggerSubmitAvgUs=%llu nativeTriggerSubmitP95Us=%llu nativeTriggerSubmitP99Us=%llu nativeTriggerSubmitMaxUs=%llu completionReleaseCount=%llu completionReleaseAvgUs=%llu completionReleaseP95Us=%llu completionReleaseP99Us=%llu completionReleaseMaxUs=%llu counterWindowMs=%llu",
                  reason ? reason : "unknown",
                  (unsigned long long)runtimePeakPendingReads,
                  (unsigned long long)runtimePeakActiveReads,
                  pending_read_total(),
                  activeReads.size(),
                  (unsigned long long)maxAioAgeMs,
                  (unsigned long long)currentOldestAgeMs,
                  (unsigned long long)runtimeAioCompletionCount,
                  (unsigned long long)aioCompletionAvgUs,
                  (unsigned long long)runtimeAioCompletionMaxUs,
                  (unsigned long long)latency_percentile_us(runtimeAioSubmitToCompletionLatency, 95),
                  (unsigned long long)latency_percentile_us(runtimeAioSubmitToCompletionLatency, 99),
                  (unsigned long long)runtimeNativeTriggerToSubmitLatency.count,
                  (unsigned long long)latency_average_us(runtimeNativeTriggerToSubmitLatency),
                  (unsigned long long)latency_percentile_us(runtimeNativeTriggerToSubmitLatency, 95),
                  (unsigned long long)latency_percentile_us(runtimeNativeTriggerToSubmitLatency, 99),
                  (unsigned long long)runtimeNativeTriggerToSubmitLatency.maxUs,
                  (unsigned long long)runtimeCompletionToReleaseLatency.count,
                  (unsigned long long)latency_average_us(runtimeCompletionToReleaseLatency),
                  (unsigned long long)latency_percentile_us(runtimeCompletionToReleaseLatency, 95),
                  (unsigned long long)latency_percentile_us(runtimeCompletionToReleaseLatency, 99),
                  (unsigned long long)runtimeCompletionToReleaseLatency.maxUs,
                  (unsigned long long)counterWindowMs);
        AMPR_LOGF("apr.reactor.counters.admission reason=%s jobQueueFirstAioCount=%llu jobQueueFirstAioTotalUs=%llu jobQueueFirstAioAvgUs=%llu jobQueueFirstAioP95Us=%llu jobQueueFirstAioP99Us=%llu jobQueueFirstAioMaxUs=%llu pendingReadQueueSubmitCount=%llu pendingReadQueueSubmitTotalUs=%llu pendingReadQueueSubmitAvgUs=%llu pendingReadQueueSubmitP95Us=%llu pendingReadQueueSubmitP99Us=%llu pendingReadQueueSubmitMaxUs=%llu counterWindowMs=%llu",
                  reason ? reason : "unknown",
                  (unsigned long long)runtimeJobQueueToFirstAioLatency.count,
                  (unsigned long long)runtimeJobQueueToFirstAioLatency.totalUs,
                  (unsigned long long)latency_average_us(runtimeJobQueueToFirstAioLatency),
                  (unsigned long long)latency_percentile_us(runtimeJobQueueToFirstAioLatency, 95),
                  (unsigned long long)latency_percentile_us(runtimeJobQueueToFirstAioLatency, 99),
                  (unsigned long long)runtimeJobQueueToFirstAioLatency.maxUs,
                  (unsigned long long)runtimePendingReadQueueToAioLatency.count,
                  (unsigned long long)runtimePendingReadQueueToAioLatency.totalUs,
                  (unsigned long long)latency_average_us(runtimePendingReadQueueToAioLatency),
                  (unsigned long long)latency_percentile_us(runtimePendingReadQueueToAioLatency, 95),
                  (unsigned long long)latency_percentile_us(runtimePendingReadQueueToAioLatency, 99),
                  (unsigned long long)runtimePendingReadQueueToAioLatency.maxUs,
                  (unsigned long long)counterWindowMs);
        AMPR_LOGF("apr.reactor.counters.admission.stage reason=%s jobQueueFirstReadCount=%llu jobQueueFirstReadTotalUs=%llu jobQueueFirstReadP95Us=%llu jobQueueFirstReadP99Us=%llu jobQueueFirstReadMaxUs=%llu firstReadQueueFirstAioCount=%llu firstReadQueueFirstAioTotalUs=%llu firstReadQueueFirstAioP95Us=%llu firstReadQueueFirstAioP99Us=%llu firstReadQueueFirstAioMaxUs=%llu counterWindowMs=%llu",
                  reason ? reason : "unknown",
                  (unsigned long long)runtimeJobQueueToFirstReadLatency.count,
                  (unsigned long long)runtimeJobQueueToFirstReadLatency.totalUs,
                  (unsigned long long)latency_percentile_us(runtimeJobQueueToFirstReadLatency, 95),
                  (unsigned long long)latency_percentile_us(runtimeJobQueueToFirstReadLatency, 99),
                  (unsigned long long)runtimeJobQueueToFirstReadLatency.maxUs,
                  (unsigned long long)runtimeFirstReadQueueToFirstAioLatency.count,
                  (unsigned long long)runtimeFirstReadQueueToFirstAioLatency.totalUs,
                  (unsigned long long)latency_percentile_us(runtimeFirstReadQueueToFirstAioLatency, 95),
                  (unsigned long long)latency_percentile_us(runtimeFirstReadQueueToFirstAioLatency, 99),
                  (unsigned long long)runtimeFirstReadQueueToFirstAioLatency.maxUs,
                  (unsigned long long)counterWindowMs);
        AMPR_LOGF("apr.reactor.counters.loop reason=%s activeLoopGapCount=%llu activeLoopGapTotalUs=%llu activeLoopGapP95Us=%llu activeLoopGapP99Us=%llu activeLoopGapMaxUs=%llu wakeOvershootCount=%llu wakeOvershootTotalUs=%llu wakeOvershootP95Us=%llu wakeOvershootP99Us=%llu wakeOvershootMaxUs=%llu counterWindowMs=%llu",
                  reason ? reason : "unknown",
                  (unsigned long long)runtimeReactorActiveLoopGapLatency.count,
                  (unsigned long long)runtimeReactorActiveLoopGapLatency.totalUs,
                  (unsigned long long)latency_percentile_us(runtimeReactorActiveLoopGapLatency, 95),
                  (unsigned long long)latency_percentile_us(runtimeReactorActiveLoopGapLatency, 99),
                  (unsigned long long)runtimeReactorActiveLoopGapLatency.maxUs,
                  (unsigned long long)runtimeReactorWakeOvershootLatency.count,
                  (unsigned long long)runtimeReactorWakeOvershootLatency.totalUs,
                  (unsigned long long)latency_percentile_us(runtimeReactorWakeOvershootLatency, 95),
                  (unsigned long long)latency_percentile_us(runtimeReactorWakeOvershootLatency, 99),
                  (unsigned long long)runtimeReactorWakeOvershootLatency.maxUs,
                  (unsigned long long)counterWindowMs);
        for (size_t priority = 0; priority < kPriorityCount; ++priority) {
            const LatencyHistogram& firstRead =
                runtimeJobQueueToFirstReadLatencyByPriority[priority];
            const LatencyHistogram& firstSubmit =
                runtimeFirstReadQueueToFirstAioLatencyByPriority[priority];
            const LatencyHistogram& total =
                runtimeJobQueueToFirstAioLatencyByPriority[priority];
            const LatencyHistogram& pending =
                runtimePendingReadQueueToAioLatencyByPriority[priority];
            if (firstRead.count == 0 && firstSubmit.count == 0 &&
                total.count == 0 && pending.count == 0) {
                continue;
            }
            AMPR_LOGF("apr.reactor.counters.admission.prio.job reason=%s aprPrio=%zu jobQueueFirstReadCount=%llu jobQueueFirstReadTotalUs=%llu jobQueueFirstReadP95Us=%llu jobQueueFirstReadP99Us=%llu jobQueueFirstReadMaxUs=%llu firstReadQueueFirstAioCount=%llu firstReadQueueFirstAioTotalUs=%llu firstReadQueueFirstAioP95Us=%llu firstReadQueueFirstAioP99Us=%llu firstReadQueueFirstAioMaxUs=%llu jobQueueFirstAioCount=%llu jobQueueFirstAioTotalUs=%llu jobQueueFirstAioP95Us=%llu jobQueueFirstAioP99Us=%llu jobQueueFirstAioMaxUs=%llu counterWindowMs=%llu",
                      reason ? reason : "unknown",
                      priority,
                      (unsigned long long)firstRead.count,
                      (unsigned long long)firstRead.totalUs,
                      (unsigned long long)latency_percentile_us(firstRead, 95),
                      (unsigned long long)latency_percentile_us(firstRead, 99),
                      (unsigned long long)firstRead.maxUs,
                      (unsigned long long)firstSubmit.count,
                      (unsigned long long)firstSubmit.totalUs,
                      (unsigned long long)latency_percentile_us(firstSubmit, 95),
                      (unsigned long long)latency_percentile_us(firstSubmit, 99),
                      (unsigned long long)firstSubmit.maxUs,
                      (unsigned long long)total.count,
                      (unsigned long long)total.totalUs,
                      (unsigned long long)latency_percentile_us(total, 95),
                      (unsigned long long)latency_percentile_us(total, 99),
                      (unsigned long long)total.maxUs,
                      (unsigned long long)counterWindowMs);
            AMPR_LOGF("apr.reactor.counters.admission.prio.pending reason=%s aprPrio=%zu pendingReadQueueSubmitCount=%llu pendingReadQueueSubmitTotalUs=%llu pendingReadQueueSubmitP95Us=%llu pendingReadQueueSubmitP99Us=%llu pendingReadQueueSubmitMaxUs=%llu counterWindowMs=%llu",
                      reason ? reason : "unknown",
                      priority,
                      (unsigned long long)pending.count,
                      (unsigned long long)pending.totalUs,
                      (unsigned long long)latency_percentile_us(pending, 95),
                      (unsigned long long)latency_percentile_us(pending, 99),
                      (unsigned long long)pending.maxUs,
                      (unsigned long long)counterWindowMs);
        }
        AMPR_LOGF("apr.reactor.counters.io reason=%s acceptedCount=%llu acceptedBytes=%llu le64K=%llu le256K=%llu partialQuantum=%llu fullQuantum=%llu overQuantum=%llu quantumBytes=%u apr0Count=%llu apr0Bytes=%llu apr1Count=%llu apr1Bytes=%llu apr2Count=%llu apr2Bytes=%llu apr3Count=%llu apr3Bytes=%llu apr4Count=%llu apr4Bytes=%llu apr5Count=%llu apr5Bytes=%llu apr6Count=%llu apr6Bytes=%llu counterWindowMs=%llu",
                  reason ? reason : "unknown",
                  (unsigned long long)runtimeAioAcceptedRequestCount,
                  (unsigned long long)runtimeAioAcceptedBytes,
                  (unsigned long long)runtimeAioAcceptedLe64K,
                  (unsigned long long)runtimeAioAcceptedLe256K,
                  (unsigned long long)runtimeAioAcceptedPartialQuantum,
                  (unsigned long long)runtimeAioAcceptedFullQuantum,
                  (unsigned long long)runtimeAioAcceptedOverQuantum,
                  (unsigned)AMPR_EMU_APR_AIO_DISPATCH_QUANTUM_BYTES,
                  (unsigned long long)runtimeAioAcceptedRequestCountByPriority[0],
                  (unsigned long long)runtimeAioAcceptedBytesByPriority[0],
                  (unsigned long long)runtimeAioAcceptedRequestCountByPriority[1],
                  (unsigned long long)runtimeAioAcceptedBytesByPriority[1],
                  (unsigned long long)runtimeAioAcceptedRequestCountByPriority[2],
                  (unsigned long long)runtimeAioAcceptedBytesByPriority[2],
                  (unsigned long long)runtimeAioAcceptedRequestCountByPriority[3],
                  (unsigned long long)runtimeAioAcceptedBytesByPriority[3],
                  (unsigned long long)runtimeAioAcceptedRequestCountByPriority[4],
                  (unsigned long long)runtimeAioAcceptedBytesByPriority[4],
                  (unsigned long long)runtimeAioAcceptedRequestCountByPriority[5],
                  (unsigned long long)runtimeAioAcceptedBytesByPriority[5],
                  (unsigned long long)runtimeAioAcceptedRequestCountByPriority[6],
                  (unsigned long long)runtimeAioAcceptedBytesByPriority[6],
                  (unsigned long long)counterWindowMs);
        AMPR_LOGF("apr.reactor.counters.runtime reason=%s aioPollCalls=%llu aioPollBackoffSkips=%llu aioPollBudgetYields=%llu aioPollWorkNs=%llu aioPollSleepNs=%llu deadlineHeapPicks=%llu deadlineHeapFutureStops=%llu activeReadDuePolls=%llu activeReadNotDueSkips=%llu workerWakeups=%llu workerWakeupsPerSec=%llu idlePollPasses=%llu idlePollPassesPerSec=%llu emfile=%llu directEmfile=%llu efaultRetry=%llu efaultRetryLimit=%llu fdCacheHit=%llu fdCacheMiss=%llu fdCacheEmfile=%llu activeDirect=%zu activeDirectSmall=%zu activeDirectNormal=%zu activeDirectBulk=%zu fdCacheMinFileBytes=%llu aioLimit=%u aioInitState=%u aioInitLastRc=0x%x aioInitAttempts=%llu aioInitOk=%llu aioInitBusy=%llu aioInitFail=%llu aioSubmitEagain=%llu",
                  reason ? reason : "unknown",
                  (unsigned long long)runtimeAioPollCalls,
                  (unsigned long long)runtimeAioPollBackoffSkips,
                  (unsigned long long)runtimeAioPollBudgetYields,
                  (unsigned long long)runtimeAioPollWorkNs,
                  (unsigned long long)runtimeAioPollSleepNs,
                  (unsigned long long)runtimeDeadlineHeapPicks,
                  (unsigned long long)runtimeDeadlineHeapFutureStops,
                  (unsigned long long)runtimeActiveReadDuePolls,
                  (unsigned long long)runtimeActiveReadNotDueSkips,
                  (unsigned long long)runtimeWorkerWakeups,
                  (unsigned long long)workerWakeupsPerSec,
                  (unsigned long long)runtimeIdlePollPasses,
                  (unsigned long long)idlePollPassesPerSec,
                  (unsigned long long)runtimeEmfileEvents,
                  (unsigned long long)directEmfile,
                  (unsigned long long)runtimeEfaultRetryEvents,
                  (unsigned long long)runtimeEfaultRetryLimitEvents,
                  (unsigned long long)fdCounters.hits,
                  (unsigned long long)fdCounters.misses,
                  (unsigned long long)fdCounters.emfile,
                  directCounts.total,
                  directCounts.small,
                  directCounts.normal,
                  directCounts.bulk,
                  (unsigned long long)AMPR_EMU_APR_FD_CACHE_MIN_FILE_BYTES,
                  (unsigned)aio_active_read_limit(),
                  aioInitState.load(std::memory_order_relaxed),
                  aioInitLastRc.load(std::memory_order_relaxed),
                  (unsigned long long)aioInitAttemptCount.load(std::memory_order_relaxed),
                  (unsigned long long)aioInitSuccessCount.load(std::memory_order_relaxed),
                  (unsigned long long)aioInitBusyCount.load(std::memory_order_relaxed),
                  (unsigned long long)aioInitFailCount.load(std::memory_order_relaxed),
                  (unsigned long long)aioSubmitEagainCount.load(std::memory_order_relaxed));
        if (reset) {
            runtimePeakPendingReads = pending_read_total();
            runtimePeakActiveReads = activeReads.size();
            runtimeEmfileEvents = 0;
            runtimeEfaultRetryEvents = 0;
            runtimeEfaultRetryLimitEvents = 0;
            runtimeMaxAioAgeMs = currentOldestAgeMs;
            runtimeAioCompletionCount = 0;
            runtimeAioCompletionTotalUs = 0;
            runtimeAioCompletionMaxUs = 0;
            runtimeAioPollCalls = 0;
            runtimeAioPollBackoffSkips = 0;
            runtimeAioPollBudgetYields = 0;
            runtimeAioPollWorkNs = 0;
            runtimeAioPollSleepNs = 0;
            runtimeDeadlineHeapPicks = 0;
            runtimeDeadlineHeapFutureStops = 0;
            runtimeActiveReadDuePolls = 0;
            runtimeActiveReadNotDueSkips = 0;
            runtimeWorkerWakeups = 0;
            runtimeIdlePollPasses = 0;
            for (size_t priority = 0; priority < kPriorityCount; ++priority) {
                runtimeAioAcceptedRequestCountByPriority[priority] = 0;
                runtimeAioAcceptedBytesByPriority[priority] = 0;
                reset_latency_histogram(
                    runtimeJobQueueToFirstReadLatencyByPriority[priority]);
                reset_latency_histogram(
                    runtimeFirstReadQueueToFirstAioLatencyByPriority[priority]);
                reset_latency_histogram(
                    runtimeJobQueueToFirstAioLatencyByPriority[priority]);
                reset_latency_histogram(
                    runtimePendingReadQueueToAioLatencyByPriority[priority]);
            }
            runtimeAioAcceptedRequestCount = 0;
            runtimeAioAcceptedBytes = 0;
            runtimeAioAcceptedLe64K = 0;
            runtimeAioAcceptedLe256K = 0;
            runtimeAioAcceptedPartialQuantum = 0;
            runtimeAioAcceptedFullQuantum = 0;
            runtimeAioAcceptedOverQuantum = 0;
            runtimeCounterWindowStartNs = now;
            reset_latency_histogram(runtimeJobQueueToFirstReadLatency);
            reset_latency_histogram(runtimeFirstReadQueueToFirstAioLatency);
            reset_latency_histogram(runtimeJobQueueToFirstAioLatency);
            reset_latency_histogram(runtimePendingReadQueueToAioLatency);
            reset_latency_histogram(runtimeReactorActiveLoopGapLatency);
            reset_latency_histogram(runtimeReactorWakeOvershootLatency);
            reset_latency_histogram(runtimeNativeTriggerToSubmitLatency);
            reset_latency_histogram(runtimeAioSubmitToCompletionLatency);
            reset_latency_histogram(runtimeCompletionToReleaseLatency);
        }
    }

    void log_buffer_occupancy(const char* reason, uint64_t now) {
        if (!collect_log_stats()) {
            return;
        }
        const char* const tag = reason ? reason : "unknown";
        const size_t pendingTotal = pendingReadTotalAtomic.load(std::memory_order_relaxed);
        const size_t pendingFreeRaw = pendingReadFree.count;
        const size_t pendingCapacity = pendingReadFree.capacity;
        const bool pendingFreeValid = pendingFreeRaw <= pendingCapacity;
        const size_t pendingUsed =
            pendingFreeValid ? pendingCapacity - pendingFreeRaw : pendingTotal;
        const size_t activeReadCount = activeReads.size();
        uint32_t nativeReady = 0;
        {
            AmprSpinLock lock(&nativeExecutionPoolLock);
            nativeReady = nativeExecutionPoolReady ? 1u : 0u;
        }

        const AmprIndexFdCacheStats fdStats = ampr_index_fd_cache_stats();
        const AmprIndexFdPressureCaps fdCaps = ampr_index_fd_pressure_current_caps();
        const size_t directOpen = ampr_index_fd_direct_open_count();
        const size_t observedOpen = fdStats.open + directOpen;
        const bool fdPressure = fdPressureUntilNs != 0 && now < fdPressureUntilNs;

        AMPR_LOGF("apr.reactor.occupancy reason=%s activeJobs=%zu/%u pendingReadNodes=%zu/%zu pendingReads=%zu activeReads=%zu/%u pollDeadlines=%u nativeMicroReady=%u fdEntries=%zu/%u fdOpen=%zu directOpen=%zu observedOpen=%zu fdBudget=%zu fdCacheCap=%zu fdDirectCap=%zu fdPinnedOpen=%zu fdPins=%zu fdEvictable=%zu fdPressure=%u fdPressureLevel=%u",
                  tag,
                  active_lane_count_locked(),
                  (unsigned)kJobStatePoolCapacity,
                  pendingUsed,
                  pendingCapacity,
                  pendingTotal,
                  activeReadCount,
                  (unsigned)aio_active_read_limit(),
                  activePollDeadlineHeapSize,
                  nativeReady,
                  fdStats.entries,
                  (unsigned)AMPR_EMU_FD_CACHE_CAP,
                  fdStats.open,
                  directOpen,
                  observedOpen,
                  fdCaps.fdBudget,
                  fdCaps.cacheCap,
                  fdCaps.directCap,
                  fdStats.pinnedOpen,
                  fdStats.pins,
                  fdStats.evictable,
                  fdPressure ? 1u : 0u,
                  (unsigned)fdPressureLevel);
        ampr_runtime_memory_log_heartbeat(tag);
    }
#endif
#endif

#if AMPR_EMU_DEBUG_LOG && AMPR_EMU_APR_REACTOR_HEARTBEAT_MS != 0
    void log_reactor_state(const char* reason) {
        if (!collect_log_stats()) {
            return;
        }
        const uint64_t now = time_counter_now();
        uint64_t firstJobId = 0;
        size_t firstJobOpIndex = 0;
        uint32_t firstJobCommands = 0;
        const char* firstJobOp = "none";
        uint32_t firstJobPending = 0;
        uint32_t firstJobActive = 0;
        uint32_t firstJobFailed = 0;
        if (auto firstJob = first_active_job_locked()) {
            const auto& job = *firstJob;
            firstJobId = job.id;
            firstJobOpIndex = job_op_index_for_log(job);
            firstJobCommands = job_commands_for_log(job);
            Op op{};
            firstJobOp = decode_first_native_op_const(job, &op)
                             ? sce::Ampr::ampr_op_name(op.type)
                             : "none";
            firstJobPending = job.pendingReadCount;
            firstJobActive = job.activeReadCount;
            firstJobFailed = job_failed(job) ? 1u : 0u;
        }

        uint64_t firstAioJob = 0;
        uint64_t firstAioSeq = 0;
        uint32_t firstAioFileId = 0;
        uint64_t firstAioLen = 0;
        uint64_t firstAioOff = 0;
        int firstAioId = 0;
        uint64_t firstAioAgeMs = 0;
        if (!activeReads.empty()) {
            const ActiveRead& active = activeReads.front();
            firstAioId = active.aioId;
            firstAioJob = active.job ? active.job->id : 0;
            firstAioSeq = active.seq;
            firstAioFileId = active.desc.fileId;
            firstAioLen = active.desc.length;
            firstAioOff = active.desc.offset;
            firstAioAgeMs = active.submitTimeNs != 0 && now >= active.submitTimeNs
                                ? (now - active.submitTimeNs) / 1000000ull
                                : 0;
        }

        AMPR_LOGF("apr.reactor.state reason=%s activeJobs=%zu pendingReads=%zu activeReads=%zu firstJob=0x%llx opIndex=%zu commands=%u op=%s jobPending=%u jobActive=%u jobFailed=%u firstAioId=%d firstAioAgeMs=%llu firstAioJob=0x%llx firstAioSeq=0x%llx firstAioFileId=%u firstAioLen=0x%llx firstAioOff=0x%llx",
                  reason ? reason : "unknown",
                  active_lane_count_locked(),
                  pending_read_total(),
                  activeReads.size(),
                  (unsigned long long)firstJobId,
                  firstJobOpIndex,
                  firstJobCommands,
                  firstJobOp,
                  firstJobPending,
                  firstJobActive,
                  firstJobFailed,
                  firstAioId,
                  (unsigned long long)firstAioAgeMs,
                  (unsigned long long)firstAioJob,
                  (unsigned long long)firstAioSeq,
                  firstAioFileId,
                  (unsigned long long)firstAioLen,
                  (unsigned long long)firstAioOff);
        log_runtime_counters(reason, now, true);
        log_buffer_occupancy(reason, now);
    }

    void maybe_log_reactor_heartbeat() {
        if (!collect_log_stats()) {
            return;
        }
        const uint64_t now = time_counter_now();
        const uint64_t intervalNs =
            static_cast<uint64_t>(AMPR_EMU_APR_REACTOR_HEARTBEAT_MS) * 1000000ull;
        if (lastReactorHeartbeatNs != 0 && now - lastReactorHeartbeatNs < intervalNs) {
            return;
        }
        const bool hasWork =
            has_active_lanes_locked() ||
            !activeReads.empty() ||
            pendingReadTotalAtomic.load(std::memory_order_relaxed) != 0;
        lastReactorHeartbeatNs = now;
        log_reactor_state(hasWork ? "heartbeat" : "heartbeat-idle");
    }
#endif

    void refresh_native_batch_progress_snapshots() {
        for (uint32_t laneIndex = 0; laneIndex < kPriorityCount; ++laneIndex) {
            NativeBatchLane& lane = nativeBatchLanes[laneIndex];
            if (lane.activeBuffer < 0) {
                continue;
            }
            const uint32_t bufferIndex =
                static_cast<uint32_t>(lane.activeBuffer);
            NativeBatchState& state = lane.buffers[bufferIndex];
            AprNativeBatchSlot* const slot =
                apr_native_batch_slot(laneIndex, bufferIndex);
            if (!slot || state.phase != NativeBatchPhase::Active) {
                AMPR_CRITICAL_LOGF("apr.reactor.native.batch.snapshot.invalid lane=%u buffer=%u slot=%p phase=%u",
                                   laneIndex,
                                   bufferIndex,
                                   slot,
                                   static_cast<unsigned>(state.phase));
                std::abort();
            }
            state.observedProgress =
                __atomic_load_n(&slot->progress, __ATOMIC_ACQUIRE);
            if (state.observedProgress == 0) {
                continue;
            }
            if (state.firstSequence == 0 ||
                state.observedProgress <= kAprNativeBatchTokenBase) {
                AMPR_CRITICAL_LOGF("apr.reactor.native.batch.snapshot.token.invalid lane=%u buffer=%u generation=%u progress=0x%llx firstSequence=%llu",
                                   laneIndex,
                                   bufferIndex,
                                   state.generation,
                                   (unsigned long long)state.observedProgress,
                                   (unsigned long long)state.firstSequence);
                std::abort();
            }
            const uint64_t completedGroupCount =
                state.observedProgress - kAprNativeBatchTokenBase;
            if (completedGroupCount > state.nextGroup) {
                AMPR_CRITICAL_LOGF("apr.reactor.native.batch.snapshot.ahead lane=%u buffer=%u generation=%u progress=0x%llx completedGroups=%llu releasedGroups=%u",
                                   laneIndex,
                                   bufferIndex,
                                   state.generation,
                                   (unsigned long long)state.observedProgress,
                                   (unsigned long long)completedGroupCount,
                                   state.nextGroup);
                std::abort();
            }
            const uint64_t completedSequence =
                state.firstSequence + completedGroupCount - 1u;
            if (native_batch_sequence_reached(completedSequence,
                                              lane.completedSequence)) {
                lane.completedSequence = completedSequence;
            }
        }

    }

    bool progress_native_batches() {
        bool progressed = false;
        for (uint32_t laneIndex = 0; laneIndex < kPriorityCount; ++laneIndex) {
            NativeBatchLane& lane = nativeBatchLanes[laneIndex];
            if (lane.activeBuffer < 0) {
                continue;
            }
            const uint32_t bufferIndex =
                static_cast<uint32_t>(lane.activeBuffer);
            NativeBatchState& state = lane.buffers[bufferIndex];
            AprNativeBatchSlot* const slot =
                apr_native_batch_slot(laneIndex, bufferIndex);
            if (!slot || state.phase != NativeBatchPhase::Active) {
                AMPR_CRITICAL_LOGF("apr.reactor.native.batch.active.invalid lane=%u buffer=%u slot=%p phase=%u",
                                   laneIndex,
                                   bufferIndex,
                                   slot,
                                   static_cast<unsigned>(state.phase));
                std::abort();
            }
            if (state.nextGroup == 0 ||
                state.nextGroup > kAprNativeBatchGroupCount ||
                state.openGroupPackets != 0 ||
                state.packetCount == 0 ||
                state.packetCount > kAprNativeBatchPacketCount) {
                AMPR_CRITICAL_LOGF("apr.reactor.native.batch.count.invalid lane=%u buffer=%u generation=%u groups=%u openPackets=%u packets=%u",
                                   laneIndex,
                                   bufferIndex,
                                   state.generation,
                                   state.nextGroup,
                                   state.openGroupPackets,
                                   state.packetCount);
                std::abort();
            }

            // A partially populated backing buffer is intentionally parked on
            // the next false group gate. Only a buffer whose every group was
            // released can reach its physical end and become rollover-ready.
            if (state.nextGroup != kAprNativeBatchGroupCount) {
                continue;
            }

            const uint64_t expectedProgress =
                apr_native_batch_token(kAprNativeBatchGroupCount - 1u);
            const uint64_t observedProgress = state.observedProgress;
            if (native_batch_token_reached(observedProgress, expectedProgress)) {
                // The final checkpoint is the last command in the fixed native
                // buffer. Once it is visible, wait only retires the submit id;
                // it cannot block behind an unpublished gate. The SDK result
                // buffer is consumed after that wait, not used as a completion
                // predicate.
                int waitRcRaw = 0;
                const int waitDispatchRc =
                    apr_native_wait_dispatch(state.submitId, &waitRcRaw);
                const int waitRc = waitDispatchRc != 0
                    ? waitDispatchRc
                    : apr_libkernel_rc_to_sce(waitRcRaw);
                if (waitRc != 0) {
                    AMPR_CRITICAL_LOGF("apr.reactor.native.batch.wait.fail lane=%u buffer=%u generation=%u submitId=0x%x rc=0x%x raw=0x%x action=abort",
                                       laneIndex,
                                       bufferIndex,
                                       state.generation,
                                       state.submitId,
                                       waitRc,
                                       waitRcRaw);
                    std::abort();
                }
                const int result = native_batch_result(*slot);
                if (result != 0) {
                    AMPR_CRITICAL_LOGF("apr.reactor.native.batch.result.fail lane=%u buffer=%u generation=%u submitId=0x%x result=0x%x errorOffset=0x%x progress=0x%llx action=abort",
                                       laneIndex,
                                       bufferIndex,
                                       state.generation,
                                       state.submitId,
                                       result,
                                       slot->result.errorOffset,
                                       (unsigned long long)observedProgress);
                    std::abort();
                }
                state.submitId = 0;
                state.submitTimeNs = 0;
                state.lastReleaseTimeNs = 0;
                state.lastWatchdogTimeNs = 0;
                state.phase = NativeBatchPhase::Free;
                lane.activeBuffer = -1;
                progressed = true;
                AMPR_TLOGF("apr.reactor.native.batch.complete lane=%u buffer=%u generation=%u groups=%u packets=%u progress=0x%llx completedSequence=%llu",
                           laneIndex,
                           bufferIndex,
                           state.generation,
                           state.nextGroup,
                           state.packetCount,
                           (unsigned long long)observedProgress,
                           (unsigned long long)lane.completedSequence);

                const uint32_t fillingIndex = bufferIndex ^ 1u;
                NativeBatchState& filling = lane.buffers[fillingIndex];
                if (filling.phase == NativeBatchPhase::Filling) {
                    if (filling.nextGroup == 0 ||
                        filling.openGroupPackets != 0 ||
                        !submit_native_batch_buffer(laneIndex, fillingIndex)) {
                        AMPR_CRITICAL_LOGF("apr.reactor.native.batch.rollover-submit.fail lane=%u buffer=%u generation=%u groups=%u packets=%u action=abort",
                                           laneIndex,
                                           fillingIndex,
                                           filling.generation,
                                           filling.nextGroup,
                                           filling.packetCount);
                        std::abort();
                    }
                }
                continue;
            }

            if (lane.deferredReleaseSequence != 0 &&
                lane.deferredReleaseSequence == state.lastSequence) {
                continue;
            }
            const uint64_t now = time_counter_now();
            const uint64_t ageNs = state.lastReleaseTimeNs != 0 &&
                                           now >= state.lastReleaseTimeNs
                ? now - state.lastReleaseTimeNs
                : 0ull;
            if (ageNs < kNativeCompletionTimeoutNs) {
                continue;
            }
            const int result = native_batch_result(*slot);
            if (result != kAprNativeBatchResultPending) {
                AMPR_CRITICAL_LOGF("apr.reactor.native.batch.fatal-without-checkpoint lane=%u buffer=%u generation=%u submitId=0x%x ageMs=%llu result=0x%x errorOffset=0x%x expected=0x%llx observed=0x%llx release=0x%llx action=abort",
                                   laneIndex,
                                   bufferIndex,
                                   state.generation,
                                   state.submitId,
                                   (unsigned long long)(ageNs / 1000000ull),
                                   result,
                                   slot->result.errorOffset,
                                   (unsigned long long)expectedProgress,
                                   (unsigned long long)observedProgress,
                                   (unsigned long long)__atomic_load_n(
                                       &slot->release,
                                       __ATOMIC_RELAXED));
                std::abort();
            }
            if (state.lastWatchdogTimeNs == 0 ||
                now - state.lastWatchdogTimeNs >= kNativeCompletionTimeoutNs) {
                state.lastWatchdogTimeNs = now;
                AMPR_CRITICAL_LOGF("apr.reactor.native.batch.rollover.pending lane=%u buffer=%u generation=%u submitId=0x%x ageMs=%llu expected=0x%llx observed=0x%llx release=0x%llx status=running-or-blocked",
                                   laneIndex,
                                   bufferIndex,
                                   state.generation,
                                   state.submitId,
                                   (unsigned long long)(ageNs / 1000000ull),
                                   (unsigned long long)expectedProgress,
                                   (unsigned long long)observedProgress,
                                   (unsigned long long)__atomic_load_n(
                                       &slot->release,
                                       __ATOMIC_RELAXED));
            }
        }
        return progressed;
    }

    bool native_micro_completion_observed(JobState& job) {
        if (!job.nativeSubmitted.load(std::memory_order_acquire)) {
            return true;
        }

        if (job.nativeMicroEngine == NativeMicroEngine::AprBatch) {
            if (job.prioIndex >= kPriorityCount ||
                job.nativeBatchSequence == 0) {
                AMPR_CRITICAL_LOGF("apr.reactor.native.batch.job.invalid job=0x%llx lane=%u targetSequence=%llu",
                                   (unsigned long long)job.id,
                                   job.prioIndex,
                                   (unsigned long long)job.nativeBatchSequence);
                std::abort();
            }
            NativeBatchLane& lane = nativeBatchLanes[job.prioIndex];
            if (!native_batch_sequence_reached(lane.completedSequence,
                                               job.nativeBatchSequence)) {
                if (lane.activeBuffer >= 0) {
                    const uint32_t bufferIndex =
                        static_cast<uint32_t>(lane.activeBuffer);
                    NativeBatchState& state = lane.buffers[bufferIndex];
                    const bool targetIsActive =
                        state.firstSequence != 0 &&
                        native_batch_sequence_reached(job.nativeBatchSequence,
                                                      state.firstSequence) &&
                        native_batch_sequence_reached(state.lastSequence,
                                                      job.nativeBatchSequence);
                    if (!targetIsActive) {
                        return false;
                    }
                    if (job.nativeBatchReleasePending &&
                        lane.deferredReleaseSequence ==
                            job.nativeBatchSequence) {
                        return false;
                    }
                    const uint64_t now = time_counter_now();
                    const uint64_t checkBase = job.nativeSubmitTimeNs != 0 &&
                                                 job.nativeSubmitTimeNs >= state.submitTimeNs
                        ? job.nativeSubmitTimeNs
                        : state.submitTimeNs;
                    const uint64_t ageNs = checkBase != 0 && now >= checkBase
                        ? now - checkBase
                        : 0ull;
                    if (ageNs >= kNativeCompletionTimeoutNs) {
                        AprNativeBatchSlot* const slot = apr_native_batch_slot(
                            job.prioIndex, bufferIndex);
                        if (!slot) {
                            std::abort();
                        }
                        const int result = native_batch_result(*slot);
                        if (result != kAprNativeBatchResultPending) {
                            AMPR_CRITICAL_LOGF("apr.reactor.native.batch.checkpoint.fatal job=0x%llx lane=%u buffer=%u generation=%u targetSequence=%llu completedSequence=%llu progress=0x%llx result=0x%x errorOffset=0x%x ageMs=%llu action=abort",
                                               (unsigned long long)job.id,
                                               job.prioIndex,
                                               bufferIndex,
                                               state.generation,
                                               (unsigned long long)job.nativeBatchSequence,
                                               (unsigned long long)lane.completedSequence,
                                               (unsigned long long)state.observedProgress,
                                               result,
                                               slot->result.errorOffset,
                                               (unsigned long long)(ageNs /
                                                                    1000000ull));
                            std::abort();
                        }
                        job.nativeSubmitTimeNs = now;
                        AMPR_CRITICAL_LOGF("apr.reactor.native.batch.checkpoint.pending job=0x%llx lane=%u buffer=%u generation=%u targetSequence=%llu completedSequence=%llu progress=0x%llx ageMs=%llu status=running-or-blocked",
                                           (unsigned long long)job.id,
                                           job.prioIndex,
                                           bufferIndex,
                                           state.generation,
                                           (unsigned long long)job.nativeBatchSequence,
                                           (unsigned long long)lane.completedSequence,
                                           (unsigned long long)state.observedProgress,
                                           (unsigned long long)(ageNs /
                                                                1000000ull));
                    }
                }
                return false;
            }
            job.nativeSubmitted.store(false, std::memory_order_release);
            job.nativeBatchSequence = 0;
            job.nativeSubmitTimeNs = 0;
            job.nativeMicroEngine = NativeMicroEngine::None;
            return true;
        }

        const uint64_t completionValue = job.nativeCompletionAddress
            ? *job.nativeCompletionAddress
            : 0ull;
        const uint64_t now = time_counter_now();
        const uint64_t ageNs = job.nativeSubmitTimeNs != 0 &&
                                   now >= job.nativeSubmitTimeNs
            ? now - job.nativeSubmitTimeNs
            : 0ull;
        const bool timedOut = completionValue == 0 &&
                              ageNs >= kNativeCompletionTimeoutNs;
        if (completionValue == 0 && !timedOut) {
            return false;
        }
        std::atomic_thread_fence(std::memory_order_acquire);
        if (timedOut) {
            AMPR_CRITICAL_LOGF("apr.reactor.native.completion.timeout job=0x%llx lane=%u engine=%s ageMs=%llu sourceOffset=0x%x sourceType=%s completion=%p",
                               (unsigned long long)job.id,
                               (unsigned)job.prioIndex,
                               job.nativeMicroEngine == NativeMicroEngine::Amm ? "amm" : "apr",
                               (unsigned long long)(ageNs / 1000000ull),
                               job.nativeSourceOffset,
                               sce::Ampr::ampr_op_name(job.nativeSourceType),
                               (void*)const_cast<uint64_t*>(job.nativeCompletionAddress));
            set_fail(job,
                     "native-completion-timeout",
                     SCE_KERNEL_ERROR_ETIMEDOUT,
                     job.nativeSourceOffset);
        } else if (!job_failed(job) &&
                   (!job.nativeCompletionAddress ||
                    *job.nativeCompletionAddress != kAprNativeMicroCompletionDone)) {
            set_fail(job,
                     "native-completion-write",
                     SCE_KERNEL_ERROR_EIO,
                     job.nativeSourceOffset);
        }
        AMPR_TLOGF("apr.reactor.native.micro.complete job=0x%llx sourceOffset=0x%x sourceType=%s engine=%s completion=%p value=0x%llx failed=%u",
                   (unsigned long long)job.id,
                   job.nativeSourceOffset,
                   sce::Ampr::ampr_op_name(job.nativeSourceType),
                   job.nativeMicroEngine == NativeMicroEngine::Amm ? "amm" : "apr",
                   (void*)const_cast<uint64_t*>(job.nativeCompletionAddress),
                   (unsigned long long)(job.nativeCompletionAddress
                                            ? *job.nativeCompletionAddress
                                            : 0ull),
                   job_failed(job) ? 1u : 0u);
        job.nativeSubmitted.store(false, std::memory_order_release);
        job.nativeSubmitTimeNs = 0;
        job.nativeMicroEngine = NativeMicroEngine::None;
        return true;
    }

    void maybe_release_reactor_job(JobPtr& job) {
        if (!job) {
            return;
        }
        if (job->nativeSubmitted.load(std::memory_order_acquire)) {
            if (!native_micro_completion_observed(*job)) {
                return;
            }
        }
        if (job->pendingReadCount != 0 || job->activeReadCount != 0) {
            return;
        }
        if (!job_failed(*job) && !job_processing_complete(*job)) {
            return;
        }

#if AMPR_EMU_DEBUG_LOG
        const uint64_t releaseNowNs = time_counter_now();
        if (job->completionReadyNs == 0) {
            job->completionReadyNs = releaseNowNs;
        }
#endif
        {
            AmprLockGuard lk(m);
            if (job->prioIndex >= kPriorityCount ||
                activePriorityHeads[job->prioIndex] != job) {
                return;
            }
            erase_active_job_locked(job);
        }
#if AMPR_EMU_DEBUG_LOG
        const uint64_t releasedNs = time_counter_now();
        note_latency_sample(runtimeCompletionToReleaseLatency,
                            releasedNs >= job->completionReadyNs
                                ? releasedNs - job->completionReadyNs
                                : 0);
#endif
        job->nativeCompletionAddress = nullptr;
        job->nativeCommandBuffer = nullptr;
        job->nativeCommandBufferBytes = 0;
        publish_job_result(*job);
        if (job->syntheticWaitPublished) {
            publish_synthetic_wait_completion(*job);
        } else {
            AmprLockGuard lk(m);
            release_unpublished_synthetic_wait_slot_locked(*job);
        }
#if AMPR_EMU_DEBUG_LOG && (AMPR_EMU_DEBUG_LOG_VERBOSE || AMPR_EMU_DEBUG_LOG_TRACE)
        AMPR_TLOGF("apr.reactor.runtime.release job=0x%llx prio=%u lane=%u failed=%u",
                  (unsigned long long)job->id,
                  (unsigned)job->nativePrio,
                  (unsigned)job->prioIndex,
                  job_failed(*job) ? 1u : 0u);
#endif
        release_job_state(job);
        job = nullptr;
    }

    void worker() {
        configure_worker_thread();
#if AMPR_EMU_DEBUG_LOG
        runtimeCounterWindowStartNs = time_counter_now();
#endif
        for (;;) {
#if AMPR_EMU_DEBUG_LOG
            note_reactor_active_loop_gap();
#endif
#if AMPR_EMU_DEBUG_LOG && AMPR_EMU_APR_REACTOR_HEARTBEAT_MS != 0
            maybe_log_reactor_heartbeat();
#endif
            const bool shuttingDown =
                shutdownRequested.load(std::memory_order_acquire);
            const bool waitIfIdle = !shuttingDown &&
                                    !has_active_lanes_locked() &&
                                    activeReads.empty() &&
                                    !has_pending_reads();
            maybe_release_stale_fds(waitIfIdle);
            drain_incoming(waitIfIdle);
            workerObservedWakeEpoch = reactorWakeEpoch.load(std::memory_order_acquire);
            {
                AmprLockGuard lk(m);
                if (stop) {
                    return;
                }
            }

            bool progressed = false;
            if (shuttingDown && !prepare_native_batches_for_shutdown()) {
                AMPR_CRITICAL_LOGF("apr.reactor.shutdown.native-drain.fail action=abort");
                std::abort();
            }
            refresh_native_batch_progress_snapshots();
            progressed |= progress_native_batches();
            if (has_pending_reads()) {
                progressed |= submit_pending_reads();
            }
            progressed |= progress_all_jobs();
            progressed |= submit_pending_reads();

            if (shuttingDown && native_batches_idle()) {
                AmprLockGuard lk(m);
                stop = true;
                return;
            }

            if (!activeReads.empty()) {
                progressed |= wait_aio_once();
                if (has_pending_reads()) {
                    progressed |= submit_pending_reads();
                }
                refresh_native_batch_progress_snapshots();
                progressed |= progress_native_batches();
                progressed |= progress_all_jobs();
                note_reactor_progress(progressed);
                continue;
            }
            if (has_pending_reads()) {
                note_reactor_progress(progressed);
                if (!progressed) {
                    wait_for_reactor_wake(workerObservedWakeEpoch,
                                          AMPR_EMU_APR_PENDING_READ_IDLE_SLEEP_NS);
                }
                continue;
            }
            if (!progressed && has_active_lanes_locked()) {
                note_reactor_progress(false);
                wait_for_reactor_wake(workerObservedWakeEpoch,
                                      active_lane_idle_sleep_ns());
#if AMPR_EMU_DEBUG_LOG
                note_worker_wakeup();
#endif
            } else {
                note_reactor_progress(progressed);
            }
        }
    }

    AmprMutex m;
    AmprConditionVariable reactorCv;
    AmprConditionVariable syntheticWaitCvs[kPriorityCount];
    bool stop{false};
    std::atomic<bool> shutdownRequested{false};
    AmprOnceFlag startOnce;
    std::atomic<bool> started{false};
    std::atomic<uint64_t> reactorWakeEpoch{0};
    uint64_t workerObservedWakeEpoch{};
    uint64_t nextFdCacheMaintenanceNs{};
    uint32_t fdCacheMaintenanceBusyLoops{};
    std::atomic<uint32_t> aioInitState{kAioInitUninitialized};
    std::atomic<int> aioInitLastRc{0};
    std::atomic<uint64_t> aioInitAttemptCount{0};
    std::atomic<uint64_t> aioInitSuccessCount{0};
    std::atomic<uint64_t> aioInitBusyCount{0};
    std::atomic<uint64_t> aioInitFailCount{0};
    std::atomic<uint64_t> aioSubmitEagainCount{0};
    ScePthread workerThread{};

    JobPtr activeJobHead{};
    JobPtr activeJobTail{};
    JobPtr activePriorityHeads[kPriorityCount]{};
    JobPtr activePriorityTails[kPriorityCount]{};
    uint8_t jobProgressLaneCursor{};
    GatherScatterState gatherScatterStates[kPriorityCount]{};
    std::atomic<size_t> activeJobCountAtomic{0};
    std::atomic<uint32_t> jobStatePoolLock{0};
    JobStateSlot jobStateSlots[kJobStatePoolCapacity]{};
    uint32_t jobStateFreeHead{UINT32_MAX};
    ReadChainSlot readChainSlots[kReadChainPoolCapacity]{};
    uint32_t readChainFreeHead{UINT32_MAX};
    PendingReadNode pendingReadNodes[kPendingReadQueueCapacity]{};
    AmprIndexFreeList pendingReadFree{};
    PendingReadQueue pendingReadLanes[kPriorityCount]{};
    std::atomic<size_t> pendingReadTotalAtomic{0};
    std::atomic<uint64_t> invariantJobPoolFull{0};
    std::atomic<uint64_t> invariantReadChainPoolFull{0};
    std::atomic<uint64_t> invariantPendingReadPoolFull{0};
    ActiveReadList activeReads;
    ActiveFileCounts activeFileCounts;
    uint8_t aioAdmissionCursor{};
    HotPollEntry hotPollQueue[kHotPollQueueCapacity]{};
    uint32_t hotPollQueueHead{};
    uint32_t hotPollQueueTail{};
    uint32_t hotPollQueueCount{};
    ActiveRead* activePollDeadlineHeap[kMaxActiveReads]{};
    uint32_t activePollDeadlineHeapSize{};
    std::atomic<uint32_t> nativeExecutionPoolLock{0};
    bool nativeExecutionPoolInitAttempted{false};
    bool nativeExecutionPoolReady{false};
    uint32_t nativeBatchPaddingHeaders[kAprNativeBatchPaddingHeaderCount]{};
    bool nativeMicroTemplateReady[kJobStatePoolCapacity]{};
    NativeBatchLane nativeBatchLanes[kPriorityCount]{};
    SyntheticWaitSlot syntheticWaitSlots[kSyntheticWaitSlotCapacity]{};
    uint32_t syntheticWaitAllocCursor{};
#if AMPR_EMU_DEBUG_LOG
    uint64_t runtimePeakPendingReads{0};
    uint64_t runtimePeakActiveReads{0};
    uint64_t runtimeEmfileEvents{0};
    uint64_t runtimeEfaultRetryEvents{0};
    uint64_t runtimeEfaultRetryLimitEvents{0};
    uint64_t runtimeMaxAioAgeMs{0};
    uint64_t runtimeAioCompletionCount{0};
    uint64_t runtimeAioCompletionTotalUs{0};
    uint64_t runtimeAioCompletionMaxUs{0};
    uint64_t runtimeAioPollCalls{0};
    uint64_t runtimeAioPollBackoffSkips{0};
    uint64_t runtimeAioPollBudgetYields{0};
    uint64_t runtimeAioPollWorkNs{0};
    uint64_t runtimeAioPollSleepNs{0};
    uint64_t runtimeDeadlineHeapPicks{0};
    uint64_t runtimeDeadlineHeapFutureStops{0};
    uint64_t runtimeActiveReadDuePolls{0};
    uint64_t runtimeActiveReadNotDueSkips{0};
    uint64_t runtimeWorkerWakeups{0};
    uint64_t runtimeIdlePollPasses{0};
    uint64_t runtimeAioAcceptedRequestCount{0};
    uint64_t runtimeAioAcceptedBytes{0};
    uint64_t runtimeAioAcceptedLe64K{0};
    uint64_t runtimeAioAcceptedLe256K{0};
    uint64_t runtimeAioAcceptedPartialQuantum{0};
    uint64_t runtimeAioAcceptedFullQuantum{0};
    uint64_t runtimeAioAcceptedOverQuantum{0};
    uint64_t runtimeAioAcceptedRequestCountByPriority[kPriorityCount]{};
    uint64_t runtimeAioAcceptedBytesByPriority[kPriorityCount]{};
    uint64_t runtimeCounterWindowStartNs{0};
    uint64_t runtimeReactorLoopLastNs{0};
    bool runtimeReactorLoopGapArmed{false};
    LatencyHistogram runtimeJobQueueToFirstReadLatency{};
    LatencyHistogram runtimeFirstReadQueueToFirstAioLatency{};
    LatencyHistogram runtimeJobQueueToFirstAioLatency{};
    LatencyHistogram runtimePendingReadQueueToAioLatency{};
    LatencyHistogram runtimeJobQueueToFirstReadLatencyByPriority[kPriorityCount]{};
    LatencyHistogram runtimeFirstReadQueueToFirstAioLatencyByPriority[kPriorityCount]{};
    LatencyHistogram runtimeJobQueueToFirstAioLatencyByPriority[kPriorityCount]{};
    LatencyHistogram runtimePendingReadQueueToAioLatencyByPriority[kPriorityCount]{};
    LatencyHistogram runtimeReactorActiveLoopGapLatency{};
    LatencyHistogram runtimeReactorWakeOvershootLatency{};
    LatencyHistogram runtimeNativeTriggerToSubmitLatency{};
    LatencyHistogram runtimeAioSubmitToCompletionLatency{};
    LatencyHistogram runtimeCompletionToReleaseLatency{};
#endif
#if AMPR_EMU_DEBUG_LOG && AMPR_EMU_APR_REACTOR_STALL_WARN_ITERATIONS != 0
    uint64_t stallLoopCount{0};
    uint64_t stallStartTimeNs{0};
#endif
#if AMPR_EMU_DEBUG_LOG && AMPR_EMU_APR_REACTOR_HEARTBEAT_MS != 0
    uint64_t lastReactorHeartbeatNs{0};
#endif
    uint64_t slowAioCooldownUntilNs{0};
    mutable uint64_t fdPressureUntilNs{0};
    mutable uint8_t fdPressureLevel{0};
    mutable bool fdCachePressureCapApplied{false};
    mutable uint64_t fdCacheOpenPressureSeen{0};
#if AMPR_EMU_DEBUG_LOG && AMPR_EMU_APR_REACTOR_BACKLOG_WARN_THRESHOLD != 0
    size_t lastBacklogLogPending{0};
    uint64_t lastBacklogLogTimeNs{0};
#endif
#if AMPR_EMU_DEBUG_LOG && AMPR_EMU_APR_REACTOR_BACKLOG_WARN_THRESHOLD != 0 && \
    AMPR_EMU_APR_REACTOR_BACKLOG_FILE_SAMPLES != 0
    BacklogFileSample backlogFileSamples[kBacklogFileSampleCapacity]{};
#endif
};

AprAioReactor::AprAioReactor() {
    for (uint32_t slot = 0; slot < kJobStatePoolCapacity; ++slot) {
        jobStateSlots[slot].nextFree =
            slot + 1u < kJobStatePoolCapacity ? slot + 1u : UINT32_MAX;
    }
    jobStateFreeHead = kJobStatePoolCapacity != 0 ? 0u : UINT32_MAX;
    for (uint32_t slot = 0; slot < kReadChainPoolCapacity; ++slot) {
        readChainSlots[slot].nextFree =
            slot + 1u < kReadChainPoolCapacity ? slot + 1u : UINT32_MAX;
    }
    readChainFreeHead = kReadChainPoolCapacity != 0 ? 0u : UINT32_MAX;
    pending_read_pool_init();
    for (PendingReadQueue& lane : pendingReadLanes) {
        lane.set_owner(this);
    }
}

static std::atomic<AprAioReactor*> g_apr_aio_reactor{nullptr};
static std::atomic<uint32_t> g_apr_aio_reactor_init{0};
alignas(AprAioReactor) static unsigned char g_apr_aio_reactor_storage[sizeof(AprAioReactor)];

static AprAioReactor& apr_aio_reactor() {
    AprAioReactor* p = g_apr_aio_reactor.load(std::memory_order_acquire);
    if (p) {
        return *p;
    }
    uint32_t expected = 0;
    if (g_apr_aio_reactor_init.compare_exchange_strong(expected,
                                                       1u,
                                                       std::memory_order_acq_rel,
                                                       std::memory_order_acquire)) {
        p = new (g_apr_aio_reactor_storage) AprAioReactor();
        g_apr_aio_reactor.store(p, std::memory_order_release);
        g_apr_aio_reactor_init.store(2u, std::memory_order_release);
        return *p;
    }
    uint32_t spins = 0;
    while (g_apr_aio_reactor_init.load(std::memory_order_acquire) != 2u) {
        ampr_spin_pause_or_yield(spins);
    }
    return *g_apr_aio_reactor.load(std::memory_order_acquire);
}

} // namespace

int apr_reactor_shutdown() {
    AprAioReactor* const reactor =
        g_apr_aio_reactor.load(std::memory_order_acquire);
    return reactor ? reactor->shutdown() : 0;
}

int apr_reactor_wait_synthetic_submit_id(SceAprSubmitId id, bool* outHandled) {
    return apr_aio_reactor().wait_synthetic_submit_id(id, outHandled);
}

int apr_reactor_submit(const Job& j,
                       SceAprSubmitId* outSubmitId,
                       uint32_t* outErrorOffset) {
    return apr_aio_reactor().submit(j,
                                    outSubmitId,
                                    outErrorOffset);
}
