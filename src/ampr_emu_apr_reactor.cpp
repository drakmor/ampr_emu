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
#include <cstring>
#include <limits>

namespace {
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
static constexpr uint32_t kAprNativeBatchRequestedPacketCount = 1024u;
static constexpr uint32_t kAprNativeBatchPacketsPerGroup = 8u;
static constexpr uint32_t kAprNativeBatchPaddingHeaderCount = 5u;
static constexpr uint32_t kAprNativeBatchGateBytes = 16u;
static constexpr uint32_t kAprNativeBatchPayloadSlotBytes = 24u;
static constexpr uint32_t kAprNativeBatchPayloadRegionBytes =
    kAprNativeBatchPayloadSlotBytes * kAprNativeBatchPacketsPerGroup;
static constexpr uint32_t kAprNativeBatchCheckpointBytes = 16u;
static constexpr uint32_t kAprNativeBatchGroupBytes =
    kAprNativeBatchGateBytes + kAprNativeBatchPayloadRegionBytes +
    kAprNativeBatchCheckpointBytes;
// Reserve the final native-buffer group-sized tail for device-visible release
// and progress words. The old 128-group layout placed those sync words at
// +0x70c0, outside the advertised 0x7000 native command-buffer range.
static constexpr uint32_t kAprNativeBatchSubmitBytes =
    kAprNativeBatchGroupBytes *
    (kAprNativeBatchRequestedPacketCount / kAprNativeBatchPacketsPerGroup);
static constexpr uint32_t kAprNativeBatchGroupCount =
    kAprNativeBatchRequestedPacketCount / kAprNativeBatchPacketsPerGroup - 1u;
static constexpr uint32_t kAprNativeBatchPacketCount =
    kAprNativeBatchGroupCount * kAprNativeBatchPacketsPerGroup;
static constexpr uint32_t kAprNativeBatchExecutableBytes =
    kAprNativeBatchGroupBytes * kAprNativeBatchGroupCount;
static constexpr uint32_t kAprNativeBatchReleaseOffset =
    kAprNativeBatchExecutableBytes;
static constexpr uint32_t kAprNativeBatchProgressOffset =
    kAprNativeBatchReleaseOffset + sizeof(uint64_t);
static constexpr uint32_t kAprNativeBatchCommandCountPerGroup =
    2u + 2u * kAprNativeBatchPacketsPerGroup;
static constexpr uint32_t kAprNativeBatchCommandCount =
    kAprNativeBatchCommandCountPerGroup * kAprNativeBatchGroupCount;
static constexpr uint64_t kAprNativeBatchTokenBase = 0x4150524200000000ull;
static constexpr int kAprNativeBatchResultPending = INT32_MIN;
struct alignas(kAprNativeMicroSlotAlignment) AprNativeBatchSlot {
    // The complete submitted/native-visible range. Only the first
    // kAprNativeBatchExecutableBytes are parsed as commands; the remaining tail
    // contains release/progress synchronization words and reserved padding.
    alignas(8) uint8_t commands[kAprNativeBatchSubmitBytes]{};
    uint8_t defaultPayload[kAprNativeBatchPayloadRegionBytes]{};
    SceAprResultBuffer result{};
};

static volatile uint64_t* apr_native_batch_release_ptr(AprNativeBatchSlot& slot) {
    return reinterpret_cast<volatile uint64_t*>(
        slot.commands + kAprNativeBatchReleaseOffset);
}

static volatile uint64_t* apr_native_batch_progress_ptr(AprNativeBatchSlot& slot) {
    return reinterpret_cast<volatile uint64_t*>(
        slot.commands + kAprNativeBatchProgressOffset);
}

static const volatile uint64_t* apr_native_batch_release_ptr(const AprNativeBatchSlot& slot) {
    return reinterpret_cast<const volatile uint64_t*>(
        slot.commands + kAprNativeBatchReleaseOffset);
}

static const volatile uint64_t* apr_native_batch_progress_ptr(const AprNativeBatchSlot& slot) {
    return reinterpret_cast<const volatile uint64_t*>(
        slot.commands + kAprNativeBatchProgressOffset);
}
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
static_assert(kAprNativeBatchRequestedPacketCount % kAprNativeBatchPacketsPerGroup == 0,
              "native APR batch packet count must contain complete groups");
static_assert(kAprNativeBatchSubmitBytes == 0x7000u,
              "native APR batch advertised range changed");
static_assert(kAprNativeBatchExecutableBytes == 0x6f20u,
              "native APR batch executable range changed");
static_assert(kAprNativeBatchReleaseOffset + sizeof(uint64_t) <=
                  kAprNativeBatchSubmitBytes &&
              kAprNativeBatchProgressOffset + sizeof(uint64_t) <=
                  kAprNativeBatchSubmitBytes,
              "native APR batch sync words must stay inside advertised range");
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
    // Chain-owned descriptors may hold a logical continuation. Active
    // descriptors are capped to one A53-sized quantum and own one SDK AIO id.
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

static bool apr_prepare_aio_read_desc([[maybe_unused]] uint64_t jobId,
                                      uint32_t fileId,
                                      void* buffer,
                                      uint64_t length,
                                      uint64_t offset,
                                      uint32_t errorOff,
                                      AprAioReadDesc* out,
                                      int* outRc) {
    *outRc = 0;
    if (!buffer) {
        *outRc = SCE_AMPR_ERROR_APR_MEMORYFAULTWRITEBUFFERADDRESS;
        AMPR_CRITICAL_LOGF("apr.reactor.prepare.fail job=0x%llx reason=output-address fileId=%u buf=%p len=0x%llx off=0x%llx rc=0x%x",
                  (unsigned long long)jobId, fileId, buffer,
                  (unsigned long long)length, (unsigned long long)offset,
                  *outRc);
        return false;
    }
    if (length == 0) {
        *outRc = SCE_AMPR_ERROR_APR_INVALIDFILEOFFSET;
        AMPR_CRITICAL_LOGF("apr.reactor.prepare.fail job=0x%llx reason=bad-args fileId=%u buf=%p len=0x%llx off=0x%llx",
                  (unsigned long long)jobId, fileId, buffer,
                  (unsigned long long)length, (unsigned long long)offset);
        return false;
    }
    if (offset > kAprAioRequestOffsetMax) {
        *outRc = SCE_AMPR_ERROR_APR_INVALIDFILEOFFSET;
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
    FileEntryView entry{};
    if (ampr_index_get_entry_view(fileId, &entry) != 0) {
        *outRc = apr_file_id_lookup_error(fileId);
        AMPR_CRITICAL_LOGF("apr.reactor.prepare.fail job=0x%llx reason=file-id fileId=%u len=0x%llx off=0x%llx rc=0x%x",
                           (unsigned long long)jobId,
                           fileId,
                           (unsigned long long)length,
                           (unsigned long long)offset,
                           *outRc);
        return false;
    }
    const uint64_t fileSize = static_cast<uint64_t>(entry.size);
    if (offset > fileSize || length > fileSize - offset) {
        *outRc = SCE_AMPR_ERROR_APR_INVALIDFILEOFFSET;
        AMPR_CRITICAL_LOGF("apr.reactor.prepare.fail job=0x%llx reason=file-range fileId=%u len=0x%llx off=0x%llx fileSize=0x%llx rc=0x%x",
                           (unsigned long long)jobId,
                           fileId,
                           (unsigned long long)length,
                           (unsigned long long)offset,
                           (unsigned long long)fileSize,
                           *outRc);
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
                                      bool allowNewFd,
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
        if (!allowNewFd) {
            if (outRc) *outRc = SCE_KERNEL_ERROR_EAGAIN;
            AMPR_TLOGF("apr.reactor.acquire.direct.defer job=0x%llx fileId=%u reason=new-fd-blocked",
                      (unsigned long long)jobId,
                      rd.fileId);
            return false;
        }
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
            AMPR_LOGF("apr.reactor.acquire.direct.defer-emfile job=0x%llx fileId=%u path=%s mode=%s observedOpen=%zu fdBudget=%zu cacheCap=%zu directCap=%zu closedIdle=%zu cacheBefore=%zu/%zu directBefore=%zu pinned=%zu pins=%zu evictable=%zu cacheAfter=%zu/%zu directAfter=%zu pinnedAfter=%zu pinsAfter=%zu evictableAfter=%zu",
                      (unsigned long long)jobId,
                      rd.fileId,
                      ampr_log_path_arg(directEntry.path),
                      directMode,
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
                      ampr_index_fd_direct_open_count(),
                      afterStats.pinnedOpen,
                      afterStats.pins,
                      afterStats.evictable);
        }
        if (fd < 0) {
            if (outRc) *outRc = ampr_sce_errno_from_posix(openErrno);
            if (openErrno != EMFILE) {
                AMPR_CRITICAL_LOGF("apr.reactor.acquire.fail status=failed job=0x%llx reason=open-direct fileId=%u path=%s mode=%s errno=%d rc=0x%x",
                          (unsigned long long)jobId,
                          rd.fileId,
                          ampr_log_path_arg(directEntry.path),
                          directMode,
                          openErrno,
                          outRc ? *outRc : 0);
            }
            AMPR_FILE_STATUS_LOGF("apr.file.open status=%s reason=direct job=0x%llx fileId=%u path=%s mode=%s errno=%d rc=0x%x",
                                  openErrno == EMFILE ? "deferred" : "failed",
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
                                                0,
                                                allowNewFd);
    AMPR_TLOGF("apr.reactor.acquire.cached.leave job=0x%llx fileId=%u fd=%d fileSize=0x%llx",
              (unsigned long long)jobId,
              rd.fileId,
              fd,
              (unsigned long long)cachedEntry.size);
    if (fd < 0) {
        if (outRc) *outRc = ampr_sce_errno_from_posix(-fd);
        const bool deferred = fd == -EAGAIN || fd == -EMFILE;
        if (!deferred) {
            AMPR_CRITICAL_LOGF("apr.reactor.acquire.fail status=failed job=0x%llx reason=fd fileId=%u path=%s pathKnown=%u fdErr=%d rc=0x%x",
                      (unsigned long long)jobId,
                      rd.fileId,
                      ampr_log_path_arg(cachedEntry.path),
                      1u,
                      fd,
                      outRc ? *outRc : 0);
        }
        AMPR_FILE_STATUS_LOGF("apr.file.open status=%s reason=fd-cache job=0x%llx fileId=%u fdErr=%d rc=0x%x",
                              deferred ? "deferred" : "failed",
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

    int submit(const Job& j, SceAprSubmitId* outSubmitId) {
        if (outSubmitId) {
            *outSubmitId = 0;
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
        if (!start_worker()) {
            release_job_state(job);
            return SCE_KERNEL_ERROR_ENOMEM;
        }
        [[maybe_unused]] const uint32_t jobSlot = job->poolSlot;
        [[maybe_unused]] const uint8_t laneIndex = job->prioIndex;
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
            if (outSubmitId) {
                job->syntheticWaitPublished = true;
                *outSubmitId = job->syntheticSubmitId;
            }
            reactorWakeEpoch.fetch_add(1u, std::memory_order_release);
        }
        reactorCv.notify_one();
        AMPR_VLOGF("apr.reactor.submit job=0x%llx prio=%u lane=%u commands=%u bytes=0x%x mode=cursor-direct jobSlot=%u",
                  (unsigned long long)j.id,
                  (unsigned)j.nativePrio,
                  (unsigned)laneIndex,
                  j.sourceCommandCount,
                  j.sourceBytes,
                  jobSlot);
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
            if (has_active_lanes_locked() || has_live_synthetic_waits_locked()) {
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
    static constexpr unsigned kConfiguredBaseActiveReads =
        AMPR_EMU_APR_AIO_INFLIGHT > 0 ? AMPR_EMU_APR_AIO_INFLIGHT : 1;
    static constexpr unsigned kConfiguredSmallReadActiveReads =
        AMPR_EMU_APR_AIO_SMALL_READ_INFLIGHT > kConfiguredBaseActiveReads
            ? AMPR_EMU_APR_AIO_SMALL_READ_INFLIGHT
            : kConfiguredBaseActiveReads;
    // Fixed storage is sized for the largest dynamic window. Runtime admission
    // normally uses the base window and may temporarily grow only for small
    // requests; age-based backpressure can shrink it below the base.
    static constexpr unsigned kConfiguredActiveReads =
        kConfiguredSmallReadActiveReads;
    static constexpr unsigned kMaxActiveReads =
        kConfiguredActiveReads < SCE_KERNEL_AIO_ID_NUM_MAX
            ? kConfiguredActiveReads
            : SCE_KERNEL_AIO_ID_NUM_MAX;
    static constexpr unsigned kBaseActiveReads =
        kConfiguredBaseActiveReads < kMaxActiveReads
            ? kConfiguredBaseActiveReads
            : kMaxActiveReads;
    static constexpr unsigned kSmallReadActiveReads =
        kConfiguredSmallReadActiveReads < kMaxActiveReads
            ? kConfiguredSmallReadActiveReads
            : kMaxActiveReads;
    static_assert(AMPR_EMU_APR_AIO_SMALL_READ_MIN_PERCENT <= 100u,
                  "APR small-read boost percentage must be <= 100");
    static_assert(AMPR_EMU_APR_AIO_THROTTLE_SEVERE_AGE_MS >=
                      AMPR_EMU_APR_AIO_THROTTLE_MEDIUM_AGE_MS,
                  "APR severe AIO throttle age must be >= medium age");
    static_assert(AMPR_EMU_APR_AIO_THROTTLE_EMERGENCY_AGE_MS >=
                      AMPR_EMU_APR_AIO_THROTTLE_SEVERE_AGE_MS,
                  "APR emergency AIO throttle age must be >= severe age");
    static_assert(AMPR_EMU_APR_AIO_THROTTLE_RECOVER_NORMAL_MS <=
                      AMPR_EMU_APR_AIO_THROTTLE_RECOVER_MEDIUM_MS,
                  "APR AIO throttle recovery thresholds are inverted");
    static_assert(AMPR_EMU_APR_AIO_THROTTLE_RECOVER_MEDIUM_MS <=
                      AMPR_EMU_APR_AIO_THROTTLE_RECOVER_SEVERE_MS,
                  "APR emergency AIO recovery threshold is below severe recovery");
    static_assert(AMPR_EMU_APR_AIO_THROTTLE_RECOVER_SEVERE_MS <
                      AMPR_EMU_APR_AIO_THROTTLE_SEVERE_AGE_MS,
                  "APR emergency AIO recovery age must stay below severe trigger");
    static_assert(AMPR_EMU_APR_AIO_THROTTLE_RECOVER_MEDIUM_MS <
                      AMPR_EMU_APR_AIO_THROTTLE_MEDIUM_AGE_MS,
                  "APR AIO throttle recovery age must stay below medium trigger");
    static_assert(AMPR_EMU_APR_AIO_SMALL_READ_MAX_OLDEST_MS <=
                      AMPR_EMU_APR_AIO_THROTTLE_MEDIUM_AGE_MS,
                  "APR small-read boost age must not exceed medium throttle trigger");
    static_assert(AMPR_EMU_APR_AIO_THROTTLE_EMERGENCY_INFLIGHT <=
                      AMPR_EMU_APR_AIO_THROTTLE_SEVERE_INFLIGHT,
                  "APR emergency AIO window must not exceed severe window");
    static_assert(AMPR_EMU_APR_AIO_THROTTLE_SEVERE_INFLIGHT <=
                      AMPR_EMU_APR_AIO_THROTTLE_MEDIUM_INFLIGHT,
                  "APR severe AIO window must not exceed medium window");
    static_assert(AMPR_EMU_APR_AIO_THROTTLE_MEDIUM_INFLIGHT <= kBaseActiveReads,
                  "APR medium AIO window must not exceed base window");
    // One chain per active logical read plus one cursor and one speculative
    // read per priority lane. Not-yet-submitted reads remain on source cursors.
    static constexpr uint32_t kReadChainPoolCapacity =
        static_cast<uint32_t>(kMaxActiveReads) +
        static_cast<uint32_t>(kPriorityCount) * 2u + 1u;
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
    // Sequence completion is a reorder bitmap, not a pending-read queue. Keep
    // the historical 576-bit window so one old SDK AIO can coexist with many
    // later reads that finish out of order without creating artificial cursor
    // backpressure after only ~64 logical reads.
    static constexpr uint32_t kReadCompletionInitialBits = 576u;
    static constexpr size_t kReadCompletionRingWords =
        (static_cast<size_t>(kReadCompletionInitialBits) + 63u) / 64u;
    static constexpr uint64_t kReadCompletionRingBits =
        static_cast<uint64_t>(kReadCompletionRingWords * 64u);
    static_assert(kReadCompletionRingBits >= kReadCompletionInitialBits,
                  "APR completion bitmap must cover the configured reorder window");
    static_assert(kReadCompletionRingBits > kMaxActiveReads,
                  "APR completion bitmap must exceed the active AIO window");
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
#endif
    static_assert(AMPR_EMU_APR_READ_CHUNK_QUANTUM >= 1u &&
                  AMPR_EMU_APR_READ_CHUNK_QUANTUM <= 8u,
                  "A53 bridge read request quantum must stay in the 1..8 host range");
    static_assert(AMPR_EMU_APR_READ_CREDIT_GRANULE_BYTES != 0 &&
                  (AMPR_EMU_APR_READ_CREDIT_GRANULE_BYTES &
                   (AMPR_EMU_APR_READ_CREDIT_GRANULE_BYTES - 1u)) == 0,
                  "A53 bridge read credit granule must be a power of two");
    static_assert(AMPR_EMU_APR_READ_PASS_MAX_BYTES >= kSoftwareReadChunkMax,
                  "A53 bridge pass byte budget must fit one maximum AIO chunk");
    static_assert(AMPR_EMU_APR_READ_PASS_MAX_BYTES %
                      AMPR_EMU_APR_READ_CREDIT_GRANULE_BYTES == 0,
                  "A53 bridge pass byte budget must align to the credit granule");
    static_assert(AMPR_EMU_APR_PER_READ_ACTIVE_CHUNKS >= 1u,
                  "A53 bridge per-read active request window must be non-zero");
    static_assert(AMPR_EMU_APR_PER_READ_ACTIVE_BYTES >= kSoftwareReadChunkMax,
                  "A53 bridge per-read byte window must fit one maximum AIO chunk");
    static_assert(AMPR_EMU_APR_PER_READ_ACTIVE_BYTES %
                      AMPR_EMU_APR_READ_CREDIT_GRANULE_BYTES == 0,
                  "A53 bridge per-read byte window must align to the credit granule");
    static_assert(AMPR_EMU_APR_AIO_GATING_SPIN_POLLS <= kAioPollBatchLimit,
                  "APR AIO gating spin polls must fit the poll batch");
    static_assert(AMPR_EMU_APR_AIO_POLL_SMALL_BACKGROUND_BACKOFF_MAX_NS >= AMPR_EMU_APR_AIO_POLL_BACKOFF_MIN_NS,
                  "APR AIO small background poll backoff maximum must cover the minimum");
    static_assert(AMPR_EMU_APR_AIO_POLL_IDLE_SLEEP_NS >= AMPR_EMU_APR_AIO_POLL_BACKOFF_MIN_NS,
                  "APR poll idle sleep must be >= min backoff");
    static_assert(AMPR_EMU_APR_AIO_POLL_BACKGROUND_SLEEP_NS >= AMPR_EMU_APR_AIO_POLL_IDLE_SLEEP_NS,
                  "APR background poll sleep must be >= active poll idle sleep");
    static_assert(AMPR_EMU_APR_AIO_POLL_STAGED_EOP_BACKOFF_MAX_NS >= AMPR_EMU_APR_AIO_POLL_IDLE_SLEEP_NS,
                  "APR staged-EOP cap must cover the active poll idle sleep");
    static_assert(AMPR_EMU_APR_AIO_POLL_DEPENDENT_BACKOFF_MAX_NS >= AMPR_EMU_APR_AIO_POLL_IDLE_SLEEP_NS,
                  "APR dependent cap must cover the active poll idle sleep");
    static_assert(AMPR_EMU_APR_AIO_POLL_SMALL_BACKGROUND_BACKOFF_MAX_NS <= AMPR_EMU_APR_AIO_POLL_BACKOFF_MAX_NS,
                  "APR small-background AIO cap must not exceed background max");

    struct ReadChain {
        JobPtr job{};
        // Owns the only direct fd/cache pin for the complete logical read.
        // Active descriptors borrow it and are independently tracked by AIO id.
        AprAioReadDesc ownerDesc{};
        void* nextBuffer{};
        uint64_t nextOffset{};
        uint64_t remaining{};
        uint64_t seq{};
        uint64_t retryNotBeforeNs{};
        size_t commandIndex{};
        uint32_t activeCount{};
        // 64 KiB-rounded admission credit held by live slices, not literal I/O bytes.
        uint64_t activeBytes{};
        uint32_t poolSlot{UINT32_MAX};
        bool allIssued{false};
#if AMPR_EMU_DEBUG_LOG
        uint64_t nativeTriggerTimeNs{};
        uint64_t sliceReadyTimeNs{};
#endif
    };

    struct ReadIssueBudget {
        uint32_t requestsLeft{};
        // Remaining 64 KiB-rounded admission credit for this lane pass.
        uint64_t bytesLeft{};

        bool can_admit(uint64_t bytes) const {
            return requestsLeft != 0 && bytes != 0 && bytes <= bytesLeft;
        }

        void consume(uint64_t bytes) {
            if (requestsLeft == 0 || bytes == 0 || bytes > bytesLeft) {
                AMPR_KLOGF("ampr.abort reason=apr.reactor.readBudget.consume.invalid file=%s line=%d", __FILE__, __LINE__);
                std::abort();
            }
            --requestsLeft;
            bytesLeft -= bytes;
        }
    };

    struct ReadChainSlot {
        ReadChain value{};
        uint32_t nextFree{UINT32_MAX};
        bool active{false};
    };

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
        // Direct cursor-driven read issue state. A logical read larger than the
        // SDK quantum stays attached to the cursor until all slices are accepted.
        ReadChain* cursorReadChain{};
#if AMPR_EMU_APR_AIO_CROSS_EOP_READAHEAD
        // At most one speculative logical read may be in issue state per lane/job.
        ReadChain* crossEopReadChain{};
#endif
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
        uint32_t crossEopFenceCommandIndexes[
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
        uint64_t firstReadReadyTimeNs{};
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
            return nullptr;
        }
        ReadChainSlot& slot = readChainSlots[slotIndex];
        readChainFreeHead = slot.nextFree;
        slot.nextFree = UINT32_MAX;
        slot.active = true;
        slot.value = {};
        slot.value.poolSlot = slotIndex;
        if (liveReadChainCount == UINT32_MAX) {
            AMPR_CRITICAL_LOGF("apr.reactor.readChain.live.overflow");
            ampr_debug_int3_trap();
        } else {
            ++liveReadChainCount;
#if AMPR_EMU_DEBUG_LOG
            note_log_peak(runtimePeakReadChains, liveReadChainCount);
#endif
        }
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
        if (liveReadChainCount == 0) {
            AMPR_CRITICAL_LOGF("apr.reactor.readChain.live.underflow slot=%u", slotIndex);
            ampr_debug_int3_trap();
        } else {
            --liveReadChainCount;
        }
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
        const bool hasSpeculativeRead =
#if AMPR_EMU_APR_AIO_CROSS_EOP_READAHEAD
            job->crossEopReadChain != nullptr;
#else
            false;
#endif
        if (job->activeReadCount != 0 || job->cursorReadChain != nullptr ||
            hasSpeculativeRead) {
            AMPR_CRITICAL_LOGF("apr.reactor.job.pool.releaseWithReads job=0x%llx active=%u cursor=%u speculative=%u",
                               (unsigned long long)job->id,
                               job->activeReadCount,
                               job->cursorReadChain != nullptr ? 1u : 0u,
                               hasSpeculativeRead ? 1u : 0u);
            ampr_debug_int3_trap();
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
        AMPR_CRITICAL_LOGF("apr.reactor.job.pool.full capacity=%u",
                          (unsigned)kJobStatePoolCapacity);
        ampr_debug_int3_trap();
        return nullptr;
    }

    struct ActiveRead {
        JobPtr job;
        AprAioReadDesc desc;
        ReadChain* chain{};
        SceKernelAioResult result{};
        SceKernelAioRWRequest request{};
        SceKernelAioSubmitId aioId{static_cast<SceKernelAioSubmitId>(-1)};
        int aioPrio{SCE_KERNEL_AIO_PRIORITY_MID};
        uint64_t seq{};
        size_t commandIndex{};
        uint64_t readCreditBytes{};
        uint64_t submitTimeNs{};
#if AMPR_EMU_DEBUG_LOG
        uint64_t nativeTriggerTimeNs{};
        uint64_t sliceReadyTimeNs{};
#endif
        uint64_t nextPollTimeNs{};
        uint32_t pollBackoffNs{};
        int lastPollState{};
        int lastPollRc{};
        uint32_t ammEfaultRetries{};
        uint32_t aioCompletionRetries{};
        uint32_t aioDeleteRetries{};
        uint64_t aioDeleteFirstFailureNs{};
        uint64_t retryNotBeforeNs{};
        uint32_t gatingSpinPollsRemaining{};
        uint32_t listSlot{UINT32_MAX};
        uint32_t listGeneration{};
        uint32_t pollDeadlineHeapIndex{UINT32_MAX};
        uint32_t jobPrevSlot{UINT32_MAX};
        uint32_t jobNextSlot{UINT32_MAX};
        bool hotPollQueued{false};
        bool awaitingResubmit{false};
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
                AMPR_KLOGF("ampr.abort reason=apr.reactor.pollDeadline.insert.full file=%s line=%d", __FILE__, __LINE__);
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
            AMPR_KLOGF("ampr.abort reason=apr.reactor.pollDeadline.update.invalid file=%s line=%d", __FILE__, __LINE__);
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
            AMPR_KLOGF("ampr.abort reason=apr.reactor.pollDeadline.remove.invalid file=%s line=%d", __FILE__, __LINE__);
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
            AMPR_KLOGF("ampr.abort reason=apr.reactor.pollDeadline.remove.replacement file=%s line=%d", __FILE__, __LINE__);
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
            AMPR_KLOGF("ampr.abort reason=apr.reactor.pollDeadline.front.invalid file=%s line=%d", __FILE__, __LINE__);
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
            AMPR_KLOGF("ampr.abort reason=apr.reactor.pollDeadline.front.stale file=%s line=%d", __FILE__, __LINE__);
            std::abort();
        }
        return it;
    }

    static bool active_read_is_submitted(const ActiveRead& active) {
        return !active.awaitingResubmit && active.aioId >= 0;
    }

    void mark_active_read_submitted(ActiveRead& active,
                                    SceKernelAioSubmitId aioId) {
        if (aioId < 0 || active_read_is_submitted(active)) {
            AMPR_KLOGF("ampr.abort reason=apr.reactor.activeRead.submit.invalid file=%s line=%d", __FILE__, __LINE__);
            std::abort();
        }
        if (active.awaitingResubmit) {
            if (deferredActiveReadCount == 0) {
                AMPR_KLOGF("ampr.abort reason=apr.reactor.activeRead.deferred.underflow file=%s line=%d", __FILE__, __LINE__);
                std::abort();
            }
            --deferredActiveReadCount;
        } else if (active.aioId >= 0) {
            AMPR_KLOGF("ampr.abort reason=apr.reactor.activeRead.untracked.invalid file=%s line=%d", __FILE__, __LINE__);
            std::abort();
        }
        if (submittedActiveReadCount >= kMaxActiveReads) {
            AMPR_KLOGF("ampr.abort reason=apr.reactor.activeRead.submitted.overflow file=%s line=%d", __FILE__, __LINE__);
            std::abort();
        }
        ++submittedActiveReadCount;
        active.aioId = aioId;
        active.awaitingResubmit = false;
    }

    void mark_active_read_deferred(ActiveRead& active) {
        if (!active_read_is_submitted(active) || submittedActiveReadCount == 0 ||
            deferredActiveReadCount >= kMaxActiveReads) {
            AMPR_KLOGF("ampr.abort reason=apr.reactor.activeRead.defer.invalid file=%s line=%d", __FILE__, __LINE__);
            std::abort();
        }
        --submittedActiveReadCount;
        ++deferredActiveReadCount;
        active.aioId = static_cast<SceKernelAioSubmitId>(-1);
        active.awaitingResubmit = true;
    }

    ActiveReadIt erase_active_read(ActiveReadIt it) {
        if (it == activeReads.end()) {
            return activeReads.end();
        }
        if (active_read_is_submitted(*it)) {
            if (submittedActiveReadCount == 0) {
                AMPR_KLOGF("ampr.abort reason=apr.reactor.activeRead.submitted.erase.underflow file=%s line=%d", __FILE__, __LINE__);
                std::abort();
            }
            --submittedActiveReadCount;
        } else if (it->awaitingResubmit) {
            if (it->aioId >= 0 || deferredActiveReadCount == 0) {
                AMPR_KLOGF("ampr.abort reason=apr.reactor.activeRead.deferred.erase.invalid file=%s line=%d", __FILE__, __LINE__);
                std::abort();
            }
            --deferredActiveReadCount;
        } else if (it->aioId >= 0) {
            AMPR_KLOGF("ampr.abort reason=apr.reactor.activeRead.erase.state.invalid file=%s line=%d", __FILE__, __LINE__);
            std::abort();
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
        return static_cast<uint32_t>(kBaseActiveReads);
    }

    static constexpr uint32_t aio_small_read_limit() {
        return static_cast<uint32_t>(kSmallReadActiveReads);
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
        static_assert(AMPR_EMU_APR_AIO_SDK_SCHEDULING_WINDOW_SIZE > 0,
                      "APR AIO SDK scheduling window must be positive");
        static_assert(AMPR_EMU_APR_AIO_SDK_SCHEDULING_WINDOW_SIZE <=
                          SCE_KERNEL_AIO_SCHED_WINDOW_MAX,
                      "APR AIO SDK scheduling window exceeds SDK maximum");
        static_assert(AMPR_EMU_APR_AIO_SDK_DELAYED_COUNT_LIMIT > 0,
                      "APR AIO SDK delayed-count limit must be positive");
        static_assert(AMPR_EMU_APR_AIO_SDK_DELAYED_COUNT_LIMIT <=
                          SCE_KERNEL_AIO_DELAYED_COUNT_MAX,
                      "APR AIO SDK delayed-count limit exceeds SDK maximum");

        SceKernelAioParam param{};
        sceKernelAioInitializeParam(&param);
        constexpr int kAioSchedulingWindowSize =
            AMPR_EMU_APR_AIO_SDK_SCHEDULING_WINDOW_SIZE;
        constexpr int kAioDelayedCountLimit =
            AMPR_EMU_APR_AIO_SDK_DELAYED_COUNT_LIMIT;
        const auto setParam = [](SceKernelAioSchedulingParam* sched) {
            return sceKernelAioSetParam(sched,
                                        kAioSchedulingWindowSize,
                                        kAioDelayedCountLimit,
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
            AMPR_LOGF("apr.reactor.aio.init rc=0x0 schedulingWindowSize=%d delayedCountLimit=%d splitLowMidHigh=0 quantum=0x%x",
                      kAioSchedulingWindowSize,
                      kAioDelayedCountLimit,
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
        const bool physicalReads =
            job.activeReadCount != 0 ||
            job.cursorReadChain != nullptr
#if AMPR_EMU_APR_AIO_CROSS_EOP_READAHEAD
            || job.crossEopReadChain != nullptr
#endif
            ;
        // Once a job has failed, no future command may observe read ordering.
        // Keep the JobState alive only for physical SDK AIO/read-chain owners;
        // a sequence gap from a canceled suffix must not leak the failed job.
        if (job_failed(job)) {
            return physicalReads;
        }
        return physicalReads ||
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
    static uint64_t cross_eop_read_fence_for_cursor(const JobState& job) {
        return job.crossEopFenceCount != 0 &&
                       job.crossEopFenceSourceOffsets[
                           job.crossEopFenceHead] == job.sourceOffset
            ? job.crossEopFenceReadSequences[job.crossEopFenceHead]
            : job.latestSubmittedReadSeq;
    }

    static bool push_cross_eop_fence(JobState& job,
                                     uint32_t sourceOffset,
                                     uint32_t commandIndex,
                                     uint64_t readSequence) {
        if (job.crossEopFenceCount >=
            AMPR_EMU_APR_AIO_CROSS_EOP_MAX_FENCES) {
            return false;
        }
        const uint32_t tail =
            (job.crossEopFenceHead + job.crossEopFenceCount) %
            AMPR_EMU_APR_AIO_CROSS_EOP_MAX_FENCES;
        job.crossEopFenceSourceOffsets[tail] = sourceOffset;
        job.crossEopFenceCommandIndexes[tail] = commandIndex;
        job.crossEopFenceReadSequences[tail] = readSequence;
        ++job.crossEopFenceCount;
        return true;
    }

    static bool skip_cross_eop_consumed_prefix(JobState& job) {
        if (!job.crossEopScanActive ||
            job.sourceOffset >= job.crossEopScanOffset) {
            return false;
        }
        // A cursor-owned logical read pins the execution cursor until every
        // slice is submitted. Never orphan that ownership while skipping a
        // speculative prefix.
        if (job.cursorReadChain != nullptr) {
            return false;
        }

        uint32_t targetOffset = job.crossEopScanOffset;
        uint32_t targetCommandIndex = job.crossEopScanCommandIndex;
        if (job.crossEopFenceCount != 0) {
            const uint32_t head = job.crossEopFenceHead;
            const uint32_t fenceOffset = job.crossEopFenceSourceOffsets[head];
            if (job.sourceOffset == fenceOffset) {
                // EOP records retain their native publication side effect and
                // must still be decoded by the execution cursor.
                return false;
            }
            if (job.sourceOffset > fenceOffset) {
                AMPR_KLOGF("ampr.abort reason=apr.reactor.crossEop.fence.cursor.overrun file=%s line=%d", __FILE__, __LINE__);
                std::abort();
            }
            targetOffset = fenceOffset;
            targetCommandIndex = job.crossEopFenceCommandIndexes[head];
        }

        if (targetOffset <= job.sourceOffset ||
            targetOffset > job.crossEopScanOffset ||
            targetCommandIndex <= job.sourceCommandIndex ||
            targetCommandIndex > job.crossEopScanCommandIndex) {
            AMPR_KLOGF("ampr.abort reason=apr.reactor.crossEop.consumedPrefix.invalid file=%s line=%d", __FILE__, __LINE__);
            std::abort();
        }

        AMPR_TLOGF("apr.reactor.crossEop.consumePrefix job=0x%llx sourceOffset=0x%x commandIndex=%u targetOffset=0x%x targetCommandIndex=%u scanOffset=0x%x scanCommandIndex=%u",
                   (unsigned long long)job.id,
                   job.sourceOffset,
                   job.sourceCommandIndex,
                   targetOffset,
                   targetCommandIndex,
                   job.crossEopScanOffset,
                   job.crossEopScanCommandIndex);
        job.sourceOffset = targetOffset;
        job.sourceCommandIndex = targetCommandIndex;
        clear_decoded_op(job);
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
        if (job_failed(job) || job.sourceOffset != job.sourceBytes) {
            return false;
        }
        if (nativeSubmitted &&
            job.nativeMicroEngine != NativeMicroEngine::AprBatch) {
            return false;
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
                    gate.ptra = const_cast<uint64_t*>(apr_native_batch_release_ptr(*slot));
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
                    checkpoint.ptra = const_cast<uint64_t*>(apr_native_batch_progress_ptr(*slot));
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

        if (!initialize_native_batch_pool_storage()) {
            AmprSpinLock lock(&nativeExecutionPoolLock);
            nativeExecutionPoolInitAttempted = false;
            return false;
        }

        // Publish all CPU-side initialization before device access is enabled.
        std::atomic_thread_fence(std::memory_order_seq_cst);

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

        const AprNativeBatchSlot* const firstBatchSlot =
            apr_native_batch_slot(0, 0);
        if (firstBatchSlot) {
            const uintptr_t batchBase =
                reinterpret_cast<uintptr_t>(g_apr_native_batch_pool);
            const uintptr_t releaseAddress =
                reinterpret_cast<uintptr_t>(apr_native_batch_release_ptr(*firstBatchSlot));
            const uintptr_t progressAddress =
                reinterpret_cast<uintptr_t>(apr_native_batch_progress_ptr(*firstBatchSlot));
            AMPR_KLOGF("apr.reactor.native.pool.mapped micro=%p microBytes=0x%llx batch=%p batchBytes=0x%llx firstReleaseOff=0x%llx firstProgressOff=0x%llx prot=0x%x",
                       g_apr_native_micro_pool,
                       (unsigned long long)kAprNativeMicroPoolBytes,
                       g_apr_native_batch_pool,
                       (unsigned long long)kAprNativeBatchPoolBytes,
                       (unsigned long long)(releaseAddress - batchBase),
                       (unsigned long long)(progressAddress - batchBase),
                       kNativeMicroProt);
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
            sce::Ampr::PackedOpLayout completionLayout{};
            const int layoutRc = sce::Ampr::ampr_op_layout_checked(
                completion,
                &completionLayout);
            if (layoutRc != 0 ||
                completionLayout.bytes != kAprNativeMicroCompletionBytes) {
                AMPR_CRITICAL_LOGF("apr.reactor.native.micro.template.fail slot=%u reason=size rc=0x%x bytes=0x%x",
                                   slotIndex,
                                   layoutRc,
                                   completionLayout.bytes);
                set_fail(job,
                         "native-micro-template",
                         layoutRc != 0 ? layoutRc : SCE_KERNEL_ERROR_EINVAL,
                         errorOffset);
                return false;
            }
            SceAmprCommandBuffer view{};
            view.buffer = slot->completionTemplate;
            view.bufsize = kAprNativeMicroCompletionBytes;
            const int writeRc = sce::Ampr::ampr_write_op_with_layout(
                &view,
                0,
                completion,
                completionLayout);
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
                activeReads.empty()) {
                const uint64_t idleWaitNs = idle_wait_timeout_ns();
                if (idleWaitNs != 0) {
                    reactorCv.wait_for(lk, std::chrono::nanoseconds(idleWaitNs));
                } else {
                    reactorCv.wait(lk, [&] {
                        return stop ||
                               shutdownRequested.load(std::memory_order_acquire) ||
                               has_active_lanes_locked() ||
                               !activeReads.empty();
                    });
                }
#if AMPR_EMU_DEBUG_LOG
                note_worker_wakeup();
#endif
            }
        }
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

    void note_job_queue_to_first_read_ready(JobState& job, uint64_t queuedNs) {
        if (job.reactorEnqueueTimeNs == 0 ||
            job.firstReadReadyTimeNs != 0 ||
            queuedNs < job.reactorEnqueueTimeNs) {
            return;
        }
        const size_t priority = apr_clamp_priority_index(job.prioIndex);
        note_latency_sample(runtimeJobQueueToFirstReadLatency,
                            queuedNs - job.reactorEnqueueTimeNs);
        note_latency_sample(runtimeJobQueueToFirstReadLatencyByPriority[priority],
                            queuedNs - job.reactorEnqueueTimeNs);
        job.firstReadReadyTimeNs = queuedNs;
    }

    void note_job_queue_to_first_aio_submit(JobState& job, uint64_t submitNs) {
        if (job.reactorEnqueueTimeNs != 0 && submitNs >= job.reactorEnqueueTimeNs) {
            const size_t priority = apr_clamp_priority_index(job.prioIndex);
            note_latency_sample(runtimeJobQueueToFirstAioLatency,
                                submitNs - job.reactorEnqueueTimeNs);
            note_latency_sample(runtimeJobQueueToFirstAioLatencyByPriority[priority],
                                submitNs - job.reactorEnqueueTimeNs);
            if (job.firstReadReadyTimeNs != 0 &&
                submitNs >= job.firstReadReadyTimeNs) {
                note_latency_sample(runtimeFirstReadReadyToFirstAioLatency,
                                    submitNs - job.firstReadReadyTimeNs);
                note_latency_sample(
                    runtimeFirstReadReadyToFirstAioLatencyByPriority[priority],
                    submitNs - job.firstReadReadyTimeNs);
            }
            job.reactorEnqueueTimeNs = 0;
            job.firstReadReadyTimeNs = 0;
        }
    }

    void note_read_ready_to_aio_submit(uint64_t enqueueNs,
                                                uint64_t submitNs,
                                                size_t priority) {
        if (enqueueNs != 0 && submitNs >= enqueueNs) {
            note_latency_sample(runtimeReadReadyToAioLatency,
                                submitNs - enqueueNs);
            note_latency_sample(
                runtimeReadReadyToAioLatencyByPriority[
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

#endif


    struct AioAdmissionSnapshot {
        size_t activeCount{};
        size_t smallCount{};
        uint64_t oldestSubmittedTimeNs{};
        uint64_t oldestSubmittedAgeMs{};
        uint32_t groupActive[3]{}; // U, H, N
    };

    struct AioAdmissionContext {
        AioAdmissionSnapshot snapshot{};
        uint64_t laneNowNs{};
        uint32_t effectiveLimit{};
        bool initialized{};
        bool laneNowValid{};
        bool current{};
    };

    static void refresh_aio_snapshot_age(AioAdmissionSnapshot& snapshot,
                                         uint64_t now) {
        snapshot.oldestSubmittedAgeMs =
            snapshot.oldestSubmittedTimeNs != 0 &&
                    now >= snapshot.oldestSubmittedTimeNs
                ? (now - snapshot.oldestSubmittedTimeNs) / 1000000ull
                : 0;
    }

    AioAdmissionSnapshot collect_aio_admission_snapshot(uint64_t now) const {
        AioAdmissionSnapshot snapshot{};
        snapshot.activeCount = activeReads.size();
        for (const ActiveRead& active : activeReads) {
            if (aio_desc_is_small_for_boost(active.desc)) {
                ++snapshot.smallCount;
            }
            if (!active.awaitingResubmit && active.aioId >= 0) {
                if (active.submitTimeNs != 0 &&
                    (snapshot.oldestSubmittedTimeNs == 0 ||
                     active.submitTimeNs < snapshot.oldestSubmittedTimeNs)) {
                    snapshot.oldestSubmittedTimeNs = active.submitTimeNs;
                }
            }
            if (active.job && active.job->prioIndex < kPriorityCount) {
                const uint8_t priority = active.job->prioIndex;
                const size_t group = priority == 0 ? 0u : (priority <= 3 ? 1u : 2u);
                ++snapshot.groupActive[group];
            }
        }
        refresh_aio_snapshot_age(snapshot, now);
        return snapshot;
    }

    uint64_t oldest_active_read_age_ms(uint64_t now) const {
        return collect_aio_admission_snapshot(now).oldestSubmittedAgeMs;
    }

    bool slow_aio_cooldown_active(uint64_t now) const {
#if AMPR_EMU_APR_AIO_SLOW_COOLDOWN_MS != 0
        return slowAioCooldownUntilNs != 0 && now < slowAioCooldownUntilNs;
#else
        (void)now;
        return false;
#endif
    }

    bool aio_small_read_boost_recovery_cooldown_active(uint64_t now) const {
#if AMPR_EMU_APR_AIO_SMALL_READ_BOOST_RECOVERY_COOLDOWN_MS != 0
        return aioSmallReadBoostBlockedUntilNs != 0 &&
               now < aioSmallReadBoostBlockedUntilNs;
#else
        (void)now;
        return false;
#endif
    }

    void arm_aio_small_read_boost_recovery_cooldown(uint64_t now) {
#if AMPR_EMU_APR_AIO_SMALL_READ_BOOST_RECOVERY_COOLDOWN_MS != 0
        const uint64_t cooldownNs =
            static_cast<uint64_t>(AMPR_EMU_APR_AIO_SMALL_READ_BOOST_RECOVERY_COOLDOWN_MS) *
            1000000ull;
        const uint64_t until = now + cooldownNs;
        if (until > aioSmallReadBoostBlockedUntilNs) {
            aioSmallReadBoostBlockedUntilNs = until;
        }
#else
        (void)now;
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

    enum class AioAgeThrottleLevel : uint8_t {
        Normal = 0,
        Medium = 1,
        Severe = 2,
        Emergency = 3,
    };

    static bool aio_desc_is_small_for_boost(const AprAioReadDesc& desc) {
#if AMPR_EMU_APR_AIO_SMALL_READ_MAX_BYTES != 0
        return desc.length != 0 &&
               desc.length <= static_cast<uint64_t>(AMPR_EMU_APR_AIO_SMALL_READ_MAX_BYTES);
#else
        (void)desc;
        return false;
#endif
    }

    bool aio_small_read_boost_eligible(
        uint64_t now,
        const AioAdmissionSnapshot& snapshot) const {
        if (aio_small_read_limit() <= aio_active_read_limit() ||
            AMPR_EMU_APR_AIO_SMALL_READ_MAX_BYTES == 0 ||
            snapshot.activeCount < aio_active_read_limit()) {
            return false;
        }
        if (aioAgeThrottleLevel != AioAgeThrottleLevel::Normal ||
            slow_aio_cooldown_active(now) ||
            aio_small_read_boost_recovery_cooldown_active(now)) {
            return false;
        }
        if (snapshot.oldestSubmittedAgeMs >
            static_cast<uint64_t>(AMPR_EMU_APR_AIO_SMALL_READ_MAX_OLDEST_MS)) {
            return false;
        }
        return snapshot.smallCount * 100u >=
               snapshot.activeCount *
                   static_cast<size_t>(AMPR_EMU_APR_AIO_SMALL_READ_MIN_PERCENT);
    }

    void update_aio_age_throttle(uint64_t now,
                                 const AioAdmissionSnapshot& snapshot) {
        const AioAgeThrottleLevel previousLevel = aioAgeThrottleLevel;
        if (snapshot.activeCount == 0) {
            aioAgeThrottleLevel = AioAgeThrottleLevel::Normal;
            if (previousLevel != aioAgeThrottleLevel) {
                arm_aio_small_read_boost_recovery_cooldown(now);
            }
#if AMPR_EMU_DEBUG_LOG
            if (previousLevel != aioAgeThrottleLevel) {
                AMPR_LOGF("apr.reactor.aio.window throttle=%u->%u oldestAioAgeMs=0 base=%u max=%u boostCooldownMs=%u",
                          (unsigned)previousLevel,
                          (unsigned)aioAgeThrottleLevel,
                          (unsigned)aio_active_read_limit(),
                          (unsigned)aio_small_read_limit(),
                          (unsigned)AMPR_EMU_APR_AIO_SMALL_READ_BOOST_RECOVERY_COOLDOWN_MS);
            }
#endif
            return;
        }

        const uint64_t oldestAgeMs = snapshot.oldestSubmittedAgeMs;
        const uint64_t mediumAgeMs =
            static_cast<uint64_t>(AMPR_EMU_APR_AIO_THROTTLE_MEDIUM_AGE_MS);
        const uint64_t severeAgeMs =
            static_cast<uint64_t>(AMPR_EMU_APR_AIO_THROTTLE_SEVERE_AGE_MS);
        const uint64_t emergencyAgeMs =
            static_cast<uint64_t>(AMPR_EMU_APR_AIO_THROTTLE_EMERGENCY_AGE_MS);

        switch (aioAgeThrottleLevel) {
        case AioAgeThrottleLevel::Normal:
            if (emergencyAgeMs != 0 && oldestAgeMs >= emergencyAgeMs) {
                aioAgeThrottleLevel = AioAgeThrottleLevel::Emergency;
            } else if (severeAgeMs != 0 && oldestAgeMs >= severeAgeMs) {
                aioAgeThrottleLevel = AioAgeThrottleLevel::Severe;
            } else if (mediumAgeMs != 0 && oldestAgeMs >= mediumAgeMs) {
                aioAgeThrottleLevel = AioAgeThrottleLevel::Medium;
            }
            break;
        case AioAgeThrottleLevel::Medium:
            if (emergencyAgeMs != 0 && oldestAgeMs >= emergencyAgeMs) {
                aioAgeThrottleLevel = AioAgeThrottleLevel::Emergency;
            } else if (severeAgeMs != 0 && oldestAgeMs >= severeAgeMs) {
                aioAgeThrottleLevel = AioAgeThrottleLevel::Severe;
            } else if (oldestAgeMs <=
                       static_cast<uint64_t>(AMPR_EMU_APR_AIO_THROTTLE_RECOVER_NORMAL_MS)) {
                aioAgeThrottleLevel = AioAgeThrottleLevel::Normal;
            }
            break;
        case AioAgeThrottleLevel::Severe:
            if (emergencyAgeMs != 0 && oldestAgeMs >= emergencyAgeMs) {
                aioAgeThrottleLevel = AioAgeThrottleLevel::Emergency;
            } else if (oldestAgeMs <=
                       static_cast<uint64_t>(AMPR_EMU_APR_AIO_THROTTLE_RECOVER_MEDIUM_MS)) {
                aioAgeThrottleLevel = AioAgeThrottleLevel::Medium;
            }
            break;
        case AioAgeThrottleLevel::Emergency:
            if (oldestAgeMs <=
                static_cast<uint64_t>(AMPR_EMU_APR_AIO_THROTTLE_RECOVER_SEVERE_MS)) {
                aioAgeThrottleLevel = AioAgeThrottleLevel::Severe;
            }
            break;
        }
        if (previousLevel != AioAgeThrottleLevel::Normal &&
            aioAgeThrottleLevel == AioAgeThrottleLevel::Normal) {
            // Throttle already disables boost. Delay only the return to the
            // expanded small-read window after the queue has recovered.
            arm_aio_small_read_boost_recovery_cooldown(now);
        }
#if AMPR_EMU_DEBUG_LOG
        if (previousLevel != aioAgeThrottleLevel) {
            AMPR_LOGF("apr.reactor.aio.window throttle=%u->%u oldestAioAgeMs=%llu base=%u medium=%u severe=%u emergency=%u max=%u boostCooldownMs=%u",
                      (unsigned)previousLevel,
                      (unsigned)aioAgeThrottleLevel,
                      (unsigned long long)oldestAgeMs,
                      (unsigned)aio_active_read_limit(),
                      (unsigned)AMPR_EMU_APR_AIO_THROTTLE_MEDIUM_INFLIGHT,
                      (unsigned)AMPR_EMU_APR_AIO_THROTTLE_SEVERE_INFLIGHT,
                      (unsigned)AMPR_EMU_APR_AIO_THROTTLE_EMERGENCY_INFLIGHT,
                      (unsigned)aio_small_read_limit(),
                      (unsigned)AMPR_EMU_APR_AIO_SMALL_READ_BOOST_RECOVERY_COOLDOWN_MS);
        }
#endif
    }

    uint32_t aio_effective_read_limit(
        uint64_t now,
        const AioAdmissionSnapshot& snapshot) const {
        const uint32_t baseLimit = aio_active_read_limit();
        uint32_t limit = baseLimit;

        if (aioAgeThrottleLevel == AioAgeThrottleLevel::Emergency) {
            const uint32_t emergencyLimit =
                AMPR_EMU_APR_AIO_THROTTLE_EMERGENCY_INFLIGHT != 0
                    ? static_cast<uint32_t>(AMPR_EMU_APR_AIO_THROTTLE_EMERGENCY_INFLIGHT)
                    : 1u;
            return emergencyLimit < baseLimit ? emergencyLimit : baseLimit;
        }

        if (aioAgeThrottleLevel == AioAgeThrottleLevel::Severe) {
            const uint32_t severeLimit =
                AMPR_EMU_APR_AIO_THROTTLE_SEVERE_INFLIGHT != 0
                    ? static_cast<uint32_t>(AMPR_EMU_APR_AIO_THROTTLE_SEVERE_INFLIGHT)
                    : 1u;
            return severeLimit < baseLimit ? severeLimit : baseLimit;
        }

        if (aioAgeThrottleLevel == AioAgeThrottleLevel::Medium ||
            slow_aio_cooldown_active(now)) {
            const uint32_t mediumLimit =
                AMPR_EMU_APR_AIO_THROTTLE_MEDIUM_INFLIGHT != 0
                    ? static_cast<uint32_t>(AMPR_EMU_APR_AIO_THROTTLE_MEDIUM_INFLIGHT)
                    : 1u;
            return mediumLimit < baseLimit ? mediumLimit : baseLimit;
        }

        if (aio_small_read_boost_eligible(now, snapshot)) {
            limit = aio_small_read_limit();
        }
        return limit;
    }

    uint32_t aio_effective_read_limit(uint64_t now) const {
        const AioAdmissionSnapshot snapshot = collect_aio_admission_snapshot(now);
        return aio_effective_read_limit(now, snapshot);
    }

    static void begin_aio_admission_lane(AioAdmissionContext& context) {
        context.laneNowValid = false;
        context.current = false;
    }

    static uint64_t aio_admission_lane_now(AioAdmissionContext& context) {
        if (!context.laneNowValid) {
            context.laneNowNs = time_counter_now();
            context.laneNowValid = true;
        }
        return context.laneNowNs;
    }

    void prepare_aio_admission_context(AioAdmissionContext& context,
                                       uint64_t now) {
        if (context.current) {
            return;
        }
        if (!context.initialized) {
            context.snapshot = collect_aio_admission_snapshot(now);
            context.initialized = true;
        } else {
            refresh_aio_snapshot_age(context.snapshot, now);
        }
        update_aio_age_throttle(now, context.snapshot);
        context.effectiveLimit =
            aio_effective_read_limit(now, context.snapshot);
        context.current = true;
    }

    void apply_fd_pressure_event(uint64_t now) const {
        constexpr uint64_t kFdPressureCooldownNs =
            AMPR_EMU_APR_FD_PRESSURE_COOLDOWN_MS * 1000000ull;
        const uint64_t until = now + kFdPressureCooldownNs;
        if (until > fdPressureUntilNs) {
            fdPressureUntilNs = until;
        }
        const size_t cap = ampr_index_fd_pressure_current_caps().cacheCap;
        ampr_index_fd_cache_set_effective_cap(cap);
        fdCachePressureCapApplied = true;
        ampr_index_fd_cache_release_open_fd_headroom(0, cap);
    }

    void sync_fd_cache_open_pressure(uint64_t now) const {
        const uint64_t generation = ampr_index_fd_cache_open_pressure_generation();
        if (generation == fdCacheOpenPressureSeen) {
            return;
        }
        fdCacheOpenPressureSeen = generation;
        apply_fd_pressure_event(now);
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
        if (fdCachePressureCapApplied) {
            ampr_index_fd_open_budget_set_effective_cap(kFdOpenBudgetBaseCap);
            ampr_index_fd_cache_set_effective_cap(AMPR_EMU_FD_CACHE_CAP);
            fdCachePressureCapApplied = false;
        }
        return false;
    }

    bool fd_budget_available_for_read(const AprAioReadDesc& rd) const {
        if (rd.fd >= 0) {
            return true;
        }
        if (!read_would_bypass_fd_cache(rd)) {
            // Cache hits and cached-open headroom are decided atomically by
            // ampr_index_acquire_cached_fd under the fd-cache lock.
            return true;
        }
        return ampr_index_fd_common_open_budget_headroom_available(1);
    }

    uint32_t poll_only_idle_sleep_ns() {
#if AMPR_EMU_APR_AIO_POLL_BACKGROUND_SLEEP_NS != AMPR_EMU_APR_AIO_POLL_IDLE_SLEEP_NS
        if (activeJobCountAtomic.load(std::memory_order_relaxed) == 0) {
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
            // Keep backoff monotonic with request age. In particular, the
            // staged-EOP cap is 50 us, so max/2 alone would incorrectly tighten
            // it to 25 us after the request crosses 1 ms.
            uint32_t halfCapNs = maxBackoffNs / 2u;
            if (halfCapNs < AMPR_EMU_APR_AIO_POLL_IDLE_SLEEP_NS) {
                halfCapNs = AMPR_EMU_APR_AIO_POLL_IDLE_SLEEP_NS;
            }
            capNs = halfCapNs < maxBackoffNs ? halfCapNs : maxBackoffNs;
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

    static void increment_active_read_count(const JobPtr& job) {
        if (!job) {
            return;
        }
        if (job->activeReadCount == UINT32_MAX) {
            AMPR_KLOGF("ampr.abort reason=apr.reactor.job.activeReads.overflow file=%s line=%d", __FILE__, __LINE__);
            std::abort();
        }
        ++job->activeReadCount;
    }

    static void decrement_active_read_count(const JobPtr& job) {
        if (!job) {
            return;
        }
        if (job->activeReadCount == 0) {
            AMPR_KLOGF("ampr.abort reason=apr.reactor.job.activeReads.underflow file=%s line=%d", __FILE__, __LINE__);
            std::abort();
        }
        --job->activeReadCount;
    }

    static uint64_t read_credit_bytes(uint64_t requestBytes) {
        const uint64_t granule =
            static_cast<uint64_t>(AMPR_EMU_APR_READ_CREDIT_GRANULE_BYTES);
        if (requestBytes == 0) {
            return 0;
        }
        const uint64_t remainder = requestBytes & (granule - 1ull);
        return remainder == 0 ? requestBytes : requestBytes + (granule - remainder);
    }

    static void increment_read_chain_active(ReadChain* chain, uint64_t bytes) {
        if (!chain) {
            return;
        }
        if (chain->activeCount == UINT32_MAX ||
            chain->activeBytes > (std::numeric_limits<uint64_t>::max)() - bytes) {
            AMPR_KLOGF("ampr.abort reason=apr.reactor.readChain.active.overflow file=%s line=%d", __FILE__, __LINE__);
            std::abort();
        }
        ++chain->activeCount;
        chain->activeBytes += bytes;
    }

    static void decrement_read_chain_active(ReadChain* chain, uint64_t bytes) {
        if (!chain) {
            return;
        }
        if (chain->activeCount == 0 || chain->activeBytes < bytes) {
            AMPR_KLOGF("ampr.abort reason=apr.reactor.readChain.active.underflow file=%s line=%d", __FILE__, __LINE__);
            std::abort();
        }
        --chain->activeCount;
        chain->activeBytes -= bytes;
    }

    void abandon_unsubmitted_read_chain(ReadChain*& slot) {
        ReadChain* const chain = slot;
        slot = nullptr;
        if (!read_chain_is_live(chain)) {
            return;
        }
        chain->allIssued = true;
        maybe_finish_read_chain(chain);
    }

    void abandon_job_cursor_read_chains(JobState& job) {
        abandon_unsubmitted_read_chain(job.cursorReadChain);
#if AMPR_EMU_APR_AIO_CROSS_EOP_READAHEAD
        abandon_unsubmitted_read_chain(job.crossEopReadChain);
#endif
    }

#if AMPR_EMU_APR_AIO_CROSS_EOP_READAHEAD
    void drop_unsubmitted_cross_eop_suffix(JobState& job, uint32_t errorOffset) {
        ReadChain* const chain = job.crossEopReadChain;
        if (!read_chain_is_live(chain) || chain->ownerDesc.errorOff < errorOffset) {
            return;
        }
        abandon_unsubmitted_read_chain(job.crossEopReadChain);
        AMPR_LOGF("apr.reactor.crossEop.dropSuffix job=0x%llx errorOffset=0x%x active=%u",
                  (unsigned long long)job.id,
                  errorOffset,
                  job.activeReadCount);
    }
#endif

    void set_fail(JobState& job, [[maybe_unused]] const char* reason, int rc, uint32_t errorOffset) {
        if (job.failed.exchange(true, std::memory_order_acq_rel)) {
            return;
        }
        job.result.rc = rc ? rc : SCE_KERNEL_ERROR_EIO;
        job.result.errorOffset = errorOffset;
        clear_cursor_read_wait_hint(job.prioIndex);
        finish_job_processing(job);
        abandon_job_cursor_read_chains(job);
        AMPR_CRITICAL_LOGF("apr.reactor.fail job=0x%llx reason=%s rc=0x%x errorOffset=0x%x cursorRead=%u active=%u",
                  (unsigned long long)job.id,
                  reason ? reason : "unknown",
                  job.result.rc,
                  job.result.errorOffset,
                  job.cursorReadChain != nullptr ? 1u : 0u,
                  job.activeReadCount);
    }

    void set_command_error(JobState& job, const char* reason, int rc, uint32_t errorOffset) {
        if (job_failed(job) || job.hasCommandError) {
            return;
        }
        job.hasCommandError = true;
        set_fail(job, reason, rc, errorOffset);
        AMPR_CRITICAL_LOGF("apr.reactor.command.error job=0x%llx reason=%s rc=0x%x errorOffset=0x%x active=%u action=stop-cursor",
                  (unsigned long long)job.id,
                  reason ? reason : "unknown",
                  job.result.rc,
                  job.result.errorOffset,
                  job.activeReadCount);
    }


    bool set_or_defer_read_command_error(JobState& job,
                                         const char* reason,
                                         int rc,
                                         uint32_t errorOffset) {
#if AMPR_EMU_APR_AIO_CROSS_EOP_READAHEAD
        if (!job_failed(job) && job.crossEopScanActive &&
            errorOffset > job.sourceOffset &&
            errorOffset <= job.crossEopScanOffset) {
            if (job.crossEopDeferredErrorOffset == UINT32_MAX ||
                errorOffset < job.crossEopDeferredErrorOffset) {
                job.crossEopDeferredErrorOffset = errorOffset;
                job.crossEopDeferredErrorRc = rc;
                job.crossEopDeferredErrorReason = reason;
                drop_unsubmitted_cross_eop_suffix(job, errorOffset);
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
                set_command_error(
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

    void maybe_finish_read_chain(ReadChain* chain) {
        // Error handling can remove the last future slice and retire the chain
        // synchronously. Treat a repeated finish attempt as a no-op instead of
        // touching a slot that has already returned to the fixed pool.
        if (!read_chain_is_live(chain) || chain->activeCount != 0 ||
            chain->activeBytes != 0) {
            return;
        }
        JobPtr job = chain->job;
        if (job && !job_failed(*job) && !chain->allIssued) {
            return;
        }
        const uint64_t seq = chain->seq;
        apr_release_aio_read_desc(chain->ownerDesc);
        if (job && !job_failed(*job) && seq != 0) {
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
        AMPR_VLOGF("apr.reactor.blocked job=0x%llx reason=%s opIndex=%zu commands=%u type=%s off=0x%x cursorRead=%u speculativeRead=%u active=%u completedSeq=0x%llx latestSeq=0x%llx addr=%p value=0x%llx valueKnown=%u rangeValid=%u cpuReadable=%u amprReadable=%u protRc=0x%x prot=0x%x ref=0x%llx cmp=%u flush=%u count=%llu",
                  (unsigned long long)job.id,
                  reason ? reason : "unknown",
                  opIndex,
                  job_commands_for_log(job),
                  sce::Ampr::ampr_op_name(op.type),
                  op.bufOffsetBytes,
                  job.cursorReadChain != nullptr ? 1u : 0u,
#if AMPR_EMU_APR_AIO_CROSS_EOP_READAHEAD
                  job.crossEopReadChain != nullptr ? 1u : 0u,
#else
                  0u,
#endif
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

    struct CursorReadWaitHint {
        uint32_t fileId{};
        bool valid{};
    };

    void clear_cursor_read_wait_hint(size_t priority) {
        if (priority < kPriorityCount) {
            cursorReadWaitHints[priority] = {};
        }
    }

    void set_cursor_read_wait_hint(size_t priority, uint32_t fileId) {
        if (priority < kPriorityCount) {
            cursorReadWaitHints[priority].fileId = fileId;
            cursorReadWaitHints[priority].valid = true;
        }
    }


    enum class A53ReadGroup : uint8_t {
        Urgent = 0,
        High = 1,
        Normal = 2,
        Count = 3,
    };

    struct A53ReadGroupCounts {
        uint32_t values[static_cast<size_t>(A53ReadGroup::Count)]{};
    };

    static A53ReadGroup read_group_for_priority(uint8_t priority) {
        if (priority == 0) {
            return A53ReadGroup::Urgent;
        }
        if (priority <= 3) {
            return A53ReadGroup::High;
        }
        return A53ReadGroup::Normal;
    }

    static size_t read_group_index(A53ReadGroup group) {
        return static_cast<size_t>(group);
    }

    A53ReadGroupCounts active_read_group_counts() const {
        A53ReadGroupCounts counts{};
        for (auto it = activeReads.begin(); it != activeReads.end(); ++it) {
            if (!it->job || it->job->prioIndex >= kPriorityCount) {
                continue;
            }
            const A53ReadGroup group =
                read_group_for_priority(it->job->prioIndex);
            ++counts.values[read_group_index(group)];
        }
        return counts;
    }

    bool group_has_waiting_cursor(A53ReadGroup group) const {
        for (size_t priority = 0; priority < kPriorityCount; ++priority) {
            if (!cursorReadWaitHints[priority].valid ||
                read_group_for_priority(static_cast<uint8_t>(priority)) != group) {
                continue;
            }
            return true;
        }
        return false;
    }

    static uint32_t scaled_group_target(uint32_t limit,
                                             uint32_t numerator) {
        return (limit * numerator + 16u) / 32u;
    }

    A53ReadGroupCounts read_group_targets(
        uint32_t limit,
        const A53ReadGroupCounts& active) const {
        A53ReadGroupCounts targets{};
        if (limit == 0) {
            return targets;
        }

        const size_t u = read_group_index(A53ReadGroup::Urgent);
        const size_t h = read_group_index(A53ReadGroup::High);
        const size_t n = read_group_index(A53ReadGroup::Normal);
        const bool urgentDemand =
            active.values[u] != 0 || group_has_waiting_cursor(A53ReadGroup::Urgent);

        if (!urgentDemand) {
            uint32_t high = scaled_group_target(limit, 20u);
            if (limit > 1u) {
                high = (std::max)(1u, (std::min)(high, limit - 1u));
            } else {
                high = limit;
            }
            targets.values[h] = high;
            targets.values[n] = limit - high;
            return targets;
        }

        uint32_t urgent = scaled_group_target(limit, 4u);
        uint32_t high = scaled_group_target(limit, 18u);
        if (limit >= 3u) {
            urgent = (std::max)(1u, urgent);
            high = (std::max)(1u, high);
            if (urgent + high >= limit) {
                high = limit - urgent - 1u;
            }
            targets.values[u] = urgent;
            targets.values[h] = high;
            targets.values[n] = limit - urgent - high;
        } else {
            targets.values[u] = 1u;
            targets.values[h] = limit > 1u ? 1u : 0u;
            targets.values[n] = 0u;
        }
        return targets;
    }

    bool group_soft_target_available(
        uint8_t priority,
        uint32_t effectiveLimit,
        const AioAdmissionSnapshot& snapshot) const {
#if !AMPR_EMU_APR_GROUP_SOFT_TARGETS
        (void)priority;
        (void)effectiveLimit;
        (void)snapshot;
        return true;
#else
        if (effectiveLimit <= 1u) {
            return true;
        }
        A53ReadGroupCounts active{};
        for (size_t index = 0; index < 3u; ++index) {
            active.values[index] = snapshot.groupActive[index];
        }
        const A53ReadGroupCounts targets =
            read_group_targets(effectiveLimit, active);
        const A53ReadGroup requested = read_group_for_priority(priority);
        const size_t requestedIndex = read_group_index(requested);
        if (active.values[requestedIndex] < targets.values[requestedIndex]) {
            return true;
        }

        // Targets model A53's separate U/H/N resource pools over one host AIO
        // window. Capacity remains borrowable while the other groups are idle;
        // once another group has a cursor waiting below its target, stop further
        // borrowing until that group receives its share.
        for (size_t index = 0;
             index < static_cast<size_t>(A53ReadGroup::Count);
             ++index) {
            if (index == requestedIndex ||
                targets.values[index] == 0 ||
                active.values[index] >= targets.values[index]) {
                continue;
            }
            const A53ReadGroup other = static_cast<A53ReadGroup>(index);
            if (group_has_waiting_cursor(other)) {
                return false;
            }
        }
        return true;
#endif
    }

    void note_aio_admission_accepted(AioAdmissionContext& context,
                                     const ActiveRead& active,
                                     uint64_t submitTimeNs) {
        if (!context.initialized || !context.current) {
            AMPR_KLOGF("ampr.abort reason=apr.reactor.aio.admission.context.uninitialized file=%s line=%d", __FILE__, __LINE__);
            std::abort();
        }
        ++context.snapshot.activeCount;
        if (aio_desc_is_small_for_boost(active.desc)) {
            ++context.snapshot.smallCount;
        }
        if (active.job && active.job->prioIndex < kPriorityCount) {
            const A53ReadGroup group =
                read_group_for_priority(active.job->prioIndex);
            ++context.snapshot.groupActive[read_group_index(group)];
        }
        if (submitTimeNs != 0 &&
            (context.snapshot.oldestSubmittedTimeNs == 0 ||
             submitTimeNs < context.snapshot.oldestSubmittedTimeNs)) {
            context.snapshot.oldestSubmittedTimeNs = submitTimeNs;
        }
        context.laneNowNs = submitTimeNs;
        context.laneNowValid = true;
        refresh_aio_snapshot_age(context.snapshot, submitTimeNs);
        update_aio_age_throttle(submitTimeNs, context.snapshot);
        context.effectiveLimit =
            aio_effective_read_limit(submitTimeNs, context.snapshot);
    }

    enum class DirectReadSubmitResult : uint8_t {
        Deferred,
        Submitted,
        Failed,
    };

    struct DirectReadSubmitOutcome {
        DirectReadSubmitResult result{DirectReadSubmitResult::Failed};
        const char* errorReason{};
        int errorRc{};
        uint32_t errorOffset{};

        bool has_error() const {
            return errorReason != nullptr;
        }
    };

    bool direct_read_admission_available(uint8_t priority,
                                         const AprAioReadDesc& ownerDesc,
                                         const AprAioReadDesc& sliceDesc,
                                         uint64_t nowNs,
                                         AioAdmissionContext& context) {
        prepare_aio_admission_context(context, nowNs);
        // This call also synchronizes process-wide open-pressure generation and
        // restores normal FD/cache caps when the cooldown expires.
        (void)fd_pressure_active(nowNs);
        const uint32_t limit = context.effectiveLimit;
        const size_t activeCount = context.snapshot.activeCount;
        if (activeCount >= limit) {
            return false;
        }
        if (!group_soft_target_available(priority,
                                         limit,
                                         context.snapshot)) {
            return false;
        }
        // Slots above the normal window are exclusively for small SDK reads.
        if (activeCount >= aio_active_read_limit() &&
            !aio_desc_is_small_for_boost(sliceDesc)) {
            return false;
        }
        return fd_budget_available_for_read(ownerDesc);
    }

    DirectReadSubmitOutcome submit_read_chain_slice(JobPtr& job,
                                                     ReadChain& chain,
                                                     ReadIssueBudget& issueBudget,
                                                     AioAdmissionContext& admission) {
        constexpr SceKernelAioSubmitId kUnsetAioId =
            static_cast<SceKernelAioSubmitId>(-1);
        if (!job || job_failed(*job) || chain.job != job || chain.remaining == 0) {
            return {DirectReadSubmitResult::Failed, nullptr, 0, 0};
        }

        AprAioReadDesc sliceDesc = read_chain_next_desc(chain);
        const uint64_t sliceBytes = sliceDesc.length;
        const uint64_t sliceCreditBytes = read_credit_bytes(sliceBytes);
        if (sliceCreditBytes == 0) {
            return {DirectReadSubmitResult::Failed,
                    "aio-read-credit-zero",
                    SCE_KERNEL_ERROR_EINVAL,
                    sliceDesc.errorOff};
        }

        // Count and charged bytes are separate credits. Actual I/O length is
        // unchanged. <=64 KiB requests each cost 64 KiB; 65..128 KiB cost
        // 128 KiB, etc. A full 512 KiB request consumes the whole byte window.
        if (chain.activeCount >=
                static_cast<uint32_t>(AMPR_EMU_APR_PER_READ_ACTIVE_CHUNKS) ||
            sliceCreditBytes >
                static_cast<uint64_t>(AMPR_EMU_APR_PER_READ_ACTIVE_BYTES) ||
            chain.activeBytes >
                static_cast<uint64_t>(AMPR_EMU_APR_PER_READ_ACTIVE_BYTES) -
                    sliceCreditBytes) {
            return {DirectReadSubmitResult::Deferred, nullptr, 0, 0};
        }
        if (!issueBudget.can_admit(sliceCreditBytes)) {
            return {DirectReadSubmitResult::Deferred, nullptr, 0, 0};
        }
        const uint64_t nowNs = aio_admission_lane_now(admission);
        if (chain.retryNotBeforeNs != 0) {
            if (nowNs < chain.retryNotBeforeNs) {
                return {DirectReadSubmitResult::Deferred, nullptr, 0, 0};
            }
            chain.retryNotBeforeNs = 0;
        }
        if (!direct_read_admission_available(job->prioIndex,
                                             chain.ownerDesc,
                                             sliceDesc,
                                             nowNs,
                                             admission)) {
            return {DirectReadSubmitResult::Deferred, nullptr, 0, 0};
        }

        if (chain.ownerDesc.fd < 0) {
            int acquireRc = 0;
            uint32_t acquireErrorOff = chain.ownerDesc.errorOff;
            const bool allowNewFd = !fd_pressure_active(nowNs);
            const bool acquired = apr_acquire_aio_read_desc(job->id,
                                                            chain.ownerDesc,
                                                            allowNewFd,
                                                            &acquireRc,
                                                            &acquireErrorOff);
            if (!acquired) {
                if (acquireRc == SCE_KERNEL_ERROR_EAGAIN ||
                    acquireRc == SCE_KERNEL_ERROR_EMFILE) {
                    const uint64_t failureNowNs = time_counter_now();
                    if (acquireRc == SCE_KERNEL_ERROR_EMFILE) {
                        note_emfile_event();
                        // The fd layer already published process-wide pressure
                        // and released reclaimable descriptors. Synchronize it
                        // now so later APR priorities can reuse existing fds but
                        // cannot issue another open during the cooldown.
                        (void)fd_pressure_active(failureNowNs);
                    }
                    chain.retryNotBeforeNs =
                        failureNowNs + AMPR_EMU_APR_AIO_SUBMIT_RETRY_DELAY_NS;
                    return {DirectReadSubmitResult::Deferred, nullptr, 0, 0};
                }
                chain.allIssued = true;
                return {DirectReadSubmitResult::Failed,
                        "aio-acquire-fd",
                        apr_backend_read_error_to_apr(acquireRc),
                        acquireErrorOff};
            }
            // Rebuild after acquiring the chain-owned fd; the active slice
            // borrows this descriptor and never owns/duplicates the pin.
            sliceDesc = read_chain_next_desc(chain);
        }

        borrow_read_chain_fd(chain, sliceDesc);
        const uint64_t seqCandidate =
            chain.seq != 0 ? chain.seq : job->nextReadSeq;
        ActiveReadIt activeIt = activeReads.push_back(ActiveRead{});
        note_active_read_peak(activeReads.size());
        ActiveRead& active = *activeIt;
        active.job = job;
        active.desc = ampr_move(sliceDesc);
        active.chain = &chain;
        active.seq = seqCandidate;
        active.commandIndex = chain.commandIndex;
        active.readCreditBytes = sliceCreditBytes;
#if AMPR_EMU_DEBUG_LOG
        active.nativeTriggerTimeNs = chain.nativeTriggerTimeNs;
        active.sliceReadyTimeNs = chain.sliceReadyTimeNs;
#endif
        active.result = {};
        active.request = {};
        link_active_read_to_job(active, *job);
        increment_active_read_count(job);
        increment_read_chain_active(&chain, active.readCreditBytes);
        active.request.offset = static_cast<off_t>(active.desc.offset);
        active.request.nbyte = static_cast<size_t>(active.desc.length);
        active.request.buf = active.desc.buffer;
        active.request.result = &active.result;
        active.request.fd = active.desc.fd;

#if AMPR_EMU_DEBUG_LOG && AMPR_EMU_DEBUG_LOG_TRACE
        log_aio_buffer_memory_detail("apr.reactor.aio.bufVa",
                                     "submit-direct",
                                     active,
                                     time_counter_now(),
                                     0,
                                     0);
#endif

        ensure_aio_initialized();
        const int aioPriority = apr_aio_priority_from_apr(job->prioIndex);
        SceKernelAioSubmitId aioId = kUnsetAioId;
        const int submitRc = sceKernelAioSubmitReadCommands(
            &active.request,
            1,
            aioPriority,
            &aioId);
        const uint64_t submitTimeNs = time_counter_now();
        const int submitSceRc = apr_aio_api_rc_to_sce(submitRc);
        note_aio_submit_result(submitSceRc);

        if ((submitRc == 0 && aioId == kUnsetAioId) ||
            (submitRc != 0 && aioId != kUnsetAioId)) {
            AMPR_CRITICAL_LOGF("apr.reactor.aio.submit.single.inconsistent rc=0x%x aioId=%d prio=%d action=abort",
                               submitSceRc,
                               aioId,
                               aioPriority);
            AMPR_KLOGF("ampr.abort reason=apr.reactor.aio.submit.single.inconsistent file=%s line=%d", __FILE__, __LINE__);
            std::abort();
        }

        if (submitRc != 0) {
            const uint32_t errorOff = active.desc.errorOff;
            apr_release_aio_read_desc(active.desc);
            decrement_active_read_count(job);
            decrement_read_chain_active(&chain, active.readCreditBytes);
            erase_active_read(activeIt);
            if (apr_aio_submit_sce_rc_is_deferred(submitSceRc)) {
                chain.retryNotBeforeNs =
                    submitTimeNs + AMPR_EMU_APR_AIO_SUBMIT_RETRY_DELAY_NS;
                return {DirectReadSubmitResult::Deferred, nullptr, 0, 0};
            }
            chain.allIssued = true;
            return {DirectReadSubmitResult::Failed,
                    "aio-submit",
                    apr_backend_read_error_to_apr(submitSceRc),
                    errorOff};
        }

        issueBudget.consume(active.readCreditBytes);

        if (chain.seq == 0) {
            chain.seq = seqCandidate;
            ++job->nextReadSeq;
            job->latestSubmittedReadSeq = seqCandidate;
        }
        active.seq = chain.seq;
        mark_active_read_submitted(active, aioId);
        active.aioPrio = aioPriority;
        active.submitTimeNs = submitTimeNs;
        active.retryNotBeforeNs = 0;
        note_aio_admission_accepted(admission, active, submitTimeNs);

        DirectReadSubmitOutcome outcome{DirectReadSubmitResult::Submitted,
                                        nullptr,
                                        0,
                                        0};
        const uint64_t issuedLength = active.desc.length;
        if (issuedLength == 0 || issuedLength > chain.remaining) {
            chain.allIssued = true;
            outcome.errorReason = "aio-read-chain-range";
            outcome.errorRc = SCE_KERNEL_ERROR_EINVAL;
            outcome.errorOffset = active.desc.errorOff;
        } else {
            chain.remaining -= issuedLength;
            chain.nextBuffer = reinterpret_cast<void*>(
                reinterpret_cast<uintptr_t>(chain.nextBuffer) +
                static_cast<uintptr_t>(issuedLength));
            chain.nextOffset += issuedLength;
            if (chain.remaining == 0) {
                chain.allIssued = true;
            }
#if AMPR_EMU_DEBUG_LOG
            else {
                chain.sliceReadyTimeNs = submitTimeNs;
            }
#endif
        }

#if AMPR_EMU_DEBUG_LOG
        note_native_trigger_to_aio_submit(active.nativeTriggerTimeNs,
                                          submitTimeNs);
        note_read_ready_to_aio_submit(active.sliceReadyTimeNs,
                                              submitTimeNs,
                                              job->prioIndex);
        note_job_queue_to_first_aio_submit(*job, submitTimeNs);
        note_accepted_aio_request(active.desc.length, job->prioIndex);
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
        return outcome;
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
            set_command_error(
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
            set_command_error(job,
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
                             AioAdmissionContext& admission,
                             bool advanceSource = true,
                             bool deferValidationError = false,
                             bool* outLogicalIssued = nullptr,
                             ReadIssueBudget* issueBudget = nullptr) {
        if (outLogicalIssued) {
            *outLogicalIssued = false;
        }
        if (!job) {
            return false;
        }
        if (issueBudget &&
            (issueBudget->requestsLeft == 0 || issueBudget->bytesLeft == 0)) {
            return false;
        }
        if (read.length == 0 || read.length > kSoftwareReadLengthMax) {
            if (!deferValidationError) {
                set_command_error(*job,
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
                set_command_error(*job,
                                                 "software-read-range",
                                                 SCE_KERNEL_ERROR_EINVAL,
                                                 opOffset);
            }
            return false;
        }

        ReadChain*& chainSlot = advanceSource
            ? job->cursorReadChain
#if AMPR_EMU_APR_AIO_CROSS_EOP_READAHEAD
            : job->crossEopReadChain;
#else
            : job->cursorReadChain;
#endif

        ReadChain* chain = chainSlot;
        if (!chain) {
            if (apr_read_completion_window_exhausted(
                    job->latestSubmittedReadSeq,
                    job->completedReadSeq,
                    kReadCompletionRingBits)) {
#if AMPR_EMU_DEBUG_LOG
                if (!job->readCompletionWindowBlocked) {
                    job->readCompletionWindowBlocked = true;
                    AMPR_LOGF("apr.reactor.read.completion.backpressure job=0x%llx sourceOffset=0x%x nextSeq=0x%llx latest=0x%llx completed=0x%llx capacity=%llu active=%u",
                              (unsigned long long)job->id,
                              opOffset,
                              (unsigned long long)job->nextReadSeq,
                              (unsigned long long)job->latestSubmittedReadSeq,
                              (unsigned long long)job->completedReadSeq,
                              (unsigned long long)kReadCompletionRingBits,
                              job->activeReadCount);
                }
#endif
                return false;
            }
#if AMPR_EMU_DEBUG_LOG
            job->readCompletionWindowBlocked = false;
#endif

            AprAioReadDesc logicalRead{};
            int prepareRc = 0;
            if (!apr_prepare_aio_read_desc(job->id,
                                           read.fileId,
                                           read.buffer,
                                           read.length,
                                           read.offset,
                                           opOffset,
                                           &logicalRead,
                                           &prepareRc)) {
                if (!deferValidationError) {
                    set_command_error(*job,
                                                     "software-read-prepare",
                                                     prepareRc,
                                                     opOffset);
                }
                return false;
            }
            apr_update_read_desc_fd_policy(logicalRead);

            chain = allocate_read_chain();
            if (!chain) {
                AMPR_CRITICAL_LOGF("apr.reactor.readChain.pool.full job=0x%llx sourceOffset=0x%x capacity=%u activeReads=%zu action=defer",
                                   (unsigned long long)job->id,
                                   opOffset,
                                   (unsigned)kReadChainPoolCapacity,
                                   activeReads.size());
                return false;
            }
            chain->job = job;
            chain->ownerDesc = ampr_move(logicalRead);
            chain->nextBuffer = chain->ownerDesc.buffer;
            chain->nextOffset = chain->ownerDesc.offset;
            chain->remaining = chain->ownerDesc.length;
            chain->commandIndex = commandIndex;
#if AMPR_EMU_DEBUG_LOG
            chain->sliceReadyTimeNs = time_counter_now();
            note_job_queue_to_first_read_ready(*job,
                                               chain->sliceReadyTimeNs);
#endif
            chainSlot = chain;
#if AMPR_EMU_DEBUG_LOG && (AMPR_EMU_DEBUG_LOG_VERBOSE || AMPR_EMU_DEBUG_LOG_TRACE)
            ++job->readOpCount;
#endif
        } else if (!read_chain_is_live(chain) ||
                   chain->job != job ||
                   chain->commandIndex != commandIndex ||
                   chain->ownerDesc.errorOff != opOffset) {
            AMPR_CRITICAL_LOGF("apr.reactor.readChain.cursor.mismatch job=0x%llx sourceOffset=0x%x commandIndex=%zu chain=%p action=abort",
                               (unsigned long long)job->id,
                               opOffset,
                               commandIndex,
                               chain);
            AMPR_KLOGF("ampr.abort reason=apr.reactor.readChain.cursor.mismatch file=%s line=%d", __FILE__, __LINE__);
            std::abort();
        }

        if (advanceSource) {
            set_cursor_read_wait_hint(job->prioIndex, read.fileId);
        }

        ReadIssueBudget singleRequestBudget{1u, kSoftwareReadChunkMax};
        ReadIssueBudget& budget = issueBudget ? *issueBudget : singleRequestBudget;
        bool submittedAny = false;
        while (budget.requestsLeft != 0 && budget.bytesLeft != 0) {
            const DirectReadSubmitOutcome outcome =
                submit_read_chain_slice(job, *chain, budget, admission);
            if (outcome.result == DirectReadSubmitResult::Deferred) {
                return submittedAny;
            }
            if (outcome.result == DirectReadSubmitResult::Failed ||
                outcome.has_error() || job_failed(*job)) {
                if (advanceSource) {
                    clear_cursor_read_wait_hint(job->prioIndex);
                }

                // Detach cursor ownership before publishing an error. Error
                // publication may call set_fail(), which abandons cursor chains and
                // can synchronously return an unsubmitted chain to the fixed pool.
                // After maybe_finish_read_chain(), do not dereference `chain`.
                chain->allIssued = true;
                chainSlot = nullptr;
                maybe_finish_read_chain(chain);

                if (outcome.has_error() && !job_failed(*job)) {
                    set_or_defer_read_command_error(*job,
                                                    outcome.errorReason,
                                                    outcome.errorRc,
                                                    outcome.errorOffset);
                }
                return submittedAny;
            }

            submittedAny = true;

            if (!chain->allIssued) {
                // Bounded A53-like allocation batch: up to eight requests,
                // with a shared 512 KiB byte budget for the entire lane pass.
                continue;
            }

            chainSlot = nullptr;
            update_software_gs_cursor(gs, read);
            if (advanceSource) {
                clear_cursor_read_wait_hint(job->prioIndex);
                advance_job_source(*job, opBytes);
            }
            if (outLogicalIssued) {
                *outLogicalIssued = true;
            }
            return true;
        }

        // The logical read remains attached to its execution/speculative source
        // cursor and resumes on a later priority-ordered reactor pass.
        return submittedAny;
    }

#if AMPR_EMU_APR_AIO_CROSS_EOP_READAHEAD
    bool issue_reads_across_eop(JobPtr& job,
                                GatherScatterState& gs,
                                ReadIssueBudget& readIssueBudget,
                                AioAdmissionContext& admission) {
        if (!job || job_failed(*job) ||
            job->crossEopDeferredErrorOffset != UINT32_MAX) {
            return false;
        }
        if (readIssueBudget.requestsLeft == 0 ||
            readIssueBudget.bytesLeft == 0) {
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
                AMPR_KLOGF("ampr.abort reason=apr.reactor.crossEop.scan.reset.invalid file=%s line=%d", __FILE__, __LINE__);
                std::abort();
            }
            job->crossEopScanOffset = job->sourceOffset;
            job->crossEopScanCommandIndex = job->sourceCommandIndex;
            job->crossEopScanActive = true;
        }
        if (job->crossEopScanOffset >= job->sourceBytes ||
            job->crossEopScanCommandIndex >= job->commandCount) {
            return false;
        }

        // Readahead has its own speculative cursor, but it follows the same
        // scheduling rule as the execution cursor and shares the same request +
        // byte budget for the current priority-lane pass.
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
            return false;
        }
        op.bufOffsetBytes = job->crossEopScanOffset;

        if (software_op_is_eop_completion(op)) {
            if (!push_cross_eop_fence(*job,
                                      op.bufOffsetBytes,
                                      job->crossEopScanCommandIndex,
                                      job->latestSubmittedReadSeq)) {
                return false;
            }
            job->crossEopScanOffset += opBytes;
            ++job->crossEopScanCommandIndex;
            return true;
        }

        if (op.type == OpType::WaitOnAddress) {
            const uintptr_t address = reinterpret_cast<uintptr_t>(op.ptra);
            if (address == 0 ||
                (address & (alignof(uint64_t) - 1u)) != 0 ||
                op.u32a > 6u) {
                return false;
            }
            const uint64_t observed = __atomic_load_n(
                static_cast<const uint64_t*>(op.ptra),
                __ATOMIC_ACQUIRE);
            if (!software_wait_compare(observed, op.u64a, op.u32a)) {
                return false;
            }
            job->crossEopScanOffset += opBytes;
            ++job->crossEopScanCommandIndex;
            AMPR_TLOGF("apr.reactor.crossEop.waitAddress.pass job=0x%llx sourceOffset=0x%x commandIndex=%u observed=0x%llx reference=0x%llx compare=%u scanOffset=0x%x",
                       (unsigned long long)job->id,
                       op.bufOffsetBytes,
                       job->crossEopScanCommandIndex - 1u,
                       (unsigned long long)observed,
                       (unsigned long long)op.u64a,
                       op.u32a,
                       job->crossEopScanOffset);
            return true;
        }

        if (!cb_op_is_apr_read(op.type)) {
            return false;
        }

        SoftwareRead read{};
        bool logicalIssued = false;
        if (resolve_software_read(gs, op, &read) != 0 ||
            !issue_software_read(job,
                                 gs,
                                 read,
                                 opBytes,
                                 op.bufOffsetBytes,
                                 job->crossEopScanCommandIndex,
                                 admission,
                                 false,
                                 true,
                                 &logicalIssued,
                                 &readIssueBudget)) {
            return false;
        }
        if (!logicalIssued) {
            // Large logical reads retain this speculative command until one
            // slice has been accepted on each subsequent reactor tick.
            return true;
        }

        job->crossEopScanOffset += opBytes;
        ++job->crossEopScanCommandIndex;
        AMPR_TLOGF("apr.reactor.crossEop.read job=0x%llx sourceOffset=0x%x commandIndex=%u seq=0x%llx scanOffset=0x%x fences=%u",
                   (unsigned long long)job->id,
                   op.bufOffsetBytes,
                   job->crossEopScanCommandIndex - 1u,
                   (unsigned long long)job->latestSubmittedReadSeq,
                   job->crossEopScanOffset,
                   job->crossEopFenceCount);
        return true;
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
            AMPR_KLOGF("ampr.abort reason=apr.reactor.native.batch.reset.invalid file=%s line=%d", __FILE__, __LINE__);
            std::abort();
        }
        __atomic_store_n(apr_native_batch_release_ptr(*slot), 0ull, __ATOMIC_RELAXED);
        __atomic_store_n(apr_native_batch_progress_ptr(*slot), 0ull, __ATOMIC_RELAXED);
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
        nativeCommandBuffer.m_commandBuffer.offset = kAprNativeBatchExecutableBytes;
        nativeCommandBuffer.m_commandBuffer.num =
            static_cast<int32_t>(kAprNativeBatchCommandCount);
        nativeCommandBuffer.m_commandBuffer.bufsize = kAprNativeBatchSubmitBytes;
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
                               kAprNativeBatchExecutableBytes,
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
                   kAprNativeBatchExecutableBytes,
                   kAprNativeBatchCommandCount,
                   (unsigned long long)__atomic_load_n(apr_native_batch_release_ptr(*slot),
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
            __atomic_store_n(apr_native_batch_release_ptr(*slot), token, __ATOMIC_RELEASE);
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
            AMPR_KLOGF("ampr.abort reason=apr.reactor.native.batch.deferred.invalid file=%s line=%d", __FILE__, __LINE__);
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
            AMPR_KLOGF("ampr.abort reason=apr.reactor.native.batch.deferred.state.invalid file=%s line=%d", __FILE__, __LINE__);
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
        __atomic_store_n(apr_native_batch_release_ptr(*slot), token, __ATOMIC_RELEASE);
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
                        apr_native_batch_release_ptr(*slot),
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
                AMPR_KLOGF("ampr.abort reason=apr.reactor.native.batch.deferred.append.invalid file=%s line=%d", __FILE__, __LINE__);
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
            AMPR_KLOGF("ampr.abort reason=apr.reactor.native.batch.type.mismatch file=%s line=%d", __FILE__, __LINE__);
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
            AMPR_KLOGF("ampr.abort reason=apr.reactor.native.batch.sequence.wrap file=%s line=%d", __FILE__, __LINE__);
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
            AMPR_KLOGF("ampr.abort reason=apr.reactor.native.batch.group.seal.fail file=%s line=%d", __FILE__, __LINE__);
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
                      bool& speculativeCommandUsed,
                      ReadIssueBudget& readIssueBudget,
                      AioAdmissionContext& admission) {
        if (!job) {
            return false;
        }
#if !AMPR_EMU_APR_AIO_CROSS_EOP_READAHEAD
        (void)speculativeCommandUsed;
#endif
        bool progressed = false;
        const uint32_t sourceOffsetAtEntry = job->sourceOffset;

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
        if (job->nativeBatchReleasePending && !job_failed(*job) &&
            (priorReadFencePending ||
             (job->nativeBatchReleaseReadSequence != 0 &&
              job->completedReadSeq <
                  job->nativeBatchReleaseReadSequence)) &&
            !speculativeCommandUsed) {
            speculativeCommandUsed = true;
            progressed |= issue_reads_across_eop(
                job,
                gatherScatterStates[job->prioIndex],
                readIssueBudget,
                admission);
        }
#endif
        if (job->nativeBatchReleasePending) {
            if (job_failed(*job)) {
                if (!release_deferred_native_eop(*job, true)) {
                    AMPR_KLOGF("ampr.abort reason=apr.reactor.native.batch.deferred.release-failed-job file=%s line=%d", __FILE__, __LINE__);
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
                        AMPR_KLOGF("ampr.abort reason=apr.reactor.native.batch.lookahead.cursor.invalid file=%s line=%d", __FILE__, __LINE__);
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
                    AMPR_KLOGF("ampr.abort reason=apr.reactor.native.batch.deferred.cursor.invalid file=%s line=%d", __FILE__, __LINE__);
                    std::abort();
                }
                if (!job->nativeBatchReleaseAfterSoftwareAddress) {
                    const uint32_t completedOpBytes = job->nativeSubmitBytes;
                    if (!release_deferred_native_eop(*job, false)) {
                        AMPR_KLOGF("ampr.abort reason=apr.reactor.native.batch.deferred.cursor.invalid file=%s line=%d", __FILE__, __LINE__);
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
        if (job->sourceOffset != sourceOffsetAtEntry) {
            // Releasing a deferred EOP consumed this lane's one cursor command
            // for the current reactor cycle.
            maybe_release_reactor_job(job);
            return true;
        }
        GatherScatterState& gs = gatherScatterStates[job->prioIndex];
        bool continueReadBatch = false;
        while (job->sourceOffset < job->sourceBytes) {
            if (publish_deferred_cross_eop_error(*job)) {
                progressed = true;
                break;
            }
            if (native_batch_wait_pending(job->prioIndex)) {
                break;
            }
#if AMPR_EMU_APR_AIO_CROSS_EOP_READAHEAD
            if (skip_cross_eop_consumed_prefix(*job)) {
                progressed = true;
                break;
            }
#endif
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
                    set_command_error(
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

            // A byte-aware read quantum may span consecutive readFile packets,
            // but never crosses a non-read command in the same scheduler pass.
            // This makes 8 x <=64 KiB useful without pulling waits/EOP/native
            // side effects forward merely because read credit remains.
            if (continueReadBatch && !cb_op_is_apr_read(op.type)) {
                cache_decoded_op(*job, op, opBytes);
                break;
            }
            continueReadBatch = false;

            if (cb_op_is_apr_read(op.type)) {
#if AMPR_EMU_APR_AIO_CROSS_EOP_READAHEAD
                if (job->crossEopReadChain != nullptr &&
                    job->crossEopScanActive &&
                    job->sourceOffset == job->crossEopScanOffset) {
                    // The execution cursor caught a partially-issued
                    // speculative logical read. Continue that same chain;
                    // creating a cursor chain here would duplicate I/O.
                    progressed |= issue_reads_across_eop(job,
                                                         gs,
                                                         readIssueBudget,
                                                         admission);
                    if (job->crossEopReadChain != nullptr) {
                        cache_decoded_op(*job, op, opBytes);
                        break;
                    }
                    if (job_failed(*job)) {
                        break;
                    }
                    // Finishing the speculative chain advances only the scan
                    // cursor. Consume that completed read immediately, before
                    // the normal path can create a second cursor-owned chain
                    // for the same packed command.
                    if (!skip_cross_eop_consumed_prefix(*job)) {
                        AMPR_KLOGF("ampr.abort reason=apr.reactor.crossEop.caughtUp.consume.invalid file=%s line=%d", __FILE__, __LINE__);
                        std::abort();
                    }
                    progressed = true;
                    break;
                }
#endif
                SoftwareRead read{};
                const int readRc = resolve_software_read(gs, op, &read);
                if (readRc != 0) {
                    set_command_error(*job,
                                                     "software-read-state",
                                                     readRc,
                                                     op.bufOffsetBytes);
                    break;
                }
                bool logicalIssued = false;
                if (!issue_software_read(job,
                                         gs,
                                         read,
                                         opBytes,
                                         op.bufOffsetBytes,
                                         job->sourceCommandIndex,
                                         admission,
                                         true,
                                         false,
                                         &logicalIssued,
                                         &readIssueBudget)) {
                    if (!job_failed(*job)) {
                        cache_decoded_op(*job, op, opBytes);
                    }
                    break;
                }
                progressed = true;
                // Keep FIFO ownership, but let consecutive readFile packets use
                // the remaining bounded request/byte quantum. A non-read packet
                // stops the batch before it is executed, so waits/EOP/native
                // boundaries retain their previous pass-to-pass behavior.
                if (logicalIssued &&
                    readIssueBudget.requestsLeft != 0 &&
                    readIssueBudget.bytesLeft >=
                        static_cast<uint64_t>(AMPR_EMU_APR_READ_CREDIT_GRANULE_BYTES)) {
                    continueReadBatch = true;
                    continue;
                }
                break;
            }

            if (op.type == OpType::AprResetGatherScatter) {
                reset_software_gs_cursor(gs);
                advance_job_source(*job, opBytes);
                progressed = true;
                break;
            }
            if (software_op_is_marker_or_nop(op.type)) {
                advance_job_source(*job, opBytes);
                progressed = true;
                break;
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
                if ((priorReadFencePending ||
                     job->completedReadSeq < completionReadSequence ||
                     softwareCompletionOrderingPending) &&
                    !speculativeCommandUsed) {
                    speculativeCommandUsed = true;
                    progressed |= issue_reads_across_eop(job,
                                                         gs,
                                                         readIssueBudget,
                                                         admission);
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
                    set_command_error(*job,
                                                     "software-map-end-state",
                                                     SCE_KERNEL_ERROR_EINVAL,
                                                     op.bufOffsetBytes);
                    break;
                }
                job->mapActive = false;
                advance_job_source(*job, opBytes);
                progressed = true;
                break;
            }

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
                        AMPR_KLOGF("ampr.abort reason=apr.reactor.native.batch.lookahead.release.invalid file=%s line=%d", __FILE__, __LINE__);
                        std::abort();
                    }
                    const uint32_t stagedEventBytes =
                        job->nativeSubmitBytes;
                    if (!release_deferred_native_eop(*job, false)) {
                        AMPR_KLOGF("ampr.abort reason=apr.reactor.native.batch.lookahead.release.invalid file=%s line=%d", __FILE__, __LINE__);
                        std::abort();
                    }
                    advance_job_source(*job, stagedEventBytes);
                }
                progressed = true;
                break;
            }

            Op nativeOp = op;
            NativeMicroEngine engine = NativeMicroEngine::None;
            bool encodeFirst = false;
            if (op.type == OpType::AprMapBegin ||
                op.type == OpType::AprMapDirectBegin) {
                if (job->mapActive) {
                    set_command_error(*job,
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
                    set_command_error(*job,
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
                break;
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
        AioAdmissionContext admission{};
        JobPtr laneHeads[kPriorityCount]{};
        {
            AmprLockGuard lk(m);
            for (size_t lane = 0; lane < kPriorityCount; ++lane) {
                laneHeads[lane] = activePriorityHeads[lane];
            }
        }

        // A53-style front-end order: every new scheduler pass starts again at
        // the highest APR priority. A blocked lane never stops independent lower
        // priorities, but FIFO order inside one priority is preserved. Each lane
        // has a bounded host-AIO read-chunk quantum for its current logical read.
        for (size_t lane = 0; lane < kPriorityCount; ++lane) {
            begin_aio_admission_lane(admission);
            clear_cursor_read_wait_hint(lane);
            bool priorReadFencePending = false;
            bool priorNativeBatchPending = false;
            bool speculativeCommandUsed = false;
            ReadIssueBudget readIssueBudget{
                static_cast<uint32_t>(AMPR_EMU_APR_READ_CHUNK_QUANTUM),
                static_cast<uint64_t>(AMPR_EMU_APR_READ_PASS_MAX_BYTES)};
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
                                                        speculativeCommandUsed,
                                                        readIssueBudget,
                                                        admission);
                progressed |= jobProgressed;

                // FIFO ownership is decided from the cursor state AFTER this
                // job had its chance to run. If the head was blocked or only
                // partially admitted, it keeps the lane and later same-priority
                // jobs cannot leapfrog it. If it reached the end of its source,
                // however, the remaining request/byte budget may be consumed by
                // the next FIFO job during this same scheduler pass. This makes
                // bounded read admission a priority-lane property across submit
                // boundaries without changing ordering or completion fences.
                if (!job) {
                    // A synchronously released/failed head is deliberately a
                    // pass boundary. The next scheduler pass will observe the
                    // new head; do not infer successor safety after ownership
                    // has already been returned to the pool.
                    break;
                }
                if (job->sourceOffset != job->sourceBytes) {
                    break;
                }

                const bool nativeSubmitted =
                    job->nativeSubmitted.load(std::memory_order_acquire);
                if (!job_allows_priority_successor(*job, nativeSubmitted)) {
                    break;
                }
                priorReadFencePending |= job_has_outstanding_reads(*job);
                priorNativeBatchPending |=
                    nativeSubmitted &&
                    job->nativeMicroEngine == NativeMicroEngine::AprBatch;
                job = next;
            }
            if (!seal_open_native_apr_batch_group(
                    static_cast<uint32_t>(lane))) {
                AMPR_CRITICAL_LOGF("apr.reactor.native.batch.group.flush.fail lane=%u action=abort",
                                   static_cast<unsigned>(lane));
                AMPR_KLOGF("ampr.abort reason=apr.reactor.native.batch.group.flush.fail file=%s line=%d", __FILE__, __LINE__);
                std::abort();
            }
        }
        if (admission.initialized &&
            admission.snapshot.activeCount != activeReads.size()) {
            AMPR_KLOGF("ampr.abort reason=apr.reactor.aio.admission.context.drift file=%s line=%d", __FILE__, __LINE__);
            std::abort();
        }
        return progressed;
    }

    bool resubmit_deferred_active_reads() {
        constexpr SceKernelAioSubmitId kUnsetAioId =
            static_cast<SceKernelAioSubmitId>(-1);
        if (deferredActiveReadCount == 0) {
            return false;
        }
        bool progressed = false;
        const uint64_t nowNs = time_counter_now();
        for (auto it = activeReads.begin(); it != activeReads.end();) {
            ActiveRead& active = *it;
            if (!active.awaitingResubmit) {
                ++it;
                continue;
            }
            JobPtr job = active.job;
            ReadChain* const chain = active.chain;
            if (!job || !chain || job_failed(*job) ||
                cross_eop_suffix_is_canceled(*job, active.desc.errorOff)) {
                if (chain) {
                    chain->allIssued = true;
                }
                apr_release_aio_read_desc(active.desc);
                decrement_active_read_count(job);
                decrement_read_chain_active(chain, active.readCreditBytes);
                auto next = erase_active_read(it);
                maybe_finish_read_chain(chain);
                maybe_release_reactor_job(job);
                it = next;
                progressed = true;
                continue;
            }
            if (active.retryNotBeforeNs != 0 && nowNs < active.retryNotBeforeNs) {
                ++it;
                continue;
            }

            active.result = {};
            active.request.result = &active.result;
            ensure_aio_initialized();
            SceKernelAioSubmitId aioId = kUnsetAioId;
            const int submitRc = sceKernelAioSubmitReadCommands(
                &active.request,
                1,
                active.aioPrio,
                &aioId);
            const uint64_t submitTimeNs = time_counter_now();
            const int submitSceRc = apr_aio_api_rc_to_sce(submitRc);
            note_aio_submit_result(submitSceRc);
            if ((submitRc == 0 && aioId == kUnsetAioId) ||
                (submitRc != 0 && aioId != kUnsetAioId)) {
                AMPR_CRITICAL_LOGF("apr.reactor.aio.resubmit.single.inconsistent rc=0x%x aioId=%d prio=%d action=abort",
                                   submitSceRc,
                                   aioId,
                                   active.aioPrio);
                AMPR_KLOGF("ampr.abort reason=apr.reactor.aio.resubmit.single.inconsistent file=%s line=%d", __FILE__, __LINE__);
                std::abort();
            }
            if (submitRc == 0) {
                mark_active_read_submitted(active, aioId);
                active.submitTimeNs = submitTimeNs;
                active.retryNotBeforeNs = 0;
                active.aioDeleteRetries = 0;
                active.aioDeleteFirstFailureNs = 0;
                active.lastPollState = 0;
                active.lastPollRc = 0;
#if AMPR_EMU_DEBUG_LOG
                note_accepted_aio_request(active.desc.length, job->prioIndex);
#endif
                if (active_read_can_gate_publish(active)) {
                    reset_and_queue_hot_active_read_poll(active, submitTimeNs);
                } else {
                    reset_active_read_poll_backoff(active, submitTimeNs);
                }
                progressed = true;
                ++it;
                continue;
            }
            if (apr_aio_submit_sce_rc_is_deferred(submitSceRc)) {
                active.retryNotBeforeNs =
                    submitTimeNs + AMPR_EMU_APR_AIO_SUBMIT_RETRY_DELAY_NS;
                ++it;
                continue;
            }

            const uint32_t errorOff = active.desc.errorOff;
            set_or_defer_read_command_error(
                *job,
                "aio-resubmit",
                apr_backend_read_error_to_apr(submitSceRc),
                errorOff);
            chain->allIssued = true;
            apr_release_aio_read_desc(active.desc);
            decrement_active_read_count(job);
            decrement_read_chain_active(chain, active.readCreditBytes);
            auto next = erase_active_read(it);
            maybe_finish_read_chain(chain);
            maybe_release_reactor_job(job);
            it = next;
            progressed = true;
        }
        return progressed;
    }


    bool has_submitted_active_reads() const {
        return submittedActiveReadCount != 0;
    }

    uint64_t next_deferred_active_retry_wait_ns(uint64_t nowNs) const {
        if (deferredActiveReadCount == 0) {
            return static_cast<uint64_t>(active_lane_idle_sleep_ns());
        }
        uint64_t best = 0;
        for (const ActiveRead& active : activeReads) {
            if (!active.awaitingResubmit) {
                continue;
            }
            if (active.retryNotBeforeNs == 0 || active.retryNotBeforeNs <= nowNs) {
                return 1u;
            }
            const uint64_t waitNs = active.retryNotBeforeNs - nowNs;
            if (best == 0 || waitNs < best) {
                best = waitNs;
            }
        }
        return best != 0 ? best : static_cast<uint64_t>(active_lane_idle_sleep_ns());
    }
    void poll_active_aio_read(ActiveReadIt it, [[maybe_unused]] uint64_t pollNow, bool& completedAny) {
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
            } else if (!it->awaitingResubmit) {
                schedule_next_active_read_poll(*it, pollEndNs);
            }
        } else {
            schedule_next_active_read_poll(*it, pollEndNs);
        }
    }

    bool spin_poll_single_gating_read(size_t& pollCalls, bool& completedAny) {
        if (completedAny || activeReads.size() != 1u ||
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
            if (completedAny || activeReads.size() != 1u) {
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
        const auto handleDeleteFailure = [&]([[maybe_unused]] int failureRc) {
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
                AMPR_KLOGF("ampr.abort reason=apr.reactor.aio.delete.fatal file=%s line=%d", __FILE__, __LINE__);
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
            decrement_read_chain_active(chain, active.readCreditBytes);
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
            const uint32_t nextAmmEfaultRetries =
                completionEfault && active.ammEfaultRetries != UINT32_MAX
                    ? active.ammEfaultRetries + 1u
                    : active.ammEfaultRetries;
            if (completionEfault) {
                note_efault_retry_event();
            }
            active.ammEfaultRetries = nextAmmEfaultRetries;
            active.aioCompletionRetries = nextCompletionRetry;
            mark_active_read_deferred(active);
            active.retryNotBeforeNs = finishTimeNs + retryDelayNs;
            active.submitTimeNs = 0;
            active.result = {};
            active.request.result = &active.result;
            active.lastPollState = 0;
            active.lastPollRc = 0;
            active.gatingSpinPollsRemaining = 0;
            active.hotPollQueued = false;
            remove_poll_deadline(active);
            if (logCompletionRetry) {
                AMPR_CRITICAL_LOGF("apr.reactor.aio.complete.retry-direct job=0x%llx seq=0x%llx retry=%u ammRetry=%u delayNs=%llu rc=0x%x fileId=%u buf=%p len=0x%llx off=0x%llx activeReads=%zu",
                                   (unsigned long long)job->id,
                                   (unsigned long long)active.seq,
                                   nextCompletionRetry,
                                   nextAmmEfaultRetries,
                                   (unsigned long long)retryDelayNs,
                                   rc,
                                   active.desc.fileId,
                                   active.desc.buffer,
                                   (unsigned long long)active.desc.length,
                                   (unsigned long long)active.desc.offset,
                                   activeReads.size());
            }
            // Keep the same ActiveRead slot, fd borrow, chain reference and
            // sequence. The worker will resubmit it directly after retryAt.
            return true;
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
        decrement_read_chain_active(chain, active.readCreditBytes);
        maybe_finish_read_chain(chain);

        AMPR_TLOGF("apr.reactor.aio.complete job=0x%llx seq=0x%llx aioId=%d rc=0x%x state=0x%x return=0x%llx deleteRc=0x%x active=%u completedSeq=0x%llx",
                  (unsigned long long)job->id,
                  (unsigned long long)active.seq,
                  active.aioId,
                  rc,
                  state,
                  (unsigned long long)active.result.returnValue,
                  deleteResultSceRc,
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

    bool wait_aio_once(bool sleepWhenIdle) {
        if (activeReads.empty()) {
            return false;
        }
        return poll_active_aio_reads_once(sleepWhenIdle);
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
            AMPR_CRITICAL_LOGF("apr.reactor.stall activeJobs=%zu readChains=%u activeReads=%zu",
                               active_lane_count_locked(),
                               liveReadChainCount,
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
        const uint32_t effectiveAioLimit = aio_effective_read_limit(now);
        const bool smallReadBoost = effectiveAioLimit > aio_active_read_limit();
        const AmprIndexFdCacheDiagCounters fdCounters = ampr_index_fd_cache_diag_counters(reset);
        const uint64_t directEmfile = reset
            ? g_apr_direct_emfile_events.exchange(0, std::memory_order_relaxed)
            : g_apr_direct_emfile_events.load(std::memory_order_relaxed);
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

        AMPR_LOGF("apr.reactor.counters.latency reason=%s peakReadChains=%llu peakActive=%llu currentReadChains=%u currentActive=%zu maxAioAgeMs=%llu currentOldestAioAgeMs=%llu aioCompleteCount=%llu aioCompleteAvgUs=%llu aioCompleteMaxUs=%llu aioSubmitCompleteP95Us=%llu aioSubmitCompleteP99Us=%llu nativeTriggerSubmitCount=%llu nativeTriggerSubmitAvgUs=%llu nativeTriggerSubmitP95Us=%llu nativeTriggerSubmitP99Us=%llu nativeTriggerSubmitMaxUs=%llu completionReleaseCount=%llu completionReleaseAvgUs=%llu completionReleaseP95Us=%llu completionReleaseP99Us=%llu completionReleaseMaxUs=%llu counterWindowMs=%llu",
                  reason ? reason : "unknown",
                  (unsigned long long)runtimePeakReadChains,
                  (unsigned long long)runtimePeakActiveReads,
                  liveReadChainCount,
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
        AMPR_LOGF("apr.reactor.counters.admission reason=%s jobQueueFirstAioCount=%llu jobQueueFirstAioTotalUs=%llu jobQueueFirstAioAvgUs=%llu jobQueueFirstAioP95Us=%llu jobQueueFirstAioP99Us=%llu jobQueueFirstAioMaxUs=%llu readReadyAioCount=%llu readReadyAioTotalUs=%llu readReadyAioAvgUs=%llu readReadyAioP95Us=%llu readReadyAioP99Us=%llu readReadyAioMaxUs=%llu counterWindowMs=%llu",
                  reason ? reason : "unknown",
                  (unsigned long long)runtimeJobQueueToFirstAioLatency.count,
                  (unsigned long long)runtimeJobQueueToFirstAioLatency.totalUs,
                  (unsigned long long)latency_average_us(runtimeJobQueueToFirstAioLatency),
                  (unsigned long long)latency_percentile_us(runtimeJobQueueToFirstAioLatency, 95),
                  (unsigned long long)latency_percentile_us(runtimeJobQueueToFirstAioLatency, 99),
                  (unsigned long long)runtimeJobQueueToFirstAioLatency.maxUs,
                  (unsigned long long)runtimeReadReadyToAioLatency.count,
                  (unsigned long long)runtimeReadReadyToAioLatency.totalUs,
                  (unsigned long long)latency_average_us(runtimeReadReadyToAioLatency),
                  (unsigned long long)latency_percentile_us(runtimeReadReadyToAioLatency, 95),
                  (unsigned long long)latency_percentile_us(runtimeReadReadyToAioLatency, 99),
                  (unsigned long long)runtimeReadReadyToAioLatency.maxUs,
                  (unsigned long long)counterWindowMs);
        AMPR_LOGF("apr.reactor.counters.admission.stage reason=%s jobQueueFirstReadCount=%llu jobQueueFirstReadTotalUs=%llu jobQueueFirstReadP95Us=%llu jobQueueFirstReadP99Us=%llu jobQueueFirstReadMaxUs=%llu firstReadReadyFirstAioCount=%llu firstReadReadyFirstAioTotalUs=%llu firstReadReadyFirstAioP95Us=%llu firstReadReadyFirstAioP99Us=%llu firstReadReadyFirstAioMaxUs=%llu counterWindowMs=%llu",
                  reason ? reason : "unknown",
                  (unsigned long long)runtimeJobQueueToFirstReadLatency.count,
                  (unsigned long long)runtimeJobQueueToFirstReadLatency.totalUs,
                  (unsigned long long)latency_percentile_us(runtimeJobQueueToFirstReadLatency, 95),
                  (unsigned long long)latency_percentile_us(runtimeJobQueueToFirstReadLatency, 99),
                  (unsigned long long)runtimeJobQueueToFirstReadLatency.maxUs,
                  (unsigned long long)runtimeFirstReadReadyToFirstAioLatency.count,
                  (unsigned long long)runtimeFirstReadReadyToFirstAioLatency.totalUs,
                  (unsigned long long)latency_percentile_us(runtimeFirstReadReadyToFirstAioLatency, 95),
                  (unsigned long long)latency_percentile_us(runtimeFirstReadReadyToFirstAioLatency, 99),
                  (unsigned long long)runtimeFirstReadReadyToFirstAioLatency.maxUs,
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
                runtimeFirstReadReadyToFirstAioLatencyByPriority[priority];
            const LatencyHistogram& total =
                runtimeJobQueueToFirstAioLatencyByPriority[priority];
            const LatencyHistogram& pending =
                runtimeReadReadyToAioLatencyByPriority[priority];
            if (firstRead.count == 0 && firstSubmit.count == 0 &&
                total.count == 0 && pending.count == 0) {
                continue;
            }
            AMPR_LOGF("apr.reactor.counters.admission.prio.job reason=%s aprPrio=%zu jobQueueFirstReadCount=%llu jobQueueFirstReadTotalUs=%llu jobQueueFirstReadP95Us=%llu jobQueueFirstReadP99Us=%llu jobQueueFirstReadMaxUs=%llu firstReadReadyFirstAioCount=%llu firstReadReadyFirstAioTotalUs=%llu firstReadReadyFirstAioP95Us=%llu firstReadReadyFirstAioP99Us=%llu firstReadReadyFirstAioMaxUs=%llu jobQueueFirstAioCount=%llu jobQueueFirstAioTotalUs=%llu jobQueueFirstAioP95Us=%llu jobQueueFirstAioP99Us=%llu jobQueueFirstAioMaxUs=%llu counterWindowMs=%llu",
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
            AMPR_LOGF("apr.reactor.counters.admission.prio.read reason=%s aprPrio=%zu readReadyAioCount=%llu readReadyAioTotalUs=%llu readReadyAioP95Us=%llu readReadyAioP99Us=%llu readReadyAioMaxUs=%llu counterWindowMs=%llu",
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
        AMPR_LOGF("apr.reactor.counters.runtime reason=%s aioPollCalls=%llu aioPollBackoffSkips=%llu aioPollBudgetYields=%llu aioPollWorkNs=%llu aioPollSleepNs=%llu deadlineHeapPicks=%llu deadlineHeapFutureStops=%llu activeReadDuePolls=%llu activeReadNotDueSkips=%llu workerWakeups=%llu workerWakeupsPerSec=%llu idlePollPasses=%llu idlePollPassesPerSec=%llu emfile=%llu directEmfile=%llu efaultRetry=%llu efaultRetryLimit=%llu fdCacheHit=%llu fdCacheMiss=%llu fdCacheEmfile=%llu fdCacheMinFileBytes=%llu aioLimit=%u aioBaseLimit=%u aioMaxLimit=%u aioSmallBoost=%u aioThrottle=%u aioSlowCooldown=%u aioBoostCooldown=%u aioInitState=%u aioInitLastRc=0x%x aioInitAttempts=%llu aioInitOk=%llu aioInitBusy=%llu aioInitFail=%llu aioSubmitEagain=%llu",
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
                  (unsigned long long)AMPR_EMU_APR_FD_CACHE_MIN_FILE_BYTES,
                  (unsigned)effectiveAioLimit,
                  (unsigned)aio_active_read_limit(),
                  (unsigned)aio_small_read_limit(),
                  smallReadBoost ? 1u : 0u,
                  (unsigned)aioAgeThrottleLevel,
                  slow_aio_cooldown_active(now) ? 1u : 0u,
                  aio_small_read_boost_recovery_cooldown_active(now) ? 1u : 0u,
                  aioInitState.load(std::memory_order_relaxed),
                  aioInitLastRc.load(std::memory_order_relaxed),
                  (unsigned long long)aioInitAttemptCount.load(std::memory_order_relaxed),
                  (unsigned long long)aioInitSuccessCount.load(std::memory_order_relaxed),
                  (unsigned long long)aioInitBusyCount.load(std::memory_order_relaxed),
                  (unsigned long long)aioInitFailCount.load(std::memory_order_relaxed),
                  (unsigned long long)aioSubmitEagainCount.load(std::memory_order_relaxed));
        if (reset) {
            runtimePeakReadChains = liveReadChainCount;
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
                    runtimeFirstReadReadyToFirstAioLatencyByPriority[priority]);
                reset_latency_histogram(
                    runtimeJobQueueToFirstAioLatencyByPriority[priority]);
                reset_latency_histogram(
                    runtimeReadReadyToAioLatencyByPriority[priority]);
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
            reset_latency_histogram(runtimeFirstReadReadyToFirstAioLatency);
            reset_latency_histogram(runtimeJobQueueToFirstAioLatency);
            reset_latency_histogram(runtimeReadReadyToAioLatency);
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
        const uint32_t effectiveLimit = aio_effective_read_limit(now);
        const A53ReadGroupCounts groupActive = active_read_group_counts();
        const A53ReadGroupCounts groupTargets =
            read_group_targets(effectiveLimit, groupActive);
        const size_t groupU = read_group_index(A53ReadGroup::Urgent);
        const size_t groupH = read_group_index(A53ReadGroup::High);
        const size_t groupN = read_group_index(A53ReadGroup::Normal);

        AMPR_LOGF("apr.reactor.occupancy reason=%s activeJobs=%zu/%u readChains=%u/%u activeReads=%zu/%u aioBase=%u aioMax=%u aioThrottle=%u aioSlowCooldown=%u aioBoostCooldown=%u aioU=%u/%u aioH=%u/%u aioN=%u/%u readQuantumReq=%u readQuantumBytes=%u readActiveReqWindow=%u readActiveByteWindow=%u readCreditGranule=%u pollDeadlines=%u nativeMicroReady=%u fdEntries=%zu/%u fdOpen=%zu directOpen=%zu observedOpen=%zu fdBudget=%zu fdCacheCap=%zu fdDirectCap=%zu fdPinnedOpen=%zu fdPins=%zu fdEvictable=%zu fdPressure=%u",
                  tag,
                  active_lane_count_locked(),
                  (unsigned)kJobStatePoolCapacity,
                  liveReadChainCount,
                  (unsigned)kReadChainPoolCapacity,
                  activeReadCount,
                  (unsigned)effectiveLimit,
                  (unsigned)aio_active_read_limit(),
                  (unsigned)aio_small_read_limit(),
                  (unsigned)aioAgeThrottleLevel,
                  slow_aio_cooldown_active(now) ? 1u : 0u,
                  aio_small_read_boost_recovery_cooldown_active(now) ? 1u : 0u,
                  groupActive.values[groupU],
                  groupTargets.values[groupU],
                  groupActive.values[groupH],
                  groupTargets.values[groupH],
                  groupActive.values[groupN],
                  groupTargets.values[groupN],
                  (unsigned)AMPR_EMU_APR_READ_CHUNK_QUANTUM,
                  (unsigned)AMPR_EMU_APR_READ_PASS_MAX_BYTES,
                  (unsigned)AMPR_EMU_APR_PER_READ_ACTIVE_CHUNKS,
                  (unsigned)AMPR_EMU_APR_PER_READ_ACTIVE_BYTES,
                  (unsigned)AMPR_EMU_APR_READ_CREDIT_GRANULE_BYTES,
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
                  fdPressure ? 1u : 0u);
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
        uint32_t firstJobCursorRead = 0;
        uint32_t firstJobSpeculativeRead = 0;
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
            firstJobCursorRead = job.cursorReadChain != nullptr ? 1u : 0u;
#if AMPR_EMU_APR_AIO_CROSS_EOP_READAHEAD
            firstJobSpeculativeRead = job.crossEopReadChain != nullptr ? 1u : 0u;
#endif
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
        for (const ActiveRead& active : activeReads) {
            if (active.awaitingResubmit || active.aioId < 0) {
                continue;
            }
            firstAioId = active.aioId;
            firstAioJob = active.job ? active.job->id : 0;
            firstAioSeq = active.seq;
            firstAioFileId = active.desc.fileId;
            firstAioLen = active.desc.length;
            firstAioOff = active.desc.offset;
            firstAioAgeMs = active.submitTimeNs != 0 && now >= active.submitTimeNs
                                ? (now - active.submitTimeNs) / 1000000ull
                                : 0;
            break;
        }

        AMPR_LOGF("apr.reactor.state reason=%s activeJobs=%zu readChains=%u activeReads=%zu firstJob=0x%llx opIndex=%zu commands=%u op=%s jobCursorRead=%u jobSpeculativeRead=%u jobActive=%u jobFailed=%u firstAioId=%d firstAioAgeMs=%llu firstAioJob=0x%llx firstAioSeq=0x%llx firstAioFileId=%u firstAioLen=0x%llx firstAioOff=0x%llx",
                  reason ? reason : "unknown",
                  active_lane_count_locked(),
                  liveReadChainCount,
                  activeReads.size(),
                  (unsigned long long)firstJobId,
                  firstJobOpIndex,
                  firstJobCommands,
                  firstJobOp,
                  firstJobCursorRead,
                  firstJobSpeculativeRead,
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
            has_active_lanes_locked() || !activeReads.empty();
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
                AMPR_KLOGF("ampr.abort reason=apr.reactor.native.batch.snapshot.invalid file=%s line=%d", __FILE__, __LINE__);
                std::abort();
            }
            state.observedProgress =
                __atomic_load_n(apr_native_batch_progress_ptr(*slot), __ATOMIC_ACQUIRE);
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
                AMPR_KLOGF("ampr.abort reason=apr.reactor.native.batch.snapshot.token.invalid file=%s line=%d", __FILE__, __LINE__);
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
                AMPR_KLOGF("ampr.abort reason=apr.reactor.native.batch.snapshot.ahead file=%s line=%d", __FILE__, __LINE__);
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
                AMPR_KLOGF("ampr.abort reason=apr.reactor.native.batch.active.invalid file=%s line=%d", __FILE__, __LINE__);
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
                AMPR_KLOGF("ampr.abort reason=apr.reactor.native.batch.count.invalid file=%s line=%d", __FILE__, __LINE__);
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
                    AMPR_KLOGF("ampr.abort reason=apr.reactor.native.batch.wait.fail file=%s line=%d", __FILE__, __LINE__);
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
                    AMPR_KLOGF("ampr.abort reason=apr.reactor.native.batch.result.fail file=%s line=%d", __FILE__, __LINE__);
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
                        AMPR_KLOGF("ampr.abort reason=apr.reactor.native.batch.rollover-submit.fail file=%s line=%d", __FILE__, __LINE__);
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
                                       apr_native_batch_release_ptr(*slot),
                                       __ATOMIC_RELAXED));
                AMPR_KLOGF("ampr.abort reason=apr.reactor.native.batch.fatal-without-checkpoint file=%s line=%d", __FILE__, __LINE__);
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
                                       apr_native_batch_release_ptr(*slot),
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
                AMPR_KLOGF("ampr.abort reason=apr.reactor.native.batch.job.invalid file=%s line=%d", __FILE__, __LINE__);
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
                            AMPR_KLOGF("ampr.abort reason=apr.reactor.native.batch.checkpoint.slot-null file=%s line=%d", __FILE__, __LINE__);
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
                            AMPR_KLOGF("ampr.abort reason=apr.reactor.native.batch.checkpoint.fatal file=%s line=%d", __FILE__, __LINE__);
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
        if (job_has_outstanding_reads(*job)) {
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
                                    activeReads.empty();
            maybe_release_stale_fds(waitIfIdle);
            drain_incoming(waitIfIdle);
            workerObservedWakeEpoch =
                reactorWakeEpoch.load(std::memory_order_acquire);
            {
                AmprLockGuard lk(m);
                if (stop) {
                    return;
                }
            }

            bool progressed = false;
            if (shuttingDown && !prepare_native_batches_for_shutdown()) {
                AMPR_CRITICAL_LOGF("apr.reactor.shutdown.native-drain.fail action=abort");
                AMPR_KLOGF("ampr.abort reason=apr.reactor.shutdown.native-drain.fail file=%s line=%d", __FILE__, __LINE__);
                std::abort();
            }

            // One reactor tick owns exactly one cursor pass over all priority
            // lanes. Retry resubmission and completion polling are AIO state
            // maintenance and never create a second read-admission scheduler.
            progressed |= resubmit_deferred_active_reads();
            refresh_native_batch_progress_snapshots();
            progressed |= progress_native_batches();
            progressed |= progress_all_jobs();

            if (shuttingDown && native_batches_idle()) {
                AmprLockGuard lk(m);
                stop = true;
                return;
            }

            if (has_submitted_active_reads()) {
                // Do not let an AIO poll deadline insert a sleep between two
                // productive command-cursor passes. If this reactor tick
                // already advanced retry/native/job state, poll submitted AIO
                // non-blocking and immediately give the priority lanes their
                // next cursor opportunity. Timed AIO sleep is only allowed
                // when the reactor made no useful progress in this tick.
                const bool madeProgressBeforeAioPoll = progressed;
                progressed |= wait_aio_once(!madeProgressBeforeAioPoll);
                note_reactor_progress(progressed);
                continue;
            }

            if (!activeReads.empty()) {
                // Every active slot is waiting for a retry deadline. Keep the
                // slot reserved, but sleep until the nearest retry (or a new
                // job/wake event) instead of spinning the reactor.
                note_reactor_progress(progressed);
                if (!progressed) {
                    wait_for_reactor_wake(
                        workerObservedWakeEpoch,
                        next_deferred_active_retry_wait_ns(time_counter_now()));
#if AMPR_EMU_DEBUG_LOG
                    note_worker_wakeup();
#endif
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
    GatherScatterState gatherScatterStates[kPriorityCount]{};
    std::atomic<size_t> activeJobCountAtomic{0};
    std::atomic<uint32_t> jobStatePoolLock{0};
    JobStateSlot jobStateSlots[kJobStatePoolCapacity]{};
    uint32_t jobStateFreeHead{UINT32_MAX};
    ReadChainSlot readChainSlots[kReadChainPoolCapacity]{};
    uint32_t readChainFreeHead{UINT32_MAX};
    uint32_t liveReadChainCount{};
    ActiveReadList activeReads;
    uint32_t submittedActiveReadCount{};
    uint32_t deferredActiveReadCount{};
    CursorReadWaitHint cursorReadWaitHints[kPriorityCount]{};
    AioAgeThrottleLevel aioAgeThrottleLevel{AioAgeThrottleLevel::Normal};
    uint64_t aioSmallReadBoostBlockedUntilNs{0};
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
    uint64_t runtimePeakReadChains{0};
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
    LatencyHistogram runtimeFirstReadReadyToFirstAioLatency{};
    LatencyHistogram runtimeJobQueueToFirstAioLatency{};
    LatencyHistogram runtimeReadReadyToAioLatency{};
    LatencyHistogram runtimeJobQueueToFirstReadLatencyByPriority[kPriorityCount]{};
    LatencyHistogram runtimeFirstReadReadyToFirstAioLatencyByPriority[kPriorityCount]{};
    LatencyHistogram runtimeJobQueueToFirstAioLatencyByPriority[kPriorityCount]{};
    LatencyHistogram runtimeReadReadyToAioLatencyByPriority[kPriorityCount]{};
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
    mutable bool fdCachePressureCapApplied{false};
    mutable uint64_t fdCacheOpenPressureSeen{0};
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

int apr_reactor_submit(const Job& j, SceAprSubmitId* outSubmitId) {
    return apr_aio_reactor().submit(j, outSubmitId);
}
