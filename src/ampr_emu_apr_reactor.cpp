/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Software APR scheduler and SDK AIO reactor. It advances the retained source
 * stream in priority order, splits reads at dispatch, and issues only bounded
 * native APR/AMM micro-submits for hardware-owned operations.
 */

#include "ampr_emu_apr_reactor.h"
#include "ampr_emu_apr_equeue.h"
#include "ampr_emu_apr_reactor_common.h"
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
static constexpr uint32_t kAprNativeMicroAmmPriority = 0u;
static constexpr int kAprNativeMicroResultPending = INT32_MIN;

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
    SceAprResultBuffer result{};
};
static constexpr size_t kAprNativeMicroRawBytes =
    sizeof(AprNativeMicroSlot) * kAprCommandBufferLiveMax;
static constexpr size_t kAprNativeMicroPoolBytes =
    ((kAprNativeMicroRawBytes + SCE_KERNEL_PAGE_SIZE - 1u) /
     SCE_KERNEL_PAGE_SIZE) * SCE_KERNEL_PAGE_SIZE;
alignas(SCE_KERNEL_PAGE_SIZE) static uint8_t
    g_apr_native_micro_pool[kAprNativeMicroPoolBytes];

#if AMPR_EMU_APR_EAGER_NATIVE_EQUEUE
// Eager native APR sidecars are fully populated before submission. Each live
// eager job reserves only its encoded bytes from one native-visible circular
// arena. Every APR priority owns one release word; monotonic tokens let one release store
// open a FIFO prefix spanning several public submits. Per-packet checkpoints
// preserve ordering against following software/AMM work and make completion
// observable without scanning command storage.
static constexpr uint32_t kAprNativeEventGateBytes = 16u;
static constexpr uint32_t kAprNativeEventPacketMaxBytes = 20u;
static constexpr uint32_t kAprNativeEventCheckpointBytes = 16u;
static constexpr uint64_t kAprNativeEventTokenBase = 0x4150524500000000ull;
static constexpr int kAprNativeEventResultPending = INT32_MIN;
static constexpr uint32_t kAprNativeEventMaxPerJob =
    static_cast<uint32_t>(AMPR_EMU_APR_EAGER_NATIVE_EQUEUE_MAX_EVENTS);
static constexpr uint32_t kAprNativeEventArenaBytes =
    static_cast<uint32_t>(AMPR_EMU_APR_EAGER_NATIVE_EQUEUE_ARENA_BYTES);
static constexpr uint32_t kAprNativeEventArenaAlignment = 64u;
static constexpr uint32_t kAprNativeEventArenaAllocationCount =
    static_cast<uint32_t>(kAprCommandBufferLiveMax);
static_assert(kAprNativeEventMaxPerJob != 0,
              "eager native APR sidecar must hold at least one record");
static_assert(kAprNativeEventArenaBytes >= SCE_KERNEL_PAGE_SIZE &&
                  kAprNativeEventArenaBytes % SCE_KERNEL_PAGE_SIZE == 0,
              "eager native APR arena must be page aligned and non-empty");
static_assert((kAprNativeEventArenaAlignment &
               (kAprNativeEventArenaAlignment - 1u)) == 0,
              "eager native APR arena alignment must be a power of two");
static_assert(kAprNativeEventArenaAllocationCount != 0,
              "eager native APR arena needs allocation descriptors");

struct AprNativeEventArenaPlacement {
    uint32_t offset{UINT32_MAX};
    uint32_t reservedBytes{};
};

static constexpr AprNativeEventArenaPlacement
apr_native_event_arena_placement(uint32_t capacity,
                                 uint32_t readOffset,
                                 uint32_t writeOffset,
                                 uint32_t usedBytes,
                                 uint32_t requestBytes) {
    AprNativeEventArenaPlacement placement{};
    if (capacity == 0 || readOffset >= capacity || writeOffset >= capacity ||
        usedBytes > capacity || requestBytes == 0 ||
        requestBytes > capacity - usedBytes) {
        return placement;
    }
    if (writeOffset >= readOffset) {
        const uint32_t tailBytes = capacity - writeOffset;
        if (requestBytes <= tailBytes) {
            placement.offset = writeOffset;
            placement.reservedBytes = requestBytes;
        } else if (requestBytes <= readOffset &&
                   tailBytes <= capacity - usedBytes - requestBytes) {
            placement.offset = 0;
            placement.reservedBytes = tailBytes + requestBytes;
        }
    } else if (requestBytes <= readOffset - writeOffset) {
        placement.offset = writeOffset;
        placement.reservedBytes = requestBytes;
    }
    return placement;
}

static_assert(apr_native_event_arena_placement(1024, 0, 0, 0, 64).offset == 0);
static_assert(apr_native_event_arena_placement(1024, 320, 896, 576, 256).offset == 0);
static_assert(apr_native_event_arena_placement(1024, 320, 896, 576, 256).reservedBytes == 384);
static_assert(apr_native_event_arena_placement(1024, 768, 128, 384, 256).offset == 128);
static_assert(apr_native_event_arena_placement(1024, 128, 896, 768, 192).offset == UINT32_MAX);

struct alignas(8) AprNativeEventResultSlot {
    SceAprResultBuffer result{};
};

alignas(SCE_KERNEL_PAGE_SIZE) static uint8_t
    g_apr_native_event_arena[kAprNativeEventArenaBytes];
static constexpr size_t kAprNativeEventResultRawBytes =
    sizeof(AprNativeEventResultSlot) * kAprCommandBufferLiveMax;
static constexpr size_t kAprNativeEventResultPoolBytes =
    ((kAprNativeEventResultRawBytes + SCE_KERNEL_PAGE_SIZE - 1u) /
     SCE_KERNEL_PAGE_SIZE) * SCE_KERNEL_PAGE_SIZE;
alignas(SCE_KERNEL_PAGE_SIZE) static uint8_t
    g_apr_native_event_result_pool[kAprNativeEventResultPoolBytes];

static constexpr size_t kAprNativeEventLaneReleaseStride =
    kAprNativeMicroSlotAlignment;
static constexpr size_t kAprNativeEventControlRawBytes =
    kAprPriorityArrayCount * kAprNativeEventLaneReleaseStride;
static constexpr size_t kAprNativeEventControlPoolBytes =
    ((kAprNativeEventControlRawBytes + SCE_KERNEL_PAGE_SIZE - 1u) /
     SCE_KERNEL_PAGE_SIZE) * SCE_KERNEL_PAGE_SIZE;
alignas(SCE_KERNEL_PAGE_SIZE) static uint8_t
    g_apr_native_event_control_pool[kAprNativeEventControlPoolBytes];

static volatile uint64_t* apr_native_event_lane_release_ptr(size_t lane) {
    if (lane >= kAprPriorityArrayCount) {
        return nullptr;
    }
    return reinterpret_cast<volatile uint64_t*>(
        g_apr_native_event_control_pool +
        lane * kAprNativeEventLaneReleaseStride);
}

static SceAprResultBuffer* apr_native_event_result(size_t slot) {
    if (slot >= kAprCommandBufferLiveMax) {
        return nullptr;
    }
    return &(
        reinterpret_cast<AprNativeEventResultSlot*>(
            g_apr_native_event_result_pool) + slot)->result;
}
#endif

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

static bool apr_fd_acquire_sce_rc_is_deferred(int rc) {
    return rc == SCE_KERNEL_ERROR_EAGAIN ||
           rc == SCE_KERNEL_ERROR_EMFILE ||
           rc == SCE_KERNEL_ERROR_ENFILE;
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

static bool apr_backend_read_error_is_missing_path(int rc) {
    return rc == SCE_KERNEL_ERROR_ENOENT ||
           rc == SCE_KERNEL_ERROR_ENOTDIR;
}

static const char* apr_backend_read_error_reason(const char* fallback, int rc) {
    return apr_backend_read_error_is_missing_path(rc)
               ? "indexed-path-missing"
               : fallback;
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

static constexpr bool apr_read_is_single_quantum_full_file(uint64_t offset,
                                                          uint64_t length,
                                                          uint64_t fileSize) {
    return fileSize != 0 &&
           offset == 0 &&
           length == fileSize &&
           fileSize <= static_cast<uint64_t>(AMPR_EMU_APR_AIO_DISPATCH_QUANTUM_BYTES);
}

static_assert(apr_read_is_single_quantum_full_file(
                  0, AMPR_EMU_APR_AIO_DISPATCH_QUANTUM_BYTES,
                  AMPR_EMU_APR_AIO_DISPATCH_QUANTUM_BYTES),
              "a full single-quantum file must use the direct FD path");
static_assert(!apr_read_is_single_quantum_full_file(
                  0, static_cast<uint64_t>(AMPR_EMU_APR_AIO_DISPATCH_QUANTUM_BYTES) + 1u,
                  static_cast<uint64_t>(AMPR_EMU_APR_AIO_DISPATCH_QUANTUM_BYTES) + 1u),
              "a full multi-quantum file must use the FD cache");
static_assert(!apr_read_is_single_quantum_full_file(
                  0, AMPR_EMU_APR_AIO_DISPATCH_QUANTUM_BYTES / 2u,
                  AMPR_EMU_APR_AIO_DISPATCH_QUANTUM_BYTES),
              "a partial file read must use the FD cache");

static size_t apr_adaptive_direct_fd_cap(const AmprIndexFdPressureCaps& caps,
                                          uint32_t aioLimit,
                                          bool fdPressure) {
    const size_t budget = caps.fdBudget;
    if (budget == 0 || aioLimit == 0) {
        return 0;
    }

    const size_t reserve = static_cast<size_t>(AMPR_EMU_FD_DIRECT_CAP_RESERVE);
    size_t cap = 1;
    if (budget > reserve) {
        cap = budget - reserve;
    }

    if (cap > static_cast<size_t>(aioLimit)) {
        cap = static_cast<size_t>(aioLimit);
    }

    if (fdPressure) {
        size_t pressureShare =
            (budget * static_cast<size_t>(AMPR_EMU_FD_DIRECT_CAP_PRESSURE_PERCENT)) / 100u;
        if (pressureShare == 0) {
            pressureShare = 1;
        }
        if (cap > pressureShare) {
            cap = pressureShare;
        }
    }

    return cap;
}

static void apr_update_read_desc_fd_policy(AprAioReadDesc& rd) {
    if (!rd.fileMetadataValid) {
        return;
    }
    rd.bypassFdCache = apr_read_is_single_quantum_full_file(
        rd.offset, rd.length, static_cast<uint64_t>(rd.fileSize));
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
                                      size_t directOpenCap,
                                      int* outRc,
                                      uint32_t* outErrorOffset) {
    if (outRc) *outRc = 0;
    if (outErrorOffset) *outErrorOffset = rd.errorOff;
    if (rd.fd >= 0) {
        return true;
    }

    if (rd.bypassFdCache) {
        FileEntryView directEntry{};
        const bool haveDirectEntry = apr_read_desc_entry(rd, &directEntry);
        if (!allowNewFd) {
            if (outRc) *outRc = SCE_KERNEL_ERROR_EAGAIN;
            AMPR_TLOGF("apr.reactor.acquire.direct.defer job=0x%llx fileId=%u reason=new-fd-blocked",
                      (unsigned long long)jobId,
                      rd.fileId);
            return false;
        }
        [[maybe_unused]] constexpr const char* directMode =
            "single-quantum-full-file-direct";
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
        const AmprIndexFdPressureCaps fdCaps = ampr_index_fd_pressure_current_caps();
        const size_t directOpen = ampr_index_fd_direct_open_count();
        if (directOpenCap != 0 && directOpen + 1u > directOpenCap) {
            if (outRc) *outRc = SCE_KERNEL_ERROR_EAGAIN;
            AMPR_TLOGF("apr.reactor.acquire.direct.defer job=0x%llx fileId=%u reason=direct-cap directOpen=%zu directCap=%zu fdBudget=%zu",
                      (unsigned long long)jobId,
                      rd.fileId,
                      directOpen,
                      directOpenCap,
                      fdCaps.fdBudget);
            return false;
        }
        const size_t requestedReserve =
            1u + static_cast<size_t>(AMPR_EMU_FD_DIRECT_OPEN_SAFETY_RESERVE);
        const size_t openReserve =
            requestedReserve < fdCaps.fdBudget ? requestedReserve : fdCaps.fdBudget;

        // Fast path: do not proactively evict cached descriptors merely because
        // the combined FD population crossed a watermark. Most direct opens are
        // admitted while real budget headroom still exists, so one snapshot is
        // enough and no sceKernelClose() is issued. Only reclaim cache entries
        // when the requested reserve would actually exceed the effective budget.
        const AmprIndexFdCacheStats preOpenStats = ampr_index_fd_cache_stats();
        const size_t observedOpen = preOpenStats.open + directOpen;
        const bool hasBudgetHeadroom =
            observedOpen <= fdCaps.fdBudget &&
            openReserve <= fdCaps.fdBudget - observedOpen;
        if (!hasBudgetHeadroom &&
            !ampr_index_fd_cache_release_open_fd_budget_headroom(openReserve)) {
            if (outRc) *outRc = SCE_KERNEL_ERROR_EAGAIN;
            AMPR_TLOGF("apr.reactor.acquire.direct.defer job=0x%llx fileId=%u reason=fd-budget-headroom directOpen=%zu directCap=%zu observedOpen=%zu reserve=%zu fdBudget=%zu evictable=%zu",
                      (unsigned long long)jobId,
                      rd.fileId,
                      directOpen,
                      directOpenCap,
                      observedOpen,
                      openReserve,
                      fdCaps.fdBudget,
                      preOpenStats.evictable);
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
        // ampr_real_sceKernelOpen() calls the real libkernel slot directly, so
        // failures remain in the SCE_KERNEL_ERROR_* domain. Keep rawRc intact for
        // diagnostics and derive POSIX errno only for local classification.
        const int openErrno = fd < 0 ? ampr_posix_errno_from_sce(fd) : 0;
        const bool openPressure =
            fd < 0 && ampr_posix_errno_is_fd_open_pressure(openErrno);
        AMPR_TLOGF("apr.reactor.acquire.direct.leave job=0x%llx fileId=%u mode=%s fd=%d rawRc=0x%x errno=%d pressure=%u",
                  (unsigned long long)jobId,
                  rd.fileId,
                  directMode,
                  fd,
                  fd,
                  openErrno,
                  openPressure ? 1u : 0u);
        if (openPressure) {
#if AMPR_EMU_DEBUG_LOG
            if (openErrno == EMFILE) {
                g_apr_direct_emfile_events.fetch_add(1, std::memory_order_relaxed);
            }
#endif
            const AmprIndexFdCacheStats beforeStats = ampr_index_fd_cache_stats();
            const size_t observedOpen = beforeStats.open + ampr_index_fd_direct_open_count();
            const AmprIndexFdPressureCaps pressureCaps = ampr_index_fd_cache_mark_open_pressure(observedOpen);
            const size_t closedIdle = ampr_index_fd_cache_release_idle_percent(
                AMPR_EMU_FD_CACHE_OPEN_PRESSURE_IDLE_CLOSE_PERCENT);
            const AmprIndexFdCacheStats afterStats = ampr_index_fd_cache_stats();
            (void)pressureCaps;
            (void)closedIdle;
            (void)afterStats;
            AMPR_LOGF("apr.reactor.acquire.direct.defer-pressure job=0x%llx fileId=%u path=%s mode=%s rawRc=0x%x errno=%d observedOpen=%zu fdBudget=%zu cacheCap=%zu closedIdle=%zu cacheBefore=%zu/%zu directBefore=%zu pinned=%zu pins=%zu evictable=%zu cacheAfter=%zu/%zu directAfter=%zu pinnedAfter=%zu pinsAfter=%zu evictableAfter=%zu",
                      (unsigned long long)jobId,
                      rd.fileId,
                      ampr_log_path_arg(directEntry.path),
                      directMode,
                      fd,
                      openErrno,
                      observedOpen,
                      pressureCaps.fdBudget,
                      pressureCaps.cacheCap,
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
            if (outRc) {
                *outRc = ampr_sce_errno_from_posix(openErrno);
            }
            if (!openPressure) {
                AMPR_CRITICAL_LOGF("apr.reactor.acquire.fail status=failed job=0x%llx reason=open-direct fileId=%u path=%s mode=%s rawRc=0x%x errno=%d rc=0x%x",
                          (unsigned long long)jobId,
                          rd.fileId,
                          ampr_log_path_arg(directEntry.path),
                          directMode,
                          fd,
                          openErrno,
                          outRc ? *outRc : 0);
            }
            AMPR_FILE_STATUS_LOGF("apr.file.open status=%s reason=direct job=0x%llx fileId=%u path=%s mode=%s rawRc=0x%x errno=%d rc=0x%x",
                                  openPressure ? "deferred" : "failed",
                                  (unsigned long long)jobId,
                                  rd.fileId,
                                  ampr_log_path_arg(directEntry.path),
                                  directMode,
                                  fd,
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
        const bool deferred =
            fd == -EAGAIN || fd == -EMFILE || fd == -ENFILE;
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

        JobPtr job = nullptr;
        bool waitedForJobState = false;
        for (;;) {
            job = allocate_job_state();
            if (job) {
                break;
            }
            AmprUniqueLock lk(m);
            if (stop || shutdownRequested.load(std::memory_order_acquire)) {
                return SCE_KERNEL_ERROR_ECANCELED;
            }
            if (!waitedForJobState) {
                AMPR_VLOGF(
                    "apr.reactor.job.pool.wait capacity=%u",
                    (unsigned)kJobStatePoolCapacity);
                waitedForJobState = true;
            }
            jobStateWaiterCount.fetch_add(1u, std::memory_order_release);
            jobStateAvailableCv.wait(lk, [&] {
                return stop || shutdownRequested.load(std::memory_order_acquire) ||
                       jobStateFreeCount.load(std::memory_order_acquire) != 0;
            });
            jobStateWaiterCount.fetch_sub(1u, std::memory_order_release);
            if (stop || shutdownRequested.load(std::memory_order_acquire)) {
                return SCE_KERNEL_ERROR_ECANCELED;
            }
        }
        if (waitedForJobState) {
            AMPR_VLOGF("apr.reactor.job.pool.resumed slot=%u",
                       (unsigned)job->poolSlot);
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
#if AMPR_EMU_APR_EAGER_NATIVE_EQUEUE
        const int eagerPlanRc = analyze_eager_native_event_plan(*job);
        if (eagerPlanRc != 0) {
            AMPR_VLOGF("apr.reactor.native.fifo.plan.reject job=0x%llx lane=%u commands=%u rc=0x%x maxRecords=%u",
                       (unsigned long long)job->id,
                       (unsigned)job->prioIndex,
                       (unsigned)job->commandCount,
                       eagerPlanRc,
                       (unsigned)kAprNativeEventMaxPerJob);
            release_job_state(job);
            return eagerPlanRc;
        }
#endif
        if (!start_worker()) {
            release_job_state(job);
            return SCE_KERNEL_ERROR_ENOMEM;
        }
#if AMPR_EMU_APR_EAGER_NATIVE_EQUEUE
        if (!allocate_eager_native_event_arena(*job)) {
            release_job_state(job);
            return SCE_KERNEL_ERROR_ECANCELED;
        }
#endif
        [[maybe_unused]] const uint32_t jobSlot = job->poolSlot;
        [[maybe_unused]] const uint8_t laneIndex = job->prioIndex;
#if AMPR_EMU_APR_EAGER_NATIVE_EQUEUE
        AmprLockGuard eagerSubmitGuard(eagerNativeSubmitMutex[laneIndex]);
#endif
        {
            AmprUniqueLock lk(m);
            if (stop || shutdownRequested.load(std::memory_order_acquire)) {
                lk.unlock();
                release_job_state(job);
                return SCE_KERNEL_ERROR_ECANCELED;
            }
            SceAprSubmitId syntheticId = 0;
            if (outSubmitId) {
                // Account only live work here. An unclaimed completion releases
                // this record and retains its exact-id result in bounded history,
                // so titles that retire completed buffers through their own EOP
                // word do not exhaust the 4096 live-request pool.
                bool waitedForSyntheticRequest = false;
                while (!reserve_synthetic_wait_slot_locked(*job)) {
                    if (stop || shutdownRequested.load(std::memory_order_acquire)) {
                        release_unpublished_synthetic_wait_slot_locked(*job);
                        lk.unlock();
                        release_job_state(job);
                        return SCE_KERNEL_ERROR_ECANCELED;
                    }
                    if (!waitedForSyntheticRequest) {
                        AMPR_VLOGF(
                            "apr.reactor.synthetic.request.pool.wait job=0x%llx capacity=%u",
                            (unsigned long long)job->id,
                            (unsigned)kSyntheticRequestCapacity);
                        waitedForSyntheticRequest = true;
                    }
                    syntheticRequestAvailableCv.wait(lk);
                }
                if (waitedForSyntheticRequest) {
                    AMPR_VLOGF(
                        "apr.reactor.synthetic.request.pool.resumed job=0x%llx requestSlot=%u",
                        (unsigned long long)job->id,
                        (unsigned)job->syntheticWaitSlot);
                }

                // The lower submit-id descriptor is a separate, shorter-lived
                // resource. It is released on completion and advances generation.
                bool waitedForSyntheticLowerSlot = false;
                while (!allocate_synthetic_lower_slot_locked(*job, &syntheticId)) {
                    if (stop || shutdownRequested.load(std::memory_order_acquire)) {
                        release_unpublished_synthetic_wait_slot_locked(*job);
                        lk.unlock();
                        release_job_state(job);
                        return SCE_KERNEL_ERROR_ECANCELED;
                    }
                    if (!waitedForSyntheticLowerSlot) {
                        AMPR_VLOGF(
                            "apr.reactor.synthetic.lower.pool.wait job=0x%llx capacity=%u",
                            (unsigned long long)job->id,
                            (unsigned)kSyntheticLowerSlotCapacity);
                        waitedForSyntheticLowerSlot = true;
                    }
                    syntheticLowerSlotAvailableCv.wait(lk);
                }
                if (waitedForSyntheticLowerSlot) {
                    AMPR_VLOGF(
                        "apr.reactor.synthetic.lower.pool.resumed job=0x%llx id=0x%x lowerSlot=%u generation=%u",
                        (unsigned long long)job->id,
                        (unsigned)syntheticId,
                        (unsigned)job->syntheticLowerSlot,
                        (unsigned)job->syntheticLowerGeneration);
                }
            }
#if AMPR_EMU_APR_EAGER_NATIVE_EQUEUE
            if (job->eagerNativeEventPlan) {
                job->eagerNativeEventPreparePending.store(
                    true, std::memory_order_release);
            }
#endif
            if (!add_active_job_locked(job)) {
#if AMPR_EMU_APR_EAGER_NATIVE_EQUEUE
                job->eagerNativeEventPreparePending.store(
                    false, std::memory_order_relaxed);
#endif
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
        }

#if AMPR_EMU_APR_EAGER_NATIVE_EQUEUE
        if (job->eagerNativeEventPlan) {
            const bool eagerSubmitted = submit_eager_native_event_sidecar(*job);
            {
                AmprLockGuard lk(m);
                if (eagerSubmitted) {
                    link_eager_native_event_job_locked(*job);
                } else {
                    // Never mix this lane with the persistent native batch. A
                    // failed native FIFO submit is a job error; source bytes stay
                    // untouched and no packet is replayed through another engine.
                    job->eagerNativeEventPlan = false;
                    set_fail(*job,
                             "native-fifo-submit",
                             SCE_KERNEL_ERROR_EIO,
                             job->sourceOffset);
                }
                job->eagerNativeEventPreparePending.store(
                    false, std::memory_order_release);
                reactorWakeEpoch.fetch_add(1u, std::memory_order_release);
            }
        } else {
            AmprLockGuard lk(m);
            reactorWakeEpoch.fetch_add(1u, std::memory_order_release);
        }
#else
        {
            AmprLockGuard lk(m);
            reactorWakeEpoch.fetch_add(1u, std::memory_order_release);
        }
#endif
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
        uint32_t lowerSlot = 0;
        uint32_t generation = 0;
        if (!decode_synthetic_submit_id(id, &lowerSlot, &generation)) {
            return 0;
        }
        (void)lowerSlot;
        (void)generation;

        AmprUniqueLock lk(m);
        const uint32_t requestSlot = find_synthetic_wait_slot_locked(id);
        if (requestSlot >= kSyntheticRequestCapacity) {
            int completedResult = 0;
            if (take_synthetic_done_result_locked(id, &completedResult)) {
                if (outHandled) {
                    *outHandled = true;
                }
                return completedResult;
            }
            // A tag-shaped native APR/AMM id is not ours. Only an exact live
            // request or retained exact-id result may consume a synthetic wait.
            return 0;
        }
        if (outHandled) {
            *outHandled = true;
        }
        SyntheticWaitSlot& waitSlot = syntheticWaitSlots[requestSlot];
        if (waitSlot.waiterClaimed) {
            return SCE_KERNEL_ERROR_EBUSY;
        }
        waitSlot.waiterClaimed = true;
        const uint8_t laneIndex = waitSlot.prioIndex;
        syntheticWaitCvs[laneIndex].wait(lk, [&] {
            const SyntheticWaitSlot& current = syntheticWaitSlots[requestSlot];
            return !current.active || current.submitId != id || current.done;
        });
        SyntheticWaitSlot& completed = syntheticWaitSlots[requestSlot];
        if (!completed.active || completed.submitId != id) {
            return SCE_KERNEL_ERROR_ESRCH;
        }
        const int rc = completed.result;
        completed = {};
        lk.unlock();
        // A pre-completion waiter owns the live record until it consumes the
        // result. Lower descriptor waiters are woken by the completion path.
        syntheticRequestAvailableCv.notify_one();
        return rc;
    }

    void notify_external_progress() {
        reactorWakeEpoch.fetch_add(1u, std::memory_order_release);
        reactorCv.notify_one();
    }

    int shutdown() {
        // Serialize shutdown with worker creation. This prevents shutdown from
        // observing a transient not-started state while scePthreadCreate is in flight.
        AmprLockGuard lifecycle(workerLifecycleMutex);
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
    static_assert(kMaxActiveReads <= SCE_KERNEL_AIO_REQUEST_NUM_MAX,
                  "APR AIO active window exceeds an SDK request array");
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
    // One normal SDK array poll can observe every due unique id owned by the
    // reactor. Deadline filtering still excludes newly submitted/background
    // requests that are not due; this limit only removes artificial splitting
    // of the due set across worker passes.
    static constexpr size_t kAioPollBatchLimit = kMaxActiveReads;
    static_assert(kAioPollBatchLimit >= 1u,
                  "APR AIO poll batch must contain at least one SDK id");
    static constexpr uint32_t kAioPollPressureThreshold =
        (static_cast<uint32_t>(kBaseActiveReads) * 3u + 3u) / 4u;
    static_assert(kAioPollPressureThreshold >= 1u &&
                      kAioPollPressureThreshold <= kBaseActiveReads,
                  "APR AIO poll pressure threshold must fit the base window");
    static constexpr size_t kConfiguredAioCapacityPollBatchLimit =
        AMPR_EMU_APR_AIO_CAPACITY_POLL_BATCH_LIMIT != 0
            ? static_cast<size_t>(AMPR_EMU_APR_AIO_CAPACITY_POLL_BATCH_LIMIT)
            : 1u;
    static constexpr size_t kAioCapacityPollBatchLimit =
        kConfiguredAioCapacityPollBatchLimit < kAioPollBatchLimit
            ? kConfiguredAioCapacityPollBatchLimit
            : kAioPollBatchLimit;
    static_assert(AMPR_EMU_APR_AIO_CAPACITY_POLL_INTERVAL_NS > 0,
                  "APR AIO capacity poll interval must be non-zero");
    static_assert(kAioCapacityPollBatchLimit >= 1u,
                  "APR AIO capacity poll batch must contain at least one SDK id");
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
    // Keep live requests separate from the bounded late-wait result history.
    // The class-0 lower submit-id descriptor pool has 512 reusable slots.
    static constexpr uint32_t kSyntheticRequestCapacity = 4096u;
    static constexpr uint32_t kSyntheticDoneCapacity = 4096u;
    static constexpr uint32_t kSyntheticLowerSlotCapacity = 512u;
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
    // Preserve the 0xA5 synthetic namespace while matching the observed
    // 512-slot lower pool. The remaining 15 payload bits are generation.
    static constexpr uint32_t kSyntheticSubmitIdSlotMask = 0x000001FFu;
    static constexpr uint32_t kSyntheticSubmitIdGenerationMask = 0x00FFFE00u;
    static constexpr uint32_t kSyntheticSubmitIdGenerationShift = 9u;
    static_assert(kJobStatePoolCapacity != 0, "job state pool must be non-empty");
    static_assert(kSyntheticRequestCapacity != 0,
                  "synthetic APR request pool must be non-empty");
    static_assert(kSyntheticDoneCapacity != 0,
                  "synthetic APR done history must be non-empty");
    static_assert(kSyntheticLowerSlotCapacity <= kSyntheticSubmitIdSlotMask + 1u,
                  "synthetic APR submit-id slot field is too small");
    static_assert(AMPR_EMU_APR_AIO_POLL_BACKOFF_MAX_NS >= AMPR_EMU_APR_AIO_POLL_INITIAL_STEP_NS,
                  "APR AIO poll backoff maximum must cover the base poll interval");
    static_assert(AMPR_EMU_APR_AIO_POLL_BACKGROUND_INITIAL_MIN_NS >= AMPR_EMU_APR_AIO_POLL_INITIAL_STEP_NS,
                  "APR AIO background initial delay must cover the base poll interval");
    static_assert(AMPR_EMU_APR_AIO_POLL_BACKGROUND_INITIAL_MIN_NS <= AMPR_EMU_APR_AIO_POLL_PRESSURE_BACKOFF_MAX_NS,
                  "APR AIO background initial delay must fit the pressure cap");
    static_assert(AMPR_EMU_APR_AIO_POLL_CRITICAL_INITIAL_NS != 0,
                  "APR AIO critical initial backoff must be non-zero");
    static_assert(AMPR_EMU_APR_AIO_POLL_CRITICAL_INITIAL_NS <= AMPR_EMU_APR_AIO_POLL_STAGED_EOP_BACKOFF_MAX_NS,
                  "APR AIO critical initial backoff must fit the staged-EOP cap");
    static_assert(AMPR_EMU_APR_AIO_POLL_STAGED_EOP_BACKOFF_MAX_NS <= AMPR_EMU_APR_AIO_POLL_DEPENDENT_BACKOFF_MAX_NS,
                  "APR AIO staged-EOP poll cap must not exceed the dependent cap");
    static_assert(AMPR_EMU_APR_AIO_POLL_DEPENDENT_BACKOFF_MAX_NS <= AMPR_EMU_APR_AIO_POLL_CRITICAL_LONG_BACKOFF_MAX_NS,
                  "APR AIO long critical cap must not poll faster than the short critical cap");
    static_assert(AMPR_EMU_APR_AIO_POLL_CRITICAL_LONG_BACKOFF_MAX_NS <= AMPR_EMU_APR_AIO_POLL_CRITICAL_STALL_BACKOFF_MAX_NS,
                  "APR AIO stalled critical cap must not poll faster than the long critical cap");
    static_assert(AMPR_EMU_APR_AIO_POLL_CRITICAL_STALL_BACKOFF_MAX_NS <= AMPR_EMU_APR_AIO_POLL_BACKOFF_MAX_NS,
                  "APR AIO stalled critical cap must remain tighter than ordinary background work");
    static_assert(AMPR_EMU_APR_AIO_POLL_PRESSURE_BACKOFF_MAX_NS <= AMPR_EMU_APR_AIO_POLL_BACKOFF_MAX_NS,
                  "APR AIO pressure cap must not exceed the background cap");
    static_assert(AMPR_EMU_APR_AIO_POLL_LONG_REQUEST_AGE_NS < AMPR_EMU_APR_AIO_POLL_STALL_AGE_NS,
                  "APR AIO long-request age must precede the stall age");
    static_assert(AMPR_EMU_APR_AIO_POLL_STALL_BACKOFF_MAX_NS >= AMPR_EMU_APR_AIO_POLL_BACKOFF_MAX_NS,
                  "APR AIO stall cap must not poll faster than ordinary background work");
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

    // Live upper request record. An in-flight waiter keeps this record through
    // completion; an unclaimed completion moves its result to done history.
    struct SyntheticWaitSlot {
        SceAprSubmitId submitId{};
        int result{};
        uint8_t prioIndex{};
        bool active{};
        bool done{};
        bool waiterClaimed{};
    };

    // Bounded FIFO history for exact-id waits that arrive after completion.
    // next/prev form the active age list; next is also the inactive free link.
    struct SyntheticDoneSlot {
        SceAprSubmitId submitId{};
        int result{};
        uint32_t next{UINT32_MAX};
        uint32_t prev{UINT32_MAX};
        bool active{};
    };

    // Lower submit-id descriptor: short-lived execution resource. Completion
    // returns the slot to this pool and advances generation immediately.
    struct SyntheticLowerSlot {
        uint32_t generation{};
        bool active{};
        bool generationWrapped{};
    };

    enum class NativeMicroEngine : uint8_t {
        None,
        AprBatch,
        Apr,
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

    struct EagerNativeArenaAllocation {
        uint32_t offset{};
        uint32_t reservedBytes{};
        uint32_t next{UINT32_MAX};
        bool active{};
        bool released{};
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
        int crossEopDeferredBackendRc{};
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
        SceAprSubmitId nativeMicroSubmitId{};
        uint64_t nativeBatchSequence{};
        uint64_t nativeBatchReleaseReadSequence{};
        bool nativeBatchReleasePending{};
#if AMPR_EMU_APR_EAGER_NATIVE_EQUEUE
        uint32_t eagerNativeArenaAllocation{UINT32_MAX};
        uint32_t eagerNativeArenaOffset{};
        uint32_t eagerNativeArenaBytes{};
        uint32_t eagerNativeEventProgressOffset{};
        uint32_t eagerNativeEventFirstSourceOffset{};
        uint32_t eagerNativeEventCount{};
        uint32_t eagerNativeEventCursor{};
        uint32_t eagerNativeEventReleaseCursor{};
        uint32_t eagerNativeEventCommandBytes{};
        SceAprSubmitId eagerNativeEventSubmitId{};
        uint64_t eagerNativeEventFirstToken{};
        uint64_t eagerNativeCounterWaitTarget{};
        uint64_t eagerNativeEventLastReleaseNs{};
        uint64_t eagerNativeEventLastWatchdogNs{};
        bool eagerNativeEventPlan{};
        std::atomic<bool> eagerNativeEventPreparePending{false};
        bool eagerNativeEventQueueLinked{};
        bool eagerNativeEventAllReleased{};
        JobState* eagerNativeEventQueueNext{};
#endif
        uint32_t nativeSourceOffset{};
        OpType nativeSourceType{OpType::Nop};
        SceAprSubmitId syntheticSubmitId{};
        uint32_t syntheticWaitSlot{UINT32_MAX};
        uint32_t syntheticLowerSlot{UINT32_MAX};
        uint32_t syntheticLowerGeneration{};
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
#if AMPR_EMU_APR_EAGER_NATIVE_EQUEUE
        if (job->eagerNativeEventPreparePending.load(std::memory_order_acquire) ||
            job->eagerNativeEventQueueLinked ||
            job->eagerNativeEventSubmitId != 0 ||
            job->nativeMicroSubmitId != 0) {
            AMPR_CRITICAL_LOGF("apr.reactor.job.pool.releaseWithEagerNative job=0x%llx prepare=%u linked=%u submitId=0x%x microSubmitId=0x%x nativeSubmitted=%u engine=%u",
                               (unsigned long long)job->id,
                               job->eagerNativeEventPreparePending.load(std::memory_order_relaxed) ? 1u : 0u,
                               job->eagerNativeEventQueueLinked ? 1u : 0u,
                               job->eagerNativeEventSubmitId,
                               job->nativeMicroSubmitId,
                               job->nativeSubmitted.load(std::memory_order_relaxed) ? 1u : 0u,
                               (unsigned)job->nativeMicroEngine);
            ampr_debug_int3_trap();
        }
        release_eager_native_event_arena(*job);
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
        {
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
            // Publish the count while the freelist lock still makes this slot
            // unavailable to allocators; otherwise an allocator could pop the
            // new head before the count increment and underflow the counter.
            jobStateFreeCount.fetch_add(1u, std::memory_order_release);
        }
        // Pair notification with the same mutex only when someone can sleep
        // on this pool. This prevents a lost wake between predicate evaluation
        // and cond-wait without adding main-reactor mutex traffic to the common
        // no-waiter completion path.
        if (jobStateWaiterCount.load(std::memory_order_acquire) != 0) {
            AmprLockGuard availabilityLock(m);
            jobStateAvailableCv.notify_one();
        }
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
            jobStateFreeCount.fetch_sub(1u, std::memory_order_release);
            return job;
        }
        return nullptr;
    }

#if AMPR_EMU_APR_EAGER_NATIVE_EQUEUE
    uint8_t* eager_native_event_commands(const JobState& job) const {
        if (job.eagerNativeArenaAllocation >=
                kAprNativeEventArenaAllocationCount ||
            job.eagerNativeArenaBytes == 0 ||
            job.eagerNativeArenaOffset > kAprNativeEventArenaBytes ||
            job.eagerNativeArenaBytes >
                kAprNativeEventArenaBytes - job.eagerNativeArenaOffset) {
            return nullptr;
        }
        return g_apr_native_event_arena + job.eagerNativeArenaOffset;
    }

    volatile uint64_t* eager_native_event_progress(const JobState& job) const {
        uint8_t* const commands = eager_native_event_commands(job);
        if (!commands || job.eagerNativeEventProgressOffset >
                             job.eagerNativeArenaBytes - sizeof(uint64_t)) {
            return nullptr;
        }
        return reinterpret_cast<volatile uint64_t*>(
            commands + job.eagerNativeEventProgressOffset);
    }

    bool allocate_eager_native_event_arena(JobState& job) {
        if (!job.eagerNativeEventPlan) {
            return true;
        }
        if (job.eagerNativeArenaAllocation != UINT32_MAX ||
            job.eagerNativeArenaBytes == 0 ||
            job.eagerNativeArenaBytes > kAprNativeEventArenaBytes) {
            AMPR_KLOGF("ampr.abort reason=apr.reactor.native.fifo.arena.allocate-invalid file=%s line=%d", __FILE__, __LINE__);
            std::abort();
        }
        bool loggedWait = false;
        for (;;) {
            {
                AmprSpinLock lock(&eagerNativeArenaLock);
                if (eagerNativeArenaUsedBytes > kAprNativeEventArenaBytes ||
                    eagerNativeArenaReadOffset >= kAprNativeEventArenaBytes ||
                    eagerNativeArenaWriteOffset >= kAprNativeEventArenaBytes ||
                    (eagerNativeArenaFreeHead != UINT32_MAX &&
                     eagerNativeArenaFreeHead >=
                         kAprNativeEventArenaAllocationCount) ||
                    (eagerNativeArenaQueueHead != UINT32_MAX &&
                     eagerNativeArenaQueueHead >=
                         kAprNativeEventArenaAllocationCount) ||
                    (eagerNativeArenaQueueTail != UINT32_MAX &&
                     eagerNativeArenaQueueTail >=
                         kAprNativeEventArenaAllocationCount) ||
                    ((eagerNativeArenaQueueHead == UINT32_MAX) !=
                     (eagerNativeArenaQueueTail == UINT32_MAX))) {
                    AMPR_KLOGF("ampr.abort reason=apr.reactor.native.fifo.arena.state-corrupt file=%s line=%d", __FILE__, __LINE__);
                    std::abort();
                }
                const uint32_t allocationIndex = eagerNativeArenaFreeHead;
                const uint32_t requestBytes = job.eagerNativeArenaBytes;
                const uint32_t freeBytes = kAprNativeEventArenaBytes -
                    eagerNativeArenaUsedBytes;
                const AprNativeEventArenaPlacement placement =
                    allocationIndex < kAprNativeEventArenaAllocationCount
                        ? apr_native_event_arena_placement(
                              kAprNativeEventArenaBytes,
                              eagerNativeArenaReadOffset,
                              eagerNativeArenaWriteOffset,
                              eagerNativeArenaUsedBytes,
                              requestBytes)
                        : AprNativeEventArenaPlacement{};
                if (placement.offset != UINT32_MAX) {
                    EagerNativeArenaAllocation& allocation =
                        eagerNativeArenaAllocations[allocationIndex];
                    if (allocation.active) {
                        AMPR_KLOGF("ampr.abort reason=apr.reactor.native.fifo.arena.active-free file=%s line=%d", __FILE__, __LINE__);
                        std::abort();
                    }
                    if (allocation.next != UINT32_MAX &&
                        allocation.next >=
                            kAprNativeEventArenaAllocationCount) {
                        AMPR_KLOGF("ampr.abort reason=apr.reactor.native.fifo.arena.free-corrupt file=%s line=%d", __FILE__, __LINE__);
                        std::abort();
                    }
                    eagerNativeArenaFreeHead = allocation.next;
                    allocation.offset = placement.offset;
                    allocation.reservedBytes = placement.reservedBytes;
                    allocation.next = UINT32_MAX;
                    allocation.active = true;
                    allocation.released = false;
                    if (eagerNativeArenaQueueTail <
                        kAprNativeEventArenaAllocationCount) {
                        eagerNativeArenaAllocations[
                            eagerNativeArenaQueueTail].next = allocationIndex;
                    } else {
                        eagerNativeArenaQueueHead = allocationIndex;
                    }
                    eagerNativeArenaQueueTail = allocationIndex;
                    eagerNativeArenaWriteOffset =
                        (placement.offset + requestBytes) %
                        kAprNativeEventArenaBytes;
                    if (placement.reservedBytes > freeBytes) {
                        AMPR_KLOGF("ampr.abort reason=apr.reactor.native.fifo.arena.reserve-overflow file=%s line=%d", __FILE__, __LINE__);
                        std::abort();
                    }
                    eagerNativeArenaUsedBytes += placement.reservedBytes;
                    job.eagerNativeArenaAllocation = allocationIndex;
                    job.eagerNativeArenaOffset = placement.offset;
                    if (loggedWait) {
                        AMPR_VLOGF("apr.reactor.native.fifo.arena.resumed allocation=%u offset=0x%x bytes=0x%x used=0x%x capacity=0x%x",
                                   allocationIndex,
                                   placement.offset,
                                   requestBytes,
                                   eagerNativeArenaUsedBytes,
                                   kAprNativeEventArenaBytes);
                    }
                    return true;
                }
            }
            {
                AmprLockGuard lk(m);
                if (stop || shutdownRequested.load(std::memory_order_acquire)) {
                    return false;
                }
            }
            if (!loggedWait) {
                AMPR_VLOGF("apr.reactor.native.fifo.arena.wait bytes=0x%x capacity=0x%x descriptors=%u",
                           job.eagerNativeArenaBytes,
                           kAprNativeEventArenaBytes,
                           kAprNativeEventArenaAllocationCount);
                loggedWait = true;
            }
            timespec ts{0, 100000};
            (void)::sceKernelNanosleep(&ts, nullptr);
        }
    }

    void release_eager_native_event_arena(JobState& job) noexcept {
        const uint32_t allocationIndex = job.eagerNativeArenaAllocation;
        if (allocationIndex == UINT32_MAX) {
            return;
        }
        if (allocationIndex >= kAprNativeEventArenaAllocationCount) {
            AMPR_KLOGF("ampr.abort reason=apr.reactor.native.fifo.arena.release-invalid file=%s line=%d", __FILE__, __LINE__);
            std::abort();
        }
        const uint32_t allocationOffset = job.eagerNativeArenaOffset;
        AmprSpinLock lock(&eagerNativeArenaLock);
        EagerNativeArenaAllocation& released =
            eagerNativeArenaAllocations[allocationIndex];
        if (!released.active || released.released ||
            released.offset != allocationOffset) {
            AMPR_KLOGF("ampr.abort reason=apr.reactor.native.fifo.arena.double-free file=%s line=%d", __FILE__, __LINE__);
            std::abort();
        }
        released.released = true;
        while (eagerNativeArenaQueueHead <
               kAprNativeEventArenaAllocationCount) {
            const uint32_t headIndex = eagerNativeArenaQueueHead;
            EagerNativeArenaAllocation& head =
                eagerNativeArenaAllocations[headIndex];
            if (!head.active || head.reservedBytes == 0 ||
                head.reservedBytes > eagerNativeArenaUsedBytes) {
                AMPR_KLOGF("ampr.abort reason=apr.reactor.native.fifo.arena.queue-corrupt file=%s line=%d", __FILE__, __LINE__);
                std::abort();
            }
            if (!head.released) {
                break;
            }
            eagerNativeArenaReadOffset =
                (eagerNativeArenaReadOffset + head.reservedBytes) %
                kAprNativeEventArenaBytes;
            eagerNativeArenaUsedBytes -= head.reservedBytes;
            eagerNativeArenaQueueHead = head.next;
            if (eagerNativeArenaQueueHead == UINT32_MAX) {
                eagerNativeArenaQueueTail = UINT32_MAX;
                eagerNativeArenaReadOffset = eagerNativeArenaWriteOffset;
            }
            head = {};
            head.next = eagerNativeArenaFreeHead;
            eagerNativeArenaFreeHead = headIndex;
        }
        if (eagerNativeArenaQueueHead == UINT32_MAX &&
            eagerNativeArenaUsedBytes != 0) {
            AMPR_KLOGF("ampr.abort reason=apr.reactor.native.fifo.arena.reclaim-corrupt file=%s line=%d", __FILE__, __LINE__);
            std::abort();
        }
        job.eagerNativeArenaAllocation = UINT32_MAX;
        job.eagerNativeArenaOffset = 0;
        job.eagerNativeArenaBytes = 0;
        job.eagerNativeEventProgressOffset = 0;
    }
#endif

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
        uint32_t pollAttempts{};
#endif
        uint64_t nextPollTimeNs{};
        uint32_t pollBackoffNs{};
        uint32_t ammEfaultRetries{};
        uint32_t aioCompletionRetries{};
        uint32_t aioDeleteRetries{};
        uint64_t aioDeleteFirstFailureNs{};
        uint64_t retryNotBeforeNs{};
        uint32_t listSlot{UINT32_MAX};
        uint32_t listGeneration{};
        uint32_t pollDeadlineHeapIndex{UINT32_MAX};
        uint32_t jobPrevSlot{UINT32_MAX};
        uint32_t jobNextSlot{UINT32_MAX};
        bool hotPollQueued{false};
        bool awaitingBatchSubmit{false};
        bool awaitingResubmit{false};
    };

    struct ActiveReadRef {
        uint32_t slot{UINT32_MAX};
        uint32_t generation{};
    };

    struct AioSubmitBatch {
        SceKernelAioRWRequest requests[kMaxActiveReads]{};
        SceKernelAioSubmitId ids[kMaxActiveReads]{};
        ActiveReadRef items[kMaxActiveReads]{};
        size_t count{};
        int aioPriority{SCE_KERNEL_AIO_PRIORITY_MID};
    };

    struct AioSubmitRound {
        AioSubmitBatch batches[3]{};
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

    ActiveRead* first_poll_deadline_read() const {
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

    uint64_t active_poll_deadline_ns() const {
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
        return !active.awaitingBatchSubmit &&
               !active.awaitingResubmit &&
               active.aioId >= 0;
    }

    void mark_active_read_submitted(ActiveRead& active,
                                    SceKernelAioSubmitId aioId) {
        if (aioId < 0 || active_read_is_submitted(active) ||
            !active.awaitingBatchSubmit || active.aioId >= 0) {
            AMPR_KLOGF("ampr.abort reason=apr.reactor.activeRead.submit.invalid file=%s line=%d", __FILE__, __LINE__);
            std::abort();
        }
        active.awaitingBatchSubmit = false;
        if (active.awaitingResubmit) {
            if (deferredActiveReadCount == 0) {
                AMPR_KLOGF("ampr.abort reason=apr.reactor.activeRead.deferred.underflow file=%s line=%d", __FILE__, __LINE__);
                std::abort();
            }
            --deferredActiveReadCount;
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
            if (it->aioId >= 0 || it->awaitingBatchSubmit ||
                deferredActiveReadCount == 0) {
                AMPR_KLOGF("ampr.abort reason=apr.reactor.activeRead.deferred.erase.invalid file=%s line=%d", __FILE__, __LINE__);
                std::abort();
            }
            --deferredActiveReadCount;
        } else if (it->awaitingBatchSubmit) {
            if (it->aioId >= 0) {
                AMPR_KLOGF("ampr.abort reason=apr.reactor.activeRead.batch-submit.erase.invalid file=%s line=%d", __FILE__, __LINE__);
                std::abort();
            }
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
        jobStateAvailableCv.notify_all();
        syntheticRequestAvailableCv.notify_all();
        syntheticLowerSlotAvailableCv.notify_all();
        for (size_t lane = 0; lane < kPriorityCount; ++lane) {
            syntheticWaitCvs[lane].notify_all();
        }
    }

    bool start_worker() {
        int createRc = 0;
        {
            // Thread creation is retryable. Serialize concurrent submitters with
            // shutdown, but do not hold the main reactor mutex across pthread create.
            AmprLockGuard lifecycle(workerLifecycleMutex);
            if (started.load(std::memory_order_acquire)) {
                return true;
            }
            {
                AmprLockGuard lk(m);
                if (stop || shutdownRequested.load(std::memory_order_acquire)) {
                    return false;
                }
            }

            ScePthread thread{};
            createRc = scePthreadCreate(&thread, nullptr, worker_entry, this, "ampr_apr_reactor");
            if (createRc == 0) {
                workerThread = thread;
                started.store(true, std::memory_order_release);
                return true;
            }
        }

        // Failure is intentionally non-sticky. A later submit may retry creation.
        AMPR_CRITICAL_LOGF("apr.reactor.thread.create.fail rc=0x%x action=retry-next-submit",
                           createRc);
        return false;
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

    void note_aio_submit_result(int sceRc, size_t requestCount) {
        if (sceRc == SCE_KERNEL_ERROR_EAGAIN) {
            aioSubmitEagainCount.fetch_add(
                static_cast<uint64_t>(requestCount),
                std::memory_order_relaxed);
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
        if (slot >= kSyntheticLowerSlotCapacity || generation == 0) {
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

    uint32_t find_synthetic_done_slot_locked(SceAprSubmitId id) const {
        uint32_t slot = syntheticDoneHead;
        while (slot < kSyntheticDoneCapacity) {
            const SyntheticDoneSlot& done = syntheticDoneSlots[slot];
            if (done.active && done.submitId == id) {
                return slot;
            }
            slot = done.next;
        }
        return UINT32_MAX;
    }

    bool take_synthetic_done_result_locked(SceAprSubmitId id, int* outResult) {
        const uint32_t slot = find_synthetic_done_slot_locked(id);
        if (slot >= kSyntheticDoneCapacity) {
            return false;
        }

        SyntheticDoneSlot& done = syntheticDoneSlots[slot];
        if (outResult) {
            *outResult = done.result;
        }
        if (done.prev < kSyntheticDoneCapacity) {
            syntheticDoneSlots[done.prev].next = done.next;
        } else {
            syntheticDoneHead = done.next;
        }
        if (done.next < kSyntheticDoneCapacity) {
            syntheticDoneSlots[done.next].prev = done.prev;
        } else {
            syntheticDoneTail = done.prev;
        }
        done = {};
        done.next = syntheticDoneFreeHead;
        syntheticDoneFreeHead = slot;
        return true;
    }

    SceAprSubmitId retain_synthetic_done_result_locked(SceAprSubmitId id,
                                                        int result) {
        uint32_t slot = UINT32_MAX;
        SceAprSubmitId evictedId = 0;
        if (syntheticDoneFreeHead < kSyntheticDoneCapacity) {
            slot = syntheticDoneFreeHead;
            syntheticDoneFreeHead = syntheticDoneSlots[slot].next;
        } else {
            slot = syntheticDoneHead;
            if (slot >= kSyntheticDoneCapacity) {
                AMPR_KLOGF(
                    "ampr.abort reason=apr.reactor.synthetic.done.corrupt file=%s line=%d",
                    __FILE__,
                    __LINE__);
                std::abort();
            }
            SyntheticDoneSlot& oldest = syntheticDoneSlots[slot];
            evictedId = oldest.submitId;
            syntheticDoneHead = oldest.next;
            if (syntheticDoneHead < kSyntheticDoneCapacity) {
                syntheticDoneSlots[syntheticDoneHead].prev = UINT32_MAX;
            } else {
                syntheticDoneTail = UINT32_MAX;
            }
            oldest = {};
        }

        SyntheticDoneSlot& done = syntheticDoneSlots[slot];
        done.submitId = id;
        done.result = result;
        done.next = UINT32_MAX;
        done.prev = syntheticDoneTail;
        done.active = true;
        if (syntheticDoneTail < kSyntheticDoneCapacity) {
            syntheticDoneSlots[syntheticDoneTail].next = slot;
        } else {
            syntheticDoneHead = slot;
        }
        syntheticDoneTail = slot;
        return evictedId;
    }

    bool synthetic_submit_id_owned_locked(SceAprSubmitId id) const {
        if (id == 0) {
            return false;
        }
        for (const SyntheticWaitSlot& request : syntheticWaitSlots) {
            if (request.active && request.submitId == id) {
                return true;
            }
        }
        return find_synthetic_done_slot_locked(id) < kSyntheticDoneCapacity;
    }

    uint32_t find_synthetic_wait_slot_locked(SceAprSubmitId id) const {
        for (uint32_t slot = 0; slot < kSyntheticRequestCapacity; ++slot) {
            const SyntheticWaitSlot& request = syntheticWaitSlots[slot];
            if (request.active && request.submitId == id) {
                return slot;
            }
        }
        return UINT32_MAX;
    }

    bool reserve_synthetic_wait_slot_locked(JobState& job) {
        if (job.syntheticWaitSlot < kSyntheticRequestCapacity) {
            return true;
        }
        for (uint32_t attempt = 0; attempt < kSyntheticRequestCapacity; ++attempt) {
            const uint32_t slot =
                (syntheticWaitAllocCursor + attempt) % kSyntheticRequestCapacity;
            SyntheticWaitSlot& request = syntheticWaitSlots[slot];
            if (request.active) {
                continue;
            }
            request = {};
            request.prioIndex = job.prioIndex;
            request.active = true;
            job.syntheticWaitSlot = slot;
            syntheticWaitAllocCursor = (slot + 1u) % kSyntheticRequestCapacity;
            return true;
        }
        return false;
    }

    bool allocate_synthetic_lower_slot_locked(JobState& job, SceAprSubmitId* outId) {
        if (!outId || job.syntheticWaitSlot >= kSyntheticRequestCapacity) {
            return false;
        }
        constexpr uint32_t generationMax =
            kSyntheticSubmitIdGenerationMask >> kSyntheticSubmitIdGenerationShift;
        static_assert(generationMax >
                          kSyntheticRequestCapacity + kSyntheticDoneCapacity,
                      "synthetic generation space must exceed retained ids");

        for (uint32_t attempt = 0; attempt < kSyntheticLowerSlotCapacity; ++attempt) {
            const uint32_t slot =
                (syntheticLowerAllocCursor + attempt) % kSyntheticLowerSlotCapacity;
            SyntheticLowerSlot& lower = syntheticLowerSlots[slot];
            if (lower.active) {
                continue;
            }

            uint32_t generation = lower.generation;
            if (generation == 0 || generation > generationMax) {
                generation = 1u;
            }
            SceAprSubmitId id = make_synthetic_submit_id(slot, generation);
            // Before the first 15-bit wrap an encoded generation cannot have
            // appeared twice for this lower slot, so the common allocation path
            // stays O(1). After wrap, protect very old unreaped requests from an
            // ID collision by skipping any still-owned encoded generation.
            if (lower.generationWrapped) {
                id = 0;
                for (uint32_t generationAttempt = 0;
                     generationAttempt < generationMax;
                     ++generationAttempt) {
                    const SceAprSubmitId candidate =
                        make_synthetic_submit_id(slot, generation);
                    if (!synthetic_submit_id_owned_locked(candidate)) {
                        id = candidate;
                        break;
                    }
                    ++generation;
                    if (generation == 0 || generation > generationMax) {
                        generation = 1u;
                    }
                }
                if (id == 0) {
                    continue;
                }
            }

            lower.generation = generation;
            lower.active = true;
            job.syntheticLowerSlot = slot;
            job.syntheticLowerGeneration = generation;
            job.syntheticSubmitId = id;
            SyntheticWaitSlot& request = syntheticWaitSlots[job.syntheticWaitSlot];
            request.submitId = id;
            request.result = 0;
            request.done = false;
            request.waiterClaimed = false;
            syntheticLowerAllocCursor = (slot + 1u) % kSyntheticLowerSlotCapacity;
            *outId = id;
            return true;
        }
        return false;
    }

    void release_synthetic_lower_slot_locked(JobState& job) {
        if (job.syntheticLowerSlot >= kSyntheticLowerSlotCapacity) {
            return;
        }
        SyntheticLowerSlot& lower = syntheticLowerSlots[job.syntheticLowerSlot];
        if (lower.active && lower.generation == job.syntheticLowerGeneration) {
            constexpr uint32_t generationMax =
                kSyntheticSubmitIdGenerationMask >> kSyntheticSubmitIdGenerationShift;
            lower.active = false;
            uint32_t nextGeneration = lower.generation + 1u;
            if (nextGeneration == 0 || nextGeneration > generationMax) {
                nextGeneration = 1u;
                lower.generationWrapped = true;
            }
            lower.generation = nextGeneration;
            syntheticLowerSlotAvailableCv.notify_one();
        }
        job.syntheticLowerSlot = UINT32_MAX;
        job.syntheticLowerGeneration = 0;
    }

    void release_unpublished_synthetic_wait_slot_locked(JobState& job) {
        if (job.syntheticWaitPublished) {
            return;
        }

        release_synthetic_lower_slot_locked(job);
        if (job.syntheticWaitSlot < kSyntheticRequestCapacity) {
            SyntheticWaitSlot& request = syntheticWaitSlots[job.syntheticWaitSlot];
            if (request.active) {
                request = {};
                syntheticRequestAvailableCv.notify_one();
            }
        }
        job.syntheticSubmitId = 0;
        job.syntheticWaitSlot = UINT32_MAX;
    }

    void publish_synthetic_wait_completion(JobState& job) {
        if (!job.syntheticWaitPublished ||
            job.syntheticWaitSlot >= kSyntheticRequestCapacity) {
            return;
        }
        bool notifyWaiter = false;
        bool notifyRequestAvailable = false;
        SceAprSubmitId evictedId = 0;
        const uint8_t laneIndex = job.prioIndex;
        {
            AmprLockGuard lk(m);
            SyntheticWaitSlot& request = syntheticWaitSlots[job.syntheticWaitSlot];
            if (request.active && request.submitId == job.syntheticSubmitId) {
                // Native command errors stay in SceAprResultBuffer when the caller
                // requested one. Infrastructure failures and result-less submits
                // must remain observable through the synthetic wait itself.
                request.result = job_failed(job) && (!job.hasCommandError || !job.aprRes)
                    ? job.result.rc
                    : 0;
                if (request.waiterClaimed) {
                    request.done = true;
                    notifyWaiter = true;
                } else {
                    evictedId = retain_synthetic_done_result_locked(
                        request.submitId,
                        request.result);
                    request = {};
                    job.syntheticWaitSlot = UINT32_MAX;
                    notifyRequestAvailable = true;
                }
            }

            // Completion always releases the lower descriptor immediately. The
            // live upper record survives only when a waiter claimed it first.
            release_synthetic_lower_slot_locked(job);
        }
        if (notifyWaiter) {
            syntheticWaitCvs[laneIndex].notify_all();
        }
        if (notifyRequestAvailable) {
            syntheticRequestAvailableCv.notify_one();
        }
        if (evictedId != 0) {
            AMPR_VLOGF(
                "apr.reactor.done.evict count=1 evicted=0x%x newest=0x%x capacity=%u",
                (unsigned)evictedId,
                (unsigned)job.syntheticSubmitId,
                (unsigned)kSyntheticDoneCapacity);
        }
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

#if AMPR_EMU_APR_EAGER_NATIVE_EQUEUE
        const int eventProtectRc = ampr_real_sceKernelMprotect(
            g_apr_native_event_arena,
            kAprNativeEventArenaBytes,
            kNativeMicroProt);
        if (eventProtectRc != 0) {
            AMPR_CRITICAL_LOGF("apr.reactor.native.event.protect.fail rc=0x%x ptr=%p size=0x%llx prot=0x%x",
                               eventProtectRc,
                               g_apr_native_event_arena,
                               (unsigned long long)kAprNativeEventArenaBytes,
                               kNativeMicroProt);
            AmprSpinLock lock(&nativeExecutionPoolLock);
            nativeExecutionPoolInitAttempted = false;
            return false;
        }

        const int eventResultProtectRc = ampr_real_sceKernelMprotect(
            g_apr_native_event_result_pool,
            kAprNativeEventResultPoolBytes,
            kNativeMicroProt);
        if (eventResultProtectRc != 0) {
            AMPR_CRITICAL_LOGF("apr.reactor.native.event.result.protect.fail rc=0x%x ptr=%p size=0x%llx prot=0x%x",
                               eventResultProtectRc,
                               g_apr_native_event_result_pool,
                               (unsigned long long)kAprNativeEventResultPoolBytes,
                               kNativeMicroProt);
            AmprSpinLock lock(&nativeExecutionPoolLock);
            nativeExecutionPoolInitAttempted = false;
            return false;
        }

        const int eventControlProtectRc = ampr_real_sceKernelMprotect(
            g_apr_native_event_control_pool,
            kAprNativeEventControlPoolBytes,
            kNativeMicroProt);
        if (eventControlProtectRc != 0) {
            AMPR_CRITICAL_LOGF("apr.reactor.native.event.control.protect.fail rc=0x%x ptr=%p size=0x%llx prot=0x%x",
                               eventControlProtectRc,
                               g_apr_native_event_control_pool,
                               (unsigned long long)kAprNativeEventControlPoolBytes,
                               kNativeMicroProt);
            AmprSpinLock lock(&nativeExecutionPoolLock);
            nativeExecutionPoolInitAttempted = false;
            return false;
        }
        for (uint32_t lane = 0; lane < kPriorityCount; ++lane) {
            volatile uint64_t* const release =
                apr_native_event_lane_release_ptr(lane);
            __atomic_store_n(release, 0ull, __ATOMIC_RELAXED);
        }
#endif

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
#if AMPR_EMU_APR_EAGER_NATIVE_EQUEUE
            AMPR_KLOGF("apr.reactor.native.pool.mapped micro=%p microBytes=0x%llx eventArena=%p eventArenaBytes=0x%llx eventResult=%p eventResultBytes=0x%llx eventControl=%p eventControlBytes=0x%llx batch=%p batchBytes=0x%llx firstReleaseOff=0x%llx firstProgressOff=0x%llx prot=0x%x",
                       g_apr_native_micro_pool,
                       (unsigned long long)kAprNativeMicroPoolBytes,
                       g_apr_native_event_arena,
                       (unsigned long long)kAprNativeEventArenaBytes,
                       g_apr_native_event_result_pool,
                       (unsigned long long)kAprNativeEventResultPoolBytes,
                       g_apr_native_event_control_pool,
                       (unsigned long long)kAprNativeEventControlPoolBytes,
                       g_apr_native_batch_pool,
                       (unsigned long long)kAprNativeBatchPoolBytes,
                       (unsigned long long)(releaseAddress - batchBase),
                       (unsigned long long)(progressAddress - batchBase),
                       kNativeMicroProt);
#else
            AMPR_KLOGF("apr.reactor.native.pool.mapped micro=%p microBytes=0x%llx batch=%p batchBytes=0x%llx firstReleaseOff=0x%llx firstProgressOff=0x%llx prot=0x%x",
                       g_apr_native_micro_pool,
                       (unsigned long long)kAprNativeMicroPoolBytes,
                       g_apr_native_batch_pool,
                       (unsigned long long)kAprNativeBatchPoolBytes,
                       (unsigned long long)(releaseAddress - batchBase),
                       (unsigned long long)(progressAddress - batchBase),
                       kNativeMicroProt);
#endif
        }

        {
            AmprSpinLock lock(&nativeExecutionPoolLock);
            nativeExecutionPoolReady = true;
        }
#if AMPR_EMU_APR_EAGER_NATIVE_EQUEUE
        AMPR_VLOGF("apr.reactor.native.pool.ready microBase=%p microBytes=0x%llx microSlots=%u eventArena=%p eventArenaBytes=0x%llx eventResult=%p eventResultBytes=0x%llx eventAllocations=%u eventControl=%p eventControlBytes=0x%llx batchBase=%p batchBytes=0x%llx batchSlots=%u batchBlocks=%u prot=0x%x microTemplates=lazy",
                   g_apr_native_micro_pool,
                   (unsigned long long)kAprNativeMicroPoolBytes,
                   (unsigned)kJobStatePoolCapacity,
                   g_apr_native_event_arena,
                   (unsigned long long)kAprNativeEventArenaBytes,
                   g_apr_native_event_result_pool,
                   (unsigned long long)kAprNativeEventResultPoolBytes,
                   (unsigned)kAprNativeEventArenaAllocationCount,
                   g_apr_native_event_control_pool,
                   (unsigned long long)kAprNativeEventControlPoolBytes,
                   g_apr_native_batch_pool,
                   (unsigned long long)kAprNativeBatchPoolBytes,
                   (unsigned)kAprNativeBatchSlotCount,
                   (unsigned)kAprNativeBatchGroupCount,
                   kNativeMicroProt);
#else
        AMPR_VLOGF("apr.reactor.native.pool.ready microBase=%p microBytes=0x%llx microSlots=%u batchBase=%p batchBytes=0x%llx batchSlots=%u batchBlocks=%u prot=0x%x microTemplates=lazy",
                   g_apr_native_micro_pool,
                   (unsigned long long)kAprNativeMicroPoolBytes,
                   (unsigned)kJobStatePoolCapacity,
                   g_apr_native_batch_pool,
                   (unsigned long long)kAprNativeBatchPoolBytes,
                   (unsigned)kAprNativeBatchSlotCount,
                   (unsigned)kAprNativeBatchGroupCount,
                   kNativeMicroProt);
#endif
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

    void note_aio_completion_poll_attempts(uint32_t attempts) {
        if (!collect_log_stats()) {
            return;
        }
        runtimeAioCompletionPollAttempts += attempts;
        if (attempts == 1u) {
            ++runtimeAioFirstPollCompletionCount;
        }
        if (attempts > runtimeAioCompletionPollAttemptsMax) {
            runtimeAioCompletionPollAttemptsMax = attempts;
        }
    }

    void note_aio_driven_wait(uint64_t waitNs) {
        if (collect_log_stats()) {
            runtimeAioDrivenWaitNs += waitNs;
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

    void note_worker_wakeup() {
        note_log_counter(runtimeWorkerWakeups);
    }

    void note_aio_driven_wait_count() {
        note_log_counter(runtimeAioDrivenWaits);
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
                               int deleteSceRc,
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
                  deleteSceRc,
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
        size_t directFdCap{};
        bool fdPressure{};
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
        context.fdPressure = fd_pressure_active(now);
        context.directFdCap = apr_adaptive_direct_fd_cap(
            ampr_index_fd_pressure_current_caps(),
            context.effectiveLimit,
            context.fdPressure);
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

    bool fd_budget_available_for_read(const AprAioReadDesc& rd,
                                      size_t directFdCap) const {
        if (rd.fd >= 0) {
            return true;
        }
        if (!rd.bypassFdCache) {
            // Cache hits and cached-open headroom are decided atomically by
            // ampr_index_acquire_cached_fd under the fd-cache lock.
            return true;
        }
        const AmprIndexFdPressureCaps caps = ampr_index_fd_pressure_current_caps();
        const size_t directOpen = ampr_index_fd_direct_open_count();
        if (directFdCap != 0 && directOpen + 1u > directFdCap) {
            return false;
        }
        const size_t requestedReserve =
            1u + static_cast<size_t>(AMPR_EMU_FD_DIRECT_OPEN_SAFETY_RESERVE);
        const size_t reserve =
            requestedReserve < caps.fdBudget ? requestedReserve : caps.fdBudget;
        return ampr_index_fd_common_open_budget_headroom_available(reserve);
    }

    static uint64_t active_read_age_ns(const ActiveRead& active, uint64_t now) {
        return active.submitTimeNs != 0 && now >= active.submitTimeNs
                   ? now - active.submitTimeNs
                   : 0;
    }

    // Force an immediate observation only when an already-submitted read has
    // just become publication-gating. Fresh submissions use a delayed first
    // poll so millisecond-scale AIO is not queried every few microseconds.
    void reset_active_read_poll_backoff(ActiveRead& active, uint64_t now) {
        const uint64_t oldDeadlineNs = active.nextPollTimeNs;
        active.nextPollTimeNs = now;
        active.pollBackoffNs = 0;
        update_poll_deadline(active, oldDeadlineNs);
    }

    void queue_hot_active_read_poll(ActiveRead& active) {
        if (active.hotPollQueued || active.listSlot == UINT32_MAX) {
            return;
        }
        if (hotPollQueueCount >= kHotPollQueueCapacity) {
            return;
        }
        hotPollQueue[hotPollQueueTail] = ActiveReadRef{active.listSlot, active.listGeneration};
        hotPollQueueTail = (hotPollQueueTail + 1u) % kHotPollQueueCapacity;
        ++hotPollQueueCount;
        active.hotPollQueued = true;
    }

    void reset_and_queue_hot_active_read_poll(ActiveRead& active, uint64_t now) {
        reset_active_read_poll_backoff(active, now);
        queue_hot_active_read_poll(active);
    }

    ActiveReadIt pop_hot_active_read_poll() {
        while (hotPollQueueCount != 0) {
            const ActiveReadRef entry = hotPollQueue[hotPollQueueHead];
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

    bool active_read_is_completion_frontier(const ActiveRead& active) const {
        const JobPtr& job = active.job;
        return job && !job_failed(*job) &&
               active.seq == job->completedReadSeq + 1u;
    }

    bool active_read_is_latest_submitted_tail(const ActiveRead& active) const {
        const JobPtr& job = active.job;
        return job && !job_failed(*job) && job->latestSubmittedReadSeq != 0 &&
               active.seq == job->latestSubmittedReadSeq;
    }

    bool active_read_is_native_release_gate(const ActiveRead& active) const {
        const JobPtr& job = active.job;
        return job && !job_failed(*job) && job->nativeBatchReleasePending &&
               job->nativeBatchReleaseReadSequence != 0 &&
               active.seq == job->nativeBatchReleaseReadSequence;
    }

    bool active_read_is_staged_eop_gate(const ActiveRead& active) const {
        const JobPtr& job = active.job;
        if (!job || job_failed(*job) || job->prioIndex >= kPriorityCount) {
            return false;
        }
        const NativeBatchLane& lane = nativeBatchLanes[job->prioIndex];
        if (lane.deferredReleaseSequence == 0) {
            return false;
        }

        // The 50 us staged-EOP class belongs only to reads that can actually
        // unblock the currently closed native gate.  With cross-job read-ahead
        // there may be dozens of speculative successor jobs in the same lane;
        // those reads are later than the deferred EOP and must retain their
        // ordinary critical/background cadence.  Earlier FIFO jobs have already
        // reached the end of their normal source cursor and can still contribute
        // to the accumulated lane fence.  The owner job is bounded by the exact
        // read sequence captured when the EOP group was staged, so reads scanned
        // beyond that EOP are not accidentally promoted.
        if (job->id == lane.deferredReleaseJobId) {
            return job->nativeBatchReleasePending &&
                   job->nativeBatchReleaseReadSequence != 0 &&
                   active.seq <= job->nativeBatchReleaseReadSequence &&
                   (active_read_is_completion_frontier(active) ||
                    active_read_is_native_release_gate(active));
        }
        if (job->sourceOffset == job->sourceBytes) {
            return active_read_can_gate_publish(active);
        }
        return false;
    }

    bool active_read_can_gate_publish(const ActiveRead& active) const {
        const JobPtr& job = active.job;
        if (!job || job_failed(*job)) {
            return false;
        }
        // Preserve the pre-v2 publication semantics. The in-order frontier can
        // advance completedReadSeq, while the latest submitted sequence can be
        // the read fence captured by EOP/result publication. SubmitAndGetResult
        // additionally treats every owned read as title-visible critical work.
        // nativeBatchReleaseReadSequence is checked explicitly so future
        // read-ahead cannot accidentally hide the exact deferred-EOP gate.
        return job->submitMode == AprSubmitMode::kSubmitAndGetResult ||
               active_read_is_completion_frontier(active) ||
               active_read_is_latest_submitted_tail(active) ||
               active_read_is_native_release_gate(active);
    }

    bool active_read_needs_immediate_submit_poll(const ActiveRead& active) const {
        const JobPtr& job = active.job;
        if (!job || job_failed(*job)) {
            return false;
        }
        // Do not use latestSubmittedReadSeq here. Every freshly submitted read
        // is temporarily the latest read, so doing so would make the complete
        // workload immediate-poll again and discard the background optimization.
        // If that provisional tail later becomes a real EOP/fence gate, the
        // job/lane gate reset promotes it to the hot queue immediately.
        return job->submitMode == AprSubmitMode::kSubmitAndGetResult ||
               active_read_is_completion_frontier(active) ||
               active_read_is_native_release_gate(active);
    }

    static uint32_t active_lane_idle_sleep_ns() {
        return AMPR_EMU_APR_ACTIVE_LANE_IDLE_SLEEP_NS;
    }

    void reset_completion_frontier_active_aio_poll_for_job(JobState& job,
                                                            uint64_t now) {
        const uint64_t targetSeq = job.completedReadSeq + 1u;
        uint32_t slot = job.activeReadHead;
        bool chainBroken = false;
        for (uint32_t scanned = 0; slot != UINT32_MAX && scanned < kMaxActiveReads; ++scanned) {
            ActiveRead* active = activeReads.active_at_slot(slot);
            if (!active || active->job != &job) {
                chainBroken = true;
                break;
            }
            const uint32_t nextSlot = active->jobNextSlot;
            if (active->seq == targetSeq) {
                reset_and_queue_hot_active_read_poll(*active, now);
                return;
            }
            slot = nextSlot;
        }
        if (!chainBroken && slot == UINT32_MAX) {
            return;
        }
        for (ActiveRead& active : activeReads) {
            if (active.job == &job && active.seq == targetSeq) {
                reset_and_queue_hot_active_read_poll(active, now);
                return;
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
                active_read_is_staged_eop_gate(active)) {
                reset_and_queue_hot_active_read_poll(active, now);
            }
        }
    }

    uint32_t active_read_max_poll_backoff_ns(const ActiveRead& active,
                                              uint64_t now) const {
        // Explicit native release/EOP gates stay on the tightest policy at all
        // ages. They are the one class where an extra few hundred microseconds
        // can directly delay title-visible fence publication.
        if (active_read_is_staged_eop_gate(active) ||
            active_read_is_native_release_gate(active)) {
            return AMPR_EMU_APR_AIO_POLL_STAGED_EOP_BACKOFF_MAX_NS;
        }
        if (active_read_can_gate_publish(active)) {
            // Keep SubmitAndGetResult fully latency-oriented: callers are
            // synchronously waiting for the result, so do not relax it by age.
            if (active.job &&
                active.job->submitMode == AprSubmitMode::kSubmitAndGetResult) {
                return AMPR_EMU_APR_AIO_POLL_DEPENDENT_BACKOFF_MAX_NS;
            }

            // Restore the useful part of the v2 long-request optimization
            // without restoring its semantic bug. The request remains in the
            // publication-critical class for its entire lifetime; only the
            // syscall cadence is relaxed once the underlying SDK AIO is clearly
            // outside the normal completion window.
            const uint64_t ageNs = active_read_age_ns(active, now);
            if (ageNs >= AMPR_EMU_APR_AIO_POLL_STALL_AGE_NS) {
                return AMPR_EMU_APR_AIO_POLL_CRITICAL_STALL_BACKOFF_MAX_NS;
            }
            if (ageNs >= AMPR_EMU_APR_AIO_POLL_LONG_REQUEST_AGE_NS) {
                return AMPR_EMU_APR_AIO_POLL_CRITICAL_LONG_BACKOFF_MAX_NS;
            }
            return AMPR_EMU_APR_AIO_POLL_DEPENDENT_BACKOFF_MAX_NS;
        }
        if (submittedActiveReadCount >= kAioPollPressureThreshold) {
            // Under native-window pressure, reclaim completed background IDs
            // faster without forcing them down to the critical-path cap.
            return AMPR_EMU_APR_AIO_POLL_PRESSURE_BACKOFF_MAX_NS;
        }
        const uint64_t ageNs = active_read_age_ns(active, now);
        if (ageNs >= AMPR_EMU_APR_AIO_POLL_STALL_AGE_NS) {
            return AMPR_EMU_APR_AIO_POLL_STALL_BACKOFF_MAX_NS;
        }
        return AMPR_EMU_APR_AIO_POLL_BACKOFF_MAX_NS;
    }

    uint32_t initial_background_read_poll_delay_ns(const ActiveRead& active) const {
        // Scale only true background first polls. The 250 us floor makes the
        // practical defaults 250/250/250/400 us for <=16/64/256/>256 KiB.
        uint64_t delayNs = AMPR_EMU_APR_AIO_POLL_INITIAL_STEP_NS;
        if (active.desc.length > 0x4000ull) {
            delayNs *= 2u;
        }
        if (active.desc.length > 0x10000ull) {
            delayNs *= 2u;
        }
        if (active.desc.length > 0x40000ull) {
            delayNs *= 2u;
        }
        if (delayNs < AMPR_EMU_APR_AIO_POLL_BACKGROUND_INITIAL_MIN_NS) {
            delayNs = AMPR_EMU_APR_AIO_POLL_BACKGROUND_INITIAL_MIN_NS;
        }
        const uint32_t capNs = submittedActiveReadCount >= kAioPollPressureThreshold
            ? AMPR_EMU_APR_AIO_POLL_PRESSURE_BACKOFF_MAX_NS
            : AMPR_EMU_APR_AIO_POLL_BACKOFF_MAX_NS;
        if (delayNs > capNs) {
            delayNs = capNs;
        }
        return static_cast<uint32_t>(delayNs);
    }

    uint32_t initial_active_read_poll_delay_ns(const ActiveRead& active) const {
        if (active_read_can_gate_publish(active)) {
            return AMPR_EMU_APR_AIO_POLL_CRITICAL_INITIAL_NS;
        }
        return initial_background_read_poll_delay_ns(active);
    }

    void arm_active_read_poll_after_submit(ActiveRead& active, uint64_t now) {
        if (active_read_needs_immediate_submit_poll(active)) {
            reset_and_queue_hot_active_read_poll(active, now);
            return;
        }
        const uint64_t oldDeadlineNs = active.nextPollTimeNs;
        const uint32_t initialDelayNs = initial_background_read_poll_delay_ns(active);
        active.pollBackoffNs = initialDelayNs;
        active.nextPollTimeNs = now + static_cast<uint64_t>(initialDelayNs);
        update_poll_deadline(active, oldDeadlineNs);
    }

    uint32_t next_active_read_poll_backoff_ns(const ActiveRead& active,
                                             uint64_t now) const {
        const uint32_t maxBackoffNs = active_read_max_poll_backoff_ns(active, now);
        uint32_t backoffNs = active.pollBackoffNs;
        if (backoffNs == 0) {
            backoffNs = initial_active_read_poll_delay_ns(active);
        } else if (backoffNs < maxBackoffNs) {
            backoffNs = backoffNs <= maxBackoffNs / 2u
                ? backoffNs * 2u
                : maxBackoffNs;
        }
        if (backoffNs > maxBackoffNs) {
            backoffNs = maxBackoffNs;
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

    uint64_t next_aio_poll_wait_ns(uint64_t now) const {
        if (activeReads.empty()) {
            return 0;
        }
        const uint64_t deadlineNs = active_poll_deadline_ns();
        return deadlineNs != 0 && deadlineNs > now ? deadlineNs - now : 0;
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
        if (timeoutNs == UINT64_MAX) {
            reactorCv.wait(lk);
        } else {
            reactorCv.wait_for(lk, std::chrono::nanoseconds(timeoutNs));
        }
#if AMPR_EMU_DEBUG_LOG
        const uint64_t waitEndNs = time_counter_now();
        if (timeoutNs != UINT64_MAX && waitEndNs >= waitStartNs &&
            waitEndNs - waitStartNs > timeoutNs) {
            note_latency_sample(runtimeReactorWakeOvershootLatency,
                                waitEndNs - waitStartNs - timeoutNs);
        }
#endif
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

    void set_fail(JobState& job, [[maybe_unused]] const char* reason, int rc, uint32_t errorOffset, int backendRc = 0) {
        if (job.failed.exchange(true, std::memory_order_acq_rel)) {
            return;
        }
        job.result.rc = rc ? rc : SCE_KERNEL_ERROR_EIO;
        job.result.errorOffset = errorOffset;
        clear_cursor_read_wait_hint(job.prioIndex);
        finish_job_processing(job);
        abandon_job_cursor_read_chains(job);
        AMPR_CRITICAL_LOGF("apr.reactor.fail job=0x%llx reason=%s rc=0x%x backendRc=0x%x errorOffset=0x%x cursorRead=%u active=%u",
                  (unsigned long long)job.id,
                  reason ? reason : "unknown",
                  job.result.rc,
                  backendRc,
                  job.result.errorOffset,
                  job.cursorReadChain != nullptr ? 1u : 0u,
                  job.activeReadCount);
    }

    void set_command_error(JobState& job, const char* reason, int rc, uint32_t errorOffset, int backendRc = 0) {
        if (job_failed(job) || job.hasCommandError) {
            return;
        }
        job.hasCommandError = true;
        set_fail(job, reason, rc, errorOffset, backendRc);
        AMPR_CRITICAL_LOGF("apr.reactor.command.error job=0x%llx reason=%s rc=0x%x backendRc=0x%x errorOffset=0x%x active=%u action=stop-cursor",
                  (unsigned long long)job.id,
                  reason ? reason : "unknown",
                  job.result.rc,
                  backendRc,
                  job.result.errorOffset,
                  job.activeReadCount);
    }


    bool set_or_defer_read_command_error(JobState& job,
                                         const char* reason,
                                         int rc,
                                         uint32_t errorOffset,
                                         int backendRc = 0) {
#if AMPR_EMU_APR_AIO_CROSS_EOP_READAHEAD
        if (!job_failed(job) && job.crossEopScanActive &&
            errorOffset > job.sourceOffset &&
            errorOffset <= job.crossEopScanOffset) {
            if (job.crossEopDeferredErrorOffset == UINT32_MAX ||
                errorOffset < job.crossEopDeferredErrorOffset) {
                job.crossEopDeferredErrorOffset = errorOffset;
                job.crossEopDeferredErrorRc = rc;
                job.crossEopDeferredBackendRc = backendRc;
                job.crossEopDeferredErrorReason = reason;
                drop_unsubmitted_cross_eop_suffix(job, errorOffset);
                AMPR_CRITICAL_LOGF("apr.reactor.crossEop.error.defer job=0x%llx sourceOffset=0x%x errorOffset=0x%x rc=0x%x backendRc=0x%x reason=%s",
                                   (unsigned long long)job.id,
                                   job.sourceOffset,
                                   errorOffset,
                                   rc,
                                   backendRc,
                                   reason ? reason : "unknown");
            }
            return true;
        }
#endif
        set_command_error(job, reason, rc, errorOffset, backendRc);
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
        const int backendRc = job.crossEopDeferredBackendRc;
        const char* const reason = job.crossEopDeferredErrorReason;
        job.crossEopDeferredErrorOffset = UINT32_MAX;
        job.crossEopDeferredErrorRc = 0;
        job.crossEopDeferredBackendRc = 0;
        job.crossEopDeferredErrorReason = nullptr;
        set_command_error(job,
                          reason ? reason : "cross-eop-read",
                          rc,
                          errorOffset,
                          backendRc);
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

    void reserve_staged_aio_admission(AioAdmissionContext& context,
                                      const ActiveRead& active,
                                      uint64_t stageTimeNs) {
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
        if (stageTimeNs != 0 &&
            (context.snapshot.oldestSubmittedTimeNs == 0 ||
             stageTimeNs < context.snapshot.oldestSubmittedTimeNs)) {
            context.snapshot.oldestSubmittedTimeNs = stageTimeNs;
        }
        context.laneNowNs = stageTimeNs;
        context.laneNowValid = true;
        refresh_aio_snapshot_age(context.snapshot, stageTimeNs);
        update_aio_age_throttle(stageTimeNs, context.snapshot);
        context.effectiveLimit =
            aio_effective_read_limit(stageTimeNs, context.snapshot);
    }

    enum class DirectReadSubmitResult : uint8_t {
        Pending,
        Failed,
    };

    struct DirectReadSubmitOutcome {
        DirectReadSubmitResult result{DirectReadSubmitResult::Failed};
        const char* errorReason{};
        int errorRc{};
        uint32_t errorOffset{};
        int backendRc{};

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
        const uint32_t limit = context.effectiveLimit;
        const size_t activeCount = context.snapshot.activeCount;
        if (activeCount >= limit) {
            // activeReads is the reactor's last-known conservative view.  A
            // request may already be complete in the kernel, but until a real
            // AIO poll observes that completion the slot remains unavailable.
            // Remember the admission pressure; the *next* reactor pass may
            // perform a bounded capacity probe without blocking this queue pass.
            passReadBlockedOnAioCapacity = true;
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
        return fd_budget_available_for_read(ownerDesc, context.directFdCap);
    }

    static size_t aio_submit_batch_index(int aioPriority) {
        if (aioPriority == SCE_KERNEL_AIO_PRIORITY_HIGH) {
            return 0u;
        }
        if (aioPriority == SCE_KERNEL_AIO_PRIORITY_MID) {
            return 1u;
        }
        if (aioPriority == SCE_KERNEL_AIO_PRIORITY_LOW) {
            return 2u;
        }
        AMPR_KLOGF("ampr.abort reason=apr.reactor.aio.submit.batch-priority.invalid file=%s line=%d", __FILE__, __LINE__);
        std::abort();
    }

    void begin_aio_submit_round() {
        for (const AioSubmitBatch& batch : aioSubmitRound.batches) {
            if (batch.count != 0) {
                AMPR_KLOGF("ampr.abort reason=apr.reactor.aio.submit.round.not-empty file=%s line=%d", __FILE__, __LINE__);
                std::abort();
            }
        }
        aioSubmitRound.batches[0].aioPriority = SCE_KERNEL_AIO_PRIORITY_HIGH;
        aioSubmitRound.batches[1].aioPriority = SCE_KERNEL_AIO_PRIORITY_MID;
        aioSubmitRound.batches[2].aioPriority = SCE_KERNEL_AIO_PRIORITY_LOW;
    }

    void stage_aio_submit(ActiveRead& active, bool resubmit) {
        const size_t batchIndex = aio_submit_batch_index(active.aioPrio);
        AioSubmitBatch& batch = aioSubmitRound.batches[batchIndex];
        if (batch.count >= kMaxActiveReads || active.aioId >= 0 ||
            active.awaitingBatchSubmit ||
            (resubmit != active.awaitingResubmit)) {
            AMPR_KLOGF("ampr.abort reason=apr.reactor.aio.submit.stage.invalid file=%s line=%d", __FILE__, __LINE__);
            std::abort();
        }
        const size_t item = batch.count++;
        batch.requests[item] = active.request;
        batch.ids[item] = static_cast<SceKernelAioSubmitId>(-1);
        batch.items[item] = ActiveReadRef{
            active.listSlot,
            active.listGeneration,
        };
        active.awaitingBatchSubmit = true;
    }

    void rollback_staged_aio_admission(AioAdmissionContext& admission,
                                       const ActiveRead& active) {
        if (!admission.initialized || admission.snapshot.activeCount == 0) {
            AMPR_KLOGF("ampr.abort reason=apr.reactor.aio.admission.batch-rollback.invalid file=%s line=%d", __FILE__, __LINE__);
            std::abort();
        }
        --admission.snapshot.activeCount;
        if (aio_desc_is_small_for_boost(active.desc)) {
            if (admission.snapshot.smallCount == 0) {
                AMPR_KLOGF("ampr.abort reason=apr.reactor.aio.admission.batch-small.underflow file=%s line=%d", __FILE__, __LINE__);
                std::abort();
            }
            --admission.snapshot.smallCount;
        }
        if (active.job && active.job->prioIndex < kPriorityCount) {
            const size_t groupIndex = read_group_index(
                read_group_for_priority(active.job->prioIndex));
            if (admission.snapshot.groupActive[groupIndex] == 0) {
                AMPR_KLOGF("ampr.abort reason=apr.reactor.aio.admission.batch-group.underflow file=%s line=%d", __FILE__, __LINE__);
                std::abort();
            }
            --admission.snapshot.groupActive[groupIndex];
        }
    }

    bool aio_submit_id_is_unique(SceKernelAioSubmitId id,
                                 const AioSubmitBatch& batch,
                                 size_t item) const {
        if (id < 0) {
            return false;
        }
        for (const ActiveRead& active : activeReads) {
            if (active_read_is_submitted(active) && active.aioId == id) {
                return false;
            }
        }
        for (size_t prior = 0; prior < item; ++prior) {
            if (batch.ids[prior] == id) {
                return false;
            }
        }
        return true;
    }

    void detach_staged_read_chain(JobPtr job, ReadChain* chain) {
        if (!job || !chain) {
            return;
        }
        if (job->cursorReadChain == chain) {
            job->cursorReadChain = nullptr;
            return;
        }
#if AMPR_EMU_APR_AIO_CROSS_EOP_READAHEAD
        if (job->crossEopReadChain == chain) {
            job->crossEopReadChain = nullptr;
        }
#endif
    }

    void accept_aio_submit_item(const ActiveReadRef& item,
                                SceKernelAioSubmitId aioId,
                                uint64_t submitTimeNs) {
        ActiveRead* const active = activeReads.active_at_slot(
            item.slot, item.generation);
        if (!active || !active->job || !active->chain ||
            active->aioPrio < SCE_KERNEL_AIO_PRIORITY_LOW ||
            active->aioPrio > SCE_KERNEL_AIO_PRIORITY_HIGH) {
            AMPR_KLOGF("ampr.abort reason=apr.reactor.aio.submit.accept.stale file=%s line=%d", __FILE__, __LINE__);
            std::abort();
        }
        JobPtr job = active->job;
        ReadChain* const chain = active->chain;
        const bool resubmit = active->awaitingResubmit;
        mark_active_read_submitted(*active, aioId);
        active->submitTimeNs = submitTimeNs;
        active->retryNotBeforeNs = 0;
        active->aioDeleteRetries = 0;
        active->aioDeleteFirstFailureNs = 0;
#if AMPR_EMU_DEBUG_LOG
        active->pollAttempts = 0;
#endif

        if (!resubmit) {
            if (chain->seq == 0) {
                chain->seq = active->seq;
                ++job->nextReadSeq;
                job->latestSubmittedReadSeq = active->seq;
            }
            active->seq = chain->seq;
            const uint64_t issuedLength = active->desc.length;
            if (issuedLength == 0 || issuedLength > chain->remaining) {
                AMPR_KLOGF("ampr.abort reason=apr.reactor.aio.submit.accept.range file=%s line=%d", __FILE__, __LINE__);
                std::abort();
            }
            chain->remaining -= issuedLength;
            chain->nextBuffer = reinterpret_cast<void*>(
                reinterpret_cast<uintptr_t>(chain->nextBuffer) +
                static_cast<uintptr_t>(issuedLength));
            chain->nextOffset += issuedLength;
#if AMPR_EMU_DEBUG_LOG
            if (chain->remaining != 0) {
                chain->sliceReadyTimeNs = submitTimeNs;
            }
            note_native_trigger_to_aio_submit(active->nativeTriggerTimeNs,
                                              submitTimeNs);
            note_read_ready_to_aio_submit(active->sliceReadyTimeNs,
                                          submitTimeNs,
                                          job->prioIndex);
            note_job_queue_to_first_aio_submit(*job, submitTimeNs);
#endif
        }
#if AMPR_EMU_DEBUG_LOG
        note_accepted_aio_request(active->desc.length, job->prioIndex);
#endif
        arm_active_read_poll_after_submit(*active, submitTimeNs);
    }

    void reject_aio_submit_item(const ActiveReadRef& item,
                                int submitSceRc,
                                uint64_t submitTimeNs,
                                AioAdmissionContext* admission) {
        ActiveRead* const active = activeReads.active_at_slot(
            item.slot, item.generation);
        if (!active || !active->job || !active->chain) {
            AMPR_KLOGF("ampr.abort reason=apr.reactor.aio.submit.reject.stale file=%s line=%d", __FILE__, __LINE__);
            std::abort();
        }
        JobPtr job = active->job;
        ReadChain* const chain = active->chain;
        const uint32_t errorOff = active->desc.errorOff;

        if (active->awaitingResubmit) {
            if (!active->awaitingBatchSubmit) {
                AMPR_KLOGF("ampr.abort reason=apr.reactor.aio.resubmit.reject.state file=%s line=%d", __FILE__, __LINE__);
                std::abort();
            }
            active->awaitingBatchSubmit = false;
            if (apr_aio_submit_sce_rc_is_deferred(submitSceRc)) {
                active->retryNotBeforeNs =
                    submitTimeNs + AMPR_EMU_APR_AIO_SUBMIT_RETRY_DELAY_NS;
                return;
            }
            detach_staged_read_chain(job, chain);
            chain->allIssued = true;
            set_or_defer_read_command_error(
                *job,
                "aio-resubmit",
                apr_backend_read_error_to_apr(submitSceRc),
                errorOff);
            apr_release_aio_read_desc(active->desc);
            decrement_active_read_count(job);
            decrement_read_chain_active(chain, active->readCreditBytes);
            (void)erase_active_read(
                activeReads.iterator_from_slot(item.slot));
            maybe_finish_read_chain(chain);
            maybe_release_reactor_job(job);
            return;
        }

        if (!active->awaitingBatchSubmit || active->awaitingResubmit || !admission) {
            AMPR_KLOGF("ampr.abort reason=apr.reactor.aio.submit.reject.state file=%s line=%d", __FILE__, __LINE__);
            std::abort();
        }
        rollback_staged_aio_admission(*admission, *active);
        active->awaitingBatchSubmit = false;
        apr_release_aio_read_desc(active->desc);
        decrement_active_read_count(job);
        decrement_read_chain_active(chain, active->readCreditBytes);
        (void)erase_active_read(activeReads.iterator_from_slot(item.slot));
        if (apr_aio_submit_sce_rc_is_deferred(submitSceRc)) {
            chain->retryNotBeforeNs =
                submitTimeNs + AMPR_EMU_APR_AIO_SUBMIT_RETRY_DELAY_NS;
            return;
        }

        detach_staged_read_chain(job, chain);
        chain->allIssued = true;
        maybe_finish_read_chain(chain);
        if (!job_failed(*job)) {
            set_or_defer_read_command_error(
                *job,
                "aio-submit",
                apr_backend_read_error_to_apr(submitSceRc),
                errorOff);
        }
        maybe_release_reactor_job(job);
    }

    bool flush_aio_submit_round(AioAdmissionContext* admission) {
        bool progressedAny = false;
        bool hasItems = false;
        for (const AioSubmitBatch& batch : aioSubmitRound.batches) {
            hasItems |= batch.count != 0;
        }
        if (!hasItems) {
            return false;
        }

        ensure_aio_initialized();
        for (AioSubmitBatch& batch : aioSubmitRound.batches) {
            if (batch.count == 0) {
                continue;
            }
            const int submitRc = sceKernelAioSubmitReadCommandsMultiple(
                batch.requests,
                static_cast<int>(batch.count),
                batch.aioPriority,
                batch.ids);
            const uint64_t submitTimeNs = time_counter_now();
            const int submitSceRc = apr_aio_api_rc_to_sce(submitRc);
            note_aio_submit_result(submitSceRc, batch.count);

            bool inconsistent = false;
            for (size_t item = 0; item < batch.count; ++item) {
                if ((submitRc == 0 && batch.ids[item] < 0) ||
                    (submitRc != 0 && batch.ids[item] >= 0) ||
                    (submitRc == 0 &&
                     !aio_submit_id_is_unique(batch.ids[item], batch, item))) {
                    inconsistent = true;
                }
            }
            if (inconsistent) {
                AMPR_CRITICAL_LOGF("apr.reactor.aio.submit.multiple.inconsistent rc=0x%x count=%zu prio=%d action=abort",
                                   submitSceRc,
                                   batch.count,
                                   batch.aioPriority);
                AMPR_KLOGF("ampr.abort reason=apr.reactor.aio.submit.multiple.inconsistent file=%s line=%d", __FILE__, __LINE__);
                std::abort();
            }

            const size_t itemCount = batch.count;
            batch.count = 0;
            for (size_t item = 0; item < itemCount; ++item) {
                if (submitRc == 0) {
                    accept_aio_submit_item(batch.items[item],
                                           batch.ids[item],
                                           submitTimeNs);
                    progressedAny = true;
                } else {
                    reject_aio_submit_item(batch.items[item],
                                           submitSceRc,
                                           submitTimeNs,
                                           admission);
                    progressedAny |=
                        !apr_aio_submit_sce_rc_is_deferred(submitSceRc);
                }
            }
        }
        return progressedAny;
    }

    DirectReadSubmitOutcome submit_read_chain_slice(JobPtr& job,
                                                     ReadChain& chain,
                                                     ReadIssueBudget& issueBudget,
                                                     AioAdmissionContext& admission) {
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
            return {DirectReadSubmitResult::Pending, nullptr, 0, 0};
        }
        if (!issueBudget.can_admit(sliceCreditBytes)) {
            return {DirectReadSubmitResult::Pending, nullptr, 0, 0};
        }
        const uint64_t nowNs = aio_admission_lane_now(admission);
        if (chain.retryNotBeforeNs != 0) {
            if (nowNs < chain.retryNotBeforeNs) {
                return {DirectReadSubmitResult::Pending, nullptr, 0, 0};
            }
            chain.retryNotBeforeNs = 0;
        }
        if (!direct_read_admission_available(job->prioIndex,
                                             chain.ownerDesc,
                                             sliceDesc,
                                             nowNs,
                                             admission)) {
            return {DirectReadSubmitResult::Pending, nullptr, 0, 0};
        }

        if (chain.ownerDesc.fd < 0) {
            int acquireRc = 0;
            uint32_t acquireErrorOff = chain.ownerDesc.errorOff;
            const bool allowNewFd = !admission.fdPressure;
            const bool acquired = apr_acquire_aio_read_desc(job->id,
                                                            chain.ownerDesc,
                                                            allowNewFd,
                                                            admission.directFdCap,
                                                            &acquireRc,
                                                            &acquireErrorOff);
            if (!acquired) {
                if (apr_fd_acquire_sce_rc_is_deferred(acquireRc)) {
                    const uint64_t failureNowNs = time_counter_now();
                    if (acquireRc == SCE_KERNEL_ERROR_EMFILE) {
                        note_emfile_event();
                    }
                    // A real open EAGAIN/EMFILE/ENFILE publishes pressure in
                    // the fd layer. A local admission EAGAIN does not. Sample
                    // the generation for every deferred result so the two cases
                    // stay distinct without another result/status channel.
                    if (fd_pressure_active(failureNowNs)) {
                        admission.current = false;
                    }
                    chain.retryNotBeforeNs =
                        failureNowNs + AMPR_EMU_APR_AIO_SUBMIT_RETRY_DELAY_NS;
                    return {DirectReadSubmitResult::Pending, nullptr, 0, 0};
                }
                chain.allIssued = true;
                const int aprRc = apr_backend_read_error_to_apr(acquireRc);
                const char* const errorReason =
                    apr_backend_read_error_reason("aio-acquire-fd", acquireRc);
                AMPR_CRITICAL_LOGF("apr.reactor.acquire.error-map job=0x%llx fileId=%u reason=%s backendRc=0x%x aprRc=0x%x errorOffset=0x%x",
                                   (unsigned long long)job->id,
                                   chain.ownerDesc.fileId,
                                   errorReason,
                                   acquireRc,
                                   aprRc,
                                   acquireErrorOff);
                return {DirectReadSubmitResult::Failed,
                        errorReason,
                        aprRc,
                        acquireErrorOff,
                        acquireRc};
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

        const int aioPriority = apr_aio_priority_from_apr(job->prioIndex);
        active.aioPrio = aioPriority;
        issueBudget.consume(active.readCreditBytes);
        stage_aio_submit(active, false);
        // Reserve this candidate in the pass-local admission snapshot before
        // later lanes are examined. Use the real lane timestamp so provisional
        // batching cannot reset age throttling to time zero; a rejected array
        // submit rolls the count/group credits back at flush time.
        reserve_staged_aio_admission(admission, active, nowNs);

        // Source ownership remains parked until the array submit succeeds.
        // flush_aio_submit_round() updates the chain, and the next reactor pass
        // commits the already accepted range to the packed source cursor.
        return {DirectReadSubmitResult::Pending, nullptr, 0, 0};
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
#if !AMPR_EMU_APR_LOCAL_EQUEUE
            case OpType::WriteEqueue:
#endif
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
                op.type == OpType::WriteEqueue ||
                software_op_uses_native_apr_batch(op.type)) &&
               !software_op_is_sop(op);
    }

#if AMPR_EMU_APR_EAGER_NATIVE_EQUEUE
    static bool eager_native_record_type(OpType type) {
        return software_op_uses_native_apr_batch(type);
    }

    int analyze_eager_native_event_plan(JobState& job) {
        job.eagerNativeArenaAllocation = UINT32_MAX;
        job.eagerNativeArenaOffset = 0;
        job.eagerNativeArenaBytes = 0;
        job.eagerNativeEventProgressOffset = 0;
        job.eagerNativeEventFirstSourceOffset = 0;
        job.eagerNativeEventCount = 0;
        job.eagerNativeEventCursor = 0;
        job.eagerNativeEventReleaseCursor = 0;
        job.eagerNativeEventCommandBytes = 0;
        job.eagerNativeEventSubmitId = 0;
        job.eagerNativeEventFirstToken = 0;
        job.eagerNativeCounterWaitTarget = 0;
        job.eagerNativeEventLastReleaseNs = 0;
        job.eagerNativeEventLastWatchdogNs = 0;
        job.eagerNativeEventPlan = false;
        job.eagerNativeEventQueueLinked = false;
        job.eagerNativeEventAllReleased = false;
        job.eagerNativeEventQueueNext = nullptr;

        const auto finalizePlan = [&job]() -> int {
            job.eagerNativeEventPlan = job.eagerNativeEventCount != 0;
            if (!job.eagerNativeEventPlan) {
                return 0;
            }
            const uint64_t progressOffset =
                (static_cast<uint64_t>(job.eagerNativeEventCommandBytes) + 7u) &
                ~7ull;
            const uint64_t requiredBytes = progressOffset + sizeof(uint64_t);
            const uint64_t arenaBytes =
                (requiredBytes + kAprNativeEventArenaAlignment - 1u) &
                ~(static_cast<uint64_t>(kAprNativeEventArenaAlignment) - 1u);
            if (arenaBytes > kAprNativeEventArenaBytes ||
                progressOffset > UINT32_MAX) {
                job.eagerNativeEventPlan = false;
                job.eagerNativeEventCount = 0;
                return SCE_KERNEL_ERROR_E2BIG;
            }
            job.eagerNativeEventProgressOffset =
                static_cast<uint32_t>(progressOffset);
            job.eagerNativeArenaBytes = static_cast<uint32_t>(arenaBytes);
            return 0;
        };

#if AMPR_EMU_APR_LOCAL_EQUEUE
        // The overlay's runtime native fallback must remain wholly owned by the
        // proven persistent batch. Do not combine that A/B configuration with
        // an eagerly submitted native FIFO on the same APR priority.
        return 0;
#endif

        // AMM micro-submits always use native High/0. A closed eager gate on
        // the same A53 priority could otherwise sit ahead of an older AMM map
        // from this or an earlier job. Priority 0 therefore uses the bounded
        // just-in-time APR micro path below instead of a pre-submitted sidecar.
        if (job.prioIndex == kAprNativeMicroAmmPriority) {
            return 0;
        }

        uint32_t offset = 0;
        uint32_t commandIndex = 0;
        while (offset < job.sourceBytes) {
            Op op{};
            uint32_t opBytes = 0;
            uint32_t errorOffset = offset;
            const int rc = sce::Ampr::ampr_decode_apr_packed_op(
                job.sourceBuffer,
                job.sourceBytes,
                offset,
                &op,
                &opBytes,
                &errorOffset);
            if (rc != 0 || opBytes == 0 || opBytes > job.sourceBytes - offset) {
                // Preserve asynchronous decode/error behavior.  A malformed
                // suffix remains cursor-owned. Native records in the valid
                // prefix still use this FIFO and are never replayed through the
                // persistent batch.
                return finalizePlan();
            }
            op.bufOffsetBytes = offset;
            if (eager_native_record_type(op.type)) {
                if (opBytes > kAprNativeEventPacketMaxBytes ||
                    job.eagerNativeEventCount >= kAprNativeEventMaxPerJob) {
                    job.eagerNativeEventCount = 0;
                    return SCE_KERNEL_ERROR_E2BIG;
                }
                if (job.eagerNativeEventCount == 0) {
                    job.eagerNativeEventFirstSourceOffset = offset;
                }
                const uint64_t commandBytes =
                    static_cast<uint64_t>(job.eagerNativeEventCommandBytes) +
                    kAprNativeEventGateBytes + opBytes +
                    kAprNativeEventCheckpointBytes;
                if (commandBytes > UINT32_MAX) {
                    job.eagerNativeEventCount = 0;
                    return SCE_KERNEL_ERROR_E2BIG;
                }
                job.eagerNativeEventCommandBytes =
                    static_cast<uint32_t>(commandBytes);
                ++job.eagerNativeEventCount;
            }
            offset += opBytes;
            ++commandIndex;
        }
        if (offset != job.sourceBytes || commandIndex != job.commandCount) {
            return finalizePlan();
        }
        return finalizePlan();
    }

    bool submit_eager_native_event_sidecar(JobState& job) {
        if (!job.eagerNativeEventPlan || job.eagerNativeEventCount == 0 ||
            job.eagerNativeEventCount > kAprNativeEventMaxPerJob) {
            return false;
        }
        if (!ensure_native_execution_pool()) {
            return false;
        }
        uint8_t* const commands = eager_native_event_commands(job);
        volatile uint64_t* const progress = eager_native_event_progress(job);
        SceAprResultBuffer* const result =
            apr_native_event_result(job.poolSlot);
        if (!commands || !progress || !result ||
            job.eagerNativeEventCommandBytes == 0 ||
            job.eagerNativeEventCommandBytes >
                job.eagerNativeEventProgressOffset) {
            return false;
        }

        __atomic_store_n(progress, 0ull, __ATOMIC_RELAXED);
        result->errorOffset = 0;
        __atomic_store_n(&result->result,
                         kAprNativeEventResultPending,
                         __ATOMIC_RELAXED);

        SceAmprCommandBuffer commandView{};
        commandView.buffer = commands;
        commandView.bufsize = job.eagerNativeEventProgressOffset;
        uint64_t& laneNextToken = eagerNativeNextToken[job.prioIndex];
        if (laneNextToken < kAprNativeEventTokenBase) {
            laneNextToken = kAprNativeEventTokenBase;
        }
        const uint64_t firstToken = laneNextToken + 1u;
        const uint64_t lastToken = firstToken +
            static_cast<uint64_t>(job.eagerNativeEventCount) - 1u;
        if (firstToken == 0 || lastToken < firstToken) {
            AMPR_KLOGF("ampr.abort reason=apr.reactor.native.fifo.token.wrap file=%s line=%d", __FILE__, __LINE__);
            std::abort();
        }
        job.eagerNativeEventFirstToken = firstToken;
        laneNextToken = lastToken;
        volatile uint64_t* const laneRelease =
            apr_native_event_lane_release_ptr(job.prioIndex);
        if (!laneRelease) {
            return false;
        }

        uint32_t commandOffset = 0;
        uint32_t sourceOffset = 0;
        uint32_t recordIndex = 0;
        while (sourceOffset < job.sourceBytes) {
            Op op{};
            uint32_t packedBytes = 0;
            uint32_t errorOffset = sourceOffset;
            const int decodeRc = sce::Ampr::ampr_decode_apr_packed_op(
                job.sourceBuffer,
                job.sourceBytes,
                sourceOffset,
                &op,
                &packedBytes,
                &errorOffset);
            if (decodeRc != 0 || packedBytes == 0 ||
                packedBytes > job.sourceBytes - sourceOffset) {
                if (recordIndex != job.eagerNativeEventCount) {
                    return false;
                }
                break;
            }
            if (!eager_native_record_type(op.type)) {
                sourceOffset += packedBytes;
                continue;
            }
            if (recordIndex >= job.eagerNativeEventCount ||
                packedBytes > kAprNativeEventPacketMaxBytes) {
                return false;
            }
            const uint64_t recordToken = firstToken + recordIndex;
            const bool nopOnCancel = op.type != OpType::WriteEqueue;

            Op gate{};
            gate.type = OpType::WaitOnAddress;
            gate.ptra = const_cast<uint64_t*>(laneRelease);
            gate.u64a = recordToken;
            gate.u32a = static_cast<uint32_t>(
                sce::Ampr::WaitCompare::kGreaterThanOrEqualWrapped);
            // Event packets remain immutable and only need a door gate. Counter
            // records retain refetch because error cancellation may replace an
            // unconsumed packet with an equal-sized NOP after native submit.
            gate.u32c = static_cast<uint32_t>(
                nopOnCancel
                    ? sce::Ampr::WaitFlush::kEnable
                    : sce::Ampr::WaitFlush::kDisable);
            const int gateRc = sce::Ampr::ampr_strict_write_op(
                &commandView,
                commandOffset,
                gate,
                kAprNativeEventGateBytes);
            if (gateRc != 0) {
                return false;
            }
            commandOffset += kAprNativeEventGateBytes;

            if (commandOffset + packedBytes >
                job.eagerNativeEventProgressOffset) {
                return false;
            }
            std::memcpy(commands + commandOffset,
                        job.sourceBuffer + sourceOffset,
                        packedBytes);
            commandOffset += packedBytes;

            Op checkpoint{};
            checkpoint.type = OpType::WriteAddress;
            checkpoint.ptra = const_cast<uint64_t*>(progress);
            checkpoint.u64a = recordToken;
            checkpoint.u8a = 0;
            const int checkpointRc = sce::Ampr::ampr_strict_write_op(
                &commandView,
                commandOffset,
                checkpoint,
                kAprNativeEventCheckpointBytes);
            if (checkpointRc != 0) {
                return false;
            }
            commandOffset += kAprNativeEventCheckpointBytes;
            ++recordIndex;
            sourceOffset += packedBytes;
        }
        if (recordIndex != job.eagerNativeEventCount ||
            commandOffset != job.eagerNativeEventCommandBytes ||
            commandOffset > job.eagerNativeEventProgressOffset) {
            return false;
        }

        NativeAprCommandBufferView nativeCommandBuffer{};
        nativeCommandBuffer.m_commandBuffer.type = job.nativeSubmitType;
        nativeCommandBuffer.m_commandBuffer.offset = commandOffset;
        nativeCommandBuffer.m_commandBuffer.num =
            static_cast<int32_t>(job.eagerNativeEventCount * 3u);
        nativeCommandBuffer.m_commandBuffer.bufsize = job.eagerNativeArenaBytes;
        nativeCommandBuffer.m_commandBuffer.buffer = commands;
        std::atomic_thread_fence(std::memory_order_seq_cst);

        int submitRcRaw = 0;
        SceAprSubmitId submitId = 0;
        const int dispatchRc = apr_native_submit_dispatch(
            reinterpret_cast<sce::Ampr::AprCommandBuffer*>(&nativeCommandBuffer),
            job.prioIndex,
            AprSubmitMode::kSubmitAndGetResult,
            result,
            &submitId,
            &submitRcRaw);
        const int submitRc = dispatchRc != 0
            ? dispatchRc
            : apr_libkernel_rc_to_sce(submitRcRaw);
        if (submitRc != 0 || submitId == 0) {
            AMPR_VLOGF("apr.reactor.native.fifo.submit.fail job=0x%llx lane=%u records=%u rc=0x%x raw=0x%x",
                       (unsigned long long)job.id,
                       (unsigned)job.prioIndex,
                       (unsigned)job.eagerNativeEventCount,
                       submitRc != 0 ? submitRc : SCE_KERNEL_ERROR_EIO,
                       submitRcRaw);
            return false;
        }

        job.eagerNativeEventCommandBytes = commandOffset;
        job.eagerNativeEventSubmitId = submitId;
        AMPR_TLOGF("apr.reactor.native.fifo.submit job=0x%llx lane=%u records=%u submitId=0x%x bytes=0x%x first=0x%llx last=0x%llx release=%p progress=%p flush=selective",
                   (unsigned long long)job.id,
                   (unsigned)job.prioIndex,
                   (unsigned)job.eagerNativeEventCount,
                   submitId,
                   commandOffset,
                   (unsigned long long)firstToken,
                   (unsigned long long)lastToken,
                   (void*)const_cast<uint64_t*>(laneRelease),
                   (void*)const_cast<uint64_t*>(progress));
        return true;
    }

    void link_eager_native_event_job_locked(JobState& job) {
        if (!job.eagerNativeEventPlan || job.eagerNativeEventQueueLinked ||
            job.prioIndex >= kPriorityCount) {
            return;
        }
        JobPtr& tail = eagerNativeEventQueueTails[job.prioIndex];
        job.eagerNativeEventQueueNext = nullptr;
        if (tail) {
            tail->eagerNativeEventQueueNext = &job;
        } else {
            eagerNativeEventQueueHeads[job.prioIndex] = &job;
        }
        tail = &job;
        job.eagerNativeEventQueueLinked = true;
    }

    static uint64_t eager_native_record_token(const JobState& job,
                                              uint32_t recordIndex) {
        return job.eagerNativeEventFirstToken + recordIndex;
    }

    uint32_t eager_native_source_error_offset(
        const JobState& job,
        uint32_t nativeErrorOffset) const {
        uint32_t sourceOffset = 0;
        uint32_t nativeOffset = 0;
        uint32_t lastNativeSourceOffset =
            job.eagerNativeEventFirstSourceOffset;
        while (sourceOffset < job.sourceBytes) {
            Op op{};
            uint32_t opBytes = 0;
            uint32_t decodeErrorOffset = sourceOffset;
            const int decodeRc = sce::Ampr::ampr_decode_apr_packed_op(
                job.sourceBuffer,
                job.sourceBytes,
                sourceOffset,
                &op,
                &opBytes,
                &decodeErrorOffset);
            if (decodeRc != 0 || opBytes == 0 ||
                opBytes > job.sourceBytes - sourceOffset) {
                break;
            }
            if (eager_native_record_type(op.type)) {
                lastNativeSourceOffset = sourceOffset;
                const uint32_t nativeRecordBytes =
                    kAprNativeEventGateBytes + opBytes +
                    kAprNativeEventCheckpointBytes;
                if (nativeErrorOffset < nativeOffset + nativeRecordBytes) {
                    return sourceOffset;
                }
                nativeOffset += nativeRecordBytes;
            }
            sourceOffset += opBytes;
        }
        return lastNativeSourceOffset;
    }

    bool advance_eager_native_event_release_fifo(uint32_t laneIndex) {
        if (laneIndex >= kPriorityCount) {
            return false;
        }
        volatile uint64_t* const laneRelease =
            apr_native_event_lane_release_ptr(laneIndex);
        if (!laneRelease) {
            return false;
        }

        bool progressed = false;
        bool haveReleaseToken = false;
        uint64_t releaseToken = 0;
        const uint64_t releaseTimeNs = time_counter_now();
        for (;;) {
            bool stopAfterHead = false;
            bool logReady = false;
            uint64_t readyJobId = 0;
            uint32_t readyFrontier = 0;
            uint32_t readyCount = 0;
            uint64_t readyToken = 0;
            {
                AmprLockGuard lk(m);
                JobPtr const head = eagerNativeEventQueueHeads[laneIndex];
                if (!head || head->eagerNativeEventPreparePending.load(
                                 std::memory_order_acquire)) {
                    stopAfterHead = true;
                } else if (!head->eagerNativeEventPlan ||
                           head->eagerNativeEventCount == 0) {
                    AMPR_KLOGF("ampr.abort reason=apr.reactor.native.event.fifo.invalid file=%s line=%d", __FILE__, __LINE__);
                    std::abort();
                } else {
                    const uint32_t frontier = head->eagerNativeEventCursor;
                    if (frontier > head->eagerNativeEventCount ||
                        frontier < head->eagerNativeEventReleaseCursor) {
                        AMPR_KLOGF("ampr.abort reason=apr.reactor.native.event.fifo.frontier-invalid file=%s line=%d", __FILE__, __LINE__);
                        std::abort();
                    }
                    if (frontier != head->eagerNativeEventReleaseCursor) {
                        releaseToken = eager_native_record_token(
                            *head, frontier - 1u);
                        head->eagerNativeEventReleaseCursor = frontier;
                        head->eagerNativeEventLastReleaseNs = releaseTimeNs;
                        haveReleaseToken = true;
                        progressed = true;
                        logReady = true;
                        readyJobId = head->id;
                        readyFrontier = frontier;
                        readyCount = head->eagerNativeEventCount;
                        readyToken = releaseToken;
                    }
                    if (head->eagerNativeEventReleaseCursor !=
                        head->eagerNativeEventCount) {
                        stopAfterHead = true;
                    } else {
                        head->eagerNativeEventAllReleased = true;
                        eagerNativeEventQueueHeads[laneIndex] =
                            head->eagerNativeEventQueueNext;
                        if (!eagerNativeEventQueueHeads[laneIndex]) {
                            eagerNativeEventQueueTails[laneIndex] = nullptr;
                        }
                        head->eagerNativeEventQueueNext = nullptr;
                        head->eagerNativeEventQueueLinked = false;
                    }
                }
            }
            if (logReady) {
                AMPR_TLOGF("apr.reactor.native.event.fifo.ready job=0x%llx lane=%u frontier=%u/%u token=0x%llx",
                           (unsigned long long)readyJobId,
                           laneIndex,
                           readyFrontier,
                           readyCount,
                           (unsigned long long)readyToken);
            }
            if (stopAfterHead) {
                break;
            }
            // Keep scanning: if the next already-submitted job also has a
            // contiguous ready prefix, one shared-lane release store can open
            // both jobs while preserving FIFO token order.
        }

        if (haveReleaseToken) {
            // All title-visible software stores and any error-path NOP rewrites
            // for the released FIFO prefix are sequenced before publication.
            std::atomic_thread_fence(std::memory_order_release);
            __atomic_store_n(laneRelease, releaseToken, __ATOMIC_RELEASE);
            AMPR_TLOGF("apr.reactor.native.event.fifo.release lane=%u token=0x%llx",
                       laneIndex,
                       (unsigned long long)releaseToken);
        }
        return progressed;
    }

    void cancel_and_drain_eager_native_records(JobState& job) {
        if (!job.eagerNativeEventPlan || job.eagerNativeEventAllReleased) {
            return;
        }
        if (job.eagerNativeEventCursor >= job.eagerNativeEventCount) {
            return;
        }
        uint8_t* const commands = eager_native_event_commands(job);
        if (!commands) {
            AMPR_KLOGF("ampr.abort reason=apr.reactor.native.fifo.cancel.arena-null file=%s line=%d", __FILE__, __LINE__);
            std::abort();
        }
        uint32_t commandOffset = 0;
        uint32_t sourceOffset = 0;
        uint32_t recordIndex = 0;
        while (sourceOffset < job.sourceBytes) {
            Op op{};
            uint32_t opBytes = 0;
            uint32_t errorOffset = sourceOffset;
            const int decodeRc = sce::Ampr::ampr_decode_apr_packed_op(
                job.sourceBuffer,
                job.sourceBytes,
                sourceOffset,
                &op,
                &opBytes,
                &errorOffset);
            if (decodeRc != 0 || opBytes == 0 ||
                opBytes > job.sourceBytes - sourceOffset) {
                break;
            }
            if (!eager_native_record_type(op.type)) {
                sourceOffset += opBytes;
                continue;
            }
            if (recordIndex >= job.eagerNativeEventCursor &&
                op.type != OpType::WriteEqueue) {
                if (opBytes < 4u || opBytes > 20u ||
                    (opBytes & 3u) != 0 ||
                    job.eagerNativeEventCommandBytes <
                        kAprNativeEventGateBytes + 4u ||
                    commandOffset > job.eagerNativeEventCommandBytes -
                        kAprNativeEventGateBytes - 4u) {
                    AMPR_KLOGF("ampr.abort reason=apr.reactor.native.fifo.cancel.record-invalid file=%s line=%d", __FILE__, __LINE__);
                    std::abort();
                }
                const uint32_t headerIndex = opBytes / 4u - 1u;
                std::memcpy(commands + commandOffset +
                                kAprNativeEventGateBytes,
                            &nativeBatchPaddingHeaders[headerIndex],
                            sizeof(uint32_t));
            }
            commandOffset += kAprNativeEventGateBytes + opBytes +
                kAprNativeEventCheckpointBytes;
            ++recordIndex;
            sourceOffset += opBytes;
        }
        if (recordIndex != job.eagerNativeEventCount ||
            commandOffset != job.eagerNativeEventCommandBytes) {
            AMPR_KLOGF("ampr.abort reason=apr.reactor.native.fifo.cancel.scan-invalid file=%s line=%d", __FILE__, __LINE__);
            std::abort();
        }
        std::atomic_thread_fence(std::memory_order_release);
        job.eagerNativeEventCursor = job.eagerNativeEventCount;
        (void)advance_eager_native_event_release_fifo(job.prioIndex);
    }

    bool consume_eager_native_record(JobState& job,
                                    const Op& op,
                                    uint32_t opBytes) {
        if (!job.eagerNativeEventPlan || !eager_native_record_type(op.type) ||
            job.eagerNativeEventCursor >= job.eagerNativeEventCount) {
            return false;
        }
        if (!eager_native_event_commands(job) ||
            op.bufOffsetBytes != job.sourceOffset || opBytes == 0 ||
            opBytes > kAprNativeEventPacketMaxBytes) {
            AMPR_KLOGF("ampr.abort reason=apr.reactor.native.event.cursor.invalid file=%s line=%d", __FILE__, __LINE__);
            std::abort();
        }
        const uint32_t recordIndex = job.eagerNativeEventCursor;
        ++job.eagerNativeEventCursor;
        if (op.type == OpType::WaitOnCounter) {
            job.eagerNativeCounterWaitTarget =
                eager_native_record_token(job, recordIndex);
        }
        advance_job_source(job, opBytes);
        (void)advance_eager_native_event_release_fifo(job.prioIndex);
        return true;
    }

    bool eager_native_released_work_pending(const JobState& job) const {
        if (!job.eagerNativeEventPlan ||
            job.eagerNativeEventReleaseCursor == 0 ||
            job.eagerNativeEventSubmitId == 0) {
            return false;
        }
        const volatile uint64_t* const progress =
            eager_native_event_progress(job);
        if (!progress) {
            return true;
        }
        const uint64_t target = eager_native_record_token(
            job, job.eagerNativeEventReleaseCursor - 1u);
        const uint64_t observed = __atomic_load_n(
            progress, __ATOMIC_ACQUIRE);
        return !native_batch_token_reached(observed, target);
    }

    bool eager_native_counter_wait_pending(JobState& job) const {
        if (job.eagerNativeCounterWaitTarget == 0) {
            return false;
        }
        const volatile uint64_t* const progress =
            eager_native_event_progress(job);
        if (!progress) {
            return true;
        }
        const uint64_t observed = __atomic_load_n(
            progress, __ATOMIC_ACQUIRE);
        if (!native_batch_token_reached(
                observed, job.eagerNativeCounterWaitTarget)) {
            return true;
        }
        job.eagerNativeCounterWaitTarget = 0;
        return false;
    }
#endif

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
            __atomic_store_n(address, op.u64a, __ATOMIC_RELEASE);
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
            : (kSoftwareReadOffsetMaxExclusive - 1u);
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
                AMPR_LOGF("apr.reactor.readChain.pool.full job=0x%llx sourceOffset=0x%x capacity=%u activeReads=%zu action=defer",
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

        if (chain->remaining == 0) {
            // The preceding reactor pass submitted this source-owned slice as
            // part of an SDK multiple-submit call. Keep the chain attached
            // until acceptance is known, then commit the source/GS cursor here.
            chain->allIssued = true;
            chainSlot = nullptr;
            update_software_gs_cursor(gs, read);
            if (advanceSource) {
                clear_cursor_read_wait_hint(job->prioIndex);
                advance_job_source(*job, opBytes);
            }
            if (outLogicalIssued) {
                *outLogicalIssued = true;
            }
            maybe_finish_read_chain(chain);
            return true;
        }

        ReadIssueBudget singleRequestBudget{1u, kSoftwareReadChunkMax};
        ReadIssueBudget& budget = issueBudget ? *issueBudget : singleRequestBudget;
        const DirectReadSubmitOutcome outcome =
            submit_read_chain_slice(job, *chain, budget, admission);
        if (outcome.result == DirectReadSubmitResult::Pending) {
            return false;
        }

        if (advanceSource) {
            clear_cursor_read_wait_hint(job->prioIndex);
        }

        // Detach cursor ownership before publishing an error. Error publication
        // may call set_fail(), which abandons cursor chains and can synchronously
        // return an unsubmitted chain to the fixed pool. After
        // maybe_finish_read_chain(), do not dereference `chain`.
        chain->allIssued = true;
        chainSlot = nullptr;
        maybe_finish_read_chain(chain);

        if (outcome.has_error() && !job_failed(*job)) {
            set_or_defer_read_command_error(*job,
                                            outcome.errorReason,
                                            outcome.errorRc,
                                            outcome.errorOffset,
                                            outcome.backendRc);
        }
        return false;
    }

#if AMPR_EMU_APR_AIO_CROSS_EOP_READAHEAD
    bool issue_reads_across_eop_job(JobPtr& job,
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

    static bool cross_eop_scan_complete(const JobState& job) {
        return job.crossEopScanActive &&
               job.crossEopReadChain == nullptr &&
               job.crossEopDeferredErrorOffset == UINT32_MAX &&
               job.crossEopScanOffset == job.sourceBytes &&
               job.crossEopScanCommandIndex == job.commandCount;
    }

    bool issue_reads_across_eop_lane(JobPtr job,
                                     GatherScatterState& gs,
                                     ReadIssueBudget& readIssueBudget,
                                     AioAdmissionContext& admission) {
        if (!job || readIssueBudget.requestsLeft == 0 ||
            readIssueBudget.bytesLeft == 0) {
            return false;
        }

        const uint32_t laneIndex = job->prioIndex;
        for (;;) {
            // Preserve the old one-record-per-call speculative parser bound.
            // Reaching a clean end-of-job consumes no parser/read budget, so a
            // fully scanned job may expose the next FIFO job in the same lane.
            if (!cross_eop_scan_complete(*job)) {
                const bool progressed = issue_reads_across_eop_job(
                    job, gs, readIssueBudget, admission);
                if (progressed || !cross_eop_scan_complete(*job)) {
                    return progressed;
                }
            }

            JobPtr const next =
                job->priorityNext.load(std::memory_order_acquire);
            if (!next) {
                return false;
            }
            if (next->prioIndex != laneIndex) {
                AMPR_KLOGF("ampr.abort reason=apr.reactor.crossEop.priorityNext.invalid file=%s line=%d", __FILE__, __LINE__);
                std::abort();
            }
            AMPR_TLOGF("apr.reactor.crossEop.nextJob from=0x%llx to=0x%llx lane=%u",
                       (unsigned long long)job->id,
                       (unsigned long long)next->id,
                       laneIndex);
            job = next;
        }
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
                kAprNativeMicroAmmPriority,
                nullptr);
            if (submitRc == 0) {
                submitted = true;
            } else {
                set_fail(job, "native-amm-submit", submitRc, job.nativeSourceOffset);
            }
        } else if (engine == NativeMicroEngine::Apr) {
            AprNativeMicroSlot* const slot = apr_native_micro_slot(job.poolSlot);
            if (!slot || job.nativeMicroSubmitId != 0) {
                AMPR_KLOGF("ampr.abort reason=apr.reactor.native.micro.apr.state-invalid file=%s line=%d", __FILE__, __LINE__);
                std::abort();
            }
            NativeAprCommandBufferView nativeCommandBuffer{};
            nativeCommandBuffer.m_commandBuffer.type = job.nativeSubmitType;
            nativeCommandBuffer.m_commandBuffer.offset = job.nativeSubmitBytes;
            nativeCommandBuffer.m_commandBuffer.num = 2;
            nativeCommandBuffer.m_commandBuffer.bufsize =
                kAprNativeMicroCommandCapacity;
            nativeCommandBuffer.m_commandBuffer.buffer = slot->commands;
            slot->result.errorOffset = 0;
            __atomic_store_n(&slot->result.result,
                             kAprNativeMicroResultPending,
                             __ATOMIC_RELAXED);
            std::atomic_thread_fence(std::memory_order_seq_cst);

            int submitRcRaw = 0;
            SceAprSubmitId submitId = 0;
            const int dispatchRc = apr_native_submit_dispatch(
                reinterpret_cast<sce::Ampr::AprCommandBuffer*>(
                    &nativeCommandBuffer),
                job.prioIndex,
                AprSubmitMode::kSubmitAndGetResult,
                &slot->result,
                &submitId,
                &submitRcRaw);
            const int submitRc = dispatchRc != 0
                ? dispatchRc
                : apr_libkernel_rc_to_sce(submitRcRaw);
            if (submitRc == 0 && submitId != 0) {
                job.nativeMicroSubmitId = submitId;
                submitted = true;
            } else {
                set_fail(job,
                         "native-apr-micro-submit",
                         submitRc != 0 ? submitRc : SCE_KERNEL_ERROR_EIO,
                         job.nativeSourceOffset);
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
                   engine == NativeMicroEngine::Amm ? "amm" : "apr",
                   (unsigned)job.nativePrio,
                   engine == NativeMicroEngine::Amm
                       ? kAprNativeMicroAmmPriority
                       : (unsigned)job.prioIndex,
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
#if AMPR_EMU_APR_EAGER_NATIVE_EQUEUE
        if (job->eagerNativeEventPreparePending.load(std::memory_order_acquire)) {
            return false;
        }
#endif
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
            progressed |= issue_reads_across_eop_lane(
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
                if (job->sourceOffset != job->nativeSourceOffset ||
                    job->decodedOpCacheBytes != job->nativeSubmitBytes ||
                    job->decodedOpCache.bufOffsetBytes !=
                        job->nativeSourceOffset ||
                    job->decodedOpCache.type != job->nativeSourceType ||
                    !software_op_is_native_apr_eop(job->decodedOpCache) ||
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
                const uint32_t completedOpBytes = job->nativeSubmitBytes;
                if (!release_deferred_native_eop(*job, false)) {
                    AMPR_KLOGF("ampr.abort reason=apr.reactor.native.batch.deferred.cursor.invalid file=%s line=%d", __FILE__, __LINE__);
                    std::abort();
                }
                advance_job_source(*job, completedOpBytes);
                progressed = true;
            } else {
                return progressed;
            }
        }
#if AMPR_EMU_APR_EAGER_NATIVE_EQUEUE
        if (job_failed(*job) && job->eagerNativeEventPlan) {
            cancel_and_drain_eager_native_records(*job);
        }
#endif
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
#if AMPR_EMU_APR_LOCAL_EQUEUE
        bool continueWithAdjacentEqueue = false;
#endif
        while (job->sourceOffset < job->sourceBytes) {
            if (publish_deferred_cross_eop_error(*job)) {
                progressed = true;
                break;
            }
            if (native_batch_wait_pending(job->prioIndex)) {
                break;
            }
#if AMPR_EMU_APR_EAGER_NATIVE_EQUEUE
            if (eager_native_counter_wait_pending(*job)) {
                break;
            }
#endif
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

#if AMPR_EMU_APR_LOCAL_EQUEUE
            if (continueWithAdjacentEqueue) {
                continueWithAdjacentEqueue = false;
                if (op.type != OpType::WriteEqueue) {
                    cache_decoded_op(*job, op, opBytes);
                    break;
                }
#if AMPR_EMU_DEBUG_LOG
                note_log_counter(runtimeAdjacentAddressEqueuePasses);
#endif
            }
#endif

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
                    progressed |= issue_reads_across_eop_lane(job,
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
                (job->nativeSubmitted.load(std::memory_order_acquire) &&
                 job->nativeMicroEngine == NativeMicroEngine::AprBatch)
#if AMPR_EMU_APR_EAGER_NATIVE_EQUEUE
                || eager_native_released_work_pending(*job)
#endif
                ;
            uint64_t completionReadSequence = job->latestSubmittedReadSeq;
#if AMPR_EMU_APR_AIO_CROSS_EOP_READAHEAD
            if (software_op_is_eop_completion(op)) {
                completionReadSequence =
                    cross_eop_read_fence_for_cursor(*job);
                const bool softwareCompletionOrderingPending =
                    (priorNativeBatchPending || nativeBatchPending) &&
                    !software_op_uses_native_apr_batch(op.type);
                if ((priorReadFencePending ||
                     job->completedReadSeq < completionReadSequence ||
                     softwareCompletionOrderingPending) &&
                    !speculativeCommandUsed) {
                    speculativeCommandUsed = true;
                    progressed |= issue_reads_across_eop_lane(job,
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
#if AMPR_EMU_APR_EAGER_NATIVE_EQUEUE
            if (job->eagerNativeEventPlan &&
                eager_native_record_type(op.type)) {
                if (readFencePending && !software_op_is_sop(op)) {
                    cache_decoded_op(*job, op, opBytes);
                    break;
                }
                if (!consume_eager_native_record(*job, op, opBytes)) {
                    AMPR_KLOGF("ampr.abort reason=apr.reactor.native.fifo.consume.fail file=%s line=%d", __FILE__, __LINE__);
                    std::abort();
                }
                progressed = true;
                break;
            }
#if !AMPR_EMU_APR_LOCAL_EQUEUE
            if (eager_native_record_type(op.type)) {
                AMPR_KLOGF("ampr.abort reason=apr.reactor.native.fifo.unplanned-record file=%s line=%d", __FILE__, __LINE__);
                std::abort();
            }
#endif
#endif
            if (readFencePending && software_op_is_native_apr_eop(op)) {
#if AMPR_EMU_APR_EAGER_NATIVE_EQUEUE && !AMPR_EMU_APR_LOCAL_EQUEUE
                if (job->prioIndex == kAprNativeMicroAmmPriority) {
                    // The just-in-time priority-0 micro must not enter A53 until
                    // its accumulated read fence is complete.
                    cache_decoded_op(*job, op, opBytes);
                    break;
                }
#endif
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
            if (readFencePending && !software_op_is_sop(op)) {
                cache_decoded_op(*job, op, opBytes);
                break;
            }
            if ((priorNativeBatchPending || nativeBatchPending) &&
                ((!software_op_is_sop(op) &&
                  !software_op_uses_native_apr_batch(op.type)) ||
                 op.type == OpType::WriteEqueue)) {
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
                    if (op.type == OpType::WaitOnAddress) {
                        // WaitOnAddress is a synchronization primitive, not an
                        // AIO dependency.  The unified reactor wait below keeps
                        // its recheck deadline independent of all AIO deadlines.
                        passWaitOnAddressPending = true;
                    }
                    cache_decoded_op(*job, op, opBytes);
                    log_blocked_job(*job, op, "software-wait-address");
                    break;
                }
                advance_job_source(*job, opBytes);
                progressed = true;
#if AMPR_EMU_APR_EAGER_NATIVE_EQUEUE
                if (op.type == OpType::WriteAddress &&
                    job->eagerNativeEventPlan &&
                    job->eagerNativeEventCursor < job->eagerNativeEventCount &&
                    job->sourceOffset < job->sourceBytes) {
                    Op nextOp{};
                    uint32_t nextBytes = 0;
                    uint32_t errorOffset = job->sourceOffset;
                    const int decodeRc = sce::Ampr::ampr_decode_apr_packed_op(
                        job->sourceBuffer,
                        job->sourceBytes,
                        job->sourceOffset,
                        &nextOp,
                        &nextBytes,
                        &errorOffset);
                    if (decodeRc == 0 && nextBytes != 0 &&
                        nextBytes <= job->sourceBytes - job->sourceOffset &&
                        nextOp.type == OpType::WriteEqueue) {
                        nextOp.bufOffsetBytes = job->sourceOffset;
                        cache_decoded_op(*job, nextOp, nextBytes);
                        // Common Read -> WriteAddress -> WriteEvent tail: the
                        // release store and event gate are handled in this pass.
                        continue;
                    }
                }
#endif
#if AMPR_EMU_APR_LOCAL_EQUEUE
                if (op.type == OpType::WriteAddress &&
                    job->sourceOffset < job->sourceBytes) {
                    // The store is complete before decoding the one permitted
                    // adjacent local-equeue candidate. All event fence/native-
                    // order checks below still run unchanged.
                    continueWithAdjacentEqueue = true;
                    continue;
                }
#endif
                break;
            }

#if AMPR_EMU_APR_LOCAL_EQUEUE
            if (op.type == OpType::WriteEqueue) {
                const AprEqueuePublishResult publish = apr_equeue_try_publish(
                    reinterpret_cast<SceKernelEqueue>(
                        static_cast<uintptr_t>(op.u64b)),
                    static_cast<int32_t>(op.u32b),
                    op.u64a);
                if (publish == AprEqueuePublishResult::Published) {
                    advance_job_source(*job, opBytes);
                    progressed = true;
                    break;
                }
                if (publish == AprEqueuePublishResult::Backpressure) {
                    passLocalEqueueBackpressure = true;
                    cache_decoded_op(*job, op, opBytes);
                    log_blocked_job(*job, op, "local-equeue-backpressure");
                    break;
                }
                if (publish == AprEqueuePublishResult::NativeFallback) {
                    // Missing hooks, mirror, registration, or private wake
                    // support uses the unchanged native APR packet.
                    const void* const packedSource =
                        job->sourceBuffer + job->sourceOffset;
                    if (!append_native_apr_batch(*job, op, packedSource, opBytes)) {
                        if (!job_failed(*job)) {
                            cache_decoded_op(*job, op, opBytes);
                        }
                        break;
                    }
                    advance_job_source(*job, opBytes);
                    progressed = true;
                    break;
                }
                AMPR_KLOGF("ampr.abort reason=apr.reactor.local-equeue.publish.invalid file=%s line=%d", __FILE__, __LINE__);
                std::abort();
            }
#endif

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
#if AMPR_EMU_APR_EAGER_NATIVE_EQUEUE && !AMPR_EMU_APR_LOCAL_EQUEUE
                if (job->prioIndex == kAprNativeMicroAmmPriority) {
                    if (!prepare_native_micro_pair(*job,
                                                   op,
                                                   packedSource,
                                                   opBytes,
                                                   false) ||
                        !submit_native_micro(*job, NativeMicroEngine::Apr)) {
                        break;
                    }
                    advance_job_source(*job, opBytes);
                    progressed = true;
                    break;
                }
#endif
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
        begin_aio_submit_round();
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
#if AMPR_EMU_APR_EAGER_NATIVE_EQUEUE
                priorNativeBatchPending |=
                    eager_native_released_work_pending(*job);
#endif
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
        progressed |= flush_aio_submit_round(&admission);
        if (admission.initialized &&
            admission.snapshot.activeCount != activeReads.size()) {
            AMPR_KLOGF("ampr.abort reason=apr.reactor.aio.admission.context.drift file=%s line=%d", __FILE__, __LINE__);
            std::abort();
        }
        return progressed;
    }

    bool resubmit_deferred_active_reads() {
        if (deferredActiveReadCount == 0) {
            return false;
        }
        begin_aio_submit_round();
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
            stage_aio_submit(active, true);
            ++it;
        }
        progressed |= flush_aio_submit_round(nullptr);
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
    struct AioObservationResult {
        bool polled{};
        bool completed{};
    };

    struct AioPollBatch {
        ActiveReadRef items[kAioPollBatchLimit]{};
        SceKernelAioSubmitId ids[kAioPollBatchLimit]{};
        int states[kAioPollBatchLimit]{};
        size_t count{};
    };

    void stage_active_aio_poll(AioPollBatch& batch, ActiveReadIt it) {
        if (it == activeReads.end() || !active_read_is_submitted(*it) ||
            batch.count >= kAioPollBatchLimit) {
            AMPR_KLOGF("ampr.abort reason=apr.reactor.aio.poll.batch-stage.invalid file=%s line=%d", __FILE__, __LINE__);
            std::abort();
        }
        for (size_t prior = 0; prior < batch.count; ++prior) {
            if (batch.ids[prior] == it->aioId) {
                AMPR_KLOGF("ampr.abort reason=apr.reactor.aio.poll.batch-id.duplicate file=%s line=%d", __FILE__, __LINE__);
                std::abort();
            }
        }

        const size_t item = batch.count++;
        batch.items[item] = ActiveReadRef{
            it->listSlot,
            it->listGeneration,
        };
        batch.ids[item] = it->aioId;
        batch.states[item] = INT32_MIN;
        it->hotPollQueued = false;
        remove_poll_deadline(*it);
#if AMPR_EMU_DEBUG_LOG
        note_active_read_due_poll();
        if (it->pollAttempts != UINT32_MAX) {
            ++it->pollAttempts;
        }
        if (active_read_is_staged_eop_gate(*it)) {
            ++runtimeAioPollStagedEopCalls;
        } else if (active_read_can_gate_publish(*it)) {
            ++runtimeAioPollCriticalCalls;
        } else {
            ++runtimeAioPollBackgroundCalls;
        }
#endif
    }

    AioObservationResult execute_active_aio_poll_batch(AioPollBatch& batch,
                                                        uint64_t pollNow) {
        if (batch.count == 0) {
            return {};
        }
#if AMPR_EMU_DEBUG_LOG
        const uint64_t pollStartNs = time_counter_now();
#endif
        const int pollRc = sceKernelAioPollRequests(
            batch.ids,
            static_cast<int>(batch.count),
            batch.states);
#if AMPR_EMU_DEBUG_LOG
        const uint64_t pollEndNs = time_counter_now();
        note_aio_poll_call(pollEndNs >= pollStartNs ? pollEndNs - pollStartNs : 0);
#else
        const uint64_t pollEndNs = pollNow;
#endif
        if (pollRc != 0) {
            AMPR_CRITICAL_LOGF("apr.reactor.aio.poll.multiple.fail rc=0x%x count=%zu action=abort",
                               apr_aio_api_rc_to_sce(pollRc),
                               batch.count);
            AMPR_KLOGF("ampr.abort reason=apr.reactor.aio.poll.multiple.fail file=%s line=%d", __FILE__, __LINE__);
            std::abort();
        }

        size_t terminalItems[kAioPollBatchLimit]{};
        SceKernelAioSubmitId deleteIds[kAioPollBatchLimit]{};
        int deleteResults[kAioPollBatchLimit]{};
        size_t terminalCount = 0;
        for (size_t item = 0; item < batch.count; ++item) {
            ActiveRead* const active = activeReads.active_at_slot(
                batch.items[item].slot,
                batch.items[item].generation);
            if (!active || !active_read_is_submitted(*active) ||
                active->aioId != batch.ids[item]) {
                AMPR_KLOGF("ampr.abort reason=apr.reactor.aio.poll.batch-result.stale file=%s line=%d", __FILE__, __LINE__);
                std::abort();
            }
            int state = batch.states[item];
            if (state == INT32_MIN) {
                AMPR_KLOGF("ampr.abort reason=apr.reactor.aio.poll.multiple.result-unset file=%s line=%d", __FILE__, __LINE__);
                std::abort();
            }
            if (state < 0) {
                // PollRequests reports an invalid/problematic ID in the
                // corresponding states[] element. Preserve the former
                // single-ID behavior for that read only: publish its poll
                // error, retire its ID through the common delete batch, and
                // leave unrelated IDs in this batch independently usable.
                if (active->job) {
                    set_or_defer_read_command_error(
                        *active->job,
                        "aio-poll",
                        apr_backend_read_error_to_apr(
                            apr_aio_api_rc_to_sce(state)),
                        active->desc.errorOff);
                }
                state = SCE_KERNEL_AIO_STATE_ABORTED;
                batch.states[item] = state;
            }
            const int finalState = state & ~SCE_KERNEL_AIO_STATE_NOTIFIED;
            if (finalState == SCE_KERNEL_AIO_STATE_COMPLETED ||
                finalState == SCE_KERNEL_AIO_STATE_ABORTED) {
                terminalItems[terminalCount] = item;
                deleteIds[terminalCount] = active->aioId;
                deleteResults[terminalCount] = INT32_MIN;
                ++terminalCount;
            } else {
                schedule_next_active_read_poll(*active, pollEndNs);
            }
        }

        if (terminalCount == 0) {
            batch.count = 0;
            return {true, false};
        }

        const int deleteRc = sceKernelAioDeleteRequests(
            deleteIds,
            static_cast<int>(terminalCount),
            deleteResults);
        if (deleteRc != 0) {
            AMPR_CRITICAL_LOGF("apr.reactor.aio.delete.multiple.fail rc=0x%x count=%zu action=abort",
                               apr_aio_api_rc_to_sce(deleteRc),
                               terminalCount);
            AMPR_KLOGF("ampr.abort reason=apr.reactor.aio.delete.multiple.fail file=%s line=%d", __FILE__, __LINE__);
            std::abort();
        }

        bool completedAny = false;
        for (size_t terminal = 0; terminal < terminalCount; ++terminal) {
            if (deleteResults[terminal] == INT32_MIN) {
                AMPR_KLOGF("ampr.abort reason=apr.reactor.aio.delete.multiple.result-unset file=%s line=%d", __FILE__, __LINE__);
                std::abort();
            }
            const size_t item = terminalItems[terminal];
            const ActiveReadRef& batchItem = batch.items[item];
            ActiveReadIt it = activeReads.iterator_from_slot(batchItem.slot);
            if (it == activeReads.end() ||
                it->listGeneration != batchItem.generation ||
                it->aioId != batch.ids[item]) {
                AMPR_KLOGF("ampr.abort reason=apr.reactor.aio.delete.batch-result.stale file=%s line=%d", __FILE__, __LINE__);
                std::abort();
            }
            JobPtr finishedJob = it->job;
            if (!finish_active_read_after_delete(it,
                                                 batch.states[item],
                                                 deleteResults[terminal])) {
                (void)erase_active_read(it);
                if (finishedJob && !activeReads.empty()) {
                    reset_completion_frontier_active_aio_poll_for_job(*finishedJob, pollEndNs);
                }
                maybe_release_reactor_job(finishedJob);
                completedAny = true;
            } else if (!it->awaitingResubmit) {
                schedule_next_active_read_poll(*it, pollEndNs);
            }
        }
        batch.count = 0;
        return {true, completedAny};
    }

    ActiveReadIt next_capacity_probe_active_read() {
        ActiveRead* afterCursor = nullptr;
        ActiveRead* wrapped = nullptr;
        for (ActiveRead& active : activeReads) {
            if (!active_read_is_submitted(active)) {
                continue;
            }
            if (!wrapped || active.listSlot < wrapped->listSlot) {
                wrapped = &active;
            }
            if (active.listSlot > capacityPollCursorSlot &&
                (!afterCursor || active.listSlot < afterCursor->listSlot)) {
                afterCursor = &active;
            }
        }
        ActiveRead* const selected = afterCursor ? afterCursor : wrapped;
        if (!selected) {
            capacityPollCursorSlot = UINT32_MAX;
            return activeReads.end();
        }
        capacityPollCursorSlot = selected->listSlot;
        return activeReads.iterator_from_slot(selected->listSlot);
    }

    AioObservationResult poll_active_aio_reads_for_capacity(uint64_t now) {
        if (!capacityPollRequested || submittedActiveReadCount == 0 ||
            (nextCapacityPollNs != 0 && now < nextCapacityPollNs)) {
            return {};
        }

        AioPollBatch batch{};
        const size_t itemLimit =
            submittedActiveReadCount < kAioCapacityPollBatchLimit
                ? submittedActiveReadCount
                : kAioCapacityPollBatchLimit;
        while (batch.count < itemLimit) {
            ActiveReadIt it = next_capacity_probe_active_read();
            if (it == activeReads.end()) {
                break;
            }
            stage_active_aio_poll(batch, it);
        }
#if AMPR_EMU_DEBUG_LOG
        if (batch.count != 0) {
            note_log_counter(runtimeAioCapacityProbeCalls);
        }
#endif
        const AioObservationResult result =
            execute_active_aio_poll_batch(batch, now);
        if (result.polled) {
            const uint64_t afterPollNs = time_counter_now();
            nextCapacityPollNs =
                afterPollNs +
                static_cast<uint64_t>(AMPR_EMU_APR_AIO_CAPACITY_POLL_INTERVAL_NS);
        }
        return result;
    }

    AioObservationResult poll_active_aio_reads_once() {
        const uint64_t observationNow = time_counter_now();

        AioPollBatch batch{};
        while (batch.count < kAioPollBatchLimit) {
            auto hotIt = pop_hot_active_read_poll();
            if (hotIt == activeReads.end()) {
                break;
            }
            // Hot entries are queued only after their deadline is reset to now.
            // With a single reactor consumer they cannot become non-due before
            // observation, so the old defensive backoff-skip path was dead.
            stage_active_aio_poll(batch, hotIt);
        }
        while (batch.count < kAioPollBatchLimit && !activeReads.empty()) {
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
            stage_active_aio_poll(batch, dueIt);
        }

        const AioObservationResult result =
            execute_active_aio_poll_batch(batch, observationNow);
        // Polling is observation only.  Reactor sleeping is centralized in
        // worker() so command synchronization can contribute an independent
        // deadline and can never be delayed by an AIO helper.
        return result;
    }


    bool finish_active_read_after_delete(ActiveReadIt it,
                                         int state,
                                         int deleteResult) {
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
                AMPR_LOGF("apr.reactor.aio.delete.pending job=0x%llx seq=0x%llx retry=%u ageMs=%llu aioId=%d deleteResult=0x%x deleteSce=0x%x state=0x%x return=0x%llx fileId=%u",
                               job ? (unsigned long long)job->id : 0ull,
                               (unsigned long long)active.seq,
                               nextDeleteRetry,
                               (unsigned long long)(deleteFailureAgeNs / 1000000ull),
                               active.aioId,
                               deleteResult,
                               deleteResultSceRc,
                               state,
                               (unsigned long long)active.result.returnValue,
                               active.desc.fileId);
            }
            if (timedOut) {
                AMPR_CRITICAL_LOGF("apr.reactor.aio.delete.fatal job=0x%llx seq=0x%llx retry=%u ageMs=%llu aioId=%d rc=0x%x deleteResult=0x%x state=0x%x fileId=%u action=abort",
                                   job ? (unsigned long long)job->id : 0ull,
                                   (unsigned long long)active.seq,
                                   nextDeleteRetry,
                                   (unsigned long long)(deleteFailureAgeNs / 1000000ull),
                                   active.aioId,
                                   failureRc,
                                   deleteResult,
                                   state,
                                   active.desc.fileId);
                AMPR_KLOGF("ampr.abort reason=apr.reactor.aio.delete.fatal file=%s line=%d", __FILE__, __LINE__);
                std::abort();
            }
            return true;
        };
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
        note_aio_completion_poll_attempts(active.pollAttempts);
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
                log_aio_efault_detail(active,
                                      rc,
                                      state,
                                      deleteResultSceRc,
                                      errorOff,
                                      finishTimeNs);
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
            active.hotPollQueued = false;
            remove_poll_deadline(active);
            if (logCompletionRetry) {
                AMPR_LOGF("apr.reactor.aio.complete.retry-direct job=0x%llx seq=0x%llx retry=%u ammRetry=%u delayNs=%llu rc=0x%x fileId=%u buf=%p len=0x%llx off=0x%llx activeReads=%zu",
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


    void note_reactor_progress(bool progressed) {
#if AMPR_EMU_DEBUG_LOG && AMPR_EMU_APR_REACTOR_STALL_WARN_NS != 0
        if (progressed) {
            stallStartTimeNs = 0;
            stallWarningEmitted = false;
            return;
        }

        // No-progress time while the reactor is genuinely idle is not a
        // stall. Without this guard heartbeat/idle loops can emit repeated
        // false-positive stall snapshots with activeJobs=0.
        if (!has_active_lanes_locked() && activeReads.empty() &&
            liveReadChainCount == 0) {
            stallStartTimeNs = 0;
            stallWarningEmitted = false;
            return;
        }

        const uint64_t now = time_counter_now();
        if (stallStartTimeNs == 0 && now != 0) {
            stallStartTimeNs = now;
        }
        if (stallWarningEmitted) {
            return;
        }

        const bool warn =
            now != 0 && stallStartTimeNs != 0 && now >= stallStartTimeNs &&
            now - stallStartTimeNs >= AMPR_EMU_APR_REACTOR_STALL_WARN_NS;
        if (!warn) {
            return;
        }

        stallWarningEmitted = true;
        const uint64_t noProgressNs =
            now != 0 && stallStartTimeNs != 0 && now >= stallStartTimeNs
                ? now - stallStartTimeNs
                : 0;

        // A stall snapshot is diagnostic, not a fatal/invariant event.  Never
        // use AMPR_CRITICAL_LOGF here: critical logging waits for an fsync'd
        // writer flush and can itself stop the reactor for hundreds of ms,
        // turning a short WaitOnAddress/native dependency into a visible hang.
        AMPR_LOGF("apr.reactor.stall activeJobs=%zu readChains=%u activeReads=%zu noProgressMs=%llu diagnostic=async",
                  active_lane_count_locked(),
                  liveReadChainCount,
                  activeReads.size(),
                  (unsigned long long)(noProgressNs / 1000000ull));
        log_runtime_counters("stall", now, true);
        log_buffer_occupancy("stall", now);
#else
        (void)progressed;
#endif
    }

#if AMPR_EMU_DEBUG_LOG
#if AMPR_EMU_APR_REACTOR_STALL_WARN_NS != 0 || \
    AMPR_EMU_APR_REACTOR_HEARTBEAT_MS != 0
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
        const uint64_t aioPollsPerCompletionX100 =
            runtimeAioCompletionCount != 0
                ? (runtimeAioPollCalls * 100ull) / runtimeAioCompletionCount
                : 0;
        const uint64_t aioPollAttemptsPerCompletionX100 =
            runtimeAioCompletionCount != 0
                ? (runtimeAioCompletionPollAttempts * 100ull) /
                      runtimeAioCompletionCount
                : 0;
        const uint64_t windowStartNs =
            runtimeCounterWindowStartNs != 0 ? runtimeCounterWindowStartNs : now;
        const uint64_t counterWindowNs = now >= windowStartNs ? now - windowStartNs : 0;
        const uint64_t counterWindowMs = counterWindowNs / 1000000ull;
        const uint64_t workerWakeupsPerSec =
            counter_rate_per_sec(runtimeWorkerWakeups, counterWindowNs);
        const uint64_t aioDrivenWaitsPerSec =
            counter_rate_per_sec(runtimeAioDrivenWaits, counterWindowNs);

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
        AMPR_LOGF("apr.reactor.counters.runtime reason=%s aioPollCalls=%llu aioPollsPerCompletionX100=%llu aioPollAttemptsPerCompletionX100=%llu aioFirstPollCompletion=%llu aioCompletionPollAttemptsMax=%llu aioPollCriticalCalls=%llu aioPollStagedEopCalls=%llu aioPollBackgroundCalls=%llu aioCapacityProbeCalls=%llu aioCapacityBlockedPasses=%llu waitAddressBlockedPasses=%llu aioPollWorkNs=%llu aioDrivenWaitNs=%llu deadlineHeapPicks=%llu deadlineHeapFutureStops=%llu activeReadDuePolls=%llu workerWakeups=%llu workerWakeupsPerSec=%llu aioDrivenWaits=%llu aioDrivenWaitsPerSec=%llu emfile=%llu directEmfile=%llu efaultRetry=%llu efaultRetryLimit=%llu fdCacheHit=%llu fdCacheMiss=%llu fdCacheEmfile=%llu aioLimit=%u aioBaseLimit=%u aioMaxLimit=%u aioSmallBoost=%u aioThrottle=%u aioSlowCooldown=%u aioBoostCooldown=%u aioInitState=%u aioInitLastRc=0x%x aioInitAttempts=%llu aioInitOk=%llu aioInitBusy=%llu aioInitFail=%llu aioSubmitEagain=%llu",
                  reason ? reason : "unknown",
                  (unsigned long long)runtimeAioPollCalls,
                  (unsigned long long)aioPollsPerCompletionX100,
                  (unsigned long long)aioPollAttemptsPerCompletionX100,
                  (unsigned long long)runtimeAioFirstPollCompletionCount,
                  (unsigned long long)runtimeAioCompletionPollAttemptsMax,
                  (unsigned long long)runtimeAioPollCriticalCalls,
                  (unsigned long long)runtimeAioPollStagedEopCalls,
                  (unsigned long long)runtimeAioPollBackgroundCalls,
                  (unsigned long long)runtimeAioCapacityProbeCalls,
                  (unsigned long long)runtimeAioCapacityBlockedPasses,
                  (unsigned long long)runtimeWaitAddressBlockedPasses,
                  (unsigned long long)runtimeAioPollWorkNs,
                  (unsigned long long)runtimeAioDrivenWaitNs,
                  (unsigned long long)runtimeDeadlineHeapPicks,
                  (unsigned long long)runtimeDeadlineHeapFutureStops,
                  (unsigned long long)runtimeActiveReadDuePolls,
                  (unsigned long long)runtimeWorkerWakeups,
                  (unsigned long long)workerWakeupsPerSec,
                  (unsigned long long)runtimeAioDrivenWaits,
                  (unsigned long long)aioDrivenWaitsPerSec,
                  (unsigned long long)runtimeEmfileEvents,
                  (unsigned long long)directEmfile,
                  (unsigned long long)runtimeEfaultRetryEvents,
                  (unsigned long long)runtimeEfaultRetryLimitEvents,
                  (unsigned long long)fdCounters.hits,
                  (unsigned long long)fdCounters.misses,
                  (unsigned long long)fdCounters.emfile,
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
        AMPR_LOGF("apr.reactor.counters.fastpath reason=%s adjacentAddressEqueuePasses=%llu",
                  reason ? reason : "unknown",
                  (unsigned long long)runtimeAdjacentAddressEqueuePasses);
        apr_equeue_log_counters(reason, reset);
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
            runtimeAioCompletionPollAttempts = 0;
            runtimeAioFirstPollCompletionCount = 0;
            runtimeAioCompletionPollAttemptsMax = 0;
            runtimeAioPollCriticalCalls = 0;
            runtimeAioPollStagedEopCalls = 0;
            runtimeAioPollBackgroundCalls = 0;
            runtimeAioCapacityProbeCalls = 0;
            runtimeAioCapacityBlockedPasses = 0;
            runtimeWaitAddressBlockedPasses = 0;
            runtimeAioPollWorkNs = 0;
            runtimeAioDrivenWaitNs = 0;
            runtimeDeadlineHeapPicks = 0;
            runtimeDeadlineHeapFutureStops = 0;
            runtimeActiveReadDuePolls = 0;
            runtimeWorkerWakeups = 0;
            runtimeAioDrivenWaits = 0;
            runtimeAdjacentAddressEqueuePasses = 0;
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
        const size_t adaptiveDirectCap =
            apr_adaptive_direct_fd_cap(fdCaps, effectiveLimit, fdPressure);
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
                  adaptiveDirectCap,
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
                AMPR_LOGF("apr.reactor.native.batch.rollover.pending lane=%u buffer=%u generation=%u submitId=0x%x ageMs=%llu expected=0x%llx observed=0x%llx release=0x%llx status=running-or-blocked",
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

#if AMPR_EMU_APR_EAGER_NATIVE_EQUEUE
    bool eager_native_completion_observed(JobState& job) {
        if (!job.eagerNativeEventPlan || job.eagerNativeEventSubmitId == 0) {
            return true;
        }
        if (job.eagerNativeEventCount == 0 ||
            job.eagerNativeEventFirstToken == 0) {
            AMPR_KLOGF("ampr.abort reason=apr.reactor.native.fifo.completion.invalid file=%s line=%d", __FILE__, __LINE__);
            std::abort();
        }
        volatile uint64_t* const progress =
            eager_native_event_progress(job);
        SceAprResultBuffer* const resultBuffer =
            apr_native_event_result(job.poolSlot);
        if (!progress || !resultBuffer) {
            AMPR_KLOGF("ampr.abort reason=apr.reactor.native.fifo.completion.storage-null file=%s line=%d", __FILE__, __LINE__);
            std::abort();
        }
        const uint64_t target = eager_native_record_token(
            job, job.eagerNativeEventCount - 1u);
        const uint64_t observed = __atomic_load_n(progress, __ATOMIC_ACQUIRE);
        if (!native_batch_token_reached(observed, target)) {
            if (job.eagerNativeEventAllReleased) {
                const int earlyResult = __atomic_load_n(
                    &resultBuffer->result, __ATOMIC_ACQUIRE);
                const uint64_t now = time_counter_now();
                const uint64_t ageNs =
                    job.eagerNativeEventLastReleaseNs != 0 &&
                            now >= job.eagerNativeEventLastReleaseNs
                        ? now - job.eagerNativeEventLastReleaseNs
                        : 0ull;
                if (earlyResult != kAprNativeEventResultPending &&
                    earlyResult != 0) {
                    int waitRcRaw = 0;
                    const SceAprSubmitId failedSubmitId =
                        job.eagerNativeEventSubmitId;
                    const int waitDispatchRc = apr_native_wait_dispatch(
                        failedSubmitId, &waitRcRaw);
                    const int waitRc = waitDispatchRc != 0
                        ? waitDispatchRc
                        : apr_libkernel_rc_to_sce(waitRcRaw);
                    if (waitRc != 0) {
                        AMPR_CRITICAL_LOGF("apr.reactor.native.fifo.wait.fail job=0x%llx lane=%u records=%u submitId=0x%x rc=0x%x raw=0x%x result=0x%x action=abort",
                                           (unsigned long long)job.id,
                                           (unsigned)job.prioIndex,
                                           (unsigned)job.eagerNativeEventCount,
                                           failedSubmitId,
                                           waitRc,
                                           waitRcRaw,
                                           earlyResult);
                        AMPR_KLOGF("ampr.abort reason=apr.reactor.native.fifo.wait.fail file=%s line=%d", __FILE__, __LINE__);
                        std::abort();
                    }
                    set_fail(job,
                             "native-fifo-result",
                             earlyResult,
                             eager_native_source_error_offset(
                                 job, resultBuffer->errorOffset));
                    job.eagerNativeEventSubmitId = 0;
                    return true;
                }
                if (ageNs >= kNativeCompletionTimeoutNs) {
                    const bool counterWaitPending =
                        job.eagerNativeCounterWaitTarget != 0 &&
                        !native_batch_token_reached(
                            observed, job.eagerNativeCounterWaitTarget);
                    if (counterWaitPending) {
                        if (job.eagerNativeEventLastWatchdogNs == 0 ||
                            now - job.eagerNativeEventLastWatchdogNs >=
                                kNativeCompletionTimeoutNs) {
                            job.eagerNativeEventLastWatchdogNs = now;
                            AMPR_LOGF("apr.reactor.native.fifo.completion.pending job=0x%llx lane=%u records=%u submitId=0x%x target=0x%llx progress=0x%llx ageMs=%llu status=counter-wait",
                                      (unsigned long long)job.id,
                                      (unsigned)job.prioIndex,
                                      (unsigned)job.eagerNativeEventCount,
                                      job.eagerNativeEventSubmitId,
                                      (unsigned long long)target,
                                      (unsigned long long)observed,
                                      (unsigned long long)(ageNs / 1000000ull));
                        }
                        return false;
                    }
                    [[maybe_unused]] const uint64_t release = __atomic_load_n(
                        apr_native_event_lane_release_ptr(job.prioIndex),
                        __ATOMIC_ACQUIRE);
                    AMPR_CRITICAL_LOGF("apr.reactor.native.fifo.completion.timeout job=0x%llx lane=%u records=%u submitId=0x%x target=0x%llx progress=0x%llx release=0x%llx ageMs=%llu action=abort",
                                       (unsigned long long)job.id,
                                       (unsigned)job.prioIndex,
                                       (unsigned)job.eagerNativeEventCount,
                                       job.eagerNativeEventSubmitId,
                                       (unsigned long long)target,
                                       (unsigned long long)observed,
                                       (unsigned long long)release,
                                       (unsigned long long)(ageNs / 1000000ull));
                    AMPR_KLOGF("ampr.abort reason=apr.reactor.native.fifo.completion.timeout file=%s line=%d", __FILE__, __LINE__);
                    std::abort();
                }
            }
            return false;
        }

        int waitRcRaw = 0;
        const SceAprSubmitId completedSubmitId = job.eagerNativeEventSubmitId;
        const int waitDispatchRc = apr_native_wait_dispatch(
            completedSubmitId, &waitRcRaw);
        const int waitRc = waitDispatchRc != 0
            ? waitDispatchRc
            : apr_libkernel_rc_to_sce(waitRcRaw);
        if (waitRc != 0) {
            AMPR_CRITICAL_LOGF("apr.reactor.native.fifo.wait.fail job=0x%llx lane=%u records=%u submitId=0x%x rc=0x%x raw=0x%x action=abort",
                               (unsigned long long)job.id,
                               (unsigned)job.prioIndex,
                               (unsigned)job.eagerNativeEventCount,
                               completedSubmitId,
                               waitRc,
                               waitRcRaw);
            AMPR_KLOGF("ampr.abort reason=apr.reactor.native.fifo.wait.fail file=%s line=%d", __FILE__, __LINE__);
            std::abort();
        }
        const int result = __atomic_load_n(
            &resultBuffer->result, __ATOMIC_ACQUIRE);
        if (result != 0) {
            set_fail(job,
                     "native-fifo-result",
                     result,
                     eager_native_source_error_offset(
                         job, resultBuffer->errorOffset));
        }
        job.eagerNativeEventSubmitId = 0;
        AMPR_TLOGF("apr.reactor.native.fifo.complete job=0x%llx lane=%u records=%u submitId=0x%x progress=0x%llx failed=%u",
                   (unsigned long long)job.id,
                   (unsigned)job.prioIndex,
                   (unsigned)job.eagerNativeEventCount,
                   completedSubmitId,
                   (unsigned long long)observed,
                   job_failed(job) ? 1u : 0u);
        return true;
    }
#endif

    int retire_native_apr_micro_submit(JobState& job,
                                       AprNativeMicroSlot& slot) {
        if (job.nativeMicroEngine != NativeMicroEngine::Apr ||
            job.nativeMicroSubmitId == 0) {
            AMPR_KLOGF("ampr.abort reason=apr.reactor.native.micro.apr.retire-invalid file=%s line=%d", __FILE__, __LINE__);
            std::abort();
        }
        int waitRcRaw = 0;
        const SceAprSubmitId submitId = job.nativeMicroSubmitId;
        const int waitDispatchRc = apr_native_wait_dispatch(submitId, &waitRcRaw);
        const int waitRc = waitDispatchRc != 0
            ? waitDispatchRc
            : apr_libkernel_rc_to_sce(waitRcRaw);
        if (waitRc != 0) {
            AMPR_CRITICAL_LOGF("apr.reactor.native.micro.apr.wait.fail job=0x%llx lane=%u submitId=0x%x rc=0x%x raw=0x%x action=abort",
                               (unsigned long long)job.id,
                               (unsigned)job.prioIndex,
                               submitId,
                               waitRc,
                               waitRcRaw);
            AMPR_KLOGF("ampr.abort reason=apr.reactor.native.micro.apr.wait.fail file=%s line=%d", __FILE__, __LINE__);
            std::abort();
        }
        job.nativeMicroSubmitId = 0;
        return __atomic_load_n(&slot.result.result, __ATOMIC_ACQUIRE);
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
                        AMPR_LOGF("apr.reactor.native.batch.checkpoint.pending job=0x%llx lane=%u buffer=%u generation=%u targetSequence=%llu completedSequence=%llu progress=0x%llx ageMs=%llu status=running-or-blocked",
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

        const bool aprMicro =
            job.nativeMicroEngine == NativeMicroEngine::Apr;
        AprNativeMicroSlot* const microSlot = aprMicro
            ? apr_native_micro_slot(job.poolSlot)
            : nullptr;
        if (aprMicro && (!microSlot || job.nativeMicroSubmitId == 0)) {
            AMPR_KLOGF("ampr.abort reason=apr.reactor.native.micro.apr.completion-invalid file=%s line=%d", __FILE__, __LINE__);
            std::abort();
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
        bool aprTerminalError = false;
        if (aprMicro && completionValue == 0) {
            const int earlyResult = __atomic_load_n(
                &microSlot->result.result, __ATOMIC_ACQUIRE);
            if (earlyResult != kAprNativeMicroResultPending &&
                earlyResult != 0) {
                const int result = retire_native_apr_micro_submit(
                    job, *microSlot);
                set_fail(job,
                         "native-apr-micro-result",
                         result != 0 ? result : earlyResult,
                         job.nativeSourceOffset);
                aprTerminalError = true;
            }
        }
        if (completionValue == 0 && !timedOut && !aprTerminalError) {
            return false;
        }
        std::atomic_thread_fence(std::memory_order_acquire);
        if (timedOut && !aprTerminalError) {
            if (aprMicro) {
                if (job.nativeSourceType == OpType::WaitOnCounter) {
                    job.nativeSubmitTimeNs = now;
                    AMPR_LOGF("apr.reactor.native.micro.apr.pending job=0x%llx lane=%u submitId=0x%x ageMs=%llu sourceOffset=0x%x sourceType=%s status=counter-wait",
                              (unsigned long long)job.id,
                              (unsigned)job.prioIndex,
                              job.nativeMicroSubmitId,
                              (unsigned long long)(ageNs / 1000000ull),
                              job.nativeSourceOffset,
                              sce::Ampr::ampr_op_name(job.nativeSourceType));
                    return false;
                }
                AMPR_CRITICAL_LOGF("apr.reactor.native.micro.apr.completion.timeout job=0x%llx lane=%u submitId=0x%x ageMs=%llu sourceOffset=0x%x sourceType=%s action=abort",
                                   (unsigned long long)job.id,
                                   (unsigned)job.prioIndex,
                                   job.nativeMicroSubmitId,
                                   (unsigned long long)(ageNs / 1000000ull),
                                   job.nativeSourceOffset,
                                   sce::Ampr::ampr_op_name(job.nativeSourceType));
                AMPR_KLOGF("ampr.abort reason=apr.reactor.native.micro.apr.completion.timeout file=%s line=%d", __FILE__, __LINE__);
                std::abort();
            }
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
        } else if (!aprTerminalError && !job_failed(job) &&
                   (!job.nativeCompletionAddress ||
                    *job.nativeCompletionAddress != kAprNativeMicroCompletionDone)) {
            set_fail(job,
                     "native-completion-write",
                     SCE_KERNEL_ERROR_EIO,
                     job.nativeSourceOffset);
        }
        if (aprMicro && !aprTerminalError) {
            const int result = retire_native_apr_micro_submit(job, *microSlot);
            if (result != 0) {
                set_fail(job,
                         "native-apr-micro-result",
                         result,
                         job.nativeSourceOffset);
            }
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
#if AMPR_EMU_APR_EAGER_NATIVE_EQUEUE
        if (job_failed(*job) && job->eagerNativeEventPlan) {
            // NOP-cancel only still-closed counter-family records. Immutable
            // event packets are left intact and retire by gate release alone.
            cancel_and_drain_eager_native_records(*job);
        }
#endif
#if AMPR_EMU_APR_EAGER_NATIVE_EQUEUE
        if (job->eagerNativeEventSubmitId != 0 &&
            !eager_native_completion_observed(*job)) {
            return;
        }
#endif
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

            // Phase 1: AIO observation.  Completion knowledge changes only via
            // a real sceKernelAioPollRequests().  poll_active_aio_reads_once()
            // touches only hot/deadline-due requests and never sleeps.
            bool aioPolledThisPass = false;
            if (has_submitted_active_reads()) {
                const AioObservationResult normalObservation =
                    poll_active_aio_reads_once();
                progressed |= normalObservation.completed;
                aioPolledThisPass = normalObservation.polled;

                // A previous queue pass may have found ready reads while the
                // last-known AIO window was full.  If normal deadline polling
                // did not already issue a syscall in this pass, perform a
                // small rate-limited round-robin probe.  Never block the queue
                // traversal waiting for capacity to become visible.
                if (capacityPollRequested && !aioPolledThisPass) {
                    const AioObservationResult capacityObservation =
                        poll_active_aio_reads_for_capacity(time_counter_now());
                    progressed |= capacityObservation.completed;
                    aioPolledThisPass = capacityObservation.polled;
                }
                if (aioPolledThisPass) {
                    nextCapacityPollNs =
                        time_counter_now() +
                        static_cast<uint64_t>(
                            AMPR_EMU_APR_AIO_CAPACITY_POLL_INTERVAL_NS);
                }
            } else {
                capacityPollCursorSlot = UINT32_MAX;
            }

            // Retry/native maintenance uses the freshly observed AIO state.
            // A deferred resubmit retains its ActiveRead slot, so it cannot
            // make the conservative admission view overcommit the native window.
            progressed |= resubmit_deferred_active_reads();
            refresh_native_batch_progress_snapshots();
            progressed |= progress_native_batches();

            // Phase 2: exactly one fair cursor pass.  WaitOnAddress and other
            // resource-independent commands are checked here regardless of AIO.
            // ReadFile consumes only capacity that is known free from the last
            // observed state plus successful submits in this same pass.
            passWaitOnAddressPending = false;
            passReadBlockedOnAioCapacity = false;
            passLocalEqueueBackpressure = false;
            progressed |= progress_all_jobs();
            capacityPollRequested = passReadBlockedOnAioCapacity;
#if AMPR_EMU_DEBUG_LOG
            if (passWaitOnAddressPending) {
                note_log_counter(runtimeWaitAddressBlockedPasses);
            }
            if (passReadBlockedOnAioCapacity) {
                note_log_counter(runtimeAioCapacityBlockedPasses);
            }
#endif

            if (shuttingDown && native_batches_idle()) {
                AmprLockGuard lk(m);
                stop = true;
                return;
            }

            // Productive work never sleeps: go straight back to AIO observation
            // and then another queue pass.  This keeps completion -> admission
            // bubbles small without coupling command progress to AIO waits.
            if (progressed) {
                note_reactor_progress(true);
                continue;
            }

            note_reactor_progress(false);

            // Phase 3: one unified wait domain.  AIO deadlines only determine
            // when AIO should next be observed; WaitOnAddress gets its own 10 us
            // recheck deadline and therefore remains responsive even when every
            // background AIO deadline is hundreds of microseconds away.
            const uint64_t nowNs = time_counter_now();
            uint64_t waitNs = 0;
            bool aioDrivenWait = false;
            bool retryImmediately = false;
            auto consider_wait = [&](uint64_t candidateNs, bool aioDriven) {
                if (candidateNs == 0) {
                    retryImmediately = true;
                    return;
                }
                if (waitNs == 0 || candidateNs < waitNs) {
                    waitNs = candidateNs;
                    aioDrivenWait = aioDriven;
                }
            };

            if (passWaitOnAddressPending) {
                consider_wait(
                    static_cast<uint64_t>(AMPR_EMU_APR_ACTIVE_LANE_IDLE_SLEEP_NS),
                    false);
            }

            if (submittedActiveReadCount != 0) {
                consider_wait(
                    next_aio_poll_wait_ns(nowNs),
                    true);
            }

            if (capacityPollRequested && submittedActiveReadCount != 0) {
                const uint64_t capacityReadyNs = nextCapacityPollNs;
                const uint64_t capacityWaitNs =
                    capacityReadyNs == 0 || capacityReadyNs <= nowNs
                        ? 0
                        : capacityReadyNs - nowNs;
                consider_wait(capacityWaitNs, true);
            }

            if (deferredActiveReadCount != 0) {
                consider_wait(next_deferred_active_retry_wait_ns(nowNs), false);
            }

            const bool localEqueueOnlyWait =
                passLocalEqueueBackpressure &&
                submittedActiveReadCount == 0 &&
                deferredActiveReadCount == 0 &&
                native_batches_idle();
            if (localEqueueOnlyWait) {
                // The pending-node pool can change only when a hooked wait or
                // queue deletion consumes/releases synthetic events. Sleep on
                // the reactor epoch instead of polling this parked source cursor.
                consider_wait(UINT64_MAX, false);
            } else if (!passWaitOnAddressPending && has_active_lanes_locked()) {
                // Preserve the existing short recheck for non-AIO lane-local
                // dependencies (native completion, counters, etc.).  A pure
                // read-capacity block is already governed by the capacity/AIO
                // deadlines above, but taking the minimum is always safe.
                consider_wait(
                    static_cast<uint64_t>(active_lane_idle_sleep_ns()),
                    false);
            }

            if (retryImmediately) {
                continue;
            }
            if (waitNs != 0) {
#if AMPR_EMU_DEBUG_LOG
                if (aioDrivenWait) {
                    note_aio_driven_wait_count();
                    note_aio_driven_wait(waitNs);
                }
#endif
                wait_for_reactor_wake(workerObservedWakeEpoch, waitNs);
#if AMPR_EMU_DEBUG_LOG
                note_worker_wakeup();
#endif
            }
        }
    }

    // Worker-thread-only pass state.  These flags intentionally do not
    // participate in producer synchronization; they describe why the current
    // cursor pass could not advance.
    bool passWaitOnAddressPending{false};
    bool passReadBlockedOnAioCapacity{false};
    bool passLocalEqueueBackpressure{false};
    bool capacityPollRequested{false};
    uint64_t nextCapacityPollNs{0};
    uint32_t capacityPollCursorSlot{UINT32_MAX};

    AmprMutex workerLifecycleMutex;
    AmprMutex m;
    AmprConditionVariable reactorCv;
    AmprConditionVariable jobStateAvailableCv;
    AmprConditionVariable syntheticRequestAvailableCv;
    AmprConditionVariable syntheticLowerSlotAvailableCv;
    AmprConditionVariable syntheticWaitCvs[kPriorityCount];
    bool stop{false};
    std::atomic<bool> shutdownRequested{false};
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
    std::atomic<uint32_t> jobStateFreeCount{kJobStatePoolCapacity};
    std::atomic<uint32_t> jobStateWaiterCount{0};
    JobStateSlot jobStateSlots[kJobStatePoolCapacity]{};
    uint32_t jobStateFreeHead{UINT32_MAX};
    ReadChainSlot readChainSlots[kReadChainPoolCapacity]{};
    uint32_t readChainFreeHead{UINT32_MAX};
    uint32_t liveReadChainCount{};
    ActiveReadList activeReads;
    AioSubmitRound aioSubmitRound{};
    uint32_t submittedActiveReadCount{};
    uint32_t deferredActiveReadCount{};
    CursorReadWaitHint cursorReadWaitHints[kPriorityCount]{};
    AioAgeThrottleLevel aioAgeThrottleLevel{AioAgeThrottleLevel::Normal};
    uint64_t aioSmallReadBoostBlockedUntilNs{0};
    ActiveReadRef hotPollQueue[kHotPollQueueCapacity]{};
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
#if AMPR_EMU_APR_EAGER_NATIVE_EQUEUE
    std::atomic<uint32_t> eagerNativeArenaLock{0};
    EagerNativeArenaAllocation
        eagerNativeArenaAllocations[kAprNativeEventArenaAllocationCount]{};
    uint32_t eagerNativeArenaFreeHead{UINT32_MAX};
    uint32_t eagerNativeArenaQueueHead{UINT32_MAX};
    uint32_t eagerNativeArenaQueueTail{UINT32_MAX};
    uint32_t eagerNativeArenaReadOffset{};
    uint32_t eagerNativeArenaWriteOffset{};
    uint32_t eagerNativeArenaUsedBytes{};
    AmprMutex eagerNativeSubmitMutex[kPriorityCount];
    JobPtr eagerNativeEventQueueHeads[kPriorityCount]{};
    JobPtr eagerNativeEventQueueTails[kPriorityCount]{};
    uint64_t eagerNativeNextToken[kPriorityCount]{};
#endif
    NativeBatchLane nativeBatchLanes[kPriorityCount]{};
    SyntheticWaitSlot syntheticWaitSlots[kSyntheticRequestCapacity]{};
    SyntheticDoneSlot syntheticDoneSlots[kSyntheticDoneCapacity]{};
    SyntheticLowerSlot syntheticLowerSlots[kSyntheticLowerSlotCapacity]{};
    uint32_t syntheticWaitAllocCursor{};
    uint32_t syntheticDoneHead{UINT32_MAX};
    uint32_t syntheticDoneTail{UINT32_MAX};
    uint32_t syntheticDoneFreeHead{UINT32_MAX};
    uint32_t syntheticLowerAllocCursor{};
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
    uint64_t runtimeAioCompletionPollAttempts{0};
    uint64_t runtimeAioFirstPollCompletionCount{0};
    uint64_t runtimeAioCompletionPollAttemptsMax{0};
    uint64_t runtimeAioPollCriticalCalls{0};
    uint64_t runtimeAioPollStagedEopCalls{0};
    uint64_t runtimeAioPollBackgroundCalls{0};
    uint64_t runtimeAioCapacityProbeCalls{0};
    uint64_t runtimeAioCapacityBlockedPasses{0};
    uint64_t runtimeWaitAddressBlockedPasses{0};
    uint64_t runtimeAioPollWorkNs{0};
    uint64_t runtimeAioDrivenWaitNs{0};
    uint64_t runtimeDeadlineHeapPicks{0};
    uint64_t runtimeDeadlineHeapFutureStops{0};
    uint64_t runtimeActiveReadDuePolls{0};
    uint64_t runtimeWorkerWakeups{0};
    uint64_t runtimeAioDrivenWaits{0};
    uint64_t runtimeAdjacentAddressEqueuePasses{0};
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
#if AMPR_EMU_DEBUG_LOG && AMPR_EMU_APR_REACTOR_STALL_WARN_NS != 0
    uint64_t stallStartTimeNs{0};
    bool stallWarningEmitted{false};
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
    jobStateFreeCount.store(kJobStatePoolCapacity, std::memory_order_relaxed);
#if AMPR_EMU_APR_EAGER_NATIVE_EQUEUE
    for (uint32_t slot = 0;
         slot < kAprNativeEventArenaAllocationCount;
         ++slot) {
        eagerNativeArenaAllocations[slot].next =
            slot + 1u < kAprNativeEventArenaAllocationCount
                ? slot + 1u
                : UINT32_MAX;
    }
    eagerNativeArenaFreeHead =
        kAprNativeEventArenaAllocationCount != 0 ? 0u : UINT32_MAX;
#endif
    for (uint32_t slot = 0; slot < kSyntheticDoneCapacity; ++slot) {
        syntheticDoneSlots[slot].next =
            slot + 1u < kSyntheticDoneCapacity ? slot + 1u : UINT32_MAX;
    }
    syntheticDoneFreeHead = kSyntheticDoneCapacity != 0 ? 0u : UINT32_MAX;
    for (uint32_t slot = 0; slot < kSyntheticLowerSlotCapacity; ++slot) {
        syntheticLowerSlots[slot].generation = 1u;
    }
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

void apr_reactor_notify_external_progress() {
    AprAioReactor* const reactor =
        g_apr_aio_reactor.load(std::memory_order_acquire);
    if (reactor) {
        reactor->notify_external_progress();
    }
}

int apr_reactor_wait_synthetic_submit_id(SceAprSubmitId id, bool* outHandled) {
    return apr_aio_reactor().wait_synthetic_submit_id(id, outHandled);
}

int apr_reactor_submit(const Job& j, SceAprSubmitId* outSubmitId) {
    return apr_aio_reactor().submit(j, outSubmitId);
}
