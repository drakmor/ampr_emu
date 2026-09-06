/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Seekable AMPR asset-pack runtime.
 */
#include "ampr_emu_pack.h"

#include "ampr_emu_aio_broker.h"
#include "ampr_emu_errno.h"
#include "ampr_emu_fd_cache.h"
#include "ampr_emu_index.h"
#include "ampr_emu_kernel_lookup.h"
#include "ampr_emu_log.h"
#include "ampr_emu_pack_core.h"
#include "ampr_emu_runtime_memory.h"
#include "ampr_emu_sync.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <lz4.h>
#include <new>
#include <sys/dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

void apr_reactor_notify_external_progress();

#ifndef SCE_KERNEL_PATH_MAX
#define SCE_KERNEL_PATH_MAX 1024
#endif

namespace {
static_assert(AMPR_EMU_PACK_VIRTUAL_FD_SLOTS > 0 &&
                  AMPR_EMU_PACK_VIRTUAL_FD_SLOTS <= 256,
              "virtual pack FD count must fit the encoded id");
static_assert(AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS > 0 &&
                  AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS <= 256,
              "virtual pack AIO count must fit the encoded id");
static_assert(AMPR_EMU_PACK_WORKERS > 0 && AMPR_EMU_PACK_WORKERS <= 16,
              "pack worker count is outside the supported range");
static_assert(AMPR_EMU_PACK_PIPELINE_SLOTS >= AMPR_EMU_PACK_WORKERS &&
                  AMPR_EMU_PACK_PIPELINE_SLOTS <=
                      SCE_KERNEL_AIO_REQUEST_NUM_MAX,
              "pack pipeline slot count must cover workers and remain bounded");
static_assert(AMPR_EMU_PACK_PIPELINE_SLOTS == kAprExternalAioCapacity,
              "pack pipeline must cover the complete external AIO broker");
static_assert(AMPR_EMU_PACK_LATENCY_RESERVE_WORKERS < AMPR_EMU_PACK_WORKERS ||
                  AMPR_EMU_PACK_LATENCY_RESERVE_WORKERS == 0,
              "latency worker reserve must leave at least one general worker");
static_assert(AMPR_EMU_PACK_LATENCY_READ_MAX_BYTES > 0,
              "latency read threshold must be non-zero");
static_assert(AMPR_EMU_PACK_BULK_READ_MIN_BYTES >=
                  AMPR_EMU_PACK_LATENCY_READ_MAX_BYTES,
              "bulk threshold must not be below the latency threshold");
static_assert(AMPR_EMU_PACK_IO_STAGING_BYTES >=
                  2ull * (1ull << kAmprPackBlockShiftMax),
              "pack I/O staging must hold a maximally unaligned 1 MiB block");
static_assert(AMPR_EMU_PACK_PREAD_MAX_BYTES > 0,
              "physical pack-read limit must be non-zero");
static_assert(AMPR_EMU_PACK_MAX_PACKS > 0 && AMPR_EMU_PACK_MAX_PACKS <= 65535,
              "pack count must fit uint16_t");
static_assert(AMPR_EMU_PACK_OPEN_PACK_FD_CAP > 0,
              "at least one physical pack FD must be available");
static_assert((AMPR_EMU_PACK_CACHE_HASH_BUCKETS &
               (AMPR_EMU_PACK_CACHE_HASH_BUCKETS - 1u)) == 0,
              "pack cache hash bucket count must be a power of two");
static_assert((AMPR_EMU_PACK_PHYSICAL_CACHE_HASH_BUCKETS &
               (AMPR_EMU_PACK_PHYSICAL_CACHE_HASH_BUCKETS - 1u)) == 0,
              "physical page cache hash bucket count must be a power of two");
static_assert(AMPR_EMU_PACK_PHYSICAL_CACHE_ENTRY_CAP > 0,
              "physical page cache needs at least one entry");
static_assert(AMPR_EMU_PACK_INLINE_CACHE_MAX_TASKS > 0 &&
                  AMPR_EMU_PACK_INLINE_CACHE_MAX_TASKS <= 256,
              "inline decoded-cache task cap is outside the supported range");
static_assert((AMPR_EMU_PACK_TOUCH_TABLE_SIZE &
               (AMPR_EMU_PACK_TOUCH_TABLE_SIZE - 1u)) == 0,
              "pack touch table size must be a power of two");
static_assert(AMPR_EMU_PACK_CACHE_PAGE_SHIFT >= kAmprPackBlockShiftMin &&
                  AMPR_EMU_PACK_CACHE_PAGE_SHIFT <= kAmprPackBlockShiftMax,
              "pack cache page size must fit the pack block domain");

static constexpr size_t kPackMaxBlockBytes =
    static_cast<size_t>(1u) << kAmprPackBlockShiftMax;
static constexpr size_t kPackPipelineIoBytes =
    static_cast<size_t>(AMPR_EMU_PACK_IO_STAGING_BYTES);
static constexpr size_t kPackPipelineMaxIoPages =
    kPackPipelineIoBytes /
    (static_cast<size_t>(1u) << kAmprPackIoPageShiftMin);
static_assert(kPackPipelineMaxIoPages > 0 &&
                  kPackPipelineMaxIoPages <= 1024,
              "pack pipeline page plan is outside the supported range");
static constexpr size_t kPackMandatoryGroupMaxPages =
    kAprExternalAioGroupMaxRequests;
static_assert(kPackMandatoryGroupMaxPages > 1u &&
                  kPackMandatoryGroupMaxPages <= kPackPipelineMaxIoPages,
              "mandatory pack AIO group is outside the pipeline page plan");
static constexpr size_t kPackCoalescedAioMinBytes = 128u * 1024u;
static constexpr size_t kPackCoalescedAioMaxBytes = 512u * 1024u;
static_assert(kPackCoalescedAioMinBytes <= kPackCoalescedAioMaxBytes &&
                  kPackCoalescedAioMaxBytes <= kPackPipelineIoBytes,
              "coalesced pack AIO range must fit the pipeline staging window");
static constexpr size_t kPackCachePageBytes =
    static_cast<size_t>(1u) << AMPR_EMU_PACK_CACHE_PAGE_SHIFT;
static_assert(AMPR_EMU_PACK_DECODED_CACHE_MAX_BYTES % kPackCachePageBytes == 0 &&
              AMPR_EMU_PACK_PHYSICAL_CACHE_MAX_BYTES % kPackCachePageBytes == 0,
              "runtime cache ceilings must be whole cache pages");
static constexpr size_t kPackCacheMaxPages =
    static_cast<size_t>(AMPR_EMU_PACK_DECODED_CACHE_MAX_BYTES) /
    kPackCachePageBytes;
static constexpr size_t kPackCacheBitmapWords =
    (kPackCacheMaxPages + 63u) / 64u;
static constexpr size_t kPackPhysicalCacheMaxPages =
    static_cast<size_t>(AMPR_EMU_PACK_PHYSICAL_CACHE_MAX_BYTES) /
    kPackCachePageBytes;
static constexpr size_t kPackPhysicalCacheBitmapWords =
    (kPackPhysicalCacheMaxPages + 63u) / 64u;
static constexpr uint32_t kInvalidIndex = UINT32_MAX;
static constexpr uint32_t kVirtualFdTag = 0x65000000u;
static constexpr uint32_t kVirtualAioTag = 0x66000000u;
static constexpr uint32_t kVirtualDirectoryFdTag = 0x67000000u;
static constexpr uint32_t kVirtualAioGroupTag = 0x68000000u;
static constexpr uint32_t kVirtualTagMask = 0xff000000u;
static constexpr uint32_t kVirtualGenerationMask = 0xffffu;
static constexpr uint32_t kPackLoadUninitialized = 0u;
static constexpr uint32_t kPackLoadLoading = 1u;
static constexpr uint32_t kPackLoadReady = 2u;
static constexpr uint32_t kPackLoadUnavailable = 3u;
static constexpr uint32_t kPackLoadInvalid = 4u;
static constexpr uint32_t kPackCacheWaitBucketCount = 64u;
static_assert((kPackCacheWaitBucketCount &
               (kPackCacheWaitBucketCount - 1u)) == 0,
              "cache wait bucket count must be a power of two");

using KernelOpenFn = int (*)(const char*, int, ...);
using KernelCloseFn = int (*)(int);
using KernelFstatFn = int (*)(int, SceKernelStat*);
using KernelStatFn = int (*)(const char*, SceKernelStat*);
using KernelGetdentsFn = int (*)(int, char*, int);
using KernelGetdirentriesFn = int (*)(int, char*, int, long*);
using KernelPreadFn = ssize_t (*)(int, void*, size_t, off_t);
using KernelPreadvFn = ssize_t (*)(int, const SceKernelIovec*, int, off_t);
using KernelReadFn = ssize_t (*)(int, void*, size_t);
using KernelReadvFn = ssize_t (*)(int, const SceKernelIovec*, int);
using KernelLseekFn = off_t (*)(int, off_t, int);
using KernelAioSubmitFn = int (*)(SceKernelAioRWRequest*, int, int,
                                  SceKernelAioSubmitId*);
using KernelAioPollSingleFn = int (*)(SceKernelAioSubmitId, int*);
using KernelAioPollFn = int (*)(SceKernelAioSubmitId*, int, int*);
using KernelAioWaitSingleFn = int (*)(SceKernelAioSubmitId, int*,
                                      SceKernelUseconds*);
using KernelAioWaitFn = int (*)(SceKernelAioSubmitId*, int, int*, uint32_t,
                                SceKernelUseconds*);
using KernelAioCancelSingleFn = int (*)(SceKernelAioSubmitId, int*);
using KernelAioCancelFn = int (*)(SceKernelAioSubmitId*, int, int*);
using KernelAioDeleteSingleFn = int (*)(SceKernelAioSubmitId, int*);
using KernelAioDeleteFn = int (*)(SceKernelAioSubmitId*, int, int*);

static std::atomic<void*> g_real_open{nullptr};
static std::atomic<void*> g_real_close{nullptr};
static std::atomic<void*> g_real_sce_close{nullptr};
static std::atomic<void*> g_real_fstat{nullptr};
static std::atomic<void*> g_real_stat{nullptr};
static std::atomic<void*> g_real_getdents{nullptr};
static std::atomic<void*> g_real_getdirentries{nullptr};
static std::atomic<void*> g_real_pread{nullptr};
static std::atomic<void*> g_real_preadv{nullptr};
static std::atomic<void*> g_real_read{nullptr};
static std::atomic<void*> g_real_readv{nullptr};
static std::atomic<void*> g_real_lseek{nullptr};
static std::atomic<void*> g_real_aio_submit_single{nullptr};
static std::atomic<void*> g_real_aio_submit{nullptr};
static std::atomic<void*> g_real_aio_poll_single{nullptr};
static std::atomic<void*> g_real_aio_poll{nullptr};
static std::atomic<void*> g_real_aio_wait_single{nullptr};
static std::atomic<void*> g_real_aio_wait{nullptr};
static std::atomic<void*> g_real_aio_cancel_single{nullptr};
static std::atomic<void*> g_real_aio_cancel{nullptr};
static std::atomic<void*> g_real_aio_delete_single{nullptr};
static std::atomic<void*> g_real_aio_delete{nullptr};

template <typename Fn>
static Fn resolve_cached(std::atomic<void*>& slot, const char* symbol) {
    void* value = slot.load(std::memory_order_acquire);
    if (!value) {
        value = amprResolveLibkernelFunction(symbol);
        if (value) {
            slot.store(value, std::memory_order_release);
        }
    }
    return reinterpret_cast<Fn>(value);
}

static KernelOpenFn real_open() {
    if (KernelOpenFn fn = ampr_fixed_kernel_slot<KernelOpenFn>(
            kAmprLibkernelHook_open)) return fn;
    return resolve_cached<KernelOpenFn>(g_real_open, "open");
}
static KernelCloseFn real_close() {
#if AMPR_EMU_PACK_ENABLE && (AMPR_EMU_PACK_DIRECTORY_OVERLAY_ENABLE || AMPR_EMU_PACK_PROCESS_OPEN_ENABLE)
    if (KernelCloseFn fn = ampr_fixed_kernel_slot<KernelCloseFn>(
            kAmprLibkernelHook_close)) return fn;
#endif
    return resolve_cached<KernelCloseFn>(g_real_close, "close");
}
static KernelCloseFn real_sce_close() {
#if AMPR_EMU_PACK_ENABLE && (AMPR_EMU_PACK_DIRECTORY_OVERLAY_ENABLE || AMPR_EMU_PACK_PROCESS_OPEN_ENABLE)
    if (KernelCloseFn fn = ampr_fixed_kernel_slot<KernelCloseFn>(
            kAmprLibkernelHook_sceKernelClose)) return fn;
#endif
    return resolve_cached<KernelCloseFn>(g_real_sce_close, "sceKernelClose");
}
static KernelFstatFn real_fstat() {
#if AMPR_EMU_PACK_ENABLE && (AMPR_EMU_PACK_DIRECTORY_OVERLAY_ENABLE || AMPR_EMU_PACK_PROCESS_OPEN_ENABLE)
    if (KernelFstatFn fn = ampr_fixed_kernel_slot<KernelFstatFn>(
            kAmprLibkernelHook_fstat)) return fn;
#endif
    return resolve_cached<KernelFstatFn>(g_real_fstat, "fstat");
}
static KernelStatFn real_stat() {
    if (KernelStatFn fn = ampr_fixed_kernel_slot<KernelStatFn>(
            kAmprLibkernelHook_stat)) return fn;
    return resolve_cached<KernelStatFn>(g_real_stat, "stat");
}
static KernelGetdentsFn real_getdents() {
#if AMPR_EMU_PACK_ENABLE && AMPR_EMU_PACK_DIRECTORY_OVERLAY_ENABLE
    if (KernelGetdentsFn fn = ampr_fixed_kernel_slot<KernelGetdentsFn>(
            kAmprLibkernelHook_getdents)) return fn;
#endif
    return resolve_cached<KernelGetdentsFn>(g_real_getdents, "getdents");
}
static KernelGetdirentriesFn real_getdirentries() {
#if AMPR_EMU_PACK_ENABLE && AMPR_EMU_PACK_DIRECTORY_OVERLAY_ENABLE
    if (KernelGetdirentriesFn fn = ampr_fixed_kernel_slot<KernelGetdirentriesFn>(
            kAmprLibkernelHook_getdirentries)) return fn;
#endif
    return resolve_cached<KernelGetdirentriesFn>(
        g_real_getdirentries, "getdirentries");
}
static KernelPreadFn real_pread() {
#if AMPR_EMU_PACK_ENABLE && AMPR_EMU_PACK_INTERCEPT_PROCESS_SYNC_READS
    if (KernelPreadFn fn = ampr_fixed_kernel_slot<KernelPreadFn>(
            kAmprLibkernelHook_pread)) return fn;
#endif
    return resolve_cached<KernelPreadFn>(g_real_pread, "pread");
}
[[maybe_unused]] static KernelPreadvFn real_preadv() {
#if AMPR_EMU_PACK_ENABLE && AMPR_EMU_PACK_INTERCEPT_PROCESS_SYNC_READS
    if (KernelPreadvFn fn = ampr_fixed_kernel_slot<KernelPreadvFn>(
            kAmprLibkernelHook_preadv)) return fn;
#endif
    return resolve_cached<KernelPreadvFn>(g_real_preadv, "preadv");
}
[[maybe_unused]] static KernelReadFn real_read() {
#if AMPR_EMU_PACK_ENABLE && AMPR_EMU_PACK_INTERCEPT_PROCESS_SYNC_READS
    if (KernelReadFn fn = ampr_fixed_kernel_slot<KernelReadFn>(
            kAmprLibkernelHook_read)) return fn;
#endif
    return resolve_cached<KernelReadFn>(g_real_read, "read");
}
[[maybe_unused]] static KernelReadvFn real_readv() {
#if AMPR_EMU_PACK_ENABLE && AMPR_EMU_PACK_INTERCEPT_PROCESS_SYNC_READS
    if (KernelReadvFn fn = ampr_fixed_kernel_slot<KernelReadvFn>(
            kAmprLibkernelHook_readv)) return fn;
#endif
    return resolve_cached<KernelReadvFn>(g_real_readv, "readv");
}
static KernelLseekFn real_lseek() {
#if AMPR_EMU_PACK_ENABLE && (AMPR_EMU_PACK_DIRECTORY_OVERLAY_ENABLE || AMPR_EMU_PACK_PROCESS_OPEN_ENABLE)
    if (KernelLseekFn fn = ampr_fixed_kernel_slot<KernelLseekFn>(
            kAmprLibkernelHook_lseek)) return fn;
#endif
    return resolve_cached<KernelLseekFn>(g_real_lseek, "lseek");
}
static KernelAioSubmitFn real_aio_submit() {
#if AMPR_EMU_PACK_ENABLE && AMPR_EMU_PACK_INTERCEPT_PROCESS_AIO
    if (KernelAioSubmitFn fn = ampr_fixed_kernel_slot<KernelAioSubmitFn>(
            kAmprLibkernelHook_sceKernelAioSubmitReadCommandsMultiple)) return fn;
#endif
    return resolve_cached<KernelAioSubmitFn>(
        g_real_aio_submit, "sceKernelAioSubmitReadCommandsMultiple");
}
static KernelAioSubmitFn real_aio_submit_single() {
#if AMPR_EMU_PACK_ENABLE && AMPR_EMU_PACK_INTERCEPT_PROCESS_AIO
    if (KernelAioSubmitFn fn = ampr_fixed_kernel_slot<KernelAioSubmitFn>(
            kAmprLibkernelHook_sceKernelAioSubmitReadCommands)) return fn;
#endif
    return resolve_cached<KernelAioSubmitFn>(
        g_real_aio_submit_single, "sceKernelAioSubmitReadCommands");
}
static KernelAioPollSingleFn real_aio_poll_single() {
#if AMPR_EMU_PACK_ENABLE && AMPR_EMU_PACK_INTERCEPT_PROCESS_AIO
    if (KernelAioPollSingleFn fn =
            ampr_fixed_kernel_slot<KernelAioPollSingleFn>(
                kAmprLibkernelHook_sceKernelAioPollRequest)) return fn;
#endif
    return resolve_cached<KernelAioPollSingleFn>(
        g_real_aio_poll_single, "sceKernelAioPollRequest");
}
static KernelAioPollFn real_aio_poll() {
#if AMPR_EMU_PACK_ENABLE && AMPR_EMU_PACK_INTERCEPT_PROCESS_AIO
    if (KernelAioPollFn fn = ampr_fixed_kernel_slot<KernelAioPollFn>(
            kAmprLibkernelHook_sceKernelAioPollRequests)) return fn;
#endif
    return resolve_cached<KernelAioPollFn>(
        g_real_aio_poll, "sceKernelAioPollRequests");
}
static KernelAioWaitSingleFn real_aio_wait_single() {
#if AMPR_EMU_PACK_ENABLE && AMPR_EMU_PACK_INTERCEPT_PROCESS_AIO
    if (KernelAioWaitSingleFn fn =
            ampr_fixed_kernel_slot<KernelAioWaitSingleFn>(
                kAmprLibkernelHook_sceKernelAioWaitRequest)) return fn;
#endif
    return resolve_cached<KernelAioWaitSingleFn>(
        g_real_aio_wait_single, "sceKernelAioWaitRequest");
}
static KernelAioWaitFn real_aio_wait() {
#if AMPR_EMU_PACK_ENABLE && AMPR_EMU_PACK_INTERCEPT_PROCESS_AIO
    if (KernelAioWaitFn fn = ampr_fixed_kernel_slot<KernelAioWaitFn>(
            kAmprLibkernelHook_sceKernelAioWaitRequests)) return fn;
#endif
    return resolve_cached<KernelAioWaitFn>(
        g_real_aio_wait, "sceKernelAioWaitRequests");
}
static KernelAioCancelSingleFn real_aio_cancel_single() {
#if AMPR_EMU_PACK_ENABLE && AMPR_EMU_PACK_INTERCEPT_PROCESS_AIO
    if (KernelAioCancelSingleFn fn =
            ampr_fixed_kernel_slot<KernelAioCancelSingleFn>(
                kAmprLibkernelHook_sceKernelAioCancelRequest)) return fn;
#endif
    return resolve_cached<KernelAioCancelSingleFn>(
        g_real_aio_cancel_single, "sceKernelAioCancelRequest");
}
static KernelAioCancelFn real_aio_cancel() {
#if AMPR_EMU_PACK_ENABLE && AMPR_EMU_PACK_INTERCEPT_PROCESS_AIO
    if (KernelAioCancelFn fn = ampr_fixed_kernel_slot<KernelAioCancelFn>(
            kAmprLibkernelHook_sceKernelAioCancelRequests)) return fn;
#endif
    return resolve_cached<KernelAioCancelFn>(
        g_real_aio_cancel, "sceKernelAioCancelRequests");
}
static KernelAioDeleteSingleFn real_aio_delete_single() {
#if AMPR_EMU_PACK_ENABLE && AMPR_EMU_PACK_INTERCEPT_PROCESS_AIO
    if (KernelAioDeleteSingleFn fn =
            ampr_fixed_kernel_slot<KernelAioDeleteSingleFn>(
                kAmprLibkernelHook_sceKernelAioDeleteRequest)) return fn;
#endif
    return resolve_cached<KernelAioDeleteSingleFn>(
        g_real_aio_delete_single, "sceKernelAioDeleteRequest");
}
static KernelAioDeleteFn real_aio_delete() {
#if AMPR_EMU_PACK_ENABLE && AMPR_EMU_PACK_INTERCEPT_PROCESS_AIO
    if (KernelAioDeleteFn fn = ampr_fixed_kernel_slot<KernelAioDeleteFn>(
            kAmprLibkernelHook_sceKernelAioDeleteRequests)) return fn;
#endif
    return resolve_cached<KernelAioDeleteFn>(
        g_real_aio_delete, "sceKernelAioDeleteRequests");
}
static int close_physical_pack_fd(int fd) {
    if (fd < 0) return 0;
    KernelCloseFn closeFn = real_close();
    if (!closeFn) return SCE_KERNEL_ERROR_EIO;
    const int rc = closeFn(fd);
    if (rc == 0) {
        ampr_index_fd_pack_note_close();
    } else {
        AMPR_CRITICAL_LOGF("apr.pack.fd.close.fail fd=%d rc=0x%x", fd, rc);
    }
    return rc == -1 ? ampr_sce_errno_from_posix(errno) : rc;
}

static bool checked_add_u64(uint64_t a, uint64_t b, uint64_t* out) {
    if (!out || a > UINT64_MAX - b) return false;
    *out = a + b;
    return true;
}

static size_t align_up_size(size_t value, size_t alignment) {
    if (alignment == 0 || (alignment & (alignment - 1u)) != 0 ||
        value > SIZE_MAX - (alignment - 1u)) {
        return SIZE_MAX;
    }
    return (value + alignment - 1u) & ~(alignment - 1u);
}

static uint64_t align_down_u64(uint64_t value, uint64_t alignment) {
    return value & ~(alignment - 1u);
}

static bool align_up_u64(uint64_t value, uint64_t alignment, uint64_t* out) {
    if (!out || alignment == 0 || (alignment & (alignment - 1u)) != 0 ||
        value > UINT64_MAX - (alignment - 1u)) {
        return false;
    }
    *out = (value + alignment - 1u) & ~(alignment - 1u);
    return true;
}

static uint64_t mix64(uint64_t value) {
    value ^= value >> 30u;
    value *= 0xbf58476d1ce4e5b9ull;
    value ^= value >> 27u;
    value *= 0x94d049bb133111ebull;
    value ^= value >> 31u;
    return value;
}

struct VirtualFdSlot {
    uint32_t fileId{};
    uint64_t cursor{};
    uint16_t generation{};
    bool active{};
    bool processOpen{};
};

static constexpr uint32_t kDirectoryPhysicalHashCap = 512u;

struct VirtualDirectorySlot {
    int realFd{-1};
    long directoryOffset{};
    uint32_t rangeBegin{};
    uint32_t rangeEnd{};
    uint32_t virtualCursor{};
    uint32_t physicalHashCount{};
    uint16_t generation{};
    uint16_t pathLength{};
    bool active{};
    bool realExhausted{};
    bool dotEmitted{};
    bool dotDotEmitted{};
    bool physicalHashOverflow{};
    char path[SCE_KERNEL_PATH_MAX]{};
    uint64_t physicalNameHashes[kDirectoryPhysicalHashCap]{};
};

enum class VirtualAioPhase : uint8_t {
    Free,
    Reserved,
    Queued,
    Running,
    WaitingCache,
    WaitingFd,
    IoQueued,
    Done,
};

enum class PackWorkClass : uint8_t {
    Latency = 0,
    Balanced = 1,
    Bulk = 2,
    Count = 3,
};

static constexpr uint32_t kPackWorkClassCount =
    static_cast<uint32_t>(PackWorkClass::Count);

struct VirtualAioSlot {
    SceKernelAioRWRequest request{};
    uint32_t fileId{};
    uint32_t next{kInvalidIndex};
    uint32_t pipelineIndex{kInvalidIndex};
    uint16_t generation{};
    uint8_t priority{};
    PackWorkClass workClass{PackWorkClass::Balanced};
    bool processOrigin{};
    bool waitNotified{};
#if AMPR_EMU_PACK_TELEMETRY
    uint64_t queuedAtUsec{};
    uint64_t admittedAtUsec{};
#endif
    VirtualAioPhase phase{VirtualAioPhase::Free};
    std::atomic<bool> cancelRequested{false};
    int completionState{};
    int64_t returnValue{};
};

struct VirtualAioGroupSlot {
    SceKernelAioSubmitId children[SCE_KERNEL_AIO_REQUEST_NUM_MAX]{};
    uint16_t generation{};
    uint16_t childCount{};
    int deleteResult{};
    bool active{};
    bool waitNotified{};
    bool hasNativeChildren{};
};

struct PackHandle {
    int fd{-1};
    uint32_t pins{};
    uint64_t lastUse{};
    uint64_t payloadBegin{};
    uint64_t payloadEnd{};
    bool opening{};
};

enum class CacheEntryState : uint8_t {
    Free,
    Loading,
    Ready,
    Failed,
};

struct CacheEntry {
    uint64_t keyHash{};
    uint64_t physicalOffset{};
    uint32_t storedSize{};
    uint32_t rawSize{};
    uint32_t pageStart{};
    uint32_t pageCount{};
    uint32_t pinCount{};
    uint32_t hashNextPlusOne{};
    uint32_t freeNext{kInvalidIndex};
    uint16_t packId{};
    CacheEntryState state{CacheEntryState::Free};
    bool referenced{};
    int error{};
};

struct TouchEntry {
    uint64_t keyHash{};
    uint8_t count{};
};

enum class PhysicalCacheEntryState : uint8_t {
    Free,
    Loading,
    Ready,
    Failed,
};

struct PhysicalCacheEntry {
    uint64_t keyHash{};
    uint64_t physicalOffset{};
    uint32_t size{};
    uint32_t pageStart{};
    uint32_t pageCount{};
    uint32_t pinCount{};
    uint32_t hashNextPlusOne{};
    uint32_t freeNext{kInvalidIndex};
    uint16_t packId{};
    PhysicalCacheEntryState state{PhysicalCacheEntryState::Free};
    bool referenced{};
    int error{};
};

struct PhysicalCacheLease {
    uint32_t entry{kInvalidIndex};
    uint8_t* data{};
    bool loader{};
    int error{};
};

enum class PhysicalCacheAcquireKind : uint8_t {
    Bypass,
    Ready,
    Load,
    Pending,
    Failed,
};

struct PhysicalCacheAcquireResult {
    PhysicalCacheAcquireKind kind{PhysicalCacheAcquireKind::Bypass};
    PhysicalCacheLease lease{};
};

struct PhysicalCachePublication {
    PhysicalCacheLease* lease{};
    int error{};
};

struct PhysicalCacheAcquireBatchItem {
    PhysicalCacheAcquireResult* result{};
    uint64_t offset{};
    uint32_t size{};
    uint16_t packId{};
};

struct PipelineMandatoryPage {
    PhysicalCacheAcquireResult acquired{};
    uint64_t offset{};
    uint32_t size{};
    uint32_t requestIndex{kInvalidIndex};
    uint32_t stagingOffset{kInvalidIndex};
    uint16_t packId{UINT16_MAX};
};

struct CacheLease {
    uint32_t entry{kInvalidIndex};
    uint8_t* data{};
    bool loader{};
    int error{};
};

enum class CacheAcquireKind : uint8_t {
    Bypass,
    Ready,
    Load,
    Pending,
    Failed,
};

struct CacheAcquireResult {
    CacheAcquireKind kind{CacheAcquireKind::Bypass};
    CacheLease lease{};
};

struct WorkerContext {
    uint32_t index{};
    ScePthread thread{};
    uint8_t* decodedScratch{};
    size_t decodedScratchSize{};
    bool started{};
};

struct PipelineIoRange {
    uint64_t offset{};
    uint32_t length{};
    uint32_t ioPageSize{};
    uint16_t packId{UINT16_MAX};
};

enum class CacheWaitDomain : uint8_t {
    Decoded,
    Physical,
};

enum class PipelineStep : uint8_t {
    Ready,
    YieldIo,
    YieldCache,
    YieldFd,
    Complete,
    Failed,
};

// Physical-window state belongs to an in-progress logical read, not to the
// pthread that happens to decode it. The context stays retained across native
// AIO completion and a different worker may resume its decode continuation.
struct ReadPipelineContext {
    uint32_t nextFree{kInvalidIndex};
    uint32_t owner{kInvalidIndex};
    uint8_t* ioScratch{};
    size_t ioScratchSize{};
    uint64_t ioWindowOffset{};
    uint32_t ioWindowSize{};
    uint16_t ioWindowPackId{UINT16_MAX};
    bool ioWindowValid{};
    const uint8_t* ioWindowData{};
    PipelineIoRange ioRange{};
    bool active{};
    size_t taskIndex{};
    size_t taskCount{};
    CacheLease decodedLease{};
    PhysicalCacheAcquireResult ioPages[kPackPipelineMaxIoPages]{};
    size_t ioPageCount{};
    PipelineMandatoryPage
        mandatoryPages[kPackMandatoryGroupMaxPages]{};
    size_t mandatoryPageCount{};
    size_t mandatoryTaskEnd{};
    size_t mandatorySkipTask{SIZE_MAX};
    SceKernelAioRWRequest
        mandatoryRequests[kPackMandatoryGroupMaxPages]{};
    SceKernelAioResult
        mandatoryResults[kPackMandatoryGroupMaxPages]{};
    bool mandatoryRequestUsesScratch[kPackMandatoryGroupMaxPages]{};
    uint16_t mandatoryFdPackIds[kPackMandatoryGroupMaxPages]{};
    int mandatoryFds[kPackMandatoryGroupMaxPages]{};
    size_t mandatoryRequestCount{};
    size_t mandatoryFdCount{};
    bool mandatoryPlanActive{};
    int packFd{-1};
    SceKernelAioRWRequest nativeRequest{};
    SceKernelAioResult nativeResult{};
#if AMPR_EMU_PACK_TELEMETRY
    uint64_t nativeSubmittedAtUsec{};
#endif
    uint64_t cacheWaitEpoch{};
    uint16_t cacheWaitBucket{};
    CacheWaitDomain cacheWaitDomain{CacheWaitDomain::Decoded};
    uint64_t fdWaitEpoch{};
    uint64_t fdBudgetWaitEpoch{};
    int nativeIoError{};
    bool nativeCompletionReady{};
    bool nativeAccepted{};
    bool nativeSubmitted{};
};

#if AMPR_EMU_PACK_TELEMETRY
using PackTelemetryCounter = std::atomic<uint64_t>;
#else
struct PackTelemetryCounter {
    constexpr PackTelemetryCounter(uint64_t = 0) noexcept {}
    uint64_t load(std::memory_order = std::memory_order_relaxed) const noexcept {
        return 0;
    }
    uint64_t exchange(uint64_t,
                      std::memory_order = std::memory_order_seq_cst) noexcept {
        return 0;
    }
    uint64_t fetch_add(uint64_t,
                       std::memory_order = std::memory_order_seq_cst) noexcept {
        return 0;
    }
    uint64_t fetch_sub(uint64_t,
                       std::memory_order = std::memory_order_seq_cst) noexcept {
        return 0;
    }
};
#endif

struct AtomicPackStats {
    PackTelemetryCounter logicalLatency[32]{};
    PackTelemetryCounter latencyClassLatency[32]{};
    PackTelemetryCounter physicalLatency[32]{};
    PackTelemetryCounter queueLatency[32]{};
    PackTelemetryCounter workerLatency[32]{};
    PackTelemetryCounter deliveredBytes{0};
    PackTelemetryCounter logicalFailures{0};
    PackTelemetryCounter virtualOpens{0};
    PackTelemetryCounter aioSubmitted{0};
    PackTelemetryCounter aioCompleted{0};
    PackTelemetryCounter logicalBytes{0};
    PackTelemetryCounter physicalBytes{0};
    PackTelemetryCounter physicalReadOps{0};
    PackTelemetryCounter physicalReadSamples{0};
    PackTelemetryCounter physicalReadUsecTotal{0};
    PackTelemetryCounter physicalReadUsecMax{0};
    PackTelemetryCounter physicalReadSlow1ms{0};
    PackTelemetryCounter physicalReadSlow5ms{0};
    PackTelemetryCounter physicalReadSlow20ms{0};
    PackTelemetryCounter physicalReadLe64K{0};
    PackTelemetryCounter physicalReadLe512K{0};
    PackTelemetryCounter physicalReadGt512K{0};
    PackTelemetryCounter physicalReadsInFlight{0};
    PackTelemetryCounter physicalReadsInFlightPeak{0};
    PackTelemetryCounter backingAioSubmitBatches{0};
    PackTelemetryCounter backingAioSubmitRequests{0};
    PackTelemetryCounter backingAioSubmitEagain{0};
    PackTelemetryCounter backingAioSubmitFailures{0};
    PackTelemetryCounter backingAioPollFailures{0};
    PackTelemetryCounter backingAioDeleteFailures{0};
    PackTelemetryCounter pipelineContextsActive{0};
    PackTelemetryCounter pipelineContextsActivePeak{0};
    PackTelemetryCounter pipelineIoYields{0};
    PackTelemetryCounter pipelineCacheYields{0};
    PackTelemetryCounter pipelineFdYields{0};
    PackTelemetryCounter physicalWindowHits{0};
    PackTelemetryCounter physicalPageHits{0};
    PackTelemetryCounter physicalPageMisses{0};
    PackTelemetryCounter physicalPageLoadingJoins{0};
    PackTelemetryCounter physicalPageAdmissions{0};
    PackTelemetryCounter physicalPageEvictions{0};
    PackTelemetryCounter physicalPageBypasses{0};
    PackTelemetryCounter physicalCacheDirectReadWindows{0};
    PackTelemetryCounter physicalCacheDirectReadyWindows{0};
    PackTelemetryCounter physicalCacheScratchWindows{0};
    PackTelemetryCounter physicalCacheCopyBytesAvoided{0};
    PackTelemetryCounter inlineCacheCompletions{0};
    PackTelemetryCounter latencyJobsSubmitted{0};
    PackTelemetryCounter balancedJobsSubmitted{0};
    PackTelemetryCounter bulkJobsSubmitted{0};
    PackTelemetryCounter latencyWorkerDispatches{0};
    PackTelemetryCounter queueDepthPeakLatency{0};
    PackTelemetryCounter queueDepthPeakBalanced{0};
    PackTelemetryCounter queueDepthPeakBulk{0};
    PackTelemetryCounter workerJobs{0};
    PackTelemetryCounter workerJobUsecTotal{0};
    PackTelemetryCounter workerJobUsecMax{0};
    PackTelemetryCounter workersBusy{0};
    PackTelemetryCounter workersBusyPeak{0};
    PackTelemetryCounter workerQueueWaitUsecTotal{0};
    PackTelemetryCounter workerQueueWaitUsecMax{0};
    PackTelemetryCounter workerQueueWaitSlow1ms{0};
    PackTelemetryCounter workerQueueWaitSlow5ms{0};
    PackTelemetryCounter workerQueueWaitSlow20ms{0};
    PackTelemetryCounter storedBytesConsumed{0};
    PackTelemetryCounter lz4DecodedBytes{0};
    PackTelemetryCounter rawBytes{0};
    PackTelemetryCounter cacheHits{0};
    PackTelemetryCounter cacheMisses{0};
    PackTelemetryCounter cacheLoadingJoins{0};
    PackTelemetryCounter cacheAdmissions{0};
    PackTelemetryCounter cacheEvictions{0};
    PackTelemetryCounter ioFailures{0};
    PackTelemetryCounter processVirtualOpens{0};
    PackTelemetryCounter directoryOpens{0};
    PackTelemetryCounter directoryHybridOpens{0};
    PackTelemetryCounter directoryVirtualOpens{0};
    PackTelemetryCounter directoryGetdentsCalls{0};
    PackTelemetryCounter directoryPhysicalEntries{0};
    PackTelemetryCounter directoryVirtualEntries{0};
    PackTelemetryCounter directoryDuplicateEntries{0};
    PackTelemetryCounter directoryHiddenEntries{0};
    PackTelemetryCounter syntheticFileStats{0};
    PackTelemetryCounter syntheticDirectoryStats{0};
    PackTelemetryCounter syntheticReachability{0};
    PackTelemetryCounter synchronousPreads{0};
    PackTelemetryCounter synchronousReads{0};
    PackTelemetryCounter synchronousLseeks{0};
};

struct PackState {
    AmprMutex m;
    // Cursor operations and close serialize only with synchronous operations
    // on the same synthetic descriptor. Different packed files remain parallel.
    AmprMutex virtualFdMutexes[AMPR_EMU_PACK_VIRTUAL_FD_SLOTS];
    AmprMutex cacheMutex;
    AmprMutex physicalCacheMutex;
    // Cold manifest publication is rare but may include large index I/O.
    // Waiters sleep here while the one loading thread performs that work.
    AmprMutex manifestMutex;
    // Allocation cursor and per-directory state are separate: a slow physical
    // enumeration blocks only operations on the same synthetic directory.
    AmprMutex directoryTableMutex;
    AmprMutex directoryMutexes[AMPR_EMU_PACK_VIRTUAL_DIRECTORY_SLOTS];
    AmprConditionVariable queueCv;
    AmprConditionVariable aioCv;
    AmprConditionVariable submitCv;
    uint32_t activeSubmissions{}; // Protected by m, including singular groups.
    bool submissionsClosed{};
    AmprConditionVariable cacheCvs[kPackCacheWaitBucketCount];
    AmprConditionVariable manifestCv;
    std::atomic<uint32_t> loadState{kPackLoadUninitialized};

    void* manifestBase{};
    size_t manifestBytes{};
    AmprPackCoreView coreView{};
    const AmprPackIndexHeader* header{};
    const AmprPackFileRecord* files{};
    const AmprPackChunkRecord* chunks{};
    const AmprPackDataRecord* packs{};
    const char* strings{};
    size_t stringsBytes{};
    uint32_t* packedFileOrder{};
    uint32_t packedFileCount{};

    VirtualFdSlot virtualFds[AMPR_EMU_PACK_VIRTUAL_FD_SLOTS]{};
    uint32_t virtualFdCursor{};
    VirtualDirectorySlot virtualDirectories[AMPR_EMU_PACK_VIRTUAL_DIRECTORY_SLOTS]{};
    uint32_t virtualDirectoryCursor{};
    VirtualAioSlot virtualAio[AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS]{};
    uint32_t virtualAioCursor{};
    VirtualAioGroupSlot virtualAioGroups[AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS]{};
    uint32_t virtualAioGroupCursor{};
    uint32_t queueHead[3][kPackWorkClassCount]{};
    uint32_t queueTail[3][kPackWorkClassCount]{};
    uint32_t queueDepth[kPackWorkClassCount]{};
    uint32_t queuePickCounter{};
    uint64_t aioCompletionEpoch{};

    size_t decodedCacheTargetBytes{AMPR_EMU_PACK_DECODED_CACHE_BYTES};
    size_t physicalCacheTargetBytes{AMPR_EMU_PACK_PHYSICAL_CACHE_BYTES};
    uint32_t requestedWorkers{AMPR_EMU_PACK_WORKERS};
    uint32_t latencyReserveWorkers{AMPR_EMU_PACK_LATENCY_RESERVE_WORKERS};
    bool runtimeProfileLoaded{};
    size_t profileDecodedBytes{}; // Immutable after manifest publication.
    size_t profilePhysicalBytes{};
    std::atomic<uint32_t> profileStartedWorkers{0};
    WorkerContext workers[AMPR_EMU_PACK_WORKER_CAPACITY]{};
    ReadPipelineContext pipelines[AMPR_EMU_PACK_PIPELINE_SLOTS]{};
    uint32_t pipelineFreeHead{kInvalidIndex};
    uint32_t pipelineCapacity{};
    uint32_t cacheWaiterCount{};
    uint32_t fdWaiterCount{};
    std::atomic<uint64_t> packFdProgressEpoch{1};
    uint32_t workersStarted{};
    uint32_t workerCapacity{};
    uint32_t pipelineActiveCount{};
    std::atomic<bool> workerStopRequested{false};
#if AMPR_EMU_DEBUG_LOG
    std::atomic<uint64_t> nextIoTelemetryUsec{0};
#endif
    std::atomic<uint64_t>
        decodedCachePublicationEpoch[kPackCacheWaitBucketCount]{};
    std::atomic<uint64_t>
        physicalCachePublicationEpoch[kPackCacheWaitBucketCount]{};

    PackHandle packHandles[AMPR_EMU_PACK_MAX_PACKS]{};
    uint32_t openPackCount{};
    uint32_t openingPackCount{};
    uint64_t tick{1};

    uint8_t* cacheBase{};
    size_t cacheBytes{};
    uint32_t cachePageCount{};
    uint64_t cachePageBitmap[kPackCacheBitmapWords ? kPackCacheBitmapWords : 1]{};
    CacheEntry cacheEntries[AMPR_EMU_PACK_CACHE_ENTRY_CAP]{};
    uint32_t cacheFreeHead{kInvalidIndex};
    uint32_t cacheHashHeads[AMPR_EMU_PACK_CACHE_HASH_BUCKETS]{};
    uint32_t cachePageCursor{};
    uint32_t cacheClock{};
    TouchEntry touches[AMPR_EMU_PACK_TOUCH_TABLE_SIZE]{};

    uint8_t* physicalCacheBase{};
    size_t physicalCacheBytes{};
    uint32_t physicalCachePageCount{};
    uint64_t physicalCachePageBitmap[
        kPackPhysicalCacheBitmapWords ? kPackPhysicalCacheBitmapWords : 1]{};
    PhysicalCacheEntry physicalCacheEntries[
        AMPR_EMU_PACK_PHYSICAL_CACHE_ENTRY_CAP]{};
    uint32_t physicalCacheFreeHead{kInvalidIndex};
    uint32_t physicalCacheHashHeads[
        AMPR_EMU_PACK_PHYSICAL_CACHE_HASH_BUCKETS]{};
    uint32_t physicalCachePageCursor{};
    uint32_t physicalCacheClock{};

    AtomicPackStats stats;
};

static std::atomic<PackState*> g_pack_state{nullptr};
alignas(PackState) static unsigned char g_pack_state_storage[sizeof(PackState)];
static std::atomic<uint32_t> g_pack_state_init{0};

static PackState* pack_state_create() {
    PackState* state = g_pack_state.load(std::memory_order_acquire);
    if (state) return state;
    uint32_t expected = 0;
    if (g_pack_state_init.compare_exchange_strong(expected, 1u,
                                                  std::memory_order_acq_rel,
                                                  std::memory_order_acquire)) {
        state = new (g_pack_state_storage) PackState();
        for (uint32_t i = 0; i < AMPR_EMU_PACK_MAX_PACKS; ++i) {
            state->packHandles[i].fd = -1;
        }
        for (uint32_t priority = 0; priority < 3u; ++priority) {
            for (uint32_t workClass = 0;
                 workClass < kPackWorkClassCount; ++workClass) {
                state->queueHead[priority][workClass] = kInvalidIndex;
                state->queueTail[priority][workClass] = kInvalidIndex;
            }
        }
        g_pack_state.store(state, std::memory_order_release);
        g_pack_state_init.store(2u, std::memory_order_release);
        return state;
    }
    uint32_t spins = 0;
    while (g_pack_state_init.load(std::memory_order_acquire) != 2u) {
        ampr_spin_pause_or_yield(spins);
    }
    return g_pack_state.load(std::memory_order_acquire);
}

static PackState& pack_state() {
    PackState* state = pack_state_create();
    if (!state) {
        AMPR_KLOGF("ampr.abort reason=pack.state.null file=%s line=%d", __FILE__, __LINE__);
        std::abort();
    }
    return *state;
}

// Covers the unlocked native call and inline cache copy as well as slot
// reservation/publication. Shutdown must not cancel Reserved slots mid-call.
class PackSubmission {
public:
    explicit PackSubmission(PackState& state) : state_(state) {
        AmprLockGuard lock(state_.m);
        if (!state_.submissionsClosed) {
            ++state_.activeSubmissions;
            admitted_ = true;
        }
    }
    ~PackSubmission() {
        if (!admitted_) return;
        AmprLockGuard lock(state_.m);
        if (--state_.activeSubmissions == 0) state_.submitCv.notify_all();
    }
    bool admitted() const { return admitted_; }
    PackSubmission(const PackSubmission&) = delete;
    PackSubmission& operator=(const PackSubmission&) = delete;
private:
    PackState& state_;
    bool admitted_{};
};

static uint32_t next_generation(uint16_t current) {
    uint32_t generation = (static_cast<uint32_t>(current) + 1u) &
                          kVirtualGenerationMask;
    return generation ? generation : 1u;
}

static int encode_virtual_fd(uint32_t slot, uint16_t generation) {
    return static_cast<int>(kVirtualFdTag |
                            (static_cast<uint32_t>(generation) << 8u) |
                            slot);
}

static bool decode_virtual_fd(int fd, uint32_t* slot, uint16_t* generation) {
    const uint32_t value = static_cast<uint32_t>(fd);
    if ((value & kVirtualTagMask) != kVirtualFdTag) return false;
    const uint32_t decodedSlot = value & 0xffu;
    if (decodedSlot >= AMPR_EMU_PACK_VIRTUAL_FD_SLOTS) return false;
    if (slot) *slot = decodedSlot;
    if (generation) *generation = static_cast<uint16_t>((value >> 8u) & 0xffffu);
    return true;
}

static int encode_virtual_directory_fd(uint32_t slot, uint16_t generation) {
    return static_cast<int>(kVirtualDirectoryFdTag |
                            (static_cast<uint32_t>(generation) << 8u) |
                            slot);
}

static bool decode_virtual_directory_fd(int fd, uint32_t* slot,
                                        uint16_t* generation) {
    const uint32_t value = static_cast<uint32_t>(fd);
    if ((value & kVirtualTagMask) != kVirtualDirectoryFdTag) return false;
    const uint32_t decodedSlot = value & 0xffu;
    if (decodedSlot >= AMPR_EMU_PACK_VIRTUAL_DIRECTORY_SLOTS) return false;
    if (slot) *slot = decodedSlot;
    if (generation) {
        *generation = static_cast<uint16_t>((value >> 8u) & 0xffffu);
    }
    return true;
}

static SceKernelAioSubmitId encode_virtual_aio(uint32_t slot,
                                               uint16_t generation) {
    return static_cast<SceKernelAioSubmitId>(
        kVirtualAioTag | (static_cast<uint32_t>(generation) << 8u) | slot);
}

static bool decode_virtual_aio(SceKernelAioSubmitId id,
                               uint32_t* slot,
                               uint16_t* generation) {
    const uint32_t value = static_cast<uint32_t>(id);
    if ((value & kVirtualTagMask) != kVirtualAioTag) return false;
    const uint32_t decodedSlot = value & 0xffu;
    if (decodedSlot >= AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS) return false;
    if (slot) *slot = decodedSlot;
    if (generation) *generation = static_cast<uint16_t>((value >> 8u) & 0xffffu);
    return true;
}

static SceKernelAioSubmitId encode_virtual_aio_group(uint32_t slot,
                                                     uint16_t generation) {
    return static_cast<SceKernelAioSubmitId>(
        kVirtualAioGroupTag |
        (static_cast<uint32_t>(generation) << 8u) | slot);
}

static bool decode_virtual_aio_group(SceKernelAioSubmitId id,
                                     uint32_t* slot,
                                     uint16_t* generation) {
    const uint32_t value = static_cast<uint32_t>(id);
    if ((value & kVirtualTagMask) != kVirtualAioGroupTag) return false;
    const uint32_t decodedSlot = value & 0xffu;
    if (decodedSlot >= AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS) return false;
    if (slot) *slot = decodedSlot;
    if (generation) {
        *generation = static_cast<uint16_t>((value >> 8u) & 0xffffu);
    }
    return true;
}

static uint64_t pack_monotonic_usecs() {
    timespec ts{};
    if (sceKernelClockGettime(SCE_KERNEL_CLOCK_MONOTONIC, &ts) != 0) return 0;
    return static_cast<uint64_t>(ts.tv_sec) * 1000000ull +
           static_cast<uint64_t>(ts.tv_nsec) / 1000ull;
}

static uint64_t pack_telemetry_usecs() {
#if AMPR_EMU_PACK_TELEMETRY
    return pack_monotonic_usecs();
#else
    return 0;
#endif
}

static void update_atomic_peak(PackTelemetryCounter& peak,
                               uint64_t value) {
#if AMPR_EMU_PACK_TELEMETRY
    uint64_t observed = peak.load(std::memory_order_relaxed);
    while (observed < value &&
           !peak.compare_exchange_weak(
               observed, value,
               std::memory_order_relaxed,
               std::memory_order_relaxed)) {
    }
#else
    (void)peak;
    (void)value;
#endif
}

static uint64_t elapsed_usecs(uint64_t start, uint64_t end) {
    return start != 0 && end >= start ? end - start : 0;
}

#if AMPR_EMU_PACK_TELEMETRY
static void record_latency(PackTelemetryCounter (&histogram)[32],
                           uint64_t usecs, uint64_t count = 1) {
    uint32_t bucket = 0;
    while (usecs > 1 && bucket < 31) {
        usecs = (usecs >> 1u) + (usecs & 1u);
        ++bucket;
    }
    histogram[bucket].fetch_add(count, std::memory_order_relaxed);
}

static void record_slow_buckets(
    uint64_t usecs,
    PackTelemetryCounter& slow1ms,
    PackTelemetryCounter& slow5ms,
    PackTelemetryCounter& slow20ms) {
    if (usecs >= 1000u) slow1ms.fetch_add(1, std::memory_order_relaxed);
    if (usecs >= 5000u) slow5ms.fetch_add(1, std::memory_order_relaxed);
    if (usecs >= 20000u) slow20ms.fetch_add(1, std::memory_order_relaxed);
}
#endif

static bool pread_exact(int fd, void* destination, size_t size, uint64_t offset) {
    KernelPreadFn fn = real_pread();
    if (!fn || offset > static_cast<uint64_t>((std::numeric_limits<off_t>::max)())) {
        return false;
    }
    auto* out = static_cast<uint8_t*>(destination);
    size_t done = 0;
    while (done < size) {
        const size_t request = (std::min)(
            size - done, static_cast<size_t>(AMPR_EMU_PACK_PREAD_MAX_BYTES));
        const ssize_t rc = fn(fd, out + done, request,
                              static_cast<off_t>(offset + done));
        if (rc <= 0) return false;
        done += static_cast<size_t>(rc);
    }
    return true;
}

static bool bytes_equal(const void* a, const void* b, size_t size) {
    return std::memcmp(a, b, size) == 0;
}

static const char* manifest_string(const PackState& state,
                                   uint32_t offset,
                                   uint32_t length) {
    if (!state.strings || offset >= state.stringsBytes ||
        length >= state.stringsBytes - offset) {
        return nullptr;
    }
    const char* value = state.strings + offset;
    return value[length] == '\0' ? value : nullptr;
}

static unsigned char ascii_fold(unsigned char value) {
    return value >= 'A' && value <= 'Z'
        ? static_cast<unsigned char>(value + ('a' - 'A'))
        : value;
}

static int folded_compare(const char* a, size_t aLength,
                          const char* b, size_t bLength) {
    const size_t common = (std::min)(aLength, bLength);
    for (size_t i = 0; i < common; ++i) {
        const unsigned char av = ascii_fold(static_cast<unsigned char>(a[i]));
        const unsigned char bv = ascii_fold(static_cast<unsigned char>(b[i]));
        if (av != bv) return av < bv ? -1 : 1;
    }
    if (aLength == bLength) return 0;
    return aLength < bLength ? -1 : 1;
}

static bool folded_equal(const char* a, size_t aLength,
                         const char* b, size_t bLength) {
    return folded_compare(a, aLength, b, bLength) == 0;
}

static uint64_t folded_hash(const char* value, size_t length) {
    uint64_t hash = 1469598103934665603ull;
    for (size_t i = 0; i < length; ++i) {
        hash ^= ascii_fold(static_cast<unsigned char>(value[i]));
        hash *= 1099511628211ull;
    }
    return hash | 1ull;
}

static bool normalize_overlay_path(const char* input, char* output,
                                   size_t capacity, uint16_t* outLength) {
    if (outLength) *outLength = 0;
    if (!input || !output || capacity < 6u) return false;
    size_t source = 0;
    size_t destination = 0;
    bool previousSlash = false;
    while (input[source] != '\0') {
        unsigned char ch = static_cast<unsigned char>(input[source++]);
        if (ch == '\\') ch = '/';
        if (ch == '/') {
            if (previousSlash) continue;
            previousSlash = true;
        } else {
            previousSlash = false;
        }
        if (destination + 1u >= capacity) return false;
        output[destination++] = static_cast<char>(ch);
    }
    while (destination > 5u && output[destination - 1u] == '/') {
        --destination;
    }
    output[destination] = '\0';
    static constexpr char root[] = AMPR_EMU_PACK_LOGICAL_ROOT_PATH;
    static constexpr size_t rootLength = sizeof(root) - 1u;
    if (destination < rootLength ||
        !folded_equal(output, rootLength, root, rootLength) ||
        (destination != rootLength && output[rootLength] != '/')) {
        return false;
    }
    if (destination > UINT16_MAX) return false;
    if (outLength) *outLength = static_cast<uint16_t>(destination);
    return true;
}

static const char* file_record_path(const PackState& state,
                                    uint32_t fileIndex) {
    if (!state.header || fileIndex >= state.header->fileCount) return nullptr;
    const AmprPackFileRecord& file = state.files[fileIndex];
    return manifest_string(state, file.pathOffset, file.pathLength);
}

static int compare_file_index_path(const PackState& state, uint32_t left,
                                   uint32_t right) {
    const AmprPackFileRecord& a = state.files[left];
    const AmprPackFileRecord& b = state.files[right];
    const char* ap = file_record_path(state, left);
    const char* bp = file_record_path(state, right);
    if (!ap || !bp) return left < right ? -1 : (left == right ? 0 : 1);
    const int result = folded_compare(ap, a.pathLength, bp, b.pathLength);
    return result != 0 ? result : (left < right ? -1 : (left == right ? 0 : 1));
}

static int compare_file_index_key(const PackState& state, uint32_t fileIndex,
                                  const char* key, size_t keyLength) {
    const AmprPackFileRecord& file = state.files[fileIndex];
    const char* path = file_record_path(state, fileIndex);
    if (!path) return 1;
    return folded_compare(path, file.pathLength, key, keyLength);
}

static bool build_packed_file_order(PackState& state) {
    if (!state.header || !state.files) return false;
    uint32_t count = 0;
    for (uint64_t i = 0; i < state.header->fileCount; ++i) {
        if ((state.files[i].flags & kAmprPackFilePacked) != 0) ++count;
    }
    state.packedFileCount = count;
    if (count == 0) return true;
    size_t actual = 0;
    const size_t bytes = static_cast<size_t>(count) * sizeof(uint32_t);
    void* memory = ampr_internal_amm_pool_alloc(
        bytes, &actual, "apr.pack.directory-index", true, alignof(uint32_t));
    if (!memory || actual < bytes) {
        if (memory) {
            (void)ampr_internal_amm_pool_free(
                memory, "apr.pack.directory-index.short");
        }
        return false;
    }
    state.packedFileOrder = static_cast<uint32_t*>(memory);
    uint32_t cursor = 0;
    for (uint32_t i = 0; i < state.header->fileCount; ++i) {
        if ((state.files[i].flags & kAmprPackFilePacked) != 0) {
            state.packedFileOrder[cursor++] = i;
        }
    }
    std::sort(state.packedFileOrder, state.packedFileOrder + count,
              [&](uint32_t a, uint32_t b) {
                  return compare_file_index_path(state, a, b) < 0;
              });
    AMPR_LOGF("apr.pack.directory-index.init packed=%u bytes=0x%llx",
              count, (unsigned long long)bytes);
    return true;
}

static uint32_t packed_lower_bound(const PackState& state,
                                   const char* key, size_t keyLength) {
    uint32_t first = 0;
    uint32_t count = state.packedFileCount;
    while (count != 0) {
        const uint32_t step = count / 2u;
        const uint32_t candidate = first + step;
        if (compare_file_index_key(
                state, state.packedFileOrder[candidate], key, keyLength) < 0) {
            first = candidate + 1u;
            count -= step + 1u;
        } else {
            count = step;
        }
    }
    return first;
}

static bool find_virtual_directory_range(const PackState& state,
                                         const char* directory,
                                         uint16_t directoryLength,
                                         uint32_t* outBegin,
                                         uint32_t* outEnd) {
    if (outBegin) *outBegin = 0;
    if (outEnd) *outEnd = 0;
    if (!state.packedFileOrder || state.packedFileCount == 0 ||
        !directory || directoryLength == 0 ||
        static_cast<size_t>(directoryLength) + 1u >= SCE_KERNEL_PATH_MAX) {
        return false;
    }
    char prefix[SCE_KERNEL_PATH_MAX]{};
    std::memcpy(prefix, directory, directoryLength);
    size_t prefixLength = directoryLength;
    if (prefixLength == 0 || prefix[prefixLength - 1u] != '/') {
        prefix[prefixLength++] = '/';
    }
    prefix[prefixLength] = '\0';
    const uint32_t begin = packed_lower_bound(state, prefix, prefixLength);
    uint32_t end = begin;
    while (end < state.packedFileCount) {
        const uint32_t fileIndex = state.packedFileOrder[end];
        const AmprPackFileRecord& file = state.files[fileIndex];
        const char* path = file_record_path(state, fileIndex);
        if (!path || file.pathLength <= prefixLength ||
            !folded_equal(path, prefixLength, prefix, prefixLength)) {
            break;
        }
        ++end;
    }
    if (begin == end) return false;
    if (outBegin) *outBegin = begin;
    if (outEnd) *outEnd = end;
    return true;
}

static bool resolve_packed_file(const PackState& state, const char* path,
                                uint32_t* outFileId,
                                const AmprPackFileRecord** outRecord) {
    uint32_t fileId = 0;
    size_t indexedSize = 0;
    if (!path || ampr_index_resolve_path_to_id(path, &fileId, &indexedSize) != 0 ||
        fileId == 0 || !state.header || fileId > state.header->fileCount) {
        return false;
    }
    const AmprPackFileRecord& file = state.files[fileId - 1u];
    if ((file.flags & kAmprPackFilePacked) == 0 ||
        file.logicalSize != indexedSize) {
        return false;
    }
    if (outFileId) *outFileId = fileId;
    if (outRecord) *outRecord = &file;
    return true;
}

static void fill_synthetic_stat(SceKernelStat* stat, bool directory,
                                uint64_t size, int64_t mtime,
                                uint64_t inodeSeed) {
    if (!stat) return;
    std::memset(stat, 0, sizeof(*stat));
    stat->st_mode = static_cast<mode_t>(directory ? (S_IFDIR | 0555) :
                                                   (S_IFREG | 0444));
    stat->st_nlink = static_cast<nlink_t>(directory ? 2 : 1);
    stat->st_size = static_cast<off_t>(size);
    stat->st_blksize = static_cast<blksize_t>(65536);
    stat->st_blocks = static_cast<blkcnt_t>((size + 511u) / 512u);
    stat->st_mtim.tv_sec = static_cast<time_t>(mtime);
    stat->st_atim.tv_sec = static_cast<time_t>(mtime);
    stat->st_ctim.tv_sec = static_cast<time_t>(mtime);
    stat->st_ino = static_cast<ino_t>((inodeSeed & 0x7fffffffu) | 1u);
}

static bool joined_entry_matches_path(const char* directory,
                                      uint16_t directoryLength,
                                      const char* name, size_t nameLength,
                                      const char* target) {
    if (!directory || !name || !target) return false;
    const size_t targetLength = std::strlen(target);
    const bool slash = directoryLength == 0 ||
                       directory[directoryLength - 1u] != '/';
    const size_t joinedLength = static_cast<size_t>(directoryLength) +
                                (slash ? 1u : 0u) + nameLength;
    if (joinedLength != targetLength) return false;
    if (!folded_equal(directory, directoryLength, target, directoryLength)) {
        return false;
    }
    size_t targetCursor = directoryLength;
    if (slash) {
        if (target[targetCursor] != '/') return false;
        ++targetCursor;
    }
    return folded_equal(name, nameLength, target + targetCursor, nameLength);
}

static bool service_name_hidden(const PackState& state,
                                const char* directory,
                                uint16_t directoryLength,
                                const char* name, size_t nameLength) {
    static constexpr const char* fixedPaths[] = {
        AMPR_EMU_PACK_LOGICAL_ROOT_PATH "/ampr_emu.index",
        AMPR_EMU_PACK_LOGICAL_ROOT_PATH "/ampr_assets.index",
        AMPR_EMU_PACK_LOGICAL_ROOT_PATH "/ampr_commands.bin",
        AMPR_EMU_PACK_LOGICAL_ROOT_PATH "/ampr_emu.log",
        AMPR_EMU_PACK_INDEX_PATH,
    };
    for (const char* path : fixedPaths) {
        if (joined_entry_matches_path(
                directory, directoryLength, name, nameLength, path)) {
            return true;
        }
    }

    // Hide the exact physical volumes named by the loaded manifest, including
    // custom pack_pattern values and nested volume paths. This is more precise
    // than relying only on the default "ampr_assets-*.pak" convention.
    if (state.header && state.packs) {
        // Pack record names are deployment-relative.  Directory handles use
        // the logical /app0 namespace even when host tests or a custom loader
        // map the physical pack root elsewhere.
        static constexpr char physicalRoot[] = AMPR_EMU_PACK_LOGICAL_ROOT_PATH;
        static constexpr size_t physicalRootLength = sizeof(physicalRoot) - 1u;
        for (uint32_t packId = 0; packId < state.header->packCount; ++packId) {
            const AmprPackDataRecord& record = state.packs[packId];
            const char* packName = manifest_string(
                state, record.nameOffset, record.nameLength);
            if (!packName) continue;
            const bool rootSlash = physicalRootLength == 0 ||
                                   physicalRoot[physicalRootLength - 1u] != '/';
            const size_t targetLength = physicalRootLength +
                                        (rootSlash ? 1u : 0u) +
                                        record.nameLength;
            if (targetLength >= SCE_KERNEL_PATH_MAX) continue;
            char target[SCE_KERNEL_PATH_MAX]{};
            std::memcpy(target, physicalRoot, physicalRootLength);
            size_t cursor = physicalRootLength;
            if (rootSlash) target[cursor++] = '/';
            std::memcpy(target + cursor, packName, record.nameLength);
            target[targetLength] = '\0';
            if (joined_entry_matches_path(
                    directory, directoryLength, name, nameLength, target)) {
                return true;
            }
        }
    }

    // Also hide stale/default-named volumes in /app0 so an interrupted update
    // cannot make implementation files appear as game content.
    static constexpr char root[] = AMPR_EMU_PACK_LOGICAL_ROOT_PATH;
    if (!folded_equal(directory, directoryLength, root, sizeof(root) - 1u)) {
        return false;
    }
    static constexpr char packPrefix[] = "ampr_assets-";
    static constexpr char suffix[] = ".pak";
    return nameLength > sizeof(packPrefix) - 1u &&
           nameLength >= sizeof(suffix) - 1u &&
           folded_equal(name, sizeof(packPrefix) - 1u,
                        packPrefix, sizeof(packPrefix) - 1u) &&
           folded_equal(name + nameLength - (sizeof(suffix) - 1u),
                        sizeof(suffix) - 1u, suffix,
                        sizeof(suffix) - 1u);
}

static bool join_directory_child(const VirtualDirectorySlot& slot,
                                 const char* name, size_t nameLength,
                                 char* output, size_t capacity) {
    const bool slash = slot.pathLength == 0 ||
                       slot.path[slot.pathLength - 1u] != '/';
    const size_t needed = static_cast<size_t>(slot.pathLength) +
                          (slash ? 1u : 0u) + nameLength + 1u;
    if (!output || needed > capacity) return false;
    std::memcpy(output, slot.path, slot.pathLength);
    size_t cursor = slot.pathLength;
    if (slash) output[cursor++] = '/';
    std::memcpy(output + cursor, name, nameLength);
    output[cursor + nameLength] = '\0';
    return true;
}

static bool validate_manifest_layout(PackState& state,
                                     void* base,
                                     size_t bytes) {
    AmprPackCoreView view{};
    const int mountRc = ampr_pack_core_mount(base, bytes, &view);
    if (mountRc != kAmprPackCoreOk || !view.header ||
        view.header->fileCount > AMPR_EMU_PACK_MAX_FILES ||
        view.header->chunkCount > AMPR_EMU_PACK_MAX_CHUNKS ||
        view.header->packCount > AMPR_EMU_PACK_MAX_PACKS) {
        return false;
    }


    state.coreView = view;
    state.header = view.header;
    state.files = view.files;
    state.chunks = view.chunks;
    state.packs = view.packs;
    state.strings = view.strings;
    state.stringsBytes = view.stringsSize;
    return true;
}

static void initialize_physical_cache(PackState& state) {
    if (state.physicalCacheTargetBytes == 0 ||
        kPackPhysicalCacheMaxPages == 0) {
        return;
    }

    size_t candidate = align_up_size(
        state.physicalCacheTargetBytes,
        kPackCachePageBytes);
    const size_t minimum = align_up_size(
        (std::min)(state.physicalCacheTargetBytes, static_cast<size_t>(AMPR_EMU_PACK_PHYSICAL_CACHE_MIN_BYTES)),
        kPackCachePageBytes);
    while (candidate != SIZE_MAX && candidate >= minimum && candidate != 0) {
        size_t actual = 0;
        void* memory = ampr_internal_amm_pool_alloc(
            candidate, &actual, "apr.pack.physical-page-cache", false,
            kPackCachePageBytes);
        if (memory && actual >= candidate) {
            state.physicalCacheBase = static_cast<uint8_t*>(memory);
            state.physicalCacheBytes = candidate;
            state.physicalCachePageCount = static_cast<uint32_t>(
                candidate / kPackCachePageBytes);
            std::memset(state.physicalCachePageBitmap, 0,
                        sizeof(state.physicalCachePageBitmap));
            std::memset(state.physicalCacheHashHeads, 0,
                        sizeof(state.physicalCacheHashHeads));
            state.physicalCachePageCursor = 0;
            state.physicalCacheFreeHead = 0;
            for (uint32_t i = 0;
                 i < AMPR_EMU_PACK_PHYSICAL_CACHE_ENTRY_CAP; ++i) {
                state.physicalCacheEntries[i] = {};
                state.physicalCacheEntries[i].freeNext =
                    (i + 1u < AMPR_EMU_PACK_PHYSICAL_CACHE_ENTRY_CAP)
                        ? i + 1u
                        : kInvalidIndex;
            }
            AMPR_LOGF("apr.pack.physical-cache.init bytes=0x%llx pages=%u allocationPageBytes=0x%llx entries=%u",
                      (unsigned long long)candidate,
                      state.physicalCachePageCount,
                      (unsigned long long)kPackCachePageBytes,
                      (unsigned)AMPR_EMU_PACK_PHYSICAL_CACHE_ENTRY_CAP);
            return;
        }
        if (memory) {
            (void)ampr_internal_amm_pool_free(
                memory, "apr.pack.physical-page-cache.short");
        }
        candidate /= 2u;
        candidate &= ~(kPackCachePageBytes - 1u);
    }
    AMPR_LOGF("apr.pack.physical-cache.disabled reason=no-memory target=0x%llx minimum=0x%llx",
              (unsigned long long)state.physicalCacheTargetBytes,
              (unsigned long long)AMPR_EMU_PACK_PHYSICAL_CACHE_MIN_BYTES);
}

static bool load_runtime_profile(PackState& state) {
    static constexpr char path[] = AMPR_EMU_PACK_INDEX_PATH ".runtime";
    const int fd = real_open()(path, SCE_KERNEL_O_RDONLY, 0);
    if (fd < 0) {
        const int error = fd == -1 ? errno : ampr_posix_errno_from_sce(fd);
        if (error == ENOENT) return true;
        AMPR_CRITICAL_LOGF("apr.pack.profile.open.fail rc=0x%x", fd);
        return false;
    }
    AmprPackRuntimeProfile profile{};
    SceKernelStat st{};
    bool valid = real_fstat()(fd, &st) == 0 &&
                 st.st_size == static_cast<off_t>(sizeof(profile)) &&
                 pread_exact(fd, &profile, sizeof(profile), 0);
    const int closeRc = real_close()(fd);
    const uint32_t expectedCrc = profile.crc32;
    profile.crc32 = 0;
    valid = valid && closeRc == 0 &&
        std::memcmp(profile.magic, "AMPRCFG1", 8) == 0 &&
        profile.version == 1 && profile.size == sizeof(profile) &&
        profile.reserved == 0 &&
        std::memcmp(profile.buildId, state.header->buildId, 16) == 0 &&
        ampr_pack_crc32(&profile, sizeof(profile)) == expectedCrc &&
        profile.workers >= 1 && profile.workers <= 16 &&
        profile.latencyReserveWorkers < profile.workers &&
        profile.decodedCacheBytes % kPackCachePageBytes == 0 &&
        profile.physicalCacheBytes % kPackCachePageBytes == 0;
    if (!valid) {
        AMPR_CRITICAL_LOGF("apr.pack.profile.invalid path=%s", path);
        return false;
    }
    state.decodedCacheTargetBytes = static_cast<size_t>((std::min)(
        profile.decodedCacheBytes, uint64_t{AMPR_EMU_PACK_DECODED_CACHE_MAX_BYTES}));
    state.physicalCacheTargetBytes = static_cast<size_t>((std::min)(
        profile.physicalCacheBytes, uint64_t{AMPR_EMU_PACK_PHYSICAL_CACHE_MAX_BYTES}));
    state.requestedWorkers = (std::min)(profile.workers,
        static_cast<uint32_t>(AMPR_EMU_PACK_WORKER_CAPACITY));
    state.latencyReserveWorkers = (std::min)(profile.latencyReserveWorkers,
                                            state.requestedWorkers - 1u);
    state.runtimeProfileLoaded = true;
    AMPR_LOGF("apr.pack.profile.request decoded=%llu physical=%llu workers=%u reserve=%u",
              (unsigned long long)profile.decodedCacheBytes,
              (unsigned long long)profile.physicalCacheBytes,
              profile.workers, profile.latencyReserveWorkers);
    return true;
}

static size_t runtime_cache_reserve_bytes(const PackState& state) {
    size_t reserve = static_cast<size_t>(AMPR_EMU_PACK_MEMORY_RESERVE_BYTES);
    if (AMPR_EMU_PACK_PIPELINE_SLOTS >
        (SIZE_MAX - reserve) / kPackPipelineIoBytes) {
        return SIZE_MAX;
    }
    reserve += static_cast<size_t>(AMPR_EMU_PACK_PIPELINE_SLOTS) *
               kPackPipelineIoBytes;
    if (state.requestedWorkers >
        (SIZE_MAX - reserve) / kPackMaxBlockBytes) {
        return SIZE_MAX;
    }
    reserve += static_cast<size_t>(state.requestedWorkers) *
               kPackMaxBlockBytes;
    return align_up_size(reserve, kPackCachePageBytes);
}

static void initialize_decoded_cache(PackState& state) {
    if (state.decodedCacheTargetBytes == 0 || kPackCacheMaxPages == 0) return;

    size_t candidate = align_up_size(
        state.decodedCacheTargetBytes,
        kPackCachePageBytes);
    const size_t minimum = align_up_size(
        (std::min)(state.decodedCacheTargetBytes, static_cast<size_t>(AMPR_EMU_PACK_DECODED_CACHE_MIN_BYTES)),
        kPackCachePageBytes);
    while (candidate != SIZE_MAX && candidate >= minimum && candidate != 0) {
        size_t actual = 0;
        void* memory = ampr_internal_amm_pool_alloc(
            candidate, &actual, "apr.pack.decoded-cache", false,
            kPackCachePageBytes);
        if (memory && actual >= candidate) {
            state.cacheBase = static_cast<uint8_t*>(memory);
            state.cacheBytes = candidate;
            state.cachePageCount = static_cast<uint32_t>(
                candidate / kPackCachePageBytes);
            std::memset(state.cachePageBitmap, 0,
                        sizeof(state.cachePageBitmap));
            std::memset(state.cacheHashHeads, 0,
                        sizeof(state.cacheHashHeads));
            state.cachePageCursor = 0;
            state.cacheFreeHead = 0;
            for (uint32_t i = 0; i < AMPR_EMU_PACK_CACHE_ENTRY_CAP; ++i) {
                state.cacheEntries[i] = {};
                state.cacheEntries[i].freeNext =
                    (i + 1u < AMPR_EMU_PACK_CACHE_ENTRY_CAP)
                        ? i + 1u
                        : kInvalidIndex;
            }
            AMPR_LOGF("apr.pack.cache.init bytes=0x%llx pages=%u pageBytes=0x%llx entries=%u",
                      (unsigned long long)candidate,
                      state.cachePageCount,
                      (unsigned long long)kPackCachePageBytes,
                      (unsigned)AMPR_EMU_PACK_CACHE_ENTRY_CAP);
            return;
        }
        if (memory) {
            (void)ampr_internal_amm_pool_free(memory,
                                              "apr.pack.decoded-cache.short");
        }
        candidate /= 2u;
        candidate &= ~(kPackCachePageBytes - 1u);
    }
    AMPR_LOGF("apr.pack.cache.disabled reason=no-memory target=0x%llx minimum=0x%llx",
              (unsigned long long)state.decodedCacheTargetBytes,
              (unsigned long long)AMPR_EMU_PACK_DECODED_CACHE_MIN_BYTES);
}

static void initialize_caches(PackState& state) {
    const size_t reserveBytes = runtime_cache_reserve_bytes(state);
    size_t reserveActual = 0;
    void* reserve = nullptr;
    if (reserveBytes != 0 && reserveBytes != SIZE_MAX) {
        reserve = ampr_internal_amm_pool_alloc(
            reserveBytes, &reserveActual, "apr.pack.cache-reserve", false,
            kPackCachePageBytes);
    }
    if (!reserve || reserveActual < reserveBytes) {
        if (reserve) {
            (void)ampr_internal_amm_pool_free(
                reserve, "apr.pack.cache-reserve.short");
        }
        AMPR_LOGF("apr.pack.caches.disabled reason=no-runtime-reserve reserve=0x%llx pipelines=%u workers=%u",
                  (unsigned long long)reserveBytes,
                  (unsigned)AMPR_EMU_PACK_PIPELINE_SLOTS,
                  state.requestedWorkers);
        return;
    }

    AMPR_LOGF("apr.pack.caches.reserve bytes=0x%llx pipelines=%u workers=%u",
              (unsigned long long)reserveBytes,
              (unsigned)AMPR_EMU_PACK_PIPELINE_SLOTS,
              state.requestedWorkers);
    initialize_physical_cache(state);
    initialize_decoded_cache(state);
    (void)ampr_internal_amm_pool_free(
        reserve, "apr.pack.cache-reserve.release");
}

static void clear_manifest_view(PackState& state) {
    state.manifestBase = nullptr;
    state.manifestBytes = 0;
    state.coreView = {};
    state.header = nullptr;
    state.files = nullptr;
    state.chunks = nullptr;
    state.packs = nullptr;
    state.strings = nullptr;
    state.stringsBytes = 0;
}

static void release_manifest_storage(PackState& state) {
    if (state.packedFileOrder) {
        (void)ampr_internal_amm_pool_free(
            state.packedFileOrder, "apr.pack.directory-index.release");
        state.packedFileOrder = nullptr;
    }
    state.packedFileCount = 0;
    void* manifest = state.manifestBase;
    clear_manifest_view(state);
    if (manifest) {
        (void)ampr_internal_amm_pool_free(
            manifest, "apr.pack.index.release");
    }
}

static bool load_manifest(PackState& state, bool* absent) {
    if (absent) *absent = false;
    KernelOpenFn openFn = real_open();
    KernelCloseFn closeFn = real_close();
    KernelFstatFn fstatFn = real_fstat();
    if (!openFn || !closeFn || !fstatFn || !real_pread()) return false;

    const int fd = openFn(AMPR_EMU_PACK_INDEX_PATH,
                          SCE_KERNEL_O_RDONLY, static_cast<SceKernelMode>(0));
    if (fd < 0) {
        const int openErrno = fd == -1 ? errno : ampr_posix_errno_from_sce(fd);
        if (absent && openErrno == ENOENT) *absent = true;
        if (openErrno == ENOENT) {
            AMPR_LOGF("apr.pack.index.missing path=%s rc=0x%x",
                      AMPR_EMU_PACK_INDEX_PATH, fd);
        } else {
            AMPR_CRITICAL_LOGF("apr.pack.index.open.fail path=%s rc=0x%x errno=%d",
                               AMPR_EMU_PACK_INDEX_PATH, fd, openErrno);
        }
        return false;
    }
    SceKernelStat stat{};
    const int statRc = fstatFn(fd, &stat);
    if (statRc != 0 || stat.st_size < static_cast<off_t>(sizeof(AmprPackIndexHeader)) ||
        static_cast<uint64_t>(stat.st_size) > AMPR_EMU_PACK_INDEX_MAX_BYTES) {
        (void)closeFn(fd);
        AMPR_CRITICAL_LOGF("apr.pack.index.stat.fail path=%s rc=0x%x size=0x%llx",
                           AMPR_EMU_PACK_INDEX_PATH, statRc,
                           statRc == 0 ? (unsigned long long)stat.st_size : 0ull);
        return false;
    }
    const size_t bytes = static_cast<size_t>(stat.st_size);
    size_t actual = 0;
    void* memory = ampr_internal_amm_pool_alloc(
        bytes, &actual, "apr.pack.index", true,
        alignof(AmprPackIndexHeader));
    if (!memory || actual < bytes || !pread_exact(fd, memory, bytes, 0)) {
        if (memory) (void)ampr_internal_amm_pool_free(memory, "apr.pack.index.fail");
        (void)closeFn(fd);
        AMPR_CRITICAL_LOGF("apr.pack.index.read.fail path=%s bytes=0x%llx",
                           AMPR_EMU_PACK_INDEX_PATH,
                           (unsigned long long)bytes);
        return false;
    }
    (void)closeFn(fd);

    if (!validate_manifest_layout(state, memory, bytes)) {
        (void)ampr_internal_amm_pool_free(memory, "apr.pack.index.invalid");
        clear_manifest_view(state);
        AMPR_CRITICAL_LOGF("apr.pack.index.invalid path=%s bytes=0x%llx",
                           AMPR_EMU_PACK_INDEX_PATH,
                           (unsigned long long)bytes);
        return false;
    }
    state.manifestBase = memory;
    state.manifestBytes = bytes;
    if (!load_runtime_profile(state)) {
        release_manifest_storage(state);
        return false;
    }
    if (!build_packed_file_order(state)) {
        AMPR_CRITICAL_LOGF("apr.pack.directory-index.fail files=%llu",
                           (unsigned long long)state.header->fileCount);
        release_manifest_storage(state);
        return false;
    }
    initialize_caches(state);
    state.profileDecodedBytes = state.cacheBytes;
    state.profilePhysicalBytes = state.physicalCacheBytes;
    AMPR_LOGF("apr.pack.profile.effective loaded=%u decodedTarget=%llu physicalTarget=%llu decodedAllocated=%llu physicalAllocated=%llu workers=%u reserve=%u",
              state.runtimeProfileLoaded ? 1u : 0u,
              (unsigned long long)state.decodedCacheTargetBytes,
              (unsigned long long)state.physicalCacheTargetBytes,
              (unsigned long long)state.cacheBytes,
              (unsigned long long)state.physicalCacheBytes,
              state.requestedWorkers, state.latencyReserveWorkers);
    AMPR_LOGF("apr.pack.index.loaded path=%s files=%llu packed=%u loose=%llu chunks=%llu packs=%u bytes=0x%llx dirOverlay=%u processOpen=%u processAio=%u processSync=%u",
              AMPR_EMU_PACK_INDEX_PATH,
              (unsigned long long)state.header->fileCount,
              state.packedFileCount,
              (unsigned long long)(state.header->fileCount - state.packedFileCount),
              (unsigned long long)state.header->chunkCount,
              state.header->packCount,
              (unsigned long long)bytes,
              AMPR_EMU_PACK_DIRECTORY_OVERLAY_ENABLE ? 1u : 0u,
              AMPR_EMU_PACK_PROCESS_OPEN_ENABLE ? 1u : 0u,
              AMPR_EMU_PACK_INTERCEPT_PROCESS_AIO ? 1u : 0u,
              AMPR_EMU_PACK_INTERCEPT_PROCESS_SYNC_READS ? 1u : 0u);
    return true;
}

static bool ensure_manifest_ready() {
#if !AMPR_EMU_PACK_ENABLE
    return false;
#else
    PackState& state = pack_state();
    for (;;) {
        if (state.workerStopRequested.load(std::memory_order_acquire)) {
            return false;
        }
        const uint32_t current = state.loadState.load(std::memory_order_acquire);
        if (current == kPackLoadReady) return true;
        if (current == kPackLoadUnavailable || current == kPackLoadInvalid) return false;
        uint32_t expected = kPackLoadUninitialized;
        if (state.loadState.compare_exchange_strong(
                expected, kPackLoadLoading,
                std::memory_order_acq_rel,
                std::memory_order_acquire)) {
            bool absent = false;
            const bool loaded = load_manifest(state, &absent);
            {
                AmprLockGuard lock(state.manifestMutex);
                state.loadState.store(
                    loaded ? kPackLoadReady
                           : (absent ? kPackLoadUnavailable : kPackLoadInvalid),
                    std::memory_order_release);
            }
            state.manifestCv.notify_all();
            return loaded;
        }
        AmprUniqueLock lock(state.manifestMutex);
        state.manifestCv.wait(lock, [&state] {
            return state.loadState.load(std::memory_order_acquire) !=
                       kPackLoadLoading ||
                   state.workerStopRequested.load(std::memory_order_acquire);
        });
    }
#endif
}

static uint64_t chunk_key_hash(const AmprPackChunkView& chunk) {
    uint64_t value = chunk.offset;
    value ^= static_cast<uint64_t>(chunk.packId) << 48u;
    value ^= static_cast<uint64_t>(chunk.storedSize) << 16u;
    value ^= static_cast<uint64_t>(chunk.rawSize) << 32u;
    return mix64(value) | 1ull;
}

static bool cache_key_equal(const CacheEntry& entry,
                            const AmprPackChunkView& chunk,
                            uint64_t keyHash) {
    return entry.state != CacheEntryState::Free &&
           entry.keyHash == keyHash &&
           entry.packId == chunk.packId &&
           entry.physicalOffset == chunk.offset &&
           entry.storedSize == chunk.storedSize &&
           entry.rawSize == chunk.rawSize;
}

static uint32_t cache_find_locked(PackState& state,
                                  const AmprPackChunkView& chunk,
                                  uint64_t keyHash) {
    const uint32_t bucket = static_cast<uint32_t>(
        keyHash & (AMPR_EMU_PACK_CACHE_HASH_BUCKETS - 1u));
    uint32_t link = state.cacheHashHeads[bucket];
    while (link != 0) {
        const uint32_t index = link - 1u;
        if (index >= AMPR_EMU_PACK_CACHE_ENTRY_CAP) break;
        const CacheEntry& entry = state.cacheEntries[index];
        if (cache_key_equal(entry, chunk, keyHash)) return index;
        link = entry.hashNextPlusOne;
    }
    return kInvalidIndex;
}

static void cache_hash_link_locked(PackState& state, uint32_t index) {
    CacheEntry& entry = state.cacheEntries[index];
    const uint32_t bucket = static_cast<uint32_t>(
        entry.keyHash & (AMPR_EMU_PACK_CACHE_HASH_BUCKETS - 1u));
    entry.hashNextPlusOne = state.cacheHashHeads[bucket];
    state.cacheHashHeads[bucket] = index + 1u;
}

static void cache_hash_unlink_locked(PackState& state, uint32_t index) {
    CacheEntry& entry = state.cacheEntries[index];
    const uint32_t bucket = static_cast<uint32_t>(
        entry.keyHash & (AMPR_EMU_PACK_CACHE_HASH_BUCKETS - 1u));
    uint32_t* link = &state.cacheHashHeads[bucket];
    while (*link != 0) {
        const uint32_t current = *link - 1u;
        if (current == index) {
            *link = entry.hashNextPlusOne;
            entry.hashNextPlusOne = 0;
            return;
        }
        if (current >= AMPR_EMU_PACK_CACHE_ENTRY_CAP) break;
        link = &state.cacheEntries[current].hashNextPlusOne;
    }
    entry.hashNextPlusOne = 0;
}

static bool cache_bitmap_page_used(const uint64_t* bitmap, uint32_t page) {
    return (bitmap[page / 64u] & (1ull << (page & 63u))) != 0;
}

static uint32_t cache_find_page_run_range(const uint64_t* bitmap,
                                          uint32_t begin,
                                          uint32_t end,
                                          uint32_t count) {
    uint32_t runStart = begin;
    uint32_t runLength = 0;
    for (uint32_t page = begin; page < end; ++page) {
        if (!cache_bitmap_page_used(bitmap, page)) {
            if (runLength == 0) runStart = page;
            if (++runLength == count) return runStart;
        } else {
            runLength = 0;
        }
    }
    return kInvalidIndex;
}

static uint32_t cache_find_page_run_next_fit(const uint64_t* bitmap,
                                             uint32_t pageCount,
                                             uint32_t cursor,
                                             uint32_t count) {
    if (count == 0 || count > pageCount) return kInvalidIndex;
    if (cursor >= pageCount) cursor = 0;
    uint32_t found = cache_find_page_run_range(
        bitmap, cursor, pageCount, count);
    if (found == kInvalidIndex && cursor != 0) {
        // Include at most count-1 pages beyond the cursor on the wrap scan so
        // a contiguous run spanning the cursor remains eligible without
        // rescanning the complete suffix that just failed.
        const uint64_t wrapEnd64 = static_cast<uint64_t>(cursor) + count - 1u;
        const uint32_t wrapEnd = wrapEnd64 < pageCount
                                     ? static_cast<uint32_t>(wrapEnd64)
                                     : pageCount;
        found = cache_find_page_run_range(bitmap, 0, wrapEnd, count);
    }
    return found;
}

static void cache_mark_pages(PackState& state,
                             uint32_t start,
                             uint32_t count,
                             bool used) {
    for (uint32_t page = start; page < start + count; ++page) {
        uint64_t& word = state.cachePageBitmap[page / 64u];
        const uint64_t mask = 1ull << (page & 63u);
        if (used) word |= mask;
        else word &= ~mask;
    }
}

static uint32_t cache_find_page_run_locked(PackState& state, uint32_t count) {
    return cache_find_page_run_next_fit(
        state.cachePageBitmap, state.cachePageCount,
        state.cachePageCursor, count);
}

static void cache_release_entry_locked(PackState& state, uint32_t index) {
    CacheEntry& entry = state.cacheEntries[index];
    cache_hash_unlink_locked(state, index);
    if (entry.pageCount != 0) {
        cache_mark_pages(state, entry.pageStart, entry.pageCount, false);
    }
    entry = {};
    entry.state = CacheEntryState::Free;
    entry.freeNext = state.cacheFreeHead;
    state.cacheFreeHead = index;
}

static bool cache_evict_one_locked(PackState& state) {
    for (uint32_t attempt = 0;
         attempt < AMPR_EMU_PACK_CACHE_ENTRY_CAP * 2u;
         ++attempt) {
        const uint32_t index = state.cacheClock++ %
                               AMPR_EMU_PACK_CACHE_ENTRY_CAP;
        CacheEntry& entry = state.cacheEntries[index];
        if (entry.state == CacheEntryState::Free || entry.pinCount != 0 ||
            entry.state == CacheEntryState::Loading) {
            continue;
        }
        if (entry.referenced) {
            entry.referenced = false;
            continue;
        }
        cache_release_entry_locked(state, index);
        state.stats.cacheEvictions.fetch_add(1, std::memory_order_relaxed);
        return true;
    }
    return false;
}

static bool cache_should_admit_locked(PackState& state,
                                      const AmprPackChunkView& chunk,
                                      uint32_t fileFlags,
                                      uint64_t keyHash) {
    if ((fileFlags & kAmprPackFileStreaming) != 0 ||
        (chunk.flags & kAmprPackChunkStreaming) != 0) {
        return false;
    }
    if ((fileFlags & kAmprPackFileHot) != 0 ||
        (chunk.flags & kAmprPackChunkShared) != 0) {
        return true;
    }
    TouchEntry& touch = state.touches[
        keyHash & (AMPR_EMU_PACK_TOUCH_TABLE_SIZE - 1u)];
    if (touch.keyHash != keyHash) {
        touch.keyHash = keyHash;
        touch.count = 1;
        return false;
    }
    if (touch.count < 3u) ++touch.count;
    return touch.count >= 2u;
}

static CacheAcquireResult cache_acquire(const AmprPackChunkView& chunk,
                                        uint32_t fileFlags,
                                        bool waitForLoader = true) {
    PackState& state = pack_state();
    CacheAcquireResult result{};
    if (!state.cacheBase || state.cachePageCount == 0) {
        state.stats.cacheMisses.fetch_add(1, std::memory_order_relaxed);
        return result;
    }
    const uint64_t keyHash = chunk_key_hash(chunk);
    for (;;) {
        AmprUniqueLock lock(state.cacheMutex);
        const uint32_t found = cache_find_locked(state, chunk, keyHash);
        if (found != kInvalidIndex) {
            CacheEntry& entry = state.cacheEntries[found];
            if (entry.state == CacheEntryState::Loading) {
                state.stats.cacheLoadingJoins.fetch_add(1,
                                                        std::memory_order_relaxed);
                if (!waitForLoader) {
                    result.kind = CacheAcquireKind::Pending;
                    return result;
                }
                state.cacheCvs[
                    keyHash & (kPackCacheWaitBucketCount - 1u)].wait(lock);
                continue;
            }
            if (entry.state == CacheEntryState::Ready) {
                ++entry.pinCount;
                entry.referenced = true;
                result.kind = CacheAcquireKind::Ready;
                result.lease.entry = found;
                result.lease.data = state.cacheBase +
                    static_cast<size_t>(entry.pageStart) * kPackCachePageBytes;
                state.stats.cacheHits.fetch_add(1, std::memory_order_relaxed);
                return result;
            }
            if (entry.state == CacheEntryState::Failed) {
                result.kind = CacheAcquireKind::Failed;
                result.lease.error = entry.error ? entry.error
                                                 : SCE_KERNEL_ERROR_EIO;
                state.stats.cacheHits.fetch_add(1, std::memory_order_relaxed);
                return result;
            }
        }

        state.stats.cacheMisses.fetch_add(1, std::memory_order_relaxed);
        if (!cache_should_admit_locked(state, chunk, fileFlags, keyHash)) {
            return result;
        }
        const uint32_t pageCount = static_cast<uint32_t>(
            (chunk.rawSize + kPackCachePageBytes - 1u) /
            kPackCachePageBytes);
        uint32_t pageStart = cache_find_page_run_locked(state, pageCount);
        while ((pageStart == kInvalidIndex ||
                state.cacheFreeHead == kInvalidIndex) &&
               cache_evict_one_locked(state)) {
            pageStart = cache_find_page_run_locked(state, pageCount);
        }
        if (pageStart == kInvalidIndex || state.cacheFreeHead == kInvalidIndex) {
            return result;
        }
        const uint32_t index = state.cacheFreeHead;
        CacheEntry& entry = state.cacheEntries[index];
        state.cacheFreeHead = entry.freeNext;
        entry = {};
        entry.keyHash = keyHash;
        entry.physicalOffset = chunk.offset;
        entry.storedSize = chunk.storedSize;
        entry.rawSize = chunk.rawSize;
        entry.pageStart = pageStart;
        entry.pageCount = pageCount;
        entry.pinCount = 1;
        entry.packId = chunk.packId;
        entry.state = CacheEntryState::Loading;
        entry.referenced = true;
        entry.freeNext = kInvalidIndex;
        cache_mark_pages(state, pageStart, pageCount, true);
        const uint32_t pageEnd = pageStart + pageCount;
        state.cachePageCursor = pageEnd == state.cachePageCount ? 0 : pageEnd;
        cache_hash_link_locked(state, index);
        state.stats.cacheAdmissions.fetch_add(1, std::memory_order_relaxed);
        result.kind = CacheAcquireKind::Load;
        result.lease.entry = index;
        result.lease.data = state.cacheBase +
            static_cast<size_t>(pageStart) * kPackCachePageBytes;
        result.lease.loader = true;
        return result;
    }
}

static bool cache_error_is_transient(int error) {
    return error == SCE_KERNEL_ERROR_EAGAIN ||
           error == SCE_KERNEL_ERROR_EMFILE ||
           error == SCE_KERNEL_ERROR_ECANCELED;
}

static void cache_publish(CacheLease& lease, int error) {
    if (lease.entry == kInvalidIndex) return;
    PackState& state = pack_state();
    uint32_t waitBucket = 0;
    {
        AmprLockGuard lock(state.cacheMutex);
        if (lease.entry >= AMPR_EMU_PACK_CACHE_ENTRY_CAP) return;
        CacheEntry& entry = state.cacheEntries[lease.entry];
        if (entry.state != CacheEntryState::Loading || entry.pinCount == 0) return;
        waitBucket = static_cast<uint32_t>(
            entry.keyHash & (kPackCacheWaitBucketCount - 1u));
        if (error == 0) {
            entry.state = CacheEntryState::Ready;
            entry.error = 0;
        } else if (cache_error_is_transient(error) && entry.pinCount == 1) {
            // Pending readers do not pin loading entries. Remove a transient
            // loader failure before waking them so none can observe a short-
            // lived Failed entry and turn pressure into a logical I/O error.
            cache_release_entry_locked(state, lease.entry);
            lease = {};
            lease.entry = kInvalidIndex;
        } else {
            entry.state = CacheEntryState::Failed;
            entry.error = error;
        }
    }
    state.decodedCachePublicationEpoch[waitBucket].fetch_add(
        1, std::memory_order_release);
    state.cacheCvs[waitBucket].notify_all();
}

static void cache_release(CacheLease& lease) {
    if (lease.entry == kInvalidIndex) return;
    PackState& state = pack_state();
    AmprLockGuard lock(state.cacheMutex);
    if (lease.entry < AMPR_EMU_PACK_CACHE_ENTRY_CAP) {
        CacheEntry& entry = state.cacheEntries[lease.entry];
        if (entry.pinCount != 0) --entry.pinCount;
        if (entry.pinCount == 0 && entry.state == CacheEntryState::Failed &&
            cache_error_is_transient(entry.error)) {
            cache_release_entry_locked(state, lease.entry);
        }
    }
    lease = {};
    lease.entry = kInvalidIndex;
}

static bool cache_try_pin_ready(const AmprPackChunkView& chunk,
                                CacheLease* out) {
    if (out) {
        *out = {};
        out->entry = kInvalidIndex;
    }
    if (!out) return false;
    PackState& state = pack_state();
    if (!state.cacheBase || state.cachePageCount == 0) return false;
    const uint64_t keyHash = chunk_key_hash(chunk);
    AmprLockGuard lock(state.cacheMutex);
    const uint32_t found = cache_find_locked(state, chunk, keyHash);
    if (found == kInvalidIndex) return false;
    CacheEntry& entry = state.cacheEntries[found];
    if (entry.state != CacheEntryState::Ready) return false;
    ++entry.pinCount;
    entry.referenced = true;
    out->entry = found;
    out->data = state.cacheBase +
        static_cast<size_t>(entry.pageStart) * kPackCachePageBytes;
    state.stats.cacheHits.fetch_add(1, std::memory_order_relaxed);
    return true;
}

static uint64_t physical_cache_key_hash(uint16_t packId,
                                        uint64_t offset,
                                        uint32_t size) {
    uint64_t value = offset;
    value ^= static_cast<uint64_t>(packId) << 48u;
    value ^= static_cast<uint64_t>(size) << 17u;
    return mix64(value) | 1ull;
}

static uint32_t cache_wait_bucket(uint64_t keyHash) {
    return static_cast<uint32_t>(
        keyHash & (kPackCacheWaitBucketCount - 1u));
}

static uint64_t cache_wait_epoch(const PackState& state,
                                 CacheWaitDomain domain,
                                 uint32_t bucket) {
    if (bucket >= kPackCacheWaitBucketCount) return 0;
    const std::atomic<uint64_t>* epochs =
        domain == CacheWaitDomain::Physical
            ? state.physicalCachePublicationEpoch
            : state.decodedCachePublicationEpoch;
    return epochs[bucket].load(std::memory_order_acquire);
}

static void prepare_cache_wait(ReadPipelineContext& pipeline,
                               CacheWaitDomain domain,
                               uint64_t keyHash) {
    PackState& state = pack_state();
    pipeline.cacheWaitDomain = domain;
    pipeline.cacheWaitBucket = static_cast<uint16_t>(
        cache_wait_bucket(keyHash));
    pipeline.cacheWaitEpoch = cache_wait_epoch(
        state, domain, pipeline.cacheWaitBucket);
}

static bool physical_cache_key_equal(const PhysicalCacheEntry& entry,
                                     uint16_t packId,
                                     uint64_t offset,
                                     uint32_t size,
                                     uint64_t keyHash) {
    return entry.state != PhysicalCacheEntryState::Free &&
           entry.keyHash == keyHash && entry.packId == packId &&
           entry.physicalOffset == offset && entry.size == size;
}

static uint32_t physical_cache_find_locked(PackState& state,
                                           uint16_t packId,
                                           uint64_t offset,
                                           uint32_t size,
                                           uint64_t keyHash) {
    const uint32_t bucket = static_cast<uint32_t>(
        keyHash & (AMPR_EMU_PACK_PHYSICAL_CACHE_HASH_BUCKETS - 1u));
    uint32_t link = state.physicalCacheHashHeads[bucket];
    while (link != 0) {
        const uint32_t index = link - 1u;
        if (index >= AMPR_EMU_PACK_PHYSICAL_CACHE_ENTRY_CAP) break;
        const PhysicalCacheEntry& entry = state.physicalCacheEntries[index];
        if (physical_cache_key_equal(
                entry, packId, offset, size, keyHash)) {
            return index;
        }
        link = entry.hashNextPlusOne;
    }
    return kInvalidIndex;
}

static void physical_cache_hash_link_locked(PackState& state,
                                            uint32_t index) {
    PhysicalCacheEntry& entry = state.physicalCacheEntries[index];
    const uint32_t bucket = static_cast<uint32_t>(
        entry.keyHash & (AMPR_EMU_PACK_PHYSICAL_CACHE_HASH_BUCKETS - 1u));
    entry.hashNextPlusOne = state.physicalCacheHashHeads[bucket];
    state.physicalCacheHashHeads[bucket] = index + 1u;
}

static void physical_cache_hash_unlink_locked(PackState& state,
                                              uint32_t index) {
    PhysicalCacheEntry& entry = state.physicalCacheEntries[index];
    const uint32_t bucket = static_cast<uint32_t>(
        entry.keyHash & (AMPR_EMU_PACK_PHYSICAL_CACHE_HASH_BUCKETS - 1u));
    uint32_t* link = &state.physicalCacheHashHeads[bucket];
    while (*link != 0) {
        const uint32_t current = *link - 1u;
        if (current == index) {
            *link = entry.hashNextPlusOne;
            entry.hashNextPlusOne = 0;
            return;
        }
        if (current >= AMPR_EMU_PACK_PHYSICAL_CACHE_ENTRY_CAP) break;
        link = &state.physicalCacheEntries[current].hashNextPlusOne;
    }
    entry.hashNextPlusOne = 0;
}

static void physical_cache_mark_pages(PackState& state,
                                      uint32_t start,
                                      uint32_t count,
                                      bool used) {
    for (uint32_t page = start; page < start + count; ++page) {
        uint64_t& word = state.physicalCachePageBitmap[page / 64u];
        const uint64_t mask = 1ull << (page & 63u);
        if (used) word |= mask;
        else word &= ~mask;
    }
}

static uint32_t physical_cache_find_page_run_locked(PackState& state,
                                                    uint32_t count) {
    return cache_find_page_run_next_fit(
        state.physicalCachePageBitmap, state.physicalCachePageCount,
        state.physicalCachePageCursor, count);
}

static void physical_cache_release_entry_locked(PackState& state,
                                                uint32_t index) {
    PhysicalCacheEntry& entry = state.physicalCacheEntries[index];
    physical_cache_hash_unlink_locked(state, index);
    if (entry.pageCount != 0) {
        physical_cache_mark_pages(
            state, entry.pageStart, entry.pageCount, false);
    }
    entry = {};
    entry.state = PhysicalCacheEntryState::Free;
    entry.freeNext = state.physicalCacheFreeHead;
    state.physicalCacheFreeHead = index;
}

static bool physical_cache_evict_one_locked(PackState& state) {
    for (uint32_t attempt = 0;
         attempt < AMPR_EMU_PACK_PHYSICAL_CACHE_ENTRY_CAP * 2u;
         ++attempt) {
        const uint32_t index = state.physicalCacheClock++ %
            AMPR_EMU_PACK_PHYSICAL_CACHE_ENTRY_CAP;
        PhysicalCacheEntry& entry = state.physicalCacheEntries[index];
        if (entry.state == PhysicalCacheEntryState::Free ||
            entry.pinCount != 0 ||
            entry.state == PhysicalCacheEntryState::Loading) {
            continue;
        }
        if (entry.referenced) {
            entry.referenced = false;
            continue;
        }
        physical_cache_release_entry_locked(state, index);
        state.stats.physicalPageEvictions.fetch_add(
            1, std::memory_order_relaxed);
        return true;
    }
    return false;
}

static bool physical_cache_request_valid(const PackState& state,
                                         uint64_t offset,
                                         uint32_t size) {
    return state.physicalCacheBase && state.physicalCachePageCount != 0 &&
           size != 0 && size <= (1u << kAmprPackIoPageShiftMax) &&
           (offset & (static_cast<uint64_t>(size) - 1u)) == 0;
}

static PhysicalCacheAcquireResult physical_cache_acquire_locked(
    PackState& state,
    uint16_t packId,
    uint64_t offset,
    uint32_t size,
    uint64_t keyHash) {
    PhysicalCacheAcquireResult result{};
    const uint32_t found = physical_cache_find_locked(
        state, packId, offset, size, keyHash);
    if (found != kInvalidIndex) {
        PhysicalCacheEntry& entry = state.physicalCacheEntries[found];
        if (entry.state == PhysicalCacheEntryState::Loading) {
            state.stats.physicalPageLoadingJoins.fetch_add(
                1, std::memory_order_relaxed);
            result.kind = PhysicalCacheAcquireKind::Pending;
            return result;
        }
        if (entry.state == PhysicalCacheEntryState::Ready) {
            ++entry.pinCount;
            entry.referenced = true;
            result.kind = PhysicalCacheAcquireKind::Ready;
            result.lease.entry = found;
            result.lease.data = state.physicalCacheBase +
                static_cast<size_t>(entry.pageStart) *
                kPackCachePageBytes;
            state.stats.physicalPageHits.fetch_add(
                1, std::memory_order_relaxed);
            return result;
        }
        if (entry.state == PhysicalCacheEntryState::Failed) {
            result.kind = PhysicalCacheAcquireKind::Failed;
            result.lease.error = entry.error ? entry.error
                                             : SCE_KERNEL_ERROR_EIO;
            return result;
        }
    }

    state.stats.physicalPageMisses.fetch_add(
        1, std::memory_order_relaxed);
    const uint32_t pageCount = static_cast<uint32_t>(
        (size + kPackCachePageBytes - 1u) / kPackCachePageBytes);
    uint32_t pageStart = physical_cache_find_page_run_locked(
        state, pageCount);
    while ((pageStart == kInvalidIndex ||
            state.physicalCacheFreeHead == kInvalidIndex) &&
           physical_cache_evict_one_locked(state)) {
        pageStart = physical_cache_find_page_run_locked(
            state, pageCount);
    }
    if (pageStart == kInvalidIndex ||
        state.physicalCacheFreeHead == kInvalidIndex) {
        state.stats.physicalPageBypasses.fetch_add(
            1, std::memory_order_relaxed);
        return result;
    }

    const uint32_t index = state.physicalCacheFreeHead;
    PhysicalCacheEntry& entry = state.physicalCacheEntries[index];
    state.physicalCacheFreeHead = entry.freeNext;
    entry = {};
    entry.keyHash = keyHash;
    entry.physicalOffset = offset;
    entry.size = size;
    entry.pageStart = pageStart;
    entry.pageCount = pageCount;
    entry.pinCount = 1;
    entry.packId = packId;
    entry.state = PhysicalCacheEntryState::Loading;
    entry.referenced = true;
    entry.freeNext = kInvalidIndex;
    physical_cache_mark_pages(state, pageStart, pageCount, true);
    const uint32_t pageEnd = pageStart + pageCount;
    state.physicalCachePageCursor =
        pageEnd == state.physicalCachePageCount ? 0 : pageEnd;
    physical_cache_hash_link_locked(state, index);
    state.stats.physicalPageAdmissions.fetch_add(
        1, std::memory_order_relaxed);
    result.kind = PhysicalCacheAcquireKind::Load;
    result.lease.entry = index;
    result.lease.data = state.physicalCacheBase +
        static_cast<size_t>(pageStart) * kPackCachePageBytes;
    result.lease.loader = true;
    return result;
}

static size_t physical_cache_acquire_batch(
    const PhysicalCacheAcquireBatchItem* items,
    size_t itemCount) {
    if (!items || itemCount == 0) return 0;
    PackState& state = pack_state();
    AmprLockGuard lock(state.physicalCacheMutex);
    size_t processed = 0;
    for (; processed < itemCount; ++processed) {
        const PhysicalCacheAcquireBatchItem& item = items[processed];
        if (!item.result) break;
        *item.result = {};
        if (!physical_cache_request_valid(state, item.offset, item.size)) {
            state.stats.physicalPageMisses.fetch_add(
                1, std::memory_order_relaxed);
            state.stats.physicalPageBypasses.fetch_add(
                1, std::memory_order_relaxed);
        } else {
            *item.result = physical_cache_acquire_locked(
                state,
                item.packId,
                item.offset,
                item.size,
                physical_cache_key_hash(
                    item.packId, item.offset, item.size));
        }
        const PhysicalCacheAcquireKind kind = item.result->kind;
        if (kind != PhysicalCacheAcquireKind::Ready &&
            kind != PhysicalCacheAcquireKind::Load) {
            return processed + 1u;
        }
    }
    return processed;
}

static void physical_cache_publish_batch(
    const PhysicalCachePublication* publications,
    size_t publicationCount) {
    if (!publications || publicationCount == 0) return;
    PackState& state = pack_state();
    bool published = false;
    uint64_t publishedBuckets = 0;
    {
        AmprLockGuard lock(state.physicalCacheMutex);
        for (size_t publicationIndex = 0;
             publicationIndex < publicationCount;
             ++publicationIndex) {
            const PhysicalCachePublication& publication =
                publications[publicationIndex];
            if (!publication.lease ||
                publication.lease->entry == kInvalidIndex ||
                publication.lease->entry >=
                    AMPR_EMU_PACK_PHYSICAL_CACHE_ENTRY_CAP) {
                continue;
            }
            PhysicalCacheEntry& entry = state.physicalCacheEntries[
                publication.lease->entry];
            if (entry.state != PhysicalCacheEntryState::Loading ||
                entry.pinCount == 0) {
                continue;
            }
            if (publication.error == 0) {
                entry.state = PhysicalCacheEntryState::Ready;
                entry.error = 0;
            } else if (cache_error_is_transient(publication.error) &&
                       entry.pinCount == 1) {
                const uint32_t waitBucket = cache_wait_bucket(entry.keyHash);
                physical_cache_release_entry_locked(
                    state, publication.lease->entry);
                *publication.lease = {};
                publication.lease->entry = kInvalidIndex;
                publishedBuckets |= 1ull << waitBucket;
                published = true;
                continue;
            } else {
                entry.state = PhysicalCacheEntryState::Failed;
                entry.error = publication.error;
            }
            publishedBuckets |= 1ull << cache_wait_bucket(entry.keyHash);
            published = true;
        }
    }
    if (!published) return;
    for (uint32_t bucket = 0;
         bucket < kPackCacheWaitBucketCount;
         ++bucket) {
        if ((publishedBuckets & (1ull << bucket)) == 0) continue;
        state.physicalCachePublicationEpoch[bucket].fetch_add(
            1, std::memory_order_release);
    }
}

static void physical_cache_release_locked(PackState& state,
                                          PhysicalCacheLease& lease) {
    if (lease.entry == kInvalidIndex) return;
    if (lease.entry < AMPR_EMU_PACK_PHYSICAL_CACHE_ENTRY_CAP) {
        PhysicalCacheEntry& entry =
            state.physicalCacheEntries[lease.entry];
        if (entry.pinCount != 0) --entry.pinCount;
        if (entry.pinCount == 0 &&
            entry.state == PhysicalCacheEntryState::Failed &&
            cache_error_is_transient(entry.error)) {
            physical_cache_release_entry_locked(state, lease.entry);
        }
    }
    lease = {};
    lease.entry = kInvalidIndex;
}

static void physical_cache_release_batch(PhysicalCacheLease* const* leases,
                                         size_t leaseCount) {
    if (!leases || leaseCount == 0) return;
    PackState& state = pack_state();
    AmprLockGuard lock(state.physicalCacheMutex);
    for (size_t leaseIndex = 0;
         leaseIndex < leaseCount;
         ++leaseIndex) {
        if (leases[leaseIndex]) {
            physical_cache_release_locked(state, *leases[leaseIndex]);
        }
    }
}

static void physical_cache_invalidate(uint16_t packId,
                                      uint64_t offset,
                                      uint32_t size) {
    if (size == 0) return;
    PackState& state = pack_state();
    const uint64_t keyHash = physical_cache_key_hash(packId, offset, size);
    AmprLockGuard lock(state.physicalCacheMutex);
    const uint32_t found = physical_cache_find_locked(
        state, packId, offset, size, keyHash);
    if (found == kInvalidIndex) return;
    PhysicalCacheEntry& entry = state.physicalCacheEntries[found];
    if (entry.pinCount == 0 &&
        entry.state != PhysicalCacheEntryState::Loading) {
        physical_cache_release_entry_locked(state, found);
    } else if (entry.state == PhysicalCacheEntryState::Ready) {
        entry.state = PhysicalCacheEntryState::Failed;
        entry.error = SCE_KERNEL_ERROR_EIO;
    }
}

static bool build_pack_path(const PackState& state,
                            uint16_t packId,
                            char* output,
                            size_t outputSize) {
    if (!output || outputSize == 0 || !state.header ||
        packId >= state.header->packCount) return false;
    const AmprPackDataRecord& record = state.packs[packId];
    const char* name = manifest_string(state, record.nameOffset, record.nameLength);
    static constexpr const char root[] = AMPR_EMU_PACK_ROOT_PATH;
    static constexpr size_t rootLength = sizeof(root) - 1u;
    const bool needsSlash = rootLength != 0 && root[rootLength - 1u] != '/';
    const size_t prefixLength = rootLength + (needsSlash ? 1u : 0u);
    if (!name || prefixLength + record.nameLength + 1u > outputSize) {
        return false;
    }
    std::memcpy(output, root, rootLength);
    if (needsSlash) output[rootLength] = '/';
    std::memcpy(output + prefixLength, name, record.nameLength);
    output[prefixLength + record.nameLength] = '\0';
    return true;
}

static bool validate_data_header(const PackState& state,
                                 uint16_t packId,
                                 int fd,
                                 uint64_t fileSize,
                                 uint64_t* payloadBegin,
                                 uint64_t* payloadEnd) {
    AmprPackDataHeader header{};
    if (!pread_exact(fd, &header, sizeof(header), 0) ||
        !bytes_equal(header.magic, kAmprPackDataMagic, sizeof(header.magic)) ||
        header.version != kAmprPackDataVersion ||
        header.headerSize != sizeof(header) ||
        header.packId != packId ||
        header.flags != state.packs[packId].flags ||
        (header.flags & ~kAmprPackDataKnownFlags) != 0 ||
        header.reserved != 0 ||
        !bytes_equal(header.buildId, state.header->buildId,
                     sizeof(header.buildId))) {
        return false;
    }
    AmprPackDataHeader copy = header;
    copy.headerCrc32 = 0;
    uint64_t end = 0;
    if (ampr_pack_crc32(&copy, sizeof(copy)) != header.headerCrc32 ||
        !checked_add_u64(header.payloadOffset, header.payloadBytes, &end) ||
        header.payloadOffset < sizeof(AmprPackDataHeader) ||
        (header.payloadOffset & (state.packs[packId].ioPageSize - 1u)) != 0 ||
        (fileSize & (state.packs[packId].ioPageSize - 1u)) != 0 ||
        end != fileSize ||
        header.payloadBytes != state.packs[packId].payloadBytes ||
        fileSize != state.packs[packId].fileSize) {
        return false;
    }
    if (payloadBegin) *payloadBegin = header.payloadOffset;
    if (payloadEnd) *payloadEnd = end;
    return true;
}

static bool wake_fd_waiters_locked(PackState& state);

static int acquire_pack_fd(uint16_t packId) {
    PackState& state = pack_state();
    char path[SCE_KERNEL_PATH_MAX]{};
    KernelOpenFn openFn = real_open();
    KernelFstatFn fstatFn = real_fstat();
    if (!openFn || !real_close() || !fstatFn) return SCE_KERNEL_ERROR_EIO;
    int victimFd = -1;
    for (;;) {
        AmprUniqueLock lock(state.m);
        if (!state.header || packId >= state.header->packCount) {
            return SCE_KERNEL_ERROR_EINVAL;
        }
        PackHandle& handle = state.packHandles[packId];
        if (handle.fd >= 0) {
            if (handle.pins == UINT32_MAX) {
                return SCE_KERNEL_ERROR_EBUSY;
            }
            ++handle.pins;
            handle.lastUse = state.tick++;
            return handle.fd;
        }
        if (handle.opening) {
            return SCE_KERNEL_ERROR_EAGAIN;
        }
        if (!build_pack_path(state, packId, path, sizeof(path))) {
            return SCE_KERNEL_ERROR_ENAMETOOLONG;
        }

        if (state.openPackCount + state.openingPackCount >=
            AMPR_EMU_PACK_OPEN_PACK_FD_CAP) {
            uint32_t victim = kInvalidIndex;
            uint64_t oldest = UINT64_MAX;
            for (uint32_t i = 0; i < state.header->packCount; ++i) {
                const PackHandle& candidate = state.packHandles[i];
                if (candidate.fd >= 0 && candidate.pins == 0 &&
                    !candidate.opening && candidate.lastUse < oldest) {
                    victim = i;
                    oldest = candidate.lastUse;
                }
            }
            if (victim == kInvalidIndex) {
                return SCE_KERNEL_ERROR_EAGAIN;
            }
            victimFd = state.packHandles[victim].fd;
            state.packHandles[victim] = {};
            state.packHandles[victim].fd = -1;
            if (state.openPackCount == 0) {
                AMPR_KLOGF("ampr.abort reason=apr.pack.fd.open-count-underflow file=%s line=%d",
                           __FILE__, __LINE__);
                std::abort();
            }
            --state.openPackCount;
        }

        handle.opening = true;
        ++state.openingPackCount;
        break;
    }

    if (victimFd >= 0) {
        (void)close_physical_pack_fd(victimFd);
    }
    if (!ampr_index_fd_cache_release_open_fd_budget_headroom(1u)) {
        {
            AmprLockGuard lock(state.m);
            PackHandle& handle = state.packHandles[packId];
            if (!handle.opening || state.openingPackCount == 0) {
                AMPR_KLOGF("ampr.abort reason=apr.pack.fd.budget-state-corrupt file=%s line=%d",
                           __FILE__, __LINE__);
                std::abort();
            }
            handle.opening = false;
            --state.openingPackCount;
        }
        return SCE_KERNEL_ERROR_EAGAIN;
    }
    int fd = openFn(path, SCE_KERNEL_O_RDONLY | O_NONBLOCK,
                    static_cast<SceKernelMode>(0));
    if (fd >= 0) {
        ampr_index_fd_pack_note_open();
    }
    SceKernelStat stat{};
    const int statRc = fd >= 0 ? fstatFn(fd, &stat) : fd;
    uint64_t payloadBegin = 0;
    uint64_t payloadEnd = 0;
    int result = fd;
    if (fd >= 0) {
        if (statRc != 0 || stat.st_size < 0 ||
            !validate_data_header(state, packId, fd,
                                  static_cast<uint64_t>(stat.st_size),
                                  &payloadBegin, &payloadEnd)) {
            (void)close_physical_pack_fd(fd);
            fd = -1;
            result = statRc != 0 ? statRc : SCE_KERNEL_ERROR_EIO;
        } else {
            result = fd;
#if AMPR_EMU_PACK_IO_LOG
            AMPR_LOGF("apr.pack.volume.open packId=%u path=%s fd=%d payloadBegin=0x%llx payloadEnd=0x%llx",
                      (unsigned)packId, path, fd,
                      (unsigned long long)payloadBegin,
                      (unsigned long long)payloadEnd);
#endif
        }
    }
    bool wakeWorkers = false;
    {
        AmprLockGuard lock(state.m);
        PackHandle& handle = state.packHandles[packId];
        if (!handle.opening || state.openingPackCount == 0) {
            AMPR_KLOGF("ampr.abort reason=apr.pack.fd.open-state-corrupt file=%s line=%d",
                       __FILE__, __LINE__);
            std::abort();
        }
        handle.opening = false;
        --state.openingPackCount;
        if (fd >= 0) {
            handle.fd = fd;
            handle.pins = 1;
            handle.lastUse = state.tick++;
            handle.payloadBegin = payloadBegin;
            handle.payloadEnd = payloadEnd;
            ++state.openPackCount;
        }
        state.packFdProgressEpoch.fetch_add(1, std::memory_order_release);
        wakeWorkers = wake_fd_waiters_locked(state);
    }
    if (wakeWorkers) state.queueCv.notify_all();
    return result;
}

static void release_pack_fd(uint16_t packId) {
    PackState& state = pack_state();
    bool wakeWorkers = false;
    {
        AmprLockGuard lock(state.m);
        if (!state.header || packId >= state.header->packCount) return;
        PackHandle& handle = state.packHandles[packId];
        if (handle.pins != 0) {
            --handle.pins;
            state.packFdProgressEpoch.fetch_add(1, std::memory_order_release);
            wakeWorkers = wake_fd_waiters_locked(state);
        }
        handle.lastUse = state.tick++;
    }
    if (wakeWorkers) state.queueCv.notify_all();
}

#if AMPR_EMU_DEBUG_LOG && AMPR_EMU_PACK_TELEMETRY
static void log_latency_histogram(const char* kind,
                                  const PackTelemetryCounter (&source)[32]) {
    uint64_t bins[32]{};
    uint64_t count = 0;
    for (uint32_t i = 0; i < 32; ++i) {
        bins[i] = source[i].load(std::memory_order_relaxed);
        count += bins[i];
    }
    const auto percentile = [&](uint64_t percent) -> uint64_t {
        if (count == 0) return 0;
        const uint64_t rank = (count / 100u) * percent +
                             ((count % 100u) * percent + 99u) / 100u;
        uint64_t cumulative = 0;
        for (uint32_t i = 0; i < 32; ++i) {
            cumulative += bins[i];
            if (cumulative >= rank) {
                return i == 31 ? UINT64_MAX : (1ull << i);
            }
        }
        return UINT64_MAX;
    };
    AMPR_LOGF("apr.pack.latency kind=%s samples=%llu p50=%llu p95=%llu p99=%llu overflow=%llu",
              kind, (unsigned long long)count,
              (unsigned long long)percentile(50),
              (unsigned long long)percentile(95),
              (unsigned long long)percentile(99), (unsigned long long)bins[31]);
}
#endif

static void log_pack_io_telemetry(PackState& state,
                                  const char* reason,
                                  bool force,
                                  uint64_t nowUsec = 0) {
#if AMPR_EMU_DEBUG_LOG
    static constexpr uint64_t kTelemetryIntervalUsec = 1000000ull;
    if (!force) {
        if (nowUsec == 0) return;
        uint64_t deadline = state.nextIoTelemetryUsec.load(
            std::memory_order_relaxed);
        if (deadline != 0 && nowUsec < deadline) return;
        if (!state.nextIoTelemetryUsec.compare_exchange_strong(
                deadline, nowUsec + kTelemetryIntervalUsec,
                std::memory_order_relaxed,
                std::memory_order_relaxed)) {
            return;
        }
    }

    uint32_t queueLatency = 0;
    uint32_t queueBalanced = 0;
    uint32_t queueBulk = 0;
    uint32_t workerCount = 0;
    uint32_t pipelineCapacity = 0;
    uint32_t pipelineActive = 0;
    uint32_t pipelineRunnable = 0;
    uint32_t pipelineRunning = 0;
    uint32_t pipelineIoQueued = 0;
    uint32_t pipelineIoSubmitted = 0;
    uint32_t pipelineCacheWait = 0;
    uint32_t pipelineFdWait = 0;
    {
        AmprLockGuard lock(state.m);
        queueLatency = state.queueDepth[
            static_cast<uint32_t>(PackWorkClass::Latency)];
        queueBalanced = state.queueDepth[
            static_cast<uint32_t>(PackWorkClass::Balanced)];
        queueBulk = state.queueDepth[
            static_cast<uint32_t>(PackWorkClass::Bulk)];
        workerCount = state.workerCapacity;
        pipelineCapacity = state.pipelineCapacity;
        for (uint32_t index = 0; index < pipelineCapacity; ++index) {
            const ReadPipelineContext& pipeline = state.pipelines[index];
            if (!pipeline.active || pipeline.owner == kInvalidIndex) continue;
            ++pipelineActive;
            switch (state.virtualAio[pipeline.owner].phase) {
                case VirtualAioPhase::Queued:
                    ++pipelineRunnable;
                    break;
                case VirtualAioPhase::Running:
                    ++pipelineRunning;
                    break;
                case VirtualAioPhase::WaitingCache:
                    ++pipelineCacheWait;
                    break;
                case VirtualAioPhase::WaitingFd:
                    ++pipelineFdWait;
                    break;
                case VirtualAioPhase::IoQueued:
                    if (__atomic_load_n(&pipeline.nativeSubmitted,
                                        __ATOMIC_ACQUIRE)) {
                        ++pipelineIoSubmitted;
                    } else {
                        ++pipelineIoQueued;
                    }
                    break;
                default:
                    break;
            }
        }
    }

    AtomicPackStats& stats = state.stats;
    AMPR_LOGF(
        "apr.pack.io.telemetry reason=%s workers=%u pSamples=%llu pOps=%llu pBytes=0x%llx pUsec=%llu pMax=%llu pSlow1=%llu pSlow5=%llu pSlow20=%llu pLe64=%llu pLe512=%llu pGt512=%llu pActive=%llu pPeak=%llu aioBatches=%llu aioRequests=%llu aioEagain=%llu aioSubmitFail=%llu aioPollFail=%llu aioDeleteFail=%llu pipeCap=%u pipeActive=%u pipePeak=%llu pipeRunnable=%u pipeRunning=%u pipeIoQueued=%u pipeIoSubmitted=%u pipeCacheWait=%u pipeFdWait=%u pipeIoYields=%llu pipeCacheYields=%llu pipeFdYields=%llu wJobs=%llu wUsec=%llu wMax=%llu wBusy=%llu wPeak=%llu qUsec=%llu qMax=%llu qSlow1=%llu qSlow5=%llu qSlow20=%llu qDepth=%u/%u/%u",
        reason ? reason : "periodic", workerCount,
        (unsigned long long)stats.physicalReadSamples.load(
            std::memory_order_relaxed),
        (unsigned long long)stats.physicalReadOps.load(
            std::memory_order_relaxed),
        (unsigned long long)stats.physicalBytes.load(
            std::memory_order_relaxed),
        (unsigned long long)stats.physicalReadUsecTotal.load(
            std::memory_order_relaxed),
        (unsigned long long)stats.physicalReadUsecMax.load(
            std::memory_order_relaxed),
        (unsigned long long)stats.physicalReadSlow1ms.load(
            std::memory_order_relaxed),
        (unsigned long long)stats.physicalReadSlow5ms.load(
            std::memory_order_relaxed),
        (unsigned long long)stats.physicalReadSlow20ms.load(
            std::memory_order_relaxed),
        (unsigned long long)stats.physicalReadLe64K.load(
            std::memory_order_relaxed),
        (unsigned long long)stats.physicalReadLe512K.load(
            std::memory_order_relaxed),
        (unsigned long long)stats.physicalReadGt512K.load(
            std::memory_order_relaxed),
        (unsigned long long)stats.physicalReadsInFlight.load(
            std::memory_order_relaxed),
        (unsigned long long)stats.physicalReadsInFlightPeak.load(
            std::memory_order_relaxed),
        (unsigned long long)stats.backingAioSubmitBatches.load(
            std::memory_order_relaxed),
        (unsigned long long)stats.backingAioSubmitRequests.load(
            std::memory_order_relaxed),
        (unsigned long long)stats.backingAioSubmitEagain.load(
            std::memory_order_relaxed),
        (unsigned long long)stats.backingAioSubmitFailures.load(
            std::memory_order_relaxed),
        (unsigned long long)stats.backingAioPollFailures.load(
            std::memory_order_relaxed),
        (unsigned long long)stats.backingAioDeleteFailures.load(
            std::memory_order_relaxed),
        pipelineCapacity, pipelineActive,
        (unsigned long long)stats.pipelineContextsActivePeak.load(
            std::memory_order_relaxed),
        pipelineRunnable, pipelineRunning, pipelineIoQueued,
        pipelineIoSubmitted, pipelineCacheWait, pipelineFdWait,
        (unsigned long long)stats.pipelineIoYields.load(
            std::memory_order_relaxed),
        (unsigned long long)stats.pipelineCacheYields.load(
            std::memory_order_relaxed),
        (unsigned long long)stats.pipelineFdYields.load(
            std::memory_order_relaxed),
        (unsigned long long)stats.workerJobs.load(std::memory_order_relaxed),
        (unsigned long long)stats.workerJobUsecTotal.load(
            std::memory_order_relaxed),
        (unsigned long long)stats.workerJobUsecMax.load(
            std::memory_order_relaxed),
        (unsigned long long)stats.workersBusy.load(std::memory_order_relaxed),
        (unsigned long long)stats.workersBusyPeak.load(
            std::memory_order_relaxed),
        (unsigned long long)stats.workerQueueWaitUsecTotal.load(
            std::memory_order_relaxed),
        (unsigned long long)stats.workerQueueWaitUsecMax.load(
            std::memory_order_relaxed),
        (unsigned long long)stats.workerQueueWaitSlow1ms.load(
            std::memory_order_relaxed),
        (unsigned long long)stats.workerQueueWaitSlow5ms.load(
            std::memory_order_relaxed),
        (unsigned long long)stats.workerQueueWaitSlow20ms.load(
            std::memory_order_relaxed),
        queueLatency, queueBalanced, queueBulk);
#if AMPR_EMU_PACK_TELEMETRY
    AMPR_LOGF("apr.pack.metrics reason=%s loaded=%u decodedTarget=%llu physicalTarget=%llu decodedAllocated=%llu physicalAllocated=%llu requestedWorkers=%u workers=%u reserve=%u completed=%llu failed=%llu delivered=%llu physical=%llu stored=%llu cacheHit=%llu cacheMiss=%llu cacheEviction=%llu pageHit=%llu pageMiss=%llu pageEviction=%llu inline=%llu",
        reason, (unsigned)state.runtimeProfileLoaded,
        (unsigned long long)state.decodedCacheTargetBytes,
        (unsigned long long)state.physicalCacheTargetBytes,
        (unsigned long long)state.profileDecodedBytes,
        (unsigned long long)state.profilePhysicalBytes,
        state.requestedWorkers, workerCount, state.latencyReserveWorkers,
        (unsigned long long)stats.aioCompleted.load(std::memory_order_relaxed),
        (unsigned long long)stats.logicalFailures.load(std::memory_order_relaxed),
        (unsigned long long)stats.deliveredBytes.load(std::memory_order_relaxed),
        (unsigned long long)stats.physicalBytes.load(std::memory_order_relaxed),
        (unsigned long long)stats.storedBytesConsumed.load(std::memory_order_relaxed),
        (unsigned long long)stats.cacheHits.load(std::memory_order_relaxed),
        (unsigned long long)stats.cacheMisses.load(std::memory_order_relaxed),
        (unsigned long long)stats.cacheEvictions.load(std::memory_order_relaxed),
        (unsigned long long)stats.physicalPageHits.load(std::memory_order_relaxed),
        (unsigned long long)stats.physicalPageMisses.load(std::memory_order_relaxed),
        (unsigned long long)stats.physicalPageEvictions.load(std::memory_order_relaxed),
        (unsigned long long)stats.inlineCacheCompletions.load(std::memory_order_relaxed));
    log_latency_histogram("logical", stats.logicalLatency);
    log_latency_histogram("latency_class", stats.latencyClassLatency);
    log_latency_histogram("physical", stats.physicalLatency);
    log_latency_histogram("queue", stats.queueLatency);
    log_latency_histogram("worker", stats.workerLatency);
#endif
#else
    (void)state;
    (void)reason;
    (void)force;
    (void)nowUsec;
#endif
}

static bool pipeline_window_contains(const ReadPipelineContext& pipeline,
                                     const AmprPackChunkView& chunk) {
    if (!pipeline.ioWindowValid || pipeline.ioWindowPackId != chunk.packId) {
        return false;
    }
    uint64_t chunkEnd = 0;
    uint64_t windowEnd = 0;
    return checked_add_u64(chunk.offset, chunk.storedSize, &chunkEnd) &&
           checked_add_u64(pipeline.ioWindowOffset, pipeline.ioWindowSize,
                           &windowEnd) &&
           chunk.offset >= pipeline.ioWindowOffset && chunkEnd <= windowEnd;
}

static void abandon_pipeline_page_plan(ReadPipelineContext& pipeline,
                                       int error) {
    PhysicalCachePublication
        publications[kPackPipelineMaxIoPages];
    size_t publicationCount = 0;
    for (size_t page = 0; page < pipeline.ioPageCount; ++page) {
        PhysicalCacheAcquireResult& acquired = pipeline.ioPages[page];
        if (acquired.kind == PhysicalCacheAcquireKind::Load) {
            publications[publicationCount++] = {&acquired.lease, error};
        }
    }
    physical_cache_publish_batch(publications, publicationCount);
    PhysicalCacheLease* leases[kPackPipelineMaxIoPages];
    for (size_t page = 0; page < pipeline.ioPageCount; ++page) {
        leases[page] = &pipeline.ioPages[page].lease;
    }
    physical_cache_release_batch(leases, pipeline.ioPageCount);
    for (size_t page = 0; page < pipeline.ioPageCount; ++page) {
        pipeline.ioPages[page] = {};
    }
    pipeline.ioPageCount = 0;
    pipeline.ioWindowData = nullptr;
}

static void release_pipeline_window_pages(ReadPipelineContext& pipeline) {
    PhysicalCacheLease* leases[kPackPipelineMaxIoPages];
    for (size_t page = 0; page < pipeline.ioPageCount; ++page) {
        leases[page] = &pipeline.ioPages[page].lease;
    }
    physical_cache_release_batch(leases, pipeline.ioPageCount);
    for (size_t page = 0; page < pipeline.ioPageCount; ++page) {
        pipeline.ioPages[page] = {};
    }
    pipeline.ioPageCount = 0;
}

static void release_mandatory_fds(ReadPipelineContext& pipeline) {
    for (size_t fdIndex = 0;
         fdIndex < pipeline.mandatoryFdCount;
         ++fdIndex) {
        release_pack_fd(pipeline.mandatoryFdPackIds[fdIndex]);
        pipeline.mandatoryFdPackIds[fdIndex] = UINT16_MAX;
        pipeline.mandatoryFds[fdIndex] = -1;
    }
    pipeline.mandatoryFdCount = 0;
}

static void clear_mandatory_requests(ReadPipelineContext& pipeline) {
    for (size_t requestIndex = 0;
         requestIndex < pipeline.mandatoryRequestCount;
         ++requestIndex) {
        pipeline.mandatoryRequests[requestIndex] = {};
        pipeline.mandatoryResults[requestIndex] = {};
        pipeline.mandatoryRequestUsesScratch[requestIndex] = false;
    }
    pipeline.mandatoryRequestCount = 0;
}

static void abandon_mandatory_page_plan(ReadPipelineContext& pipeline,
                                        int error) {
    PhysicalCachePublication
        publications[kPackMandatoryGroupMaxPages];
    size_t publicationCount = 0;
    for (size_t pageIndex = 0;
         pageIndex < pipeline.mandatoryPageCount;
         ++pageIndex) {
        PipelineMandatoryPage& page =
            pipeline.mandatoryPages[pageIndex];
        if (page.acquired.kind == PhysicalCacheAcquireKind::Load) {
            publications[publicationCount++] = {
                &page.acquired.lease, error};
        }
    }
    physical_cache_publish_batch(publications, publicationCount);
    PhysicalCacheLease* leases[kPackMandatoryGroupMaxPages];
    for (size_t pageIndex = 0;
         pageIndex < pipeline.mandatoryPageCount;
         ++pageIndex) {
        leases[pageIndex] =
            &pipeline.mandatoryPages[pageIndex].acquired.lease;
    }
    physical_cache_release_batch(leases, pipeline.mandatoryPageCount);
    for (size_t pageIndex = 0;
         pageIndex < pipeline.mandatoryPageCount;
         ++pageIndex) {
        pipeline.mandatoryPages[pageIndex] = {};
    }
    pipeline.mandatoryPageCount = 0;
    pipeline.mandatoryTaskEnd = 0;
    pipeline.mandatoryPlanActive = false;
    release_mandatory_fds(pipeline);
    clear_mandatory_requests(pipeline);
}

static void release_mandatory_page_plan(ReadPipelineContext& pipeline) {
    PhysicalCacheLease* leases[kPackMandatoryGroupMaxPages];
    for (size_t pageIndex = 0;
         pageIndex < pipeline.mandatoryPageCount;
         ++pageIndex) {
        leases[pageIndex] =
            &pipeline.mandatoryPages[pageIndex].acquired.lease;
    }
    physical_cache_release_batch(leases, pipeline.mandatoryPageCount);
    for (size_t pageIndex = 0;
         pageIndex < pipeline.mandatoryPageCount;
         ++pageIndex) {
        pipeline.mandatoryPages[pageIndex] = {};
    }
    pipeline.mandatoryPageCount = 0;
    pipeline.mandatoryTaskEnd = 0;
    pipeline.mandatoryPlanActive = false;
}

static size_t find_mandatory_page(const ReadPipelineContext& pipeline,
                                  uint16_t packId,
                                  uint64_t offset,
                                  uint32_t size) {
    for (size_t pageIndex = 0;
         pageIndex < pipeline.mandatoryPageCount;
         ++pageIndex) {
        const PipelineMandatoryPage& page =
            pipeline.mandatoryPages[pageIndex];
        if (page.packId == packId && page.offset == offset &&
            page.size == size) {
            return pageIndex;
        }
    }
    return SIZE_MAX;
}

static bool ensure_pipeline_io_scratch(ReadPipelineContext& pipeline) {
    if (pipeline.ioScratch) {
        return pipeline.ioScratchSize >= kPackPipelineIoBytes;
    }
    size_t actual = 0;
    uint8_t* scratch = static_cast<uint8_t*>(
        ampr_internal_amm_pool_alloc(
            kPackPipelineIoBytes, &actual,
            "apr.pack.pipeline.io-window", false, 64u));
    if (!scratch || actual < kPackPipelineIoBytes) {
        if (scratch) {
            (void)ampr_internal_amm_pool_free(
                scratch, "apr.pack.pipeline.io-window.fail");
        }
        return false;
    }
    pipeline.ioScratch = scratch;
    pipeline.ioScratchSize = actual;
    return true;
}

static PipelineStep prepare_mandatory_page_group(
    const AmprPackFileRecord& file,
    uint64_t logicalOffset,
    uint64_t logicalLength,
    ReadPipelineContext& pipeline,
    int* errorOut) {
    if (errorOut) *errorOut = 0;
    PackState& state = pack_state();
    if (!state.header || !state.packs ||
        pipeline.taskIndex >= pipeline.taskCount ||
        pipeline.mandatoryPageCount != 0 ||
        pipeline.mandatoryRequestCount != 0 ||
        pipeline.mandatoryFdCount != 0) {
        if (errorOut) *errorOut = SCE_KERNEL_ERROR_EINVAL;
        return PipelineStep::Failed;
    }

    const size_t firstTask = pipeline.taskIndex;
    size_t taskEnd = firstTask;
    for (size_t taskIndex = firstTask;
         taskIndex < pipeline.taskCount;
         ++taskIndex) {
        AmprPackBlockReadTask task{};
        const int taskRc = ampr_pack_core_make_task(
            state.coreView,
            file,
            logicalOffset,
            logicalLength,
            taskIndex,
            &task);
        if (taskRc != kAmprPackCoreOk ||
            task.chunkIndex >= state.header->chunkCount) {
            abandon_mandatory_page_plan(
                pipeline, SCE_KERNEL_ERROR_EIO);
            if (errorOut) *errorOut = SCE_KERNEL_ERROR_EIO;
            return PipelineStep::Failed;
        }
        const AmprPackChunkView& chunk = task.chunk;
        if (chunk.packId >= state.header->packCount ||
            chunk.storedSize == 0) {
            abandon_mandatory_page_plan(
                pipeline, SCE_KERNEL_ERROR_EIO);
            if (errorOut) *errorOut = SCE_KERNEL_ERROR_EIO;
            return PipelineStep::Failed;
        }
        bool packAlreadyPlanned = false;
        size_t plannedPackCount = 0;
        for (size_t pageIndex = 0;
             pageIndex < pipeline.mandatoryPageCount;
             ++pageIndex) {
            const uint16_t plannedPackId =
                pipeline.mandatoryPages[pageIndex].packId;
            if (plannedPackId == chunk.packId) {
                packAlreadyPlanned = true;
            }
            bool firstOccurrence = true;
            for (size_t prior = 0; prior < pageIndex; ++prior) {
                if (pipeline.mandatoryPages[prior].packId ==
                    plannedPackId) {
                    firstOccurrence = false;
                    break;
                }
            }
            if (firstOccurrence) ++plannedPackCount;
        }
        // A complete mandatory set owns all of its pack descriptors until its
        // backing AIO retires. Never construct a set that cannot fit inside
        // the configured pack-FD cap or it could repeatedly yield after
        // pinning the earlier descriptors without ever reaching submission.
        if (!packAlreadyPlanned &&
            plannedPackCount >= AMPR_EMU_PACK_OPEN_PACK_FD_CAP) {
            break;
        }
        const AmprPackDataRecord& pack = state.packs[chunk.packId];
        uint64_t chunkEnd = 0;
        uint64_t pageEnd = 0;
        if (!checked_add_u64(chunk.offset, chunk.storedSize, &chunkEnd) ||
            !align_up_u64(chunkEnd, pack.ioPageSize, &pageEnd)) {
            abandon_mandatory_page_plan(
                pipeline, SCE_KERNEL_ERROR_EIO);
            if (errorOut) *errorOut = SCE_KERNEL_ERROR_EIO;
            return PipelineStep::Failed;
        }
        const uint64_t pageBegin =
            align_down_u64(chunk.offset, pack.ioPageSize);
        uint64_t missingPageOffsets[kPackMandatoryGroupMaxPages];
        size_t missingPageCount = 0;
        const size_t availablePages =
            kPackMandatoryGroupMaxPages - pipeline.mandatoryPageCount;
        bool pageCapacityExceeded = false;
        for (uint64_t pageOffset = pageBegin;
             pageOffset < pageEnd;
             pageOffset += pack.ioPageSize) {
            if (find_mandatory_page(
                    pipeline,
                    chunk.packId,
                    pageOffset,
                    pack.ioPageSize) != SIZE_MAX) {
                continue;
            }
            if (missingPageCount >= availablePages) {
                pageCapacityExceeded = true;
                break;
            }
            missingPageOffsets[missingPageCount++] = pageOffset;
        }
        if (pageCapacityExceeded) break;
        for (size_t missingIndex = 0;
             missingIndex < missingPageCount;
             ++missingIndex) {
            PipelineMandatoryPage& page =
                pipeline.mandatoryPages[pipeline.mandatoryPageCount++];
            page.offset = missingPageOffsets[missingIndex];
            page.size = pack.ioPageSize;
            page.packId = chunk.packId;
            page.requestIndex = kInvalidIndex;
            page.stagingOffset = kInvalidIndex;
            page.acquired = {};
        }
        taskEnd = taskIndex + 1u;
    }
    if (taskEnd == firstTask || pipeline.mandatoryPageCount == 0) {
        abandon_mandatory_page_plan(
            pipeline, SCE_KERNEL_ERROR_EAGAIN);
        pipeline.mandatorySkipTask = firstTask;
        return PipelineStep::Ready;
    }

    PhysicalCacheAcquireBatchItem
        acquireItems[kPackMandatoryGroupMaxPages];
    uint16_t waitBuckets[kPackMandatoryGroupMaxPages]{};
    uint64_t waitEpochs[kPackMandatoryGroupMaxPages]{};
    for (size_t pageIndex = 0;
         pageIndex < pipeline.mandatoryPageCount;
         ++pageIndex) {
        PipelineMandatoryPage& page =
            pipeline.mandatoryPages[pageIndex];
        const uint64_t keyHash = physical_cache_key_hash(
            page.packId, page.offset, page.size);
        waitBuckets[pageIndex] = static_cast<uint16_t>(
            cache_wait_bucket(keyHash));
        waitEpochs[pageIndex] = cache_wait_epoch(
            state, CacheWaitDomain::Physical, waitBuckets[pageIndex]);
        acquireItems[pageIndex] = {
            &page.acquired, page.offset, page.size, page.packId};
    }
    const size_t acquiredCount = physical_cache_acquire_batch(
        acquireItems, pipeline.mandatoryPageCount);
    for (size_t pageIndex = 0;
         pageIndex < acquiredCount;
         ++pageIndex) {
        const PhysicalCacheAcquireResult& acquired =
            pipeline.mandatoryPages[pageIndex].acquired;
        if (acquired.kind == PhysicalCacheAcquireKind::Ready ||
            acquired.kind == PhysicalCacheAcquireKind::Load) {
            continue;
        }
        if (acquired.kind == PhysicalCacheAcquireKind::Pending) {
            pipeline.cacheWaitDomain = CacheWaitDomain::Physical;
            pipeline.cacheWaitBucket = waitBuckets[pageIndex];
            pipeline.cacheWaitEpoch = waitEpochs[pageIndex];
            abandon_mandatory_page_plan(
                pipeline, SCE_KERNEL_ERROR_EAGAIN);
            return PipelineStep::YieldCache;
        }
        if (acquired.kind == PhysicalCacheAcquireKind::Bypass) {
            abandon_mandatory_page_plan(
                pipeline, SCE_KERNEL_ERROR_EAGAIN);
            pipeline.mandatorySkipTask = firstTask;
            return PipelineStep::Ready;
        }
        const int error = acquired.lease.error
            ? acquired.lease.error
            : SCE_KERNEL_ERROR_EIO;
        abandon_mandatory_page_plan(pipeline, error);
        if (errorOut) *errorOut = error;
        return PipelineStep::Failed;
    }
    if (acquiredCount != pipeline.mandatoryPageCount) {
        abandon_mandatory_page_plan(
            pipeline, SCE_KERNEL_ERROR_EIO);
        if (errorOut) *errorOut = SCE_KERNEL_ERROR_EIO;
        return PipelineStep::Failed;
    }

    pipeline.mandatoryTaskEnd = taskEnd;
    pipeline.mandatoryPlanActive = true;
    pipeline.fdWaitEpoch = state.packFdProgressEpoch.load(
        std::memory_order_acquire);
    pipeline.fdBudgetWaitEpoch =
        ampr_index_fd_open_budget_progress_generation();
    size_t loadOrder[kPackMandatoryGroupMaxPages]{};
    size_t loadCount = 0;
    for (size_t pageIndex = 0;
         pageIndex < pipeline.mandatoryPageCount;
         ++pageIndex) {
        PipelineMandatoryPage& page =
            pipeline.mandatoryPages[pageIndex];
        if (page.acquired.kind != PhysicalCacheAcquireKind::Load) {
            continue;
        }
        size_t fdIndex = 0;
        while (fdIndex < pipeline.mandatoryFdCount &&
               pipeline.mandatoryFdPackIds[fdIndex] != page.packId) {
            ++fdIndex;
        }
        if (fdIndex == pipeline.mandatoryFdCount) {
            const int fd = acquire_pack_fd(page.packId);
            if (fd < 0) {
                abandon_mandatory_page_plan(pipeline, fd);
                if (fd == SCE_KERNEL_ERROR_EAGAIN) {
                    return PipelineStep::YieldFd;
                }
                if (errorOut) *errorOut = fd;
                return PipelineStep::Failed;
            }
            pipeline.mandatoryFdPackIds[fdIndex] = page.packId;
            pipeline.mandatoryFds[fdIndex] = fd;
            ++pipeline.mandatoryFdCount;
        }
        bool inRange = false;
        {
            AmprLockGuard lock(state.m);
            if (state.header && page.packId < state.header->packCount) {
                const PackHandle& handle = state.packHandles[page.packId];
                uint64_t end = 0;
                inRange = handle.fd == pipeline.mandatoryFds[fdIndex] &&
                          checked_add_u64(page.offset, page.size, &end) &&
                          page.offset >= handle.payloadBegin &&
                          end <= handle.payloadEnd;
            }
        }
        if (!inRange) {
            abandon_mandatory_page_plan(
                pipeline, SCE_KERNEL_ERROR_EIO);
            if (errorOut) *errorOut = SCE_KERNEL_ERROR_EIO;
            return PipelineStep::Failed;
        }
        loadOrder[loadCount++] = pageIndex;
    }

    // Cache allocation follows logical task order, which can interleave pack
    // lanes. Sort only the bounded cold-page index list so physically adjacent
    // pages can share one backing AIO without changing task or cache ordering.
    for (size_t i = 1; i < loadCount; ++i) {
        const size_t value = loadOrder[i];
        size_t insert = i;
        while (insert != 0) {
            const PipelineMandatoryPage& left =
                pipeline.mandatoryPages[loadOrder[insert - 1u]];
            const PipelineMandatoryPage& right =
                pipeline.mandatoryPages[value];
            if (left.packId < right.packId ||
                (left.packId == right.packId &&
                 left.offset <= right.offset)) {
                break;
            }
            loadOrder[insert] = loadOrder[insert - 1u];
            --insert;
        }
        loadOrder[insert] = value;
    }

    const auto findFd = [&pipeline](uint16_t packId) -> int {
        for (size_t fdIndex = 0;
             fdIndex < pipeline.mandatoryFdCount;
             ++fdIndex) {
            if (pipeline.mandatoryFdPackIds[fdIndex] == packId) {
                return pipeline.mandatoryFds[fdIndex];
            }
        }
        return -1;
    };
    const auto appendRequest = [&pipeline, &findFd, &loadOrder](
                                   size_t firstOrder,
                                   size_t endOrder,
                                   size_t requestBytes,
                                   uint8_t* requestBuffer,
                                   size_t scratchOffset) -> bool {
        if (firstOrder >= endOrder ||
            pipeline.mandatoryRequestCount >=
                kPackMandatoryGroupMaxPages) {
            return false;
        }
        PipelineMandatoryPage& first =
            pipeline.mandatoryPages[loadOrder[firstOrder]];
        const int fd = findFd(first.packId);
        if (fd < 0 || !requestBuffer) return false;
        size_t verifiedBytes = 0;
        uint64_t expectedOffset = first.offset;
        for (size_t order = firstOrder; order < endOrder; ++order) {
            const PipelineMandatoryPage& page =
                pipeline.mandatoryPages[loadOrder[order]];
            uint64_t nextOffset = 0;
            if (page.packId != first.packId ||
                page.offset != expectedOffset ||
                page.size > SIZE_MAX - verifiedBytes ||
                !checked_add_u64(page.offset, page.size, &nextOffset)) {
                return false;
            }
            verifiedBytes += page.size;
            expectedOffset = nextOffset;
        }
        if (verifiedBytes != requestBytes) return false;
        const size_t requestIndex = pipeline.mandatoryRequestCount++;
        pipeline.mandatoryResults[requestIndex] = {};
        pipeline.mandatoryRequestUsesScratch[requestIndex] =
            scratchOffset != SIZE_MAX;
        SceKernelAioRWRequest& request =
            pipeline.mandatoryRequests[requestIndex];
        request = {};
        request.offset = static_cast<off_t>(first.offset);
        request.nbyte = requestBytes;
        request.buf = requestBuffer;
        request.result = &pipeline.mandatoryResults[requestIndex];
        request.fd = fd;
        size_t pageOffset = 0;
        for (size_t order = firstOrder; order < endOrder; ++order) {
            PipelineMandatoryPage& page =
                pipeline.mandatoryPages[loadOrder[order]];
            page.requestIndex = static_cast<uint32_t>(requestIndex);
            page.stagingOffset = scratchOffset == SIZE_MAX
                ? kInvalidIndex
                : static_cast<uint32_t>(scratchOffset + pageOffset);
            pageOffset += page.size;
        }
        return pageOffset == verifiedBytes;
    };

    size_t scratchUsed = 0;
    size_t spanBegin = 0;
    while (spanBegin < loadCount) {
        size_t spanEnd = spanBegin + 1u;
        while (spanEnd < loadCount) {
            const PipelineMandatoryPage& previous =
                pipeline.mandatoryPages[loadOrder[spanEnd - 1u]];
            const PipelineMandatoryPage& next =
                pipeline.mandatoryPages[loadOrder[spanEnd]];
            uint64_t previousEnd = 0;
            if (previous.packId != next.packId ||
                !checked_add_u64(
                    previous.offset, previous.size, &previousEnd) ||
                previousEnd != next.offset) {
                break;
            }
            ++spanEnd;
        }

        size_t batchBegin = spanBegin;
        while (batchBegin < spanEnd) {
            size_t batchEnd = batchBegin;
            size_t batchBytes = 0;
            while (batchEnd < spanEnd) {
                const size_t pageBytes =
                    pipeline.mandatoryPages[loadOrder[batchEnd]].size;
                if (pageBytes > kPackCoalescedAioMaxBytes - batchBytes) {
                    break;
                }
                batchBytes += pageBytes;
                ++batchEnd;
            }
            if (batchEnd == batchBegin) {
                batchEnd = batchBegin + 1u;
                batchBytes =
                    pipeline.mandatoryPages[loadOrder[batchBegin]].size;
            }

            size_t tailBytes = 0;
            for (size_t order = batchEnd; order < spanEnd; ++order) {
                tailBytes += pipeline.mandatoryPages[loadOrder[order]].size;
            }
            while (tailBytes != 0 &&
                   tailBytes < kPackCoalescedAioMinBytes &&
                   batchEnd - batchBegin > 1u) {
                const size_t movedBytes =
                    pipeline.mandatoryPages[loadOrder[batchEnd - 1u]].size;
                if (batchBytes - movedBytes < kPackCoalescedAioMinBytes) {
                    break;
                }
                --batchEnd;
                batchBytes -= movedBytes;
                tailBytes += movedBytes;
            }

            const size_t pageCount = batchEnd - batchBegin;
            const bool canCoalesce = pageCount > 1u &&
                batchBytes >= kPackCoalescedAioMinBytes &&
                batchBytes <= kPackCoalescedAioMaxBytes;
            bool cacheContiguous = canCoalesce;
            for (size_t order = batchBegin + 1u;
                 cacheContiguous && order < batchEnd;
                 ++order) {
                const PipelineMandatoryPage& previous =
                    pipeline.mandatoryPages[loadOrder[order - 1u]];
                const PipelineMandatoryPage& next =
                    pipeline.mandatoryPages[loadOrder[order]];
                const uintptr_t previousData = reinterpret_cast<uintptr_t>(
                    previous.acquired.lease.data);
                const uintptr_t nextData = reinterpret_cast<uintptr_t>(
                    next.acquired.lease.data);
                cacheContiguous = previousData <= UINTPTR_MAX - previous.size &&
                    previousData + previous.size == nextData;
            }

            bool appended = false;
            if (canCoalesce && cacheContiguous) {
                appended = appendRequest(
                    batchBegin, batchEnd,
                    batchBytes,
                    pipeline.mandatoryPages[loadOrder[batchBegin]]
                        .acquired.lease.data,
                    SIZE_MAX);
            } else if (canCoalesce &&
                       scratchUsed <= kPackPipelineIoBytes - batchBytes &&
                       ensure_pipeline_io_scratch(pipeline)) {
                appended = appendRequest(
                    batchBegin, batchEnd, batchBytes,
                    pipeline.ioScratch + scratchUsed, scratchUsed);
                if (appended) {
                    scratchUsed += batchBytes;
                }
            }

            if (!appended) {
                for (size_t order = batchBegin;
                     order < batchEnd;
                     ++order) {
                    PipelineMandatoryPage& page =
                        pipeline.mandatoryPages[loadOrder[order]];
                    if (!appendRequest(
                            order, order + 1u, page.size,
                            page.acquired.lease.data, SIZE_MAX)) {
                        abandon_mandatory_page_plan(
                            pipeline, SCE_KERNEL_ERROR_EIO);
                        if (errorOut) *errorOut = SCE_KERNEL_ERROR_EIO;
                        return PipelineStep::Failed;
                    }
                }
            }
            batchBegin = batchEnd;
        }
        spanBegin = spanEnd;
    }
    if (pipeline.mandatoryRequestCount == 0) {
        return PipelineStep::Ready;
    }
#if AMPR_EMU_PACK_TELEMETRY
    // Count actual backing requests after adjacent cold pages are coalesced.
    for (size_t i = 0; i < pipeline.mandatoryRequestCount; ++i) {
        if (pipeline.mandatoryRequestUsesScratch[i]) {
            state.stats.physicalCacheScratchWindows.fetch_add(
                1, std::memory_order_relaxed);
        } else {
            state.stats.physicalCacheDirectReadWindows.fetch_add(
                1, std::memory_order_relaxed);
            state.stats.physicalCacheCopyBytesAvoided.fetch_add(
                pipeline.mandatoryRequests[i].nbyte,
                std::memory_order_relaxed);
        }
    }
    pipeline.nativeSubmittedAtUsec = 0;
#endif
    pipeline.nativeIoError = 0;
    pipeline.nativeCompletionReady = false;
    __atomic_store_n(&pipeline.nativeSubmitted, false, __ATOMIC_RELEASE);
    return PipelineStep::YieldIo;
}

static PipelineStep prepare_pipeline_window_aio(
    const PipelineIoRange& range,
    ReadPipelineContext& pipeline,
    int* errorOut) {
    if (errorOut) *errorOut = 0;
    PackState& state = pack_state();
    if (!state.header || !state.packs ||
        range.packId >= state.header->packCount || range.length == 0 ||
        range.length > kPackPipelineIoBytes) {
        if (errorOut) *errorOut = SCE_KERNEL_ERROR_EINVAL;
        return PipelineStep::Failed;
    }
    const AmprPackDataRecord& pack = state.packs[range.packId];
    if (range.ioPageSize != pack.ioPageSize ||
        (range.offset & (pack.ioPageSize - 1u)) != 0 ||
        (range.length & (pack.ioPageSize - 1u)) != 0) {
        if (errorOut) *errorOut = SCE_KERNEL_ERROR_EIO;
        return PipelineStep::Failed;
    }
    const size_t pageCount = range.length / pack.ioPageSize;
    if (pageCount == 0 || pageCount > kPackPipelineMaxIoPages) {
        if (errorOut) *errorOut = SCE_KERNEL_ERROR_ENOMEM;
        return PipelineStep::Failed;
    }

    release_pipeline_window_pages(pipeline);
    pipeline.ioWindowValid = false;
    pipeline.ioWindowData = nullptr;
    pipeline.ioRange = range;
    pipeline.ioPageCount = pageCount;
    bool needsPhysicalIo = false;
    bool waitsForLoader = false;
    bool allReady = true;
    bool allLoad = true;
    bool cacheContiguous = true;
    uint8_t* cacheWindow = nullptr;
    int error = 0;
    PhysicalCacheAcquireBatchItem
        acquireItems[kPackPipelineMaxIoPages];
    uint16_t waitBuckets[kPackPipelineMaxIoPages]{};
    uint64_t waitEpochs[kPackPipelineMaxIoPages]{};
    for (size_t page = 0; page < pageCount; ++page) {
        const uint64_t pageOffset =
            range.offset + page * static_cast<uint64_t>(pack.ioPageSize);
        const uint64_t keyHash = physical_cache_key_hash(
            range.packId, pageOffset, pack.ioPageSize);
        waitBuckets[page] = static_cast<uint16_t>(
            cache_wait_bucket(keyHash));
        waitEpochs[page] = cache_wait_epoch(
            state, CacheWaitDomain::Physical, waitBuckets[page]);
        pipeline.ioPages[page] = {};
        acquireItems[page] = {
            &pipeline.ioPages[page],
            pageOffset,
            pack.ioPageSize,
            range.packId};
    }
    const size_t acquiredCount = physical_cache_acquire_batch(
        acquireItems, pageCount);
    if (acquiredCount == 0) {
        abandon_pipeline_page_plan(pipeline, SCE_KERNEL_ERROR_EIO);
        pipeline.ioRange = {};
        if (errorOut) *errorOut = SCE_KERNEL_ERROR_EIO;
        return PipelineStep::Failed;
    }
    for (size_t page = 0; page < pageCount; ++page) {
        PhysicalCacheAcquireResult& acquired = pipeline.ioPages[page];
        switch (acquired.kind) {
            case PhysicalCacheAcquireKind::Ready:
                allLoad = false;
                break;
            case PhysicalCacheAcquireKind::Load:
                allReady = false;
                needsPhysicalIo = true;
                break;
            case PhysicalCacheAcquireKind::Bypass:
                allReady = false;
                allLoad = false;
                cacheContiguous = false;
                needsPhysicalIo = true;
                break;
            case PhysicalCacheAcquireKind::Pending:
                allReady = false;
                allLoad = false;
                waitsForLoader = true;
                pipeline.cacheWaitDomain = CacheWaitDomain::Physical;
                pipeline.cacheWaitBucket = waitBuckets[page];
                pipeline.cacheWaitEpoch = waitEpochs[page];
                break;
            case PhysicalCacheAcquireKind::Failed:
                allReady = false;
                allLoad = false;
                error = acquired.lease.error ? acquired.lease.error
                                             : SCE_KERNEL_ERROR_EIO;
                break;
        }
        if (acquired.lease.entry != kInvalidIndex) {
            uint8_t* const expected = cacheWindow
                ? cacheWindow + page * pack.ioPageSize
                : acquired.lease.data;
            if (!cacheWindow) cacheWindow = acquired.lease.data;
            if (acquired.lease.data != expected) cacheContiguous = false;
        } else {
            cacheContiguous = false;
        }
        if (error != 0) break;
    }
    if (error != 0 || waitsForLoader) {
        // Do not retain a loader lease while waiting for another page: that
        // could form a cycle between two exact windows. EAGAIN is transient
        // and release removes the temporary failed entry once unpinned.
        abandon_pipeline_page_plan(
            pipeline, error != 0 ? error : SCE_KERNEL_ERROR_EAGAIN);
        pipeline.ioRange = {};
        if (error != 0) {
            if (errorOut) *errorOut = error;
            return PipelineStep::Failed;
        }
        return PipelineStep::YieldCache;
    }
    if (!needsPhysicalIo) {
        if (!allReady) {
            abandon_pipeline_page_plan(pipeline, SCE_KERNEL_ERROR_EIO);
            pipeline.ioRange = {};
            if (errorOut) *errorOut = SCE_KERNEL_ERROR_EIO;
            return PipelineStep::Failed;
        }
        if (cacheContiguous && cacheWindow) {
            pipeline.ioWindowData = cacheWindow;
            state.stats.physicalCacheDirectReadyWindows.fetch_add(
                1, std::memory_order_relaxed);
            state.stats.physicalCacheCopyBytesAvoided.fetch_add(
                range.length, std::memory_order_relaxed);
        } else {
            if (!ensure_pipeline_io_scratch(pipeline)) {
                release_pipeline_window_pages(pipeline);
                pipeline.ioRange = {};
                if (errorOut) *errorOut = SCE_KERNEL_ERROR_ENOMEM;
                return PipelineStep::Failed;
            }
            for (size_t page = 0; page < pageCount; ++page) {
                std::memcpy(
                    pipeline.ioScratch + page * pack.ioPageSize,
                    pipeline.ioPages[page].lease.data,
                    pack.ioPageSize);
            }
            release_pipeline_window_pages(pipeline);
            pipeline.ioWindowData = pipeline.ioScratch;
            state.stats.physicalCacheScratchWindows.fetch_add(
                1, std::memory_order_relaxed);
        }
        pipeline.ioWindowOffset = range.offset;
        pipeline.ioWindowSize = range.length;
        pipeline.ioWindowPackId = range.packId;
        pipeline.ioWindowValid = true;
        return PipelineStep::Ready;
    }

    const bool directCacheRead = allLoad && cacheContiguous && cacheWindow;
    if (!directCacheRead && !ensure_pipeline_io_scratch(pipeline)) {
        abandon_pipeline_page_plan(pipeline, SCE_KERNEL_ERROR_ENOMEM);
        pipeline.ioRange = {};
        if (errorOut) *errorOut = SCE_KERNEL_ERROR_ENOMEM;
        return PipelineStep::Failed;
    }
    pipeline.fdWaitEpoch = state.packFdProgressEpoch.load(
        std::memory_order_acquire);
    pipeline.fdBudgetWaitEpoch =
        ampr_index_fd_open_budget_progress_generation();
    const int fd = acquire_pack_fd(range.packId);
    if (fd < 0) {
        abandon_pipeline_page_plan(pipeline, fd);
        pipeline.ioRange = {};
        if (fd == SCE_KERNEL_ERROR_EAGAIN) {
            return PipelineStep::YieldFd;
        }
        if (errorOut) *errorOut = fd;
        return PipelineStep::Failed;
    }
    bool inRange = false;
    {
        AmprLockGuard lock(state.m);
        if (state.header && range.packId < state.header->packCount) {
            const PackHandle& handle = state.packHandles[range.packId];
            uint64_t end = 0;
            inRange = handle.fd == fd &&
                      checked_add_u64(range.offset, range.length, &end) &&
                      range.offset >= handle.payloadBegin &&
                      end <= handle.payloadEnd;
        }
    }
    if (!inRange) {
        release_pack_fd(range.packId);
        abandon_pipeline_page_plan(pipeline, SCE_KERNEL_ERROR_EIO);
        pipeline.ioRange = {};
        if (errorOut) *errorOut = SCE_KERNEL_ERROR_EIO;
        return PipelineStep::Failed;
    }

    pipeline.packFd = fd;
    pipeline.nativeResult = {};
    pipeline.nativeRequest.offset = static_cast<off_t>(range.offset);
    pipeline.nativeRequest.nbyte = range.length;
    pipeline.nativeRequest.buf = directCacheRead
        ? cacheWindow
        : pipeline.ioScratch;
    if (directCacheRead) {
        state.stats.physicalCacheDirectReadWindows.fetch_add(
            1, std::memory_order_relaxed);
        state.stats.physicalCacheCopyBytesAvoided.fetch_add(
            range.length, std::memory_order_relaxed);
    } else {
        state.stats.physicalCacheScratchWindows.fetch_add(
            1, std::memory_order_relaxed);
    }
    pipeline.nativeRequest.result = &pipeline.nativeResult;
    pipeline.nativeRequest.fd = fd;
#if AMPR_EMU_PACK_TELEMETRY
    pipeline.nativeSubmittedAtUsec = 0;
#endif
    pipeline.nativeIoError = 0;
    pipeline.nativeCompletionReady = false;
    __atomic_store_n(&pipeline.nativeSubmitted, false, __ATOMIC_RELEASE);
    return PipelineStep::YieldIo;
}

static int finish_mandatory_page_group(ReadPipelineContext& pipeline) {
    PackState& state = pack_state();
    const int completionError = pipeline.nativeIoError;
    int groupError = completionError;
    release_mandatory_fds(pipeline);
    PhysicalCachePublication
        publications[kPackMandatoryGroupMaxPages];
    size_t publicationCount = 0;
    for (size_t pageIndex = 0;
         pageIndex < pipeline.mandatoryPageCount;
         ++pageIndex) {
        PipelineMandatoryPage& page =
            pipeline.mandatoryPages[pageIndex];
        if (page.acquired.kind != PhysicalCacheAcquireKind::Load) {
            continue;
        }
        // A group-level lifecycle error invalidates the complete set. Once
        // native completion succeeds, however, each SDK result owns only the
        // cache pages covered by that request; one failed ID must not poison
        // successful sibling requests.
        int pageError = completionError;
        if (page.requestIndex >= pipeline.mandatoryRequestCount) {
            pageError = SCE_KERNEL_ERROR_EIO;
        } else if (pageError == 0) {
            const SceKernelAioRWRequest& request =
                pipeline.mandatoryRequests[page.requestIndex];
            const int64_t returnValue =
                pipeline.mandatoryResults[page.requestIndex].returnValue;
            if (returnValue != static_cast<int64_t>(request.nbyte)) {
                pageError = returnValue < 0
                    ? static_cast<int>(returnValue)
                    : SCE_KERNEL_ERROR_EIO;
            }
        }
        if (pageError == 0 && page.stagingOffset != kInvalidIndex) {
            const size_t stagingOffset = page.stagingOffset;
            if (!pipeline.ioScratch ||
                stagingOffset > pipeline.ioScratchSize ||
                page.size > pipeline.ioScratchSize - stagingOffset) {
                pageError = SCE_KERNEL_ERROR_EIO;
            } else {
                std::memcpy(page.acquired.lease.data,
                            pipeline.ioScratch + stagingOffset,
                            page.size);
            }
        }
        publications[publicationCount++] = {
            &page.acquired.lease, pageError};
        page.acquired.kind = pageError == 0
            ? PhysicalCacheAcquireKind::Ready
            : PhysicalCacheAcquireKind::Failed;
        if (groupError == 0 && pageError != 0) {
            groupError = pageError;
        }
    }
    physical_cache_publish_batch(publications, publicationCount);
    clear_mandatory_requests(pipeline);
#if AMPR_EMU_PACK_TELEMETRY
    pipeline.nativeSubmittedAtUsec = 0;
#endif
    pipeline.cacheWaitEpoch = 0;
    pipeline.cacheWaitBucket = 0;
    pipeline.cacheWaitDomain = CacheWaitDomain::Decoded;
    pipeline.fdWaitEpoch = 0;
    pipeline.fdBudgetWaitEpoch = 0;
    pipeline.nativeIoError = 0;
    pipeline.nativeCompletionReady = false;
    __atomic_store_n(&pipeline.nativeSubmitted, false, __ATOMIC_RELEASE);
    if (groupError != 0) {
        release_mandatory_page_plan(pipeline);
        state.stats.ioFailures.fetch_add(1, std::memory_order_relaxed);
    }
    return groupError;
}

static int finish_pipeline_window_aio(ReadPipelineContext& pipeline) {
    PackState& state = pack_state();
    int error = pipeline.nativeIoError;
    const PipelineIoRange range = pipeline.ioRange;
    const bool directCacheWindow =
        pipeline.nativeRequest.buf != pipeline.ioScratch;
    const auto* const nativeWindowData = static_cast<const uint8_t*>(
        pipeline.nativeRequest.buf);
    if (error == 0 &&
        pipeline.nativeResult.returnValue != static_cast<int64_t>(range.length)) {
        error = pipeline.nativeResult.returnValue < 0
                    ? static_cast<int>(pipeline.nativeResult.returnValue)
                    : SCE_KERNEL_ERROR_EIO;
    }
    if (pipeline.packFd >= 0) {
        release_pack_fd(range.packId);
        pipeline.packFd = -1;
    }
    PhysicalCachePublication
        publications[kPackPipelineMaxIoPages];
    size_t publicationCount = 0;
    for (size_t page = 0; page < pipeline.ioPageCount; ++page) {
        PhysicalCacheAcquireResult& acquired = pipeline.ioPages[page];
        if (acquired.kind == PhysicalCacheAcquireKind::Load) {
            if (error == 0 && !directCacheWindow) {
                const uint32_t pageSize = range.ioPageSize;
                std::memcpy(acquired.lease.data,
                            pipeline.ioScratch + page * pageSize,
                            pageSize);
            }
            publications[publicationCount++] = {&acquired.lease, error};
            if (error == 0) {
                acquired.kind = PhysicalCacheAcquireKind::Ready;
            }
        }
    }
    physical_cache_publish_batch(publications, publicationCount);
    if (error != 0 || !directCacheWindow) {
        PhysicalCacheLease* leases[kPackPipelineMaxIoPages];
        for (size_t page = 0; page < pipeline.ioPageCount; ++page) {
            leases[page] = &pipeline.ioPages[page].lease;
        }
        physical_cache_release_batch(leases, pipeline.ioPageCount);
        for (size_t page = 0; page < pipeline.ioPageCount; ++page) {
            pipeline.ioPages[page] = {};
        }
    }
    if (error != 0 || !directCacheWindow) {
        pipeline.ioPageCount = 0;
    }
    pipeline.nativeRequest = {};
    pipeline.nativeResult = {};
#if AMPR_EMU_PACK_TELEMETRY
    pipeline.nativeSubmittedAtUsec = 0;
#endif
    pipeline.cacheWaitEpoch = 0;
    pipeline.cacheWaitBucket = 0;
    pipeline.cacheWaitDomain = CacheWaitDomain::Decoded;
    pipeline.fdWaitEpoch = 0;
    pipeline.fdBudgetWaitEpoch = 0;
    pipeline.nativeIoError = 0;
    pipeline.nativeCompletionReady = false;
    __atomic_store_n(&pipeline.nativeSubmitted, false, __ATOMIC_RELEASE);
    if (error != 0) {
        pipeline.ioWindowData = nullptr;
        pipeline.ioRange = {};
        state.stats.ioFailures.fetch_add(1, std::memory_order_relaxed);
        return error;
    }
    pipeline.ioWindowOffset = range.offset;
    pipeline.ioWindowSize = range.length;
    pipeline.ioWindowPackId = range.packId;
    pipeline.ioWindowValid = true;
    pipeline.ioWindowData = directCacheWindow
        ? nativeWindowData
        : pipeline.ioScratch;
    pipeline.ioRange = {};
    return 0;
}

static void invalidate_physical_pages_for_chunk(
    const AmprPackChunkView& chunk) {
    PackState& state = pack_state();
    if (!state.header || !state.packs ||
        chunk.packId >= state.header->packCount) {
        return;
    }
    const uint32_t pageSize = state.packs[chunk.packId].ioPageSize;
    uint64_t chunkEnd = 0;
    uint64_t pageEnd = 0;
    if (!checked_add_u64(chunk.offset, chunk.storedSize, &chunkEnd) ||
        !align_up_u64(chunkEnd, pageSize, &pageEnd)) {
        return;
    }
    for (uint64_t page = align_down_u64(chunk.offset, pageSize);
         page < pageEnd;
         page += pageSize) {
        physical_cache_invalidate(chunk.packId, page, pageSize);
    }
}

static bool try_process_virtual_read_cache_only(VirtualAioSlot& job,
                                                uint64_t* completedBytes) {
    if (completedBytes) *completedBytes = 0;
    PackState& state = pack_state();
    if (!state.header || job.fileId == 0 ||
        job.fileId > state.header->fileCount || !job.request.result ||
        job.request.offset < 0) {
        return false;
    }
    const AmprPackFileRecord& file = state.files[job.fileId - 1u];
    if ((file.flags & kAmprPackFilePacked) == 0) return false;
    const uint64_t offset = static_cast<uint64_t>(job.request.offset);
    if (job.request.nbyte == 0 || offset >= file.logicalSize) {
        return true;
    }
    if (!job.request.buf) return false;
    const uint64_t length = (std::min)(
        static_cast<uint64_t>(job.request.nbyte), file.logicalSize - offset);

    const size_t taskCount = ampr_pack_core_task_count(file, offset, length);
    if (taskCount == 0 ||
        taskCount > AMPR_EMU_PACK_INLINE_CACHE_MAX_TASKS) {
        return false;
    }
    AmprPackBlockReadTask tasks[AMPR_EMU_PACK_INLINE_CACHE_MAX_TASKS]{};
    CacheLease leases[AMPR_EMU_PACK_INLINE_CACHE_MAX_TASKS]{};
    size_t pinned = 0;
    for (size_t taskIndex = 0; taskIndex < taskCount; ++taskIndex) {
        if (ampr_pack_core_make_task(
                state.coreView, file, offset, length,
                taskIndex, &tasks[taskIndex]) != kAmprPackCoreOk ||
            tasks[taskIndex].chunkIndex >= state.header->chunkCount ||
            static_cast<uint64_t>(tasks[taskIndex].destinationOffset) +
                    tasks[taskIndex].copyLength >
                length) {
            break;
        }
        const AmprPackChunkView& chunk = tasks[taskIndex].chunk;
        if (!cache_try_pin_ready(chunk, &leases[taskIndex])) break;
        ++pinned;
    }
    if (pinned != taskCount) {
        for (size_t index = 0; index < pinned; ++index) {
            cache_release(leases[index]);
        }
        return false;
    }

    auto* output = static_cast<uint8_t*>(job.request.buf);
    for (size_t taskIndex = 0; taskIndex < taskCount; ++taskIndex) {
        const AmprPackBlockReadTask& task = tasks[taskIndex];
        std::memcpy(
            output + task.destinationOffset,
            leases[taskIndex].data + task.sourceOffset,
            task.copyLength);
    }
    for (size_t index = 0; index < taskCount; ++index) {
        cache_release(leases[index]);
    }
    state.stats.logicalBytes.fetch_add(length, std::memory_order_relaxed);
    state.stats.inlineCacheCompletions.fetch_add(
        1, std::memory_order_relaxed);
    if (completedBytes) *completedBytes = length;
    return true;
}

static void cleanup_pipeline_continuation(ReadPipelineContext& pipeline,
                                          int error) {
    if (pipeline.decodedLease.entry != kInvalidIndex) {
        cache_publish(pipeline.decodedLease, error);
        cache_release(pipeline.decodedLease);
    }
    abandon_pipeline_page_plan(pipeline, error);
    if (!pipeline.nativeAccepted) {
        abandon_mandatory_page_plan(pipeline, error);
    }
    if (pipeline.packFd >= 0 && !pipeline.nativeAccepted) {
        release_pack_fd(pipeline.ioRange.packId);
        pipeline.packFd = -1;
    }
    pipeline.ioRange = {};
    pipeline.ioWindowValid = false;
    pipeline.ioWindowData = nullptr;
    pipeline.nativeRequest = {};
    pipeline.nativeResult = {};
#if AMPR_EMU_PACK_TELEMETRY
    pipeline.nativeSubmittedAtUsec = 0;
#endif
    pipeline.nativeIoError = 0;
    pipeline.nativeCompletionReady = false;
    __atomic_store_n(&pipeline.nativeSubmitted, false, __ATOMIC_RELEASE);
}

static int make_pipeline_window_range(const AmprPackChunkView& chunk,
                                      PipelineIoRange* out) {
    if (out) *out = {};
    if (!out) return SCE_KERNEL_ERROR_EINVAL;
    PackState& state = pack_state();
    if (!state.header || !state.packs ||
        chunk.packId >= state.header->packCount) {
        return SCE_KERNEL_ERROR_EIO;
    }
    const AmprPackDataRecord& pack = state.packs[chunk.packId];
    uint64_t chunkEnd = 0;
    uint64_t rangeEnd = 0;
    if (!checked_add_u64(chunk.offset, chunk.storedSize, &chunkEnd) ||
        !align_up_u64(chunkEnd, pack.ioPageSize, &rangeEnd)) {
        return SCE_KERNEL_ERROR_EIO;
    }
    const uint64_t rangeBegin = align_down_u64(chunk.offset, pack.ioPageSize);
    if (rangeEnd < rangeBegin || rangeEnd - rangeBegin > UINT32_MAX ||
        rangeEnd - rangeBegin > kPackPipelineIoBytes) {
        return SCE_KERNEL_ERROR_ENOMEM;
    }
    out->packId = chunk.packId;
    out->offset = rangeBegin;
    out->length = static_cast<uint32_t>(rangeEnd - rangeBegin);
    out->ioPageSize = pack.ioPageSize;
    return 0;
}

static bool bind_mandatory_page_window(
    const AmprPackChunkView& chunk,
    ReadPipelineContext& pipeline) {
    if (!pipeline.mandatoryPlanActive ||
        pipeline.mandatoryPageCount == 0) {
        return false;
    }
    uint64_t chunkEnd = 0;
    if (!checked_add_u64(chunk.offset, chunk.storedSize, &chunkEnd)) {
        return false;
    }
    for (size_t pageIndex = 0;
         pageIndex < pipeline.mandatoryPageCount;
         ++pageIndex) {
        const PipelineMandatoryPage& page =
            pipeline.mandatoryPages[pageIndex];
        uint64_t pageEnd = 0;
        if (page.packId != chunk.packId ||
            page.acquired.kind != PhysicalCacheAcquireKind::Ready ||
            !checked_add_u64(page.offset, page.size, &pageEnd) ||
            chunk.offset < page.offset || chunkEnd > pageEnd) {
            continue;
        }
        release_pipeline_window_pages(pipeline);
        pipeline.ioWindowOffset = page.offset;
        pipeline.ioWindowSize = page.size;
        pipeline.ioWindowPackId = page.packId;
        pipeline.ioWindowData = page.acquired.lease.data;
        pipeline.ioWindowValid = true;
        pipeline.ioRange = {};
        PackState& state = pack_state();
        state.stats.physicalCacheDirectReadyWindows.fetch_add(
            1, std::memory_order_relaxed);
        state.stats.physicalCacheCopyBytesAvoided.fetch_add(
            page.size, std::memory_order_relaxed);
        return true;
    }
    return false;
}

static int decode_pipeline_chunk(const AmprPackChunkView& chunk,
                                 uint8_t* destination,
                                 ReadPipelineContext& pipeline,
                                 size_t rawOffset,
                                 size_t rawLength) {
#if AMPR_EMU_DEBUG_LOG
    // The worker established this invariant immediately before decode. Keep a
    // diagnostic assertion path without repeating two checked additions and
    // the window comparisons in production builds.
    if (!destination || !pipeline.ioWindowData ||
        !pipeline_window_contains(pipeline, chunk)) {
        return SCE_KERNEL_ERROR_EIO;
    }
#endif
    const size_t relative = static_cast<size_t>(
        chunk.offset - pipeline.ioWindowOffset);
    const uint8_t* stored = pipeline.ioWindowData + relative;
    PackState& state = pack_state();
    int rc = 0;
    if (chunk.codec == kAmprPackChunkRaw) {
        // Bypassed partial reads need no full-chunk decoded scratch copy.
    } else if (chunk.codec == kAmprPackChunkLz4) {
        const int decodedSize = LZ4_decompress_safe(
            reinterpret_cast<const char*>(stored),
            reinterpret_cast<char*>(destination),
            static_cast<int>(chunk.storedSize),
            static_cast<int>(chunk.rawSize));
        if (decodedSize != static_cast<int>(chunk.rawSize)) {
            invalidate_physical_pages_for_chunk(chunk);
            rc = SCE_KERNEL_ERROR_EIO;
        } else {
            state.stats.lz4DecodedBytes.fetch_add(
                chunk.rawSize, std::memory_order_relaxed);
        }
    } else {
        rc = SCE_KERNEL_ERROR_EINVAL;
    }
    if (rc == 0) {
        if (chunk.codec == kAmprPackChunkRaw) {
            std::memcpy(destination, stored + rawOffset, rawLength);
            state.stats.rawBytes.fetch_add(chunk.rawSize,
                                           std::memory_order_relaxed);
        }
        state.stats.storedBytesConsumed.fetch_add(
            chunk.storedSize, std::memory_order_relaxed);
    }
    return rc;
}

static PipelineStep advance_virtual_read_aio(VirtualAioSlot& job,
                                             WorkerContext& worker,
                                             ReadPipelineContext& pipeline,
                                             int64_t* returnValue,
                                             int* errorOut) {
    if (returnValue) *returnValue = 0;
    if (errorOut) *errorOut = 0;
    PackState& state = pack_state();
    if (!state.header || job.fileId == 0 ||
        job.fileId > state.header->fileCount || !job.request.result ||
        job.request.offset < 0) {
        if (errorOut) *errorOut = SCE_KERNEL_ERROR_EINVAL;
        return PipelineStep::Failed;
    }
    const AmprPackFileRecord& file = state.files[job.fileId - 1u];
    if ((file.flags & kAmprPackFilePacked) == 0) {
        if (errorOut) *errorOut = SCE_KERNEL_ERROR_ENOENT;
        return PipelineStep::Failed;
    }
    const uint64_t offset = static_cast<uint64_t>(job.request.offset);
    if (job.request.nbyte == 0 || offset >= file.logicalSize) {
        return PipelineStep::Complete;
    }
    if (!job.request.buf) {
        if (errorOut) *errorOut = SCE_KERNEL_ERROR_EFAULT;
        return PipelineStep::Failed;
    }
    const uint64_t length = (std::min)(
        static_cast<uint64_t>(job.request.nbyte), file.logicalSize - offset);
    if (pipeline.taskCount == 0) {
        pipeline.taskCount = ampr_pack_core_task_count(file, offset, length);
        if (pipeline.taskCount == 0) {
            if (errorOut) *errorOut = SCE_KERNEL_ERROR_EIO;
            return PipelineStep::Failed;
        }
    }
    if (pipeline.nativeCompletionReady) {
        const int finishRc = pipeline.mandatoryPlanActive &&
                                     pipeline.mandatoryRequestCount != 0
            ? finish_mandatory_page_group(pipeline)
            : finish_pipeline_window_aio(pipeline);
        if (finishRc != 0) {
            cleanup_pipeline_continuation(pipeline, finishRc);
            if (errorOut) *errorOut = finishRc;
            return PipelineStep::Failed;
        }
    }
    auto* output = static_cast<uint8_t*>(job.request.buf);
    while (pipeline.taskIndex < pipeline.taskCount) {
        if (pipeline.mandatoryPlanActive &&
            pipeline.taskIndex >= pipeline.mandatoryTaskEnd) {
            release_pipeline_window_pages(pipeline);
            pipeline.ioWindowValid = false;
            pipeline.ioWindowData = nullptr;
            release_mandatory_page_plan(pipeline);
        }
        if (pipeline.mandatorySkipTask != pipeline.taskIndex) {
            pipeline.mandatorySkipTask = SIZE_MAX;
        }
        if (job.cancelRequested.load(std::memory_order_acquire)) {
            cleanup_pipeline_continuation(
                pipeline, SCE_KERNEL_ERROR_ECANCELED);
            if (errorOut) *errorOut = SCE_KERNEL_ERROR_ECANCELED;
            return PipelineStep::Failed;
        }
        AmprPackBlockReadTask task{};
        const int taskRc = ampr_pack_core_make_task(
            state.coreView, file, offset, length,
            pipeline.taskIndex, &task);
        if (taskRc != kAmprPackCoreOk ||
            task.chunkIndex >= state.header->chunkCount ||
            static_cast<uint64_t>(task.destinationOffset) + task.copyLength >
                length) {
            cleanup_pipeline_continuation(pipeline, SCE_KERNEL_ERROR_EIO);
            if (errorOut) *errorOut = SCE_KERNEL_ERROR_EIO;
            return PipelineStep::Failed;
        }
        const AmprPackChunkView& chunk = task.chunk;
        if (!pipeline.mandatoryPlanActive &&
            pipeline.mandatorySkipTask != pipeline.taskIndex &&
            !pipeline_window_contains(pipeline, chunk)) {
            int groupError = 0;
            const PipelineStep grouped = prepare_mandatory_page_group(
                file,
                offset,
                length,
                pipeline,
                &groupError);
            if (grouped == PipelineStep::YieldIo ||
                grouped == PipelineStep::YieldCache ||
                grouped == PipelineStep::YieldFd) {
                return grouped;
            }
            if (grouped == PipelineStep::Failed) {
                cleanup_pipeline_continuation(pipeline, groupError);
                if (errorOut) *errorOut = groupError;
                return grouped;
            }
        }
        if (pipeline.decodedLease.entry == kInvalidIndex) {
            prepare_cache_wait(
                pipeline, CacheWaitDomain::Decoded,
                chunk_key_hash(chunk));
            CacheAcquireResult cache = cache_acquire(chunk, file.flags, false);
            if (cache.kind == CacheAcquireKind::Pending) {
                return PipelineStep::YieldCache;
            }
            if (cache.kind == CacheAcquireKind::Failed) {
                const int error = cache.lease.error ? cache.lease.error
                                                    : SCE_KERNEL_ERROR_EIO;
                cleanup_pipeline_continuation(pipeline, error);
                if (errorOut) *errorOut = error;
                return PipelineStep::Failed;
            }
            if (cache.kind == CacheAcquireKind::Ready) {
                std::memcpy(output + task.destinationOffset,
                            cache.lease.data + task.sourceOffset,
                            task.copyLength);
                cache_release(cache.lease);
                ++pipeline.taskIndex;
                continue;
            }
            if (cache.kind == CacheAcquireKind::Load) {
                pipeline.decodedLease = cache.lease;
            }
        }

        if (!pipeline_window_contains(pipeline, chunk) &&
            !bind_mandatory_page_window(chunk, pipeline)) {
            PipelineIoRange range{};
            const int rangeRc =
                make_pipeline_window_range(chunk, &range);
            if (rangeRc != 0) {
                cleanup_pipeline_continuation(pipeline, rangeRc);
                if (errorOut) *errorOut = rangeRc;
                return PipelineStep::Failed;
            }
            int prepareError = 0;
            const PipelineStep prepared = prepare_pipeline_window_aio(
                range, pipeline, &prepareError);
            if (prepared == PipelineStep::YieldCache) {
                return prepared;
            }
            if (prepared == PipelineStep::YieldIo ||
                prepared == PipelineStep::YieldFd) {
                return prepared;
            }
            if (prepared == PipelineStep::Failed) {
                cleanup_pipeline_continuation(pipeline, prepareError);
                if (errorOut) *errorOut = prepareError;
                return prepared;
            }
        } else {
            state.stats.physicalWindowHits.fetch_add(
                1, std::memory_order_relaxed);
        }

        uint8_t* decoded = nullptr;
        const bool cacheLoader =
            pipeline.decodedLease.entry != kInvalidIndex;
        if (cacheLoader) {
            decoded = pipeline.decodedLease.data;
        } else if (chunk.codec == kAmprPackChunkRaw ||
                   (task.sourceOffset == 0 && task.copyLength == chunk.rawSize)) {
            decoded = output + task.destinationOffset;
        } else {
            decoded = worker.decodedScratch;
        }
        const bool rawBypass = !cacheLoader && chunk.codec == kAmprPackChunkRaw;
        const int decodeRc = decode_pipeline_chunk(
            chunk, decoded, pipeline,
            rawBypass ? task.sourceOffset : 0,
            rawBypass ? task.copyLength : chunk.rawSize);
        if (cacheLoader) {
            cache_publish(pipeline.decodedLease, decodeRc);
            if (decodeRc == 0) {
                std::memcpy(output + task.destinationOffset,
                            pipeline.decodedLease.data + task.sourceOffset,
                            task.copyLength);
            }
            cache_release(pipeline.decodedLease);
        } else if (decodeRc == 0 &&
                   decoded == worker.decodedScratch) {
            std::memcpy(output + task.destinationOffset,
                        decoded + task.sourceOffset,
                        task.copyLength);
        }
        if (decodeRc != 0) {
            cleanup_pipeline_continuation(pipeline, decodeRc);
            if (errorOut) *errorOut = decodeRc;
            return PipelineStep::Failed;
        }
        ++pipeline.taskIndex;
    }
    release_pipeline_window_pages(pipeline);
    release_mandatory_page_plan(pipeline);
    pipeline.ioWindowValid = false;
    pipeline.ioWindowData = nullptr;
    state.stats.logicalBytes.fetch_add(length, std::memory_order_relaxed);
    if (returnValue) *returnValue = static_cast<int64_t>(length);
    return PipelineStep::Complete;
}

static uint8_t queue_priority(int priority) {
    if (priority == SCE_KERNEL_AIO_PRIORITY_HIGH) return 2u;
    if (priority == SCE_KERNEL_AIO_PRIORITY_MID) return 1u;
    return 0u;
}

static PackWorkClass classify_work(const AmprPackFileRecord& file,
                                   const SceKernelAioRWRequest& request) {
    const uint64_t requestBytes = static_cast<uint64_t>(request.nbyte);
    if (requestBytes <= AMPR_EMU_PACK_LATENCY_READ_MAX_BYTES ||
        ((file.flags & kAmprPackFileHot) != 0 &&
         requestBytes < AMPR_EMU_PACK_BULK_READ_MIN_BYTES)) {
        return PackWorkClass::Latency;
    }
    if ((file.flags & kAmprPackFileStreaming) != 0 ||
        requestBytes >= AMPR_EMU_PACK_BULK_READ_MIN_BYTES) {
        return PackWorkClass::Bulk;
    }
    return PackWorkClass::Balanced;
}

static uint32_t work_class_index(PackWorkClass workClass) {
    return static_cast<uint32_t>(workClass);
}

static uint32_t effective_latency_reserve_locked(const PackState& state) {
    if (state.workersStarted <= 1u) return 0u;
    return (std::min)(
        state.latencyReserveWorkers,
        state.workersStarted - 1u);
}

static bool worker_is_latency_reserved_locked(const PackState& state,
                                               uint32_t workerIndex) {
    return workerIndex < effective_latency_reserve_locked(state);
}

static void update_queue_depth_peak(AtomicPackStats& stats,
                                    PackWorkClass workClass,
                                    uint32_t depth) {
    PackTelemetryCounter* peak = nullptr;
    switch (workClass) {
        case PackWorkClass::Latency:
            peak = &stats.queueDepthPeakLatency;
            break;
        case PackWorkClass::Balanced:
            peak = &stats.queueDepthPeakBalanced;
            break;
        case PackWorkClass::Bulk:
            peak = &stats.queueDepthPeakBulk;
            break;
        default:
            return;
    }
    update_atomic_peak(*peak, depth);
}

static void queue_push_locked(PackState& state,
                              uint32_t index,
                              uint64_t queuedAtUsec) {
    VirtualAioSlot& job = state.virtualAio[index];
    const uint32_t priority = job.priority;
    const uint32_t workClass = work_class_index(job.workClass);
    job.next = kInvalidIndex;
    if (state.queueTail[priority][workClass] != kInvalidIndex) {
        state.virtualAio[state.queueTail[priority][workClass]].next = index;
    } else {
        state.queueHead[priority][workClass] = index;
    }
    state.queueTail[priority][workClass] = index;
    if (state.queueDepth[workClass] == UINT32_MAX) {
        AMPR_KLOGF("ampr.abort reason=apr.pack.queue.depth-overflow file=%s line=%d",
                   __FILE__, __LINE__);
        std::abort();
    }
    const uint32_t depth = ++state.queueDepth[workClass];
    update_queue_depth_peak(state.stats, job.workClass, depth);
#if AMPR_EMU_PACK_TELEMETRY
    job.queuedAtUsec = queuedAtUsec;
#else
    (void)queuedAtUsec;
#endif
    job.phase = VirtualAioPhase::Queued;
}

static uint32_t queue_pop_lane_locked(PackState& state,
                                      uint32_t lane,
                                      PackWorkClass workClass,
                                      bool requireRetainedPipeline) {
    const uint32_t classIndex = work_class_index(workClass);
    uint32_t previous = kInvalidIndex;
    uint32_t index = state.queueHead[lane][classIndex];
    while (index != kInvalidIndex && requireRetainedPipeline &&
           state.virtualAio[index].pipelineIndex == kInvalidIndex) {
        previous = index;
        index = state.virtualAio[index].next;
    }
    if (index == kInvalidIndex) return kInvalidIndex;
    VirtualAioSlot& job = state.virtualAio[index];
    if (previous == kInvalidIndex) {
        state.queueHead[lane][classIndex] = job.next;
    } else {
        state.virtualAio[previous].next = job.next;
    }
    if (state.queueTail[lane][classIndex] == index) {
        state.queueTail[lane][classIndex] = previous;
    }
    if (state.queueHead[lane][classIndex] == kInvalidIndex) {
        state.queueTail[lane][classIndex] = kInvalidIndex;
    }
    job.next = kInvalidIndex;
    if (state.queueDepth[classIndex] == 0) {
        AMPR_KLOGF("ampr.abort reason=apr.pack.queue.depth-underflow file=%s line=%d",
                   __FILE__, __LINE__);
        std::abort();
    }
    --state.queueDepth[classIndex];
    return index;
}

static bool queue_remove_locked(PackState& state, uint32_t index) {
    if (index >= AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS) return false;
    VirtualAioSlot& target = state.virtualAio[index];
    const uint32_t lane = target.priority;
    const uint32_t classIndex = work_class_index(target.workClass);
    uint32_t previous = kInvalidIndex;
    uint32_t current = state.queueHead[lane][classIndex];
    while (current != kInvalidIndex) {
        VirtualAioSlot& entry = state.virtualAio[current];
        if (current == index) {
            if (previous == kInvalidIndex) {
                state.queueHead[lane][classIndex] = entry.next;
            } else {
                state.virtualAio[previous].next = entry.next;
            }
            if (state.queueTail[lane][classIndex] == index) {
                state.queueTail[lane][classIndex] = previous;
            }
            entry.next = kInvalidIndex;
            if (state.queueDepth[classIndex] == 0) {
                AMPR_KLOGF("ampr.abort reason=apr.pack.queue.depth-underflow file=%s line=%d",
                           __FILE__, __LINE__);
                std::abort();
            }
            --state.queueDepth[classIndex];
            return true;
        }
        previous = current;
        current = entry.next;
    }
    return false;
}

static bool queue_has_matching_work_for_worker_locked(
    const PackState& state,
    uint32_t workerIndex,
    bool requireRetainedPipeline) {
    const bool reserved = worker_is_latency_reserved_locked(
        state, workerIndex);
    for (uint32_t priority = 0; priority < 3u; ++priority) {
        for (uint32_t classIndex = 0;
             classIndex < kPackWorkClassCount; ++classIndex) {
            if (reserved &&
                classIndex == work_class_index(PackWorkClass::Bulk)) {
                continue;
            }
            uint32_t index = state.queueHead[priority][classIndex];
            while (index != kInvalidIndex) {
                if (!requireRetainedPipeline ||
                    state.virtualAio[index].pipelineIndex != kInvalidIndex) {
                    return true;
                }
                index = state.virtualAio[index].next;
            }
        }
    }
    return false;
}

static bool queue_has_work_for_worker_locked(const PackState& state,
                                             uint32_t workerIndex) {
    if (queue_has_matching_work_for_worker_locked(
            state, workerIndex, true)) {
        return true;
    }
    return state.pipelineFreeHead != kInvalidIndex &&
           queue_has_matching_work_for_worker_locked(
               state, workerIndex, false);
}

static uint32_t queue_pop_scheduled_locked(PackState& state,
                                           uint32_t workerIndex,
                                           bool requireRetainedPipeline) {
    // Weighted high:mid:low service (4:2:1), with immediate fallback to any
    // non-empty queue. Within one SDK priority, latency requests precede
    // balanced requests, which precede bulk requests. Trace-derived profiles
    // may reserve one worker that never consumes bulk work.
    static constexpr uint8_t schedule[7] = {2, 2, 2, 2, 1, 1, 0};
    static constexpr PackWorkClass classOrder[3] = {
        PackWorkClass::Latency,
        PackWorkClass::Balanced,
        PackWorkClass::Bulk,
    };
    const bool reserved = worker_is_latency_reserved_locked(
        state, workerIndex);
    for (size_t attempt = 0; attempt < 7u; ++attempt) {
        const uint32_t lane = schedule[state.queuePickCounter++ % 7u];
        for (PackWorkClass workClass : classOrder) {
            if (reserved && workClass == PackWorkClass::Bulk) continue;
            const uint32_t index = queue_pop_lane_locked(
                state, lane, workClass, requireRetainedPipeline);
            if (index != kInvalidIndex) return index;
        }
    }
    for (int lane = 2; lane >= 0; --lane) {
        for (PackWorkClass workClass : classOrder) {
            if (reserved && workClass == PackWorkClass::Bulk) continue;
            const uint32_t index = queue_pop_lane_locked(
                state, static_cast<uint32_t>(lane), workClass,
                requireRetainedPipeline);
            if (index != kInvalidIndex) return index;
        }
    }
    return kInvalidIndex;
}

static uint32_t queue_pop_locked(PackState& state, uint32_t workerIndex) {
    // Resume completed/cache-ready pipelines before admitting new logical
    // reads. A resumed pipeline either completes or yields back to AIO, so this
    // short preference reduces visible completion latency without pinning a
    // worker or preventing the I/O window from refilling.
    const uint32_t retained = queue_pop_scheduled_locked(
        state, workerIndex, true);
    if (retained != kInvalidIndex) return retained;
    if (state.pipelineFreeHead == kInvalidIndex) return kInvalidIndex;
    return queue_pop_scheduled_locked(state, workerIndex, false);
}

static ReadPipelineContext* acquire_pipeline_locked(PackState& state,
                                                    uint32_t owner) {
    if (owner >= AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS ||
        state.pipelineFreeHead == kInvalidIndex) {
        return nullptr;
    }
    const uint32_t index = state.pipelineFreeHead;
    if (index >= state.pipelineCapacity ||
        index >= AMPR_EMU_PACK_PIPELINE_SLOTS) {
        AMPR_KLOGF("ampr.abort reason=apr.pack.pipeline.free-corrupt index=%u capacity=%u file=%s line=%d",
                   index, state.pipelineCapacity, __FILE__, __LINE__);
        std::abort();
    }
    ReadPipelineContext& pipeline = state.pipelines[index];
    state.pipelineFreeHead = pipeline.nextFree;
    pipeline.nextFree = kInvalidIndex;
    pipeline.owner = owner;
    pipeline.ioWindowOffset = 0;
    pipeline.ioWindowSize = 0;
    pipeline.ioWindowPackId = UINT16_MAX;
    pipeline.ioWindowValid = false;
    pipeline.ioWindowData = nullptr;
    pipeline.ioRange = {};
    pipeline.taskIndex = 0;
    pipeline.taskCount = 0;
    pipeline.decodedLease = {};
    pipeline.decodedLease.entry = kInvalidIndex;
    for (PhysicalCacheAcquireResult& page : pipeline.ioPages) page = {};
    pipeline.ioPageCount = 0;
    for (PipelineMandatoryPage& page : pipeline.mandatoryPages) page = {};
    for (SceKernelAioRWRequest& request : pipeline.mandatoryRequests) {
        request = {};
    }
    for (SceKernelAioResult& result : pipeline.mandatoryResults) result = {};
    for (size_t fdIndex = 0;
         fdIndex < kPackMandatoryGroupMaxPages;
         ++fdIndex) {
        pipeline.mandatoryFdPackIds[fdIndex] = UINT16_MAX;
        pipeline.mandatoryFds[fdIndex] = -1;
    }
    pipeline.mandatoryPageCount = 0;
    pipeline.mandatoryTaskEnd = 0;
    pipeline.mandatorySkipTask = SIZE_MAX;
    pipeline.mandatoryRequestCount = 0;
    pipeline.mandatoryFdCount = 0;
    pipeline.mandatoryPlanActive = false;
    pipeline.packFd = -1;
    pipeline.nativeRequest = {};
    pipeline.nativeResult = {};
#if AMPR_EMU_PACK_TELEMETRY
    pipeline.nativeSubmittedAtUsec = 0;
#endif
    pipeline.cacheWaitEpoch = 0;
    pipeline.cacheWaitBucket = 0;
    pipeline.cacheWaitDomain = CacheWaitDomain::Decoded;
    pipeline.fdWaitEpoch = 0;
    pipeline.fdBudgetWaitEpoch = 0;
    pipeline.nativeIoError = 0;
    pipeline.nativeCompletionReady = false;
    pipeline.nativeAccepted = false;
    __atomic_store_n(&pipeline.nativeSubmitted, false, __ATOMIC_RELAXED);
    pipeline.active = true;
    state.virtualAio[owner].pipelineIndex = index;
    if (state.pipelineActiveCount >= state.pipelineCapacity) {
        AMPR_KLOGF("ampr.abort reason=apr.pack.pipeline.active-overflow owner=%u active=%u capacity=%u file=%s line=%d",
                   owner, state.pipelineActiveCount, state.pipelineCapacity,
                   __FILE__, __LINE__);
        std::abort();
    }
    ++state.pipelineActiveCount;
    const uint64_t active = state.stats.pipelineContextsActive.fetch_add(
                                1, std::memory_order_relaxed) + 1u;
    update_atomic_peak(state.stats.pipelineContextsActivePeak, active);
    return &pipeline;
}

static void release_pipeline_locked(PackState& state, uint32_t owner) {
    if (owner >= AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS) return;
    VirtualAioSlot& job = state.virtualAio[owner];
    const uint32_t index = job.pipelineIndex;
    if (index == kInvalidIndex) return;
    if (index >= state.pipelineCapacity ||
        index >= AMPR_EMU_PACK_PIPELINE_SLOTS) {
        AMPR_KLOGF("ampr.abort reason=apr.pack.pipeline.owner-corrupt owner=%u index=%u capacity=%u file=%s line=%d",
                   owner, index, state.pipelineCapacity, __FILE__, __LINE__);
        std::abort();
    }
    ReadPipelineContext& pipeline = state.pipelines[index];
    if (!pipeline.active || pipeline.owner != owner) {
        AMPR_KLOGF("ampr.abort reason=apr.pack.pipeline.owner-mismatch owner=%u index=%u actual=%u active=%u file=%s line=%d",
                   owner, index, pipeline.owner, pipeline.active ? 1u : 0u,
                   __FILE__, __LINE__);
        std::abort();
    }
    if (job.phase == VirtualAioPhase::WaitingCache) {
        if (state.cacheWaiterCount == 0) {
            AMPR_KLOGF("ampr.abort reason=apr.pack.cache-waiter-underflow owner=%u file=%s line=%d",
                       owner, __FILE__, __LINE__);
            std::abort();
        }
        --state.cacheWaiterCount;
    } else if (job.phase == VirtualAioPhase::WaitingFd) {
        if (state.fdWaiterCount == 0) {
            AMPR_KLOGF("ampr.abort reason=apr.pack.fd-waiter-underflow owner=%u file=%s line=%d",
                       owner, __FILE__, __LINE__);
            std::abort();
        }
        --state.fdWaiterCount;
    }
    if (pipeline.packFd >= 0 || pipeline.mandatoryFdCount != 0 ||
        pipeline.nativeAccepted ||
        __atomic_load_n(&pipeline.nativeSubmitted, __ATOMIC_ACQUIRE) ||
        pipeline.decodedLease.entry != kInvalidIndex) {
        AMPR_KLOGF("ampr.abort reason=apr.pack.pipeline.release-live-resource owner=%u index=%u fd=%d native=%u submitted=%u decoded=%u file=%s line=%d",
                   owner, index, pipeline.packFd,
                   pipeline.nativeAccepted ? 1u : 0u,
                   __atomic_load_n(&pipeline.nativeSubmitted, __ATOMIC_RELAXED)
                       ? 1u : 0u,
                   pipeline.decodedLease.entry, __FILE__, __LINE__);
        std::abort();
    }
    for (size_t page = 0; page < pipeline.ioPageCount; ++page) {
        if (pipeline.ioPages[page].lease.entry != kInvalidIndex) {
            AMPR_KLOGF("ampr.abort reason=apr.pack.pipeline.release-live-page owner=%u index=%u page=%llu entry=%u file=%s line=%d",
                       owner, index, (unsigned long long)page,
                       pipeline.ioPages[page].lease.entry, __FILE__, __LINE__);
            std::abort();
        }
    }
    for (size_t page = 0;
         page < pipeline.mandatoryPageCount;
         ++page) {
        if (pipeline.mandatoryPages[page].acquired.lease.entry !=
            kInvalidIndex) {
            AMPR_KLOGF("ampr.abort reason=apr.pack.pipeline.release-live-mandatory-page owner=%u index=%u page=%llu entry=%u file=%s line=%d",
                       owner, index, (unsigned long long)page,
                       pipeline.mandatoryPages[page].acquired.lease.entry,
                       __FILE__, __LINE__);
            std::abort();
        }
    }
    pipeline.owner = kInvalidIndex;
    pipeline.ioWindowOffset = 0;
    pipeline.ioWindowSize = 0;
    pipeline.ioWindowPackId = UINT16_MAX;
    pipeline.ioWindowValid = false;
    pipeline.ioWindowData = nullptr;
    pipeline.ioRange = {};
    pipeline.taskIndex = 0;
    pipeline.taskCount = 0;
    pipeline.ioPageCount = 0;
    pipeline.mandatoryPageCount = 0;
    pipeline.mandatoryTaskEnd = 0;
    pipeline.mandatorySkipTask = SIZE_MAX;
    pipeline.mandatoryRequestCount = 0;
    pipeline.mandatoryFdCount = 0;
    pipeline.mandatoryPlanActive = false;
    pipeline.nativeRequest = {};
    pipeline.nativeResult = {};
#if AMPR_EMU_PACK_TELEMETRY
    pipeline.nativeSubmittedAtUsec = 0;
#endif
    pipeline.cacheWaitEpoch = 0;
    pipeline.cacheWaitBucket = 0;
    pipeline.cacheWaitDomain = CacheWaitDomain::Decoded;
    pipeline.fdWaitEpoch = 0;
    pipeline.fdBudgetWaitEpoch = 0;
    pipeline.nativeIoError = 0;
    pipeline.nativeCompletionReady = false;
    pipeline.nativeAccepted = false;
    __atomic_store_n(&pipeline.nativeSubmitted, false, __ATOMIC_RELAXED);
    pipeline.active = false;
    pipeline.nextFree = state.pipelineFreeHead;
    state.pipelineFreeHead = index;
    job.pipelineIndex = kInvalidIndex;
    if (state.pipelineActiveCount == 0) {
        AMPR_KLOGF("ampr.abort reason=apr.pack.pipeline.active-underflow owner=%u file=%s line=%d",
                   owner, __FILE__, __LINE__);
        std::abort();
    }
    --state.pipelineActiveCount;
    state.stats.pipelineContextsActive.fetch_sub(
        1, std::memory_order_relaxed);
    state.queueCv.notify_one();
}

static void complete_virtual_job(PackState& state,
                                 uint32_t index,
                                 int64_t returnValue,
                                 int completionState) {
    VirtualAioSlot& job = state.virtualAio[index];
    release_pipeline_locked(state, index);
#if AMPR_EMU_PACK_TELEMETRY
    const uint64_t usecs = elapsed_usecs(job.admittedAtUsec, pack_monotonic_usecs());
    record_latency(state.stats.logicalLatency, usecs);
    if (job.workClass == PackWorkClass::Latency) {
        record_latency(state.stats.latencyClassLatency, usecs);
    }
    if (returnValue >= 0 && completionState == SCE_KERNEL_AIO_STATE_COMPLETED) {
        state.stats.deliveredBytes.fetch_add(static_cast<uint64_t>(returnValue),
                                             std::memory_order_relaxed);
    } else {
        state.stats.logicalFailures.fetch_add(1, std::memory_order_relaxed);
    }
#endif
    job.returnValue = returnValue;
    job.completionState = completionState;
    if (job.request.result) {
        __atomic_store_n(&job.request.result->returnValue,
                         returnValue, __ATOMIC_RELAXED);
        __atomic_store_n(&job.request.result->state,
                         static_cast<uint32_t>(completionState),
                         __ATOMIC_RELEASE);
    }
    job.phase = VirtualAioPhase::Done;
    ++state.aioCompletionEpoch;
    state.stats.aioCompleted.fetch_add(1, std::memory_order_relaxed);
    state.aioCv.notify_all();
    apr_reactor_notify_external_progress();
#if AMPR_EMU_PACK_IO_LOG
    AMPR_LOGF("apr.pack.aio.complete vaio=0x%x fileId=%u off=0x%llx bytes=0x%llx return=%lld state=0x%x class=%u origin=%s",
              (unsigned)encode_virtual_aio(index, job.generation),
              job.fileId, (unsigned long long)job.request.offset,
              (unsigned long long)job.request.nbyte,
              (long long)returnValue, completionState,
              (unsigned)job.workClass,
              job.processOrigin ? "process" : "indexed");
#endif
}

static void queue_cache_waiter_locked(PackState& state,
                                      uint32_t owner,
                                      uint64_t queuedAtUsec) {
    if (owner >= AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS ||
        state.virtualAio[owner].phase != VirtualAioPhase::WaitingCache ||
        state.cacheWaiterCount == 0) {
        AMPR_KLOGF("ampr.abort reason=apr.pack.cache-waiter-corrupt owner=%u count=%u file=%s line=%d",
                   owner, state.cacheWaiterCount, __FILE__, __LINE__);
        std::abort();
    }
    --state.cacheWaiterCount;
    queue_push_locked(state, owner, queuedAtUsec);
}

static void queue_fd_waiter_locked(PackState& state,
                                   uint32_t owner,
                                   uint64_t queuedAtUsec) {
    if (owner >= AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS ||
        state.virtualAio[owner].phase != VirtualAioPhase::WaitingFd ||
        state.fdWaiterCount == 0) {
        AMPR_KLOGF("ampr.abort reason=apr.pack.fd-waiter-corrupt owner=%u count=%u file=%s line=%d",
                   owner, state.fdWaiterCount, __FILE__, __LINE__);
        std::abort();
    }
    --state.fdWaiterCount;
    queue_push_locked(state, owner, queuedAtUsec);
}

static bool wake_cache_waiters_locked(PackState& state) {
    if (state.cacheWaiterCount == 0) return false;
    bool queued = false;
    const uint64_t nowUsec = pack_telemetry_usecs();
    for (uint32_t index = 0; index < state.pipelineCapacity; ++index) {
        ReadPipelineContext& pipeline = state.pipelines[index];
        const uint64_t epoch = cache_wait_epoch(
            state, pipeline.cacheWaitDomain, pipeline.cacheWaitBucket);
        if (!pipeline.active || pipeline.owner == kInvalidIndex ||
            pipeline.cacheWaitEpoch == epoch) {
            continue;
        }
        VirtualAioSlot& job = state.virtualAio[pipeline.owner];
        if (job.phase != VirtualAioPhase::WaitingCache) continue;
        pipeline.cacheWaitEpoch = epoch;
        queue_cache_waiter_locked(state, pipeline.owner, nowUsec);
        queued = true;
    }
    return queued;
}

static bool wake_fd_waiters_locked(PackState& state) {
    if (state.fdWaiterCount == 0) return false;
    const uint64_t epoch = state.packFdProgressEpoch.load(
        std::memory_order_acquire);
    const uint64_t budgetEpoch =
        ampr_index_fd_open_budget_progress_generation();
    bool queued = false;
    const uint64_t nowUsec = pack_telemetry_usecs();
    for (uint32_t index = 0; index < state.pipelineCapacity; ++index) {
        ReadPipelineContext& pipeline = state.pipelines[index];
        if (!pipeline.active || pipeline.owner == kInvalidIndex ||
            (pipeline.fdWaitEpoch == epoch &&
             pipeline.fdBudgetWaitEpoch == budgetEpoch)) {
            continue;
        }
        VirtualAioSlot& job = state.virtualAio[pipeline.owner];
        if (job.phase != VirtualAioPhase::WaitingFd) continue;
        pipeline.fdWaitEpoch = epoch;
        pipeline.fdBudgetWaitEpoch = budgetEpoch;
        queue_fd_waiter_locked(state, pipeline.owner, nowUsec);
        queued = true;
    }
    return queued;
}

static int native_pack_priority(uint8_t priority);
static AprExternalAioClass native_pack_io_class(PackWorkClass workClass,
                                                 size_t physicalBytes);
static void complete_pack_backing_aio(
    void* context, const AprExternalAioNotification& notification);

static void* pack_worker_entry(void* argument) {
    auto* worker = static_cast<WorkerContext*>(argument);
    if (!worker) return nullptr;
    PackState& state = pack_state();
    (void)scePthreadSetprio(scePthreadSelf(), AMPR_EMU_PACK_WORKER_PRIORITY);
    if (AMPR_EMU_PACK_WORKER_AFFINITY != 0) {
        (void)scePthreadSetaffinity(scePthreadSelf(),
                                   AMPR_EMU_PACK_WORKER_AFFINITY);
    }
    for (;;) {
        uint32_t index = kInvalidIndex;
        ReadPipelineContext* pipeline = nullptr;
        {
            AmprUniqueLock lock(state.m);
            state.queueCv.wait(lock, [&] {
                return state.workerStopRequested.load(
                           std::memory_order_acquire) ||
                       wake_fd_waiters_locked(state) ||
                       queue_has_work_for_worker_locked(
                    state, worker->index);
            });
            if (state.workerStopRequested.load(std::memory_order_acquire) &&
                !queue_has_work_for_worker_locked(state, worker->index)) {
                return nullptr;
            }
            index = queue_pop_locked(state, worker->index);
            if (index == kInvalidIndex) continue;
            VirtualAioSlot& job = state.virtualAio[index];
            if (job.pipelineIndex == kInvalidIndex) {
                pipeline = acquire_pipeline_locked(state, index);
                if (!pipeline) {
#if AMPR_EMU_PACK_TELEMETRY
                    queue_push_locked(
                        state, index, state.virtualAio[index].queuedAtUsec);
#else
                    queue_push_locked(state, index, 0);
#endif
                    continue;
                }
            } else {
                const uint32_t pipelineIndex = job.pipelineIndex;
                if (pipelineIndex >= state.pipelineCapacity) {
                    AMPR_KLOGF("ampr.abort reason=apr.pack.pipeline.resume-corrupt owner=%u index=%u capacity=%u file=%s line=%d",
                               index, pipelineIndex, state.pipelineCapacity,
                               __FILE__, __LINE__);
                    std::abort();
                }
                pipeline = &state.pipelines[pipelineIndex];
                if (!pipeline->active || pipeline->owner != index) {
                    AMPR_KLOGF("ampr.abort reason=apr.pack.pipeline.resume-owner owner=%u index=%u actual=%u active=%u file=%s line=%d",
                               index, pipelineIndex, pipeline->owner,
                               pipeline->active ? 1u : 0u,
                               __FILE__, __LINE__);
                    std::abort();
                }
            }
            job.phase = VirtualAioPhase::Running;
            if (worker_is_latency_reserved_locked(state, worker->index)) {
                state.stats.latencyWorkerDispatches.fetch_add(
                    1, std::memory_order_relaxed);
            }
        }

        VirtualAioSlot& job = state.virtualAio[index];
#if AMPR_EMU_PACK_TELEMETRY
        const uint64_t workerStartUsec = pack_monotonic_usecs();
        const uint64_t queueWaitUsec = elapsed_usecs(
            job.queuedAtUsec, workerStartUsec);
        record_latency(state.stats.queueLatency, queueWaitUsec);
        state.stats.workerJobs.fetch_add(1, std::memory_order_relaxed);
        state.stats.workerQueueWaitUsecTotal.fetch_add(
            queueWaitUsec, std::memory_order_relaxed);
        update_atomic_peak(
            state.stats.workerQueueWaitUsecMax, queueWaitUsec);
        record_slow_buckets(
            queueWaitUsec,
            state.stats.workerQueueWaitSlow1ms,
            state.stats.workerQueueWaitSlow5ms,
            state.stats.workerQueueWaitSlow20ms);
        const uint64_t workersBusy = state.stats.workersBusy.fetch_add(
                                         1, std::memory_order_relaxed) + 1u;
        update_atomic_peak(state.stats.workersBusyPeak, workersBusy);
        if (queueWaitUsec >= 20000u) {
            AMPR_LOGF("apr.pack.worker.queue.slow worker=%u fileId=%u bytes=0x%llx class=%u usec=%llu",
                      worker->index, job.fileId,
                      (unsigned long long)job.request.nbyte,
                      (unsigned)job.workClass,
                      (unsigned long long)queueWaitUsec);
        }
#endif
        int64_t returnValue = 0;
        int pipelineError = 0;
        const PipelineStep step = advance_virtual_read_aio(
            job, *worker, *pipeline, &returnValue, &pipelineError);
#if AMPR_EMU_PACK_TELEMETRY
        const uint64_t workerEndUsec = pack_monotonic_usecs();
        const uint64_t workerUsec = elapsed_usecs(
            workerStartUsec, workerEndUsec);
        record_latency(state.stats.workerLatency, workerUsec);
        state.stats.workersBusy.fetch_sub(1, std::memory_order_relaxed);
        state.stats.workerJobUsecTotal.fetch_add(
            workerUsec, std::memory_order_relaxed);
        update_atomic_peak(state.stats.workerJobUsecMax, workerUsec);
        if (workerUsec >= 20000u) {
            AMPR_LOGF("apr.pack.worker.slow worker=%u fileId=%u bytes=0x%llx class=%u usec=%llu return=%lld",
                      worker->index, job.fileId,
                      (unsigned long long)job.request.nbyte,
                      (unsigned)job.workClass,
                      (unsigned long long)workerUsec,
                      (long long)(step == PipelineStep::Failed
                                      ? pipelineError
                                      : returnValue));
        }
#endif
        bool notifyWorkers = false;
        {
            AmprLockGuard lock(state.m);
            notifyWorkers = wake_cache_waiters_locked(state);
            switch (step) {
                case PipelineStep::YieldIo:
                    state.stats.pipelineIoYields.fetch_add(
                        1, std::memory_order_relaxed);
                    if (job.cancelRequested.load(
                            std::memory_order_acquire) ||
                        state.workerStopRequested.load(
                            std::memory_order_acquire)) {
                        queue_push_locked(state, index,
                                          pack_telemetry_usecs());
                        notifyWorkers = true;
                    } else {
                        job.phase = VirtualAioPhase::IoQueued;
                        pipeline->nativeAccepted = true;
                        const bool mandatoryGroup =
                            pipeline->mandatoryPlanActive &&
                            pipeline->mandatoryRequestCount != 0;
                        size_t physicalBytes = 0;
                        if (mandatoryGroup) {
                            for (size_t requestIndex = 0;
                                 requestIndex <
                                     pipeline->mandatoryRequestCount;
                                 ++requestIndex) {
                                physicalBytes += pipeline->mandatoryRequests[
                                    requestIndex].nbyte;
                            }
                        } else {
                            physicalBytes = pipeline->nativeRequest.nbyte;
                        }
                        const int aioPriority =
                            native_pack_priority(job.priority);
                        const AprExternalAioClass ioClass =
                            native_pack_io_class(
                                job.workClass, physicalBytes);
                        const bool submitMultiple = mandatoryGroup &&
                            pipeline->mandatoryRequestCount > 1u;
                        const int submitRc = submitMultiple
                            ? apr_reactor_submit_external_aio_read_group(
                                  pipeline->mandatoryRequests,
                                  pipeline->mandatoryRequestCount,
                                  aioPriority,
                                  ioClass,
                                  pipeline,
                                  &complete_pack_backing_aio)
                            : apr_reactor_submit_external_aio_read(
                                  mandatoryGroup
                                      ? pipeline->mandatoryRequests[0]
                                      : pipeline->nativeRequest,
                                  aioPriority,
                                  ioClass,
                                  pipeline,
                                  &complete_pack_backing_aio);
                        if (submitRc != 0) {
                            pipeline->nativeAccepted = false;
                            pipeline->nativeIoError = submitRc;
                            pipeline->nativeCompletionReady = true;
                            state.stats.backingAioSubmitFailures.fetch_add(
                                1, std::memory_order_relaxed);
                            queue_push_locked(
                                state, index, pack_telemetry_usecs());
                            notifyWorkers = true;
                        }
                    }
                    break;
                case PipelineStep::YieldCache: {
                    state.stats.pipelineCacheYields.fetch_add(
                        1, std::memory_order_relaxed);
                    const uint64_t epoch = cache_wait_epoch(
                        state, pipeline->cacheWaitDomain,
                        pipeline->cacheWaitBucket);
                    if (job.cancelRequested.load(
                            std::memory_order_acquire) ||
                        state.workerStopRequested.load(
                            std::memory_order_acquire) ||
                        epoch != pipeline->cacheWaitEpoch) {
                        pipeline->cacheWaitEpoch = epoch;
                        queue_push_locked(state, index,
                                          pack_telemetry_usecs());
                        notifyWorkers = true;
                    } else {
                        job.phase = VirtualAioPhase::WaitingCache;
                        ++state.cacheWaiterCount;
                    }
                    break;
                }
                case PipelineStep::YieldFd: {
                    state.stats.pipelineFdYields.fetch_add(
                        1, std::memory_order_relaxed);
                    const uint64_t epoch = state.packFdProgressEpoch.load(
                        std::memory_order_acquire);
                    const uint64_t budgetEpoch =
                        ampr_index_fd_open_budget_progress_generation();
                    if (job.cancelRequested.load(
                            std::memory_order_acquire) ||
                        state.workerStopRequested.load(
                            std::memory_order_acquire) ||
                        epoch != pipeline->fdWaitEpoch ||
                        budgetEpoch != pipeline->fdBudgetWaitEpoch) {
                        pipeline->fdWaitEpoch = epoch;
                        pipeline->fdBudgetWaitEpoch = budgetEpoch;
                        queue_push_locked(state, index,
                                          pack_telemetry_usecs());
                        notifyWorkers = true;
                    } else {
                        job.phase = VirtualAioPhase::WaitingFd;
                        ++state.fdWaiterCount;
                    }
                    break;
                }
                case PipelineStep::Complete:
                    complete_virtual_job(
                        state, index, returnValue,
                        SCE_KERNEL_AIO_STATE_COMPLETED);
                    break;
                case PipelineStep::Failed: {
                    const bool canceled =
                        pipelineError == SCE_KERNEL_ERROR_ECANCELED ||
                        job.cancelRequested.load(std::memory_order_relaxed);
                    complete_virtual_job(
                        state, index, pipelineError,
                        canceled ? SCE_KERNEL_AIO_STATE_ABORTED
                                 : SCE_KERNEL_AIO_STATE_COMPLETED);
                    break;
                }
                case PipelineStep::Ready:
                    AMPR_KLOGF("ampr.abort reason=apr.pack.pipeline.unconsumed-ready owner=%u file=%s line=%d",
                               index, __FILE__, __LINE__);
                    std::abort();
            }
        }
        if (notifyWorkers) state.queueCv.notify_all();
    }
}

static bool ensure_workers_locked(PackState& state) {
    if (state.workerStopRequested.load(std::memory_order_acquire)) return false;
    if (state.workersStarted != 0) return true;
    constexpr size_t decodedBytes = kPackMaxBlockBytes;
    if (state.pipelineCapacity == 0) {
        state.pipelineFreeHead = kInvalidIndex;
        for (uint32_t i = 0; i < AMPR_EMU_PACK_PIPELINE_SLOTS; ++i) {
            ReadPipelineContext& pipeline = state.pipelines[i];
            pipeline.ioWindowPackId = UINT16_MAX;
            pipeline.owner = kInvalidIndex;
            pipeline.nextFree = state.pipelineFreeHead;
            state.pipelineFreeHead = i;
            ++state.pipelineCapacity;
        }
    }
    if (state.pipelineCapacity == 0) {
        AMPR_CRITICAL_LOGF("apr.pack.pipeline.start.fail requested=%u",
                           (unsigned)AMPR_EMU_PACK_PIPELINE_SLOTS);
        return false;
    }

    const uint32_t requestedWorkers = (std::min)(
        state.requestedWorkers,
        state.pipelineCapacity);
    for (uint32_t i = 0; i < requestedWorkers; ++i) {
        WorkerContext& worker = state.workers[i];
        worker.index = state.workersStarted;
        size_t actualDecoded = 0;
        worker.decodedScratch = static_cast<uint8_t*>(
            ampr_internal_amm_pool_alloc(
                decodedBytes, &actualDecoded,
                "apr.pack.worker.decoded", false, 64u));
        if (!worker.decodedScratch || actualDecoded < decodedBytes) {
            if (worker.decodedScratch) {
                (void)ampr_internal_amm_pool_free(
                    worker.decodedScratch, "apr.pack.worker.decoded.fail");
            }
            worker = {};
            continue;
        }
        worker.decodedScratchSize = decodedBytes;
        const int createRc = scePthreadCreate(
            &worker.thread, nullptr, pack_worker_entry, &worker,
            "ampr_pack_worker");
        if (createRc != 0) {
            (void)ampr_internal_amm_pool_free(
                worker.decodedScratch, "apr.pack.worker.decoded.create-fail");
            worker = {};
            continue;
        }
        worker.started = true;
        ++state.workersStarted;
        state.profileStartedWorkers.store(state.workersStarted, std::memory_order_release);
        state.workerCapacity = (std::max)(
            state.workerCapacity, state.workersStarted);
    }
    if (state.workersStarted == 0) {
        AMPR_CRITICAL_LOGF("apr.pack.worker.start.fail requested=%u",
                           (unsigned)AMPR_EMU_PACK_WORKERS);
        return false;
    }
    AMPR_LOGF("apr.pack.worker.start count=%u pipelines=%u latencyReserve=%u pipelineWindow=0x%llx decodedPerWorker=0x%llx",
              state.workersStarted,
              state.pipelineCapacity,
              (unsigned)effective_latency_reserve_locked(state),
              (unsigned long long)kPackPipelineIoBytes,
              (unsigned long long)decodedBytes);
    return true;
}

static void reset_virtual_aio_slot(VirtualAioSlot& slot,
                                   uint16_t generation,
                                   VirtualAioPhase phase) {
    slot.request = {};
    slot.fileId = 0;
    slot.next = kInvalidIndex;
    slot.pipelineIndex = kInvalidIndex;
    slot.generation = generation;
    slot.priority = 0;
    slot.workClass = PackWorkClass::Balanced;
    slot.processOrigin = false;
    slot.waitNotified = false;
#if AMPR_EMU_PACK_TELEMETRY
    slot.queuedAtUsec = 0;
    slot.admittedAtUsec = 0;
#endif
    slot.phase = phase;
    slot.cancelRequested.store(false, std::memory_order_relaxed);
    slot.completionState = 0;
    slot.returnValue = 0;
}

static uint32_t allocate_virtual_aio_locked(PackState& state) {
    for (uint32_t n = 0; n < AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS; ++n) {
        const uint32_t index = (state.virtualAioCursor + n) %
                               AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS;
        VirtualAioSlot& slot = state.virtualAio[index];
        if (slot.phase == VirtualAioPhase::Free) {
            const uint16_t generation = static_cast<uint16_t>(
                next_generation(slot.generation));
            reset_virtual_aio_slot(slot, generation,
                                   VirtualAioPhase::Reserved);
            state.virtualAioCursor = (index + 1u) %
                                     AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS;
            return index;
        }
    }
    return kInvalidIndex;
}

static void free_virtual_aio_locked(PackState& state, uint32_t index) {
    if (index >= AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS) return;
    VirtualAioSlot& slot = state.virtualAio[index];
    release_pipeline_locked(state, index);
    const uint16_t generation = slot.generation;
    reset_virtual_aio_slot(slot, generation, VirtualAioPhase::Free);
}

static VirtualAioSlot* lookup_virtual_aio_locked(PackState& state,
                                                  SceKernelAioSubmitId id,
                                                  uint32_t* outIndex = nullptr) {
    uint32_t index = 0;
    uint16_t generation = 0;
    if (!decode_virtual_aio(id, &index, &generation)) return nullptr;
    VirtualAioSlot& slot = state.virtualAio[index];
    if (slot.phase == VirtualAioPhase::Free || slot.generation != generation) {
        return nullptr;
    }
    if (outIndex) *outIndex = index;
    return &slot;
}

static uint32_t allocate_virtual_aio_group_locked(PackState& state) {
    for (uint32_t n = 0; n < AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS; ++n) {
        const uint32_t index =
            (state.virtualAioGroupCursor + n) %
            AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS;
        VirtualAioGroupSlot& slot = state.virtualAioGroups[index];
        if (slot.active) continue;
        const uint16_t generation = static_cast<uint16_t>(
            next_generation(slot.generation));
        slot = {};
        slot.generation = generation;
        slot.active = true;
        state.virtualAioGroupCursor =
            (index + 1u) % AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS;
        return index;
    }
    return kInvalidIndex;
}

static void free_virtual_aio_group_locked(PackState& state,
                                          uint32_t index) {
    if (index >= AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS) return;
    VirtualAioGroupSlot& slot = state.virtualAioGroups[index];
    const uint16_t generation = slot.generation;
    slot = {};
    slot.generation = generation;
}

static VirtualAioGroupSlot* lookup_virtual_aio_group_locked(
    PackState& state,
    SceKernelAioSubmitId id,
    uint32_t* outIndex = nullptr) {
    uint32_t index = 0;
    uint16_t generation = 0;
    if (!decode_virtual_aio_group(id, &index, &generation)) return nullptr;
    VirtualAioGroupSlot& slot = state.virtualAioGroups[index];
    if (!slot.active || slot.generation != generation) return nullptr;
    if (outIndex) *outIndex = index;
    return &slot;
}

[[maybe_unused]] static VirtualFdSlot* lookup_virtual_fd_locked(PackState& state,
                                                int fd,
                                                uint32_t* outIndex = nullptr) {
    uint32_t index = 0;
    uint16_t generation = 0;
    if (!decode_virtual_fd(fd, &index, &generation)) return nullptr;
    VirtualFdSlot& slot = state.virtualFds[index];
    if (!slot.active || slot.generation != generation) return nullptr;
    if (outIndex) *outIndex = index;
    return &slot;
}

static uint32_t allocate_virtual_fd_locked(PackState& state, uint32_t fileId) {
    for (uint32_t n = 0; n < AMPR_EMU_PACK_VIRTUAL_FD_SLOTS; ++n) {
        const uint32_t index = (state.virtualFdCursor + n) %
                               AMPR_EMU_PACK_VIRTUAL_FD_SLOTS;
        VirtualFdSlot& slot = state.virtualFds[index];
        if (!slot.active) {
            slot.generation = static_cast<uint16_t>(
                next_generation(slot.generation));
            slot.fileId = fileId;
            slot.cursor = 0;
            slot.processOpen = false;
            slot.active = true;
            state.virtualFdCursor = (index + 1u) %
                                    AMPR_EMU_PACK_VIRTUAL_FD_SLOTS;
            return index;
        }
    }
    return kInvalidIndex;
}

static AmprPackRuntimeStats collect_stats(AtomicPackStats& source, bool reset) {
    AmprPackRuntimeStats result{};
#define AMPR_PACK_STAT(field) \
    result.field = reset ? source.field.exchange(0, std::memory_order_acq_rel) \
                         : source.field.load(std::memory_order_acquire)
    AMPR_PACK_STAT(virtualOpens);
    AMPR_PACK_STAT(deliveredBytes);
    AMPR_PACK_STAT(logicalFailures);
    for (uint32_t i = 0; i < 32; ++i) {
        AMPR_PACK_STAT(logicalLatency[i]);
        AMPR_PACK_STAT(latencyClassLatency[i]);
        AMPR_PACK_STAT(physicalLatency[i]);
        AMPR_PACK_STAT(queueLatency[i]);
        AMPR_PACK_STAT(workerLatency[i]);
    }
    AMPR_PACK_STAT(aioSubmitted);
    AMPR_PACK_STAT(aioCompleted);
    AMPR_PACK_STAT(logicalBytes);
    AMPR_PACK_STAT(physicalBytes);
    AMPR_PACK_STAT(physicalReadOps);
    AMPR_PACK_STAT(physicalReadSamples);
    AMPR_PACK_STAT(physicalReadUsecTotal);
    AMPR_PACK_STAT(physicalReadUsecMax);
    AMPR_PACK_STAT(physicalReadSlow1ms);
    AMPR_PACK_STAT(physicalReadSlow5ms);
    AMPR_PACK_STAT(physicalReadSlow20ms);
    AMPR_PACK_STAT(physicalReadLe64K);
    AMPR_PACK_STAT(physicalReadLe512K);
    AMPR_PACK_STAT(physicalReadGt512K);
    result.physicalReadsInFlight = source.physicalReadsInFlight.load(
        std::memory_order_acquire);
    result.physicalReadsInFlightPeak = reset
        ? source.physicalReadsInFlightPeak.exchange(
              result.physicalReadsInFlight, std::memory_order_acq_rel)
        : source.physicalReadsInFlightPeak.load(std::memory_order_acquire);
    result.physicalReadsInFlightPeak = (std::max)(
        result.physicalReadsInFlightPeak,
        result.physicalReadsInFlight);
    update_atomic_peak(
        source.physicalReadsInFlightPeak,
        source.physicalReadsInFlight.load(std::memory_order_acquire));
    AMPR_PACK_STAT(backingAioSubmitBatches);
    AMPR_PACK_STAT(backingAioSubmitRequests);
    AMPR_PACK_STAT(backingAioSubmitEagain);
    AMPR_PACK_STAT(backingAioSubmitFailures);
    AMPR_PACK_STAT(backingAioPollFailures);
    AMPR_PACK_STAT(backingAioDeleteFailures);
    result.pipelineContextsActive = source.pipelineContextsActive.load(
        std::memory_order_acquire);
    result.pipelineContextsActivePeak = reset
        ? source.pipelineContextsActivePeak.exchange(
              result.pipelineContextsActive, std::memory_order_acq_rel)
        : source.pipelineContextsActivePeak.load(std::memory_order_acquire);
    result.pipelineContextsActivePeak = (std::max)(
        result.pipelineContextsActivePeak,
        result.pipelineContextsActive);
    update_atomic_peak(
        source.pipelineContextsActivePeak,
        source.pipelineContextsActive.load(std::memory_order_acquire));
    AMPR_PACK_STAT(pipelineIoYields);
    AMPR_PACK_STAT(pipelineCacheYields);
    AMPR_PACK_STAT(pipelineFdYields);
    AMPR_PACK_STAT(physicalWindowHits);
    AMPR_PACK_STAT(physicalPageHits);
    AMPR_PACK_STAT(physicalPageMisses);
    AMPR_PACK_STAT(physicalPageLoadingJoins);
    AMPR_PACK_STAT(physicalPageAdmissions);
    AMPR_PACK_STAT(physicalPageEvictions);
    AMPR_PACK_STAT(physicalPageBypasses);
    AMPR_PACK_STAT(physicalCacheDirectReadWindows);
    AMPR_PACK_STAT(physicalCacheDirectReadyWindows);
    AMPR_PACK_STAT(physicalCacheScratchWindows);
    AMPR_PACK_STAT(physicalCacheCopyBytesAvoided);
    AMPR_PACK_STAT(inlineCacheCompletions);
    AMPR_PACK_STAT(latencyJobsSubmitted);
    AMPR_PACK_STAT(balancedJobsSubmitted);
    AMPR_PACK_STAT(bulkJobsSubmitted);
    AMPR_PACK_STAT(latencyWorkerDispatches);
    AMPR_PACK_STAT(queueDepthPeakLatency);
    AMPR_PACK_STAT(queueDepthPeakBalanced);
    AMPR_PACK_STAT(queueDepthPeakBulk);
    AMPR_PACK_STAT(workerJobs);
    AMPR_PACK_STAT(workerJobUsecTotal);
    AMPR_PACK_STAT(workerJobUsecMax);
    result.workersBusy = source.workersBusy.load(std::memory_order_acquire);
    result.workersBusyPeak = reset
        ? source.workersBusyPeak.exchange(
              result.workersBusy, std::memory_order_acq_rel)
        : source.workersBusyPeak.load(std::memory_order_acquire);
    result.workersBusyPeak = (std::max)(
        result.workersBusyPeak, result.workersBusy);
    update_atomic_peak(
        source.workersBusyPeak,
        source.workersBusy.load(std::memory_order_acquire));
    AMPR_PACK_STAT(workerQueueWaitUsecTotal);
    AMPR_PACK_STAT(workerQueueWaitUsecMax);
    AMPR_PACK_STAT(workerQueueWaitSlow1ms);
    AMPR_PACK_STAT(workerQueueWaitSlow5ms);
    AMPR_PACK_STAT(workerQueueWaitSlow20ms);
    AMPR_PACK_STAT(storedBytesConsumed);
    AMPR_PACK_STAT(lz4DecodedBytes);
    AMPR_PACK_STAT(rawBytes);
    AMPR_PACK_STAT(cacheHits);
    AMPR_PACK_STAT(cacheMisses);
    AMPR_PACK_STAT(cacheLoadingJoins);
    AMPR_PACK_STAT(cacheAdmissions);
    AMPR_PACK_STAT(cacheEvictions);
    AMPR_PACK_STAT(ioFailures);
    AMPR_PACK_STAT(processVirtualOpens);
    AMPR_PACK_STAT(directoryOpens);
    AMPR_PACK_STAT(directoryHybridOpens);
    AMPR_PACK_STAT(directoryVirtualOpens);
    AMPR_PACK_STAT(directoryGetdentsCalls);
    AMPR_PACK_STAT(directoryPhysicalEntries);
    AMPR_PACK_STAT(directoryVirtualEntries);
    AMPR_PACK_STAT(directoryDuplicateEntries);
    AMPR_PACK_STAT(directoryHiddenEntries);
    AMPR_PACK_STAT(syntheticFileStats);
    AMPR_PACK_STAT(syntheticDirectoryStats);
    AMPR_PACK_STAT(syntheticReachability);
    AMPR_PACK_STAT(synchronousPreads);
    AMPR_PACK_STAT(synchronousReads);
    AMPR_PACK_STAT(synchronousLseeks);
#undef AMPR_PACK_STAT
    return result;
}
} // namespace

void ampr_pack_notify_fd_budget_progress() {
#if AMPR_EMU_PACK_ENABLE
    if (PackState* state = g_pack_state.load(std::memory_order_acquire)) {
        state->queueCv.notify_all();
    }
#endif
}

bool ampr_pack_ensure_manifest_ready_safe() {
    return ensure_manifest_ready();
}

bool ampr_pack_manifest_is_resident_ready() {
#if !AMPR_EMU_PACK_ENABLE
    return false;
#else
    PackState* state = g_pack_state.load(std::memory_order_acquire);
    return state && state->loadState.load(std::memory_order_acquire) ==
                        kPackLoadReady;
#endif
}

bool ampr_pack_manifest_is_absent() {
#if !AMPR_EMU_PACK_ENABLE
    return true;
#else
    PackState* state = g_pack_state.load(std::memory_order_acquire);
    return state && state->loadState.load(std::memory_order_acquire) ==
                        kPackLoadUnavailable;
#endif
}

static bool pack_open_flags_supported(int flags) {
    return (flags & O_ACCMODE) == O_RDONLY &&
           (flags & O_DIRECTORY) == 0 &&
           (AMPR_EMU_PACK_INTERCEPT_ALL_READ_ONLY != 0 ||
            (flags & O_NONBLOCK) != 0);
}

static int ampr_pack_try_open_indexed_impl(uint32_t fileId,
                                           const FileEntryView& entry,
                                           int flags,
                                           SceKernelMode mode,
                                           bool processOrigin,
                                           bool* handled) {
    (void)mode;
    if (handled) *handled = false;
#if !AMPR_EMU_PACK_ENABLE
    (void)fileId;
    (void)entry;
    (void)flags;
    (void)processOrigin;
    return SCE_KERNEL_ERROR_ENOENT;
#else
    if (!handled || fileId == 0 || !entry.path) {
        return SCE_KERNEL_ERROR_ENOENT;
    }
    if (processOrigin) {
        // Process hooks may run while libkernel owns a nonsleeping lock. The
        // safe index publication path must already have finished manifest
        // loading; never cold-load or wait here, and never fall through to the
        // physical file when pack membership is unknown.
        if (!ampr_pack_manifest_is_resident_ready()) {
            if (ampr_pack_manifest_is_absent()) {
#if AMPR_EMU_PACK_IO_LOG
                AMPR_TLOGF("apr.pack.open.skip logical=%s fileId=%u reason=manifest-absent origin=process",
                           entry.path, fileId);
#endif
                return SCE_KERNEL_ERROR_ENOENT;
            }
            *handled = true;
#if AMPR_EMU_PACK_IO_LOG
            AMPR_CRITICAL_LOGF("apr.pack.open.fail logical=%s fileId=%u reason=manifest-not-ready origin=process",
                               entry.path, fileId);
#endif
            return SCE_KERNEL_ERROR_EIO;
        }
    } else if (!ensure_manifest_ready()) {
        return SCE_KERNEL_ERROR_ENOENT;
    }
    PackState& state = pack_state();
    const int validateRc = ampr_pack_core_validate_logical_file(
        state.coreView, fileId, entry.path, entry.pathLength, entry.size);
    if (validateRc != kAmprPackCoreOk) {
        *handled = true;
#if AMPR_EMU_PACK_IO_LOG
        AMPR_CRITICAL_LOGF("apr.pack.open.fail logical=%s fileId=%u size=0x%llx reason=manifest-mismatch coreRc=%d origin=%s",
                           entry.path, fileId,
                           (unsigned long long)entry.size, validateRc,
                           processOrigin ? "process" : "indexed");
#endif
        return SCE_KERNEL_ERROR_EIO;
    }
    const AmprPackFileRecord& record = state.files[fileId - 1u];
    if ((record.flags & kAmprPackFilePacked) == 0) {
#if AMPR_EMU_PACK_IO_LOG
        AMPR_TLOGF("apr.pack.open.skip logical=%s fileId=%u size=0x%llx reason=manifest-loose origin=%s",
                   entry.path, fileId,
                   (unsigned long long)record.logicalSize,
                   processOrigin ? "process" : "indexed");
#endif
        return SCE_KERNEL_ERROR_ENOENT;
    }
    *handled = true;
    if (!pack_open_flags_supported(flags)) {
#if AMPR_EMU_PACK_IO_LOG
        AMPR_LOGF("apr.pack.open.fail logical=%s fileId=%u flags=0x%x reason=unsupported-open-flags origin=%s",
                  entry.path, fileId, flags,
                  processOrigin ? "process" : "indexed");
#endif
        return ampr_sce_errno_from_posix(EACCES);
    }
    if (processOrigin && !amprPackProcessOpenHooksReady()) {
#if AMPR_EMU_PACK_IO_LOG
        AMPR_CRITICAL_LOGF("apr.pack.open.fail logical=%s fileId=%u reason=process-fd-hooks-not-ready origin=process",
                           entry.path, fileId);
#endif
        return SCE_KERNEL_ERROR_EIO;
    }
    AmprLockGuard lock(state.m);
    const uint32_t slot = allocate_virtual_fd_locked(state, fileId);
    if (slot == kInvalidIndex) return SCE_KERNEL_ERROR_EMFILE;
    state.virtualFds[slot].processOpen = processOrigin;
    state.stats.virtualOpens.fetch_add(1, std::memory_order_relaxed);
    if (processOrigin) {
        state.stats.processVirtualOpens.fetch_add(1, std::memory_order_relaxed);
    }
    const int virtualFd = encode_virtual_fd(
        slot, state.virtualFds[slot].generation);
#if AMPR_EMU_PACK_IO_LOG
    [[maybe_unused]] uint16_t firstPack = UINT16_MAX;
    [[maybe_unused]] uint8_t firstCodec = 0xffu;
    if (record.chunkCount != 0 && record.firstChunk < state.header->chunkCount) {
        firstPack = ampr_pack_chunk_pack_id(state.chunks[record.firstChunk]);
        firstCodec = ampr_pack_chunk_codec(state.chunks[record.firstChunk]);
    }
    AMPR_LOGF("apr.pack.open logical=%s fileId=%u vfd=0x%x size=0x%llx chunks=%u firstPack=%u firstCodec=%u origin=%s",
              entry.path, fileId, (unsigned)virtualFd,
              (unsigned long long)record.logicalSize, record.chunkCount,
              (unsigned)firstPack, (unsigned)firstCodec,
              processOrigin ? "process" : "indexed");
#endif
    return virtualFd;
#endif
}

int ampr_pack_try_open_indexed(uint32_t fileId,
                               const FileEntryView& entry,
                               int flags,
                               SceKernelMode mode,
                               bool* handled) {
    return ampr_pack_try_open_indexed_impl(
        fileId, entry, flags, mode, false, handled);
}

int ampr_pack_try_process_open_indexed(uint32_t fileId,
                                       const FileEntryView& entry,
                                       int flags,
                                       SceKernelMode mode,
                                       bool* handled) {
    return ampr_pack_try_open_indexed_impl(
        fileId, entry, flags, mode, true, handled);
}

__attribute__((noinline)) int ampr_pack_try_open(const char* path,
                                                 int flags,
                                                 SceKernelMode mode,
                                                 bool* handled) {
    if (handled) *handled = false;
#if !AMPR_EMU_PACK_ENABLE
    (void)path;
    (void)flags;
    (void)mode;
    return SCE_KERNEL_ERROR_ENOENT;
#else
    if (!path || !handled || !pack_open_flags_supported(flags)) {
        return SCE_KERNEL_ERROR_ENOENT;
    }
    uint32_t fileId = 0;
    size_t indexedSize = 0;
    if (ampr_index_resolve_path_to_id(path, &fileId, &indexedSize) != 0) {
        return SCE_KERNEL_ERROR_ENOENT;
    }
    FileEntryView entry{};
    if (ampr_index_get_entry_view(fileId, &entry) != 0 ||
        entry.size != indexedSize) {
        return SCE_KERNEL_ERROR_EIO;
    }
    return ampr_pack_try_open_indexed_impl(
        fileId, entry, flags, mode, true, handled);
#endif
}

static uint32_t allocate_virtual_directory_locked(
    PackState& state, const char* path, uint16_t pathLength, int realFd,
    uint32_t rangeBegin, uint32_t rangeEnd) {
    // Prefer an immediately available slot. Only wait on slot mutexes when
    // the first pass found none, so temporary contention is not EMFILE.
    for (unsigned pass = 0; pass < 2; ++pass) {
        for (uint32_t n = 0; n < AMPR_EMU_PACK_VIRTUAL_DIRECTORY_SLOTS; ++n) {
            const uint32_t index = (state.virtualDirectoryCursor + n) %
                                   AMPR_EMU_PACK_VIRTUAL_DIRECTORY_SLOTS;
            if (pass == 0) {
                if (!state.directoryMutexes[index].try_lock()) continue;
            } else {
                state.directoryMutexes[index].lock();
            }
            VirtualDirectorySlot& slot = state.virtualDirectories[index];
            if (slot.active) {
                state.directoryMutexes[index].unlock();
                continue;
            }
            const uint16_t generation = static_cast<uint16_t>(
                next_generation(slot.generation));
            slot = {};
            slot.realFd = realFd;
            slot.generation = generation;
            slot.active = true;
            slot.rangeBegin = rangeBegin;
            slot.rangeEnd = rangeEnd;
            slot.virtualCursor = rangeBegin;
            slot.pathLength = pathLength;
            std::memcpy(slot.path, path, pathLength);
            slot.path[pathLength] = '\0';
            state.virtualDirectoryCursor = (index + 1u) %
                                           AMPR_EMU_PACK_VIRTUAL_DIRECTORY_SLOTS;
            state.directoryMutexes[index].unlock();
            return index;
        }
    }
    return kInvalidIndex;
}

static bool directory_physical_name_seen(const VirtualDirectorySlot& slot,
                                         const char* name,
                                         size_t nameLength) {
    const uint64_t hash = folded_hash(name, nameLength);
    for (uint32_t i = 0; i < slot.physicalHashCount; ++i) {
        if (slot.physicalNameHashes[i] == hash) return true;
    }
    return false;
}

static void directory_record_physical_name(VirtualDirectorySlot& slot,
                                           const char* name,
                                           size_t nameLength) {
    if (directory_physical_name_seen(slot, name, nameLength)) return;
    if (slot.physicalHashCount < kDirectoryPhysicalHashCap) {
        slot.physicalNameHashes[slot.physicalHashCount++] =
            folded_hash(name, nameLength);
    } else {
        slot.physicalHashOverflow = true;
    }
}

static bool next_virtual_child(const PackState& state,
                               const VirtualDirectorySlot& slot,
                               uint32_t cursor, char* name,
                               uint8_t* nameLength, uint8_t* type,
                               uint32_t* nextCursor) {
    if (nextCursor) *nextCursor = cursor;
    if (!name || !nameLength || !type || cursor >= slot.rangeEnd) return false;
    const uint32_t fileIndex = state.packedFileOrder[cursor];
    const AmprPackFileRecord& file = state.files[fileIndex];
    const char* path = file_record_path(state, fileIndex);
    if (!path || file.pathLength <= slot.pathLength) return false;
    size_t relative = slot.pathLength;
    if (path[relative] == '/') ++relative;
    if (relative >= file.pathLength) return false;
    size_t end = relative;
    while (end < file.pathLength && path[end] != '/') ++end;
    const size_t childLength = end - relative;
    if (childLength == 0 || childLength > 255u) return false;
    std::memcpy(name, path + relative, childLength);
    name[childLength] = '\0';
    *nameLength = static_cast<uint8_t>(childLength);
    *type = end < file.pathLength ? DT_DIR : DT_REG;

    uint32_t groupEnd = cursor + 1u;
    while (groupEnd < slot.rangeEnd) {
        const uint32_t otherIndex = state.packedFileOrder[groupEnd];
        const AmprPackFileRecord& other = state.files[otherIndex];
        const char* otherPath = file_record_path(state, otherIndex);
        if (!otherPath || other.pathLength <= slot.pathLength) break;
        size_t otherRelative = slot.pathLength;
        if (otherPath[otherRelative] == '/') ++otherRelative;
        size_t otherEnd = otherRelative;
        while (otherEnd < other.pathLength && otherPath[otherEnd] != '/') {
            ++otherEnd;
        }
        const size_t otherLength = otherEnd - otherRelative;
        if (!folded_equal(name, childLength,
                          otherPath + otherRelative, otherLength)) {
            break;
        }
        if (otherEnd < other.pathLength) *type = DT_DIR;
        ++groupEnd;
    }
    if (nextCursor) *nextCursor = groupEnd;
    return true;
}

static size_t synthetic_dirent_size(size_t nameLength) {
    const size_t base = offsetof(struct dirent, d_name);
    return align_up_size(base + nameLength + 1u, 4u);
}

static int emit_synthetic_dirent(char* buffer, int capacity, const char* name,
                                 uint8_t nameLength, uint8_t type,
                                 uint64_t inodeSeed) {
    const size_t recordSize = synthetic_dirent_size(nameLength);
    if (!buffer || capacity < 0 || recordSize == SIZE_MAX ||
        recordSize > static_cast<size_t>(capacity) || recordSize > UINT16_MAX) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    std::memset(buffer, 0, recordSize);
    auto* entry = reinterpret_cast<struct dirent*>(buffer);
    entry->d_fileno = static_cast<uint32_t>((inodeSeed & 0x7fffffffu) | 1u);
    entry->d_reclen = static_cast<uint16_t>(recordSize);
    entry->d_type = type;
    entry->d_namlen = nameLength;
    std::memcpy(entry->d_name, name, nameLength);
    entry->d_name[nameLength] = '\0';
    return static_cast<int>(recordSize);
}

static int open_failure_errno(int rc) {
    if (rc >= 0) return 0;
    if (rc == -1) return errno;
    // Host tests and a few compatibility shims use the conventional -errno
    // form, whereas Prospero libkernel uses 0x8002xxxx SCE error values.
    if (rc > -256) return -rc;
    return ampr_posix_errno_from_sce(rc);
}

__attribute__((noinline)) static int ampr_pack_open_directory_impl(
    const char* path, int flags, SceKernelMode mode, bool allowPhysicalOpen,
    bool* handled) {
    if (handled) *handled = false;
#if !AMPR_EMU_PACK_ENABLE || !AMPR_EMU_PACK_DIRECTORY_OVERLAY_ENABLE
    (void)path; (void)flags; (void)mode; (void)allowPhysicalOpen;
    return SCE_KERNEL_ERROR_ENOENT;
#else
    if (!path || !handled || (flags & O_DIRECTORY) == 0) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    int realFd = -1;
    if (allowPhysicalOpen) {
        KernelOpenFn openFn = real_open();
        if (!openFn) return SCE_KERNEL_ERROR_EIO;
        realFd = openFn(path, flags, mode);
        *handled = true;
    }

    // Directory overlay is read-only. Never turn an access/permission error,
    // an invalid flag combination, or a writable directory request into a
    // synthetic success merely because a matching packed descendant exists.
    if (allowPhysicalOpen && (flags & O_ACCMODE) != O_RDONLY) return realFd;
    if (allowPhysicalOpen && realFd < 0) {
        const int openErrno = open_failure_errno(realFd);
        if (openErrno != ENOENT && openErrno != ENOTDIR) return realFd;
    }

    char normalized[SCE_KERNEL_PATH_MAX]{};
    uint16_t normalizedLength = 0;
    uint32_t rangeBegin = 0;
    uint32_t rangeEnd = 0;
    if (!normalize_overlay_path(path, normalized, sizeof(normalized),
                                &normalizedLength)) {
        return allowPhysicalOpen ? realFd : SCE_KERNEL_ERROR_ENOENT;
    }
    const bool manifestReady = allowPhysicalOpen
        ? ensure_manifest_ready()
        : ampr_pack_manifest_is_resident_ready();
    if (!manifestReady) {
        return allowPhysicalOpen ? realFd : SCE_KERNEL_ERROR_ENOENT;
    }
    PackState& state = pack_state();
    if (!find_virtual_directory_range(
            state, normalized, normalizedLength, &rangeBegin, &rangeEnd)) {
        return allowPhysicalOpen ? realFd : SCE_KERNEL_ERROR_ENOENT;
    }
    *handled = true;
    if ((flags & O_ACCMODE) != O_RDONLY) {
        return ampr_sce_errno_from_posix(EACCES);
    }

    AmprLockGuard lock(state.directoryTableMutex);
    if (state.workerStopRequested.load(std::memory_order_acquire)) {
        if (realFd >= 0) {
            KernelCloseFn closeFn = real_close();
            if (closeFn) (void)closeFn(realFd);
        }
        return SCE_KERNEL_ERROR_EBADF;
    }
    const uint32_t slot = allocate_virtual_directory_locked(
        state, normalized, normalizedLength, realFd, rangeBegin, rangeEnd);
    if (slot == kInvalidIndex) {
        if (realFd >= 0) {
            KernelCloseFn closeFn = real_close();
            if (closeFn) (void)closeFn(realFd);
        }
        return SCE_KERNEL_ERROR_EMFILE;
    }
    const int fd = encode_virtual_directory_fd(
        slot, state.virtualDirectories[slot].generation);
    state.stats.directoryOpens.fetch_add(1, std::memory_order_relaxed);
    if (realFd >= 0) {
        state.stats.directoryHybridOpens.fetch_add(1, std::memory_order_relaxed);
    } else {
        state.stats.directoryVirtualOpens.fetch_add(1, std::memory_order_relaxed);
    }
#if AMPR_EMU_PACK_IO_LOG
    AMPR_LOGF("apr.pack.dir.open path=%s vfd=0x%x realFd=%d mode=%s range=%u..%u",
              normalized, (unsigned)fd, realFd,
              realFd >= 0 ? "hybrid" : "virtual", rangeBegin, rangeEnd);
#endif
    return fd;
#endif
}

int ampr_pack_open_directory(const char* path, int flags, SceKernelMode mode,
                             bool* handled) {
    return ampr_pack_open_directory_impl(path, flags, mode, true, handled);
}

int ampr_pack_open_virtual_directory(const char* path, int flags,
                                     SceKernelMode mode, bool* handled) {
    return ampr_pack_open_directory_impl(path, flags, mode, false, handled);
}

__attribute__((noinline)) int ampr_pack_try_stat_path(
    const char* path, SceKernelStat* stat, bool* handled) {
    if (handled) *handled = false;
#if !AMPR_EMU_PACK_ENABLE || !AMPR_EMU_PACK_DIRECTORY_OVERLAY_ENABLE
    (void)path; (void)stat;
    return SCE_KERNEL_ERROR_ENOENT;
#else
    if (!path || !stat || !handled || !ensure_manifest_ready()) {
        return SCE_KERNEL_ERROR_ENOENT;
    }
    PackState& state = pack_state();
    uint32_t fileId = 0;
    const AmprPackFileRecord* file = nullptr;
    if (resolve_packed_file(state, path, &fileId, &file)) {
        fill_synthetic_stat(stat, false, file->logicalSize, file->mtime,
                            file->pathHash ^ fileId);
        *handled = true;
        state.stats.syntheticFileStats.fetch_add(1, std::memory_order_relaxed);
#if AMPR_EMU_PACK_IO_LOG
        AMPR_LOGF("apr.pack.stat.synthetic type=file path=%s fileId=%u size=0x%llx",
                  path, fileId, (unsigned long long)file->logicalSize);
#endif
        return 0;
    }
    char normalized[SCE_KERNEL_PATH_MAX]{};
    uint16_t length = 0;
    uint32_t begin = 0;
    uint32_t end = 0;
    if (normalize_overlay_path(path, normalized, sizeof(normalized), &length) &&
        find_virtual_directory_range(state, normalized, length, &begin, &end)) {
        fill_synthetic_stat(stat, true, 0, 0, folded_hash(normalized, length));
        *handled = true;
        state.stats.syntheticDirectoryStats.fetch_add(
            1, std::memory_order_relaxed);
#if AMPR_EMU_PACK_IO_LOG
        AMPR_LOGF("apr.pack.stat.synthetic type=directory path=%s range=%u..%u",
                  normalized, begin, end);
#endif
        return 0;
    }
    return SCE_KERNEL_ERROR_ENOENT;
#endif
}

__attribute__((noinline)) int ampr_pack_try_reachability(const char* path,
                                                          bool* handled) {
    if (handled) *handled = false;
    SceKernelStat stat{};
    const int rc = ampr_pack_try_stat_path(path, &stat, handled);
    if (handled && *handled) {
        pack_state().stats.syntheticReachability.fetch_add(
            1, std::memory_order_relaxed);
    }
    return rc;
}

bool ampr_pack_is_virtual_directory_fd(int fd) {
#if !AMPR_EMU_PACK_ENABLE || !AMPR_EMU_PACK_DIRECTORY_OVERLAY_ENABLE
    (void)fd;
    return false;
#else
    uint32_t slot = 0;
    uint16_t generation = 0;
    if (!decode_virtual_directory_fd(fd, &slot, &generation)) return false;
    PackState& state = pack_state();
    AmprLockGuard lock(state.directoryMutexes[slot]);
    return state.virtualDirectories[slot].active &&
           state.virtualDirectories[slot].generation == generation;
#endif
}

int ampr_pack_try_close_fd(int fd, bool* handled) {
    if (handled) *handled = false;
#if !AMPR_EMU_PACK_ENABLE
    (void)fd;
    return SCE_KERNEL_ERROR_EBADF;
#else
    PackState& state = pack_state();
    uint32_t index = 0;
    uint16_t generation = 0;
    if (decode_virtual_directory_fd(fd, &index, &generation)) {
        if (handled) *handled = true;
        int realFd = -1;
        char path[SCE_KERNEL_PATH_MAX]{};
        {
            AmprLockGuard lock(state.directoryMutexes[index]);
            if (state.workerStopRequested.load(std::memory_order_acquire)) {
                return SCE_KERNEL_ERROR_EBADF;
            }
            VirtualDirectorySlot& slot = state.virtualDirectories[index];
            if (!slot.active || slot.generation != generation) {
                return SCE_KERNEL_ERROR_EBADF;
            }
            realFd = slot.realFd;
            std::memcpy(path, slot.path, slot.pathLength + 1u);
            const uint16_t preservedGeneration = slot.generation;
            slot = {};
            slot.realFd = -1;
            slot.generation = preservedGeneration;
        }
#if AMPR_EMU_PACK_IO_LOG
        AMPR_LOGF("apr.pack.dir.close path=%s vfd=0x%x realFd=%d",
                  path, (unsigned)fd, realFd);
#endif
        if (realFd < 0) return 0;
        KernelCloseFn closeFn = real_close();
        if (!closeFn) return SCE_KERNEL_ERROR_EIO;
        const int rc = closeFn(realFd);
        return rc == -1 ? ampr_sce_errno_from_posix(errno) : rc;
    }
    if (decode_virtual_fd(fd, &index, &generation)) {
        if (handled) *handled = true;
        AmprLockGuard descriptorLock(state.virtualFdMutexes[index]);
        if (state.workerStopRequested.load(std::memory_order_acquire)) {
            return SCE_KERNEL_ERROR_EBADF;
        }
        AmprLockGuard lock(state.m);
        VirtualFdSlot& slot = state.virtualFds[index];
        if (!slot.active || slot.generation != generation) {
            return SCE_KERNEL_ERROR_EBADF;
        }
#if AMPR_EMU_PACK_IO_LOG
        AMPR_LOGF("apr.pack.close fileId=%u vfd=0x%x cursor=0x%llx process=%u",
                  slot.fileId, (unsigned)fd,
                  (unsigned long long)slot.cursor,
                  slot.processOpen ? 1u : 0u);
#endif
        slot.active = false;
        slot.fileId = 0;
        slot.cursor = 0;
        slot.processOpen = false;
        return 0;
    }
    return SCE_KERNEL_ERROR_EBADF;
#endif
}

int ampr_pack_try_fstat_fd(int fd, SceKernelStat* stat, bool* handled) {
    if (handled) *handled = false;
#if !AMPR_EMU_PACK_ENABLE
    (void)fd; (void)stat;
    return SCE_KERNEL_ERROR_EBADF;
#else
    if (!stat) return SCE_KERNEL_ERROR_EFAULT;
    PackState& state = pack_state();
    uint32_t index = 0;
    uint16_t generation = 0;
    if (decode_virtual_directory_fd(fd, &index, &generation)) {
        if (handled) *handled = true;
        AmprLockGuard lock(state.directoryMutexes[index]);
        if (state.workerStopRequested.load(std::memory_order_acquire)) {
            return SCE_KERNEL_ERROR_EBADF;
        }
        const VirtualDirectorySlot& slot = state.virtualDirectories[index];
        if (!slot.active || slot.generation != generation) {
            return SCE_KERNEL_ERROR_EBADF;
        }
        fill_synthetic_stat(stat, true, 0, 0,
                            folded_hash(slot.path, slot.pathLength));
        return 0;
    }
    if (decode_virtual_fd(fd, &index, &generation)) {
        if (handled) *handled = true;
        AmprLockGuard lock(state.m);
        const VirtualFdSlot& slot = state.virtualFds[index];
        if (!slot.active || slot.generation != generation || !state.header ||
            slot.fileId == 0 || slot.fileId > state.header->fileCount) {
            return SCE_KERNEL_ERROR_EBADF;
        }
        const AmprPackFileRecord& file = state.files[slot.fileId - 1u];
        fill_synthetic_stat(stat, false, file.logicalSize, file.mtime,
                            file.pathHash ^ slot.fileId);
        return 0;
    }
    return SCE_KERNEL_ERROR_EBADF;
#endif
}

static long advance_directory_offset(long base, int bytes) {
    if (bytes <= 0) return base;
    const long amount = static_cast<long>(bytes);
    if (base > (std::numeric_limits<long>::max)() - amount) {
        return (std::numeric_limits<long>::max)();
    }
    return base + amount;
}

static int ampr_pack_try_directory_read_fd(int fd, char* buffer, int size,
                                           long* basep,
                                           bool useGetdirentries,
                                           bool* handled) {
    if (handled) *handled = false;
#if !AMPR_EMU_PACK_ENABLE || !AMPR_EMU_PACK_DIRECTORY_OVERLAY_ENABLE
    (void)fd; (void)buffer; (void)size; (void)basep;
    (void)useGetdirentries;
    return SCE_KERNEL_ERROR_EBADF;
#else
    uint32_t index = 0;
    uint16_t generation = 0;
    if (!decode_virtual_directory_fd(fd, &index, &generation)) {
        return SCE_KERNEL_ERROR_EBADF;
    }
    if (handled) *handled = true;
    if (useGetdirentries && !basep) return SCE_KERNEL_ERROR_EFAULT;
    if (!buffer || size <= 0) return SCE_KERNEL_ERROR_EINVAL;
    PackState& state = pack_state();
    KernelGetdentsFn getdentsFn = real_getdents();
    KernelGetdirentriesFn getdirentriesFn = real_getdirentries();
    KernelStatFn statFn = real_stat();
    AmprLockGuard lock(state.directoryMutexes[index]);
    if (state.workerStopRequested.load(std::memory_order_acquire)) {
        return SCE_KERNEL_ERROR_EBADF;
    }
    VirtualDirectorySlot& slot = state.virtualDirectories[index];
    if (!slot.active || slot.generation != generation) {
        return SCE_KERNEL_ERROR_EBADF;
    }
    state.stats.directoryGetdentsCalls.fetch_add(1, std::memory_order_relaxed);

    while (!slot.realExhausted && slot.realFd >= 0) {
        long physicalBase = slot.directoryOffset;
        int rc = SCE_KERNEL_ERROR_EIO;
        if (useGetdirentries) {
            if (!getdirentriesFn) return SCE_KERNEL_ERROR_EIO;
            rc = getdirentriesFn(slot.realFd, buffer, size, &physicalBase);
        } else {
            if (!getdentsFn) return SCE_KERNEL_ERROR_EIO;
            rc = getdentsFn(slot.realFd, buffer, size);
        }
        if (rc < 0) return rc;
        if (useGetdirentries) {
            slot.directoryOffset = advance_directory_offset(physicalBase, rc);
        } else if (KernelLseekFn lseekFn = real_lseek()) {
            const off_t current = lseekFn(slot.realFd, 0, SEEK_CUR);
            if (current >= 0 &&
                static_cast<uint64_t>(current) <=
                    static_cast<uint64_t>((std::numeric_limits<long>::max)())) {
                slot.directoryOffset = static_cast<long>(current);
            } else {
                slot.directoryOffset = advance_directory_offset(
                    slot.directoryOffset, rc);
            }
        } else {
            slot.directoryOffset = advance_directory_offset(
                slot.directoryOffset, rc);
        }
        if (rc == 0) {
            slot.realExhausted = true;
            break;
        }
        size_t input = 0;
        size_t output = 0;
        while (input < static_cast<size_t>(rc)) {
            auto* entry = reinterpret_cast<struct dirent*>(buffer + input);
            const size_t recordSize = entry->d_reclen;
            if (recordSize < offsetof(struct dirent, d_name) + 1u ||
                recordSize > static_cast<size_t>(rc) - input ||
                static_cast<size_t>(entry->d_namlen) + 1u >
                    recordSize - offsetof(struct dirent, d_name)) {
                return SCE_KERNEL_ERROR_EIO;
            }
            const size_t nameLength = entry->d_namlen;
            const bool hidden = service_name_hidden(
                state, slot.path, slot.pathLength, entry->d_name, nameLength);
            if (hidden) {
                state.stats.directoryHiddenEntries.fetch_add(
                    1, std::memory_order_relaxed);
            } else {
                directory_record_physical_name(
                    slot, entry->d_name, nameLength);
                if (output != input) {
                    std::memmove(buffer + output, entry, recordSize);
                }
                output += recordSize;
                state.stats.directoryPhysicalEntries.fetch_add(
                    1, std::memory_order_relaxed);
            }
            input += recordSize;
        }
        if (output != 0) {
            if (basep) *basep = physicalBase;
#if AMPR_EMU_PACK_IO_LOG
            AMPR_LOGF("apr.pack.dir.%s path=%s vfd=0x%x phase=physical bytes=%llu base=%lld",
                      useGetdirentries ? "getdirentries" : "getdents",
                      slot.path, (unsigned)fd,
                      (unsigned long long)output,
                      (long long)physicalBase);
#endif
            return static_cast<int>(output);
        }
    }

    size_t output = 0;
    const long syntheticBase = slot.directoryOffset;
    auto finishSynthetic = [&](int result) -> int {
        if (result >= 0) {
            if (basep) *basep = syntheticBase;
            slot.directoryOffset = advance_directory_offset(
                syntheticBase, result);
        }
        return result;
    };
    auto emitDot = [&](const char* name, bool* emitted) -> int {
        if (*emitted) return 0;
        const uint8_t length = static_cast<uint8_t>(std::strlen(name));
        const int rc = emit_synthetic_dirent(
            buffer + output, size - static_cast<int>(output), name, length,
            DT_DIR, folded_hash(name, length));
        if (rc < 0) return rc;
        output += static_cast<size_t>(rc);
        *emitted = true;
        return 0;
    };
    if (slot.realFd < 0) {
        int dotRc = emitDot(".", &slot.dotEmitted);
        if (dotRc < 0 && output == 0) return dotRc;
        if (dotRc < 0) return finishSynthetic(static_cast<int>(output));
        dotRc = emitDot("..", &slot.dotDotEmitted);
        if (dotRc < 0 && output == 0) return dotRc;
        if (dotRc < 0) return finishSynthetic(static_cast<int>(output));
    }

    while (slot.virtualCursor < slot.rangeEnd) {
        char name[256]{};
        uint8_t nameLength = 0;
        uint8_t type = DT_UNKNOWN;
        uint32_t nextCursor = slot.virtualCursor;
        if (!next_virtual_child(state, slot, slot.virtualCursor,
                                name, &nameLength, &type, &nextCursor)) {
            slot.virtualCursor = (std::max)(slot.virtualCursor + 1u,
                                            nextCursor);
            continue;
        }
        bool duplicate = directory_physical_name_seen(slot, name, nameLength);
        if (!duplicate && slot.physicalHashOverflow && statFn) {
            char childPath[SCE_KERNEL_PATH_MAX]{};
            SceKernelStat stat{};
            duplicate = join_directory_child(
                            slot, name, nameLength,
                            childPath, sizeof(childPath)) &&
                        statFn(childPath, &stat) == 0;
        }
        if (duplicate) {
            slot.virtualCursor = nextCursor;
            state.stats.directoryDuplicateEntries.fetch_add(
                1, std::memory_order_relaxed);
            continue;
        }
        const size_t needed = synthetic_dirent_size(nameLength);
        if (needed == SIZE_MAX || needed > static_cast<size_t>(size) - output) {
            if (output == 0) return SCE_KERNEL_ERROR_EINVAL;
            break;
        }
        const int rc = emit_synthetic_dirent(
            buffer + output, size - static_cast<int>(output),
            name, nameLength, type,
            folded_hash(slot.path, slot.pathLength) ^ folded_hash(name, nameLength));
        if (rc < 0) {
            return output == 0 ? rc
                               : finishSynthetic(static_cast<int>(output));
        }
        output += static_cast<size_t>(rc);
        slot.virtualCursor = nextCursor;
        state.stats.directoryVirtualEntries.fetch_add(
            1, std::memory_order_relaxed);
    }
#if AMPR_EMU_PACK_IO_LOG
    AMPR_LOGF("apr.pack.dir.%s path=%s vfd=0x%x phase=virtual bytes=%llu cursor=%u/%u base=%lld",
              useGetdirentries ? "getdirentries" : "getdents",
              slot.path, (unsigned)fd, (unsigned long long)output,
              slot.virtualCursor, slot.rangeEnd, (long long)syntheticBase);
#endif
    return finishSynthetic(static_cast<int>(output));
#endif
}

int ampr_pack_try_getdents_fd(int fd, char* buffer, int size, bool* handled) {
    return ampr_pack_try_directory_read_fd(
        fd, buffer, size, nullptr, false, handled);
}

int ampr_pack_try_getdirentries_fd(int fd, char* buffer, int size, long* basep,
                                   bool* handled) {
    return ampr_pack_try_directory_read_fd(
        fd, buffer, size, basep, true, handled);
}

#if AMPR_EMU_PACK_ENABLE && AMPR_EMU_PACK_INTERCEPT_PROCESS_SYNC_READS
extern "C" int sceKernelAioSubmitReadCommandsMultiple(
    SceKernelAioRWRequest requests[], int count, int priority,
    SceKernelAioSubmitId ids[]);
extern "C" int sceKernelAioPollRequests(
    SceKernelAioSubmitId ids[], int count, int states[]);
extern "C" int sceKernelAioWaitRequest(
    SceKernelAioSubmitId id, int* state, SceKernelUseconds* usec);
extern "C" int sceKernelAioDeleteRequests(
    SceKernelAioSubmitId ids[], int count, int results[]);

static ssize_t synchronous_virtual_pread(int fd, void* buffer, size_t size,
                                         off_t offset) {
    if (size == 0) return 0;
    if (!buffer) return SCE_KERNEL_ERROR_EFAULT;
    if (offset < 0) return SCE_KERNEL_ERROR_EINVAL;
    SceKernelAioResult result{};
    SceKernelAioRWRequest request{};
    request.fd = fd;
    request.offset = offset;
    request.nbyte = size;
    request.buf = buffer;
    request.result = &result;
    SceKernelAioSubmitId id = 0;
    const int submitRc = sceKernelAioSubmitReadCommandsMultiple(
        &request, 1, SCE_KERNEL_AIO_PRIORITY_MID, &id);
    if (submitRc != 0) return submitRc;

    int stateValue = 0;
    const int waitRc = sceKernelAioWaitRequest(id, &stateValue, nullptr);
    ssize_t returnValue = waitRc == 0
        ? static_cast<ssize_t>(result.returnValue)
        : static_cast<ssize_t>(waitRc);

    int deleteResult = 0;
    const int deleteRc = sceKernelAioDeleteRequests(&id, 1, &deleteResult);
    if (returnValue >= 0 && deleteRc != 0) returnValue = deleteRc;
    if (returnValue >= 0 && deleteResult != 0) returnValue = deleteResult;
    return returnValue;
}
#endif

ssize_t ampr_pack_try_pread_fd(int fd, void* buffer, size_t size,
                               off_t offset, bool* handled) {
    if (handled) *handled = false;
#if !AMPR_EMU_PACK_ENABLE || !AMPR_EMU_PACK_INTERCEPT_PROCESS_SYNC_READS
    (void)fd; (void)buffer; (void)size; (void)offset;
    return SCE_KERNEL_ERROR_EBADF;
#else
    uint32_t index = 0;
    uint16_t generation = 0;
    if (!decode_virtual_fd(fd, &index, &generation)) {
        return SCE_KERNEL_ERROR_EBADF;
    }
    if (handled) *handled = true;
    PackState& state = pack_state();
    AmprLockGuard descriptorLock(state.virtualFdMutexes[index]);
    if (state.workerStopRequested.load(std::memory_order_acquire)) {
        return SCE_KERNEL_ERROR_EBADF;
    }
    uint64_t logicalSize = 0;
    {
        AmprLockGuard lock(state.m);
        const VirtualFdSlot& slot = state.virtualFds[index];
        if (!slot.active || slot.generation != generation || !state.header ||
            slot.fileId == 0 || slot.fileId > state.header->fileCount) {
            return SCE_KERNEL_ERROR_EBADF;
        }
        logicalSize = state.files[slot.fileId - 1u].logicalSize;
    }
    if (offset < 0) return SCE_KERNEL_ERROR_EINVAL;
    if (size == 0 || static_cast<uint64_t>(offset) >= logicalSize) return 0;
    if (!buffer) return SCE_KERNEL_ERROR_EFAULT;
    const size_t request = static_cast<size_t>((std::min)(
        static_cast<uint64_t>(size),
        logicalSize - static_cast<uint64_t>(offset)));
    const ssize_t rc = synchronous_virtual_pread(fd, buffer, request, offset);
    state.stats.synchronousPreads.fetch_add(1, std::memory_order_relaxed);
#if AMPR_EMU_PACK_IO_LOG
    AMPR_LOGF("apr.pack.sync.pread vfd=0x%x off=0x%llx requested=0x%llx effective=0x%llx rc=%lld",
              (unsigned)fd, (unsigned long long)offset,
              (unsigned long long)size, (unsigned long long)request,
              (long long)rc);
#endif
    return rc;
#endif
}

#if AMPR_EMU_PACK_ENABLE && AMPR_EMU_PACK_INTERCEPT_PROCESS_SYNC_READS
static int validate_read_iov(const SceKernelIovec* iov, int iovcnt,
                             size_t* totalSize) {
    if (totalSize) *totalSize = 0;
    if (iovcnt <= 0 || iovcnt > SCE_KERNEL_IOV_MAX) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    if (!iov) return SCE_KERNEL_ERROR_EFAULT;
    size_t total = 0;
    const size_t maximum = static_cast<size_t>(
        (std::numeric_limits<ssize_t>::max)());
    for (int i = 0; i < iovcnt; ++i) {
        const size_t length = iov[i].iov_len;
        if (length != 0 && !iov[i].iov_base) {
            return SCE_KERNEL_ERROR_EFAULT;
        }
        if (length > maximum - total) return SCE_KERNEL_ERROR_EINVAL;
        total += length;
    }
    if (totalSize) *totalSize = total;
    return 0;
}

static ssize_t synchronous_virtual_preadv_locked(
    int fd, const SceKernelIovec* iov, int iovcnt, uint64_t logicalSize,
    uint64_t startOffset, size_t* requestedSize) {
    size_t totalRequested = 0;
    const int validateRc = validate_read_iov(iov, iovcnt, &totalRequested);
    if (requestedSize) *requestedSize = totalRequested;
    if (validateRc != 0) return validateRc;
    if (totalRequested == 0 || startOffset >= logicalSize) return 0;

    ssize_t completed = 0;
    uint64_t cursor = startOffset;
    for (int i = 0; i < iovcnt && cursor < logicalSize; ++i) {
        const size_t length = iov[i].iov_len;
        if (length == 0) continue;
        if (cursor > static_cast<uint64_t>(
                         (std::numeric_limits<off_t>::max)())) {
            return completed > 0 ? completed : SCE_KERNEL_ERROR_EINVAL;
        }
        const size_t request = static_cast<size_t>((std::min)(
            static_cast<uint64_t>(length), logicalSize - cursor));
        const ssize_t rc = synchronous_virtual_pread(
            fd, iov[i].iov_base, request, static_cast<off_t>(cursor));
        if (rc < 0) return completed > 0 ? completed : rc;
        completed += rc;
        cursor += static_cast<uint64_t>(rc);
        if (static_cast<size_t>(rc) < request) break;
    }
    return completed;
}
#endif

ssize_t ampr_pack_try_preadv_fd(int fd, const SceKernelIovec* iov, int iovcnt,
                                off_t offset, bool* handled) {
    if (handled) *handled = false;
#if !AMPR_EMU_PACK_ENABLE || !AMPR_EMU_PACK_INTERCEPT_PROCESS_SYNC_READS
    (void)fd; (void)iov; (void)iovcnt; (void)offset;
    return SCE_KERNEL_ERROR_EBADF;
#else
    uint32_t index = 0;
    uint16_t generation = 0;
    if (!decode_virtual_fd(fd, &index, &generation)) {
        return SCE_KERNEL_ERROR_EBADF;
    }
    if (handled) *handled = true;
    if (offset < 0) return SCE_KERNEL_ERROR_EINVAL;
    PackState& state = pack_state();
    AmprLockGuard descriptorLock(state.virtualFdMutexes[index]);
    if (state.workerStopRequested.load(std::memory_order_acquire)) {
        return SCE_KERNEL_ERROR_EBADF;
    }
    uint64_t logicalSize = 0;
    {
        AmprLockGuard lock(state.m);
        const VirtualFdSlot& slot = state.virtualFds[index];
        if (!slot.active || slot.generation != generation || !state.header ||
            slot.fileId == 0 || slot.fileId > state.header->fileCount) {
            return SCE_KERNEL_ERROR_EBADF;
        }
        logicalSize = state.files[slot.fileId - 1u].logicalSize;
    }
    size_t requested = 0;
    const ssize_t rc = synchronous_virtual_preadv_locked(
        fd, iov, iovcnt, logicalSize, static_cast<uint64_t>(offset),
        &requested);
    state.stats.synchronousPreads.fetch_add(1, std::memory_order_relaxed);
#if AMPR_EMU_PACK_IO_LOG
    AMPR_LOGF("apr.pack.sync.preadv vfd=0x%x off=0x%llx iovcnt=%d requested=0x%llx rc=%lld",
              (unsigned)fd, (unsigned long long)offset, iovcnt,
              (unsigned long long)requested, (long long)rc);
#endif
    return rc;
#endif
}

ssize_t ampr_pack_try_read_fd(int fd, void* buffer, size_t size,
                              bool* handled) {
    if (handled) *handled = false;
#if !AMPR_EMU_PACK_ENABLE || !AMPR_EMU_PACK_INTERCEPT_PROCESS_SYNC_READS
    (void)fd; (void)buffer; (void)size;
    return SCE_KERNEL_ERROR_EBADF;
#else
    uint32_t index = 0;
    uint16_t generation = 0;
    if (!decode_virtual_fd(fd, &index, &generation)) {
        return SCE_KERNEL_ERROR_EBADF;
    }
    if (handled) *handled = true;
    PackState& state = pack_state();
    AmprLockGuard descriptorLock(state.virtualFdMutexes[index]);
    if (state.workerStopRequested.load(std::memory_order_acquire)) {
        return SCE_KERNEL_ERROR_EBADF;
    }
    uint64_t cursor = 0;
    uint64_t logicalSize = 0;
    {
        AmprLockGuard lock(state.m);
        const VirtualFdSlot& slot = state.virtualFds[index];
        if (!slot.active || slot.generation != generation || !state.header ||
            slot.fileId == 0 || slot.fileId > state.header->fileCount) {
            return SCE_KERNEL_ERROR_EBADF;
        }
        cursor = slot.cursor;
        logicalSize = state.files[slot.fileId - 1u].logicalSize;
    }
    if (size == 0 || cursor >= logicalSize) return 0;
    if (!buffer) return SCE_KERNEL_ERROR_EFAULT;
    const size_t request = static_cast<size_t>((std::min)(
        static_cast<uint64_t>(size), logicalSize - cursor));
    if (cursor > static_cast<uint64_t>(INT64_MAX)) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    const ssize_t rc = synchronous_virtual_pread(
        fd, buffer, request, static_cast<off_t>(cursor));
    if (rc > 0) {
        AmprLockGuard lock(state.m);
        VirtualFdSlot& slot = state.virtualFds[index];
        if (!slot.active || slot.generation != generation) {
            return SCE_KERNEL_ERROR_EBADF;
        }
        slot.cursor = cursor + static_cast<uint64_t>(rc);
    }
    state.stats.synchronousReads.fetch_add(1, std::memory_order_relaxed);
#if AMPR_EMU_PACK_IO_LOG
    AMPR_LOGF("apr.pack.sync.read vfd=0x%x cursor=0x%llx requested=0x%llx effective=0x%llx rc=%lld",
              (unsigned)fd, (unsigned long long)cursor,
              (unsigned long long)size, (unsigned long long)request,
              (long long)rc);
#endif
    return rc;
#endif
}

ssize_t ampr_pack_try_readv_fd(int fd, const SceKernelIovec* iov, int iovcnt,
                               bool* handled) {
    if (handled) *handled = false;
#if !AMPR_EMU_PACK_ENABLE || !AMPR_EMU_PACK_INTERCEPT_PROCESS_SYNC_READS
    (void)fd; (void)iov; (void)iovcnt;
    return SCE_KERNEL_ERROR_EBADF;
#else
    uint32_t index = 0;
    uint16_t generation = 0;
    if (!decode_virtual_fd(fd, &index, &generation)) {
        return SCE_KERNEL_ERROR_EBADF;
    }
    if (handled) *handled = true;
    PackState& state = pack_state();
    AmprLockGuard descriptorLock(state.virtualFdMutexes[index]);
    if (state.workerStopRequested.load(std::memory_order_acquire)) {
        return SCE_KERNEL_ERROR_EBADF;
    }
    uint64_t cursor = 0;
    uint64_t logicalSize = 0;
    {
        AmprLockGuard lock(state.m);
        const VirtualFdSlot& slot = state.virtualFds[index];
        if (!slot.active || slot.generation != generation || !state.header ||
            slot.fileId == 0 || slot.fileId > state.header->fileCount) {
            return SCE_KERNEL_ERROR_EBADF;
        }
        cursor = slot.cursor;
        logicalSize = state.files[slot.fileId - 1u].logicalSize;
    }
    size_t requested = 0;
    const ssize_t rc = synchronous_virtual_preadv_locked(
        fd, iov, iovcnt, logicalSize, cursor, &requested);
    if (rc > 0) {
        AmprLockGuard lock(state.m);
        VirtualFdSlot& slot = state.virtualFds[index];
        if (!slot.active || slot.generation != generation) {
            return SCE_KERNEL_ERROR_EBADF;
        }
        slot.cursor = cursor + static_cast<uint64_t>(rc);
    }
    state.stats.synchronousReads.fetch_add(1, std::memory_order_relaxed);
#if AMPR_EMU_PACK_IO_LOG
    AMPR_LOGF("apr.pack.sync.readv vfd=0x%x cursor=0x%llx iovcnt=%d requested=0x%llx rc=%lld",
              (unsigned)fd, (unsigned long long)cursor, iovcnt,
              (unsigned long long)requested, (long long)rc);
#endif
    return rc;
#endif
}

off_t ampr_pack_try_lseek_fd(int fd, off_t offset, int whence,
                             bool* handled) {
    if (handled) *handled = false;
#if !AMPR_EMU_PACK_ENABLE
    (void)fd; (void)offset; (void)whence;
    return static_cast<off_t>(SCE_KERNEL_ERROR_EBADF);
#else
    PackState& state = pack_state();
    uint32_t index = 0;
    uint16_t generation = 0;
    if (decode_virtual_directory_fd(fd, &index, &generation)) {
        if (handled) *handled = true;
        if (whence != SEEK_SET || offset != 0) {
            return static_cast<off_t>(SCE_KERNEL_ERROR_EINVAL);
        }
        AmprLockGuard lock(state.directoryMutexes[index]);
        if (state.workerStopRequested.load(std::memory_order_acquire)) {
            return static_cast<off_t>(SCE_KERNEL_ERROR_EBADF);
        }
        VirtualDirectorySlot& slot = state.virtualDirectories[index];
        if (!slot.active || slot.generation != generation) {
            return static_cast<off_t>(SCE_KERNEL_ERROR_EBADF);
        }
        if (slot.realFd >= 0) {
            KernelLseekFn fn = real_lseek();
            if (!fn || fn(slot.realFd, 0, SEEK_SET) < 0) {
                return static_cast<off_t>(SCE_KERNEL_ERROR_EIO);
            }
        }
        slot.realExhausted = false;
        slot.directoryOffset = 0;
        slot.dotEmitted = false;
        slot.dotDotEmitted = false;
        slot.virtualCursor = slot.rangeBegin;
        slot.physicalHashCount = 0;
        slot.physicalHashOverflow = false;
        return 0;
    }
#if AMPR_EMU_PACK_PROCESS_OPEN_ENABLE
    if (decode_virtual_fd(fd, &index, &generation)) {
        if (handled) *handled = true;
        AmprLockGuard descriptorLock(state.virtualFdMutexes[index]);
        if (state.workerStopRequested.load(std::memory_order_acquire)) {
            return static_cast<off_t>(SCE_KERNEL_ERROR_EBADF);
        }
        AmprLockGuard lock(state.m);
        VirtualFdSlot& slot = state.virtualFds[index];
        if (!slot.active || slot.generation != generation || !state.header ||
            slot.fileId == 0 || slot.fileId > state.header->fileCount) {
            return static_cast<off_t>(SCE_KERNEL_ERROR_EBADF);
        }
        const uint64_t logicalSize = state.files[slot.fileId - 1u].logicalSize;
        if (slot.cursor > static_cast<uint64_t>(INT64_MAX) ||
            logicalSize > static_cast<uint64_t>(INT64_MAX)) {
            return static_cast<off_t>(SCE_KERNEL_ERROR_EINVAL);
        }
        int64_t base = 0;
        if (whence == SEEK_SET) base = 0;
        else if (whence == SEEK_CUR) base = static_cast<int64_t>(slot.cursor);
        else if (whence == SEEK_END) base = static_cast<int64_t>(logicalSize);
        else return static_cast<off_t>(SCE_KERNEL_ERROR_EINVAL);
        const int64_t signedOffset = static_cast<int64_t>(offset);
        if ((signedOffset > 0 && base > INT64_MAX - signedOffset) ||
            (signedOffset < 0 && base < INT64_MIN - signedOffset)) {
            return static_cast<off_t>(SCE_KERNEL_ERROR_EINVAL);
        }
        const int64_t result = base + signedOffset;
        if (result < 0) return static_cast<off_t>(SCE_KERNEL_ERROR_EINVAL);
        slot.cursor = static_cast<uint64_t>(result);
        state.stats.synchronousLseeks.fetch_add(1, std::memory_order_relaxed);
        return static_cast<off_t>(result);
    }
#endif
    return static_cast<off_t>(SCE_KERNEL_ERROR_EBADF);
#endif
}

bool ampr_pack_is_virtual_fd(int fd) {
#if !AMPR_EMU_PACK_ENABLE
    (void)fd;
    return false;
#else
    uint32_t slot = 0;
    uint16_t generation = 0;
    if (!decode_virtual_fd(fd, &slot, &generation)) return false;
    PackState& state = pack_state();
    AmprLockGuard lock(state.m);
    return state.virtualFds[slot].active &&
           state.virtualFds[slot].generation == generation;
#endif
}

namespace {

static int native_pack_priority(uint8_t priority) {
    if (priority >= 2u) return SCE_KERNEL_AIO_PRIORITY_HIGH;
    if (priority == 1u) return SCE_KERNEL_AIO_PRIORITY_MID;
    return SCE_KERNEL_AIO_PRIORITY_LOW;
}

static AprExternalAioClass native_pack_io_class(PackWorkClass workClass,
                                                 size_t physicalBytes) {
    if (workClass == PackWorkClass::Bulk) {
        return AprExternalAioClass::Bulk;
    }
    if (workClass == PackWorkClass::Latency &&
        physicalBytes <= AMPR_EMU_PACK_LATENCY_READ_MAX_BYTES) {
        return AprExternalAioClass::Latency;
    }
    return AprExternalAioClass::Balanced;
}

static void record_backing_aio_completion(PackState& state,
                                          ReadPipelineContext& pipeline,
                                          int stateValue,
                                          uint64_t nowUsec) {
#if AMPR_EMU_PACK_TELEMETRY
    const bool mandatoryGroup = pipeline.mandatoryPlanActive &&
                                pipeline.mandatoryRequestCount != 0;
    const size_t requestCount = mandatoryGroup
        ? pipeline.mandatoryRequestCount
        : 1u;
    const uint64_t usecs = elapsed_usecs(
        pipeline.nativeSubmittedAtUsec, nowUsec);
    record_latency(state.stats.physicalLatency, usecs, requestCount);
    state.stats.physicalReadSamples.fetch_add(
        requestCount, std::memory_order_relaxed);
    state.stats.physicalReadUsecTotal.fetch_add(
        usecs * requestCount, std::memory_order_relaxed);
    update_atomic_peak(state.stats.physicalReadUsecMax, usecs);
    for (size_t requestIndex = 0;
         requestIndex < requestCount;
         ++requestIndex) {
        const SceKernelAioRWRequest& request = mandatoryGroup
            ? pipeline.mandatoryRequests[requestIndex]
            : pipeline.nativeRequest;
        const SceKernelAioResult& result = mandatoryGroup
            ? pipeline.mandatoryResults[requestIndex]
            : pipeline.nativeResult;
        const size_t size = static_cast<size_t>(request.nbyte);
        if (size <= 64u * 1024u) {
            state.stats.physicalReadLe64K.fetch_add(
                1, std::memory_order_relaxed);
        } else if (size <= 512u * 1024u) {
            state.stats.physicalReadLe512K.fetch_add(
                1, std::memory_order_relaxed);
        } else {
            state.stats.physicalReadGt512K.fetch_add(
                1, std::memory_order_relaxed);
        }
        record_slow_buckets(usecs,
                            state.stats.physicalReadSlow1ms,
                            state.stats.physicalReadSlow5ms,
                            state.stats.physicalReadSlow20ms);
        const int base = stateValue < 0
            ? stateValue
            : stateValue & ~SCE_KERNEL_AIO_STATE_NOTIFIED;
        if (base == SCE_KERNEL_AIO_STATE_COMPLETED &&
            result.returnValue == static_cast<int64_t>(request.nbyte)) {
            state.stats.physicalBytes.fetch_add(
                size, std::memory_order_relaxed);
            state.stats.physicalReadOps.fetch_add(
                1, std::memory_order_relaxed);
        }
    }
    state.stats.physicalReadsInFlight.fetch_sub(
        requestCount, std::memory_order_relaxed);
    [[maybe_unused]] const int base = stateValue < 0
        ? stateValue
        : stateValue & ~SCE_KERNEL_AIO_STATE_NOTIFIED;
    if (usecs >= 20000u) {
        [[maybe_unused]] size_t totalBytes = 0;
        for (size_t requestIndex = 0;
             requestIndex < requestCount;
             ++requestIndex) {
            totalBytes += mandatoryGroup
                ? pipeline.mandatoryRequests[requestIndex].nbyte
                : pipeline.nativeRequest.nbyte;
        }
        AMPR_LOGF("apr.pack.io.slow packId=%u fd=%d off=0x%llx bytes=0x%llx requests=%llu usec=%llu active=%llu rc=0x%x mode=aio",
                  mandatoryGroup
                      ? (unsigned)pipeline.mandatoryPages[0].packId
                      : (unsigned)pipeline.ioRange.packId,
                  mandatoryGroup ? -1 : pipeline.packFd,
                  mandatoryGroup
                      ? (unsigned long long)pipeline.mandatoryPages[0].offset
                      : (unsigned long long)pipeline.nativeRequest.offset,
                  (unsigned long long)totalBytes,
                  (unsigned long long)requestCount,
                  (unsigned long long)usecs,
                  (unsigned long long)state.stats.physicalReadsInFlight.load(
                      std::memory_order_relaxed),
                  base == SCE_KERNEL_AIO_STATE_COMPLETED
                      ? 0 : SCE_KERNEL_ERROR_EIO);
    }
#else
    (void)state;
    (void)pipeline;
    (void)stateValue;
    (void)nowUsec;
#endif
}

static void complete_pack_backing_aio(
    void* context, const AprExternalAioNotification& notification) {
    auto* pipeline = static_cast<ReadPipelineContext*>(context);
    if (!pipeline) return;
    PackState& state = pack_state();
    if (notification.event == AprExternalAioEvent::Submitted) {
#if AMPR_EMU_PACK_TELEMETRY
        pipeline->nativeSubmittedAtUsec = pack_telemetry_usecs();
#endif
        __atomic_store_n(&pipeline->nativeSubmitted, true, __ATOMIC_RELEASE);
        if (notification.firstExternalInSubmitBatch) {
            state.stats.backingAioSubmitBatches.fetch_add(
                1, std::memory_order_relaxed);
        }
        const bool mandatoryGroup = pipeline->mandatoryPlanActive &&
            pipeline->mandatoryRequestCount != 0;
        const size_t requestCount = mandatoryGroup
            ? pipeline->mandatoryRequestCount
            : 1u;
        state.stats.backingAioSubmitRequests.fetch_add(
            requestCount, std::memory_order_relaxed);
        const uint64_t active = state.stats.physicalReadsInFlight.fetch_add(
                                    requestCount,
                                    std::memory_order_relaxed) + requestCount;
        update_atomic_peak(state.stats.physicalReadsInFlightPeak, active);
        return;
    }
    bool queueWorker = false;
    uint64_t telemetryNowUsec = 0;
    {
        AmprLockGuard lock(state.m);
        if (!pipeline->active || !pipeline->nativeAccepted ||
            pipeline->owner == kInvalidIndex ||
            pipeline->owner >= AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS) {
            AMPR_KLOGF("ampr.abort reason=apr.pack.aio.callback.stale owner=%u active=%u accepted=%u file=%s line=%d",
                       pipeline->owner,
                       pipeline->active ? 1u : 0u,
                       pipeline->nativeAccepted ? 1u : 0u,
                       __FILE__, __LINE__);
            std::abort();
        }
        VirtualAioSlot& job = state.virtualAio[pipeline->owner];
        switch (notification.event) {
            case AprExternalAioEvent::Submitted:
                AMPR_KLOGF("ampr.abort reason=apr.pack.aio.callback.submitted-slow-path file=%s line=%d", __FILE__, __LINE__);
                std::abort();
            case AprExternalAioEvent::SubmitDeferred:
                state.stats.backingAioSubmitEagain.fetch_add(
                    1, std::memory_order_relaxed);
                job.phase = VirtualAioPhase::IoQueued;
                break;
            case AprExternalAioEvent::SubmitFailed:
                state.stats.backingAioSubmitFailures.fetch_add(
                    1, std::memory_order_relaxed);
                pipeline->nativeAccepted = false;
                pipeline->nativeIoError = notification.value;
                pipeline->nativeCompletionReady = true;
                queue_push_locked(
                    state, pipeline->owner, pack_telemetry_usecs());
                queueWorker = true;
                break;
            case AprExternalAioEvent::Completed: {
                telemetryNowUsec = pack_telemetry_usecs();
                if (!__atomic_load_n(&pipeline->nativeSubmitted,
                                     __ATOMIC_ACQUIRE)) {
                    AMPR_KLOGF("ampr.abort reason=apr.pack.aio.callback.complete-before-submit file=%s line=%d", __FILE__, __LINE__);
                    std::abort();
                }
                record_backing_aio_completion(
                    state, *pipeline, notification.value, telemetryNowUsec);
                const int base = notification.value < 0
                    ? notification.value
                    : notification.value &
                          ~SCE_KERNEL_AIO_STATE_NOTIFIED;
                pipeline->nativeAccepted = false;
                pipeline->nativeIoError =
                    base == SCE_KERNEL_AIO_STATE_COMPLETED
                        ? 0
                        : (base < 0 ? base : SCE_KERNEL_ERROR_ECANCELED);
                pipeline->nativeCompletionReady = true;
                queue_push_locked(state, pipeline->owner, telemetryNowUsec);
                queueWorker = true;
                break;
            }
        }
        ++state.aioCompletionEpoch;
    }
    state.aioCv.notify_all();
    if (queueWorker) state.queueCv.notify_all();
    if (telemetryNowUsec != 0) {
        log_pack_io_telemetry(
            state, "periodic", false, telemetryNowUsec);
    }
}

} // namespace

int ampr_pack_shutdown() {
#if !AMPR_EMU_PACK_ENABLE
    return 0;
#else
    uint32_t initState = g_pack_state_init.load(std::memory_order_acquire);
    if (initState == 0) return 0;
    uint32_t spins = 0;
    while (initState == 1u) {
        ampr_spin_pause_or_yield(spins);
        initState = g_pack_state_init.load(std::memory_order_acquire);
    }
    PackState* state = g_pack_state.load(std::memory_order_acquire);
    if (!state) return 0;

    {
        AmprUniqueLock lock(state->m);
        state->submissionsClosed = true;
        state->submitCv.wait(lock, [state] {
            return state->activeSubmissions == 0;
        });
    }
    {
        AmprLockGuard manifestLock(state->manifestMutex);
        state->workerStopRequested.store(true, std::memory_order_release);
    }
    state->manifestCv.notify_all();
    for (AmprMutex& mutex : state->virtualFdMutexes) {
        mutex.lock();
        mutex.unlock();
    }
    for (AmprMutex& mutex : state->directoryMutexes) {
        mutex.lock();
        mutex.unlock();
    }
    {
        AmprUniqueLock manifestLock(state->manifestMutex);
        state->manifestCv.wait(manifestLock, [state] {
            return state->loadState.load(std::memory_order_acquire) !=
                   kPackLoadLoading;
        });
    }

    {
        AmprLockGuard lock(state->m);
        for (uint32_t index = 0;
             index < AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS; ++index) {
            VirtualAioSlot& aio = state->virtualAio[index];
            if (aio.phase == VirtualAioPhase::Queued) {
                aio.cancelRequested.store(true, std::memory_order_release);
                if (aio.pipelineIndex == kInvalidIndex &&
                    queue_remove_locked(*state, index)) {
                    complete_virtual_job(*state, index,
                                         SCE_KERNEL_ERROR_ECANCELED,
                                         SCE_KERNEL_AIO_STATE_ABORTED);
                }
            } else if (aio.phase == VirtualAioPhase::Reserved) {
                aio.cancelRequested.store(true, std::memory_order_release);
                complete_virtual_job(*state, index,
                                     SCE_KERNEL_ERROR_ECANCELED,
                                     SCE_KERNEL_AIO_STATE_ABORTED);
            } else if (aio.phase == VirtualAioPhase::Running) {
                aio.cancelRequested.store(true, std::memory_order_release);
            } else if (aio.phase == VirtualAioPhase::WaitingCache) {
                aio.cancelRequested.store(true, std::memory_order_release);
                const uint64_t nowUsec = pack_telemetry_usecs();
                queue_cache_waiter_locked(*state, index, nowUsec);
            } else if (aio.phase == VirtualAioPhase::WaitingFd) {
                aio.cancelRequested.store(true, std::memory_order_release);
                const uint64_t nowUsec = pack_telemetry_usecs();
                queue_fd_waiter_locked(*state, index, nowUsec);
            } else if (aio.phase == VirtualAioPhase::IoQueued) {
                aio.cancelRequested.store(true, std::memory_order_release);
            }
        }
        state->queueCv.notify_all();
        for (AmprConditionVariable& cv : state->cacheCvs) cv.notify_all();
    }

    const uint64_t backingDrainStart = pack_monotonic_usecs();
    for (;;) {
        bool hasNativeBackingAio = false;
        {
            AmprLockGuard lock(state->m);
            for (uint32_t index = 0;
                 index < state->pipelineCapacity; ++index) {
                if (state->pipelines[index].nativeAccepted) {
                    hasNativeBackingAio = true;
                    break;
                }
            }
        }
        if (!hasNativeBackingAio) break;
        if (elapsed_usecs(backingDrainStart, pack_monotonic_usecs()) >=
            10000000u) {
            AMPR_CRITICAL_LOGF(
                "apr.pack.aio.shutdown.timeout usec=10000000");
            return SCE_KERNEL_ERROR_ETIMEDOUT;
        }
        (void)sceKernelUsleep(100u);
    }

    int joinError = 0;
    for (uint32_t i = 0; i < AMPR_EMU_PACK_WORKER_CAPACITY; ++i) {
        WorkerContext& worker = state->workers[i];
        if (!worker.started) continue;
        const int rc = scePthreadJoin(worker.thread, nullptr);
        if (rc != 0) {
            if (joinError == 0) joinError = rc;
            AMPR_CRITICAL_LOGF(
                "apr.pack.worker.join.fail worker=%u rc=0x%x", i, rc);
            continue;
        }
        worker.started = false;
        if (state->workersStarted != 0) --state->workersStarted;
        state->profileStartedWorkers.store(state->workersStarted, std::memory_order_release);
    }
    if (joinError != 0) return joinError;
    log_pack_io_telemetry(*state, "shutdown", true);

    int packFds[AMPR_EMU_PACK_MAX_PACKS]{};
    uint32_t packFdCount = 0;
    {
        AmprLockGuard lock(state->m);
        for (uint32_t i = 0; i < AMPR_EMU_PACK_MAX_PACKS; ++i) {
            PackHandle& handle = state->packHandles[i];
            if (handle.fd >= 0) packFds[packFdCount++] = handle.fd;
            handle = {};
            handle.fd = -1;
        }
        state->openPackCount = 0;
        state->openingPackCount = 0;
        for (uint32_t i = 0;
             i < AMPR_EMU_PACK_VIRTUAL_AIO_SLOTS; ++i) {
            free_virtual_aio_locked(*state, i);
            free_virtual_aio_group_locked(*state, i);
        }
        for (VirtualFdSlot& fd : state->virtualFds) fd = {};
    }
    for (uint32_t i = 0; i < packFdCount; ++i) {
        (void)close_physical_pack_fd(packFds[i]);
    }

    int directoryFds[AMPR_EMU_PACK_VIRTUAL_DIRECTORY_SLOTS]{};
    uint32_t directoryFdCount = 0;
    {
        AmprLockGuard tableLock(state->directoryTableMutex);
        for (uint32_t i = 0;
             i < AMPR_EMU_PACK_VIRTUAL_DIRECTORY_SLOTS; ++i) {
            AmprLockGuard directoryLock(state->directoryMutexes[i]);
            VirtualDirectorySlot& directory = state->virtualDirectories[i];
            if (directory.realFd >= 0) {
                directoryFds[directoryFdCount++] = directory.realFd;
            }
            const uint16_t generation = directory.generation;
            directory = {};
            directory.realFd = -1;
            directory.generation = generation;
        }
    }
    if (KernelCloseFn closeFn = real_close()) {
        for (uint32_t i = 0; i < directoryFdCount; ++i) {
            (void)closeFn(directoryFds[i]);
        }
    }

    for (uint32_t i = 0; i < AMPR_EMU_PACK_WORKER_CAPACITY; ++i) {
        WorkerContext& worker = state->workers[i];
        if (worker.decodedScratch) {
            (void)ampr_internal_amm_pool_free(
                worker.decodedScratch, "apr.pack.worker.decoded.shutdown");
        }
        worker = {};
    }
    for (uint32_t i = 0; i < AMPR_EMU_PACK_PIPELINE_SLOTS; ++i) {
        ReadPipelineContext& pipeline = state->pipelines[i];
        if (pipeline.ioScratch) {
            (void)ampr_internal_amm_pool_free(
                pipeline.ioScratch, "apr.pack.pipeline.io-window.shutdown");
        }
        pipeline = ReadPipelineContext{};
    }
    state->pipelineFreeHead = kInvalidIndex;
    state->pipelineCapacity = 0;
    state->cacheWaiterCount = 0;
    if (state->cacheBase) {
        (void)ampr_internal_amm_pool_free(
            state->cacheBase, "apr.pack.decoded-cache.shutdown");
        state->cacheBase = nullptr;
        state->cacheBytes = 0;
        state->cachePageCount = 0;
        state->cachePageCursor = 0;
    }
    if (state->physicalCacheBase) {
        (void)ampr_internal_amm_pool_free(
            state->physicalCacheBase, "apr.pack.physical-cache.shutdown");
        state->physicalCacheBase = nullptr;
        state->physicalCacheBytes = 0;
        state->physicalCachePageCount = 0;
        state->physicalCachePageCursor = 0;
    }
    release_manifest_storage(*state);
    {
        AmprLockGuard manifestLock(state->manifestMutex);
        state->loadState.store(kPackLoadUnavailable,
                               std::memory_order_release);
    }
    state->manifestCv.notify_all();
    AMPR_LOGF("apr.pack.shutdown packFds=%u directoryFds=%u",
              packFdCount, directoryFdCount);
    return 0;
#endif
}

AmprPackRuntimeStats ampr_pack_runtime_stats(bool reset) {
    PackState& state = pack_state();
    AmprLockGuard manifestLock(state.manifestMutex);
    AmprPackRuntimeStats result = collect_stats(state.stats, reset);
    if (state.loadState.load(std::memory_order_acquire) == kPackLoadReady) {
        result.decodedCacheTargetBytes = state.decodedCacheTargetBytes;
        result.physicalCacheTargetBytes = state.physicalCacheTargetBytes;
        result.decodedCacheAllocatedBytes = state.profileDecodedBytes;
        result.physicalCacheAllocatedBytes = state.profilePhysicalBytes;
        result.requestedWorkers = state.requestedWorkers;
        result.startedWorkers = state.profileStartedWorkers.load(std::memory_order_acquire);
        result.latencyReserveWorkers = result.startedWorkers > 1u
            ? (std::min)(state.latencyReserveWorkers, result.startedWorkers - 1u) : 0u;
        result.runtimeProfileLoaded = state.runtimeProfileLoaded;
    }
    return result;
}

void ampr_pack_log_summary(const char* reason) {
#if AMPR_EMU_DEBUG_LOG
    const AmprPackRuntimeStats stats = ampr_pack_runtime_stats(false);
    PackState& state = pack_state();
    size_t cacheBytes = 0;
    size_t physicalCacheBytes = 0;
    uint32_t workers = 0;
    uint32_t latencyReserve = 0;
    uint32_t packs = 0;
    {
        AmprLockGuard lock(state.m);
        cacheBytes = state.cacheBytes;
        physicalCacheBytes = state.physicalCacheBytes;
        workers = state.workersStarted;
        latencyReserve = effective_latency_reserve_locked(state);
        packs = state.header ? state.header->packCount : 0;
    }
    AMPR_LOGF("apr.pack.summary reason=%s packs=%u workers=%u latencyReserve=%u cacheBytes=0x%llx physicalCacheBytes=0x%llx opens=%llu processOpens=%llu submitted=%llu completed=%llu logical=0x%llx physical=0x%llx physicalOps=%llu windowHits=%llu physicalPageHit=%llu physicalPageMiss=%llu physicalPageJoin=%llu physicalPageAdmission=%llu physicalPageEviction=%llu physicalPageBypass=%llu physicalDirectRead=%llu physicalDirectReady=%llu physicalScratch=%llu physicalCopyAvoided=0x%llx inlineCache=%llu jobsLatency=%llu jobsBalanced=%llu jobsBulk=%llu latencyWorkerDispatch=%llu queuePeakLatency=%llu queuePeakBalanced=%llu queuePeakBulk=%llu storedConsumed=0x%llx decoded=0x%llx raw=0x%llx cacheHit=%llu cacheMiss=%llu cacheJoin=%llu cacheAdmission=%llu cacheEviction=%llu ioFail=%llu dirOpens=%llu dirHybrid=%llu dirVirtual=%llu dirGetdents=%llu dirPhysical=%llu dirVirtualEntries=%llu dirDuplicates=%llu dirHidden=%llu syntheticFileStat=%llu syntheticDirStat=%llu syntheticReachability=%llu syncPread=%llu syncRead=%llu syncLseek=%llu",
              reason ? reason : "(null)", packs, workers,
              (unsigned)latencyReserve,
              (unsigned long long)cacheBytes,
              (unsigned long long)physicalCacheBytes,
              (unsigned long long)stats.virtualOpens,
              (unsigned long long)stats.processVirtualOpens,
              (unsigned long long)stats.aioSubmitted,
              (unsigned long long)stats.aioCompleted,
              (unsigned long long)stats.logicalBytes,
              (unsigned long long)stats.physicalBytes,
              (unsigned long long)stats.physicalReadOps,
              (unsigned long long)stats.physicalWindowHits,
              (unsigned long long)stats.physicalPageHits,
              (unsigned long long)stats.physicalPageMisses,
              (unsigned long long)stats.physicalPageLoadingJoins,
              (unsigned long long)stats.physicalPageAdmissions,
              (unsigned long long)stats.physicalPageEvictions,
              (unsigned long long)stats.physicalPageBypasses,
              (unsigned long long)stats.physicalCacheDirectReadWindows,
              (unsigned long long)stats.physicalCacheDirectReadyWindows,
              (unsigned long long)stats.physicalCacheScratchWindows,
              (unsigned long long)stats.physicalCacheCopyBytesAvoided,
              (unsigned long long)stats.inlineCacheCompletions,
              (unsigned long long)stats.latencyJobsSubmitted,
              (unsigned long long)stats.balancedJobsSubmitted,
              (unsigned long long)stats.bulkJobsSubmitted,
              (unsigned long long)stats.latencyWorkerDispatches,
              (unsigned long long)stats.queueDepthPeakLatency,
              (unsigned long long)stats.queueDepthPeakBalanced,
              (unsigned long long)stats.queueDepthPeakBulk,
              (unsigned long long)stats.storedBytesConsumed,
              (unsigned long long)stats.lz4DecodedBytes,
              (unsigned long long)stats.rawBytes,
              (unsigned long long)stats.cacheHits,
              (unsigned long long)stats.cacheMisses,
              (unsigned long long)stats.cacheLoadingJoins,
              (unsigned long long)stats.cacheAdmissions,
              (unsigned long long)stats.cacheEvictions,
              (unsigned long long)stats.ioFailures,
              (unsigned long long)stats.directoryOpens,
              (unsigned long long)stats.directoryHybridOpens,
              (unsigned long long)stats.directoryVirtualOpens,
              (unsigned long long)stats.directoryGetdentsCalls,
              (unsigned long long)stats.directoryPhysicalEntries,
              (unsigned long long)stats.directoryVirtualEntries,
              (unsigned long long)stats.directoryDuplicateEntries,
              (unsigned long long)stats.directoryHiddenEntries,
              (unsigned long long)stats.syntheticFileStats,
              (unsigned long long)stats.syntheticDirectoryStats,
              (unsigned long long)stats.syntheticReachability,
              (unsigned long long)stats.synchronousPreads,
              (unsigned long long)stats.synchronousReads,
              (unsigned long long)stats.synchronousLseeks);
#else
    (void)reason;
#endif
}

extern "C" int sceKernelClose(int fd) {
    bool handled = false;
    const int rc = ampr_pack_try_close_fd(fd, &handled);
    if (handled) return rc;
    KernelCloseFn fn = real_sce_close();
    return fn ? fn(fd) : SCE_KERNEL_ERROR_EIO;
}

extern "C" int sceKernelClose_emul(int fd) {
    return ampr_klog_io_hook_result("sceKernelClose", sceKernelClose(fd));
}

template <typename Result>
static Result posix_result_from_pack(Result rc) {
    if (rc >= 0) return rc;
    // A real POSIX fallback can already have produced -1 with the precise
    // errno. Synthetic virtual-fd failures use SCE error values instead.
    if (rc != static_cast<Result>(-1)) {
        errno = ampr_posix_errno_from_sce(static_cast<int>(rc));
    }
    return static_cast<Result>(-1);
}

template <typename Result>
static Result posix_missing_original() {
    errno = EIO;
    return static_cast<Result>(-1);
}

extern "C" int posix_close_emul(int fd) {
    bool handled = false;
    const int rc = ampr_pack_try_close_fd(fd, &handled);
    if (handled) {
        return ampr_klog_io_hook_result("close", posix_result_from_pack(rc));
    }
    KernelCloseFn fn = real_close();
    return ampr_klog_io_hook_result(
        "close", fn ? fn(fd) : posix_missing_original<int>());
}

extern "C" int posix_fstat_emul(int fd, struct stat* stat) {
    bool handled = false;
    const int rc = ampr_pack_try_fstat_fd(fd, stat, &handled);
    if (handled) {
        return ampr_klog_io_hook_result("fstat", posix_result_from_pack(rc));
    }
    KernelFstatFn fn = real_fstat();
    return ampr_klog_io_hook_result(
        "fstat", fn ? fn(fd, stat) : posix_missing_original<int>());
}

extern "C" int posix_getdents_emul(int fd, char* buffer, int size) {
    bool handled = false;
    const int rc = ampr_pack_try_getdents_fd(fd, buffer, size, &handled);
    if (handled) {
        return ampr_klog_io_hook_result("getdents",
                                        posix_result_from_pack(rc));
    }
    KernelGetdentsFn fn = real_getdents();
    return ampr_klog_io_hook_result(
        "getdents",
        fn ? fn(fd, buffer, size) : posix_missing_original<int>());
}

extern "C" int posix_getdirentries_emul(int fd, char* buffer, int size,
                                          long* basep) {
    bool handled = false;
    const int rc = ampr_pack_try_getdirentries_fd(
        fd, buffer, size, basep, &handled);
    if (handled) {
        return ampr_klog_io_hook_result("getdirentries",
                                        posix_result_from_pack(rc));
    }
    KernelGetdirentriesFn fn = real_getdirentries();
    return ampr_klog_io_hook_result(
        "getdirentries",
        fn ? fn(fd, buffer, size, basep) : posix_missing_original<int>());
}

extern "C" off_t posix_lseek_emul(int fd, off_t offset, int whence) {
    bool handled = false;
    const off_t rc = ampr_pack_try_lseek_fd(fd, offset, whence, &handled);
    if (handled) {
        return ampr_klog_io_hook_result("lseek", posix_result_from_pack(rc));
    }
    KernelLseekFn fn = real_lseek();
    return ampr_klog_io_hook_result(
        "lseek",
        fn ? fn(fd, offset, whence) : posix_missing_original<off_t>());
}

#if AMPR_EMU_PACK_ENABLE && AMPR_EMU_PACK_INTERCEPT_PROCESS_SYNC_READS
extern "C" ssize_t posix_pread_emul(int fd, void* buffer, size_t size,
                                      off_t offset) {
    bool handled = false;
    const ssize_t rc = ampr_pack_try_pread_fd(
        fd, buffer, size, offset, &handled);
    if (handled) {
        return ampr_klog_io_hook_result("pread", posix_result_from_pack(rc));
    }
    KernelPreadFn fn = real_pread();
    return ampr_klog_io_hook_result(
        "pread",
        fn ? fn(fd, buffer, size, offset)
           : posix_missing_original<ssize_t>());
}

extern "C" ssize_t posix_preadv_emul(int fd, const SceKernelIovec* iov,
                                       int iovcnt, off_t offset) {
    bool handled = false;
    const ssize_t rc = ampr_pack_try_preadv_fd(
        fd, iov, iovcnt, offset, &handled);
    if (handled) {
        return ampr_klog_io_hook_result("preadv", posix_result_from_pack(rc));
    }
    KernelPreadvFn fn = real_preadv();
    return ampr_klog_io_hook_result(
        "preadv",
        fn ? fn(fd, iov, iovcnt, offset)
           : posix_missing_original<ssize_t>());
}

extern "C" ssize_t posix_read_emul(int fd, void* buffer, size_t size) {
    bool handled = false;
    const ssize_t rc = ampr_pack_try_read_fd(fd, buffer, size, &handled);
    if (handled) {
        return ampr_klog_io_hook_result("read", posix_result_from_pack(rc));
    }
    KernelReadFn fn = real_read();
    return ampr_klog_io_hook_result(
        "read",
        fn ? fn(fd, buffer, size) : posix_missing_original<ssize_t>());
}

extern "C" ssize_t posix_readv_emul(int fd, const SceKernelIovec* iov,
                                      int iovcnt) {
    bool handled = false;
    const ssize_t rc = ampr_pack_try_readv_fd(fd, iov, iovcnt, &handled);
    if (handled) {
        return ampr_klog_io_hook_result("readv", posix_result_from_pack(rc));
    }
    KernelReadvFn fn = real_readv();
    return ampr_klog_io_hook_result(
        "readv",
        fn ? fn(fd, iov, iovcnt) : posix_missing_original<ssize_t>());
}
#endif

extern "C" int sceKernelAioSubmitReadCommands(
    SceKernelAioRWRequest requests[], int count, int priority,
    SceKernelAioSubmitId* id);
extern "C" int sceKernelAioSubmitReadCommandsMultiple(
    SceKernelAioRWRequest requests[], int count, int priority,
    SceKernelAioSubmitId ids[]);
extern "C" int sceKernelAioPollRequest(SceKernelAioSubmitId id, int* state);
extern "C" int sceKernelAioPollRequests(
    SceKernelAioSubmitId ids[], int count, int states[]);
extern "C" int sceKernelAioWaitRequest(
    SceKernelAioSubmitId id, int* state, SceKernelUseconds* usec);
extern "C" int sceKernelAioWaitRequests(
    SceKernelAioSubmitId ids[], int count, int states[], uint32_t mode,
    SceKernelUseconds* usec);
extern "C" int sceKernelAioCancelRequest(
    SceKernelAioSubmitId id, int* state);
extern "C" int sceKernelAioCancelRequests(
    SceKernelAioSubmitId ids[], int count, int states[]);
extern "C" int sceKernelAioDeleteRequest(SceKernelAioSubmitId id,
                                           int* result);
extern "C" int sceKernelAioDeleteRequests(
    SceKernelAioSubmitId ids[], int count, int results[]);

extern "C" int sceKernelAioSubmitReadCommands(
    SceKernelAioRWRequest requests[], int count, int priority,
    SceKernelAioSubmitId* id) {
#if !AMPR_EMU_PACK_ENABLE
    KernelAioSubmitFn fn = real_aio_submit_single();
    return fn ? fn(requests, count, priority, id) : SCE_KERNEL_ERROR_EIO;
#else
    if (!requests || !id || count <= 0 ||
        count > SCE_KERNEL_AIO_REQUEST_NUM_MAX) {
        return SCE_KERNEL_ERROR_EINVAL;
    }

    bool hasVirtualFd = false;
    for (int i = 0; i < count; ++i) {
        if (decode_virtual_fd(requests[i].fd, nullptr, nullptr)) {
            hasVirtualFd = true;
            break;
        }
    }
    if (!hasVirtualFd) {
        KernelAioSubmitFn fn = real_aio_submit_single();
        return fn ? fn(requests, count, priority, id)
                  : SCE_KERNEL_ERROR_EIO;
    }

    PackState& state = pack_state();
    uint32_t groupIndex = kInvalidIndex;
    PackSubmission submission(state);
    if (!submission.admitted()) return SCE_KERNEL_ERROR_EBUSY;
    uint16_t groupGeneration = 0;
    {
        AmprLockGuard lock(state.m);
        groupIndex = allocate_virtual_aio_group_locked(state);
        if (groupIndex == kInvalidIndex) return SCE_KERNEL_ERROR_EAGAIN;
        groupGeneration = state.virtualAioGroups[groupIndex].generation;
    }

    SceKernelAioSubmitId childIds[SCE_KERNEL_AIO_REQUEST_NUM_MAX]{};
    const int submitRc = sceKernelAioSubmitReadCommandsMultiple(
        requests, count, priority, childIds);
    if (submitRc != 0) {
        AmprLockGuard lock(state.m);
        VirtualAioGroupSlot& group = state.virtualAioGroups[groupIndex];
        if (group.active && group.generation == groupGeneration) {
            free_virtual_aio_group_locked(state, groupIndex);
        }
        return submitRc;
    }

    bool groupPublished = false;
    {
        AmprLockGuard lock(state.m);
        VirtualAioGroupSlot& group = state.virtualAioGroups[groupIndex];
        if (group.active && group.generation == groupGeneration) {
            std::memcpy(group.children, childIds,
                        static_cast<size_t>(count) * sizeof(childIds[0]));
            group.childCount = static_cast<uint16_t>(count);
            for (int i = 0; i < count; ++i) {
                group.hasNativeChildren = group.hasNativeChildren ||
                    !decode_virtual_aio(childIds[i], nullptr, nullptr);
            }
            *id = encode_virtual_aio_group(groupIndex, groupGeneration);
            groupPublished = true;
        }
    }
    if (!groupPublished) {
        int childResults[SCE_KERNEL_AIO_REQUEST_NUM_MAX]{};
        (void)sceKernelAioDeleteRequests(childIds, count, childResults);
        return SCE_KERNEL_ERROR_EIO;
    }
#if AMPR_EMU_PACK_IO_LOG
    AMPR_LOGF("apr.pack.aio.group.submit gaio=0x%x children=%d priority=%d",
              (unsigned)*id, count, priority);
#endif
    return 0;
#endif
}

extern "C" int sceKernelAioSubmitReadCommandsMultiple(
    SceKernelAioRWRequest requests[], int count, int priority,
    SceKernelAioSubmitId ids[]) {
#if !AMPR_EMU_PACK_ENABLE
    KernelAioSubmitFn fn = real_aio_submit();
    return fn ? fn(requests, count, priority, ids) : SCE_KERNEL_ERROR_EIO;
#else
    if (!requests || !ids || count <= 0 ||
        count > SCE_KERNEL_AIO_REQUEST_NUM_MAX) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    bool hasVirtualFd = false;
    for (int i = 0; i < count; ++i) {
        if (decode_virtual_fd(requests[i].fd, nullptr, nullptr)) {
            hasVirtualFd = true;
            break;
        }
    }
    if (!hasVirtualFd) {
        KernelAioSubmitFn fn = real_aio_submit();
        return fn ? fn(requests, count, priority, ids) : SCE_KERNEL_ERROR_EIO;
    }
    PackState& state = pack_state();
    SceKernelAioRWRequest realRequests[SCE_KERNEL_AIO_REQUEST_NUM_MAX]{};
    PackSubmission submission(state);
    if (!submission.admitted()) return SCE_KERNEL_ERROR_EBUSY;
    SceKernelAioSubmitId realIds[SCE_KERNEL_AIO_REQUEST_NUM_MAX]{};
    int realPositions[SCE_KERNEL_AIO_REQUEST_NUM_MAX]{};
    uint32_t virtualIndexes[SCE_KERNEL_AIO_REQUEST_NUM_MAX]{};
    int virtualPositions[SCE_KERNEL_AIO_REQUEST_NUM_MAX]{};
    bool inlineCompleted[SCE_KERNEL_AIO_REQUEST_NUM_MAX]{};
    uint64_t inlineBytes[SCE_KERNEL_AIO_REQUEST_NUM_MAX]{};
    int realCount = 0;
    int virtualCount = 0;
    int prepareRc = 0;

    {
        AmprLockGuard lock(state.m);
        for (int i = 0; i < count; ++i) {
            uint32_t fdIndex = 0;
            uint16_t fdGeneration = 0;
            if (!decode_virtual_fd(requests[i].fd, &fdIndex, &fdGeneration)) {
                realPositions[realCount] = i;
                realRequests[realCount++] = requests[i];
                continue;
            }
            VirtualFdSlot& fdSlot = state.virtualFds[fdIndex];
            if (!fdSlot.active || fdSlot.generation != fdGeneration) {
                prepareRc = SCE_KERNEL_ERROR_EBADF;
                break;
            }
            const uint32_t aioIndex = allocate_virtual_aio_locked(state);
            if (aioIndex == kInvalidIndex) {
                prepareRc = SCE_KERNEL_ERROR_EAGAIN;
                break;
            }
            VirtualAioSlot& aio = state.virtualAio[aioIndex];
            aio.request = requests[i];
#if AMPR_EMU_PACK_TELEMETRY
            aio.admittedAtUsec = pack_monotonic_usecs();
#endif
            aio.fileId = fdSlot.fileId;
            aio.priority = queue_priority(priority);
            aio.processOrigin = fdSlot.processOpen;
            if (!state.header || !state.files || aio.fileId == 0 ||
                aio.fileId > state.header->fileCount) {
                free_virtual_aio_locked(state, aioIndex);
                prepareRc = SCE_KERNEL_ERROR_EIO;
                break;
            }
            aio.workClass =
#if AMPR_EMU_PACK_PROCESS_AIO_STRICT_FIFO
                aio.processOrigin ? PackWorkClass::Balanced :
#endif
                classify_work(state.files[aio.fileId - 1u], aio.request);
            aio.cancelRequested.store(false, std::memory_order_relaxed);
            if (aio.request.result) {
                __atomic_store_n(&aio.request.result->returnValue, 0,
                                 __ATOMIC_RELAXED);
                __atomic_store_n(&aio.request.result->state, 0u,
                                 __ATOMIC_RELEASE);
            }
            virtualIndexes[virtualCount] = aioIndex;
            virtualPositions[virtualCount] = i;
            ++virtualCount;
        }
        if (prepareRc == 0 && virtualCount != 0 &&
            !ensure_workers_locked(state)) {
            prepareRc = SCE_KERNEL_ERROR_ENOMEM;
        }
        if (prepareRc != 0) {
            for (int i = 0; i < virtualCount; ++i) {
                free_virtual_aio_locked(state, virtualIndexes[i]);
            }
        }
    }
    if (prepareRc != 0) return prepareRc;

    if (realCount != 0) {
        KernelAioSubmitFn fn = real_aio_submit();
        if (!fn) {
            AmprLockGuard lock(state.m);
            for (int i = 0; i < virtualCount; ++i) {
                free_virtual_aio_locked(state, virtualIndexes[i]);
            }
            return SCE_KERNEL_ERROR_EIO;
        }
        const int rc = fn(realRequests, realCount, priority, realIds);
        if (rc != 0) {
            AmprLockGuard lock(state.m);
            for (int i = 0; i < virtualCount; ++i) {
                free_virtual_aio_locked(state, virtualIndexes[i]);
            }
            return rc;
        }
        for (int i = 0; i < realCount; ++i) {
            ids[realPositions[i]] = realIds[i];
        }
    }

    if (virtualCount != 0) {
        for (int i = 0; i < virtualCount; ++i) {
            inlineCompleted[i] = try_process_virtual_read_cache_only(
                state.virtualAio[virtualIndexes[i]], &inlineBytes[i]);
        }
        const uint64_t queuedAtUsec = pack_telemetry_usecs();
        bool queued = false;
        {
            AmprLockGuard lock(state.m);
            for (int i = 0; i < virtualCount; ++i) {
                const uint32_t index = virtualIndexes[i];
                VirtualAioSlot& aio = state.virtualAio[index];
                ids[virtualPositions[i]] = encode_virtual_aio(
                    index, aio.generation);
#if AMPR_EMU_PACK_IO_LOG
                AMPR_LOGF("apr.pack.aio.submit vaio=0x%x vfd=0x%x fileId=%u off=0x%llx bytes=0x%llx priority=%d class=%u inline=%u origin=%s",
                          (unsigned)ids[virtualPositions[i]],
                          (unsigned)aio.request.fd, aio.fileId,
                          (unsigned long long)aio.request.offset,
                          (unsigned long long)aio.request.nbyte, priority,
                          (unsigned)aio.workClass,
                          inlineCompleted[i] ? 1u : 0u,
                          aio.processOrigin ? "process" : "indexed");
#endif
                if (inlineCompleted[i]) {
                    complete_virtual_job(
                        state, index,
                        static_cast<int64_t>(inlineBytes[i]),
                        SCE_KERNEL_AIO_STATE_COMPLETED);
                } else {
                    queue_push_locked(state, index, queuedAtUsec);
                    queued = true;
                }
                switch (aio.workClass) {
                    case PackWorkClass::Latency:
                        state.stats.latencyJobsSubmitted.fetch_add(
                            1, std::memory_order_relaxed);
                        break;
                    case PackWorkClass::Balanced:
                        state.stats.balancedJobsSubmitted.fetch_add(
                            1, std::memory_order_relaxed);
                        break;
                    case PackWorkClass::Bulk:
                        state.stats.bulkJobsSubmitted.fetch_add(
                            1, std::memory_order_relaxed);
                        break;
                    default:
                        break;
                }
            }
            state.stats.aioSubmitted.fetch_add(
                static_cast<uint64_t>(virtualCount),
                std::memory_order_relaxed);
        }
        if (queued) state.queueCv.notify_all();
    }
    return 0;
#endif
}

extern "C" int sceKernelAioPollRequests(SceKernelAioSubmitId ids[],
                                         int count,
                                         int states[]) {
#if !AMPR_EMU_PACK_ENABLE
    KernelAioPollFn fn = real_aio_poll();
    return fn ? fn(ids, count, states) : SCE_KERNEL_ERROR_EIO;
#else
    if (!ids || !states || count <= 0 || count > SCE_KERNEL_AIO_ID_NUM_MAX) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    bool hasGroup = false;
    bool hasVirtual = false;
    for (int i = 0; i < count; ++i) {
        if (decode_virtual_aio_group(ids[i], nullptr, nullptr)) {
            hasGroup = true;
            break;
        }
        hasVirtual = hasVirtual || decode_virtual_aio(ids[i], nullptr, nullptr);
    }
    if (!hasGroup && !hasVirtual) {
        KernelAioPollFn fn = real_aio_poll();
        return fn ? fn(ids, count, states) : SCE_KERNEL_ERROR_EIO;
    }
    if (hasGroup) {
        for (int i = 0; i < count; ++i) {
            const int rc = sceKernelAioPollRequest(ids[i], &states[i]);
            if (rc != 0) return rc;
        }
        return 0;
    }
    SceKernelAioSubmitId realIds[SCE_KERNEL_AIO_ID_NUM_MAX]{};
    int realStates[SCE_KERNEL_AIO_ID_NUM_MAX]{};
    int realPositions[SCE_KERNEL_AIO_ID_NUM_MAX]{};
    int realCount = 0;
    PackState& state = pack_state();
    {
        AmprLockGuard lock(state.m);
        for (int i = 0; i < count; ++i) {
            if ((static_cast<uint32_t>(ids[i]) & kVirtualTagMask) !=
                kVirtualAioTag) {
                realPositions[realCount] = i;
                realIds[realCount++] = ids[i];
                continue;
            }
            VirtualAioSlot* aio = lookup_virtual_aio_locked(state, ids[i]);
            if (!aio) {
                states[i] = SCE_KERNEL_ERROR_ESRCH;
                continue;
            }
            switch (aio->phase) {
                case VirtualAioPhase::Reserved:
                case VirtualAioPhase::Queued:
                case VirtualAioPhase::WaitingCache:
                case VirtualAioPhase::WaitingFd:
                    states[i] = SCE_KERNEL_AIO_STATE_SUBMITTED;
                    break;
                case VirtualAioPhase::IoQueued: {
                    const uint32_t pipelineIndex = aio->pipelineIndex;
                    states[i] = pipelineIndex < state.pipelineCapacity &&
                                        __atomic_load_n(
                                            &state.pipelines[pipelineIndex]
                                                 .nativeSubmitted,
                                            __ATOMIC_ACQUIRE)
                                    ? SCE_KERNEL_AIO_STATE_PROCESSING
                                    : SCE_KERNEL_AIO_STATE_SUBMITTED;
                    break;
                }
                case VirtualAioPhase::Running:
                    states[i] = SCE_KERNEL_AIO_STATE_PROCESSING;
                    break;
                case VirtualAioPhase::Done:
                    states[i] = aio->completionState;
                    break;
                default:
                    states[i] = SCE_KERNEL_ERROR_ESRCH;
                    break;
            }
        }
    }
    if (realCount != 0) {
        KernelAioPollFn fn = real_aio_poll();
        if (!fn) return SCE_KERNEL_ERROR_EIO;
        const int rc = fn(realIds, realCount, realStates);
        if (rc != 0) return rc;
        for (int i = 0; i < realCount; ++i) {
            states[realPositions[i]] = realStates[i];
        }
    }
    return 0;
#endif
}

extern "C" int sceKernelAioCancelRequests(SceKernelAioSubmitId ids[],
                                            int count,
                                            int states[]) {
#if !AMPR_EMU_PACK_ENABLE
    KernelAioCancelFn fn = real_aio_cancel();
    return fn ? fn(ids, count, states) : SCE_KERNEL_ERROR_EIO;
#else
    if (!ids || !states || count <= 0 || count > SCE_KERNEL_AIO_ID_NUM_MAX) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    bool hasVirtual = false;
    for (int i = 0; i < count; ++i) {
        hasVirtual = hasVirtual || decode_virtual_aio(ids[i], nullptr, nullptr);
        if (decode_virtual_aio_group(ids[i], nullptr, nullptr)) {
            for (int n = 0; n < count; ++n) {
                const int rc = sceKernelAioCancelRequest(ids[n], &states[n]);
                if (rc != 0) return rc;
            }
            return 0;
        }
    }

    if (!hasVirtual) {
        KernelAioCancelFn fn = real_aio_cancel();
        return fn ? fn(ids, count, states) : SCE_KERNEL_ERROR_EIO;
    }
    SceKernelAioSubmitId realIds[SCE_KERNEL_AIO_ID_NUM_MAX]{};
    int realStates[SCE_KERNEL_AIO_ID_NUM_MAX]{};
    int realPositions[SCE_KERNEL_AIO_ID_NUM_MAX]{};
    int realCount = 0;
    bool completedQueuedJob = false;
    PackState& state = pack_state();
    {
        AmprLockGuard lock(state.m);
        for (int i = 0; i < count; ++i) {
            if (!decode_virtual_aio(ids[i], nullptr, nullptr)) {
                realPositions[realCount] = i;
                realIds[realCount++] = ids[i];
                continue;
            }
            uint32_t index = 0;
            VirtualAioSlot* aio = lookup_virtual_aio_locked(
                state, ids[i], &index);
            if (!aio) {
                states[i] = SCE_KERNEL_ERROR_ESRCH;
                continue;
            }
            switch (aio->phase) {
                case VirtualAioPhase::Reserved:
                    aio->cancelRequested.store(true, std::memory_order_release);
                    complete_virtual_job(state, index,
                                         SCE_KERNEL_ERROR_ECANCELED,
                                         SCE_KERNEL_AIO_STATE_ABORTED);
                    states[i] = SCE_KERNEL_AIO_STATE_ABORTED;
                    completedQueuedJob = true;
                    break;
                case VirtualAioPhase::Queued:
                    aio->cancelRequested.store(true, std::memory_order_release);
                    if (aio->pipelineIndex != kInvalidIndex) {
                        states[i] = SCE_KERNEL_AIO_STATE_PROCESSING;
                        break;
                    }
                    if (!queue_remove_locked(state, index)) {
                        states[i] = SCE_KERNEL_AIO_STATE_PROCESSING;
                        break;
                    }
                    complete_virtual_job(state, index,
                                         SCE_KERNEL_ERROR_ECANCELED,
                                         SCE_KERNEL_AIO_STATE_ABORTED);
                    states[i] = SCE_KERNEL_AIO_STATE_ABORTED;
                    completedQueuedJob = true;
                    break;
                case VirtualAioPhase::WaitingCache:
                    aio->cancelRequested.store(true,
                                               std::memory_order_release);
                    queue_cache_waiter_locked(
                        state, index, pack_telemetry_usecs());
                    states[i] = SCE_KERNEL_AIO_STATE_PROCESSING;
                    completedQueuedJob = true;
                    break;
                case VirtualAioPhase::WaitingFd:
                    aio->cancelRequested.store(true,
                                               std::memory_order_release);
                    queue_fd_waiter_locked(
                        state, index, pack_telemetry_usecs());
                    states[i] = SCE_KERNEL_AIO_STATE_PROCESSING;
                    completedQueuedJob = true;
                    break;
                case VirtualAioPhase::Running:
                case VirtualAioPhase::IoQueued:
                    aio->cancelRequested.store(true, std::memory_order_release);
                    states[i] = SCE_KERNEL_AIO_STATE_PROCESSING;
                    break;
                case VirtualAioPhase::Done:
                    states[i] = aio->completionState;
                    break;
                default:
                    states[i] = SCE_KERNEL_ERROR_ESRCH;
                    break;
            }
        }
    }
    if (completedQueuedJob) state.queueCv.notify_all();
    if (realCount != 0) {
        KernelAioCancelFn fn = real_aio_cancel();
        if (!fn) return SCE_KERNEL_ERROR_EIO;
        const int rc = fn(realIds, realCount, realStates);
        if (rc != 0) return rc;
        for (int i = 0; i < realCount; ++i) {
            states[realPositions[i]] = realStates[i];
        }
    }
    return 0;
#endif
}

static bool aio_state_terminal(int state) {
    if (state < 0) return true;
    const int base = state & ~SCE_KERNEL_AIO_STATE_NOTIFIED;
    return base == SCE_KERNEL_AIO_STATE_COMPLETED ||
           base == SCE_KERNEL_AIO_STATE_ABORTED;
}

static void mark_virtual_wait_notified(SceKernelAioSubmitId ids[],
                                       int count,
                                       int states[]) {
    PackState& state = pack_state();
    AmprLockGuard lock(state.m);
    for (int i = 0; i < count; ++i) {
        if (!aio_state_terminal(states[i]) || states[i] < 0) continue;
        if (VirtualAioSlot* aio = lookup_virtual_aio_locked(state, ids[i])) {
            if (aio->waitNotified) states[i] |= SCE_KERNEL_AIO_STATE_NOTIFIED;
            aio->waitNotified = true;
            continue;
        }
        if (VirtualAioGroupSlot* group =
                lookup_virtual_aio_group_locked(state, ids[i])) {
            if (group->waitNotified) states[i] |= SCE_KERNEL_AIO_STATE_NOTIFIED;
            group->waitNotified = true;
        }
    }
}

extern "C" int sceKernelAioWaitRequests(SceKernelAioSubmitId ids[],
                                          int count,
                                          int states[],
                                          uint32_t mode,
                                          SceKernelUseconds* usec) {
#if !AMPR_EMU_PACK_ENABLE
    KernelAioWaitFn fn = real_aio_wait();
    return fn ? fn(ids, count, states, mode, usec) : SCE_KERNEL_ERROR_EIO;
#else
    if (!ids || !states || count <= 0 || count > SCE_KERNEL_AIO_ID_NUM_MAX ||
        (count > 1 && mode != SCE_KERNEL_AIO_WAIT_AND &&
         mode != SCE_KERNEL_AIO_WAIT_OR)) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    bool hasSynthetic = false;
    bool needsNativePolling = false;
    for (int i = 0; i < count; ++i) {
        const bool direct = decode_virtual_aio(ids[i], nullptr, nullptr);
        const bool group = decode_virtual_aio_group(ids[i], nullptr, nullptr);
        hasSynthetic = hasSynthetic || direct || group;
        needsNativePolling = needsNativePolling || (!direct && !group);
    }
    if (!hasSynthetic) {
        KernelAioWaitFn fn = real_aio_wait();
        return fn ? fn(ids, count, states, mode, usec)
                  : SCE_KERNEL_ERROR_EIO;
    }

    const bool waitAll = count == 1 || mode == SCE_KERNEL_AIO_WAIT_AND;
    const uint64_t timeout = usec ? static_cast<uint64_t>(*usec) : 0;
    const uint64_t start = pack_monotonic_usecs();
    PackState& pack = pack_state();
    uint64_t observedEpoch = 0;
    {
        AmprLockGuard lock(pack.m);
        observedEpoch = pack.aioCompletionEpoch;
        for (int i = 0; i < count; ++i) {
            const VirtualAioGroupSlot* group =
                lookup_virtual_aio_group_locked(pack, ids[i]);
            if (group && group->hasNativeChildren) needsNativePolling = true;
        }
    }

    for (;;) {
        const int pollRc = sceKernelAioPollRequests(ids, count, states);
        if (pollRc != 0) return pollRc;
        bool anyTerminal = false;
        bool allTerminal = true;
        for (int i = 0; i < count; ++i) {
            const bool terminal = aio_state_terminal(states[i]);
            anyTerminal = anyTerminal || terminal;
            allTerminal = allTerminal && terminal;
        }
        if ((waitAll && allTerminal) || (!waitAll && anyTerminal)) {
            if (usec) {
                const uint64_t now = pack_monotonic_usecs();
                const uint64_t elapsed = now >= start ? now - start : timeout;
                *usec = static_cast<SceKernelUseconds>(
                    elapsed < timeout ? timeout - elapsed : 0);
            }
            mark_virtual_wait_notified(ids, count, states);
            return 0;
        }

        uint64_t waitUsecs = needsNativePolling ? 1000ull : UINT64_MAX;
        if (usec) {
            const uint64_t now = pack_monotonic_usecs();
            const uint64_t elapsed = now >= start ? now - start : timeout;
            if (elapsed >= timeout) {
                *usec = 0;
                return SCE_KERNEL_ERROR_ETIMEDOUT;
            }
            waitUsecs = (std::min)(waitUsecs, timeout - elapsed);
        }

        AmprUniqueLock lock(pack.m);
        if (pack.aioCompletionEpoch != observedEpoch) {
            observedEpoch = pack.aioCompletionEpoch;
            continue;
        }
        if (waitUsecs == UINT64_MAX) {
            pack.aioCv.wait(lock);
        } else {
            pack.aioCv.wait_for(lock, std::chrono::microseconds(waitUsecs));
        }
        observedEpoch = pack.aioCompletionEpoch;
    }
#endif
}

extern "C" int sceKernelAioDeleteRequests(SceKernelAioSubmitId ids[],
                                           int count,
                                           int results[]) {
#if !AMPR_EMU_PACK_ENABLE
    KernelAioDeleteFn fn = real_aio_delete();
    return fn ? fn(ids, count, results) : SCE_KERNEL_ERROR_EIO;
#else
    if (!ids || !results || count <= 0 || count > SCE_KERNEL_AIO_ID_NUM_MAX) {
        return SCE_KERNEL_ERROR_EINVAL;
    }
    bool hasGroup = false;
    bool hasVirtual = false;
    for (int i = 0; i < count; ++i) {
        if (decode_virtual_aio_group(ids[i], nullptr, nullptr)) {
            hasGroup = true;
            break;
        }
        hasVirtual = hasVirtual || decode_virtual_aio(ids[i], nullptr, nullptr);
    }
    if (!hasGroup && !hasVirtual) {
        KernelAioDeleteFn fn = real_aio_delete();
        return fn ? fn(ids, count, results) : SCE_KERNEL_ERROR_EIO;
    }
    if (hasGroup) {
        for (int i = 0; i < count; ++i) {
            const int rc = sceKernelAioDeleteRequest(ids[i], &results[i]);
            if (rc != 0) return rc;
        }
        return 0;
    }
    SceKernelAioSubmitId realIds[SCE_KERNEL_AIO_ID_NUM_MAX]{};
    int realResults[SCE_KERNEL_AIO_ID_NUM_MAX]{};
    int realPositions[SCE_KERNEL_AIO_ID_NUM_MAX]{};
    int realCount = 0;
    PackState& state = pack_state();
    {
        AmprLockGuard lock(state.m);
        for (int i = 0; i < count; ++i) {
            if ((static_cast<uint32_t>(ids[i]) & kVirtualTagMask) !=
                kVirtualAioTag) {
                realPositions[realCount] = i;
                realIds[realCount++] = ids[i];
                continue;
            }
            uint32_t index = 0;
            VirtualAioSlot* aio = lookup_virtual_aio_locked(state, ids[i],
                                                            &index);
            if (!aio) {
                results[i] = SCE_KERNEL_ERROR_ESRCH;
                continue;
            }
            if (aio->phase != VirtualAioPhase::Done) {
                aio->cancelRequested.store(true, std::memory_order_release);
                results[i] = SCE_KERNEL_ERROR_EBUSY;
                continue;
            }
            free_virtual_aio_locked(state, index);
            results[i] = 0;
        }
    }
    if (realCount != 0) {
        KernelAioDeleteFn fn = real_aio_delete();
        if (!fn) return SCE_KERNEL_ERROR_EIO;
        const int rc = fn(realIds, realCount, realResults);
        if (rc != 0) return rc;
        for (int i = 0; i < realCount; ++i) {
            results[realPositions[i]] = realResults[i];
        }
    }
    return 0;
#endif
}

extern "C" int sceKernelAioPollRequest(SceKernelAioSubmitId id,
                                         int* stateOut) {
    if (!stateOut) return SCE_KERNEL_ERROR_EINVAL;
#if !AMPR_EMU_PACK_ENABLE
    KernelAioPollSingleFn fn = real_aio_poll_single();
    return fn ? fn(id, stateOut) : SCE_KERNEL_ERROR_EIO;
#else
    if (decode_virtual_aio(id, nullptr, nullptr)) {
        return sceKernelAioPollRequests(&id, 1, stateOut);
    }
    if (!decode_virtual_aio_group(id, nullptr, nullptr)) {
        KernelAioPollSingleFn fn = real_aio_poll_single();
        return fn ? fn(id, stateOut) : SCE_KERNEL_ERROR_EIO;
    }

    SceKernelAioSubmitId children[SCE_KERNEL_AIO_REQUEST_NUM_MAX]{};
    int childCount = 0;
    {
        PackState& state = pack_state();
        AmprLockGuard lock(state.m);
        VirtualAioGroupSlot* group =
            lookup_virtual_aio_group_locked(state, id);
        if (!group) {
            *stateOut = SCE_KERNEL_ERROR_ESRCH;
            return 0;
        }
        childCount = static_cast<int>(group->childCount);
        if (childCount <= 0 || childCount > SCE_KERNEL_AIO_REQUEST_NUM_MAX) {
            return SCE_KERNEL_ERROR_EIO;
        }
        std::memcpy(children, group->children,
                    static_cast<size_t>(childCount) * sizeof(children[0]));
    }

    int childStates[SCE_KERNEL_AIO_REQUEST_NUM_MAX]{};
    const int pollRc = sceKernelAioPollRequests(
        children, childCount, childStates);
    if (pollRc != 0) return pollRc;
    bool terminal = true;
    bool aborted = false;
    for (int i = 0; i < childCount; ++i) {
        if (childStates[i] < 0) {
            *stateOut = childStates[i];
            return 0;
        }
        if ((childStates[i] & ~SCE_KERNEL_AIO_STATE_NOTIFIED) ==
            SCE_KERNEL_AIO_STATE_ABORTED) {
            aborted = true;
        } else if ((childStates[i] & ~SCE_KERNEL_AIO_STATE_NOTIFIED) !=
                   SCE_KERNEL_AIO_STATE_COMPLETED) {
            terminal = false;
        }
    }
    *stateOut = terminal
        ? (aborted ? SCE_KERNEL_AIO_STATE_ABORTED
                   : SCE_KERNEL_AIO_STATE_COMPLETED)
        : 0;
    return 0;
#endif
}

extern "C" int sceKernelAioWaitRequest(SceKernelAioSubmitId id,
                                         int* stateOut,
                                         SceKernelUseconds* usec) {
    if (!stateOut) return SCE_KERNEL_ERROR_EINVAL;
#if !AMPR_EMU_PACK_ENABLE
    KernelAioWaitSingleFn fn = real_aio_wait_single();
    return fn ? fn(id, stateOut, usec) : SCE_KERNEL_ERROR_EIO;
#else
    if (!decode_virtual_aio(id, nullptr, nullptr) &&
        !decode_virtual_aio_group(id, nullptr, nullptr)) {
        KernelAioWaitSingleFn fn = real_aio_wait_single();
        return fn ? fn(id, stateOut, usec) : SCE_KERNEL_ERROR_EIO;
    }
    return sceKernelAioWaitRequests(
        &id, 1, stateOut, SCE_KERNEL_AIO_WAIT_AND, usec);
#endif
}

extern "C" int sceKernelAioCancelRequest(SceKernelAioSubmitId id,
                                           int* stateOut) {
    if (!stateOut) return SCE_KERNEL_ERROR_EINVAL;
#if !AMPR_EMU_PACK_ENABLE
    KernelAioCancelSingleFn fn = real_aio_cancel_single();
    return fn ? fn(id, stateOut) : SCE_KERNEL_ERROR_EIO;
#else
    if (decode_virtual_aio(id, nullptr, nullptr)) {
        return sceKernelAioCancelRequests(&id, 1, stateOut);
    }
    if (!decode_virtual_aio_group(id, nullptr, nullptr)) {
        KernelAioCancelSingleFn fn = real_aio_cancel_single();
        return fn ? fn(id, stateOut) : SCE_KERNEL_ERROR_EIO;
    }

    SceKernelAioSubmitId children[SCE_KERNEL_AIO_REQUEST_NUM_MAX]{};
    int childCount = 0;
    {
        PackState& state = pack_state();
        AmprLockGuard lock(state.m);
        VirtualAioGroupSlot* group =
            lookup_virtual_aio_group_locked(state, id);
        if (!group) {
            *stateOut = SCE_KERNEL_ERROR_ESRCH;
            return 0;
        }
        childCount = static_cast<int>(group->childCount);
        if (childCount <= 0 || childCount > SCE_KERNEL_AIO_REQUEST_NUM_MAX) {
            return SCE_KERNEL_ERROR_EIO;
        }
        std::memcpy(children, group->children,
                    static_cast<size_t>(childCount) * sizeof(children[0]));
    }

    int childStates[SCE_KERNEL_AIO_REQUEST_NUM_MAX]{};
    const int cancelRc = sceKernelAioCancelRequests(
        children, childCount, childStates);
    if (cancelRc != 0) return cancelRc;
    int aggregate = SCE_KERNEL_AIO_STATE_COMPLETED;
    for (int i = 0; i < childCount; ++i) {
        if (childStates[i] < 0) {
            aggregate = childStates[i];
            break;
        }
        const int child = childStates[i] & ~SCE_KERNEL_AIO_STATE_NOTIFIED;
        if (child == SCE_KERNEL_AIO_STATE_ABORTED) {
            aggregate = SCE_KERNEL_AIO_STATE_ABORTED;
        } else if (child == SCE_KERNEL_AIO_STATE_PROCESSING &&
                   aggregate != SCE_KERNEL_AIO_STATE_ABORTED) {
            aggregate = SCE_KERNEL_AIO_STATE_PROCESSING;
        } else if (child == SCE_KERNEL_AIO_STATE_SUBMITTED &&
                   aggregate == SCE_KERNEL_AIO_STATE_COMPLETED) {
            aggregate = SCE_KERNEL_AIO_STATE_SUBMITTED;
        }
    }
    *stateOut = aggregate;
    return 0;
#endif
}

extern "C" int sceKernelAioDeleteRequest(SceKernelAioSubmitId id,
                                           int* resultOut) {
    if (!resultOut) return SCE_KERNEL_ERROR_EINVAL;
#if !AMPR_EMU_PACK_ENABLE
    KernelAioDeleteSingleFn fn = real_aio_delete_single();
    return fn ? fn(id, resultOut) : SCE_KERNEL_ERROR_EIO;
#else
    if (decode_virtual_aio(id, nullptr, nullptr)) {
        return sceKernelAioDeleteRequests(&id, 1, resultOut);
    }
    if (!decode_virtual_aio_group(id, nullptr, nullptr)) {
        KernelAioDeleteSingleFn fn = real_aio_delete_single();
        return fn ? fn(id, resultOut) : SCE_KERNEL_ERROR_EIO;
    }

    SceKernelAioSubmitId children[SCE_KERNEL_AIO_REQUEST_NUM_MAX]{};
    int childCount = 0;
    {
        PackState& state = pack_state();
        AmprLockGuard lock(state.m);
        VirtualAioGroupSlot* group =
            lookup_virtual_aio_group_locked(state, id);
        if (!group) return SCE_KERNEL_ERROR_ESRCH;
        childCount = static_cast<int>(group->childCount);
        if (childCount <= 0 || childCount > SCE_KERNEL_AIO_REQUEST_NUM_MAX) {
            return SCE_KERNEL_ERROR_EIO;
        }
        std::memcpy(children, group->children,
                    static_cast<size_t>(childCount) * sizeof(children[0]));
    }

    int childResults[SCE_KERNEL_AIO_REQUEST_NUM_MAX]{};
    const int deleteRc = sceKernelAioDeleteRequests(
        children, childCount, childResults);
    if (deleteRc != 0) return deleteRc;

    PackState& state = pack_state();
    AmprLockGuard lock(state.m);
    uint32_t groupIndex = 0;
    VirtualAioGroupSlot* group =
        lookup_virtual_aio_group_locked(state, id, &groupIndex);
    if (!group) return SCE_KERNEL_ERROR_ESRCH;
    uint16_t remaining = 0;
    for (int i = 0; i < childCount; ++i) {
        if (childResults[i] == SCE_KERNEL_ERROR_EBUSY) {
            group->children[remaining++] = children[i];
        } else if (childResults[i] != 0 && group->deleteResult == 0) {
            group->deleteResult = childResults[i];
        }
    }
    group->childCount = remaining;
    if (remaining != 0) {
        *resultOut = SCE_KERNEL_ERROR_EBUSY;
        return 0;
    }
    *resultOut = group->deleteResult;
    free_virtual_aio_group_locked(state, groupIndex);
    return 0;
#endif
}


#if AMPR_EMU_PACK_ENABLE && AMPR_EMU_PACK_INTERCEPT_PROCESS_AIO
extern "C" int sceKernelAioSubmitReadCommands_emul(
    SceKernelAioRWRequest requests[], int count, int priority,
    SceKernelAioSubmitId* id) {
    return ampr_klog_io_hook_result(
        "sceKernelAioSubmitReadCommands",
        sceKernelAioSubmitReadCommands(requests, count, priority, id));
}

extern "C" int sceKernelAioSubmitReadCommandsMultiple_emul(
    SceKernelAioRWRequest requests[], int count, int priority,
    SceKernelAioSubmitId ids[]) {
    return ampr_klog_io_hook_result(
        "sceKernelAioSubmitReadCommandsMultiple",
        sceKernelAioSubmitReadCommandsMultiple(
            requests, count, priority, ids));
}

extern "C" int sceKernelAioPollRequest_emul(
    SceKernelAioSubmitId id, int* state) {
    const int rc = sceKernelAioPollRequest(id, state);
#if AMPR_EMU_DEBUG_LOG
    if (rc == 0 && state) {
        ampr_klog_io_hook_output_error(
            "sceKernelAioPollRequest", "state", -1, *state);
    }
#endif
    return ampr_klog_io_hook_result("sceKernelAioPollRequest", rc);
}

extern "C" int sceKernelAioPollRequests_emul(
    SceKernelAioSubmitId ids[], int count, int states[]) {
    const int rc = sceKernelAioPollRequests(ids, count, states);
#if AMPR_EMU_DEBUG_LOG
    if (rc == 0 && states) {
        for (int i = 0; i < count; ++i) {
            ampr_klog_io_hook_output_error(
                "sceKernelAioPollRequests", "states", i, states[i]);
        }
    }
#endif
    return ampr_klog_io_hook_result("sceKernelAioPollRequests", rc);
}

extern "C" int sceKernelAioWaitRequest_emul(
    SceKernelAioSubmitId id, int* state, SceKernelUseconds* usec) {
    const int rc = sceKernelAioWaitRequest(id, state, usec);
#if AMPR_EMU_DEBUG_LOG
    if (rc == 0 && state) {
        ampr_klog_io_hook_output_error(
            "sceKernelAioWaitRequest", "state", -1, *state);
    }
#endif
    return ampr_klog_io_hook_result("sceKernelAioWaitRequest", rc);
}

extern "C" int sceKernelAioWaitRequests_emul(
    SceKernelAioSubmitId ids[], int count, int states[], uint32_t mode,
    SceKernelUseconds* usec) {
    const int rc = sceKernelAioWaitRequests(ids, count, states, mode, usec);
#if AMPR_EMU_DEBUG_LOG
    if (rc == 0 && states) {
        for (int i = 0; i < count; ++i) {
            ampr_klog_io_hook_output_error(
                "sceKernelAioWaitRequests", "states", i, states[i]);
        }
    }
#endif
    return ampr_klog_io_hook_result("sceKernelAioWaitRequests", rc);
}

extern "C" int sceKernelAioCancelRequest_emul(
    SceKernelAioSubmitId id, int* state) {
    const int rc = sceKernelAioCancelRequest(id, state);
#if AMPR_EMU_DEBUG_LOG
    if (rc == 0 && state) {
        ampr_klog_io_hook_output_error(
            "sceKernelAioCancelRequest", "state", -1, *state);
    }
#endif
    return ampr_klog_io_hook_result("sceKernelAioCancelRequest", rc);
}

extern "C" int sceKernelAioCancelRequests_emul(
    SceKernelAioSubmitId ids[], int count, int states[]) {
    const int rc = sceKernelAioCancelRequests(ids, count, states);
#if AMPR_EMU_DEBUG_LOG
    if (rc == 0 && states) {
        for (int i = 0; i < count; ++i) {
            ampr_klog_io_hook_output_error(
                "sceKernelAioCancelRequests", "states", i, states[i]);
        }
    }
#endif
    return ampr_klog_io_hook_result("sceKernelAioCancelRequests", rc);
}

extern "C" int sceKernelAioDeleteRequest_emul(
    SceKernelAioSubmitId id, int* result) {
    const int rc = sceKernelAioDeleteRequest(id, result);
#if AMPR_EMU_DEBUG_LOG
    if (rc == 0 && result) {
        ampr_klog_io_hook_output_error(
            "sceKernelAioDeleteRequest", "result", -1, *result);
    }
#endif
    return ampr_klog_io_hook_result("sceKernelAioDeleteRequest", rc);
}

extern "C" int sceKernelAioDeleteRequests_emul(
    SceKernelAioSubmitId ids[], int count, int results[]) {
    const int rc = sceKernelAioDeleteRequests(ids, count, results);
#if AMPR_EMU_DEBUG_LOG
    if (rc == 0 && results) {
        for (int i = 0; i < count; ++i) {
            ampr_klog_io_hook_output_error(
                "sceKernelAioDeleteRequests", "results", i, results[i]);
        }
    }
#endif
    return ampr_klog_io_hook_result("sceKernelAioDeleteRequests", rc);
}
#endif
