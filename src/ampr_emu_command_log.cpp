/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Optional raw submit-time AMPR command journal.
 */

#include "ampr_emu_command_log.h"

#if AMPR_EMU_COMMAND_LOG

#include "ampr_emu_kernel_lookup.h"
#include "ampr_emu_log.h"
#include "ampr_emu_sync.h"
#include "ampr_libkernel_hook.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include <_kernel.h>
#include <fcntl.h>
#include <time.h>

namespace sce::Ampr::Emu {
namespace {

static constexpr char kCommandLogMagic[8] = {'A', 'M', 'P', 'R', 'C', 'M', 'D', '1'};
static constexpr uint16_t kCommandLogVersion = 1u;

#pragma pack(push, 1)
struct CommandLogRecordHeaderV1 {
    char magic[8];
    uint16_t version;
    uint16_t headerBytes;
    uint32_t recordBytes;
    uint64_t sequence;
    uint64_t utcNs;
    uint64_t monotonicNs;
    uint64_t submitCookie;
    uint64_t sourceAddress;
    uint64_t payloadHash;
    uint32_t payloadBytes;
    uint32_t sourceCapacity;
    uint32_t commandCount;
    uint32_t priority;
    uint32_t domain;
    uint32_t submitMode;
    uint32_t submitType;
    uint32_t flags;
};
#pragma pack(pop)

static_assert(sizeof(CommandLogRecordHeaderV1) == 96u,
              "AMPR command-log record header ABI changed");
static_assert(AMPR_EMU_COMMAND_LOG_QUEUE_BYTES > sizeof(CommandLogRecordHeaderV1),
              "AMPR command-log queue is too small");
static_assert(AMPR_EMU_COMMAND_LOG_MAX_RECORD_BYTES >= sizeof(CommandLogRecordHeaderV1),
              "AMPR command-log max record is too small");
static_assert(AMPR_EMU_COMMAND_LOG_MAX_RECORD_BYTES <= AMPR_EMU_COMMAND_LOG_QUEUE_BYTES,
              "AMPR command-log max record must fit in the queue");

alignas(64) uint8_t g_commandLogQueue[AMPR_EMU_COMMAND_LOG_QUEUE_BYTES]{};

struct CommandLogState {
    AmprMutex mutex{};
    AmprConditionVariable cv{};
    uint64_t sequence{};

    size_t queueHead{};
    size_t queueTail{};
    size_t queueUsed{};
    size_t queueRecords{};
    size_t queueHighWaterBytes{};

    std::atomic<uint64_t> enqueuedRecords{0};
    std::atomic<uint64_t> writtenRecords{0};
    std::atomic<uint64_t> droppedRecords{0};
    std::atomic<uint64_t> droppedBytes{0};
    uint64_t writerMaxWriteNs{};
    uint64_t writerSlowWriteCount{};

    // The file descriptor is owned exclusively by the writer thread. Submit
    // threads must never open/write/fsync/close the command journal.
    int fd{-1};
    bool truncateOnNextOpen{true};
    bool openFailureReported{false};
    bool writeFailureReported{false};

    std::atomic<bool> writerStarted{false};
    std::atomic<bool> writerStop{false};
    std::atomic<bool> shutdownRequested{false};
    std::atomic<bool> permanentlyFailed{false};
    ScePthread writer{};
    bool writerJoinable{false};
};

CommandLogState& commandLogState() {
    static CommandLogState state{};
    return state;
}

uint64_t commandLogUtcNs() {
    SceKernelTimeval now{};
    if (sceKernelGettimeofday(&now) != 0 || now.tv_sec < 0 || now.tv_usec < 0) {
        return 0;
    }
    return static_cast<uint64_t>(now.tv_sec) * 1000000000ull +
           static_cast<uint64_t>(now.tv_usec) * 1000ull;
}

uint64_t commandLogMonotonicNs() {
    timespec now{};
    if (sceKernelClockGettime(SCE_KERNEL_CLOCK_MONOTONIC, &now) != 0 ||
        now.tv_sec < 0 || now.tv_nsec < 0) {
        return 0;
    }
    return static_cast<uint64_t>(now.tv_sec) * 1000000000ull +
           static_cast<uint64_t>(now.tv_nsec);
}

uint64_t commandLogPayloadHashRing(size_t offset, uint32_t bytes) {
    const size_t capacity = sizeof(g_commandLogQueue);
    uint64_t h = 1469598103934665603ull;
    for (uint32_t i = 0; i < bytes; ++i) {
        h ^= g_commandLogQueue[offset];
        h *= 1099511628211ull;
        if (++offset == capacity) {
            offset = 0;
        }
    }
    return h ? h : 1ull;
}

struct CommandLogUtcAnchor {
    uint64_t utcNs{};
    uint64_t monotonicNs{};
};

CommandLogUtcAnchor commandLogCaptureUtcAnchor() {
    const uint64_t monoBeforeNs = commandLogMonotonicNs();
    const uint64_t utcNs = commandLogUtcNs();
    const uint64_t monoAfterNs = commandLogMonotonicNs();

    CommandLogUtcAnchor anchor{};
    anchor.utcNs = utcNs;
    if (monoBeforeNs != 0 && monoAfterNs >= monoBeforeNs) {
        anchor.monotonicNs = monoBeforeNs + (monoAfterNs - monoBeforeNs) / 2u;
    } else {
        anchor.monotonicNs = monoAfterNs != 0 ? monoAfterNs : monoBeforeNs;
    }
    return anchor;
}

uint64_t commandLogUtcFromMonotonic(const CommandLogUtcAnchor& anchor,
                                    uint64_t monotonicNs) {
    if (anchor.utcNs == 0 || anchor.monotonicNs == 0 || monotonicNs == 0) {
        return 0;
    }
    if (monotonicNs >= anchor.monotonicNs) {
        const uint64_t delta = monotonicNs - anchor.monotonicNs;
        return delta <= UINT64_MAX - anchor.utcNs ? anchor.utcNs + delta : 0;
    }
    const uint64_t delta = anchor.monotonicNs - monotonicNs;
    return delta <= anchor.utcNs ? anchor.utcNs - delta : 0;
}

void commandLogRingCopyIn(size_t offset, const void* data, size_t bytes) {
    if (!data || bytes == 0) {
        return;
    }
    const auto* src = static_cast<const uint8_t*>(data);
    const size_t capacity = sizeof(g_commandLogQueue);
    const size_t first = bytes < capacity - offset ? bytes : capacity - offset;
    std::memcpy(g_commandLogQueue + offset, src, first);
    if (bytes > first) {
        std::memcpy(g_commandLogQueue, src + first, bytes - first);
    }
}

void commandLogRingCopyOut(size_t offset, void* data, size_t bytes) {
    if (!data || bytes == 0) {
        return;
    }
    auto* dst = static_cast<uint8_t*>(data);
    const size_t capacity = sizeof(g_commandLogQueue);
    const size_t first = bytes < capacity - offset ? bytes : capacity - offset;
    std::memcpy(dst, g_commandLogQueue + offset, first);
    if (bytes > first) {
        std::memcpy(dst + first, g_commandLogQueue, bytes - first);
    }
}

int commandLogOpenOriginal(const char* path, int flags, SceKernelMode mode) {
    if (amprLibkernelHooksInstalled()) {
        using Fn = int (*)(const char*, int, SceKernelMode);
        if (Fn fn = ampr_fixed_kernel_slot<Fn>(kAmprLibkernelHook_sceKernelOpen)) {
            return fn(path, flags, mode);
        }
    }
    return sceKernelOpen(path, flags, mode);
}

int commandLogOpenForWriter(CommandLogState& state) {
    if (state.fd >= 0) {
        return state.fd;
    }
    const int flags = SCE_KERNEL_O_WRONLY | SCE_KERNEL_O_CREAT |
        (state.truncateOnNextOpen ? SCE_KERNEL_O_TRUNC : SCE_KERNEL_O_APPEND);
    const int fd = commandLogOpenOriginal(AMPR_EMU_COMMAND_LOG_PATH,
                                          flags,
                                          SCE_KERNEL_S_IRWU);
    if (fd < 0) {
        if (!state.openFailureReported) {
            state.openFailureReported = true;
            AMPR_LOGF("ampr.commandLog.open.fail path=%s rc=0x%x writer=async",
                      AMPR_EMU_COMMAND_LOG_PATH,
                      fd);
        }
        return fd;
    }
    state.fd = fd;
    state.truncateOnNextOpen = false;
    state.openFailureReported = false;
    return fd;
}

void commandLogCloseForWriter(CommandLogState& state) {
    const int fd = state.fd;
    state.fd = -1;
    if (fd >= 0) {
#if AMPR_EMU_COMMAND_LOG_FSYNC_ON_SHUTDOWN
        (void)sceKernelFsync(fd);
#endif
        (void)sceKernelClose(fd);
    }
}

bool commandLogWriteAllForWriter(CommandLogState& state,
                                 const void* data,
                                 size_t bytes) {
    if (!data || bytes == 0) {
        return true;
    }
    if (commandLogOpenForWriter(state) < 0) {
        return false;
    }
    const auto* p = static_cast<const uint8_t*>(data);
    size_t done = 0;
    while (done < bytes) {
        const ssize_t written = sceKernelWrite(state.fd, p + done, bytes - done);
        if (written <= 0) {
            if (!state.writeFailureReported) {
                state.writeFailureReported = true;
                AMPR_LOGF("ampr.commandLog.write.fail path=%s fd=%d written=%lld remaining=0x%llx writer=async action=disable",
                          AMPR_EMU_COMMAND_LOG_PATH,
                          state.fd,
                          static_cast<long long>(written),
                          static_cast<unsigned long long>(bytes - done));
            }
            commandLogCloseForWriter(state);
            state.permanentlyFailed.store(true, std::memory_order_release);
            return false;
        }
        done += static_cast<size_t>(written);
    }
    state.writeFailureReported = false;
    return true;
}

bool commandLogWriteQueuedRecordForWriter(CommandLogState& state,
                                          size_t recordOffset,
                                          size_t recordBytes) {
    const size_t capacity = sizeof(g_commandLogQueue);
    const size_t first = recordBytes < capacity - recordOffset
        ? recordBytes
        : capacity - recordOffset;
    if (!commandLogWriteAllForWriter(state, g_commandLogQueue + recordOffset, first)) {
        return false;
    }
    if (recordBytes > first &&
        !commandLogWriteAllForWriter(state, g_commandLogQueue, recordBytes - first)) {
        return false;
    }
    return true;
}

void commandLogReportDropsForWriter(CommandLogState& state,
                                    uint64_t& reportedDrops) {
    const uint64_t dropped = state.droppedRecords.load(std::memory_order_acquire);
    if (dropped == reportedDrops) {
        return;
    }
    const uint64_t droppedBytes = state.droppedBytes.load(std::memory_order_acquire);
    size_t highWater = 0;
    {
        AmprLockGuard guard(state.mutex);
        highWater = state.queueHighWaterBytes;
    }
    AMPR_LOGF("ampr.commandLog.queue.drop records=%llu bytes=0x%llx queueBytes=0x%llx highWater=0x%llx policy=nonblocking",
              static_cast<unsigned long long>(dropped),
              static_cast<unsigned long long>(droppedBytes),
              static_cast<unsigned long long>(sizeof(g_commandLogQueue)),
              static_cast<unsigned long long>(highWater));
    reportedDrops = dropped;
}

void commandLogDiscardQueueAfterFailure(CommandLogState& state) {
    AmprLockGuard guard(state.mutex);
    state.queueHead = state.queueTail;
    state.queueUsed = 0;
    state.queueRecords = 0;
}

void* commandLogWriterMain(void* arg) {
    auto* state = static_cast<CommandLogState*>(arg);
    if (!state) {
        return nullptr;
    }
    (void)scePthreadRename(scePthreadSelf(), "ampr_cmd_writer");

    const CommandLogUtcAnchor utcAnchor = commandLogCaptureUtcAnchor();
    uint64_t reportedDrops = 0;
    for (;;) {
        size_t recordOffset = 0;
        size_t recordBytes = 0;
        CommandLogRecordHeaderV1 recordHeader{};
        bool haveRecord = false;
        bool shouldStop = false;
        bool corruptQueue = false;

        {
            AmprUniqueLock lock(state->mutex);
            state->cv.wait(lock, [&]() {
                return state->queueUsed != 0 ||
                       state->writerStop.load(std::memory_order_acquire) ||
                       state->permanentlyFailed.load(std::memory_order_acquire) ||
                       state->droppedRecords.load(std::memory_order_acquire) != reportedDrops;
            });

            shouldStop = state->writerStop.load(std::memory_order_acquire);
            if (state->permanentlyFailed.load(std::memory_order_acquire)) {
                lock.unlock();
                commandLogDiscardQueueAfterFailure(*state);
                break;
            }

            if (state->queueUsed != 0) {
                if (state->queueUsed < sizeof(recordHeader)) {
                    corruptQueue = true;
                } else {
                    commandLogRingCopyOut(state->queueHead,
                                          &recordHeader,
                                          sizeof(recordHeader));
                    if (std::memcmp(recordHeader.magic,
                                    kCommandLogMagic,
                                    sizeof(recordHeader.magic)) != 0 ||
                        recordHeader.version != kCommandLogVersion ||
                        recordHeader.headerBytes != sizeof(recordHeader) ||
                        recordHeader.recordBytes < sizeof(recordHeader) ||
                        recordHeader.recordBytes > state->queueUsed ||
                        recordHeader.recordBytes > sizeof(g_commandLogQueue) ||
                        recordHeader.payloadBytes !=
                            recordHeader.recordBytes - sizeof(recordHeader)) {
                        corruptQueue = true;
                    } else {
                        recordOffset = state->queueHead;
                        recordBytes = recordHeader.recordBytes;
                        haveRecord = true;
                    }
                }
            } else if (shouldStop) {
                break;
            }
        }

        commandLogReportDropsForWriter(*state, reportedDrops);

        if (corruptQueue) {
            AMPR_LOGF("ampr.commandLog.queue.corrupt action=disable writer=async");
            state->permanentlyFailed.store(true, std::memory_order_release);
            commandLogDiscardQueueAfterFailure(*state);
            break;
        }
        if (!haveRecord) {
            continue;
        }

        // Complete the expensive metadata in the writer thread. The producer
        // captured only monotonic submit time and copied the payload into the
        // ring; it never scans the payload or calls gettimeofday(). The head
        // record is immutable until this single consumer retires it.
        const size_t payloadOffset =
            (recordOffset + sizeof(recordHeader)) % sizeof(g_commandLogQueue);
        recordHeader.utcNs = commandLogUtcFromMonotonic(utcAnchor,
                                                        recordHeader.monotonicNs);
        recordHeader.payloadHash =
            commandLogPayloadHashRing(payloadOffset, recordHeader.payloadBytes);
        commandLogRingCopyIn(recordOffset, &recordHeader, sizeof(recordHeader));

        if (state->fd < 0 && commandLogOpenForWriter(*state) < 0) {
            if (shouldStop) {
                state->permanentlyFailed.store(true, std::memory_order_release);
                commandLogDiscardQueueAfterFailure(*state);
                break;
            }
            (void)sceKernelUsleep(10000u);
            continue;
        }

        const uint64_t writeStartNs = commandLogMonotonicNs();
        if (!commandLogWriteQueuedRecordForWriter(*state, recordOffset, recordBytes)) {
            commandLogDiscardQueueAfterFailure(*state);
            break;
        }
        const uint64_t writeEndNs = commandLogMonotonicNs();
        const uint64_t writeNs = writeStartNs != 0 && writeEndNs >= writeStartNs
            ? writeEndNs - writeStartNs
            : 0;
        if (writeNs > state->writerMaxWriteNs) {
            state->writerMaxWriteNs = writeNs;
        }
#if AMPR_EMU_COMMAND_LOG_SLOW_WRITE_MS != 0
        if (writeNs >= static_cast<uint64_t>(AMPR_EMU_COMMAND_LOG_SLOW_WRITE_MS) * 1000000ull) {
            ++state->writerSlowWriteCount;
            if (state->writerSlowWriteCount <= 8u ||
                (state->writerSlowWriteCount & 0xffu) == 0u) {
                AMPR_LOGF("ampr.commandLog.writer.slow writeUs=%llu recordBytes=0x%llx slowCount=%llu writer=async",
                          static_cast<unsigned long long>(writeNs / 1000ull),
                          static_cast<unsigned long long>(recordBytes),
                          static_cast<unsigned long long>(state->writerSlowWriteCount));
            }
        }
#endif

        {
            AmprLockGuard guard(state->mutex);
            // There is exactly one consumer, and producers only append at the
            // tail, so the head record remains immutable until the writer
            // explicitly retires it after the kernel write has completed.
            if (state->queueHead != recordOffset ||
                state->queueUsed < recordBytes || state->queueRecords == 0) {
                state->permanentlyFailed.store(true, std::memory_order_release);
            } else {
                state->queueHead = (state->queueHead + recordBytes) % sizeof(g_commandLogQueue);
                state->queueUsed -= recordBytes;
                --state->queueRecords;
                state->writtenRecords.fetch_add(1u, std::memory_order_relaxed);
            }
        }
        if (state->permanentlyFailed.load(std::memory_order_acquire)) {
            AMPR_LOGF("ampr.commandLog.queue.state.invalid action=disable writer=async");
            commandLogDiscardQueueAfterFailure(*state);
            break;
        }
    }

    commandLogReportDropsForWriter(*state, reportedDrops);
    commandLogCloseForWriter(*state);
    size_t highWater = 0;
    {
        AmprLockGuard guard(state->mutex);
        highWater = state->queueHighWaterBytes;
    }
    AMPR_LOGF("ampr.commandLog.summary enqueued=%llu written=%llu dropped=%llu droppedBytes=0x%llx queueHighWater=0x%llx queueBytes=0x%llx maxWriteUs=%llu slowWrites=%llu writer=async",
              static_cast<unsigned long long>(state->enqueuedRecords.load(std::memory_order_acquire)),
              static_cast<unsigned long long>(state->writtenRecords.load(std::memory_order_acquire)),
              static_cast<unsigned long long>(state->droppedRecords.load(std::memory_order_acquire)),
              static_cast<unsigned long long>(state->droppedBytes.load(std::memory_order_acquire)),
              static_cast<unsigned long long>(highWater),
              static_cast<unsigned long long>(sizeof(g_commandLogQueue)),
              static_cast<unsigned long long>(state->writerMaxWriteNs / 1000ull),
              static_cast<unsigned long long>(state->writerSlowWriteCount));
    return nullptr;
}

} // namespace

void startCommandLog() {
    CommandLogState& state = commandLogState();
    if (state.writerStarted.load(std::memory_order_acquire) ||
        state.shutdownRequested.load(std::memory_order_acquire) ||
        state.permanentlyFailed.load(std::memory_order_acquire)) {
        return;
    }

    AmprUniqueLock lock(state.mutex);
    if (state.writerStarted.load(std::memory_order_acquire) ||
        state.shutdownRequested.load(std::memory_order_acquire) ||
        state.permanentlyFailed.load(std::memory_order_acquire)) {
        return;
    }

    state.writerStop.store(false, std::memory_order_release);
    ScePthread thread{};
    const int rc = scePthreadCreate(&thread,
                                    nullptr,
                                    commandLogWriterMain,
                                    &state,
                                    "ampr_cmd_writer");
    if (rc != 0) {
        state.permanentlyFailed.store(true, std::memory_order_release);
        lock.unlock();
        AMPR_LOGF("ampr.commandLog.writer.start.fail rc=0x%x action=disable", rc);
        return;
    }
    state.writer = thread;
    state.writerJoinable = true;
    state.writerStarted.store(true, std::memory_order_release);
    lock.unlock();
    AMPR_LOGF("ampr.commandLog.writer.start path=%s queueBytes=0x%llx maxRecordBytes=0x%llx mode=0x%x writer=async",
              AMPR_EMU_COMMAND_LOG_PATH,
              static_cast<unsigned long long>(sizeof(g_commandLogQueue)),
              static_cast<unsigned long long>(AMPR_EMU_COMMAND_LOG_MAX_RECORD_BYTES),
              static_cast<unsigned>(AMPR_EMU_COMMAND_LOG));
}

void commandLogSubmit(const AmprCommandLogSubmitInfo& info) {
    const uint32_t domainBit = info.domain == AmprCommandLogDomain::Apr ? 1u : 2u;
    if ((static_cast<uint32_t>(AMPR_EMU_COMMAND_LOG) & domainBit) == 0u) {
        return;
    }
    if (!info.buffer || info.bytes == 0u) {
        return;
    }

    CommandLogState& state = commandLogState();
    if (state.shutdownRequested.load(std::memory_order_acquire) ||
        state.permanentlyFailed.load(std::memory_order_acquire)) {
        return;
    }
    // The command-journal writer is started only by startDebugLogWriter().
    // Before the main logging subsystem is active, tracing must be a no-op:
    // submit paths are never allowed to create threads or open files.
    if (!state.writerStarted.load(std::memory_order_acquire)) {
        return;
    }

    const uint64_t wideRecordBytes =
        static_cast<uint64_t>(sizeof(CommandLogRecordHeaderV1)) + info.bytes;
    const bool recordTooLarge =
        wideRecordBytes > UINT32_MAX ||
        wideRecordBytes > AMPR_EMU_COMMAND_LOG_MAX_RECORD_BYTES ||
        wideRecordBytes > sizeof(g_commandLogQueue);
    if (recordTooLarge) {
        {
            AmprLockGuard guard(state.mutex);
            ++state.sequence;
            state.droppedRecords.fetch_add(1u, std::memory_order_relaxed);
            state.droppedBytes.fetch_add(wideRecordBytes, std::memory_order_relaxed);
        }
        state.cv.notify_one();
        return;
    }

    // Keep producer-side metadata deliberately cheap. UTC reconstruction and
    // payload hashing are completed by the writer after this immutable record
    // has been committed to the ring.
    const uint64_t monotonicNs = commandLogMonotonicNs();

    bool queued = false;
    {
        AmprUniqueLock lock(state.mutex);
        if (state.shutdownRequested.load(std::memory_order_acquire) ||
            state.permanentlyFailed.load(std::memory_order_acquire)) {
            return;
        }

        const uint64_t sequence = ++state.sequence;
        const bool queueFull =
            wideRecordBytes > sizeof(g_commandLogQueue) - state.queueUsed;
        if (queueFull) {
            state.droppedRecords.fetch_add(1u, std::memory_order_relaxed);
            state.droppedBytes.fetch_add(wideRecordBytes, std::memory_order_relaxed);
            lock.unlock();
            state.cv.notify_one();
            return;
        }

        CommandLogRecordHeaderV1 header{};
        std::memcpy(header.magic, kCommandLogMagic, sizeof(header.magic));
        header.version = kCommandLogVersion;
        header.headerBytes = static_cast<uint16_t>(sizeof(header));
        header.recordBytes = static_cast<uint32_t>(wideRecordBytes);
        header.sequence = sequence;
        header.utcNs = 0;
        header.monotonicNs = monotonicNs;
        header.submitCookie = info.submitCookie;
        header.sourceAddress = static_cast<uint64_t>(reinterpret_cast<uintptr_t>(info.buffer));
        header.payloadHash = 0;
        header.payloadBytes = info.bytes;
        header.sourceCapacity = info.sourceCapacity;
        header.commandCount = info.commandCount;
        header.priority = info.priority;
        header.domain = static_cast<uint32_t>(info.domain);
        header.submitMode = static_cast<uint32_t>(info.mode);
        header.submitType = info.submitType;
        header.flags = info.flags;

        size_t tail = state.queueTail;
        commandLogRingCopyIn(tail, &header, sizeof(header));
        tail = (tail + sizeof(header)) % sizeof(g_commandLogQueue);
        commandLogRingCopyIn(tail, info.buffer, info.bytes);
        state.queueTail = (state.queueTail + static_cast<size_t>(wideRecordBytes)) %
                          sizeof(g_commandLogQueue);
        state.queueUsed += static_cast<size_t>(wideRecordBytes);
        ++state.queueRecords;
        if (state.queueUsed > state.queueHighWaterBytes) {
            state.queueHighWaterBytes = state.queueUsed;
        }
        state.enqueuedRecords.fetch_add(1u, std::memory_order_relaxed);
        queued = true;
    }

    if (queued) {
        state.cv.notify_one();
    }
}

void shutdownCommandLog() {
    CommandLogState& state = commandLogState();
    state.shutdownRequested.store(true, std::memory_order_release);
    state.writerStop.store(true, std::memory_order_release);

    ScePthread writer{};
    bool joinWriter = false;
    {
        AmprLockGuard guard(state.mutex);
        joinWriter = state.writerStarted.load(std::memory_order_acquire) &&
                     state.writerJoinable;
        writer = state.writer;
        state.writerJoinable = false;
    }
    state.cv.notify_all();

    if (joinWriter) {
        (void)scePthreadJoin(writer, nullptr);
    }
}

} // namespace sce::Ampr::Emu

#endif // AMPR_EMU_COMMAND_LOG
