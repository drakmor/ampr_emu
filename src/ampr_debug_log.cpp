/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Optional debug logger backend.
 */

#include "ampr_debug_log.h"
#include "ampr_emu_kernel_lookup.h"
#include "ampr_libkernel_hook.h"

#include <cstdarg>
#include <cstdio>
#include <_kernel.h>

namespace sce::Ampr::Emu {

void kernelDebugLogf(const char* fmt, ...) {
    if (!fmt || !*fmt) {
        return;
    }

    char body[896]{};
    va_list args;
    va_start(args, fmt);
    const int bodyLen = vsnprintf(body, sizeof(body), fmt, args);
    va_end(args);
    if (bodyLen <= 0) {
        return;
    }
    body[sizeof(body) - 1u] = '\0';

    char line[1024]{};
    const int lineLen = snprintf(line, sizeof(line), "[AMPR_EMU] %s\n", body);
    if (lineLen <= 0) {
        return;
    }
    line[sizeof(line) - 1u] = '\0';

    using KernelDebugOutTextFn = int (*)(int, const char*);
    void* address = nullptr;
    const int dlsymRc = sceKernelDlsym(static_cast<SceKernelModule>(0x2001),
                                       "sceKernelDebugOutText",
                                       &address);
    if (dlsymRc == 0 && address) {
        auto* const debugOut = reinterpret_cast<KernelDebugOutTextFn>(address);
        (void)debugOut(AMPR_EMU_DEBUG_LOG_KERNEL_OUT_CHANNEL, line);
    }
}

} // namespace sce::Ampr::Emu

#if AMPR_EMU_DEBUG_LOG

#include <atomic>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include <_fs.h>
#include <_kernel.h>
#include <_pthread.h>
#include <kernel/semaphore.h>
#include <stdio.h>
#include <time.h>

namespace sce::Ampr::Emu {

#ifndef AMPR_EMU_DEBUG_LOG_PATH
#define AMPR_EMU_DEBUG_LOG_PATH "/app0/apr_emu.log"
#endif

struct AmprDebugLogState {
    std::atomic<bool> enabled{true};
    std::atomic<uint64_t> sequence{0};
    std::atomic<uint64_t> flushedCriticalSequence{0};
    std::atomic<uint32_t> nextThreadTag{1};
    std::atomic_flag queueLock = ATOMIC_FLAG_INIT;
    std::atomic_flag lifecycleLock = ATOMIC_FLAG_INIT;
    ScePthread writer{};
    std::atomic<SceKernelSema> writerWakeSema{SCE_KERNEL_SEMA_ID_INVALID};
    std::atomic<uint32_t> writerSignalers{0};
    int fd{-1};
    bool truncateOnNextOpen{true};
    std::atomic<bool> shutdownRequested{false};
    bool startupInfoQueued{false};
    std::atomic<bool> writerStarted{false};
    bool writerJoinable{false};
    std::atomic<bool> writerStop{false};
    size_t queueHead{0};
    size_t queueCount{0};
    uint64_t droppedLines{0};
    std::atomic<uint64_t> contendedDrops{0};
};

inline AmprDebugLogState& debugLogState() {
    static AmprDebugLogState state{};
    return state;
}

const char* getDebugLogPath() {
    return AMPR_EMU_DEBUG_LOG_PATH;
}

bool getDebugLogEnabled() {
    return debugLogState().enabled.load(std::memory_order_relaxed);
}

void setDebugLogEnabled(bool enabled) {
    debugLogState().enabled.store(enabled, std::memory_order_relaxed);
}

static constexpr size_t kAmprDebugLogLineCapacity = 1024u;
static constexpr size_t kAmprDebugLogQueueCapacity = 4096u;

struct AmprDebugLogEntry {
    uint64_t sequence{};
    uint32_t threadTag{};
    bool critical{};
    char text[kAmprDebugLogLineCapacity]{};
};

inline AmprDebugLogEntry* debugLogQueueStorage() {
    static AmprDebugLogEntry entries[kAmprDebugLogQueueCapacity]{};
    return entries;
}

inline bool debugLogTryLockQueue(AmprDebugLogState& state) {
#if AMPR_EMU_DEBUG_LOG_LOSSLESS
    while (state.queueLock.test_and_set(std::memory_order_acquire)) {
        __builtin_ia32_pause();
    }
    return true;
#else
    if (state.queueLock.test_and_set(std::memory_order_acquire)) {
        state.contendedDrops.fetch_add(1u, std::memory_order_relaxed);
        return false;
    }
    return true;
#endif
}

inline void debugLogUnlockQueue(AmprDebugLogState& state) {
    state.queueLock.clear(std::memory_order_release);
}

inline bool debugLogTryLockQueueForWriter(AmprDebugLogState& state) {
    return !state.queueLock.test_and_set(std::memory_order_acquire);
}

inline void debugLogSignalWriter(AmprDebugLogState& state) {
    state.writerSignalers.fetch_add(1u);
    const SceKernelSema sema = state.writerWakeSema.load();
    if (sema != SCE_KERNEL_SEMA_ID_INVALID) {
        // A binary semaphore coalesces bursts. A signal against an already-set
        // semaphore can fail harmlessly because one wakeup drains the queue.
        (void)sceKernelSignalSema(sema, 1);
    }
    state.writerSignalers.fetch_sub(1u);
}

inline void debugLogDeleteWriterWakeSema(AmprDebugLogState& state) {
    const SceKernelSema retiredSema =
        state.writerWakeSema.exchange(SCE_KERNEL_SEMA_ID_INVALID);
    while (state.writerSignalers.load() != 0) {
        (void)sceKernelUsleep(50ll);
    }
    if (retiredSema != SCE_KERNEL_SEMA_ID_INVALID) {
        (void)sceKernelDeleteSema(retiredSema);
    }
}

inline bool debugLogTryLockLifecycle(AmprDebugLogState& state) {
    return !state.lifecycleLock.test_and_set(std::memory_order_acquire);
}

inline void debugLogUnlockLifecycle(AmprDebugLogState& state) {
    state.lifecycleLock.clear(std::memory_order_release);
}

inline uint32_t debugLogThreadTag() {
    static thread_local uint32_t tag = debugLogState().nextThreadTag.fetch_add(1u, std::memory_order_relaxed);
    return tag;
}

inline void debugLogFormatEventTime(char* out, size_t outSize) {
    if (!out || outSize == 0) {
        return;
    }
    out[0] = '\0';

    SceKernelTimeval now {};
    if (sceKernelGettimeofday(&now) != 0 || now.tv_sec < 0) {
        snprintf(out, outSize, "unavailable");
        return;
    }

    const time_t raw = static_cast<time_t>(now.tv_sec);
    struct tm utc {};
    char date[32] {};
    if (!gmtime_s(&raw, &utc) || strftime(date, sizeof(date), "%Y-%m-%dT%H:%M:%S", &utc) == 0) {
        snprintf(out, outSize, "unavailable");
        return;
    }

    snprintf(out, outSize, "%s.%06lldZ", date, static_cast<long long>(now.tv_usec));
}

inline int debugLogKernelOpen(const char* path, int flags, SceKernelMode mode) {
    if (!amprLibkernelHooksInstalled()) {
        return -1;
    }
    using Fn = int (*)(const char*, int, SceKernelMode);
    Fn fn = ampr_fixed_kernel_slot<Fn>(kAmprLibkernelHook_sceKernelOpen);
    return fn(path, flags, mode);
}

inline ssize_t debugLogKernelWrite(int fd, const void* data, size_t len) {
    return sceKernelWrite(fd, data, len);
}

inline int debugLogKernelFsync(int fd) {
    return sceKernelFsync(fd);
}

inline int debugLogKernelClose(int fd) {
    return sceKernelClose(fd);
}

inline int debugLogKernelUsleep(SceKernelUseconds usec) {
    return sceKernelUsleep(usec);
}

using DebugLogKernelOutTextFn = int (*)(int, const char*);

inline bool debugLogKernelOutEnabledFor(bool critical) {
#if AMPR_EMU_DEBUG_LOG_KERNEL_OUT
    (void)critical;
    return true;
#elif AMPR_EMU_DEBUG_LOG_CRITICAL_KERNEL_OUT
    return critical;
#else
    (void)critical;
    return false;
#endif
}

inline DebugLogKernelOutTextFn debugLogKernelOutTextFn() {
#if AMPR_EMU_DEBUG_LOG_KERNEL_OUT || AMPR_EMU_DEBUG_LOG_CRITICAL_KERNEL_OUT
    static DebugLogKernelOutTextFn const cached = []() {
        void* addr = nullptr;
        const int rc = sceKernelDlsym(static_cast<SceKernelModule>(0x2001),
                                      "sceKernelDebugOutText",
                                      &addr);
        return rc == 0 && addr
            ? reinterpret_cast<DebugLogKernelOutTextFn>(addr)
            : nullptr;
    }();
    return cached;
#else
    return nullptr;
#endif
}

inline bool debugLogKernelOutText(const char* text) {
#if AMPR_EMU_DEBUG_LOG_KERNEL_OUT || AMPR_EMU_DEBUG_LOG_CRITICAL_KERNEL_OUT
    static std::atomic<bool> disabled{false};
    if (!text || !*text) {
        return false;
    }
    if (disabled.load(std::memory_order_relaxed)) {
        return false;
    }
    DebugLogKernelOutTextFn fn = debugLogKernelOutTextFn();
    if (fn) {
        const int rc = fn(AMPR_EMU_DEBUG_LOG_KERNEL_OUT_CHANNEL, text);
        if (rc < 0) {
            disabled.store(true, std::memory_order_relaxed);
            return false;
        }
        return true;
    }
    disabled.store(true, std::memory_order_relaxed);
    return false;
#else
    (void)text;
    return false;
#endif
}

inline bool debugLogKernelOutLine(const char* text, bool critical = false) {
#if AMPR_EMU_DEBUG_LOG_KERNEL_OUT || AMPR_EMU_DEBUG_LOG_CRITICAL_KERNEL_OUT
    if (!debugLogKernelOutEnabledFor(critical)) {
        return false;
    }
    if (!text || !*text) {
        return false;
    }
    char line[kAmprDebugLogLineCapacity + 2u];
    const int len = snprintf(line, sizeof(line), "[AMPR_EMU] %s\n", text);
    if (len > 0) {
        line[sizeof(line) - 1u] = '\0';
        return debugLogKernelOutText(line);
    }
    return false;
#else
    (void)text;
    (void)critical;
    return false;
#endif
}

inline int debugLogOpenOnceForWriter(AmprDebugLogState& state) {
    if (state.fd >= 0) {
        return state.fd;
    }
    if (state.shutdownRequested.load(std::memory_order_acquire)) {
        return -1;
    }
    const int flags = SCE_KERNEL_O_WRONLY | SCE_KERNEL_O_CREAT |
        (state.truncateOnNextOpen ? SCE_KERNEL_O_TRUNC : SCE_KERNEL_O_APPEND);
    const int fd = debugLogKernelOpen(getDebugLogPath(), flags, SCE_KERNEL_S_IRWU);
    if (fd >= 0 && !state.shutdownRequested.load(std::memory_order_acquire)) {
        state.fd = fd;
        // Only the first successful open truncates. A reopen after a hard
        // write/fsync failure appends so crash-tail diagnostics are preserved.
        state.truncateOnNextOpen = false;
        return fd;
    }
    if (fd >= 0) {
        (void)debugLogKernelClose(fd);
    }
    return -1;
}

inline void debugLogCloseForWriter(AmprDebugLogState& state) {
    const int fd = state.fd;
    state.fd = -1;
    if (fd >= 0) {
#if AMPR_EMU_DEBUG_LOG_SYNC_FSYNC
        (void)debugLogKernelFsync(fd);
#endif
        (void)debugLogKernelClose(fd);
    }
}

inline bool debugLogWriteAllForWriter(AmprDebugLogState& state, const char* data, size_t len) {
    int fd = debugLogOpenOnceForWriter(state);
    if (fd < 0 || !data || len == 0) {
        return false;
    }

    size_t done = 0;
    while (done < len) {
        const ssize_t wr = debugLogKernelWrite(fd, data + done, len - done);
        if (wr <= 0) {
            debugLogCloseForWriter(state);
            return false;
        }
        done += static_cast<size_t>(wr);
    }
    return true;
}

inline bool debugLogWriteEntryForWriter(AmprDebugLogState& state, const AmprDebugLogEntry& entry) {
    char eventTime[64];
    debugLogFormatEventTime(eventTime, sizeof(eventTime));
    char prefix[96];
    const int prefixLen = snprintf(prefix,
                                   sizeof(prefix),
                                   "[%06llu %s th=%u] ",
                                   static_cast<unsigned long long>(entry.sequence),
                                   eventTime,
                                   entry.threadTag);
    if (prefixLen <= 0) {
        return false;
    }
    const size_t cappedPrefixLen =
        static_cast<size_t>(prefixLen) < sizeof(prefix) ? static_cast<size_t>(prefixLen) : sizeof(prefix) - 1u;
    const size_t textLen = strnlen(entry.text, sizeof(entry.text));
    char line[sizeof(prefix) + kAmprDebugLogLineCapacity + 1u];
    std::memcpy(line, prefix, cappedPrefixLen);
    std::memcpy(line + cappedPrefixLen, entry.text, textLen);
    line[cappedPrefixLen + textLen] = '\n';
    const bool written = debugLogWriteAllForWriter(
        state, line, cappedPrefixLen + textLen + 1u);
    bool durable = written;
#if AMPR_EMU_DEBUG_LOG_SYNC_FSYNC || AMPR_EMU_DEBUG_LOG_CRITICAL_SYNC_FSYNC
    if (written && state.fd >= 0) {
#if AMPR_EMU_DEBUG_LOG_SYNC_FSYNC
        durable = debugLogKernelFsync(state.fd) == 0;
#elif AMPR_EMU_DEBUG_LOG_CRITICAL_SYNC_FSYNC
        if (entry.critical) {
            durable = debugLogKernelFsync(state.fd) == 0;
        }
#endif
    }
#endif
    if (written && !durable) {
        debugLogCloseForWriter(state);
    }
    if (entry.critical && durable) {
        state.flushedCriticalSequence.store(entry.sequence, std::memory_order_release);
    }
    return written && durable;
}

inline void* debugLogWriterMain(void* arg) {
    auto* state = static_cast<AmprDebugLogState*>(arg);
    if (!state) {
        return nullptr;
    }
    for (;;) {
        bool observedEmpty = false;
        bool queueLockContended = false;
        AmprDebugLogEntry entry{};
        for (;;) {
            if (!debugLogTryLockQueueForWriter(*state)) {
                queueLockContended = true;
                break;
            }
            if (state->queueCount == 0) {
                observedEmpty = true;
                debugLogUnlockQueue(*state);
                break;
            }
            AmprDebugLogEntry* entries = debugLogQueueStorage();
            entry = entries[state->queueHead];
            state->queueHead = (state->queueHead + 1u) % kAmprDebugLogQueueCapacity;
            --state->queueCount;
            debugLogUnlockQueue(*state);
            (void)debugLogWriteEntryForWriter(*state, entry);
        }
        if (queueLockContended) {
            // A producer that owns the queue lock is responsible for publishing
            // its entry before unlock. Retry that entry instead of consuming a
            // second semaphore token and losing the original wakeup.
            (void)debugLogKernelUsleep(50ll);
            continue;
        }
        if (state->writerStop.load(std::memory_order_acquire) && observedEmpty) {
            break;
        }

        const SceKernelSema sema = state->writerWakeSema.load(std::memory_order_acquire);
        if (sema == SCE_KERNEL_SEMA_ID_INVALID) {
            if (state->writerStop.load(std::memory_order_acquire)) {
                break;
            }
            // This path is limited to an unexpected synchronization teardown;
            // normal empty-queue waits are event driven.
            (void)debugLogKernelUsleep(500ll);
            continue;
        }
        if (sceKernelWaitSema(sema, 1, nullptr) != 0) {
            // Avoid a hot loop if the SDK wait is interrupted or rejected.
            (void)debugLogKernelUsleep(500ll);
        }
    }
    debugLogCloseForWriter(*state);
    return nullptr;
}

inline void debugLogStartWriterLocked(AmprDebugLogState& state) {
    if (state.writerStarted.load(std::memory_order_acquire) ||
        state.shutdownRequested.load(std::memory_order_acquire)) {
        return;
    }
    SceKernelSema wakeSema = SCE_KERNEL_SEMA_ID_INVALID;
    if (sceKernelCreateSema(&wakeSema,
                            "ampr_log_wake",
                            SCE_KERNEL_SEMA_ATTR_TH_FIFO,
                            0,
                            1,
                            nullptr) == 0) {
        state.writerWakeSema.store(wakeSema, std::memory_order_release);
    }
    state.writerStop.store(false, std::memory_order_release);
    ScePthread thread{};
    const int rc = scePthreadCreate(&thread, nullptr, debugLogWriterMain, &state, "ampr_log_writer");
    if (rc == 0) {
        state.writer = thread;
        state.writerStarted.store(true, std::memory_order_release);
        state.writerJoinable = true;
    } else {
        debugLogDeleteWriterWakeSema(state);
    }
}

void startDebugLogWriter() {
    if (!getDebugLogEnabled()) {
        return;
    }
    auto& state = debugLogState();
    if (!debugLogTryLockLifecycle(state)) {
        return;
    }
    debugLogStartWriterLocked(state);
    debugLogUnlockLifecycle(state);
}

inline bool debugLogPushLocked(AmprDebugLogState& state,
                               uint64_t sequence,
                               uint32_t threadTag,
                               const char* text,
                               bool critical = false) {
    if (state.shutdownRequested.load(std::memory_order_acquire) || !text || !*text) {
        return false;
    }
    if (state.queueCount == kAmprDebugLogQueueCapacity) {
#if AMPR_EMU_DEBUG_LOG_LOSSLESS
        return false;
#else
        state.queueHead = (state.queueHead + 1u) % kAmprDebugLogQueueCapacity;
        --state.queueCount;
        ++state.droppedLines;
#endif
    }
    const size_t index = (state.queueHead + state.queueCount) % kAmprDebugLogQueueCapacity;
    AmprDebugLogEntry* entries = debugLogQueueStorage();
    entries[index].sequence = sequence;
    entries[index].threadTag = threadTag;
    entries[index].critical = critical;
    snprintf(entries[index].text, sizeof(entries[index].text), "%s", text);
    ++state.queueCount;
    return true;
}

inline AmprDebugLogEntry* debugLogReserveLocked(AmprDebugLogState& state,
                                                uint64_t sequence,
                                                uint32_t threadTag,
                                                bool critical) {
    if (state.shutdownRequested.load(std::memory_order_acquire)) {
        return nullptr;
    }
    if (state.queueCount == kAmprDebugLogQueueCapacity) {
#if AMPR_EMU_DEBUG_LOG_LOSSLESS
        return nullptr;
#else
        state.queueHead = (state.queueHead + 1u) % kAmprDebugLogQueueCapacity;
        --state.queueCount;
        ++state.droppedLines;
#endif
    }
    const size_t index = (state.queueHead + state.queueCount) % kAmprDebugLogQueueCapacity;
    AmprDebugLogEntry* entries = debugLogQueueStorage();
    entries[index].sequence = sequence;
    entries[index].threadTag = threadTag;
    entries[index].critical = critical;
    entries[index].text[0] = '\0';
    ++state.queueCount;
    return &entries[index];
}

inline void debugLogDropReservedTailLocked(AmprDebugLogState& state) {
    if (state.queueCount != 0) {
        --state.queueCount;
    }
}

inline bool debugLogCanWaitForQueueSpaceLocked(const AmprDebugLogState& state) {
    return state.writerStarted.load(std::memory_order_acquire) &&
           !state.writerStop.load(std::memory_order_acquire) &&
           !state.shutdownRequested.load(std::memory_order_acquire);
}

inline void debugLogQueueStartupInfoLocked(AmprDebugLogState& state, uint32_t threadTag) {
    if (state.startupInfoQueued) {
        return;
    }
    state.startupInfoQueued = true;
    char versionMessage[256];
    snprintf(versionMessage,
             sizeof(versionMessage),
             "ampr_emu.version version=%s build=%s %s",
             AMPR_EMU_VERSION,
             __DATE__,
             __TIME__);
    const uint64_t versionSeq = state.sequence.fetch_add(1u, std::memory_order_relaxed) + 1u;
    (void)debugLogPushLocked(state, versionSeq, threadTag, versionMessage);

    char hookMessage[256];
    if (amprFormatLibkernelHookStatus(hookMessage, sizeof(hookMessage)) > 0) {
        const uint64_t hookSeq = state.sequence.fetch_add(1u, std::memory_order_relaxed) + 1u;
        (void)debugLogPushLocked(state, hookSeq, threadTag, hookMessage);
    }

    char indexMessage[160];
    snprintf(indexMessage,
             sizeof(indexMessage),
             "apr.index.startup status=not-attempted path=/app0/ampr_emu.index autobuild=%u",
             static_cast<unsigned>(AMPR_EMU_APP0_INDEX_AUTOBUILD != 0));
    const uint64_t indexSeq = state.sequence.fetch_add(1u, std::memory_order_relaxed) + 1u;
    (void)debugLogPushLocked(state, indexSeq, threadTag, indexMessage);

#if AMPR_EMU_TIME_LIMIT_UNIX_SECONDS
    const time_t timeBombRaw = static_cast<time_t>(AMPR_EMU_TIME_LIMIT_UNIX_SECONDS);
    struct tm timeBombUtc {};
    char timeBombDate[32] = "(unavailable)";
    if (gmtime_s(&timeBombRaw, &timeBombUtc)) {
        (void)strftime(timeBombDate, sizeof(timeBombDate), "%Y-%m-%dT%H:%M:%SZ", &timeBombUtc);
    }

    char timeBombMessage[128];
    snprintf(timeBombMessage,
             sizeof(timeBombMessage),
             "ampr_emu.timebomb deadline=%s",
             timeBombDate);
    const uint64_t timeBombSeq = state.sequence.fetch_add(1u, std::memory_order_relaxed) + 1u;
    (void)debugLogPushLocked(state, timeBombSeq, threadTag, timeBombMessage);
#endif
}

inline void debugLogWaitForCriticalFlush(uint64_t sequence, bool critical) {
#if AMPR_EMU_DEBUG_LOG_CRITICAL_SYNC_FSYNC
    if (!critical || sequence == 0) {
        return;
    }
    startDebugLogWriter();
    auto& state = debugLogState();
    uint64_t waitedUs = 0;
    for (;;) {
        if (state.flushedCriticalSequence.load(std::memory_order_acquire) >= sequence ||
            state.shutdownRequested.load(std::memory_order_acquire)) {
            return;
        }
#if AMPR_EMU_DEBUG_LOG_CRITICAL_SYNC_WAIT_US
        if (waitedUs >= static_cast<uint64_t>(AMPR_EMU_DEBUG_LOG_CRITICAL_SYNC_WAIT_US)) {
            return;
        }
#endif
        (void)debugLogKernelUsleep(100ll);
        waitedUs += 100u;
    }
#else
    (void)sequence;
    (void)critical;
#endif
}

inline bool debugLogEnqueueBody(const char* body,
                                bool critical,
                                uint64_t* outSequence,
                                bool* outCritical) {
    if (!body || !*body || !getDebugLogEnabled()) {
        return false;
    }
    if (outSequence) {
        *outSequence = 0;
    }
    if (outCritical) {
        *outCritical = false;
    }
#if AMPR_EMU_DEBUG_LOG_LOSSLESS
    uint32_t fullSpins = 0;
    for (;;) {
        auto& state = debugLogState();
        const uint32_t threadTag = debugLogThreadTag();
        if (!debugLogTryLockQueue(state)) {
            return false;
        }
        if (state.shutdownRequested.load(std::memory_order_acquire) ||
            !state.enabled.load(std::memory_order_relaxed)) {
            debugLogUnlockQueue(state);
            return false;
        }
        const bool wakeWriter = state.queueCount == 0;
        debugLogQueueStartupInfoLocked(state, threadTag);
        const uint64_t seq = state.sequence.fetch_add(1u, std::memory_order_relaxed) + 1u;
        AmprDebugLogEntry* entry = debugLogReserveLocked(state, seq, threadTag, critical);
        if (!entry) {
            state.sequence.fetch_sub(1u, std::memory_order_relaxed);
            if (!debugLogCanWaitForQueueSpaceLocked(state)) {
                ++state.droppedLines;
                debugLogUnlockQueue(state);
                return false;
            }
#if AMPR_EMU_DEBUG_LOG_LOSSLESS_SPIN_LIMIT
            if (++fullSpins >= static_cast<uint32_t>(AMPR_EMU_DEBUG_LOG_LOSSLESS_SPIN_LIMIT)) {
                ++state.droppedLines;
                debugLogUnlockQueue(state);
                return false;
            }
#endif
            debugLogUnlockQueue(state);
            __builtin_ia32_pause();
            continue;
        }
        snprintf(entry->text, sizeof(entry->text), "%s", body);
        debugLogUnlockQueue(state);
        if (wakeWriter) {
            debugLogSignalWriter(state);
        }
        if (outSequence) {
            *outSequence = seq;
        }
        if (outCritical) {
            *outCritical = critical;
        }
        return true;
    }
#else
    auto& state = debugLogState();
    const uint32_t threadTag = debugLogThreadTag();
    if (!debugLogTryLockQueue(state)) {
        return false;
    }
    if (state.shutdownRequested.load(std::memory_order_acquire) ||
        !state.enabled.load(std::memory_order_relaxed)) {
        debugLogUnlockQueue(state);
        return false;
    }
    const bool wakeWriter = state.queueCount == 0;
    debugLogQueueStartupInfoLocked(state, threadTag);
    const uint64_t seq = state.sequence.fetch_add(1u, std::memory_order_relaxed) + 1u;
    AmprDebugLogEntry* entry = debugLogReserveLocked(state, seq, threadTag, critical);
    const bool queued = entry != nullptr;
    if (entry) {
        snprintf(entry->text, sizeof(entry->text), "%s", body);
    }
    debugLogUnlockQueue(state);
    if (queued && wakeWriter) {
        debugLogSignalWriter(state);
    }
    if (queued) {
        if (outSequence) {
            *outSequence = seq;
        }
        if (outCritical) {
            *outCritical = critical;
        }
    }
    return queued;
#endif
}

void shutdownDebugLog() {
    auto& state = debugLogState();
    while (!debugLogTryLockLifecycle(state)) {
        (void)debugLogKernelUsleep(200ll);
    }
    state.shutdownRequested.store(true, std::memory_order_release);
    state.enabled.store(false, std::memory_order_relaxed);
    state.writerStop.store(true, std::memory_order_release);
    const SceKernelSema wakeSema = state.writerWakeSema.load(std::memory_order_acquire);
    if (wakeSema != SCE_KERNEL_SEMA_ID_INVALID) {
        (void)sceKernelSignalSema(wakeSema, 1);
    }
    const bool joinWriter = state.writerStarted.load(std::memory_order_acquire) &&
                            state.writerJoinable;
    const ScePthread writer = state.writer;
    state.writerJoinable = false;
    debugLogUnlockLifecycle(state);

    if (joinWriter) {
        (void)scePthreadJoin(writer, nullptr);
    } else {
        debugLogCloseForWriter(state);
    }
    debugLogDeleteWriterWakeSema(state);
}

void debugLogLine(const char* rawLine) {
    static thread_local bool inLogger = false;
    if (!rawLine || !*rawLine || !getDebugLogEnabled()) {
        return;
    }
    if (inLogger) {
        return;
    }
    inLogger = true;
    debugLogKernelOutLine(rawLine, false);
    uint64_t sequence = 0;
    bool critical = false;
    const bool queued = debugLogEnqueueBody(rawLine, false, &sequence, &critical);
    inLogger = false;
    if (queued) {
        debugLogWaitForCriticalFlush(sequence, critical);
    }
}

static void debugLogV(bool criticalEntry, const char* fmt, va_list args) {
    static thread_local bool inLogger = false;
    if (!fmt || !*fmt || !getDebugLogEnabled() || inLogger) {
        return;
    }
    inLogger = true;
    char line[kAmprDebugLogLineCapacity];
    const int written = vsnprintf(line, sizeof(line), fmt, args);
    if (written <= 0) {
        inLogger = false;
        return;
    }
    line[sizeof(line) - 1u] = '\0';
    debugLogKernelOutLine(line, criticalEntry);
    uint64_t sequence = 0;
    bool queuedCritical = false;
    const bool queued = debugLogEnqueueBody(
        line, criticalEntry, &sequence, &queuedCritical);
    inLogger = false;
    if (queued) {
        debugLogWaitForCriticalFlush(sequence, queuedCritical);
    }
}

void debugLogf(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    debugLogV(false, fmt, args);
    va_end(args);
}

void debugLogCriticalf(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    debugLogV(true, fmt, args);
    va_end(args);
}

} // namespace sce::Ampr::Emu


#endif // AMPR_EMU_DEBUG_LOG
