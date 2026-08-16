/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Small synchronization primitives used by AMPR runtime subsystems.
 */

#pragma once

#include <_kernel.h>
#include <_pthread.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <errno.h>
#include <pthread.h>
#include <sys/sce_errno.h>

extern "C" int sceKernelUsleep(unsigned int usec);

template <typename T>
static inline T&& ampr_move(T& v) { return static_cast<T&&>(v); }

template <typename T>
static inline const T& ampr_min(const T& a, const T& b) { return (a < b) ? a : b; }

static inline void ampr_spin_pause_or_yield(uint32_t& spins) {
    ++spins;
    if (spins < 4096u || (spins & 0xffu) != 0) {
        __builtin_ia32_pause();
        return;
    }
    (void)sceKernelUsleep(1u);
}

class AmprSpinLock {
public:
    explicit AmprSpinLock(std::atomic<uint32_t>* lock) : lock_(lock) {
        uint32_t spins = 0;
        while (lock_->exchange(1u, std::memory_order_acquire) != 0u) {
            ampr_spin_pause_or_yield(spins);
        }
    }

    ~AmprSpinLock() {
        lock_->store(0u, std::memory_order_release);
    }

    AmprSpinLock(const AmprSpinLock&) = delete;
    AmprSpinLock& operator=(const AmprSpinLock&) = delete;

private:
    std::atomic<uint32_t>* lock_;
};

class AmprTrySpinLock {
public:
    explicit AmprTrySpinLock(std::atomic<uint32_t>* lock) : lock_(lock) {
        uint32_t expected = 0;
        owns_ = lock_ &&
                lock_->compare_exchange_strong(expected,
                                               1u,
                                               std::memory_order_acquire,
                                               std::memory_order_relaxed);
    }

    ~AmprTrySpinLock() {
        if (owns_) {
            lock_->store(0u, std::memory_order_release);
        }
    }

    AmprTrySpinLock(const AmprTrySpinLock&) = delete;
    AmprTrySpinLock& operator=(const AmprTrySpinLock&) = delete;

    bool owns_lock() const { return owns_; }

private:
    std::atomic<uint32_t>* lock_{};
    bool owns_{false};
};

class AmprMutex {
public:
    AmprMutex() {
        const int rc = scePthreadMutexInit(&mutex_, nullptr, "ampr_mutex");
        if (rc != 0) {
            __builtin_trap();
        }
    }

    ~AmprMutex() {
        (void)scePthreadMutexDestroy(&mutex_);
    }

    AmprMutex(const AmprMutex&) = delete;
    AmprMutex& operator=(const AmprMutex&) = delete;

    void lock() {
        const int rc = scePthreadMutexLock(&mutex_);
        if (rc != 0) {
            __builtin_trap();
        }
    }

    bool try_lock() {
        const int rc = scePthreadMutexTrylock(&mutex_);
        if (rc == 0) {
            return true;
        }
        if (rc == SCE_KERNEL_ERROR_EBUSY || rc == EBUSY) {
            return false;
        }
        __builtin_trap();
    }

    void unlock() {
        const int rc = scePthreadMutexUnlock(&mutex_);
        if (rc != 0) {
            __builtin_trap();
        }
    }

    ScePthreadMutex* native_handle() {
        return &mutex_;
    }

private:
    ScePthreadMutex mutex_{};
};

class AmprLockGuard {
public:
    explicit AmprLockGuard(AmprMutex& mutex) : mutex_(&mutex) {
        mutex_->lock();
    }

    ~AmprLockGuard() {
        mutex_->unlock();
    }

    AmprLockGuard(const AmprLockGuard&) = delete;
    AmprLockGuard& operator=(const AmprLockGuard&) = delete;

private:
    AmprMutex* mutex_{};
};

struct AmprTryToLockTag {};
static constexpr AmprTryToLockTag AmprTryToLock{};

class AmprUniqueLock {
public:
    explicit AmprUniqueLock(AmprMutex& mutex) : mutex_(&mutex), owns_(true) {
        mutex_->lock();
    }

    AmprUniqueLock(AmprMutex& mutex, AmprTryToLockTag) : mutex_(&mutex), owns_(mutex_->try_lock()) {}

    ~AmprUniqueLock() {
        if (owns_) {
            mutex_->unlock();
        }
    }

    AmprUniqueLock(const AmprUniqueLock&) = delete;
    AmprUniqueLock& operator=(const AmprUniqueLock&) = delete;

    bool owns_lock() const {
        return owns_;
    }

    AmprMutex* mutex() const {
        return mutex_;
    }

    void lock() {
        if (!mutex_ || owns_) {
            __builtin_trap();
        }
        mutex_->lock();
        owns_ = true;
    }

    void unlock() {
        if (!mutex_ || !owns_) {
            __builtin_trap();
        }
        mutex_->unlock();
        owns_ = false;
    }

private:
    AmprMutex* mutex_{};
    bool owns_{false};
};

class AmprConditionVariable {
public:
    AmprConditionVariable() {
        const int rc = scePthreadCondInit(&cond_, nullptr, "ampr_cond");
        if (rc != 0) {
            __builtin_trap();
        }
    }

    ~AmprConditionVariable() {
        (void)scePthreadCondDestroy(&cond_);
    }

    AmprConditionVariable(const AmprConditionVariable&) = delete;
    AmprConditionVariable& operator=(const AmprConditionVariable&) = delete;

    void notify_one() {
        (void)scePthreadCondSignal(&cond_);
    }

    void notify_all() {
        (void)scePthreadCondBroadcast(&cond_);
    }

    void wait(AmprUniqueLock& lock) {
        if (!lock.owns_lock()) {
            __builtin_trap();
        }
        ScePthreadMutex* mutex = lock.mutex() ? lock.mutex()->native_handle() : nullptr;
        if (!mutex) {
            __builtin_trap();
        }
        const int rc = scePthreadCondWait(&cond_, mutex);
        if (rc != 0) {
            __builtin_trap();
        }
    }

    template <typename Predicate>
    void wait(AmprUniqueLock& lock, Predicate pred) {
        while (!pred()) {
            wait(lock);
        }
    }

    template <typename Rep, typename Period>
    void wait_for(AmprUniqueLock& lock, const std::chrono::duration<Rep, Period>& timeout) {
        if (!lock.owns_lock()) {
            __builtin_trap();
        }
        ScePthreadMutex* mutex = lock.mutex() ? lock.mutex()->native_handle() : nullptr;
        if (!mutex) {
            __builtin_trap();
        }
        const auto usecDuration = std::chrono::duration_cast<std::chrono::microseconds>(timeout);
        uint64_t usec = usecDuration.count() > 0 ? static_cast<uint64_t>(usecDuration.count()) : 0;
        if (usec > 0xffffffffull) {
            usec = 0xffffffffull;
        }
        const int rc = scePthreadCondTimedwait(&cond_, mutex, static_cast<SceKernelUseconds>(usec));
        if (rc != 0 && rc != SCE_KERNEL_ERROR_ETIMEDOUT && rc != ETIMEDOUT) {
            __builtin_trap();
        }
    }

private:
    ScePthreadCond cond_{};
};

class AmprOnceFlag {
public:
    AmprOnceFlag() = default;
    AmprOnceFlag(const AmprOnceFlag&) = delete;
    AmprOnceFlag& operator=(const AmprOnceFlag&) = delete;

private:
    template <typename Callable>
    friend void ampr_call_once(AmprOnceFlag& flag, Callable&& callable);

    std::atomic<uint32_t> state_{0};
};

template <typename Callable>
void ampr_call_once(AmprOnceFlag& flag, Callable&& callable) {
    uint32_t expected = 0;
    if (flag.state_.compare_exchange_strong(expected,
                                            1u,
                                            std::memory_order_acq_rel,
                                            std::memory_order_acquire)) {
        callable();
        flag.state_.store(2u, std::memory_order_release);
        return;
    }

    uint32_t spins = 0;
    while (flag.state_.load(std::memory_order_acquire) != 2u) {
        ampr_spin_pause_or_yield(spins);
    }
}
