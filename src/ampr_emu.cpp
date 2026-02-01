/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Copyright (C) 2026 Roman Tarasov
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */


#include "ampr.h"
#include "ampr_emu_config.h"
#include "ampr_emu_io.h"
#include "ampr_emu_extra.h"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <deque>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <vector>
#include <string>
#include <algorithm>
#include <chrono>

#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#if AMPR_EMU_USE_PREADV
  #include <sys/uio.h>
#endif

#if AMPR_EMU_LOG
  #if AMPR_EMU_USE_KLOG
    #include <ps5/klog.h>
    #define AMPR_LOGF(...) do{ klog_printf(__VA_ARGS__); klog_printf("\n"); }while(0)
  #else
    #include <stdio.h>
    #define AMPR_LOGF(...) do{ fprintf(stderr, __VA_ARGS__); fprintf(stderr, "\n"); }while(0)
  #endif
#else
  #define AMPR_LOGF(...) do{}while(0)
#endif

static inline int ampr_sce_errno_from_posix(int err) {
    switch (err) {
        case EPERM: return SCE_KERNEL_ERROR_EPERM;
        case ENOENT: return SCE_KERNEL_ERROR_ENOENT;
        case ESRCH: return SCE_KERNEL_ERROR_ESRCH;
        case EIO: return SCE_KERNEL_ERROR_EIO;
        case EBADF: return SCE_KERNEL_ERROR_EBADF;
        case EAGAIN: return SCE_KERNEL_ERROR_EAGAIN;
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
        case EWOULDBLOCK: return SCE_KERNEL_ERROR_EAGAIN;
#endif
        case ENOMEM: return SCE_KERNEL_ERROR_ENOMEM;
        case EACCES: return SCE_KERNEL_ERROR_EACCES;
        case EFAULT: return SCE_KERNEL_ERROR_EFAULT;
        case EBUSY: return SCE_KERNEL_ERROR_EBUSY;
        case EEXIST: return SCE_KERNEL_ERROR_EEXIST;
        case EINVAL: return SCE_KERNEL_ERROR_EINVAL;
        case ENOSPC: return SCE_KERNEL_ERROR_ENOSPC;
        case EPIPE: return SCE_KERNEL_ERROR_EPIPE;
        case ENOTEMPTY: return SCE_KERNEL_ERROR_ENOTEMPTY;
        case ETIMEDOUT: return SCE_KERNEL_ERROR_ETIMEDOUT;
        case ECANCELED: return SCE_KERNEL_ERROR_ECANCELED;
        case ENOBUFS: return SCE_KERNEL_ERROR_ENOBUFS;
        default: return (int)SCE_KERNEL_ERROR_UNKNOWN;
    }
}

// -----------------------------
// I/O backend (C API)
// -----------------------------
static int default_open(const char* path, int flags, int mode) { return ::open(path, flags, mode); }
static int default_close(int fd) { return ::close(fd); }
static ssize_t default_pread(int fd, void* buf, size_t len, off_t off) { return ::pread(fd, buf, len, off); }
static int default_stat(const char* path, struct stat* st) { return ::stat(path, st); }

static AmprIoBackend g_default_backend { default_open, default_close, default_pread, default_stat };
static std::atomic<const AmprIoBackend*> g_backend { &g_default_backend };

extern "C" void amprSetIoBackend(const AmprIoBackend* backend) {
    if (backend == nullptr) {
        g_backend.store(&g_default_backend, std::memory_order_release);
    } else {
        g_backend.store(backend, std::memory_order_release);
    }
}
extern "C" const AmprIoBackend* amprGetIoBackend(void) {
    const AmprIoBackend* b = g_backend.load(std::memory_order_acquire);
    return b ? b : &g_default_backend;
}

// -----------------------------
// Userland Equeue emulation (C API)
// -----------------------------
#if AMPR_EMU_KERNEL_STUBS_QUEUE

#if AMPR_EMU_QUEUE_BACKEND_KQUEUE

// PS5/FreeBSD backend: implement the equeue subset using the real kqueue/kevent.
//
// Why: when AMPR runs in one module and the equeue APIs are provided by another,
// a module-local userland queue (global maps) breaks because the handle space
// is not shared. Using kqueue makes the handle a kernel object, so AMPR can
// trigger events reliably regardless of which module created the queue.
namespace {
// Prospero SDK sys/event.h:
//   #define EVFILT_USER (-11)
//   #define NOTE_TRIGGER 0x01000000
constexpr int16_t  kEvfiltUser  = -11;
constexpr uint32_t kNoteTrigger = 0x01000000u;

// kernel.h declares a struct named `kevent`, so call the syscall wrappers via
// stable aliases to avoid the C++ "type vs function" ambiguity.
extern "C" int ampr_kqueue(void) __asm__("kqueue");
extern "C" int ampr_kevent(int kq,
                           const struct kevent* changelist,
                           int nchanges,
                           struct kevent* eventlist,
                           int nevents,
                           const struct timespec* timeout) __asm__("kevent");

struct KqReg {
    int16_t filter{};  // what we should report to the user (e.g., EVFILT_AMPR)
    void*   udata{};   // stored registration udata (returned to the user)
};

static std::mutex g_kq_m;
static std::unordered_map<uintptr_t, std::unordered_map<uint32_t, KqReg>> g_kq_regs;
static std::atomic<uint32_t> g_eq_tag{1};

static inline int kqfd_from_eq(SceKernelEqueue eq) {
    // libkernel_sys.sprx treats SceKernelEqueue as an opaque 64-bit handle whose low dword is the fd.
    return (int)(uint32_t)(uintptr_t)eq;
}

static inline SceKernelEqueue make_eq_handle(int kqfd) {
    // Avoid returning nullptr when the fd happens to be 0: encode a non-zero tag in the high dword.
    uint32_t tag = g_eq_tag.fetch_add(1, std::memory_order_relaxed);
    uint64_t h = (uint64_t)(uint32_t)kqfd | ((uint64_t)tag << 32);
    return (SceKernelEqueue)(uintptr_t)h;
}

static int kevent_wait_retry(int kq,
                             struct kevent* ev,
                             int evCount,
                             int* outCount,
                             const SceKernelUseconds* timeoutUsec) {
    if (outCount) *outCount = 0;

    if (!timeoutUsec) {
        for (;;) {
            int rc = ampr_kevent(kq, nullptr, 0, ev, evCount, nullptr);
            if (rc >= 0) {
                if (rc == 0) return SCE_KERNEL_ERROR_ETIMEDOUT;
                if (outCount) *outCount = rc;
                return 0;
            }
            if (errno != EINTR) return ampr_sce_errno_from_posix(errno);
        }
    }

    uint64_t remaining = (uint64_t)(*timeoutUsec);
    for (;;) {
        struct timespec ts{};
        ts.tv_sec = (time_t)(remaining / 1000000ull);
        ts.tv_nsec = (long)((remaining % 1000000ull) * 1000ull);

        struct timespec t0{};
        (void)clock_gettime(CLOCK_MONOTONIC, &t0);
        int rc = ampr_kevent(kq, nullptr, 0, ev, evCount, &ts);
        if (rc >= 0) {
            if (rc == 0) return SCE_KERNEL_ERROR_ETIMEDOUT;
            if (outCount) *outCount = rc;
            return 0;
        }
        if (errno != EINTR) return ampr_sce_errno_from_posix(errno);

        // EINTR: subtract elapsed time and retry until timeout.
        struct timespec t1{};
        (void)clock_gettime(CLOCK_MONOTONIC, &t1);
        int64_t sec = (int64_t)t1.tv_sec - (int64_t)t0.tv_sec;
        int64_t nsec = (int64_t)t1.tv_nsec - (int64_t)t0.tv_nsec;
        if (nsec < 0) { nsec += 1000000000ll; sec -= 1; }
        uint64_t elapsed = (sec <= 0 && nsec <= 0) ? 0ull : (uint64_t)sec * 1000000ull + (uint64_t)(nsec / 1000ll);
        if (elapsed >= remaining) return SCE_KERNEL_ERROR_ETIMEDOUT;
        remaining -= elapsed;
    }
}

static void eq_push_ex(SceKernelEqueue eq, uint32_t id, uint64_t data, int16_t /*filter*/, uint32_t /*fflags*/) {
    int kq = kqfd_from_eq(eq);
    if (!eq || kq < 0) return;

    // Trigger a kqueue user event. The kernel will deliver the udata from the registration.
    struct kevent ch{};
    ch.ident = (uintptr_t)id;
    ch.filter = kEvfiltUser;
    ch.flags = 0;
    ch.fflags = kNoteTrigger;
    ch.data = (intptr_t)data; // best-effort; may be ignored by EVFILT_USER
    ch.udata = nullptr;
    (void)ampr_kevent(kq, &ch, 1, nullptr, 0, nullptr);
}

static void eq_push(SceKernelEqueue eq, uint32_t id, uint64_t data) {
    eq_push_ex(eq, id, data, (int16_t)SCE_KERNEL_EVFILT_AMPR, 0);
}
} // namespace

extern "C" int sceKernelCreateEqueue(SceKernelEqueue* eq, const char* name) {
    if (!eq) return SCE_KERNEL_ERROR_EFAULT;
    if (!name) return SCE_KERNEL_ERROR_EINVAL;
    int kq = ampr_kqueue();
    if (kq < 0) return ampr_sce_errno_from_posix(errno);
    *eq = make_eq_handle(kq);
    return 0;
}

extern "C" int sceKernelDeleteEqueue(SceKernelEqueue eq) {
    if (!eq) return SCE_KERNEL_ERROR_EBADF;
    int kq = kqfd_from_eq(eq);
    if (kq < 0) return SCE_KERNEL_ERROR_EBADF;

    {
        std::lock_guard<std::mutex> lk(g_kq_m);
        g_kq_regs.erase((uintptr_t)eq);
    }

    if (::close(kq) < 0) return ampr_sce_errno_from_posix(errno);
    return 0;
}

extern "C" int sceKernelAddAmprEvent(SceKernelEqueue eq, uint32_t id, void* udata) {
    if (!eq) return SCE_KERNEL_ERROR_EBADF;
    int kq = kqfd_from_eq(eq);
    if (kq < 0) return SCE_KERNEL_ERROR_EBADF;

    struct kevent ch{};
    ch.ident = (uintptr_t)id;
    ch.filter = kEvfiltUser;
    ch.flags = (uint16_t)(SCE_KERNEL_EV_ADD | SCE_KERNEL_EV_CLEAR);
    ch.fflags = 0;
    ch.data = 0;
    ch.udata = udata;
    if (ampr_kevent(kq, &ch, 1, nullptr, 0, nullptr) < 0) return ampr_sce_errno_from_posix(errno);

    {
        std::lock_guard<std::mutex> lk(g_kq_m);
        g_kq_regs[(uintptr_t)eq][id] = KqReg{(int16_t)SCE_KERNEL_EVFILT_AMPR, udata};
    }
    return 0;
}

extern "C" int sceKernelDeleteAmprEvent(SceKernelEqueue eq, uint32_t id) {
    if (!eq) return SCE_KERNEL_ERROR_EBADF;
    int kq = kqfd_from_eq(eq);
    if (kq < 0) return SCE_KERNEL_ERROR_EBADF;

    struct kevent ch{};
    ch.ident = (uintptr_t)id;
    ch.filter = kEvfiltUser;
    ch.flags = (uint16_t)SCE_KERNEL_EV_DELETE;
    ch.fflags = 0;
    ch.data = 0;
    ch.udata = nullptr;
    if (ampr_kevent(kq, &ch, 1, nullptr, 0, nullptr) < 0) return ampr_sce_errno_from_posix(errno);

    {
        std::lock_guard<std::mutex> lk(g_kq_m);
        auto itq = g_kq_regs.find((uintptr_t)eq);
        if (itq != g_kq_regs.end()) itq->second.erase(id);
    }
    return 0;
}

extern "C" int sceKernelAddAmprSystemEvent(SceKernelEqueue eq, int id, unsigned int data, void* udata) {
    if (data > 1) return SCE_KERNEL_ERROR_EINVAL;
    if (!eq) return SCE_KERNEL_ERROR_EBADF;
    int kq = kqfd_from_eq(eq);
    if (kq < 0) return SCE_KERNEL_ERROR_EBADF;

    struct kevent ch{};
    ch.ident = (uintptr_t)(uint32_t)id;
    ch.filter = kEvfiltUser;
    ch.flags = (uint16_t)(SCE_KERNEL_EV_ADD | SCE_KERNEL_EV_CLEAR);
    ch.fflags = 0;
    ch.data = (intptr_t)data;
    ch.udata = udata;
    if (ampr_kevent(kq, &ch, 1, nullptr, 0, nullptr) < 0) return ampr_sce_errno_from_posix(errno);

    {
        std::lock_guard<std::mutex> lk(g_kq_m);
        g_kq_regs[(uintptr_t)eq][(uint32_t)id] = KqReg{(int16_t)SCE_KERNEL_EVFILT_AMPR_SYSTEM, udata};
    }
    return 0;
}

extern "C" int sceKernelWaitEqueue(SceKernelEqueue eq, SceKernelEvent* ev, int evCount, int* outCount, SceKernelUseconds* timeout) {
    if (outCount) *outCount = 0;
    if (!ev || evCount <= 0) return SCE_KERNEL_ERROR_EINVAL;

    int kq = kqfd_from_eq(eq);
    if (!eq || kq < 0) return SCE_KERNEL_ERROR_EBADF;

    int rc = kevent_wait_retry(kq, (struct kevent*)ev, evCount, outCount, timeout);
    if (rc != 0) return rc;

    // Patch the filter to look like a real EVFILT_AMPR event.
    const int n = outCount ? *outCount : 0;
    if (n <= 0) return 0;

    std::lock_guard<std::mutex> lk(g_kq_m);
    auto itq = g_kq_regs.find((uintptr_t)eq);
    for (int i = 0; i < n; ++i) {
        if (ev[i].filter != kEvfiltUser) continue;
        int16_t outFilter = (int16_t)SCE_KERNEL_EVFILT_AMPR;
        if (itq != g_kq_regs.end()) {
            auto it = itq->second.find((uint32_t)ev[i].ident);
            if (it != itq->second.end()) {
                outFilter = it->second.filter;
                ev[i].udata = it->second.udata;
            }
        }
        ev[i].filter = outFilter;
    }
    return 0;
}

#else  // !AMPR_EMU_QUEUE_BACKEND_KQUEUE

namespace {
struct EmuEqueue {
    std::mutex m;
    std::condition_variable cv;
    struct Reg {
        uint32_t id{};
        int16_t filter{};
        uint16_t flags{};
        uint32_t fflags{};
        void* udata{};
        bool enabled{true};
    };
    struct QEv {
        uint32_t id{};
        uint32_t flags{};
        uint32_t fflags{};
        int16_t filter{};
        uint64_t data{};
        void* udata{};
    };
    std::deque<QEv> events;
    std::unordered_map<uint32_t, Reg> regs; // registered event IDs
    bool closed{false};
};

static std::mutex g_eq_m;
static std::unordered_map<uintptr_t, std::shared_ptr<EmuEqueue>> g_equeues;
static std::atomic<uintptr_t> g_eq_next{1};

static std::shared_ptr<EmuEqueue> eq_get(SceKernelEqueue eq) {
    if (!eq) return {};
    std::lock_guard<std::mutex> lk(g_eq_m);
    auto it = g_equeues.find((uintptr_t)eq);
    return it == g_equeues.end() ? std::shared_ptr<EmuEqueue>{} : it->second;
}

static void eq_push_ex(SceKernelEqueue eq, uint32_t id, uint64_t data, int16_t filter, uint32_t fflags) {
    auto q = eq_get(eq);
    if (!q) return;
    std::unique_lock<std::mutex> lk(q->m);
    if (q->closed) return;
    auto it = q->regs.find(id);
    if (it == q->regs.end()) return; // not registered
    if (!it->second.enabled) return;
    if (it->second.filter != filter) return;
    uint32_t efflags = fflags;
    if (efflags == 0 && it->second.fflags != 0) efflags = it->second.fflags;
    if (it->second.fflags != 0 && (efflags & it->second.fflags) == 0) return;
    if (it->second.flags & SCE_KERNEL_EV_CLEAR) {
        for (auto ev_it = q->events.begin(); ev_it != q->events.end(); ) {
            if (ev_it->id == id) ev_it = q->events.erase(ev_it);
            else ++ev_it;
        }
    }
    EmuEqueue::QEv ev{};
    ev.id = id;
    ev.flags = it->second.flags;
    ev.fflags = efflags;
    ev.filter = filter;
    ev.data = data;
    ev.udata = it->second.udata;
    q->events.push_back(ev);
    if (it->second.flags & SCE_KERNEL_EV_ONESHOT) {
        q->regs.erase(it);
    } else if (it->second.flags & SCE_KERNEL_EV_DISPATCH) {
        it->second.enabled = false;
    }
    lk.unlock();
    q->cv.notify_all();
}

static void eq_push(SceKernelEqueue eq, uint32_t id, uint64_t data) {
    eq_push_ex(eq, id, data, (int16_t)SCE_KERNEL_EVFILT_AMPR, 0);
}
} // namespace

extern "C" int sceKernelCreateEqueue(SceKernelEqueue* eq, const char* /*name*/) {
    if (!eq) return SCE_KERNEL_ERROR_EINVAL;
    auto q = std::make_shared<EmuEqueue>();
    uintptr_t h = g_eq_next.fetch_add(1);
    {
        std::lock_guard<std::mutex> lk(g_eq_m);
        g_equeues[h] = q;
    }
    *eq = (SceKernelEqueue)h;
    return 0;
}

extern "C" int sceKernelAddAmprEvent(SceKernelEqueue eq, uint32_t id, void* udata) {
    auto q = eq_get(eq);
    if (!q) return SCE_KERNEL_ERROR_EBADF;
    std::lock_guard<std::mutex> lk(q->m);
    auto it = q->regs.find(id);
    if (it == q->regs.end()) {
        EmuEqueue::Reg reg{};
        reg.id = id;
        reg.filter = (int16_t)SCE_KERNEL_EVFILT_AMPR;
        reg.flags = (SCE_KERNEL_EV_ADD | SCE_KERNEL_EV_CLEAR);
        reg.fflags = 0;
        reg.udata = udata;
        reg.enabled = true;
        q->regs[id] = reg;
    } else {
        it->second.udata = udata;
        it->second.flags |= SCE_KERNEL_EV_CLEAR;
        it->second.enabled = true;
    }
    return 0;
}

extern "C" int sceKernelDeleteAmprEvent(SceKernelEqueue eq, uint32_t id) {
    auto q = eq_get(eq);
    if (!q) return SCE_KERNEL_ERROR_EBADF;
    std::lock_guard<std::mutex> lk(q->m);
    q->regs.erase(id);
    // Match kqueue-style behavior closer: deleting the registration should also
    // prevent already-queued events from being observed by userland.
    for (auto it = q->events.begin(); it != q->events.end(); ) {
        if (it->id == id && it->filter == (int16_t)SCE_KERNEL_EVFILT_AMPR) it = q->events.erase(it);
        else ++it;
    }
    return 0;
}

extern "C" int sceKernelAddAmprSystemEvent(SceKernelEqueue eq, int id, unsigned int data, void* udata) {
    if (data > 1) return SCE_KERNEL_ERROR_EINVAL;
    auto q = eq_get(eq);
    if (!q) return SCE_KERNEL_ERROR_EBADF;
    std::lock_guard<std::mutex> lk(q->m);
    EmuEqueue::Reg reg{};
    reg.id = (uint32_t)id;
    reg.filter = (int16_t)SCE_KERNEL_EVFILT_AMPR_SYSTEM;
    reg.flags = (SCE_KERNEL_EV_ADD | SCE_KERNEL_EV_CLEAR);
    reg.fflags = 0;
    reg.udata = udata;
    reg.enabled = true;
    q->regs[reg.id] = reg;
    (void)data;
    return 0;
}

extern "C" int sceKernelWaitEqueue(SceKernelEqueue eq, SceKernelEvent* ev, int evCount, int* outCount, SceKernelUseconds* timeout) {
    if (outCount) *outCount = 0;
    if (!ev || evCount <= 0) return SCE_KERNEL_ERROR_EINVAL;
    auto q = eq_get(eq);
    if (!q) return SCE_KERNEL_ERROR_EBADF;

    std::unique_lock<std::mutex> lk(q->m);
    auto pred = [&]{ return q->closed || !q->events.empty(); };

    if (timeout) {
        // microseconds
        auto dur = std::chrono::microseconds(*timeout);
        if (!q->cv.wait_for(lk, dur, pred)) {
            return SCE_KERNEL_ERROR_ETIMEDOUT;
        }
    } else {
        q->cv.wait(lk, pred);
    }

    if (q->closed) return SCE_KERNEL_ERROR_ECANCELED;
    int n = 0;
    while (n < evCount && !q->events.empty()) {
        EmuEqueue::QEv qe = q->events.front();
        q->events.pop_front();
        ev[n].ident = (uintptr_t)qe.id;
        ev[n].filter = qe.filter;
        ev[n].flags = qe.flags;
        ev[n].fflags = qe.fflags;
        ev[n].data = (intptr_t)qe.data;
        ev[n].udata = qe.udata;
        // If a queued event carries EV_ONESHOT/EV_DISPATCH, it was handled at push time.
        ++n;
    }
    if (outCount) *outCount = n;
    return 0;
}

extern "C" int sceKernelDeleteEqueue(SceKernelEqueue eq) {
    std::shared_ptr<EmuEqueue> q;
    {
        std::lock_guard<std::mutex> lk(g_eq_m);
        auto it = g_equeues.find((uintptr_t)eq);
        if (it == g_equeues.end()) return SCE_KERNEL_ERROR_EBADF;
        q = it->second;
        g_equeues.erase(it);
    }
    {
        std::lock_guard<std::mutex> lk(q->m);
        q->closed = true;
    }
    q->cv.notify_all();
    return 0;
}

#endif // AMPR_EMU_QUEUE_BACKEND_KQUEUE

#else
static inline void eq_push(SceKernelEqueue, uint32_t, uint64_t) {}
#endif

#if AMPR_EMU_KERNEL_STUBS_MEMORY
static int ampr_normalize_prot(int prot) {
    int out = 0;
    if (prot & SCE_KERNEL_PROT_CPU_READ) out |= PROT_READ;
    if (prot & SCE_KERNEL_PROT_CPU_WRITE) out |= PROT_WRITE;
    if (prot & SCE_KERNEL_PROT_CPU_EXEC) out |= PROT_EXEC;
    if (prot & SCE_KERNEL_PROT_GPU_RW) out |= (PROT_READ | PROT_WRITE);
    if (prot & SCE_KERNEL_PROT_AMPR_READ) out |= PROT_READ;
    if (prot & SCE_KERNEL_PROT_AMPR_WRITE) out |= PROT_WRITE;
    if (prot & SCE_KERNEL_PROT_AMPR_RW) out |= (PROT_READ | PROT_WRITE);
    if (out == 0) out = prot & (PROT_READ | PROT_WRITE | PROT_EXEC);
    return out;
}

extern "C" int sceKernelMprotect(const void* addr, size_t len, int prot) {
    if (!addr || len == 0) return SCE_KERNEL_ERROR_EINVAL;
    long ps = ::sysconf(_SC_PAGESIZE);
    size_t pageSize = ps > 0 ? (size_t)ps : (size_t)4096;
    uintptr_t start = (uintptr_t)addr;
    uintptr_t pageStart = start & ~(pageSize - 1);
    uintptr_t end = start + len;
    uintptr_t pageEnd = (end + pageSize - 1) & ~(pageSize - 1);
    size_t span = pageEnd - pageStart;
    int rc = ::mprotect((void*)pageStart, span, ampr_normalize_prot(prot));
    if (rc != 0) return ampr_sce_errno_from_posix(errno);
    return 0;
}

extern "C" int sceKernelMtypeprotect(const void* addr, size_t len, int type, int prot) {
    (void)type;
    return sceKernelMprotect(addr, len, prot);
}
#endif

// -----------------------------
// Internal shared state
// -----------------------------
namespace {

constexpr uint32_t kMaxCounters = 256;

enum class OpType : uint8_t {
    WaitOnAddress,
    WaitOnCounter,
    WriteAddress,
    WriteCounter,
    WriteEqueue,
    WriteAddressFromTimeCounter,
    WriteAddressFromCounter,
    WriteAddressFromCounterPair,
    Nop,
    MarkerSet,
    MarkerPush,
    MarkerPop,

    // AMM
    AmmMap,
    AmmMapDirect,
    AmmUnmap,
    AmmRemap,
    AmmMultiMap,
    AmmModifyProtect,
    AmmModifyMtypeProtect,
    AmmMapAsPrt,
    AmmAllocPaForPrt,
    AmmRemapIntoPrt,
    AmmUnmapToPrt,

    // APR
    AprReadFile,
    AprReadGather,
    AprReadScatter,
    AprReadGatherScatter,
    AprResetGatherScatter,
    AprMapBegin,
    AprMapDirectBegin,
    AprMapEnd
};

struct Op {
    OpType type{};
    uint32_t bufOffsetBytes{}; // for debugging / errorOffset
    // Generic fields:
    uint64_t u64a{}, u64b{}, u64c{};
    uint32_t u32a{}, u32b{}, u32c{};
    uint8_t  u8a{};
    void*    ptra{};
    const void* cptr{};
    std::string s; // marker msg or pathPrefix etc (rare; used only at build-time)
};

struct CommandBufferState {
    std::mutex m;
    std::condition_variable cv;
    // mirrors SceAmprCommandBuffer fields:
    SceAmprCommandBuffer* cb{};
    bool inFlight{false};
    std::vector<Op> ops;
};

static std::mutex g_cb_map_m;
static std::unordered_map<SceAmprCommandBuffer*, std::unique_ptr<CommandBufferState>> g_cb_states;

static CommandBufferState& state_for(SceAmprCommandBuffer* cb) {
    std::lock_guard<std::mutex> lk(g_cb_map_m);
    auto it = g_cb_states.find(cb);
    if (it == g_cb_states.end()) {
        auto up = std::make_unique<CommandBufferState>();
        up->cb = cb;
        auto [it2, _] = g_cb_states.emplace(cb, std::move(up));
        return *it2->second;
    }
    return *it->second;
}

// Counters (shared between AMM and APR emulation to keep wait/write semantics)
static std::mutex g_counter_m;
static std::condition_variable g_counter_cv;
static std::atomic<uint32_t> g_counters[kMaxCounters];

static uint64_t time_counter_now() {
    // Lightweight monotonically increasing counter (ns-ish), not a real HW counter.
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return uint64_t(ts.tv_sec) * 1000000000ull + uint64_t(ts.tv_nsec);
}

static bool compare_u32(uint32_t v, uint32_t ref, sce::Ampr::WaitCompare cmp) {
    using sce::Ampr::WaitCompare;
    switch (cmp) {
        case WaitCompare::kEqual: return v == ref;
        case WaitCompare::kGreaterThan: return v > ref;
        case WaitCompare::kLessThan: return v < ref;
        case WaitCompare::kNotEqual: return v != ref;
        default: return v == ref;
    }
}
static bool compare_u64(uint64_t v, uint64_t ref, sce::Ampr::WaitCompare cmp) {
    using sce::Ampr::WaitCompare;
    switch (cmp) {
        case WaitCompare::kEqual: return v == ref;
        case WaitCompare::kGreaterThan: return v > ref;
        case WaitCompare::kLessThan: return v < ref;
        case WaitCompare::kNotEqual: return v != ref;
        default: return v == ref;
    }
}

// -----------------------------
// FileId table + fd cache
// -----------------------------
struct FileEntry {
    std::string path;
    size_t size{};
    bool pinned{false};
#if AMPR_EMU_ENABLE_FD_CACHE
    int fd{-1};
    uint64_t lastUseTick{0};
#endif
};

static std::mutex g_file_m;
static std::unordered_map<uint32_t, FileEntry> g_files;
static std::atomic<uint32_t> g_next_file_id{1};
static std::atomic<uint64_t> g_tick{1};

#if AMPR_EMU_ENABLE_FD_CACHE
static void fd_cache_maybe_evict_locked() {
    // Cap the number of simultaneously open cached FDs, not the number of file IDs.
    size_t openCount = 0;
    for (const auto& [id, e] : g_files) (void)id, openCount += (e.fd >= 0);
    while (openCount > AMPR_EMU_FD_CACHE_CAP) {
        // Evict least-recently-used non-pinned with open fd.
        uint32_t victim = 0;
        uint64_t best = UINT64_MAX;
        for (auto& [id, e] : g_files) {
            if (e.pinned) continue;
            if (e.fd < 0) continue;
            if (e.lastUseTick < best) { best = e.lastUseTick; victim = id; }
        }
        if (victim == 0) break;
        auto it = g_files.find(victim);
        if (it != g_files.end() && it->second.fd >= 0) {
            amprGetIoBackend()->close_fn(it->second.fd);
            it->second.fd = -1;
            openCount--;
        } else {
            break;
        }
    }
}
static int open_cached_fd_locked(uint32_t id, int flags, int mode) {
    auto it = g_files.find(id);
    if (it == g_files.end()) return -ENOENT;
    FileEntry& e = it->second;
    e.lastUseTick = g_tick.fetch_add(1);
    if (e.fd >= 0) return e.fd;
    int fd = amprGetIoBackend()->open_fn(e.path.c_str(), flags, mode);
    if (fd < 0) return -errno;
    e.fd = fd;
    fd_cache_maybe_evict_locked();
    return fd;
}
#endif

static int stat_path(const char* path, struct stat* st) {
    if (!path || !st) return -EINVAL;
    if (amprGetIoBackend()->stat_fn(path, st) != 0) return -errno;
    return 0;
}

static int resolve_path_to_id(const char* path, uint32_t* outId, size_t* outSize) {
    if (!path || !outId) return -EINVAL;
    struct stat st{};
    int rc = stat_path(path, &st);
    if (rc != 0) return rc;

    std::lock_guard<std::mutex> lk(g_file_m);
    // Deduplicate by path.
    for (auto& [id, e] : g_files) {
        if (e.path == path) {
            e.size = (size_t)st.st_size;
            if (outSize) *outSize = e.size;
            *outId = id;
            return 0;
        }
    }
    uint32_t id = g_next_file_id.fetch_add(1);
    FileEntry e;
    e.path = path;
    e.size = (size_t)st.st_size;
#if AMPR_EMU_ENABLE_FD_CACHE
    e.fd = -1;
    e.lastUseTick = g_tick.fetch_add(1);
#endif
    g_files.emplace(id, std::move(e));
    if (outSize) *outSize = (size_t)st.st_size;
    *outId = id;
    return 0;
}

static int get_entry(uint32_t id, FileEntry* out) {
    std::lock_guard<std::mutex> lk(g_file_m);
    auto it = g_files.find(id);
    if (it == g_files.end()) return -ENOENT;
    if (out) *out = it->second;
    return 0;
}

// -----------------------------
// AMM mapping model (userland)
// -----------------------------
struct Mapping {
    uint64_t va{};
    uint64_t size{};
    int prot{};
    int type{};
    int fd{-1};
    uint64_t off{};
    bool prt{false};
};
static std::mutex g_map_m;
static std::unordered_map<uint64_t, Mapping> g_mappings;

struct DmemRange {
    uint64_t off{};
    uint64_t size{};
};

struct VaRange {
    uint64_t va{};
    uint64_t size{};
};

static void mapping_table_cut_range_locked(uint64_t cutStart, uint64_t cutEnd, bool includePrt,
                                           std::vector<VaRange>* outVaCuts,
                                           std::vector<DmemRange>* outPhysCuts) {
    if (cutStart >= cutEnd) return;

    struct Pending {
        uint64_t oldVa{};
        std::vector<Mapping> add;
    };
    std::vector<Pending> pend;

    for (const auto& [_, m] : g_mappings) {
        if (!includePrt && m.prt) continue;
        uint64_t mStart = m.va;
        uint64_t mEnd = m.va + m.size;
        if (mStart >= cutEnd || mEnd <= cutStart) continue;

        uint64_t s = std::max(mStart, cutStart);
        uint64_t e = std::min(mEnd, cutEnd);
        if (s >= e) continue;

        if (outVaCuts) outVaCuts->push_back(VaRange{s, e - s});
        if (outPhysCuts) outPhysCuts->push_back(DmemRange{m.off + (s - mStart), e - s});

        Pending p{};
        p.oldVa = mStart;

        // Left remainder.
        if (s > mStart) {
            Mapping left = m;
            left.va = mStart;
            left.size = s - mStart;
            // left.off unchanged
            p.add.push_back(left);
        }
        // Right remainder.
        if (e < mEnd) {
            Mapping right = m;
            right.va = e;
            right.size = mEnd - e;
            right.off = m.off + (e - mStart);
            p.add.push_back(right);
        }
        pend.push_back(std::move(p));
    }

    for (auto& p : pend) {
        g_mappings.erase(p.oldVa);
        for (const auto& m : p.add) {
            g_mappings[m.va] = m;
        }
    }
}

static int g_dmem_fd = -1;
static size_t g_dmem_size = 0;
static std::atomic<uint64_t> g_dmem_next_off{0};
static std::mutex g_dmem_alloc_m;
static std::vector<DmemRange> g_dmem_allocs;
static std::vector<DmemRange> g_dmem_free;
static void dmem_free_insert_locked(uint64_t off, uint64_t size);
enum class DmemUsage : uint8_t { Auto = 0, Direct = 1 };
struct DmemPool {
    uint64_t base{};
    uint64_t size{};
    uint64_t next{};
    DmemUsage usage{};
    std::vector<DmemRange> free;
};
static std::mutex g_dmem_pool_m;
static std::vector<DmemPool> g_dmem_pools;

static inline bool ampr_is_pow2(uint64_t v) { return v && ((v & (v - 1)) == 0); }
static int ampr_validate_dmem_params(size_t size, size_t align) {
    if (size == 0 || (size % PAGE_SIZE) != 0) return EINVAL;
    if (align != 0) {
        if ((align % PAGE_SIZE) != 0) return EINVAL;
        if (!ampr_is_pow2((uint64_t)align)) return EINVAL;
    }
    return 0;
}
static int ampr_validate_dmem_range(uint64_t off, size_t size) {
    if (size == 0 || (size % PAGE_SIZE) != 0) return EINVAL;
    if ((off % PAGE_SIZE) != 0) return EINVAL;
    return 0;
}

static int ensure_dmem_emulated(size_t minSize) {
    if (g_dmem_fd >= 0 && g_dmem_size >= minSize) return 0;
    size_t sz = std::max(minSize, (size_t)64*1024*1024); // 64 MiB baseline
    int fd = -1;

    char name[64];
    uint64_t r = (uint64_t)time_counter_now();
    snprintf(name, sizeof(name), "/ampr_dmem_%llx_%u", (unsigned long long)r, (unsigned)getpid());
    fd = ::shm_open(name, O_CREAT|O_EXCL|O_RDWR, 0600);
    if (fd >= 0) {
        ::shm_unlink(name);
        if (::ftruncate(fd, (off_t)sz) != 0) {
            ::close(fd);
            fd = -1;
        } else {
            AMPR_LOGF("ensure_dmem_emulated: using shm_open");
        }
    } else {
        AMPR_LOGF("ensure_dmem_emulated: shm_open failed errno=%d", errno);
    }

    if (fd < 0) return -errno;

    g_dmem_fd = fd;
    g_dmem_size = sz;
    g_dmem_next_off.store(0);
    {
        std::lock_guard<std::mutex> lk(g_dmem_alloc_m);
        g_dmem_allocs.clear();
        g_dmem_free.clear();
    }
    return 0;
}

static int dmem_alloc_emulated(size_t size, size_t align, uint64_t* outOff) {
    if (!outOff) return -EINVAL;
    int vrc = ampr_validate_dmem_params(size, align);
    if (vrc != 0) return vrc;
    int rc = ensure_dmem_emulated(size);
    if (rc != 0) return rc;
    AMPR_LOGF("dmem_alloc_emulated size=0x%llx align=0x%llx", (unsigned long long)size, (unsigned long long)align);
    uint64_t a = align ? align : (16 * 1024);
    std::lock_guard<std::mutex> lk(g_dmem_alloc_m);

    for (size_t i = 0; i < g_dmem_free.size(); ++i) {
        DmemRange r = g_dmem_free[i];
        uint64_t aligned = (r.off + (a - 1)) & ~(a - 1);
        uint64_t end = r.off + r.size;
        if (aligned + size > end) continue;

        if (aligned == r.off && size == r.size) {
            g_dmem_free.erase(g_dmem_free.begin() + (ptrdiff_t)i);
        } else if (aligned == r.off) {
            g_dmem_free[i].off += size;
            g_dmem_free[i].size -= size;
        } else if (aligned + size == end) {
            g_dmem_free[i].size = aligned - r.off;
        } else {
            DmemRange tail{aligned + size, end - (aligned + size)};
            g_dmem_free[i].size = aligned - r.off;
            g_dmem_free.insert(g_dmem_free.begin() + (ptrdiff_t)i + 1, tail);
        }

        g_dmem_allocs.push_back(DmemRange{aligned, (uint64_t)size});
        *outOff = aligned;
        AMPR_LOGF("dmem_alloc_emulated off=0x%llx reuse=1", (unsigned long long)aligned);
        return 0;
    }

    uint64_t off = g_dmem_next_off.load();
    uint64_t aligned = (off + (a - 1)) & ~(a - 1);
    // Track alignment padding as free so it can be reused later.
    if (aligned > off) {
        dmem_free_insert_locked(off, aligned - off);
    }
    uint64_t next = aligned + size;
    if (next > g_dmem_size) {
        size_t newSize = g_dmem_size;
        while (newSize < next) newSize *= 2;
        if (::ftruncate(g_dmem_fd, (off_t)newSize) != 0) return -errno;
        g_dmem_size = newSize;
    }
    g_dmem_next_off.store(next);
    g_dmem_allocs.push_back(DmemRange{aligned, (uint64_t)size});
    *outOff = aligned;
    AMPR_LOGF("dmem_alloc_emulated off=0x%llx reuse=0", (unsigned long long)aligned);
    return 0;
}

static void dmem_free_insert_locked(uint64_t off, uint64_t size) {
    DmemRange nr{off, size};
    auto it = std::lower_bound(
        g_dmem_free.begin(), g_dmem_free.end(), nr,
        [](const DmemRange& a, const DmemRange& b) { return a.off < b.off; });
    it = g_dmem_free.insert(it, nr);

    if (it != g_dmem_free.begin()) {
        auto prev = it - 1;
        if (prev->off + prev->size >= it->off) {
            uint64_t end = std::max(prev->off + prev->size, it->off + it->size);
            prev->size = end - prev->off;
            it = g_dmem_free.erase(it);
            it = prev;
        }
    }
    if (it + 1 != g_dmem_free.end()) {
        auto next = it + 1;
        if (it->off + it->size >= next->off) {
            uint64_t end = std::max(it->off + it->size, next->off + next->size);
            it->size = end - it->off;
            g_dmem_free.erase(next);
        }
    }
}

static void dmem_ranges_insert(std::vector<DmemRange>& ranges, uint64_t off, uint64_t size) {
    DmemRange nr{off, size};
    auto it = std::lower_bound(
        ranges.begin(), ranges.end(), nr,
        [](const DmemRange& a, const DmemRange& b) { return a.off < b.off; });
    it = ranges.insert(it, nr);

    if (it != ranges.begin()) {
        auto prev = it - 1;
        if (prev->off + prev->size >= it->off) {
            uint64_t end = std::max(prev->off + prev->size, it->off + it->size);
            prev->size = end - prev->off;
            it = ranges.erase(it);
            it = prev;
        }
    }
    if (it + 1 != ranges.end()) {
        auto next = it + 1;
        if (it->off + it->size >= next->off) {
            uint64_t end = std::max(it->off + it->size, next->off + next->size);
            it->size = end - it->off;
            ranges.erase(next);
        }
    }
}

static int dmem_release_emulated(uint64_t off, size_t size) {
    int vrc = ampr_validate_dmem_range(off, size);
    AMPR_LOGF("dmem_release_emulated off=0x%llx size=0x%llx", (unsigned long long)off, (unsigned long long)size);
    if (vrc != 0) {
        AMPR_LOGF("dmem_release_emulated invalid rc=%d", vrc);
        return vrc;
    }
    if (off + size > g_dmem_size) {
        AMPR_LOGF("dmem_release_emulated out of range");
        return EINVAL;
    }

    std::lock_guard<std::mutex> lk(g_dmem_alloc_m);
    auto it = std::find_if(
        g_dmem_allocs.begin(), g_dmem_allocs.end(),
        [&](const DmemRange& r) { return r.off == off && r.size == size; });
    if (it == g_dmem_allocs.end()) {
        AMPR_LOGF("dmem_release_emulated not found");
        return EINVAL;
    }
    {
        std::lock_guard<std::mutex> lk(g_map_m);
        uint64_t rel_start = off;
        uint64_t rel_end = off + (uint64_t)size;
        for (const auto& [va, m] : g_mappings) {
            if (m.fd != g_dmem_fd) continue;
            uint64_t m_start = m.off;
            uint64_t m_end = m.off + m.size;
            if (m_start < rel_end && m_end > rel_start) {
                AMPR_LOGF("dmem_release_emulated busy");
                return EBUSY;
            }
        }
    }
    g_dmem_allocs.erase(it);
    dmem_free_insert_locked(off, size);
    AMPR_LOGF("dmem_release_emulated released");
    return 0;
}

static int ensure_dmem(size_t minSize) {
#if AMPR_EMU_KERNEL_STUBS_MEMORY
    return ensure_dmem_emulated(minSize);
#else
    if (minSize == 0) return 0;
    AMPR_LOGF("ensure_dmem minSize=0x%llx", (unsigned long long)minSize);
    size_t total = sceKernelGetDirectMemorySize();
    AMPR_LOGF("ensure_dmem total=0x%llx", (unsigned long long)total);
    if (total == 0) return ENOMEM;
    return (minSize <= total) ? 0 : ENOMEM;
#endif
}

static int dmem_alloc(size_t size, size_t align, int type, uint64_t* outOff) {
    if (!outOff) return -EINVAL;
    int vrc = ampr_validate_dmem_params(size, align);
    if (vrc != 0) return vrc;
    int rc = ensure_dmem(size);
    if (rc != 0) return rc;
    AMPR_LOGF("dmem_alloc size=0x%llx align=0x%llx type=0x%x", (unsigned long long)size, (unsigned long long)align, type);
    off_t off = 0;
    rc = sceKernelAllocateDirectMemory(0, (off_t)SCE_KERNEL_MAIN_DMEM_SIZE,
                                       size, align ? align : 0,
                                       (SceKernelMemoryType)type, &off);
    AMPR_LOGF("dmem_alloc rc=0x%x off=0x%llx", rc, (unsigned long long)off);
    if (rc != 0) return rc;
    *outOff = (uint64_t)off;
    return 0;
}

static int dmem_pool_add(DmemUsage usage, size_t size, size_t align, int type, uint64_t* outBase) {
    uint64_t base = 0;
    int rc = dmem_alloc(size, align, type, &base);
    if (rc != 0) return rc;
    {
        std::lock_guard<std::mutex> lk(g_dmem_pool_m);
        g_dmem_pools.push_back(DmemPool{base, (uint64_t)size, 0, usage});
    }
    if (outBase) *outBase = base;
    return 0;
}

static int dmem_pool_alloc_auto(size_t size, uint64_t* outOff) {
    if (!outOff) return -EINVAL;
    int vrc = ampr_validate_dmem_params(size, 0);
    if (vrc != 0) return vrc;
    std::lock_guard<std::mutex> lk(g_dmem_pool_m);
    for (auto& p : g_dmem_pools) {
        if (p.usage != DmemUsage::Auto) continue;
        // Reuse holes first (pages returned by AMM unmap when unaliased).
        for (size_t i = 0; i < p.free.size(); ++i) {
            DmemRange r = p.free[i];
            uint64_t aligned = (r.off + (PAGE_SIZE - 1)) & ~(uint64_t)(PAGE_SIZE - 1);
            uint64_t end = r.off + r.size;
            if (aligned + (uint64_t)size > end) continue;

            if (aligned == r.off && (uint64_t)size == r.size) {
                p.free.erase(p.free.begin() + (ptrdiff_t)i);
            } else if (aligned == r.off) {
                p.free[i].off += (uint64_t)size;
                p.free[i].size -= (uint64_t)size;
            } else if (aligned + (uint64_t)size == end) {
                p.free[i].size = aligned - r.off;
            } else {
                DmemRange tail{aligned + (uint64_t)size, end - (aligned + (uint64_t)size)};
                p.free[i].size = aligned - r.off;
                p.free.insert(p.free.begin() + (ptrdiff_t)i + 1, tail);
            }

            *outOff = aligned;
            return 0;
        }

        // Fall back to bump allocation from the end of the pool.
        uint64_t aligned = (p.base + p.next + (PAGE_SIZE - 1)) & ~(uint64_t)(PAGE_SIZE - 1);
        uint64_t end = aligned + (uint64_t)size;
        if (end <= p.base + p.size) {
            p.next = end - p.base;
            *outOff = aligned;
            return 0;
        }
    }
    return ENOMEM;
}

static int dmem_pool_free_auto(uint64_t off, size_t size) {
    int vrc = ampr_validate_dmem_range(off, size);
    if (vrc != 0) return vrc;

    std::lock_guard<std::mutex> lk(g_dmem_pool_m);
    for (auto& p : g_dmem_pools) {
        if (p.usage != DmemUsage::Auto) continue;
        if (off < p.base) continue;
        if (off + (uint64_t)size > p.base + p.size) continue;
        dmem_ranges_insert(p.free, off, (uint64_t)size);
        return 0;
    }
    return EINVAL;
}

static bool dmem_pool_contains(DmemUsage usage, uint64_t off, size_t size) {
    std::lock_guard<std::mutex> lk(g_dmem_pool_m);
    for (const auto& p : g_dmem_pools) {
        if (p.usage != usage) continue;
        uint64_t start = p.base;
        uint64_t end = p.base + p.size;
        if (off >= start && (off + (uint64_t)size) <= end) return true;
    }
    return false;
}

#if AMPR_EMU_KERNEL_STUBS_MEMORY
extern "C" int sceKernelAllocateDirectMemory(off_t searchStart, off_t searchEnd, size_t len, size_t alignment, SceKernelMemoryType type, off_t* outOffset) {
    (void)searchStart; (void)searchEnd; (void)type;
    if (!outOffset) return SCE_KERNEL_ERROR_EFAULT;
    uint64_t off = 0;
    int rc = dmem_alloc_emulated(len, alignment ? alignment : (16 * 1024), &off);
    if (rc != 0) return ampr_sce_errno_from_posix(rc < 0 ? -rc : rc);
    *outOffset = (off_t)off;
    return 0;
}

extern "C" int sceKernelReleaseDirectMemory(off_t start, size_t len) {
    int rc = dmem_release_emulated((uint64_t)start, len);
    if (rc != 0) return ampr_sce_errno_from_posix(rc < 0 ? -rc : rc);
    return 0;
}

extern "C" int sceKernelCheckedReleaseDirectMemory(off_t start, size_t len) {
    return sceKernelReleaseDirectMemory(start, len);
}

extern "C" int sceKernelAvailableDirectMemorySize(off_t start, off_t end, size_t alignment, off_t* startOut, size_t* sizeOut) {
    if (!startOut || !sizeOut) return SCE_KERNEL_ERROR_EFAULT;
    *startOut = 0;
    *sizeOut = 0;
    if (start < 0 || end < 0 || end <= start) return SCE_KERNEL_ERROR_EINVAL;

    // Do not implicitly grow the backing store from this query; only ensure it exists.
    if (g_dmem_fd < 0) {
        int erc = ensure_dmem_emulated(0);
        if (erc != 0) return ampr_sce_errno_from_posix(erc < 0 ? -erc : erc);
    }

    const uint64_t a = alignment ? (uint64_t)alignment : (uint64_t)PAGE_SIZE;
    if (alignment != 0) {
        if ((alignment % PAGE_SIZE) != 0) return SCE_KERNEL_ERROR_EINVAL;
        if (!ampr_is_pow2((uint64_t)alignment)) return SCE_KERNEL_ERROR_EINVAL;
    }

    const uint64_t searchStart = (uint64_t)start;
    const uint64_t searchEnd = (uint64_t)end;
    if (searchEnd > (uint64_t)g_dmem_size) return SCE_KERNEL_ERROR_EINVAL;

    uint64_t bestStart = 0;
    uint64_t bestSize = 0;

    std::lock_guard<std::mutex> lk(g_dmem_alloc_m);
    auto consider = [&](uint64_t off, uint64_t sz) {
        uint64_t rStart = off;
        uint64_t rEnd = off + sz;
        if (rEnd <= searchStart || rStart >= searchEnd) return;
        if (rStart < searchStart) rStart = searchStart;
        if (rEnd > searchEnd) rEnd = searchEnd;

        uint64_t alignedStart = (rStart + (a - 1)) & ~(a - 1);
        if (alignedStart >= rEnd) return;
        uint64_t avail = rEnd - alignedStart;
        avail &= ~(uint64_t)(PAGE_SIZE - 1); // direct memory is 16 KiB-granular
        if (avail > bestSize) {
            bestStart = alignedStart;
            bestSize = avail;
        }
    };

    for (const auto& r : g_dmem_free) consider(r.off, r.size);
    uint64_t tailOff = g_dmem_next_off.load();
    if (tailOff < g_dmem_size) consider(tailOff, g_dmem_size - tailOff);

    if (bestSize == 0) return SCE_KERNEL_ERROR_EAGAIN;
    *startOut = (off_t)bestStart;
    *sizeOut = (size_t)bestSize;
    return 0;
}

extern "C" int sceKernelMapDirectMemory(void** addr, size_t len, int prot, int flags, off_t offset, size_t alignment) {
    if (!addr) return SCE_KERNEL_ERROR_EINVAL;
    int rc = ensure_dmem((size_t)(offset + (off_t)len));
    if (rc != 0) return ampr_sce_errno_from_posix(rc < 0 ? -rc : rc);
    int nprot = ampr_normalize_prot(prot);
    void* hint = (addr && *addr) ? *addr : nullptr;
    int mflags = MAP_SHARED;
    if (addr && *addr) mflags |= MAP_FIXED;
    void* p = ::mmap(hint, len, nprot, mflags, g_dmem_fd, offset);
    if (p == MAP_FAILED) return ampr_sce_errno_from_posix(errno);
    {
        std::lock_guard<std::mutex> lk(g_map_m);
        g_mappings[(uint64_t)(uintptr_t)p] =
            Mapping{(uint64_t)(uintptr_t)p, (uint64_t)len, prot, 0, g_dmem_fd, (uint64_t)offset, false};
    }
    *addr = p;
    return 0;
}

extern "C" int sceKernelMapFlexibleMemory(void** addrInOut, size_t len, int prot, int flags) {
    if (!addrInOut) return SCE_KERNEL_ERROR_EINVAL;
    void* hint = *addrInOut;
    int mflags = MAP_PRIVATE | MAP_ANON;
    if (flags & SCE_KERNEL_MAP_FIXED) mflags |= MAP_FIXED;
    void* p = ::mmap(hint, len, ampr_normalize_prot(prot), mflags, -1, 0);
    if (p == MAP_FAILED) return ampr_sce_errno_from_posix(errno);
    *addrInOut = p;
    return 0;
}

extern "C" int sceKernelReleaseFlexibleMemory(void* addr, size_t len) {
    if (!addr || len == 0) return SCE_KERNEL_ERROR_EINVAL;
    if (::munmap(addr, len) != 0) return ampr_sce_errno_from_posix(errno);
    return 0;
}

extern "C" int sceKernelMunmap(void* addr, size_t len) {
    if (!addr || len == 0) return SCE_KERNEL_ERROR_EINVAL;
    if (::munmap(addr, len) != 0) return ampr_sce_errno_from_posix(errno);
    {
        std::lock_guard<std::mutex> lk(g_map_m);
        mapping_table_cut_range_locked((uint64_t)(uintptr_t)addr,
                                       (uint64_t)(uintptr_t)addr + (uint64_t)len,
                                       /*includePrt=*/true,
                                       nullptr,
                                       nullptr);
    }
    return 0;
}

extern "C" size_t sceKernelGetDirectMemorySize(void) {
    if (g_dmem_size != 0) return g_dmem_size;
    return 0;
}
#endif

#if AMPR_EMU_KERNEL_STUBS_QUEUE || AMPR_EMU_KERNEL_STUBS_MEMORY
extern "C" int sceKernelAprGetFileSize(int fileId, uint64_t* outSize) {
    if (!outSize) return SCE_KERNEL_ERROR_EFAULT;
    size_t sz = 0;
    int rc = sce::Ampr::Apr::getFileSize((SceAprFileId)fileId, &sz);
    if (rc != 0) return rc;
    *outSize = (uint64_t)sz;
    return 0;
}

extern "C" int sceKernelAprGetFileStat(int fileId, SceKernelStat* st) {
    return sce::Ampr::Apr::getFileStat((SceAprFileId)fileId, st);
}
#endif

#if AMPR_EMU_KERNEL_STUBS_QUEUE || AMPR_EMU_KERNEL_STUBS_MEMORY
static sce::Ampr::Apr::Priority apr_prio_from_int(int prio) {
    // libkernel_sys.sprx uses a "non-zero" priority field in the submit param.
    // Treat this as (prio + 1) encoding: 1..7 => Priority0..Priority6.
    int p = prio - 1;
    if (p < 0) p = 0;
    if (p > 6) p = 6;
    return (sce::Ampr::Apr::Priority)p;
}

struct SceAprSubmitParam {
    uint32_t reserved0;
    uint32_t prio;
    uint64_t reserved1;
    sce::Ampr::AprCommandBuffer* commandBuffer;
    SceAprResultBuffer* result;
    SceAprSubmitId* id;
};

static int apr_submit_from_param(void* submitParam) {
    if (!submitParam) {
        errno = EPERM;
        return -1;
    }
    auto* param = reinterpret_cast<SceAprSubmitParam*>(submitParam);
    if (!param->commandBuffer) {
        errno = EPERM;
        return -1;
    }
    if (param->prio == 0) {
        errno = EINVAL;
        return -1;
    }
    return sce::Ampr::Apr::submitCommandBufferAndGetResult(
        param->commandBuffer,
        apr_prio_from_int((int)param->prio),
        param->result,
        param->id);
}

extern "C" int sceKernelAprResolveFilepathsToIds(const char* path[], uint32_t num, uint32_t ids[], uint32_t* errorIndex) {
    return sce::Ampr::Apr::resolveFilepathsToIds(path, num, (SceAprFileId*)ids, errorIndex);
}
extern "C" int sceKernelAprResolveFilepathsToIdsAndFileSizes(const char* path[], uint32_t num, uint32_t ids[], size_t fileSizes[], uint32_t* errorIndex) {
    return sce::Ampr::Apr::resolveFilepathsToIdsAndFileSizes(path, num, (SceAprFileId*)ids, fileSizes, errorIndex);
}
extern "C" int sceKernelAprResolveFilepathsWithPrefixToIds(const char* pathPrefix, const char* path[], uint32_t num, uint32_t ids[], uint32_t* errorIndex) {
    return sce::Ampr::Apr::resolveFilepathsWithPrefixToIds(pathPrefix, path, num, (SceAprFileId*)ids, errorIndex);
}
extern "C" int sceKernelAprResolveFilepathsWithPrefixToIdsAndFileSizes(const char* pathPrefix, const char* path[], uint32_t num, uint32_t ids[], size_t fileSizes[], uint32_t* errorIndex) {
    return sce::Ampr::Apr::resolveFilepathsWithPrefixToIdsAndFileSizes(pathPrefix, path, num, (SceAprFileId*)ids, fileSizes, errorIndex);
}
extern "C" int sceKernelAprResolveFilepathsToIdsForEach(const char* path[], uint32_t num, uint32_t ids[], int results[]) {
    return sce::Ampr::Apr::resolveFilepathsToIdsForEach(path, num, (SceAprFileId*)ids, results);
}
extern "C" int sceKernelAprResolveFilepathsToIdsAndFileSizesForEach(const char* path[], uint32_t num, uint32_t ids[], size_t fileSizes[], int results[]) {
    return sce::Ampr::Apr::resolveFilepathsToIdsAndFileSizesForEach(path, num, (SceAprFileId*)ids, fileSizes, results);
}
extern "C" int sceKernelAprResolveFilepathsWithPrefixToIdsForEach(const char* pathPrefix, const char* path[], uint32_t num, uint32_t ids[], int results[]) {
    return sce::Ampr::Apr::resolveFilepathsWithPrefixToIdsForEach(pathPrefix, path, num, (SceAprFileId*)ids, results);
}
extern "C" int sceKernelAprResolveFilepathsWithPrefixToIdsAndFileSizesForEach(const char* pathPrefix, const char* path[], uint32_t num, uint32_t ids[], size_t fileSizes[], int results[]) {
    return sce::Ampr::Apr::resolveFilepathsWithPrefixToIdsAndFileSizesForEach(pathPrefix, path, num, (SceAprFileId*)ids, fileSizes, results);
}

extern "C" int sceKernelAprSubmitCommandBuffer(void* submitParam) {
    return apr_submit_from_param(submitParam);
}
extern "C" int sceKernelAprSubmitCommandBuffer_TEST(void* submitParam) {
    return apr_submit_from_param(submitParam);
}
extern "C" int sceKernelAprSubmitCommandBufferAndGetResult(void* submitParam) {
    return apr_submit_from_param(submitParam);
}
extern "C" int sceKernelAprSubmitCommandBufferAndGetResult_TEST(void* submitParam) {
    return apr_submit_from_param(submitParam);
}
extern "C" int sceKernelAprSubmitCommandBufferAndGetId(void* submitParam) {
    return apr_submit_from_param(submitParam);
}
extern "C" int sceKernelAprWaitCommandBuffer(uint32_t id) {
    return sce::Ampr::Apr::waitCommandBufferCompletion((SceAprSubmitId)id);
}
#endif

static int map_shared(uint64_t va, uint64_t size, int type, int prot, uint64_t off) {
#if AMPR_EMU_KERNEL_STUBS_MEMORY
    void* p = ::mmap((void*)va, (size_t)size, ampr_normalize_prot(prot),
                     MAP_SHARED|MAP_FIXED, g_dmem_fd, (off_t)off);
    if (p == MAP_FAILED) return -errno;
    return 0;
#else
    void* addr = (void*)va;
    int rc = sceKernelMapDirectMemory2(&addr, (size_t)size, type, prot, SCE_KERNEL_MAP_FIXED, (off_t)off, 0);
    if (rc != 0) return rc;
    return 0;
#endif
}

static int map_flexible(uint64_t va, uint64_t size, int prot) {
#if AMPR_EMU_KERNEL_STUBS_MEMORY
    void* p = ::mmap((void*)va, (size_t)size, ampr_normalize_prot(prot),
                     MAP_PRIVATE|MAP_ANON|MAP_FIXED, -1, 0);
    if (p == MAP_FAILED) return -errno;
    return 0;
#else
    void* addr = (void*)va;
    int rc = sceKernelMapFlexibleMemory(&addr, (size_t)size, prot, SCE_KERNEL_MAP_FIXED);
    if (rc != 0) return rc;
    return 0;
#endif
}

static int unmap_region(uint64_t va, uint64_t size) {
#if AMPR_EMU_KERNEL_STUBS_MEMORY
    if (::munmap((void*)va, (size_t)size) != 0) return -errno;
    return 0;
#else
    return sceKernelMunmap((void*)va, (size_t)size);
#endif
}

static int amm_unmap_best_effort(uint64_t va, uint64_t size) {
    if (size == 0) return EINVAL;
    uint64_t start = va;
    uint64_t end = va + size;

    std::vector<VaRange> vaCuts;
    std::vector<DmemRange> physCuts;
    std::vector<DmemRange> remainingPhys;

    {
        std::lock_guard<std::mutex> lk(g_map_m);
        mapping_table_cut_range_locked(start, end, /*includePrt=*/false, &vaCuts, &physCuts);
        // Snapshot remaining physical references (for multimap alias detection).
        for (const auto& [_, m] : g_mappings) {
            if (m.fd != g_dmem_fd) continue;
            remainingPhys.push_back(DmemRange{m.off, m.size});
        }
    }

    // Best-effort: unmap only the regions that were known-mapped.
    for (const auto& r : vaCuts) {
        int rc = unmap_region(r.va, r.size);
        if (rc != 0) return rc;
    }

    // Return AUTO pages back to the pool if no remaining mappings reference them.
    std::vector<DmemRange> refsMerged;
    for (const auto& r : remainingPhys) dmem_ranges_insert(refsMerged, r.off, r.size);

    std::vector<DmemRange> candMerged;
    for (const auto& r : physCuts) dmem_ranges_insert(candMerged, r.off, r.size);

    std::vector<DmemRange> holes;
    for (const auto& c : candMerged) {
        uint64_t cStart = c.off;
        uint64_t cEnd = c.off + c.size;
        uint64_t cur = cStart;
        for (const auto& ref : refsMerged) {
            uint64_t rStart = ref.off;
            uint64_t rEnd = ref.off + ref.size;
            if (rEnd <= cur) continue;
            if (rStart >= cEnd) break;
            uint64_t oStart = std::max(cur, rStart);
            uint64_t oEnd = std::min(cEnd, rEnd);
            if (oStart > cur) holes.push_back(DmemRange{cur, oStart - cur});
            cur = std::max(cur, oEnd);
            if (cur >= cEnd) break;
        }
        if (cur < cEnd) holes.push_back(DmemRange{cur, cEnd - cur});
    }

    std::vector<DmemRange> holesMerged;
    for (const auto& h : holes) dmem_ranges_insert(holesMerged, h.off, h.size);

    for (const auto& h : holesMerged) {
        if (!dmem_pool_contains(DmemUsage::Auto, h.off, (size_t)h.size)) continue;
        (void)dmem_pool_free_auto(h.off, (size_t)h.size);
        AMPR_LOGF("amm.auto_free off=0x%llx size=0x%llx",
                  (unsigned long long)h.off, (unsigned long long)h.size);
    }

    return 0;
}

// VA ranges returned to the user (stable per-process)
static std::once_flag g_va_once;
static sce::Ampr::AmmVirtualAddressRanges g_va_ranges{};
static void init_va_ranges() {
#if AMPR_EMU_KERNEL_STUBS_MEMORY
    // Reserve a big region so we can use MAP_FIXED safely inside it.
    size_t reserve = (size_t)1ull<<31; // 2 GiB
    void* base = ::mmap(nullptr, reserve, PROT_NONE, MAP_PRIVATE|MAP_ANON, -1, 0);
    if (base == MAP_FAILED) {
        // fallback: smaller
        reserve = (size_t)512ull<<20;
        base = ::mmap(nullptr, reserve, PROT_NONE, MAP_PRIVATE|MAP_ANON, -1, 0);
    }
#else
    size_t reserve = (size_t)1ull<<31; // 2 GiB
    void* base = nullptr;
    int rc = sceKernelReserveVirtualRange(&base, reserve, 0, 0);
    if (rc != 0 || base == nullptr) {
        reserve = (size_t)512ull<<20;
        base = nullptr;
        rc = sceKernelReserveVirtualRange(&base, reserve, 0, 0);
    }
#endif
    uint64_t b = (uint64_t)(uintptr_t)base;
    g_va_ranges.vaStart = b;
    g_va_ranges.vaEnd = b + reserve;
    // Dedicate the middle third for multimap aliases (arbitrary but stable)
    g_va_ranges.multimapVaStart = b + reserve/3;
    g_va_ranges.multimapVaEnd   = b + 2*reserve/3;
}

// -----------------------------
// Executor / scheduling
// -----------------------------
struct JobResult {
    int rc{0};
    uint32_t errorOffset{0};
};

struct Job {
    uint64_t id{};
    SceAmprCommandBuffer* cb{};
    bool isAmm{true};
    uint8_t prioIndex{}; // 0 = highest
    // for AndGetResult
    SceAmmResultBuffer* ammRes{};
    SceAprResultBuffer* aprRes{};
};

class Executor {
public:
    Executor(uint8_t numPriorities_, const char* name_)
        : numPriorities(numPriorities_),
          name(name_ ? name_ : "exec"),
          queues(numPriorities_),
          inflight(numPriorities_, false) {

        unsigned n = AMPR_EMU_WORKERS;
        if (n == 0) n = std::max(2u, std::thread::hardware_concurrency());
        for (unsigned i = 0; i < n; ++i) workers.emplace_back([this] { this->worker(); });
    }

    ~Executor() {
        {
            std::lock_guard<std::mutex> lk(m);
            stop = true;
        }
        cv.notify_all();
        for (auto& t : workers) if (t.joinable()) t.join();
    }

    void submit(const Job& j) {
        uint8_t p = j.prioIndex;
        if (numPriorities == 0) p = 0;
        else if (p >= numPriorities) p = (uint8_t)(numPriorities - 1);
        {
            std::lock_guard<std::mutex> lk(done_m);
            pending.insert(j.id);
        }
        {
            std::lock_guard<std::mutex> lk(m);
            queues[p].push_back(j);
        }
        cv.notify_one();
    }

    int wait(uint64_t id) {
        std::unique_lock<std::mutex> lk(done_m);
        done_cv.wait(lk, [&]{ return done.count(id) != 0 || pending.count(id) == 0; });
        auto it = done.find(id);
        if (it == done.end()) return SCE_KERNEL_ERROR_ESRCH;
        done.erase(it);
        return 0;
    }

private:
    bool has_runnable_locked() const {
        for (uint8_t p = 0; p < numPriorities; ++p) {
            if (!inflight[p] && !queues[p].empty()) return true;
        }
        return false;
    }

    void worker() {
        for (;;) {
            Job job{};
            uint8_t psel = 0;
            {
                std::unique_lock<std::mutex> lk(m);
                cv.wait(lk, [&]{ return stop || has_runnable_locked(); });
                if (stop) return;

                for (uint8_t p = 0; p < numPriorities; ++p) {
                    if (inflight[p]) continue;
                    if (queues[p].empty()) continue;
                    job = queues[p].front();
                    queues[p].pop_front();
                    inflight[p] = true;
                    psel = p;
                    break;
                }
            }

            JobResult r = execute(job);

            {
                std::lock_guard<std::mutex> lk(done_m);
                pending.erase(job.id);
                done[job.id] = r;
            }
            done_cv.notify_all();

            {
                std::lock_guard<std::mutex> lk(m);
                if (psel < inflight.size()) inflight[psel] = false;
            }
            cv.notify_all();
        }
    }

JobResult execute(const Job& job) {
        JobResult out{};
        auto& st = state_for(job.cb);
        std::unique_lock<std::mutex> lk(st.m);
        st.inFlight = true;
        auto ops = st.ops; // copy for execution (keeps build thread free)
        lk.unlock();

        if (job.isAmm) out = exec_amm(ops);
        else out = exec_apr(ops);
        if (out.rc != 0) {
            uint32_t u = (uint32_t)out.rc;
            if ((u & 0xFFFF0000u) != 0x80020000u) {
                int err = out.rc < 0 ? -out.rc : out.rc;
                out.rc = ampr_sce_errno_from_posix(err);
            }
        }

        // Fill result buffers (best-effort; emulate Sony-style offset)
        if (job.isAmm && job.ammRes) {
            job.ammRes->result = out.rc;
            job.ammRes->errorOffset = out.errorOffset;
        }
        if (!job.isAmm && job.aprRes) {
            job.aprRes->result = out.rc;
            job.aprRes->errorOffset = out.errorOffset;
        }

        lk.lock();
        st.inFlight = false;
        lk.unlock();
        st.cv.notify_all();
        return out;
    }

    JobResult exec_amm(const std::vector<Op>& ops) {
        JobResult out{};
        for (const auto& op : ops) {
            int rc = 0;
            switch (op.type) {
                case OpType::WaitOnAddress: {
                    volatile uint64_t* addr = (volatile uint64_t*)op.ptra;
                    uint64_t ref = op.u64a;
                    auto cmp = (sce::Ampr::WaitCompare)op.u32a;
                    // Poll with backoff. No kernel help.
                    int spins = 0;
                    for (;;) {
                        uint64_t v = *addr;
                        if (compare_u64(v, ref, cmp)) break;
                        if (++spins < 1000) { asm volatile("" ::: "memory"); }
                        else {
                            timespec ts{0, 200000}; // 0.2ms
                            nanosleep(&ts, nullptr);
                        }
                    }
                    if ((sce::Ampr::WaitFlush)op.u32c == sce::Ampr::WaitFlush::kEnable) {
                        // Flush remaining commands in this buffer (userland approximation).
                        goto exec_amm_done;
                    }
                    break;
                }
                case OpType::WaitOnCounter: {
                    uint8_t idx = op.u8a;
                    uint32_t ref = op.u32a;
                    auto cmp = (sce::Ampr::WaitCompare)op.u32b;
                    std::unique_lock<std::mutex> lk(g_counter_m);
                    g_counter_cv.wait(lk, [&]{
                        uint32_t v = g_counters[idx].load(std::memory_order_acquire);
                        return compare_u32(v, ref, cmp);
                    });
                    if ((sce::Ampr::WaitFlush)op.u32c == sce::Ampr::WaitFlush::kEnable) {
                        goto exec_amm_done;
                    }
                    break;
                }
                case OpType::WriteAddress: {
                    volatile uint64_t* addr = (volatile uint64_t*)op.ptra;
                    *addr = op.u64a;
                    break;
                }
                case OpType::WriteCounter: {
                    uint8_t idx = op.u8a;
                    g_counters[idx].store(op.u32a, std::memory_order_release);
                    g_counter_cv.notify_all();
                    break;
                }
                case OpType::WriteAddressFromTimeCounter: {
                    volatile uint64_t* addr = (volatile uint64_t*)op.ptra;
                    *addr = time_counter_now();
                    break;
                }
                case OpType::WriteAddressFromCounter: {
                    volatile uint64_t* addr = (volatile uint64_t*)op.ptra;
                    uint8_t idx = op.u8a;
                    *addr = (uint64_t)g_counters[idx].load(std::memory_order_acquire);
                    break;
                }
                case OpType::WriteAddressFromCounterPair: {
                    volatile uint64_t* addr = (volatile uint64_t*)op.ptra;
                    uint8_t idx = op.u8a;
                    // pair emulation: read idx and idx+1 as hi/lo
                    uint64_t lo = (uint64_t)g_counters[idx].load(std::memory_order_acquire);
                    uint64_t hi = (uint64_t)g_counters[(uint8_t)(idx+1)].load(std::memory_order_acquire);
                    *addr = (hi<<32) | (lo & 0xffffffffu);
                    break;
                }
                case OpType::Nop:
                case OpType::MarkerSet:
                case OpType::MarkerPush:
                case OpType::MarkerPop:
                    // no-op in userland emulation (markers are for tooling).
                    break;
                case OpType::WriteEqueue:
                    // Userland equeue emulation: push an event if the queue/id was registered.
                    eq_push((SceKernelEqueue)(uintptr_t)op.u64b, op.u32b, op.u64a);
                    break;

                case OpType::AmmMap: {
                    uint64_t va = op.u64a;
                    uint64_t sz = op.u64b;
                    int prot = (int)op.u32a;
                    int type = (int)op.u32b;
                    // Map fresh backing from DMEM
                    uint64_t off=0;
                    rc = dmem_pool_alloc_auto((size_t)sz, &off);
                    if (rc==0) rc = map_shared(va, sz, type, prot, off);
                    if (rc==0) {
                        std::lock_guard<std::mutex> lk(g_map_m);
                        g_mappings[va] = Mapping{va, sz, prot, type, g_dmem_fd, off, false};
                    }
                    break;
                }
                case OpType::AmmMapDirect: {
                    uint64_t va = op.u64a;
                    uint64_t off = op.u64b;
                    uint64_t sz = op.u64c;
                    int prot = (int)op.u32a;
                    int type = (int)op.u32b;
                    if (!dmem_pool_contains(DmemUsage::Direct, off, (size_t)sz)) {
                        rc = EINVAL;
                        break;
                    }
                    rc = ensure_dmem((size_t)(off+sz));
                    if (rc==0) rc = map_shared(va, sz, type, prot, off);
                    if (rc==0) {
                        std::lock_guard<std::mutex> lk(g_map_m);
                        g_mappings[va] = Mapping{va, sz, prot, type, g_dmem_fd, off, false};
                    }
                    break;
                }
                case OpType::AmmUnmap: {
                    uint64_t va = op.u64a;
                    uint64_t sz = op.u64b;
                    rc = amm_unmap_best_effort(va, sz);
                    break;
                }
                case OpType::AmmRemap: {
                    uint64_t vaNew = op.u64a;
                    uint64_t vaOld = op.u64b;
                    uint64_t sz = op.u64c;
                    int prot = (int)op.u32a;
                    Mapping old{};
                    {
                        std::lock_guard<std::mutex> lk(g_map_m);
                        auto it = g_mappings.find(vaOld);
                        if (it==g_mappings.end()) { rc = -ENOENT; break; }
                        old = it->second;
                    }
                    rc = map_shared(vaNew, sz, old.type, prot, old.off);
                    if (rc==0) rc = unmap_region(vaOld, sz);
                    if (rc==0) {
                        std::lock_guard<std::mutex> lk(g_map_m);
                        g_mappings.erase(vaOld);
                        g_mappings[vaNew] = Mapping{vaNew, sz, prot, old.type, g_dmem_fd, old.off, false};
                    }
                    break;
                }
                case OpType::AmmMultiMap: {
                    uint64_t vaStart = op.u64a;
                    uint64_t vaAlias = op.u64b;
                    uint64_t sz = op.u64c;
                    int prot = (int)op.u32a;
                    Mapping base{};
                    {
                        std::lock_guard<std::mutex> lk(g_map_m);
                        auto it = g_mappings.find(vaStart);
                        if (it==g_mappings.end()) { rc = -ENOENT; break; }
                        base = it->second;
                    }
                    rc = map_shared(vaAlias, sz, base.type, prot, base.off);
                    if (rc==0) {
                        std::lock_guard<std::mutex> lk(g_map_m);
                        g_mappings[vaAlias] = Mapping{vaAlias, sz, prot, base.type, g_dmem_fd, base.off, false};
                    }
                    break;
                }
                case OpType::AmmModifyProtect: {
                    uint64_t va = op.u64a;
                    uint64_t sz = op.u64b;
                    int prot = (int)op.u32a;
                    rc = sceKernelMprotect((void*)va, (size_t)sz, prot);
                    break;
                }
                case OpType::AmmModifyMtypeProtect: {
                    // Memory type not emulated; just mprotect
                    uint64_t va = op.u64a;
                    uint64_t sz = op.u64b;
                    int prot = (int)op.u32a;
                    int type = (int)op.u32b;
                    rc = sceKernelMtypeprotect((void*)va, (size_t)sz, type, prot);
                    break;
                }
                case OpType::AmmMapAsPrt: {
                    uint64_t va = op.u64a;
                    uint64_t sz = op.u64b;
                    rc = map_flexible(va, sz, 0);
                    if (rc == 0) {
                        std::lock_guard<std::mutex> lk(g_map_m);
                        g_mappings[va] = Mapping{va, sz, PROT_NONE, 0, -1, 0, true};
                    }
                    break;
                }
                case OpType::AmmAllocPaForPrt: {
                    uint64_t va = op.u64a;
                    uint64_t sz = op.u64b;
                    int prot = (int)op.u32a;
                    int type = (int)op.u32b;
                    uint64_t off=0;
                    rc = dmem_pool_alloc_auto((size_t)sz, &off);
                    if (rc==0) rc = map_shared(va, sz, type, prot, off);
                    if (rc==0) {
                        std::lock_guard<std::mutex> lk(g_map_m);
                        g_mappings[va] = Mapping{va, sz, prot, type, g_dmem_fd, off, false};
                    }
                    break;
                }

                case OpType::AmmRemapIntoPrt: {
                    uint64_t va = op.u64a;
                    uint64_t sz = op.u64b;
                    int prot = (int)op.u32a;
                    // In the original this remaps physical pages into a PRT reservation.
                    // Userland emu: ensure mapping exists, then apply protection.
                    auto it = g_mappings.find(va);
                    if (it == g_mappings.end()) {
                        rc = map_flexible(va, sz, prot);
                        if (rc == 0) {
                            std::lock_guard<std::mutex> lk(g_map_m);
                            g_mappings[va] = Mapping{va, sz, prot, 0, -1, 0, false};
                        }
                    } else {
                        rc = sceKernelMprotect((void*)va, (size_t)sz, prot);
                        if (rc == 0) it->second.prot = prot;
                    }
                    break;
                }
                case OpType::AmmUnmapToPrt: {
                    uint64_t va = op.u64a;
                    uint64_t sz = op.u64b;
                    rc = sceKernelMprotect((void*)va, (size_t)sz, 0);
                    if (rc == 0) {
                        std::lock_guard<std::mutex> lk(g_map_m);
                        auto it = g_mappings.find(va);
                        if (it != g_mappings.end()) it->second.prot = PROT_NONE;
                    }
                    break;
                }

                default:
                    break;
            }
            if (rc != 0) {
                out.rc = rc;
                out.errorOffset = op.bufOffsetBytes;
                return out;
            }
        }
exec_amm_done:
        out.rc = 0;
        return out;
    }

    struct GatherSeg { uint64_t len; uint64_t off; };
    struct ScatterSeg { void* buf; uint64_t len; };

    JobResult exec_apr(const std::vector<Op>& ops) {
        JobResult out{};
        // Execute with simple "batching": run consecutive reads in parallel, but keep barriers.
        std::vector<std::thread> localThreads; // small batches; uses system threads
        std::mutex batch_m;
        std::vector<int> batch_rc;
        std::vector<uint32_t> batch_error_off;
        std::deque<GatherSeg> gather_q;
        std::deque<ScatterSeg> scatter_q;
        bool gs_active = false;
        uint32_t gs_file_id = 0;
        bool map_active = false;

        auto flush_batch = [&](){
            for (auto& t: localThreads) if (t.joinable()) t.join();
            localThreads.clear();
            for (size_t i = 0; i < batch_rc.size(); ++i) {
                int rc = batch_rc[i];
                if (rc != 0) {
                    out.rc = rc;
                    out.errorOffset = (i < batch_error_off.size()) ? batch_error_off[i] : 0;
                    return false;
                }
            }
            batch_rc.clear();
            batch_error_off.clear();
            return true;
        };

        auto submit_read = [&](uint32_t fileId, void* buffer, uint64_t length, uint64_t offset, uint32_t errorOff){
            // Start lightweight thread per read. The batch_rc vector is shared between threads, so
            // all mutations and element writes must be serialized.
            size_t idx = 0;
            {
                std::lock_guard<std::mutex> lk(batch_m);
                batch_rc.push_back(0);
                batch_error_off.push_back(errorOff);
                idx = batch_rc.size() - 1;
            }
            localThreads.emplace_back([&, idx, fileId, buffer, length, offset]{
                int rc = 0;
                FileEntry e;
                bool have_entry = false;
                {
                    std::lock_guard<std::mutex> lk(g_file_m);
                    auto it = g_files.find(fileId);
                    if (it == g_files.end()) {
                        rc = -ENOENT;
                    } else {
                        have_entry = true;
#if AMPR_EMU_ENABLE_FD_CACHE
                        int fd = open_cached_fd_locked(fileId, O_RDONLY, 0);
                        if (fd < 0) {
                            rc = fd;
                        } else {
                            ssize_t r = amprGetIoBackend()->pread_fn(fd, buffer, (size_t)length, (off_t)offset);
                            if (r < 0) rc = -errno;
                            else if ((uint64_t)r != length) rc = -EIO;
                        }
#else
                        e = it->second;
#endif
                    }
                }
#if !AMPR_EMU_ENABLE_FD_CACHE
                if (rc == 0 && have_entry) {
                    int fd = amprGetIoBackend()->open_fn(e.path.c_str(), O_RDONLY, 0);
                    if (fd < 0) {
                        rc = -errno;
                    } else {
                        ssize_t r = amprGetIoBackend()->pread_fn(fd, buffer, (size_t)length, (off_t)offset);
                        int saved = errno;
                        amprGetIoBackend()->close_fn(fd);
                        if (r < 0) rc = -saved;
                        else if ((uint64_t)r != length) rc = -EIO;
                    }
                }
#endif
                {
                    std::lock_guard<std::mutex> lk(batch_m);
                    batch_rc[idx] = rc;
                }
            });
        };

        for (const auto& op : ops) {
            int rc = 0;
            switch (op.type) {
                // Barriers / sync: flush outstanding IO before continuing.
                case OpType::WaitOnAddress:
                case OpType::WaitOnCounter:
                case OpType::WriteAddress:
                case OpType::WriteCounter:
                case OpType::WriteEqueue:
                case OpType::WriteAddressFromTimeCounter:
                case OpType::WriteAddressFromCounter:
                case OpType::WriteAddressFromCounterPair:
                case OpType::MarkerSet:
                case OpType::MarkerPush:
                case OpType::MarkerPop:
                case OpType::AprResetGatherScatter:
                case OpType::AprMapBegin:
                case OpType::AprMapDirectBegin:
                case OpType::AprMapEnd:
                    if (!flush_batch()) return out;
                    // fallthrough to shared behavior by reusing AMM handler subset:
                    break;
                default: break;
            }

            // Execute barrier ops (shared semantics with AMM)
            switch (op.type) {
                case OpType::WaitOnAddress: {
                    volatile uint64_t* addr = (volatile uint64_t*)op.ptra;
                    uint64_t ref = op.u64a;
                    auto cmp = (sce::Ampr::WaitCompare)op.u32a;
                    int spins = 0;
                    for (;;) {
                        uint64_t v = *addr;
                        if (compare_u64(v, ref, cmp)) break;
                        if (++spins < 1000) { asm volatile("" ::: "memory"); }
                        else { timespec ts{0, 200000}; nanosleep(&ts, nullptr); }
                    }
                    if ((sce::Ampr::WaitFlush)op.u32c == sce::Ampr::WaitFlush::kEnable) {
                        goto exec_apr_done;
                    }
                    break;
                }
                case OpType::WaitOnCounter: {
                    uint8_t idx = op.u8a;
                    uint32_t ref = op.u32a;
                    auto cmp = (sce::Ampr::WaitCompare)op.u32b;
                    std::unique_lock<std::mutex> lk(g_counter_m);
                    g_counter_cv.wait(lk, [&]{
                        uint32_t v = g_counters[idx].load(std::memory_order_acquire);
                        return compare_u32(v, ref, cmp);
                    });
                    if ((sce::Ampr::WaitFlush)op.u32c == sce::Ampr::WaitFlush::kEnable) {
                        goto exec_apr_done;
                    }
                    break;
                }
                case OpType::WriteAddress: {
                    volatile uint64_t* addr = (volatile uint64_t*)op.ptra;
                    *addr = op.u64a;
                    break;
                }
                case OpType::WriteCounter: {
                    uint8_t idx = op.u8a;
                    g_counters[idx].store(op.u32a, std::memory_order_release);
                    g_counter_cv.notify_all();
                    break;
                }
                case OpType::WriteEqueue: {
                    eq_push((SceKernelEqueue)(uintptr_t)op.u64b, op.u32b, op.u64a);
                    break;
                }
                case OpType::WriteAddressFromTimeCounter: {
                    volatile uint64_t* addr = (volatile uint64_t*)op.ptra;
                    *addr = time_counter_now();
                    break;
                }
                case OpType::WriteAddressFromCounter: {
                    volatile uint64_t* addr = (volatile uint64_t*)op.ptra;
                    uint8_t idx = op.u8a;
                    *addr = (uint64_t)g_counters[idx].load(std::memory_order_acquire);
                    break;
                }
                case OpType::WriteAddressFromCounterPair: {
                    volatile uint64_t* addr = (volatile uint64_t*)op.ptra;
                    uint8_t idx = op.u8a;
                    uint64_t lo = (uint64_t)g_counters[idx].load(std::memory_order_acquire);
                    uint64_t hi = (uint64_t)g_counters[(uint8_t)(idx+1)].load(std::memory_order_acquire);
                    *addr = (hi<<32) | (lo & 0xffffffffu);
                    break;
                }
                default: break;
            }

            if (out.rc != 0) { out.errorOffset = op.bufOffsetBytes; return out; }

            // APR-specific ops
            switch (op.type) {
                case OpType::AprReadFile: {
                    uint32_t fileId = op.u32a;
                    void* buf = op.ptra;
                    uint64_t len = op.u64a;
                    uint64_t off = op.u64b;
                    AMPR_LOGF("apr.readFile fileId=%u buf=%p len=0x%llx off=0x%llx",
                              fileId, buf, (unsigned long long)len, (unsigned long long)off);
                    gs_active = true;
                    gs_file_id = fileId;
                    gather_q.clear();
                    scatter_q.clear();
                    submit_read(fileId, buf, len, off, op.bufOffsetBytes);
                    break;
                }
                case OpType::AprReadGather: {
                    if (!gs_active || gs_file_id == 0) { out.rc = SCE_KERNEL_ERROR_EINVAL; out.errorOffset = op.bufOffsetBytes; return out; }
                    AMPR_LOGF("apr.readFileGather len=0x%llx off=0x%llx",
                              (unsigned long long)op.u64a, (unsigned long long)op.u64b);
                    gather_q.push_back(GatherSeg{op.u64a, op.u64b});
                    break;
                }
                case OpType::AprReadScatter: {
                    if (!gs_active || gs_file_id == 0) { out.rc = SCE_KERNEL_ERROR_EINVAL; out.errorOffset = op.bufOffsetBytes; return out; }
                    AMPR_LOGF("apr.readFileScatter buf=%p len=0x%llx",
                              op.ptra, (unsigned long long)op.u64a);
                    scatter_q.push_back(ScatterSeg{op.ptra, op.u64a});
                    break;
                }
                case OpType::AprReadGatherScatter: {
                    if (!gs_active || gs_file_id == 0) { out.rc = SCE_KERNEL_ERROR_EINVAL; out.errorOffset = op.bufOffsetBytes; return out; }
                    AMPR_LOGF("apr.readFileGatherScatter buf=%p len=0x%llx off=0x%llx",
                              op.ptra, (unsigned long long)op.u64a, (unsigned long long)op.u64b);
                    submit_read(gs_file_id, op.ptra, op.u64a, op.u64b, op.bufOffsetBytes);
                    break;
                }
                case OpType::AprResetGatherScatter: {
                    gather_q.clear();
                    scatter_q.clear();
                    gs_active = false;
                    gs_file_id = 0;
                    AMPR_LOGF("apr.resetGatherScatterState");
                    break;
                }
                case OpType::AprMapBegin: {
                    if (map_active) { out.rc = SCE_KERNEL_ERROR_EINVAL; out.errorOffset = op.bufOffsetBytes; return out; }
                    if (op.u64a == 0) { out.rc = SCE_KERNEL_ERROR_EINVAL; out.errorOffset = op.bufOffsetBytes; return out; }
                    map_active = true;
                    AMPR_LOGF("apr.mapBegin a2=0x%llx a3=0x%llx a4=0x%x a5=0x%llx",
                              (unsigned long long)op.u64a, (unsigned long long)op.u64b,
                              op.u32a, (unsigned long long)op.u64c);
                    break;
                }
                case OpType::AprMapDirectBegin: {
                    if (map_active) { out.rc = SCE_KERNEL_ERROR_EINVAL; out.errorOffset = op.bufOffsetBytes; return out; }
                    if (op.u64a == 0) { out.rc = SCE_KERNEL_ERROR_EINVAL; out.errorOffset = op.bufOffsetBytes; return out; }
                    map_active = true;
                    AMPR_LOGF("apr.mapDirectBegin a2=0x%llx a3=0x%llx a4=0x%llx a5=0x%x a6=0x%x",
                              (unsigned long long)op.u64a, (unsigned long long)op.u64b,
                              (unsigned long long)op.u64c, op.u32a, op.u32b);
                    break;
                }
                case OpType::AprMapEnd: {
                    if (!map_active) { out.rc = SCE_KERNEL_ERROR_EINVAL; out.errorOffset = op.bufOffsetBytes; return out; }
                    map_active = false;
                    AMPR_LOGF("apr.mapEnd");
                    break;
                }
                default:
                    break;
            }

            while (!gather_q.empty() && !scatter_q.empty()) {
                GatherSeg g = gather_q.front();
                ScatterSeg s = scatter_q.front();
                if (g.len != s.len || g.len == 0) {
                    out.rc = SCE_KERNEL_ERROR_EINVAL;
                    out.errorOffset = op.bufOffsetBytes;
                    return out;
                }
                AMPR_LOGF("apr.gather+scatter fileId=%u buf=%p len=0x%llx off=0x%llx",
                          gs_file_id, s.buf, (unsigned long long)g.len, (unsigned long long)g.off);
                submit_read(gs_file_id, s.buf, g.len, g.off, op.bufOffsetBytes);
                gather_q.pop_front();
                scatter_q.pop_front();
            }
        }

        if (!gather_q.empty() || !scatter_q.empty()) {
            out.rc = SCE_KERNEL_ERROR_EINVAL;
            out.errorOffset = 0;
            return out;
        }

exec_apr_done:
        if (!flush_batch()) return out;
        out.rc = 0;
        return out;
    }
    uint8_t numPriorities{0};
    const char* name{nullptr};

    std::mutex m;
    std::condition_variable cv;
    std::vector<std::deque<Job>> queues;
    std::vector<bool> inflight;
    bool stop{false};
    std::vector<std::thread> workers;

    std::mutex done_m;
    std::condition_variable done_cv;
    std::unordered_set<uint64_t> pending;
    std::unordered_map<uint64_t, JobResult> done;
};

static Executor g_amm_exec(3, "amm");
static Executor g_apr_exec(7, "apr");
static std::atomic<uint64_t> g_next_submit{1};

} // namespace

// -----------------------------
// sce::Ampr implementations
// -----------------------------
namespace sce::Ampr {

CommandBuffer::CommandBuffer(void) {
    std::memset(&m_commandBuffer, 0, sizeof(m_commandBuffer));
    m_commandBuffer.type = 0;
}
CommandBuffer::~CommandBuffer(void) {
    SceAmprCommandBuffer* cb = &m_commandBuffer;

    CommandBufferState* stp = nullptr;
    {
        std::lock_guard<std::mutex> lk(g_cb_map_m);
        auto it = g_cb_states.find(cb);
        if (it == g_cb_states.end()) return;
        stp = it->second.get();
    }

    // Avoid leaving a dangling key (cb pointer) in the global map when the
    // owning C++ object is destroyed. If someone destroys a command buffer
    // while it is in-flight, we block until completion to prevent UAF.
    {
        std::unique_lock<std::mutex> lk(stp->m);
        stp->cv.wait(lk, [&]{ return !stp->inFlight; });
    }

    std::lock_guard<std::mutex> lk(g_cb_map_m);
    g_cb_states.erase(cb);
}


int CommandBuffer::setBuffer(void* buffer, uint32_t size) {
    auto& st = state_for(&m_commandBuffer);
    std::lock_guard<std::mutex> lk(st.m);
    if (m_commandBuffer.buffer) return SCE_KERNEL_ERROR_EBUSY;
    if (!buffer) return SCE_KERNEL_ERROR_EINVAL;
    if (((uintptr_t)buffer & 3u) != 0) return SCE_KERNEL_ERROR_EINVAL;
    if (size == 0 || (size & 3u) != 0) return SCE_KERNEL_ERROR_EINVAL;
    if (size > (uint32_t)SCE_AMPR_APR_BUFFER_MAX) return SCE_KERNEL_ERROR_EINVAL;
    if (st.inFlight) return SCE_KERNEL_ERROR_EBUSY;
    m_commandBuffer.buffer = buffer;
    m_commandBuffer.bufsize = size;
    m_commandBuffer.offset = 0;
    m_commandBuffer.num = 0;
    st.ops.clear();
    return 0;
}


void* CommandBuffer::clearBuffer(void) {
    auto& st = state_for(&m_commandBuffer);
    std::lock_guard<std::mutex> lk(st.m);
    if (!m_commandBuffer.buffer) return nullptr;
    if (st.inFlight) return nullptr;
    void* p = m_commandBuffer.buffer;
    m_commandBuffer.buffer = nullptr;
    m_commandBuffer.bufsize = 0;
    st.ops.clear();
     return p;
}

int CommandBuffer::getType() const { return m_commandBuffer.type; }
uint32_t CommandBuffer::getSize() const { return m_commandBuffer.bufsize; }
caddr_t CommandBuffer::getBufferBaseAddress() const { return (caddr_t)m_commandBuffer.buffer; }
uint32_t CommandBuffer::getNumCommands() const { return (uint32_t)m_commandBuffer.num; }
uint32_t CommandBuffer::getCurrentOffset() const { return m_commandBuffer.offset; }

static inline uint32_t ampr_align4(uint32_t x) { return (x + 3u) & ~3u; }

static inline bool ampr_valid_wait_compare(WaitCompare c) {
    switch (c) {
        case WaitCompare::kEqual:
        case WaitCompare::kGreaterThan:
        case WaitCompare::kLessThan:
        case WaitCompare::kNotEqual:
            return true;
        default:
            return false;
    }
}

static inline bool ampr_valid_wait_flush(WaitFlush f) {
    switch (f) {
        case WaitFlush::kDisable:
        case WaitFlush::kEnable:
            return true;
        default:
            return false;
    }
}

static inline bool ampr_valid_u64_addr(const volatile uint64_t* p) {
    return p && (((uintptr_t)p & 7u) == 0);
}

static inline bool ampr_strict_writer_enabled() {
#if AMPR_EMU_STRICT_WRITER
    return true;
#else
    return false;
#endif
}

// Best-effort packed sizes (bytes) for FW10-like command buffer records.
// For commands where the exact layout is known (from libSceAmpr.sprx.c), sizes
// match the original. For marker commands and AMM commands this is an
// approximation (kernel writers are not available in userland).
static uint32_t ampr_op_size_bytes(const Op& op) {
    switch (op.type) {
        case OpType::WaitOnAddress: {
            uint64_t ref = op.u64a;
            uint32_t dwords = 4;
            if ((ref >> 32) == 0) dwords = 3u - (ref == 0 ? 1u : 0u);
            return dwords * 4u;
        }
        case OpType::WaitOnCounter: {
            uint32_t ref = op.u32a;
            uint32_t dwords = (ref < 0x100u) ? 1u : 2u;
            return dwords * 4u;
        }
        case OpType::WriteAddress: {
            uint64_t v = op.u64a;
            uint32_t dwords = 4;
            if (v < 0x400000000ull) dwords = (v < 4ull) ? 2u : 3u;
            return dwords * 4u;
        }
        case OpType::WriteCounter: {
            uint32_t v = op.u32a;
            uint32_t dwords = (v < 0x1000u) ? 1u : 2u;
            return dwords * 4u;
        }
        case OpType::WriteEqueue: {
            return 5u * 4u;
        }
        case OpType::WriteAddressFromTimeCounter:
        case OpType::WriteAddressFromCounter:
        case OpType::WriteAddressFromCounterPair: {
            // In FW10 these share a common writer; use the common "5 dwords" size
            // used by WriteKernelEventQueue and other completion ops.
            return 5u * 4u;
        }
        case OpType::Nop: {
            // Our API: nop(numU32) -> total dwords = numU32.
            // nop(numU32,data) -> total dwords = numU32 + 1 (header + data).
            uint32_t n = op.u32a;
            if (op.u32b) return (n + 1u) * 4u;
            return n * 4u;
        }
        case OpType::MarkerSet:
        case OpType::MarkerPush: {
            // Marker payload is variable (string + metadata). Keep it stable:
            // header (16) + string bytes aligned to 4, capped to something sane.
            uint32_t s = (uint32_t)op.s.size() + 1u;
            uint32_t payload = ampr_align4(s);
            return 16u + payload;
        }
        case OpType::MarkerPop:
            return 16u;

        // AMM ops: best-effort fixed sizes (opaque placeholders)
        case OpType::AmmMap:
        case OpType::AmmMapAsPrt:
        case OpType::AmmAllocPaForPrt:
        case OpType::AmmModifyMtypeProtect:
            return 32u;
        case OpType::AmmMapDirect:
            return 40u;
        case OpType::AmmUnmap:
        case OpType::AmmUnmapToPrt:
            return 24u;
        case OpType::AmmRemap:
        case OpType::AmmRemapIntoPrt:
            return 36u;
        case OpType::AmmModifyProtect:
            return 28u;
        case OpType::AmmMultiMap:
            return 32u;
        default:
            return 16u;
    }
}

static void ampr_strict_write_words(SceAmprCommandBuffer* cb, uint32_t offBytes, const uint32_t* words, uint32_t dwords) {
    if (!cb || !cb->buffer) return;
    uint32_t bytes = dwords * 4u;
    if (offBytes + bytes > cb->bufsize) return;
    std::memcpy((uint8_t*)cb->buffer + offBytes, words, bytes);
}

static void ampr_strict_write_op(SceAmprCommandBuffer* cb, uint32_t offBytes, const Op& op) {
    if (!ampr_strict_writer_enabled()) return;

    // Zero-fill the region for determinism.
    uint32_t bytes = ampr_op_size_bytes(op);
    if (!cb || !cb->buffer) return;
    if (offBytes + bytes > cb->bufsize) return;
    std::memset((uint8_t*)cb->buffer + offBytes, 0, bytes);

    uint32_t w[8]{}; // enough for all variable writers we implement here

    switch (op.type) {
        case OpType::WaitOnAddress: {
            uint64_t addr = (uint64_t)op.ptra;
            uint64_t ref  = op.u64a;
            uint32_t cmp  = (op.u32a & 7u);
            uint32_t flush = (op.u32c & 1u);

            uint32_t dwords = 4;
            if ((ref >> 32) == 0) dwords = 3u - (ref == 0 ? 1u : 0u);

            w[0] = (uint32_t)((addr >> 16) & 0xFFFF0000ull)
                 | ((((uint16_t)dwords << 8) + 3840u) & 0xF00u)
                 | ((cmp & 7u) << 13)
                 | ((flush & 1u) << 12)
                 | 1u;
            w[1] = (uint32_t)(addr & 0xFFFFFFFFu);
            if (ref != 0) {
                w[2] = (uint32_t)(ref & 0xFFFFFFFFu);
                if (dwords == 4) w[3] = (uint32_t)(ref >> 32);
            }
            ampr_strict_write_words(cb, offBytes, w, dwords);
            break;
        }
        case OpType::WaitOnCounter: {
            uint8_t idx = op.u8a;
            uint32_t ref = op.u32a;
            uint32_t cmp = (op.u32b & 7u);
            uint32_t flush = (op.u32c & 1u);
            uint32_t dwords = (ref < 0x100u) ? 1u : 2u;

            w[0] = ((ref & 0xFFu) << 16)
                 | ((((uint16_t)dwords << 8) + 3840u) & 0xF00u)
                 | ((cmp & 7u) << 13)
                 | ((flush & 1u) << 12)
                 | ((uint32_t)idx << 24)
                 | 2u;
            if (dwords == 2u) w[1] = (ref >> 8);
            ampr_strict_write_words(cb, offBytes, w, dwords);
            break;
        }
        case OpType::WriteAddress: {
            uint64_t addr = (uint64_t)op.ptra;
            uint64_t val  = op.u64a;
            // "OnCompletion" flavour (FW10 uses opcode 117)
            uint32_t dwords = 4;
            if (val < 0x400000000ull) dwords = (val < 4ull) ? 2u : 3u;

            w[0] = (uint32_t)((addr >> 16) & 0xFFFF0000ull)
                 | ((((uint16_t)dwords << 8) + 3840u) & 0xF00u)
                 | 117u
                 | ((uint32_t)(val & 3ull) << 12)
                 | ((uint32_t)((uint16_t)dwords) << 14);
            w[0] ^= 0x8000u;
            w[1] = (uint32_t)(addr & 0xFFFFFFF8ull);
            if (val >= 4ull) {
                w[2] = (uint32_t)(val >> 2);
                if (val - 4ull >= 0x3FFFFFFFCull) w[3] = (uint32_t)(val >> 34);
            }
            ampr_strict_write_words(cb, offBytes, w, dwords);
            break;
        }
        case OpType::WriteCounter: {
            uint8_t idx = op.u8a;
            uint32_t val = op.u32a;
            uint32_t dwords = (val < 0x1000u) ? 1u : 2u;

            w[0] = ((val << 12) & 0xFFF000u)
                 | ((((uint16_t)dwords << 8) + 3840u) & 0xF00u)
                 | ((uint32_t)idx << 24)
                 | 6u;
            if (dwords == 2u) w[1] = (val >> 12);
            ampr_strict_write_words(cb, offBytes, w, dwords);
            break;
        }
        case OpType::WriteEqueue: {
            uint64_t eq = op.u64b;
            int32_t id = (int32_t)op.u32b;
            uint64_t data = op.u64a;
            // Use the "on completion" opcode variant (1144) from FW10.
            w[0] = 1144u | (uint32_t)((eq >> 16) & 0xFFFF0000ull);
            w[1] = (uint32_t)eq;
            w[2] = (uint32_t)id;
            w[3] = (uint32_t)(data & 0xFFFFFFFFu);
            w[4] = (uint32_t)(data >> 32);
            ampr_strict_write_words(cb, offBytes, w, 5u);
            break;
        }
        case OpType::Nop: {
            uint32_t n = op.u32a;
            if (!op.u32b) {
                if (!n) break;
                uint32_t n0x3C = 4u * n - 4u;
                w[0] = (n0x3C << 6) | 0x5452000Fu;
                ampr_strict_write_words(cb, offBytes, w, 1u);
            } else {
                w[0] = ((n & 0xFu) << 8) | 0x5452000Fu;
                ampr_strict_write_words(cb, offBytes, w, 1u);
                uint32_t bytes = n * 4u;
                if (op.cptr && bytes && offBytes + 4u + bytes <= cb->bufsize) {
                    std::memcpy((uint8_t*)cb->buffer + offBytes + 4u, op.cptr, bytes);
                }
            }
            break;
        }
        default:
            // For other ops we keep the zero-filled placeholder.
            break;
    }
}

static int cb_append(SceAmprCommandBuffer* cb, Op&& op) {
    if (!cb) return SCE_KERNEL_ERROR_EINVAL;
    if (!cb->buffer) return SCE_KERNEL_ERROR_EPERM;
    auto& st = state_for(cb);
    std::lock_guard<std::mutex> lk(st.m);
    if (st.inFlight) return SCE_KERNEL_ERROR_EBUSY;

    uint32_t sz = ampr_op_size_bytes(op);
    uint32_t off = cb->offset;

    // Capacity check (best-effort). SDK methods typically return EBUSY when the
    // command buffer has insufficient remaining space.
    if (off + sz > cb->bufsize) return SCE_KERNEL_ERROR_EBUSY;

    // Optionally emit a packed u32 stream for clients that inspect the command buffer.
    ampr_strict_write_op(cb, off, op);

    op.bufOffsetBytes = off;
    st.ops.push_back(std::move(op));

    cb->num += 1;
    cb->offset = off + sz;
    return 0;
}


int CommandBuffer::waitOnAddress(volatile uint64_t* address, uint64_t refValue, WaitCompare eCmp, WaitFlush eFlush) {
    if (!ampr_valid_u64_addr(address)) return SCE_KERNEL_ERROR_EINVAL;
    if (!ampr_valid_wait_compare(eCmp)) return SCE_KERNEL_ERROR_EINVAL;
    if (!ampr_valid_wait_flush(eFlush)) return SCE_KERNEL_ERROR_EINVAL;
    Op op; op.type=OpType::WaitOnAddress; op.ptra=(void*)address; op.u64a=refValue; op.u32a=(uint32_t)eCmp; op.u32c=(uint32_t)eFlush;
    return cb_append(&m_commandBuffer, std::move(op));
}

int CommandBuffer::waitOnCounter(uint8_t counterIndex, uint32_t refValue, WaitCompare eCmp, WaitFlush eFlush) {
    if ((uint32_t)counterIndex >= kMaxCounters) return SCE_KERNEL_ERROR_EINVAL;
    if (!ampr_valid_wait_compare(eCmp)) return SCE_KERNEL_ERROR_EINVAL;
    if (!ampr_valid_wait_flush(eFlush)) return SCE_KERNEL_ERROR_EINVAL;
    Op op; op.type=OpType::WaitOnCounter; op.u8a=counterIndex; op.u32a=refValue; op.u32b=(uint32_t)eCmp; op.u32c=(uint32_t)eFlush;
    return cb_append(&m_commandBuffer, std::move(op));
}

int CommandBuffer::writeAddressOnCompletion(volatile uint64_t* address, uint64_t value) {
    if (!ampr_valid_u64_addr(address)) return SCE_KERNEL_ERROR_EINVAL;
    Op op; op.type=OpType::WriteAddress; op.ptra=(void*)address; op.u64a=value;
    return cb_append(&m_commandBuffer, std::move(op));
}

int CommandBuffer::writeCounterOnCompletion(uint8_t counterIndex, uint32_t value) {
    if ((uint32_t)counterIndex >= kMaxCounters) return SCE_KERNEL_ERROR_EINVAL;
    Op op; op.type=OpType::WriteCounter; op.u8a=counterIndex; op.u32a=value;
    return cb_append(&m_commandBuffer, std::move(op));
}

int CommandBuffer::writeKernelEventQueueOnCompletion(SceKernelEqueue eq, int32_t id, uint64_t data) {
    if (!eq) return SCE_KERNEL_ERROR_EINVAL;
    Op op; op.type=OpType::WriteEqueue;
    op.u64b = (uint64_t)(uintptr_t)eq;
    op.u32b = (uint32_t)id;
    op.u64a = data;
    return cb_append(&m_commandBuffer, std::move(op));
}

int CommandBuffer::writeAddressFromTimeCounterOnCompletion(volatile uint64_t* address) {
    if (!ampr_valid_u64_addr(address)) return SCE_KERNEL_ERROR_EINVAL;
    Op op; op.type=OpType::WriteAddressFromTimeCounter; op.ptra=(void*)address;
    return cb_append(&m_commandBuffer, std::move(op));
}

int CommandBuffer::writeAddressFromCounterOnCompletion(volatile uint64_t* address, uint8_t counterIndex) {
    if (!ampr_valid_u64_addr(address)) return SCE_KERNEL_ERROR_EINVAL;
    if ((uint32_t)counterIndex >= kMaxCounters) return SCE_KERNEL_ERROR_EINVAL;
    Op op; op.type=OpType::WriteAddressFromCounter; op.ptra=(void*)address; op.u8a=counterIndex;
    return cb_append(&m_commandBuffer, std::move(op));
}

int CommandBuffer::writeAddressFromCounterPairOnCompletion(volatile uint64_t* address, uint8_t counterIndex) {
    if (!ampr_valid_u64_addr(address)) return SCE_KERNEL_ERROR_EINVAL;
    // SDK requires a 2-aligned index, and the pair uses index and index+1.
    if ((counterIndex & 1u) != 0) return SCE_KERNEL_ERROR_EINVAL;
    if ((uint32_t)counterIndex + 1u >= kMaxCounters) return SCE_KERNEL_ERROR_EINVAL;
    Op op; op.type=OpType::WriteAddressFromCounterPair; op.ptra=(void*)address; op.u8a=counterIndex;
    return cb_append(&m_commandBuffer, std::move(op));
}

int CommandBuffer::nop(uint32_t numU32) {
    if (numU32 == 0 || numU32 > 16) return SCE_KERNEL_ERROR_EINVAL;
    Op op; op.type=OpType::Nop; op.u32a=numU32; op.u32b=0; // no payload variant
    return cb_append(&m_commandBuffer, std::move(op));
}

int CommandBuffer::nop(uint32_t numU32, const uint32_t* data) {
    if (numU32 > 15) return SCE_KERNEL_ERROR_EINVAL;
    Op op; op.type=OpType::Nop; op.u32a=numU32; op.u32b=1; op.cptr=data; // payload may be NULL (SDK allows reserving space)
    return cb_append(&m_commandBuffer, std::move(op));
}

int CommandBuffer::setMarker(const char* msg) {
    if (!msg) return SCE_KERNEL_ERROR_EINVAL;
    Op op; op.type=OpType::MarkerSet; op.s = msg;
    return cb_append(&m_commandBuffer, std::move(op));
}

int CommandBuffer::setMarker(const char* msg, uint32_t) {
    return setMarker(msg);
}

int CommandBuffer::pushMarker(const char* msg) {
    if (!msg) return SCE_KERNEL_ERROR_EINVAL;
    Op op; op.type=OpType::MarkerPush; op.s = msg;
    return cb_append(&m_commandBuffer, std::move(op));
}

int CommandBuffer::pushMarker(const char* msg, uint32_t) {
    return pushMarker(msg);
}

int CommandBuffer::popMarker() {
    Op op; op.type=OpType::MarkerPop;
    return cb_append(&m_commandBuffer, std::move(op));
}

int CommandBuffer::reset(void) {
    auto& st = state_for(&m_commandBuffer);
    std::lock_guard<std::mutex> lk(st.m);
    if (!m_commandBuffer.buffer) return SCE_KERNEL_ERROR_EPERM;
    if (st.inFlight) return SCE_KERNEL_ERROR_EBUSY;
    m_commandBuffer.offset = 0;
    m_commandBuffer.num = 0;
    st.ops.clear();
    return 0;
}

// ---------------- AMM command buffer ----------------
AmmCommandBuffer::AmmCommandBuffer(void) : CommandBuffer() {}
AmmCommandBuffer::~AmmCommandBuffer(void) = default;


int AmmCommandBuffer::map(uint64_t va, uint64_t size, int type, int prot) {
    Op op; op.type=OpType::AmmMap; op.u64a=va; op.u64b=size; op.u32a=(uint32_t)prot; op.u32b=(uint32_t)type;
    return cb_append(&m_commandBuffer, std::move(op));
}

int AmmCommandBuffer::mapWithGpuMaskId(uint64_t va, uint64_t size, int type, int prot, uint8_t) {
    return map(va, size, type, prot);
}

int AmmCommandBuffer::mapDirect(uint64_t va, uint64_t dmemOffset, size_t size, int type, int prot) {
    Op op; op.type=OpType::AmmMapDirect; op.u64a=va; op.u64b=dmemOffset; op.u64c=size; op.u32a=(uint32_t)prot; op.u32b=(uint32_t)type;
    return cb_append(&m_commandBuffer, std::move(op));
}

int AmmCommandBuffer::mapDirectWithGpuMaskId(uint64_t va, uint64_t dmemOffset, uint64_t size, int type, int prot, uint8_t) {
    return mapDirect(va, dmemOffset, (size_t)size, type, prot);
}

int AmmCommandBuffer::unmap(uint64_t va, size_t size) {
    Op op; op.type=OpType::AmmUnmap; op.u64a=va; op.u64b=size;
    return cb_append(&m_commandBuffer, std::move(op));
}

int AmmCommandBuffer::remap(uint64_t vaNewStart, uint64_t vaOldStart, uint64_t vaSize, int prot) {
    Op op; op.type=OpType::AmmRemap; op.u64a=vaNewStart; op.u64b=vaOldStart; op.u64c=vaSize; op.u32a=(uint32_t)prot;
    return cb_append(&m_commandBuffer, std::move(op));
}

int AmmCommandBuffer::remapWithGpuMaskId(uint64_t vaNewStart, uint64_t vaOldStart, uint64_t vaSize, int prot, uint8_t) {
    return remap(vaNewStart, vaOldStart, vaSize, prot);
}

int AmmCommandBuffer::multiMap(uint64_t vaNewStart, uint64_t vaAliasStart, uint64_t vaSize, int prot) {
    Op op; op.type=OpType::AmmMultiMap; op.u64a=vaNewStart; op.u64b=vaAliasStart; op.u64c=vaSize; op.u32a=(uint32_t)prot;
    return cb_append(&m_commandBuffer, std::move(op));
}

int AmmCommandBuffer::multiMapWithGpuMaskId(uint64_t vaNewStart, uint64_t vaAliasStart, uint64_t vaSize, int prot, uint8_t) {
    return multiMap(vaNewStart, vaAliasStart, vaSize, prot);
}

int AmmCommandBuffer::modifyProtect(uint64_t va, uint64_t size, int prot, int) {
    Op op; op.type=OpType::AmmModifyProtect; op.u64a=va; op.u64b=size; op.u32a=(uint32_t)prot;
    return cb_append(&m_commandBuffer, std::move(op));
}

int AmmCommandBuffer::modifyProtectWithGpuMaskId(uint64_t va, uint64_t size, int prot, int protMask, uint8_t) {
    return modifyProtect(va, size, prot, protMask);
}

int AmmCommandBuffer::modifyMtypeProtect(uint64_t va, uint64_t size, int type, int prot, int) {
    Op op; op.type=OpType::AmmModifyMtypeProtect; op.u64a=va; op.u64b=size; op.u32a=(uint32_t)prot; op.u32b=(uint32_t)type;
    return cb_append(&m_commandBuffer, std::move(op));
}

int AmmCommandBuffer::modifyMtypeProtectWithGpuMaskId(uint64_t va, uint64_t size, int type, int prot, int protMask, uint8_t) {
    return modifyMtypeProtect(va, size, type, prot, protMask);
}

int AmmCommandBuffer::mapAsPrt(uint64_t va, uint64_t size) {
    Op op; op.type=OpType::AmmMapAsPrt; op.u64a=va; op.u64b=size;
    return cb_append(&m_commandBuffer, std::move(op));
}

int AmmCommandBuffer::allocatePaForPrt(uint64_t va, uint64_t size, int type, int prot) {
    Op op; op.type=OpType::AmmAllocPaForPrt;
    op.u64a = va; op.u64b = size;
    op.u32a = (uint32_t)prot;
    op.u32b = (uint32_t)type; // currently unused in emulation, kept for signature/trace
    return cb_append(&m_commandBuffer, std::move(op));
}


int AmmCommandBuffer::remapIntoPrt(uint64_t va, uint64_t size, uint64_t arg4, int prot) {
    Op op; op.type=OpType::AmmRemapIntoPrt;
    op.u64a = va; op.u64b = size; op.u64c = arg4; op.u32a = (uint32_t)prot;
    return cb_append(&m_commandBuffer, std::move(op));
}


int AmmCommandBuffer::unmapToPrt(uint64_t va, uint64_t size) {
    Op op; op.type=OpType::AmmUnmapToPrt;
    op.u64a = va; op.u64b = size;
    return cb_append(&m_commandBuffer, std::move(op));
}

// ---------------- APR command buffer ----------------
AprCommandBuffer::AprCommandBuffer(void) : CommandBuffer() {
    // SDK initializes these extra state blocks to 0.
    m_mapState.asU64 = 0;
    m_scatterGatherState.asU64 = 0;
}
AprCommandBuffer::~AprCommandBuffer(void) = default;


int AprCommandBuffer::readFile(SceAprFileId fileId, void* buffer, uint64_t length, uint64_t offset) {
    Op op; op.type=OpType::AprReadFile; op.u32a=(uint32_t)fileId; op.ptra=buffer; op.u64a=length; op.u64b=offset;
    return cb_append(&m_commandBuffer, std::move(op));
}

int AprCommandBuffer::readFileGather(uint64_t length, uint64_t offset) {
    Op op; op.type=OpType::AprReadGather; op.u64a=length; op.u64b=offset;
    return cb_append(&m_commandBuffer, std::move(op));
}

int AprCommandBuffer::readFileScatter(void* buffer, uint64_t length) {
    Op op; op.type=OpType::AprReadScatter; op.ptra=buffer; op.u64a=length;
    return cb_append(&m_commandBuffer, std::move(op));
}

int AprCommandBuffer::readFileGatherScatter(void* buffer, uint64_t length, uint64_t offset) {
    Op op; op.type=OpType::AprReadGatherScatter; op.ptra=buffer; op.u64a=length; op.u64b=offset;
    return cb_append(&m_commandBuffer, std::move(op));
}

int AprCommandBuffer::resetGatherScatterState() {
    Op op; op.type=OpType::AprResetGatherScatter;
    return cb_append(&m_commandBuffer, std::move(op));
}



int AprCommandBuffer::mapBegin(uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)a2; (void)a3; (void)a4; (void)a5;
    Op op; op.type=OpType::AprMapBegin;
    op.u64a=a2; op.u64b=a3; op.u64c=a4; op.u32a=(uint32_t)a5;
    return cb_append(&m_commandBuffer, std::move(op));
}


int AprCommandBuffer::mapDirectBegin(uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6) {
    (void)a2; (void)a3; (void)a4; (void)a5; (void)a6;
    Op op; op.type=OpType::AprMapDirectBegin;
    op.u64a=a2; op.u64b=a3; op.u64c=a4; op.u32a=(uint32_t)a5; op.u32b=(uint32_t)a6;
    return cb_append(&m_commandBuffer, std::move(op));
}


int AprCommandBuffer::mapEnd() {
    Op op; op.type=OpType::AprMapEnd;
    return cb_append(&m_commandBuffer, std::move(op));
}

// ---------------- AMM service ----------------
void Amm::getVirtualAddressRanges(AmmVirtualAddressRanges& ranges) {
    std::call_once(g_va_once, init_va_ranges);
    ranges = g_va_ranges;
}


int Amm::giveDirectMemory(off_t searchStart, off_t searchEnd, size_t size, size_t align, Usage usage, off_t* dmemOffset) {
    (void)searchStart; (void)searchEnd; (void)usage;
    if (!dmemOffset) return SCE_KERNEL_ERROR_EFAULT;
    if (usage != Usage::kAuto && usage != Usage::kDirect) return SCE_KERNEL_ERROR_EINVAL;
    if (size == 0 || (size % (2ull * 1024 * 1024)) != 0) return SCE_KERNEL_ERROR_EINVAL;
    if (align != 0 && (align % (2ull * 1024 * 1024)) != 0) return SCE_KERNEL_ERROR_EINVAL;
    uint64_t off=0;
    DmemUsage du = (usage == Usage::kAuto) ? DmemUsage::Auto : DmemUsage::Direct;
    int rc = dmem_pool_add(du, size, align ? align : 0, SCE_KERNEL_MTYPE_C_SHARED, &off);
    if (rc != 0) {
        uint32_t u = (uint32_t)rc;
        if ((u & 0xFFFF0000u) == 0x80020000u) return rc;
        return ampr_sce_errno_from_posix(rc < 0 ? -rc : rc);
    }
    *dmemOffset = (off_t)off;
    return 0;
}


int Amm::submitCommandBuffer(const AmmCommandBuffer* commandBuffer, Priority pri) {
    SceAmmSubmitId id{};
    return submitCommandBuffer((AmmCommandBuffer*)commandBuffer, pri, &id);
}

int Amm::submitCommandBuffer(AmmCommandBuffer* commandBuffer, Priority pri, SceAmmSubmitId* id) {
    return submitCommandBufferAndGetResult(commandBuffer, pri, nullptr, id);
}


int Amm::submitCommandBufferAndGetResult(AmmCommandBuffer* commandBuffer, Priority prio, SceAmmResultBuffer* res, SceAmmSubmitId* id) {
    if (!commandBuffer) return SCE_KERNEL_ERROR_EINVAL;
    if (!commandBuffer->m_commandBuffer.buffer) return SCE_KERNEL_ERROR_EPERM;
    if (commandBuffer->m_commandBuffer.num == 0) return SCE_KERNEL_ERROR_EINVAL;
    if (prio != Priority::kHigh && prio != Priority::kMid && prio != Priority::kLow) return SCE_KERNEL_ERROR_EINVAL;

    {
        auto& st = state_for(&commandBuffer->m_commandBuffer);
        std::lock_guard<std::mutex> lk(st.m);
        if (st.inFlight) return SCE_KERNEL_ERROR_EBUSY;
        st.inFlight = true;
    }

    uint64_t sid = g_next_submit.fetch_add(1);
    if (id) *id = (SceAmmSubmitId)sid;
    Job j;
    j.id = sid;
    j.cb = &commandBuffer->m_commandBuffer;
    j.isAmm = true;
    j.prioIndex = (prio == Priority::kHigh ? 0 : (prio == Priority::kMid ? 1 : 2));
    j.ammRes = res;
    g_amm_exec.submit(j);
    return 0;
}


int Amm::waitCommandBufferCompletion(SceAmmSubmitId id) {
    return g_amm_exec.wait((uint64_t)id);
}

// ---------------- APR service ----------------
int Apr::resolveFilepathsToIds(const char* path[], uint32_t num, SceAprFileId ids[], uint32_t* errorIndex) {
    if (!path || !ids) return SCE_KERNEL_ERROR_EINVAL;
    for (uint32_t i=0;i<num;i++) {
        uint32_t id=0;
        int rc = resolve_path_to_id(path[i], &id, nullptr);
        if (rc!=0) { if (errorIndex) *errorIndex=i; return ampr_sce_errno_from_posix(rc < 0 ? -rc : rc); }
        ids[i]=id;
    }
    return 0;
}

int Apr::resolveFilepathsToIdsAndFileSizes(const char* path[], uint32_t num, SceAprFileId ids[], size_t fileSizes[], uint32_t* errorIndex) {
    if (!path || !ids || !fileSizes) return SCE_KERNEL_ERROR_EINVAL;
    for (uint32_t i=0;i<num;i++) {
        uint32_t id=0; size_t sz=0;
        int rc = resolve_path_to_id(path[i], &id, &sz);
        if (rc!=0) { if (errorIndex) *errorIndex=i; return ampr_sce_errno_from_posix(rc < 0 ? -rc : rc); }
        ids[i]=id; fileSizes[i]=sz;
    }
    return 0;
}
static std::string join_prefix(const char* prefix, const char* p) {
    std::string a = prefix ? prefix : "";
    std::string b = p ? p : "";
    if (!a.empty() && a.back()=='/') return a + b;
    if (!a.empty()) return a + "/" + b;
    return b;
}

int Apr::resolveFilepathsWithPrefixToIds(const char* pathPrefix, const char* path[], uint32_t num, SceAprFileId ids[], uint32_t* errorIndex) {
    if (!path || !ids) return SCE_KERNEL_ERROR_EINVAL;
    for (uint32_t i=0;i<num;i++) {
        auto full = join_prefix(pathPrefix, path[i]);
        uint32_t id=0;
        int rc = resolve_path_to_id(full.c_str(), &id, nullptr);
        if (rc!=0) { if (errorIndex) *errorIndex=i; return ampr_sce_errno_from_posix(rc < 0 ? -rc : rc); }
        ids[i]=id;
    }
    return 0;
}

int Apr::resolveFilepathsWithPrefixToIdsAndFileSizes(const char* pathPrefix, const char* path[], uint32_t num, SceAprFileId ids[], size_t fileSizes[], uint32_t* errorIndex) {
    if (!path || !ids || !fileSizes) return SCE_KERNEL_ERROR_EINVAL;
    for (uint32_t i=0;i<num;i++) {
        auto full = join_prefix(pathPrefix, path[i]);
        uint32_t id=0; size_t sz=0;
        int rc = resolve_path_to_id(full.c_str(), &id, &sz);
        if (rc!=0) { if (errorIndex) *errorIndex=i; return ampr_sce_errno_from_posix(rc < 0 ? -rc : rc); }
        ids[i]=id; fileSizes[i]=sz;
    }
    return 0;
}

// forEach variants: write per-item rc
int Apr::resolveFilepathsToIdsForEach(const char* path[], uint32_t num, SceAprFileId ids[], int results[]) {
    if (!path || !ids || !results) return SCE_KERNEL_ERROR_EINVAL;
    for (uint32_t i=0;i<num;i++) {
        uint32_t id=0;
        int rc = resolve_path_to_id(path[i], &id, nullptr);
        results[i] = (rc==0)?0:ampr_sce_errno_from_posix(rc < 0 ? -rc : rc);
        ids[i]=id;
    }
    return 0;
}

int Apr::resolveFilepathsToIdsAndFileSizesForEach(const char* path[], uint32_t num, SceAprFileId ids[], size_t fileSizes[], int results[]) {
    if (!path || !ids || !fileSizes || !results) return SCE_KERNEL_ERROR_EINVAL;
    for (uint32_t i=0;i<num;i++) {
        uint32_t id=0; size_t sz=0;
        int rc = resolve_path_to_id(path[i], &id, &sz);
        results[i] = (rc==0)?0:ampr_sce_errno_from_posix(rc < 0 ? -rc : rc);
        ids[i]=id; fileSizes[i]=sz;
    }
    return 0;
}

int Apr::resolveFilepathsWithPrefixToIdsForEach(const char* pathPrefix, const char* path[], uint32_t num, SceAprFileId ids[], int results[]) {
    if (!path || !ids || !results) return SCE_KERNEL_ERROR_EINVAL;
    for (uint32_t i=0;i<num;i++) {
        auto full = join_prefix(pathPrefix, path[i]);
        uint32_t id=0;
        int rc = resolve_path_to_id(full.c_str(), &id, nullptr);
        results[i] = (rc==0)?0:ampr_sce_errno_from_posix(rc < 0 ? -rc : rc);
        ids[i]=id;
    }
    return 0;
}

int Apr::resolveFilepathsWithPrefixToIdsAndFileSizesForEach(const char* pathPrefix, const char* path[], uint32_t num, SceAprFileId ids[], size_t fileSizes[], int results[]) {
    if (!path || !ids || !fileSizes || !results) return SCE_KERNEL_ERROR_EINVAL;
    for (uint32_t i=0;i<num;i++) {
        auto full = join_prefix(pathPrefix, path[i]);
        uint32_t id=0; size_t sz=0;
        int rc = resolve_path_to_id(full.c_str(), &id, &sz);
        results[i] = (rc==0)?0:ampr_sce_errno_from_posix(rc < 0 ? -rc : rc);
        ids[i]=id; fileSizes[i]=sz;
    }
    return 0;
}


int Apr::getFileSize(SceAprFileId fileId, size_t* size) {
    if (!size) return SCE_KERNEL_ERROR_EFAULT;
    FileEntry e;
    int rc = get_entry((uint32_t)fileId, &e);
    if (rc!=0) return ampr_sce_errno_from_posix(rc < 0 ? -rc : rc);
    *size = e.size;
    return 0;
}


int Apr::getFileStat(SceAprFileId fileId, SceKernelStat* st) {
    if (!st) return SCE_KERNEL_ERROR_EFAULT;
    FileEntry e;
    int rc = get_entry((uint32_t)fileId, &e);
    if (rc!=0) return ampr_sce_errno_from_posix(rc < 0 ? -rc : rc);
    struct stat s{};
    rc = stat_path(e.path.c_str(), &s);
    if (rc!=0) return ampr_sce_errno_from_posix(rc < 0 ? -rc : rc);
    // SceKernelStat layout is assumed compatible with struct stat in this header's environment.
    std::memcpy(st, &s, std::min(sizeof(*st), sizeof(s)));
    return 0;
}


int Apr::submitCommandBuffer(AprCommandBuffer* commandBuffer, Priority prio) {
    SceAprSubmitId id{};
    return submitCommandBuffer(commandBuffer, prio, &id);
}

int Apr::submitCommandBuffer(AprCommandBuffer* commandBuffer, Priority prio, SceAprSubmitId* id) {
    return submitCommandBufferAndGetResult(commandBuffer, prio, nullptr, id);
}

int Apr::submitCommandBufferAndGetResult(AprCommandBuffer* commandBuffer, Priority prio, SceAprResultBuffer* res, SceAprSubmitId* id) {
    if (!commandBuffer) return SCE_KERNEL_ERROR_EINVAL;
    if (!commandBuffer->m_commandBuffer.buffer) return SCE_KERNEL_ERROR_EPERM;
    if (commandBuffer->m_commandBuffer.num == 0) return SCE_KERNEL_ERROR_EINVAL;
    switch (prio) {
        case Priority::kPriority0:
        case Priority::kPriority1:
        case Priority::kPriority2:
        case Priority::kPriority3:
        case Priority::kPriority4:
        case Priority::kPriority5:
        case Priority::kPriority6:
            break;
        default:
            return SCE_KERNEL_ERROR_EINVAL;
    }

    {
        auto& st = state_for(&commandBuffer->m_commandBuffer);
        std::lock_guard<std::mutex> lk(st.m);
        if (st.inFlight) return SCE_KERNEL_ERROR_EBUSY;
        st.inFlight = true;
    }

    uint64_t sid = g_next_submit.fetch_add(1);
    if (id) *id = (SceAprSubmitId)sid;
    Job j;
    j.id = sid;
    j.cb = &commandBuffer->m_commandBuffer;
    j.isAmm = false;
    j.prioIndex = (uint8_t)prio; // 0..6
    j.aprRes = res;
    g_apr_exec.submit(j);
    return 0;
}

int Apr::waitCommandBufferCompletion(SceAprSubmitId id) {
    return g_apr_exec.wait((uint64_t)id);
}

// ---------------- Measure*CommandSize (best-effort; returns a stable upper bound)
int MeasureCommandSize::waitOnAddress(volatile uint64_t*, uint64_t refValue, WaitCompare, WaitFlush) {
    uint32_t dwords = 4;
    if ((refValue >> 32) == 0) dwords = 3u - (refValue == 0 ? 1u : 0u);
    return (int)(dwords * 4u);
}

int MeasureCommandSize::waitOnCounter(uint8_t, uint32_t refValue, WaitCompare, WaitFlush) {
    uint32_t dwords = (refValue < 0x100u) ? 1u : 2u;
    return (int)(dwords * 4u);
}

int MeasureCommandSize::writeAddressOnCompletion(volatile uint64_t*, uint64_t value) {
    uint32_t dwords = 4;
    if (value < 0x400000000ull) dwords = (value < 4ull) ? 2u : 3u;
    return (int)(dwords * 4u);
}

int MeasureCommandSize::writeCounterOnCompletion(uint8_t, uint32_t value) {
    uint32_t dwords = (value < 0x1000u) ? 1u : 2u;
    return (int)(dwords * 4u);
}
int MeasureCommandSize::writeKernelEventQueueOnCompletion(SceKernelEqueue, int32_t, uint64_t) { return 20; }
int MeasureCommandSize::nop(uint32_t numU32) { return (int)(numU32 * 4u); }
int MeasureCommandSize::nop(uint32_t numU32, const uint32_t*) { return (int)((numU32 + 1u) * 4u); }

int MeasureAmmCommandSize::map(uint64_t, uint64_t, int, int) { return 32; }
int MeasureAmmCommandSize::mapWithGpuMaskId(uint64_t, uint64_t, int, int, uint8_t) { return 32; }
int MeasureAmmCommandSize::mapDirect(uint64_t, uint64_t, size_t, int, int) { return 40; }
int MeasureAmmCommandSize::mapDirectWithGpuMaskId(uint64_t, uint64_t, uint64_t, int, int, uint8_t) { return 40; }
int MeasureAmmCommandSize::unmap(uint64_t, size_t) { return 24; }
int MeasureAmmCommandSize::remap(uint64_t, uint64_t, uint64_t, int) { return 36; }
int MeasureAmmCommandSize::remapWithGpuMaskId(uint64_t, uint64_t, uint64_t, int, uint8_t) { return 36; }
int MeasureAmmCommandSize::multiMap(uint64_t, uint64_t, uint64_t, int) { return 32; }
int MeasureAmmCommandSize::multiMapWithGpuMaskId(uint64_t, uint64_t, uint64_t, int, uint8_t) { return 32; }
int MeasureAmmCommandSize::modifyProtect(uint64_t, uint64_t, int, int) { return 28; }
int MeasureAmmCommandSize::modifyProtectWithGpuMaskId(uint64_t, uint64_t, int, int, uint8_t) { return 28; }
int MeasureAmmCommandSize::modifyMtypeProtect(uint64_t, uint64_t, int, int, int) { return 32; }
int MeasureAmmCommandSize::modifyMtypeProtectWithGpuMaskId(uint64_t, uint64_t, int, int, int, uint8_t) { return 32; }
int MeasureAmmCommandSize::mapAsPrt(uint64_t, uint64_t) { return 32; }
int MeasureAmmCommandSize::allocatePaForPrt(uint64_t, uint64_t, int, int) { return 32; }

int MeasureAprCommandSize::readFile(SceAprFileId, void*, uint64_t, uint64_t) { return 16; }
int MeasureAprCommandSize::readFileGather(uint64_t, uint64_t) { return 16; }
int MeasureAprCommandSize::readFileScatter(void*, uint64_t) { return 16; }
int MeasureAprCommandSize::readFileGatherScatter(void*, uint64_t, uint64_t) { return 16; }
int MeasureAprCommandSize::resetGatherScatterState() { return 16; }
int MeasureAprCommandSize::setMarker(const char*, uint32_t) { return 16; }
int MeasureAprCommandSize::setMarker(const char*) { return 16; }
int MeasureAprCommandSize::pushMarker(const char*, uint32_t) { return 16; }
int MeasureAprCommandSize::pushMarker(const char*) { return 16; }
int MeasureAprCommandSize::popMarker() { return 16; }

} // namespace sce::Ampr

// -----------------------------
// Emulation-only helpers
// -----------------------------
namespace sce::Ampr::Emu {

int pinFileId(SceAprFileId fileId) {
    std::lock_guard<std::mutex> lk(g_file_m);
    auto it = g_files.find((uint32_t)fileId);
    if (it == g_files.end()) return -ENOENT;
    it->second.pinned = true;
    return 0;
}
int unpinFileId(SceAprFileId fileId) {
    std::lock_guard<std::mutex> lk(g_file_m);
    auto it = g_files.find((uint32_t)fileId);
    if (it == g_files.end()) return -ENOENT;
    it->second.pinned = false;
    return 0;
}

int pushEqueueEvent(SceKernelEqueue eq, uint32_t id, uint64_t data, int16_t filter, uint32_t fflags) {
#if AMPR_EMU_KERNEL_STUBS_QUEUE && !AMPR_EMU_QUEUE_BACKEND_KQUEUE
    eq_push_ex(eq, id, data, filter, fflags);
    return 0;
#else
    (void)eq; (void)id; (void)data; (void)filter; (void)fflags;
    return SCE_KERNEL_ERROR_EINVAL;
#endif
}

int addAmprEventWithFilter(SceKernelEqueue eq, uint32_t id, const SceKernelEventFilter* f) {
#if AMPR_EMU_KERNEL_STUBS_QUEUE && !AMPR_EMU_QUEUE_BACKEND_KQUEUE
    if (!f) return SCE_KERNEL_ERROR_EINVAL;
    auto q = eq_get(eq);
    if (!q) return SCE_KERNEL_ERROR_EBADF;
    std::lock_guard<std::mutex> lk(q->m);
    uint16_t flags = f->flags;
    int16_t filter = f->filter;
    uint32_t fflags = f->fflags;
    void* udata = f->udata;

    if (flags & SCE_KERNEL_EV_DELETE) {
        q->regs.erase(id);
        return 0;
    }

    auto it = q->regs.find(id);
    if (it == q->regs.end()) {
        EmuEqueue::Reg reg{};
        reg.id = id;
        reg.filter = filter;
        reg.flags = flags;
        reg.fflags = fflags;
        reg.udata = udata;
        reg.enabled = !(flags & SCE_KERNEL_EV_DISABLE);
        q->regs[id] = reg;
    } else {
        if (flags & SCE_KERNEL_EV_ADD) {
            it->second.filter = filter;
            it->second.flags = flags;
            it->second.fflags = fflags;
            it->second.udata = udata;
            it->second.enabled = !(flags & SCE_KERNEL_EV_DISABLE);
        } else {
            if (flags & SCE_KERNEL_EV_ENABLE) it->second.enabled = true;
            if (flags & SCE_KERNEL_EV_DISABLE) it->second.enabled = false;
        }
    }
    return 0;
#else
    (void)eq; (void)id; (void)f;
    return SCE_KERNEL_ERROR_EINVAL;
#endif
}


} // namespace sce::Ampr::Emu
