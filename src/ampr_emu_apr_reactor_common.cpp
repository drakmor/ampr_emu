/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Shared APR reactor helpers.
 */

#define AMPR_EMU_CORE_IMPL 1
#include "ampr_emu_apr_reactor_common.h"
#include "ampr_emu_log.h"

const char* ampr_log_path_arg(const char* path) {
    return path ? path : "(null)";
}

uint64_t time_counter_now() {
    timespec ts{};
    (void)::sceKernelClockGettime(SCE_KERNEL_CLOCK_MONOTONIC, &ts);
    return uint64_t(ts.tv_sec) * 1000000000ull + uint64_t(ts.tv_nsec);
}

static constexpr unsigned kFdCacheWatermarkHighPercent = 85;
static constexpr unsigned kFdCacheWatermarkCriticalPercent = 95;
static constexpr unsigned kFdCacheWatermarkHighClosePercent =
    AMPR_EMU_FD_CACHE_EMFILE_IDLE_CLOSE_PERCENT < 25
        ? 25
        : AMPR_EMU_FD_CACHE_EMFILE_IDLE_CLOSE_PERCENT;
static constexpr unsigned kFdCacheWatermarkCriticalClosePercent =
    AMPR_EMU_FD_CACHE_EMFILE_IDLE_CLOSE_PERCENT < 50
        ? 50
        : AMPR_EMU_FD_CACHE_EMFILE_IDLE_CLOSE_PERCENT;

static size_t fd_cache_watermark_value(size_t budget, unsigned percent) {
    if (budget == 0) {
        return 0;
    }
    size_t value = (budget * percent + 99u) / 100u;
    if (value == 0) {
        value = 1;
    }
    return value < budget ? value : budget;
}

void fd_cache_release_watermark_headroom(size_t reserve, const char* reason) {
    const AmprIndexFdCacheStats stats = ampr_index_fd_cache_stats();
    if (stats.evictable == 0) {
        return;
    }
    const size_t budget = ampr_index_fd_open_budget_effective_cap();
    if (budget == 0) {
        return;
    }
    const size_t observed = stats.open + ampr_index_fd_direct_open_count();
    const size_t projected = observed + reserve;
    const size_t high = fd_cache_watermark_value(budget, kFdCacheWatermarkHighPercent);
    if (projected < high) {
        return;
    }
    const size_t critical = fd_cache_watermark_value(budget, kFdCacheWatermarkCriticalPercent);
    const bool criticalPressure = projected >= critical || projected > budget;
    const unsigned closePercent = criticalPressure
                                      ? kFdCacheWatermarkCriticalClosePercent
                                      : kFdCacheWatermarkHighClosePercent;
    const size_t closed = ampr_index_fd_cache_release_idle_percent(closePercent);
    (void)closed;
    AMPR_TLOGF("apr.fdcache.watermark reason=%s observed=%zu projected=%zu budget=%zu evictable=%zu closePercent=%u closed=%zu",
              reason ? reason : "unknown",
              observed,
              projected,
              budget,
              stats.evictable,
              closePercent,
              closed);
}

int apr_libkernel_rc_to_sce(int rc) {
    if (rc == 0) return 0;
    const uint32_t u = static_cast<uint32_t>(rc);
    if ((u & 0xFFFF0000u) == 0x80020000u) return rc;
    if (rc < 0) {
        return ampr_sce_errno_from_posix(errno ? errno : EIO);
    }
    return ampr_sce_errno_from_posix(rc);
}

