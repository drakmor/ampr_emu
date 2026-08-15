/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * AMPR command state, APR index, APR execution, and public C++ API module.
 */

#define AMPR_EMU_CORE_IMPL 1
#include "ampr_emu_fd_cache.h"
#include "ampr_emu_index.h"
#include "ampr_emu_log.h"
#include "ampr_emu_sync.h"
#include "ampr_libkernel_hook.h"

#include <ampr.h>
#include <errno.h>
#include <kernel.h>

namespace sce::Ampr::Emu {

void ensureApp0IndexStartup() {
#if AMPR_EMU_TIME_LIMIT_UNIX_SECONDS
    SceKernelTimeval now{};
    if (sceKernelGettimeofday(&now) == 0 &&
        now.tv_sec >= 0 &&
        static_cast<uint64_t>(now.tv_sec) >= static_cast<uint64_t>(AMPR_EMU_TIME_LIMIT_UNIX_SECONDS)) {
        AMPR_CRITICAL_LOGF("time_limit.expired now=%llu deadline=%llu",
                  (unsigned long long)now.tv_sec,
                  (unsigned long long)AMPR_EMU_TIME_LIMIT_UNIX_SECONDS);
        abort();
    }
#endif
    ampr_index_ensure_app0_index_before_apr_resolve_hook();
    amprFlushLibkernelHookLog();
}

int pinFileId(SceAprFileId fileId) {
    FileEntryView entry{};
    if (ampr_index_get_entry_view((uint32_t)fileId, &entry) != 0) return -ENOENT;
    uint32_t pinCount = 0;
    const int rc = ampr_index_pin_file_id((uint32_t)fileId, &pinCount);
    if (rc != 0) return rc;
    AMPR_LOGF("apr.pinFileId fileId=%u path=%s pinCount=%u",
              (unsigned)fileId, entry.path ? entry.path : "(null)", pinCount);
    return 0;
}
int unpinFileId(SceAprFileId fileId) {
    FileEntryView entry{};
    if (ampr_index_get_entry_view((uint32_t)fileId, &entry) != 0) return -ENOENT;
    uint32_t pinCount = 0;
    const int rc = ampr_index_unpin_file_id((uint32_t)fileId, &pinCount);
    if (rc != 0) return rc;
    AMPR_LOGF("apr.unpinFileId fileId=%u path=%s pinCount=%u",
              (unsigned)fileId, entry.path ? entry.path : "(null)", pinCount);
    return 0;
}

} // namespace sce::Ampr::Emu
