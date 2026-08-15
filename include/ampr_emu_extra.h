/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 */

#pragma once
#include "ampr.h"
#include "ampr_debug_log.h"
#include <stdint.h>

namespace sce::Ampr::Emu {

// Must be called after module_start.
void ensureApp0IndexStartup();

// Compatibility no-op; AMM event delivery is native.
void clearCommandBufferAmmCompletion(SceAmprCommandBuffer* cb);

int pinFileId(SceAprFileId fileId);
int unpinFileId(SceAprFileId fileId);

int mapperGetUsageStatsData(uint64_t* data);
int mapperSetPageTablePoolOccupancyNotificationThreshold(int threshold);

} // namespace sce::Ampr::Emu
