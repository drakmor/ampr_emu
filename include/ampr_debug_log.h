/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include "ampr_emu_config.h"
#include <stdint.h>

namespace sce::Ampr::Emu {

#if !AMPR_EMU_DEBUG_LOG

inline const char* getDebugLogPath() { return AMPR_EMU_DEBUG_LOG_PATH; }
inline bool getDebugLogEnabled() { return false; }
inline void setDebugLogEnabled(bool enabled) { (void)enabled; }
inline void startDebugLogWriter() {}
inline void shutdownDebugLog() {}
inline void debugLogLine(const char* rawLine) { (void)rawLine; }
inline void debugLogCriticalLine(const char* rawLine) { (void)rawLine; }
inline void debugLogf(const char* fmt, ...) { (void)fmt; }
inline void debugLogCriticalf(const char* fmt, ...) { (void)fmt; }
inline uint32_t debugLogCurrentThreadTag() { return 0; }

#else

const char* getDebugLogPath();
bool getDebugLogEnabled();
void setDebugLogEnabled(bool enabled);
void startDebugLogWriter();
void shutdownDebugLog();
void debugLogLine(const char* rawLine);
void debugLogCriticalLine(const char* rawLine);
void debugLogf(const char* fmt, ...);
void debugLogCriticalf(const char* fmt, ...);
uint32_t debugLogCurrentThreadTag();

#endif // AMPR_EMU_DEBUG_LOG

} // namespace sce::Ampr::Emu
