/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#pragma once

#include "ampr_emu_config.h"
#include <stdint.h>

namespace sce::Ampr::Emu {

// Always-on kernel debug output for fatal/invariant diagnostics. This path is
// independent of the optional file logger so a message can be emitted immediately
// before abort/trap paths even when AMPR_EMU_DEBUG_LOG is compiled out.
void kernelDebugLogf(const char* fmt, ...);
void setKernelDebugOutput(void* address);

#if AMPR_EMU_DEBUG_LOG
// Diagnostic used at intercepted file-I/O boundaries. The helper preserves
// errno so emitting the diagnostic cannot change the error observed by the
// title. outputName is "return" for a function return or an output name;
// outputIndex is -1 when the value is not indexed.
void kernelIoErrorLog(const char* functionName,
                      const char* outputName,
                      int outputIndex,
                      long long code,
                      int errorNumber,
                      const char* contextName = nullptr,
                      const char* contextValue = nullptr,
                      const char* context2Name = nullptr,
                      const char* context2Value = nullptr);
#endif

#if !AMPR_EMU_DEBUG_LOG

inline const char* getDebugLogPath() { return AMPR_EMU_DEBUG_LOG_PATH; }
inline bool getDebugLogEnabled() { return false; }
inline void setDebugLogEnabled(bool enabled) { (void)enabled; }
inline void startDebugLogWriter() {}
inline int shutdownDebugLog() { return 0; }
inline void debugLogLine(const char* rawLine) { (void)rawLine; }
inline void debugLogf(const char* fmt, ...) { (void)fmt; }
inline void debugLogCriticalf(const char* fmt, ...) { (void)fmt; }

#else

const char* getDebugLogPath();
bool getDebugLogEnabled();
void setDebugLogEnabled(bool enabled);
void startDebugLogWriter();
int shutdownDebugLog();
void debugLogLine(const char* rawLine);
void debugLogf(const char* fmt, ...);
void debugLogCriticalf(const char* fmt, ...);

#endif // AMPR_EMU_DEBUG_LOG

} // namespace sce::Ampr::Emu
