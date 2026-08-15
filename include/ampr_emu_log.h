/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Internal debug/log helpers.
 */

#pragma once

#include "ampr_debug_log.h"
#include "ampr_emu_config.h"

static inline void ampr_debug_int3_trap() {
#if defined(__x86_64__) || defined(__i386__)
    __asm__ volatile("int3" ::: "memory");
#else
    __builtin_trap();
#endif
}

static inline bool ampr_debug_log_runtime_enabled() {
#if AMPR_EMU_DEBUG_LOG
    return sce::Ampr::Emu::getDebugLogEnabled();
#else
    return false;
#endif
}

#if AMPR_EMU_DEBUG_LOG
#define AMPR_LOGF(...)                                                           \
    do {                                                                         \
        if (ampr_debug_log_runtime_enabled()) {                                  \
            sce::Ampr::Emu::debugLogf(__VA_ARGS__);                              \
        }                                                                        \
    } while (0)
#define AMPR_CRITICAL_LOGF(...)                                                  \
    do {                                                                         \
        if (ampr_debug_log_runtime_enabled()) {                                  \
            sce::Ampr::Emu::debugLogCriticalf(__VA_ARGS__);                      \
        }                                                                        \
    } while (0)
#else
#define AMPR_LOGF(...) ((void)0)
#define AMPR_CRITICAL_LOGF(...) ((void)0)
#endif

#if AMPR_EMU_DEBUG_LOG && (AMPR_EMU_DEBUG_LOG_VERBOSE || AMPR_EMU_DEBUG_LOG_TRACE)
#define AMPR_VLOGF(...) AMPR_LOGF(__VA_ARGS__)
#else
#define AMPR_VLOGF(...) ((void)0)
#endif

#if AMPR_EMU_DEBUG_LOG && AMPR_EMU_DEBUG_LOG_TRACE
#define AMPR_TLOGF(...) AMPR_LOGF(__VA_ARGS__)
#else
#define AMPR_TLOGF(...) ((void)0)
#endif

#if AMPR_EMU_DEBUG_LOG && AMPR_EMU_DEBUG_LOG_FILE_STATUS
#define AMPR_FILE_STATUS_LOGF(...) AMPR_LOGF(__VA_ARGS__)
#else
#define AMPR_FILE_STATUS_LOGF(...) ((void)0)
#endif

#define AMPR_FILE_WRAPPER_LOGF(...) ((void)0)
