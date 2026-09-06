/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Internal debug/log helpers.
 */

#pragma once

#include "ampr_debug_log.h"
#include "ampr_emu_config.h"

#if AMPR_EMU_DEBUG_LOG
#include "ampr_emu_errno.h"

#include <errno.h>
#endif

#define AMPR_KLOGF(...) sce::Ampr::Emu::kernelDebugLogf(__VA_ARGS__)

#if AMPR_EMU_DEBUG_LOG
template <typename Result>
static inline Result ampr_klog_io_hook_result(const char* functionName,
                                              Result result) {
    if (result < 0) {
        const int savedErrno = errno;
        const int errorNumber =
            result == static_cast<Result>(-1) && savedErrno != 0
                ? savedErrno
                : ampr_posix_errno_from_sce(static_cast<int>(result));
        sce::Ampr::Emu::kernelIoErrorLog(functionName,
                                         "return",
                                         -1,
                                         static_cast<long long>(result),
                                         errorNumber);
    }
    return result;
}

template <typename Result>
static inline Result ampr_klog_io_hook_path_result(const char* functionName,
                                                   const char* path,
                                                   Result result) {
    if (result < 0) {
        const int savedErrno = errno;
        const int errorNumber =
            result == static_cast<Result>(-1) && savedErrno != 0
                ? savedErrno
                : ampr_posix_errno_from_sce(static_cast<int>(result));
        sce::Ampr::Emu::kernelIoErrorLog(functionName,
                                         "return",
                                         -1,
                                         static_cast<long long>(result),
                                         errorNumber,
                                         errorNumber == EFAULT ? nullptr : "path",
                                         errorNumber == EFAULT ? nullptr : path);
    }
    return result;
}

template <typename Result>
static inline Result ampr_klog_io_hook_paths_result(
    const char* functionName,
    const char* firstName,
    const char* firstValue,
    const char* secondName,
    const char* secondValue,
    Result result) {
    if (result < 0) {
        const int savedErrno = errno;
        const int errorNumber =
            result == static_cast<Result>(-1) && savedErrno != 0
                ? savedErrno
                : ampr_posix_errno_from_sce(static_cast<int>(result));
        const bool contextSafe = errorNumber != EFAULT;
        sce::Ampr::Emu::kernelIoErrorLog(
            functionName,
            "return",
            -1,
            static_cast<long long>(result),
            errorNumber,
            contextSafe ? firstName : nullptr,
            contextSafe ? firstValue : nullptr,
            contextSafe ? secondName : nullptr,
            contextSafe ? secondValue : nullptr);
    }
    return result;
}

static inline void ampr_klog_io_hook_output_error(const char* functionName,
                                                   const char* outputName,
                                                   int outputIndex,
                                                   int result) {
    if (result < 0) {
        sce::Ampr::Emu::kernelIoErrorLog(
            functionName,
            outputName,
            outputIndex,
            static_cast<long long>(result),
            ampr_posix_errno_from_sce(result));
    }
}

static inline void ampr_klog_io_hook_output_path_error(
    const char* functionName,
    const char* outputName,
    int outputIndex,
    int result,
    const char* path,
    const char* prefix = nullptr) {
    if (result < 0) {
        const int errorNumber = ampr_posix_errno_from_sce(result);
        const bool contextSafe = errorNumber != EFAULT;
        if (contextSafe && prefix) {
            sce::Ampr::Emu::kernelIoErrorLog(
                functionName,
                outputName,
                outputIndex,
                static_cast<long long>(result),
                errorNumber,
                "prefix",
                prefix,
                "path",
                path);
        } else {
            sce::Ampr::Emu::kernelIoErrorLog(
                functionName,
                outputName,
                outputIndex,
                static_cast<long long>(result),
                errorNumber,
                contextSafe ? "path" : nullptr,
                contextSafe ? path : nullptr);
        }
    }
}

#else

// Do not evaluate the diagnostic arguments or add a result comparison when
// debug logging is compiled out. The wrapped expression is evaluated once.
#define ampr_klog_io_hook_result(functionName, result) (result)
#define ampr_klog_io_hook_path_result(functionName, path, result) (result)
#define ampr_klog_io_hook_paths_result(functionName, firstName, firstValue, secondName, secondValue, result) (result)
#define ampr_klog_io_hook_output_error(...) ((void)0)
#define ampr_klog_io_hook_output_path_error(...) ((void)0)

#endif

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
