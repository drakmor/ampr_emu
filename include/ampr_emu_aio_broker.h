/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * Bounded bridge for native AIO reads owned outside the APR command stream.
 */

#pragma once

#include <kernel.h>

#include <cstddef>
#include <cstdint>

// Fixed external-read ownership shared by the broker and its pack producer.
// Requests still pass through the reactor's dynamic global admission window;
// this is storage capacity, not a reserved share of native SDK AIO IDs.
inline constexpr uint32_t kAprExternalAioCapacity = 32u;
inline constexpr uint32_t kAprExternalAioGroupMaxRequests = 32u;

enum class AprExternalAioClass : uint8_t {
    Latency,
    Balanced,
    Bulk,
};

enum class AprExternalAioEvent : uint8_t {
    Submitted,
    SubmitDeferred,
    SubmitFailed,
    Completed,
};

struct AprExternalAioNotification {
    AprExternalAioEvent event{AprExternalAioEvent::SubmitFailed};
    int value{};
    bool firstExternalInSubmitBatch{};
};

using AprExternalAioCallback = void (*)(
    void* context, const AprExternalAioNotification& notification);

// The request and its result storage must remain valid until the terminal
// SubmittedFailed or Completed notification. priority is an SDK AIO priority;
// ioClass controls completion-observation latency, not SDK request ordering.
int apr_reactor_submit_external_aio_read(
    const SceKernelAioRWRequest& request,
    int priority,
    AprExternalAioClass ioClass,
    void* context,
    AprExternalAioCallback callback);

// Submits every request in one SDK multiple-submit call and owns all returned
// ids until the group reaches a terminal state. The request array is copied by
// the broker; every request's buffers and result storage remain caller-owned
// and must outlive the terminal notification.
int apr_reactor_submit_external_aio_read_group(
    const SceKernelAioRWRequest* requests,
    size_t requestCount,
    int priority,
    AprExternalAioClass ioClass,
    void* context,
    AprExternalAioCallback callback);
