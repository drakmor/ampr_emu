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

#pragma once
/*
 * AMPR userland emulation configuration.
 *
 * This project implements the sce::Ampr public API in pure userland:
 * - AMM memory management commands map/unmap/remap via mmap/mprotect.
 * - APR file reads are executed by a userland thread pool using a pluggable I/O backend.
 *
 * Goals:
 * - Keep full control over file I/O (read-only, per original APR API) without kernel modules.
 * - Maximize throughput via batching, fd caching, and parallelism.
 */

#ifndef AMPR_EMU_ENABLE_FD_CACHE
#define AMPR_EMU_ENABLE_FD_CACHE 1
#endif

#ifndef AMPR_EMU_FD_CACHE_CAP
#define AMPR_EMU_FD_CACHE_CAP 32
#endif

#ifndef AMPR_EMU_WORKERS
// 0 -> auto (hardware_concurrency, min 2)
#define AMPR_EMU_WORKERS 0
#endif

#ifndef AMPR_EMU_USE_PREADV
// Enable preadv batching when available.
#define AMPR_EMU_USE_PREADV 1
#endif

#ifndef AMPR_EMU_KERNEL_STUBS_MEMORY
// 1 -> build userland stubs for memory-related sceKernel* APIs.
// 0 -> declare them as extern and rely on the real kernel / SDK.
#define AMPR_EMU_KERNEL_STUBS_MEMORY 1
#endif

#ifndef AMPR_EMU_KERNEL_STUBS_QUEUE
// 1 -> build userland stubs for event queue sceKernel* APIs.
// 0 -> declare them as extern and rely on the real kernel / SDK.
#define AMPR_EMU_KERNEL_STUBS_QUEUE 1
#endif

#ifndef AMPR_EMU_QUEUE_BACKEND_KQUEUE
// 1 -> implement the equeue stubs on top of the real kernel kqueue/kevent (PS5/FreeBSD).
//      This is useful when AMPR runs in one module but equeue APIs are provided by another:
//      the handle becomes a kernel object (fd-based), so both modules can interact safely.
// 0 -> pure userland implementation (portable; used for host tests / payload builds by default).
#define AMPR_EMU_QUEUE_BACKEND_KQUEUE 0
#endif

#ifndef AMPR_EMU_STRICT_WRITER
// 1 -> additionally write a packed u32 stream into the user-provided command buffer.
// This aims to match FW10 command buffer sizing/offset behavior for the common commands.
// AMM commands still use opaque placeholders (kernel writers are unavailable in userland).
#define AMPR_EMU_STRICT_WRITER 1
#endif

#ifndef AMPR_EMU_LOG
#define AMPR_EMU_LOG 1
#endif

#ifndef AMPR_EMU_USE_KLOG
#define AMPR_EMU_USE_KLOG 0
#endif
