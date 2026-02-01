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
#include "ampr.h"
#include <stdint.h>

/* Emu-only: event registration parameters (not present in SDK). */
typedef struct SceKernelEventFilter {
    int16_t  filter;
    uint16_t flags;
    uint32_t fflags;
    void*    udata;
} SceKernelEventFilter;

namespace sce::Ampr::Emu {

/*
 * Optional helpers not present in Sony's public AMPR header.
 * These exist purely for the userland emulation to give you explicit
 * control over cache behavior and observability.
 */

/* Hint to the emulated APR that a fileId will be used heavily; keeps fd cached. */
int pinFileId(SceAprFileId fileId);

/* Release pin and allow fd eviction. */
int unpinFileId(SceAprFileId fileId);

/* Emu-only helper: push an event with explicit filter/fflags. */
int pushEqueueEvent(SceKernelEqueue eq, uint32_t id, uint64_t data, int16_t filter, uint32_t fflags);

/* Emu-only helper: register AMPR event with explicit filter/flags/fflags. */
int addAmprEventWithFilter(SceKernelEqueue eq, uint32_t id, const SceKernelEventFilter* filter);

} // namespace sce::Ampr::Emu
