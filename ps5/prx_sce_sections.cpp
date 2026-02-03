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

#include <cstdint>

#ifdef AMPR_PRX_STUB_INIT_FINI
extern "C" __attribute__((section(".init"), used)) void ampr_prx_init_stub(void) {}
extern "C" __attribute__((section(".fini"), used)) void ampr_prx_fini_stub(void) {}
#endif

// Minimal SCE-specific sections to force corresponding PHDRs.
// Some retail loaders validate these headers (especially .sce_module_param),
// so keep the magic/format consistent with system SPRX stubs.

__attribute__((section(".sce_module_param"), used, aligned(8)))
static const uint8_t g_sce_module_param[0x20] = {
	// uint64_t size = 0x20
	0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	// uint32_t magic = 0x3C13F4BF ("BF F4 13 3C" little-endian)
	0xBF, 0xF4, 0x13, 0x3C,
	// uint32_t version = 3
	0x03, 0x00, 0x00, 0x00,
	// Remaining fields match libSceLibcInternal/libkernel_web (fw-versioned).
	0x01, 0x00, 0x59, 0x11,
	0x08, 0x00, 0x40, 0x09,
	0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
};

__attribute__((section(".prodg_meta_data"), used, aligned(16)))
#ifndef AMPR_PRX_PRODG_META_SIZE
#define AMPR_PRX_PRODG_META_SIZE 0x84
#endif
static const uint8_t g_prodg_meta_data[AMPR_PRX_PRODG_META_SIZE] = {
	// System SPRX stubs store a small header that starts with "PATH" and embeds
	// the original build path. We keep a minimal valid header.
	'P', 'A', 'T', 'H',
	// uint32_t size = (segment_size - 8)
	(uint8_t)((AMPR_PRX_PRODG_META_SIZE - 8) & 0xFF),
	(uint8_t)(((AMPR_PRX_PRODG_META_SIZE - 8) >> 8) & 0xFF),
	(uint8_t)(((AMPR_PRX_PRODG_META_SIZE - 8) >> 16) & 0xFF),
	(uint8_t)(((AMPR_PRX_PRODG_META_SIZE - 8) >> 24) & 0xFF),
	// uint32_t path_len = 0 (no path string)
	0x00, 0x00, 0x00, 0x00,
	// rest is zero
};

__attribute__((section(".sceversion"), used, aligned(4)))
static const uint8_t g_sceversion[0x10] = {0};

// A small empty NOTE block to match system stub layout (readelf shows it as unknown note).
__attribute__((section(".note"), used, aligned(4)))
static const uint8_t g_empty_note[0x30] = {0};

// The retail rtld does not accept DT_GNU_HASH (0x6ffffef5). We reserve a SysV
// hash table region and fill it during SPRX packaging (see make_fself.py).
#ifndef AMPR_PRX_SYSV_HASH_SIZE
#define AMPR_PRX_SYSV_HASH_SIZE 0x6000
#endif
__attribute__((section(".hash"), used, aligned(4)))
static const uint8_t g_sysv_hash_storage[AMPR_PRX_SYSV_HASH_SIZE] = {0};

// Extra space after .dynamic to allow make_fself.py to append SCE DT_* entries
// without relocating PT_DYNAMIC. This region remains all-zero in the linked PRX.
#ifndef AMPR_PRX_DYNAMIC_PAD_SIZE
#define AMPR_PRX_DYNAMIC_PAD_SIZE 0x400
#endif
__attribute__((section(".dynamic_pad"), used, aligned(16)))
static const uint8_t g_dynamic_pad[AMPR_PRX_DYNAMIC_PAD_SIZE] = {0};
