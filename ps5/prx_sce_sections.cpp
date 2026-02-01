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

// Minimal SCE-specific sections to force corresponding PHDRs.
// Content is placeholder; layout and presence is what matters.

__attribute__((section(".sce_module_param"), used, aligned(8)))
static const uint8_t g_sce_module_param[0x20] = {0};

__attribute__((section(".prodg_meta_data"), used, aligned(16)))
#ifndef AMPR_PRX_PRODG_META_SIZE
#define AMPR_PRX_PRODG_META_SIZE 0x84
#endif
static const uint8_t g_prodg_meta_data[AMPR_PRX_PRODG_META_SIZE] = {0};

__attribute__((section(".sceversion"), used, aligned(4)))
static const uint8_t g_sceversion[0x10] = {0};

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
