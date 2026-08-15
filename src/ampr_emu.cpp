/*
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * libSceAmpr emulator module index.
 *
 * Implementation files:
 *   - ampr_emu_runtime_memory.cpp: runtime memory and SDK CPU allocation
 *   - ampr_emu_amm.cpp: AMM mapper/runtime bridge
 *   - ampr_emu_apr_kernel_bridge.cpp: APR libkernel hook bridge
 *   - ampr_emu_apr_reactor.cpp: APR SDK AIO reactor
 *   - ampr_emu_apr_services.cpp: APR public service API
 *   - ampr_emu_command_buffer.cpp: shared AMM/APR command-buffer writers
 *   - ampr_emu_apr_command_buffer.cpp: APR read/map validation and writers
 *   - ampr_emu_command_buffer_*.cpp: AMM/APR derived command-buffer classes
 *   - ampr_emu_command_packing.cpp: packed command encode/decode helpers
 *   - ampr_emu_core.cpp: small shared emulator entrypoints
 *   - ampr_libkernel_hook.cpp: libkernel detour installation
 */

#include "ampr_emu_amm.h"
#include "ampr_emu_apr_services.h"
#include "ampr_emu_command_buffer_types.h"
