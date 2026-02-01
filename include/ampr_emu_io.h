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
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Pluggable I/O backend.
 *
 * By default, the emulation uses POSIX open/close/pread/stat.
 * You can replace these with your own implementation (e.g., cache, decryption,
 * network fetch, virtual FS) while keeping the same AMPR command scheduling.
 */
typedef int     (*ampr_open_fn)(const char* path, int flags, int mode);
typedef int     (*ampr_close_fn)(int fd);
typedef ssize_t (*ampr_pread_fn)(int fd, void* buf, size_t len, off_t off);
typedef int     (*ampr_stat_fn)(const char* path, struct stat* st);

typedef struct AmprIoBackend {
    ampr_open_fn   open_fn;
    ampr_close_fn  close_fn;
    ampr_pread_fn  pread_fn;
    ampr_stat_fn   stat_fn;
} AmprIoBackend;

/* Install a process-wide backend. Passing NULL resets to defaults. */
void amprSetIoBackend(const AmprIoBackend* backend);

/* Read current backend (never NULL; returns defaults if not set). */
const AmprIoBackend* amprGetIoBackend(void);

#ifdef __cplusplus
} // extern "C"
#endif
