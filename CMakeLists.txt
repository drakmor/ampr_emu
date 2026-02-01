# SPDX-License-Identifier: GPL-3.0-or-later
#
# Copyright (C) 2026 Roman Tarasov
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

cmake_minimum_required(VERSION 3.16)
project(ampr_userland_emu LANGUAGES CXX ASM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(ampr_userland_emu STATIC
    src/ampr_emu.cpp
    src/sceampr_exports.cpp
    src/ampr_nid_stubs.S
    src/libkernel_nid_stubs.S
)

target_include_directories(ampr_userland_emu PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if(UNIX)
  # shm_open/shm_unlink live in librt on some Linux toolchains.
  target_link_libraries(ampr_userland_emu PUBLIC pthread rt)
endif()

add_executable(ampr_smoketest
    tests/smoketest.cpp
)
target_link_libraries(ampr_smoketest PRIVATE ampr_userland_emu)

add_executable(ampr_negtest
    tests/negtest.cpp
)
target_link_libraries(ampr_negtest PRIVATE ampr_userland_emu)

add_executable(ampr_stress
    tests/stress.cpp
)
target_link_libraries(ampr_stress PRIVATE ampr_userland_emu)
