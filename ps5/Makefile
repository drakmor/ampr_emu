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

# AMPR userland emulation (drop-in libSceAmpr replacement) built as a PS5 payload
# using https://github.com/ps5-payload-dev/sdk
#
# Build:
#   export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
#   make -C ps5
#
# Send payload to a listening loader:
#   export PS5_HOST=ps5 ; export PS5_PORT=9021
#   make -C ps5 test

PS5_HOST ?= ps5
PS5_PORT ?= 9021

ifndef PS5_PAYLOAD_SDK
$(error PS5_PAYLOAD_SDK is undefined. Set it to your SDK prefix, e.g. /opt/ps5-payload-sdk)
endif

# The SDK ships a Makefile-based toolchain.
include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

BUILD := build
TEST ?= smoketest
# Most tests link against libampr_userland_emu.a. `prx_smoketest` is special:
# it must NOT link the static lib to validate module boundary behavior.
LIB_TESTS ?= smoketest test1 test2 test3 negtest stress
PRX_TESTS ?= prx_smoketest

ELFS_LIB := $(addprefix ampr_,$(addsuffix .elf,$(LIB_TESTS)))
ELFS_PRX := $(addprefix ampr_,$(addsuffix .elf,$(PRX_TESTS)))
ELFS := $(ELFS_LIB) $(ELFS_PRX)
ELF := ampr_$(TEST).elf
LIB := libampr_userland_emu.a

# Project includes
INCLUDES := -I../include

# Keep flags minimal and let toolchain.mk do the heavy lifting.
CXXFLAGS += -std=gnu++17 -fno-exceptions -fno-rtti -ffunction-sections -fdata-sections $(INCLUDES) -DAMPR_EMU_LOG=1 -DAMPR_EMU_USE_KLOG=1
CFLAGS   += -ffunction-sections -fdata-sections $(INCLUDES) -DAMPR_EMU_LOG=1 -DAMPR_EMU_USE_KLOG=1
LDFLAGS  += -Wl,--gc-sections -Wl,--as-needed
LDLIBS   += -Wl,-Bstatic -lc++ -lc++abi -lunwind -Wl,-Bdynamic

LIB_SRCS_CPP := \
  ../src/ampr_emu.cpp \
  ../src/sceampr_exports.cpp
LIB_SRCS_ASM := \
  ../src/ampr_nid_stubs.S

LIB_OBJS := \
  $(BUILD)/ampr_emu.o \
  $(BUILD)/sceampr_exports.o \
  $(BUILD)/ampr_nid_stubs.o


.PHONY: all clean test print-vars

all: $(ELFS)

$(BUILD):
	@mkdir -p $(BUILD)

# --- objects ---
$(BUILD)/ampr_emu.o: ../src/ampr_emu.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD)/sceampr_exports.o: ../src/sceampr_exports.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD)/ampr_nid_stubs.o: ../src/ampr_nid_stubs.S | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/%.o: ../tests/%.cpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# --- static lib (useful for embedding into other payloads) ---
$(LIB): $(LIB_OBJS)
	$(AR) rcs $@ $^

# --- payload ELF ---
$(ELFS_LIB): ampr_%.elf: $(BUILD)/%.o $(LIB)
	$(CXX) $(LDFLAGS) -o $@ \
		$< \
		-Wl,--whole-archive $(LIB) -Wl,--no-whole-archive \
		$(LDLIBS)

# PRX integration test must NOT link libampr_userland_emu.a, otherwise it doesn't
# validate the "module boundary" behavior (dlsym + NID calls).
ampr_prx_smoketest.elf: $(BUILD)/prx_smoketest.o
	$(CXX) $(LDFLAGS) -o $@ \
		$< \
		$(LDLIBS)

# Convenience: send to the console with netcat.
# (Most loaders accept a raw ELF streamed over TCP.)
# If your environment needs socat instead of nc, tweak this command.

test: $(ELF)
	@echo "Sending $(ELF) to $(PS5_HOST):$(PS5_PORT) ..."
	nc -q0 $(PS5_HOST) $(PS5_PORT) < $(ELF)

clean:
	rm -rf $(BUILD) *.elf $(LIB)

print-vars:
	@echo "PS5_PAYLOAD_SDK=$(PS5_PAYLOAD_SDK)"
	@echo "CC=$(CC)"
	@echo "CXX=$(CXX)"
	@echo "CFLAGS=$(CFLAGS)"
	@echo "CXXFLAGS=$(CXXFLAGS)"
	@echo "LDFLAGS=$(LDFLAGS)"
	@echo "LDLIBS=$(LDLIBS)"
