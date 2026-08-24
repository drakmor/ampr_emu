# Self-contained Linux PRX build with ps5-payload-sdk.

PS5_PAYLOAD_SDK ?= /opt/ps5-payload-sdk
PYTHON ?= python3
BUILD_MAKEFILE := $(lastword $(MAKEFILE_LIST))

include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

LLVM_BINDIR := $(shell $(PS5_PAYLOAD_SDK)/bin/prospero-llvm-config --bindir)
PRX_LD := $(LLVM_BINDIR)/ld.lld

OUT := out/payload-sdk
OBJ := $(OUT)/obj
GENERATED := $(OBJ)/generated
CRT_DIR := $(OBJ)/sce-crt
LINK_DIR := $(OBJ)/link
PRX := $(OUT)/libSceAmpr.prx
SPRX := $(OUT)/libSceAmpr.sprx
LINKED_PRX := $(LINK_DIR)/libSceAmpr.prx
COMBINED_OBJ := $(LINK_DIR)/libSceAmpr.combined.o
UNDEFINED_LIST := $(GENERATED)/libSceAmpr.undefined.txt
RENAME_MAP := $(GENERATED)/libSceAmpr.rename.txt
EXPORT_RESPONSE := $(GENERATED)/libSceAmpr.exports.rsp
VERSION_SCRIPT := $(GENERATED)/libSceAmpr.version.script
LIBC_ASM := $(GENERATED)/libSceLibcInternal.imports.S
LIBC_LIST := $(GENERATED)/libSceLibcInternal.imports.txt
KERNEL_ASM := $(GENERATED)/libkernel.imports.S
KERNEL_LIST := $(GENERATED)/libkernel.imports.txt
METADATA_ASM := $(GENERATED)/libSceAmpr.metadata.S
LIBC_SO := $(GENERATED)/libSceLibcInternal.prx.so
KERNEL_SO := $(GENERATED)/libkernel.prx.so
METADATA_OBJ := $(GENERATED)/libSceAmpr.metadata.o
GENERATED_STAMP := $(GENERATED)/libSceAmpr.nids.stamp
PRX_SCRIPT_SOURCE := ps5/prx/prx.script
PRX_SCRIPT := $(GENERATED)/prx.script
CRT_OBJECTS := \
  $(CRT_DIR)/crti.o \
  $(CRT_DIR)/crtbeginS.o \
  $(CRT_DIR)/crtendS.o \
  $(CRT_DIR)/crtn.o
RENAMED_CRT_OBJECTS := $(patsubst $(CRT_DIR)/%.o,$(OBJ)/nids/sce-crt/%.o,$(CRT_OBJECTS))

PROSPERO_200_FSELF_VERSION := 0x02000001

CPP_SOURCES := \
  src/ampr_debug_log.cpp \
  src/ampr_emu_command_log.cpp \
  src/ampr_emu_runtime_memory.cpp \
  src/ampr_emu_index.cpp \
  src/ampr_emu_fd_cache.cpp \
  src/ampr_emu_amm.cpp \
  src/ampr_emu_command_buffer.cpp \
  src/ampr_emu_command_buffer_amm.cpp \
  src/ampr_emu_command_buffer_apr.cpp \
  src/ampr_emu_apr_command_buffer.cpp \
  src/ampr_emu_apr_services.cpp \
  src/ampr_emu_apr_kernel_bridge.cpp \
  src/ampr_emu_apr_equeue.cpp \
  src/ampr_emu_apr_reactor_common.cpp \
  src/ampr_emu_apr_reactor.cpp \
  src/ampr_emu_command_packing.cpp \
  src/ampr_emu_measure_commands.cpp \
  src/ampr_libc_internal_link.cpp \
  src/sceampr_exports.cpp \
  src/ampr_libkernel_hook.cpp \
  src/hde64.cpp

OBJECTS := $(patsubst %.cpp,$(OBJ)/%.o,$(CPP_SOURCES))
RENAMED_OBJECTS := $(patsubst $(OBJ)/%.o,$(OBJ)/nids/%.o,$(OBJECTS))

COMMON_DEFS := \
  -DLIBSCEAMPR_IMPL=1 \
  -DAMPR_PAYLOAD_SDK_BUILD=1 \
  -DAMPR_EMU_HAS_LIBKERNEL_HOOK_IMPL=1 \
  -Drestrict=__restrict \
  -DEVFILT_AMPR=-25 \
  -DNDEBUG

COMMON_FLAGS := \
  -fPIC -fplt -O3 -ffast-math -fno-strict-aliasing \
  -ffunction-sections -fdata-sections -fvisibility=hidden \
  -Iinclude -idirafter ps5/include/sce $(COMMON_DEFS)

CXXFLAGS += \
  -std=c++17 -fno-exceptions -fno-rtti -fvisibility-inlines-hidden \
  $(COMMON_FLAGS)

CRT_CFLAGS := \
  -std=c11 -O2 -fPIC -fplt -ffreestanding -fno-stack-protector \
  -fno-asynchronous-unwind-tables -fno-unwind-tables -fvisibility=hidden

PRX_LDFLAGS := \
  -m elf_x86_64 --shared --eh-frame-hdr -mllvm -emulated-tls \
  -T $(PRX_SCRIPT) --hash-style=sysv --build-id=sha1 -z relro \
  -z max-page-size=0x4000 -z common-page-size=0x4000 \
  --version-script=$(VERSION_SCRIPT)

.DELETE_ON_ERROR:
.SECONDARY: $(CRT_OBJECTS)
.DEFAULT_GOAL := all
.PHONY: all clean verify print-vars

all: $(PRX) $(SPRX)

$(OBJ)/%.o: %.cpp $(BUILD_MAKEFILE)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -MD -MP -c $< -o $@

$(COMBINED_OBJ): $(OBJECTS)
	@mkdir -p $(dir $@)
	$(PRX_LD) -m elf_x86_64 -r -o $@ $(OBJECTS)

$(UNDEFINED_LIST): $(COMBINED_OBJ)
	@mkdir -p $(dir $@)
	$(NM) -u -j $< | LC_ALL=C sort -u > $@

$(GENERATED_STAMP): \
    $(COMBINED_OBJ) $(UNDEFINED_LIST) \
    src/sceampr_exports.cpp tools/generate_payload_exports.py $(BUILD_MAKEFILE)
	@mkdir -p $(GENERATED)
	$(PYTHON) tools/generate_payload_exports.py \
	  --source src/sceampr_exports.cpp \
	  --undefined $(UNDEFINED_LIST) \
	  --response $(EXPORT_RESPONSE) \
	  --version-script $(VERSION_SCRIPT) \
	  --rename-map $(RENAME_MAP) \
	  --libc-asm $(LIBC_ASM) \
	  --libc-list $(LIBC_LIST) \
	  --kernel-asm $(KERNEL_ASM) \
	  --kernel-list $(KERNEL_LIST) \
	  --metadata-asm $(METADATA_ASM)
	@touch $@

$(EXPORT_RESPONSE) $(VERSION_SCRIPT) $(RENAME_MAP) $(LIBC_ASM) $(LIBC_LIST) $(KERNEL_ASM) $(KERNEL_LIST) $(METADATA_ASM): \
    $(GENERATED_STAMP)
	@test -f $@ || { echo "missing generated PRX input: $@" >&2; exit 1; }

$(OBJ)/nids/%.o: $(OBJ)/%.o $(RENAME_MAP)
	@mkdir -p $(dir $@)
	cp $< $@
	$(OBJCOPY) @$(RENAME_MAP) $@

$(LIBC_SO): $(LIBC_ASM) $(BUILD_MAKEFILE)
	$(CC) -shared -nostdlib -nodefaultlibs \
	  -Wl,--hash-style=sysv -Wl,-soname,libSceLibcInternal.prx -o $@ $<

$(KERNEL_SO): $(KERNEL_ASM) $(BUILD_MAKEFILE)
	$(CC) -shared -nostdlib -nodefaultlibs \
	  -Wl,--hash-style=sysv -Wl,-soname,libkernel.prx -o $@ $<

$(METADATA_OBJ): $(METADATA_ASM) $(BUILD_MAKEFILE)
	$(CC) -c $< -o $@

$(PRX_SCRIPT): $(PRX_SCRIPT_SOURCE) tools/prepare_prx_link_script.py $(BUILD_MAKEFILE)
	@mkdir -p $(dir $@)
	$(PYTHON) tools/prepare_prx_link_script.py "$(PRX_SCRIPT_SOURCE)" $@

$(CRT_DIR)/%.o: ps5/crt/%.c $(BUILD_MAKEFILE)
	@mkdir -p $(dir $@)
	$(CC) $(CRT_CFLAGS) -c $< -o $@

$(CRT_DIR)/%.o: ps5/crt/%.S $(BUILD_MAKEFILE)
	@mkdir -p $(dir $@)
	$(CC) -c $< -o $@

$(OBJ)/nids/sce-crt/%.o: $(CRT_DIR)/%.o $(RENAME_MAP)
	@mkdir -p $(dir $@)
	cp $< $@
	$(OBJCOPY) @$(RENAME_MAP) $@

$(LINKED_PRX): \
    $(RENAMED_OBJECTS) $(METADATA_OBJ) $(LIBC_SO) $(KERNEL_SO) \
    $(EXPORT_RESPONSE) $(VERSION_SCRIPT) $(PRX_SCRIPT) $(RENAMED_CRT_OBJECTS) \
    tools/stamp_payload_prx.py $(BUILD_MAKEFILE)
	@mkdir -p $(dir $@)
	$(PRX_LD) $(PRX_LDFLAGS) -o $@ \
	  $(OBJ)/nids/sce-crt/crti.o $(OBJ)/nids/sce-crt/crtbeginS.o \
	  $(RENAMED_OBJECTS) $(METADATA_OBJ) \
	  $(OBJ)/nids/sce-crt/crtendS.o $(OBJ)/nids/sce-crt/crtn.o \
	  --no-as-needed $(LIBC_SO) $(KERNEL_SO) --as-needed \
	  @$(EXPORT_RESPONSE)
	$(PYTHON) tools/stamp_payload_prx.py $@

$(PRX): $(LINKED_PRX) tools/prx_hash_fix.py $(BUILD_MAKEFILE)
	$(PYTHON) tools/prx_hash_fix.py $(LINKED_PRX) $@ --module libSceAmpr

$(SPRX): $(PRX) tools/make_fself.py $(BUILD_MAKEFILE)
	$(PYTHON) tools/make_fself.py $(PRX) $@ \
	  --ptype fake \
	  --app-version $(PROSPERO_200_FSELF_VERSION) \
	  --fw-version $(PROSPERO_200_FSELF_VERSION)

verify: all
	$(PYTHON) tools/verify_payload_prx.py --prx $(PRX) \
	  --linked $(LINKED_PRX) \
	  --libc-imports $(LIBC_LIST) \
	  --kernel-imports $(KERNEL_LIST) \
	  --source src/sceampr_exports.cpp \
	  --reference docs/refs/12.70/libSceAmpr.sprx.asm \
	  --sprx $(SPRX) \
	  --fself-version $(PROSPERO_200_FSELF_VERSION)

clean:
	rm -rf $(OUT)

print-vars:
	@echo "PS5_PAYLOAD_SDK=$(PS5_PAYLOAD_SDK)"
	@echo "PRX_SCRIPT_SOURCE=$(PRX_SCRIPT_SOURCE)"
	@echo "PROSPERO_200_FSELF_VERSION=$(PROSPERO_200_FSELF_VERSION)"
	@echo "PRX=$(PRX)"
	@echo "SPRX=$(SPRX)"

-include $(OBJECTS:.o=.d)
