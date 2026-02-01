/* SPDX-License-Identifier: GPL-3.0-or-later
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

OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(0)

PHDRS
{
    ph_text            PT_LOAD       FLAGS (0x1);
    ph_ro              PT_LOAD       FLAGS (0x4);
    ph_relro_load      PT_LOAD       FLAGS (0x2 | 0x4);
    ph_relro           PT_GNU_RELRO  FLAGS (0x4);
    ph_data            PT_LOAD       FLAGS (0x2 | 0x4);

    /* SCE-specific program headers (numeric IDs to avoid relying on toolchain macros). */
    ph_sce_moduleparam 0x61000002    FLAGS (0x4);
    ph_dynamic         PT_DYNAMIC    FLAGS (0x2 | 0x4);
    ph_tls             PT_TLS        FLAGS (0x4);
    ph_eh_frame_hdr    PT_GNU_EH_FRAME FLAGS (0x4);

    /* "dynlibdata" load segment used by retail PRX layout. */
    ph_dynlibdata      PT_LOAD       FLAGS (0x0);
    ph_sce_comment     0x6fffff00    FLAGS (0x0);
    ph_libversion      0x6fffff01    FLAGS (0x0);

    /* Split notes like the SDK script. */
    ph_load_note       PT_NOTE       FLAGS (0x0);
    ph_note            PT_NOTE       FLAGS (0x0);
}

SECTIONS
{
    PROVIDE (__executable_start = .);

    .sce_padding : { QUAD (0xcccccccccccccccc); QUAD (0xcccccccccccccccc); } : ph_text

    .init :
    {
        PROVIDE (__start__Zinit = .);
        KEEP (*(.init))
    } : ph_text

    .text :
    {
        PROVIDE (__start__Ztext = .);
        *(.text .text.*)
        PROVIDE (__text_end = .);
        PROVIDE (__stop__Ztext = .);
    } : ph_text

    .plt : { *(.plt .plt.*) } : ph_text

    .fini : { KEEP (*(.fini)) } : ph_text

    PROVIDE (etext = .);
    PROVIDE (_etext = .);

    . = ALIGN (CONSTANT (MAXPAGESIZE));

    .rodata : { *(.rodata .rodata.*) } : ph_ro
    .gcc_except_table : { *(.gcc_except_table .gcc_except_table.*) } : ph_ro
    .eh_frame : { *(.eh_frame) } : ph_ro
    .eh_frame_hdr : { *(.eh_frame_hdr) } : ph_ro : ph_eh_frame_hdr

    . = ALIGN (CONSTANT (MAXPAGESIZE));

    .data.rel.ro : { *(.data.rel.ro .data.rel.ro*) } : ph_relro_load : ph_relro
    .got : { *(.got) }
    .got.plt :
    {
        PROVIDE (__got_plt_start = .);
        *(.got.plt)
    }
    .got.dll : { *(.got.dll .got.dll.*) }

    .ctors :
    {
        PROVIDE (__CTOR_LIST__ = .); PROVIDE (___CTOR_LIST__ = .);
        KEEP (*crtbegin*.o(.ctors))
        KEEP (*(EXCLUDE_FILE (*crtend*.o) .ctors))
        KEEP (*(SORT (.ctors.*)))
        KEEP (*crtend*.o(.ctors))
        PROVIDE (__CTOR_END__ = .); PROVIDE (___CTOR_END__ = .);
    }
    .dtors :
    {
        PROVIDE (__DTOR_LIST__ = .); PROVIDE (___DTOR_LIST__ = .);
        KEEP (*crtbegin*.o(.dtors))
        KEEP (*(EXCLUDE_FILE (*crtend*.o) .dtors))
        KEEP (*(SORT (.dtors.*)))
        KEEP (*crtend*.o(.dtors))
        PROVIDE (__DTOR_END__ = .); PROVIDE (___DTOR_END__ = .);
    }

    .preinit_array :
    {
        PROVIDE (__start__Zpreinit_array = .);
        *(.preinit_array)
        PROVIDE (__stop__Zpreinit_array = .);
    }
    .init_array :
    {
        PROVIDE (__start__Zinit_array = .);
        *(SORT (.init_array.*))
        *(.init_array)
        PROVIDE (__stop__Zinit_array = .);
    }
    .fini_array :
    {
        *(.fini_array)
        *(SORT (.fini_array.*))
    }

    .sce_module_param : { KEEP (*(.sce_module_param)) } : ph_relro_load : ph_relro : ph_sce_moduleparam

    . = ALIGN (32);
    .tdata : { *(.tdata .tdata.*) } : ph_relro_load : ph_relro : ph_tls
    .tbss  : { *(.tbss .tbss.*) } : ph_tls

    . = ALIGN (CONSTANT (MAXPAGESIZE));

    .shader_header :
    {
        PROVIDE (__shader_header_start = .);
        *(.shader_header)
        PROVIDE (__shader_header_end = .);
    } : ph_data

    . = ALIGN (CONSTANT (MAXPAGESIZE));
    .shader_text :
    {
        PROVIDE (__shader_text_start = .);
        *(.shader_text)
        PROVIDE (__shader_text_end = .);
    } : ph_data

    . = ALIGN (CONSTANT (MAXPAGESIZE));

    .shader_data : { *(.shader_data) } : ph_data
    .data : { *(.data .data.*) } : ph_data

    __llvm_prf_cnts  : { KEEP (*(__llvm_prf_cnts __llvm_prf_cnts.*)) }
    __llvm_prf_data  : { KEEP (*(__llvm_prf_data __llvm_prf_data.*)) }
    __llvm_prf_names : { KEEP (*(__llvm_prf_names __llvm_prf_names.*)) }
    __llvm_prf_vals  : { KEEP (*(__llvm_prf_vals __llvm_prf_vals.*)) }
    __llvm_prf_vnds  : { KEEP (*(__llvm_prf_vnds __llvm_prf_vnds.*)) }
    __sancov_guards  : { KEEP (*(__sancov_guards __sancov_guards.*)) }

    PROVIDE (edata = .);
    PROVIDE (_edata = .);
    PROVIDE (__bss_start = .);

    .bss : { *(.bss .bss.*) *(COMMON) } : ph_data

    PROVIDE (end = .);
    PROVIDE (_end = .);

    /* dynlibdata: keep first section 16-byte aligned. */
    .dynstr   : ALIGN (16) { *(.dynstr) } : ph_dynlibdata
    .dynsym   : { *(.dynsym) } : ph_dynlibdata
    .rela.plt : { . = .; *(.dyn.rela.plt) *(.rela.plt) } : ph_dynlibdata
    .rela.dyn : { . = .; *(.rela.dyn) *(.rela.dyn.*) } : ph_dynlibdata
    .hash     : { KEEP (*(.hash)) *(.hash) } : ph_dynlibdata
    .gnu.hash : { *(.gnu.hash) } : ph_dynlibdata
    .note.gnu.build-id : { *(.note.gnu.build-id) } : ph_load_note : ph_dynlibdata

    .dynamic :
    {
        PROVIDE_HIDDEN (_DYNAMIC = 0);
        *(.dynamic)
    } : ph_dynamic : ph_dynlibdata

    /* Extra all-zero space for appending additional DT_* entries during SPRX packaging. */
    .dynamic_pad : ALIGN (16) { KEEP (*(.dynamic_pad)) } : ph_dynlibdata

    .prodg_meta_data : ALIGN (16) { KEEP (*(.prodg_meta_data)) } : ph_sce_comment
    .sceversion : { KEEP (*(.sceversion)) } : ph_libversion

    .note (INFO) : { *(.note .note.*) } : ph_note

    /DISCARD/ : { *(.linker_cmd) } : NONE
    /DISCARD/ : { *(.note.GNU-stack) } : NONE
}
