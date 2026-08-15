/*
 * Hacker Disassembler Engine 64 C
 * Copyright (c) 2008-2009, Vyacheslav Patkov.
 * All rights reserved.
 *
 */

#if defined(_M_X64) || defined(__x86_64__)

// #include <kernel.h>
#include "../include/hde64.h"
#include "../include/table64.h"

static void hde64_zero(void *ptr, size_t size)
{
    auto *p = static_cast<volatile uint8_t *>(ptr);
    for (size_t i = 0; i < size; ++i) {
        p[i] = 0;
    }
}

static int8_t hde64_load_i8(const uint8_t *p)
{
    return static_cast<int8_t>(p[0]);
}

static int32_t hde64_load_i32(const uint8_t *p)
{
    const uint32_t value = static_cast<uint32_t>(p[0]) |
                           (static_cast<uint32_t>(p[1]) << 8) |
                           (static_cast<uint32_t>(p[2]) << 16) |
                           (static_cast<uint32_t>(p[3]) << 24);
    return static_cast<int32_t>(value);
}

size_t hde64_imm_size(const hde64s *hs)
{
    if (!hs) {
        return 0;
    }
    if (hs->flags & F_IMM64) return 8;
    if (hs->flags & F_IMM32) return 4;
    if (hs->flags & F_IMM16) return 2;
    if (hs->flags & F_IMM8) return 1;
    return 0;
}

int hde64_relative_target(const void *code, uintptr_t ip, const hde64s *hs, uintptr_t *target)
{
    if (!code || !hs || !target || (hs->flags & F_RELATIVE) == 0 || hs->imm_offset == 0) {
        return 0;
    }

    const uint8_t *src = static_cast<const uint8_t *>(code);
    const size_t relSize = hde64_imm_size(hs);
    if (relSize == 1) {
        *target = static_cast<uintptr_t>(static_cast<int64_t>(ip + hs->len) + hde64_load_i8(src + hs->imm_offset));
        return 1;
    }
    if (relSize == 4) {
        *target = static_cast<uintptr_t>(static_cast<int64_t>(ip + hs->len) + hde64_load_i32(src + hs->imm_offset));
        return 1;
    }
    return 0;
}

int hde64_rip_absolute(const void *code, uintptr_t ip, const hde64s *hs, uintptr_t *absolute)
{
    if (!code || !hs || !absolute || (hs->flags & F_RIP_RELATIVE) == 0 || hs->disp_offset == 0) {
        return 0;
    }

    const uint8_t *src = static_cast<const uint8_t *>(code);
    *absolute = static_cast<uintptr_t>(static_cast<int64_t>(ip + hs->len) + hde64_load_i32(src + hs->disp_offset));
    return 1;
}

static void hde64_fill_meta(hde64s *hs)
{
    if ((hs->flags & F_RELATIVE) != 0) {
        if (hs->opcode == 0xe8 && (hs->flags & F_IMM32) != 0) {
            hs->meta = HDE64_META_REL_CALL;
        } else if ((hs->opcode == 0xe9 && (hs->flags & F_IMM32) != 0) ||
                   (hs->opcode == 0xeb && (hs->flags & F_IMM8) != 0)) {
            hs->meta = HDE64_META_REL_JMP;
        } else if (hs->opcode >= 0x70 && hs->opcode <= 0x7f && (hs->flags & F_IMM8) != 0) {
            hs->meta = HDE64_META_REL_JCC;
            hs->branch_opcode = hs->opcode;
        } else if (hs->opcode == 0x0f && hs->opcode2 >= 0x80 && hs->opcode2 <= 0x8f && (hs->flags & F_IMM32) != 0) {
            hs->meta = HDE64_META_REL_JCC;
            hs->branch_opcode = static_cast<uint8_t>(0x70u + (hs->opcode2 & 0x0fu));
        }
    }

    const bool ripRelative = (hs->flags & F_MODRM) != 0 &&
                             hs->modrm_mod == 0 &&
                             hs->modrm_rm == 5 &&
                             hs->p_67 == 0 &&
                             (hs->flags & F_DISP32) != 0;
    if (!ripRelative) {
        return;
    }

    hs->flags |= F_RIP_RELATIVE;
    if (hs->meta == HDE64_META_NONE) {
        hs->meta = HDE64_META_RIP_REL;
    }

    const bool noSizePrefixes = hs->p_66 == 0 && hs->p_lock == 0 && hs->p_rep == 0;
    if (hs->opcode == 0x8d && hs->rex_w != 0 && noSizePrefixes && hs->p_seg == 0) {
        hs->operand_reg = static_cast<uint8_t>(hs->modrm_reg + (hs->rex_r ? 8u : 0u));
        hs->meta = HDE64_META_RIP_REL_LEA64;
    } else if (hs->opcode == 0x8b && hs->rex_w != 0 && noSizePrefixes &&
               (hs->p_seg == 0 || hs->p_seg == PREFIX_SEGMENT_CS)) {
        hs->operand_reg = static_cast<uint8_t>(hs->modrm_reg + (hs->rex_r ? 8u : 0u));
        hs->meta = HDE64_META_RIP_REL_MOV_R64_PTR;
    } else if (hs->opcode == 0x39 && hs->rex_w != 0 && noSizePrefixes &&
               (hs->p_seg == 0 || hs->p_seg == PREFIX_SEGMENT_CS)) {
        hs->operand_reg = static_cast<uint8_t>(hs->modrm_reg + (hs->rex_r ? 8u : 0u));
        hs->meta = HDE64_META_RIP_REL_CMP_PTR_R64;
    }
}

static bool hde64_disasm_vex(const uint8_t *code, hde64s *hs)
{
    const uint8_t prefix = code[0];
    const uint8_t *p = code;
    uint8_t vex_map = 1;

    if (prefix == 0xc5) {
        p += 2;
    } else if (prefix == 0xc4) {
        vex_map = code[1] & 0x1f;
        p += 3;
    } else {
        return false;
    }

    hs->opcode = *p++;
    if (hs->opcode == 0x77) {
        hs->len = static_cast<uint8_t>(p - code);
        hde64_fill_meta(hs);
        return true;
    }

    hs->flags |= F_MODRM;
    hs->modrm = *p++;
    hs->modrm_mod = hs->modrm >> 6;
    hs->modrm_reg = (hs->modrm & 0x3f) >> 3;
    hs->modrm_rm = hs->modrm & 7;

    uint8_t disp_size = 0;
    if (hs->modrm_mod == 0) {
        if (hs->modrm_rm == 5) {
            disp_size = 4;
        }
    } else if (hs->modrm_mod == 1) {
        disp_size = 1;
    } else if (hs->modrm_mod == 2) {
        disp_size = 4;
    }

    if (hs->modrm_mod != 3 && hs->modrm_rm == 4) {
        hs->flags |= F_SIB;
        hs->sib = *p++;
        hs->sib_scale = hs->sib >> 6;
        hs->sib_index = (hs->sib & 0x3f) >> 3;
        hs->sib_base = hs->sib & 7;
        if (hs->modrm_mod == 0 && hs->sib_base == 5) {
            disp_size = 4;
        }
    }

    switch (disp_size) {
        case 1:
            hs->flags |= F_DISP8;
            hs->disp_offset = static_cast<uint8_t>(p - code);
            hs->disp.disp8 = *p;
            break;
        case 4:
            hs->flags |= F_DISP32;
            hs->disp_offset = static_cast<uint8_t>(p - code);
            hs->disp.disp32 = static_cast<uint32_t>(hde64_load_i32(p));
            break;
    }
    p += disp_size;

    const bool has_imm8 = vex_map == 3 ||
                          hs->opcode == 0xc2 ||
                          hs->opcode == 0xc4 ||
                          hs->opcode == 0xc5 ||
                          hs->opcode == 0xc6;
    if (has_imm8) {
        hs->flags |= F_IMM8;
        hs->imm_offset = static_cast<uint8_t>(p - code);
        hs->imm.imm8 = *p++;
    }

    hs->len = (uint8_t)(p - code);
    if (hs->len > 15) {
        hs->flags |= F_ERROR | F_ERROR_LENGTH;
        hs->len = 15;
    }
    hde64_fill_meta(hs);
    return true;
}

unsigned int hde64_disasm(const void *code, hde64s *hs)
{
    uint8_t x, c, *p = (uint8_t *)code, cflags, opcode, pref = 0;
    uint8_t *ht = hde64_table, m_mod, m_reg, m_rm, disp_size = 0;
    uint8_t op64 = 0;

    hde64_zero(hs, sizeof(hde64s));

    for (x = 16; x; x--)
        switch (c = *p++) {
            case 0xf3:
                hs->p_rep = c;
                pref |= PRE_F3;
                break;
            case 0xf2:
                hs->p_rep = c;
                pref |= PRE_F2;
                break;
            case 0xf0:
                hs->p_lock = c;
                pref |= PRE_LOCK;
                break;
            case 0x26: case 0x2e: case 0x36:
            case 0x3e: case 0x64: case 0x65:
                hs->p_seg = c;
                pref |= PRE_SEG;
                break;
            case 0x66:
                hs->p_66 = c;
                pref |= PRE_66;
                break;
            case 0x67:
                hs->p_67 = c;
                pref |= PRE_67;
                break;
            default:
                goto pref_done;
        }
  pref_done:

    hs->flags = (uint32_t)pref << 23;

    if ((c == 0xc4 || c == 0xc5) && hde64_disasm_vex(static_cast<const uint8_t *>(code), hs)) {
        return (unsigned int)hs->len;
    }

    if (!pref)
        pref |= PRE_NONE;

    if ((c & 0xf0) == 0x40) {
        hs->flags |= F_PREFIX_REX;
        if ((hs->rex_w = (c & 0xf) >> 3) && (*p & 0xf8) == 0xb8)
            op64++;
        hs->rex_r = (c & 7) >> 2;
        hs->rex_x = (c & 3) >> 1;
        hs->rex_b = c & 1;
        if (((c = *p++) & 0xf0) == 0x40) {
            opcode = c;
            goto error_opcode;
        }
    }

    if ((hs->opcode = c) == 0x0f) {
        hs->opcode2 = c = *p++;
        ht += DELTA_OPCODES;
    } else if (c >= 0xa0 && c <= 0xa3) {
        op64++;
        if (pref & PRE_67)
            pref |= PRE_66;
        else
            pref &= ~PRE_66;
    }

    opcode = c;
    cflags = ht[ht[opcode / 4] + (opcode % 4)];

    if (cflags == C_ERROR) {
      error_opcode:
        hs->flags |= F_ERROR | F_ERROR_OPCODE;
        cflags = 0;
        if ((opcode & -3) == 0x24)
            cflags++;
    }

    x = 0;
    if (cflags & C_GROUP) {
        uint16_t t;
        t = *(uint16_t *)(ht + (cflags & 0x7f));
        cflags = (uint8_t)t;
        x = (uint8_t)(t >> 8);
    }

    if (hs->opcode2) {
        ht = hde64_table + DELTA_PREFIXES;
        if (ht[ht[opcode / 4] + (opcode % 4)] & pref)
            hs->flags |= F_ERROR | F_ERROR_OPCODE;
    }

    if (cflags & C_MODRM) {
        hs->flags |= F_MODRM;
        hs->modrm = c = *p++;
        hs->modrm_mod = m_mod = c >> 6;
        hs->modrm_rm = m_rm = c & 7;
        hs->modrm_reg = m_reg = (c & 0x3f) >> 3;

        if (x && ((x << m_reg) & 0x80))
            hs->flags |= F_ERROR | F_ERROR_OPCODE;

        if (!hs->opcode2 && opcode >= 0xd9 && opcode <= 0xdf) {
            uint8_t t = opcode - 0xd9;
            if (m_mod == 3) {
                ht = hde64_table + DELTA_FPU_MODRM + t*8;
                t = ht[m_reg] << m_rm;
            } else {
                ht = hde64_table + DELTA_FPU_REG;
                t = ht[t] << m_reg;
            }
            if (t & 0x80)
                hs->flags |= F_ERROR | F_ERROR_OPCODE;
        }

        if (pref & PRE_LOCK) {
            if (m_mod == 3) {
                hs->flags |= F_ERROR | F_ERROR_LOCK;
            } else {
                uint8_t *table_end, op = opcode;
                if (hs->opcode2) {
                    ht = hde64_table + DELTA_OP2_LOCK_OK;
                    table_end = ht + DELTA_OP_ONLY_MEM - DELTA_OP2_LOCK_OK;
                } else {
                    ht = hde64_table + DELTA_OP_LOCK_OK;
                    table_end = ht + DELTA_OP2_LOCK_OK - DELTA_OP_LOCK_OK;
                    op &= -2;
                }
                for (; ht != table_end; ht++)
                    if (*ht++ == op) {
                        if (!((*ht << m_reg) & 0x80))
                            goto no_lock_error;
                        else
                            break;
                    }
                hs->flags |= F_ERROR | F_ERROR_LOCK;
              no_lock_error:
                ;
            }
        }

        if (hs->opcode2) {
            switch (opcode) {
                case 0x20: case 0x22:
                    m_mod = 3;
                    if (m_reg > 4 || m_reg == 1)
                        goto error_operand;
                    else
                        goto no_error_operand;
                case 0x21: case 0x23:
                    m_mod = 3;
                    if (m_reg == 4 || m_reg == 5)
                        goto error_operand;
                    else
                        goto no_error_operand;
            }
        } else {
            switch (opcode) {
                case 0x8c:
                    if (m_reg > 5)
                        goto error_operand;
                    else
                        goto no_error_operand;
                case 0x8e:
                    if (m_reg == 1 || m_reg > 5)
                        goto error_operand;
                    else
                        goto no_error_operand;
            }
        }

        if (m_mod == 3) {
            uint8_t *table_end;
            if (hs->opcode2) {
                ht = hde64_table + DELTA_OP2_ONLY_MEM;
                table_end = ht + sizeof(hde64_table) - DELTA_OP2_ONLY_MEM;
            } else {
                ht = hde64_table + DELTA_OP_ONLY_MEM;
                table_end = ht + DELTA_OP2_ONLY_MEM - DELTA_OP_ONLY_MEM;
            }
            for (; ht != table_end; ht += 2)
                if (*ht++ == opcode) {
                    if ((*ht++ & pref) && !((*ht << m_reg) & 0x80))
                        goto error_operand;
                    else
                        break;
                }
            goto no_error_operand;
        } else if (hs->opcode2) {
            switch (opcode) {
                case 0x50: case 0xd7: case 0xf7:
                    if (pref & (PRE_NONE | PRE_66))
                        goto error_operand;
                    break;
                case 0xd6:
                    if (pref & (PRE_F2 | PRE_F3))
                        goto error_operand;
                    break;
                case 0xc5:
                    goto error_operand;
            }
            goto no_error_operand;
        } else
            goto no_error_operand;

      error_operand:
        hs->flags |= F_ERROR | F_ERROR_OPERAND;
      no_error_operand:

        c = *p++;
        if (m_reg <= 1) {
            if (opcode == 0xf6)
                cflags |= C_IMM8;
            else if (opcode == 0xf7)
                cflags |= C_IMM_P66;
        }

        switch (m_mod) {
            case 0:
                if (pref & PRE_67) {
                    if (m_rm == 6)
                        disp_size = 2;
                } else
                    if (m_rm == 5)
                        disp_size = 4;
                break;
            case 1:
                disp_size = 1;
                break;
            case 2:
                disp_size = 2;
                if (!(pref & PRE_67))
                    disp_size <<= 1;
                break;
        }

        if (m_mod != 3 && m_rm == 4) {
            hs->flags |= F_SIB;
            p++;
            hs->sib = c;
            hs->sib_scale = c >> 6;
            hs->sib_index = (c & 0x3f) >> 3;
            if ((hs->sib_base = c & 7) == 5 && !(m_mod & 1))
                disp_size = 4;
        }

        p--;
        switch (disp_size) {
            case 1:
                hs->flags |= F_DISP8;
                hs->disp_offset = static_cast<uint8_t>(p - (uint8_t *)code);
                hs->disp.disp8 = *p;
                break;
            case 2:
                hs->flags |= F_DISP16;
                hs->disp_offset = static_cast<uint8_t>(p - (uint8_t *)code);
                hs->disp.disp16 = *(uint16_t *)p;
                break;
            case 4:
                hs->flags |= F_DISP32;
                hs->disp_offset = static_cast<uint8_t>(p - (uint8_t *)code);
                hs->disp.disp32 = *(uint32_t *)p;
                break;
        }
        p += disp_size;
    } else if (pref & PRE_LOCK)
        hs->flags |= F_ERROR | F_ERROR_LOCK;

    if (cflags & C_IMM_P66) {
        if (cflags & C_REL32) {
            if (pref & PRE_66) {
                hs->flags |= F_IMM16 | F_RELATIVE;
                hs->imm_offset = static_cast<uint8_t>(p - (uint8_t *)code);
                hs->imm.imm16 = *(uint16_t *)p;
                p += 2;
                goto disasm_done;
            }
            goto rel32_ok;
        }
        if (op64) {
            hs->flags |= F_IMM64;
            hs->imm_offset = static_cast<uint8_t>(p - (uint8_t *)code);
            hs->imm.imm64 = *(uint64_t *)p;
            p += 8;
        } else if (!(pref & PRE_66)) {
            hs->flags |= F_IMM32;
            hs->imm_offset = static_cast<uint8_t>(p - (uint8_t *)code);
            hs->imm.imm32 = *(uint32_t *)p;
            p += 4;
        } else
            goto imm16_ok;
    }


    if (cflags & C_IMM16) {
      imm16_ok:
        hs->flags |= F_IMM16;
        hs->imm_offset = static_cast<uint8_t>(p - (uint8_t *)code);
        hs->imm.imm16 = *(uint16_t *)p;
        p += 2;
    }
    if (cflags & C_IMM8) {
        hs->flags |= F_IMM8;
        hs->imm_offset = static_cast<uint8_t>(p - (uint8_t *)code);
        hs->imm.imm8 = *p++;
    }

    if (cflags & C_REL32) {
      rel32_ok:
        hs->flags |= F_IMM32 | F_RELATIVE;
        hs->imm_offset = static_cast<uint8_t>(p - (uint8_t *)code);
        hs->imm.imm32 = *(uint32_t *)p;
        p += 4;
    } else if (cflags & C_REL8) {
        hs->flags |= F_IMM8 | F_RELATIVE;
        hs->imm_offset = static_cast<uint8_t>(p - (uint8_t *)code);
        hs->imm.imm8 = *p++;
    }

  disasm_done:

    if ((hs->len = (uint8_t)(p-(uint8_t *)code)) > 15) {
        hs->flags |= F_ERROR | F_ERROR_LENGTH;
        hs->len = 15;
    }
    hde64_fill_meta(hs);

    return (unsigned int)hs->len;
}


#endif // defined(_M_X64) || defined(__x86_64__)
