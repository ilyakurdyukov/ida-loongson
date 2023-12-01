# ----------------------------------------------------------------------
# Loongarch64 processor module
# Copyright (c) 2023 Ilya Kurdyukov
#
# Compatible with IDA 7.x and possibly later versions.

import sys
from ida_idp import *
from ida_ua import *
from ida_lines import *
from ida_problems import *
from ida_xref import *
from ida_idaapi import *
from ida_bytes import *

if sys.version_info.major < 3:
  range = xrange

# sign extend b low bits in x
def SIGNEXT(x, b):
    m = 1 << (b - 1)
    return (x & (m - 1)) - (x & m)

# ----------------------------------------------------------------------
class loong64_processor_t(processor_t):
    """
    Processor module classes must derive from processor_t
    """

    # IDP id ( Numbers above 0x8000 are reserved for the third-party modules)
    # elf.h: EM_LOONGARCH = 258
    id = 0x8000 + 258

    # Processor features
    flag = PR_SEGS | PR_USE32 | PR_DEFSEG32 | PR_RNAMESOK | PRN_HEX

    # Number of bits in a byte for code segments (usually 8)
    # IDA supports values up to 32 bits (64 for IDA64)
    cnbits = 8

    # Number of bits in a byte for non-code segments (usually 8)
    # IDA supports values up to 32 bits (64 for IDA64)
    dnbits = 8

    # short processor names
    # Each name should be shorter than 9 characters
    psnames = ["loong64"]

    # long processor names
    # No restriction on name lengthes.
    plnames = ["Loongarch64"]

    # size of a segment register in bytes
    segreg_size = 0

    #
    # Number of digits in floating numbers after the decimal point.
    # If an element of this array equals 0, then the corresponding
    # floating point data is not used for the processor.
    # This array is used to align numbers in the output.
    #      real_width[0] - number of digits for short floats (only PDP-11 has them)
    #      real_width[1] - number of digits for "float"
    #      real_width[2] - number of digits for "double"
    #      real_width[3] - number of digits for "long double"
    # Example: IBM PC module has { 0,7,15,19 }
    #
    # (optional)
    real_width = (0, 7, 15, 0)


    # only one assembler is supported
    assembler = {
        # flag
        "flag": ASH_HEXF3 | ASD_DECF0 | ASO_OCTF1 | ASB_BINF3 | AS_N2CHR,

        # user defined flags (local only for IDP) (optional)
        "uflag": 0,

        # Assembler name (displayed in menus)
        "name": "Loongarch64 assembler",

        # array of automatically generated header lines they appear at the start of disassembled text (optional)
        # 'header': [".loong64"],

        # org directive
        "origin": ".org",

        # end directive
        "end": ".end",

        # comment string (see also cmnt2)
        "cmnt": "#",

        # ASCII string delimiter
        'ascsep': "\"",

        # ASCII char constant delimiter
        "accsep": "'",

        # ASCII special chars (they can't appear in character and ascii constants)
        'esccodes': "\"'",

        #
        #      Data representation (db,dw,...):
        #
        # ASCII string directive
        'a_ascii': ".char",

        # byte directive
        'a_byte': ".byte",

        # word directive
        'a_word': ".half",

        # remove if not allowed
        'a_dword': ".word",

        # remove if not allowed
        'a_qword': ".dword",

        # float;  4bytes; remove if not allowed
        'a_float': ".float",

        # double; 8bytes; NULL if not allowed
        'a_double': ".double",

        # uninitialized data directive (should include '%s' for the size of data)
        'a_bss': ".space %s",

        # 'equ' Used if AS_UNEQU is set (optional)
        'a_equ': ".equ",

        # 'seg ' prefix (example: push seg seg001)
        'a_seg': "seg",

        # current IP (instruction pointer) symbol in assembler
        'a_curip': ".",

        # "public" name keyword. NULL-gen default, ""-do not generate
        'a_public': "",

        # "weak"   name keyword. NULL-gen default, ""-do not generate
        'a_weak': "",

        # "extrn"  name keyword
        'a_extrn': ".extern",

        # "comm" (communal variable)
        "a_comdef": "",

        # "align" keyword
        "a_align": ".align",

        # Left and right braces used in complex expressions
        "lbrace": "(",
        "rbrace": ")",

        # %  mod     assembler time operation
        "a_mod": "%",

        # &  bit and assembler time operation
        "a_band": "&",

        # |  bit or  assembler time operation
        "a_bor": "|",

        # ^  bit xor assembler time operation
        "a_xor": "^",

        # ~  bit not assembler time operation
        "a_bnot": "~",

        # << shift left assembler time operation
        "a_shl": "<<",

        # >> shift right assembler time operation
        "a_shr": ">>",

        # size of type (format string) (optional)
        "a_sizeof_fmt": "size %s",

        'flag2': 0,

        # the include directive (format string) (optional)
        'a_include_fmt': '.include "%s"',
    }

    # ----------------------------------------------------------------------
    def notify_get_autocmt(self, insn):
        """
        Get instruction comment. 'insn' describes the instruction in question
        @return: None or the comment string
        """
        if 'cmt' in self.instruc[insn.itype]:
          return self.instruc[insn.itype]['cmt']

    # ----------------------------------------------------------------------

    maptbl0 = [ '', '', 'movgr2scr', 'movscr2gr',
        'clo.w', 'clz.w', 'cto.w', 'ctz.w',
        'clo.d', 'clz.d', 'cto.d', 'ctz.d',
        'revb.2h', 'revb.4h', 'revb.2w', 'revb.d',
        'revh.2w', 'revh.d', 'bitrev.4b', 'bitrev.8b',
        'bitrev.w', 'bitrev.d', 'ext.w.h', 'ext.w.b',
        'rdtimel.w', 'rdtimeh.w', 'rdtime.d', 'cpucfg']

    maptbl_arith = ['add.w', 'add.d', 'sub.w', 'sub.d',
        'slt', 'sltu', 'maskeqz', 'masknez',
        'nor', 'and', 'or', 'xor',
        'orn', 'andn', 'sll.w', 'srl.w',

        'sra.w', 'sll.d', 'srl.d', 'sra.d',
        '', '', 'rotr.w', 'rotr.d',
        'mul.w', 'mulh.w', 'mulh.wu', 'mul.d',
        'mulh.d', 'mulh.du', 'mulw.d.w', 'mulw.d.wu',

        'div.w', 'mod.w', 'div.wu', 'mod.wu',
        'div.d', 'mod.d', 'div.du', 'mod.du',
        'crc.w.b.w', 'crc.w.h.w', 'crc.w.w.w', 'crc.w.d.w',
        'crcc.w.b.w', 'crcc.w.h.w', 'crcc.w.w.w', 'crcc.w.d.w',
    ]

    maptbl_shift_imm = ['slli.w', 'slli.d', 'srli.w', 'srli.d',
        'srai.w', 'srai.d', 'rotri.w', 'rotri.d']

    maptbl_arith_imm = ['slti', 'sltui', 'addi.w', 'addi.d',
        'lu52i.d', 'andi', 'ori', 'xori']

    maptbl_pcadd = ['addu16i.d', 'addu16i.d', 'lu12i.w', 'lu32i.d',
        'pcaddi', 'pcalau12i', 'pcaddu12i', 'pcaddu18i']

    maptbl_mem14 = ['ll.w', 'sc.w', 'll.d', 'sc.d',
        'ldptr.w', 'stptr.w', 'ldptr.d', 'stptr.d']

    maptbl_mem12 = ['ld.b', 'ld.h', 'ld.w', 'ld.d',
        'st.b', 'st.h', 'st.w', 'st.d',
        'ld.bu', 'ld.hu', 'ld.wu', 'preld',
        'fld.s', 'fst.s', 'fld.d', 'fst.d']

    maptbl_memx = ['ldx.b', 'ldx.h', 'ldx.w', 'ldx.d',
        'stx.b', 'stx.h', 'stx.w', 'stx.d',
        'ldx.bu', 'ldx.hu', 'ldx.wu', 'preldx',
        'fldx.s', 'fldx.d', 'fstx.s', 'fstx.d']

    maptbl_privileged = [
        'iocsrrd.b', 'iocsrrd.h', 'iocsrrd.w', 'iocsrrd.d',
        'iocsrwr.b', 'iocsrwr.h', 'iocsrwr.w', 'iocsrwr.d',
        'tlbclr', 'tlbflush', 'tlbsrch', 'tlbrd',
        'tlbwr', 'tlbfill', 'ertn']

    maptbl_branch = ['beqz', 'bnez', '', 'jirl',
        'b', 'bl', 'beq', 'bne', 'blt', 'bge', 'bltu', 'bgeu']

    maptbl_float3 = {
        0x01: 'fadd.s',
        0x02: 'fadd.d',
        0x05: 'fsub.s',
        0x06: 'fsub.d',
        0x09: 'fmul.s',
        0x0a: 'fmul.d',
        0x0d: 'fdiv.s',
        0x0e: 'fdiv.d',
        0x11: 'fmax.s',
        0x12: 'fmax.d',
        0x15: 'fmin.s',
        0x16: 'fmin.d',
        0x19: 'fmaxa.s',
        0x1a: 'fmaxa.d',
        0x1d: 'fmina.s',
        0x1e: 'fmina.d',
        0x21: 'fscaleb.s',
        0x22: 'fscaleb.d',
        0x25: 'fcopysign.s',
        0x26: 'fcopysign.d'
    }

    maptbl_float2 = {
        0x501: 'fabs.s',
        0x502: 'fabs.d',
        0x505: 'fneg.s',
        0x506: 'fneg.d',
        0x509: 'flogb.s',
        0x50a: 'flogb.d',
        0x50d: 'fclass.s',
        0x50e: 'fclass.d',
        0x511: 'fsqrt.s',
        0x512: 'fsqrt.d',
        0x515: 'frecip.s',
        0x516: 'frecip.d',
        0x519: 'frsqrt.s',
        0x51a: 'frsqrt.d',
        0x51d: 'frecipe.s',
        0x51e: 'frecipe.d',
        0x521: 'frsqrte.s',
        0x522: 'frsqrte.d',
        0x525: 'fmov.s',
        0x526: 'fmov.d',

        0x529: 'movgr2fr.w',
        0x52a: 'movgr2fr.d',
        0x52b: 'movgr2frh.w',
        0x52d: 'movfr2gr.s',
        0x52e: 'movfr2gr.d',
        0x52f: 'movfrh2gr.s',
        0x530: 'movgr2fcsr',
        0x532: 'movfcsr2gr',
        0x534: 'movfr2cf',
        0x535: 'movcf2fr',
        0x536: 'movgr2cf',
        0x537: 'movcf2gr',

        0x646: 'fcvt.s.d',
        0x649: 'fcvt.d.s',
        0x681: 'ftintrm.w.s',
        0x682: 'ftintrm.w.d',
        0x689: 'ftintrm.l.s',
        0x68a: 'ftintrm.l.d',
        0x691: 'ftintrp.w.s',
        0x692: 'ftintrp.w.d',
        0x699: 'ftintrp.l.s',
        0x69a: 'ftintrp.l.d',
        0x6a1: 'ftintrz.w.s',
        0x6a2: 'ftintrz.w.d',
        0x6a9: 'ftintrz.l.s',
        0x6aa: 'ftintrz.l.d',
        0x6b1: 'ftintrne.w.s',
        0x6b2: 'ftintrne.w.d',
        0x6b9: 'ftintrne.l.s',
        0x6ba: 'ftintrne.l.d',
        0x6c1: 'ftint.w.s',
        0x6c2: 'ftint.w.d',
        0x6c9: 'ftint.l.s',
        0x6ca: 'ftint.l.d',
        0x744: 'ffint.s.w',
        0x746: 'ffint.s.l',
        0x748: 'ffint.d.w',
        0x74a: 'ffint.d.l',
        0x791: 'frint.s',
        0x792: 'frint.d',
    }

    maptbl_float4 = {
        0x01: 'fmadd.s',
        0x02: 'fmadd.d',
        0x05: 'fmsub.s',
        0x06: 'fmsub.d',
        0x09: 'fnmadd.s',
        0x0a: 'fnmadd.d',
        0x0d: 'fnmsub.s',
        0x0e: 'fnmsub.d',
        0x50: 'fsel'
    }

    maptbl_fcmp = {
        0x820: 'fcmp.caf.s',
        0x821: 'fcmp.saf.s',
        0x822: 'fcmp.clt.s',
        0x823: 'fcmp.slt.s',
        0x824: 'fcmp.ceq.s',
        0x825: 'fcmp.seq.s',
        0x826: 'fcmp.cle.s',
        0x827: 'fcmp.sle.s',
        0x828: 'fcmp.cun.s',
        0x829: 'fcmp.sun.s',
        0x82a: 'fcmp.cult.s',
        0x82b: 'fcmp.sult.s',
        0x82c: 'fcmp.cueq.s',
        0x82d: 'fcmp.sueq.s',
        0x82e: 'fcmp.cule.s',
        0x82f: 'fcmp.sule.s',
        0x830: 'fcmp.cne.s',
        0x831: 'fcmp.sne.s',
        0x834: 'fcmp.cor.s',
        0x835: 'fcmp.sor.s',
        0x838: 'fcmp.cune.s',
        0x839: 'fcmp.sune.s',

        0x840: 'fcmp.caf.d',
        0x841: 'fcmp.saf.d',
        0x842: 'fcmp.clt.d',
        0x843: 'fcmp.slt.d',
        0x844: 'fcmp.ceq.d',
        0x845: 'fcmp.seq.d',
        0x846: 'fcmp.cle.d',
        0x847: 'fcmp.sle.d',
        0x848: 'fcmp.cun.d',
        0x849: 'fcmp.sun.d',
        0x84a: 'fcmp.cult.d',
        0x84b: 'fcmp.sult.d',
        0x84c: 'fcmp.cueq.d',
        0x84d: 'fcmp.sueq.d',
        0x84e: 'fcmp.cule.d',
        0x84f: 'fcmp.sule.d',
        0x850: 'fcmp.cne.d',
        0x851: 'fcmp.sne.d',
        0x854: 'fcmp.cor.d',
        0x855: 'fcmp.sor.d',
        0x858: 'fcmp.cune.d',
        0x859: 'fcmp.sune.d'
    }

    maptbl_atomic_mem_2f = ['llacq.w', 'screl.w', 'llacq.d', 'screl.d']

    maptbl_atomic_mem = {
        0x2e: 'sc.q',
        # 0x2f -> maptbl_atomic_mem_2f
        0x30: 'amcas.b',
        0x31: 'amcas.h',
        0x32: 'amcas.w',
        0x33: 'amcas.d',
        0x34: 'amcas_db.b',
        0x35: 'amcas_db.h',
        0x36: 'amcas_db.w',
        0x37: 'amcas_db.d',

        0x38: 'amswap.b',
        0x39: 'amswap.h',
        0x3a: 'amadd.b',
        0x3b: 'amadd.h',
        0x3c: 'amswap_db.b',
        0x3d: 'amswap_db.h',
        0x3e: 'amadd_db.b',
        0x3f: 'amadd_db.h',

        0x40: 'amswap.w',
        0x41: 'amswap.d',
        0x42: 'amadd.w',
        0x43: 'amadd.d',
        0x44: 'amand.w',
        0x45: 'amand.d',
        0x46: 'amor.w',
        0x47: 'amor.d',
        0x48: 'amxor.w',
        0x49: 'amxor.d',
        0x4a: 'ammax.w',
        0x4b: 'ammax.d',
        0x4c: 'ammin.w',
        0x4d: 'ammin.d',
        0x4e: 'ammax.wu',
        0x4f: 'ammax.du',
        0x50: 'ammin.wu',
        0x51: 'ammin.du',
        0x52: 'amswap_db.w',
        0x53: 'amswap_db.d',
        0x54: 'amadd_db.w',
        0x55: 'amadd_db.d',
        0x56: 'amand_db.w',
        0x57: 'amand_db.d',
        0x58: 'amor_db.w',
        0x59: 'amor_db.d',
        0x5a: 'amxor_db.w',
        0x5b: 'amxor_db.d',
        0x5c: 'ammax_db.w',
        0x5d: 'ammax_db.d',
        0x5e: 'ammin_db.w',
        0x5f: 'ammin_db.d',
        0x60: 'ammax_db.wu',
        0x61: 'ammax_db.du',
        0x62: 'ammin_db.wu',
        0x63: 'ammin_db.du',
        0x64: 'dbar',
        0x65: 'ibar',

        0x68: 'fldgt.s',
        0x69: 'fldgt.d',
        0x6a: 'fldle.s',
        0x6b: 'fldle.d',
        0x6c: 'fstgt.s',
        0x6d: 'fstgt.d',
        0x6e: 'fstle.s',
        0x6f: 'fstle.d',
        0x70: 'ldgt.b',
        0x71: 'ldgt.h',
        0x72: 'ldgt.w',
        0x73: 'ldgt.d',
        0x74: 'ldle.b',
        0x75: 'ldle.h',
        0x76: 'ldle.w',
        0x77: 'ldle.d',
        0x78: 'stgt.b',
        0x79: 'stgt.h',
        0x7a: 'stgt.w',
        0x7b: 'stgt.d',
        0x7c: 'stle.b',
        0x7d: 'stle.h',
        0x7e: 'stle.w',
        0x7f: 'stle.d'
    }


    def notify_ana(self, insn):
        """
        Decodes an instruction into 'insn'.
        Returns: insn.size (=the size of the decoded instruction) or zero
        """
        if insn.ea & 3 != 0:
            return 0
        raw = insn.get_next_dword()
        rD = raw & 0x1f
        rJ = raw >> 5 & 0x1f
        rK = raw >> 10 & 0x1f
        hi16 = raw >> 16 & 0xffff

        if raw & 0xffff8000 == 0:
            if 1 << rK & 0x0ffffff0 == 0:
                if rK == 2: # movgr2scr
                   if rD > 3:
                      return 0
                   rD += self.ireg_scr0
                elif rK == 3: # movscr2gr
                   if rJ > 3:
                      return 0
                   rJ += self.ireg_scr0
                else:
                    return 0
            insn.itype = self.maptbl0[rK]
            insn.Op1.type = o_reg
            insn.Op1.reg = rD
            insn.Op2.type = o_reg
            insn.Op2.reg = rJ

        elif raw & 0xffff0000 == 0x10000:
            insn.Op1.type = o_reg
            insn.Op1.reg = rJ
            insn.Op2.type = o_reg
            insn.Op2.reg = rK
            if rD != 0:
                return 0
            if raw & 0x8000 == 0:
                insn.itype = self.name2icode['asrtle.d']
            else:
                insn.itype = self.name2icode['asrtgt.d']

        elif raw & 0xfffc0000 == 0x40000:
            insn.Op1.type = o_reg
            insn.Op1.reg = rD
            insn.Op2.type = o_reg
            insn.Op2.reg = rJ
            insn.Op3.type = o_reg
            insn.Op3.reg = rK
            insn.Op4.type = o_imm
            insn.Op4.value = (raw >> 15 & 3) + 1 # sa2
            if raw & 0x20000 == 0:
                insn.itype = self.name2icode['alsl.w']
            else:
                insn.itype = self.name2icode['alsl.wu']

        elif raw & 0xfff80000 == 0x80000:
            insn.Op1.type = o_reg
            insn.Op1.reg = rD
            insn.Op2.type = o_reg
            insn.Op2.reg = rJ
            insn.Op3.type = o_reg
            insn.Op3.reg = rK
            insn.Op4.type = o_imm
            if raw & 0x40000 == 0:
                if raw & 0x20000 != 0:
                    return 0
                insn.Op4.value = raw >> 15 & 3 # sa2
                insn.itype = self.name2icode['bytepick.w']
            else:
                insn.Op4.value = raw >> 15 & 7 # sa3
                insn.itype = self.name2icode['bytepick.d']

        elif raw & 0xfff00000 == 0x00100000:
            insn.Op1.type = o_reg
            insn.Op1.reg = rD
            insn.Op2.type = o_reg
            insn.Op2.reg = rJ
            # move rD, rJ = or rD, rJ, r0
            if raw & 0xfffffc00 == 0x00150000:
                insn.itype = self.name2icode['move']
            else:
                insn.itype = self.maptbl_arith[raw >> 15 & 0x1f]
                insn.Op3.type = o_reg
                insn.Op3.reg = rK

        elif raw & 0xffe00000 == 0x00200000:
            opc2 = raw >> 15 & 0x3f
            if opc2 < 0x10:
                insn.itype = self.maptbl_arith[opc2 + 0x20]
                insn.Op1.type = o_reg
                insn.Op1.reg = rD
                insn.Op2.type = o_reg
                insn.Op2.reg = rJ
                insn.Op3.type = o_reg
                insn.Op3.reg = rK
            elif opc2 & 0x3c == 0x18:
                insn.itype = self.name2icode['alsl.d']
                insn.Op1.type = o_reg
                insn.Op1.reg = rD
                insn.Op2.type = o_reg
                insn.Op2.reg = rJ
                insn.Op3.type = o_reg
                insn.Op3.reg = rK
                insn.Op4.type = o_imm
                insn.Op4.value = (raw >> 15 & 3) + 1 # sa2
            else:
                if opc2 == 0x14:
                    insn.itype = self.name2icode['break']
                elif opc2 == 0x15:
                    insn.itype = self.name2icode['dbcl']
                elif opc2 == 0x16:
                    insn.itype = self.name2icode['syscall']
                else:
                    return 0
                insn.Op1.type = o_imm
                insn.Op1.value = raw & 0x7fff # code

        elif raw & 0xffe00000 == 0x00400000:
            opc2 = raw >> 15 & 0x3f
            if opc2 & 2 == 0:
               if opc2 & 0x27 != 1:
                   return 0
               insn.Op3.value = rK # ui5
            else:
               if opc2 & 0x26 != 2:
                   return 0
               insn.Op3.value = raw >> 10 & 0x3f # ui6
            insn.itype = self.maptbl_shift_imm[(opc2 + 2) >> 2]
            insn.Op1.type = o_reg
            insn.Op1.reg = rD
            insn.Op2.type = o_reg
            insn.Op2.reg = rJ
            insn.Op3.type = o_imm

        elif raw & 0xffe00000 == 0x00600000:
            if raw & 0x8000 == 0:
                insn.itype = self.name2icode['bstrins.w']
            else:
                insn.itype = self.name2icode['bstrpick.w']
            insn.Op1.type = o_reg
            insn.Op1.reg = rD
            insn.Op2.type = o_reg
            insn.Op2.reg = rJ
            insn.Op3.type = o_imm
            insn.Op3.value = raw >> 16 & 0x1f # msbw
            insn.Op4.type = o_imm
            insn.Op4.value = rK # lsbw

        elif raw & 0xff800000 == 0x00800000:
            if raw & 0x400000 == 0:
                insn.itype = self.name2icode['bstrins.d']
            else:
                insn.itype = self.name2icode['bstrpick.d']
            insn.Op1.type = o_reg
            insn.Op1.reg = rD
            insn.Op2.type = o_reg
            insn.Op2.reg = rJ
            insn.Op3.type = o_imm
            insn.Op3.value = raw >> 16 & 0x3f # msbd
            insn.Op4.type = o_imm
            insn.Op4.value = raw >> 10 & 0x3f # lsbd

        elif raw & 0xffe00000 == 0x01000000:
            opc2 = raw >> 15 & 0x3f
            if opc2 >= 0x28:
                opc2 = raw >> 10 & 0x7ff
                if not opc2 in self.maptbl_float2:
                    return 0
                insn.itype = self.maptbl_float2[opc2]
                if opc2 < 0x529 or opc2 > 0x537:
                    insn.Op1.type = o_reg
                    insn.Op1.reg = rD + self.ireg_f0
                    insn.Op2.type = o_reg
                    insn.Op2.reg = rJ + self.ireg_f0
                elif opc2 <= 0x52b: # movgr2fr{h}.{s,d}
                    insn.Op1.type = o_reg
                    insn.Op1.reg = rD + self.ireg_f0
                    insn.Op2.type = o_reg
                    insn.Op2.reg = rJ
                elif opc2 <= 0x52f: # movfr{h}2gr.{s,d}
                    insn.Op1.type = o_reg
                    insn.Op1.reg = rD
                    insn.Op2.type = o_reg
                    insn.Op2.reg = rJ + self.ireg_f0
                elif opc2 == 0x530: # movgr2fcsr
                    if rD > 3:
                        return 0
                    insn.Op1.type = o_reg
                    insn.Op1.reg = rD + self.ireg_fcsr0
                    insn.Op2.type = o_reg
                    insn.Op2.reg = rJ
                elif opc2 == 0x532: # movfcsr2gr
                    if rJ > 3:
                        return 0
                    insn.Op1.type = o_reg
                    insn.Op1.reg = rD
                    insn.Op2.type = o_reg
                    insn.Op2.reg = rJ + self.ireg_fcsr0
                elif opc2 == 0x534: # movfr2cf
                    if rD > 7:
                        return 0
                    insn.Op1.type = o_reg
                    insn.Op1.reg = rD + self.ireg_fcc0
                    insn.Op2.type = o_reg
                    insn.Op2.reg = rJ + self.ireg_f0
                elif opc2 == 0x535: # movcf2fr
                    if rJ > 7:
                        return 0
                    insn.Op1.type = o_reg
                    insn.Op1.reg = rD + self.ireg_f0
                    insn.Op2.type = o_reg
                    insn.Op2.reg = rJ + self.ireg_fcc0
                elif opc2 == 0x536: # movgr2cf
                    if rD > 7:
                        return 0
                    insn.Op1.type = o_reg
                    insn.Op1.reg = rD + self.ireg_fcc0
                    insn.Op2.type = o_reg
                    insn.Op2.reg = rJ
                elif opc2 == 0x537: # movcf2gr
                    if rJ > 7:
                        return 0
                    insn.Op1.type = o_reg
                    insn.Op1.reg = rD
                    insn.Op2.type = o_reg
                    insn.Op2.reg = rJ + self.ireg_fcc0

            elif opc2 in self.maptbl_float3:
                insn.itype = self.maptbl_float3[opc2]
                insn.Op1.type = o_reg
                insn.Op1.reg = rD + self.ireg_f0
                insn.Op2.type = o_reg
                insn.Op2.reg = rJ + self.ireg_f0
                insn.Op3.type = o_reg
                insn.Op3.reg = rK + self.ireg_f0
            else:
                return 0

        # arith
        elif raw & 0xfe000000 == 0x02000000:
            masked = raw & 0xffc003e0
            if masked == 0x02800000:
                insn.itype = self.name2icode['li.w']
                insn.Op1.type = o_reg
                insn.Op1.reg = rD
                insn.Op2.type = o_imm
                insn.Op2.value = SIGNEXT(raw >> 10, 12) # si12
            elif masked == 0x02c00000:
                insn.itype = self.name2icode['li.d']
                insn.Op1.type = o_reg
                insn.Op1.reg = rD
                insn.Op2.type = o_imm
                insn.Op2.value = SIGNEXT(raw >> 10, 12) # si12
            elif raw & 0xffffffff == 0x03400000:
                insn.itype = self.name2icode['nop']
            elif masked == 0x03800000:
                insn.itype = self.name2icode['li.w']
                insn.Op1.type = o_reg
                insn.Op1.reg = rD
                insn.Op2.type = o_imm
                insn.Op2.value = raw >> 10 & 0xfff # ui12
            else:
                opc2 = raw >> 22 & 7
                insn.itype = self.maptbl_arith_imm[opc2]
                insn.Op1.type = o_reg
                insn.Op1.reg = rD
                insn.Op2.type = o_reg
                insn.Op2.reg = rJ
                insn.Op3.type = o_imm
                if opc2 < 5:
                    insn.Op3.value = SIGNEXT(raw >> 10, 12) # si12
                else:
                    insn.Op3.value = raw >> 10 & 0xfff # ui12

        # CSR (Control and Status Registers) access
        elif raw & 0xff000000 == 0x04000000:
            insn.Op1.type = o_reg
            insn.Op1.reg = rD
            if rJ < 2:
                insn.Op2.type = o_imm
                insn.Op2.value = raw >> 10 & 0x3fff # csr
                if rJ == 0:
                    insn.itype = self.name2icode['csrrd']
                else:
                    insn.itype = self.name2icode['csrwr']
            else:
                insn.itype = self.name2icode['csrxchg']
                insn.Op2.type = o_reg
                insn.Op2.reg = rJ
                insn.Op3.type = o_imm
                insn.Op3.value = raw >> 10 & 0x3fff # csr

        elif raw & 0xffc00000 == 0x06000000:
            insn.itype = self.name2icode['cacop']
            insn.Op1.type = o_imm
            insn.Op1.value = rD
            insn.Op2.type = o_reg
            insn.Op2.reg = rJ
            insn.Op3.type = o_imm
            insn.Op3.value = SIGNEXT(raw >> 10, 12) # si12

        elif raw & 0xfff80000 == 0x06400000:
            if raw & 0x40000 == 0:
                insn.itype = self.name2icode['lddir']
                insn.Op1.type = o_reg
                insn.Op1.reg = rD
                insn.Op2.type = o_reg
                insn.Op2.reg = rJ
                insn.Op3.type = o_imm
                insn.Op3.value = raw >> 10 & 0xff # level
            elif rD == 0:
                insn.itype = self.name2icode['ldpte']
                insn.Op1.type = o_reg
                insn.Op1.reg = rJ
                insn.Op2.type = o_imm
                insn.Op2.value = raw >> 10 & 0xff # seq
            else:
                return 0

        elif raw & 0xfff80000 == 0x06480000:
            opc2 = raw >> 15 & 0xf
            if opc2 == 0:
                if rK < 8:
                    insn.Op1.type = o_reg
                    insn.Op1.reg = rD
                    insn.Op2.type = o_reg
                    insn.Op2.reg = rJ
                elif rK > 0xe or raw & 0x3ff != 0:
                    return 0
                insn.itype = self.maptbl_privileged[rK]
            elif opc2 == 1:
                insn.itype = self.name2icode['idle']
                insn.Op1.type = o_imm
                insn.Op1.value = raw & 0x7fff # level
            elif opc2 == 3:
                insn.itype = self.name2icode['invtlb']
                insn.Op1.type = o_imm
                insn.Op1.value = rD # op
                insn.Op2.type = o_reg
                insn.Op2.reg = rJ
                insn.Op3.type = o_reg
                insn.Op3.reg = rK
            else:
                return 0

        elif raw & 0xf8000000 == 0x08000000:
            opc2 = raw >> 20 & 0x7f
            if opc2 in self.maptbl_float4:
                insn.itype = self.maptbl_float4[opc2]
                rA = raw >> 15 & 0x1f
                if opc2 < 0x10:
                    insn.Op1.type = o_reg
                    insn.Op1.reg = rD + self.ireg_f0
                    insn.Op2.type = o_reg
                    insn.Op2.reg = rJ + self.ireg_f0
                    insn.Op3.type = o_reg
                    insn.Op3.reg = rK + self.ireg_f0
                    insn.Op4.type = o_reg
                    insn.Op4.reg = rA + self.ireg_f0
                elif opc2 == 0x50: # fsel
                    if rA > 7:
                        return 0
                    insn.Op1.type = o_reg
                    insn.Op1.reg = rD + self.ireg_f0
                    insn.Op2.type = o_reg
                    insn.Op2.reg = rJ + self.ireg_f0
                    insn.Op3.type = o_reg
                    insn.Op3.reg = rK + self.ireg_f0
                    insn.Op4.type = o_reg
                    insn.Op4.reg = rA + self.ireg_fcc0
            else: # fcmp.{cond}.{s,d}
                if rD > 7:
                    return 0
                opc2 = raw >> 15 & 0xfff
                if not opc2 in self.maptbl_fcmp:
                    return 0
                insn.itype = self.maptbl_fcmp[opc2]
                insn.Op1.type = o_reg
                insn.Op1.reg = rD + self.ireg_fcc0
                insn.Op2.type = o_reg
                insn.Op2.reg = rJ + self.ireg_f0
                insn.Op3.type = o_reg
                insn.Op3.reg = rK + self.ireg_f0

        elif raw & 0xf0000000 == 0x10000000:
            insn.Op1.type = o_reg
            insn.Op1.reg = rD
            opc2 = raw >> 25 & 7
            insn.itype = self.maptbl_pcadd[opc2]
            if opc2 < 2:
                insn.Op2.type = o_reg
                insn.Op2.reg = rJ
                insn.Op3.type = o_imm
                insn.Op3.value = SIGNEXT(raw >> 10, 16) # si16
            else:
                insn.Op2.type = o_imm
                insn.Op2.value = SIGNEXT(raw >> 5, 20) # si20

        # load/store imm14
        elif raw & 0xf8000000 == 0x20000000:
            insn.itype = self.maptbl_mem14[raw >> 24 & 7]
            insn.Op1.type = o_reg
            insn.Op1.reg = rD
            insn.Op2.type = o_reg
            insn.Op2.reg = rJ
            insn.Op3.type = o_imm
            insn.Op3.value = SIGNEXT(raw >> 10, 14) * 4 # si14

        # load/store imm12
        elif raw & 0xfc000000 == 0x28000000:
            opc2 = raw >> 22 & 0xf
            insn.itype = self.maptbl_mem12[opc2]
            if opc2 == 0xb: # preld
                insn.Op1.type = o_imm
                insn.Op1.value = rD
            elif opc2 >= 0xc: # float
                insn.Op1.type = o_reg
                insn.Op1.reg = rD + self.ireg_f0
            else:
                insn.Op1.type = o_reg
                insn.Op1.reg = rD
            insn.Op2.type = o_reg
            insn.Op2.reg = rJ
            insn.Op3.type = o_imm
            insn.Op3.value = SIGNEXT(raw >> 10, 12) # si12

        # load/store
        elif raw & 0xffc38000 == 0x38000000:
            opc2 = raw >> 18 & 0xf
            if opc2 == 0xb: # preldx
                insn.Op1.type = o_imm
                insn.Op1.value = rD
            elif opc2 >= 0xc: # float
                insn.Op1.type = o_reg
                insn.Op1.reg = rD + self.ireg_f0
            else:
                insn.Op1.type = o_reg
                insn.Op1.reg = rD
            insn.itype = self.maptbl_memx[opc2]
            insn.Op2.type = o_reg
            insn.Op2.reg = rJ
            insn.Op3.type = o_reg
            insn.Op3.reg = rK

        elif raw & 0xffc00000 == 0x38400000:
            opc2 = raw >> 15 & 0x7f
            if opc2 in self.maptbl_atomic_mem:
                insn.itype = self.maptbl_atomic_mem[opc2]
                if opc2 < 0x64: # sc.q, am*
                    insn.Op1.type = o_reg
                    insn.Op1.reg = rD
                    insn.Op2.type = o_reg
                    insn.Op2.reg = rK
                    insn.Op3.type = o_reg
                    insn.Op3.reg = rJ
                elif opc2 < 0x66: # dbar, ibar
                    insn.Op1.type = o_imm
                    insn.Op1.value = raw & 0x7fff
                elif opc2 < 0x70: # f{ld,st}{gt,le}.{s,d}
                    insn.Op1.type = o_reg
                    insn.Op1.reg = rD + self.ireg_f0
                    insn.Op2.type = o_reg
                    insn.Op2.reg = rJ
                    insn.Op3.type = o_reg
                    insn.Op3.reg = rK
                else: # {ld,st}{gt,le}.{b,h,w,d}
                    insn.Op1.type = o_reg
                    insn.Op1.reg = rD
                    insn.Op2.type = o_reg
                    insn.Op2.reg = rJ
                    insn.Op3.type = o_reg
                    insn.Op3.reg = rK
            elif opc2 == 0x2f:
                if rK > 3:
                    return 0
                insn.itype = self.maptbl_atomic_mem_2f[rK]
                insn.Op1.type = o_reg
                insn.Op1.reg = rD
                insn.Op2.type = o_reg
                insn.Op2.reg = rJ
            else:
                return 0

        # branch
        elif raw & 0xc0000000 == 0x40000000:
            opc2 = raw >> 26 & 0xf
            if opc2 >= 0xc:
                return 0

            addr = raw >> 10 & 0xffff
            if opc2 != 2:
                insn.itype = self.maptbl_branch[opc2]
                if opc2 >= 6:
                    insn.itype = self.maptbl_branch[opc2]
                    insn.Op1.type = o_reg
                    insn.Op1.reg = rJ
                    insn.Op2.type = o_reg
                    insn.Op2.reg = rD
                    insn.Op3.type = o_near
                    insn.Op3.addr = (insn.ea + SIGNEXT(addr, 16) * 4) & 0xffffffff
                elif opc2 >= 4: # b, bl
                    insn.Op1.type = o_near
                    addr = addr | (raw & 0x3ff) << 16
                    insn.Op1.addr = (insn.ea + SIGNEXT(addr, 26) * 4) & 0xffffffff
                elif opc2 < 2: # beqz, bnez
                    insn.Op1.type = o_reg
                    insn.Op1.reg = rJ
                    insn.Op2.type = o_near
                    addr = addr | rD << 16
                    insn.Op2.addr = (insn.ea + SIGNEXT(addr, 21) * 4) & 0xffffffff
                elif opc2 == 3: # jirl
                    # jr rJ = jirl r0, rJ, 0
                    if addr == 0 and rD == 0:
                        insn.itype = self.name2icode['jr']
                        insn.Op1.type = o_reg
                        insn.Op1.reg = rJ
                    else:
                        insn.Op1.type = o_reg
                        insn.Op1.reg = rD
                        insn.Op2.type = o_reg
                        insn.Op2.reg = rJ
                        insn.Op3.type = o_imm
                        insn.Op3.value = SIGNEXT(addr, 16) * 4

            else: # bceqz, bcnez
                if rJ & 0x18 == 0:
                    insn.itype = self.name2icode['bceqz']
                elif rJ & 0x18 == 8:
                    insn.itype = self.name2icode['bcnez']
                else:
                    return 0
                insn.Op1.type = o_reg
                insn.Op1.reg = (rJ & 7) + self.ireg_fcc0
                insn.Op2.type = o_near
                addr = (raw >> 10 & 0xffff) | rD << 16
                insn.Op2.addr = (insn.ea + SIGNEXT(addr, 21) * 4) & 0xffffffff

        else:
            return 0
        return insn.size

    # ----------------------------------------------------------------------
    def handle_operand(self, insn, op, dref_flag):
        if op.type == o_near:
            if insn.get_canon_feature() & CF_CALL:
                insn.add_cref(op.addr, 0, fl_CN)
            else:
                insn.add_cref(op.addr, 0, fl_JN)

    def notify_emu(self, insn):
        Feature = insn.get_canon_feature()

        if Feature & CF_USE1:
            self.handle_operand(insn, insn.Op1, dr_R)
        if Feature & CF_CHG1:
            self.handle_operand(insn, insn.Op1, dr_W)
        if Feature & CF_USE2:
            self.handle_operand(insn, insn.Op2, dr_R)
        if Feature & CF_USE3:
            self.handle_operand(insn, insn.Op3, dr_R)
        if Feature & CF_USE4:
            self.handle_operand(insn, insn.Op4, dr_R)
        if Feature & CF_JUMP:
            remember_problem(PR_JUMP, insn.ea)

        flow = Feature & CF_STOP == 0
        if flow:
            add_cref(insn.ea, insn.ea + insn.size, fl_F)

        return True

    # ----------------------------------------------------------------------
    def notify_out_operand(self, ctx, op):
        optype = op.type

        if optype == o_reg:
            ctx.out_symbol('$')
            ctx.out_register(self.reg_names[op.reg])
        elif optype == o_imm:
            ctx.out_value(op, OOFW_32 | OOF_SIGNED)
        elif optype == o_near:
            r = ctx.out_name_expr(op, op.addr, BADADDR)
            if not r:
                ctx.out_tagon(COLOR_ERROR)
                ctx.out_long(op.addr, 16)
                ctx.out_tagoff(COLOR_ERROR)
                remember_problem(PR_NONAME, ctx.insn.ea)
        else:
            return False

        return True

    # ----------------------------------------------------------------------
    def out_mnem(self, ctx):
        ctx.out_mnem(16, "")
        return 1

    # ----------------------------------------------------------------------
    def notify_out_insn(self, ctx):
        ctx.out_mnemonic()

        if ctx.insn.Op1.type != o_void:
            ctx.out_one_operand(0)
        for i in range(1, 4):
            if ctx.insn[i].type == o_void:
                break
            ctx.out_symbol(',')
            ctx.out_char(' ')
            ctx.out_one_operand(i)

        ctx.set_gen_cmt()
        ctx.flush_outbuf()
        return True

    # ----------------------------------------------------------------------

    # Array of instructions
    instruc = [
        {'name': '', 'feature': 0, 'cmt': 'bad opcode'},

        {'name': 'clo.w',     'feature': CF_CHG1 | CF_USE2 },
        {'name': 'clz.w',     'feature': CF_CHG1 | CF_USE2 },
        {'name': 'cto.w',     'feature': CF_CHG1 | CF_USE2 },
        {'name': 'ctz.w',     'feature': CF_CHG1 | CF_USE2 },
        {'name': 'clo.d',     'feature': CF_CHG1 | CF_USE2 },
        {'name': 'clz.d',     'feature': CF_CHG1 | CF_USE2 },
        {'name': 'cto.d',     'feature': CF_CHG1 | CF_USE2 },
        {'name': 'ctz.d',     'feature': CF_CHG1 | CF_USE2 },
        {'name': 'revb.2h',   'feature': CF_CHG1 | CF_USE2 },
        {'name': 'revb.4h',   'feature': CF_CHG1 | CF_USE2 },
        {'name': 'revb.2w',   'feature': CF_CHG1 | CF_USE2 },
        {'name': 'revb.d',    'feature': CF_CHG1 | CF_USE2 },
        {'name': 'revh.2w',   'feature': CF_CHG1 | CF_USE2 },
        {'name': 'revh.d',    'feature': CF_CHG1 | CF_USE2 },
        {'name': 'bitrev.4b', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'bitrev.8b', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'bitrev.w',  'feature': CF_CHG1 | CF_USE2 },
        {'name': 'bitrev.d',  'feature': CF_CHG1 | CF_USE2 },
        {'name': 'ext.w.h',   'feature': CF_CHG1 | CF_USE2 },
        {'name': 'ext.w.b',   'feature': CF_CHG1 | CF_USE2 },
        {'name': 'rdtimel.w', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'rdtimeh.w', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'rdtime.d',  'feature': CF_CHG1 | CF_USE2 },
        {'name': 'cpucfg',    'feature': CF_CHG1 | CF_USE2 },

        {'name': 'asrtle.d',  'feature': CF_USE1 | CF_USE2 },
        {'name': 'asrtgt.d',  'feature': CF_USE1 | CF_USE2 },

        {'name': 'alsl.w',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4 },
        {'name': 'alsl.wu',   'feature': CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4 },
        {'name': 'bytepick.w', 'feature': CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4 },
        {'name': 'bytepick.d', 'feature': CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4 },

        {'name': 'add.w',     'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'add.d',     'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'sub.w',     'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'sub.d',     'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'slt',       'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'sltu',      'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'maskeqz',   'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'masknez',   'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'nor',       'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'and',       'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'or',        'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'xor',       'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'orn',       'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'andn',      'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'sll.w',     'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'srl.w',     'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'sra.w',     'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'sll.d',     'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'srl.d',     'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'sra.d',     'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'rotr.w',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'rotr.d',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },

        {'name': 'mul.w',     'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'mulh.w',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'mulh.wu',   'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'mul.d',     'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'mulh.d',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'mulh.du',   'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'mulw.d.w',  'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'mulw.d.wu', 'feature': CF_CHG1 | CF_USE2 | CF_USE3 },

        {'name': 'div.w',     'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'mod.w',     'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'div.wu',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'mod.wu',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'div.d',     'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'mod.d',     'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'div.du',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'mod.du',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },

        {'name': 'crc.w.b.w', 'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'crc.w.h.w', 'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'crc.w.w.w', 'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'crc.w.d.w', 'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'crcc.w.b.w', 'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'crcc.w.h.w', 'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'crcc.w.w.w', 'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'crcc.w.d.w', 'feature': CF_CHG1 | CF_USE2 | CF_USE3 },

        {'name': 'break',     'feature': CF_USE1 },
        {'name': 'dbcl',      'feature': CF_USE1 },
        {'name': 'syscall',   'feature': CF_USE1 },
        {'name': 'alsl.d',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4 },

        {'name': 'slli.w',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'slli.d',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'srli.w',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'srli.d',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'srai.w',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'srai.d',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'rotri.w',   'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'rotri.d',   'feature': CF_CHG1 | CF_USE2 | CF_USE3 },

        {'name': 'bstrins.w',  'feature': CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4 },
        {'name': 'bstrpick.w', 'feature': CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4 },
        {'name': 'bstrins.d',  'feature': CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4 },
        {'name': 'bstrpick.d', 'feature': CF_CHG1 | CF_USE2 | CF_USE3 | CF_USE4 },

        # float
        {'name': 'fadd.s',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'fadd.d',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'fsub.s',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'fsub.d',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'fmul.s',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'fmul.d',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'fdiv.s',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'fdiv.d',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'fmax.s',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'fmax.d',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'fmin.s',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'fmin.d',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'fmaxa.s',   'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'fmaxa.d',   'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'fmina.s',   'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'fmina.d',   'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'fscaleb.s', 'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'fscaleb.d', 'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'fcopysign.s', 'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'fcopysign.d', 'feature': CF_CHG1 | CF_USE2 | CF_USE3 },

        {'name': 'fabs.s',    'feature': CF_CHG1 | CF_USE2 },
        {'name': 'fabs.d',    'feature': CF_CHG1 | CF_USE2 },
        {'name': 'fneg.s',    'feature': CF_CHG1 | CF_USE2 },
        {'name': 'fneg.d',    'feature': CF_CHG1 | CF_USE2 },
        {'name': 'flogb.s',   'feature': CF_CHG1 | CF_USE2 },
        {'name': 'flogb.d',   'feature': CF_CHG1 | CF_USE2 },
        {'name': 'fclass.s',  'feature': CF_CHG1 | CF_USE2 },
        {'name': 'fclass.d',  'feature': CF_CHG1 | CF_USE2 },
        {'name': 'fsqrt.s',   'feature': CF_CHG1 | CF_USE2 },
        {'name': 'fsqrt.d',   'feature': CF_CHG1 | CF_USE2 },
        {'name': 'frecip.s',  'feature': CF_CHG1 | CF_USE2 },
        {'name': 'frecip.d',  'feature': CF_CHG1 | CF_USE2 },
        {'name': 'frsqrt.s',  'feature': CF_CHG1 | CF_USE2 },
        {'name': 'frsqrt.d',  'feature': CF_CHG1 | CF_USE2 },
        {'name': 'frecipe.s', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'frecipe.d', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'frsqrte.s', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'frsqrte.d', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'fmov.s',    'feature': CF_CHG1 | CF_USE2 },
        {'name': 'fmov.d',    'feature': CF_CHG1 | CF_USE2 },

        {'name': 'movgr2fr.w',  'feature': CF_CHG1 | CF_USE2 },
        {'name': 'movgr2fr.d',  'feature': CF_CHG1 | CF_USE2 },
        {'name': 'movgr2frh.w', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'movfr2gr.s',  'feature': CF_CHG1 | CF_USE2 },
        {'name': 'movfr2gr.d',  'feature': CF_CHG1 | CF_USE2 },
        {'name': 'movfrh2gr.s', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'movgr2fcsr',  'feature': CF_CHG1 | CF_USE2 },
        {'name': 'movfcsr2gr',  'feature': CF_CHG1 | CF_USE2 },
        {'name': 'movfr2cf',    'feature': CF_CHG1 | CF_USE2 },
        {'name': 'movcf2fr',    'feature': CF_CHG1 | CF_USE2 },
        {'name': 'movgr2cf',    'feature': CF_CHG1 | CF_USE2 },
        {'name': 'movcf2gr',    'feature': CF_CHG1 | CF_USE2 },
        {'name': 'fcvt.s.d',    'feature': CF_CHG1 | CF_USE2 },
        {'name': 'fcvt.d.s',    'feature': CF_CHG1 | CF_USE2 },
        {'name': 'ftintrm.w.s', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'ftintrm.w.d', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'ftintrm.l.s', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'ftintrm.l.d', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'ftintrp.w.s', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'ftintrp.w.d', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'ftintrp.l.s', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'ftintrp.l.d', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'ftintrz.w.s', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'ftintrz.w.d', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'ftintrz.l.s', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'ftintrz.l.d', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'ftintrne.w.s', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'ftintrne.w.d', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'ftintrne.l.s', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'ftintrne.l.d', 'feature': CF_CHG1 | CF_USE2 },

        {'name': 'ftint.w.s', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'ftint.w.d', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'ftint.l.s', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'ftint.l.d', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'ffint.s.w', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'ffint.s.l', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'ffint.d.w', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'ffint.d.l', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'frint.s',   'feature': CF_CHG1 | CF_USE2 },
        {'name': 'frint.d',   'feature': CF_CHG1 | CF_USE2 },

        {'name': 'slti',      'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'sltui',     'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'addi.w',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'addi.d',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'lu52i.d',   'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'andi',      'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'ori',       'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'xori',      'feature': CF_CHG1 | CF_USE2 | CF_USE3 },

        {'name': 'csrrd',     'feature': CF_CHG1 | CF_USE2 },
        {'name': 'csrwr',     'feature': CF_CHG1 | CF_USE2 },
        {'name': 'csrxchg',   'feature': CF_CHG1 | CF_USE2 | CF_USE3 },

        {'name': 'cacop',     'feature': CF_USE1 | CF_USE2 | CF_USE3 },
        {'name': 'lddir',     'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'ldpte',     'feature': CF_USE1 | CF_USE2 },

        {'name': 'iocsrrd.b', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'iocsrrd.h', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'iocsrrd.w', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'iocsrrd.d', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'iocsrwr.b', 'feature': CF_USE1 | CF_USE2 },
        {'name': 'iocsrwr.h', 'feature': CF_USE1 | CF_USE2 },
        {'name': 'iocsrwr.w', 'feature': CF_USE1 | CF_USE2 },
        {'name': 'iocsrwr.d', 'feature': CF_USE1 | CF_USE2 },
        {'name': 'tlbclr',    'feature': 0 },
        {'name': 'tlbflush',  'feature': 0 },
        {'name': 'tlbsrch',   'feature': 0 },
        {'name': 'tlbrd',     'feature': 0 },
        {'name': 'tlbwr',     'feature': 0 },
        {'name': 'tlbfill',   'feature': 0 },
        {'name': 'ertn',      'feature': 0 },
        {'name': 'idle',      'feature': CF_USE1 },
        {'name': 'invtlb',    'feature': CF_USE1 | CF_USE2 | CF_USE3 },

        {'name': 'fmadd.s',   'feature': CF_CHG1 | CF_USE2 | CF_CHG3 | CF_USE4 },
        {'name': 'fmadd.d',   'feature': CF_CHG1 | CF_USE2 | CF_CHG3 | CF_USE4 },
        {'name': 'fmsub.s',   'feature': CF_CHG1 | CF_USE2 | CF_CHG3 | CF_USE4 },
        {'name': 'fmsub.d',   'feature': CF_CHG1 | CF_USE2 | CF_CHG3 | CF_USE4 },
        {'name': 'fnmadd.s',  'feature': CF_CHG1 | CF_USE2 | CF_CHG3 | CF_USE4 },
        {'name': 'fnmadd.d',  'feature': CF_CHG1 | CF_USE2 | CF_CHG3 | CF_USE4 },
        {'name': 'fnmsub.s',  'feature': CF_CHG1 | CF_USE2 | CF_CHG3 | CF_USE4 },
        {'name': 'fnmsub.d',  'feature': CF_CHG1 | CF_USE2 | CF_CHG3 | CF_USE4 },
        # fcmp.{cond}.{s,d}
        {'name': 'fsel',      'feature': CF_CHG1 | CF_USE2 | CF_CHG3 | CF_USE4 },

        {'name': 'addu16i.d', 'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'lu12i.w',   'feature': CF_CHG1 | CF_USE2 },
        {'name': 'lu32i.d',   'feature': CF_CHG1 | CF_USE2 },
        {'name': 'pcaddi',    'feature': CF_CHG1 | CF_USE2 },
        {'name': 'pcalau12i', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'pcaddu12i', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'pcaddu18i', 'feature': CF_CHG1 | CF_USE2 },

        {'name': 'll.w',      'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'sc.w',      'feature': CF_USE1 | CF_USE2 | CF_USE3 },
        {'name': 'll.d',      'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'sc.d',      'feature': CF_USE1 | CF_USE2 | CF_USE3 },
        {'name': 'ldptr.w',   'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'stptr.w',   'feature': CF_USE1 | CF_USE2 | CF_USE3 },
        {'name': 'ldptr.d',   'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'stptr.d',   'feature': CF_USE1 | CF_USE2 | CF_USE3 },

        {'name': 'ld.b',      'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'ld.h',      'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'ld.w',      'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'ld.d',      'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'st.b',      'feature': CF_USE1 | CF_USE2 | CF_USE3 },
        {'name': 'st.h',      'feature': CF_USE1 | CF_USE2 | CF_USE3 },
        {'name': 'st.w',      'feature': CF_USE1 | CF_USE2 | CF_USE3 },
        {'name': 'st.d',      'feature': CF_USE1 | CF_USE2 | CF_USE3 },
        {'name': 'ld.bu',     'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'ld.hu',     'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'ld.wu',     'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'preld',     'feature': CF_USE1 | CF_USE2 | CF_USE3 },
        {'name': 'fld.s',     'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'fst.s',     'feature': CF_USE1 | CF_USE2 | CF_USE3 },
        {'name': 'fld.d',     'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'fst.d',     'feature': CF_USE1 | CF_USE2 | CF_USE3 },

        {'name': 'ldx.b',     'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'ldx.h',     'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'ldx.w',     'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'ldx.d',     'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'stx.b',     'feature': CF_USE1 | CF_USE2 | CF_USE3 },
        {'name': 'stx.h',     'feature': CF_USE1 | CF_USE2 | CF_USE3 },
        {'name': 'stx.w',     'feature': CF_USE1 | CF_USE2 | CF_USE3 },
        {'name': 'stx.d',     'feature': CF_USE1 | CF_USE2 | CF_USE3 },
        {'name': 'ldx.bu',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'ldx.hu',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'ldx.wu',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'preldx',    'feature': CF_USE1 | CF_USE2 | CF_USE3 },
        {'name': 'fldx.s',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'fldx.d',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'fstx.s',    'feature': CF_USE1 | CF_USE2 | CF_USE3 },
        {'name': 'fstx.d',    'feature': CF_USE1 | CF_USE2 | CF_USE3 },

        {'name': 'sc.q',      'feature': CF_USE1 | CF_USE2 | CF_USE3 },
        {'name': 'llacq.w',   'feature': CF_USE1 | CF_USE2 },
        {'name': 'screl.w',   'feature': CF_USE1 | CF_USE2 },
        {'name': 'llacq.d',   'feature': CF_USE1 | CF_USE2 },
        {'name': 'screl.d',   'feature': CF_USE1 | CF_USE2 },
        # am*
        {'name': 'dbar',      'feature': CF_USE1 },
        {'name': 'ibar',      'feature': CF_USE1 },
        {'name': 'fldgt.s',   'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'fldgt.d',   'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'fldle.s',   'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'fldle.d',   'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'fstgt.s',   'feature': CF_USE1 | CF_USE2 | CF_USE3 },
        {'name': 'fstgt.d',   'feature': CF_USE1 | CF_USE2 | CF_USE3 },
        {'name': 'fstle.s',   'feature': CF_USE1 | CF_USE2 | CF_USE3 },
        {'name': 'fstle.d',   'feature': CF_USE1 | CF_USE2 | CF_USE3 },
        {'name': 'ldgt.b',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'ldgt.h',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'ldgt.w',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'ldgt.d',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'ldle.b',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'ldle.h',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'ldle.w',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'ldle.d',    'feature': CF_CHG1 | CF_USE2 | CF_USE3 },
        {'name': 'stgt.b',    'feature': CF_USE1 | CF_USE2 | CF_USE3 },
        {'name': 'stgt.h',    'feature': CF_USE1 | CF_USE2 | CF_USE3 },
        {'name': 'stgt.w',    'feature': CF_USE1 | CF_USE2 | CF_USE3 },
        {'name': 'stgt.d',    'feature': CF_USE1 | CF_USE2 | CF_USE3 },
        {'name': 'stle.b',    'feature': CF_USE1 | CF_USE2 | CF_USE3 },
        {'name': 'stle.h',    'feature': CF_USE1 | CF_USE2 | CF_USE3 },
        {'name': 'stle.w',    'feature': CF_USE1 | CF_USE2 | CF_USE3 },
        {'name': 'stle.d',    'feature': CF_USE1 | CF_USE2 | CF_USE3 },

        # branch
        {'name': 'beqz',      'feature': CF_USE1 | CF_USE2 | CF_JUMP },
        {'name': 'bnez',      'feature': CF_USE1 | CF_USE2 | CF_JUMP },
        {'name': 'bceqz',     'feature': CF_USE1 | CF_USE2 | CF_JUMP },
        {'name': 'bcnez',     'feature': CF_USE1 | CF_USE2 | CF_JUMP },
        {'name': 'jirl',      'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_CALL },
        {'name': 'b',         'feature': CF_USE1 | CF_USE2 | CF_JUMP | CF_STOP },
        {'name': 'bl',        'feature': CF_USE1 | CF_USE2 | CF_CALL },
        {'name': 'beq',       'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP },
        {'name': 'bne',       'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP },
        {'name': 'blt',       'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP },
        {'name': 'bge',       'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP },
        {'name': 'bltu',      'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP },
        {'name': 'bgeu',      'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_JUMP },

        # TODO: LSX (Loongson SIMD EXtension)

        # TODO: LASX (Loongson Advanced SIMD EXtension)

        # TODO: LVZ (Loongson VirtualiZation)

        # TODO: LBT (Loongson Binary Translation)
        {'name': 'movgr2scr', 'feature': CF_CHG1 | CF_USE2 },
        {'name': 'movscr2gr', 'feature': CF_CHG1 | CF_USE2 },

        # aliases
        {'name': 'move',      'feature': CF_USE1 | CF_USE2 },
        {'name': 'jr',        'feature': CF_USE1 | CF_JUMP | CF_STOP },
        {'name': 'li.w',      'feature': CF_CHG1 | CF_USE2 },
        {'name': 'li.d',      'feature': CF_CHG1 | CF_USE2 },
        {'name': 'nop',       'feature': 0 }
    ]

    # icode of the first instruction
    instruc_start = 0

    def maptbl_icode(self, tab):
        for i, s in enumerate(tab):
            tab[i] = self.name2icode[s]

    def mapdict_icode(self, tab):
        for i, s in tab.items():
            tab[i] = self.name2icode[s]

    def init_instructions(self):

        fcmp_names = ['af', 'lt', 'eq', 'le', 'un',
            'ult', 'ueq', 'ule', 'ne', 'or', 'une']

        for t in ['.s', '.d']:
            for n in fcmp_names:
                for m in ['c', 's']: # quiet, signal
                    name = 'fcmp.' + m + n + t
                    self.instruc.append({'name': name, 'feature': CF_CHG1 | CF_USE2 | CF_USE3 })

        for i in range(0x30, 0x64):
            name = self.maptbl_atomic_mem[i]
            self.instruc.append({'name': name, 'feature': CF_CHG1 | CF_USE2 | CF_USE3 })

        self.name2icode = {}
        for i, x in enumerate(self.instruc):
            self.name2icode[x['name']] = i

        # icode of the last instruction + 1
        self.instruc_end = len(self.instruc)

        self.maptbl_icode(self.maptbl0)
        self.maptbl_icode(self.maptbl_arith)
        self.maptbl_icode(self.maptbl_shift_imm)
        self.maptbl_icode(self.maptbl_arith_imm)
        self.maptbl_icode(self.maptbl_pcadd)
        self.maptbl_icode(self.maptbl_mem14)
        self.maptbl_icode(self.maptbl_mem12)
        self.maptbl_icode(self.maptbl_memx)
        self.maptbl_icode(self.maptbl_privileged)
        self.maptbl_icode(self.maptbl_branch)
        self.maptbl_icode(self.maptbl_atomic_mem_2f)
        self.mapdict_icode(self.maptbl_float3)
        self.mapdict_icode(self.maptbl_float2)
        self.mapdict_icode(self.maptbl_float4)
        self.mapdict_icode(self.maptbl_fcmp)
        self.mapdict_icode(self.maptbl_atomic_mem)

    # ----------------------------------------------------------------------

    # Registers definition
    reg_names = [
        # General purpose registers
        # r0: fixed to zero
        # r1: RA (return address)
        # r3: SP (stack pointer)
        # r4..r11: function args
        # r4: return value
        # r11: syscall number
        # r22: FP (frame pointer)
        "zero", "ra", "r2",  "sp",  "a0",  "a1",  "a2",  "a3",
        "a4",  "a5",  "a6",  "a7",  "r12", "r13", "r14", "r15",
        "r16", "r17", "r18", "r19", "r20", "r21", "fp",  "r23",
        "r24", "r25", "r26", "r27", "r28", "r29", "r30", "r31",

        # Floating point registers
        "f0",  "f1",  "f2",  "f3",  "f4",  "f5",  "f6",  "f7",
        "f8",  "f9",  "f10", "f11", "f12", "f13", "f14", "f15",
        "f16", "f17", "f18", "f19", "f20", "f21", "f22", "f23",
        "f24", "f25", "f26", "f27", "f28", "f29", "f30", "f31",

        # Condition flag registers
        "fcc0", "fcc1", "fcc2", "fcc3", "fcc4", "fcc5", "fcc6", "fcc7",

        # Floating-point Control and Status Registers
        "fcsr0", "fcsr1", "fcsr2", "fcsr3",

        # LSX 128-bit vector registers
        "vr0",  "vr1",  "vr2",  "vr3",  "vr4",  "vr5",  "vr6",  "vr7",
        "vr8",  "vr9",  "vr10", "vr11", "vr12", "vr13", "vr14", "vr15",
        "vr16", "vr17", "vr18", "vr19", "vr20", "vr21", "vr22", "vr23",
        "vr24", "vr25", "vr26", "vr27", "vr28", "vr29", "vr30", "vr31",

        # LASX 256-bit vector registers
        "xr0",  "xr1",  "xr2",  "xr3",  "xr4",  "xr5",  "xr6",  "xr7",
        "xr8",  "xr9",  "xr10", "xr11", "xr12", "xr13", "xr14", "xr15",
        "xr16", "xr17", "xr18", "xr19", "xr20", "xr21", "xr22", "xr23",
        "xr24", "xr25", "xr26", "xr27", "xr28", "xr29", "xr30", "xr31",

        # LBT
        "scr0", "scr1", "scr2", "scr3",

        # Fake segment registers
        "CS", "DS"
    ]

    def init_registers(self):
        self.ireg_f0 = self.reg_names.index("f0")
        self.ireg_fcc0 = self.reg_names.index("fcc0")
        self.ireg_fcsr0 = self.reg_names.index("fcsr0")
        self.ireg_vr0 = self.reg_names.index("vr0")
        self.ireg_xr0 = self.reg_names.index("xr0")
        self.ireg_scr0 = self.reg_names.index("scr0")

        # number of CS register
        self.reg_code_sreg = self.reg_names.index("CS")

        # number of DS register
        self.reg_data_sreg = self.reg_names.index("DS")

        # Segment register information (use virtual CS and DS registers if your
        # processor doesn't have segment registers):
        self.reg_first_sreg = self.reg_code_sreg
        self.reg_last_sreg  = self.reg_data_sreg

    # ----------------------------------------------------------------------
    def __init__(self):
        processor_t.__init__(self)
        self.init_instructions()
        self.init_registers()

# ----------------------------------------------------------------------
# Every processor module script must provide this function.
# It should return a new instance of a class derived from processor_t
def PROCESSOR_ENTRY():
    return loong64_processor_t()
