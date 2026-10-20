//! T32 outside floating point and SIMD: the 16-bit instructions and the 32-bit
//! Thumb-2 ones — data processing, loads and stores, branches, IT, status
//! registers, hints, barriers and the coprocessor instructions.
//!
//! The sections follow the T32 encoding tables of the Arm Architecture
//! Reference Manual. What is printed, and which encodings are refused, follow
//! LLVM's disassembler: an UNPREDICTABLE encoding that LLVM still names is
//! named here too, and one it refuses comes out as `.inst`.
//!
//! Most T32 instructions carry no condition of their own: an IT block lends
//! them one, which `it` brings in (-1 outside a block). LLVM prints it after the
//! mnemonic and before a `.w` (`ldrne.w`), and the 16-bit data-processing
//! instructions lose their `s` inside a block, where they do not set the flags.

use super::a32::{banked, cpsie_flags, msr_mask, BARRIER_OPTIONS};
use super::types::*;

/* ------------------------------------------------------------------ *
 * Building instructions
 * ------------------------------------------------------------------ */

/// The condition suffix an IT block gives: `eq`…`le`, nothing for al, `<und>` for the 15 an `it al` block's else slots get.
#[inline]
fn cond_suffix(it: i32) -> &'static str {
    if it < 0 {
        ""
    } else if it == 15 {
        "<und>"
    } else {
        cond_text(it)
    }
}

/// An instruction that takes the IT block's condition: `base` before it, `q`
/// (`.w`) after it. A conditional one also reads the flags.
#[inline]
fn mk(it: i32, size: u8, base: &str, q: &str, ops: &[Op], f: u32) -> Insn {
    let mut m = Mn::from(base);
    // Most instructions have neither: each push is a call to memcpy.
    if it >= 0 {
        m.push(cond_suffix(it));
    }
    if !q.is_empty() {
        m.push(q);
    }
    let mut insn = Insn::new(m, ops, f, size);
    if it >= 0 && it != 14 {
        insn.f |= f::COND | f::READS_FLAGS;
        if it != 15 {
            insn.cond = cond_at(it);
        }
    }
    insn
}

/// An instruction LLVM prints without the IT block's condition (cbz, b<c>, cps, setend, crc32…).
#[inline]
fn plain(size: u8, m: &str, ops: &[Op], f: u32) -> Insn {
    Insn::new(Mn::from(m), ops, f, size)
}

#[inline]
fn none(w: u32) -> Insn {
    unknown(w, 4, true)
}

#[inline]
fn none16(hw: u32) -> Insn {
    unknown(hw, 2, true)
}

#[allow(non_snake_case)]
#[inline(always)]
fn R(n: u32) -> Op {
    reg(r(n), false)
}

#[inline(always)]
fn named(name: &str) -> Op {
    reg_str(name)
}

/// `a` + `b`, for mnemonics put together from parts.
#[inline]
fn cat2(a: &str, b: &str) -> Mn {
    cat!(Mn; a, b)
}

#[inline]
fn pc_aligned(pc: i64) -> u32 {
    (pc as u32).wrapping_add(4) & !3
}

/// `(base + off) >>> 0`
#[inline]
fn addr(base: u32, off: i64) -> i64 {
    base.wrapping_add(off as u32) as i64
}

/// A memory operand; `t` is LLVM's whole bracketed text.
#[inline]
fn mem(base: u32, t: MemText, mode: Mode, off: Option<i64>, index: Option<u32>) -> Op {
    Op::Mem(Mem { base: r(base), t, off, index: index.map(r), mode })
}

/// `[r1, #0x4]`, `[r1]` for 0: the T16 immediate forms, imm12 and the exclusive ones (hex).
#[inline]
fn mem_hex(rn: u32, imm: i64) -> Op {
    let t = if imm != 0 { cat!(MemText; "[", r(rn), ", #", Hex(imm), "]") } else { cat!(MemText; "[", r(rn), "]") };
    mem(rn, t, Mode::Off, Some(imm), None)
}

/// `[r1, #-8]`, `[r1, #8]`, `[r1]`: the T2 8-bit forms (decimal); `#-0` is kept when the U bit is clear.
#[inline]
fn mem_dec(rn: u32, imm: i64, add: bool, always: bool) -> MemText {
    if !add {
        return cat!(MemText; "[", r(rn), ", #-", Dec(imm), "]");
    }
    if imm != 0 || always {
        cat!(MemText; "[", r(rn), ", #", Dec(imm), "]")
    } else {
        cat!(MemText; "[", r(rn), "]")
    }
}

/// `[pc, #0x10]`, `[pc, #-0x10]`, `[pc, #-0x0]`: LLVM's literal operand (printThumbLdrLabelOperand).
#[inline]
fn mem_literal(imm: i64, add: bool) -> Op {
    mem(15, cat!(MemText; "[pc, #", if add { "" } else { "-" }, Hex(imm), "]"), Mode::Off, Some(if add { imm } else { -imm }), None)
}

/// `[r1, r2]`, `[r1, r2, lsl #2]`: a register offset.
#[inline]
fn mem_reg(rn: u32, rm: u32, sh: u32) -> Op {
    let t = if sh != 0 { cat!(MemText; "[", r(rn), ", ", r(rm), ", lsl #", Dec(sh as i64), "]") } else { cat!(MemText; "[", r(rn), ", ", r(rm), "]") };
    mem(rn, t, Mode::Off, None, Some(rm))
}

const SHIFTS: [&str; 4] = ["lsl", "lsr", "asr", "ror"];

/// A register with a constant shift, as t2_so_reg prints it: nothing for lsl #0, #32 for lsr/asr #0, rrx for ror #0.
#[inline]
fn so_reg(ops: &mut Ops, rm: u32, ty: u32, amount: u32) {
    ops.push(R(rm));
    if ty == 0 && amount == 0 {
        return;
    }
    if ty == 3 && amount == 0 {
        ops.push(shift("rrx"));
        return;
    }
    ops.push(Op::Shift(cat!(ShiftText; SHIFTS[ty as usize], " #", Dec(if amount == 0 { 32 } else { amount } as i64))));
}

/// ThumbExpandImm: an 8-bit value repeated across the word, or rotated into place.
fn expand_imm(imm12: u32) -> u32 {
    if imm12 >> 10 == 0 {
        let b = imm12 & 0xff;
        return match (imm12 >> 8) & 3 {
            0 => b,
            1 => (b << 16) | b,
            2 => (b << 24) | (b << 8),
            _ => b * 0x01010101,
        };
    }
    let unrot = 0x80 | (imm12 & 0x7f);
    let rot = (imm12 >> 7) & 31;
    unrot.rotate_right(rot)
}

/// Load and store flags with the size moved; a load to pc is an indirect branch.
#[inline]
fn ld_flags(rt: u32) -> u32 {
    if rt == 15 {
        f::LOAD | f::BRANCH | f::INDIRECT
    } else {
        f::LOAD
    }
}

/// Flags of a data-processing instruction writing `rd`: writing pc branches.
#[inline]
fn dp_flags(rd: u32, sets_flags: bool) -> u32 {
    (if sets_flags { f::SETS_FLAGS } else { 0 }) | if rd == 15 { f::BRANCH | f::INDIRECT } else { 0 }
}

/* ------------------------------------------------------------------ *
 * 16-bit instructions
 * ------------------------------------------------------------------ */

const DP16: [&str; 16] = ["and", "eor", "lsl", "lsr", "asr", "adc", "sbc", "ror", "tst", "rsb", "cmp", "cmn", "orr", "mul", "bic", "mvn"];
const DP16S: [&str; 16] = ["ands", "eors", "lsls", "lsrs", "asrs", "adcs", "sbcs", "rors", "tsts", "rsbs", "cmps", "cmns", "orrs", "muls", "bics", "mvns"];
const LDST16: [&str; 8] = ["str", "strh", "strb", "ldrsb", "ldr", "ldrh", "ldrb", "ldrsh"];
const LDST16_BYTES: [u32; 8] = [4, 2, 1, 1, 4, 2, 1, 2];
const HINTS16: [&str; 6] = ["nop", "yield", "wfe", "wfi", "sev", "sevl"];

pub fn decode_t16(hw: u32, pc: i64, it: i32) -> Insn {
    let in_it = it >= 0;
    // Inside an IT block the 16-bit data-processing instructions do not set the flags, and LLVM drops their `s`.
    let s = !in_it;
    let sf = if in_it { 0 } else { f::SETS_FLAGS };
    let rd = hw & 7;
    let rn = (hw >> 3) & 7;
    match hw >> 11 {
        // Shift by an immediate; lsl #0 is the flag-setting move LLVM calls movs even inside an IT block.
        0x00 => {
            let imm = (hw >> 6) & 31;
            if imm == 0 {
                return plain(2, "movs", &[R(rd), R(rn)], f::SETS_FLAGS);
            }
            mk(it, 2, if s { "lsls" } else { "lsl" }, "", &[R(rd), R(rn), imm_hex(imm as i64)], sf)
        }
        0x01 | 0x02 => {
            let imm = match (hw >> 6) & 31 {
                0 => 32,
                v => v,
            };
            let m = match (hw >> 11 == 1, s) {
                (true, true) => "lsrs",
                (true, false) => "lsr",
                (false, true) => "asrs",
                (false, false) => "asr",
            };
            mk(it, 2, m, "", &[R(rd), R(rn), imm_hex(imm as i64)], sf)
        }
        // Add and subtract, three low registers or a 3-bit immediate.
        0x03 => {
            let m = match (bit(hw, 9) != 0, s) {
                (true, true) => "subs",
                (true, false) => "sub",
                (false, true) => "adds",
                (false, false) => "add",
            };
            let third = if bit(hw, 10) != 0 { imm_hex(((hw >> 6) & 7) as i64) } else { R((hw >> 6) & 7) };
            mk(it, 2, m, "", &[R(rd), R(rn), third], sf)
        }
        // Move, compare, add and subtract with an 8-bit immediate.
        0x04..=0x07 => {
            let rdn = (hw >> 8) & 7;
            let op = (hw >> 11) & 3;
            let imm = imm_hex((hw & 0xff) as i64);
            if op == 1 {
                return mk(it, 2, "cmp", "", &[R(rdn), imm], f::SETS_FLAGS);
            }
            let m = if s { ["movs", "s", "adds", "subs"] } else { ["mov", "", "add", "sub"] }[op as usize];
            mk(it, 2, m, "", &[R(rdn), imm], sf)
        }
        0x08 => {
            if bit(hw, 10) == 0 {
                return data_processing16(hw, it, s, sf);
            }
            special16(hw, it)
        }
        // ldr rt, [pc, #imm]: a literal word.
        0x09 => {
            let imm = ((hw & 0xff) * 4) as i64;
            let target = addr(pc_aligned(pc), imm);
            mk(it, 2, "ldr", "", &[R((hw >> 8) & 7), mem(15, cat!(MemText; "[pc, #", Hex(imm), "]"), Mode::Off, Some(imm), None)], f::LOAD).target(target).bytes(4)
        }
        // Loads and stores with a register offset.
        0x0a | 0x0b => {
            let op = (hw >> 9) & 7;
            let rm = (hw >> 6) & 7;
            let m = LDST16[op as usize];
            mk(it, 2, m, "", &[R(rd), mem_reg(rn, rm, 0)], if op < 3 { f::STORE } else { f::LOAD }).bytes(LDST16_BYTES[op as usize])
        }
        // Loads and stores with a 5-bit immediate offset: words scale it by 4, halfwords by 2.
        0x0c..=0x11 => {
            let load = bit(hw, 11) != 0;
            let kind = if hw >> 13 == 3 {
                if bit(hw, 12) != 0 {
                    1
                } else {
                    4
                }
            } else {
                2
            };
            let imm = (((hw >> 6) & 31) * kind) as i64;
            let m = match (load, kind) {
                (true, 1) => "ldrb",
                (true, 2) => "ldrh",
                (true, _) => "ldr",
                (false, 1) => "strb",
                (false, 2) => "strh",
                (false, _) => "str",
            };
            mk(it, 2, m, "", &[R(rd), mem_hex(rn, imm)], if load { f::LOAD } else { f::STORE }).bytes(kind)
        }
        // Loads and stores relative to sp.
        0x12 | 0x13 => {
            let load = bit(hw, 11) != 0;
            mk(it, 2, if load { "ldr" } else { "str" }, "", &[R((hw >> 8) & 7), mem_hex(13, ((hw & 0xff) * 4) as i64)], if load { f::LOAD } else { f::STORE }).bytes(4)
        }
        // adr rd, #imm (decimal, as LLVM prints it) and add rd, sp, #imm.
        0x14 => {
            let imm = ((hw & 0xff) * 4) as i64;
            mk(it, 2, "adr", "", &[R((hw >> 8) & 7), imm_dec(imm)], 0).target(addr(pc_aligned(pc), imm))
        }
        0x15 => mk(it, 2, "add", "", &[R((hw >> 8) & 7), R(13), imm_hex(((hw & 0xff) * 4) as i64)], 0),
        0x16 | 0x17 => misc16(hw, pc, it),
        // stm rn!, {…} and ldm rn{!}, {…}: the load writes back only when rn is not in the list.
        0x18 | 0x19 => {
            let base = (hw >> 8) & 7;
            let mask = hw & 0xff;
            if mask == 0 {
                return none16(hw);
            }
            let regs = Op::List(reg_list(mask));
            if bit(hw, 11) == 0 {
                return mk(it, 2, "stm", "", &[reg(r(base), true), regs], f::STORE).bytes(4);
            }
            mk(it, 2, "ldm", "", &[reg(r(base), mask & (1 << base) == 0), regs], f::LOAD).bytes(4)
        }
        // b<cond>, udf and svc.
        0x1a | 0x1b => {
            let c = (hw >> 8) & 15;
            let imm8 = hw & 0xff;
            if c == 14 {
                // LLVM names two udf values after their use: the trap and the divide-by-zero break.
                if imm8 == 0xfe {
                    return plain(2, "trap", &[], f::TRAP);
                }
                if imm8 == 0xf9 {
                    return plain(2, "__brkdiv0", &[], f::TRAP);
                }
                return plain(2, "udf", &[imm_hex(imm8 as i64)], f::TRAP);
            }
            if c == 15 {
                return mk(it, 2, "svc", "", &[imm_hex(imm8 as i64)], 0);
            }
            let target = addr(pc as u32, 4 + sext(imm8, 8) as i64 * 2);
            cond_branch(2, c as i32, it, "", target)
        }
        0x1c => {
            let target = addr(pc as u32, 4 + sext(hw & 0x7ff, 11) as i64 * 2);
            mk(it, 2, "b", "", &[label(target)], f::BRANCH).target(target)
        }
        _ => none16(hw),
    }
}

/// b<cond>: inside an IT block (UNPREDICTABLE) LLVM puts the block's condition
/// in place of the encoded one, and prints that.
fn cond_branch(size: u8, c: i32, it: i32, q: &str, target: i64) -> Insn {
    let shown = if it >= 0 { it } else { c };
    let mut insn = plain(size, &cat!(Mn; "b", cond_suffix(shown), q), &[label(target)], f::BRANCH).target(target);
    if shown != 14 {
        insn.f |= f::COND | f::READS_FLAGS;
        if shown != 15 {
            insn.cond = cond_at(shown);
        }
    }
    insn
}

/// 010000: the two-register data-processing instructions.
fn data_processing16(hw: u32, it: i32, s: bool, sf: u32) -> Insn {
    let op = (hw >> 6) & 15;
    let rdn = hw & 7;
    let rm = (hw >> 3) & 7;
    let name = if s { DP16S[op as usize] } else { DP16[op as usize] };
    match op {
        // tst, cmp, cmn
        8 | 10 | 11 => mk(it, 2, DP16[op as usize], "", &[R(rdn), R(rm)], f::SETS_FLAGS),
        // rsbs rd, rn, #0
        9 => mk(it, 2, name, "", &[R(rdn), R(rm), imm_text(0.0, "#0")], sf),
        // muls rd, rn, rd
        13 => mk(it, 2, name, "", &[R(rdn), R(rm), R(rdn)], sf),
        // adc, sbc, ror
        5..=7 => mk(it, 2, name, "", &[R(rdn), R(rm)], sf | if op == 7 { 0 } else { f::READS_FLAGS }),
        _ => mk(it, 2, name, "", &[R(rdn), R(rm)], sf),
    }
}

/// 010001: add, cmp and mov on any registers, bx and blx.
fn special16(hw: u32, it: i32) -> Insn {
    let rdn = (hw & 7) | (bit(hw, 7) << 3);
    let rm = (hw >> 3) & 15;
    match (hw >> 8) & 3 {
        0 => {
            if rm == 13 {
                return mk(it, 2, "add", "", &[R(rdn), R(13), R(rdn)], dp_flags(rdn, false));
            }
            if rdn == 13 {
                return mk(it, 2, "add", "", &[R(13), R(rm)], 0);
            }
            mk(it, 2, "add", "", &[R(rdn), R(rm)], dp_flags(rdn, false))
        }
        1 => mk(it, 2, "cmp", "", &[R(rdn), R(rm)], f::SETS_FLAGS),
        2 => {
            let mut f = 0;
            if rdn == 15 {
                f = if rm == 14 { f::BRANCH | f::RET | f::INDIRECT } else { f::BRANCH | f::INDIRECT };
            }
            mk(it, 2, "mov", "", &[R(rdn), R(rm)], f)
        }
        _ => {
            if bit(hw, 7) == 0 {
                return mk(it, 2, "bx", "", &[R(rm)], if rm == 14 { f::BRANCH | f::RET | f::INDIRECT } else { f::BRANCH | f::INDIRECT });
            }
            if hw & 7 != 0 {
                return none16(hw);
            }
            mk(it, 2, "blx", "", &[R(rm)], f::CALL | f::INDIRECT)
        }
    }
}

/// 1011: the miscellaneous 16-bit instructions.
fn misc16(hw: u32, pc: i64, it: i32) -> Insn {
    let rd = hw & 7;
    let rm = (hw >> 3) & 7;
    match (hw >> 8) & 15 {
        0x0 => {
            let imm = ((hw & 0x7f) * 4) as i64;
            mk(it, 2, if bit(hw, 7) != 0 { "sub" } else { "add" }, "", &[R(13), imm_hex(imm)], 0)
        }
        0x1 | 0x3 | 0x9 | 0xb => {
            // cbz/cbnz rn, label: always forward, and never conditional on an IT block.
            let off = (((bit(hw, 9) << 5) | ((hw >> 3) & 31)) * 2) as i64;
            let target = addr(pc as u32, 4 + off);
            plain(2, if bit(hw, 11) != 0 { "cbnz" } else { "cbz" }, &[R(rd), label(target)], f::BRANCH | f::COND).target(target)
        }
        0x2 => mk(it, 2, ["sxth", "sxtb", "uxth", "uxtb"][((hw >> 6) & 3) as usize], "", &[R(rd), R(rm)], 0),
        0x4 | 0x5 => {
            let mask = (hw & 0xff) | (bit(hw, 8) << 14);
            if mask == 0 {
                return none16(hw);
            }
            mk(it, 2, "push", "", &[Op::List(reg_list(mask))], f::STORE).bytes(4)
        }
        0x6 => {
            let op = (hw >> 5) & 7;
            if op == 0 {
                return plain(2, "setpan", &[imm_hex(bit(hw, 3) as i64)], 0);
            }
            if op == 2 && bit(hw, 4) != 0 && hw & 7 == 0 {
                return plain(2, "setend", &[text(if bit(hw, 3) != 0 { "be" } else { "le" })], 0);
            }
            if op == 3 && bit(hw, 3) == 0 {
                let flags = cpsie_flags(bit(hw, 2) != 0, bit(hw, 1) != 0, bit(hw, 0) != 0);
                return plain(2, if bit(hw, 4) != 0 { "cpsid" } else { "cpsie" }, &[flags], 0);
            }
            none16(hw)
        }
        0xa => {
            let op = (hw >> 6) & 3;
            if op == 2 {
                return plain(2, "hlt", &[imm_hex((hw & 0x3f) as i64)], f::TRAP);
            }
            mk(it, 2, ["rev", "rev16", "", "revsh"][op as usize], "", &[R(rd), R(rm)], 0)
        }
        0xc | 0xd => {
            let mask = (hw & 0xff) | (bit(hw, 8) << 15);
            if mask == 0 {
                return none16(hw);
            }
            let f = if bit(hw, 8) != 0 { f::LOAD | f::BRANCH | f::RET | f::INDIRECT } else { f::LOAD };
            mk(it, 2, "pop", "", &[Op::List(reg_list(mask))], f).bytes(4)
        }
        0xe => plain(2, "bkpt", &[imm_hex((hw & 0xff) as i64)], f::TRAP),
        0xf => {
            let mask = hw & 15;
            if mask != 0 {
                return it_instruction(hw);
            }
            let op = (hw >> 4) & 15;
            if op < 6 {
                return mk(it, 2, HINTS16[op as usize], "", &[], 0);
            }
            mk(it, 2, "hint", "", &[imm_hex(op as i64)], 0)
        }
        _ => none16(hw),
    }
}

/// it{t|e}{t|e}{t|e} cond. A first condition of 15 is read as al, as LLVM does,
/// so the else slots of such a block get the condition 15 that prints `<und>`.
fn it_instruction(hw: u32) -> Insn {
    let mask = hw & 15;
    let mut first = (hw >> 4) & 15;
    if first == 15 {
        first = 14;
    }
    let m = cat!(Mn; "it", it_suffix(first, mask));
    plain(2, &m, &[text(if first == 14 { "al" } else { CONDS[first as usize] })], 0).it(it_conditions(first, mask))
}

/* ------------------------------------------------------------------ *
 * 32-bit instructions
 * ------------------------------------------------------------------ */

pub fn decode_t32_base(word: u32, pc: i64, it: i32) -> Insn {
    let w = word;
    match (w >> 27) & 3 {
        1 => {
            if bit(w, 26) != 0 {
                return coprocessor(w, it);
            }
            if bit(w, 25) != 0 {
                return dp_shifted_register(w, it);
            }
            if bit(w, 22) != 0 {
                load_store_dual(w, pc, it)
            } else {
                load_store_multiple(w, it)
            }
        }
        2 => {
            if bit(w, 15) != 0 {
                return branches_misc(w, pc, it);
            }
            if bit(w, 25) != 0 {
                dp_plain_immediate(w, pc, it)
            } else {
                dp_modified_immediate(w, it)
            }
        }
        3 => {
            if bit(w, 26) != 0 {
                return coprocessor(w, it);
            }
            match (w >> 23) & 7 {
                0..=3 => load_store(w, pc, it),
                4 | 5 => dp_register(w, it),
                6 => multiply(w, it),
                _ => long_multiply(w, it),
            }
        }
        _ => none(w),
    }
}

/* ------------------------------------------------------------------ *
 * Load and store multiple, srs and rfe
 * ------------------------------------------------------------------ */

fn load_store_multiple(w: u32, it: i32) -> Insn {
    let op = (w >> 23) & 3;
    let wb = bit(w, 21) != 0;
    let load = bit(w, 20) != 0;
    let rn = (w >> 16) & 15;
    if op == 0 || op == 3 {
        let m = if op == 0 { "db" } else { "ia" };
        if load {
            if (w & 0xffff) != 0xc000 {
                return none(w);
            }
            return mk(it, 4, &cat2("rfe", m), "", &[reg(r(rn), wb)], f::BRANCH | f::RET | f::INDIRECT | f::LOAD);
        }
        if rn != 13 || (w & 0xffe0) != 0xc000 {
            return none(w);
        }
        return mk(it, 4, &cat2("srs", m), "", &[reg(r(13), wb), imm_hex((w & 31) as i64)], f::STORE);
    }
    let mask = w & 0xffff;
    // A store list may not hold pc or sp.
    if !load && mask & 0xa000 != 0 {
        return none(w);
    }
    if mask == 0 {
        return none(w);
    }
    let regs = reg_list(mask);
    let many = regs.len() > 1;
    let regs = Op::List(regs);
    if load {
        let mut f = f::LOAD;
        if mask & 0x8000 != 0 {
            f |= if rn == 13 && wb && op == 1 { f::BRANCH | f::RET | f::INDIRECT } else { f::BRANCH | f::INDIRECT };
        }
        if op == 1 && wb && rn == 13 && many {
            return mk(it, 4, "pop", ".w", &[regs], f).bytes(4);
        }
        return mk(it, 4, if op == 1 { "ldm" } else { "ldmdb" }, if op == 1 { ".w" } else { "" }, &[reg(r(rn), wb), regs], f).bytes(4);
    }
    if op == 2 && wb && rn == 13 && many {
        return mk(it, 4, "push", ".w", &[regs], f::STORE).bytes(4);
    }
    mk(it, 4, if op == 1 { "stm" } else { "stmdb" }, if op == 1 { ".w" } else { "" }, &[reg(r(rn), wb), regs], f::STORE).bytes(4)
}

/* ------------------------------------------------------------------ *
 * Load and store dual, exclusive, acquire/release, table branch
 * ------------------------------------------------------------------ */

fn load_store_dual(w: u32, pc: i64, it: i32) -> Insn {
    let p = bit(w, 24);
    let u = bit(w, 23);
    let wb = bit(w, 21);
    let load = bit(w, 20) != 0;
    let rn = (w >> 16) & 15;
    let rt = (w >> 12) & 15;
    let rt2 = (w >> 8) & 15;
    if p != 0 || wb != 0 {
        // ldrd/strd: the offset is a multiple of 4, printed in decimal.
        let imm = ((w & 0xff) * 4) as i64;
        let add = u != 0;
        let f = if load { f::LOAD } else { f::STORE };
        let off = if add { imm } else { -imm };
        let a = if p == 0 {
            mem(rn, cat!(MemText; "[", r(rn), "], #", if add { "" } else { "-" }, Dec(imm)), Mode::Post, Some(off), None)
        } else if wb != 0 {
            mem(rn, cat!(MemText; mem_dec(rn, imm, add, true), "!"), Mode::Pre, Some(off), None)
        } else {
            mem(rn, mem_dec(rn, imm, add, false), Mode::Off, Some(off), None)
        };
        let insn = mk(it, 4, if load { "ldrd" } else { "strd" }, "", &[R(rt), R(rt2), a], f).bytes(4);
        return if rn == 15 { insn.target(addr(pc_aligned(pc), off)) } else { insn };
    }
    if u == 0 {
        // ldrex/strex with an offset (a multiple of 4, hex).
        let imm = ((w & 0xff) * 4) as i64;
        if load {
            if rt2 != 15 {
                return none(w);
            }
            return mk(it, 4, "ldrex", "", &[R(rt), mem_hex(rn, imm)], f::LOAD | f::ATOMIC).bytes(4);
        }
        return mk(it, 4, "strex", "", &[R(rt2), R(rt), mem_hex(rn, imm)], f::STORE | f::ATOMIC).bytes(4);
    }
    let op = (w >> 4) & 15;
    let rd = w & 15;
    let plain_mem = mem(rn, cat!(MemText; "[", r(rn), "]"), Mode::Off, Some(0), None);
    if load {
        if op == 0 || op == 1 {
            // tbb [rn, rm] / tbh [rn, rm, lsl #1]
            if (w & 0xffe0) != 0xf000 {
                return none(w);
            }
            return mk(it, 4, if op != 0 { "tbh" } else { "tbb" }, "", &[mem_reg(rn, rd, op)], f::BRANCH | f::INDIRECT | f::LOAD).bytes(if op != 0 { 2 } else { 1 });
        }
        if rd != 15 {
            return none(w);
        }
        return match op {
            4 | 5 | 12 | 13 => {
                if rt2 != 15 {
                    return none(w);
                }
                let m = cat2(if op & 8 != 0 { "ldaex" } else { "ldrex" }, if op & 1 != 0 { "h" } else { "b" });
                mk(it, 4, &m, "", &[R(rt), plain_mem], f::LOAD | f::ATOMIC).bytes(if op & 1 != 0 { 2 } else { 1 })
            }
            7 | 15 => mk(it, 4, if op & 8 != 0 { "ldaexd" } else { "ldrexd" }, "", &[R(rt), R(rt2), plain_mem], f::LOAD | f::ATOMIC).bytes(4),
            8..=10 => {
                if rt2 != 15 {
                    return none(w);
                }
                mk(it, 4, ["ldab", "ldah", "lda"][(op - 8) as usize], "", &[R(rt), plain_mem], f::LOAD | f::ATOMIC).bytes([1, 2, 4][(op - 8) as usize])
            }
            14 => {
                if rt2 != 15 {
                    return none(w);
                }
                mk(it, 4, "ldaex", "", &[R(rt), plain_mem], f::LOAD | f::ATOMIC).bytes(4)
            }
            _ => none(w),
        };
    }
    match op {
        4 | 5 | 12 | 13 | 14 => {
            if rt2 != 15 {
                return none(w);
            }
            let m = cat2(
                if op & 8 != 0 { "stlex" } else { "strex" },
                if op == 14 {
                    ""
                } else if op & 1 != 0 {
                    "h"
                } else {
                    "b"
                },
            );
            let bytes = if op == 14 {
                4
            } else if op & 1 != 0 {
                2
            } else {
                1
            };
            mk(it, 4, &m, "", &[R(rd), R(rt), plain_mem], f::STORE | f::ATOMIC).bytes(bytes)
        }
        7 | 15 => mk(it, 4, if op & 8 != 0 { "stlexd" } else { "strexd" }, "", &[R(rd), R(rt), R(rt2), plain_mem], f::STORE | f::ATOMIC).bytes(4),
        8..=10 => {
            if rt2 != 15 || rd != 15 {
                return none(w);
            }
            mk(it, 4, ["stlb", "stlh", "stl"][(op - 8) as usize], "", &[R(rt), plain_mem], f::STORE | f::ATOMIC).bytes([1, 2, 4][(op - 8) as usize])
        }
        _ => none(w),
    }
}

/* ------------------------------------------------------------------ *
 * Data processing with a shifted register
 * ------------------------------------------------------------------ */

fn dp_shifted_register(w: u32, it: i32) -> Insn {
    let op = (w >> 21) & 15;
    let s_bit = bit(w, 20) != 0;
    let s = if s_bit { "s" } else { "" };
    let rn = (w >> 16) & 15;
    let rd = (w >> 8) & 15;
    let rm = w & 15;
    let ty = (w >> 4) & 3;
    let amount = (((w >> 12) & 7) << 2) | ((w >> 6) & 3);
    let flags = dp_flags(rd, s_bit);
    // [R(rn), ...shifted] and [R(rd), R(rn), ...shifted]
    let two = |a: u32| -> Ops {
        let mut ops = Ops::new();
        ops.push(R(a));
        so_reg(&mut ops, rm, ty, amount);
        ops
    };
    let three = || -> Ops {
        let mut ops = Ops::new();
        ops.push(R(rd));
        ops.push(R(rn));
        so_reg(&mut ops, rm, ty, amount);
        ops
    };
    match op {
        // and / tst
        0 => {
            if rd == 15 && s_bit {
                return mk(it, 4, "tst", ".w", &two(rn), f::SETS_FLAGS);
            }
            mk(it, 4, &cat2("and", s), ".w", &three(), flags)
        }
        1 => mk(it, 4, &cat2("bic", s), ".w", &three(), flags),
        // orr / mov and the shifts
        2 => {
            if rn != 15 {
                if bit(w, 15) != 0 {
                    return none(w);
                }
                return mk(it, 4, &cat2("orr", s), ".w", &three(), flags);
            }
            move_shift(w, it, rd, rm, ty, amount, s, flags)
        }
        // orn / mvn
        3 => {
            if rn == 15 {
                return mk(it, 4, &cat2("mvn", s), ".w", &two(rd), flags);
            }
            mk(it, 4, &cat2("orn", s), "", &three(), flags)
        }
        // eor / teq
        4 => {
            if rd == 15 && s_bit {
                return mk(it, 4, "teq", ".w", &two(rn), f::SETS_FLAGS);
            }
            mk(it, 4, &cat2("eor", s), ".w", &three(), flags)
        }
        6 => {
            // pkhbt rd, rn, rm{, lsl #n} / pkhtb rd, rn, rm, asr #n
            if s_bit || bit(w, 4) != 0 {
                return none(w);
            }
            let tb = bit(w, 5) != 0;
            let mut ops = Ops::new();
            ops.push(R(rd));
            ops.push(R(rn));
            ops.push(R(rm));
            if tb {
                ops.push(Op::Shift(cat!(ShiftText; "asr #", Dec(if amount != 0 { amount } else { 32 } as i64))));
            } else if amount != 0 {
                ops.push(Op::Shift(cat!(ShiftText; "lsl #", Dec(amount as i64))));
            }
            mk(it, 4, if tb { "pkhtb" } else { "pkhbt" }, "", &ops, 0)
        }
        // add / cmn
        8 => {
            if rd == 15 && s_bit {
                return mk(it, 4, "cmn", ".w", &two(rn), f::SETS_FLAGS);
            }
            mk(it, 4, &cat2("add", s), ".w", &three(), flags)
        }
        10 => mk(it, 4, &cat2("adc", s), ".w", &three(), flags | f::READS_FLAGS),
        11 => mk(it, 4, &cat2("sbc", s), ".w", &three(), flags | f::READS_FLAGS),
        // sub / cmp
        13 => {
            if rd == 15 && s_bit {
                return mk(it, 4, "cmp", ".w", &two(rn), f::SETS_FLAGS);
            }
            mk(it, 4, &cat2("sub", s), ".w", &three(), flags)
        }
        14 => mk(it, 4, &cat2("rsb", s), "", &three(), flags),
        _ => none(w),
    }
}

/// orr with rn = pc: mov.w, the constant shifts (lsl.w…) and rrx.
#[allow(clippy::too_many_arguments)]
fn move_shift(w: u32, it: i32, rd: u32, rm: u32, ty: u32, amount: u32, s: &str, flags: u32) -> Insn {
    if ty == 3 && amount == 0 {
        return mk(it, 4, &cat2("rrx", s), "", &[R(rd), R(rm)], flags | f::READS_FLAGS);
    }
    if bit(w, 15) != 0 {
        return none(w);
    }
    if ty == 0 && amount == 0 {
        let mut f = flags;
        if rd == 15 {
            f = if rm == 14 && s.is_empty() { f::BRANCH | f::RET | f::INDIRECT } else { flags };
        }
        return mk(it, 4, &cat2("mov", s), ".w", &[R(rd), R(rm)], f);
    }
    mk(it, 4, &cat2(SHIFTS[ty as usize], s), ".w", &[R(rd), R(rm), imm_hex(if amount == 0 { 32 } else { amount } as i64)], flags)
}

/* ------------------------------------------------------------------ *
 * Data processing with a modified immediate
 * ------------------------------------------------------------------ */

fn dp_modified_immediate(w: u32, it: i32) -> Insn {
    let op = (w >> 21) & 15;
    let s_bit = bit(w, 20) != 0;
    let s = if s_bit { "s" } else { "" };
    let rn = (w >> 16) & 15;
    let rd = (w >> 8) & 15;
    let imm12 = (bit(w, 26) << 11) | (((w >> 12) & 7) << 8) | (w & 0xff);
    let value = expand_imm(imm12);
    let imm = imm_hex(value as i64);
    let flags = dp_flags(rd, s_bit);
    match op {
        0 => {
            if rd == 15 && s_bit {
                return mk(it, 4, "tst", ".w", &[R(rn), imm], f::SETS_FLAGS);
            }
            mk(it, 4, &cat2("and", s), "", &[R(rd), R(rn), imm], flags)
        }
        1 => mk(it, 4, &cat2("bic", s), "", &[R(rd), R(rn), imm], flags),
        2 => {
            if rn == 15 {
                return mk(it, 4, &cat2("mov", s), ".w", &[R(rd), imm], flags);
            }
            mk(it, 4, &cat2("orr", s), "", &[R(rd), R(rn), imm], flags)
        }
        3 => {
            if rn == 15 {
                return mk(it, 4, &cat2("mvn", s), "", &[R(rd), imm], flags);
            }
            mk(it, 4, &cat2("orn", s), "", &[R(rd), R(rn), imm], flags)
        }
        4 => {
            if rd == 15 && s_bit {
                return mk(it, 4, "teq", ".w", &[R(rn), imm], f::SETS_FLAGS);
            }
            mk(it, 4, &cat2("eor", s), "", &[R(rd), R(rn), imm], flags)
        }
        8 => {
            if rd == 15 && s_bit {
                return mk(it, 4, "cmn", ".w", &[R(rn), imm], f::SETS_FLAGS);
            }
            mk(it, 4, &cat2("add", s), ".w", &[R(rd), R(rn), imm], flags)
        }
        10 => mk(it, 4, &cat2("adc", s), "", &[R(rd), R(rn), imm], flags | f::READS_FLAGS),
        11 => mk(it, 4, &cat2("sbc", s), "", &[R(rd), R(rn), imm], flags | f::READS_FLAGS),
        13 => {
            if rd == 15 && s_bit {
                return mk(it, 4, "cmp", ".w", &[R(rn), imm], f::SETS_FLAGS);
            }
            mk(it, 4, &cat2("sub", s), ".w", &[R(rd), R(rn), imm], flags)
        }
        14 => mk(it, 4, &cat2("rsb", s), ".w", &[R(rd), R(rn), imm], flags),
        _ => none(w),
    }
}

/* ------------------------------------------------------------------ *
 * Data processing with a plain binary immediate
 * ------------------------------------------------------------------ */

fn dp_plain_immediate(w: u32, pc: i64, it: i32) -> Insn {
    let op = (w >> 20) & 31;
    let rn = (w >> 16) & 15;
    let rd = (w >> 8) & 15;
    let imm12 = (bit(w, 26) << 11) | (((w >> 12) & 7) << 8) | (w & 0xff);
    match op {
        0 | 10 => {
            // addw/subw; on pc they are adr.w (decimal), except subw rd, pc, #0.
            let sub = op == 10;
            if rn == 15 && !(sub && imm12 == 0) {
                let off = if sub { -(imm12 as i64) } else { imm12 as i64 };
                return mk(it, 4, "adr", ".w", &[R(rd), imm_dec(off)], 0).target(addr(pc_aligned(pc), off));
            }
            let insn = mk(it, 4, if sub { "subw" } else { "addw" }, "", &[R(rd), R(rn), imm_hex(imm12 as i64)], dp_flags(rd, false));
            if rn == 15 {
                insn.target(pc_aligned(pc) as i64)
            } else {
                insn
            }
        }
        4 | 12 => {
            let imm16 = (rn << 12) | imm12;
            mk(it, 4, if op == 4 { "movw" } else { "movt" }, "", &[R(rd), imm_hex(imm16 as i64)], 0)
        }
        16 | 18 | 24 | 26 => {
            // ssat/usat rd, #n, rn{, shift}, and the 16-bit forms when the shift is asr #0.
            if bit(w, 26) != 0 || bit(w, 5) != 0 {
                return none(w);
            }
            let unsigned = op >= 24;
            let sh = bit(w, 21) != 0;
            let amount = (((w >> 12) & 7) << 2) | ((w >> 6) & 3);
            let sat = w & 31;
            if sh && amount == 0 {
                if bit(w, 4) != 0 {
                    return none(w);
                }
                return mk(it, 4, if unsigned { "usat16" } else { "ssat16" }, "", &[R(rd), imm_hex(if unsigned { sat & 15 } else { (sat & 15) + 1 } as i64), R(rn)], 0);
            }
            let mut ops = Ops::new();
            ops.push(R(rd));
            ops.push(imm_hex(if unsigned { sat } else { sat + 1 } as i64));
            ops.push(R(rn));
            if sh {
                ops.push(Op::Shift(cat!(ShiftText; "asr #", Dec(amount as i64))));
            } else if amount != 0 {
                ops.push(Op::Shift(cat!(ShiftText; "lsl #", Dec(amount as i64))));
            }
            mk(it, 4, if unsigned { "usat" } else { "ssat" }, "", &ops, 0)
        }
        20 | 28 => {
            let lsb = (((w >> 12) & 7) << 2) | ((w >> 6) & 3);
            let width = (w & 31) + 1;
            mk(it, 4, if op == 20 { "sbfx" } else { "ubfx" }, "", &[R(rd), R(rn), imm_hex(lsb as i64), imm_hex(width as i64)], 0)
        }
        22 => {
            // bfi rd, rn, #lsb, #width / bfc rd, #lsb, #width (decimal); an msb below the lsb is read as msb.
            if bit(w, 26) != 0 || bit(w, 5) != 0 {
                return none(w);
            }
            let msb = w & 31;
            let mut lsb = (((w >> 12) & 7) << 2) | ((w >> 6) & 3);
            if lsb > msb {
                lsb = msb;
            }
            let field = [imm_dec(lsb as i64), imm_dec((msb - lsb + 1) as i64)];
            if rn == 15 {
                return mk(it, 4, "bfc", "", &[R(rd), field[0], field[1]], 0);
            }
            mk(it, 4, "bfi", "", &[R(rd), R(rn), field[0], field[1]], 0)
        }
        _ => none(w),
    }
}

/* ------------------------------------------------------------------ *
 * Branches and miscellaneous control
 * ------------------------------------------------------------------ */

/// The 32-bit branch offset S:I1:I2:imm10:imm11:0, with I = not(J xor S).
#[inline]
fn branch_offset(w: u32) -> i64 {
    let s = bit(w, 26);
    let i1 = bit(w, 13) ^ s ^ 1;
    let i2 = bit(w, 11) ^ s ^ 1;
    sext((s << 24) | (i1 << 23) | (i2 << 22) | (((w >> 16) & 0x3ff) << 12) | ((w & 0x7ff) << 1), 25) as i64
}

fn branches_misc(w: u32, pc: i64, it: i32) -> Insn {
    let op1 = (w >> 12) & 7;
    if op1 & 4 != 0 {
        // bl / blx: blx switches to A32 and aligns the target to a word.
        let off = branch_offset(w);
        if op1 & 1 != 0 {
            let target = addr(pc as u32, 4 + off);
            return mk(it, 4, "bl", "", &[label(target)], f::CALL).target(target).thumb(true);
        }
        if w & 1 != 0 {
            return none(w);
        }
        let target = addr(pc_aligned(pc), off);
        return mk(it, 4, "blx", "", &[label(target)], f::CALL).target(target).thumb(false);
    }
    if op1 & 1 != 0 {
        let target = addr(pc as u32, 4 + branch_offset(w));
        return mk(it, 4, "b", ".w", &[label(target)], f::BRANCH).target(target);
    }
    let cond = (w >> 22) & 15;
    if cond < 14 {
        // b<cond>.w: S:J2:J1:imm6:imm11:0.
        let off = sext((bit(w, 26) << 20) | (bit(w, 11) << 19) | (bit(w, 13) << 18) | (((w >> 16) & 0x3f) << 12) | ((w & 0x7ff) << 1), 21) as i64;
        return cond_branch(4, cond as i32, it, ".w", addr(pc as u32, 4 + off));
    }
    misc_control(w, it)
}

fn misc_control(w: u32, it: i32) -> Insn {
    let hw1 = w >> 16;
    let hw2 = w & 0xffff;
    let op = (w >> 20) & 0x7f;
    let rn = hw1 & 15;
    match op {
        0x38 | 0x39 => {
            // msr spec_reg, rn and msr banked_reg, rn
            if (hw2 & 0xf000) != 0x8000 {
                return none(w);
            }
            let r_bit = bit(w, 20);
            if bit(w, 5) != 0 {
                if (hw2 & 0xef) != 0x20 {
                    return none(w);
                }
                let name = banked((r_bit << 5) | (bit(w, 4) << 4) | ((hw2 >> 8) & 15));
                if name.is_empty() {
                    return none(w);
                }
                return mk(it, 4, "msr", "", &[text(name), R(rn)], 0);
            }
            if hw2 & 0xff != 0 {
                return none(w);
            }
            let mask = (hw2 >> 8) & 15;
            if r_bit == 0 && mask == 0 {
                return none(w);
            }
            mk(it, 4, "msr", "", &[Op::Text(msr_mask(r_bit, mask)), R(rn)], if mask & 8 != 0 && r_bit == 0 { f::SETS_FLAGS } else { 0 })
        }
        0x3a => hint_space(w, it),
        0x3b => barriers(w, it),
        0x3c => {
            if hw2 != 0x8f00 {
                return none(w);
            }
            mk(it, 4, "bxj", "", &[R(rn)], f::BRANCH | f::INDIRECT)
        }
        0x3d => {
            // subs pc, lr, #imm (eret when 0)
            if hw1 != 0xf3de || (hw2 & 0xff00) != 0x8f00 {
                return none(w);
            }
            if hw2 & 0xff == 0 {
                return mk(it, 4, "eret", "", &[], f::BRANCH | f::RET);
            }
            mk(it, 4, "subs", "", &[R(15), R(14), imm_hex((hw2 & 0xff) as i64)], f::BRANCH | f::RET)
        }
        0x3e | 0x3f => {
            // mrs rd, apsr / spsr, and mrs rd, banked_reg
            if (hw2 & 0xf000) != 0x8000 {
                return none(w);
            }
            let rd = (hw2 >> 8) & 15;
            if bit(w, 5) != 0 {
                if (hw2 & 0xef) != 0x20 {
                    return none(w);
                }
                let name = banked((bit(w, 20) << 5) | (bit(w, 4) << 4) | rn);
                if name.is_empty() {
                    return none(w);
                }
                return mk(it, 4, "mrs", "", &[R(rd), text(name)], 0);
            }
            if rn != 15 || hw2 & 0xff != 0 {
                return none(w);
            }
            mk(it, 4, "mrs", "", &[R(rd), named(if bit(w, 20) != 0 { "spsr" } else { "apsr" })], if bit(w, 20) != 0 { 0 } else { f::READS_FLAGS })
        }
        0x78 => {
            // dcps1-3
            if hw1 == 0xf78f && (hw2 & 0xfffc) == 0x8000 && hw2 & 3 != 0 {
                return mk(it, 4, &cat!(Mn; "dcps", Dec((hw2 & 3) as i64)), "", &[], 0);
            }
            none(w)
        }
        0x7e => {
            if (hw2 & 0xf000) != 0x8000 {
                return none(w);
            }
            plain(4, "hvc.w", &[imm_hex((((hw1 & 15) << 12) | (hw2 & 0xfff)) as i64)], 0)
        }
        0x7f => {
            // udf.w #imm16 and smc #imm4
            if (hw2 & 0xf000) == 0xa000 {
                return plain(4, "udf.w", &[imm_hex((((hw1 & 15) << 12) | (hw2 & 0xfff)) as i64)], f::TRAP);
            }
            if (hw2 & 0xf000) != 0x8000 {
                return none(w);
            }
            mk(it, 4, "smc", "", &[imm_hex((hw1 & 15) as i64)], 0)
        }
        _ => none(w),
    }
}

/// f3af 8xxx: cps, the hints (nop.w, wfe.w, esb.w, csdb, tsb csync, dbg…).
fn hint_space(w: u32, it: i32) -> Insn {
    let hw1 = w >> 16;
    let hw2 = w & 0xffff;
    if hw1 != 0xf3af || (hw2 & 0xf800) != 0x8000 {
        return none(w);
    }
    let imod = (hw2 >> 9) & 3;
    let m = bit(hw2, 8);
    if imod != 0 || m != 0 {
        if imod == 1 {
            return none(w);
        }
        let flags = cpsie_flags(bit(hw2, 7) != 0, bit(hw2, 6) != 0, bit(hw2, 5) != 0);
        let mode = hw2 & 31;
        if imod == 0 {
            return plain(4, "cps", &[imm_hex(mode as i64)], 0);
        }
        let name = if imod == 2 { "cpsie" } else { "cpsid" };
        if m == 0 {
            return if mode != 0 { none(w) } else { plain(4, &cat2(name, ".w"), &[flags], 0) };
        }
        return plain(4, name, &[flags, imm_hex(mode as i64)], 0);
    }
    let imm = hw2 & 0xff;
    match imm {
        0 => mk(it, 4, "nop", ".w", &[], 0),
        1 => mk(it, 4, "yield", ".w", &[], 0),
        2 => mk(it, 4, "wfe", ".w", &[], 0),
        3 => mk(it, 4, "wfi", ".w", &[], 0),
        4 => mk(it, 4, "sev", ".w", &[], 0),
        5 => mk(it, 4, "sevl", ".w", &[], 0),
        0x10 => mk(it, 4, "esb", ".w", &[], 0),
        0x12 => mk(it, 4, "tsb", "", &[text("csync")], 0),
        0x14 => mk(it, 4, "csdb", "", &[], 0),
        0x16 => mk(it, 4, "clrbhb", "", &[], 0),
        // The M-profile pointer authentication hints, which LLVM names whatever the profile, without an IT condition.
        0x0d | 0x1d | 0x2d => plain(
            4,
            if imm == 0x0d {
                "pacbti"
            } else if imm == 0x1d {
                "pac"
            } else {
                "aut"
            },
            &[R(12), R(14), R(13)],
            0,
        ),
        0x0f => plain(4, "bti", &[], 0),
        _ => {
            if imm >= 0xf0 {
                return mk(it, 4, "dbg", "", &[imm_hex((imm & 15) as i64)], 0);
            }
            mk(it, 4, "hint", ".w", &[imm_hex(imm as i64)], 0)
        }
    }
}

/// f3bf 8f.x: clrex, dsb, dmb, isb, sb, and dsb's ssbb / pssbb.
fn barriers(w: u32, it: i32) -> Insn {
    let hw2 = w & 0xffff;
    let op = (hw2 >> 4) & 15;
    let opt = hw2 & 15;
    // sb tolerates other values in its should-be fields; the others are exact.
    if op == 7 && (hw2 & 0xd000) == 0x8000 {
        return plain(4, "sb", &[], 0);
    }
    if w >> 16 != 0xf3bf || (hw2 & 0xff00) != 0x8f00 {
        return none(w);
    }
    match op {
        2 => {
            if opt != 15 {
                return none(w);
            }
            mk(it, 4, "clrex", "", &[], 0)
        }
        4 => {
            if opt == 0 {
                return mk(it, 4, "ssbb", "", &[], 0);
            }
            if opt == 4 {
                return mk(it, 4, "pssbb", "", &[], 0);
            }
            mk(it, 4, "dsb", "", &[text(BARRIER_OPTIONS[opt as usize])], 0)
        }
        5 => mk(it, 4, "dmb", "", &[text(BARRIER_OPTIONS[opt as usize])], 0),
        6 => {
            if opt == 15 {
                mk(it, 4, "isb", "", &[text("sy")], 0)
            } else {
                mk(it, 4, "isb", "", &[Op::Text(cat!(Text; "#", Hex(opt as i64)))], 0)
            }
        }
        _ => none(w),
    }
}

/* ------------------------------------------------------------------ *
 * Loads and stores of one register, and the preload hints
 * ------------------------------------------------------------------ */

const LD_NAMES: [&str; 4] = ["ldrb", "ldrh", "ldr", ""];
const LDS_NAMES: [&str; 4] = ["ldrsb", "ldrsh", "", ""];
const ST_NAMES: [&str; 4] = ["strb", "strh", "str", ""];

fn load_store(w: u32, pc: i64, it: i32) -> Insn {
    let signed = bit(w, 24) != 0;
    let up = bit(w, 23) != 0;
    let size = (w >> 21) & 3;
    let load = bit(w, 20) != 0;
    let rn = (w >> 16) & 15;
    let rt = (w >> 12) & 15;
    if size == 3 {
        return none(w);
    }
    let bytes = 1 << size;
    if !load {
        if signed || rn == 15 {
            return none(w);
        }
        return single_transfer(w, it, ST_NAMES[size as usize], rt, rn, up, bytes, false);
    }
    let name = if signed { LDS_NAMES[size as usize] } else { LD_NAMES[size as usize] };
    if name.is_empty() {
        return none(w);
    }
    if rn == 15 {
        // Literal loads: [pc, #±imm12]; with rt = pc, the byte and halfword forms are preload hints.
        let imm = (w & 0xfff) as i64;
        let target = addr(pc_aligned(pc), if up { imm } else { -imm });
        if rt == 15 && size < 2 {
            // ldrh pc, [pc, …] falls on pldw in its offset forms, and pldw has no literal form.
            if size == 1 && (signed || up || ((w >> 6) & 63) == 0 || ((w >> 8) & 15) == 12) {
                return none(w);
            }
            return mk(it, 4, if signed { "pli" } else { "pld" }, "", &[mem_literal(imm, up)], 0).target(target);
        }
        return mk(it, 4, name, ".w", &[R(rt), mem_literal(imm, up)], ld_flags(rt)).target(target).bytes(bytes);
    }
    let op2 = (w >> 6) & 63;
    if rt == 15 && size < 2 && (up || op2 == 0 || op2 >> 2 == 12) {
        // The preload hints in the offset forms: pld (byte), pldw (halfword), pli (signed byte); ldrsh pc is refused there.
        if signed && size == 1 {
            return none(w);
        }
        let hint = if signed {
            "pli"
        } else if size != 0 {
            "pldw"
        } else {
            "pld"
        };
        if up {
            return mk(it, 4, hint, "", &[mem_hex(rn, (w & 0xfff) as i64)], 0);
        }
        if op2 == 0 {
            return mk(it, 4, hint, "", &[mem_reg(rn, w & 15, (w >> 4) & 3)], 0);
        }
        let imm = (w & 0xff) as i64;
        return mk(it, 4, hint, "", &[mem(rn, mem_dec(rn, imm, false, false), Mode::Off, Some(-imm), None)], 0);
    }
    single_transfer(w, it, name, rt, rn, up, bytes, true)
}

/// The addressing forms shared by loads and stores: imm12, register, negative imm8, unprivileged, post- and pre-indexed.
#[allow(clippy::too_many_arguments)]
fn single_transfer(w: u32, it: i32, name: &str, rt: u32, rn: u32, up: bool, bytes: u32, load: bool) -> Insn {
    let f = if load { ld_flags(rt) } else { f::STORE };
    if up {
        return mk(it, 4, name, ".w", &[R(rt), mem_hex(rn, (w & 0xfff) as i64)], f).bytes(bytes);
    }
    if ((w >> 6) & 63) == 0 {
        return mk(it, 4, name, ".w", &[R(rt), mem_reg(rn, w & 15, (w >> 4) & 3)], f).bytes(bytes);
    }
    let imm = (w & 0xff) as i64;
    let add = bit(w, 9) != 0;
    let off = if add { imm } else { -imm };
    match (w >> 8) & 15 {
        12 => mk(it, 4, name, "", &[R(rt), mem(rn, mem_dec(rn, imm, add, false), Mode::Off, Some(off), None)], f).bytes(bytes),
        14 => mk(it, 4, &cat2(name, "t"), "", &[R(rt), mem(rn, mem_dec(rn, imm, true, false), Mode::Off, Some(imm), None)], f).bytes(bytes),
        9 | 11 => {
            // ldr pc, [sp], #4 is a pop of the return address.
            let ret = if load && rt == 15 && rn == 13 && add && imm == 4 { f::RET } else { 0 };
            let t = cat!(MemText; "[", r(rn), "], #", if add { "" } else { "-" }, Dec(imm));
            mk(it, 4, name, "", &[R(rt), mem(rn, t, Mode::Post, Some(off), None)], f | ret).bytes(bytes)
        }
        13 | 15 => mk(it, 4, name, "", &[R(rt), mem(rn, cat!(MemText; mem_dec(rn, imm, add, true), "!"), Mode::Pre, Some(off), None)], f).bytes(bytes),
        _ => none(w),
    }
}

/* ------------------------------------------------------------------ *
 * Data processing on registers
 * ------------------------------------------------------------------ */

const PARALLEL_OPS: [&str; 8] = ["add8", "add16", "asx", "", "sub8", "sub16", "sax", ""];
const PARALLEL_PREFIX: [&str; 16] = ["s", "q", "sh", "", "u", "uq", "uh", "", "", "", "", "", "", "", "", ""];
const EXTENDS: [&str; 6] = ["sxth", "uxth", "sxtb16", "uxtb16", "sxtb", "uxtb"];
const EXTENDS_ADD: [&str; 6] = ["sxtah", "uxtah", "sxtab16", "uxtab16", "sxtab", "uxtab"];

fn dp_register(w: u32, it: i32) -> Insn {
    let op1 = (w >> 20) & 15;
    let op2 = (w >> 4) & 15;
    let rn = (w >> 16) & 15;
    let rd = (w >> 8) & 15;
    let rm = w & 15;
    if ((w >> 12) & 15) != 15 {
        return none(w);
    }
    if op1 < 8 {
        if op2 == 0 {
            // lsl/lsr/asr/ror rd, rn, rm
            let s = if op1 & 1 != 0 { "s" } else { "" };
            return mk(it, 4, &cat2(SHIFTS[(op1 >> 1) as usize], s), ".w", &[R(rd), R(rn), R(rm)], dp_flags(rd, !s.is_empty()));
        }
        if op2 & 8 == 0 || op1 > 5 {
            return none(w);
        }
        // The extends, with an optional rotation; rn = pc is the plain form.
        let rot = (w >> 4) & 3;
        let mut ops = Ops::new();
        ops.push(R(rd));
        if rn != 15 {
            ops.push(R(rn));
        }
        ops.push(R(rm));
        if rot != 0 {
            ops.push(Op::Shift(cat!(ShiftText; "ror #", Dec((rot * 8) as i64))));
        }
        if rn == 15 {
            return mk(it, 4, EXTENDS[op1 as usize], if op1 == 2 || op1 == 3 { "" } else { ".w" }, &ops, 0);
        }
        return mk(it, 4, EXTENDS_ADD[op1 as usize], "", &ops, 0);
    }
    if op2 & 8 == 0 {
        // Parallel add and subtract: s, q, sh, u, uq, uh.
        let name = PARALLEL_OPS[(op1 & 7) as usize];
        let prefix = PARALLEL_PREFIX[op2 as usize];
        if name.is_empty() || prefix.is_empty() {
            return none(w);
        }
        return mk(it, 4, &cat2(prefix, name), "", &[R(rd), R(rn), R(rm)], if prefix == "s" || prefix == "u" { f::SETS_FLAGS } else { 0 });
    }
    if op1 >= 12 {
        // crc32{c}{b,h,w}: not conditional, so LLVM prints no IT condition.
        if op1 > 13 || (op2 & 12) != 8 || (op2 & 3) == 3 {
            return none(w);
        }
        let m = cat!(Mn; "crc32", if op1 & 1 != 0 { "c" } else { "" }, ["b", "h", "w"][(op2 & 3) as usize]);
        return plain(4, &m, &[R(rd), R(rn), R(rm)], 0);
    }
    if op2 >= 12 {
        return none(w);
    }
    // These name Rm in both register fields; LLVM reads the register from the two fields or-ed together.
    let rm_both = rm | rn;
    match op1 & 3 {
        // qadd rd, rm, rn: the operands come out in Rm, Rn order.
        0 => mk(it, 4, ["qadd", "qdadd", "qsub", "qdsub"][(op2 & 3) as usize], "", &[R(rd), R(rm), R(rn)], 0),
        1 => mk(it, 4, ["rev", "rev16", "rbit", "revsh"][(op2 & 3) as usize], if (op2 & 3) == 2 { "" } else { ".w" }, &[R(rd), R(rm_both)], 0),
        2 => {
            if op2 != 8 {
                return none(w);
            }
            mk(it, 4, "sel", "", &[R(rd), R(rn), R(rm)], f::READS_FLAGS)
        }
        _ => {
            if op2 != 8 {
                return none(w);
            }
            mk(it, 4, "clz", "", &[R(rd), R(rm_both)], 0)
        }
    }
}

/* ------------------------------------------------------------------ *
 * Multiply, multiply-accumulate, and the long forms and divides
 * ------------------------------------------------------------------ */

const XY: [&str; 4] = ["bb", "bt", "tb", "tt"];

fn multiply(w: u32, it: i32) -> Insn {
    let op1 = (w >> 20) & 7;
    let op2 = (w >> 4) & 15;
    let rn = (w >> 16) & 15;
    let ra = (w >> 12) & 15;
    let rd = (w >> 8) & 15;
    let rm = w & 15;
    let three = |m: &str| mk(it, 4, m, "", &[R(rd), R(rn), R(rm)], 0);
    let four = |m: &str| mk(it, 4, m, "", &[R(rd), R(rn), R(rm), R(ra)], 0);
    // ra = pc names the form without the accumulator.
    let pick = |a: &str, b: &str, suffix: &str| if ra == 15 { three(&cat2(a, suffix)) } else { four(&cat2(b, suffix)) };
    match op1 {
        0 => {
            if op2 == 0 {
                return if ra == 15 { three("mul") } else { four("mla") };
            }
            if op2 == 1 {
                return four("mls");
            }
            none(w)
        }
        1 => {
            if op2 > 3 {
                return none(w);
            }
            pick("smul", "smla", XY[op2 as usize])
        }
        2 | 4 => {
            if op2 > 1 {
                return none(w);
            }
            let x = if op2 != 0 { "x" } else { "" };
            if op1 == 2 {
                return pick("smuad", "smlad", x);
            }
            pick("smusd", "smlsd", x)
        }
        3 => {
            if op2 > 1 {
                return none(w);
            }
            pick("smulw", "smlaw", if op2 != 0 { "t" } else { "b" })
        }
        5 => {
            if op2 > 1 {
                return none(w);
            }
            pick("smmul", "smmla", if op2 != 0 { "r" } else { "" })
        }
        6 => {
            if op2 > 1 {
                return none(w);
            }
            four(&cat2("smmls", if op2 != 0 { "r" } else { "" }))
        }
        _ => {
            if op2 != 0 {
                return none(w);
            }
            if ra == 15 {
                three("usad8")
            } else {
                four("usada8")
            }
        }
    }
}

fn long_multiply(w: u32, it: i32) -> Insn {
    let op1 = (w >> 20) & 7;
    let op2 = (w >> 4) & 15;
    let rn = (w >> 16) & 15;
    let lo = (w >> 12) & 15;
    let hi = (w >> 8) & 15;
    let rm = w & 15;
    let long = |m: &str| mk(it, 4, m, "", &[R(lo), R(hi), R(rn), R(rm)], 0);
    match op1 {
        0 => {
            if op2 == 0 {
                long("smull")
            } else {
                none(w)
            }
        }
        1 | 3 => {
            if op2 != 15 || lo != 15 {
                return none(w);
            }
            mk(it, 4, if op1 == 1 { "sdiv" } else { "udiv" }, "", &[R(hi), R(rn), R(rm)], 0)
        }
        2 => {
            if op2 == 0 {
                long("umull")
            } else {
                none(w)
            }
        }
        4 => {
            if op2 == 0 {
                return long("smlal");
            }
            if (op2 & 12) == 8 {
                return long(&cat2("smlal", XY[(op2 & 3) as usize]));
            }
            if op2 == 12 || op2 == 13 {
                return long(if op2 & 1 != 0 { "smlaldx" } else { "smlald" });
            }
            none(w)
        }
        5 => {
            if op2 == 12 || op2 == 13 {
                return long(if op2 & 1 != 0 { "smlsldx" } else { "smlsld" });
            }
            none(w)
        }
        6 => {
            if op2 == 0 {
                return long("umlal");
            }
            if op2 == 6 {
                return long("umaal");
            }
            none(w)
        }
        _ => none(w),
    }
}

/* ------------------------------------------------------------------ *
 * Coprocessor instructions
 * ------------------------------------------------------------------ */

/// `p14`, `c3`: a coprocessor or one of its registers.
#[inline]
fn cp_text(prefix: &str, n: u32) -> Op {
    Op::Text(cat!(Text; prefix, Dec(n as i64)))
}

/// ldc/stc, mcr/mrc and mcrr/mrrc. Armv8 keeps only coprocessors 14 and 15
/// (ldc and stc only 14) and drops cdp and the `2` forms, so LLVM refuses
/// the rest; coprocessors 10 and 11 are floating point, decoded in simd.rs.
fn coprocessor(w: u32, it: i32) -> Insn {
    if bit(w, 28) != 0 {
        return none(w);
    }
    let coproc = (w >> 8) & 15;
    let rn = (w >> 16) & 15;
    let crd = (w >> 12) & 15;
    if bit(w, 25) == 0 {
        let p = bit(w, 24) != 0;
        let u = bit(w, 23) != 0;
        let d = bit(w, 22) != 0;
        let wb = bit(w, 21) != 0;
        let load = bit(w, 20) != 0;
        if !p && !u && !wb {
            if !d {
                return none(w);
            }
            // mcrr / mrrc p, #opc1, rt, rt2, cN
            if coproc < 14 {
                return none(w);
            }
            return mk(it, 4, if load { "mrrc" } else { "mcrr" }, "", &[cp_text("p", coproc), imm_hex(((w >> 4) & 15) as i64), R(crd), R(rn), cp_text("c", w & 15)], 0);
        }
        if coproc != 14 {
            return none(w);
        }
        let m = cat2(if load { "ldc" } else { "stc" }, if d { "l" } else { "" });
        let imm = ((w & 0xff) * 4) as i64;
        let sign = if u { "" } else { "-" };
        let off = if u { imm } else { -imm };
        let a = if p {
            let t = if wb {
                cat!(MemText; "[", r(rn), ", #", sign, Dec(imm), "]!")
            } else if u && imm == 0 {
                cat!(MemText; "[", r(rn), "]")
            } else {
                cat!(MemText; "[", r(rn), ", #", sign, Dec(imm), "]")
            };
            mem(rn, t, if wb { Mode::Pre } else { Mode::Off }, Some(off), None)
        } else if wb {
            mem(rn, cat!(MemText; "[", r(rn), "], #", sign, Dec(imm)), Mode::Post, Some(off), None)
        } else {
            mem(rn, cat!(MemText; "[", r(rn), "], {", Dec((w & 0xff) as i64), "}"), Mode::Off, None, None)
        };
        return mk(it, 4, &m, "", &[cp_text("p", coproc), cp_text("c", crd), a], if load { f::LOAD } else { f::STORE });
    }
    if bit(w, 24) != 0 || bit(w, 4) == 0 || coproc < 14 {
        return none(w);
    }
    // mcr / mrc p, #opc1, rt, cN, cM, #opc2; mrc to pc writes the flags (apsr_nzcv).
    let load = bit(w, 20) != 0;
    let rt = crd;
    let rt_op = if load && rt == 15 { named("apsr_nzcv") } else { R(rt) };
    let ops = [cp_text("p", coproc), imm_hex(((w >> 21) & 7) as i64), rt_op, cp_text("c", rn), cp_text("c", w & 15), imm_hex(((w >> 5) & 7) as i64)];
    mk(it, 4, if load { "mrc" } else { "mcr" }, "", &ops, if load && rt == 15 { f::SETS_FLAGS } else { 0 })
}
