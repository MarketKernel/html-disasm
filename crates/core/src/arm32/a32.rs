//! A32 outside floating point and SIMD: data processing, multiplies, loads and
//! stores, branches, status registers, hints, barriers and the coprocessor
//! instructions.
//!
//! The decoder follows the top-level A32 encoding table — the condition field,
//! then bits 27:25 — and prints each instruction as llvm-objdump does, which is
//! not always as the Arm manual does: LLVM names `mov r0, r1, lsl #2` `lsl`,
//! prints a data-processing immediate in decimal but a load offset in hex
//! (except the post-indexed and halfword forms, which are decimal again), and
//! leaves out the operands an encoding cannot express. Where the manual calls
//! an encoding UNPREDICTABLE, LLVM usually still prints it; it gives up only on
//! the encodings it has no instruction for, and those are `.inst` here as well.
//! tools/verify-arm32.mjs compares the two line by line.

use super::types::*;

const SHIFTS: [&str; 4] = ["lsl", "lsr", "asr", "ror"];
const DP: [&str; 16] = ["and", "eor", "sub", "rsb", "add", "adc", "sbc", "rsc", "tst", "teq", "cmp", "cmn", "orr", "mov", "bic", "mvn"];
/// `DP[opc] + 's'`
const DPS: [&str; 16] = ["ands", "eors", "subs", "rsbs", "adds", "adcs", "sbcs", "rscs", "tsts", "teqs", "cmps", "cmns", "orrs", "movs", "bics", "mvns"];
const PC: u32 = 15;
const SP: u32 = 13;
const LR: u32 = 14;

#[inline]
fn none(w: u32) -> Insn {
    unknown(w, 4, false)
}

#[allow(non_snake_case)]
#[inline(always)]
fn R(n: u32) -> Op {
    reg(r(n), false)
}

/// An instruction under the condition in bits 31:28: the condition joins the
/// mnemonic (`addeq`, `ldrbne`), and a conditional instruction reads the flags.
#[inline]
fn mk(w: u32, m: &str, ops: &[Op], f: u32) -> Insn {
    let c = w >> 28;
    let mut insn = Insn::new(Mn::from(m), ops, f, 4);
    if c < 14 {
        insn.m.push(CONDS[c as usize]);
        insn.f |= f::COND | f::READS_FLAGS;
        insn.cond = Some(CONDS[c as usize]);
    }
    insn
}

/// An instruction of the unconditional space (cond = 1111), which has no condition to print.
#[inline]
fn mk_u(m: &str, ops: &[Op], f: u32) -> Insn {
    Insn::new(Mn::from(m), ops, f, 4)
}

/// `a` + `b`, for mnemonics put together from parts.
#[inline]
fn cat2(a: &str, b: &str) -> Mn {
    cat!(Mn; a, b)
}

/// `lsl #3`, `lsr #32`, `rrx`, or None for no shift (lsl #0): a shift by an immediate.
fn shift_text(ty: u32, amount: u32) -> Option<ShiftText> {
    match ty {
        0 => {
            if amount != 0 {
                Some(cat!(ShiftText; "lsl #", Dec(amount as i64)))
            } else {
                None
            }
        }
        3 => Some(if amount != 0 { cat!(ShiftText; "ror #", Dec(amount as i64)) } else { ShiftText::from("rrx") }),
        _ => Some(cat!(ShiftText; SHIFTS[ty as usize], " #", Dec(if amount != 0 { amount } else { 32 } as i64))),
    }
}

/// A data-processing immediate: eight bits rotated right by twice bits 11:8.
/// LLVM prints the value in decimal (signed, except for a move to pc or a
/// status register), or, when the same value has an encoding with a smaller
/// rotation, the raw `#bits, #rot` pair, so the text still names one encoding.
fn mod_imm(w: u32, unsigned: bool) -> Op {
    let imm8 = w & 0xff;
    let rot = bits(w, 11, 8) * 2;
    let value = imm8.rotate_right(rot);
    if canonical_rotation(value) == rot as i32 {
        let shown = if unsigned { value as i64 } else { value as i32 as i64 };
        return Op::Imm { v: value as f64, t: cat!(ImmText; "#", Dec(shown)) };
    }
    Op::Imm { v: value as f64, t: cat!(ImmText; "#", Dec(imm8 as i64), ", #", Dec(rot as i64)) }
}

/// The smallest rotation that encodes a value, as LLVM's getSOImmVal picks it.
fn canonical_rotation(value: u32) -> i32 {
    if (value & !0xff) == 0 {
        return 0;
    }
    let mut rot = 2;
    while rot < 32 {
        let back = value.rotate_left(rot);
        if (back & !0xff) == 0 {
            return rot as i32;
        }
        rot += 2;
    }
    -1
}

/// A memory operand.
#[inline]
fn mem(base: u32, t: MemText, mode: Mode, off: Option<i64>, index: Option<u32>) -> Op {
    // `off || 0` in the TypeScript: no -0 for a subtracted zero, which an i64 cannot hold anyway.
    Op::Mem(Mem { base: r(base), t, off, index: index.map(r), mode })
}

#[inline]
fn pc_relative(pc: i64, offset: i64) -> i64 {
    (pc as u32).wrapping_add(8).wrapping_add(offset as u32) as i64
}

pub fn decode_a32_base(w: u32, pc: i64) -> Insn {
    if w >> 28 == 15 {
        return unconditional(w, pc);
    }
    match bits(w, 27, 25) {
        0 => group000(w, pc),
        1 => group001(w, pc),
        2 => load_store_word(w, pc),
        3 => {
            if bit(w, 4) != 0 {
                media(w)
            } else {
                load_store_word(w, pc)
            }
        }
        4 => block_transfer(w),
        5 => branch(w, pc),
        _ => coprocessor(w),
    }
}

/* ------------------------------------------------------------------ *
 * Bits 27:25 = 000: data processing on registers, the miscellaneous
 * instructions, multiplies, synchronisation and the halfword/doubleword
 * loads and stores
 * ------------------------------------------------------------------ */

fn group000(w: u32, pc: i64) -> Insn {
    let op4 = bit(w, 4);
    let op7 = bit(w, 7);
    if op4 != 0 && op7 != 0 {
        if bits(w, 6, 5) == 0 {
            return if bit(w, 24) != 0 { synchronization(w) } else { multiply(w) };
        }
        return extra_load_store(w, pc);
    }
    if bits(w, 24, 23) == 2 && bit(w, 20) == 0 {
        return if op7 != 0 { halfword_multiply(w) } else { miscellaneous(w) };
    }
    data_processing_register(w)
}

/// Data processing with a register operand, shifted by an immediate (bit 4 = 0)
/// or by a register. The moves with a shift print as the shift itself:
/// `mov r0, r1, lsl #2` is `lsl r0, r1, #2`, `mov r0, r1, ror #0` is `rrx r0, r1`.
fn data_processing_register(w: u32) -> Insn {
    let opc = bits(w, 24, 21);
    let s = bit(w, 20);
    let rn = bits(w, 19, 16);
    let rd = bits(w, 15, 12);
    let rm = bits(w, 3, 0);
    let ty = bits(w, 6, 5);
    let by_reg = bit(w, 4);
    let rs = bits(w, 11, 8);
    let amount = bits(w, 11, 7);
    let test = (8..=11).contains(&opc);

    let mut f = if s != 0 || test { f::SETS_FLAGS } else { 0 };
    if (5..=7).contains(&opc) {
        f |= f::READS_FLAGS;
    }
    if by_reg == 0 && ty == 3 && amount == 0 {
        f |= f::READS_FLAGS;
    }

    if opc == 13 {
        // mov: the shift becomes the mnemonic. Bits 19:16 must be zero, except
        // that LLVM also knows a plain mov between the registers a tail call may
        // use (r0-r3, r9, r12) without that rule.
        let sx = if s != 0 { "s" } else { "" };
        let plain = by_reg == 0 && ty == 0 && amount == 0;
        if rn != 0 && !(plain && TAIL_CALL_REGS & (1 << rd) != 0 && TAIL_CALL_REGS & (1 << rm) != 0) {
            return none(w);
        }
        if by_reg != 0 {
            return mk(w, &cat2(SHIFTS[ty as usize], sx), &[R(rd), R(rm), R(rs)], f | writes_pc(rd));
        }
        if ty == 0 && amount == 0 {
            return mk(w, &cat2("mov", sx), &[R(rd), R(rm)], f | writes_pc(rd) | if rd == PC && rm == LR { f::RET } else { 0 });
        }
        if ty == 3 && amount == 0 {
            return mk(w, &cat2("rrx", sx), &[R(rd), R(rm)], f | writes_pc(rd));
        }
        let shown = if amount != 0 {
            amount
        } else if ty == 0 {
            0
        } else {
            32
        };
        return mk(w, &cat2(SHIFTS[ty as usize], sx), &[R(rd), R(rm), imm_dec(shown as i64)], f | writes_pc(rd));
    }

    let mut ops = Ops::new();
    if !test {
        ops.push(R(rd));
    }
    if test || opc != 15 {
        ops.push(R(rn));
    }
    ops.push(R(rm));
    if by_reg != 0 {
        ops.push(Op::Shift(cat!(ShiftText; SHIFTS[ty as usize], " ", r(rs))));
    } else if let Some(sh) = shift_text(ty, amount) {
        ops.push(Op::Shift(sh));
    }
    if test {
        return mk(w, DP[opc as usize], &ops, f);
    }
    let m = if s != 0 { DPS[opc as usize] } else { DP[opc as usize] };
    mk(w, m, &ops, f | writes_pc(rd))
}

/// A data-processing result written to pc is a branch to a computed address.
#[inline]
fn writes_pc(rd: u32) -> u32 {
    if rd == PC {
        f::BRANCH | f::INDIRECT
    } else {
        0
    }
}

/// r0-r3, r9, r12: LLVM's tcGPR class.
const TAIL_CALL_REGS: u32 = 0x120f;

/// MUL, MLA, UMAAL, MLS and the long multiplies (bits 7:4 = 1001, bit 24 = 0).
fn multiply(w: u32) -> Insn {
    let op = bits(w, 23, 21);
    let s = bit(w, 20);
    let hi = bits(w, 19, 16);
    let lo = bits(w, 15, 12);
    let rm = bits(w, 11, 8);
    let rn = bits(w, 3, 0);
    let sx = if s != 0 { "s" } else { "" };
    let f = if s != 0 { f::SETS_FLAGS } else { 0 };
    match op {
        0 => mk(w, &cat2("mul", sx), &[R(hi), R(rn), R(rm)], f),
        1 => mk(w, &cat2("mla", sx), &[R(hi), R(rn), R(rm), R(lo)], f),
        2 => {
            if s != 0 {
                none(w)
            } else {
                mk(w, "umaal", &[R(lo), R(hi), R(rn), R(rm)], 0)
            }
        }
        3 => {
            if s != 0 {
                none(w)
            } else {
                mk(w, "mls", &[R(hi), R(rn), R(rm), R(lo)], 0)
            }
        }
        _ => mk(w, &cat2(["umull", "umlal", "smull", "smlal"][(op - 4) as usize], sx), &[R(lo), R(hi), R(rn), R(rm)], f),
    }
}

/// The exclusive and acquire/release loads and stores (bits 7:4 = 1001,
/// bit 24 = 1). SWP and SWPB share the space but are gone from Armv8, and LLVM
/// does not decode them there.
fn synchronization(w: u32) -> Insn {
    if bit(w, 23) == 0 {
        return none(w);
    }
    let size = bits(w, 22, 21);
    let load = bit(w, 20) != 0;
    let rn = bits(w, 19, 16);
    let rt = bits(w, 15, 12);
    let rt2 = bits(w, 3, 0);
    let kind = bits(w, 9, 8);
    // Bits 11:10 are ones, and so are the unused register fields (Rt2 of a load, Rt of stl).
    if kind == 1 || bits(w, 11, 10) != 3 || (load && rt2 != 15) || (!load && kind == 0 && rt != 15) {
        return none(w);
    }
    let suffix = ["", "d", "b", "h"][size as usize];
    let bytes = [4, 8, 1, 2][size as usize];
    let address = mem(rn, cat!(MemText; "[", r(rn), "]"), Mode::Off, None, None);
    let f = f::ATOMIC | if load { f::LOAD } else { f::STORE };
    if kind == 0 {
        // lda/stl: no exclusive monitor, no doubleword form.
        if size == 1 {
            return none(w);
        }
        let m = cat2(if load { "lda" } else { "stl" }, suffix);
        return mk(w, &m, &[R(if load { rt } else { rt2 }), address], f | if load && rt == PC { f::BRANCH | f::INDIRECT } else { 0 }).bytes(bytes);
    }
    let m = cat2(
        if kind == 2 {
            if load {
                "ldaex"
            } else {
                "stlex"
            }
        } else if load {
            "ldrex"
        } else {
            "strex"
        },
        suffix,
    );
    if size == 1 {
        // The pair is the even register and the next one; an odd register prints as its pair.
        if load {
            return if rt >= 14 { none(w) } else { mk(w, &m, &[R(rt & !1), R((rt & !1) + 1), address], f).bytes(bytes) };
        }
        return if rt2 >= 14 { none(w) } else { mk(w, &m, &[R(rt), R(rt2 & !1), R((rt2 & !1) + 1), address], f).bytes(bytes) };
    }
    if load {
        return mk(w, &m, &[R(rt), address], f).bytes(bytes);
    }
    mk(w, &m, &[R(rt), R(rt2), address], f).bytes(bytes)
}

/// LDRH, STRH, LDRSB, LDRSH, LDRD, STRD and their unprivileged forms (bit 7 =
/// bit 4 = 1, bits 6:5 ≠ 00). Addressing mode 3 prints its offset in decimal.
fn extra_load_store(w: u32, pc: i64) -> Insn {
    let p = bit(w, 24);
    let u = bit(w, 23);
    let is_imm = bit(w, 22);
    let wb = bit(w, 21);
    let load = bit(w, 20);
    let rn = bits(w, 19, 16);
    let rt = bits(w, 15, 12);
    let rm = bits(w, 3, 0);
    let op2 = bits(w, 6, 5);
    let imm = ((bits(w, 11, 8) << 4) | rm) as i64;
    let sign = if u != 0 { "" } else { "-" };
    let unprivileged = p == 0 && wb != 0;
    let double = load == 0 && op2 != 1;

    let mut m: Mn;
    let bytes: u32;
    if double {
        m = Mn::from(if op2 == 2 { "ldrd" } else { "strd" });
        bytes = 8;
    } else if op2 == 1 {
        m = Mn::from(if load != 0 { "ldrh" } else { "strh" });
        bytes = 2;
    } else {
        m = Mn::from(if op2 == 2 { "ldrsb" } else { "ldrsh" });
        bytes = if op2 == 2 { 1 } else { 2 };
    }
    let is_load = if double { op2 == 2 } else { load == 1 };
    if unprivileged {
        // ldrd and strd have no unprivileged form; the others take no register shift bits.
        if double || (is_imm == 0 && load == 0 && bits(w, 11, 8) != 0) {
            return none(w);
        }
        m.push("t");
    }

    let address: Op;
    let mut target = None;
    let off = if u != 0 { imm } else { -imm };
    if p != 0 {
        if is_imm != 0 {
            let mut t = if imm != 0 || u == 0 || wb != 0 { cat!(MemText; "[", r(rn), ", #", sign, Dec(imm), "]") } else { cat!(MemText; "[", r(rn), "]") };
            if wb != 0 {
                t.push("!");
            }
            address = mem(rn, t, if wb != 0 { Mode::Pre } else { Mode::Off }, Some(off), None);
            if rn == PC && wb == 0 {
                target = Some(pc_relative(pc, off));
            }
        } else {
            address = mem(rn, cat!(MemText; "[", r(rn), ", ", sign, r(rm), "]", if wb != 0 { "!" } else { "" }), if wb != 0 { Mode::Pre } else { Mode::Off }, None, Some(rm));
        }
    } else if is_imm != 0 {
        address = mem(rn, cat!(MemText; "[", r(rn), "], #", sign, Dec(imm)), Mode::Post, Some(off), None);
    } else {
        address = mem(rn, cat!(MemText; "[", r(rn), "], ", sign, r(rm)), Mode::Post, None, Some(rm));
    }

    let mut ops = Ops::new();
    ops.push(R(rt));
    if double {
        if rt == PC {
            return none(w);
        }
        ops.push(R(rt + 1));
    }
    ops.push(address);
    let mut f = if is_load { f::LOAD } else { f::STORE };
    if is_load && (rt == PC || (double && rt + 1 == PC)) {
        f |= f::BRANCH | f::INDIRECT;
    }
    let insn = mk(w, &m, &ops, f).bytes(bytes);
    match target {
        Some(t) => insn.target(t),
        None => insn,
    }
}

/// The miscellaneous instructions (bits 27:23 = 00010, bit 20 = 0, bit 7 = 0):
/// status register moves, bx/blx/bxj, clz, the saturating adds, crc32, eret
/// and the breakpoint and call-gate instructions.
fn miscellaneous(w: u32) -> Insn {
    let op = bits(w, 22, 21);
    let rd = bits(w, 15, 12);
    let rm = bits(w, 3, 0);
    let rn = bits(w, 19, 16);
    let c = w >> 28;
    match bits(w, 6, 4) {
        0 => {
            let spsr = bit(w, 22);
            if bit(w, 9) != 0 {
                // Banked registers: SYSm is bit 8 and bits 19:16.
                let name = banked((spsr << 5) | (bit(w, 8) << 4) | rn);
                if name.is_empty() || bits(w, 11, 10) != 0 {
                    return none(w);
                }
                if op & 1 != 0 {
                    return if rd == 15 { mk(w, "msr", &[text(name), R(rm)], 0) } else { none(w) };
                }
                return if rm != 0 { none(w) } else { mk(w, "mrs", &[R(rd), text(name)], 0) };
            }
            if op & 1 != 0 {
                // A mask of nothing (CPSR with no fields) is not an instruction to LLVM.
                if rd != 15 || bits(w, 11, 8) != 0 || (spsr == 0 && rn == 0) {
                    return none(w);
                }
                return mk(w, "msr", &[Op::Text(msr_mask(spsr, rn)), R(rm)], if rn & 8 != 0 && spsr == 0 { f::SETS_FLAGS } else { 0 });
            }
            // mrs: the other bits are UNPREDICTABLE, which LLVM accepts, except bit 16 of apsr.
            if spsr == 0 && bit(w, 16) == 0 {
                return none(w);
            }
            mk(w, "mrs", &[R(rd), text(if spsr != 0 { "spsr" } else { "apsr" })], 0)
        }
        1 => {
            if op == 1 {
                return if bits(w, 19, 8) == 0xfff { mk(w, "bx", &[R(rm)], f::BRANCH | f::INDIRECT | if rm == LR { f::RET } else { 0 }) } else { none(w) };
            }
            if op == 3 {
                return if (w & 0xf0f00) == 0xf0f00 { mk(w, "clz", &[R(rd), R(rm)], 0) } else { none(w) };
            }
            none(w)
        }
        2 => {
            if op == 1 && bits(w, 19, 8) == 0xfff {
                mk(w, "bxj", &[R(rm)], f::BRANCH | f::INDIRECT)
            } else {
                none(w)
            }
        }
        3 => {
            if op == 1 && bits(w, 19, 8) == 0xfff {
                mk(w, "blx", &[R(rm)], f::CALL | f::INDIRECT)
            } else {
                none(w)
            }
        }
        4 => {
            // crc32 exists only unconditionally.
            if op == 3 || c != 14 {
                return none(w);
            }
            let m = cat!(Mn; "crc32", if bit(w, 9) != 0 { "c" } else { "" }, ["b", "h", "w"][op as usize]);
            mk(w, &m, &[R(rd), R(rn), R(rm)], 0)
        }
        5 => mk(w, ["qadd", "qsub", "qdadd", "qdsub"][op as usize], &[R(rd), R(rm), R(rn)], 0),
        6 => {
            if op == 3 && (w & 0xfffff) == 0x0006e {
                mk(w, "eret", &[], f::BRANCH | f::RET)
            } else {
                none(w)
            }
        }
        _ => {
            let imm16 = ((bits(w, 19, 8) << 4) | rm) as i64;
            // hlt and bkpt are unconditional; hvc takes any condition but does not print it.
            if op == 0 {
                return if c == 14 { mk(w, "hlt", &[imm_hex(imm16)], f::TRAP) } else { none(w) };
            }
            if op == 1 {
                return if c == 14 { mk(w, "bkpt", &[imm_hex(imm16)], f::TRAP) } else { none(w) };
            }
            if op == 2 {
                return mk_u("hvc", &[imm_hex(imm16)], 0);
            }
            if bits(w, 19, 8) != 0 {
                none(w)
            } else {
                mk(w, "smc", &[imm_hex(rm as i64)], 0)
            }
        }
    }
}

/// The CPSR/SPSR field mask of an msr, as LLVM's printMSRMaskOperand prints it.
pub(crate) fn msr_mask(spsr: u32, mask: u32) -> Text {
    if spsr == 0 && (mask == 8 || mask == 4 || mask == 12) {
        return Text::from(if mask == 8 {
            "APSR_nzcvq"
        } else if mask == 4 {
            "APSR_g"
        } else {
            "APSR_nzcvqg"
        });
    }
    let mut t = Text::from(if spsr != 0 { "SPSR" } else { "CPSR" });
    if mask != 0 {
        t.push("_");
        if mask & 8 != 0 {
            t.push("f");
        }
        if mask & 4 != 0 {
            t.push("s");
        }
        if mask & 2 != 0 {
            t.push("x");
        }
        if mask & 1 != 0 {
            t.push("c");
        }
    }
    t
}

/// The banked registers by SYSm (R:M:M1), or "" where there is none.
pub(crate) fn banked(v: u32) -> &'static str {
    match v {
        0x00 => "r8_usr",
        0x01 => "r9_usr",
        0x02 => "r10_usr",
        0x03 => "r11_usr",
        0x04 => "r12_usr",
        0x05 => "sp_usr",
        0x06 => "lr_usr",
        0x08 => "r8_fiq",
        0x09 => "r9_fiq",
        0x0a => "r10_fiq",
        0x0b => "r11_fiq",
        0x0c => "r12_fiq",
        0x0d => "sp_fiq",
        0x0e => "lr_fiq",
        0x10 => "lr_irq",
        0x11 => "sp_irq",
        0x12 => "lr_svc",
        0x13 => "sp_svc",
        0x14 => "lr_abt",
        0x15 => "sp_abt",
        0x16 => "lr_und",
        0x17 => "sp_und",
        0x1c => "lr_mon",
        0x1d => "sp_mon",
        0x1e => "elr_hyp",
        0x1f => "sp_hyp",
        0x2e => "SPSR_fiq",
        0x30 => "SPSR_irq",
        0x32 => "SPSR_svc",
        0x34 => "SPSR_abt",
        0x36 => "SPSR_und",
        0x3c => "SPSR_mon",
        0x3e => "SPSR_hyp",
        _ => "",
    }
}

/// SMLA<x><y>, SMLAW<y>, SMULW<y>, SMLAL<x><y>, SMUL<x><y> (bits 27:23 = 00010, bit 7 = 1, bit 4 = 0).
fn halfword_multiply(w: u32) -> Insn {
    let op = bits(w, 22, 21);
    let rd = bits(w, 19, 16);
    let ra = bits(w, 15, 12);
    let rm = bits(w, 11, 8);
    let rn = bits(w, 3, 0);
    let x = if bit(w, 5) != 0 { "t" } else { "b" };
    let y = if bit(w, 6) != 0 { "t" } else { "b" };
    match op {
        0 => mk(w, &cat!(Mn; "smla", x, y), &[R(rd), R(rn), R(rm), R(ra)], 0),
        1 => {
            if bit(w, 5) != 0 {
                mk(w, &cat2("smulw", y), &[R(rd), R(rn), R(rm)], 0)
            } else {
                mk(w, &cat2("smlaw", y), &[R(rd), R(rn), R(rm), R(ra)], 0)
            }
        }
        2 => mk(w, &cat!(Mn; "smlal", x, y), &[R(ra), R(rd), R(rn), R(rm)], 0),
        _ => mk(w, &cat!(Mn; "smul", x, y), &[R(rd), R(rn), R(rm)], 0),
    }
}

/* ------------------------------------------------------------------ *
 * Bits 27:25 = 001: data processing with an immediate, movw/movt,
 * msr with an immediate and the hints
 * ------------------------------------------------------------------ */

fn group001(w: u32, pc: i64) -> Insn {
    let opc = bits(w, 24, 21);
    let s = bit(w, 20);
    if (8..=11).contains(&opc) && s == 0 {
        let rd = bits(w, 15, 12);
        if opc == 8 || opc == 10 {
            let imm16 = (bits(w, 19, 16) << 12) | (w & 0xfff);
            return mk(w, if opc == 8 { "movw" } else { "movt" }, &[R(rd), imm_hex(imm16 as i64)], writes_pc(rd));
        }
        return msr_immediate(w);
    }
    let rn = bits(w, 19, 16);
    let rd = bits(w, 15, 12);
    let mut f = if s != 0 || (8..=11).contains(&opc) { f::SETS_FLAGS } else { 0 };
    if (5..=7).contains(&opc) {
        f |= f::READS_FLAGS;
    }
    if (8..=11).contains(&opc) {
        return mk(w, DP[opc as usize], &[R(rn), mod_imm(w, false)], f);
    }
    let m = if s != 0 { DPS[opc as usize] } else { DP[opc as usize] };
    if opc == 13 || opc == 15 {
        return if rn != 0 { none(w) } else { mk(w, m, &[R(rd), mod_imm(w, opc == 13 && rd == PC)], f | writes_pc(rd)) };
    }
    let op2 = mod_imm(w, false);
    let mut target = None;
    if rn == PC && s == 0 && (opc == 2 || opc == 4) {
        // add/sub rX, pc, #imm computes an address: the analysis reads it as adr.
        let v = match op2 {
            Op::Imm { v, .. } => v as i64,
            _ => 0,
        };
        target = Some(pc_relative(pc, if opc == 4 { v } else { -v }));
    }
    // subs pc, lr, #imm returns from an exception.
    if rd == PC && rn == LR && s != 0 && opc == 2 {
        return mk(w, m, &[R(rd), R(rn), op2], f | f::BRANCH | f::RET);
    }
    let insn = mk(w, m, &[R(rd), R(rn), op2], f | writes_pc(rd));
    match target {
        Some(t) => insn.target(t),
        None => insn,
    }
}

/// MSR with an immediate; a zero mask is the hint space (nop, yield, wfe, csdb…).
fn msr_immediate(w: u32) -> Insn {
    let spsr = bit(w, 22);
    let mask = bits(w, 19, 16);
    if bits(w, 15, 12) != 15 {
        return none(w);
    }
    if spsr != 0 || mask != 0 {
        return mk(w, "msr", &[Op::Text(msr_mask(spsr, mask)), mod_imm(w, true)], if mask & 8 != 0 && spsr == 0 { f::SETS_FLAGS } else { 0 });
    }
    if bits(w, 11, 8) != 0 {
        return none(w);
    }
    let imm = w & 0xff;
    match imm {
        0 => return mk(w, "nop", &[], 0),
        1 => return mk(w, "yield", &[], 0),
        2 => return mk(w, "wfe", &[], 0),
        3 => return mk(w, "wfi", &[], 0),
        4 => return mk(w, "sev", &[], 0),
        5 => return mk(w, "sevl", &[], 0),
        16 => return mk(w, "esb", &[], 0),
        18 => {
            // tsb is defined only unconditionally; under a condition it stays a hint.
            if w >> 28 == 14 {
                return mk(w, "tsb", &[text("csync")], 0);
            }
        }
        20 => return mk(w, "csdb", &[], 0),
        22 => return mk(w, "clrbhb", &[], 0),
        _ => {}
    }
    if imm >= 0xf0 {
        return mk(w, "dbg", &[imm_hex((imm & 15) as i64)], 0);
    }
    mk(w, "hint", &[imm_hex(imm as i64)], 0)
}

/* ------------------------------------------------------------------ *
 * Bits 27:25 = 010 and 011 (bit 4 = 0): ldr, str, ldrb, strb and their
 * unprivileged forms
 * ------------------------------------------------------------------ */

/// The register offset of addressing mode 2: `-r2, lsl #2` (sign, register, shift).
#[inline]
fn index_text(t: &mut MemText, u: u32, rm: u32, ty: u32, amount: u32) {
    if u == 0 {
        t.push("-");
    }
    t.push(&r(rm));
    if let Some(sh) = shift_text(ty, amount) {
        t.push(", ");
        t.push(&sh);
    }
}

/// Addressing mode 2 prints an immediate offset in hex inside the brackets
/// (`[r1, #0x4]`, `[r1, #-0x0]` for a subtracted zero) and in decimal after
/// them (`[r1], #4`); a register offset carries its sign and shift.
fn load_store_word(w: u32, pc: i64) -> Insn {
    let is_reg = bit(w, 25);
    let p = bit(w, 24);
    let u = bit(w, 23);
    let byte = bit(w, 22);
    let wb = bit(w, 21);
    let load = bit(w, 20);
    let rn = bits(w, 19, 16);
    let rt = bits(w, 15, 12);
    let sign = if u != 0 { "" } else { "-" };
    let base = r(rn);

    let address: Op;
    let mut target = None;
    if is_reg == 0 {
        let imm = (w & 0xfff) as i64;
        let off = if u != 0 { imm } else { -imm };
        if p != 0 {
            let mut t = if u == 0 {
                cat!(MemText; "[", base, ", #-", Hex(imm), "]")
            } else if imm != 0 || wb != 0 {
                cat!(MemText; "[", base, ", #", Hex(imm), "]")
            } else {
                cat!(MemText; "[", base, "]")
            };
            if wb != 0 {
                t.push("!");
            }
            address = mem(rn, t, if wb != 0 { Mode::Pre } else { Mode::Off }, Some(off), None);
            if rn == PC && wb == 0 {
                target = Some(pc_relative(pc, off));
            }
        } else {
            address = mem(rn, cat!(MemText; "[", base, "], #", sign, Dec(imm)), Mode::Post, Some(off), None);
        }
    } else {
        let rm = bits(w, 3, 0);
        let (ty, amount) = (bits(w, 6, 5), bits(w, 11, 7));
        if p != 0 {
            let mut t = cat!(MemText; "[", base, ", ");
            index_text(&mut t, u, rm, ty, amount);
            t.push(if wb != 0 { "]!" } else { "]" });
            address = mem(rn, t, if wb != 0 { Mode::Pre } else { Mode::Off }, None, Some(rm));
        } else {
            let mut t = cat!(MemText; "[", base, "], ");
            index_text(&mut t, u, rm, ty, amount);
            address = mem(rn, t, Mode::Post, None, Some(rm));
        }
    }

    let m = cat!(Mn; if load != 0 { "ldr" } else { "str" }, if byte != 0 { "b" } else { "" }, if p == 0 && wb != 0 { "t" } else { "" });
    let mut f = if load != 0 { f::LOAD } else { f::STORE };
    if load != 0 && rt == PC {
        f |= f::BRANCH | f::INDIRECT;
        if rn == SP && p == 0 {
            f |= f::RET;
        }
    }
    let insn = mk(w, &m, &[R(rt), address], f).bytes(if byte != 0 { 1 } else { 4 });
    match target {
        Some(t) => insn.target(t),
        None => insn,
    }
}

/* ------------------------------------------------------------------ *
 * Bits 27:25 = 011, bit 4 = 1: the media instructions — parallel add and
 * subtract, packing, extension, saturation, reversal, signed multiplies,
 * divides, bitfields and udf
 * ------------------------------------------------------------------ */

const PARALLEL_OPS: [&str; 8] = ["add16", "asx", "sax", "sub16", "add8", "", "", "sub8"];

fn media(w: u32) -> Insn {
    let op1 = bits(w, 24, 20);
    let op2 = bits(w, 7, 5);
    let rn = bits(w, 19, 16);
    let rd = bits(w, 15, 12);
    let rs = bits(w, 11, 8);
    let rm = bits(w, 3, 0);

    if op1 < 8 {
        // Parallel add/subtract: s, q, sh (signed) and u, uq, uh (unsigned).
        let kind = op1 & 3;
        let name = PARALLEL_OPS[op2 as usize];
        if kind == 0 || name.is_empty() {
            return none(w);
        }
        let prefix = (if op1 & 4 != 0 { ["", "u", "uq", "uh"] } else { ["", "s", "q", "sh"] })[kind as usize];
        return mk(w, &cat2(prefix, name), &[R(rd), R(rn), R(rm)], 0);
    }

    if op1 < 16 {
        return packing(w, op1, op2);
    }

    match op1 {
        0x10 | 0x14 => {
            // smlad/smlsd (and smuad/smusd with Ra = pc), smlald/smlsld.
            if op2 >= 4 {
                return none(w);
            }
            let x = if op2 & 1 != 0 { "x" } else { "" };
            let sub = if op2 & 2 != 0 { "s" } else { "a" };
            if op1 == 0x14 {
                return mk(w, &cat!(Mn; "sml", sub, "ld", x), &[R(rd), R(rn), R(rm), R(rs)], 0);
            }
            if rd == PC {
                return mk(w, &cat!(Mn; "smu", sub, "d", x), &[R(rn), R(rm), R(rs)], 0);
            }
            mk(w, &cat!(Mn; "sml", sub, "d", x), &[R(rn), R(rm), R(rs), R(rd)], 0)
        }
        0x11 | 0x13 => {
            if op2 != 0 || rd != PC {
                return none(w);
            }
            mk(w, if op1 == 0x11 { "sdiv" } else { "udiv" }, &[R(rn), R(rm), R(rs)], 0)
        }
        0x15 => {
            // smmla/smmls (and smmul with Ra = pc), with or without rounding.
            let round = if op2 & 1 != 0 { "r" } else { "" };
            if op2 < 2 {
                return if rd == PC { mk(w, &cat2("smmul", round), &[R(rn), R(rm), R(rs)], 0) } else { mk(w, &cat2("smmla", round), &[R(rn), R(rm), R(rs), R(rd)], 0) };
            }
            if op2 >= 6 {
                return mk(w, &cat2("smmls", round), &[R(rn), R(rm), R(rs), R(rd)], 0);
            }
            none(w)
        }
        0x18 => {
            if op2 != 0 {
                return none(w);
            }
            if rd == PC {
                mk(w, "usad8", &[R(rn), R(rm), R(rs)], 0)
            } else {
                mk(w, "usada8", &[R(rn), R(rm), R(rs), R(rd)], 0)
            }
        }
        0x1a | 0x1b | 0x1e | 0x1f => {
            if op1 == 0x1f && op2 == 7 {
                return udf(w);
            }
            if (op2 & 3) != 2 {
                return none(w);
            }
            let lsb = bits(w, 11, 7);
            let width = bits(w, 20, 16) + 1;
            mk(w, if op1 < 0x1e { "sbfx" } else { "ubfx" }, &[R(rd), R(rm), imm_hex(lsb as i64), imm_hex(width as i64)], 0)
        }
        0x1c | 0x1d => {
            if (op2 & 3) != 0 {
                return none(w);
            }
            let lsb = bits(w, 11, 7);
            let msb = bits(w, 20, 16);
            let from = if lsb > msb { msb } else { lsb };
            let field = [imm_dec(from as i64), imm_dec((msb - from + 1) as i64)];
            if rm == PC {
                mk(w, "bfc", &[R(rd), field[0], field[1]], 0)
            } else {
                mk(w, "bfi", &[R(rd), R(rm), field[0], field[1]], 0)
            }
        }
        _ => none(w),
    }
}

/// udf, a permanently undefined instruction, exists only unconditionally. One
/// of them, 0xe7ffdefe, is the trap LLVM emits for __builtin_trap, and it
/// prints it as `trap`.
fn udf(w: u32) -> Insn {
    if w >> 28 != 14 {
        return none(w);
    }
    if w == 0xe7ffdefe {
        return mk_u("trap", &[], f::TRAP);
    }
    let imm16 = (bits(w, 19, 8) << 4) | bits(w, 3, 0);
    mk_u("udf", &[imm_hex(imm16 as i64)], f::TRAP)
}

/// pkhbt/pkhtb, the sign and zero extensions (sxtb, uxtah…), ssat/usat, sel, rev, rbit.
fn packing(w: u32, op1: u32, op2: u32) -> Insn {
    let rn = bits(w, 19, 16);
    let rd = bits(w, 15, 12);
    let rm = bits(w, 3, 0);
    let rotate = bits(w, 11, 10);
    let ror = if rotate != 0 { Some(Op::Shift(cat!(ShiftText; "ror #", Dec((rotate * 8) as i64)))) } else { None };

    if (op2 & 1) == 0 {
        if op1 == 8 {
            let amount = bits(w, 11, 7);
            if op2 & 2 != 0 {
                return mk(w, "pkhtb", &[R(rd), R(rn), R(rm), Op::Shift(cat!(ShiftText; "asr #", Dec(if amount != 0 { amount } else { 32 } as i64)))], 0);
            }
            if amount != 0 {
                return mk(w, "pkhbt", &[R(rd), R(rn), R(rm), Op::Shift(cat!(ShiftText; "lsl #", Dec(amount as i64)))], 0);
            }
            return mk(w, "pkhbt", &[R(rd), R(rn), R(rm)], 0);
        }
        if (op1 & 2) == 0 {
            return none(w);
        }
        // ssat/usat: a shift of the source by lsl or asr.
        let amount = bits(w, 11, 7);
        let sh = if bit(w, 6) != 0 {
            Some(cat!(ShiftText; "asr #", Dec(if amount != 0 { amount } else { 32 } as i64)))
        } else if amount != 0 {
            Some(cat!(ShiftText; "lsl #", Dec(amount as i64)))
        } else {
            None
        };
        let sat = bits(w, 20, 16);
        let mut ops = Ops::new();
        ops.push(R(rd));
        ops.push(imm_hex(if op1 & 4 != 0 { sat } else { sat + 1 } as i64));
        ops.push(R(rm));
        if let Some(sh) = sh {
            ops.push(Op::Shift(sh));
        }
        return mk(w, if op1 & 4 != 0 { "usat" } else { "ssat" }, &ops, 0);
    }

    let ones = (w & 0xf0f00) == 0xf0f00;
    let extend = |name: &str| -> Insn {
        let mut ops = Ops::new();
        ops.push(R(rd));
        let m = if rn == PC {
            // sxtab16 → sxtb16: the name without its `a`.
            cat!(Mn; &name[..2], "t", &name[4..])
        } else {
            ops.push(R(rn));
            Mn::from(name)
        };
        ops.push(R(rm));
        if let Some(ror) = ror {
            ops.push(ror);
        }
        mk(w, &m, &ops, 0)
    };
    match (op1 << 3) | op2 {
        0x43 => extend("sxtab16"), // (8 << 3) | 3
        0x45 => mk(w, "sel", &[R(rd), R(rn), R(rm)], 0),
        0x51 => {
            // (10 << 3) | 1
            if bits(w, 11, 8) == 15 {
                mk(w, "ssat16", &[R(rd), imm_hex((rn + 1) as i64), R(rm)], 0)
            } else {
                none(w)
            }
        }
        0x53 => extend("sxtab"),
        0x59 => {
            if ones {
                mk(w, "rev", &[R(rd), R(rm)], 0)
            } else {
                none(w)
            }
        }
        0x5b => extend("sxtah"),
        0x5d => {
            if ones {
                mk(w, "rev16", &[R(rd), R(rm)], 0)
            } else {
                none(w)
            }
        }
        0x63 => extend("uxtab16"),
        0x71 => {
            if bits(w, 11, 8) == 15 {
                mk(w, "usat16", &[R(rd), imm_hex(rn as i64), R(rm)], 0)
            } else {
                none(w)
            }
        }
        0x73 => extend("uxtab"),
        0x79 => {
            if ones {
                mk(w, "rbit", &[R(rd), R(rm)], 0)
            } else {
                none(w)
            }
        }
        0x7b => extend("uxtah"),
        0x7d => {
            if ones {
                mk(w, "revsh", &[R(rd), R(rm)], 0)
            } else {
                none(w)
            }
        }
        _ => none(w),
    }
}

/* ------------------------------------------------------------------ *
 * Bits 27:25 = 100: ldm and stm in their four modes, push and pop, and the
 * user-register forms (`^`)
 * ------------------------------------------------------------------ */

const LDM_MODES: [&str; 4] = ["da", "", "db", "ib"];

fn block_transfer(w: u32) -> Insn {
    let mode = bits(w, 24, 23);
    let user = bit(w, 22);
    let wb = bit(w, 21);
    let load = bit(w, 20);
    let rn = bits(w, 19, 16);
    let mask = w & 0xffff;
    if mask == 0 {
        return none(w);
    }
    let mut regs = reg_list(mask);
    let many = regs.len() > 1;
    let mut f = if load != 0 { f::LOAD } else { f::STORE };
    if load != 0 && mask & 0x8000 != 0 {
        f |= f::BRANCH | f::INDIRECT;
        // pop {…, pc} (ldm sp! in the increment-after mode) is the usual return.
        if rn == SP && wb != 0 && mode == 1 {
            f |= f::RET;
        }
    }
    if user == 0 && wb != 0 && rn == SP && many && ((load != 0 && mode == 1) || (load == 0 && mode == 2)) {
        return mk(w, if load != 0 { "pop" } else { "push" }, &[Op::List(regs)], f).bytes(4);
    }
    regs.user = user != 0;
    mk(w, &cat2(if load != 0 { "ldm" } else { "stm" }, LDM_MODES[mode as usize]), &[reg(r(rn), wb != 0), Op::List(regs)], f).bytes(4)
}

/* ------------------------------------------------------------------ *
 * Bits 27:25 = 101: b and bl
 * ------------------------------------------------------------------ */

fn branch(w: u32, pc: i64) -> Insn {
    let target = pc_relative(pc, sext(w & 0xffffff, 24) as i64 * 4);
    if bit(w, 24) != 0 {
        return mk(w, "bl", &[label(target)], f::CALL).target(target).thumb(false);
    }
    mk(w, "b", &[label(target)], f::BRANCH).target(target)
}

/* ------------------------------------------------------------------ *
 * Bits 27:25 = 110 and 111: the coprocessor instructions and svc
 *
 * Armv8 keeps only coprocessors 14 and 15 (debug and system control) for
 * mcr, mrc, mcrr and mrrc, and only 14 for ldc and stc; cdp is gone. 10 and
 * 11 are floating point and SIMD, decoded in simd.rs.
 * ------------------------------------------------------------------ */

/// `p14`, `c3`: a coprocessor or one of its registers.
#[inline]
fn cp_text(prefix: &str, n: u32) -> Op {
    Op::Text(cat!(Text; prefix, Dec(n as i64)))
}

fn coprocessor(w: u32) -> Insn {
    if bits(w, 27, 24) == 15 {
        return mk(w, "svc", &[imm_hex((w & 0xffffff) as i64)], 0);
    }
    let cp = bits(w, 11, 8);
    if (cp & 0xe) != 0xe {
        return none(w);
    }
    let rn = bits(w, 19, 16);
    let rt = bits(w, 15, 12);
    if bits(w, 27, 25) == 6 {
        if bits(w, 24, 21) == 2 {
            // mcrr/mrrc: two core registers, one 64-bit coprocessor register.
            let m = if bit(w, 20) != 0 { "mrrc" } else { "mcrr" };
            return mk(w, m, &[cp_text("p", cp), imm_hex(bits(w, 7, 4) as i64), R(rt), R(rn), cp_text("c", w & 15)], 0);
        }
        return load_store_coprocessor(w);
    }
    // cdp is gone from Armv8 altogether.
    if bit(w, 4) == 0 {
        return none(w);
    }
    let to_core = bit(w, 20) != 0;
    let core = if to_core && rt == PC { text("apsr_nzcv") } else { R(rt) };
    mk(
        w,
        if to_core { "mrc" } else { "mcr" },
        &[cp_text("p", cp), imm_hex(bits(w, 23, 21) as i64), core, cp_text("c", rn), cp_text("c", w & 15), imm_hex(bits(w, 7, 5) as i64)],
        if to_core && rt == PC { f::SETS_FLAGS } else { 0 },
    )
}

/// ldc/stc: addressing mode 5, a word offset printed in decimal, or an option `{imm}`.
fn load_store_coprocessor(w: u32) -> Insn {
    let p = bit(w, 24);
    let u = bit(w, 23);
    let long = bit(w, 22);
    let wb = bit(w, 21);
    let load = bit(w, 20);
    let rn = bits(w, 19, 16);
    let cp = bits(w, 11, 8);
    if cp != 14 {
        return none(w);
    }
    if p == 0 && wb == 0 && u == 0 {
        return none(w);
    }
    let imm8 = (w & 0xff) as i64;
    let sign = if u != 0 { "" } else { "-" };
    let base = r(rn);
    let off = if u != 0 { imm8 * 4 } else { -imm8 * 4 };
    let address = if p != 0 {
        let mut t = if imm8 != 0 || u == 0 || wb != 0 { cat!(MemText; "[", base, ", #", sign, Dec(imm8 * 4), "]") } else { cat!(MemText; "[", base, "]") };
        if wb != 0 {
            t.push("!");
        }
        mem(rn, t, if wb != 0 { Mode::Pre } else { Mode::Off }, Some(off), None)
    } else if wb != 0 {
        mem(rn, cat!(MemText; "[", base, "], #", sign, Dec(imm8 * 4)), Mode::Post, Some(off), None)
    } else {
        mem(rn, cat!(MemText; "[", base, "], {", Dec(imm8), "}"), Mode::Off, None, None)
    };
    let m = cat2(if load != 0 { "ldc" } else { "stc" }, if long != 0 { "l" } else { "" });
    mk(w, &m, &[cp_text("p", cp), cp_text("c", bits(w, 15, 12)), address], if load != 0 { f::LOAD } else { f::STORE })
}

/* ------------------------------------------------------------------ *
 * cond = 1111: the unconditional instructions — cps, setend, setpan,
 * preloads, barriers, clrex, srs, rfe and blx to an immediate
 * ------------------------------------------------------------------ */

fn unconditional(w: u32, pc: i64) -> Insn {
    let op = bits(w, 27, 25);
    if op == 5 {
        let target = pc_relative(pc, sext(w & 0xffffff, 24) as i64 * 4 + bit(w, 24) as i64 * 2);
        return mk_u("blx", &[label(target)], f::CALL).target(target).thumb(true);
    }
    if op == 4 {
        return return_state(w);
    }
    if op >= 6 {
        return none(w);
    }
    unconditional_misc(w, pc)
}

/// srs (store return state) and rfe (return from exception). LLVM decodes an
/// rfe whose low bits are not the architected 0x0a00 through its ldm decoder
/// when it writes back, and then prints the addressing mode where the base
/// register should be (`rfeia #0x1!`); without writeback it gives up.
fn return_state(w: u32) -> Insn {
    let mode_bits = bits(w, 24, 23);
    let mode = match LDM_MODES[mode_bits as usize] {
        "" => "ia",
        m => m,
    };
    let wb = bit(w, 21);
    if bit(w, 20) != 0 {
        if bit(w, 22) != 0 {
            return none(w);
        }
        let f = f::BRANCH | f::INDIRECT | f::RET | f::LOAD;
        if (w & 0xffff) != 0x0a00 {
            return if wb != 0 { mk_u(&cat2("rfe", mode), &[Op::Text(cat!(Text; "#", Hex(SUBMODE[mode_bits as usize]), "!"))], f) } else { none(w) };
        }
        let rn = bits(w, 19, 16);
        return mk_u(&cat2("rfe", mode), &[reg(r(rn), wb != 0)], f);
    }
    if bit(w, 22) == 0 || (w & 0xfffe0) != 0xd0500 {
        return none(w);
    }
    mk_u(&cat2("srs", mode), &[reg(r(SP), wb != 0), imm_hex((w & 31) as i64)], f::STORE)
}

/// LLVM's numbering of the ldm/stm modes (ARM_AM::AMSubMode), indexed by bits 24:23.
const SUBMODE: [i64; 4] = [3, 1, 4, 2];

pub(crate) const BARRIER_OPTIONS: [&str; 16] = ["#0x0", "oshld", "oshst", "osh", "#0x4", "nshld", "nshst", "nsh", "#0x8", "ishld", "ishst", "ish", "#0xc", "ld", "st", "sy"];

fn unconditional_misc(w: u32, pc: i64) -> Insn {
    let op1 = bits(w, 26, 20);
    if op1 == 0x10 {
        if bit(w, 16) != 0 {
            return if (w & 0x0ffffdff) == 0x01010000 { mk_u("setend", &[text(if bit(w, 9) != 0 { "be" } else { "le" })], 0) } else { none(w) };
        }
        return change_processor_state(w);
    }
    if op1 == 0x11 {
        // setpan: only bits 7:4 must be zero; the other unused bits are UNPREDICTABLE.
        if bits(w, 7, 4) != 0 {
            return none(w);
        }
        return mk_u("setpan", &[imm_hex(bit(w, 9) as i64)], 0);
    }
    if op1 == 0x57 {
        let option = w & 15;
        if bits(w, 7, 4) == 7 {
            return mk_u("sb", &[], 0);
        }
        if bits(w, 19, 8) != 0xff0 {
            return none(w);
        }
        return match bits(w, 7, 4) {
            1 => {
                if option == 15 {
                    mk_u("clrex", &[], 0)
                } else {
                    none(w)
                }
            }
            4 => {
                if option == 0 {
                    return mk_u("ssbb", &[], 0);
                }
                if option == 4 {
                    return mk_u("pssbb", &[], 0);
                }
                mk_u("dsb", &[text(BARRIER_OPTIONS[option as usize])], 0)
            }
            5 => mk_u("dmb", &[text(BARRIER_OPTIONS[option as usize])], 0),
            6 => {
                if option == 15 {
                    mk_u("isb", &[text("sy")], 0)
                } else {
                    mk_u("isb", &[Op::Text(cat!(Text; "#", Hex(option as i64)))], 0)
                }
            }
            _ => none(w),
        };
    }
    // Preloads: pli (bits 26:24 = 100), pld/pldw (101, bit 22 = 1 for pld).
    if (op1 & 0x47) == 0x45 || (op1 & 0x47) == 0x41 {
        let is_reg = bit(w, 25);
        if (is_reg != 0 && bit(w, 4) != 0) || bits(w, 15, 12) != 15 {
            return none(w);
        }
        let m = if op1 & 0x10 != 0 {
            if bit(w, 22) != 0 {
                "pld"
            } else {
                "pldw"
            }
        } else {
            "pli"
        };
        if m == "pli" && bit(w, 22) == 0 {
            return none(w);
        }
        return preload(w, pc, m);
    }
    none(w)
}

/// pld, pldw, pli: addressing mode 2 without writeback.
fn preload(w: u32, pc: i64, m: &str) -> Insn {
    let u = bit(w, 23);
    let rn = bits(w, 19, 16);
    let base = r(rn);
    if bit(w, 25) == 0 {
        let imm = (w & 0xfff) as i64;
        let t = if u != 0 {
            if imm != 0 {
                cat!(MemText; "[", base, ", #", Hex(imm), "]")
            } else {
                cat!(MemText; "[", base, "]")
            }
        } else {
            cat!(MemText; "[", base, ", #-", Hex(imm), "]")
        };
        let off = if u != 0 { imm } else { -imm };
        let insn = mk_u(m, &[mem(rn, t, Mode::Off, Some(off), None)], 0);
        return if rn == PC { insn.target(pc_relative(pc, off)) } else { insn };
    }
    let rm = bits(w, 3, 0);
    let mut t = cat!(MemText; "[", base, ", ");
    index_text(&mut t, u, rm, bits(w, 6, 5), bits(w, 11, 7));
    t.push("]");
    mk_u(m, &[mem(rn, t, Mode::Off, None, Some(rm))], 0)
}

/// cps, cpsie, cpsid: the interrupt masks and the mode. LLVM's encodings want
/// bits 15:9 zero, and a zero mode unless M (bit 17) says it changes; but it
/// also reaches its cps decoder from the qadd and smla<x><y> encodings it
/// shares (bits 7:4 = 0101, 1000, 1100), which look at neither.
fn change_processor_state(w: u32) -> Insn {
    let low = bits(w, 7, 4);
    let imod = bits(w, 19, 18);
    let change_mode = bit(w, 17);
    let mode = w & 31;
    let shared = low == 5 || low == 8 || low == 12;
    if bit(w, 5) != 0 || bit(w, 16) != 0 || imod == 1 {
        return none(w);
    }
    if !shared && (bits(w, 15, 9) != 0 || (change_mode == 0 && mode != 0)) {
        return none(w);
    }
    if imod == 0 {
        return mk_u("cps", &[imm_hex(mode as i64)], 0);
    }
    let flags = bits(w, 8, 6);
    let names = cpsie_flags(flags & 4 != 0, flags & 2 != 0, flags & 1 != 0);
    let m = if imod == 2 { "cpsie" } else { "cpsid" };
    if change_mode != 0 {
        return mk_u(m, &[names, imm_hex(mode as i64)], 0);
    }
    mk_u(m, &[names], 0)
}

/// `aif`, `i`, or `none` for no flags.
pub(crate) fn cpsie_flags(a: bool, i: bool, f: bool) -> Op {
    let t = cat!(Text; if a { "a" } else { "" }, if i { "i" } else { "" }, if f { "f" } else { "" });
    if t.is_empty() {
        text("none")
    } else {
        Op::Text(t)
    }
}
