//! What the floating-point and SIMD decoders share: register operands, the
//! way a mnemonic takes its condition and data type, and the immediates LLVM
//! prints in its own formats.
//!
//! Every decoder here reads an A32-shaped word. T32 encodings are turned into
//! their A32 twins first (simd.rs), so `Ctx` says what the word really was:
//! the condition it executes under and whether it came from Thumb code.

use super::types::*;
use crate::text::{push_dec, Str};

pub struct Ctx {
    /// The instruction as it was encoded (the T32 word for Thumb), for `.inst`.
    pub raw: u32,
    pub pc: i64,
    pub thumb: bool,
    /// The condition: the A32 field, or the IT block's in Thumb; 14 is always, 15 (Thumb only) the "else" of an IT on AL.
    pub cond: i32,
}

pub use super::types::{bit, bits};

/* ------------------------------------------------------------------ *
 * Registers
 * ------------------------------------------------------------------ */

macro_rules! names {
    ($p:literal; $($n:literal)*) => {
        [$(Name::from_static(concat!($p, $n))),*]
    };
}

static SREGS: [Name; 32] =
    names!("s"; "0" "1" "2" "3" "4" "5" "6" "7" "8" "9" "10" "11" "12" "13" "14" "15" "16" "17" "18" "19" "20" "21" "22" "23" "24" "25" "26" "27" "28" "29" "30" "31");
/// d0…d31, then the registers that follow d31 in LLVM's numbering (see `dname`).
static DNAMES: [Name; 35] = {
    let d: [Name; 32] =
        names!("d"; "0" "1" "2" "3" "4" "5" "6" "7" "8" "9" "10" "11" "12" "13" "14" "15" "16" "17" "18" "19" "20" "21" "22" "23" "24" "25" "26" "27" "28" "29" "30" "31");
    let mut out = [Name::new(); 35];
    let mut i = 0;
    while i < 32 {
        out[i] = d[i];
        i += 1;
    }
    out[32] = Name::from_static("fpinst2");
    out[33] = Name::from_static("mvfr0");
    out[34] = Name::from_static("mvfr1");
    out
};
static QREGS: [Name; 16] = names!("q"; "0" "1" "2" "3" "4" "5" "6" "7" "8" "9" "10" "11" "12" "13" "14" "15");

#[allow(non_snake_case)]
#[inline(always)]
pub fn S(n: u32) -> Op {
    reg(SREGS[(n & 31) as usize], false)
}
#[allow(non_snake_case)]
#[inline(always)]
pub fn D(n: u32) -> Op {
    reg(DNAMES[(n & 31) as usize], false)
}
/// A Q register from its D-register number (always even here).
#[allow(non_snake_case)]
#[inline(always)]
pub fn Q(n: u32) -> Op {
    reg(QREGS[((n >> 1) & 15) as usize], false)
}
#[allow(non_snake_case)]
#[inline(always)]
pub fn R(n: u32) -> Op {
    reg(r(n), false)
}
/// A D register, or a Q register when `q` is set: the shape of most vector operands.
#[allow(non_snake_case)]
#[inline(always)]
pub fn V(n: u32, q: u32) -> Op {
    if q != 0 {
        Q(n)
    } else {
        D(n)
    }
}

/// The name LLVM prints for the D register `n` places after d0. Lists of three
/// or four consecutive registers are printed by stepping through LLVM's
/// register numbering, so past d31 they run on into the registers that follow
/// it there: `{d30, d31, fpinst2}`.
#[inline]
pub fn dname(n: u32) -> Name {
    match DNAMES.get(n as usize) {
        Some(name) => *name,
        None => {
            let mut name = Name::from("d");
            push_dec(&mut name, n as i64);
            name
        }
    }
}

/// `s${n}`.
#[inline]
pub fn sname(n: u32) -> Name {
    match SREGS.get(n as usize) {
        Some(name) => *name,
        None => {
            let mut name = Name::from("s");
            push_dec(&mut name, n as i64);
            name
        }
    }
}

/// A lane suffix of `dlist`.
#[derive(Clone, Copy)]
pub enum Suffix {
    None,
    /// `[]`
    All,
    /// `[i]`
    Lane(u32),
}

/// `{d4, d5, d6}`: `count` registers from `first`, `step` apart, each followed by `suffix` (`[]`, `[1]`).
#[inline]
pub fn dlist(first: u32, count: u32, step: u32, suffix: Suffix, wrap: bool) -> Op {
    let mut regs = List::new(Bank::D);
    for i in 0..count {
        let n = first + i * step;
        regs.push(if wrap { n & 31 } else { n });
    }
    Op::List(match suffix {
        Suffix::None => regs,
        Suffix::All => regs.all_lanes(),
        Suffix::Lane(i) => regs.lane(i),
    })
}

/// The D (or S) register number from a 4-bit field and its extra bit: D:Vd for D, Vd:D for S.
#[inline(always)]
pub fn dreg(w: u32, lo: u32, extra: u32) -> u32 {
    (bit(w, extra) << 4) | bits(w, lo + 3, lo)
}
#[inline(always)]
pub fn sreg(w: u32, lo: u32, extra: u32) -> u32 {
    (bits(w, lo + 3, lo) << 1) | bit(w, extra)
}

/// Vd, Vn, Vm of the usual places: Vd = D:Vd(22, 15-12), Vn = N:Vn(7, 19-16), Vm = M:Vm(5, 3-0).
#[inline(always)]
pub fn vd(w: u32) -> u32 {
    dreg(w, 12, 22)
}
#[inline(always)]
pub fn vn(w: u32) -> u32 {
    dreg(w, 16, 7)
}
#[inline(always)]
pub fn vm(w: u32) -> u32 {
    dreg(w, 0, 5)
}
#[inline(always)]
pub fn sd(w: u32) -> u32 {
    sreg(w, 12, 22)
}
#[inline(always)]
pub fn sn(w: u32) -> u32 {
    sreg(w, 16, 7)
}
#[inline(always)]
pub fn sm(w: u32) -> u32 {
    sreg(w, 0, 5)
}

/// A register with a lane: `d3[1]`, `s5[0]`.
#[inline]
pub fn lane_reg(prefix: &str, n: u32, index: u32) -> Op {
    let mut name = Name::from(prefix);
    push_dec(&mut name, n as i64);
    name.push("[");
    push_dec(&mut name, index as i64);
    name.push("]");
    reg(name, false)
}

/* ------------------------------------------------------------------ *
 * Data types
 * ------------------------------------------------------------------ */

/// A data type as printed after the mnemonic's dot: `f32`, `u16`, `s32.f64`, `bf16.f32`.
pub type Dt = Str<15>;

/// `${prefix}${n}`: `s16`, `i64`, `32`.
#[inline]
pub fn dt_num(prefix: &str, n: u32) -> Dt {
    let mut dt = Dt::from(prefix);
    push_dec(&mut dt, n as i64);
    dt
}

/// `${a}.${b}`.
#[inline]
pub fn dt_pair(a: &str, b: &str) -> Dt {
    let mut dt = Dt::from(a);
    dt.push(".");
    dt.push(b);
    dt
}

/* ------------------------------------------------------------------ *
 * Instructions
 * ------------------------------------------------------------------ */

/// An instruction under the context's condition. `predicable` instructions
/// print it between the operation and the data type (`vaddeq.f32`,
/// `vldmiane`); the Armv8 additions (vsel, vrinta, the crypto ones…) cannot
/// be conditional and never print one.
#[inline]
pub fn mk(ctx: &Ctx, op: &str, dt: &str, ops: &[Op], f: u32, predicable: bool) -> Insn {
    let mut m = Mn::from(op);
    let mut flags = f;
    let mut cond_name = None;
    if predicable && ctx.cond != 14 {
        if ctx.cond == 15 {
            // The "else" half of an IT block on AL: LLVM marks the impossible condition.
            m.push("<und>");
        } else {
            cond_name = cond_at(ctx.cond);
            m.push(cond_text(ctx.cond));
            flags |= f::COND | f::READS_FLAGS;
        }
    }
    if !dt.is_empty() {
        m.push(".");
        m.push(dt);
    }
    let mut insn = Insn::new(m, ops, flags, 4);
    insn.cond = cond_name;
    insn
}

/// An encoding of this space that is not an instruction.
#[inline]
pub fn undef(ctx: &Ctx) -> Insn {
    unknown(ctx.raw, 4, ctx.thumb)
}

/* ------------------------------------------------------------------ *
 * Immediates
 * ------------------------------------------------------------------ */

/// `#0x1f`: what LLVM prints for most NEON immediates (shift amounts, vext indexes).
#[inline]
pub fn ih(v: i64) -> Op {
    imm_hex(v)
}
/// `#-13`: decimal, as fixed-point fraction bits print.
#[inline]
pub fn id(v: i64) -> Op {
    imm_dec(v)
}

/// The value of the 8-bit floating-point immediate of vmov.f32/.f64/.f16 (VFPExpandImm).
pub fn fp_imm8(imm8: u32) -> f64 {
    let sign = if imm8 & 0x80 != 0 { -1.0 } else { 1.0 };
    let exponent = ((((imm8 >> 4) & 7) ^ 4) as i32) - 3;
    sign * ((16 + (imm8 & 15)) as f64 / 16.0) * 2f64.powi(exponent)
}

/// The operand of an 8-bit floating-point immediate, as LLVM prints it with C's `%e`: `#5.000000e-01`.
///
/// The TypeScript core formats the value with `toExponential(6)`. The value is
/// ±(16 + m) · 2^(e - 4) for m in 0…15, e in -3…4: times 10^7 it is an integer of at
/// most seven significant digits, so its digits are exact and are written out here directly.
pub fn fp_imm_op(imm8: u32) -> Op {
    let imm8 = imm8 & 0xff;
    let value = fp_imm8(imm8);
    let e = ((((imm8 >> 4) & 7) ^ 4) as i32) - 3;
    // value · 10^7 = (16 + m) · 10^7 / 2^(4 - e), 4 - e in 0…7.
    let scaled = ((16 + (imm8 & 15)) as u64 * 10_000_000) >> (4 - e);
    let mut digits = Str::<12>::new();
    push_dec(&mut digits, scaled as i64);
    let d = digits.as_bytes();
    // d[0].d[1..7] × 10^(len - 1 - 7)
    let exp10 = d.len() as i32 - 1 - 7;
    let mut t = ImmText::from("#");
    if imm8 & 0x80 != 0 {
        t.push("-");
    }
    t.push_byte(d[0]);
    t.push(".");
    for i in 1..7 {
        t.push_byte(if i < d.len() { d[i] } else { b'0' });
    }
    t.push(if exp10 < 0 { "e-" } else { "e+" });
    let a = exp10.unsigned_abs();
    t.push_byte(b'0' + (a / 10) as u8);
    t.push_byte(b'0' + (a % 10) as u8);
    Op::Imm { v: value, t }
}
