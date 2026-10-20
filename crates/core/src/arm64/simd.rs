//! SIMD and floating point: scalar FP arithmetic and conversions, the
//! Advanced SIMD (NEON) vector instructions, the cryptographic extensions and
//! the SIMD structure loads and stores (ld1…ld4, st1…st4).
//!
//! Registers print in the generic Arm syntax, `cmeq v0.8b, v1.8b, v2.8b`,
//! not Apple's `cmeq.8b v0, v1, v2`. Half-precision arithmetic (FP16), the
//! dot-product, matrix-multiply, BFloat16, complex and FP8 extensions are all
//! here; only SVE and SME, which have their own encoding space, are left as
//! `.inst`.
//!
//! A port of simd.ts: the same functions, tables and checks, in the same order.

use super::decode::{bit, bits, fp_reg, unknown, wr, xr, xs};
use super::types::*;
use crate::sfmt;
use crate::text::push_dec;

const ARR: [&str; 8] = ["8b", "16b", "4h", "8h", "2s", "4s", "1d", "2d"];

#[inline]
fn arr(size: u32, q: u32) -> &'static str {
    ARR[(size * 2 + q) as usize]
}

const WIDE: [&str; 4] = ["8h", "4s", "2d", "1q"];

/// `v{n}.{a}`: a vector register with its arrangement.
#[inline]
fn v(n: u32, a: &str) -> Op {
    let mut r = Name::from("v");
    push_dec(&mut r, n as i64);
    r.push(".");
    r.push(a);
    Op::Reg(r)
}

/// `v{n}.{t}[{i}]`: one element (or, with `4b`, `2b`, `2h`, one group of them).
#[inline]
fn el(n: u32, t: &str, i: u32) -> Op {
    let mut r = Name::from("v");
    push_dec(&mut r, n as i64);
    r.push(".");
    r.push(t);
    r.push("[");
    push_dec(&mut r, i as i64);
    r.push("]");
    Op::Reg(r)
}

/// A scalar register by its prefix letter: `b`, `h`, `s`, `d`, `q`.
#[inline]
fn sc(prefix: u8, n: u32) -> Op {
    reg(fp_reg(prefix, n))
}

/// The mnemonic with `2` appended for the upper-half forms (Q set).
#[inline]
fn two(m: &str, q: u32) -> Mn {
    let mut out = Mn::from(m);
    if q != 0 {
        out.push("2");
    }
    out
}

#[inline]
fn zero_fp() -> Op {
    text("#0.0")
}

#[inline]
fn zero() -> Op {
    imm_dec(0)
}

/// The 8-bit floating-point immediate of fmov (VFPExpandImm).
pub fn fp_imm(imm8: u32) -> f64 {
    let sign = if imm8 & 0x80 != 0 { -1.0 } else { 1.0 };
    let exponent = ((((imm8 >> 4) & 7) ^ 4) as i32) - 3;
    sign * ((16 + (imm8 & 15)) as f64 / 16.0) * 2f64.powi(exponent)
}

/// `#value` with eight decimals, JavaScript's `toFixed(8)`: the values are short binary fractions, printed exactly.
fn fp_imm_op(imm8: u32) -> Op {
    let value = fp_imm(imm8);
    Op::Imm { v: value, t: sfmt!(ImmText, "#{:.8}", value) }
}

/// LLVM prints 64-bit SIMD immediates with printf's "%#016llx".
fn simd64(value: u64) -> Op {
    let t = if value == 0 { ImmText::from("#0000000000000000") } else { sfmt!(ImmText, "#0x{:014x}", value) };
    Op::Imm { v: value as f64, t }
}

/* ------------------------------------------------------------------ *
 * Scalar floating point
 * ------------------------------------------------------------------ */

#[inline]
fn fp_prefix(ftype: u32) -> Option<u8> {
    match ftype {
        0 => Some(b's'),
        1 => Some(b'd'),
        3 => Some(b'h'),
        _ => None,
    }
}

/// FEAT_FPRCVT: the same conversions with the integer in a SIMD register (s or
/// d by sf), by rmode:opcode. Only sizes that differ are encoded here; equal
/// sizes are the Advanced SIMD scalar forms.
fn fprcvt(key: u32) -> Option<&'static str> {
    Some(match key {
        0b01010 => "fcvtns",
        0b01011 => "fcvtnu",
        0b10010 => "fcvtps",
        0b10011 => "fcvtpu",
        0b10100 => "fcvtms",
        0b10101 => "fcvtmu",
        0b10110 => "fcvtzs",
        0b10111 => "fcvtzu",
        0b11010 => "fcvtas",
        0b11011 => "fcvtau",
        0b11100 => "scvtf",
        0b11101 => "ucvtf",
        _ => return None,
    })
}

fn fp_int_convert(w: u32) -> Insn {
    let sf = bit(w, 31);
    let ftype = bits(w, 23, 22);
    let rmode = bits(w, 20, 19);
    let opcode = bits(w, 18, 16);
    let rn = bits(w, 9, 5);
    let rd = bits(w, 4, 0);
    if bit(w, 29) != 0 {
        return unknown(w);
    }
    if rmode == 1 && opcode & 6 == 6 {
        if sf == 0 || ftype != 2 {
            return unknown(w);
        }
        return if opcode == 6 { mk("fmov", &[reg(xr(rd)), el(rn, "d", 1)], 0) } else { mk("fmov", &[el(rd, "d", 1), reg(xr(rn))], 0) };
    }
    if rmode == 3 && opcode == 6 {
        return if sf == 0 && ftype == 1 { mk("fjcvtzs", &[reg(wr(rd)), sc(b'd', rn)], f::SETS_FLAGS) } else { unknown(w) };
    }
    let Some(p) = fp_prefix(ftype) else { return unknown(w) };
    if let Some(simd_int) = fprcvt((rmode << 3) | opcode) {
        let i = if sf != 0 { b'd' } else { b's' };
        if i == p {
            return unknown(w);
        }
        return if simd_int.ends_with("cvtf") { mk(simd_int, &[sc(p, rd), sc(i, rn)], 0) } else { mk(simd_int, &[sc(i, rd), sc(p, rn)], 0) };
    }
    let g: fn(u32) -> Name = if sf != 0 { xr } else { wr };
    if opcode == 6 || opcode == 7 {
        if rmode != 0 {
            return unknown(w);
        }
        if p == b's' && sf != 0 {
            return unknown(w);
        }
        if p == b'd' && sf == 0 {
            return unknown(w);
        }
        return if opcode == 6 { mk("fmov", &[reg(g(rd)), sc(p, rn)], 0) } else { mk("fmov", &[sc(p, rd), reg(g(rn))], 0) };
    }
    if opcode == 2 || opcode == 3 {
        if rmode != 0 {
            return unknown(w);
        }
        return mk(if opcode == 2 { "scvtf" } else { "ucvtf" }, &[sc(p, rd), reg(g(rn))], 0);
    }
    let round = if opcode >= 4 { "a" } else { ["n", "p", "m", "z"][rmode as usize] };
    if opcode >= 4 && rmode != 0 {
        return unknown(w);
    }
    Insn::new(sfmt!(Mn, "fcvt{}{}", round, if opcode & 1 != 0 { "u" } else { "s" }), &[reg(g(rd)), sc(p, rn)], 0)
}

fn fp_fixed_convert(w: u32) -> Insn {
    let sf = bit(w, 31);
    let ftype = bits(w, 23, 22);
    let rmode = bits(w, 20, 19);
    let opcode = bits(w, 18, 16);
    let scale = bits(w, 15, 10);
    let p = match fp_prefix(ftype) {
        Some(p) if !(sf == 0 && scale < 32) => p,
        _ => return unknown(w),
    };
    let g: fn(u32) -> Name = if sf != 0 { xr } else { wr };
    let fbits = imm(64 - scale as i64);
    let rn = bits(w, 9, 5);
    let rd = bits(w, 4, 0);
    if rmode == 0 && (opcode == 2 || opcode == 3) {
        return mk(if opcode == 2 { "scvtf" } else { "ucvtf" }, &[sc(p, rd), reg(g(rn)), fbits], 0);
    }
    if rmode == 3 && (opcode == 0 || opcode == 1) {
        return mk(if opcode != 0 { "fcvtzu" } else { "fcvtzs" }, &[reg(g(rd)), sc(p, rn), fbits], 0);
    }
    unknown(w)
}

const FP1: [&str; 20] =
    ["fmov", "fabs", "fneg", "fsqrt", "", "", "", "", "frintn", "frintp", "frintm", "frintz", "frinta", "", "frintx", "frinti", "frint32z", "frint32x", "frint64z", "frint64x"];

fn fp1(w: u32) -> Insn {
    let ftype = bits(w, 23, 22);
    let opcode = bits(w, 20, 15);
    let rn = bits(w, 9, 5);
    let rd = bits(w, 4, 0);
    let p = match fp_prefix(ftype) {
        Some(p) if bit(w, 29) == 0 && bit(w, 31) == 0 => p,
        _ => return unknown(w),
    };
    if (4..=7).contains(&opcode) {
        let to = [b's', b'd', 0, b'h'][(opcode - 4) as usize];
        if opcode == 6 {
            return if ftype == 1 { mk("bfcvt", &[sc(b'h', rd), sc(b's', rn)], 0) } else { unknown(w) };
        }
        if to == 0 || to == p {
            return unknown(w);
        }
        return mk("fcvt", &[sc(to, rd), sc(p, rn)], 0);
    }
    match FP1.get(opcode as usize) {
        Some(&m) if !(m.is_empty() || (opcode >= 16 && p == b'h')) => mk(m, &[sc(p, rd), sc(p, rn)], 0),
        _ => unknown(w),
    }
}

fn fp_compare(w: u32) -> Insn {
    let ftype = bits(w, 23, 22);
    let op2 = bits(w, 4, 0);
    let p = match fp_prefix(ftype) {
        Some(p) if bits(w, 15, 14) == 0 && op2 & 7 == 0 => p,
        _ => return unknown(w),
    };
    let m = if op2 & 16 != 0 { "fcmpe" } else { "fcmp" };
    let rn = bits(w, 9, 5);
    if op2 & 8 != 0 {
        return mk(m, &[sc(p, rn), zero_fp()], f::SETS_FLAGS);
    }
    mk(m, &[sc(p, rn), sc(p, bits(w, 20, 16))], f::SETS_FLAGS)
}

const FP2: [&str; 9] = ["fmul", "fdiv", "fadd", "fsub", "fmax", "fmin", "fmaxnm", "fminnm", "fnmul"];

fn scalar_fp(w: u32) -> Insn {
    // Conversions to and from integers keep sf in bit 31; everything else needs M = S = 0 there.
    let conversion = bit(w, 24) == 0 && (bit(w, 21) == 0 || bits(w, 15, 10) == 0);
    if bit(w, 29) != 0 || (!conversion && bit(w, 31) != 0) {
        return unknown(w);
    }
    // x0x1 1x: data processing, 3 source
    if bit(w, 24) != 0 {
        let Some(p) = fp_prefix(bits(w, 23, 22)) else { return unknown(w) };
        let m = ["fmadd", "fmsub", "fnmadd", "fnmsub"][((bit(w, 21) << 1) | bit(w, 15)) as usize];
        return mk(m, &[sc(p, bits(w, 4, 0)), sc(p, bits(w, 9, 5)), sc(p, bits(w, 20, 16)), sc(p, bits(w, 14, 10))], 0);
    }
    if bit(w, 21) == 0 {
        return fp_fixed_convert(w);
    }
    let op3 = bits(w, 15, 10);
    if op3 & 0x3f == 0 {
        return fp_int_convert(w);
    }
    if op3 & 0x1f == 0x10 {
        return fp1(w);
    }
    if op3 & 0xf == 8 {
        return fp_compare(w);
    }
    if op3 & 7 == 4 {
        let p = match fp_prefix(bits(w, 23, 22)) {
            Some(p) if bits(w, 9, 5) == 0 => p,
            _ => return unknown(w),
        };
        return mk("fmov", &[sc(p, bits(w, 4, 0)), fp_imm_op(bits(w, 20, 13))], 0);
    }
    let Some(p) = fp_prefix(bits(w, 23, 22)) else { return unknown(w) };
    let rm = bits(w, 20, 16);
    let rn = bits(w, 9, 5);
    let rd = bits(w, 4, 0);
    let c = CONDITIONS[bits(w, 15, 12) as usize];
    match op3 & 3 {
        1 => mk(if bit(w, 4) != 0 { "fccmpe" } else { "fccmp" }, &[sc(p, rn), sc(p, rm), imm(bits(w, 3, 0) as i64), text(c)], f::SETS_FLAGS | f::READS_FLAGS).cond(c),
        2 => match FP2.get(bits(w, 15, 12) as usize) {
            Some(&m) => mk(m, &[sc(p, rd), sc(p, rn), sc(p, rm)], 0),
            None => unknown(w),
        },
        3 => mk("fcsel", &[sc(p, rd), sc(p, rn), sc(p, rm), text(c)], f::READS_FLAGS).cond(c),
        _ => unknown(w),
    }
}

/* ------------------------------------------------------------------ *
 * Advanced SIMD — vector
 * ------------------------------------------------------------------ */

const SAME_U0: [&str; 24] = [
    "shadd", "sqadd", "srhadd", "", "shsub", "sqsub", "cmgt", "cmge", "sshl", "sqshl", "srshl", "sqrshl", "smax", "smin", "sabd", "saba", "add", "cmtst", "mla", "mul", "smaxp",
    "sminp", "sqdmulh", "addp",
];
const SAME_U1: [&str; 24] = [
    "uhadd", "uqadd", "urhadd", "", "uhsub", "uqsub", "cmhi", "cmhs", "ushl", "uqshl", "urshl", "uqrshl", "umax", "umin", "uabd", "uaba", "sub", "cmeq", "mls", "pmul", "umaxp",
    "uminp", "sqrdmulh", "",
];

/// A non-empty entry of an integer three-same table (`undefined` and `''` in the TypeScript both mean none).
#[inline]
fn same_int(u: u32, opcode: u32) -> Option<&'static str> {
    let table = if u != 0 { &SAME_U1 } else { &SAME_U0 };
    table.get(opcode as usize).copied().filter(|m| !m.is_empty())
}

/// FP three-same, by U, size<1> and opcode<2:0>; the half-precision group uses
/// the same table with a in place of size<1>.
const SAME_FP: [[[&str; 8]; 2]; 2] = [
    [["fmaxnm", "fmla", "fadd", "fmulx", "fcmeq", "", "fmax", "frecps"], ["fminnm", "fmls", "fsub", "famax", "", "", "fmin", "frsqrts"]],
    [["fmaxnmp", "", "faddp", "fmul", "fcmge", "facge", "fmaxp", "fdiv"], ["fminnmp", "", "fabd", "famin", "fcmgt", "facgt", "fminp", "fscale"]],
];

#[inline]
fn same_fp(u: u32, hi: u32, op: u32) -> Option<&'static str> {
    Some(SAME_FP[u as usize][hi as usize][op as usize]).filter(|m| !m.is_empty())
}

/// FEAT_FHM sits in the single-precision slots the table leaves free: half-precision sources, single-precision sums.
#[inline]
fn same_fhm(u: u32, hi: u32, op: u32) -> Option<&'static str> {
    match (u, hi, op) {
        (0, 0, 5) => Some("fmlal"),
        (0, 1, 5) => Some("fmlsl"),
        (1, 0, 1) => Some("fmlal2"),
        (1, 1, 1) => Some("fmlsl2"),
        _ => None,
    }
}

fn three_same(w: u32) -> Insn {
    let q = bit(w, 30);
    let u = bit(w, 29);
    let size = bits(w, 23, 22);
    let rm = bits(w, 20, 16);
    let opcode = bits(w, 15, 11);
    let rn = bits(w, 9, 5);
    let rd = bits(w, 4, 0);
    if opcode == 3 {
        let m = (if u != 0 { ["eor", "bsl", "bit", "bif"] } else { ["and", "bic", "orr", "orn"] })[size as usize];
        let a = if q != 0 { "16b" } else { "8b" };
        if m == "orr" && rm == rn {
            return mk("mov", &[v(rd, a), v(rn, a)], 0);
        }
        return mk(m, &[v(rd, a), v(rn, a), v(rm, a)], 0);
    }
    if opcode >= 24 {
        let (hi, op) = (size >> 1, opcode & 7);
        let sz = size & 1;
        if let Some(fhm) = same_fhm(u, hi, op) {
            let h = if q != 0 { "4h" } else { "2h" };
            return if sz != 0 { unknown(w) } else { mk(fhm, &[v(rd, arr(2, q)), v(rn, h), v(rm, h)], 0) };
        }
        let m = match same_fp(u, hi, op) {
            Some(m) if !(sz != 0 && q == 0) => m,
            _ => return unknown(w),
        };
        let a = arr(2 + sz, q);
        return mk(m, &[v(rd, a), v(rn, a), v(rm, a)], 0);
    }
    let m = match same_int(u, opcode) {
        Some(m) if !(size == 3 && q == 0) => m,
        _ => return unknown(w),
    };
    // Only these work on 64-bit lanes; the halving, min/max, absolute-difference and multiply ones do not.
    if size == 3 && !(opcode == 1 || opcode == 5 || (6..=11).contains(&opcode) || opcode == 16 || opcode == 17 || (opcode == 23 && u == 0)) {
        return unknown(w);
    }
    if m.contains("mulh") && (size == 0 || size == 3) {
        return unknown(w);
    }
    if m == "pmul" && size != 0 {
        return unknown(w);
    }
    let a = arr(size, q);
    mk(m, &[v(rd, a), v(rn, a), v(rm, a)], 0)
}

fn three_same_fp16(w: u32, scalar: bool) -> Insn {
    let Some(m) = same_fp(bit(w, 29), bit(w, 23), bits(w, 13, 11)) else { return unknown(w) };
    let rm = bits(w, 20, 16);
    let rn = bits(w, 9, 5);
    let rd = bits(w, 4, 0);
    if scalar {
        // Only the compares, the steps of the reciprocal estimates, fmulx and fabd have a scalar form.
        if !["fmulx", "fcmeq", "fcmge", "fcmgt", "facge", "facgt", "frecps", "frsqrts", "fabd"].contains(&m) {
            return unknown(w);
        }
        return mk(m, &[sc(b'h', rd), sc(b'h', rn), sc(b'h', rm)], 0);
    }
    let a = if bit(w, 30) != 0 { "8h" } else { "4h" };
    mk(m, &[v(rd, a), v(rn, a), v(rm, a)], 0)
}

const DIFF_U0: [&str; 15] = ["saddl", "saddw", "ssubl", "ssubw", "addhn", "sabal", "subhn", "sabdl", "smlal", "sqdmlal", "smlsl", "sqdmlsl", "smull", "sqdmull", "pmull"];
const DIFF_U1: [&str; 15] = ["uaddl", "uaddw", "usubl", "usubw", "raddhn", "uabal", "rsubhn", "uabdl", "umlal", "", "umlsl", "", "umull", "", ""];

fn three_different(w: u32) -> Insn {
    let q = bit(w, 30);
    let u = bit(w, 29);
    let size = bits(w, 23, 22);
    let opcode = bits(w, 15, 12);
    let rm = bits(w, 20, 16);
    let rn = bits(w, 9, 5);
    let rd = bits(w, 4, 0);
    let table = if u != 0 { &DIFF_U1 } else { &DIFF_U0 };
    let Some(base) = table.get(opcode as usize).copied().filter(|m| !m.is_empty()) else { return unknown(w) };
    let m = two(base, q);
    if base == "pmull" {
        if size == 0 {
            return Insn::new(m, &[v(rd, "8h"), v(rn, arr(0, q)), v(rm, arr(0, q))], 0);
        }
        if size == 3 {
            return Insn::new(m, &[v(rd, "1q"), v(rn, arr(3, q)), v(rm, arr(3, q))], 0);
        }
        return unknown(w);
    }
    if size == 3 || (base.starts_with("sqd") && size == 0) {
        return unknown(w);
    }
    let wide = WIDE[size as usize];
    let narrow = arr(size, q);
    if opcode == 1 || opcode == 3 {
        return Insn::new(m, &[v(rd, wide), v(rn, wide), v(rm, narrow)], 0);
    }
    if opcode == 4 || opcode == 6 {
        return Insn::new(m, &[v(rd, narrow), v(rn, wide), v(rm, wide)], 0);
    }
    Insn::new(m, &[v(rd, wide), v(rn, narrow), v(rm, narrow)], 0)
}

/// The floating-point half of the two-register miscellaneous table, by U, size<1> and opcode.
fn two_reg_misc_fp(u: u32, hi: u32, opcode: u32) -> Option<&'static str> {
    Some(match (u, hi, opcode) {
        (0, 0, 24) => "frintn",
        (0, 0, 25) => "frintm",
        (0, 0, 26) => "fcvtns",
        (0, 0, 27) => "fcvtms",
        (0, 0, 28) => "fcvtas",
        (0, 0, 29) => "scvtf",
        (0, 0, 30) => "frint32z",
        (0, 0, 31) => "frint64z",
        (0, 1, 24) => "frintp",
        (0, 1, 25) => "frintz",
        (0, 1, 26) => "fcvtps",
        (0, 1, 27) => "fcvtzs",
        (0, 1, 28) => "urecpe",
        (0, 1, 29) => "frecpe",
        (1, 0, 24) => "frinta",
        (1, 0, 25) => "frintx",
        (1, 0, 26) => "fcvtnu",
        (1, 0, 27) => "fcvtmu",
        (1, 0, 28) => "fcvtau",
        (1, 0, 29) => "ucvtf",
        (1, 0, 30) => "frint32x",
        (1, 0, 31) => "frint64x",
        (1, 1, 25) => "frinti",
        (1, 1, 26) => "fcvtpu",
        (1, 1, 27) => "fcvtzu",
        (1, 1, 28) => "ursqrte",
        (1, 1, 29) => "frsqrte",
        (1, 1, 31) => "fsqrt",
        _ => return None,
    })
}

/// Two registers, miscellaneous; fp16 is the half-precision group, which has only the floating-point half of the table.
fn two_reg_misc(w: u32, fp16: bool) -> Insn {
    let q = bit(w, 30);
    let u = bit(w, 29);
    let size = bits(w, 23, 22);
    let opcode = bits(w, 16, 12);
    let rn = bits(w, 9, 5);
    let rd = bits(w, 4, 0);
    let a = arr(size, q);
    let same = |m: &str, ok: bool| if ok { mk(m, &[v(rd, a), v(rn, a)], 0) } else { unknown(w) };
    if fp16 && (opcode < 12 || (opcode > 15 && opcode < 24)) {
        return unknown(w);
    }
    if opcode < 12 || opcode == 18 || opcode == 19 || opcode == 20 {
        let u1 = u != 0;
        return match opcode {
            0 => same(if u1 { "rev32" } else { "rev64" }, if u1 { size < 2 } else { size < 3 }),
            1 => same("rev16", !u1 && size == 0),
            2 | 6 => {
                if size == 3 {
                    return unknown(w);
                }
                let m = sfmt!(Mn, "{}{}", if u1 { "u" } else { "s" }, if opcode == 2 { "addlp" } else { "adalp" });
                Insn::new(m, &[v(rd, arr(size + 1, q)), v(rn, a)], 0)
            }
            3 => same(if u1 { "usqadd" } else { "suqadd" }, size < 3 || q != 0),
            4 => same(if u1 { "clz" } else { "cls" }, size < 3),
            5 => {
                if !u1 {
                    return same("cnt", size == 0);
                }
                if size == 0 {
                    return same("mvn", true);
                }
                if size == 1 {
                    mk("rbit", &[v(rd, arr(0, q)), v(rn, arr(0, q))], 0)
                } else {
                    unknown(w)
                }
            }
            7 => same(if u1 { "sqneg" } else { "sqabs" }, size < 3 || q != 0),
            8 => {
                if size == 3 && q == 0 {
                    unknown(w)
                } else {
                    mk(if u1 { "cmge" } else { "cmgt" }, &[v(rd, a), v(rn, a), zero()], 0)
                }
            }
            9 => {
                if size == 3 && q == 0 {
                    unknown(w)
                } else {
                    mk(if u1 { "cmle" } else { "cmeq" }, &[v(rd, a), v(rn, a), zero()], 0)
                }
            }
            10 => {
                if u1 || (size == 3 && q == 0) {
                    unknown(w)
                } else {
                    mk("cmlt", &[v(rd, a), v(rn, a), zero()], 0)
                }
            }
            11 => same(if u1 { "neg" } else { "abs" }, size < 3 || q != 0),
            18 => {
                if size == 3 {
                    return unknown(w);
                }
                Insn::new(two(if u1 { "sqxtun" } else { "xtn" }, q), &[v(rd, a), v(rn, WIDE[size as usize])], 0)
            }
            19 => {
                if !u1 || size == 3 {
                    return unknown(w);
                }
                Insn::new(two("shll", q), &[v(rd, WIDE[size as usize]), v(rn, a), imm_dec(8 << size)], 0)
            }
            20 => {
                if size == 3 {
                    return unknown(w);
                }
                Insn::new(two(if u1 { "uqxtn" } else { "sqxtn" }, q), &[v(rd, a), v(rn, WIDE[size as usize])], 0)
            }
            _ => unknown(w),
        };
    }
    // Floating point: size<1> picks one of two operations, size<0> the precision.
    let hi = size >> 1;
    let sz = size & 1;
    let fa = if fp16 { arr(1, q) } else { arr(2 + sz, q) };
    if sz != 0 && q == 0 && !fp16 && opcode != 22 && opcode != 23 {
        return unknown(w);
    }
    let fsame = |m: &str| mk(m, &[v(rd, fa), v(rn, fa)], 0);
    if opcode == 22 {
        if hi != 0 {
            return if u != 0 || sz != 0 { unknown(w) } else { Insn::new(two("bfcvtn", q), &[v(rd, arr(1, q)), v(rn, "4s")], 0) };
        }
        if u != 0 {
            return if sz != 0 { Insn::new(two("fcvtxn", q), &[v(rd, arr(2, q)), v(rn, "2d")], 0) } else { unknown(w) };
        }
        return Insn::new(two("fcvtn", q), &[v(rd, if sz != 0 { arr(2, q) } else { arr(1, q) }), v(rn, if sz != 0 { "2d" } else { "4s" })], 0);
    }
    if opcode == 23 {
        // With U set, size picks one of the FP8 widenings to half precision or BFloat16.
        if u != 0 {
            return Insn::new(two(["f1cvtl", "f2cvtl", "bf1cvtl", "bf2cvtl"][size as usize], q), &[v(rd, "8h"), v(rn, arr(0, q))], 0);
        }
        if hi != 0 {
            return unknown(w);
        }
        return Insn::new(two("fcvtl", q), &[v(rd, if sz != 0 { "2d" } else { "4s" }), v(rn, if sz != 0 { arr(2, q) } else { arr(1, q) })], 0);
    }
    if hi != 0 && (12..=15).contains(&opcode) {
        if opcode == 15 {
            return fsame(if u != 0 { "fneg" } else { "fabs" });
        }
        let m = [if u != 0 { "fcmge" } else { "fcmgt" }, if u != 0 { "fcmle" } else { "fcmeq" }, if u != 0 { "" } else { "fcmlt" }][(opcode - 12) as usize];
        return if !m.is_empty() { mk(m, &[v(rd, fa), v(rn, fa), zero_fp()], 0) } else { unknown(w) };
    }
    let Some(m) = two_reg_misc_fp(u, hi, opcode) else { return unknown(w) };
    if m == "urecpe" || m == "ursqrte" {
        return if sz != 0 || fp16 { unknown(w) } else { mk(m, &[v(rd, arr(2, q)), v(rn, arr(2, q))], 0) };
    }
    // frint32x and its kin have no half-precision form
    if fp16 && m.starts_with("frint") && m.as_bytes()[5].is_ascii_digit() {
        return unknown(w);
    }
    fsame(m)
}

fn across_lanes(w: u32) -> Insn {
    let q = bit(w, 30);
    let u = bit(w, 29);
    let size = bits(w, 23, 22);
    let opcode = bits(w, 16, 12);
    let rn = bits(w, 9, 5);
    let rd = bits(w, 4, 0);
    if opcode == 12 || opcode == 15 {
        // With U clear these are the half-precision forms, over four or eight lanes.
        if size & 1 != 0 || (u != 0 && q == 0) {
            return unknown(w);
        }
        let m = if opcode == 12 {
            if size != 0 {
                "fminnmv"
            } else {
                "fmaxnmv"
            }
        } else if size != 0 {
            "fminv"
        } else {
            "fmaxv"
        };
        return if u != 0 { mk(m, &[sc(b's', rd), v(rn, "4s")], 0) } else { mk(m, &[sc(b'h', rd), v(rn, arr(1, q))], 0) };
    }
    let a = arr(size, q);
    if size == 3 || (size == 2 && q == 0) {
        return unknown(w);
    }
    if opcode == 3 {
        return mk(if u != 0 { "uaddlv" } else { "saddlv" }, &[sc(b"hsd"[size as usize], rd), v(rn, a)], 0);
    }
    let m = match opcode {
        10 => Some(if u != 0 { "umaxv" } else { "smaxv" }),
        26 => Some(if u != 0 { "uminv" } else { "sminv" }),
        27 if u == 0 => Some("addv"),
        _ => None,
    };
    let Some(m) = m else { return unknown(w) };
    mk(m, &[sc(b"bhs"[size as usize], rd), v(rn, a)], 0)
}

fn copy(w: u32, scalar: bool) -> Insn {
    let q = bit(w, 30);
    let op = bit(w, 29);
    let imm5 = bits(w, 20, 16);
    let imm4 = bits(w, 14, 11);
    let rn = bits(w, 9, 5);
    let rd = bits(w, 4, 0);
    let size = if imm5 & 1 != 0 {
        0
    } else if imm5 & 2 != 0 {
        1
    } else if imm5 & 4 != 0 {
        2
    } else if imm5 & 8 != 0 {
        3
    } else {
        return unknown(w);
    };
    let t = ["b", "h", "s", "d"][size as usize];
    let index = imm5 >> (size + 1);
    if scalar {
        if op != 0 || imm4 != 0 {
            return unknown(w);
        }
        return mk("mov", &[sc(t.as_bytes()[0], rd), el(rn, t, index)], 0);
    }
    if op != 0 {
        if q == 0 {
            return unknown(w);
        }
        return mk("mov", &[el(rd, t, index), el(rn, t, imm4 >> size)], 0);
    }
    match imm4 {
        0 => {
            if size == 3 && q == 0 {
                return unknown(w);
            }
            mk("dup", &[v(rd, arr(size, q)), el(rn, t, index)], 0)
        }
        1 => {
            if size == 3 && q == 0 {
                return unknown(w);
            }
            mk("dup", &[v(rd, arr(size, q)), reg(if size == 3 { xr(rn) } else { wr(rn) })], 0)
        }
        3 => {
            if q == 0 {
                return unknown(w);
            }
            mk("mov", &[el(rd, t, index), reg(if size == 3 { xr(rn) } else { wr(rn) })], 0)
        }
        5 => {
            if size == 3 || (size == 2 && q == 0) {
                return unknown(w);
            }
            mk("smov", &[reg(if q != 0 { xr(rd) } else { wr(rd) }), el(rn, t, index)], 0)
        }
        7 => {
            if (size == 3) != (q != 0) {
                return unknown(w);
            }
            mk(if size >= 2 { "mov" } else { "umov" }, &[reg(if q != 0 { xr(rd) } else { wr(rd) }), el(rn, t, index)], 0)
        }
        _ => unknown(w),
    }
}

fn modified_immediate(w: u32) -> Insn {
    let q = bit(w, 30);
    let op = bit(w, 29);
    let cmode = bits(w, 15, 12);
    let o2 = bit(w, 11);
    let rd = bits(w, 4, 0);
    let imm8 = (bits(w, 18, 16) << 5) | bits(w, 9, 5);
    if o2 != 0 && !(cmode == 15 && op == 0) {
        return unknown(w);
    }
    let shifted = |m: &str, a: &str, amount: u32| {
        let mut ops = Ops::new();
        ops.push(v(rd, a));
        ops.push(imm(imm8 as i64));
        if amount != 0 {
            ops.push(shift("lsl", amount as i64));
        }
        Insn::new(Mn::from(m), &ops, 0)
    };
    let name = |cmode: u32| {
        if cmode & 1 != 0 {
            if op != 0 {
                "bic"
            } else {
                "orr"
            }
        } else if op != 0 {
            "mvni"
        } else {
            "movi"
        }
    };
    if cmode < 8 {
        let a = if q != 0 { "4s" } else { "2s" };
        let amount = (cmode >> 1) * 8;
        return shifted(name(cmode), a, amount);
    }
    if cmode < 12 {
        let a = if q != 0 { "8h" } else { "4h" };
        let amount = ((cmode >> 1) & 1) * 8;
        return shifted(name(cmode), a, amount);
    }
    if cmode < 14 {
        let a = if q != 0 { "4s" } else { "2s" };
        return mk(if op != 0 { "mvni" } else { "movi" }, &[v(rd, a), imm(imm8 as i64), shift("msl", if cmode & 1 != 0 { 16 } else { 8 })], 0);
    }
    if cmode == 14 {
        if op == 0 {
            return mk("movi", &[v(rd, if q != 0 { "16b" } else { "8b" }), imm(imm8 as i64)], 0);
        }
        let mut value: u64 = 0;
        for i in 0..8 {
            if imm8 & (1 << i) != 0 {
                value |= 0xffu64 << (i * 8);
            }
        }
        return if q != 0 { mk("movi", &[v(rd, "2d"), simd64(value)], 0) } else { mk("movi", &[sc(b'd', rd), simd64(value)], 0) };
    }
    if op == 0 {
        let a = if o2 != 0 {
            if q != 0 {
                "8h"
            } else {
                "4h"
            }
        } else if q != 0 {
            "4s"
        } else {
            "2s"
        };
        return mk("fmov", &[v(rd, a), fp_imm_op(imm8)], 0);
    }
    if q == 0 {
        return unknown(w);
    }
    mk("fmov", &[v(rd, "2d"), fp_imm_op(imm8)], 0)
}

fn shift_name(u: u32, opcode: u32) -> Option<&'static str> {
    Some(if u == 0 {
        match opcode {
            0 => "sshr",
            2 => "ssra",
            4 => "srshr",
            6 => "srsra",
            10 => "shl",
            14 => "sqshl",
            16 => "shrn",
            17 => "rshrn",
            18 => "sqshrn",
            19 => "sqrshrn",
            20 => "sshll",
            28 => "scvtf",
            31 => "fcvtzs",
            _ => return None,
        }
    } else {
        match opcode {
            0 => "ushr",
            2 => "usra",
            4 => "urshr",
            6 => "ursra",
            8 => "sri",
            10 => "sli",
            12 => "sqshlu",
            14 => "uqshl",
            16 => "sqshrun",
            17 => "sqrshrun",
            18 => "uqshrn",
            19 => "uqrshrn",
            20 => "ushll",
            28 => "ucvtf",
            31 => "fcvtzu",
            _ => return None,
        }
    })
}

const LEFT: [&str; 7] = ["shl", "sqshl", "sli", "sqshlu", "uqshl", "sshll", "ushll"];

fn shift_immediate(w: u32, scalar: bool) -> Insn {
    let q = bit(w, 30);
    let u = bit(w, 29);
    let immh = bits(w, 22, 19);
    let immb = bits(w, 18, 16);
    let opcode = bits(w, 15, 11);
    let rn = bits(w, 9, 5);
    let rd = bits(w, 4, 0);
    let m = match shift_name(u, opcode) {
        Some(m) if immh != 0 => m,
        _ => return unknown(w),
    };
    let size = 31 - immh.leading_zeros();
    let esize = 8i64 << size;
    let value = ((immh << 3) | immb) as i64;
    let amount = if LEFT.contains(&m) { value - esize } else { 2 * esize - value };
    let narrow = (16..=19).contains(&opcode);
    let long = opcode == 20;
    let fixed = opcode == 28 || opcode == 31;
    if scalar {
        if long {
            return unknown(w);
        }
        if narrow {
            if size == 3 || m == "shrn" || m == "rshrn" {
                return unknown(w);
            }
            return mk(m, &[sc(b"bhs"[size as usize], rd), sc(b"hsd"[size as usize], rn), imm(amount)], 0);
        }
        if fixed {
            if size < 1 {
                return unknown(w);
            }
            let p = b"hsd"[(size - 1) as usize];
            return mk(m, &[sc(p, rd), sc(p, rn), imm(amount)], 0);
        }
        let p = b"bhsd"[size as usize];
        if !["sqshl", "uqshl", "sqshlu"].contains(&m) && size != 3 {
            return unknown(w);
        }
        return mk(m, &[sc(p, rd), sc(p, rn), imm(amount)], 0);
    }
    if narrow {
        if size == 3 {
            return unknown(w);
        }
        return Insn::new(two(m, q), &[v(rd, arr(size, q)), v(rn, WIDE[size as usize]), imm(amount)], 0);
    }
    if long {
        if size == 3 {
            return unknown(w);
        }
        return Insn::new(two(m, q), &[v(rd, WIDE[size as usize]), v(rn, arr(size, q)), imm(amount)], 0);
    }
    if size == 3 && q == 0 {
        return unknown(w);
    }
    if fixed && size < 1 {
        return unknown(w);
    }
    mk(m, &[v(rd, arr(size, q)), v(rn, arr(size, q)), imm(amount)], 0)
}

fn indexed_name(u: u32, opcode: u32) -> Option<&'static str> {
    Some(if u == 0 {
        match opcode {
            2 => "smlal",
            3 => "sqdmlal",
            6 => "smlsl",
            7 => "sqdmlsl",
            8 => "mul",
            10 => "smull",
            11 => "sqdmull",
            12 => "sqdmulh",
            13 => "sqrdmulh",
            14 => "sdot",
            1 => "fmla",
            5 => "fmls",
            9 => "fmul",
            _ => return None,
        }
    } else {
        match opcode {
            0 => "mla",
            2 => "umlal",
            4 => "mls",
            6 => "umlsl",
            10 => "umull",
            9 => "fmulx",
            14 => "udot",
            13 => "sqrdmlah",
            15 => "sqrdmlsh",
            _ => return None,
        }
    })
}

/// The by-element forms of the newer extensions (FP8 and BFloat16 dot products
/// and widening multiply-adds, FHM, the mixed-sign dot products, fcmla), in
/// slots the older table leaves free; None where the older table applies.
fn indexed_extra(w: u32, q: u32, u: u32, size: u32, opcode: u32) -> Option<Insn> {
    let l = bit(w, 21);
    let m_bit = bit(w, 20);
    let h = bit(w, 11);
    let rn = bits(w, 9, 5);
    let rd = bits(w, 4, 0);
    let rm4 = bits(w, 19, 16); // v0-v15 where M is an index bit
    let rm5 = bits(w, 20, 16);
    let hlm = (h << 2) | (l << 1) | m_bit;
    let hl = (h << 1) | l;
    let b = if q != 0 { "16b" } else { "8b" };
    let s = arr(2, q);
    // The FP8 forms that pick a single byte take the lowest index bit from bit 19, which leaves them v0-v7.
    let byte = || el(bits(w, 18, 16), "b", (hlm << 1) | bit(w, 19));
    let halves = |m: &str| mk(m, &[v(rd, s), v(rn, if q != 0 { "4h" } else { "2h" }), el(rm4, "h", hlm)], 0);
    if u == 0 {
        return match opcode {
            0 => Some(match size {
                0 => mk("fdot", &[v(rd, s), v(rn, b), el(rm5, "4b", hl)], 0),
                1 => mk("fdot", &[v(rd, arr(1, q)), v(rn, b), el(rm4, "2b", hlm)], 0),
                2 => halves("fmlal"),
                _ => mk(if q != 0 { "fmlalt" } else { "fmlalb" }, &[v(rd, "8h"), v(rn, "16b"), byte()], 0),
            }),
            4 => Some(if size == 2 { halves("fmlsl") } else { unknown(w) }),
            15 => Some(match size {
                1 => mk("bfdot", &[v(rd, s), v(rn, arr(1, q)), el(rm5, "2h", hl)], 0),
                3 => mk(if q != 0 { "bfmlalt" } else { "bfmlalb" }, &[v(rd, "4s"), v(rn, "8h"), el(rm4, "h", hlm)], 0),
                _ => mk(if size != 0 { "usdot" } else { "sudot" }, &[v(rd, s), v(rn, b), el(rm5, "4b", hl)], 0),
            }),
            _ => None,
        };
    }
    if opcode == 8 && size < 2 {
        let m = sfmt!(Mn, "fmlall{}{}", if q != 0 { "t" } else { "b" }, if size != 0 { "t" } else { "b" });
        return Some(Insn::new(m, &[v(rd, "4s"), v(rn, "16b"), byte()], 0));
    }
    if (opcode == 8 || opcode == 12) && size == 2 {
        return Some(halves(if opcode == 8 { "fmlal2" } else { "fmlsl2" }));
    }
    if opcode & 1 != 0 && opcode < 8 {
        // fcmla indexes complex pairs, so its index has one bit fewer than the lanes would need.
        let rot = imm_dec((opcode >> 1) as i64 * 90);
        if size == 1 {
            return Some(if q == 0 && h != 0 { unknown(w) } else { mk("fcmla", &[v(rd, arr(1, q)), v(rn, arr(1, q)), el(rm5, "h", hl), rot], 0) });
        }
        if size == 2 {
            return Some(if q == 0 || l != 0 { unknown(w) } else { mk("fcmla", &[v(rd, "4s"), v(rn, "4s"), el(rm5, "s", h), rot], 0) });
        }
        return Some(unknown(w));
    }
    None
}

const LONG_OPS: [&str; 9] = ["smlal", "smlsl", "smull", "umlal", "umlsl", "umull", "sqdmlal", "sqdmlsl", "sqdmull"];

fn indexed_element(w: u32, scalar: bool) -> Insn {
    let q = bit(w, 30);
    let u = bit(w, 29);
    let size = bits(w, 23, 22);
    let l = bit(w, 21);
    let m_bit = bit(w, 20);
    let rm_low = bits(w, 19, 16);
    let opcode = bits(w, 15, 12);
    let h = bit(w, 11);
    let rn = bits(w, 9, 5);
    let rd = bits(w, 4, 0);
    if !scalar {
        if let Some(extra) = indexed_extra(w, q, u, size, opcode) {
            return extra;
        }
    }
    let Some(m) = indexed_name(u, opcode) else { return unknown(w) };
    let fp = m.starts_with('f');
    if fp && size == 0 {
        // Half precision: eight lanes to index, so M joins H:L and the register is v0-v15.
        let e = el(rm_low, "h", (h << 2) | (l << 1) | m_bit);
        if scalar {
            return mk(m, &[sc(b'h', rd), sc(b'h', rn), e], 0);
        }
        return mk(m, &[v(rd, arr(1, q)), v(rn, arr(1, q)), e], 0);
    }
    if fp {
        if size < 2 {
            return unknown(w);
        }
        let sz = size & 1;
        let index = if sz != 0 { h } else { (h << 1) | l };
        if sz != 0 && l != 0 {
            return unknown(w);
        }
        let rm = (m_bit << 4) | rm_low;
        let t = if sz != 0 { "d" } else { "s" };
        if scalar {
            let p = t.as_bytes()[0];
            return mk(m, &[sc(p, rd), sc(p, rn), el(rm, t, index)], 0);
        }
        if sz != 0 && q == 0 {
            return unknown(w);
        }
        let a = arr(2 + sz, q);
        return mk(m, &[v(rd, a), v(rn, a), el(rm, t, index)], 0);
    }
    if size != 1 && size != 2 {
        return unknown(w);
    }
    let index = if size == 1 { (h << 2) | (l << 1) | m_bit } else { (h << 1) | l };
    let rm = if size == 1 { rm_low } else { (m_bit << 4) | rm_low };
    let t = if size == 1 { "h" } else { "s" };
    if m == "sdot" || m == "udot" {
        if size != 2 || scalar {
            return unknown(w);
        }
        return mk(m, &[v(rd, if q != 0 { "4s" } else { "2s" }), v(rn, if q != 0 { "16b" } else { "8b" }), el(rm, "4b", index)], 0);
    }
    let long_op = LONG_OPS.contains(&m);
    if scalar {
        if !m.starts_with("sq") {
            return unknown(w);
        }
        let d = if long_op { b"sd"[(size - 1) as usize] } else { t.as_bytes()[0] };
        return mk(m, &[sc(d, rd), sc(t.as_bytes()[0], rn), el(rm, t, index)], 0);
    }
    if long_op {
        return Insn::new(two(m, q), &[v(rd, WIDE[size as usize]), v(rn, arr(size, q)), el(rm, t, index)], 0);
    }
    mk(m, &[v(rd, arr(size, q)), v(rn, arr(size, q)), el(rm, t, index)], 0)
}

/// Three registers, extension: the dot products and matrix multiplies, the
/// rounding doubling multiply-accumulates, the complex fcmla/fcadd, BFloat16
/// and FP8. The scalar group has only sqrdmlah and sqrdmlsh.
fn three_same_extra(w: u32, scalar: bool) -> Insn {
    let q = bit(w, 30);
    let u = bit(w, 29);
    let size = bits(w, 23, 22);
    let opcode = bits(w, 14, 11);
    let rm = bits(w, 20, 16);
    let rn = bits(w, 9, 5);
    let rd = bits(w, 4, 0);
    if u != 0 && opcode < 2 && (size == 1 || size == 2) {
        let m = if opcode != 0 { "sqrdmlsh" } else { "sqrdmlah" };
        if scalar {
            let p = b"hs"[(size - 1) as usize];
            return mk(m, &[sc(p, rd), sc(p, rn), sc(p, rm)], 0);
        }
        let a = arr(size, q);
        return mk(m, &[v(rd, a), v(rn, a), v(rm, a)], 0);
    }
    if scalar {
        return unknown(w);
    }
    let b = if q != 0 { "16b" } else { "8b" };
    let s = arr(2, q);
    let ops = |d: &str, n: &str, m: &str| [v(rd, d), v(rn, n), v(rm, m)];
    if u == 0 {
        return match opcode {
            2 => {
                if size == 2 {
                    mk("sdot", &ops(s, b, b), 0)
                } else {
                    unknown(w)
                }
            }
            3 => {
                if size == 2 {
                    mk("usdot", &ops(s, b, b), 0)
                } else {
                    unknown(w)
                }
            }
            4 | 5 => {
                if size == 2 && q != 0 {
                    mk(if opcode == 4 { "smmla" } else { "usmmla" }, &ops("4s", "16b", "16b"), 0)
                } else {
                    unknown(w)
                }
            }
            8 => {
                if size < 2 {
                    Insn::new(sfmt!(Mn, "fmlall{}{}", if q != 0 { "t" } else { "b" }, if size != 0 { "t" } else { "b" }), &ops("4s", "16b", "16b"), 0)
                } else {
                    unknown(w)
                }
            }
            14 => {
                // FP8 narrowing: two half-precision sources fill one register, two single-precision sources half of one.
                if size == 1 {
                    return mk("fcvtn", &ops(b, arr(1, q), arr(1, q)), 0);
                }
                if size == 0 {
                    mk(if q != 0 { "fcvtn2" } else { "fcvtn" }, &ops(b, "4s", "4s"), 0)
                } else {
                    unknown(w)
                }
            }
            15 => match size {
                0 => mk("fdot", &ops(s, b, b), 0),
                1 => mk("fdot", &ops(arr(1, q), b, b), 0),
                3 => mk(if q != 0 { "fmlalt" } else { "fmlalb" }, &ops("8h", "16b", "16b"), 0),
                _ => unknown(w),
            },
            _ => unknown(w),
        };
    }
    if opcode == 2 {
        return if size == 2 { mk("udot", &ops(s, b, b), 0) } else { unknown(w) };
    }
    if opcode == 4 {
        return if size == 2 && q != 0 { mk("ummla", &ops("4s", "16b", "16b"), 0) } else { unknown(w) };
    }
    if opcode >= 8 && opcode != 13 && opcode != 15 {
        // fcmla (rotation in opcode<1:0>) and fcadd (rotation in opcode<1>) on half, single or double precision.
        if size == 0 || (size == 3 && q == 0) {
            return unknown(w);
        }
        let a = arr(size, q);
        let [d, n, m] = ops(a, a, a);
        if opcode < 12 {
            return mk("fcmla", &[d, n, m, imm_dec((opcode & 3) as i64 * 90)], 0);
        }
        return mk("fcadd", &[d, n, m, imm_dec(if opcode & 2 != 0 { 270 } else { 90 })], 0);
    }
    if opcode == 13 {
        if q == 0 || size == 3 {
            return unknown(w);
        }
        return if size == 1 { mk("bfmmla", &ops("4s", "8h", "8h"), 0) } else { mk("fmmla", &ops(if size != 0 { "4s" } else { "8h" }, "16b", "16b"), 0) };
    }
    if opcode == 15 {
        if size == 1 {
            return mk("bfdot", &ops(s, arr(1, q), arr(1, q)), 0);
        }
        return if size == 3 { mk(if q != 0 { "bfmlalt" } else { "bfmlalb" }, &ops("4s", "8h", "8h"), 0) } else { unknown(w) };
    }
    unknown(w)
}

fn lookup_table(w: u32, size: u32) -> Insn {
    let rm = bits(w, 20, 16);
    let rn = bits(w, 9, 5);
    let rd = bits(w, 4, 0);
    if bit(w, 30) == 0 {
        return unknown(w);
    }
    let index = |i: u32| Op::Reg(sfmt!(Name, "v{}[{}]", rm, i));
    if size == 1 {
        // luti4: bytes from one table register, or halfwords from a pair.
        if bit(w, 12) != 0 {
            return mk("luti4", &[v(rd, "8h"), Op::Text(vector_reg_list(rn, 2, "8h")), index(bits(w, 14, 13))], 0);
        }
        return if bit(w, 13) != 0 { mk("luti4", &[v(rd, "16b"), Op::Text(vector_reg_list(rn, 1, "16b")), index(bit(w, 14))], 0) } else { unknown(w) };
    }
    if size == 2 {
        return if bit(w, 12) != 0 { mk("luti2", &[v(rd, "16b"), Op::Text(vector_reg_list(rn, 1, "16b")), index(bits(w, 14, 13))], 0) } else { unknown(w) };
    }
    mk("luti2", &[v(rd, "8h"), Op::Text(vector_reg_list(rn, 1, "8h")), index(bits(w, 14, 12))], 0)
}

/// `{ v1.16b, v2.16b }`: `count` consecutive registers, wrapping from v31 to v0.
fn vector_reg_list(first: u32, count: u32, a: &str) -> Text {
    let mut out = Text::from("{ ");
    for i in 0..count {
        if i > 0 {
            out.push(", ");
        }
        out.push("v");
        push_dec(&mut out, ((first + i) % 32) as i64);
        out.push(".");
        out.push(a);
    }
    out.push(" }");
    out
}

fn adv_simd_vector(w: u32) -> Insn {
    let op0 = bits(w, 31, 28);
    let op1 = bits(w, 24, 23);
    let op2 = bits(w, 22, 19);
    let op3 = bits(w, 18, 10);
    let q = bit(w, 30);
    let rm = bits(w, 20, 16);
    let rn = bits(w, 9, 5);
    let rd = bits(w, 4, 0);
    if op0 & 0xb == 0 && op1 < 2 && op2 & 4 == 0 && op3 & 0x23 == 0 {
        // Table lookup; a nonzero size field is FEAT_LUT's luti2 and luti4, whose table is indexed by 2 or 4 bits.
        let size = bits(w, 23, 22);
        if size != 0 {
            return lookup_table(w, size);
        }
        let len = bits(w, 14, 13) + 1;
        let a = if q != 0 { "16b" } else { "8b" };
        return mk(if bit(w, 12) != 0 { "tbx" } else { "tbl" }, &[v(rd, a), Op::Text(vector_reg_list(rn, len, "16b")), v(rm, a)], 0);
    }
    if op0 & 0xb == 0 && op1 < 2 && op2 & 4 == 0 && op3 & 0x23 == 2 {
        let m = ["", "uzp1", "trn1", "zip1", "", "uzp2", "trn2", "zip2"][bits(w, 14, 12) as usize];
        let size = bits(w, 23, 22);
        if m.is_empty() || (size == 3 && q == 0) {
            return unknown(w);
        }
        let a = arr(size, q);
        return mk(m, &[v(rd, a), v(rn, a), v(rm, a)], 0);
    }
    if op0 & 0xb == 2 && op1 < 2 && op2 & 4 == 0 && op3 & 0x21 == 0 {
        let index = bits(w, 14, 11);
        if bits(w, 23, 22) != 0 || (q == 0 && index > 7) {
            return unknown(w);
        }
        let a = if q != 0 { "16b" } else { "8b" };
        return mk("ext", &[v(rd, a), v(rn, a), v(rm, a), imm(index as i64)], 0);
    }
    if op1 == 0 && op2 & 0xc == 0 && op3 & 0x21 == 1 {
        return copy(w, false);
    }
    if op1 < 2 && op2 & 0xc == 8 && op3 & 0x31 == 1 {
        return three_same_fp16(w, false);
    }
    if op1 < 2 && op2 & 4 == 0 && op3 & 0x21 == 0x21 {
        return three_same_extra(w, false);
    }
    if op1 < 2 && op2 & 7 == 4 && op3 & 0x183 == 2 {
        return two_reg_misc(w, false);
    }
    if op1 < 2 && op2 == 15 && op3 & 0x183 == 2 {
        return two_reg_misc(w, true);
    }
    if op1 < 2 && op2 & 7 == 6 && op3 & 0x183 == 2 {
        return across_lanes(w);
    }
    if op1 < 2 && op2 & 4 != 0 && op3 & 3 == 0 {
        return three_different(w);
    }
    if op1 < 2 && op2 & 4 != 0 && op3 & 1 != 0 {
        return three_same(w);
    }
    if op1 == 2 && op2 == 0 && op3 & 1 != 0 {
        return modified_immediate(w);
    }
    if op1 == 2 && op2 != 0 && op3 & 1 != 0 {
        return shift_immediate(w, false);
    }
    if op1 >= 2 && op3 & 1 == 0 {
        return indexed_element(w, false);
    }
    unknown(w)
}

/* ------------------------------------------------------------------ *
 * Advanced SIMD — scalar
 * ------------------------------------------------------------------ */

const ANY_SIZE: [&str; 8] = ["sqadd", "uqadd", "sqsub", "uqsub", "sqshl", "uqshl", "sqrshl", "uqrshl"];
const D_ONLY: [&str; 12] = ["cmgt", "cmge", "cmhi", "cmhs", "sshl", "ushl", "srshl", "urshl", "add", "sub", "cmtst", "cmeq"];

fn scalar_three_same(w: u32) -> Insn {
    let u = bit(w, 29);
    let size = bits(w, 23, 22);
    let opcode = bits(w, 15, 11);
    let rm = bits(w, 20, 16);
    let rn = bits(w, 9, 5);
    let rd = bits(w, 4, 0);
    if opcode >= 24 {
        let m = match (u, size >> 1, opcode & 7) {
            (0, 0, 3) => Some("fmulx"),
            (0, 0, 4) => Some("fcmeq"),
            (0, 0, 7) => Some("frecps"),
            (0, 1, 7) => Some("frsqrts"),
            (1, 0, 4) => Some("fcmge"),
            (1, 0, 5) => Some("facge"),
            (1, 1, 2) => Some("fabd"),
            (1, 1, 4) => Some("fcmgt"),
            (1, 1, 5) => Some("facgt"),
            _ => None,
        };
        let p = if size & 1 != 0 { b'd' } else { b's' };
        return match m {
            Some(m) => mk(m, &[sc(p, rd), sc(p, rn), sc(p, rm)], 0),
            None => unknown(w),
        };
    }
    let Some(m) = same_int(u, opcode) else { return unknown(w) };
    if D_ONLY.contains(&m) {
        return if size == 3 { mk(m, &[sc(b'd', rd), sc(b'd', rn), sc(b'd', rm)], 0) } else { unknown(w) };
    }
    if ANY_SIZE.contains(&m) {
        let p = b"bhsd"[size as usize];
        return mk(m, &[sc(p, rd), sc(p, rn), sc(p, rm)], 0);
    }
    if (m == "sqdmulh" || m == "sqrdmulh") && (size == 1 || size == 2) {
        let p = b"hs"[(size - 1) as usize];
        return mk(m, &[sc(p, rd), sc(p, rn), sc(p, rm)], 0);
    }
    unknown(w)
}

/// The floating-point conversions and estimates of the scalar two-register miscellaneous table, by U, size<1> and opcode.
fn scalar_two_reg_misc_fp(u: u32, hi: u32, opcode: u32) -> Option<&'static str> {
    Some(match (u, hi, opcode) {
        (0, 0, 26) => "fcvtns",
        (0, 0, 27) => "fcvtms",
        (0, 0, 28) => "fcvtas",
        (0, 0, 29) => "scvtf",
        (0, 1, 26) => "fcvtps",
        (0, 1, 27) => "fcvtzs",
        (0, 1, 29) => "frecpe",
        (0, 1, 31) => "frecpx",
        (1, 0, 26) => "fcvtnu",
        (1, 0, 27) => "fcvtmu",
        (1, 0, 28) => "fcvtau",
        (1, 0, 29) => "ucvtf",
        (1, 1, 26) => "fcvtpu",
        (1, 1, 27) => "fcvtzu",
        (1, 1, 29) => "frsqrte",
        _ => return None,
    })
}

fn scalar_two_reg_misc(w: u32, fp16: bool) -> Insn {
    let u = bit(w, 29);
    let size = bits(w, 23, 22);
    let opcode = bits(w, 16, 12);
    let rn = bits(w, 9, 5);
    let rd = bits(w, 4, 0);
    let p = b"bhsd"[size as usize];
    if !fp16 {
        let u1 = u != 0;
        match opcode {
            3 => return mk(if u1 { "usqadd" } else { "suqadd" }, &[sc(p, rd), sc(p, rn)], 0),
            7 => return mk(if u1 { "sqneg" } else { "sqabs" }, &[sc(p, rd), sc(p, rn)], 0),
            8 | 9 => {
                if size != 3 {
                    return unknown(w);
                }
                let m = [if u1 { "cmge" } else { "cmgt" }, if u1 { "cmle" } else { "cmeq" }][(opcode - 8) as usize];
                return mk(m, &[sc(b'd', rd), sc(b'd', rn), zero()], 0);
            }
            10 => return if size == 3 && !u1 { mk("cmlt", &[sc(b'd', rd), sc(b'd', rn), zero()], 0) } else { unknown(w) },
            11 => return if size == 3 { mk(if u1 { "neg" } else { "abs" }, &[sc(b'd', rd), sc(b'd', rn)], 0) } else { unknown(w) },
            18 => return if u1 && size < 3 { mk("sqxtun", &[sc(p, rd), sc(b"hsd"[size as usize], rn)], 0) } else { unknown(w) },
            20 => return if size < 3 { mk(if u1 { "uqxtn" } else { "sqxtn" }, &[sc(p, rd), sc(b"hsd"[size as usize], rn)], 0) } else { unknown(w) },
            22 => return if u1 && size == 1 { mk("fcvtxn", &[sc(b's', rd), sc(b'd', rn)], 0) } else { unknown(w) },
            _ => {}
        }
    }
    let hi = size >> 1;
    let fp = if fp16 {
        b'h'
    } else if size & 1 != 0 {
        b'd'
    } else {
        b's'
    };
    if hi != 0 && (12..=14).contains(&opcode) {
        let m = [if u != 0 { "fcmge" } else { "fcmgt" }, if u != 0 { "fcmle" } else { "fcmeq" }, if u != 0 { "" } else { "fcmlt" }][(opcode - 12) as usize];
        return if !m.is_empty() { mk(m, &[sc(fp, rd), sc(fp, rn), zero_fp()], 0) } else { unknown(w) };
    }
    match scalar_two_reg_misc_fp(u, hi, opcode) {
        Some(m) => mk(m, &[sc(fp, rd), sc(fp, rn)], 0),
        None => unknown(w),
    }
}

fn adv_simd_scalar(w: u32) -> Insn {
    let op1 = bits(w, 24, 23);
    let op2 = bits(w, 22, 19);
    let op3 = bits(w, 18, 10);
    let rn = bits(w, 9, 5);
    let rd = bits(w, 4, 0);
    if op1 == 0 && op2 & 0xc == 0 && op3 & 0x21 == 1 {
        return copy(w, true);
    }
    if op1 < 2 && op2 & 0xc == 8 && op3 & 0x31 == 1 {
        return three_same_fp16(w, true);
    }
    if op1 < 2 && op2 & 4 == 0 && op3 & 0x21 == 0x21 {
        return three_same_extra(w, true);
    }
    if op1 < 2 && op2 & 7 == 4 && op3 & 0x183 == 2 {
        return scalar_two_reg_misc(w, false);
    }
    if op1 < 2 && op2 == 15 && op3 & 0x183 == 2 {
        return scalar_two_reg_misc(w, true);
    }
    if op1 < 2 && op2 & 7 == 6 && op3 & 0x183 == 2 {
        let u = bit(w, 29);
        let size = bits(w, 23, 22);
        let opcode = bits(w, 16, 12);
        if u == 0 && opcode == 27 && size == 3 {
            return mk("addp", &[sc(b'd', rd), v(rn, "2d")], 0);
        }
        // Pairwise FP: U set for single and double precision, U clear (and size<0> clear) for half.
        let sz = size & 1;
        let hi = size >> 1;
        let m = match opcode {
            12 => {
                if hi != 0 {
                    "fminnmp"
                } else {
                    "fmaxnmp"
                }
            }
            13 => {
                if hi != 0 {
                    ""
                } else {
                    "faddp"
                }
            }
            15 => {
                if hi != 0 {
                    "fminp"
                } else {
                    "fmaxp"
                }
            }
            _ => "",
        };
        if m.is_empty() {
            return unknown(w);
        }
        if u != 0 {
            return mk(m, &[sc(if sz != 0 { b'd' } else { b's' }, rd), v(rn, if sz != 0 { "2d" } else { "2s" })], 0);
        }
        return if sz != 0 { unknown(w) } else { mk(m, &[sc(b'h', rd), v(rn, "2h")], 0) };
    }
    if op1 < 2 && op2 & 4 != 0 && op3 & 3 == 0 {
        let u = bit(w, 29);
        let size = bits(w, 23, 22);
        let opcode = bits(w, 15, 12);
        let m = match opcode {
            9 => "sqdmlal",
            11 => "sqdmlsl",
            13 => "sqdmull",
            _ => "",
        };
        if u != 0 || m.is_empty() || (size != 1 && size != 2) {
            return unknown(w);
        }
        let (d, s) = (b"sd"[(size - 1) as usize], b"hs"[(size - 1) as usize]);
        return mk(m, &[sc(d, rd), sc(s, rn), sc(s, bits(w, 20, 16))], 0);
    }
    if op1 < 2 && op2 & 4 != 0 && op3 & 1 != 0 {
        return scalar_three_same(w);
    }
    if op1 == 2 && op3 & 1 != 0 {
        return shift_immediate(w, true);
    }
    if op1 >= 2 && op3 & 1 == 0 {
        return indexed_element(w, true);
    }
    unknown(w)
}

/* ------------------------------------------------------------------ *
 * Cryptography
 * ------------------------------------------------------------------ */

fn crypto(w: u32) -> Insn {
    let rn = bits(w, 9, 5);
    let rd = bits(w, 4, 0);
    let rm = bits(w, 20, 16);
    let top = bits(w, 31, 24);
    if top == 0x4e && bits(w, 21, 17) == 0x14 && bits(w, 11, 10) == 2 {
        let m = match bits(w, 16, 12) {
            4 => Some("aese"),
            5 => Some("aesd"),
            6 => Some("aesmc"),
            7 => Some("aesimc"),
            _ => None,
        };
        return match m {
            Some(m) if bits(w, 23, 22) == 0 => mk(m, &[v(rd, "16b"), v(rn, "16b")], 0),
            _ => unknown(w),
        };
    }
    if top == 0x5e && bit(w, 21) == 0 && bit(w, 15) == 0 && bits(w, 11, 10) == 0 && bits(w, 23, 22) == 0 {
        let opcode = bits(w, 14, 12);
        if opcode < 3 {
            return mk(["sha1c", "sha1p", "sha1m"][opcode as usize], &[sc(b'q', rd), sc(b's', rn), v(rm, "4s")], 0);
        }
        if opcode == 3 {
            return mk("sha1su0", &[v(rd, "4s"), v(rn, "4s"), v(rm, "4s")], 0);
        }
        if opcode < 6 {
            return mk(if opcode == 4 { "sha256h" } else { "sha256h2" }, &[sc(b'q', rd), sc(b'q', rn), v(rm, "4s")], 0);
        }
        if opcode == 6 {
            return mk("sha256su1", &[v(rd, "4s"), v(rn, "4s"), v(rm, "4s")], 0);
        }
        return unknown(w);
    }
    if top == 0x5e && bits(w, 21, 17) == 0x14 && bits(w, 11, 10) == 2 && bits(w, 23, 22) == 0 {
        let opcode = bits(w, 16, 12);
        if opcode == 0 {
            return mk("sha1h", &[sc(b's', rd), sc(b's', rn)], 0);
        }
        if opcode == 1 {
            return mk("sha1su1", &[v(rd, "4s"), v(rn, "4s")], 0);
        }
        if opcode == 2 {
            return mk("sha256su0", &[v(rd, "4s"), v(rn, "4s")], 0);
        }
        return unknown(w);
    }
    if top == 0xce {
        if bit(w, 23) == 0 && bit(w, 15) == 0 {
            let op0 = bits(w, 22, 21);
            let ra = bits(w, 14, 10);
            if op0 == 0 {
                return mk("eor3", &[v(rd, "16b"), v(rn, "16b"), v(rm, "16b"), v(ra, "16b")], 0);
            }
            if op0 == 1 {
                return mk("bcax", &[v(rd, "16b"), v(rn, "16b"), v(rm, "16b"), v(ra, "16b")], 0);
            }
            if op0 == 2 {
                return mk("sm3ss1", &[v(rd, "4s"), v(rn, "4s"), v(rm, "4s"), v(ra, "4s")], 0);
            }
            return unknown(w);
        }
        if bits(w, 23, 21) == 2 && bits(w, 15, 14) == 2 {
            let m = ["sm3tt1a", "sm3tt1b", "sm3tt2a", "sm3tt2b"][bits(w, 11, 10) as usize];
            return mk(m, &[v(rd, "4s"), v(rn, "4s"), el(rm, "s", bits(w, 13, 12))], 0);
        }
        if bits(w, 23, 21) == 3 && bits(w, 15, 12) == 8 {
            let opcode = bits(w, 11, 10);
            if opcode == 0 {
                return mk("sha512h", &[sc(b'q', rd), sc(b'q', rn), v(rm, "2d")], 0);
            }
            if opcode == 1 {
                return mk("sha512h2", &[sc(b'q', rd), sc(b'q', rn), v(rm, "2d")], 0);
            }
            return mk(if opcode == 2 { "sha512su1" } else { "rax1" }, &[v(rd, "2d"), v(rn, "2d"), v(rm, "2d")], 0);
        }
        if bits(w, 23, 21) == 3 && bits(w, 15, 12) == 12 {
            let m = ["sm3partw1", "sm3partw2", "sm4ekey", ""][bits(w, 11, 10) as usize];
            return if !m.is_empty() { mk(m, &[v(rd, "4s"), v(rn, "4s"), v(rm, "4s")], 0) } else { unknown(w) };
        }
        if bits(w, 23, 21) == 4 {
            return mk("xar", &[v(rd, "2d"), v(rn, "2d"), v(rm, "2d"), imm(bits(w, 15, 10) as i64)], 0);
        }
        if bits(w, 23, 10) == 0x3020 {
            return mk("sha512su0", &[v(rd, "2d"), v(rn, "2d")], 0);
        }
        if bits(w, 23, 10) == 0x3021 {
            return mk("sm4e", &[v(rd, "4s"), v(rn, "4s")], 0);
        }
    }
    unknown(w)
}

/* ------------------------------------------------------------------ *
 * Structure loads and stores
 * ------------------------------------------------------------------ */

/// The multiple-structure forms by opcode: the n of ldN/stN and how many registers.
fn multiple(opcode: u32) -> Option<(&'static str, u32)> {
    Some(match opcode {
        0 => ("4", 4),
        2 => ("1", 4),
        4 => ("3", 3),
        6 => ("1", 3),
        7 => ("1", 1),
        8 => ("2", 2),
        10 => ("1", 2),
        _ => return None,
    })
}

/// The memory operand of a structure load or store: `[x0]`, or post-indexed by
/// the bytes moved (`[x0], #32`) or by a register (`[x0], x2`).
fn structure_mem(rn: u32, post: u32, rm: u32, bytes: u32, off: i64) -> Op {
    let mut m = Mem::new(xs(rn), off, if post != 0 { Mode::Post } else { Mode::Off });
    if post != 0 {
        m.post = Some(if rm == 31 { sfmt!(Name, "#{}", bytes) } else { xr(rm) });
    }
    Op::Mem(m)
}

pub fn decode_simd_structure(w: u32) -> Insn {
    let q = bit(w, 30);
    let l = bit(w, 22);
    let post = bit(w, 23);
    let rm = bits(w, 20, 16);
    let rn = bits(w, 9, 5);
    let rt = bits(w, 4, 0);
    let flags = if l != 0 { f::LOAD } else { f::STORE };
    let ld_st = if l != 0 { "ld" } else { "st" };
    if bit(w, 24) == 0 {
        if bit(w, 21) != 0 || (post == 0 && rm != 0) {
            return unknown(w);
        }
        let opcode = bits(w, 15, 12);
        let size = bits(w, 11, 10);
        let (n, regs) = match multiple(opcode) {
            Some((n, regs)) if !(size == 3 && q == 0 && n != "1") => (n, regs),
            _ => return unknown(w),
        };
        let a = arr(size, q);
        let bytes = (if q != 0 { 16 } else { 8 }) * regs;
        let off = if post != 0 && rm == 31 { bytes as i64 } else { 0 };
        let mem = structure_mem(rn, post, rm, bytes, off);
        return Insn::new(sfmt!(Mn, "{}{}", ld_st, n), &[Op::Text(vector_reg_list(rt, regs, a)), mem], flags).size(1 << size);
    }
    let r = bit(w, 21);
    let opcode = bits(w, 15, 13);
    let s = bit(w, 12);
    let size = bits(w, 11, 10);
    let selem = (((opcode & 1) << 1) | r) + 1;
    if post == 0 && rm == 1 && opcode == 4 && r == 0 && s == 0 && size == 1 {
        // FEAT_LRCPC3: one doubleword lane, loaded with acquire or stored with release.
        let mem = Op::Mem(Mem::new(xs(rn), 0, Mode::Off));
        return mk(if l != 0 { "ldap1" } else { "stl1" }, &[Op::Text(sfmt!(Text, "{{ v{}.d }}[{}]", rt, q)), mem], flags).size(8);
    }
    if post == 0 && rm != 0 {
        return unknown(w);
    }
    if opcode >= 6 {
        // LDnR: load and replicate to all lanes. (The TypeScript spells the check
        // `(!l || s || opcode === 7) && !(l && !s && opcode === 7)`, which is this.)
        if l == 0 || s != 0 {
            return unknown(w);
        }
        let a = arr(size, q);
        let bytes = selem << size;
        let mem = structure_mem(rn, post, rm, bytes, 0);
        return Insn::new(sfmt!(Mn, "ld{}r", selem), &[Op::Text(vector_reg_list(rt, selem, a)), mem], f::LOAD).size(1 << size);
    }
    let (t, esize, index) = if opcode < 2 {
        ("b", 1, (q << 3) | (s << 2) | size)
    } else if opcode < 4 {
        if size & 1 != 0 {
            return unknown(w);
        }
        ("h", 2, (q << 2) | (s << 1) | (size >> 1))
    } else if size == 0 {
        ("s", 4, (q << 1) | s)
    } else if size == 1 && s == 0 {
        ("d", 8, q)
    } else {
        return unknown(w);
    };
    let mut list = Text::from("{ ");
    for i in 0..selem {
        if i > 0 {
            list.push(", ");
        }
        list.push("v");
        push_dec(&mut list, ((rt + i) % 32) as i64);
        list.push(".");
        list.push(t);
    }
    list.push(" }[");
    push_dec(&mut list, index as i64);
    list.push("]");
    let bytes = selem * esize;
    let mem = structure_mem(rn, post, rm, bytes, 0);
    Insn::new(sfmt!(Mn, "{}{}", ld_st, selem), &[Op::Text(list), mem], flags).size(esize)
}

/* ------------------------------------------------------------------ */

pub fn decode_simd(w: u32, _pc: i64) -> Insn {
    let op0 = bits(w, 31, 28);
    if op0 == 0xc || op0 == 0xd {
        return if op0 == 0xc { crypto(w) } else { unknown(w) };
    }
    if op0 & 5 == 1 {
        return scalar_fp(w);
    }
    if op0 == 4 || op0 == 5 {
        let c = crypto(w);
        if c.f & f::UNKNOWN == 0 {
            return c;
        }
    }
    if op0 & 0xd == 5 {
        return adv_simd_scalar(w);
    }
    if op0 & 9 == 0 {
        return adv_simd_vector(w);
    }
    unknown(w)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fp_immediates() {
        assert_eq!(fp_imm(0x70), 1.0);
        assert_eq!(fp_imm(0xf0), -1.0);
        assert_eq!(fp_imm(0x00), 2.0);
        assert_eq!(fp_imm(0x4f), 0.2421875);
        assert_eq!(format_op_string(&fp_imm_op(0x4f)), "#0.24218750");
        assert_eq!(format_op_string(&fp_imm_op(0x80)), "#-2.00000000");
    }

    #[test]
    fn simd64_like_printf() {
        assert_eq!(format_op_string(&simd64(0)), "#0000000000000000");
        assert_eq!(format_op_string(&simd64(0xff)), "#0x000000000000ff");
        assert_eq!(format_op_string(&simd64(u64::MAX)), "#0xffffffffffffffff");
    }
}
