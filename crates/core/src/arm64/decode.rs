//! The AArch64 decoder: one 32-bit word in, one instruction out.
//!
//! It follows the top-level encoding table of the Arm Architecture Reference
//! Manual — data processing with an immediate, branches and system
//! instructions, loads and stores, data processing on registers, and SIMD and
//! floating point (in simd.rs) — and prints the preferred alias where the
//! manual (and LLVM) do: `mov` for `orr x0, xzr, x1`, `cmp` for `subs xzr, …`,
//! `lsl` for `ubfm`, `cset` for `csinc`. tools/verify-decoder.mjs compares the
//! output with llvm-objdump instruction by instruction.
//!
//! SVE and SME, which macOS user code does not run outside streaming mode,
//! are left undecoded and shown as `.inst`.

use super::simd::{decode_simd, decode_simd_structure};
use super::sysreg::sysreg_name;
use super::types::*;
use crate::sfmt;

#[inline]
pub fn bits(w: u32, hi: u32, lo: u32) -> u32 {
    let mask = if hi - lo == 31 { u32::MAX } else { (1u32 << (hi - lo + 1)) - 1 };
    (w >> lo) & mask
}

#[inline]
pub fn bit(w: u32, n: u32) -> u32 {
    (w >> n) & 1
}

/// Sign-extends the low `width` bits of `v`.
#[inline]
pub fn sext(v: u32, width: u32) -> i64 {
    (((v << (32 - width)) as i32) >> (32 - width)) as i64
}

macro_rules! names32 {
    ($p:literal, $last:literal) => {
        [
            Name::from_static(concat!($p, "0")),
            Name::from_static(concat!($p, "1")),
            Name::from_static(concat!($p, "2")),
            Name::from_static(concat!($p, "3")),
            Name::from_static(concat!($p, "4")),
            Name::from_static(concat!($p, "5")),
            Name::from_static(concat!($p, "6")),
            Name::from_static(concat!($p, "7")),
            Name::from_static(concat!($p, "8")),
            Name::from_static(concat!($p, "9")),
            Name::from_static(concat!($p, "10")),
            Name::from_static(concat!($p, "11")),
            Name::from_static(concat!($p, "12")),
            Name::from_static(concat!($p, "13")),
            Name::from_static(concat!($p, "14")),
            Name::from_static(concat!($p, "15")),
            Name::from_static(concat!($p, "16")),
            Name::from_static(concat!($p, "17")),
            Name::from_static(concat!($p, "18")),
            Name::from_static(concat!($p, "19")),
            Name::from_static(concat!($p, "20")),
            Name::from_static(concat!($p, "21")),
            Name::from_static(concat!($p, "22")),
            Name::from_static(concat!($p, "23")),
            Name::from_static(concat!($p, "24")),
            Name::from_static(concat!($p, "25")),
            Name::from_static(concat!($p, "26")),
            Name::from_static(concat!($p, "27")),
            Name::from_static(concat!($p, "28")),
            Name::from_static(concat!($p, "29")),
            Name::from_static(concat!($p, "30")),
            Name::from_static($last),
        ]
    };
}

// Register names as ready-made inline strings: an operand copies twelve bytes instead of building its name.
pub(crate) static XR: [Name; 32] = names32!("x", "xzr");
pub(crate) static WR: [Name; 32] = names32!("w", "wzr");
pub(crate) static XS: [Name; 32] = names32!("x", "sp");
pub(crate) static WS: [Name; 32] = names32!("w", "wsp");
pub(crate) static BN: [Name; 32] = names32!("b", "b31");
pub(crate) static HN: [Name; 32] = names32!("h", "h31");
pub(crate) static SN: [Name; 32] = names32!("s", "s31");
pub(crate) static DN: [Name; 32] = names32!("d", "d31");
pub(crate) static QN: [Name; 32] = names32!("q", "q31");

#[inline]
pub fn xr(n: u32) -> Name {
    XR[(n & 31) as usize]
}
#[inline]
pub fn wr(n: u32) -> Name {
    WR[(n & 31) as usize]
}
#[inline]
pub fn xs(n: u32) -> Name {
    XS[(n & 31) as usize]
}
#[inline]
pub fn ws(n: u32) -> Name {
    WS[(n & 31) as usize]
}
#[inline]
pub fn gr(sf: u32, n: u32) -> Name {
    if sf != 0 {
        xr(n)
    } else {
        wr(n)
    }
}
#[inline]
pub fn gs(sf: u32, n: u32) -> Name {
    if sf != 0 {
        xs(n)
    } else {
        ws(n)
    }
}

/// `x32` and above: TypeScript's xr(rt + 1) never wraps (x30 + 1 is printed `xzr` there only for 31).
#[inline]
fn xr_next(n: u32) -> Name {
    xr(n + 1)
}

/// A scalar SIMD&FP register by its prefix letter: `b`, `h`, `s`, `d`, `q`.
#[inline]
pub fn fp_reg(prefix: u8, n: u32) -> Name {
    let table = match prefix {
        b'b' => &BN,
        b'h' => &HN,
        b's' => &SN,
        b'd' => &DN,
        _ => &QN,
    };
    table[(n & 31) as usize]
}

#[inline]
fn cond(c: u32) -> &'static str {
    CONDITIONS[(c & 15) as usize]
}

#[inline]
fn invert(c: u32) -> &'static str {
    cond(c ^ 1)
}

pub fn unknown(word: u32) -> Insn {
    let mut t = ImmText::from("0x");
    for shift in (0..8).rev() {
        t.push_byte(b"0123456789abcdef"[((word >> (shift * 4)) & 15) as usize]);
    }
    Insn::new(Mn::from(".inst"), &[Op::Imm { v: word as f64, t }], f::UNKNOWN)
}

/// Logical immediates: a rotated run of ones, replicated across the register (DecodeBitMasks).
pub fn decode_bit_mask(n: u32, imms: u32, immr: u32, width: u32) -> Option<u64> {
    let combined = (n << 6) | (!imms & 0x3f);
    if combined == 0 {
        return None;
    }
    let len = 31 - combined.leading_zeros();
    if len < 1 {
        return None;
    }
    if width == 32 && n != 0 {
        return None;
    }
    let levels = (1u32 << len) - 1;
    let s = imms & levels;
    let r = immr & levels;
    if s == levels {
        return None;
    }
    let esize = 1u32 << len;
    let emask: u128 = (1u128 << esize) - 1;
    let mut elem: u128 = (1u128 << (s + 1)) - 1;
    if r != 0 {
        elem = ((elem >> r) | (elem << (esize - r))) & emask;
    }
    let mut out: u128 = 0;
    let mut i = 0;
    while i < width {
        out |= elem << i;
        i += esize;
    }
    Some(out as u64)
}

/// Whether a value fits one movz or movn. LLVM prints `orr x0, xzr, #imm` as
/// `mov x0, #imm` only when it does not — otherwise the mov would be read as
/// the wide-immediate form.
fn mov_wide_fits(value: u64, width: u32) -> bool {
    let mask: u128 = (1u128 << width) - 1;
    let single = |v: u128| {
        let mut shift = 0;
        while shift < width {
            if v & !(0xffffu128 << shift) & mask == 0 {
                return true;
            }
            shift += 16;
        }
        false
    };
    let v = value as u128;
    single(v & mask) || single(!v & mask)
}

#[inline]
fn signed(v: u128, width: u32) -> i128 {
    let v = v as i128;
    if v >= 1i128 << (width - 1) {
        v - (1i128 << width)
    } else {
        v
    }
}

/* ------------------------------------------------------------------ *
 * Data processing — immediate
 * ------------------------------------------------------------------ */

fn dp_imm(w: u32, pc: i64) -> Insn {
    let op0 = bits(w, 25, 23);
    let rd = bits(w, 4, 0);
    let rn = bits(w, 9, 5);
    let sf = bit(w, 31);
    match op0 {
        0 | 1 => {
            let lo = bits(w, 30, 29) as i64;
            let hi = sext(bits(w, 23, 5), 19);
            if bit(w, 31) != 0 {
                let target = pc.div_euclid(4096) * 4096 + (hi * 4 + lo) * 4096;
                return mk("adrp", &[reg(xr(rd)), label(target)], 0).target(target);
            }
            let target = pc + hi * 4 + lo;
            mk("adr", &[reg(xr(rd)), label(target)], 0).target(target)
        }
        2 => {
            let op = bit(w, 30);
            let s = bit(w, 29);
            let sh = bit(w, 22);
            let value = bits(w, 21, 10) as i64;
            if op == 0 && s == 0 && sh == 0 && value == 0 && (rd == 31 || rn == 31) {
                return mk("mov", &[reg(gs(sf, rd)), reg(gs(sf, rn))], 0);
            }
            let mut ops = Ops::new();
            if s != 0 && rd == 31 {
                ops.push(reg(gs(sf, rn)));
                ops.push(imm(value));
                if sh != 0 {
                    ops.push(shift("lsl", 12));
                }
                return Insn::new(Mn::from(if op != 0 { "cmp" } else { "cmn" }), &ops, f::SETS_FLAGS);
            }
            let m = match (op, s) {
                (0, 0) => "add",
                (0, _) => "adds",
                (_, 0) => "sub",
                _ => "subs",
            };
            ops.push(reg(if s != 0 { gr(sf, rd) } else { gs(sf, rd) }));
            ops.push(reg(gs(sf, rn)));
            ops.push(imm(value));
            if sh != 0 {
                ops.push(shift("lsl", 12));
            }
            Insn::new(Mn::from(m), &ops, if s != 0 { f::SETS_FLAGS } else { 0 })
        }
        3 => {
            if bit(w, 22) != 0 {
                // SMAX/UMAX/SMIN/UMIN with an 8-bit immediate (FEAT_CSSC), signed for the s forms.
                let opc = bits(w, 21, 18);
                if bits(w, 30, 29) != 0 || opc > 3 {
                    return unknown(w);
                }
                let value = bits(w, 17, 10);
                let v = if opc & 1 != 0 { value as i64 } else { sext(value, 8) };
                return mk(["smax", "umax", "smin", "umin"][opc as usize], &[reg(gr(sf, rd)), reg(gr(sf, rn)), imm(v)], 0);
            }
            // ADDG/SUBG (memory tagging)
            if sf == 0 || bit(w, 29) != 0 {
                return unknown(w);
            }
            let m = if bit(w, 30) != 0 { "subg" } else { "addg" };
            mk(m, &[reg(xs(rd)), reg(xs(rn)), imm(bits(w, 21, 16) as i64 * 16), imm(bits(w, 13, 10) as i64)], 0)
        }
        4 => {
            let opc = bits(w, 30, 29);
            let n = bit(w, 22);
            let immr = bits(w, 21, 16);
            let imms = bits(w, 15, 10);
            let width = if sf != 0 { 64 } else { 32 };
            let Some(value) = decode_bit_mask(n, imms, immr, width) else { return unknown(w) };
            let op = big_imm(value as i128);
            if opc == 3 {
                if rd == 31 {
                    return mk("tst", &[reg(gr(sf, rn)), op], f::SETS_FLAGS);
                }
                return mk("ands", &[reg(gr(sf, rd)), reg(gr(sf, rn)), op], f::SETS_FLAGS);
            }
            if opc == 1 && rn == 31 && !mov_wide_fits(value, width) {
                return mk("mov", &[reg(gs(sf, rd)), big_imm(signed(value as u128, width))], 0);
            }
            mk(["and", "orr", "eor"][opc as usize], &[reg(gs(sf, rd)), reg(gr(sf, rn)), op], 0)
        }
        5 => {
            let opc = bits(w, 30, 29);
            let hw = bits(w, 22, 21);
            let value = bits(w, 20, 5);
            if opc == 1 || (sf == 0 && hw > 1) {
                return unknown(w);
            }
            let width = if sf != 0 { 64 } else { 32 };
            let amount = hw * 16;
            let wide = |m: &str| {
                let mut ops = Ops::new();
                ops.push(reg(gr(sf, rd)));
                ops.push(imm(value as i64));
                if amount != 0 {
                    ops.push(shift("lsl", amount as i64));
                }
                Insn::new(Mn::from(m), &ops, 0)
            };
            if opc == 3 {
                return wide("movk");
            }
            let plain = !(value == 0 && hw != 0);
            if opc == 2 && plain {
                return mk("mov", &[reg(gr(sf, rd)), big_imm(signed((value as u128) << amount, width))], 0);
            }
            if opc == 0 && plain && (sf != 0 || value != 0xffff) {
                let mask: u128 = (1u128 << width) - 1;
                return mk("mov", &[reg(gr(sf, rd)), big_imm(signed(!((value as u128) << amount) & mask, width))], 0);
            }
            wide(if opc == 2 { "movz" } else { "movn" })
        }
        6 => {
            let opc = bits(w, 30, 29);
            let n = bit(w, 22);
            let immr = bits(w, 21, 16) as i64;
            let imms = bits(w, 15, 10) as i64;
            if opc == 3 || n != sf || (sf == 0 && (immr > 31 || imms > 31)) {
                return unknown(w);
            }
            let width: i64 = if sf != 0 { 64 } else { 32 };
            let top = width - 1;
            let d = reg(gr(sf, rd));
            let s = reg(gr(sf, rn));
            let dec = imm_dec;
            if opc == 0 {
                if imms == top {
                    return mk("asr", &[d, s, dec(immr)], 0);
                }
                if imms < immr {
                    return mk("sbfiz", &[d, s, dec(width - immr), dec(imms + 1)], 0);
                }
                if immr == 0 && (imms == 7 || imms == 15 || imms == 31) {
                    let m = if imms == 7 {
                        "sxtb"
                    } else if imms == 15 {
                        "sxth"
                    } else {
                        "sxtw"
                    };
                    if !(m == "sxtw" && sf == 0) {
                        return mk(m, &[d, reg(wr(rn))], 0);
                    }
                }
                return mk("sbfx", &[d, s, dec(immr), dec(imms - immr + 1)], 0);
            }
            if opc == 1 {
                if imms < immr {
                    return mk("bfi", &[d, s, dec(width - immr), dec(imms + 1)], 0);
                }
                return mk("bfxil", &[d, s, dec(immr), dec(imms - immr + 1)], 0);
            }
            if imms != top && imms + 1 == immr {
                return mk("lsl", &[d, s, dec(top - imms)], 0);
            }
            if imms == top {
                return mk("lsr", &[d, s, dec(immr)], 0);
            }
            if imms < immr {
                return mk("ubfiz", &[d, s, dec(width - immr), dec(imms + 1)], 0);
            }
            if immr == 0 && sf == 0 && (imms == 7 || imms == 15) {
                return mk(if imms == 7 { "uxtb" } else { "uxth" }, &[d, reg(wr(rn))], 0);
            }
            mk("ubfx", &[d, s, dec(immr), dec(imms - immr + 1)], 0)
        }
        _ => {
            if bits(w, 31, 22) == 0x3ce {
                // AUTIASPPC / AUTIBSPPC (FEAT_PAuth_LR): the label is where the return address was signed.
                if rd != 31 {
                    return unknown(w);
                }
                return mk(if bit(w, 21) != 0 { "autibsppc" } else { "autiasppc" }, &[label(pc - bits(w, 20, 5) as i64 * 4)], 0);
            }
            let op21 = bits(w, 30, 29);
            let n = bit(w, 22);
            let o0 = bit(w, 21);
            let rm = bits(w, 20, 16);
            let lsb = bits(w, 15, 10);
            if op21 != 0 || o0 != 0 || n != sf || (sf == 0 && lsb > 31) {
                return unknown(w);
            }
            if rn == rm {
                return mk("ror", &[reg(gr(sf, rd)), reg(gr(sf, rn)), imm(lsb as i64)], 0);
            }
            mk("extr", &[reg(gr(sf, rd)), reg(gr(sf, rn)), reg(gr(sf, rm)), imm(lsb as i64)], 0)
        }
    }
}

/* ------------------------------------------------------------------ *
 * Branches, exception generation, system
 * ------------------------------------------------------------------ */

pub fn hint_name(value: u32) -> Option<&'static str> {
    Some(match value {
        0 => "nop",
        1 => "yield",
        2 => "wfe",
        3 => "wfi",
        4 => "sev",
        5 => "sevl",
        6 => "dgh",
        7 => "xpaclri",
        8 => "pacia1716",
        10 => "pacib1716",
        12 => "autia1716",
        14 => "autib1716",
        16 => "esb",
        17 => "psb csync",
        18 => "tsb csync",
        19 => "gcsb dsync",
        20 => "csdb",
        22 => "clrbhb",
        24 => "paciaz",
        25 => "paciasp",
        26 => "pacibz",
        27 => "pacibsp",
        28 => "autiaz",
        29 => "autiasp",
        30 => "autibz",
        31 => "autibsp",
        32 => "bti r",
        34 => "bti c",
        36 => "bti j",
        38 => "bti jc",
        39 => "pacm",
        40 => "chkfeat x16",
        _ => return None,
    })
}

pub fn barrier_name(crm: u32) -> Option<&'static str> {
    Some(match crm {
        1 => "oshld",
        2 => "oshst",
        3 => "osh",
        5 => "nshld",
        6 => "nshst",
        7 => "nsh",
        9 => "ishld",
        10 => "ishst",
        11 => "ish",
        13 => "ld",
        14 => "st",
        15 => "sy",
        _ => return None,
    })
}

fn pstate(op1: u32, op2: u32) -> Option<&'static str> {
    Some(match (op1, op2) {
        (0, 5) => "SPSel",
        (3, 6) => "DAIFSet",
        (3, 7) => "DAIFClr",
        (0, 3) => "UAO",
        (0, 4) => "PAN",
        (3, 2) => "DIT",
        (3, 1) => "SSBS",
        (3, 4) => "TCO",
        _ => return None,
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Takes {
    Reg,
    None,
    Any,
}

/// SYS operations LLVM names, by op1, CRn, CRm, op2: cache maintenance, the
/// speculation-restriction and trace operations, and the Guarded Control Stack
/// pushes and pops. `Takes::Reg` says the operation takes Xt; one that does not
/// gets its name only when Xt is xzr (`gcspushx`), except the instruction-cache
/// invalidates, which LLVM names whatever Xt holds. TLB and address-translation
/// operations, which only an operating system runs, stay `sys`.
fn sys_op(op1: u32, crn: u32, crm: u32, op2: u32) -> Option<(&'static str, &'static str, Takes)> {
    use Takes::*;
    Some(match (op1, crn, crm, op2) {
        (0, 7, 1, 0) => ("ic", "ialluis", Any),
        (0, 7, 5, 0) => ("ic", "iallu", Any),
        (3, 7, 5, 1) => ("ic", "ivau", Reg),
        (3, 7, 4, 1) => ("dc", "zva", Reg),
        (3, 7, 10, 1) => ("dc", "cvac", Reg),
        (3, 7, 11, 1) => ("dc", "cvau", Reg),
        (3, 7, 14, 1) => ("dc", "civac", Reg),
        (3, 7, 12, 1) => ("dc", "cvap", Reg),
        (3, 7, 13, 1) => ("dc", "cvadp", Reg),
        (0, 7, 6, 1) => ("dc", "ivac", Reg),
        (0, 7, 6, 2) => ("dc", "isw", Reg),
        (0, 7, 10, 2) => ("dc", "csw", Reg),
        (0, 7, 14, 2) => ("dc", "cisw", Reg),
        (0, 7, 15, 1) => ("dc", "civaps", Reg),
        (0, 7, 6, 3) => ("dc", "igvac", Reg),
        (0, 7, 6, 4) => ("dc", "igsw", Reg),
        (0, 7, 6, 5) => ("dc", "igdvac", Reg),
        (0, 7, 6, 6) => ("dc", "igdsw", Reg),
        (0, 7, 10, 4) => ("dc", "cgsw", Reg),
        (0, 7, 10, 6) => ("dc", "cgdsw", Reg),
        (0, 7, 14, 4) => ("dc", "cigsw", Reg),
        (0, 7, 14, 6) => ("dc", "cigdsw", Reg),
        (0, 7, 15, 5) => ("dc", "cigdvaps", Reg),
        (3, 7, 4, 3) => ("dc", "gva", Reg),
        (3, 7, 4, 4) => ("dc", "gzva", Reg),
        (3, 7, 4, 5) => ("dc", "zgbva", Reg),
        (3, 7, 4, 7) => ("dc", "gbva", Reg),
        (3, 7, 10, 3) => ("dc", "cgvac", Reg),
        (3, 7, 10, 5) => ("dc", "cgdvac", Reg),
        (3, 7, 12, 3) => ("dc", "cgvap", Reg),
        (3, 7, 12, 5) => ("dc", "cgdvap", Reg),
        (3, 7, 13, 3) => ("dc", "cgvadp", Reg),
        (3, 7, 13, 5) => ("dc", "cgdvadp", Reg),
        (3, 7, 14, 3) => ("dc", "cigvac", Reg),
        (3, 7, 14, 5) => ("dc", "cigdvac", Reg),
        (3, 7, 11, 0) => ("dc", "cvaoc", Reg),
        (3, 7, 11, 7) => ("dc", "cgdvaoc", Reg),
        (3, 7, 15, 0) => ("dc", "civaoc", Reg),
        (3, 7, 15, 7) => ("dc", "cigdvaoc", Reg),
        (4, 7, 14, 0) => ("dc", "cipae", Reg),
        (4, 7, 14, 7) => ("dc", "cigdpae", Reg),
        (6, 7, 14, 1) => ("dc", "cipapa", Reg),
        (6, 7, 14, 5) => ("dc", "cigdpapa", Reg),
        (3, 7, 3, 4) => ("cfp", "rctx", Reg),
        (3, 7, 3, 5) => ("dvp", "rctx", Reg),
        (3, 7, 3, 6) => ("cosp", "rctx", Reg),
        (3, 7, 3, 7) => ("cpp", "rctx", Reg),
        (3, 7, 2, 7) => ("trcit", "", Reg),
        (6, 7, 0, 0) => ("apas", "", Reg),
        (1, 7, 2, 4) => ("brb", "iall", None),
        (1, 7, 2, 5) => ("brb", "inj", None),
        (3, 7, 7, 0) => ("gcspushm", "", Reg),
        (3, 7, 7, 2) => ("gcsss1", "", Reg),
        (0, 7, 7, 4) => ("gcspushx", "", None),
        (0, 7, 7, 5) => ("gcspopcx", "", None),
        (0, 7, 7, 6) => ("gcspopx", "", None),
        _ => return Option::None,
    })
}

#[inline]
fn ctext(prefix: &str, n: u32) -> Op {
    Op::Text(sfmt!(Text, "{}{}", prefix, n))
}

#[inline]
fn sysreg(op0: u32, op1: u32, crn: u32, crm: u32, op2: u32) -> Op {
    Op::Text(sysreg_name(op0, op1, crn, crm, op2))
}

/// Op0 = 0 with L = 0: hints, barriers, PSTATE fields and a few more; anything else is a plain msr.
fn system_op0(w: u32) -> Insn {
    let op1 = bits(w, 18, 16);
    let crn = bits(w, 15, 12);
    let crm = bits(w, 11, 8);
    let op2 = bits(w, 7, 5);
    let rt = bits(w, 4, 0);
    if crn == 2 && rt == 31 && op1 == 3 {
        let value = (crm << 3) | op2;
        return match hint_name(value) {
            Some(name) => match name.split_once(' ') {
                Some((m, arg)) => mk(m, &[text(arg)], 0),
                None => mk(name, &[], 0),
            },
            None => mk("hint", &[imm(value as i64)], 0),
        };
    }
    if crn == 3 && rt == 31 && op1 == 3 {
        // Barrier numbers without a name print in decimal.
        let option = || match barrier_name(crm) {
            Some(name) => text(name),
            None => imm_dec(crm as i64),
        };
        match op2 {
            1 => {
                // DSB with the nXS qualifier (FEAT_XS): the domain is in CRm<3:2>.
                if crm & 3 == 2 {
                    return mk("dsb", &[Op::Text(sfmt!(Text, "{}nxs", ["osh", "nsh", "ish", "sy"][(crm >> 2) as usize]))], 0);
                }
            }
            2 => return if crm == 15 { mk("clrex", &[], 0) } else { mk("clrex", &[imm(crm as i64)], 0) },
            3 => {
                if crm == 0 {
                    return mk("tcommit", &[], 0);
                }
            }
            4 => {
                if crm == 0 {
                    return mk("ssbb", &[], 0);
                }
                if crm == 4 {
                    return mk("pssbb", &[], 0);
                }
                if crm == 12 {
                    return mk("dfb", &[], 0);
                }
                return mk("dsb", &[option()], 0);
            }
            5 => return mk("dmb", &[option()], 0),
            6 => return if crm == 15 { mk("isb", &[], 0) } else { mk("isb", &[imm_dec(crm as i64)], 0) },
            7 => return mk("sb", &[], 0),
            _ => {}
        }
    }
    if crn == 4 && rt == 31 {
        if op1 == 0 && op2 < 3 {
            return mk(["cfinv", "xaflag", "axflag"][op2 as usize], &[], f::SETS_FLAGS | f::READS_FLAGS);
        }
        if op1 == 3 && op2 == 3 {
            // SVCR: SMSTART / SMSTOP; CRm<2:1> picks SM, ZA or both, CRm<0> the value.
            let which = (crm >> 1) & 3;
            if crm < 8 && which != 0 {
                let m = if crm & 1 != 0 { "smstart" } else { "smstop" };
                return match which {
                    1 => mk(m, &[text("sm")], 0),
                    2 => mk(m, &[text("za")], 0),
                    _ => mk(m, &[], 0),
                };
            }
        } else if op1 == 1 && op2 == 0 {
            // ALLINT (FEAT_NMI) and PM (FEAT_EBEP) take a single bit from CRm<0>.
            if crm < 4 {
                return mk("msr", &[text(if crm < 2 { "ALLINT" } else { "PM" }), imm((crm & 1) as i64)], 0);
            }
        } else if let Some(field) = pstate(op1, op2) {
            return mk("msr", &[text(field), imm(crm as i64)], 0);
        }
    }
    if op1 == 3 && crn == 1 && crm == 0 && op2 < 2 {
        return mk(if op2 != 0 { "wfit" } else { "wfet" }, &[reg(xr(rt))], 0);
    }
    if op1 == 1 && crn == 9 && crm == 6 && rt == 31 {
        let op = if op2 < 2 { text(if op2 != 0 { "strm" } else { "keep" }) } else { imm(op2 as i64) };
        return mk("stshh", &[op], 0);
    }
    mk("msr", &[sysreg(0, op1, crn, crm, op2), reg(xr(rt))], 0)
}

fn system(w: u32) -> Insn {
    let l = bit(w, 21);
    let op0 = bits(w, 20, 19);
    let op1 = bits(w, 18, 16);
    let crn = bits(w, 15, 12);
    let crm = bits(w, 11, 8);
    let op2 = bits(w, 7, 5);
    let rt = bits(w, 4, 0);
    if op0 == 0 {
        if l == 0 {
            return system_op0(w);
        }
        // TSTART and TTEST (transactional memory) read into Xt; the rest of this space is mrs.
        if op1 == 3 && crn == 3 && crm < 2 && op2 == 3 {
            return mk(if crm != 0 { "ttest" } else { "tstart" }, &[reg(xr(rt))], 0);
        }
        return mk("mrs", &[reg(xr(rt)), sysreg(0, op1, crn, crm, op2)], 0);
    }
    if op0 == 1 {
        let sys = [imm(op1 as i64), ctext("c", crn), ctext("c", crm), imm(op2 as i64)];
        if l != 0 {
            // GCSPOPM and GCSSS2 return a value from the Guarded Control Stack.
            if op1 == 3 && crn == 7 && crm == 7 && op2 == 1 {
                return if rt == 31 { mk("gcspopm", &[], 0) } else { mk("gcspopm", &[reg(xr(rt))], 0) };
            }
            if op1 == 3 && crn == 7 && crm == 7 && op2 == 3 {
                return mk("gcsss2", &[reg(xr(rt))], 0);
            }
            let mut ops = Ops::new();
            ops.push(reg(xr(rt)));
            ops.extend(&sys);
            return Insn::new(Mn::from("sysl"), &ops, 0);
        }
        if let Some((m, op, takes)) = sys_op(op1, crn, crm, op2) {
            let mut ops = Ops::new();
            if !op.is_empty() {
                ops.push(text(op));
            }
            if takes == Takes::Reg {
                ops.push(reg(xr(rt)));
                return Insn::new(Mn::from(m), &ops, 0);
            }
            if takes == Takes::Any || rt == 31 {
                return Insn::new(Mn::from(m), &ops, 0);
            }
        }
        let mut ops = Ops::from_slice(&sys);
        if rt != 31 {
            ops.push(reg(xr(rt)));
        }
        return Insn::new(Mn::from("sys"), &ops, 0);
    }
    let name = sysreg_name(op0, op1, crn, crm, op2);
    let nzcv = name == "NZCV";
    if l != 0 {
        mk("mrs", &[reg(xr(rt)), Op::Text(name)], if nzcv { f::READS_FLAGS } else { 0 })
    } else {
        mk("msr", &[Op::Text(name), reg(xr(rt))], if nzcv { f::SETS_FLAGS } else { 0 })
    }
}

/// The 128-bit system instructions (FEAT_SYSREG128, FEAT_SYSINSTR128): MRRS and
/// MSRR move a register pair, SYSP is SYS with a pair. Xt must be even; x30
/// pairs with xzr.
fn system_pair(w: u32) -> Insn {
    let l = bit(w, 21);
    let op0 = bits(w, 20, 19);
    let op1 = bits(w, 18, 16);
    let crn = bits(w, 15, 12);
    let crm = bits(w, 11, 8);
    let op2 = bits(w, 7, 5);
    let rt = bits(w, 4, 0);
    if rt & 1 != 0 && rt != 31 {
        return unknown(w);
    }
    let mut pair = Ops::new();
    if rt != 31 {
        pair.push(reg(xr(rt)));
        pair.push(reg(xr_next(rt)));
    }
    let name = Op::Text(sysreg_name(op0, op1, crn, crm, op2));
    if l != 0 {
        if rt == 31 {
            return unknown(w);
        }
        let mut ops = pair;
        ops.push(name);
        return Insn::new(Mn::from("mrrs"), &ops, 0);
    }
    if op0 != 1 {
        if rt == 31 {
            return unknown(w);
        }
        let mut ops = Ops::new();
        ops.push(name);
        ops.extend(&pair);
        return Insn::new(Mn::from("msrr"), &ops, 0);
    }
    let mut ops = Ops::from_slice(&[imm(op1 as i64), ctext("c", crn), ctext("c", crm), imm(op2 as i64)]);
    ops.extend(&pair);
    Insn::new(Mn::from("sysp"), &ops, 0)
}

/// TCHANGEF / TCHANGEB (FEAT_S1POE2): change the permission-overlay TIndex to Xn or an immediate.
fn tchange(w: u32) -> Insn {
    let m = if bit(w, 18) != 0 { "tchangeb" } else { "tchangef" };
    if bit(w, 21) != 0 || bit(w, 19) != 0 || bit(w, 16) != 0 {
        return unknown(w);
    }
    let mut ops = Ops::new();
    ops.push(reg(xr(bits(w, 4, 0))));
    if bit(w, 20) != 0 {
        if bits(w, 15, 12) != 0 {
            return unknown(w);
        }
        ops.push(imm(bits(w, 11, 5) as i64));
    } else {
        if bits(w, 15, 10) != 0 {
            return unknown(w);
        }
        ops.push(reg(xr(bits(w, 9, 5))));
    }
    if bit(w, 17) != 0 {
        ops.push(text("nb"));
    }
    Insn::new(Mn::from(m), &ops, 0)
}

const CB_IMM: [&str; 8] = ["gt", "lt", "hi", "lo", "", "", "eq", "ne"];
const CB_REG: [&str; 8] = ["gt", "ge", "hi", "hs", "", "", "eq", "ne"];

/// CB<cc> (FEAT_CMPBR): compare a register with a register or a 6-bit
/// immediate and branch, without touching the flags. CBB and CBH compare the
/// low byte or halfword. LLVM prints the encoded condition, never the swapped
/// aliases (cblt for cbgt with the registers exchanged).
fn compare_branch(w: u32, pc: i64) -> Insn {
    let sf = bit(w, 31);
    let rt = bits(w, 4, 0);
    let target = pc + sext(bits(w, 13, 5), 9) * 4;
    let lbl = label(target);
    if bit(w, 24) != 0 {
        let c = CB_IMM[bits(w, 23, 21) as usize];
        if c.is_empty() || bit(w, 14) != 0 {
            return unknown(w);
        }
        return Insn::new(sfmt!(Mn, "cb{}", c), &[reg(gr(sf, rt)), imm(bits(w, 20, 15) as i64), lbl], f::BRANCH | f::COND).target(target).cond(c);
    }
    let c = CB_REG[bits(w, 23, 21) as usize];
    let width = bits(w, 15, 14);
    if c.is_empty() || width == 1 || (width != 0 && sf != 0) {
        return unknown(w);
    }
    let size = match width {
        2 => "b",
        3 => "h",
        _ => "",
    };
    Insn::new(sfmt!(Mn, "cb{}{}", size, c), &[reg(gr(sf, rt)), reg(gr(sf, bits(w, 20, 16))), lbl], f::BRANCH | f::COND).target(target).cond(c)
}

fn branches(w: u32, pc: i64) -> Insn {
    let op0 = bits(w, 31, 29);
    if op0 & 3 == 0 && bit(w, 30) == 0 {
        // B / BL
        let target = pc + sext(bits(w, 25, 0), 26) * 4;
        return if bit(w, 31) != 0 { mk("bl", &[label(target)], f::CALL).target(target) } else { mk("b", &[label(target)], f::BRANCH).target(target) };
    }
    if op0 & 3 == 1 {
        if bit(w, 25) == 0 {
            let sf = bit(w, 31);
            let target = pc + sext(bits(w, 23, 5), 19) * 4;
            return mk(if bit(w, 24) != 0 { "cbnz" } else { "cbz" }, &[reg(gr(sf, bits(w, 4, 0))), label(target)], f::BRANCH | f::COND).target(target);
        }
        let b5 = bit(w, 31);
        let number = (b5 << 5) | bits(w, 23, 19);
        let target = pc + sext(bits(w, 18, 5), 14) * 4;
        return mk(if bit(w, 24) != 0 { "tbnz" } else { "tbz" }, &[reg(gr(b5, bits(w, 4, 0))), imm(number as i64), label(target)], f::BRANCH | f::COND).target(target);
    }
    if op0 & 3 == 3 && bit(w, 25) == 0 {
        return compare_branch(w, pc);
    }
    if op0 == 2 {
        if bits(w, 25, 24) == 1 && bits(w, 23, 22) == 0 && bits(w, 4, 0) == 31 {
            // RETAASPPC / RETABSPPC (FEAT_PAuth_LR): return, authenticating against the signing address.
            return mk(if bit(w, 21) != 0 { "retabsppc" } else { "retaasppc" }, &[label(pc - bits(w, 20, 5) as i64 * 4)], f::BRANCH | f::RET | f::INDIRECT);
        }
        if bit(w, 25) != 0 || bit(w, 24) != 0 {
            return unknown(w);
        }
        let target = pc + sext(bits(w, 23, 5), 19) * 4;
        let c = cond(bits(w, 3, 0));
        let consistent = bit(w, 4);
        let flags = f::BRANCH | if c == "al" || c == "nv" { 0 } else { f::COND } | f::READS_FLAGS;
        return Insn::new(sfmt!(Mn, "{}.{}", if consistent != 0 { "bc" } else { "b" }, c), &[label(target)], flags).target(target).cond(c);
    }
    if op0 == 6 {
        if bits(w, 25, 24) == 0 {
            let opc = bits(w, 23, 21);
            let ll = bits(w, 1, 0);
            let value = bits(w, 20, 5);
            if bits(w, 4, 2) != 0 {
                return unknown(w);
            }
            let name = ["", "brk", "hlt", "tcancel", "", "dcps", "", ""][opc as usize];
            if opc == 0 {
                let m = ["", "svc", "hvc", "smc"][ll as usize];
                return if m.is_empty() { unknown(w) } else { mk(m, &[imm(value as i64)], 0) };
            }
            if opc == 5 {
                if ll == 0 {
                    return unknown(w);
                }
                let m = sfmt!(Mn, "dcps{}", ll);
                return if value != 0 { Insn::new(m, &[imm(value as i64)], 0) } else { Insn::new(m, &[], 0) };
            }
            if opc == 7 {
                // TENTER (FEAT_TEV): an exception-like entry through the vector the 7-bit immediate picks.
                // Like svc, execution comes back to the next instruction (through TEXIT).
                if ll != 0 || value & !0x107f != 0 {
                    return unknown(w);
                }
                let mut ops = Ops::new();
                ops.push(imm((value & 0x7f) as i64));
                if value & 0x1000 != 0 {
                    ops.push(text("nb"));
                }
                return Insn::new(Mn::from("tenter"), &ops, 0);
            }
            if name.is_empty() || ll != 0 {
                return unknown(w);
            }
            return mk(name, &[imm(value as i64)], if opc == 1 || opc == 2 { f::TRAP } else { 0 });
        }
        match bits(w, 25, 22) {
            4 => return system(w),
            5 => return system_pair(w),
            6 => return tchange(w),
            _ => {}
        }
        if bit(w, 25) != 0 {
            let opc = bits(w, 24, 21);
            let op2 = bits(w, 20, 16);
            let op3 = bits(w, 15, 10);
            let rn = bits(w, 9, 5);
            let op4 = bits(w, 4, 0);
            if op2 != 31 {
                return unknown(w);
            }
            if op3 == 0 && op4 == 0 {
                if opc == 0 {
                    return mk("br", &[reg(xr(rn))], f::BRANCH | f::INDIRECT);
                }
                if opc == 1 {
                    return mk("blr", &[reg(xr(rn))], f::CALL | f::INDIRECT);
                }
                if opc == 2 {
                    return if rn == 30 { mk("ret", &[], f::BRANCH | f::RET | f::INDIRECT) } else { mk("ret", &[reg(xr(rn))], f::BRANCH | f::RET | f::INDIRECT) };
                }
                if opc == 4 && rn == 31 {
                    return mk("eret", &[], f::BRANCH | f::RET);
                }
                if opc == 7 && rn == 31 {
                    return mk("texit", &[], f::BRANCH | f::RET);
                }
                if opc == 5 && rn == 31 {
                    return mk("drps", &[], f::BRANCH);
                }
            }
            if opc == 7 && op3 == 1 && rn == 31 && op4 == 0 {
                return mk("texit", &[text("nb")], f::BRANCH | f::RET);
            }
            if op3 & 0x3e == 2 {
                let key = if op3 & 1 != 0 { "b" } else { "a" };
                if opc == 0 && op4 == 31 {
                    return Insn::new(sfmt!(Mn, "bra{}z", key), &[reg(xr(rn))], f::BRANCH | f::INDIRECT);
                }
                if opc == 1 && op4 == 31 {
                    return Insn::new(sfmt!(Mn, "blra{}z", key), &[reg(xr(rn))], f::CALL | f::INDIRECT);
                }
                if opc == 2 && rn == 31 && op4 == 31 {
                    return Insn::new(sfmt!(Mn, "reta{}", key), &[], f::BRANCH | f::RET | f::INDIRECT);
                }
                if opc == 2 && rn == 31 {
                    return Insn::new(sfmt!(Mn, "reta{}sppcr", key), &[reg(xr(op4))], f::BRANCH | f::RET | f::INDIRECT);
                }
                if opc == 4 && rn == 31 && op4 == 31 {
                    return Insn::new(sfmt!(Mn, "ereta{}", key), &[], f::BRANCH | f::RET);
                }
                if opc == 8 {
                    return Insn::new(sfmt!(Mn, "bra{}", key), &[reg(xr(rn)), reg(xs(op4))], f::BRANCH | f::INDIRECT);
                }
                if opc == 9 {
                    return Insn::new(sfmt!(Mn, "blra{}", key), &[reg(xr(rn)), reg(xs(op4))], f::CALL | f::INDIRECT);
                }
            }
            return unknown(w);
        }
    }
    unknown(w)
}

/* ------------------------------------------------------------------ *
 * Loads and stores
 * ------------------------------------------------------------------ */

/// How a load or store names its transfer register.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RegKind {
    X,
    W,
    Fp(u8),
}

impl RegKind {
    #[inline]
    fn name(self, n: u32) -> Name {
        match self {
            RegKind::X => xr(n),
            RegKind::W => wr(n),
            RegKind::Fp(p) => fp_reg(p, n),
        }
    }
}

#[derive(Clone, Copy)]
struct Access {
    load: bool,
    /// Suffix after ldr/ldur/ldtr: '', 'b', 'h', 'sb', 'sh', 'sw'.
    ext: &'static str,
    rt: RegKind,
    bytes: u32,
    signed: bool,
    prefetch: bool,
}

/// What size, V and opc of a single-register load or store mean.
fn access(size: u32, v: u32, opc: u32) -> Option<Access> {
    let a = |load: bool, ext: &'static str, rt: RegKind, bytes: u32| Access { load, ext, rt, bytes, signed: false, prefetch: false };
    if v != 0 {
        if opc & 2 != 0 {
            return if size == 0 { Some(a(opc & 1 != 0, "", RegKind::Fp(b'q'), 16)) } else { None };
        }
        return Some(a(opc & 1 != 0, "", RegKind::Fp(b"bhsd"[size as usize]), 1 << size));
    }
    let bytes = 1 << size;
    let ext = ["b", "h", "", ""][size as usize];
    let gpr = if size == 3 { RegKind::X } else { RegKind::W };
    if opc == 0 {
        return Some(a(false, ext, gpr, bytes));
    }
    if opc == 1 {
        return Some(a(true, ext, gpr, bytes));
    }
    if size == 3 {
        return if opc == 2 { Some(Access { prefetch: true, ..a(true, "", RegKind::X, 8) }) } else { None };
    }
    if size == 2 {
        return if opc == 2 { Some(Access { signed: true, ..a(true, "sw", RegKind::X, 4) }) } else { None };
    }
    Some(Access { signed: true, ..a(true, if size == 0 { "sb" } else { "sh" }, if opc == 2 { RegKind::X } else { RegKind::W }, bytes) })
}

const PRF_TYPES: [&str; 3] = ["pld", "pli", "pst"];

fn rprf_op(op: u32) -> Option<&'static str> {
    match op {
        0 => Some("pldkeep"),
        1 => Some("pstkeep"),
        4 => Some("pldstrm"),
        5 => Some("pststrm"),
        _ => None,
    }
}

fn prfop(rt: u32) -> Op {
    let kind = rt >> 3;
    let target = (rt >> 1) & 3;
    if kind < 3 {
        let mut t = Text::from(PRF_TYPES[kind as usize]);
        if target < 3 {
            t.push("l");
            t.push(["1", "2", "3"][target as usize]);
        } else {
            t.push("slc");
        }
        t.push(if rt & 1 != 0 { "strm" } else { "keep" });
        return Op::Text(t);
    }
    imm(rt as i64)
}

#[inline]
fn mem_flags(a: &Access) -> u32 {
    if a.prefetch {
        0
    } else if a.load {
        f::LOAD
    } else {
        f::STORE
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Form {
    Uimm,
    Unscaled,
    Post,
    Pre,
    Unpriv,
    RegOff,
}

#[inline]
fn base(n: u32) -> Name {
    xs(n)
}

fn single(w: u32, form: Form) -> Insn {
    let size = bits(w, 31, 30);
    let v = bit(w, 26);
    let opc = bits(w, 23, 22);
    let rn = bits(w, 9, 5);
    let rt = bits(w, 4, 0);
    let Some(a) = access(size, v, opc) else { return unknown(w) };
    if form == Form::Unpriv && (v != 0 || a.prefetch) {
        return unknown(w);
    }
    if (form == Form::Post || form == Form::Pre) && a.prefetch {
        return unknown(w);
    }
    let mnemonic = if a.prefetch {
        Mn::from(if form == Form::Unscaled { "prfum" } else { "prfm" })
    } else {
        let mut m = Mn::from(if a.load { "ld" } else { "st" });
        m.push(match form {
            Form::Unscaled => "ur",
            Form::Unpriv => "tr",
            _ => "r",
        });
        m.push(a.ext);
        m
    };
    let target = if a.prefetch { prfop(rt) } else { reg(a.rt.name(rt)) };
    let done = |ops: &[Op]| Insn::new(mnemonic, ops, mem_flags(&a)).size(a.bytes).signed(a.signed);
    if form == Form::RegOff {
        let rm = bits(w, 20, 16);
        let option = bits(w, 15, 13);
        let s = bit(w, 12);
        if option & 2 == 0 {
            return unknown(w);
        }
        if a.prefetch && rt >> 3 == 3 {
            // RPRFM: a range prefetch, its operation built from option<2>, option<0>, S and Rt<2:0>; Xm is the range.
            let op = ((option >> 2) << 5) | ((option & 1) << 4) | (s << 3) | (rt & 7);
            let first = match rprf_op(op) {
                Some(name) => text(name),
                None => imm(op as i64),
            };
            return mk("rprfm", &[first, reg(xr(rm)), mem(base(rn), 0, Mode::Off)], 0);
        }
        let scale = if v != 0 && opc & 2 != 0 { 4 } else { size };
        let ext = ["", "", "uxtw", "lsl", "", "", "sxtw", "sxtx"][option as usize];
        let index = if option & 1 != 0 { xr(rm) } else { wr(rm) };
        let shown = s == 1;
        let mut m = Mem::new(base(rn), 0, Mode::Off);
        m.index = Some(index);
        m.ext = if ext == "lsl" && !shown { None } else { Some(Name::from(ext)) };
        m.amount = Some(if s != 0 { scale as u8 } else { 0 });
        m.show_amount = shown;
        return done(&[target, Op::Mem(m)]);
    }
    if form == Form::Uimm {
        let scale = if v != 0 && opc & 2 != 0 { 4 } else { size };
        let off = (bits(w, 21, 10) as i64) << scale;
        return done(&[target, mem(base(rn), off, Mode::Off)]);
    }
    let off = sext(bits(w, 20, 12), 9);
    let mode = match form {
        Form::Post => Mode::Post,
        Form::Pre => Mode::Pre,
        _ => Mode::Off,
    };
    done(&[target, mem(base(rn), off, mode)])
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PairForm {
    NoAlloc,
    Post,
    Off,
    Pre,
}

fn pair(w: u32, form: PairForm) -> Insn {
    let opc = bits(w, 31, 30);
    let v = bit(w, 26);
    let l = bit(w, 22);
    let imm7 = sext(bits(w, 21, 15), 7);
    let rt2 = bits(w, 14, 10);
    let rn = bits(w, 9, 5);
    let rt = bits(w, 4, 0);
    let name: RegKind;
    let scale: u32;
    let mut mnemonic = match (form == PairForm::NoAlloc, l != 0) {
        (true, true) => "ldnp",
        (true, false) => "stnp",
        (false, true) => "ldp",
        (false, false) => "stp",
    };
    let mut signed_load = false;
    if opc == 3 {
        // LDTP / STTP (FEAT_LSUI): a pair accessed with user (EL0) permissions, of X or Q registers.
        name = if v != 0 { RegKind::Fp(b'q') } else { RegKind::X };
        scale = if v != 0 { 4 } else { 3 };
        mnemonic = match mnemonic {
            "ldnp" => "ldtnp",
            "stnp" => "sttnp",
            "ldp" => "ldtp",
            _ => "sttp",
        };
    } else if v != 0 {
        name = RegKind::Fp(b"sdq"[opc as usize]);
        scale = 2 + opc;
    } else if opc == 0 {
        name = RegKind::W;
        scale = 2;
    } else if opc == 2 {
        name = RegKind::X;
        scale = 3;
    } else if opc == 1 && l != 0 && form != PairForm::NoAlloc {
        name = RegKind::X;
        scale = 2;
        mnemonic = "ldpsw";
        signed_load = true;
    } else if opc == 1 && l == 0 && form != PairForm::NoAlloc {
        // STGP (memory tagging): stores two registers and the tag
        name = RegKind::X;
        scale = 4;
        mnemonic = "stgp";
    } else {
        return unknown(w);
    }
    let off = imm7 * (1i64 << scale);
    let mode = match form {
        PairForm::Post => Mode::Post,
        PairForm::Pre => Mode::Pre,
        _ => Mode::Off,
    };
    mk(mnemonic, &[reg(name.name(rt)), reg(name.name(rt2)), mem(base(rn), off, mode)], if l != 0 { f::LOAD } else { f::STORE })
        .size(if mnemonic == "stgp" { 8 } else { 1 << scale })
        .signed(signed_load)
}

/// The FEAT_LSUI exclusives and compare-and-swaps: the same operations as their
/// privileged forms, but checked against user (EL0) permissions.
fn exclusive_unprivileged(w: u32) -> Insn {
    let size = bits(w, 31, 30);
    let o2 = bit(w, 23);
    let l = bit(w, 22);
    let rs = bits(w, 20, 16);
    let o0 = bit(w, 15);
    let rn = bits(w, 9, 5);
    let rt = bits(w, 4, 0);
    let m0 = mem(base(rn), 0, Mode::Off);
    if bit(w, 21) != 0 {
        return unknown(w);
    }
    if o2 == 0 {
        if size < 2 {
            return unknown(w);
        }
        let r = if size == 3 { RegKind::X } else { RegKind::W };
        if l != 0 {
            return Insn::new(sfmt!(Mn, "ld{}txr", if o0 != 0 { "a" } else { "" }), &[reg(r.name(rt)), m0], f::LOAD | f::ATOMIC).size(1 << size);
        }
        return Insn::new(sfmt!(Mn, "st{}txr", if o0 != 0 { "l" } else { "" }), &[reg(wr(rs)), reg(r.name(rt)), m0], f::STORE | f::ATOMIC).size(1 << size);
    }
    let order = order(l, o0);
    if size == 3 {
        return Insn::new(sfmt!(Mn, "cas{}t", order), &[reg(xr(rs)), reg(xr(rt)), m0], f::LOAD | f::STORE | f::ATOMIC).size(8);
    }
    if size == 1 && rs & 1 == 0 && rt & 1 == 0 {
        return Insn::new(sfmt!(Mn, "casp{}t", order), &[reg(xr(rs)), reg(xr_next(rs)), reg(xr(rt)), reg(xr_next(rt)), m0], f::LOAD | f::STORE | f::ATOMIC).size(8);
    }
    unknown(w)
}

/// `a`, `l`, `al` or nothing: the ordering suffix of an atomic.
#[inline]
fn order(a: u32, l: u32) -> &'static str {
    match (a != 0, l != 0) {
        (true, true) => "al",
        (true, false) => "a",
        (false, true) => "l",
        (false, false) => "",
    }
}

fn exclusive(w: u32) -> Insn {
    let size = bits(w, 31, 30);
    let o2 = bit(w, 23);
    let l = bit(w, 22);
    let o1 = bit(w, 21);
    let rs = bits(w, 20, 16);
    let o0 = bit(w, 15);
    let rt2 = bits(w, 14, 10);
    let rn = bits(w, 9, 5);
    let rt = bits(w, 4, 0);
    let sfx = ["b", "h", "", ""][size as usize];
    let r = if size == 3 { RegKind::X } else { RegKind::W };
    let m0 = mem(base(rn), 0, Mode::Off);
    let bytes = 1 << size;
    if o2 == 1 && o1 == 1 {
        // CAS, CASA, CASL, CASAL (+B/H)
        if rt2 != 31 {
            return unknown(w);
        }
        return Insn::new(sfmt!(Mn, "cas{}{}", order(l, o0), sfx), &[reg(r.name(rs)), reg(r.name(rt)), m0], f::LOAD | f::STORE | f::ATOMIC).size(bytes);
    }
    if o2 == 0 && o1 == 1 {
        if size < 2 {
            // CASP, CASPA, CASPL, CASPAL: register pairs
            if rt2 != 31 || rs & 1 != 0 || rt & 1 != 0 {
                return unknown(w);
            }
            let pr = if size != 0 { RegKind::X } else { RegKind::W };
            return Insn::new(
                sfmt!(Mn, "casp{}", order(l, o0)),
                &[reg(pr.name(rs)), reg(pr.name(rs + 1)), reg(pr.name(rt)), reg(pr.name(rt + 1)), m0],
                f::LOAD | f::STORE | f::ATOMIC,
            )
            .size(if size != 0 { 8 } else { 4 });
        }
        let pr = if size == 3 { RegKind::X } else { RegKind::W };
        if l != 0 {
            return mk(if o0 != 0 { "ldaxp" } else { "ldxp" }, &[reg(pr.name(rt)), reg(pr.name(rt2)), m0], f::LOAD | f::ATOMIC).size(bytes);
        }
        return mk(if o0 != 0 { "stlxp" } else { "stxp" }, &[reg(wr(rs)), reg(pr.name(rt)), reg(pr.name(rt2)), m0], f::STORE | f::ATOMIC).size(bytes);
    }
    if o2 == 0 {
        if l != 0 {
            return Insn::new(sfmt!(Mn, "ld{}xr{}", if o0 != 0 { "a" } else { "" }, sfx), &[reg(r.name(rt)), m0], f::LOAD | f::ATOMIC).size(bytes);
        }
        return Insn::new(sfmt!(Mn, "st{}xr{}", if o0 != 0 { "l" } else { "" }, sfx), &[reg(wr(rs)), reg(r.name(rt)), m0], f::STORE | f::ATOMIC).size(bytes);
    }
    // o2 = 1, o1 = 0: load-acquire / store-release
    if l != 0 {
        return Insn::new(sfmt!(Mn, "{}{}", if o0 != 0 { "ldar" } else { "ldlar" }, sfx), &[reg(r.name(rt)), m0], f::LOAD).size(bytes);
    }
    Insn::new(sfmt!(Mn, "{}{}", if o0 != 0 { "stlr" } else { "stllr" }, sfx), &[reg(r.name(rt)), m0], f::STORE).size(bytes)
}

const ATOMIC_OPS: [&str; 8] = ["add", "clr", "eor", "set", "smax", "smin", "umax", "umin"];
const FP_ATOMIC_OPS: [&str; 8] = ["add", "", "", "", "max", "min", "maxnm", "minnm"];

fn atomic(w: u32) -> Insn {
    let size = bits(w, 31, 30);
    let v = bit(w, 26);
    let a = bit(w, 23);
    let r = bit(w, 22);
    let rs = bits(w, 20, 16);
    let o3 = bit(w, 15);
    let opc = bits(w, 14, 12);
    let rn = bits(w, 9, 5);
    let rt = bits(w, 4, 0);
    let m0 = mem(base(rn), 0, Mode::Off);
    let ord = order(a, r);
    if v != 0 {
        // LDFADD & co (FEAT_LSFE): floating-point atomics on H, S or D; size 0 is BFloat16 (ldbf…).
        // The STF… forms, which return nothing, have encodings of their own.
        let op = FP_ATOMIC_OPS[opc as usize];
        if op.is_empty() {
            return unknown(w);
        }
        let prefix = if size != 0 { "f" } else { "bf" };
        let fr = RegKind::Fp(b"hhsd"[size as usize]);
        let bytes = if size != 0 { 1 << size } else { 2 };
        if o3 != 0 {
            return if rt == 31 && a == 0 {
                Insn::new(sfmt!(Mn, "st{}{}{}", prefix, op, if r != 0 { "l" } else { "" }), &[reg(fr.name(rs)), m0], f::LOAD | f::STORE | f::ATOMIC).size(bytes)
            } else {
                unknown(w)
            };
        }
        return Insn::new(sfmt!(Mn, "ld{}{}{}", prefix, op, ord), &[reg(fr.name(rs)), reg(fr.name(rt)), m0], f::LOAD | f::STORE | f::ATOMIC).size(bytes);
    }
    if o3 != 0 && (1..=3).contains(&opc) && size < 2 {
        // RCWCLR, RCWSWP, RCWSET (FEAT_THE): read-check-write on a translation table entry; RCWS… with size 1.
        let m = sfmt!(Mn, "rcw{}{}{}", if size != 0 { "s" } else { "" }, ["", "clr", "swp", "set"][opc as usize], ord);
        return Insn::new(m, &[reg(xr(rs)), reg(xr(rt)), m0], f::LOAD | f::STORE | f::ATOMIC).size(8);
    }
    if o3 != 0 && size == 3 && a == 0 && r == 0 && rt & 1 == 0 && rt < 24 && (opc == 1 || opc == 2 || opc == 3 || opc == 5) {
        // ST64B, ST64BV, ST64BV0, LD64B (FEAT_LS64): 64 bytes in one access, through Xt…Xt+7.
        if opc == 1 || opc == 5 {
            return if rs == 31 { mk(if opc == 1 { "st64b" } else { "ld64b" }, &[reg(xr(rt)), m0], if opc == 1 { f::STORE } else { f::LOAD }).size(64) } else { unknown(w) };
        }
        return mk(if opc == 2 { "st64bv0" } else { "st64bv" }, &[reg(xr(rs)), reg(xr(rt)), m0], f::LOAD | f::STORE).size(64);
    }
    let sfx = ["b", "h", "", ""][size as usize];
    let g = if size == 3 { RegKind::X } else { RegKind::W };
    let bytes = 1 << size;
    if o3 == 0 {
        let op = ATOMIC_OPS[opc as usize];
        if rt == 31 && a == 0 {
            return Insn::new(sfmt!(Mn, "st{}{}{}", op, if r != 0 { "l" } else { "" }, sfx), &[reg(g.name(rs)), m0], f::LOAD | f::STORE | f::ATOMIC).size(bytes);
        }
        return Insn::new(sfmt!(Mn, "ld{}{}{}", op, ord, sfx), &[reg(g.name(rs)), reg(g.name(rt)), m0], f::LOAD | f::STORE | f::ATOMIC).size(bytes);
    }
    if opc == 0 {
        return Insn::new(sfmt!(Mn, "swp{}{}", ord, sfx), &[reg(g.name(rs)), reg(g.name(rt)), m0], f::LOAD | f::STORE | f::ATOMIC).size(bytes);
    }
    if opc == 4 && a != 0 && r == 0 && rs == 31 {
        return Insn::new(sfmt!(Mn, "ldapr{}", sfx), &[reg(g.name(rt)), m0], f::LOAD).size(bytes);
    }
    unknown(w)
}

/// LDAPUR / STLUR: load-acquire (RCpc) and store-release with an unscaled offset.
fn rcpc_unscaled(w: u32) -> Insn {
    let size = bits(w, 31, 30);
    let opc = bits(w, 23, 22);
    let rn = bits(w, 9, 5);
    let rt = bits(w, 4, 0);
    let off = sext(bits(w, 20, 12), 9);
    let sfx = ["b", "h", "", ""][size as usize];
    let m0 = mem(base(rn), off, Mode::Off);
    if bit(w, 26) != 0 {
        // SIMD&FP registers (FEAT_LRCPC3): B, H, S, D, or Q when size is 0 and opc<1> is set.
        let Some(a) = access(size, 1, opc) else { return unknown(w) };
        return mk(if a.load { "ldapur" } else { "stlur" }, &[reg(a.rt.name(rt)), m0], if a.load { f::LOAD } else { f::STORE }).size(a.bytes);
    }
    let g = if size == 3 { RegKind::X } else { RegKind::W };
    if opc == 0 {
        return Insn::new(sfmt!(Mn, "stlur{}", sfx), &[reg(g.name(rt)), m0], f::STORE).size(1 << size);
    }
    if opc == 1 {
        return Insn::new(sfmt!(Mn, "ldapur{}", sfx), &[reg(g.name(rt)), m0], f::LOAD).size(1 << size);
    }
    if size == 3 || (size == 2 && opc == 3) {
        return unknown(w);
    }
    let ext = if size == 2 {
        "w"
    } else if size == 1 {
        "h"
    } else {
        "b"
    };
    Insn::new(sfmt!(Mn, "ldapurs{}", ext), &[reg(if opc == 2 { xr(rt) } else { wr(rt) }), m0], f::LOAD).size(1 << size).signed(true)
}

fn literal(w: u32, pc: i64) -> Insn {
    let opc = bits(w, 31, 30);
    let v = bit(w, 26);
    let rt = bits(w, 4, 0);
    let target = pc + sext(bits(w, 23, 5), 19) * 4;
    let lbl = label(target);
    if v != 0 {
        if opc == 3 {
            return unknown(w);
        }
        return mk("ldr", &[reg(fp_reg(b"sdq"[opc as usize], rt)), lbl], f::LOAD).target(target).size(4 << opc);
    }
    if opc == 3 {
        return mk("prfm", &[prfop(rt), lbl], 0).target(target);
    }
    if opc == 2 {
        return mk("ldrsw", &[reg(xr(rt)), lbl], f::LOAD).target(target).size(4).signed(true);
    }
    mk("ldr", &[reg(if opc != 0 { xr(rt) } else { wr(rt) }), lbl], f::LOAD).target(target).size(if opc != 0 { 8 } else { 4 })
}

const MOPS_OPTIONS: [&str; 16] = ["", "wt", "rt", "t", "wn", "wtwn", "rtwn", "twn", "rn", "wtrn", "rtrn", "trn", "n", "wtn", "rtn", "tn"];

/// The memory copy and set instructions (FEAT_MOPS): each operation is three
/// instructions — prologue, main, epilogue — that update their registers as
/// they go, hence the writeback marks. The suffix says which accesses are
/// unprivileged (t, wt, rt) and which non-temporal (n, wn, rn).
fn mops(w: u32) -> Insn {
    let o0 = bit(w, 26);
    let op1 = bits(w, 23, 22);
    let rs = bits(w, 20, 16);
    let op2 = bits(w, 15, 12);
    let rn = bits(w, 9, 5);
    let rd = bits(w, 4, 0);
    // The three registers must differ; the count may be xzr, and so may the value of a set.
    if rd == rn || rd == rs || rn == rs || rd == 31 {
        return unknown(w);
    }
    let pme = ["p", "m", "e"];
    if op1 == 3 {
        let stage = op2 >> 2;
        if stage == 3 {
            return unknown(w);
        }
        let m = sfmt!(Mn, "set{}{}{}", if o0 != 0 { "g" } else { "" }, pme[stage as usize], ["", "t", "n", "tn"][(op2 & 3) as usize]);
        return Insn::new(m, &[Op::Text(sfmt!(Text, "[{}]!", xr(rd))), Op::Text(sfmt!(Text, "{}!", xr(rn))), reg(xr(rs))], f::STORE);
    }
    if rs == 31 {
        return unknown(w);
    }
    let m = sfmt!(Mn, "cpy{}{}{}", if o0 != 0 { "" } else { "f" }, pme[op1 as usize], MOPS_OPTIONS[op2 as usize]);
    Insn::new(m, &[Op::Text(sfmt!(Text, "[{}]!", xr(rd))), Op::Text(sfmt!(Text, "[{}]!", xr(rs))), Op::Text(sfmt!(Text, "{}!", xr(rn)))], f::LOAD | f::STORE)
}

/// LDIAPP / STILP and the writeback forms of LDAPR / STLR (FEAT_LRCPC3):
/// load-acquire and store-release of one or two registers, the pair ordered
/// as a unit.
fn rcpc_pair(w: u32) -> Insn {
    let size = bits(w, 31, 30);
    let opc = bits(w, 23, 22);
    let rt2 = bits(w, 20, 16);
    let opc2 = bits(w, 15, 12);
    let rn = bits(w, 9, 5);
    let rt = bits(w, 4, 0);
    if size < 2 || opc2 > 1 {
        return unknown(w);
    }
    let r = if size == 3 { RegKind::X } else { RegKind::W };
    let bytes: i64 = 1 << size;
    let load = opc & 1 != 0;
    let flags = if load { f::LOAD } else { f::STORE };
    let writeback = opc2 == 0;
    let stepped = |amount: i64| {
        let mut m = Mem::new(base(rn), if load { amount } else { -amount }, if load { Mode::Post } else { Mode::Pre });
        m.decimal = true;
        Op::Mem(m)
    };
    if opc < 2 {
        // Loads step the base up after, stores step it down before: a stack's pop and push.
        let m0 = if writeback { stepped(2 * bytes) } else { mem(base(rn), 0, Mode::Off) };
        return mk(if load { "ldiapp" } else { "stilp" }, &[reg(r.name(rt)), reg(r.name(rt2)), m0], flags).size(bytes as u32);
    }
    if !writeback || rt2 != 0 {
        return unknown(w);
    }
    mk(if load { "ldapr" } else { "stlr" }, &[reg(r.name(rt)), stepped(bytes)], flags).size(bytes as u32)
}

/// The memory-tagging loads and stores (FEAT_MTE): STG and friends set the
/// allocation tag of one or two 16-byte granules (STZG… zero them as well),
/// LDG reads one; the …GM forms move a whole block of tags through Xt.
fn memory_tag(w: u32) -> Insn {
    let opc = bits(w, 23, 22);
    let imm9 = sext(bits(w, 20, 12), 9);
    let op2 = bits(w, 11, 10);
    let rn = bits(w, 9, 5);
    let rt = bits(w, 4, 0);
    if op2 == 0 {
        if opc == 1 {
            return mk("ldg", &[reg(xr(rt)), mem(base(rn), imm9 * 16, Mode::Off)], f::LOAD);
        }
        if imm9 != 0 {
            return unknown(w);
        }
        let m = ["stzgm", "", "stgm", "ldgm"][opc as usize];
        return mk(m, &[reg(xr(rt)), mem(base(rn), 0, Mode::Off)], if opc == 3 { f::LOAD } else { f::STORE });
    }
    let mode = [Mode::Off, Mode::Post, Mode::Off, Mode::Pre][op2 as usize];
    mk(["stg", "stzg", "st2g", "stz2g"][opc as usize], &[reg(xs(rt)), mem(base(rn), imm9 * 16, mode)], f::STORE)
}

/// Size 0 or 1 with bit 21 set: the 128-bit atomics (FEAT_LSE128), the
/// read-check-write instructions on 128-bit translation table entries
/// (FEAT_THE) and the unprivileged atomics (FEAT_LSUI).
fn atomic_extra(w: u32) -> Insn {
    let size = bits(w, 31, 30);
    let a = bit(w, 23);
    let r = bit(w, 22);
    let rs = bits(w, 20, 16);
    let o3 = bit(w, 15);
    let opc = bits(w, 14, 12);
    let kind = bits(w, 11, 10);
    let rn = bits(w, 9, 5);
    let rt = bits(w, 4, 0);
    let m0 = mem(base(rn), 0, Mode::Off);
    let ord = order(a, r);
    let rw = f::LOAD | f::STORE | f::ATOMIC;
    if kind == 0 {
        // Xt and Xt2 hold the 128-bit operand and receive the old value.
        let op = if o3 != 0 { ["swpp", "rcwclrp", "rcwswpp", "rcwsetp"] } else { ["", "ldclrp", "", "ldsetp"] }.get(opc as usize).copied().unwrap_or("");
        if op.is_empty() || (size != 0 && !op.starts_with("rcw")) || rt == 31 || rs == 31 {
            return unknown(w);
        }
        let mut m = Mn::new();
        if size != 0 {
            m.push("rcws");
            m.push(&op[3..]);
        } else {
            m.push(op);
        }
        m.push(ord);
        return Insn::new(m, &[reg(xr(rt)), reg(xr(rs)), m0], rw).size(16);
    }
    if kind == 1 {
        let g = if size != 0 { RegKind::X } else { RegKind::W };
        let bytes = if size != 0 { 8 } else { 4 };
        if o3 != 0 {
            return if opc == 0 { Insn::new(sfmt!(Mn, "swpt{}", ord), &[reg(g.name(rs)), reg(g.name(rt)), m0], rw).size(bytes) } else { unknown(w) };
        }
        let op = ["add", "clr", "", "set"].get(opc as usize).copied().unwrap_or("");
        if op.is_empty() {
            return unknown(w);
        }
        return Insn::new(sfmt!(Mn, "ldt{}{}", op, ord), &[reg(g.name(rs)), reg(g.name(rt)), m0], rw).size(bytes);
    }
    // RCWCAS / RCWCASP: compare-and-swap of a 64-bit or 128-bit table entry.
    if o3 != 0 || opc != 0 {
        return unknown(w);
    }
    let s = if size != 0 { "s" } else { "" };
    if kind == 2 {
        return Insn::new(sfmt!(Mn, "rcw{}cas{}", s, ord), &[reg(xr(rs)), reg(xr(rt)), m0], rw).size(8);
    }
    if rs & 1 != 0 || rt & 1 != 0 {
        return unknown(w);
    }
    Insn::new(sfmt!(Mn, "rcw{}casp{}", s, ord), &[reg(xr(rs)), reg(xr_next(rs)), reg(xr(rt)), reg(xr_next(rt)), m0], rw).size(16)
}

/// Bits 29:28 = 01 with bit 24 set, an encoding space the later extensions
/// filled: RCpc unscaled and writeback forms, memory copy and set, memory
/// tagging, GCS stores, and the 128-bit and unprivileged atomics.
fn load_store_extra(w: u32) -> Insn {
    let size = bits(w, 31, 30);
    let v = bit(w, 26);
    let kind = bits(w, 11, 10);
    if bit(w, 21) == 0 {
        // The SIMD&FP forms of LDAPUR / STLUR sit where the general-register pair forms do.
        if kind == 0 {
            return if v != 0 { unknown(w) } else { rcpc_unscaled(w) };
        }
        if kind == 1 {
            return if size == 0 { mops(w) } else { unknown(w) };
        }
        if kind == 2 {
            return if v != 0 { rcpc_unscaled(w) } else { rcpc_pair(w) };
        }
        if v != 0 {
            return unknown(w);
        }
        // GCSSTR / GCSSTTR: a store to the Guarded Control Stack, the second unprivileged.
        if size == 3 && bits(w, 23, 13) == 0x0f8 {
            let m = if bit(w, 12) != 0 { "gcssttr" } else { "gcsstr" };
            return mk(m, &[reg(xr(bits(w, 4, 0))), mem(base(bits(w, 9, 5)), 0, Mode::Off)], f::STORE).size(8);
        }
        return unknown(w);
    }
    if v != 0 {
        return unknown(w);
    }
    if size == 3 {
        return memory_tag(w);
    }
    if size < 2 {
        return atomic_extra(w);
    }
    unknown(w)
}

/// LDRAA / LDRAB: a load through a pointer authenticated on the way.
fn ldra(w: u32) -> Insn {
    if bits(w, 31, 30) != 3 || bit(w, 26) != 0 {
        return unknown(w);
    }
    let m = if bit(w, 23) != 0 { "ldrab" } else { "ldraa" };
    let off = sext((bit(w, 22) << 9) | bits(w, 20, 12), 10) * 8;
    let pre = bit(w, 11);
    mk(m, &[reg(xr(bits(w, 4, 0))), mem(base(bits(w, 9, 5)), off, if pre != 0 { Mode::Pre } else { Mode::Off })], f::LOAD).size(8)
}

fn load_store(w: u32, pc: i64) -> Insn {
    let op0 = bits(w, 31, 28);
    let v = bit(w, 26);
    let op2 = bits(w, 24, 23);
    let b29 = bits(w, 29, 28);
    if b29 == 0 {
        if v != 0 {
            if op0 & 0xb != 0 {
                return unknown(w);
            }
            return decode_simd_structure(w);
        }
        if bits(w, 27, 25) != 4 {
            return unknown(w);
        }
        return if bit(w, 24) != 0 { exclusive_unprivileged(w) } else { exclusive(w) };
    }
    if b29 == 1 {
        if bit(w, 24) == 0 {
            return literal(w, pc);
        }
        return load_store_extra(w);
    }
    if b29 == 2 {
        return pair(w, [PairForm::NoAlloc, PairForm::Post, PairForm::Off, PairForm::Pre][op2 as usize]);
    }
    if bit(w, 24) != 0 {
        return single(w, Form::Uimm);
    }
    if bit(w, 21) == 0 {
        return single(w, [Form::Unscaled, Form::Post, Form::Unpriv, Form::Pre][bits(w, 11, 10) as usize]);
    }
    match bits(w, 11, 10) {
        0 => atomic(w),
        2 => single(w, Form::RegOff),
        _ => ldra(w),
    }
}

/* ------------------------------------------------------------------ *
 * Data processing — register
 * ------------------------------------------------------------------ */

const SHIFTS: [&str; 4] = ["lsl", "lsr", "asr", "ror"];
const EXTENDS: [&str; 8] = ["uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw", "sxtx"];

fn logical_shifted(w: u32) -> Insn {
    let sf = bit(w, 31);
    let opc = bits(w, 30, 29);
    let sh = bits(w, 23, 22);
    let n = bit(w, 21);
    let rm = bits(w, 20, 16);
    let amount = bits(w, 15, 10);
    let rn = bits(w, 9, 5);
    let rd = bits(w, 4, 0);
    if sf == 0 && amount > 31 {
        return unknown(w);
    }
    let names = if n != 0 { ["bic", "orn", "eon", "bics"] } else { ["and", "orr", "eor", "ands"] };
    let s_op = if amount != 0 || sh != 0 { Some(shift(SHIFTS[sh as usize], amount as i64)) } else { None };
    let flags = if opc == 3 { f::SETS_FLAGS } else { 0 };
    let with = |m: &str, ops: &[Op], flags: u32| {
        let mut all = Ops::from_slice(ops);
        if let Some(s) = s_op {
            all.push(s);
        }
        Insn::new(Mn::from(m), &all, flags)
    };
    if opc == 1 && rn == 31 {
        if n == 0 && sh == 0 && amount == 0 {
            return mk("mov", &[reg(gr(sf, rd)), reg(gr(sf, rm))], 0);
        }
        if n != 0 {
            return with("mvn", &[reg(gr(sf, rd)), reg(gr(sf, rm))], 0);
        }
    }
    if opc == 3 && rd == 31 && n == 0 {
        return with("tst", &[reg(gr(sf, rn)), reg(gr(sf, rm))], flags);
    }
    with(names[opc as usize], &[reg(gr(sf, rd)), reg(gr(sf, rn)), reg(gr(sf, rm))], flags)
}

fn add_sub_shifted(w: u32) -> Insn {
    let sf = bit(w, 31);
    let op = bit(w, 30);
    let s = bit(w, 29);
    let sh = bits(w, 23, 22);
    let rm = bits(w, 20, 16);
    let amount = bits(w, 15, 10);
    let rn = bits(w, 9, 5);
    let rd = bits(w, 4, 0);
    if sh == 3 || (sf == 0 && amount > 31) {
        return unknown(w);
    }
    let s_op = if amount != 0 || sh != 0 { Some(shift(SHIFTS[sh as usize], amount as i64)) } else { None };
    let flags = if s != 0 { f::SETS_FLAGS } else { 0 };
    let with = |m: &str, ops: &[Op]| {
        let mut all = Ops::from_slice(ops);
        if let Some(sop) = s_op {
            all.push(sop);
        }
        Insn::new(Mn::from(m), &all, flags)
    };
    if s != 0 && rd == 31 {
        return with(if op != 0 { "cmp" } else { "cmn" }, &[reg(gr(sf, rn)), reg(gr(sf, rm))]);
    }
    if op != 0 && rn == 31 {
        return with(if s != 0 { "negs" } else { "neg" }, &[reg(gr(sf, rd)), reg(gr(sf, rm))]);
    }
    let m = match (op, s) {
        (0, 0) => "add",
        (0, _) => "adds",
        (_, 0) => "sub",
        _ => "subs",
    };
    with(m, &[reg(gr(sf, rd)), reg(gr(sf, rn)), reg(gr(sf, rm))])
}

fn add_sub_extended(w: u32) -> Insn {
    let sf = bit(w, 31);
    let op = bit(w, 30);
    let s = bit(w, 29);
    let opt = bits(w, 23, 22);
    let rm = bits(w, 20, 16);
    let option = bits(w, 15, 13);
    let amount = bits(w, 12, 10);
    let rn = bits(w, 9, 5);
    let rd = bits(w, 4, 0);
    if opt != 0 || amount > 4 {
        return unknown(w);
    }
    let flags = if s != 0 { f::SETS_FLAGS } else { 0 };
    let m = if sf != 0 && option & 3 == 3 { xr(rm) } else { wr(rm) };
    // With SP as the destination or first source, the "natural" extend (uxtw / uxtx) is printed as lsl.
    let natural = if sf != 0 { option == 3 } else { option == 2 };
    let uses_sp = (if s != 0 { false } else { rd == 31 }) || rn == 31;
    let ext: Option<Op> = if natural && uses_sp {
        if amount != 0 {
            Some(shift("lsl", amount as i64))
        } else {
            None
        }
    } else if amount != 0 {
        Some(shift(EXTENDS[option as usize], amount as i64))
    } else {
        Some(text(EXTENDS[option as usize]))
    };
    let with = |mn: &str, ops: &[Op]| {
        let mut all = Ops::from_slice(ops);
        if let Some(e) = ext {
            all.push(e);
        }
        Insn::new(Mn::from(mn), &all, flags)
    };
    if s != 0 && rd == 31 {
        return with(if op != 0 { "cmp" } else { "cmn" }, &[reg(gs(sf, rn)), reg(m)]);
    }
    let mn = match (op, s) {
        (0, 0) => "add",
        (0, _) => "adds",
        (_, 0) => "sub",
        _ => "subs",
    };
    with(mn, &[reg(if s != 0 { gr(sf, rd) } else { gs(sf, rd) }), reg(gs(sf, rn)), reg(m)])
}

fn cond_select(w: u32) -> Insn {
    let sf = bit(w, 31);
    let op = bit(w, 30);
    let s = bit(w, 29);
    let rm = bits(w, 20, 16);
    let c = bits(w, 15, 12);
    let o2 = bits(w, 11, 10);
    let rn = bits(w, 9, 5);
    let rd = bits(w, 4, 0);
    if s != 0 || o2 > 1 {
        return unknown(w);
    }
    let d = reg(gr(sf, rd));
    let fl = f::READS_FLAGS;
    let usable = c & 14 != 14;
    let plain = |m: &str| mk(m, &[d, reg(gr(sf, rn)), reg(gr(sf, rm)), text(cond(c))], fl).cond(cond(c));
    if op == 0 && o2 == 0 {
        return plain("csel");
    }
    if op == 0 && o2 == 1 {
        if rm == 31 && rn == 31 && usable {
            return mk("cset", &[d, text(invert(c))], fl).cond(invert(c));
        }
        if rm == rn && rn != 31 && usable {
            return mk("cinc", &[d, reg(gr(sf, rn)), text(invert(c))], fl).cond(invert(c));
        }
        return plain("csinc");
    }
    if op != 0 && o2 == 0 {
        if rm == 31 && rn == 31 && usable {
            return mk("csetm", &[d, text(invert(c))], fl).cond(invert(c));
        }
        if rm == rn && rn != 31 && usable {
            return mk("cinv", &[d, reg(gr(sf, rn)), text(invert(c))], fl).cond(invert(c));
        }
        return plain("csinv");
    }
    if rm == rn && usable {
        return mk("cneg", &[d, reg(gr(sf, rn)), text(invert(c))], fl).cond(invert(c));
    }
    plain("csneg")
}

fn cond_compare(w: u32) -> Insn {
    let sf = bit(w, 31);
    let op = bit(w, 30);
    if bit(w, 29) == 0 || bit(w, 10) != 0 || bit(w, 4) != 0 {
        return unknown(w);
    }
    let c = cond(bits(w, 15, 12));
    let second = if bit(w, 11) != 0 { imm(bits(w, 20, 16) as i64) } else { reg(gr(sf, bits(w, 20, 16))) };
    mk(if op != 0 { "ccmp" } else { "ccmn" }, &[reg(gr(sf, bits(w, 9, 5))), second, imm(bits(w, 3, 0) as i64), text(c)], f::SETS_FLAGS | f::READS_FLAGS).cond(c)
}

fn dp2(w: u32) -> Insn {
    let sf = bit(w, 31);
    let s = bit(w, 29);
    let rm = bits(w, 20, 16);
    let opcode = bits(w, 15, 10);
    let rn = bits(w, 9, 5);
    let rd = bits(w, 4, 0);
    let three = |m: &str| mk(m, &[reg(gr(sf, rd)), reg(gr(sf, rn)), reg(gr(sf, rm))], 0);
    if s != 0 {
        if sf != 0 && opcode == 0 {
            return mk("subps", &[reg(xr(rd)), reg(xs(rn)), reg(xs(rm))], f::SETS_FLAGS);
        }
        return unknown(w);
    }
    match opcode {
        0 => return if sf != 0 { mk("subp", &[reg(xr(rd)), reg(xs(rn)), reg(xs(rm))], 0) } else { unknown(w) },
        2 => return three("udiv"),
        3 => return three("sdiv"),
        4 => {
            if sf == 0 {
                return unknown(w);
            }
            return if rm == 31 { mk("irg", &[reg(xs(rd)), reg(xs(rn))], 0) } else { mk("irg", &[reg(xs(rd)), reg(xs(rn)), reg(xr(rm))], 0) };
        }
        5 => return if sf != 0 { mk("gmi", &[reg(xr(rd)), reg(xs(rn)), reg(xr(rm))], 0) } else { unknown(w) },
        8 => return three("lsl"),
        9 => return three("lsr"),
        10 => return three("asr"),
        11 => return three("ror"),
        12 => return if sf != 0 { mk("pacga", &[reg(xr(rd)), reg(xr(rn)), reg(xs(rm))], 0) } else { unknown(w) },
        24 => return three("smax"),
        25 => return three("umax"),
        26 => return three("smin"),
        27 => return three("umin"),
        _ => {}
    }
    if (16..=23).contains(&opcode) {
        let sz = opcode & 3;
        let c = if opcode & 4 != 0 { "c" } else { "" };
        if (sz == 3) != (sf != 0) {
            return unknown(w);
        }
        return Insn::new(sfmt!(Mn, "crc32{}{}", c, ["b", "h", "w", "x"][sz as usize]), &[reg(wr(rd)), reg(wr(rn)), reg(if sz == 3 { xr(rm) } else { wr(rm) })], 0);
    }
    unknown(w)
}

const PAC1: [&str; 8] = ["pacia", "pacib", "pacda", "pacdb", "autia", "autib", "autda", "autdb"];

fn pac_lr(opcode: u32) -> Option<&'static str> {
    Some(match opcode {
        32 => "pacnbiasppc",
        33 => "pacnbibsppc",
        34 => "pacia171615",
        35 => "pacib171615",
        40 => "paciasppc",
        41 => "pacibsppc",
        46 => "autia171615",
        47 => "autib171615",
        _ => return None,
    })
}

fn dp1(w: u32) -> Insn {
    let sf = bit(w, 31);
    let opcode2 = bits(w, 20, 16);
    let opcode = bits(w, 15, 10);
    let rn = bits(w, 9, 5);
    let rd = bits(w, 4, 0);
    if bit(w, 29) != 0 {
        return unknown(w);
    }
    let two = |m: &str| mk(m, &[reg(gr(sf, rd)), reg(gr(sf, rn))], 0);
    if opcode2 == 0 {
        return match opcode {
            0 => two("rbit"),
            1 => two("rev16"),
            2 => {
                if sf != 0 {
                    two("rev32")
                } else {
                    two("rev")
                }
            }
            3 => {
                if sf != 0 {
                    two("rev")
                } else {
                    unknown(w)
                }
            }
            4 => two("clz"),
            5 => two("cls"),
            6 => two("ctz"),
            7 => two("cnt"),
            8 => two("abs"),
            _ => unknown(w),
        };
    }
    if opcode2 == 1 && sf != 0 {
        if opcode < 8 {
            return mk(PAC1[opcode as usize], &[reg(xr(rd)), reg(xs(rn))], 0);
        }
        if opcode < 16 && rn == 31 {
            let name = PAC1[(opcode - 8) as usize];
            return Insn::new(sfmt!(Mn, "{}z{}", &name[..4], &name[4..]), &[reg(xr(rd))], 0);
        }
        if opcode == 16 && rn == 31 {
            return mk("xpaci", &[reg(xr(rd))], 0);
        }
        if opcode == 17 && rn == 31 {
            return mk("xpacd", &[reg(xr(rd))], 0);
        }
        // FEAT_PAuth_LR: signing and authenticating with the address of the signing instruction as well.
        if rd == 30 && (opcode == 36 || opcode == 37) {
            return mk(if opcode & 1 != 0 { "autibsppcr" } else { "autiasppcr" }, &[reg(xr(rn))], 0);
        }
        if let Some(lr) = pac_lr(opcode) {
            if rn == 31 && rd == 30 {
                return mk(lr, &[], 0);
            }
        }
    }
    unknown(w)
}

fn dp3(w: u32) -> Insn {
    let sf = bit(w, 31);
    let op54 = bits(w, 30, 29);
    let op31 = bits(w, 23, 21);
    let o0 = bit(w, 15);
    let rm = bits(w, 20, 16);
    let ra = bits(w, 14, 10);
    let rn = bits(w, 9, 5);
    let rd = bits(w, 4, 0);
    if op54 != 0 {
        return unknown(w);
    }
    if op31 == 0 {
        let ops = [reg(gr(sf, rd)), reg(gr(sf, rn)), reg(gr(sf, rm))];
        if ra == 31 {
            return mk(if o0 != 0 { "mneg" } else { "mul" }, &ops, 0);
        }
        return mk(if o0 != 0 { "msub" } else { "madd" }, &[ops[0], ops[1], ops[2], reg(gr(sf, ra))], 0);
    }
    if sf == 0 {
        return unknown(w);
    }
    if op31 == 2 || op31 == 6 {
        if o0 != 0 {
            return unknown(w);
        }
        return mk(if op31 == 2 { "smulh" } else { "umulh" }, &[reg(xr(rd)), reg(xr(rn)), reg(xr(rm))], 0);
    }
    if op31 == 3 {
        // MADDPT / MSUBPT (FEAT_CPA): multiply-add on pointers, checked against the pointer's top bits.
        return mk(if o0 != 0 { "msubpt" } else { "maddpt" }, &[reg(xr(rd)), reg(xr(rn)), reg(xr(rm)), reg(xr(ra))], 0);
    }
    if op31 == 1 || op31 == 5 {
        let u = if op31 == 5 { "u" } else { "s" };
        let ops = [reg(xr(rd)), reg(wr(rn)), reg(wr(rm))];
        if ra == 31 {
            return Insn::new(sfmt!(Mn, "{}{}", u, if o0 != 0 { "mnegl" } else { "mull" }), &ops, 0);
        }
        return Insn::new(sfmt!(Mn, "{}{}", u, if o0 != 0 { "msubl" } else { "maddl" }), &[ops[0], ops[1], ops[2], reg(xr(ra))], 0);
    }
    unknown(w)
}

fn dp_reg(w: u32) -> Insn {
    let op0 = bit(w, 30);
    let op1 = bit(w, 28);
    let op2 = bits(w, 24, 21);
    let op3 = bits(w, 15, 10);
    if op1 == 0 {
        if op2 & 8 == 0 {
            return logical_shifted(w);
        }
        return if op2 & 1 != 0 { add_sub_extended(w) } else { add_sub_shifted(w) };
    }
    if op2 & 8 != 0 {
        return dp3(w);
    }
    match op2 {
        0 => {
            let sf = bit(w, 31);
            let op = bit(w, 30);
            let s = bit(w, 29);
            let rm = bits(w, 20, 16);
            let rn = bits(w, 9, 5);
            let rd = bits(w, 4, 0);
            if op3 & 0x38 == 8 {
                // ADDPT / SUBPT (FEAT_CPA): pointer arithmetic, with an optional left shift of Xm.
                if sf == 0 || s != 0 {
                    return unknown(w);
                }
                let amount = op3 & 7;
                let mut ops = Ops::from_slice(&[reg(xs(rd)), reg(xs(rn)), reg(xr(rm))]);
                if amount != 0 {
                    ops.push(shift("lsl", amount as i64));
                }
                return Insn::new(Mn::from(if op != 0 { "subpt" } else { "addpt" }), &ops, 0);
            }
            if op3 & 0x1f == 1 {
                // RMIF (FEAT_FlagM): rotate Xn right and insert its low bits into the flags the mask picks.
                if sf == 0 || op != 0 || s == 0 || bit(w, 4) != 0 {
                    return unknown(w);
                }
                return mk("rmif", &[reg(xr(rn)), imm(bits(w, 20, 15) as i64), imm(bits(w, 3, 0) as i64)], f::SETS_FLAGS | f::READS_FLAGS);
            }
            if op3 & 0xf == 2 {
                // SETF8 / SETF16 (FEAT_FlagM): N and Z from the low byte or halfword, V from the bit above it.
                if sf != 0 || op != 0 || s == 0 || bits(w, 20, 15) != 0 || rd != 13 {
                    return unknown(w);
                }
                return mk(if bit(w, 14) != 0 { "setf16" } else { "setf8" }, &[reg(wr(rn))], f::SETS_FLAGS | f::READS_FLAGS);
            }
            if op3 != 0 {
                return unknown(w);
            }
            let flags = f::READS_FLAGS | if s != 0 { f::SETS_FLAGS } else { 0 };
            if op != 0 && rn == 31 {
                return mk(if s != 0 { "ngcs" } else { "ngc" }, &[reg(gr(sf, rd)), reg(gr(sf, rm))], flags);
            }
            let m = match (op, s) {
                (0, 0) => "adc",
                (0, _) => "adcs",
                (_, 0) => "sbc",
                _ => "sbcs",
            };
            mk(m, &[reg(gr(sf, rd)), reg(gr(sf, rn)), reg(gr(sf, rm))], flags)
        }
        2 => cond_compare(w),
        4 => cond_select(w),
        6 => {
            if op0 != 0 {
                dp1(w)
            } else {
                dp2(w)
            }
        }
        _ => unknown(w),
    }
}

/* ------------------------------------------------------------------ */

pub fn decode(word: u32, pc: i64) -> Insn {
    let w = word;
    let op1 = bits(w, 28, 25);
    if op1 == 0 {
        if bit(w, 31) == 0 && bits(w, 30, 16) == 0 {
            return mk("udf", &[imm(bits(w, 15, 0) as i64)], f::TRAP);
        }
        return unknown(w);
    }
    if op1 & 0xe == 8 {
        return dp_imm(w, pc);
    }
    if op1 & 0xe == 0xa {
        return branches(w, pc);
    }
    if op1 & 5 == 4 {
        return load_store(w, pc);
    }
    if op1 & 7 == 5 {
        return dp_reg(w);
    }
    if op1 & 7 == 7 {
        return decode_simd(w, pc);
    }
    unknown(w)
}
