//! Advanced SIMD data processing: the A32 space 1111 001U, which T32 encodes
//! as 111U 1111. Bit 23 splits it: three registers of the same length below,
//! everything else above — three registers of different lengths, two
//! registers and a scalar, shifts by an immediate, the modified immediates,
//! vext, the two-register operations, vtbl/vtbx and vdup of a scalar.
//!
//! Q forms name every register by its D number, so an odd one is not an
//! instruction; LLVM prints it as <unknown>, and so do we.

use super::simd_common::*;
use super::types::*;
use crate::text::push_hex_u64;

/// `${u ? 'u' : 's'}${8 << size}`
#[allow(non_snake_case)]
#[inline]
fn SU(u: u32, size: u32) -> Dt {
    dt_num(if u != 0 { "u" } else { "s" }, 8 << size)
}

/* ------------------------------------------------------------------ *
 * Three registers of the same length
 * ------------------------------------------------------------------ */

/// How an entry of the three-register table forms its data type:
///   Su, S, I, P   that prefix and the element size (vhadd.u16, vqdmulh.s32,
///                 vadd.i64, vmul.p8; Su takes s or u from U), sizes in `sizes`
///   N             the element size alone (vtst.8)
///   F             floating point: bit 21 picks one of the two operations in
///                 `alt`, bit 20 f32 or f16
///   L             the logical operations: bits 21-20 pick one of `alt`
///   Sha           SHA-1/SHA-256 (Q registers only): bits 21-20 pick one
#[derive(Clone, Copy, PartialEq, Eq)]
enum K {
    Su,
    S,
    I,
    P,
    N,
    F,
    L,
    Sha,
}

#[derive(Clone, Copy)]
struct Same {
    m: &'static str,
    k: K,
    /// Allowed sizes as a bit mask (bit n for size n).
    sizes: u32,
    alt: [&'static str; 4],
    /// Pairwise integer operations exist for D registers only.
    d_only: bool,
    /// Shifts by a register take the shift from Vn and print Vd, Vm, Vn.
    swap: bool,
    /// Armv8 additions that cannot be conditional, not even in an IT block.
    np: bool,
}

impl Same {
    const fn new(m: &'static str, k: K, sizes: u32) -> Option<Same> {
        Some(Same { m, k, sizes, alt: ["", "", "", ""], d_only: false, swap: false, np: false })
    }
    const fn alt(k: K, alt: [&'static str; 4], np: bool) -> Option<Same> {
        Some(Same { m: "", k, sizes: 0, alt, d_only: false, swap: false, np })
    }
    const fn f(a: &'static str, b: &'static str) -> Option<Same> {
        Same::alt(K::F, [a, b, "", ""], false)
    }
    const fn swap(m: &'static str) -> Option<Same> {
        Some(Same { m, k: K::Su, sizes: S0123, alt: ["", "", "", ""], d_only: false, swap: true, np: false })
    }
    const fn d_only(m: &'static str, k: K) -> Option<Same> {
        Some(Same { m, k, sizes: S012, alt: ["", "", "", ""], d_only: true, swap: false, np: false })
    }
}

const S012: u32 = 0b0111;
const S0123: u32 = 0b1111;
const S12: u32 = 0b0110;

// Indexed by opc (bits 11-8) << 2 | o (bit 4) << 1 | U (bit 24).
const SAME: [Option<Same>; 64] = [
    // 0000
    Same::new("vhadd", K::Su, S012),
    Same::new("vhadd", K::Su, S012),
    Same::new("vqadd", K::Su, S0123),
    Same::new("vqadd", K::Su, S0123),
    // 0001
    Same::new("vrhadd", K::Su, S012),
    Same::new("vrhadd", K::Su, S012),
    Same::alt(K::L, ["vand", "vbic", "vorr", "vorn"], false),
    Same::alt(K::L, ["veor", "vbsl", "vbit", "vbif"], false),
    // 0010
    Same::new("vhsub", K::Su, S012),
    Same::new("vhsub", K::Su, S012),
    Same::new("vqsub", K::Su, S0123),
    Same::new("vqsub", K::Su, S0123),
    // 0011
    Same::new("vcgt", K::Su, S012),
    Same::new("vcgt", K::Su, S012),
    Same::new("vcge", K::Su, S012),
    Same::new("vcge", K::Su, S012),
    // 0100
    Same::swap("vshl"),
    Same::swap("vshl"),
    Same::swap("vqshl"),
    Same::swap("vqshl"),
    // 0101
    Same::swap("vrshl"),
    Same::swap("vrshl"),
    Same::swap("vqrshl"),
    Same::swap("vqrshl"),
    // 0110
    Same::new("vmax", K::Su, S012),
    Same::new("vmax", K::Su, S012),
    Same::new("vmin", K::Su, S012),
    Same::new("vmin", K::Su, S012),
    // 0111
    Same::new("vabd", K::Su, S012),
    Same::new("vabd", K::Su, S012),
    Same::new("vaba", K::Su, S012),
    Same::new("vaba", K::Su, S012),
    // 1000
    Same::new("vadd", K::I, S0123),
    Same::new("vsub", K::I, S0123),
    Same::new("vtst", K::N, S012),
    Same::new("vceq", K::I, S012),
    // 1001
    Same::new("vmla", K::I, S012),
    Same::new("vmls", K::I, S012),
    Same::new("vmul", K::I, S012),
    Same::new("vmul", K::P, 1),
    // 1010
    Same::d_only("vpmax", K::Su),
    Same::d_only("vpmax", K::Su),
    Same::d_only("vpmin", K::Su),
    Same::d_only("vpmin", K::Su),
    // 1011
    Same::new("vqdmulh", K::S, S12),
    Same::new("vqrdmulh", K::S, S12),
    Same::d_only("vpadd", K::I),
    Same::new("vqrdmlah", K::S, S12),
    // 1100
    Same::alt(K::Sha, ["sha1c", "sha1p", "sha1m", "sha1su0"], true),
    Same::alt(K::Sha, ["sha256h", "sha256h2", "sha256su1", ""], true),
    Same::f("vfma", "vfms"),
    Same::new("vqrdmlsh", K::S, S12),
    // 1101
    Same::f("vadd", "vsub"),
    Same::f("vpadd", "vabd"),
    Same::f("vmla", "vmls"),
    Same::f("vmul", ""),
    // 1110
    Same::f("vceq", ""),
    Same::f("vcge", "vcgt"),
    None,
    Same::f("vacge", "vacgt"),
    // 1111
    Same::f("vmax", "vmin"),
    Same::f("vpmax", "vpmin"),
    Same::f("vrecps", "vrsqrts"),
    Same::alt(K::F, ["vmaxnm", "vminnm", "", ""], true),
];

/// Floating-point operations that work pairwise and so exist for D registers only.
#[inline]
fn pairwise_f(name: &str) -> bool {
    matches!(name, "vpadd" | "vpmax" | "vpmin")
}

fn three_same(w: u32, ctx: &Ctx) -> Insn {
    let u = bit(w, 24);
    let Some(e) = SAME[((bits(w, 11, 8) << 2) | (bit(w, 4) << 1) | u) as usize] else {
        return undef(ctx);
    };
    let size = bits(w, 21, 20);
    let q = bit(w, 6);
    let d = vd(w);
    let n = vn(w);
    let m = vm(w);
    if q != 0 && ((d | n | m) & 1) != 0 {
        return undef(ctx);
    }
    let name;
    let dt: Dt;
    match e.k {
        K::L => {
            name = e.alt[size as usize];
            dt = Dt::new();
        }
        K::F => {
            name = e.alt[(size >> 1) as usize];
            if name.is_empty() || (q != 0 && pairwise_f(name)) {
                return undef(ctx);
            }
            dt = Dt::from(if size & 1 != 0 { "f16" } else { "f32" });
        }
        K::Sha => {
            name = e.alt[size as usize];
            if name.is_empty() || q == 0 {
                return undef(ctx);
            }
            dt = Dt::from("32");
        }
        _ => {
            if (e.sizes >> size) & 1 == 0 || (e.d_only && q != 0) {
                return undef(ctx);
            }
            name = e.m;
            let prefix = match e.k {
                K::Su => {
                    if u != 0 {
                        "u"
                    } else {
                        "s"
                    }
                }
                K::N => "",
                K::S => "s",
                K::I => "i",
                _ => "p",
            };
            dt = dt_num(prefix, 8 << size);
        }
    }
    let ops = if e.swap { [V(d, q), V(m, q), V(n, q)] } else { [V(d, q), V(n, q), V(m, q)] };
    mk(ctx, name, &dt, &ops, 0, !e.np)
}

/* ------------------------------------------------------------------ *
 * Three registers of different lengths
 * ------------------------------------------------------------------ */

/// Shapes: L = Qd, Dn, Dm (long); W = Qd, Qn, Dm (wide); N = Dd, Qn, Qm (narrow).
#[derive(Clone, Copy)]
enum Shape {
    L,
    W,
    N,
}

#[derive(Clone, Copy)]
enum DiffDt {
    Su,
    S,
    I,
}

const DIFF: [Option<([&str; 2], Shape, DiffDt)>; 16] = [
    Some((["vaddl", "vaddl"], Shape::L, DiffDt::Su)),
    Some((["vaddw", "vaddw"], Shape::W, DiffDt::Su)),
    Some((["vsubl", "vsubl"], Shape::L, DiffDt::Su)),
    Some((["vsubw", "vsubw"], Shape::W, DiffDt::Su)),
    Some((["vaddhn", "vraddhn"], Shape::N, DiffDt::I)),
    Some((["vabal", "vabal"], Shape::L, DiffDt::Su)),
    Some((["vsubhn", "vrsubhn"], Shape::N, DiffDt::I)),
    Some((["vabdl", "vabdl"], Shape::L, DiffDt::Su)),
    Some((["vmlal", "vmlal"], Shape::L, DiffDt::Su)),
    Some((["vqdmlal", ""], Shape::L, DiffDt::S)),
    Some((["vmlsl", "vmlsl"], Shape::L, DiffDt::Su)),
    Some((["vqdmlsl", ""], Shape::L, DiffDt::S)),
    Some((["vmull", "vmull"], Shape::L, DiffDt::Su)),
    Some((["vqdmull", ""], Shape::L, DiffDt::S)),
    None, // 1110: vmull.p8 / vmull.p64, below
    None,
];

fn three_diff(w: u32, ctx: &Ctx) -> Insn {
    let u = bit(w, 24);
    let opc = bits(w, 11, 8);
    let size = bits(w, 21, 20);
    let d = vd(w);
    let n = vn(w);
    let m = vm(w);
    if opc == 14 {
        if u != 0 || d & 1 != 0 {
            return undef(ctx);
        }
        if size == 0 {
            return mk(ctx, "vmull", "p8", &[Q(d), D(n), D(m)], 0, true);
        }
        if size == 2 {
            return mk(ctx, "vmull", "p64", &[Q(d), D(n), D(m)], 0, false);
        }
        return undef(ctx);
    }
    let Some((names, shape, kind)) = DIFF[opc as usize] else {
        return undef(ctx);
    };
    let name = names[u as usize];
    if name.is_empty() {
        return undef(ctx);
    }
    let dt = match kind {
        DiffDt::Su => SU(u, size),
        DiffDt::S => {
            if size == 0 {
                return undef(ctx);
            }
            dt_num("s", 8 << size)
        }
        DiffDt::I => dt_num("i", 16 << size),
    };
    match shape {
        Shape::L => {
            if d & 1 != 0 {
                return undef(ctx);
            }
            mk(ctx, name, &dt, &[Q(d), D(n), D(m)], 0, true)
        }
        Shape::W => {
            if (d | n) & 1 != 0 {
                return undef(ctx);
            }
            mk(ctx, name, &dt, &[Q(d), Q(n), D(m)], 0, true)
        }
        Shape::N => {
            if (n | m) & 1 != 0 {
                return undef(ctx);
            }
            mk(ctx, name, &dt, &[D(d), Q(n), Q(m)], 0, true)
        }
    }
}

/* ------------------------------------------------------------------ *
 * Two registers and a scalar
 * ------------------------------------------------------------------ */

/// qi, qf and qs keep the vector length (Q in bit 24) with an integer,
/// floating-point or signed type; l widens with U in bit 24; sl widens and is
/// signed only (bit 24 clear).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Sk {
    Qi,
    Qf,
    L,
    Sl,
    Qs,
}

/// By bits 11-8.
const SCALAR: [(&str, Sk); 16] = [
    ("vmla", Sk::Qi),
    ("vmla", Sk::Qf),
    ("vmlal", Sk::L),
    ("vqdmlal", Sk::Sl),
    ("vmls", Sk::Qi),
    ("vmls", Sk::Qf),
    ("vmlsl", Sk::L),
    ("vqdmlsl", Sk::Sl),
    ("vmul", Sk::Qi),
    ("vmul", Sk::Qf),
    ("vmull", Sk::L),
    ("vqdmull", Sk::Sl),
    ("vqdmulh", Sk::Qs),
    ("vqrdmulh", Sk::Qs),
    ("vqrdmlah", Sk::Qs),
    ("vqrdmlsh", Sk::Qs),
];

fn scalar(w: u32, ctx: &Ctx) -> Insn {
    let top = bit(w, 24);
    let opc = bits(w, 11, 8);
    let size = bits(w, 21, 20);
    if size == 0 {
        return undef(ctx);
    }
    let (name, kind) = SCALAR[opc as usize];
    let d = vd(w);
    let n = vn(w);
    let mfield = bits(w, 3, 0);
    // The scalar: d0-d7 with a 2-bit index for 16-bit elements, d0-d15 with a 1-bit index for 32-bit ones.
    let sc = if size == 1 { lane_reg("d", mfield & 7, (bit(w, 5) << 1) | (mfield >> 3)) } else { lane_reg("d", mfield, bit(w, 5)) };
    match kind {
        Sk::Qi | Sk::Qf | Sk::Qs => {
            if top != 0 && ((d | n) & 1) != 0 {
                return undef(ctx);
            }
            let dt = match kind {
                Sk::Qi => dt_num("i", 8 << size),
                Sk::Qf => Dt::from(if size == 1 { "f16" } else { "f32" }),
                _ => dt_num("s", 8 << size),
            };
            mk(ctx, name, &dt, &[V(d, top), V(n, top), sc], 0, true)
        }
        Sk::L => {
            if d & 1 != 0 {
                return undef(ctx);
            }
            mk(ctx, name, &SU(top, size), &[Q(d), D(n), sc], 0, true)
        }
        Sk::Sl => {
            if top != 0 || d & 1 != 0 {
                return undef(ctx);
            }
            mk(ctx, name, &dt_num("s", 8 << size), &[Q(d), D(n), sc], 0, true)
        }
    }
}

/* ------------------------------------------------------------------ *
 * Two registers and a shift amount
 * ------------------------------------------------------------------ */

fn shift_imm(w: u32, ctx: &Ctx) -> Insn {
    let u = bit(w, 24);
    let opc = bits(w, 11, 8);
    let l = bit(w, 7);
    let q = bit(w, 6);
    let imm6 = bits(w, 21, 16);
    let imm = ((l << 6) | imm6) as i64;
    // The element size: the highest set bit of L:imm6.
    let esize: u32 = if l != 0 {
        64
    } else if imm6 & 32 != 0 {
        32
    } else if imm6 & 16 != 0 {
        16
    } else {
        8
    };
    let size = match esize {
        8 => 0,
        16 => 1,
        32 => 2,
        _ => 3,
    };
    let right = 2 * esize as i64 - imm;
    let left = imm - esize as i64;
    let d = vd(w);
    let m = vm(w);
    let same = |name: &str, dt: &str, amount: i64| -> Insn {
        if q != 0 && ((d | m) & 1) != 0 {
            return undef(ctx);
        }
        mk(ctx, name, dt, &[V(d, q), V(m, q), ih(amount)], 0, true)
    };
    match opc {
        0 => same("vshr", &SU(u, size), right),
        1 => same("vsra", &SU(u, size), right),
        2 => same("vrshr", &SU(u, size), right),
        3 => same("vrsra", &SU(u, size), right),
        4 => {
            if u != 0 {
                same("vsri", &dt_num("", esize), right)
            } else {
                undef(ctx)
            }
        }
        5 => {
            if u != 0 {
                same("vsli", &dt_num("", esize), left)
            } else {
                same("vshl", &dt_num("i", esize), left)
            }
        }
        6 => {
            if u != 0 {
                same("vqshlu", &dt_num("s", esize), left)
            } else {
                undef(ctx)
            }
        }
        7 => same("vqshl", &SU(u, size), left),
        8 | 9 => {
            // Narrowing: the data type names the source elements, twice the size of the result's.
            if l != 0 || m & 1 != 0 {
                return undef(ctx);
            }
            let src = esize * 2;
            let name;
            let dt;
            if opc == 8 {
                if u != 0 {
                    name = if q != 0 { "vqrshrun" } else { "vqshrun" };
                    dt = dt_num("s", src);
                } else {
                    name = if q != 0 { "vrshrn" } else { "vshrn" };
                    dt = dt_num("i", src);
                }
            } else {
                name = if q != 0 { "vqrshrn" } else { "vqshrn" };
                dt = dt_num(if u != 0 { "u" } else { "s" }, src);
            }
            mk(ctx, name, &dt, &[D(d), Q(m), ih(right)], 0, true)
        }
        10 => {
            if l != 0 || q != 0 || d & 1 != 0 {
                return undef(ctx);
            }
            if left == 0 {
                return mk(ctx, "vmovl", &SU(u, size), &[Q(d), D(m)], 0, true);
            }
            mk(ctx, "vshll", &SU(u, size), &[Q(d), D(m), ih(left)], 0, true)
        }
        12..=15 => {
            // Fixed-point conversions; imm6 must leave a 32-bit element.
            if l != 0 || imm6 & 32 == 0 {
                return undef(ctx);
            }
            if q != 0 && ((d | m) & 1) != 0 {
                return undef(ctx);
            }
            let half = opc < 14;
            let fl = if half { "f16" } else { "f32" };
            let it = dt_num(if u != 0 { "u" } else { "s" }, if half { 16 } else { 32 });
            let dt = if opc & 1 != 0 { dt_pair(&it, fl) } else { dt_pair(fl, &it) };
            mk(ctx, "vcvt", &dt, &[V(d, q), V(m, q), ih(64 - imm6 as i64)], 0, true)
        }
        _ => undef(ctx),
    }
}

/* ------------------------------------------------------------------ *
 * One register and a modified immediate
 * ------------------------------------------------------------------ */

fn mod_imm(w: u32, ctx: &Ctx) -> Insn {
    let op = bit(w, 5);
    let cmode = bits(w, 11, 8);
    let q = bit(w, 6);
    let d = vd(w);
    if q != 0 && d & 1 != 0 {
        return undef(ctx);
    }
    let imm8 = (bit(w, 24) << 7) | (bits(w, 18, 16) << 4) | bits(w, 3, 0);
    let reg_op = V(d, q);
    if cmode == 15 {
        if op != 0 {
            return undef(ctx);
        }
        return mk(ctx, "vmov", "f32", &[reg_op, fp_imm_op(imm8)], 0, true);
    }
    if cmode == 14 {
        if op == 0 {
            return mk(ctx, "vmov", "i8", &[reg_op, imm_hex(imm8 as i64)], 0, true);
        }
        // vmov.i64: each bit of imm8 sets a byte of ones.
        let mut hi: u32 = 0;
        let mut lo: u32 = 0;
        for byte in 0..4 {
            if (imm8 >> byte) & 1 != 0 {
                lo |= 0xff << (8 * byte);
            }
            if (imm8 >> (byte + 4)) & 1 != 0 {
                hi |= 0xff << (8 * byte);
            }
        }
        let mut t = ImmText::from("#0x");
        if hi != 0 {
            push_hex_u64(&mut t, hi as u64);
            let digits = if lo == 0 { 1 } else { (32 - lo.leading_zeros()).div_ceil(4) };
            for _ in digits..8 {
                t.push_byte(b'0');
            }
        }
        push_hex_u64(&mut t, lo as u64);
        return mk(ctx, "vmov", "i64", &[reg_op, Op::Imm { v: imm8 as f64, t }], 0, true);
    }
    let value: u32;
    let esize: &str;
    if (cmode & 12) == 8 {
        value = imm8 << (8 * ((cmode >> 1) & 1));
        esize = "i16";
    } else if (cmode & 8) == 0 {
        value = imm8 << (8 * ((cmode >> 1) & 3));
        esize = "i32";
    } else {
        // 110x: one byte with ones below it.
        let byte_num = 1 + (cmode & 1);
        value = (imm8 << (8 * byte_num)) | (0xffff >> (8 * (2 - byte_num)));
        esize = "i32";
    }
    // Odd cmodes below 12 are vorr/vbic (they keep the register), the rest vmov/vmvn.
    let orr = cmode < 12 && cmode & 1 != 0;
    let name = if orr {
        if op != 0 {
            "vbic"
        } else {
            "vorr"
        }
    } else if op != 0 {
        "vmvn"
    } else {
        "vmov"
    };
    let mut t = ImmText::from("#0x");
    push_hex_u64(&mut t, value as u64);
    mk(ctx, name, esize, &[reg_op, Op::Imm { v: value as f64, t }], 0, true)
}

/* ------------------------------------------------------------------ *
 * Two registers, miscellaneous
 * ------------------------------------------------------------------ */

const CMP0: [&str; 5] = ["vcgt", "vcge", "vceq", "vcle", "vclt"];
const VRINT: [&str; 8] = ["vrintn", "vrintx", "vrinta", "vrintz", "", "vrintm", "", "vrintp"];
const VCVT_ROUND: [&str; 4] = ["vcvta", "vcvtn", "vcvtp", "vcvtm"];

fn two_misc(w: u32, ctx: &Ctx) -> Insn {
    let size = bits(w, 19, 18);
    let a = bits(w, 17, 16);
    let b = bits(w, 10, 7);
    let q = bit(w, 6);
    let d = vd(w);
    let m = vm(w);
    let two = |name: &str, dt: &str, predicable: bool| -> Insn {
        if q != 0 && ((d | m) & 1) != 0 {
            return undef(ctx);
        }
        mk(ctx, name, dt, &[V(d, q), V(m, q)], 0, predicable)
    };
    let zero = |name: &str, dt: &str| -> Insn {
        if q != 0 && ((d | m) & 1) != 0 {
            return undef(ctx);
        }
        mk(ctx, name, dt, &[V(d, q), V(m, q), imm_text(0.0, "#0")], 0, true)
    };
    if size == 3 {
        return undef(ctx);
    }
    match a {
        0 => match b {
            0 => two("vrev64", &dt_num("", 8 << size), true),
            1 => {
                if size < 2 {
                    two("vrev32", &dt_num("", 8 << size), true)
                } else {
                    undef(ctx)
                }
            }
            2 => {
                if size < 1 {
                    two("vrev16", &dt_num("", 8 << size), true)
                } else {
                    undef(ctx)
                }
            }
            4 | 5 => two("vpaddl", &SU(b & 1, size), true),
            6 | 7 => {
                if size != 0 || (d | m) & 1 != 0 {
                    return undef(ctx);
                }
                let name = if b == 6 {
                    if q != 0 {
                        "aesd"
                    } else {
                        "aese"
                    }
                } else if q != 0 {
                    "aesimc"
                } else {
                    "aesmc"
                };
                mk(ctx, name, "8", &[Q(d), Q(m)], 0, false)
            }
            8 => two("vcls", &dt_num("s", 8 << size), true),
            9 => two("vclz", &dt_num("i", 8 << size), true),
            10 => {
                if size != 0 {
                    undef(ctx)
                } else {
                    two("vcnt", "8", true)
                }
            }
            11 => {
                if size != 0 {
                    undef(ctx)
                } else {
                    two("vmvn", "", true)
                }
            }
            12 | 13 => two("vpadal", &SU(b & 1, size), true),
            14 => two("vqabs", &dt_num("s", 8 << size), true),
            15 => two("vqneg", &dt_num("s", 8 << size), true),
            _ => undef(ctx),
        },
        1 => {
            let fl = b >> 3;
            let op = b & 7;
            if op == 5 {
                // sha1h lives where a float vcge-like operation would.
                if fl != 0 || size != 2 || q == 0 || (d | m) & 1 != 0 {
                    return undef(ctx);
                }
                return mk(ctx, "sha1h", "32", &[Q(d), Q(m)], 0, false);
            }
            let dt = if fl != 0 {
                if size == 0 {
                    return undef(ctx);
                }
                Dt::from(if size == 1 { "f16" } else { "f32" })
            } else {
                dt_num(if op == 2 { "i" } else { "s" }, 8 << size)
            };
            if op < 5 {
                return zero(CMP0[op as usize], &dt);
            }
            two(if op == 6 { "vabs" } else { "vneg" }, &dt, true)
        }
        2 => match b {
            0 => {
                if size != 0 {
                    undef(ctx)
                } else {
                    two("vswp", "", true)
                }
            }
            1 => two("vtrn", &dt_num("", 8 << size), true),
            2 | 3 => {
                // 32-bit vuzp and vzip of D registers would be vtrn; they are not encodable.
                if size == 2 && q == 0 {
                    return undef(ctx);
                }
                two(if b == 2 { "vuzp" } else { "vzip" }, &dt_num("", 8 << size), true)
            }
            4 => {
                if m & 1 != 0 {
                    return undef(ctx);
                }
                if q != 0 {
                    mk(ctx, "vqmovun", &dt_num("s", 16 << size), &[D(d), Q(m)], 0, true)
                } else {
                    mk(ctx, "vmovn", &dt_num("i", 16 << size), &[D(d), Q(m)], 0, true)
                }
            }
            5 => {
                if m & 1 != 0 {
                    return undef(ctx);
                }
                mk(ctx, "vqmovn", &dt_num(if q != 0 { "u" } else { "s" }, 16 << size), &[D(d), Q(m)], 0, true)
            }
            6 => {
                if q != 0 || d & 1 != 0 {
                    return undef(ctx);
                }
                mk(ctx, "vshll", &dt_num("i", 8 << size), &[Q(d), D(m), ih((8 << size) as i64)], 0, true)
            }
            7 => {
                if size != 2 || (d | m) & 1 != 0 {
                    return undef(ctx);
                }
                mk(ctx, if q != 0 { "sha256su0" } else { "sha1su1" }, "32", &[Q(d), Q(m)], 0, false)
            }
            12 => {
                // f32 to f16 (or bf16) narrowing.
                if size != 1 || m & 1 != 0 {
                    return undef(ctx);
                }
                if q != 0 {
                    mk(ctx, "vcvt", "bf16.f32", &[D(d), Q(m)], 0, true)
                } else {
                    mk(ctx, "vcvt", "f16.f32", &[D(d), Q(m)], 0, true)
                }
            }
            14 => {
                if size != 1 || q != 0 || d & 1 != 0 {
                    return undef(ctx);
                }
                mk(ctx, "vcvt", "f32.f16", &[Q(d), D(m)], 0, true)
            }
            _ => {
                // b is 8…15 here (0…7 are above), so VRINT[b - 8] is in range.
                let name = if b >= 8 { VRINT[(b - 8) as usize] } else { "" };
                if name.is_empty() || size == 0 {
                    return undef(ctx);
                }
                two(name, if size == 1 { "f16" } else { "f32" }, false)
            }
        },
        _ => {
            if size == 0 {
                return undef(ctx);
            }
            let half = size == 1;
            let fl = if half { "f16" } else { "f32" };
            let bits_w = if half { 16 } else { 32 };
            if b < 8 {
                return two(VCVT_ROUND[(b >> 1) as usize], &dt_pair(&dt_num(if b & 1 != 0 { "u" } else { "s" }, bits_w), fl), false);
            }
            if b < 12 {
                // 10F0 vrecpe, 10F1 vrsqrte: F picks float over unsigned.
                let name = if b & 1 != 0 { "vrsqrte" } else { "vrecpe" };
                if b & 2 != 0 {
                    return two(name, fl, true);
                }
                return if half { undef(ctx) } else { two(name, "u32", true) };
            }
            let op = b & 3;
            let dt = if op < 2 { dt_pair(fl, &dt_num(if op != 0 { "u" } else { "s" }, bits_w)) } else { dt_pair(&dt_num(if op & 1 != 0 { "u" } else { "s" }, bits_w), fl) };
            two("vcvt", &dt, true)
        }
    }
}

/* ------------------------------------------------------------------ *
 * The rest of bit 23 = 1: vext, vtbl/vtbx, vdup (scalar)
 * ------------------------------------------------------------------ */

fn vext(w: u32, ctx: &Ctx) -> Insn {
    let q = bit(w, 6);
    let imm4 = bits(w, 11, 8);
    let d = vd(w);
    let n = vn(w);
    let m = vm(w);
    if q != 0 && ((d | n | m) & 1) != 0 {
        return undef(ctx);
    }
    if q == 0 && imm4 & 8 != 0 {
        return undef(ctx);
    }
    // LLVM names the largest element size that the byte index is a multiple of.
    let mut ebytes = 1;
    if q != 0 && (imm4 & 7) == 0 {
        ebytes = 8;
    } else if (imm4 & 3) == 0 {
        ebytes = 4;
    } else if (imm4 & 1) == 0 {
        ebytes = 2;
    }
    mk(ctx, "vext", &dt_num("", ebytes * 8), &[V(d, q), V(n, q), V(m, q), ih((imm4 / ebytes) as i64)], 0, true)
}

fn vtbl(w: u32, ctx: &Ctx) -> Insn {
    let len = bits(w, 9, 8) + 1;
    let d = vd(w);
    let n = vn(w);
    let m = vm(w);
    // Two-register tables are a register pair, which cannot start at d31.
    if len == 2 && n == 31 {
        return undef(ctx);
    }
    mk(ctx, if bit(w, 6) != 0 { "vtbx" } else { "vtbl" }, "8", &[D(d), dlist(n, len, 1, Suffix::None, false), D(m)], 0, true)
}

fn vdup_scalar(w: u32, ctx: &Ctx) -> Insn {
    let imm4 = bits(w, 19, 16);
    let q = bit(w, 6);
    let d = vd(w);
    let m = vm(w);
    if bit(w, 7) != 0 || (q != 0 && d & 1 != 0) {
        return undef(ctx);
    }
    let dt;
    let index;
    if imm4 & 1 != 0 {
        dt = "8";
        index = imm4 >> 1;
    } else if imm4 & 2 != 0 {
        dt = "16";
        index = imm4 >> 2;
    } else if imm4 & 4 != 0 {
        dt = "32";
        index = imm4 >> 3;
    } else {
        return undef(ctx);
    }
    mk(ctx, "vdup", dt, &[V(d, q), lane_reg("d", m, index)], 0, true)
}

/// An A32 word of the form 1111 001U (or its T32 twin).
pub fn neon_data(w: u32, ctx: &Ctx) -> Insn {
    if bit(w, 23) == 0 {
        return three_same(w, ctx);
    }
    if bit(w, 4) != 0 {
        return if bits(w, 21, 19) == 0 && bit(w, 7) == 0 { mod_imm(w, ctx) } else { shift_imm(w, ctx) };
    }
    if bits(w, 21, 20) != 3 {
        return if bit(w, 6) != 0 { scalar(w, ctx) } else { three_diff(w, ctx) };
    }
    if bit(w, 24) == 0 {
        return vext(w, ctx);
    }
    if bit(w, 11) == 0 {
        return two_misc(w, ctx);
    }
    if bit(w, 10) == 0 {
        return vtbl(w, ctx);
    }
    if bits(w, 11, 8) == 12 {
        return vdup_scalar(w, ctx);
    }
    undef(ctx)
}
