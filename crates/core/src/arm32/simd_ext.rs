//! The Armv8.2-8.6 SIMD additions that live in the unconditional coprocessor
//! space, the same in A32 and T32: complex arithmetic (vcmla, vcadd), dot
//! products (vsdot, vudot, vusdot, vsudot, vdot.bf16), half-precision
//! multiply-long (vfmal, vfmsl), BF16 multiply-add (vfmab, vfmat) and the
//! matrix multiplies (vsmmla, vummla, vusmmla, vmmla.bf16).
//!
//! 1111 110x holds the vector forms, 1111 1110 the by-element ones; bits 11-8
//! are 1000 (complex, vfmal, bf16 multiply-add), 1100 (matrix multiplies) or
//! 1101 (dot products). None of them can be conditional.

use super::simd_common::*;
use super::types::*;

#[inline]
fn idx(reg: u32, index: u32) -> Op {
    lane_reg("d", reg, index)
}
#[inline]
fn sidx(reg: u32, index: u32) -> Op {
    lane_reg("s", reg, index)
}
#[inline]
fn rot(degrees: u32) -> Op {
    imm_dec(degrees as i64)
}

/// Q forms need even register numbers throughout.
#[inline]
fn even_q(q: u32, regs: &[u32]) -> bool {
    q == 0 || regs.iter().all(|n| n & 1 == 0)
}

#[inline]
fn np(ctx: &Ctx, name: &str, dt: &str, ops: &[Op]) -> Insn {
    mk(ctx, name, dt, ops, 0, false)
}

/// 1111 110x: three vector registers.
fn vector(w: u32, ctx: &Ctx) -> Insn {
    let cp = bits(w, 11, 8);
    let q = bit(w, 6);
    let d = vd(w);
    let n = vn(w);
    let m = vm(w);
    let op4 = bit(w, 4);
    let top = bits(w, 24, 23);
    let op21 = bits(w, 21, 20);
    if cp == 8 {
        if op4 == 0 {
            if !even_q(q, &[d, n, m]) {
                return undef(ctx);
            }
            let dt = if op21 & 1 != 0 { "f32" } else { "f16" };
            // vcmla: bit 21 set, bits 24-23 the rotation; vcadd: bit 21 clear, bit 23 set, bit 24 the rotation.
            if op21 & 2 != 0 {
                return np(ctx, "vcmla", dt, &[V(d, q), V(n, q), V(m, q), rot(top * 90)]);
            }
            if top & 1 != 0 {
                return np(ctx, "vcadd", dt, &[V(d, q), V(n, q), V(m, q), rot(if top & 2 != 0 { 270 } else { 90 })]);
            }
            return undef(ctx);
        }
        if op21 == 2 && top < 2 {
            // vfmal/vfmsl: Q forms widen D to Q, the others S to D.
            let name = if top != 0 { "vfmsl" } else { "vfmal" };
            if q != 0 {
                return if d & 1 != 0 { undef(ctx) } else { np(ctx, name, "f16", &[Q(d), D(n), D(m)]) };
            }
            return np(ctx, name, "f16", &[D(d), S((bits(w, 19, 16) << 1) | bit(w, 7)), S((bits(w, 3, 0) << 1) | bit(w, 5))]);
        }
        if op21 == 3 && top == 0 {
            if (d | n | m) & 1 != 0 {
                return undef(ctx);
            }
            return np(ctx, if q != 0 { "vfmat" } else { "vfmab" }, "bf16", &[Q(d), Q(n), Q(m)]);
        }
        return undef(ctx);
    }
    if bit(w, 24) != 0 {
        return undef(ctx);
    }
    let b = bit(w, 23);
    if cp == 12 {
        // Matrix multiplies, Q registers only.
        if q == 0 || (d | n | m) & 1 != 0 {
            return undef(ctx);
        }
        if op21 == 2 {
            if b != 0 {
                return if op4 != 0 { undef(ctx) } else { np(ctx, "vusmmla", "s8", &[Q(d), Q(n), Q(m)]) };
            }
            return np(ctx, if op4 != 0 { "vummla" } else { "vsmmla" }, if op4 != 0 { "u8" } else { "s8" }, &[Q(d), Q(n), Q(m)]);
        }
        if op21 == 0 && b == 0 && op4 == 0 {
            return np(ctx, "vmmla", "bf16", &[Q(d), Q(n), Q(m)]);
        }
        return undef(ctx);
    }
    if cp == 13 {
        if !even_q(q, &[d, n, m]) {
            return undef(ctx);
        }
        let ops = [V(d, q), V(n, q), V(m, q)];
        if op21 == 2 {
            if b != 0 {
                return if op4 != 0 { undef(ctx) } else { np(ctx, "vusdot", "s8", &ops) };
            }
            return np(ctx, if op4 != 0 { "vudot" } else { "vsdot" }, if op4 != 0 { "u8" } else { "s8" }, &ops);
        }
        if op21 == 0 && b == 0 && op4 == 0 {
            return np(ctx, "vdot", "bf16", &ops);
        }
        return undef(ctx);
    }
    undef(ctx)
}

/// 1111 1110: by-element forms.
fn element(w: u32, ctx: &Ctx) -> Insn {
    let cp = bits(w, 11, 8);
    let q = bit(w, 6);
    let d = vd(w);
    let n = vn(w);
    let op4 = bit(w, 4);
    let b = bit(w, 23);
    let op21 = bits(w, 21, 20);
    let mlo = bits(w, 3, 0);
    if cp == 8 {
        if op4 == 0 {
            // vcmla by element: f16 indexes a pair of halves in d0-d15, f32 has only element 0 of any D register.
            if !even_q(q, &[d, n]) {
                return undef(ctx);
            }
            if b != 0 {
                return np(ctx, "vcmla", "f32", &[V(d, q), V(n, q), idx(vm(w), 0), rot(op21 * 90)]);
            }
            return np(ctx, "vcmla", "f16", &[V(d, q), V(n, q), idx(mlo, bit(w, 5)), rot(op21 * 90)]);
        }
        if b != 0 {
            return undef(ctx);
        }
        if op21 < 2 {
            let name = if op21 != 0 { "vfmsl" } else { "vfmal" };
            if q != 0 {
                if d & 1 != 0 {
                    return undef(ctx);
                }
                return np(ctx, name, "f16", &[Q(d), D(n), idx(mlo & 7, (bit(w, 5) << 1) | bit(w, 3))]);
            }
            return np(ctx, name, "f16", &[D(d), S((bits(w, 19, 16) << 1) | bit(w, 7)), sidx(((mlo & 7) << 1) | bit(w, 5), bit(w, 3))]);
        }
        if op21 == 3 {
            if (d | n) & 1 != 0 {
                return undef(ctx);
            }
            return np(ctx, if q != 0 { "vfmat" } else { "vfmab" }, "bf16", &[Q(d), Q(n), idx(mlo & 7, (bit(w, 5) << 1) | bit(w, 3))]);
        }
        return undef(ctx);
    }
    if cp == 13 {
        if !even_q(q, &[d, n]) {
            return undef(ctx);
        }
        let ops = [V(d, q), V(n, q), idx(mlo, bit(w, 5))];
        if op21 == 2 && b == 0 {
            return np(ctx, if op4 != 0 { "vudot" } else { "vsdot" }, if op4 != 0 { "u8" } else { "s8" }, &ops);
        }
        if op21 == 0 && b != 0 {
            return np(ctx, if op4 != 0 { "vsudot" } else { "vusdot" }, if op4 != 0 { "u8" } else { "s8" }, &ops);
        }
        if op21 == 0 && b == 0 && op4 == 0 {
            return np(ctx, "vdot", "bf16", &ops);
        }
        return undef(ctx);
    }
    undef(ctx)
}

/// An unconditional word 1111 110x or 1111 1110 with bits 11-8 = 1000, 1100 or 1101.
pub fn simd_extension(w: u32, ctx: &Ctx) -> Insn {
    if bit(w, 25) != 0 {
        element(w, ctx)
    } else {
        vector(w, ctx)
    }
}
