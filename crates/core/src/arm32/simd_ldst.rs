//! Advanced SIMD element and structure loads and stores, vld1…vld4 and
//! vst1…vst4: the A32 space 1111 0100 xxx0, which T32 encodes as 1111 1001
//! xxx0. Bit 23 separates whole structures (multiple registers, `{d0, d1}`)
//! from single elements (one lane, `{d0[1]}`, or every lane, `{d0[], d1[]}`).
//!
//! The address is `[rN]` or `[rN:align]`, then `!` when the base moves on by
//! the bytes transferred (Rm = 13) or `, rM` when it moves on by a register.

use super::simd_common::*;
use super::types::*;
use crate::text::push_dec;

/// The address operand: Rm = 15 leaves the base alone, 13 adds the size moved, anything else adds rM.
fn address(rn: u32, align_bits: u32, rm: u32) -> Op {
    let base = r(rn);
    let mut t = MemText::from("[");
    t.push(&base);
    if align_bits != 0 {
        t.push(":");
        push_dec(&mut t, align_bits as i64);
    }
    t.push("]");
    if rm == 15 {
        return Op::Mem(Mem { base, t, off: None, index: None, mode: Mode::Off });
    }
    if rm == 13 {
        t.push("!");
        return Op::Mem(Mem { base, t, off: None, index: None, mode: Mode::Post });
    }
    let index = r(rm);
    t.push(", ");
    t.push(&index);
    Op::Mem(Mem { base, t, off: None, index: Some(index), mode: Mode::Post })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    One,
    Pair,
    Enum,
    Mod,
}

/// Multiple structures, by bits 11-8: the instruction, how many registers and
/// how far apart, the alignments allowed (a mask over the 2-bit field), and
/// how the register list is formed: `pair` lists must fit below d32, `enum`
/// lists run on past d31 as LLVM numbers them, `mod` lists wrap to d0.
/// (registers per structure n, register count, step, alignment mask, list kind)
type Multi = (u32, u32, u32, u32, Kind);

const MULTI: [Option<Multi>; 16] = [
    Some((4, 4, 1, 0b1111, Kind::Mod)),  // 0000 vld4/vst4, d..d+3
    Some((4, 4, 2, 0b1111, Kind::Mod)),  // 0001 vld4/vst4, d, d+2, d+4, d+6
    Some((1, 4, 1, 0b1111, Kind::Enum)), // 0010 vld1/vst1, four registers
    Some((2, 4, 1, 0b1111, Kind::Enum)), // 0011 vld2/vst2, four registers
    Some((3, 3, 1, 0b0011, Kind::Mod)),  // 0100 vld3/vst3
    Some((3, 3, 2, 0b0011, Kind::Mod)),  // 0101 vld3/vst3, double spaced
    Some((1, 3, 1, 0b0011, Kind::Enum)), // 0110 vld1/vst1, three registers
    Some((1, 1, 1, 0b0011, Kind::One)),  // 0111 vld1/vst1, one register
    Some((2, 2, 1, 0b0111, Kind::Pair)), // 1000 vld2/vst2
    Some((2, 2, 2, 0b0111, Kind::Pair)), // 1001 vld2/vst2, double spaced
    Some((1, 2, 1, 0b0111, Kind::Pair)), // 1010 vld1/vst1, two registers
    None,
    None,
    None,
    None,
    None,
];

/// `vld3` / `vst2`
#[inline]
fn name(load: bool, n: u32) -> Mn {
    let mut m = Mn::from(if load { "vld" } else { "vst" });
    push_dec(&mut m, n as i64);
    m
}

/// `${8 << size}`
const ESIZE: [&str; 4] = ["8", "16", "32", "64"];

fn multiple(w: u32, ctx: &Ctx, load: bool) -> Insn {
    let ty = bits(w, 11, 8);
    let Some((n, count, step, aligns, kind)) = MULTI[ty as usize] else {
        return undef(ctx);
    };
    let size = bits(w, 7, 6);
    let align = bits(w, 5, 4);
    if (aligns >> align) & 1 == 0 {
        return undef(ctx);
    }
    if size == 3 && n != 1 {
        return undef(ctx);
    }
    let d = (bit(w, 22) << 4) | bits(w, 15, 12);
    if kind == Kind::Pair && d + (count - 1) * step > 31 {
        return undef(ctx);
    }
    let regs = dlist(d, count, step, Suffix::None, kind == Kind::Mod);
    let mem = address(bits(w, 19, 16), if align != 0 { 32 << align } else { 0 }, bits(w, 3, 0));
    mk(ctx, &name(load, n), ESIZE[size as usize], &[regs, mem], if load { f::LOAD } else { f::STORE }, true).bytes(8)
}

/// One lane of 1-4 registers: vld2.16 {d0[1], d2[1]}, [r0:32].
fn lane(w: u32, ctx: &Ctx, load: bool) -> Insn {
    let size = bits(w, 11, 10);
    let n = bits(w, 9, 8) + 1;
    let ia = bits(w, 7, 4);
    let index: u32;
    let mut inc = 1;
    let mut align_bytes = 0;
    if size == 0 {
        index = ia >> 1;
        if ia & 1 != 0 {
            if n == 1 || n == 3 {
                return undef(ctx);
            }
            align_bytes = if n == 2 { 2 } else { 4 };
        }
    } else if size == 1 {
        index = ia >> 2;
        if n == 1 && ia & 2 != 0 {
            return undef(ctx);
        }
        if n > 1 && ia & 2 != 0 {
            inc = 2;
        }
        if ia & 1 != 0 {
            if n == 3 {
                return undef(ctx);
            }
            align_bytes = if n == 1 {
                2
            } else if n == 2 {
                4
            } else {
                8
            };
        }
    } else {
        index = ia >> 3;
        if n == 1 {
            if ia & 4 != 0 {
                return undef(ctx);
            }
            let a = ia & 3;
            if a == 3 {
                align_bytes = 4;
            } else if a != 0 {
                return undef(ctx);
            }
        } else if n == 2 {
            if ia & 2 != 0 {
                return undef(ctx);
            }
            if ia & 4 != 0 {
                inc = 2;
            }
            if ia & 1 != 0 {
                align_bytes = 8;
            }
        } else if n == 3 {
            if ia & 3 != 0 {
                return undef(ctx);
            }
            if ia & 4 != 0 {
                inc = 2;
            }
        } else {
            if ia & 4 != 0 {
                inc = 2;
            }
            let a = ia & 3;
            if a == 3 {
                return undef(ctx);
            }
            if a != 0 {
                align_bytes = 4 << a;
            }
        }
    }
    let d = (bit(w, 22) << 4) | bits(w, 15, 12);
    if d + (n - 1) * inc > 31 {
        return undef(ctx);
    }
    let regs = dlist(d, n, inc, Suffix::Lane(index), false);
    let mem = address(bits(w, 19, 16), align_bytes * 8, bits(w, 3, 0));
    mk(ctx, &name(load, n), ESIZE[size as usize], &[regs, mem], if load { f::LOAD } else { f::STORE }, true).bytes(1 << size)
}

/// Every lane: vld1.8 {d0[]}, vld4.32 {d0[], d2[], d4[], d6[]}, [r0:128].
fn all_lanes(w: u32, ctx: &Ctx) -> Insn {
    let n = bits(w, 9, 8) + 1;
    let mut size = bits(w, 7, 6);
    let t = bit(w, 5);
    let a = bit(w, 4);
    let d = (bit(w, 22) << 4) | bits(w, 15, 12);
    let mut count = n;
    let mut inc = 1;
    let mut align_bytes = 0;
    let mut wrap = true;
    match n {
        1 => {
            if size == 3 || (size == 0 && a != 0) {
                return undef(ctx);
            }
            count = t + 1;
            align_bytes = a << size;
            wrap = false;
        }
        2 => {
            if size == 3 {
                return undef(ctx);
            }
            inc = t + 1;
            align_bytes = (a * 2) << size;
            wrap = false;
        }
        3 => {
            if size == 3 || a != 0 {
                return undef(ctx);
            }
            inc = t + 1;
        }
        _ => {
            inc = t + 1;
            if size == 3 {
                if a == 0 {
                    return undef(ctx);
                }
                align_bytes = 16;
                size = 2;
            } else {
                align_bytes = if size == 2 { a * 8 } else { (a * 4) << size };
            }
        }
    }
    if !wrap && d + (count - 1) * inc > 31 {
        return undef(ctx);
    }
    let regs = dlist(d, count, inc, Suffix::All, wrap);
    let mem = address(bits(w, 19, 16), align_bytes * 8, bits(w, 3, 0));
    mk(ctx, &name(true, n), ESIZE[size as usize], &[regs, mem], f::LOAD, true).bytes(1 << size)
}

/// An A32 word of the form 1111 0100 xxx0 (or its T32 twin).
pub fn neon_load_store(w: u32, ctx: &Ctx) -> Insn {
    let load = bit(w, 21) == 1;
    if bit(w, 23) == 0 {
        return multiple(w, ctx, load);
    }
    if bits(w, 11, 10) != 3 {
        return lane(w, ctx, load);
    }
    if load {
        all_lanes(w, ctx)
    } else {
        undef(ctx)
    }
}
