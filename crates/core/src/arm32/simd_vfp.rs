//! Floating point in the coprocessor space (coprocessors 9, 10 and 11: half,
//! single and double precision): the data-processing instructions, moves
//! between core and floating-point registers, vmrs/vmsr, vldr/vstr and
//! vldm/vstm, and the unconditional Armv8 additions (vsel, vmaxnm, vrinta,
//! vcvta, vins, vmovx). A32 and T32 encode them alike; Thumb takes the
//! condition from the IT block instead of bits 31-28.

use super::simd_common::*;
use super::types::*;
use crate::text::push_dec;

/* ------------------------------------------------------------------ *
 * Data processing
 * ------------------------------------------------------------------ */

const THREE: [[&str; 2]; 7] = [["vmla", "vmls"], ["vnmls", "vnmla"], ["vmul", "vnmul"], ["vadd", "vsub"], ["vdiv", ""], ["vfnms", "vfnma"], ["vfma", "vfms"]];

/// cp: 9 half, 10 single, 11 double.
#[inline]
fn fdt(cp: u32) -> &'static str {
    if cp == 11 {
        "f64"
    } else if cp == 10 {
        "f32"
    } else {
        "f16"
    }
}

fn data_processing(w: u32, ctx: &Ctx, cp: u32) -> Insn {
    let dbl = cp == 11;
    let dt = fdt(cp);
    let opc1 = (bit(w, 23) << 2) | bits(w, 21, 20);
    let op6 = bit(w, 6);
    #[allow(non_snake_case)]
    let Rd = if dbl { D(vd(w)) } else { S(sd(w)) };
    #[allow(non_snake_case)]
    let Rm = if dbl { D(vm(w)) } else { S(sm(w)) };
    if opc1 < 7 {
        let name = THREE[opc1 as usize][op6 as usize];
        if name.is_empty() {
            return undef(ctx);
        }
        return mk(ctx, name, dt, &[Rd, if dbl { D(vn(w)) } else { S(sn(w)) }, Rm], 0, true);
    }
    if op6 == 0 {
        // vmov.f32 s0, #1.000000e+00: the immediate's low bits fill 3-0, bits 7-4 are zero.
        if bits(w, 7, 4) != 0 {
            return undef(ctx);
        }
        return mk(ctx, "vmov", dt, &[Rd, fp_imm_op((bits(w, 19, 16) << 4) | bits(w, 3, 0))], 0, true);
    }
    let opc2 = bits(w, 19, 16);
    let o7 = bit(w, 7) != 0;
    let sdst = S(sd(w));
    let ssrc = S(sm(w));
    match opc2 {
        0 => {
            if !o7 && cp == 9 {
                return undef(ctx);
            }
            mk(ctx, if o7 { "vabs" } else { "vmov" }, dt, &[Rd, Rm], 0, true)
        }
        1 => mk(ctx, if o7 { "vsqrt" } else { "vneg" }, dt, &[Rd, Rm], 0, true),
        2 => {
            // Half to single or double: vcvtb.f32.f16 s0, s1.
            if cp == 9 {
                return undef(ctx);
            }
            mk(ctx, if o7 { "vcvtt" } else { "vcvtb" }, &dt_pair(dt, "f16"), &[Rd, ssrc], 0, true)
        }
        3 => {
            if cp == 9 {
                return mk(ctx, if o7 { "vcvtt" } else { "vcvtb" }, "bf16.f32", &[sdst, ssrc], 0, true);
            }
            mk(ctx, if o7 { "vcvtt" } else { "vcvtb" }, &dt_pair("f16", dt), &[sdst, Rm], 0, true)
        }
        4 => mk(ctx, if o7 { "vcmpe" } else { "vcmp" }, dt, &[Rd, Rm], 0, true),
        5 => {
            if bit(w, 5) != 0 || bits(w, 3, 0) != 0 {
                return undef(ctx);
            }
            mk(ctx, if o7 { "vcmpe" } else { "vcmp" }, dt, &[Rd, imm_text(0.0, "#0")], 0, true)
        }
        6 => mk(ctx, if o7 { "vrintz" } else { "vrintr" }, dt, &[Rd, Rm], 0, true),
        7 => {
            if !o7 {
                return mk(ctx, "vrintx", dt, &[Rd, Rm], 0, true);
            }
            if cp == 10 {
                return mk(ctx, "vcvt", "f64.f32", &[D(vd(w)), ssrc], 0, true);
            }
            if cp == 11 {
                return mk(ctx, "vcvt", "f32.f64", &[sdst, D(vm(w))], 0, true);
            }
            undef(ctx)
        }
        8 => mk(ctx, "vcvt", &dt_pair(dt, if o7 { "s32" } else { "u32" }), &[Rd, ssrc], 0, true),
        9 => {
            if cp != 11 || !o7 {
                return undef(ctx);
            }
            mk(ctx, "vjcvt", "s32.f64", &[sdst, D(vm(w))], 0, true)
        }
        10 | 11 | 14 | 15 => {
            // Fixed point: the register is both source and destination, the fraction bits count down from 16 or 32.
            let size: i64 = if o7 { 32 } else { 16 };
            let fbits = size - (((bits(w, 3, 0) << 1) | bit(w, 5)) as i64);
            let fixed = dt_num(if opc2 & 1 != 0 { "u" } else { "s" }, size as u32);
            let dts = if opc2 & 4 != 0 { dt_pair(&fixed, dt) } else { dt_pair(dt, &fixed) };
            mk(ctx, "vcvt", &dts, &[Rd, Rd, id(fbits)], 0, true)
        }
        12 | 13 => mk(ctx, if o7 { "vcvt" } else { "vcvtr" }, &dt_pair(if opc2 & 1 != 0 { "s32" } else { "u32" }, dt), &[sdst, Rm], 0, true),
        _ => undef(ctx),
    }
}

/* ------------------------------------------------------------------ *
 * Transfers between core and floating-point registers
 * ------------------------------------------------------------------ */

const SYSREG: [&str; 11] = ["fpsid", "fpscr", "", "", "", "mvfr2", "mvfr1", "mvfr0", "fpexc", "fpinst", "fpinst2"];

fn transfer(w: u32, ctx: &Ctx, cp: u32) -> Insn {
    let load = bit(w, 20) != 0;
    let rt = bits(w, 15, 12);
    if cp == 11 {
        if bits(w, 3, 0) != 0 {
            return undef(ctx);
        }
        let dn = (bit(w, 7) << 4) | bits(w, 19, 16);
        if !load && bit(w, 23) != 0 {
            // vdup.32 q0, r0: B (bit 22) and E (bit 5) give the size.
            if bit(w, 6) != 0 {
                return undef(ctx);
            }
            let be = (bit(w, 22) << 1) | bit(w, 5);
            if be == 3 {
                return undef(ctx);
            }
            let q = bit(w, 21);
            if q != 0 && dn & 1 != 0 {
                return undef(ctx);
            }
            return mk(ctx, "vdup", ["32", "16", "8"][be as usize], &[V(dn, q), R(rt)], 0, true);
        }
        let opc = (bits(w, 22, 21) << 2) | bits(w, 6, 5);
        let size: u32;
        let index: u32;
        if opc & 8 != 0 {
            size = 8;
            index = opc & 7;
        } else if opc & 1 != 0 {
            size = 16;
            index = opc >> 1;
        } else if opc & 2 == 0 {
            size = 32;
            index = opc >> 2;
        } else {
            return undef(ctx);
        }
        let scalar = lane_reg("d", dn, index);
        if !load {
            return mk(ctx, "vmov", &dt_num("", size), &[scalar, R(rt)], 0, true);
        }
        let u = bit(w, 23) != 0;
        if size == 32 && u {
            return undef(ctx);
        }
        let dt = if size == 32 { dt_num("", 32) } else { dt_num(if u { "u" } else { "s" }, size) };
        return mk(ctx, "vmov", &dt, &[R(rt), scalar], 0, true);
    }
    if cp == 8 {
        return undef(ctx);
    }
    let opc1 = bits(w, 23, 21);
    if opc1 == 0 {
        if bits(w, 6, 5) != 0 || bits(w, 3, 0) != 0 {
            return undef(ctx);
        }
        let s = S(sn(w));
        let dt = if cp == 9 { "f16" } else { "" };
        return if load { mk(ctx, "vmov", dt, &[R(rt), s], 0, true) } else { mk(ctx, "vmov", dt, &[s, R(rt)], 0, true) };
    }
    if opc1 != 7 || cp != 10 {
        return undef(ctx);
    }
    let reg_n = bits(w, 19, 16);
    let sys = SYSREG.get(reg_n as usize).copied().unwrap_or("");
    if sys.is_empty() {
        return undef(ctx);
    }
    if load {
        if rt == 15 && sys == "fpscr" {
            // vmrs APSR_nzcv, fpscr copies the comparison flags to the integer ones.
            return mk(ctx, "vmrs", "", &[reg_str("APSR_nzcv"), reg_str("fpscr")], f::SETS_FLAGS, true);
        }
        return mk(ctx, "vmrs", "", &[R(rt), reg_str(sys)], 0, true);
    }
    // The media and VFP feature registers (mvfr0-2) can only be read.
    if (5..=7).contains(&reg_n) {
        return undef(ctx);
    }
    mk(ctx, "vmsr", "", &[reg_str(sys), R(rt)], 0, true)
}

/// vmov d0, r0, r1 and vmov s0, s1, r0, r1, either way.
fn transfer64(w: u32, ctx: &Ctx, cp: u32) -> Insn {
    if bits(w, 7, 6) != 0 || bit(w, 4) == 0 || (cp != 10 && cp != 11) {
        return undef(ctx);
    }
    let load = bit(w, 20) != 0;
    let rt = R(bits(w, 15, 12));
    let rt2 = R(bits(w, 19, 16));
    if cp == 11 {
        let dm = D(vm(w));
        return if load { mk(ctx, "vmov", "", &[rt, rt2, dm], 0, true) } else { mk(ctx, "vmov", "", &[dm, rt, rt2], 0, true) };
    }
    let m = sm(w);
    if m == 31 {
        return undef(ctx);
    }
    if load {
        mk(ctx, "vmov", "", &[rt, rt2, S(m), S(m + 1)], 0, true)
    } else {
        mk(ctx, "vmov", "", &[S(m), S(m + 1), rt, rt2], 0, true)
    }
}

/* ------------------------------------------------------------------ *
 * Loads and stores
 * ------------------------------------------------------------------ */

fn load_store(w: u32, ctx: &Ctx, cp: u32) -> Insn {
    let p = bit(w, 24);
    let u = bit(w, 23);
    let wb = bit(w, 21);
    let load = bit(w, 20) != 0;
    let rn = bits(w, 19, 16);
    let imm8 = bits(w, 7, 0);
    if p != 0 && wb == 0 {
        // vldr/vstr: the offset counts words (halfwords for .16), and #-0 still prints.
        if cp == 8 {
            return undef(ctx);
        }
        let scale = if cp == 9 { 2 } else { 4 };
        let off = (imm8 * scale) as i64 * if u != 0 { 1 } else { -1 };
        let base = r(rn);
        let mut t = MemText::from("[");
        t.push(&base);
        if imm8 != 0 || u == 0 {
            t.push(if u != 0 { ", #" } else { ", #-" });
            push_dec(&mut t, (imm8 * scale) as i64);
        }
        t.push("]");
        let mem = Op::Mem(Mem { base, t, off: Some(off), index: None, mode: Mode::Off });
        let reg_op = if cp == 11 { D(vd(w)) } else { S(sd(w)) };
        let mut insn =
            mk(ctx, if load { "vldr" } else { "vstr" }, if cp == 9 { "16" } else { "" }, &[reg_op, mem], if load { f::LOAD } else { f::STORE }, true).bytes(if cp == 11 {
                8
            } else if cp == 10 {
                4
            } else {
                2
            });
        if rn == 15 {
            let pc = ctx.pc as u32;
            let from = if ctx.thumb { pc.wrapping_add(4) & !3 } else { pc.wrapping_add(8) };
            insn = insn.target(from.wrapping_add(off as u32) as i64);
        }
        return insn;
    }
    // vldm/vstm: increment after (with or without writeback) or decrement before with writeback.
    if p == u || cp < 10 {
        return undef(ctx);
    }
    let dbl = cp == 11;
    let first = if dbl { vd(w) } else { sd(w) };
    let mut count = if dbl { imm8 >> 1 } else { imm8 };
    // An empty or overlong list is unpredictable; LLVM makes it one register, or cuts it at the last one.
    if count == 0 {
        count = 1;
    } else if first + count > 32 {
        count = 32 - first;
    }
    let mut regs = List::new(if dbl { Bank::D } else { Bank::S });
    for i in 0..count {
        regs.push(first + i);
    }
    let regs = Op::List(regs);
    let flags = if load { f::LOAD } else { f::STORE };
    let bytes = if dbl { 8 } else { 4 };
    let mode = if p != 0 { "db" } else { "ia" };
    let base = reg(r(rn), wb != 0);
    // An odd word count with doubles is the old FLDMX/FSTMX form, which reaches d0-d15 only.
    if dbl && imm8 & 1 != 0 {
        if bit(w, 22) != 0 {
            return undef(ctx);
        }
        let mut m = Mn::from(if load { "fldm" } else { "fstm" });
        m.push(mode);
        m.push("x");
        return mk(ctx, &m, "", &[base, regs], flags, true).bytes(bytes);
    }
    // vpush/vpop: sp with writeback, decrementing for stores and incrementing for loads.
    if rn == 13 && wb != 0 && (if load { p == 0 } else { p != 0 }) {
        return mk(ctx, if load { "vpop" } else { "vpush" }, "", &[regs], flags, true).bytes(bytes);
    }
    let mut m = Mn::from(if load { "vldm" } else { "vstm" });
    m.push(mode);
    mk(ctx, &m, "", &[base, regs], flags, true).bytes(bytes)
}

/* ------------------------------------------------------------------ *
 * The conditional space: coprocessors 8-11 with cond != 1111
 * ------------------------------------------------------------------ */

/// A32 cond 110x/1110 with bits 11-8 = 10xx, or the same T32 word under an IT condition.
pub fn vfp(w: u32, ctx: &Ctx) -> Insn {
    let cp = bits(w, 11, 8);
    if bit(w, 25) != 0 {
        if cp == 8 {
            return undef(ctx);
        }
        return if bit(w, 4) != 0 { transfer(w, ctx, cp) } else { data_processing(w, ctx, cp) };
    }
    if (bits(w, 24, 21) & 0b1101) == 0b0000 {
        // P = U = W = 0: 64-bit transfers when bit 22 is set, nothing otherwise.
        return if bit(w, 22) != 0 { transfer64(w, ctx, cp) } else { undef(ctx) };
    }
    load_store(w, ctx, cp)
}

/* ------------------------------------------------------------------ *
 * Armv8 additions: 1111 1110 with coprocessor 9, 10 or 11
 * ------------------------------------------------------------------ */

const VSEL: [&str; 4] = ["vseleq", "vselvs", "vselge", "vselgt"];
const VRINT8: [&str; 4] = ["vrinta", "vrintn", "vrintp", "vrintm"];
const VCVT8: [&str; 4] = ["vcvta", "vcvtn", "vcvtp", "vcvtm"];

pub fn fp_v8(w: u32, ctx: &Ctx) -> Insn {
    let cp = bits(w, 11, 8);
    if bit(w, 4) != 0 || cp == 8 {
        return undef(ctx);
    }
    let dbl = cp == 11;
    let dt = fdt(cp);
    #[allow(non_snake_case)]
    let Rd = if dbl { D(vd(w)) } else { S(sd(w)) };
    #[allow(non_snake_case)]
    let Rm = if dbl { D(vm(w)) } else { S(sm(w)) };
    if bit(w, 23) == 0 {
        if bit(w, 6) != 0 {
            return undef(ctx);
        }
        return mk(ctx, VSEL[bits(w, 21, 20) as usize], dt, &[Rd, if dbl { D(vn(w)) } else { S(sn(w)) }, Rm], f::READS_FLAGS, false);
    }
    let opc = bits(w, 21, 20);
    if opc == 0 {
        return mk(ctx, if bit(w, 6) != 0 { "vminnm" } else { "vmaxnm" }, dt, &[Rd, if dbl { D(vn(w)) } else { S(sn(w)) }, Rm], 0, false);
    }
    if opc != 3 || bit(w, 6) == 0 {
        return undef(ctx);
    }
    let opc2 = bits(w, 19, 16);
    if opc2 == 0 {
        if cp != 10 {
            return undef(ctx);
        }
        return mk(ctx, if bit(w, 7) != 0 { "vins" } else { "vmovx" }, "f16", &[Rd, Rm], 0, false);
    }
    if opc2 >> 2 == 2 {
        if bit(w, 7) != 0 {
            return undef(ctx);
        }
        return mk(ctx, VRINT8[(opc2 & 3) as usize], dt, &[Rd, Rm], 0, false);
    }
    if opc2 >> 2 == 3 {
        return mk(ctx, VCVT8[(opc2 & 3) as usize], &dt_pair(if bit(w, 7) != 0 { "s32" } else { "u32" }, dt), &[S(sd(w)), Rm], 0, false);
    }
    undef(ctx)
}
