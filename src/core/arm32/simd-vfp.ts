/**
 * Floating point in the coprocessor space (coprocessors 9, 10 and 11: half,
 * single and double precision): the data-processing instructions, moves
 * between core and floating-point registers, vmrs/vmsr, vldr/vstr and
 * vldm/vstm, and the unconditional Armv8 additions (vsel, vmaxnm, vrinta,
 * vcvta, vins, vmovx). A32 and T32 encode them alike; Thumb takes the
 * condition from the IT block instead of bits 31-28.
 */

import { F, immText, list, r, type Insn, type Op } from './types';
import { bit, bits, type Ctx, D, dname, fpImmOp, id, mk, R, S, sd, sm, sn, undef, V, vd, vm, vn } from './simd-common';

/* ------------------------------------------------------------------ *
 * Data processing
 * ------------------------------------------------------------------ */

const THREE = [
  ['vmla', 'vmls'],
  ['vnmls', 'vnmla'],
  ['vmul', 'vnmul'],
  ['vadd', 'vsub'],
  ['vdiv', ''],
  ['vfnms', 'vfnma'],
  ['vfma', 'vfms'],
];

/** cp: 9 half, 10 single, 11 double. */
const fdt = (cp: number): string => (cp === 11 ? 'f64' : cp === 10 ? 'f32' : 'f16');

function dataProcessing(w: number, ctx: Ctx, cp: number): Insn {
  const dbl = cp === 11;
  const dt = fdt(cp);
  const opc1 = (bit(w, 23) << 2) | bits(w, 21, 20);
  const op6 = bit(w, 6);
  const Rd = dbl ? D(vd(w)) : S(sd(w));
  const Rm = dbl ? D(vm(w)) : S(sm(w));
  if (opc1 < 7) {
    const name = THREE[opc1]![op6]!;
    if (!name) return undef(ctx);
    return mk(ctx, name, dt, [Rd, dbl ? D(vn(w)) : S(sn(w)), Rm]);
  }
  if (!op6) {
    // vmov.f32 s0, #1.000000e+00: the immediate's low bits fill 3-0, bits 7-4 are zero.
    if (bits(w, 7, 4)) return undef(ctx);
    return mk(ctx, 'vmov', dt, [Rd, fpImmOp((bits(w, 19, 16) << 4) | bits(w, 3, 0))]);
  }
  const opc2 = bits(w, 19, 16);
  const o7 = bit(w, 7);
  const sdst = S(sd(w));
  const ssrc = S(sm(w));
  switch (opc2) {
    case 0:
      if (!o7 && cp === 9) return undef(ctx);
      return mk(ctx, o7 ? 'vabs' : 'vmov', dt, [Rd, Rm]);
    case 1:
      return mk(ctx, o7 ? 'vsqrt' : 'vneg', dt, [Rd, Rm]);
    case 2:
      // Half to single or double: vcvtb.f32.f16 s0, s1.
      if (cp === 9) return undef(ctx);
      return mk(ctx, o7 ? 'vcvtt' : 'vcvtb', `${dt}.f16`, [Rd, ssrc]);
    case 3:
      if (cp === 9) return mk(ctx, o7 ? 'vcvtt' : 'vcvtb', 'bf16.f32', [sdst, ssrc]);
      return mk(ctx, o7 ? 'vcvtt' : 'vcvtb', `f16.${dt}`, [sdst, Rm]);
    case 4:
      return mk(ctx, o7 ? 'vcmpe' : 'vcmp', dt, [Rd, Rm]);
    case 5:
      if (bit(w, 5) || bits(w, 3, 0)) return undef(ctx);
      return mk(ctx, o7 ? 'vcmpe' : 'vcmp', dt, [Rd, immText(0, '#0')]);
    case 6:
      return mk(ctx, o7 ? 'vrintz' : 'vrintr', dt, [Rd, Rm]);
    case 7:
      if (!o7) return mk(ctx, 'vrintx', dt, [Rd, Rm]);
      if (cp === 10) return mk(ctx, 'vcvt', 'f64.f32', [D(vd(w)), ssrc]);
      if (cp === 11) return mk(ctx, 'vcvt', 'f32.f64', [sdst, D(vm(w))]);
      return undef(ctx);
    case 8:
      return mk(ctx, 'vcvt', `${dt}.${o7 ? 's' : 'u'}32`, [Rd, ssrc]);
    case 9:
      if (cp !== 11 || !o7) return undef(ctx);
      return mk(ctx, 'vjcvt', 's32.f64', [sdst, D(vm(w))]);
    case 10:
    case 11:
    case 14:
    case 15: {
      // Fixed point: the register is both source and destination, the fraction bits count down from 16 or 32.
      const size = o7 ? 32 : 16;
      const fbits = size - ((bits(w, 3, 0) << 1) | bit(w, 5));
      const fixed = `${opc2 & 1 ? 'u' : 's'}${size}`;
      const dts = opc2 & 4 ? `${fixed}.${dt}` : `${dt}.${fixed}`;
      return mk(ctx, 'vcvt', dts, [Rd, Rd, id(fbits)]);
    }
    case 12:
    case 13:
      return mk(ctx, o7 ? 'vcvt' : 'vcvtr', `${opc2 & 1 ? 's' : 'u'}32.${dt}`, [sdst, Rm]);
    default:
      return undef(ctx);
  }
}

/* ------------------------------------------------------------------ *
 * Transfers between core and floating-point registers
 * ------------------------------------------------------------------ */

const SYSREG: (string | undefined)[] = ['fpsid', 'fpscr', undefined, undefined, undefined, 'mvfr2', 'mvfr1', 'mvfr0', 'fpexc', 'fpinst', 'fpinst2'];

function transfer(w: number, ctx: Ctx, cp: number): Insn {
  const load = bit(w, 20);
  const rt = bits(w, 15, 12);
  if (cp === 11) {
    if (bits(w, 3, 0)) return undef(ctx);
    const dn = (bit(w, 7) << 4) | bits(w, 19, 16);
    if (!load && bit(w, 23)) {
      // vdup.32 q0, r0: B (bit 22) and E (bit 5) give the size.
      if (bit(w, 6)) return undef(ctx);
      const be = (bit(w, 22) << 1) | bit(w, 5);
      if (be === 3) return undef(ctx);
      const q = bit(w, 21);
      if (q && dn & 1) return undef(ctx);
      return mk(ctx, 'vdup', ['32', '16', '8'][be]!, [V(dn, q), R(rt)]);
    }
    const opc = (bits(w, 22, 21) << 2) | bits(w, 6, 5);
    let size: number;
    let index: number;
    if (opc & 8) {
      size = 8;
      index = opc & 7;
    } else if (opc & 1) {
      size = 16;
      index = opc >> 1;
    } else if (!(opc & 2)) {
      size = 32;
      index = opc >> 2;
    } else return undef(ctx);
    const scalar: Op = { k: 'reg', r: `d${dn}[${index}]` };
    if (!load) return mk(ctx, 'vmov', `${size}`, [scalar, R(rt)]);
    const u = bit(w, 23);
    if (size === 32 && u) return undef(ctx);
    return mk(ctx, 'vmov', size === 32 ? '32' : `${u ? 'u' : 's'}${size}`, [R(rt), scalar]);
  }
  if (cp === 8) return undef(ctx);
  const opc1 = bits(w, 23, 21);
  if (opc1 === 0) {
    if (bits(w, 6, 5) || bits(w, 3, 0)) return undef(ctx);
    const s = S(sn(w));
    const dt = cp === 9 ? 'f16' : '';
    return load ? mk(ctx, 'vmov', dt, [R(rt), s]) : mk(ctx, 'vmov', dt, [s, R(rt)]);
  }
  if (opc1 !== 7 || cp !== 10) return undef(ctx);
  const reg = bits(w, 19, 16);
  const sys = SYSREG[reg];
  if (!sys) return undef(ctx);
  if (load) {
    if (rt === 15 && sys === 'fpscr') {
      // vmrs APSR_nzcv, fpscr copies the comparison flags to the integer ones.
      return mk(ctx, 'vmrs', '', [{ k: 'reg', r: 'APSR_nzcv' }, { k: 'reg', r: 'fpscr' }], F.SETS_FLAGS);
    }
    return mk(ctx, 'vmrs', '', [R(rt), { k: 'reg', r: sys }]);
  }
  // The media and VFP feature registers (mvfr0-2) can only be read.
  if (reg >= 5 && reg <= 7) return undef(ctx);
  return mk(ctx, 'vmsr', '', [{ k: 'reg', r: sys }, R(rt)]);
}

/** vmov d0, r0, r1 and vmov s0, s1, r0, r1, either way. */
function transfer64(w: number, ctx: Ctx, cp: number): Insn {
  if (bits(w, 7, 6) || !bit(w, 4) || (cp !== 10 && cp !== 11)) return undef(ctx);
  const load = bit(w, 20);
  const rt = R(bits(w, 15, 12));
  const rt2 = R(bits(w, 19, 16));
  if (cp === 11) {
    const dm = D(vm(w));
    return load ? mk(ctx, 'vmov', '', [rt, rt2, dm]) : mk(ctx, 'vmov', '', [dm, rt, rt2]);
  }
  const m = sm(w);
  if (m === 31) return undef(ctx);
  return load ? mk(ctx, 'vmov', '', [rt, rt2, S(m), S(m + 1)]) : mk(ctx, 'vmov', '', [S(m), S(m + 1), rt, rt2]);
}

/* ------------------------------------------------------------------ *
 * Loads and stores
 * ------------------------------------------------------------------ */

function loadStore(w: number, ctx: Ctx, cp: number): Insn {
  const p = bit(w, 24);
  const u = bit(w, 23);
  const wb = bit(w, 21);
  const load = bit(w, 20);
  const rn = bits(w, 19, 16);
  const imm8 = bits(w, 7, 0);
  if (p && !wb) {
    // vldr/vstr: the offset counts words (halfwords for .16), and #-0 still prints.
    if (cp === 8) return undef(ctx);
    const scale = cp === 9 ? 2 : 4;
    const off = imm8 * scale * (u ? 1 : -1);
    const base = r(rn);
    const t = imm8 || !u ? `[${base}, #${u ? '' : '-'}${imm8 * scale}]` : `[${base}]`;
    const mem: Op = { k: 'mem', base, t, off, mode: 'off' };
    const reg = cp === 11 ? D(vd(w)) : S(sd(w));
    const extra: Partial<Insn> = { bytes: cp === 11 ? 8 : cp === 10 ? 4 : 2 };
    if (rn === 15) extra.target = ((ctx.thumb ? (ctx.pc + 4) & ~3 : ctx.pc + 8) + off) >>> 0;
    return mk(ctx, load ? 'vldr' : 'vstr', cp === 9 ? '16' : '', [reg, mem], load ? F.LOAD : F.STORE, true, extra);
  }
  // vldm/vstm: increment after (with or without writeback) or decrement before with writeback.
  if (p === u || cp < 10) return undef(ctx);
  const dbl = cp === 11;
  const first = dbl ? vd(w) : sd(w);
  let count = dbl ? imm8 >> 1 : imm8;
  // An empty or overlong list is unpredictable; LLVM makes it one register, or cuts it at the last one.
  if (count === 0) count = 1;
  else if (first + count > 32) count = 32 - first;
  const regs: string[] = [];
  for (let i = 0; i < count; i++) regs.push(dbl ? dname(first + i) : `s${first + i}`);
  const flags = load ? F.LOAD : F.STORE;
  const extra: Partial<Insn> = { bytes: dbl ? 8 : 4 };
  const mode = p ? 'db' : 'ia';
  const base: Op = wb ? { k: 'reg', r: r(rn), wb: true } : R(rn);
  // An odd word count with doubles is the old FLDMX/FSTMX form, which reaches d0-d15 only.
  if (dbl && imm8 & 1) return bit(w, 22) ? undef(ctx) : mk(ctx, `${load ? 'fldm' : 'fstm'}${mode}x`, '', [base, list(regs)], flags, true, extra);
  // vpush/vpop: sp with writeback, decrementing for stores and incrementing for loads.
  if (rn === 13 && wb && (load ? !p : p)) return mk(ctx, load ? 'vpop' : 'vpush', '', [list(regs)], flags, true, extra);
  return mk(ctx, `${load ? 'vldm' : 'vstm'}${mode}`, '', [base, list(regs)], flags, true, extra);
}

/* ------------------------------------------------------------------ *
 * The conditional space: coprocessors 8-11 with cond != 1111
 * ------------------------------------------------------------------ */

/** A32 cond 110x/1110 with bits 11-8 = 10xx, or the same T32 word under an IT condition. */
export function vfp(w: number, ctx: Ctx): Insn {
  const cp = bits(w, 11, 8);
  if (bit(w, 25)) {
    if (cp === 8) return undef(ctx);
    return bit(w, 4) ? transfer(w, ctx, cp) : dataProcessing(w, ctx, cp);
  }
  if ((bits(w, 24, 21) & 0b1101) === 0b0000) {
    // P = U = W = 0: 64-bit transfers when bit 22 is set, nothing otherwise.
    return bit(w, 22) ? transfer64(w, ctx, cp) : undef(ctx);
  }
  return loadStore(w, ctx, cp);
}

/* ------------------------------------------------------------------ *
 * Armv8 additions: 1111 1110 with coprocessor 9, 10 or 11
 * ------------------------------------------------------------------ */

const VSEL = ['vseleq', 'vselvs', 'vselge', 'vselgt'];
const VRINT8 = ['vrinta', 'vrintn', 'vrintp', 'vrintm'];
const VCVT8 = ['vcvta', 'vcvtn', 'vcvtp', 'vcvtm'];

export function fpV8(w: number, ctx: Ctx): Insn {
  const cp = bits(w, 11, 8);
  if (bit(w, 4) || cp === 8) return undef(ctx);
  const dbl = cp === 11;
  const dt = fdt(cp);
  const Rd = dbl ? D(vd(w)) : S(sd(w));
  const Rm = dbl ? D(vm(w)) : S(sm(w));
  if (!bit(w, 23)) {
    if (bit(w, 6)) return undef(ctx);
    return mk(ctx, VSEL[bits(w, 21, 20)]!, dt, [Rd, dbl ? D(vn(w)) : S(sn(w)), Rm], F.READS_FLAGS, false);
  }
  const opc = bits(w, 21, 20);
  if (opc === 0) return mk(ctx, bit(w, 6) ? 'vminnm' : 'vmaxnm', dt, [Rd, dbl ? D(vn(w)) : S(sn(w)), Rm], 0, false);
  if (opc !== 3 || !bit(w, 6)) return undef(ctx);
  const opc2 = bits(w, 19, 16);
  if (opc2 === 0) {
    if (cp !== 10) return undef(ctx);
    return mk(ctx, bit(w, 7) ? 'vins' : 'vmovx', 'f16', [Rd, Rm], 0, false);
  }
  if (opc2 >> 2 === 2) {
    if (bit(w, 7)) return undef(ctx);
    return mk(ctx, VRINT8[opc2 & 3]!, dt, [Rd, Rm], 0, false);
  }
  if (opc2 >> 2 === 3) return mk(ctx, VCVT8[opc2 & 3]!, `${bit(w, 7) ? 's' : 'u'}32.${dt}`, [S(sd(w)), Rm], 0, false);
  return undef(ctx);
}
