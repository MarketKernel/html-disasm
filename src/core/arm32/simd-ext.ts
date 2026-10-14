/**
 * The Armv8.2-8.6 SIMD additions that live in the unconditional coprocessor
 * space, the same in A32 and T32: complex arithmetic (vcmla, vcadd), dot
 * products (vsdot, vudot, vusdot, vsudot, vdot.bf16), half-precision
 * multiply-long (vfmal, vfmsl), BF16 multiply-add (vfmab, vfmat) and the
 * matrix multiplies (vsmmla, vummla, vusmmla, vmmla.bf16).
 *
 * 1111 110x holds the vector forms, 1111 1110 the by-element ones; bits 11-8
 * are 1000 (complex, vfmal, bf16 multiply-add), 1100 (matrix multiplies) or
 * 1101 (dot products). None of them can be conditional.
 */

import { immText, type Insn, type Op } from './types';
import { bit, bits, type Ctx, D, mk, Q, S, undef, V, vd, vm, vn } from './simd-common';

const idx = (reg: number, index: number): Op => ({ k: 'reg', r: `d${reg}[${index}]` });
const sidx = (reg: number, index: number): Op => ({ k: 'reg', r: `s${reg}[${index}]` });
const rot = (degrees: number): Op => immText(degrees, `#${degrees}`);

/** Q forms need even register numbers throughout. */
const evenQ = (q: number, ...regs: number[]): boolean => !q || regs.every((n) => !(n & 1));

/** 1111 110x: three vector registers. */
function vector(w: number, ctx: Ctx): Insn {
  const cp = bits(w, 11, 8);
  const q = bit(w, 6);
  const d = vd(w);
  const n = vn(w);
  const m = vm(w);
  const op4 = bit(w, 4);
  const top = bits(w, 24, 23);
  const op21 = bits(w, 21, 20);
  const np = (name: string, dt: string, ops: Op[]): Insn => mk(ctx, name, dt, ops, 0, false);
  if (cp === 8) {
    if (!op4) {
      if (!evenQ(q, d, n, m)) return undef(ctx);
      const dt = op21 & 1 ? 'f32' : 'f16';
      // vcmla: bit 21 set, bits 24-23 the rotation; vcadd: bit 21 clear, bit 23 set, bit 24 the rotation.
      if (op21 & 2) return np('vcmla', dt, [V(d, q), V(n, q), V(m, q), rot(top * 90)]);
      if (top & 1) return np('vcadd', dt, [V(d, q), V(n, q), V(m, q), rot(top & 2 ? 270 : 90)]);
      return undef(ctx);
    }
    if (op21 === 2 && top < 2) {
      // vfmal/vfmsl: Q forms widen D to Q, the others S to D.
      const name = top ? 'vfmsl' : 'vfmal';
      if (q) return d & 1 ? undef(ctx) : np(name, 'f16', [Q(d), D(n), D(m)]);
      return np(name, 'f16', [D(d), S((bits(w, 19, 16) << 1) | bit(w, 7)), S((bits(w, 3, 0) << 1) | bit(w, 5))]);
    }
    if (op21 === 3 && top === 0) {
      if ((d | n | m) & 1) return undef(ctx);
      return np(q ? 'vfmat' : 'vfmab', 'bf16', [Q(d), Q(n), Q(m)]);
    }
    return undef(ctx);
  }
  if (bit(w, 24)) return undef(ctx);
  const b = bit(w, 23);
  if (cp === 12) {
    // Matrix multiplies, Q registers only.
    if (!q || (d | n | m) & 1) return undef(ctx);
    if (op21 === 2) {
      if (b) return op4 ? undef(ctx) : np('vusmmla', 's8', [Q(d), Q(n), Q(m)]);
      return np(op4 ? 'vummla' : 'vsmmla', op4 ? 'u8' : 's8', [Q(d), Q(n), Q(m)]);
    }
    if (op21 === 0 && !b && !op4) return np('vmmla', 'bf16', [Q(d), Q(n), Q(m)]);
    return undef(ctx);
  }
  if (cp === 13) {
    if (!evenQ(q, d, n, m)) return undef(ctx);
    const ops = [V(d, q), V(n, q), V(m, q)];
    if (op21 === 2) {
      if (b) return op4 ? undef(ctx) : np('vusdot', 's8', ops);
      return np(op4 ? 'vudot' : 'vsdot', op4 ? 'u8' : 's8', ops);
    }
    if (op21 === 0 && !b && !op4) return np('vdot', 'bf16', ops);
    return undef(ctx);
  }
  return undef(ctx);
}

/** 1111 1110: by-element forms. */
function element(w: number, ctx: Ctx): Insn {
  const cp = bits(w, 11, 8);
  const q = bit(w, 6);
  const d = vd(w);
  const n = vn(w);
  const op4 = bit(w, 4);
  const b = bit(w, 23);
  const op21 = bits(w, 21, 20);
  const mlo = bits(w, 3, 0);
  const np = (name: string, dt: string, ops: Op[]): Insn => mk(ctx, name, dt, ops, 0, false);
  if (cp === 8) {
    if (!op4) {
      // vcmla by element: f16 indexes a pair of halves in d0-d15, f32 has only element 0 of any D register.
      if (!evenQ(q, d, n)) return undef(ctx);
      if (b) return np('vcmla', 'f32', [V(d, q), V(n, q), idx(vm(w), 0), rot(op21 * 90)]);
      return np('vcmla', 'f16', [V(d, q), V(n, q), idx(mlo, bit(w, 5)), rot(op21 * 90)]);
    }
    if (b) return undef(ctx);
    if (op21 < 2) {
      const name = op21 ? 'vfmsl' : 'vfmal';
      if (q) {
        if (d & 1) return undef(ctx);
        return np(name, 'f16', [Q(d), D(n), idx(mlo & 7, (bit(w, 5) << 1) | bit(w, 3))]);
      }
      return np(name, 'f16', [D(d), S((bits(w, 19, 16) << 1) | bit(w, 7)), sidx(((mlo & 7) << 1) | bit(w, 5), bit(w, 3))]);
    }
    if (op21 === 3) {
      if ((d | n) & 1) return undef(ctx);
      return np(q ? 'vfmat' : 'vfmab', 'bf16', [Q(d), Q(n), idx(mlo & 7, (bit(w, 5) << 1) | bit(w, 3))]);
    }
    return undef(ctx);
  }
  if (cp === 13) {
    if (!evenQ(q, d, n)) return undef(ctx);
    const ops = [V(d, q), V(n, q), idx(mlo, bit(w, 5))];
    if (op21 === 2 && !b) return np(op4 ? 'vudot' : 'vsdot', op4 ? 'u8' : 's8', ops);
    if (op21 === 0 && b) return np(op4 ? 'vsudot' : 'vusdot', op4 ? 'u8' : 's8', ops);
    if (op21 === 0 && !b && !op4) return np('vdot', 'bf16', ops);
    return undef(ctx);
  }
  return undef(ctx);
}

/** An unconditional word 1111 110x or 1111 1110 with bits 11-8 = 1000, 1100 or 1101. */
export function simdExtension(w: number, ctx: Ctx): Insn {
  return bit(w, 25) ? element(w, ctx) : vector(w, ctx);
}
