/**
 * Advanced SIMD data processing: the A32 space 1111 001U, which T32 encodes
 * as 111U 1111. Bit 23 splits it: three registers of the same length below,
 * everything else above — three registers of different lengths, two
 * registers and a scalar, shifts by an immediate, the modified immediates,
 * vext, the two-register operations, vtbl/vtbx and vdup of a scalar.
 *
 * Q forms name every register by its D number, so an odd one is not an
 * instruction; LLVM prints it as <unknown>, and so do we.
 */

import { hex, immText, type Insn, type Op } from './types';
import { bit, bits, type Ctx, D, dlist, fpImmOp, ih, mk, Q, undef, V, vd, vm, vn } from './simd-common';

const SU = (u: number, size: number): string => `${u ? 'u' : 's'}${8 << size}`;

/* ------------------------------------------------------------------ *
 * Three registers of the same length
 * ------------------------------------------------------------------ */

/**
 * An entry of the three-register table. Its kind says how the data type is
 * formed:
 *   su, s, i, p   that prefix and the element size (vhadd.u16, vqdmulh.s32,
 *                 vadd.i64, vmul.p8; su takes s or u from U), sizes in `sizes`
 *   n             the element size alone (vtst.8)
 *   f             floating point: bit 21 picks one of the two operations in
 *                 `alt`, bit 20 f32 or f16
 *   l             the logical operations: bits 21-20 pick one of `alt`
 *   sha           SHA-1/SHA-256 (Q registers only): bits 21-20 pick one
 */
interface Same {
  m: string;
  k: 'su' | 's' | 'i' | 'p' | 'n' | 'f' | 'l' | 'sha';
  /** Allowed sizes as a bit mask (bit n for size n). */
  sizes?: number;
  alt?: string[];
  /** Pairwise integer operations exist for D registers only. */
  dOnly?: boolean;
  /** Shifts by a register take the shift from Vn and print Vd, Vm, Vn. */
  swap?: boolean;
  /** Armv8 additions that cannot be conditional, not even in an IT block. */
  np?: boolean;
}

const S012 = 0b0111;
const S0123 = 0b1111;
const S12 = 0b0110;

// Indexed by opc (bits 11-8) << 2 | o (bit 4) << 1 | U (bit 24).
const SAME: (Same | null)[] = [
  // 0000
  { m: 'vhadd', k: 'su', sizes: S012 }, { m: 'vhadd', k: 'su', sizes: S012 },
  { m: 'vqadd', k: 'su', sizes: S0123 }, { m: 'vqadd', k: 'su', sizes: S0123 },
  // 0001
  { m: 'vrhadd', k: 'su', sizes: S012 }, { m: 'vrhadd', k: 'su', sizes: S012 },
  { m: '', k: 'l', alt: ['vand', 'vbic', 'vorr', 'vorn'] }, { m: '', k: 'l', alt: ['veor', 'vbsl', 'vbit', 'vbif'] },
  // 0010
  { m: 'vhsub', k: 'su', sizes: S012 }, { m: 'vhsub', k: 'su', sizes: S012 },
  { m: 'vqsub', k: 'su', sizes: S0123 }, { m: 'vqsub', k: 'su', sizes: S0123 },
  // 0011
  { m: 'vcgt', k: 'su', sizes: S012 }, { m: 'vcgt', k: 'su', sizes: S012 },
  { m: 'vcge', k: 'su', sizes: S012 }, { m: 'vcge', k: 'su', sizes: S012 },
  // 0100
  { m: 'vshl', k: 'su', sizes: S0123, swap: true }, { m: 'vshl', k: 'su', sizes: S0123, swap: true },
  { m: 'vqshl', k: 'su', sizes: S0123, swap: true }, { m: 'vqshl', k: 'su', sizes: S0123, swap: true },
  // 0101
  { m: 'vrshl', k: 'su', sizes: S0123, swap: true }, { m: 'vrshl', k: 'su', sizes: S0123, swap: true },
  { m: 'vqrshl', k: 'su', sizes: S0123, swap: true }, { m: 'vqrshl', k: 'su', sizes: S0123, swap: true },
  // 0110
  { m: 'vmax', k: 'su', sizes: S012 }, { m: 'vmax', k: 'su', sizes: S012 },
  { m: 'vmin', k: 'su', sizes: S012 }, { m: 'vmin', k: 'su', sizes: S012 },
  // 0111
  { m: 'vabd', k: 'su', sizes: S012 }, { m: 'vabd', k: 'su', sizes: S012 },
  { m: 'vaba', k: 'su', sizes: S012 }, { m: 'vaba', k: 'su', sizes: S012 },
  // 1000
  { m: 'vadd', k: 'i', sizes: S0123 }, { m: 'vsub', k: 'i', sizes: S0123 },
  { m: 'vtst', k: 'n', sizes: S012 }, { m: 'vceq', k: 'i', sizes: S012 },
  // 1001
  { m: 'vmla', k: 'i', sizes: S012 }, { m: 'vmls', k: 'i', sizes: S012 },
  { m: 'vmul', k: 'i', sizes: S012 }, { m: 'vmul', k: 'p', sizes: 1 },
  // 1010
  { m: 'vpmax', k: 'su', sizes: S012, dOnly: true }, { m: 'vpmax', k: 'su', sizes: S012, dOnly: true },
  { m: 'vpmin', k: 'su', sizes: S012, dOnly: true }, { m: 'vpmin', k: 'su', sizes: S012, dOnly: true },
  // 1011
  { m: 'vqdmulh', k: 's', sizes: S12 }, { m: 'vqrdmulh', k: 's', sizes: S12 },
  { m: 'vpadd', k: 'i', sizes: S012, dOnly: true }, { m: 'vqrdmlah', k: 's', sizes: S12 },
  // 1100
  { m: '', k: 'sha', alt: ['sha1c', 'sha1p', 'sha1m', 'sha1su0'], np: true },
  { m: '', k: 'sha', alt: ['sha256h', 'sha256h2', 'sha256su1', ''], np: true },
  { m: '', k: 'f', alt: ['vfma', 'vfms'] }, { m: 'vqrdmlsh', k: 's', sizes: S12 },
  // 1101
  { m: '', k: 'f', alt: ['vadd', 'vsub'] }, { m: '', k: 'f', alt: ['vpadd', 'vabd'] },
  { m: '', k: 'f', alt: ['vmla', 'vmls'] }, { m: '', k: 'f', alt: ['vmul', ''] },
  // 1110
  { m: '', k: 'f', alt: ['vceq', ''] }, { m: '', k: 'f', alt: ['vcge', 'vcgt'] },
  null, { m: '', k: 'f', alt: ['vacge', 'vacgt'] },
  // 1111
  { m: '', k: 'f', alt: ['vmax', 'vmin'] }, { m: '', k: 'f', alt: ['vpmax', 'vpmin'] },
  { m: '', k: 'f', alt: ['vrecps', 'vrsqrts'] }, { m: '', k: 'f', alt: ['vmaxnm', 'vminnm'], np: true },
];

/** Floating-point operations that work pairwise and so exist for D registers only. */
const PAIRWISE_F = new Set(['vpadd', 'vpmax', 'vpmin']);

function threeSame(w: number, ctx: Ctx): Insn {
  const u = bit(w, 24);
  const e = SAME[(bits(w, 11, 8) << 2) | (bit(w, 4) << 1) | u];
  if (!e) return undef(ctx);
  const size = bits(w, 21, 20);
  const q = bit(w, 6);
  const d = vd(w);
  const n = vn(w);
  const m = vm(w);
  if (q && ((d | n | m) & 1)) return undef(ctx);
  let name = e.m;
  let dt: string;
  switch (e.k) {
    case 'l':
      name = e.alt![size]!;
      dt = '';
      break;
    case 'f':
      name = e.alt![size >> 1]!;
      if (!name || (q && PAIRWISE_F.has(name))) return undef(ctx);
      dt = size & 1 ? 'f16' : 'f32';
      break;
    case 'sha':
      name = e.alt![size]!;
      if (!name || !q) return undef(ctx);
      dt = '32';
      break;
    default:
      if (!((e.sizes! >> size) & 1) || (e.dOnly && q)) return undef(ctx);
      dt = (e.k === 'su' ? (u ? 'u' : 's') : e.k === 'n' ? '' : e.k) + (8 << size);
  }
  const ops = e.swap ? [V(d, q), V(m, q), V(n, q)] : [V(d, q), V(n, q), V(m, q)];
  return mk(ctx, name, dt, ops, 0, !e.np);
}

/* ------------------------------------------------------------------ *
 * Three registers of different lengths
 * ------------------------------------------------------------------ */

/** Shapes: L = Qd, Dn, Dm (long); W = Qd, Qn, Dm (wide); N = Dd, Qn, Qm (narrow). */
const DIFF: ([string, string, 'L' | 'W' | 'N', 'su' | 's' | 'i'] | null)[] = [
  ['vaddl', 'vaddl', 'L', 'su'],
  ['vaddw', 'vaddw', 'W', 'su'],
  ['vsubl', 'vsubl', 'L', 'su'],
  ['vsubw', 'vsubw', 'W', 'su'],
  ['vaddhn', 'vraddhn', 'N', 'i'],
  ['vabal', 'vabal', 'L', 'su'],
  ['vsubhn', 'vrsubhn', 'N', 'i'],
  ['vabdl', 'vabdl', 'L', 'su'],
  ['vmlal', 'vmlal', 'L', 'su'],
  ['vqdmlal', '', 'L', 's'],
  ['vmlsl', 'vmlsl', 'L', 'su'],
  ['vqdmlsl', '', 'L', 's'],
  ['vmull', 'vmull', 'L', 'su'],
  ['vqdmull', '', 'L', 's'],
  null, // 1110: vmull.p8 / vmull.p64, below
  null,
];

function threeDiff(w: number, ctx: Ctx): Insn {
  const u = bit(w, 24);
  const opc = bits(w, 11, 8);
  const size = bits(w, 21, 20);
  const d = vd(w);
  const n = vn(w);
  const m = vm(w);
  if (opc === 14) {
    if (u || d & 1) return undef(ctx);
    if (size === 0) return mk(ctx, 'vmull', 'p8', [Q(d), D(n), D(m)]);
    if (size === 2) return mk(ctx, 'vmull', 'p64', [Q(d), D(n), D(m)], 0, false);
    return undef(ctx);
  }
  const e = DIFF[opc];
  if (!e) return undef(ctx);
  const name = e[u];
  if (!name) return undef(ctx);
  let dt: string;
  if (e[3] === 'su') dt = SU(u, size);
  else if (e[3] === 's') {
    if (size === 0) return undef(ctx);
    dt = `s${8 << size}`;
  } else dt = `i${16 << size}`;
  switch (e[2]) {
    case 'L':
      if (d & 1) return undef(ctx);
      return mk(ctx, name, dt, [Q(d), D(n), D(m)]);
    case 'W':
      if ((d | n) & 1) return undef(ctx);
      return mk(ctx, name, dt, [Q(d), Q(n), D(m)]);
    default:
      if ((n | m) & 1) return undef(ctx);
      return mk(ctx, name, dt, [D(d), Q(n), Q(m)]);
  }
}

/* ------------------------------------------------------------------ *
 * Two registers and a scalar
 * ------------------------------------------------------------------ */

/**
 * By bits 11-8. qi, qf and qs keep the vector length (Q in bit 24) with an
 * integer, floating-point or signed type; l widens with U in bit 24; sl
 * widens and is signed only (bit 24 clear).
 */
const SCALAR: [string, 'qi' | 'qf' | 'l' | 'sl' | 'qs'][] = [
  ['vmla', 'qi'], ['vmla', 'qf'], ['vmlal', 'l'], ['vqdmlal', 'sl'],
  ['vmls', 'qi'], ['vmls', 'qf'], ['vmlsl', 'l'], ['vqdmlsl', 'sl'],
  ['vmul', 'qi'], ['vmul', 'qf'], ['vmull', 'l'], ['vqdmull', 'sl'],
  ['vqdmulh', 'qs'], ['vqrdmulh', 'qs'], ['vqrdmlah', 'qs'], ['vqrdmlsh', 'qs'],
];

function scalar(w: number, ctx: Ctx): Insn {
  const top = bit(w, 24);
  const opc = bits(w, 11, 8);
  const size = bits(w, 21, 20);
  if (size === 0) return undef(ctx);
  const [name, kind] = SCALAR[opc]!;
  const d = vd(w);
  const n = vn(w);
  const mfield = bits(w, 3, 0);
  // The scalar: d0-d7 with a 2-bit index for 16-bit elements, d0-d15 with a 1-bit index for 32-bit ones.
  const scalarText = size === 1 ? `d${mfield & 7}[${(bit(w, 5) << 1) | (mfield >> 3)}]` : `d${mfield}[${bit(w, 5)}]`;
  const sc: Op = { k: 'reg', r: scalarText };
  switch (kind) {
    case 'qi':
    case 'qf':
    case 'qs': {
      if (top && ((d | n) & 1)) return undef(ctx);
      const dt = kind === 'qi' ? `i${8 << size}` : kind === 'qf' ? (size === 1 ? 'f16' : 'f32') : `s${8 << size}`;
      return mk(ctx, name, dt, [V(d, top), V(n, top), sc]);
    }
    case 'l':
      if (d & 1) return undef(ctx);
      return mk(ctx, name, SU(top, size), [Q(d), D(n), sc]);
    default:
      if (top || d & 1) return undef(ctx);
      return mk(ctx, name, `s${8 << size}`, [Q(d), D(n), sc]);
  }
}

/* ------------------------------------------------------------------ *
 * Two registers and a shift amount
 * ------------------------------------------------------------------ */

function shiftImm(w: number, ctx: Ctx): Insn {
  const u = bit(w, 24);
  const opc = bits(w, 11, 8);
  const l = bit(w, 7);
  const q = bit(w, 6);
  const imm6 = bits(w, 21, 16);
  const imm = (l << 6) | imm6;
  // The element size: the highest set bit of L:imm6.
  const esize = l ? 64 : imm6 & 32 ? 32 : imm6 & 16 ? 16 : 8;
  const size = esize === 8 ? 0 : esize === 16 ? 1 : esize === 32 ? 2 : 3;
  const right = 2 * esize - imm;
  const left = imm - esize;
  const d = vd(w);
  const m = vm(w);
  const same = (name: string, dt: string, amount: number): Insn => {
    if (q && ((d | m) & 1)) return undef(ctx);
    return mk(ctx, name, dt, [V(d, q), V(m, q), ih(amount)]);
  };
  switch (opc) {
    case 0:
      return same('vshr', SU(u, size), right);
    case 1:
      return same('vsra', SU(u, size), right);
    case 2:
      return same('vrshr', SU(u, size), right);
    case 3:
      return same('vrsra', SU(u, size), right);
    case 4:
      return u ? same('vsri', `${esize}`, right) : undef(ctx);
    case 5:
      return u ? same('vsli', `${esize}`, left) : same('vshl', `i${esize}`, left);
    case 6:
      return u ? same('vqshlu', `s${esize}`, left) : undef(ctx);
    case 7:
      return same('vqshl', SU(u, size), left);
    case 8:
    case 9: {
      // Narrowing: the data type names the source elements, twice the size of the result's.
      if (l || m & 1) return undef(ctx);
      const src = esize * 2;
      let name: string;
      let dt: string;
      if (opc === 8) {
        if (u) {
          name = q ? 'vqrshrun' : 'vqshrun';
          dt = `s${src}`;
        } else {
          name = q ? 'vrshrn' : 'vshrn';
          dt = `i${src}`;
        }
      } else {
        name = q ? 'vqrshrn' : 'vqshrn';
        dt = `${u ? 'u' : 's'}${src}`;
      }
      return mk(ctx, name, dt, [D(d), Q(m), ih(right)]);
    }
    case 10:
      if (l || q || d & 1) return undef(ctx);
      if (left === 0) return mk(ctx, 'vmovl', SU(u, size), [Q(d), D(m)]);
      return mk(ctx, 'vshll', SU(u, size), [Q(d), D(m), ih(left)]);
    case 12:
    case 13:
    case 14:
    case 15: {
      // Fixed-point conversions; imm6 must leave a 32-bit element.
      if (l || !(imm6 & 32)) return undef(ctx);
      if (q && ((d | m) & 1)) return undef(ctx);
      const half = opc < 14;
      const fl = half ? 'f16' : 'f32';
      const it = `${u ? 'u' : 's'}${half ? 16 : 32}`;
      const dt = opc & 1 ? `${it}.${fl}` : `${fl}.${it}`;
      return mk(ctx, 'vcvt', dt, [V(d, q), V(m, q), ih(64 - imm6)]);
    }
    default:
      return undef(ctx);
  }
}

/* ------------------------------------------------------------------ *
 * One register and a modified immediate
 * ------------------------------------------------------------------ */

function modImm(w: number, ctx: Ctx): Insn {
  const op = bit(w, 5);
  const cmode = bits(w, 11, 8);
  const q = bit(w, 6);
  const d = vd(w);
  if (q && d & 1) return undef(ctx);
  const imm8 = (bit(w, 24) << 7) | (bits(w, 18, 16) << 4) | bits(w, 3, 0);
  const reg = V(d, q);
  if (cmode === 15) {
    if (op) return undef(ctx);
    return mk(ctx, 'vmov', 'f32', [reg, fpImmOp(imm8)]);
  }
  if (cmode === 14) {
    if (!op) return mk(ctx, 'vmov', 'i8', [reg, immText(imm8, `#${hex(imm8)}`)]);
    // vmov.i64: each bit of imm8 sets a byte of ones.
    let hi = 0;
    let lo = 0;
    for (let byte = 0; byte < 4; byte++) {
      if ((imm8 >> byte) & 1) lo |= 0xff << (8 * byte);
      if ((imm8 >> (byte + 4)) & 1) hi |= 0xff << (8 * byte);
    }
    const text = hi ? (hi >>> 0).toString(16) + (lo >>> 0).toString(16).padStart(8, '0') : (lo >>> 0).toString(16);
    return mk(ctx, 'vmov', 'i64', [reg, immText(imm8, `#0x${text}`)]);
  }
  let value: number;
  let esize: string;
  if ((cmode & 12) === 8) {
    value = imm8 << (8 * ((cmode >> 1) & 1));
    esize = 'i16';
  } else if ((cmode & 8) === 0) {
    value = (imm8 << (8 * ((cmode >> 1) & 3))) >>> 0;
    esize = 'i32';
  } else {
    // 110x: one byte with ones below it.
    const byteNum = 1 + (cmode & 1);
    value = ((imm8 << (8 * byteNum)) | (0xffff >> (8 * (2 - byteNum)))) >>> 0;
    esize = 'i32';
  }
  // Odd cmodes below 12 are vorr/vbic (they keep the register), the rest vmov/vmvn.
  const orr = cmode < 12 && cmode & 1;
  const name = orr ? (op ? 'vbic' : 'vorr') : op ? 'vmvn' : 'vmov';
  return mk(ctx, name, esize, [reg, immText(value, `#0x${value.toString(16)}`)]);
}

/* ------------------------------------------------------------------ *
 * Two registers, miscellaneous
 * ------------------------------------------------------------------ */

const CMP0 = ['vcgt', 'vcge', 'vceq', 'vcle', 'vclt'];
const VRINT = ['vrintn', 'vrintx', 'vrinta', 'vrintz', '', 'vrintm', '', 'vrintp'];
const VCVT_ROUND = ['vcvta', 'vcvtn', 'vcvtp', 'vcvtm'];

function twoMisc(w: number, ctx: Ctx): Insn {
  const size = bits(w, 19, 18);
  const a = bits(w, 17, 16);
  const b = bits(w, 10, 7);
  const q = bit(w, 6);
  const d = vd(w);
  const m = vm(w);
  const two = (name: string, dt: string, predicable = true): Insn => {
    if (q && ((d | m) & 1)) return undef(ctx);
    return mk(ctx, name, dt, [V(d, q), V(m, q)], 0, predicable);
  };
  const zero = (name: string, dt: string): Insn => {
    if (q && ((d | m) & 1)) return undef(ctx);
    return mk(ctx, name, dt, [V(d, q), V(m, q), immText(0, '#0')]);
  };
  if (size === 3) return undef(ctx);
  switch (a) {
    case 0:
      switch (b) {
        case 0:
          return two('vrev64', `${8 << size}`);
        case 1:
          return size < 2 ? two('vrev32', `${8 << size}`) : undef(ctx);
        case 2:
          return size < 1 ? two('vrev16', `${8 << size}`) : undef(ctx);
        case 4:
        case 5:
          return two('vpaddl', SU(b & 1, size));
        case 6:
        case 7: {
          if (size || (d | m) & 1) return undef(ctx);
          const name = b === 6 ? (q ? 'aesd' : 'aese') : q ? 'aesimc' : 'aesmc';
          return mk(ctx, name, '8', [Q(d), Q(m)], 0, false);
        }
        case 8:
          return two('vcls', `s${8 << size}`);
        case 9:
          return two('vclz', `i${8 << size}`);
        case 10:
          return size ? undef(ctx) : two('vcnt', '8');
        case 11:
          return size ? undef(ctx) : two('vmvn', '');
        case 12:
        case 13:
          return two('vpadal', SU(b & 1, size));
        case 14:
          return two('vqabs', `s${8 << size}`);
        case 15:
          return two('vqneg', `s${8 << size}`);
        default:
          return undef(ctx);
      }
    case 1: {
      const f = b >> 3;
      const op = b & 7;
      if (op === 5) {
        // sha1h lives where a float vcge-like operation would.
        if (f || size !== 2 || !q || (d | m) & 1) return undef(ctx);
        return mk(ctx, 'sha1h', '32', [Q(d), Q(m)], 0, false);
      }
      let dt: string;
      if (f) {
        if (size === 0) return undef(ctx);
        dt = size === 1 ? 'f16' : 'f32';
      } else dt = `${op === 2 ? 'i' : 's'}${8 << size}`;
      if (op < 5) return zero(CMP0[op]!, dt);
      return two(op === 6 ? 'vabs' : 'vneg', dt);
    }
    case 2:
      switch (b) {
        case 0:
          return size ? undef(ctx) : two('vswp', '');
        case 1:
          return two('vtrn', `${8 << size}`);
        case 2:
        case 3:
          // 32-bit vuzp and vzip of D registers would be vtrn; they are not encodable.
          if (size === 2 && !q) return undef(ctx);
          return two(b === 2 ? 'vuzp' : 'vzip', `${8 << size}`);
        case 4:
          if (m & 1) return undef(ctx);
          return q ? mk(ctx, 'vqmovun', `s${16 << size}`, [D(d), Q(m)]) : mk(ctx, 'vmovn', `i${16 << size}`, [D(d), Q(m)]);
        case 5:
          if (m & 1) return undef(ctx);
          return mk(ctx, 'vqmovn', `${q ? 'u' : 's'}${16 << size}`, [D(d), Q(m)]);
        case 6:
          if (q || d & 1) return undef(ctx);
          return mk(ctx, 'vshll', `i${8 << size}`, [Q(d), D(m), ih(8 << size)]);
        case 7:
          if (size !== 2 || (d | m) & 1) return undef(ctx);
          return mk(ctx, q ? 'sha256su0' : 'sha1su1', '32', [Q(d), Q(m)], 0, false);
        case 12:
          // f32 to f16 (or bf16) narrowing.
          if (size !== 1 || m & 1) return undef(ctx);
          return q ? mk(ctx, 'vcvt', 'bf16.f32', [D(d), Q(m)]) : mk(ctx, 'vcvt', 'f16.f32', [D(d), Q(m)]);
        case 14:
          if (size !== 1 || q || d & 1) return undef(ctx);
          return mk(ctx, 'vcvt', 'f32.f16', [Q(d), D(m)]);
        default: {
          const name = VRINT[b - 8];
          if (!name || size === 0) return undef(ctx);
          return two(name, size === 1 ? 'f16' : 'f32', false);
        }
      }
    default: {
      if (size === 0) return undef(ctx);
      const half = size === 1;
      const fl = half ? 'f16' : 'f32';
      const bitsW = half ? 16 : 32;
      if (b < 8) return two(VCVT_ROUND[b >> 1]!, `${b & 1 ? 'u' : 's'}${bitsW}.${fl}`, false);
      if (b < 12) {
        // 10F0 vrecpe, 10F1 vrsqrte: F picks float over unsigned.
        const name = b & 1 ? 'vrsqrte' : 'vrecpe';
        if (b & 2) return two(name, fl);
        return half ? undef(ctx) : two(name, 'u32');
      }
      const op = b & 3;
      return two('vcvt', op < 2 ? `${fl}.${op ? 'u' : 's'}${bitsW}` : `${op & 1 ? 'u' : 's'}${bitsW}.${fl}`);
    }
  }
}

/* ------------------------------------------------------------------ *
 * The rest of bit 23 = 1: vext, vtbl/vtbx, vdup (scalar)
 * ------------------------------------------------------------------ */

function vext(w: number, ctx: Ctx): Insn {
  const q = bit(w, 6);
  const imm4 = bits(w, 11, 8);
  const d = vd(w);
  const n = vn(w);
  const m = vm(w);
  if (q && ((d | n | m) & 1)) return undef(ctx);
  if (!q && imm4 & 8) return undef(ctx);
  // LLVM names the largest element size that the byte index is a multiple of.
  let ebytes = 1;
  if (q && (imm4 & 7) === 0) ebytes = 8;
  else if ((imm4 & 3) === 0) ebytes = 4;
  else if ((imm4 & 1) === 0) ebytes = 2;
  return mk(ctx, 'vext', `${ebytes * 8}`, [V(d, q), V(n, q), V(m, q), ih(imm4 / ebytes)]);
}

function vtbl(w: number, ctx: Ctx): Insn {
  const len = bits(w, 9, 8) + 1;
  const d = vd(w);
  const n = vn(w);
  const m = vm(w);
  // Two-register tables are a register pair, which cannot start at d31.
  if (len === 2 && n === 31) return undef(ctx);
  return mk(ctx, bit(w, 6) ? 'vtbx' : 'vtbl', '8', [D(d), dlist(n, len, 1), D(m)]);
}

function vdupScalar(w: number, ctx: Ctx): Insn {
  const imm4 = bits(w, 19, 16);
  const q = bit(w, 6);
  const d = vd(w);
  const m = vm(w);
  if (bit(w, 7) || (q && d & 1)) return undef(ctx);
  let dt: string;
  let index: number;
  if (imm4 & 1) {
    dt = '8';
    index = imm4 >> 1;
  } else if (imm4 & 2) {
    dt = '16';
    index = imm4 >> 2;
  } else if (imm4 & 4) {
    dt = '32';
    index = imm4 >> 3;
  } else return undef(ctx);
  return mk(ctx, 'vdup', dt, [V(d, q), { k: 'reg', r: `d${m}[${index}]` }]);
}

/** An A32 word of the form 1111 001U (or its T32 twin). */
export function neonData(w: number, ctx: Ctx): Insn {
  if (!bit(w, 23)) return threeSame(w, ctx);
  if (bit(w, 4)) return bits(w, 21, 19) === 0 && !bit(w, 7) ? modImm(w, ctx) : shiftImm(w, ctx);
  if (bits(w, 21, 20) !== 3) return bit(w, 6) ? scalar(w, ctx) : threeDiff(w, ctx);
  if (!bit(w, 24)) return vext(w, ctx);
  if (!bit(w, 11)) return twoMisc(w, ctx);
  if (!bit(w, 10)) return vtbl(w, ctx);
  if (bits(w, 11, 8) === 12) return vdupScalar(w, ctx);
  return undef(ctx);
}
