/**
 * SIMD and floating point: scalar FP arithmetic and conversions, the
 * Advanced SIMD (NEON) vector instructions, the cryptographic extensions and
 * the SIMD structure loads and stores (ld1…ld4, st1…st4).
 *
 * Registers print in the generic Arm syntax, `cmeq v0.8b, v1.8b, v2.8b`,
 * not Apple's `cmeq.8b v0, v1, v2`. Half-precision arithmetic (FP16), the
 * dot-product, matrix-multiply, BFloat16, complex and FP8 extensions are all
 * here; only SVE and SME, which have their own encoding space, are left as
 * `.inst`.
 */

import { bit, bits, sext, unknown, wr, xr, xs } from './decode';
import { CONDITIONS, F, imm, immText, reg, shift, text, type Insn, type Op } from './types';

const ARR = ['8b', '16b', '4h', '8h', '2s', '4s', '1d', '2d'];
const arr = (size: number, q: number): string => ARR[size * 2 + q]!;
const WIDE = ['8h', '4s', '2d', '1q'];
const v = (n: number, a: string): Op => reg(`v${n}.${a}`);
const el = (n: number, t: string, i: number): Op => reg(`v${n}.${t}[${i}]`);
const sc = (prefix: string, n: number): Op => reg(`${prefix}${n}`);
const mk = (m: string, ops: Op[], f = 0, extra?: Partial<Insn>): Insn => ({ m, ops, f, ...extra });
const ZERO_FP = text('#0.0');
const ZERO = imm(0, true);

/** The 8-bit floating-point immediate of fmov (VFPExpandImm). */
export function fpImm(imm8: number): number {
  const sign = imm8 & 0x80 ? -1 : 1;
  const exponent = (((imm8 >> 4) & 7) ^ 4) - 3;
  return sign * ((16 + (imm8 & 15)) / 16) * 2 ** exponent;
}
const fpImmOp = (imm8: number): Op => {
  const value = fpImm(imm8);
  return immText(value, `#${value.toFixed(8)}`);
};

/** LLVM prints 64-bit SIMD immediates with printf's "%#016llx". */
function simd64(value: bigint): Op {
  const t = value === 0n ? '0'.padStart(16, '0') : `0x${value.toString(16).padStart(14, '0')}`;
  return immText(Number(value), `#${t}`);
}

/* ------------------------------------------------------------------ *
 * Scalar floating point
 * ------------------------------------------------------------------ */

const fpPrefix = (ftype: number): string | null => (ftype === 0 ? 's' : ftype === 1 ? 'd' : ftype === 3 ? 'h' : null);

// FEAT_FPRCVT: the same conversions with the integer in a SIMD register (s or
// d by sf), by rmode:opcode. Only sizes that differ are encoded here; equal
// sizes are the Advanced SIMD scalar forms.
const FPRCVT: Record<number, string> = {
  0b01010: 'fcvtns', 0b01011: 'fcvtnu', 0b10010: 'fcvtps', 0b10011: 'fcvtpu', 0b10100: 'fcvtms', 0b10101: 'fcvtmu',
  0b10110: 'fcvtzs', 0b10111: 'fcvtzu', 0b11010: 'fcvtas', 0b11011: 'fcvtau', 0b11100: 'scvtf', 0b11101: 'ucvtf',
};

function fpIntConvert(w: number): Insn {
  const sf = bit(w, 31);
  const ftype = bits(w, 23, 22);
  const rmode = bits(w, 20, 19);
  const opcode = bits(w, 18, 16);
  const rn = bits(w, 9, 5);
  const rd = bits(w, 4, 0);
  if (bit(w, 29)) return unknown(w);
  if (rmode === 1 && (opcode & 6) === 6) {
    if (!sf || ftype !== 2) return unknown(w);
    return opcode === 6 ? mk('fmov', [reg(xr(rd)), el(rn, 'd', 1)]) : mk('fmov', [el(rd, 'd', 1), reg(xr(rn))]);
  }
  if (rmode === 3 && opcode === 6) return !sf && ftype === 1 ? mk('fjcvtzs', [reg(wr(rd)), sc('d', rn)], F.SETS_FLAGS) : unknown(w);
  const p = fpPrefix(ftype);
  if (!p) return unknown(w);
  const simdInt = FPRCVT[(rmode << 3) | opcode];
  if (simdInt) {
    const i = sf ? 'd' : 's';
    if (i === p) return unknown(w);
    return simdInt.endsWith('cvtf') ? mk(simdInt, [sc(p, rd), sc(i, rn)]) : mk(simdInt, [sc(i, rd), sc(p, rn)]);
  }
  const g = sf ? xr : wr;
  if (opcode === 6 || opcode === 7) {
    if (rmode) return unknown(w);
    if (p === 's' && sf) return unknown(w);
    if (p === 'd' && !sf) return unknown(w);
    return opcode === 6 ? mk('fmov', [reg(g(rd)), sc(p, rn)]) : mk('fmov', [sc(p, rd), reg(g(rn))]);
  }
  if (opcode === 2 || opcode === 3) {
    if (rmode) return unknown(w);
    return mk(opcode === 2 ? 'scvtf' : 'ucvtf', [sc(p, rd), reg(g(rn))]);
  }
  const round = opcode >= 4 ? 'a' : 'npmz'[rmode]!;
  if (opcode >= 4 && rmode) return unknown(w);
  return mk(`fcvt${round}${opcode & 1 ? 'u' : 's'}`, [reg(g(rd)), sc(p, rn)]);
}

function fpFixedConvert(w: number): Insn {
  const sf = bit(w, 31);
  const ftype = bits(w, 23, 22);
  const rmode = bits(w, 20, 19);
  const opcode = bits(w, 18, 16);
  const scale = bits(w, 15, 10);
  const p = fpPrefix(ftype);
  if (!p || (!sf && scale < 32)) return unknown(w);
  const g = sf ? xr : wr;
  const fbits = imm(64 - scale);
  const rn = bits(w, 9, 5);
  const rd = bits(w, 4, 0);
  if (rmode === 0 && (opcode === 2 || opcode === 3)) return mk(opcode === 2 ? 'scvtf' : 'ucvtf', [sc(p, rd), reg(g(rn)), fbits]);
  if (rmode === 3 && (opcode === 0 || opcode === 1)) return mk(opcode ? 'fcvtzu' : 'fcvtzs', [reg(g(rd)), sc(p, rn), fbits]);
  return unknown(w);
}

const FP1 = ['fmov', 'fabs', 'fneg', 'fsqrt', '', '', '', '', 'frintn', 'frintp', 'frintm', 'frintz', 'frinta', '', 'frintx', 'frinti', 'frint32z', 'frint32x', 'frint64z', 'frint64x'];

function fp1(w: number): Insn {
  const ftype = bits(w, 23, 22);
  const opcode = bits(w, 20, 15);
  const rn = bits(w, 9, 5);
  const rd = bits(w, 4, 0);
  const p = fpPrefix(ftype);
  if (!p || bit(w, 29) || bit(w, 31)) return unknown(w);
  if (opcode >= 4 && opcode <= 7) {
    const to = ['s', 'd', '', 'h'][opcode - 4];
    if (opcode === 6) return ftype === 1 ? mk('bfcvt', [sc('h', rd), sc('s', rn)]) : unknown(w);
    if (!to || to === p) return unknown(w);
    return mk('fcvt', [sc(to, rd), sc(p, rn)]);
  }
  const m = FP1[opcode];
  if (!m || (opcode >= 16 && p === 'h')) return unknown(w);
  return mk(m, [sc(p, rd), sc(p, rn)]);
}

function fpCompare(w: number): Insn {
  const ftype = bits(w, 23, 22);
  const p = fpPrefix(ftype);
  const op2 = bits(w, 4, 0);
  if (!p || bits(w, 15, 14) || (op2 & 7)) return unknown(w);
  const m = op2 & 16 ? 'fcmpe' : 'fcmp';
  const rn = bits(w, 9, 5);
  if (op2 & 8) return mk(m, [sc(p, rn), ZERO_FP], F.SETS_FLAGS);
  return mk(m, [sc(p, rn), sc(p, bits(w, 20, 16))], F.SETS_FLAGS);
}

const FP2 = ['fmul', 'fdiv', 'fadd', 'fsub', 'fmax', 'fmin', 'fmaxnm', 'fminnm', 'fnmul'];

function scalarFp(w: number): Insn {
  // Conversions to and from integers keep sf in bit 31; everything else needs M = S = 0 there.
  const conversion = !bit(w, 24) && (!bit(w, 21) || bits(w, 15, 10) === 0);
  if (bit(w, 29) || (!conversion && bit(w, 31))) return unknown(w);
  // x0x1 1x: data processing, 3 source
  if (bit(w, 24)) {
    const p = fpPrefix(bits(w, 23, 22));
    if (!p) return unknown(w);
    const m = ['fmadd', 'fmsub', 'fnmadd', 'fnmsub'][(bit(w, 21) << 1) | bit(w, 15)]!;
    return mk(m, [sc(p, bits(w, 4, 0)), sc(p, bits(w, 9, 5)), sc(p, bits(w, 20, 16)), sc(p, bits(w, 14, 10))]);
  }
  if (!bit(w, 21)) return fpFixedConvert(w);
  const op3 = bits(w, 15, 10);
  if ((op3 & 0x3f) === 0) return fpIntConvert(w);
  if ((op3 & 0x1f) === 0x10) return fp1(w);
  if ((op3 & 0xf) === 8) return fpCompare(w);
  if ((op3 & 7) === 4) {
    const p = fpPrefix(bits(w, 23, 22));
    if (!p || bits(w, 9, 5)) return unknown(w);
    return mk('fmov', [sc(p, bits(w, 4, 0)), fpImmOp(bits(w, 20, 13))]);
  }
  const p = fpPrefix(bits(w, 23, 22));
  if (!p) return unknown(w);
  const rm = bits(w, 20, 16);
  const rn = bits(w, 9, 5);
  const rd = bits(w, 4, 0);
  const c = CONDITIONS[bits(w, 15, 12)]!;
  switch (op3 & 3) {
    case 1:
      return mk(bit(w, 4) ? 'fccmpe' : 'fccmp', [sc(p, rn), sc(p, rm), imm(bits(w, 3, 0)), text(c)], F.SETS_FLAGS | F.READS_FLAGS, { cond: c });
    case 2: {
      const m = FP2[bits(w, 15, 12)];
      return m ? mk(m, [sc(p, rd), sc(p, rn), sc(p, rm)]) : unknown(w);
    }
    case 3:
      return mk('fcsel', [sc(p, rd), sc(p, rn), sc(p, rm), text(c)], F.READS_FLAGS, { cond: c });
  }
  return unknown(w);
}

/* ------------------------------------------------------------------ *
 * Advanced SIMD — vector
 * ------------------------------------------------------------------ */

const SAME_U0 = ['shadd', 'sqadd', 'srhadd', '', 'shsub', 'sqsub', 'cmgt', 'cmge', 'sshl', 'sqshl', 'srshl', 'sqrshl', 'smax', 'smin', 'sabd', 'saba', 'add', 'cmtst', 'mla', 'mul', 'smaxp', 'sminp', 'sqdmulh', 'addp'];
const SAME_U1 = ['uhadd', 'uqadd', 'urhadd', '', 'uhsub', 'uqsub', 'cmhi', 'cmhs', 'ushl', 'uqshl', 'urshl', 'uqrshl', 'umax', 'umin', 'uabd', 'uaba', 'sub', 'cmeq', 'mls', 'pmul', 'umaxp', 'uminp', 'sqrdmulh', ''];
// FP three-same, by U, size<1> and opcode<2:0>; the half-precision group uses
// the same table with a in place of size<1>.
const SAME_FP: Record<string, string> = {
  '0,0,0': 'fmaxnm', '0,0,1': 'fmla', '0,0,2': 'fadd', '0,0,3': 'fmulx', '0,0,4': 'fcmeq', '0,0,6': 'fmax', '0,0,7': 'frecps',
  '0,1,0': 'fminnm', '0,1,1': 'fmls', '0,1,2': 'fsub', '0,1,3': 'famax', '0,1,6': 'fmin', '0,1,7': 'frsqrts',
  '1,0,0': 'fmaxnmp', '1,0,2': 'faddp', '1,0,3': 'fmul', '1,0,4': 'fcmge', '1,0,5': 'facge', '1,0,6': 'fmaxp', '1,0,7': 'fdiv',
  '1,1,0': 'fminnmp', '1,1,2': 'fabd', '1,1,3': 'famin', '1,1,4': 'fcmgt', '1,1,5': 'facgt', '1,1,6': 'fminp', '1,1,7': 'fscale',
};
// FEAT_FHM sits in the single-precision slots the table leaves free: half-precision sources, single-precision sums.
const SAME_FHM: Record<string, string> = { '0,0,5': 'fmlal', '0,1,5': 'fmlsl', '1,0,1': 'fmlal2', '1,1,1': 'fmlsl2' };

function threeSame(w: number): Insn {
  const q = bit(w, 30);
  const u = bit(w, 29);
  const size = bits(w, 23, 22);
  const rm = bits(w, 20, 16);
  const opcode = bits(w, 15, 11);
  const rn = bits(w, 9, 5);
  const rd = bits(w, 4, 0);
  if (opcode === 3) {
    const m = (u ? ['eor', 'bsl', 'bit', 'bif'] : ['and', 'bic', 'orr', 'orn'])[size]!;
    const a = q ? '16b' : '8b';
    if (m === 'orr' && rm === rn) return mk('mov', [v(rd, a), v(rn, a)]);
    return mk(m, [v(rd, a), v(rn, a), v(rm, a)]);
  }
  if (opcode >= 24) {
    const key = `${u},${size >> 1},${opcode & 7}`;
    const sz = size & 1;
    const fhm = SAME_FHM[key];
    if (fhm) return sz ? unknown(w) : mk(fhm, [v(rd, arr(2, q)), v(rn, q ? '4h' : '2h'), v(rm, q ? '4h' : '2h')]);
    const m = SAME_FP[key];
    if (!m || (sz && !q)) return unknown(w);
    const a = arr(2 + sz, q);
    return mk(m, [v(rd, a), v(rn, a), v(rm, a)]);
  }
  const m = (u ? SAME_U1 : SAME_U0)[opcode];
  if (!m || (size === 3 && !q)) return unknown(w);
  // Only these work on 64-bit lanes; the halving, min/max, absolute-difference and multiply ones do not.
  if (size === 3 && !(opcode === 1 || opcode === 5 || (opcode >= 6 && opcode <= 11) || opcode === 16 || opcode === 17 || (opcode === 23 && !u))) return unknown(w);
  if (m.includes('mulh') && (size === 0 || size === 3)) return unknown(w);
  if (m === 'pmul' && size) return unknown(w);
  const a = arr(size, q);
  return mk(m, [v(rd, a), v(rn, a), v(rm, a)]);
}

function threeSameFp16(w: number, scalar: boolean): Insn {
  const m = SAME_FP[`${bit(w, 29)},${bit(w, 23)},${bits(w, 13, 11)}`];
  if (!m) return unknown(w);
  const rm = bits(w, 20, 16);
  const rn = bits(w, 9, 5);
  const rd = bits(w, 4, 0);
  if (scalar) {
    // Only the compares, the steps of the reciprocal estimates, fmulx and fabd have a scalar form.
    if (!['fmulx', 'fcmeq', 'fcmge', 'fcmgt', 'facge', 'facgt', 'frecps', 'frsqrts', 'fabd'].includes(m)) return unknown(w);
    return mk(m, [sc('h', rd), sc('h', rn), sc('h', rm)]);
  }
  const a = bit(w, 30) ? '8h' : '4h';
  return mk(m, [v(rd, a), v(rn, a), v(rm, a)]);
}

const DIFF_U0 = ['saddl', 'saddw', 'ssubl', 'ssubw', 'addhn', 'sabal', 'subhn', 'sabdl', 'smlal', 'sqdmlal', 'smlsl', 'sqdmlsl', 'smull', 'sqdmull', 'pmull'];
const DIFF_U1 = ['uaddl', 'uaddw', 'usubl', 'usubw', 'raddhn', 'uabal', 'rsubhn', 'uabdl', 'umlal', '', 'umlsl', '', 'umull', '', ''];

function threeDifferent(w: number): Insn {
  const q = bit(w, 30);
  const u = bit(w, 29);
  const size = bits(w, 23, 22);
  const opcode = bits(w, 15, 12);
  const rm = bits(w, 20, 16);
  const rn = bits(w, 9, 5);
  const rd = bits(w, 4, 0);
  const base = (u ? DIFF_U1 : DIFF_U0)[opcode];
  if (!base) return unknown(w);
  const m = base + (q ? '2' : '');
  if (base === 'pmull') {
    if (size === 0) return mk(m, [v(rd, '8h'), v(rn, arr(0, q)), v(rm, arr(0, q))]);
    if (size === 3) return mk(m, [v(rd, '1q'), v(rn, arr(3, q)), v(rm, arr(3, q))]);
    return unknown(w);
  }
  if (size === 3 || (base.startsWith('sqd') && size === 0)) return unknown(w);
  const wide = WIDE[size]!;
  const narrow = arr(size, q);
  if (opcode === 1 || opcode === 3) return mk(m, [v(rd, wide), v(rn, wide), v(rm, narrow)]);
  if (opcode === 4 || opcode === 6) return mk(m, [v(rd, narrow), v(rn, wide), v(rm, wide)]);
  return mk(m, [v(rd, wide), v(rn, narrow), v(rm, narrow)]);
}

/** Two registers, miscellaneous; fp16 is the half-precision group, which has only the floating-point half of the table. */
function twoRegMisc(w: number, fp16 = false): Insn {
  const q = bit(w, 30);
  const u = bit(w, 29);
  const size = bits(w, 23, 22);
  const opcode = bits(w, 16, 12);
  const rn = bits(w, 9, 5);
  const rd = bits(w, 4, 0);
  const a = arr(size, q);
  const same = (m: string, ok = true) => (ok ? mk(m, [v(rd, a), v(rn, a)]) : unknown(w));
  const two = q ? '2' : '';
  if (fp16 && (opcode < 12 || (opcode > 15 && opcode < 24))) return unknown(w);
  if (opcode < 12 || opcode === 18 || opcode === 19 || opcode === 20) {
    switch (opcode) {
      case 0:
        return same(u ? 'rev32' : 'rev64', u ? size < 2 : size < 3);
      case 1:
        return same('rev16', !u && size === 0);
      case 2:
      case 6:
        if (size === 3) return unknown(w);
        return mk(`${u ? 'u' : 's'}${opcode === 2 ? 'addlp' : 'adalp'}`, [v(rd, arr(size + 1, q)), v(rn, a)]);
      case 3:
        return same(u ? 'usqadd' : 'suqadd', size < 3 || !!q);
      case 4:
        return same(u ? 'clz' : 'cls', size < 3);
      case 5:
        if (!u) return same('cnt', size === 0);
        if (size === 0) return same('mvn');
        return size === 1 ? mk('rbit', [v(rd, arr(0, q)), v(rn, arr(0, q))]) : unknown(w);
      case 7:
        return same(u ? 'sqneg' : 'sqabs', size < 3 || !!q);
      case 8:
        return size === 3 && !q ? unknown(w) : mk(u ? 'cmge' : 'cmgt', [v(rd, a), v(rn, a), ZERO]);
      case 9:
        return size === 3 && !q ? unknown(w) : mk(u ? 'cmle' : 'cmeq', [v(rd, a), v(rn, a), ZERO]);
      case 10:
        return u || (size === 3 && !q) ? unknown(w) : mk('cmlt', [v(rd, a), v(rn, a), ZERO]);
      case 11:
        return same(u ? 'neg' : 'abs', size < 3 || !!q);
      case 18:
        if (size === 3) return unknown(w);
        return mk((u ? 'sqxtun' : 'xtn') + two, [v(rd, a), v(rn, WIDE[size]!)]);
      case 19:
        if (!u || size === 3) return unknown(w);
        return mk(`shll${two}`, [v(rd, WIDE[size]!), v(rn, a), imm(8 << size, true)]);
      case 20:
        if (size === 3) return unknown(w);
        return mk((u ? 'uqxtn' : 'sqxtn') + two, [v(rd, a), v(rn, WIDE[size]!)]);
    }
    return unknown(w);
  }
  // Floating point: size<1> picks one of two operations, size<0> the precision.
  const hi = size >> 1;
  const sz = size & 1;
  const fa = fp16 ? arr(1, q) : arr(2 + sz, q);
  if (sz && !q && !fp16 && opcode !== 22 && opcode !== 23) return unknown(w);
  const fsame = (m: string) => mk(m, [v(rd, fa), v(rn, fa)]);
  if (opcode === 22) {
    if (hi) return u || sz ? unknown(w) : mk(`bfcvtn${two}`, [v(rd, arr(1, q)), v(rn, '4s')]);
    if (u) return sz ? mk(`fcvtxn${two}`, [v(rd, arr(2, q)), v(rn, '2d')]) : unknown(w);
    return mk(`fcvtn${two}`, [v(rd, sz ? arr(2, q) : arr(1, q)), v(rn, sz ? '2d' : '4s')]);
  }
  if (opcode === 23) {
    // With U set, size picks one of the FP8 widenings to half precision or BFloat16.
    if (u) return mk(['f1cvtl', 'f2cvtl', 'bf1cvtl', 'bf2cvtl'][size]! + two, [v(rd, '8h'), v(rn, arr(0, q))]);
    if (hi) return unknown(w);
    return mk(`fcvtl${two}`, [v(rd, sz ? '2d' : '4s'), v(rn, sz ? arr(2, q) : arr(1, q))]);
  }
  if (hi && opcode >= 12 && opcode <= 15) {
    if (opcode === 15) return fsame(u ? 'fneg' : 'fabs');
    const m = [u ? 'fcmge' : 'fcmgt', u ? 'fcmle' : 'fcmeq', u ? '' : 'fcmlt'][opcode - 12];
    return m ? mk(m, [v(rd, fa), v(rn, fa), ZERO_FP]) : unknown(w);
  }
  const key = `${u}${hi}${opcode}`;
  const table: Record<string, string> = {
    '0024': 'frintn', '0025': 'frintm', '0026': 'fcvtns', '0027': 'fcvtms', '0028': 'fcvtas', '0029': 'scvtf', '0030': 'frint32z', '0031': 'frint64z',
    '0124': 'frintp', '0125': 'frintz', '0126': 'fcvtps', '0127': 'fcvtzs', '0128': 'urecpe', '0129': 'frecpe',
    '1024': 'frinta', '1025': 'frintx', '1026': 'fcvtnu', '1027': 'fcvtmu', '1028': 'fcvtau', '1029': 'ucvtf', '1030': 'frint32x', '1031': 'frint64x',
    '1125': 'frinti', '1126': 'fcvtpu', '1127': 'fcvtzu', '1128': 'ursqrte', '1129': 'frsqrte', '1131': 'fsqrt',
  };
  const m = table[key];
  if (!m) return unknown(w);
  if (m === 'urecpe' || m === 'ursqrte') return sz || fp16 ? unknown(w) : mk(m, [v(rd, arr(2, q)), v(rn, arr(2, q))]);
  if (fp16 && /^frint\d/.test(m)) return unknown(w); // frint32x and its kin have no half-precision form
  return fsame(m);
}

function acrossLanes(w: number): Insn {
  const q = bit(w, 30);
  const u = bit(w, 29);
  const size = bits(w, 23, 22);
  const opcode = bits(w, 16, 12);
  const rn = bits(w, 9, 5);
  const rd = bits(w, 4, 0);
  if (opcode === 12 || opcode === 15) {
    // With U clear these are the half-precision forms, over four or eight lanes.
    if (size & 1 || (u && !q)) return unknown(w);
    const m = opcode === 12 ? (size ? 'fminnmv' : 'fmaxnmv') : size ? 'fminv' : 'fmaxv';
    return u ? mk(m, [sc('s', rd), v(rn, '4s')]) : mk(m, [sc('h', rd), v(rn, arr(1, q))]);
  }
  const a = arr(size, q);
  if (size === 3 || (size === 2 && !q)) return unknown(w);
  if (opcode === 3) return mk(u ? 'uaddlv' : 'saddlv', [sc('hsd'[size]!, rd), v(rn, a)]);
  const m = { 10: u ? 'umaxv' : 'smaxv', 26: u ? 'uminv' : 'sminv', 27: u ? '' : 'addv' }[opcode];
  if (!m) return unknown(w);
  return mk(m, [sc('bhs'[size]!, rd), v(rn, a)]);
}

function copy(w: number, scalar: boolean): Insn {
  const q = bit(w, 30);
  const op = bit(w, 29);
  const imm5 = bits(w, 20, 16);
  const imm4 = bits(w, 14, 11);
  const rn = bits(w, 9, 5);
  const rd = bits(w, 4, 0);
  const size = imm5 & 1 ? 0 : imm5 & 2 ? 1 : imm5 & 4 ? 2 : imm5 & 8 ? 3 : -1;
  if (size < 0) return unknown(w);
  const t = 'bhsd'[size]!;
  const index = imm5 >> (size + 1);
  if (scalar) {
    if (op || imm4) return unknown(w);
    return mk('mov', [sc(t, rd), el(rn, t, index)]);
  }
  if (op) {
    if (!q) return unknown(w);
    return mk('mov', [el(rd, t, index), el(rn, t, imm4 >> size)]);
  }
  switch (imm4) {
    case 0:
      if (size === 3 && !q) return unknown(w);
      return mk('dup', [v(rd, arr(size, q)), el(rn, t, index)]);
    case 1:
      if (size === 3 && !q) return unknown(w);
      return mk('dup', [v(rd, arr(size, q)), reg(size === 3 ? xr(rn) : wr(rn))]);
    case 3:
      if (!q) return unknown(w);
      return mk('mov', [el(rd, t, index), reg(size === 3 ? xr(rn) : wr(rn))]);
    case 5:
      if (size === 3 || (size === 2 && !q)) return unknown(w);
      return mk('smov', [reg(q ? xr(rd) : wr(rd)), el(rn, t, index)]);
    case 7:
      if ((size === 3) !== !!q) return unknown(w);
      return mk(size >= 2 ? 'mov' : 'umov', [reg(q ? xr(rd) : wr(rd)), el(rn, t, index)]);
  }
  return unknown(w);
}

function modifiedImmediate(w: number): Insn {
  const q = bit(w, 30);
  const op = bit(w, 29);
  const cmode = bits(w, 15, 12);
  const o2 = bit(w, 11);
  const rd = bits(w, 4, 0);
  const imm8 = (bits(w, 18, 16) << 5) | bits(w, 9, 5);
  if (o2 && !(cmode === 15 && !op)) return unknown(w);
  if (cmode < 8) {
    const a = q ? '4s' : '2s';
    const amount = (cmode >> 1) * 8;
    const m = cmode & 1 ? (op ? 'bic' : 'orr') : op ? 'mvni' : 'movi';
    return mk(m, [v(rd, a), imm(imm8), ...(amount ? [shift('lsl', amount, false)] : [])]);
  }
  if (cmode < 12) {
    const a = q ? '8h' : '4h';
    const amount = ((cmode >> 1) & 1) * 8;
    const m = cmode & 1 ? (op ? 'bic' : 'orr') : op ? 'mvni' : 'movi';
    return mk(m, [v(rd, a), imm(imm8), ...(amount ? [shift('lsl', amount, false)] : [])]);
  }
  if (cmode < 14) {
    const a = q ? '4s' : '2s';
    return mk(op ? 'mvni' : 'movi', [v(rd, a), imm(imm8), shift('msl', cmode & 1 ? 16 : 8, false)]);
  }
  if (cmode === 14) {
    if (!op) return mk('movi', [v(rd, q ? '16b' : '8b'), imm(imm8)]);
    let value = 0n;
    for (let i = 0; i < 8; i++) if (imm8 & (1 << i)) value |= 0xffn << BigInt(i * 8);
    return q ? mk('movi', [v(rd, '2d'), simd64(value)]) : mk('movi', [sc('d', rd), simd64(value)]);
  }
  if (!op) return mk('fmov', [v(rd, o2 ? (q ? '8h' : '4h') : q ? '4s' : '2s'), fpImmOp(imm8)]);
  if (!q) return unknown(w);
  return mk('fmov', [v(rd, '2d'), fpImmOp(imm8)]);
}

const SHIFT_U0: Record<number, string> = { 0: 'sshr', 2: 'ssra', 4: 'srshr', 6: 'srsra', 10: 'shl', 14: 'sqshl', 16: 'shrn', 17: 'rshrn', 18: 'sqshrn', 19: 'sqrshrn', 20: 'sshll', 28: 'scvtf', 31: 'fcvtzs' };
const SHIFT_U1: Record<number, string> = { 0: 'ushr', 2: 'usra', 4: 'urshr', 6: 'ursra', 8: 'sri', 10: 'sli', 12: 'sqshlu', 14: 'uqshl', 16: 'sqshrun', 17: 'sqrshrun', 18: 'uqshrn', 19: 'uqrshrn', 20: 'ushll', 28: 'ucvtf', 31: 'fcvtzu' };
const LEFT = new Set(['shl', 'sqshl', 'sli', 'sqshlu', 'uqshl', 'sshll', 'ushll']);

function shiftImmediate(w: number, scalar: boolean): Insn {
  const q = bit(w, 30);
  const u = bit(w, 29);
  const immh = bits(w, 22, 19);
  const immb = bits(w, 18, 16);
  const opcode = bits(w, 15, 11);
  const rn = bits(w, 9, 5);
  const rd = bits(w, 4, 0);
  const m = (u ? SHIFT_U1 : SHIFT_U0)[opcode];
  if (!m || !immh) return unknown(w);
  const size = 31 - Math.clz32(immh);
  const esize = 8 << size;
  const value = (immh << 3) | immb;
  const amount = LEFT.has(m) ? value - esize : 2 * esize - value;
  const narrow = opcode >= 16 && opcode <= 19;
  const long = opcode === 20;
  const fixed = opcode === 28 || opcode === 31;
  if (scalar) {
    if (long) return unknown(w);
    if (narrow) {
      if (size === 3 || m === 'shrn' || m === 'rshrn') return unknown(w);
      return mk(m, [sc('bhs'[size]!, rd), sc('hsd'[size]!, rn), imm(amount)]);
    }
    if (fixed) {
      if (size < 1) return unknown(w);
      return mk(m, [sc('hsd'[size - 1]!, rd), sc('hsd'[size - 1]!, rn), imm(amount)]);
    }
    const p = 'bhsd'[size]!;
    if (!['sqshl', 'uqshl', 'sqshlu'].includes(m) && size !== 3) return unknown(w);
    return mk(m, [sc(p, rd), sc(p, rn), imm(amount)]);
  }
  const two = q ? '2' : '';
  if (narrow) {
    if (size === 3) return unknown(w);
    return mk(m + two, [v(rd, arr(size, q)), v(rn, WIDE[size]!), imm(amount)]);
  }
  if (long) {
    if (size === 3) return unknown(w);
    return mk(m + two, [v(rd, WIDE[size]!), v(rn, arr(size, q)), imm(amount)]);
  }
  if (size === 3 && !q) return unknown(w);
  if (fixed && size < 1) return unknown(w);
  return mk(m, [v(rd, arr(size, q)), v(rn, arr(size, q)), imm(amount)]);
}

const INDEXED_U0: Record<number, string> = { 2: 'smlal', 3: 'sqdmlal', 6: 'smlsl', 7: 'sqdmlsl', 8: 'mul', 10: 'smull', 11: 'sqdmull', 12: 'sqdmulh', 13: 'sqrdmulh', 14: 'sdot', 1: 'fmla', 5: 'fmls', 9: 'fmul' };
const INDEXED_U1: Record<number, string> = { 0: 'mla', 2: 'umlal', 4: 'mls', 6: 'umlsl', 10: 'umull', 9: 'fmulx', 14: 'udot', 13: 'sqrdmlah', 15: 'sqrdmlsh' };

/**
 * The by-element forms of the newer extensions (FP8 and BFloat16 dot products
 * and widening multiply-adds, FHM, the mixed-sign dot products, fcmla), in
 * slots the older table leaves free; null where the older table applies.
 */
function indexedExtra(w: number, q: number, u: number, size: number, opcode: number): Insn | null {
  const l = bit(w, 21);
  const mBit = bit(w, 20);
  const h = bit(w, 11);
  const rn = bits(w, 9, 5);
  const rd = bits(w, 4, 0);
  const rm4 = bits(w, 19, 16); // v0-v15 where M is an index bit
  const rm5 = bits(w, 20, 16);
  const hlm = (h << 2) | (l << 1) | mBit;
  const hl = (h << 1) | l;
  const b = q ? '16b' : '8b';
  const s = arr(2, q);
  // The FP8 forms that pick a single byte take the lowest index bit from bit 19, which leaves them v0-v7.
  const byte = () => el(bits(w, 18, 16), 'b', (hlm << 1) | bit(w, 19));
  const halves = (m: string) => mk(m, [v(rd, s), v(rn, q ? '4h' : '2h'), el(rm4, 'h', hlm)]);
  if (!u) {
    switch (opcode) {
      case 0:
        if (size === 0) return mk('fdot', [v(rd, s), v(rn, b), reg(`v${rm5}.4b[${hl}]`)]);
        if (size === 1) return mk('fdot', [v(rd, arr(1, q)), v(rn, b), reg(`v${rm4}.2b[${hlm}]`)]);
        if (size === 2) return halves('fmlal');
        return mk(q ? 'fmlalt' : 'fmlalb', [v(rd, '8h'), v(rn, '16b'), byte()]);
      case 4:
        return size === 2 ? halves('fmlsl') : unknown(w);
      case 15:
        if (size === 1) return mk('bfdot', [v(rd, s), v(rn, arr(1, q)), reg(`v${rm5}.2h[${hl}]`)]);
        if (size === 3) return mk(q ? 'bfmlalt' : 'bfmlalb', [v(rd, '4s'), v(rn, '8h'), el(rm4, 'h', hlm)]);
        return mk(size ? 'usdot' : 'sudot', [v(rd, s), v(rn, b), reg(`v${rm5}.4b[${hl}]`)]);
    }
    return null;
  }
  if (opcode === 8 && size < 2) return mk(`fmlall${q ? 't' : 'b'}${size ? 't' : 'b'}`, [v(rd, '4s'), v(rn, '16b'), byte()]);
  if ((opcode === 8 || opcode === 12) && size === 2) return halves(opcode === 8 ? 'fmlal2' : 'fmlsl2');
  if (opcode & 1 && opcode < 8) {
    // fcmla indexes complex pairs, so its index has one bit fewer than the lanes would need.
    const rot = imm((opcode >> 1) * 90, true);
    if (size === 1) return !q && h ? unknown(w) : mk('fcmla', [v(rd, arr(1, q)), v(rn, arr(1, q)), el(rm5, 'h', hl), rot]);
    if (size === 2) return !q || l ? unknown(w) : mk('fcmla', [v(rd, '4s'), v(rn, '4s'), el(rm5, 's', h), rot]);
    return unknown(w);
  }
  return null;
}

function indexedElement(w: number, scalar: boolean): Insn {
  const q = bit(w, 30);
  const u = bit(w, 29);
  const size = bits(w, 23, 22);
  const l = bit(w, 21);
  const mBit = bit(w, 20);
  const rmLow = bits(w, 19, 16);
  const opcode = bits(w, 15, 12);
  const h = bit(w, 11);
  const rn = bits(w, 9, 5);
  const rd = bits(w, 4, 0);
  if (!scalar) {
    const extra = indexedExtra(w, q, u, size, opcode);
    if (extra) return extra;
  }
  const m = (u ? INDEXED_U1 : INDEXED_U0)[opcode];
  if (!m) return unknown(w);
  const fp = m.startsWith('f');
  if (fp && size === 0) {
    // Half precision: eight lanes to index, so M joins H:L and the register is v0-v15.
    const e = el(rmLow, 'h', (h << 2) | (l << 1) | mBit);
    if (scalar) return mk(m, [sc('h', rd), sc('h', rn), e]);
    return mk(m, [v(rd, arr(1, q)), v(rn, arr(1, q)), e]);
  }
  if (fp) {
    if (size < 2) return unknown(w);
    const sz = size & 1;
    const index = sz ? h : (h << 1) | l;
    if (sz && l) return unknown(w);
    const rm = (mBit << 4) | rmLow;
    const t = sz ? 'd' : 's';
    if (scalar) return mk(m, [sc(t, rd), sc(t, rn), el(rm, t, index)]);
    if (sz && !q) return unknown(w);
    const a = arr(2 + sz, q);
    return mk(m, [v(rd, a), v(rn, a), el(rm, t, index)]);
  }
  if (size !== 1 && size !== 2) return unknown(w);
  const index = size === 1 ? (h << 2) | (l << 1) | mBit : (h << 1) | l;
  const rm = size === 1 ? rmLow : (mBit << 4) | rmLow;
  const t = size === 1 ? 'h' : 's';
  if (m === 'sdot' || m === 'udot') {
    if (size !== 2 || scalar) return unknown(w);
    return mk(m, [v(rd, q ? '4s' : '2s'), v(rn, q ? '16b' : '8b'), reg(`v${rm}.4b[${index}]`)]);
  }
  const longOp = ['smlal', 'smlsl', 'smull', 'umlal', 'umlsl', 'umull', 'sqdmlal', 'sqdmlsl', 'sqdmull'].includes(m);
  if (scalar) {
    if (!m.startsWith('sq')) return unknown(w);
    return mk(m, [sc(longOp ? 'sd'[size - 1]! : t, rd), sc(t, rn), el(rm, t, index)]);
  }
  if (longOp) return mk(m + (q ? '2' : ''), [v(rd, WIDE[size]!), v(rn, arr(size, q)), el(rm, t, index)]);
  return mk(m, [v(rd, arr(size, q)), v(rn, arr(size, q)), el(rm, t, index)]);
}

/**
 * Three registers, extension: the dot products and matrix multiplies, the
 * rounding doubling multiply-accumulates, the complex fcmla/fcadd, BFloat16
 * and FP8. The scalar group has only sqrdmlah and sqrdmlsh.
 */
function threeSameExtra(w: number, scalar: boolean): Insn {
  const q = bit(w, 30);
  const u = bit(w, 29);
  const size = bits(w, 23, 22);
  const opcode = bits(w, 14, 11);
  const rm = bits(w, 20, 16);
  const rn = bits(w, 9, 5);
  const rd = bits(w, 4, 0);
  if (u && opcode < 2 && (size === 1 || size === 2)) {
    const m = opcode ? 'sqrdmlsh' : 'sqrdmlah';
    if (scalar) return mk(m, [sc('hs'[size - 1]!, rd), sc('hs'[size - 1]!, rn), sc('hs'[size - 1]!, rm)]);
    const a = arr(size, q);
    return mk(m, [v(rd, a), v(rn, a), v(rm, a)]);
  }
  if (scalar) return unknown(w);
  const b = q ? '16b' : '8b';
  const s = arr(2, q);
  const ops = (d: string, n: string, m = n) => [v(rd, d), v(rn, n), v(rm, m)];
  if (!u) {
    switch (opcode) {
      case 2:
        return size === 2 ? mk('sdot', ops(s, b)) : unknown(w);
      case 3:
        return size === 2 ? mk('usdot', ops(s, b)) : unknown(w);
      case 4:
      case 5:
        return size === 2 && q ? mk(opcode === 4 ? 'smmla' : 'usmmla', ops('4s', '16b')) : unknown(w);
      case 8:
        return size < 2 ? mk(`fmlall${q ? 't' : 'b'}${size ? 't' : 'b'}`, ops('4s', '16b')) : unknown(w);
      case 14:
        // FP8 narrowing: two half-precision sources fill one register, two single-precision sources half of one.
        if (size === 1) return mk('fcvtn', ops(b, arr(1, q)));
        return size === 0 ? mk(q ? 'fcvtn2' : 'fcvtn', ops(b, '4s')) : unknown(w);
      case 15:
        if (size === 0) return mk('fdot', ops(s, b));
        if (size === 1) return mk('fdot', ops(arr(1, q), b));
        return size === 3 ? mk(q ? 'fmlalt' : 'fmlalb', ops('8h', '16b')) : unknown(w);
    }
    return unknown(w);
  }
  if (opcode === 2) return size === 2 ? mk('udot', ops(s, b)) : unknown(w);
  if (opcode === 4) return size === 2 && q ? mk('ummla', ops('4s', '16b')) : unknown(w);
  if (opcode >= 8 && opcode !== 13 && opcode !== 15) {
    // fcmla (rotation in opcode<1:0>) and fcadd (rotation in opcode<1>) on half, single or double precision.
    if (size === 0 || (size === 3 && !q)) return unknown(w);
    const a = arr(size, q);
    if (opcode < 12) return mk('fcmla', [...ops(a, a), imm((opcode & 3) * 90, true)]);
    return mk('fcadd', [...ops(a, a), imm(opcode & 2 ? 270 : 90, true)]);
  }
  if (opcode === 13) {
    if (!q || size === 3) return unknown(w);
    return size === 1 ? mk('bfmmla', ops('4s', '8h')) : mk('fmmla', ops(size ? '4s' : '8h', '16b'));
  }
  if (opcode === 15) {
    if (size === 1) return mk('bfdot', ops(s, arr(1, q)));
    return size === 3 ? mk(q ? 'bfmlalt' : 'bfmlalb', ops('4s', '8h')) : unknown(w);
  }
  return unknown(w);
}

function lookupTable(w: number, size: number): Insn {
  const rm = bits(w, 20, 16);
  const rn = bits(w, 9, 5);
  const rd = bits(w, 4, 0);
  if (!bit(w, 30)) return unknown(w);
  const index = (i: number) => reg(`v${rm}[${i}]`);
  if (size === 1) {
    // luti4: bytes from one table register, or halfwords from a pair.
    if (bit(w, 12)) return mk('luti4', [v(rd, '8h'), text(vectorRegList(rn, 2, '8h')), index(bits(w, 14, 13))]);
    return bit(w, 13) ? mk('luti4', [v(rd, '16b'), text(vectorRegList(rn, 1, '16b')), index(bit(w, 14))]) : unknown(w);
  }
  if (size === 2) return bit(w, 12) ? mk('luti2', [v(rd, '16b'), text(vectorRegList(rn, 1, '16b')), index(bits(w, 14, 13))]) : unknown(w);
  return mk('luti2', [v(rd, '8h'), text(vectorRegList(rn, 1, '8h')), index(bits(w, 14, 12))]);
}

function vectorRegList(first: number, count: number, a: string): string {
  const regs = [];
  for (let i = 0; i < count; i++) regs.push(`v${(first + i) % 32}.${a}`);
  return `{ ${regs.join(', ')} }`;
}

function advSimdVector(w: number): Insn {
  const op0 = bits(w, 31, 28);
  const op1 = bits(w, 24, 23);
  const op2 = bits(w, 22, 19);
  const op3 = bits(w, 18, 10);
  const q = bit(w, 30);
  const rm = bits(w, 20, 16);
  const rn = bits(w, 9, 5);
  const rd = bits(w, 4, 0);
  if ((op0 & 0xb) === 0 && op1 < 2 && !(op2 & 4) && !(op3 & 0x23)) {
    // Table lookup; a nonzero size field is FEAT_LUT's luti2 and luti4, whose table is indexed by 2 or 4 bits.
    const size = bits(w, 23, 22);
    if (size) return lookupTable(w, size);
    const len = bits(w, 14, 13) + 1;
    const a = q ? '16b' : '8b';
    return mk(bit(w, 12) ? 'tbx' : 'tbl', [v(rd, a), text(vectorRegList(rn, len, '16b')), v(rm, a)]);
  }
  if ((op0 & 0xb) === 0 && op1 < 2 && !(op2 & 4) && (op3 & 0x23) === 2) {
    const m = ['', 'uzp1', 'trn1', 'zip1', '', 'uzp2', 'trn2', 'zip2'][bits(w, 14, 12)];
    const size = bits(w, 23, 22);
    if (!m || (size === 3 && !q)) return unknown(w);
    const a = arr(size, q);
    return mk(m, [v(rd, a), v(rn, a), v(rm, a)]);
  }
  if ((op0 & 0xb) === 2 && op1 < 2 && !(op2 & 4) && !(op3 & 0x21)) {
    const index = bits(w, 14, 11);
    if (bits(w, 23, 22) || (!q && index > 7)) return unknown(w);
    const a = q ? '16b' : '8b';
    return mk('ext', [v(rd, a), v(rn, a), v(rm, a), imm(index)]);
  }
  if (op1 === 0 && (op2 & 0xc) === 0 && (op3 & 0x21) === 1) return copy(w, false);
  if (op1 < 2 && (op2 & 0xc) === 8 && (op3 & 0x31) === 1) return threeSameFp16(w, false);
  if (op1 < 2 && (op2 & 4) === 0 && (op3 & 0x21) === 0x21) return threeSameExtra(w, false);
  if (op1 < 2 && (op2 & 7) === 4 && (op3 & 0x183) === 2) return twoRegMisc(w);
  if (op1 < 2 && op2 === 15 && (op3 & 0x183) === 2) return twoRegMisc(w, true);
  if (op1 < 2 && (op2 & 7) === 6 && (op3 & 0x183) === 2) return acrossLanes(w);
  if (op1 < 2 && (op2 & 4) && (op3 & 3) === 0) return threeDifferent(w);
  if (op1 < 2 && (op2 & 4) && (op3 & 1)) return threeSame(w);
  if (op1 === 2 && op2 === 0 && (op3 & 1)) return modifiedImmediate(w);
  if (op1 === 2 && op2 !== 0 && (op3 & 1)) return shiftImmediate(w, false);
  if (op1 >= 2 && !(op3 & 1)) return indexedElement(w, false);
  return unknown(w);
}

/* ------------------------------------------------------------------ *
 * Advanced SIMD — scalar
 * ------------------------------------------------------------------ */

function scalarThreeSame(w: number): Insn {
  const u = bit(w, 29);
  const size = bits(w, 23, 22);
  const opcode = bits(w, 15, 11);
  const rm = bits(w, 20, 16);
  const rn = bits(w, 9, 5);
  const rd = bits(w, 4, 0);
  if (opcode >= 24) {
    const fp: Record<string, string> = { '0,0,3': 'fmulx', '0,0,4': 'fcmeq', '0,0,7': 'frecps', '0,1,7': 'frsqrts', '1,0,4': 'fcmge', '1,0,5': 'facge', '1,1,2': 'fabd', '1,1,4': 'fcmgt', '1,1,5': 'facgt' };
    const m = fp[`${u},${size >> 1},${opcode & 7}`];
    const p = size & 1 ? 'd' : 's';
    return m ? mk(m, [sc(p, rd), sc(p, rn), sc(p, rm)]) : unknown(w);
  }
  const m = (u ? SAME_U1 : SAME_U0)[opcode];
  const anySize = ['sqadd', 'uqadd', 'sqsub', 'uqsub', 'sqshl', 'uqshl', 'sqrshl', 'uqrshl'];
  const dOnly = ['cmgt', 'cmge', 'cmhi', 'cmhs', 'sshl', 'ushl', 'srshl', 'urshl', 'add', 'sub', 'cmtst', 'cmeq'];
  if (!m) return unknown(w);
  if (dOnly.includes(m)) return size === 3 ? mk(m, [sc('d', rd), sc('d', rn), sc('d', rm)]) : unknown(w);
  if (anySize.includes(m)) return mk(m, [sc('bhsd'[size]!, rd), sc('bhsd'[size]!, rn), sc('bhsd'[size]!, rm)]);
  if ((m === 'sqdmulh' || m === 'sqrdmulh') && (size === 1 || size === 2)) return mk(m, [sc('hs'[size - 1]!, rd), sc('hs'[size - 1]!, rn), sc('hs'[size - 1]!, rm)]);
  return unknown(w);
}

function scalarTwoRegMisc(w: number, fp16 = false): Insn {
  const u = bit(w, 29);
  const size = bits(w, 23, 22);
  const opcode = bits(w, 16, 12);
  const rn = bits(w, 9, 5);
  const rd = bits(w, 4, 0);
  const p = 'bhsd'[size]!;
  if (!fp16) switch (opcode) {
    case 3:
      return mk(u ? 'usqadd' : 'suqadd', [sc(p, rd), sc(p, rn)]);
    case 7:
      return mk(u ? 'sqneg' : 'sqabs', [sc(p, rd), sc(p, rn)]);
    case 8:
    case 9:
      if (size !== 3) return unknown(w);
      return mk([u ? 'cmge' : 'cmgt', u ? 'cmle' : 'cmeq'][opcode - 8]!, [sc('d', rd), sc('d', rn), ZERO]);
    case 10:
      return size === 3 && !u ? mk('cmlt', [sc('d', rd), sc('d', rn), ZERO]) : unknown(w);
    case 11:
      return size === 3 ? mk(u ? 'neg' : 'abs', [sc('d', rd), sc('d', rn)]) : unknown(w);
    case 18:
      return u && size < 3 ? mk('sqxtun', [sc(p, rd), sc('hsd'[size]!, rn)]) : unknown(w);
    case 20:
      return size < 3 ? mk(u ? 'uqxtn' : 'sqxtn', [sc(p, rd), sc('hsd'[size]!, rn)]) : unknown(w);
    case 22:
      return u && size === 1 ? mk('fcvtxn', [sc('s', rd), sc('d', rn)]) : unknown(w);
  }
  const hi = size >> 1;
  const fp = fp16 ? 'h' : size & 1 ? 'd' : 's';
  if (hi && opcode >= 12 && opcode <= 14) {
    const m = [u ? 'fcmge' : 'fcmgt', u ? 'fcmle' : 'fcmeq', u ? '' : 'fcmlt'][opcode - 12];
    return m ? mk(m, [sc(fp, rd), sc(fp, rn), ZERO_FP]) : unknown(w);
  }
  const table: Record<string, string> = {
    '0026': 'fcvtns', '0027': 'fcvtms', '0028': 'fcvtas', '0029': 'scvtf',
    '0126': 'fcvtps', '0127': 'fcvtzs', '0129': 'frecpe', '0131': 'frecpx',
    '1026': 'fcvtnu', '1027': 'fcvtmu', '1028': 'fcvtau', '1029': 'ucvtf',
    '1126': 'fcvtpu', '1127': 'fcvtzu', '1129': 'frsqrte',
  };
  const m = table[`${u}${hi}${opcode}`];
  return m ? mk(m, [sc(fp, rd), sc(fp, rn)]) : unknown(w);
}

function advSimdScalar(w: number): Insn {
  const op1 = bits(w, 24, 23);
  const op2 = bits(w, 22, 19);
  const op3 = bits(w, 18, 10);
  const rn = bits(w, 9, 5);
  const rd = bits(w, 4, 0);
  if (op1 === 0 && (op2 & 0xc) === 0 && (op3 & 0x21) === 1) return copy(w, true);
  if (op1 < 2 && (op2 & 0xc) === 8 && (op3 & 0x31) === 1) return threeSameFp16(w, true);
  if (op1 < 2 && (op2 & 4) === 0 && (op3 & 0x21) === 0x21) return threeSameExtra(w, true);
  if (op1 < 2 && (op2 & 7) === 4 && (op3 & 0x183) === 2) return scalarTwoRegMisc(w);
  if (op1 < 2 && op2 === 15 && (op3 & 0x183) === 2) return scalarTwoRegMisc(w, true);
  if (op1 < 2 && (op2 & 7) === 6 && (op3 & 0x183) === 2) {
    const u = bit(w, 29);
    const size = bits(w, 23, 22);
    const opcode = bits(w, 16, 12);
    if (!u && opcode === 27 && size === 3) return mk('addp', [sc('d', rd), v(rn, '2d')]);
    // Pairwise FP: U set for single and double precision, U clear (and size<0> clear) for half.
    const sz = size & 1;
    const hi = size >> 1;
    const m = { 12: hi ? 'fminnmp' : 'fmaxnmp', 13: hi ? '' : 'faddp', 15: hi ? 'fminp' : 'fmaxp' }[opcode];
    if (!m) return unknown(w);
    if (u) return mk(m, [sc(sz ? 'd' : 's', rd), v(rn, sz ? '2d' : '2s')]);
    return sz ? unknown(w) : mk(m, [sc('h', rd), v(rn, '2h')]);
  }
  if (op1 < 2 && (op2 & 4) && (op3 & 3) === 0) {
    const u = bit(w, 29);
    const size = bits(w, 23, 22);
    const opcode = bits(w, 15, 12);
    const m = { 9: 'sqdmlal', 11: 'sqdmlsl', 13: 'sqdmull' }[opcode];
    if (u || !m || (size !== 1 && size !== 2)) return unknown(w);
    return mk(m, [sc('sd'[size - 1]!, rd), sc('hs'[size - 1]!, rn), sc('hs'[size - 1]!, bits(w, 20, 16))]);
  }
  if (op1 < 2 && (op2 & 4) && (op3 & 1)) return scalarThreeSame(w);
  if (op1 === 2 && (op3 & 1)) return shiftImmediate(w, true);
  if (op1 >= 2 && !(op3 & 1)) return indexedElement(w, true);
  return unknown(w);
}

/* ------------------------------------------------------------------ *
 * Cryptography
 * ------------------------------------------------------------------ */

function crypto(w: number): Insn {
  const rn = bits(w, 9, 5);
  const rd = bits(w, 4, 0);
  const rm = bits(w, 20, 16);
  const top = bits(w, 31, 24);
  if (top === 0x4e && bits(w, 21, 17) === 0x14 && bits(w, 11, 10) === 2) {
    const m = { 4: 'aese', 5: 'aesd', 6: 'aesmc', 7: 'aesimc' }[bits(w, 16, 12)];
    return m && !bits(w, 23, 22) ? mk(m, [v(rd, '16b'), v(rn, '16b')]) : unknown(w);
  }
  if (top === 0x5e && !bit(w, 21) && !bit(w, 15) && bits(w, 11, 10) === 0 && !bits(w, 23, 22)) {
    const opcode = bits(w, 14, 12);
    if (opcode < 3) return mk(['sha1c', 'sha1p', 'sha1m'][opcode]!, [sc('q', rd), sc('s', rn), v(rm, '4s')]);
    if (opcode === 3) return mk('sha1su0', [v(rd, '4s'), v(rn, '4s'), v(rm, '4s')]);
    if (opcode < 6) return mk(opcode === 4 ? 'sha256h' : 'sha256h2', [sc('q', rd), sc('q', rn), v(rm, '4s')]);
    if (opcode === 6) return mk('sha256su1', [v(rd, '4s'), v(rn, '4s'), v(rm, '4s')]);
    return unknown(w);
  }
  if (top === 0x5e && bits(w, 21, 17) === 0x14 && bits(w, 11, 10) === 2 && !bits(w, 23, 22)) {
    const opcode = bits(w, 16, 12);
    if (opcode === 0) return mk('sha1h', [sc('s', rd), sc('s', rn)]);
    if (opcode === 1) return mk('sha1su1', [v(rd, '4s'), v(rn, '4s')]);
    if (opcode === 2) return mk('sha256su0', [v(rd, '4s'), v(rn, '4s')]);
    return unknown(w);
  }
  if (top === 0xce) {
    if (!bit(w, 23) && !bit(w, 15)) {
      const op0 = bits(w, 22, 21);
      const ra = bits(w, 14, 10);
      if (op0 === 0) return mk('eor3', [v(rd, '16b'), v(rn, '16b'), v(rm, '16b'), v(ra, '16b')]);
      if (op0 === 1) return mk('bcax', [v(rd, '16b'), v(rn, '16b'), v(rm, '16b'), v(ra, '16b')]);
      if (op0 === 2) return mk('sm3ss1', [v(rd, '4s'), v(rn, '4s'), v(rm, '4s'), v(ra, '4s')]);
      return unknown(w);
    }
    if (bits(w, 23, 21) === 2 && bits(w, 15, 14) === 2) {
      const m = ['sm3tt1a', 'sm3tt1b', 'sm3tt2a', 'sm3tt2b'][bits(w, 11, 10)]!;
      return mk(m, [v(rd, '4s'), v(rn, '4s'), el(rm, 's', bits(w, 13, 12))]);
    }
    if (bits(w, 23, 21) === 3 && bits(w, 15, 12) === 8) {
      const opcode = bits(w, 11, 10);
      if (opcode === 0) return mk('sha512h', [sc('q', rd), sc('q', rn), v(rm, '2d')]);
      if (opcode === 1) return mk('sha512h2', [sc('q', rd), sc('q', rn), v(rm, '2d')]);
      return mk(opcode === 2 ? 'sha512su1' : 'rax1', [v(rd, '2d'), v(rn, '2d'), v(rm, '2d')]);
    }
    if (bits(w, 23, 21) === 3 && bits(w, 15, 12) === 12) {
      const m = ['sm3partw1', 'sm3partw2', 'sm4ekey', ''][bits(w, 11, 10)];
      return m ? mk(m, [v(rd, '4s'), v(rn, '4s'), v(rm, '4s')]) : unknown(w);
    }
    if (bits(w, 23, 21) === 4) return mk('xar', [v(rd, '2d'), v(rn, '2d'), v(rm, '2d'), imm(bits(w, 15, 10))]);
    if (bits(w, 23, 10) === 0x3020) return mk('sha512su0', [v(rd, '2d'), v(rn, '2d')]);
    if (bits(w, 23, 10) === 0x3021) return mk('sm4e', [v(rd, '4s'), v(rn, '4s')]);
  }
  return unknown(w);
}

/* ------------------------------------------------------------------ *
 * Structure loads and stores
 * ------------------------------------------------------------------ */

const MULTIPLE: Record<number, [string, number, number]> = {
  0: ['4', 4, 1], 2: ['1', 4, 4], 4: ['3', 3, 1], 6: ['1', 3, 3], 7: ['1', 1, 1], 8: ['2', 2, 1], 10: ['1', 2, 2],
};

export function decodeSimdStructure(w: number): Insn {
  const q = bit(w, 30);
  const l = bit(w, 22);
  const post = bit(w, 23);
  const rm = bits(w, 20, 16);
  const rn = bits(w, 9, 5);
  const rt = bits(w, 4, 0);
  const base = xs(rn);
  const flags = l ? F.LOAD : F.STORE;
  if (!bit(w, 24)) {
    if (bit(w, 21) || (!post && rm)) return unknown(w);
    const opcode = bits(w, 15, 12);
    const size = bits(w, 11, 10);
    const info = MULTIPLE[opcode];
    if (!info || (size === 3 && !q && info[0] !== '1')) return unknown(w);
    const [n, regs] = info;
    const a = arr(size, q);
    const bytes = (q ? 16 : 8) * regs;
    const mem: Op = { k: 'mem', base, off: post && rm === 31 ? bytes : 0, mode: post ? 'post' : 'off', post: post ? (rm === 31 ? `#${bytes}` : xr(rm)) : undefined };
    return mk(`${l ? 'ld' : 'st'}${n}`, [text(vectorRegList(rt, regs, a)), mem], flags, { size: 1 << size });
  }
  const r = bit(w, 21);
  const opcode = bits(w, 15, 13);
  const s = bit(w, 12);
  const size = bits(w, 11, 10);
  const selem = (((opcode & 1) << 1) | r) + 1;
  if (!post && rm === 1 && opcode === 4 && !r && !s && size === 1) {
    // FEAT_LRCPC3: one doubleword lane, loaded with acquire or stored with release.
    const mem: Op = { k: 'mem', base, off: 0, mode: 'off' };
    return mk(l ? 'ldap1' : 'stl1', [text(`{ v${rt}.d }[${q}]`), mem], flags, { size: 8 });
  }
  if (!post && rm) return unknown(w);
  if (opcode >= 6) {
    // LDnR: load and replicate to all lanes
    if (!l || s || opcode === 7) {
      if (!(l && !s && opcode === 7)) return unknown(w);
    }
    const a = arr(size, q);
    const bytes = selem << size;
    const mem: Op = { k: 'mem', base, off: 0, mode: post ? 'post' : 'off', post: post ? (rm === 31 ? `#${bytes}` : xr(rm)) : undefined };
    return mk(`ld${selem}r`, [text(vectorRegList(rt, selem, a)), mem], F.LOAD, { size: 1 << size });
  }
  let t: string;
  let index: number;
  let esize: number;
  if (opcode < 2) {
    t = 'b';
    esize = 1;
    index = (q << 3) | (s << 2) | size;
  } else if (opcode < 4) {
    if (size & 1) return unknown(w);
    t = 'h';
    esize = 2;
    index = (q << 2) | (s << 1) | (size >> 1);
  } else if (size === 0) {
    t = 's';
    esize = 4;
    index = (q << 1) | s;
  } else if (size === 1 && !s) {
    t = 'd';
    esize = 8;
    index = q;
  } else return unknown(w);
  const regs = [];
  for (let i = 0; i < selem; i++) regs.push(`v${(rt + i) % 32}.${t}`);
  const bytes = selem * esize;
  const mem: Op = { k: 'mem', base, off: 0, mode: post ? 'post' : 'off', post: post ? (rm === 31 ? `#${bytes}` : xr(rm)) : undefined };
  return mk(`${l ? 'ld' : 'st'}${selem}`, [text(`{ ${regs.join(', ')} }[${index}]`), mem], flags, { size: esize });
}

/* ------------------------------------------------------------------ */

export function decodeSimd(w: number, _pc: number): Insn {
  const op0 = bits(w, 31, 28);
  if (op0 === 0xc || op0 === 0xd) return op0 === 0xc ? crypto(w) : unknown(w);
  if ((op0 & 5) === 1) return scalarFp(w);
  if (op0 === 4 || op0 === 5) {
    const c = crypto(w);
    if (!(c.f & F.UNKNOWN)) return c;
  }
  if ((op0 & 0xd) === 5) return advSimdScalar(w);
  if (!(op0 & 9)) return advSimdVector(w);
  return unknown(w);
}

// sext is re-exported for symmetry with decode.ts helpers used by tests.
export { sext };
