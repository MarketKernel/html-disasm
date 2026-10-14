/**
 * The AArch64 decoder: one 32-bit word in, one instruction out.
 *
 * It follows the top-level encoding table of the Arm Architecture Reference
 * Manual — data processing with an immediate, branches and system
 * instructions, loads and stores, data processing on registers, and SIMD and
 * floating point (in simd.ts) — and prints the preferred alias where the
 * manual (and LLVM) do: `mov` for `orr x0, xzr, x1`, `cmp` for `subs xzr, …`,
 * `lsl` for `ubfm`, `cset` for `csinc`. tools/verify-decoder.mjs compares the
 * output with llvm-objdump instruction by instruction.
 *
 * SVE and SME, which macOS user code does not run outside streaming mode,
 * are left undecoded and shown as `.inst`.
 */

import { decodeSimd, decodeSimdStructure } from './simd';
import { sysregName } from './sysreg';
import { CONDITIONS, F, hex, imm, immText, reg, shift, text, type Insn, type Op } from './types';

export const bits = (w: number, hi: number, lo: number): number => (w >>> lo) & (hi - lo === 31 ? 0xffffffff : (1 << (hi - lo + 1)) - 1);
export const bit = (w: number, n: number): number => (w >>> n) & 1;
export const sext = (v: number, width: number): number => (v << (32 - width)) >> (32 - width);

export const xr = (n: number): string => (n === 31 ? 'xzr' : `x${n}`);
export const wr = (n: number): string => (n === 31 ? 'wzr' : `w${n}`);
export const xs = (n: number): string => (n === 31 ? 'sp' : `x${n}`);
export const ws = (n: number): string => (n === 31 ? 'wsp' : `w${n}`);
export const gr = (sf: number, n: number): string => (sf ? xr(n) : wr(n));
export const gs = (sf: number, n: number): string => (sf ? xs(n) : ws(n));

const cond = (c: number): string => CONDITIONS[c & 15] ?? 'al';
const invert = (c: number): string => cond(c ^ 1);

export function unknown(word: number): Insn {
  return { m: '.inst', ops: [immText(word, `0x${(word >>> 0).toString(16).padStart(8, '0')}`)], f: F.UNKNOWN };
}

const mk = (m: string, ops: Op[], f = 0, extra?: Partial<Insn>): Insn => ({ m, ops, f, ...extra });

/** Logical immediates: a rotated run of ones, replicated across the register (DecodeBitMasks). */
export function decodeBitMask(n: number, imms: number, immr: number, width: number): bigint | null {
  const combined = (n << 6) | (~imms & 0x3f);
  if (combined === 0) return null;
  const len = 31 - Math.clz32(combined);
  if (len < 1) return null;
  if (width === 32 && n) return null;
  const levels = (1 << len) - 1;
  const s = imms & levels;
  const r = immr & levels;
  if (s === levels) return null;
  const esize = 1 << len;
  const emask = (1n << BigInt(esize)) - 1n;
  let elem = (1n << BigInt(s + 1)) - 1n;
  if (r) elem = ((elem >> BigInt(r)) | (elem << BigInt(esize - r))) & emask;
  let out = 0n;
  for (let i = 0; i < width; i += esize) out |= elem << BigInt(i);
  return out;
}

/**
 * Whether a value fits one movz or movn. LLVM prints `orr x0, xzr, #imm` as
 * `mov x0, #imm` only when it does not — otherwise the mov would be read as
 * the wide-immediate form.
 */
function movWideFits(value: bigint, width: number): boolean {
  const mask = (1n << BigInt(width)) - 1n;
  const single = (v: bigint) => {
    for (let shift = 0n; shift < BigInt(width); shift += 16n) if ((v & ~(0xffffn << shift) & mask) === 0n) return true;
    return false;
  };
  return single(value & mask) || single(~value & mask);
}

const signed = (v: bigint, width: number): bigint => (v >= 1n << BigInt(width - 1) ? v - (1n << BigInt(width)) : v);
const bigImm = (v: bigint): Op => immText(Number(v), `#${hex(v)}`);

/* ------------------------------------------------------------------ *
 * Data processing — immediate
 * ------------------------------------------------------------------ */

function dpImm(w: number, pc: number): Insn {
  const op0 = bits(w, 25, 23);
  const rd = bits(w, 4, 0);
  const rn = bits(w, 9, 5);
  const sf = bit(w, 31);
  switch (op0) {
    case 0:
    case 1: {
      const lo = bits(w, 30, 29);
      const hi = sext(bits(w, 23, 5), 19);
      if (bit(w, 31)) {
        const target = Math.floor(pc / 4096) * 4096 + (hi * 4 + lo) * 4096;
        return mk('adrp', [reg(xr(rd)), { k: 'label', addr: target }], 0, { target });
      }
      const target = pc + hi * 4 + lo;
      return mk('adr', [reg(xr(rd)), { k: 'label', addr: target }], 0, { target });
    }
    case 2: {
      const op = bit(w, 30);
      const s = bit(w, 29);
      const sh = bit(w, 22);
      const value = bits(w, 21, 10);
      const ops: Op[] = sh ? [imm(value), shift('lsl', 12)] : [imm(value)];
      if (!op && !s && !sh && value === 0 && (rd === 31 || rn === 31)) return mk('mov', [reg(gs(sf, rd)), reg(gs(sf, rn))]);
      if (s && rd === 31) return mk(op ? 'cmp' : 'cmn', [reg(gs(sf, rn)), ...ops], F.SETS_FLAGS);
      const m = (op ? 'sub' : 'add') + (s ? 's' : '');
      return mk(m, [reg(s ? gr(sf, rd) : gs(sf, rd)), reg(gs(sf, rn)), ...ops], s ? F.SETS_FLAGS : 0);
    }
    case 3: {
      if (bit(w, 22)) {
        // SMAX/UMAX/SMIN/UMIN with an 8-bit immediate (FEAT_CSSC), signed for the s forms.
        const opc = bits(w, 21, 18);
        if (bits(w, 30, 29) || opc > 3) return unknown(w);
        const value = bits(w, 17, 10);
        return mk(['smax', 'umax', 'smin', 'umin'][opc]!, [reg(gr(sf, rd)), reg(gr(sf, rn)), imm(opc & 1 ? value : sext(value, 8))]);
      }
      // ADDG/SUBG (memory tagging)
      if (!sf || bit(w, 29)) return unknown(w);
      const m = bit(w, 30) ? 'subg' : 'addg';
      return mk(m, [reg(xs(rd)), reg(xs(rn)), imm(bits(w, 21, 16) * 16), imm(bits(w, 13, 10))]);
    }
    case 4: {
      const opc = bits(w, 30, 29);
      const n = bit(w, 22);
      const immr = bits(w, 21, 16);
      const imms = bits(w, 15, 10);
      const width = sf ? 64 : 32;
      const value = decodeBitMask(n, imms, immr, width);
      if (value === null) return unknown(w);
      const op = bigImm(value);
      if (opc === 3) {
        if (rd === 31) return mk('tst', [reg(gr(sf, rn)), op], F.SETS_FLAGS);
        return mk('ands', [reg(gr(sf, rd)), reg(gr(sf, rn)), op], F.SETS_FLAGS);
      }
      if (opc === 1 && rn === 31 && !movWideFits(value, width)) return mk('mov', [reg(gs(sf, rd)), bigImm(signed(value, width))]);
      return mk(['and', 'orr', 'eor'][opc]!, [reg(gs(sf, rd)), reg(gr(sf, rn)), op]);
    }
    case 5: {
      const opc = bits(w, 30, 29);
      const hw = bits(w, 22, 21);
      const value = bits(w, 20, 5);
      if (opc === 1 || (!sf && hw > 1)) return unknown(w);
      const width = sf ? 64 : 32;
      const amount = hw * 16;
      if (opc === 3) return mk('movk', [reg(gr(sf, rd)), imm(value), ...(amount ? [shift('lsl', amount)] : [])]);
      const plain = !(value === 0 && hw !== 0);
      if (opc === 2 && plain) return mk('mov', [reg(gr(sf, rd)), bigImm(signed(BigInt(value) << BigInt(amount), width))]);
      if (opc === 0 && plain && (sf || value !== 0xffff)) {
        const mask = (1n << BigInt(width)) - 1n;
        return mk('mov', [reg(gr(sf, rd)), bigImm(signed(~(BigInt(value) << BigInt(amount)) & mask, width))]);
      }
      return mk(opc === 2 ? 'movz' : 'movn', [reg(gr(sf, rd)), imm(value), ...(amount ? [shift('lsl', amount)] : [])]);
    }
    case 6: {
      const opc = bits(w, 30, 29);
      const n = bit(w, 22);
      const immr = bits(w, 21, 16);
      const imms = bits(w, 15, 10);
      if (opc === 3 || n !== sf || (!sf && (immr > 31 || imms > 31))) return unknown(w);
      const width = sf ? 64 : 32;
      const top = width - 1;
      const d = reg(gr(sf, rd));
      const s = reg(gr(sf, rn));
      const dec = (v: number) => imm(v, true);
      if (opc === 0) {
        if (imms === top) return mk('asr', [d, s, dec(immr)]);
        if (imms < immr) return mk('sbfiz', [d, s, dec(width - immr), dec(imms + 1)]);
        if (immr === 0 && (imms === 7 || imms === 15 || imms === 31)) {
          const m = imms === 7 ? 'sxtb' : imms === 15 ? 'sxth' : 'sxtw';
          if (!(m === 'sxtw' && !sf)) return mk(m, [d, reg(wr(rn))]);
        }
        return mk('sbfx', [d, s, dec(immr), dec(imms - immr + 1)]);
      }
      if (opc === 1) {
        if (imms < immr) {
          return mk('bfi', [d, s, dec(width - immr), dec(imms + 1)]);
        }
        return mk('bfxil', [d, s, dec(immr), dec(imms - immr + 1)]);
      }
      if (imms !== top && imms + 1 === immr) return mk('lsl', [d, s, dec(top - imms)]);
      if (imms === top) return mk('lsr', [d, s, dec(immr)]);
      if (imms < immr) return mk('ubfiz', [d, s, dec(width - immr), dec(imms + 1)]);
      if (immr === 0 && !sf && (imms === 7 || imms === 15)) return mk(imms === 7 ? 'uxtb' : 'uxth', [d, reg(wr(rn))]);
      return mk('ubfx', [d, s, dec(immr), dec(imms - immr + 1)]);
    }
    default: {
      if (bits(w, 31, 22) === 0x3ce) {
        // AUTIASPPC / AUTIBSPPC (FEAT_PAuth_LR): the label is where the return address was signed.
        if (rd !== 31) return unknown(w);
        return mk(bit(w, 21) ? 'autibsppc' : 'autiasppc', [{ k: 'label', addr: pc - bits(w, 20, 5) * 4 }]);
      }
      const op21 = bits(w, 30, 29);
      const n = bit(w, 22);
      const o0 = bit(w, 21);
      const rm = bits(w, 20, 16);
      const lsb = bits(w, 15, 10);
      if (op21 || o0 || n !== sf || (!sf && lsb > 31)) return unknown(w);
      if (rn === rm) return mk('ror', [reg(gr(sf, rd)), reg(gr(sf, rn)), imm(lsb)]);
      return mk('extr', [reg(gr(sf, rd)), reg(gr(sf, rn)), reg(gr(sf, rm)), imm(lsb)]);
    }
  }
}

/* ------------------------------------------------------------------ *
 * Branches, exception generation, system
 * ------------------------------------------------------------------ */

export const HINTS: Record<number, string> = {
  0: 'nop', 1: 'yield', 2: 'wfe', 3: 'wfi', 4: 'sev', 5: 'sevl', 6: 'dgh', 7: 'xpaclri',
  8: 'pacia1716', 10: 'pacib1716', 12: 'autia1716', 14: 'autib1716',
  16: 'esb', 17: 'psb csync', 18: 'tsb csync', 19: 'gcsb dsync', 20: 'csdb', 22: 'clrbhb',
  24: 'paciaz', 25: 'paciasp', 26: 'pacibz', 27: 'pacibsp', 28: 'autiaz', 29: 'autiasp', 30: 'autibz', 31: 'autibsp',
  32: 'bti r', 34: 'bti c', 36: 'bti j', 38: 'bti jc', 39: 'pacm', 40: 'chkfeat x16',
};
export const BARRIERS: Record<number, string> = { 1: 'oshld', 2: 'oshst', 3: 'osh', 5: 'nshld', 6: 'nshst', 7: 'nsh', 9: 'ishld', 10: 'ishst', 11: 'ish', 13: 'ld', 14: 'st', 15: 'sy' };
const PSTATE: Record<string, string> = { '0,5': 'SPSel', '3,6': 'DAIFSet', '3,7': 'DAIFClr', '0,3': 'UAO', '0,4': 'PAN', '3,2': 'DIT', '3,1': 'SSBS', '3,4': 'TCO' };

/**
 * SYS operations LLVM names, by op1, CRn, CRm, op2: cache maintenance, the
 * speculation-restriction and trace operations, and the Guarded Control Stack
 * pushes and pops. `reg` says whether the operation takes Xt; one that does not
 * gets its name only when Xt is xzr (`gcspushx`), except the instruction-cache
 * invalidates, which LLVM names whatever Xt holds. TLB and address-translation
 * operations, which only an operating system runs, stay `sys`.
 */
const SYS_OPS: Record<string, [string, string, 'reg' | 'none' | 'any']> = {
  '0,7,1,0': ['ic', 'ialluis', 'any'], '0,7,5,0': ['ic', 'iallu', 'any'], '3,7,5,1': ['ic', 'ivau', 'reg'],
  '3,7,4,1': ['dc', 'zva', 'reg'], '3,7,10,1': ['dc', 'cvac', 'reg'], '3,7,11,1': ['dc', 'cvau', 'reg'], '3,7,14,1': ['dc', 'civac', 'reg'],
  '3,7,12,1': ['dc', 'cvap', 'reg'], '3,7,13,1': ['dc', 'cvadp', 'reg'], '0,7,6,1': ['dc', 'ivac', 'reg'], '0,7,6,2': ['dc', 'isw', 'reg'],
  '0,7,10,2': ['dc', 'csw', 'reg'], '0,7,14,2': ['dc', 'cisw', 'reg'], '0,7,15,1': ['dc', 'civaps', 'reg'],
  '0,7,6,3': ['dc', 'igvac', 'reg'], '0,7,6,4': ['dc', 'igsw', 'reg'], '0,7,6,5': ['dc', 'igdvac', 'reg'], '0,7,6,6': ['dc', 'igdsw', 'reg'],
  '0,7,10,4': ['dc', 'cgsw', 'reg'], '0,7,10,6': ['dc', 'cgdsw', 'reg'], '0,7,14,4': ['dc', 'cigsw', 'reg'], '0,7,14,6': ['dc', 'cigdsw', 'reg'],
  '0,7,15,5': ['dc', 'cigdvaps', 'reg'],
  '3,7,4,3': ['dc', 'gva', 'reg'], '3,7,4,4': ['dc', 'gzva', 'reg'], '3,7,4,5': ['dc', 'zgbva', 'reg'], '3,7,4,7': ['dc', 'gbva', 'reg'],
  '3,7,10,3': ['dc', 'cgvac', 'reg'], '3,7,10,5': ['dc', 'cgdvac', 'reg'], '3,7,12,3': ['dc', 'cgvap', 'reg'], '3,7,12,5': ['dc', 'cgdvap', 'reg'],
  '3,7,13,3': ['dc', 'cgvadp', 'reg'], '3,7,13,5': ['dc', 'cgdvadp', 'reg'], '3,7,14,3': ['dc', 'cigvac', 'reg'], '3,7,14,5': ['dc', 'cigdvac', 'reg'],
  '3,7,11,0': ['dc', 'cvaoc', 'reg'], '3,7,11,7': ['dc', 'cgdvaoc', 'reg'], '3,7,15,0': ['dc', 'civaoc', 'reg'], '3,7,15,7': ['dc', 'cigdvaoc', 'reg'],
  '4,7,14,0': ['dc', 'cipae', 'reg'], '4,7,14,7': ['dc', 'cigdpae', 'reg'], '6,7,14,1': ['dc', 'cipapa', 'reg'], '6,7,14,5': ['dc', 'cigdpapa', 'reg'],
  '3,7,3,4': ['cfp', 'rctx', 'reg'], '3,7,3,5': ['dvp', 'rctx', 'reg'], '3,7,3,6': ['cosp', 'rctx', 'reg'], '3,7,3,7': ['cpp', 'rctx', 'reg'],
  '3,7,2,7': ['trcit', '', 'reg'], '6,7,0,0': ['apas', '', 'reg'], '1,7,2,4': ['brb', 'iall', 'none'], '1,7,2,5': ['brb', 'inj', 'none'],
  '3,7,7,0': ['gcspushm', '', 'reg'], '3,7,7,2': ['gcsss1', '', 'reg'],
  '0,7,7,4': ['gcspushx', '', 'none'], '0,7,7,5': ['gcspopcx', '', 'none'], '0,7,7,6': ['gcspopx', '', 'none'],
};

/** Op0 = 0 with L = 0: hints, barriers, PSTATE fields and a few more; anything else is a plain msr. */
function systemOp0(w: number): Insn {
  const op1 = bits(w, 18, 16);
  const crn = bits(w, 15, 12);
  const crm = bits(w, 11, 8);
  const op2 = bits(w, 7, 5);
  const rt = bits(w, 4, 0);
  if (crn === 2 && rt === 31 && op1 === 3) {
    const value = (crm << 3) | op2;
    const name = HINTS[value];
    return name ? mk(name.split(' ')[0]!, name.includes(' ') ? [text(name.split(' ')[1]!)] : []) : mk('hint', [imm(value)]);
  }
  if (crn === 3 && rt === 31 && op1 === 3) {
    // Barrier numbers without a name print in decimal.
    const option = (names: Record<number, string>) => (names[crm] ? text(names[crm]!) : imm(crm, true));
    switch (op2) {
      case 1:
        // DSB with the nXS qualifier (FEAT_XS): the domain is in CRm<3:2>.
        if ((crm & 3) === 2) return mk('dsb', [text(`${['osh', 'nsh', 'ish', 'sy'][crm >> 2]}nxs`)]);
        break;
      case 2:
        return mk('clrex', crm === 15 ? [] : [imm(crm)]);
      case 3:
        if (crm === 0) return mk('tcommit', []);
        break;
      case 4:
        if (crm === 0) return mk('ssbb', []);
        if (crm === 4) return mk('pssbb', []);
        if (crm === 12) return mk('dfb', []);
        return mk('dsb', [option(BARRIERS)]);
      case 5:
        return mk('dmb', [option(BARRIERS)]);
      case 6:
        return mk('isb', crm === 15 ? [] : [imm(crm, true)]);
      case 7:
        return mk('sb', []);
    }
  }
  if (crn === 4 && rt === 31) {
    if (op1 === 0 && op2 < 3) return mk(['cfinv', 'xaflag', 'axflag'][op2]!, [], F.SETS_FLAGS | F.READS_FLAGS);
    if (op1 === 3 && op2 === 3) {
      // SVCR: SMSTART / SMSTOP; CRm<2:1> picks SM, ZA or both, CRm<0> the value.
      const which = (crm >> 1) & 3;
      if (crm < 8 && which) return mk(crm & 1 ? 'smstart' : 'smstop', which === 1 ? [text('sm')] : which === 2 ? [text('za')] : []);
    } else if (op1 === 1 && op2 === 0) {
      // ALLINT (FEAT_NMI) and PM (FEAT_EBEP) take a single bit from CRm<0>.
      if (crm < 4) return mk('msr', [text(crm < 2 ? 'ALLINT' : 'PM'), imm(crm & 1)]);
    } else {
      const field = PSTATE[`${op1},${op2}`];
      if (field) return mk('msr', [text(field), imm(crm)]);
    }
  }
  if (op1 === 3 && crn === 1 && crm === 0 && op2 < 2) return mk(op2 ? 'wfit' : 'wfet', [reg(xr(rt))]);
  if (op1 === 1 && crn === 9 && crm === 6 && rt === 31) return mk('stshh', [op2 < 2 ? text(op2 ? 'strm' : 'keep') : imm(op2)]);
  return mk('msr', [text(sysregName(0, op1, crn, crm, op2)), reg(xr(rt))]);
}

function system(w: number): Insn {
  const l = bit(w, 21);
  const op0 = bits(w, 20, 19);
  const op1 = bits(w, 18, 16);
  const crn = bits(w, 15, 12);
  const crm = bits(w, 11, 8);
  const op2 = bits(w, 7, 5);
  const rt = bits(w, 4, 0);
  if (op0 === 0) {
    if (!l) return systemOp0(w);
    // TSTART and TTEST (transactional memory) read into Xt; the rest of this space is mrs.
    if (op1 === 3 && crn === 3 && crm < 2 && op2 === 3) return mk(crm ? 'ttest' : 'tstart', [reg(xr(rt))]);
    return mk('mrs', [reg(xr(rt)), text(sysregName(0, op1, crn, crm, op2))]);
  }
  if (op0 === 1) {
    const sys = [imm(op1), text(`c${crn}`), text(`c${crm}`), imm(op2)];
    if (l) {
      // GCSPOPM and GCSSS2 return a value from the Guarded Control Stack.
      if (op1 === 3 && crn === 7 && crm === 7 && op2 === 1) return mk('gcspopm', rt === 31 ? [] : [reg(xr(rt))]);
      if (op1 === 3 && crn === 7 && crm === 7 && op2 === 3) return mk('gcsss2', [reg(xr(rt))]);
      return mk('sysl', [reg(xr(rt)), ...sys]);
    }
    const named = SYS_OPS[`${op1},${crn},${crm},${op2}`];
    if (named) {
      const [m, op, takes] = named;
      const first = op ? [text(op)] : [];
      if (takes === 'reg') return mk(m, [...first, reg(xr(rt))]);
      if (takes === 'any' || rt === 31) return mk(m, first);
    }
    return mk('sys', rt === 31 ? sys : [...sys, reg(xr(rt))]);
  }
  const name = sysregName(op0, op1, crn, crm, op2);
  return l ? mk('mrs', [reg(xr(rt)), text(name)], name === 'NZCV' ? F.READS_FLAGS : 0) : mk('msr', [text(name), reg(xr(rt))], name === 'NZCV' ? F.SETS_FLAGS : 0);
}

/**
 * The 128-bit system instructions (FEAT_SYSREG128, FEAT_SYSINSTR128): MRRS and
 * MSRR move a register pair, SYSP is SYS with a pair. Xt must be even; x30
 * pairs with xzr.
 */
function systemPair(w: number): Insn {
  const l = bit(w, 21);
  const op0 = bits(w, 20, 19);
  const op1 = bits(w, 18, 16);
  const crn = bits(w, 15, 12);
  const crm = bits(w, 11, 8);
  const op2 = bits(w, 7, 5);
  const rt = bits(w, 4, 0);
  if (rt & 1 && rt !== 31) return unknown(w);
  const pair = rt === 31 ? [] : [reg(xr(rt)), reg(xr(rt + 1))];
  const name = sysregName(op0, op1, crn, crm, op2);
  if (l) return rt === 31 ? unknown(w) : mk('mrrs', [...pair, text(name)]);
  if (op0 !== 1) return rt === 31 ? unknown(w) : mk('msrr', [text(name), ...pair]);
  return mk('sysp', [imm(op1), text(`c${crn}`), text(`c${crm}`), imm(op2), ...pair]);
}

/** TCHANGEF / TCHANGEB (FEAT_S1POE2): change the permission-overlay TIndex to Xn or an immediate. */
function tchange(w: number): Insn {
  const m = bit(w, 18) ? 'tchangeb' : 'tchangef';
  if (bit(w, 21) || bit(w, 19) || bit(w, 16)) return unknown(w);
  const nb = bit(w, 17) ? [text('nb')] : [];
  if (bit(w, 20)) return bits(w, 15, 12) ? unknown(w) : mk(m, [reg(xr(bits(w, 4, 0))), imm(bits(w, 11, 5)), ...nb]);
  return bits(w, 15, 10) ? unknown(w) : mk(m, [reg(xr(bits(w, 4, 0))), reg(xr(bits(w, 9, 5))), ...nb]);
}

const CB_IMM = ['gt', 'lt', 'hi', 'lo', '', '', 'eq', 'ne'];
const CB_REG = ['gt', 'ge', 'hi', 'hs', '', '', 'eq', 'ne'];

/**
 * CB<cc> (FEAT_CMPBR): compare a register with a register or a 6-bit
 * immediate and branch, without touching the flags. CBB and CBH compare the
 * low byte or halfword. LLVM prints the encoded condition, never the swapped
 * aliases (cblt for cbgt with the registers exchanged).
 */
function compareBranch(w: number, pc: number): Insn {
  const sf = bit(w, 31);
  const rt = bits(w, 4, 0);
  const target = pc + sext(bits(w, 13, 5), 9) * 4;
  const label: Op = { k: 'label', addr: target };
  if (bit(w, 24)) {
    const c = CB_IMM[bits(w, 23, 21)]!;
    if (!c || bit(w, 14)) return unknown(w);
    return mk(`cb${c}`, [reg(gr(sf, rt)), imm(bits(w, 20, 15)), label], F.BRANCH | F.COND, { target, cond: c });
  }
  const c = CB_REG[bits(w, 23, 21)]!;
  const width = bits(w, 15, 14);
  if (!c || width === 1 || (width && sf)) return unknown(w);
  const m = `cb${width === 2 ? 'b' : width === 3 ? 'h' : ''}${c}`;
  return mk(m, [reg(gr(sf, rt)), reg(gr(sf, bits(w, 20, 16))), label], F.BRANCH | F.COND, { target, cond: c });
}

function branches(w: number, pc: number): Insn {
  const op0 = bits(w, 31, 29);
  if ((op0 & 3) === 0 && !bit(w, 30)) {
    // B / BL
    const target = pc + sext(bits(w, 25, 0), 26) * 4;
    return bit(w, 31) ? mk('bl', [{ k: 'label', addr: target }], F.CALL, { target }) : mk('b', [{ k: 'label', addr: target }], F.BRANCH, { target });
  }
  if ((op0 & 3) === 1) {
    if (!bit(w, 25)) {
      const sf = bit(w, 31);
      const target = pc + sext(bits(w, 23, 5), 19) * 4;
      return mk(bit(w, 24) ? 'cbnz' : 'cbz', [reg(gr(sf, bits(w, 4, 0))), { k: 'label', addr: target }], F.BRANCH | F.COND, { target });
    }
    const b5 = bit(w, 31);
    const number = (b5 << 5) | bits(w, 23, 19);
    const target = pc + sext(bits(w, 18, 5), 14) * 4;
    return mk(bit(w, 24) ? 'tbnz' : 'tbz', [reg(gr(b5, bits(w, 4, 0))), imm(number), { k: 'label', addr: target }], F.BRANCH | F.COND, { target });
  }
  if ((op0 & 3) === 3 && !bit(w, 25)) return compareBranch(w, pc);
  if (op0 === 2) {
    if (bits(w, 25, 24) === 1 && bits(w, 23, 22) === 0 && bits(w, 4, 0) === 31) {
      // RETAASPPC / RETABSPPC (FEAT_PAuth_LR): return, authenticating against the signing address.
      return mk(bit(w, 21) ? 'retabsppc' : 'retaasppc', [{ k: 'label', addr: pc - bits(w, 20, 5) * 4 }], F.BRANCH | F.RET | F.INDIRECT);
    }
    if (bit(w, 25) || bit(w, 24)) return unknown(w);
    const target = pc + sext(bits(w, 23, 5), 19) * 4;
    const c = cond(bits(w, 3, 0));
    const consistent = bit(w, 4);
    return mk(`${consistent ? 'bc' : 'b'}.${c}`, [{ k: 'label', addr: target }], F.BRANCH | (c === 'al' || c === 'nv' ? 0 : F.COND) | F.READS_FLAGS, { target, cond: c });
  }
  if (op0 === 6) {
    if (bits(w, 25, 24) === 0) {
      const opc = bits(w, 23, 21);
      const ll = bits(w, 1, 0);
      const value = bits(w, 20, 5);
      if (bits(w, 4, 2)) return unknown(w);
      const name = ['', 'brk', 'hlt', 'tcancel', '', 'dcps', '', ''][opc];
      if (opc === 0) {
        const m = ['', 'svc', 'hvc', 'smc'][ll];
        return m ? mk(m, [imm(value)]) : unknown(w);
      }
      if (opc === 5) return ll ? mk(`dcps${ll}`, value ? [imm(value)] : []) : unknown(w);
      if (opc === 7) {
        // TENTER (FEAT_TEV): an exception-like entry through the vector the 7-bit immediate picks.
        // Like svc, execution comes back to the next instruction (through TEXIT).
        if (ll || value & ~0x107f) return unknown(w);
        return mk('tenter', [imm(value & 0x7f), ...(value & 0x1000 ? [text('nb')] : [])]);
      }
      if (!name || ll) return unknown(w);
      return mk(name, [imm(value)], opc === 1 || opc === 2 ? F.TRAP : 0);
    }
    if (bits(w, 25, 22) === 4) return system(w);
    if (bits(w, 25, 22) === 5) return systemPair(w);
    if (bits(w, 25, 22) === 6) return tchange(w);
    if (bit(w, 25)) {
      const opc = bits(w, 24, 21);
      const op2 = bits(w, 20, 16);
      const op3 = bits(w, 15, 10);
      const rn = bits(w, 9, 5);
      const op4 = bits(w, 4, 0);
      if (op2 !== 31) return unknown(w);
      if (op3 === 0 && op4 === 0) {
        if (opc === 0) return mk('br', [reg(xr(rn))], F.BRANCH | F.INDIRECT);
        if (opc === 1) return mk('blr', [reg(xr(rn))], F.CALL | F.INDIRECT);
        if (opc === 2) return mk('ret', rn === 30 ? [] : [reg(xr(rn))], F.BRANCH | F.RET | F.INDIRECT);
        if (opc === 4 && rn === 31) return mk('eret', [], F.BRANCH | F.RET);
        if (opc === 7 && rn === 31) return mk('texit', [], F.BRANCH | F.RET);
        if (opc === 5 && rn === 31) return mk('drps', [], F.BRANCH);
      }
      if (opc === 7 && op3 === 1 && rn === 31 && op4 === 0) return mk('texit', [text('nb')], F.BRANCH | F.RET);
      if ((op3 & 0x3e) === 2) {
        const key = op3 & 1 ? 'b' : 'a';
        if (opc === 0 && op4 === 31) return mk(`bra${key}z`, [reg(xr(rn))], F.BRANCH | F.INDIRECT);
        if (opc === 1 && op4 === 31) return mk(`blra${key}z`, [reg(xr(rn))], F.CALL | F.INDIRECT);
        if (opc === 2 && rn === 31 && op4 === 31) return mk(`reta${key}`, [], F.BRANCH | F.RET | F.INDIRECT);
        if (opc === 2 && rn === 31) return mk(`reta${key}sppcr`, [reg(xr(op4))], F.BRANCH | F.RET | F.INDIRECT);
        if (opc === 4 && rn === 31 && op4 === 31) return mk(`ereta${key}`, [], F.BRANCH | F.RET);
        if (opc === 8) return mk(`bra${key}`, [reg(xr(rn)), reg(xs(op4))], F.BRANCH | F.INDIRECT);
        if (opc === 9) return mk(`blra${key}`, [reg(xr(rn)), reg(xs(op4))], F.CALL | F.INDIRECT);
      }
      return unknown(w);
    }
  }
  return unknown(w);
}

/* ------------------------------------------------------------------ *
 * Loads and stores
 * ------------------------------------------------------------------ */

interface Access {
  load: boolean;
  /** Suffix after ldr/ldur/ldtr: '', 'b', 'h', 'sb', 'sh', 'sw'. */
  ext: string;
  rt: (n: number) => string;
  bytes: number;
  signed?: boolean;
  prefetch?: boolean;
}

const fpReg = (prefix: string) => (n: number) => `${prefix}${n}`;

/** What size, V and opc of a single-register load or store mean. */
function access(size: number, v: number, opc: number): Access | null {
  if (v) {
    if (opc & 2) return size === 0 ? { load: !!(opc & 1), ext: '', rt: fpReg('q'), bytes: 16 } : null;
    return { load: !!(opc & 1), ext: '', rt: fpReg('bhsd'[size]!), bytes: 1 << size };
  }
  const bytes = 1 << size;
  const ext = ['b', 'h', '', ''][size]!;
  if (opc === 0) return { load: false, ext, rt: size === 3 ? xr : wr, bytes };
  if (opc === 1) return { load: true, ext, rt: size === 3 ? xr : wr, bytes };
  if (size === 3) return opc === 2 ? { load: true, ext: '', rt: xr, bytes: 8, prefetch: true } : null;
  if (size === 2) return opc === 2 ? { load: true, ext: 'sw', rt: xr, bytes: 4, signed: true } : null;
  return { load: true, ext: size === 0 ? 'sb' : 'sh', rt: opc === 2 ? xr : wr, bytes, signed: true };
}

const PRF_TYPES = ['pld', 'pli', 'pst'];
const RPRF_OPS: Record<number, string> = { 0: 'pldkeep', 1: 'pstkeep', 4: 'pldstrm', 5: 'pststrm' };
function prfop(rt: number): Op {
  const type = rt >> 3;
  const target = (rt >> 1) & 3;
  if (type < 3) return text(`${PRF_TYPES[type]}${target < 3 ? `l${target + 1}` : 'slc'}${rt & 1 ? 'strm' : 'keep'}`);
  return imm(rt);
}

function memFlags(a: Access): number {
  return a.prefetch ? 0 : a.load ? F.LOAD : F.STORE;
}

function single(w: number, form: 'uimm' | 'unscaled' | 'post' | 'pre' | 'unpriv' | 'regoff'): Insn {
  const size = bits(w, 31, 30);
  const v = bit(w, 26);
  const opc = bits(w, 23, 22);
  const rn = bits(w, 9, 5);
  const rt = bits(w, 4, 0);
  const a = access(size, v, opc);
  if (!a) return unknown(w);
  if (form === 'unpriv' && (v || a.prefetch)) return unknown(w);
  if ((form === 'post' || form === 'pre') && a.prefetch) return unknown(w);
  const base = a.load ? 'ld' : 'st';
  const mnemonic = a.prefetch
    ? form === 'unscaled' ? 'prfum' : 'prfm'
    : base + (form === 'unscaled' ? 'ur' : form === 'unpriv' ? 'tr' : 'r') + a.ext;
  const target = a.prefetch ? prfop(rt) : reg(a.rt(rt));
  const extra = { size: a.bytes, signed: a.signed };
  if (form === 'regoff') {
    const rm = bits(w, 20, 16);
    const option = bits(w, 15, 13);
    const s = bit(w, 12);
    if (!(option & 2)) return unknown(w);
    if (a.prefetch && rt >> 3 === 3) {
      // RPRFM: a range prefetch, its operation built from option<2>, option<0>, S and Rt<2:0>; Xm is the range.
      const op = ((option >> 2) << 5) | ((option & 1) << 4) | (s << 3) | (rt & 7);
      return mk('rprfm', [RPRF_OPS[op] ? text(RPRF_OPS[op]!) : imm(op), reg(xr(rm)), { k: 'mem', base: xs(rn), off: 0, mode: 'off' }]);
    }
    const scale = v && opc & 2 ? 4 : size;
    const ext = ['', '', 'uxtw', 'lsl', '', '', 'sxtw', 'sxtx'][option]!;
    const index = option & 1 ? xr(rm) : wr(rm);
    const shown = s === 1;
    const mem: Op = { k: 'mem', base: xs(rn), off: 0, index, mode: 'off', ext: ext === 'lsl' && !shown ? undefined : ext, amount: s ? scale : 0, showAmount: shown };
    return mk(mnemonic, [target, mem], memFlags(a), extra);
  }
  if (form === 'uimm') {
    const scale = v && opc & 2 ? 4 : size;
    const off = bits(w, 21, 10) << scale;
    return mk(mnemonic, [target, { k: 'mem', base: xs(rn), off, mode: 'off' }], memFlags(a), extra);
  }
  const off = sext(bits(w, 20, 12), 9);
  const mode = form === 'post' ? 'post' : form === 'pre' ? 'pre' : 'off';
  return mk(mnemonic, [target, { k: 'mem', base: xs(rn), off, mode }], memFlags(a), extra);
}

function pair(w: number, form: 'noalloc' | 'post' | 'off' | 'pre'): Insn {
  const opc = bits(w, 31, 30);
  const v = bit(w, 26);
  const l = bit(w, 22);
  const imm7 = sext(bits(w, 21, 15), 7);
  const rt2 = bits(w, 14, 10);
  const rn = bits(w, 9, 5);
  const rt = bits(w, 4, 0);
  let name: (n: number) => string;
  let scale: number;
  let mnemonic = form === 'noalloc' ? (l ? 'ldnp' : 'stnp') : l ? 'ldp' : 'stp';
  let signedLoad = false;
  if (opc === 3) {
    // LDTP / STTP (FEAT_LSUI): a pair accessed with user (EL0) permissions, of X or Q registers.
    name = v ? fpReg('q') : xr;
    scale = v ? 4 : 3;
    mnemonic = mnemonic.replace(/^(ld|st)/, '$1t');
  } else if (v) {
    name = fpReg('sdq'[opc]!);
    scale = 2 + opc;
  } else if (opc === 0) {
    name = wr;
    scale = 2;
  } else if (opc === 2) {
    name = xr;
    scale = 3;
  } else if (opc === 1 && l && form !== 'noalloc') {
    name = xr;
    scale = 2;
    mnemonic = 'ldpsw';
    signedLoad = true;
  } else if (opc === 1 && !l && form !== 'noalloc') {
    // STGP (memory tagging): stores two registers and the tag
    name = xr;
    scale = 4;
    mnemonic = 'stgp';
  } else return unknown(w);
  const off = imm7 * (1 << scale);
  const mode = form === 'post' ? 'post' : form === 'pre' ? 'pre' : 'off';
  return mk(mnemonic, [reg(name(rt)), reg(name(rt2)), { k: 'mem', base: xs(rn), off, mode }], l ? F.LOAD : F.STORE, {
    size: mnemonic === 'stgp' ? 8 : 1 << scale,
    signed: signedLoad,
  });
}

/**
 * The FEAT_LSUI exclusives and compare-and-swaps: the same operations as their
 * privileged forms, but checked against user (EL0) permissions.
 */
function exclusiveUnprivileged(w: number): Insn {
  const size = bits(w, 31, 30);
  const o2 = bit(w, 23);
  const l = bit(w, 22);
  const rs = bits(w, 20, 16);
  const o0 = bit(w, 15);
  const rn = bits(w, 9, 5);
  const rt = bits(w, 4, 0);
  const mem: Op = { k: 'mem', base: xs(rn), off: 0, mode: 'off' };
  if (bit(w, 21)) return unknown(w);
  if (!o2) {
    if (size < 2) return unknown(w);
    const r = size === 3 ? xr : wr;
    if (l) return mk(`ld${o0 ? 'a' : ''}txr`, [reg(r(rt)), mem], F.LOAD | F.ATOMIC, { size: 1 << size });
    return mk(`st${o0 ? 'l' : ''}txr`, [reg(wr(rs)), reg(r(rt)), mem], F.STORE | F.ATOMIC, { size: 1 << size });
  }
  const order = `${l ? 'a' : ''}${o0 ? 'l' : ''}`;
  if (size === 3) return mk(`cas${order}t`, [reg(xr(rs)), reg(xr(rt)), mem], F.LOAD | F.STORE | F.ATOMIC, { size: 8 });
  if (size === 1 && !(rs & 1) && !(rt & 1)) {
    return mk(`casp${order}t`, [reg(xr(rs)), reg(xr(rs + 1)), reg(xr(rt)), reg(xr(rt + 1)), mem], F.LOAD | F.STORE | F.ATOMIC, { size: 8 });
  }
  return unknown(w);
}

function exclusive(w: number): Insn {
  const size = bits(w, 31, 30);
  const o2 = bit(w, 23);
  const l = bit(w, 22);
  const o1 = bit(w, 21);
  const rs = bits(w, 20, 16);
  const o0 = bit(w, 15);
  const rt2 = bits(w, 14, 10);
  const rn = bits(w, 9, 5);
  const rt = bits(w, 4, 0);
  const sfx = ['b', 'h', '', ''][size]!;
  const r = size === 3 ? xr : wr;
  const mem: Op = { k: 'mem', base: xs(rn), off: 0, mode: 'off' };
  const bytes = 1 << size;
  if (o2 === 1 && o1 === 1) {
    // CAS, CASA, CASL, CASAL (+B/H)
    if (rt2 !== 31) return unknown(w);
    return mk(`cas${l ? 'a' : ''}${o0 ? 'l' : ''}${sfx}`, [reg(r(rs)), reg(r(rt)), mem], F.LOAD | F.STORE | F.ATOMIC, { size: bytes });
  }
  if (o2 === 0 && o1 === 1) {
    if (size < 2) {
      // CASP, CASPA, CASPL, CASPAL: register pairs
      if (rt2 !== 31 || rs & 1 || rt & 1) return unknown(w);
      const pr = size ? xr : wr;
      return mk(`casp${l ? 'a' : ''}${o0 ? 'l' : ''}`, [reg(pr(rs)), reg(pr(rs + 1)), reg(pr(rt)), reg(pr(rt + 1)), mem], F.LOAD | F.STORE | F.ATOMIC, { size: size ? 8 : 4 });
    }
    const pr = size === 3 ? xr : wr;
    if (l) return mk(o0 ? 'ldaxp' : 'ldxp', [reg(pr(rt)), reg(pr(rt2)), mem], F.LOAD | F.ATOMIC, { size: bytes });
    return mk(o0 ? 'stlxp' : 'stxp', [reg(wr(rs)), reg(pr(rt)), reg(pr(rt2)), mem], F.STORE | F.ATOMIC, { size: bytes });
  }
  if (o2 === 0) {
    if (l) return mk(`ld${o0 ? 'a' : ''}xr${sfx}`, [reg(r(rt)), mem], F.LOAD | F.ATOMIC, { size: bytes });
    return mk(`st${o0 ? 'l' : ''}xr${sfx}`, [reg(wr(rs)), reg(r(rt)), mem], F.STORE | F.ATOMIC, { size: bytes });
  }
  // o2 = 1, o1 = 0: load-acquire / store-release
  if (l) return mk(`${o0 ? 'ldar' : 'ldlar'}${sfx}`, [reg(r(rt)), mem], F.LOAD, { size: bytes });
  return mk(`${o0 ? 'stlr' : 'stllr'}${sfx}`, [reg(r(rt)), mem], F.STORE, { size: bytes });
}

const ATOMIC_OPS = ['add', 'clr', 'eor', 'set', 'smax', 'smin', 'umax', 'umin'];
const FP_ATOMIC_OPS = ['add', '', '', '', 'max', 'min', 'maxnm', 'minnm'];

function atomic(w: number): Insn {
  const size = bits(w, 31, 30);
  const v = bit(w, 26);
  const a = bit(w, 23);
  const r = bit(w, 22);
  const rs = bits(w, 20, 16);
  const o3 = bit(w, 15);
  const opc = bits(w, 14, 12);
  const rn = bits(w, 9, 5);
  const rt = bits(w, 4, 0);
  const mem: Op = { k: 'mem', base: xs(rn), off: 0, mode: 'off' };
  const order = `${a ? 'a' : ''}${r ? 'l' : ''}`;
  if (v) {
    // LDFADD & co (FEAT_LSFE): floating-point atomics on H, S or D; size 0 is BFloat16 (ldbf…).
    // The STF… forms, which return nothing, have encodings of their own.
    const op = FP_ATOMIC_OPS[opc];
    if (!op) return unknown(w);
    const name = `${size ? 'f' : 'bf'}${op}`;
    const fr = fpReg('hhsd'[size]!);
    const extra = { size: size ? 1 << size : 2 };
    if (o3) return rt === 31 && !a ? mk(`st${name}${r ? 'l' : ''}`, [reg(fr(rs)), mem], F.LOAD | F.STORE | F.ATOMIC, extra) : unknown(w);
    return mk(`ld${name}${order}`, [reg(fr(rs)), reg(fr(rt)), mem], F.LOAD | F.STORE | F.ATOMIC, extra);
  }
  if (o3 && opc >= 1 && opc <= 3 && size < 2) {
    // RCWCLR, RCWSWP, RCWSET (FEAT_THE): read-check-write on a translation table entry; RCWS… with size 1.
    const m = `rcw${size ? 's' : ''}${['', 'clr', 'swp', 'set'][opc]}${order}`;
    return mk(m, [reg(xr(rs)), reg(xr(rt)), mem], F.LOAD | F.STORE | F.ATOMIC, { size: 8 });
  }
  if (o3 && size === 3 && !a && !r && !(rt & 1) && rt < 24 && (opc === 1 || opc === 2 || opc === 3 || opc === 5)) {
    // ST64B, ST64BV, ST64BV0, LD64B (FEAT_LS64): 64 bytes in one access, through Xt…Xt+7.
    if (opc === 1 || opc === 5) return rs === 31 ? mk(opc === 1 ? 'st64b' : 'ld64b', [reg(xr(rt)), mem], opc === 1 ? F.STORE : F.LOAD, { size: 64 }) : unknown(w);
    return mk(opc === 2 ? 'st64bv0' : 'st64bv', [reg(xr(rs)), reg(xr(rt)), mem], F.LOAD | F.STORE, { size: 64 });
  }
  const sfx = ['b', 'h', '', ''][size]!;
  const g = size === 3 ? xr : wr;
  const extra = { size: 1 << size };
  if (!o3) {
    const op = ATOMIC_OPS[opc]!;
    if (rt === 31 && !a) return mk(`st${op}${r ? 'l' : ''}${sfx}`, [reg(g(rs)), mem], F.LOAD | F.STORE | F.ATOMIC, extra);
    return mk(`ld${op}${order}${sfx}`, [reg(g(rs)), reg(g(rt)), mem], F.LOAD | F.STORE | F.ATOMIC, extra);
  }
  if (opc === 0) return mk(`swp${order}${sfx}`, [reg(g(rs)), reg(g(rt)), mem], F.LOAD | F.STORE | F.ATOMIC, extra);
  if (opc === 4 && a && !r && rs === 31) return mk(`ldapr${sfx}`, [reg(g(rt)), mem], F.LOAD, extra);
  return unknown(w);
}

/** LDAPUR / STLUR: load-acquire (RCpc) and store-release with an unscaled offset. */
function rcpcUnscaled(w: number): Insn {
  const size = bits(w, 31, 30);
  const opc = bits(w, 23, 22);
  const rn = bits(w, 9, 5);
  const rt = bits(w, 4, 0);
  const off = sext(bits(w, 20, 12), 9);
  const sfx = ['b', 'h', '', ''][size]!;
  const mem: Op = { k: 'mem', base: xs(rn), off, mode: 'off' };
  if (bit(w, 26)) {
    // SIMD&FP registers (FEAT_LRCPC3): B, H, S, D, or Q when size is 0 and opc<1> is set.
    const a = access(size, 1, opc);
    if (!a) return unknown(w);
    return mk(a.load ? 'ldapur' : 'stlur', [reg(a.rt(rt)), mem], a.load ? F.LOAD : F.STORE, { size: a.bytes });
  }
  if (opc === 0) return mk(`stlur${sfx}`, [reg((size === 3 ? xr : wr)(rt)), mem], F.STORE, { size: 1 << size });
  if (opc === 1) return mk(`ldapur${sfx}`, [reg((size === 3 ? xr : wr)(rt)), mem], F.LOAD, { size: 1 << size });
  if (size === 3 || (size === 2 && opc === 3)) return unknown(w);
  const ext = size === 2 ? 'sw' : size === 1 ? 'sh' : 'sb';
  return mk(`ldapurs${ext.slice(1)}`, [reg((opc === 2 ? xr : wr)(rt)), mem], F.LOAD, { size: 1 << size, signed: true });
}

function literal(w: number, pc: number): Insn {
  const opc = bits(w, 31, 30);
  const v = bit(w, 26);
  const rt = bits(w, 4, 0);
  const target = pc + sext(bits(w, 23, 5), 19) * 4;
  const label: Op = { k: 'label', addr: target };
  if (v) {
    if (opc === 3) return unknown(w);
    return mk('ldr', [reg(`${'sdq'[opc]}${rt}`), label], F.LOAD, { target, size: 4 << opc });
  }
  if (opc === 3) return mk('prfm', [prfop(rt), label], 0, { target });
  if (opc === 2) return mk('ldrsw', [reg(xr(rt)), label], F.LOAD, { target, size: 4, signed: true });
  return mk('ldr', [reg(opc ? xr(rt) : wr(rt)), label], F.LOAD, { target, size: opc ? 8 : 4 });
}

const MOPS_OPTIONS = ['', 'wt', 'rt', 't', 'wn', 'wtwn', 'rtwn', 'twn', 'rn', 'wtrn', 'rtrn', 'trn', 'n', 'wtn', 'rtn', 'tn'];

/**
 * The memory copy and set instructions (FEAT_MOPS): each operation is three
 * instructions — prologue, main, epilogue — that update their registers as
 * they go, hence the writeback marks. The suffix says which accesses are
 * unprivileged (t, wt, rt) and which non-temporal (n, wn, rn).
 */
function mops(w: number): Insn {
  const o0 = bit(w, 26);
  const op1 = bits(w, 23, 22);
  const rs = bits(w, 20, 16);
  const op2 = bits(w, 15, 12);
  const rn = bits(w, 9, 5);
  const rd = bits(w, 4, 0);
  // The three registers must differ; the count may be xzr, and so may the value of a set.
  if (rd === rn || rd === rs || rn === rs || rd === 31) return unknown(w);
  if (op1 === 3) {
    const stage = op2 >> 2;
    if (stage === 3) return unknown(w);
    const m = `set${o0 ? 'g' : ''}${'pme'[stage]}${['', 't', 'n', 'tn'][op2 & 3]}`;
    return mk(m, [text(`[${xr(rd)}]!`), text(`${xr(rn)}!`), reg(xr(rs))], F.STORE);
  }
  if (rs === 31) return unknown(w);
  const m = `cpy${o0 ? '' : 'f'}${'pme'[op1]}${MOPS_OPTIONS[op2]}`;
  return mk(m, [text(`[${xr(rd)}]!`), text(`[${xr(rs)}]!`), text(`${xr(rn)}!`)], F.LOAD | F.STORE);
}

/**
 * LDIAPP / STILP and the writeback forms of LDAPR / STLR (FEAT_LRCPC3):
 * load-acquire and store-release of one or two registers, the pair ordered
 * as a unit.
 */
function rcpcPair(w: number): Insn {
  const size = bits(w, 31, 30);
  const opc = bits(w, 23, 22);
  const rt2 = bits(w, 20, 16);
  const opc2 = bits(w, 15, 12);
  const rn = bits(w, 9, 5);
  const rt = bits(w, 4, 0);
  if (size < 2 || opc2 > 1) return unknown(w);
  const r = size === 3 ? xr : wr;
  const bytes = 1 << size;
  const load = !!(opc & 1);
  const flags = load ? F.LOAD : F.STORE;
  const writeback = opc2 === 0;
  if (opc < 2) {
    // Loads step the base up after, stores step it down before: a stack's pop and push.
    const mem: Op = writeback ? { k: 'mem', base: xs(rn), off: load ? 2 * bytes : -2 * bytes, mode: load ? 'post' : 'pre', decimal: true } : { k: 'mem', base: xs(rn), off: 0, mode: 'off' };
    return mk(load ? 'ldiapp' : 'stilp', [reg(r(rt)), reg(r(rt2)), mem], flags, { size: bytes });
  }
  if (!writeback || rt2) return unknown(w);
  const mem: Op = { k: 'mem', base: xs(rn), off: load ? bytes : -bytes, mode: load ? 'post' : 'pre', decimal: true };
  return mk(load ? 'ldapr' : 'stlr', [reg(r(rt)), mem], flags, { size: bytes });
}

/**
 * The memory-tagging loads and stores (FEAT_MTE): STG and friends set the
 * allocation tag of one or two 16-byte granules (STZG… zero them as well),
 * LDG reads one; the …GM forms move a whole block of tags through Xt.
 */
function memoryTag(w: number): Insn {
  const opc = bits(w, 23, 22);
  const imm9 = sext(bits(w, 20, 12), 9);
  const op2 = bits(w, 11, 10);
  const rn = bits(w, 9, 5);
  const rt = bits(w, 4, 0);
  if (op2 === 0) {
    if (opc === 1) return mk('ldg', [reg(xr(rt)), { k: 'mem', base: xs(rn), off: imm9 * 16, mode: 'off' }], F.LOAD);
    if (imm9) return unknown(w);
    const m = ['stzgm', '', 'stgm', 'ldgm'][opc]!;
    return mk(m, [reg(xr(rt)), { k: 'mem', base: xs(rn), off: 0, mode: 'off' }], opc === 3 ? F.LOAD : F.STORE);
  }
  const mode = (['off', 'post', 'off', 'pre'] as const)[op2]!;
  return mk(['stg', 'stzg', 'st2g', 'stz2g'][opc]!, [reg(xs(rt)), { k: 'mem', base: xs(rn), off: imm9 * 16, mode }], F.STORE);
}

/**
 * Size 0 or 1 with bit 21 set: the 128-bit atomics (FEAT_LSE128), the
 * read-check-write instructions on 128-bit translation table entries
 * (FEAT_THE) and the unprivileged atomics (FEAT_LSUI).
 */
function atomicExtra(w: number): Insn {
  const size = bits(w, 31, 30);
  const a = bit(w, 23);
  const r = bit(w, 22);
  const rs = bits(w, 20, 16);
  const o3 = bit(w, 15);
  const opc = bits(w, 14, 12);
  const kind = bits(w, 11, 10);
  const rn = bits(w, 9, 5);
  const rt = bits(w, 4, 0);
  const mem: Op = { k: 'mem', base: xs(rn), off: 0, mode: 'off' };
  const order = `${a ? 'a' : ''}${r ? 'l' : ''}`;
  const rw = F.LOAD | F.STORE | F.ATOMIC;
  if (kind === 0) {
    // Xt and Xt2 hold the 128-bit operand and receive the old value.
    const op = o3 ? ['swpp', 'rcwclrp', 'rcwswpp', 'rcwsetp'][opc] : ['', 'ldclrp', '', 'ldsetp'][opc];
    if (!op || (size && !op.startsWith('rcw')) || rt === 31 || rs === 31) return unknown(w);
    return mk(`${size ? op.replace('rcw', 'rcws') : op}${order}`, [reg(xr(rt)), reg(xr(rs)), mem], rw, { size: 16 });
  }
  if (kind === 1) {
    const g = size ? xr : wr;
    const extra = { size: size ? 8 : 4 };
    if (o3) return opc === 0 ? mk(`swpt${order}`, [reg(g(rs)), reg(g(rt)), mem], rw, extra) : unknown(w);
    const op = ['add', 'clr', '', 'set'][opc];
    if (!op) return unknown(w);
    return mk(`ldt${op}${order}`, [reg(g(rs)), reg(g(rt)), mem], rw, extra);
  }
  // RCWCAS / RCWCASP: compare-and-swap of a 64-bit or 128-bit table entry.
  if (o3 || opc) return unknown(w);
  const s = size ? 's' : '';
  if (kind === 2) return mk(`rcw${s}cas${order}`, [reg(xr(rs)), reg(xr(rt)), mem], rw, { size: 8 });
  if (rs & 1 || rt & 1) return unknown(w);
  return mk(`rcw${s}casp${order}`, [reg(xr(rs)), reg(xr(rs + 1)), reg(xr(rt)), reg(xr(rt + 1)), mem], rw, { size: 16 });
}

/**
 * Bits 29:28 = 01 with bit 24 set, an encoding space the later extensions
 * filled: RCpc unscaled and writeback forms, memory copy and set, memory
 * tagging, GCS stores, and the 128-bit and unprivileged atomics.
 */
function loadStoreExtra(w: number): Insn {
  const size = bits(w, 31, 30);
  const v = bit(w, 26);
  const kind = bits(w, 11, 10);
  if (!bit(w, 21)) {
    // The SIMD&FP forms of LDAPUR / STLUR sit where the general-register pair forms do.
    if (kind === 0) return v ? unknown(w) : rcpcUnscaled(w);
    if (kind === 1) return size === 0 ? mops(w) : unknown(w);
    if (kind === 2) return v ? rcpcUnscaled(w) : rcpcPair(w);
    if (v) return unknown(w);
    // GCSSTR / GCSSTTR: a store to the Guarded Control Stack, the second unprivileged.
    if (size === 3 && bits(w, 23, 13) === 0x0f8) {
      const m = bit(w, 12) ? 'gcssttr' : 'gcsstr';
      return mk(m, [reg(xr(bits(w, 4, 0))), { k: 'mem', base: xs(bits(w, 9, 5)), off: 0, mode: 'off' }], F.STORE, { size: 8 });
    }
    return unknown(w);
  }
  if (v) return unknown(w);
  if (size === 3) return memoryTag(w);
  if (size < 2) return atomicExtra(w);
  return unknown(w);
}

/** LDRAA / LDRAB: a load through a pointer authenticated on the way. */
function ldra(w: number): Insn {
  if (bits(w, 31, 30) !== 3 || bit(w, 26)) return unknown(w);
  const m = bit(w, 23) ? 'ldrab' : 'ldraa';
  const off = sext((bit(w, 22) << 9) | bits(w, 20, 12), 10) * 8;
  const pre = bit(w, 11);
  return mk(m, [reg(xr(bits(w, 4, 0))), { k: 'mem', base: xs(bits(w, 9, 5)), off, mode: pre ? 'pre' : 'off' }], F.LOAD, { size: 8 });
}

function loadStore(w: number, pc: number): Insn {
  const op0 = bits(w, 31, 28);
  const v = bit(w, 26);
  const op2 = bits(w, 24, 23);
  const b29 = bits(w, 29, 28);
  if (b29 === 0) {
    if (v) {
      if ((op0 & 0xb) !== 0) return unknown(w);
      return decodeSimdStructure(w);
    }
    if (bits(w, 27, 25) !== 4) return unknown(w);
    return bit(w, 24) ? exclusiveUnprivileged(w) : exclusive(w);
  }
  if (b29 === 1) {
    if (!bit(w, 24)) return literal(w, pc);
    return loadStoreExtra(w);
  }
  if (b29 === 2) return pair(w, (['noalloc', 'post', 'off', 'pre'] as const)[op2]!);
  if (bit(w, 24)) return single(w, 'uimm');
  if (!bit(w, 21)) return single(w, (['unscaled', 'post', 'unpriv', 'pre'] as const)[bits(w, 11, 10)]!);
  const op4 = bits(w, 11, 10);
  if (op4 === 0) return atomic(w);
  if (op4 === 2) return single(w, 'regoff');
  return ldra(w);
}

/* ------------------------------------------------------------------ *
 * Data processing — register
 * ------------------------------------------------------------------ */

const SHIFTS = ['lsl', 'lsr', 'asr', 'ror'];
const EXTENDS = ['uxtb', 'uxth', 'uxtw', 'uxtx', 'sxtb', 'sxth', 'sxtw', 'sxtx'];

function logicalShifted(w: number): Insn {
  const sf = bit(w, 31);
  const opc = bits(w, 30, 29);
  const sh = bits(w, 23, 22);
  const n = bit(w, 21);
  const rm = bits(w, 20, 16);
  const amount = bits(w, 15, 10);
  const rn = bits(w, 9, 5);
  const rd = bits(w, 4, 0);
  if (!sf && amount > 31) return unknown(w);
  const names = n ? ['bic', 'orn', 'eon', 'bics'] : ['and', 'orr', 'eor', 'ands'];
  const sOp = amount || sh ? [shift(SHIFTS[sh]!, amount)] : [];
  const flags = opc === 3 ? F.SETS_FLAGS : 0;
  if (opc === 1 && rn === 31) {
    if (!n && sh === 0 && amount === 0) return mk('mov', [reg(gr(sf, rd)), reg(gr(sf, rm))]);
    if (n) return mk('mvn', [reg(gr(sf, rd)), reg(gr(sf, rm)), ...sOp]);
  }
  if (opc === 3 && rd === 31 && !n) return mk('tst', [reg(gr(sf, rn)), reg(gr(sf, rm)), ...sOp], flags);
  return mk(names[opc]!, [reg(gr(sf, rd)), reg(gr(sf, rn)), reg(gr(sf, rm)), ...sOp], flags);
}

function addSubShifted(w: number): Insn {
  const sf = bit(w, 31);
  const op = bit(w, 30);
  const s = bit(w, 29);
  const sh = bits(w, 23, 22);
  const rm = bits(w, 20, 16);
  const amount = bits(w, 15, 10);
  const rn = bits(w, 9, 5);
  const rd = bits(w, 4, 0);
  if (sh === 3 || (!sf && amount > 31)) return unknown(w);
  const sOp = amount || sh ? [shift(SHIFTS[sh]!, amount)] : [];
  const flags = s ? F.SETS_FLAGS : 0;
  if (s && rd === 31) return mk(op ? 'cmp' : 'cmn', [reg(gr(sf, rn)), reg(gr(sf, rm)), ...sOp], flags);
  if (op && rn === 31) return mk(s ? 'negs' : 'neg', [reg(gr(sf, rd)), reg(gr(sf, rm)), ...sOp], flags);
  return mk((op ? 'sub' : 'add') + (s ? 's' : ''), [reg(gr(sf, rd)), reg(gr(sf, rn)), reg(gr(sf, rm)), ...sOp], flags);
}

function addSubExtended(w: number): Insn {
  const sf = bit(w, 31);
  const op = bit(w, 30);
  const s = bit(w, 29);
  const opt = bits(w, 23, 22);
  const rm = bits(w, 20, 16);
  const option = bits(w, 15, 13);
  const amount = bits(w, 12, 10);
  const rn = bits(w, 9, 5);
  const rd = bits(w, 4, 0);
  if (opt || amount > 4) return unknown(w);
  const flags = s ? F.SETS_FLAGS : 0;
  const m = sf && (option & 3) === 3 ? xr(rm) : wr(rm);
  // With SP as the destination or first source, the "natural" extend (uxtw / uxtx) is printed as lsl.
  const natural = sf ? option === 3 : option === 2;
  const usesSp = (s ? false : rd === 31) || rn === 31;
  let ext: Op[];
  if (natural && usesSp) ext = amount ? [shift('lsl', amount)] : [];
  else ext = [amount ? shift(EXTENDS[option]!, amount) : text(EXTENDS[option]!)];
  if (s && rd === 31) return mk(op ? 'cmp' : 'cmn', [reg(gs(sf, rn)), reg(m), ...ext], flags);
  return mk((op ? 'sub' : 'add') + (s ? 's' : ''), [reg(s ? gr(sf, rd) : gs(sf, rd)), reg(gs(sf, rn)), reg(m), ...ext], flags);
}

function condSelect(w: number): Insn {
  const sf = bit(w, 31);
  const op = bit(w, 30);
  const s = bit(w, 29);
  const rm = bits(w, 20, 16);
  const c = bits(w, 15, 12);
  const o2 = bits(w, 11, 10);
  const rn = bits(w, 9, 5);
  const rd = bits(w, 4, 0);
  if (s || o2 > 1) return unknown(w);
  const d = reg(gr(sf, rd));
  const f = F.READS_FLAGS;
  const usable = (c & 14) !== 14;
  if (!op && o2 === 0) return mk('csel', [d, reg(gr(sf, rn)), reg(gr(sf, rm)), text(cond(c))], f, { cond: cond(c) });
  if (!op && o2 === 1) {
    if (rm === 31 && rn === 31 && usable) return mk('cset', [d, text(invert(c))], f, { cond: invert(c) });
    if (rm === rn && rn !== 31 && usable) return mk('cinc', [d, reg(gr(sf, rn)), text(invert(c))], f, { cond: invert(c) });
    return mk('csinc', [d, reg(gr(sf, rn)), reg(gr(sf, rm)), text(cond(c))], f, { cond: cond(c) });
  }
  if (op && o2 === 0) {
    if (rm === 31 && rn === 31 && usable) return mk('csetm', [d, text(invert(c))], f, { cond: invert(c) });
    if (rm === rn && rn !== 31 && usable) return mk('cinv', [d, reg(gr(sf, rn)), text(invert(c))], f, { cond: invert(c) });
    return mk('csinv', [d, reg(gr(sf, rn)), reg(gr(sf, rm)), text(cond(c))], f, { cond: cond(c) });
  }
  if (rm === rn && usable) return mk('cneg', [d, reg(gr(sf, rn)), text(invert(c))], f, { cond: invert(c) });
  return mk('csneg', [d, reg(gr(sf, rn)), reg(gr(sf, rm)), text(cond(c))], f, { cond: cond(c) });
}

function condCompare(w: number): Insn {
  const sf = bit(w, 31);
  const op = bit(w, 30);
  if (!bit(w, 29) || bit(w, 10) || bit(w, 4)) return unknown(w);
  const c = cond(bits(w, 15, 12));
  const second = bit(w, 11) ? imm(bits(w, 20, 16)) : reg(gr(sf, bits(w, 20, 16)));
  return mk(op ? 'ccmp' : 'ccmn', [reg(gr(sf, bits(w, 9, 5))), second, imm(bits(w, 3, 0)), text(c)], F.SETS_FLAGS | F.READS_FLAGS, { cond: c });
}

function dp2(w: number): Insn {
  const sf = bit(w, 31);
  const s = bit(w, 29);
  const rm = bits(w, 20, 16);
  const opcode = bits(w, 15, 10);
  const rn = bits(w, 9, 5);
  const rd = bits(w, 4, 0);
  const three = (m: string) => mk(m, [reg(gr(sf, rd)), reg(gr(sf, rn)), reg(gr(sf, rm))]);
  if (s) {
    if (sf && opcode === 0) return mk('subps', [reg(xr(rd)), reg(xs(rn)), reg(xs(rm))], F.SETS_FLAGS);
    return unknown(w);
  }
  switch (opcode) {
    case 0:
      return sf ? mk('subp', [reg(xr(rd)), reg(xs(rn)), reg(xs(rm))]) : unknown(w);
    case 2:
      return three('udiv');
    case 3:
      return three('sdiv');
    case 4:
      return sf ? mk('irg', [reg(xs(rd)), reg(xs(rn)), ...(rm === 31 ? [] : [reg(xr(rm))])]) : unknown(w);
    case 5:
      return sf ? mk('gmi', [reg(xr(rd)), reg(xs(rn)), reg(xr(rm))]) : unknown(w);
    case 8:
      return three('lsl');
    case 9:
      return three('lsr');
    case 10:
      return three('asr');
    case 11:
      return three('ror');
    case 12:
      return sf ? mk('pacga', [reg(xr(rd)), reg(xr(rn)), reg(xs(rm))]) : unknown(w);
    case 24:
      return three('smax');
    case 25:
      return three('umax');
    case 26:
      return three('smin');
    case 27:
      return three('umin');
  }
  if (opcode >= 16 && opcode <= 23) {
    const sz = opcode & 3;
    const c = opcode & 4 ? 'c' : '';
    if ((sz === 3) !== !!sf) return unknown(w);
    return mk(`crc32${c}${'bhwx'[sz]}`, [reg(wr(rd)), reg(wr(rn)), reg(sz === 3 ? xr(rm) : wr(rm))]);
  }
  return unknown(w);
}

const PAC1 = ['pacia', 'pacib', 'pacda', 'pacdb', 'autia', 'autib', 'autda', 'autdb'];
const PAC_LR: Record<number, string> = {
  32: 'pacnbiasppc', 33: 'pacnbibsppc', 34: 'pacia171615', 35: 'pacib171615', 40: 'paciasppc', 41: 'pacibsppc', 46: 'autia171615', 47: 'autib171615',
};

function dp1(w: number): Insn {
  const sf = bit(w, 31);
  const opcode2 = bits(w, 20, 16);
  const opcode = bits(w, 15, 10);
  const rn = bits(w, 9, 5);
  const rd = bits(w, 4, 0);
  if (bit(w, 29)) return unknown(w);
  const two = (m: string) => mk(m, [reg(gr(sf, rd)), reg(gr(sf, rn))]);
  if (opcode2 === 0) {
    switch (opcode) {
      case 0:
        return two('rbit');
      case 1:
        return two('rev16');
      case 2:
        return sf ? two('rev32') : two('rev');
      case 3:
        return sf ? two('rev') : unknown(w);
      case 4:
        return two('clz');
      case 5:
        return two('cls');
      case 6:
        return two('ctz');
      case 7:
        return two('cnt');
      case 8:
        return two('abs');
    }
    return unknown(w);
  }
  if (opcode2 === 1 && sf) {
    if (opcode < 8) return mk(PAC1[opcode]!, [reg(xr(rd)), reg(xs(rn))]);
    if (opcode < 16 && rn === 31) return mk(`${PAC1[opcode - 8]!.slice(0, 4)}z${PAC1[opcode - 8]!.slice(4)}`, [reg(xr(rd))]);
    if (opcode === 16 && rn === 31) return mk('xpaci', [reg(xr(rd))]);
    if (opcode === 17 && rn === 31) return mk('xpacd', [reg(xr(rd))]);
    // FEAT_PAuth_LR: signing and authenticating with the address of the signing instruction as well.
    if (rd === 30 && (opcode === 36 || opcode === 37)) return mk(opcode & 1 ? 'autibsppcr' : 'autiasppcr', [reg(xr(rn))]);
    const lr = PAC_LR[opcode];
    if (lr && rn === 31 && rd === 30) return mk(lr, []);
  }
  return unknown(w);
}

function dp3(w: number): Insn {
  const sf = bit(w, 31);
  const op54 = bits(w, 30, 29);
  const op31 = bits(w, 23, 21);
  const o0 = bit(w, 15);
  const rm = bits(w, 20, 16);
  const ra = bits(w, 14, 10);
  const rn = bits(w, 9, 5);
  const rd = bits(w, 4, 0);
  if (op54) return unknown(w);
  if (op31 === 0) {
    const ops = [reg(gr(sf, rd)), reg(gr(sf, rn)), reg(gr(sf, rm))];
    if (ra === 31) return mk(o0 ? 'mneg' : 'mul', ops);
    return mk(o0 ? 'msub' : 'madd', [...ops, reg(gr(sf, ra))]);
  }
  if (!sf) return unknown(w);
  if (op31 === 2 || op31 === 6) {
    if (o0) return unknown(w);
    return mk(op31 === 2 ? 'smulh' : 'umulh', [reg(xr(rd)), reg(xr(rn)), reg(xr(rm))]);
  }
  if (op31 === 3) {
    // MADDPT / MSUBPT (FEAT_CPA): multiply-add on pointers, checked against the pointer's top bits.
    return mk(o0 ? 'msubpt' : 'maddpt', [reg(xr(rd)), reg(xr(rn)), reg(xr(rm)), reg(xr(ra))]);
  }
  if (op31 === 1 || op31 === 5) {
    const u = op31 === 5 ? 'u' : 's';
    const ops = [reg(xr(rd)), reg(wr(rn)), reg(wr(rm))];
    if (ra === 31) return mk(`${u}${o0 ? 'mnegl' : 'mull'}`, ops);
    return mk(`${u}${o0 ? 'msubl' : 'maddl'}`, [...ops, reg(xr(ra))]);
  }
  return unknown(w);
}

function dpReg(w: number): Insn {
  const op0 = bit(w, 30);
  const op1 = bit(w, 28);
  const op2 = bits(w, 24, 21);
  const op3 = bits(w, 15, 10);
  if (!op1) {
    if (!(op2 & 8)) return logicalShifted(w);
    return op2 & 1 ? addSubExtended(w) : addSubShifted(w);
  }
  if (op2 & 8) return dp3(w);
  switch (op2) {
    case 0: {
      const sf = bit(w, 31);
      const op = bit(w, 30);
      const s = bit(w, 29);
      const rm = bits(w, 20, 16);
      const rn = bits(w, 9, 5);
      const rd = bits(w, 4, 0);
      if ((op3 & 0x38) === 8) {
        // ADDPT / SUBPT (FEAT_CPA): pointer arithmetic, with an optional left shift of Xm.
        if (!sf || s) return unknown(w);
        const amount = op3 & 7;
        return mk(op ? 'subpt' : 'addpt', [reg(xs(rd)), reg(xs(rn)), reg(xr(rm)), ...(amount ? [shift('lsl', amount)] : [])]);
      }
      if ((op3 & 0x1f) === 1) {
        // RMIF (FEAT_FlagM): rotate Xn right and insert its low bits into the flags the mask picks.
        if (!sf || op || !s || bit(w, 4)) return unknown(w);
        return mk('rmif', [reg(xr(rn)), imm(bits(w, 20, 15)), imm(bits(w, 3, 0))], F.SETS_FLAGS | F.READS_FLAGS);
      }
      if ((op3 & 0xf) === 2) {
        // SETF8 / SETF16 (FEAT_FlagM): N and Z from the low byte or halfword, V from the bit above it.
        if (sf || op || !s || bits(w, 20, 15) || rd !== 13) return unknown(w);
        return mk(bit(w, 14) ? 'setf16' : 'setf8', [reg(wr(rn))], F.SETS_FLAGS | F.READS_FLAGS);
      }
      if (op3 !== 0) return unknown(w);
      const flags = F.READS_FLAGS | (s ? F.SETS_FLAGS : 0);
      if (op && rn === 31) return mk(s ? 'ngcs' : 'ngc', [reg(gr(sf, rd)), reg(gr(sf, rm))], flags);
      return mk((op ? 'sbc' : 'adc') + (s ? 's' : ''), [reg(gr(sf, rd)), reg(gr(sf, rn)), reg(gr(sf, rm))], flags);
    }
    case 2:
      return condCompare(w);
    case 4:
      return condSelect(w);
    case 6:
      return op0 ? dp1(w) : dp2(w);
  }
  return unknown(w);
}

/* ------------------------------------------------------------------ */

export function decode(word: number, pc: number): Insn {
  const w = word >>> 0;
  const op1 = bits(w, 28, 25);
  if (op1 === 0) {
    if (!bit(w, 31) && bits(w, 30, 16) === 0) return mk('udf', [imm(bits(w, 15, 0))], F.TRAP);
    return unknown(w);
  }
  if ((op1 & 0xe) === 8) return dpImm(w, pc);
  if ((op1 & 0xe) === 0xa) return branches(w, pc);
  if ((op1 & 5) === 4) return loadStore(w, pc);
  if ((op1 & 7) === 5) return dpReg(w);
  if ((op1 & 7) === 7) return decodeSimd(w, pc);
  return unknown(w);
}
