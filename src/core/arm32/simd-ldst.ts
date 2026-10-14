/**
 * Advanced SIMD element and structure loads and stores, vld1…vld4 and
 * vst1…vst4: the A32 space 1111 0100 xxx0, which T32 encodes as 1111 1001
 * xxx0. Bit 23 separates whole structures (multiple registers, `{d0, d1}`)
 * from single elements (one lane, `{d0[1]}`, or every lane, `{d0[], d1[]}`).
 *
 * The address is `[rN]` or `[rN:align]`, then `!` when the base moves on by
 * the bytes transferred (Rm = 13) or `, rM` when it moves on by a register.
 */

import { F, r, type Insn, type Op } from './types';
import { bit, bits, type Ctx, dlist, mk, undef } from './simd-common';

/** The address operand: Rm = 15 leaves the base alone, 13 adds the size moved, anything else adds rM. */
function address(rn: number, alignBits: number, rm: number): Op {
  const base = r(rn);
  const inner = alignBits ? `[${base}:${alignBits}]` : `[${base}]`;
  if (rm === 15) return { k: 'mem', base, t: inner, mode: 'off' };
  if (rm === 13) return { k: 'mem', base, t: `${inner}!`, mode: 'post' };
  const index = r(rm);
  return { k: 'mem', base, t: `${inner}, ${index}`, index, mode: 'post' };
}

/**
 * Multiple structures, by bits 11-8: the instruction, how many registers and
 * how far apart, the alignments allowed (a mask over the 2-bit field), and
 * how the register list is formed: `pair` lists must fit below d32, `enum`
 * lists run on past d31 as LLVM numbers them, `mod` lists wrap to d0.
 */
const MULTI: ([number, number, number, number, 'one' | 'pair' | 'enum' | 'mod'] | null)[] = [
  [4, 4, 1, 0b1111, 'mod'], // 0000 vld4/vst4, d..d+3
  [4, 4, 2, 0b1111, 'mod'], // 0001 vld4/vst4, d, d+2, d+4, d+6
  [1, 4, 1, 0b1111, 'enum'], // 0010 vld1/vst1, four registers
  [2, 4, 1, 0b1111, 'enum'], // 0011 vld2/vst2, four registers
  [3, 3, 1, 0b0011, 'mod'], // 0100 vld3/vst3
  [3, 3, 2, 0b0011, 'mod'], // 0101 vld3/vst3, double spaced
  [1, 3, 1, 0b0011, 'enum'], // 0110 vld1/vst1, three registers
  [1, 1, 1, 0b0011, 'one'], // 0111 vld1/vst1, one register
  [2, 2, 1, 0b0111, 'pair'], // 1000 vld2/vst2
  [2, 2, 2, 0b0111, 'pair'], // 1001 vld2/vst2, double spaced
  [1, 2, 1, 0b0111, 'pair'], // 1010 vld1/vst1, two registers
];

function multiple(w: number, ctx: Ctx, load: boolean): Insn {
  const type = bits(w, 11, 8);
  const e = MULTI[type];
  if (!e) return undef(ctx);
  const [n, count, step, aligns, kind] = e;
  const size = bits(w, 7, 6);
  const align = bits(w, 5, 4);
  if (!((aligns >> align) & 1)) return undef(ctx);
  if (size === 3 && n !== 1) return undef(ctx);
  const d = (bit(w, 22) << 4) | bits(w, 15, 12);
  if (kind === 'pair' && d + (count - 1) * step > 31) return undef(ctx);
  const regs = dlist(d, count, step, '', kind === 'mod');
  const mem = address(bits(w, 19, 16), align ? 32 << align : 0, bits(w, 3, 0));
  return mk(ctx, `${load ? 'vld' : 'vst'}${n}`, `${8 << size}`, [regs, mem], load ? F.LOAD : F.STORE, true, { bytes: 8 });
}

/** One lane of 1-4 registers: vld2.16 {d0[1], d2[1]}, [r0:32]. */
function lane(w: number, ctx: Ctx, load: boolean): Insn {
  const size = bits(w, 11, 10);
  const n = bits(w, 9, 8) + 1;
  const ia = bits(w, 7, 4);
  let index: number;
  let inc = 1;
  let alignBytes = 0;
  if (size === 0) {
    index = ia >> 1;
    if (ia & 1) {
      if (n === 1 || n === 3) return undef(ctx);
      alignBytes = n === 2 ? 2 : 4;
    }
  } else if (size === 1) {
    index = ia >> 2;
    if (n === 1 && ia & 2) return undef(ctx);
    if (n > 1 && ia & 2) inc = 2;
    if (ia & 1) {
      if (n === 3) return undef(ctx);
      alignBytes = n === 1 ? 2 : n === 2 ? 4 : 8;
    }
  } else {
    index = ia >> 3;
    if (n === 1) {
      if (ia & 4) return undef(ctx);
      const a = ia & 3;
      if (a === 3) alignBytes = 4;
      else if (a) return undef(ctx);
    } else if (n === 2) {
      if (ia & 2) return undef(ctx);
      if (ia & 4) inc = 2;
      if (ia & 1) alignBytes = 8;
    } else if (n === 3) {
      if (ia & 3) return undef(ctx);
      if (ia & 4) inc = 2;
    } else {
      if (ia & 4) inc = 2;
      const a = ia & 3;
      if (a === 3) return undef(ctx);
      if (a) alignBytes = 4 << a;
    }
  }
  const d = (bit(w, 22) << 4) | bits(w, 15, 12);
  if (d + (n - 1) * inc > 31) return undef(ctx);
  const regs = dlist(d, n, inc, `[${index}]`);
  const mem = address(bits(w, 19, 16), alignBytes * 8, bits(w, 3, 0));
  return mk(ctx, `${load ? 'vld' : 'vst'}${n}`, `${8 << size}`, [regs, mem], load ? F.LOAD : F.STORE, true, { bytes: 1 << size });
}

/** Every lane: vld1.8 {d0[]}, vld4.32 {d0[], d2[], d4[], d6[]}, [r0:128]. */
function allLanes(w: number, ctx: Ctx): Insn {
  const n = bits(w, 9, 8) + 1;
  let size = bits(w, 7, 6);
  const t = bit(w, 5);
  const a = bit(w, 4);
  const d = (bit(w, 22) << 4) | bits(w, 15, 12);
  let count = n;
  let inc = 1;
  let alignBytes = 0;
  let wrap = true;
  switch (n) {
    case 1:
      if (size === 3 || (size === 0 && a)) return undef(ctx);
      count = t + 1;
      alignBytes = a << size;
      wrap = false;
      break;
    case 2:
      if (size === 3) return undef(ctx);
      inc = t + 1;
      alignBytes = a * 2 << size;
      wrap = false;
      break;
    case 3:
      if (size === 3 || a) return undef(ctx);
      inc = t + 1;
      break;
    default:
      inc = t + 1;
      if (size === 3) {
        if (!a) return undef(ctx);
        alignBytes = 16;
        size = 2;
      } else alignBytes = size === 2 ? a * 8 : a * 4 << size;
  }
  if (!wrap && d + (count - 1) * inc > 31) return undef(ctx);
  const regs = dlist(d, count, inc, '[]', wrap);
  const mem = address(bits(w, 19, 16), alignBytes * 8, bits(w, 3, 0));
  return mk(ctx, `vld${n}`, `${8 << size}`, [regs, mem], F.LOAD, true, { bytes: 1 << size });
}

/** An A32 word of the form 1111 0100 xxx0 (or its T32 twin). */
export function neonLoadStore(w: number, ctx: Ctx): Insn {
  const load = bit(w, 21) === 1;
  if (!bit(w, 23)) return multiple(w, ctx, load);
  if (bits(w, 11, 10) !== 3) return lane(w, ctx, load);
  return load ? allLanes(w, ctx) : undef(ctx);
}
