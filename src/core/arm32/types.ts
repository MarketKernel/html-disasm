/**
 * A decoded AArch32 instruction — A32 (ARM state) or T32 (Thumb state, 16 or
 * 32 bits).
 *
 * As on A64, operands stay structured: the listing prints them, the analysis
 * reads branch targets, PC-relative literals and the registers an `add rX, pc`
 * completes. Each operand carries the exact text LLVM's printer gives it, since
 * the ARM printer is not uniform (`add r0, r1, #4` in decimal, `ldr r0, [r1,
 * #0x4]` in hex, `ldr r0, [r1], #4` in decimal again) and the decoder is
 * checked against llvm-objdump line by line (tools/verify-arm32.mjs).
 */

import { F } from '../arm64/types';

export { F };

export type Op =
  /** A register: r0…r12, sp, lr, pc, s0, d16, q8, apsr_nzcv, fpscr, p15, c13… `wb` prints `!` after it (ldm r0!, …). */
  | { k: 'reg'; r: string; wb?: boolean }
  | { k: 'imm'; v: number; t: string }
  /** A branch target, printed as LLVM prints it: the absolute address in hex. */
  | { k: 'label'; addr: number }
  /** A memory operand with its whole text: `[r1, #0x4]`, `[r2], #4`, `[sp, #-4]!`, `[r0, r1, lsl #2]`, `[lr:128]!`. */
  | { k: 'mem'; base: string; t: string; off?: number; index?: string; mode: 'off' | 'pre' | 'post' }
  /** A register list: `{r4, r5, lr}`, `{d16, d17}`, `{d0[], d1[]}`, `{d2[1]}`. */
  | { k: 'list'; regs: string[]; t: string }
  /** A shift of the last register: `lsl #2`, `asr r3`, `rrx`. */
  | { k: 'shift'; t: string }
  /** Anything else, printed as it is: `ish`, `eq` (of an it), `aif`, `be`, `cpsr_fc`. */
  | { k: 'text'; t: string };

export interface Insn {
  /** As printed, with the condition and qualifiers: `addeq`, `ldr.w`, `vadd.f32`, `itte`. */
  m: string;
  ops: Op[];
  f: number;
  /** Bytes: 4 for A32 and 32-bit T32, 2 for 16-bit T32. */
  size: 2 | 4;
  /** Branch target, or the address a PC-relative operand names (ldr/vldr literal, adr, pld literal). */
  target?: number;
  /** The condition the instruction executes under (eq, ne…): its own or that of the IT block around it. */
  cond?: string;
  /** bl/blx to an immediate: whether the code at the target is Thumb. */
  thumb?: boolean;
  /** An IT instruction: the conditions of the instructions it covers, in order. */
  it?: number[];
  /** Bytes a load or store moves per register (1, 2, 4, 8). */
  bytes?: number;
}

/** Condition codes as LLVM prints them; 14 (al) prints nothing. */
export const CONDS = ['eq', 'ne', 'hs', 'lo', 'mi', 'pl', 'vs', 'vc', 'hi', 'ls', 'ge', 'lt', 'gt', 'le', '', ''] as const;
export const cond = (c: number): string => CONDS[c & 15] ?? '';

export const REGS = ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'sp', 'lr', 'pc'] as const;
export const r = (n: number): string => REGS[n & 15]!;

export const bits = (w: number, hi: number, lo: number): number => (w >>> lo) & (hi - lo === 31 ? 0xffffffff : (1 << (hi - lo + 1)) - 1);
export const bit = (w: number, n: number): number => (w >>> n) & 1;
export const sext = (v: number, width: number): number => (v << (32 - width)) >> (32 - width);

/** `0x1f`, `-0x4`: LLVM's hex for immediates and offsets. */
export const hex = (v: number): string => (v < 0 ? `-0x${(-v).toString(16)}` : `0x${(v >>> 0).toString(16)}`);

export const reg = (name: string, wb = false): Op => (wb ? { k: 'reg', r: name, wb } : { k: 'reg', r: name });
/** `#0x1f` */
export const immHex = (v: number): Op => ({ k: 'imm', v, t: `#${hex(v)}` });
/** `#31` */
export const immDec = (v: number): Op => ({ k: 'imm', v, t: `#${v}` });
export const immText = (v: number, t: string): Op => ({ k: 'imm', v, t });
export const label = (addr: number): Op => ({ k: 'label', addr: addr >>> 0 });
export const list = (regs: string[]): Op => ({ k: 'list', regs, t: `{${regs.join(', ')}}` });
export const shift = (t: string): Op => ({ k: 'shift', t });
export const text = (t: string): Op => ({ k: 'text', t });

/** The registers of a 16-bit mask, lowest first: {r4, r5, lr}. */
export function regList(mask: number): string[] {
  const out: string[] = [];
  for (let i = 0; i < 16; i++) if (mask & (1 << i)) out.push(r(i));
  return out;
}

export function formatOp(op: Op): string {
  switch (op.k) {
    case 'reg':
      return op.wb ? `${op.r}!` : op.r;
    case 'label':
      return hex(op.addr);
    default:
      return op.t;
  }
}

export function formatInsn(insn: Insn): string {
  if (!insn.ops.length) return insn.m;
  return `${insn.m} ${insn.ops.map(formatOp).join(', ')}`;
}

/** What is not an instruction: `.inst 0xe7f000f0`, `.inst.n 0xde00`, `.inst.w 0xf7f0a000`. */
export function unknown(word: number, size: 2 | 4, thumb: boolean): Insn {
  const m = thumb ? (size === 2 ? '.inst.n' : '.inst.w') : '.inst';
  const t = `0x${(word >>> 0).toString(16).padStart(size * 2, '0')}`;
  return { m, ops: [{ k: 'imm', v: word >>> 0, t }], f: F.UNKNOWN, size };
}

/**
 * The state an IT instruction leaves for the instructions after it: `it`
 * holds their conditions in order. A decoder of a T32 instruction inside the
 * block gets its condition (0…14); outside a block it gets -1.
 */
export function itConditions(firstcond: number, mask: number): number[] {
  const out = [firstcond];
  // The mask's lowest set bit ends the block; each bit above it says then (= firstcond[0]) or else.
  const trailing = mask & -mask;
  for (let b = 3; (1 << b) > trailing; b--) out.push((firstcond & ~1) | ((mask >> b) & 1));
  return out;
}

/** The suffix of an IT instruction: `itte` for firstcond eq, mask 0b0110. */
export function itSuffix(firstcond: number, mask: number): string {
  let s = '';
  const trailing = mask & -mask;
  for (let b = 3; (1 << b) > trailing; b--) s += ((mask >> b) & 1) === (firstcond & 1) ? 't' : 'e';
  return s;
}
