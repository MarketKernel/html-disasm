/**
 * What the floating-point and SIMD decoders share: register operands, the
 * way a mnemonic takes its condition and data type, and the immediates LLVM
 * prints in its own formats.
 *
 * Every decoder here reads an A32-shaped word. T32 encodings are turned into
 * their A32 twins first (simd.ts), so `Ctx` says what the word really was:
 * the condition it executes under and whether it came from Thumb code.
 */

import { CONDS, F, hex, immText, list, type Insn, type Op, unknown } from './types';

export interface Ctx {
  /** The instruction as it was encoded (the T32 word for Thumb), for `.inst`. */
  raw: number;
  pc: number;
  thumb: boolean;
  /** The condition: the A32 field, or the IT block's in Thumb; 14 is always, 15 (Thumb only) the "else" of an IT on AL. */
  cond: number;
}

export const bits = (w: number, hi: number, lo: number): number => (w >>> lo) & ((1 << (hi - lo + 1)) - 1);
export const bit = (w: number, n: number): number => (w >>> n) & 1;

/* ------------------------------------------------------------------ *
 * Registers
 * ------------------------------------------------------------------ */

// Register operands are shared between instructions, so they are frozen.
const regOps = (prefix: string, n: number): Op[] => Array.from({ length: n }, (_, i) => Object.freeze({ k: 'reg', r: `${prefix}${i}` }) as Op);
const SREGS = regOps('s', 32);
const DREGS = regOps('d', 32);
const QREGS = regOps('q', 16);
const GREGS = ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'sp', 'lr', 'pc'].map((r) => Object.freeze({ k: 'reg', r }) as Op);

export const S = (n: number): Op => SREGS[n]!;
export const D = (n: number): Op => DREGS[n]!;
/** A Q register from its D-register number (always even here). */
export const Q = (n: number): Op => QREGS[n >> 1]!;
export const R = (n: number): Op => GREGS[n]!;
/** A D register, or a Q register when `q` is set: the shape of most vector operands. */
export const V = (n: number, q: number): Op => (q ? QREGS[n >> 1]! : DREGS[n]!);

/**
 * The name LLVM prints for the D register `n` places after d0. Lists of three
 * or four consecutive registers are printed by stepping through LLVM's
 * register numbering, so past d31 they run on into the registers that follow
 * it there: `{d30, d31, fpinst2}`.
 */
const DNAMES = [...DREGS.map((op) => (op as { r: string }).r), 'fpinst2', 'mvfr0', 'mvfr1'];
export const dname = (n: number): string => DNAMES[n] ?? `d${n}`;

/** `{d4, d5, d6}`: `count` registers from `first`, `step` apart, each followed by `suffix` (`[]`, `[1]`). */
export function dlist(first: number, count: number, step: number, suffix = '', wrap = false): Op {
  const regs: string[] = [];
  for (let i = 0; i < count; i++) {
    const n = first + i * step;
    regs.push(dname(wrap ? n & 31 : n) + suffix);
  }
  return list(regs);
}

/** The D (or S) register number from a 4-bit field and its extra bit: D:Vd for D, Vd:D for S. */
export const dreg = (w: number, lo: number, extra: number): number => (bit(w, extra) << 4) | bits(w, lo + 3, lo);
export const sreg = (w: number, lo: number, extra: number): number => (bits(w, lo + 3, lo) << 1) | bit(w, extra);

/** Vd, Vn, Vm of the usual places: Vd = D:Vd(22, 15-12), Vn = N:Vn(7, 19-16), Vm = M:Vm(5, 3-0). */
export const vd = (w: number): number => dreg(w, 12, 22);
export const vn = (w: number): number => dreg(w, 16, 7);
export const vm = (w: number): number => dreg(w, 0, 5);
export const sd = (w: number): number => sreg(w, 12, 22);
export const sn = (w: number): number => sreg(w, 16, 7);
export const sm = (w: number): number => sreg(w, 0, 5);

/* ------------------------------------------------------------------ *
 * Instructions
 * ------------------------------------------------------------------ */

/**
 * An instruction under the context's condition. `predicable` instructions
 * print it between the operation and the data type (`vaddeq.f32`,
 * `vldmiane`); the Armv8 additions (vsel, vrinta, the crypto ones…) cannot
 * be conditional and never print one.
 */
export function mk(ctx: Ctx, op: string, dt: string, ops: Op[], f = 0, predicable = true, extra?: Partial<Insn>): Insn {
  let m = op;
  let flags = f;
  let condName: string | undefined;
  if (predicable && ctx.cond !== 14) {
    if (ctx.cond === 15) {
      // The "else" half of an IT block on AL: LLVM marks the impossible condition.
      m += '<und>';
    } else {
      condName = CONDS[ctx.cond];
      m += condName;
      flags |= F.COND | F.READS_FLAGS;
    }
  }
  if (dt) m += `.${dt}`;
  const insn: Insn = { m, ops, f: flags, size: 4 };
  if (condName) insn.cond = condName;
  if (extra) Object.assign(insn, extra);
  return insn;
}

/** An encoding of this space that is not an instruction. */
export const undef = (ctx: Ctx): Insn => unknown(ctx.raw, 4, ctx.thumb);

/* ------------------------------------------------------------------ *
 * Immediates
 * ------------------------------------------------------------------ */

/** `#0x1f`: what LLVM prints for most NEON immediates (shift amounts, vext indexes). */
export const ih = (v: number): Op => immText(v, `#${hex(v)}`);
/** `#-13`: decimal, as fixed-point fraction bits print. */
export const id = (v: number): Op => immText(v, `#${v}`);

/** The value of the 8-bit floating-point immediate of vmov.f32/.f64/.f16 (VFPExpandImm). */
export function fpImm8(imm8: number): number {
  const sign = imm8 & 0x80 ? -1 : 1;
  const exponent = (((imm8 >> 4) & 7) ^ 4) - 3;
  return sign * ((16 + (imm8 & 15)) / 16) * 2 ** exponent;
}

/** C's `%e`, which LLVM uses for floating-point immediates: `#5.000000e-01`. */
function cExponent(value: number): string {
  const [mantissa, exponent] = value.toExponential(6).split('e') as [string, string];
  const sign = exponent[0] === '-' ? '-' : '+';
  return `${mantissa}e${sign}${exponent.slice(1).padStart(2, '0')}`;
}
const FP_IMMS: Op[] = Array.from({ length: 256 }, (_, imm8) => immText(fpImm8(imm8), `#${cExponent(fpImm8(imm8))}`));
/** The operand of an 8-bit floating-point immediate, as LLVM prints it: `#5.000000e-01`. */
export const fpImmOp = (imm8: number): Op => FP_IMMS[imm8 & 0xff]!;
