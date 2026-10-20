/**
 * The AArch32 decoder: an A32 word or a T32 instruction in, one instruction
 * out, printed as llvm-objdump prints it.
 *
 * The decoders — A32, T32, and the floating point, Advanced SIMD and crypto
 * extensions both share — are in the Rust core (crates/core/src/arm32/),
 * where the analysis of a whole program decodes every instruction without
 * leaving WebAssembly (crates/core/src/arm32_pass.rs). This is their face
 * for the rest of the TypeScript: one instruction per call, for the rows on
 * screen and the few questions the analysis still asks here.
 */

import { engine } from '../engine/engine';
import { F, type Insn } from './types';

/** Whether a T32 halfword starts a 32-bit instruction. */
export const isWide = (hw1: number): boolean => hw1 >>> 11 >= 0x1d;

/** An A32 instruction at `pc`. */
export function decodeArm(word: number, pc: number): Insn {
  return engine().arm32Decode<Insn>(0, word >>> 0, pc, -1);
}

/**
 * A T32 instruction at `pc`: `hw1` is its first halfword, `hw2` the next one
 * (read only when hw1 starts a 32-bit instruction). `it` is the condition the
 * enclosing IT block gives it (0…14), or -1 outside a block.
 */
export function decodeThumb(hw1: number, hw2: number, pc: number, it = -1): Insn {
  if (!isWide(hw1)) return engine().arm32Decode<Insn>(1, hw1 & 0xffff, pc, it);
  return engine().arm32Decode<Insn>(2, (((hw1 & 0xffff) << 16) | (hw2 & 0xffff)) >>> 0, pc, it);
}

/**
 * The IT conditions still to come after a T32 instruction, as LLVM counts
 * them: an instruction it cannot decode takes no slot, nor do the Armv8 FP and
 * SIMD encodings that ignore IT; a nested IT puts its own slots in front of
 * what is left of the outer block. `pending` is the list before the
 * instruction, the first entry being the condition it was decoded with.
 */
export function itAfter(pending: number[], insn: Insn, word: number): number[] {
  let rest = pending;
  if (rest.length && !(insn.f & F.UNKNOWN) && !(insn.size === 4 && engine().x.arm32_ignores_it(word >>> 0))) rest = rest.slice(1);
  return insn.it ? [...insn.it, ...rest] : rest;
}
