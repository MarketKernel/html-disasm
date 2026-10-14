/**
 * The AArch32 decoder: an A32 word or a T32 instruction in, one instruction
 * out, printed as llvm-objdump prints it.
 *
 * Floating point, Advanced SIMD and the crypto extensions are the same in both
 * instruction sets (T32 moves a bit or two), so simd.ts decodes them for both;
 * a32.ts and thumb.ts decode the rest of each set — data processing, branches,
 * loads and stores, the system and coprocessor instructions.
 */

import { decodeA32Base } from './a32';
import { decodeSimdA32, decodeSimdT32, ignoresIt } from './simd';
import { decodeT16, decodeT32Base } from './thumb';
import { F, type Insn } from './types';

/** Whether a T32 halfword starts a 32-bit instruction. */
export const isWide = (hw1: number): boolean => hw1 >>> 11 >= 0x1d;

/** An A32 instruction at `pc`. */
export function decodeArm(word: number, pc: number): Insn {
  return decodeSimdA32(word >>> 0, pc) ?? decodeA32Base(word >>> 0, pc);
}

/**
 * A T32 instruction at `pc`: `hw1` is its first halfword, `hw2` the next one
 * (read only when hw1 starts a 32-bit instruction). `it` is the condition the
 * enclosing IT block gives it (0…14), or -1 outside a block.
 */
export function decodeThumb(hw1: number, hw2: number, pc: number, it = -1): Insn {
  if (!isWide(hw1)) return decodeT16(hw1 & 0xffff, pc, it);
  const word = (((hw1 & 0xffff) << 16) | (hw2 & 0xffff)) >>> 0;
  return decodeSimdT32(word, pc, it) ?? decodeT32Base(word, pc, it);
}

/**
 * The IT conditions still to come after a T32 instruction, as LLVM counts
 * them: an instruction it cannot decode takes no slot, nor do the Armv8 FP and
 * SIMD encodings that ignore IT (ignoresIt); a nested IT puts its own slots in
 * front of what is left of the outer block. `pending` is the list before the
 * instruction, the first entry being the condition it was decoded with.
 */
export function itAfter(pending: number[], insn: Insn, word: number): number[] {
  let rest = pending;
  if (rest.length && !(insn.f & F.UNKNOWN) && !(insn.size === 4 && ignoresIt(word))) rest = rest.slice(1);
  return insn.it ? [...insn.it, ...rest] : rest;
}
