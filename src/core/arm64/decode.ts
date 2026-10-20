/**
 * The AArch64 decoder: one 32-bit word in, one instruction out.
 *
 * The decoder itself is in the Rust core (crates/core/src/arm64/decode.rs and
 * simd.rs), which the whole-program pass runs over every instruction without
 * leaving WebAssembly. This is its face for the rest of the TypeScript: one
 * call per instruction, for the rows on screen, the details panel and the
 * editor — never for a whole program.
 *
 * It still prints what llvm-objdump prints: tools/verify-decoder.mjs compares
 * the two instruction by instruction.
 */

import { engine } from '../engine/engine';
import type { Insn } from './types';

export function decode(word: number, pc: number): Insn {
  return engine().arm64Decode<Insn>(word, pc);
}
