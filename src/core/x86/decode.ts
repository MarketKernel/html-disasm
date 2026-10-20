/**
 * The x86 decoder: bytes in, an instruction out, the way LLVM's X86
 * disassembler reads them — so that, printed (print.ts), it is the line
 * llvm-objdump prints in Intel syntax. tools/verify-x86.mjs checks it.
 *
 * The decoder and its tables (generated from LLVM's description of the
 * target) are in the Rust core, crates/core/src/x86/; the pass over a whole
 * program runs there too (crates/core/src/x86_pass.rs). This is the face the
 * rest of the TypeScript sees: one instruction per call, decoded and printed
 * at once, for the rows on screen and the few questions the analysis still
 * asks here.
 *
 * The result is a list of operands as LLVM's MCInst has them: a register
 * name, an immediate, or a memory reference as five of them (base, scale,
 * index, displacement, segment).
 */

import { engine, ready } from '../engine/engine';
import type { X86Printed } from './print';

/** The operand specifiers' types, as X86DisassemblerDecoderCommon.h numbers them. */
export const TYPE = {
  NONE: 0, REL: 1, R8: 2, R16: 3, R32: 4, R64: 5, IMM: 6, UIMM8: 7, M: 8, MSIB: 9, MVSIBX: 10, MVSIBY: 11, MVSIBZ: 12, SRCIDX: 13, DSTIDX: 14,
  MOFFS: 15, ST: 16, MM64: 17, XMM: 18, YMM: 19, ZMM: 20, VK: 21, VK_PAIR: 22, TMM: 23, TMM_PAIR: 24, SEGMENTREG: 25, DEBUGREG: 26,
  CONTROLREG: 27, BNDR: 28, Rv: 29, RELv: 30, DUP0: 31,
} as const;
/** Bits of the generated `sem` table: what an instruction does, for the analysis. */
export const SEM = { CALL: 1, BRANCH: 2, RET: 4, INDIRECT: 8, COND: 16, BARRIER: 32, TRAP: 64, LOAD: 128, STORE: 256, SETS_FLAGS: 512, READS_FLAGS: 1024, PREFIX: 2048 } as const;
export const PFX = { AD_SIZE: 1, LOCK: 2, REPEAT: 4, REPEAT_NE: 8 } as const;

/** A register name ('' for none), or an immediate (a bigint only when it took 8 bytes). */
export type McOp = string | number | bigint;

export interface X86Decoded {
  /** The instruction, in the tables' dense numbering; 0 when the bytes do not decode. */
  id: number;
  /** Bytes taken — on failure, the bytes read before it failed (at least 1), as llvm-objdump skips them. */
  length: number;
  addr: number;
  mode: 64 | 32;
  ops: McOp[];
  /** Which operand specifier each MCInst operand came from (its type), for the analysis. */
  types: number[];
  /** Prefix flags the printer reads: lock, rep, repne, addr32. */
  flags: number;
  /** rep/repne before a locked instruction or xchg: printed as xrelease/xacquire. */
  xacquire: boolean;
  /** What the core printed for it, and what the analysis reads of it (the F bits, a relative target, a fixed address). */
  printed?: X86Printed;
  f?: number;
  target?: number;
  mem?: number;
  memAbs?: number;
}

interface Raw extends Omit<X86Decoded, 'printed'> {
  prefix: string;
  m: string;
  text: string;
}

/** The tables live in the core, which loads them itself: this waits for the core. */
export function loadX86(): Promise<void> {
  return ready();
}

export function decodeX86(bytes: Uint8Array, offset: number, end: number, addr: number, mode: 64 | 32): X86Decoded {
  const raw = engine().x86Decode<Raw>(bytes.subarray(offset, Math.max(offset, Math.min(end, bytes.length))), addr, mode);
  const { prefix, m, text, ...d } = raw;
  return { ...d, printed: { prefix, m, ops: text } };
}
