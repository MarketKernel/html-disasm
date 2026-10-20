/**
 * The HLA64 view of x86-64 code. HLA64 has an x64 target, with the same
 * sugar as on ARM64 over x86's registers: `rax = [rbx + 8]`, `eax = u8[rdi]`,
 * `rcx += rdx`, `if eax < ebx { goto L }`, `printf()`. As on ARM64 a line is
 * one instruction, or a compare joined with the jump or conditional move that
 * tests its flags, and it uses sugar only where the sugar means exactly what
 * the instruction does; anything else stays the instruction.
 *
 * The lifter is in the core (crates/core/src/x86/hla.rs). It reads the
 * instruction as printed, so that is what goes in — data among the
 * instructions and patched bytes included — and the names it asks for are
 * answered from the context, in rounds (../hla.ts).
 */

import { contextAnswers, rounds, type Input, type Lifted, type LiftContext } from '../hla';
import { engine } from '../engine/engine';
import type { X86Insn } from './program';

export interface X86LiftContext extends LiftContext {
  /** The import whose slot is at an address (`call qword ptr [rip + …]`). */
  importAt(addr: number): string | undefined;
}

function write(input: Input, insn: X86Insn): void {
  input.text(insn.prefix);
  input.text(insn.m);
  input.text(insn.ops);
  input.f64(insn.addr);
  input.f64(insn.length);
  input.f64(insn.f);
  input.f64(insn.target ?? NaN);
  input.f64(insn.mem ?? NaN);
}

/** The HLA64 line of an instruction: joined with `next` when that is given and the two make one line, alone otherwise. */
export function liftX86(insn: X86Insn, ctx: X86LiftContext, next?: X86Insn): Lifted {
  const e = engine();
  return rounds<Lifted>(
    contextAnswers(ctx),
    (input) => {
      write(input, insn);
      if (next) write(input, next);
    },
    (input) => e.x86Hla(next !== undefined, input),
  );
}
