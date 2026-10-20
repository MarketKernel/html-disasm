/**
 * The HLA64 view: decoded instructions written as HLA64.
 *
 * HLA64 is an assembler with sugar, not a separate language, so this is not
 * decompilation: each line still stands for the instruction (or the two) at
 * its address. Where HLA64 has a word for what an instruction does —
 * `x0 = [x1 + 8]`, `if x8 == 0 { goto L… }`, `push x29, x30`, `f()` — the
 * line uses it; where it has none (SIMD, exclusives, system registers) the
 * instruction stays as it is, which HLA64 accepts too.
 *
 * The lifters are in the core: crates/core/src/arm64/hla.rs and
 * crates/core/src/x86/hla.rs, the same ones the analysis asks which
 * neighbours make one line. What a line names — functions, labels, strings,
 * imports — is the page's to say (it names functions as the settings ask), so
 * the core asks for it: a line is made in rounds (crates/wasm/src/hla.rs),
 * each answering the questions the last one left, and this file answers them
 * from a LiftContext.
 *
 * Each line lists the words of src/data/hla64-words.json it uses, so the
 * page can explain them; words marked "new" there are this project's
 * additions to HLA64.
 */

import type { DataAt } from './disassembly';
import { engine } from './engine/engine';

export interface Target {
  name: string;
  kind: 'label' | 'function' | 'import';
}

export interface LiftContext {
  /** How to name a branch or call target. */
  target(addr: number): Target | undefined;
  /** What is at a data address: a string, or a named symbol. */
  data(addr: number): DataAt;
  /** Start of the function the instruction is in (for telling a tail call from a goto). */
  functionStart(pc: number): number;
  /** The import whose slot is at an address (`call qword ptr [rip + …]`); x86 asks it. */
  importAt?(addr: number): string | undefined;
}

export interface HlaLine {
  text: string;
  words: string[];
  comment?: string;
}

/** A line as the core makes it: whether it stands for the instruction and the next, and where its names lead (arm64). */
export interface Lifted extends HlaLine {
  fused: boolean;
  link?: number;
}

/* ------------------------------------------------------------------ *
 * The rounds
 * ------------------------------------------------------------------ */

const encoder = new TextEncoder();

/** The little-endian buffer a lifting call reads (see crates/wasm/src/hla.rs). */
export class Input {
  private bytes = new Uint8Array(256);
  private view = new DataView(this.bytes.buffer);
  length = 0;

  private room(n: number): void {
    if (this.length + n <= this.bytes.length) return;
    const bigger = new Uint8Array(Math.max(this.bytes.length * 2, this.length + n));
    bigger.set(this.bytes.subarray(0, this.length));
    this.bytes = bigger;
    this.view = new DataView(bigger.buffer);
  }

  u8(v: number): void {
    this.room(1);
    this.bytes[this.length++] = v;
  }

  u32(v: number): void {
    this.room(4);
    this.view.setUint32(this.length, v, true);
    this.length += 4;
  }

  f64(v: number): void {
    this.room(8);
    this.view.setFloat64(this.length, v, true);
    this.length += 8;
  }

  text(s: string): void {
    const b = encoder.encode(s);
    this.u32(b.length);
    this.room(b.length);
    this.bytes.set(b, this.length);
    this.length += b.length;
  }

  get data(): Uint8Array {
    return this.bytes.subarray(0, this.length);
  }
}

const TARGET_KIND = { label: 1, function: 2, import: 3 } as const;

/** Writes what is at `addr` for a question of `kind` (and `text`, which a question of a Java string carries), after its kind and address. */
export type Answer = (input: Input, kind: number, addr: number, text?: string) => void;

/** Answers from a LiftContext: 0 a target, 1 data, 2 the start of a function, 3 an import's slot. */
export function contextAnswers(ctx: LiftContext): Answer {
  return (input, kind, addr) => {
    switch (kind) {
      case 0: {
        const t = ctx.target(addr);
        input.u8(t ? TARGET_KIND[t.kind] : 0);
        if (t) input.text(t.name);
        break;
      }
      case 1: {
        const d = ctx.data(addr);
        input.u8(!d ? 0 : d.kind === 'symbol' ? 3 : d.objc ? 2 : 1);
        if (d) input.text(d.kind === 'symbol' ? d.name : d.text);
        break;
      }
      case 2:
        input.f64(ctx.functionStart(addr));
        break;
      default: {
        const name = ctx.importAt?.(addr);
        input.u8(name === undefined ? 0 : 1);
        if (name !== undefined) input.text(name);
      }
    }
  };
}

/**
 * Runs a lifting call until the core has asked all it needs: `call` gets the
 * input (`head` written first, then the answers `answer` writes) and returns the core's JSON.
 */
export function rounds<T>(answer: Answer, head: (input: Input) => void, call: (input: Uint8Array) => string): T {
  const asked: [number, number, string?][] = [];
  for (;;) {
    const input = new Input();
    head(input);
    input.u32(asked.length);
    for (const [kind, addr, text] of asked) {
      input.u8(kind);
      input.f64(addr);
      answer(input, kind, addr, text);
    }
    const result = JSON.parse(call(input.data)) as T & { need?: [number, number, string?][] };
    if (!result.need) return result;
    asked.push(...result.need);
  }
}

/* ------------------------------------------------------------------ *
 * arm64
 * ------------------------------------------------------------------ */

/**
 * The HLA64 line of the instruction `word` at `pc`: joined with the next one
 * when `next` is given and the two make one line, alone otherwise.
 */
export function liftArm64(word: number, pc: number, ctx: LiftContext, next?: { word: number; pc: number }): Lifted {
  const e = engine();
  return rounds<Lifted>(contextAnswers(ctx), () => {}, (input) => e.arm64Hla(word, pc, next?.word ?? 0, next?.pc ?? 0, next ? 1 : 0, input));
}

/** The instruction as printed, with branch targets by name. */
export function rawInstruction(word: number, pc: number, ctx: LiftContext): string {
  const e = engine();
  return rounds<{ text: string }>(contextAnswers(ctx), () => {}, (input) => e.arm64Hla(word, pc, 0, 0, 2, input)).text;
}

/**
 * The address an adrp + second instruction pair forms, or undefined when the
 * second one does not complete it (add #pageoff or a load/store at [reg, #pageoff]).
 */
export function pairedAddress(word: number, pc: number, next: number, nextPc: number): number | undefined {
  const addr = engine().arm64Paired(word, pc, next, nextPc);
  return Number.isNaN(addr) ? undefined : addr;
}
