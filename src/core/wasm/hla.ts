/**
 * The HLA64 view of WebAssembly code: the marks its lines carry.
 *
 * HLA64 is an assembler with sugar for WebAssembly as for ARM64: its
 * programs are instructions, with words for what is obvious. On a stack
 * machine the obvious is the expression: `local.get 0, i32.const 1,
 * i32.add, local.set 2` is `l2 = l0 + 1`. The analysis
 * (crates/core/src/wasm/program.rs) marks the runs of instructions that make one
 * statement; the lifter (crates/core/src/wasm/hla.rs, asked through
 * WasmProgram.hla()) turns a run back into that statement, evaluating
 * the stack with expressions instead of values. Every line stands for the
 * instructions at its addresses and means exactly what they do:
 * operands are written in the order the instructions compute them, a
 * select becomes `c ? a : b` only when nothing in it has an effect, and
 * whatever has no word stays an instruction — as HLA64 accepts.
 *
 * `block`, `loop` and their `end` stay instructions (HLA64's own `loop { }`
 * repeats, a WebAssembly loop does not); an `if` whose condition is in the
 * line reads `if c {`, `} else {`, `}`. Branches name their target by its
 * address, as labels do on ARM64: `if l3 != l1 { goto L1f7 }`.
 *
 * Names in a line — functions, labels, strings, locals — are wrapped in
 * invisible marks (see mark()) so the page can make each one a link;
 * plain() takes them out.
 */

/* ------------------------------------------------------------------ *
 * Marks
 * ------------------------------------------------------------------ */

/** What a mark names: a function, a label, a string or data address, a local, a global. */
export type MarkKind = 'f' | 'l' | 's' | 'd' | 'v' | 'g';

const OPEN = '\u0001';
const SEP = '\u0002';
const CLOSE = '\u0003';

export function mark(kind: MarkKind, value: number, text: string): string {
  return `${OPEN}${kind}${value}${SEP}${text}${CLOSE}`;
}

/** The text of a line without its marks. */
export function plain(text: string): string {
  return text.replace(/\u0001[a-z]-?\d+\u0002/g, '').replace(/\u0003/g, '');
}

export interface Part {
  text: string;
  kind?: MarkKind;
  value?: number;
}

/** A line split into plain runs and marked names. */
export function parts(text: string): Part[] {
  const out: Part[] = [];
  const re = /\u0001([a-z])(-?\d+)\u0002([^\u0003]*)\u0003/g;
  let at = 0;
  for (let match = re.exec(text); match; match = re.exec(text)) {
    if (match.index > at) out.push({ text: text.slice(at, match.index) });
    out.push({ text: match[3]!, kind: match[1] as MarkKind, value: Number(match[2]) });
    at = re.lastIndex;
  }
  if (at < text.length) out.push({ text: text.slice(at) });
  return out;
}
