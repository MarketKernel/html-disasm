/**
 * The rows of the listing. A program of two million instructions is two
 * and a half million rows once function headers and labels are in, so the
 * rows are two typed arrays — what a row is and which instruction or
 * function it belongs to — and the page draws only the ones on screen.
 *
 * The assembly view has one row per instruction. The HLA64 view joins the
 * runs the analysis marked (a compare and its branch, adrp and its add; on
 * WebAssembly every instruction of a statement) into one row, and closes
 * every function with `}`. A long run of padding between functions (x86's
 * `int3`, zero bytes) is one row in both.
 */

import { IF, type Disassembly } from './disassembly';

export const ROW = {
  INSN: 0,
  LABEL: 1,
  FN_HEADER: 2,
  FN_END: 3,
  SECTION: 4,
  GAP: 5,
  /** A run of the same padding instruction: value is its first instruction, `span` how many. */
  PAD: 6,
} as const;

/** How many padding instructions make a run worth one row. */
const PAD_RUN = 8;

export type Mode = 'asm' | 'hla';

export interface Rows {
  mode: Mode;
  count: number;
  kind: Uint8Array;
  /** Instruction index (INSN, LABEL), function index (FN_*), range index (SECTION). */
  value: Int32Array;
  /** Instruction index → its row. */
  rowOfInsn: Int32Array;
  /** A padding row → how many instructions it stands for. */
  span: Map<number, number>;
}

export function buildRows(program: Disassembly, mode: Mode): Rows {
  const total = program.totalInstructions;
  const capacity = total + program.functions.length * 3 + program.ranges.length + 16 + countLabels(program);
  const kind = new Uint8Array(capacity);
  const value = new Int32Array(capacity);
  const rowOfInsn = new Int32Array(total);
  const span = new Map<number, number>();
  const flags = program.flags;
  let row = 0;
  const push = (k: number, v: number) => {
    kind[row] = k;
    value[row] = v;
    row++;
  };
  program.ranges.forEach((range, r) => {
    push(ROW.SECTION, r);
    let openFn = -1;
    const end = range.first + range.count;
    for (let i = range.first; i < end; i++) {
      if (flags[i]! & IF.FUNCTION) {
        const fn = program.functionAtIndex.get(i)!;
        if (mode === 'hla' && openFn >= 0) push(ROW.FN_END, openFn);
        push(ROW.GAP, fn);
        push(ROW.FN_HEADER, fn);
        openFn = fn;
      } else if (flags[i]! & IF.LABEL) {
        push(ROW.LABEL, i);
      }
      const run = program.paddingRun(i, end);
      if (run >= PAD_RUN) {
        for (let k = i; k < i + run; k++) rowOfInsn[k] = row;
        span.set(row, run);
        push(ROW.PAD, i);
        i += run - 1;
        continue;
      }
      rowOfInsn[i] = row;
      push(ROW.INSN, i);
      while (mode === 'hla' && flags[i]! & IF.FUSE && i + 1 < end) {
        i++;
        rowOfInsn[i] = row - 1;
      }
    }
    if (mode === 'hla' && openFn >= 0) push(ROW.FN_END, openFn);
  });
  return { mode, count: row, kind, value, rowOfInsn, span };
}

function countLabels(program: Disassembly): number {
  let n = 0;
  for (let i = 0; i < program.flags.length; i++) if (program.flags[i]! & IF.LABEL) n++;
  return n;
}
