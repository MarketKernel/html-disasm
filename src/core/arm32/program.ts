/**
 * The analysis of a 32-bit Arm library (Android's armeabi-v7a): the same
 * results as src/core/program.ts gives for arm64 — statistics, functions,
 * labels, call and data references, strings — for code that mixes two
 * instruction sets and keeps its constants among the instructions.
 *
 * Which bytes are A32, which are T32 and which are data is the first thing
 * to settle. A library that kept its symbol table says it with mapping
 * symbols ($a, $t, $d), exactly as llvm-objdump reads them. A stripped one
 * (every library in an APK) does not, and the analysis works it out:
 *
 * - every function symbol, init/fini pointer and the entry point says the
 *   instruction set at its address (bit 0 set is Thumb), and the PLT is A32;
 * - the code is decoded with that, and every `bl` and `blx` to an address
 *   says the set at its target (`blx` switches, `bl` keeps);
 * - every PC-relative load names a literal-pool word, and every `tbb`/`tbh`
 *   a table of branch offsets right after it: those bytes are data, shown as
 *   `.word`, `.short` or `.byte`, and decoding resumes after them.
 *
 * Twice round that loop is enough for what compilers emit. Instructions are
 * kept as small typed arrays — address, encoding, kind, IT condition — and
 * decoded again only for the rows on screen.
 */

import { F } from '../arm64/types';
import { Disassembly, IF, tick, type CodeRange, type DataAt, type Progress, type StringRef } from '../disassembly';
import { Arm32Pass, loadEngine } from '../engine/engine';
import { abiOf, objcDataAt, platformOf, textAt, type Image, type ImageSection } from '../image';
import { decodeArm, decodeThumb } from './decode';
import { type Insn } from './types';

/** What an entry of the instruction arrays is. */
export const KIND = { A32: 0, T16: 1, T32: 2, WORD: 3, SHORT: 4, BYTE: 5 } as const;
const SIZE = [4, 2, 4, 4, 2, 1] as const;
const DATA_NAMES = ['', '', '', '.word', '.short', '.byte'] as const;

export interface Arm32Range extends CodeRange {
  section: ImageSection;
}


export class Arm32Program extends Disassembly {
  readonly arch = 'arm32';
  declare readonly ranges: Arm32Range[];
  addrs = new Uint32Array(0);
  /** A32 word, T16 halfword, T32 as hw1 << 16 | hw2, or the data value. */
  words = new Uint32Array(0);
  kinds = new Uint8Array(0);
  /** The condition an IT block gives the instruction (0…14), or -1. */
  its = new Int8Array(0);
  /** Address → symbol name, for data and code. */
  readonly symbolAt = new Map<number, string>();
  readonly importSlots = new Map<number, string>();
  /**
   * The address an instruction completes or reads through: `add r0, pc` after
   * a literal load, `adr`, a literal holding an address, a load from a GOT
   * slot. The listing shows what is there.
   */
  readonly addressAt = new Map<number, number>();
  /** tbb/tbh: the instruction → where its table sends execution. */
  readonly tables = new Map<number, number[]>();
  /** Calls and branches with a target: the instruction → where it goes (from the core's pass). */
  readonly targets: Map<number, number> = new Map();
  /** Whether the instruction set came from mapping symbols (exact) or was worked out. */
  mapped = false;

  constructor(readonly image: Image) {
    super();
  }

  addrOf(index: number): number {
    return this.addrs[index] ?? 0;
  }

  sizeOf(index: number): number {
    return SIZE[this.kinds[index] as 0] ?? 4;
  }

  /** Whether an instruction is T32 (16 or 32 bits). */
  isThumb(index: number): boolean {
    const kind = this.kinds[index];
    return kind === KIND.T16 || kind === KIND.T32;
  }

  isData(index: number): boolean {
    return (this.kinds[index] ?? 0) >= KIND.WORD;
  }

  archLabel(): string {
    return abiOf(this.image);
  }

  override platformLabel(): string | undefined {
    return platformOf(this.image)?.label;
  }

  /** The instruction containing an address in code, or -1. */
  indexOf(addr: number): number {
    const addrs = this.addrs;
    let lo = 0;
    let hi = this.totalInstructions - 1;
    let found = -1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (addrs[mid]! <= addr) {
        found = mid;
        lo = mid + 1;
      } else hi = mid - 1;
    }
    if (found < 0 || addr >= addrs[found]! + this.sizeOf(found)) return -1;
    return found;
  }

  insn(index: number): Insn {
    return decodeAt(this.kinds[index]!, this.words[index]!, this.addrs[index]!, this.its[index]!);
  }

  branchTargets(index: number): number[] {
    const table = this.tables.get(index);
    const out: number[] = [];
    if (table) {
      for (const addr of table) {
        const at = this.indexOf(addr);
        if (at >= 0 && !out.includes(at)) out.push(at);
      }
      return out;
    }
    if (!(this.flags[index]! & IF.BRANCH) || this.isData(index)) return out;
    const insn = this.insn(index);
    if (insn.target === undefined || insn.f & (F.CALL | F.INDIRECT)) return out;
    const at = this.indexOf(insn.target);
    return at >= 0 ? [at] : out;
  }

  dataAt(addr: number): DataAt {
    const objc = objcDataAt(this.image, addr);
    if (objc) return objc;
    const string = this.stringAt.get(addr) ?? textAt(this.image, addr);
    if (string) return { kind: 'string', text: string.text };
    const imported = this.importSlots.get(addr);
    if (imported) return { kind: 'symbol', name: `got.${imported}` };
    const symbol = this.symbolAt.get(addr);
    if (symbol) return { kind: 'symbol', name: this.image.demangle(symbol).short };
    return undefined;
  }

  /** A function or a label at a code address, as the listing names it. */
  target(addr: number): { name: string; kind: 'function' | 'import' | 'label' } | undefined {
    const fn = this.functionAt(addr);
    if (fn) return { name: fn.name, kind: fn.kind === 'import' ? 'import' : 'function' };
    const index = this.indexOf(addr);
    if (index >= 0 && this.addrs[index] === addr && this.flags[index]! & IF.LABEL) return { name: this.labelName(addr), kind: 'label' };
    return undefined;
  }
}

/** One entry of the arrays, decoded. */
export function decodeAt(kind: number, word: number, pc: number, it: number): Insn {
  switch (kind) {
    case KIND.A32:
      return decodeArm(word, pc);
    case KIND.T16:
      return decodeThumb(word, 0, pc, it);
    case KIND.T32:
      return decodeThumb(word >>> 16, word & 0xffff, pc, it);
  }
  const bytes: number = SIZE[kind as 3];
  const t = `0x${(word >>> 0).toString(16).padStart(bytes * 2, '0')}`;
  return { m: DATA_NAMES[kind as 3], ops: [{ k: 'imm', v: word >>> 0, t }], f: 0, size: bytes === 4 ? 4 : 2, bytes };
}

/* ------------------------------------------------------------------ *
 * The analysis
 * ------------------------------------------------------------------ */

/** Instructions per step of the core's pass. */
const CHUNK = 262144;

export async function analyzeArm32(image: Image, progress: Progress = () => {}): Promise<Arm32Program> {
  const program = new Arm32Program(image);
  const started = Date.now();

  // Names known from the file, for the pages.
  for (const sym of image.symbols) if (sym.name && sym.addr) program.symbolAt.set(sym.addr, sym.name);
  for (const exp of image.exports) program.symbolAt.set(exp.addr, exp.name);
  for (const [slot, name] of image.slots) program.importSlots.set(slot, name);

  // The core reads the file again (crates/core/src/native), settles which bytes are A32, T32 and
  // data, makes the pass over every instruction (crates/core/src/arm32/pass.rs), and then finds the
  // stubs, the functions and their names, and the strings: the file goes in once, the results come out once.
  progress('decode', 0, 1);
  await tick();
  const pass = Arm32Pass.native(await loadEngine(), image.source);
  let shown = performance.now();
  while (!pass.step(CHUNK)) {
    if (performance.now() - shown > 40) {
      progress('decode', pass.done, pass.total);
      await tick();
      shown = performance.now();
    }
  }
  progress('decode', pass.total, pass.total);
  progress('functions', 0, 1);
  await tick();
  const found = pass.take((index) => program.addrOf(index));
  program.mapped = found.mapped;
  program.addrs = found.addrs;
  program.words = found.words;
  program.kinds = found.kinds;
  program.its = found.its;
  program.ranges.push(...found.ranges.map((r) => ({ section: image.sections[r.section]!, name: image.sections[r.section]!.label, first: r.first, count: r.count })));
  const total = found.addrs.length;
  program.totalInstructions = total;
  program.mnemonicIds = found.mnemonicIds;
  program.flags = found.flags;
  program.mnemonics.push(...found.mnemonics);
  Object.assign(program, { callers: found.callers, dataRefs: found.dataRefs, slotCallers: found.slotCallers, slotCalls: found.slotCalls, tables: found.tables, addressAt: found.addressAt, targets: found.targets });
  program.decodeMs = Date.now() - started;
  program.tally(found.counts);

  // The stubs of the PLT or a Windows import table, which the core named.
  for (const [stub, name] of found.native.stubs) image.stubs.set(stub, name);
  for (const [addr, first, count, name, full, raw, kind, language] of found.native.functions) {
    program.functionAtIndex.set(first, program.functions.length);
    program.functions.push({ addr, first, count, name, full, raw: raw ?? undefined, kind, language: language ?? undefined });
  }
  for (const [addr, text, section, cstring] of found.native.strings) {
    const ref: StringRef = { addr, text, section, kind: cstring ? 'cstring' : 'const' };
    program.strings.push(ref);
    program.stringAt.set(addr, ref);
  }
  progress('done', 1, 1);
  return program;
}

export type { StringRef };
