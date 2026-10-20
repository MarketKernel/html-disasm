/**
 * The analysis of a whole arm64 program — a Mach-O file, or an ELF library
 * for Android or Linux: every instruction of every code section is
 * decoded once, in chunks so the page stays responsive, and from that pass
 * come the statistics, the functions, the labels, the call and data cross
 * references, and which neighbouring instructions the HLA64 view joins.
 *
 * Only small typed arrays are kept per instruction (a mnemonic number and a
 * few flag bits); the listing decodes again the few hundred rows it shows.
 */

import { decode } from './arm64/decode';
import { F, type Insn } from './arm64/types';
import { Disassembly, IF, tick, type CodeRange, type Progress, type StringRef } from './disassembly';
import { Arm64Pass, loadEngine } from './engine/engine';
import { type LiftContext } from './hla';
import { abiOf, objcDataAt, platformOf, textAt, type Image, type ImageSection } from './image';

export { IF, type Fn, type MnemonicCount, type Progress, type Stage, type StringRef } from './disassembly';

export interface ArmRange extends CodeRange {
  section: ImageSection;
}

export class Program extends Disassembly {
  readonly arch = 'arm64';
  declare readonly ranges: ArmRange[];
  words = new Uint32Array(0);
  /** Address → symbol name, for data and code. */
  readonly symbolAt = new Map<number, string>();
  readonly importSlots = new Map<number, string>();
  /**
   * Rust passes a &str as a pointer and a length in the next register:
   * adrp x1 / add x1 / mov w2, #len. The length found that way bounds the
   * string shown for the address, since Rust's literals sit back to back.
   */
  readonly lengthAt = new Map<number, number>();

  constructor(readonly image: Image) {
    super();
  }

  override rangeOfIndex(index: number): ArmRange | undefined {
    for (const range of this.ranges) if (index >= range.first && index < range.first + range.count) return range;
    return undefined;
  }

  addrOf(index: number): number {
    const range = this.rangeOfIndex(index);
    return range ? range.section.addr + (index - range.first) * 4 : 0;
  }

  /** A run of zero words (`udf #0`), the padding a Windows linker leaves between functions. */
  override paddingRun(index: number, end: number): number {
    if (this.words[index] !== 0) return 0;
    let k = index + 1;
    while (k < end && this.words[k] === 0 && !(this.flags[k]! & (IF.FUNCTION | IF.LABEL))) k++;
    return k - index;
  }

  archLabel(): string {
    return abiOf(this.image);
  }

  override platformLabel(): string | undefined {
    return platformOf(this.image)?.label;
  }

  branchTargets(index: number): number[] {
    const insn = this.insn(index);
    if (insn.target === undefined || insn.f & F.CALL || !(insn.f & F.BRANCH)) return [];
    const target = this.indexOf(insn.target);
    return target >= 0 ? [target] : [];
  }

  /** The instruction index of an address in code, or -1. */
  indexOf(addr: number): number {
    for (const range of this.ranges) {
      const start = range.section.addr;
      if (addr >= start && addr < start + range.count * 4) return range.first + Math.floor((addr - start) / 4);
    }
    return -1;
  }

  insn(index: number): Insn {
    return decode(this.words[index]!, this.addrOf(index));
  }

  /** What is at a data address: a string, an imported pointer, a symbol. */
  dataAt(addr: number): ReturnType<LiftContext['data']> {
    const objc = objcDataAt(this.image, addr);
    if (objc) return objc;
    const string = this.stringAt.get(addr) ?? this.printableAt(addr);
    if (string) return { kind: 'string', text: string.text };
    const imported = this.importSlots.get(addr);
    if (imported) return { kind: 'symbol', name: `got.${imported}` };
    const symbol = this.symbolAt.get(addr);
    // A data symbol as code reads it: Mach-O's `_counter` is C's `counter`.
    if (symbol) return { kind: 'symbol', name: this.image.demangle(symbol).short };
    return undefined;
  }

  /** A string that starts at an address inside another one or in constant data. */
  private printableAt(addr: number): StringRef | undefined {
    return textAt(this.image, addr, this.lengthAt.get(addr));
  }

  context(): LiftContext {
    return {
      target: (addr) => {
        const fn = this.functionAt(addr);
        if (fn) return { name: fn.name, kind: fn.kind === 'import' ? 'import' : 'function' };
        const index = this.indexOf(addr);
        if (index >= 0 && this.flags[index]! & IF.LABEL) return { name: this.labelName(addr), kind: 'label' };
        return undefined;
      },
      data: (addr) => this.dataAt(addr),
      functionStart: (pc) => {
        const at = this.functionOfIndex(this.indexOf(pc));
        return at < 0 ? -1 : this.functions[at]!.addr;
      },
    };
  }
}

export async function analyze(image: Image, progress: Progress = () => {}): Promise<Program> {
  const program = new Program(image);
  const started = Date.now();

  // Code: every section of instructions, in address order (the core lays them out the same way).
  let total = 0;
  const code = image.sections.filter((s) => s.code && s.size >= 4 && s.offset).sort((a, b) => a.addr - b.addr);
  for (const section of code) {
    const count = Math.floor(section.size / 4);
    program.ranges.push({ section, name: section.label, first: total, count });
    total += count;
  }
  program.totalInstructions = total;

  // The core reads the file again (crates/core/src/native), makes the pass over every instruction
  // (crates/core/src/arm64/pass.rs) and then finds the stubs, the functions and their names, and
  // the strings: the file goes in once, the results come out once.
  const pass = Arm64Pass.native(await loadEngine(), image.source);
  // Back to the page every few dozen milliseconds, not every chunk: a browser's timer waits 4 ms at the least.
  let shown = performance.now();
  while (!pass.step(CHUNK)) {
    if (performance.now() - shown > 40) {
      progress('decode', pass.done, total);
      await tick();
      shown = performance.now();
    }
  }
  progress('decode', total, total);
  progress('functions', 0, 1);
  await tick();
  const found = pass.take((index) => program.addrOf(index));
  program.words = found.words;
  program.mnemonicIds = found.mnemonicIds;
  program.flags = found.flags;
  program.mnemonics.push(...found.mnemonics);
  Object.assign(program, { callers: found.callers, dataRefs: found.dataRefs, slotCallers: found.slotCallers, slotCalls: found.slotCalls, lengthAt: found.lengthAt });
  program.decodeMs = Date.now() - started;
  program.tally(found.counts);

  // Names known from the file, for the pages.
  for (const sym of image.symbols) if (sym.name && sym.addr) program.symbolAt.set(sym.addr, sym.name);
  for (const exp of image.exports) program.symbolAt.set(exp.addr, exp.name);
  for (const [slot, name] of image.slots) program.importSlots.set(slot, name);
  // The stubs of an ELF PLT or a Windows import table, which the core named.
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

/** Instructions per step of the core's pass. */
const CHUNK = 262144;
