/**
 * The analysis of an x86 program — x86-64 or i386 code in an ELF file
 * (Linux, Android) or a Mach-O slice: the same results as src/core/program.ts
 * gives for arm64 — statistics, functions, labels, call and data references,
 * strings — for instructions of one to fifteen bytes.
 *
 * The code is cut into instructions as llvm-objdump cuts it: a linear sweep
 * through each code section that starts afresh wherever a function is known
 * to begin (a symbol, an export, the unwind table, the entry point), so the
 * listing lines up with LLVM's. A call into the middle of what the sweep took
 * for one instruction adds a start there, and the section is swept again.
 *
 * What the instructions point at is read from their operands: x86-64 code
 * names data relative to rip; i386 code that is position-independent keeps the
 * address of its GOT in a register it got from a call (`call
 * __x86.get_pc_thunk.bx` / `add ebx, …`), which is followed; code that is not
 * uses absolute addresses. Jumps through a GOT slot, an import stub or the PLT
 * name the import; `jmp` through a table of offsets (a switch) gets its cases.
 *
 * Per instruction only its offset, its length, a mnemonic number and a few
 * flag bits are kept; the listing decodes again the rows it shows.
 */

import { F } from '../arm64/types';
import { Disassembly, IF, tick, type CodeRange, type DataAt, type Progress, type StringRef } from '../disassembly';
import { loadEngine, X86Pass } from '../engine/engine';
import { abiOf, objcDataAt, platformOf, textAt, valueAt, type Image, type ImageSection } from '../image';
import { decodeX86, TYPE, type X86Decoded } from './decode';
import { type X86LiftContext } from './hla';
import { printX86 } from './print';

export interface X86Range extends CodeRange {
  section: ImageSection;
}

/** A memory operand as the decoder gives it. */
export interface X86Memory {
  /** Where its five MCInst operands start. */
  at: number;
  base: string;
  scale: number;
  index: string;
  disp: number;
  seg: string;
}

/** An instruction as the page shows it. */
export interface X86Insn {
  /** Prefixes the printer writes before the mnemonic: `lock`, `rep`, `notrack`, `{vex}`. */
  prefix: string;
  m: string;
  /** The operands as printed. */
  ops: string;
  addr: number;
  length: number;
  /** F bits (arm64/types): branch, call, return, load, store, flags. */
  f: number;
  /** Where a branch or call goes. */
  target?: number;
  /** The address a memory operand names, when it is fixed: rip-relative, absolute. */
  mem?: number;
  d: X86Decoded;
}

const MEMORY_TYPES = new Set<number>([TYPE.M, TYPE.MSIB, TYPE.MVSIBX, TYPE.MVSIBY, TYPE.MVSIBZ]);

/** F bits, as the core worked them out from the tables. */
function flagsOf(d: X86Decoded): number {
  if (!d.id) return F.UNKNOWN;
  return d.f ?? 0;
}

/** The first memory operand of an instruction. */
export function memoryOf(d: X86Decoded): X86Memory | undefined {
  for (let k = 0; k < d.types.length; k++) {
    if (!MEMORY_TYPES.has(d.types[k]!)) continue;
    return { at: k, base: d.ops[k] as string, scale: d.ops[k + 1] as number, index: d.ops[k + 2] as string, disp: d.ops[k + 3] as number, seg: d.ops[k + 4] as string };
  }
  return undefined;
}

/** Where a branch or call with a relative target goes. */
export function targetOf(d: X86Decoded): number | undefined {
  for (let k = 0; k < d.types.length; k++) {
    if (d.types[k] !== TYPE.REL) continue;
    const target = d.addr + d.length + Number(d.ops[k]);
    return d.mode === 32 ? target >>> 0 : target;
  }
  return undefined;
}

/** The address a memory operand names on its own: rip-relative, or absolute; an absolute moffs. */
export function fixedAddressOf(d: X86Decoded, absolute: boolean): number | undefined {
  const mem = memoryOf(d);
  if (mem) {
    if (mem.base === 'rip') return d.addr + d.length + mem.disp;
    if (mem.base === 'eip') return (d.addr + d.length + mem.disp) >>> 0;
    if (absolute && !mem.base && !mem.index && !mem.seg) return d.mode === 32 ? mem.disp >>> 0 : mem.disp;
    return undefined;
  }
  if (absolute) for (let k = 0; k < d.types.length; k++) if (d.types[k] === TYPE.MOFFS && typeof d.ops[k] !== 'string') return Number(d.ops[k]);
  return undefined;
}

export function insnOf(d: X86Decoded, absolute = false): X86Insn {
  const printed = printX86(d);
  return { ...printed, addr: d.addr, length: d.length, f: flagsOf(d), target: targetOf(d), mem: fixedAddressOf(d, absolute), d };
}

export class X86Program extends Disassembly {
  readonly arch = 'x86';
  declare readonly ranges: X86Range[];
  readonly mode: 64 | 32;
  /** Each instruction's offset in its section, its length, and whether it is an instruction (0) or data (DATA_KIND). */
  offs = new Uint32Array(0);
  lens = new Uint8Array(0);
  kinds = new Uint8Array(0);
  /** Address → symbol name, for data and code. */
  readonly symbolAt = new Map<number, string>();
  readonly importSlots = new Map<number, string>();
  /** The data address an instruction names or reads through: rip-relative, absolute, through the GOT register. */
  readonly addressAt = new Map<number, number>();
  /** The code address an instruction names without calling it: a function pointer (`lea rdi, [rip + main]`). */
  readonly codeAt = new Map<number, number>();
  /** Calls and jumps through an import's slot: slot → the instructions. */
  /** A jump through a table (a switch): the instruction → where its cases go. */
  readonly tables = new Map<number, number[]>();
  /** A call or jump with a relative target: the instruction → where it goes (from the core's pass). */
  readonly targets: Map<number, number> = new Map();
  /** Whether addresses in immediates and displacements are absolute (code that is not position-independent). */
  absolute = false;

  constructor(readonly image: Image) {
    super();
    this.mode = image.arch === 'x86_64' ? 64 : 32;
  }

  override rangeOfIndex(index: number): X86Range | undefined {
    for (const range of this.ranges) if (index >= range.first && index < range.first + range.count) return range;
    return undefined;
  }

  addrOf(index: number): number {
    const range = this.rangeOfIndex(index);
    return range ? range.section.addr + this.offs[index]! : 0;
  }

  sizeOf(index: number): number {
    return this.lens[index] ?? 1;
  }

  archLabel(): string {
    return abiOf(this.image);
  }

  override platformLabel(): string | undefined {
    return platformOf(this.image)?.label;
  }

  /** The instruction containing an address in code, or -1. */
  indexOf(addr: number): number {
    for (const range of this.ranges) {
      const start = range.section.addr;
      if (addr < start || addr >= start + range.section.size) continue;
      const offset = addr - start;
      let lo = range.first;
      let hi = range.first + range.count - 1;
      let found = -1;
      while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        if (this.offs[mid]! <= offset) {
          found = mid;
          lo = mid + 1;
        } else hi = mid - 1;
      }
      if (found < 0 || offset >= this.offs[found]! + this.lens[found]!) return -1;
      return found;
    }
    return -1;
  }

  /** The decoder's view of an instruction, without printing it. */
  decoded(index: number): X86Decoded {
    const range = this.rangeOfIndex(index)!;
    const s = range.section;
    return decodeX86(this.image.bytes, s.offset + this.offs[index]!, s.offset + s.size, s.addr + this.offs[index]!, this.mode);
  }

  insn(index: number): X86Insn {
    const kind = this.kinds[index]!;
    if (!kind) return insnOf(this.decoded(index), this.absolute);
    // Data among the instructions: one entry of it.
    const addr = this.addrOf(index);
    const size = DATA_SIZES[kind]!;
    const v = valueAt(this.image, addr, size as 1 | 2 | 4 | 8) ?? 0;
    return { prefix: '', m: DATA_NAMES[kind]!, ops: `0x${v.toString(16)}`, addr, length: size, f: 0, d: { id: 0, length: size, addr, mode: this.mode, ops: [], types: [], flags: 0, xacquire: false } };
  }

  isData(index: number): boolean {
    return !!this.kinds[index];
  }

  /** Whether an instruction is padding: `int3`, or two zero bytes (`add byte ptr [rax], al`). */
  private padding(index: number): boolean {
    if (this.kinds[index]) return false;
    const m = this.mnemonics[this.mnemonicIds[index]!];
    if (m === 'int3') return true;
    if (m !== 'add' || this.lens[index] !== 2) return false;
    const range = this.rangeOfIndex(index)!;
    const at = range.section.offset + this.offs[index]!;
    return this.image.bytes[at] === 0 && this.image.bytes[at + 1] === 0;
  }

  override paddingRun(index: number, end: number): number {
    if (!this.padding(index)) return 0;
    const id = this.mnemonicIds[index];
    let k = index + 1;
    while (k < end && this.mnemonicIds[k] === id && !(this.flags[k]! & (IF.FUNCTION | IF.LABEL)) && this.padding(k)) k++;
    return k - index;
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
    if (!(this.flags[index]! & IF.BRANCH) || this.kinds[index]) return out;
    const target = targetOf(this.decoded(index));
    if (target === undefined) return out;
    const at = this.indexOf(target);
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

  /** What the HLA64 view needs to name things. */
  context(): X86LiftContext {
    return {
      target: (addr) => this.target(addr),
      data: (addr) => this.dataAt(addr),
      functionStart: (pc) => {
        const at = this.functionOfIndex(this.indexOf(pc));
        return at < 0 ? -1 : this.functions[at]!.addr;
      },
      importAt: (addr) => {
        const name = this.importSlots.get(addr);
        return name === undefined ? undefined : this.image.demangle(name).short;
      },
    };
  }

  /** A function or a label at a code address, as the listing names it. */
  target(addr: number): { name: string; kind: 'function' | 'import' | 'label' } | undefined {
    const fn = this.functionAt(addr);
    if (fn) return { name: fn.name, kind: fn.kind === 'import' ? 'import' : 'function' };
    const index = this.indexOf(addr);
    if (index >= 0 && this.addrOf(index) === addr && this.flags[index]! & IF.LABEL) return { name: this.labelName(addr), kind: 'label' };
    return undefined;
  }
}

/** kinds: 0 an instruction; data entries by size. */
export const DATA_KIND = { 1: 1, 2: 2, 4: 3, 8: 4 } as const;
export const DATA_NAMES = ['', '.byte', '.short', '.long', '.quad'] as const;
const DATA_SIZES = [0, 1, 2, 4, 8] as const;

/* ------------------------------------------------------------------ *
 * The analysis
 * ------------------------------------------------------------------ */

/** Instructions per step of the core's pass. */
const CHUNK = 262144;

export async function analyzeX86(image: Image, progress: Progress = () => {}): Promise<X86Program> {
  const program = new X86Program(image);
  const started = Date.now();
  // Code that is not position-independent puts addresses in its immediates and displacements:
  // an ELF executable, and 32-bit Windows code (the loader relocates the addresses).
  program.absolute = image.format === 'elf' ? image.elf!.type === 2 : image.format === 'pe' && program.mode === 32;

  // Names known from the file, for the pages.
  for (const sym of image.symbols) if (sym.name && sym.addr) program.symbolAt.set(sym.addr, sym.name);
  for (const exp of image.exports) program.symbolAt.set(exp.addr, exp.name);
  for (const [slot, name] of image.slots) program.importSlots.set(slot, name);

  // The core reads the file again (crates/core/src/native), lays the code out, makes the pass
  // over every instruction (crates/core/src/x86/pass.rs), and then finds the stubs, the functions
  // and their names, and the strings: the file goes in once, the results come out once.
  const pass = X86Pass.native(await loadEngine(), image.source);
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
  program.ranges.push(...found.ranges.map((r) => ({ section: image.sections[r.section]!, name: image.sections[r.section]!.label, first: r.first, count: r.count })));
  program.offs = found.offs;
  program.lens = found.lens;
  program.kinds = found.kinds;
  program.mnemonicIds = found.mnemonicIds;
  program.flags = found.flags;
  program.totalInstructions = found.offs.length;
  program.mnemonics.push(...found.mnemonics);
  Object.assign(program, { callers: found.callers, dataRefs: found.dataRefs, slotCallers: found.slotCallers, tables: found.tables, addressAt: found.addressAt, codeAt: found.codeAt, targets: found.targets });
  program.decodeMs = Date.now() - started;
  program.tally(found.counts);

  // The stubs of a PLT or a Windows import table, which the core named.
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
