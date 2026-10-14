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
import { append, Disassembly, IF, tick, windowsMain, type CodeRange, type DataAt, type Fn, type Progress, type StringRef } from '../disassembly';
import { abiOf, bytesAt, cstrings, entryName, functionNames, objcDataAt, platformOf, sectionOf, slotValue, stubFunction, textAt, valueAt, type Image, type ImageSection } from '../image';
import { decodeX86, loadX86, SEM, TYPE, x86Tables, type McOp, type X86Decoded } from './decode';
import { fuseX86, isX86Consumer, X86_SETTERS, type X86LiftContext } from './hla';
import { formatX86, mnemonicX86, printX86 } from './print';

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
const GPR_TYPES = new Set<number>([TYPE.R8, TYPE.R16, TYPE.R32, TYPE.R64, TYPE.Rv]);

/** F bits from the analysis bits of the tables. */
function flagsOf(d: X86Decoded): number {
  if (!d.id) return F.UNKNOWN;
  const sem = x86Tables().sem[d.id]!;
  let f = 0;
  if (sem & SEM.CALL) f |= F.CALL;
  if (sem & SEM.BRANCH) f |= F.BRANCH;
  if (sem & SEM.RET) f |= F.RET;
  if (sem & SEM.INDIRECT) f |= F.INDIRECT;
  if (sem & SEM.COND) f |= F.COND;
  if (sem & SEM.TRAP) f |= F.TRAP;
  if (sem & SEM.LOAD) f |= F.LOAD;
  if (sem & SEM.STORE) f |= F.STORE;
  if (sem & SEM.SETS_FLAGS) f |= F.SETS_FLAGS;
  if (sem & SEM.READS_FLAGS) f |= F.READS_FLAGS;
  return f;
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

/** The general registers by number, whatever their width: rax, eax, ax and al are 0. */
const GPR = new Map<string, number>();
['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi'].forEach((r, i) => GPR.set(r, i));
['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi'].forEach((r, i) => GPR.set(r, i));
for (let i = 8; i < 32; i++) {
  GPR.set(`r${i}`, i);
  GPR.set(`r${i}d`, i);
}
const gpr = (op: McOp | undefined): number => (typeof op === 'string' ? GPR.get(op) ?? -1 : -1);

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
  /** An i386 load through [GOT register + index]: the value the register held, for switch tables. */
  readonly baseValues = new Map<number, number>();
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

/* ------------------------------------------------------------------ *
 * Laying out the code
 * ------------------------------------------------------------------ */

/** Bytes known to be data among the instructions: a switch table, an entry of LC_DATA_IN_CODE. */
interface DataRegion {
  addr: number;
  length: number;
  /** The size of each entry: 1, 2, 4 or 8. */
  entry: 1 | 2 | 4 | 8;
}

interface Layout {
  offs: Uint32Array<ArrayBuffer>;
  lens: Uint8Array<ArrayBuffer>;
  kinds: Uint8Array<ArrayBuffer>;
  ranges: X86Range[];
  /** Where calls with a relative target go, and the indirect jumps (for switches). */
  calls: Set<number>;
  jumps: number[];
}

/**
 * Sweeps every code section from its start, as llvm-objdump does, and starts
 * afresh at each of `starts` (sorted): an instruction that would run past one
 * still has its whole length, but the next begins at the start. The bytes of
 * `data` (sorted) become entries of data instead.
 */
function layOut(image: Image, sections: ImageSection[], starts: number[], data: DataRegion[], mode: 64 | 32): Layout {
  const capacity = sections.reduce((n, s) => n + s.size, 0);
  let offs = new Uint32Array(Math.max(16, Math.min(capacity, 1 << 20)));
  let lens = new Uint8Array(offs.length);
  let kinds = new Uint8Array(offs.length);
  const ranges: X86Range[] = [];
  const calls = new Set<number>();
  const jumps: number[] = [];
  const sem = x86Tables().sem;
  let count = 0;
  const grow = () => {
    const size = Math.min(capacity, offs.length * 2);
    const o = new Uint32Array(size);
    o.set(offs);
    offs = o;
    const l = new Uint8Array(size);
    l.set(lens);
    lens = l;
    const k = new Uint8Array(size);
    k.set(kinds);
    kinds = k;
  };
  const push = (pos: number, length: number, kind: number) => {
    if (count === offs.length) grow();
    offs[count] = pos;
    lens[count] = length;
    kinds[count] = kind;
    count++;
  };
  let k = 0;
  let r = 0;
  for (const s of sections) {
    const first = count;
    const end = s.offset + s.size;
    let pos = 0;
    while (pos < s.size) {
      const addr = s.addr + pos;
      while (k < starts.length && starts[k]! <= addr) k++;
      while (r < data.length && data[r]!.addr + data[r]!.length <= addr) r++;
      const region = data[r];
      if (region && region.addr <= addr) {
        // Inside data: entries of its size, up to its end (and bytes for a tail that is not one).
        const left = region.addr + region.length - addr;
        const size = left >= region.entry ? region.entry : 1;
        push(pos, Math.min(size, s.size - pos), DATA_KIND[size as 1]);
        pos += Math.min(size, s.size - pos);
        continue;
      }
      const d = decodeX86(image.bytes, s.offset + pos, end, addr, mode);
      push(pos, Math.min(d.length, 255), 0);
      let length = d.length;
      const next = Math.min(starts[k] ?? Infinity, region?.addr ?? Infinity);
      if (next > addr && next < addr + length) length = next - addr;
      pos += length;
      if (!d.id) continue;
      const bits = sem[d.id]!;
      if (bits & SEM.CALL) {
        const target = targetOf(d);
        if (target !== undefined && target !== addr + d.length) calls.add(target);
      } else if (bits & SEM.BRANCH && bits & SEM.INDIRECT && !(bits & SEM.RET)) jumps.push(count - 1);
    }
    ranges.push({ section: s, name: s.label, first, count: count - first });
  }
  return { offs: offs.slice(0, count), lens: lens.slice(0, count), kinds: kinds.slice(0, count), ranges, calls, jumps };
}

/** kinds: 0 an instruction; data entries by size. */
export const DATA_KIND = { 1: 1, 2: 2, 4: 3, 8: 4 } as const;
export const DATA_NAMES = ['', '.byte', '.short', '.long', '.quad'] as const;
const DATA_SIZES = [0, 1, 2, 4, 8] as const;

/* ------------------------------------------------------------------ *
 * The analysis
 * ------------------------------------------------------------------ */

export async function analyzeX86(image: Image, progress: Progress = () => {}): Promise<X86Program> {
  await loadX86();
  const program = new X86Program(image);
  const started = Date.now();
  const mode = program.mode;
  const sections = image.sections.filter((s) => s.code && s.size && s.offset).sort((a, b) => a.addr - b.addr);
  const inCode = (addr: number) => sections.some((s) => addr >= s.addr && addr < s.addr + s.size);
  // Code that is not position-independent puts addresses in its immediates and displacements:
  // an ELF executable, and 32-bit Windows code (the loader relocates the addresses).
  program.absolute = image.format === 'elf' ? image.elf!.type === 2 : image.format === 'pe' && mode === 32;

  // Where functions start, for the sweep to start afresh.
  const known = new Set<number>();
  for (const sym of [...image.symbols, ...image.exports]) if (inCode(sym.addr) && (sym.function || image.format === 'macho')) known.add(sym.addr);
  for (const addr of image.functionStarts) if (inCode(addr)) known.add(addr);
  for (const addr of image.stubs.keys()) if (inCode(addr)) known.add(addr);
  if (image.entry !== undefined && inCode(image.entry)) known.add(image.entry);
  for (const s of sections) if (s.stubSize) for (let at = s.addr; at < s.addr + s.size; at += s.stubSize) known.add(at);
  // Data the file says is among the instructions (Mach-O).
  const data: DataRegion[] = [];
  for (const entry of image.macho?.dataInCode ?? []) {
    if (!inCode(entry.addr) || !entry.length) continue;
    data.push({ addr: entry.addr, length: entry.length, entry: entry.kind === 2 ? 1 : entry.kind === 3 ? 2 : entry.length % 4 ? 1 : 4 });
  }

  const apply = (layout: Layout) => {
    program.ranges.length = 0;
    program.ranges.push(...layout.ranges);
    program.offs = layout.offs;
    program.lens = layout.lens;
    program.kinds = layout.kinds;
    program.totalInstructions = layout.offs.length;
  };
  const sorted = () => [...known].sort((a, b) => a - b);
  let layout = layOut(image, sections, sorted(), data.sort((a, b) => a.addr - b.addr), mode);
  apply(layout);
  // A call into what the sweep took for the middle of an instruction starts afresh there; a switch
  // table among the instructions is data. Once more over the code with both.
  let again = false;
  for (const target of layout.calls) {
    if (known.has(target) || !inCode(target)) continue;
    const at = program.indexOf(target);
    if (at >= 0 && program.addrOf(at) !== target) {
      known.add(target);
      again = true;
    }
  }
  for (const index of layout.jumps) {
    const found = switchOf(program, index, inCode, known);
    if (!found || !inCode(found.table)) continue;
    data.push({ addr: found.table, length: found.targets.length * found.entry, entry: found.entry });
    again = true;
  }
  if (again) {
    layout = layOut(image, sections, sorted(), mergeRegions(data), mode);
    apply(layout);
  }
  const total = program.totalInstructions;
  program.mnemonicIds = new Uint16Array(total);
  program.flags = new Uint8Array(total);

  // Names known from the file.
  for (const sym of image.symbols) if (sym.name && sym.addr) program.symbolAt.set(sym.addr, sym.name);
  for (const exp of image.exports) program.symbolAt.set(exp.addr, exp.name);
  for (const [slot, name] of image.slots) program.importSlots.set(slot, name);
  for (const ref of cstrings(image)) {
    program.strings.push(ref);
    program.stringAt.set(ref.addr, ref);
  }
  // i386 PLT stubs jump through [ebx + offset], ebx holding the address of .got.plt.
  const gotPlt = image.sections.find((s) => s.name === '.got.plt')?.addr ?? image.sections.find((s) => s.name === '.got')?.addr;

  // The pass over every instruction.
  const ids = new Map<string, number>();
  const counts: number[] = [];
  const labelTargets: number[] = [];
  const callTargets = new Set<number>();
  const flags = program.flags;
  const kinds = program.kinds;
  const tables = x86Tables();
  // Values of registers, for i386 position-independent code: an address.
  const value = new Float64Array(32).fill(NaN);
  const forget = (all: boolean) => {
    // A call keeps what the callee must preserve: ebx, esi, edi, ebp.
    for (let reg = 0; reg < 32; reg++) if (all || reg < 3) value[reg] = NaN;
  };
  const ref = (addr: number, pc: number) => {
    append(program.dataRefs, addr, pc);
  };
  /** Whether an address may be data the listing can name: a string, a slot, a symbol, or in a section that is not code. */
  const isData = (addr: number) => program.stringAt.has(addr) || program.importSlots.has(addr) || program.symbolAt.has(addr) || (!inCode(addr) && !!sectionOf(image, addr));
  const thunkReg = (addr: number): number => {
    const b = bytesAt(image, addr, 4);
    return b && b.length === 4 && b[0] === 0x8b && (b[1]! & 0xc7) === 0x04 && b[2] === 0x24 && b[3] === 0xc3 ? (b[1]! >> 3) & 7 : -1;
  };
  const dataIds: number[] = [];
  const CHUNK = 65536;
  let rangeEnd = -1;
  let range: X86Range | undefined;
  for (let i = 0; i < total; i++) {
    if (i % CHUNK === 0) {
      progress('decode', i, total);
      await tick();
    }
    if (i >= rangeEnd) {
      forget(true);
      range = program.rangeOfIndex(i);
      rangeEnd = range ? range.first + range.count : total;
    }
    if (kinds[i]) {
      const kind = kinds[i]!;
      let id = dataIds[kind];
      if (id === undefined) {
        id = program.mnemonics.length;
        dataIds[kind] = id;
        program.mnemonics.push(DATA_NAMES[kind]!);
        counts.push(0);
      }
      program.mnemonicIds[i] = id;
      counts[id]!++;
      continue;
    }
    const s = range!.section;
    const pc = s.addr + program.offs[i]!;
    // A function starts with nothing known of its registers.
    if (known.has(pc)) forget(true);
    const d = decodeX86(image.bytes, s.offset + program.offs[i]!, s.offset + s.size, pc, mode);
    const m = mnemonicX86(d);
    let id = ids.get(m);
    if (id === undefined) {
      id = program.mnemonics.length;
      ids.set(m, id);
      program.mnemonics.push(m);
      counts.push(0);
    }
    program.mnemonicIds[i] = id;
    counts[id]!++;
    if (!d.id) {
      flags[i]! |= IF.UNKNOWN;
      continue;
    }
    const sem = tables.sem[d.id]!;
    const next = pc + d.length;
    const target = targetOf(d);
    if (sem & SEM.CALL) {
      flags[i]! |= IF.CALL;
      // `call` to the next instruction is i386 code reading its own address, not a call.
      if (target !== undefined && target !== next) {
        callTargets.add(target);
        append(program.callers, target, pc);
      }
    } else if (sem & SEM.BRANCH) {
      flags[i]! |= IF.BRANCH;
      if (target !== undefined) labelTargets.push(target);
    }

    // The data the instruction names.
    const mem = memoryOf(d);
    let addr = fixedAddressOf(d, program.absolute || (mode === 32 && image.format !== 'elf'));
    if (addr === undefined && mem) {
      // Through a register holding an address: the GOT register of i386 code, a stub's [ebx + offset].
      const base = gpr(mem.base);
      if (base >= 0 && !Number.isNaN(value[base]!)) {
        if (!mem.index) addr = (value[base]! + mem.disp) >>> 0;
        else program.baseValues.set(i, value[base]!);
      } else if (mode === 32 && mem.base === 'ebx' && !mem.index && gotPlt !== undefined && /plt/.test(s.name)) addr = (gotPlt + mem.disp) >>> 0;
    }
    if (addr !== undefined && sem & (SEM.CALL | SEM.BRANCH) && program.importSlots.has(addr)) {
      program.addressAt.set(i, addr);
      append(program.slotCallers, addr, pc);
    } else if (addr !== undefined && isData(addr)) {
      program.addressAt.set(i, addr);
      ref(addr, pc);
    } else if (addr !== undefined && !(sem & (SEM.CALL | SEM.BRANCH)) && inCode(addr)) {
      program.codeAt.set(i, addr);
    } else if (program.absolute) {
      // An immediate that is an address (`push offset`, `mov dword ptr [esp], offset` in code that is not PIC).
      for (let k = 0; k < d.types.length; k++) {
        if (d.types[k] !== TYPE.IMM) continue;
        const v = Number(d.ops[k]) >>> 0;
        if (v >= 0x1000 && (program.stringAt.has(v) || program.symbolAt.has(v) || (isData(v) && textAt(image, v)))) {
          program.addressAt.set(i, v);
          ref(v, pc);
        } else if (inCode(v) && v >= 0x1000) program.codeAt.set(i, v);
        break;
      }
    }

    // Registers holding addresses, for i386 position-independent code.
    if (mode === 32) {
      const dest = GPR_TYPES.has(d.types[0] ?? -1) ? gpr(d.ops[0]) : -1;
      if (sem & SEM.CALL) {
        forget(false);
        const reg = target === next ? -2 : target !== undefined ? thunkReg(target) : -1;
        if (reg >= 0) value[reg] = next;
        continue;
      }
      if (sem & SEM.BRANCH) continue;
      if (m === 'pop' && dest >= 0 && i > 0 && kinds[i - 1] === 0) {
        // call next / pop reg: the address of the pop.
        const prev = program.decoded(i - 1);
        value[dest] = prev.id && tables.sem[prev.id]! & SEM.CALL && targetOf(prev) === pc ? pc : NaN;
        continue;
      }
      const last = d.ops.length - 1;
      if (m === 'add' && dest >= 0 && !mem && typeof d.ops[last] === 'number' && d.types[last] === TYPE.IMM) {
        value[dest] = Number.isNaN(value[dest]!) ? NaN : (value[dest]! + (d.ops[last] as number)) >>> 0;
        continue;
      }
      if (m === 'lea' && dest >= 0) {
        value[dest] = addr ?? NaN;
        continue;
      }
      if (dest >= 0 && !(sem & SEM.STORE)) value[dest] = NaN;
    }
  }
  progress('decode', total, total);

  // Stubs: a jump through an import's slot in a stub section or the PLT; in a Windows program the
  // thunks the linker puts among the code (`jmp qword ptr [__imp_X]`), one after another or after padding.
  for (const r of program.ranges) {
    const pe = image.format === 'pe';
    if (!pe && !/plt|stub/.test(r.section.name)) continue;
    for (let i = r.first; i < r.first + r.count; i++) {
      const slot = program.addressAt.get(i);
      if (slot === undefined || !(flags[i]! & IF.BRANCH)) continue;
      const name = program.importSlots.get(slot);
      if (!name) continue;
      if (pe && i > r.first && !known.has(program.addrOf(i))) {
        const before = program.mnemonics[program.mnemonicIds[i - 1]!]!;
        const thunkBefore = program.addressAt.has(i - 1) && flags[i - 1]! & IF.BRANCH;
        if (!thunkBefore && !/^(int3|nop|ret|jmp|ud2)$/.test(before)) continue;
      }
      // An endbr64 before the jump (a PLT with IBT) starts the stub.
      let start = program.addrOf(i);
      if (i > r.first && program.lens[i - 1] === 4 && /^endbr/.test(program.mnemonics[program.mnemonicIds[i - 1]!]!)) start = program.addrOf(i - 1);
      if (!image.stubs.has(start)) image.stubs.set(start, name);
    }
  }

  // Switches: a jump through a table of offsets or addresses.
  for (let i = 0; i < total; i++) {
    if ((flags[i]! & (IF.BRANCH | IF.CALL)) !== IF.BRANCH) continue;
    const found = switchOf(program, i, inCode, known);
    if (found) {
      program.tables.set(i, found.targets);
      labelTargets.push(...found.targets);
    }
  }
  program.decodeMs = Date.now() - started;
  program.tally(counts);

  // Labels: branch targets inside code.
  for (const target of labelTargets) {
    const index = program.indexOf(target);
    if (index >= 0 && program.addrOf(index) === target) flags[index]! |= IF.LABEL;
  }

  // Functions.
  progress('functions', 0, 1);
  await tick();
  const starts = new Map<number, { raw?: string; kind: Fn['kind'] }>();
  const add = (addr: number, raw: string | undefined, kind: Fn['kind']) => {
    const index = program.indexOf(addr);
    if (index < 0 || program.addrOf(index) !== addr || kinds[index]) return;
    const seen = starts.get(addr);
    if (!seen || (seen.kind === 'anonymous' && kind !== 'anonymous') || (!seen.raw && raw)) starts.set(addr, { raw: raw ?? seen?.raw, kind: seen && seen.kind !== 'anonymous' ? seen.kind : kind });
  };
  for (const r of program.ranges) {
    add(r.section.addr, undefined, 'anonymous');
    const stride = r.section.stubSize;
    if (stride) for (let at = r.section.addr; at < r.section.addr + r.section.size; at += stride) add(at, image.stubs.get(at), image.stubs.has(at) ? 'import' : 'anonymous');
  }
  for (const [at, name] of image.stubs) {
    if (image.format === 'macho') add(at, name, 'import');
    else {
      const stub = stubFunction(image, name);
      add(at, stub.raw, stub.kind);
    }
  }
  for (const addr of image.functionStarts) add(addr, undefined, 'anonymous');
  // Exports first: a function both exported and in the symbol table is listed as exported.
  for (const exp of image.exports) if (exp.function || image.format === 'macho') add(exp.addr, exp.name, 'export');
  for (const sym of image.symbols) if (sym.name && (sym.function || image.format === 'macho')) add(sym.addr, sym.name, 'symbol');
  for (const target of callTargets) add(target, undefined, 'anonymous');
  // A run of `jmp rel32` thunks (the table an incremental link puts calls through): a function each.
  const jmp = program.mnemonics.indexOf('jmp');
  for (const r of program.ranges) {
    let run = 0;
    for (let i = r.first; i <= r.first + r.count; i++) {
      const thunk = i < r.first + r.count && program.mnemonicIds[i] === jmp && program.lens[i] === 5 && !kinds[i];
      if (thunk) run++;
      else {
        if (run >= 4) for (let k = i - run; k < i; k++) add(program.addrOf(k), undefined, 'anonymous');
        run = 0;
      }
    }
  }
  if (image.entry !== undefined) add(image.entry, starts.get(image.entry)?.raw ?? entryName(image), 'entry');
  // A Windows entry point may end by jumping to the C runtime's startup (MinGW's __tmainCRTStartup on
  // i386, which no unwind table lists): that is a function too.
  if (image.format === 'pe' && image.entry !== undefined && program.indexOf(image.entry) >= 0) {
    const first = program.indexOf(image.entry);
    for (let i = first, end = Math.min(first + 16, total); i < end; i++) {
      const m = program.mnemonics[program.mnemonicIds[i]!];
      if (m === 'ret' || m === 'int3' || (flags[i]! & IF.BRANCH && m !== 'jmp')) break;
      if (m !== 'jmp') continue;
      const target = targetOf(program.decoded(i));
      if (target !== undefined && (target < image.entry || target > program.addrOf(i))) add(target, undefined, 'anonymous');
      break;
    }
  }
  // A stripped program's main is what _start hands to __libc_start_main.
  const main = mainOf(program, image);
  if (main !== undefined && !starts.get(main)?.raw) add(main, 'main', 'symbol');

  const sortedStarts = [...starts.keys()].sort((a, b) => a - b);
  for (let k = 0; k < sortedStarts.length; k++) {
    const addr = sortedStarts[k]!;
    const first = program.indexOf(addr);
    const r = program.rangeOfIndex(first)!;
    const nextStart = sortedStarts[k + 1];
    const nextIndex = nextStart !== undefined ? program.indexOf(nextStart) : -1;
    const end = nextIndex > first && nextIndex <= r.first + r.count ? nextIndex : r.first + r.count;
    const { raw, kind } = starts.get(addr)!;
    let name = `sub_${addr.toString(16)}`;
    let full = name;
    let language: string | undefined;
    if (raw) {
      const dm = functionNames(image, raw);
      name = dm.short;
      full = dm.full;
      language = dm.language;
    }
    if (kind === 'entry' && !raw) name = full = 'main';
    program.functionAtIndex.set(first, program.functions.length);
    program.functions.push({ addr, first, count: end - first, name, full, raw, kind, language });
    flags[first]! |= IF.FUNCTION;
  }

  // A function that only jumps elsewhere is a thunk: without a name of its own it is named after where it goes (j_name).
  for (let pass = 0; pass < 3; pass++) {
    for (const fn of program.functions) {
      if (fn.kind !== 'anonymous' || fn.raw || program.mnemonicIds[fn.first] !== jmp) continue;
      const target = targetOf(program.decoded(fn.first));
      const to = target !== undefined ? program.functionAt(target) : undefined;
      if (!to || to === fn || to.name.startsWith('sub_')) continue;
      fn.name = `j_${to.name}`;
      fn.full = `j_${to.full}`;
    }
  }

  // A stripped Windows program's main is found from how its C runtime calls it.
  if (image.format === 'pe') {
    const imported = (name: string): Fn => ({ addr: 0, first: -1, count: 0, name, full: name, raw: name, kind: 'import' });
    // The function a direct call or jump reaches, through the jmp thunks of an incremental link.
    const reached = (i: number): Fn | undefined => {
      const target = targetOf(program.decoded(i));
      let fn = target !== undefined ? program.functionAt(target) : undefined;
      if (!fn || fn.addr !== target) return undefined;
      for (let hop = 0; fn.count <= 2 && program.mnemonicIds[fn.first] === jmp && hop < 3; hop++) {
        const to = targetOf(program.decoded(fn.first));
        const next = to !== undefined ? program.functionAt(to) : undefined;
        if (!next || next.addr !== to) break;
        fn = next;
      }
      return fn;
    };
    const calls: { at: number; in: number; callee: Fn }[] = [];
    for (let i = 0; i < total; i++) {
      if (!(flags[i]! & IF.CALL)) continue;
      const slot = program.addressAt.get(i);
      const name = slot !== undefined ? program.importSlots.get(slot) : undefined;
      const callee = name !== undefined ? imported(name) : reached(i);
      if (callee) calls.push({ at: i, in: program.functionOfIndex(i), callee });
    }
    // The entry point and what it calls or jumps to, two steps deep (MSVC: mainCRTStartup, then __scrt_common_main_seh).
    const startup = new Set<number>();
    const entry = image.entry !== undefined ? program.indexOf(image.entry) : -1;
    let level = entry >= 0 ? [program.functionOfIndex(entry)] : [];
    for (let depth = 0; depth < 3 && level.length; depth++) {
      const next: number[] = [];
      for (const at of level) {
        if (at < 0 || startup.has(at)) continue;
        startup.add(at);
        const fn = program.functions[at]!;
        for (let i = fn.first; i < fn.first + fn.count && depth < 2; i++) {
          if (!(flags[i]! & (IF.CALL | IF.BRANCH))) continue;
          // A jump may land inside what the analysis takes for another function: that one is meant.
          const to = reached(i);
          const target = targetOf(program.decoded(i));
          if (to) next.push(program.functions.indexOf(to));
          else if (target !== undefined && program.indexOf(target) >= 0) next.push(program.functionOfIndex(program.indexOf(target)));
        }
      }
      level = next;
    }
    const stops = new Set(['jmp', 'ret', 'int3', 'ud2', 'hlt'].map((m) => program.mnemonics.indexOf(m)).filter((id) => id >= 0));
    const text = (i: number) => formatX86(printX86(program.decoded(i)));
    const found = windowsMain(calls, startup, {
      straight: (from, to) => {
        for (let i = from + 1; i < to; i++) if (stops.has(program.mnemonicIds[i]!)) return false;
        return true;
      },
      // `mov ecx, dword ptr [rax]` on x86-64, `push dword ptr [eax]` on i386.
      argc: (from, to) => {
        for (let i = from + 1; i < to; i++) {
          if (text(i) === 'mov ecx, dword ptr [rax]' || text(i) === 'push dword ptr [eax]') return true;
        }
        return false;
      },
      // x86-64: `lea rcx, [__ImageBase]` and `xor edx, edx`; i386: `push 0` and `push <image base>`.
      instance: (from, to) => {
        const base = image.pe?.imageBase;
        let first = false;
        let second = false;
        for (let i = from + 1; i < to; i++) {
          const line = text(i);
          if (line.startsWith('lea rcx, ') && program.addressAt.get(i) === base) first = true;
          else if (line === `push 0x${base?.toString(16)}`) first = true;
          else if (line === 'xor edx, edx' || line === 'push 0x0') second = true;
        }
        return first && second;
      },
      // x86-64: `mov ecx, dword ptr [rip + …]`, `mov rdx, qword ptr [rip + …]`, `mov r8, qword ptr [rip + …]`;
      // i386: three `push dword ptr [0x…]`.
      globals: (from, to) => {
        const seen = new Set<string>();
        for (let i = from + 1; i < to; i++) {
          const m = /^(?:mov (ecx|rdx|r8), [dq]word ptr \[rip [+-] 0x[0-9a-f]+\]|(push) dword ptr \[0x[0-9a-f]+\])$/.exec(text(i));
          if (m) seen.add(m[1] ?? `push${seen.size}`);
        }
        return seen.size >= 3;
      },
    });
    if (found && found.fn.kind === 'anonymous') Object.assign(found.fn, { name: found.name, full: found.name, raw: found.name });
  }

  // The HLA64 view of x86-64 code joins a compare with the jump or conditional move that reads its flags.
  if (mode === 64) {
    const setters = new Set(program.mnemonics.flatMap((m, id) => (X86_SETTERS.has(m) ? [id] : [])));
    const consumers = new Set(program.mnemonics.flatMap((m, id) => (isX86Consumer(m) ? [id] : [])));
    const bare: X86LiftContext = { target: () => undefined, data: () => undefined, functionStart: () => -1, importAt: () => undefined };
    for (let i = 0; i + 1 < total; i++) {
      if (!setters.has(program.mnemonicIds[i]!) || !consumers.has(program.mnemonicIds[i + 1]!)) continue;
      if (flags[i + 1]! & (IF.LABEL | IF.FUNCTION) || kinds[i] || kinds[i + 1]) continue;
      if (fuseX86(program.insn(i), program.insn(i + 1), bare)) flags[i]! |= IF.FUSE;
    }
  }

  // Strings in constant data that code points at.
  for (const addr of program.dataRefs.keys()) {
    if (program.stringAt.has(addr)) continue;
    const found = textAt(image, addr);
    if (!found) continue;
    program.strings.push(found);
    program.stringAt.set(addr, found);
  }
  program.strings.sort((a, b) => a.addr - b.addr);
  progress('done', 1, 1);
  return program;
}

/**
 * Where main is, for a program without symbols: the code address the entry
 * point passes to __libc_start_main (in rdi on x86-64, pushed last on i386),
 * the last one an instruction names before that call.
 */
function mainOf(p: X86Program, image: Image): number | undefined {
  if (image.format !== 'elf' || image.entry === undefined) return undefined;
  const entry = p.indexOf(image.entry);
  if (entry < 0) return undefined;
  let found: number | undefined;
  for (let i = entry; i < Math.min(entry + 48, p.totalInstructions); i++) {
    // A function pointer in the instruction, or in the GOT slot it reads (i386 PIE: `push dword ptr [ebx + …]`).
    const slotted = p.addressAt.get(i);
    const pointed = slotted !== undefined ? slotValue(image, slotted, p.mode === 64 ? 8 : 4) : undefined;
    const code = p.codeAt.get(i) ?? (pointed !== undefined && p.indexOf(pointed) >= 0 ? pointed : undefined);
    if (code !== undefined) found = code;
    if (!(p.flags[i]! & IF.CALL)) continue;
    const slot = p.addressAt.get(i);
    const target = slot === undefined ? targetOf(p.decoded(i)) : undefined;
    const callee = slot !== undefined ? p.importSlots.get(slot) : target !== undefined ? image.stubs.get(target) : undefined;
    if (callee === '__libc_start_main') return found;
  }
  return undefined;
}

/** Regions sorted, the ones that overlap joined (keeping the first one's entry size). */
function mergeRegions(regions: DataRegion[]): DataRegion[] {
  const out: DataRegion[] = [];
  for (const r of regions.sort((a, b) => a.addr - b.addr)) {
    const last = out[out.length - 1];
    if (last && r.addr < last.addr + last.length) last.length = Math.max(last.length, r.addr + r.length - last.addr);
    else out.push({ ...r });
  }
  return out;
}

interface Switch {
  table: number;
  entry: 4 | 8;
  targets: number[];
}

/**
 * The cases of a switch that jumps through a table, from the instructions
 * before the jump. Compilers write it in one of these ways:
 *
 *   lea rcx, [rip + T] / movsxd rax, dword ptr [rcx + 4*rax] / add rax, rcx / jmp rax
 *     (offsets from the table: x86-64 position-independent code)
 *   mov ecx, dword ptr [ebx + 4*eax + D] / add ecx, ebx / jmp ecx, or
 *   add edx, dword ptr [edx + 4*esi + D] / jmp edx
 *     (offsets from the GOT, a register holding its address: i386 position-independent code)
 *   jmp qword ptr [8*rax + T], jmp dword ptr [4*eax + T]
 *     (addresses: code that is not position-independent)
 *
 * How many cases there are is read from the bounds check before it (`cmp
 * reg, N` and `ja`); without one the table is read while its entries land
 * on instructions and before the next function.
 */
function switchOf(p: X86Program, index: number, inCode: (addr: number) => boolean, known: Set<number>): Switch | undefined {
  const jump = p.decoded(index);
  if (!jump.id) return undefined;
  const window: { d: X86Decoded; index: number }[] = [];
  for (let k = Math.max(0, index - 16); k < index; k++) if (!p.kinds[k]) window.push({ d: p.decoded(k), index: k });
  let table: number | undefined;
  let entry: 4 | 8 = 8;
  /** What an entry is added to: the table (x86-64) or the GOT (i386); undefined for addresses. */
  let base: number | undefined;
  const mem = memoryOf(jump);
  if (mem) {
    if (mem.base || !mem.index || mem.scale !== (p.mode === 32 ? 4 : 8) || mem.seg) return undefined;
    table = p.mode === 32 ? mem.disp >>> 0 : mem.disp;
    entry = mem.scale as 4 | 8;
  } else {
    const reg = gpr(jump.ops[0]);
    if (reg < 0) return undefined;
    for (let k = window.length - 1; k >= 0 && table === undefined; k--) {
      const { d, index: at } = window[k]!;
      const load = memoryOf(d);
      const m = mnemonicX86(d);
      if (!((m === 'movsxd' || m === 'mov' || m === 'add') && load?.index && load.scale === 4 && load.base)) continue;
      // `add reg, [got + 4*i + D]` loads and adds at once (clang's i386 PIC switch).
      const got = p.baseValues.get(at);
      if (m === 'add' && got === undefined) continue;
      if (got !== undefined) {
        table = (got + load.disp) >>> 0;
        entry = 4;
        base = got;
        break;
      }
      // The base came from `lea base, [rip + T]` before it: the table itself (clang, entries are offsets
      // from it), or the image base (MSVC: `mov ecx, [rdx + 4*rax + RVA]`, entries are RVAs).
      if (load.disp && p.image.format !== 'pe') continue;
      const reg2 = gpr(load.base);
      for (let j = k - 1; j >= 0; j--) {
        const lea = window[j]!.d;
        if (mnemonicX86(lea) !== 'lea' || gpr(lea.ops[0]) !== reg2) continue;
        const at2 = fixedAddressOf(lea, p.absolute);
        if (at2 !== undefined) {
          table = at2 + load.disp;
          entry = 4;
          base = at2;
        }
        break;
      }
    }
    if (table === undefined) return undefined;
  }
  // The bound: `cmp reg, N` and a branch that leaves when the index is above it — unless a byte table
  // maps the index to a case first (MSVC), when the cases are fewer than the values it checks.
  let count = 0;
  for (let k = window.length - 1; k > 0; k--) {
    const m = mnemonicX86(window[k]!.d);
    if (m === 'movzx' && memoryOf(window[k]!.d)?.index) break;
    if (m !== 'ja' && m !== 'jae' && m !== 'jbe' && m !== 'jb') continue;
    const cmp = window[k - 1]!.d;
    const last = cmp.ops.length - 1;
    if (mnemonicX86(cmp) === 'cmp' && typeof cmp.ops[last] === 'number' && cmp.types[last] === TYPE.IMM) {
      const n = (cmp.ops[last] as number) >>> 0;
      count = m === 'ja' || m === 'jbe' ? n + 1 : n;
    }
    break;
  }
  if (count > 4096) return undefined;
  const limit = count || 512;
  const targets: number[] = [];
  const signed = base !== undefined;
  for (let k = 0; k < limit; k++) {
    const at = table + k * entry;
    // Without a bound, a table ends where code or the next function begins.
    if (!count && k && (known.has(at) || targets.includes(at))) break;
    const v = valueAt(p.image, at, entry, signed);
    if (v === undefined) break;
    const target = base !== undefined ? (p.mode === 32 ? (base + v) >>> 0 : base + v) : v;
    const i = p.indexOf(target);
    if (!inCode(target) || i < 0 || p.addrOf(i) !== target) {
      if (count) return undefined;
      break;
    }
    targets.push(target);
  }
  return targets.length ? { table, entry, targets } : undefined;
}

export type { StringRef };
