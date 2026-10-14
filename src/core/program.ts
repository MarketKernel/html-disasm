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
import { F, formatInsn, type Insn } from './arm64/types';
import { append, Disassembly, IF, tick, windowsMain, type CodeRange, type Fn, type Progress, type StringRef } from './disassembly';
import { CONSUMERS, SETTERS, fuse, pairedAddress, type LiftContext } from './hla';
import { abiOf, cstrings, entryName, functionNames, objcDataAt, platformOf, sectionOf, slotValue, stubFunction, textAt, type Image, type ImageSection } from './image';

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

  // Code: every section of instructions, in address order.
  let total = 0;
  const code = image.sections.filter((s) => s.code && s.size >= 4 && s.offset).sort((a, b) => a.addr - b.addr);
  for (const section of code) {
    const count = Math.floor(section.size / 4);
    program.ranges.push({ section, name: section.label, first: total, count });
    total += count;
  }
  const words = new Uint32Array(total);
  for (const range of program.ranges) {
    const bytes = image.bytes.subarray(range.section.offset, range.section.offset + range.count * 4);
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    for (let i = 0; i < range.count; i++) words[range.first + i] = view.getUint32(i * 4, true);
  }
  program.words = words;
  program.mnemonicIds = new Uint16Array(total);
  program.flags = new Uint8Array(total);
  program.totalInstructions = total;

  // Names known from the file.
  for (const sym of image.symbols) if (sym.name && sym.addr) program.symbolAt.set(sym.addr, sym.name);
  for (const exp of image.exports) program.symbolAt.set(exp.addr, exp.name);
  for (const [slot, name] of image.slots) program.importSlots.set(slot, name);
  if (image.format === 'elf') for (const [stub, name] of pltStubs(program)) image.stubs.set(stub, name);
  if (image.format === 'pe') for (const [stub, name] of importThunks(program)) image.stubs.set(stub, name);

  // Strings: the C-string sections, whole.
  for (const ref of cstrings(image)) {
    program.strings.push(ref);
    program.stringAt.set(ref.addr, ref);
  }

  // The pass over every instruction.
  const ids = new Map<string, number>();
  const counts: number[] = [];
  const labelTargets: number[] = [];
  const callTargets = new Set<number>();
  const pages = new Float64Array(32).fill(-1);
  const pageAt = new Int32Array(32).fill(-1);
  // A register loaded from an import's slot, for a call through it (`ldr x8, [x8, #…]; blr x8`, as MSVC calls imports).
  const slots = new Float64Array(32).fill(-1);
  const slotAt = new Int32Array(32).fill(-1);
  const flags = program.flags;
  const CHUNK = 65536;
  let previous: Insn | undefined;
  let pending = { reg: -1, addr: 0, index: 0 };
  for (const range of program.ranges) {
    pages.fill(-1);
    slots.fill(-1);
    previous = undefined;
    for (let i = 0; i < range.count; i++) {
      const index = range.first + i;
      if (index % CHUNK === 0) {
        progress('decode', index, total);
        await tick();
      }
      const pc = range.section.addr + i * 4;
      const insn = decode(words[index]!, pc);
      let id = ids.get(insn.m);
      if (id === undefined) {
        id = program.mnemonics.length;
        ids.set(insn.m, id);
        program.mnemonics.push(insn.m);
        counts.push(0);
      }
      program.mnemonicIds[index] = id;
      counts[id]!++;
      if (insn.f & F.UNKNOWN) flags[index]! |= IF.UNKNOWN;
      if (insn.target !== undefined) {
        if (insn.f & F.CALL) {
          flags[index]! |= IF.CALL;
          callTargets.add(insn.target);
          append(program.callers, insn.target, pc);
        } else if (insn.f & F.BRANCH) {
          flags[index]! |= IF.BRANCH;
          labelTargets.push(insn.target);
        }
      } else if (insn.f & F.CALL) flags[index]! |= IF.CALL;
      else if (insn.f & F.BRANCH) flags[index]! |= IF.BRANCH;

      // adrp + add / load / store: the address they make together is a data reference.
      if (previous && previous.m === 'adrp') {
        const joined = pairedAddress(previous, insn);
        if (joined !== undefined) {
          flags[index - 1]! |= IF.FUSE;
          if (insn.m === 'add') pending = { reg: regIndex(insn.ops[0]), addr: joined, index };
        }
      } else if (previous && SETTERS.has(previous.m) && CONSUMERS.has(insn.m) && fuse(previous, insn, NO_NAMES)) {
        flags[index - 1]! |= IF.FUSE;
      }
      if (pending.reg >= 0 && index - pending.index <= 4 && insn.m === 'mov' && regIndex(insn.ops[0]) === pending.reg + 1 && insn.ops[1]?.k === 'imm') {
        const length = insn.ops[1].v;
        if (length > 0 && length < 4096) {
          const seen = program.lengthAt.get(pending.addr);
          program.lengthAt.set(pending.addr, seen === undefined ? length : Math.min(seen, length));
        }
        pending.reg = -1;
      }
      if (insn.m === 'adrp') {
        const r = regIndex(insn.ops[0]);
        if (r >= 0) {
          pages[r] = insn.target!;
          pageAt[r] = index;
        }
      } else {
        const base = baseOf(insn);
        let slot = -1;
        if (base >= 0 && pages[base]! >= 0 && index - pageAt[base]! <= 16) {
          const addr = pages[base]! + offsetOf(insn);
          append(program.dataRefs, addr, pc);
          if (image.format === 'pe' && insn.m === 'ldr' && program.importSlots.has(addr)) slot = addr;
        }
        if ((insn.m === 'blr' || insn.m === 'br') && insn.ops[0]?.k === 'reg') {
          const r = regIndex(insn.ops[0]);
          if (r >= 0 && slots[r]! >= 0 && index - slotAt[r]! <= 16) {
            program.slotCalls.set(index, slots[r]!);
            append(program.slotCallers, slots[r]!, pc);
          }
        }
        const written = writtenReg(insn);
        if (written >= 0) {
          pages[written] = -1;
          slots[written] = slot;
          slotAt[written] = index;
        }
        if (insn.f & (F.BRANCH | F.CALL)) {
          pages.fill(-1);
          // A call keeps x19–x28 (MSVC holds an import it calls twice in one of them); a branch may land anywhere.
          if (insn.f & F.CALL) slots.fill(-1, 0, 19);
          else slots.fill(-1);
        }
      }
      if (insn.m === 'adr' && insn.target !== undefined) {
        append(program.dataRefs, insn.target, pc);
      }
      previous = insn;
    }
  }
  progress('decode', total, total);
  program.decodeMs = Date.now() - started;
  program.tally(counts);

  // Labels: branch targets inside code.
  for (const target of labelTargets) {
    const index = program.indexOf(target);
    if (index >= 0) flags[index]! |= IF.LABEL;
  }

  // Functions.
  progress('functions', 0, 1);
  await tick();
  const starts = new Map<number, { raw?: string; kind: Fn['kind'] }>();
  const add = (addr: number, raw: string | undefined, kind: Fn['kind']) => {
    if (program.indexOf(addr) < 0) return;
    const known = starts.get(addr);
    if (!known || (known.kind === 'anonymous' && kind !== 'anonymous') || (!known.raw && raw)) starts.set(addr, { raw: raw ?? known?.raw, kind: known && known.kind !== 'anonymous' ? known.kind : kind });
  };
  for (const range of program.ranges) {
    add(range.section.addr, undefined, 'anonymous');
    const stride = range.section.stubSize;
    if (stride) {
      for (let at = range.section.addr; at < range.section.addr + range.section.size; at += stride) {
        const name = image.stubs.get(at);
        add(at, name, name ? 'import' : 'anonymous');
      }
    }
  }
  // ELF stubs are found by reading the PLT, not by a stride.
  if (image.format !== 'macho') for (const [at, name] of image.stubs) {
    const stub = stubFunction(image, name);
    add(at, stub.raw, stub.kind);
  }
  for (const addr of image.functionStarts) add(addr, undefined, 'anonymous');
  // Exports first: a function both exported and in the symbol table is listed as exported.
  for (const exp of image.exports) add(exp.addr, exp.name, 'export');
  for (const sym of image.symbols) if (sym.name) add(sym.addr, sym.name, 'symbol');
  for (const target of callTargets) add(target, undefined, 'anonymous');
  if (image.entry !== undefined) add(image.entry, starts.get(image.entry)?.raw ?? entryName(image), 'entry');
  // A stripped Linux program's main is what _start hands to __libc_start_main.
  const main = mainOf(program, image);
  if (main !== undefined && !starts.get(main)?.raw) add(main, 'main', 'symbol');

  const sorted = [...starts.keys()].sort((a, b) => a - b);
  for (let k = 0; k < sorted.length; k++) {
    const addr = sorted[k]!;
    const first = program.indexOf(addr);
    const range = program.rangeOfIndex(first)!;
    const next = sorted[k + 1];
    const nextIndex = next !== undefined ? program.indexOf(next) : -1;
    const end = nextIndex > first && nextIndex <= range.first + range.count ? nextIndex : range.first + range.count;
    const { raw, kind } = starts.get(addr)!;
    let name = `sub_${addr.toString(16)}`;
    let full = name;
    let language: string | undefined;
    if (raw) {
      const d = functionNames(image, raw);
      name = d.short;
      full = d.full;
      language = d.language;
    }
    if (kind === 'entry' && !raw) name = full = 'main';
    program.functionAtIndex.set(first, program.functions.length);
    program.functions.push({ addr, first, count: end - first, name, full, raw, kind, language });
    flags[first]! |= IF.FUNCTION;
  }

  // A stripped Windows program's main is found from how its C runtime calls it.
  if (image.format === 'pe') {
    const calls: { at: number; in: number; callee: Fn }[] = [];
    for (const range of program.ranges) {
      for (let i = range.first; i < range.first + range.count; i++) {
        const word = words[i]!;
        const slot = program.slotCalls.get(i);
        if (slot !== undefined) {
          const name = program.importSlots.get(slot)!;
          calls.push({ at: i, in: program.functionOfIndex(i), callee: { addr: 0, first: -1, count: 0, name, full: name, raw: name, kind: 'import' } });
          continue;
        }
        if ((word & 0xfc000000) >>> 0 !== 0x94000000) continue; // bl
        const target = program.addrOf(i) + ((word << 6) >> 6) * 4;
        const callee = program.functionAt(target);
        if (callee?.addr === target) calls.push({ at: i, in: program.functionOfIndex(i), callee });
      }
    }
    // The entry point, and what it calls or jumps to: where the C runtime's startup is.
    // Two steps deep: MSVC's mainCRTStartup goes on to __scrt_common_main_seh.
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
          const insn = decode(words[i]!, program.addrOf(i));
          if (!(insn.f & (F.BRANCH | F.CALL)) || insn.target === undefined) continue;
          const index = program.indexOf(insn.target);
          if (index >= 0) next.push(program.functionOfIndex(index));
        }
      }
      level = next;
    }
    const found = windowsMain(calls, startup, {
      straight: (from, to) => {
        for (let i = from + 1; i < to; i++) {
          const insn = decode(words[i]!, program.addrOf(i));
          if ((insn.f & F.BRANCH && !/^(b\.|cbn?z|tbn?z)/.test(insn.m)) || /^(brk|udf|hlt)$/.test(insn.m)) return false;
        }
        return true;
      },
      // `ldr w0, [x0]`
      argc: (from, to) => {
        for (let i = from + 1; i < to; i++) if (formatInsn(decode(words[i]!, program.addrOf(i))) === 'ldr w0, [x0]') return true;
        return false;
      },
      // `adrp xN, <image base>; add x0, xN, #0` and `mov x1, #0`
      instance: (from, to) => {
        let base = -1;
        let first = false;
        let second = false;
        for (let i = from + 1; i < to; i++) {
          const insn = decode(words[i]!, program.addrOf(i));
          const text = formatInsn(insn);
          if (insn.m === 'adrp' && insn.target === image.pe?.imageBase) base = regIndex(insn.ops[0]);
          else if (base >= 0 && text === `add x0, x${base}, #0x0`) first = true;
          else if (/^mov [xw]1, (#0x0|[xw]zr)$/.test(text)) second = true;
        }
        return first && second;
      },
      // No arm64 runtime keeps argc in a global for main.
      globals: () => false,
    });
    if (found && found.fn.kind === 'anonymous') Object.assign(found.fn, { name: found.name, full: found.name, raw: found.name });
  }

  // The listing should not join an instruction with one that a branch also reaches.
  for (let i = 0; i + 1 < total; i++) if (flags[i]! & IF.FUSE && flags[i + 1]! & (IF.LABEL | IF.FUNCTION)) flags[i]! &= ~IF.FUSE;

  // Strings in constant data that code points at (Rust keeps its literals there, without a NUL).
  for (const addr of program.dataRefs.keys()) {
    if (program.stringAt.has(addr)) continue;
    const found = program.dataAt(addr);
    if (found?.kind !== 'string' || found.objc) continue;
    const ref: StringRef = { addr, text: found.text, section: sectionOf(image, addr)?.name ?? '', kind: 'const' };
    program.strings.push(ref);
    program.stringAt.set(addr, ref);
  }
  program.strings.sort((a, b) => a.addr - b.addr);
  progress('done', 1, 1);
  return program;
}

const NO_NAMES: LiftContext = { target: () => undefined, data: () => undefined, functionStart: () => -1 };

function regIndex(op: Insn['ops'][number] | undefined): number {
  if (op?.k !== 'reg') return -1;
  const match = /^[xw](\d+)$/.exec(op.r);
  return match ? Number(match[1]) : -1;
}

/** The base register of an add-immediate or a load/store with an immediate offset, which may complete an adrp. */
function baseOf(insn: Insn): number {
  if (insn.m === 'add' && insn.ops.length === 3 && insn.ops[2]?.k === 'imm') return regIndex(insn.ops[1]);
  if (insn.f & (F.LOAD | F.STORE)) {
    const mem = insn.ops.find((op) => op.k === 'mem');
    if (mem?.k === 'mem' && !mem.index && mem.mode === 'off') {
      const match = /^x(\d+)$/.exec(mem.base);
      return match ? Number(match[1]) : -1;
    }
  }
  return -1;
}

function offsetOf(insn: Insn): number {
  if (insn.m === 'add') {
    const op = insn.ops[2];
    return op?.k === 'imm' ? op.v : 0;
  }
  const mem = insn.ops.find((op) => op.k === 'mem');
  return mem?.k === 'mem' ? mem.off : 0;
}

/** The general register an instruction writes, as far as tracking adrp pages needs. */
function writtenReg(insn: Insn): number {
  if (insn.f & F.STORE && !(insn.f & F.LOAD)) return -1;
  // A branch or call through a register reads it (`blr x21`).
  if (insn.f & (F.BRANCH | F.CALL)) return -1;
  return regIndex(insn.ops[0]);
}

/**
 * Where main is, for an ELF program without symbols: what the entry point passes to
 * __libc_start_main in x0. glibc's start code makes it with adrp + add (which the linker may
 * relax to nop + adr), or, position-independent, loads it from the GOT with adrp + ldr.
 */
function mainOf(program: Program, image: Image): number | undefined {
  if (image.format !== 'elf' || image.entry === undefined) return undefined;
  const entry = program.indexOf(image.entry);
  if (entry < 0) return undefined;
  const regs = new Array<number>(31).fill(NaN);
  const value = (op: Insn['ops'][number] | undefined) => regs[regIndex(op)] ?? NaN;
  for (let i = entry; i < Math.min(entry + 32, program.totalInstructions); i++) {
    const insn = decode(program.words[i]!, program.addrOf(i));
    if (insn.f & F.CALL) {
      if (insn.target === undefined || image.stubs.get(insn.target) !== '__libc_start_main') return undefined;
      return program.indexOf(regs[0]!) >= 0 ? regs[0] : undefined;
    }
    if (insn.f & F.BRANCH) return undefined;
    const written = writtenReg(insn);
    if (written < 0) continue;
    let v = NaN;
    if (insn.m === 'adr' || insn.m === 'adrp') v = insn.target!;
    else if (insn.m === 'add' && insn.ops.length === 3 && insn.ops[2]?.k === 'imm') v = value(insn.ops[1]) + insn.ops[2].v;
    else if (insn.m === 'ldr' && insn.ops[0]?.k === 'reg' && insn.ops[0].r.startsWith('x')) {
      const mem = insn.ops[1];
      const base = mem?.k === 'mem' && !mem.index && mem.mode === 'off' ? /^x(\d+)$/.exec(mem.base) : null;
      if (mem?.k === 'mem' && base) {
        const slot = (regs[Number(base[1])] ?? NaN) + mem.off;
        v = Number.isNaN(slot) ? NaN : slotValue(image, slot, 8) ?? NaN;
      }
    }
    regs[written] = v;
  }
  return undefined;
}

/**
 * The stubs of an ELF PLT, named after the GOT slot each one jumps through.
 * A stub is `adrp x16, page` / `ldr x17, [x16, #off]` / `add x16, …` / `br x17`
 * (with a `bti c` before it when the library has BTI); the first one, the
 * header, loads a slot that names no symbol and stays anonymous; the nops that pad it
 * belong to no stub.
 */
/**
 * The import thunks of a Windows program: `adrp xN, page; ldr xN, [xN, #off]; br xN` through a
 * slot of the import address table, which MSVC and MinGW link in for each function called by name.
 */
function importThunks(program: Program): Map<number, string> {
  const thunks = new Map<number, string>();
  const words = program.words;
  for (const range of program.ranges) {
    for (let i = range.first; i + 2 < range.first + range.count; i++) {
      const adrp = words[i]!;
      const br = words[i + 2]!;
      // adrp xN, …  then  br xN (with N the same register)
      if ((adrp & 0x9f000000) >>> 0 !== 0x90000000 || (br & 0xfffffc1f) >>> 0 !== 0xd61f0000 || ((br >>> 5) & 31) !== (adrp & 31)) continue;
      const pc = program.addrOf(i);
      const page = decode(adrp, pc);
      const ldr = decode(words[i + 1]!, pc + 4);
      const mem = ldr.ops[1];
      if (ldr.m !== 'ldr' || regIndex(ldr.ops[0]) !== (adrp & 31) || mem?.k !== 'mem' || mem.mode !== 'off' || mem.base !== `x${adrp & 31}`) continue;
      const name = program.image.slots.get(page.target! + mem.off);
      if (name) thunks.set(pc, name);
    }
  }
  return thunks;
}

function pltStubs(program: Program): Map<number, string> {
  const stubs = new Map<number, string>();
  for (const range of program.ranges) {
    if (!/^\.i?plt/.test(range.section.name)) continue;
    let start = range.section.addr;
    let page = -1;
    for (let i = 0; i < range.count; i++) {
      const pc = range.section.addr + i * 4;
      const insn = decode(program.words[range.first + i]!, pc);
      if (insn.m === 'adrp' && regIndex(insn.ops[0]) === 16) page = insn.target!;
      else if (insn.m === 'ldr' && page >= 0) {
        const mem = insn.ops[1];
        if (mem?.k === 'mem' && mem.base === 'x16') {
          const name = program.image.slots.get(page + mem.off);
          if (name) stubs.set(start, name);
        }
      } else if (insn.f & F.BRANCH) {
        start = pc + 4;
        page = -1;
      } else if (insn.m === 'nop' && start === pc) start = pc + 4; // the header's padding
    }
  }
  return stubs;
}
