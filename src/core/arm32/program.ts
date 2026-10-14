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
import { append, Disassembly, IF, tick, windowsMain, type CodeRange, type DataAt, type Fn, type Progress, type StringRef } from '../disassembly';
import { abiOf, bytesAt, cstrings, entryName, functionNames, objcDataAt, platformOf, sectionOf, slotValue, stubFunction, textAt, valueAt, type Image, type ImageSection } from '../image';
import { decodeArm, decodeThumb, isWide, itAfter } from './decode';
import { formatInsn, type Insn } from './types';

/** What an entry of the instruction arrays is. */
export const KIND = { A32: 0, T16: 1, T32: 2, WORD: 3, SHORT: 4, BYTE: 5 } as const;
const SIZE = [4, 2, 4, 4, 2, 1] as const;
const DATA_NAMES = ['', '', '', '.word', '.short', '.byte'] as const;

export interface Arm32Range extends CodeRange {
  section: ImageSection;
}

type Mode = 'a' | 't' | 'd';
interface Mark {
  addr: number;
  kind: Mode;
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
 * Laying out the code: instruction sets and data
 * ------------------------------------------------------------------ */

interface Layout {
  addrs: Uint32Array<ArrayBuffer>;
  words: Uint32Array<ArrayBuffer>;
  kinds: Uint8Array<ArrayBuffer>;
  its: Int8Array<ArrayBuffer>;
  ranges: Arm32Range[];
}

/**
 * Cuts the code sections into instructions and data: `marks` (sorted) switch
 * the instruction set, `data` holds the bytes known to be data (address →
 * length) wherever the set is.
 */
function layOut(image: Image, sections: ImageSection[], marks: Mark[], data: Map<number, number>, fallback: Mode): Layout {
  const capacity = sections.reduce((n, s) => n + Math.ceil(s.size / 2) + 1, 0);
  const addrs = new Uint32Array(capacity);
  const words = new Uint32Array(capacity);
  const kinds = new Uint8Array(capacity);
  const its = new Int8Array(capacity).fill(-1);
  const ranges: Arm32Range[] = [];
  const bytes = image.bytes;
  let n = 0;
  const push = (addr: number, word: number, kind: number, it = -1) => {
    addrs[n] = addr;
    words[n] = word;
    kinds[n] = kind;
    its[n] = it;
    n++;
  };
  // The data, by address, walked with a cursor as the layout moves forward.
  const claims = [...data].sort((a, b) => a[0] - b[0]);
  let c = 0;
  const claimAt = (addr: number): number => {
    while (c < claims.length && claims[c]![0] < addr) c++;
    return c < claims.length && claims[c]![0] === addr ? claims[c]![1] : 0;
  };
  const claimed = (addr: number): boolean => {
    for (let k = c; k < claims.length && claims[k]![0] <= addr; k++) if (claims[k]![0] === addr) return true;
    return false;
  };
  let m = 0;
  for (const section of sections) {
    const first = n;
    const base = section.offset - section.addr;
    const u8 = (addr: number) => bytes[base + addr]!;
    const u16 = (addr: number) => bytes[base + addr]! | (bytes[base + addr + 1]! << 8);
    const u32 = (addr: number) => (u16(addr) | (u16(addr + 2) << 16)) >>> 0;
    const end = section.addr + section.size;
    while (m < marks.length && marks[m]!.addr < section.addr) m++;
    let mode: Mode = fallback;
    let it: number[] = [];
    /** Data from addr up to limit, in words where aligned. */
    const dataUnit = (addr: number, limit: number): number => {
      if (addr % 4 === 0 && addr + 4 <= limit) {
        push(addr, u32(addr), KIND.WORD);
        return 4;
      }
      if (addr % 2 === 0 && addr + 2 <= limit) {
        push(addr, u16(addr), KIND.SHORT);
        return 2;
      }
      push(addr, u8(addr), KIND.BYTE);
      return 1;
    };
    for (let addr = section.addr; addr < end; ) {
      while (m < marks.length && marks[m]!.addr <= addr) {
        mode = marks[m]!.kind;
        it = [];
        m++;
      }
      const limit = Math.min(end, m < marks.length ? marks[m]!.addr : end);
      const known = mode === 'd' ? 0 : claimAt(addr);
      if (known) {
        const stop = Math.min(limit, addr + known);
        while (addr < stop) addr += dataUnit(addr, stop);
        it = [];
        continue;
      }
      if (mode === 'd') {
        addr += dataUnit(addr, limit);
        continue;
      }
      // lld fills the gaps between functions with 0xd4: as A32 a nonsense ldrble, as T32 two bmi
      // in a row of which the second could never run.
      if (addr % 4 === 0 && addr + 4 <= limit && u32(addr) === 0xd4d4d4d4) {
        addr += dataUnit(addr, limit);
        it = [];
        continue;
      }
      if (mode === 'a') {
        if (addr % 4 || addr + 4 > limit) {
          addr += dataUnit(addr, limit);
          continue;
        }
        push(addr, u32(addr), KIND.A32);
        addr += 4;
        continue;
      }
      if (addr % 2 || addr + 2 > limit) {
        addr += dataUnit(addr, limit);
        continue;
      }
      const hw1 = u16(addr);
      const cond = it.length ? it[0]! : -1;
      const wide = isWide(hw1);
      if (wide && (addr + 4 > limit || claimed(addr + 2))) {
        addr += dataUnit(addr, Math.min(limit, addr + 2));
        continue;
      }
      const word = wide ? ((hw1 << 16) | u16(addr + 2)) >>> 0 : hw1;
      push(addr, word, wide ? KIND.T32 : KIND.T16, cond);
      // An IT instruction makes the next one to four conditional. Only inside a block, or at an
      // IT, is the instruction decoded here: whether it takes a slot depends on what it is.
      if (it.length || (hw1 & 0xff00) === 0xbf00) it = itAfter(it, decodeThumb(hw1, wide ? word & 0xffff : 0, addr, cond), word);
      addr += wide ? 4 : 2;
    }
    ranges.push({ section, name: section.label, first, count: n - first });
  }
  return { addrs: addrs.slice(0, n), words: words.slice(0, n), kinds: kinds.slice(0, n), its: its.slice(0, n), ranges };
}

/**
 * What decoding a layout teaches about a stripped library: the literal-pool
 * words and branch tables (data), and the instruction set at every call target.
 */
function discover(layout: Layout, inCode: (addr: number) => boolean, owned: (addr: number) => boolean, data: Map<number, number>, marks: Map<number, Mode>, image: Image): void {
  const { addrs, words, kinds, its } = layout;
  for (let i = 0; i < addrs.length; i++) {
    const kind = kinds[i]!;
    if (kind >= KIND.WORD || !mayName(kind, words[i]!)) continue;
    const pc = addrs[i]!;
    const insn = decodeAt(kind, words[i]!, pc, its[i]!);
    if (insn.f & F.UNKNOWN) continue;
    if (insn.target === undefined) continue;
    const target = insn.target;
    if (insn.f & F.LOAD) {
      // A literal: the bytes it reads are data, not code.
      if (inCode(target) && !data.has(target)) data.set(target, Math.max(4, insn.bytes ?? 4));
      continue;
    }
    // adr (or A32 `add rX, pc, #…`) and a load through the register right after: constants
    // kept in the code, often NEON ones (`adr r1, …` / `vld1.32 {d16, d17}, [r1]`).
    if (!(insn.f & (F.BRANCH | F.CALL)) && inCode(target) && insn.ops[0]?.k === 'reg') {
      const base = insn.ops[0].r;
      for (let k = i + 1; k <= i + 4 && k < addrs.length && kinds[k]! < KIND.WORD; k++) {
        const next = decodeAt(kinds[k]!, words[k]!, addrs[k]!, its[k]!);
        const mem = next.ops.find((op) => op.k === 'mem');
        if (next.f & F.LOAD && mem?.k === 'mem' && mem.base === base && !mem.index && mem.mode !== 'pre') {
          const list = next.ops.find((op) => op.k === 'list');
          const count = list?.k === 'list' ? list.regs.length : next.ops.filter((op) => op.k === 'reg').length > 2 ? 2 : 1;
          const at = target + (mem.mode === 'off' ? mem.off ?? 0 : 0);
          if (inCode(at) && !data.has(at)) data.set(at, Math.max(4, (next.bytes ?? 4) * count));
          break;
        }
        if (next.ops[0]?.k === 'reg' && next.ops[0].r === base) break;
      }
      continue;
    }
    if (insn.f & F.CALL && insn.thumb !== undefined && inCode(target) && !owned(target)) {
      const mode: Mode = insn.thumb ? 't' : 'a';
      if ((mode === 'a' && target % 4) || target % 2) continue;
      // A call decoded from bytes that are not code (or code read in the wrong set) names a
      // random place: its claim stands only if the code around the call reads cleanly and the
      // bytes at the target look like that instruction set.
      if (!marks.has(target) && cleanAround(layout, i) && !cleanOtherwise(layout, target, mode) && sniff(image, target) === mode) marks.set(target, mode);
    }
  }
  // Switch tables: tbb/tbh in T32, an indexed `add pc` or `ldr pc` in A32.
  for (let i = 0; i < addrs.length; i++) {
    const w = words[i]!;
    const table =
      kinds[i] === KIND.T32 && ((w & 0xfff0ffe0) >>> 0) === 0xe8d0f000
        ? branchTable(image, layout, i)
        : kinds[i] === KIND.A32 && ((w & 0x0ffffff0) === 0x079ff100 || (w & 0x0ff0fff0) === 0x0080f000)
          ? armTable(image, layout, i)
          : undefined;
    if (table) data.set(table.start, table.length);
  }
}

/** No undecodable instruction among the three before and the three after an instruction. */
function cleanAround(layout: Layout, i: number): boolean {
  const { addrs, words, kinds, its } = layout;
  for (let k = Math.max(0, i - 3); k <= i + 3 && k < addrs.length; k++) {
    if (k === i || kinds[k]! >= KIND.WORD) continue;
    if (decodeAt(kinds[k]!, words[k]!, addrs[k]!, its[k]!).f & F.UNKNOWN) return false;
  }
  return true;
}

/**
 * Whether the code at an address already reads cleanly in the other instruction set (or is
 * data): a call that says otherwise is the one that is wrong.
 */
function cleanOtherwise(layout: Layout, addr: number, mode: Mode): boolean {
  const { addrs, kinds } = layout;
  let lo = 0;
  let hi = addrs.length - 1;
  let at = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (addrs[mid]! <= addr) {
      at = mid;
      lo = mid + 1;
    } else hi = mid - 1;
  }
  if (at < 0) return false;
  const kind = kinds[at]!;
  const now: Mode = kind === KIND.A32 ? 'a' : kind === KIND.T16 || kind === KIND.T32 ? 't' : 'd';
  return now !== mode && now !== 'd' && cleanAround(layout, at);
}

/**
 * Whether an instruction can teach discovery anything — a call, a load from
 * pc, a write to pc — judged from its bits so the rest is never decoded:
 * T16 literal loads; T32 branches with link and anything with base register
 * pc; A32 branches, and anything reading or writing pc.
 */
function mayName(kind: number, word: number): boolean {
  if (kind === KIND.T16) return (word & 0xf800) === 0x4800 || (word & 0xf800) === 0xa000;
  if (kind === KIND.T32) return (word & 0xf8000000) >>> 0 === 0xf0000000 || ((word >>> 16) & 0xf) === 0xf;
  return ((word >>> 25) & 7) === 5 || ((word >>> 16) & 0xf) === 15 || ((word >>> 12) & 0xf) === 15;
}

/**
 * An A32 switch: `adr rT, table` / `ldr rO, [rT, rI, lsl #2]` / `add pc, rT, rO`
 * with offsets from the table, or `ldrls pc, [pc, rI, lsl #2]` / `b default`
 * with addresses after it. The `cmp rI, #n` that bounds the index says the
 * table has n + 1 entries; without one, as with tbb, the table ends where the
 * nearest place it sends execution begins.
 */
function armTable(image: Image, layout: Pick<Layout, 'addrs' | 'words' | 'kinds'>, i: number): { start: number; length: number; targets: number[] } | undefined {
  const { addrs, words, kinds } = layout;
  const word = words[i]!;
  const viaLoad = (word & 0x0ffffff0) === 0x079ff100;
  if (!viaLoad && (word & 0x0ff0fff0) !== 0x0080f000) return undefined;
  let base = viaLoad ? addrs[i]! + 8 : -1;
  // The index register: of the ldr pc itself, or of the `ldr rO, [rT, rI, lsl #2]` before the add.
  let index = viaLoad ? word & 0xf : -1;
  let count = Infinity;
  for (let k = i - 1; k >= 0 && k >= i - 8 && kinds[k] === KIND.A32; k--) {
    const w = words[k]!;
    if (!viaLoad && base < 0 && (w & 0x0fff0000) === 0x028f0000 && ((w >>> 12) & 0xf) === ((word >>> 16) & 0xf)) base = addrs[k]! + 8 + armImm(w);
    if (index < 0 && (w & 0x0ff00ff0) === 0x07900100) index = w & 0xf;
    // The bound check of that index, when there is one, says how many entries there are.
    if (index >= 0 && count === Infinity && (w & 0x0ff0f000) === 0x03500000 && ((w >>> 16) & 0xf) === index) count = armImm(w) + 1;
  }
  if (base < 0) return undefined;
  const bytes = bytesAt(image, base, 16384);
  if (!bytes) return undefined;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const targets: number[] = [];
  let nearest = base + bytes.length;
  let p = 0;
  while (base + p < nearest && p + 4 <= bytes.length && targets.length < count) {
    const entry = view.getUint32(p, true);
    const target = viaLoad ? entry : (base + entry) >>> 0;
    targets.push(target);
    if (target > base) nearest = Math.min(nearest, target);
    p += 4;
  }
  return targets.length ? { start: base, length: p, targets } : undefined;
}

/**
 * The table of a `tbb`/`tbh`: offsets in halfwords from the instruction's pc
 * + 4. Usually it follows the instruction (`tbb [pc, rX]`) and ends where the
 * nearest place it sends execution begins. When it sits elsewhere — `adr rT,
 * table` / `tbb [rT, rX]` — the `cmp rX, #n` before says it has n + 1 entries.
 */
function branchTable(image: Image, layout: Pick<Layout, 'addrs' | 'words' | 'kinds' | 'its'>, i: number): { start: number; length: number; targets: number[] } | undefined {
  const { addrs, words, kinds, its } = layout;
  const word = words[i]!;
  if (kinds[i] !== KIND.T32 || ((word & 0xfff0ffe0) >>> 0) !== 0xe8d0f000) return undefined;
  const half = (word & 0x10) !== 0;
  const step = half ? 2 : 1;
  const pc = addrs[i]!;
  const rn = (word >>> 16) & 0xf;
  const entryAt = (bytes: Uint8Array, p: number) => (half ? bytes[p]! | (bytes[p + 1]! << 8) : bytes[p]!);
  const targets: number[] = [];
  if (rn === 15) {
    const start = pc + 4;
    const bytes = bytesAt(image, start, 2048);
    if (!bytes) return undefined;
    let nearest = start + bytes.length;
    let p = 0;
    while (start + p < nearest && p + step <= bytes.length && targets.length < 1024) {
      const target = start + entryAt(bytes, p) * 2;
      targets.push(target);
      if (target > start) nearest = Math.min(nearest, target);
      p += step;
    }
    return targets.length ? { start, length: p, targets } : undefined;
  }
  const rm = word & 0xf;
  let base = -1;
  let count = -1;
  for (let k = i - 1; k >= 0 && k >= i - 6 && (kinds[k] === KIND.T16 || kinds[k] === KIND.T32) && (base < 0 || count < 0); k--) {
    const insn = decodeAt(kinds[k]!, words[k]!, addrs[k]!, its[k]!);
    const dest = insn.ops[0]?.k === 'reg' ? insn.ops[0].r : '';
    if (base < 0 && insn.target !== undefined && insn.m.startsWith('adr') && dest === `r${rn}`) base = insn.target;
    if (count < 0 && insn.m.startsWith('cmp') && dest === `r${rm}` && insn.ops[1]?.k === 'imm') count = insn.ops[1].v + 1;
  }
  if (base < 0 || count <= 0 || count > 1024) return undefined;
  const bytes = bytesAt(image, base, count * step);
  if (!bytes || bytes.length < count * step) return undefined;
  for (let e = 0; e < count; e++) targets.push(pc + 4 + entryAt(bytes, e * step) * 2);
  return { start: base, length: count * step, targets };
}

/**
 * A32 or T32, from the bytes alone. A prologue says it outright: push {…, lr}
 * is b5xx in T16 and e92d 4xxx in T32, but e92d4xxx as an A32 word. Otherwise
 * the first 32 bytes are read both ways and each reading is charged for what
 * real code rarely has: an undecodable word in either; in A32, instructions
 * that do not always run (most compiled A32 runs always); in T32, an
 * unconditional 16-bit branch or a 0x0000 halfword mid-function — what A32
 * words read as T32 are full of. A start that is not word-aligned is T32.
 */
function sniff(image: Image, addr: number): Mode {
  if (addr % 4) return 't';
  const bytes = bytesAt(image, addr, 32);
  if (!bytes || bytes.length < 4) return 't';
  const half = (p: number) => bytes[p]! | (bytes[p + 1]! << 8);
  const first = half(0);
  if ((first & 0xff00) === 0xb500 || first === 0xe92d) return 't';
  // e92d in the upper half: an A32 push whose register list (the lower half) has lr — or a T32
  // push.w after one 16-bit instruction (`sub sp, #…` opens a variadic function).
  if (half(2) === 0xe92d) return first & 0x4000 ? 'a' : 't';
  let a = 0;
  for (let p = 0; p + 4 <= bytes.length; p += 4) {
    const word = (half(p) | (half(p + 2) << 16)) >>> 0;
    if (decodeArm(word, addr + p).f & F.UNKNOWN) a += 3;
    else if (word >>> 28 < 0xe) a += 1;
  }
  let t = 0;
  for (let p = 0; p + 2 <= bytes.length; ) {
    const hw = half(p);
    const wide = isWide(hw);
    if (wide && p + 4 > bytes.length) break;
    if (decodeThumb(hw, wide ? half(p + 2) : 0, addr + p).f & F.UNKNOWN) t += 3;
    else if (!wide && (hw === 0 || (hw & 0xf800) === 0xe000)) t += 2;
    p += wide ? 4 : 2;
  }
  return a < t ? 'a' : 't';
}

/* ------------------------------------------------------------------ *
 * The analysis
 * ------------------------------------------------------------------ */

const REG = new Map(['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'r12', 'sp', 'lr', 'pc'].map((name, i) => [name, i]));
const regOf = (op: Insn['ops'][number] | undefined): number => (op?.k === 'reg' ? REG.get(op.r) ?? -1 : -1);

/** An A32 modified immediate: eight bits rotated right by twice the rotation field. */
const armImm = (word: number) => {
  const rot = ((word >>> 8) & 0xf) * 2;
  const imm = word & 0xff;
  return ((imm >>> rot) | (imm << (32 - rot))) >>> 0;
};

export async function analyzeArm32(image: Image, progress: Progress = () => {}): Promise<Arm32Program> {
  const program = new Arm32Program(image);
  const started = Date.now();
  const sections = image.sections.filter((s) => s.code && s.size >= 2 && s.offset).sort((a, b) => a.addr - b.addr);
  const inCode = (addr: number) => sections.some((s) => addr >= s.addr && addr < s.addr + s.size);

  // Where each instruction set is.
  const fileMarks = image.marks.filter((mk) => mk.kind !== 'x' && inCode(mk.addr));
  program.mapped = fileMarks.length > 0;
  const data = new Map<number, number>();
  let marks: Mark[];
  let layout: Layout;
  const thumbSymbols = image.symbols.filter((s) => s.function && s.thumb).length;
  const fallback: Mode = thumbSymbols * 2 >= image.symbols.filter((s) => s.function).length ? 't' : 'a';
  if (program.mapped) {
    marks = fileMarks.map((mk) => ({ addr: mk.addr, kind: mk.kind as Mode }));
    layout = layOut(image, sections, marks, data, fallback);
  } else {
    const known = new Map<number, Mode>();
    for (const s of sections) if (/^\.i?plt/.test(s.name)) known.set(s.addr, 'a');
    for (const sym of [...image.symbols, ...image.exports]) if (sym.function && inCode(sym.addr)) known.set(sym.addr, sym.thumb ? 't' : 'a');
    for (const value of [...(image.elf?.initArray ?? []), ...(image.elf?.finiArray ?? [])]) if (inCode(value & ~1)) known.set(value & ~1, value & 1 ? 't' : 'a');
    if (image.entry !== undefined && inCode(image.entry & ~1)) known.set(image.entry & ~1, image.entry & 1 ? 't' : 'a');
    for (const addr of image.thumb ?? []) if (inCode(addr) && !known.has(addr)) known.set(addr, 't');
    // Code inside a function the symbols describe keeps that function's set, whatever a stray call says.
    const spans = image.symbols.filter((s) => s.function && s.size).map((s) => [s.addr, s.addr + s.size!] as const).sort((a, b) => a[0] - b[0]);
    const owned = (addr: number) => {
      let lo = 0;
      let hi = spans.length - 1;
      while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        if (spans[mid]![0] <= addr) {
          if (addr < spans[mid]![1]) return true;
          lo = mid + 1;
        } else hi = mid - 1;
      }
      return false;
    };
    // Functions the unwind tables list but no symbol names (static ones, often reached only through
    // a pointer) get the set their first instructions look like.
    for (const addr of image.functionStarts) if (inCode(addr) && !known.has(addr)) known.set(addr, sniff(image, addr));
    const sorted = () => [...known].map(([addr, kind]) => ({ addr, kind })).sort((a, b) => a.addr - b.addr);
    // Data the file marks among the instructions (a Mach-O file's LC_DATA_IN_CODE) is data whatever the code says.
    const marked = (into: Map<number, number>) => {
      for (const d of image.dataInCode ?? []) if (inCode(d.addr) && d.length) into.set(d.addr, d.length);
    };
    marked(data);
    marks = sorted();
    layout = layOut(image, sections, marks, data, fallback);
    // Each round starts the data afresh from the latest layout, so a literal that only a wrong
    // decoding saw does not outlive it; the instruction sets found at call targets stay. It is
    // over when no new call target turns up and the data hardly moves (a few words can flip
    // back and forth between two readings for ever).
    for (let round = 0; round < 5; round++) {
      progress('decode', round, 5);
      await tick();
      const targets = known.size;
      const found = new Map<number, number>();
      discover(layout, inCode, owned, found, known, image);
      let moved = 0;
      for (const [addr, length] of found) if (data.get(addr) !== length) moved++;
      for (const addr of data.keys()) if (!found.has(addr)) moved++;
      data.clear();
      for (const [addr, length] of found) data.set(addr, length);
      marked(data);
      if (round > 0 && known.size === targets && moved <= Math.max(8, found.size / 1000)) break;
      marks = sorted();
      layout = layOut(image, sections, marks, data, fallback);
    }
  }
  program.addrs = layout.addrs;
  program.words = layout.words;
  program.kinds = layout.kinds;
  program.its = layout.its;
  program.ranges.push(...layout.ranges);
  const total = layout.addrs.length;
  program.totalInstructions = total;
  program.mnemonicIds = new Uint16Array(total);
  program.flags = new Uint8Array(total);

  // Names known from the file.
  for (const sym of image.symbols) if (sym.name && sym.addr) program.symbolAt.set(sym.addr, sym.name);
  for (const exp of image.exports) program.symbolAt.set(exp.addr, exp.name);
  for (const [slot, name] of image.slots) program.importSlots.set(slot, name);
  for (const [stub, name] of pltStubs(program)) image.stubs.set(stub, name);
  for (const ref of cstrings(image)) {
    program.strings.push(ref);
    program.stringAt.set(ref.addr, ref);
  }

  // The pass over every instruction.
  const ids = new Map<string, number>();
  const printed = new Map<string, number>();
  const counts: number[] = [];
  const labelTargets: number[] = [];
  const callTargets = new Set<number>();
  const flags = program.flags;
  const { addrs, words, kinds, its } = program;
  // Values the code has put in registers, for PC-relative addresses: the value and where it was set.
  const value = new Float64Array(16).fill(NaN);
  const setAt = new Int32Array(16).fill(-1);
  const isAddress = new Uint8Array(16);
  // A register loaded from an import's slot, for the call through it (`ldr r3, [r3]; blx r3`, as MSVC calls imports).
  const slotIn = new Float64Array(16).fill(-1);
  const slotAt = new Int32Array(16).fill(-1);
  const forget = () => {
    value.fill(NaN);
    isAddress.fill(0);
  };
  const ref = (addr: number, pc: number) => {
    append(program.dataRefs, addr, pc);
  };
  const CHUNK = 65536;
  let rangeEnd = -1;
  for (let i = 0; i < total; i++) {
    if (i % CHUNK === 0) {
      progress('decode', i, total);
      await tick();
    }
    if (i >= rangeEnd) {
      forget();
      slotIn.fill(-1);
      const range = program.rangeOfIndex(i);
      rangeEnd = range ? range.first + range.count : total;
    }
    const kind = kinds[i]!;
    const pc = addrs[i]!;
    const word = words[i]!;
    const insn = kind >= KIND.WORD ? undefined : decodeAt(kind, word, pc, its[i]!);
    const m = insn ? insn.m : DATA_NAMES[kind as 3];
    // Statistics count the mnemonic as printed, without the .w/.n width qualifier.
    let id = printed.get(m);
    if (id === undefined) {
      const name = m.replace(/\.[wn]$/, '').replace(/\.[wn]\./, '.');
      id = ids.get(name);
      if (id === undefined) {
        id = program.mnemonics.length;
        ids.set(name, id);
        program.mnemonics.push(name);
        counts.push(0);
      }
      printed.set(m, id);
    }
    program.mnemonicIds[i] = id;
    counts[id]!++;
    if (!insn) continue;
    const f = insn.f;
    if (f & F.UNKNOWN) {
      flags[i]! |= IF.UNKNOWN;
      continue;
    }
    if (f & F.CALL) {
      flags[i]! |= IF.CALL;
      if (insn.target !== undefined) {
        callTargets.add(insn.target);
        append(program.callers, insn.target, pc);
      }
    } else if (f & F.BRANCH) {
      flags[i]! |= IF.BRANCH;
      // `ldr pc, [pc, #…]` names its literal, not where it goes.
      if (insn.target !== undefined && !(f & F.INDIRECT)) labelTargets.push(insn.target);
    }
    if ((kind === KIND.T32 || kind === KIND.A32) && f & F.BRANCH) {
      const table = kind === KIND.T32 ? branchTable(image, program, i) : armTable(image, program, i);
      if (table) {
        program.tables.set(i, table.targets);
        labelTargets.push(...table.targets);
        flags[i]! |= IF.BRANCH;
      }
    }

    // PC-relative addresses. A literal load gives a register a value: an address already (an
    // absolute pointer the loader relocates), or an offset that `add rX, pc` turns into one.
    // movw/movt build the same offsets in two halves.
    const dest = regOf(insn.ops[0]);
    if (f & F.LOAD && insn.target !== undefined && !insn.ops.some((op) => op.k === 'list')) {
      const literal = insn.bytes === 4 || insn.bytes === undefined ? valueAt(image, insn.target, 4) : undefined;
      if (dest >= 0 && dest < 15 && literal !== undefined && insn.ops[0]?.k === 'reg' && /^r|^sp|^lr/.test(insn.ops[0].r)) {
        value[dest] = literal;
        setAt[dest] = i;
        // In a Windows program a literal is already an address (relocated by the loader), not an offset from pc.
        isAddress[dest] = image.format === 'pe' && sectionOf(image, literal) ? 1 : 0;
        const pointed = program.image.elf?.relative.get(insn.target) ?? literal;
        if (sectionOf(image, pointed) && !inCode(pointed) && (program.stringAt.has(pointed) || program.dataAt(pointed))) {
          program.addressAt.set(i, pointed);
          ref(pointed, pc);
        }
      }
      continue;
    }
    // adr, and the `add`/`sub rX, pc, #imm` A32 prints instead: an address made from pc.
    if (insn.target !== undefined && !(f & (F.BRANCH | F.CALL))) {
      program.addressAt.set(i, insn.target);
      ref(insn.target, pc);
      if (dest >= 0) {
        value[dest] = insn.target;
        setAt[dest] = i;
        isAddress[dest] = 1;
      }
      continue;
    }
    let added = -1;
    let source = -1;
    if (kind === KIND.T16 && (word & 0xff78) === 0x4478) {
      added = (word & 7) | ((word >> 4) & 8);
      source = added;
    } else if (kind === KIND.A32 && (word & 0x0fff0ff0) === 0x008f0000) {
      added = (word >>> 12) & 0xf;
      source = word & 0xf;
    } else if (kind === KIND.A32 && (word & 0x0ff00fff) === 0x0080000f) {
      added = (word >>> 12) & 0xf;
      source = (word >>> 16) & 0xf;
    }
    if (added >= 0) {
      const v = value[source]!;
      if (!Number.isNaN(v) && !isAddress[source] && i - setAt[source]! <= 32) {
        const addr = (v + pc + (kind === KIND.A32 ? 8 : 4)) >>> 0;
        program.addressAt.set(i, addr);
        // The load (or movt) that brought the offset names the same address.
        program.addressAt.set(setAt[source]!, addr);
        ref(addr, pc);
        value[added] = addr;
        setAt[added] = i;
        isAddress[added] = 1;
      } else value[added] = NaN;
      continue;
    }
    // An address plus an offset a literal brought (glibc's start code adds the GOT's offset to
    // an address made by adr): the sum is the address, and the literal, which may happen to
    // fall inside a section, was no address at all.
    if (/^adds?(\.w)?$/.test(insn.m) && insn.ops.length >= 2 && insn.ops.every((op) => op.k === 'reg')) {
      const [x, y] = insn.ops.length === 3 ? [regOf(insn.ops[1]), regOf(insn.ops[2])] : [dest, regOf(insn.ops[1])];
      const [address, offset] = x >= 0 && y >= 0 && x < 15 && y < 15 ? (isAddress[x] && !isAddress[y] ? [x, y] : isAddress[y] && !isAddress[x] ? [y, x] : [-1, -1]) : [-1, -1];
      const addr = address >= 0 ? (value[address]! + value[offset]!) >>> 0 : NaN;
      if (address >= 0 && !Number.isNaN(addr) && i - setAt[address]! <= 32 && i - setAt[offset]! <= 32 && sectionOf(image, addr)) {
        const at = setAt[offset]!;
        if (program.addressAt.get(at) === value[offset]) {
          program.addressAt.delete(at);
          const list = program.dataRefs.get(value[offset]!)?.filter((from) => from !== addrs[at]);
          if (list?.length) program.dataRefs.set(value[offset]!, list);
          else program.dataRefs.delete(value[offset]!);
        }
        program.addressAt.set(i, addr);
        ref(addr, pc);
        value[dest] = addr;
        setAt[dest] = i;
        isAddress[dest] = 1;
        continue;
      }
    }
    if (insn.m.startsWith('movw') && dest >= 0 && insn.ops[1]?.k === 'imm') {
      value[dest] = insn.ops[1].v & 0xffff;
      setAt[dest] = i;
      isAddress[dest] = 0;
      continue;
    }
    if (insn.m.startsWith('movt') && dest >= 0 && insn.ops[1]?.k === 'imm') {
      const low = value[dest]!;
      value[dest] = Number.isNaN(low) ? NaN : ((low & 0xffff) | ((insn.ops[1].v & 0xffff) << 16)) >>> 0;
      // A Windows program is not position-independent: the two halves are the address itself.
      if (image.format === 'pe' && !Number.isNaN(value[dest]!) && sectionOf(image, value[dest]!)) {
        const addr = value[dest]!;
        program.addressAt.set(i, addr);
        if (!inCode(addr)) ref(addr, pc);
        isAddress[dest] = 1;
      }
      continue;
    }
    // A load through a register holding an address: a GOT slot, a global.
    let loadedSlot = -1;
    if (f & F.LOAD) {
      const mem = insn.ops.find((op) => op.k === 'mem');
      if (mem?.k === 'mem' && !mem.index && mem.mode === 'off') {
        const base = REG.get(mem.base) ?? -1;
        if (base >= 0 && isAddress[base] && !Number.isNaN(value[base]!) && i - setAt[base]! <= 32) {
          const addr = (value[base]! + (mem.off ?? 0)) >>> 0;
          program.addressAt.set(i, addr);
          ref(addr, pc);
          if (image.format === 'pe' && dest >= 0 && program.importSlots.has(addr)) loadedSlot = addr;
        }
      }
    }
    // A call or jump through a register that holds an import (`blx r3`, `bx r12`).
    if (f & (F.BRANCH | F.CALL) && insn.target === undefined && insn.ops[0]?.k === 'reg') {
      const r = REG.get(insn.ops[0].r) ?? -1;
      if (r >= 0 && slotIn[r]! >= 0 && i - slotAt[r]! <= 16) {
        program.slotCalls.set(i, slotIn[r]!);
        append(program.slotCallers, slotIn[r]!, pc);
      }
    }
    // What the instruction writes is no longer known.
    if (dest >= 0 && !(f & (F.BRANCH | F.CALL))) slotIn[dest] = -1;
    if (loadedSlot >= 0) {
      slotIn[dest] = loadedSlot;
      slotAt[dest] = i;
    }
    if (f & (F.BRANCH | F.CALL)) {
      forget();
      // A call keeps r4–r11; a branch may land anywhere.
      if (f & F.CALL) for (const r of [0, 1, 2, 3, 12, 14]) slotIn[r] = -1;
      else slotIn.fill(-1);
    }
    else {
      const list = insn.ops.find((op) => op.k === 'list');
      if (list?.k === 'list' && f & F.LOAD) for (const r of list.regs) value[REG.get(r) ?? 15] = NaN;
      if (dest >= 0 && !(f & F.STORE)) value[dest] = NaN;
      if (dest >= 0 && insn.ops[0]?.k === 'reg' && insn.ops[0].wb) value[dest] = NaN;
    }
  }
  progress('decode', total, total);
  program.decodeMs = Date.now() - started;
  program.tally(counts);

  // Labels: branch targets inside code.
  for (const target of labelTargets) {
    const index = program.indexOf(target);
    if (index >= 0 && addrs[index] === target) flags[index]! |= IF.LABEL;
  }

  // Functions.
  progress('functions', 0, 1);
  await tick();
  const starts = new Map<number, { raw?: string; kind: Fn['kind'] }>();
  const add = (addr: number, raw: string | undefined, kind: Fn['kind']) => {
    const index = program.indexOf(addr);
    if (index < 0 || addrs[index] !== addr) return;
    const known = starts.get(addr);
    if (!known || (known.kind === 'anonymous' && kind !== 'anonymous') || (!known.raw && raw)) starts.set(addr, { raw: raw ?? known?.raw, kind: known && known.kind !== 'anonymous' ? known.kind : kind });
  };
  for (const range of program.ranges) add(range.section.addr, undefined, 'anonymous');
  if (image.format === 'pe') for (const [at, name] of importThunks(program)) image.stubs.set(at, name);
  for (const [at, name] of image.stubs) {
    const stub = stubFunction(image, name);
    add(at, stub.raw, stub.kind);
  }
  for (const addr of image.functionStarts) add(addr, undefined, 'anonymous');
  // Exports first: a function both exported and in the symbol table is listed as exported.
  for (const exp of image.exports) if (exp.function) add(exp.addr, exp.name, 'export');
  for (const sym of image.symbols) if (sym.name && sym.function) add(sym.addr, sym.name, 'symbol');
  for (const target of callTargets) add(target, undefined, 'anonymous');
  if (image.entry !== undefined) add(image.entry & ~1, starts.get(image.entry & ~1)?.raw ?? entryName(image), 'entry');
  // A stripped Linux program's main is what _start hands to __libc_start_main.
  const main = mainOf(program, image);
  if (main !== undefined && !starts.get(main)?.raw) add(main, 'main', 'symbol');

  const sortedStarts = [...starts.keys()].sort((a, b) => a - b);
  for (let k = 0; k < sortedStarts.length; k++) {
    const addr = sortedStarts[k]!;
    const first = program.indexOf(addr);
    const range = program.rangeOfIndex(first)!;
    const next = sortedStarts[k + 1];
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
    program.functionAtIndex.set(first, program.functions.length);
    program.functions.push({ addr, first, count: end - first, name, full, raw, kind, language });
    flags[first]! |= IF.FUNCTION;
  }

  // A stripped Windows program's main is found from how its C runtime calls it.
  if (image.format === 'pe') {
    const calls: { at: number; in: number; callee: Fn }[] = [];
    for (let i = 0; i < total; i++) {
      if (program.isData(i) || !(flags[i]! & IF.CALL)) continue;
      const slot = program.slotCalls.get(i);
      if (slot !== undefined) {
        const name = program.importSlots.get(slot)!;
        calls.push({ at: i, in: program.functionOfIndex(i), callee: { addr: 0, first: -1, count: 0, name, full: name, raw: name, kind: 'import' } });
        continue;
      }
      const target = program.insn(i).target;
      const callee = target !== undefined ? program.functionAt(target) : undefined;
      if (callee && callee.addr === target) calls.push({ at: i, in: program.functionOfIndex(i), callee });
    }
    // The entry point and what it calls or jumps to, two steps deep.
    const startup = new Set<number>();
    const entry = image.entry !== undefined ? program.indexOf(image.entry & ~1) : -1;
    let level = entry >= 0 ? [program.functionOfIndex(entry)] : [];
    for (let depth = 0; depth < 3 && level.length; depth++) {
      const next: number[] = [];
      for (const at of level) {
        if (at < 0 || startup.has(at)) continue;
        startup.add(at);
        const fn = program.functions[at]!;
        for (let i = fn.first; i < fn.first + fn.count && depth < 2; i++) {
          const target = !program.isData(i) && flags[i]! & (IF.CALL | IF.BRANCH) ? program.insn(i).target : undefined;
          const index = target !== undefined ? program.indexOf(target) : -1;
          if (index >= 0) next.push(program.functionOfIndex(index));
        }
      }
      level = next;
    }
    const text = (i: number) => (!program.isData(i) ? formatInsn(program.insn(i)) : '');
    const found = windowsMain(calls, startup, {
      straight: (from, to) => {
        for (let i = from + 1; i < to; i++) if (/^(b(\.w)?|bx|udf|bkpt) |^pop(\.w)? \{.*pc\}/.test(text(i))) return false;
        return true;
      },
      argc: (from, to) => {
        for (let i = from + 1; i < to; i++) if (text(i) === 'ldr r0, [r0]') return true;
        return false;
      },
      // `movw r0, …; movt r0, …` to the image base, and `movs r1, #0`
      instance: (from, to) => {
        let first = false;
        let second = false;
        for (let i = from + 1; i < to; i++) {
          if (/^movt r0, /.test(text(i)) && program.addressAt.get(i) === image.pe?.imageBase) first = true;
          else if (/^movs?(\.w)? r1, #0(x0)?$/.test(text(i))) second = true;
        }
        return first && second;
      },
      globals: () => false,
    });
    if (found && found.fn.kind === 'anonymous') Object.assign(found.fn, { name: found.name, full: found.name, raw: found.name });
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
 * Where main is, for an ELF program without symbols: what the entry point passes to
 * __libc_start_main in r0. glibc's start code loads it from a literal (`ldr r0, =main`) or,
 * position-independent, from the GOT: the GOT's address made from pc and a literal, then
 * `ldr r0, [r10, r0]` with the slot's offset in r0.
 */
function mainOf(program: Arm32Program, image: Image): number | undefined {
  if (image.format !== 'elf' || image.entry === undefined) return undefined;
  const entry = program.indexOf(image.entry & ~1);
  if (entry < 0) return undefined;
  const regs = new Array<number>(16).fill(NaN);
  const pointer = (addr: number) => (Number.isNaN(addr) ? NaN : slotValue(image, addr, 4) ?? NaN);
  for (let i = entry; i < Math.min(entry + 32, program.totalInstructions); i++) {
    if (program.isData(i)) return undefined;
    const insn = program.insn(i);
    regs[15] = program.addrs[i]! + (program.kinds[i] === KIND.A32 ? 8 : 4);
    const value = (op: Insn['ops'][number] | undefined) => regs[regOf(op)] ?? NaN;
    if (insn.f & F.CALL) {
      if (insn.target === undefined || image.stubs.get(insn.target) !== '__libc_start_main') return undefined;
      const main = (regs[0]! & ~1) >>> 0;
      return program.indexOf(main) >= 0 && program.addrs[program.indexOf(main)] === main ? main : undefined;
    }
    if (insn.f & F.BRANCH) return undefined;
    const dest = regOf(insn.ops[0]);
    if (insn.f & F.STORE || dest < 0 || dest === 15) continue;
    const [, a, b] = insn.ops;
    const mem = insn.ops.find((op) => op.k === 'mem');
    let v = NaN;
    if (insn.f & F.LOAD && insn.target !== undefined) v = pointer(insn.target);
    else if (insn.target !== undefined) v = insn.target;
    else if (mem?.k === 'mem' && insn.m.startsWith('ldr') && insn.bytes === 4 && mem.mode === 'off' && (mem.index === undefined || mem.t === `[${mem.base}, ${mem.index}]`)) {
      const base = regs[REG.get(mem.base) ?? -1] ?? NaN;
      v = pointer((base + (mem.index !== undefined ? regs[REG.get(mem.index) ?? -1] ?? NaN : mem.off ?? 0)) >>> 0);
    } else if (/^adds?(\.w)?$/.test(insn.m) && insn.ops.length <= 3) {
      const [x, y] = insn.ops.length === 3 ? [a, b] : [insn.ops[0], a];
      v = (value(x) + (y?.k === 'imm' ? y.v : value(y))) >>> 0;
    } else if (/^movs?(\.w)?$/.test(insn.m) && insn.ops.length === 2) v = a?.k === 'imm' ? a.v >>> 0 : value(a);
    else if (insn.m.startsWith('movw') && a?.k === 'imm') v = a.v & 0xffff;
    else if (insn.m.startsWith('movt') && a?.k === 'imm') v = ((regs[dest]! & 0xffff) | ((a.v & 0xffff) << 16)) >>> 0;
    regs[dest] = v;
    // A load with writeback (`ldr r1, [sp], #4`) changes its base too.
    if (mem?.k === 'mem' && mem.mode !== 'off') regs[REG.get(mem.base) ?? 15] = NaN;
  }
  return undefined;
}

/**
 * The stubs of the PLT, named after the GOT slot each one jumps through. A
 * stub computes the slot's address from pc in A32 and loads pc from it:
 * `add r12, pc, #…` / `add r12, r12, #…` / `ldr pc, [r12, #…]!`. The
 * encodings are read directly, which covers both lld's and GNU ld's stubs.
 */
/**
 * The import thunks of a Windows program: `movw r12, #lo; movt r12, #hi; ldr.w pc, [r12]`, a
 * jump through a slot of the import address table.
 */
function importThunks(program: Arm32Program): Map<number, string> {
  const thunks = new Map<number, string>();
  for (let i = 2; i < program.totalInstructions; i++) {
    if (program.kinds[i] !== KIND.T32 || program.words[i] !== 0xf8dcf000) continue; // ldr.w pc, [r12]
    const name = program.importSlots.get(program.addressAt.get(i) ?? -1);
    if (name && program.insn(i - 2).m.startsWith('movw')) thunks.set(program.addrs[i - 2]!, name);
  }
  return thunks;
}

function pltStubs(program: Arm32Program): Map<number, string> {
  const stubs = new Map<number, string>();
  for (const range of program.ranges) {
    if (!/^\.i?plt/.test(range.section.name)) continue;
    let start = -1;
    let ip = NaN;
    for (let i = range.first; i < range.first + range.count; i++) {
      if (program.kinds[i] !== KIND.A32) continue;
      const word = program.words[i]!;
      const pc = program.addrs[i]!;
      if ((word & 0x0ffff000) === 0x028fc000) {
        start = pc;
        ip = pc + 8 + armImm(word);
      } else if ((word & 0x0ffff000) === 0x028cc000) {
        ip += armImm(word);
      } else if ((word & 0x0f7ff000) === 0x053cf000 || (word & 0x0f7ff000) === 0x051cf000) {
        const offset = word & 0xfff;
        const slot = (ip + (word & 0x800000 ? offset : -offset)) >>> 0;
        const name = program.importSlots.get(slot);
        if (name && start >= 0) stubs.set(start, name);
        start = -1;
        ip = NaN;
      }
    }
  }
  return stubs;
}

export type { StringRef };
