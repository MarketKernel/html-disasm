/**
 * An ELF reader: everything about an Android (or Linux) library or program
 * that is not its code.
 *
 * 32- and 64-bit little-endian files are read: the header, the segments and
 * sections, the symbol tables (`.dynsym`, and `.symtab` when the file was not
 * stripped, with the Arm mapping symbols that say where A32, T32 and data
 * lie), the dynamic section (needed libraries, soname, run paths), the
 * symbol versions — which, on Android, is how an imported symbol says which
 * library it comes from (`strcmp@LIBC`) — the relocations in every form a
 * linker writes them (REL, RELA, RELR, and Android's packed APS2), the notes
 * (Android's API level and NDK, the build ID), the Arm build attributes, and
 * the unwind tables (`.ARM.exidx`, `.eh_frame_hdr`), which list where
 * functions start even in a stripped library.
 *
 * A file whose section headers were removed is read through its segments and
 * dynamic section alone: the code is then the executable segment.
 *
 * Nothing here touches the DOM, so the tests run it in Node.
 */

import { t } from './i18n';
import { sleb, uleb, utf8 } from './bytes';

export interface ElfSection {
  index: number;
  name: string;
  type: number;
  flags: number;
  addr: number;
  offset: number;
  size: number;
  link: number;
  info: number;
  align: number;
  entsize: number;
}

export interface ElfSegment {
  type: number;
  flags: number;
  offset: number;
  vaddr: number;
  filesz: number;
  memsz: number;
  align: number;
}

export interface ElfSymbol {
  name: string;
  /** The address, without the Thumb bit of an A32/T32 function. */
  addr: number;
  size: number;
  type: number;
  bind: number;
  visibility: number;
  shndx: number;
  /** A function in Thumb state (its value had bit 0 set). */
  thumb?: boolean;
  /** The version it is bound to (`LIBC`), and the library that version belongs to. */
  version?: string;
  library?: string;
}

export interface ElfImport {
  name: string;
  library: string;
  version?: string;
  weak: boolean;
  /** STT_FUNC, STT_OBJECT… (the type of the undefined symbol). */
  type: number;
}

export interface ElfExport {
  name: string;
  addr: number;
  size: number;
  type: number;
  thumb?: boolean;
  version?: string;
}

export interface DynamicEntry {
  tag: number;
  name: string;
  value: number;
  /** What it says, for the overview: a library name, a size, an address. */
  text: string;
}

export interface Relocation {
  offset: number;
  type: number;
  sym: number;
  addend: number;
}

export interface ElfNote {
  owner: string;
  type: number;
  desc: Uint8Array;
}

/** Arm mapping symbols: where A32 ($a), T32 ($t), A64 ($x) code and data ($d) begin. */
export interface CodeMark {
  addr: number;
  kind: 'a' | 't' | 'x' | 'd';
}

export interface Elf {
  bytes: Uint8Array;
  is64: boolean;
  machine: number;
  machineName: string;
  /** arm64, armv7, x86_64… as the file chip shows it. */
  arch: string;
  type: number;
  typeName: string;
  osabi: number;
  flags: number;
  flagNames: string[];
  entry: number;
  segments: ElfSegment[];
  sections: ElfSection[];
  /** No section headers: sections were made up from the segments. */
  sectionless: boolean;
  dynamic: DynamicEntry[];
  needed: string[];
  soname?: string;
  runpath: string[];
  interpreter?: string;
  /** The symbol tables: .dynsym, and .symtab when the file has one. */
  dynsyms: ElfSymbol[];
  symtab: ElfSymbol[];
  imports: ElfImport[];
  exports: ElfExport[];
  marks: CodeMark[];
  relocations: Relocation[];
  /** Relocation counts by type name, RELR and packed ones included. */
  relocationCounts: Map<string, number>;
  /** How the relocations are stored: rel, rela, relr, android packed. */
  relocationFormats: string[];
  /** A GOT or data slot a symbol's address is written into → the symbol. */
  slots: Map<number, string>;
  /** Slots the loader rebases → the address they then hold (RELA keeps it out of the file). */
  relative: Map<number, number>;
  /** Where functions begin, from the unwind tables and the init/fini arrays. */
  functionStarts: number[];
  /** The init and fini arrays, as stored: an ARM pointer to Thumb code has bit 0 set. */
  initArray: number[];
  finiArray: number[];
  notes: ElfNote[];
  android?: { api: number; ndk?: string; build?: string };
  buildId?: string;
  /** GNU property notes: BTI and PAC on arm64. */
  features: string[];
  /** The Arm build attributes (.ARM.attributes): CPU, FPU, NEON, ABI. */
  attributes: [string, string][];
  /** `.comment`: the compilers and linkers that made the file. */
  comment: string[];
  /** Whether it carries DWARF debugging information. */
  debugInfo: boolean;
}

export class NotElf extends Error {}

export const isElf = (bytes: Uint8Array): boolean => bytes.length >= 16 && bytes[0] === 0x7f && bytes[1] === 0x45 && bytes[2] === 0x4c && bytes[3] === 0x46;

export const EM = { ARM: 40, AARCH64: 183, X86: 3, X86_64: 62, MIPS: 8, RISCV: 243 } as const;
export const SHF = { WRITE: 1, ALLOC: 2, EXEC: 4, MERGE: 0x10, STRINGS: 0x20 } as const;
export const SHT = { PROGBITS: 1, SYMTAB: 2, STRTAB: 3, RELA: 4, HASH: 5, DYNAMIC: 6, NOTE: 7, NOBITS: 8, REL: 9, DYNSYM: 11, INIT_ARRAY: 14, FINI_ARRAY: 15, ARM_EXIDX: 0x70000001, ARM_ATTRIBUTES: 0x70000003 } as const;
export const STT = { NOTYPE: 0, OBJECT: 1, FUNC: 2, SECTION: 3, FILE: 4, TLS: 6, GNU_IFUNC: 10 } as const;
const PT = { LOAD: 1, DYNAMIC: 2, INTERP: 3, NOTE: 4, GNU_EH_FRAME: 0x6474e550 } as const;

const MACHINES: Record<number, string> = {
  2: 'SPARC', 3: 'x86', 8: 'MIPS', 20: 'PowerPC', 21: 'PowerPC 64', 22: 'S/390', 40: 'ARM', 42: 'SuperH', 50: 'IA-64', 62: 'x86-64', 183: 'AArch64',
  243: 'RISC-V', 247: 'BPF', 258: 'LoongArch',
};
const TYPES: Record<number, string> = { 0: 'None', 1: 'Relocatable object', 2: 'Executable', 3: 'Shared library', 4: 'Core dump' };

export const SEGMENT_TYPES: Record<number, string> = {
  0: 'NULL', 1: 'LOAD', 2: 'DYNAMIC', 3: 'INTERP', 4: 'NOTE', 5: 'SHLIB', 6: 'PHDR', 7: 'TLS', 0x6474e550: 'GNU_EH_FRAME', 0x6474e551: 'GNU_STACK',
  0x6474e552: 'GNU_RELRO', 0x6474e553: 'GNU_PROPERTY', 0x70000000: 'ARM_ARCHEXT', 0x70000001: 'ARM_EXIDX', 0x70000002: 'AARCH64_MEMTAG_MTE',
};

export const SECTION_TYPES: Record<number, string> = {
  0: 'NULL', 1: 'PROGBITS', 2: 'SYMTAB', 3: 'STRTAB', 4: 'RELA', 5: 'HASH', 6: 'DYNAMIC', 7: 'NOTE', 8: 'NOBITS', 9: 'REL', 11: 'DYNSYM', 14: 'INIT_ARRAY',
  15: 'FINI_ARRAY', 16: 'PREINIT_ARRAY', 17: 'GROUP', 19: 'RELR', 0x60000001: 'ANDROID_REL', 0x60000002: 'ANDROID_RELA', 0x6fffff00: 'ANDROID_RELR',
  0x6ffffff6: 'GNU_HASH', 0x6ffffffd: 'GNU_VERDEF', 0x6ffffffe: 'GNU_VERNEED', 0x6fffffff: 'GNU_VERSYM', 0x70000001: 'ARM_EXIDX',
  0x70000003: 'ARM_ATTRIBUTES', 0x6fff4c00: 'LLVM_ODRTAB', 0x6fff4c02: 'LLVM_CALL_GRAPH_PROFILE', 0x6fff4c03: 'LLVM_ADDRSIG',
};

const DT: Record<number, string> = {
  0: 'NULL', 1: 'NEEDED', 2: 'PLTRELSZ', 3: 'PLTGOT', 4: 'HASH', 5: 'STRTAB', 6: 'SYMTAB', 7: 'RELA', 8: 'RELASZ', 9: 'RELAENT', 10: 'STRSZ', 11: 'SYMENT',
  12: 'INIT', 13: 'FINI', 14: 'SONAME', 15: 'RPATH', 16: 'SYMBOLIC', 17: 'REL', 18: 'RELSZ', 19: 'RELENT', 20: 'PLTREL', 21: 'DEBUG', 22: 'TEXTREL',
  23: 'JMPREL', 24: 'BIND_NOW', 25: 'INIT_ARRAY', 26: 'FINI_ARRAY', 27: 'INIT_ARRAYSZ', 28: 'FINI_ARRAYSZ', 29: 'RUNPATH', 30: 'FLAGS',
  32: 'PREINIT_ARRAY', 33: 'PREINIT_ARRAYSZ', 35: 'RELRSZ', 36: 'RELR', 37: 'RELRENT', 0x6000000f: 'ANDROID_REL', 0x60000010: 'ANDROID_RELSZ',
  0x60000011: 'ANDROID_RELA', 0x60000012: 'ANDROID_RELASZ', 0x6fffe000: 'ANDROID_RELR', 0x6fffe001: 'ANDROID_RELRSZ', 0x6fffe003: 'ANDROID_RELRENT',
  0x6ffffef5: 'GNU_HASH', 0x6ffffff0: 'VERSYM', 0x6ffffff9: 'RELACOUNT', 0x6ffffffa: 'RELCOUNT', 0x6ffffffb: 'FLAGS_1', 0x6ffffffc: 'VERDEF',
  0x6ffffffd: 'VERDEFNUM', 0x6ffffffe: 'VERNEED', 0x6fffffff: 'VERNEEDNUM', 0x70000001: 'AARCH64_BTI_PLT', 0x70000003: 'AARCH64_PAC_PLT',
  0x70000005: 'AARCH64_VARIANT_PCS', 0x70000009: 'AARCH64_MEMTAG_MODE',
};

/** The relocation types the overview counts, by machine. */
const RELOCATION_NAMES: Record<number, Record<number, string>> = {
  [EM.ARM]: { 0: 'NONE', 2: 'ABS32', 3: 'REL32', 17: 'TLS_DTPMOD32', 18: 'TLS_DTPOFF32', 19: 'TLS_TPOFF32', 20: 'COPY', 21: 'GLOB_DAT', 22: 'JUMP_SLOT', 23: 'RELATIVE', 160: 'IRELATIVE' },
  [EM.AARCH64]: { 0: 'NONE', 257: 'ABS64', 258: 'ABS32', 1024: 'COPY', 1025: 'GLOB_DAT', 1026: 'JUMP_SLOT', 1027: 'RELATIVE', 1028: 'TLS_DTPMOD', 1029: 'TLS_DTPREL', 1030: 'TLS_TPREL', 1031: 'TLSDESC', 1032: 'IRELATIVE' },
  [EM.X86_64]: { 1: 'ABS64', 5: 'COPY', 6: 'GLOB_DAT', 7: 'JUMP_SLOT', 8: 'RELATIVE', 37: 'IRELATIVE' },
  [EM.X86]: { 1: 'ABS32', 5: 'COPY', 6: 'GLOB_DAT', 7: 'JUMP_SLOT', 8: 'RELATIVE', 42: 'IRELATIVE' },
};
/** Relocations that put a symbol's address into a slot: the slot is then named after it. */
const SLOT_TYPES = new Set(['ABS32', 'ABS64', 'GLOB_DAT', 'JUMP_SLOT']);

/**
 * Unversioned imports name no library. These prefixes are what the Android NDK's own libraries
 * export; an import with one is filed under that library when the file needs it.
 */
const KNOWN_LIBRARIES: [RegExp, string][] = [
  [/^__android_log_|^__android_log$/, 'liblog.so'],
  [/^(A(Asset|Configuration|Looper|NativeActivity|NativeWindow|InputQueue|InputEvent|KeyEvent|MotionEvent|Sensor|Choreographer|Surface|Thermal|Hardware|Font|Storage|Trace|Performance|Window|SharedMemory|Bitmap|Chooser|Activity)|ATrace_)/, 'libandroid.so'],
  [/^ANativeWindow_|^AHardwareBuffer_/, 'libnativewindow.so'],
  [/^AndroidBitmap_/, 'libjnigraphics.so'],
  [/^egl[A-Z]/, 'libEGL.so'],
  [/^gl[A-Z]/, 'libGLESv3.so'],
  [/^vk[A-Z]/, 'libvulkan.so'],
  [/^AAudio/, 'libaaudio.so'],
  [/^AMedia|^AImage/, 'libmediandk.so'],
  [/^ACamera/, 'libcamera2ndk.so'],
  [/^sl[A-Z]|^SL_IID/, 'libOpenSLES.so'],
  [/^(inflate|deflate|crc32|adler32|compress|uncompress|zlib|gz)/, 'libz.so'],
  [/^ANeuralNetworks/, 'libneuralnetworks.so'],
  [/^ABinder|^AIBinder|^AParcel|^AStatus/, 'libbinder_ndk.so'],
  [/^_Z.*St3__1|^_ZNSt6__ndk1|^_ZNKSt6__ndk1|^_ZTVNSt6__ndk1/, 'libc++_shared.so'],
  [/^_Unwind_|^__cxa_|^__gxx_personality/, 'libc++_shared.so'],
];

class Reader {
  readonly view: DataView;
  constructor(
    readonly bytes: Uint8Array,
    readonly is64: boolean,
  ) {
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }
  ok = (at: number, length: number) => at >= 0 && at + length <= this.bytes.length;
  u8 = (at: number) => this.bytes[at] ?? 0;
  u16 = (at: number) => (this.ok(at, 2) ? this.view.getUint16(at, true) : 0);
  u32 = (at: number) => (this.ok(at, 4) ? this.view.getUint32(at, true) : 0);
  i32 = (at: number) => (this.ok(at, 4) ? this.view.getInt32(at, true) : 0);
  u64 = (at: number) => (this.ok(at, 8) ? Number(this.view.getBigUint64(at, true)) : 0);
  i64 = (at: number) => (this.ok(at, 8) ? Number(this.view.getBigInt64(at, true)) : 0);
  /** A pointer-sized field. */
  word = (at: number) => (this.is64 ? this.u64(at) : this.u32(at));
  sword = (at: number) => (this.is64 ? this.i64(at) : this.i32(at));
  cstr(at: number, max = 4096): string {
    let end = at;
    const limit = Math.min(this.bytes.length, at + max);
    while (end < limit && this.bytes[end] !== 0) end++;
    return utf8(this.bytes.subarray(at, end));
  }
  uleb = (at: number) => uleb(this.bytes, at);
  sleb = (at: number) => sleb(this.bytes, at);
}

export function archOf(machine: number, flags = 0): string {
  switch (machine) {
    case EM.AARCH64:
      return 'arm64';
    case EM.ARM:
      return flags & 0x800000 ? 'armv7 (be8)' : 'armv7';
    case EM.X86_64:
      return 'x86_64';
    case EM.X86:
      return 'x86';
  }
  return MACHINES[machine] ?? `machine ${machine}`;
}

/** Opens an ELF file. */
export function parseElf(file: Uint8Array): Elf {
  if (!isElf(file)) throw new NotElf(t('open', 'Not an ELF file (no \\x7fELF signature).'));
  const cls = file[4];
  if (cls !== 1 && cls !== 2) throw new NotElf(t('open', 'The ELF file has an unknown class.'));
  if (file[5] !== 1) throw new NotElf(t('open', 'This ELF file is big-endian; only little-endian ones are supported.'));
  const is64 = cls === 2;
  const r = new Reader(file, is64);
  const type = r.u16(16);
  const machine = r.u16(18);
  const entry = r.word(24);
  const phoff = is64 ? r.u64(32) : r.u32(28);
  const shoff = is64 ? r.u64(40) : r.u32(32);
  const flags = r.u32(is64 ? 48 : 36);
  const phentsize = r.u16(is64 ? 54 : 42);
  const phnum = r.u16(is64 ? 56 : 44);
  const shentsize = r.u16(is64 ? 58 : 46);
  let shnum = r.u16(is64 ? 60 : 48);
  let shstrndx = r.u16(is64 ? 62 : 50);

  const elf: Elf = {
    bytes: file, is64, machine, machineName: MACHINES[machine] ?? `machine ${machine}`, arch: archOf(machine, flags), type, typeName: TYPES[type] ?? `type ${type}`,
    osabi: file[7] ?? 0, flags, flagNames: flagNames(machine, flags), entry, segments: [], sections: [], sectionless: false, dynamic: [], needed: [], runpath: [],
    dynsyms: [], symtab: [], imports: [], exports: [], marks: [], relocations: [], relocationCounts: new Map(), relocationFormats: [], slots: new Map(),
    relative: new Map(), functionStarts: [], initArray: [], finiArray: [], notes: [], features: [], attributes: [], comment: [], debugInfo: false,
  };

  // Segments.
  for (let i = 0; i < phnum && phoff; i++) {
    const at = phoff + i * phentsize;
    if (!r.ok(at, is64 ? 56 : 32)) break;
    elf.segments.push(
      is64
        ? { type: r.u32(at), flags: r.u32(at + 4), offset: r.u64(at + 8), vaddr: r.u64(at + 16), filesz: r.u64(at + 32), memsz: r.u64(at + 40), align: r.u64(at + 48) }
        : { type: r.u32(at), offset: r.u32(at + 4), vaddr: r.u32(at + 8), filesz: r.u32(at + 16), memsz: r.u32(at + 20), flags: r.u32(at + 24), align: r.u32(at + 28) },
    );
  }

  // Sections. A count too large for the header lives in section 0's size field.
  if (shoff && shnum === 0 && r.ok(shoff, shentsize)) shnum = is64 ? r.u64(shoff + 32) : r.u32(shoff + 20);
  if (shstrndx === 0xffff && shoff) shstrndx = r.u32(shoff + (is64 ? 44 : 28));
  const nameOffsets: number[] = [];
  for (let i = 0; i < shnum && shoff; i++) {
    const at = shoff + i * shentsize;
    if (!r.ok(at, is64 ? 64 : 40)) break;
    nameOffsets.push(r.u32(at));
    elf.sections.push(
      is64
        ? { index: i, name: '', type: r.u32(at + 4), flags: r.u64(at + 8), addr: r.u64(at + 16), offset: r.u64(at + 24), size: r.u64(at + 32), link: r.u32(at + 40), info: r.u32(at + 44), align: r.u64(at + 48), entsize: r.u64(at + 56) }
        : { index: i, name: '', type: r.u32(at + 4), flags: r.u32(at + 8), addr: r.u32(at + 12), offset: r.u32(at + 16), size: r.u32(at + 20), link: r.u32(at + 24), info: r.u32(at + 28), align: r.u32(at + 32), entsize: r.u32(at + 36) },
    );
  }
  const names = elf.sections[shstrndx];
  if (names) elf.sections.forEach((s, i) => (s.name = r.cstr(names.offset + nameOffsets[i]!, 256)));
  if (!elf.sections.some((s) => s.type !== 0)) {
    elf.sectionless = true;
    elf.sections = sectionsFromSegments(elf);
  }

  /** The file offset of a virtual address, through the loaded segments. */
  const offsetOf = (addr: number): number => {
    for (const seg of elf.segments) if (seg.type === PT.LOAD && addr >= seg.vaddr && addr < seg.vaddr + seg.filesz) return seg.offset + (addr - seg.vaddr);
    return -1;
  };

  // The dynamic section.
  const dynSeg = elf.segments.find((s) => s.type === PT.DYNAMIC);
  const dynSection = elf.sections.find((s) => s.type === SHT.DYNAMIC);
  const dynAt = dynSection?.offset ?? dynSeg?.offset;
  const dynSize = dynSection?.size ?? dynSeg?.filesz ?? 0;
  const dyn = new Map<number, number>();
  const dynList: [number, number][] = [];
  if (dynAt !== undefined) {
    const step = is64 ? 16 : 8;
    for (let at = dynAt; at + step <= dynAt + dynSize; at += step) {
      const tag = is64 ? r.i64(at) : r.i32(at);
      const value = r.word(at + (is64 ? 8 : 4));
      if (tag === 0) break;
      dynList.push([tag, value]);
      if (!dyn.has(tag)) dyn.set(tag, value);
    }
  }
  const dynstrAt = dyn.has(5) ? offsetOf(dyn.get(5)!) : elf.sections.find((s) => s.name === '.dynstr')?.offset ?? -1;
  const dynstr = (offset: number) => (dynstrAt >= 0 ? r.cstr(dynstrAt + offset, 1024) : '');
  for (const [tag, value] of dynList) {
    const name = DT[tag] ?? `0x${(tag >>> 0).toString(16)}`;
    let text = `0x${value.toString(16)}`;
    if (tag === 1 || tag === 14 || tag === 15 || tag === 29) text = dynstr(value);
    else if ([2, 8, 9, 10, 11, 18, 19, 27, 28, 33, 35, 37, 0x60000010, 0x60000012, 0x6fffe001, 0x6fffe003].includes(tag)) text = `${value}`;
    else if (tag === 0x6ffffff9 || tag === 0x6ffffffa || tag === 0x6ffffffd || tag === 0x6fffffff) text = `${value}`;
    else if (tag === 20) text = value === 7 ? 'RELA' : 'REL';
    else if (tag === 30) text = dtFlags(value);
    else if (tag === 0x6ffffffb) text = dtFlags1(value);
    elf.dynamic.push({ tag, name, value, text });
    if (tag === 1) elf.needed.push(text);
    if (tag === 14) elf.soname = text;
    if (tag === 15 || tag === 29) elf.runpath.push(...text.split(':').filter(Boolean));
  }
  const interp = elf.segments.find((s) => s.type === PT.INTERP);
  if (interp) elf.interpreter = r.cstr(interp.offset, interp.filesz);

  // Symbol versions: index → (version, library).
  const versions = new Map<number, { name: string; library?: string }>();
  const verneedAt = dyn.has(0x6ffffffe) ? offsetOf(dyn.get(0x6ffffffe)!) : -1;
  for (let at = verneedAt, n = 0; at >= 0 && n < (dyn.get(0x6fffffff) ?? 0) && r.ok(at, 16); n++) {
    const count = r.u16(at + 2);
    const library = dynstr(r.u32(at + 4));
    for (let aux = at + r.u32(at + 8), k = 0; k < count && r.ok(aux, 16); k++) {
      versions.set(r.u16(aux + 6) & 0x7fff, { name: dynstr(r.u32(aux + 8)), library });
      const next = r.u32(aux + 12);
      if (!next) break;
      aux += next;
    }
    const next = r.u32(at + 12);
    if (!next) break;
    at += next;
  }
  const verdefAt = dyn.has(0x6ffffffc) ? offsetOf(dyn.get(0x6ffffffc)!) : -1;
  for (let at = verdefAt, n = 0; at >= 0 && n < (dyn.get(0x6ffffffd) ?? 0) && r.ok(at, 20); n++) {
    const index = r.u16(at + 4);
    const flagsBase = r.u16(at + 2) & 1;
    if (!flagsBase) versions.set(index, { name: dynstr(r.u32(at + r.u32(at + 12))) });
    const next = r.u32(at + 16);
    if (!next) break;
    at += next;
  }

  // Symbols: .dynsym (through the section, or DT_SYMTAB with a count from the hash tables) and .symtab.
  const symsize = is64 ? 24 : 16;
  const readSymbols = (at: number, count: number, strAt: number, versym: number): ElfSymbol[] => {
    const out: ElfSymbol[] = [];
    for (let i = 0; i < count && r.ok(at + i * symsize, symsize); i++) {
      const p = at + i * symsize;
      const nameAt = r.u32(p);
      const value = is64 ? r.u64(p + 8) : r.u32(p + 4);
      const size = is64 ? r.u64(p + 16) : r.u32(p + 8);
      const info = r.u8(is64 ? p + 4 : p + 12);
      const other = r.u8(is64 ? p + 5 : p + 13);
      const shndx = r.u16(is64 ? p + 6 : p + 14);
      const symType = info & 0xf;
      const thumb = machine === EM.ARM && (symType === STT.FUNC || symType === STT.GNU_IFUNC) && (value & 1) === 1;
      const sym: ElfSymbol = { name: strAt >= 0 && nameAt ? r.cstr(strAt + nameAt, 4096) : '', addr: thumb ? value - 1 : value, size, type: symType, bind: info >> 4, visibility: other & 3, shndx };
      if (thumb) sym.thumb = true;
      if (versym >= 0) {
        const v = versions.get(r.u16(versym + i * 2) & 0x7fff);
        if (v) {
          sym.version = v.name;
          if (v.library) sym.library = v.library;
        }
      }
      out.push(sym);
    }
    return out;
  };
  const dynsymSection = elf.sections.find((s) => s.type === SHT.DYNSYM);
  const versymAt = dyn.has(0x6ffffff0) ? offsetOf(dyn.get(0x6ffffff0)!) : -1;
  if (dynsymSection) {
    const str = elf.sections[dynsymSection.link];
    elf.dynsyms = readSymbols(dynsymSection.offset, Math.floor(dynsymSection.size / symsize), str?.offset ?? dynstrAt, versymAt);
  } else if (dyn.has(6)) {
    const count = symbolCount(r, dyn, offsetOf);
    elf.dynsyms = readSymbols(offsetOf(dyn.get(6)!), count, dynstrAt, versymAt);
  }
  const symtabSection = elf.sections.find((s) => s.type === SHT.SYMTAB);
  if (symtabSection) {
    const str = elf.sections[symtabSection.link];
    elf.symtab = readSymbols(symtabSection.offset, Math.floor(symtabSection.size / symsize), str?.offset ?? -1, -1);
    for (const sym of elf.symtab) {
      const mark = /^\$([atxd])(?:\.|$)/.exec(sym.name);
      if (mark && sym.type === STT.NOTYPE) elf.marks.push({ addr: sym.addr, kind: mark[1] as CodeMark['kind'] });
    }
    elf.marks.sort((a, b) => a.addr - b.addr);
  }

  // Imports and exports.
  for (const sym of elf.dynsyms) {
    if (!sym.name || sym.type === STT.SECTION || sym.type === STT.FILE) continue;
    if (sym.shndx === 0) {
      const library = sym.library ?? guessLibrary(sym.name, elf.needed);
      elf.imports.push({ name: sym.name, library, version: sym.version, weak: sym.bind === 2, type: sym.type });
    } else if ((sym.bind === 1 || sym.bind === 2 || sym.bind === 10) && (sym.visibility === 0 || sym.visibility === 3)) {
      elf.exports.push({ name: sym.name, addr: sym.addr, size: sym.size, type: sym.type, ...(sym.thumb ? { thumb: true } : {}), ...(sym.version ? { version: sym.version } : {}) });
    }
  }

  readRelocations(elf, r, dyn, offsetOf);
  readNotes(elf, r);
  readUnwindTables(elf, r, offsetOf);
  readInitArrays(elf, r, dyn, offsetOf);
  const attributes = elf.sections.find((s) => s.type === SHT.ARM_ATTRIBUTES);
  if (attributes) elf.attributes = armAttributes(r, attributes.offset, attributes.size);
  const comment = elf.sections.find((s) => s.name === '.comment');
  if (comment) elf.comment = [...new Set(utf8(file.subarray(comment.offset, comment.offset + comment.size)).split('\0').map((s) => s.trim()).filter(Boolean))];
  elf.debugInfo = elf.sections.some((s) => s.name === '.debug_info' || s.name === '.zdebug_info');
  return elf;
}

/** Without section headers: one made-up section per loaded segment, code where the segment is executable. */
function sectionsFromSegments(elf: Elf): ElfSection[] {
  const out: ElfSection[] = [];
  elf.segments.forEach((seg, i) => {
    if (seg.type !== PT.LOAD) return;
    const exec = seg.flags & 1;
    const write = seg.flags & 2;
    const name = exec ? '.text' : write ? '.data' : '.rodata';
    out.push({ index: out.length + 1, name: `${name} (LOAD ${i})`, type: SHT.PROGBITS, flags: SHF.ALLOC | (exec ? SHF.EXEC : 0) | (write ? SHF.WRITE : 0), addr: seg.vaddr, offset: seg.offset, size: seg.filesz, link: 0, info: 0, align: seg.align, entsize: 0 });
    if (seg.memsz > seg.filesz) out.push({ index: out.length + 1, name: `.bss (LOAD ${i})`, type: SHT.NOBITS, flags: SHF.ALLOC | SHF.WRITE, addr: seg.vaddr + seg.filesz, offset: 0, size: seg.memsz - seg.filesz, link: 0, info: 0, align: 1, entsize: 0 });
  });
  return out;
}

/** How many dynamic symbols there are, when no section header says: from DT_HASH, or by walking DT_GNU_HASH. */
function symbolCount(r: Reader, dyn: Map<number, number>, offsetOf: (addr: number) => number): number {
  if (dyn.has(4)) {
    const at = offsetOf(dyn.get(4)!);
    if (at >= 0) return r.u32(at + 4);
  }
  if (!dyn.has(0x6ffffef5)) return 0;
  const at = offsetOf(dyn.get(0x6ffffef5)!);
  if (at < 0) return 0;
  const nbuckets = r.u32(at);
  const symoffset = r.u32(at + 4);
  const bloomSize = r.u32(at + 8);
  const buckets = at + 16 + bloomSize * (r.is64 ? 8 : 4);
  const chains = buckets + nbuckets * 4;
  let last = 0;
  for (let i = 0; i < nbuckets; i++) last = Math.max(last, r.u32(buckets + i * 4));
  if (last < symoffset) return symoffset;
  while (r.ok(chains + (last - symoffset) * 4, 4) && !(r.u32(chains + (last - symoffset) * 4) & 1)) last++;
  return last + 1;
}

function guessLibrary(name: string, needed: string[]): string {
  for (const [pattern, library] of KNOWN_LIBRARIES) {
    if (!pattern.test(name)) continue;
    if (needed.includes(library)) return library;
    if (library === 'libGLESv3.so') return needed.find((n) => /^libGLES/.test(n)) ?? '';
  }
  return '';
}

function flagNames(machine: number, flags: number): string[] {
  const out: string[] = [];
  if (machine === EM.ARM) {
    const eabi = flags >>> 24;
    if (eabi) out.push(`EABI${eabi}`);
    if (flags & 0x400) out.push('hard-float');
    if (flags & 0x200) out.push('soft-float');
    if (flags & 0x800000) out.push('BE8');
  }
  return out;
}

function dtFlags(value: number): string {
  const names = ['ORIGIN', 'SYMBOLIC', 'TEXTREL', 'BIND_NOW', 'STATIC_TLS'];
  return names.filter((_, i) => value & (1 << i)).join(' ') || '0';
}

function dtFlags1(value: number): string {
  const names = ['NOW', 'GLOBAL', 'GROUP', 'NODELETE', 'LOADFLTR', 'INITFIRST', 'NOOPEN', 'ORIGIN', 'DIRECT', 'TRANS', 'INTERPOSE', 'NODEFLIB', 'NODUMP', 'CONFALT', 'ENDFILTEE', 'DISPRELDNE', 'DISPRELPND', 'NODIRECT', 'IGNMULDEF', 'NOKSYMS', 'NOHDR', 'EDITED', 'NORELOC', 'SYMINTPOSE', 'GLOBAUDIT', 'SINGLETON', 'STUB', 'PIE'];
  return names.filter((_, i) => value & (1 << i)).join(' ') || '0';
}

/* ------------------------------------------------------------------ *
 * Relocations
 * ------------------------------------------------------------------ */

function readRelocations(elf: Elf, r: Reader, dyn: Map<number, number>, offsetOf: (addr: number) => number): void {
  const names = RELOCATION_NAMES[elf.machine] ?? {};
  const word = elf.is64 ? 8 : 4;
  const count = (name: string, n = 1) => elf.relocationCounts.set(name, (elf.relocationCounts.get(name) ?? 0) + n);
  const formats = new Set<string>();
  const take = (offset: number, info: number, addend: number | undefined) => {
    const type = elf.is64 ? info % 2 ** 32 : info & 0xff;
    const sym = elf.is64 ? Math.floor(info / 2 ** 32) : info >>> 8;
    const name = names[type] ?? `type ${type}`;
    count(name);
    if (name === 'RELATIVE' || name === 'IRELATIVE') {
      // REL keeps the address in the slot itself; RELA keeps it here.
      const value = addend ?? r.word(offsetOf(offset));
      elf.relative.set(offset, value);
      return;
    }
    elf.relocations.push({ offset, type, sym, addend: addend ?? 0 });
    const symbol = elf.dynsyms[sym];
    if (symbol?.name && SLOT_TYPES.has(name)) elf.slots.set(offset, symbol.name);
  };

  // Plain tables, through the dynamic section (or the sections of a file without one).
  const tables: [number, number, boolean][] = [];
  if (dyn.has(17)) tables.push([dyn.get(17)!, dyn.get(18) ?? 0, false]);
  if (dyn.has(7)) tables.push([dyn.get(7)!, dyn.get(8) ?? 0, true]);
  if (dyn.has(23)) tables.push([dyn.get(23)!, dyn.get(2) ?? 0, dyn.get(20) === 7]);
  if (!dyn.size) for (const s of elf.sections) if ((s.type === SHT.REL || s.type === SHT.RELA) && s.flags & SHF.ALLOC) tables.push([s.addr, s.size, s.type === SHT.RELA]);
  for (const [addr, size, rela] of tables) {
    const at = offsetOf(addr);
    if (at < 0) continue;
    formats.add(rela ? 'RELA' : 'REL');
    const step = rela ? word * 3 : word * 2;
    for (let p = at; p + step <= at + size && r.ok(p, step); p += step) take(r.word(p), r.word(p + word), rela ? r.sword(p + word * 2) : undefined);
  }

  // Android's packed relocations (APS2): groups of relocations sharing an info word, an offset
  // step or an addend, all in SLEB128.
  for (const [tagAt, tagSize, rela] of [[0x6000000f, 0x60000010, false], [0x60000011, 0x60000012, true]] as const) {
    if (!dyn.has(tagAt)) continue;
    const start = offsetOf(dyn.get(tagAt)!);
    if (start < 0 || r.u32(start) !== 0x32535041) continue; // "APS2"
    formats.add(rela ? 'Android packed RELA' : 'Android packed REL');
    const end = start + (dyn.get(tagSize) ?? 0);
    let p = start + 4;
    const next = () => {
      const [v, q] = r.sleb(p);
      p = q;
      return v;
    };
    let remaining = next();
    let offset = next();
    let info = 0;
    let addend = 0;
    while (remaining > 0 && p < end) {
      const groupSize = next();
      const groupFlags = next();
      const byInfo = groupFlags & 1;
      const byOffset = groupFlags & 2;
      const byAddend = groupFlags & 4;
      const hasAddend = groupFlags & 8;
      const delta = byOffset ? next() : 0;
      if (byInfo) info = next();
      if (hasAddend && byAddend) addend += next();
      if (!hasAddend) addend = 0;
      for (let i = 0; i < groupSize && remaining > 0; i++, remaining--) {
        offset += byOffset ? delta : next();
        if (!byInfo) info = next();
        if (hasAddend && !byAddend) addend += next();
        take(offset, info, rela ? addend : undefined);
      }
      if (groupSize <= 0) break;
    }
  }

  // RELR: relative relocations as a bitmap of words after each address.
  const relrAddr = dyn.get(36) ?? dyn.get(0x6fffe000);
  if (relrAddr !== undefined) {
    const at = offsetOf(relrAddr);
    const size = dyn.get(35) ?? dyn.get(0x6fffe001) ?? 0;
    if (at >= 0) {
      formats.add('RELR');
      let base = 0;
      let n = 0;
      // RELR slots hold their addresses in place, as REL ones do.
      const relocate = (slot: number) => {
        n++;
        elf.relative.set(slot, r.word(offsetOf(slot)));
      };
      for (let p = at; p + word <= at + size; p += word) {
        const entry = r.word(p);
        if (entry % 2 === 0) {
          relocate(entry);
          base = entry + word;
        } else {
          let bitmap = (elf.is64 ? r.view.getBigUint64(p, true) : BigInt(entry >>> 0)) >> 1n;
          for (let i = 0; bitmap; i++, bitmap >>= 1n) if (bitmap & 1n) relocate(base + i * word);
          base += word * (word * 8 - 1);
        }
      }
      count('RELATIVE (RELR)', n);
    }
  }
  elf.relocationFormats = [...formats];
}

/* ------------------------------------------------------------------ *
 * Notes, unwind tables, init arrays, Arm attributes
 * ------------------------------------------------------------------ */

function readNotes(elf: Elf, r: Reader): void {
  const regions = elf.sections.filter((s) => s.type === SHT.NOTE).map((s) => [s.offset, s.size] as const);
  if (!regions.length) for (const seg of elf.segments) if (seg.type === PT.NOTE) regions.push([seg.offset, seg.filesz]);
  for (const [start, size] of regions) {
    for (let at = start; at + 12 <= start + size; ) {
      const namesz = r.u32(at);
      const descsz = r.u32(at + 4);
      const type = r.u32(at + 8);
      const owner = r.cstr(at + 12, namesz);
      const descAt = at + 12 + ((namesz + 3) & ~3);
      const desc = elf.bytes.subarray(descAt, descAt + descsz);
      elf.notes.push({ owner, type, desc });
      at = descAt + ((descsz + 3) & ~3);
      if (owner === 'Android' && type === 1 && descsz >= 4) {
        elf.android = { api: r.u32(descAt) };
        if (descsz >= 4 + 64) elf.android.ndk = r.cstr(descAt + 4, 64);
        if (descsz >= 4 + 128) elf.android.build = r.cstr(descAt + 68, 64);
      } else if (owner === 'GNU' && type === 3) {
        elf.buildId = [...desc].map((b) => b.toString(16).padStart(2, '0')).join('');
      } else if (owner === 'GNU' && type === 5) {
        // Program properties: on AArch64, GNU_PROPERTY_AARCH64_FEATURE_1_AND says BTI and PAC.
        for (let p = descAt; p + 8 <= descAt + descsz; ) {
          const kind = r.u32(p);
          const length = r.u32(p + 4);
          if (kind === 0xc0000000 && length >= 4) {
            const bits = r.u32(p + 8);
            if (bits & 1) elf.features.push('BTI');
            if (bits & 2) elf.features.push('PAC');
            if (bits & 4) elf.features.push('GCS');
          }
          p += 8 + ((length + (elf.is64 ? 7 : 3)) & ~(elf.is64 ? 7 : 3));
        }
      }
    }
  }
}

/**
 * Function starts from the unwind tables: every function that can be unwound through has an entry,
 * stripped or not. ARM's EHABI index is a list of 31-bit offsets; the .eh_frame_hdr of other
 * machines is a sorted table of encoded addresses.
 */
function readUnwindTables(elf: Elf, r: Reader, offsetOf: (addr: number) => number): void {
  const starts = new Set<number>();
  const exidx = elf.sections.find((s) => s.type === SHT.ARM_EXIDX) ?? (() => {
    const seg = elf.segments.find((s) => s.type === 0x70000001);
    return seg ? ({ addr: seg.vaddr, offset: seg.offset, size: seg.filesz } as ElfSection) : undefined;
  })();
  if (exidx) {
    for (let i = 0; i + 8 <= exidx.size; i += 8) {
      const word = r.u32(exidx.offset + i);
      const prel31 = (word << 1) >> 1;
      starts.add(((exidx.addr + i + prel31) >>> 0) & ~1);
    }
  }
  const hdr = elf.sections.find((s) => s.name === '.eh_frame_hdr') ?? (() => {
    const seg = elf.segments.find((s) => s.type === PT.GNU_EH_FRAME);
    return seg ? ({ addr: seg.vaddr, offset: seg.offset, size: seg.filesz } as ElfSection) : undefined;
  })();
  if (hdr && r.u8(hdr.offset) === 1) {
    const base = hdr.offset;
    const framePtrEnc = r.u8(base + 1);
    const countEnc = r.u8(base + 2);
    const tableEnc = r.u8(base + 3);
    let p = base + 4;
    const read = (enc: number): number => {
      const at = p;
      let value: number;
      switch (enc & 0x0f) {
        case 0x00: value = r.word(at); p += elf.is64 ? 8 : 4; break;
        case 0x01: [value, p] = r.uleb(at); break;
        case 0x02: value = r.u16(at); p += 2; break;
        case 0x03: value = r.u32(at); p += 4; break;
        case 0x04: value = r.u64(at); p += 8; break;
        case 0x09: [value, p] = r.sleb(at); break;
        case 0x0a: value = (r.u16(at) << 16) >> 16; p += 2; break;
        case 0x0b: value = r.i32(at); p += 4; break;
        case 0x0c: value = r.i64(at); p += 8; break;
        default: return NaN;
      }
      if ((enc & 0x70) === 0x10) value += hdr.addr + (at - base);
      else if ((enc & 0x70) === 0x30) value += hdr.addr;
      return value;
    };
    if (framePtrEnc !== 0xff) read(framePtrEnc);
    const count = countEnc === 0xff ? 0 : read(countEnc);
    if (Number.isFinite(count) && tableEnc !== 0xff) {
      for (let i = 0; i < count && p < base + hdr.size; i++) {
        const start = read(tableEnc);
        read(tableEnc);
        if (Number.isFinite(start)) starts.add(start);
      }
    }
  }
  void offsetOf;
  elf.functionStarts.push(...starts);
}

function readInitArrays(elf: Elf, r: Reader, dyn: Map<number, number>, offsetOf: (addr: number) => number): void {
  const word = elf.is64 ? 8 : 4;
  const read = (addrTag: number, sizeTag: number): number[] => {
    if (!dyn.has(addrTag)) return [];
    const out: number[] = [];
    const addr = dyn.get(addrTag)!;
    for (let i = 0; i < (dyn.get(sizeTag) ?? 0); i += word) {
      const slot = addr + i;
      const value = elf.relative.get(slot) ?? r.word(offsetOf(slot));
      if (value && value !== -1 && value !== 0xffffffff) out.push(value);
    }
    return out;
  };
  // The pointers stay as stored: on ARM, bit 0 says the function is Thumb code.
  elf.initArray = read(25, 27);
  elf.finiArray = read(26, 28);
  for (const value of [...elf.initArray, ...elf.finiArray]) elf.functionStarts.push(elf.machine === EM.ARM ? value & ~1 : value);
}

const CPU_ARCH = ['Pre-v4', 'v4', 'v4T', 'v5T', 'v5TE', 'v5TEJ', 'v6', 'v6KZ', 'v6T2', 'v6K', 'v7', 'v6-M', 'v6S-M', 'v7E-M', 'v8-A', 'v8-R', 'v8-M.baseline', 'v8-M.mainline', 'v8.1-M.mainline', 'v9-A'];
const FP_ARCH = ['none', 'VFPv1', 'VFPv2', 'VFPv3', 'VFPv3-D16', 'VFPv4', 'VFPv4-D16', 'ARMv8 FP', 'ARMv8 FP-D16'];
const SIMD_ARCH = ['none', 'NEON', 'NEON with FMA', 'ARMv8 NEON', 'ARMv8.1 NEON'];

/**
 * The public "aeabi" attributes of .ARM.attributes: which architecture, FPU and SIMD unit the
 * code was built for, and how floating-point arguments are passed.
 */
function armAttributes(r: Reader, start: number, size: number): [string, string][] {
  const out: [string, string][] = [];
  if (r.u8(start) !== 0x41) return out; // 'A'
  let at = start + 1;
  while (at + 4 < start + size) {
    const length = r.u32(at);
    const vendor = r.cstr(at + 4, 32);
    const end = at + length;
    if (vendor === 'aeabi') {
      let p = at + 4 + vendor.length + 1;
      while (p < end) {
        const tag = r.u8(p);
        const subLength = r.u32(p + 1);
        const subEnd = p + subLength;
        if (tag === 1) {
          // Tag_File: tag/value pairs; the string-valued tags are 4, 5, 32, 65 and 67.
          let q = p + 5;
          while (q < subEnd) {
            let attr: number;
            [attr, q] = r.uleb(q);
            if (attr === 4 || attr === 5 || attr === 67 || attr === 65 || attr === 32) {
              const value = r.cstr(q, 256);
              q += value.length + 1;
              if (attr === 5) out.push(['CPU', value]);
              continue;
            }
            let value: number;
            [value, q] = r.uleb(q);
            if (attr === 6) out.push(['Architecture', CPU_ARCH[value] ?? `${value}`]);
            else if (attr === 7 && value) out.push(['Profile', String.fromCharCode(value)]);
            else if (attr === 8) out.push(['A32', value ? 'yes' : 'no']);
            else if (attr === 9) out.push(['Thumb', ['no', 'Thumb-1', 'Thumb-2'][value] ?? `${value}`]);
            else if (attr === 10) out.push(['FPU', FP_ARCH[value] ?? `${value}`]);
            else if (attr === 12) out.push(['SIMD', SIMD_ARCH[value] ?? `${value}`]);
            else if (attr === 28) out.push(['Float arguments', value === 1 ? 'in VFP registers (hard-float)' : 'in core registers (soft-float)']);
            else if (attr === 44) out.push(['Integer division', ['if v7-R/v7-M', 'not used', 'allowed'][value] ?? `${value}`]);
          }
        }
        if (subLength <= 0) break;
        p = subEnd;
      }
    }
    if (length <= 0) break;
    at = end;
  }
  return out;
}
