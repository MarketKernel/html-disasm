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
 * The reading runs in the core (crates/core/src/elf.rs); what is here turns
 * its answer into these objects. Nothing here touches the DOM, so the tests
 * run it in Node.
 */

import { engine } from './engine/engine';
import { t } from './i18n';

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

/** An ELF file's reading as the core writes it (`elf_json` in crates/wasm/src/containers.rs). */
interface CoreElf {
  error?: 'notElf' | 'unknownClass' | 'bigEndian';
  is64: boolean;
  machine: number;
  machineName: string;
  arch: string;
  type: number;
  typeName: string;
  osabi: number;
  flags: number;
  flagNames: string[];
  entry: number;
  /** type, flags, offset, vaddr, filesz, memsz, align */
  segments: [number, number, number, number, number, number, number][];
  /** name, index, type, flags, addr, offset, size, link, info, align, entsize */
  sections: [string, number, number, number, number, number, number, number, number, number, number][];
  sectionless: boolean;
  /** tag, name, value, text */
  dynamic: [number, string, number, string][];
  needed: string[];
  soname: string | null;
  runpath: string[];
  interpreter: string | null;
  dynsyms: CoreSymbol[];
  symtab: CoreSymbol[];
  /** name, library, version, weak, type */
  imports: [string, string, string | null, number, number][];
  /** name, addr, size, type, thumb, version */
  exports: [string, number, number, number, number, string | null][];
  /** address, kind… */
  marks: (number | CodeMark['kind'])[];
  /** offset, type, sym, addend… */
  relocations: number[];
  relocationCounts: [string, number][];
  relocationFormats: string[];
  slots: [number, string][];
  /** slot, value… */
  relative: number[];
  functionStarts: number[];
  initArray: number[];
  finiArray: number[];
  /** owner, type, where its description starts and ends in the file */
  notes: [string, number, number, number][];
  android?: Elf['android'];
  buildId?: string;
  features: string[];
  attributes: [string, string][];
  comment: string[];
  debugInfo: boolean;
}

/** name, addr, size, type, bind, visibility, shndx, thumb, version, library */
type CoreSymbol = [string, number, number, number, number, number, number, number, string | null, string | null];

function symbolOf([name, addr, size, type, bind, visibility, shndx, thumb, version, library]: CoreSymbol): ElfSymbol {
  const sym: ElfSymbol = { name, addr, size, type, bind, visibility, shndx };
  if (thumb) sym.thumb = true;
  if (version !== null) {
    sym.version = version;
    if (library) sym.library = library;
  }
  return sym;
}

/** Opens an ELF file. The core must be loaded (`loadEngine`). */
export function parseElf(file: Uint8Array): Elf {
  const c = engine().containerParse<CoreElf>('elf', file);
  switch (c.error) {
    case 'notElf':
      throw new NotElf(t('open', 'Not an ELF file (no \\x7fELF signature).'));
    case 'unknownClass':
      throw new NotElf(t('open', 'The ELF file has an unknown class.'));
    case 'bigEndian':
      throw new NotElf(t('open', 'This ELF file is big-endian; only little-endian ones are supported.'));
  }
  const pairs = <V>(flat: (number | V)[]): [number, V][] => {
    const out: [number, V][] = [];
    for (let k = 0; k + 1 < flat.length; k += 2) out.push([flat[k] as number, flat[k + 1] as V]);
    return out;
  };
  const relocations: Relocation[] = [];
  for (let k = 0; k + 3 < c.relocations.length; k += 4) relocations.push({ offset: c.relocations[k]!, type: c.relocations[k + 1]!, sym: c.relocations[k + 2]!, addend: c.relocations[k + 3]! });
  const elf: Elf = {
    bytes: file,
    is64: c.is64,
    machine: c.machine,
    machineName: c.machineName,
    arch: c.arch,
    type: c.type,
    typeName: c.typeName,
    osabi: c.osabi,
    flags: c.flags,
    flagNames: c.flagNames,
    entry: c.entry,
    segments: c.segments.map(([type, flags, offset, vaddr, filesz, memsz, align]) => ({ type, flags, offset, vaddr, filesz, memsz, align })),
    sections: c.sections.map(([name, index, type, flags, addr, offset, size, link, info, align, entsize]) => ({ index, name, type, flags, addr, offset, size, link, info, align, entsize })),
    sectionless: c.sectionless,
    dynamic: c.dynamic.map(([tag, name, value, text]) => ({ tag, name, value, text })),
    needed: c.needed,
    runpath: c.runpath,
    dynsyms: c.dynsyms.map(symbolOf),
    symtab: c.symtab.map(symbolOf),
    imports: c.imports.map(([name, library, version, weak, type]) => ({ name, library, version: version ?? undefined, weak: !!weak, type })),
    exports: c.exports.map(([name, addr, size, type, thumb, version]) => ({ name, addr, size, type, ...(thumb ? { thumb: true } : {}), ...(version !== null ? { version } : {}) })),
    marks: pairs<CodeMark['kind']>(c.marks).map(([addr, kind]) => ({ addr, kind })),
    relocations,
    relocationCounts: new Map(c.relocationCounts),
    relocationFormats: c.relocationFormats,
    slots: new Map(c.slots),
    relative: new Map(pairs<number>(c.relative)),
    functionStarts: c.functionStarts,
    initArray: c.initArray,
    finiArray: c.finiArray,
    notes: c.notes.map(([owner, type, start, end]) => ({ owner, type, desc: file.subarray(start, end) })),
    features: c.features,
    attributes: c.attributes,
    comment: c.comment,
    debugInfo: c.debugInfo,
  };
  if (c.soname !== null) elf.soname = c.soname;
  if (c.interpreter !== null) elf.interpreter = c.interpreter;
  if (c.android) elf.android = c.android;
  if (c.buildId !== undefined) elf.buildId = c.buildId;
  return elf;
}
