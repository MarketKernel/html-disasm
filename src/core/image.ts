/**
 * A program as the analysis needs it, whatever the container: its sections
 * (which are code, which hold C strings), the symbols it defines, what it
 * imports and exports, where functions start. A Mach-O file (src/core/macho.ts),
 * an ELF file (src/core/elf.ts) and a PE file (src/core/pe.ts) are each turned into one; the pages about
 * the container itself read the original, kept beside it.
 */

import { demangle, demangleUnprefixed, type Demangled } from './demangle';
import { isText, type DataAt, type StringRef } from './disassembly';
import { EM, SHF, SHT, STT, type CodeMark, type Elf } from './elf';
import { utf8 } from './bytes';
import type { MachO } from './macho';
import { parseObjc, type Objc } from './objc';
import { MACHINE, SECTION_FLAGS, type CodeKind, type Pe } from './pe';

export interface ImageSection {
  /** `__text`, `.text` */
  name: string;
  /** As the listing and the pages name it: `__TEXT,__text`, `.text`. */
  label: string;
  addr: number;
  size: number;
  /** Where its bytes are in the file; none for zero-fill sections. */
  offset: number;
  code: boolean;
  /** Only NUL-terminated strings: Mach-O's cstring sections, ELF's merged string sections. */
  cstrings: boolean;
  /** No bytes in the file (bss). */
  zerofill: boolean;
  /** Written at run time (data, relocated pointers): text found there is not taken for a literal. */
  writable?: boolean;
  /** A Mach-O __stubs section: the size of each stub. */
  stubSize?: number;
}

export interface ImageSymbol {
  name: string;
  addr: number;
  function: boolean;
  /** An AArch32 function in Thumb state. */
  thumb?: boolean;
  /** Bytes, when the file says (ELF symbols do). */
  size?: number;
}

export interface ImageImport {
  name: string;
  library: string;
  weak?: boolean;
  /** The symbol version an ELF import is bound to (LIBC). */
  version?: string;
}

export interface Image {
  format: 'macho' | 'elf' | 'pe';
  bytes: Uint8Array;
  /** arm64, arm64e, armv7 */
  arch: string;
  sections: ImageSection[];
  /** Symbols defined in the file, functions and data. */
  symbols: ImageSymbol[];
  exports: ImageSymbol[];
  imports: ImageImport[];
  libraries: string[];
  /** Code that stands for an imported function (a Mach-O stub) → its name. */
  stubs: Map<number, string>;
  /** A pointer slot holding an imported (or exported) symbol's address → its name. */
  slots: Map<number, string>;
  functionStarts: number[];
  entry?: number;
  /** ELF mapping symbols: where A32, T32 and data begin. */
  marks: CodeMark[];
  /** Where Thumb code starts, as a 32-bit Mach-O file's function starts say (with the low bit set). */
  thumb?: Set<number>;
  /** Data among the instructions that the file itself marks (a Mach-O file's LC_DATA_IN_CODE): jump tables, literal pools. */
  dataInCode?: { addr: number; length: number }[];
  /** A symbol name back to source: Mach-O names carry an extra leading underscore, ELF names do not. */
  demangle(raw: string): Demangled;
  macho?: MachO;
  /** Objective-C classes, methods and references of a Mach-O image. */
  objc?: Objc;
  elf?: Elf;
  pe?: Pe;
}

const isMachCode = (flags: number, sectname: string) => !!(flags & 0x80000000) || !!(flags & 0x400) || sectname === '__text';

export function fromMachO(m: MachO): Image {
  const sections: ImageSection[] = m.sections.map((s) => {
    const type = s.flags & 0xff;
    return {
      name: s.sectname,
      label: `${s.segname},${s.sectname}`,
      addr: s.addr,
      size: s.size,
      offset: s.offset,
      code: isMachCode(s.flags, s.sectname),
      cstrings: type === 2,
      zerofill: type === 1 || type === 0xc || type === 0x12 || !s.offset,
      ...(type === 8 && s.reserved2 ? { stubSize: s.reserved2 } : {}),
    };
  });
  const stubs = new Map<number, string>();
  const slots = new Map<number, string>();
  for (const [addr, name] of m.stubs) {
    const section = sections.find((s) => addr >= s.addr && addr < s.addr + s.size);
    if (section?.code) stubs.set(addr, name);
    else if (section) slots.set(addr, name.replace(/^_/, ''));
  }
  // N_SECT symbols: defined in a section of this file; in a code section, a function. On 32-bit
  // Arm, code is Thumb where N_ARM_THUMB_DEF (desc 8) says so, where an address has its low bit set
  // (an export, a method's code), or where the function starts (which keep that bit) say so.
  const arm = m.cputype === 12;
  const inCode = (addr: number) => sections.some((s) => s.code && addr >= s.addr && addr < s.addr + s.size);
  const thumb = new Set(arm ? m.functionStarts.filter((a) => a & 1).map((a) => a & ~1) : []);
  const thumbAt = (addr: number, flagged = false) => (arm && (flagged || !!(addr & 1) || thumb.has(addr & ~1)) ? { thumb: true } : {});
  const symbols: ImageSymbol[] = m.symbols
    .filter((s) => !s.undefined && s.name && (s.type & 0x0e) === 0x0e)
    .map((s) => ({ name: s.name, addr: s.addr, function: inCode(s.addr), ...thumbAt(s.addr, !!(s.desc & 8)) }));
  const exports: ImageSymbol[] = m.exports.map((e) => {
    const addr = arm ? e.addr & ~1 : e.addr;
    return { name: e.name, addr, function: inCode(addr), ...thumbAt(e.addr) };
  });
  const entry = m.entry !== undefined && thumb.has(m.entry & ~1) ? m.entry | 1 : m.entry;
  // A stripped program still names its Objective-C methods and its objc_msgSend stubs, as the linker did.
  const objc = parseObjc(m);
  if (objc) {
    const named = new Set(symbols.map((s) => s.addr));
    for (const [imp, name] of objc.methods) {
      const addr = arm ? imp & ~1 : imp;
      if (!named.has(addr)) symbols.push({ name, addr, function: true, ...thumbAt(imp) });
    }
    for (const [addr, selector] of objc.stubs) if (!named.has(addr)) symbols.push({ name: `_objc_msgSend$${selector}`, addr, function: true });
  }
  return {
    format: 'macho',
    bytes: m.bytes,
    arch: m.arch,
    sections,
    symbols,
    exports,
    imports: m.imports.map((i) => ({ name: i.name, library: i.library, weak: i.weak })),
    libraries: m.libraries,
    stubs,
    slots,
    functionStarts: arm ? m.functionStarts.map((a) => a & ~1) : m.functionStarts,
    entry,
    marks: [],
    ...(arm ? { thumb, dataInCode: m.dataInCode.map((d) => ({ addr: d.addr, length: d.length })) } : {}),
    demangle,
    macho: m,
    ...(objc ? { objc } : {}),
  };
}

export function fromElf(e: Elf): Image {
  const sections: ImageSection[] = e.sections
    .filter((s) => s.flags & SHF.ALLOC && s.size && (s.addr || e.type !== 1))
    .map((s) => ({
      name: s.name,
      label: s.name,
      addr: s.addr,
      size: s.size,
      offset: s.type === SHT.NOBITS ? 0 : s.offset,
      code: !!(s.flags & SHF.EXEC),
      cstrings: !!(s.flags & SHF.STRINGS) && s.entsize <= 1,
      zerofill: s.type === SHT.NOBITS,
      writable: !!(s.flags & SHF.WRITE),
    }));
  const isFunction = (type: number) => type === STT.FUNC || type === STT.GNU_IFUNC;
  const seen = new Set<string>();
  const symbols: ImageSymbol[] = [];
  for (const sym of [...e.symtab, ...e.dynsyms]) {
    if (!sym.name || sym.shndx === 0 || sym.type === STT.SECTION || sym.type === STT.FILE || /^\$[atxd](?:\.|$)/.test(sym.name)) continue;
    const key = `${sym.addr}:${sym.name}`;
    if (seen.has(key)) continue;
    seen.add(key);
    symbols.push({ name: sym.name, addr: sym.addr, function: isFunction(sym.type), ...(sym.thumb ? { thumb: true } : {}), ...(sym.size ? { size: sym.size } : {}) });
  }
  return {
    format: 'elf',
    bytes: e.bytes,
    arch: e.arch,
    sections,
    symbols,
    exports: e.exports.map((x) => ({ name: x.name, addr: x.addr, function: isFunction(x.type), ...(x.thumb ? { thumb: true } : {}) })),
    imports: e.imports.map((i) => ({ name: i.name, library: i.library, weak: i.weak, version: i.version })),
    libraries: e.needed,
    stubs: new Map(),
    slots: new Map(e.slots),
    functionStarts: e.functionStarts,
    entry: e.entry || undefined,
    marks: e.marks,
    demangle: demangleUnprefixed,
    elf: e,
  };
}

/**
 * Which code of a hybrid Windows program (ARM64EC, ARM64X) the image holds: its Arm code — arm64
 * and ARM64EC, which one analysis reads — or its x64 code. The other kind is left as data.
 */
export type PeView = 'arm' | 'x64';

const VIEW_KINDS: Record<PeView, CodeKind[]> = { arm: ['arm64', 'arm64ec'], x64: ['x64'] };
const KIND_LABELS: Record<CodeKind, string> = { arm64: 'ARM64', arm64ec: 'ARM64EC', x64: 'x64' };

export function fromPe(native: Pe, view: PeView = 'arm'): Image {
  const hybrid = native.hybrid;
  // An ARM64X program's x64 code is described by the view an x64 process gets: its exports and imports.
  const p = hybrid && view === 'x64' && hybrid.ec ? hybrid.ec : native;
  const pieces = (s: Pe['sections'][number], addr: number, size: number): { addr: number; size: number; kind?: CodeKind }[] => {
    if (!hybrid) return [{ addr, size }];
    const out: { addr: number; size: number; kind?: CodeKind }[] = [];
    let at = addr;
    for (const r of [...hybrid.ranges].sort((a, b) => a.addr - b.addr)) {
      const from = Math.max(r.addr, addr);
      const to = Math.min(r.addr + r.size, addr + size);
      if (from >= to) continue;
      if (from > at) out.push({ addr: at, size: from - at });
      out.push({ addr: from, size: to - from, kind: r.kind });
      at = to;
    }
    if (at < addr + size) out.push({ addr: at, size: addr + size - at });
    return s.flags & (SECTION_FLAGS.CODE | SECTION_FLAGS.EXECUTE) ? out : [{ addr, size }];
  };
  const sections: ImageSection[] = native.sections.flatMap((s) => {
    const inFile = s.rawSize > 0;
    // Bytes past the end of the raw data are zero; only what the file holds is read as the section.
    const size = inFile ? Math.min(s.virtualSize || s.rawSize, s.rawSize) : s.virtualSize;
    const addr = native.imageBase + s.rva;
    const code = !!(s.flags & (SECTION_FLAGS.CODE | SECTION_FLAGS.EXECUTE));
    return pieces(s, addr, size).map((piece) => ({
      name: s.name,
      // A hybrid program's code section is cut by the code map; each piece says what it holds.
      label: piece.kind ? `${s.name} (${KIND_LABELS[piece.kind]})` : s.name,
      addr: piece.addr,
      size: piece.size,
      offset: inFile ? s.rawOffset + (piece.addr - addr) : 0,
      code: hybrid ? !!piece.kind && VIEW_KINDS[view].includes(piece.kind) : code,
      cstrings: false,
      zerofill: !inFile,
      writable: !!(s.flags & SECTION_FLAGS.WRITE),
    }));
  });
  const inCode = (addr: number) => sections.some((s) => s.code && addr >= s.addr && addr < s.addr + s.size);
  // Windows on 32-bit Arm runs Thumb code only; a code address there has its low bit set.
  const thumb = p.machine === MACHINE.ARMNT;
  const code = (addr: number) => (thumb && inCode(addr & ~1) ? addr & ~1 : addr);
  return {
    format: 'pe',
    bytes: p.bytes,
    arch: hybrid ? (view === 'x64' ? 'x86_64' : hybrid.ranges.some((r) => r.kind === 'arm64') ? 'arm64x' : 'arm64ec') : p.arch,
    sections,
    symbols: [
      ...p.symbols.map((s) => ({ name: s.name, addr: code(s.addr), function: s.function && inCode(code(s.addr)), ...(thumb ? { thumb: true } : {}) })),
      // An x64 entry point of an ARM64EC function names the function itself in the Arm view.
      ...(hybrid && view === 'arm' ? [...native.exports, ...(hybrid.ec?.exports ?? [])].flatMap((e) => {
        const to = hybrid.redirections.get(e.addr);
        return to !== undefined && inCode(to) ? [{ name: e.name, addr: to, function: true }] : [];
      }) : []),
    ],
    exports: [...p.exports, ...(hybrid && view === 'arm' && hybrid.ec ? hybrid.ec.exports : [])]
      .filter((e) => !e.forwarder && (!hybrid || inCode(e.addr)))
      .map((e) => ({ name: e.name, addr: code(e.addr), function: inCode(code(e.addr)), ...(thumb ? { thumb: true } : {}) })),
    imports: p.imports.map((i) => ({ name: i.name, library: i.library })),
    libraries: p.libraries,
    stubs: new Map(),
    slots: new Map([...(hybrid?.ec && view === 'arm' ? hybrid.ec.imports : []), ...p.imports].map((i) => [i.slot, i.name])),
    functionStarts: [...p.functionStarts, ...p.tlsCallbacks.map(code), ...(hybrid && view === 'arm' ? hybrid.armStarts : [])].filter((a) => !hybrid || inCode(a)),
    entry: p.entry !== undefined && (!hybrid || inCode(p.entry)) ? p.entry : undefined,
    marks: thumb ? sections.filter((s) => s.code).map((s) => ({ addr: s.addr, kind: 't' as const })) : [],
    demangle: demangleUnprefixed,
    pe: p,
  };
}

/**
 * How an ELF PLT stub is listed: under the name of the import it calls, or —
 * when it calls a function the library defines itself, as a library calls
 * its own exported functions — as `name@plt`, not an import.
 */
/** The raw name the entry point goes by when no symbol names it. */
export function entryName(image: Image): string {
  if (image.format === 'macho') return image.macho?.entryKind === 'thread' ? 'start' : '_main';
  return image.format === 'pe' ? 'entry' : '_start';
}

export function stubFunction(image: Image, name: string): { raw: string; kind: 'import' | 'symbol' } {
  return image.imports.some((i) => i.name === name) ? { raw: name, kind: 'import' } : { raw: `${name}@plt`, kind: 'symbol' };
}

/** A function's names from its symbol; `@plt` stays after the demangled name. */
export function functionNames(image: Image, raw: string): Demangled {
  if (!raw.endsWith('@plt')) return image.demangle(raw);
  const d = image.demangle(raw.slice(0, -4));
  return { ...d, full: `${d.full}@plt`, short: `${d.short}@plt` };
}

/** Whether an image holds AArch32 code. */
export const isArm32 = (image: Image): boolean => image.elf?.machine === EM.ARM;

/**
 * Objective-C data that code loads: a selector reference (`selref.initWithName:`), a class
 * reference (`classref.NSString`), a constant NSString.
 */
export function objcDataAt(image: Image, addr: number): DataAt {
  const objc = image.objc;
  if (!objc) return undefined;
  const selector = objc.selrefs.get(addr);
  if (selector !== undefined) return { kind: 'symbol', name: `selref.${selector}` };
  const cls = objc.classrefs.get(addr);
  if (cls !== undefined) return { kind: 'symbol', name: `classref.${cls}` };
  const text = objc.cfstrings.get(addr);
  if (text !== undefined) return { kind: 'string', text, objc: true };
  return undefined;
}

export function sectionOf(image: Image, addr: number): ImageSection | undefined {
  for (const section of image.sections) if (addr >= section.addr && addr < section.addr + section.size) return section;
  return undefined;
}

/** The file bytes behind a virtual address (none for zero-fill sections). */
export function bytesAt(image: Image, addr: number, length: number): Uint8Array | undefined {
  const section = sectionOf(image, addr);
  if (!section || section.zerofill || !section.offset) return undefined;
  const at = section.offset + (addr - section.addr);
  return image.bytes.subarray(at, Math.min(at + length, section.offset + section.size));
}

/** A little-endian value of 1, 2, 4 or 8 bytes at an address in the file. */
export function valueAt(image: Image, addr: number, size: 1 | 2 | 4 | 8, signed = false): number | undefined {
  const b = bytesAt(image, addr, size);
  if (!b || b.length < size) return undefined;
  const view = new DataView(b.buffer, b.byteOffset, size);
  if (size === 1) return signed ? view.getInt8(0) : view.getUint8(0);
  if (size === 2) return signed ? view.getInt16(0, true) : view.getUint16(0, true);
  if (size === 4) return signed ? view.getInt32(0, true) : view.getUint32(0, true);
  return Number(signed ? view.getBigInt64(0, true) : view.getBigUint64(0, true));
}

/** What a pointer-sized slot holds once the program is loaded: the target of its ELF relative relocation, or its bytes. */
export function slotValue(image: Image, addr: number, size: 4 | 8): number | undefined {
  return image.elf?.relative.get(addr) ?? valueAt(image, addr, size);
}

/**
 * A string that starts at an address in data: a C string, or — when the code
 * says how long it is (`known`, from Rust's pointer-and-length pairs) — a run
 * of text without a NUL. Short runs are not taken for strings.
 */
export function textAt(image: Image, addr: number, known?: number): StringRef | undefined {
  const section = sectionOf(image, addr);
  if (!section || !section.offset || section.code || section.zerofill || section.writable) return undefined;
  const at = section.offset + (addr - section.addr);
  const bytes = image.bytes.subarray(at, Math.min(at + 96, section.offset + section.size));
  let end = 0;
  const limit = known !== undefined ? Math.min(known, bytes.length) : bytes.length;
  while (end < limit && isText(bytes[end]!)) end++;
  const text = strictUtf8(bytes.subarray(0, end));
  if (text === undefined) return undefined;
  if (known !== undefined && end === known && known > 0) return { addr, text, section: section.name, kind: 'const' };
  const terminated = bytes[end] === 0;
  if (end < (terminated ? 2 : 6)) return undefined;
  return { addr, text, section: section.name, kind: terminated ? 'cstring' : 'const' };
}

const strict = new TextDecoder('utf-8', { fatal: true });
const strictUtf8 = (bytes: Uint8Array): string | undefined => {
  try {
    return strict.decode(bytes);
  } catch {
    return undefined;
  }
};

/**
 * Every string of the sections that hold only NUL-terminated strings. A Mach-O
 * __cstring section holds nothing else; an ELF linker may merge other read-only
 * constants into a section marked for strings, so there a string must be text
 * through and through, valid UTF-8 and at least two characters long.
 */
export function cstrings(image: Image): StringRef[] {
  const out: StringRef[] = [];
  const elf = image.format === 'elf';
  for (const section of image.sections) {
    if (!section.cstrings || !section.offset) continue;
    const bytes = image.bytes.subarray(section.offset, section.offset + section.size);
    let start = 0;
    for (let i = 0; i < bytes.length; i++) {
      if (bytes[i] !== 0) continue;
      if (i > start) {
        const run = bytes.subarray(start, i);
        const text = elf ? (i - start >= 2 && run.every(isText) ? strictUtf8(run) : undefined) : utf8(run);
        if (text !== undefined) out.push({ addr: section.addr + start, text, section: section.name, kind: 'cstring' });
      }
      start = i + 1;
    }
  }
  return out;
}

/** Android's version names by API level, for what a library says it needs. */
const ANDROID_VERSIONS: Record<number, string> = {
  14: '4.0', 15: '4.0.3', 16: '4.1', 17: '4.2', 18: '4.3', 19: '4.4', 20: '4.4W', 21: '5.0', 22: '5.1', 23: '6.0', 24: '7.0', 25: '7.1', 26: '8.0',
  27: '8.1', 28: '9', 29: '10', 30: '11', 31: '12', 32: '12L', 33: '13', 34: '14', 35: '15', 36: '16',
};

export const androidVersion = (api: number): string | undefined => ANDROID_VERSIONS[api];

export interface Platform {
  os: 'android' | 'linux' | 'apple' | 'windows';
  /** As the file chip shows it: `Android 5.0+`, `Linux`, `macOS 14.0+`. */
  label: string;
}

/**
 * The system a program is built for. An Android library says so in its
 * `.note.android.ident` (the NDK puts it there, with the lowest API level it
 * runs on); without the note, Bionic gives it away — its symbol versions are
 * LIBC, LIBC_N…, and programs are loaded by /system/bin/linker — while glibc's
 * are GLIBC_2.x. A Mach-O file names its platform in its build version.
 */
export function platformOf(image: Image): Platform | undefined {
  const build = image.macho?.build;
  if (build) return { os: 'apple', label: `${build.platform} ${build.minos}+` };
  if (image.pe) return { os: 'windows', label: windowsLabel(image.pe) };
  const elf = image.elf;
  if (!elf) return undefined;
  if (elf.android) {
    const version = androidVersion(elf.android.api);
    return { os: 'android', label: version ? `Android ${version}+` : `Android API ${elf.android.api}+` };
  }
  const versions = new Set(elf.imports.map((i) => i.version ?? ''));
  if (elf.interpreter?.startsWith('/system/bin/linker') || [...versions].some((v) => /^LIBC(_[A-Z])?$/.test(v))) return { os: 'android', label: 'Android' };
  if (elf.interpreter?.includes('ld-linux') || [...versions].some((v) => v.startsWith('GLIBC_')) || elf.osabi === 3) return { os: 'linux', label: 'Linux' };
  return undefined;
}

/** Windows versions by the version a PE file says it needs. */
const WINDOWS_VERSIONS: Record<string, string> = { '5.0': '2000', '5.1': 'XP', '5.2': 'XP x64', '6.0': 'Vista', '6.1': '7', '6.2': '8', '6.3': '8.1', '10.0': '10' };

/** `Windows 10+`, `Windows 7+`: the lowest version the subsystem version admits. */
function windowsLabel(p: Pe): string {
  const name = WINDOWS_VERSIONS[p.subsystemVersion] ?? WINDOWS_VERSIONS[p.osVersion];
  return name ? `Windows ${name}+` : 'Windows';
}

/** The architecture as the platform names it: Android's ABIs are arm64-v8a, armeabi-v7a, x86_64 and x86. */
export function abiOf(image: Image): string {
  if (platformOf(image)?.os === 'android') {
    if (image.elf?.machine === EM.AARCH64) return 'arm64-v8a';
    if (image.elf?.machine === EM.ARM) return 'armeabi-v7a';
    if (image.elf?.machine === EM.X86_64) return 'x86_64';
    if (image.elf?.machine === EM.X86) return 'x86';
  }
  return image.arch;
}
