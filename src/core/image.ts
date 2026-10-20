/**
 * A program as the analysis needs it, whatever the container: its sections
 * (which are code, which hold C strings), the symbols it defines, what it
 * imports and exports, where functions start. The core builds it from a
 * Mach-O, ELF or PE file (crates/core/src/native/image.rs) — the same image
 * its analysis reads — and the page takes it once; the pages about the
 * container itself read the container's reading (macho.ts, elf.ts, pe.ts),
 * kept beside it.
 */

import { demangle, demangleAll, demangleUnprefixed, type Demangled } from './demangle';
import { isText, type DataAt, type StringRef } from './disassembly';
import { EM, type CodeMark, type Elf } from './elf';
import { engine } from './engine/engine';
import type { MachO } from './macho';
import type { Objc, ObjcClass } from './objc';
import type { Pe } from './pe';

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
  /** Reads many names at once (a page of imports), so that `demangle` then has them. */
  demangleAll(raws: Iterable<string>): void;
  /** The file the image was read from, for the core to read again: a Mach-O slice, an ELF file, a PE file and which of its code. */
  source: { container: 'macho' | 'elf' | 'pe'; file: Uint8Array; view?: PeView };
  macho?: MachO;
  /** Objective-C classes, methods and references of a Mach-O image. */
  objc?: Objc;
  elf?: Elf;
  pe?: Pe;
}

/** A native program's image as the core writes it (`native_image` in crates/wasm/src/native_image.rs). */
interface CoreImage {
  arch: string;
  sections: (Omit<ImageSection, 'stubSize'> & { stubSize: number | null })[];
  /** name, address, function, Thumb, size */
  symbols: [string, number, boolean, boolean, number | null][];
  exports: [string, number, boolean, boolean, number | null][];
  /** name, library, weak, version */
  imports: [string, string, boolean, string | null][];
  stubs: [number, string][];
  slots: [number, string][];
  functionStarts: number[];
  entry: number | null;
  marks: [number, CodeMark['kind']][];
  thumb: number[] | null;
  dataInCode: [number, number][] | null;
  objc: (Omit<Objc, 'classes' | 'categories' | 'selrefs' | 'classrefs' | 'cfstrings' | 'methods' | 'stubs'> & {
    classes: CoreClass[];
    categories: CoreClass[];
    selrefs: [number, string][];
    classrefs: [number, string][];
    cfstrings: [number, string][];
    methods: [number, string][];
    stubs: [number, string][];
  }) | null;
}

interface CoreClass {
  name: string;
  addr: number;
  swift: string | null;
  superclass: string | null;
  category: string | null;
  /** name, selector, code, class method */
  methods: [string, string, number, boolean][];
}

const symbolOf = ([name, addr, fn, thumb, size]: CoreImage['symbols'][number]): ImageSymbol => ({ name, addr, function: fn, ...(thumb ? { thumb: true } : {}), ...(size !== null ? { size } : {}) });

const classOf = (c: CoreClass): ObjcClass => ({
  name: c.name,
  ...(c.swift !== null ? { swift: c.swift } : {}),
  addr: c.addr,
  ...(c.superclass !== null ? { superclass: c.superclass } : {}),
  ...(c.category !== null ? { category: c.category } : {}),
  methods: c.methods.map(([name, selector, imp, classMethod]) => ({ name, selector, imp, classMethod })),
});

/**
 * The image the core builds of a program — the one its analysis reads (crates/core/src/native/image.rs):
 * the sections, symbols, imports, exports, stubs and slots, where functions start, and the
 * Objective-C metadata of a Mach-O image. `container` says which: 0 a Mach-O slice, 1 ELF, 2 a PE
 * file's Arm code, 3 its x64 code.
 */
function coreImage(file: Uint8Array, container: number): CoreImage {
  const image = engine().nativeImage<CoreImage>(file, container);
  if (!image) throw new Error('The core could not read the program');
  return image;
}

/** The parts every container's image has, from the core's. */
function common(c: CoreImage): Pick<Image, 'arch' | 'sections' | 'symbols' | 'exports' | 'imports' | 'stubs' | 'slots' | 'functionStarts' | 'entry' | 'marks'> {
  return {
    arch: c.arch,
    sections: c.sections.map(({ stubSize, ...s }) => ({ ...s, ...(stubSize !== null ? { stubSize } : {}) })),
    symbols: c.symbols.map(symbolOf),
    exports: c.exports.map(symbolOf),
    imports: c.imports.map(([name, library, weak, version]) => ({ name, library, ...(weak ? { weak } : {}), ...(version !== null ? { version } : {}) })),
    stubs: new Map(c.stubs),
    slots: new Map(c.slots),
    functionStarts: c.functionStarts,
    ...(c.entry !== null ? { entry: c.entry } : {}),
    marks: c.marks.map(([addr, kind]) => ({ addr, kind })),
  };
}

export function fromMachO(m: MachO): Image {
  const c = coreImage(m.bytes, 0);
  const objc = c.objc;
  return {
    format: 'macho',
    bytes: m.bytes,
    ...common(c),
    // The imports as the container's reading lists them: by name.
    imports: m.imports.map((i) => ({ name: i.name, library: i.library, weak: i.weak })),
    libraries: m.libraries,
    ...(c.thumb ? { thumb: new Set(c.thumb) } : {}),
    ...(c.dataInCode ? { dataInCode: c.dataInCode.map(([addr, length]) => ({ addr, length })) } : {}),
    demangle,
    demangleAll: (raws) => demangleAll(raws, false),
    source: { container: 'macho', file: m.bytes },
    macho: m,
    ...(objc
      ? {
          objc: {
            classes: objc.classes.map(classOf),
            categories: objc.categories.map(classOf),
            protocols: objc.protocols,
            selrefs: new Map(objc.selrefs),
            classrefs: new Map(objc.classrefs),
            cfstrings: new Map(objc.cfstrings),
            methods: new Map(objc.methods),
            stubs: new Map(objc.stubs),
          },
        }
      : {}),
  };
}

export function fromElf(e: Elf): Image {
  const c = coreImage(e.bytes, 1);
  return {
    format: 'elf',
    bytes: e.bytes,
    ...common(c),
    libraries: e.needed,
    demangle: demangleUnprefixed,
    demangleAll: (raws) => demangleAll(raws, true),
    source: { container: 'elf', file: e.bytes },
    elf: e,
  };
}

/**
 * Which code of a hybrid Windows program (ARM64EC, ARM64X) the image holds: its Arm code — arm64
 * and ARM64EC, which one analysis reads — or its x64 code. The other kind is left as data.
 */
export type PeView = 'arm' | 'x64';

export function fromPe(native: Pe, view: PeView = 'arm'): Image {
  // An ARM64X program's x64 code is described by the view an x64 process gets: its exports and imports, its bytes.
  const p = native.hybrid && view === 'x64' && native.hybrid.ec ? native.hybrid.ec : native;
  const c = coreImage(native.bytes, view === 'x64' ? 3 : 2);
  return {
    format: 'pe',
    bytes: p.bytes,
    ...common(c),
    libraries: p.libraries,
    demangle: demangleUnprefixed,
    demangleAll: (raws) => demangleAll(raws, true),
    source: { container: 'pe', file: native.bytes, view },
    pe: p,
  };
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
