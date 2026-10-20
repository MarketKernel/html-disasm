/**
 * A Mach-O reader: everything about a macOS program that is not its code.
 *
 * 64-bit files, and the 32-bit ones of old macOS (i386) and iOS (armv7)
 * programs, whose headers, segments, symbols and pointers are narrower and
 * whose entry point may be the thread state of LC_UNIXTHREAD rather than
 * LC_MAIN. Universal ("fat") files are opened at their arm64 slice. From the load
 * commands come the segments and sections, the symbol table, the libraries,
 * the entry point, the build and source versions, the UUID, the code
 * signature (with its identifier, team and entitlements), the function starts
 * and the data-in-code ranges. Imported functions are named twice over: the
 * classic way, through the indirect symbol table that __stubs and __got point
 * into, and through the dyld bind opcodes or, in newer binaries, the chained
 * fixups — whichever the file has. Exported symbols come from the export trie.
 *
 * The reading runs in the core (crates/core/src/macho.rs); what is here
 * turns its answer into these objects. Nothing here touches the DOM, so the
 * tests run it in Node.
 */

import { engine } from './engine/engine';
import { t } from './i18n';

export interface Section {
  segname: string;
  sectname: string;
  addr: number;
  size: number;
  offset: number;
  align: number;
  flags: number;
  reserved1: number;
  reserved2: number;
}

export interface Segment {
  name: string;
  vmaddr: number;
  vmsize: number;
  fileoff: number;
  filesize: number;
  maxprot: number;
  initprot: number;
  sections: Section[];
}

export interface MachSymbol {
  name: string;
  addr: number;
  type: number;
  sect: number;
  desc: number;
  external: boolean;
  undefined: boolean;
}

export interface Import {
  name: string;
  library: string;
  /** Where the pointer to it lives (a GOT or lazy pointer slot), when known. */
  slot?: number;
  weak?: boolean;
}

export interface ExportedSymbol {
  name: string;
  addr: number;
  flags: number;
}

export interface LoadCommand {
  cmd: number;
  name: string;
  size: number;
  offset: number;
  /** One line about what it says. */
  summary: string;
}

export interface CodeSignature {
  identifier?: string;
  teamId?: string;
  hashType?: string;
  flags?: number;
  entitlements?: string;
  pages?: number;
}

export interface MachO {
  /** The architecture slices of a universal file; one entry for a thin file. */
  arches: { name: string; offset: number; size: number }[];
  /** The bytes of the opened slice. */
  bytes: Uint8Array;
  cputype: number;
  cpusubtype: number;
  arch: string;
  /** 64-bit (0xfeedfacf), or 32-bit (0xfeedface): the size of pointers and of the structures that hold them. */
  is64: boolean;
  filetype: number;
  fileTypeName: string;
  flags: number;
  flagNames: string[];
  commands: LoadCommand[];
  segments: Segment[];
  sections: Section[];
  symbols: MachSymbol[];
  libraries: string[];
  imports: Import[];
  exports: ExportedSymbol[];
  /** Address of a stub (or GOT slot, or lazy pointer) → the imported name. */
  stubs: Map<number, string>;
  /** A pointer dyld rebases through a fixup chain → the address it holds. */
  rebases: Map<number, number>;
  functionStarts: number[];
  dataInCode: { addr: number; length: number; kind: number }[];
  entry?: number;
  /** Where the entry point comes from: LC_MAIN (it is main) or the thread state of LC_UNIXTHREAD (crt1's start). */
  entryKind?: 'main' | 'thread';
  uuid?: string;
  build?: { platform: string; minos: string; sdk: string; tools: string[] };
  sourceVersion?: string;
  dylinker?: string;
  rpaths: string[];
  installName?: string;
  signature?: CodeSignature;
  encrypted?: boolean;
  /** LC_ENCRYPTION_INFO: the file range (from the slice's start) that the App Store encrypted, and whether it still is (id 0: decrypted). */
  encryption?: { offset: number; size: number; id: number };
  /** Text-segment base: addresses minus it are offsets into the slice. */
  base: number;
  /** Where the opened slice starts in the file (0 for a thin file). */
  sliceOffset: number;
  /** LC_CODE_SIGNATURE: where the signature is in the slice, and the room it has. */
  signatureAt?: { offset: number; size: number };
}

/** A Mach-O file's reading as the core writes it (`macho_json` in crates/wasm/src/containers.rs). */
interface CoreMachO {
  error?: 'tooSmall' | 'javaClass' | 'noArches' | 'notMachO' | 'outOfBounds';
  arches: MachO['arches'];
  slice: [number, number];
  cputype: number;
  cpusubtype: number;
  arch: string;
  is64: boolean;
  filetype: number;
  fileTypeName: string;
  flags: number;
  flagNames: string[];
  commands: LoadCommand[];
  sections: Section[];
  segments: (Omit<Segment, 'sections'> & { sections: number[] })[];
  /** name, address, type, section, desc */
  symbols: [string, number, number, number, number][];
  libraries: string[];
  /** name, library, slot (null: none), weak */
  imports: [string, string, number | null, number][];
  exports: [string, number, number][];
  stubs: [number, string][];
  /** address, target, address, target… */
  rebases: number[];
  functionStarts: number[];
  /** address, length, kind… */
  dataInCode: number[];
  rpaths: string[];
  base: number;
  sliceOffset: number;
  entry?: number;
  entryKind?: 'main' | 'thread';
  uuid?: string;
  build?: MachO['build'];
  sourceVersion?: string;
  dylinker?: string;
  installName?: string;
  signature?: CodeSignature;
  encrypted?: boolean;
  encryption?: MachO['encryption'];
  signatureAt?: MachO['signatureAt'];
}

export class NotMachO extends Error {}

/**
 * Opens a Mach-O file, or one slice of a universal one: the one named
 * `slice` (`x86_64`), else the arm64 slice, else the first. The core must be loaded (`loadEngine`).
 */
export function parseMachO(file: Uint8Array, want?: string): MachO {
  const c = engine().machoParse<CoreMachO>(file, want ?? '');
  switch (c.error) {
    case 'tooSmall':
      throw new NotMachO(t('open', 'The file is too small to be a Mach-O program.'));
    case 'javaClass':
      throw new NotMachO(t('open', 'This looks like a Java class file, not a universal Mach-O.'));
    case 'noArches':
      throw new NotMachO(t('open', 'The universal file has no architectures.'));
    case 'notMachO':
      throw new NotMachO(t('open', 'Not a Mach-O program (no 0xfeedfacf signature).'));
    case 'outOfBounds':
      throw new RangeError('Offset is outside the bounds of the DataView');
  }
  const sections = c.sections;
  const rebases = new Map<number, number>();
  for (let k = 0; k + 1 < c.rebases.length; k += 2) rebases.set(c.rebases[k]!, c.rebases[k + 1]!);
  const dataInCode: MachO['dataInCode'] = [];
  for (let k = 0; k + 2 < c.dataInCode.length; k += 3) dataInCode.push({ addr: c.dataInCode[k]!, length: c.dataInCode[k + 1]!, kind: c.dataInCode[k + 2]! });
  const image: MachO = {
    arches: c.arches,
    bytes: file.subarray(c.slice[0], c.slice[1]),
    cputype: c.cputype,
    cpusubtype: c.cpusubtype,
    arch: c.arch,
    is64: c.is64,
    filetype: c.filetype,
    fileTypeName: c.fileTypeName,
    flags: c.flags,
    flagNames: c.flagNames,
    commands: c.commands,
    segments: c.segments.map((s) => ({ ...s, sections: s.sections.map((k) => sections[k]!) })),
    sections,
    symbols: c.symbols.map(([name, addr, type, sect, desc]) => ({ name, type, sect, desc, addr, external: !!(type & 1), undefined: (type & 0x0e) === 0 })),
    libraries: c.libraries,
    // The core lists the imports as it found them; the page shows them by name.
    imports: c.imports.map(([name, library, slot, weak]) => ({ name, library, slot: slot ?? undefined, weak: !!weak })).sort((a, b) => a.name.localeCompare(b.name)),
    exports: c.exports.map(([name, addr, flags]) => ({ name, addr, flags })),
    stubs: new Map(c.stubs),
    rebases,
    functionStarts: c.functionStarts,
    dataInCode,
    rpaths: c.rpaths,
    base: c.base,
    sliceOffset: c.sliceOffset,
  };
  for (const key of ['entry', 'entryKind', 'uuid', 'build', 'sourceVersion', 'dylinker', 'installName', 'signature', 'encrypted', 'encryption', 'signatureAt'] as const) {
    if (c[key] !== undefined) (image as unknown as Record<string, unknown>)[key] = c[key];
  }
  return image;
}

