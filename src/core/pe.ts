/**
 * The PE reader: Windows executables and DLLs (PE32 for i386, PE32+ for
 * x86-64 and arm64). What the analysis needs — sections, the imports and the
 * address of each one's slot in the import address table, the exports, where
 * functions start (the exception table of x86-64 and arm64 lists every
 * function that has unwind data, even in a program without symbols) — and
 * what the PE page shows: the headers, the data directories, the debug
 * information (the PDB a build points at), relocations, TLS callbacks.
 *
 * The reading runs in the core (crates/core/src/pe.rs); what is here turns its
 * answer into these objects.
 */

import { engine } from './engine/engine';
import { t } from './i18n';

export class NotPe extends Error {}

export const isPe = (bytes: Uint8Array): boolean => bytes.length >= 64 && bytes[0] === 0x4d && bytes[1] === 0x5a;

export const MACHINE = { I386: 0x14c, AMD64: 0x8664, ARM64: 0xaa64, ARMNT: 0x1c4, ARM64EC: 0xa641, ARM64X: 0xa64e, IA64: 0x200 } as const;
export const DIRECTORY_NAMES = ['Export', 'Import', 'Resource', 'Exception', 'Certificate', 'Base relocation', 'Debug', 'Architecture', 'Global pointer', 'TLS', 'Load config', 'Bound import', 'IAT', 'Delay import', 'CLR runtime', 'Reserved'];
export const SECTION_FLAGS = { CODE: 0x20, INITIALIZED: 0x40, UNINITIALIZED: 0x80, DISCARDABLE: 0x2000000, EXECUTE: 0x20000000, READ: 0x40000000, WRITE: 0x80000000 } as const;

export interface PeSection {
  name: string;
  /** Relative to the image base. */
  rva: number;
  virtualSize: number;
  rawSize: number;
  rawOffset: number;
  flags: number;
}

export interface PeImport {
  name: string;
  library: string;
  /** Imported by number rather than by name. */
  ordinal?: number;
  hint?: number;
  /** The virtual address of its slot in the import address table. */
  slot: number;
  delayed?: boolean;
}

export interface PeExport {
  name: string;
  ordinal: number;
  addr: number;
  /** `OTHER.dll.Function`: the export is passed on to another DLL, and has no code here. */
  forwarder?: string;
}

export interface PeSymbol {
  name: string;
  addr: number;
  function: boolean;
  external: boolean;
}

export interface Pe {
  bytes: Uint8Array;
  machine: number;
  machineName: string;
  /** x86_64, x86, arm64 — as the analysis names architectures. */
  arch: string;
  is64: boolean;
  timestamp: number;
  characteristics: number;
  flagNames: string[];
  dll: boolean;
  imageBase: number;
  entry?: number;
  sectionAlignment: number;
  fileAlignment: number;
  osVersion: string;
  subsystemVersion: string;
  linkerVersion: string;
  subsystem: number;
  subsystemName: string;
  dllCharacteristics: number;
  dllFlagNames: string[];
  sizeOfImage: number;
  checksum: number;
  directories: { name: string; rva: number; size: number }[];
  sections: PeSection[];
  imports: PeImport[];
  libraries: string[];
  exports: PeExport[];
  /** The DLL's own name, from its export directory. */
  dllName?: string;
  functionStarts: number[];
  tlsCallbacks: number[];
  symbols: PeSymbol[];
  relocationCount: number;
  /** CodeView: the PDB the build wrote, its GUID and age. */
  pdb?: { path: string; guid: string; age: number };
  /** A .NET assembly: its code is CIL bytecode, not machine code. */
  clr: boolean;
  /** The certificate table: signed with Authenticode. */
  signed: boolean;
  /** An ARM64EC or ARM64X program: Arm code and x64 code side by side. */
  hybrid?: PeHybrid;
}

export type CodeKind = 'arm64' | 'arm64ec' | 'x64';

/**
 * What the CHPE metadata (in the load configuration) says about a hybrid program. ARM64EC code is
 * Arm code that follows x64's conventions, so that it can call and be called by x64 code in the
 * same process; an ARM64EC program may hold both. An ARM64X program adds plain arm64 code and two
 * views of itself: the arm64 one its header shows, and an x64-compatible one that dynamic
 * relocations make from it when an x64 process loads it.
 */
export interface PeHybrid {
  /** The code map: each range of code and what it is. */
  ranges: { addr: number; size: number; kind: CodeKind }[];
  /** An x64 entry point → the ARM64EC function it stands for. */
  redirections: Map<number, number>;
  /** Where ARM64EC functions start: their unwind table (the "extra RFE table"), in arm64's format. */
  armStarts: number[];
  /** ARM64X: the program as an x64 process sees it (its own exports and imports). */
  ec?: Pe;
}

/** A PE file's reading as the core writes it (`pe_json` in crates/wasm/src/containers.rs). */
interface CorePe {
  error?: 'notPe' | 'noPeHeader' | 'noOptionalHeader' | 'outOfBounds';
  machine: number;
  machineName: string;
  arch: string;
  is64: boolean;
  timestamp: number;
  characteristics: number;
  flagNames: string[];
  dll: boolean;
  imageBase: number;
  entry?: number;
  sectionAlignment: number;
  fileAlignment: number;
  osVersion: string;
  subsystemVersion: string;
  linkerVersion: string;
  subsystem: number;
  subsystemName: string;
  dllCharacteristics: number;
  dllFlagNames: string[];
  sizeOfImage: number;
  checksum: number;
  relocationCount: number;
  /** name, rva, size */
  directories: [string, number, number][];
  /** name, rva, virtual size, raw size, raw offset, flags */
  sections: [string, number, number, number, number, number][];
  /** name, library, ordinal, hint, slot, delayed */
  imports: [string, string, number | null, number | null, number, number][];
  libraries: string[];
  /** name, ordinal, addr, forwarder */
  exports: [string, number, number, string | null][];
  dllName?: string;
  functionStarts: number[];
  tlsCallbacks: number[];
  /** name, addr, function, external */
  symbols: [string, number, number, number][];
  pdb?: Pe['pdb'];
  clr: boolean;
  signed: boolean;
  hybrid?: {
    ranges: [number, number, CodeKind][];
    /** from, to, from, to… */
    redirections: number[];
    armStarts: number[];
    /** Where the ARM64X dynamic relocations wrote, and what: offset, then the bytes. */
    ecPatches?: number[][];
    ec?: CorePe;
  };
}

/** Builds a Pe from the core's reading of `bytes`. */
function peOf(c: CorePe, bytes: Uint8Array): Pe {
  const pe: Pe = {
    bytes,
    machine: c.machine,
    machineName: c.machineName,
    arch: c.arch,
    is64: c.is64,
    timestamp: c.timestamp,
    characteristics: c.characteristics,
    flagNames: c.flagNames,
    dll: c.dll,
    imageBase: c.imageBase,
    entry: c.entry,
    sectionAlignment: c.sectionAlignment,
    fileAlignment: c.fileAlignment,
    osVersion: c.osVersion,
    subsystemVersion: c.subsystemVersion,
    linkerVersion: c.linkerVersion,
    subsystem: c.subsystem,
    subsystemName: c.subsystemName,
    dllCharacteristics: c.dllCharacteristics,
    dllFlagNames: c.dllFlagNames,
    sizeOfImage: c.sizeOfImage,
    checksum: c.checksum,
    directories: c.directories.map(([name, rva, size]) => ({ name, rva, size })),
    sections: c.sections.map(([name, rva, virtualSize, rawSize, rawOffset, flags]) => ({ name, virtualSize, rva, rawSize, rawOffset, flags })),
    imports: c.imports.map(([name, library, ordinal, hint, slot, delayed]) => ({
      name,
      library,
      ...(ordinal !== null ? { ordinal } : {}),
      ...(hint !== null ? { hint } : {}),
      slot,
      ...(delayed ? { delayed: true } : {}),
    })),
    libraries: c.libraries,
    exports: c.exports.map(([name, ordinal, addr, forwarder]) => ({ name, ordinal, addr, ...(forwarder !== null ? { forwarder } : {}) })),
    functionStarts: c.functionStarts,
    tlsCallbacks: c.tlsCallbacks,
    symbols: c.symbols.map(([name, addr, fn, external]) => ({ name, addr, function: !!fn, external: !!external })),
    relocationCount: c.relocationCount,
    clr: c.clr,
    signed: c.signed,
  };
  if (c.dllName !== undefined) pe.dllName = c.dllName;
  if (c.pdb) pe.pdb = c.pdb;
  const h = c.hybrid;
  if (h) {
    const redirections = new Map<number, number>();
    for (let k = 0; k + 1 < h.redirections.length; k += 2) redirections.set(h.redirections[k]!, h.redirections[k + 1]!);
    const hybrid: PeHybrid = { ranges: h.ranges.map(([addr, size, kind]) => ({ addr, size, kind })), redirections, armStarts: h.armStarts };
    if (h.ec && h.ecPatches) {
      // The x64 view: a copy of the file with the core's writes made again.
      const view = bytes.slice();
      for (const [at, ...written] of h.ecPatches) view.set(written, at!);
      hybrid.ec = peOf(h.ec, view);
    }
    pe.hybrid = hybrid;
  }
  return pe;
}

/** Opens a PE file. The core must be loaded (`loadEngine`). */
export function parsePe(file: Uint8Array): Pe {
  const c = engine().containerParse<CorePe>('pe', file);
  switch (c.error) {
    case 'notPe':
      throw new NotPe(t('open', 'Not a Windows program (no MZ signature).'));
    case 'noPeHeader':
      throw new NotPe(t('open', 'An MS-DOS program without a PE header: only Windows programs are read.'));
    case 'noOptionalHeader':
      throw new NotPe(t('open', 'The PE file has no optional header the reader knows.'));
    case 'outOfBounds':
      throw new RangeError('Offset is outside the bounds of the DataView');
  }
  return peOf(c, file);
}

/** The time a PE file says it was linked (or a hash of it, for reproducible builds). */
export function peTime(pe: Pe): string | undefined {
  // Reproducible builds put a hash here; dates before 1995 or in the future are not dates.
  const date = new Date(pe.timestamp * 1000);
  return pe.timestamp > 788918400 && date.getTime() < Date.now() + 86400000 ? date.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC') : undefined;
}
