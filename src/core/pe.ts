/**
 * The PE reader: Windows executables and DLLs (PE32 for i386, PE32+ for
 * x86-64 and arm64). What the analysis needs — sections, the imports and the
 * address of each one's slot in the import address table, the exports, where
 * functions start (the exception table of x86-64 and arm64 lists every
 * function that has unwind data, even in a program without symbols) — and
 * what the PE page shows: the headers, the data directories, the debug
 * information (the PDB a build points at), relocations, TLS callbacks.
 */

import { t } from './i18n';

export class NotPe extends Error {}

export const isPe = (bytes: Uint8Array): boolean => bytes.length >= 64 && bytes[0] === 0x4d && bytes[1] === 0x5a;

export const MACHINE = { I386: 0x14c, AMD64: 0x8664, ARM64: 0xaa64, ARMNT: 0x1c4, ARM64EC: 0xa641, ARM64X: 0xa64e, IA64: 0x200 } as const;
const MACHINE_NAMES: Record<number, string> = { 0x14c: 'i386', 0x8664: 'x86-64', 0xaa64: 'arm64', 0x1c4: 'arm (Thumb-2)', 0xa641: 'arm64ec', 0xa64e: 'arm64x', 0x200: 'ia64', 0x1c0: 'arm', 0x5064: 'riscv64' };
const SUBSYSTEMS: Record<number, string> = { 1: 'native', 2: 'Windows GUI', 3: 'Windows console', 5: 'OS/2 console', 7: 'POSIX console', 9: 'Windows CE', 10: 'EFI application', 11: 'EFI boot driver', 12: 'EFI runtime driver', 13: 'EFI ROM', 14: 'Xbox', 16: 'Windows boot application' };
const CHARACTERISTICS: [number, string][] = [[0x1, 'RELOCS_STRIPPED'], [0x2, 'EXECUTABLE_IMAGE'], [0x20, 'LARGE_ADDRESS_AWARE'], [0x100, '32BIT_MACHINE'], [0x200, 'DEBUG_STRIPPED'], [0x1000, 'SYSTEM'], [0x2000, 'DLL']];
const DLL_CHARACTERISTICS: [number, string][] = [[0x20, 'HIGH_ENTROPY_VA'], [0x40, 'DYNAMIC_BASE'], [0x80, 'FORCE_INTEGRITY'], [0x100, 'NX_COMPAT'], [0x200, 'NO_ISOLATION'], [0x400, 'NO_SEH'], [0x800, 'NO_BIND'], [0x1000, 'APPCONTAINER'], [0x2000, 'WDM_DRIVER'], [0x4000, 'GUARD_CF'], [0x8000, 'TERMINAL_SERVER_AWARE']];
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

class Reader {
  readonly view: DataView;
  constructor(readonly bytes: Uint8Array) {
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }
  u8(at: number): number {
    return at < this.bytes.length ? this.bytes[at]! : 0;
  }
  u16(at: number): number {
    return at + 2 <= this.bytes.length ? this.view.getUint16(at, true) : 0;
  }
  u32(at: number): number {
    return at + 4 <= this.bytes.length ? this.view.getUint32(at, true) : 0;
  }
  u64(at: number): number {
    return at + 8 <= this.bytes.length ? Number(this.view.getBigUint64(at, true)) : 0;
  }
  cstr(at: number, max = 512): string {
    let end = at;
    while (end < this.bytes.length && end - at < max && this.bytes[end] !== 0) end++;
    return new TextDecoder().decode(this.bytes.subarray(at, end));
  }
}

const archOf = (machine: number): string =>
  machine === MACHINE.AMD64 ? 'x86_64' : machine === MACHINE.I386 ? 'x86' : machine === MACHINE.ARM64 ? 'arm64' : machine === MACHINE.ARMNT ? 'armv7' : MACHINE_NAMES[machine] ?? `machine 0x${machine.toString(16)}`;
const names = (value: number, table: [number, string][]) => table.filter(([bit]) => value & bit).map(([, name]) => name);

/** Opens a PE file. `asEc`: the bytes are an ARM64X program's EC view, made from it, and are not read for another. */
export function parsePe(file: Uint8Array, asEc = false): Pe {
  const r = new Reader(file);
  if (!isPe(file)) throw new NotPe(t('open', 'Not a Windows program (no MZ signature).'));
  const peAt = r.u32(0x3c);
  if (peAt + 24 > file.length || r.u32(peAt) !== 0x4550) throw new NotPe(t('open', 'An MS-DOS program without a PE header: only Windows programs are read.'));
  const coff = peAt + 4;
  const machine = r.u16(coff);
  const sectionCount = r.u16(coff + 2);
  const timestamp = r.u32(coff + 4);
  const symbolTable = r.u32(coff + 8);
  const symbolCount = r.u32(coff + 12);
  const optionalSize = r.u16(coff + 16);
  const characteristics = r.u16(coff + 18);
  const opt = coff + 20;
  const magic = r.u16(opt);
  if (magic !== 0x10b && magic !== 0x20b) throw new NotPe(t('open', 'The PE file has no optional header the reader knows.'));
  const is64 = magic === 0x20b;
  const imageBase = is64 ? r.u64(opt + 24) : r.u32(opt + 28);
  const entryRva = r.u32(opt + 16);
  const dirCount = r.u32(opt + (is64 ? 108 : 92));
  const dirAt = opt + (is64 ? 112 : 96);
  const directories: Pe['directories'] = [];
  for (let i = 0; i < Math.min(dirCount, 16); i++) directories.push({ name: DIRECTORY_NAMES[i]!, rva: r.u32(dirAt + i * 8), size: r.u32(dirAt + i * 8 + 4) });

  // The string table after the COFF symbols holds section names longer than eight bytes (/4…).
  const strings = symbolTable && symbolCount ? symbolTable + symbolCount * 18 : 0;
  const sections: PeSection[] = [];
  const sectionAt = opt + optionalSize;
  for (let i = 0; i < sectionCount; i++) {
    const at = sectionAt + i * 40;
    let name = r.cstr(at, 8);
    if (/^\/\d+$/.test(name) && strings) name = r.cstr(strings + Number(name.slice(1)));
    sections.push({ name, virtualSize: r.u32(at + 8), rva: r.u32(at + 12), rawSize: r.u32(at + 16), rawOffset: r.u32(at + 20), flags: r.u32(at + 36) });
  }
  /** The file offset of a relative virtual address, or -1. */
  const offsetOf = (rva: number): number => {
    for (const s of sections) {
      const size = Math.max(s.virtualSize, s.rawSize);
      if (rva >= s.rva && rva < s.rva + size) return rva - s.rva < s.rawSize ? s.rawOffset + (rva - s.rva) : -1;
    }
    return rva < (sections[0]?.rva ?? 0x1000) && rva < file.length ? rva : -1;
  };
  const strAt = (rva: number) => {
    const at = offsetOf(rva);
    return at < 0 ? '' : r.cstr(at);
  };
  const dir = (i: number) => directories[i] ?? { name: '', rva: 0, size: 0 };
  const ptr = is64 ? 8 : 4;
  const readPtr = (at: number) => (is64 ? r.u64(at) : r.u32(at));

  const pe: Pe = {
    bytes: file, machine, machineName: MACHINE_NAMES[machine] ?? `0x${machine.toString(16)}`, arch: archOf(machine), is64, timestamp, characteristics,
    flagNames: names(characteristics, CHARACTERISTICS), dll: !!(characteristics & 0x2000), imageBase, entry: entryRva ? imageBase + entryRva : undefined,
    sectionAlignment: r.u32(opt + 32), fileAlignment: r.u32(opt + 36), osVersion: `${r.u16(opt + 40)}.${r.u16(opt + 42)}`, subsystemVersion: `${r.u16(opt + 48)}.${r.u16(opt + 50)}`,
    linkerVersion: `${r.u8(opt + 2)}.${r.u8(opt + 3)}`, subsystem: r.u16(opt + 68), subsystemName: SUBSYSTEMS[r.u16(opt + 68)] ?? `subsystem ${r.u16(opt + 68)}`,
    dllCharacteristics: r.u16(opt + 70), dllFlagNames: names(r.u16(opt + 70), DLL_CHARACTERISTICS), sizeOfImage: r.u32(opt + 56), checksum: r.u32(opt + 64),
    directories, sections, imports: [], libraries: [], exports: [], functionStarts: [], tlsCallbacks: [], symbols: [], relocationCount: 0, clr: !!dir(14).rva, signed: !!dir(4).size,
  };

  // Imports: one descriptor per DLL; the lookup table names each import, the address table holds its slot.
  const libraries = new Set<string>();
  const readThunks = (library: string, lookup: number, iat: number, delayed: boolean) => {
    for (let i = 0; i < 65536; i++) {
      const at = offsetOf(lookup + i * ptr);
      if (at < 0) break;
      const value = readPtr(at);
      if (!value) break;
      const slot = imageBase + iat + i * ptr;
      const byOrdinal = is64 ? value >= 2 ** 63 : value >= 2 ** 31;
      if (byOrdinal) pe.imports.push({ name: `#${value % 65536}`, library, ordinal: value % 65536, slot, ...(delayed ? { delayed } : {}) });
      else {
        const hintAt = offsetOf(value % 2 ** 31);
        if (hintAt < 0) continue;
        pe.imports.push({ name: r.cstr(hintAt + 2), library, hint: r.u16(hintAt), slot, ...(delayed ? { delayed } : {}) });
      }
    }
  };
  if (dir(1).rva) {
    for (let at = offsetOf(dir(1).rva), k = 0; at >= 0 && k < 4096; at += 20, k++) {
      const lookup = r.u32(at);
      const nameRva = r.u32(at + 12);
      const iat = r.u32(at + 16);
      if (!nameRva && !iat) break;
      const library = strAt(nameRva);
      libraries.add(library);
      readThunks(library, lookup || iat, iat, false);
    }
  }
  if (dir(13).rva) {
    for (let at = offsetOf(dir(13).rva), k = 0; at >= 0 && k < 4096; at += 32, k++) {
      const attributes = r.u32(at);
      const nameRva = r.u32(at + 4);
      if (!nameRva) break;
      // Old (Visual C++ 6) descriptors hold virtual addresses instead of RVAs.
      const fix = (v: number) => (attributes & 1 ? v : v - imageBase);
      const library = strAt(fix(nameRva));
      libraries.add(library);
      readThunks(library, fix(r.u32(at + 16)), fix(r.u32(at + 12)), true);
    }
  }
  pe.libraries = [...libraries];

  // Exports, by ordinal; the names point at some of them. An address inside the export directory is a forwarder.
  if (dir(0).rva) {
    const at = offsetOf(dir(0).rva);
    if (at >= 0) {
      pe.dllName = strAt(r.u32(at + 12)) || undefined;
      const base = r.u32(at + 16);
      const functions = Math.min(r.u32(at + 20), 1 << 20);
      const namesCount = Math.min(r.u32(at + 24), 1 << 20);
      const addressAt = offsetOf(r.u32(at + 28));
      const nameAt = offsetOf(r.u32(at + 32));
      const ordinalAt = offsetOf(r.u32(at + 36));
      const named = new Map<number, string>();
      for (let i = 0; i < namesCount && nameAt >= 0 && ordinalAt >= 0; i++) named.set(r.u16(ordinalAt + i * 2), strAt(r.u32(nameAt + i * 4)));
      for (let i = 0; i < functions && addressAt >= 0; i++) {
        const rva = r.u32(addressAt + i * 4);
        if (!rva) continue;
        const name = named.get(i) ?? `#${base + i}`;
        const forwarded = rva >= dir(0).rva && rva < dir(0).rva + dir(0).size;
        pe.exports.push({ name, ordinal: base + i, addr: imageBase + rva, ...(forwarded ? { forwarder: strAt(rva) } : {}) });
      }
    }
  }

  // The exception table: x86-64 entries are 12 bytes (begin, end, unwind info), arm64 and 32-bit Arm ones 8
  // (a Thumb function's start has its low bit set).
  if (dir(3).rva && (machine === MACHINE.AMD64 || machine === MACHINE.ARM64 || machine === MACHINE.ARMNT)) {
    const size = machine === MACHINE.AMD64 ? 12 : 8;
    const at = offsetOf(dir(3).rva);
    for (let i = 0; at >= 0 && i * size + size <= dir(3).size; i++) {
      const begin = r.u32(at + i * size) & (machine === MACHINE.ARMNT ? ~1 : ~0);
      if (begin) pe.functionStarts.push(imageBase + begin);
    }
  }

  // TLS callbacks run before the entry point: functions too.
  if (dir(9).rva) {
    const at = offsetOf(dir(9).rva);
    const callbacks = at >= 0 ? readPtr(at + ptr * 3) : 0;
    for (let k = 0, cb = callbacks ? offsetOf(callbacks - imageBase) : -1; cb >= 0 && k < 64; k++) {
      const v = readPtr(cb + k * ptr);
      if (!v) break;
      pe.tlsCallbacks.push(v);
    }
  }

  // Relocations: blocks of a page and its 16-bit entries (type 0 is padding).
  if (dir(5).rva) {
    let at = offsetOf(dir(5).rva);
    const end = at + dir(5).size;
    while (at >= 0 && at + 8 <= end) {
      const block = r.u32(at + 4);
      if (block < 8) break;
      for (let k = 8; k < block; k += 2) if (r.u16(at + k) >> 12) pe.relocationCount++;
      at += block;
    }
  }

  // Debug directory: a CodeView RSDS record names the PDB.
  if (dir(6).rva) {
    const at = offsetOf(dir(6).rva);
    for (let i = 0; at >= 0 && i * 28 < dir(6).size; i++) {
      const entry = at + i * 28;
      if (r.u32(entry + 12) !== 2) continue;
      const data = r.u32(entry + 24);
      if (r.u32(data) !== 0x53445352) continue;
      const g = file.subarray(data + 4, data + 20);
      const hex = (from: number, to: number, reverse = false) => {
        const part = [...g.subarray(from, to)];
        return (reverse ? part.reverse() : part).map((b) => b.toString(16).padStart(2, '0')).join('');
      };
      const guid = `${hex(0, 4, true)}-${hex(4, 6, true)}-${hex(6, 8, true)}-${hex(8, 10)}-${hex(10, 16)}`.toUpperCase();
      pe.pdb = { path: r.cstr(data + 24), guid, age: r.u32(data + 20) };
      break;
    }
  }

  // The load configuration of a 64-bit program: the CHPE metadata of a hybrid one, and the
  // dynamic relocations that turn an ARM64X program into its x64-compatible view.
  if (is64 && dir(10).rva) {
    const at = offsetOf(dir(10).rva);
    const size = at >= 0 ? r.u32(at) : 0;
    const chpe = size >= 0xd0 ? r.u64(at + 200) : 0;
    const meta = chpe ? offsetOf(chpe - imageBase) : -1;
    if (meta >= 0 && r.u32(meta) >= 1) {
      const hybrid: PeHybrid = { ranges: [], redirections: new Map(), armStarts: [] };
      const map = offsetOf(r.u32(meta + 4));
      const KINDS: CodeKind[] = ['arm64', 'arm64ec', 'x64'];
      for (let i = 0, count = r.u32(meta + 8); map >= 0 && i < Math.min(count, 65536); i++) {
        const start = r.u32(map + i * 8);
        const kind = KINDS[start & 3];
        if (kind) hybrid.ranges.push({ addr: imageBase + (start & ~3), size: r.u32(map + i * 8 + 4), kind });
      }
      const redirects = offsetOf(r.u32(meta + 16));
      for (let i = 0, count = r.u32(meta + 52); redirects >= 0 && i < Math.min(count, 1 << 20); i++) {
        hybrid.redirections.set(imageBase + r.u32(redirects + i * 8), imageBase + r.u32(redirects + i * 8 + 4));
      }
      const rfe = offsetOf(r.u32(meta + 64));
      for (let i = 0, count = Math.floor(r.u32(meta + 68) / 8); rfe >= 0 && i < count; i++) {
        const begin = r.u32(rfe + i * 8);
        if (begin) hybrid.armStarts.push(imageBase + begin);
      }
      if (hybrid.ranges.length) pe.hybrid = hybrid;
      if (hybrid.ranges.length && !asEc && size >= 0xe8) {
        const view = ecView(r, sections, r.u32(at + 224), r.u16(at + 228));
        if (view) {
          try {
            hybrid.ec = parsePe(view, true);
          } catch {
            // Without its EC view the program still opens as arm64.
          }
        }
      }
    }
  }

  // COFF symbols, which MinGW and some other linkers keep in an unstripped image.
  if (symbolTable && symbolCount && symbolTable + symbolCount * 18 <= file.length) {
    for (let i = 0; i < symbolCount; i++) {
      const at = symbolTable + i * 18;
      const aux = r.u8(at + 17);
      const section = r.u16(at + 12);
      const storage = r.u8(at + 16);
      const type = r.u16(at + 14);
      if (section >= 1 && section <= sections.length && (storage === 2 || storage === 3)) {
        const name = r.u32(at) === 0 ? r.cstr(strings + r.u32(at + 4)) : r.cstr(at, 8);
        const s = sections[section - 1]!;
        const isFunction = type >> 4 === 2 || (storage === 2 && !!(s.flags & SECTION_FLAGS.EXECUTE));
        if (name && !name.startsWith('.')) pe.symbols.push({ name, addr: imageBase + s.rva + r.u32(at + 8), function: isFunction, external: storage === 2 });
      }
      i += aux;
    }
  }
  return pe;
}

/**
 * An ARM64X program as an x64 process loads it: its ARM64X dynamic relocations (in the dynamic
 * value relocation table) applied to a copy of the file. They rewrite the header — the machine,
 * the entry point, the export and import directories — and little else. Undefined for a program
 * that has none.
 */
function ecView(r: Reader, sections: PeSection[], tableOffset: number, tableSection: number): Uint8Array | undefined {
  const section = sections[tableSection - 1];
  if (!section || !tableOffset) return undefined;
  const table = section.rawOffset + tableOffset;
  if (r.u32(table) !== 1) return undefined;
  const end = table + 8 + r.u32(table + 4);
  const out = r.bytes.slice();
  const view = new DataView(out.buffer);
  // Relative addresses in the headers are file offsets; past them, the section that holds them says.
  const fileAt = (rva: number) => {
    for (const s of sections) if (rva >= s.rva && rva < s.rva + s.rawSize) return s.rawOffset + rva - s.rva;
    return rva < (sections[0]?.rva ?? 0x1000) ? rva : -1;
  };
  let changed = false;
  for (let at = table + 8; at + 12 <= end; ) {
    const symbol = r.u64(at);
    const size = r.u32(at + 8);
    at += 12;
    if (symbol === 6) {
      // IMAGE_DYNAMIC_RELOCATION_ARM64X: blocks of a page and its entries, like base relocations.
      for (let block = at; block + 8 <= at + size; ) {
        const page = r.u32(block);
        const blockSize = r.u32(block + 4);
        if (blockSize < 8) break;
        for (let p = block + 8; p + 2 <= block + blockSize; ) {
          const entry = r.u16(p);
          p += 2;
          const offset = entry & 0xfff;
          const type = (entry >> 12) & 3;
          const meta = entry >> 14;
          const target = fileAt(page + offset);
          if (type === 0 || type === 1) {
            // Zero-fill, or a value of 1 << meta bytes that follows.
            const bytes = 1 << meta;
            if (!entry && p >= block + blockSize) break; // padding at the end of a block
            if (target >= 0 && target + bytes <= out.length) {
              for (let k = 0; k < bytes; k++) out[target + k] = type === 1 ? r.u8(p + k) : 0;
              changed = true;
            }
            if (type === 1) p += bytes;
          } else if (type === 2) {
            // A delta: a 16-bit count of 4- or 8-byte units, added or taken away.
            const delta = r.u16(p) * (meta & 1 ? 8 : 4) * (meta & 2 ? -1 : 1);
            p += 2;
            if (target >= 0 && target + 8 <= out.length) {
              view.setBigUint64(target, BigInt.asUintN(64, view.getBigUint64(target, true) + BigInt(delta)), true);
              changed = true;
            }
          } else break;
        }
        block += blockSize;
      }
    }
    at += size;
  }
  return changed ? out : undefined;
}

/** The time a PE file says it was linked (or a hash of it, for reproducible builds). */
export function peTime(pe: Pe): string | undefined {
  // Reproducible builds put a hash here; dates before 1995 or in the future are not dates.
  const date = new Date(pe.timestamp * 1000);
  return pe.timestamp > 788918400 && date.getTime() < Date.now() + 86400000 ? date.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC') : undefined;
}
