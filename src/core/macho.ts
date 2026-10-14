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
 * Nothing here touches the DOM, so the tests run it in Node.
 */

import { sleb, uleb, utf8 } from './bytes';
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

const CPU_ARM64 = 0x0100000c;
const CPU_X86_64 = 0x01000007;

const FILE_TYPES: Record<number, string> = {
  1: 'Object file', 2: 'Executable', 3: 'Fixed VM library', 4: 'Core dump', 5: 'Preloaded executable', 6: 'Dynamic library',
  7: 'Dynamic linker', 8: 'Bundle', 9: 'Dynamic library stub', 10: 'Debug symbols (dSYM)', 11: 'Kernel extension',
};

const HEADER_FLAGS = [
  'NOUNDEFS', 'INCRLINK', 'DYLDLINK', 'BINDATLOAD', 'PREBOUND', 'SPLIT_SEGS', 'LAZY_INIT', 'TWOLEVEL', 'FORCE_FLAT', 'NOMULTIDEFS',
  'NOFIXPREBINDING', 'PREBINDABLE', 'ALLMODSBOUND', 'SUBSECTIONS_VIA_SYMBOLS', 'CANONICAL', 'WEAK_DEFINES', 'BINDS_TO_WEAK',
  'ALLOW_STACK_EXECUTION', 'ROOT_SAFE', 'SETUID_SAFE', 'NO_REEXPORTED_DYLIBS', 'PIE', 'DEAD_STRIPPABLE_DYLIB', 'HAS_TLV_DESCRIPTORS',
  'NO_HEAP_EXECUTION', 'APP_EXTENSION_SAFE', 'NLIST_OUTOFSYNC_WITH_DYLDINFO', 'SIM_SUPPORT', '', '', '', 'DYLIB_IN_CACHE',
];

const COMMANDS: Record<number, string> = {
  0x1: 'LC_SEGMENT', 0x2: 'LC_SYMTAB', 0x5: 'LC_UNIXTHREAD', 0xb: 'LC_DYSYMTAB', 0xc: 'LC_LOAD_DYLIB', 0xd: 'LC_ID_DYLIB',
  0xe: 'LC_LOAD_DYLINKER', 0xf: 'LC_ID_DYLINKER', 0x80000018: 'LC_LOAD_WEAK_DYLIB', 0x19: 'LC_SEGMENT_64', 0x1b: 'LC_UUID',
  0x8000001c: 'LC_RPATH', 0x1d: 'LC_CODE_SIGNATURE', 0x1e: 'LC_SEGMENT_SPLIT_INFO', 0x8000001f: 'LC_REEXPORT_DYLIB',
  0x21: 'LC_ENCRYPTION_INFO', 0x22: 'LC_DYLD_INFO', 0x80000022: 'LC_DYLD_INFO_ONLY', 0x80000023: 'LC_LOAD_UPWARD_DYLIB',
  0x24: 'LC_VERSION_MIN_MACOSX', 0x25: 'LC_VERSION_MIN_IPHONEOS', 0x26: 'LC_FUNCTION_STARTS', 0x27: 'LC_DYLD_ENVIRONMENT',
  0x80000028: 'LC_MAIN', 0x29: 'LC_DATA_IN_CODE', 0x2a: 'LC_SOURCE_VERSION', 0x2b: 'LC_DYLIB_CODE_SIGN_DRS',
  0x2c: 'LC_ENCRYPTION_INFO_64', 0x2d: 'LC_LINKER_OPTION', 0x2e: 'LC_LINKER_OPTIMIZATION_HINT', 0x32: 'LC_BUILD_VERSION',
  0x80000033: 'LC_DYLD_EXPORTS_TRIE', 0x80000034: 'LC_DYLD_CHAINED_FIXUPS', 0x35: 'LC_FILESET_ENTRY', 0x36: 'LC_ATOM_INFO',
};

const PLATFORMS: Record<number, string> = {
  1: 'macOS', 2: 'iOS', 3: 'tvOS', 4: 'watchOS', 5: 'bridgeOS', 6: 'Mac Catalyst', 7: 'iOS Simulator', 8: 'tvOS Simulator',
  9: 'watchOS Simulator', 10: 'DriverKit', 11: 'visionOS', 12: 'visionOS Simulator',
};
const TOOLS: Record<number, string> = { 1: 'clang', 2: 'swift', 3: 'ld', 4: 'lld', 1024: 'Metal' };

const ARM_SUBTYPES: Record<number, string> = {
  5: 'armv4t', 6: 'armv6', 7: 'armv5', 9: 'armv7', 10: 'armv7f', 11: 'armv7s', 12: 'armv7k', 14: 'armv6m', 15: 'armv7m', 16: 'armv7em',
};

export function archName(cputype: number, subtype = 0): string {
  if (cputype === CPU_ARM64) return (subtype & 0xff) === 2 ? 'arm64e' : 'arm64';
  if (cputype === CPU_X86_64) return 'x86_64';
  if (cputype === 0x0200000c) return 'arm64_32';
  if (cputype === 12) return ARM_SUBTYPES[subtype & 0xff] ?? 'arm';
  if (cputype === 7) return 'i386';
  return `cpu ${cputype.toString(16)}`;
}

/** major.minor.patch packed as xxxx.yy.zz */
const version32 = (v: number): string => {
  const patch = v & 0xff;
  return `${v >>> 16}.${(v >>> 8) & 0xff}${patch ? `.${patch}` : ''}`;
};

class Reader {
  readonly view: DataView;
  constructor(readonly bytes: Uint8Array) {
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }
  u8 = (at: number) => this.bytes[at] ?? 0;
  u16 = (at: number) => this.view.getUint16(at, true);
  u32 = (at: number) => this.view.getUint32(at, true);
  i32 = (at: number) => this.view.getInt32(at, true);
  u64 = (at: number) => Number(this.view.getBigUint64(at, true));
  big64 = (at: number) => this.view.getBigUint64(at, true);
  be32 = (at: number) => this.view.getUint32(at, false);
  /** A NUL-terminated string, at most `max` bytes. */
  cstr(at: number, max = 4096): string {
    let end = at;
    const limit = Math.min(this.bytes.length, at + max);
    while (end < limit && this.bytes[end] !== 0) end++;
    return utf8(this.bytes.subarray(at, end));
  }
  fixed(at: number, length: number): string {
    return this.cstr(at, length);
  }
  uleb = (at: number) => uleb(this.bytes, at);
  /** A ULEB128 that the bind opcodes use as a 64-bit step, where a step back wraps around. */
  ulebStep(at: number): [number, number] {
    let result = 0n;
    let shift = 0n;
    let p = at;
    for (;;) {
      const byte = this.bytes[p++] ?? 0;
      result |= BigInt(byte & 0x7f) << shift;
      shift += 7n;
      if (!(byte & 0x80) || p >= this.bytes.length) break;
    }
    return [Number(BigInt.asIntN(64, result)), p];
  }
  sleb = (at: number) => sleb(this.bytes, at);
}

export class NotMachO extends Error {}

/**
 * Opens a Mach-O file, or one slice of a universal one: the one named
 * `slice` (`x86_64`), else the arm64 slice, else the first.
 */
export function parseMachO(file: Uint8Array, want?: string): MachO {
  if (file.length < 32) throw new NotMachO(t('open', 'The file is too small to be a Mach-O program.'));
  const outer = new Reader(file);
  const magicBE = outer.be32(0);
  let arches: MachO['arches'] = [];
  let slice = file;
  let sliceOffset = 0;
  if (magicBE === 0xcafebabe || magicBE === 0xcafebabf) {
    const wide = magicBE === 0xcafebabf;
    const count = outer.be32(4);
    if (count > 64) throw new NotMachO(t('open', 'This looks like a Java class file, not a universal Mach-O.'));
    const entries = [];
    for (let i = 0; i < count; i++) {
      const at = 8 + i * (wide ? 32 : 20);
      const cputype = outer.be32(at);
      const subtype = outer.be32(at + 4);
      const offset = wide ? Number(outer.view.getBigUint64(at + 8, false)) : outer.be32(at + 8);
      const size = wide ? Number(outer.view.getBigUint64(at + 16, false)) : outer.be32(at + 12);
      entries.push({ name: archName(cputype, subtype), offset, size, cputype });
    }
    arches = entries.map(({ name, offset, size }) => ({ name, offset, size }));
    const pick = entries.find((e) => e.name === want) ?? entries.find((e) => e.cputype === CPU_ARM64) ?? entries[0];
    if (!pick) throw new NotMachO(t('open', 'The universal file has no architectures.'));
    slice = file.subarray(pick.offset, pick.offset + pick.size);
    sliceOffset = pick.offset;
  }
  const r = new Reader(slice);
  const magic = r.u32(0);
  if (magic !== 0xfeedfacf && magic !== 0xfeedface) throw new NotMachO(t('open', 'Not a Mach-O program (no 0xfeedfacf signature).'));
  const is64 = magic === 0xfeedfacf;
  // Pointers, and the fields that hold addresses, are 8 bytes in a 64-bit file and 4 in a 32-bit one.
  const ptrSize = is64 ? 8 : 4;
  const addrAt = (at: number) => (is64 ? r.u64(at) : r.u32(at));
  const cputype = r.u32(4);
  const cpusubtype = r.u32(8);
  const filetype = r.u32(12);
  const ncmds = r.u32(16);
  const flags = r.u32(24);
  const arch = archName(cputype, cpusubtype);
  if (!arches.length) arches = [{ name: arch, offset: 0, size: file.length }];

  const image: MachO = {
    arches, bytes: slice, cputype, cpusubtype, arch, is64, filetype, fileTypeName: FILE_TYPES[filetype] ?? `type ${filetype}`, flags,
    flagNames: HEADER_FLAGS.filter((name, i) => name && flags & (1 << i)),
    commands: [], segments: [], sections: [], symbols: [], libraries: [], imports: [], exports: [], stubs: new Map(), rebases: new Map(),
    functionStarts: [], dataInCode: [], rpaths: [], base: 0, sliceOffset,
  };

  let symtab: { symoff: number; nsyms: number; stroff: number; strsize: number } | undefined;
  let dysymtab: { indirectoff: number; nindirect: number } | undefined;
  let dyldInfo: { bind: [number, number]; weak: [number, number]; lazy: [number, number]; exports: [number, number] } | undefined;
  let exportsTrie: [number, number] | undefined;
  let chained: [number, number] | undefined;
  let functionStarts: [number, number] | undefined;
  let dataInCode: [number, number] | undefined;
  let signature: [number, number] | undefined;
  let entryOff: number | undefined;
  let threadEntry: number | undefined;

  let at = is64 ? 32 : 28;
  for (let i = 0; i < ncmds && at + 8 <= slice.length; i++) {
    const cmd = r.u32(at);
    const size = r.u32(at + 4);
    if (size < 8) break;
    const name = COMMANDS[cmd] ?? `0x${cmd.toString(16)}`;
    let summary = '';
    switch (cmd) {
      case 0x19: {
        const segment: Segment = {
          name: r.fixed(at + 8, 16), vmaddr: r.u64(at + 24), vmsize: r.u64(at + 32), fileoff: r.u64(at + 40), filesize: r.u64(at + 48),
          maxprot: r.u32(at + 56), initprot: r.u32(at + 60), sections: [],
        };
        const nsects = r.u32(at + 64);
        for (let s = 0; s < nsects; s++) {
          const p = at + 72 + s * 80;
          const section: Section = {
            sectname: r.fixed(p, 16), segname: r.fixed(p + 16, 16), addr: r.u64(p + 32), size: r.u64(p + 40), offset: r.u32(p + 48),
            align: r.u32(p + 52), flags: r.u32(p + 64), reserved1: r.u32(p + 68), reserved2: r.u32(p + 72),
          };
          segment.sections.push(section);
          image.sections.push(section);
        }
        image.segments.push(segment);
        if (segment.name === '__TEXT') image.base = segment.vmaddr - segment.fileoff;
        summary = `${segment.name} at 0x${segment.vmaddr.toString(16)}, ${segment.vmsize.toLocaleString('en')} bytes, ${nsects} section${nsects === 1 ? '' : 's'}`;
        break;
      }
      case 0x1: {
        // LC_SEGMENT: the 32-bit layout, with 4-byte addresses and sizes.
        const segment: Segment = {
          name: r.fixed(at + 8, 16), vmaddr: r.u32(at + 24), vmsize: r.u32(at + 28), fileoff: r.u32(at + 32), filesize: r.u32(at + 36),
          maxprot: r.u32(at + 40), initprot: r.u32(at + 44), sections: [],
        };
        const nsects = r.u32(at + 48);
        for (let s = 0; s < nsects; s++) {
          const p = at + 56 + s * 68;
          const section: Section = {
            sectname: r.fixed(p, 16), segname: r.fixed(p + 16, 16), addr: r.u32(p + 32), size: r.u32(p + 36), offset: r.u32(p + 40),
            align: r.u32(p + 44), flags: r.u32(p + 56), reserved1: r.u32(p + 60), reserved2: r.u32(p + 64),
          };
          segment.sections.push(section);
          image.sections.push(section);
        }
        image.segments.push(segment);
        if (segment.name === '__TEXT') image.base = segment.vmaddr - segment.fileoff;
        summary = `${segment.name} at 0x${segment.vmaddr.toString(16)}, ${segment.vmsize.toLocaleString('en')} bytes, ${nsects} section${nsects === 1 ? '' : 's'}`;
        break;
      }
      case 0x5: {
        // LC_UNIXTHREAD: the initial registers of the main thread, programs before LC_MAIN start where their pc says.
        threadEntry = threadPc(r, at, size, cputype);
        if (threadEntry !== undefined) summary = `entry at 0x${threadEntry.toString(16)}`;
        break;
      }
      case 0x2:
        symtab = { symoff: r.u32(at + 8), nsyms: r.u32(at + 12), stroff: r.u32(at + 16), strsize: r.u32(at + 20) };
        summary = `${symtab.nsyms.toLocaleString('en')} symbols`;
        break;
      case 0xb:
        dysymtab = { indirectoff: r.u32(at + 56), nindirect: r.u32(at + 60) };
        summary = `${dysymtab.nindirect.toLocaleString('en')} indirect symbols`;
        break;
      case 0xc:
      case 0x80000018:
      case 0x8000001f:
      case 0x80000023: {
        const lib = r.cstr(at + r.u32(at + 8), size);
        image.libraries.push(lib);
        summary = `${lib} (${version32(r.u32(at + 16))})`;
        break;
      }
      case 0xd:
        image.installName = r.cstr(at + r.u32(at + 8), size);
        summary = image.installName;
        break;
      case 0xe:
        image.dylinker = r.cstr(at + r.u32(at + 8), size);
        summary = image.dylinker;
        break;
      case 0x8000001c: {
        const path = r.cstr(at + r.u32(at + 8), size);
        image.rpaths.push(path);
        summary = path;
        break;
      }
      case 0x1b: {
        const hex = [...slice.subarray(at + 8, at + 24)].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
        image.uuid = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
        summary = image.uuid;
        break;
      }
      case 0x22:
      case 0x80000022:
        dyldInfo = {
          bind: [r.u32(at + 16), r.u32(at + 20)], weak: [r.u32(at + 24), r.u32(at + 28)], lazy: [r.u32(at + 32), r.u32(at + 36)],
          exports: [r.u32(at + 40), r.u32(at + 44)],
        };
        summary = `rebase ${r.u32(at + 12)} B, bind ${dyldInfo.bind[1]} B, lazy bind ${dyldInfo.lazy[1]} B, exports ${dyldInfo.exports[1]} B`;
        break;
      case 0x80000033:
        exportsTrie = [r.u32(at + 8), r.u32(at + 12)];
        summary = `${exportsTrie[1].toLocaleString('en')} bytes`;
        break;
      case 0x80000034:
        chained = [r.u32(at + 8), r.u32(at + 12)];
        summary = `${chained[1].toLocaleString('en')} bytes`;
        break;
      case 0x26:
        functionStarts = [r.u32(at + 8), r.u32(at + 12)];
        summary = `${functionStarts[1].toLocaleString('en')} bytes`;
        break;
      case 0x29:
        dataInCode = [r.u32(at + 8), r.u32(at + 12)];
        summary = `${dataInCode[1] / 8} entries`;
        break;
      case 0x1d:
        signature = [r.u32(at + 8), r.u32(at + 12)];
        summary = `${signature[1].toLocaleString('en')} bytes at offset 0x${signature[0].toString(16)}`;
        break;
      case 0x80000028:
        entryOff = r.u64(at + 8);
        summary = `entry at file offset 0x${entryOff.toString(16)}, stack ${r.u64(at + 16) || 'default'}`;
        break;
      case 0x2a: {
        const v = r.big64(at + 8);
        const parts = [v >> 40n, (v >> 30n) & 0x3ffn, (v >> 20n) & 0x3ffn, (v >> 10n) & 0x3ffn, v & 0x3ffn];
        while (parts.length > 2 && parts[parts.length - 1] === 0n) parts.pop();
        image.sourceVersion = parts.join('.');
        summary = image.sourceVersion;
        break;
      }
      case 0x32: {
        const platform = PLATFORMS[r.u32(at + 8)] ?? `platform ${r.u32(at + 8)}`;
        const tools = [];
        const ntools = r.u32(at + 20);
        for (let t = 0; t < ntools; t++) {
          const tool = r.u32(at + 24 + t * 8);
          tools.push(`${TOOLS[tool] ?? `tool ${tool}`} ${version32(r.u32(at + 28 + t * 8))}`);
        }
        image.build = { platform, minos: version32(r.u32(at + 12)), sdk: version32(r.u32(at + 16)), tools };
        summary = `${platform} ${image.build.minos}, SDK ${image.build.sdk}${tools.length ? `, ${tools.join(', ')}` : ''}`;
        break;
      }
      case 0x24:
      case 0x25:
        summary = `min ${version32(r.u32(at + 8))}, SDK ${version32(r.u32(at + 12))}`;
        image.build ??= { platform: cmd === 0x24 ? 'macOS' : 'iOS', minos: version32(r.u32(at + 8)), sdk: version32(r.u32(at + 12)), tools: [] };
        break;
      case 0x21:
      case 0x2c:
        image.encryption = { offset: r.u32(at + 8), size: r.u32(at + 12), id: r.u32(at + 16) };
        image.encrypted = image.encryption.id !== 0 && image.encryption.size !== 0;
        summary = `${image.encrypted ? 'encrypted (FairPlay)' : 'not encrypted'}: ${image.encryption.size.toLocaleString('en')} bytes at 0x${image.encryption.offset.toString(16)}`;
        break;
    }
    image.commands.push({ cmd, name, size, offset: at, summary });
    at += size;
  }

  if (entryOff !== undefined) {
    image.entry = image.base + entryOff;
    image.entryKind = 'main';
  } else if (threadEntry !== undefined) {
    image.entry = threadEntry;
    image.entryKind = 'thread';
  }

  const nlistSize = is64 ? 16 : 12;
  if (symtab) {
    for (let s = 0; s < symtab.nsyms; s++) {
      const p = symtab.symoff + s * nlistSize;
      if (p + nlistSize > slice.length) break;
      const strx = r.u32(p);
      const type = r.u8(p + 4);
      if (type & 0xe0) continue; // stabs: debugging entries
      const name = strx && strx < symtab.strsize ? r.cstr(symtab.stroff + strx) : '';
      image.symbols.push({
        name, type, sect: r.u8(p + 5), desc: r.u16(p + 6), addr: addrAt(p + 8),
        external: !!(type & 1), undefined: (type & 0x0e) === 0,
      });
    }
  }

  const allSymbols = symtab
    ? (index: number) => {
        const p = symtab.symoff + index * nlistSize;
        const strx = r.u32(p);
        return strx < symtab.strsize ? r.cstr(symtab.stroff + strx) : '';
      }
    : () => '';

  // __stubs, __got, __la_symbol_ptr: each slot is one entry of the indirect symbol table.
  if (dysymtab && symtab) {
    for (const section of image.sections) {
      const type = section.flags & 0xff;
      // S_NON_LAZY_SYMBOL_POINTERS 6, S_LAZY_SYMBOL_POINTERS 7, S_SYMBOL_STUBS 8, S_THREAD_LOCAL_VARIABLE_POINTERS 0x14
      if (type !== 6 && type !== 7 && type !== 8 && type !== 0x14) continue;
      const stride = type === 8 ? section.reserved2 : ptrSize;
      if (!stride) continue;
      for (let k = 0; k * stride < section.size; k++) {
        const entry = section.reserved1 + k;
        if (entry >= dysymtab.nindirect) break;
        const index = r.u32(dysymtab.indirectoff + entry * 4);
        if (index & 0xc0000000) continue; // INDIRECT_SYMBOL_LOCAL / ABS
        if (index >= symtab.nsyms) continue;
        const name = allSymbols(index);
        if (name) image.stubs.set(section.addr + k * stride, name);
      }
    }
  }

  const libraryName = (ordinal: number): string => {
    if (ordinal === 0) return 'this image';
    if (ordinal === -1) return 'main executable';
    if (ordinal === -2) return 'flat lookup';
    if (ordinal === -3) return 'weak lookup';
    return image.libraries[ordinal - 1] ?? `library #${ordinal}`;
  };

  const imports = new Map<string, Import>();
  const addImport = (name: string, ordinal: number, slot?: number, weak?: boolean) => {
    if (!name) return;
    const key = `${name}@${slot ?? ''}`;
    if (!imports.has(key)) imports.set(key, { name, library: libraryName(ordinal), slot, weak });
    if (slot !== undefined && !image.stubs.has(slot)) image.stubs.set(slot, name);
  };

  if (dyldInfo) {
    for (const [range, lazy] of [[dyldInfo.bind, false], [dyldInfo.lazy, true], [dyldInfo.weak, false]] as const) {
      if (range[1]) runBindOpcodes(r, range[0], range[1], lazy, image.segments, ptrSize, addImport);
    }
  }
  if (chained?.[1] && is64) parseChainedFixups(r, chained[0], image, addImport);
  image.imports = [...imports.values()].sort((a, b) => a.name.localeCompare(b.name));

  const trie = exportsTrie ?? (dyldInfo?.exports[1] ? dyldInfo.exports : undefined);
  if (trie?.[1]) image.exports = parseExportTrie(r, trie[0], trie[1], image.base);

  if (functionStarts?.[1]) {
    const textSegment = image.segments.find((s) => s.name === '__TEXT');
    let addr = textSegment?.vmaddr ?? image.base;
    let p = functionStarts[0];
    const end = functionStarts[0] + functionStarts[1];
    while (p < end) {
      const [delta, next] = r.uleb(p);
      p = next;
      if (!delta) break;
      addr += delta;
      image.functionStarts.push(addr);
    }
  }

  if (dataInCode?.[1]) {
    for (let p = dataInCode[0]; p + 8 <= dataInCode[0] + dataInCode[1]; p += 8) {
      image.dataInCode.push({ addr: image.base + r.u32(p), length: r.u16(p + 4), kind: r.u16(p + 6) });
    }
  }

  if (signature?.[1]) {
    image.signatureAt = { offset: signature[0], size: signature[1] };
    image.signature = parseSignature(r, signature[0], signature[1]);
  }
  return image;
}

/** The pc a thread state starts at: LC_UNIXTHREAD holds one or more (flavor, count, registers) entries. */
function threadPc(r: Reader, at: number, size: number, cputype: number): number | undefined {
  let p = at + 8;
  while (p + 8 <= at + size) {
    const flavor = r.u32(p);
    const count = r.u32(p + 4);
    const state = p + 8;
    if (cputype === 7 && flavor === 1) return r.u32(state + 10 * 4); // x86_THREAD_STATE32: eip
    if (cputype === 12 && flavor === 1) return r.u32(state + 15 * 4); // ARM_THREAD_STATE: pc
    if (cputype === CPU_X86_64 && flavor === 4) return r.u64(state + 16 * 8); // x86_THREAD_STATE64: rip
    if (cputype === CPU_ARM64 && flavor === 6) return r.u64(state + 32 * 8); // ARM_THREAD_STATE64: pc
    p = state + count * 4;
  }
  return undefined;
}

function runBindOpcodes(
  r: Reader, start: number, size: number, lazy: boolean, segments: Segment[], ptrSize: number,
  add: (name: string, ordinal: number, slot?: number, weak?: boolean) => void,
): void {
  let p = start;
  const end = start + size;
  let ordinal = 0;
  let name = '';
  let weak = false;
  let segment = 0;
  let offset = 0;
  const slot = () => (segments[segment]?.vmaddr ?? 0) + offset;
  while (p < end) {
    const byte = r.u8(p++);
    const op = byte & 0xf0;
    const immediate = byte & 0x0f;
    switch (op) {
      case 0x00: // DONE
        if (!lazy) return;
        break;
      case 0x10:
        ordinal = immediate;
        break;
      case 0x20:
        [ordinal, p] = r.uleb(p);
        break;
      case 0x30:
        // SET_DYLIB_SPECIAL_IMM: 0 this image, then -1, -2, -3 sign-extended from four bits
        ordinal = immediate ? (immediate | ~0xf) | 0 : 0;
        break;
      case 0x40: {
        weak = !!(immediate & 1);
        const at = p;
        while (p < end && r.u8(p) !== 0) p++;
        name = utf8(r.bytes.subarray(at, p));
        p++;
        break;
      }
      case 0x50: // SET_TYPE
        break;
      case 0x60: // SET_ADDEND_SLEB
        [, p] = r.sleb(p);
        break;
      case 0x70:
        segment = immediate;
        [offset, p] = r.uleb(p);
        break;
      case 0x80: {
        let add2 = 0;
        [add2, p] = r.ulebStep(p);
        offset += add2;
        break;
      }
      case 0x90: // DO_BIND
        add(name, ordinal, slot(), weak);
        offset += ptrSize;
        break;
      case 0xa0: {
        add(name, ordinal, slot(), weak);
        let add2 = 0;
        [add2, p] = r.ulebStep(p);
        offset += ptrSize + add2;
        break;
      }
      case 0xb0:
        add(name, ordinal, slot(), weak);
        offset += ptrSize + immediate * ptrSize;
        break;
      case 0xc0: {
        let count = 0;
        let skip = 0;
        [count, p] = r.uleb(p);
        [skip, p] = r.ulebStep(p);
        for (let i = 0; i < count && i < 1 << 20; i++) {
          add(name, ordinal, slot(), weak);
          offset += ptrSize + skip;
        }
        break;
      }
      default:
        return;
    }
  }
}

/** dyld's chained fixups: the import table, and the chains that say which pointer binds to which import. */
function parseChainedFixups(
  r: Reader, start: number, image: MachO, add: (name: string, ordinal: number, slot?: number, weak?: boolean) => void,
): void {
  const startsOffset = r.u32(start + 4);
  const importsOffset = r.u32(start + 8);
  const symbolsOffset = r.u32(start + 12);
  const importsCount = r.u32(start + 16);
  const format = r.u32(start + 20);
  const names: { name: string; ordinal: number; weak: boolean }[] = [];
  for (let i = 0; i < importsCount; i++) {
    let ordinal: number;
    let weak: boolean;
    let nameOffset: number;
    if (format === 1) {
      const v = r.u32(start + importsOffset + i * 4);
      ordinal = v & 0xff;
      weak = !!(v & 0x100);
      nameOffset = v >>> 9;
      if (ordinal > 0xf0) ordinal = ordinal - 0x100;
    } else if (format === 2) {
      const at = start + importsOffset + i * 8;
      const v = r.u32(at);
      ordinal = v & 0xff;
      weak = !!(v & 0x100);
      nameOffset = v >>> 9;
      if (ordinal > 0xf0) ordinal = ordinal - 0x100;
    } else {
      const at = start + importsOffset + i * 16;
      const v = r.big64(at);
      ordinal = Number(v & 0xffffn);
      weak = !!(v & 0x10000n);
      nameOffset = Number(v >> 32n);
      if (ordinal > 0xfff0) ordinal = ordinal - 0x10000;
    }
    names.push({ name: r.cstr(start + symbolsOffset + nameOffset), ordinal, weak });
  }

  const segCount = r.u32(start + startsOffset);
  for (let s = 0; s < segCount; s++) {
    const segInfo = r.u32(start + startsOffset + 4 + s * 4);
    if (!segInfo) continue;
    const at = start + startsOffset + segInfo;
    const pageSize = r.u16(at + 4);
    const pointerFormat = r.u16(at + 6);
    const segmentOffset = r.u64(at + 8);
    const pageCount = r.u16(at + 20);
    const stride = pointerFormat === 1 || pointerFormat === 12 ? 8 : 4; // ARM64E (and its userland24) use 8-byte strides
    for (let page = 0; page < pageCount; page++) {
      const pageStart = r.u16(at + 22 + page * 2);
      if (pageStart === 0xffff) continue;
      if (pageStart & 0x8000) continue; // multiple starts (32-bit formats only)
      let offset = segmentOffset + page * pageSize + pageStart;
      for (let guard = 0; guard < 1 << 16; guard++) {
        if (offset + 8 > r.bytes.length) break;
        const raw = r.big64(offset);
        const addr = image.base + offset;
        let next: number;
        let bind = false;
        let ordinal = 0;
        let target: number;
        if (pointerFormat === 1 || pointerFormat === 9 || pointerFormat === 12) {
          // DYLD_CHAINED_PTR_ARM64E(_USERLAND/_USERLAND24): an authenticated rebase has a 32-bit offset, a plain one 43 bits.
          bind = !!(raw >> 62n & 1n);
          next = Number((raw >> 51n) & 0x7ffn);
          ordinal = Number(raw & (pointerFormat === 12 ? 0xffffffn : 0xffffn));
          target = Number(raw & (raw >> 63n ? 0xffffffffn : 0x7ffffffffffn));
        } else {
          // DYLD_CHAINED_PTR_64 / 64_OFFSET
          bind = !!(raw >> 63n);
          next = Number((raw >> 51n) & 0xfffn);
          ordinal = Number(raw & 0xffffffn);
          target = Number(raw & 0xfffffffffn);
        }
        if (bind) {
          const name = names[ordinal];
          if (name) add(name.name, name.ordinal, addr, name.weak);
        } else {
          // The formats differ in whether the target is an address or an offset from the base; the size tells.
          image.rebases.set(addr, target < image.base ? image.base + target : target);
        }
        if (!next) break;
        offset += next * stride;
      }
    }
  }
  for (const target of names) add(target.name, target.ordinal, undefined, target.weak);
}

function parseExportTrie(r: Reader, start: number, size: number, base: number): ExportedSymbol[] {
  const out: ExportedSymbol[] = [];
  const end = start + size;
  const stack: [number, string][] = [[start, '']];
  const seen = new Set<number>();
  while (stack.length && out.length < 1 << 20) {
    const [node, prefix] = stack.pop()!;
    if (node >= end || seen.has(node)) continue;
    seen.add(node);
    let [terminal, p] = r.uleb(node);
    const childrenAt = p + terminal;
    if (terminal) {
      let flags: number;
      [flags, p] = r.uleb(p);
      if (!(flags & 8)) {
        let offset: number;
        [offset, p] = r.uleb(p);
        out.push({ name: prefix, addr: base + offset, flags });
      }
    }
    p = childrenAt;
    const children = r.u8(p++);
    for (let c = 0; c < children; c++) {
      const at = p;
      while (p < end && r.u8(p) !== 0) p++;
      const edge = utf8(r.bytes.subarray(at, p));
      p++;
      let child: number;
      [child, p] = r.uleb(p);
      stack.push([start + child, prefix + edge]);
    }
  }
  return out.sort((a, b) => a.addr - b.addr);
}

const HASHES: Record<number, string> = { 1: 'SHA-1', 2: 'SHA-256', 3: 'SHA-256 (truncated)', 4: 'SHA-384' };

function parseSignature(r: Reader, start: number, size: number): CodeSignature | undefined {
  if (start + 12 > r.bytes.length || r.be32(start) !== 0xfade0cc0) return undefined;
  const out: CodeSignature = {};
  const count = r.be32(start + 8);
  for (let i = 0; i < count && i < 64; i++) {
    const offset = r.be32(start + 12 + i * 8 + 4);
    const at = start + offset;
    if (offset >= size) continue;
    const magic = r.be32(at);
    if (magic === 0xfade0c02 && !out.identifier) {
      const version = r.be32(at + 8);
      out.flags = r.be32(at + 12);
      out.identifier = r.cstr(at + r.be32(at + 20), 512);
      out.pages = r.be32(at + 28);
      out.hashType = HASHES[r.u8(at + 37)] ?? `hash ${r.u8(at + 37)}`;
      if (version >= 0x20200) {
        const team = r.be32(at + 48);
        if (team) out.teamId = r.cstr(at + team, 64);
      }
    } else if (magic === 0xfade7171) {
      const length = r.be32(at + 4);
      out.entitlements = utf8(r.bytes.subarray(at + 8, at + length));
    }
  }
  return out;
}

/** The section an address falls in. */
export function sectionAt(image: MachO, addr: number): Section | undefined {
  for (const section of image.sections) if (addr >= section.addr && addr < section.addr + section.size) return section;
  return undefined;
}

/** The file bytes behind a virtual address (none for zero-fill sections). */
export function bytesAt(image: MachO, addr: number, length: number): Uint8Array | undefined {
  const section = sectionAt(image, addr);
  if (!section || section.offset === 0) return undefined;
  const type = section.flags & 0xff;
  if (type === 1 || type === 0xc || type === 0x12) return undefined; // zerofill
  const at = section.offset + (addr - section.addr);
  const end = Math.min(at + length, section.offset + section.size);
  return image.bytes.subarray(at, end);
}

/** A NUL-terminated string at a virtual address, if the bytes there look like text. */
export function cstringAt(image: MachO, addr: number, max = 256): string | undefined {
  const bytes = bytesAt(image, addr, max);
  if (!bytes) return undefined;
  let end = 0;
  while (end < bytes.length && bytes[end] !== 0) end++;
  if (!end) return '';
  return utf8(bytes.subarray(0, end));
}

/** Reads a pointer at a virtual address (as stored: rebased pointers may carry chained-fixup bits); 4 bytes in a 32-bit file. */
export function pointerAt(image: MachO, addr: number): number | undefined {
  if (!image.is64) {
    const bytes = bytesAt(image, addr, 4);
    if (!bytes || bytes.length < 4) return undefined;
    return image.rebases.get(addr) ?? new DataView(bytes.buffer, bytes.byteOffset, 4).getUint32(0, true);
  }
  const bytes = bytesAt(image, addr, 8);
  if (!bytes || bytes.length < 8) return undefined;
  const rebased = image.rebases.get(addr);
  if (rebased !== undefined) return rebased;
  const raw = new DataView(bytes.buffer, bytes.byteOffset, 8).getBigUint64(0, true);
  // A chained rebase keeps the target in its low 36 bits — an address, or an offset from the base.
  if (raw >> 51n) {
    const target = Number(raw & 0xfffffffffn);
    return target < image.base ? image.base + target : target;
  }
  return Number(raw);
}
