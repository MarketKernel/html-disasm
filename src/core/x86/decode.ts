/**
 * The x86 decoder: bytes in, an instruction out, the way LLVM's X86
 * disassembler reads them — so that, printed (print.ts), it is the line
 * llvm-objdump prints in Intel syntax. tools/verify-x86.mjs checks it.
 *
 * The decoding goes in LLVM's steps. The prefixes give a set of attributes
 * (64-bit mode, REX.W, 66, F2/F3, VEX.L, EVEX.b…), and the attributes a
 * context; the opcode map, the context and the opcode select a decision,
 * which may need the ModR/M byte to settle on one instruction; the
 * instruction's operand specifiers say where each operand is encoded and
 * what it is. The tables for all of it are in tables.ts, generated from
 * LLVM's description of the target; this file is the reading of them.
 *
 * The result is a list of operands as LLVM's MCInst has them: a register
 * name, an immediate, or a memory reference as five of them (base, scale,
 * index, displacement, segment). The printer and the analysis work on that.
 */

import { inflateBase64 } from '../inflate';
import { BLOB, CONTEXT_COUNT, PARTS, SPECIAL } from './tables';

/* ------------------------------------------------------------------ *
 * The tables
 * ------------------------------------------------------------------ */

interface Tables {
  contexts: Uint8Array;
  ctxBlock: Uint16Array;
  blockTypes: Uint8Array;
  blockOffsets: Uint16Array;
  modrm: Uint16Array;
  opset: Uint16Array;
  template: Uint16Array;
  info: Uint32Array;
  sem: Uint32Array;
  sets: Uint8Array;
  pairs: Set<number>;
  templates: string[];
}

let tables: Tables | undefined;
let loading: Promise<void> | undefined;

function unpack(raw: Uint8Array): Tables {
  const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  const parts: Record<string, Uint8Array> = {};
  let at = 0;
  for (const name of PARTS) {
    const length = view.getUint32(at, true);
    parts[name] = raw.subarray(at + 4, at + 4 + length);
    at += 4 + ((length + 3) & ~3);
  }
  const u16 = (b: Uint8Array) => new Uint16Array(b.buffer, b.byteOffset, b.byteLength >> 1);
  const u32 = (b: Uint8Array) => new Uint32Array(b.buffer, b.byteOffset, b.byteLength >> 2);
  let text = '';
  const bytes = parts.templates!;
  for (let i = 0; i < bytes.length; i += 8192) text += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return {
    contexts: parts.contexts!,
    ctxBlock: u16(parts.ctxBlock!),
    blockTypes: parts.blockTypes!,
    blockOffsets: u16(parts.blockOffsets!),
    modrm: u16(parts.modrm!),
    opset: u16(parts.opset!),
    template: u16(parts.template!),
    info: u32(parts.info!),
    sem: u32(parts.sem!),
    sets: parts.sets!,
    pairs: new Set(u32(parts.pairs!)),
    templates: text.split('\0'),
  };
}

/** Inflates the tables; the decoder can be used once this has resolved. */
export function loadX86(): Promise<void> {
  loading ??= (async () => {
    tables = unpack(await inflateBase64(BLOB));
  })();
  return loading;
}

export function x86Tables(): Tables {
  if (!tables) throw new Error('the x86 tables are not loaded (loadX86)');
  return tables;
}

/* ------------------------------------------------------------------ *
 * Enums, as X86DisassemblerDecoderCommon.h numbers them
 * ------------------------------------------------------------------ */

const ENC = {
  NONE: 0, REG: 1, RM: 2, RM_CD64: 8, SIB: 9, VSIB: 10, VSIB_CD64: 16, VVVV: 17, WRITEMASK: 18, IB: 19, IW: 20, ID: 21, IO: 22,
  RB: 23, RW: 24, RD: 25, RO: 26, FP: 27, Iv: 28, Ia: 29, IRC: 30, Rv: 31, CC: 32, CF: 33, DUP: 34, SI: 35, DI: 36,
} as const;
export const TYPE = {
  NONE: 0, REL: 1, R8: 2, R16: 3, R32: 4, R64: 5, IMM: 6, UIMM8: 7, M: 8, MSIB: 9, MVSIBX: 10, MVSIBY: 11, MVSIBZ: 12, SRCIDX: 13, DSTIDX: 14,
  MOFFS: 15, ST: 16, MM64: 17, XMM: 18, YMM: 19, ZMM: 20, VK: 21, VK_PAIR: 22, TMM: 23, TMM_PAIR: 24, SEGMENTREG: 25, DEBUGREG: 26,
  CONTROLREG: 27, BNDR: 28, Rv: 29, RELv: 30, DUP0: 31,
} as const;
const ATTR = { BIT64: 1, XS: 2, XD: 4, REXW: 8, OPSIZE: 0x10, ADSIZE: 0x20, VEX: 0x40, VEXL: 0x80, EVEX: 0x100, EVEXL2: 0x200, EVEXK: 0x400, EVEXKZ: 0x800, EVEXB: 0x1000, REX2: 0x2000, EVEXNF: 0x4000, EVEXU: 0x8000 } as const;
const MAP = { ONEBYTE: 0, TWOBYTE: 1, THREEBYTE_38: 2, THREEBYTE_3A: 3, XOP8: 4, XOP9: 5, XOPA: 6, THREEDNOW: 7, MAP4: 8, MAP5: 9, MAP6: 10, MAP7: 11 } as const;
const VEXT = { NONE: 0, VEX2: 1, VEX3: 2, EVEX: 3, XOP: 4 } as const;
const SEG = ['', 'cs', 'ss', 'ds', 'es', 'fs', 'gs'] as const;

/** Bits of the generated `info` table (tools/x86-index.mjs). */
export const INFO = {
  MEMOP_SHIFT: 0, ADSIZE_SHIFT: 4, RAW_SHIFT: 6, LOCK: 1 << 8, NOTRACK: 1 << 9, NF: 1 << 10, EXPLICIT_VEX: 1 << 11, EXPLICIT_EVEX: 1 << 12,
  NAME64: 1 << 13, VCMP_SHIFT: 14, SRCMEM: 1 << 17, XS: 1 << 18, XD: 1 << 19, TA: 1 << 20, EVEX_K: 1 << 21, EVEX_B: 1 << 22, REX_W: 1 << 23,
  EVEX_L2: 1 << 24, VEX_L: 1 << 25, SUFFIX_SHIFT: 26, CCMP: 1 << 30,
} as const;
/** Bits of the generated `sem` table: what an instruction does, for the analysis. */
export const SEM = { CALL: 1, BRANCH: 2, RET: 4, INDIRECT: 8, COND: 16, BARRIER: 32, TRAP: 64, LOAD: 128, STORE: 256, SETS_FLAGS: 512, READS_FLAGS: 1024, PREFIX: 2048 } as const;

/**
 * LLVM's `Reg` enum (ALL_REGS) as names: the decoder adds field values to
 * the start of a class, so the order matters.
 */
const GPR8 = ['al', 'cl', 'dl', 'bl', 'ah', 'ch', 'dh', 'bh', ...Array.from({ length: 24 }, (_, i) => `r${i + 8}b`), 'spl', 'bpl', 'sil', 'dil'];
const GPR16 = ['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di', ...Array.from({ length: 24 }, (_, i) => `r${i + 8}w`)];
const GPR32 = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi', ...Array.from({ length: 24 }, (_, i) => `r${i + 8}d`)];
const GPR64 = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi', ...Array.from({ length: 24 }, (_, i) => `r${i + 8}`)];
const n32 = (prefix: string, count = 32) => Array.from({ length: count }, (_, i) => `${prefix}${i}`);
const ALL_REGS = [
  ...GPR8, ...GPR16, ...GPR32, ...GPR64, ...n32('mm', 8), ...n32('xmm'), ...n32('ymm'), ...n32('zmm'), ...n32('k', 8),
  // The pairs have no assembler names, so LLVM prints their record names (only an out-of-range field reaches them).
  'K0_K1', 'K2_K3', 'K4_K5', 'K6_K7', 'es', 'cs', 'ss', 'ds', 'fs', 'gs', ...n32('dr', 16), ...n32('cr', 16), ...n32('tmm', 8),
  'TMM0_TMM1', 'TMM2_TMM3', 'TMM4_TMM5', 'TMM6_TMM7', 'rip',
];
const R = (name: string): number => ALL_REGS.indexOf(name);
const REG = { AL: R('al'), SPL: R('spl'), AX: R('ax'), EAX: R('eax'), RAX: R('rax'), MM0: R('mm0'), XMM0: R('xmm0'), YMM0: R('ymm0'), ZMM0: R('zmm0'), K0: R('k0'), K0_K1: R('K0_K1'), ES: R('es'), DR0: R('dr0'), CR0: R('cr0'), TMM0: R('tmm0'), TMM0_TMM1: R('TMM0_TMM1') };

// EABase: none, the 16-, 32- and 64-bit bases (with `sib` in place of esp/rsp), then the registers.
const EA_BASES_16 = ['bx_si', 'bx_di', 'bp_si', 'bp_di', 'si', 'di', 'bp', 'bx', ...GPR16.slice(8)];
const EA_BASES_32 = ['eax', 'ecx', 'edx', 'ebx', 'sib', 'ebp', 'esi', 'edi', ...GPR32.slice(8)];
const EA_BASES_64 = ['rax', 'rcx', 'rdx', 'rbx', 'sib64', 'rbp', 'rsi', 'rdi', ...GPR64.slice(8)];
const EA = { NONE: 0, BX_SI: 1, EAX: 33, SIB: 37, RAX: 65, SIB64: 69, REG: 97 } as const;
const eaName = (base: number): string => (base <= 32 ? EA_BASES_16[base - 1]! : base <= 64 ? EA_BASES_32[base - 33]! : EA_BASES_64[base - 65]!);
// SIBIndex: none, the EA bases, then xmm, ymm, zmm. SIBBase: none, then the 32- and 64-bit registers.
const SIB_INDEX = { NONE: 0, EAX: 33, RAX: 65, XMM0: 97, YMM0: 129, ZMM0: 161 } as const;
const SIB_BASE = { NONE: 0, EAX: 1, RAX: 33 } as const;
const sibIndexName = (index: number): string | undefined => {
  if (index >= SIB_INDEX.EAX && index < SIB_INDEX.XMM0) return eaName(index);
  if (index >= SIB_INDEX.XMM0 && index < SIB_INDEX.YMM0) return `xmm${index - SIB_INDEX.XMM0}`;
  if (index >= SIB_INDEX.YMM0 && index < SIB_INDEX.ZMM0) return `ymm${index - SIB_INDEX.YMM0}`;
  if (index >= SIB_INDEX.ZMM0 && index < SIB_INDEX.ZMM0 + 32) return `zmm${index - SIB_INDEX.ZMM0}`;
  return undefined;
};
const sibBaseName = (base: number): string => (base <= 32 ? GPR32[base - 1]! : GPR64[base - 33]!);

/* ------------------------------------------------------------------ *
 * The decoded instruction
 * ------------------------------------------------------------------ */

/** A register name ('' for none), or an immediate (a bigint only when it took 8 bytes). */
export type McOp = string | number | bigint;

export interface X86Decoded {
  /** The instruction, in the tables' dense numbering; 0 when the bytes do not decode. */
  id: number;
  /** Bytes taken — on failure, the bytes read before it failed (at least 1), as llvm-objdump skips them. */
  length: number;
  addr: number;
  mode: 64 | 32;
  ops: McOp[];
  /** Which operand specifier each MCInst operand came from (its type), for the analysis. */
  types: number[];
  /** Prefix flags the printer reads: lock, rep, repne, addr32. */
  flags: number;
  /** rep/repne before a locked instruction or xchg: printed as xrelease/xacquire. */
  xacquire: boolean;
}

export const PFX = { AD_SIZE: 1, LOCK: 2, REPEAT: 4, REPEAT_NE: 8 } as const;

class Insn {
  bytes: Uint8Array;
  start: number;
  end: number;
  cursor: number;
  mode: 64 | 32;
  mandatoryPrefix = 0;
  vex = [0, 0, 0, 0];
  vexType: number = VEXT.NONE;
  rex2 = [0, 0];
  rex = 0;
  segment = 0;
  xAcquireRelease = false;
  hasAdSize = false;
  hasOpSize = false;
  hasLock = false;
  repeat = 0;
  registerSize = 0;
  addressSize = 0;
  displacementSize = 0;
  immediateSize = 0;
  opcode = 0;
  map = 0;
  id = 0;
  vvvv = 0;
  writemask = 0;
  consumedModRM = false;
  modRM = 0;
  sib = 0;
  displacement = 0;
  eaDisplacement = 0; // 0 none, 1 disp8, 2 disp16, 3 disp32
  immediates: (number | bigint)[] = [0, 0, 0];
  immCount = 0;
  immTranslated = 0;
  opcodeRegister = 0;
  eaRegBase = 0;
  regBase = 0;
  eaBase = 0;
  reg = 0;
  sibIndexBase = 0;
  sibIndex = 0;
  sibScale = 0;
  sibBase = 0;
  rc = 0;

  constructor(bytes: Uint8Array, start: number, end: number, mode: 64 | 32) {
    this.bytes = bytes;
    this.start = start;
    this.end = end;
    this.cursor = start;
    this.mode = mode;
  }

  /** The next byte without taking it, or -1 at the end. */
  peek(): number {
    return this.cursor < this.end ? this.bytes[this.cursor]! : -1;
  }

  /** Takes the next byte, or returns -1 (and takes nothing) at the end. */
  byte(): number {
    return this.cursor < this.end ? this.bytes[this.cursor++]! : -1;
  }

  /** Takes a little-endian value of 1, 2 or 4 bytes (unsigned), or -1. */
  take(size: 1 | 2 | 4): number {
    if (this.cursor + size > this.end) return -1;
    const b = this.bytes;
    const at = this.cursor;
    this.cursor += size;
    if (size === 1) return b[at]!;
    if (size === 2) return b[at]! | (b[at + 1]! << 8);
    return (b[at]! | (b[at + 1]! << 8) | (b[at + 2]! << 16) | (b[at + 3]! << 24)) >>> 0;
  }

  isREX(b: number): boolean {
    return this.mode === 64 && b >= 0x40 && b <= 0x4f;
  }

  isREX2(b: number): boolean {
    return this.mode === 64 && b === 0xd5;
  }

  // REX, REX2 and the vector prefixes' fields.
  get rexW(): number { return (this.rex >> 3) & 1; }
  get rexR(): number { return (this.rex >> 2) & 1; }
  get rexX(): number { return (this.rex >> 1) & 1; }
  get rexB(): number { return this.rex & 1; }
  get rex2M(): number { return (this.rex2[1]! >> 7) & 1; }
  get rex2R2(): number { return (this.rex2[1]! >> 6) & 1; }
  get rex2X2(): number { return (this.rex2[1]! >> 5) & 1; }
  get rex2B2(): number { return (this.rex2[1]! >> 4) & 1; }
}

const inv = (v: number, bit: number) => (~v >> bit) & 1;

function readPrefixes(insn: Insn): number {
  let isPrefix = true;
  let byte = 0;
  while (isPrefix) {
    const b = insn.byte();
    if (b < 0) break;
    byte = b;
    // A LOCK first is an instruction of its own.
    if (insn.cursor - 1 === insn.start && byte === 0xf0) break;
    const next = insn.peek();
    if ((byte === 0xf2 || byte === 0xf3) && next >= 0) {
      // Before a LOCK or an xchg they are xacquire/xrelease, not repne/rep.
      if (next === 0xf0 || (next & 0xfe) === 0x86 || (next & 0xf8) === 0x90) {
        insn.xAcquireRelease = true;
        if (!(byte === 0xf3 && next === 0x90)) break;
      }
      if (byte === 0xf3 && (next === 0x88 || next === 0x89 || next === 0xc6 || next === 0xc7)) {
        insn.xAcquireRelease = true;
        break;
      }
      if (insn.isREX(next)) {
        insn.cursor++;
        if (insn.peek() < 0) return -1;
        insn.cursor--;
      }
    }
    switch (byte) {
      case 0xf0:
        insn.hasLock = true;
        break;
      case 0xf2:
      case 0xf3: {
        const nb = insn.peek();
        if (nb < 0) break;
        if (insn.isREX(nb) || insn.isREX2(nb) || nb === 0x0f || nb === 0x66) insn.mandatoryPrefix = byte;
        insn.repeat = byte;
        break;
      }
      case 0x2e:
        insn.segment = 1;
        break;
      case 0x36:
        insn.segment = 2;
        break;
      case 0x3e:
        insn.segment = 3;
        break;
      case 0x26:
        insn.segment = 4;
        break;
      case 0x64:
        insn.segment = 5;
        break;
      case 0x65:
        insn.segment = 6;
        break;
      case 0x66: {
        insn.hasOpSize = true;
        const nb = insn.peek();
        if (nb < 0) break;
        if (!insn.mandatoryPrefix && (nb === 0x0f || insn.isREX(nb))) insn.mandatoryPrefix = byte;
        break;
      }
      case 0x67:
        insn.hasAdSize = true;
        break;
      default:
        isPrefix = false;
        break;
    }
    if (insn.isREX(byte)) {
      insn.rex = byte;
      isPrefix = true;
    } else if (isPrefix) insn.rex = 0;
  }

  insn.vexType = VEXT.NONE;
  const v = insn.vex;
  if (byte === 0x62) {
    const b1 = insn.byte();
    if (b1 < 0) return -1;
    if (insn.peek() < 0) return -1;
    if (insn.mode === 64 || (b1 & 0xc0) === 0xc0) insn.vexType = VEXT.EVEX;
    else insn.cursor -= 2;
    if (insn.vexType === VEXT.EVEX) {
      v[0] = byte;
      v[1] = b1;
      const b2 = insn.byte();
      if (b2 < 0) return -1;
      v[2] = b2;
      const b3 = insn.byte();
      if (b3 < 0) return -1;
      v[3] = b3;
      if (insn.mode === 64) {
        insn.rex = 0x40 | (((v[2] >> 7) & 1) << 3) | (inv(v[1], 7) << 2) | (inv(v[1], 6) << 1) | inv(v[1], 5);
        insn.rex2[1] = (inv(v[1], 4) << 6) | (inv(v[2], 2) << 5) | (((v[1] >> 3) & 1) << 4);
      }
    }
  } else if (byte === 0xc4) {
    const b1 = insn.peek();
    if (b1 < 0) return -1;
    if (insn.mode === 64 || (b1 & 0xc0) === 0xc0) insn.vexType = VEXT.VEX3;
    else insn.cursor--;
    if (insn.vexType === VEXT.VEX3) {
      v[0] = byte;
      v[1] = Math.max(insn.byte(), 0);
      v[2] = Math.max(insn.byte(), 0);
      if (insn.mode === 64) insn.rex = 0x40 | (((v[2] >> 7) & 1) << 3) | (inv(v[1], 7) << 2) | (inv(v[1], 6) << 1) | inv(v[1], 5);
    }
  } else if (byte === 0xc5) {
    const b1 = insn.peek();
    if (b1 < 0) return -1;
    if (insn.mode === 64 || (b1 & 0xc0) === 0xc0) insn.vexType = VEXT.VEX2;
    else insn.cursor--;
    if (insn.vexType === VEXT.VEX2) {
      v[0] = byte;
      v[1] = Math.max(insn.byte(), 0);
      if (insn.mode === 64) insn.rex = 0x40 | (inv(v[1], 7) << 2);
      if ((v[1] & 3) === 1) insn.hasOpSize = true;
    }
  } else if (byte === 0x8f) {
    const b1 = insn.peek();
    if (b1 < 0) return -1;
    if ((b1 & 0x38) !== 0) insn.vexType = VEXT.XOP;
    else insn.cursor--;
    if (insn.vexType === VEXT.XOP) {
      v[0] = byte;
      v[1] = Math.max(insn.byte(), 0);
      v[2] = Math.max(insn.byte(), 0);
      if (insn.mode === 64) insn.rex = 0x40 | (((v[2] >> 7) & 1) << 3) | (inv(v[1], 7) << 2) | (inv(v[1], 6) << 1) | inv(v[1], 5);
      if ((v[2] & 3) === 1) insn.hasOpSize = true;
    }
  } else if (insn.isREX2(byte)) {
    if (insn.peek() < 0) return -1;
    insn.rex2[0] = byte;
    insn.rex2[1] = Math.max(insn.byte(), 0);
    const r2 = insn.rex2[1];
    insn.rex = 0x40 | (((r2 >> 3) & 1) << 3) | (((r2 >> 2) & 1) << 2) | (((r2 >> 1) & 1) << 1) | (r2 & 1);
  } else insn.cursor--;

  if (insn.mode === 32) {
    insn.registerSize = insn.hasOpSize ? 2 : 4;
    insn.addressSize = insn.hasAdSize ? 2 : 4;
    insn.displacementSize = insn.hasAdSize ? 2 : 4;
    insn.immediateSize = insn.hasOpSize ? 2 : 4;
  } else {
    insn.displacementSize = 4;
    if (insn.rex && insn.rexW) {
      insn.registerSize = 8;
      insn.addressSize = insn.hasAdSize ? 4 : 8;
      insn.immediateSize = 4;
      insn.hasOpSize = false;
    } else {
      insn.registerSize = insn.hasOpSize ? 2 : 4;
      insn.addressSize = insn.hasAdSize ? 4 : 8;
      insn.immediateSize = insn.hasOpSize ? 2 : 4;
    }
  }
  return 0;
}

function readSIB(insn: Insn): number {
  let sibBaseBase: number;
  if (insn.addressSize === 4) {
    insn.sibIndexBase = SIB_INDEX.EAX;
    sibBaseBase = SIB_BASE.EAX;
  } else {
    insn.sibIndexBase = SIB_INDEX.RAX;
    sibBaseBase = SIB_BASE.RAX;
  }
  const sib = insn.byte();
  if (sib < 0) return -1;
  insn.sib = sib;
  const index = ((sib >> 3) & 7) | (insn.rexX << 3) | (insn.rex2X2 << 4);
  insn.sibIndex = index === 4 ? SIB_INDEX.NONE : insn.sibIndexBase + index;
  insn.sibScale = 1 << (sib >> 6);
  const base = (sib & 7) | (insn.rexB << 3) | (insn.rex2B2 << 4);
  if (base === 5 || base === 0xd) {
    switch (insn.modRM >> 6) {
      case 0:
        insn.eaDisplacement = 3;
        insn.sibBase = SIB_BASE.NONE;
        break;
      case 1:
        insn.eaDisplacement = 1;
        insn.sibBase = sibBaseBase + base;
        break;
      default:
        insn.eaDisplacement = 3;
        insn.sibBase = sibBaseBase + base;
        break;
    }
  } else insn.sibBase = sibBaseBase + base;
  return 0;
}

function readDisplacement(insn: Insn): number {
  switch (insn.eaDisplacement) {
    case 1: {
      const d = insn.take(1);
      if (d < 0) return -1;
      insn.displacement = (d << 24) >> 24;
      break;
    }
    case 2: {
      const d = insn.take(2);
      if (d < 0) return -1;
      insn.displacement = (d << 16) >> 16;
      break;
    }
    case 3: {
      const d = insn.take(4);
      if (d < 0) return -1;
      insn.displacement = d | 0;
      break;
    }
  }
  return 0;
}

function readModRM(insn: Insn): number {
  if (insn.consumedModRM) return 0;
  const m = insn.byte();
  if (m < 0) return -1;
  insn.modRM = m;
  insn.consumedModRM = true;
  const mod = m >> 6;
  let rm = m & 7;
  let reg = (m >> 3) & 7;
  switch (insn.registerSize) {
    case 2:
      insn.regBase = REG.AX;
      insn.eaRegBase = EA.REG + REG.AX;
      break;
    case 4:
      insn.regBase = REG.EAX;
      insn.eaRegBase = EA.REG + REG.EAX;
      break;
    case 8:
      insn.regBase = REG.RAX;
      insn.eaRegBase = EA.REG + REG.RAX;
      break;
  }
  reg |= (insn.rexR << 3) | (insn.rex2R2 << 4);
  rm |= (insn.rexB << 3) | (insn.rex2B2 << 4);
  if (insn.vexType === VEXT.EVEX && insn.mode === 64) reg |= inv(insn.vex[1]!, 4) << 4;
  insn.reg = insn.regBase + reg;

  if (insn.addressSize === 2) {
    switch (mod) {
      case 0:
        if (rm === 6) {
          insn.eaBase = EA.NONE;
          insn.eaDisplacement = 2;
          if (readDisplacement(insn)) return -1;
        } else {
          insn.eaBase = EA.BX_SI + rm;
          insn.eaDisplacement = 0;
        }
        break;
      case 1:
        insn.eaBase = EA.BX_SI + rm;
        insn.eaDisplacement = 1;
        insn.displacementSize = 1;
        if (readDisplacement(insn)) return -1;
        break;
      case 2:
        insn.eaBase = EA.BX_SI + rm;
        insn.eaDisplacement = 2;
        if (readDisplacement(insn)) return -1;
        break;
      case 3:
        insn.eaBase = insn.eaRegBase + rm;
        if (readDisplacement(insn)) return -1;
        break;
    }
    return 0;
  }
  const eaBaseBase = insn.addressSize === 4 ? EA.EAX : EA.RAX;
  switch (mod) {
    case 0:
      insn.eaDisplacement = 0;
      switch (rm & 7) {
        case 4:
          insn.eaBase = insn.addressSize === 4 ? EA.SIB : EA.SIB64;
          if (readSIB(insn) || readDisplacement(insn)) return -1;
          break;
        case 5:
          insn.eaBase = EA.NONE;
          insn.eaDisplacement = 3;
          if (readDisplacement(insn)) return -1;
          break;
        default:
          insn.eaBase = eaBaseBase + rm;
          break;
      }
      break;
    case 1:
    case 2:
      if (mod === 1) insn.displacementSize = 1;
      insn.eaDisplacement = mod === 1 ? 1 : 3;
      if ((rm & 7) === 4) {
        insn.eaBase = EA.SIB;
        if (readSIB(insn) || readDisplacement(insn)) return -1;
      } else {
        insn.eaBase = eaBaseBase + rm;
        if (readDisplacement(insn)) return -1;
      }
      break;
    case 3:
      insn.eaDisplacement = 0;
      insn.eaBase = insn.eaRegBase + rm;
      break;
  }
  return 0;
}

/** fixupRegValue / fixupRMValue: a field's value as a register of the operand's type, or -1 when invalid. */
function fixupValue(insn: Insn, type: number, index: number, base: number): number {
  switch (type) {
    case TYPE.Rv:
      return base + index;
    case TYPE.R8:
      return insn.rex && index >= 4 && index <= 7 ? REG.SPL + (index - 4) : REG.AL + index;
    case TYPE.R16:
      return REG.AX + index;
    case TYPE.R32:
      return REG.EAX + index;
    case TYPE.R64:
      return REG.RAX + index;
    case TYPE.ZMM:
    case TYPE.MVSIBZ:
      return REG.ZMM0 + index;
    case TYPE.YMM:
    case TYPE.MVSIBY:
      return REG.YMM0 + index;
    case TYPE.XMM:
    case TYPE.MVSIBX:
      return REG.XMM0 + index;
    case TYPE.TMM:
      return index > 7 ? -1 : REG.TMM0 + index;
    case TYPE.TMM_PAIR:
      return index > 7 ? -1 : REG.TMM0_TMM1 + (index >> 1);
    case TYPE.VK:
      index &= 0xf;
      return index > 7 ? -1 : REG.K0 + index;
    case TYPE.VK_PAIR:
      return index > 7 ? -1 : REG.K0_K1 + (index >> 1);
    case TYPE.MM64:
      return REG.MM0 + (index & 7);
    case TYPE.SEGMENTREG:
      return (index & 7) > 5 ? -1 : REG.ES + (index & 7);
    case TYPE.DEBUGREG:
      return index > 15 ? -1 : REG.DR0 + index;
    case TYPE.CONTROLREG:
      return index > 15 ? -1 : REG.CR0 + index;
  }
  return -1;
}

function fixupReg(insn: Insn, encoding: number, type: number): number {
  if (encoding === ENC.VVVV) {
    const v = fixupValue(insn, type, insn.vvvv, insn.regBase);
    if (v < 0) return -1;
    insn.vvvv = v;
  } else if (encoding === ENC.REG) {
    const v = fixupValue(insn, type, insn.reg - insn.regBase, insn.regBase);
    if (v < 0) return -1;
    insn.reg = v;
  } else if ((encoding >= ENC.RM && encoding <= ENC.RM_CD64) || encoding === ENC.SIB) {
    if (encoding !== ENC.SIB && insn.vexType === VEXT.EVEX && insn.mode === 64 && insn.modRM >> 6 === 3) {
      // EVEX.X extends a vector register in r/m to 32.
      if (type !== TYPE.Rv && type !== TYPE.R8 && type !== TYPE.R16 && type !== TYPE.R32 && type !== TYPE.R64) insn.eaBase += inv(insn.vex[1]!, 6) << 4;
    }
    if (insn.eaBase >= insn.eaRegBase) {
      const v = fixupValue(insn, type, insn.eaBase - insn.eaRegBase, insn.eaRegBase - EA.REG);
      if (v < 0) return -1;
      insn.eaBase = EA.REG + v;
    }
  } else return -1;
  return 0;
}

function readOpcode(insn: Insn): boolean {
  insn.map = MAP.ONEBYTE;
  const take = () => {
    const b = insn.byte();
    if (b < 0) return true;
    insn.opcode = b;
    return false;
  };
  const v = insn.vex;
  if (insn.vexType === VEXT.EVEX) {
    const mmm = v[1]! & 7;
    const map = [-1, MAP.TWOBYTE, MAP.THREEBYTE_38, MAP.THREEBYTE_3A, MAP.MAP4, MAP.MAP5, MAP.MAP6, MAP.MAP7][mmm]!;
    if (map < 0) return true;
    insn.map = map;
    return take();
  } else if (insn.vexType === VEXT.VEX3) {
    const map = [-1, MAP.TWOBYTE, MAP.THREEBYTE_38, MAP.THREEBYTE_3A, -1, MAP.MAP5, MAP.MAP6, MAP.MAP7][v[1]! & 0x1f] ?? -1;
    if (map < 0) return true;
    insn.map = map;
    return take();
  } else if (insn.vexType === VEXT.VEX2) {
    insn.map = MAP.TWOBYTE;
    return take();
  } else if (insn.vexType === VEXT.XOP) {
    const sel = v[1]! & 0x1f;
    if (sel < 8 || sel > 10) return true;
    insn.map = MAP.XOP8 + (sel - 8);
    return take();
  } else if (insn.rex2M) {
    insn.map = MAP.TWOBYTE;
    return take();
  }
  let current = insn.byte();
  if (current < 0) return true;
  if (current === 0x0f) {
    current = insn.byte();
    if (current < 0) return true;
    if (current === 0x38) {
      current = insn.byte();
      if (current < 0) return true;
      insn.map = MAP.THREEBYTE_38;
    } else if (current === 0x3a) {
      current = insn.byte();
      if (current < 0) return true;
      insn.map = MAP.THREEBYTE_3A;
    } else if (current === 0x0f) {
      // 3DNow!: the ModR/M byte (and what follows it) comes before the opcode.
      if (readModRM(insn)) return true;
      current = insn.byte();
      if (current < 0) return true;
      insn.map = MAP.THREEDNOW;
    } else insn.map = MAP.TWOBYTE;
  } else if (insn.mandatoryPrefix) insn.mandatoryPrefix = 0;
  insn.opcode = current;
  return false;
}

/** The instruction an attribute mask selects for the opcode read (0 if none), reading the ModR/M byte when the decision needs it; -1 on running out of bytes. */
function idWithAttrMask(insn: Insn, attrMask: number): number {
  const t = tables!;
  const ctx = t.contexts[attrMask]!;
  const block = t.ctxBlock[insn.map * CONTEXT_COUNT + ctx]!;
  if (!block) return 0;
  const at = (block - 1) * 256 + insn.opcode;
  const type = t.blockTypes[at]!;
  const off = t.blockOffsets[at]!;
  if (type === 0) return t.modrm[off]!;
  if (readModRM(insn)) return -1;
  const m = insn.modRM;
  const mod3 = m >> 6 === 3;
  switch (type) {
    case 1:
      return t.modrm[off + (mod3 ? 1 : 0)]!;
    case 2:
      return t.modrm[off + (mod3 ? (m & 0x3f) + 8 : (m & 0x38) >> 3)]!;
    case 3:
      return t.modrm[off + (mod3 ? ((m & 0x38) >> 3) + 8 : (m & 0x38) >> 3)]!;
    default:
      return t.modrm[off + m]!;
  }
}

function isCCMPOrCTEST(insn: Insn): boolean {
  if (insn.map !== MAP.MAP4) return false;
  const reg = (insn.modRM >> 3) & 7;
  if (insn.opcode === 0x83 && reg === 7) return true;
  switch (insn.opcode & 0xfe) {
    case 0x38:
    case 0x3a:
    case 0x84:
      return true;
    case 0x80:
      return reg === 7;
    case 0xf6:
      return reg === 0;
  }
  return false;
}

function isNF(insn: Insn): boolean {
  if (!((insn.vex[3]! >> 2) & 1)) return false;
  if (insn.map === MAP.MAP4) return true;
  if (insn.map === MAP.THREEBYTE_38 && (insn.vex[2]! & 3) === 0) {
    switch (insn.opcode) {
      case 0xf2:
      case 0xf3:
      case 0xf5:
      case 0xf7:
        return true;
    }
  }
  return false;
}

function getInstructionID(insn: Insn): number {
  const t = tables!;
  let attrMask = 0;
  if (insn.mode === 64) attrMask |= ATTR.BIT64;
  const v = insn.vex;
  if (insn.vexType !== VEXT.NONE) {
    attrMask |= insn.vexType === VEXT.EVEX ? ATTR.EVEX : ATTR.VEX;
    const pp = insn.vexType === VEXT.VEX2 ? v[1]! & 3 : v[2]! & 3;
    if (pp === 1) attrMask |= ATTR.OPSIZE;
    else if (pp === 2) attrMask |= ATTR.XS;
    else if (pp === 3) attrMask |= ATTR.XD;
    if (insn.vexType === VEXT.EVEX) {
      if ((v[3]! >> 7) & 1) attrMask |= ATTR.EVEXKZ;
      if (isNF(insn) && !readModRM(insn) && !isCCMPOrCTEST(insn)) attrMask |= ATTR.EVEXNF;
      else if (v[3]! & 7 && insn.map !== MAP.MAP4) attrMask |= ATTR.EVEXK;
      if ((v[3]! >> 4) & 1) {
        attrMask |= ATTR.EVEXB;
        if (inv(v[2]!, 2) && !readModRM(insn) && insn.modRM >> 6 === 3) attrMask |= ATTR.EVEXU;
      }
      if ((v[3]! >> 5) & 1) attrMask |= ATTR.VEXL;
      if ((v[3]! >> 6) & 1) attrMask |= ATTR.EVEXL2;
    } else if (insn.vexType === VEXT.VEX3) {
      if ((v[2]! >> 2) & 1) attrMask |= ATTR.VEXL;
    } else if (insn.vexType === VEXT.VEX2) {
      if (pp === 1 && insn.hasAdSize) attrMask |= ATTR.ADSIZE;
      if ((v[1]! >> 2) & 1) attrMask |= ATTR.VEXL;
    } else {
      if ((v[2]! >> 2) & 1) attrMask |= ATTR.VEXL;
    }
  } else if (!insn.mandatoryPrefix) {
    if (insn.hasOpSize) attrMask |= ATTR.OPSIZE;
    if (insn.hasAdSize) attrMask |= ATTR.ADSIZE;
    if (insn.map === MAP.ONEBYTE) {
      if (insn.repeat === 0xf3 && insn.opcode === 0x90) attrMask |= ATTR.XS;
    } else if (insn.repeat === 0xf2) attrMask |= ATTR.XD;
    else if (insn.repeat === 0xf3) attrMask |= ATTR.XS;
  } else {
    switch (insn.mandatoryPrefix) {
      case 0xf2:
        attrMask |= ATTR.XD;
        break;
      case 0xf3:
        attrMask |= ATTR.XS;
        break;
      case 0x66:
        attrMask |= ATTR.OPSIZE;
        if (insn.hasAdSize) attrMask |= ATTR.ADSIZE;
        break;
      case 0x67:
        attrMask |= ATTR.ADSIZE;
        break;
    }
  }
  if (insn.rex & 0x08) {
    attrMask |= ATTR.REXW;
    attrMask &= ~ATTR.ADSIZE;
  }
  // Absolute jump and pushp/popp.
  if (insn.rex2[0] === 0xd5 && insn.map === MAP.ONEBYTE && (insn.opcode === 0xa1 || (insn.opcode & 0xf0) === 0x50)) attrMask |= ATTR.REX2;

  let id = idWithAttrMask(insn, attrMask);
  if (id < 0) return -1;

  // The tables cannot tell W selecting the register size from W being part of the opcode outside 64-bit mode.
  if (insn.mode !== 64 && insn.vexType !== VEXT.NONE) {
    const w = insn.vexType === VEXT.VEX2 ? 0 : (v[2]! >> 7) & 1;
    if (w && insn.vexType !== VEXT.VEX2) {
      const withW = idWithAttrMask(insn, attrMask | ATTR.REXW);
      if (withW < 0) {
        insn.id = id;
        return 0;
      }
      if (!(t.info[withW]! & INFO.NAME64)) {
        insn.id = withW;
        return 0;
      }
    }
  }

  // Absolute moves, umonitor and movdir64b: the prefixes count wherever they are.
  if ((insn.map === MAP.ONEBYTE && (insn.opcode & 0xfc) === 0xa0) || (insn.map === MAP.TWOBYTE && insn.opcode === 0xae) || (insn.map === MAP.THREEBYTE_38 && insn.opcode === 0xf8) || (insn.map === MAP.MAP4 && insn.opcode === 0xf8)) {
    if (insn.hasAdSize) attrMask |= ATTR.ADSIZE;
    if (insn.hasOpSize) attrMask |= ATTR.OPSIZE;
    id = idWithAttrMask(insn, attrMask);
    if (id < 0) return -1;
    insn.id = id;
    return 0;
  }

  if (insn.hasOpSize && !(attrMask & ATTR.OPSIZE)) {
    // OpSize out of its place: take the 16-bit form when there is one.
    const withOpSize = idWithAttrMask(insn, attrMask | ATTR.OPSIZE);
    if (withOpSize < 0) {
      insn.id = id;
      return 0;
    }
    insn.id = t.pairs.has(id * 65536 + withOpSize) ? withOpSize : id;
    return 0;
  }

  if (insn.map === MAP.ONEBYTE && insn.opcode === 0x90 && insn.rex & 1) {
    // With REX.B, 90 is xchg r8, eax, not a nop: borrow the opcode of the other xchg forms.
    insn.opcode = 0x91;
    const xchg = idWithAttrMask(insn, attrMask);
    insn.opcode = 0x90;
    insn.id = xchg < 0 ? id : xchg;
    return 0;
  }
  insn.id = id;
  return 0;
}

function readOpcodeRegister(insn: Insn, size: number): void {
  if (size === 0) size = insn.registerSize;
  const index = (insn.rexB << 3) | (insn.rex2B2 << 4) | (insn.opcode & 7);
  switch (size) {
    case 1:
      insn.opcodeRegister = REG.AL + index;
      if (insn.rex && index >= 4 && index < 8) insn.opcodeRegister = REG.SPL + (index - 4);
      break;
    case 2:
      insn.opcodeRegister = REG.AX + index;
      break;
    case 4:
      insn.opcodeRegister = REG.EAX + index;
      break;
    case 8:
      insn.opcodeRegister = REG.RAX + index;
      break;
  }
}

function readImmediate(insn: Insn, size: number): number {
  insn.immediateSize = size;
  let value: number | bigint;
  if (size === 8) {
    if (insn.cursor + 8 > insn.end) return -1;
    const lo = insn.take(4);
    const hi = insn.take(4);
    value = (BigInt(hi) << 32n) | BigInt(lo);
  } else {
    const v = insn.take(size as 1 | 2 | 4);
    if (v < 0) return -1;
    value = v;
  }
  insn.immediates[insn.immCount++] = value;
  return 0;
}

function readVVVV(insn: Insn): number {
  const v = insn.vex;
  let vvvv: number;
  if (insn.vexType === VEXT.EVEX) vvvv = (inv(v[3]!, 3) << 4) | ((~v[2]! >> 3) & 0xf);
  else if (insn.vexType === VEXT.VEX3 || insn.vexType === VEXT.XOP) vvvv = (~v[2]! >> 3) & 0xf;
  else if (insn.vexType === VEXT.VEX2) vvvv = (~v[1]! >> 3) & 0xf;
  else return -1;
  if (insn.mode !== 64) vvvv &= 0xf;
  insn.vvvv = vvvv;
  return 0;
}

function readOperands(insn: Insn): number {
  const t = tables!;
  const hasVVVV = !readVVVV(insn);
  let needVVVV = hasVVVV && insn.vvvv !== 0;
  let sawRegImm = false;
  const base = t.opset[insn.id]! * 12;
  for (let k = 0; k < 6; k++) {
    const encoding = t.sets[base + k * 2]!;
    const type = t.sets[base + k * 2 + 1]!;
    switch (encoding) {
      case ENC.NONE:
      case ENC.SI:
      case ENC.DI:
      case ENC.FP:
      case ENC.DUP:
        break;
      case ENC.SIB:
        if (insn.eaBase !== EA.SIB && insn.eaBase !== EA.SIB64) return -1;
        if (readModRM(insn)) return -1;
        if (fixupReg(insn, encoding, type)) return -1;
        break;
      case ENC.REG:
        if (readModRM(insn)) return -1;
        if (fixupReg(insn, encoding, type)) return -1;
        break;
      case ENC.IB:
        if (sawRegImm) {
          // A register in the immediate's high nibble, and the low nibble as an immediate of its own.
          insn.immediates[insn.immCount] = Number(insn.immediates[insn.immCount - 1]) & 0xf;
          insn.immCount++;
          break;
        }
        if (readImmediate(insn, 1)) return -1;
        if (type === TYPE.XMM || type === TYPE.YMM) sawRegImm = true;
        break;
      case ENC.IW:
        if (readImmediate(insn, 2)) return -1;
        break;
      case ENC.ID:
        if (readImmediate(insn, 4)) return -1;
        break;
      case ENC.IO:
        if (readImmediate(insn, 8)) return -1;
        break;
      case ENC.Iv:
        if (readImmediate(insn, insn.immediateSize)) return -1;
        break;
      case ENC.Ia:
        if (readImmediate(insn, insn.addressSize)) return -1;
        break;
      case ENC.IRC:
        insn.rc = (((insn.vex[3]! >> 6) & 1) << 1) | ((insn.vex[3]! >> 5) & 1);
        break;
      case ENC.RB:
        readOpcodeRegister(insn, 1);
        break;
      case ENC.RW:
        readOpcodeRegister(insn, 2);
        break;
      case ENC.RD:
        readOpcodeRegister(insn, 4);
        break;
      case ENC.RO:
        readOpcodeRegister(insn, 8);
        break;
      case ENC.Rv:
        readOpcodeRegister(insn, 0);
        break;
      case ENC.CF:
        insn.immediates[1] = (insn.vex[2]! >> 3) & 0xf;
        needVVVV = false;
        break;
      case ENC.CC:
        if (isCCMPOrCTEST(insn)) insn.immediates[2] = insn.vex[3]! & 0xf;
        else insn.immediates[1] = insn.opcode & 0xf;
        break;
      case ENC.VVVV:
        needVVVV = false;
        if (!hasVVVV) return -1;
        if (insn.mode !== 64) insn.vvvv &= 7;
        if (fixupReg(insn, encoding, type)) return -1;
        break;
      case ENC.WRITEMASK:
        if (insn.vexType !== VEXT.EVEX) return -1;
        insn.writemask = insn.vex[3]! & 7;
        break;
      default:
        if (encoding >= ENC.VSIB && encoding <= ENC.VSIB_CD64) {
          if (needVVVV) needVVVV = hasVVVV && (insn.vvvv & 0xf) !== 0;
          if (readModRM(insn)) return -1;
          if (insn.eaBase !== EA.SIB && insn.eaBase !== EA.SIB64) return -1;
          if (insn.sibIndex === SIB_INDEX.NONE) insn.sibIndex = insn.sibIndexBase + 4;
          if (insn.vexType === VEXT.EVEX && insn.mode === 64 && inv(insn.vex[3]!, 3)) insn.sibIndex += 16;
          const offset = insn.sibIndex - insn.sibIndexBase;
          if (type === TYPE.MVSIBX) insn.sibIndex = SIB_INDEX.XMM0 + offset;
          else if (type === TYPE.MVSIBY) insn.sibIndex = SIB_INDEX.YMM0 + offset;
          else if (type === TYPE.MVSIBZ) insn.sibIndex = SIB_INDEX.ZMM0 + offset;
          else return -1;
          if (insn.eaDisplacement === 1) insn.displacement *= 1 << (encoding - ENC.VSIB);
        } else if (encoding >= ENC.RM && encoding <= ENC.RM_CD64) {
          if (readModRM(insn)) return -1;
          if (fixupReg(insn, encoding, type)) return -1;
          if (insn.eaDisplacement === 1) insn.displacement *= 1 << (encoding - ENC.RM);
        } else return -1;
    }
  }
  return needVVVV ? -1 : 0;
}

/* ------------------------------------------------------------------ *
 * The MCInst
 * ------------------------------------------------------------------ */

function signExtend(value: number | bigint, bytes: number): number | bigint {
  if (typeof value === 'bigint') return value;
  if (bytes === 1) return (value << 24) >> 24;
  if (bytes === 2) return (value << 16) >> 16;
  if (bytes === 4) return value | 0;
  return value;
}

function translateImmediate(insn: Insn, length: number, value: number | bigint, encoding: number, type: number, out: McOp[], types: number[]): void {
  if (type === TYPE.REL) {
    const bytes = encoding === ENC.Iv ? insn.displacementSize : encoding === ENC.IB ? 1 : encoding === ENC.IW ? 2 : encoding === ENC.ID ? 4 : 8;
    value = signExtend(value, bytes);
  } else if (type === TYPE.IMM) {
    const bytes = encoding === ENC.IB ? 1 : encoding === ENC.IW ? 2 : encoding === ENC.ID ? 4 : 0;
    if (bytes) value = signExtend(value, bytes);
  }
  if (type === TYPE.XMM || type === TYPE.YMM || type === TYPE.ZMM) {
    const prefix = type === TYPE.XMM ? 'xmm' : type === TYPE.YMM ? 'ymm' : 'zmm';
    out.push(`${prefix}${Number(value) >> 4}`);
    types.push(type);
    return;
  }
  out.push(value);
  types.push(type);
  if (type === TYPE.MOFFS) {
    out.push(SEG[insn.segment]!);
    types.push(type);
  }
  void length;
}

function translateRMRegister(insn: Insn, out: McOp[]): boolean {
  if (insn.eaBase < EA.REG) return true;
  out.push(ALL_REGS[insn.eaBase - EA.REG]!);
  return false;
}

function translateRMMemory(insn: Insn, out: McOp[], forceSIB: boolean): boolean {
  let base: string;
  let index: string;
  let scale: number;
  if (insn.eaBase === EA.SIB || insn.eaBase === EA.SIB64) {
    base = insn.sibBase !== SIB_BASE.NONE ? sibBaseName(insn.sibBase) : '';
    if (insn.sibIndex !== SIB_INDEX.NONE) {
      const name = sibIndexName(insn.sibIndex);
      if (name === undefined) return true;
      index = name;
    } else {
      const b = insn.sibBase;
      const spLike = b === SIB_BASE.EAX + 4 || b === SIB_BASE.RAX + 4 || b === SIB_BASE.EAX + 12 || b === SIB_BASE.RAX + 12;
      index = !forceSIB && (insn.sibScale !== 1 || (b === SIB_BASE.NONE && insn.mode !== 64) || (b !== SIB_BASE.NONE && !spLike)) ? (insn.addressSize === 4 ? 'eiz' : 'riz') : '';
    }
    scale = insn.sibScale;
  } else {
    switch (insn.eaBase) {
      case EA.NONE:
        if (insn.eaDisplacement === 0) return true;
        base = insn.mode === 64 ? (insn.addressSize === 4 ? 'eip' : 'rip') : '';
        index = '';
        break;
      case EA.BX_SI:
        base = 'bx';
        index = 'si';
        break;
      case EA.BX_SI + 1:
        base = 'bx';
        index = 'di';
        break;
      case EA.BX_SI + 2:
        base = 'bp';
        index = 'si';
        break;
      case EA.BX_SI + 3:
        base = 'bp';
        index = 'di';
        break;
      default:
        if (insn.eaBase >= EA.REG) return true;
        base = eaName(insn.eaBase);
        index = '';
    }
    scale = 1;
  }
  out.push(base, scale, index, insn.displacement, SEG[insn.segment]!);
  return false;
}

function translateOperand(insn: Insn, length: number, k: number, out: McOp[], types: number[]): boolean {
  const t = tables!;
  const base = t.opset[insn.id]! * 12;
  const encoding = t.sets[base + k * 2]!;
  const type = t.sets[base + k * 2 + 1]!;
  const before = out.length;
  let failed = false;
  switch (encoding) {
    case ENC.REG:
      out.push(ALL_REGS[insn.reg]!);
      break;
    case ENC.WRITEMASK:
      if (insn.writemask >= 8) return true;
      out.push(`k${insn.writemask}`);
      break;
    case ENC.IB:
    case ENC.IW:
    case ENC.ID:
    case ENC.IO:
    case ENC.Iv:
    case ENC.Ia:
      translateImmediate(insn, length, insn.immediates[insn.immTranslated++]!, encoding, type, out, types);
      return false;
    case ENC.IRC:
      out.push(insn.rc);
      break;
    case ENC.SI:
      out.push(insn.mode === 64 ? (insn.hasAdSize ? 'esi' : 'rsi') : insn.hasAdSize ? 'si' : 'esi', SEG[insn.segment]!);
      break;
    case ENC.DI:
      out.push(insn.mode === 64 ? (insn.hasAdSize ? 'edi' : 'rdi') : insn.hasAdSize ? 'di' : 'edi');
      break;
    case ENC.RB:
    case ENC.RW:
    case ENC.RD:
    case ENC.RO:
    case ENC.Rv:
      out.push(ALL_REGS[insn.opcodeRegister]!);
      break;
    case ENC.CF:
      out.push(insn.immediates[1]!);
      break;
    case ENC.CC:
      out.push(isCCMPOrCTEST(insn) ? insn.immediates[2]! : insn.immediates[1]!);
      break;
    case ENC.FP:
      out.push(insn.modRM & 7 ? `st(${insn.modRM & 7})` : 'st');
      break;
    case ENC.VVVV:
      out.push(ALL_REGS[insn.vvvv]!);
      break;
    case ENC.DUP:
      return translateOperand(insn, length, type - TYPE.DUP0, out, types);
    default:
      if ((encoding >= ENC.RM && encoding <= ENC.RM_CD64) || encoding === ENC.SIB || (encoding >= ENC.VSIB && encoding <= ENC.VSIB_CD64)) {
        if (type === TYPE.M || type === TYPE.MVSIBX || type === TYPE.MVSIBY || type === TYPE.MVSIBZ) failed = translateRMMemory(insn, out, false);
        else if (type === TYPE.MSIB) failed = translateRMMemory(insn, out, true);
        else failed = translateRMRegister(insn, out);
        if (failed) return true;
        break;
      }
      return true;
  }
  for (let i = before; i < out.length; i++) types.push(type);
  return false;
}

/**
 * Decodes one instruction at `offset` in `bytes` (not past `end`), at the
 * virtual address `addr`. `mode` is 64 for x86-64 code, 32 for i386.
 */
export function decodeX86(bytes: Uint8Array, offset: number, end: number, addr: number, mode: 64 | 32): X86Decoded {
  const insn = new Insn(bytes, offset, Math.min(end, bytes.length), mode);
  const fail = (): X86Decoded => ({ id: 0, length: Math.max(insn.cursor - offset, 1), addr, mode, ops: [], types: [], flags: 0, xacquire: false });
  if (offset >= insn.end || readPrefixes(insn) || readOpcode(insn) || getInstructionID(insn) || insn.id === 0 || readOperands(insn)) return fail();
  const length = insn.cursor - offset;
  const ops: McOp[] = [];
  const types: number[] = [];
  for (let k = 0; k < 6; k++) {
    const encoding = tables!.sets[tables!.opset[insn.id]! * 12 + k * 2]!;
    if (encoding === ENC.NONE) continue;
    if (translateOperand(insn, length, k, ops, types)) return fail();
  }
  let flags = 0;
  if (insn.hasAdSize) flags |= PFX.AD_SIZE;
  if (!insn.mandatoryPrefix) {
    if (insn.repeat === 0xf2) flags |= PFX.REPEAT_NE;
    else if (insn.repeat === 0xf3 && insn.opcode !== 0x90) flags |= PFX.REPEAT;
    if (insn.hasLock) flags |= PFX.LOCK;
  }
  const xacquire = insn.xAcquireRelease && (insn.id === SPECIAL.REP_PREFIX || insn.id === SPECIAL.REPNE_PREFIX);
  return { id: insn.id, length, addr, mode, ops, types, flags, xacquire };
}
