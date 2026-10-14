/**
 * The AArch64 assembler: one line of text in, one 32-bit word out — the
 * reverse of decode.ts, for patching an instruction in place.
 *
 * It reads the syntax the decoder prints (LLVM's generic syntax), so a line
 * copied from the listing and edited assembles back, and the spellings people
 * type besides: decimal immediates, `cs` for `hs`, `movz` for `mov`, a
 * negative `add` immediate, an `ldr` offset only `ldur` can hold. Branch and
 * address targets are absolute addresses, as llvm-objdump prints them, or
 * names the caller resolves.
 *
 * Every word is decoded again before it is returned, and the decoded text is
 * compared with the input by meaning: both are brought to one form (aliases
 * to the instruction they stand for, numbers to their values) and must agree.
 * A word that would decode to anything else is an error, never a patch.
 */

import { t } from '../i18n';
import { BARRIERS, decode, HINTS } from './decode';
import { fpImm } from './simd';
import { CONDITIONS, formatInsn, hex } from './types';

export interface Assembled {
  word: number;
}

export interface AssembleError {
  /** Already translated. */
  error: string;
}

/* ------------------------------------------------------------------ *
 * Operands
 * ------------------------------------------------------------------ */

type Cls = 'x' | 'w' | 'b' | 'h' | 's' | 'd' | 'q';
interface Reg { k: 'reg'; cls: Cls; n: number; sp: boolean }
/** An integer: an immediate, or a target address (a bare number or a resolved name). */
interface Imm { k: 'imm'; v: bigint }
interface Float { k: 'float'; v: number }
/** A condition, a barrier or prefetch name, a BTI target. */
interface Word { k: 'word'; w: string }
/** A shift or extend; `given` says whether an amount was written (`uxtw` against `uxtw #0`). */
interface Shift { k: 'shift'; s: string; amount: number; given: boolean }
interface Mem { k: 'mem'; base: Reg; off: bigint; bare: boolean; index?: Reg; ext?: Shift; mode: 'off' | 'pre' | 'post' }
type Operand = Reg | Imm | Float | Word | Shift | Mem;
interface Line { m: string; ops: Operand[] }

/** What goes wrong. No message means the operands do not fit the mnemonic. */
class Problem {
  constructor(readonly message?: string) {}
}
const fail = (message?: string): never => {
  throw new Problem(message);
};

const badImmediate = (value: bigint | string): string => t('assemble', 'The immediate {value} cannot be encoded here.', { value: typeof value === 'string' ? value : `#${hex(value)}` });
const unpredictable = (): never => fail(t('assemble', 'Arm leaves the result of this combination of registers unpredictable.'));
const badOffset = (value: bigint): string => t('assemble', 'The offset {value} is out of range.', { value: `#${hex(value)}` });

const COND_ALIASES: Record<string, string> = { cs: 'hs', cc: 'lo' };
const condName = (w: string): string => COND_ALIASES[w] ?? w;
const CONDS = CONDITIONS as readonly string[];
const EXTENDS = ['uxtb', 'uxth', 'uxtw', 'uxtx', 'sxtb', 'sxth', 'sxtw', 'sxtx'];
const SHIFT_RE = /^(lsl|lsr|asr|ror|uxt[bhwx]|sxt[bhwx])(?:\s+(.+))?$/;
const PRFOP_RE = /^(pld|pli|pst)(l[123]|slc)(keep|strm)$/;
const WORDS = new Set([...CONDS, 'cs', 'cc', ...Object.values(BARRIERS), 'oshnxs', 'nshnxs', 'ishnxs', 'synxs', 'c', 'j', 'jc', 'r', 'csync', 'dsync']);

function parseInteger(text: string): bigint | null {
  const m = /^#?\s*([+-]?)\s*(0x[0-9a-f]+|\d+)$/.exec(text);
  if (!m) return null;
  const v = BigInt(m[2]!);
  return m[1] === '-' ? -v : v;
}

function parseFloatText(text: string): number | null {
  const m = /^#?\s*([+-]?(?:\d+\.\d*|\.\d+|\d+)(?:e[+-]?\d+)?)$/.exec(text);
  return m ? Number(m[1]) : null;
}

function parseReg(text: string): Reg | null {
  const special: Record<string, Reg> = {
    sp: { k: 'reg', cls: 'x', n: 31, sp: true },
    wsp: { k: 'reg', cls: 'w', n: 31, sp: true },
    xzr: { k: 'reg', cls: 'x', n: 31, sp: false },
    wzr: { k: 'reg', cls: 'w', n: 31, sp: false },
    fp: { k: 'reg', cls: 'x', n: 29, sp: false },
    lr: { k: 'reg', cls: 'x', n: 30, sp: false },
  };
  if (special[text]) return special[text]!;
  const m = /^([xwbhsdq])([0-9]|[12][0-9]|3[01])$/.exec(text);
  if (!m) return null;
  const n = Number(m[2]);
  if (n === 31 && (m[1] === 'x' || m[1] === 'w')) return null;
  return { k: 'reg', cls: m[1] as Cls, n, sp: false };
}

function parseShift(text: string): Shift | null {
  const m = SHIFT_RE.exec(text);
  if (!m) return null;
  // Only an extend may leave its amount out.
  if (m[2] === undefined) return m[1]!.includes('xt') ? { k: 'shift', s: m[1]!, amount: 0, given: false } : unreadable(text);
  const amount = parseInteger(m[2]);
  if (amount === null) return unreadable(text);
  if (amount < 0n || amount > 63n) fail(badImmediate(amount));
  return { k: 'shift', s: m[1]!, amount: Number(amount), given: true };
}

const unsupported = (): never => fail(t('assemble', 'This instruction cannot be assembled here; enter its encoding in hex instead.'));
const unreadable = (text: string): never => fail(t('assemble', 'Cannot read “{text}”.', { text }));

function parseMem(text: string): Mem {
  const m = /^\[([^\]]*)\]\s*(!?)$/.exec(text);
  if (!m) return unreadable(text);
  const parts = m[1]!.split(',').map((part) => part.trim());
  const base = parseReg(parts[0]!);
  if (!base) return unreadable(text);
  const mem: Mem = { k: 'mem', base, off: 0n, bare: parts.length === 1, mode: m[2] ? 'pre' : 'off' };
  if (parts.length > 1) {
    const off = parseInteger(parts[1]!);
    if (off !== null) {
      if (parts.length > 2) return unreadable(text);
      mem.off = off;
    } else {
      const index = parseReg(parts[1]!);
      if (!index || m[2]) return unreadable(text);
      mem.index = index;
      if (parts.length > 2) {
        const ext = parseShift(parts[2]!);
        if (!ext || parts.length > 3) return unreadable(text);
        mem.ext = ext;
      }
    }
  }
  return mem;
}

/** Splits at the commas outside brackets. */
function split(text: string): { raw: string; start: number }[] {
  const out: { raw: string; start: number }[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i <= text.length; i++) {
    const c = text[i];
    if (c === '[') depth++;
    else if (c === ']') depth--;
    else if ((c === ',' && depth === 0) || i === text.length) {
      out.push({ raw: text.slice(start, i), start });
      start = i + 1;
    }
  }
  return out;
}

type Resolve = (name: string) => number | undefined;

function resolveName(name: string, resolve?: Resolve): Imm {
  const direct = resolve?.(name);
  if (direct !== undefined) return { k: 'imm', v: BigInt(direct) };
  // name+0x10, name-8: an address past a symbol.
  const m = /^(.*?)\s*([+-])\s*(0x[0-9a-f]+|\d+)$/i.exec(name);
  const base = m ? resolve?.(m[1]!) : undefined;
  if (m && base !== undefined) return { k: 'imm', v: BigInt(base) + (m[2] === '-' ? -BigInt(m[3]!.toLowerCase()) : BigInt(m[3]!.toLowerCase())) };
  return fail(t('assemble', 'Unknown name: {name}.', { name }));
}

/**
 * One line into a mnemonic and operands. Comments (`//`, `;`) and the
 * `<symbol>` llvm-objdump adds after a target are dropped. Anything that is
 * not a register, number, shift or keyword is a name, and runs to the end of
 * the line: a demangled name may hold commas and brackets.
 */
function parse(text: string, resolve?: Resolve): Line | null {
  const source = text.replace(/(\/\/|;).*$/, '').trim();
  if (!source) return null;
  const head = /^(\S+)\s*([\s\S]*)$/.exec(source)!;
  const m = head[1]!.toLowerCase().replace(/^(bc?)\.(cs|cc)$/, (_, b: string, c: string) => `${b}.${condName(c)}`);
  const rest = head[2]!;
  const ops: Operand[] = [];
  if (!rest) return { m, ops };
  for (const piece of split(rest)) {
    const raw = piece.raw.trim();
    const lower = raw.toLowerCase().replace(/\s+<[^>]*>$/, '');
    if (!lower) return unreadable(rest);
    if (lower.startsWith('[')) {
      ops.push(parseMem(lower));
      continue;
    }
    const integer = parseInteger(lower);
    if (integer !== null) {
      // `[x0], #8` is one operand: post-index.
      const last = ops[ops.length - 1];
      if (last?.k === 'mem' && last.bare && last.mode === 'off') {
        last.mode = 'post';
        last.off = integer;
      } else ops.push({ k: 'imm', v: integer });
      continue;
    }
    const float = parseFloatText(lower);
    if (float !== null) {
      ops.push({ k: 'float', v: float });
      continue;
    }
    const r = parseReg(lower);
    if (r) {
      ops.push(r);
      continue;
    }
    const s = parseShift(lower);
    if (s) {
      ops.push(s);
      continue;
    }
    if (WORDS.has(lower) || PRFOP_RE.test(lower)) {
      ops.push({ k: 'word', w: lower });
      continue;
    }
    if (lower.startsWith('#')) return unreadable(raw);
    // Vector registers and lists (NEON, SVE, SME) are outside what this assembler knows.
    if (/^([vzp]\d+\b|\{)/.test(lower)) return unsupported();
    ops.push(resolveName(rest.slice(piece.start).trim(), resolve));
    break;
  }
  return { m, ops };
}

/* ------------------------------------------------------------------ *
 * Operand checks
 * ------------------------------------------------------------------ */

const regName = (r: Reg): string => (r.n === 31 && (r.cls === 'x' || r.cls === 'w') ? (r.sp ? (r.cls === 'x' ? 'sp' : 'wsp') : `${r.cls}zr`) : `${r.cls}${r.n}`);
const zrLike = (r: Reg): Reg => ({ k: 'reg', cls: r.cls, n: 31, sp: false });
const isReg = (op: Operand | undefined): op is Reg => op?.k === 'reg';
const isGp = (op: Operand | undefined): op is Reg => isReg(op) && (op.cls === 'x' || op.cls === 'w');
const isZr = (op: Operand | undefined): boolean => isGp(op) && op.n === 31 && !op.sp;
const isSp = (op: Operand | undefined): boolean => isGp(op) && op.n === 31 && op.sp;
const isImm = (op: Operand | undefined): op is Imm => op?.k === 'imm';

function count(ops: Operand[], ...allowed: number[]): void {
  if (!allowed.includes(ops.length)) fail();
}

/** A general register; register 31 must be what the slot means — sp or the zero register. */
function gpr(op: Operand | undefined, slot: 'zr' | 'sp' = 'zr'): Reg {
  if (!isGp(op)) return fail();
  if (op.n === 31 && op.sp !== (slot === 'sp')) fail();
  return op;
}

function xreg(op: Operand | undefined, slot: 'zr' | 'sp' = 'zr'): number {
  const r = gpr(op, slot);
  if (r.cls !== 'x') fail();
  return r.n;
}

function wreg(op: Operand | undefined): number {
  const r = gpr(op);
  if (r.cls !== 'w') fail();
  return r.n;
}

const sfOf = (r: Reg): number => (r.cls === 'x' ? 1 : 0);

/** The sf bit of registers that must all be the same width. */
function sameWidth(...regs: Reg[]): number {
  const sf = sfOf(regs[0]!);
  if (regs.some((r) => sfOf(r) !== sf)) fail();
  return sf;
}

function immediate(op: Operand | undefined): bigint {
  if (!isImm(op)) return fail();
  return op.v;
}

function inRange(op: Operand | undefined, lo: number, hi: number): number {
  const v = immediate(op);
  if (v < BigInt(lo) || v > BigInt(hi)) fail(badImmediate(v));
  return Number(v);
}

function condition(op: Operand | undefined): number {
  if (op?.k !== 'word') return fail();
  const c = CONDS.indexOf(condName(op.w));
  return c < 0 ? fail() : c;
}

function shiftAmount(op: Operand | undefined, kinds: string[], limit: number): { kind: number; amount: number } {
  if (op?.k !== 'shift') return fail();
  const kind = kinds.indexOf(op.s);
  if (kind < 0) fail();
  if (op.amount >= limit) fail(badImmediate(BigInt(op.amount)));
  return { kind, amount: op.amount };
}

/** A value for a register of `width` bits, as LLVM takes it: unsigned or negative, wrapped to the width. */
function fitWidth(v: bigint, width: number): bigint {
  if (v < -(1n << BigInt(width - 1)) || v >= 1n << BigInt(width)) fail(badImmediate(v));
  return BigInt.asUintN(width, v);
}

/** A pc-relative field of `width` bits counting `unit`-byte steps. */
function relative(distance: number, unit: number, width: number, shown = distance): number {
  if (distance % unit) fail(t('assemble', 'The target is not a multiple of 4 bytes away.'));
  const steps = distance / unit;
  const half = 2 ** (width - 1);
  if (steps < -half || steps >= half) fail(t('assemble', 'The target is too far: {distance} bytes away.', { distance: shown }));
  return steps & (2 ** width - 1);
}

const target = (op: Operand | undefined): number => Number(immediate(op));

/* ------------------------------------------------------------------ *
 * Logical immediates
 * ------------------------------------------------------------------ */

/**
 * The N:immr:imms of a bitmask immediate: the value must be a rotated run of
 * ones repeated across the register (the reverse of decodeBitMask). The
 * element is the smallest period the value repeats with.
 */
export function encodeBitMask(value: bigint, width: number): { n: number; immr: number; imms: number } | null {
  const mask = (1n << BigInt(width)) - 1n;
  const v = value & mask;
  if (v === 0n || v === mask) return null;
  let size = width;
  while (size > 2) {
    const half = BigInt(size / 2);
    const halfMask = (1n << half) - 1n;
    if ((v & halfMask) !== ((v >> half) & halfMask)) break;
    size /= 2;
  }
  const elemMask = (1n << BigInt(size)) - 1n;
  const elem = v & elemMask;
  let ones = 0;
  for (let x = elem; x; x >>= 1n) ones += Number(x & 1n);
  const run = (1n << BigInt(ones)) - 1n;
  // elem is the run rotated right by immr: rotating it left by as much gives the run back.
  for (let r = 0; r < size; r++) {
    const rotated = ((elem << BigInt(r)) | (elem >> BigInt(size - r))) & elemMask;
    if (rotated === run) return { n: size === 64 ? 1 : 0, immr: r, imms: (~(size * 2 - 1) & 0x3f) | (ones - 1) };
  }
  return null;
}

/** The imm8 of fmov: the values ±(16…31)/16 × 2^(−3…4). */
function fpImm8(value: number): number | null {
  for (let i = 0; i < 256; i++) if (fpImm(i) === value) return i;
  return null;
}

/* ------------------------------------------------------------------ *
 * Data processing
 * ------------------------------------------------------------------ */

const ZERO: Imm = { k: 'imm', v: 0n };

/** ADD, SUB, ADDS, SUBS: immediate, shifted register or extended register. */
function addSub(op: number, s: number, ops: Operand[]): number {
  count(ops, 3, 4);
  const [d, n, x, extra] = ops;
  if (!isGp(d) || !isGp(n)) return fail();
  if (isImm(x)) {
    const rd = gpr(d, s ? 'zr' : 'sp');
    const rn = gpr(n, 'sp');
    const sf = sameWidth(rd, rn);
    let v = x.v;
    let sh = 0;
    if (extra) {
      const { amount } = shiftAmount(extra, ['lsl'], 13);
      if (amount !== 0 && amount !== 12) fail(badImmediate(BigInt(amount)));
      sh = amount / 12;
    }
    // LLVM takes add #-n as sub #n, and a multiple of 4096 as the shifted form.
    if (v < 0n) {
      v = -v;
      op ^= 1;
    }
    if (!sh && v > 0xfffn && !(v & 0xfffn) && v >> 12n <= 0xfffn) {
      v >>= 12n;
      sh = 1;
    }
    if (v > 0xfffn) fail(badImmediate(x.v));
    return (sf << 31) | (op << 30) | (s << 29) | 0x11000000 | (sh << 22) | (Number(v) << 10) | (rn.n << 5) | rd.n;
  }
  const rm = gpr(x);
  const extend = extra?.k === 'shift' && EXTENDS.includes(extra.s);
  // The shifted form reads register 31 as zr; sp needs the extended form.
  if (extend || (!s && isSp(d)) || isSp(n)) {
    const rd = gpr(d, s ? 'zr' : 'sp');
    const rn = gpr(n, 'sp');
    const sf = sameWidth(rd, rn);
    let option = sf ? 3 : 2;
    let amount = 0;
    if (extra) {
      if (extra.k !== 'shift') fail();
      const ext = extra as Shift;
      if (ext.s !== 'lsl') option = EXTENDS.indexOf(ext.s);
      if (option < 0) fail();
      amount = ext.amount;
      if (amount > 4) fail(badImmediate(BigInt(amount)));
    }
    if ((rm.cls === 'x') !== (sf === 1 && (option & 3) === 3)) fail();
    return (sf << 31) | (op << 30) | (s << 29) | 0x0b200000 | (rm.n << 16) | (option << 13) | (amount << 10) | (rn.n << 5) | rd.n;
  }
  const rd = gpr(d);
  const rn = gpr(n);
  const sf = sameWidth(rd, rn, rm);
  const sh = extra ? shiftAmount(extra, ['lsl', 'lsr', 'asr'], sf ? 64 : 32) : { kind: 0, amount: 0 };
  return (sf << 31) | (op << 30) | (s << 29) | 0x0b000000 | (sh.kind << 22) | (rm.n << 16) | (sh.amount << 10) | (rn.n << 5) | rd.n;
}

/** AND, ORR, EOR, ANDS and their inverted forms: bitmask immediate or shifted register. */
function logical(opc: number, invert: number, ops: Operand[]): number {
  count(ops, 3, 4);
  const [d, n, x, extra] = ops;
  if (isImm(x)) {
    if (extra) fail();
    const rd = gpr(d, opc === 3 ? 'zr' : 'sp');
    const rn = gpr(n);
    const sf = sameWidth(rd, rn);
    const width = sf ? 64 : 32;
    let v = fitWidth(x.v, width);
    if (invert) v = BigInt.asUintN(width, ~v);
    const e = encodeBitMask(v, width);
    if (!e) return fail(badImmediate(x.v));
    return (sf << 31) | (opc << 29) | 0x12000000 | (e.n << 22) | (e.immr << 16) | (e.imms << 10) | (rn.n << 5) | rd.n;
  }
  const rd = gpr(d);
  const rn = gpr(n);
  const rm = gpr(x);
  const sf = sameWidth(rd, rn, rm);
  const sh = extra ? shiftAmount(extra, ['lsl', 'lsr', 'asr', 'ror'], sf ? 64 : 32) : { kind: 0, amount: 0 };
  return (sf << 31) | (opc << 29) | 0x0a000000 | (sh.kind << 22) | (invert << 21) | (rm.n << 16) | (sh.amount << 10) | (rn.n << 5) | rd.n;
}

/** MOVZ, MOVN, MOVK: a 16-bit value at a multiple of 16 bits. */
function moveWide(opc: number, ops: Operand[]): number {
  count(ops, 2, 3);
  const rd = gpr(ops[0]);
  const sf = sfOf(rd);
  const width = sf ? 64 : 32;
  const v = immediate(ops[1]);
  let amount = 0;
  if (ops[2]) {
    amount = shiftAmount(ops[2], ['lsl'], width).amount;
    if (amount % 16) fail(badImmediate(BigInt(amount)));
  }
  if (v < 0n || v > 0xffffn) fail(badImmediate(v));
  return (sf << 31) | (opc << 29) | 0x12800000 | ((amount / 16) << 21) | (Number(v) << 5) | rd.n;
}

/**
 * MOV with an immediate, the way LLVM picks the instruction: movz if one
 * 16-bit piece makes the value, movn if one makes its complement, a bitmask
 * orr otherwise.
 */
function movImmediate(d: Operand, x: Imm): number {
  const rd = gpr(d, isSp(d) ? 'sp' : 'zr');
  const width = rd.cls === 'x' ? 64 : 32;
  const value = fitWidth(x.v, width);
  if (!rd.sp) {
    for (const [opc, v] of [[2, value], [0, BigInt.asUintN(width, ~value)]] as const) {
      for (let shift = 0; shift < width; shift += 16) {
        if (!(v & ~(0xffffn << BigInt(shift)))) return moveWide(opc, [rd, { k: 'imm', v: v >> BigInt(shift) }, { k: 'shift', s: 'lsl', amount: shift, given: true }]);
      }
    }
  }
  if (!encodeBitMask(value, width)) fail(badImmediate(x.v));
  return logical(1, 0, [rd, zrLike(rd), { k: 'imm', v: value }]);
}

function mov(ops: Operand[]): number {
  count(ops, 2);
  const [d, x] = ops;
  if (isImm(x)) return movImmediate(d!, x);
  if (!isGp(d) || !isGp(x)) return fail();
  if (isSp(d) || isSp(x)) return addSub(0, 0, [d, x, ZERO]);
  return logical(1, 0, [d, zrLike(d), x]);
}

/** SBFM, BFM, UBFM. */
function bitfield(opc: number, d: Operand | undefined, n: Operand | undefined, immr: number, imms: number): number {
  const rd = gpr(d);
  const rn = gpr(n);
  const sf = sameWidth(rd, rn);
  return (sf << 31) | (opc << 29) | 0x13000000 | (sf << 22) | (immr << 16) | (imms << 10) | (rn.n << 5) | rd.n;
}

const widthOf = (op: Operand | undefined): number => (gpr(op).cls === 'x' ? 64 : 32);

/** The bitfield aliases that take a position and a width: ubfx, ubfiz, bfi… */
function bitfieldField(opc: number, insert: boolean, ops: Operand[]): number {
  count(ops, 4);
  const width = widthOf(ops[0]);
  const lsb = inRange(ops[2], 0, width - 1);
  const size = inRange(ops[3], 1, width - lsb);
  return insert ? bitfield(opc, ops[0], ops[1], (width - lsb) % width, size - 1) : bitfield(opc, ops[0], ops[1], lsb, lsb + size - 1);
}

/** SXTB, SXTH, SXTW, UXTB, UXTH: the source is always a w register. */
function extend(opc: number, imms: number, ops: Operand[]): number {
  count(ops, 2);
  const rn = gpr(ops[1]);
  if (rn.cls !== 'w') fail();
  const rd = gpr(ops[0]);
  return bitfield(opc, rd, { ...rn, cls: rd.cls }, 0, imms);
}

function extr(d: Operand | undefined, n: Operand | undefined, m: Operand | undefined, lsb: Operand | undefined): number {
  const rd = gpr(d);
  const rn = gpr(n);
  const rm = gpr(m);
  const sf = sameWidth(rd, rn, rm);
  return (sf << 31) | 0x13800000 | (sf << 22) | (rm.n << 16) | (inRange(lsb, 0, sf ? 63 : 31) << 10) | (rn.n << 5) | rd.n;
}

/** LSL, LSR, ASR, ROR: by an immediate (a bitfield or extr) or by a register. */
function shiftInsn(kind: number, ops: Operand[]): number {
  count(ops, 3);
  if (!isImm(ops[2])) return dataProcessing2(8 + kind, ops);
  const width = widthOf(ops[0]);
  const amount = inRange(ops[2], 0, width - 1);
  if (kind === 0) return bitfield(2, ops[0], ops[1], (width - amount) % width, width - 1 - amount);
  if (kind === 3) return extr(ops[0], ops[1], ops[1], ops[2]);
  return bitfield(kind === 1 ? 2 : 0, ops[0], ops[1], amount, width - 1);
}

function dataProcessing2(opcode: number, ops: Operand[]): number {
  count(ops, 3);
  const rd = gpr(ops[0]);
  const rn = gpr(ops[1]);
  const rm = gpr(ops[2]);
  const sf = sameWidth(rd, rn, rm);
  return (sf << 31) | 0x1ac00000 | (rm.n << 16) | (opcode << 10) | (rn.n << 5) | rd.n;
}

function dataProcessing1(opcode: number, ops: Operand[], only?: 'x'): number {
  count(ops, 2);
  const rd = gpr(ops[0]);
  const rn = gpr(ops[1]);
  const sf = sameWidth(rd, rn);
  if (only && !sf) fail();
  return (sf << 31) | 0x5ac00000 | (opcode << 10) | (rn.n << 5) | rd.n;
}

/** SMAX, UMAX, SMIN, UMIN (FEAT_CSSC): with a register, or an 8-bit immediate, signed for the s forms. */
function minMax(opc: number, ops: Operand[]): number {
  count(ops, 3);
  if (!isImm(ops[2])) return dataProcessing2(24 + opc, ops);
  const rd = gpr(ops[0]);
  const rn = gpr(ops[1]);
  const sf = sameWidth(rd, rn);
  const value = opc & 1 ? inRange(ops[2], 0, 255) : inRange(ops[2], -128, 127) & 0xff;
  return (sf << 31) | 0x11c00000 | (opc << 18) | (value << 10) | (rn.n << 5) | rd.n;
}

/** ADC, ADCS, SBC, SBCS. */
function carry(op: number, s: number, ops: Operand[]): number {
  count(ops, 3);
  const rd = gpr(ops[0]);
  const rn = gpr(ops[1]);
  const rm = gpr(ops[2]);
  const sf = sameWidth(rd, rn, rm);
  return (sf << 31) | (op << 30) | (s << 29) | 0x1a000000 | (rm.n << 16) | (rn.n << 5) | rd.n;
}

/** CSEL, CSINC, CSINV, CSNEG. */
function condSelect(op: number, o2: number, d: Operand | undefined, n: Operand | undefined, m: Operand | undefined, c: number): number {
  const rd = gpr(d);
  const rn = gpr(n);
  const rm = gpr(m);
  const sf = sameWidth(rd, rn, rm);
  return (sf << 31) | (op << 30) | 0x1a800000 | (rm.n << 16) | (c << 12) | (o2 << 10) | (rn.n << 5) | rd.n;
}

/** The aliases that test the inverted condition; al and nv have no inverse LLVM accepts. */
function invertible(op: Operand | undefined): number {
  const c = condition(op);
  if (c >= 14) fail();
  return c ^ 1;
}

function condCompare(op: number, ops: Operand[]): number {
  count(ops, 4);
  const rn = gpr(ops[0]);
  const nzcv = inRange(ops[2], 0, 15);
  const c = condition(ops[3]);
  let second: number;
  let isImmediate = 0;
  if (isImm(ops[1])) {
    second = inRange(ops[1], 0, 31);
    isImmediate = 1;
  } else {
    const rm = gpr(ops[1]);
    sameWidth(rn, rm);
    second = rm.n;
  }
  return (sfOf(rn) << 31) | (op << 30) | 0x3a400000 | (second << 16) | (c << 12) | (isImmediate << 11) | (rn.n << 5) | nzcv;
}

/** MADD, MSUB and the multiplies that accumulate into zr. */
function multiply(o0: number, ops: Operand[], accumulate: boolean): number {
  count(ops, accumulate ? 4 : 3);
  const rd = gpr(ops[0]);
  const rn = gpr(ops[1]);
  const rm = gpr(ops[2]);
  const ra = accumulate ? gpr(ops[3]) : zrLike(rd);
  const sf = sameWidth(rd, rn, rm, ra);
  return (sf << 31) | 0x1b000000 | (rm.n << 16) | (o0 << 15) | (ra.n << 10) | (rn.n << 5) | rd.n;
}

/** SMADDL, UMADDL, SMSUBL, UMSUBL (and SMULH, UMULH, which take x sources): a 64-bit result. */
function multiplyLong(op31: number, o0: number, ops: Operand[], accumulate: boolean, wide = false): number {
  count(ops, accumulate ? 4 : 3);
  const rd = xreg(ops[0]);
  const rn = wide ? xreg(ops[1]) : wreg(ops[1]);
  const rm = wide ? xreg(ops[2]) : wreg(ops[2]);
  const ra = accumulate ? xreg(ops[3]) : 31;
  return 0x9b000000 | (op31 << 21) | (rm << 16) | (o0 << 15) | (ra << 10) | (rn << 5) | rd;
}

/* ------------------------------------------------------------------ *
 * Branches and system
 * ------------------------------------------------------------------ */

const HINT_NUMBERS = new Map(Object.entries(HINTS).map(([n, name]) => [name, Number(n)]));
const BARRIER_NUMBERS = new Map(Object.entries(BARRIERS).map(([n, name]) => [name, Number(n)]));

/** DSB with the nXS qualifier (FEAT_XS), by the number LLVM also takes for it. */
const NXS: Record<number, string> = { 16: 'oshnxs', 20: 'nshnxs', 24: 'ishnxs', 28: 'synxs' };
const NXS_NUMBERS = new Map(Object.entries(NXS).map(([n, name]) => [name, Number(n)]));

function barrier(op2: number, ops: Operand[], none?: number): number {
  count(ops, none === undefined ? 1 : 0, 1);
  let crm: number;
  const nxs = op2 === 4 && ops[0] ? (ops[0].k === 'word' ? NXS_NUMBERS.get(ops[0].w) : isImm(ops[0]) ? Number(ops[0].v) : undefined) : undefined;
  if (nxs !== undefined && NXS[nxs]) return 0xd503323f | ((nxs & 12) << 8);
  if (!ops.length) crm = none!;
  else if (ops[0]!.k === 'word' && BARRIER_NUMBERS.has(ops[0]!.w) && op2 !== 6) crm = BARRIER_NUMBERS.get(ops[0]!.w)!;
  else crm = inRange(ops[0], 0, 15);
  return 0xd503301f | (crm << 8) | (op2 << 5);
}

/** HINT and the hints with names: nop, yield, paciasp, bti c… */
function hint(m: string, ops: Operand[]): number | null {
  if (m === 'hint') {
    count(ops, 1);
    return 0xd503201f | (inRange(ops[0], 0, 127) << 5);
  }
  const name = [m, ...ops.map((op) => (op.k === 'word' ? op.w : op.k === 'reg' ? regName(op) : '?'))].join(' ');
  const n = HINT_NUMBERS.get(name);
  return n === undefined ? null : 0xd503201f | (n << 5);
}

function prfop(op: Operand | undefined): number {
  if (op?.k === 'word') {
    const m = PRFOP_RE.exec(op.w);
    if (!m) return fail();
    return (['pld', 'pli', 'pst'].indexOf(m[1]!) << 3) | (['l1', 'l2', 'l3', 'slc'].indexOf(m[2]!) << 1) | (m[3] === 'strm' ? 1 : 0);
  }
  return inRange(op, 0, 31);
}

/* ------------------------------------------------------------------ *
 * Loads and stores
 * ------------------------------------------------------------------ */

const FP_SIZE: Partial<Record<Cls, number>> = { b: 0, h: 1, s: 2, d: 3, q: 0 };

/** The base register of an address: x0…x30 or sp. */
function baseOf(mem: Mem): number {
  return xreg(mem.base, 'sp');
}

function offsetField(off: bigint, scale: number, lo: number, hi: number): number {
  const bytes = BigInt(1 << scale);
  if (off % bytes) fail(t('assemble', 'The offset {value} is not a multiple of {size}.', { value: `#${hex(off)}`, size: Number(bytes) }));
  const v = off / bytes;
  if (v < BigInt(lo) || v > BigInt(hi)) fail(badOffset(off));
  return Number(v);
}

/**
 * LDR, STR, LDUR, STUR, LDTR, STTR and their byte, halfword and
 * sign-extending forms, for general and SIMD&FP registers; PRFM and PRFUM.
 */
function single(m: string, ops: Operand[], pc: number): number {
  count(ops, 2);
  const prefetch = m === 'prfm' || m === 'prfum';
  const parts = prefetch ? ['', 'ld', m === 'prfm' ? 'r' : 'ur', ''] : /^(ld|st)(r|ur|tr)(b|h|sb|sh|sw)?$/.exec(m);
  if (!parts) return fail();
  const load = parts[1] === 'ld';
  const form = parts[2]!;
  const suffix = parts[3] ?? '';
  let size: number;
  let opc: number;
  let v = 0;
  let scale: number;
  let rt: number;
  const r = ops[0];
  if (prefetch) {
    rt = prfop(r);
    size = 3;
    opc = 2;
    scale = 3;
  } else if (isReg(r) && FP_SIZE[r.cls] !== undefined) {
    if (suffix || form === 'tr') fail();
    v = 1;
    size = FP_SIZE[r.cls]!;
    opc = (r.cls === 'q' ? 2 : 0) | (load ? 1 : 0);
    scale = r.cls === 'q' ? 4 : size;
    rt = r.n;
  } else {
    const g = gpr(r);
    rt = g.n;
    if (!load && suffix.startsWith('s')) fail();
    if (suffix === '') {
      size = g.cls === 'x' ? 3 : 2;
      opc = load ? 1 : 0;
    } else if (suffix === 'b' || suffix === 'h') {
      if (g.cls !== 'w') fail();
      size = suffix === 'b' ? 0 : 1;
      opc = load ? 1 : 0;
    } else if (suffix === 'sw') {
      if (g.cls !== 'x') fail();
      size = 2;
      opc = 2;
    } else {
      size = suffix === 'sb' ? 0 : 1;
      opc = g.cls === 'x' ? 2 : 3;
    }
    scale = size;
  }
  const mem = ops[1]!;
  if (mem.k === 'imm') {
    // A literal: ldr (w, x, s, d, q), ldrsw, prfm.
    if (form !== 'r' || !load || (suffix && suffix !== 'sw')) return fail();
    const lit = prefetch ? 3 : suffix === 'sw' ? 2 : v ? [2, 3, 4].indexOf(scale) : size === 3 ? 1 : 0;
    if (lit < 0) fail();
    return (lit << 30) | 0x18000000 | (v << 26) | (relative(target(mem) - pc, 4, 19) << 5) | rt;
  }
  if (mem.k !== 'mem') return fail();
  const rn = baseOf(mem);
  const head = (size << 30) | (v << 26) | (opc << 22) | (rn << 5) | rt;
  const unscaled = (op: number): number => {
    if (mem.off < -256n || mem.off > 255n) fail(badOffset(mem.off));
    // With writeback, the base must not also be the register loaded or stored.
    if ((op === 1 || op === 3) && !v && rn === rt && rn !== 31) unpredictable();
    return head | 0x38000000 | ((Number(mem.off) & 0x1ff) << 12) | (op << 10);
  };
  if (mem.index) {
    if (form !== 'r' || mem.mode !== 'off') fail();
    const ext = mem.ext?.s ?? 'lsl';
    const option = ['', '', 'uxtw', 'lsl', '', '', 'sxtw', 'sxtx'].indexOf(ext);
    if (option < 0) fail();
    if ((mem.index.cls === 'x') !== !!(option & 1) || (mem.index.cls !== 'x' && mem.index.cls !== 'w') || (mem.index.n === 31 && mem.index.sp)) fail();
    let s = 0;
    if (mem.ext?.given) {
      if (mem.ext.amount === scale) s = 1;
      else if (mem.ext.amount !== 0) fail(badImmediate(BigInt(mem.ext.amount)));
    }
    return head | 0x38200800 | (mem.index.n << 16) | (option << 13) | (s << 12);
  }
  if (form === 'ur' || form === 'tr') {
    if (mem.mode !== 'off') fail();
    return unscaled(form === 'ur' ? 0 : 2);
  }
  if (mem.mode !== 'off') {
    if (prefetch) fail();
    return unscaled(mem.mode === 'post' ? 1 : 3);
  }
  // An offset the scaled form cannot hold goes to ldur / stur, as LLVM does.
  const bytes = BigInt(1 << scale);
  if (mem.off < 0n || mem.off % bytes || mem.off / bytes > 0xfffn) {
    if (mem.off >= -256n && mem.off <= 255n) return unscaled(0);
    offsetField(mem.off, scale, 0, 0xfff);
  }
  return head | 0x39000000 | (Number(mem.off / bytes) << 10);
}

/** LDP, STP, LDNP, STNP, LDPSW. */
function pair(m: string, ops: Operand[]): number {
  count(ops, 3);
  const l = m.startsWith('ld') ? 1 : 0;
  const r1 = ops[0];
  const r2 = ops[1];
  const mem = ops[2];
  if (!isReg(r1) || !isReg(r2) || r1.cls !== r2.cls || mem?.k !== 'mem' || mem.index) return fail();
  let opc: number;
  let v = 0;
  let scale: number;
  if (m === 'ldpsw') {
    gpr(r1);
    gpr(r2);
    if (r1.cls !== 'x') fail();
    opc = 1;
    scale = 2;
  } else if (r1.cls === 's' || r1.cls === 'd' || r1.cls === 'q') {
    v = 1;
    opc = ['s', 'd', 'q'].indexOf(r1.cls);
    scale = opc + 2;
  } else {
    gpr(r1);
    gpr(r2);
    opc = r1.cls === 'x' ? 2 : 0;
    scale = r1.cls === 'x' ? 3 : 2;
  }
  const noalloc = m === 'ldnp' || m === 'stnp';
  if (noalloc && mem.mode !== 'off') fail();
  const mode = noalloc ? 0 : { post: 1, off: 2, pre: 3 }[mem.mode];
  const imm7 = offsetField(mem.off, scale, -64, 63);
  const rn = baseOf(mem);
  // As LLVM does, refuse what Arm leaves unpredictable: one register loaded twice, or a written-back base also transferred.
  if ((l && !noalloc && r1.n === r2.n) || ((mode === 1 || mode === 3) && !v && rn !== 31 && (rn === r1.n || rn === r2.n))) unpredictable();
  return (opc << 30) | 0x28000000 | (v << 26) | (mode << 23) | (l << 22) | ((imm7 & 0x7f) << 15) | (r2.n << 10) | (rn << 5) | r1.n;
}

/**
 * The exclusive and acquire/release loads and stores: LDXR, STXR, LDAXR,
 * STLXR, LDAR, STLR, LDLAR, STLLR (with b and h), and the exclusive pairs.
 */
const EXCLUSIVE: Record<string, [o2: number, l: number, o1: number, o0: number, status: boolean, pair: boolean]> = {
  stxr: [0, 0, 0, 0, true, false], stlxr: [0, 0, 0, 1, true, false], ldxr: [0, 1, 0, 0, false, false], ldaxr: [0, 1, 0, 1, false, false],
  stllr: [1, 0, 0, 0, false, false], stlr: [1, 0, 0, 1, false, false], ldlar: [1, 1, 0, 0, false, false], ldar: [1, 1, 0, 1, false, false],
  stxp: [0, 0, 1, 0, true, true], stlxp: [0, 0, 1, 1, true, true], ldxp: [0, 1, 1, 0, false, true], ldaxp: [0, 1, 1, 1, false, true],
};

function exclusive(m: string, ops: Operand[]): number | null {
  const parts = /^(.*?)(b|h)?$/.exec(m)!;
  const mem = ops[ops.length - 1];
  if ((m === 'stlr' || m === 'ldapr') && mem?.k === 'mem' && mem.mode !== 'off') return rcpcWriteback(m === 'ldapr', ops);
  if (parts[1] === 'ldapr') return acquireRcpc(parts[2], ops);
  const spec = EXCLUSIVE[m] ?? (parts[2] && !m.endsWith('p') ? EXCLUSIVE[parts[1]!] : undefined);
  if (!spec) return null;
  const [o2, l, o1, o0, status, isPair] = spec;
  count(ops, 2 + (status ? 1 : 0) + (isPair ? 1 : 0));
  const rs = status ? wreg(ops[0]) : 31;
  const regs = ops.slice(status ? 1 : 0, -1);
  if (mem?.k !== 'mem' || mem.index || mem.mode !== 'off' || mem.off !== 0n) return fail();
  const rt = gpr(regs[0]);
  const rt2 = isPair ? gpr(regs[1]) : undefined;
  let size = rt.cls === 'x' ? 3 : 2;
  if (rt2) sameWidth(rt, rt2);
  // The status register of a store-exclusive must differ from the registers it stores and the base.
  const rn = baseOf(mem);
  if (status && (rs === rt.n || rs === rt2?.n || (rs === rn && rn !== 31))) unpredictable();
  if (parts[2] && EXCLUSIVE[m] === undefined) {
    if (rt.cls !== 'w') fail();
    size = parts[2] === 'b' ? 0 : 1;
  }
  return (size << 30) | 0x08000000 | (o2 << 23) | (l << 22) | (o1 << 21) | (rs << 16) | (o0 << 15) | ((rt2?.n ?? 31) << 10) | (rn << 5) | rt.n;
}

/** A plain [Xn] address, as the exclusives and atomics take. */
function plainBase(op: Operand | undefined): number {
  if (op?.k !== 'mem' || op.index || op.mode !== 'off' || op.off !== 0n) return fail();
  return baseOf(op);
}

/** The size of an access by suffix (b, h) or by the register. */
function accessSize(suffix: string | undefined, rt: Reg): number {
  if (!suffix) return rt.cls === 'x' ? 3 : 2;
  if (rt.cls !== 'w') fail();
  return suffix === 'b' ? 0 : 1;
}

/** LDAPR (FEAT_LRCPC): a load-acquire with the weaker RCpc ordering. */
function acquireRcpc(suffix: string | undefined, ops: Operand[]): number {
  count(ops, 2);
  const rt = gpr(ops[0]);
  return (accessSize(suffix, rt) << 30) | 0x38bfc000 | (plainBase(ops[1]) << 5) | rt.n;
}

/** STLR with pre-decrement and LDAPR with post-increment (FEAT_LRCPC3): the step is the access size. */
function rcpcWriteback(load: boolean, ops: Operand[]): number {
  count(ops, 2);
  const rt = gpr(ops[0]);
  const mem = ops[1] as Mem;
  const size = accessSize(undefined, rt);
  if (mem.index || mem.mode !== (load ? 'post' : 'pre')) fail();
  if (mem.off !== BigInt(load ? 1 << size : -(1 << size))) fail(badOffset(mem.off));
  return (size << 30) | 0x19000800 | ((load ? 3 : 2) << 22) | (baseOf(mem) << 5) | rt.n;
}

const ATOMIC_OPS = ['add', 'clr', 'eor', 'set', 'smax', 'smin', 'umax', 'umin'];

/**
 * The LSE atomics: LD<op>, ST<op> (LD<op> into zr, without acquire), SWP,
 * CAS and CASP, each with its a/l ordering and b/h size suffixes.
 */
function atomic(m: string, ops: Operand[]): number | null {
  const lse = /^(ld|st)(add|clr|eor|set|smax|smin|umax|umin)(a|l|al)?(b|h)?$/.exec(m);
  const swap = /^(swp|casp?)(a|l|al)?(b|h)?$/.exec(m);
  if (lse) {
    const [, kind, op, order = '', suffix] = lse;
    const store = kind === 'st';
    if (store && order.includes('a')) return null;
    count(ops, store ? 2 : 3);
    const rs = gpr(ops[0]);
    const rt = store ? zrLike(rs) : gpr(ops[1]);
    sameWidth(rs, rt);
    const a = order.includes('a') ? 1 : 0;
    const r = order.includes('l') ? 1 : 0;
    return (accessSize(suffix, rs) << 30) | 0x38200000 | (a << 23) | (r << 22) | (rs.n << 16) | (ATOMIC_OPS.indexOf(op!) << 12) | (plainBase(ops[ops.length - 1]) << 5) | rt.n;
  }
  if (!swap) return null;
  const [, kind, order = '', suffix] = swap;
  const a = order.includes('a') ? 1 : 0;
  const r = order.includes('l') ? 1 : 0;
  if (kind === 'casp') {
    // Two pairs of consecutive registers, each starting at an even one; only the first of each is encoded.
    if (suffix) return null;
    count(ops, 5);
    const regs = ops.slice(0, 4).map((op) => gpr(op));
    sameWidth(...regs);
    if (regs[0]!.n & 1 || regs[2]!.n & 1 || regs[1]!.n !== regs[0]!.n + 1 || regs[3]!.n !== regs[2]!.n + 1) fail();
    return ((regs[0]!.cls === 'x' ? 1 : 0) << 30) | 0x08207c00 | (a << 22) | (regs[0]!.n << 16) | (r << 15) | (plainBase(ops[4]) << 5) | regs[2]!.n;
  }
  count(ops, 3);
  const rs = gpr(ops[0]);
  const rt = gpr(ops[1]);
  sameWidth(rs, rt);
  const size = accessSize(suffix, rs) << 30;
  if (kind === 'cas') return size | 0x08a07c00 | (a << 22) | (rs.n << 16) | (r << 15) | (plainBase(ops[2]) << 5) | rt.n;
  return size | 0x38208000 | (a << 23) | (r << 22) | (rs.n << 16) | (plainBase(ops[2]) << 5) | rt.n;
}

/* ------------------------------------------------------------------ *
 * Floating point
 * ------------------------------------------------------------------ */

const FTYPE: Partial<Record<Cls, number>> = { s: 0, d: 1, h: 3 };
const FP1 = ['fmov', 'fabs', 'fneg', 'fsqrt', '', '', '', '', 'frintn', 'frintp', 'frintm', 'frintz', 'frinta', '', 'frintx', 'frinti', 'frint32z', 'frint32x', 'frint64z', 'frint64x'];
const FP2 = ['fmul', 'fdiv', 'fadd', 'fsub', 'fmax', 'fmin', 'fmaxnm', 'fminnm', 'fnmul'];
const FP3 = ['fmadd', 'fmsub', 'fnmadd', 'fnmsub'];

/** A scalar s, d or h register, and its ftype. */
function fpr(op: Operand | undefined, like?: Reg): Reg & { type: number } {
  if (!isReg(op)) return fail();
  const type = FTYPE[op.cls];
  if (type === undefined || (like && like.cls !== op.cls)) return fail();
  return { ...op, type };
}

function fpValue(op: Operand | undefined): number {
  if (op?.k === 'float') return op.v;
  return Number(immediate(op));
}

function fmov(ops: Operand[]): number {
  count(ops, 2);
  const [d, n] = ops;
  if (isGp(d)) {
    // To a general register: w from s or h, x from d or h.
    const rn = fpr(n);
    if ((rn.cls === 's' && d.cls !== 'w') || (rn.cls === 'd' && d.cls !== 'x')) fail();
    return (sfOf(gpr(d)) << 31) | 0x1e260000 | (rn.type << 22) | (rn.n << 5) | d.n;
  }
  const rd = fpr(d);
  if (isGp(n)) {
    if ((rd.cls === 's' && n.cls !== 'w') || (rd.cls === 'd' && n.cls !== 'x')) fail();
    return (sfOf(gpr(n)) << 31) | 0x1e270000 | (rd.type << 22) | (n.n << 5) | rd.n;
  }
  if (isReg(n)) return 0x1e204000 | (rd.type << 22) | (fpr(n, rd).n << 5) | rd.n;
  const value = fpValue(n);
  // Zero has no imm8; LLVM moves it from the zero register.
  if (value === 0 && !Object.is(value, -0)) return fmov([rd, zrLike({ ...rd, cls: rd.cls === 'd' ? 'x' : 'w' })]);
  const imm8 = fpImm8(value);
  if (imm8 === null) return fail(badImmediate(`#${value}`));
  return 0x1e201000 | (rd.type << 22) | (imm8 << 13) | rd.n;
}

function fpCompare(e: number, ops: Operand[]): number {
  count(ops, 2);
  const rn = fpr(ops[0]);
  if (isReg(ops[1])) return 0x1e202000 | (rn.type << 22) | (fpr(ops[1], rn).n << 16) | (rn.n << 5) | (e << 4);
  if (fpValue(ops[1]) !== 0) fail(badImmediate(`#${fpValue(ops[1])}`));
  return 0x1e202008 | (rn.type << 22) | (rn.n << 5) | (e << 4);
}

// The conversions between SIMD&FP registers: U, size<1> and opcode of the Advanced SIMD scalar
// form (both registers the same size), and rmode:opcode of the FEAT_FPRCVT form (sizes differ).
const SIMD_CONVERT: Record<string, [u: number, hi: number, opcode: number, fprcvt: number]> = {
  fcvtns: [0, 0, 26, 0b01010], fcvtms: [0, 0, 27, 0b10100], fcvtas: [0, 0, 28, 0b11010], scvtf: [0, 0, 29, 0b11100],
  fcvtps: [0, 1, 26, 0b10010], fcvtzs: [0, 1, 27, 0b10110], fcvtnu: [1, 0, 26, 0b01011], fcvtmu: [1, 0, 27, 0b10101],
  fcvtau: [1, 0, 28, 0b11011], ucvtf: [1, 0, 29, 0b11101], fcvtpu: [1, 1, 26, 0b10011], fcvtzu: [1, 1, 27, 0b10111],
};

/** A conversion with both registers SIMD&FP: the integer in s or d (or h, when both are h). */
function simdConvert(m: string, ops: Operand[]): number {
  const [u, hi, opcode, fprcvt] = SIMD_CONVERT[m]!;
  const rd = fpr(ops[0]);
  const rn = fpr(ops[1]);
  if (rd.cls !== rn.cls) {
    // FEAT_FPRCVT: sf says whether the integer is in d or s.
    count(ops, 2);
    const toFp = m.endsWith('cvtf');
    const int = toFp ? rn : rd;
    const fp = toFp ? rd : rn;
    if (int.cls === 'h') fail();
    return ((int.cls === 'd' ? 1 : 0) << 31) | 0x1e200000 | (fp.type << 22) | (fprcvt << 16) | (rn.n << 5) | rd.n;
  }
  if (ops.length === 3) {
    // Fixed point, by the shift-immediate encoding: immh:immb is twice the element size less fbits.
    if (opcode !== 27 && opcode !== 29) fail();
    const esize = rd.cls === 'h' ? 16 : rd.cls === 's' ? 32 : 64;
    const value = 2 * esize - inRange(ops[2], 1, esize);
    return 0x5f000400 | (u << 29) | (value << 16) | ((opcode === 27 ? 31 : 28) << 11) | (rn.n << 5) | rd.n;
  }
  count(ops, 2);
  const size = rd.cls === 'h' ? 0x00780000 : 0x00200000 | ((rd.cls === 'd' ? 1 : 0) << 22);
  return 0x5e000800 | (u << 29) | size | (hi << 23) | (opcode << 12) | (rn.n << 5) | rd.n;
}

/** SCVTF, UCVTF and FCVT<mode>S/U between a general register and s, d or h; fixed point with fbits. */
function fpIntConvert(toFp: boolean, rmode: number, opcode: number, ops: Operand[], m: string): number {
  count(ops, 2, 3);
  if (!isGp(ops[0]) && !isGp(ops[1])) return simdConvert(m, ops);
  const g = gpr(ops[toFp ? 1 : 0]);
  const f = fpr(ops[toFp ? 0 : 1]);
  const sf = sfOf(g);
  const fields = (sf << 31) | (f.type << 22) | (rmode << 19) | (opcode << 16) | ((toFp ? g.n : f.n) << 5) | (toFp ? f.n : g.n);
  if (ops.length === 2) return 0x1e200000 | fields;
  // Fixed point: only scvtf, ucvtf, fcvtzs and fcvtzu.
  if (opcode > 3 || (rmode !== 0 && rmode !== 3)) fail();
  const fbits = inRange(ops[2], 1, sf ? 64 : 32);
  return 0x1e000000 | fields | ((64 - fbits) << 10);
}

/* ------------------------------------------------------------------ *
 * The mnemonics
 * ------------------------------------------------------------------ */

type Encoder = (ops: Operand[], pc: number, m: string) => number;

const bitfieldAlias = (opc: number, insert: boolean): Encoder => (ops) => bitfieldField(opc, insert, ops);

const ENCODERS: Record<string, Encoder> = {
  '.inst': (ops) => (count(ops, 1), inRange(ops[0], 0, 0xffffffff)),

  b: (ops, pc) => (count(ops, 1), 0x14000000 | relative(target(ops[0]) - pc, 4, 26)),
  bl: (ops, pc) => (count(ops, 1), 0x94000000 | relative(target(ops[0]) - pc, 4, 26)),
  cbz: (ops, pc) => (count(ops, 2), (sfOf(gpr(ops[0])) << 31) | 0x34000000 | (relative(target(ops[1]) - pc, 4, 19) << 5) | gpr(ops[0]).n),
  cbnz: (ops, pc) => (count(ops, 2), (sfOf(gpr(ops[0])) << 31) | 0x35000000 | (relative(target(ops[1]) - pc, 4, 19) << 5) | gpr(ops[0]).n),
  tbz: (ops, pc) => testBranch(0, ops, pc),
  tbnz: (ops, pc) => testBranch(1, ops, pc),
  br: (ops) => (count(ops, 1), 0xd61f0000 | (xreg(ops[0]) << 5)),
  blr: (ops) => (count(ops, 1), 0xd63f0000 | (xreg(ops[0]) << 5)),
  ret: (ops) => (count(ops, 0, 1), 0xd65f0000 | ((ops.length ? xreg(ops[0]) : 30) << 5)),

  svc: (ops) => (count(ops, 1), 0xd4000001 | (inRange(ops[0], 0, 0xffff) << 5)),
  hvc: (ops) => (count(ops, 1), 0xd4000002 | (inRange(ops[0], 0, 0xffff) << 5)),
  smc: (ops) => (count(ops, 1), 0xd4000003 | (inRange(ops[0], 0, 0xffff) << 5)),
  brk: (ops) => (count(ops, 1), 0xd4200000 | (inRange(ops[0], 0, 0xffff) << 5)),
  hlt: (ops) => (count(ops, 1), 0xd4400000 | (inRange(ops[0], 0, 0xffff) << 5)),
  udf: (ops) => (count(ops, 1), inRange(ops[0], 0, 0xffff)),
  dsb: (ops) => barrier(4, ops),
  dmb: (ops) => barrier(5, ops),
  isb: (ops) => barrier(6, ops, 15),
  clrex: (ops) => barrier(2, ops, 15),
  sb: (ops) => (count(ops, 0), 0xd50330ff),

  adr: (ops, pc) => {
    count(ops, 2);
    const field = relative(target(ops[1]) - pc, 1, 21);
    return 0x10000000 | ((field & 3) << 29) | ((field >> 2) << 5) | xreg(ops[0]);
  },
  adrp: (ops, pc) => {
    count(ops, 2);
    const address = target(ops[1]);
    const field = relative(Math.floor(address / 4096) - Math.floor(pc / 4096), 1, 21, address - pc);
    return 0x90000000 | ((field & 3) << 29) | ((field >> 2) << 5) | xreg(ops[0]);
  },

  add: (ops) => (isD(ops[0]) ? scalarD(0, 16, ops) : addSub(0, 0, ops)),
  adds: (ops) => addSub(0, 1, ops),
  sub: (ops) => (isD(ops[0]) ? scalarD(1, 16, ops) : addSub(1, 0, ops)),
  subs: (ops) => addSub(1, 1, ops),
  cmp: (ops) => addSub(1, 1, [zrOf(ops[0]), ...ops]),
  cmn: (ops) => addSub(0, 1, [zrOf(ops[0]), ...ops]),
  neg: (ops) => (isD(ops[0]) ? scalarD(1, 11, ops) : (count(ops, 2, 3), addSub(1, 0, [ops[0]!, zrOf(ops[0]), ...ops.slice(1)]))),
  negs: (ops) => (count(ops, 2, 3), addSub(1, 1, [ops[0]!, zrOf(ops[0]), ...ops.slice(1)])),
  adc: (ops) => carry(0, 0, ops),
  adcs: (ops) => carry(0, 1, ops),
  sbc: (ops) => carry(1, 0, ops),
  sbcs: (ops) => carry(1, 1, ops),
  ngc: (ops) => (count(ops, 2), carry(1, 0, [ops[0]!, zrOf(ops[0]), ops[1]!])),
  ngcs: (ops) => (count(ops, 2), carry(1, 1, [ops[0]!, zrOf(ops[0]), ops[1]!])),

  and: (ops) => logical(0, 0, ops),
  orr: (ops) => logical(1, 0, ops),
  eor: (ops) => logical(2, 0, ops),
  ands: (ops) => logical(3, 0, ops),
  bic: (ops) => logical(0, 1, ops),
  orn: (ops) => logical(1, 1, ops),
  eon: (ops) => logical(2, 1, ops),
  bics: (ops) => logical(3, 1, ops),
  tst: (ops) => logical(3, 0, [zrOf(ops[0]), ...ops]),
  mvn: (ops) => (count(ops, 2, 3), isImm(ops[1]) ? fail() : logical(1, 1, [ops[0]!, zrOf(ops[0]), ...ops.slice(1)])),
  mov: (ops) => mov(ops),
  movz: (ops) => moveWide(2, ops),
  movn: (ops) => moveWide(0, ops),
  movk: (ops) => moveWide(3, ops),

  lsl: (ops) => shiftInsn(0, ops),
  lsr: (ops) => shiftInsn(1, ops),
  asr: (ops) => shiftInsn(2, ops),
  ror: (ops) => shiftInsn(3, ops),
  lslv: (ops) => dataProcessing2(8, ops),
  lsrv: (ops) => dataProcessing2(9, ops),
  asrv: (ops) => dataProcessing2(10, ops),
  rorv: (ops) => dataProcessing2(11, ops),
  udiv: (ops) => dataProcessing2(2, ops),
  sdiv: (ops) => dataProcessing2(3, ops),
  extr: (ops) => (count(ops, 4), extr(ops[0], ops[1], ops[2], ops[3])),
  sbfm: (ops) => (count(ops, 4), bitfield(0, ops[0], ops[1], inRange(ops[2], 0, widthOf(ops[0]) - 1), inRange(ops[3], 0, widthOf(ops[0]) - 1))),
  bfm: (ops) => (count(ops, 4), bitfield(1, ops[0], ops[1], inRange(ops[2], 0, widthOf(ops[0]) - 1), inRange(ops[3], 0, widthOf(ops[0]) - 1))),
  ubfm: (ops) => (count(ops, 4), bitfield(2, ops[0], ops[1], inRange(ops[2], 0, widthOf(ops[0]) - 1), inRange(ops[3], 0, widthOf(ops[0]) - 1))),
  sbfx: bitfieldAlias(0, false),
  bfxil: bitfieldAlias(1, false),
  ubfx: bitfieldAlias(2, false),
  sbfiz: bitfieldAlias(0, true),
  bfi: bitfieldAlias(1, true),
  ubfiz: bitfieldAlias(2, true),
  sxtb: (ops) => extend(0, 7, ops),
  sxth: (ops) => extend(0, 15, ops),
  sxtw: (ops) => (widthOf(ops[0]) === 64 ? extend(0, 31, ops) : fail()),
  // A zero-extend into x is the same as into w, which clears the top half anyway; LLVM takes both.
  uxtb: (ops) => extend(2, 7, [asW(ops[0]), ...ops.slice(1)]),
  uxth: (ops) => extend(2, 15, [asW(ops[0]), ...ops.slice(1)]),

  rbit: (ops) => dataProcessing1(0, ops),
  rev16: (ops) => dataProcessing1(1, ops),
  rev32: (ops) => dataProcessing1(2, ops, 'x'),
  rev: (ops) => dataProcessing1(widthOf(ops[0]) === 64 ? 3 : 2, ops),
  clz: (ops) => dataProcessing1(4, ops),
  cls: (ops) => dataProcessing1(5, ops),
  ctz: (ops) => dataProcessing1(6, ops),
  cnt: (ops) => dataProcessing1(7, ops),
  abs: (ops) => (isD(ops[0]) ? scalarD(0, 11, ops) : dataProcessing1(8, ops)),
  smax: (ops) => minMax(0, ops),
  umax: (ops) => minMax(1, ops),
  smin: (ops) => minMax(2, ops),
  umin: (ops) => minMax(3, ops),

  csel: (ops) => (count(ops, 4), condSelect(0, 0, ops[0], ops[1], ops[2], condition(ops[3]))),
  csinc: (ops) => (count(ops, 4), condSelect(0, 1, ops[0], ops[1], ops[2], condition(ops[3]))),
  csinv: (ops) => (count(ops, 4), condSelect(1, 0, ops[0], ops[1], ops[2], condition(ops[3]))),
  csneg: (ops) => (count(ops, 4), condSelect(1, 1, ops[0], ops[1], ops[2], condition(ops[3]))),
  cset: (ops) => (count(ops, 2), condSelect(0, 1, ops[0], zrOf(ops[0]), zrOf(ops[0]), invertible(ops[1]))),
  csetm: (ops) => (count(ops, 2), condSelect(1, 0, ops[0], zrOf(ops[0]), zrOf(ops[0]), invertible(ops[1]))),
  cinc: (ops) => (count(ops, 3), condSelect(0, 1, ops[0], ops[1], ops[1], invertible(ops[2]))),
  cinv: (ops) => (count(ops, 3), condSelect(1, 0, ops[0], ops[1], ops[1], invertible(ops[2]))),
  cneg: (ops) => (count(ops, 3), condSelect(1, 1, ops[0], ops[1], ops[1], invertible(ops[2]))),
  ccmn: (ops) => condCompare(0, ops),
  ccmp: (ops) => condCompare(1, ops),

  madd: (ops) => multiply(0, ops, true),
  msub: (ops) => multiply(1, ops, true),
  mul: (ops) => multiply(0, ops, false),
  mneg: (ops) => multiply(1, ops, false),
  smaddl: (ops) => multiplyLong(1, 0, ops, true),
  smsubl: (ops) => multiplyLong(1, 1, ops, true),
  umaddl: (ops) => multiplyLong(5, 0, ops, true),
  umsubl: (ops) => multiplyLong(5, 1, ops, true),
  smull: (ops) => multiplyLong(1, 0, ops, false),
  smnegl: (ops) => multiplyLong(1, 1, ops, false),
  umull: (ops) => multiplyLong(5, 0, ops, false),
  umnegl: (ops) => multiplyLong(5, 1, ops, false),
  smulh: (ops) => multiplyLong(2, 0, ops, false, true),
  umulh: (ops) => multiplyLong(6, 0, ops, false, true),

  ldp: (ops, _pc, m) => pair(m, ops),
  stp: (ops, _pc, m) => pair(m, ops),
  ldnp: (ops, _pc, m) => pair(m, ops),
  stnp: (ops, _pc, m) => pair(m, ops),
  ldpsw: (ops, _pc, m) => pair(m, ops),

  fmov: (ops) => fmov(ops),
  fcmp: (ops) => fpCompare(0, ops),
  fcmpe: (ops) => fpCompare(1, ops),
  fcsel: (ops) => {
    count(ops, 4);
    const rd = fpr(ops[0]);
    return 0x1e200c00 | (rd.type << 22) | (fpr(ops[2], rd).n << 16) | (condition(ops[3]) << 12) | (fpr(ops[1], rd).n << 5) | rd.n;
  },
  fccmp: (ops) => fpCondCompare(0, ops),
  fccmpe: (ops) => fpCondCompare(1, ops),
  fcvt: (ops) => {
    count(ops, 2);
    const rd = fpr(ops[0]);
    const rn = fpr(ops[1]);
    if (rd.cls === rn.cls) fail();
    return 0x1e204000 | (rn.type << 22) | ((4 + rd.type) << 15) | (rn.n << 5) | rd.n;
  },
  scvtf: (ops, _pc, m) => fpIntConvert(true, 0, 2, ops, m),
  ucvtf: (ops, _pc, m) => fpIntConvert(true, 0, 3, ops, m),
};

const asW = (op: Operand | undefined): Operand => (isGp(op) ? { ...op, cls: 'w' } : fail());

const isD = (op: Operand | undefined): boolean => isReg(op) && op.cls === 'd';

/** ADD, SUB (three-same) and NEG, ABS (two-register misc) on d registers: Advanced SIMD scalar. */
function scalarD(u: number, opcode: number, ops: Operand[]): number {
  const regs = ops.map((op) => (isD(op) ? (op as Reg).n : fail()));
  if (opcode === 11) {
    count(ops, 2);
    return 0x5ee0b800 | (u << 29) | (regs[1]! << 5) | regs[0]!;
  }
  count(ops, 3);
  return 0x5ee00400 | (u << 29) | (regs[2]! << 16) | (opcode << 11) | (regs[1]! << 5) | regs[0]!;
}

function zrOf(op: Operand | undefined): Reg {
  return zrLike(gpr(op, isSp(op) ? 'sp' : 'zr'));
}

function testBranch(nz: number, ops: Operand[], pc: number): number {
  count(ops, 3);
  const rt = gpr(ops[0]);
  const n = inRange(ops[1], 0, rt.cls === 'x' ? 63 : 31);
  return ((n >> 5) << 31) | 0x36000000 | (nz << 24) | ((n & 31) << 19) | (relative(target(ops[2]) - pc, 4, 14) << 5) | rt.n;
}

function fpCondCompare(e: number, ops: Operand[]): number {
  count(ops, 4);
  const rn = fpr(ops[0]);
  return 0x1e200400 | (rn.type << 22) | (fpr(ops[1], rn).n << 16) | (condition(ops[3]) << 12) | (rn.n << 5) | (e << 4) | inRange(ops[2], 0, 15);
}

for (const [i, m] of FP1.entries()) {
  if (!m || m === 'fmov') continue;
  ENCODERS[m] = (ops) => {
    count(ops, 2);
    const rd = fpr(ops[0]);
    if (i >= 16 && rd.cls === 'h') fail();
    return 0x1e204000 | (rd.type << 22) | (i << 15) | (fpr(ops[1], rd).n << 5) | rd.n;
  };
}
for (const [i, m] of FP2.entries()) {
  ENCODERS[m] = (ops) => {
    count(ops, 3);
    const rd = fpr(ops[0]);
    return 0x1e200800 | (rd.type << 22) | (fpr(ops[2], rd).n << 16) | (i << 12) | (fpr(ops[1], rd).n << 5) | rd.n;
  };
}
for (const [i, m] of FP3.entries()) {
  ENCODERS[m] = (ops) => {
    count(ops, 4);
    const rd = fpr(ops[0]);
    return 0x1f000000 | (rd.type << 22) | ((i >> 1) << 21) | (fpr(ops[2], rd).n << 16) | ((i & 1) << 15) | (fpr(ops[3], rd).n << 10) | (fpr(ops[1], rd).n << 5) | rd.n;
  };
}
// FCVTNS … FCVTAU: the rounding mode is rmode, except "a", which has opcodes of its own.
for (const mode of ['n', 'p', 'm', 'z', 'a']) {
  for (const [u, sign] of ['s', 'u'].entries()) {
    ENCODERS[`fcvt${mode}${sign}`] = (ops, _pc, m) => (mode === 'a' ? fpIntConvert(false, 0, 4 + u, ops, m) : fpIntConvert(false, 'npmz'.indexOf(mode), u, ops, m));
  }
}
for (const m of ['ldr', 'str', 'ldur', 'stur', 'ldtr', 'sttr', 'prfm', 'prfum']) {
  for (const suffix of ['', 'b', 'h', 'sb', 'sh', 'sw']) {
    if (m.startsWith('prf') && suffix) continue;
    ENCODERS[m + suffix] = (ops, pc) => single(m + suffix, ops, pc);
  }
}

function encode(line: Line, pc: number): number {
  const { m, ops } = line;
  const branch = /^(bc?)\.(\w+)$/.exec(m);
  if (branch) {
    count(ops, 1);
    const c = CONDS.indexOf(branch[2]!);
    if (c < 0) fail();
    return 0x54000000 | (relative(target(ops[0]) - pc, 4, 19) << 5) | (branch[1] === 'bc' ? 0x10 : 0) | c;
  }
  const encoder = ENCODERS[m];
  if (encoder) return encoder(ops, pc, m);
  const named: Record<string, number> = { ssbb: 0, pssbb: 4, dfb: 12 };
  const special = named[m] !== undefined ? barrier(4, ops, named[m]) : (hint(m, ops) ?? exclusive(m, ops) ?? atomic(m, ops));
  return special ?? unsupported();
}

/* ------------------------------------------------------------------ *
 * Meaning: what the round trip compares
 * ------------------------------------------------------------------ */

const LOGICAL_NOT: Record<string, string> = { bic: 'and', orn: 'orr', eon: 'eor', bics: 'ands' };
const BITFIELD_OPC = ['sbfm', 'bfm', 'ubfm'];

/**
 * One form for every spelling of an instruction: the aliases a person types
 * and the ones the decoder prints are taken to the same text when they mean
 * the same thing — `movz x0, #1` and `mov x0, #0x1`, `cmp w0, #-1` and
 * `cmn w0, #0x1`, `ubfx w0, w1, #0, #8` and `uxtb w0, w1`, `ldr x0,
 * [x1, #8]` and `ldur x0, [x1, #8]`. Both the input and the decoded word go
 * through it, so the comparison is between meanings, not spellings.
 */
function meaning(line: Line): Line {
  let m = line.m;
  let ops: Operand[] = line.ops
    .filter((op) => !(op.k === 'shift' && op.s === 'lsl' && op.amount === 0))
    .map((op) => (op.k === 'word' ? { k: 'word', w: condName(op.w) } : op));
  const width = (op: Operand | undefined): number => (isReg(op) && op.cls === 'x' ? 64 : 32);
  const inverse = (op: Operand | undefined): Operand => {
    const c = op?.k === 'word' ? CONDS.indexOf(op.w) : -1;
    return c < 0 || c >= 14 ? op! : { k: 'word', w: CONDS[c ^ 1]! };
  };

  if (m === 'ret' && isReg(ops[0]) && ops[0].cls === 'x' && ops[0].n === 30) ops = [];
  if (m === 'hint' && isImm(ops[0]) && HINTS[Number(ops[0].v)]) {
    const [name, operand] = HINTS[Number(ops[0].v)]!.split(' ');
    m = name!;
    ops = operand ? [{ k: 'word', w: operand }] : [];
  }
  // Barriers by number, as the names the decoder prints; DSB with these domains has names of its own.
  const dsb: Record<number, string> = { 0: 'ssbb', 4: 'pssbb', 12: 'dfb' };
  if ((m === 'dsb' || m === 'dmb') && isImm(ops[0])) {
    const n = Number(ops[0].v);
    if (m === 'dsb' && dsb[n]) {
      m = dsb[n]!;
      ops = [];
    } else if (BARRIERS[n]) ops = [{ k: 'word', w: BARRIERS[n]! }];
    else if (m === 'dsb' && NXS[n]) ops = [{ k: 'word', w: NXS[n]! }];
  }
  if ((m === 'isb' || m === 'clrex') && isImm(ops[0]) && ops[0].v === 15n) ops = [];
  if (/^(lsl|lsr|asr|ror)v$/.test(m)) m = m.slice(0, -1);
  if (LOGICAL_NOT[m] && isImm(ops[2])) {
    m = LOGICAL_NOT[m]!;
    ops = [ops[0]!, ops[1]!, { k: 'imm', v: ~ops[2].v }];
  }
  if ((m === 'subs' || m === 'adds' || m === 'ands') && isZr(ops[0])) {
    m = m === 'subs' ? 'cmp' : m === 'adds' ? 'cmn' : 'tst';
    ops = ops.slice(1);
  }
  // add/sub immediates: the lsl #12 folded into the value, a negative value turned around.
  const flip: Record<string, string> = { add: 'sub', sub: 'add', adds: 'subs', subs: 'adds', cmp: 'cmn', cmn: 'cmp' };
  const at = m === 'cmp' || m === 'cmn' ? 1 : 2;
  if (flip[m] && isImm(ops[at])) {
    let v = ops[at].v;
    if (ops[at + 1]?.k === 'shift') v <<= BigInt((ops[at + 1] as Shift).amount);
    if (v < 0n) {
      m = flip[m]!;
      v = -v;
    }
    ops = [...ops.slice(0, at), { k: 'imm', v }];
    if ((m === 'add' || m === 'sub') && v === 0n) {
      m = 'mov';
      ops = ops.slice(0, 2);
    }
  }
  if (flip[m] && ops[at + 1]?.k === 'shift') {
    // The extend that changes nothing reads as lsl.
    const ext = ops[at + 1] as Shift;
    if ((ext.s === 'uxtx' && width(ops[0]) === 64) || (ext.s === 'uxtw' && width(ops[0]) === 32)) {
      ops = [...ops.slice(0, at + 1), ...(ext.amount ? [{ ...ext, s: 'lsl' }] : [])];
    }
  }
  if ((m === 'sub' || m === 'subs') && isZr(ops[1]) && isReg(ops[2])) {
    m = m === 'sub' ? 'neg' : 'negs';
    ops = [ops[0]!, ...ops.slice(2)];
  }
  if (m === 'orr' && isZr(ops[1]) && ops.length === 3) {
    m = 'mov';
    ops = [ops[0]!, ops[2]!];
  }
  if (m === 'orn' && isZr(ops[1]) && isReg(ops[2])) {
    m = 'mvn';
    ops = [ops[0]!, ...ops.slice(2)];
  }
  if ((m === 'movz' || m === 'movn') && isImm(ops[1])) {
    const v = ops[1].v << BigInt(ops[2]?.k === 'shift' ? ops[2].amount : 0);
    ops = [ops[0]!, { k: 'imm', v: m === 'movn' ? ~v : v }];
    m = 'mov';
  }
  if (['mov', 'and', 'orr', 'eor', 'ands', 'tst'].includes(m)) {
    const last = ops[ops.length - 1];
    if (isImm(last)) ops = [...ops.slice(0, -1), { k: 'imm', v: BigInt.asUintN(width(ops[0]), last.v) }];
  }
  // The conditional aliases, first spelt out, then taken back to the one the decoder prefers.
  const spelled: Record<string, string> = { cset: 'csinc', csetm: 'csinv', cinc: 'csinc', cinv: 'csinv', cneg: 'csneg' };
  if (spelled[m] && isReg(ops[0])) {
    const n = m.startsWith('cset') ? zrLike(ops[0]) : ops[1]!;
    ops = [ops[0], n, n, inverse(ops[ops.length - 1])];
    m = spelled[m]!;
  }
  if (['csinc', 'csinv', 'csneg'].includes(m) && ops.length === 4 && isReg(ops[1]) && isReg(ops[2]) && ops[1].n === ops[2].n && ops[1].sp === ops[2].sp) {
    const c = ops[3]?.k === 'word' ? CONDS.indexOf(ops[3].w) : -1;
    if (c >= 0 && c < 14) {
      if (isZr(ops[1]) && m !== 'csneg') {
        m = m === 'csinc' ? 'cset' : 'csetm';
        ops = [ops[0]!, inverse(ops[3])];
      } else {
        m = m === 'csinc' ? 'cinc' : m === 'csinv' ? 'cinv' : 'cneg';
        ops = [ops[0]!, ops[1], inverse(ops[3])];
      }
    }
  }
  const lastZr = ops.length === 4 && isZr(ops[3]);
  const products: Record<string, string> = { madd: 'mul', msub: 'mneg', smaddl: 'smull', umaddl: 'umull', smsubl: 'smnegl', umsubl: 'umnegl' };
  if (products[m] && lastZr) {
    m = products[m]!;
    ops = ops.slice(0, 3);
  }

  // The bitfield aliases, as the bitfield move they are.
  let w = width(ops[0]);
  const same = (op: Operand | undefined): Operand => (isReg(op) ? { ...op, cls: w === 64 ? 'x' : 'w' } : op!);
  const num = (op: Operand | undefined): number => (isImm(op) ? Number(op.v) : NaN);
  const bfm = (opc: number, immr: number, imms: number): void => {
    m = BITFIELD_OPC[opc]!;
    ops = [ops[0]!, same(ops[1]), { k: 'imm', v: BigInt(immr) }, { k: 'imm', v: BigInt(imms) }];
  };
  const fieldAliases: Record<string, [number, boolean]> = { sbfx: [0, false], bfxil: [1, false], ubfx: [2, false], sbfiz: [0, true], bfi: [1, true], ubfiz: [2, true] };
  if (fieldAliases[m] && ops.length === 4) {
    const [opc, insert] = fieldAliases[m]!;
    const lsb = num(ops[2]);
    const size = num(ops[3]);
    if (insert) bfm(opc, (w - lsb) % w, size - 1);
    else bfm(opc, lsb, lsb + size - 1);
  } else if ((m === 'lsl' || m === 'lsr' || m === 'asr') && isImm(ops[2])) {
    const s = num(ops[2]);
    if (m === 'lsl') bfm(2, (w - s) % w, w - 1 - s);
    else bfm(m === 'lsr' ? 2 : 0, s, w - 1);
  } else if (m === 'ror' && isImm(ops[2])) {
    m = 'extr';
    ops = [ops[0]!, ops[1]!, ops[1]!, ops[2]];
  } else if (/^[su]xt[bhw]$/.test(m) && ops.length === 2) {
    if (m.startsWith('u') && isReg(ops[0])) ops = [{ ...ops[0], cls: 'w' }, ops[1]!];
    w = width(ops[0]);
    bfm(m[0] === 's' ? 0 : 2, 0, m[3] === 'b' ? 7 : m[3] === 'h' ? 15 : 31);
  }

  if ((m === 'tbz' || m === 'tbnz') && isReg(ops[0]) && isImm(ops[1]) && ops[1].v < 32n) ops = [{ ...ops[0], cls: 'w' }, ...ops.slice(1)];
  if (/^((ld|st)r(b|h|sb|sh|sw)?|prfm)$/.test(m) && ops[1]?.k === 'mem' && ops[1].mode === 'off' && !ops[1].index) {
    m = m === 'prfm' ? 'prfum' : m.replace(/^(ld|st)r/, '$1ur');
  }
  if (m === 'fmov' || m === 'fcmp' || m === 'fcmpe') {
    ops = ops.map((op) => (isImm(op) ? { k: 'float', v: Number(op.v) } : op));
    if (m === 'fmov' && ops[1]?.k === 'float' && ops[1].v === 0 && !Object.is(ops[1].v, -0) && isReg(ops[0])) {
      ops = [ops[0], zrLike({ ...ops[0], cls: ops[0].cls === 'd' ? 'x' : 'w' })];
    }
  }
  const lse = /^ld(add|clr|eor|set|smax|smin|umax|umin)(l?)(b|h)?$/.exec(m);
  if (lse && ops.length === 3 && isZr(ops[1])) {
    m = `st${lse[1]}${lse[2]}${lse[3] ?? ''}`;
    ops = [ops[0]!, ops[2]!];
  }
  if (m === 'adrp' && isImm(ops[1])) ops = [ops[0]!, { k: 'imm', v: ops[1].v & ~0xfffn }];
  return { m, ops };
}

function canonical(op: Operand): string {
  switch (op.k) {
    case 'reg':
      return regName(op);
    case 'imm':
      return `#${op.v}`;
    case 'float':
      return `#f${op.v}`;
    case 'word':
      return op.w;
    case 'shift':
      return op.amount ? `${op.s} #${op.amount}` : op.s;
    case 'mem': {
      let inner = regName(op.base);
      if (op.index) {
        inner += `, ${regName(op.index)}`;
        if (op.ext && !(op.ext.s === 'lsl' && !op.ext.amount)) inner += `, ${canonical(op.ext)}`;
      } else inner += `, #${op.off}`;
      return `[${inner}]${op.mode === 'pre' ? '!' : op.mode === 'post' ? ' post' : ''}`;
    }
  }
}

const spell = (line: Line): string => `${line.m} ${line.ops.map(canonical).join(', ')}`;

function sameMeaning(input: Line, decoded: string): boolean {
  let back: Line | null;
  try {
    back = parse(decoded);
  } catch {
    return false;
  }
  return !!back && spell(meaning(input)) === spell(meaning(back));
}

/* ------------------------------------------------------------------ */

/**
 * One instruction in the syntax the decoder prints, to be placed at `pc`.
 * `resolve` gives the address of a name — a function, a label, a symbol —
 * where the text uses one as a branch or address target.
 */
export function assemble(text: string, pc: number, resolve?: (name: string) => number | undefined): Assembled | AssembleError {
  let line: Line | null = null;
  try {
    line = parse(text, resolve);
    if (!line) return { error: t('assemble', 'Enter an instruction.') };
    const word = encode(line, pc) >>> 0;
    if (line.m === '.inst') return { word };
    const back = formatInsn(decode(word, pc));
    if (!sameMeaning(line, back)) return { error: t('assemble', 'This assembles to “{text}”, not to what was entered; enter the encoding in hex instead.', { text: back }) };
    return { word };
  } catch (e) {
    if (!(e instanceof Problem)) throw e;
    return { error: e.message ?? t('assemble', 'The operands do not fit {mnemonic}.', { mnemonic: line?.m ?? '' }) };
  }
}
