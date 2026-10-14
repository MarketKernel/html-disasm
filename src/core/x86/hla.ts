/**
 * The HLA64 view of x86-64 code. HLA64 has an x64 target, with the same
 * sugar as on ARM64 over x86's registers: `rax = [rbx + 8]`, `eax = u8[rdi]`,
 * `rcx += rdx`, `if eax < ebx { goto L }`, `printf()`. As on ARM64 a line is
 * one instruction, or a compare joined with the jump or conditional move that
 * tests its flags, and it uses sugar only where the sugar means exactly what
 * the instruction does; anything else stays the instruction.
 *
 * Two of x86's mnemonics are words of HLA64 itself: on x64 HLA64's `push` and
 * `pop` keep registers in frame slots, so a real `push rbx` is written as
 * what it does (`rsp -= 8; [rsp] = rbx`), and an instruction whose mnemonic
 * HLA64 would read as a keyword (`loop`) goes into `asm "…"`.
 *
 * The operands are read from the instruction as LLVM prints it in Intel
 * syntax, which is regular enough to parse: registers, immediates, and
 * `qword ptr [base + 4*index + disp]`.
 */

import { F } from '../arm64/types';
import { hlaName, type HlaLine, type LiftContext } from '../hla';
import type { X86Insn } from './program';

export interface X86LiftContext extends LiftContext {
  /** The import whose slot is at an address (`call qword ptr [rip + …]`). */
  importAt(addr: number): string | undefined;
}

type Operand =
  | { k: 'reg'; r: string; bits: number }
  | { k: 'imm'; v: number }
  | { k: 'mem'; size: number; seg: string; base: string; index: string; scale: number; disp: number }
  | { k: 'other'; t: string };

const SIZES: Record<string, number> = { byte: 8, word: 16, dword: 32, qword: 64, tbyte: 80, xmmword: 128, ymmword: 256, zmmword: 512 };
const LEGACY = ['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di'];

/** The width of a general register, or 0: rax 64, eax 32, ax 16, al 8; xmm 128. */
function registerBits(r: string): number {
  if (/^r(?:[abcd]x|[sd]i|[sb]p|\d+)$/.test(r)) return 64;
  if (/^(?:e(?:[abcd]x|[sd]i|[sb]p)|r\d+d)$/.test(r)) return 32;
  if (/^(?:[abcd]x|[sd]i|[sb]p|r\d+w)$/.test(r)) return 16;
  if (/^(?:[abcd][lh]|[sd]il|[sb]pl|r\d+b)$/.test(r)) return 8;
  if (/^xmm\d+$/.test(r)) return 128;
  return 0;
}

/** The 32-bit name of a general register, the width HLA64 names next to the 64-bit one: cl → ecx. */
function name32(r: string): string | undefined {
  let m = /^r(\d+)[bwd]?$/.exec(r);
  if (m) return `r${m[1]}d`;
  m = /^(?:e|r)?([abcd])(?:x|l)$/.exec(r);
  if (m) return `e${m[1]}x`;
  m = /^(?:e|r)?([sd]i|[sb]p)l?$/.exec(r);
  if (m && LEGACY.includes(m[1]!)) return `e${m[1]}`;
  return undefined;
}

function parseOperand(text: string): Operand {
  const t = text.trim();
  const bits = registerBits(t);
  if (bits) return { k: 'reg', r: t, bits };
  if (/^-?0x[0-9a-f]+$/.test(t)) return { k: 'imm', v: t.startsWith('-') ? -parseInt(t.slice(1), 16) : parseInt(t, 16) };
  const m = /^(?:(\w+) ptr )?(?:([cdefgs]s):)?\[([^\]]*)\]$/.exec(t);
  if (m) {
    const mem = { k: 'mem' as const, size: m[1] ? SIZES[m[1]] ?? 0 : 0, seg: m[2] ?? '', base: '', index: '', scale: 1, disp: 0 };
    for (const part of m[3]!.replace(/ - /g, ' + -').split(' + ')) {
      const p = part.trim();
      const scaled = /^(\d)\*(\w+)$/.exec(p);
      if (scaled) {
        mem.scale = Number(scaled[1]);
        mem.index = scaled[2]!;
      } else if (/^-?0x[0-9a-f]+$/.test(p)) mem.disp = p.startsWith('-') ? -parseInt(p.slice(1), 16) : parseInt(p, 16);
      else if (registerBits(p) || p === 'rip') {
        if (mem.base) mem.index = p;
        else mem.base = p;
      } else return { k: 'other', t };
    }
    return mem;
  }
  return { k: 'other', t };
}

/** The operands of a printed instruction, split at the commas between them. */
function operandsOf(ops: string): Operand[] {
  if (!ops) return [];
  const out: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < ops.length; i++) {
    const c = ops[i];
    if (c === '[' || c === '{') depth++;
    else if (c === ']' || c === '}') depth--;
    else if (c === ',' && depth === 0) {
      out.push(ops.slice(start, i));
      start = i + 1;
    }
  }
  out.push(ops.slice(start));
  return out.map(parseOperand);
}

const num = (v: number): string => (Math.abs(v) < 10 ? String(v) : v < 0 ? `-0x${(-v).toString(16)}` : `0x${v.toString(16)}`);
/** A general register HLA64 can name in sugar: the 64- and 32-bit ones. */
const isGpr = (op: Operand | undefined): op is Extract<Operand, { k: 'reg' }> => op?.k === 'reg' && (op.bits === 64 || op.bits === 32);
const isXmm = (op: Operand | undefined): op is Extract<Operand, { k: 'reg' }> => op?.k === 'reg' && op.bits === 128;

/** A value: a register, an immediate. */
function value(op: Operand | undefined): string | null {
  if (op?.k === 'reg') return op.r;
  if (op?.k === 'imm') return num(op.v);
  return null;
}

/** What a memory operand addresses, as HLA64 writes it inside brackets; rip-relative ones by name. */
function address(mem: Extract<Operand, { k: 'mem' }>, insn: X86Insn, ctx: X86LiftContext, words: string[]): string | null {
  if (mem.seg) return null;
  if (mem.base === 'rip') {
    if (insn.mem === undefined) return null;
    const data = ctx.data(insn.mem);
    const target = ctx.target(insn.mem);
    words.push('address');
    if (target) return `&${target.kind === 'label' ? target.name : hlaName(target.name, words)}`;
    if (data?.kind === 'symbol') return `&${hlaName(data.name, words)}`;
    return `&data_${insn.mem.toString(16)}`;
  }
  if (mem.base && registerBits(mem.base) !== 64) return null;
  if (mem.index && registerBits(mem.index) !== 64) return null;
  const parts: string[] = [];
  if (mem.base) parts.push(mem.base);
  if (mem.index) parts.push(mem.scale === 1 ? mem.index : `${mem.index} * ${mem.scale}`);
  let text = parts.join(' + ');
  if (mem.disp) text = text ? `${text} ${mem.disp < 0 ? '-' : '+'} ${num(Math.abs(mem.disp))}` : num(mem.disp);
  return text || '0';
}

/** A load or store's type prefix for the access size: '' when the register's width says it. */
function typeOf(bits: number, regBits: number, signed: boolean): string {
  if (bits === regBits && !signed) return '';
  return `${signed ? 'i' : 'u'}${bits}`;
}

const SIGNED: Record<string, string> = { e: '==', ne: '!=', l: '<', le: '<=', g: '>', ge: '>=' };
const UNSIGNED: Record<string, string> = { b: '<u', be: '<=u', a: '>u', ae: '>=u' };
const ZERO: Record<string, string> = { e: '== 0', ne: '!= 0', s: '< 0', ns: '>= 0' };

/** The branch or call target by name. */
function targetText(insn: X86Insn, ctx: X86LiftContext, words: string[]): string | null {
  if (insn.target === undefined) return null;
  const t = ctx.target(insn.target);
  if (!t) return num(insn.target);
  return t.kind === 'label' ? t.name : hlaName(t.name, words);
}

/** Mnemonics HLA64 would read as its own words, not as instructions. */
const KEYWORDS = new Set(['push', 'pop', 'loop', 'return', 'if', 'goto', 'let', 'local', 'data', 'fn', 'while', 'for', 'do', 'switch', 'break', 'continue']);

/** The instruction as printed, with branch targets by name — in `asm "…"` when HLA64 would take it for a word of its own. */
export function rawX86(insn: X86Insn, ctx: X86LiftContext): string {
  let ops = insn.ops;
  if (insn.target !== undefined) {
    const t = ctx.target(insn.target);
    if (t) ops = ops.replace(`0x${insn.target.toString(16)}`, t.kind === 'label' ? t.name : hlaName(t.name, []));
  }
  const text = [insn.prefix, insn.m, ops].filter(Boolean).join(' ');
  return KEYWORDS.has(insn.m) || KEYWORDS.has(insn.prefix.split(' ')[0] ?? '') ? `asm ${JSON.stringify(text)}` : text;
}

/**
 * A locked read-modify-write as the atomic it is — every locked instruction
 * on x86 is sequentially consistent: `lock add [mem], r` is atomic_add,
 * `lock xadd` the same returning the old value, `lock cmpxchg` a compare and
 * swap, `xchg` with memory (locked without the prefix) a swap.
 */
function atomic(insn: X86Insn, locked: boolean, ctx: X86LiftContext, words: string[]): string | null {
  const [d, s] = operandsOf(insn.ops);
  if (d?.k !== 'mem' || !d.size || d.size > 64) return null;
  const at = address(d, insn, ctx, words);
  if (at === null) return null;
  const cell = `u${d.size}[${at}]`;
  const reg = s?.k === 'reg' ? (s.bits === d.size && s.bits >= 32 ? s.r : s.bits === d.size ? name32(s.r) : undefined) : undefined;
  const m = insn.m;
  if (m === 'xchg' && reg) {
    words.push('atomic');
    return `${reg} = atomic_swap(${cell}, ${reg}, seq_cst)`;
  }
  if (!locked) return null;
  if (m === 'cmpxchg' && reg) {
    words.push('cas');
    const acc = d.size === 64 ? 'rax' : 'eax';
    if (d.size < 32) return null;
    return `${acc} = cas(${cell}, ${acc}, ${reg}, seq_cst)`;
  }
  if (m === 'xadd' && reg) {
    words.push('atomic');
    return `${reg} = atomic_add(${cell}, ${reg}, seq_cst)`;
  }
  const operand = m === 'inc' ? '1' : m === 'dec' ? '-1' : reg ?? (s?.k === 'imm' ? num(s.v) : null);
  const name = { add: 'atomic_add', inc: 'atomic_add', dec: 'atomic_add', or: 'atomic_or', xor: 'atomic_eor' }[m];
  if (!name || operand === null) return null;
  words.push('atomic');
  return `${name}(${cell}, ${operand}, seq_cst)`;
}

function lift(insn: X86Insn, ctx: X86LiftContext, words: string[]): string | null {
  if (insn.prefix === 'lock' || insn.m === 'xchg') return atomic(insn, insn.prefix === 'lock', ctx, words);
  if (insn.prefix || insn.f & F.UNKNOWN || insn.m.startsWith('.')) return null;
  const ops = operandsOf(insn.ops);
  const [d, a, b] = ops;
  const m = insn.m;
  const mem = (op: Operand | undefined) => (op?.k === 'mem' ? address(op, insn, ctx, words) : null);
  // A memory operand in an arithmetic expression, typed by its size when that is not the register's.
  const source = (op: Operand | undefined, regBits: number): string | null => {
    if (op?.k === 'mem') {
      if (op.size !== regBits) return null;
      const at = mem(op);
      if (at === null) return null;
      words.push('memory');
      return `[${at}]`;
    }
    if (op?.k === 'reg' && op.bits !== regBits) return null;
    return value(op);
  };
  switch (m) {
    case 'mov':
    case 'movabs': {
      if (isGpr(d)) {
        if (a?.k === 'mem') {
          if (a.size !== d.bits) return null;
          const at = mem(a);
          if (at === null) return null;
          words.push('memory');
          return `${d.r} = [${at}]`;
        }
        if (a?.k === 'reg' && a.bits !== d.bits) return null;
        const v = value(a);
        if (v === null) return null;
        words.push('assign');
        return `${d.r} = ${v}`;
      }
      if (d?.k === 'mem') {
        const at = mem(d);
        if (at === null || !d.size || d.size > 64) return null;
        let v: string | null;
        if (a?.k === 'reg') {
          // A narrow store names the register by its 32-bit view: `mov byte ptr [rax], cl` is `u8[rax] = ecx`.
          v = a.bits === d.size && a.bits >= 32 ? a.r : a.bits === d.size ? name32(a.r) ?? null : null;
          if (/^[abcd]h$/.test(a.r)) return null;
        } else v = value(a);
        if (v === null) return null;
        const type = d.size === 64 ? '' : d.size === 32 && a?.k === 'reg' ? '' : `u${d.size}`;
        words.push(type ? 'typed-memory' : 'memory');
        return `${type}[${at}] = ${v}`;
      }
      return null;
    }
    case 'movzx':
    case 'movsx':
    case 'movsxd': {
      if (!isGpr(d)) return null;
      const signed = m !== 'movzx';
      if (a?.k === 'mem') {
        const at = mem(a);
        if (at === null || !a.size) return null;
        words.push('typed-memory');
        return `${d.r} = ${typeOf(a.size, d.bits, signed) || `${signed ? 'i' : 'u'}${a.size}`}[${at}]`;
      }
      if (a?.k === 'reg') {
        if (/^[abcd]h$/.test(a.r)) return null;
        const wide = a.bits === 32 ? a.r : name32(a.r);
        if (!wide) return null;
        words.push('extend');
        return `${d.r} = ${signed ? 'sext' : 'zext'}${a.bits}(${wide})`;
      }
      return null;
    }
    case 'lea': {
      if (!isGpr(d) || a?.k !== 'mem' || a.seg) return null;
      if (a.base === 'rip') {
        if (insn.mem === undefined) return null;
        const data = ctx.data(insn.mem);
        if (data?.kind === 'string') {
          words.push(data.objc ? 'nsstring' : 'string');
          return `${d.r} = ${data.objc ? '@' : ''}${JSON.stringify(data.text.length > 80 ? `${data.text.slice(0, 80)}…` : data.text)}`;
        }
        const at = address(a, insn, ctx, words);
        return at === null ? null : `${d.r} = ${at}`;
      }
      if (d.bits !== 64) return null;
      const at = address(a, insn, ctx, words);
      if (at === null) return null;
      words.push('arith');
      return `${d.r} = ${at}`;
    }
    case 'add':
    case 'sub':
    case 'and':
    case 'or':
    case 'xor':
    case 'imul': {
      if (!isGpr(d)) return null;
      const op = { add: '+', sub: '-', and: '&', or: '|', xor: '^', imul: '*' }[m]!;
      if (m === 'xor' && a?.k === 'reg' && a.r === d.r) {
        words.push('assign');
        return `${d.r} = 0`;
      }
      if (m === 'imul' && b) {
        const left = source(a, d.bits);
        const right = value(b);
        if (left === null || right === null) return null;
        words.push('arith');
        return `${d.r} = ${left} * ${right}`;
      }
      if (m === 'imul' && !a) return null;
      const right = source(a, d.bits);
      if (right === null) return null;
      words.push('arith', 'compound');
      return `${d.r} ${op}= ${right}`;
    }
    case 'shl':
    case 'shr':
    case 'sar': {
      if (!isGpr(d)) return null;
      const op = { shl: '<<', shr: '>>>', sar: '>>' }[m]!;
      const count = a === undefined ? '1' : a.k === 'reg' && a.r === 'cl' ? (d.bits === 64 ? 'rcx' : 'ecx') : value(a);
      if (count === null) return null;
      words.push('shift', 'compound');
      return `${d.r} ${op}= ${count}`;
    }
    case 'ror':
    case 'rol': {
      if (!isGpr(d) || a?.k !== 'imm') return null;
      words.push('ror');
      return `${d.r} = ror(${d.r}, ${m === 'ror' ? a.v : d.bits - (a.v % d.bits)})`;
    }
    case 'neg':
    case 'not':
      if (!isGpr(d)) return null;
      words.push('arith');
      return `${d.r} = ${m === 'neg' ? '-' : '~'}${d.r}`;
    case 'inc':
    case 'dec':
      if (!isGpr(d)) return null;
      words.push('compound');
      return `${d.r} ${m === 'inc' ? '+' : '-'}= 1`;
    case 'push': {
      // A register, or an immediate sign-extended to 64 bits as the push does.
      const pushed = d?.k === 'reg' && d.bits === 64 ? d.r : d?.k === 'imm' ? num(d.v) : null;
      if (pushed === null) return null;
      words.push('compound', 'memory');
      return `rsp -= 8; [rsp] = ${pushed}`;
    }
    case 'pop': {
      if (d?.k !== 'reg' || d.bits !== 64) return null;
      words.push('compound', 'memory');
      return `${d.r} = [rsp]; rsp += 8`;
    }
    case 'call': {
      if (insn.target !== undefined) {
        words.push('call');
        return `${targetText(insn, ctx, words)}()`;
      }
      if (isGpr(d) && d.bits === 64) {
        words.push('call');
        return `${d.r}()`;
      }
      const imported = insn.mem !== undefined ? ctx.importAt(insn.mem) : undefined;
      if (imported && d?.k === 'mem' && d.base === 'rip') {
        words.push('call');
        return `${hlaName(imported, words)}()`;
      }
      return null;
    }
    case 'jmp': {
      if (insn.target !== undefined) {
        const t = ctx.target(insn.target);
        if (t && t.kind !== 'label' && insn.target !== ctx.functionStart(insn.addr)) {
          words.push('tail-call');
          return `return ${hlaName(t.name, words)}()`;
        }
        words.push('goto');
        return `goto ${targetText(insn, ctx, words)}`;
      }
      const imported = insn.mem !== undefined ? ctx.importAt(insn.mem) : undefined;
      if (imported && d?.k === 'mem' && d.base === 'rip') {
        words.push('tail-call');
        return `return ${hlaName(imported, words)}()`;
      }
      if (isGpr(d) && d.bits === 64) {
        words.push('jump-table');
        return `goto [${d.r}]`;
      }
      return null;
    }
    case 'ret':
      if (ops.length) return null;
      words.push('return');
      return 'return';
    // Scalar double precision: HLA64's xmm registers hold doubles.
    case 'addsd':
    case 'subsd':
    case 'mulsd':
    case 'divsd': {
      if (!isXmm(d)) return null;
      const right = a?.k === 'mem' ? (a.size === 64 && mem(a) !== null ? `f64[${mem(a)}]` : null) : isXmm(a) ? a.r : null;
      if (right === null) return null;
      words.push('float', 'compound');
      return `${d.r} ${{ addsd: '+', subsd: '-', mulsd: '*', divsd: '/' }[m]}= ${right}`;
    }
    case 'sqrtsd':
      if (!isXmm(d) || !isXmm(a)) return null;
      words.push('float');
      return `${d.r} = sqrt(${a.r})`;
    case 'movsd': {
      if (isXmm(d) && a?.k === 'mem' && a.size === 64) {
        const at = mem(a);
        if (at === null) return null;
        words.push('float', 'typed-memory');
        return `${d.r} = f64[${at}]`;
      }
      if (d?.k === 'mem' && d.size === 64 && isXmm(a)) {
        const at = mem(d);
        if (at === null) return null;
        words.push('float', 'typed-memory');
        return `f64[${at}] = ${a.r}`;
      }
      return null;
    }
    case 'movaps':
    case 'movapd':
      if (!isXmm(d) || !isXmm(a)) return null;
      words.push('assign');
      return `${d.r} = ${a.r}`;
    case 'xorps':
    case 'xorpd':
      if (!isXmm(d) || !isXmm(a) || a.r !== d.r) return null;
      words.push('float');
      return `${d.r} = 0.0`;
    case 'cvtsi2sd':
      if (!isXmm(d) || !isGpr(a)) return null;
      words.push('float');
      return `${d.r} = float(${a.r})`;
    case 'cvttsd2si':
      if (!isGpr(d) || !isXmm(a)) return null;
      words.push('float');
      return `${d.r} = int(${a.r})`;
  }
  return null;
}

/** One instruction as an HLA64 line; the instruction itself when HLA64 has no word that means the same. */
export function liftX86(insn: X86Insn, ctx: X86LiftContext): HlaLine {
  const words: string[] = [];
  let text: string | null = null;
  try {
    text = lift(insn, ctx, words);
  } catch {
    text = null;
  }
  if (text === null) return { text: rawX86(insn, ctx), words: ['instruction'] };
  return { text, words: [...new Set(words)] };
}

/* ------------------------------------------------------------------ *
 * A compare and the jump or conditional move that reads its flags
 * ------------------------------------------------------------------ */

export const X86_SETTERS = new Set(['cmp', 'test', 'add', 'sub', 'and', 'or', 'xor', 'inc', 'dec', 'neg', 'ucomisd', 'comisd', 'lock']);
/** What a lone `lock` line makes atomic. */
const LOCKABLE = new Set(['add', 'or', 'xor', 'inc', 'dec', 'xadd', 'cmpxchg']);
const CC = 'o|no|b|ae|e|ne|be|a|s|ns|p|np|l|ge|le|g';
const JCC = new RegExp(`^j(${CC})$`);
const CMOV = new RegExp(`^cmov(${CC})$`);

/** Whether an instruction reads the flags a setter left: jcc or cmovcc. */
export const isX86Consumer = (m: string): boolean => JCC.test(m) || CMOV.test(m) || LOCKABLE.has(m);

/** What the flags of `setter` say under `cond`, as an expression; and a statement before it when the setter has a result. */
function relation(setter: X86Insn, cond: string, ctx: X86LiftContext, words: string[]): { pre?: string; expr: string } | null {
  if (setter.prefix) return null;
  const [a, b] = operandsOf(setter.ops);
  const m = setter.m;
  if (m === 'ucomisd' || m === 'comisd') {
    // Unordered compares set ZF, PF and CF together: only `above` and `above or equal` exclude NaN.
    if (!isXmm(a) || !isXmm(b) || (cond !== 'a' && cond !== 'ae')) return null;
    words.push('float');
    return { expr: `${a.r} ${cond === 'a' ? '>' : '>='} ${b.r}` };
  }
  if (!isGpr(a)) return null;
  if (m === 'cmp') {
    const right = b?.k === 'reg' ? (b.bits === a.bits ? b.r : null) : value(b);
    if (right === null) return null;
    if (SIGNED[cond]) return { expr: `${a.r} ${SIGNED[cond]} ${right}` };
    if (UNSIGNED[cond]) {
      words.push('unsigned-compare');
      return { expr: `${a.r} ${UNSIGNED[cond]} ${right}` };
    }
    return null;
  }
  if (m === 'test') {
    const same = b?.k === 'reg' && b.r === a.r;
    const anded = same ? a.r : b?.k === 'reg' && b.bits === a.bits ? `${a.r} & ${b.r}` : b?.k === 'imm' ? `${a.r} & ${num(b.v)}` : null;
    if (anded === null) return null;
    if (!same) words.push('arith');
    if (ZERO[cond]) return { expr: `${anded} ${ZERO[cond]}` };
    // test clears OF: the signed conditions compare the result with zero.
    if (SIGNED[cond]) return { expr: `${anded} ${SIGNED[cond]} 0` };
    return null;
  }
  // An operation with a result: the line does it, then tests the result against zero.
  const test = ZERO[cond];
  if (!test) return null;
  const pre = lift(setter, ctx, words);
  if (!pre || pre.includes(';')) return null;
  return { pre, expr: `${a.r} ${test}` };
}

/** A setter and the consumer after it as one line, or null when they do not pair; or a `lock` and the instruction it makes atomic. */
export function fuseX86(first: X86Insn, second: X86Insn, ctx: X86LiftContext): HlaLine | null {
  const words: string[] = [];
  if (first.m === 'lock' && !first.ops && !second.prefix) {
    const text = atomic(second, true, ctx, words);
    return text ? { text, words: [...new Set(words)] } : null;
  }
  if (!X86_SETTERS.has(first.m) || second.prefix) return null;
  let match = JCC.exec(second.m);
  if (match) {
    const rel = relation(first, match[1]!, ctx, words);
    const target = rel ? targetText(second, ctx, words) : null;
    if (!rel || target === null) return null;
    words.push('if-goto');
    const tail = `if ${rel.expr} { goto ${target} }`;
    return { text: rel.pre ? `${rel.pre}; ${tail}` : tail, words: [...new Set(words)] };
  }
  match = CMOV.exec(second.m);
  if (match) {
    const [d, s] = operandsOf(second.ops);
    if (!isGpr(d) || !isGpr(s) || s.bits !== d.bits) return null;
    const rel = relation(first, match[1]!, ctx, words);
    if (!rel) return null;
    words.push('ternary');
    const tail = `${d.r} = ${rel.expr} ? ${s.r} : ${d.r}`;
    return { text: rel.pre ? `${rel.pre}; ${tail}` : tail, words: [...new Set(words)] };
  }
  return null;
}
