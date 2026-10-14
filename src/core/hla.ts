/**
 * The HLA64 view: decoded instructions written as HLA64.
 *
 * HLA64 is an assembler with sugar, not a separate language, so this is not
 * decompilation: each line still stands for the instruction (or the two) at
 * its address. Where HLA64 has a word for what an instruction does —
 * `x0 = [x1 + 8]`, `if x8 == 0 { goto L… }`, `push x29, x30`, `f()` — the
 * line uses it; where it has none (SIMD, exclusives, system registers) the
 * instruction stays as it is, which HLA64 accepts too.
 *
 * Two kinds of neighbours read better as one line, and fuse() joins them: a
 * compare and the branch or select that tests its flags, and the adrp + add
 * (or load) that together build an address.
 *
 * Each line lists the words of src/data/hla64-words.json it uses, so the
 * page can explain them; words marked "new" there are this project's
 * additions to HLA64.
 */

import { F, formatInsn, type Insn, type Op } from './arm64/types';
import type { DataAt } from './disassembly';

export interface Target {
  name: string;
  kind: 'label' | 'function' | 'import';
}

export interface LiftContext {
  /** How to name a branch or call target. */
  target(addr: number): Target | undefined;
  /** What is at a data address: a string, or a named symbol. */
  data(addr: number): DataAt;
  /** Start of the function the instruction is in (for telling a tail call from a goto). */
  functionStart(pc: number): number;
}

export interface HlaLine {
  text: string;
  words: string[];
  comment?: string;
}

const num = (v: number): string => (Math.abs(v) < 10 ? String(v) : v < 0 ? `-0x${(-v).toString(16)}` : `0x${v.toString(16)}`);

/** An immediate operand as HLA64 writes it (64-bit ones keep LLVM's exact text). */
function immOf(op: Op): string {
  if (op.k !== 'imm') return '?';
  if (Math.abs(op.v) >= 2 ** 53 || !Number.isFinite(op.v)) return op.t.replace(/^#/, '');
  if (!Number.isInteger(op.v)) return op.t.replace(/^#/, '');
  return num(op.v);
}

const isZr = (r: string) => r === 'xzr' || r === 'wzr';
const val = (op: Op | undefined): string => {
  if (!op) return '?';
  if (op.k === 'reg') return isZr(op.r) ? '0' : op.r;
  if (op.k === 'imm') return immOf(op);
  if (op.k === 'text') return op.t;
  return '?';
};
const regNo = (r: string): string => (r === 'sp' || r === 'wsp' ? 'sp' : r.replace(/^[xw]/, 'r'));
const sameReg = (a: Op | undefined, b: Op | undefined) => a?.k === 'reg' && b?.k === 'reg' && regNo(a.r) === regNo(b.r);

const EXTEND_FN: Record<string, string> = { uxtb: 'zext8', uxth: 'zext16', uxtw: 'zext32', sxtb: 'sext8', sxth: 'sext16', sxtw: 'sext32' };

/** The second operand of an arithmetic instruction with its optional shift or extension. */
function operand2(ops: Op[], words: string[]): string {
  const [value, mod] = ops;
  if (!value) return '?';
  let text = val(value);
  if (!mod) return text;
  if (mod.k === 'shift') {
    if (value.k === 'imm') return num(value.v * 2 ** mod.amount);
    if (EXTEND_FN[mod.s]) {
      words.push('extend');
      text = `${EXTEND_FN[mod.s]}(${text})`;
      return mod.amount ? `(${text} << ${mod.amount})` : text;
    }
    if (mod.s === 'uxtx' || mod.s === 'sxtx') return mod.amount ? `(${text} << ${mod.amount})` : text;
    words.push('shift');
    const op = { lsl: '<<', lsr: '>>>', asr: '>>' }[mod.s];
    if (!op) {
      words.push('ror');
      return `ror(${text}, ${mod.amount})`;
    }
    return `(${text} ${op} ${mod.amount})`;
  }
  if (mod.k === 'text' && EXTEND_FN[mod.t]) {
    words.push('extend');
    return `${EXTEND_FN[mod.t]}(${text})`;
  }
  if (mod.k === 'text' && (mod.t === 'uxtx' || mod.t === 'sxtx')) return text;
  return text;
}

/** `d = a op b`, or `d op= b` when d is a. */
function binary(d: Op | undefined, a: string, op: string, b: string, words: string[]): string {
  const dest = val(d);
  words.push('arith');
  if (dest === a && dest !== '0') {
    words.push('compound');
    return `${dest} ${op}= ${b}`;
  }
  return `${dest} = ${a} ${op} ${b}`;
}

/** The address of a memory operand as an HLA64 expression (without brackets). */
function address(op: Extract<Op, { k: 'mem' }>, words: string[]): string {
  if (op.index) {
    const scale = op.showAmount && op.amount ? 2 ** op.amount : 1;
    let index = op.index;
    if (op.ext && EXTEND_FN[op.ext]) {
      words.push('extend');
      index = `${EXTEND_FN[op.ext]}(${index})`;
    }
    return scale === 1 ? `${op.base} + ${index}` : `${op.base} + ${index} * ${scale}`;
  }
  if (op.mode === 'post' || !op.off) return op.base;
  return op.off < 0 ? `${op.base} - ${num(-op.off)}` : `${op.base} + ${num(op.off)}`;
}

/** The type prefix of a load or store: '' when the register's width says it all. */
function memType(insn: Insn, r: string): string | null {
  const size = insn.size ?? 8;
  const fp = /^[bhsdq]\d/.test(r);
  if (fp) return r[0] === 'd' ? 'f64' : r[0] === 's' ? 'f32' : null;
  if (size === 8 || (size === 4 && r[0] === 'w' && !insn.signed)) return '';
  return `${insn.signed ? 'i' : 'u'}${size * 8}`;
}

function loadStore(insn: Insn, words: string[]): string | null {
  const [rt, mem] = insn.ops;
  if (rt?.k !== 'reg' || mem?.k !== 'mem') return null;
  const type = memType(insn, rt.r);
  if (type === null) return null;
  const load = !!(insn.f & F.LOAD);
  words.push(type ? 'typed-memory' : 'memory');
  const value = isZr(rt.r) ? '0' : rt.r;
  const access = (addr: string) => `${type}[${addr}]`;
  if (mem.mode === 'pre') {
    words.push('compound');
    const step = mem.off < 0 ? `${mem.base} -= ${num(-mem.off)}` : `${mem.base} += ${num(mem.off)}`;
    return load ? `${step}; ${rt.r} = ${access(mem.base)}` : `${step}; ${access(mem.base)} = ${value}`;
  }
  if (mem.mode === 'post') {
    if (mem.off === (insn.size ?? 8)) {
      words.push('post-increment');
      return load ? `${rt.r} = ${access(`${mem.base}++`)}` : `${access(`${mem.base}++`)} = ${value}`;
    }
    words.push('compound');
    const step = mem.off < 0 ? `${mem.base} -= ${num(-mem.off)}` : `${mem.base} += ${num(mem.off)}`;
    return load ? `${rt.r} = ${access(mem.base)}; ${step}` : `${access(mem.base)} = ${value}; ${step}`;
  }
  const addr = address(mem, words);
  return load ? `${rt.r} = ${access(addr)}` : `${access(addr)} = ${value}`;
}

function pair(insn: Insn, words: string[]): string | null {
  const [a, b, mem] = insn.ops;
  if (a?.k !== 'reg' || b?.k !== 'reg' || mem?.k !== 'mem') return null;
  const load = insn.m === 'ldp';
  if (insn.m !== 'ldp' && insn.m !== 'stp') return null;
  const r = a.r[0];
  const type = r === 'x' ? 'u64' : r === 'w' ? 'u32' : r === 'd' ? 'f64' : r === 's' ? 'f32' : null;
  if (!type) return null;
  const size = type.endsWith('64') ? 8 : 4;
  if (type === 'u64' && mem.base === 'sp' && size === 8) {
    if (!load && mem.mode === 'pre' && mem.off === -16) {
      words.push('push-pop');
      return `push ${a.r}, ${b.r}`;
    }
    if (load && mem.mode === 'post' && mem.off === 16) {
      words.push('push-pop');
      return `pop ${a.r}, ${b.r}`;
    }
  }
  words.push('pair');
  const regs = `(${val(a)}, ${val(b)})`;
  if (mem.mode === 'post') {
    if (mem.off === 2 * size) return load ? `${regs} = ${type}[${mem.base}++]` : `${type}[${mem.base}++] = ${regs}`;
    if (mem.off === -2 * size) return load ? `${regs} = ${type}[${mem.base}--]` : `${type}[${mem.base}--] = ${regs}`;
    words.push('compound');
    const step = mem.off < 0 ? `${mem.base} -= ${num(-mem.off)}` : `${mem.base} += ${num(mem.off)}`;
    return load ? `${regs} = ${type}[${mem.base}]; ${step}` : `${type}[${mem.base}] = ${regs}; ${step}`;
  }
  const addr = mem.off ? `${mem.base} ${mem.off < 0 ? '-' : '+'} ${num(Math.abs(mem.off))}` : mem.base;
  const bang = mem.mode === 'pre' ? '!' : '';
  return load ? `${regs} = ${type}[${addr}]${bang}` : `${type}[${addr}]${bang} = ${regs}`;
}

const ORDER = (m: string, base: string): string => {
  const suffix = m.slice(base.length).replace(/[bh]$/, '');
  return suffix === 'al' ? 'acq_rel' : suffix === 'a' ? 'acquire' : suffix === 'l' ? 'release' : 'relaxed';
};
const ATOMIC_NAMES: Record<string, string> = { add: 'atomic_add', clr: 'atomic_clr', eor: 'atomic_eor', set: 'atomic_or', smax: 'atomic_smax', smin: 'atomic_smin', umax: 'atomic_umax', umin: 'atomic_umin' };
const atomicType = (m: string, r: string) => (m.endsWith('b') && !m.endsWith('sb') ? 'u8' : m.endsWith('h') ? 'u16' : r[0] === 'x' ? 'u64' : 'u32');

function atomic(insn: Insn, words: string[]): string | null {
  const m = insn.m;
  const ops = insn.ops;
  let match = /^ld(add|clr|eor|set|smax|smin|umax|umin)(a|al|l)?([bh])?$/.exec(m);
  if (match) {
    const [s, t, mem] = ops;
    if (s?.k !== 'reg' || t?.k !== 'reg' || mem?.k !== 'mem') return null;
    words.push('atomic');
    const call = `${ATOMIC_NAMES[match[1]!]}(${atomicType(m, s.r)}[${mem.base}], ${val(s)}, ${ORDER(m.replace(/[bh]$/, ''), `ld${match[1]}`)})`;
    return isZr(t.r) ? call : `${t.r} = ${call}`;
  }
  match = /^st(add|clr|eor|set|smax|smin|umax|umin)(l)?([bh])?$/.exec(m);
  if (match) {
    const [s, mem] = ops;
    if (s?.k !== 'reg' || mem?.k !== 'mem') return null;
    words.push('atomic');
    return `${ATOMIC_NAMES[match[1]!]}(${atomicType(m, s.r)}[${mem.base}], ${val(s)}, ${match[2] ? 'release' : 'relaxed'})`;
  }
  match = /^swp(a|al|l)?([bh])?$/.exec(m);
  if (match) {
    const [s, t, mem] = ops;
    if (s?.k !== 'reg' || t?.k !== 'reg' || mem?.k !== 'mem') return null;
    words.push('atomic');
    const call = `atomic_swap(${atomicType(m, s.r)}[${mem.base}], ${val(s)}, ${ORDER(m.replace(/[bh]$/, ''), 'swp')})`;
    return isZr(t.r) ? call : `${t.r} = ${call}`;
  }
  match = /^cas(a|al|l)?([bh])?$/.exec(m);
  if (match) {
    const [s, t, mem] = ops;
    if (s?.k !== 'reg' || t?.k !== 'reg' || mem?.k !== 'mem') return null;
    words.push('cas');
    return `${s.r} = cas(${atomicType(m, s.r)}[${mem.base}], ${val(s)}, ${val(t)}, ${ORDER(m.replace(/[bh]$/, ''), 'cas')})`;
  }
  // Only the plain forms: not the writeback ones of FEAT_LRCPC3, nor its SIMD&FP registers.
  match = /^(ldar|ldapr|ldapur)([bh])?$/.exec(m);
  if (match) {
    const [t, mem] = ops;
    if (t?.k !== 'reg' || mem?.k !== 'mem' || mem.mode !== 'off' || !GPR.test(t.r)) return null;
    words.push('atomic-load-store');
    const addr = mem.off ? address(mem, words) : mem.base;
    return `${t.r} = load_acquire(${atomicType(m, t.r)}[${addr}])`;
  }
  match = /^(stlr|stlur)([bh])?$/.exec(m);
  if (match) {
    const [t, mem] = ops;
    if (t?.k !== 'reg' || mem?.k !== 'mem' || mem.mode !== 'off' || !GPR.test(t.r)) return null;
    words.push('atomic-load-store');
    const addr = mem.off ? address(mem, words) : mem.base;
    return `store_release(${atomicType(m, t.r)}[${addr}], ${val(t)})`;
  }
  return null;
}

/** A Rust or C++ path, or anything else that is not an identifier, goes between backticks. */
export function hlaName(name: string, words: string[]): string {
  if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) return name;
  words.push('quoted-name');
  return `\`${name}\``;
}

function branchTarget(insn: Insn, ctx: LiftContext, words: string[]): string {
  const addr = insn.target ?? 0;
  const t = ctx.target(addr);
  if (!t) return num(addr);
  return t.kind === 'label' ? t.name : hlaName(t.name, words);
}

/** General-purpose registers, the only ones integer sugar may name: `d0 = d1 + d2` means floating point. */
const GPR = /^(?:[xw](?:[12]?\d|3[01])|sp|wsp|xzr|wzr)$/;
const INTEGER = new Set([
  'add', 'sub', 'adds', 'subs', 'ands', 'bics', 'neg', 'negs', 'mvn', 'and', 'orr', 'eor', 'bic', 'orn', 'eon', 'lsl', 'lsr', 'asr', 'ror',
  'mul', 'madd', 'msub', 'mneg', 'smull', 'umull', 'smaddl', 'umaddl', 'smsubl', 'umsubl', 'smnegl', 'umnegl', 'umulh', 'smulh', 'sdiv', 'udiv',
  'sxtb', 'sxth', 'sxtw', 'uxtb', 'uxth', 'clz', 'rbit', 'rev', 'rev16', 'rev32', 'cls', 'ctz', 'cnt', 'ubfx', 'ubfiz', 'sbfx', 'sbfiz',
]);
/** Scalar floating-point registers: vector forms of fadd & co stay instructions. */
const FPR = /^[hsd](?:[12]?\d|3[01])$/;
const FLOAT_OPS = new Set(['fadd', 'fsub', 'fmul', 'fdiv', 'fnmul', 'fmadd', 'fmsub', 'fnmadd', 'fnmsub', 'fneg', 'fabs', 'fsqrt', 'fmin', 'fmax', 'fminnm', 'fmaxnm', 'fcvt']);

function lift(insn: Insn, pc: number, ctx: LiftContext, words: string[]): string | null {
  const { m, ops } = insn;
  const [d, a, b] = ops;
  const regs = ops.filter((op): op is Extract<Op, { k: 'reg' }> => op.k === 'reg');
  if (INTEGER.has(m) && !regs.every((op) => GPR.test(op.r))) return null;
  if (FLOAT_OPS.has(m) && !regs.every((op) => FPR.test(op.r))) return null;
  if (ops.some((op) => op.k === 'text' && op.t.startsWith('{'))) return null;
  switch (m) {
    case 'mov': {
      if (d?.k === 'reg' && d.r.startsWith('v')) return null;
      if (a?.k === 'reg' && a.r.startsWith('v')) return null;
      words.push('assign');
      return `${val(d)} = ${val(a)}`;
    }
    case 'movz':
    case 'movn':
      return null;
    case 'add':
    case 'sub': {
      if (d?.k !== 'reg' || a?.k !== 'reg') return null;
      const second = operand2(ops.slice(2), words);
      return binary(d, val(a), m === 'add' ? '+' : '-', second, words);
    }
    case 'adds':
    case 'subs':
    case 'ands':
    case 'bics': {
      const second = operand2(ops.slice(2), words);
      const op = { adds: '+', subs: '-', ands: '&', bics: '& ~' }[m]!;
      return `${binary(d, val(a), op, second, words)}`;
    }
    case 'neg':
    case 'negs':
      words.push('arith');
      return `${val(d)} = -${operand2(ops.slice(1), words)}`;
    case 'mvn':
      words.push('arith');
      return `${val(d)} = ~${operand2(ops.slice(1), words)}`;
    case 'and':
    case 'orr':
    case 'eor': {
      if (d?.k === 'reg' && d.r.startsWith('v')) return null;
      return binary(d, val(a), { and: '&', orr: '|', eor: '^' }[m]!, operand2(ops.slice(2), words), words);
    }
    case 'bic':
    case 'orn':
    case 'eon': {
      if (d?.k === 'reg' && d.r.startsWith('v')) return null;
      words.push('arith');
      return `${val(d)} = ${val(a)} ${{ bic: '&', orn: '|', eon: '^' }[m]} ~${operand2(ops.slice(2), words)}`;
    }
    case 'lsl':
    case 'lsr':
    case 'asr': {
      words.push('shift');
      return binary(d, val(a), { lsl: '<<', lsr: '>>>', asr: '>>' }[m]!, val(b), words);
    }
    case 'ror':
      words.push('ror');
      return `${val(d)} = ror(${val(a)}, ${val(b)})`;
    case 'mul':
      if (d?.k === 'reg' && d.r.startsWith('v')) return null;
      return binary(d, val(a), '*', val(b), words);
    case 'madd':
    case 'msub':
      words.push('arith');
      return `${val(d)} = ${val(ops[3])} ${m === 'madd' ? '+' : '-'} ${val(a)} * ${val(b)}`;
    case 'mneg':
      words.push('arith');
      return `${val(d)} = -(${val(a)} * ${val(b)})`;
    case 'smull':
    case 'umull':
    case 'smaddl':
    case 'umaddl':
    case 'smsubl':
    case 'umsubl':
    case 'smnegl':
    case 'umnegl': {
      if (d?.k === 'reg' && d.r.startsWith('v')) return null;
      words.push('widening-multiply', 'extend');
      const ext = m[0] === 's' ? 'sext32' : 'zext32';
      const product = `${ext}(${val(a)}) * ${ext}(${val(b)})`;
      if (m.endsWith('mull')) return `${val(d)} = ${product}`;
      if (m.endsWith('negl')) return `${val(d)} = -(${product})`;
      return `${val(d)} = ${val(ops[3])} ${m.includes('add') ? '+' : '-'} ${product}`;
    }
    case 'umulh':
    case 'smulh':
      words.push('mul-high');
      return `${val(d)} = ${m}(${val(a)}, ${val(b)})`;
    case 'sdiv':
      return binary(d, val(a), '/', val(b), words);
    case 'udiv':
      words.push('udiv');
      return `${val(d)} = udiv(${val(a)}, ${val(b)})`;
    case 'sxtb':
    case 'sxth':
    case 'sxtw':
    case 'uxtb':
    case 'uxth':
      words.push('extend');
      return `${val(d)} = ${EXTEND_FN[m]}(${val(a)})`;
    case 'clz':
    case 'rbit':
    case 'rev':
      if (d?.k === 'reg' && d.r.startsWith('v')) return null;
      words.push('builtin');
      return `${val(d)} = ${m}(${val(a)})`;
    case 'rev16':
    case 'rev32':
    case 'cls':
    case 'ctz':
    case 'cnt':
      if (d?.k === 'reg' && d.r.startsWith('v')) return null;
      words.push('bit-builtins');
      return `${val(d)} = ${m === 'cnt' ? 'popcount' : m}(${val(a)})`;
    case 'ubfx': {
      const lsb = (b as { v: number }).v;
      const width = (ops[3] as { v: number }).v;
      const regWidth = val(d).startsWith('w') ? 32 : 64;
      words.push('shift', 'arith');
      const mask = num(2 ** width - 1);
      if (lsb === 0) return `${val(d)} = ${val(a)} & ${mask}`;
      if (lsb + width === regWidth) return `${val(d)} = ${val(a)} >>> ${lsb}`;
      return `${val(d)} = (${val(a)} >>> ${lsb}) & ${mask}`;
    }
    case 'ubfiz': {
      const lsb = (b as { v: number }).v;
      const width = (ops[3] as { v: number }).v;
      words.push('shift', 'arith');
      return `${val(d)} = (${val(a)} & ${num(2 ** width - 1)}) << ${lsb}`;
    }
    case 'sbfx':
      words.push('bits');
      return `${val(d)} = sbits(${val(a)}, ${val(b)}, ${val(ops[3])})`;
    case 'sbfiz':
      words.push('bits', 'shift');
      return `${val(d)} = sbits(${val(a)}, 0, ${val(ops[3])}) << ${val(b)}`;
    case 'b': {
      const target = insn.target ?? 0;
      const t = ctx.target(target);
      if (t && t.kind !== 'label' && target !== ctx.functionStart(pc)) {
        words.push('tail-call');
        return `return ${hlaName(t.name, words)}()`;
      }
      words.push('goto');
      return `goto ${branchTarget(insn, ctx, words)}`;
    }
    case 'bl':
      words.push('call');
      return `${branchTarget(insn, ctx, words)}()`;
    case 'blr':
      words.push('call');
      return `${val(d)}()`;
    case 'br':
      words.push('jump-table');
      return `goto [${val(d)}]`;
    case 'ret':
      words.push('return');
      return ops.length ? null : 'return';
    case 'cbz':
    case 'cbnz':
      words.push('if-goto');
      return `if ${val(d)} ${m === 'cbz' ? '==' : '!='} 0 { goto ${branchTarget(insn, ctx, words)} }`;
    case 'tbz':
    case 'tbnz': {
      words.push('if-goto');
      const bitNo = (a as { v: number }).v;
      const r = val(d);
      const top = r.startsWith('w') ? 31 : 63;
      const goto = `goto ${branchTarget(insn, ctx, words)}`;
      if (bitNo === top) return `if ${r} ${m === 'tbz' ? '>=' : '<'} 0 { ${goto} }`;
      return `if ${r} & ${num(2 ** bitNo)} ${m === 'tbz' ? '==' : '!='} 0 { ${goto} }`;
    }
    case 'brk':
    case 'udf':
      words.push('trap');
      return `trap(${val(d)})`;
    case 'fadd':
    case 'fsub':
    case 'fmul':
    case 'fdiv': {
      if (d?.k !== 'reg' || d.r.startsWith('v')) return null;
      words.push('float');
      return binary(d, val(a), { fadd: '+', fsub: '-', fmul: '*', fdiv: '/' }[m]!, val(b), words);
    }
    case 'fnmul':
      if (d?.k !== 'reg' || d.r.startsWith('v')) return null;
      words.push('float');
      return `${val(d)} = -(${val(a)} * ${val(b)})`;
    case 'fmadd':
    case 'fmsub':
    case 'fnmadd':
    case 'fnmsub': {
      words.push('float');
      const product = `${val(a)} * ${val(b)}`;
      const acc = val(ops[3]);
      const text = { fmadd: `${acc} + ${product}`, fmsub: `${acc} - ${product}`, fnmadd: `-${acc} - ${product}`, fnmsub: `${product} - ${acc}` }[m];
      return `${val(d)} = ${text}`;
    }
    case 'fneg':
    case 'fabs':
    case 'fsqrt': {
      if (d?.k !== 'reg' || d.r.startsWith('v')) return null;
      words.push('float');
      if (m === 'fneg') return `${val(d)} = -${val(a)}`;
      return `${val(d)} = ${m === 'fabs' ? 'fabs' : 'sqrt'}(${val(a)})`;
    }
    case 'fmin':
    case 'fmax':
    case 'fminnm':
    case 'fmaxnm':
      if (d?.k !== 'reg' || d.r.startsWith('v')) return null;
      words.push('float-extra');
      return `${val(d)} = ${m.slice(0, 4)}(${val(a)}, ${val(b)})`;
    case 'scvtf':
    case 'ucvtf':
      if (d?.k !== 'reg' || a?.k !== 'reg' || !FPR.test(d.r) || !GPR.test(a.r) || ops.length > 2) return null;
      words.push(m === 'scvtf' ? 'float' : 'float-extra');
      return `${val(d)} = ${m === 'scvtf' ? 'float' : 'ufloat'}(${val(a)})`;
    case 'fcvtzs':
    case 'fcvtzu':
      if (d?.k !== 'reg' || a?.k !== 'reg' || !GPR.test(d.r) || !FPR.test(a.r) || ops.length > 2) return null;
      words.push(m === 'fcvtzs' ? 'float' : 'float-extra');
      return `${val(d)} = ${m === 'fcvtzs' ? 'int' : 'uint'}(${val(a)})`;
    case 'fcvt':
      if (d?.k !== 'reg' || (d.r[0] !== 'd' && d.r[0] !== 's')) return null;
      words.push('float-extra');
      return `${val(d)} = ${d.r[0] === 'd' ? 'f64' : 'f32'}(${val(a)})`;
    case 'fmov': {
      if (d?.k !== 'reg' || a === undefined) return null;
      if (d.r.startsWith('v') || (a.k === 'reg' && a.r.startsWith('v'))) return null;
      if (a.k === 'imm') {
        words.push('float');
        return `${val(d)} = ${String(a.v).includes('.') ? a.v : a.v.toFixed(1)}`;
      }
      const fp = (r: string) => /^[hsd]\d/.test(r);
      if (a.k === 'reg' && fp(d.r) !== fp(a.r)) {
        words.push('float-extra');
        return `${val(d)} = bitcast(${val(a)})`;
      }
      words.push('assign');
      return `${val(d)} = ${val(a)}`;
    }
  }
  if (insn.f & F.ATOMIC || /^(ldar|ldapr|ldapur|stlr|stlur)[bh]?$/.test(m)) return atomic(insn, words);
  if (m === 'ldp' || m === 'stp') return pair(insn, words);
  if (/^(ldr|ldur|str|stur)(b|h|sb|sh|sw)?$/.test(m) && ops[0]?.k === 'reg') return ops[1]?.k === 'mem' ? loadStore(insn, words) : null;
  return null;
}

/** One instruction as an HLA64 line; the instruction itself when HLA64 has no better word. */
export function liftOne(insn: Insn, pc: number, ctx: LiftContext): HlaLine {
  const words: string[] = [];
  let text: string | null = null;
  try {
    text = lift(insn, pc, ctx, words);
  } catch {
    text = null;
  }
  if (text === null) return { text: rawInstruction(insn, ctx), words: ['instruction'] };
  return { text, words: [...new Set(words)] };
}

/** The instruction as printed, with branch targets by name. */
export function rawInstruction(insn: Insn, ctx: LiftContext): string {
  const text = formatInsn(insn);
  if (insn.target === undefined || insn.m === 'adrp' || insn.m === 'adr') return text;
  const t = ctx.target(insn.target);
  if (!t) return text;
  return text.replace(`0x${insn.target.toString(16)}`, t.kind === 'label' ? t.name : hlaName(t.name, []));
}

/* ------------------------------------------------------------------ *
 * Pairs: a compare and its consumer; adrp and the instruction that completes the address
 * ------------------------------------------------------------------ */

const SIGNED: Record<string, string> = { eq: '==', ne: '!=', ge: '>=', lt: '<', gt: '>', le: '<=' };
const UNSIGNED: Record<string, string> = { hs: '>=u', lo: '<u', hi: '>u', ls: '<=u' };
const FLOAT: Record<string, string> = { eq: '==', ne: '!=', gt: '>', ge: '>=', mi: '<', ls: '<=' };
const ZERO_TEST: Record<string, string> = { eq: '== 0', ne: '!= 0', mi: '< 0', pl: '>= 0' };

export const SETTERS = new Set(['cmp', 'cmn', 'tst', 'subs', 'adds', 'ands', 'negs', 'fcmp', 'fcmpe']);
export const CONSUMERS = new Set(['b.eq', 'b.ne', 'b.hs', 'b.lo', 'b.mi', 'b.pl', 'b.vs', 'b.vc', 'b.hi', 'b.ls', 'b.ge', 'b.lt', 'b.gt', 'b.le', 'csel', 'csinc', 'csinv', 'csneg', 'cset', 'csetm', 'cinc', 'cinv', 'cneg', 'fcsel']);

/** What the flags of `setter` say under condition `cond`, as an expression; null when no plain one fits. */
function relation(setter: Insn, cond: string, words: string[]): { pre?: string; expr: string } | null {
  const { m, ops } = setter;
  if (m === 'fcmp' || m === 'fcmpe') {
    const op = FLOAT[cond];
    if (!op) return null;
    words.push('float');
    return { expr: `${val(ops[0])} ${op} ${ops[1]?.k === 'text' ? '0.0' : val(ops[1])}` };
  }
  const compare = (left: string, right: string): string | null => {
    if (SIGNED[cond]) return `${left} ${SIGNED[cond]} ${right}`;
    if (UNSIGNED[cond]) {
      words.push('unsigned-compare');
      return `${left} ${UNSIGNED[cond]} ${right}`;
    }
    return null;
  };
  const exprWords: string[] = [];
  const right = operand2(ops.slice(m === 'cmp' || m === 'cmn' || m === 'tst' ? 1 : 2), exprWords);
  const negated = (v: string) => (/^-?(0x)?[0-9a-f]+$/i.test(v) ? (v.startsWith('-') ? v.slice(1) : `-${v}`) : `-${v}`);
  if (m === 'cmp') {
    const expr = compare(val(ops[0]), right);
    words.push(...exprWords);
    return expr ? { expr } : null;
  }
  if (m === 'cmn') {
    if (!SIGNED[cond]) return null;
    words.push(...exprWords);
    return { expr: `${val(ops[0])} ${SIGNED[cond]} ${negated(right)}` };
  }
  if (m === 'tst') {
    const anded = `${val(ops[0])} & ${right}`;
    words.push(...exprWords, 'arith');
    if (ZERO_TEST[cond]) return { expr: `${anded} ${ZERO_TEST[cond]}` };
    if (SIGNED[cond]) return { expr: `${anded} ${SIGNED[cond]} 0` };
    return null;
  }
  // With a destination: the operation stays a statement before the test.
  const preWords: string[] = [];
  const pre = lift(setter, 0, NO_CONTEXT, preWords);
  if (!pre) return null;
  words.push(...preWords);
  const dest = ops[0];
  if (m === 'ands' || m === 'negs' || sameReg(dest, ops[1]) || sameReg(dest, ops[2])) {
    const test = ZERO_TEST[cond];
    if (test) return { pre, expr: `${val(dest)} ${test}` };
    if (m === 'ands' && SIGNED[cond]) return { pre, expr: `${val(dest)} ${SIGNED[cond]} 0` };
    return null;
  }
  const expr = m === 'subs' ? compare(val(ops[1]), right) : SIGNED[cond] ? `${val(ops[1])} ${SIGNED[cond]} ${negated(right)}` : null;
  return expr ? { pre, expr } : null;
}

const NO_CONTEXT: LiftContext = { target: () => undefined, data: () => undefined, functionStart: () => -1 };

function consume(consumer: Insn, expr: string, ctx: LiftContext, words: string[]): string | null {
  const [d, a, b] = consumer.ops;
  const r = `(${expr})`;
  switch (consumer.m) {
    case 'csel':
    case 'fcsel':
      words.push('ternary');
      return `${val(d)} = ${expr} ? ${val(a)} : ${val(b)}`;
    case 'cset':
      words.push('condition-value');
      return `${val(d)} = ${expr}`;
    case 'csetm':
      words.push('condition-value');
      return `${val(d)} = -${r}`;
    case 'cinc':
      words.push('condition-value', 'arith');
      return `${val(d)} = ${val(a)} + ${r}`;
    case 'cinv':
      words.push('ternary');
      return `${val(d)} = ${expr} ? ~${val(a)} : ${val(a)}`;
    case 'cneg':
      words.push('ternary');
      return `${val(d)} = ${expr} ? -${val(a)} : ${val(a)}`;
    case 'csinc':
      words.push('ternary');
      return `${val(d)} = ${expr} ? ${val(a)} : ${val(b)} + 1`;
    case 'csinv':
      words.push('ternary');
      return `${val(d)} = ${expr} ? ${val(a)} : ~${val(b)}`;
    case 'csneg':
      words.push('ternary');
      return `${val(d)} = ${expr} ? ${val(a)} : -${val(b)}`;
  }
  if (consumer.m.startsWith('b.')) {
    words.push('if-goto');
    return `if ${expr} { goto ${branchTarget(consumer, ctx, words)} }`;
  }
  return null;
}

/** A string or symbol for an address an adrp pair builds, as a comment and as an HLA64 value. */
function describeAddress(addr: number, ctx: LiftContext, words: string[]): { value: string; comment?: string } {
  const data = ctx.data(addr);
  if (data?.kind === 'string') {
    words.push(data.objc ? 'nsstring' : 'string');
    return { value: `${data.objc ? '@' : ''}${JSON.stringify(data.text.length > 80 ? `${data.text.slice(0, 80)}…` : data.text)}` };
  }
  const t = ctx.target(addr);
  if (t) {
    words.push('address');
    return { value: `&${t.kind === 'label' ? t.name : hlaName(t.name, words)}` };
  }
  if (data?.kind === 'symbol') {
    words.push('address');
    return { value: `&${hlaName(data.name, words)}` };
  }
  words.push('address');
  return { value: `&data_${addr.toString(16)}` };
}

/**
 * The address an adrp + second instruction pair forms, or undefined when the
 * second one does not complete it (add #pageoff or a load/store at [reg, #pageoff]).
 */
export function pairedAddress(adrp: Insn, next: Insn): number | undefined {
  if (adrp.m !== 'adrp' || adrp.target === undefined) return undefined;
  const reg = adrp.ops[0];
  if (next.m === 'add' && next.ops.length === 3 && sameReg(next.ops[1], reg) && next.ops[2]?.k === 'imm') return adrp.target + next.ops[2].v;
  const mem = next.ops.find((op) => op.k === 'mem');
  if (mem?.k === 'mem' && mem.mode === 'off' && !mem.index && regNo(mem.base) === regNo((reg as { r: string }).r) && next.f & (F.LOAD | F.STORE)) {
    return adrp.target + mem.off;
  }
  return undefined;
}

/** Two neighbouring instructions as one line, or null when they do not pair. */
export function fuse(first: Insn, second: Insn, ctx: LiftContext): HlaLine | null {
  const words: string[] = [];
  if (first.m === 'adrp') {
    const addr = pairedAddress(first, second);
    if (addr === undefined) return null;
    const { value, comment } = describeAddress(addr, ctx, words);
    if (second.m === 'add') {
      return { text: `${val(second.ops[0])} = ${value}`, words: [...new Set(words)], comment };
    }
    // A load or store through the page: the address goes inside the brackets.
    const rt = second.ops[0];
    if (rt?.k !== 'reg') return null;
    const type = memType(second, rt.r);
    if (type === null || /^(ldp|stp)$/.test(second.m)) return null;
    words.push(type ? 'typed-memory' : 'memory');
    // Reading or writing at a string's address: the address is the operand, the text a comment.
    const isString = /^@?"/.test(value);
    const slot = isString ? `data_${addr.toString(16)}` : value.slice(1);
    const access = `${type}[&${slot}]`;
    const text = second.f & F.LOAD ? `${rt.r} = ${access}` : `${access} = ${isZr(rt.r) ? '0' : rt.r}`;
    // When the load goes elsewhere, the adrp register keeps only the page: say so.
    const keeps = sameReg(first.ops[0], rt) && second.f & F.LOAD ? undefined : `${val(first.ops[0])} = page ${num(first.target ?? 0)}`;
    return { text, words: [...new Set(words)], comment: [isString ? value : comment, keeps].filter(Boolean).join('; ') || undefined };
  }
  if (!SETTERS.has(first.m) || !CONSUMERS.has(second.m)) return null;
  const cond = second.cond;
  if (!cond) return null;
  const rel = relation(first, cond, words);
  if (!rel) return null;
  const tail = consume(second, rel.expr, ctx, words);
  if (!tail) return null;
  return { text: rel.pre ? `${rel.pre}; ${tail}` : tail, words: [...new Set(words)] };
}
