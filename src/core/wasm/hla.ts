/**
 * The HLA64 view of WebAssembly code.
 *
 * HLA64 is an assembler with sugar for WebAssembly as for ARM64: its
 * programs are instructions, with words for what is obvious. On a stack
 * machine the obvious is the expression: `local.get 0, i32.const 1,
 * i32.add, local.set 2` is `l2 = l0 + 1`. The analysis
 * (src/core/wasm/program.ts) marks the runs of instructions that make one
 * statement; liftGroup() turns a run back into that statement, evaluating
 * the stack with expressions instead of values. Every line stands for the
 * instructions at its addresses and means exactly what they do:
 * operands are written in the order the instructions compute them, a
 * select becomes `c ? a : b` only when nothing in it has an effect, and
 * whatever has no word stays an instruction — as HLA64 accepts.
 *
 * `block`, `loop` and their `end` stay instructions (HLA64's own `loop { }`
 * repeats, a WebAssembly loop does not); an `if` whose condition is in the
 * line reads `if c {`, `} else {`, `}`. Branches name their target by its
 * address, as labels do on ARM64: `if l3 != l1 { goto L1f7 }`.
 *
 * Names in a line — functions, labels, strings, locals — are wrapped in
 * invisible marks (see mark()) so the page can make each one a link;
 * plain() takes them out.
 */

import { append } from '../disassembly';
import type { HlaLine } from '../hla';
import { decodeAt, operandsText, WasmInsn } from './decode';
import { effect } from './effects';
import { formatContext } from './module';
import { IMM, W } from './opcodes';
import { decimalFloat, f32FromBits, f64FromBits } from './reader';
import type { WasmProgram } from './program';

/** Bits of WasmProgram.flags beyond the shared ones. */
export const WF = {
  /** An `if` written `if c {`: its condition is in its line. */
  SUGAR_IF: 64,
  /** The `else` or `end` of such an if: `} else {`, `}`. */
  IF_END: 128,
} as const;

/* ------------------------------------------------------------------ *
 * Marks
 * ------------------------------------------------------------------ */

/** What a mark names: a function, a label, a string or data address, a local, a global. */
export type MarkKind = 'f' | 'l' | 's' | 'd' | 'v' | 'g';

const OPEN = '\u0001';
const SEP = '\u0002';
const CLOSE = '\u0003';

export function mark(kind: MarkKind, value: number, text: string): string {
  return `${OPEN}${kind}${value}${SEP}${text}${CLOSE}`;
}

/** The text of a line without its marks. */
export function plain(text: string): string {
  return text.replace(/\u0001[a-z]-?\d+\u0002/g, '').replace(/\u0003/g, '');
}

export interface Part {
  text: string;
  kind?: MarkKind;
  value?: number;
}

/** A line split into plain runs and marked names. */
export function parts(text: string): Part[] {
  const out: Part[] = [];
  const re = /\u0001([a-z])(-?\d+)\u0002([^\u0003]*)\u0003/g;
  let at = 0;
  for (let match = re.exec(text); match; match = re.exec(text)) {
    if (match.index > at) out.push({ text: text.slice(at, match.index) });
    out.push({ text: match[3]!, kind: match[1] as MarkKind, value: Number(match[2]) });
    at = re.lastIndex;
  }
  if (at < text.length) out.push({ text: text.slice(at) });
  return out;
}

/* ------------------------------------------------------------------ *
 * Names
 * ------------------------------------------------------------------ */

/** How the view names things: the page passes its own (to follow the settings for function names). */
export interface Naming {
  func(index: number): string;
}

const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/;

function quoted(name: string, words: string[]): string {
  if (IDENTIFIER.test(name)) return name;
  words.push('quoted-name');
  return `\`${name}\``;
}

const num = (v: number | bigint): string => {
  if (typeof v === 'bigint') return v < 0n ? (v > -10n ? String(v) : `-0x${(-v).toString(16)}`) : v < 10n ? String(v) : `0x${v.toString(16)}`;
  return Math.abs(v) < 10 ? String(v) : v < 0 ? `-0x${(-v).toString(16)}` : `0x${v.toString(16)}`;
};

function floatLiteral(value: number, single: boolean): string {
  if (Number.isNaN(value)) return 'nan';
  if (!Number.isFinite(value)) return value > 0 ? 'inf' : '-inf';
  const text = decimalFloat(value, single);
  return /[.e]/.test(text) || text.includes('inf') ? text : `${text}.0`;
}

/* ------------------------------------------------------------------ *
 * Expressions
 * ------------------------------------------------------------------ */

/** A value on the stack, as HLA64 writes it. */
interface Expr {
  text: string;
  /** Go's levels: 6 an operand, 5 * / % << >> >>> &, 4 + - | ^, 3 comparisons, 0 c ? a : b and assignments. */
  prec: number;
  /** Computing it has no effect (no call, store, assignment): it may move into a ?:. */
  pure: boolean;
  /** For x op= y: the operator and operands of a binary expression. */
  op?: string;
  left?: string;
  right?: Expr;
}

const atom = (text: string, pure = true): Expr => ({ text, prec: 6, pure });
const wrap = (e: Expr, min: number) => (e.prec >= min ? e.text : `(${e.text})`);
const SHIFTS = new Set(['<<', '>>', '>>>']);

/** A shift inside another operation gets parentheses, as the ARM64 view writes them: `x + (y << 2)`. */
const operand = (e: Expr, min: number) => (e.op && SHIFTS.has(e.op) && e.prec === 5 ? `(${e.text})` : wrap(e, min));

function binary(left: Expr, op: string, prec: number, right: Expr): Expr {
  return { text: `${operand(left, prec)} ${op} ${operand(right, prec + 1)}`, prec, pure: left.pure && right.pure, op, left: left.text, right };
}

const call = (name: string, args: Expr[], pure = true): Expr => atom(`${name}(${args.map((a) => a.text).join(', ')})`, pure && args.every((a) => a.pure));

const INT_BINARY: Record<string, [string, number, string?]> = {
  add: ['+', 4], sub: ['-', 4], mul: ['*', 5], div_s: ['/', 5], rem_s: ['%', 5], and: ['&', 5], or: ['|', 4], xor: ['^', 4],
  shl: ['<<', 5, 'shift'], shr_s: ['>>', 5, 'shift'], shr_u: ['>>>', 5, 'shift'],
  eq: ['==', 3, 'condition-value'], ne: ['!=', 3, 'condition-value'], lt_s: ['<', 3, 'condition-value'], gt_s: ['>', 3, 'condition-value'],
  le_s: ['<=', 3, 'condition-value'], ge_s: ['>=', 3, 'condition-value'],
  lt_u: ['<u', 3, 'unsigned-compare'], gt_u: ['>u', 3, 'unsigned-compare'], le_u: ['<=u', 3, 'unsigned-compare'], ge_u: ['>=u', 3, 'unsigned-compare'],
};
const FLOAT_BINARY: Record<string, [string, number]> = {
  add: ['+', 4], sub: ['-', 4], mul: ['*', 5], div: ['/', 5], eq: ['==', 3], ne: ['!=', 3], lt: ['<', 3], gt: ['>', 3], le: ['<=', 3], ge: ['>=', 3],
};
/** Instructions written as a function of their operands, and the word that explains the function. */
const FUNCTIONS: Record<string, [string, string]> = {
  'i32.div_u': ['udiv', 'udiv'], 'i64.div_u': ['udiv', 'udiv'], 'i32.rem_u': ['urem', 'udiv'], 'i64.rem_u': ['urem', 'udiv'],
  'i32.rotl': ['rotl', 'ror'], 'i64.rotl': ['rotl', 'ror'], 'i32.rotr': ['ror', 'ror'], 'i64.rotr': ['ror', 'ror'],
  'i32.clz': ['clz', 'builtin'], 'i64.clz': ['clz', 'builtin'], 'i32.ctz': ['ctz', 'bit-builtins'], 'i64.ctz': ['ctz', 'bit-builtins'],
  'i32.popcnt': ['popcount', 'bit-builtins'], 'i64.popcnt': ['popcount', 'bit-builtins'],
  'i32.extend8_s': ['sext8', 'extend'], 'i32.extend16_s': ['sext16', 'extend'], 'i64.extend8_s': ['sext8', 'extend'], 'i64.extend16_s': ['sext16', 'extend'],
  'i64.extend32_s': ['sext32', 'extend'], 'i64.extend_i32_s': ['i64', 'wasm-convert'], 'i64.extend_i32_u': ['u64', 'wasm-convert'],
  'i32.wrap_i64': ['i32', 'wasm-convert'],
  'f32.abs': ['fabs', 'float'], 'f64.abs': ['fabs', 'float'], 'f32.sqrt': ['sqrt', 'float'], 'f64.sqrt': ['sqrt', 'float'],
  'f32.min': ['fmin', 'float-extra'], 'f64.min': ['fmin', 'float-extra'], 'f32.max': ['fmax', 'float-extra'], 'f64.max': ['fmax', 'float-extra'],
  'f32.ceil': ['ceil', 'wasm-round'], 'f64.ceil': ['ceil', 'wasm-round'], 'f32.floor': ['floor', 'wasm-round'], 'f64.floor': ['floor', 'wasm-round'],
  'f32.trunc': ['trunc', 'wasm-round'], 'f64.trunc': ['trunc', 'wasm-round'], 'f32.nearest': ['nearest', 'wasm-round'], 'f64.nearest': ['nearest', 'wasm-round'],
  'f32.copysign': ['copysign', 'wasm-round'], 'f64.copysign': ['copysign', 'wasm-round'],
  'f32.demote_f64': ['f32', 'wasm-convert'], 'f64.promote_f32': ['f64', 'wasm-convert'],
  'i32.reinterpret_f32': ['bitcast', 'float-extra'], 'i64.reinterpret_f64': ['bitcast', 'float-extra'],
  'f32.reinterpret_i32': ['bitcast', 'float-extra'], 'f64.reinterpret_i64': ['bitcast', 'float-extra'],
};

/** Integer ↔ float conversions: i32(x) truncates (and traps out of range), i32_sat(x) saturates, f64u(x) reads x as unsigned. */
function conversion(m: string): string | undefined {
  let match = /^(i32|i64)\.trunc_(sat_)?f(32|64)_([su])$/.exec(m);
  if (match) return `${match[4] === 'u' ? 'u' : 'i'}${match[1]!.slice(1)}${match[2] ? '_sat' : ''}`;
  match = /^(f32|f64)\.convert_i(32|64)_([su])$/.exec(m);
  if (match) return `${match[1]}${match[3] === 'u' ? 'u' : ''}`;
  return undefined;
}

/** The access type of a load or store: i32.load8_u reads u8[…], i64.store32 writes u32[…]. */
function accessType(m: string): string | null {
  const match = /^(i32|i64|f32|f64)\.(load|store)(8|16|32)?(_[su])?$/.exec(m);
  if (!match) return null;
  if (!match[3]) return match[1]!;
  return `${match[4] === '_s' ? 'i' : 'u'}${match[3]}`;
}

const ATOMIC_RMW: Record<string, string> = { add: 'atomic_add', sub: 'atomic_sub', and: 'atomic_and', or: 'atomic_or', xor: 'atomic_xor', xchg: 'atomic_swap' };

/* ------------------------------------------------------------------ *
 * Lifting
 * ------------------------------------------------------------------ */

interface State {
  p: WasmProgram;
  names: Naming;
  /** The function the line is in: its index in the module, its last instruction. */
  func: number;
  last: number;
  /** How many values the function returns. */
  results: number;
  stack: Expr[];
  out: string[];
  words: string[];
  comments: string[];
}

function local(s: State, index: number): string {
  const name = s.p.localName(s.func, index);
  if (name && IDENTIFIER.test(name)) return mark('v', index, name);
  s.words.push('wasm-local');
  return mark('v', index, `l${index}`);
}

function global(s: State, index: number): string {
  const name = s.p.module.names.globals.get(index) ?? s.p.module.exports.find((e) => e.kind === 'global' && e.index === index)?.name;
  if (name) return mark('g', index, quoted(name, s.words));
  s.words.push('wasm-local');
  return mark('g', index, `g${index}`);
}

function funcName(s: State, index: number): string {
  const fn = s.p.func(index);
  return mark('f', fn?.addr ?? -1, quoted(s.names.func(index), s.words));
}

/** The label a branch goes to, or `return` for a branch to the end of its function. */
function goto(s: State, from: number, target: number): string {
  if (target === s.last) {
    s.words.push('return');
    return 'return';
  }
  s.words.push('goto');
  const addr = s.p.addrOf(target);
  return `goto ${mark('l', addr, s.p.labelName(addr))}`;
}

function address(base: Expr, offset: number | bigint): string {
  const isZero = offset === 0 || offset === 0n;
  if (base.text === '0') return isZero ? '0' : num(offset);
  if (isZero) return base.text;
  return `${operand(base, 4)} + ${num(offset)}`;
}

/** An i32.const or i64.const: the address of a string the code uses reads as the string. */
function constant(s: State, value: number | bigint): Expr {
  if (typeof value === 'number' && value > 0 && s.p.dataRefs.has(value)) {
    const data = s.p.dataAt(value);
    if (data?.kind === 'string') {
      s.words.push('string');
      return atom(mark('s', value, JSON.stringify(data.text.length > 80 ? `${data.text.slice(0, 80)}…` : data.text)));
    }
  }
  return atom(num(value));
}

/** The instruction as a function of its operands: i32x4.add(a, b), memory.grow(n), i8x16.extract_lane_s<3>(v). */
function folded(s: State, insn: WasmInsn, args: Expr[]): Expr {
  s.words.push('wasm-folded');
  const imm = operandsText(insn, formatContext(s.p.module)).trim();
  const op = insn.op!;
  const pure = !(op.flags & (W.LOAD | W.STORE | W.CALL | W.TRAPS | W.ATOMIC)) && !/grow|size|init|drop|copy|fill/.test(insn.m);
  return call(`${insn.m}${imm ? `<${imm}>` : ''}`, args, pure);
}

/** Takes `count` values off the expression stack; null when the stack has fewer (the line cannot be written). */
function take(s: State, count: number): Expr[] | null {
  if (count > s.stack.length) return null;
  return s.stack.splice(s.stack.length - count, count);
}

function assign(s: State, dest: string, value: Expr): string {
  s.words.push('assign');
  if (value.op && value.left === dest && value.right && /^(\+|-|\*|\/|%|&|\||\^|<<|>>|>>>)$/.test(value.op)) {
    s.words.push('compound');
    return `${dest} ${value.op}= ${value.right.text}`;
  }
  return `${dest} = ${value.text}`;
}

/** One instruction applied to the expression stack. False when it has no form here. */
function step(s: State, index: number, insn: WasmInsn): boolean {
  const m = insn.m;
  const op = insn.op;
  if (!op) return false;
  const p = s.p;

  // Structure and branches.
  if (p.valueBranches.has(index)) return false;
  switch (m) {
    case 'if': {
      if (!(p.flags[index]! & WF.SUGAR_IF)) return false;
      const [cond] = take(s, 1) ?? [];
      if (!cond) return false;
      s.words.push('if-else');
      s.out.push(`if ${cond.text} {`);
      return true;
    }
    case 'else':
      if (!(p.flags[index]! & WF.IF_END)) return false;
      s.words.push('if-else');
      s.out.push('} else {');
      return true;
    case 'end':
      if (index === s.last) {
        s.words.push('return');
        const values = s.stack.splice(0);
        if (values.length !== s.results || values.length > 1) return false;
        s.out.push(values.length ? `return ${values[0]!.text}` : 'return');
        return true;
      }
      if (!(p.flags[index]! & WF.IF_END)) return false;
      s.out.push('}');
      return true;
    case 'br': {
      const [target] = p.branchTargets(index);
      if (target === undefined) return false;
      s.out.push(goto(s, index, target));
      return true;
    }
    case 'br_if': {
      const [target] = p.branchTargets(index);
      const [cond] = take(s, 1) ?? [];
      if (target === undefined || !cond) return false;
      s.words.push('if-goto');
      s.out.push(`if ${cond.text} { ${goto(s, index, target)} }`);
      return true;
    }
    case 'br_table': {
      const [value] = take(s, 1) ?? [];
      const targets = p.branchTargets(index);
      if (!value || targets.length !== insn.labels!.length || targets.some((target) => target < 0)) return false;
      s.words.push('switch');
      // Cases that go to the same place share a branch: case 0, 3..=5 { goto L… }.
      const byTarget = new Map<number, number[]>();
      targets.slice(0, -1).forEach((target, k) => append(byTarget, target, k));
      const fallback = targets[targets.length - 1]!;
      const cases: string[] = [];
      for (const [target, keys] of byTarget) {
        if (target === fallback) continue;
        const ranges: string[] = [];
        for (let k = 0; k < keys.length; ) {
          let e = k;
          while (e + 1 < keys.length && keys[e + 1] === keys[e]! + 1) e++;
          ranges.push(e === k ? String(keys[k]) : e === k + 1 ? `${keys[k]}, ${keys[e]}` : `${keys[k]}..=${keys[e]}`);
          k = e + 1;
        }
        cases.push(`case ${ranges.join(', ')} { ${goto(s, index, target)} }`);
      }
      cases.push(`default { ${goto(s, index, fallback)} }`);
      s.out.push(`switch ${value.text} { ${cases.join(' ')} }`);
      return true;
    }
    case 'return': {
      const values = s.stack.splice(0);
      if (values.length !== s.results || values.length > 1) return false;
      s.words.push('return');
      s.out.push(values.length ? `return ${values[0]!.text}` : 'return');
      return true;
    }
  }
  if (op.flags & (W.STRUCTURE | W.BRANCH)) return false;

  const eff = effect(insn, p.effects);
  if (!eff) return false;
  const [pops, pushes] = eff;
  if (pushes > 1) return false;
  const args = take(s, pops);
  if (!args) return false;
  const result = (e: Expr) => {
    if (pushes) s.stack.push(e);
    else s.out.push(e.text);
    return true;
  };
  const prefix = m.slice(0, m.indexOf('.'));
  const name = m.slice(m.indexOf('.') + 1);

  switch (m) {
    case 'nop':
    case 'unreachable':
      return false;
    case 'local.get':
      return result(atom(local(s, insn.a)));
    case 'local.set':
      s.out.push(assign(s, local(s, insn.a), args[0]!));
      return true;
    case 'local.tee':
      s.words.push('wasm-tee');
      return result({ text: `(${local(s, insn.a)} = ${args[0]!.text})`, prec: 6, pure: false });
    case 'global.get':
      return result(atom(global(s, insn.a)));
    case 'global.set':
      s.out.push(assign(s, global(s, insn.a), args[0]!));
      return true;
    case 'drop': {
      const value = args[0]!;
      if (/\)$/.test(value.text) && !value.pure) {
        s.out.push(value.text);
        return true;
      }
      s.words.push('wasm-drop');
      s.out.push(`_ = ${value.text}`);
      return true;
    }
    case 'select': {
      const [a, b, c] = args as [Expr, Expr, Expr];
      if (a.pure && b.pure && c.pure) {
        s.words.push('ternary');
        return result({ text: `${wrap(c, 1)} ? ${wrap(a, 1)} : ${wrap(b, 1)}`, prec: 0, pure: true });
      }
      s.words.push('wasm-select');
      return result(call('select', [a, b, c]));
    }
    case 'i32.const':
    case 'i64.const':
      return result(constant(s, insn.value));
    case 'f32.const':
      s.words.push('float');
      return result(atom(floatLiteral(f32FromBits(insn.bits as number), true)));
    case 'f64.const':
      s.words.push('float');
      return result(atom(floatLiteral(f64FromBits(insn.bits as bigint), false)));
    case 'call':
      s.words.push('call');
      return result(call(funcName(s, insn.a), args, false));
    case 'return_call':
      s.words.push('tail-call');
      s.out.push(`return ${call(funcName(s, insn.a), args, false).text}`);
      return true;
    case 'call_indirect':
    case 'return_call_indirect': {
      s.words.push('wasm-call-table');
      const index = args.pop()!;
      const sig = p.module.types[insn.a]?.func;
      if (sig) s.comments.push(`type ${insn.a}: (${sig.params.map((t) => t.text).join(', ')})${sig.results.length ? ` -> ${sig.results.map((t) => t.text).join(', ')}` : ''}`);
      const text = `${quoted(p.tableName(insn.b), s.words)}[${index.text}](${args.map((a) => a.text).join(', ')})`;
      if (m.startsWith('return')) {
        s.words.push('tail-call');
        s.out.push(`return ${text}`);
        return true;
      }
      return result(atom(text, false));
    }
    case 'i32.eqz':
    case 'i64.eqz':
      s.words.push('condition-value');
      return result(binary(args[0]!, '==', 3, atom('0')));
  }

  // Memory: typed access, and atomics.
  if (op.imm === IMM.MEMARG && !insn.mem) {
    const type = accessType(m);
    if (type && (prefix === 'i32' || prefix === 'i64' || prefix === 'f32' || prefix === 'f64')) {
      s.words.push('typed-memory');
      const addr = address(args[0]!, insn.value);
      if (op.flags & W.LOAD) return result(atom(`${type}[${addr}]`));
      s.out.push(`${type}[${addr}] = ${args[1]!.text}`);
      return true;
    }
    const atomic = /^(i32|i64)\.atomic\.(load|store|rmw)(8|16|32)?(?:\.([a-z]+?))?(_u)?$/.exec(m);
    if (atomic) {
      const width = atomic[3] ?? (atomic[1] === 'i64' ? '64' : '32');
      const cell = `u${width}[${address(args[0]!, insn.value)}]`;
      if (atomic[2] === 'load') {
        s.words.push('atomic-load-store');
        return result(atom(`atomic_load(${cell})`, false));
      }
      if (atomic[2] === 'store') {
        s.words.push('atomic-load-store');
        s.out.push(`atomic_store(${cell}, ${args[1]!.text})`);
        return true;
      }
      const rmw = atomic[4]!;
      if (rmw === 'cmpxchg') {
        s.words.push('cas');
        return result(atom(`cas(${cell}, ${args[1]!.text}, ${args[2]!.text}, seq_cst)`, false));
      }
      if (ATOMIC_RMW[rmw]) {
        s.words.push('atomic');
        return result(atom(`${ATOMIC_RMW[rmw]}(${cell}, ${args[1]!.text}, seq_cst)`, false));
      }
    }
  }

  // Numbers.
  if (prefix === 'i32' || prefix === 'i64') {
    const bin = INT_BINARY[name];
    if (bin && args.length === 2) {
      s.words.push(bin[2] ?? 'arith');
      return result(binary(args[0]!, bin[0], bin[1], args[1]!));
    }
  }
  if ((prefix === 'f32' || prefix === 'f64') && args.length === 2) {
    const bin = FLOAT_BINARY[name];
    if (bin) {
      s.words.push('float');
      return result(binary(args[0]!, bin[0], bin[1], args[1]!));
    }
  }
  if ((m === 'f32.neg' || m === 'f64.neg') && args.length === 1) {
    s.words.push('float');
    return result({ text: `-${wrap(args[0]!, 6)}`, prec: 6, pure: args[0]!.pure });
  }
  const fn = FUNCTIONS[m];
  if (fn) {
    s.words.push(fn[1]);
    return result(call(fn[0], args));
  }
  const converted = conversion(m);
  if (converted) {
    s.words.push('wasm-convert');
    return result(call(converted, args, !(op.flags & W.TRAPS)));
  }
  // Anything else with a fixed stack effect: the instruction as a function of its operands.
  return result(folded(s, insn, args));
}

/**
 * The HLA64 line of the instructions first..last (one statement), or null
 * when they cannot be written as one — then each stays an instruction.
 */
export function liftGroup(p: WasmProgram, first: number, last: number, names: Naming): HlaLine | null {
  const fnIndex = p.functionOfIndex(first);
  const fn = p.functions[fnIndex];
  if (!fn) return null;
  const s: State = { p, names, func: fn.index!, last: fn.first + fn.count - 1, results: p.funcType(fn.index!)?.results.length ?? 0, stack: [], out: [], words: [], comments: [] };
  const insn = new WasmInsn();
  const end = p.bodies[fnIndex]!.end;
  for (let i = first; i <= last; i++) {
    decodeAt(p.module.bytes, p.offsets[i]!, end, insn);
    if (!step(s, i, insn)) return null;
  }
  if (s.stack.length || s.out.length !== 1) return null;
  return { text: s.out[0]!, words: [...new Set(s.words)], comment: s.comments.join('; ') || undefined };
}
