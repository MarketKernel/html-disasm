/**
 * The HLA64 view of Java bytecode.
 *
 * The JVM is a stack machine, like CIL and WebAssembly, and its view is
 * written the same way: the analysis (src/core/jvm/program.ts) marks the runs
 * of instructions that make one statement, and liftGroup() turns a run back
 * into that statement by evaluating the stack with expressions instead of
 * values — `aload_0, aload_0, arraylength, invokestatic sum, lstore_2` is
 * `sum = Hello::sum(values, len(values))`. Every line stands for the
 * instructions at its addresses and means exactly what they do, operands in
 * the order the instructions compute them; whatever has no word stays an
 * instruction, as HLA64 accepts.
 *
 * The JVM's instructions say what they work on (iadd, fadd, lcmp…), so every
 * value's kind is known: a comparison of floats is joined with the branch that
 * tests it only where a NaN makes both mean the same — fcmpl leaves -1 for a
 * NaN, so `fcmpl; ifge` is `if a >= b` but `fcmpl; iflt` stays `fcmpl(a, b) < 0`.
 *
 * Locals go by the names the class keeps (LocalVariableTable, MethodParameters)
 * where a name means one slot in the whole method, else `l` and the slot.
 * Names in a line — methods, fields, labels, strings, variables — are wrapped
 * in the WebAssembly view's marks, so the page can make each one a link.
 */

import type { HlaLine } from '../hla';
import { floatLiteral } from '../cil/hla';
import { mark } from '../wasm/hla';
import { CONSTANT, descriptorKinds, fieldType, javaName, methodTypes, type ClassFile, type LocalVariable } from './classfile';
import { JvmInsn } from './decode';
import { ATYPES, F } from './opcodes';
import type { JvmProgram } from './program';

/** What kind of value: int (and boolean, byte, char, short), long, float, double, a reference; undefined when it is not known. */
type Kind = 'i' | 'l' | 'f' | 'd' | 'a' | undefined;

/** A value on the stack, as HLA64 writes it. */
interface Expr {
  text: string;
  /** Go's levels: 6 an operand, 5.5 a unary operator, 5 * / % << >> >>> &, 4 + - | ^, 3 comparisons. */
  prec: number;
  /** Computing it has no effect (no call, store, allocation). */
  pure: boolean;
  kind: Kind;
  /** For x op= y: the operator and operands of a binary expression. */
  op?: string;
  left?: Expr;
  right?: Expr;
  /** A variable or a constant: dup may write it twice. */
  copyable?: boolean;
  /** A Java boolean (a method's or field's Z, instanceof): `if b` tests it. */
  bool?: boolean;
  /** lcmp, fcmpl…: the two values compared and how a NaN compares, for the branch that tests the result. */
  cmp?: { a: Expr; b: Expr; nan: 0 | -1 | 1 };
  /** `new C` before its constructor has run: the class's name. */
  construct?: string;
  /** The copy of a `new` its constructor takes. */
  init?: boolean;
  /** A new array, `new int[n]`, and the elements an initializer has stored in it so far; the copy of it a store takes. */
  array?: { head: string; items: string[] };
  fillCopy?: boolean;
  /** An int constant's value. */
  int?: number;
}

const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/;
/** Words a local cannot be named in a line: they are HLA64's own, or the view's. */
const RESERVED = new Set(['if', 'goto', 'return', 'switch', 'case', 'default', 'fn', 'null', 'new', 'len', 'concat', 'lambda', 'asm', 'nan', 'inf', 'this', '_']);
const atom = (text: string, kind: Kind, pure = true): Expr => ({ text, prec: 6, pure, kind });
const unary = (text: string, kind: Kind, pure = true): Expr => ({ text, prec: 5.5, pure, kind });
const wrap = (e: Expr, min: number) => (e.prec >= min ? e.text : `(${e.text})`);
const SHIFTS = new Set(['<<', '>>', '>>>']);
const operand = (e: Expr, min: number) => (e.op && SHIFTS.has(e.op) && e.prec === 5 ? `(${e.text})` : wrap(e, min));

function binary(left: Expr, op: string, prec: number, right: Expr, kind: Kind): Expr {
  const min = prec === 3 ? 4 : prec;
  return { text: `${operand(left, min)} ${op} ${operand(right, prec === 3 ? 4 : prec + 1)}`, prec, pure: left.pure && right.pure, kind, op, left, right };
}

const num = (v: number | bigint): string => {
  if (typeof v === 'bigint') return v < 0n ? (v > -10n ? String(v) : `-0x${(-v).toString(16)}`) : v < 10n ? String(v) : `0x${v.toString(16)}`;
  return Math.abs(v) < 10 ? String(v) : v < 0 ? `-0x${(-v).toString(16)}` : `0x${v.toString(16)}`;
};

const LETTER: Record<string, Kind> = { i: 'i', l: 'l', f: 'f', d: 'd', a: 'a', b: 'i', c: 'i', s: 'i' };

/** The arithmetic, by the operation's name without its type letter: [operator, precedence, word, integers only]. */
const BINARY: Record<string, [string, number, string, boolean?]> = {
  add: ['+', 4, 'arith'], sub: ['-', 4, 'arith'], mul: ['*', 5, 'arith'], div: ['/', 5, 'arith'], rem: ['%', 5, 'arith', true],
  and: ['&', 5, 'arith'], or: ['|', 4, 'arith'], xor: ['^', 4, 'arith'], shl: ['<<', 5, 'shift'], shr: ['>>', 5, 'shift'], ushr: ['>>>', 5, 'shift'],
};

/** Conversions named after their result: i2b is i8(x), i2c u16(x). */
const CONVERSIONS: Record<string, { to: string; kind: Kind }> = {
  i2l: { to: 'i64', kind: 'l' }, i2f: { to: 'f32', kind: 'f' }, i2d: { to: 'f64', kind: 'd' }, l2i: { to: 'i32', kind: 'i' }, l2f: { to: 'f32', kind: 'f' },
  l2d: { to: 'f64', kind: 'd' }, f2i: { to: 'i32', kind: 'i' }, f2l: { to: 'i64', kind: 'l' }, f2d: { to: 'f64', kind: 'd' }, d2i: { to: 'i32', kind: 'i' },
  d2l: { to: 'i64', kind: 'l' }, d2f: { to: 'f32', kind: 'f' }, i2b: { to: 'i8', kind: 'i' }, i2c: { to: 'u16', kind: 'i' }, i2s: { to: 'i16', kind: 'i' },
};

/** The conditions of the branches: if<cond> against zero, if_icmp<cond> and if_acmp<cond> between two values. */
const CONDITIONS: Record<string, string> = { eq: '==', ne: '!=', lt: '<', ge: '>=', gt: '>', le: '<=' };

/* ------------------------------------------------------------------ *
 * What a method holds
 * ------------------------------------------------------------------ */

interface MethodInfo {
  instance: boolean;
  /** The local variables the class names, and the names that mean more than one slot. */
  locals: LocalVariable[];
  ambiguous: Set<string>;
  /** Parameter names by slot (MethodParameters), when there is no LocalVariableTable. */
  params: Map<number, string>;
  /** Slot 0 is written: `this` cannot name it. */
  thisWritten: boolean;
}

const methodsOf = new WeakMap<JvmProgram, Map<number, MethodInfo>>();

function methodInfo(p: JvmProgram, fnIndex: number): MethodInfo {
  let cache = methodsOf.get(p);
  if (!cache) methodsOf.set(p, (cache = new Map()));
  let info = cache.get(fnIndex);
  if (info) return info;
  const body = p.bodies[fnIndex]!;
  const cf = p.classes[body.cls]!;
  const instance = !(body.method.access & 0x0008);
  const locals = cf.localVariables(body.code);
  const slotsOf = new Map<string, Set<number>>();
  for (const v of locals) slotsOf.set(v.name, (slotsOf.get(v.name) ?? new Set()).add(v.slot));
  const ambiguous = new Set([...slotsOf].filter(([, slots]) => slots.size > 1).map(([name]) => name));
  const params = new Map<number, string>();
  const names = cf.parameterNames(body.method);
  if (names) {
    let slot = instance ? 1 : 0;
    const kinds = descriptorKinds(body.method.descriptor).params;
    names.forEach((name, k) => {
      if (name) params.set(slot, name);
      slot += kinds[k] === 'l' || kinds[k] === 'd' ? 2 : 1;
    });
  }
  let thisWritten = false;
  const fn = p.functions[fnIndex]!;
  const insn = new JvmInsn();
  for (let i = fn.first; i < fn.first + fn.count && instance; i++) {
    p.insn(i, insn);
    if ((insn.m === 'astore_0' || ((insn.m === 'astore' || insn.m === 'astore_w') && insn.a === 0))) thisWritten = true;
  }
  info = { instance, locals, ambiguous, params, thisWritten };
  cache.set(fnIndex, info);
  return info;
}

/* ------------------------------------------------------------------ *
 * Names
 * ------------------------------------------------------------------ */

interface State {
  p: JvmProgram;
  cf: ClassFile;
  cls: number;
  info: MethodInfo;
  insn: JvmInsn;
  stack: Expr[];
  out: string[];
  words: string[];
}

function quoted(name: string, words: string[]): string {
  if (IDENTIFIER.test(name)) return name;
  words.push('quoted-name');
  return `\`${name}\``;
}

/** A class as the view names it: its simple name — `String`, `Point` for hello/Hello$Point —, an array as Java writes its type. */
export function shortClass(internal: string): string {
  if (internal.startsWith('[')) return fieldType(internal).replace(/(?:[\w$]+\.)+/g, '').replace(/\b[\w$]+\$(?=[A-Za-z_])/g, '');
  const simple = internal.slice(internal.lastIndexOf('/') + 1);
  const nested = simple.slice(simple.lastIndexOf('$') + 1);
  return IDENTIFIER.test(nested) ? nested : simple;
}

const className = (s: State, internal: string) => quoted(shortClass(internal), s.words);
/** A class between angle brackets, where an array type needs no quotes: `checkcast<int[]>`. */
const typeArgument = (s: State, internal: string) => (internal.startsWith('[') ? shortClass(internal) : className(s, internal));

/** The name of a local at an instruction: the class's own name for it, `this`, or `l` and the slot. */
function localName(s: State, slot: number, store: boolean): string {
  const pc = s.insn.at;
  const after = pc + s.insn.len;
  const { locals, ambiguous, params, instance, thisWritten } = s.info;
  let found: LocalVariable | undefined;
  for (const v of locals) {
    if (v.slot !== slot) continue;
    if (pc >= v.start && pc < v.start + v.length) {
      found = v;
      break;
    }
    // A store starts the variable's range: the range begins after it.
    if (store && after >= v.start && after <= v.start + v.length && !found) found = v;
  }
  const name = found?.name ?? (locals.length ? undefined : params.get(slot));
  if (name === 'this' && slot === 0 && instance && !thisWritten) return 'this';
  if (name && IDENTIFIER.test(name) && !RESERVED.has(name) && !/^l\d+$/.test(name) && !ambiguous.has(name)) return name;
  if (slot === 0 && instance && !thisWritten && !found) return 'this';
  return `l${slot}`;
}

function variable(s: State, slot: number, kind: Kind, store: boolean): Expr {
  s.words.push('jvm-local');
  return { ...atom(mark('v', slot, localName(s, slot, store)), kind), copyable: true };
}

function gotoLabel(s: State, target: number): string {
  s.words.push('goto');
  const addr = s.p.addrOf(target);
  return `goto ${mark('l', addr, s.p.labelName(addr))}`;
}

function assign(s: State, dest: string, value: Expr): string {
  s.words.push('assign');
  if (value.op && value.left?.text === dest && value.right && /^(\+|-|\*|\/|%|&|\||\^|<<|>>|>>>)$/.test(value.op)) {
    s.words.push('compound');
    return `${dest} ${value.op}= ${value.right.text}`;
  }
  return `${dest} = ${value.text}`;
}

/** The instruction as a function of its operands: `checkcast<String>(x)`, `monitorenter(x)`. */
function folded(s: State, name: string, imm: string, args: Expr[], kind: Kind, pure: boolean): Expr {
  s.words.push('jvm-folded');
  return atom(`${name}${imm ? `<${imm}>` : ''}(${args.map((a) => a.text).join(', ')})`, kind, pure);
}

/* ------------------------------------------------------------------ *
 * Lifting
 * ------------------------------------------------------------------ */

function take(s: State, count: number): Expr[] | null {
  if (count > s.stack.length) return null;
  return s.stack.splice(s.stack.length - count, count);
}

const wide = (e: Expr) => e.kind === 'l' || e.kind === 'd';

/** The value a constant pool entry loads (ldc), or null when it has no form here. */
function constant(s: State, index: number): Expr | null {
  const cf = s.cf;
  switch (cf.tags[index]) {
    case CONSTANT.Integer:
      return { ...atom(num(cf.int(index)), 'i'), copyable: true };
    case CONSTANT.Long:
      return { ...atom(num(cf.long(index)), 'l'), copyable: true };
    case CONSTANT.Float:
      s.words.push('float');
      return { ...atom(floatLiteral(cf.float(index), true), 'f'), copyable: true };
    case CONSTANT.Double:
      s.words.push('float');
      return { ...atom(floatLiteral(cf.double(index), false), 'd'), copyable: true };
    case CONSTANT.String: {
      const text = cf.utf8(cf.ref1(index));
      s.words.push('string');
      return { ...atom(mark('s', s.p.stringAddr(text), JSON.stringify(text.length > 80 ? `${text.slice(0, 80)}…` : text)), 'a'), copyable: true };
    }
    case CONSTANT.Class:
      return { ...folded(s, 'ldc', typeArgument(s, cf.className(index)), [], 'a', true), copyable: true };
  }
  return null;
}

/** A call's callee as a link: its code here, or the import. */
function calleeLink(s: State, index: number, text: string): string {
  return mark('f', s.p.callee(s.cls, index)?.addr ?? -1, text);
}

/** invokedynamic: string concatenation and lambdas have words; any other call site is written as the instruction with its name. */
function dynamic(s: State, index: number, args: Expr[]): Expr {
  const cf = s.cf;
  const site = cf.dynamic(index);
  const bootstrap = cf.bootstrapMethods()[site.bootstrap];
  const handle = bootstrap && cf.tags[bootstrap.method] === CONSTANT.MethodHandle ? cf.member(cf.handle(bootstrap.method).reference) : undefined;
  const ret = descriptorKinds(site.descriptor).ret as Kind;
  if (handle?.owner === 'java/lang/invoke/StringConcatFactory' && handle.name === 'makeConcatWithConstants' && bootstrap!.args.length >= 1 && cf.tags[bootstrap!.args[0]!] === CONSTANT.String) {
    // The recipe: \u0001 takes the next argument, \u0002 the next constant of the bootstrap's, the rest is text.
    const recipe = cf.utf8(cf.ref1(bootstrap!.args[0]!));
    const parts: string[] = [];
    let text = '';
    let next = 0;
    let constants = 1;
    const flush = () => {
      if (text) parts.push(mark('s', s.p.stringAddr(text), JSON.stringify(text)));
      text = '';
    };
    for (const c of recipe) {
      if (c === '\u0001') {
        flush();
        const arg = args[next++];
        if (!arg) return folded(s, 'invokedynamic', quoted(site.name, s.words), args, ret, false);
        parts.push(arg.text);
      } else if (c === '\u0002') {
        const k = bootstrap!.args[constants++];
        if (k === undefined || cf.tags[k] !== CONSTANT.String) return folded(s, 'invokedynamic', quoted(site.name, s.words), args, ret, false);
        text += cf.utf8(cf.ref1(k));
      } else text += c;
    }
    flush();
    if (next !== args.length) return folded(s, 'invokedynamic', quoted(site.name, s.words), args, ret, false);
    s.words.push('jvm-concat');
    return atom(`concat(${parts.join(', ')})`, 'a', false);
  }
  if (handle?.owner === 'java/lang/invoke/LambdaMetafactory' && (handle.name === 'metafactory' || handle.name === 'altMetafactory') && bootstrap!.args.length >= 2 && cf.tags[bootstrap!.args[1]!] === CONSTANT.MethodHandle) {
    const impl = cf.member(cf.handle(bootstrap!.args[1]!).reference);
    const target = s.p.callee(s.cls, bootstrap!.args[1]!);
    const iface = methodTypes(site.descriptor).ret;
    const implText = mark('f', target?.addr ?? -1, `${className(s, impl.owner)}::${quoted(impl.name, s.words)}`);
    s.words.push('jvm-lambda');
    return atom(`lambda<${quoted(iface.slice(iface.lastIndexOf('.') + 1).replace(/^.*\$/, ''), s.words)}, ${implText}>(${args.map((a) => a.text).join(', ')})`, 'a', false);
  }
  return folded(s, 'invokedynamic', quoted(site.name, s.words), args, ret, false);
}

/** A branch on a value against zero: joined with the comparison that made it where that means exactly the same. */
function zeroCondition(value: Expr, cond: string): string {
  const op = CONDITIONS[cond]!;
  if (value.cmp) {
    const { a, b, nan } = value.cmp;
    // With a NaN the comparison leaves `nan`, and the branch is taken when `nan cond 0`; `a op b` is false for a NaN, `a != b` true. They must agree.
    const taken = cond === 'eq' ? nan === 0 : cond === 'ne' ? nan !== 0 : cond === 'lt' ? nan < 0 : cond === 'le' ? nan <= 0 : cond === 'gt' ? nan > 0 : nan >= 0;
    if (nan === 0 || taken === (cond === 'ne')) return binary(a, op, 3, b, 'i').text;
  }
  if (value.bool && cond === 'ne') return value.text;
  return `${wrap(value, 4)} ${op} 0`;
}

/** One instruction applied to the expression stack. False when it has no form here. */
function step(s: State, index: number): boolean {
  const insn = s.insn;
  const op = insn.op;
  if (!op || op.flags & F.SUBROUTINE) return false;
  const m = insn.m;
  const p = s.p;
  const cf = s.cf;
  const push = (e: Expr) => (s.stack.push(e), true);
  const statement = (text: string) => (s.out.push(text), true);

  // Locals.
  let match = /^([ilfda])(load|store)(?:_([0-3])|_w)?$/.exec(m);
  if (match) {
    const slot = match[3] !== undefined ? Number(match[3]) : insn.a;
    const kind = LETTER[match[1]!];
    if (match[2] === 'load') return push(variable(s, slot, kind, false));
    const [value] = take(s, 1) ?? [];
    return value ? statement(assign(s, variable(s, slot, kind, true).text, value)) : false;
  }
  if (m === 'iinc' || m === 'iinc_w') {
    s.words.push('compound');
    const v = variable(s, insn.a, 'i', true).text;
    return statement(insn.b < 0 ? `${v} -= ${num(-insn.b)}` : `${v} += ${num(insn.b)}`);
  }
  // Constants.
  match = /^([ilfd])const_(m1|\d)$/.exec(m);
  if (match) {
    const value = match[2] === 'm1' ? -1 : Number(match[2]);
    const kind = LETTER[match[1]!];
    if (kind === 'f' || kind === 'd') s.words.push('float');
    return push({ ...atom(kind === 'f' || kind === 'd' ? `${value}.0` : String(value), kind), copyable: true, int: kind === 'i' ? value : undefined });
  }
  switch (m) {
    case 'bipush':
    case 'sipush':
      return push({ ...atom(num(insn.a), 'i'), copyable: true, int: insn.a });
    case 'aconst_null':
      s.words.push('jvm-new');
      return push({ ...atom('null', 'a'), copyable: true });
    case 'ldc':
    case 'ldc_w':
    case 'ldc2_w': {
      const value = constant(s, insn.a);
      return value ? push(value) : false;
    }
    case 'pop':
    case 'pop2': {
      const top = s.stack[s.stack.length - 1];
      if (!top || (m === 'pop2' && !wide(top))) return false;
      s.stack.pop();
      if (!top.pure && top.text.endsWith(')') && !top.construct) return statement(top.text);
      s.words.push('jvm-pop');
      return statement(`_ = ${top.text}`);
    }
    case 'dup': {
      const top = s.stack[s.stack.length - 1];
      if (top?.construct) return push({ ...top, init: true, construct: undefined });
      if (top?.array) return push({ ...top, fillCopy: true, array: undefined });
      if (!top?.copyable) return false;
      return push(top);
    }
    case 'dup2': {
      const top = s.stack[s.stack.length - 1];
      const below = s.stack[s.stack.length - 2];
      if (top && wide(top)) return top.copyable ? push(top) : false;
      if (!top?.copyable || !below?.copyable || wide(below)) return false;
      s.stack.push(below, top);
      return true;
    }
    case 'ireturn':
    case 'lreturn':
    case 'freturn':
    case 'dreturn':
    case 'areturn':
    case 'return': {
      s.words.push('return');
      // ireturn … areturn take one value: when it was made before a label, the line cannot name it.
      const values = s.stack.splice(0);
      if (values.length !== (m === 'return' ? 0 : 1)) return false;
      return statement(values.length ? `return ${values[0]!.text}` : 'return');
    }
    case 'goto':
    case 'goto_w':
      return statement(gotoLabel(s, p.branchTargets(index)[0] ?? -1));
    case 'tableswitch':
    case 'lookupswitch': {
      const [value] = take(s, 1) ?? [];
      const targets = p.branchTargets(index);
      const keys = insn.keys ?? [];
      if (!value || targets.length !== keys.length + 1) return false;
      s.words.push('switch', 'goto');
      const byTarget = new Map<number, number[]>();
      keys.forEach((key, k) => byTarget.set(targets[k]!, [...(byTarget.get(targets[k]!) ?? []), key]));
      const fallback = targets[keys.length]!;
      const cases: string[] = [];
      for (const [target, values] of byTarget) {
        if (target === fallback) continue;
        const ranges: string[] = [];
        for (let k = 0; k < values.length; ) {
          let e = k;
          while (e + 1 < values.length && values[e + 1] === values[e]! + 1) e++;
          ranges.push(e === k ? num(values[k]!) : e === k + 1 ? `${num(values[k]!)}, ${num(values[e]!)}` : `${num(values[k]!)}..=${num(values[e]!)}`);
          k = e + 1;
        }
        const addr = p.addrOf(target);
        cases.push(`case ${ranges.join(', ')} { goto ${mark('l', addr, p.labelName(addr))} }`);
      }
      const addr = p.addrOf(fallback);
      cases.push(`default { goto ${mark('l', addr, p.labelName(addr))} }`);
      return statement(`switch ${value.text} { ${cases.join(' ')} }`);
    }
  }

  // Branches.
  match = /^if(eq|ne|lt|ge|gt|le)$/.exec(m);
  if (match) {
    const [value] = take(s, 1) ?? [];
    if (!value) return false;
    const cond = zeroCondition(value, match[1]!);
    if (!cond) return false;
    s.words.push('if-goto');
    return statement(`if ${cond} { ${gotoLabel(s, p.branchTargets(index)[0] ?? -1)} }`);
  }
  match = /^if_[ia]cmp(eq|ne|lt|ge|gt|le)$/.exec(m);
  if (match) {
    const [a, b] = take(s, 2) ?? [];
    if (!a || !b) return false;
    s.words.push('if-goto');
    return statement(`if ${binary(a, CONDITIONS[match[1]!]!, 3, b, 'i').text} { ${gotoLabel(s, p.branchTargets(index)[0] ?? -1)} }`);
  }
  if (m === 'ifnull' || m === 'ifnonnull') {
    const [value] = take(s, 1) ?? [];
    if (!value) return false;
    s.words.push('if-goto', 'jvm-new');
    return statement(`if ${wrap(value, 4)} ${m === 'ifnull' ? '==' : '!='} null { ${gotoLabel(s, p.branchTargets(index)[0] ?? -1)} }`);
  }

  // Fields, calls, objects.
  switch (m) {
    case 'getfield':
    case 'putfield':
    case 'getstatic':
    case 'putstatic': {
      const ref = cf.member(insn.a);
      const kind = descriptorKinds(`()${ref.descriptor}`).ret as Kind;
      const field = mark('g', p.fieldAddr(s.cls, insn.a), quoted(ref.name, s.words));
      s.words.push('jvm-member');
      if (m === 'getstatic') return push({ ...atom(`${className(s, ref.owner)}::${field}`, kind), bool: ref.descriptor === 'Z' });
      if (m === 'putstatic') {
        const [value] = take(s, 1) ?? [];
        return value ? statement(assign(s, `${className(s, ref.owner)}::${field}`, value)) : false;
      }
      if (m === 'getfield') {
        const [obj] = take(s, 1) ?? [];
        return obj ? push({ ...atom(`${wrap(obj, 6)}.${field}`, kind, obj.pure), bool: ref.descriptor === 'Z' }) : false;
      }
      const [obj, value] = take(s, 2) ?? [];
      return obj && value ? statement(assign(s, `${wrap(obj, 6)}.${field}`, value)) : false;
    }
    case 'invokestatic':
    case 'invokevirtual':
    case 'invokeinterface':
    case 'invokespecial': {
      const ref = cf.member(insn.a);
      const shape = descriptorKinds(ref.descriptor);
      const args = take(s, shape.params.length + (m === 'invokestatic' ? 0 : 1));
      if (!args) return false;
      const kind = shape.ret as Kind;
      let text: string;
      if (m === 'invokespecial' && ref.name === '<init>' && args[0]?.init) {
        // new C; dup; …; invokespecial C.<init>: the object made is the value below the copy.
        const made = s.stack[s.stack.length - 1];
        if (!made?.construct) return false;
        s.words.push('jvm-new');
        s.stack[s.stack.length - 1] = unary(`new ${calleeLink(s, insn.a, made.construct)}(${args.slice(1).map((a) => a.text).join(', ')})`, 'a', false);
        return true;
      }
      s.words.push('jvm-member');
      if (m === 'invokevirtual' || m === 'invokeinterface') {
        const [obj, ...rest] = args;
        text = `${wrap(obj!, 6)}.${calleeLink(s, insn.a, quoted(ref.name, s.words))}(${rest.map((a) => a.text).join(', ')})`;
      } else text = `${calleeLink(s, insn.a, `${className(s, ref.owner)}::${quoted(ref.name, s.words)}`)}(${args.map((a) => a.text).join(', ')})`;
      return shape.ret ? push({ ...atom(text, kind, false), bool: ref.descriptor.endsWith(')Z') }) : statement(text);
    }
    case 'invokedynamic': {
      const site = cf.dynamic(insn.a);
      const shape = descriptorKinds(site.descriptor);
      const args = take(s, shape.params.length);
      if (!args) return false;
      const value = dynamic(s, insn.a, args);
      return shape.ret ? push(value) : statement(value.text);
    }
    case 'new':
      return push({ ...unary(`new ${className(s, cf.className(insn.a))}`, 'a', false), construct: className(s, cf.className(insn.a)) });
    case 'newarray':
    case 'anewarray': {
      const [length] = take(s, 1) ?? [];
      if (!length) return false;
      s.words.push('jvm-new');
      const element = m === 'newarray' ? ATYPES[insn.a] ?? '?' : className(s, cf.className(insn.a));
      const head = `new ${element}[${length.text}]`;
      return push({ ...unary(head, 'a', false), array: { head, items: [] } });
    }
    case 'multianewarray': {
      const dims = take(s, insn.b);
      if (!dims) return false;
      const type = cf.className(insn.a);
      const depth = /^\[+/.exec(type)?.[0].length ?? 0;
      const base = type[depth] === 'L' ? className(s, type.slice(depth + 1, -1)) : fieldType(type.slice(depth));
      s.words.push('jvm-new');
      return push(unary(`new ${base}${dims.map((d) => `[${d.text}]`).join('')}${'[]'.repeat(Math.max(0, depth - dims.length))}`, 'a', false));
    }
    case 'arraylength': {
      const [array] = take(s, 1) ?? [];
      if (!array) return false;
      s.words.push('jvm-array');
      return push(atom(`len(${array.text})`, 'i', array.pure));
    }
    case 'checkcast':
    case 'instanceof': {
      const [value] = take(s, 1) ?? [];
      if (!value) return false;
      const e = folded(s, m, typeArgument(s, cf.className(insn.a)), [value], m === 'checkcast' ? 'a' : 'i', value.pure && m === 'instanceof');
      return push(m === 'instanceof' ? { ...e, bool: true } : e);
    }
    case 'athrow':
    case 'monitorenter':
    case 'monitorexit': {
      const [value] = take(s, 1) ?? [];
      return value ? statement(folded(s, m, '', [value], undefined, false).text) : false;
    }
  }

  // Arrays.
  match = /^([ilfdabcs])a(load|store)$/.exec(m);
  if (match) {
    s.words.push('jvm-array');
    if (match[2] === 'load') {
      const [array, at] = take(s, 2) ?? [];
      if (!array || !at) return false;
      return push(atom(`${wrap(array, 6)}[${at.text}]`, LETTER[match[1]!], array.pure && at.pure));
    }
    const [array, at, value] = take(s, 3) ?? [];
    if (!array || !at || !value) return false;
    if (array.fillCopy) {
      // An initializer's store: the next element of the new array below the copy.
      const made = s.stack[s.stack.length - 1];
      if (!made?.array || at.int !== made.array.items.length) return false;
      const items = [...made.array.items, value.text];
      s.stack[s.stack.length - 1] = { ...unary(`${made.array.head} { ${items.join(', ')} }`, 'a', false), array: { head: made.array.head, items } };
      return true;
    }
    return statement(assign(s, `${wrap(array, 6)}[${at.text}]`, value));
  }

  // Numbers.
  match = /^([ilfd])(add|sub|mul|div|rem|and|or|xor|shl|shr|ushr|neg)$/.exec(m);
  if (match) {
    const kind = LETTER[match[1]!];
    if (match[2] === 'neg') {
      const [a] = take(s, 1) ?? [];
      if (!a) return false;
      s.words.push('arith');
      return push(unary(`-${wrap(a, 6)}`, kind, a.pure));
    }
    const [a, b] = take(s, 2) ?? [];
    if (!a || !b) return false;
    const [operator, prec, word, integers] = BINARY[match[2]!]!;
    if (integers && (kind === 'f' || kind === 'd')) return push(folded(s, m, '', [a, b], kind, a.pure && b.pure));
    s.words.push(word);
    if (kind === 'f' || kind === 'd') s.words.push('float');
    return push(binary(a, operator, prec, b, kind));
  }
  const conversion = CONVERSIONS[m];
  if (conversion) {
    const [a] = take(s, 1) ?? [];
    if (!a) return false;
    s.words.push('jvm-convert');
    return push(atom(`${conversion.to}(${a.text})`, conversion.kind, a.pure));
  }
  if (op.flags & F.COMPARE) {
    const [a, b] = take(s, 2) ?? [];
    if (!a || !b) return false;
    const nan = m === 'lcmp' ? 0 : m.endsWith('l') ? -1 : 1;
    return push({ ...atom(`${m}(${a.text}, ${b.text})`, 'i', a.pure && b.pure), cmp: { a, b, nan } });
  }
  return false;
}

/**
 * The HLA64 line of the instructions first..last (one statement), or null
 * when they cannot be written as one — then each stays an instruction.
 */
export function liftGroup(p: JvmProgram, first: number, last: number): HlaLine | null {
  const fnIndex = p.functionOfIndex(first);
  const body = p.bodies[fnIndex];
  if (!body) return null;
  const s: State = { p, cf: p.classes[body.cls]!, cls: body.cls, info: methodInfo(p, fnIndex), insn: new JvmInsn(), stack: [], out: [], words: [] };
  for (let i = first; i <= last; i++) {
    p.insn(i, s.insn);
    if (!step(s, i)) return null;
  }
  if (s.stack.length || s.out.length !== 1) return null;
  const text = s.out[0]!;
  // A comparison's value that no branch took is written as the instruction.
  if (/\b(?:lcmp|[fd]cmp[lg])\(/.test(text)) s.words.push('jvm-folded');
  return { text, words: [...new Set(s.words)] };
}

/** The names of a method's parameters for its header: the class's own, else `l` and the slot; and their Java types. */
export function headerParams(p: JvmProgram, fnIndex: number): { name: string; type: string }[] {
  const body = p.bodies[fnIndex]!;
  const info = methodInfo(p, fnIndex);
  const types = methodTypes(body.method.descriptor).params;
  const kinds = descriptorKinds(body.method.descriptor).params;
  let slot = info.instance ? 1 : 0;
  return types.map((type, k) => {
    const v = info.locals.find((l) => l.slot === slot && l.start === 0);
    const name = v?.name ?? info.params.get(slot);
    const shown = name && IDENTIFIER.test(name) && !RESERVED.has(name) && !/^l\d+$/.test(name) && !info.ambiguous.has(name) ? name : `l${slot}`;
    slot += kinds[k] === 'l' || kinds[k] === 'd' ? 2 : 1;
    return { name: shown, type: javaName(type).replace(/(?:[\w$]+\.)+/g, '') };
  });
}
