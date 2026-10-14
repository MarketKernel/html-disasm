/**
 * The HLA64 view of CIL.
 *
 * CIL is a stack machine, like WebAssembly, and its view is written the same
 * way: the analysis (src/core/cil/program.ts) marks the runs of instructions
 * that make one statement, and liftGroup() turns a run back into that
 * statement by evaluating the stack with expressions instead of values —
 * `ldloc.0, ldloc.0, ldlen, conv.i4, call Sum, stloc.1` is
 * `V_1 = Program::Sum(V_0, i32(len(V_0)))`. Every line stands for the
 * instructions at its addresses and means exactly what they do, operands in
 * the order the instructions compute them; whatever has no word stays an
 * instruction, as HLA64 accepts.
 *
 * What a word needs to mean exactly decides where it is written: `>u` only
 * between integers (cgt.un between floats is "greater or unordered", between
 * references a test for null), a negated condition only where no NaN can make
 * it wrong, `%` only on integers. To know, every value carries what kind of
 * thing it is — an integer, a float, a reference, a pointer — from the
 * signatures of the locals, arguments, fields and methods it comes from.
 *
 * Names in a line — methods, fields, labels, strings, variables — are wrapped
 * in the WebAssembly view's marks, so the page can make each one a link.
 */

import type { HlaLine } from '../hla';
import { mark } from '../wasm/hla';
import { CilInsn } from './decode';
import { Effects } from './effects';
import { decodeIndex, TABLE, tokenRow, tokenTable, USER_STRING } from './metadata';
import { SigReader, type GenericContext } from './names';
import { F, OPERAND } from './opcodes';
import type { CilProgram } from './program';

/** What kind of value: an integer, a float, a reference, a pointer (managed or not); undefined when it is not known. */
type Kind = 'i' | 'f' | 'r' | 'p' | undefined;

/** A value on the stack, as HLA64 writes it. */
interface Expr {
  text: string;
  /** Go's levels: 6 an operand, 5.5 a unary operator, 5 * / % << >> >>> &, 4 + - | ^, 3 comparisons. */
  prec: number;
  /** Computing it has no effect (no call, store, allocation). */
  pure: boolean;
  kind: Kind;
  /** For x op= y, and for negating a condition: the operator and operands of a binary expression. */
  op?: string;
  left?: Expr;
  right?: Expr;
  /** A variable or a constant: dup may write it twice. */
  copyable?: boolean;
  /** The null reference. */
  isNull?: boolean;
}

const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/;
const atom = (text: string, kind: Kind, pure = true): Expr => ({ text, prec: 6, pure, kind });
/** `&x`, `-x`, `~x`, `new T()`: tighter than any binary operator, looser than a member access, so `(&V_0).n`. */
const unary = (text: string, kind: Kind, pure = true): Expr => ({ text, prec: 5.5, pure, kind });
const wrap = (e: Expr, min: number) => (e.prec >= min ? e.text : `(${e.text})`);
const SHIFTS = new Set(['<<', '>>', '>>>']);
/** A shift inside another operation gets parentheses, as the other views write them: `x + (y << 2)`. */
const operand = (e: Expr, min: number) => (e.op && SHIFTS.has(e.op) && e.prec === 5 ? `(${e.text})` : wrap(e, min));

/** `a op b`; a comparison of comparisons keeps both in parentheses: `(a > 0) == 0`. */
function binary(left: Expr, op: string, prec: number, right: Expr, kind: Kind): Expr {
  const min = prec === 3 ? 4 : prec;
  return { text: `${operand(left, min)} ${op} ${operand(right, prec === 3 ? 4 : prec + 1)}`, prec, pure: left.pure && right.pure, kind, op, left, right };
}

const num = (v: number | bigint): string => {
  if (typeof v === 'bigint') return v < 0n ? (v > -10n ? String(v) : `-0x${(-v).toString(16)}`) : v < 10n ? String(v) : `0x${v.toString(16)}`;
  return Math.abs(v) < 10 ? String(v) : v < 0 ? `-0x${(-v).toString(16)}` : `0x${v.toString(16)}`;
};

/** The shortest decimal that reads back as the same float (`0.1`, `1.5`, `3.4e+38`), always with a point or an exponent. */
export function floatLiteral(value: number, single: boolean): string {
  if (Number.isNaN(value)) return 'nan';
  if (!Number.isFinite(value)) return value > 0 ? 'inf' : '-inf';
  let text = String(value);
  if (single) {
    for (let digits = 1; digits <= 9; digits++) {
      const candidate = Number(value.toPrecision(digits));
      if (Math.fround(candidate) === value) {
        text = String(candidate);
        break;
      }
    }
  }
  if (Object.is(value, -0)) return '-0.0';
  return /[.e]/.test(text) ? text : `${text}.0`;
}

/** The kind of a type as ildasm writes it in a signature. */
export function kindOf(type: string | undefined): Kind {
  if (!type) return undefined;
  const t = type.replace(/ (pinned|mod(req|opt)\([^)]*\))/g, '');
  if (/[&*]$/.test(t)) return 'p';
  if (/\]$/.test(t) || t === 'string' || t === 'object' || t.startsWith('class ')) return 'r';
  if (/^(bool|char|u?int(8|16|32|64)|native u?int)$/.test(t)) return 'i';
  if (t === 'float32' || t === 'float64') return 'f';
  return undefined;
}

/** What each conversion is called: conv.i1 is i8(x), conv.u is nuint(x). What it gives is a float for f32, f64, f64u, else an integer. */
const CONVERSIONS: Record<string, string> = {
  'conv.i1': 'i8', 'conv.u1': 'u8', 'conv.i2': 'i16', 'conv.u2': 'u16', 'conv.i4': 'i32', 'conv.u4': 'u32',
  'conv.i8': 'i64', 'conv.u8': 'u64', 'conv.i': 'nint', 'conv.u': 'nuint', 'conv.r4': 'f32', 'conv.r8': 'f64', 'conv.r.un': 'f64u',
};

/** Loads and stores through a pointer that have a typed form: ldind.u1 reads u8[p]. */
const INDIRECT: Record<string, string> = {
  'ldind.i1': 'i8', 'ldind.u1': 'u8', 'ldind.i2': 'i16', 'ldind.u2': 'u16', 'ldind.i4': 'i32', 'ldind.u4': 'u32', 'ldind.i8': 'i64', 'ldind.r4': 'f32', 'ldind.r8': 'f64',
  'stind.i1': 'i8', 'stind.i2': 'i16', 'stind.i4': 'i32', 'stind.i8': 'i64', 'stind.r4': 'f32', 'stind.r8': 'f64',
};

const typeKind = (type: string): Kind => (type.startsWith('f') ? 'f' : 'i');

/** The kind of what an array element load gives. */
const ELEMENT: Record<string, Kind> = {
  'ldelem.i1': 'i', 'ldelem.u1': 'i', 'ldelem.i2': 'i', 'ldelem.u2': 'i', 'ldelem.i4': 'i', 'ldelem.u4': 'i', 'ldelem.i8': 'i', 'ldelem.i': 'i',
  'ldelem.r4': 'f', 'ldelem.r8': 'f', 'ldelem.ref': 'r', ldelem: undefined,
};

/** The operators of the arithmetic, and whether integers alone may use them. */
const BINARY: Record<string, [string, number, string, boolean?]> = {
  add: ['+', 4, 'arith'], sub: ['-', 4, 'arith'], mul: ['*', 5, 'arith'], div: ['/', 5, 'arith'], rem: ['%', 5, 'arith', true],
  and: ['&', 5, 'arith'], or: ['|', 4, 'arith'], xor: ['^', 4, 'arith'], shl: ['<<', 5, 'shift'], shr: ['>>', 5, 'shift'], 'shr.un': ['>>>', 5, 'shift'],
  ceq: ['==', 3, 'condition-value'], cgt: ['>', 3, 'condition-value'], clt: ['<', 3, 'condition-value'],
};

/** The conditional branches, by their comparison: [operator, unsigned]. */
const BRANCHES: Record<string, [string, boolean]> = {
  beq: ['==', false], 'bne.un': ['!=', false], bge: ['>=', false], bgt: ['>', false], ble: ['<=', false], blt: ['<', false],
  'bge.un': ['>=u', true], 'bgt.un': ['>u', true], 'ble.un': ['<=u', true], 'blt.un': ['<u', true],
};

const NEGATE: Record<string, string> = { '==': '!=', '!=': '==', '<': '>=', '>=': '<', '>': '<=', '<=': '>', '<u': '>=u', '>=u': '<u', '>u': '<=u', '<=u': '>u' };
const integral = (e: Expr) => e.kind === 'i' || e.kind === 'p';

/* ------------------------------------------------------------------ *
 * What a program's methods hold
 * ------------------------------------------------------------------ */

const effectsOf = new WeakMap<CilProgram, Effects>();
const enumsOf = new WeakMap<CilProgram, Set<string>>();

/** The enums this assembly defines, as signatures write them (`valuetype Hello.Kind`): their values are integers. */
function enums(p: CilProgram): Set<string> {
  let found = enumsOf.get(p);
  if (!found) {
    found = new Set();
    const types = p.md.table(TABLE.TypeDef);
    const refs = p.md.table(TABLE.TypeRef);
    for (let row = 2; row <= types.rows; row++) {
      const base = decodeIndex('TypeDefOrRef', types.get(row, 'Extends'));
      if (base.table === TABLE.TypeRef && p.md.string(refs.get(base.row, 'Name')) === 'Enum' && p.md.string(refs.get(base.row, 'Namespace')) === 'System') found.add(`valuetype ${p.names.typeDef(row)}`);
    }
    enumsOf.set(p, found);
  }
  return found;
}

/** The kind of a type in a signature of this program: an enum it defines is an integer. */
function kindIn(p: CilProgram, type: string | undefined): Kind {
  return kindOf(type) ?? (type && enums(p).has(type.replace(/ (pinned|mod(req|opt)\([^)]*\))/g, '')) ? 'i' : undefined);
}
const localsOf = new WeakMap<CilProgram, Map<number, Kind[]>>();

function effects(p: CilProgram): Effects {
  let found = effectsOf.get(p);
  if (!found) effectsOf.set(p, (found = new Effects(p.md)));
  return found;
}

/** The kinds of a method's locals (by its index in `functions`), from its LocalVarSig. */
function localKinds(p: CilProgram, fnIndex: number): Kind[] {
  let cache = localsOf.get(p);
  if (!cache) localsOf.set(p, (cache = new Map()));
  let kinds = cache.get(fnIndex);
  if (!kinds) {
    const body = p.bodies[fnIndex]!;
    kinds = body.localsToken ? p.names.locals(body.localsToken).map((type) => kindIn(p, type)) : [];
    cache.set(fnIndex, kinds);
  }
  return kinds;
}

/** `this` is a reference in a class's method and a pointer to the value in a struct's. */
function thisKind(p: CilProgram, method: number): Kind {
  const md = p.md;
  const owner = p.names.methodOwner[method] ?? 0;
  const base = decodeIndex('TypeDefOrRef', md.table(TABLE.TypeDef).get(owner, 'Extends'));
  if (base.table !== TABLE.TypeRef) return 'r';
  const refs = md.table(TABLE.TypeRef);
  const name = md.string(refs.get(base.row, 'Name'));
  return md.string(refs.get(base.row, 'Namespace')) === 'System' && (name === 'ValueType' || name === 'Enum') ? 'p' : 'r';
}

/* ------------------------------------------------------------------ *
 * Names
 * ------------------------------------------------------------------ */

interface State {
  p: CilProgram;
  insn: CilInsn;
  /** The class and method whose generic parameters the line may name. */
  generic: GenericContext;
  /** The method: its MethodDef row, and the kinds of its locals and arguments. */
  method: number;
  instance: boolean;
  params: string[];
  argKinds: Kind[];
  localKinds: Kind[];
  /** The method returns a value. */
  returns: boolean;
  stack: Expr[];
  out: string[];
  words: string[];
}

function quoted(name: string, words: string[]): string {
  if (IDENTIFIER.test(name)) return name;
  words.push('quoted-name');
  return `\`${name}\``;
}

/** A type as ildasm writes it, shortened: no `class`, `valuetype`, assembly, namespace or arity — `List<string>`, `Func<int32,int32>`. */
export function shortType(text: string): string {
  return text
    .replace(/\b(?:class|valuetype) /g, '')
    .replace(/\[(?:\.module )?[A-Za-z_][^\]]*\]/g, '')
    .replace(/(?:[A-Za-z_$][\w$]*\.)+(?=[A-Za-z_$'])/g, '')
    .replace(/`\d+/g, '');
}

/** A type as the view names it: its own name, without namespace or generic arity — `Console`; a generic instance with its arguments — `List<string>`. */
function typeName(s: State, table: number, row: number): string {
  const md = s.p.md;
  if (table === TABLE.TypeDef || table === TABLE.TypeRef) {
    const name = md.string(md.table(table).get(row, 'Name')).replace(/`\d+$/, '');
    return quoted(name, s.words);
  }
  if (table === TABLE.TypeSpec) {
    const blob = md.blob(md.table(TABLE.TypeSpec).get(row, 'Signature'));
    if (blob[0] === 0x15 && (blob[1] === 0x12 || blob[1] === 0x11)) {
      const value = blob[2]! & 0x80 ? ((blob[2]! & 0x3f) << 8) | blob[3]! : blob[2]!;
      const base = [TABLE.TypeDef, TABLE.TypeRef][value & 3];
      const full = shortType(s.p.names.typeSpec(row, s.generic));
      if (base !== undefined) return `${typeName(s, base, value >>> 2)}${full.slice(full.indexOf('<'))}`;
    }
    return quoted(shortType(s.p.names.typeSpec(row, s.generic)), s.words);
  }
  return '?';
}

function typeOfToken(s: State, tok: number): string {
  return typeName(s, tokenTable(tok), tokenRow(tok));
}

/** The class part of a member reference, `Console::`, and the member's name. */
function member(s: State, tok: number): { owner: string; name: string } {
  const md = s.p.md;
  let table = tokenTable(tok);
  let row = tokenRow(tok);
  // A generic method's instantiation follows its name: `IsEvenInteger<float32>`.
  let inst = '';
  if (table === TABLE.MethodSpec) {
    const spec = md.table(TABLE.MethodSpec);
    const r = new SigReader(md.blob(spec.get(row, 'Instantiation')));
    r.byte();
    const args: string[] = [];
    for (let k = r.u(); k > 0 && !r.done; k--) args.push(shortType(s.p.names.sigType(r, s.generic)));
    inst = `<${args.join(',')}>`;
    const target = decodeIndex('MethodDefOrRef', spec.get(row, 'Method'));
    table = target.table;
    row = target.row;
  }
  if (table === TABLE.MethodDef || table === TABLE.Field) {
    const owner = (table === TABLE.MethodDef ? s.p.names.methodOwner : s.p.names.fieldOwner)[row] ?? 0;
    return { owner: owner > 1 ? typeName(s, TABLE.TypeDef, owner) : '', name: quoted(md.string(md.table(table).get(row, 'Name')), s.words) + inst };
  }
  const refs = md.table(TABLE.MemberRef);
  const parent = decodeIndex('MemberRefParent', refs.get(row, 'Class'));
  const owner = parent.table === TABLE.MethodDef ? typeName(s, TABLE.TypeDef, s.p.names.methodOwner[parent.row] ?? 0) : parent.table === TABLE.ModuleRef ? '' : typeName(s, parent.table, parent.row);
  return { owner, name: quoted(md.string(refs.get(row, 'Name')), s.words) + inst };
}

const qualified = (m: { owner: string; name: string }) => (m.owner ? `${m.owner}::${m.name}` : m.name);

/** The kind of what a field holds, or a method returns. */
function fieldKind(s: State, tok: number): Kind {
  return kindIn(s.p, s.p.names.field(tok).replace(/ \S+$/, ''));
}

function returnKind(s: State, tok: number): Kind {
  const text = s.p.names.method(tok);
  const paren = text.lastIndexOf(' ', text.indexOf('('));
  return kindIn(s.p, text.slice(0, paren).replace(/^(explicit |instance |vararg |unmanaged \w* ?)+/, ''));
}

function variable(s: State, local: boolean, index: number): Expr {
  s.words.push('cil-local');
  if (local) return { ...atom(mark('v', index, `V_${index}`), s.localKinds[index]), copyable: true };
  if (s.instance && index === 0) return { ...atom(mark('v', 0, 'this'), s.argKinds[0]), copyable: true };
  const name = s.params[s.instance ? index : index + 1];
  return { ...atom(mark('v', index, name ? quoted(name, s.words) : `A_${index}`), s.argKinds[index]), copyable: true };
}

function gotoLabel(s: State, index: number): string {
  s.words.push('goto');
  const [target] = s.p.branchTargets(index);
  const addr = s.p.addrOf(target ?? -1);
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

/** The instruction as a function of its operands: `box<Kind>(x)`, `add.ovf(a, b)`, `sizeof<Point>()`. */
function folded(s: State, args: Expr[], kind: Kind): Expr {
  s.words.push('cil-folded');
  const insn = s.insn;
  const op = insn.op!;
  const imm = op.operand === OPERAND.TYPE ? typeOfToken(s, insn.a) : op.operand === OPERAND.NONE ? '' : undefined;
  const pure = !(op.flags & (F.LOAD | F.STORE | F.CALL | F.TRAPS | F.THROW));
  return atom(`${insn.m}${imm ? `<${imm}>` : ''}(${args.map((a) => a.text).join(', ')})`, kind, pure);
}

/** A condition for `if c { … }`: a branch on false negates it where that means exactly the opposite. */
function condition(value: Expr, negate: boolean): string {
  if (!negate) return value.text;
  if (value.op && value.left && value.right && NEGATE[value.op] && value.prec === 3) {
    const flips = value.op === '==' || value.op === '!=' || (integral(value.left) && integral(value.right)) || value.op.endsWith('u');
    if (flips) return binary(value.left, NEGATE[value.op]!, 3, value.right, 'i').text;
  }
  return `${wrap(value, 4)} == ${value.kind === 'r' ? 'null' : '0'}`;
}

/* ------------------------------------------------------------------ *
 * Lifting
 * ------------------------------------------------------------------ */

function take(s: State, count: number): Expr[] | null {
  if (count > s.stack.length) return null;
  return s.stack.splice(s.stack.length - count, count);
}

/** One instruction applied to the expression stack. False when it has no form here. */
function step(s: State, index: number): boolean {
  const insn = s.insn;
  const op = insn.op;
  if (!op || op.flags & F.PREFIX) return false;
  const m = insn.m;
  const p = s.p;
  const push = (e: Expr) => (s.stack.push(e), true);
  const statement = (text: string) => (s.out.push(text), true);

  // Variables and constants.
  let match = /^(ld|st)(loc|arg)(a?)(?:\.([0-3])|\.s)?$/.exec(m);
  if (match) {
    const n = match[4] !== undefined ? Number(match[4]) : insn.a;
    const v = variable(s, match[2] === 'loc', n);
    if (match[1] === 'ld') {
      if (!match[3]) return push(v);
      s.words.push('address');
      return push(unary(`&${v.text}`, 'p'));
    }
    const [value] = take(s, 1) ?? [];
    return value ? statement(assign(s, v.text, value)) : false;
  }
  match = /^ldc\.i4(?:\.(m1|\d))?(?:\.s)?$/.exec(m);
  if (match) return push({ ...atom(num(match[1] === 'm1' ? -1 : match[1] !== undefined ? Number(match[1]) : insn.a), 'i'), copyable: true });
  switch (m) {
    case 'ldc.i8':
      return push({ ...atom(num(insn.value as bigint), 'i'), copyable: true });
    case 'ldc.r4':
    case 'ldc.r8':
      s.words.push('float');
      return push({ ...atom(floatLiteral(insn.value as number, m === 'ldc.r4'), 'f'), copyable: true });
    case 'ldnull':
      s.words.push('cil-new');
      return push({ ...atom('null', 'r'), copyable: true, isNull: true });
    case 'ldstr': {
      if (tokenTable(insn.a) !== USER_STRING) return false;
      const text = p.md.userString(tokenRow(insn.a)) ?? '';
      s.words.push('string');
      return push({ ...atom(mark('s', insn.a, JSON.stringify(text.length > 80 ? `${text.slice(0, 80)}…` : text)), 'r'), copyable: true });
    }
    case 'dup': {
      const top = s.stack[s.stack.length - 1];
      if (!top?.copyable) return false;
      return push(top);
    }
    case 'pop': {
      const [value] = take(s, 1) ?? [];
      if (!value) return false;
      if (!value.pure && value.text.endsWith(')')) return statement(value.text);
      s.words.push('cil-pop');
      return statement(`_ = ${value.text}`);
    }
    case 'ret': {
      s.words.push('return');
      // ret takes the return value when the method has one: when it was made before a label, the line cannot name it.
      const values = s.stack.splice(0);
      if (values.length !== (s.returns ? 1 : 0)) return false;
      return statement(values.length ? `return ${values[0]!.text}` : 'return');
    }
    case 'br':
    case 'br.s':
      return statement(gotoLabel(s, index));
    case 'brtrue':
    case 'brtrue.s':
    case 'brfalse':
    case 'brfalse.s': {
      const [value] = take(s, 1) ?? [];
      if (!value) return false;
      s.words.push('if-goto');
      return statement(`if ${condition(value, m.startsWith('brfalse'))} { ${gotoLabel(s, index)} }`);
    }
    case 'switch': {
      const [value] = take(s, 1) ?? [];
      const targets = p.branchTargets(index);
      if (!value || !targets.length) return false;
      s.words.push('switch', 'goto');
      const byTarget = new Map<number, number[]>();
      targets.forEach((target, k) => byTarget.set(target, [...(byTarget.get(target) ?? []), k]));
      const cases: string[] = [];
      for (const [target, keys] of byTarget) {
        const ranges: string[] = [];
        for (let k = 0; k < keys.length; ) {
          let e = k;
          while (e + 1 < keys.length && keys[e + 1] === keys[e]! + 1) e++;
          ranges.push(e === k ? String(keys[k]) : e === k + 1 ? `${keys[k]}, ${keys[e]}` : `${keys[k]}..=${keys[e]}`);
          k = e + 1;
        }
        const addr = p.addrOf(target);
        cases.push(`case ${ranges.join(', ')} { goto ${mark('l', addr, p.labelName(addr))} }`);
      }
      return statement(`switch ${value.text} { ${cases.join(' ')} }`);
    }
  }
  const branch = BRANCHES[m.replace(/\.s$/, '')];
  if (branch) {
    const [a, b] = take(s, 2) ?? [];
    if (!a || !b) return false;
    // Unsigned between integers only: between floats the .un forms mean "or unordered".
    if (branch[1] && !(integral(a) && integral(b))) return false;
    s.words.push('if-goto');
    if (branch[1]) s.words.push('unsigned-compare');
    return statement(`if ${binary(a, branch[0], 3, b, 'i').text} { ${gotoLabel(s, index)} }`);
  }

  // Fields, calls, objects.
  switch (m) {
    case 'ldfld':
    case 'ldflda': {
      const [obj] = take(s, 1) ?? [];
      if (!obj) return false;
      s.words.push('cil-member');
      const text = `${wrap(obj, 6)}.${mark('g', insn.a, member(s, insn.a).name)}`;
      if (m === 'ldflda') {
        s.words.push('address');
        return push(unary(`&${text}`, 'p'));
      }
      return push(atom(text, fieldKind(s, insn.a), obj.pure));
    }
    case 'ldsfld':
    case 'ldsflda': {
      s.words.push('cil-member');
      const text = mark('g', insn.a, qualified(member(s, insn.a)));
      if (m === 'ldsflda') {
        s.words.push('address');
        return push(unary(`&${text}`, 'p'));
      }
      return push(atom(text, fieldKind(s, insn.a)));
    }
    case 'stfld': {
      const [obj, value] = take(s, 2) ?? [];
      if (!obj || !value) return false;
      s.words.push('cil-member');
      return statement(assign(s, `${wrap(obj, 6)}.${mark('g', insn.a, member(s, insn.a).name)}`, value));
    }
    case 'stsfld': {
      const [value] = take(s, 1) ?? [];
      if (!value) return false;
      s.words.push('cil-member');
      return statement(assign(s, mark('g', insn.a, qualified(member(s, insn.a))), value));
    }
    case 'call':
    case 'callvirt':
    case 'newobj': {
      const shape = effects(p).shape(insn.a);
      const args = take(s, shape.params + (shape.instance && m !== 'newobj' ? 1 : 0));
      if (!args) return false;
      const callee = p.callee(insn.a);
      const who = member(s, insn.a);
      const link = (text: string) => mark('f', callee?.addr ?? -1, text);
      let text: string;
      if (m === 'newobj') {
        s.words.push('cil-new');
        text = `new ${link(who.owner)}(${args.map((a) => a.text).join(', ')})`;
      } else if (m === 'callvirt' && shape.instance) {
        s.words.push('cil-member');
        const [obj, ...rest] = args;
        text = `${wrap(obj!, 6)}.${link(who.name)}(${rest.map((a) => a.text).join(', ')})`;
      } else {
        s.words.push('cil-member');
        text = `${link(qualified(who))}(${args.map((a) => a.text).join(', ')})`;
      }
      if (m === 'newobj') return push(unary(text, 'r', false));
      return shape.returns ? push(atom(text, returnKind(s, insn.a), false)) : statement(text);
    }
    case 'ldtoken': {
      s.words.push('cil-folded');
      const table = tokenTable(insn.a);
      const what = table === TABLE.Field || table === TABLE.MemberRef || table === TABLE.MethodDef || table === TABLE.MethodSpec ? qualified(member(s, insn.a)) : typeOfToken(s, insn.a);
      return push(atom(`ldtoken<${what}>()`, undefined));
    }
    case 'ldftn':
      s.words.push('address');
      return push(unary(`&${mark('f', p.callee(insn.a)?.addr ?? -1, qualified(member(s, insn.a)))}`, 'p'));
    case 'newarr': {
      const [length] = take(s, 1) ?? [];
      if (!length) return false;
      s.words.push('cil-new');
      return push(unary(`new ${typeOfToken(s, insn.a)}[${length.text}]`, 'r', false));
    }
    case 'ldlen': {
      const [array] = take(s, 1) ?? [];
      if (!array) return false;
      s.words.push('cil-array');
      return push(atom(`len(${array.text})`, 'i', array.pure));
    }
    case 'ldelema': {
      const [array, at] = take(s, 2) ?? [];
      if (!array || !at) return false;
      s.words.push('cil-array', 'address');
      return push(unary(`&${wrap(array, 6)}[${at.text}]`, 'p'));
    }
  }
  if (m in ELEMENT) {
    const [array, at] = take(s, 2) ?? [];
    if (!array || !at) return false;
    s.words.push('cil-array');
    return push(atom(`${wrap(array, 6)}[${at.text}]`, ELEMENT[m], array.pure && at.pure));
  }
  if (/^stelem/.test(m)) {
    const [array, at, value] = take(s, 3) ?? [];
    if (!array || !at || !value) return false;
    s.words.push('cil-array');
    return statement(assign(s, `${wrap(array, 6)}[${at.text}]`, value));
  }
  const indirect = INDIRECT[m];
  if (indirect) {
    s.words.push('typed-memory');
    if (m.startsWith('ld')) {
      const [pointer] = take(s, 1) ?? [];
      return pointer ? push(atom(`${indirect}[${pointer.text}]`, typeKind(indirect), pointer.pure)) : false;
    }
    const [pointer, value] = take(s, 2) ?? [];
    return pointer && value ? statement(`${indirect}[${pointer.text}] = ${value.text}`) : false;
  }

  // Numbers.
  const bin = BINARY[m];
  if (bin) {
    const [a, b] = take(s, 2) ?? [];
    if (!a || !b) return false;
    if (bin[3] && !(a.kind === 'i' && b.kind === 'i')) return push(folded(s, [a, b], undefined));
    s.words.push(bin[2]);
    const kind = bin[1] === 3 ? 'i' : a.kind === 'f' || b.kind === 'f' ? 'f' : a.kind === 'p' || b.kind === 'p' ? 'p' : a.kind === 'i' && b.kind === 'i' ? 'i' : undefined;
    return push(binary(a, bin[0], bin[1], b, kind));
  }
  if (m === 'cgt.un' || m === 'clt.un') {
    const [a, b] = take(s, 2) ?? [];
    if (!a || !b) return false;
    // cgt.un against null is the test a reference is not null; between integers an unsigned comparison.
    if (m === 'cgt.un' && b.isNull && a.kind === 'r') {
      s.words.push('condition-value');
      return push(binary(a, '!=', 3, b, 'i'));
    }
    if (!(integral(a) && integral(b))) return push(folded(s, [a, b], 'i'));
    s.words.push('condition-value', 'unsigned-compare');
    return push(binary(a, m === 'cgt.un' ? '>u' : '<u', 3, b, 'i'));
  }
  if (m === 'div.un' || m === 'rem.un') {
    const [a, b] = take(s, 2) ?? [];
    if (!a || !b) return false;
    s.words.push('udiv');
    return push(atom(`${m === 'div.un' ? 'udiv' : 'urem'}(${a.text}, ${b.text})`, a.kind, a.pure && b.pure));
  }
  if (m === 'neg' || m === 'not') {
    const [a] = take(s, 1) ?? [];
    if (!a) return false;
    s.words.push('arith');
    return push(unary(`${m === 'neg' ? '-' : '~'}${wrap(a, 6)}`, a.kind, a.pure));
  }
  const conversion = CONVERSIONS[m];
  if (conversion) {
    const [a] = take(s, 1) ?? [];
    if (!a) return false;
    s.words.push('cil-convert');
    return push(atom(`${conversion}(${a.text})`, typeKind(conversion), a.pure));
  }

  // Anything else with a known stack effect and no branch: the instruction as a function of its operands.
  if (op.flags & (F.BRANCH | F.END) && m !== 'throw') return false;
  if (op.operand !== OPERAND.NONE && op.operand !== OPERAND.TYPE) return false;
  const effect = effects(p).of(insn);
  if (!effect || effect[1] > 1) return false;
  const args = take(s, effect[0]);
  if (!args) return false;
  const value = folded(s, args, m === 'isinst' || m === 'castclass' || m === 'box' ? 'r' : m === 'sizeof' ? 'i' : undefined);
  return effect[1] ? push(value) : statement(value.text);
}

/**
 * The HLA64 line of the instructions first..last (one statement), or null
 * when they cannot be written as one — then each stays an instruction.
 */
export function liftGroup(p: CilProgram, first: number, last: number): HlaLine | null {
  const fnIndex = p.functionOfIndex(first);
  const body = p.bodies[fnIndex];
  if (!body) return null;
  const method = body.method;
  const ctx = p.context(first);
  const sig = p.names.methodDefSig(method);
  const argKinds: Kind[] = (ctx.instance ? [thisKind(p, method)] : []).concat(sig.params.map((type) => kindIn(p, type)));
  const s: State = {
    p, insn: new CilInsn(), generic: ctx.generic, method, instance: ctx.instance, params: ctx.params, argKinds,
    localKinds: localKinds(p, fnIndex), returns: sig.ret !== 'void', stack: [], out: [], words: [],
  };
  for (let i = first; i <= last; i++) {
    p.insn(i, s.insn);
    if (!step(s, i)) return null;
  }
  if (s.stack.length || s.out.length !== 1) return null;
  return { text: s.out[0]!, words: [...new Set(s.words)] };
}

