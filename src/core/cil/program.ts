/**
 * The analysis of a .NET assembly: every method body is decoded once, and
 * from that pass come the statistics, the methods (the functions of the
 * listing, named `Namespace.Type::Method`), the labels branches and exception
 * handlers go to, the calls — to methods of this assembly, and to members of
 * others, which are its imports — and the strings `ldstr` loads.
 *
 * An instruction's address is its RVA, as ildasm's "Method begins at RVA"
 * gives a method's; the listing writes it as the offset in its method's IL
 * (`IL_001f`), as ildasm does. What is not code is addressed by its metadata
 * token: a string of #US by 0x70…, a member of another assembly by its
 * MemberRef 0x0A…, so a string or an import has an address of its own that
 * is never an instruction's.
 */

import { append, BytecodeProgram, IF, tick, type DataAt, type Fn, type Progress, type StringRef } from '../disassembly';
import { t } from '../i18n';
import type { Pe } from '../pe';
import { CilInsn, decodeAt, label, type MethodContext } from './decode';
import { Effects, shapeOf } from './effects';
import { compressed, decodeIndex, readMetadata, TABLE, token, tokenRow, tokenTable, USER_STRING, type Clause, type Metadata, type MethodBody } from './metadata';
import { Names, NO_CONTEXT, paramsText, properName } from './names';
import { F, OPERAND } from './opcodes';

/** A member of another assembly the code uses: a method or a field, through a MemberRef. */
export interface ImportedMember extends Fn {
  /** The MemberRef token. */
  token: number;
  /** The assembly (or module) it comes from, and the type, as ildasm writes it. */
  assembly: string;
  type: string;
  field: boolean;
}

/** A P/Invoke: a method whose code is a function of a native library. */
export interface PInvoke {
  method: number;
  name: string;
  library: string;
  entry: string;
  flags: number;
}

/** A .NET assembly's IL; an instruction's address is its RVA. */
export class CilProgram extends BytecodeProgram {
  readonly arch = 'cil';
  /** The body of each function of `functions`, and its MethodDef row. */
  readonly bodies: MethodBody[] = [];
  /** MethodDef row → its function (an index into `functions`), when it has code. */
  readonly methodFn = new Map<number, number>();
  /** Members of other assemblies, by MemberRef token. */
  readonly imported: ImportedMember[] = [];
  readonly importByToken = new Map<number, ImportedMember>();
  readonly pinvokes: PInvoke[] = [];
  /** Field token (Field or MemberRef) → the instructions that read, write or take its address. */
  readonly fieldRefs = new Map<number, number[]>();
  /** Type token → the instructions that name it (newarr, box, castclass, ldtoken…). */
  readonly typeRefs = new Map<number, number[]>();
  /** Instruction index → the clauses that start a try or a handler there. */
  readonly regions = new Map<number, { clause: Clause; part: 'try' | 'handler' | 'filter' }[]>();
  /** Calls through a function pointer (calli) and through a delegate's Invoke cannot be followed. */
  indirectCalls = 0;
  readonly names: Names;
  /** The method the runtime starts at, a MethodDef row (0 for a library). */
  readonly entryMethod: number;
  readonly assemblyName: string;
  readonly framework: string | undefined;

  constructor(
    readonly pe: Pe,
    readonly md: Metadata,
  ) {
    super();
    this.names = new Names(md);
    const entry = md.header.entryToken;
    this.entryMethod = !(md.header.flags & 0x10) && tokenTable(entry) === TABLE.MethodDef ? tokenRow(entry) : 0;
    this.assemblyName = md.rows(TABLE.Assembly) ? md.string(md.table(TABLE.Assembly).get(1, 'Name')) : md.string(md.table(TABLE.Module).get(1, 'Name'));
    this.framework = targetFramework(md, this.names);
  }

  archLabel(): string {
    const flags = this.md.header.flags;
    const r2r = this.md.header.managedNative.rva ? ' · ReadyToRun' : '';
    if (!(flags & 0x1)) return `CIL + ${this.pe.arch}${r2r}`;
    return `CIL${flags & 0x2 ? ' (x86)' : this.pe.machine === 0x14c ? '' : ` (${this.pe.arch})`}${r2r}`;
  }

  override platformLabel(): string | undefined {
    return this.framework ? frameworkLabel(this.framework) : undefined;
  }

  /** `IL_001f`: where an address is in its method's IL. */
  override labelName(addr: number): string {
    const fn = this.functions[this.functionOfIndex(this.indexOf(addr))];
    return fn ? label(addr - fn.addr) : `L${addr.toString(16)}`;
  }

  /** The body an instruction is in, and its index in `functions`. */
  bodyOf(index: number): MethodBody | undefined {
    return this.bodies[this.functionOfIndex(index)];
  }

  /** Where an instruction is in the file. */
  fileOffset(index: number): number {
    const body = this.bodyOf(index);
    return body ? body.code + (this.offsets[index]! - (body.rva + body.headerSize)) : -1;
  }

  insn(index: number, into?: CilInsn): CilInsn {
    const body = this.bodyOf(index);
    if (!body) {
      const insn = into ?? new CilInsn();
      insn.op = undefined;
      insn.m = '.byte';
      insn.len = 1;
      return insn;
    }
    return decodeAt(this.md.bytes, body.code, this.fileOffset(index), body.code + body.size, into);
  }

  /** The raw bytes of an instruction's floating-point operand, for printing a NaN as ildasm does. */
  operandBytes(index: number, insn: CilInsn): Uint8Array {
    const end = this.fileOffset(index) + insn.len;
    const size = insn.op?.operand === OPERAND.R4 ? 4 : 8;
    return this.md.bytes.subarray(end - size, end);
  }

  /** What an instruction's operand needs: the names of its method's parameters, its generic parameters. */
  context(index: number): MethodContext {
    const body = this.bodyOf(index);
    return body ? methodContext(this.md, this.names, body.method) : { names: this.names, generic: NO_CONTEXT, instance: false, params: [] };
  }

  /** The function of a MethodDef row, when it has code. */
  methodFunction(row: number): Fn | undefined {
    const at = this.methodFn.get(row);
    return at === undefined ? undefined : this.functions[at];
  }

  /** A method token called, as the function it reaches here or the member of another assembly. */
  callee(tok: number): Fn | undefined {
    const row = tokenRow(tok);
    switch (tokenTable(tok)) {
      case TABLE.MethodDef:
        return this.methodFunction(row);
      case TABLE.MemberRef:
        return this.importByToken.get(tok) ?? this.methodFunction(this.localMethod(row));
      case TABLE.MethodSpec: {
        const target = decodeIndex('MethodDefOrRef', this.md.table(TABLE.MethodSpec).get(row, 'Method'));
        return this.callee(token(target.table, target.row));
      }
    }
    return undefined;
  }

  /** The MethodDef a MemberRef stands for when its class is defined here (a generic one, through a TypeSpec): matched by name and signature. */
  localMethod(memberRef: number): number {
    const cached = this.localCache.get(memberRef);
    if (cached !== undefined) return cached;
    const md = this.md;
    const refs = md.table(TABLE.MemberRef);
    let type = 0;
    const parent = decodeIndex('MemberRefParent', refs.get(memberRef, 'Class'));
    if (parent.table === TABLE.TypeDef) type = parent.row;
    else if (parent.table === TABLE.MethodDef) type = this.names.methodOwner[parent.row] ?? 0;
    else if (parent.table === TABLE.TypeSpec) {
      const blob = md.blob(md.table(TABLE.TypeSpec).get(parent.row, 'Signature'));
      if (blob[0] === 0x15) {
        const [value] = compressed(blob, 2);
        if ((value & 3) === 0) type = value >>> 2;
      }
    }
    let found = 0;
    if (type) {
      const name = md.string(refs.get(memberRef, 'Name'));
      const sig = md.blob(refs.get(memberRef, 'Signature'));
      const methods = md.table(TABLE.MethodDef);
      const [start, end] = md.range(TABLE.TypeDef, type, 'MethodList', TABLE.MethodDef);
      for (let m = start; m < end && !found; m++) {
        if (md.string(methods.get(m, 'Name')) !== name) continue;
        const own = md.blob(methods.get(m, 'Signature'));
        if (own.length === sig.length && own.every((b, k) => b === sig[k])) found = m;
      }
    }
    this.localCache.set(memberRef, found);
    return found;
  }

  private readonly localCache = new Map<number, number>();

  dataAt(addr: number): DataAt {
    const string = this.stringAt.get(addr);
    if (string) return { kind: 'string', text: string.text };
    if (tokenTable(addr) === USER_STRING) {
      const text = this.md.userString(tokenRow(addr));
      if (text !== undefined) return { kind: 'string', text };
    }
    return undefined;
  }

  /** The clauses of the method an instruction is in. */
  clausesOf(index: number): Clause[] {
    return this.bodyOf(index)?.clauses ?? [];
  }
}

/** The context to print a method's operands in: its type and itself for generic names, its parameters. */
export function methodContext(md: Metadata, names: Names, method: number): MethodContext {
  const sig = md.blob(md.table(TABLE.MethodDef).get(method, 'Signature'));
  return { names, generic: { type: names.methodOwner[method] ?? 0, method }, instance: !!(sig[0]! & 0x20), params: names.paramNames(method) };
}

/** The framework the assembly was built for, from its TargetFrameworkAttribute: `.NETCoreApp,Version=v10.0`. */
function targetFramework(md: Metadata, names: Names): string | undefined {
  const attrs = md.table(TABLE.CustomAttribute);
  const refs = md.table(TABLE.MemberRef);
  for (let r = 1; r <= attrs.rows; r++) {
    const parent = decodeIndex('HasCustomAttribute', attrs.get(r, 'Parent'));
    if (parent.table !== TABLE.Assembly) continue;
    const type = decodeIndex('CustomAttributeType', attrs.get(r, 'Type'));
    if (type.table !== TABLE.MemberRef) continue;
    const owner = decodeIndex('MemberRefParent', refs.get(type.row, 'Class'));
    if (owner.table !== TABLE.TypeRef || !names.typeRef(owner.row).endsWith('System.Runtime.Versioning.TargetFrameworkAttribute')) continue;
    const blob = md.blob(attrs.get(r, 'Value'));
    if (blob[0] !== 1 || blob[1] !== 0) continue;
    const [length, size] = compressed(blob, 2);
    return new TextDecoder().decode(blob.subarray(2 + size, 2 + size + length));
  }
  return undefined;
}

/** `.NETCoreApp,Version=v10.0` → `.NET 10.0`; `.NETFramework,Version=v4.8` → `.NET Framework 4.8`. */
export function frameworkLabel(moniker: string): string {
  const version = /Version=v?([\d.]+)/.exec(moniker)?.[1] ?? '';
  if (moniker.startsWith('.NETCoreApp')) return Number(version.split('.')[0]) >= 5 ? `.NET ${version}` : `.NET Core ${version}`;
  if (moniker.startsWith('.NETFramework')) return `.NET Framework ${version}`;
  if (moniker.startsWith('.NETStandard')) return `.NET Standard ${version}`;
  return moniker;
}

/** Bits of the kinds the grouping looks at. */
const KIND = { BARRIER: 1, PURE: 2 } as const;

/** Loads that read nothing but a variable or a constant: `dup` may copy them as text. */
const PURE_LOADS = new Set([
  'ldarg.0', 'ldarg.1', 'ldarg.2', 'ldarg.3', 'ldarg.s', 'ldarg', 'ldloc.0', 'ldloc.1', 'ldloc.2', 'ldloc.3', 'ldloc.s', 'ldloc', 'ldnull', 'ldstr',
  'ldc.i4.m1', 'ldc.i4.0', 'ldc.i4.1', 'ldc.i4.2', 'ldc.i4.3', 'ldc.i4.4', 'ldc.i4.5', 'ldc.i4.6', 'ldc.i4.7', 'ldc.i4.8', 'ldc.i4.s', 'ldc.i4', 'ldc.i8', 'ldc.r4', 'ldc.r8',
]);

/** A value on the stack while the statements are grouped: the instructions that made it. */
interface Node {
  start: number;
  end: number;
  /** It can be written as an expression inside the instruction that takes it. */
  ok: boolean;
  /** Its instructions start with a dup: the line must also take the value the dup copied, right below it. */
  copy?: boolean;
}

/**
 * Marks the runs of instructions that make one statement of the HLA64 view, the way the
 * WebAssembly analysis does: an instruction that takes values made right before it, one after
 * another, each an expression, joins them into its line; when it leaves nothing on the stack the
 * line is a statement. A value does not cross a label or the start of a handler (another path
 * may reach it), a branch, a prefix or an instruction that cannot be decoded; `dup` copies only a
 * variable or a constant, which can be written twice. src/core/cil/hla.ts writes the lines and
 * must agree with this on what makes one.
 */
function groupStatements(program: CilProgram, flags: Uint8Array, first: number, end: number, pops: Int16Array, pushes: Int8Array, kinds: Uint8Array): void {
  const nodes: Node[] = [];
  const folds = (count: number, at: number): boolean => {
    if (count > nodes.length) return false;
    let expected = at;
    for (let j = nodes.length - 1; j >= nodes.length - count; j--) {
      const node = nodes[j]!;
      if (!node.ok || node.end !== expected - 1) return false;
      expected = node.start;
    }
    return true;
  };
  for (let i = first; i < end; i++) {
    if (i === first || flags[i]! & IF.LABEL) {
      nodes.length = 0;
      // A catch or filter starts with the exception on the stack: a value no line can name.
      for (const { clause, part } of program.regions.get(i) ?? []) if ((part === 'handler' && !(clause.kind & 6)) || part === 'filter') nodes.push({ start: -2, end: -2, ok: false });
    }
    const popped = pops[i]!;
    const pushed = pushes[i]!;
    if (pushed < 0 || kinds[i]! & KIND.BARRIER && pushed > 0) {
      nodes.length = 0;
      continue;
    }
    const fold = folds(popped, i);
    const start = fold && popped ? nodes[nodes.length - popped]!.start : i;
    const copy = fold && popped ? !!nodes[nodes.length - popped]!.copy : false;
    if (pushed === 2) {
      // dup: the copy is the dup itself, and both are values only when a variable or a constant is copied.
      const source = nodes[nodes.length - 1];
      const pure = !!source && source.ok && source.start === source.end && source.end === i - 1 && !!(kinds[source.start]! & KIND.PURE);
      if (!source) {
        nodes.length = 0;
        continue;
      }
      source.ok = pure;
      nodes.push({ start: i, end: i, ok: pure, copy: true });
      continue;
    }
    if (popped > nodes.length) nodes.length = 0;
    else nodes.length -= popped;
    if (pushed === 0) {
      // A line that takes a dup's copy without the value it copied would need that value from before it.
      if (fold && popped && !copy) for (let k = start; k < i; k++) flags[k]! |= IF.FUSE;
    } else nodes.push({ start, end: i, ok: fold || popped === 0, copy });
    if (kinds[i]! & KIND.BARRIER) nodes.length = 0;
  }
}

/** The members of other assemblies the code may use: every MemberRef whose class is not defined here. */
function collectImports(program: CilProgram): void {
  const md = program.md;
  const names = program.names;
  const refs = md.table(TABLE.MemberRef);
  for (let r = 1; r <= refs.rows; r++) {
    const parent = decodeIndex('MemberRefParent', refs.get(r, 'Class'));
    let typeRef = 0;
    let typeText = '';
    if (parent.table === TABLE.TypeRef) {
      typeRef = parent.row;
      typeText = names.typeRef(parent.row);
    } else if (parent.table === TABLE.TypeSpec) {
      if (program.localMethod(r)) continue;
      const blob = md.blob(md.table(TABLE.TypeSpec).get(parent.row, 'Signature'));
      if (blob[0] === 0x15) {
        const [value] = compressed(blob, 2);
        if ((value & 3) === 1) typeRef = value >>> 2;
        else continue;
      } else if (blob[0] === 0x14 || blob[0] === 0x1d) {
        typeText = names.typeSpec(parent.row, NO_CONTEXT);
      } else continue;
      if (typeRef) typeText = names.typeSpec(parent.row, NO_CONTEXT);
    } else if (parent.table === TABLE.ModuleRef) {
      typeText = `[.module ${md.string(md.table(TABLE.ModuleRef).get(parent.row, 'Name'))}]`;
    } else continue;
    const tok = token(TABLE.MemberRef, r);
    const field = names.isFieldRef(r);
    const name = md.string(refs.get(r, 'Name'));
    const assembly = typeRef ? names.typeRefAssembly(typeRef) : '';
    const full = field ? names.field(tok) : names.method(tok);
    const owner = typeRef ? names.typeRef(typeRef).replace(/^\[[^\]]*\]/, '') : typeText;
    const member: ImportedMember = { addr: tok, first: -1, count: 0, name: `${owner}::${name}`, full, raw: name, kind: 'import', token: tok, assembly, type: typeText, field };
    program.imported.push(member);
    program.importByToken.set(tok, member);
  }
  // P/Invoke: methods whose code is in a native library.
  const maps = md.table(TABLE.ImplMap);
  for (let r = 1; r <= maps.rows; r++) {
    const member = decodeIndex('MemberForwarded', maps.get(r, 'MemberForwarded'));
    if (member.table !== TABLE.MethodDef) continue;
    const owner = names.methodOwner[member.row] ?? 0;
    program.pinvokes.push({
      method: member.row,
      name: `${owner > 1 ? `${names.typeDef(owner)}::` : ''}${properName(md.string(md.table(TABLE.MethodDef).get(member.row, 'Name')))}`,
      library: md.string(md.table(TABLE.ModuleRef).get(maps.get(r, 'ImportScope'), 'Name')),
      entry: md.string(maps.get(r, 'ImportName')),
      flags: maps.get(r, 'MappingFlags'),
    });
  }
}

/** Is a type visible outside the assembly: public, and nested only in public types? */
function visible(md: Metadata, names: Names, type: number): boolean {
  const types = md.table(TABLE.TypeDef);
  for (let k = 0; k < 32 && type; k++) {
    const vis = types.get(type, 'Flags') & 7;
    const outer = names.enclosing.get(type);
    if (outer === undefined) return vis === 1;
    if (vis !== 2 && vis !== 4 && vis !== 7) return false;
    type = outer;
  }
  return false;
}

export async function analyzeCil(pe: Pe, progress: Progress = () => {}): Promise<CilProgram> {
  const started = Date.now();
  const md = readMetadata(pe);
  const program = new CilProgram(pe, md);
  const names = program.names;
  collectImports(program);

  // Every method with a body, in the order of the file.
  const methods = md.table(TABLE.MethodDef);
  const bodies: MethodBody[] = [];
  const seen = new Set<number>();
  for (let m = 1; m <= methods.rows; m++) {
    const body = md.body(m);
    if (!body || !body.size || seen.has(body.rva)) continue;
    seen.add(body.rva);
    bodies.push(body);
  }
  bodies.sort((a, b) => a.rva - b.rva);
  let capacity = 0;
  for (const body of bodies) capacity += body.size;
  const offsets = new Uint32Array(capacity);
  const ids = new Uint16Array(capacity);
  const flags = new Uint8Array(capacity);
  const mnemonicIds = new Map<string, number>();
  const counts: number[] = [];
  const insn = new CilInsn();
  // What each instruction does to the stack, for grouping the statements of the HLA64 view: -1 pushes when it cannot be known.
  const pops = new Int16Array(capacity);
  const pushes = new Int8Array(capacity);
  const kinds = new Uint8Array(capacity);
  const effects = new Effects(md);
  const CHUNK = 65536;
  let total = 0;
  let nextTick = CHUNK;
  let lastType = -1;

  // Functions first, so calls can be counted against their addresses.
  bodies.forEach((body) => {
    const m = body.method;
    const owner = names.methodOwner[m] ?? 0;
    const name = properName(md.string(methods.get(m, 'Name')));
    const typeName = owner > 1 ? names.typeDef(owner) : '';
    const sig = names.methodDefSig(m);
    const flagsOf = methods.get(m, 'Flags');
    const kind: Fn['kind'] = m === program.entryMethod ? 'entry' : (flagsOf & 7) === 6 && owner && visible(md, names, owner) ? 'export' : 'symbol';
    const generics = names.genericParams('m', m);
    const shown = `${typeName ? `${typeName}::` : ''}${name}${generics.length ? `<${generics.map(properName).join(',')}>` : ''}`;
    const fn: Fn = { addr: body.rva + body.headerSize, first: 0, count: 0, name: shown, full: `${sig.ret} ${shown}(${paramsText(sig, ', ')})`, raw: md.string(methods.get(m, 'Name')), kind, index: m };
    program.methodFn.set(m, program.functions.length);
    program.functions.push(fn);
    program.bodies.push(body);
  });

  for (let f = 0; f < bodies.length; f++) {
    const body = bodies[f]!;
    const fn = program.functions[f]!;
    const first = total;
    const codeRva = fn.addr;
    const end = body.code + body.size;
    // Branch targets inside the method, by IL offset, resolved once its instructions are known.
    const pending: [number, number, number][] = [];
    const at = new Map<number, number>();
    effects.returns = shapeOf(md.blob(methods.get(body.method, 'Signature'))).returns;
    for (let pos = body.code; pos < end && total < capacity; ) {
      const i = total++;
      if (i >= nextTick) {
        nextTick += CHUNK;
        progress('decode', f, bodies.length);
        await tick();
      }
      decodeAt(md.bytes, body.code, pos, end, insn);
      offsets[i] = codeRva + insn.at;
      at.set(insn.at, i);
      let id = mnemonicIds.get(insn.m);
      if (id === undefined) {
        id = program.mnemonics.length;
        mnemonicIds.set(insn.m, id);
        program.mnemonics.push(insn.m);
        counts.push(0);
      }
      ids[i] = id;
      counts[id]!++;
      pos += insn.len;
      const op = insn.op;
      const eff = effects.of(insn);
      pops[i] = eff ? eff[0] : 0;
      pushes[i] = eff ? eff[1] : -1;
      kinds[i] = !op ? 0 : (op.flags & (F.END | F.BRANCH | F.PREFIX) ? KIND.BARRIER : 0) | (PURE_LOADS.has(op.name) ? KIND.PURE : 0);
      if (!op) {
        flags[i]! |= IF.UNKNOWN;
        continue;
      }
      if (op.flags & F.BRANCH) {
        flags[i]! |= IF.BRANCH;
        if (insn.targets) insn.targets.forEach((target, slot) => pending.push([i, target, slot]));
        else pending.push([i, insn.a, -1]);
      }
      if (op.flags & F.CALL) {
        flags[i]! |= IF.CALL;
        if (op.operand === OPERAND.METHOD) {
          const callee = program.callee(insn.a);
          if (callee) append(program.callers, callee.addr, offsets[i]!);
          if (op.name === 'callvirt' && callee?.raw === 'Invoke') program.indirectCalls++;
        } else program.indirectCalls++;
      } else if (op.operand === OPERAND.METHOD) {
        // ldftn, ldvirtftn: the method is taken, not called.
        const callee = program.callee(insn.a);
        if (callee) append(program.dataRefs, callee.addr, offsets[i]!);
      }
      switch (op.operand) {
        case OPERAND.STRING:
          append(program.dataRefs, insn.a, offsets[i]!);
          break;
        case OPERAND.FIELD:
          append(program.fieldRefs, insn.a, offsets[i]!);
          break;
        case OPERAND.TYPE:
          append(program.typeRefs, insn.a, offsets[i]!);
          break;
        case OPERAND.TOKEN:
          if (tokenTable(insn.a) === TABLE.Field || tokenTable(insn.a) === TABLE.MemberRef) append(program.fieldRefs, insn.a, offsets[i]!);
          else append(program.typeRefs, insn.a, offsets[i]!);
          break;
      }
    }
    for (const [from, target, slot] of pending) {
      const to = at.get(target);
      if (to === undefined) continue;
      flags[to]! |= IF.LABEL;
      const known = program.targets.get(from);
      if (slot >= 0) {
        if (Array.isArray(known)) known.push(to);
        else program.targets.set(from, [to]);
      } else program.targets.set(from, to);
    }
    for (const clause of body.clauses) {
      const mark = (offset: number, part: 'try' | 'handler' | 'filter') => {
        const index = at.get(offset);
        if (index === undefined) return;
        flags[index]! |= IF.LABEL;
        append(program.regions, index, { clause, part });
      };
      mark(clause.tryStart, 'try');
      if (clause.kind & 1) mark(clause.filterStart, 'filter');
      mark(clause.handlerStart, 'handler');
    }
    fn.first = first;
    fn.count = total - first;
    groupStatements(program, flags, first, total, pops, pushes, kinds);
    flags[first]! |= IF.FUNCTION;
    flags[first]! &= ~IF.LABEL;
    program.functionAtIndex.set(first, f);
    // The functions of one type make one range of the listing.
    const owner = names.methodOwner[body.method] ?? 0;
    if (owner !== lastType) {
      lastType = owner;
      program.ranges.push({ name: owner > 1 ? `.class ${names.typeDef(owner)}` : t('listing', 'global functions'), first, count: 0 });
    }
    program.ranges[program.ranges.length - 1]!.count += fn.count;
  }

  program.offsets = offsets.slice(0, total);
  program.mnemonicIds = ids.slice(0, total);
  program.flags = flags.slice(0, total);
  program.totalInstructions = total;
  program.decodeMs = Date.now() - started;
  program.tally(counts);
  progress('decode', 1, 1);

  // The strings: every one of #US, in the order of the heap.
  progress('functions', 0, 1);
  await tick();
  for (const { index, text } of md.userStrings()) {
    const ref: StringRef = { addr: token(USER_STRING, index), text, section: '#US', kind: 'const' };
    program.strings.push(ref);
    program.stringAt.set(ref.addr, ref);
  }
  progress('done', 1, 1);
  return program;
}

/** The function the page opens at: the entry point, else the first public method, else the first. */
export function entryOf(program: CilProgram): Fn | undefined {
  return program.methodFunction(program.entryMethod) ?? program.functions.find((f) => f.kind === 'export') ?? program.functions[0];
}
