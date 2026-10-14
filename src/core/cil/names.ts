/**
 * Names and signatures of a .NET assembly written as ildasm writes them, so
 * the listing can be checked against it line by line: `[System.Runtime]System.String`
 * for a type another assembly defines, `Outer/Inner` for a nested one,
 * `class …<int32,string>` for a generic instance, `instance void
 * Owner::Name(int32, string)` for a method. A name that is not an ILAsm
 * identifier, or is one of its keywords, is quoted: `'<>c'`, `'value'`.
 *
 * The rules are ildasm's own (src/coreclr/ildasm and inc/formattype.cpp of
 * dotnet/runtime), quirks included:
 *
 * - a generic parameter is named (`!T`, `!!T`) by the class and the method
 *   being disassembled, if they have one with that number and the name is not
 *   taken twice; a member of a generic instance (`List`1<int32>::Add`) forgets
 *   the class's names for its own signature, a MethodSpec the method's;
 * - a method's parameters are broken onto new lines at the commas outside
 *   brackets, counted from the start of the current line — which the listing
 *   writes as `, ` — and joined with a bare `,` where ildasm keeps them on one
 *   line: inside a function pointer, after one, and after a name with an
 *   escaped quote in it, which throws its count of quotes off.
 */

import { compressed, decodeIndex, Metadata, TABLE, tokenRow, tokenTable } from './metadata';

/** Where a signature is read: the class and method whose generic parameters it may name (rows; 0 for none). */
export interface GenericContext {
  type: number;
  method: number;
}

export const NO_CONTEXT: GenericContext = { type: 0, method: 0 };

/** The words of ILAsm (its opcodes, their aliases, and il_kywd.h), which a name must not be written as unquoted. */
const KEYWORDS = new Set([
  '#define', '#else', '#endif', '#ifdef', '#ifndef', '#include', '#line', '#undef', 'abstract', 'add', 'add.ovf', 'add.ovf.un',
  'aggressiveinlining', 'aggressiveoptimization', 'algorithm', 'alignment', 'amd64', 'and', 'ansi', 'any', 'arglist', 'arm', 'arm64',
  'array', 'as', 'assembly', 'assert', 'async', 'at', 'auto', 'autochar', 'beforefieldinit', 'beq', 'beq.s', 'bestfit', 'bge', 'bge.s',
  'bge.un', 'bge.un.s', 'bgt', 'bgt.s', 'bgt.un', 'bgt.un.s', 'ble', 'ble.s', 'ble.un', 'ble.un.s', 'blob', 'blob_object', 'blt', 'blt.s',
  'blt.un', 'blt.un.s', 'bne.un', 'bne.un.s', 'bool', 'box', 'br', 'br.s', 'break', 'brfalse', 'brfalse.s', 'brinst', 'brinst.s', 'brnull',
  'brnull.s', 'brtrue', 'brtrue.s', 'brzero', 'brzero.s', 'bstr', 'byreflike', 'bytearray', 'byvalstr', 'call', 'callconv', 'calli',
  'callmostderived', 'callvirt', 'carray', 'castclass', 'catch', 'cdecl', 'ceq', 'cf', 'cgt', 'cgt.un', 'char', 'charmaperror', 'cil',
  'ckfinite', 'class', 'clsid', 'clt', 'clt.un', 'codelabel', 'constrained.', 'constraint', 'conv.i', 'conv.i1', 'conv.i2', 'conv.i4',
  'conv.i8', 'conv.ovf.i', 'conv.ovf.i.un', 'conv.ovf.i1', 'conv.ovf.i1.un', 'conv.ovf.i2', 'conv.ovf.i2.un', 'conv.ovf.i4',
  'conv.ovf.i4.un', 'conv.ovf.i8', 'conv.ovf.i8.un', 'conv.ovf.u', 'conv.ovf.u.un', 'conv.ovf.u1', 'conv.ovf.u1.un', 'conv.ovf.u2',
  'conv.ovf.u2.un', 'conv.ovf.u4', 'conv.ovf.u4.un', 'conv.ovf.u8', 'conv.ovf.u8.un', 'conv.r.un', 'conv.r4', 'conv.r8', 'conv.u', 'conv.u1',
  'conv.u2', 'conv.u4', 'conv.u8', 'cpblk', 'cpobj', 'currency', 'custom', 'date', 'decimal', 'default', 'demand', 'deny', 'div', 'div.un',
  'dup', 'endfault', 'endfilter', 'endfinally', 'endmac', 'enum', 'error', 'explicit', 'extends', 'extern', 'false', 'famandassem', 'family',
  'famorassem', 'fastcall', 'fault', 'field', 'filetime', 'filter', 'final', 'finally', 'fixed', 'flags', 'float', 'float32', 'float64',
  'forwarder', 'forwardref', 'fromunmanaged', 'handler', 'hidebysig', 'hresult', 'idispatch', 'iidparam', 'il', 'illegal', 'implements',
  'import', 'in', 'inheritcheck', 'init', 'initblk', 'initobj', 'initonly', 'instance', 'int', 'int16', 'int32', 'int64', 'int8',
  'interface', 'internalcall', 'isinst', 'iunknown', 'jmp', 'lasterr', 'ldarg', 'ldarg.0', 'ldarg.1', 'ldarg.2', 'ldarg.3', 'ldarg.s',
  'ldarga', 'ldarga.s', 'ldc.i4', 'ldc.i4.0', 'ldc.i4.1', 'ldc.i4.2', 'ldc.i4.3', 'ldc.i4.4', 'ldc.i4.5', 'ldc.i4.6', 'ldc.i4.7', 'ldc.i4.8',
  'ldc.i4.M1', 'ldc.i4.m1', 'ldc.i4.s', 'ldc.i8', 'ldc.r4', 'ldc.r8', 'ldelem', 'ldelem.any', 'ldelem.i', 'ldelem.i1', 'ldelem.i2',
  'ldelem.i4', 'ldelem.i8', 'ldelem.r4', 'ldelem.r8', 'ldelem.ref', 'ldelem.u1', 'ldelem.u2', 'ldelem.u4', 'ldelem.u8', 'ldelema', 'ldfld',
  'ldflda', 'ldftn', 'ldind.i', 'ldind.i1', 'ldind.i2', 'ldind.i4', 'ldind.i8', 'ldind.r4', 'ldind.r8', 'ldind.ref', 'ldind.u1', 'ldind.u2',
  'ldind.u4', 'ldind.u8', 'ldlen', 'ldloc', 'ldloc.0', 'ldloc.1', 'ldloc.2', 'ldloc.3', 'ldloc.s', 'ldloca', 'ldloca.s', 'ldnull', 'ldobj',
  'ldsfld', 'ldsflda', 'ldstr', 'ldtoken', 'ldvirtftn', 'leave', 'leave.s', 'legacy', 'library', 'linkcheck', 'literal', 'localloc', 'lpstr',
  'lpstruct', 'lptstr', 'lpvoid', 'lpwstr', 'managed', 'marshal', 'mdtoken', 'method', 'mkrefany', 'modopt', 'modreq', 'mul', 'mul.ovf',
  'mul.ovf.un', 'native', 'neg', 'nested', 'newarr', 'newobj', 'newslot', 'noinlining', 'nomangle', 'nometadata', 'noncasdemand',
  'noncasinheritance', 'noncaslinkdemand', 'nooptimization', 'nop', 'noplatform', 'not', 'notserialized', 'null', 'nullref', 'object',
  'objectref', 'off', 'on', 'opt', 'optil', 'or', 'out', 'permitonly', 'pinned', 'pinvokeimpl', 'pop', 'prefix1', 'prefix2', 'prefix3',
  'prefix4', 'prefix5', 'prefix6', 'prefix7', 'prefixref', 'prejitdeny', 'prejitgrant', 'preservesig', 'private', 'privatescope', 'property',
  'public', 'readonly.', 'record', 'refany', 'refanytype', 'refanyval', 'rem', 'rem.un', 'reqmin', 'reqopt', 'reqrefuse', 'reqsecobj',
  'request', 'ret', 'retainappdomain', 'retargetable', 'rethrow', 'rtspecialname', 'runtime', 'safearray', 'sealed', 'sequential',
  'serializable', 'shl', 'shr', 'shr.un', 'sizeof', 'specialname', 'starg', 'starg.s', 'static', 'stdcall', 'stelem', 'stelem.any',
  'stelem.i', 'stelem.i1', 'stelem.i2', 'stelem.i4', 'stelem.i8', 'stelem.r4', 'stelem.r8', 'stelem.ref', 'stfld', 'stind.i', 'stind.i1',
  'stind.i2', 'stind.i4', 'stind.i8', 'stind.r4', 'stind.r8', 'stind.ref', 'stloc', 'stloc.0', 'stloc.1', 'stloc.2', 'stloc.3', 'stloc.s',
  'stobj', 'storage', 'stored_object', 'stream', 'streamed_object', 'strict', 'string', 'struct', 'stsfld', 'sub', 'sub.ovf', 'sub.ovf.un',
  'switch', 'synchronized', 'syschar', 'sysstring', 'tail.', 'tbstr', 'thiscall', 'throw', 'tls', 'to', 'true', 'type', 'typedref', 'uint',
  'uint16', 'uint32', 'uint64', 'uint8', 'unaligned.', 'unbox', 'unbox.any', 'unicode', 'unmanaged', 'unmanagedexp', 'unsigned', 'unused',
  'userdefined', 'value', 'valuetype', 'vararg', 'variant', 'vector', 'virtual', 'void', 'volatile.', 'wchar', 'winapi', 'windowsruntime',
  'with', 'x86', 'xor',
]);

const LETTER = (c: number) => (c >= 65 && c <= 90) || (c >= 97 && c <= 122);
/** A name may start with a letter or one of `#_@$.`, and go on with those (but `#`), digits, `?` and `` ` ``. */
const START = (c: number) => LETTER(c) || c === 35 || c === 95 || c === 64 || c === 36 || c === 46;
const CONTINUE = (c: number) => LETTER(c) || (c >= 48 && c <= 57) || c === 95 || c === 64 || c === 36 || c === 46 || c === 63 || c === 96;

/** Does a name need quotes to be read back by ILAsm (ildasm's IsNameToQuote)? */
export function needsQuotes(name: string): boolean {
  if (!name) return true;
  let starting = true;
  for (let k = 0; k < name.length; k++) {
    const c = name.charCodeAt(k);
    if (starting ? !START(c) : !CONTINUE(c)) return true;
    starting = c === 46;
    if (starting && name.charCodeAt(k + 1) === 46) return true;
  }
  if (name === '.ctor' || name === '.cctor') return false;
  return KEYWORDS.has(name) || name.startsWith('.') || name.endsWith('.');
}

const NAME_ESCAPES: Record<string, string> = { '\t': '\\t', '\n': '\\n', '\b': '\\b', '\r': '\\r', '\f': '\\f', '\v': '\\v', '\x07': '\\a', '\\': '\\\\', "'": "\\'", '"': '\\"' };
const escapeName = (name: string) => name.replace(/[\t\n\b\r\f\v\x07\\'"]/g, (c) => NAME_ESCAPES[c]!);

/** A name as ildasm writes it: escaped, and quoted when it must be. An empty name is written as nothing. */
export function properName(name: string): string {
  if (!name) return '';
  return needsQuotes(name) ? `'${escapeName(name)}'` : escapeName(name);
}

/** A parameter's or a local's name: quoted also when it has a dot after its first character. */
export function properLocalName(name: string): string {
  if (!name) return '';
  return needsQuotes(name) || name.indexOf('.', 1) > 0 ? `'${escapeName(name)}'` : escapeName(name);
}

const PRIMITIVES: Record<number, string> = {
  0x01: 'void', 0x02: 'bool', 0x03: 'char', 0x04: 'int8', 0x05: 'uint8', 0x06: 'int16', 0x07: 'uint16', 0x08: 'int32', 0x09: 'uint32',
  0x0a: 'int64', 0x0b: 'uint64', 0x0c: 'float32', 0x0d: 'float64', 0x0e: 'string', 0x16: 'typedref', 0x18: 'native int', 0x19: 'native uint', 0x1c: 'object',
};

/** A cursor over a signature blob. */
export class SigReader {
  pos = 0;
  constructor(readonly bytes: Uint8Array) {}
  get done(): boolean {
    return this.pos >= this.bytes.length;
  }
  byte(): number {
    return this.bytes[this.pos++] ?? 0;
  }
  peek(): number {
    return this.bytes[this.pos] ?? 0;
  }
  /** The next byte even past the end of the blob, in the heap that holds it (0 past the file). */
  peekPast(): number {
    if (this.pos < this.bytes.length) return this.bytes[this.pos]!;
    const at = this.bytes.byteOffset + this.pos;
    return at < this.bytes.buffer.byteLength ? new Uint8Array(this.bytes.buffer, at, 1)[0]! : 0;
  }
  u(): number {
    const [value, size] = compressed(this.bytes, this.pos);
    this.pos += size;
    return value;
  }
  /** A signed compressed integer (II.23.2): the sign is the lowest bit, rotated. */
  s(): number {
    const first = this.peek();
    const [value, size] = compressed(this.bytes, this.pos);
    this.pos += size;
    const bits = (first & 0x80) === 0 ? 7 : (first & 0xc0) === 0x80 ? 14 : 29;
    return value & 1 ? (value >>> 1) - 2 ** (bits - 1) : value >>> 1;
  }
}

/** A method signature as it is in the blob. */
export interface MethodSig {
  conv: number;
  generics: number;
  ret: string;
  params: string[];
  /** Where a vararg call site's extra arguments start: the index of the `...` in `params`; -1 if none. */
  sentinel: number;
}

/** The calling convention as ildasm writes it before the return type. */
export function convText(conv: number): string {
  let out = '';
  if (conv & 0x40) out += 'explicit ';
  if (conv & 0x20) out += 'instance ';
  const kind = conv & 0x0f;
  out += ['', 'unmanaged cdecl ', 'unmanaged stdcall ', 'unmanaged thiscall ', 'unmanaged fastcall ', 'vararg '][kind] ?? (kind === 9 ? 'unmanaged ' : `callconv(${kind}) `);
  return out;
}

/** The parameters of a signature joined as ildasm joins them (`...` is the sentinel of a vararg call site). */
export function paramsText(sig: MethodSig, comma = ','): string {
  return sig.params.join(comma);
}

/**
 * ildasm's SplitSignatureByCommas: from `start` (just inside the parameter list), every comma with
 * no bracket, quote, parenthesis (beyond the list's own) or angle bracket open since the start of
 * its line starts a new line. The counters are unsigned: one that goes below zero stays off.
 * A comma that breaks the line is written `, `, one that does not `,`.
 */
export function splitCommas(text: string, start: number): string {
  if (start >= text.length) return text;
  let out = '';
  let lineStart = 0;
  let from = 0;
  let pos = text.indexOf(',', start);
  while (pos >= 0) {
    let brackets = 0;
    let quote = 0;
    let parens = 0;
    let angles = 0;
    for (let k = lineStart; k < pos; k++) {
      const c = text[k];
      if (c === "'") quote = 1 - quote;
      else if (!quote) {
        if (c === '[') brackets++;
        else if (c === ']') brackets--;
        else if (c === '(') parens++;
        else if (c === ')') parens--;
        else if (c === '<') angles++;
        else if (c === '>') angles--;
      }
    }
    if (brackets === 0 && quote === 0 && parens >= 0 && parens <= 1 && angles === 0) {
      out += `${text.slice(from, pos)}, `;
      from = pos + 1;
      lineStart = pos + 1;
    }
    pos = text.indexOf(',', pos + 1);
  }
  return out + text.slice(from);
}

export class Names {
  /** TypeDef row → the TypeDef it is nested in. */
  readonly enclosing = new Map<number, number>();
  /** MethodDef row → its TypeDef row; Field row → its TypeDef row. */
  readonly methodOwner: Uint32Array;
  readonly fieldOwner: Uint32Array;
  /** Generic parameter names, by owner (`t` + TypeDef row, `m` + MethodDef row). */
  private readonly generic = new Map<string, string[]>();
  private readonly typeDefCache = new Map<number, string>();
  private readonly typeRefCache = new Map<number, string>();

  constructor(readonly md: Metadata) {
    const nested = md.table(TABLE.NestedClass);
    for (let r = 1; r <= nested.rows; r++) this.enclosing.set(nested.get(r, 'NestedClass'), nested.get(r, 'EnclosingClass'));
    this.methodOwner = this.owners(TABLE.MethodDef, 'MethodList', TABLE.MethodPtr, 'Method');
    this.fieldOwner = this.owners(TABLE.Field, 'FieldList', TABLE.FieldPtr, 'Field');
    const gp = md.table(TABLE.GenericParam);
    for (let r = 1; r <= gp.rows; r++) {
      const owner = decodeIndex('TypeOrMethodDef', gp.get(r, 'Owner'));
      const key = `${owner.table === TABLE.TypeDef ? 't' : 'm'}${owner.row}`;
      const list = this.generic.get(key) ?? [];
      list[gp.get(r, 'Number')] = md.string(gp.get(r, 'Name'));
      this.generic.set(key, list);
    }
  }

  /** Which TypeDef each row of a member table belongs to, from the TypeDefs' lists (through the pointer table when there is one). */
  private owners(table: number, column: string, pointer: number, pointerColumn: string): Uint32Array {
    const md = this.md;
    const out = new Uint32Array(md.rows(table) + 1);
    const types = md.table(TABLE.TypeDef);
    const ptr = md.rows(pointer) ? md.table(pointer) : undefined;
    const listEnd = ptr ? ptr.rows + 1 : md.rows(table) + 1;
    const lists = types.col(column);
    for (let t = 1; t <= types.rows; t++) {
      const start = lists[t - 1]!;
      const end = t < types.rows ? lists[t]! : listEnd;
      for (let k = start; k < end && k < listEnd; k++) {
        const row = ptr ? ptr.get(k, pointerColumn) : k;
        if (row > 0 && row < out.length) out[row] = t;
      }
    }
    return out;
  }

  /** The generic parameters of a type or a method (by row). */
  genericParams(kind: 't' | 'm', row: number): string[] {
    return this.generic.get(`${kind}${row}`) ?? [];
  }

  /* ---------------------------------------------------------------- *
   * Types
   * ---------------------------------------------------------------- */

  /** A type this assembly defines: `Ns.Name`, `Ns.Outer/Inner`. */
  typeDef(row: number, depth = 0): string {
    const cached = this.typeDefCache.get(row);
    if (cached !== undefined) return cached;
    const t = this.md.table(TABLE.TypeDef);
    const ns = this.md.string(t.get(row, 'Namespace'));
    const name = this.md.string(t.get(row, 'Name')) || `$TD$${row.toString(16).toUpperCase()}`;
    let text = `${ns ? `${properName(ns)}.` : ''}${properName(name)}`;
    const outer = this.enclosing.get(row);
    if (outer && outer !== row && depth < 64) text = `${this.typeDef(outer, depth + 1)}/${text}`;
    this.typeDefCache.set(row, text);
    return text;
  }

  /** A type another assembly or module defines: `[System.Runtime]System.Object`. */
  typeRef(row: number, depth = 0): string {
    const cached = this.typeRefCache.get(row);
    if (cached !== undefined) return cached;
    const md = this.md;
    const t = md.table(TABLE.TypeRef);
    const ns = md.string(t.get(row, 'Namespace'));
    const name = md.string(t.get(row, 'Name')) || `$TR$${row.toString(16).toUpperCase()}`;
    const coded = t.get(row, 'ResolutionScope');
    const scope = decodeIndex('ResolutionScope', coded);
    let prefix = '';
    if (!coded) prefix = '[*]';
    else if (scope.row) {
      if (scope.table === TABLE.TypeRef) prefix = depth < 64 ? `${this.typeRef(scope.row, depth + 1)}/` : '';
      else if (scope.table === TABLE.AssemblyRef) {
        const assembly = md.string(md.table(TABLE.AssemblyRef).get(scope.row, 'Name'));
        prefix = assembly ? `[${properName(assembly)}]` : '';
      } else if (scope.table === TABLE.ModuleRef) {
        const module = md.string(md.table(TABLE.ModuleRef).get(scope.row, 'Name'));
        prefix = module ? `[.module ${properName(module)}]` : '';
      }
    }
    const text = `${prefix}${ns ? `${properName(ns)}.` : ''}${properName(name)}`;
    this.typeRefCache.set(row, text);
    return text;
  }

  /** The assembly a TypeRef comes from (following nesting), or '' for this one. */
  typeRefAssembly(row: number): string {
    const t = this.md.table(TABLE.TypeRef);
    for (let k = 0; k < 32 && row; k++) {
      const scope = decodeIndex('ResolutionScope', t.get(row, 'ResolutionScope'));
      if (scope.table === TABLE.AssemblyRef) return this.md.string(this.md.table(TABLE.AssemblyRef).get(scope.row, 'Name'));
      if (scope.table === TABLE.ModuleRef) return this.md.string(this.md.table(TABLE.ModuleRef).get(scope.row, 'Name'));
      if (scope.table !== TABLE.TypeRef) return '';
      row = scope.row;
    }
    return '';
  }

  /** A TypeDef, TypeRef or TypeSpec token as an operand: a class name, or the type a TypeSpec spells out. */
  type(tok: number, ctx: GenericContext = NO_CONTEXT): string {
    const row = tokenRow(tok);
    switch (tokenTable(tok)) {
      case TABLE.TypeDef: return this.typeDef(row);
      case TABLE.TypeRef: return this.typeRef(row);
      case TABLE.TypeSpec: return this.typeSpec(row, ctx);
    }
    return `[unknown token 0x${tok.toString(16)}]`;
  }

  typeSpec(row: number, ctx: GenericContext): string {
    return this.sigType(new SigReader(this.md.blob(this.md.table(TABLE.TypeSpec).get(row, 'Signature'))), ctx);
  }

  /** Is a TypeSpec a generic instance (through pointers, arrays and references)? ildasm's IsGenericInst. */
  isGenericInst(row: number): boolean {
    for (const b of this.md.blob(this.md.table(TABLE.TypeSpec).get(row, 'Signature'))) {
      if (b === 0x0f || b === 0x1d || b === 0x14 || b === 0x10) continue;
      return b === 0x15;
    }
    return false;
  }

  /** A TypeDefOrRefOrSpecEncoded token in a signature. */
  private encodedType(r: SigReader, ctx: GenericContext, depth: number): string {
    const value = r.u();
    const table = [TABLE.TypeDef, TABLE.TypeRef, TABLE.TypeSpec][value & 3];
    const row = value >>> 2;
    if (table === TABLE.TypeDef) return this.typeDef(row);
    if (table === TABLE.TypeRef) return this.typeRef(row);
    if (table === TABLE.TypeSpec && depth < 32) return this.sigType(new SigReader(this.md.blob(this.md.table(TABLE.TypeSpec).get(row, 'Signature'))), ctx, depth + 1);
    return '?';
  }

  /** `T` for generic parameter `number` of the owner, unless the owner has no such parameter or two of that name (ildasm's PrettyPrintGP). */
  private genericName(kind: 't' | 'm', number: number, ctx: GenericContext): string {
    const owner = kind === 't' ? ctx.type : ctx.method;
    if (owner) {
      const names = this.genericParams(kind, owner);
      const name = names[number];
      if (name !== undefined && names.indexOf(name) === number && names.lastIndexOf(name) === number) return properName(name);
    }
    return String(number);
  }

  /** A type in a signature (II.23.2.12), as ildasm prints it. */
  sigType(r: SigReader, ctx: GenericContext, depth = 0): string {
    if (depth > 64 || r.done) return '?';
    const et = r.byte();
    const primitive = PRIMITIVES[et];
    if (primitive) return primitive;
    switch (et) {
      case 0x0f: return `${this.sigType(r, ctx, depth + 1)}*`;
      case 0x10: return `${this.sigType(r, ctx, depth + 1)}&`;
      case 0x11: return `valuetype ${this.encodedType(r, ctx, depth)}`;
      case 0x12: return `class ${this.encodedType(r, ctx, depth)}`;
      case 0x13: return `!${this.genericName('t', r.u(), ctx)}`;
      case 0x1e: return `!!${this.genericName('m', r.u(), ctx)}`;
      case 0x1d: return `${this.sigType(r, ctx, depth + 1)}[]`;
      case 0x14: {
        const element = this.sigType(r, ctx, depth + 1);
        const rank = r.u();
        const sizes: number[] = [];
        for (let k = r.u(); k > 0 && !r.done; k--) sizes.push(r.u());
        const lower: number[] = [];
        for (let k = r.u(); k > 0 && !r.done; k--) lower.push(r.s());
        if (!rank) return `${element}[BAD: RANK == 0!]`;
        if (rank === 1 && !sizes.length && !lower.length) return `${element}[...]`;
        const dims: string[] = [];
        for (let i = 0; i < rank; i++) {
          const lo = lower[i] ?? 0;
          if (lo === 0 && i < sizes.length) dims.push(String(sizes[i]));
          else if (i < lower.length) dims.push(`${lo}...${i < sizes.length ? lo + sizes[i]! - 1 : ''}`);
          else dims.push('');
        }
        return `${element}[${dims.join(',')}]`;
      }
      case 0x15: {
        const base = this.sigType(r, ctx, depth + 1);
        const args: string[] = [];
        for (let k = r.u(); k > 0 && !r.done; k--) args.push(this.sigType(r, ctx, depth + 1));
        return `${base}<${args.join(',')}>`;
      }
      case 0x1b: {
        const sig = this.methodSig(r, ctx, depth + 1, true);
        return `method ${convText(sig.conv)}${sig.ret} *(${paramsText(sig)})`;
      }
      case 0x1f:
      case 0x20: {
        const modifier = this.encodedType(r, ctx, depth);
        return `${this.sigType(r, ctx, depth + 1)} ${et === 0x1f ? 'modreq' : 'modopt'}(${modifier})`;
      }
      case 0x45: return `${this.sigType(r, ctx, depth + 1)} pinned`;
    }
    return et ? `/* UNKNOWN TYPE (0x${et.toString(16).toUpperCase()})*/` : '';
  }

  /**
   * A method signature (MethodDefSig, MethodRefSig, StandAloneMethodSig). A function pointer's is
   * read as ildasm reads it, with no end but its count: a sentinel byte right after it — even one
   * past the end of the blob — is taken for one more `...`.
   */
  methodSig(r: SigReader, ctx: GenericContext, depth = 0, pointer = false): MethodSig {
    const conv = r.byte();
    const generics = conv & 0x10 ? r.u() : 0;
    let count = r.u();
    const ret = this.sigType(r, ctx, depth);
    const params: string[] = [];
    let sentinel = -1;
    for (let guard = 0; guard < 0x10000 && (pointer || !r.done); guard++) {
      if ((pointer ? r.peekPast() : r.peek()) === 0x41) {
        r.pos++;
        if (sentinel < 0) sentinel = params.length;
        params.push('...');
        continue;
      }
      if (count <= 0 || r.done) break;
      params.push(this.sigType(r, ctx, depth));
      count--;
    }
    return { conv, generics, ret, params, sentinel };
  }

  /* ---------------------------------------------------------------- *
   * Members
   * ---------------------------------------------------------------- */

  /** The class part of a member: nothing for a global function or field of `<Module>`. */
  private ownerOf(typeDef: number): string {
    return typeDef > 1 ? `${this.typeDef(typeDef)}::` : '';
  }

  /** A member's name; a privatescope one carries its token (`Name$PST06000123`). */
  private memberName(table: number, row: number, privateScope: boolean): string {
    const plain = this.md.string(this.md.table(table).get(row, 'Name')) || `$${table === TABLE.Field ? 'FD' : 'MD'}$${row.toString(16).toUpperCase()}`;
    return properName(privateScope ? `${plain}$PST${((table << 24) | row).toString(16).toUpperCase().padStart(8, '0')}` : plain);
  }

  /**
   * `instance void Owner::Name<inst>(params)` for a MethodDef, MemberRef or MethodSpec token, with
   * ildasm's line breaks as `, `. `ctx` is the class and the method being disassembled.
   */
  method(tok: number, ctx: GenericContext = NO_CONTEXT): string {
    const parts = this.methodParts(tok, ctx);
    return parts ? splitCommas(parts.text, parts.listStart) : `[unknown token 0x${tok.toString(16)}]`;
  }

  /** The text of a method operand before its commas are split, and where its parameter list starts. */
  private methodParts(tok: number, ctx: GenericContext): { text: string; listStart: number } | undefined {
    const md = this.md;
    let target = { table: tokenTable(tok), row: tokenRow(tok) };
    let inst: Uint8Array | undefined;
    let outer = ctx;
    if (target.table === TABLE.MethodSpec) {
      const spec = md.table(TABLE.MethodSpec);
      inst = md.blob(spec.get(target.row, 'Instantiation'));
      target = decodeIndex('MethodDefOrRef', spec.get(target.row, 'Method'));
      outer = { type: ctx.type, method: 0 };
    }
    let owner: string;
    let name: string;
    let blob: Uint8Array;
    let inner = outer;
    if (target.table === TABLE.MethodDef) {
      owner = this.ownerOf(this.methodOwner[target.row] ?? 0);
      name = this.memberName(TABLE.MethodDef, target.row, (md.table(TABLE.MethodDef).get(target.row, 'Flags') & 7) === 0);
      blob = md.blob(md.table(TABLE.MethodDef).get(target.row, 'Signature'));
    } else if (target.table === TABLE.MemberRef) {
      const t = md.table(TABLE.MemberRef);
      const parent = decodeIndex('MemberRefParent', t.get(target.row, 'Class'));
      owner = this.memberParent(parent, outer);
      if (parent.table === TABLE.TypeSpec && this.isGenericInst(parent.row)) inner = { type: 0, method: outer.method };
      const plain = md.string(t.get(target.row, 'Name')) || `$MR$${target.row.toString(16).toUpperCase()}`;
      const scoped = parent.table === TABLE.MethodDef && (md.table(TABLE.MethodDef).get(parent.row, 'Flags') & 7) === 0;
      name = properName(scoped ? `${plain}$PST06${parent.row.toString(16).toUpperCase().padStart(6, '0')}` : plain);
      blob = md.blob(t.get(target.row, 'Signature'));
    } else return undefined;
    let head = `${owner}${name}`;
    if (inst) {
      const r = new SigReader(inst);
      r.byte();
      const args: string[] = [];
      for (let k = r.u(); k > 0 && !r.done; k--) args.push(this.sigType(r, inner));
      head += `<${args.join(',')}>`;
    }
    const sig = this.methodSig(new SigReader(blob), inner);
    const arity = !inst && sig.generics ? `<[${sig.generics}]>` : '';
    const before = `${convText(sig.conv)}${sig.ret} `;
    const text = `${before}${head}${arity}(${paramsText(sig)})`;
    // ildasm finds the name in the text again; the list starts one character after it.
    const at = text.indexOf(head);
    return { text, listStart: (at < 0 ? before.length : at) + head.length + 1 };
  }

  /** The class part of a MemberRef, by its parent. */
  private memberParent(parent: { table: number; row: number }, ctx: GenericContext): string {
    if (!parent.row) return '';
    switch (parent.table) {
      case TABLE.TypeDef: return this.ownerOf(parent.row);
      case TABLE.TypeRef: return `${this.typeRef(parent.row)}::`;
      case TABLE.TypeSpec: return `${this.typeSpec(parent.row, ctx)}::`;
      case TABLE.ModuleRef: {
        const module = this.md.string(this.md.table(TABLE.ModuleRef).get(parent.row, 'Name'));
        return `${module ? `[.module ${properName(module)}]` : ''}::`;
      }
      case TABLE.MethodDef: return this.ownerOf(this.methodOwner[parent.row] ?? 0);
    }
    return '';
  }

  /** `int32 Owner::Name` for a Field or MemberRef token. */
  field(tok: number, ctx: GenericContext = NO_CONTEXT): string {
    const md = this.md;
    const row = tokenRow(tok);
    if (tokenTable(tok) === TABLE.Field) {
      const t = md.table(TABLE.Field);
      const name = this.memberName(TABLE.Field, row, (t.get(row, 'Flags') & 7) === 0);
      return `${this.fieldType(t.get(row, 'Signature'), ctx)} ${this.ownerOf(this.fieldOwner[row] ?? 0)}${name}`;
    }
    if (tokenTable(tok) === TABLE.MemberRef) {
      const t = md.table(TABLE.MemberRef);
      const parent = decodeIndex('MemberRefParent', t.get(row, 'Class'));
      const owner = this.memberParent(parent, ctx);
      const inner = parent.table === TABLE.TypeSpec && this.isGenericInst(parent.row) ? { type: 0, method: ctx.method } : ctx;
      const name = md.string(t.get(row, 'Name')) || `$MR$${row.toString(16).toUpperCase()}`;
      return `${this.fieldType(t.get(row, 'Signature'), inner)} ${owner}${properName(name)}`;
    }
    return `[unknown token 0x${tok.toString(16)}]`;
  }

  private fieldType(blob: number, ctx: GenericContext): string {
    const r = new SigReader(this.md.blob(blob));
    r.byte();
    return this.sigType(r, ctx);
  }

  /** A MemberRef is a field when its signature says so (0x06). */
  isFieldRef(row: number): boolean {
    return this.md.blob(this.md.table(TABLE.MemberRef).get(row, 'Signature'))[0] === 0x06;
  }

  /** The operand of ldtoken: a type, `field …` or `method …`. */
  token(tok: number, ctx: GenericContext): string {
    switch (tokenTable(tok)) {
      case TABLE.Field: return `field ${this.field(tok, ctx)}`;
      case TABLE.MethodDef:
      case TABLE.MethodSpec: return `method ${this.method(tok, ctx)}`;
      case TABLE.MemberRef: return this.isFieldRef(tokenRow(tok)) ? `field ${this.field(tok, ctx)}` : `method ${this.method(tok, ctx)}`;
    }
    return this.type(tok, ctx);
  }

  /** The operand of calli: a stand-alone method signature, `unmanaged cdecl int32(int32)`. */
  standalone(tok: number, ctx: GenericContext = NO_CONTEXT): string {
    const blob = this.md.blob(this.md.table(TABLE.StandAloneSig).get(tokenRow(tok), 'Signature'));
    const sig = this.methodSig(new SigReader(blob), ctx);
    return `${convText(sig.conv)}${sig.ret}(${paramsText(sig)})`;
  }

  /** The types of a method's locals, from its LocalVarSig. */
  locals(tok: number, ctx: GenericContext = NO_CONTEXT): string[] {
    if (tokenTable(tok) !== TABLE.StandAloneSig) return [];
    const r = new SigReader(this.md.blob(this.md.table(TABLE.StandAloneSig).get(tokenRow(tok), 'Signature')));
    if (r.byte() !== 0x07) return [];
    const out: string[] = [];
    for (let k = r.u(); k > 0 && !r.done && out.length < 65536; k--) out.push(this.sigType(r, ctx));
    return out;
  }

  /** A MethodDef's own signature, generic parameters named. */
  methodDefSig(row: number): MethodSig {
    const t = this.md.table(TABLE.MethodDef);
    return this.methodSig(new SigReader(this.md.blob(t.get(row, 'Signature'))), { type: this.methodOwner[row] ?? 0, method: row });
  }

  /** The names of a MethodDef's parameters by sequence (1 = the first; 0 = the return value). */
  paramNames(row: number): string[] {
    const md = this.md;
    const out: string[] = [];
    const [start, end] = md.range(TABLE.MethodDef, row, 'ParamList', TABLE.Param);
    const params = md.table(TABLE.Param);
    const ptr = md.rows(TABLE.ParamPtr) ? md.table(TABLE.ParamPtr) : undefined;
    for (let k = start; k < end && k <= (ptr ? ptr.rows : params.rows); k++) {
      const p = ptr ? ptr.get(k, 'Param') : k;
      const name = md.string(params.get(p, 'Name'));
      if (name) out[params.get(p, 'Sequence')] = name;
    }
    return out;
  }
}
