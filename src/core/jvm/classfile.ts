/**
 * The class file format (the Java Virtual Machine Specification, chapter 4):
 * the constant pool, the class's own name, its super class and interfaces,
 * its fields and methods, and the attributes the disassembler shows — Code
 * with its exception table, line numbers and local variables, the bootstrap
 * methods of invokedynamic, the source file, inner classes, records, sealed
 * classes, nests and modules.
 *
 * Constants are printed as javap prints them (its ConstantWriter): a class or
 * member name that is not a Java binary name in quotes, strings with Java's
 * escapes, floating point as Java's Double.toString and Float.toString write
 * it, and a member of the class itself without its class.
 */

export class NotClass extends Error {}

export const CONSTANT = {
  Utf8: 1, Integer: 3, Float: 4, Long: 5, Double: 6, Class: 7, String: 8, Fieldref: 9, Methodref: 10, InterfaceMethodref: 11,
  NameAndType: 12, MethodHandle: 15, MethodType: 16, Dynamic: 17, InvokeDynamic: 18, Module: 19, Package: 20,
} as const;

/** The class file's magic number. */
export const isClassFile = (bytes: Uint8Array): boolean =>
  // 0xCAFEBABE is also a universal Mach-O file's: there the next word counts its slices (a few), here it is the version (45 or more).
  bytes.length >= 10 && bytes[0] === 0xca && bytes[1] === 0xfe && bytes[2] === 0xba && bytes[3] === 0xbe && ((bytes[6]! << 8) | bytes[7]!) >= 45;

export interface Attribute {
  name: string;
  /** Where its contents start in the class file, and their length. */
  offset: number;
  length: number;
}

export interface Handler {
  start: number;
  end: number;
  handler: number;
  /** The Class entry of what it catches; 0 catches anything (finally). */
  catchType: number;
}

export interface LocalVariable {
  start: number;
  length: number;
  name: string;
  descriptor: string;
  slot: number;
}

export interface Code {
  maxStack: number;
  maxLocals: number;
  /** Where the bytecode starts in the class file, and its length. */
  offset: number;
  length: number;
  handlers: Handler[];
  attributes: Attribute[];
}

export interface Member {
  access: number;
  name: string;
  descriptor: string;
  attributes: Attribute[];
}

export interface Method extends Member {
  code: Code | undefined;
}

export interface BootstrapMethod {
  /** A MethodHandle entry, and the constants passed to it. */
  method: number;
  args: number[];
}

const UTF8 = new TextDecoder();

/** A name in the constant pool's UTF-8 is "modified": NUL is two bytes and a character outside the BMP is two surrogates of three bytes each. */
function modifiedUtf8(bytes: Uint8Array, start: number, end: number): string {
  let ascii = true;
  for (let p = start; p < end; p++) {
    if (bytes[p]! >= 0x80 || bytes[p] === 0) {
      ascii = false;
      break;
    }
  }
  if (ascii) return UTF8.decode(bytes.subarray(start, end));
  const units: number[] = [];
  for (let p = start; p < end; ) {
    const b = bytes[p]!;
    if (b < 0x80) {
      units.push(b);
      p += 1;
    } else if ((b & 0xe0) === 0xc0 && p + 1 < end) {
      units.push(((b & 0x1f) << 6) | (bytes[p + 1]! & 0x3f));
      p += 2;
    } else if ((b & 0xf0) === 0xe0 && p + 2 < end) {
      units.push(((b & 0x0f) << 12) | ((bytes[p + 1]! & 0x3f) << 6) | (bytes[p + 2]! & 0x3f));
      p += 3;
    } else {
      units.push(0xfffd);
      p += 1;
    }
  }
  let out = '';
  for (let k = 0; k < units.length; k += 8192) out += String.fromCharCode(...units.slice(k, k + 8192));
  return out;
}

export class ClassFile {
  readonly minor: number;
  readonly major: number;
  /** The constant pool: each entry's tag, and where its contents start (after the tag). Index 0 is unused, as is the slot after a long or double. */
  readonly tags: Uint8Array;
  readonly at: Int32Array;
  readonly access: number;
  readonly thisClass: number;
  readonly superClass: number;
  readonly interfaces: number[] = [];
  readonly fields: Member[] = [];
  readonly methods: Method[] = [];
  readonly attributes: Attribute[] = [];
  /** The class's name as the file writes it: `java/lang/String`. */
  readonly name: string;
  private readonly strings: (string | undefined)[];
  private readonly view: DataView;
  private bootstraps: BootstrapMethod[] | undefined;

  /** `path` is where the class was found (its entry in a JAR), for the page. */
  constructor(
    readonly bytes: Uint8Array,
    readonly path = '',
  ) {
    const view = (this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength));
    if (!isClassFile(bytes)) throw new NotClass('not a class file');
    const end = bytes.length;
    const need = (p: number, n: number) => {
      if (p + n > end) throw new NotClass('the class file is cut short');
    };
    this.minor = view.getUint16(4);
    this.major = view.getUint16(6);
    const count = view.getUint16(8);
    this.tags = new Uint8Array(count);
    this.at = new Int32Array(count);
    this.strings = new Array(count);
    let p = 10;
    for (let i = 1; i < count; i++) {
      need(p, 1);
      const tag = bytes[p]!;
      this.tags[i] = tag;
      this.at[i] = p + 1;
      p += 1;
      switch (tag) {
        case CONSTANT.Utf8:
          need(p, 2);
          p += 2 + view.getUint16(p);
          break;
        case CONSTANT.Integer:
        case CONSTANT.Float:
        case CONSTANT.Fieldref:
        case CONSTANT.Methodref:
        case CONSTANT.InterfaceMethodref:
        case CONSTANT.NameAndType:
        case CONSTANT.Dynamic:
        case CONSTANT.InvokeDynamic:
          p += 4;
          break;
        case CONSTANT.Long:
        case CONSTANT.Double:
          p += 8;
          i++;
          break;
        case CONSTANT.Class:
        case CONSTANT.String:
        case CONSTANT.MethodType:
        case CONSTANT.Module:
        case CONSTANT.Package:
          p += 2;
          break;
        case CONSTANT.MethodHandle:
          p += 3;
          break;
        default:
          throw new NotClass(`constant #${i} has an unknown tag ${tag}`);
      }
    }
    need(p, 8);
    this.access = view.getUint16(p);
    this.thisClass = view.getUint16(p + 2);
    this.superClass = view.getUint16(p + 4);
    const interfaces = view.getUint16(p + 6);
    p += 8;
    need(p, interfaces * 2);
    for (let k = 0; k < interfaces; k++) this.interfaces.push(view.getUint16(p + k * 2));
    p += interfaces * 2;
    for (const into of [this.fields, this.methods as Member[]]) {
      need(p, 2);
      const members = view.getUint16(p);
      p += 2;
      for (let k = 0; k < members; k++) {
        need(p, 6);
        const member: Member = { access: view.getUint16(p), name: this.utf8(view.getUint16(p + 2)), descriptor: this.utf8(view.getUint16(p + 4)), attributes: [] };
        p = this.readAttributes(p + 6, member.attributes);
        into.push(member);
      }
    }
    p = this.readAttributes(p, this.attributes);
    for (const method of this.methods) {
      const code = method.attributes.find((a) => a.name === 'Code');
      method.code = code ? this.readCode(code) : undefined;
    }
    this.name = this.className(this.thisClass);
  }

  private readAttributes(p: number, into: Attribute[]): number {
    const view = this.view;
    if (p + 2 > this.bytes.length) throw new NotClass('the class file is cut short');
    const count = view.getUint16(p);
    p += 2;
    for (let k = 0; k < count; k++) {
      if (p + 6 > this.bytes.length) throw new NotClass('the class file is cut short');
      const length = view.getUint32(p + 2);
      if (p + 6 + length > this.bytes.length) throw new NotClass('an attribute runs past the end of the class file');
      into.push({ name: this.utf8(view.getUint16(p)), offset: p + 6, length });
      p += 6 + length;
    }
    return p;
  }

  private readCode(attr: Attribute): Code {
    const view = this.view;
    let p = attr.offset;
    const length = view.getUint32(p + 4);
    const code: Code = { maxStack: view.getUint16(p), maxLocals: view.getUint16(p + 2), offset: p + 8, length, handlers: [], attributes: [] };
    if (8 + length > attr.length) throw new NotClass('a method\'s code runs past its attribute');
    p += 8 + length;
    const handlers = view.getUint16(p);
    p += 2;
    for (let k = 0; k < handlers; k++, p += 8) code.handlers.push({ start: view.getUint16(p), end: view.getUint16(p + 2), handler: view.getUint16(p + 4), catchType: view.getUint16(p + 6) });
    this.readAttributes(p, code.attributes);
    return code;
  }

  u1(p: number): number {
    return this.bytes[p]!;
  }

  u2(p: number): number {
    return this.view.getUint16(p);
  }

  u4(p: number): number {
    return this.view.getUint32(p);
  }

  /** Is `index` an entry of the pool with this tag? */
  is(index: number, tag: number): boolean {
    return index > 0 && index < this.tags.length && this.tags[index] === tag;
  }

  utf8(index: number): string {
    if (!this.is(index, CONSTANT.Utf8)) return '';
    let text = this.strings[index];
    if (text === undefined) {
      const p = this.at[index]!;
      text = modifiedUtf8(this.bytes, p + 2, p + 2 + this.view.getUint16(p));
      this.strings[index] = text;
    }
    return text;
  }

  /** The first and second u2 of an entry (a Class's name, a Fieldref's class and NameAndType…). */
  ref1(index: number): number {
    return index > 0 && index < this.tags.length ? this.view.getUint16(this.at[index]!) : 0;
  }

  ref2(index: number): number {
    return index > 0 && index < this.tags.length ? this.view.getUint16(this.at[index]! + 2) : 0;
  }

  /** The internal name of a Class entry: `java/lang/String`, `[I`. */
  className(index: number): string {
    return this.is(index, CONSTANT.Class) ? this.utf8(this.ref1(index)) : '';
  }

  /** A member reference: its class's internal name, its name and its descriptor. */
  member(index: number): { owner: string; name: string; descriptor: string } {
    const nat = this.ref2(index);
    return { owner: this.className(this.ref1(index)), name: this.utf8(this.ref1(nat)), descriptor: this.utf8(this.ref2(nat)) };
  }

  /** The NameAndType of an InvokeDynamic or Dynamic entry, and its bootstrap method's number. */
  dynamic(index: number): { bootstrap: number; name: string; descriptor: string } {
    const nat = this.ref2(index);
    return { bootstrap: this.ref1(index), name: this.utf8(this.ref1(nat)), descriptor: this.utf8(this.ref2(nat)) };
  }

  int(index: number): number {
    return this.view.getInt32(this.at[index]!);
  }

  float(index: number): number {
    return this.view.getFloat32(this.at[index]!);
  }

  long(index: number): bigint {
    return this.view.getBigInt64(this.at[index]!);
  }

  double(index: number): number {
    return this.view.getFloat64(this.at[index]!);
  }

  /** A MethodHandle: its kind (1 getField … 9 invokeInterface) and the member it refers to. */
  handle(index: number): { kind: number; reference: number } {
    const p = this.at[index]!;
    return { kind: this.bytes[p]!, reference: this.view.getUint16(p + 1) };
  }

  attribute(name: string, list: Attribute[] = this.attributes): Attribute | undefined {
    return list.find((a) => a.name === name);
  }

  /** The bootstrap methods invokedynamic and dynamic constants name by number. */
  bootstrapMethods(): BootstrapMethod[] {
    if (!this.bootstraps) {
      this.bootstraps = [];
      const attr = this.attribute('BootstrapMethods');
      if (attr) {
        let p = attr.offset + 2;
        for (let k = this.u2(attr.offset); k > 0 && p + 4 <= attr.offset + attr.length; k--) {
          const count = this.u2(p + 2);
          const args: number[] = [];
          for (let a = 0; a < count; a++) args.push(this.u2(p + 4 + a * 2));
          this.bootstraps.push({ method: this.u2(p), args });
          p += 4 + count * 2;
        }
      }
    }
    return this.bootstraps;
  }

  /** The source file the class was compiled from (SourceFile), if the compiler kept it. */
  sourceFile(): string | undefined {
    const attr = this.attribute('SourceFile');
    return attr ? this.utf8(this.u2(attr.offset)) : undefined;
  }

  /** The generic signature of the class, a field or a method (Signature). */
  signature(list: Attribute[] = this.attributes): string | undefined {
    const attr = this.attribute('Signature', list);
    return attr ? this.utf8(this.u2(attr.offset)) : undefined;
  }

  /** The local variables a method's code names (LocalVariableTable), when it was compiled with them. */
  localVariables(code: Code): LocalVariable[] {
    const out: LocalVariable[] = [];
    for (const attr of code.attributes) {
      if (attr.name !== 'LocalVariableTable') continue;
      let p = attr.offset + 2;
      for (let k = this.u2(attr.offset); k > 0; k--, p += 10) {
        out.push({ start: this.u2(p), length: this.u2(p + 2), name: this.utf8(this.u2(p + 4)), descriptor: this.utf8(this.u2(p + 6)), slot: this.u2(p + 8) });
      }
    }
    return out;
  }

  /** The source lines of a method's code (LineNumberTable): pc → line, in the order of the table. */
  lineNumbers(code: Code): [pc: number, line: number][] {
    const out: [number, number][] = [];
    for (const attr of code.attributes) {
      if (attr.name !== 'LineNumberTable') continue;
      let p = attr.offset + 2;
      for (let k = this.u2(attr.offset); k > 0; k--, p += 4) out.push([this.u2(p), this.u2(p + 2)]);
    }
    return out;
  }

  /** The names of a method's parameters (MethodParameters), when the compiler kept them. */
  parameterNames(method: Method): string[] | undefined {
    const attr = this.attribute('MethodParameters', method.attributes);
    if (!attr) return undefined;
    const out: string[] = [];
    for (let k = 0, n = this.u1(attr.offset); k < n; k++) out.push(this.utf8(this.u2(attr.offset + 1 + k * 4)));
    return out;
  }

  /** The exceptions a method declares (Exceptions), as internal names. */
  exceptions(method: Method): string[] {
    const attr = this.attribute('Exceptions', method.attributes);
    if (!attr) return [];
    const out: string[] = [];
    for (let k = 0, n = this.u2(attr.offset); k < n; k++) out.push(this.className(this.u2(attr.offset + 2 + k * 2)));
    return out;
  }

  /** The types of the annotations on the class, a field or a method, visible and invisible: `Lkotlin/Metadata;`. */
  annotations(list: Attribute[] = this.attributes): string[] {
    const out: string[] = [];
    for (const attr of list) {
      if (attr.name !== 'RuntimeVisibleAnnotations' && attr.name !== 'RuntimeInvisibleAnnotations') continue;
      // Only the first level's types: skipping an annotation's values needs walking them.
      let p = attr.offset + 2;
      const end = attr.offset + attr.length;
      for (let k = this.u2(attr.offset); k > 0 && p + 4 <= end; k--) {
        out.push(this.utf8(this.u2(p)));
        p = this.skipAnnotation(p, end);
      }
    }
    return out;
  }

  private skipAnnotation(p: number, end: number): number {
    const pairs = this.u2(p + 2);
    p += 4;
    for (let k = 0; k < pairs && p < end; k++) p = this.skipElement(p + 2, end);
    return p;
  }

  private skipElement(p: number, end: number): number {
    const tag = String.fromCharCode(this.u1(p));
    p += 1;
    switch (tag) {
      case 'e':
        return p + 4;
      case '@':
        return this.skipAnnotation(p, end);
      case '[': {
        const n = this.u2(p);
        p += 2;
        for (let k = 0; k < n && p < end; k++) p = this.skipElement(p, end);
        return p;
      }
    }
    return p + 2;
  }

  /** The classes nested in this one, and the class this one is nested in, by InnerClasses: inner → [outer, simple name, flags]. */
  innerClasses(): { inner: string; outer: string; name: string; access: number }[] {
    const attr = this.attribute('InnerClasses');
    if (!attr) return [];
    const out = [];
    let p = attr.offset + 2;
    for (let k = this.u2(attr.offset); k > 0; k--, p += 8) {
      out.push({ inner: this.className(this.u2(p)), outer: this.className(this.u2(p + 2)), name: this.utf8(this.u2(p + 4)), access: this.u2(p + 6) });
    }
    return out;
  }

  /** Classes named by a list attribute (NestMembers, PermittedSubclasses). */
  classList(name: string): string[] {
    const attr = this.attribute(name);
    if (!attr) return [];
    const out: string[] = [];
    for (let k = 0, n = this.u2(attr.offset); k < n; k++) out.push(this.className(this.u2(attr.offset + 2 + k * 2)));
    return out;
  }

  /** A record's components (Record): name and descriptor. */
  recordComponents(): { name: string; descriptor: string }[] {
    const attr = this.attribute('Record');
    if (!attr) return [];
    const out = [];
    let p = attr.offset + 2;
    for (let k = this.u2(attr.offset); k > 0; k--) {
      out.push({ name: this.utf8(this.u2(p)), descriptor: this.utf8(this.u2(p + 2)) });
      const attrs: Attribute[] = [];
      p = this.readAttributes(p + 4, attrs);
    }
    return out;
  }

  /** A module-info's module: its name, version, and what it requires, exports and opens. */
  module(): { name: string; version: string; requires: string[]; exports: string[]; opens: string[]; uses: string[]; provides: string[] } | undefined {
    const attr = this.attribute('Module');
    if (!attr) return undefined;
    let p = attr.offset;
    const mod = (index: number) => (this.is(index, CONSTANT.Module) ? this.utf8(this.ref1(index)) : '');
    const pkg = (index: number) => (this.is(index, CONSTANT.Package) ? this.utf8(this.ref1(index)).replace(/\//g, '.') : '');
    const out = { name: mod(this.u2(p)), version: this.utf8(this.u2(p + 4)), requires: [] as string[], exports: [] as string[], opens: [] as string[], uses: [] as string[], provides: [] as string[] };
    p += 6;
    for (let k = 0, n = this.u2(p); k < n; k++) out.requires.push(mod(this.u2(p + 2 + k * 6)));
    p += 2 + this.u2(p) * 6;
    for (const list of [out.exports, out.opens]) {
      const n = this.u2(p);
      p += 2;
      for (let k = 0; k < n; k++) {
        list.push(pkg(this.u2(p)));
        p += 6 + this.u2(p + 4) * 2;
      }
    }
    const uses = this.u2(p);
    for (let k = 0; k < uses; k++) out.uses.push(javaName(this.className(this.u2(p + 2 + k * 2))));
    p += 2 + uses * 2;
    const provides = this.u2(p);
    p += 2;
    for (let k = 0; k < provides; k++) {
      out.provides.push(javaName(this.className(this.u2(p))));
      p += 4 + this.u2(p + 2) * 2;
    }
    return out;
  }
}

/* ------------------------------------------------------------------ *
 * Constants as javap prints them
 * ------------------------------------------------------------------ */

const ASCII_START = /[A-Za-z_$]/;
const ASCII_PART = /[A-Za-z0-9_$\u0000-\u0008\u000e-\u001b\u007f]/;
// Character.isJavaIdentifierStart and isJavaIdentifierPart: letters, letter numbers, currency symbols, connectors; and digits, marks and the ignorable controls and formats.
const START = /[\p{L}\p{Nl}\p{Sc}\p{Pc}]/u;
const PART = /[\p{L}\p{Nl}\p{Sc}\p{Pc}\p{Nd}\p{Mn}\p{Mc}\p{Cf}\u0000-\u0008\u000e-\u001b\u007f-\u009f]/u;

const isStart = (c: string) => (c.length === 1 && c < '\u0080' ? ASCII_START.test(c) : START.test(c));
const isPart = (c: string) => (c.length === 1 && c < '\u0080' ? ASCII_PART.test(c) : PART.test(c));

/** A class, member or package name as javap writes it: as it is when it is a binary name (identifiers between slashes), else in quotes. */
export function checkName(name: string): string {
  if (!name.length) return '""';
  let previous = '/';
  for (const c of name) {
    if ((previous === '/' && !isStart(c)) || (c !== '/' && !isPart(c))) return `"${name.replace(/[\\"\n\t]/g, (m) => ({ '\\': '\\\\', '"': '\\"', '\n': '\\n', '\t': '\\t' })[m]!)}"`;
    previous = c;
  }
  return name;
}

const STRING_ESCAPES: Record<string, string> = { '\t': '\\t', '\n': '\\n', '\r': '\\r', '\b': '\\b', '\f': '\\f', '"': '\\"', "'": "\\'", '\\': '\\\\' };

/** A string constant as javap writes it: Java's escapes, and \uXXXX for the other control characters. */
export function escapeString(text: string): string {
  // eslint-disable-next-line no-control-regex
  return text.replace(/[\t\n\r\b\f"'\\\u0000-\u001f\u007f-\u009f]/g, (c) => STRING_ESCAPES[c] ?? `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

/** Digits and exponent: `x = d.ddd × 10^exp`. */
function decimal(text: string): { digits: string; exp: number } {
  const [mantissa, e] = text.split('e') as [string, string];
  return { digits: mantissa.replace('.', '').replace(/0+$/, '') || '0', exp: Number(e) };
}

/**
 * JavaScript rounds a tie up (toExponential), Java to the even digit: when `value` is exactly
 * halfway between the digits `text` has and the ones below, and the last digit is odd, the ones
 * below. Exact, in integers: 2·value = (2·digits − 1)·10^q.
 */
function evenTie(value: number, text: string): string {
  const [mantissa, e] = text.split('e') as [string, string];
  const digits = mantissa.replace('.', '');
  if (!/[13579]$/.test(digits)) return text;
  const view = new DataView(new ArrayBuffer(8));
  view.setFloat64(0, value);
  const bits = view.getBigUint64(0);
  const biased = Number((bits >> 52n) & 0x7ffn);
  const m = biased ? (bits & 0xfffffffffffffn) | (1n << 52n) : bits & 0xfffffffffffffn;
  const e2 = (biased || 1) - 1075;
  const q = Number(e) - digits.length + 1;
  let left = 2n * m;
  let right = 2n * BigInt(digits) - 1n;
  if (e2 >= 0) left <<= BigInt(e2);
  else right <<= BigInt(-e2);
  if (q >= 0) right *= 10n ** BigInt(q);
  else left *= 10n ** BigInt(-q);
  if (left !== right) return text;
  const lower = String(BigInt(digits) - 1n);
  return `${lower[0]}${lower.length > 1 ? `.${lower.slice(1)}` : ''}e${e}`;
}

/**
 * Java's Double.toString and Float.toString (JDK 19 and later): the shortest decimal that reads
 * back as the same value — two digits when one would do but two are closer —, written plainly
 * between 10^-3 and 10^7 and as `1.0E10` outside.
 */
function javaNumber(value: number, single: boolean): string {
  if (Number.isNaN(value)) return 'NaN';
  if (!Number.isFinite(value)) return value > 0 ? 'Infinity' : '-Infinity';
  if (value === 0) return Object.is(value, -0) ? '-0.0' : '0.0';
  const abs = Math.abs(value);
  const same = (text: string) => (single ? Math.fround(Number(text)) === abs : Number(text) === abs);
  // Of two digits equally close the even one, when it too reads back as the value.
  const pick = (text: string) => {
    const even = evenTie(abs, text);
    return even !== text && same(even) ? even : text;
  };
  let d = decimal(abs.toExponential());
  if (single) {
    for (let p = 1; p <= 9; p++) {
      const text = pick(abs.toExponential(p - 1));
      if (same(text)) {
        d = decimal(text);
        break;
      }
    }
  }
  if (d.digits.length === 1) {
    const two = pick(abs.toExponential(1));
    if (same(two)) d = decimal(two);
  }
  const { digits, exp } = d;
  let out: string;
  if (abs >= 1e-3 && abs < 1e7) {
    if (exp >= 0) {
      const whole = digits.length > exp + 1 ? digits.slice(0, exp + 1) : digits.padEnd(exp + 1, '0');
      const fraction = digits.slice(exp + 1) || '0';
      out = `${whole}.${fraction}`;
    } else out = `0.${'0'.repeat(-exp - 1)}${digits}`;
  } else out = `${digits[0]}.${digits.slice(1) || '0'}E${exp}`;
  return value < 0 ? `-${out}` : out;
}

export const javaDouble = (value: number): string => javaNumber(value, false);
export const javaFloat = (value: number): string => javaNumber(value, true);

/** javap's names for the kinds of entry, as it writes them before a constant. */
const TAG_NAMES: Record<number, string> = {
  1: 'Utf8', 3: 'int', 4: 'float', 5: 'long', 6: 'double', 7: 'class', 8: 'String', 9: 'Field', 10: 'Method', 11: 'InterfaceMethod',
  12: 'NameAndType', 15: 'MethodHandle', 16: 'MethodType', 17: 'Dynamic', 18: 'InvokeDynamic', 19: 'Module', 20: 'Package',
};

const HANDLE_KINDS = ['', 'REF_getField', 'REF_getStatic', 'REF_putField', 'REF_putStatic', 'REF_invokeVirtual', 'REF_invokeStatic', 'REF_invokeSpecial', 'REF_newInvokeSpecial', 'REF_invokeInterface'];

/** An entry's value as javap writes it (ConstantWriter.stringValue). */
export function constantValue(cf: ClassFile, index: number): string {
  const name = (i: number) => checkName(cf.utf8(i));
  switch (cf.tags[index]) {
    case CONSTANT.Utf8:
      return escapeString(cf.utf8(index));
    case CONSTANT.Integer:
      return String(cf.int(index));
    case CONSTANT.Float:
      return `${javaFloat(cf.float(index))}f`;
    case CONSTANT.Long:
      return `${cf.long(index)}l`;
    case CONSTANT.Double:
      return `${javaDouble(cf.double(index))}d`;
    case CONSTANT.Class:
      return name(cf.ref1(index));
    case CONSTANT.String:
      return escapeString(cf.utf8(cf.ref1(index)));
    case CONSTANT.Fieldref:
    case CONSTANT.Methodref:
    case CONSTANT.InterfaceMethodref:
      return `${constantValue(cf, cf.ref1(index))}.${constantValue(cf, cf.ref2(index))}`;
    case CONSTANT.NameAndType:
      return `${name(cf.ref1(index))}:${cf.utf8(cf.ref2(index))}`;
    case CONSTANT.MethodHandle: {
      const { kind, reference } = cf.handle(index);
      // An interface's static or special method is still REF_invokeStatic or REF_invokeSpecial.
      return `${HANDLE_KINDS[kind] ?? `kind ${kind}`} ${constantValue(cf, reference)}`;
    }
    case CONSTANT.MethodType:
      return cf.utf8(cf.ref1(index));
    case CONSTANT.Dynamic:
    case CONSTANT.InvokeDynamic:
      return `#${cf.ref1(index)}:${constantValue(cf, cf.ref2(index))}`;
    case CONSTANT.Module:
    case CONSTANT.Package:
      return name(cf.ref1(index));
  }
  return `#${index}`;
}

/** What javap writes after an instruction's `//`: the kind of entry and its value; a member of the class itself without its class. */
export function constantComment(cf: ClassFile, index: number): string {
  if (index === 0) return '#0';
  const tag = cf.tags[index] ?? 0;
  let shown = index;
  if ((tag === CONSTANT.Fieldref || tag === CONSTANT.Methodref || tag === CONSTANT.InterfaceMethodref) && cf.ref1(index) === cf.thisClass) shown = cf.ref2(index);
  return `${TAG_NAMES[tag] ?? `(unknown tag ${tag})`} ${constantValue(cf, shown)}`;
}

/* ------------------------------------------------------------------ *
 * Descriptors
 * ------------------------------------------------------------------ */

const PRIMITIVES: Record<string, string> = { B: 'byte', C: 'char', D: 'double', F: 'float', I: 'int', J: 'long', S: 'short', Z: 'boolean', V: 'void' };

/** One field type of a descriptor, from `at`, as Java writes it: `int`, `java.lang.String[]`; and where it ends. */
export function readType(descriptor: string, at: number): [string, number] {
  let dims = 0;
  while (descriptor[at] === '[') {
    dims++;
    at++;
  }
  let name: string;
  const c = descriptor[at] ?? '';
  if (c === 'L') {
    const end = descriptor.indexOf(';', at);
    if (end < 0) return [descriptor.slice(at), descriptor.length];
    name = descriptor.slice(at + 1, end).replace(/\//g, '.');
    at = end + 1;
  } else {
    name = PRIMITIVES[c] ?? c;
    at++;
  }
  return [name + '[]'.repeat(dims), at];
}

/** A field descriptor as Java writes the type. */
export const fieldType = (descriptor: string): string => readType(descriptor, 0)[0];

/** A method descriptor's parameter types and return type, as Java writes them. */
export function methodTypes(descriptor: string): { params: string[]; ret: string } {
  const params: string[] = [];
  let at = descriptor.indexOf('(') + 1;
  while (at > 0 && at < descriptor.length && descriptor[at] !== ')') {
    const [type, next] = readType(descriptor, at);
    params.push(type);
    at = next;
  }
  return { params, ret: readType(descriptor, descriptor.indexOf(')') + 1)[0] };
}

/** What a descriptor's values are: one letter per parameter (I, J, F, D, or A for a reference), and the return's ('' for void). */
export function descriptorKinds(descriptor: string): { params: string; ret: string } {
  let params = '';
  let at = descriptor.indexOf('(') + 1;
  const kind = (c: string) => (c === 'J' ? 'l' : c === 'F' ? 'f' : c === 'D' ? 'd' : c === 'L' || c === '[' ? 'a' : c === 'V' ? '' : 'i');
  while (at > 0 && at < descriptor.length && descriptor[at] !== ')') {
    params += kind(descriptor[at]!);
    const [, next] = readType(descriptor, at);
    at = next;
  }
  if (at <= 0) return { params: '', ret: kind(descriptor[0] ?? 'V') };
  return { params, ret: kind(descriptor[at + 1] ?? 'V') };
}

/** `java/lang/String` → `java.lang.String`; an array class as Java writes its type. */
export const javaName = (internal: string): string => (internal.startsWith('[') ? fieldType(internal) : internal.replace(/\//g, '.'));

const CLASS_FLAGS: [number, string][] = [[0x0001, 'public'], [0x0010, 'final'], [0x0400, 'abstract']];
const MEMBER_FLAGS: [number, string][] = [[0x0001, 'public'], [0x0002, 'private'], [0x0004, 'protected'], [0x0008, 'static'], [0x0010, 'final'], [0x0020, 'synchronized'], [0x0100, 'native'], [0x0400, 'abstract'], [0x0800, 'strictfp']];
const FIELD_FLAGS: [number, string][] = [[0x0001, 'public'], [0x0002, 'private'], [0x0004, 'protected'], [0x0008, 'static'], [0x0010, 'final'], [0x0040, 'volatile'], [0x0080, 'transient']];

/** The Java modifiers of a class, a method or a field: `public static final`. */
export function modifiers(access: number, what: 'class' | 'method' | 'field'): string {
  const table = what === 'class' ? CLASS_FLAGS : what === 'method' ? MEMBER_FLAGS : FIELD_FLAGS;
  return table.filter(([bit]) => access & bit).map(([, word]) => word).join(' ');
}

/** What a class is: an interface, an annotation, an enum, a record, a module, or a class. */
export function classKind(cf: ClassFile): 'class' | 'interface' | 'annotation' | 'enum' | 'record' | 'module' {
  if (cf.access & 0x8000) return 'module';
  if (cf.access & 0x2000) return 'annotation';
  if (cf.access & 0x0200) return 'interface';
  if (cf.access & 0x4000) return 'enum';
  if (cf.className(cf.superClass) === 'java/lang/Record') return 'record';
  return 'class';
}

/** The Java release a class file version is from: 52 → 8, 49 → 5, 48 → 1.4. */
export function javaRelease(major: number): string {
  if (major >= 49) return String(major - 44);
  return `1.${Math.max(1, major - 44)}`;
}
