/**
 * The analysis of Java bytecode: a class file, or every class of a JAR (or a
 * .jmod, a .war, an Android library's classes.jar) as one program. Every
 * method with code is decoded once, and from that pass come the statistics,
 * the methods (the functions of the listing, named `package.Class::method`),
 * the labels branches and exception handlers go to, the calls — to methods of
 * the program, and to members of classes it does not have, which are its
 * imports —, the fields and the strings `ldc` loads.
 *
 * A class file has no addresses: each method's code is given a place of its
 * own, one after another in the order of the classes, and an instruction's
 * address is that place plus its pc; the listing writes the pc, as javap
 * does. What is not code has addresses of its own that are never an
 * instruction's: a string (all classes' constants of the same text are one)
 * from STRING_BASE, a field of the program from FIELD_BASE, a member of
 * another class from IMPORT_BASE.
 */

import { append, BytecodeProgram, IF, tick, type DataAt, type Fn, type Progress, type StringRef } from '../disassembly';
import { t } from '../i18n';
import { isZip, NotZip, zipEntries, zipRead } from '../zip';
import { ClassFile, classKind, CONSTANT, descriptorKinds, isClassFile, javaName, javaRelease, methodTypes, modifiers, NotClass, type Code, type Handler, type Method } from './classfile';
import { decodeAt, JvmInsn, poolIndex } from './decode';
import { allOps, F, OPERAND } from './opcodes';

export const STRING_BASE = 0x40000000;
export const FIELD_BASE = 0x50000000;
export const IMPORT_BASE = 0x60000000;
/** Where the first method's code is placed. */
const CODE_BASE = 0x10000;

/** A member of a class the program does not have: a method or a field its code uses. */
export interface ImportedMember extends Fn {
  /** The class as the code names it (`java/io/PrintStream`), the member and its descriptor. */
  owner: string;
  member: string;
  descriptor: string;
  field: boolean;
  /** The package, as Java writes it (`java.io`), '' for the unnamed one. */
  package: string;
}

/** A field of the program's own classes, by its address. */
export interface OwnField {
  cls: number;
  name: string;
  descriptor: string;
  access: number;
}

/** A method with code: its class (an index into `classes`), the method, and where its code is placed. */
export interface Body {
  cls: number;
  method: Method;
  code: Code;
  base: number;
}

/** What the file around the classes says: a JAR's manifest and the entries that are not classes. */
export interface Container {
  kind: 'class' | 'jar' | 'jmod';
  manifest: Map<string, string>;
  /** Entries that are not classes of the program (resources, nested JARs, other releases' classes). */
  resources: { name: string; size: number }[];
  /** Classes for other Java releases (META-INF/versions/…), which are not read. */
  versioned: number;
  /** Classes that could not be read, and why. */
  broken: { name: string; reason: string }[];
  /** The archive an Android library's classes.jar was taken from. */
  from?: string;
}

const KIND_CODE: Record<string, number> = { i: 1, l: 2, f: 3, d: 4, a: 5, r: 6 };
const isWide = (kind: number) => kind === 2 || kind === 4;

/** The bytecode of Java classes, laid out one method after another at addresses of its own; a switch's targets are its cases', then the default's. */
export class JvmProgram extends BytecodeProgram {
  readonly arch = 'jvm';
  /** The code of each function of `functions`. */
  readonly bodies: Body[] = [];
  /** A class's internal name → its index in `classes`. */
  readonly classIndex = new Map<string, number>();
  readonly imported: ImportedMember[] = [];
  readonly importByAddr = new Map<number, ImportedMember>();
  /** The program's own fields, from FIELD_BASE. */
  readonly fields: OwnField[] = [];
  /** A field's address (its own or an import's) → the instructions that read or write it. */
  readonly fieldRefs = new Map<number, number[]>();
  /** A class (internal name) → the instructions that name it: new, checkcast, instanceof, anewarray, ldc. */
  readonly classRefs = new Map<string, number[]>();
  /** Instruction index → the exception handlers whose protected range or handler starts there. */
  readonly regions = new Map<number, { handler: Handler; part: 'try' | 'handler' }[]>();
  /** invokedynamic call sites: where they go is decided at run time. */
  dynamicCalls = 0;
  /** The function the program starts at, by Main-Class or `main`. */
  entry: Fn | undefined;
  /** The newest class file version, for the platform label: [major, minor]. */
  version: [number, number] = [0, 0];
  kotlin = false;
  private readonly methodKey = new Map<string, number>();
  private readonly fieldKey = new Map<string, number>();
  private readonly importKey = new Map<string, ImportedMember>();
  private readonly resolved = new Map<number, Fn | null>();
  private readonly fieldResolved = new Map<number, number>();
  private readonly stringKey = new Map<string, number>();

  constructor(
    readonly classes: ClassFile[],
    readonly container: Container,
  ) {
    super();
    classes.forEach((cf, k) => this.classIndex.set(cf.name, k));
  }

  archLabel(): string {
    return 'JVM';
  }

  override platformLabel(): string | undefined {
    const [major, minor] = this.version;
    if (!major) return undefined;
    return `${this.kotlin ? 'Kotlin · ' : ''}Java ${javaRelease(major)}${minor === 0xffff ? ` (${t('platform', 'preview')})` : ''}`;
  }

  /** `L12`: the pc an address is at in its method. */
  override labelName(addr: number): string {
    const fn = this.functions[this.functionOfIndex(this.indexOf(addr))];
    return fn ? `L${addr - fn.addr}` : `L${addr.toString(16)}`;
  }

  bodyOf(index: number): Body | undefined {
    return this.bodies[this.functionOfIndex(index)];
  }

  /** The class an instruction is in. */
  classOf(index: number): ClassFile {
    return this.classes[this.bodyOf(index)?.cls ?? 0]!;
  }

  /** Where an instruction is in its class file. */
  fileOffset(index: number): number {
    const body = this.bodyOf(index);
    return body ? body.code.offset + (this.offsets[index]! - body.base) : -1;
  }

  /** The pc of an instruction in its method. */
  pc(index: number): number {
    const body = this.bodyOf(index);
    return body ? this.offsets[index]! - body.base : 0;
  }

  insn(index: number, into?: JvmInsn): JvmInsn {
    const body = this.bodyOf(index);
    if (!body) {
      const insn = into ?? new JvmInsn();
      insn.op = undefined;
      insn.m = '.byte';
      insn.len = 1;
      return insn;
    }
    const cf = this.classes[body.cls]!;
    return decodeAt(cf.bytes, body.code.offset, this.fileOffset(index), body.code.offset + body.code.length, into);
  }

  /** The function of a method of a class, when it has code. */
  methodFunction(cls: number, method: Method): Fn | undefined {
    const at = this.methodKey.get(`${cls}:${method.name}${method.descriptor}`);
    return at === undefined ? undefined : this.functions[at];
  }

  /** A method of the program by its class, name and descriptor, looked for in the class, its super classes and its interfaces. */
  findMethod(owner: string, name: string, descriptor: string): Fn | undefined {
    const seen = new Set<number>();
    const walk = (cls: number | undefined): Fn | undefined => {
      if (cls === undefined || seen.has(cls)) return undefined;
      seen.add(cls);
      const at = this.methodKey.get(`${cls}:${name}${descriptor}`);
      if (at !== undefined) return this.functions[at];
      const cf = this.classes[cls]!;
      const found = walk(this.classIndex.get(cf.className(cf.superClass)));
      if (found) return found;
      for (const i of cf.interfaces) {
        const inInterface = walk(this.classIndex.get(cf.className(i)));
        if (inInterface) return inInterface;
      }
      return undefined;
    };
    return walk(this.classIndex.get(owner));
  }

  /** The function or import a method reference of a class reaches. */
  callee(cls: number, index: number): Fn | undefined {
    const key = cls * 65536 + index;
    const cached = this.resolved.get(key);
    if (cached !== undefined) return cached ?? undefined;
    const cf = this.classes[cls]!;
    const tag = cf.tags[index];
    let found: Fn | undefined;
    if (tag === CONSTANT.Methodref || tag === CONSTANT.InterfaceMethodref) {
      const { owner, name, descriptor } = cf.member(index);
      found = this.findMethod(owner, name, descriptor) ?? this.importOf(owner, name, descriptor, false);
    } else if (tag === CONSTANT.MethodHandle) {
      const { kind, reference } = cf.handle(index);
      found = kind >= 5 ? this.callee(cls, reference) : undefined;
    }
    this.resolved.set(key, found ?? null);
    return found;
  }

  /** The address of a field a Fieldref of a class names: the program's own field, or an import. */
  fieldAddr(cls: number, index: number): number {
    const key = cls * 65536 + index;
    const cached = this.fieldResolved.get(key);
    if (cached !== undefined) return cached;
    const cf = this.classes[cls]!;
    const { owner, name, descriptor } = cf.member(index);
    let addr = -1;
    // Declared in the class or one of its super classes here.
    const seen = new Set<number>();
    for (let c = this.classIndex.get(owner); c !== undefined && !seen.has(c); ) {
      seen.add(c);
      const at = this.fieldKey.get(`${c}:${name}:${descriptor}`);
      if (at !== undefined) {
        addr = FIELD_BASE + at;
        break;
      }
      const sup = this.classes[c]!;
      c = this.classIndex.get(sup.className(sup.superClass));
    }
    if (addr < 0) addr = this.importOf(owner, name, descriptor, true).addr;
    this.fieldResolved.set(key, addr);
    return addr;
  }

  private importOf(owner: string, name: string, descriptor: string, field: boolean): ImportedMember {
    const key = `${owner}.${name}:${descriptor}`;
    let member = this.importKey.get(key);
    if (!member) {
      const java = javaName(owner);
      const dot = owner.startsWith('[') ? -1 : owner.lastIndexOf('/');
      member = {
        addr: IMPORT_BASE + this.imported.length,
        first: -1,
        count: 0,
        name: `${java}::${name}`,
        full: field ? `${javaName(methodTypes(`()${descriptor}`).ret)} ${java}.${name}` : `${methodTypes(descriptor).ret} ${java}.${name}(${methodTypes(descriptor).params.join(', ')})`,
        raw: name,
        kind: 'import',
        owner,
        member: name,
        descriptor,
        field,
        package: dot < 0 ? '' : owner.slice(0, dot).replace(/\//g, '.'),
      };
      this.importKey.set(key, member);
      this.imported.push(member);
      this.importByAddr.set(member.addr, member);
    }
    return member;
  }

  /** The address of a string constant's text, made when it is first seen. */
  stringAddr(text: string): number {
    let addr = this.stringKey.get(text);
    if (addr === undefined) {
      addr = STRING_BASE + this.strings.length;
      this.stringKey.set(text, addr);
      const ref: StringRef = { addr, text, section: 'ldc', kind: 'const' };
      this.strings.push(ref);
      this.stringAt.set(addr, ref);
    }
    return addr;
  }

  dataAt(addr: number): DataAt {
    const string = this.stringAt.get(addr);
    return string ? { kind: 'string', text: string.text } : undefined;
  }

  /** The handlers of the method an instruction is in. */
  handlersOf(index: number): Handler[] {
    return this.bodyOf(index)?.code.handlers ?? [];
  }

  /** Registers the classes' methods and fields; called once, before the code is read. */
  index(): void {
    let base = CODE_BASE;
    this.classes.forEach((cf, cls) => {
      cf.fields.forEach((field) => {
        this.fieldKey.set(`${cls}:${field.name}:${field.descriptor}`, this.fields.length);
        this.fields.push({ cls, name: field.name, descriptor: field.descriptor, access: field.access });
      });
      const owner = javaName(cf.name);
      const visible = !!(cf.access & 0x0001);
      for (const method of cf.methods) {
        if (!method.code || !method.code.length) continue;
        const types = methodTypes(method.descriptor);
        const mods = modifiers(method.access, 'method');
        const fn: Fn = {
          addr: base,
          first: 0,
          count: 0,
          name: `${owner}::${method.name}`,
          full: `${mods ? `${mods} ` : ''}${method.name === '<init>' || method.name === '<clinit>' ? '' : `${types.ret} `}${owner}.${method.name}(${types.params.join(', ')})`,
          raw: method.name,
          kind: visible && method.access & 0x0001 ? 'export' : 'symbol',
        };
        this.methodKey.set(`${cls}:${method.name}${method.descriptor}`, this.functions.length);
        this.functions.push(fn);
        this.bodies.push({ cls, method, code: method.code, base });
        base += Math.ceil((method.code.length + 1) / 16) * 16;
      }
      if (cf.major > this.version[0] || (cf.major === this.version[0] && cf.minor > this.version[1])) this.version = [cf.major, cf.minor];
      if (!this.kotlin && cf.annotations().includes('Lkotlin/Metadata;')) this.kotlin = true;
    });
  }
}

/* ------------------------------------------------------------------ *
 * Statements for the HLA64 view
 * ------------------------------------------------------------------ */

/** Bits of the kinds the grouping looks at. */
const KIND = { BARRIER: 1, PURE: 2, NEW: 4, INIT: 8, ARRAY: 16, ARRAY_STORE: 32, INT: 64, OPAQUE: 128 } as const;

/** The stack operations whose effect depends on what is on the stack: pop2 … swap. */
const STACK_OP = { POP2: 0x58, DUP: 0x59, DUP_X1: 0x5a, DUP_X2: 0x5b, DUP2: 0x5c, DUP2_X1: 0x5d, DUP2_X2: 0x5e, SWAP: 0x5f } as const;

/** A value on the stack while the statements are grouped: the instructions that made it. */
interface Node {
  start: number;
  end: number;
  /** It can be written as an expression inside the instruction that takes it. */
  ok: boolean;
  /** What kind of value (KIND_CODE): a long or a double is one value of two slots. */
  kind: number;
  /** Its instructions start with a dup: the line must also take the value the dup copied, right below it. */
  copy?: boolean;
  /** The lower of the two copies one dup2 makes: it ends where the copy above it starts. */
  twin?: boolean;
  /** A `new` its `dup` has copied: the object is made by the constructor that takes the copy. */
  construct?: boolean;
  /** The copy of a `new` that the constructor takes. */
  init?: boolean;
  /** A new array: how many of its elements, from the first, the stores after it have set. */
  fill?: number;
  /** A new array its `dup` has copied for a store; and that copy. */
  filling?: boolean;
  fillCopy?: boolean;
}

/**
 * Marks the runs of instructions that make one statement of the HLA64 view, the way the .NET and
 * WebAssembly analyses do: an instruction that takes values made right before it, one after
 * another, each an expression, joins them into its line; when it leaves nothing on the stack the
 * line is a statement. A value does not cross a label or the start of a handler, a branch or an
 * instruction that cannot be decoded. `dup` and `dup2` copy only variables and constants, which
 * can be written twice — and `new C; dup; …; invokespecial C.<init>` is one value, `new C(…)`, as is
 * an array with the stores that fill it from its first element (`new int[n]; dup; 0; v; iastore…`);
 * the other stack operations (swap, dup_x1 …) end a run, and a method handle, a method type or a
 * dynamic constant is not a value a line can write. src/core/jvm/hla.ts writes the lines and
 * must agree with this on what makes one.
 */
function groupStatements(program: JvmProgram, flags: Uint8Array, first: number, end: number, pops: Int16Array, pushes: Int8Array, pushKinds: Uint8Array, kinds: Uint8Array, stackOps: Uint8Array, ints: Int32Array): void {
  let nodes: Node[] = [];
  const folds = (count: number, at: number): boolean => {
    if (count > nodes.length) return false;
    let expected = at;
    for (let j = nodes.length - 1; j >= nodes.length - count; j--) {
      const node = nodes[j]!;
      if (!node.ok || (node.end !== expected - 1 && !(node.twin && node.end === expected))) return false;
      expected = node.start;
    }
    return true;
  };
  const single = (node: Node | undefined, i: number) => !!node && node.ok && node.start === node.end && !!(kinds[node.start]! & KIND.PURE) && node.end < i;
  for (let i = first; i < end; i++) {
    if (i === first || flags[i]! & IF.LABEL) {
      nodes = [];
      // A handler starts with the exception on the stack: a value no line can name.
      for (const { part } of program.regions.get(i) ?? []) if (part === 'handler' && !nodes.length) nodes.push({ start: -2, end: -2, ok: false, kind: 5 });
    }
    const op = stackOps[i]!;
    if (op) {
      const top = nodes[nodes.length - 1];
      const below = nodes[nodes.length - 2];
      if (op === STACK_OP.POP2 && top && isWide(top.kind)) {
        // pop2 of a long or a double: one value thrown away, as pop does.
      } else if (op === STACK_OP.DUP && top) {
        if (top.ok && top.fill !== undefined && top.end === i - 1) {
          // new int[n]; dup; k; v; iastore — the array's initializer, element k = the count so far.
          top.filling = true;
          top.ok = false;
          nodes.push({ start: i, end: i, ok: true, kind: 5, copy: true, fillCopy: true });
        } else if (top.ok && top.start === top.end && top.end === i - 1 && kinds[top.start]! & KIND.NEW) {
          top.construct = true;
          top.ok = false;
          nodes.push({ start: i, end: i, ok: true, kind: 5, copy: true, init: true });
        } else {
          const pure = single(top, i) && top.end === i - 1;
          top.ok = pure;
          nodes.push({ start: i, end: i, ok: pure, kind: top.kind, copy: true });
        }
        continue;
      } else if (op === STACK_OP.DUP2 && top && isWide(top.kind)) {
        const pure = single(top, i) && top.end === i - 1;
        top.ok = pure;
        nodes.push({ start: i, end: i, ok: pure, kind: top.kind, copy: true });
        continue;
      } else if (op === STACK_OP.DUP2 && top && below && !isWide(top.kind) && !isWide(below.kind) && single(top, i) && single(below, i) && top.end === i - 1 && below.end === top.start - 1) {
        nodes.push({ start: i, end: i, ok: true, kind: below.kind, copy: true, twin: true }, { start: i, end: i, ok: true, kind: top.kind, copy: true });
        continue;
      } else {
        nodes = [];
        continue;
      }
    }
    // pop2 that got here throws away one long or double.
    const popped = op === STACK_OP.POP2 ? 1 : pops[i]!;
    const pushed = pushes[i]!;
    if (pushed < 0 || (kinds[i]! & KIND.BARRIER && pushed > 0)) {
      nodes = [];
      continue;
    }
    const fold = folds(popped, i);
    const bottom = fold && popped ? nodes[nodes.length - popped]! : undefined;
    const start = bottom ? bottom.start : i;
    const copy = bottom ? !!bottom.copy : false;
    if (kinds[i]! & KIND.INIT && bottom?.init) {
      const made = nodes[nodes.length - popped - 1];
      if (made?.construct && made.end === bottom.start - 1) {
        nodes.length -= popped;
        made.end = i;
        made.ok = true;
        made.construct = false;
        continue;
      }
    }
    if (kinds[i]! & KIND.ARRAY_STORE && bottom?.fillCopy) {
      const array = nodes[nodes.length - 4];
      const at = nodes[nodes.length - 2]!;
      if (array?.filling && array.end === bottom.start - 1 && at.start === at.end && kinds[at.start]! & KIND.INT && ints[at.start] === array.fill) {
        nodes.length -= 3;
        array.end = i;
        array.ok = true;
        array.filling = false;
        array.fill!++;
        continue;
      }
    }
    if (popped > nodes.length) nodes = [];
    else nodes.length -= popped;
    if (pushed === 0) {
      // A line that takes a dup's copy without the value it copied would need that value from before it.
      if (fold && popped && !copy) for (let k = start; k < i; k++) flags[k]! |= IF.FUSE;
    } else nodes.push({ start, end: i, ok: (fold || popped === 0) && !(kinds[i]! & KIND.OPAQUE), kind: pushKinds[i]!, copy, fill: kinds[i]! & KIND.ARRAY ? 0 : undefined });
    if (kinds[i]! & KIND.BARRIER) nodes = [];
  }
}

/** Loads that read nothing but a variable or a constant: dup may copy them as text. */
const PURE_LOAD = /^(?:[ilfda]load(?:_\d|_w)?|[ilfd]const_m?\d|aconst_null|bipush|sipush|ldc(?:_w|2_w)?)$/;
const PURE = new Uint8Array(0x10000);
for (const op of allOps()) if (PURE_LOAD.test(op.name)) PURE[op.code] = 1;

/** What the value an ldc loads is: by the kind of its constant. */
function constantKind(cf: ClassFile, index: number): number {
  switch (cf.tags[index]) {
    case CONSTANT.Integer:
      return 1;
    case CONSTANT.Long:
      return 2;
    case CONSTANT.Float:
      return 3;
    case CONSTANT.Double:
      return 4;
    case CONSTANT.Dynamic: {
      const kind = descriptorKinds(`()${cf.dynamic(index).descriptor}`).ret;
      return KIND_CODE[kind] ?? 5;
    }
  }
  return 5;
}

/** In entryShape's number: the method is a constructor. */
const SHAPE_INIT = 1 << 13;

/**
 * What an instruction that names a constant pool entry does to the stack, as one number: the
 * values a call takes besides its object (bits 0–7), whether it leaves one (8–9), its kind
 * (10–12), whether the method is a constructor (13).
 */
function entryShape(cf: ClassFile, name: string, index: number): number {
  if (name.startsWith('invoke')) {
    const member = name === 'invokedynamic' ? cf.dynamic(index) : cf.member(index);
    const shape = descriptorKinds(member.descriptor);
    return Math.min(255, shape.params.length) | (shape.ret ? 1 << 8 : 0) | ((KIND_CODE[shape.ret] ?? 0) << 10) | (member.name === '<init>' ? SHAPE_INIT : 0);
  }
  if (name === 'getfield' || name === 'getstatic') return (KIND_CODE[descriptorKinds(`()${cf.member(index).descriptor}`).ret] ?? 5) << 10;
  if (name.startsWith('ldc')) return constantKind(cf, index) << 10;
  return 5 << 10;
}

export async function analyzeJvm(classes: ClassFile[], container: Container, progress: Progress = () => {}): Promise<JvmProgram> {
  const started = Date.now();
  const program = new JvmProgram(classes, container);
  program.index();
  const bodies = program.bodies;
  let capacity = 0;
  for (const body of bodies) capacity += body.code.length;
  const offsets = new Uint32Array(capacity);
  const ids = new Uint16Array(capacity);
  const flags = new Uint8Array(capacity);
  // What each instruction does to the stack, for grouping the statements of the HLA64 view: -1 pushes when it cannot be known.
  const pops = new Int16Array(capacity);
  const pushes = new Int8Array(capacity);
  const pushKinds = new Uint8Array(capacity);
  const kinds = new Uint8Array(capacity);
  const stackOps = new Uint8Array(capacity);
  // An int constant's value (iconst, bipush, sipush): an array initializer's index.
  const ints = new Int32Array(capacity);
  // Mnemonic ids by opcode (0xFFFF: not one), and pc → instruction index within a method.
  const mnemonicIds = new Int32Array(0x10000).fill(-1);
  let at = new Int32Array(1024);
  const counts: number[] = [];
  const insn = new JvmInsn();
  const shapes = new Map<number, number>();
  const CHUNK = 65536;
  let total = 0;
  let nextTick = CHUNK;
  let lastClass = -1;

  for (let f = 0; f < bodies.length; f++) {
    const body = bodies[f]!;
    const cls = body.cls;
    const cf = classes[cls]!;
    const fn = program.functions[f]!;
    const first = total;
    const code = body.code;
    const end = code.offset + code.length;
    // Branch targets inside the method, by pc, resolved once its instructions are known.
    const pending: [number, number, number][] = [];
    if (at.length < code.length) at = new Int32Array(code.length * 2);
    at.fill(-1, 0, code.length);
    for (let pos = code.offset; pos < end && total < capacity; ) {
      const i = total++;
      if (i >= nextTick) {
        nextTick += CHUNK;
        progress('decode', f, bodies.length);
        await tick();
      }
      decodeAt(cf.bytes, code.offset, pos, end, insn);
      offsets[i] = body.base + insn.at;
      at[insn.at] = i;
      const code0 = insn.op ? insn.op.code : 0xffff;
      let id = mnemonicIds[code0]!;
      if (id < 0) {
        id = program.mnemonics.length;
        mnemonicIds[code0] = id;
        program.mnemonics.push(insn.m);
        counts.push(0);
      }
      ids[i] = id;
      counts[id]!++;
      pos += insn.len;
      const op = insn.op;
      if (!op) {
        flags[i]! |= IF.UNKNOWN;
        pushes[i] = -1;
        continue;
      }
      // The stack: what it takes and leaves, and what kind of value; what a constant pool entry says is worked out once per class.
      let pop = op.pop;
      let pushed = op.push;
      let kind = KIND_CODE[op.kind] ?? 0;
      let init = false;
      const index = poolIndex(insn);
      if (op.code >= STACK_OP.POP2 && op.code <= STACK_OP.SWAP) stackOps[i] = op.code;
      else if (index && (op.flags & F.CALL || op.pop < 0 || op.push < 0 || !kind)) {
        const key = cls * 65536 + index;
        let shape = shapes.get(key);
        if (shape === undefined) {
          shape = entryShape(cf, op.name, index);
          shapes.set(key, shape);
        }
        if (op.flags & F.CALL) {
          pop = (shape & 0xff) + (op.name === 'invokestatic' || op.name === 'invokedynamic' ? 0 : 1);
          pushed = (shape >> 8) & 3;
          init = !!(shape & SHAPE_INIT);
        }
        kind = (shape >> 10) & 7;
        if (op.operand === OPERAND.DIMENSIONS) {
          pop = insn.b;
          kind = 5;
        }
      }
      pops[i] = Math.max(0, pop);
      pushes[i] = pushed;
      pushKinds[i] = kind;
      kinds[i] = (op.flags & (F.END | F.BRANCH) ? KIND.BARRIER : 0) | (PURE[op.code] ? KIND.PURE : 0) | (op.code === 0xbb ? KIND.NEW : 0) | (init && op.code === 0xb7 ? KIND.INIT : 0) |
        (op.code === 0xbc || op.code === 0xbd ? KIND.ARRAY : 0) |
        (op.code >= 0x4f && op.code <= 0x56 ? KIND.ARRAY_STORE : 0);
      // A method handle, a method type or a dynamic constant has no form in a line: its ldc stays an instruction.
      if (op.code >= 0x12 && op.code <= 0x14 && (cf.tags[index] === CONSTANT.MethodHandle || cf.tags[index] === CONSTANT.MethodType || cf.tags[index] === CONSTANT.Dynamic)) kinds[i]! |= KIND.OPAQUE;
      if ((op.code >= 0x02 && op.code <= 0x08) || op.code === 0x10 || op.code === 0x11) {
        kinds[i]! |= KIND.INT;
        ints[i] = op.code <= 0x08 ? op.code - 0x03 : insn.a;
      }

      if (op.flags & F.BRANCH) {
        flags[i]! |= IF.BRANCH;
        if (insn.targets) insn.targets.forEach((target, slot) => pending.push([i, target, slot]));
        if (op.operand === OPERAND.TABLESWITCH || op.operand === OPERAND.LOOKUPSWITCH) pending.push([i, insn.a, insn.targets!.length]);
        else pending.push([i, insn.a, -1]);
      }
      if (op.flags & F.CALL) {
        flags[i]! |= IF.CALL;
        if (op.operand === OPERAND.DYNAMIC) {
          program.dynamicCalls++;
          // The methods a call site's bootstrap is given (a lambda's body, a method reference) are taken, not called.
          const bootstrap = cf.bootstrapMethods()[cf.dynamic(index).bootstrap];
          for (const arg of bootstrap?.args ?? []) {
            if (cf.tags[arg] !== CONSTANT.MethodHandle) continue;
            const target = program.callee(cls, arg);
            if (target) append(program.dataRefs, target.addr, offsets[i]!);
          }
        } else {
          const callee = program.callee(cls, index);
          if (callee) append(program.callers, callee.addr, offsets[i]!);
        }
        continue;
      }
      switch (op.name) {
        case 'getfield':
        case 'putfield':
        case 'getstatic':
        case 'putstatic':
          append(program.fieldRefs, program.fieldAddr(cls, index), offsets[i]!);
          break;
      }
      if (index && (op.operand === OPERAND.CP8 || op.operand === OPERAND.CP16 || op.operand === OPERAND.DIMENSIONS)) {
        const tag = cf.tags[index];
        if (tag === CONSTANT.String) append(program.dataRefs, program.stringAddr(cf.utf8(cf.ref1(index))), offsets[i]!);
        else if (tag === CONSTANT.MethodHandle) {
          const target = program.callee(cls, index);
          if (target) append(program.dataRefs, target.addr, offsets[i]!);
        }
        if (tag === CONSTANT.Class) {
          const name = cf.className(index);
          append(program.classRefs, name, offsets[i]!);
        }
      }
    }
    for (const [from, target, slot] of pending) {
      const to = target >= 0 && target < code.length ? at[target]! : -1;
      if (to < 0) continue;
      flags[to]! |= IF.LABEL;
      if (slot >= 0) {
        const known = program.targets.get(from);
        if (Array.isArray(known)) known.push(to);
        else program.targets.set(from, [to]);
      } else program.targets.set(from, to);
    }
    for (const handler of code.handlers) {
      const mark = (pc: number, part: 'try' | 'handler') => {
        const index = pc < code.length ? at[pc]! : -1;
        if (index < 0) return;
        flags[index]! |= IF.LABEL;
        append(program.regions, index, { handler, part });
      };
      mark(handler.start, 'try');
      mark(handler.handler, 'handler');
    }
    fn.first = first;
    fn.count = total - first;
    groupStatements(program, flags, first, total, pops, pushes, pushKinds, kinds, stackOps, ints);
    flags[first]! |= IF.FUNCTION;
    flags[first]! &= ~IF.LABEL;
    program.functionAtIndex.set(first, f);
    // The methods of one class make one range of the listing.
    if (cls !== lastClass) {
      lastClass = cls;
      program.ranges.push({ name: `${classKind(cf)} ${javaName(cf.name)}`, first, count: 0 });
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
  program.entry = findEntry(program);
  if (program.entry) program.entry.kind = 'entry';
  progress('done', 1, 1);
  return program;
}

/** The method the program starts at: Main-Class's `main`, else the only class with one. */
function findEntry(program: JvmProgram): Fn | undefined {
  const isMain = (body: Body) => body.method.name === 'main' && (body.method.descriptor === '([Ljava/lang/String;)V' || body.method.descriptor === '()V') && !!(body.method.access & 0x0008 || body.method.descriptor === '()V');
  const mainClass = program.container.manifest.get('Main-Class')?.trim().replace(/\./g, '/');
  if (mainClass) {
    const cls = program.classIndex.get(mainClass);
    const at = program.bodies.findIndex((b) => b.cls === cls && isMain(b));
    if (at >= 0) return program.functions[at];
  }
  const mains = program.bodies.map((b, k) => (isMain(b) ? k : -1)).filter((k) => k >= 0);
  return mains.length === 1 || (mains.length && program.container.kind === 'class') ? program.functions[mains[0]!] : undefined;
}

/** The function the page opens at: the entry point, else the first public method, else the first. */
export function entryOf(program: JvmProgram): Fn | undefined {
  return program.entry ?? program.functions.find((f) => f.kind === 'export' && f.raw !== '<init>') ?? program.functions[0];
}

/* ------------------------------------------------------------------ *
 * Opening files
 * ------------------------------------------------------------------ */

/** A .jmod starts with `JM`, a version, and a ZIP. */
export const isJmod = (bytes: Uint8Array): boolean => bytes.length > 8 && bytes[0] === 0x4a && bytes[1] === 0x4d && bytes[2] === 1 && bytes[3] === 0 && isZip(bytes.subarray(4));

/** Does a ZIP hold Java classes (a JAR, a WAR), or an Android library's classes.jar (an AAR)? */
export function holdsClasses(names: string[]): boolean {
  return names.some((name) => name.endsWith('.class')) || (names.includes('classes.jar') && !names.includes('classes.dex'));
}

/** The attributes of a JAR's META-INF/MANIFEST.MF; a line starting with a space continues the one before. */
export function parseManifest(text: string): Map<string, string> {
  const out = new Map<string, string>();
  let last = '';
  for (const line of text.split(/\r?\n/)) {
    if (line.startsWith(' ') && last) out.set(last, out.get(last)! + line.slice(1));
    else {
      const colon = line.indexOf(':');
      if (colon <= 0) continue;
      last = line.slice(0, colon).trim();
      if (!out.has(last)) out.set(last, line.slice(colon + 1).trim());
    }
  }
  return out;
}

/**
 * The classes of a class file, a JAR, a .jmod or an AAR (its classes.jar), parsed and sorted by
 * name, and what the archive says about itself. Classes for other Java releases
 * (META-INF/versions/…) are counted, not read: the program is the classes every release runs.
 */
export async function readClasses(bytes: Uint8Array, progress: Progress = () => {}): Promise<{ classes: ClassFile[]; container: Container }> {
  if (isClassFile(bytes)) {
    const cf = new ClassFile(bytes, '');
    return { classes: [cf], container: { kind: 'class', manifest: new Map(), resources: [], versioned: 0, broken: [] } };
  }
  const jmod = isJmod(bytes);
  const zip = jmod ? bytes.subarray(4) : bytes;
  if (!isZip(zip)) throw new NotClass(t('open', 'This is not a class file or a JAR.'));
  const entries = zipEntries(zip);
  const names = entries.map((e) => e.name);
  if (!names.some((name) => name.endsWith('.class'))) {
    const inner = entries.find((e) => e.name === 'classes.jar');
    if (inner) {
      const read = await readClasses(await zipRead(zip, inner), progress);
      read.container.from = 'classes.jar';
      return read;
    }
    throw new NotZip(t('open', 'The archive holds no Java classes.'));
  }
  const container: Container = { kind: jmod ? 'jmod' : 'jar', manifest: new Map(), resources: [], versioned: 0, broken: [] };
  const wanted = entries.filter((e) => {
    if (!e.name.endsWith('.class')) {
      if (!e.name.endsWith('/')) container.resources.push({ name: e.name, size: e.size });
      return false;
    }
    if (/^META-INF\/versions\/\d+\//.test(e.name)) {
      container.versioned++;
      return false;
    }
    return true;
  });
  const manifest = entries.find((e) => e.name.toUpperCase() === 'META-INF/MANIFEST.MF');
  if (manifest) container.manifest = parseManifest(new TextDecoder().decode(await zipRead(zip, manifest)));
  const classes: ClassFile[] = [];
  const BATCH = 64;
  for (let k = 0; k < wanted.length; k += BATCH) {
    progress('decode', k, wanted.length);
    const batch = wanted.slice(k, k + BATCH);
    const read = await Promise.all(batch.map((e) => zipRead(zip, e).catch((err: unknown) => err as Error)));
    read.forEach((data, j) => {
      const name = batch[j]!.name;
      if (data instanceof Error) container.broken.push({ name, reason: data.message });
      else {
        try {
          classes.push(new ClassFile(data, name));
        } catch (err) {
          container.broken.push({ name, reason: err instanceof Error ? err.message : String(err) });
        }
      }
    });
  }
  classes.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  return { classes, container };
}
