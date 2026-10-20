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
 *
 * The reading and the pass run in the core (crates/core/src/jvm/program.rs); what is here takes
 * their results and answers the page's questions about them. The classes stay in the core: what the
 * page shows of one — an instruction as javap prints it, a method's card, a class's card — the core
 * writes when it is asked (crates/core/src/jvm/page.rs), and it is kept here once asked for.
 */

import { BytecodeProgram, type DataAt, type Fn, type Progress, type StringRef, tick } from '../disassembly';
import { engine as currentEngine, JVM_TEXT, JVM_VIEW, JvmOpenFailed, JvmSession, loadEngine, type RefMap } from '../engine/engine';
import { rounds, type HlaLine } from '../hla';
import { t } from '../i18n';
import { isZip, NotZip } from '../archive';

/** Why bytes are not a class file, or not one the core can read. */
export class NotClass extends Error {}

/** The tags of the constant pool. */
export const CONSTANT = {
  Utf8: 1, Integer: 3, Float: 4, Long: 5, Double: 6, Class: 7, String: 8, Fieldref: 9, Methodref: 10, InterfaceMethodref: 11,
  NameAndType: 12, MethodHandle: 15, MethodType: 16, Dynamic: 17, InvokeDynamic: 18, Module: 19, Package: 20,
} as const;

/** The class file's magic number. */
export const isClassFile = (bytes: Uint8Array): boolean =>
  // 0xCAFEBABE is also a universal Mach-O file's: there the next word counts its slices (a few), here it is the version (45 or more).
  bytes.length >= 10 && bytes[0] === 0xca && bytes[1] === 0xfe && bytes[2] === 0xba && bytes[3] === 0xbe && ((bytes[6]! << 8) | bytes[7]!) >= 45;

/** An instruction as the page shows it (crates/wasm/src/jvm_page.rs, `jvm_insn`). */
export interface JvmInsn {
  /** The opcode: its code, its kind of operand (OPERAND), its F flags; undefined for a byte that is not one. */
  op: { code: number; operand: number; flags: number } | undefined;
  /** As printed, `.byte` for what is not an instruction. */
  m: string;
  /** Its pc (offset in the method's code), and its length in bytes. */
  at: number;
  len: number;
  /** A slot, a constant, a constant pool index, a branch's target pc, an array type, a switch's default target. */
  a: number;
  /** iinc's constant, invokeinterface's count, multianewarray's dimensions. */
  b: number;
  /** A switch: the value of each case and where it goes (pcs), in the order of the instruction; null for the others. */
  keys: number[] | null;
  targets: number[] | null;
  /** The operand as javap prints it, and the whole instruction. */
  operand: string;
  text: string;
  /** The constant pool index it names (0: none), that entry's tag, and javap's comment for it. */
  pool: number;
  tag: number;
  comment: string;
  /** A String constant's text. */
  string: string | null;
  /** The local it reads or writes, as the class names it (`count: int`), or ''. */
  local: string;
  /** Its bytes in hex: the first five, the first twenty-four. */
  bytes5: string;
  bytes24: string;
  /** invokedynamic: the bootstrap method's comment (null: none) and its arguments: index, tag, comment. */
  dynamic: { method: string | null; args: [number, number, string][] } | null;
}

/** A row of a method's exception table: its protected range, its handler, what it catches (`any` for a finally). */
export interface Handler {
  start: number;
  end: number;
  handler: number;
  catch: string;
}

/** What a method's card and header show (`jvm_method`). */
export interface MethodInfo {
  access: number;
  modifiers: string;
  descriptor: string;
  signature: string | null;
  exceptions: string[];
  /** Its class as Java names it, and where the class was in the archive. */
  class: string;
  path: string;
  source: string | null;
  firstLine: number | null;
  codeLength: number;
  maxStack: number;
  maxLocals: number;
  /** slot, name, type as Java writes it, start, length. */
  locals: [number, string, string, number, number][];
  handlers: Handler[];
  /** The parameters of its HLA64 header (name, type) and its return type. */
  params: [string, string][];
  ret: string;
}

/** What a class's card shows (`jvm_class_info`). */
export interface ClassInfo {
  java: string;
  modifiers: string;
  kind: string;
  extends: string | null;
  implements: string[];
  source: string | null;
  /** Entries in its constant pool. */
  pool: number;
  attributes: string[];
  module: { name: string; version: string; requires: string[]; exports: string[]; opens: string[]; uses: string[]; provides: string[] } | null;
  /** name, descriptor, access, declaration. */
  fields: [string, string, number, string][];
}

export const STRING_BASE = 0x40000000;
export const FIELD_BASE = 0x50000000;
export const IMPORT_BASE = 0x60000000;

/** A member of a class the program does not have: a method or a field its code uses. */
export interface ImportedMember extends Fn {
  /** The class as the code names it (`java/io/PrintStream`), the member and its descriptor. */
  owner: string;
  /** The class as Java writes it (`java.io.PrintStream`). */
  ownerJava: string;
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
  /** Its declaration: `private int hello.More.count`. */
  decl: string;
}

/** A method with code: its class (an index into the classes), the method, and where its code is placed. */
export class Body {
  constructor(
    readonly cls: number,
    /** Its index in the class's methods. */
    readonly methodIndex: number,
    readonly base: number,
    readonly access: number,
    /** Where its bytecode is in the class file, and its length. */
    readonly codeOffset: number,
    readonly codeLength: number,
  ) {}
}

/** What the page shows of a class without reading it: its name, where it was, what it is, its version and source file. */
export interface ClassSummary {
  name: string;
  path: string;
  kind: 'class' | 'interface' | 'annotation' | 'enum' | 'record' | 'module';
  access: number;
  major: number;
  minor: number;
  source: string | null;
  /** As the page shows them: the name as Java writes it, the modifiers, the Java release. */
  java: string;
  modifiers: string;
  release: string;
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

/** A handler's protected range or the handler itself starts at an instruction. */
export interface Region {
  handler: Handler;
  part: 'try' | 'handler';
}

/** Closes a program's session in the core once the program is gone. */
const sessions = new FinalizationRegistry<JvmSession>((session) => session.close());

/** Binary search of a sorted key list: the key's position, or -1. */
function find(keys: ArrayLike<number>, key: number): number {
  let lo = 0;
  let hi = keys.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const at = keys[mid]!;
    if (at === key) return mid;
    if (at < key) lo = mid + 1;
    else hi = mid - 1;
  }
  return -1;
}

/**
 * The bytecode of Java classes, laid out one method after another at addresses of its own; a
 * switch's targets are its cases', then the default's. The core (crates/core/src/jvm/program.rs)
 * reads the classes and makes the analysis; they stay in its session.
 */
export class JvmProgram extends BytecodeProgram {
  readonly arch = 'jvm';
  /** The code of each function of `functions`. */
  readonly bodies: Body[] = [];
  /** Every class of the program, sorted by name. */
  classInfo: ClassSummary[] = [];
  readonly imported: ImportedMember[] = [];
  readonly importByAddr = new Map<number, ImportedMember>();
  /** A field's address (its own or an import's) → the instructions that read or write it. */
  fieldRefs: Map<number, number[]> = new Map();
  /** invokedynamic call sites: where they go is decided at run time. */
  dynamicCalls = 0;
  /** The function the program starts at, by Main-Class or `main`. */
  entry: Fn | undefined;
  /** The newest class file version, for the platform label: [major, minor]. */
  version: [number, number] = [0, 0];
  /** The Java release of that version. */
  release = '';
  kotlin = false;
  container: Container = { kind: 'class', manifest: new Map(), resources: [], versioned: 0, broken: [] };
  private fieldStarts = new Uint32Array(1);
  private calleeKeys = new Float64Array(0);
  private calleeValues = new Float64Array(0);
  private fieldKeys = new Float64Array(0);
  private fieldValues = new Float64Array(0);
  private targetIndex = new Uint32Array(0);
  private targetStarts = new Uint32Array(1);
  private targetValues = new Uint32Array(0);
  private readonly stringKey = new Map<string, number>();
  private readonly methods = new Map<number, MethodInfo>();
  private readonly classes = new Map<number, ClassInfo>();

  constructor(
    /** The file, to read and analyse again should the core's session be lost. */
    private readonly file: Uint8Array,
    private session: JvmSession | null,
  ) {
    super();
  }

  archLabel(): string {
    return 'JVM';
  }

  override platformLabel(): string | undefined {
    const [major, minor] = this.version;
    if (!major) return undefined;
    return `${this.kotlin ? 'Kotlin · ' : ''}Java ${this.release}${minor === 0xffff ? ` (${t('platform', 'preview')})` : ''}`;
  }

  /** `L12`: the pc an address is at in its method. */
  override labelName(addr: number): string {
    const fn = this.functions[this.functionOfIndex(this.indexOf(addr))];
    return fn ? `L${addr - fn.addr}` : `L${addr.toString(16)}`;
  }

  override branchTargets(index: number): number[] {
    const k = find(this.targetIndex, index);
    return k < 0 ? [] : Array.from(this.targetValues.subarray(this.targetStarts[k]!, this.targetStarts[k + 1]!));
  }

  /**
   * The HLA64 line of the instructions first..last (one statement), or null
   * when they cannot be written as one — then each stays an instruction.
   * The core writes it (crates/core/src/jvm/hla.rs); a string it names gets
   * its address here, as one the strings page lists.
   */
  hla(first: number, last: number): HlaLine | null {
    const session = this.liveSession();
    const line = rounds<HlaLine & { none?: true }>(
      (input, _kind, _addr, text) => input.f64(this.stringAddr(text ?? '')),
      () => {},
      (input) => session.engine.jvmHla(session.handle, first, last, input),
    );
    return line.none ? null : { text: line.text, words: line.words };
  }

  /** What a method's card and header show, by its function's number. */
  method(fnIndex: number): MethodInfo {
    let found = this.methods.get(fnIndex);
    if (!found) {
      const session = this.liveSession();
      const m = session.engine.pageJson<Omit<MethodInfo, 'handlers'> & { handlers: [number, number, number, string][] }>(() => session.engine.x.jvm_method(session.handle, fnIndex));
      found = { ...m, handlers: m.handlers.map(([start, end, handler, c]) => ({ start, end, handler, catch: c })) };
      this.methods.set(fnIndex, found);
    }
    return found;
  }

  /** What a class's card shows, by its number. */
  classView(k: number): ClassInfo {
    let found = this.classes.get(k);
    if (!found) {
      const session = this.liveSession();
      found = session.engine.pageJson<ClassInfo>(() => session.engine.x.jvm_class_info(session.handle, k));
      this.classes.set(k, found);
    }
    return found;
  }

  /** What a method's code calls (the constant of each call that is not invokedynamic, in order), how many invokedynamic calls, and the strings it loads. */
  functionRefs(fnIndex: number): { calls: number[]; dynamic: number; strings: string[] } {
    const session = this.liveSession();
    return session.engine.pageJson(() => session.engine.x.jvm_fn_refs(session.handle, fnIndex));
  }

  /** A string as javap writes it in a comment. */
  escape(text: string): string {
    return this.liveSession().engine.jvmEscape(text);
  }

  /** The core's session, opened (and analysed) again if the core was restarted since. */
  private liveSession(): JvmSession {
    const engine = currentEngine();
    if (this.session && this.session.engine === engine) return this.session;
    if (this.session) sessions.unregister(this);
    const session = new JvmSession(engine, this.file, true);
    while (!session.step(1 << 20));
    this.session = session;
    sessions.register(this, session, this);
    return session;
  }

  /** Closes the core's session now rather than when the program is collected; it is opened again if a class or a line is asked for. */
  override dispose(): void {
    if (!this.session) return;
    sessions.unregister(this);
    if (this.session.engine === currentEngine()) this.session.close();
    this.session = null;
  }

  bodyOf(index: number): Body | undefined {
    return this.bodies[this.functionOfIndex(index)];
  }

  /** Where an instruction is in its class file. */
  fileOffset(index: number): number {
    const body = this.bodyOf(index);
    return body ? body.codeOffset + (this.offsets[index]! - body.base) : -1;
  }

  /** The pc of an instruction in its method. */
  pc(index: number): number {
    const body = this.bodyOf(index);
    return body ? this.offsets[index]! - body.base : 0;
  }

  /** An instruction as the page shows it, written by the core. */
  insn(index: number): JvmInsn {
    const session = this.liveSession();
    const raw = session.engine.pageJson<(Omit<JvmInsn, 'op'> & { op: [number, number, number] | null }) | null>(() => session.engine.x.jvm_insn(session.handle, index));
    if (!raw) return { op: undefined, m: '.byte', at: 0, len: 1, a: 0, b: 0, keys: null, targets: null, operand: '', text: '', pool: 0, tag: 0, comment: '', string: null, local: '', bytes5: '', bytes24: '', dynamic: null };
    const op = raw.op;
    const switches = op !== null && (op[1] === 15 || op[1] === 16);
    return { ...raw, op: op ? { code: op[0], operand: op[1], flags: op[2] } : undefined, keys: switches ? raw.keys : null, targets: switches ? raw.targets : null };
  }

  /** The function or import a method reference of a class reaches (one the code uses). */
  callee(cls: number, index: number): Fn | undefined {
    const k = find(this.calleeKeys, cls * 65536 + index);
    const addr = k < 0 ? -1 : this.calleeValues[k]!;
    if (addr < 0) return undefined;
    return addr >= IMPORT_BASE ? this.importByAddr.get(addr) : this.functionAt(addr);
  }

  /** The address of a field a Fieldref of a class names (one the code uses): the program's own field, or an import. */
  fieldAddr(cls: number, index: number): number {
    const k = find(this.fieldKeys, cls * 65536 + index);
    return k < 0 ? -1 : this.fieldValues[k]!;
  }

  /** How many fields the program's classes declare. */
  get fieldCount(): number {
    return this.fieldStarts[this.fieldStarts.length - 1]!;
  }

  /** A field of the program's own classes, by its number (its address less FIELD_BASE). */
  field(i: number): OwnField | undefined {
    if (i < 0 || i >= this.fieldCount) return undefined;
    // The last class whose fields start at or before it.
    let lo = 0;
    let hi = this.fieldStarts.length - 2;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (this.fieldStarts[mid]! <= i) lo = mid;
      else hi = mid - 1;
    }
    const [name, descriptor, access, decl] = this.classView(lo).fields[i - this.fieldStarts[lo]!]!;
    return { cls: lo, name, descriptor, access, decl };
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
    const f = this.functionOfIndex(index);
    return f < 0 ? [] : this.method(f).handlers;
  }

  /** The exception handlers whose protected range or handler starts at an instruction, in the method's order. */
  regionsAt(index: number): Region[] {
    const body = this.bodyOf(index);
    if (!body) return [];
    const pc = this.pc(index);
    const out: Region[] = [];
    for (const handler of this.handlersOf(index)) {
      if (handler.start === pc) out.push({ handler, part: 'try' });
      if (handler.handler === pc) out.push({ handler, part: 'handler' });
    }
    return out;
  }

  /** Takes the analysis from the core's session. */
  take(session: JvmSession): void {
    const addrOf = (index: number) => this.offsets[index] ?? 0;
    this.offsets = session.copy(JVM_VIEW.offsets, Uint32Array);
    this.mnemonicIds = session.copy(JVM_VIEW.mnemonicIds, Uint16Array);
    this.flags = session.copy(JVM_VIEW.flags, Uint8Array);
    this.totalInstructions = this.offsets.length;
    const mnemonics = session.text(JVM_TEXT.mnemonics);
    if (mnemonics) this.mnemonics.push(...mnemonics.split('\n'));
    this.tally([...session.copy(JVM_VIEW.counts, Uint32Array)]);
    const refs = (id: number): RefMap => session.refs(id, addrOf);
    Object.assign(this, { callers: refs(JVM_VIEW.callers), dataRefs: refs(JVM_VIEW.dataRefs) });
    this.fieldRefs = refs(JVM_VIEW.fieldRefs);
    this.targetIndex = session.copy(JVM_VIEW.targetIndex, Uint32Array);
    this.targetStarts = session.copy(JVM_VIEW.targetStarts, Uint32Array);
    this.targetValues = session.copy(JVM_VIEW.targetValues, Uint32Array);
    this.fieldStarts = session.copy(JVM_VIEW.fieldStarts, Uint32Array);
    this.calleeKeys = session.copy(JVM_VIEW.calleeKeys, Float64Array);
    this.calleeValues = session.copy(JVM_VIEW.calleeValues, Float64Array);
    this.fieldKeys = session.copy(JVM_VIEW.fieldKeys, Float64Array);
    this.fieldValues = session.copy(JVM_VIEW.fieldValues, Float64Array);
    this.classInfo = session
      .json<[string, string, ClassSummary['kind'], number, number, number, string | null, string, string, string][]>(JVM_TEXT.classes)
      .map(([name, path, kind, access, major, minor, source, java, modifiers, release]) => ({ name, path, kind, access, major, minor, source, java, modifiers, release }));

    // A class's name as Java writes it, made once for all its methods.
    const owner = (cls: number) => this.classInfo[cls]!.java;
    const b = session.copy(JVM_VIEW.bodies, Uint32Array);
    const fns = session.json<[string, string, string, Fn['kind']][]>(JVM_TEXT.functions);
    fns.forEach(([raw, prefix, params, kind], f) => {
      const at = f * 8;
      const cls = b[at]!;
      this.bodies.push(new Body(cls, b[at + 1]!, b[at + 2]!, b[at + 3]!, b[at + 4]!, b[at + 5]!));
      this.functions.push({ addr: b[at + 2]!, first: b[at + 6]!, count: b[at + 7]!, name: `${owner(cls)}::${raw}`, full: `${prefix}${owner(cls)}.${raw}(${params})`, raw, kind });
      this.functionAtIndex.set(b[at + 6]!, f);
    });
    const r = session.copy(JVM_VIEW.ranges, Uint32Array);
    for (let k = 0; k + 2 < r.length; k += 3) this.ranges.push({ name: `${this.classInfo[r[k + 2]!]!.kind} ${owner(r[k + 2]!)}`, first: r[k]!, count: r[k + 1]! });
    for (const [owner, member, descriptor, field, ret, params, java] of session.json<[string, string, string, number, string, string, string][]>(JVM_TEXT.imports)) {
      const dot = owner.startsWith('[') ? -1 : owner.lastIndexOf('/');
      const m: ImportedMember = {
        addr: IMPORT_BASE + this.imported.length,
        first: -1,
        count: 0,
        name: `${java}::${member}`,
        full: field ? `${ret} ${java}.${member}` : `${ret} ${java}.${member}(${params})`,
        raw: member,
        kind: 'import',
        owner,
        ownerJava: java,
        member,
        descriptor,
        field: !!field,
        package: dot < 0 ? '' : owner.slice(0, dot).replace(/\//g, '.'),
      };
      this.imported.push(m);
      this.importByAddr.set(m.addr, m);
    }
    for (const text of session.json<string[]>(JVM_TEXT.strings)) this.stringAddr(text);
    const meta = session.json<{ version: [number, number]; release: string; kotlin: boolean; dynamicCalls: number; entry: number }>(JVM_TEXT.meta);
    this.version = meta.version;
    this.release = meta.release;
    this.kotlin = meta.kotlin;
    this.dynamicCalls = meta.dynamicCalls;
    this.entry = meta.entry < 0 ? undefined : this.functions[meta.entry];
    const c = session.json<{ kind: Container['kind']; manifest: [string, string][]; resources: [string, number][]; versioned: number; broken: [string, string][]; from: boolean }>(JVM_TEXT.container);
    this.container = {
      kind: c.kind,
      manifest: new Map(c.manifest),
      resources: c.resources.map(([name, size]) => ({ name, size })),
      versioned: c.versioned,
      broken: c.broken.map(([name, reason]) => ({ name, reason })),
      ...(c.from ? { from: 'classes.jar' } : {}),
    };
  }
}

/** Opens a file in the core, saying in the page's words why it cannot be. */
function openSession(bytes: Uint8Array, analyse: boolean): JvmSession {
  try {
    return new JvmSession(currentEngine(), bytes, analyse);
  } catch (err) {
    if (!(err instanceof JvmOpenFailed)) throw err;
    const r = err.reason;
    if ('text' in r) throw r.error === 'zip' ? new NotZip(r.text) : new NotClass(r.text);
    throw r.error === 'notJava' ? new NotClass(t('open', 'This is not a class file or a JAR.')) : new NotZip(t('open', 'The archive holds no Java classes.'));
  }
}

/** The instructions the core decodes between two looks at the page. */
const BUDGET = 1 << 17;

/**
 * Reads and analyses a class file, a JAR, a .jmod or an AAR (its classes.jar) in the core: the
 * classes sorted by name; classes for other Java releases (META-INF/versions/…) are counted, not
 * read — the program is the classes every release runs.
 */
export async function analyzeJvm(bytes: Uint8Array, progress: Progress = () => {}): Promise<JvmProgram> {
  const started = Date.now();
  await loadEngine();
  const session = openSession(bytes, true);
  let program: JvmProgram;
  try {
    while (!session.step(BUDGET)) {
      progress('decode', session.done, session.total);
      await tick();
    }
    program = new JvmProgram(bytes, session);
    program.take(session);
  } catch (err) {
    session.close();
    throw err;
  }
  sessions.register(program, session, program);
  program.decodeMs = Date.now() - started;
  progress('decode', 1, 1);
  progress('done', 1, 1);
  return program;
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
