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
 *
 * The core reads the metadata and runs the pass (crates/core/src/cil/); what
 * is here takes its results once and asks the session, which stays open, for
 * what the page shows — an instruction as ildasm prints it, a method's card,
 * the Assembly and References pages (crates/core/src/cil/page.rs) — when it
 * shows it.
 */

import { BytecodeProgram, tick, type DataAt, type Fn, type Progress, type StringRef } from '../disassembly';
import { CIL_TEXT, CIL_VIEW, CoreError, engine, engine as currentEngine, loadEngine, PassSession } from '../engine/engine';
import type { HlaLine } from '../hla';
import { t } from '../i18n';
import type { Pe } from '../pe';

export class NotCil extends Error {}

/** The token type of a #US string (ldstr). */
export const USER_STRING = 0x70;
export const tokenTable = (tok: number): number => tok >>> 24;
export const tokenRow = (tok: number): number => tok & 0xffffff;

/** `IL_001f`: an offset in a method's IL. */
export const label = (offset: number): string => `IL_${(offset >>> 0).toString(16).padStart(4, '0')}`;

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

/** An instruction as the page shows it (crates/wasm/src/cil_page.rs, `cil_insn`). */
export interface CilInsn {
  /** The opcode: its number, its kind of operand (OPERAND), its F flags; undefined for a byte that is not one. */
  op: { code: number; operand: number; flags: number } | undefined;
  /** As printed, `.byte` for what is not an instruction. */
  m: string;
  /** Offset in the method's IL, and length in bytes. */
  at: number;
  len: number;
  /** A variable number, a constant, a token, a branch target (IL offset). */
  a: number;
  /** A switch: its targets (IL offsets); null for the others. */
  targets: number[] | null;
  /** The operand as ildasm prints it, and the whole line. */
  operand: string;
  text: string;
  /** Where it is in the file, and its bytes in hex (the first five, the first twenty-four). */
  fileOffset: number;
  bytes5: string;
  bytes24: string;
  /** What a method operand reaches: a function's address, or a member of another assembly's token; the function's number (-1: none here). */
  callee: number | null;
  calleeFn: number;
  /** ldstr's string, and whether ildasm writes it as text (else as bytes). */
  string: string | null;
  plain: boolean;
  /** The field a field operand (or ldtoken's) names, as ildasm writes it. */
  field: string | null;
  /** The table of a token operand: `MethodDef`, `#US`. */
  tokenKind: string;
}

/** An exception-handling clause of a method body; offsets are in the method's IL. */
export interface Clause {
  /** 0 catch, 1 filter, 2 finally, 4 fault. */
  kind: number;
  tryStart: number;
  tryEnd: number;
  handlerStart: number;
  handlerEnd: number;
  /** Where a filter's code starts (-1 for the other kinds). */
  filterStart: number;
  /** In ILAsm's words: `.try IL_00c9 to IL_00f2 catch [System.Runtime]System.Exception handler IL_00f2 to IL_0107`. */
  text: string;
  /** What a catch catches: a type, or `object`. */
  catch: string;
}

/** What a method's card and header show (`cil_method`). */
export interface MethodInfo {
  /** Its MethodDef token; its attributes as ILAsm writes them: `public hidebysig static · cil managed`. */
  token: number;
  attributes: string;
  /** Its body: where it is, how long its IL is, its header. */
  rva: number;
  size: number;
  fat: boolean;
  maxStack: number;
  initLocals: boolean;
  /** The types of its locals. */
  locals: string[];
  clauses: Clause[];
  /** `static int32 (string[] args)`. */
  signature: string;
  /** The parameters of its HLA64 header (name, type) and its return type. */
  params: [string, string][];
  ret: string;
}

/** What the Assembly page shows (`cil_assembly`). */
export interface AssemblyInfo {
  /** Name, version, culture, public key; null for a module of another assembly. */
  assembly: [string, string, string, string] | null;
  /** Name and MVID. */
  module: [string, string];
  /** The metadata's version, the CLI header's runtime, the table schema. */
  runtime: [string, string, string];
  /** The CLI header's flags by name, and the size of the space for a strong-name signature. */
  flags: string;
  strongName: number;
  /** Rows of TypeDef, MethodDef, Field, Property, Event. */
  counts: [number, number, number, number, number];
  warnings: string[];
  /** Name, file offset, size. */
  streams: [string, number, number][];
  /** Number, name, rows. */
  tables: [number, string, number][];
  /** Name, public, where (null: in this file). */
  resources: [string, boolean, string | null][];
  /** The first 3000 types but `<Module>`: name, kind, visibility, methods, the address of its first function. */
  types: [string, string, string, number, number | null][];
}

/** What the References page shows besides the imports (`cil_references`). */
export interface ReferencesInfo {
  /** Name, version, culture, public key token. */
  assemblies: [string, string, string, string][];
  /** The first 5000 types forwarded to another assembly, and where; how many there are. */
  forwarders: [string, string][];
  exported: number;
}

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

/** Closes an assembly's session in the core once its program is gone. */
const sessions = new FinalizationRegistry<PassSession>((session) => session.close());

/** A .NET assembly's IL; an instruction's address is its RVA. */
export class CilProgram extends BytecodeProgram {
  readonly arch = 'cil';
  /** MethodDef row → its function (an index into `functions`), when it has code. */
  readonly methodFn = new Map<number, number>();
  /** Members of other assemblies, by MemberRef token. */
  readonly imported: ImportedMember[] = [];
  readonly importByToken = new Map<number, ImportedMember>();
  readonly pinvokes: PInvoke[] = [];
  /** Field token (Field or MemberRef) → the instructions that read, write or take its address. */
  fieldRefs: Map<number, number[]> = new Map();
  /** Type token → the instructions that name it (newarr, box, castclass, ldtoken…). */
  typeRefs: Map<number, number[]> = new Map();
  /** Instruction index → the clauses that start a try or a handler there: the clause's place in its method's body, the part. */
  readonly regions = new Map<number, { clause: number; part: 'try' | 'handler' | 'filter' }[]>();
  /** Calls through a function pointer (calli) and through a delegate's Invoke cannot be followed. */
  indirectCalls = 0;
  /** The method the runtime starts at, a MethodDef row (0 for a library). */
  entryMethod = 0;
  assemblyName = '';
  framework: string | undefined;
  /** The CLI header's flags; whether native code compiled ahead of time (ReadyToRun) is beside the IL. */
  headerFlags = 0;
  readyToRun = false;
  /** How many bytes of IL the methods with code have. */
  codeBytes = 0;
  private session: PassSession | null = null;
  private readonly methods = new Map<number, MethodInfo>();
  private readonly fields = new Map<number, string>();

  constructor(readonly pe: Pe) {
    super();
  }

  archLabel(): string {
    const flags = this.headerFlags;
    const r2r = this.readyToRun ? ' · ReadyToRun' : '';
    if (!(flags & 0x1)) return `CIL + ${this.pe.arch}${r2r}`;
    return `CIL${flags & 0x2 ? ' (x86)' : this.pe.machine === 0x14c ? '' : ` (${this.pe.arch})`}${r2r}`;
  }

  override platformLabel(): string | undefined {
    return this.framework ? frameworkLabel(this.framework) : undefined;
  }

  private targetIndex = new Uint32Array(0);
  private targetStarts = new Uint32Array(1);
  private targetValues = new Uint32Array(0);

  override branchTargets(index: number): number[] {
    const k = find(this.targetIndex, index);
    return k < 0 ? [] : Array.from(this.targetValues.subarray(this.targetStarts[k]!, this.targetStarts[k + 1]!));
  }

  /** `IL_001f`: where an address is in its method's IL. */
  override labelName(addr: number): string {
    const fn = this.functions[this.functionOfIndex(this.indexOf(addr))];
    return fn ? label(addr - fn.addr) : `L${addr.toString(16)}`;
  }

  /**
   * The HLA64 line of the instructions first..last (one statement), or null
   * when they cannot be written as one — then each stays an instruction.
   * The core writes it (crates/core/src/cil/hla.rs); names in it are marked (../wasm/hla.ts).
   */
  hla(first: number, last: number): HlaLine | null {
    const session = this.liveSession();
    const line = JSON.parse(session.engine.cilHla(session.handle, first, last)) as HlaLine & { none?: true };
    return line.none ? null : { text: line.text, words: line.words };
  }

  /** One of the page's questions to the core (crates/wasm/src/cil_page.rs). */
  private ask<T>(call: (x: ReturnType<typeof currentEngine>['x'], handle: number) => number): T {
    const session = this.liveSession();
    return session.engine.pageJson<T>(() => call(session.engine.x, session.handle));
  }

  /** The core's session, analysed again if the core was restarted since. */
  private liveSession(): PassSession {
    const engine = currentEngine();
    if (this.session && this.session.engine === engine) return this.session;
    if (this.session) sessions.unregister(this);
    const session = PassSession.cil(engine, this.pe.bytes, this.pe.sections, this.pe.directories[14]?.rva);
    while (!session.step(1 << 20));
    this.hold(session);
    return session;
  }

  /** Keeps the session the analysis ran in, closed when the program is collected or disposed of. */
  hold(session: PassSession): void {
    this.session = session;
    sessions.register(this, session, this);
  }

  /** Closes the core's session now rather than when the program is collected; it is opened again if something is asked of it. */
  override dispose(): void {
    if (!this.session) return;
    sessions.unregister(this);
    if (this.session.engine === currentEngine()) this.session.close();
    this.session = null;
  }

  /** An instruction as the page shows it. */
  insn(index: number): CilInsn {
    const raw = this.ask<(Omit<CilInsn, 'op'> & { op: [number, number, number] | null }) | null>((x, h) => x.cil_insn(h, index));
    if (!raw) return { op: undefined, m: '.byte', at: 0, len: 1, a: 0, targets: null, operand: '', text: '', fileOffset: -1, bytes5: '', bytes24: '', callee: null, calleeFn: -1, string: null, plain: true, field: null, tokenKind: '' };
    const op = raw.op;
    return { ...raw, op: op ? { code: op[0], operand: op[1], flags: op[2] } : undefined };
  }

  /** What a method's card and header show, by its function's number. */
  method(fnIndex: number): MethodInfo {
    let found = this.methods.get(fnIndex);
    if (!found) {
      found = this.ask<MethodInfo>((x, h) => x.cil_method(h, fnIndex));
      this.methods.set(fnIndex, found);
    }
    return found;
  }

  /** What a method's code calls (the address each call reaches, in order), how many calls go through a function pointer, and the strings it loads (token, text). */
  functionRefs(fnIndex: number): { calls: number[]; indirect: number; strings: [number, string][] } {
    return this.ask((x, h) => x.cil_fn_refs(h, fnIndex));
  }

  /** A field token as ildasm writes it (for an HLA64 line's tooltip). */
  fieldName(tok: number): string {
    let found = this.fields.get(tok);
    if (found === undefined) {
      found = this.ask<string>((x, h) => x.cil_field(h, tok));
      this.fields.set(tok, found);
    }
    return found;
  }

  /** What the Assembly page shows. */
  assemblyInfo(): AssemblyInfo {
    return this.ask((x, h) => x.cil_assembly(h));
  }

  /** What the References page shows besides the imports. */
  referencesInfo(): ReferencesInfo {
    return this.ask((x, h) => x.cil_references(h));
  }

  /** A string of #US (by its token) as ldstr's operand writes it: `"text"`, or `bytearray (…)`. */
  stringText(tok: number): string {
    return this.ask((x, h) => x.cil_string_text(h, tokenRow(tok)));
  }

  /** The function of a MethodDef row, when it has code. */
  methodFunction(row: number): Fn | undefined {
    const at = this.methodFn.get(row);
    return at === undefined ? undefined : this.functions[at];
  }

  /** What a method operand reaches: the function here, or the member of another assembly. */
  callee(insn: CilInsn): Fn | undefined {
    if (insn.calleeFn >= 0) return this.functions[insn.calleeFn];
    return insn.callee === null ? undefined : this.importByToken.get(insn.callee);
  }

  dataAt(addr: number): DataAt {
    const string = this.stringAt.get(addr);
    if (string) return { kind: 'string', text: string.text };
    if (tokenTable(addr) === USER_STRING) {
      const text = this.ask<string | null>((x, h) => x.cil_user_string(h, tokenRow(addr)));
      if (text !== null) return { kind: 'string', text };
    }
    return undefined;
  }

  /** The clauses that start a try or a handler at an instruction. */
  regionsAt(index: number): { clause: Clause; part: 'try' | 'handler' | 'filter' }[] {
    const list = this.regions.get(index);
    if (!list) return [];
    const clauses = this.method(this.functionOfIndex(index)).clauses;
    return list.map(({ clause, part }) => ({ clause: clauses[clause]!, part }));
  }

  /** The clauses of the method an instruction is in. */
  clausesOf(index: number): Clause[] {
    const f = this.functionOfIndex(index);
    return f < 0 ? [] : this.method(f).clauses;
  }

  /** Takes the analysis from the core's session. */
  take(session: PassSession): void {
    const addrOf = (index: number) => this.offsets[index] ?? 0;
    this.offsets = session.copy(CIL_VIEW.offsets, Uint32Array);
    this.mnemonicIds = session.copy(CIL_VIEW.mnemonicIds, Uint16Array);
    this.flags = session.copy(CIL_VIEW.flags, Uint8Array);
    this.totalInstructions = this.offsets.length;
    const mnemonics = session.text(CIL_TEXT.mnemonics);
    if (mnemonics) this.mnemonics.push(...mnemonics.split('\n'));
    this.tally([...session.copy(CIL_VIEW.counts, Uint32Array)]);
    Object.assign(this, { callers: session.refs(CIL_VIEW.callers, addrOf), dataRefs: session.refs(CIL_VIEW.dataRefs, addrOf) });
    this.fieldRefs = session.refs(CIL_VIEW.fieldRefs, addrOf);
    this.typeRefs = session.refs(CIL_VIEW.typeRefs, addrOf);
    this.targetIndex = session.copy(CIL_VIEW.targetIndex, Uint32Array);
    this.targetStarts = session.copy(CIL_VIEW.targetStarts, Uint32Array);
    this.targetValues = session.copy(CIL_VIEW.targetValues, Uint32Array);
    const meta = session.json<{ indirectCalls: number; assembly: string; framework: string | null; flags: number; entryToken: number; r2r: boolean; codeBytes: number }>(CIL_TEXT.meta);
    this.codeBytes = meta.codeBytes;
    this.indirectCalls = meta.indirectCalls;
    this.assemblyName = meta.assembly;
    this.framework = meta.framework ?? undefined;
    this.headerFlags = meta.flags;
    this.readyToRun = meta.r2r;
    this.entryMethod = !(meta.flags & 0x10) && tokenTable(meta.entryToken) === 0x06 ? tokenRow(meta.entryToken) : 0;

    for (const [tok, name, full, raw, assembly, type, field] of session.json<[number, string, string, string, string, string, number][]>(CIL_TEXT.imports)) {
      const member: ImportedMember = { addr: tok, first: -1, count: 0, name, full, raw, kind: 'import', token: tok, assembly, type, field: !!field };
      this.imported.push(member);
      this.importByToken.set(tok, member);
    }
    for (const [method, name, library, entry, flags] of session.json<[number, string, string, string, number][]>(CIL_TEXT.pinvokes)) this.pinvokes.push({ method, name, library, entry, flags });

    const spans = session.copy(CIL_VIEW.functions, Uint32Array);
    session.json<[number, Fn['kind'], string, string, string][]>(CIL_TEXT.functions).forEach(([addr, kind, name, full, raw], f) => {
      const m = spans[f * 3]!;
      const first = spans[f * 3 + 1]!;
      this.functions.push({ addr, first, count: spans[f * 3 + 2]!, name, full, raw, kind, index: m });
      this.methodFn.set(m, f);
      this.functionAtIndex.set(first, f);
    });
    for (const [first, count, name] of session.json<[number, number, string | null][]>(CIL_TEXT.ranges)) this.ranges.push({ name: name ?? t('listing', 'global functions'), first, count });

    const parts = ['try', 'handler', 'filter'] as const;
    const regions = session.copy(CIL_VIEW.regions, Uint32Array);
    for (let k = 0; k + 2 < regions.length; k += 3) {
      const index = regions[k]!;
      const list = this.regions.get(index);
      const region = { clause: regions[k + 1]!, part: parts[regions[k + 2]!]! };
      if (list) list.push(region);
      else this.regions.set(index, [region]);
    }

    // The strings: every one of #US, in the order of the heap.
    for (const [index, text] of session.json<[number, string][]>(CIL_TEXT.strings)) {
      const ref: StringRef = { addr: ((USER_STRING << 24) | index) >>> 0, text, section: '#US', kind: 'const' };
      this.strings.push(ref);
      this.stringAt.set(ref.addr, ref);
    }
  }
}

/** `.NETCoreApp,Version=v10.0` → `.NET 10.0`; `.NETFramework,Version=v4.8` → `.NET Framework 4.8`. */
export function frameworkLabel(moniker: string): string {
  const version = /Version=v?([\d.]+)/.exec(moniker)?.[1] ?? '';
  if (moniker.startsWith('.NETCoreApp')) return Number(version.split('.')[0]) >= 5 ? `.NET ${version}` : `.NET Core ${version}`;
  if (moniker.startsWith('.NETFramework')) return `.NET Framework ${version}`;
  if (moniker.startsWith('.NETStandard')) return `.NET Standard ${version}`;
  return moniker;
}

/** The instructions the core decodes between two looks at the page. */
const BUDGET = 1 << 17;

/** Opens an assembly's session in the core; why it cannot, in the page's words. */
function open(pe: Pe): PassSession {
  const e = engine();
  try {
    return PassSession.cil(e, pe.bytes, pe.sections, pe.directories[14]?.rva);
  } catch (err) {
    if (!(err instanceof CoreError)) throw err;
    throw new NotCil(e.x.cil_open_error() === 2 ? t('open', 'The .NET metadata of this file has no tables.') : t('open', 'The .NET metadata of this file cannot be found or is damaged.'));
  }
}

/** Analyses the assembly in the core, which reads its metadata. */
export async function analyzeCil(pe: Pe, progress: Progress = () => {}): Promise<CilProgram> {
  const started = Date.now();
  const program = new CilProgram(pe);
  await loadEngine();
  const session = open(pe);
  try {
    while (!session.step(BUDGET)) {
      progress('decode', session.done, session.total);
      await tick();
    }
    program.take(session);
  } catch (err) {
    session.close();
    throw err;
  }
  program.hold(session);
  program.decodeMs = Date.now() - started;
  progress('decode', 1, 1);
  progress('done', 1, 1);
  return program;
}

/** The function the page opens at: the entry point, else the first public method, else the first. */
export function entryOf(program: CilProgram): Fn | undefined {
  return program.methodFunction(program.entryMethod) ?? program.functions.find((f) => f.kind === 'export') ?? program.functions[0];
}
