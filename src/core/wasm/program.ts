/**
 * The analysis of a whole WebAssembly module: every instruction of every
 * function body is decoded once, and from that pass come the statistics, the
 * functions and their names, the labels branches go to (worked out from the
 * nesting of blocks), the call graph, the places code reads or builds an
 * address of data, the strings, and which instructions the HLA64 view writes
 * as one line.
 *
 * Addresses of code are offsets in the file, as browsers and wasm tools show
 * them; addresses of data are addresses in the module's linear memory, where
 * the data segments put their bytes. The two are never mixed: a string is
 * selected by its memory address, an instruction by its offset.
 *
 * Instructions have different lengths, so their offsets are kept in an
 * array; the listing decodes again the few hundred rows it shows.
 *
 * The pass runs in the core (crates/core/src/wasm/program.rs); what is here
 * takes its results and answers the page's questions about them. The core
 * keeps the module for the HLA64 lines of the rows on screen (crates/core/src/wasm/hla.rs).
 */

import { BytecodeProgram, isText, tick, type DataAt, type Fn, type Progress, type StringRef } from '../disassembly';
import { engine, engine as currentEngine, loadEngine, PassSession, WASM_TEXT, WASM_VIEW } from '../engine/engine';
import { rounds, type HlaLine } from '../hla';
import { insnOf, type CoreInsn, type WasmInsn } from './decode';
import { lineTable, type LineTable } from './dwarf';
import { funcTypeOf, type FuncType, type WasmBody, type WasmModule } from './module';
import { utf8 } from '../bytes';

/** Where a data segment's bytes are in memory and in the file. */
export interface Segment {
  index: number;
  addr: number;
  end: number;
  /** File offset of its first byte. */
  start: number;
  name: string;
  /** A passive segment, placed by memory.init in the start function. */
  passive: boolean;
}

export interface ImportedFn extends Fn {
  module: string;
  field: string;
  type: number;
}

/** How the HLA64 view names functions: the page passes its own (to follow the settings for function names). */
export interface Naming {
  func(index: number): string;
}

/** Closes a module's session in the core once its program is gone. */
const sessions = new FinalizationRegistry<PassSession>((session) => session.close());

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

/** A WebAssembly module's code; an instruction's address is its offset in the file. */
export class WasmProgram extends BytecodeProgram {
  readonly arch = 'wasm';
  /** Instruction index → how deep in blocks it is (for indentation). */
  depth = new Uint16Array(0);
  /** The body of each function of `functions`, in the same order. */
  readonly bodies: WasmBody[] = [];
  readonly imported: ImportedFn[] = [];
  /** Function index → its entry in `functions` (defined) or `imported`. */
  readonly byIndex: Fn[] = [];
  readonly segments: Segment[] = [];
  readonly lengthAt = new Map<number, number>();
  /** Function address → the instructions that take a reference to it (ref.func). */
  refFuncs: Map<number, number[]> = new Map();
  /** Global index → the instructions that read or write it. */
  globalRefs: Map<number, number[]> = new Map();
  /** Type index → the functions a call_indirect of that type may reach (those in a table). */
  indirect: Map<number, number[]> = new Map();
  /** Branches that carry values to their label: HLA64 leaves them instructions. */
  readonly valueBranches = new Set<number>();
  /** How many call_indirect / call_ref instructions there are. */
  indirectCalls = 0;
  lines: LineTable | null = null;
  private session: PassSession | null = null;

  constructor(readonly module: WasmModule) {
    super();
  }

  /**
   * The HLA64 line of the instructions first..last (one statement), or null
   * when they cannot be written as one — then each stays an instruction.
   * Names in it are marked (hla.ts: mark()); `names` names the functions.
   */
  hla(first: number, last: number, names: Naming): HlaLine | null {
    const session = this.liveSession();
    const line = rounds<HlaLine & { none?: true }>(
      (input, _kind, index) => input.text(names.func(index)),
      () => {},
      (input) => session.engine.wasmHla(session.handle, first, last, input),
    );
    return line.none ? null : { text: line.text, words: line.words, comment: line.comment };
  }

  /** The core's session, analysed again if the core was restarted since. */
  private liveSession(): PassSession {
    const engine = currentEngine();
    if (this.session && this.session.engine === engine) return this.session;
    if (this.session) sessions.unregister(this);
    const session = PassSession.wasm(engine, this.module.bytes);
    while (!session.step(1 << 20));
    this.hold(session);
    return session;
  }

  /** Keeps the session the analysis ran in, closed when the program is collected or disposed of. */
  hold(session: PassSession): void {
    this.session = session;
    sessions.register(this, session, this);
  }

  /** Closes the core's session now rather than when the program is collected; it is opened again if a line is asked for. */
  override dispose(): void {
    if (!this.session) return;
    sessions.unregister(this);
    if (this.session.engine === currentEngine()) this.session.close();
    this.session = null;
  }

  archLabel(): string {
    return this.module.memory64 ? 'wasm64' : 'wasm32';
  }

  private targetIndex = new Uint32Array(0);
  private targetStarts = new Uint32Array(1);
  private targetValues = new Int32Array(0);

  /** Where a branch goes; a slot of a br_table whose label was never found is -1. */
  override branchTargets(index: number): number[] {
    const k = find(this.targetIndex, index);
    return k < 0 ? [] : Array.from(this.targetValues.subarray(this.targetStarts[k]!, this.targetStarts[k + 1]!));
  }

  /** The end of an instruction: the next one's offset, or the end of its function. */
  endOf(index: number): number {
    const fn = this.functions[this.functionOfIndex(index)];
    if (fn && index + 1 < fn.first + fn.count) return this.offsets[index + 1]!;
    return fn ? this.bodies[this.functions.indexOf(fn)]!.end : this.offsets[index]! + 1;
  }

  /** An instruction, decoded by the core for the row or the details that show it. */
  insn(index: number): WasmInsn {
    const session = this.liveSession();
    return insnOf(session.engine.wasmInsn<CoreInsn>(session.handle, index));
  }

  /** What a function's instructions call (by index, how often, in the order first met), how many calls go through a table or a reference, and the data addresses they name. */
  functionRefs(fnIndex: number): { calls: [number, number][]; indirect: number; consts: number[] } {
    const fn = this.functions[fnIndex]!;
    const session = this.liveSession();
    return session.engine.wasmFnRefs(session.handle, fn.first, fn.count);
  }

  /** The source lines of the module (DWARF), read by the core. */
  readLines(): LineTable | null {
    const session = this.liveSession();
    const files = session.engine.wasmLines(session.handle);
    return files ? lineTable(files, session.copy(WASM_VIEW.lineAddrs, Uint32Array), session.copy(WASM_VIEW.lineRows, Uint32Array)) : null;
  }

  /** The function (defined or imported) with an index in the function index space. */
  func(index: number): Fn | undefined {
    return this.byIndex[index];
  }

  /** The address calls to a function are counted under: its first instruction, or its import entry. */
  funcAddr(index: number): number {
    return this.byIndex[index]?.addr ?? -1;
  }

  funcType(index: number): FuncType | undefined {
    return funcTypeOf(this.module, index);
  }

  /** The function whose code or import entry is at an address. */
  funcAtAddr(addr: number): Fn | undefined {
    return this.functionAt(addr) ?? this.imported.find((f) => f.addr === addr);
  }

  /** The name of a local of a function (by function index), if the module gives one. */
  localName(func: number, local: number): string | undefined {
    return this.module.names.locals.get(func)?.get(local);
  }

  globalName(index: number): string {
    return this.module.names.globals.get(index) ?? exportName(this.module, 'global', index) ?? importName(this.module, 'global', index) ?? `global${index}`;
  }

  tableName(index: number): string {
    return this.module.names.tables.get(index) ?? exportName(this.module, 'table', index) ?? `table${index}`;
  }

  dataName(index: number): string {
    return this.module.names.data.get(index) ?? `data[${index}]`;
  }

  /** The data segment holding a memory address. */
  segmentAt(addr: number): Segment | undefined {
    const segments = this.segments;
    let lo = 0;
    let hi = segments.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      const s = segments[mid]!;
      if (addr < s.addr) hi = mid - 1;
      else if (addr >= s.end) lo = mid + 1;
      else return s;
    }
    return undefined;
  }

  /** The bytes of memory at an address, as the data segments set them. */
  memoryAt(addr: number, length: number): Uint8Array | undefined {
    const segment = this.segmentAt(addr);
    if (!segment) return undefined;
    const at = segment.start + (addr - segment.addr);
    return this.module.bytes.subarray(at, Math.min(at + length, segment.start + (segment.end - segment.addr)));
  }

  dataAt(addr: number): DataAt {
    const string = this.stringAt.get(addr) ?? this.printableAt(addr);
    if (string) return { kind: 'string', text: string.text };
    return undefined;
  }

  /** A string that starts at an address inside another one, or one the code gives a length for. */
  private printableAt(addr: number): StringRef | undefined {
    const bytes = this.memoryAt(addr, 160);
    if (!bytes) return undefined;
    const known = this.lengthAt.get(addr);
    const limit = known !== undefined ? Math.min(known, bytes.length) : bytes.length;
    let end = 0;
    while (end < limit && isText(bytes[end]!)) end++;
    const section = this.segmentAt(addr)!.name;
    if (known !== undefined && end === known && known > 0) return { addr, text: utf8(bytes.subarray(0, end)), section, kind: 'const' };
    const terminated = bytes[end] === 0;
    if (end < (terminated ? 2 : 6)) return undefined;
    return { addr, text: utf8(bytes.subarray(0, end)), section, kind: terminated ? 'cstring' : 'const' };
  }

  /** The source line of an instruction, when the module carries DWARF line tables. */
  lineOf(index: number): { file: string; line: number; column: number } | undefined {
    return this.lines?.lookup(this.addrOf(index));
  }

  /** Takes the analysis from the core's session. */
  take(session: PassSession): void {
    const module = this.module;
    const addrOf = (index: number) => this.offsets[index] ?? 0;
    this.offsets = session.copy(WASM_VIEW.offsets, Uint32Array);
    this.depth = session.copy(WASM_VIEW.depth, Uint16Array);
    this.mnemonicIds = session.copy(WASM_VIEW.mnemonicIds, Uint16Array);
    this.flags = session.copy(WASM_VIEW.flags, Uint8Array);
    const total = this.offsets.length;
    this.totalInstructions = total;
    if (total) this.ranges.push({ name: 'code', first: 0, count: total });
    const mnemonics = session.text(WASM_TEXT.mnemonics);
    if (mnemonics) this.mnemonics.push(...mnemonics.split('\n'));
    this.tally([...session.copy(WASM_VIEW.counts, Uint32Array)]);
    Object.assign(this, { callers: session.refs(WASM_VIEW.callers, addrOf), dataRefs: session.refs(WASM_VIEW.dataRefs, addrOf) });
    this.refFuncs = session.refs(WASM_VIEW.refFuncs, addrOf);
    this.globalRefs = session.refs(WASM_VIEW.globalRefs, addrOf);
    this.indirect = session.refs(WASM_VIEW.indirect, (func) => func);
    this.targetIndex = session.copy(WASM_VIEW.targetIndex, Uint32Array);
    this.targetStarts = session.copy(WASM_VIEW.targetStarts, Uint32Array);
    this.targetValues = session.copy(WASM_VIEW.targetValues, Int32Array);
    for (const index of session.copy(WASM_VIEW.valueBranches, Uint32Array)) this.valueBranches.add(index);
    const lengthAddr = session.copy(WASM_VIEW.lengthAddr, Float64Array);
    const lengthValue = session.copy(WASM_VIEW.lengthValue, Float64Array);
    lengthAddr.forEach((addr, k) => this.lengthAt.set(addr, lengthValue[k]!));
    this.indirectCalls = session.json<{ indirectCalls: number }>(WASM_TEXT.meta).indirectCalls;

    // The imported functions, named as the module calls them (or as its name section does).
    const importNames = session.json<CoreName[]>(WASM_TEXT.imports);
    for (const imp of module.imports) {
      if (imp.kind !== 'func') continue;
      const [raw, short, full, language] = importNames[this.imported.length]!;
      const index = imp.index;
      const fn: ImportedFn = { addr: imp.offset, first: -1, count: 0, name: short ?? raw, full: full ?? raw, raw, language, kind: 'import', index, module: imp.module, field: imp.name, type: imp.type ?? 0 };
      this.imported.push(fn);
      this.byIndex[index] = fn;
    }

    // Every body is a function of the index space; those with instructions are the listing's.
    const spans = session.copy(WASM_VIEW.bodies, Uint32Array);
    session.json<(Fn['kind'] | [Fn['kind'], ...CoreName])[]>(WASM_TEXT.bodies).forEach((entry, b) => {
      const body = module.bodies[b]!;
      const index = module.importedFuncs + b;
      const fn: Fn = { addr: body.code, first: spans[b * 2]!, count: spans[b * 2 + 1]!, name: `func${index}`, full: `func${index}`, kind: 'anonymous', index };
      if (typeof entry === 'string') fn.kind = entry;
      else {
        const [kind, raw, short, full, language] = entry;
        Object.assign(fn, { name: short ?? raw, full: full ?? raw, raw, language });
        fn.kind = kind;
      }
      this.byIndex[index] = fn;
      if (!fn.count) return;
      this.functionAtIndex.set(fn.first, this.functions.length);
      this.functions.push(fn);
      this.bodies.push(body);
    });

    for (const [index, addr, end, start, passive] of session.json<[number, number, number, number, number][]>(WASM_TEXT.segments)) {
      this.segments.push({ index, addr, end, start, name: this.dataName(index), passive: !!passive });
    }
    for (const [addr, text, segment, cstring] of session.json<[number, string, number, number][]>(WASM_TEXT.strings)) {
      const ref: StringRef = { addr, text, section: this.segments[segment]!.name, kind: cstring ? 'cstring' : 'const' };
      this.strings.push(ref);
      this.stringAt.set(addr, ref);
    }
  }
}

function exportName(module: WasmModule, kind: string, index: number): string | undefined {
  return module.exports.find((e) => e.kind === kind && e.index === index)?.name;
}

function importName(module: WasmModule, kind: string, index: number): string | undefined {
  const found = module.imports.find((i) => i.kind === kind && i.index === index);
  return found ? found.name : undefined;
}

export const WASI_ENTRIES = new Set(['_start', 'main', '__main_argc_argv', '__original_main', '_initialize']);

/** A name as the core hands it over: the name found, what it demangles to (null: the same), the language. */
type CoreName = [raw: string, short: string | null, full: string | null, language: NonNullable<Fn['language']>];

/** The instructions the core decodes between two looks at the page. */
const BUDGET = 1 << 17;

/**
 * Analyses a module in the core (crates/core/src/wasm/program.rs), which reads it again from its
 * bytes and keeps it for the rows the page shows; its DWARF line table comes from there too.
 */
export async function analyzeWasm(module: WasmModule, progress: Progress = () => {}): Promise<WasmProgram> {
  const program = new WasmProgram(module);
  const started = Date.now();
  await loadEngine();
  const session = PassSession.wasm(engine(), module.bytes);
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
  program.lines = program.readLines();
  program.decodeMs = Date.now() - started;
  progress('decode', 1, 1);
  progress('done', 1, 1);
  return program;
}

/** The function the page opens at: main, then the WASI entry points, the start function, the first export. */
export function entryOf(program: WasmProgram): Fn | undefined {
  const fns = program.functions;
  return (
    fns.find((f) => f.name === 'main') ??
    fns.find((f) => f.kind === 'export' && WASI_ENTRIES.has(f.raw ?? '')) ??
    fns.find((f) => f.kind === 'entry') ??
    fns.find((f) => f.kind === 'export') ??
    fns[0]
  );
}
