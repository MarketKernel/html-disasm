/**
 * The analysis of a whole WebAssembly module: every instruction of every
 * function body is decoded once, in chunks so the page stays responsive, and
 * from that pass come the statistics, the functions and their names, the
 * labels branches go to (worked out from the nesting of blocks), the call
 * graph, the places code reads or builds an address of data, the strings,
 * and which instructions the HLA64 view writes as one line.
 *
 * Addresses of code are offsets in the file, as browsers and wasm tools show
 * them; addresses of data are addresses in the module's linear memory, where
 * the data segments put their bytes. The two are never mixed: a string is
 * selected by its memory address, an instruction by its offset.
 *
 * Instructions have different lengths, so their offsets are kept in an
 * array; the listing decodes again the few hundred rows it shows.
 */

import { demangleWasm as demangle } from '../demangle';
import { append, BytecodeProgram, IF, isText, tick, type DataAt, type Fn, type Progress, type StringRef } from '../disassembly';
import { decodeAt, WasmInsn } from './decode';
import { readLines, type LineTable } from './dwarf';
import { effect, type EffectContext } from './effects';
import { funcTypeOf, type FuncType, type WasmBody, type WasmModule } from './module';
import { WF } from './hla';
import { IMM, W } from './opcodes';
import { utf8 } from './reader';

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

/** What the analysis keeps of a block while it is open. */
interface Frame {
  kind: number;
  /** The instruction that opened it (the first of the function for the function itself). */
  start: number;
  /** The if (or else) waiting for its end, for the arrows. */
  open: number;
  /** Branches waiting for the end of the block: the branch, and its place in a br_table (-1 for others). */
  pending: [number, number][] | null;
  params: number;
  results: number;
  /** An if written `if c {` in HLA64. */
  sugar: boolean;
}

const FRAME = { FUNCTION: 0, BLOCK: 1, LOOP: 2, IF: 3, TRY: 4 } as const;

/** A value on the stack while the analysis groups instructions: the instructions that made it. */
interface Node {
  start: number;
  end: number;
  /** It can be written as an expression inside the instruction that takes it. */
  ok: boolean;
  /** The value of a lone i32.const / i64.const. */
  value: number | undefined;
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
  readonly refFuncs = new Map<number, number[]>();
  /** Global index → the instructions that read or write it. */
  readonly globalRefs = new Map<number, number[]>();
  /** Type index → the functions a call_indirect of that type may reach (those in a table). */
  readonly indirect = new Map<number, number[]>();
  /** Branches that carry values to their label: HLA64 leaves them instructions. */
  readonly valueBranches = new Set<number>();
  /** How many call_indirect / call_ref instructions there are. */
  indirectCalls = 0;
  lines: LineTable | null = null;
  readonly effects: EffectContext;

  constructor(readonly module: WasmModule) {
    super();
    this.effects = {
      funcType: (func) => funcTypeOf(module, func),
      typeDef: (type) => module.types[type],
      tagParams: (tag) => {
        const type = module.tags[tag];
        return type === undefined ? 0 : module.types[type]?.func?.params.length ?? 0;
      },
    };
  }

  archLabel(): string {
    return this.module.memory64 ? 'wasm64' : 'wasm32';
  }

  /** The end of an instruction: the next one's offset, or the end of its function. */
  endOf(index: number): number {
    const fn = this.functions[this.functionOfIndex(index)];
    if (fn && index + 1 < fn.first + fn.count) return this.offsets[index + 1]!;
    return fn ? this.bodies[this.functions.indexOf(fn)]!.end : this.offsets[index]! + 1;
  }

  insn(index: number, into?: WasmInsn): WasmInsn {
    const fnIndex = this.functionOfIndex(index);
    const end = fnIndex >= 0 ? this.bodies[fnIndex]!.end : this.module.bytes.length;
    return decodeAt(this.module.bytes, this.offsets[index]!, end, into);
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
}

function exportName(module: WasmModule, kind: string, index: number): string | undefined {
  return module.exports.find((e) => e.kind === kind && e.index === index)?.name;
}

function importName(module: WasmModule, kind: string, index: number): string | undefined {
  const found = module.imports.find((i) => i.kind === kind && i.index === index);
  return found ? found.name : undefined;
}

/* ------------------------------------------------------------------ *
 * Names
 * ------------------------------------------------------------------ */

export const WASI_ENTRIES = new Set(['_start', 'main', '__main_argc_argv', '__original_main', '_initialize']);

/** The imported functions, named as the module calls them (or as its name section does). */
function nameImports(program: WasmProgram): void {
  const module = program.module;
  for (const imp of module.imports) {
    if (imp.kind !== 'func') continue;
    const index = imp.index;
    const raw = module.names.functions.get(index) ?? imp.name;
    const d = demangle(raw);
    const fn: ImportedFn = { addr: imp.offset, first: -1, count: 0, name: d.short, full: d.full, raw, language: d.language, kind: 'import', index, module: imp.module, field: imp.name, type: imp.type ?? 0 };
    program.imported.push(fn);
    program.byIndex[index] = fn;
  }
}

/* ------------------------------------------------------------------ *
 * Data segments
 * ------------------------------------------------------------------ */

/**
 * Where passive segments go: a module with shared memory (threads) keeps its
 * data passive and copies it in from the start function — `i32.const dest,
 * i32.const 0, i32.const size, memory.init n` — so that is where the
 * addresses are found.
 */
function placePassive(module: WasmModule): Map<number, number> {
  const placed = new Map<number, number>();
  if (!module.data.some((d) => d.mode === 'passive')) return placed;
  const candidates = new Set<number>();
  if (module.start !== undefined) candidates.add(module.start);
  for (const [index, name] of module.names.functions) if (/init_memory|init_data/.test(name)) candidates.add(index);
  const insn = new WasmInsn();
  for (const func of candidates) {
    const body = module.bodies[func - module.importedFuncs];
    if (!body) continue;
    const consts: (number | undefined)[] = [];
    for (let pos = body.code; pos < body.end; ) {
      decodeAt(module.bytes, pos, body.end, insn);
      if (!insn.op) break;
      if (insn.m === 'memory.init' && consts.length >= 3) {
        const [dest, offset] = consts.slice(-3);
        if (dest !== undefined && offset !== undefined && !placed.has(insn.a)) placed.set(insn.a, dest - offset);
      }
      consts.push(insn.m === 'i32.const' || insn.m === 'i64.const' ? Number(insn.value) : undefined);
      if (consts.length > 3) consts.shift();
      pos += insn.len;
    }
  }
  return placed;
}

function layOutSegments(program: WasmProgram): void {
  const module = program.module;
  const passive = placePassive(module);
  module.data.forEach((d, index) => {
    const addr = d.mode === 'active' ? d.addr : passive.get(index);
    if (addr === undefined || !d.size || d.memory !== 0) return;
    program.segments.push({ index, addr, end: addr + d.size, start: d.start, name: program.dataName(index), passive: d.mode === 'passive' });
  });
  program.segments.sort((a, b) => a.addr - b.addr);
}

/** NUL-terminated runs of text in the data segments: the C strings. */
function findStrings(program: WasmProgram): void {
  const bytes = program.module.bytes;
  const LIMIT = 300_000;
  for (const segment of program.segments) {
    const size = segment.end - segment.addr;
    let start = -1;
    for (let i = 0; i < size; i++) {
      const b = bytes[segment.start + i]!;
      if (b === 0) {
        if (start >= 0 && i - start >= 4) {
          const ref: StringRef = { addr: segment.addr + start, text: utf8(bytes.subarray(segment.start + start, segment.start + i)), section: segment.name, kind: 'cstring' };
          program.strings.push(ref);
          program.stringAt.set(ref.addr, ref);
          if (program.strings.length >= LIMIT) return;
        }
        start = -1;
      } else if (!isText(b)) start = -1;
      else if (start < 0) start = i;
    }
  }
}

/* ------------------------------------------------------------------ *
 * The pass over every instruction
 * ------------------------------------------------------------------ */

function blockArity(program: WasmProgram, insn: WasmInsn): [number, number] {
  const block = insn.block;
  if (!block || block.kind === 'empty') return [0, 0];
  if (block.kind === 'value') return [0, 1];
  const type = program.module.types[block.index]?.func;
  return type ? [type.params.length, type.results.length] : [0, 0];
}

export async function analyzeWasm(module: WasmModule, progress: Progress = () => {}): Promise<WasmProgram> {
  const program = new WasmProgram(module);
  const started = Date.now();
  const bytes = module.bytes;

  nameImports(program);
  layOutSegments(program);
  try {
    program.lines = readLines(module);
  } catch {
    program.lines = null;
  }

  // A first count of the instructions, so the arrays can be allocated once: every byte could be one.
  let capacity = 0;
  for (const body of module.bodies) capacity += body.end - body.code;
  const offsets = new Uint32Array(capacity);
  const depth = new Uint16Array(capacity);
  const ids = new Uint16Array(capacity);
  const flags = new Uint8Array(capacity);

  // Functions in tables, by type: what a call_indirect may reach.
  for (const element of module.elements) {
    for (const func of element.funcs) {
      if (func === null) continue;
      const type = module.funcTypes[func];
      if (type === undefined) continue;
      const list = program.indirect.get(type) ?? [];
      if (!list.includes(func)) list.push(func);
      program.indirect.set(type, list);
    }
  }

  const exported = new Set(module.exports.filter((e) => e.kind === 'func').map((e) => e.index));
  const mnemonicIds = new Map<string, number>();
  const counts: number[] = [];
  const insn = new WasmInsn();
  const frames: Frame[] = [];
  const nodes: Node[] = [];
  const CHUNK = 65536;
  let total = 0;
  let nextTick = CHUNK;

  // Function addresses must be known before calls are counted: they are the offsets of the first instructions.
  module.bodies.forEach((body, i) => {
    const index = module.importedFuncs + i;
    const fn: Fn = { addr: body.code, first: 0, count: 0, name: `func${index}`, full: `func${index}`, kind: 'anonymous', index };
    program.byIndex[index] = fn;
  });

  const fuse = (start: number, end: number) => {
    for (let k = start; k < end; k++) flags[k]! |= IF.FUSE;
  };
  /** Do the top `count` values fold into the instruction at `at`: made right before it, one after another, each an expression? */
  const folds = (count: number, at: number): boolean => {
    if (count > nodes.length) return false;
    if (!count) return true;
    let expected = at;
    for (let j = nodes.length - 1; j >= nodes.length - count; j--) {
      const node = nodes[j]!;
      if (!node.ok || node.end !== expected - 1) return false;
      expected = node.start;
    }
    return true;
  };
  const addTarget = (from: number, slot: number, target: number) => {
    const known = program.targets.get(from);
    if (slot >= 0 && Array.isArray(known)) known[slot] = target;
    else if (known === undefined) program.targets.set(from, target);
    else if (typeof known === 'number') program.targets.set(from, [known, target]);
    else known.push(target);
  };
  const resolve = (frame: Frame, target: number) => {
    for (const [from, slot] of frame.pending ?? []) addTarget(from, slot, target);
  };
  /** Records a branch to the label `depthOf` blocks out (at `slot` of a br_table); returns how many values it carries. */
  const branchTo = (from: number, depthOf: number, slot = -1): number => {
    const frame = frames[frames.length - 1 - depthOf];
    if (!frame) return 0;
    if (frame.kind === FRAME.LOOP) {
      addTarget(from, slot, frame.start);
      flags[frame.start]! |= IF.LABEL;
      return frame.params;
    }
    (frame.pending ??= []).push([from, slot]);
    return frame.results;
  };

  for (let b = 0; b < module.bodies.length; b++) {
    const body = module.bodies[b]!;
    const func = module.importedFuncs + b;
    const type = funcTypeOf(module, func);
    const results = type?.results.length ?? 0;
    const first = total;
    frames.length = 0;
    nodes.length = 0;
    frames.push({ kind: FRAME.FUNCTION, start: first, open: -1, pending: null, params: 0, results, sugar: false });
    let previousConst: number | undefined;
    for (let pos = body.code; pos < body.end && total < capacity; ) {
      const i = total++;
      if (i >= nextTick) {
        nextTick += CHUNK;
        progress('decode', pos - module.bodies[0]!.code, module.bodies[module.bodies.length - 1]!.end - module.bodies[0]!.code);
        await tick();
      }
      decodeAt(bytes, pos, body.end, insn);
      offsets[i] = pos;
      let id = mnemonicIds.get(insn.m);
      if (id === undefined) {
        id = program.mnemonics.length;
        mnemonicIds.set(insn.m, id);
        program.mnemonics.push(insn.m);
        counts.push(0);
      }
      ids[i] = id;
      counts[id]!++;
      const level = Math.max(0, frames.length - 1);
      depth[i] = level;
      const op = insn.op;
      pos += insn.len;
      if (!op) {
        flags[i]! |= IF.UNKNOWN;
        nodes.length = 0;
        continue;
      }
      const m = insn.m;
      const opFlags = op.flags;
      let constValue: number | undefined;

      if (opFlags & W.STRUCTURE) {
        let fold = false;
        switch (m) {
          case 'block':
          case 'loop':
          case 'try':
          case 'try_table': {
            const [params, res] = blockArity(program, insn);
            frames.push({ kind: m === 'loop' ? FRAME.LOOP : m === 'block' ? FRAME.BLOCK : FRAME.TRY, start: i, open: -1, pending: null, params, results: res, sugar: false });
            if (m === 'try_table') {
              // Catch clauses go to labels outside the try_table.
              frames.pop();
              for (const c of insn.catches ?? []) branchTo(i, c.label);
              frames.push({ kind: FRAME.TRY, start: i, open: -1, pending: null, params, results: res, sugar: false });
              if (insn.catches?.length) flags[i]! |= IF.BRANCH;
            }
            break;
          }
          case 'if': {
            const [params, res] = blockArity(program, insn);
            // `if c {` when the condition is in the line and no values go in or out of the block.
            fold = params === 0 && res === 0 && folds(1, i);
            if (fold) {
              fuse(nodes[nodes.length - 1]!.start, i);
              flags[i]! |= WF.SUGAR_IF;
            }
            frames.push({ kind: FRAME.IF, start: i, open: i, pending: null, params, results: res, sugar: fold });
            flags[i]! |= IF.BRANCH;
            break;
          }
          case 'else':
          case 'catch':
          case 'catch_all': {
            const frame = frames[frames.length - 1];
            depth[i] = Math.max(0, level - 1);
            if (frame && frame.kind === FRAME.IF && m === 'else') {
              if (frame.sugar) flags[i]! |= WF.IF_END;
              program.targets.set(frame.open, i);
              frame.open = i;
              flags[i]! |= IF.BRANCH;
            }
            break;
          }
          case 'end':
          case 'delegate': {
            depth[i] = Math.max(0, level - 1);
            const frame = frames.pop();
            if (!frame) break;
            if (frame.kind === FRAME.IF && frame.open >= 0) program.targets.set(frame.open, i);
            if (frame.kind === FRAME.IF && frame.sugar) flags[i]! |= WF.IF_END;
            if (frame.pending) {
              resolve(frame, i);
              flags[i]! |= IF.LABEL;
            }
            if (frame.kind === FRAME.FUNCTION) {
              // The function's end returns what is on the stack.
              if (results <= 1 && folds(results, i) && results) fuse(nodes[nodes.length - 1]!.start, i);
            }
            break;
          }
        }
        nodes.length = 0;
        previousConst = undefined;
        continue;
      }

      if (opFlags & W.BRANCH || m === 'return') {
        flags[i]! |= IF.BRANCH;
        let pops = -1;
        switch (m) {
          case 'br':
            if (branchTo(i, insn.a) === 0) pops = 0;
            break;
          case 'br_if':
            if (branchTo(i, insn.a) === 0) pops = 1;
            break;
          case 'br_table': {
            let arity = 0;
            const labels = insn.labels ?? [];
            program.targets.set(i, new Array<number>(labels.length).fill(-1));
            labels.forEach((label, slot) => {
              arity = branchTo(i, label, slot);
            });
            if (arity === 0) pops = 1;
            break;
          }
          case 'return':
            flags[i]! &= ~IF.BRANCH;
            if (results <= 1) pops = results;
            break;
          default:
            // br_on_null, br_on_cast…: they leave values behind; the line stays an instruction.
            branchTo(i, insn.a);
        }
        if (pops < 0) program.valueBranches.add(i);
        if (pops > 0 && folds(pops, i)) fuse(nodes[nodes.length - pops]!.start, i);
        nodes.length = 0;
        previousConst = undefined;
        continue;
      }

      const eff = effect(insn, program.effects);
      if (!eff) {
        nodes.length = 0;
        previousConst = undefined;
        continue;
      }
      const [pops, pushes] = eff;
      const fold = folds(pops, i);
      const start = fold && pops ? nodes[nodes.length - pops]!.start : i;

      // Memory at a constant address: the address operand is the first value taken.
      if (op.imm === IMM.MEMARG || op.imm === IMM.MEMARG_LANE) {
        const address = pops <= nodes.length ? nodes[nodes.length - pops] : undefined;
        if (address && address.start === address.end && address.value !== undefined && typeof insn.value === 'number') {
          append(program.dataRefs, address.value + insn.value, pos - insn.len);
        }
      }
      if (op.imm === IMM.I32 || op.imm === IMM.I64) {
        const value = Number(insn.value);
        constValue = Number.isSafeInteger(value) ? value : undefined;
        if (constValue !== undefined && constValue > 0 && program.segmentAt(constValue)) append(program.dataRefs, constValue, pos - insn.len);
        // Rust passes a &str as a pointer and then its length.
        if (constValue !== undefined && previousConst !== undefined && constValue > 0 && constValue < 4096 && program.segmentAt(previousConst)) {
          const seen = program.lengthAt.get(previousConst);
          program.lengthAt.set(previousConst, seen === undefined ? constValue : Math.min(seen, constValue));
        }
      }
      switch (m) {
        case 'call':
        case 'return_call':
          flags[i]! |= IF.CALL;
          append(program.callers, program.funcAddr(insn.a), pos - insn.len);
          break;
        case 'call_indirect':
        case 'return_call_indirect':
        case 'call_ref':
        case 'return_call_ref':
          flags[i]! |= IF.CALL;
          program.indirectCalls++;
          break;
        case 'ref.func':
          append(program.refFuncs, program.funcAddr(insn.a), pos - insn.len);
          break;
        case 'global.get':
        case 'global.set':
          append(program.globalRefs, insn.a, pos - insn.len);
          break;
      }

      if (pops > nodes.length) nodes.length = 0;
      else nodes.length -= pops;
      if (pushes === 0) {
        if (fold && pops) fuse(start, i);
      } else if (pushes === 1) {
        nodes.push({ start, end: i, ok: fold || pops === 0, value: constValue });
      } else {
        for (let k = 0; k < pushes; k++) nodes.push({ start: i, end: i, ok: false, value: undefined });
      }
      if (opFlags & W.END) nodes.length = 0;
      previousConst = constValue;
    }
    const fn = program.byIndex[func]!;
    fn.first = first;
    fn.count = total - first;
    if (!fn.count) continue;
    program.functionAtIndex.set(first, program.functions.length);
    program.functions.push(fn);
    program.bodies.push(body);
    flags[first]! |= IF.FUNCTION;
  }

  program.offsets = offsets.slice(0, total);
  program.depth = depth.slice(0, total);
  program.mnemonicIds = ids.slice(0, total);
  program.flags = flags.slice(0, total);
  program.totalInstructions = total;
  if (total) program.ranges.push({ name: 'code', first: 0, count: total });
  program.decodeMs = Date.now() - started;
  program.tally(counts);
  progress('decode', 1, 1);

  // Names and kinds.
  progress('functions', 0, 1);
  await tick();
  const names = new Map<number, Pick<Fn, 'name' | 'full' | 'raw' | 'language'>>();
  const exports = new Map<number, string>();
  for (const e of module.exports) if (e.kind === 'func' && !exports.has(e.index)) exports.set(e.index, e.name);
  const symbols = new Map<number, string>();
  for (const s of module.linking?.symbols ?? []) if (s.kind === 'function' && s.name && !symbols.has(s.index)) symbols.set(s.index, s.name);
  for (const fn of program.functions) {
    const index = fn.index!;
    const raw = module.names.functions.get(index) ?? symbols.get(index) ?? exports.get(index);
    if (raw) {
      const d = demangle(raw);
      Object.assign(fn, { name: d.short, full: d.full, raw, language: d.language });
      names.set(index, fn);
    }
    if (index === module.start) fn.kind = 'entry';
    else if (exported.has(index)) fn.kind = 'export';
    else if (raw) fn.kind = 'symbol';
  }

  // Branches into the end of their own function stay; labels on a function's first instruction are not shown twice.
  for (let k = 0; k + 1 < total; k++) if (flags[k]! & IF.FUSE && flags[k + 1]! & IF.FUNCTION) flags[k]! &= ~IF.FUSE;

  findStrings(program);
  // A Rust literal has no NUL: the length its code passes cuts it from the next one.
  for (const ref of program.strings) {
    const length = program.lengthAt.get(ref.addr);
    const bytes = new TextEncoder().encode(ref.text);
    if (length !== undefined && length > 0 && length < bytes.length) {
      ref.text = utf8(bytes.subarray(0, length));
      ref.kind = 'const';
    }
  }
  // Strings code points at that the scan did not find (no NUL, or short).
  for (const addr of program.dataRefs.keys()) {
    if (program.stringAt.has(addr)) continue;
    const found = program.dataAt(addr);
    if (found?.kind !== 'string') continue;
    const ref: StringRef = { addr, text: found.text, section: program.segmentAt(addr)?.name ?? '', kind: 'const' };
    program.strings.push(ref);
    program.stringAt.set(addr, ref);
  }
  program.strings.sort((a, b) => a.addr - b.addr);
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
