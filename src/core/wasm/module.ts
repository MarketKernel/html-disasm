/**
 * A WebAssembly module reader: everything in the file that is not code.
 *
 * Every section of the binary format is read — types (with the rec groups,
 * structs and arrays of GC), imports, functions, tables, memories, globals,
 * exports, the start function, element and data segments, tags — and the
 * custom sections tools leave behind: the `name` section (names of
 * functions, locals, globals, data segments and more), `producers` (the
 * languages and compilers), `target_features`, `dylink.0` of dynamic
 * libraries, `linking` and `reloc.*` of object files, `sourceMappingURL`,
 * `external_debug_info`, `build_id` and the DWARF `.debug_*` sections.
 *
 * Function bodies are only located here; src/core/wasm/program.ts decodes them.
 * Nothing here touches the DOM.
 */

import { t } from '../i18n';
import { decodeAt, formatInsn, WasmInsn, type FormatContext } from './decode';
import { Reader, storageType, utf8, valType, WasmError, type ValType } from './reader';

export class NotWasm extends Error {}

export interface FuncType {
  params: ValType[];
  results: ValType[];
}

export interface TypeDef {
  kind: 'func' | 'struct' | 'array' | 'cont';
  func?: FuncType;
  fields?: { type: ValType; mutable: boolean }[];
  /** The function type a continuation type wraps. */
  cont?: number;
  final: boolean;
  supers: number[];
  /** Index of the first type of its rec group, and how many the group has. */
  group: number;
  groupSize: number;
}

export interface WasmSection {
  id: number;
  /** The section's name: `type`, `code`, or the name of a custom section. */
  name: string;
  /** Where the section starts (its id byte) and where its contents start. */
  offset: number;
  start: number;
  size: number;
  /** The number of entries, for sections that are a vector. */
  count?: number;
}

export interface Limits {
  min: number | bigint;
  max?: number | bigint;
  shared: boolean;
  is64: boolean;
  /** log2 of the page size, when it is not the usual 64 KiB. */
  pageSizeLog2?: number;
}

export type ExternKind = 'func' | 'table' | 'memory' | 'global' | 'tag';

export interface WasmImport {
  module: string;
  name: string;
  kind: ExternKind;
  /** Its index among the items of its kind (imports come first). */
  index: number;
  /** For a function or tag: its type. */
  type?: number;
  /** Where the entry is in the file. */
  offset: number;
}

export interface WasmExport {
  name: string;
  kind: ExternKind;
  index: number;
}

export interface WasmTable {
  type: ValType;
  limits: Limits;
  imported: boolean;
  init?: string;
}

export interface WasmMemory {
  limits: Limits;
  imported: boolean;
}

export interface WasmGlobal {
  type: ValType;
  mutable: boolean;
  imported: boolean;
  init?: string;
  /** The value of a constant initialiser. */
  value?: number | bigint;
}

export interface WasmElement {
  mode: 'active' | 'passive' | 'declarative';
  table: number;
  offset?: string;
  offsetValue?: number;
  type: string;
  /** Function indices (null for an entry that is not a ref.func). */
  funcs: (number | null)[];
}

export interface WasmData {
  mode: 'active' | 'passive';
  memory: number;
  offset?: string;
  /** The memory address of an active segment with a constant offset. */
  addr?: number;
  /** Where its bytes are in the file. */
  start: number;
  size: number;
}

export interface WasmBody {
  /** Index of the function in the function index space (imports first). */
  func: number;
  /** Where the body's size is, where its locals start, where its first instruction is, where it ends. */
  offset: number;
  start: number;
  code: number;
  end: number;
  locals: { count: number; type: ValType }[];
}

export interface Names {
  module?: string;
  functions: Map<number, string>;
  locals: Map<number, Map<number, string>>;
  labels: Map<number, Map<number, string>>;
  types: Map<number, string>;
  tables: Map<number, string>;
  memories: Map<number, string>;
  globals: Map<number, string>;
  elements: Map<number, string>;
  data: Map<number, string>;
  fields: Map<number, Map<number, string>>;
  tags: Map<number, string>;
}

export interface Producer {
  field: string;
  values: { name: string; version: string }[];
}

export interface CustomSection {
  name: string;
  offset: number;
  start: number;
  size: number;
  /** Its contents, when they are short printable text. */
  text?: string;
}

export interface Dylink {
  memorySize: number;
  memoryAlign: number;
  tableSize: number;
  tableAlign: number;
  needed: string[];
}

export interface LinkingSymbol {
  kind: 'function' | 'data' | 'global' | 'section' | 'tag' | 'table';
  name: string;
  index: number;
  flags: number;
  defined: boolean;
}

export interface WasmModule {
  bytes: Uint8Array;
  version: number;
  sections: WasmSection[];
  types: TypeDef[];
  imports: WasmImport[];
  /** The type of every function, imported ones first. */
  funcTypes: number[];
  importedFuncs: number;
  tables: WasmTable[];
  memories: WasmMemory[];
  globals: WasmGlobal[];
  tags: number[];
  exports: WasmExport[];
  start?: number;
  elements: WasmElement[];
  data: WasmData[];
  dataCount?: number;
  bodies: WasmBody[];
  names: Names;
  producers: Producer[];
  features: { prefix: string; name: string }[];
  customs: CustomSection[];
  dylink?: Dylink;
  /** A relocatable object file (from `clang -c`): its symbols. */
  linking?: { version: number; symbols: LinkingSymbol[] };
  relocations: { section: string; count: number }[];
  sourceMappingUrl?: string;
  externalDebugInfo?: string;
  buildId?: string;
  /** The DWARF sections, by name. */
  debug: Map<string, { start: number; size: number }>;
  /** True when any memory is 64-bit (addresses are i64). */
  memory64: boolean;
  /** Problems met while reading, kept so the page can say what it skipped. */
  warnings: string[];
}

const SECTION_NAMES = ['custom', 'type', 'import', 'function', 'table', 'memory', 'global', 'export', 'start', 'element', 'code', 'data', 'data count', 'tag'];
const KINDS: ExternKind[] = ['func', 'table', 'memory', 'global', 'tag'];

export function isWasm(bytes: Uint8Array): boolean {
  return bytes.length >= 8 && bytes[0] === 0 && bytes[1] === 0x61 && bytes[2] === 0x73 && bytes[3] === 0x6d;
}

function emptyNames(): Names {
  return {
    functions: new Map(), locals: new Map(), labels: new Map(), types: new Map(), tables: new Map(), memories: new Map(),
    globals: new Map(), elements: new Map(), data: new Map(), fields: new Map(), tags: new Map(),
  };
}

/** Reads a WebAssembly module. Throws NotWasm for anything else. */
export function parseWasm(bytes: Uint8Array): WasmModule {
  if (!isWasm(bytes)) throw new NotWasm(t('open', 'Not a WebAssembly module (no \\0asm signature).'));
  const version = bytes[4]! | (bytes[5]! << 8) | (bytes[6]! << 16) | (bytes[7]! << 24);
  if ((version & 0xffff) !== 1 || version >>> 16 !== 0) {
    if (version >>> 16 === 1) throw new NotWasm(t('open', 'This is a WebAssembly component, not a core module: the disassembler reads core modules.'));
    throw new NotWasm(t('open', 'Unknown WebAssembly version {version}.', { version: `0x${version.toString(16)}` }));
  }
  const module: WasmModule = {
    bytes, version: 1, sections: [], types: [], imports: [], funcTypes: [], importedFuncs: 0, tables: [], memories: [], globals: [],
    tags: [], exports: [], elements: [], data: [], bodies: [], names: emptyNames(), producers: [], features: [], customs: [],
    relocations: [], debug: new Map(), memory64: false, warnings: [],
  };
  const r = new Reader(bytes, 8);
  let defined: number[] = [];
  while (!r.done) {
    const offset = r.pos;
    const id = r.u8();
    const size = r.u32();
    const start = r.pos;
    const end = start + size;
    if (end > bytes.length) {
      module.warnings.push(`section ${id} at 0x${offset.toString(16)} runs past the end of the file`);
      break;
    }
    const s = new Reader(bytes, start, end);
    const section: WasmSection = { id, name: SECTION_NAMES[id] ?? `unknown ${id}`, offset, start, size };
    module.sections.push(section);
    try {
      switch (id) {
        case 0: {
          section.name = s.name();
          readCustom(module, section.name, new Reader(bytes, s.pos, end), offset);
          break;
        }
        case 1:
          section.count = readTypes(s, module.types);
          break;
        case 2:
          section.count = readImports(s, module);
          break;
        case 3: {
          const count = (section.count = s.u32());
          defined = [];
          for (let i = 0; i < count; i++) defined.push(s.u32());
          break;
        }
        case 4: {
          const count = (section.count = s.u32());
          for (let i = 0; i < count; i++) {
            let init: string | undefined;
            if (s.peek() === 0x40) {
              s.u8();
              s.u8();
              const type = valType(s);
              const limits = readLimits(s);
              init = constExpr(s, module).text;
              module.tables.push({ type, limits, imported: false, init });
            } else {
              const type = valType(s);
              module.tables.push({ type, limits: readLimits(s), imported: false });
            }
          }
          break;
        }
        case 5: {
          const count = (section.count = s.u32());
          for (let i = 0; i < count; i++) module.memories.push({ limits: readLimits(s), imported: false });
          break;
        }
        case 6: {
          const count = (section.count = s.u32());
          for (let i = 0; i < count; i++) {
            const type = valType(s);
            const mutable = !!(s.u8() & 1);
            const init = constExpr(s, module);
            module.globals.push({ type, mutable, imported: false, init: init.text, value: init.value });
          }
          break;
        }
        case 7: {
          const count = (section.count = s.u32());
          for (let i = 0; i < count; i++) {
            const name = s.name();
            const kind = KINDS[s.u8()] ?? 'func';
            module.exports.push({ name, kind, index: s.u32() });
          }
          break;
        }
        case 8:
          module.start = s.u32();
          break;
        case 9:
          section.count = readElements(s, module);
          break;
        case 10: {
          const count = (section.count = s.u32());
          for (let i = 0; i < count; i++) {
            const bodyOffset = s.pos;
            const bodySize = s.u32();
            const bodyStart = s.pos;
            const bodyEnd = bodyStart + bodySize;
            const b = new Reader(bytes, bodyStart, bodyEnd);
            const locals: WasmBody['locals'] = [];
            const groups = b.u32();
            for (let g = 0; g < groups; g++) locals.push({ count: b.u32(), type: valType(b) });
            module.bodies.push({ func: module.importedFuncs + i, offset: bodyOffset, start: bodyStart, code: b.pos, end: bodyEnd, locals });
            s.pos = bodyEnd;
          }
          break;
        }
        case 11: {
          const count = (section.count = s.u32());
          for (let i = 0; i < count; i++) {
            const flags = s.u32();
            const memory = flags === 2 ? s.u32() : 0;
            let offset: string | undefined;
            let addr: number | undefined;
            if (flags !== 1) {
              const expr = constExpr(s, module);
              offset = expr.text;
              if (typeof expr.value === 'number') addr = expr.value >>> 0;
              else if (typeof expr.value === 'bigint' && expr.value >= 0n && expr.value <= BigInt(Number.MAX_SAFE_INTEGER)) addr = Number(expr.value);
            }
            const size = s.u32();
            module.data.push({ mode: flags === 1 ? 'passive' : 'active', memory, offset, addr, start: s.pos, size });
            s.pos += size;
          }
          break;
        }
        case 12:
          module.dataCount = s.u32();
          break;
        case 13: {
          const count = (section.count = s.u32());
          for (let i = 0; i < count; i++) {
            s.u8();
            module.tags.push(s.u32());
          }
          break;
        }
        default:
          module.warnings.push(`unknown section ${id} at 0x${offset.toString(16)}`);
      }
    } catch (err) {
      module.warnings.push(`${section.name} section: ${err instanceof Error ? err.message : String(err)}`);
    }
    r.pos = end;
  }
  module.funcTypes.push(...defined);
  module.memory64 = module.memories.some((m) => m.limits.is64);
  if (module.bodies.length !== defined.length) module.warnings.push(`${defined.length} functions declared, ${module.bodies.length} bodies`);
  return module;
}

/* ------------------------------------------------------------------ *
 * Sections
 * ------------------------------------------------------------------ */

function funcType(s: Reader): FuncType {
  const params: ValType[] = [];
  const results: ValType[] = [];
  for (let n = s.u32(), i = 0; i < n; i++) params.push(valType(s));
  for (let n = s.u32(), i = 0; i < n; i++) results.push(valType(s));
  return { params, results };
}

function field(s: Reader): { type: ValType; mutable: boolean } {
  const type = storageType(s);
  return { type, mutable: !!(s.u8() & 1) };
}

function compositeType(s: Reader, first: number, base: Omit<TypeDef, 'kind'>): TypeDef {
  switch (first) {
    case 0x60:
      return { ...base, kind: 'func', func: funcType(s) };
    case 0x5f: {
      const fields: TypeDef['fields'] = [];
      for (let n = s.u32(), i = 0; i < n; i++) fields.push(field(s));
      return { ...base, kind: 'struct', fields };
    }
    case 0x5e:
      return { ...base, kind: 'array', fields: [field(s)] };
    case 0x5d:
      return { ...base, kind: 'cont', cont: s.u32() };
  }
  throw new WasmError(`unknown type form 0x${first.toString(16)}`);
}

function subType(s: Reader, group: number, groupSize: number): TypeDef {
  let first = s.u8();
  let final = true;
  let supers: number[] = [];
  if (first === 0x50 || first === 0x4f) {
    final = first === 0x4f;
    supers = [];
    for (let n = s.u32(), i = 0; i < n; i++) supers.push(s.u32());
    first = s.u8();
  }
  if (first === 0x65) first = s.u8(); // shared composite type
  return compositeType(s, first, { final, supers, group, groupSize });
}

function readTypes(s: Reader, types: TypeDef[]): number {
  const count = s.u32();
  for (let i = 0; i < count; i++) {
    if (s.peek() === 0x4e) {
      s.u8();
      const size = s.u32();
      const group = types.length;
      for (let j = 0; j < size; j++) types.push(subType(s, group, size));
    } else types.push(subType(s, types.length, 1));
  }
  return count;
}

function readLimits(s: Reader): Limits {
  const flags = s.u8();
  const is64 = !!(flags & 4);
  const min = is64 ? s.u64() : s.u32();
  const max = flags & 1 ? (is64 ? s.u64() : s.u32()) : undefined;
  const pageSizeLog2 = flags & 8 ? s.u32() : undefined;
  return { min, max, shared: !!(flags & 2), is64, pageSizeLog2 };
}

function readImports(s: Reader, module: WasmModule): number {
  const count = s.u32();
  const counters = { func: 0, table: 0, memory: 0, global: 0, tag: 0 };
  for (let i = 0; i < count; i++) {
    const offset = s.pos;
    const moduleName = s.name();
    const name = s.name();
    const kind = KINDS[s.u8()];
    if (!kind) throw new WasmError(`import ${moduleName}.${name}: unknown kind`);
    const entry: WasmImport = { module: moduleName, name, kind, index: counters[kind]++, offset };
    switch (kind) {
      case 'func':
        entry.type = s.u32();
        module.funcTypes.push(entry.type);
        module.importedFuncs++;
        break;
      case 'table': {
        const type = valType(s);
        module.tables.push({ type, limits: readLimits(s), imported: true });
        break;
      }
      case 'memory':
        module.memories.push({ limits: readLimits(s), imported: true });
        break;
      case 'global': {
        const type = valType(s);
        module.globals.push({ type, mutable: !!(s.u8() & 1), imported: true });
        break;
      }
      case 'tag':
        s.u8();
        entry.type = s.u32();
        module.tags.push(entry.type);
        break;
    }
    module.imports.push(entry);
  }
  return count;
}

/**
 * A constant expression up to its `end`: its text, and its value when it can
 * be worked out — constants, the extended-constant arithmetic, and the
 * globals a dynamic library is given (__memory_base and __table_base, taken
 * as 0 so its data shows at offsets from its base).
 */
function constExpr(s: Reader, module: WasmModule): { text: string; value?: number | bigint; func?: number | null } {
  const parts: string[] = [];
  const insn = new WasmInsn();
  const stack: (number | bigint | undefined)[] = [];
  let func: number | null | undefined;
  let count = 0;
  const ctx = formatContext(module);
  const binary = (f: (a: bigint, b: bigint) => bigint, bits: number) => {
    const b = stack.pop();
    const a = stack.pop();
    if (a === undefined || b === undefined) return stack.push(undefined);
    const r = f(BigInt(a), BigInt(b));
    stack.push(bits === 32 ? Number(BigInt.asIntN(32, r)) : BigInt.asIntN(64, r));
  };
  for (;;) {
    decodeAt(s.bytes, s.pos, s.end, insn);
    if (!insn.op) throw new WasmError(`bad constant expression at 0x${s.pos.toString(16)}`);
    s.pos += insn.len;
    if (insn.m === 'end') break;
    count++;
    parts.push(formatInsn(insn, ctx));
    switch (insn.m) {
      case 'i32.const':
      case 'i64.const':
        stack.push(insn.value);
        break;
      case 'global.get': {
        const global = module.globals[insn.a];
        const imported = module.imports.find((i) => i.kind === 'global' && i.index === insn.a);
        if (imported && /^__(memory|table)_base$/.test(imported.name)) stack.push(0);
        else stack.push(global?.imported ? undefined : global?.value);
        break;
      }
      case 'i32.add': binary((a, b) => a + b, 32); break;
      case 'i32.sub': binary((a, b) => a - b, 32); break;
      case 'i32.mul': binary((a, b) => a * b, 32); break;
      case 'i64.add': binary((a, b) => a + b, 64); break;
      case 'i64.sub': binary((a, b) => a - b, 64); break;
      case 'i64.mul': binary((a, b) => a * b, 64); break;
      case 'ref.func': func = insn.a; stack.push(undefined); break;
      case 'ref.null': func = null; stack.push(undefined); break;
      default: stack.push(undefined);
    }
  }
  let value = stack.length === 1 ? stack[0] : undefined;
  if (typeof value === 'bigint' && value >= -BigInt(Number.MAX_SAFE_INTEGER) && value <= BigInt(Number.MAX_SAFE_INTEGER)) value = Number(value);
  return { text: parts.join(' '), value, func: count === 1 ? func : undefined };
}

function readElements(s: Reader, module: WasmModule): number {
  const count = s.u32();
  for (let i = 0; i < count; i++) {
    const flags = s.u32();
    const passiveOrDeclarative = flags & 1;
    const explicitTable = flags & 2;
    const usesExprs = flags & 4;
    const mode: WasmElement['mode'] = passiveOrDeclarative ? (explicitTable ? 'declarative' : 'passive') : 'active';
    let table = 0;
    let offset: string | undefined;
    let offsetValue: number | undefined;
    if (!passiveOrDeclarative) {
      if (explicitTable) table = s.u32();
      const expr = constExpr(s, module);
      offset = expr.text;
      if (typeof expr.value === 'number') offsetValue = expr.value;
    }
    let type = 'funcref';
    if (passiveOrDeclarative || explicitTable) {
      if (usesExprs) type = valType(s).text;
      else s.u8(); // elemkind 0x00: funcref
    }
    const funcs: (number | null)[] = [];
    const n = s.u32();
    for (let j = 0; j < n; j++) {
      if (usesExprs) {
        const expr = constExpr(s, module);
        funcs.push(expr.func ?? null);
      } else funcs.push(s.u32());
    }
    module.elements.push({ mode, table, offset, offsetValue, type, funcs });
  }
  return count;
}

/* ------------------------------------------------------------------ *
 * Custom sections
 * ------------------------------------------------------------------ */

function isPrintable(bytes: Uint8Array): boolean {
  for (const b of bytes) if ((b < 0x20 && b !== 9 && b !== 10 && b !== 13) || b === 0x7f) return false;
  return true;
}

function readCustom(module: WasmModule, name: string, s: Reader, offset: number): void {
  const custom: CustomSection = { name, offset, start: s.pos, size: s.end - s.pos };
  module.customs.push(custom);
  if (name.startsWith('.debug_')) {
    module.debug.set(name, { start: s.pos, size: s.end - s.pos });
    return;
  }
  switch (name) {
    case 'name':
      readNames(s, module.names);
      return;
    case 'producers': {
      for (let n = s.u32(), i = 0; i < n; i++) {
        const field = s.name();
        const values: Producer['values'] = [];
        for (let m = s.u32(), j = 0; j < m; j++) values.push({ name: s.name(), version: s.name() });
        module.producers.push({ field, values });
      }
      return;
    }
    case 'target_features': {
      for (let n = s.u32(), i = 0; i < n; i++) {
        const prefix = String.fromCharCode(s.u8());
        module.features.push({ prefix, name: s.name() });
      }
      return;
    }
    case 'sourceMappingURL':
      module.sourceMappingUrl = s.name();
      return;
    case 'external_debug_info':
      module.externalDebugInfo = s.name();
      return;
    case 'build_id': {
      const bytes = s.bytesN(s.u32());
      module.buildId = [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
      return;
    }
    case 'dylink.0': {
      const dylink: Dylink = { memorySize: 0, memoryAlign: 0, tableSize: 0, tableAlign: 0, needed: [] };
      while (!s.done) {
        const type = s.u8();
        const size = s.u32();
        const end = s.pos + size;
        if (type === 1) {
          dylink.memorySize = s.u32();
          dylink.memoryAlign = s.u32();
          dylink.tableSize = s.u32();
          dylink.tableAlign = s.u32();
        } else if (type === 2) {
          for (let n = s.u32(), i = 0; i < n; i++) dylink.needed.push(s.name());
        }
        s.pos = end;
      }
      module.dylink = dylink;
      return;
    }
    case 'dylink': {
      const dylink: Dylink = { memorySize: s.u32(), memoryAlign: s.u32(), tableSize: s.u32(), tableAlign: s.u32(), needed: [] };
      for (let n = s.u32(), i = 0; i < n; i++) dylink.needed.push(s.name());
      module.dylink = dylink;
      return;
    }
    case 'linking':
      module.linking = readLinking(s);
      return;
  }
  if (name.startsWith('reloc.')) {
    s.u32();
    module.relocations.push({ section: name.slice(6), count: s.u32() });
    return;
  }
  // Short custom sections that are text (go:buildid, a URL, a version) are shown as they are.
  const bytes = s.bytes.subarray(s.pos, s.end);
  if (bytes.length && bytes.length <= 512 && isPrintable(bytes)) custom.text = utf8(bytes);
}

function nameMap(s: Reader, into: Map<number, string>): void {
  for (let n = s.u32(), i = 0; i < n; i++) {
    const index = s.u32();
    into.set(index, s.name());
  }
}

function indirectNameMap(s: Reader, into: Map<number, Map<number, string>>): void {
  for (let n = s.u32(), i = 0; i < n; i++) {
    const index = s.u32();
    const map = new Map<number, string>();
    nameMap(s, map);
    into.set(index, map);
  }
}

function readNames(s: Reader, names: Names): void {
  while (!s.done) {
    const id = s.u8();
    const size = s.u32();
    const end = s.pos + size;
    const sub = new Reader(s.bytes, s.pos, end);
    try {
      switch (id) {
        case 0: names.module = sub.name(); break;
        case 1: nameMap(sub, names.functions); break;
        case 2: indirectNameMap(sub, names.locals); break;
        case 3: indirectNameMap(sub, names.labels); break;
        case 4: nameMap(sub, names.types); break;
        case 5: nameMap(sub, names.tables); break;
        case 6: nameMap(sub, names.memories); break;
        case 7: nameMap(sub, names.globals); break;
        case 8: nameMap(sub, names.elements); break;
        case 9: nameMap(sub, names.data); break;
        case 10: indirectNameMap(sub, names.fields); break;
        case 11: nameMap(sub, names.tags); break;
      }
    } catch {
      // A damaged subsection loses its names; the others stay.
    }
    s.pos = end;
  }
}

const SYMBOL_KINDS: LinkingSymbol['kind'][] = ['function', 'data', 'global', 'section', 'tag', 'table'];

function readLinking(s: Reader): WasmModule['linking'] {
  const version = s.u32();
  const symbols: LinkingSymbol[] = [];
  while (!s.done) {
    const type = s.u8();
    const size = s.u32();
    const end = s.pos + size;
    if (type === 8) {
      for (let n = s.u32(), i = 0; i < n; i++) {
        const kind = SYMBOL_KINDS[s.u8()] ?? 'function';
        const flags = s.u32();
        const undefinedSymbol = !!(flags & 0x10);
        const explicitName = !!(flags & 0x40);
        let name = '';
        let index = -1;
        if (kind === 'data') {
          name = s.name();
          if (!undefinedSymbol) {
            index = s.u32();
            s.u64();
            s.u64();
          }
        } else if (kind === 'section') {
          index = s.u32();
        } else {
          index = s.u32();
          if (!undefinedSymbol || explicitName) name = s.name();
        }
        symbols.push({ kind, name, index, flags, defined: !undefinedSymbol });
      }
    }
    s.pos = end;
  }
  return { version, symbols };
}

/* ------------------------------------------------------------------ *
 * Lookups
 * ------------------------------------------------------------------ */

export function formatContext(module: WasmModule): FormatContext {
  return { funcType: (index) => module.types[index]?.func };
}

/** The type of a function by its index, or undefined. */
export function funcTypeOf(module: WasmModule, func: number): FuncType | undefined {
  const type = module.funcTypes[func];
  return type === undefined ? undefined : module.types[type]?.func;
}

/** `(i32, i32) -> i32` */
export function signatureText(type: FuncType | undefined): string {
  if (!type) return '?';
  const params = `(${type.params.map((p) => p.text).join(', ')})`;
  if (!type.results.length) return params;
  return `${params} -> ${type.results.length === 1 ? type.results[0]!.text : `(${type.results.map((p) => p.text).join(', ')})`}`;
}

/** The text of a type definition: `func (i32) -> i32`, `struct { i32, mut i8 }`, `array mut i8`. */
export function typeText(def: TypeDef | undefined): string {
  if (!def) return '?';
  switch (def.kind) {
    case 'func':
      return `func ${signatureText(def.func)}`;
    case 'struct':
      return `struct { ${def.fields!.map((f) => `${f.mutable ? 'mut ' : ''}${f.type.text}`).join(', ')} }`;
    case 'array':
      return `array ${def.fields![0]!.mutable ? 'mut ' : ''}${def.fields![0]!.type.text}`;
    case 'cont':
      return `cont ${def.cont}`;
  }
}

export function limitsText(limits: Limits): string {
  return `${limits.min}${limits.max !== undefined ? `..${limits.max}` : '..'}`;
}

/** Bytes in one page of a memory. */
export function pageSize(limits: Limits): number {
  return 2 ** (limits.pageSizeLog2 ?? 16);
}
