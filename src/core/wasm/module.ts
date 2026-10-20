/**
 * A WebAssembly module: everything in the file that is not code.
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
 * The core reads it (crates/core/src/wasm/module.rs) and hands it over as JSON
 * (crates/wasm/src/wasm_module.rs); what is here is its shape, built from that,
 * and the few texts the page makes of it. Nothing here touches the DOM.
 */

import { engine } from '../engine/engine';
import { t } from '../i18n';

/** A heap type: an abstract one by name, or a type index. */
export type HeapType = string | number;

/** A value type as the decoder keeps it: its text, and whether it is a number type. */
export interface ValType {
  text: string;
  /** i32, i64, f32, f64, v128, or 'ref'. */
  kind: string;
}

/** A module so damaged its sections cannot be told apart: the reader's own message. */
export class WasmError extends Error {}

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

export function isWasm(bytes: Uint8Array): boolean {
  return bytes.length >= 8 && bytes[0] === 0 && bytes[1] === 0x61 && bytes[2] === 0x73 && bytes[3] === 0x6d;
}

/** What the core hands over: the module without its bytes, its maps as lists of entries; or why it is not one. */
type CoreModule = Omit<WasmModule, 'bytes' | 'names' | 'debug'> & {
  names: { [K in keyof Names]: K extends 'module' ? string | undefined : [number, unknown][] };
  debug: [string, { start: number; size: number }][];
};
type CoreError = { error: 'signature' | 'component' | 'version' | 'damaged'; version?: string; message?: string };

const map = <V>(entries: [number, V][]): Map<number, V> => new Map(entries);

/** Reads a WebAssembly module. Throws NotWasm for anything else, WasmError for a module too damaged to read. */
export function parseWasm(bytes: Uint8Array): WasmModule {
  const found = engine().wasmParse<CoreModule | CoreError>(bytes);
  if ('error' in found) {
    switch (found.error) {
      case 'signature':
        throw new NotWasm(t('open', 'Not a WebAssembly module (no \\0asm signature).'));
      case 'component':
        throw new NotWasm(t('open', 'This is a WebAssembly component, not a core module: the disassembler reads core modules.'));
      case 'version':
        throw new NotWasm(t('open', 'Unknown WebAssembly version {version}.', { version: found.version ?? '' }));
    }
    throw new WasmError(found.message ?? '');
  }
  const n = found.names;
  const nested = (entries: [number, unknown][]) => new Map(entries.map(([k, inner]) => [k, map(inner as [number, string][])]));
  const names: Names = {
    functions: map(n.functions as [number, string][]), locals: nested(n.locals), labels: nested(n.labels), types: map(n.types as [number, string][]),
    tables: map(n.tables as [number, string][]), memories: map(n.memories as [number, string][]), globals: map(n.globals as [number, string][]),
    elements: map(n.elements as [number, string][]), data: map(n.data as [number, string][]), fields: nested(n.fields), tags: map(n.tags as [number, string][]),
  };
  if (n.module !== undefined) names.module = n.module;
  return { ...found, bytes, names, debug: new Map(found.debug) };
}

/* ------------------------------------------------------------------ *
 * Lookups
 * ------------------------------------------------------------------ */

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
