/**
 * The metadata of a .NET assembly (ECMA-335, Partition II): the CLI header a
 * PE file's CLR data directory points at, the metadata root and its streams —
 * the tables (`#~`, or `#-` as Edit and Continue leaves them), the string
 * heaps (`#Strings`, `#US`), `#Blob` and `#GUID` — and the method bodies, with
 * their headers and exception-handling clauses.
 *
 * Every table is read whole into one typed array per column: an assembly the
 * size of System.Private.CoreLib has a few hundred thousand rows, and the
 * listing asks for names many times. Rows are numbered from 1, as tokens
 * number them; row 0 means none.
 */

import { t } from '../i18n';
import type { Pe } from '../pe';

export class NotCil extends Error {}

/** Table numbers, as the top byte of a token has them. */
export const TABLE = {
  Module: 0x00, TypeRef: 0x01, TypeDef: 0x02, FieldPtr: 0x03, Field: 0x04, MethodPtr: 0x05, MethodDef: 0x06, ParamPtr: 0x07, Param: 0x08,
  InterfaceImpl: 0x09, MemberRef: 0x0a, Constant: 0x0b, CustomAttribute: 0x0c, FieldMarshal: 0x0d, DeclSecurity: 0x0e, ClassLayout: 0x0f,
  FieldLayout: 0x10, StandAloneSig: 0x11, EventMap: 0x12, EventPtr: 0x13, Event: 0x14, PropertyMap: 0x15, PropertyPtr: 0x16, Property: 0x17,
  MethodSemantics: 0x18, MethodImpl: 0x19, ModuleRef: 0x1a, TypeSpec: 0x1b, ImplMap: 0x1c, FieldRVA: 0x1d, ENCLog: 0x1e, ENCMap: 0x1f,
  Assembly: 0x20, AssemblyProcessor: 0x21, AssemblyOS: 0x22, AssemblyRef: 0x23, AssemblyRefProcessor: 0x24, AssemblyRefOS: 0x25, File: 0x26,
  ExportedType: 0x27, ManifestResource: 0x28, NestedClass: 0x29, GenericParam: 0x2a, MethodSpec: 0x2b, GenericParamConstraint: 0x2c,
} as const;

/** The token type of a #US string (ldstr). */
export const USER_STRING = 0x70;

export const TABLE_NAMES = Object.fromEntries(Object.entries(TABLE).map(([name, id]) => [id, name])) as Record<number, string>;

/** Coded indexes: the tables a column may point into, in the order of their tags. -1 is a tag no table has. */
const CODED = {
  TypeDefOrRef: [TABLE.TypeDef, TABLE.TypeRef, TABLE.TypeSpec],
  HasConstant: [TABLE.Field, TABLE.Param, TABLE.Property],
  HasCustomAttribute: [
    TABLE.MethodDef, TABLE.Field, TABLE.TypeRef, TABLE.TypeDef, TABLE.Param, TABLE.InterfaceImpl, TABLE.MemberRef, TABLE.Module, TABLE.DeclSecurity,
    TABLE.Property, TABLE.Event, TABLE.StandAloneSig, TABLE.ModuleRef, TABLE.TypeSpec, TABLE.Assembly, TABLE.AssemblyRef, TABLE.File,
    TABLE.ExportedType, TABLE.ManifestResource, TABLE.GenericParam, TABLE.GenericParamConstraint, TABLE.MethodSpec,
  ],
  HasFieldMarshal: [TABLE.Field, TABLE.Param],
  HasDeclSecurity: [TABLE.TypeDef, TABLE.MethodDef, TABLE.Assembly],
  MemberRefParent: [TABLE.TypeDef, TABLE.TypeRef, TABLE.ModuleRef, TABLE.MethodDef, TABLE.TypeSpec],
  HasSemantics: [TABLE.Event, TABLE.Property],
  MethodDefOrRef: [TABLE.MethodDef, TABLE.MemberRef],
  MemberForwarded: [TABLE.Field, TABLE.MethodDef],
  Implementation: [TABLE.File, TABLE.AssemblyRef, TABLE.ExportedType],
  CustomAttributeType: [-1, -1, TABLE.MethodDef, TABLE.MemberRef, -1],
  ResolutionScope: [TABLE.Module, TABLE.ModuleRef, TABLE.AssemblyRef, TABLE.TypeRef],
  TypeOrMethodDef: [TABLE.TypeDef, TABLE.MethodDef],
} as const;

export type Coded = keyof typeof CODED;

/** A column: a fixed size, an index into a heap, a row of a table, or a coded index. */
type Column = 1 | 2 | 4 | 'str' | 'guid' | 'blob' | number | Coded;
/** A table index column is a table number written as `-1 - table`, to keep it apart from fixed sizes. */
const ix = (table: number): number => -1 - table;

const SCHEMA: Record<number, [string, Column][]> = {
  [TABLE.Module]: [['Generation', 2], ['Name', 'str'], ['Mvid', 'guid'], ['EncId', 'guid'], ['EncBaseId', 'guid']],
  [TABLE.TypeRef]: [['ResolutionScope', 'ResolutionScope'], ['Name', 'str'], ['Namespace', 'str']],
  [TABLE.TypeDef]: [['Flags', 4], ['Name', 'str'], ['Namespace', 'str'], ['Extends', 'TypeDefOrRef'], ['FieldList', ix(TABLE.Field)], ['MethodList', ix(TABLE.MethodDef)]],
  [TABLE.FieldPtr]: [['Field', ix(TABLE.Field)]],
  [TABLE.Field]: [['Flags', 2], ['Name', 'str'], ['Signature', 'blob']],
  [TABLE.MethodPtr]: [['Method', ix(TABLE.MethodDef)]],
  [TABLE.MethodDef]: [['RVA', 4], ['ImplFlags', 2], ['Flags', 2], ['Name', 'str'], ['Signature', 'blob'], ['ParamList', ix(TABLE.Param)]],
  [TABLE.ParamPtr]: [['Param', ix(TABLE.Param)]],
  [TABLE.Param]: [['Flags', 2], ['Sequence', 2], ['Name', 'str']],
  [TABLE.InterfaceImpl]: [['Class', ix(TABLE.TypeDef)], ['Interface', 'TypeDefOrRef']],
  [TABLE.MemberRef]: [['Class', 'MemberRefParent'], ['Name', 'str'], ['Signature', 'blob']],
  [TABLE.Constant]: [['Type', 2], ['Parent', 'HasConstant'], ['Value', 'blob']],
  [TABLE.CustomAttribute]: [['Parent', 'HasCustomAttribute'], ['Type', 'CustomAttributeType'], ['Value', 'blob']],
  [TABLE.FieldMarshal]: [['Parent', 'HasFieldMarshal'], ['NativeType', 'blob']],
  [TABLE.DeclSecurity]: [['Action', 2], ['Parent', 'HasDeclSecurity'], ['PermissionSet', 'blob']],
  [TABLE.ClassLayout]: [['PackingSize', 2], ['ClassSize', 4], ['Parent', ix(TABLE.TypeDef)]],
  [TABLE.FieldLayout]: [['Offset', 4], ['Field', ix(TABLE.Field)]],
  [TABLE.StandAloneSig]: [['Signature', 'blob']],
  [TABLE.EventMap]: [['Parent', ix(TABLE.TypeDef)], ['EventList', ix(TABLE.Event)]],
  [TABLE.EventPtr]: [['Event', ix(TABLE.Event)]],
  [TABLE.Event]: [['Flags', 2], ['Name', 'str'], ['EventType', 'TypeDefOrRef']],
  [TABLE.PropertyMap]: [['Parent', ix(TABLE.TypeDef)], ['PropertyList', ix(TABLE.Property)]],
  [TABLE.PropertyPtr]: [['Property', ix(TABLE.Property)]],
  [TABLE.Property]: [['Flags', 2], ['Name', 'str'], ['Type', 'blob']],
  [TABLE.MethodSemantics]: [['Semantics', 2], ['Method', ix(TABLE.MethodDef)], ['Association', 'HasSemantics']],
  [TABLE.MethodImpl]: [['Class', ix(TABLE.TypeDef)], ['MethodBody', 'MethodDefOrRef'], ['MethodDeclaration', 'MethodDefOrRef']],
  [TABLE.ModuleRef]: [['Name', 'str']],
  [TABLE.TypeSpec]: [['Signature', 'blob']],
  [TABLE.ImplMap]: [['MappingFlags', 2], ['MemberForwarded', 'MemberForwarded'], ['ImportName', 'str'], ['ImportScope', ix(TABLE.ModuleRef)]],
  [TABLE.FieldRVA]: [['RVA', 4], ['Field', ix(TABLE.Field)]],
  [TABLE.ENCLog]: [['Token', 4], ['FuncCode', 4]],
  [TABLE.ENCMap]: [['Token', 4]],
  [TABLE.Assembly]: [['HashAlgId', 4], ['Major', 2], ['Minor', 2], ['Build', 2], ['Revision', 2], ['Flags', 4], ['PublicKey', 'blob'], ['Name', 'str'], ['Culture', 'str']],
  [TABLE.AssemblyProcessor]: [['Processor', 4]],
  [TABLE.AssemblyOS]: [['Platform', 4], ['Major', 4], ['Minor', 4]],
  [TABLE.AssemblyRef]: [['Major', 2], ['Minor', 2], ['Build', 2], ['Revision', 2], ['Flags', 4], ['PublicKeyOrToken', 'blob'], ['Name', 'str'], ['Culture', 'str'], ['HashValue', 'blob']],
  [TABLE.AssemblyRefProcessor]: [['Processor', 4], ['AssemblyRef', ix(TABLE.AssemblyRef)]],
  [TABLE.AssemblyRefOS]: [['Platform', 4], ['Major', 4], ['Minor', 4], ['AssemblyRef', ix(TABLE.AssemblyRef)]],
  [TABLE.File]: [['Flags', 4], ['Name', 'str'], ['HashValue', 'blob']],
  [TABLE.ExportedType]: [['Flags', 4], ['TypeDefId', 4], ['Name', 'str'], ['Namespace', 'str'], ['Implementation', 'Implementation']],
  [TABLE.ManifestResource]: [['Offset', 4], ['Flags', 4], ['Name', 'str'], ['Implementation', 'Implementation']],
  [TABLE.NestedClass]: [['NestedClass', ix(TABLE.TypeDef)], ['EnclosingClass', ix(TABLE.TypeDef)]],
  [TABLE.GenericParam]: [['Number', 2], ['Flags', 2], ['Owner', 'TypeOrMethodDef'], ['Name', 'str']],
  [TABLE.MethodSpec]: [['Method', 'MethodDefOrRef'], ['Instantiation', 'blob']],
  [TABLE.GenericParamConstraint]: [['Owner', ix(TABLE.GenericParam)], ['Constraint', 'TypeDefOrRef']],
};

/** A table: its rows, one array per column; a coded index stays coded. */
export class Table {
  constructor(
    readonly id: number,
    readonly rows: number,
    readonly names: string[],
    readonly columns: Uint32Array[],
  ) {}

  /** A column of a row (rows from 1). */
  get(row: number, column: string): number {
    const c = this.names.indexOf(column);
    return c < 0 || row < 1 || row > this.rows ? 0 : this.columns[c]![row - 1]!;
  }

  col(column: string): Uint32Array {
    const c = this.names.indexOf(column);
    return c < 0 ? new Uint32Array(this.rows) : this.columns[c]!;
  }
}

/** A coded index split into its table and row. */
export function decodeIndex(kind: Coded, value: number): { table: number; row: number } {
  const tables = CODED[kind] as readonly number[];
  const bits = Math.ceil(Math.log2(tables.length));
  return { table: tables[value & ((1 << bits) - 1)] ?? -1, row: value >>> bits };
}

export const token = (table: number, row: number): number => ((table << 24) | row) >>> 0;
export const tokenTable = (tok: number): number => tok >>> 24;
export const tokenRow = (tok: number): number => tok & 0xffffff;

export interface Stream {
  name: string;
  /** File offset and size. */
  offset: number;
  size: number;
}

/** An exception-handling clause of a method body; offsets are in the method's IL. */
export interface Clause {
  /** 0 catch, 1 filter, 2 finally, 4 fault. */
  kind: number;
  tryStart: number;
  tryEnd: number;
  handlerStart: number;
  handlerEnd: number;
  /** A catch: the type token it catches; a filter: where the filter's code starts. */
  classToken: number;
  filterStart: number;
}

export interface MethodBody {
  /** The MethodDef row. */
  method: number;
  rva: number;
  /** File offset of the header and of the first IL byte; the IL's length. */
  offset: number;
  code: number;
  size: number;
  /** The fat header's fields (a tiny one: 8, no locals). */
  maxStack: number;
  localsToken: number;
  initLocals: boolean;
  fat: boolean;
  headerSize: number;
  clauses: Clause[];
}

export interface CliHeader {
  runtime: string;
  flags: number;
  /** A MethodDef token, or — with the native entry point flag — an RVA. */
  entryToken: number;
  metadataRva: number;
  metadataSize: number;
  resources: { rva: number; size: number };
  strongName: { rva: number; size: number };
  vtableFixups: { rva: number; size: number };
  /** ReadyToRun: the header of the native code compiled ahead of time. */
  managedNative: { rva: number; size: number };
}

export const CLI_FLAGS: [number, string][] = [[0x1, 'ILONLY'], [0x2, '32BITREQUIRED'], [0x4, 'IL_LIBRARY'], [0x8, 'STRONGNAMESIGNED'], [0x10, 'NATIVE_ENTRYPOINT'], [0x10000, 'TRACKDEBUGDATA'], [0x20000, '32BITPREFERRED']];

export class Metadata {
  readonly view: DataView;
  readonly tables: Table[] = [];
  readonly streams: Stream[] = [];
  version = '';
  /** The version of the table schema (2.0), and the heap size flags. */
  schema = '';
  heapSizes = 0;
  /** The tables are sorted where the standard asks: a bit per table. */
  sorted = 0n;
  /** File offsets of the heaps; -1 for a missing one. */
  private stringsAt = -1;
  private stringsEnd = -1;
  private blobAt = -1;
  private blobEnd = -1;
  private guidAt = -1;
  private usAt = -1;
  private usEnd = -1;
  private readonly stringCache = new Map<number, string>();
  readonly warnings: string[] = [];

  constructor(
    readonly bytes: Uint8Array,
    readonly offsetOf: (rva: number) => number,
    readonly header: CliHeader,
  ) {
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }

  u8(at: number): number {
    return at >= 0 && at < this.bytes.length ? this.bytes[at]! : 0;
  }
  u16(at: number): number {
    return at >= 0 && at + 2 <= this.bytes.length ? this.view.getUint16(at, true) : 0;
  }
  u32(at: number): number {
    return at >= 0 && at + 4 <= this.bytes.length ? this.view.getUint32(at, true) : 0;
  }

  table(id: number): Table {
    return this.tables[id] ?? EMPTY[id] ?? new Table(id, 0, [], []);
  }

  rows(id: number): number {
    return this.tables[id]?.rows ?? 0;
  }

  /** A name from #Strings (UTF-8, NUL-terminated). */
  string(index: number): string {
    if (!index || this.stringsAt < 0) return '';
    const cached = this.stringCache.get(index);
    if (cached !== undefined) return cached;
    const start = this.stringsAt + index;
    let end = start;
    while (end < this.stringsEnd && this.bytes[end] !== 0) end++;
    const text = utf8.decode(this.bytes.subarray(start, end));
    this.stringCache.set(index, text);
    return text;
  }

  /** A blob: its length is a compressed integer before it. */
  blob(index: number): Uint8Array {
    if (this.blobAt < 0) return new Uint8Array(0);
    const at = this.blobAt + index;
    if (at >= this.blobEnd) return new Uint8Array(0);
    const [length, size] = compressed(this.bytes, at);
    return this.bytes.subarray(at + size, Math.min(at + size + length, this.blobEnd));
  }


  guid(index: number): string {
    if (!index || this.guidAt < 0) return '';
    const at = this.guidAt + (index - 1) * 16;
    const b = this.bytes.subarray(at, at + 16);
    if (b.length < 16) return '';
    const h = (from: number, to: number, reverse = false) => {
      const part = [...b.subarray(from, to)];
      if (reverse) part.reverse();
      return part.map((x) => x.toString(16).padStart(2, '0')).join('');
    };
    return `${h(0, 4, true)}-${h(4, 6, true)}-${h(6, 8, true)}-${h(8, 10)}-${h(10, 16)}`.toUpperCase();
  }

  /** A string of #US (ldstr): UTF-16 after its byte length, with one more byte that flags special characters. */
  userString(index: number): string | undefined {
    if (this.usAt < 0) return undefined;
    const at = this.usAt + index;
    if (at >= this.usEnd) return undefined;
    const [length, size] = compressed(this.bytes, at);
    const start = at + size;
    const chars = Math.max(0, (length - 1) >> 1);
    if (start + chars * 2 > this.usEnd) return undefined;
    let text = '';
    for (let k = 0; k < chars; k++) text += String.fromCharCode(this.u16(start + k * 2));
    return text;
  }

  /** How big #US is: the user strings are the indices from 1 to its end. */
  userStrings(): { index: number; text: string }[] {
    const out: { index: number; text: string }[] = [];
    if (this.usAt < 0) return out;
    for (let index = 1; this.usAt + index < this.usEnd; ) {
      const [length, size] = compressed(this.bytes, this.usAt + index);
      if (!length && !size) break;
      if (length) out.push({ index, text: this.userString(index) ?? '' });
      index += size + length;
    }
    return out;
  }

  /** Reads the metadata root, the streams and the tables. */
  read(): void {
    const at = this.offsetOf(this.header.metadataRva);
    if (at < 0 || this.u32(at) !== 0x424a5342) throw new NotCil(t('open', 'The .NET metadata of this file cannot be found or is damaged.'));
    const length = this.u32(at + 12);
    let end = at + 16;
    while (end < at + 16 + length && this.bytes[end] !== 0) end++;
    this.version = utf8.decode(this.bytes.subarray(at + 16, end));
    let p = at + 16 + length;
    const count = this.u16(p + 2);
    p += 4;
    for (let k = 0; k < count; k++) {
      const offset = this.u32(p);
      const size = this.u32(p + 4);
      let nameEnd = p + 8;
      while (nameEnd < this.bytes.length && this.bytes[nameEnd] !== 0 && nameEnd - p < 40) nameEnd++;
      const name = utf8.decode(this.bytes.subarray(p + 8, nameEnd));
      p = p + 8 + ((nameEnd - (p + 8) + 4) & ~3);
      this.streams.push({ name, offset: at + offset, size });
    }
    const stream = (name: string) => this.streams.find((s) => s.name === name);
    const strings = stream('#Strings');
    if (strings) [this.stringsAt, this.stringsEnd] = [strings.offset, strings.offset + strings.size];
    const blob = stream('#Blob');
    if (blob) [this.blobAt, this.blobEnd] = [blob.offset, blob.offset + blob.size];
    const guid = stream('#GUID');
    if (guid) this.guidAt = guid.offset;
    const us = stream('#US');
    if (us) [this.usAt, this.usEnd] = [us.offset, us.offset + us.size];
    const tables = stream('#~') ?? stream('#-');
    if (!tables) throw new NotCil(t('open', 'The .NET metadata of this file has no tables.'));
    this.readTables(tables.offset);
  }

  private readTables(at: number): void {
    this.schema = `${this.u8(at + 4)}.${this.u8(at + 5)}`;
    this.heapSizes = this.u8(at + 6);
    const valid = this.view.getBigUint64(at + 8, true);
    this.sorted = this.view.getBigUint64(at + 16, true);
    let p = at + 24;
    const counts: number[] = new Array(64).fill(0);
    for (let id = 0; id < 64; id++) {
      if ((valid >> BigInt(id)) & 1n) {
        counts[id] = this.u32(p);
        p += 4;
      }
    }
    // Edit and Continue's uncompressed tables may carry four bytes more.
    if (this.heapSizes & 0x40) p += 4;
    const strSize = this.heapSizes & 1 ? 4 : 2;
    const guidSize = this.heapSizes & 2 ? 4 : 2;
    const blobSize = this.heapSizes & 4 ? 4 : 2;
    const sizeOf = (column: Column): number => {
      if (column === 'str') return strSize;
      if (column === 'guid') return guidSize;
      if (column === 'blob') return blobSize;
      if (typeof column === 'number') return column > 0 ? column : counts[-1 - column]! < 65536 ? 2 : 4;
      const tables = CODED[column] as readonly number[];
      const bits = Math.ceil(Math.log2(tables.length));
      const max = Math.max(...tables.map((id) => (id < 0 ? 0 : counts[id]!)));
      return max < 1 << (16 - bits) ? 2 : 4;
    };
    for (let id = 0; id < 64; id++) {
      const rows = counts[id]!;
      if (!rows) continue;
      const schema = SCHEMA[id];
      if (!schema) {
        // Tables after the standard ones (a portable PDB's) come last: nothing that matters follows them.
        this.warnings.push(`table 0x${id.toString(16)}: not in the standard`);
        break;
      }
      const sizes = schema.map(([, column]) => sizeOf(column));
      const rowSize = sizes.reduce((a, b) => a + b, 0);
      const columns = schema.map(() => new Uint32Array(rows));
      if (p + rowSize * rows > this.bytes.length) {
        this.warnings.push(`table ${TABLE_NAMES[id]}: cut short`);
        break;
      }
      for (let r = 0; r < rows; r++) {
        let q = p + r * rowSize;
        for (let c = 0; c < sizes.length; c++) {
          const size = sizes[c]!;
          columns[c]![r] = size === 1 ? this.bytes[q]! : size === 2 ? this.view.getUint16(q, true) : this.view.getUint32(q, true);
          q += size;
        }
      }
      p += rowSize * rows;
      this.tables[id] = new Table(id, rows, schema.map(([name]) => name), columns);
    }
  }

  /** The body of a method, from its RVA: the header, the IL, and the clauses after it. */
  body(method: number): MethodBody | undefined {
    const rva = this.table(TABLE.MethodDef).get(method, 'RVA');
    if (!rva) return undefined;
    const offset = this.offsetOf(rva);
    if (offset < 0) return undefined;
    const first = this.u8(offset);
    if ((first & 3) === 2) {
      return { method, rva, offset, code: offset + 1, size: first >> 2, maxStack: 8, localsToken: 0, initLocals: false, fat: false, headerSize: 1, clauses: [] };
    }
    if ((first & 3) !== 3) return undefined;
    const flags = this.u16(offset);
    const headerSize = (flags >> 12) * 4;
    const size = this.u32(offset + 4);
    const code = offset + headerSize;
    if (headerSize < 12 || code + size > this.bytes.length) return undefined;
    const body: MethodBody = { method, rva, offset, code, size, maxStack: this.u16(offset + 2), localsToken: this.u32(offset + 8), initLocals: !!(flags & 0x10), fat: true, headerSize, clauses: [] };
    let more = !!(flags & 0x08);
    let p = (code + size + 3) & ~3;
    for (let guard = 0; more && guard < 64 && p < this.bytes.length; guard++) {
      const kind = this.u8(p);
      const fatSection = !!(kind & 0x40);
      const dataSize = fatSection ? this.u8(p + 1) | (this.u8(p + 2) << 8) | (this.u8(p + 3) << 16) : this.u8(p + 1);
      if (kind & 0x01) {
        const clauseSize = fatSection ? 24 : 12;
        const n = Math.floor((dataSize - 4) / clauseSize);
        for (let k = 0; k < n; k++) {
          const c = p + 4 + k * clauseSize;
          const clause = fatSection
            ? { kind: this.u32(c), tryStart: this.u32(c + 4), tryLength: this.u32(c + 8), handlerStart: this.u32(c + 12), handlerLength: this.u32(c + 16), extra: this.u32(c + 20) }
            : { kind: this.u16(c), tryStart: this.u16(c + 2), tryLength: this.u8(c + 4), handlerStart: this.u8(c + 5) | (this.u8(c + 6) << 8), handlerLength: this.u8(c + 7), extra: this.u32(c + 8) };
          body.clauses.push({
            kind: clause.kind & 7,
            tryStart: clause.tryStart,
            tryEnd: clause.tryStart + clause.tryLength,
            handlerStart: clause.handlerStart,
            handlerEnd: clause.handlerStart + clause.handlerLength,
            classToken: clause.kind & 1 ? 0 : clause.extra,
            filterStart: clause.kind & 1 ? clause.extra : -1,
          });
        }
      }
      more = !!(kind & 0x80);
      p = (p + Math.max(dataSize, 4) + 3) & ~3;
    }
    return body;
  }

  /** The rows of a list a parent owns (its fields, methods, parameters): from its start to the next parent's. */
  range(table: number, row: number, column: string, target: number): [number, number] {
    const owner = this.table(table);
    const start = owner.get(row, column);
    const end = row < owner.rows ? owner.get(row + 1, column) : this.rows(target) + 1;
    return [start, Math.max(start, end)];
  }
}

const EMPTY: Record<number, Table> = {};
const utf8 = new TextDecoder();

/** A compressed unsigned integer (II.23.2): its value and how many bytes it took. */
export function compressed(bytes: Uint8Array, at: number): [number, number] {
  const b = bytes[at] ?? 0;
  if ((b & 0x80) === 0) return [b, 1];
  if ((b & 0xc0) === 0x80) return [((b & 0x3f) << 8) | (bytes[at + 1] ?? 0), 2];
  if ((b & 0xe0) === 0xc0) return [(((b & 0x1f) << 24) | ((bytes[at + 1] ?? 0) << 16) | ((bytes[at + 2] ?? 0) << 8) | (bytes[at + 3] ?? 0)) >>> 0, 4];
  return [0, 1];
}

/** The CLI header of a PE file with a CLR data directory, and the metadata it points at. */
export function readMetadata(pe: Pe): Metadata {
  const offsetOf = (rva: number): number => {
    for (const s of pe.sections) {
      const size = Math.max(s.virtualSize, s.rawSize);
      if (rva >= s.rva && rva < s.rva + size) return rva - s.rva < s.rawSize ? s.rawOffset + (rva - s.rva) : -1;
    }
    return -1;
  };
  const dir = pe.directories[14];
  const at = dir ? offsetOf(dir.rva) : -1;
  if (at < 0) throw new NotCil(t('open', 'The .NET metadata of this file cannot be found or is damaged.'));
  const view = new DataView(pe.bytes.buffer, pe.bytes.byteOffset, pe.bytes.byteLength);
  const u16 = (o: number) => view.getUint16(at + o, true);
  const u32 = (o: number) => view.getUint32(at + o, true);
  const pair = (o: number) => ({ rva: u32(o), size: u32(o + 4) });
  const header: CliHeader = {
    runtime: `${u16(4)}.${u16(6)}`,
    metadataRva: u32(8),
    metadataSize: u32(12),
    flags: u32(16),
    entryToken: u32(20),
    resources: pair(24),
    strongName: pair(32),
    vtableFixups: pair(48),
    managedNative: pair(64),
  };
  const md = new Metadata(pe.bytes, offsetOf, header);
  md.read();
  return md;
}
