/**
 * The WebAssembly instruction decoder.
 *
 * decodeAt() reads one instruction of a function body into a WasmInsn — the
 * opcode, its length and its immediates as numbers — and formatInsn() writes
 * it in the text format exactly as `wasm-tools print` does for a module
 * without names (`i32.load offset=8 align=1`, `call_indirect 1 (type 3)`,
 * `f64.const 0x1.8p+1 (;=3;)`), so it can be checked line by line
 * (tools/verify-wasm.mjs). The listing replaces indices with names when it
 * draws a line; the text here is the reference.
 */

import { IMM, opInfo, PREFIXES, type OpInfo } from './opcodes';
import { floatText, heapType, isValTypeByte, Reader, refText, valType, WasmError, type HeapType, type ValType } from './reader';

export type BlockType = { kind: 'empty' } | { kind: 'value'; type: ValType } | { kind: 'type'; index: number };

export interface Catch {
  /** catch, catch_ref, catch_all, catch_all_ref */
  kind: string;
  tag: number;
  label: number;
}

export class WasmInsn {
  op: OpInfo | undefined = undefined;
  /** As printed: i32.add, local.get, .bytes for what could not be decoded. */
  m = '';
  pos = 0;
  len = 0;
  /** The first and second index immediates: label depth, function, local, global, type, table, memory, data, elem, tag, lane, field. */
  a = 0;
  b = 0;
  /** An integer constant, or a memory offset. */
  value: number | bigint = 0;
  /** Float bits of f32.const / f64.const. */
  bits: number | bigint = 0;
  align = 0;
  mem = 0;
  bytes: Uint8Array | null = null;
  labels: number[] | null = null;
  block: BlockType | null = null;
  types: ValType[] | null = null;
  heap: HeapType = '';
  heap2: HeapType = '';
  nullable = 0;
  catches: Catch[] | null = null;
}

/** What the text of block types needs from the module. */
export interface FormatContext {
  funcType(index: number): { params: ValType[]; results: ValType[] } | undefined;
}

const EMPTY: BlockType = { kind: 'empty' };

function blockType(r: Reader): BlockType {
  const byte = r.peek();
  if (byte === 0x40) {
    r.u8();
    return EMPTY;
  }
  if (isValTypeByte(byte)) return { kind: 'value', type: valType(r) };
  const index = r.s32();
  if (index < 0) throw new WasmError(`bad block type ${index}`);
  return { kind: 'type', index };
}

function memarg(r: Reader, insn: WasmInsn): void {
  const flags = r.u32();
  if (flags >= 64 && flags < 128) {
    insn.align = flags - 64;
    insn.mem = r.u32();
  } else {
    insn.align = flags;
    insn.mem = 0;
  }
  insn.value = r.u64();
}

/**
 * Decodes the instruction at `pos`; `end` is the end of the function body.
 * An unknown opcode gives `.bytes` covering the rest of the body, since its
 * length cannot be known.
 */
export function decodeAt(bytes: Uint8Array, pos: number, end: number, insn = new WasmInsn()): WasmInsn {
  const r = new Reader(bytes, pos, end);
  insn.pos = pos;
  insn.labels = null;
  insn.block = null;
  insn.types = null;
  insn.bytes = null;
  insn.catches = null;
  insn.mem = 0;
  insn.align = 0;
  try {
    let code = r.u8();
    if (PREFIXES.has(code)) code = (code << 16) | r.u32();
    const op = opInfo(code);
    if (!op) throw new WasmError(`unknown opcode`);
    insn.op = op;
    insn.m = op.name;
    readImmediates(r, op, insn);
    insn.len = r.pos - pos;
  } catch {
    insn.op = undefined;
    insn.m = '.bytes';
    insn.len = Math.max(1, end - pos);
    insn.bytes = bytes.subarray(pos, pos + insn.len);
  }
  return insn;
}

function readImmediates(r: Reader, op: OpInfo, insn: WasmInsn): void {
  switch (op.imm) {
    case IMM.NONE:
      return;
    case IMM.BLOCK:
      insn.block = blockType(r);
      return;
    case IMM.LABEL:
    case IMM.FUNC:
    case IMM.LOCAL:
    case IMM.GLOBAL:
    case IMM.TABLE:
    case IMM.MEM:
    case IMM.DATA:
    case IMM.ELEM:
    case IMM.TAG:
    case IMM.TYPE:
    case IMM.LANE:
      insn.a = op.imm === IMM.LANE ? r.u8() : r.u32();
      return;
    case IMM.BR_TABLE: {
      const count = r.u32();
      if (count > r.end - r.pos) throw new WasmError('br_table too long');
      const labels: number[] = [];
      for (let i = 0; i <= count; i++) labels.push(r.u32());
      insn.labels = labels;
      return;
    }
    case IMM.CALL_INDIRECT:
      insn.a = r.u32(); // type
      insn.b = r.u32(); // table
      return;
    case IMM.MEMARG:
      memarg(r, insn);
      return;
    case IMM.MEMARG_LANE:
      memarg(r, insn);
      insn.a = r.u8();
      return;
    case IMM.I32:
      insn.value = r.s32() | 0;
      return;
    case IMM.I64:
      insn.value = r.s64();
      return;
    case IMM.F32:
      insn.bits = r.f32Bits();
      return;
    case IMM.F64:
      insn.bits = r.f64Bits();
      return;
    case IMM.SELECT_T: {
      const count = r.u32();
      if (count > r.end - r.pos) throw new WasmError('select too long');
      const types: ValType[] = [];
      for (let i = 0; i < count; i++) types.push(valType(r));
      insn.types = types;
      return;
    }
    case IMM.HEAP:
      insn.heap = heapType(r);
      return;
    case IMM.MEMORY_INIT:
    case IMM.TABLE_INIT:
    case IMM.MEMORY_COPY:
    case IMM.TABLE_COPY:
    case IMM.TYPE_FIELD:
    case IMM.TYPE_N:
    case IMM.TYPE_DATA:
    case IMM.TYPE_ELEM:
    case IMM.TYPE_TYPE:
      insn.a = r.u32();
      insn.b = r.u32();
      return;
    case IMM.V128:
      insn.bytes = r.bytesN(16);
      return;
    case IMM.SHUFFLE:
      insn.bytes = r.bytesN(16);
      return;
    case IMM.FENCE:
      if (r.u8() !== 0) throw new WasmError('atomic.fence: reserved byte');
      return;
    case IMM.TRY_TABLE: {
      insn.block = blockType(r);
      const count = r.u32();
      if (count > r.end - r.pos) throw new WasmError('try_table too long');
      const catches: Catch[] = [];
      for (let i = 0; i < count; i++) {
        const kind = r.u8();
        if (kind > 3) throw new WasmError('bad catch');
        const tag = kind < 2 ? r.u32() : -1;
        catches.push({ kind: ['catch', 'catch_ref', 'catch_all', 'catch_all_ref'][kind]!, tag, label: r.u32() });
      }
      insn.catches = catches;
      return;
    }
    case IMM.REF_TEST:
    case IMM.REF_TEST_NULL:
      insn.heap = heapType(r);
      insn.nullable = op.imm === IMM.REF_TEST_NULL ? 1 : 0;
      return;
    case IMM.BR_ON_CAST:
      insn.nullable = r.u8(); // bit 0: the source may be null; bit 1: the target may be
      if (insn.nullable > 3) throw new WasmError('br_on_cast flags');
      insn.a = r.u32();
      insn.heap = heapType(r);
      insn.heap2 = heapType(r);
      return;
  }
  throw new WasmError(`immediate kind ${op.imm}`);
}

/* ------------------------------------------------------------------ *
 * Text
 * ------------------------------------------------------------------ */

const hex2 = (b: number) => b.toString(16).padStart(2, '0');

export function blockTypeText(block: BlockType | null, ctx?: FormatContext): string {
  if (!block || block.kind === 'empty') return '';
  if (block.kind === 'value') return ` (result ${block.type.text})`;
  const type = ctx?.funcType(block.index);
  let text = ` (type ${block.index})`;
  if (type?.params.length) text += ` (param ${type.params.map((t) => t.text).join(' ')})`;
  if (type?.results.length) text += ` (result ${type.results.map((t) => t.text).join(' ')})`;
  return text;
}

function memargText(insn: WasmInsn): string {
  let text = insn.mem ? ` ${insn.mem}` : '';
  if (insn.value !== 0 && insn.value !== 0n) text += ` offset=${insn.value}`;
  if (insn.op && insn.align !== insn.op.align) text += ` align=${insn.align < 64 ? 2n ** BigInt(insn.align) : `2**${insn.align}`}`;
  return text;
}

/** The operands of an instruction, as text after its name (with a leading space), or ''. */
export function operandsText(insn: WasmInsn, ctx?: FormatContext): string {
  const op = insn.op;
  if (!op) return ` ${[...(insn.bytes ?? [])].slice(0, 32).map(hex2).join(' ')}${(insn.bytes?.length ?? 0) > 32 ? ' …' : ''}`;
  switch (op.imm) {
    case IMM.NONE:
    case IMM.FENCE:
      return '';
    case IMM.BLOCK:
      return blockTypeText(insn.block, ctx);
    case IMM.LABEL:
    case IMM.FUNC:
    case IMM.LOCAL:
    case IMM.GLOBAL:
    case IMM.TABLE:
    case IMM.DATA:
    case IMM.ELEM:
    case IMM.TAG:
    case IMM.TYPE:
    case IMM.LANE:
      return ` ${insn.a}`;
    case IMM.MEM:
      return insn.a ? ` ${insn.a}` : '';
    case IMM.BR_TABLE:
      return ` ${insn.labels!.join(' ')}`;
    case IMM.CALL_INDIRECT:
      return `${insn.b ? ` ${insn.b}` : ''} (type ${insn.a})`;
    case IMM.MEMARG:
      return memargText(insn);
    case IMM.MEMARG_LANE:
      return `${memargText(insn)} ${insn.a}`;
    case IMM.I32:
    case IMM.I64:
      return ` ${insn.value}`;
    case IMM.F32:
      return ` ${floatText(insn.bits, true)}`;
    case IMM.F64:
      return ` ${floatText(insn.bits, false)}`;
    case IMM.SELECT_T:
      return insn.types!.length ? ` (result ${insn.types!.map((t) => t.text).join(' ')})` : ' (result)';
    case IMM.HEAP:
      return ` ${insn.heap}`;
    case IMM.MEMORY_INIT:
      return insn.b ? ` ${insn.b} ${insn.a}` : ` ${insn.a}`;
    case IMM.TABLE_INIT:
      return insn.b ? ` ${insn.b} ${insn.a}` : ` ${insn.a}`;
    case IMM.MEMORY_COPY:
    case IMM.TABLE_COPY:
      return insn.a || insn.b ? ` ${insn.a} ${insn.b}` : '';
    case IMM.TYPE_FIELD:
    case IMM.TYPE_N:
    case IMM.TYPE_DATA:
    case IMM.TYPE_ELEM:
    case IMM.TYPE_TYPE:
      return ` ${insn.a} ${insn.b}`;
    case IMM.V128: {
      const b = insn.bytes!;
      const words: string[] = [];
      for (let i = 0; i < 16; i += 4) words.push(`0x${hex2(b[i + 3]!)}${hex2(b[i + 2]!)}${hex2(b[i + 1]!)}${hex2(b[i]!)}`);
      return ` i32x4 ${words.join(' ')}`;
    }
    case IMM.SHUFFLE:
      return ` ${[...insn.bytes!].join(' ')}`;
    case IMM.TRY_TABLE:
      return `${blockTypeText(insn.block, ctx)}${insn.catches!.map((c) => ` (${c.kind}${c.tag >= 0 ? ` ${c.tag}` : ''} ${c.label})`).join('')}`;
    case IMM.REF_TEST:
    case IMM.REF_TEST_NULL:
      return ` ${refText(!!insn.nullable, insn.heap)}`;
    case IMM.BR_ON_CAST:
      return ` ${insn.a} ${refText(!!(insn.nullable & 1), insn.heap)} ${refText(!!(insn.nullable & 2), insn.heap2)}`;
  }
  return '';
}

export function formatInsn(insn: WasmInsn, ctx?: FormatContext): string {
  return insn.m + operandsText(insn, ctx);
}

/** The bytes of an instruction as hex: `41 80 08`. */
export function bytesText(bytes: Uint8Array, insn: WasmInsn, max = 12): string {
  const shown = Math.min(insn.len, max);
  let text = '';
  for (let i = 0; i < shown; i++) text += `${i ? ' ' : ''}${hex2(bytes[insn.pos + i]!)}`;
  return insn.len > max ? `${text} …` : text;
}
