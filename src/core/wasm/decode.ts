/**
 * A WebAssembly instruction as the page shows it.
 *
 * The decoder is in the core (crates/core/src/wasm/decode.rs): it reads an
 * instruction of a function body — the opcode, its length and its immediates —
 * and writes it in the text format exactly as `wasm-tools print` does for a
 * module without names (`i32.load offset=8 align=1`, `call_indirect 1 (type 3)`,
 * `f64.const 0x1.8p+1 (;=3;)`), which tools/verify-wasm.mjs checks line by line.
 * The page asks it for the instructions of the rows on screen
 * (WasmProgram.insn); the listing replaces indices with names when it draws a
 * line, and the text here is the reference.
 */

import { engine } from '../engine/engine';

/** What the opcode is: its number (the byte, or prefix << 16 | the prefixed opcode), its kind of immediate (IMM), its W flags, its group, the bytes a load or store moves. */
export interface WasmOp {
  code: number;
  imm: number;
  flags: number;
  group: string;
  size: number;
}

export interface WasmInsn {
  /** undefined for bytes that are not an instruction. */
  op: WasmOp | undefined;
  /** As printed: i32.add, local.get, .bytes for what could not be decoded. */
  m: string;
  pos: number;
  len: number;
  /** The first and second index immediates: label depth, function, local, global, type, table, memory, data, elem, tag, lane, field. */
  a: number;
  b: number;
  /** An integer constant, or a memory offset. */
  value: number | bigint;
  align: number;
  mem: number;
  /** The labels of br_table (the default last); null for the others. */
  labels: number[] | null;
  /** The operands as the text format prints them (with a leading space), alone and with the module's types. */
  ops: string;
  opsCtx: string;
}

/** The instruction as the core read it: the opcode as [code, imm, flags, group, size]. */
export type CoreInsn = Omit<WasmInsn, 'op'> & { op: [number, number, number, string, number] | null };

export function insnOf(raw: CoreInsn): WasmInsn {
  const op = raw.op;
  return { ...raw, op: op ? { code: op[0], imm: op[1], flags: op[2], group: op[3], size: op[4] } : undefined };
}

/** The first instruction of some bytes, decoded with no module around them. */
export function decodeBytes(bytes: Uint8Array): WasmInsn {
  return insnOf(engine().wasmDecode<CoreInsn>(bytes));
}

/** The operands as the text format prints them; `typed` names block types by their signature. */
export function operandsText(insn: WasmInsn, typed = false): string {
  return typed ? insn.opsCtx : insn.ops;
}

export function formatInsn(insn: WasmInsn, typed = false): string {
  return insn.m + operandsText(insn, typed);
}

const hex2 = (b: number) => b.toString(16).padStart(2, '0');

/** The bytes of an instruction as hex: `41 80 08`. */
export function bytesText(bytes: Uint8Array, insn: WasmInsn, max = 12): string {
  const shown = Math.min(insn.len, max);
  let text = '';
  for (let i = 0; i < shown; i++) text += `${i ? ' ' : ''}${hex2(bytes[insn.pos + i]!)}`;
  return insn.len > max ? `${text} …` : text;
}
