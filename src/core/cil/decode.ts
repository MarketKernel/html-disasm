/**
 * CIL instructions: decoded from a method's IL and printed as ildasm prints
 * them — the mnemonic padded to ten columns, then the operand: `IL_001f` for
 * a branch, a method or field with its full signature, a string in quotes (or
 * as the bytes of its UTF-16, `bytearray (…)`, when it is not plain ASCII),
 * floating-point constants with as many digits as make them exact, and the
 * raw bytes of a NaN or an infinity. `tools/verify-cil.mjs` compares the text
 * with ildasm's.
 */

import { TABLE, tokenRow, tokenTable, USER_STRING, type Metadata } from './metadata';
import { properLocalName, type GenericContext, type Names } from './names';
import { ONE, OPERAND, TWO, type OpInfo } from './opcodes';

/** A decoded instruction; one object is reused while a method is read. */
export class CilInsn {
  op: OpInfo | undefined = undefined;
  /** Offset in the method's IL, and length in bytes. */
  at = 0;
  len = 1;
  /** The mnemonic (`.byte` for an opcode that is not one). */
  m = '';
  /** A variable number, a constant, a token, a branch target (IL offset). */
  a = 0;
  value: number | bigint = 0;
  /** A switch: its targets (IL offsets). */
  targets: number[] | null = null;
}

/** The view of the last file decoded: the decoder runs for every instruction, and a view made each time costs more than the reading. */
let viewed: Uint8Array | undefined;
let view: DataView = new DataView(new ArrayBuffer(0));
function viewOf(bytes: Uint8Array): DataView {
  if (bytes !== viewed) {
    viewed = bytes;
    view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }
  return view;
}

/** Decodes the instruction at `pos` of a method whose IL is `code[start, end)`. */
export function decodeAt(bytes: Uint8Array, start: number, pos: number, end: number, into = new CilInsn()): CilInsn {
  const insn = into;
  insn.at = pos - start;
  insn.targets = null;
  insn.a = 0;
  insn.value = 0;
  const first = bytes[pos]!;
  let op: OpInfo | undefined;
  let p = pos + 1;
  if (first === 0xfe && pos + 1 < end) {
    op = TWO[bytes[pos + 1]!];
    p = pos + 2;
  } else op = ONE[first];
  if (!op) {
    insn.op = undefined;
    insn.m = '.byte';
    insn.a = first;
    insn.len = 1;
    return insn;
  }
  const view = viewOf(bytes);
  const need = (n: number) => p + n <= end;
  insn.op = op;
  insn.m = op.name;
  switch (op.operand) {
    case OPERAND.NONE:
      break;
    case OPERAND.VAR8:
    case OPERAND.U8:
      if (!need(1)) return truncated(insn, first);
      insn.a = bytes[p]!;
      p += 1;
      break;
    case OPERAND.I8:
      if (!need(1)) return truncated(insn, first);
      insn.a = view.getInt8(p);
      p += 1;
      break;
    case OPERAND.VAR16:
      if (!need(2)) return truncated(insn, first);
      insn.a = view.getUint16(p, true);
      p += 2;
      break;
    case OPERAND.BR8:
      if (!need(1)) return truncated(insn, first);
      insn.a = p + 1 + view.getInt8(p) - start;
      p += 1;
      break;
    case OPERAND.BR32:
      if (!need(4)) return truncated(insn, first);
      insn.a = p + 4 + view.getInt32(p, true) - start;
      p += 4;
      break;
    case OPERAND.I32:
      if (!need(4)) return truncated(insn, first);
      insn.a = view.getInt32(p, true);
      p += 4;
      break;
    case OPERAND.I64:
      if (!need(8)) return truncated(insn, first);
      insn.value = view.getBigInt64(p, true);
      p += 8;
      break;
    case OPERAND.R4:
      if (!need(4)) return truncated(insn, first);
      insn.value = view.getFloat32(p, true);
      insn.a = view.getUint32(p, true);
      p += 4;
      break;
    case OPERAND.R8:
      if (!need(8)) return truncated(insn, first);
      insn.value = view.getFloat64(p, true);
      p += 8;
      break;
    case OPERAND.SWITCH: {
      if (!need(4)) return truncated(insn, first);
      const count = view.getUint32(p, true);
      p += 4;
      if (count > (end - p) / 4) return truncated(insn, first);
      const base = p + count * 4 - start;
      const targets: number[] = new Array(count);
      for (let k = 0; k < count; k++) targets[k] = base + view.getInt32(p + k * 4, true);
      insn.targets = targets;
      insn.a = count;
      p += count * 4;
      break;
    }
    default:
      // A token.
      if (!need(4)) return truncated(insn, first);
      insn.a = view.getUint32(p, true);
      p += 4;
  }
  insn.len = p - pos;
  return insn;
}

/** An instruction whose operand runs past the end of the method: its first byte, as data. */
function truncated(insn: CilInsn, first: number): CilInsn {
  insn.op = undefined;
  insn.m = '.byte';
  insn.a = first;
  insn.len = 1;
  return insn;
}

/* ------------------------------------------------------------------ *
 * Printing
 * ------------------------------------------------------------------ */

/** What printing an operand needs to know of the method it is in. */
export interface MethodContext {
  names: Names;
  generic: GenericContext;
  /** The method has `this`: argument 0 is it. */
  instance: boolean;
  /** Parameter names by sequence (1 = the first parameter). */
  params: string[];
}

export const label = (offset: number): string => `IL_${(offset >>> 0).toString(16).padStart(4, '0')}`;

/** Floating point as ildasm writes it: C's `%.8g` / `%.17g`. */
export function gFormat(value: number, digits: number): string {
  if (value === 0) return Object.is(value, -0) ? '-0.0' : '0.0';
  const exp = Number(value.toExponential(digits - 1).split('e')[1]);
  if (exp < -4 || exp >= digits) {
    const [mantissa, e] = value.toExponential(digits - 1).split('e') as [string, string];
    const m = mantissa.includes('.') ? mantissa.replace(/0+$/, '').replace(/\.$/, '') : mantissa;
    const n = Number(e);
    return `${m}e${n < 0 ? '-' : '+'}${String(Math.abs(n)).padStart(2, '0')}`;
  }
  const fixed = value.toFixed(Math.max(0, digits - 1 - exp));
  return fixed.includes('.') ? fixed.replace(/0+$/, '').replace(/\.$/, '') : fixed;
}

const hexByte = (b: number) => b.toString(16).toUpperCase().padStart(2, '0');

function floatText(insn: CilInsn, bytes: Uint8Array | undefined): string {
  const value = insn.value as number;
  if (Number.isFinite(value)) return gFormat(value, insn.op!.operand === OPERAND.R4 ? 8 : 17);
  const raw = bytes ?? new Uint8Array(0);
  return `(${[...raw].map(hexByte).join(' ')})`;
}

/** Characters ildasm writes with a backslash in a string it can print as text (`?`, so that no C trigraph is read). */
const ESCAPES: Record<number, string> = { 9: '\\t', 10: '\\n', 13: '\\r', 34: '\\"', 63: '\\?', 92: '\\\\' };

/** Is the string printable as a quoted literal (ASCII and the escapes above)? */
export function plainString(text: string): boolean {
  for (let k = 0; k < text.length; k++) {
    const c = text.charCodeAt(k);
    if (c >= 0x7f || (c < 0x20 && !ESCAPES[c])) return false;
  }
  return true;
}

/** ldstr's operand: `"text"` with escapes, or `bytearray (…)` with the UTF-16 bytes. */
export function stringText(text: string): string {
  if (plainString(text)) {
    let out = '"';
    for (let k = 0; k < text.length; k++) out += ESCAPES[text.charCodeAt(k)] ?? text[k];
    return `${out}"`;
  }
  const bytes: string[] = [];
  for (let k = 0; k < text.length; k++) {
    const c = text.charCodeAt(k);
    bytes.push(hexByte(c & 0xff), hexByte(c >> 8));
  }
  return `bytearray (${bytes.join(' ')})`;
}

/** The name of an argument as ildasm writes it: its parameter's name, `A_n` when it has none; `this` stays 0. */
export function argName(ctx: MethodContext, index: number): string {
  if (ctx.instance && index === 0) return '0';
  const seq = ctx.instance ? index : index + 1;
  const name = ctx.params[seq];
  return name ? properLocalName(name) : `A_${index}`;
}

/** The operand of an instruction as ildasm prints it. */
export function operandText(md: Metadata, insn: CilInsn, ctx: MethodContext, raw?: Uint8Array): string {
  const op = insn.op;
  if (!op) return `0x${hexByte(insn.a)}`;
  const names = ctx.names;
  switch (op.operand) {
    case OPERAND.NONE:
      return '';
    case OPERAND.VAR8:
    case OPERAND.VAR16:
      return /arg/.test(op.name) ? argName(ctx, insn.a) : `V_${insn.a}`;
    case OPERAND.I8:
    case OPERAND.U8:
      return String(insn.a);
    case OPERAND.I32:
      return `0x${(insn.a >>> 0).toString(16)}`;
    case OPERAND.I64:
      return `0x${BigInt.asUintN(64, insn.value as bigint).toString(16)}`;
    case OPERAND.R4:
    case OPERAND.R8:
      return floatText(insn, raw);
    case OPERAND.BR8:
    case OPERAND.BR32:
      return label(insn.a);
    case OPERAND.SWITCH:
      return `( ${(insn.targets ?? []).map(label).join(', ')})`;
    case OPERAND.STRING: {
      if (tokenTable(insn.a) !== USER_STRING) return `0x${insn.a.toString(16)}`;
      const text = md.userString(tokenRow(insn.a));
      return text === undefined ? `0x${insn.a.toString(16)}` : stringText(text);
    }
    case OPERAND.METHOD:
      return names.method(insn.a, ctx.generic);
    case OPERAND.FIELD:
      return names.field(insn.a, ctx.generic);
    case OPERAND.TYPE:
      return names.type(insn.a, ctx.generic);
    case OPERAND.TOKEN:
      return names.token(insn.a, ctx.generic);
    case OPERAND.SIG:
      return tokenTable(insn.a) === TABLE.StandAloneSig ? names.standalone(insn.a, ctx.generic) : `0x${insn.a.toString(16)}`;
  }
  return '';
}

/** An instruction as one line of ildasm's text: `ldstr      "hello"`. */
export function insnText(md: Metadata, insn: CilInsn, ctx: MethodContext, raw?: Uint8Array): string {
  const operand = operandText(md, insn, ctx, raw);
  if (!insn.op) return `.byte ${operand}`;
  return operand ? `${insn.m.padEnd(10)} ${operand}` : insn.m;
}

/** The bytes of an instruction as hex: `72 25 00 00 70`. */
export function bytesText(bytes: Uint8Array, at: number, len: number, max = 16): string {
  const shown = bytes.subarray(at, at + Math.min(len, max));
  return [...shown].map((b) => b.toString(16).padStart(2, '0')).join(' ') + (len > max ? ' …' : '');
}
