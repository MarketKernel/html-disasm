/**
 * Reading the WebAssembly binary format: LEB128 integers, floats, names and
 * the value types, and their text as the WebAssembly text format writes them
 * (`i32`, `funcref`, `(ref null 3)`).
 *
 * Integers that fit a double exactly stay numbers; 64-bit values that do not
 * (an i64.const, an offset of a 64-bit memory) become bigints, so their text
 * is exact.
 */

import { utf8 } from '../bytes';

export class WasmError extends Error {}

export class Reader {
  constructor(
    readonly bytes: Uint8Array,
    public pos = 0,
    public end = bytes.length,
  ) {}

  get done(): boolean {
    return this.pos >= this.end;
  }

  u8(): number {
    if (this.pos >= this.end) throw new WasmError(`unexpected end at 0x${this.pos.toString(16)}`);
    return this.bytes[this.pos++]!;
  }

  peek(): number {
    return this.pos < this.end ? this.bytes[this.pos]! : -1;
  }

  /** An unsigned LEB128 of up to 32 bits (redundant leading bytes allowed). */
  u32(): number {
    let result = 0;
    let shift = 0;
    for (;;) {
      const byte = this.u8();
      if (shift < 35) result += (byte & 0x7f) * 2 ** shift;
      shift += 7;
      if (!(byte & 0x80)) break;
      if (shift > 70) throw new WasmError('LEB128 too long');
    }
    return result;
  }

  /** A signed LEB128 that fits in a double: s32, and the s33 of block types. */
  s32(): number {
    let result = 0;
    let shift = 0;
    let byte = 0;
    do {
      byte = this.u8();
      if (shift < 49) result += (byte & 0x7f) * 2 ** shift;
      shift += 7;
      if (shift > 70) throw new WasmError('LEB128 too long');
    } while (byte & 0x80);
    if (byte & 0x40 && shift < 53) result -= 2 ** shift;
    else if (byte & 0x40) result -= 2 ** 49;
    return result;
  }

  /** An unsigned 64-bit LEB128: a number when it is exact, a bigint otherwise. */
  u64(): number | bigint {
    const start = this.pos;
    let result = 0;
    let shift = 0;
    let byte = 0;
    do {
      byte = this.u8();
      result += (byte & 0x7f) * 2 ** shift;
      shift += 7;
      if (shift > 70) throw new WasmError('LEB128 too long');
    } while (byte & 0x80);
    if (result <= Number.MAX_SAFE_INTEGER) return result;
    return this.bigLeb(start, false);
  }

  /** A signed 64-bit LEB128: a number when it is exact, a bigint otherwise. */
  s64(): number | bigint {
    const start = this.pos;
    let length = 0;
    while (this.bytes[start + length]! & 0x80) {
      length++;
      if (start + length >= this.end) throw new WasmError(`unexpected end at 0x${this.pos.toString(16)}`);
    }
    length++;
    // Seven bytes carry 49 bits: their value is exact in a double.
    if (length <= 7) return this.s32();
    const value = this.bigLeb(start, true);
    return value >= -BigInt(Number.MAX_SAFE_INTEGER) && value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value;
  }

  private bigLeb(start: number, signed: boolean): bigint {
    this.pos = start;
    let result = 0n;
    let shift = 0n;
    let byte = 0;
    do {
      byte = this.u8();
      result |= BigInt(byte & 0x7f) << shift;
      shift += 7n;
    } while (byte & 0x80);
    if (signed) {
      if (byte & 0x40) result -= 1n << shift;
      return BigInt.asIntN(64, result);
    }
    return BigInt.asUintN(64, result);
  }

  f32Bits(): number {
    const b = this.bytesN(4);
    return (b[0]! | (b[1]! << 8) | (b[2]! << 16) | (b[3]! << 24)) >>> 0;
  }

  f64Bits(): bigint {
    const b = this.bytesN(8);
    let bits = 0n;
    for (let i = 7; i >= 0; i--) bits = (bits << 8n) | BigInt(b[i]!);
    return bits;
  }

  bytesN(n: number): Uint8Array {
    if (this.pos + n > this.end) throw new WasmError(`unexpected end at 0x${this.pos.toString(16)}`);
    const out = this.bytes.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }

  name(): string {
    const length = this.u32();
    return utf8(this.bytesN(length));
  }
}

export { utf8 };

/* ------------------------------------------------------------------ *
 * Value types
 * ------------------------------------------------------------------ */

/** Abstract heap types by their byte. */
const HEAP: Record<number, string> = {
  0x70: 'func', 0x6f: 'extern', 0x6e: 'any', 0x6d: 'eq', 0x6c: 'i31', 0x6b: 'struct', 0x6a: 'array', 0x69: 'exn',
  0x71: 'none', 0x72: 'noextern', 0x73: 'nofunc', 0x74: 'noexn', 0x68: 'cont', 0x75: 'nocont',
};
const NUMERIC: Record<number, string> = { 0x7f: 'i32', 0x7e: 'i64', 0x7d: 'f32', 0x7c: 'f64', 0x7b: 'v128' };
const PACKED: Record<number, string> = { 0x78: 'i8', 0x77: 'i16' };

/** A heap type: an abstract one by name, or a type index. */
export type HeapType = string | number;

/** A value type as the decoder keeps it: its text, and whether it is a number type. */
export interface ValType {
  text: string;
  /** i32, i64, f32, f64, v128, or 'ref'. */
  kind: string;
}

export function heapType(r: Reader): HeapType {
  const byte = r.peek();
  if (byte === 0x65) {
    r.u8();
    const inner = heapType(r);
    return `(shared ${typeof inner === 'number' ? inner : inner})`;
  }
  if (HEAP[byte] !== undefined) {
    r.u8();
    return HEAP[byte]!;
  }
  const index = r.s32();
  if (index < 0) throw new WasmError(`unknown heap type ${index}`);
  return index;
}

export function refText(nullable: boolean, heap: HeapType): string {
  if (nullable && typeof heap === 'string' && !heap.startsWith('(')) {
    // The bottom types read as null…ref: (ref null nofunc) is nullfuncref.
    if (heap === 'none') return 'nullref';
    if (heap.startsWith('no')) return `null${heap.slice(2)}ref`;
    return `${heap}ref`;
  }
  return nullable ? `(ref null ${heap})` : `(ref ${heap})`;
}

/** Reads a value type; `first` is its first byte, already read when the caller had to look at it. */
export function valType(r: Reader, first = r.u8()): ValType {
  const numeric = NUMERIC[first];
  if (numeric) return { text: numeric, kind: numeric };
  if (first === 0x63 || first === 0x64) return { text: refText(first === 0x63, heapType(r)), kind: 'ref' };
  const heap = HEAP[first];
  if (heap) return { text: refText(true, heap), kind: 'ref' };
  throw new WasmError(`unknown value type 0x${first.toString(16)} at 0x${(r.pos - 1).toString(16)}`);
}

/** A field of a struct or the element of an array: a value type or a packed i8 / i16. */
export function storageType(r: Reader): ValType {
  const first = r.u8();
  if (PACKED[first]) return { text: PACKED[first]!, kind: PACKED[first]! };
  return valType(r, first);
}

/** Is this byte the start of a value type (as opposed to an s33 type index in a block type)? */
export function isValTypeByte(byte: number): boolean {
  return NUMERIC[byte] !== undefined || HEAP[byte] !== undefined || byte === 0x63 || byte === 0x64;
}

/* ------------------------------------------------------------------ *
 * Floats, as the text format writes them
 * ------------------------------------------------------------------ */

/**
 * The hexadecimal text of a float's bits, as wasm-tools prints it: `0x1.8p+0`,
 * `-0x1.999999999999ap-4`, `nan`, `nan:0x200000`, `-inf`. Subnormals are
 * normalised (`0x1.p-1074`).
 */
export function hexFloat(bits: bigint, mantissaBits: number, exponentBits: number): string {
  const sign = (bits >> BigInt(mantissaBits + exponentBits)) & 1n ? '-' : '';
  const exponentMask = (1n << BigInt(exponentBits)) - 1n;
  const mantissaMask = (1n << BigInt(mantissaBits)) - 1n;
  const exponent = Number((bits >> BigInt(mantissaBits)) & exponentMask);
  let mantissa = bits & mantissaMask;
  if (exponent === Number(exponentMask)) {
    if (mantissa === 0n) return `${sign}inf`;
    if (mantissa === 1n << BigInt(mantissaBits - 1)) return `${sign}nan`;
    return `${sign}nan:0x${mantissa.toString(16)}`;
  }
  if (exponent === 0 && mantissa === 0n) return `${sign}0x0p+0`;
  const bias = (1 << (exponentBits - 1)) - 1;
  let power = exponent - bias;
  let subnormal = false;
  if (exponent === 0) {
    // Shift the leading one up to the implicit position.
    subnormal = true;
    power = 1 - bias;
    while (!(mantissa & (1n << BigInt(mantissaBits)))) {
      mantissa <<= 1n;
      power--;
    }
    mantissa &= mantissaMask;
  }
  // The fraction in whole hex digits, trailing zeros dropped.
  const digits = Math.ceil(mantissaBits / 4);
  let fraction = (mantissa << BigInt(digits * 4 - mantissaBits)).toString(16).padStart(digits, '0').replace(/0+$/, '');
  const dot = fraction || subnormal ? '.' : '';
  return `${sign}0x1${dot}${fraction}p${power >= 0 ? '+' : ''}${power}`;
}

/** A double in positional notation, shortest digits that read back the same (Rust's `{}`). */
function positional(value: number, digits: string, exponent: number): string {
  // digits "15", exponent -1 means 0.15 × 10^0 … rewritten as a plain decimal.
  const sign = value < 0 || Object.is(value, -0) ? '-' : '';
  const point = exponent; // position of the decimal point within the digits
  if (point <= 0) return `${sign}0.${'0'.repeat(-point)}${digits}`;
  if (point >= digits.length) return `${sign}${digits}${'0'.repeat(point - digits.length)}`;
  return `${sign}${digits.slice(0, point)}.${digits.slice(point)}`;
}

/** The exact decimal digits of a positive double (a binary fraction, so they end) and where its point goes. */
function exactDigits(magnitude: number): { digits: string; point: number } {
  const view = new DataView(new ArrayBuffer(8));
  view.setFloat64(0, magnitude);
  const bits = view.getBigUint64(0);
  const exponent = Number((bits >> 52n) & 0x7ffn);
  let mantissa = bits & ((1n << 52n) - 1n);
  let power = -1074;
  if (exponent) {
    mantissa |= 1n << 52n;
    power = exponent - 1075;
  }
  if (power >= 0) {
    const digits = (mantissa << BigInt(power)).toString();
    return { digits, point: digits.length };
  }
  const digits = (mantissa * 5n ** BigInt(-power)).toString();
  return { digits, point: digits.length + power };
}

/** The shortest decimal digits that read back as the same float, and where the point goes. */
function shortest(magnitude: number, single: boolean): { digits: string; point: number } {
  let text = '';
  if (single) {
    for (let precision = 1; precision <= 9; precision++) {
      text = magnitude.toPrecision(precision);
      if (Math.fround(Number(text)) === magnitude) break;
    }
    text = Number(text).toExponential();
  } else text = magnitude.toExponential();
  const [mantissa, exp] = text.split('e') as [string, string];
  const digits = mantissa.replace('.', '').replace(/0+$/, '') || '0';
  const found = { digits, point: Number(exp) + 1 };
  // Of two equally near candidates JavaScript takes the even one, Rust the one above: round the exact value half up.
  const exact = exactDigits(magnitude);
  if (exact.digits.length <= digits.length) return found;
  let head = BigInt(exact.digits.slice(0, digits.length));
  if (exact.digits[digits.length]! >= '5') head += 1n;
  let rounded = head.toString();
  let point = exact.point;
  if (rounded.length > digits.length) {
    point++;
    rounded = rounded.slice(0, digits.length);
  }
  rounded = rounded.replace(/0+$/, '') || '0';
  const value = Number(`0.${rounded}e${point}`);
  return (single ? Math.fround(value) : value) === magnitude ? { digits: rounded, point } : found;
}

/** A float as Rust's Display writes it: `1.5`, `-0.1`, `1000000000000000000000000000000`, `NaN`, `-inf`. */
export function decimalFloat(value: number, single: boolean): string {
  if (Number.isNaN(value)) return 'NaN';
  if (value === Infinity) return 'inf';
  if (value === -Infinity) return '-inf';
  if (value === 0) return Object.is(value, -0) ? '-0' : '0';
  const { digits, point } = shortest(Math.abs(value), single);
  return positional(value, digits, point);
}

export function f32FromBits(bits: number): number {
  const view = new DataView(new ArrayBuffer(4));
  view.setUint32(0, bits, true);
  return view.getFloat32(0, true);
}

export function f64FromBits(bits: bigint): number {
  const view = new DataView(new ArrayBuffer(8));
  view.setBigUint64(0, bits, true);
  return view.getFloat64(0, true);
}

/** The text of an f32.const / f64.const operand: hex, then the value in a comment. */
export function floatText(bits: number | bigint, single: boolean): string {
  if (single) {
    const value = f32FromBits(bits as number);
    return `${hexFloat(BigInt(bits), 23, 8)} (;=${decimalFloat(value, true)};)`;
  }
  const value = f64FromBits(bits as bigint);
  return `${hexFloat(bits as bigint, 52, 11)} (;=${decimalFloat(value, false)};)`;
}
