/**
 * Every WebAssembly instruction the decoder knows, by opcode: its name in the
 * text format, the immediates that follow it, what it takes from the stack and
 * pushes, the kind of instruction (the group the reference files it under) and
 * what it does to control flow and memory.
 *
 * Covered: WebAssembly 3.0 — the MVP, sign extension, saturating conversions,
 * bulk memory, reference types, multi-value, SIMD and relaxed SIMD, tail
 * calls, exception handling (with the legacy try/catch), typed function
 * references, GC, memory64 and multiple memories — and the threads proposal
 * (atomics) and wide arithmetic.
 *
 * A signature is written `pops > pushes` with the types of the stack: `addr`
 * is an address (i32, or i64 in a 64-bit memory), `ref` a reference, `T` a
 * type the immediates or the module decide. Instructions whose stack effect
 * depends on a type (calls, blocks, branches) have none here; the analysis
 * works it out.
 */

/** The immediates of an instruction, as the decoder reads them. */
export const IMM = {
  NONE: 0,
  BLOCK: 1, // block type
  LABEL: 2,
  BR_TABLE: 3,
  FUNC: 4,
  CALL_INDIRECT: 5, // type, table
  LOCAL: 6,
  GLOBAL: 7,
  TABLE: 8,
  MEMARG: 9,
  I32: 10,
  I64: 11,
  F32: 12,
  F64: 13,
  SELECT_T: 14,
  HEAP: 15, // ref.null
  MEM: 16, // memory.size, memory.grow, memory.fill
  MEMORY_INIT: 17, // data, memory
  DATA: 18,
  MEMORY_COPY: 19,
  TABLE_INIT: 20, // elem, table
  ELEM: 21,
  TABLE_COPY: 22,
  V128: 23,
  SHUFFLE: 24,
  LANE: 25,
  MEMARG_LANE: 26,
  FENCE: 27,
  TRY_TABLE: 28,
  TAG: 29,
  TYPE: 30, // struct.new, array.get…, call_ref
  TYPE_FIELD: 31,
  TYPE_N: 32, // array.new_fixed
  TYPE_DATA: 33,
  TYPE_ELEM: 34,
  TYPE_TYPE: 35, // array.copy
  REF_TEST: 36, // ref.test / ref.cast with a non-null type
  REF_TEST_NULL: 37,
  BR_ON_CAST: 38,
} as const;

/** What an instruction does, for the analysis and the colours of the listing. */
export const W = {
  BRANCH: 1, // br, br_if, br_table, br_on_*: may go to a label
  COND: 2, // only sometimes
  CALL: 4,
  RETURN: 8, // return, return_call*
  INDIRECT: 16, // call_indirect, call_ref
  LOAD: 32,
  STORE: 64,
  TRAPS: 128, // may stop the program (out of bounds, division by zero, …)
  ATOMIC: 256,
  STRUCTURE: 512, // block, loop, if, else, end, try…: shapes the code
  END: 1024, // nothing after it in its block runs: br, return, unreachable, throw
  CONST: 2048,
} as const;

export type Group = 'control' | 'reference' | 'parametric' | 'variable' | 'table' | 'memory' | 'numeric' | 'vector' | 'atomic' | 'aggregate' | 'exception';

export interface OpInfo {
  /** The opcode as one number: the byte, or prefix << 16 | the prefixed opcode. */
  code: number;
  name: string;
  imm: number;
  /** `pops > pushes`, or '' when it depends on the module. */
  sig: string;
  group: Group;
  flags: number;
  /** For memory instructions: the natural alignment, as a power of two. */
  align: number;
  /** For loads and stores: bytes moved (the memory operand's width). */
  size: number;
}

const OPS = new Map<number, OpInfo>();

function def(code: number, name: string, imm: number, sig: string, group: Group, flags = 0, align = -1, size = 0): void {
  if (OPS.has(code)) throw new Error(`opcode 0x${code.toString(16)} twice`);
  OPS.set(code, { code, name, imm, sig, group, flags, align, size });
}

const FB = 0xfb << 16;
const FC = 0xfc << 16;
const FD = 0xfd << 16;
const FE = 0xfe << 16;

/* ------------------------------------------------------------------ *
 * Control, parametric, variables, tables
 * ------------------------------------------------------------------ */

const { NONE, BLOCK, LABEL, FUNC, LOCAL, GLOBAL, TABLE, MEMARG } = IMM;
const S = W.STRUCTURE;

def(0x00, 'unreachable', NONE, '', 'control', W.TRAPS | W.END);
def(0x01, 'nop', NONE, ' > ', 'control');
def(0x02, 'block', BLOCK, '', 'control', S);
def(0x03, 'loop', BLOCK, '', 'control', S);
def(0x04, 'if', BLOCK, '', 'control', S | W.BRANCH | W.COND);
def(0x05, 'else', NONE, '', 'control', S | W.BRANCH);
def(0x06, 'try', BLOCK, '', 'exception', S);
def(0x07, 'catch', IMM.TAG, '', 'exception', S);
def(0x08, 'throw', IMM.TAG, '', 'exception', W.END | W.TRAPS);
def(0x09, 'rethrow', LABEL, '', 'exception', W.END | W.TRAPS);
def(0x0a, 'throw_ref', NONE, 'exnref > ', 'exception', W.END | W.TRAPS);
def(0x0b, 'end', NONE, '', 'control', S);
def(0x0c, 'br', LABEL, '', 'control', W.BRANCH | W.END);
def(0x0d, 'br_if', LABEL, '', 'control', W.BRANCH | W.COND);
def(0x0e, 'br_table', IMM.BR_TABLE, '', 'control', W.BRANCH | W.END);
def(0x0f, 'return', NONE, '', 'control', W.RETURN | W.END);
def(0x10, 'call', FUNC, '', 'control', W.CALL);
def(0x11, 'call_indirect', IMM.CALL_INDIRECT, '', 'control', W.CALL | W.INDIRECT | W.TRAPS);
def(0x12, 'return_call', FUNC, '', 'control', W.CALL | W.RETURN | W.END);
def(0x13, 'return_call_indirect', IMM.CALL_INDIRECT, '', 'control', W.CALL | W.RETURN | W.END | W.INDIRECT | W.TRAPS);
def(0x14, 'call_ref', IMM.TYPE, '', 'control', W.CALL | W.INDIRECT | W.TRAPS);
def(0x15, 'return_call_ref', IMM.TYPE, '', 'control', W.CALL | W.RETURN | W.END | W.INDIRECT | W.TRAPS);
def(0x18, 'delegate', LABEL, '', 'exception', S);
def(0x19, 'catch_all', NONE, '', 'exception', S);
def(0x1a, 'drop', NONE, 'T > ', 'parametric');
def(0x1b, 'select', NONE, 'T T i32 > T', 'parametric');
def(0x1c, 'select', IMM.SELECT_T, 'T T i32 > T', 'parametric');
def(0x1f, 'try_table', IMM.TRY_TABLE, '', 'exception', S);
def(0x20, 'local.get', LOCAL, ' > T', 'variable');
def(0x21, 'local.set', LOCAL, 'T > ', 'variable');
def(0x22, 'local.tee', LOCAL, 'T > T', 'variable');
def(0x23, 'global.get', GLOBAL, ' > T', 'variable');
def(0x24, 'global.set', GLOBAL, 'T > ', 'variable');
def(0x25, 'table.get', TABLE, 'i32 > ref', 'table', W.TRAPS);
def(0x26, 'table.set', TABLE, 'i32 ref > ', 'table', W.TRAPS);

/* ------------------------------------------------------------------ *
 * Memory
 * ------------------------------------------------------------------ */

const LOADS: [number, string, string, number][] = [
  [0x28, 'i32.load', 'i32', 2], [0x29, 'i64.load', 'i64', 3], [0x2a, 'f32.load', 'f32', 2], [0x2b, 'f64.load', 'f64', 3],
  [0x2c, 'i32.load8_s', 'i32', 0], [0x2d, 'i32.load8_u', 'i32', 0], [0x2e, 'i32.load16_s', 'i32', 1], [0x2f, 'i32.load16_u', 'i32', 1],
  [0x30, 'i64.load8_s', 'i64', 0], [0x31, 'i64.load8_u', 'i64', 0], [0x32, 'i64.load16_s', 'i64', 1], [0x33, 'i64.load16_u', 'i64', 1],
  [0x34, 'i64.load32_s', 'i64', 2], [0x35, 'i64.load32_u', 'i64', 2],
];
for (const [code, name, type, align] of LOADS) def(code, name, MEMARG, `addr > ${type}`, 'memory', W.LOAD | W.TRAPS, align, 1 << align);
const STORES: [number, string, string, number][] = [
  [0x36, 'i32.store', 'i32', 2], [0x37, 'i64.store', 'i64', 3], [0x38, 'f32.store', 'f32', 2], [0x39, 'f64.store', 'f64', 3],
  [0x3a, 'i32.store8', 'i32', 0], [0x3b, 'i32.store16', 'i32', 1], [0x3c, 'i64.store8', 'i64', 0], [0x3d, 'i64.store16', 'i64', 1],
  [0x3e, 'i64.store32', 'i64', 2],
];
for (const [code, name, type, align] of STORES) def(code, name, MEMARG, `addr ${type} > `, 'memory', W.STORE | W.TRAPS, align, 1 << align);
def(0x3f, 'memory.size', IMM.MEM, ' > addr', 'memory');
def(0x40, 'memory.grow', IMM.MEM, 'addr > addr', 'memory');

/* ------------------------------------------------------------------ *
 * Numbers
 * ------------------------------------------------------------------ */

def(0x41, 'i32.const', IMM.I32, ' > i32', 'numeric', W.CONST);
def(0x42, 'i64.const', IMM.I64, ' > i64', 'numeric', W.CONST);
def(0x43, 'f32.const', IMM.F32, ' > f32', 'numeric', W.CONST);
def(0x44, 'f64.const', IMM.F64, ' > f64', 'numeric', W.CONST);

const INT_COMPARE = ['eq', 'ne', 'lt_s', 'lt_u', 'gt_s', 'gt_u', 'le_s', 'le_u', 'ge_s', 'ge_u'];
const FLOAT_COMPARE = ['eq', 'ne', 'lt', 'gt', 'le', 'ge'];
const INT_UNARY = ['clz', 'ctz', 'popcnt'];
const INT_BINARY = ['add', 'sub', 'mul', 'div_s', 'div_u', 'rem_s', 'rem_u', 'and', 'or', 'xor', 'shl', 'shr_s', 'shr_u', 'rotl', 'rotr'];
const FLOAT_UNARY = ['abs', 'neg', 'ceil', 'floor', 'trunc', 'nearest', 'sqrt'];
const FLOAT_BINARY = ['add', 'sub', 'mul', 'div', 'min', 'max', 'copysign'];

def(0x45, 'i32.eqz', NONE, 'i32 > i32', 'numeric');
INT_COMPARE.forEach((op, i) => def(0x46 + i, `i32.${op}`, NONE, 'i32 i32 > i32', 'numeric'));
def(0x50, 'i64.eqz', NONE, 'i64 > i32', 'numeric');
INT_COMPARE.forEach((op, i) => def(0x51 + i, `i64.${op}`, NONE, 'i64 i64 > i32', 'numeric'));
FLOAT_COMPARE.forEach((op, i) => def(0x5b + i, `f32.${op}`, NONE, 'f32 f32 > i32', 'numeric'));
FLOAT_COMPARE.forEach((op, i) => def(0x61 + i, `f64.${op}`, NONE, 'f64 f64 > i32', 'numeric'));
INT_UNARY.forEach((op, i) => def(0x67 + i, `i32.${op}`, NONE, 'i32 > i32', 'numeric'));
INT_BINARY.forEach((op, i) => def(0x6a + i, `i32.${op}`, NONE, 'i32 i32 > i32', 'numeric', /^(div|rem)/.test(op) ? W.TRAPS : 0));
INT_UNARY.forEach((op, i) => def(0x79 + i, `i64.${op}`, NONE, 'i64 > i64', 'numeric'));
INT_BINARY.forEach((op, i) => def(0x7c + i, `i64.${op}`, NONE, 'i64 i64 > i64', 'numeric', /^(div|rem)/.test(op) ? W.TRAPS : 0));
FLOAT_UNARY.forEach((op, i) => def(0x8b + i, `f32.${op}`, NONE, 'f32 > f32', 'numeric'));
FLOAT_BINARY.forEach((op, i) => def(0x92 + i, `f32.${op}`, NONE, 'f32 f32 > f32', 'numeric'));
FLOAT_UNARY.forEach((op, i) => def(0x99 + i, `f64.${op}`, NONE, 'f64 > f64', 'numeric'));
FLOAT_BINARY.forEach((op, i) => def(0xa0 + i, `f64.${op}`, NONE, 'f64 f64 > f64', 'numeric'));

const CONVERSIONS: [string, string][] = [
  ['i32.wrap_i64', 'i64 > i32'], ['i32.trunc_f32_s', 'f32 > i32'], ['i32.trunc_f32_u', 'f32 > i32'], ['i32.trunc_f64_s', 'f64 > i32'],
  ['i32.trunc_f64_u', 'f64 > i32'], ['i64.extend_i32_s', 'i32 > i64'], ['i64.extend_i32_u', 'i32 > i64'], ['i64.trunc_f32_s', 'f32 > i64'],
  ['i64.trunc_f32_u', 'f32 > i64'], ['i64.trunc_f64_s', 'f64 > i64'], ['i64.trunc_f64_u', 'f64 > i64'], ['f32.convert_i32_s', 'i32 > f32'],
  ['f32.convert_i32_u', 'i32 > f32'], ['f32.convert_i64_s', 'i64 > f32'], ['f32.convert_i64_u', 'i64 > f32'], ['f32.demote_f64', 'f64 > f32'],
  ['f64.convert_i32_s', 'i32 > f64'], ['f64.convert_i32_u', 'i32 > f64'], ['f64.convert_i64_s', 'i64 > f64'], ['f64.convert_i64_u', 'i64 > f64'],
  ['f64.promote_f32', 'f32 > f64'], ['i32.reinterpret_f32', 'f32 > i32'], ['i64.reinterpret_f64', 'f64 > i64'], ['f32.reinterpret_i32', 'i32 > f32'],
  ['f64.reinterpret_i64', 'i64 > f64'], ['i32.extend8_s', 'i32 > i32'], ['i32.extend16_s', 'i32 > i32'], ['i64.extend8_s', 'i64 > i64'],
  ['i64.extend16_s', 'i64 > i64'], ['i64.extend32_s', 'i64 > i64'],
];
CONVERSIONS.forEach(([name, sig], i) => def(0xa7 + i, name, NONE, sig, 'numeric', /trunc_f/.test(name) ? W.TRAPS : 0));

/* ------------------------------------------------------------------ *
 * References
 * ------------------------------------------------------------------ */

def(0xd0, 'ref.null', IMM.HEAP, ' > ref', 'reference', W.CONST);
def(0xd1, 'ref.is_null', NONE, 'ref > i32', 'reference');
def(0xd2, 'ref.func', FUNC, ' > ref', 'reference', W.CONST);
def(0xd3, 'ref.eq', NONE, 'ref ref > i32', 'reference');
def(0xd4, 'ref.as_non_null', NONE, 'ref > ref', 'reference', W.TRAPS);
def(0xd5, 'br_on_null', LABEL, '', 'reference', W.BRANCH | W.COND);
def(0xd6, 'br_on_non_null', LABEL, '', 'reference', W.BRANCH | W.COND);

/* ------------------------------------------------------------------ *
 * 0xFB: garbage-collected structs, arrays, i31 and casts
 * ------------------------------------------------------------------ */

const GC: [number, string, number, string, number][] = [
  [0, 'struct.new', IMM.TYPE, '', 0],
  [1, 'struct.new_default', IMM.TYPE, ' > ref', 0],
  [2, 'struct.get', IMM.TYPE_FIELD, 'ref > T', W.TRAPS],
  [3, 'struct.get_s', IMM.TYPE_FIELD, 'ref > i32', W.TRAPS],
  [4, 'struct.get_u', IMM.TYPE_FIELD, 'ref > i32', W.TRAPS],
  [5, 'struct.set', IMM.TYPE_FIELD, 'ref T > ', W.TRAPS],
  [6, 'array.new', IMM.TYPE, 'T i32 > ref', 0],
  [7, 'array.new_default', IMM.TYPE, 'i32 > ref', 0],
  [8, 'array.new_fixed', IMM.TYPE_N, '', 0],
  [9, 'array.new_data', IMM.TYPE_DATA, 'i32 i32 > ref', W.TRAPS],
  [10, 'array.new_elem', IMM.TYPE_ELEM, 'i32 i32 > ref', W.TRAPS],
  [11, 'array.get', IMM.TYPE, 'ref i32 > T', W.TRAPS],
  [12, 'array.get_s', IMM.TYPE, 'ref i32 > i32', W.TRAPS],
  [13, 'array.get_u', IMM.TYPE, 'ref i32 > i32', W.TRAPS],
  [14, 'array.set', IMM.TYPE, 'ref i32 T > ', W.TRAPS],
  [15, 'array.len', NONE, 'ref > i32', W.TRAPS],
  [16, 'array.fill', IMM.TYPE, 'ref i32 T i32 > ', W.TRAPS],
  [17, 'array.copy', IMM.TYPE_TYPE, 'ref i32 ref i32 i32 > ', W.TRAPS],
  [18, 'array.init_data', IMM.TYPE_DATA, 'ref i32 i32 i32 > ', W.TRAPS],
  [19, 'array.init_elem', IMM.TYPE_ELEM, 'ref i32 i32 i32 > ', W.TRAPS],
  [20, 'ref.test', IMM.REF_TEST, 'ref > i32', 0],
  [21, 'ref.test', IMM.REF_TEST_NULL, 'ref > i32', 0],
  [22, 'ref.cast', IMM.REF_TEST, 'ref > ref', W.TRAPS],
  [23, 'ref.cast', IMM.REF_TEST_NULL, 'ref > ref', W.TRAPS],
  [24, 'br_on_cast', IMM.BR_ON_CAST, '', W.BRANCH | W.COND],
  [25, 'br_on_cast_fail', IMM.BR_ON_CAST, '', W.BRANCH | W.COND],
  [26, 'any.convert_extern', NONE, 'ref > ref', 0],
  [27, 'extern.convert_any', NONE, 'ref > ref', 0],
  [28, 'ref.i31', NONE, 'i32 > ref', 0],
  [29, 'i31.get_s', NONE, 'ref > i32', W.TRAPS],
  [30, 'i31.get_u', NONE, 'ref > i32', W.TRAPS],
];
for (const [sub, name, imm, sig, flags] of GC) def(FB | sub, name, imm, sig, name.startsWith('ref.') || name.startsWith('br_') || name.includes('convert') ? 'reference' : 'aggregate', flags);

/* ------------------------------------------------------------------ *
 * 0xFC: saturating conversions, bulk memory and tables, wide arithmetic
 * ------------------------------------------------------------------ */

const SAT: [string, string][] = [
  ['i32.trunc_sat_f32_s', 'f32 > i32'], ['i32.trunc_sat_f32_u', 'f32 > i32'], ['i32.trunc_sat_f64_s', 'f64 > i32'], ['i32.trunc_sat_f64_u', 'f64 > i32'],
  ['i64.trunc_sat_f32_s', 'f32 > i64'], ['i64.trunc_sat_f32_u', 'f32 > i64'], ['i64.trunc_sat_f64_s', 'f64 > i64'], ['i64.trunc_sat_f64_u', 'f64 > i64'],
];
SAT.forEach(([name, sig], i) => def(FC | i, name, NONE, sig, 'numeric'));
def(FC | 8, 'memory.init', IMM.MEMORY_INIT, 'addr i32 i32 > ', 'memory', W.STORE | W.TRAPS);
def(FC | 9, 'data.drop', IMM.DATA, ' > ', 'memory');
def(FC | 10, 'memory.copy', IMM.MEMORY_COPY, 'addr addr addr > ', 'memory', W.LOAD | W.STORE | W.TRAPS);
def(FC | 11, 'memory.fill', IMM.MEM, 'addr i32 addr > ', 'memory', W.STORE | W.TRAPS);
def(FC | 12, 'table.init', IMM.TABLE_INIT, 'i32 i32 i32 > ', 'table', W.TRAPS);
def(FC | 13, 'elem.drop', IMM.ELEM, ' > ', 'table');
def(FC | 14, 'table.copy', IMM.TABLE_COPY, 'i32 i32 i32 > ', 'table', W.TRAPS);
def(FC | 15, 'table.grow', TABLE, 'ref i32 > i32', 'table');
def(FC | 16, 'table.size', TABLE, ' > i32', 'table');
def(FC | 17, 'table.fill', TABLE, 'i32 ref i32 > ', 'table', W.TRAPS);
def(FC | 19, 'i64.add128', NONE, 'i64 i64 i64 i64 > i64 i64', 'numeric');
def(FC | 20, 'i64.sub128', NONE, 'i64 i64 i64 i64 > i64 i64', 'numeric');
def(FC | 21, 'i64.mul_wide_s', NONE, 'i64 i64 > i64 i64', 'numeric');
def(FC | 22, 'i64.mul_wide_u', NONE, 'i64 i64 > i64 i64', 'numeric');

/* ------------------------------------------------------------------ *
 * 0xFD: 128-bit SIMD and relaxed SIMD
 * ------------------------------------------------------------------ */

const SIMD = [
  'v128.load', 'v128.load8x8_s', 'v128.load8x8_u', 'v128.load16x4_s', 'v128.load16x4_u', 'v128.load32x2_s', 'v128.load32x2_u', 'v128.load8_splat',
  'v128.load16_splat', 'v128.load32_splat', 'v128.load64_splat', 'v128.store', 'v128.const', 'i8x16.shuffle', 'i8x16.swizzle', 'i8x16.splat',
  'i16x8.splat', 'i32x4.splat', 'i64x2.splat', 'f32x4.splat', 'f64x2.splat', 'i8x16.extract_lane_s', 'i8x16.extract_lane_u', 'i8x16.replace_lane',
  'i16x8.extract_lane_s', 'i16x8.extract_lane_u', 'i16x8.replace_lane', 'i32x4.extract_lane', 'i32x4.replace_lane', 'i64x2.extract_lane', 'i64x2.replace_lane', 'f32x4.extract_lane',
  'f32x4.replace_lane', 'f64x2.extract_lane', 'f64x2.replace_lane', 'i8x16.eq', 'i8x16.ne', 'i8x16.lt_s', 'i8x16.lt_u', 'i8x16.gt_s',
  'i8x16.gt_u', 'i8x16.le_s', 'i8x16.le_u', 'i8x16.ge_s', 'i8x16.ge_u', 'i16x8.eq', 'i16x8.ne', 'i16x8.lt_s',
  'i16x8.lt_u', 'i16x8.gt_s', 'i16x8.gt_u', 'i16x8.le_s', 'i16x8.le_u', 'i16x8.ge_s', 'i16x8.ge_u', 'i32x4.eq',
  'i32x4.ne', 'i32x4.lt_s', 'i32x4.lt_u', 'i32x4.gt_s', 'i32x4.gt_u', 'i32x4.le_s', 'i32x4.le_u', 'i32x4.ge_s',
  'i32x4.ge_u', 'f32x4.eq', 'f32x4.ne', 'f32x4.lt', 'f32x4.gt', 'f32x4.le', 'f32x4.ge', 'f64x2.eq',
  'f64x2.ne', 'f64x2.lt', 'f64x2.gt', 'f64x2.le', 'f64x2.ge', 'v128.not', 'v128.and', 'v128.andnot',
  'v128.or', 'v128.xor', 'v128.bitselect', 'v128.any_true', 'v128.load8_lane', 'v128.load16_lane', 'v128.load32_lane', 'v128.load64_lane',
  'v128.store8_lane', 'v128.store16_lane', 'v128.store32_lane', 'v128.store64_lane', 'v128.load32_zero', 'v128.load64_zero', 'f32x4.demote_f64x2_zero', 'f64x2.promote_low_f32x4',
  'i8x16.abs', 'i8x16.neg', 'i8x16.popcnt', 'i8x16.all_true', 'i8x16.bitmask', 'i8x16.narrow_i16x8_s', 'i8x16.narrow_i16x8_u', 'f32x4.ceil',
  'f32x4.floor', 'f32x4.trunc', 'f32x4.nearest', 'i8x16.shl', 'i8x16.shr_s', 'i8x16.shr_u', 'i8x16.add', 'i8x16.add_sat_s',
  'i8x16.add_sat_u', 'i8x16.sub', 'i8x16.sub_sat_s', 'i8x16.sub_sat_u', 'f64x2.ceil', 'f64x2.floor', 'i8x16.min_s', 'i8x16.min_u',
  'i8x16.max_s', 'i8x16.max_u', 'f64x2.trunc', 'i8x16.avgr_u', 'i16x8.extadd_pairwise_i8x16_s', 'i16x8.extadd_pairwise_i8x16_u', 'i32x4.extadd_pairwise_i16x8_s', 'i32x4.extadd_pairwise_i16x8_u',
  'i16x8.abs', 'i16x8.neg', 'i16x8.q15mulr_sat_s', 'i16x8.all_true', 'i16x8.bitmask', 'i16x8.narrow_i32x4_s', 'i16x8.narrow_i32x4_u', 'i16x8.extend_low_i8x16_s',
  'i16x8.extend_high_i8x16_s', 'i16x8.extend_low_i8x16_u', 'i16x8.extend_high_i8x16_u', 'i16x8.shl', 'i16x8.shr_s', 'i16x8.shr_u', 'i16x8.add', 'i16x8.add_sat_s',
  'i16x8.add_sat_u', 'i16x8.sub', 'i16x8.sub_sat_s', 'i16x8.sub_sat_u', 'f64x2.nearest', 'i16x8.mul', 'i16x8.min_s', 'i16x8.min_u',
  'i16x8.max_s', 'i16x8.max_u', '', 'i16x8.avgr_u', 'i16x8.extmul_low_i8x16_s', 'i16x8.extmul_high_i8x16_s', 'i16x8.extmul_low_i8x16_u', 'i16x8.extmul_high_i8x16_u',
  'i32x4.abs', 'i32x4.neg', '', 'i32x4.all_true', 'i32x4.bitmask', '', '', 'i32x4.extend_low_i16x8_s',
  'i32x4.extend_high_i16x8_s', 'i32x4.extend_low_i16x8_u', 'i32x4.extend_high_i16x8_u', 'i32x4.shl', 'i32x4.shr_s', 'i32x4.shr_u', 'i32x4.add', '',
  '', 'i32x4.sub', '', '', '', 'i32x4.mul', 'i32x4.min_s', 'i32x4.min_u',
  'i32x4.max_s', 'i32x4.max_u', 'i32x4.dot_i16x8_s', '', 'i32x4.extmul_low_i16x8_s', 'i32x4.extmul_high_i16x8_s', 'i32x4.extmul_low_i16x8_u', 'i32x4.extmul_high_i16x8_u',
  'i64x2.abs', 'i64x2.neg', '', 'i64x2.all_true', 'i64x2.bitmask', '', '', 'i64x2.extend_low_i32x4_s',
  'i64x2.extend_high_i32x4_s', 'i64x2.extend_low_i32x4_u', 'i64x2.extend_high_i32x4_u', 'i64x2.shl', 'i64x2.shr_s', 'i64x2.shr_u', 'i64x2.add', '',
  '', 'i64x2.sub', '', '', '', 'i64x2.mul', 'i64x2.eq', 'i64x2.ne',
  'i64x2.lt_s', 'i64x2.gt_s', 'i64x2.le_s', 'i64x2.ge_s', 'i64x2.extmul_low_i32x4_s', 'i64x2.extmul_high_i32x4_s', 'i64x2.extmul_low_i32x4_u', 'i64x2.extmul_high_i32x4_u',
  'f32x4.abs', 'f32x4.neg', '', 'f32x4.sqrt', 'f32x4.add', 'f32x4.sub', 'f32x4.mul', 'f32x4.div',
  'f32x4.min', 'f32x4.max', 'f32x4.pmin', 'f32x4.pmax', 'f64x2.abs', 'f64x2.neg', '', 'f64x2.sqrt',
  'f64x2.add', 'f64x2.sub', 'f64x2.mul', 'f64x2.div', 'f64x2.min', 'f64x2.max', 'f64x2.pmin', 'f64x2.pmax',
  'i32x4.trunc_sat_f32x4_s', 'i32x4.trunc_sat_f32x4_u', 'f32x4.convert_i32x4_s', 'f32x4.convert_i32x4_u', 'i32x4.trunc_sat_f64x2_s_zero', 'i32x4.trunc_sat_f64x2_u_zero', 'f64x2.convert_low_i32x4_s', 'f64x2.convert_low_i32x4_u',
  // 0x100: relaxed SIMD
  'i8x16.relaxed_swizzle', 'i32x4.relaxed_trunc_f32x4_s', 'i32x4.relaxed_trunc_f32x4_u', 'i32x4.relaxed_trunc_f64x2_s_zero', 'i32x4.relaxed_trunc_f64x2_u_zero', 'f32x4.relaxed_madd', 'f32x4.relaxed_nmadd', 'f64x2.relaxed_madd',
  'f64x2.relaxed_nmadd', 'i8x16.relaxed_laneselect', 'i16x8.relaxed_laneselect', 'i32x4.relaxed_laneselect', 'i64x2.relaxed_laneselect', 'f32x4.relaxed_min', 'f32x4.relaxed_max', 'f64x2.relaxed_min',
  'f64x2.relaxed_max', 'i16x8.relaxed_q15mulr_s', 'i16x8.relaxed_dot_i8x16_i7x16_s', 'i32x4.relaxed_dot_i8x16_i7x16_add_s',
];

const LANE_TYPE: Record<string, string> = { i8x16: 'i32', i16x8: 'i32', i32x4: 'i32', i64x2: 'i64', f32x4: 'f32', f64x2: 'f64' };
const LOG_SIZE: Record<string, number> = { '8': 0, '16': 1, '32': 2, '64': 3 };

SIMD.forEach((name, sub) => {
  if (!name) return;
  const code = FD | sub;
  const shape = name.slice(0, name.indexOf('.'));
  const op = name.slice(name.indexOf('.') + 1);
  if (name === 'v128.store') return def(code, name, MEMARG, 'addr v128 > ', 'vector', W.STORE | W.TRAPS, 4, 16);
  if (name === 'v128.const') return def(code, name, IMM.V128, ' > v128', 'vector', W.CONST);
  if (name === 'i8x16.shuffle') return def(code, name, IMM.SHUFFLE, 'v128 v128 > v128', 'vector');
  let match = /^load(\d+)_lane$/.exec(op);
  if (match) return def(code, name, IMM.MEMARG_LANE, 'addr v128 > v128', 'vector', W.LOAD | W.TRAPS, LOG_SIZE[match[1]!]!, Number(match[1]) / 8);
  match = /^store(\d+)_lane$/.exec(op);
  if (match) return def(code, name, IMM.MEMARG_LANE, 'addr v128 > ', 'vector', W.STORE | W.TRAPS, LOG_SIZE[match[1]!]!, Number(match[1]) / 8);
  if (shape === 'v128' && op.startsWith('load')) {
    const align = op === 'load' ? 4 : /x/.test(op) ? 3 : LOG_SIZE[/(\d+)/.exec(op)![1]!]!;
    return def(code, name, MEMARG, 'addr > v128', 'vector', W.LOAD | W.TRAPS, align, 1 << align);
  }
  if (op === 'splat') return def(code, name, NONE, `${LANE_TYPE[shape]} > v128`, 'vector');
  if (op.startsWith('extract_lane')) return def(code, name, IMM.LANE, `v128 > ${LANE_TYPE[shape]}`, 'vector');
  if (op === 'replace_lane') return def(code, name, IMM.LANE, `v128 ${LANE_TYPE[shape]} > v128`, 'vector');
  if (/^(any_true|all_true|bitmask)$/.test(op)) return def(code, name, NONE, 'v128 > i32', 'vector');
  if (/^(shl|shr_s|shr_u)$/.test(op)) return def(code, name, NONE, 'v128 i32 > v128', 'vector');
  if (/^(bitselect|relaxed_madd|relaxed_nmadd|relaxed_laneselect|relaxed_dot_i8x16_i7x16_add_s)$/.test(op)) return def(code, name, NONE, 'v128 v128 v128 > v128', 'vector');
  const unary = /^(not|abs|neg|popcnt|sqrt|ceil|floor|trunc|nearest|extend_|extadd_|convert_|trunc_sat_|demote_|promote_|relaxed_trunc)/.test(op);
  return def(code, name, NONE, unary ? 'v128 > v128' : 'v128 v128 > v128', 'vector');
});

/* ------------------------------------------------------------------ *
 * 0xFE: threads — atomic memory access, wait and notify
 * ------------------------------------------------------------------ */

const A = W.ATOMIC | W.TRAPS;
def(FE | 0x00, 'memory.atomic.notify', MEMARG, 'addr i32 > i32', 'atomic', A, 2, 4);
def(FE | 0x01, 'memory.atomic.wait32', MEMARG, 'addr i32 i64 > i32', 'atomic', A | W.LOAD, 2, 4);
def(FE | 0x02, 'memory.atomic.wait64', MEMARG, 'addr i64 i64 > i32', 'atomic', A | W.LOAD, 3, 8);
def(FE | 0x03, 'atomic.fence', IMM.FENCE, ' > ', 'atomic', W.ATOMIC);
const WIDTHS: [string, string, number, string][] = [
  ['i32', '', 2, 'i32'], ['i64', '', 3, 'i64'], ['i32', '8', 0, 'i32'], ['i32', '16', 1, 'i32'], ['i64', '8', 0, 'i64'], ['i64', '16', 1, 'i64'], ['i64', '32', 2, 'i64'],
];
WIDTHS.forEach(([type, bits, align, value], i) => def(FE | (0x10 + i), `${type}.atomic.load${bits}${bits ? '_u' : ''}`, MEMARG, `addr > ${value}`, 'atomic', A | W.LOAD, align, 1 << align));
WIDTHS.forEach(([type, bits, align, value], i) => def(FE | (0x17 + i), `${type}.atomic.store${bits}`, MEMARG, `addr ${value} > `, 'atomic', A | W.STORE, align, 1 << align));
['add', 'sub', 'and', 'or', 'xor', 'xchg', 'cmpxchg'].forEach((op, k) => {
  WIDTHS.forEach(([type, bits, align, value], i) => {
    const sig = op === 'cmpxchg' ? `addr ${value} ${value} > ${value}` : `addr ${value} > ${value}`;
    def(FE | (0x1e + k * 7 + i), `${type}.atomic.rmw${bits}.${op}${bits ? '_u' : ''}`, MEMARG, sig, 'atomic', A | W.LOAD | W.STORE, align, 1 << align);
  });
});

/* ------------------------------------------------------------------ *
 * Lookups
 * ------------------------------------------------------------------ */

export function opInfo(code: number): OpInfo | undefined {
  return OPS.get(code);
}

/** Every instruction, by name (ref.test and select have two encodings and one name). */
export function allOps(): OpInfo[] {
  return [...OPS.values()];
}

export const PREFIXES = new Set([0xfb, 0xfc, 0xfd, 0xfe]);

/** The opcode bytes as they appear in the file: `0x6a`, `0xfd 0x0e`. */
export function opcodeText(code: number): string {
  const prefix = code >>> 16;
  const sub = code & 0xffff;
  if (!prefix) return `0x${sub.toString(16).padStart(2, '0')}`;
  return `0x${prefix.toString(16)} ${sub}`;
}
