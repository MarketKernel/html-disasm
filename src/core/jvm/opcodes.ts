/**
 * The JVM's opcodes (the Java Virtual Machine Specification, chapter 6): a
 * byte, then the operand its kind says. `wide` (0xC4) is not one of them on
 * its own: with the instruction it widens it is one instruction, and javap
 * names the pair as the ClassFile API does — `iload_w`, `iinc_w`, `ret_w`. Each
 * opcode has the values it takes from the operand stack and leaves there
 * (values, not slots: a long is one value; `-1` when the descriptor of what it
 * calls or names says), and flags for the analysis and the colours of the
 * listing. The descriptions are in src/data/jvm-instructions.json.
 */

/** The kinds of operand an opcode is followed by. */
export const OPERAND = {
  NONE: 0,
  /** A local variable's slot: one byte, or two after wide. */
  LOCAL: 1,
  LOCAL_W: 2,
  /** iinc: a slot and a signed constant, a byte each, or two bytes each after wide. */
  IINC: 3,
  IINC_W: 4,
  /** A signed byte (bipush) or a signed short (sipush). */
  BYTE: 5,
  SHORT: 6,
  /** A constant pool index: one byte (ldc) or two. */
  CP8: 7,
  CP16: 8,
  /** invokeinterface: an index, the count of argument slots and a zero byte. */
  INTERFACE: 9,
  /** invokedynamic: an index and two zero bytes. */
  DYNAMIC: 10,
  /** multianewarray: an index and the number of dimensions. */
  DIMENSIONS: 11,
  /** newarray: the type of the elements (4 boolean … 11 long). */
  ATYPE: 12,
  /** A branch offset from the instruction: two bytes or four. */
  BRANCH16: 13,
  BRANCH32: 14,
  TABLESWITCH: 15,
  LOOKUPSWITCH: 16,
  /** jsr and ret, whose operands javap does not print. */
  JSR16: 17,
  JSR32: 18,
  RET: 19,
  RET_W: 20,
} as const;

/** Bits of OpInfo.flags. */
export const F = {
  BRANCH: 1,
  CONDITIONAL: 2,
  CALL: 4,
  RETURN: 8,
  THROW: 16,
  /** Ends a block of code: nothing after it runs unless something branches there. */
  END: 32,
  LOAD: 64,
  STORE: 128,
  COMPARE: 256,
  /** Can throw on its own (a null reference, an index out of the array, a bad cast, division by zero). */
  TRAPS: 512,
  /** A subroutine (jsr, ret): the return address is a value no line can name. */
  SUBROUTINE: 1024,
} as const;

export type Group = 'jvm-constants' | 'jvm-loads' | 'jvm-stores' | 'jvm-stack' | 'jvm-math' | 'jvm-conversions' | 'jvm-comparisons' | 'jvm-control' | 'jvm-references' | 'jvm-extended';

export interface OpInfo {
  name: string;
  /** 0x00–0xC9, or 0xC4xx for a wide form. */
  code: number;
  operand: number;
  /** Values taken from and pushed on the stack; -1 when the descriptor of the operand says. */
  pop: number;
  push: number;
  flags: number;
  group: Group;
  category: string;
  /** What kind of value it pushes: i(nt), l(ong), f(loat), d(ouble), a (reference), r(eturn address); '' when it pushes nothing or the descriptor says. */
  kind: string;
}

const O = OPERAND;
type Row = [code: number, name: string, operand: number, pop: number, push: number, flags: number, group: Group, category: string, kind: string];

const C = 'jvm-constants';
const L = 'jvm-loads';
const S = 'jvm-stores';
const K = 'jvm-stack';
const M = 'jvm-math';
const V = 'jvm-conversions';
const P = 'jvm-comparisons';
const T = 'jvm-control';
const R = 'jvm-references';
const X = 'jvm-extended';
const IF = F.BRANCH | F.CONDITIONAL;

const ROWS: Row[] = [
  [0x00, 'nop', O.NONE, 0, 0, 0, C, 'other', ''],
  [0x01, 'aconst_null', O.NONE, 0, 1, 0, C, 'constant', 'a'],
  [0x02, 'iconst_m1', O.NONE, 0, 1, 0, C, 'constant', 'i'],
  [0x03, 'iconst_0', O.NONE, 0, 1, 0, C, 'constant', 'i'],
  [0x04, 'iconst_1', O.NONE, 0, 1, 0, C, 'constant', 'i'],
  [0x05, 'iconst_2', O.NONE, 0, 1, 0, C, 'constant', 'i'],
  [0x06, 'iconst_3', O.NONE, 0, 1, 0, C, 'constant', 'i'],
  [0x07, 'iconst_4', O.NONE, 0, 1, 0, C, 'constant', 'i'],
  [0x08, 'iconst_5', O.NONE, 0, 1, 0, C, 'constant', 'i'],
  [0x09, 'lconst_0', O.NONE, 0, 1, 0, C, 'constant', 'l'],
  [0x0a, 'lconst_1', O.NONE, 0, 1, 0, C, 'constant', 'l'],
  [0x0b, 'fconst_0', O.NONE, 0, 1, 0, C, 'constant', 'f'],
  [0x0c, 'fconst_1', O.NONE, 0, 1, 0, C, 'constant', 'f'],
  [0x0d, 'fconst_2', O.NONE, 0, 1, 0, C, 'constant', 'f'],
  [0x0e, 'dconst_0', O.NONE, 0, 1, 0, C, 'constant', 'd'],
  [0x0f, 'dconst_1', O.NONE, 0, 1, 0, C, 'constant', 'd'],
  [0x10, 'bipush', O.BYTE, 0, 1, 0, C, 'constant', 'i'],
  [0x11, 'sipush', O.SHORT, 0, 1, 0, C, 'constant', 'i'],
  [0x12, 'ldc', O.CP8, 0, 1, 0, C, 'constant', ''],
  [0x13, 'ldc_w', O.CP16, 0, 1, 0, C, 'constant', ''],
  [0x14, 'ldc2_w', O.CP16, 0, 1, 0, C, 'constant', ''],
  [0x15, 'iload', O.LOCAL, 0, 1, 0, L, 'variable', 'i'],
  [0x16, 'lload', O.LOCAL, 0, 1, 0, L, 'variable', 'l'],
  [0x17, 'fload', O.LOCAL, 0, 1, 0, L, 'variable', 'f'],
  [0x18, 'dload', O.LOCAL, 0, 1, 0, L, 'variable', 'd'],
  [0x19, 'aload', O.LOCAL, 0, 1, 0, L, 'variable', 'a'],
  [0x1a, 'iload_0', O.NONE, 0, 1, 0, L, 'variable', 'i'],
  [0x1b, 'iload_1', O.NONE, 0, 1, 0, L, 'variable', 'i'],
  [0x1c, 'iload_2', O.NONE, 0, 1, 0, L, 'variable', 'i'],
  [0x1d, 'iload_3', O.NONE, 0, 1, 0, L, 'variable', 'i'],
  [0x1e, 'lload_0', O.NONE, 0, 1, 0, L, 'variable', 'l'],
  [0x1f, 'lload_1', O.NONE, 0, 1, 0, L, 'variable', 'l'],
  [0x20, 'lload_2', O.NONE, 0, 1, 0, L, 'variable', 'l'],
  [0x21, 'lload_3', O.NONE, 0, 1, 0, L, 'variable', 'l'],
  [0x22, 'fload_0', O.NONE, 0, 1, 0, L, 'variable', 'f'],
  [0x23, 'fload_1', O.NONE, 0, 1, 0, L, 'variable', 'f'],
  [0x24, 'fload_2', O.NONE, 0, 1, 0, L, 'variable', 'f'],
  [0x25, 'fload_3', O.NONE, 0, 1, 0, L, 'variable', 'f'],
  [0x26, 'dload_0', O.NONE, 0, 1, 0, L, 'variable', 'd'],
  [0x27, 'dload_1', O.NONE, 0, 1, 0, L, 'variable', 'd'],
  [0x28, 'dload_2', O.NONE, 0, 1, 0, L, 'variable', 'd'],
  [0x29, 'dload_3', O.NONE, 0, 1, 0, L, 'variable', 'd'],
  [0x2a, 'aload_0', O.NONE, 0, 1, 0, L, 'variable', 'a'],
  [0x2b, 'aload_1', O.NONE, 0, 1, 0, L, 'variable', 'a'],
  [0x2c, 'aload_2', O.NONE, 0, 1, 0, L, 'variable', 'a'],
  [0x2d, 'aload_3', O.NONE, 0, 1, 0, L, 'variable', 'a'],
  [0x2e, 'iaload', O.NONE, 2, 1, F.LOAD | F.TRAPS, L, 'array', 'i'],
  [0x2f, 'laload', O.NONE, 2, 1, F.LOAD | F.TRAPS, L, 'array', 'l'],
  [0x30, 'faload', O.NONE, 2, 1, F.LOAD | F.TRAPS, L, 'array', 'f'],
  [0x31, 'daload', O.NONE, 2, 1, F.LOAD | F.TRAPS, L, 'array', 'd'],
  [0x32, 'aaload', O.NONE, 2, 1, F.LOAD | F.TRAPS, L, 'array', 'a'],
  [0x33, 'baload', O.NONE, 2, 1, F.LOAD | F.TRAPS, L, 'array', 'i'],
  [0x34, 'caload', O.NONE, 2, 1, F.LOAD | F.TRAPS, L, 'array', 'i'],
  [0x35, 'saload', O.NONE, 2, 1, F.LOAD | F.TRAPS, L, 'array', 'i'],
  [0x36, 'istore', O.LOCAL, 1, 0, 0, S, 'variable', ''],
  [0x37, 'lstore', O.LOCAL, 1, 0, 0, S, 'variable', ''],
  [0x38, 'fstore', O.LOCAL, 1, 0, 0, S, 'variable', ''],
  [0x39, 'dstore', O.LOCAL, 1, 0, 0, S, 'variable', ''],
  [0x3a, 'astore', O.LOCAL, 1, 0, 0, S, 'variable', ''],
  [0x3b, 'istore_0', O.NONE, 1, 0, 0, S, 'variable', ''],
  [0x3c, 'istore_1', O.NONE, 1, 0, 0, S, 'variable', ''],
  [0x3d, 'istore_2', O.NONE, 1, 0, 0, S, 'variable', ''],
  [0x3e, 'istore_3', O.NONE, 1, 0, 0, S, 'variable', ''],
  [0x3f, 'lstore_0', O.NONE, 1, 0, 0, S, 'variable', ''],
  [0x40, 'lstore_1', O.NONE, 1, 0, 0, S, 'variable', ''],
  [0x41, 'lstore_2', O.NONE, 1, 0, 0, S, 'variable', ''],
  [0x42, 'lstore_3', O.NONE, 1, 0, 0, S, 'variable', ''],
  [0x43, 'fstore_0', O.NONE, 1, 0, 0, S, 'variable', ''],
  [0x44, 'fstore_1', O.NONE, 1, 0, 0, S, 'variable', ''],
  [0x45, 'fstore_2', O.NONE, 1, 0, 0, S, 'variable', ''],
  [0x46, 'fstore_3', O.NONE, 1, 0, 0, S, 'variable', ''],
  [0x47, 'dstore_0', O.NONE, 1, 0, 0, S, 'variable', ''],
  [0x48, 'dstore_1', O.NONE, 1, 0, 0, S, 'variable', ''],
  [0x49, 'dstore_2', O.NONE, 1, 0, 0, S, 'variable', ''],
  [0x4a, 'dstore_3', O.NONE, 1, 0, 0, S, 'variable', ''],
  [0x4b, 'astore_0', O.NONE, 1, 0, 0, S, 'variable', ''],
  [0x4c, 'astore_1', O.NONE, 1, 0, 0, S, 'variable', ''],
  [0x4d, 'astore_2', O.NONE, 1, 0, 0, S, 'variable', ''],
  [0x4e, 'astore_3', O.NONE, 1, 0, 0, S, 'variable', ''],
  [0x4f, 'iastore', O.NONE, 3, 0, F.STORE | F.TRAPS, S, 'array', ''],
  [0x50, 'lastore', O.NONE, 3, 0, F.STORE | F.TRAPS, S, 'array', ''],
  [0x51, 'fastore', O.NONE, 3, 0, F.STORE | F.TRAPS, S, 'array', ''],
  [0x52, 'dastore', O.NONE, 3, 0, F.STORE | F.TRAPS, S, 'array', ''],
  [0x53, 'aastore', O.NONE, 3, 0, F.STORE | F.TRAPS, S, 'array', ''],
  [0x54, 'bastore', O.NONE, 3, 0, F.STORE | F.TRAPS, S, 'array', ''],
  [0x55, 'castore', O.NONE, 3, 0, F.STORE | F.TRAPS, S, 'array', ''],
  [0x56, 'sastore', O.NONE, 3, 0, F.STORE | F.TRAPS, S, 'array', ''],
  [0x57, 'pop', O.NONE, 1, 0, 0, K, 'stack', ''],
  [0x58, 'pop2', O.NONE, -1, 0, 0, K, 'stack', ''],
  [0x59, 'dup', O.NONE, -1, -1, 0, K, 'stack', ''],
  [0x5a, 'dup_x1', O.NONE, -1, -1, 0, K, 'stack', ''],
  [0x5b, 'dup_x2', O.NONE, -1, -1, 0, K, 'stack', ''],
  [0x5c, 'dup2', O.NONE, -1, -1, 0, K, 'stack', ''],
  [0x5d, 'dup2_x1', O.NONE, -1, -1, 0, K, 'stack', ''],
  [0x5e, 'dup2_x2', O.NONE, -1, -1, 0, K, 'stack', ''],
  [0x5f, 'swap', O.NONE, -1, -1, 0, K, 'stack', ''],
  [0x60, 'iadd', O.NONE, 2, 1, 0, M, 'arithmetic', 'i'],
  [0x61, 'ladd', O.NONE, 2, 1, 0, M, 'arithmetic', 'l'],
  [0x62, 'fadd', O.NONE, 2, 1, 0, M, 'arithmetic', 'f'],
  [0x63, 'dadd', O.NONE, 2, 1, 0, M, 'arithmetic', 'd'],
  [0x64, 'isub', O.NONE, 2, 1, 0, M, 'arithmetic', 'i'],
  [0x65, 'lsub', O.NONE, 2, 1, 0, M, 'arithmetic', 'l'],
  [0x66, 'fsub', O.NONE, 2, 1, 0, M, 'arithmetic', 'f'],
  [0x67, 'dsub', O.NONE, 2, 1, 0, M, 'arithmetic', 'd'],
  [0x68, 'imul', O.NONE, 2, 1, 0, M, 'arithmetic', 'i'],
  [0x69, 'lmul', O.NONE, 2, 1, 0, M, 'arithmetic', 'l'],
  [0x6a, 'fmul', O.NONE, 2, 1, 0, M, 'arithmetic', 'f'],
  [0x6b, 'dmul', O.NONE, 2, 1, 0, M, 'arithmetic', 'd'],
  [0x6c, 'idiv', O.NONE, 2, 1, F.TRAPS, M, 'arithmetic', 'i'],
  [0x6d, 'ldiv', O.NONE, 2, 1, F.TRAPS, M, 'arithmetic', 'l'],
  [0x6e, 'fdiv', O.NONE, 2, 1, 0, M, 'arithmetic', 'f'],
  [0x6f, 'ddiv', O.NONE, 2, 1, 0, M, 'arithmetic', 'd'],
  [0x70, 'irem', O.NONE, 2, 1, F.TRAPS, M, 'arithmetic', 'i'],
  [0x71, 'lrem', O.NONE, 2, 1, F.TRAPS, M, 'arithmetic', 'l'],
  [0x72, 'frem', O.NONE, 2, 1, 0, M, 'arithmetic', 'f'],
  [0x73, 'drem', O.NONE, 2, 1, 0, M, 'arithmetic', 'd'],
  [0x74, 'ineg', O.NONE, 1, 1, 0, M, 'arithmetic', 'i'],
  [0x75, 'lneg', O.NONE, 1, 1, 0, M, 'arithmetic', 'l'],
  [0x76, 'fneg', O.NONE, 1, 1, 0, M, 'arithmetic', 'f'],
  [0x77, 'dneg', O.NONE, 1, 1, 0, M, 'arithmetic', 'd'],
  [0x78, 'ishl', O.NONE, 2, 1, 0, M, 'shift', 'i'],
  [0x79, 'lshl', O.NONE, 2, 1, 0, M, 'shift', 'l'],
  [0x7a, 'ishr', O.NONE, 2, 1, 0, M, 'shift', 'i'],
  [0x7b, 'lshr', O.NONE, 2, 1, 0, M, 'shift', 'l'],
  [0x7c, 'iushr', O.NONE, 2, 1, 0, M, 'shift', 'i'],
  [0x7d, 'lushr', O.NONE, 2, 1, 0, M, 'shift', 'l'],
  [0x7e, 'iand', O.NONE, 2, 1, 0, M, 'logic', 'i'],
  [0x7f, 'land', O.NONE, 2, 1, 0, M, 'logic', 'l'],
  [0x80, 'ior', O.NONE, 2, 1, 0, M, 'logic', 'i'],
  [0x81, 'lor', O.NONE, 2, 1, 0, M, 'logic', 'l'],
  [0x82, 'ixor', O.NONE, 2, 1, 0, M, 'logic', 'i'],
  [0x83, 'lxor', O.NONE, 2, 1, 0, M, 'logic', 'l'],
  [0x84, 'iinc', O.IINC, 0, 0, 0, M, 'arithmetic', ''],
  [0x85, 'i2l', O.NONE, 1, 1, 0, V, 'conversion', 'l'],
  [0x86, 'i2f', O.NONE, 1, 1, 0, V, 'conversion', 'f'],
  [0x87, 'i2d', O.NONE, 1, 1, 0, V, 'conversion', 'd'],
  [0x88, 'l2i', O.NONE, 1, 1, 0, V, 'conversion', 'i'],
  [0x89, 'l2f', O.NONE, 1, 1, 0, V, 'conversion', 'f'],
  [0x8a, 'l2d', O.NONE, 1, 1, 0, V, 'conversion', 'd'],
  [0x8b, 'f2i', O.NONE, 1, 1, 0, V, 'conversion', 'i'],
  [0x8c, 'f2l', O.NONE, 1, 1, 0, V, 'conversion', 'l'],
  [0x8d, 'f2d', O.NONE, 1, 1, 0, V, 'conversion', 'd'],
  [0x8e, 'd2i', O.NONE, 1, 1, 0, V, 'conversion', 'i'],
  [0x8f, 'd2l', O.NONE, 1, 1, 0, V, 'conversion', 'l'],
  [0x90, 'd2f', O.NONE, 1, 1, 0, V, 'conversion', 'f'],
  [0x91, 'i2b', O.NONE, 1, 1, 0, V, 'conversion', 'i'],
  [0x92, 'i2c', O.NONE, 1, 1, 0, V, 'conversion', 'i'],
  [0x93, 'i2s', O.NONE, 1, 1, 0, V, 'conversion', 'i'],
  [0x94, 'lcmp', O.NONE, 2, 1, F.COMPARE, P, 'compare', 'i'],
  [0x95, 'fcmpl', O.NONE, 2, 1, F.COMPARE, P, 'compare', 'i'],
  [0x96, 'fcmpg', O.NONE, 2, 1, F.COMPARE, P, 'compare', 'i'],
  [0x97, 'dcmpl', O.NONE, 2, 1, F.COMPARE, P, 'compare', 'i'],
  [0x98, 'dcmpg', O.NONE, 2, 1, F.COMPARE, P, 'compare', 'i'],
  [0x99, 'ifeq', O.BRANCH16, 1, 0, IF, P, 'branch', ''],
  [0x9a, 'ifne', O.BRANCH16, 1, 0, IF, P, 'branch', ''],
  [0x9b, 'iflt', O.BRANCH16, 1, 0, IF, P, 'branch', ''],
  [0x9c, 'ifge', O.BRANCH16, 1, 0, IF, P, 'branch', ''],
  [0x9d, 'ifgt', O.BRANCH16, 1, 0, IF, P, 'branch', ''],
  [0x9e, 'ifle', O.BRANCH16, 1, 0, IF, P, 'branch', ''],
  [0x9f, 'if_icmpeq', O.BRANCH16, 2, 0, IF, P, 'branch', ''],
  [0xa0, 'if_icmpne', O.BRANCH16, 2, 0, IF, P, 'branch', ''],
  [0xa1, 'if_icmplt', O.BRANCH16, 2, 0, IF, P, 'branch', ''],
  [0xa2, 'if_icmpge', O.BRANCH16, 2, 0, IF, P, 'branch', ''],
  [0xa3, 'if_icmpgt', O.BRANCH16, 2, 0, IF, P, 'branch', ''],
  [0xa4, 'if_icmple', O.BRANCH16, 2, 0, IF, P, 'branch', ''],
  [0xa5, 'if_acmpeq', O.BRANCH16, 2, 0, IF, P, 'branch', ''],
  [0xa6, 'if_acmpne', O.BRANCH16, 2, 0, IF, P, 'branch', ''],
  [0xa7, 'goto', O.BRANCH16, 0, 0, F.BRANCH | F.END, T, 'branch', ''],
  [0xa8, 'jsr', O.JSR16, 0, 1, F.BRANCH | F.SUBROUTINE, T, 'branch', 'r'],
  [0xa9, 'ret', O.RET, 0, 0, F.END | F.SUBROUTINE, T, 'branch', ''],
  [0xaa, 'tableswitch', O.TABLESWITCH, 1, 0, IF | F.END, T, 'branch', ''],
  [0xab, 'lookupswitch', O.LOOKUPSWITCH, 1, 0, IF | F.END, T, 'branch', ''],
  [0xac, 'ireturn', O.NONE, 1, 0, F.RETURN | F.END | F.TRAPS, T, 'branch', ''],
  [0xad, 'lreturn', O.NONE, 1, 0, F.RETURN | F.END | F.TRAPS, T, 'branch', ''],
  [0xae, 'freturn', O.NONE, 1, 0, F.RETURN | F.END | F.TRAPS, T, 'branch', ''],
  [0xaf, 'dreturn', O.NONE, 1, 0, F.RETURN | F.END | F.TRAPS, T, 'branch', ''],
  [0xb0, 'areturn', O.NONE, 1, 0, F.RETURN | F.END | F.TRAPS, T, 'branch', ''],
  [0xb1, 'return', O.NONE, 0, 0, F.RETURN | F.END | F.TRAPS, T, 'branch', ''],
  [0xb2, 'getstatic', O.CP16, 0, 1, F.LOAD | F.TRAPS, R, 'object', ''],
  [0xb3, 'putstatic', O.CP16, 1, 0, F.STORE | F.TRAPS, R, 'object', ''],
  [0xb4, 'getfield', O.CP16, 1, 1, F.LOAD | F.TRAPS, R, 'object', ''],
  [0xb5, 'putfield', O.CP16, 2, 0, F.STORE | F.TRAPS, R, 'object', ''],
  [0xb6, 'invokevirtual', O.CP16, -1, -1, F.CALL | F.TRAPS, R, 'call', ''],
  [0xb7, 'invokespecial', O.CP16, -1, -1, F.CALL | F.TRAPS, R, 'call', ''],
  [0xb8, 'invokestatic', O.CP16, -1, -1, F.CALL | F.TRAPS, R, 'call', ''],
  [0xb9, 'invokeinterface', O.INTERFACE, -1, -1, F.CALL | F.TRAPS, R, 'call', ''],
  [0xba, 'invokedynamic', O.DYNAMIC, -1, -1, F.CALL | F.TRAPS, R, 'call', ''],
  [0xbb, 'new', O.CP16, 0, 1, F.TRAPS, R, 'object', 'a'],
  [0xbc, 'newarray', O.ATYPE, 1, 1, F.TRAPS, R, 'array', 'a'],
  [0xbd, 'anewarray', O.CP16, 1, 1, F.TRAPS, R, 'array', 'a'],
  [0xbe, 'arraylength', O.NONE, 1, 1, F.TRAPS, R, 'array', 'i'],
  [0xbf, 'athrow', O.NONE, 1, 0, F.THROW | F.END | F.TRAPS, R, 'exception', ''],
  [0xc0, 'checkcast', O.CP16, 1, 1, F.TRAPS, R, 'object', 'a'],
  [0xc1, 'instanceof', O.CP16, 1, 1, F.TRAPS, R, 'object', 'i'],
  [0xc2, 'monitorenter', O.NONE, 1, 0, F.TRAPS, R, 'system', ''],
  [0xc3, 'monitorexit', O.NONE, 1, 0, F.TRAPS, R, 'system', ''],
  [0xc5, 'multianewarray', O.DIMENSIONS, -1, 1, F.TRAPS, X, 'array', 'a'],
  [0xc6, 'ifnull', O.BRANCH16, 1, 0, IF, X, 'branch', ''],
  [0xc7, 'ifnonnull', O.BRANCH16, 1, 0, IF, X, 'branch', ''],
  [0xc8, 'goto_w', O.BRANCH32, 0, 0, F.BRANCH | F.END, X, 'branch', ''],
  [0xc9, 'jsr_w', O.JSR32, 0, 1, F.BRANCH | F.SUBROUTINE, X, 'branch', 'r'],
  // The wide forms: 0xC4 and the opcode they widen.
  [0xc415, 'iload_w', O.LOCAL_W, 0, 1, 0, X, 'variable', 'i'],
  [0xc416, 'lload_w', O.LOCAL_W, 0, 1, 0, X, 'variable', 'l'],
  [0xc417, 'fload_w', O.LOCAL_W, 0, 1, 0, X, 'variable', 'f'],
  [0xc418, 'dload_w', O.LOCAL_W, 0, 1, 0, X, 'variable', 'd'],
  [0xc419, 'aload_w', O.LOCAL_W, 0, 1, 0, X, 'variable', 'a'],
  [0xc436, 'istore_w', O.LOCAL_W, 1, 0, 0, X, 'variable', ''],
  [0xc437, 'lstore_w', O.LOCAL_W, 1, 0, 0, X, 'variable', ''],
  [0xc438, 'fstore_w', O.LOCAL_W, 1, 0, 0, X, 'variable', ''],
  [0xc439, 'dstore_w', O.LOCAL_W, 1, 0, 0, X, 'variable', ''],
  [0xc43a, 'astore_w', O.LOCAL_W, 1, 0, 0, X, 'variable', ''],
  [0xc484, 'iinc_w', O.IINC_W, 0, 0, 0, X, 'arithmetic', ''],
  [0xc4a9, 'ret_w', O.RET_W, 0, 0, F.END | F.SUBROUTINE, X, 'branch', ''],
];

/** Opcodes by their byte; the wide forms by the byte they widen. */
export const ONE = new Array<OpInfo | undefined>(256);
export const WIDE = new Array<OpInfo | undefined>(256);
const ALL: OpInfo[] = [];

for (const [code, name, operand, pop, push, flags, group, category, kind] of ROWS) {
  const op: OpInfo = { name, code, operand, pop, push, flags, group, category, kind };
  ALL.push(op);
  if (code > 0xff) WIDE[code & 0xff] = op;
  else ONE[code] = op;
}

export function allOps(): readonly OpInfo[] {
  return ALL;
}

/** The opcode as the bytes it is written with: `B6`, `C4 15`. */
export function opcodeText(code: number): string {
  const hex = (b: number) => b.toString(16).toUpperCase().padStart(2, '0');
  return code > 0xff ? `C4 ${hex(code & 0xff)}` : hex(code);
}

/** newarray's element types, by its operand. */
export const ATYPES: Record<number, string> = { 4: 'boolean', 5: 'char', 6: 'float', 7: 'double', 8: 'byte', 9: 'short', 10: 'int', 11: 'long' };
