/**
 * The CIL opcodes of ECMA-335 (Partition III): a byte, or 0xFE and a byte,
 * then the operand its kind says. Each opcode has what it takes from the
 * evaluation stack and what it leaves there, as the standard's tables give
 * them (`-1`: it depends on the signature of the call or the return), and
 * flags for the analysis and the colours of the listing. The descriptions
 * are in src/data/cil-instructions.json.
 */

/** The kinds of operand an opcode is followed by. */
export const OPERAND = {
  NONE: 0,
  /** An argument or local number: one byte (ShortInlineVar) or two (InlineVar). */
  VAR8: 1,
  VAR16: 2,
  /** A signed byte (ldc.i4.s) or an unsigned one (unaligned., no.). */
  I8: 3,
  U8: 4,
  I32: 5,
  I64: 6,
  R4: 7,
  R8: 8,
  /** A branch offset from the next instruction: one signed byte or four. */
  BR8: 9,
  BR32: 10,
  /** A count of four-byte branch offsets. */
  SWITCH: 11,
  /** Metadata tokens: a method, a field, a type, a #US string, a stand-alone signature, any of the first three. */
  METHOD: 12,
  FIELD: 13,
  TYPE: 14,
  STRING: 15,
  SIG: 16,
  TOKEN: 17,
} as const;

/** Bits of OpInfo.flags. */
export const F = {
  BRANCH: 1,
  CONDITIONAL: 2,
  CALL: 4,
  RETURN: 8,
  THROW: 16,
  PREFIX: 32,
  /** Ends a block of code: nothing after it runs unless something branches there. */
  END: 64,
  LOAD: 128,
  STORE: 256,
  COMPARE: 512,
  /** Can throw on its own (overflow, a null reference, a bad cast, an index out of range). */
  TRAPS: 1024,
} as const;

export interface OpInfo {
  name: string;
  /** 0x00–0xE0, or 0xFE00–0xFE1E. */
  code: number;
  operand: number;
  /** Values taken from and pushed on the stack; -1 when the operand's signature says. */
  pop: number;
  push: number;
  flags: number;
  group: 'il-base' | 'il-object' | 'il-prefix';
  category: string;
}

const O = OPERAND;
const B = 'il-base';
const OB = 'il-object';
const P = 'il-prefix';

type Row = [code: number, name: string, operand: number, pop: number, push: number, flags: number, group: OpInfo['group'], category: string];

const ROWS: Row[] = [
  [0x00, 'nop', O.NONE, 0, 0, 0, B, 'other'],
  [0x01, 'break', O.NONE, 0, 0, 0, B, 'system'],
  [0x02, 'ldarg.0', O.NONE, 0, 1, 0, B, 'variable'],
  [0x03, 'ldarg.1', O.NONE, 0, 1, 0, B, 'variable'],
  [0x04, 'ldarg.2', O.NONE, 0, 1, 0, B, 'variable'],
  [0x05, 'ldarg.3', O.NONE, 0, 1, 0, B, 'variable'],
  [0x06, 'ldloc.0', O.NONE, 0, 1, 0, B, 'variable'],
  [0x07, 'ldloc.1', O.NONE, 0, 1, 0, B, 'variable'],
  [0x08, 'ldloc.2', O.NONE, 0, 1, 0, B, 'variable'],
  [0x09, 'ldloc.3', O.NONE, 0, 1, 0, B, 'variable'],
  [0x0a, 'stloc.0', O.NONE, 1, 0, 0, B, 'variable'],
  [0x0b, 'stloc.1', O.NONE, 1, 0, 0, B, 'variable'],
  [0x0c, 'stloc.2', O.NONE, 1, 0, 0, B, 'variable'],
  [0x0d, 'stloc.3', O.NONE, 1, 0, 0, B, 'variable'],
  [0x0e, 'ldarg.s', O.VAR8, 0, 1, 0, B, 'variable'],
  [0x0f, 'ldarga.s', O.VAR8, 0, 1, 0, B, 'variable'],
  [0x10, 'starg.s', O.VAR8, 1, 0, 0, B, 'variable'],
  [0x11, 'ldloc.s', O.VAR8, 0, 1, 0, B, 'variable'],
  [0x12, 'ldloca.s', O.VAR8, 0, 1, 0, B, 'variable'],
  [0x13, 'stloc.s', O.VAR8, 1, 0, 0, B, 'variable'],
  [0x14, 'ldnull', O.NONE, 0, 1, 0, B, 'constant'],
  [0x15, 'ldc.i4.m1', O.NONE, 0, 1, 0, B, 'constant'],
  [0x16, 'ldc.i4.0', O.NONE, 0, 1, 0, B, 'constant'],
  [0x17, 'ldc.i4.1', O.NONE, 0, 1, 0, B, 'constant'],
  [0x18, 'ldc.i4.2', O.NONE, 0, 1, 0, B, 'constant'],
  [0x19, 'ldc.i4.3', O.NONE, 0, 1, 0, B, 'constant'],
  [0x1a, 'ldc.i4.4', O.NONE, 0, 1, 0, B, 'constant'],
  [0x1b, 'ldc.i4.5', O.NONE, 0, 1, 0, B, 'constant'],
  [0x1c, 'ldc.i4.6', O.NONE, 0, 1, 0, B, 'constant'],
  [0x1d, 'ldc.i4.7', O.NONE, 0, 1, 0, B, 'constant'],
  [0x1e, 'ldc.i4.8', O.NONE, 0, 1, 0, B, 'constant'],
  [0x1f, 'ldc.i4.s', O.I8, 0, 1, 0, B, 'constant'],
  [0x20, 'ldc.i4', O.I32, 0, 1, 0, B, 'constant'],
  [0x21, 'ldc.i8', O.I64, 0, 1, 0, B, 'constant'],
  [0x22, 'ldc.r4', O.R4, 0, 1, 0, B, 'constant'],
  [0x23, 'ldc.r8', O.R8, 0, 1, 0, B, 'constant'],
  [0x25, 'dup', O.NONE, 1, 2, 0, B, 'stack'],
  [0x26, 'pop', O.NONE, 1, 0, 0, B, 'stack'],
  [0x27, 'jmp', O.METHOD, 0, 0, F.CALL | F.END, B, 'call'],
  [0x28, 'call', O.METHOD, -1, -1, F.CALL, B, 'call'],
  [0x29, 'calli', O.SIG, -1, -1, F.CALL, B, 'call'],
  [0x2a, 'ret', O.NONE, -1, 0, F.RETURN | F.END, B, 'branch'],
  [0x2b, 'br.s', O.BR8, 0, 0, F.BRANCH | F.END, B, 'branch'],
  [0x2c, 'brfalse.s', O.BR8, 1, 0, F.BRANCH | F.CONDITIONAL, B, 'branch'],
  [0x2d, 'brtrue.s', O.BR8, 1, 0, F.BRANCH | F.CONDITIONAL, B, 'branch'],
  [0x2e, 'beq.s', O.BR8, 2, 0, F.BRANCH | F.CONDITIONAL, B, 'branch'],
  [0x2f, 'bge.s', O.BR8, 2, 0, F.BRANCH | F.CONDITIONAL, B, 'branch'],
  [0x30, 'bgt.s', O.BR8, 2, 0, F.BRANCH | F.CONDITIONAL, B, 'branch'],
  [0x31, 'ble.s', O.BR8, 2, 0, F.BRANCH | F.CONDITIONAL, B, 'branch'],
  [0x32, 'blt.s', O.BR8, 2, 0, F.BRANCH | F.CONDITIONAL, B, 'branch'],
  [0x33, 'bne.un.s', O.BR8, 2, 0, F.BRANCH | F.CONDITIONAL, B, 'branch'],
  [0x34, 'bge.un.s', O.BR8, 2, 0, F.BRANCH | F.CONDITIONAL, B, 'branch'],
  [0x35, 'bgt.un.s', O.BR8, 2, 0, F.BRANCH | F.CONDITIONAL, B, 'branch'],
  [0x36, 'ble.un.s', O.BR8, 2, 0, F.BRANCH | F.CONDITIONAL, B, 'branch'],
  [0x37, 'blt.un.s', O.BR8, 2, 0, F.BRANCH | F.CONDITIONAL, B, 'branch'],
  [0x38, 'br', O.BR32, 0, 0, F.BRANCH | F.END, B, 'branch'],
  [0x39, 'brfalse', O.BR32, 1, 0, F.BRANCH | F.CONDITIONAL, B, 'branch'],
  [0x3a, 'brtrue', O.BR32, 1, 0, F.BRANCH | F.CONDITIONAL, B, 'branch'],
  [0x3b, 'beq', O.BR32, 2, 0, F.BRANCH | F.CONDITIONAL, B, 'branch'],
  [0x3c, 'bge', O.BR32, 2, 0, F.BRANCH | F.CONDITIONAL, B, 'branch'],
  [0x3d, 'bgt', O.BR32, 2, 0, F.BRANCH | F.CONDITIONAL, B, 'branch'],
  [0x3e, 'ble', O.BR32, 2, 0, F.BRANCH | F.CONDITIONAL, B, 'branch'],
  [0x3f, 'blt', O.BR32, 2, 0, F.BRANCH | F.CONDITIONAL, B, 'branch'],
  [0x40, 'bne.un', O.BR32, 2, 0, F.BRANCH | F.CONDITIONAL, B, 'branch'],
  [0x41, 'bge.un', O.BR32, 2, 0, F.BRANCH | F.CONDITIONAL, B, 'branch'],
  [0x42, 'bgt.un', O.BR32, 2, 0, F.BRANCH | F.CONDITIONAL, B, 'branch'],
  [0x43, 'ble.un', O.BR32, 2, 0, F.BRANCH | F.CONDITIONAL, B, 'branch'],
  [0x44, 'blt.un', O.BR32, 2, 0, F.BRANCH | F.CONDITIONAL, B, 'branch'],
  [0x45, 'switch', O.SWITCH, 1, 0, F.BRANCH | F.CONDITIONAL, B, 'branch'],
  [0x46, 'ldind.i1', O.NONE, 1, 1, F.LOAD | F.TRAPS, B, 'load'],
  [0x47, 'ldind.u1', O.NONE, 1, 1, F.LOAD | F.TRAPS, B, 'load'],
  [0x48, 'ldind.i2', O.NONE, 1, 1, F.LOAD | F.TRAPS, B, 'load'],
  [0x49, 'ldind.u2', O.NONE, 1, 1, F.LOAD | F.TRAPS, B, 'load'],
  [0x4a, 'ldind.i4', O.NONE, 1, 1, F.LOAD | F.TRAPS, B, 'load'],
  [0x4b, 'ldind.u4', O.NONE, 1, 1, F.LOAD | F.TRAPS, B, 'load'],
  [0x4c, 'ldind.i8', O.NONE, 1, 1, F.LOAD | F.TRAPS, B, 'load'],
  [0x4d, 'ldind.i', O.NONE, 1, 1, F.LOAD | F.TRAPS, B, 'load'],
  [0x4e, 'ldind.r4', O.NONE, 1, 1, F.LOAD | F.TRAPS, B, 'load'],
  [0x4f, 'ldind.r8', O.NONE, 1, 1, F.LOAD | F.TRAPS, B, 'load'],
  [0x50, 'ldind.ref', O.NONE, 1, 1, F.LOAD | F.TRAPS, B, 'load'],
  [0x51, 'stind.ref', O.NONE, 2, 0, F.STORE | F.TRAPS, B, 'store'],
  [0x52, 'stind.i1', O.NONE, 2, 0, F.STORE | F.TRAPS, B, 'store'],
  [0x53, 'stind.i2', O.NONE, 2, 0, F.STORE | F.TRAPS, B, 'store'],
  [0x54, 'stind.i4', O.NONE, 2, 0, F.STORE | F.TRAPS, B, 'store'],
  [0x55, 'stind.i8', O.NONE, 2, 0, F.STORE | F.TRAPS, B, 'store'],
  [0x56, 'stind.r4', O.NONE, 2, 0, F.STORE | F.TRAPS, B, 'store'],
  [0x57, 'stind.r8', O.NONE, 2, 0, F.STORE | F.TRAPS, B, 'store'],
  [0x58, 'add', O.NONE, 2, 1, 0, B, 'arithmetic'],
  [0x59, 'sub', O.NONE, 2, 1, 0, B, 'arithmetic'],
  [0x5a, 'mul', O.NONE, 2, 1, 0, B, 'arithmetic'],
  [0x5b, 'div', O.NONE, 2, 1, F.TRAPS, B, 'arithmetic'],
  [0x5c, 'div.un', O.NONE, 2, 1, F.TRAPS, B, 'arithmetic'],
  [0x5d, 'rem', O.NONE, 2, 1, F.TRAPS, B, 'arithmetic'],
  [0x5e, 'rem.un', O.NONE, 2, 1, F.TRAPS, B, 'arithmetic'],
  [0x5f, 'and', O.NONE, 2, 1, 0, B, 'logic'],
  [0x60, 'or', O.NONE, 2, 1, 0, B, 'logic'],
  [0x61, 'xor', O.NONE, 2, 1, 0, B, 'logic'],
  [0x62, 'shl', O.NONE, 2, 1, 0, B, 'shift'],
  [0x63, 'shr', O.NONE, 2, 1, 0, B, 'shift'],
  [0x64, 'shr.un', O.NONE, 2, 1, 0, B, 'shift'],
  [0x65, 'neg', O.NONE, 1, 1, 0, B, 'arithmetic'],
  [0x66, 'not', O.NONE, 1, 1, 0, B, 'logic'],
  [0x67, 'conv.i1', O.NONE, 1, 1, 0, B, 'conversion'],
  [0x68, 'conv.i2', O.NONE, 1, 1, 0, B, 'conversion'],
  [0x69, 'conv.i4', O.NONE, 1, 1, 0, B, 'conversion'],
  [0x6a, 'conv.i8', O.NONE, 1, 1, 0, B, 'conversion'],
  [0x6b, 'conv.r4', O.NONE, 1, 1, 0, B, 'conversion'],
  [0x6c, 'conv.r8', O.NONE, 1, 1, 0, B, 'conversion'],
  [0x6d, 'conv.u4', O.NONE, 1, 1, 0, B, 'conversion'],
  [0x6e, 'conv.u8', O.NONE, 1, 1, 0, B, 'conversion'],
  [0x6f, 'callvirt', O.METHOD, -1, -1, F.CALL | F.TRAPS, OB, 'call'],
  [0x70, 'cpobj', O.TYPE, 2, 0, F.LOAD | F.STORE | F.TRAPS, OB, 'object'],
  [0x71, 'ldobj', O.TYPE, 1, 1, F.LOAD | F.TRAPS, OB, 'object'],
  [0x72, 'ldstr', O.STRING, 0, 1, 0, OB, 'constant'],
  [0x73, 'newobj', O.METHOD, -1, 1, F.CALL, OB, 'object'],
  [0x74, 'castclass', O.TYPE, 1, 1, F.TRAPS, OB, 'object'],
  [0x75, 'isinst', O.TYPE, 1, 1, 0, OB, 'object'],
  [0x76, 'conv.r.un', O.NONE, 1, 1, 0, B, 'conversion'],
  [0x79, 'unbox', O.TYPE, 1, 1, F.TRAPS, OB, 'object'],
  [0x7a, 'throw', O.NONE, 1, 0, F.THROW | F.END, OB, 'exception'],
  [0x7b, 'ldfld', O.FIELD, 1, 1, F.LOAD | F.TRAPS, OB, 'object'],
  [0x7c, 'ldflda', O.FIELD, 1, 1, F.TRAPS, OB, 'object'],
  [0x7d, 'stfld', O.FIELD, 2, 0, F.STORE | F.TRAPS, OB, 'object'],
  [0x7e, 'ldsfld', O.FIELD, 0, 1, F.LOAD, OB, 'object'],
  [0x7f, 'ldsflda', O.FIELD, 0, 1, 0, OB, 'object'],
  [0x80, 'stsfld', O.FIELD, 1, 0, F.STORE, OB, 'object'],
  [0x81, 'stobj', O.TYPE, 2, 0, F.STORE | F.TRAPS, OB, 'object'],
  [0x82, 'conv.ovf.i1.un', O.NONE, 1, 1, F.TRAPS, B, 'conversion'],
  [0x83, 'conv.ovf.i2.un', O.NONE, 1, 1, F.TRAPS, B, 'conversion'],
  [0x84, 'conv.ovf.i4.un', O.NONE, 1, 1, F.TRAPS, B, 'conversion'],
  [0x85, 'conv.ovf.i8.un', O.NONE, 1, 1, F.TRAPS, B, 'conversion'],
  [0x86, 'conv.ovf.u1.un', O.NONE, 1, 1, F.TRAPS, B, 'conversion'],
  [0x87, 'conv.ovf.u2.un', O.NONE, 1, 1, F.TRAPS, B, 'conversion'],
  [0x88, 'conv.ovf.u4.un', O.NONE, 1, 1, F.TRAPS, B, 'conversion'],
  [0x89, 'conv.ovf.u8.un', O.NONE, 1, 1, F.TRAPS, B, 'conversion'],
  [0x8a, 'conv.ovf.i.un', O.NONE, 1, 1, F.TRAPS, B, 'conversion'],
  [0x8b, 'conv.ovf.u.un', O.NONE, 1, 1, F.TRAPS, B, 'conversion'],
  [0x8c, 'box', O.TYPE, 1, 1, 0, OB, 'object'],
  [0x8d, 'newarr', O.TYPE, 1, 1, F.TRAPS, OB, 'array'],
  [0x8e, 'ldlen', O.NONE, 1, 1, F.TRAPS, OB, 'array'],
  [0x8f, 'ldelema', O.TYPE, 2, 1, F.TRAPS, OB, 'array'],
  [0x90, 'ldelem.i1', O.NONE, 2, 1, F.LOAD | F.TRAPS, OB, 'array'],
  [0x91, 'ldelem.u1', O.NONE, 2, 1, F.LOAD | F.TRAPS, OB, 'array'],
  [0x92, 'ldelem.i2', O.NONE, 2, 1, F.LOAD | F.TRAPS, OB, 'array'],
  [0x93, 'ldelem.u2', O.NONE, 2, 1, F.LOAD | F.TRAPS, OB, 'array'],
  [0x94, 'ldelem.i4', O.NONE, 2, 1, F.LOAD | F.TRAPS, OB, 'array'],
  [0x95, 'ldelem.u4', O.NONE, 2, 1, F.LOAD | F.TRAPS, OB, 'array'],
  [0x96, 'ldelem.i8', O.NONE, 2, 1, F.LOAD | F.TRAPS, OB, 'array'],
  [0x97, 'ldelem.i', O.NONE, 2, 1, F.LOAD | F.TRAPS, OB, 'array'],
  [0x98, 'ldelem.r4', O.NONE, 2, 1, F.LOAD | F.TRAPS, OB, 'array'],
  [0x99, 'ldelem.r8', O.NONE, 2, 1, F.LOAD | F.TRAPS, OB, 'array'],
  [0x9a, 'ldelem.ref', O.NONE, 2, 1, F.LOAD | F.TRAPS, OB, 'array'],
  [0x9b, 'stelem.i', O.NONE, 3, 0, F.STORE | F.TRAPS, OB, 'array'],
  [0x9c, 'stelem.i1', O.NONE, 3, 0, F.STORE | F.TRAPS, OB, 'array'],
  [0x9d, 'stelem.i2', O.NONE, 3, 0, F.STORE | F.TRAPS, OB, 'array'],
  [0x9e, 'stelem.i4', O.NONE, 3, 0, F.STORE | F.TRAPS, OB, 'array'],
  [0x9f, 'stelem.i8', O.NONE, 3, 0, F.STORE | F.TRAPS, OB, 'array'],
  [0xa0, 'stelem.r4', O.NONE, 3, 0, F.STORE | F.TRAPS, OB, 'array'],
  [0xa1, 'stelem.r8', O.NONE, 3, 0, F.STORE | F.TRAPS, OB, 'array'],
  [0xa2, 'stelem.ref', O.NONE, 3, 0, F.STORE | F.TRAPS, OB, 'array'],
  [0xa3, 'ldelem', O.TYPE, 2, 1, F.LOAD | F.TRAPS, OB, 'array'],
  [0xa4, 'stelem', O.TYPE, 3, 0, F.STORE | F.TRAPS, OB, 'array'],
  [0xa5, 'unbox.any', O.TYPE, 1, 1, F.TRAPS, OB, 'object'],
  [0xb3, 'conv.ovf.i1', O.NONE, 1, 1, F.TRAPS, B, 'conversion'],
  [0xb4, 'conv.ovf.u1', O.NONE, 1, 1, F.TRAPS, B, 'conversion'],
  [0xb5, 'conv.ovf.i2', O.NONE, 1, 1, F.TRAPS, B, 'conversion'],
  [0xb6, 'conv.ovf.u2', O.NONE, 1, 1, F.TRAPS, B, 'conversion'],
  [0xb7, 'conv.ovf.i4', O.NONE, 1, 1, F.TRAPS, B, 'conversion'],
  [0xb8, 'conv.ovf.u4', O.NONE, 1, 1, F.TRAPS, B, 'conversion'],
  [0xb9, 'conv.ovf.i8', O.NONE, 1, 1, F.TRAPS, B, 'conversion'],
  [0xba, 'conv.ovf.u8', O.NONE, 1, 1, F.TRAPS, B, 'conversion'],
  [0xc2, 'refanyval', O.TYPE, 1, 1, F.TRAPS, OB, 'object'],
  [0xc3, 'ckfinite', O.NONE, 1, 1, F.TRAPS, B, 'arithmetic'],
  [0xc6, 'mkrefany', O.TYPE, 1, 1, 0, OB, 'object'],
  [0xd0, 'ldtoken', O.TOKEN, 0, 1, 0, OB, 'constant'],
  [0xd1, 'conv.u2', O.NONE, 1, 1, 0, B, 'conversion'],
  [0xd2, 'conv.u1', O.NONE, 1, 1, 0, B, 'conversion'],
  [0xd3, 'conv.i', O.NONE, 1, 1, 0, B, 'conversion'],
  [0xd4, 'conv.ovf.i', O.NONE, 1, 1, F.TRAPS, B, 'conversion'],
  [0xd5, 'conv.ovf.u', O.NONE, 1, 1, F.TRAPS, B, 'conversion'],
  [0xd6, 'add.ovf', O.NONE, 2, 1, F.TRAPS, B, 'arithmetic'],
  [0xd7, 'add.ovf.un', O.NONE, 2, 1, F.TRAPS, B, 'arithmetic'],
  [0xd8, 'mul.ovf', O.NONE, 2, 1, F.TRAPS, B, 'arithmetic'],
  [0xd9, 'mul.ovf.un', O.NONE, 2, 1, F.TRAPS, B, 'arithmetic'],
  [0xda, 'sub.ovf', O.NONE, 2, 1, F.TRAPS, B, 'arithmetic'],
  [0xdb, 'sub.ovf.un', O.NONE, 2, 1, F.TRAPS, B, 'arithmetic'],
  [0xdc, 'endfinally', O.NONE, 0, 0, F.END, B, 'exception'],
  [0xdd, 'leave', O.BR32, 0, 0, F.BRANCH | F.END, B, 'exception'],
  [0xde, 'leave.s', O.BR8, 0, 0, F.BRANCH | F.END, B, 'exception'],
  [0xdf, 'stind.i', O.NONE, 2, 0, F.STORE | F.TRAPS, B, 'store'],
  [0xe0, 'conv.u', O.NONE, 1, 1, 0, B, 'conversion'],
  [0xfe00, 'arglist', O.NONE, 0, 1, 0, B, 'variable'],
  [0xfe01, 'ceq', O.NONE, 2, 1, F.COMPARE, B, 'compare'],
  [0xfe02, 'cgt', O.NONE, 2, 1, F.COMPARE, B, 'compare'],
  [0xfe03, 'cgt.un', O.NONE, 2, 1, F.COMPARE, B, 'compare'],
  [0xfe04, 'clt', O.NONE, 2, 1, F.COMPARE, B, 'compare'],
  [0xfe05, 'clt.un', O.NONE, 2, 1, F.COMPARE, B, 'compare'],
  [0xfe06, 'ldftn', O.METHOD, 0, 1, 0, B, 'call'],
  [0xfe07, 'ldvirtftn', O.METHOD, 1, 1, F.TRAPS, OB, 'call'],
  [0xfe09, 'ldarg', O.VAR16, 0, 1, 0, B, 'variable'],
  [0xfe0a, 'ldarga', O.VAR16, 0, 1, 0, B, 'variable'],
  [0xfe0b, 'starg', O.VAR16, 1, 0, 0, B, 'variable'],
  [0xfe0c, 'ldloc', O.VAR16, 0, 1, 0, B, 'variable'],
  [0xfe0d, 'ldloca', O.VAR16, 0, 1, 0, B, 'variable'],
  [0xfe0e, 'stloc', O.VAR16, 1, 0, 0, B, 'variable'],
  [0xfe0f, 'localloc', O.NONE, 1, 1, F.TRAPS, B, 'stack'],
  [0xfe11, 'endfilter', O.NONE, 1, 0, F.END, B, 'exception'],
  [0xfe12, 'unaligned.', O.U8, 0, 0, F.PREFIX, P, 'prefix'],
  [0xfe13, 'volatile.', O.NONE, 0, 0, F.PREFIX, P, 'prefix'],
  [0xfe14, 'tail.', O.NONE, 0, 0, F.PREFIX, P, 'prefix'],
  [0xfe15, 'initobj', O.TYPE, 1, 0, F.STORE | F.TRAPS, OB, 'object'],
  [0xfe16, 'constrained.', O.TYPE, 0, 0, F.PREFIX, P, 'prefix'],
  [0xfe17, 'cpblk', O.NONE, 3, 0, F.LOAD | F.STORE | F.TRAPS, B, 'memory-copy'],
  [0xfe18, 'initblk', O.NONE, 3, 0, F.STORE | F.TRAPS, B, 'memory-copy'],
  [0xfe19, 'no.', O.U8, 0, 0, F.PREFIX, P, 'prefix'],
  [0xfe1a, 'rethrow', O.NONE, 0, 0, F.THROW | F.END, OB, 'exception'],
  [0xfe1c, 'sizeof', O.TYPE, 0, 1, 0, OB, 'object'],
  [0xfe1d, 'refanytype', O.NONE, 1, 1, 0, OB, 'object'],
  [0xfe1e, 'readonly.', O.NONE, 0, 0, F.PREFIX, P, 'prefix'],
];

/** One-byte opcodes by their byte; two-byte ones (0xFE xx) by the second byte. */
export const ONE = new Array<OpInfo | undefined>(256);
export const TWO = new Array<OpInfo | undefined>(256);
const ALL: OpInfo[] = [];

for (const [code, name, operand, pop, push, flags, group, category] of ROWS) {
  const op: OpInfo = { name, code, operand, pop, push, flags, group, category };
  ALL.push(op);
  if (code > 0xff) TWO[code & 0xff] = op;
  else ONE[code] = op;
}

export function allOps(): readonly OpInfo[] {
  return ALL;
}

/** The opcode as the bytes it is written with: `72`, `FE 06`. */
export function opcodeText(code: number): string {
  return code > 0xff ? `FE ${(code & 0xff).toString(16).toUpperCase().padStart(2, '0')}` : code.toString(16).toUpperCase().padStart(2, '0');
}

