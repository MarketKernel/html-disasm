/**
 * What an instruction takes from the evaluation stack and leaves on it, for
 * the HLA64 view: the analysis (src/core/cil/program.ts) groups the
 * instructions that make one statement by it, and the lifting
 * (src/core/cil/hla.ts) evaluates them with it. Most opcodes say so in their
 * table; a call, newobj and ret depend on the signature of what they call or
 * return from.
 */

import type { CilInsn } from './decode';
import { decodeIndex, TABLE, tokenRow, tokenTable, type Metadata } from './metadata';
import { OPERAND } from './opcodes';

/** A method signature's shape: whether it has `this`, how many parameters, whether it returns a value. */
export interface Shape {
  instance: boolean;
  params: number;
  returns: boolean;
}

/** The shape of a method signature blob (MethodDefSig, MethodRefSig, StandAloneMethodSig). */
export function shapeOf(blob: Uint8Array): Shape {
  let p = 0;
  const conv = blob[p++] ?? 0;
  const u = () => {
    const b = blob[p] ?? 0;
    if ((b & 0x80) === 0) return (p += 1), b;
    if ((b & 0xc0) === 0x80) return (p += 2), ((b & 0x3f) << 8) | (blob[p - 1] ?? 0);
    p += 4;
    return ((b & 0x1f) << 24) | ((blob[p - 3] ?? 0) << 16) | ((blob[p - 2] ?? 0) << 8) | (blob[p - 1] ?? 0);
  };
  if (conv & 0x10) u();
  const params = u();
  // The return type: custom modifiers, then void (0x01) or anything else.
  while (blob[p] === 0x1f || blob[p] === 0x20) {
    p++;
    u();
  }
  return { instance: !!(conv & 0x20) && !(conv & 0x40), params, returns: blob[p] !== 0x01 };
}

/** The signature blob of a method token (through a MethodSpec to its method). */
export function methodBlob(md: Metadata, tok: number): Uint8Array {
  let table = tokenTable(tok);
  let row = tokenRow(tok);
  if (table === TABLE.MethodSpec) {
    const target = decodeIndex('MethodDefOrRef', md.table(TABLE.MethodSpec).get(row, 'Method'));
    table = target.table;
    row = target.row;
  }
  if (table === TABLE.MethodDef) return md.blob(md.table(TABLE.MethodDef).get(row, 'Signature'));
  if (table === TABLE.MemberRef) return md.blob(md.table(TABLE.MemberRef).get(row, 'Signature'));
  return new Uint8Array(0);
}

/** Shapes of the method tokens seen so far, and of the method being read (for ret). */
export class Effects {
  private readonly shapes = new Map<number, Shape>();
  /** The method the instructions are in returns a value. */
  returns = false;

  constructor(readonly md: Metadata) {}

  shape(tok: number): Shape {
    let shape = this.shapes.get(tok);
    if (!shape) {
      const blob = tokenTable(tok) === TABLE.StandAloneSig ? this.md.blob(this.md.table(TABLE.StandAloneSig).get(tokenRow(tok), 'Signature')) : methodBlob(this.md, tok);
      shape = shapeOf(blob);
      this.shapes.set(tok, shape);
    }
    return shape;
  }

  /** [pops, pushes] of an instruction, or null when it cannot be known (an opcode that is not one). */
  of(insn: CilInsn): [number, number] | null {
    const op = insn.op;
    if (!op) return null;
    switch (op.name) {
      case 'call':
      case 'callvirt': {
        const s = this.shape(insn.a);
        return [s.params + (s.instance ? 1 : 0), s.returns ? 1 : 0];
      }
      case 'newobj':
        return [this.shape(insn.a).params, 1];
      case 'calli': {
        const s = this.shape(insn.a);
        return [s.params + (s.instance ? 1 : 0) + 1, s.returns ? 1 : 0];
      }
      case 'ret':
        return [this.returns ? 1 : 0, 0];
      case 'jmp':
        return [0, 0];
    }
    if (op.operand === OPERAND.METHOD && op.pop < 0) return null;
    return [op.pop, op.push];
  }
}
