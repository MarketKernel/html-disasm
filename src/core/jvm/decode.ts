/**
 * JVM instructions: decoded from a method's Code and printed as javap -c
 * prints them — the mnemonic padded to thirteen columns, then the operand: a
 * local's slot, a constant, a branch's target pc, a constant pool index
 * (`#7`) with what it names after `//` (`Field java/lang/System.out:…`), a
 * switch's cases. javap writes a switch on several lines; here it is one, the
 * lines joined by spaces. `tools/verify-jvm.mjs` compares the text with
 * javap's.
 */

import { ClassFile, constantComment } from './classfile';
import { ATYPES, ONE, OPERAND, WIDE, type OpInfo } from './opcodes';

/** A decoded instruction; one object is reused while a method is read. */
export class JvmInsn {
  op: OpInfo | undefined = undefined;
  /** Its pc (offset in the method's code), and its length in bytes. */
  at = 0;
  len = 1;
  /** The mnemonic (`.byte` for a byte that is not an opcode, or one whose operands run past the code). */
  m = '';
  /** A slot, a constant, a constant pool index, a branch's target pc, an array type, a switch's default target. */
  a = 0;
  /** iinc's constant, invokeinterface's count, multianewarray's dimensions. */
  b = 0;
  /** A switch: the value of each case and where it goes (pcs), in the order of the instruction. */
  keys: number[] | null = null;
  targets: number[] | null = null;
}

/** Decodes the instruction at `pos` of a method whose code is `bytes[start, end)`. */
export function decodeAt(bytes: Uint8Array, start: number, pos: number, end: number, into = new JvmInsn()): JvmInsn {
  const insn = into;
  const pc = pos - start;
  insn.at = pc;
  insn.a = 0;
  insn.b = 0;
  insn.keys = null;
  insn.targets = null;
  const first = bytes[pos]!;
  let op: OpInfo | undefined;
  let p = pos + 1;
  if (first === 0xc4) {
    op = pos + 1 < end ? WIDE[bytes[pos + 1]!] : undefined;
    p = pos + 2;
  } else op = ONE[first];
  if (!op) return unknown(insn, first);
  // Big-endian reads without a DataView: one would be made for every instruction.
  const u2 = (at: number) => (bytes[at]! << 8) | bytes[at + 1]!;
  const s4 = (at: number) => (bytes[at]! << 24) | (bytes[at + 1]! << 16) | (bytes[at + 2]! << 8) | bytes[at + 3]!;
  const s1 = (at: number) => (bytes[at]! << 24) >> 24;
  const s2 = (at: number) => (u2(at) << 16) >> 16;
  const need = (n: number) => p + n <= end;
  insn.op = op;
  insn.m = op.name;
  switch (op.operand) {
    case OPERAND.NONE:
      break;
    case OPERAND.LOCAL:
    case OPERAND.RET:
    case OPERAND.CP8:
    case OPERAND.ATYPE:
      if (!need(1)) return unknown(insn, first);
      insn.a = bytes[p]!;
      p += 1;
      break;
    case OPERAND.BYTE:
      if (!need(1)) return unknown(insn, first);
      insn.a = s1(p);
      p += 1;
      break;
    case OPERAND.LOCAL_W:
    case OPERAND.RET_W:
    case OPERAND.CP16:
      if (!need(2)) return unknown(insn, first);
      insn.a = u2(p);
      p += 2;
      break;
    case OPERAND.SHORT:
      if (!need(2)) return unknown(insn, first);
      insn.a = s2(p);
      p += 2;
      break;
    case OPERAND.IINC:
      if (!need(2)) return unknown(insn, first);
      insn.a = bytes[p]!;
      insn.b = s1(p + 1);
      p += 2;
      break;
    case OPERAND.IINC_W:
      if (!need(4)) return unknown(insn, first);
      insn.a = u2(p);
      insn.b = s2(p + 2);
      p += 4;
      break;
    case OPERAND.INTERFACE:
    case OPERAND.DYNAMIC:
      if (!need(4)) return unknown(insn, first);
      insn.a = u2(p);
      insn.b = bytes[p + 2]!;
      p += 4;
      break;
    case OPERAND.DIMENSIONS:
      if (!need(3)) return unknown(insn, first);
      insn.a = u2(p);
      insn.b = bytes[p + 2]!;
      p += 3;
      break;
    case OPERAND.BRANCH16:
    case OPERAND.JSR16:
      if (!need(2)) return unknown(insn, first);
      insn.a = pc + s2(p);
      p += 2;
      break;
    case OPERAND.BRANCH32:
    case OPERAND.JSR32:
      if (!need(4)) return unknown(insn, first);
      insn.a = pc + s4(p);
      p += 4;
      break;
    case OPERAND.TABLESWITCH:
    case OPERAND.LOOKUPSWITCH: {
      // The operands start at a multiple of four from the start of the code.
      p += (4 - ((pc + 1) % 4)) % 4;
      if (!need(8)) return unknown(insn, first);
      insn.a = pc + s4(p);
      const keys: number[] = [];
      const targets: number[] = [];
      if (op.operand === OPERAND.TABLESWITCH) {
        if (!need(12)) return unknown(insn, first);
        const low = s4(p + 4);
        const high = s4(p + 8);
        p += 12;
        const count = high - low + 1;
        if (count < 0 || !need(count * 4)) return unknown(insn, first);
        for (let k = 0; k < count; k++) {
          keys.push(low + k);
          targets.push(pc + s4(p + k * 4));
        }
        p += count * 4;
      } else {
        const count = s4(p + 4);
        p += 8;
        if (count < 0 || !need(count * 8)) return unknown(insn, first);
        for (let k = 0; k < count; k++) {
          keys.push(s4(p + k * 8));
          targets.push(pc + s4(p + k * 8 + 4));
        }
        p += count * 8;
      }
      insn.keys = keys;
      insn.targets = targets;
      break;
    }
  }
  insn.len = p - pos;
  return insn;
}

function unknown(insn: JvmInsn, first: number): JvmInsn {
  insn.op = undefined;
  insn.m = '.byte';
  insn.a = first;
  insn.len = 1;
  return insn;
}

/** The constant pool index an instruction names, or 0. */
export function poolIndex(insn: JvmInsn): number {
  const kind = insn.op?.operand;
  return kind === OPERAND.CP8 || kind === OPERAND.CP16 || kind === OPERAND.INTERFACE || kind === OPERAND.DYNAMIC || kind === OPERAND.DIMENSIONS ? insn.a : 0;
}

/** The operand of an instruction as javap prints it, and what it writes after `//`. */
export function operandText(cf: ClassFile, insn: JvmInsn): { operand: string; comment: string } {
  const op = insn.op;
  if (!op) return { operand: `0x${insn.a.toString(16).padStart(2, '0')}`, comment: '' };
  switch (op.operand) {
    case OPERAND.LOCAL:
    case OPERAND.LOCAL_W:
    case OPERAND.BYTE:
    case OPERAND.SHORT:
    case OPERAND.BRANCH16:
    case OPERAND.BRANCH32:
      return { operand: String(insn.a), comment: '' };
    case OPERAND.IINC:
    case OPERAND.IINC_W:
      return { operand: `${insn.a}, ${insn.b}`, comment: '' };
    case OPERAND.CP8:
    case OPERAND.CP16:
      return { operand: `#${insn.a}`, comment: constantComment(cf, insn.a) };
    case OPERAND.INTERFACE:
    case OPERAND.DIMENSIONS:
      return { operand: `#${insn.a},  ${insn.b}`, comment: constantComment(cf, insn.a) };
    case OPERAND.DYNAMIC:
      return { operand: `#${insn.a},  0`, comment: constantComment(cf, insn.a) };
    case OPERAND.ATYPE:
      return { operand: ATYPES[insn.a] ?? String(insn.a), comment: '' };
    case OPERAND.TABLESWITCH:
    case OPERAND.LOOKUPSWITCH: {
      const keys = insn.keys ?? [];
      const head = op.operand === OPERAND.TABLESWITCH ? `{ // ${keys[0] ?? 0} to ${keys.length ? keys[keys.length - 1] : -1}` : `{ // ${keys.length}`;
      const cases = keys.map((key, k) => `${key}: ${insn.targets![k]}`);
      return { operand: [head, ...cases, `default: ${insn.a}`, '}'].join(' '), comment: '' };
    }
  }
  // jsr and ret: javap leaves their operands out.
  return { operand: '', comment: '' };
}

/** An instruction as javap prints it after its pc: `getstatic     #7                  // Field …`, the comment after two spaces. */
export function insnText(cf: ClassFile, insn: JvmInsn): string {
  const { operand, comment } = operandText(cf, insn);
  if (!insn.op) return `.byte ${operand}`;
  const head = operand ? `${insn.m.padEnd(13)} ${operand}` : insn.m;
  return comment ? `${head}  // ${comment}` : head;
}

/** The bytes of an instruction as hex: `b6 00 0f`. */
export function bytesText(bytes: Uint8Array, at: number, len: number, max = 16): string {
  const shown = bytes.subarray(at, at + Math.min(len, max));
  return [...shown].map((b) => b.toString(16).padStart(2, '0')).join(' ') + (len > max ? ' …' : '');
}
