/**
 * A32 outside floating point and SIMD: data processing, multiplies, loads and
 * stores, branches, status registers, hints, barriers and the coprocessor
 * instructions.
 *
 * The decoder follows the top-level A32 encoding table — the condition field,
 * then bits 27:25 — and prints each instruction as llvm-objdump does, which is
 * not always as the Arm manual does: LLVM names `mov r0, r1, lsl #2` `lsl`,
 * prints a data-processing immediate in decimal but a load offset in hex
 * (except the post-indexed and halfword forms, which are decimal again), and
 * leaves out the operands an encoding cannot express. Where the manual calls
 * an encoding UNPREDICTABLE, LLVM usually still prints it; it gives up only on
 * the encodings it has no instruction for, and those are `.inst` here as well.
 * tools/verify-arm32.mjs compares the two line by line.
 */

import { F, bit, bits, hex, immDec, immHex, immText, label, list, r, regList, sext, shift, text, unknown, CONDS, type Insn, type Op } from './types';

const SHIFTS = ['lsl', 'lsr', 'asr', 'ror'] as const;
const DP = ['and', 'eor', 'sub', 'rsb', 'add', 'adc', 'sbc', 'rsc', 'tst', 'teq', 'cmp', 'cmn', 'orr', 'mov', 'bic', 'mvn'] as const;
const PC = 15;
const SP = 13;
const LR = 14;

const none = (w: number): Insn => unknown(w, 4, false);
const R = (n: number): Op => ({ k: 'reg', r: r(n) });

/**
 * An instruction under the condition in bits 31:28: the condition joins the
 * mnemonic (`addeq`, `ldrbne`), and a conditional instruction reads the flags.
 */
function mk(w: number, m: string, ops: Op[], f = 0, extra?: Partial<Insn>): Insn {
  const c = w >>> 28;
  const insn: Insn = { m, ops, f, size: 4, ...extra };
  if (c < 14) {
    insn.m = m + CONDS[c]!;
    insn.f |= F.COND | F.READS_FLAGS;
    insn.cond = CONDS[c]!;
  }
  return insn;
}

/** An instruction of the unconditional space (cond = 1111), which has no condition to print. */
function mkU(m: string, ops: Op[], f = 0, extra?: Partial<Insn>): Insn {
  return { m, ops, f, size: 4, ...extra };
}

/** `lsl #3`, `lsr #32`, `rrx`, or '' for no shift (lsl #0): a shift by an immediate. */
function shiftText(type: number, amount: number): string {
  if (type === 0) return amount ? `lsl #${amount}` : '';
  if (type === 3) return amount ? `ror #${amount}` : 'rrx';
  return `${SHIFTS[type]} #${amount || 32}`;
}

/**
 * A data-processing immediate: eight bits rotated right by twice bits 11:8.
 * LLVM prints the value in decimal (signed, except for a move to pc or a
 * status register), or, when the same value has an encoding with a smaller
 * rotation, the raw `#bits, #rot` pair, so the text still names one encoding.
 */
function modImm(w: number, unsigned: boolean): Op {
  const imm8 = w & 0xff;
  const rot = bits(w, 11, 8) * 2;
  const value = rot ? ((imm8 >>> rot) | (imm8 << (32 - rot))) >>> 0 : imm8;
  if (canonicalRotation(value) === rot) return immText(value, `#${unsigned ? value : value | 0}`);
  return immText(value, `#${imm8}, #${rot}`);
}

/** The smallest rotation that encodes a value, as LLVM's getSOImmVal picks it. */
function canonicalRotation(value: number): number {
  if ((value & ~0xff) === 0) return 0;
  for (let rot = 2; rot < 32; rot += 2) {
    const back = ((value << rot) | (value >>> (32 - rot))) >>> 0;
    if ((back & ~0xff) === 0) return rot;
  }
  return -1;
}

/** A memory operand. */
function mem(base: number, t: string, mode: 'off' | 'pre' | 'post', off?: number, index?: number): Op {
  const op: Op = { k: 'mem', base: r(base), t, mode };
  if (off !== undefined) op.off = off || 0; // no -0 for a subtracted zero
  if (index !== undefined) op.index = r(index);
  return op;
}

const pcRelative = (pc: number, offset: number): number => (pc + 8 + offset) >>> 0;

export function decodeA32Base(w: number, pc: number): Insn {
  if (w >>> 28 === 15) return unconditional(w, pc);
  switch (bits(w, 27, 25)) {
    case 0:
      return group000(w, pc);
    case 1:
      return group001(w, pc);
    case 2:
      return loadStoreWord(w, pc);
    case 3:
      return bit(w, 4) ? media(w) : loadStoreWord(w, pc);
    case 4:
      return blockTransfer(w);
    case 5:
      return branch(w, pc);
    default:
      return coprocessor(w);
  }
}

/* ------------------------------------------------------------------ *
 * Bits 27:25 = 000: data processing on registers, the miscellaneous
 * instructions, multiplies, synchronisation and the halfword/doubleword
 * loads and stores
 * ------------------------------------------------------------------ */

function group000(w: number, pc: number): Insn {
  const op4 = bit(w, 4);
  const op7 = bit(w, 7);
  if (op4 && op7) {
    if (bits(w, 6, 5) === 0) return bit(w, 24) ? synchronization(w) : multiply(w);
    return extraLoadStore(w, pc);
  }
  if (bits(w, 24, 23) === 2 && !bit(w, 20)) return op7 ? halfwordMultiply(w) : miscellaneous(w);
  return dataProcessingRegister(w);
}

/**
 * Data processing with a register operand, shifted by an immediate (bit 4 = 0)
 * or by a register. The moves with a shift print as the shift itself:
 * `mov r0, r1, lsl #2` is `lsl r0, r1, #2`, `mov r0, r1, ror #0` is `rrx r0, r1`.
 */
function dataProcessingRegister(w: number): Insn {
  const opc = bits(w, 24, 21);
  const s = bit(w, 20);
  const rn = bits(w, 19, 16);
  const rd = bits(w, 15, 12);
  const rm = bits(w, 3, 0);
  const type = bits(w, 6, 5);
  const byReg = bit(w, 4);
  const rs = bits(w, 11, 8);
  const amount = bits(w, 11, 7);
  const test = opc >= 8 && opc <= 11;

  let f = s || test ? F.SETS_FLAGS : 0;
  if (opc >= 5 && opc <= 7) f |= F.READS_FLAGS;
  if (!byReg && type === 3 && amount === 0) f |= F.READS_FLAGS;

  if (opc === 13) {
    // mov: the shift becomes the mnemonic. Bits 19:16 must be zero, except
    // that LLVM also knows a plain mov between the registers a tail call may
    // use (r0-r3, r9, r12) without that rule.
    const sx = s ? 's' : '';
    const plain = !byReg && type === 0 && amount === 0;
    if (rn && !(plain && TAIL_CALL_REGS & (1 << rd) && TAIL_CALL_REGS & (1 << rm))) return none(w);
    if (byReg) return mk(w, SHIFTS[type] + sx, [R(rd), R(rm), R(rs)], f | writesPc(rd));
    if (type === 0 && amount === 0) return mk(w, 'mov' + sx, [R(rd), R(rm)], f | writesPc(rd) | (rd === PC && rm === LR ? F.RET : 0));
    if (type === 3 && amount === 0) return mk(w, 'rrx' + sx, [R(rd), R(rm)], f | writesPc(rd));
    return mk(w, SHIFTS[type] + sx, [R(rd), R(rm), immDec(amount || (type === 0 ? 0 : 32))], f | writesPc(rd));
  }

  const operand2: Op[] = [R(rm)];
  if (byReg) operand2.push(shift(`${SHIFTS[type]} ${r(rs)}`));
  else {
    const sh = shiftText(type, amount);
    if (sh) operand2.push(shift(sh));
  }
  if (test) return mk(w, DP[opc]!, [R(rn), ...operand2], f);
  const m = DP[opc]! + (s ? 's' : '');
  if (opc === 15) return mk(w, m, [R(rd), ...operand2], f | writesPc(rd));
  return mk(w, m, [R(rd), R(rn), ...operand2], f | writesPc(rd));
}

/** A data-processing result written to pc is a branch to a computed address. */
const writesPc = (rd: number): number => (rd === PC ? F.BRANCH | F.INDIRECT : 0);

/** r0-r3, r9, r12: LLVM's tcGPR class. */
const TAIL_CALL_REGS = 0x120f;

/** MUL, MLA, UMAAL, MLS and the long multiplies (bits 7:4 = 1001, bit 24 = 0). */
function multiply(w: number): Insn {
  const op = bits(w, 23, 21);
  const s = bit(w, 20);
  const hi = bits(w, 19, 16);
  const lo = bits(w, 15, 12);
  const rm = bits(w, 11, 8);
  const rn = bits(w, 3, 0);
  const sx = s ? 's' : '';
  const f = s ? F.SETS_FLAGS : 0;
  switch (op) {
    case 0:
      return mk(w, 'mul' + sx, [R(hi), R(rn), R(rm)], f);
    case 1:
      return mk(w, 'mla' + sx, [R(hi), R(rn), R(rm), R(lo)], f);
    case 2:
      return s ? none(w) : mk(w, 'umaal', [R(lo), R(hi), R(rn), R(rm)]);
    case 3:
      return s ? none(w) : mk(w, 'mls', [R(hi), R(rn), R(rm), R(lo)]);
    default:
      return mk(w, ['umull', 'umlal', 'smull', 'smlal'][op - 4]! + sx, [R(lo), R(hi), R(rn), R(rm)], f);
  }
}

/**
 * The exclusive and acquire/release loads and stores (bits 7:4 = 1001,
 * bit 24 = 1). SWP and SWPB share the space but are gone from Armv8, and LLVM
 * does not decode them there.
 */
function synchronization(w: number): Insn {
  if (!bit(w, 23)) return none(w);
  const size = bits(w, 22, 21);
  const load = bit(w, 20);
  const rn = bits(w, 19, 16);
  const rt = bits(w, 15, 12);
  const rt2 = bits(w, 3, 0);
  const kind = bits(w, 9, 8);
  // Bits 11:10 are ones, and so are the unused register fields (Rt2 of a load, Rt of stl).
  if (kind === 1 || bits(w, 11, 10) !== 3 || (load && rt2 !== 15) || (!load && kind === 0 && rt !== 15)) return none(w);
  const suffix = ['', 'd', 'b', 'h'][size]!;
  const bytes = [4, 8, 1, 2][size]!;
  const address = mem(rn, `[${r(rn)}]`, 'off');
  const f = F.ATOMIC | (load ? F.LOAD : F.STORE);
  if (kind === 0) {
    // lda/stl: no exclusive monitor, no doubleword form.
    if (size === 1) return none(w);
    const m = (load ? 'lda' : 'stl') + suffix;
    return mk(w, m, [R(load ? rt : rt2), address], f | (load && rt === PC ? F.BRANCH | F.INDIRECT : 0), { bytes });
  }
  const m = (kind === 2 ? (load ? 'ldaex' : 'stlex') : load ? 'ldrex' : 'strex') + suffix;
  if (size === 1) {
    // The pair is the even register and the next one; an odd register prints as its pair.
    if (load) return rt >= 14 ? none(w) : mk(w, m, [R(rt & ~1), R((rt & ~1) + 1), address], f, { bytes });
    return rt2 >= 14 ? none(w) : mk(w, m, [R(rt), R(rt2 & ~1), R((rt2 & ~1) + 1), address], f, { bytes });
  }
  if (load) return mk(w, m, [R(rt), address], f, { bytes });
  return mk(w, m, [R(rt), R(rt2), address], f, { bytes });
}

/**
 * LDRH, STRH, LDRSB, LDRSH, LDRD, STRD and their unprivileged forms (bit 7 =
 * bit 4 = 1, bits 6:5 ≠ 00). Addressing mode 3 prints its offset in decimal.
 */
function extraLoadStore(w: number, pc: number): Insn {
  const p = bit(w, 24);
  const u = bit(w, 23);
  const isImm = bit(w, 22);
  const wb = bit(w, 21);
  const load = bit(w, 20);
  const rn = bits(w, 19, 16);
  const rt = bits(w, 15, 12);
  const rm = bits(w, 3, 0);
  const op2 = bits(w, 6, 5);
  const imm = (bits(w, 11, 8) << 4) | rm;
  const sign = u ? '' : '-';
  const unprivileged = !p && wb;
  const double = !load && op2 !== 1;

  let m: string;
  let bytes: number;
  if (double) {
    m = op2 === 2 ? 'ldrd' : 'strd';
    bytes = 8;
  } else if (op2 === 1) {
    m = load ? 'ldrh' : 'strh';
    bytes = 2;
  } else {
    m = op2 === 2 ? 'ldrsb' : 'ldrsh';
    bytes = op2 === 2 ? 1 : 2;
  }
  const isLoad = double ? op2 === 2 : load === 1;
  if (unprivileged) {
    // ldrd and strd have no unprivileged form; the others take no register shift bits.
    if (double || (!isImm && !load && bits(w, 11, 8))) return none(w);
    m += 't';
  }

  let address: Op;
  let target: number | undefined;
  if (p) {
    if (isImm) {
      const t = imm || !u || wb ? `[${r(rn)}, #${sign}${imm}]` : `[${r(rn)}]`;
      address = mem(rn, wb ? `${t}!` : t, wb ? 'pre' : 'off', u ? imm : -imm);
      if (rn === PC && !wb) target = pcRelative(pc, u ? imm : -imm);
    } else {
      address = mem(rn, `[${r(rn)}, ${sign}${r(rm)}]${wb ? '!' : ''}`, wb ? 'pre' : 'off', undefined, rm);
    }
  } else if (isImm) {
    address = mem(rn, `[${r(rn)}], #${sign}${imm}`, 'post', u ? imm : -imm);
  } else {
    address = mem(rn, `[${r(rn)}], ${sign}${r(rm)}`, 'post', undefined, rm);
  }

  const regs: Op[] = [R(rt)];
  if (double) {
    if (rt === PC) return none(w);
    regs.push(R(rt + 1));
  }
  let f = isLoad ? F.LOAD : F.STORE;
  if (isLoad && (rt === PC || (double && rt + 1 === PC))) f |= F.BRANCH | F.INDIRECT;
  return mk(w, m, [...regs, address], f, target === undefined ? { bytes } : { bytes, target });
}

/**
 * The miscellaneous instructions (bits 27:23 = 00010, bit 20 = 0, bit 7 = 0):
 * status register moves, bx/blx/bxj, clz, the saturating adds, crc32, eret
 * and the breakpoint and call-gate instructions.
 */
function miscellaneous(w: number): Insn {
  const op = bits(w, 22, 21);
  const rd = bits(w, 15, 12);
  const rm = bits(w, 3, 0);
  const rn = bits(w, 19, 16);
  const c = w >>> 28;
  switch (bits(w, 6, 4)) {
    case 0: {
      const spsr = bit(w, 22);
      if (bit(w, 9)) {
        // Banked registers: SYSm is bit 8 and bits 19:16.
        const name = BANKED[(spsr << 5) | (bit(w, 8) << 4) | rn];
        if (!name || bits(w, 11, 10)) return none(w);
        if (op & 1) return rd === 15 ? mk(w, 'msr', [text(name), R(rm)]) : none(w);
        return rm ? none(w) : mk(w, 'mrs', [R(rd), text(name)]);
      }
      if (op & 1) {
        // A mask of nothing (CPSR with no fields) is not an instruction to LLVM.
        if (rd !== 15 || bits(w, 11, 8) || (!spsr && !rn)) return none(w);
        return mk(w, 'msr', [text(msrMask(spsr, rn)), R(rm)], rn & 8 && !spsr ? F.SETS_FLAGS : 0);
      }
      // mrs: the other bits are UNPREDICTABLE, which LLVM accepts, except bit 16 of apsr.
      if (!spsr && !bit(w, 16)) return none(w);
      return mk(w, 'mrs', [R(rd), text(spsr ? 'spsr' : 'apsr')]);
    }
    case 1:
      if (op === 1) return bits(w, 19, 8) === 0xfff ? mk(w, 'bx', [R(rm)], F.BRANCH | F.INDIRECT | (rm === LR ? F.RET : 0)) : none(w);
      if (op === 3) return (w & 0xf0f00) === 0xf0f00 ? mk(w, 'clz', [R(rd), R(rm)]) : none(w);
      return none(w);
    case 2:
      return op === 1 && bits(w, 19, 8) === 0xfff ? mk(w, 'bxj', [R(rm)], F.BRANCH | F.INDIRECT) : none(w);
    case 3:
      return op === 1 && bits(w, 19, 8) === 0xfff ? mk(w, 'blx', [R(rm)], F.CALL | F.INDIRECT) : none(w);
    case 4: {
      // crc32 exists only unconditionally.
      if (op === 3 || c !== 14) return none(w);
      return mk(w, `crc32${bit(w, 9) ? 'c' : ''}${['b', 'h', 'w'][op]}`, [R(rd), R(rn), R(rm)]);
    }
    case 5:
      return mk(w, ['qadd', 'qsub', 'qdadd', 'qdsub'][op]!, [R(rd), R(rm), R(rn)]);
    case 6:
      return op === 3 && (w & 0xfffff) === 0x0006e ? mk(w, 'eret', [], F.BRANCH | F.RET) : none(w);
    default: {
      const imm16 = (bits(w, 19, 8) << 4) | rm;
      // hlt and bkpt are unconditional; hvc takes any condition but does not print it.
      if (op === 0) return c === 14 ? mk(w, 'hlt', [immHex(imm16)], F.TRAP) : none(w);
      if (op === 1) return c === 14 ? mk(w, 'bkpt', [immHex(imm16)], F.TRAP) : none(w);
      if (op === 2) return mkU('hvc', [immHex(imm16)]);
      return bits(w, 19, 8) ? none(w) : mk(w, 'smc', [immHex(rm)]);
    }
  }
}

/** The CPSR/SPSR field mask of an msr, as LLVM's printMSRMaskOperand prints it. */
function msrMask(spsr: number, mask: number): string {
  if (!spsr && (mask === 8 || mask === 4 || mask === 12)) return mask === 8 ? 'APSR_nzcvq' : mask === 4 ? 'APSR_g' : 'APSR_nzcvqg';
  let t = spsr ? 'SPSR' : 'CPSR';
  if (mask) {
    t += '_';
    if (mask & 8) t += 'f';
    if (mask & 4) t += 's';
    if (mask & 2) t += 'x';
    if (mask & 1) t += 'c';
  }
  return t;
}

const BANKED: Record<number, string> = {
  0x00: 'r8_usr', 0x01: 'r9_usr', 0x02: 'r10_usr', 0x03: 'r11_usr', 0x04: 'r12_usr', 0x05: 'sp_usr', 0x06: 'lr_usr',
  0x08: 'r8_fiq', 0x09: 'r9_fiq', 0x0a: 'r10_fiq', 0x0b: 'r11_fiq', 0x0c: 'r12_fiq', 0x0d: 'sp_fiq', 0x0e: 'lr_fiq',
  0x10: 'lr_irq', 0x11: 'sp_irq', 0x12: 'lr_svc', 0x13: 'sp_svc', 0x14: 'lr_abt', 0x15: 'sp_abt', 0x16: 'lr_und', 0x17: 'sp_und',
  0x1c: 'lr_mon', 0x1d: 'sp_mon', 0x1e: 'elr_hyp', 0x1f: 'sp_hyp',
  0x2e: 'SPSR_fiq', 0x30: 'SPSR_irq', 0x32: 'SPSR_svc', 0x34: 'SPSR_abt', 0x36: 'SPSR_und', 0x3c: 'SPSR_mon', 0x3e: 'SPSR_hyp',
};

/** SMLA<x><y>, SMLAW<y>, SMULW<y>, SMLAL<x><y>, SMUL<x><y> (bits 27:23 = 00010, bit 7 = 1, bit 4 = 0). */
function halfwordMultiply(w: number): Insn {
  const op = bits(w, 22, 21);
  const rd = bits(w, 19, 16);
  const ra = bits(w, 15, 12);
  const rm = bits(w, 11, 8);
  const rn = bits(w, 3, 0);
  const x = bit(w, 5) ? 't' : 'b';
  const y = bit(w, 6) ? 't' : 'b';
  switch (op) {
    case 0:
      return mk(w, `smla${x}${y}`, [R(rd), R(rn), R(rm), R(ra)]);
    case 1:
      return bit(w, 5) ? mk(w, `smulw${y}`, [R(rd), R(rn), R(rm)]) : mk(w, `smlaw${y}`, [R(rd), R(rn), R(rm), R(ra)]);
    case 2:
      return mk(w, `smlal${x}${y}`, [R(ra), R(rd), R(rn), R(rm)]);
    default:
      return mk(w, `smul${x}${y}`, [R(rd), R(rn), R(rm)]);
  }
}

/* ------------------------------------------------------------------ *
 * Bits 27:25 = 001: data processing with an immediate, movw/movt,
 * msr with an immediate and the hints
 * ------------------------------------------------------------------ */

function group001(w: number, pc: number): Insn {
  const opc = bits(w, 24, 21);
  const s = bit(w, 20);
  if (opc >= 8 && opc <= 11 && !s) {
    const rd = bits(w, 15, 12);
    if (opc === 8 || opc === 10) {
      const imm16 = (bits(w, 19, 16) << 12) | (w & 0xfff);
      return mk(w, opc === 8 ? 'movw' : 'movt', [R(rd), immHex(imm16)], writesPc(rd));
    }
    return msrImmediate(w);
  }
  const rn = bits(w, 19, 16);
  const rd = bits(w, 15, 12);
  let f = s || (opc >= 8 && opc <= 11) ? F.SETS_FLAGS : 0;
  if (opc >= 5 && opc <= 7) f |= F.READS_FLAGS;
  if (opc >= 8 && opc <= 11) return mk(w, DP[opc]!, [R(rn), modImm(w, false)], f);
  const m = DP[opc]! + (s ? 's' : '');
  if (opc === 13 || opc === 15) return rn ? none(w) : mk(w, m, [R(rd), modImm(w, opc === 13 && rd === PC)], f | writesPc(rd));
  const op2 = modImm(w, false);
  let extra: Partial<Insn> | undefined;
  if (rn === PC && !s && (opc === 2 || opc === 4)) {
    // add/sub rX, pc, #imm computes an address: the analysis reads it as adr.
    extra = { target: pcRelative(pc, opc === 4 ? (op2 as { v: number }).v : -(op2 as { v: number }).v) };
  }
  // subs pc, lr, #imm returns from an exception.
  if (rd === PC && rn === LR && s && opc === 2) return mk(w, m, [R(rd), R(rn), op2], f | F.BRANCH | F.RET);
  return mk(w, m, [R(rd), R(rn), op2], f | writesPc(rd), extra);
}

/** MSR with an immediate; a zero mask is the hint space (nop, yield, wfe, csdb…). */
function msrImmediate(w: number): Insn {
  const spsr = bit(w, 22);
  const mask = bits(w, 19, 16);
  if (bits(w, 15, 12) !== 15) return none(w);
  if (spsr || mask) return mk(w, 'msr', [text(msrMask(spsr, mask)), modImm(w, true)], mask & 8 && !spsr ? F.SETS_FLAGS : 0);
  if (bits(w, 11, 8)) return none(w);
  const imm = w & 0xff;
  switch (imm) {
    case 0:
      return mk(w, 'nop', []);
    case 1:
      return mk(w, 'yield', []);
    case 2:
      return mk(w, 'wfe', []);
    case 3:
      return mk(w, 'wfi', []);
    case 4:
      return mk(w, 'sev', []);
    case 5:
      return mk(w, 'sevl', []);
    case 16:
      return mk(w, 'esb', []);
    case 18:
      // tsb is defined only unconditionally; under a condition it stays a hint.
      if (w >>> 28 === 14) return mk(w, 'tsb', [text('csync')]);
      break;
    case 20:
      return mk(w, 'csdb', []);
    case 22:
      return mk(w, 'clrbhb', []);
  }
  if (imm >= 0xf0) return mk(w, 'dbg', [immHex(imm & 15)]);
  return mk(w, 'hint', [immHex(imm)]);
}

/* ------------------------------------------------------------------ *
 * Bits 27:25 = 010 and 011 (bit 4 = 0): ldr, str, ldrb, strb and their
 * unprivileged forms
 * ------------------------------------------------------------------ */

/**
 * Addressing mode 2 prints an immediate offset in hex inside the brackets
 * (`[r1, #0x4]`, `[r1, #-0x0]` for a subtracted zero) and in decimal after
 * them (`[r1], #4`); a register offset carries its sign and shift.
 */
function loadStoreWord(w: number, pc: number): Insn {
  const isReg = bit(w, 25);
  const p = bit(w, 24);
  const u = bit(w, 23);
  const byte = bit(w, 22);
  const wb = bit(w, 21);
  const load = bit(w, 20);
  const rn = bits(w, 19, 16);
  const rt = bits(w, 15, 12);
  const sign = u ? '' : '-';
  const base = r(rn);

  let address: Op;
  let target: number | undefined;
  if (!isReg) {
    const imm = w & 0xfff;
    const off = u ? imm : -imm;
    if (p) {
      const t = !u ? `[${base}, #-${hex(imm)}]` : imm || wb ? `[${base}, #${hex(imm)}]` : `[${base}]`;
      address = mem(rn, wb ? `${t}!` : t, wb ? 'pre' : 'off', off);
      if (rn === PC && !wb) target = pcRelative(pc, off);
    } else {
      address = mem(rn, `[${base}], #${sign}${imm}`, 'post', off);
    }
  } else {
    const rm = bits(w, 3, 0);
    const sh = shiftText(bits(w, 6, 5), bits(w, 11, 7));
    const index = `${sign}${r(rm)}${sh ? `, ${sh}` : ''}`;
    address = p ? mem(rn, `[${base}, ${index}]${wb ? '!' : ''}`, wb ? 'pre' : 'off', undefined, rm) : mem(rn, `[${base}], ${index}`, 'post', undefined, rm);
  }

  const m = (load ? 'ldr' : 'str') + (byte ? 'b' : '') + (!p && wb ? 't' : '');
  let f = load ? F.LOAD : F.STORE;
  if (load && rt === PC) {
    f |= F.BRANCH | F.INDIRECT;
    if (rn === SP && !p) f |= F.RET;
  }
  const extra: Partial<Insn> = { bytes: byte ? 1 : 4 };
  if (target !== undefined) extra.target = target;
  return mk(w, m, [R(rt), address], f, extra);
}

/* ------------------------------------------------------------------ *
 * Bits 27:25 = 011, bit 4 = 1: the media instructions — parallel add and
 * subtract, packing, extension, saturation, reversal, signed multiplies,
 * divides, bitfields and udf
 * ------------------------------------------------------------------ */

const PARALLEL_OPS = ['add16', 'asx', 'sax', 'sub16', 'add8', '', '', 'sub8'] as const;

function media(w: number): Insn {
  const op1 = bits(w, 24, 20);
  const op2 = bits(w, 7, 5);
  const rn = bits(w, 19, 16);
  const rd = bits(w, 15, 12);
  const rs = bits(w, 11, 8);
  const rm = bits(w, 3, 0);

  if (op1 < 8) {
    // Parallel add/subtract: s, q, sh (signed) and u, uq, uh (unsigned).
    const kind = op1 & 3;
    const name = PARALLEL_OPS[op2];
    if (!kind || !name) return none(w);
    const prefix = (op1 & 4 ? ['', 'u', 'uq', 'uh'] : ['', 's', 'q', 'sh'])[kind]!;
    return mk(w, prefix + name, [R(rd), R(rn), R(rm)]);
  }

  if (op1 < 16) return packing(w, op1, op2);

  switch (op1) {
    case 0x10:
    case 0x14: {
      // smlad/smlsd (and smuad/smusd with Ra = pc), smlald/smlsld.
      if (op2 >= 4) return none(w);
      const x = op2 & 1 ? 'x' : '';
      const sub = op2 & 2 ? 's' : 'a';
      if (op1 === 0x14) return mk(w, `sml${sub}ld${x}`, [R(rd), R(rn), R(rm), R(rs)]);
      if (rd === PC) return mk(w, `smu${sub}d${x}`, [R(rn), R(rm), R(rs)]);
      return mk(w, `sml${sub}d${x}`, [R(rn), R(rm), R(rs), R(rd)]);
    }
    case 0x11:
    case 0x13:
      if (op2 !== 0 || rd !== PC) return none(w);
      return mk(w, op1 === 0x11 ? 'sdiv' : 'udiv', [R(rn), R(rm), R(rs)]);
    case 0x15: {
      // smmla/smmls (and smmul with Ra = pc), with or without rounding.
      const round = op2 & 1 ? 'r' : '';
      if (op2 < 2) return rd === PC ? mk(w, `smmul${round}`, [R(rn), R(rm), R(rs)]) : mk(w, `smmla${round}`, [R(rn), R(rm), R(rs), R(rd)]);
      if (op2 >= 6) return mk(w, `smmls${round}`, [R(rn), R(rm), R(rs), R(rd)]);
      return none(w);
    }
    case 0x18:
      if (op2 !== 0) return none(w);
      return rd === PC ? mk(w, 'usad8', [R(rn), R(rm), R(rs)]) : mk(w, 'usada8', [R(rn), R(rm), R(rs), R(rd)]);
    case 0x1a:
    case 0x1b:
    case 0x1e:
    case 0x1f: {
      if (op1 === 0x1f && op2 === 7) return udf(w);
      if ((op2 & 3) !== 2) return none(w);
      const lsb = bits(w, 11, 7);
      const width = bits(w, 20, 16) + 1;
      return mk(w, op1 < 0x1e ? 'sbfx' : 'ubfx', [R(rd), R(rm), immHex(lsb), immHex(width)]);
    }
    case 0x1c:
    case 0x1d: {
      if ((op2 & 3) !== 0) return none(w);
      const lsb = bits(w, 11, 7);
      const msb = bits(w, 20, 16);
      const from = lsb > msb ? msb : lsb;
      const field = [immDec(from), immDec(msb - from + 1)];
      return rm === PC ? mk(w, 'bfc', [R(rd), ...field]) : mk(w, 'bfi', [R(rd), R(rm), ...field]);
    }
    default:
      return none(w);
  }
}

/**
 * udf, a permanently undefined instruction, exists only unconditionally. One
 * of them, 0xe7ffdefe, is the trap LLVM emits for __builtin_trap, and it
 * prints it as `trap`.
 */
function udf(w: number): Insn {
  if (w >>> 28 !== 14) return none(w);
  if (w === 0xe7ffdefe) return mkU('trap', [], F.TRAP);
  const imm16 = (bits(w, 19, 8) << 4) | bits(w, 3, 0);
  return mkU('udf', [immHex(imm16)], F.TRAP);
}

/** pkhbt/pkhtb, the sign and zero extensions (sxtb, uxtah…), ssat/usat, sel, rev, rbit. */
function packing(w: number, op1: number, op2: number): Insn {
  const rn = bits(w, 19, 16);
  const rd = bits(w, 15, 12);
  const rm = bits(w, 3, 0);
  const rotate = bits(w, 11, 10);
  const ror = rotate ? [shift(`ror #${rotate * 8}`)] : [];

  if ((op2 & 1) === 0) {
    if (op1 === 8) {
      const amount = bits(w, 11, 7);
      if (op2 & 2) return mk(w, 'pkhtb', [R(rd), R(rn), R(rm), shift(`asr #${amount || 32}`)]);
      return mk(w, 'pkhbt', [R(rd), R(rn), R(rm), ...(amount ? [shift(`lsl #${amount}`)] : [])]);
    }
    if ((op1 & 2) === 0) return none(w);
    // ssat/usat: a shift of the source by lsl or asr.
    const amount = bits(w, 11, 7);
    const sh = bit(w, 6) ? [shift(`asr #${amount || 32}`)] : amount ? [shift(`lsl #${amount}`)] : [];
    const sat = bits(w, 20, 16);
    if (op1 & 4) return mk(w, 'usat', [R(rd), immHex(sat), R(rm), ...sh]);
    return mk(w, 'ssat', [R(rd), immHex(sat + 1), R(rm), ...sh]);
  }

  const ones = (w & 0xf0f00) === 0xf0f00;
  const extend = (name: string): Insn => (rn === PC ? mk(w, `${name.slice(0, 2)}t${name.slice(4)}`, [R(rd), R(rm), ...ror]) : mk(w, name, [R(rd), R(rn), R(rm), ...ror]));
  switch ((op1 << 3) | op2) {
    case (8 << 3) | 3:
      return extend('sxtab16');
    case (8 << 3) | 5:
      return mk(w, 'sel', [R(rd), R(rn), R(rm)]);
    case (10 << 3) | 1:
      return bits(w, 11, 8) === 15 ? mk(w, 'ssat16', [R(rd), immHex(rn + 1), R(rm)]) : none(w);
    case (10 << 3) | 3:
      return extend('sxtab');
    case (11 << 3) | 1:
      return ones ? mk(w, 'rev', [R(rd), R(rm)]) : none(w);
    case (11 << 3) | 3:
      return extend('sxtah');
    case (11 << 3) | 5:
      return ones ? mk(w, 'rev16', [R(rd), R(rm)]) : none(w);
    case (12 << 3) | 3:
      return extend('uxtab16');
    case (14 << 3) | 1:
      return bits(w, 11, 8) === 15 ? mk(w, 'usat16', [R(rd), immHex(rn), R(rm)]) : none(w);
    case (14 << 3) | 3:
      return extend('uxtab');
    case (15 << 3) | 1:
      return ones ? mk(w, 'rbit', [R(rd), R(rm)]) : none(w);
    case (15 << 3) | 3:
      return extend('uxtah');
    case (15 << 3) | 5:
      return ones ? mk(w, 'revsh', [R(rd), R(rm)]) : none(w);
    default:
      return none(w);
  }
}

/* ------------------------------------------------------------------ *
 * Bits 27:25 = 100: ldm and stm in their four modes, push and pop, and the
 * user-register forms (`^`)
 * ------------------------------------------------------------------ */

const LDM_MODES = ['da', '', 'db', 'ib'] as const;

function blockTransfer(w: number): Insn {
  const mode = bits(w, 24, 23);
  const user = bit(w, 22);
  const wb = bit(w, 21);
  const load = bit(w, 20);
  const rn = bits(w, 19, 16);
  const mask = w & 0xffff;
  if (!mask) return none(w);
  const regs = regList(mask);
  const many = regs.length > 1;
  let f = load ? F.LOAD : F.STORE;
  if (load && mask & 0x8000) {
    f |= F.BRANCH | F.INDIRECT;
    // pop {…, pc} (ldm sp! in the increment-after mode) is the usual return.
    if (rn === SP && wb && mode === 1) f |= F.RET;
  }
  const extra: Partial<Insn> = { bytes: 4 };
  if (!user && wb && rn === SP && many && ((load && mode === 1) || (!load && mode === 2))) {
    return mk(w, load ? 'pop' : 'push', [list(regs)], f, extra);
  }
  const listOp: Op = user ? { k: 'list', regs, t: `{${regs.join(', ')}} ^` } : list(regs);
  return mk(w, (load ? 'ldm' : 'stm') + LDM_MODES[mode], [{ k: 'reg', r: r(rn), ...(wb ? { wb: true } : {}) }, listOp], f, extra);
}

/* ------------------------------------------------------------------ *
 * Bits 27:25 = 101: b and bl
 * ------------------------------------------------------------------ */

function branch(w: number, pc: number): Insn {
  const target = pcRelative(pc, sext(w & 0xffffff, 24) * 4);
  if (bit(w, 24)) return mk(w, 'bl', [label(target)], F.CALL, { target, thumb: false });
  return mk(w, 'b', [label(target)], F.BRANCH, { target });
}

/* ------------------------------------------------------------------ *
 * Bits 27:25 = 110 and 111: the coprocessor instructions and svc
 *
 * Armv8 keeps only coprocessors 14 and 15 (debug and system control) for
 * mcr, mrc, mcrr and mrrc, and only 14 for ldc and stc; cdp is gone. 10 and
 * 11 are floating point and SIMD, decoded in simd.ts.
 * ------------------------------------------------------------------ */

function coprocessor(w: number): Insn {
  if (bits(w, 27, 24) === 15) return mk(w, 'svc', [immHex(w & 0xffffff)]);
  const cp = bits(w, 11, 8);
  if ((cp & 0xe) !== 0xe) return none(w);
  const rn = bits(w, 19, 16);
  const rt = bits(w, 15, 12);
  if (bits(w, 27, 25) === 6) {
    if (bits(w, 24, 21) === 2) {
      // mcrr/mrrc: two core registers, one 64-bit coprocessor register.
      const m = bit(w, 20) ? 'mrrc' : 'mcrr';
      return mk(w, m, [text(`p${cp}`), immHex(bits(w, 7, 4)), R(rt), R(rn), text(`c${w & 15}`)]);
    }
    return loadStoreCoprocessor(w);
  }
  // cdp is gone from Armv8 altogether.
  if (!bit(w, 4)) return none(w);
  const toCore = bit(w, 20);
  const core: Op = toCore && rt === PC ? text('apsr_nzcv') : R(rt);
  return mk(w, toCore ? 'mrc' : 'mcr', [text(`p${cp}`), immHex(bits(w, 23, 21)), core, text(`c${rn}`), text(`c${w & 15}`), immHex(bits(w, 7, 5))], toCore && rt === PC ? F.SETS_FLAGS : 0);
}

/** ldc/stc: addressing mode 5, a word offset printed in decimal, or an option `{imm}`. */
function loadStoreCoprocessor(w: number): Insn {
  const p = bit(w, 24);
  const u = bit(w, 23);
  const long = bit(w, 22);
  const wb = bit(w, 21);
  const load = bit(w, 20);
  const rn = bits(w, 19, 16);
  const cp = bits(w, 11, 8);
  if (cp !== 14) return none(w);
  if (!p && !wb && !u) return none(w);
  const imm8 = w & 0xff;
  const sign = u ? '' : '-';
  const base = r(rn);
  let address: Op;
  if (p) {
    const t = imm8 || !u || wb ? `[${base}, #${sign}${imm8 * 4}]` : `[${base}]`;
    address = mem(rn, wb ? `${t}!` : t, wb ? 'pre' : 'off', u ? imm8 * 4 : -imm8 * 4);
  } else if (wb) {
    address = mem(rn, `[${base}], #${sign}${imm8 * 4}`, 'post', u ? imm8 * 4 : -imm8 * 4);
  } else {
    address = mem(rn, `[${base}], {${imm8}}`, 'off');
  }
  const m = (load ? 'ldc' : 'stc') + (long ? 'l' : '');
  return mk(w, m, [text(`p${cp}`), text(`c${bits(w, 15, 12)}`), address], load ? F.LOAD : F.STORE);
}

/* ------------------------------------------------------------------ *
 * cond = 1111: the unconditional instructions — cps, setend, setpan,
 * preloads, barriers, clrex, srs, rfe and blx to an immediate
 * ------------------------------------------------------------------ */

function unconditional(w: number, pc: number): Insn {
  const op = bits(w, 27, 25);
  if (op === 5) {
    const target = pcRelative(pc, sext(w & 0xffffff, 24) * 4 + bit(w, 24) * 2);
    return mkU('blx', [label(target)], F.CALL, { target, thumb: true });
  }
  if (op === 4) return returnState(w);
  if (op >= 6) return none(w);
  return unconditionalMisc(w, pc);
}

/**
 * srs (store return state) and rfe (return from exception). LLVM decodes an
 * rfe whose low bits are not the architected 0x0a00 through its ldm decoder
 * when it writes back, and then prints the addressing mode where the base
 * register should be (`rfeia #0x1!`); without writeback it gives up.
 */
function returnState(w: number): Insn {
  const modeBits = bits(w, 24, 23);
  const mode = LDM_MODES[modeBits] || 'ia';
  const wb = bit(w, 21);
  if (bit(w, 20)) {
    if (bit(w, 22)) return none(w);
    const f = F.BRANCH | F.INDIRECT | F.RET | F.LOAD;
    if ((w & 0xffff) !== 0x0a00) return wb ? mkU(`rfe${mode}`, [text(`#${hex(SUBMODE[modeBits]!)}!`)], f) : none(w);
    const rn = bits(w, 19, 16);
    return mkU(`rfe${mode}`, [{ k: 'reg', r: r(rn), ...(wb ? { wb: true } : {}) }], f);
  }
  if (!bit(w, 22) || (w & 0xfffe0) !== 0xd0500) return none(w);
  return mkU(`srs${mode}`, [{ k: 'reg', r: 'sp', ...(wb ? { wb: true } : {}) }, immHex(w & 31)], F.STORE);
}

/** LLVM's numbering of the ldm/stm modes (ARM_AM::AMSubMode), indexed by bits 24:23. */
const SUBMODE = [3, 1, 4, 2] as const;

const BARRIER_OPTIONS = ['#0x0', 'oshld', 'oshst', 'osh', '#0x4', 'nshld', 'nshst', 'nsh', '#0x8', 'ishld', 'ishst', 'ish', '#0xc', 'ld', 'st', 'sy'] as const;

function unconditionalMisc(w: number, pc: number): Insn {
  const op1 = bits(w, 26, 20);
  if (op1 === 0x10) {
    if (bit(w, 16)) return (w & 0x0ffffdff) === 0x01010000 ? mkU('setend', [text(bit(w, 9) ? 'be' : 'le')]) : none(w);
    return changeProcessorState(w);
  }
  if (op1 === 0x11) {
    // setpan: only bits 7:4 must be zero; the other unused bits are UNPREDICTABLE.
    if (bits(w, 7, 4) !== 0) return none(w);
    return mkU('setpan', [immHex(bit(w, 9))]);
  }
  if (op1 === 0x57) {
    const option = w & 15;
    if (bits(w, 7, 4) === 7) return mkU('sb', []);
    if (bits(w, 19, 8) !== 0xff0) return none(w);
    switch (bits(w, 7, 4)) {
      case 1:
        return option === 15 ? mkU('clrex', []) : none(w);
      case 4:
        if (option === 0) return mkU('ssbb', []);
        if (option === 4) return mkU('pssbb', []);
        return mkU('dsb', [text(BARRIER_OPTIONS[option]!)]);
      case 5:
        return mkU('dmb', [text(BARRIER_OPTIONS[option]!)]);
      case 6:
        return mkU('isb', [text(option === 15 ? 'sy' : `#${hex(option)}`)]);
      default:
        return none(w);
    }
  }
  // Preloads: pli (bits 26:24 = 100), pld/pldw (101, bit 22 = 1 for pld).
  if ((op1 & 0x47) === 0x45 || (op1 & 0x47) === 0x41) {
    const isReg = bit(w, 25);
    if ((isReg && bit(w, 4)) || bits(w, 15, 12) !== 15) return none(w);
    const m = op1 & 0x10 ? (bit(w, 22) ? 'pld' : 'pldw') : 'pli';
    if (m === 'pli' && !bit(w, 22)) return none(w);
    return preload(w, pc, m);
  }
  return none(w);
}

/** pld, pldw, pli: addressing mode 2 without writeback. */
function preload(w: number, pc: number, m: string): Insn {
  const u = bit(w, 23);
  const rn = bits(w, 19, 16);
  const base = r(rn);
  if (!bit(w, 25)) {
    const imm = w & 0xfff;
    const t = u ? (imm ? `[${base}, #${hex(imm)}]` : `[${base}]`) : `[${base}, #-${hex(imm)}]`;
    const extra: Partial<Insn> = rn === PC ? { target: pcRelative(pc, u ? imm : -imm) } : {};
    return mkU(m, [mem(rn, t, 'off', u ? imm : -imm)], 0, extra);
  }
  const rm = bits(w, 3, 0);
  const sh = shiftText(bits(w, 6, 5), bits(w, 11, 7));
  return mkU(m, [mem(rn, `[${base}, ${u ? '' : '-'}${r(rm)}${sh ? `, ${sh}` : ''}]`, 'off', undefined, rm)]);
}

/**
 * cps, cpsie, cpsid: the interrupt masks and the mode. LLVM's encodings want
 * bits 15:9 zero, and a zero mode unless M (bit 17) says it changes; but it
 * also reaches its cps decoder from the qadd and smla<x><y> encodings it
 * shares (bits 7:4 = 0101, 1000, 1100), which look at neither.
 */
function changeProcessorState(w: number): Insn {
  const low = bits(w, 7, 4);
  const imod = bits(w, 19, 18);
  const changeMode = bit(w, 17);
  const mode = w & 31;
  const shared = low === 5 || low === 8 || low === 12;
  if (bit(w, 5) || bit(w, 16) || imod === 1) return none(w);
  if (!shared && (bits(w, 15, 9) || (!changeMode && mode))) return none(w);
  if (!imod) return mkU('cps', [immHex(mode)]);
  const flags = bits(w, 8, 6);
  const names = (flags & 4 ? 'a' : '') + (flags & 2 ? 'i' : '') + (flags & 1 ? 'f' : '') || 'none';
  const ops: Op[] = [text(names)];
  if (changeMode) ops.push(immHex(mode));
  return mkU(imod === 2 ? 'cpsie' : 'cpsid', ops);
}
