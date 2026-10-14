/**
 * T32 outside floating point and SIMD: the 16-bit instructions and the 32-bit
 * Thumb-2 ones — data processing, loads and stores, branches, IT, status
 * registers, hints, barriers and the coprocessor instructions.
 *
 * The sections follow the T32 encoding tables of the Arm Architecture
 * Reference Manual. What is printed, and which encodings are refused, follow
 * LLVM's disassembler: an UNPREDICTABLE encoding that LLVM still names is
 * named here too, and one it refuses comes out as `.inst`.
 *
 * Most T32 instructions carry no condition of their own: an IT block lends
 * them one, which `it` brings in (-1 outside a block). LLVM prints it after the
 * mnemonic and before a `.w` (`ldrne.w`), and the 16-bit data-processing
 * instructions lose their `s` inside a block, where they do not set the flags.
 */

import { CONDS, F, bit, hex, immDec, immHex, immText, itConditions, itSuffix, label, list, r, reg, regList, sext, shift, text, unknown, type Insn, type Op } from './types';

/* ------------------------------------------------------------------ *
 * Building instructions
 * ------------------------------------------------------------------ */

/** The condition suffix an IT block gives: `eq`…`le`, nothing for al, `<und>` for the 15 an `it al` block's else slots get. */
const condSuffix = (it: number): string => (it < 0 ? '' : it === 15 ? '<und>' : CONDS[it]!);

/**
 * An instruction that takes the IT block's condition: `base` before it, `q`
 * (`.w`) after it. A conditional one also reads the flags.
 */
function mk(it: number, size: 2 | 4, base: string, q: string, ops: Op[], f: number, extra?: Partial<Insn>): Insn {
  const insn: Insn = { m: base + condSuffix(it) + q, ops, f, size };
  if (it >= 0 && it !== 14) {
    insn.f |= F.COND | F.READS_FLAGS;
    if (it !== 15) insn.cond = CONDS[it];
  }
  if (extra) Object.assign(insn, extra);
  return insn;
}

/** An instruction LLVM prints without the IT block's condition (cbz, b<c>, cps, setend, crc32…). */
function plain(size: 2 | 4, m: string, ops: Op[], f: number, extra?: Partial<Insn>): Insn {
  const insn: Insn = { m, ops, f, size };
  if (extra) Object.assign(insn, extra);
  return insn;
}

const R = (n: number): Op => reg(r(n));
const pcAligned = (pc: number): number => ((pc + 4) & ~3) >>> 0;

/** A memory operand; `t` is LLVM's whole bracketed text. */
function mem(base: number, t: string, mode: 'off' | 'pre' | 'post', off?: number, index?: number): Op {
  const op: Op = { k: 'mem', base: r(base), t, mode };
  if (off !== undefined) op.off = off;
  if (index !== undefined) op.index = r(index);
  return op;
}

/** `[r1, #0x4]`, `[r1]` for 0: the T16 immediate forms, imm12 and the exclusive ones (hex). */
const memHex = (rn: number, imm: number): Op => mem(rn, imm ? `[${r(rn)}, #${hex(imm)}]` : `[${r(rn)}]`, 'off', imm);

/** `[r1, #-8]`, `[r1, #8]`, `[r1]`: the T2 8-bit forms (decimal); `#-0` is kept when the U bit is clear. */
function memDec(rn: number, imm: number, add: boolean, always = false): string {
  if (!add) return `[${r(rn)}, #-${imm}]`;
  return imm || always ? `[${r(rn)}, #${imm}]` : `[${r(rn)}]`;
}

/** `[pc, #0x10]`, `[pc, #-0x10]`, `[pc, #-0x0]`: LLVM's literal operand (printThumbLdrLabelOperand). */
const memLiteral = (imm: number, add: boolean): Op => mem(15, `[pc, #${add ? '' : '-'}${hex(imm)}]`, 'off', add ? imm : -imm);

const SHIFTS = ['lsl', 'lsr', 'asr', 'ror'] as const;

/** A register with a constant shift, as t2_so_reg prints it: nothing for lsl #0, #32 for lsr/asr #0, rrx for ror #0. */
function soReg(rm: number, type: number, amount: number): Op[] {
  if (type === 0 && amount === 0) return [R(rm)];
  if (type === 3 && amount === 0) return [R(rm), shift('rrx')];
  return [R(rm), shift(`${SHIFTS[type]} #${amount === 0 ? 32 : amount}`)];
}

/** ThumbExpandImm: an 8-bit value repeated across the word, or rotated into place. */
function expandImm(imm12: number): number {
  if (imm12 >> 10 === 0) {
    const b = imm12 & 0xff;
    switch ((imm12 >> 8) & 3) {
      case 0:
        return b;
      case 1:
        return ((b << 16) | b) >>> 0;
      case 2:
        return ((b << 24) | (b << 8)) >>> 0;
      default:
        return (b * 0x01010101) >>> 0;
    }
  }
  const unrot = 0x80 | (imm12 & 0x7f);
  const rot = (imm12 >> 7) & 31;
  return ((unrot >>> rot) | (unrot << (32 - rot))) >>> 0;
}

/** Load and store flags with the size moved; a load to pc is an indirect branch. */
function ldFlags(rt: number): number {
  return rt === 15 ? F.LOAD | F.BRANCH | F.INDIRECT : F.LOAD;
}

/** Flags of a data-processing instruction writing `rd`: writing pc branches. */
const dpFlags = (rd: number, setsFlags: boolean): number => (setsFlags ? F.SETS_FLAGS : 0) | (rd === 15 ? F.BRANCH | F.INDIRECT : 0);

/* ------------------------------------------------------------------ *
 * 16-bit instructions
 * ------------------------------------------------------------------ */

const DP16 = ['and', 'eor', 'lsl', 'lsr', 'asr', 'adc', 'sbc', 'ror', 'tst', 'rsb', 'cmp', 'cmn', 'orr', 'mul', 'bic', 'mvn'] as const;
const LDST16 = ['str', 'strh', 'strb', 'ldrsb', 'ldr', 'ldrh', 'ldrb', 'ldrsh'] as const;
const LDST16_BYTES = [4, 2, 1, 1, 4, 2, 1, 2];
const HINTS16 = ['nop', 'yield', 'wfe', 'wfi', 'sev', 'sevl'] as const;

export function decodeT16(hw: number, pc: number, it: number): Insn {
  const inIt = it >= 0;
  // Inside an IT block the 16-bit data-processing instructions do not set the flags, and LLVM drops their `s`.
  const s = inIt ? '' : 's';
  const sf = inIt ? 0 : F.SETS_FLAGS;
  const rd = hw & 7;
  const rn = (hw >> 3) & 7;
  switch (hw >>> 11) {
    // Shift by an immediate; lsl #0 is the flag-setting move LLVM calls movs even inside an IT block.
    case 0x00: {
      const imm = (hw >> 6) & 31;
      if (imm === 0) return plain(2, 'movs', [R(rd), R(rn)], F.SETS_FLAGS);
      return mk(it, 2, 'lsl' + s, '', [R(rd), R(rn), immHex(imm)], sf);
    }
    case 0x01:
    case 0x02: {
      const imm = (hw >> 6) & 31 || 32;
      return mk(it, 2, (hw >>> 11 === 1 ? 'lsr' : 'asr') + s, '', [R(rd), R(rn), immHex(imm)], sf);
    }
    // Add and subtract, three low registers or a 3-bit immediate.
    case 0x03: {
      const m = (bit(hw, 9) ? 'sub' : 'add') + s;
      const third = bit(hw, 10) ? immHex((hw >> 6) & 7) : R((hw >> 6) & 7);
      return mk(it, 2, m, '', [R(rd), R(rn), third], sf);
    }
    // Move, compare, add and subtract with an 8-bit immediate.
    case 0x04:
    case 0x05:
    case 0x06:
    case 0x07: {
      const rdn = (hw >> 8) & 7;
      const op = (hw >> 11) & 3;
      const imm = immHex(hw & 0xff);
      if (op === 1) return mk(it, 2, 'cmp', '', [R(rdn), imm], F.SETS_FLAGS);
      return mk(it, 2, ['mov', '', 'add', 'sub'][op]! + s, '', [R(rdn), imm], sf);
    }
    case 0x08:
      if (!bit(hw, 10)) return dataProcessing16(hw, it, s, sf);
      return special16(hw, it);
    // ldr rt, [pc, #imm]: a literal word.
    case 0x09: {
      const imm = (hw & 0xff) * 4;
      const target = pcAligned(pc) + imm;
      return mk(it, 2, 'ldr', '', [R((hw >> 8) & 7), mem(15, `[pc, #${hex(imm)}]`, 'off', imm)], F.LOAD, { target: target >>> 0, bytes: 4 });
    }
    // Loads and stores with a register offset.
    case 0x0a:
    case 0x0b: {
      const op = (hw >> 9) & 7;
      const rm = (hw >> 6) & 7;
      const m = LDST16[op]!;
      return mk(it, 2, m, '', [R(rd), mem(rn, `[${r(rn)}, ${r(rm)}]`, 'off', undefined, rm)], op < 3 ? F.STORE : F.LOAD, { bytes: LDST16_BYTES[op]! });
    }
    // Loads and stores with a 5-bit immediate offset: words scale it by 4, halfwords by 2.
    case 0x0c:
    case 0x0d:
    case 0x0e:
    case 0x0f:
    case 0x10:
    case 0x11: {
      const load = bit(hw, 11);
      const kind = hw >>> 13 === 3 ? (bit(hw, 12) ? 1 : 4) : 2;
      const imm = ((hw >> 6) & 31) * kind;
      const m = (load ? 'ldr' : 'str') + (kind === 1 ? 'b' : kind === 2 ? 'h' : '');
      return mk(it, 2, m, '', [R(rd), memHex(rn, imm)], load ? F.LOAD : F.STORE, { bytes: kind });
    }
    // Loads and stores relative to sp.
    case 0x12:
    case 0x13: {
      const load = bit(hw, 11);
      return mk(it, 2, load ? 'ldr' : 'str', '', [R((hw >> 8) & 7), memHex(13, (hw & 0xff) * 4)], load ? F.LOAD : F.STORE, { bytes: 4 });
    }
    // adr rd, #imm (decimal, as LLVM prints it) and add rd, sp, #imm.
    case 0x14: {
      const imm = (hw & 0xff) * 4;
      return mk(it, 2, 'adr', '', [R((hw >> 8) & 7), immDec(imm)], 0, { target: (pcAligned(pc) + imm) >>> 0 });
    }
    case 0x15:
      return mk(it, 2, 'add', '', [R((hw >> 8) & 7), reg('sp'), immHex((hw & 0xff) * 4)], 0);
    case 0x16:
    case 0x17:
      return misc16(hw, pc, it);
    // stm rn!, {…} and ldm rn{!}, {…}: the load writes back only when rn is not in the list.
    case 0x18:
    case 0x19: {
      const base = (hw >> 8) & 7;
      const mask = hw & 0xff;
      if (!mask) return unknown(hw, 2, true);
      const regs = regList(mask);
      if (!bit(hw, 11)) return mk(it, 2, 'stm', '', [reg(r(base), true), list(regs)], F.STORE, { bytes: 4 });
      return mk(it, 2, 'ldm', '', [reg(r(base), !(mask & (1 << base))), list(regs)], F.LOAD, { bytes: 4 });
    }
    // b<cond>, udf and svc.
    case 0x1a:
    case 0x1b: {
      const c = (hw >> 8) & 15;
      const imm8 = hw & 0xff;
      if (c === 14) {
        // LLVM names two udf values after their use: the trap and the divide-by-zero break.
        if (imm8 === 0xfe) return plain(2, 'trap', [], F.TRAP);
        if (imm8 === 0xf9) return plain(2, '__brkdiv0', [], F.TRAP);
        return plain(2, 'udf', [immHex(imm8)], F.TRAP);
      }
      if (c === 15) return mk(it, 2, 'svc', '', [immHex(imm8)], 0);
      const target = (pc + 4 + sext(imm8, 8) * 2) >>> 0;
      return condBranch(2, c, it, '', target);
    }
    case 0x1c: {
      const target = (pc + 4 + sext(hw & 0x7ff, 11) * 2) >>> 0;
      return mk(it, 2, 'b', '', [label(target)], F.BRANCH, { target });
    }
    default:
      return unknown(hw, 2, true);
  }
}

/**
 * b<cond>: inside an IT block (UNPREDICTABLE) LLVM puts the block's condition
 * in place of the encoded one, and prints that.
 */
function condBranch(size: 2 | 4, c: number, it: number, q: string, target: number): Insn {
  const shown = it >= 0 ? it : c;
  const insn = plain(size, 'b' + condSuffix(shown) + q, [label(target)], F.BRANCH, { target });
  if (shown !== 14) {
    insn.f |= F.COND | F.READS_FLAGS;
    if (shown !== 15) insn.cond = CONDS[shown];
  }
  return insn;
}

/** 010000: the two-register data-processing instructions. */
function dataProcessing16(hw: number, it: number, s: string, sf: number): Insn {
  const op = (hw >> 6) & 15;
  const rdn = hw & 7;
  const rm = (hw >> 3) & 7;
  const name = DP16[op]!;
  switch (op) {
    case 8: // tst
    case 10: // cmp
    case 11: // cmn
      return mk(it, 2, name, '', [R(rdn), R(rm)], F.SETS_FLAGS);
    case 9: // rsbs rd, rn, #0
      return mk(it, 2, 'rsb' + s, '', [R(rdn), R(rm), immText(0, '#0')], sf);
    case 13: // muls rd, rn, rd
      return mk(it, 2, 'mul' + s, '', [R(rdn), R(rm), R(rdn)], sf);
    case 5: // adc
    case 6: // sbc
    case 7: // ror
      return mk(it, 2, name + s, '', [R(rdn), R(rm)], sf | (op === 7 ? 0 : F.READS_FLAGS));
    default:
      return mk(it, 2, name + s, '', [R(rdn), R(rm)], sf);
  }
}

/** 010001: add, cmp and mov on any registers, bx and blx. */
function special16(hw: number, it: number): Insn {
  const rdn = (hw & 7) | (bit(hw, 7) << 3);
  const rm = (hw >> 3) & 15;
  switch ((hw >> 8) & 3) {
    case 0:
      if (rm === 13) return mk(it, 2, 'add', '', [R(rdn), reg('sp'), R(rdn)], dpFlags(rdn, false));
      if (rdn === 13) return mk(it, 2, 'add', '', [reg('sp'), R(rm)], 0);
      return mk(it, 2, 'add', '', [R(rdn), R(rm)], dpFlags(rdn, false));
    case 1:
      return mk(it, 2, 'cmp', '', [R(rdn), R(rm)], F.SETS_FLAGS);
    case 2: {
      let f = 0;
      if (rdn === 15) f = rm === 14 ? F.BRANCH | F.RET | F.INDIRECT : F.BRANCH | F.INDIRECT;
      return mk(it, 2, 'mov', '', [R(rdn), R(rm)], f);
    }
    default:
      if (!bit(hw, 7)) return mk(it, 2, 'bx', '', [R(rm)], rm === 14 ? F.BRANCH | F.RET | F.INDIRECT : F.BRANCH | F.INDIRECT);
      if (hw & 7) return unknown(hw, 2, true);
      return mk(it, 2, 'blx', '', [R(rm)], F.CALL | F.INDIRECT);
  }
}

/** 1011: the miscellaneous 16-bit instructions. */
function misc16(hw: number, pc: number, it: number): Insn {
  const rd = hw & 7;
  const rm = (hw >> 3) & 7;
  switch ((hw >> 8) & 15) {
    case 0x0: {
      const imm = (hw & 0x7f) * 4;
      return mk(it, 2, bit(hw, 7) ? 'sub' : 'add', '', [reg('sp'), immHex(imm)], 0);
    }
    case 0x1:
    case 0x3:
    case 0x9:
    case 0xb: {
      // cbz/cbnz rn, label: always forward, and never conditional on an IT block.
      const off = ((bit(hw, 9) << 5) | ((hw >> 3) & 31)) * 2;
      const target = (pc + 4 + off) >>> 0;
      return plain(2, bit(hw, 11) ? 'cbnz' : 'cbz', [R(rd), label(target)], F.BRANCH | F.COND, { target });
    }
    case 0x2:
      return mk(it, 2, ['sxth', 'sxtb', 'uxth', 'uxtb'][(hw >> 6) & 3]!, '', [R(rd), R(rm)], 0);
    case 0x4:
    case 0x5: {
      const mask = (hw & 0xff) | (bit(hw, 8) << 14);
      if (!mask) return unknown(hw, 2, true);
      return mk(it, 2, 'push', '', [list(regList(mask))], F.STORE, { bytes: 4 });
    }
    case 0x6: {
      const op = (hw >> 5) & 7;
      if (op === 0) return plain(2, 'setpan', [immHex(bit(hw, 3))], 0);
      if (op === 2 && bit(hw, 4) && !(hw & 7)) return plain(2, 'setend', [text(bit(hw, 3) ? 'be' : 'le')], 0);
      if (op === 3 && !bit(hw, 3)) {
        const flags = (bit(hw, 2) ? 'a' : '') + (bit(hw, 1) ? 'i' : '') + (bit(hw, 0) ? 'f' : '');
        return plain(2, bit(hw, 4) ? 'cpsid' : 'cpsie', [text(flags || 'none')], 0);
      }
      return unknown(hw, 2, true);
    }
    case 0xa: {
      const op = (hw >> 6) & 3;
      if (op === 2) return plain(2, 'hlt', [immHex(hw & 0x3f)], F.TRAP);
      return mk(it, 2, ['rev', 'rev16', '', 'revsh'][op]!, '', [R(rd), R(rm)], 0);
    }
    case 0xc:
    case 0xd: {
      const mask = (hw & 0xff) | (bit(hw, 8) << 15);
      if (!mask) return unknown(hw, 2, true);
      const f = bit(hw, 8) ? F.LOAD | F.BRANCH | F.RET | F.INDIRECT : F.LOAD;
      return mk(it, 2, 'pop', '', [list(regList(mask))], f, { bytes: 4 });
    }
    case 0xe:
      return plain(2, 'bkpt', [immHex(hw & 0xff)], F.TRAP);
    case 0xf: {
      const mask = hw & 15;
      if (mask) return itInstruction(hw);
      const op = (hw >> 4) & 15;
      if (op < 6) return mk(it, 2, HINTS16[op]!, '', [], 0);
      return mk(it, 2, 'hint', '', [immHex(op)], 0);
    }
    default:
      return unknown(hw, 2, true);
  }
}

/**
 * it{t|e}{t|e}{t|e} cond. A first condition of 15 is read as al, as LLVM does,
 * so the else slots of such a block get the condition 15 that prints `<und>`.
 */
function itInstruction(hw: number): Insn {
  const mask = hw & 15;
  let first = (hw >> 4) & 15;
  if (first === 15) first = 14;
  return plain(2, 'it' + itSuffix(first, mask), [text(first === 14 ? 'al' : CONDS[first]!)], 0, { it: itConditions(first, mask) });
}

/* ------------------------------------------------------------------ *
 * 32-bit instructions
 * ------------------------------------------------------------------ */

export function decodeT32Base(word: number, pc: number, it: number): Insn {
  const w = word >>> 0;
  switch ((w >>> 27) & 3) {
    case 1:
      if (bit(w, 26)) return coprocessor(w, it);
      if (bit(w, 25)) return dpShiftedRegister(w, it);
      return bit(w, 22) ? loadStoreDual(w, pc, it) : loadStoreMultiple(w, it);
    case 2:
      if (bit(w, 15)) return branchesMisc(w, pc, it);
      return bit(w, 25) ? dpPlainImmediate(w, pc, it) : dpModifiedImmediate(w, it);
    case 3:
      if (bit(w, 26)) return coprocessor(w, it);
      switch ((w >>> 23) & 7) {
        case 0:
        case 1:
        case 2:
        case 3:
          return loadStore(w, pc, it);
        case 4:
        case 5:
          return dpRegister(w, it);
        case 6:
          return multiply(w, it);
        default:
          return longMultiply(w, it);
      }
    default:
      return unknown(w, 4, true);
  }
}

/* ------------------------------------------------------------------ *
 * Load and store multiple, srs and rfe
 * ------------------------------------------------------------------ */

function loadStoreMultiple(w: number, it: number): Insn {
  const op = (w >>> 23) & 3;
  const wb = bit(w, 21);
  const load = bit(w, 20);
  const rn = (w >>> 16) & 15;
  if (op === 0 || op === 3) {
    const m = op === 0 ? 'db' : 'ia';
    if (load) {
      if ((w & 0xffff) !== 0xc000) return unknown(w, 4, true);
      return mk(it, 4, 'rfe' + m, '', [reg(r(rn), !!wb)], F.BRANCH | F.RET | F.INDIRECT | F.LOAD);
    }
    if (rn !== 13 || (w & 0xffe0) !== 0xc000) return unknown(w, 4, true);
    return mk(it, 4, 'srs' + m, '', [reg('sp', !!wb), immHex(w & 31)], F.STORE);
  }
  const mask = w & 0xffff;
  // A store list may not hold pc or sp.
  if (!load && mask & 0xa000) return unknown(w, 4, true);
  if (!mask) return unknown(w, 4, true);
  const regs = regList(mask);
  const many = regs.length > 1;
  if (load) {
    let f = F.LOAD;
    if (mask & 0x8000) f |= rn === 13 && wb && op === 1 ? F.BRANCH | F.RET | F.INDIRECT : F.BRANCH | F.INDIRECT;
    if (op === 1 && wb && rn === 13 && many) return mk(it, 4, 'pop', '.w', [list(regs)], f, { bytes: 4 });
    return mk(it, 4, op === 1 ? 'ldm' : 'ldmdb', op === 1 ? '.w' : '', [reg(r(rn), !!wb), list(regs)], f, { bytes: 4 });
  }
  if (op === 2 && wb && rn === 13 && many) return mk(it, 4, 'push', '.w', [list(regs)], F.STORE, { bytes: 4 });
  return mk(it, 4, op === 1 ? 'stm' : 'stmdb', op === 1 ? '.w' : '', [reg(r(rn), !!wb), list(regs)], F.STORE, { bytes: 4 });
}

/* ------------------------------------------------------------------ *
 * Load and store dual, exclusive, acquire/release, table branch
 * ------------------------------------------------------------------ */

function loadStoreDual(w: number, pc: number, it: number): Insn {
  const p = bit(w, 24);
  const u = bit(w, 23);
  const wb = bit(w, 21);
  const load = bit(w, 20);
  const rn = (w >>> 16) & 15;
  const rt = (w >>> 12) & 15;
  const rt2 = (w >>> 8) & 15;
  if (p || wb) {
    // ldrd/strd: the offset is a multiple of 4, printed in decimal.
    const imm = (w & 0xff) * 4;
    const add = !!u;
    const f = load ? F.LOAD : F.STORE;
    const extra: Partial<Insn> = { bytes: 4 };
    if (rn === 15) extra.target = (pcAligned(pc) + (add ? imm : -imm)) >>> 0;
    const off = add ? imm : -imm;
    let addr: Op;
    if (!p) addr = mem(rn, `[${r(rn)}], #${add ? '' : '-'}${imm}`, 'post', off);
    else if (wb) addr = mem(rn, `${memDec(rn, imm, add, true)}!`, 'pre', off);
    else addr = mem(rn, memDec(rn, imm, add), 'off', off);
    return mk(it, 4, load ? 'ldrd' : 'strd', '', [R(rt), R(rt2), addr], f, extra);
  }
  if (!u) {
    // ldrex/strex with an offset (a multiple of 4, hex).
    const imm = (w & 0xff) * 4;
    if (load) {
      if (rt2 !== 15) return unknown(w, 4, true);
      return mk(it, 4, 'ldrex', '', [R(rt), memHex(rn, imm)], F.LOAD | F.ATOMIC, { bytes: 4 });
    }
    return mk(it, 4, 'strex', '', [R(rt2), R(rt), memHex(rn, imm)], F.STORE | F.ATOMIC, { bytes: 4 });
  }
  const op = (w >>> 4) & 15;
  const rd = w & 15;
  const plainMem = mem(rn, `[${r(rn)}]`, 'off', 0);
  if (load) {
    if (op === 0 || op === 1) {
      // tbb [rn, rm] / tbh [rn, rm, lsl #1]
      if ((w & 0xffe0) !== 0xf000) return unknown(w, 4, true);
      const t = op ? `[${r(rn)}, ${r(rd)}, lsl #1]` : `[${r(rn)}, ${r(rd)}]`;
      return mk(it, 4, op ? 'tbh' : 'tbb', '', [mem(rn, t, 'off', undefined, rd)], F.BRANCH | F.INDIRECT | F.LOAD, { bytes: op ? 2 : 1 });
    }
    if (rd !== 15) return unknown(w, 4, true);
    switch (op) {
      case 4:
      case 5:
      case 12:
      case 13: {
        if (rt2 !== 15) return unknown(w, 4, true);
        const m = (op & 8 ? 'ldaex' : 'ldrex') + (op & 1 ? 'h' : 'b');
        return mk(it, 4, m, '', [R(rt), plainMem], F.LOAD | F.ATOMIC, { bytes: op & 1 ? 2 : 1 });
      }
      case 7:
      case 15:
        return mk(it, 4, op & 8 ? 'ldaexd' : 'ldrexd', '', [R(rt), R(rt2), plainMem], F.LOAD | F.ATOMIC, { bytes: 4 });
      case 8:
      case 9:
      case 10:
        if (rt2 !== 15) return unknown(w, 4, true);
        return mk(it, 4, ['ldab', 'ldah', 'lda'][op - 8]!, '', [R(rt), plainMem], F.LOAD | F.ATOMIC, { bytes: [1, 2, 4][op - 8]! });
      case 14:
        if (rt2 !== 15) return unknown(w, 4, true);
        return mk(it, 4, 'ldaex', '', [R(rt), plainMem], F.LOAD | F.ATOMIC, { bytes: 4 });
      default:
        return unknown(w, 4, true);
    }
  }
  switch (op) {
    case 4:
    case 5:
    case 12:
    case 13:
    case 14: {
      if (rt2 !== 15) return unknown(w, 4, true);
      const m = (op & 8 ? 'stlex' : 'strex') + (op === 14 ? '' : op & 1 ? 'h' : 'b');
      return mk(it, 4, m, '', [R(rd), R(rt), plainMem], F.STORE | F.ATOMIC, { bytes: op === 14 ? 4 : op & 1 ? 2 : 1 });
    }
    case 7:
    case 15:
      return mk(it, 4, op & 8 ? 'stlexd' : 'strexd', '', [R(rd), R(rt), R(rt2), plainMem], F.STORE | F.ATOMIC, { bytes: 4 });
    case 8:
    case 9:
    case 10:
      if (rt2 !== 15 || rd !== 15) return unknown(w, 4, true);
      return mk(it, 4, ['stlb', 'stlh', 'stl'][op - 8]!, '', [R(rt), plainMem], F.STORE | F.ATOMIC, { bytes: [1, 2, 4][op - 8]! });
    default:
      return unknown(w, 4, true);
  }
}

/* ------------------------------------------------------------------ *
 * Data processing with a shifted register
 * ------------------------------------------------------------------ */

function dpShiftedRegister(w: number, it: number): Insn {
  const op = (w >>> 21) & 15;
  const sBit = bit(w, 20);
  const s = sBit ? 's' : '';
  const rn = (w >>> 16) & 15;
  const rd = (w >>> 8) & 15;
  const rm = w & 15;
  const type = (w >>> 4) & 3;
  const amount = (((w >>> 12) & 7) << 2) | ((w >>> 6) & 3);
  const shifted = soReg(rm, type, amount);
  const flags = dpFlags(rd, !!sBit);
  switch (op) {
    case 0: // and / tst
      if (rd === 15 && sBit) return mk(it, 4, 'tst', '.w', [R(rn), ...shifted], F.SETS_FLAGS);
      return mk(it, 4, 'and' + s, '.w', [R(rd), R(rn), ...shifted], flags);
    case 1:
      return mk(it, 4, 'bic' + s, '.w', [R(rd), R(rn), ...shifted], flags);
    case 2: // orr / mov and the shifts
      if (rn !== 15) {
        if (bit(w, 15)) return unknown(w, 4, true);
        return mk(it, 4, 'orr' + s, '.w', [R(rd), R(rn), ...shifted], flags);
      }
      return moveShift(w, it, rd, rm, type, amount, s, flags);
    case 3: // orn / mvn
      if (rn === 15) return mk(it, 4, 'mvn' + s, '.w', [R(rd), ...shifted], flags);
      return mk(it, 4, 'orn' + s, '', [R(rd), R(rn), ...shifted], flags);
    case 4: // eor / teq
      if (rd === 15 && sBit) return mk(it, 4, 'teq', '.w', [R(rn), ...shifted], F.SETS_FLAGS);
      return mk(it, 4, 'eor' + s, '.w', [R(rd), R(rn), ...shifted], flags);
    case 6: {
      // pkhbt rd, rn, rm{, lsl #n} / pkhtb rd, rn, rm, asr #n
      if (sBit || bit(w, 4)) return unknown(w, 4, true);
      const tb = bit(w, 5);
      const ops: Op[] = [R(rd), R(rn), R(rm)];
      if (tb) ops.push(shift(`asr #${amount || 32}`));
      else if (amount) ops.push(shift(`lsl #${amount}`));
      return mk(it, 4, tb ? 'pkhtb' : 'pkhbt', '', ops, 0);
    }
    case 8: // add / cmn
      if (rd === 15 && sBit) return mk(it, 4, 'cmn', '.w', [R(rn), ...shifted], F.SETS_FLAGS);
      return mk(it, 4, 'add' + s, '.w', [R(rd), R(rn), ...shifted], flags);
    case 10:
      return mk(it, 4, 'adc' + s, '.w', [R(rd), R(rn), ...shifted], flags | F.READS_FLAGS);
    case 11:
      return mk(it, 4, 'sbc' + s, '.w', [R(rd), R(rn), ...shifted], flags | F.READS_FLAGS);
    case 13: // sub / cmp
      if (rd === 15 && sBit) return mk(it, 4, 'cmp', '.w', [R(rn), ...shifted], F.SETS_FLAGS);
      return mk(it, 4, 'sub' + s, '.w', [R(rd), R(rn), ...shifted], flags);
    case 14:
      return mk(it, 4, 'rsb' + s, '', [R(rd), R(rn), ...shifted], flags);
    default:
      return unknown(w, 4, true);
  }
}

/** orr with rn = pc: mov.w, the constant shifts (lsl.w…) and rrx. */
function moveShift(w: number, it: number, rd: number, rm: number, type: number, amount: number, s: string, flags: number): Insn {
  if (type === 3 && amount === 0) return mk(it, 4, 'rrx' + s, '', [R(rd), R(rm)], flags | F.READS_FLAGS);
  if (bit(w, 15)) return unknown(w, 4, true);
  if (type === 0 && amount === 0) {
    let f = flags;
    if (rd === 15) f = rm === 14 && !s ? F.BRANCH | F.RET | F.INDIRECT : flags;
    return mk(it, 4, 'mov' + s, '.w', [R(rd), R(rm)], f);
  }
  return mk(it, 4, SHIFTS[type] + s, '.w', [R(rd), R(rm), immHex(amount === 0 ? 32 : amount)], flags);
}

/* ------------------------------------------------------------------ *
 * Data processing with a modified immediate
 * ------------------------------------------------------------------ */

function dpModifiedImmediate(w: number, it: number): Insn {
  const op = (w >>> 21) & 15;
  const sBit = bit(w, 20);
  const s = sBit ? 's' : '';
  const rn = (w >>> 16) & 15;
  const rd = (w >>> 8) & 15;
  const imm12 = (bit(w, 26) << 11) | (((w >>> 12) & 7) << 8) | (w & 0xff);
  const value = expandImm(imm12);
  const imm = immHex(value);
  const flags = dpFlags(rd, !!sBit);
  switch (op) {
    case 0:
      if (rd === 15 && sBit) return mk(it, 4, 'tst', '.w', [R(rn), imm], F.SETS_FLAGS);
      return mk(it, 4, 'and' + s, '', [R(rd), R(rn), imm], flags);
    case 1:
      return mk(it, 4, 'bic' + s, '', [R(rd), R(rn), imm], flags);
    case 2:
      if (rn === 15) return mk(it, 4, 'mov' + s, '.w', [R(rd), imm], flags);
      return mk(it, 4, 'orr' + s, '', [R(rd), R(rn), imm], flags);
    case 3:
      if (rn === 15) return mk(it, 4, 'mvn' + s, '', [R(rd), imm], flags);
      return mk(it, 4, 'orn' + s, '', [R(rd), R(rn), imm], flags);
    case 4:
      if (rd === 15 && sBit) return mk(it, 4, 'teq', '.w', [R(rn), imm], F.SETS_FLAGS);
      return mk(it, 4, 'eor' + s, '', [R(rd), R(rn), imm], flags);
    case 8:
      if (rd === 15 && sBit) return mk(it, 4, 'cmn', '.w', [R(rn), imm], F.SETS_FLAGS);
      return mk(it, 4, 'add' + s, '.w', [R(rd), R(rn), imm], flags);
    case 10:
      return mk(it, 4, 'adc' + s, '', [R(rd), R(rn), imm], flags | F.READS_FLAGS);
    case 11:
      return mk(it, 4, 'sbc' + s, '', [R(rd), R(rn), imm], flags | F.READS_FLAGS);
    case 13:
      if (rd === 15 && sBit) return mk(it, 4, 'cmp', '.w', [R(rn), imm], F.SETS_FLAGS);
      return mk(it, 4, 'sub' + s, '.w', [R(rd), R(rn), imm], flags);
    case 14:
      return mk(it, 4, 'rsb' + s, '.w', [R(rd), R(rn), imm], flags);
    default:
      return unknown(w, 4, true);
  }
}

/* ------------------------------------------------------------------ *
 * Data processing with a plain binary immediate
 * ------------------------------------------------------------------ */

function dpPlainImmediate(w: number, pc: number, it: number): Insn {
  const op = (w >>> 20) & 31;
  const rn = (w >>> 16) & 15;
  const rd = (w >>> 8) & 15;
  const imm12 = (bit(w, 26) << 11) | (((w >>> 12) & 7) << 8) | (w & 0xff);
  switch (op) {
    case 0:
    case 10: {
      // addw/subw; on pc they are adr.w (decimal), except subw rd, pc, #0.
      const sub = op === 10;
      if (rn === 15 && !(sub && imm12 === 0)) {
        const off = sub ? -imm12 : imm12;
        return mk(it, 4, 'adr', '.w', [R(rd), immDec(off)], 0, { target: (pcAligned(pc) + off) >>> 0 });
      }
      const extra = rn === 15 ? { target: pcAligned(pc) } : undefined;
      return mk(it, 4, sub ? 'subw' : 'addw', '', [R(rd), R(rn), immHex(imm12)], dpFlags(rd, false), extra);
    }
    case 4:
    case 12: {
      const imm16 = (rn << 12) | imm12;
      return mk(it, 4, op === 4 ? 'movw' : 'movt', '', [R(rd), immHex(imm16)], 0);
    }
    case 16:
    case 18:
    case 24:
    case 26: {
      // ssat/usat rd, #n, rn{, shift}, and the 16-bit forms when the shift is asr #0.
      if (bit(w, 26) || bit(w, 5)) return unknown(w, 4, true);
      const unsigned = op >= 24;
      const sh = bit(w, 21);
      const amount = (((w >>> 12) & 7) << 2) | ((w >>> 6) & 3);
      const sat = w & 31;
      if (sh && amount === 0) {
        if (bit(w, 4)) return unknown(w, 4, true);
        return mk(it, 4, unsigned ? 'usat16' : 'ssat16', '', [R(rd), immHex(unsigned ? sat & 15 : (sat & 15) + 1), R(rn)], 0);
      }
      const ops: Op[] = [R(rd), immHex(unsigned ? sat : sat + 1), R(rn)];
      if (sh) ops.push(shift(`asr #${amount}`));
      else if (amount) ops.push(shift(`lsl #${amount}`));
      return mk(it, 4, unsigned ? 'usat' : 'ssat', '', ops, 0);
    }
    case 20:
    case 28: {
      const lsb = (((w >>> 12) & 7) << 2) | ((w >>> 6) & 3);
      const width = (w & 31) + 1;
      return mk(it, 4, op === 20 ? 'sbfx' : 'ubfx', '', [R(rd), R(rn), immHex(lsb), immHex(width)], 0);
    }
    case 22: {
      // bfi rd, rn, #lsb, #width / bfc rd, #lsb, #width (decimal); an msb below the lsb is read as msb.
      if (bit(w, 26) || bit(w, 5)) return unknown(w, 4, true);
      const msb = w & 31;
      let lsb = (((w >>> 12) & 7) << 2) | ((w >>> 6) & 3);
      if (lsb > msb) lsb = msb;
      const field = [immDec(lsb), immDec(msb - lsb + 1)];
      if (rn === 15) return mk(it, 4, 'bfc', '', [R(rd), ...field], 0);
      return mk(it, 4, 'bfi', '', [R(rd), R(rn), ...field], 0);
    }
    default:
      return unknown(w, 4, true);
  }
}

/* ------------------------------------------------------------------ *
 * Branches and miscellaneous control
 * ------------------------------------------------------------------ */

const BARRIERS = ['#0x0', 'oshld', 'oshst', 'osh', '#0x4', 'nshld', 'nshst', 'nsh', '#0x8', 'ishld', 'ishst', 'ish', '#0xc', 'ld', 'st', 'sy'] as const;

/** The 32-bit branch offset S:I1:I2:imm10:imm11:0, with I = not(J xor S). */
function branchOffset(w: number): number {
  const s = bit(w, 26);
  const i1 = bit(w, 13) ^ s ^ 1;
  const i2 = bit(w, 11) ^ s ^ 1;
  return sext((s << 24) | (i1 << 23) | (i2 << 22) | (((w >>> 16) & 0x3ff) << 12) | ((w & 0x7ff) << 1), 25);
}

function branchesMisc(w: number, pc: number, it: number): Insn {
  const op1 = (w >>> 12) & 7;
  if (op1 & 4) {
    // bl / blx: blx switches to A32 and aligns the target to a word.
    const off = branchOffset(w);
    if (op1 & 1) {
      const target = (pc + 4 + off) >>> 0;
      return mk(it, 4, 'bl', '', [label(target)], F.CALL, { target, thumb: true });
    }
    if (w & 1) return unknown(w, 4, true);
    const target = (pcAligned(pc) + off) >>> 0;
    return mk(it, 4, 'blx', '', [label(target)], F.CALL, { target, thumb: false });
  }
  if (op1 & 1) {
    const target = (pc + 4 + branchOffset(w)) >>> 0;
    return mk(it, 4, 'b', '.w', [label(target)], F.BRANCH, { target });
  }
  const cond = (w >>> 22) & 15;
  if (cond < 14) {
    // b<cond>.w: S:J2:J1:imm6:imm11:0.
    const off = sext((bit(w, 26) << 20) | (bit(w, 11) << 19) | (bit(w, 13) << 18) | (((w >>> 16) & 0x3f) << 12) | ((w & 0x7ff) << 1), 21);
    return condBranch(4, cond, it, '.w', (pc + 4 + off) >>> 0);
  }
  return miscControl(w, it);
}

function miscControl(w: number, it: number): Insn {
  const hw1 = w >>> 16;
  const hw2 = w & 0xffff;
  const op = (w >>> 20) & 0x7f;
  const rn = hw1 & 15;
  switch (op) {
    case 0x38:
    case 0x39: {
      // msr spec_reg, rn and msr banked_reg, rn
      if ((hw2 & 0xf000) !== 0x8000) return unknown(w, 4, true);
      const rBit = bit(w, 20);
      if (bit(w, 5)) {
        if ((hw2 & 0xef) !== 0x20) return unknown(w, 4, true);
        const name = bankedName((rBit << 5) | (bit(w, 4) << 4) | ((hw2 >> 8) & 15));
        if (!name) return unknown(w, 4, true);
        return mk(it, 4, 'msr', '', [text(name), R(rn)], 0);
      }
      if (hw2 & 0xff) return unknown(w, 4, true);
      const mask = (hw2 >> 8) & 15;
      if (!rBit && !mask) return unknown(w, 4, true);
      return mk(it, 4, 'msr', '', [text(msrMaskName(rBit, mask)), R(rn)], mask & 8 && !rBit ? F.SETS_FLAGS : 0);
    }
    case 0x3a:
      return hintSpace(w, it);
    case 0x3b:
      return barriers(w, it);
    case 0x3c:
      if (hw2 !== 0x8f00) return unknown(w, 4, true);
      return mk(it, 4, 'bxj', '', [R(rn)], F.BRANCH | F.INDIRECT);
    case 0x3d:
      // subs pc, lr, #imm (eret when 0)
      if (hw1 !== 0xf3de || (hw2 & 0xff00) !== 0x8f00) return unknown(w, 4, true);
      if (!(hw2 & 0xff)) return mk(it, 4, 'eret', '', [], F.BRANCH | F.RET);
      return mk(it, 4, 'subs', '', [reg('pc'), reg('lr'), immHex(hw2 & 0xff)], F.BRANCH | F.RET);
    case 0x3e:
    case 0x3f: {
      // mrs rd, apsr / spsr, and mrs rd, banked_reg
      if ((hw2 & 0xf000) !== 0x8000) return unknown(w, 4, true);
      const rd = (hw2 >> 8) & 15;
      if (bit(w, 5)) {
        if ((hw2 & 0xef) !== 0x20) return unknown(w, 4, true);
        const name = bankedName((bit(w, 20) << 5) | (bit(w, 4) << 4) | rn);
        if (!name) return unknown(w, 4, true);
        return mk(it, 4, 'mrs', '', [R(rd), text(name)], 0);
      }
      if (rn !== 15 || hw2 & 0xff) return unknown(w, 4, true);
      return mk(it, 4, 'mrs', '', [R(rd), reg(bit(w, 20) ? 'spsr' : 'apsr')], bit(w, 20) ? 0 : F.READS_FLAGS);
    }
    case 0x78:
      // dcps1-3
      if (hw1 === 0xf78f && (hw2 & 0xfffc) === 0x8000 && hw2 & 3) return mk(it, 4, `dcps${hw2 & 3}`, '', [], 0);
      return unknown(w, 4, true);
    case 0x7e:
      if ((hw2 & 0xf000) !== 0x8000) return unknown(w, 4, true);
      return plain(4, 'hvc.w', [immHex(((hw1 & 15) << 12) | (hw2 & 0xfff))], 0);
    case 0x7f:
      // udf.w #imm16 and smc #imm4
      if ((hw2 & 0xf000) === 0xa000) return plain(4, 'udf.w', [immHex(((hw1 & 15) << 12) | (hw2 & 0xfff))], F.TRAP);
      if ((hw2 & 0xf000) !== 0x8000) return unknown(w, 4, true);
      return mk(it, 4, 'smc', '', [immHex(hw1 & 15)], 0);
    default:
      return unknown(w, 4, true);
  }
}

/** msr's spec_reg: APSR_nzcvq, APSR_g, APSR_nzcvqg for cpsr's f and s masks, else CPSR_fsxc / SPSR_fsxc. */
function msrMaskName(rBit: number, mask: number): string {
  if (!rBit && (mask === 8 || mask === 4 || mask === 12)) return mask === 8 ? 'APSR_nzcvq' : mask === 4 ? 'APSR_g' : 'APSR_nzcvqg';
  let name = rBit ? 'SPSR' : 'CPSR';
  if (mask) name += '_' + (mask & 8 ? 'f' : '') + (mask & 4 ? 's' : '') + (mask & 2 ? 'x' : '') + (mask & 1 ? 'c' : '');
  return name;
}

const BANKED: Record<number, string> = {
  0x00: 'r8_usr', 0x01: 'r9_usr', 0x02: 'r10_usr', 0x03: 'r11_usr', 0x04: 'r12_usr', 0x05: 'sp_usr', 0x06: 'lr_usr',
  0x08: 'r8_fiq', 0x09: 'r9_fiq', 0x0a: 'r10_fiq', 0x0b: 'r11_fiq', 0x0c: 'r12_fiq', 0x0d: 'sp_fiq', 0x0e: 'lr_fiq',
  0x10: 'lr_irq', 0x11: 'sp_irq', 0x12: 'lr_svc', 0x13: 'sp_svc', 0x14: 'lr_abt', 0x15: 'sp_abt', 0x16: 'lr_und', 0x17: 'sp_und',
  0x1c: 'lr_mon', 0x1d: 'sp_mon', 0x1e: 'elr_hyp', 0x1f: 'sp_hyp',
  0x2e: 'SPSR_fiq', 0x30: 'SPSR_irq', 0x32: 'SPSR_svc', 0x34: 'SPSR_abt', 0x36: 'SPSR_und', 0x3c: 'SPSR_mon', 0x3e: 'SPSR_hyp',
};

const bankedName = (v: number): string | undefined => BANKED[v];

/** f3af 8xxx: cps, the hints (nop.w, wfe.w, esb.w, csdb, tsb csync, dbg…). */
function hintSpace(w: number, it: number): Insn {
  const hw1 = w >>> 16;
  const hw2 = w & 0xffff;
  if (hw1 !== 0xf3af || (hw2 & 0xf800) !== 0x8000) return unknown(w, 4, true);
  const imod = (hw2 >> 9) & 3;
  const m = bit(hw2, 8);
  if (imod || m) {
    if (imod === 1) return unknown(w, 4, true);
    const flags = (bit(hw2, 7) ? 'a' : '') + (bit(hw2, 6) ? 'i' : '') + (bit(hw2, 5) ? 'f' : '');
    const mode = hw2 & 31;
    if (!imod) return plain(4, 'cps', [immHex(mode)], 0);
    const name = imod === 2 ? 'cpsie' : 'cpsid';
    if (!m) return mode ? unknown(w, 4, true) : plain(4, name + '.w', [text(flags || 'none')], 0);
    return plain(4, name, [text(flags || 'none'), immHex(mode)], 0);
  }
  const imm = hw2 & 0xff;
  switch (imm) {
    case 0:
      return mk(it, 4, 'nop', '.w', [], 0);
    case 1:
      return mk(it, 4, 'yield', '.w', [], 0);
    case 2:
      return mk(it, 4, 'wfe', '.w', [], 0);
    case 3:
      return mk(it, 4, 'wfi', '.w', [], 0);
    case 4:
      return mk(it, 4, 'sev', '.w', [], 0);
    case 5:
      return mk(it, 4, 'sevl', '.w', [], 0);
    case 0x10:
      return mk(it, 4, 'esb', '.w', [], 0);
    case 0x12:
      return mk(it, 4, 'tsb', '', [text('csync')], 0);
    case 0x14:
      return mk(it, 4, 'csdb', '', [], 0);
    case 0x16:
      return mk(it, 4, 'clrbhb', '', [], 0);
    // The M-profile pointer authentication hints, which LLVM names whatever the profile, without an IT condition.
    case 0x0d:
    case 0x1d:
    case 0x2d:
      return plain(4, imm === 0x0d ? 'pacbti' : imm === 0x1d ? 'pac' : 'aut', [reg('r12'), reg('lr'), reg('sp')], 0);
    case 0x0f:
      return plain(4, 'bti', [], 0);
    default:
      if (imm >= 0xf0) return mk(it, 4, 'dbg', '', [immHex(imm & 15)], 0);
      return mk(it, 4, 'hint', '.w', [immHex(imm)], 0);
  }
}

/** f3bf 8f.x: clrex, dsb, dmb, isb, sb, and dsb's ssbb / pssbb. */
function barriers(w: number, it: number): Insn {
  const hw2 = w & 0xffff;
  const op = (hw2 >> 4) & 15;
  const opt = hw2 & 15;
  // sb tolerates other values in its should-be fields; the others are exact.
  if (op === 7 && (hw2 & 0xd000) === 0x8000) return plain(4, 'sb', [], 0);
  if (w >>> 16 !== 0xf3bf || (hw2 & 0xff00) !== 0x8f00) return unknown(w, 4, true);
  switch (op) {
    case 2:
      if (opt !== 15) return unknown(w, 4, true);
      return mk(it, 4, 'clrex', '', [], 0);
    case 4:
      if (opt === 0) return mk(it, 4, 'ssbb', '', [], 0);
      if (opt === 4) return mk(it, 4, 'pssbb', '', [], 0);
      return mk(it, 4, 'dsb', '', [text(BARRIERS[opt]!)], 0);
    case 5:
      return mk(it, 4, 'dmb', '', [text(BARRIERS[opt]!)], 0);
    case 6:
      return mk(it, 4, 'isb', '', [text(opt === 15 ? 'sy' : `#${hex(opt)}`)], 0);
    default:
      return unknown(w, 4, true);
  }
}

/* ------------------------------------------------------------------ *
 * Loads and stores of one register, and the preload hints
 * ------------------------------------------------------------------ */

const LD_NAMES = ['ldrb', 'ldrh', 'ldr', ''] as const;
const LDS_NAMES = ['ldrsb', 'ldrsh', '', ''] as const;
const ST_NAMES = ['strb', 'strh', 'str', ''] as const;

function loadStore(w: number, pc: number, it: number): Insn {
  const signed = bit(w, 24);
  const up = bit(w, 23);
  const size = (w >>> 21) & 3;
  const load = bit(w, 20);
  const rn = (w >>> 16) & 15;
  const rt = (w >>> 12) & 15;
  if (size === 3) return unknown(w, 4, true);
  const bytes = 1 << size;
  if (!load) {
    if (signed || rn === 15) return unknown(w, 4, true);
    return singleTransfer(w, it, ST_NAMES[size]!, rt, rn, up, bytes, false);
  }
  const name = signed ? LDS_NAMES[size]! : LD_NAMES[size]!;
  if (!name) return unknown(w, 4, true);
  if (rn === 15) {
    // Literal loads: [pc, #±imm12]; with rt = pc, the byte and halfword forms are preload hints.
    const imm = w & 0xfff;
    const target = (pcAligned(pc) + (up ? imm : -imm)) >>> 0;
    if (rt === 15 && size < 2) {
      // ldrh pc, [pc, …] falls on pldw in its offset forms, and pldw has no literal form.
      if (size === 1 && (signed || up || ((w >>> 6) & 63) === 0 || ((w >>> 8) & 15) === 12)) return unknown(w, 4, true);
      return mk(it, 4, signed ? 'pli' : 'pld', '', [memLiteral(imm, !!up)], 0, { target });
    }
    return mk(it, 4, name, '.w', [R(rt), memLiteral(imm, !!up)], ldFlags(rt), { target, bytes });
  }
  const op2 = (w >>> 6) & 63;
  if (rt === 15 && size < 2 && (up || op2 === 0 || op2 >> 2 === 12)) {
    // The preload hints in the offset forms: pld (byte), pldw (halfword), pli (signed byte); ldrsh pc is refused there.
    if (signed && size === 1) return unknown(w, 4, true);
    const hint = signed ? 'pli' : size ? 'pldw' : 'pld';
    if (up) return mk(it, 4, hint, '', [memHex(rn, w & 0xfff)], 0);
    if (op2 === 0) {
      const rm = w & 15;
      const sh = (w >>> 4) & 3;
      return mk(it, 4, hint, '', [mem(rn, `[${r(rn)}, ${r(rm)}${sh ? `, lsl #${sh}` : ''}]`, 'off', undefined, rm)], 0);
    }
    const imm = w & 0xff;
    return mk(it, 4, hint, '', [mem(rn, memDec(rn, imm, false), 'off', -imm)], 0);
  }
  return singleTransfer(w, it, name, rt, rn, up, bytes, true);
}

/** The addressing forms shared by loads and stores: imm12, register, negative imm8, unprivileged, post- and pre-indexed. */
function singleTransfer(w: number, it: number, name: string, rt: number, rn: number, up: number, bytes: number, load: boolean): Insn {
  const f = load ? ldFlags(rt) : F.STORE;
  if (up) return mk(it, 4, name, '.w', [R(rt), memHex(rn, w & 0xfff)], f, { bytes });
  if (((w >>> 6) & 63) === 0) {
    const rm = w & 15;
    const sh = (w >>> 4) & 3;
    return mk(it, 4, name, '.w', [R(rt), mem(rn, `[${r(rn)}, ${r(rm)}${sh ? `, lsl #${sh}` : ''}]`, 'off', undefined, rm)], f, { bytes });
  }
  const imm = w & 0xff;
  const add = !!bit(w, 9);
  switch ((w >>> 8) & 15) {
    case 12:
      return mk(it, 4, name, '', [R(rt), mem(rn, memDec(rn, imm, add), 'off', add ? imm : -imm)], f, { bytes });
    case 14:
      return mk(it, 4, name + 't', '', [R(rt), mem(rn, memDec(rn, imm, true), 'off', imm)], f, { bytes });
    case 9:
    case 11: {
      // ldr pc, [sp], #4 is a pop of the return address.
      const ret = load && rt === 15 && rn === 13 && add && imm === 4 ? F.RET : 0;
      return mk(it, 4, name, '', [R(rt), mem(rn, `[${r(rn)}], #${add ? '' : '-'}${imm}`, 'post', add ? imm : -imm)], f | ret, { bytes });
    }
    case 13:
    case 15:
      return mk(it, 4, name, '', [R(rt), mem(rn, `${memDec(rn, imm, add, true)}!`, 'pre', add ? imm : -imm)], f, { bytes });
    default:
      return unknown(w, 4, true);
  }
}

/* ------------------------------------------------------------------ *
 * Data processing on registers
 * ------------------------------------------------------------------ */

const PARALLEL_OPS = ['add8', 'add16', 'asx', '', 'sub8', 'sub16', 'sax', ''] as const;
const PARALLEL_PREFIX = ['s', 'q', 'sh', '', 'u', 'uq', 'uh', ''] as const;
const EXTENDS = ['sxth', 'uxth', 'sxtb16', 'uxtb16', 'sxtb', 'uxtb'] as const;
const EXTENDS_ADD = ['sxtah', 'uxtah', 'sxtab16', 'uxtab16', 'sxtab', 'uxtab'] as const;

function dpRegister(w: number, it: number): Insn {
  const op1 = (w >>> 20) & 15;
  const op2 = (w >>> 4) & 15;
  const rn = (w >>> 16) & 15;
  const rd = (w >>> 8) & 15;
  const rm = w & 15;
  if (((w >>> 12) & 15) !== 15) return unknown(w, 4, true);
  if (op1 < 8) {
    if (op2 === 0) {
      // lsl/lsr/asr/ror rd, rn, rm
      const s = op1 & 1 ? 's' : '';
      return mk(it, 4, SHIFTS[op1 >> 1] + s, '.w', [R(rd), R(rn), R(rm)], dpFlags(rd, !!s));
    }
    if (!(op2 & 8) || op1 > 5) return unknown(w, 4, true);
    // The extends, with an optional rotation; rn = pc is the plain form.
    const rot = (w >>> 4) & 3;
    const ror = rot ? [shift(`ror #${rot * 8}`)] : [];
    if (rn === 15) return mk(it, 4, EXTENDS[op1]!, op1 === 2 || op1 === 3 ? '' : '.w', [R(rd), R(rm), ...ror], 0);
    return mk(it, 4, EXTENDS_ADD[op1]!, '', [R(rd), R(rn), R(rm), ...ror], 0);
  }
  if (!(op2 & 8)) {
    // Parallel add and subtract: s, q, sh, u, uq, uh.
    const name = PARALLEL_OPS[op1 & 7];
    const prefix = PARALLEL_PREFIX[op2];
    if (!name || !prefix) return unknown(w, 4, true);
    return mk(it, 4, prefix + name, '', [R(rd), R(rn), R(rm)], prefix === 's' || prefix === 'u' ? F.SETS_FLAGS : 0);
  }
  if (op1 >= 12) {
    // crc32{c}{b,h,w}: not conditional, so LLVM prints no IT condition.
    if (op1 > 13 || (op2 & 12) !== 8 || (op2 & 3) === 3) return unknown(w, 4, true);
    const m = 'crc32' + (op1 & 1 ? 'c' : '') + ['b', 'h', 'w'][op2 & 3];
    return plain(4, m, [R(rd), R(rn), R(rm)], 0);
  }
  if (op2 >= 12) return unknown(w, 4, true);
  // These name Rm in both register fields; LLVM reads the register from the two fields or-ed together.
  const rmBoth = rm | rn;
  switch (op1 & 3) {
    case 0:
      // qadd rd, rm, rn: the operands come out in Rm, Rn order.
      return mk(it, 4, ['qadd', 'qdadd', 'qsub', 'qdsub'][op2 & 3]!, '', [R(rd), R(rm), R(rn)], 0);
    case 1:
      return mk(it, 4, ['rev', 'rev16', 'rbit', 'revsh'][op2 & 3]!, (op2 & 3) === 2 ? '' : '.w', [R(rd), R(rmBoth)], 0);
    case 2:
      if (op2 !== 8) return unknown(w, 4, true);
      return mk(it, 4, 'sel', '', [R(rd), R(rn), R(rm)], F.READS_FLAGS);
    default:
      if (op2 !== 8) return unknown(w, 4, true);
      return mk(it, 4, 'clz', '', [R(rd), R(rmBoth)], 0);
  }
}

/* ------------------------------------------------------------------ *
 * Multiply, multiply-accumulate, and the long forms and divides
 * ------------------------------------------------------------------ */

const XY = ['bb', 'bt', 'tb', 'tt'] as const;

function multiply(w: number, it: number): Insn {
  const op1 = (w >>> 20) & 7;
  const op2 = (w >>> 4) & 15;
  const rn = (w >>> 16) & 15;
  const ra = (w >>> 12) & 15;
  const rd = (w >>> 8) & 15;
  const rm = w & 15;
  const three = (m: string): Insn => mk(it, 4, m, '', [R(rd), R(rn), R(rm)], 0);
  const four = (m: string): Insn => mk(it, 4, m, '', [R(rd), R(rn), R(rm), R(ra)], 0);
  switch (op1) {
    case 0:
      if (op2 === 0) return ra === 15 ? three('mul') : four('mla');
      if (op2 === 1) return four('mls');
      return unknown(w, 4, true);
    case 1:
      if (op2 > 3) return unknown(w, 4, true);
      return ra === 15 ? three('smul' + XY[op2]) : four('smla' + XY[op2]);
    case 2:
    case 4: {
      if (op2 > 1) return unknown(w, 4, true);
      const x = op2 ? 'x' : '';
      if (op1 === 2) return ra === 15 ? three('smuad' + x) : four('smlad' + x);
      return ra === 15 ? three('smusd' + x) : four('smlsd' + x);
    }
    case 3:
      if (op2 > 1) return unknown(w, 4, true);
      return ra === 15 ? three('smulw' + (op2 ? 't' : 'b')) : four('smlaw' + (op2 ? 't' : 'b'));
    case 5:
      if (op2 > 1) return unknown(w, 4, true);
      return ra === 15 ? three('smmul' + (op2 ? 'r' : '')) : four('smmla' + (op2 ? 'r' : ''));
    case 6:
      if (op2 > 1) return unknown(w, 4, true);
      return four('smmls' + (op2 ? 'r' : ''));
    default:
      if (op2 !== 0) return unknown(w, 4, true);
      return ra === 15 ? three('usad8') : four('usada8');
  }
}

function longMultiply(w: number, it: number): Insn {
  const op1 = (w >>> 20) & 7;
  const op2 = (w >>> 4) & 15;
  const rn = (w >>> 16) & 15;
  const lo = (w >>> 12) & 15;
  const hi = (w >>> 8) & 15;
  const rm = w & 15;
  const long = (m: string): Insn => mk(it, 4, m, '', [R(lo), R(hi), R(rn), R(rm)], 0);
  switch (op1) {
    case 0:
      return op2 === 0 ? long('smull') : unknown(w, 4, true);
    case 1:
    case 3:
      if (op2 !== 15 || lo !== 15) return unknown(w, 4, true);
      return mk(it, 4, op1 === 1 ? 'sdiv' : 'udiv', '', [R(hi), R(rn), R(rm)], 0);
    case 2:
      return op2 === 0 ? long('umull') : unknown(w, 4, true);
    case 4:
      if (op2 === 0) return long('smlal');
      if ((op2 & 12) === 8) return long('smlal' + XY[op2 & 3]);
      if (op2 === 12 || op2 === 13) return long('smlald' + (op2 & 1 ? 'x' : ''));
      return unknown(w, 4, true);
    case 5:
      if (op2 === 12 || op2 === 13) return long('smlsld' + (op2 & 1 ? 'x' : ''));
      return unknown(w, 4, true);
    case 6:
      if (op2 === 0) return long('umlal');
      if (op2 === 6) return long('umaal');
      return unknown(w, 4, true);
    default:
      return unknown(w, 4, true);
  }
}

/* ------------------------------------------------------------------ *
 * Coprocessor instructions
 * ------------------------------------------------------------------ */

/**
 * ldc/stc, mcr/mrc and mcrr/mrrc. Armv8 keeps only coprocessors 14 and 15
 * (ldc and stc only 14) and drops cdp and the `2` forms, so LLVM refuses
 * the rest; coprocessors 10 and 11 are floating point, decoded in simd.ts.
 */
function coprocessor(w: number, it: number): Insn {
  if (bit(w, 28)) return unknown(w, 4, true);
  const coproc = (w >>> 8) & 15;
  const rn = (w >>> 16) & 15;
  const crd = (w >>> 12) & 15;
  if (!bit(w, 25)) {
    const p = bit(w, 24);
    const u = bit(w, 23);
    const d = bit(w, 22);
    const wb = bit(w, 21);
    const load = bit(w, 20);
    if (!p && !u && !wb) {
      if (!d) return unknown(w, 4, true);
      // mcrr / mrrc p, #opc1, rt, rt2, cN
      if (coproc < 14) return unknown(w, 4, true);
      const ops: Op[] = [text(`p${coproc}`), immHex((w >>> 4) & 15), R(crd), R(rn), text(`c${w & 15}`)];
      return mk(it, 4, load ? 'mrrc' : 'mcrr', '', ops, 0);
    }
    if (coproc !== 14) return unknown(w, 4, true);
    const m = (load ? 'ldc' : 'stc') + (d ? 'l' : '');
    const imm = (w & 0xff) * 4;
    let addr: Op;
    if (p) {
      const t = u && !imm && !wb ? `[${r(rn)}]` : `[${r(rn)}, #${u ? '' : '-'}${imm}]`;
      addr = mem(rn, wb ? `[${r(rn)}, #${u ? '' : '-'}${imm}]!` : t, wb ? 'pre' : 'off', u ? imm : -imm);
    } else if (wb) {
      addr = mem(rn, `[${r(rn)}], #${u ? '' : '-'}${imm}`, 'post', u ? imm : -imm);
    } else {
      addr = mem(rn, `[${r(rn)}], {${w & 0xff}}`, 'off');
    }
    return mk(it, 4, m, '', [text(`p${coproc}`), text(`c${crd}`), addr], load ? F.LOAD : F.STORE);
  }
  if (bit(w, 24) || !bit(w, 4) || coproc < 14) return unknown(w, 4, true);
  // mcr / mrc p, #opc1, rt, cN, cM, #opc2; mrc to pc writes the flags (apsr_nzcv).
  const load = bit(w, 20);
  const rt = crd;
  const rtOp = load && rt === 15 ? reg('apsr_nzcv') : R(rt);
  const ops: Op[] = [text(`p${coproc}`), immHex((w >>> 21) & 7), rtOp, text(`c${rn}`), text(`c${w & 15}`), immHex((w >>> 5) & 7)];
  return mk(it, 4, load ? 'mrc' : 'mcr', '', ops, load && rt === 15 ? F.SETS_FLAGS : 0);
}

