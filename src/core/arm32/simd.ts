/**
 * Floating point (VFP), Advanced SIMD (NEON) and the crypto extensions, for
 * both instruction sets. T32 encodes them as A32 does with the condition field
 * replaced: 111U 1111 for 1111 001U (data processing), 1111 1001 for 1111 0100
 * (structure loads and stores); the coprocessor-space forms are identical.
 * So every T32 word is turned into its A32 twin and decoded once, with the
 * condition taken from the IT block.
 *
 *   simd-neon.ts   Advanced SIMD data processing and crypto
 *   simd-ldst.ts   vld1-vld4, vst1-vst4
 *   simd-vfp.ts    VFP (coprocessors 9-11) and the Armv8 FP additions
 *   simd-ext.ts    complex, dot product, FP16 multiply-long, BF16, Int8 matrix
 */

import { type Insn } from './types';
import { type Ctx, undef } from './simd-common';
import { simdExtension } from './simd-ext';
import { neonLoadStore } from './simd-ldst';
import { neonData } from './simd-neon';
import { fpV8, vfp } from './simd-vfp';

/** Coprocessor numbers 8-13 of an unconditional word: the Armv8 FP additions and the later SIMD ones. */
function unconditionalCoproc(w: number, ctx: Ctx): Insn | null {
  const cp = (w >>> 8) & 15;
  if (cp < 8 || cp > 13) return null;
  if ((w & 0x0f000000) === 0x0e000000 && cp >= 9 && cp <= 11) return fpV8(w, ctx);
  if (cp === 8 || cp >= 12) return simdExtension(w, ctx);
  // Coprocessors 9-11 with 1111 110x: no floating-point instruction is encoded there.
  return undef(ctx);
}

/** An A32 word in this space, or null to let the base decoder take it. */
export function decodeSimdA32(word: number, pc: number): Insn | null {
  const w = word >>> 0;
  const cond = w >>> 28;
  if (cond === 15) {
    if (w >>> 25 === 0x79) return neonData(w, { raw: w, pc, thumb: false, cond: 14 });
    if (w >>> 24 === 0xf4 && !(w & 0x00100000)) return neonLoadStore(w, { raw: w, pc, thumb: false, cond: 14 });
    if ((w & 0x0e000000) === 0x0c000000 || (w & 0x0f000000) === 0x0e000000) return unconditionalCoproc(w, { raw: w, pc, thumb: false, cond: 14 });
    return null;
  }
  // cond 110x or 1110 with coprocessor 8-11: floating point (8 is reserved, but nothing else lives there either).
  if ((w & 0x0c000000) === 0x0c000000 && (w & 0x0f000000) !== 0x0f000000 && ((w >>> 10) & 3) === 2) {
    return vfp(w, { raw: w, pc, thumb: false, cond });
  }
  return null;
}

/**
 * A 32-bit T32 instruction (hw1 << 16 | hw2) that an IT block neither
 * conditions nor counts. LLVM decodes the Armv8 additions from tables of their
 * own (VFPV8, v8NEON, v8Crypto) and leaves the IT state alone for them, so
 * inside a block they print no condition and the next instruction takes the
 * slot. They are UNPREDICTABLE there anyway; compilers never put them in one.
 * Decided by bits alone, for words that decode at all:
 *   1111 110x / 1111 1110 with coprocessor 8-13 (vsel, vmaxnm, vrinta, vcvta,
 *     vins, vmovx, vcmla, vcadd, the dot products, vfmal, BF16, Int8 matrix)
 *   vcvtb/vcvtt.bf16.f32
 *   the vector vmaxnm/vminnm, vrint and vcvta/n/p/m, aes*, sha*
 * vmull.p64 is not among them: LLVM finds it with the other NEON instructions.
 */
export function ignoresIt(word: number): boolean {
  const w = word >>> 0;
  const hi = w >>> 24;
  if (hi >= 0xfc && hi <= 0xfe) {
    const cp = (w >>> 8) & 15;
    return cp >= 8 && cp <= 13;
  }
  // vcvtb/vcvtt.bf16.f32 s0, s1 (coprocessor 9, opc2 0011).
  if (w >>> 23 === 0x1dd) return (w & 0x003f0f50) === 0x00330940;
  if (hi !== 0xef && hi !== 0xff) return false;
  // Advanced SIMD data processing, here in its T32 form: U is bit 28.
  if (!(w & 0x00800000)) {
    // sha1c…sha256su1: three registers, opc 1100 with bit 4 clear; vmaxnm/vminnm: U = 1, opc 1111, bit 4 set.
    const opc = (w >>> 8) & 15;
    if (opc === 12 && !(w & 0x10)) return true;
    return hi === 0xff && opc === 15 && (w & 0x10) !== 0;
  }
  // The two-register group: U = 1, bits 21-20 = 11, bit 11 and bit 4 clear.
  if (hi !== 0xff || (w & 0x00300810) !== 0x00300000) return false;
  const a = (w >>> 16) & 3;
  const b = (w >>> 7) & 15;
  switch (a) {
    case 0:
      return b === 6 || b === 7; // aese, aesd, aesmc, aesimc
    case 1:
      return b === 5 && (w & 0x40) !== 0; // sha1h
    case 2:
      // sha1su1, sha256su0; vrint{n,x,a,z,m,p} (1xxx but not the f16/f32 conversions at 1100 and 1110).
      return b === 7 || (b >= 8 && b !== 12 && b !== 14);
    default:
      return b < 8; // vcvta, vcvtn, vcvtp, vcvtm
  }
}

/** A 32-bit T32 instruction (hw1 << 16 | hw2) in this space, or null. */
export function decodeSimdT32(word: number, pc: number, it: number): Insn | null {
  const w = word >>> 0;
  const hi = w >>> 24;
  const ctx: Ctx = { raw: w, pc, thumb: true, cond: it < 0 || ignoresIt(w) ? 14 : it };
  // 111U 1111: data processing; U moves from bit 28 to bit 24.
  if ((hi & 0xef) === 0xef) return neonData(((w & 0x00ffffff) | 0xf2000000 | ((hi & 0x10) << 20)) >>> 0, ctx);
  // 1111 1001 xxx0: element and structure loads and stores.
  if (hi === 0xf9) return w & 0x00100000 ? null : neonLoadStore(((w & 0x00ffffff) | 0xf4000000) >>> 0, ctx);
  if ((hi & 0xec) !== 0xec) return null;
  if (hi & 0x10) return unconditionalCoproc(w, ctx);
  if (((w >>> 10) & 3) !== 2) return null;
  // LLVM reads the impossible IT condition as AL for VFP instructions, but not for the NEON lane moves
  // (vmov.32 d0[1], r0 and vdup) that share their space.
  if (ctx.cond === 15 && !(hi === 0xee && (w & 0xf10) === 0xb10)) ctx.cond = 14;
  return vfp(w, ctx);
}
