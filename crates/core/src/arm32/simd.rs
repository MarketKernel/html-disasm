//! Floating point (VFP), Advanced SIMD (NEON) and the crypto extensions, for
//! both instruction sets. T32 encodes them as A32 does with the condition field
//! replaced: 111U 1111 for 1111 001U (data processing), 1111 1001 for 1111 0100
//! (structure loads and stores); the coprocessor-space forms are identical.
//! So every T32 word is turned into its A32 twin and decoded once, with the
//! condition taken from the IT block.
//!
//!   simd_neon.rs   Advanced SIMD data processing and crypto
//!   simd_ldst.rs   vld1-vld4, vst1-vst4
//!   simd_vfp.rs    VFP (coprocessors 9-11) and the Armv8 FP additions
//!   simd_ext.rs    complex, dot product, FP16 multiply-long, BF16, Int8 matrix

use super::simd_common::{undef, Ctx};
use super::simd_ext::simd_extension;
use super::simd_ldst::neon_load_store;
use super::simd_neon::neon_data;
use super::simd_vfp::{fp_v8, vfp};
use super::types::Insn;

/// Coprocessor numbers 8-13 of an unconditional word: the Armv8 FP additions and the later SIMD ones.
fn unconditional_coproc(w: u32, ctx: &Ctx) -> Option<Insn> {
    let cp = (w >> 8) & 15;
    if !(8..=13).contains(&cp) {
        return None;
    }
    if (w & 0x0f000000) == 0x0e000000 && (9..=11).contains(&cp) {
        return Some(fp_v8(w, ctx));
    }
    if cp == 8 || cp >= 12 {
        return Some(simd_extension(w, ctx));
    }
    // Coprocessors 9-11 with 1111 110x: no floating-point instruction is encoded there.
    Some(undef(ctx))
}

/// An A32 word in this space, or None to let the base decoder take it.
pub fn decode_simd_a32(word: u32, pc: i64) -> Option<Insn> {
    let w = word;
    let cond = w >> 28;
    if cond == 15 {
        let ctx = Ctx { raw: w, pc, thumb: false, cond: 14 };
        if w >> 25 == 0x79 {
            return Some(neon_data(w, &ctx));
        }
        if w >> 24 == 0xf4 && w & 0x00100000 == 0 {
            return Some(neon_load_store(w, &ctx));
        }
        if (w & 0x0e000000) == 0x0c000000 || (w & 0x0f000000) == 0x0e000000 {
            return unconditional_coproc(w, &ctx);
        }
        return None;
    }
    // cond 110x or 1110 with coprocessor 8-11: floating point (8 is reserved, but nothing else lives there either).
    if (w & 0x0c000000) == 0x0c000000 && (w & 0x0f000000) != 0x0f000000 && ((w >> 10) & 3) == 2 {
        return Some(vfp(w, &Ctx { raw: w, pc, thumb: false, cond: cond as i32 }));
    }
    None
}

/// A 32-bit T32 instruction (hw1 << 16 | hw2) that an IT block neither
/// conditions nor counts. LLVM decodes the Armv8 additions from tables of their
/// own (VFPV8, v8NEON, v8Crypto) and leaves the IT state alone for them, so
/// inside a block they print no condition and the next instruction takes the
/// slot. They are UNPREDICTABLE there anyway; compilers never put them in one.
/// Decided by bits alone, for words that decode at all:
///   1111 110x / 1111 1110 with coprocessor 8-13 (vsel, vmaxnm, vrinta, vcvta,
///     vins, vmovx, vcmla, vcadd, the dot products, vfmal, BF16, Int8 matrix)
///   vcvtb/vcvtt.bf16.f32
///   the vector vmaxnm/vminnm, vrint and vcvta/n/p/m, aes*, sha*
/// vmull.p64 is not among them: LLVM finds it with the other NEON instructions.
pub fn ignores_it(word: u32) -> bool {
    let w = word;
    let hi = w >> 24;
    if (0xfc..=0xfe).contains(&hi) {
        let cp = (w >> 8) & 15;
        return (8..=13).contains(&cp);
    }
    // vcvtb/vcvtt.bf16.f32 s0, s1 (coprocessor 9, opc2 0011).
    if w >> 23 == 0x1dd {
        return (w & 0x003f0f50) == 0x00330940;
    }
    if hi != 0xef && hi != 0xff {
        return false;
    }
    // Advanced SIMD data processing, here in its T32 form: U is bit 28.
    if w & 0x00800000 == 0 {
        // sha1c…sha256su1: three registers, opc 1100 with bit 4 clear; vmaxnm/vminnm: U = 1, opc 1111, bit 4 set.
        let opc = (w >> 8) & 15;
        if opc == 12 && w & 0x10 == 0 {
            return true;
        }
        return hi == 0xff && opc == 15 && (w & 0x10) != 0;
    }
    // The two-register group: U = 1, bits 21-20 = 11, bit 11 and bit 4 clear.
    if hi != 0xff || (w & 0x00300810) != 0x00300000 {
        return false;
    }
    let a = (w >> 16) & 3;
    let b = (w >> 7) & 15;
    match a {
        0 => b == 6 || b == 7,          // aese, aesd, aesmc, aesimc
        1 => b == 5 && (w & 0x40) != 0, // sha1h
        // sha1su1, sha256su0; vrint{n,x,a,z,m,p} (1xxx but not the f16/f32 conversions at 1100 and 1110).
        2 => b == 7 || (b >= 8 && b != 12 && b != 14),
        _ => b < 8, // vcvta, vcvtn, vcvtp, vcvtm
    }
}

/// A 32-bit T32 instruction (hw1 << 16 | hw2) in this space, or None.
pub fn decode_simd_t32(word: u32, pc: i64, it: i32) -> Option<Insn> {
    let w = word;
    let hi = w >> 24;
    let mut ctx = Ctx { raw: w, pc, thumb: true, cond: if it < 0 || ignores_it(w) { 14 } else { it } };
    // 111U 1111: data processing; U moves from bit 28 to bit 24.
    if (hi & 0xef) == 0xef {
        return Some(neon_data((w & 0x00ffffff) | 0xf2000000 | ((hi & 0x10) << 20), &ctx));
    }
    // 1111 1001 xxx0: element and structure loads and stores.
    if hi == 0xf9 {
        return if w & 0x00100000 != 0 { None } else { Some(neon_load_store((w & 0x00ffffff) | 0xf4000000, &ctx)) };
    }
    if (hi & 0xec) != 0xec {
        return None;
    }
    if hi & 0x10 != 0 {
        return unconditional_coproc(w, &ctx);
    }
    if ((w >> 10) & 3) != 2 {
        return None;
    }
    // LLVM reads the impossible IT condition as AL for VFP instructions, but not for the NEON lane moves
    // (vmov.32 d0[1], r0 and vdup) that share their space.
    if ctx.cond == 15 && !(hi == 0xee && (w & 0xf10) == 0xb10) {
        ctx.cond = 14;
    }
    Some(vfp(w, &ctx))
}
