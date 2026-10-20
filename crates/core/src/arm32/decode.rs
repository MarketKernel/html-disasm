//! The AArch32 decoder: an A32 word or a T32 instruction in, one instruction
//! out, printed as llvm-objdump prints it.
//!
//! Floating point, Advanced SIMD and the crypto extensions are the same in both
//! instruction sets (T32 moves a bit or two), so simd.rs decodes them for both;
//! a32.rs and thumb.rs decode the rest of each set — data processing, branches,
//! loads and stores, the system and coprocessor instructions.

use super::a32::decode_a32_base;
use super::simd::{decode_simd_a32, decode_simd_t32, ignores_it};
use super::thumb::{decode_t16, decode_t32_base};
use super::types::{f, CondList, Insn};

/// Whether a T32 halfword starts a 32-bit instruction.
#[inline]
pub fn is_wide(hw1: u32) -> bool {
    hw1 >> 11 >= 0x1d
}

/// An A32 instruction at `pc`.
pub fn decode_arm(word: u32, pc: i64) -> Insn {
    match decode_simd_a32(word, pc) {
        Some(insn) => insn,
        None => decode_a32_base(word, pc),
    }
}

/// A T32 instruction at `pc`: `hw1` is its first halfword, `hw2` the next one
/// (read only when hw1 starts a 32-bit instruction). `it` is the condition the
/// enclosing IT block gives it (0…14, or 15 for the else slots of an `it al`),
/// or -1 outside a block.
pub fn decode_thumb(hw1: u32, hw2: u32, pc: i64, it: i32) -> Insn {
    if !is_wide(hw1) {
        return decode_t16(hw1 & 0xffff, pc, it);
    }
    let word = ((hw1 & 0xffff) << 16) | (hw2 & 0xffff);
    match decode_simd_t32(word, pc, it) {
        Some(insn) => insn,
        None => decode_t32_base(word, pc, it),
    }
}

/// The IT conditions still pending around an instruction, inline. A run of IT
/// instructions inside one another grows the TypeScript array by up to three
/// entries each; past `MAX_PENDING` entries (ten nested ITs in a row, which only
/// data decoded as code produces) the outermost, last entries are dropped, and
/// such a block ends early.
pub type ItPending = CondList<MAX_PENDING>;
pub const MAX_PENDING: usize = 32;

/// The IT conditions still to come after a T32 instruction, as LLVM counts
/// them: an instruction it cannot decode takes no slot, nor do the Armv8 FP and
/// SIMD encodings that ignore IT (ignores_it); a nested IT puts its own slots in
/// front of what is left of the outer block. `pending` is the list before the
/// instruction, the first entry being the condition it was decoded with.
pub fn it_after(pending: &[u8], insn: &Insn, word: u32) -> ItPending {
    let mut rest = pending;
    if !rest.is_empty() && insn.f & f::UNKNOWN == 0 && !(insn.size == 4 && ignores_it(word)) {
        rest = &rest[1..];
    }
    let mut out = ItPending::new();
    if let Some(it) = &insn.it {
        for &c in it.iter() {
            out.push(c);
        }
    }
    for &c in rest {
        out.push(c);
    }
    out
}
