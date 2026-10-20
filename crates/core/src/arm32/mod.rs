//! AArch32: the A32 and T32 decoders and their instruction type.

pub mod a32;
pub mod decode;
pub mod pass;
pub mod simd;
pub mod simd_common;
pub mod simd_ext;
pub mod simd_ldst;
pub mod simd_neon;
pub mod simd_vfp;
pub mod thumb;
pub mod types;

pub use decode::{decode_arm, decode_thumb, is_wide, it_after, ItPending};
pub use types::{f, format_insn, format_op, it_conditions, it_suffix, unknown, Insn, Op, CONDS, REGS};
