//! AArch64: the decoder, its instruction type, the HLA64 lifter and the pass over a whole program.

pub mod decode;
pub mod encode;
pub mod hla;
pub mod pass;
pub mod simd;
pub mod sysreg;
pub mod types;

pub use decode::decode;
pub use types::{f, format_insn, Insn, Op};
