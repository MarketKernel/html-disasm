//! x86 and x86-64: the decoder (a port of LLVM's X86 disassembler) and LLVM's Intel printer.

pub mod decode;
pub mod hla;
pub mod pass;
pub mod print;
#[rustfmt::skip]
pub mod tables;

pub use decode::{decode_x86, decode_x86_into, info, pfx, sem, ty, x86_tables, McOp, X86Decoded, MAX_OPS};
pub use print::{format_address, format_imm, format_x86, mnemonic_x86, print_x86, X86Printed};
