//! Java bytecode: the class file reader (classfile.rs), the opcodes
//! (opcodes.rs) and the decoder that prints instructions as javap does
//! (decode.rs). A port of src/core/jvm/{classfile,opcodes,decode}.ts; the
//! analysis and the HLA64 view (program.ts, hla.ts) are still TypeScript.
//!
//! Text from a class file is WTF-8 (wtf8.rs): it may hold a lone surrogate,
//! as the TypeScript's JavaScript strings did.

pub mod classfile;
pub mod decode;
pub mod hla;
pub mod opcodes;
pub mod page;
pub mod program;
mod unicode;
pub mod wtf8;

pub use classfile::*;
pub use decode::*;
pub use opcodes::{all_ops, opcode_text, OpInfo, Operand};
pub use wtf8::{Wtf8, Wtf8Buf};
