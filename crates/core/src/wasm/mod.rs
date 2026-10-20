//! WebAssembly: the module reader, the instruction decoder and its text (as
//! `wasm-tools print` writes it), and the DWARF line tables a module may carry.
//! A port of src/core/wasm/ (reader, opcodes, decode, module, dwarf).

pub mod decode;
pub mod dwarf;
pub mod hla;
pub mod module;
pub mod opcodes;
mod opcodes_table;
pub mod program;
pub mod reader;

pub use decode::{block_type_text, bytes_text, decode_at, format_insn, operands_text, write_insn, write_operands, BlockType, Catch, FormatContext, InsnBytes, WasmInsn};
pub use dwarf::{read_lines, LineTable, SourceLine};
pub use module::{
    format_context, func_type_of, is_wasm, limits_text, page_size, parse_wasm, signature_text, type_text, FuncType, Limits, NotWasm, ParseError, TypeDef, Warning, WasmModule,
};
pub use opcodes::{all_ops, imm, op_info, opcode_text, w, Group, OpInfo};
pub use reader::{
    decimal_float, f32_from_bits, f64_from_bits, float_text, heap_type, hex_float, ref_text, storage_type, utf8, val_type, HeapType, Num, Reader, ValType, WasmError,
};
