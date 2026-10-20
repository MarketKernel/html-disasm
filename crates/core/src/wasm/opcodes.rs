//! Every WebAssembly instruction the decoder knows, by opcode: its name in the
//! text format, the immediates that follow it, what it takes from the stack and
//! pushes, the kind of instruction (the group the reference files it under) and
//! what it does to control flow and memory.
//!
//! Covered: WebAssembly 3.0 — the MVP, sign extension, saturating conversions,
//! bulk memory, reference types, multi-value, SIMD and relaxed SIMD, tail
//! calls, exception handling (with the legacy try/catch), typed function
//! references, GC, memory64 and multiple memories — and the threads proposal
//! (atomics) and wide arithmetic.
//!
//! A signature is written `pops > pushes` with the types of the stack: `addr`
//! is an address (i32, or i64 in a 64-bit memory), `ref` a reference, `T` a
//! type the immediates or the module decide. Instructions whose stack effect
//! depends on a type (calls, blocks, branches) have none here; the analysis
//! works it out.
//!
//! The table itself is src/core/wasm/opcodes.ts, which the page's reference
//! reads too: tools/wasm-opcodes.mjs writes it here as static data
//! (opcodes_table.rs).

use super::opcodes_table::{OPS, PREFIXED, SINGLE};

/// The immediates of an instruction, as the decoder reads them (`IMM`).
pub mod imm {
    pub const NONE: u8 = 0;
    pub const BLOCK: u8 = 1; // block type
    pub const LABEL: u8 = 2;
    pub const BR_TABLE: u8 = 3;
    pub const FUNC: u8 = 4;
    pub const CALL_INDIRECT: u8 = 5; // type, table
    pub const LOCAL: u8 = 6;
    pub const GLOBAL: u8 = 7;
    pub const TABLE: u8 = 8;
    pub const MEMARG: u8 = 9;
    pub const I32: u8 = 10;
    pub const I64: u8 = 11;
    pub const F32: u8 = 12;
    pub const F64: u8 = 13;
    pub const SELECT_T: u8 = 14;
    pub const HEAP: u8 = 15; // ref.null
    pub const MEM: u8 = 16; // memory.size, memory.grow, memory.fill
    pub const MEMORY_INIT: u8 = 17; // data, memory
    pub const DATA: u8 = 18;
    pub const MEMORY_COPY: u8 = 19;
    pub const TABLE_INIT: u8 = 20; // elem, table
    pub const ELEM: u8 = 21;
    pub const TABLE_COPY: u8 = 22;
    pub const V128: u8 = 23;
    pub const SHUFFLE: u8 = 24;
    pub const LANE: u8 = 25;
    pub const MEMARG_LANE: u8 = 26;
    pub const FENCE: u8 = 27;
    pub const TRY_TABLE: u8 = 28;
    pub const TAG: u8 = 29;
    pub const TYPE: u8 = 30; // struct.new, array.get…, call_ref
    pub const TYPE_FIELD: u8 = 31;
    pub const TYPE_N: u8 = 32; // array.new_fixed
    pub const TYPE_DATA: u8 = 33;
    pub const TYPE_ELEM: u8 = 34;
    pub const TYPE_TYPE: u8 = 35; // array.copy
    pub const REF_TEST: u8 = 36; // ref.test / ref.cast with a non-null type
    pub const REF_TEST_NULL: u8 = 37;
    pub const BR_ON_CAST: u8 = 38;
}

/// What an instruction does, for the analysis and the colours of the listing (`W`).
pub mod w {
    pub const BRANCH: u32 = 1; // br, br_if, br_table, br_on_*: may go to a label
    pub const COND: u32 = 2; // only sometimes
    pub const CALL: u32 = 4;
    pub const RETURN: u32 = 8; // return, return_call*
    pub const INDIRECT: u32 = 16; // call_indirect, call_ref
    pub const LOAD: u32 = 32;
    pub const STORE: u32 = 64;
    pub const TRAPS: u32 = 128; // may stop the program (out of bounds, division by zero, …)
    pub const ATOMIC: u32 = 256;
    pub const STRUCTURE: u32 = 512; // block, loop, if, else, end, try…: shapes the code
    pub const END: u32 = 1024; // nothing after it in its block runs: br, return, unreachable, throw
    pub const CONST: u32 = 2048;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Group {
    Control,
    Reference,
    Parametric,
    Variable,
    Table,
    Memory,
    Numeric,
    Vector,
    Atomic,
    Aggregate,
    Exception,
}

impl Group {
    pub fn name(self) -> &'static str {
        match self {
            Group::Control => "control",
            Group::Reference => "reference",
            Group::Parametric => "parametric",
            Group::Variable => "variable",
            Group::Table => "table",
            Group::Memory => "memory",
            Group::Numeric => "numeric",
            Group::Vector => "vector",
            Group::Atomic => "atomic",
            Group::Aggregate => "aggregate",
            Group::Exception => "exception",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpInfo {
    /// The opcode as one number: the byte, or prefix << 16 | the prefixed opcode.
    pub code: u32,
    pub name: &'static str,
    /// One of [`imm`].
    pub imm: u8,
    /// `pops > pushes`, or '' when it depends on the module.
    pub sig: &'static str,
    pub group: Group,
    /// Bits of [`w`].
    pub flags: u32,
    /// For memory instructions: the natural alignment, as a power of two (-1 for the others).
    pub align: i32,
    /// For loads and stores: bytes moved (the memory operand's width).
    pub size: u32,
    /// How many values it takes from the stack and puts back, counted from `sig`; None when `sig` is empty.
    pub fixed: Option<(u32, u32)>,
}

/// The opcode prefixes.
#[inline]
pub fn is_prefix(byte: u8) -> bool {
    (0xfb..=0xfe).contains(&byte)
}

/// One row of the table, for the generated [`super::opcodes_table`].
#[allow(clippy::too_many_arguments)]
pub(super) const fn op(code: u32, name: &'static str, imm: u8, sig: &'static str, group: Group, flags: u32, align: i32, size: u32, fixed: Option<(u32, u32)>) -> OpInfo {
    OpInfo { code, name, imm, sig, group, flags, align, size, fixed }
}

/// The instruction with this opcode (the byte, or prefix << 16 | the prefixed opcode).
#[inline]
pub fn op_info(code: u32) -> Option<&'static OpInfo> {
    let prefix = code >> 16;
    let sub = (code & 0xffff) as usize;
    let index = if prefix == 0 {
        SINGLE.get(sub).copied().unwrap_or(0)
    } else if (0xfb..=0xfe).contains(&prefix) {
        PREFIXED[(prefix - 0xfb) as usize].get(sub).copied().unwrap_or(0)
    } else {
        0
    };
    if index == 0 {
        None
    } else {
        Some(&OPS[index as usize - 1])
    }
}

/// Every instruction, in the order they were defined (ref.test and select have two encodings and one name).
pub fn all_ops() -> &'static [OpInfo] {
    &OPS
}

/// The opcode bytes as they appear in the file: `0x6a`, `0xfd 14`.
pub fn opcode_text(code: u32) -> String {
    let prefix = code >> 16;
    let sub = code & 0xffff;
    if prefix == 0 {
        format!("0x{sub:02x}")
    } else {
        format!("0x{prefix:x} {sub}")
    }
}
