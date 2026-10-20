//! The WebAssembly instruction decoder.
//!
//! decode_at() reads one instruction of a function body into a WasmInsn — the
//! opcode, its length and its immediates as numbers — and format_insn() writes
//! it in the text format exactly as `wasm-tools print` does for a module
//! without names (`i32.load offset=8 align=1`, `call_indirect 1 (type 3)`,
//! `f64.const 0x1.8p+1 (;=3;)`), so it can be checked line by line
//! (tools/verify-wasm.mjs). The listing replaces indices with names when it
//! draws a line; the text here is the reference.
//!
//! A port of src/core/wasm/decode.ts. The instruction is reused from one
//! decode to the next, and decoding allocates nothing once its few lists
//! (br_table labels, select types, try_table catches) have grown: they are
//! cleared, not dropped. Like the TypeScript, a decode leaves the fields an
//! instruction has no use for as the previous one left them.

use core::fmt::{self, Write};

use super::module::FuncType;
use super::opcodes::{imm, is_prefix, op_info, OpInfo};
use super::reader::{heap_type, is_val_type_byte, val_type, write_float, write_ref, HeapType, Num, Reader, Result, ValType, WasmError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockType {
    Empty,
    Value(ValType),
    /// A type index (an s33).
    Type(i64),
}

/// The names of the kinds of catch clause, by their byte.
pub const CATCH_KINDS: [&str; 4] = ["catch", "catch_ref", "catch_all", "catch_all_ref"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Catch {
    /// catch, catch_ref, catch_all, catch_all_ref: an index into [`CATCH_KINDS`]; 4 when the
    /// byte was past the end of the file (the TypeScript's `undefined`).
    pub kind: u8,
    /// -1 for the catch_all kinds.
    pub tag: i64,
    pub label: u64,
}

impl Catch {
    pub fn kind_name(&self) -> &'static str {
        CATCH_KINDS.get(self.kind as usize).copied().unwrap_or("undefined")
    }
}

/// `a` of a lane whose byte was past the end of the file (the TypeScript's `undefined`).
pub const UNDEFINED: u64 = u64::MAX;

/// The bytes an instruction carries: the 16 of v128.const and i8x16.shuffle, or
/// the rest of the body for what did not decode (`.bytes`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InsnBytes {
    /// Where they start in the code, and how many there are (fewer than asked when the file ends first).
    pub at: usize,
    pub len: usize,
    head: [u8; 32],
}

impl InsnBytes {
    fn of(code: &[u8], at: usize, len: usize) -> Self {
        let from = at.min(code.len());
        let to = super::reader::add(at, len as u64).min(code.len());
        let mut head = [0; 32];
        let shown = (to - from).min(32);
        head[..shown].copy_from_slice(&code[from..from + shown]);
        InsnBytes { at, len: to - from, head }
    }

    /// The first 32 of them at most: all that the text shows.
    pub fn head(&self) -> &[u8] {
        &self.head[..self.len.min(32)]
    }

    /// All of them, from the code they came from.
    pub fn all<'a>(&self, code: &'a [u8]) -> &'a [u8] {
        let from = self.at.min(code.len());
        &code[from..from + self.len]
    }
}

#[derive(Clone, Debug)]
pub struct WasmInsn {
    pub op: Option<&'static OpInfo>,
    /// As printed: i32.add, local.get, .bytes for what could not be decoded.
    pub m: &'static str,
    pub pos: usize,
    pub len: usize,
    /// The first and second index immediates: label depth, function, local, global, type, table, memory, data, elem, tag, lane, field.
    pub a: u64,
    pub b: u64,
    /// An integer constant, or a memory offset.
    pub value: Num,
    /// Float bits of f32.const / f64.const.
    pub bits: u64,
    pub align: u64,
    pub mem: u64,
    pub bytes: Option<InsnBytes>,
    /// The labels of br_table (the default last); empty for the others.
    pub labels: Vec<u64>,
    pub block: Option<BlockType>,
    /// The types of a typed select; empty for the others.
    pub types: Vec<ValType>,
    pub heap: HeapType,
    pub heap2: HeapType,
    pub nullable: u8,
    /// The clauses of try_table; empty for the others.
    pub catches: Vec<Catch>,
}

impl Default for WasmInsn {
    fn default() -> Self {
        WasmInsn {
            op: None,
            m: "",
            pos: 0,
            len: 0,
            a: 0,
            b: 0,
            value: Num::Number(0),
            bits: 0,
            align: 0,
            mem: 0,
            bytes: None,
            labels: Vec::new(),
            block: None,
            types: Vec::new(),
            heap: HeapType::default(),
            heap2: HeapType::default(),
            nullable: 0,
            catches: Vec::new(),
        }
    }
}

impl WasmInsn {
    pub fn new() -> Self {
        Self::default()
    }

    /// Decodes the instruction at `pos` into a new instruction.
    pub fn decode(bytes: &[u8], pos: usize, end: usize) -> Self {
        let mut insn = Self::default();
        decode_at(bytes, pos, end, &mut insn);
        insn
    }

    /// The immediates kind, or None for `.bytes`.
    #[inline]
    pub fn imm(&self) -> Option<u8> {
        self.op.map(|op| op.imm)
    }
}

/// What the text of block types needs from the module.
pub trait FormatContext {
    fn func_type(&self, index: i64) -> Option<&FuncType>;
}

fn block_type(r: &mut Reader) -> Result<BlockType> {
    let byte = r.peek();
    if byte == 0x40 {
        r.u8()?;
        return Ok(BlockType::Empty);
    }
    if is_val_type_byte(byte) {
        return Ok(BlockType::Value(val_type(r)?));
    }
    let index = r.s32()?;
    if index < 0 {
        return Err(WasmError::BadBlockType { index });
    }
    Ok(BlockType::Type(index))
}

#[inline]
fn memarg(r: &mut Reader, insn: &mut WasmInsn) -> Result<()> {
    let flags = r.u32()?;
    if (64..128).contains(&flags) {
        insn.align = flags - 64;
        insn.mem = r.u32()?;
    } else {
        insn.align = flags;
        insn.mem = 0;
    }
    insn.value = r.u64()?;
    Ok(())
}

/// Decodes the instruction at `pos`; `end` is the end of the function body.
/// An unknown opcode gives `.bytes` covering the rest of the body, since its
/// length cannot be known.
pub fn decode_at(bytes: &[u8], pos: usize, end: usize, insn: &mut WasmInsn) {
    let mut r = Reader::new(bytes, pos, end);
    insn.pos = pos;
    insn.labels.clear();
    insn.block = None;
    insn.types.clear();
    insn.bytes = None;
    insn.catches.clear();
    insn.mem = 0;
    insn.align = 0;
    match read(&mut r, insn) {
        Ok(()) => insn.len = r.pos - pos,
        Err(_) => {
            // The lists the TypeScript assigned only once read whole stay empty.
            insn.labels.clear();
            insn.types.clear();
            insn.catches.clear();
            insn.op = None;
            insn.m = ".bytes";
            insn.len = end.saturating_sub(pos).max(1);
            insn.bytes = Some(InsnBytes::of(bytes, pos, insn.len));
        }
    }
}

#[inline]
fn read(r: &mut Reader, insn: &mut WasmInsn) -> Result<()> {
    // A byte past the end of the file (JavaScript's undefined) is no opcode. The prefixed
    // number is OR-ed in on its low 32 bits, as JavaScript's `|` does: a redundant LEB128 can
    // carry it into another prefix's opcodes (0xfc with 0x10000 reads as 0xfd 0).
    let mut code = r.byte()?.map_or(0x100, |b| b as u32);
    if code < 0x100 && is_prefix(code as u8) {
        code = (code << 16) | r.u32()? as u32;
    }
    let op = op_info(code).ok_or(WasmError::UnknownOpcode)?;
    insn.op = Some(op);
    insn.m = op.name;
    read_immediates(r, op, insn)
}

fn read_immediates(r: &mut Reader, op: &OpInfo, insn: &mut WasmInsn) -> Result<()> {
    match op.imm {
        imm::NONE => {}
        imm::BLOCK => insn.block = Some(block_type(r)?),
        imm::LABEL | imm::FUNC | imm::LOCAL | imm::GLOBAL | imm::TABLE | imm::MEM | imm::DATA | imm::ELEM | imm::TAG | imm::TYPE => insn.a = r.u32()?,
        imm::LANE => insn.a = r.byte()?.map_or(UNDEFINED, |b| b as u64),
        imm::BR_TABLE => {
            let count = r.u32()?;
            if count > (r.end - r.pos) as u64 {
                return Err(WasmError::BrTableTooLong);
            }
            for _ in 0..=count {
                let label = r.u32()?;
                insn.labels.push(label);
            }
        }
        imm::CALL_INDIRECT => {
            insn.a = r.u32()?; // type
            insn.b = r.u32()?; // table
        }
        imm::MEMARG => memarg(r, insn)?,
        imm::MEMARG_LANE => {
            memarg(r, insn)?;
            insn.a = r.byte()?.map_or(UNDEFINED, |b| b as u64);
        }
        imm::I32 => insn.value = Num::Number(r.s32()? as i32 as i64),
        imm::I64 => insn.value = r.s64()?,
        imm::F32 => insn.bits = r.f32_bits()? as u64,
        imm::F64 => insn.bits = r.f64_bits()?,
        imm::SELECT_T => {
            let count = r.u32()?;
            if count > (r.end - r.pos) as u64 {
                return Err(WasmError::SelectTooLong);
            }
            for _ in 0..count {
                let ty = val_type(r)?;
                insn.types.push(ty);
            }
        }
        imm::HEAP => insn.heap = heap_type(r)?,
        imm::MEMORY_INIT | imm::TABLE_INIT | imm::MEMORY_COPY | imm::TABLE_COPY | imm::TYPE_FIELD | imm::TYPE_N | imm::TYPE_DATA | imm::TYPE_ELEM | imm::TYPE_TYPE => {
            insn.a = r.u32()?;
            insn.b = r.u32()?;
        }
        imm::V128 | imm::SHUFFLE => {
            let at = r.pos;
            r.bytes_n(16)?;
            insn.bytes = Some(InsnBytes::of(r.bytes, at, 16));
        }
        imm::FENCE => {
            if r.byte()? != Some(0) {
                return Err(WasmError::FenceReserved);
            }
        }
        imm::TRY_TABLE => {
            insn.block = Some(block_type(r)?);
            let count = r.u32()?;
            if count > (r.end - r.pos) as u64 {
                return Err(WasmError::TryTableTooLong);
            }
            for _ in 0..count {
                // A kind past the end of the file is JavaScript's undefined: no tag, no name.
                let kind = match r.byte()? {
                    Some(kind) if kind > 3 => return Err(WasmError::BadCatch),
                    Some(kind) => kind,
                    None => 4,
                };
                let tag = if kind < 2 { r.u32()? as i64 } else { -1 };
                let label = r.u32()?;
                insn.catches.push(Catch { kind, tag, label });
            }
        }
        imm::REF_TEST | imm::REF_TEST_NULL => {
            insn.heap = heap_type(r)?;
            insn.nullable = (op.imm == imm::REF_TEST_NULL) as u8;
        }
        imm::BR_ON_CAST => {
            // Bit 0: the source may be null; bit 1: the target may be. A byte past the end of the
            // file (undefined) acted as 0 in every use.
            insn.nullable = r.byte()?.unwrap_or(0);
            if insn.nullable > 3 {
                return Err(WasmError::BrOnCastFlags);
            }
            insn.a = r.u32()?;
            insn.heap = heap_type(r)?;
            insn.heap2 = heap_type(r)?;
        }
        _ => unreachable!("immediate kind {}", op.imm),
    }
    Ok(())
}

/* ------------------------------------------------------------------ *
 * Text
 * ------------------------------------------------------------------ */

const HEX: &[u8; 16] = b"0123456789abcdef";

#[inline]
fn hex2<W: Write + ?Sized>(out: &mut W, b: u8) -> fmt::Result {
    out.write_char(HEX[(b >> 4) as usize] as char)?;
    out.write_char(HEX[(b & 15) as usize] as char)
}

/// An index immediate, `undefined` for a lane past the end of the file.
struct Index(u64);

impl fmt::Display for Index {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0 == UNDEFINED {
            f.write_str("undefined")
        } else {
            write!(f, "{}", self.0)
        }
    }
}

fn write_types<W: Write + ?Sized>(out: &mut W, types: &[ValType]) -> fmt::Result {
    for (i, t) in types.iter().enumerate() {
        if i > 0 {
            out.write_char(' ')?;
        }
        write!(out, "{t}")?;
    }
    Ok(())
}

/// Writes the text of a block type, with a leading space, or nothing.
pub fn write_block_type<W: Write + ?Sized>(out: &mut W, block: Option<&BlockType>, ctx: Option<&dyn FormatContext>) -> fmt::Result {
    match block {
        None | Some(BlockType::Empty) => Ok(()),
        Some(BlockType::Value(t)) => write!(out, " (result {t})"),
        Some(&BlockType::Type(index)) => {
            let ty = ctx.and_then(|c| c.func_type(index));
            write!(out, " (type {index})")?;
            if let Some(ty) = ty {
                if !ty.params.is_empty() {
                    out.write_str(" (param ")?;
                    write_types(out, &ty.params)?;
                    out.write_char(')')?;
                }
                if !ty.results.is_empty() {
                    out.write_str(" (result ")?;
                    write_types(out, &ty.results)?;
                    out.write_char(')')?;
                }
            }
            Ok(())
        }
    }
}

pub fn block_type_text(block: Option<&BlockType>, ctx: Option<&dyn FormatContext>) -> String {
    let mut s = String::new();
    let _ = write_block_type(&mut s, block, ctx);
    s
}

fn write_memarg<W: Write + ?Sized>(out: &mut W, insn: &WasmInsn) -> fmt::Result {
    if insn.mem != 0 {
        write!(out, " {}", insn.mem)?;
    }
    if !insn.value.is_zero() {
        write!(out, " offset={}", insn.value)?;
    }
    if let Some(op) = insn.op {
        if insn.align as i64 != op.align as i64 {
            if insn.align < 64 {
                write!(out, " align={}", 1u64 << insn.align)?;
            } else {
                write!(out, " align=2**{}", insn.align)?;
            }
        }
    }
    Ok(())
}

/// Writes the operands of an instruction, as text after its name (with a leading space), or nothing.
pub fn write_operands<W: Write + ?Sized>(out: &mut W, insn: &WasmInsn, ctx: Option<&dyn FormatContext>) -> fmt::Result {
    let Some(op) = insn.op else {
        out.write_char(' ')?;
        if let Some(bytes) = &insn.bytes {
            for (i, &b) in bytes.head().iter().enumerate() {
                if i > 0 {
                    out.write_char(' ')?;
                }
                hex2(out, b)?;
            }
            if bytes.len > 32 {
                out.write_str(" …")?;
            }
        }
        return Ok(());
    };
    match op.imm {
        imm::NONE | imm::FENCE => Ok(()),
        imm::BLOCK => write_block_type(out, insn.block.as_ref(), ctx),
        imm::LABEL | imm::FUNC | imm::LOCAL | imm::GLOBAL | imm::TABLE | imm::DATA | imm::ELEM | imm::TAG | imm::TYPE | imm::LANE => write!(out, " {}", Index(insn.a)),
        imm::MEM => {
            if insn.a != 0 {
                write!(out, " {}", insn.a)?;
            }
            Ok(())
        }
        imm::BR_TABLE => {
            for label in &insn.labels {
                write!(out, " {label}")?;
            }
            Ok(())
        }
        imm::CALL_INDIRECT => {
            if insn.b != 0 {
                write!(out, " {}", insn.b)?;
            }
            write!(out, " (type {})", insn.a)
        }
        imm::MEMARG => write_memarg(out, insn),
        imm::MEMARG_LANE => {
            write_memarg(out, insn)?;
            write!(out, " {}", Index(insn.a))
        }
        imm::I32 | imm::I64 => write!(out, " {}", insn.value),
        imm::F32 | imm::F64 => {
            out.write_char(' ')?;
            write_float(out, insn.bits, op.imm == imm::F32)
        }
        imm::SELECT_T => {
            if insn.types.is_empty() {
                return out.write_str(" (result)");
            }
            out.write_str(" (result ")?;
            write_types(out, &insn.types)?;
            out.write_char(')')
        }
        imm::HEAP => write!(out, " {}", insn.heap),
        imm::MEMORY_INIT | imm::TABLE_INIT => {
            if insn.b != 0 {
                write!(out, " {} {}", insn.b, insn.a)
            } else {
                write!(out, " {}", insn.a)
            }
        }
        imm::MEMORY_COPY | imm::TABLE_COPY => {
            if insn.a != 0 || insn.b != 0 {
                write!(out, " {} {}", insn.a, insn.b)?;
            }
            Ok(())
        }
        imm::TYPE_FIELD | imm::TYPE_N | imm::TYPE_DATA | imm::TYPE_ELEM | imm::TYPE_TYPE => write!(out, " {} {}", insn.a, insn.b),
        imm::V128 => {
            // A constant cut short by the end of the file made the TypeScript throw; its missing bytes read as 0 here.
            let b = insn.bytes.as_ref().map_or(&[][..], |b| b.head());
            let at = |i: usize| b.get(i).copied().unwrap_or(0);
            out.write_str(" i32x4")?;
            for i in (0..16).step_by(4) {
                out.write_str(" 0x")?;
                for k in (0..4).rev() {
                    hex2(out, at(i + k))?;
                }
            }
            Ok(())
        }
        imm::SHUFFLE => {
            for &b in insn.bytes.as_ref().map_or(&[][..], |b| b.head()) {
                write!(out, " {b}")?;
            }
            Ok(())
        }
        imm::TRY_TABLE => {
            write_block_type(out, insn.block.as_ref(), ctx)?;
            for c in &insn.catches {
                write!(out, " ({}", c.kind_name())?;
                if c.tag >= 0 {
                    write!(out, " {}", c.tag)?;
                }
                write!(out, " {})", c.label)?;
            }
            Ok(())
        }
        imm::REF_TEST | imm::REF_TEST_NULL => {
            out.write_char(' ')?;
            write_ref(out, insn.nullable != 0, &insn.heap)
        }
        imm::BR_ON_CAST => {
            write!(out, " {} ", insn.a)?;
            write_ref(out, insn.nullable & 1 != 0, &insn.heap)?;
            out.write_char(' ')?;
            write_ref(out, insn.nullable & 2 != 0, &insn.heap2)
        }
        _ => Ok(()),
    }
}

/// The operands of an instruction, as text after its name (with a leading space), or ''.
pub fn operands_text(insn: &WasmInsn, ctx: Option<&dyn FormatContext>) -> String {
    let mut s = String::new();
    let _ = write_operands(&mut s, insn, ctx);
    s
}

/// Writes the instruction: its name and its operands.
pub fn write_insn<W: Write + ?Sized>(out: &mut W, insn: &WasmInsn, ctx: Option<&dyn FormatContext>) -> fmt::Result {
    out.write_str(insn.m)?;
    write_operands(out, insn, ctx)
}

pub fn format_insn(insn: &WasmInsn, ctx: Option<&dyn FormatContext>) -> String {
    let mut s = String::with_capacity(32);
    let _ = write_insn(&mut s, insn, ctx);
    s
}

/// The bytes of an instruction as hex: `41 80 08`; at most `max` of them
/// (12 in the listing), then ` …`. Bytes past the end of the file (which made
/// the TypeScript throw) are left out.
pub fn bytes_text(bytes: &[u8], insn: &WasmInsn, max: usize) -> String {
    let shown = insn.len.min(max);
    let mut text = String::with_capacity(shown * 3 + 4);
    for i in 0..shown {
        let Some(&b) = bytes.get(insn.pos + i) else { break };
        if i > 0 {
            text.push(' ');
        }
        let _ = hex2(&mut text, b);
    }
    if insn.len > max {
        text.push_str(" …");
    }
    text
}
