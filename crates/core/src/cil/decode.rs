//! The CIL decoder (`decodeAt` of src/core/cil/decode.ts): an opcode and its
//! operand, from a method's IL. The text ildasm writes is the page's.

use super::opcodes::{one, operand as o, two, OpInfo};

/// A decoded instruction; one is reused while a method is read.
#[derive(Clone, Debug, Default)]
pub struct CilInsn {
    pub op: Option<&'static OpInfo>,
    /// Offset in the method's IL, and length in bytes.
    pub at: u32,
    pub len: u32,
    /// The mnemonic (`.byte` for an opcode that is not one).
    pub m: &'static str,
    /// A variable number, a constant, a token, a branch target (IL offset, which may be out of the method).
    pub a: i64,
    /// A switch: its targets (IL offsets); empty for anything else.
    pub targets: Vec<i64>,
    pub is_switch: bool,
}

#[inline]
fn i8_at(b: &[u8], p: usize) -> i64 {
    b[p] as i8 as i64
}

#[inline]
fn u16_at(b: &[u8], p: usize) -> i64 {
    u16::from_le_bytes([b[p], b[p + 1]]) as i64
}

#[inline]
fn u32_at(b: &[u8], p: usize) -> u32 {
    u32::from_le_bytes([b[p], b[p + 1], b[p + 2], b[p + 3]])
}

/// Decodes the instruction at `pos` of a method whose IL is `bytes[start..end]`.
pub fn decode_at(bytes: &[u8], start: usize, pos: usize, end: usize, insn: &mut CilInsn) {
    insn.at = (pos - start) as u32;
    insn.targets.clear();
    insn.is_switch = false;
    insn.a = 0;
    // A body may claim more than the file has: what is past it is no instruction.
    let end = end.min(bytes.len());
    let first = bytes.get(pos).copied();
    let (op, mut p) = match first {
        Some(0xfe) if pos + 1 < end => (two(bytes[pos + 1]), pos + 2),
        Some(b) => (one(b), pos + 1),
        None => (None, pos + 1),
    };
    let Some(op) = op else { return as_byte(insn, first) };
    let need = |p: usize, n: usize| p + n <= end;
    insn.op = Some(op);
    insn.m = op.name;
    match op.operand {
        o::NONE => {}
        o::VAR8 | o::U8 => {
            if !need(p, 1) {
                return as_byte(insn, first);
            }
            insn.a = bytes[p] as i64;
            p += 1;
        }
        o::I8 => {
            if !need(p, 1) {
                return as_byte(insn, first);
            }
            insn.a = i8_at(bytes, p);
            p += 1;
        }
        o::VAR16 => {
            if !need(p, 2) {
                return as_byte(insn, first);
            }
            insn.a = u16_at(bytes, p);
            p += 2;
        }
        o::BR8 => {
            if !need(p, 1) {
                return as_byte(insn, first);
            }
            insn.a = (p + 1) as i64 + i8_at(bytes, p) - start as i64;
            p += 1;
        }
        o::BR32 => {
            if !need(p, 4) {
                return as_byte(insn, first);
            }
            insn.a = (p + 4) as i64 + u32_at(bytes, p) as i32 as i64 - start as i64;
            p += 4;
        }
        o::I32 => {
            if !need(p, 4) {
                return as_byte(insn, first);
            }
            insn.a = u32_at(bytes, p) as i32 as i64;
            p += 4;
        }
        o::I64 | o::R8 => {
            if !need(p, 8) {
                return as_byte(insn, first);
            }
            p += 8;
        }
        o::R4 => {
            if !need(p, 4) {
                return as_byte(insn, first);
            }
            insn.a = u32_at(bytes, p) as i64;
            p += 4;
        }
        o::SWITCH => {
            if !need(p, 4) {
                return as_byte(insn, first);
            }
            let count = u32_at(bytes, p) as usize;
            p += 4;
            if count > (end - p) / 4 {
                return as_byte(insn, first);
            }
            let base = (p + count * 4) as i64 - start as i64;
            for k in 0..count {
                insn.targets.push(base + u32_at(bytes, p + k * 4) as i32 as i64);
            }
            insn.is_switch = true;
            insn.a = count as i64;
            p += count * 4;
        }
        _ => {
            // A token.
            if !need(p, 4) {
                return as_byte(insn, first);
            }
            insn.a = u32_at(bytes, p) as i64;
            p += 4;
        }
    }
    insn.len = (p - pos) as u32;
}

/// A byte that is no instruction (or an instruction whose operand runs past the end of the method): its first byte, as data.
fn as_byte(insn: &mut CilInsn, first: Option<u8>) {
    insn.op = None;
    insn.m = ".byte";
    insn.a = first.map_or(0, |b| b as i64);
    insn.len = 1;
}
