//! JVM instructions: decoded from a method's Code and printed as javap -c
//! prints them — the mnemonic padded to thirteen columns, then the operand: a
//! local's slot, a constant, a branch's target pc, a constant pool index
//! (`#7`) with what it names after `//` (`Field java/lang/System.out:…`), a
//! switch's cases. javap writes a switch on several lines; here it is one, the
//! lines joined by spaces. `tools/verify-jvm.mjs` compares the text with
//! javap's.
//!
//! A port of src/core/jvm/decode.ts. Decoding allocates nothing: one
//! `JvmInsn` is reused while a method is read (a switch's cases go into its
//! vectors, which keep their room).

use core::fmt::Write;

use super::classfile::{write_constant_comment, ClassFile};
use super::opcodes::{atype, one, wide, OpInfo, Operand};
use super::wtf8::Wtf8Buf;

/// A decoded instruction; one is reused while a method is read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JvmInsn {
    pub op: Option<&'static OpInfo>,
    /// Its pc (offset in the method's code), and its length in bytes.
    pub at: usize,
    pub len: usize,
    /// The mnemonic (`.byte` for a byte that is not an opcode, or one whose operands run past the code).
    pub m: &'static str,
    /// A slot, a constant, a constant pool index, a branch's target pc, an array type, a switch's default target.
    pub a: i64,
    /// iinc's constant, invokeinterface's count, multianewarray's dimensions.
    pub b: i32,
    /// A switch: the value of each case and where it goes (pcs), in the order of the instruction. Empty for anything else.
    pub keys: Vec<i32>,
    pub targets: Vec<i64>,
}

impl Default for JvmInsn {
    fn default() -> Self {
        JvmInsn { op: None, at: 0, len: 1, m: "", a: 0, b: 0, keys: Vec::new(), targets: Vec::new() }
    }
}

impl JvmInsn {
    pub fn new() -> Self {
        Self::default()
    }
}

/// Decodes the instruction at `pos` of a method whose code is `bytes[start, end)`. A `pos` at or
/// past the end (which the TypeScript never asks for) is a `.byte` of 0.
pub fn decode_at<'a>(bytes: &[u8], start: usize, pos: usize, end: usize, into: &'a mut JvmInsn) -> &'a mut JvmInsn {
    let insn = into;
    // Never read past the bytes, whatever `end` says.
    let end = end.min(bytes.len());
    let pc = pos.wrapping_sub(start);
    insn.at = pc;
    insn.a = 0;
    insn.b = 0;
    insn.keys.clear();
    insn.targets.clear();
    if pos >= end {
        return unknown(insn, 0);
    }
    let first = bytes[pos];
    let op;
    let mut p = pos + 1;
    if first == 0xc4 {
        op = if pos + 1 < end { wide(bytes[pos + 1]) } else { None };
        p = pos + 2;
    } else {
        op = one(first);
    }
    let Some(op) = op else { return unknown(insn, first) };
    // Big-endian reads; `need` has checked the bytes are there.
    let u2 = |at: usize| ((bytes[at] as u32) << 8 | bytes[at + 1] as u32) as i64;
    let s4 = |at: usize| i32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]) as i64;
    let s1 = |at: usize| bytes[at] as i8 as i64;
    let s2 = |at: usize| i16::from_be_bytes([bytes[at], bytes[at + 1]]) as i64;
    let need = |p: usize, n: i64| (p as i64).saturating_add(n) <= end as i64;
    let pc64 = pc as i64;
    insn.op = Some(op);
    insn.m = op.name;
    match op.operand {
        Operand::None => {}
        Operand::Local | Operand::Ret | Operand::Cp8 | Operand::Atype => {
            if !need(p, 1) {
                return unknown(insn, first);
            }
            insn.a = bytes[p] as i64;
            p += 1;
        }
        Operand::Byte => {
            if !need(p, 1) {
                return unknown(insn, first);
            }
            insn.a = s1(p);
            p += 1;
        }
        Operand::LocalW | Operand::RetW | Operand::Cp16 => {
            if !need(p, 2) {
                return unknown(insn, first);
            }
            insn.a = u2(p);
            p += 2;
        }
        Operand::Short => {
            if !need(p, 2) {
                return unknown(insn, first);
            }
            insn.a = s2(p);
            p += 2;
        }
        Operand::Iinc => {
            if !need(p, 2) {
                return unknown(insn, first);
            }
            insn.a = bytes[p] as i64;
            insn.b = s1(p + 1) as i32;
            p += 2;
        }
        Operand::IincW => {
            if !need(p, 4) {
                return unknown(insn, first);
            }
            insn.a = u2(p);
            insn.b = s2(p + 2) as i32;
            p += 4;
        }
        Operand::Interface | Operand::Dynamic => {
            if !need(p, 4) {
                return unknown(insn, first);
            }
            insn.a = u2(p);
            insn.b = bytes[p + 2] as i32;
            p += 4;
        }
        Operand::Dimensions => {
            if !need(p, 3) {
                return unknown(insn, first);
            }
            insn.a = u2(p);
            insn.b = bytes[p + 2] as i32;
            p += 3;
        }
        Operand::Branch16 | Operand::Jsr16 => {
            if !need(p, 2) {
                return unknown(insn, first);
            }
            insn.a = pc64 + s2(p);
            p += 2;
        }
        Operand::Branch32 | Operand::Jsr32 => {
            if !need(p, 4) {
                return unknown(insn, first);
            }
            insn.a = pc64 + s4(p);
            p += 4;
        }
        Operand::TableSwitch | Operand::LookupSwitch => {
            // The operands start at a multiple of four from the start of the code.
            p += (4 - (pc.wrapping_add(1) % 4)) % 4;
            if !need(p, 8) {
                return unknown(insn, first);
            }
            insn.a = pc64 + s4(p);
            if op.operand == Operand::TableSwitch {
                if !need(p, 12) {
                    return unknown(insn, first);
                }
                let low = s4(p + 4);
                let high = s4(p + 8);
                p += 12;
                let count = high - low + 1;
                if count < 0 || !need(p, count * 4) {
                    return unknown(insn, first);
                }
                for k in 0..count as usize {
                    insn.keys.push((low + k as i64) as i32);
                    insn.targets.push(pc64 + s4(p + k * 4));
                }
                p += count as usize * 4;
            } else {
                let count = s4(p + 4);
                p += 8;
                if count < 0 || !need(p, count * 8) {
                    return unknown(insn, first);
                }
                for k in 0..count as usize {
                    insn.keys.push(s4(p + k * 8) as i32);
                    insn.targets.push(pc64 + s4(p + k * 8 + 4));
                }
                p += count as usize * 8;
            }
        }
    }
    insn.len = p - pos;
    insn
}

fn unknown(insn: &mut JvmInsn, first: u8) -> &mut JvmInsn {
    insn.op = None;
    insn.m = ".byte";
    insn.a = first as i64;
    insn.len = 1;
    insn.keys.clear();
    insn.targets.clear();
    insn
}

/// The constant pool index an instruction names, or 0.
pub fn pool_index(insn: &JvmInsn) -> usize {
    match insn.op.map(|op| op.operand) {
        Some(Operand::Cp8 | Operand::Cp16 | Operand::Interface | Operand::Dynamic | Operand::Dimensions) => insn.a as usize,
        _ => 0,
    }
}

/// An instruction's operand as javap prints it, and what it writes after `//` (empty for nothing).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OperandText {
    pub operand: String,
    pub comment: Wtf8Buf,
}

/// The operand of an instruction as javap prints it, and what it writes after `//`.
pub fn operand_text(cf: &ClassFile, insn: &JvmInsn) -> OperandText {
    let mut out = OperandText::default();
    write_operand_text(cf, insn, &mut out.operand, &mut out.comment);
    out
}

/// `operand_text`, appended to `operand` and `comment`.
pub fn write_operand_text(cf: &ClassFile, insn: &JvmInsn, operand: &mut String, comment: &mut Wtf8Buf) {
    if let Some(index) = write_operand(insn, operand) {
        write_constant_comment(cf, index, comment);
    }
}

/// Writes the operand; returns the constant pool index javap writes after `//`, if there is one.
fn write_operand(insn: &JvmInsn, operand: &mut impl Write) -> Option<usize> {
    let Some(op) = insn.op else {
        let _ = write!(operand, "0x{:02x}", insn.a);
        return None;
    };
    match op.operand {
        Operand::Local | Operand::LocalW | Operand::Byte | Operand::Short | Operand::Branch16 | Operand::Branch32 => {
            let _ = write!(operand, "{}", insn.a);
        }
        Operand::Iinc | Operand::IincW => {
            let _ = write!(operand, "{}, {}", insn.a, insn.b);
        }
        Operand::Cp8 | Operand::Cp16 => {
            let _ = write!(operand, "#{}", insn.a);
            return Some(insn.a as usize);
        }
        Operand::Interface | Operand::Dimensions => {
            let _ = write!(operand, "#{},  {}", insn.a, insn.b);
            return Some(insn.a as usize);
        }
        Operand::Dynamic => {
            let _ = write!(operand, "#{},  0", insn.a);
            return Some(insn.a as usize);
        }
        Operand::Atype => {
            let _ = match atype(insn.a) {
                Some(name) => operand.write_str(name),
                None => write!(operand, "{}", insn.a),
            };
        }
        Operand::TableSwitch | Operand::LookupSwitch => {
            let keys = &insn.keys;
            let _ = if op.operand == Operand::TableSwitch {
                write!(operand, "{{ // {} to {}", keys.first().copied().unwrap_or(0), keys.last().map_or(-1, |&k| k as i64))
            } else {
                write!(operand, "{{ // {}", keys.len())
            };
            for (k, key) in keys.iter().enumerate() {
                let _ = write!(operand, " {}: {}", key, insn.targets[k]);
            }
            let _ = write!(operand, " default: {} }}", insn.a);
        }
        // jsr and ret: javap leaves their operands out.
        Operand::None | Operand::Jsr16 | Operand::Jsr32 | Operand::Ret | Operand::RetW => {}
    }
    None
}

/// An instruction as javap prints it after its pc: `getstatic     #7                  // Field …`, the comment after two spaces.
pub fn insn_text(cf: &ClassFile, insn: &JvmInsn) -> Wtf8Buf {
    let mut out = Wtf8Buf::new();
    write_insn_text(cf, insn, &mut out);
    out
}

/// `insn_text`, appended to `out`.
pub fn write_insn_text(cf: &ClassFile, insn: &JvmInsn, out: &mut Wtf8Buf) {
    if insn.op.is_none() {
        out.push_str(".byte ");
        write_operand(insn, out);
        return;
    }
    // The mnemonic padded to thirteen columns and a space, unless no operand follows.
    let start = out.len();
    out.push_str(insn.m);
    for _ in insn.m.len()..13 {
        out.push_byte(b' ');
    }
    out.push_byte(b' ');
    let at = out.len();
    let comment = write_operand(insn, out);
    if out.len() == at {
        out.truncate_ascii(start + insn.m.len());
    }
    // A constant's comment is never empty.
    if let Some(index) = comment {
        out.push_str("  // ");
        write_constant_comment(cf, index, out);
    }
}

/// The bytes of an instruction as hex: `b6 00 0f`, at most `max` of them (16 in the TypeScript's default), then ` …`.
pub fn bytes_text(bytes: &[u8], at: usize, len: usize, max: usize) -> String {
    let start = at.min(bytes.len());
    let end = at.saturating_add(len.min(max)).min(bytes.len());
    let mut out = String::with_capacity((end - start) * 3 + 4);
    for (k, b) in bytes[start..end].iter().enumerate() {
        if k > 0 {
            out.push(' ');
        }
        let _ = write!(out, "{b:02x}");
    }
    if len > max {
        out.push_str(" …");
    }
    out
}
