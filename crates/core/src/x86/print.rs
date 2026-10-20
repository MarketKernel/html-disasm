//! x86 instructions printed as LLVM's Intel printer prints them
//! (X86IntelInstPrinter and the parts it shares with the AT&T one), so a
//! line here is the line llvm-objdump -M intel prints, up to whitespace.
//!
//! Each instruction's template (tables.bin) is the Intel half of its
//! assembly string with every operand replaced by the MCInst operand it
//! prints and the method that prints it. Before the template come the
//! prefixes the printer writes on its own (lock, rep, notrack, {vex},
//! addr32); a few instructions print as an alias, and the vector compares
//! with the predicate folded into the mnemonic (cmpltps, vpcmpgtd).
//!
//! A port of src/core/x86/print.ts: the same text for every instruction,
//! written into inline strings (nothing on the heap).

use std::sync::OnceLock;

use super::decode::{info as info_bits, pfx, to_int32, x86_tables, McOp, X86Decoded};
use super::tables::{special, ALIASES, PRINT_METHODS, SUFFIXES, XACQUIRE, XRELEASE};
use crate::text::{push_dec, push_hex, push_hex_u64, Str};

// The sizes are what the longest text needs, with room to spare: over tens of millions of random
// encodings the longest prefix text was 17 bytes, mnemonic 17 (the longest template has 17 too),
// operands 71, line 86.

/// The prefixes as printed: `lock notrack repne {nf} {evex} addr32` at the most.
pub type Prefix = Str<47>;
/// A mnemonic: `mov`, `cmpltps`, `vcmpfalse_osbf16`, `tconjtcmmimfp16ps`.
pub type Mn = Str<23>;
/// The operands as printed: `zmm31 {k7} {z}, zmm30, zmmword ptr fs:[r31 + 8*zmm31 - 0x80000000]`.
pub type OpsText = Str<127>;
/// A whole line (`formatX86`).
pub type Line = Str<199>;
/// An immediate or an address in hex.
pub type Hex = Str<23>;

/// The instruction text before it is cut into mnemonic and operands.
type Text = Str<199>;

pub struct X86Printed {
    /// What the printer writes before the instruction: `lock`, `rep`, `notrack`, `{vex}`, `addr32`, joined by spaces.
    pub prefix: Prefix,
    /// The mnemonic: `mov`, `jne`, `cmpltps`, `vpaddd`.
    pub m: Mn,
    /// The operands as printed: `qword ptr [rbp - 0x8], rdi`.
    pub ops: OpsText,
}

/// LLVM's formatImm in hex, written to `out`: `0x1f`, `-0x80`.
#[inline]
fn push_imm<const N: usize>(out: &mut Str<N>, v: Option<&McOp>) {
    match v {
        // BigInt.asIntN(64, v): the bits as read are that already.
        Some(&McOp::Imm(v)) | Some(&McOp::Big(v)) => push_hex(out, v),
        // A string's toString ignores the radix (it never comes to that).
        Some(&McOp::Reg(s)) => {
            out.push("0x");
            out.push(s);
        }
        None => out.push("0xundefined"),
    }
}

/// LLVM's formatImm in hex: `0x1f`, `-0x80`.
pub fn format_imm(v: &McOp) -> Hex {
    let mut out = Hex::new();
    push_imm(&mut out, Some(v));
    out
}

/// An unsigned 64-bit address in hex, as formatHex(uint64_t) prints it.
pub fn format_address(v: i64) -> Hex {
    let mut out = Hex::new();
    push_address(&mut out, v);
    out
}

#[inline]
fn push_address<const N: usize>(out: &mut Str<N>, v: i64) {
    // BigInt.asUintN(64, v) for a negative one.
    out.push("0x");
    push_hex_u64(out, v as u64);
}

static CONDITIONS: [&str; 16] = ["o", "no", "b", "ae", "e", "ne", "be", "a", "s", "ns", "p", "np", "l", "ge", "le", "g"];
#[rustfmt::skip]
static SSE_AVX_CC: [&str; 32] = ["eq", "lt", "le", "unord", "neq", "nlt", "nle", "ord", "eq_uq", "nge", "ngt", "false", "neq_oq", "ge", "gt", "true", "eq_os", "lt_oq", "le_oq", "unord_s", "neq_us", "nlt_uq", "nle_uq", "ord_s", "eq_us", "nge_uq", "ngt_uq", "false_os", "neq_os", "ge_oq", "gt_oq", "true_us"];
static VPCOM_CC: [&str; 8] = ["lt", "le", "gt", "ge", "eq", "neq", "false", "true"];
static ROUNDING: [&str; 4] = ["{rn-sae}", "{rd-sae}", "{ru-sae}", "{rz-sae}"];
#[rustfmt::skip]
static GR16: [&str; 32] = ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w", "r16w", "r17w", "r18w", "r19w", "r20w", "r21w", "r22w", "r23w", "r24w", "r25w", "r26w", "r27w", "r28w", "r29w", "r30w", "r31w"];
#[rustfmt::skip]
static GR32: [&str; 32] = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d", "r16d", "r17d", "r18d", "r19d", "r20d", "r21d", "r22d", "r23d", "r24d", "r25d", "r26d", "r27d", "r28d", "r29d", "r30d", "r31d"];

/// How a print method prints its operand.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Method {
    Operand,
    /// A memory reference after its size: `qword ptr ` (MEM_SIZE in print.ts).
    Mem(&'static str),
    U8Imm,
    PcRelImm,
    STiReg,
    CondCode,
    CondFlags,
    RoundingControl,
    /// printVKPair, printTILEPair.
    Pair,
    MemOffs(&'static str),
    SrcIdx(&'static str),
    DstIdx(&'static str),
    Unknown,
}

/// SIZE_OF_SUFFIX in print.ts.
fn size_of_suffix(bits: &str) -> &'static str {
    match bits {
        "8" => "byte ptr ",
        "16" => "word ptr ",
        "32" => "dword ptr ",
        "64" => "qword ptr ",
        // `undefined` in a template literal: no such method in the tables.
        _ => "undefined",
    }
}

fn method_of(name: &str) -> Method {
    let mem = match name {
        "printbytemem" => Some("byte ptr "),
        "printwordmem" => Some("word ptr "),
        "printdwordmem" => Some("dword ptr "),
        "printqwordmem" => Some("qword ptr "),
        "printxmmwordmem" => Some("xmmword ptr "),
        "printymmwordmem" => Some("ymmword ptr "),
        "printzmmwordmem" => Some("zmmword ptr "),
        "printtbytemem" => Some("tbyte ptr "),
        "printMemReference" => Some(""),
        _ => None,
    };
    if let Some(size) = mem {
        return Method::Mem(size);
    }
    match name {
        "printOperand" => return Method::Operand,
        "printU8Imm" => return Method::U8Imm,
        "printPCRelImm" => return Method::PcRelImm,
        "printSTiRegOperand" => return Method::STiReg,
        "printCondCode" => return Method::CondCode,
        "printCondFlags" => return Method::CondFlags,
        "printRoundingControl" => return Method::RoundingControl,
        "printVKPair" | "printTILEPair" => return Method::Pair,
        _ => {}
    }
    let digits = |prefix: &str| name.strip_prefix(prefix).filter(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()));
    if let Some(bits) = digits("printMemOffs") {
        return Method::MemOffs(size_of_suffix(bits));
    }
    if let Some(bits) = digits("printSrcIdx") {
        return Method::SrcIdx(size_of_suffix(bits));
    }
    if let Some(bits) = digits("printDstIdx") {
        return Method::DstIdx(size_of_suffix(bits));
    }
    Method::Unknown
}

/// A template, parsed: literal text (a range of the tables' template text), or an MCInst operand and its print method.
#[derive(Clone, Copy)]
enum Part {
    Literal(&'static str),
    Operand { at: u8, method: Method },
}

/// The templates, parsed once (the `parsed` map of print.ts, for all of them at once).
struct Parsed {
    parts: Vec<Part>,
    /// Each template's parts: `parts[start..end]`.
    ranges: Vec<(u32, u32)>,
    /// The mnemonic of each template whose mnemonic is plain text (most are); `None` where conditions make it.
    literal: Vec<Option<Mn>>,
}

static PARSED: OnceLock<Parsed> = OnceLock::new();

fn parsed() -> &'static Parsed {
    PARSED.get_or_init(|| {
        let t = x86_tables();
        let methods: Vec<Method> = PRINT_METHODS.iter().map(|name| method_of(name)).collect();
        let mut parsed = Parsed { parts: Vec::new(), ranges: Vec::new(), literal: Vec::new() };
        for index in 0..t.template_count() {
            let text = t.template_text(index);
            let bytes = text.as_bytes();
            let start = parsed.parts.len();
            let mut literal = 0;
            let mut i = 0;
            while i < bytes.len() {
                if bytes[i] == 1 {
                    if literal < i {
                        parsed.parts.push(Part::Literal(&text[literal..i]));
                    }
                    let at = bytes.get(i + 1).map_or(0, |b| b.wrapping_sub(65));
                    let method = bytes.get(i + 2).and_then(|b| methods.get(b.wrapping_sub(65) as usize)).copied().unwrap_or(Method::Unknown);
                    parsed.parts.push(Part::Operand { at, method });
                    i += 3;
                    literal = i;
                } else {
                    i += 1;
                }
            }
            if literal < bytes.len() {
                parsed.parts.push(Part::Literal(&text[literal..]));
            }
            let parts = &parsed.parts[start..];
            let mnemonic = match parts.first() {
                Some(Part::Literal(first)) if first.contains('\t') || parts.len() == 1 => Some(Mn::from(first.split('\t').next().unwrap_or(""))),
                _ => None,
            };
            parsed.ranges.push((start as u32, parsed.parts.len() as u32));
            parsed.literal.push(mnemonic);
        }
        parsed
    })
}

#[inline]
fn template_parts(index: usize) -> &'static [Part] {
    let p = parsed();
    match p.ranges.get(index) {
        Some(&(start, end)) => &p.parts[start as usize..end as usize],
        None => &[],
    }
}

/// JavaScript's truthiness of an operand (`undefined` when it is missing).
#[inline]
fn truthy(op: Option<&McOp>) -> bool {
    match op {
        Some(&McOp::Reg(s)) => !s.is_empty(),
        Some(&McOp::Imm(v)) | Some(&McOp::Big(v)) => v != 0,
        None => false,
    }
}

/// JavaScript's `String(op)`.
fn push_string<const N: usize>(out: &mut Str<N>, op: Option<&McOp>) {
    match op {
        Some(&McOp::Reg(s)) => out.push(s),
        Some(&McOp::Imm(v)) => push_dec(out, v),
        Some(&McOp::Big(v)) => {
            // The bigint's decimal digits: the 64 bits unsigned.
            let mut tmp = [0u8; 20];
            let mut i = tmp.len();
            let mut u = v as u64;
            loop {
                i -= 1;
                tmp[i] = b'0' + (u % 10) as u8;
                u /= 10;
                if u == 0 {
                    break;
                }
            }
            // SAFETY: decimal digits are ASCII.
            out.push(unsafe { core::str::from_utf8_unchecked(&tmp[i..]) });
        }
        None => out.push("undefined"),
    }
}

/// JavaScript's `Number(ops[i])` (NaN when it is missing).
#[inline]
fn number(op: Option<&McOp>) -> f64 {
    op.map_or(f64::NAN, McOp::number)
}

/// The integer a JavaScript number indexes an array with, if it does.
#[inline]
fn index_of(v: f64) -> Option<usize> {
    if v >= 0.0 && v.fract() == 0.0 && v < 1e9 {
        Some(v as usize)
    } else {
        None
    }
}

struct Printer<'a> {
    d: &'a X86Decoded,
}

impl Printer<'_> {
    #[inline]
    fn op(&self, i: usize) -> Option<&McOp> {
        self.d.ops.get(i)
    }

    fn operand<const N: usize>(&self, out: &mut Str<N>, i: usize) {
        match self.op(i) {
            Some(&McOp::Reg(s)) => out.push(s),
            None => {}
            op => push_imm(out, op),
        }
    }

    fn memory<const N: usize>(&self, out: &mut Str<N>, i: usize) {
        let base = self.op(i);
        let scale = self.op(i + 1);
        let index = self.op(i + 2);
        let disp = self.op(i + 3);
        let seg = self.op(i + 4);
        if truthy(seg) {
            push_string(out, seg);
            out.push(":[");
        } else {
            out.push("[");
        }
        let mut plus = false;
        if truthy(base) {
            push_string(out, base);
            plus = true;
        }
        if truthy(index) {
            if plus {
                out.push(" + ");
            }
            if scale != Some(&McOp::Imm(1)) || !truthy(base) {
                push_string(out, scale);
                out.push("*");
            }
            push_string(out, index);
            plus = true;
        }
        if truthy(disp) || (!truthy(index) && !truthy(base)) {
            let mut disp = disp.copied();
            if plus {
                if number(disp.as_ref()) > 0.0 {
                    out.push(" + ");
                } else {
                    out.push(" - ");
                    disp = disp.map(|d| match d {
                        McOp::Imm(v) => McOp::Imm(-v),
                        McOp::Big(v) => McOp::Big(v.wrapping_neg()),
                        other => other,
                    });
                }
            }
            push_imm(out, disp.as_ref());
        }
        out.push("]");
    }

    fn method<const N: usize>(&self, out: &mut Str<N>, method: Method, i: usize) {
        match method {
            Method::Mem(size) => {
                out.push(size);
                self.memory(out, i);
            }
            Method::Operand => self.operand(out, i),
            Method::U8Imm => push_hex(out, (to_int32(number(self.op(i))) & 0xff) as i64),
            Method::PcRelImm => {
                let d = self.d;
                match self.op(i) {
                    Some(&McOp::Imm(v)) => {
                        let mut target = d.addr + d.length as i64 + v;
                        if d.mode == 32 {
                            target = target as u32 as i64;
                        }
                        push_address(out, target);
                    }
                    op => {
                        // Not an immediate a decoder makes: the arithmetic of JavaScript numbers.
                        let mut target = d.addr as f64 + d.length as f64 + number(op);
                        if d.mode == 32 {
                            target = to_int32(target) as u32 as f64;
                        }
                        if target.is_nan() {
                            out.push("0xNaN");
                        } else if target < 0.0 {
                            push_address(out, target as i64);
                        } else {
                            out.push("0x");
                            out.push(&crate::text::js_hex(target));
                        }
                    }
                }
            }
            Method::STiReg => {
                if self.op(i) == Some(&McOp::Reg("st")) {
                    out.push("st(0)");
                } else {
                    self.operand(out, i);
                }
            }
            Method::CondCode => {
                let cc = number(self.op(i));
                if info_of(self.d.id) & info_bits::CCMP != 0 && (cc == 10.0 || cc == 11.0) {
                    out.push(if cc == 10.0 { "t" } else { "f" });
                } else if let Some(name) = index_of(cc).and_then(|k| CONDITIONS.get(k)) {
                    out.push(name);
                }
            }
            Method::CondFlags => {
                let v = to_int32(number(self.op(i)));
                out.push("{dfv=");
                let mut first = true;
                for (bit, name) in [(8, "of"), (4, "sf"), (2, "zf"), (1, "cf")] {
                    if v & bit != 0 {
                        if !first {
                            out.push(",");
                        }
                        out.push(name);
                        first = false;
                    }
                }
                out.push("}");
            }
            Method::RoundingControl => out.push(ROUNDING[(to_int32(number(self.op(i))) & 3) as usize]),
            Method::Pair => {
                // A pair prints as its first register: K2_K3 as k2.
                let mut s = Str::<32>::new();
                push_string(&mut s, self.op(i));
                for b in s.split('_').next().unwrap_or("").bytes() {
                    out.push_byte(b.to_ascii_lowercase());
                }
            }
            Method::MemOffs(size) => {
                out.push(size);
                let seg = self.op(i + 1);
                if truthy(seg) {
                    push_string(out, seg);
                    out.push(":");
                }
                out.push("[");
                push_imm(out, self.op(i));
                out.push("]");
            }
            Method::SrcIdx(size) => {
                out.push(size);
                let seg = self.op(i + 1);
                if truthy(seg) {
                    push_string(out, seg);
                    out.push(":");
                }
                out.push("[");
                self.operand(out, i);
                out.push("]");
            }
            Method::DstIdx(size) => {
                out.push(size);
                out.push("es:[");
                self.operand(out, i);
                out.push("]");
            }
            // print.ts throws: the tables name no other method.
            Method::Unknown => debug_assert!(false, "x86 printer: an unknown method"),
        }
    }

    /// X86_MC::needsAddressSizeOverride: whether 67 is already implied by the operands (so addr32 is not printed).
    fn address_size_implied(&self, info: u32) -> bool {
        let mode = self.d.mode;
        let adsize = (info >> info_bits::ADSIZE_SHIFT) & 3;
        if (mode == 32 && adsize == 1) || (mode == 64 && adsize == 2) {
            return true;
        }
        let raw = (info >> info_bits::RAW_SHIFT) & 3;
        let is = |i: usize, name: &str| matches!(self.op(i), Some(McOp::Reg(s)) if *s == name);
        if raw == 1 {
            return (mode != 32 && is(1, "esi")) || (mode == 32 && is(1, "si"));
        }
        if raw == 2 {
            return (mode != 32 && is(0, "esi")) || (mode == 32 && is(0, "si"));
        }
        if raw == 3 {
            return (mode != 32 && is(0, "edi")) || (mode == 32 && is(0, "di"));
        }
        let at = ((info >> info_bits::MEMOP_SHIFT) & 15) as usize;
        if at == 15 {
            return false;
        }
        let base = self.op(at).and_then(McOp::reg);
        let index = self.op(at + 2).and_then(McOp::reg);
        let within = |set: &[&str], name: Option<&str>| name.is_some_and(|n| set.contains(&n));
        if mode == 64 {
            if base == Some("eip") {
                return true;
            }
            if index == Some("eiz") {
                return true;
            }
            return within(&GR32, base) || within(&GR32, index);
        }
        within(&GR16, base) || within(&GR16, index)
    }

    /// X86IntelInstPrinter::printVecCompareInstr, or false (nothing written) when it does not apply.
    /// With `only_mnemonic`, it writes the mnemonic alone.
    fn vector_compare<const N: usize>(&self, out: &mut Str<N>, info: u32, only_mnemonic: bool) -> bool {
        let kind = (info >> info_bits::VCMP_SHIFT) & 7;
        if kind == 0 {
            return false;
        }
        let ops = self.d.ops.as_slice();
        let last = match ops.last() {
            None | Some(McOp::Reg(_)) => return false,
            Some(last) => last,
        };
        let imm = last.number();
        let suffix = SUFFIXES[((info >> info_bits::SUFFIX_SHIFT) & 15) as usize];
        let src_mem = info & info_bits::SRCMEM != 0;
        let has = |bit: u32| info & bit != 0;
        let cc = |table: &'static [&'static str]| table[imm as usize];
        if kind == 1 {
            if !(0.0..=7.0).contains(&imm) {
                return false;
            }
            out.push("cmp");
            out.push(cc(&SSE_AVX_CC));
            out.push(suffix);
            if only_mnemonic {
                return true;
            }
            out.push("\t");
            self.operand(out, 0);
            out.push(", ");
            if src_mem {
                out.push(if has(info_bits::XS) {
                    "dword ptr "
                } else if has(info_bits::XD) {
                    "qword ptr "
                } else {
                    "xmmword ptr "
                });
                self.memory(out, 2);
            } else {
                self.operand(out, 2);
            }
            return true;
        }
        if kind == 3 {
            if !(0.0..=7.0).contains(&imm) {
                return false;
            }
            out.push("vpcom");
            out.push(cc(&VPCOM_CC));
            out.push(suffix);
            if only_mnemonic {
                return true;
            }
            out.push("\t");
            self.operand(out, 0);
            out.push(", ");
            self.operand(out, 1);
            out.push(", ");
            if src_mem {
                out.push("xmmword ptr ");
                self.memory(out, 2);
            } else {
                self.operand(out, 2);
            }
            return true;
        }
        let valid = if kind == 2 { (0.0..=31.0).contains(&imm) } else { (0.0..=2.0).contains(&imm) || (4.0..=6.0).contains(&imm) };
        if !valid {
            return false;
        }
        out.push(if kind == 2 { "vcmp" } else { "vpcmp" });
        out.push(cc(&SSE_AVX_CC));
        out.push(suffix);
        if only_mnemonic {
            return true;
        }
        out.push("\t");
        let mut cur = 0;
        self.operand(out, cur);
        cur += 1;
        if has(info_bits::EVEX_K) {
            out.push(" {");
            self.operand(out, cur);
            cur += 1;
            out.push("}");
        }
        out.push(", ");
        self.operand(out, cur);
        cur += 1;
        out.push(", ");
        let w = has(info_bits::REX_W);
        let ta = kind == 2 && has(info_bits::TA);
        if src_mem {
            if has(info_bits::EVEX_B) {
                out.push(if ta {
                    "word ptr "
                } else if w {
                    "qword ptr "
                } else {
                    "dword ptr "
                });
                self.memory(out, cur);
                let mut elements = if has(info_bits::EVEX_L2) {
                    if w {
                        8
                    } else {
                        16
                    }
                } else if has(info_bits::VEX_L) {
                    if w {
                        4
                    } else {
                        8
                    }
                } else if w {
                    2
                } else {
                    4
                };
                if ta {
                    elements *= 2;
                }
                out.push("{1to");
                push_dec(out, elements);
                out.push("}");
            } else if kind == 2 && has(info_bits::XS) {
                out.push(if ta { "word ptr " } else { "dword ptr " });
                self.memory(out, cur);
            } else if kind == 2 && has(info_bits::XD) && !ta {
                out.push("qword ptr ");
                self.memory(out, cur);
            } else {
                out.push(if has(info_bits::EVEX_L2) {
                    "zmmword ptr "
                } else if has(info_bits::VEX_L) {
                    "ymmword ptr "
                } else {
                    "xmmword ptr "
                });
                self.memory(out, cur);
            }
        } else {
            self.operand(out, cur);
            if kind == 2 && has(info_bits::EVEX_B) {
                out.push(", {sae}");
            }
        }
        true
    }

    /// The prefixes the printer writes before the instruction, joined by spaces.
    fn prefixes(&self, info: u32) -> Prefix {
        let d = self.d;
        let mut out = Prefix::new();
        let mut add = |s: &str| {
            if !out.is_empty() {
                out.push(" ");
            }
            out.push(s);
        };
        if info & info_bits::LOCK != 0 || d.flags & pfx::LOCK != 0 {
            add("lock");
        }
        if info & info_bits::NOTRACK != 0 {
            add("notrack");
        }
        if d.flags & pfx::REPEAT_NE != 0 {
            add("repne");
        } else if d.flags & pfx::REPEAT != 0 {
            add("rep");
        }
        if info & info_bits::NF != 0 {
            add("{nf}");
        }
        if info & info_bits::EXPLICIT_VEX != 0 {
            add("{vex}");
        } else if info & info_bits::EXPLICIT_EVEX != 0 {
            add("{evex}");
        }
        if d.flags & pfx::AD_SIZE != 0 && !self.address_size_implied(info) {
            add(if d.mode == 64 { "addr32" } else { "addr16" });
        }
        out
    }

    /// The alias the instruction prints as, if its immediates make it one.
    fn alias(&self) -> Option<&'static str> {
        let d = self.d;
        ALIASES
            .iter()
            .find(|(id, conds, _)| *id == d.id && conds.iter().all(|&(at, value)| matches!(self.op(at), Some(McOp::Imm(_) | McOp::Big(_))) && number(self.op(at)) == value as f64))
            .map(|a| a.2)
    }

    /// The instruction's text (mnemonic, a tab, the operands), or with `only_mnemonic` the text before the first tab.
    fn text<const N: usize>(&self, out: &mut Str<N>, info: u32, only_mnemonic: bool) {
        let d = self.d;
        let fixed = if d.xacquire { Some(if d.id == special::REP_PREFIX { XRELEASE } else { XACQUIRE }) } else { self.alias() };
        if let Some(text) = fixed {
            out.push(if only_mnemonic { text.split('\t').next().unwrap_or("") } else { text });
            return;
        }
        if self.vector_compare(out, info, only_mnemonic) {
            return;
        }
        let template = x86_tables().template.get(d.id as usize).copied().unwrap_or(0) as usize;
        for part in template_parts(template) {
            match *part {
                Part::Literal(s) => {
                    if only_mnemonic {
                        if let Some(tab) = s.find('\t') {
                            out.push(&s[..tab]);
                            return;
                        }
                    }
                    out.push(s);
                }
                Part::Operand { at, method } => self.method(out, method, at as usize),
            }
        }
    }
}

#[inline]
fn info_of(id: u32) -> u32 {
    x86_tables().info.get(id as usize).copied().unwrap_or(0)
}

/// How an instruction prints; one that did not decode prints as LLVM's `<unknown>`.
pub fn print_x86(d: &X86Decoded) -> X86Printed {
    if d.id == 0 {
        return X86Printed { prefix: Prefix::new(), m: Mn::from("<unknown>"), ops: OpsText::new() };
    }
    let printer = Printer { d };
    let info = info_of(d.id);
    let prefix = printer.prefixes(info);
    let mut text = Text::new();
    printer.text(&mut text, info, false);
    let (m, ops) = match text.find('\t') {
        None => (text.as_str(), ""),
        Some(tab) => (&text[..tab], text[tab + 1..].trim()),
    };
    let mut out = OpsText::new();
    // `.replace(/\t/g, ' ').trim()`: tabs inside the operands become spaces (the trim saw them as spaces too).
    for b in ops.bytes() {
        out.push_byte(if b == b'\t' { b' ' } else { b });
    }
    X86Printed { prefix, m: Mn::from(m), ops: out }
}

/// The whole line, with single spaces: `lock cmpxchg qword ptr [rdi], rcx`.
pub fn format_x86(p: &X86Printed) -> Line {
    let mut out = Line::new();
    for part in [p.prefix.as_str(), p.m.as_str(), p.ops.as_str()] {
        if part.is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push(" ");
        }
        out.push(part);
    }
    out
}

/// Only the mnemonic, as print_x86 would print it: cheaper, for counting every instruction (no operand text is built).
pub fn mnemonic_x86(d: &X86Decoded) -> Mn {
    if d.id == 0 {
        return Mn::from("<unknown>");
    }
    let t = x86_tables();
    let template = t.template.get(d.id as usize).copied().unwrap_or(0) as usize;
    let info = info_of(d.id);
    if let Some(Some(literal)) = parsed().literal.get(template) {
        if !d.xacquire && (info >> info_bits::VCMP_SHIFT) & 7 == 0 && !ALIASES.iter().any(|a| a.0 == d.id) {
            return *literal;
        }
    }
    let mut m = Mn::new();
    Printer { d }.text(&mut m, info, true);
    m
}
