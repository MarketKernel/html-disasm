//! The HLA64 view of x86-64 code. HLA64 has an x64 target, with the same
//! sugar as on ARM64 over x86's registers: `rax = [rbx + 8]`, `eax = u8[rdi]`,
//! `rcx += rdx`, `if eax < ebx { goto L }`, `printf()`. As on ARM64 a line is
//! one instruction, or a compare joined with the jump or conditional move that
//! tests its flags, and it uses sugar only where the sugar means exactly what
//! the instruction does; anything else stays the instruction.
//!
//! Two of x86's mnemonics are words of HLA64 itself: on x64 HLA64's `push` and
//! `pop` keep registers in frame slots, so a real `push rbx` is written as
//! what it does (`rsp -= 8; [rsp] = rbx`), and an instruction whose mnemonic
//! HLA64 would read as a keyword (`loop`) goes into `asm "…"`.
//!
//! The operands are read from the instruction as LLVM prints it in Intel
//! syntax, which is regular enough to parse: registers, immediates, and
//! `qword ptr [base + 4*index + disp]`.

use crate::arm64::types::f;
use crate::lift::{hla_name, num, quoted, unique, DataAt, HlaLine, LiftContext, TargetKind, Words};
use crate::text::{js_hex, js_number};

/// An instruction as the HLA64 lifter reads it: as printed, with what the analysis knows of it.
#[derive(Clone, Debug, Default)]
pub struct X86Insn {
    /// Prefixes the printer writes before the mnemonic: `lock`, `rep`, `notrack`, `{vex}`.
    pub prefix: String,
    pub m: String,
    /// The operands as printed.
    pub ops: String,
    pub addr: i64,
    pub length: u32,
    /// F bits (arm64/types): branch, call, return, load, store, flags.
    pub f: u32,
    /// Where a branch or call goes.
    pub target: Option<i64>,
    /// The address a memory operand names, when it is fixed: rip-relative, absolute.
    pub mem: Option<i64>,
}

pub trait X86LiftContext: LiftContext {
    /// The import whose slot is at an address (`call qword ptr [rip + …]`).
    fn import_at(&self, addr: i64) -> Option<String>;
}

/// A context that knows no names: what the analysis lifts with.
pub struct Bare;

impl LiftContext for Bare {
    fn target(&self, _: i64) -> Option<crate::lift::Target> {
        None
    }
    fn data(&self, _: i64) -> Option<DataAt> {
        None
    }
    fn function_start(&self, _: i64) -> i64 {
        -1
    }
}

impl X86LiftContext for Bare {
    fn import_at(&self, _: i64) -> Option<String> {
        None
    }
}

#[derive(Clone, Debug)]
enum Operand {
    Reg { r: String, bits: u32 },
    Imm { v: f64 },
    Mem { size: u32, seg: String, base: String, index: String, scale: u32, disp: f64 },
    Other,
}

fn size_of_ptr(word: &str) -> u32 {
    match word {
        "byte" => 8,
        "word" => 16,
        "dword" => 32,
        "qword" => 64,
        "tbyte" => 80,
        "xmmword" => 128,
        "ymmword" => 256,
        "zmmword" => 512,
        _ => 0,
    }
}

const LEGACY: [&str; 8] = ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di"];

fn all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit())
}

/// The width of a general register, or 0: rax 64, eax 32, ax 16, al 8; xmm 128.
fn register_bits(r: &str) -> u32 {
    let b = r.as_bytes();
    // ^r(?:[abcd]x|[sd]i|[sb]p|\d+)$
    if let Some(rest) = r.strip_prefix('r') {
        if matches!(rest, "ax" | "bx" | "cx" | "dx" | "si" | "di" | "sp" | "bp") || all_digits(rest) {
            return 64;
        }
    }
    // ^(?:e(?:[abcd]x|[sd]i|[sb]p)|r\d+d)$
    if let Some(rest) = r.strip_prefix('e') {
        if matches!(rest, "ax" | "bx" | "cx" | "dx" | "si" | "di" | "sp" | "bp") {
            return 32;
        }
    }
    if b.len() >= 3 && b[0] == b'r' && b[b.len() - 1] == b'd' && all_digits(&r[1..r.len() - 1]) {
        return 32;
    }
    // ^(?:[abcd]x|[sd]i|[sb]p|r\d+w)$
    if matches!(r, "ax" | "bx" | "cx" | "dx" | "si" | "di" | "sp" | "bp") {
        return 16;
    }
    if b.len() >= 3 && b[0] == b'r' && b[b.len() - 1] == b'w' && all_digits(&r[1..r.len() - 1]) {
        return 16;
    }
    // ^(?:[abcd][lh]|[sd]il|[sb]pl|r\d+b)$
    if matches!(r, "al" | "bl" | "cl" | "dl" | "ah" | "bh" | "ch" | "dh" | "sil" | "dil" | "spl" | "bpl") {
        return 8;
    }
    if b.len() >= 3 && b[0] == b'r' && b[b.len() - 1] == b'b' && all_digits(&r[1..r.len() - 1]) {
        return 8;
    }
    // ^xmm\d+$
    if let Some(rest) = r.strip_prefix("xmm") {
        if all_digits(rest) {
            return 128;
        }
    }
    0
}

/// The 32-bit name of a general register, the width HLA64 names next to the 64-bit one: cl → ecx.
fn name32(r: &str) -> Option<String> {
    // ^r(\d+)[bwd]?$
    if let Some(rest) = r.strip_prefix('r') {
        let digits = rest.strip_suffix(['b', 'w', 'd']).unwrap_or(rest);
        if all_digits(digits) {
            return Some(format!("r{digits}d"));
        }
    }
    // ^(?:e|r)?([abcd])(?:x|l)$ and ^(?:e|r)?([sd]i|[sb]p)l?$: with the prefix, or without.
    let bodies = [r.strip_prefix('e'), r.strip_prefix('r'), Some(r)];
    for body in bodies.iter().flatten() {
        let b = body.as_bytes();
        if b.len() == 2 && b"abcd".contains(&b[0]) && (b[1] == b'x' || b[1] == b'l') {
            return Some(format!("e{}x", b[0] as char));
        }
    }
    for body in bodies.iter().flatten() {
        let core = body.strip_suffix('l').unwrap_or(body);
        if LEGACY.contains(&core) && matches!(core, "si" | "di" | "sp" | "bp") {
            return Some(format!("e{core}"));
        }
    }
    None
}

/// `-?0x[0-9a-f]+` as JavaScript's parseInt reads it.
fn parse_hex(t: &str) -> Option<f64> {
    let (neg, body) = match t.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, t),
    };
    let digits = body.strip_prefix("0x")?;
    if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
        return None;
    }
    // V8 reads a power-of-two radix exactly and rounds once, to nearest with ties to even, which
    // is what converting the exact integer does; a digit at a time in doubles would round twice.
    let v = match u128::from_str_radix(digits, 16) {
        Ok(v) => v as f64,
        Err(_) => digits.bytes().fold(0f64, |v, c| v * 16.0 + (if c.is_ascii_digit() { c - b'0' } else { c - b'a' + 10 }) as f64),
    };
    Some(if neg { -v } else { v })
}

fn is_word(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

fn parse_operand(text: &str) -> Operand {
    let t = text.trim();
    let bits = register_bits(t);
    if bits != 0 {
        return Operand::Reg { r: t.to_string(), bits };
    }
    if let Some(v) = parse_hex(t) {
        return Operand::Imm { v };
    }
    // ^(?:(\w+) ptr )?(?:([cdefgs]s):)?\[([^\]]*)\]$
    let mut rest = t;
    let mut size_word: Option<&str> = None;
    if let Some(at) = rest.find(" ptr ") {
        let word = &rest[..at];
        if is_word(word) {
            size_word = Some(word);
            rest = &rest[at + 5..];
        }
    }
    let mut seg = "";
    let rb = rest.as_bytes();
    if rb.len() >= 3 && b"cdefgs".contains(&rb[0]) && rb[1] == b's' && rb[2] == b':' {
        seg = &rest[..2];
        rest = &rest[3..];
    }
    if rest.starts_with('[') && rest.ends_with(']') && !rest[1..rest.len() - 1].contains(']') {
        let inner = &rest[1..rest.len() - 1];
        let size = size_word.map_or(0, size_of_ptr);
        let (mut base, mut index, mut scale, mut disp) = (String::new(), String::new(), 1u32, 0f64);
        let replaced = inner.replace(" - ", " + -");
        for part in replaced.split(" + ") {
            let p = part.trim();
            let pb = p.as_bytes();
            if pb.len() >= 3 && pb[0].is_ascii_digit() && pb[1] == b'*' && is_word(&p[2..]) {
                scale = (pb[0] - b'0') as u32;
                index = p[2..].to_string();
            } else if let Some(v) = parse_hex(p) {
                disp = v;
            } else if register_bits(p) != 0 || p == "rip" {
                if !base.is_empty() {
                    index = p.to_string();
                } else {
                    base = p.to_string();
                }
            } else {
                return Operand::Other;
            }
        }
        return Operand::Mem { size, seg: seg.to_string(), base, index, scale, disp };
    }
    Operand::Other
}

/// The operands of a printed instruction, split at the commas between them.
fn operands_of(ops: &str) -> Vec<Operand> {
    if ops.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut start = 0;
    for (i, c) in ops.bytes().enumerate() {
        match c {
            b'[' | b'{' => depth += 1,
            b']' | b'}' => depth -= 1,
            b',' if depth == 0 => {
                out.push(&ops[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&ops[start..]);
    out.into_iter().map(parse_operand).collect()
}

/// A general register HLA64 can name in sugar: the 64- and 32-bit ones.
fn gpr(op: Option<&Operand>) -> Option<(&str, u32)> {
    match op {
        Some(Operand::Reg { r, bits }) if *bits == 64 || *bits == 32 => Some((r, *bits)),
        _ => None,
    }
}

fn xmm(op: Option<&Operand>) -> Option<&str> {
    match op {
        Some(Operand::Reg { r, bits: 128 }) => Some(r),
        _ => None,
    }
}

/// A value: a register, an immediate.
fn value(op: Option<&Operand>) -> Option<String> {
    match op {
        Some(Operand::Reg { r, .. }) => Some(r.clone()),
        Some(Operand::Imm { v }) => Some(num(*v)),
        _ => None,
    }
}

struct MemRef<'a> {
    size: u32,
    seg: &'a str,
    base: &'a str,
    index: &'a str,
    scale: u32,
    disp: f64,
}

fn mem_of(op: Option<&Operand>) -> Option<MemRef<'_>> {
    match op {
        Some(Operand::Mem { size, seg, base, index, scale, disp }) => Some(MemRef { size: *size, seg, base, index, scale: *scale, disp: *disp }),
        _ => None,
    }
}

/// What a memory operand addresses, as HLA64 writes it inside brackets; rip-relative ones by name.
fn address(mem: &MemRef, insn: &X86Insn, ctx: &dyn X86LiftContext, words: &mut Words) -> Option<String> {
    if !mem.seg.is_empty() {
        return None;
    }
    if mem.base == "rip" {
        let at = insn.mem?;
        let data = ctx.data(at);
        let target = ctx.target(at);
        words.push("address");
        if let Some(t) = target {
            return Some(format!("&{}", if t.kind == TargetKind::Label { t.name } else { hla_name(&t.name, words) }));
        }
        if let Some(DataAt::Symbol { name }) = data {
            return Some(format!("&{}", hla_name(&name, words)));
        }
        return Some(format!("&data_{}", js_hex(at as f64)));
    }
    if !mem.base.is_empty() && register_bits(mem.base) != 64 {
        return None;
    }
    if !mem.index.is_empty() && register_bits(mem.index) != 64 {
        return None;
    }
    let mut parts: Vec<String> = Vec::new();
    if !mem.base.is_empty() {
        parts.push(mem.base.to_string());
    }
    if !mem.index.is_empty() {
        parts.push(if mem.scale == 1 { mem.index.to_string() } else { format!("{} * {}", mem.index, mem.scale) });
    }
    let mut text = parts.join(" + ");
    if mem.disp != 0.0 {
        text = if !text.is_empty() { format!("{text} {} {}", if mem.disp < 0.0 { '-' } else { '+' }, num(mem.disp.abs())) } else { num(mem.disp) };
    }
    Some(if text.is_empty() { "0".into() } else { text })
}

/// A load or store's type prefix for the access size: '' when the register's width says it.
fn type_of(bits: u32, reg_bits: u32, signed: bool) -> String {
    if bits == reg_bits && !signed {
        return String::new();
    }
    format!("{}{}", if signed { 'i' } else { 'u' }, bits)
}

fn signed_op(cond: &str) -> Option<&'static str> {
    Some(match cond {
        "e" => "==",
        "ne" => "!=",
        "l" => "<",
        "le" => "<=",
        "g" => ">",
        "ge" => ">=",
        _ => return None,
    })
}

fn unsigned_op(cond: &str) -> Option<&'static str> {
    Some(match cond {
        "b" => "<u",
        "be" => "<=u",
        "a" => ">u",
        "ae" => ">=u",
        _ => return None,
    })
}

fn zero_test(cond: &str) -> Option<&'static str> {
    Some(match cond {
        "e" => "== 0",
        "ne" => "!= 0",
        "s" => "< 0",
        "ns" => ">= 0",
        _ => return None,
    })
}

/// The branch or call target by name.
fn target_text(insn: &X86Insn, ctx: &dyn X86LiftContext, words: &mut Words) -> Option<String> {
    let target = insn.target?;
    Some(match ctx.target(target) {
        None => num(target as f64),
        Some(t) if t.kind == TargetKind::Label => t.name,
        Some(t) => hla_name(&t.name, words),
    })
}

/// Mnemonics HLA64 would read as its own words, not as instructions.
fn is_keyword(m: &str) -> bool {
    matches!(m, "push" | "pop" | "loop" | "return" | "if" | "goto" | "let" | "local" | "data" | "fn" | "while" | "for" | "do" | "switch" | "break" | "continue")
}

/// The instruction as printed, with branch targets by name — in `asm "…"` when HLA64 would take it for a word of its own.
pub fn raw_x86(insn: &X86Insn, ctx: &dyn X86LiftContext) -> String {
    let mut ops = insn.ops.clone();
    if let Some(target) = insn.target {
        if let Some(t) = ctx.target(target) {
            let name = if t.kind == TargetKind::Label { t.name } else { hla_name(&t.name, &mut Vec::new()) };
            ops = ops.replacen(&format!("0x{}", js_hex(target as f64)), &name, 1);
        }
    }
    let text = [insn.prefix.as_str(), insn.m.as_str(), ops.as_str()].iter().filter(|s| !s.is_empty()).copied().collect::<Vec<_>>().join(" ");
    if is_keyword(&insn.m) || is_keyword(insn.prefix.split(' ').next().unwrap_or("")) {
        return format!("asm {}", quoted(&text, usize::MAX));
    }
    text
}

/// A locked read-modify-write as the atomic it is — every locked instruction
/// on x86 is sequentially consistent: `lock add [mem], r` is atomic_add,
/// `lock xadd` the same returning the old value, `lock cmpxchg` a compare and
/// swap, `xchg` with memory (locked without the prefix) a swap.
fn atomic(insn: &X86Insn, locked: bool, ctx: &dyn X86LiftContext, words: &mut Words) -> Option<String> {
    let ops = operands_of(&insn.ops);
    let d = mem_of(ops.first())?;
    let s = ops.get(1);
    if d.size == 0 || d.size > 64 {
        return None;
    }
    let at = address(&d, insn, ctx, words)?;
    let cell = format!("u{}[{}]", d.size, at);
    let reg: Option<String> = match s {
        Some(Operand::Reg { r, bits }) => {
            if *bits == d.size && *bits >= 32 {
                Some(r.clone())
            } else if *bits == d.size {
                name32(r)
            } else {
                None
            }
        }
        _ => None,
    };
    let m = insn.m.as_str();
    if m == "xchg" {
        if let Some(reg) = &reg {
            words.push("atomic");
            return Some(format!("{reg} = atomic_swap({cell}, {reg}, seq_cst)"));
        }
    }
    if !locked {
        return None;
    }
    if m == "cmpxchg" {
        if let Some(reg) = &reg {
            words.push("cas");
            let acc = if d.size == 64 { "rax" } else { "eax" };
            if d.size < 32 {
                return None;
            }
            return Some(format!("{acc} = cas({cell}, {acc}, {reg}, seq_cst)"));
        }
    }
    if m == "xadd" {
        if let Some(reg) = &reg {
            words.push("atomic");
            return Some(format!("{reg} = atomic_add({cell}, {reg}, seq_cst)"));
        }
    }
    let operand = match m {
        "inc" => Some("1".to_string()),
        "dec" => Some("-1".to_string()),
        _ => reg.or_else(|| if let Some(Operand::Imm { v }) = s { Some(num(*v)) } else { None }),
    };
    let name = match m {
        "add" | "inc" | "dec" => "atomic_add",
        "or" => "atomic_or",
        "xor" => "atomic_eor",
        _ => return None,
    };
    let operand = operand?;
    words.push("atomic");
    Some(format!("{name}({cell}, {operand}, seq_cst)"))
}

/// `^[abcd]h$`
fn is_high_byte(r: &str) -> bool {
    let b = r.as_bytes();
    b.len() == 2 && b"abcd".contains(&b[0]) && b[1] == b'h'
}

fn lift(insn: &X86Insn, ctx: &dyn X86LiftContext, words: &mut Words) -> Option<String> {
    if insn.prefix == "lock" || insn.m == "xchg" {
        return atomic(insn, insn.prefix == "lock", ctx, words);
    }
    if !insn.prefix.is_empty() || insn.f & f::UNKNOWN != 0 || insn.m.starts_with('.') {
        return None;
    }
    let ops = operands_of(&insn.ops);
    let (d, a, b) = (ops.first(), ops.get(1), ops.get(2));
    let m = insn.m.as_str();
    // A memory operand in an arithmetic expression, typed by its size when that is not the register's.
    let source = |op: Option<&Operand>, reg_bits: u32, words: &mut Words| -> Option<String> {
        if let Some(mem) = mem_of(op) {
            if mem.size != reg_bits {
                return None;
            }
            let at = address(&mem, insn, ctx, words)?;
            words.push("memory");
            return Some(format!("[{at}]"));
        }
        if let Some(Operand::Reg { bits, .. }) = op {
            if *bits != reg_bits {
                return None;
            }
        }
        value(op)
    };
    match m {
        "mov" | "movabs" => {
            if let Some((dr, dbits)) = gpr(d) {
                if let Some(mem) = mem_of(a) {
                    if mem.size != dbits {
                        return None;
                    }
                    let at = address(&mem, insn, ctx, words)?;
                    words.push("memory");
                    return Some(format!("{dr} = [{at}]"));
                }
                if let Some(Operand::Reg { bits, .. }) = a {
                    if *bits != dbits {
                        return None;
                    }
                }
                let v = value(a)?;
                words.push("assign");
                return Some(format!("{dr} = {v}"));
            }
            if let Some(dm) = mem_of(d) {
                let at = address(&dm, insn, ctx, words);
                let at = match at {
                    Some(at) if dm.size != 0 && dm.size <= 64 => at,
                    _ => return None,
                };
                let v: Option<String> = match a {
                    Some(Operand::Reg { r, bits }) => {
                        // A narrow store names the register by its 32-bit view: `mov byte ptr [rax], cl` is `u8[rax] = ecx`.
                        let v = if *bits == dm.size && *bits >= 32 {
                            Some(r.clone())
                        } else if *bits == dm.size {
                            name32(r)
                        } else {
                            None
                        };
                        if is_high_byte(r) {
                            return None;
                        }
                        v
                    }
                    _ => value(a),
                };
                let v = v?;
                let ty = if dm.size == 64 || (dm.size == 32 && matches!(a, Some(Operand::Reg { .. }))) { String::new() } else { format!("u{}", dm.size) };
                words.push(if ty.is_empty() { "memory" } else { "typed-memory" });
                return Some(format!("{ty}[{at}] = {v}"));
            }
            None
        }
        "movzx" | "movsx" | "movsxd" => {
            let (dr, dbits) = gpr(d)?;
            let signed = m != "movzx";
            if let Some(mem) = mem_of(a) {
                let at = address(&mem, insn, ctx, words);
                let at = match at {
                    Some(at) if mem.size != 0 => at,
                    _ => return None,
                };
                words.push("typed-memory");
                let mut ty = type_of(mem.size, dbits, signed);
                if ty.is_empty() {
                    ty = format!("{}{}", if signed { 'i' } else { 'u' }, mem.size);
                }
                return Some(format!("{dr} = {ty}[{at}]"));
            }
            if let Some(Operand::Reg { r, bits }) = a {
                if is_high_byte(r) {
                    return None;
                }
                let wide = if *bits == 32 { Some(r.clone()) } else { name32(r) };
                let wide = wide?;
                words.push("extend");
                return Some(format!("{dr} = {}{}({wide})", if signed { "sext" } else { "zext" }, bits));
            }
            None
        }
        "lea" => {
            let (dr, dbits) = gpr(d)?;
            let am = mem_of(a)?;
            if !am.seg.is_empty() {
                return None;
            }
            if am.base == "rip" {
                let at = insn.mem?;
                if let Some(DataAt::String { text, objc }) = ctx.data(at) {
                    words.push(if objc { "nsstring" } else { "string" });
                    return Some(format!("{dr} = {}{}", if objc { "@" } else { "" }, quoted(&text, 80)));
                }
                let at = address(&am, insn, ctx, words)?;
                return Some(format!("{dr} = {at}"));
            }
            if dbits != 64 {
                return None;
            }
            let at = address(&am, insn, ctx, words)?;
            words.push("arith");
            Some(format!("{dr} = {at}"))
        }
        "add" | "sub" | "and" | "or" | "xor" | "imul" => {
            let (dr, dbits) = gpr(d)?;
            let op = match m {
                "add" => "+",
                "sub" => "-",
                "and" => "&",
                "or" => "|",
                "xor" => "^",
                _ => "*",
            };
            if m == "xor" {
                if let Some(Operand::Reg { r, .. }) = a {
                    if r == dr {
                        words.push("assign");
                        return Some(format!("{dr} = 0"));
                    }
                }
            }
            if m == "imul" && b.is_some() {
                let left = source(a, dbits, words);
                let right = value(b);
                let (left, right) = (left?, right?);
                words.push("arith");
                return Some(format!("{dr} = {left} * {right}"));
            }
            if m == "imul" && a.is_none() {
                return None;
            }
            let right = source(a, dbits, words)?;
            words.push("arith");
            words.push("compound");
            Some(format!("{dr} {op}= {right}"))
        }
        "shl" | "shr" | "sar" => {
            let (dr, dbits) = gpr(d)?;
            let op = match m {
                "shl" => "<<",
                "shr" => ">>>",
                _ => ">>",
            };
            let count = match a {
                None => Some("1".to_string()),
                Some(Operand::Reg { r, .. }) if r == "cl" => Some(if dbits == 64 { "rcx" } else { "ecx" }.to_string()),
                _ => value(a),
            };
            let count = count?;
            words.push("shift");
            words.push("compound");
            Some(format!("{dr} {op}= {count}"))
        }
        "ror" | "rol" => {
            let (dr, dbits) = gpr(d)?;
            let Some(Operand::Imm { v }) = a else { return None };
            words.push("ror");
            let amount = if m == "ror" { *v } else { dbits as f64 - (v % dbits as f64) };
            Some(format!("{dr} = ror({dr}, {})", js_number(amount)))
        }
        "neg" | "not" => {
            let (dr, _) = gpr(d)?;
            words.push("arith");
            Some(format!("{dr} = {}{dr}", if m == "neg" { '-' } else { '~' }))
        }
        "inc" | "dec" => {
            let (dr, _) = gpr(d)?;
            words.push("compound");
            Some(format!("{dr} {}= 1", if m == "inc" { '+' } else { '-' }))
        }
        "push" => {
            // A register, or an immediate sign-extended to 64 bits as the push does.
            let pushed = match d {
                Some(Operand::Reg { r, bits: 64 }) => r.clone(),
                Some(Operand::Imm { v }) => num(*v),
                _ => return None,
            };
            words.push("compound");
            words.push("memory");
            Some(format!("rsp -= 8; [rsp] = {pushed}"))
        }
        "pop" => {
            let Some(Operand::Reg { r, bits: 64 }) = d else { return None };
            words.push("compound");
            words.push("memory");
            Some(format!("{r} = [rsp]; rsp += 8"))
        }
        "call" => {
            if insn.target.is_some() {
                words.push("call");
                return Some(format!("{}()", target_text(insn, ctx, words).unwrap_or_default()));
            }
            if let Some((dr, 64)) = gpr(d) {
                words.push("call");
                return Some(format!("{dr}()"));
            }
            let imported = insn.mem.and_then(|at| ctx.import_at(at));
            if let (Some(imported), Some(dm)) = (imported, mem_of(d)) {
                if dm.base == "rip" {
                    words.push("call");
                    return Some(format!("{}()", hla_name(&imported, words)));
                }
            }
            None
        }
        "jmp" => {
            if let Some(target) = insn.target {
                if let Some(t) = ctx.target(target) {
                    if t.kind != TargetKind::Label && target != ctx.function_start(insn.addr) {
                        words.push("tail-call");
                        return Some(format!("return {}()", hla_name(&t.name, words)));
                    }
                }
                words.push("goto");
                return Some(format!("goto {}", target_text(insn, ctx, words).unwrap_or_default()));
            }
            let imported = insn.mem.and_then(|at| ctx.import_at(at));
            if let (Some(imported), Some(dm)) = (imported, mem_of(d)) {
                if dm.base == "rip" {
                    words.push("tail-call");
                    return Some(format!("return {}()", hla_name(&imported, words)));
                }
            }
            if let Some((dr, 64)) = gpr(d) {
                words.push("jump-table");
                return Some(format!("goto [{dr}]"));
            }
            None
        }
        "ret" => {
            if !ops.is_empty() {
                return None;
            }
            words.push("return");
            Some("return".into())
        }
        // Scalar double precision: HLA64's xmm registers hold doubles.
        "addsd" | "subsd" | "mulsd" | "divsd" => {
            let dr = xmm(d)?;
            let right = if let Some(am) = mem_of(a) {
                if am.size == 64 {
                    // The TypeScript reads the address twice (once to check, once to print): the words come twice too, then are made unique.
                    let check = address(&am, insn, ctx, words);
                    check.map(|_| format!("f64[{}]", address(&am, insn, ctx, words).unwrap_or_default()))
                } else {
                    None
                }
            } else {
                xmm(a).map(str::to_string)
            };
            let right = right?;
            words.push("float");
            words.push("compound");
            let op = match m {
                "addsd" => "+",
                "subsd" => "-",
                "mulsd" => "*",
                _ => "/",
            };
            Some(format!("{dr} {op}= {right}"))
        }
        "sqrtsd" => {
            let (dr, ar) = (xmm(d)?, xmm(a)?);
            words.push("float");
            Some(format!("{dr} = sqrt({ar})"))
        }
        "movsd" => {
            if let (Some(dr), Some(am)) = (xmm(d), mem_of(a)) {
                if am.size == 64 {
                    let at = address(&am, insn, ctx, words)?;
                    words.push("float");
                    words.push("typed-memory");
                    return Some(format!("{dr} = f64[{at}]"));
                }
            }
            if let (Some(dm), Some(ar)) = (mem_of(d), xmm(a)) {
                if dm.size == 64 {
                    let at = address(&dm, insn, ctx, words)?;
                    words.push("float");
                    words.push("typed-memory");
                    return Some(format!("f64[{at}] = {ar}"));
                }
            }
            None
        }
        "movaps" | "movapd" => {
            let (dr, ar) = (xmm(d)?, xmm(a)?);
            words.push("assign");
            Some(format!("{dr} = {ar}"))
        }
        "xorps" | "xorpd" => {
            let (dr, ar) = (xmm(d)?, xmm(a)?);
            if ar != dr {
                return None;
            }
            words.push("float");
            Some(format!("{dr} = 0.0"))
        }
        "cvtsi2sd" => {
            let dr = xmm(d)?;
            let (ar, _) = gpr(a)?;
            words.push("float");
            Some(format!("{dr} = float({ar})"))
        }
        "cvttsd2si" => {
            let (dr, _) = gpr(d)?;
            let ar = xmm(a)?;
            words.push("float");
            Some(format!("{dr} = int({ar})"))
        }
        _ => None,
    }
}

/// One instruction as an HLA64 line; the instruction itself when HLA64 has no word that means the same.
pub fn lift_x86(insn: &X86Insn, ctx: &dyn X86LiftContext) -> HlaLine {
    let mut words = Vec::new();
    match lift(insn, ctx, &mut words) {
        Some(text) => HlaLine { text, words: unique(words), comment: None },
        None => HlaLine { text: raw_x86(insn, ctx), words: vec!["instruction"], comment: None },
    }
}

/* ------------------------------------------------------------------ *
 * A compare and the jump or conditional move that reads its flags
 * ------------------------------------------------------------------ */

pub fn is_x86_setter(m: &str) -> bool {
    matches!(m, "cmp" | "test" | "add" | "sub" | "and" | "or" | "xor" | "inc" | "dec" | "neg" | "ucomisd" | "comisd" | "lock")
}

/// What a lone `lock` line makes atomic.
fn is_lockable(m: &str) -> bool {
    matches!(m, "add" | "or" | "xor" | "inc" | "dec" | "xadd" | "cmpxchg")
}

fn is_cc(c: &str) -> bool {
    matches!(c, "o" | "no" | "b" | "ae" | "e" | "ne" | "be" | "a" | "s" | "ns" | "p" | "np" | "l" | "ge" | "le" | "g")
}

/// `^j(cc)$`: the condition of a conditional jump.
fn jcc(m: &str) -> Option<&str> {
    m.strip_prefix('j').filter(|c| is_cc(c))
}

/// `^cmov(cc)$`: the condition of a conditional move.
fn cmov(m: &str) -> Option<&str> {
    m.strip_prefix("cmov").filter(|c| is_cc(c))
}

/// Whether an instruction reads the flags a setter left: jcc or cmovcc.
pub fn is_x86_consumer(m: &str) -> bool {
    jcc(m).is_some() || cmov(m).is_some() || is_lockable(m)
}

struct Relation {
    pre: Option<String>,
    expr: String,
}

/// What the flags of `setter` say under `cond`, as an expression; and a statement before it when the setter has a result.
fn relation(setter: &X86Insn, cond: &str, ctx: &dyn X86LiftContext, words: &mut Words) -> Option<Relation> {
    if !setter.prefix.is_empty() {
        return None;
    }
    let ops = operands_of(&setter.ops);
    let (a, b) = (ops.first(), ops.get(1));
    let m = setter.m.as_str();
    if m == "ucomisd" || m == "comisd" {
        // Unordered compares set ZF, PF and CF together: only `above` and `above or equal` exclude NaN.
        let (ar, br) = (xmm(a)?, xmm(b)?);
        if cond != "a" && cond != "ae" {
            return None;
        }
        words.push("float");
        return Some(Relation { pre: None, expr: format!("{ar} {} {br}", if cond == "a" { ">" } else { ">=" }) });
    }
    let (ar, abits) = gpr(a)?;
    if m == "cmp" {
        let right = match b {
            Some(Operand::Reg { r, bits }) => {
                if *bits == abits {
                    Some(r.clone())
                } else {
                    None
                }
            }
            _ => value(b),
        };
        let right = right?;
        if let Some(op) = signed_op(cond) {
            return Some(Relation { pre: None, expr: format!("{ar} {op} {right}") });
        }
        if let Some(op) = unsigned_op(cond) {
            words.push("unsigned-compare");
            return Some(Relation { pre: None, expr: format!("{ar} {op} {right}") });
        }
        return None;
    }
    if m == "test" {
        let same = matches!(b, Some(Operand::Reg { r, .. }) if r == ar);
        let anded = if same {
            Some(ar.to_string())
        } else {
            match b {
                Some(Operand::Reg { r, bits }) if *bits == abits => Some(format!("{ar} & {r}")),
                Some(Operand::Imm { v }) => Some(format!("{ar} & {}", num(*v))),
                _ => None,
            }
        };
        let anded = anded?;
        if !same {
            words.push("arith");
        }
        if let Some(test) = zero_test(cond) {
            return Some(Relation { pre: None, expr: format!("{anded} {test}") });
        }
        // test clears OF: the signed conditions compare the result with zero.
        if let Some(op) = signed_op(cond) {
            return Some(Relation { pre: None, expr: format!("{anded} {op} 0") });
        }
        return None;
    }
    // An operation with a result: the line does it, then tests the result against zero.
    let test = zero_test(cond)?;
    let pre = lift(setter, ctx, words)?;
    if pre.contains(';') {
        return None;
    }
    Some(Relation { pre: Some(pre), expr: format!("{ar} {test}") })
}

/// A setter and the consumer after it as one line, or None when they do not pair; or a `lock` and the instruction it makes atomic.
pub fn fuse_x86(first: &X86Insn, second: &X86Insn, ctx: &dyn X86LiftContext) -> Option<HlaLine> {
    let mut words = Vec::new();
    if first.m == "lock" && first.ops.is_empty() && second.prefix.is_empty() {
        let text = atomic(second, true, ctx, &mut words)?;
        return Some(HlaLine { text, words: unique(words), comment: None });
    }
    if !is_x86_setter(&first.m) || !second.prefix.is_empty() {
        return None;
    }
    if let Some(cond) = jcc(&second.m) {
        let rel = relation(first, cond, ctx, &mut words)?;
        let target = target_text(second, ctx, &mut words)?;
        words.push("if-goto");
        let tail = format!("if {} {{ goto {target} }}", rel.expr);
        let text = match rel.pre {
            Some(pre) => format!("{pre}; {tail}"),
            None => tail,
        };
        return Some(HlaLine { text, words: unique(words), comment: None });
    }
    if let Some(cond) = cmov(&second.m) {
        let ops = operands_of(&second.ops);
        let (dr, dbits) = gpr(ops.first())?;
        let (sr, sbits) = gpr(ops.get(1))?;
        if sbits != dbits {
            return None;
        }
        let rel = relation(first, cond, ctx, &mut words)?;
        words.push("ternary");
        let tail = format!("{dr} = {} ? {sr} : {dr}", rel.expr);
        let text = match rel.pre {
            Some(pre) => format!("{pre}; {tail}"),
            None => tail,
        };
        return Some(HlaLine { text, words: unique(words), comment: None });
    }
    None
}
