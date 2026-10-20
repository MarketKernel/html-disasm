//! The HLA64 view of WebAssembly code.
//!
//! HLA64 is an assembler with sugar for WebAssembly as for ARM64: its programs
//! are instructions, with words for what is obvious. On a stack machine the
//! obvious is the expression: `local.get 0, i32.const 1, i32.add, local.set 2`
//! is `l2 = l0 + 1`. The analysis (program.rs) marks the runs of instructions
//! that make one statement; lift_group() turns a run back into that statement,
//! evaluating the stack with expressions instead of values. Every line stands
//! for the instructions at its addresses and means exactly what they do:
//! operands are written in the order the instructions compute them, a select
//! becomes `c ? a : b` only when nothing in it has an effect, and whatever has
//! no word stays an instruction — as HLA64 accepts.
//!
//! `block`, `loop` and their `end` stay instructions (HLA64's own `loop { }`
//! repeats, a WebAssembly loop does not); an `if` whose condition is in the
//! line reads `if c {`, `} else {`, `}`. Branches name their target by its
//! address, as labels do on ARM64: `if l3 != l1 { goto L1f7 }`.
//!
//! Names in a line — functions, labels, strings, locals — are wrapped in
//! invisible marks (see mark()) so the page can make each one a link. A port of
//! src/core/wasm/hla.ts; how functions are named is the page's to say (`WasmNaming`).

use super::decode::{decode_at, operands_text, WasmInsn};
use super::module::{format_context, func_type_of, ExternKind, WasmModule};
use super::opcodes::{imm, w};
use super::program::{effect, WasmProgram};
use super::reader::{decimal_float, f32_from_bits, f64_from_bits, utf8, Num};
use crate::disassembly::is_text;
use crate::lift::{quoted, unique, HlaLine, Words};
use crate::refs::FxHashMap;
use crate::text::js_hex;

/// Bits of WasmProgram::flags beyond the shared ones.
pub mod wf {
    /// An `if` written `if c {`: its condition is in its line.
    pub const SUGAR_IF: u8 = 64;
    /// The `else` or `end` of such an if: `} else {`, `}`.
    pub const IF_END: u8 = 128;
}

/// How the view names functions: the page says (it follows the settings).
pub trait WasmNaming {
    fn func(&self, index: u64) -> String;
}

/// What lifting needs beyond the program and the module, worked out once.
pub struct WasmLines {
    /// The bodies with instructions, in order: the listing's functions.
    listed: Vec<u32>,
    /// Function index → its address (its first instruction, or its import entry); -1 when none.
    fn_addr: Vec<i64>,
    string_at: FxHashMap<i64, usize>,
    length_at: FxHashMap<i64, f64>,
}

impl WasmLines {
    pub fn new(p: &WasmProgram, module: &WasmModule) -> WasmLines {
        let count = module.imported_funcs as usize + module.bodies.len();
        let mut fn_addr = vec![-1i64; count];
        for imp in &module.imports {
            if imp.kind == ExternKind::Func {
                if let Some(slot) = fn_addr.get_mut(imp.index as usize) {
                    *slot = imp.offset as i64;
                }
            }
        }
        for (b, body) in module.bodies.iter().enumerate() {
            fn_addr[module.imported_funcs as usize + b] = body.code as i64;
        }
        let listed = p.bodies.iter().enumerate().filter(|(_, f)| f.count > 0).map(|(b, _)| b as u32).collect();
        let string_at = p.strings.iter().enumerate().map(|(k, s)| (s.addr, k)).collect();
        let length_at = p.length_addr.iter().zip(&p.length_value).map(|(&a, &v)| (a as i64, v)).collect();
        WasmLines { listed, fn_addr, string_at, length_at }
    }
}

impl WasmLines {
    /// The body of the listed function holding an instruction, or None.
    pub fn body_of(&self, p: &WasmProgram, index: usize) -> Option<usize> {
        let k = self.listed.partition_point(|&b| p.bodies[b as usize].first as usize <= index).checked_sub(1)?;
        let b = self.listed[k] as usize;
        let f = &p.bodies[b];
        (index < (f.first + f.count) as usize).then_some(b)
    }
}

/* ------------------------------------------------------------------ *
 * Marks
 * ------------------------------------------------------------------ */

fn mark(kind: char, value: i64, text: &str) -> String {
    format!("\u{1}{kind}{value}\u{2}{text}\u{3}")
}

/* ------------------------------------------------------------------ *
 * Names
 * ------------------------------------------------------------------ */

fn is_identifier(name: &str) -> bool {
    let b = name.as_bytes();
    match b.first() {
        Some(c) if c.is_ascii_alphabetic() || *c == b'_' => b[1..].iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_'),
        _ => false,
    }
}

fn quoted_name(name: &str, words: &mut Words) -> String {
    if is_identifier(name) {
        return name.to_string();
    }
    words.push("quoted-name");
    format!("`{name}`")
}

/// A number as HLA64 writes it: small ones in decimal, the rest in hex.
fn num(v: Num) -> String {
    let v = v.value();
    if v > -10 && v < 10 {
        v.to_string()
    } else if v < 0 {
        format!("-0x{:x}", v.unsigned_abs())
    } else {
        format!("0x{v:x}")
    }
}

fn float_literal(value: f64, single: bool) -> String {
    if value.is_nan() {
        return "nan".into();
    }
    if value.is_infinite() {
        return if value > 0.0 { "inf".into() } else { "-inf".into() };
    }
    let text = decimal_float(value, single);
    if text.contains(['.', 'e']) || text.contains("inf") {
        text
    } else {
        format!("{text}.0")
    }
}

/* ------------------------------------------------------------------ *
 * Expressions
 * ------------------------------------------------------------------ */

/// A value on the stack, as HLA64 writes it.
#[derive(Clone)]
struct Expr {
    text: String,
    /// Go's levels: 6 an operand, 5 * / % << >> >>> &, 4 + - | ^, 3 comparisons, 0 c ? a : b and assignments.
    prec: u8,
    /// Computing it has no effect (no call, store, assignment): it may move into a ?:.
    pure: bool,
    /// For x op= y: the operator and operands of a binary expression.
    op: Option<&'static str>,
    left: Option<String>,
    right: Option<String>,
}

fn atom(text: String, pure: bool) -> Expr {
    Expr { text, prec: 6, pure, op: None, left: None, right: None }
}

fn wrap(e: &Expr, min: u8) -> String {
    if e.prec >= min {
        e.text.clone()
    } else {
        format!("({})", e.text)
    }
}

/// A shift inside another operation gets parentheses, as the ARM64 view writes them: `x + (y << 2)`.
fn operand(e: &Expr, min: u8) -> String {
    if matches!(e.op, Some("<<" | ">>" | ">>>")) && e.prec == 5 {
        format!("({})", e.text)
    } else {
        wrap(e, min)
    }
}

fn binary(left: &Expr, op: &'static str, prec: u8, right: &Expr) -> Expr {
    Expr {
        text: format!("{} {op} {}", operand(left, prec), operand(right, prec + 1)),
        prec,
        pure: left.pure && right.pure,
        op: Some(op),
        left: Some(left.text.clone()),
        right: Some(right.text.clone()),
    }
}

fn call(name: &str, args: &[Expr], pure: bool) -> Expr {
    let list: Vec<&str> = args.iter().map(|a| a.text.as_str()).collect();
    atom(format!("{name}({})", list.join(", ")), pure && args.iter().all(|a| a.pure))
}

/// i32 and i64 operations written with an operator: the operator, its level, the word (arith by default).
fn int_binary(name: &str) -> Option<(&'static str, u8, &'static str)> {
    Some(match name {
        "add" => ("+", 4, "arith"),
        "sub" => ("-", 4, "arith"),
        "mul" => ("*", 5, "arith"),
        "div_s" => ("/", 5, "arith"),
        "rem_s" => ("%", 5, "arith"),
        "and" => ("&", 5, "arith"),
        "or" => ("|", 4, "arith"),
        "xor" => ("^", 4, "arith"),
        "shl" => ("<<", 5, "shift"),
        "shr_s" => (">>", 5, "shift"),
        "shr_u" => (">>>", 5, "shift"),
        "eq" => ("==", 3, "condition-value"),
        "ne" => ("!=", 3, "condition-value"),
        "lt_s" => ("<", 3, "condition-value"),
        "gt_s" => (">", 3, "condition-value"),
        "le_s" => ("<=", 3, "condition-value"),
        "ge_s" => (">=", 3, "condition-value"),
        "lt_u" => ("<u", 3, "unsigned-compare"),
        "gt_u" => (">u", 3, "unsigned-compare"),
        "le_u" => ("<=u", 3, "unsigned-compare"),
        "ge_u" => (">=u", 3, "unsigned-compare"),
        _ => return None,
    })
}

fn float_binary(name: &str) -> Option<(&'static str, u8)> {
    Some(match name {
        "add" => ("+", 4),
        "sub" => ("-", 4),
        "mul" => ("*", 5),
        "div" => ("/", 5),
        "eq" => ("==", 3),
        "ne" => ("!=", 3),
        "lt" => ("<", 3),
        "gt" => (">", 3),
        "le" => ("<=", 3),
        "ge" => (">=", 3),
        _ => return None,
    })
}

/// Instructions written as a function of their operands, and the word that explains the function.
fn function_of(m: &str) -> Option<(&'static str, &'static str)> {
    Some(match m {
        "i32.div_u" | "i64.div_u" => ("udiv", "udiv"),
        "i32.rem_u" | "i64.rem_u" => ("urem", "udiv"),
        "i32.rotl" | "i64.rotl" => ("rotl", "ror"),
        "i32.rotr" | "i64.rotr" => ("ror", "ror"),
        "i32.clz" | "i64.clz" => ("clz", "builtin"),
        "i32.ctz" | "i64.ctz" => ("ctz", "bit-builtins"),
        "i32.popcnt" | "i64.popcnt" => ("popcount", "bit-builtins"),
        "i32.extend8_s" | "i64.extend8_s" => ("sext8", "extend"),
        "i32.extend16_s" | "i64.extend16_s" => ("sext16", "extend"),
        "i64.extend32_s" => ("sext32", "extend"),
        "i64.extend_i32_s" => ("i64", "wasm-convert"),
        "i64.extend_i32_u" => ("u64", "wasm-convert"),
        "i32.wrap_i64" => ("i32", "wasm-convert"),
        "f32.abs" | "f64.abs" => ("fabs", "float"),
        "f32.sqrt" | "f64.sqrt" => ("sqrt", "float"),
        "f32.min" | "f64.min" => ("fmin", "float-extra"),
        "f32.max" | "f64.max" => ("fmax", "float-extra"),
        "f32.ceil" | "f64.ceil" => ("ceil", "wasm-round"),
        "f32.floor" | "f64.floor" => ("floor", "wasm-round"),
        "f32.trunc" | "f64.trunc" => ("trunc", "wasm-round"),
        "f32.nearest" | "f64.nearest" => ("nearest", "wasm-round"),
        "f32.copysign" | "f64.copysign" => ("copysign", "wasm-round"),
        "f32.demote_f64" => ("f32", "wasm-convert"),
        "f64.promote_f32" => ("f64", "wasm-convert"),
        "i32.reinterpret_f32" | "i64.reinterpret_f64" | "f32.reinterpret_i32" | "f64.reinterpret_i64" => ("bitcast", "float-extra"),
        _ => return None,
    })
}

/// Integer ↔ float conversions: i32(x) truncates (and traps out of range), i32_sat(x) saturates, f64u(x) reads x as unsigned.
fn conversion(m: &str) -> Option<String> {
    // (i32|i64).trunc_(sat_)?f(32|64)_([su])
    if let Some((to, rest)) = m.split_once(".trunc_") {
        if to == "i32" || to == "i64" {
            let (sat, rest) = match rest.strip_prefix("sat_") {
                Some(r) => (true, r),
                None => (false, rest),
            };
            if let Some(sign) = rest.strip_prefix("f32_").or_else(|| rest.strip_prefix("f64_")) {
                if sign == "s" || sign == "u" {
                    return Some(format!("{}{}{}", if sign == "u" { "u" } else { "i" }, &to[1..], if sat { "_sat" } else { "" }));
                }
            }
        }
    }
    // (f32|f64).convert_i(32|64)_([su])
    if let Some((to, rest)) = m.split_once(".convert_i") {
        if to == "f32" || to == "f64" {
            if let Some(sign) = rest.strip_prefix("32_").or_else(|| rest.strip_prefix("64_")) {
                if sign == "s" || sign == "u" {
                    return Some(format!("{to}{}", if sign == "u" { "u" } else { "" }));
                }
            }
        }
    }
    None
}

/// The access type of a load or store: i32.load8_u reads u8[…], i64.store32 writes u32[…].
fn access_type(m: &str) -> Option<String> {
    let (ty, rest) = m.split_once('.')?;
    if !matches!(ty, "i32" | "i64" | "f32" | "f64") {
        return None;
    }
    let rest = rest.strip_prefix("load").or_else(|| rest.strip_prefix("store"))?;
    let (width, rest) = width_of(rest);
    let sign = match rest {
        "" => None,
        "_s" => Some('i'),
        "_u" => Some('u'),
        _ => return None,
    };
    Some(match width {
        None => ty.to_string(),
        Some(w) => format!("{}{w}", if sign == Some('i') { 'i' } else { 'u' }),
    })
}

/// A leading 8, 16 or 32, and what follows it.
fn width_of(s: &str) -> (Option<&str>, &str) {
    for w in ["8", "16", "32"] {
        if let Some(rest) = s.strip_prefix(w) {
            return (Some(w), rest);
        }
    }
    (None, s)
}

/// `^(i32|i64)\.atomic\.(load|store|rmw)(8|16|32)?(?:\.([a-z]+?))?(_u)?$`: the type, the kind, the width, the operation.
fn atomic_of(m: &str) -> Option<(&str, &str, Option<&str>, Option<&str>)> {
    let ty = m.get(..3)?;
    if !(ty == "i32" || ty == "i64") {
        return None;
    }
    let rest = m[3..].strip_prefix(".atomic.")?;
    let kind = ["load", "store", "rmw"].into_iter().find(|k| rest.starts_with(k))?;
    let (width, rest) = width_of(&rest[kind.len()..]);
    let (op, rest) = match rest.strip_prefix('.') {
        Some(r) => {
            let n = r.bytes().take_while(u8::is_ascii_lowercase).count();
            if n == 0 {
                return None;
            }
            (Some(&r[..n]), &r[n..])
        }
        None => (None, rest),
    };
    if !(rest.is_empty() || rest == "_u") {
        return None;
    }
    Some((ty, kind, width, op))
}

fn atomic_rmw(op: &str) -> Option<&'static str> {
    Some(match op {
        "add" => "atomic_add",
        "sub" => "atomic_sub",
        "and" => "atomic_and",
        "or" => "atomic_or",
        "xor" => "atomic_xor",
        "xchg" => "atomic_swap",
        _ => return None,
    })
}

/* ------------------------------------------------------------------ *
 * Lifting
 * ------------------------------------------------------------------ */

struct State<'a> {
    p: &'a WasmProgram,
    module: &'a WasmModule,
    lines: &'a WasmLines,
    names: &'a dyn WasmNaming,
    /// The function the line is in: its index in the module, its last instruction.
    func: u64,
    last: usize,
    /// How many values the function returns.
    results: usize,
    stack: Vec<Expr>,
    out: Vec<String>,
    words: Words,
    comments: Vec<String>,
}

impl State<'_> {
    fn local(&mut self, index: u64) -> String {
        let name = self.module.names.locals.get(&self.func).and_then(|m| m.get(&index));
        if let Some(name) = name.filter(|n| is_identifier(n)) {
            return mark('v', index as i64, name);
        }
        self.words.push("wasm-local");
        mark('v', index as i64, &format!("l{index}"))
    }

    fn global(&mut self, index: u64) -> String {
        let name = self.module.names.globals.get(&index).or_else(|| self.module.exports.iter().find(|e| e.kind == ExternKind::Global && e.index == index).map(|e| &e.name));
        if let Some(name) = name.filter(|n| !n.is_empty()) {
            let text = quoted_name(name, &mut self.words);
            return mark('g', index as i64, &text);
        }
        self.words.push("wasm-local");
        mark('g', index as i64, &format!("g{index}"))
    }

    fn func_name(&mut self, index: u64) -> String {
        let addr = self.lines.fn_addr.get(index as usize).copied().unwrap_or(-1);
        let text = quoted_name(&self.names.func(index), &mut self.words);
        mark('f', addr, &text)
    }

    fn table_name(&self, index: u64) -> String {
        self.module
            .names
            .tables
            .get(&index)
            .cloned()
            .or_else(|| self.module.exports.iter().find(|e| e.kind == ExternKind::Table && e.index == index).map(|e| e.name.clone()))
            .unwrap_or_else(|| format!("table{index}"))
    }

    /// The label a branch goes to, or `return` for a branch to the end of its function.
    fn goto(&mut self, target: i64) -> String {
        if target == self.last as i64 {
            self.words.push("return");
            return "return".into();
        }
        self.words.push("goto");
        let addr = if target >= 0 { self.p.offsets.get(target as usize).map_or(0, |&a| a as i64) } else { 0 };
        format!("goto {}", mark('l', addr, &format!("L{}", js_hex(addr as f64))))
    }

    /// An i32.const or i64.const: the address of a string the code uses reads as the string.
    fn constant(&mut self, value: Num) -> Expr {
        if let Num::Number(v) = value {
            if v > 0 && self.p.data_refs.has(v) {
                if let Some(text) = self.string_at(v) {
                    self.words.push("string");
                    return atom(mark('s', v, &quoted(&text, 80)), true);
                }
            }
        }
        atom(num(value), true)
    }

    /// The text of a string at an address: one the analysis found, or one that starts there.
    fn string_at(&self, addr: i64) -> Option<String> {
        if let Some(&k) = self.lines.string_at.get(&addr) {
            return Some(self.p.strings[k].text.clone());
        }
        let segment = &self.p.segments[self.p.segment_at(addr)?];
        let at = segment.start as i64 + (addr - segment.addr);
        let stop = (at + 160).min(segment.start as i64 + (segment.end - segment.addr)).min(self.module.bytes.len() as i64);
        let bytes = if at < stop { &self.module.bytes[at as usize..stop as usize] } else { &[][..] };
        let known = self.lines.length_at.get(&addr).copied();
        let limit = known.map_or(bytes.len(), |k| (k as usize).min(bytes.len()));
        let mut end = 0;
        while end < limit && is_text(bytes[end]) {
            end += 1;
        }
        if let Some(k) = known {
            if end as f64 == k && k > 0.0 {
                return Some(utf8(&bytes[..end]));
            }
        }
        let terminated = bytes.get(end) == Some(&0);
        if end < if terminated { 2 } else { 6 } {
            return None;
        }
        Some(utf8(&bytes[..end]))
    }

    /// The instruction as a function of its operands: i32x4.add(a, b), memory.grow(n), i8x16.extract_lane_s<3>(v).
    fn folded(&mut self, insn: &WasmInsn, args: &[Expr]) -> Expr {
        self.words.push("wasm-folded");
        let ctx = format_context(self.module);
        let imm = operands_text(insn, Some(&ctx));
        let imm = imm.trim();
        let flags = insn.op.map_or(0, |o| o.flags);
        let m = insn.m;
        let pure = flags & (w::LOAD | w::STORE | w::CALL | w::TRAPS | w::ATOMIC) == 0 && !["grow", "size", "init", "drop", "copy", "fill"].iter().any(|k| m.contains(k));
        let name = if imm.is_empty() { m.to_string() } else { format!("{m}<{imm}>") };
        call(&name, args, pure)
    }

    /// Takes `count` values off the expression stack; None when the stack has fewer (the line cannot be written).
    fn take(&mut self, count: usize) -> Option<Vec<Expr>> {
        if count > self.stack.len() {
            return None;
        }
        Some(self.stack.split_off(self.stack.len() - count))
    }

    fn assign(&mut self, dest: &str, value: &Expr) -> String {
        self.words.push("assign");
        if let (Some(op), Some(left), Some(right)) = (value.op, &value.left, &value.right) {
            if left == dest && matches!(op, "+" | "-" | "*" | "/" | "%" | "&" | "|" | "^" | "<<" | ">>" | ">>>") {
                self.words.push("compound");
                return format!("{dest} {op}= {right}");
            }
        }
        format!("{dest} = {}", value.text)
    }

    fn branch_targets(&self, index: usize) -> &[i32] {
        let p = self.p;
        match p.target_index.binary_search(&(index as u32)) {
            Ok(k) => &p.target_values[p.target_starts[k] as usize..p.target_starts[k + 1] as usize],
            Err(_) => &[],
        }
    }

    /// One instruction applied to the expression stack. False when it has no form here.
    fn step(&mut self, index: usize, insn: &WasmInsn) -> bool {
        let m = insn.m;
        let Some(op) = insn.op else { return false };
        let flags = self.p.flags[index];

        // Structure and branches.
        if self.p.value_branches.binary_search(&(index as u32)).is_ok() {
            return false;
        }
        match m {
            "if" => {
                if flags & wf::SUGAR_IF == 0 {
                    return false;
                }
                let Some(cond) = self.take(1).and_then(|mut v| v.pop()) else { return false };
                self.words.push("if-else");
                self.out.push(format!("if {} {{", cond.text));
                return true;
            }
            "else" => {
                if flags & wf::IF_END == 0 {
                    return false;
                }
                self.words.push("if-else");
                self.out.push("} else {".into());
                return true;
            }
            "end" => {
                if index == self.last {
                    self.words.push("return");
                    let values = std::mem::take(&mut self.stack);
                    if values.len() != self.results || values.len() > 1 {
                        return false;
                    }
                    self.out.push(match values.first() {
                        Some(v) => format!("return {}", v.text),
                        None => "return".into(),
                    });
                    return true;
                }
                if flags & wf::IF_END == 0 {
                    return false;
                }
                self.out.push("}".into());
                return true;
            }
            "br" => {
                let Some(&target) = self.branch_targets(index).first() else { return false };
                let text = self.goto(target as i64);
                self.out.push(text);
                return true;
            }
            "br_if" => {
                let target = self.branch_targets(index).first().copied();
                let cond = self.take(1).and_then(|mut v| v.pop());
                let (Some(target), Some(cond)) = (target, cond) else { return false };
                self.words.push("if-goto");
                let goto = self.goto(target as i64);
                self.out.push(format!("if {} {{ {goto} }}", cond.text));
                return true;
            }
            "br_table" => {
                let value = self.take(1).and_then(|mut v| v.pop());
                let targets = self.branch_targets(index).to_vec();
                let Some(value) = value else { return false };
                if targets.is_empty() || targets.len() != insn.labels.len() || targets.iter().any(|&t| t < 0) {
                    return false;
                }
                self.words.push("switch");
                // Cases that go to the same place share a branch: case 0, 3..=5 { goto L… }.
                let mut by_target: Vec<(i32, Vec<usize>)> = Vec::new();
                for (k, &target) in targets[..targets.len() - 1].iter().enumerate() {
                    match by_target.iter_mut().find(|(t, _)| *t == target) {
                        Some((_, keys)) => keys.push(k),
                        None => by_target.push((target, vec![k])),
                    }
                }
                let fallback = targets[targets.len() - 1];
                let mut cases = Vec::new();
                for (target, keys) in &by_target {
                    if *target == fallback {
                        continue;
                    }
                    let mut ranges = Vec::new();
                    let mut k = 0;
                    while k < keys.len() {
                        let mut e = k;
                        while e + 1 < keys.len() && keys[e + 1] == keys[e] + 1 {
                            e += 1;
                        }
                        ranges.push(if e == k {
                            keys[k].to_string()
                        } else if e == k + 1 {
                            format!("{}, {}", keys[k], keys[e])
                        } else {
                            format!("{}..={}", keys[k], keys[e])
                        });
                        k = e + 1;
                    }
                    let goto = self.goto(*target as i64);
                    cases.push(format!("case {} {{ {goto} }}", ranges.join(", ")));
                }
                let goto = self.goto(fallback as i64);
                cases.push(format!("default {{ {goto} }}"));
                self.out.push(format!("switch {} {{ {} }}", value.text, cases.join(" ")));
                return true;
            }
            "return" => {
                let values = std::mem::take(&mut self.stack);
                if values.len() != self.results || values.len() > 1 {
                    return false;
                }
                self.words.push("return");
                self.out.push(match values.first() {
                    Some(v) => format!("return {}", v.text),
                    None => "return".into(),
                });
                return true;
            }
            _ => {}
        }
        if op.flags & (w::STRUCTURE | w::BRANCH) != 0 {
            return false;
        }

        let Some((pops, pushes)) = effect(insn, self.module) else { return false };
        if pushes > 1 {
            return false;
        }
        let Some(mut args) = self.take(pops as usize) else { return false };
        // Every case below reads only the operands the instruction's effect takes; a module that
        // says otherwise leaves the instructions as they are rather than stopping the core.
        let wants = match m {
            "select" => 3,
            "local.set" | "local.tee" | "global.set" | "drop" | "i32.eqz" | "i64.eqz" => 1,
            _ if op.imm == imm::MEMARG && insn.mem == 0 => {
                if m.contains("cmpxchg") {
                    3
                } else if op.flags & w::LOAD != 0 && !m.contains(".rmw") {
                    1
                } else {
                    2
                }
            }
            _ => 0,
        };
        if args.len() < wants {
            return false;
        }
        let pushes = pushes == 1;
        macro_rules! result {
            ($e:expr) => {{
                let e = $e;
                if pushes {
                    self.stack.push(e);
                } else {
                    self.out.push(e.text);
                }
                return true;
            }};
        }
        // `m.slice(0, m.indexOf('.'))` and `m.slice(m.indexOf('.') + 1)`, as the TypeScript cut them.
        let (prefix, name) = match m.find('.') {
            Some(i) => (&m[..i], &m[i + 1..]),
            None => (&m[..m.len().saturating_sub(1)], m),
        };

        match m {
            "nop" | "unreachable" => return false,
            "local.get" => {
                let text = self.local(insn.a);
                result!(atom(text, true))
            }
            "local.set" => {
                let dest = self.local(insn.a);
                let line = self.assign(&dest, &args[0]);
                self.out.push(line);
                return true;
            }
            "local.tee" => {
                self.words.push("wasm-tee");
                let dest = self.local(insn.a);
                result!(Expr { text: format!("({dest} = {})", args[0].text), prec: 6, pure: false, op: None, left: None, right: None })
            }
            "global.get" => {
                let text = self.global(insn.a);
                result!(atom(text, true))
            }
            "global.set" => {
                let dest = self.global(insn.a);
                let line = self.assign(&dest, &args[0]);
                self.out.push(line);
                return true;
            }
            "drop" => {
                let value = &args[0];
                if value.text.ends_with(')') && !value.pure {
                    self.out.push(value.text.clone());
                    return true;
                }
                self.words.push("wasm-drop");
                self.out.push(format!("_ = {}", value.text));
                return true;
            }
            "select" => {
                let (a, b, c) = (&args[0], &args[1], &args[2]);
                if a.pure && b.pure && c.pure {
                    self.words.push("ternary");
                    result!(Expr { text: format!("{} ? {} : {}", wrap(c, 1), wrap(a, 1), wrap(b, 1)), prec: 0, pure: true, op: None, left: None, right: None })
                }
                self.words.push("wasm-select");
                result!(call("select", &args, true))
            }
            "i32.const" | "i64.const" => result!(self.constant(insn.value)),
            "f32.const" => {
                self.words.push("float");
                result!(atom(float_literal(f32_from_bits(insn.bits as u32), true), true))
            }
            "f64.const" => {
                self.words.push("float");
                result!(atom(float_literal(f64_from_bits(insn.bits), false), true))
            }
            "call" => {
                self.words.push("call");
                let name = self.func_name(insn.a);
                result!(call(&name, &args, false))
            }
            "return_call" => {
                self.words.push("tail-call");
                let name = self.func_name(insn.a);
                self.out.push(format!("return {}", call(&name, &args, false).text));
                return true;
            }
            "call_indirect" | "return_call_indirect" => {
                self.words.push("wasm-call-table");
                let Some(index) = args.pop() else { return false };
                if let Some(sig) = self.module.types.get(insn.a as usize).and_then(|t| t.func.as_ref()) {
                    let params: Vec<String> = sig.params.iter().map(|t| t.to_string()).collect();
                    let results: Vec<String> = sig.results.iter().map(|t| t.to_string()).collect();
                    let to = if results.is_empty() { String::new() } else { format!(" -> {}", results.join(", ")) };
                    self.comments.push(format!("type {}: ({}){to}", insn.a, params.join(", ")));
                }
                let table = self.table_name(insn.b);
                let table = quoted_name(&table, &mut self.words);
                let list: Vec<&str> = args.iter().map(|a| a.text.as_str()).collect();
                let text = format!("{table}[{}]({})", index.text, list.join(", "));
                if m.starts_with("return") {
                    self.words.push("tail-call");
                    self.out.push(format!("return {text}"));
                    return true;
                }
                result!(atom(text, false))
            }
            "i32.eqz" | "i64.eqz" => {
                self.words.push("condition-value");
                result!(binary(&args[0], "==", 3, &atom("0".into(), true)))
            }
            _ => {}
        }

        // Memory: typed access, and atomics.
        if op.imm == imm::MEMARG && insn.mem == 0 {
            if let Some(ty) = access_type(m) {
                if matches!(prefix, "i32" | "i64" | "f32" | "f64") {
                    self.words.push("typed-memory");
                    let addr = address(&args[0], insn.value);
                    if op.flags & w::LOAD != 0 {
                        result!(atom(format!("{ty}[{addr}]"), true))
                    }
                    self.out.push(format!("{ty}[{addr}] = {}", args[1].text));
                    return true;
                }
            }
            if let Some((ty, kind, width, rmw)) = atomic_of(m) {
                let width = width.unwrap_or(if ty == "i64" { "64" } else { "32" });
                let cell = format!("u{width}[{}]", address(&args[0], insn.value));
                if kind == "load" {
                    self.words.push("atomic-load-store");
                    result!(atom(format!("atomic_load({cell})"), false))
                }
                if kind == "store" {
                    self.words.push("atomic-load-store");
                    self.out.push(format!("atomic_store({cell}, {})", args[1].text));
                    return true;
                }
                let rmw = rmw.unwrap_or("");
                if rmw == "cmpxchg" {
                    self.words.push("cas");
                    result!(atom(format!("cas({cell}, {}, {}, seq_cst)", args[1].text, args[2].text), false))
                }
                if let Some(f) = atomic_rmw(rmw) {
                    self.words.push("atomic");
                    result!(atom(format!("{f}({cell}, {}, seq_cst)", args[1].text), false))
                }
            }
        }

        // Numbers.
        if prefix == "i32" || prefix == "i64" {
            if let Some((sym, prec, word)) = int_binary(name) {
                if args.len() == 2 {
                    self.words.push(word);
                    result!(binary(&args[0], sym, prec, &args[1]))
                }
            }
        }
        if (prefix == "f32" || prefix == "f64") && args.len() == 2 {
            if let Some((sym, prec)) = float_binary(name) {
                self.words.push("float");
                result!(binary(&args[0], sym, prec, &args[1]))
            }
        }
        if (m == "f32.neg" || m == "f64.neg") && args.len() == 1 {
            self.words.push("float");
            result!(Expr { text: format!("-{}", wrap(&args[0], 6)), prec: 6, pure: args[0].pure, op: None, left: None, right: None })
        }
        if let Some((f, word)) = function_of(m) {
            self.words.push(word);
            result!(call(f, &args, true))
        }
        if let Some(converted) = conversion(m) {
            self.words.push("wasm-convert");
            result!(call(&converted, &args, op.flags & w::TRAPS == 0))
        }
        // Anything else with a fixed stack effect: the instruction as a function of its operands.
        result!(self.folded(insn, &args))
    }
}

fn address(base: &Expr, offset: Num) -> String {
    let zero = offset.is_zero();
    if base.text == "0" {
        return if zero { "0".into() } else { num(offset) };
    }
    if zero {
        return base.text.clone();
    }
    format!("{} + {}", operand(base, 4), num(offset))
}

/// The HLA64 line of the instructions first..=last (one statement), or None when they cannot be
/// written as one — then each stays an instruction.
pub fn lift_group(p: &WasmProgram, module: &WasmModule, lines: &WasmLines, first: usize, last: usize, names: &dyn WasmNaming) -> Option<HlaLine> {
    // The listed function holding `first`.
    let k = lines.listed.partition_point(|&b| p.bodies[b as usize].first as usize <= first).checked_sub(1)?;
    let b = lines.listed[k] as usize;
    let f = &p.bodies[b];
    if first >= (f.first + f.count) as usize {
        return None;
    }
    let mut s = State {
        p,
        module,
        lines,
        names,
        func: f.index,
        last: (f.first + f.count - 1) as usize,
        results: func_type_of(module, f.index).map_or(0, |t| t.results.len()),
        stack: Vec::new(),
        out: Vec::new(),
        words: Vec::new(),
        comments: Vec::new(),
    };
    let end = module.bodies[b].end;
    let mut insn = WasmInsn::new();
    for i in first..=last {
        decode_at(&module.bytes, p.offsets[i] as usize, end, &mut insn);
        if !s.step(i, &insn) {
            return None;
        }
    }
    if !s.stack.is_empty() || s.out.len() != 1 {
        return None;
    }
    let comment = s.comments.join("; ");
    Some(HlaLine { text: s.out.pop().unwrap(), words: unique(s.words), comment: (!comment.is_empty()).then_some(comment) })
}
