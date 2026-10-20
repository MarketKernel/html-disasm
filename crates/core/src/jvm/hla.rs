//! The HLA64 view of Java bytecode.
//!
//! The JVM is a stack machine, like CIL and WebAssembly, and its view is
//! written the same way: the analysis (program.rs) marks the runs of
//! instructions that make one statement, and lift_group() turns a run back
//! into that statement by evaluating the stack with expressions instead of
//! values — `aload_0, aload_0, arraylength, invokestatic sum, lstore_2` is
//! `sum = Hello::sum(values, len(values))`. Every line stands for the
//! instructions at its addresses and means exactly what they do, operands in
//! the order the instructions compute them; whatever has no word stays an
//! instruction, as HLA64 accepts.
//!
//! The JVM's instructions say what they work on (iadd, fadd, lcmp…), so every
//! value's kind is known: a comparison of floats is joined with the branch that
//! tests it only where a NaN makes both mean the same — fcmpl leaves -1 for a
//! NaN, so `fcmpl; ifge` is `if a >= b` but `fcmpl; iflt` stays `fcmpl(a, b) < 0`.
//!
//! Locals go by the names the class keeps (LocalVariableTable, MethodParameters)
//! where a name means one slot in the whole method, else `l` and the slot.
//! Names in a line — methods, fields, labels, strings, variables — are wrapped
//! in the WebAssembly view's marks, so the page can make each one a link. A
//! port of src/core/jvm/hla.ts.
//!
//! Java's text is UTF-16 that may hold lone surrogates; here it is a String in
//! which each lone surrogate is a character of Supplementary Private Use
//! Area-B (`marked`), which the bridge writes back as `\udxxx` in its JSON.

use super::classfile::{constant, descriptor_kinds, field_kind, field_type, java_name, method_types, ClassFile};
use super::decode::{decode_at, JvmInsn};
use super::opcodes::{atype, flags as F};
use super::program::{JvmProgram, IMPORT_BASE};
use super::wtf8::Wtf8;
use crate::cil::hla::float_literal;
use crate::lift::{unique, HlaLine, Words};
use crate::refs::{FxHashMap, FxHashSet};
use crate::text::{js_hex, js_number};

/// Where lone surrogates go in a String: U+100000 + (unit − 0xD800).
const MARK_BASE: u32 = 0x10_0000;

/// A lone surrogate's unit, when the character stands for one.
pub fn lone_surrogate(c: char) -> Option<u16> {
    let v = c as u32;
    (MARK_BASE..MARK_BASE + 0x800).contains(&v).then(|| (v - MARK_BASE + 0xd800) as u16)
}

/// Java text as a String, lone surrogates marked.
pub fn marked(w: &Wtf8) -> String {
    if let Some(s) = w.as_str() {
        return s.to_string();
    }
    w.code_points().map(|cp| if (0xd800..0xe000).contains(&cp) { char::from_u32(MARK_BASE + cp - 0xd800).unwrap() } else { char::from_u32(cp).unwrap_or('\u{fffd}') }).collect()
}

/// How many UTF-16 units a character is in the Java text it came from.
fn units(c: char) -> usize {
    if lone_surrogate(c).is_some() {
        1
    } else {
        c.len_utf16()
    }
}

/// `JSON.stringify(text.length > limit ? text.slice(0, limit) + '…' : text)` (no limit: the whole text).
fn js_quote(text: &str, limit: Option<usize>) -> String {
    let total: usize = text.chars().map(units).sum();
    let cut = limit.is_some_and(|l| total > l);
    let limit = if cut { limit.unwrap() } else { usize::MAX };
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    let mut count = 0;
    for c in text.chars() {
        let n = units(c);
        if count + n > limit {
            if count < limit {
                // The cut falls inside a surrogate pair: JavaScript keeps the lone high half.
                let mut buf = [0u16; 2];
                c.encode_utf16(&mut buf);
                out.push_str(&format!("\\u{:04x}", buf[0]));
            }
            break;
        }
        count += n;
        match lone_surrogate(c) {
            Some(unit) => out.push_str(&format!("\\u{unit:04x}")),
            None => crate::lift::escape_json_char(&mut out, c),
        }
    }
    if cut {
        out.push('…');
    }
    out.push('"');
    out
}

/// What kind of value: int (and boolean, byte, char, short), long, float, double, a reference; None when it is not known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum K {
    I,
    L,
    F,
    D,
    A,
}

type Kind = Option<K>;

fn letter(c: &str) -> Kind {
    Some(match c {
        "i" | "b" | "c" | "s" => K::I,
        "l" => K::L,
        "f" => K::F,
        "d" => K::D,
        "a" => K::A,
        _ => return None,
    })
}

/// A value on the stack, as HLA64 writes it.
#[derive(Clone)]
struct Expr {
    text: String,
    /// Go's levels: 6 an operand, 5.5 a unary operator, 5 * / % << >> >>> &, 4 + - | ^, 3 comparisons.
    prec: f64,
    /// Computing it has no effect (no call, store, allocation).
    pure: bool,
    kind: Kind,
    /// For x op= y: the operator and operands of a binary expression.
    op: Option<&'static str>,
    left: Option<Box<Expr>>,
    right: Option<Box<Expr>>,
    /// A variable or a constant: dup may write it twice.
    copyable: bool,
    /// A Java boolean (a method's or field's Z, instanceof): `if b` tests it.
    boolean: bool,
    /// lcmp, fcmpl…: the two values compared and how a NaN compares, for the branch that tests the result.
    cmp: Option<Box<(Expr, Expr, i8)>>,
    /// `new C` before its constructor has run: the class's name.
    construct: Option<String>,
    /// The copy of a `new` its constructor takes.
    init: bool,
    /// A new array, `new int[n]`, and the elements an initializer has stored in it so far; the copy of it a store takes.
    array: Option<(String, Vec<String>)>,
    fill_copy: bool,
    /// An int constant's value.
    int: Option<i64>,
}

fn atom(text: String, kind: Kind, pure: bool) -> Expr {
    Expr {
        text,
        prec: 6.0,
        pure,
        kind,
        op: None,
        left: None,
        right: None,
        copyable: false,
        boolean: false,
        cmp: None,
        construct: None,
        init: false,
        array: None,
        fill_copy: false,
        int: None,
    }
}

fn unary(text: String, kind: Kind, pure: bool) -> Expr {
    Expr { prec: 5.5, ..atom(text, kind, pure) }
}

fn copyable(mut e: Expr) -> Expr {
    e.copyable = true;
    e
}

fn wrap(e: &Expr, min: f64) -> String {
    if e.prec >= min {
        e.text.clone()
    } else {
        format!("({})", e.text)
    }
}

fn operand_text(e: &Expr, min: f64) -> String {
    if matches!(e.op, Some("<<" | ">>" | ">>>")) && e.prec == 5.0 {
        format!("({})", e.text)
    } else {
        wrap(e, min)
    }
}

fn binary(left: &Expr, op: &'static str, prec: f64, right: &Expr, kind: Kind) -> Expr {
    let min = if prec == 3.0 { 4.0 } else { prec };
    let text = format!("{} {op} {}", operand_text(left, min), operand_text(right, if prec == 3.0 { 4.0 } else { prec + 1.0 }));
    Expr { op: Some(op), left: Some(Box::new(left.clone())), right: Some(Box::new(right.clone())), prec, ..atom(text, kind, left.pure && right.pure) }
}

fn num(v: i64) -> String {
    if v > -10 && v < 10 {
        v.to_string()
    } else if v < 0 {
        format!("-0x{:x}", v.unsigned_abs())
    } else {
        format!("0x{v:x}")
    }
}

/// The arithmetic, by the operation's name without its type letter: the operator, its level, its word, integers only.
fn binary_op(name: &str) -> Option<(&'static str, f64, &'static str, bool)> {
    Some(match name {
        "add" => ("+", 4.0, "arith", false),
        "sub" => ("-", 4.0, "arith", false),
        "mul" => ("*", 5.0, "arith", false),
        "div" => ("/", 5.0, "arith", false),
        "rem" => ("%", 5.0, "arith", true),
        "and" => ("&", 5.0, "arith", false),
        "or" => ("|", 4.0, "arith", false),
        "xor" => ("^", 4.0, "arith", false),
        "shl" => ("<<", 5.0, "shift", false),
        "shr" => (">>", 5.0, "shift", false),
        "ushr" => (">>>", 5.0, "shift", false),
        _ => return None,
    })
}

/// Conversions named after their result: i2b is i8(x), i2c u16(x).
fn conversion(m: &str) -> Option<(&'static str, Kind)> {
    Some(match m {
        "i2l" => ("i64", Some(K::L)),
        "i2f" => ("f32", Some(K::F)),
        "i2d" => ("f64", Some(K::D)),
        "l2i" => ("i32", Some(K::I)),
        "l2f" => ("f32", Some(K::F)),
        "l2d" => ("f64", Some(K::D)),
        "f2i" => ("i32", Some(K::I)),
        "f2l" => ("i64", Some(K::L)),
        "f2d" => ("f64", Some(K::D)),
        "d2i" => ("i32", Some(K::I)),
        "d2l" => ("i64", Some(K::L)),
        "d2f" => ("f32", Some(K::F)),
        "i2b" => ("i8", Some(K::I)),
        "i2c" => ("u16", Some(K::I)),
        "i2s" => ("i16", Some(K::I)),
        _ => return None,
    })
}

/// The conditions of the branches: if<cond> against zero, if_icmp<cond> and if_acmp<cond> between two values.
fn condition_op(cond: &str) -> Option<&'static str> {
    Some(match cond {
        "eq" => "==",
        "ne" => "!=",
        "lt" => "<",
        "ge" => ">=",
        "gt" => ">",
        "le" => "<=",
        _ => return None,
    })
}

pub fn is_identifier(name: &str) -> bool {
    let b = name.as_bytes();
    match b.first() {
        Some(c) if c.is_ascii_alphabetic() || *c == b'_' => b[1..].iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_'),
        _ => false,
    }
}

/// Words a local cannot be named in a line: they are HLA64's own, or the view's.
pub fn reserved(name: &str) -> bool {
    matches!(name, "if" | "goto" | "return" | "switch" | "case" | "default" | "fn" | "null" | "new" | "len" | "concat" | "lambda" | "asm" | "nan" | "inf" | "this" | "_")
}

/// `/^l\d+$/`
pub fn slot_like(name: &str) -> bool {
    name.len() > 1 && name.starts_with('l') && name[1..].bytes().all(|b| b.is_ascii_digit())
}

fn quoted(name: &str, words: &mut Words) -> String {
    if is_identifier(name) {
        return name.to_string();
    }
    words.push("quoted-name");
    format!("`{name}`")
}

fn mark(kind: char, value: f64, text: &str) -> String {
    format!("\u{1}{kind}{}\u{2}{text}\u{3}", js_number(value))
}

fn is_word(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// `text.replace(/(?:[\w$]+\.)+/g, '')`: a Java type without its packages, `java.util.Map$Entry` → `Map$Entry`.
pub fn strip_packages(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let word = |c: char| is_word(c) || c == '$';
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < chars.len() {
        let mut j = i;
        let mut end = None;
        loop {
            let mut k = j;
            while k < chars.len() && word(chars[k]) {
                k += 1;
            }
            if k > j && chars.get(k) == Some(&'.') {
                j = k + 1;
                end = Some(j);
            } else {
                break;
            }
        }
        match end {
            Some(e) => i = e,
            None => {
                out.push(chars[i]);
                i += 1;
            }
        }
    }
    out
}

/// A class as the view names it: its simple name — `String`, `Point` for hello/Hello$Point —, an array as Java writes its type.
pub fn short_class(internal: &str, internal_wtf8: &Wtf8) -> String {
    if internal.starts_with('[') {
        let ty = marked(&field_type(internal_wtf8));
        let a = strip_packages(&ty);
        // .replace(/\b[\w$]+\$(?=[A-Za-z_])/g, '')
        let chars: Vec<char> = a.chars().collect();
        let mut out = String::with_capacity(a.len());
        let mut i = 0;
        while i < chars.len() {
            let before = i > 0 && is_word(chars[i - 1]);
            let boundary = before != is_word(chars[i]);
            let mut matched = None;
            if boundary && (is_word(chars[i]) || chars[i] == '$') {
                let mut j = i;
                while j < chars.len() && (is_word(chars[j]) || chars[j] == '$') {
                    j += 1;
                }
                // The last `$` past the first character of the run that a letter or _ follows.
                let mut k = j;
                while k > i + 1 {
                    k -= 1;
                    if chars[k] == '$' && chars.get(k + 1).is_some_and(|c| c.is_ascii_alphabetic() || *c == '_') {
                        matched = Some(k + 1);
                        break;
                    }
                }
            }
            match matched {
                Some(e) => i = e,
                None => {
                    out.push(chars[i]);
                    i += 1;
                }
            }
        }
        return out;
    }
    let simple = match internal.rfind('/') {
        Some(k) => &internal[k + 1..],
        None => internal,
    };
    let nested = match simple.rfind('$') {
        Some(k) => &simple[k + 1..],
        None => simple,
    };
    if is_identifier(nested) {
        nested.to_string()
    } else {
        simple.to_string()
    }
}

/* ------------------------------------------------------------------ *
 * What a method holds
 * ------------------------------------------------------------------ */

struct Local {
    start: u32,
    length: u32,
    name: String,
    slot: u32,
}

struct MethodInfo {
    instance: bool,
    /// The local variables the class names, and the names that mean more than one slot.
    locals: Vec<Local>,
    ambiguous: FxHashSet<String>,
    /// Parameter names by slot (MethodParameters), when there is no LocalVariableTable.
    params: FxHashMap<u32, String>,
    /// Slot 0 is written: `this` cannot name it.
    this_written: bool,
}

/// What a page asks of Java's names that only it can say: the address its strings page gives a text.
pub trait JvmNaming {
    fn string_addr(&self, text: &str) -> f64;
}

/// What lifting has worked out of the methods it has seen.
#[derive(Default)]
pub struct JvmLines {
    methods: FxHashMap<usize, MethodInfo>,
}

impl JvmLines {
    fn method_info(&mut self, p: &JvmProgram, fn_index: usize) -> &MethodInfo {
        self.methods.entry(fn_index).or_insert_with(|| {
            let body = p.bodies[fn_index];
            let cf = &p.classes[body.cls as usize];
            let method = &cf.methods[body.method as usize];
            let instance = method.access & 0x0008 == 0;
            let locals: Vec<Local> = match &method.code {
                Some(code) => {
                    cf.local_variables(code).into_iter().map(|v| Local { start: v.start as u32, length: v.length as u32, name: marked(v.name), slot: v.slot as u32 }).collect()
                }
                None => Vec::new(),
            };
            let mut slots_of: FxHashMap<&str, FxHashSet<u32>> = FxHashMap::default();
            for v in &locals {
                slots_of.entry(v.name.as_str()).or_default().insert(v.slot);
            }
            let ambiguous = slots_of.iter().filter(|(_, slots)| slots.len() > 1).map(|(name, _)| name.to_string()).collect();
            let mut params = FxHashMap::default();
            if let Some(names) = cf.parameter_names(method) {
                let mut slot = if instance { 1 } else { 0 };
                let kinds = descriptor_kinds(cf.utf8(method.descriptor_index as usize)).params;
                let kinds = kinds.as_bytes();
                for (k, name) in names.iter().enumerate() {
                    if !name.is_empty() {
                        params.insert(slot, marked(name));
                    }
                    slot += if matches!(kinds.get(k), Some(b'l' | b'd')) { 2 } else { 1 };
                }
            }
            let mut this_written = false;
            if instance {
                let f = &p.functions[fn_index];
                let mut insn = JvmInsn::new();
                for i in f.first..f.first + f.count {
                    insn_at(p, fn_index, i as usize, &mut insn);
                    if insn.m == "astore_0" || ((insn.m == "astore" || insn.m == "astore_w") && insn.a == 0) {
                        this_written = true;
                    }
                }
            }
            MethodInfo { instance, locals, ambiguous, params, this_written }
        })
    }

    /// The parameters of a method's HLA64 header: the class's own names where a name means one slot,
    /// else `l` and the slot; and their Java types without packages (headerParams in the TypeScript).
    pub fn header_params(&mut self, p: &JvmProgram, fn_index: usize) -> Vec<(String, String)> {
        let body = p.bodies[fn_index];
        let cf = &p.classes[body.cls as usize];
        let descriptor = cf.utf8(cf.methods[body.method as usize].descriptor_index as usize);
        let info = self.method_info(p, fn_index);
        let types = method_types(descriptor).params;
        let kinds = descriptor_kinds(descriptor).params;
        let kinds = kinds.as_bytes();
        let mut slot = u32::from(info.instance);
        let mut out = Vec::new();
        for (k, ty) in types.iter().enumerate() {
            let name = match info.locals.iter().find(|l| l.slot == slot && l.start == 0) {
                Some(v) => Some(v.name.as_str()),
                None => info.params.get(&slot).map(String::as_str),
            };
            let shown = match name {
                Some(n) if is_identifier(n) && !reserved(n) && !slot_like(n) && !info.ambiguous.contains(n) => n.to_string(),
                _ => format!("l{slot}"),
            };
            slot += if matches!(kinds.get(k), Some(b'l' | b'd')) { 2 } else { 1 };
            out.push((shown, strip_packages(&marked(&java_name(ty)))));
        }
        out
    }

    /// The HLA64 line of the instructions first..=last (one statement), or None when they cannot
    /// be written as one — then each stays an instruction.
    pub fn lift_group(&mut self, p: &JvmProgram, first: usize, last: usize, names: &dyn JvmNaming) -> Option<HlaLine> {
        let fn_index = function_of_index(p, first)?;
        let body = p.bodies[fn_index];
        let info = self.method_info(p, fn_index);
        let cf = &p.classes[body.cls as usize];
        let mut s = State { p, cf, cls: body.cls, info, names, insn: JvmInsn::new(), stack: Vec::new(), out: Vec::new(), words: Vec::new() };
        for i in first..=last {
            insn_at(p, fn_index, i, &mut s.insn);
            if !s.step(i) {
                return None;
            }
        }
        if !s.stack.is_empty() || s.out.len() != 1 {
            return None;
        }
        let text = s.out.pop().unwrap();
        // A comparison's value that no branch took is written as the instruction.
        if compares(&text) {
            s.words.push("jvm-folded");
        }
        Some(HlaLine { text, words: unique(s.words), comment: None })
    }
}

/// `/\b(?:lcmp|[fd]cmp[lg])\(/`
fn compares(text: &str) -> bool {
    let b = text.as_bytes();
    let at_boundary = |i: usize| i == 0 || !(b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_');
    (0..b.len()).any(|i| {
        at_boundary(i) && {
            let rest = &b[i..];
            rest.starts_with(b"lcmp(")
                || (rest.len() >= 5 && matches!(rest[0], b'f' | b'd') && rest[1..].starts_with(b"cmp") && matches!(rest[4], b'l' | b'g') && rest.get(5) == Some(&b'('))
        }
    })
}

/// The function holding an instruction, or None.
pub fn function_of_index(p: &JvmProgram, index: usize) -> Option<usize> {
    let k = p.functions.partition_point(|f| f.first as usize <= index).checked_sub(1)?;
    let f = &p.functions[k];
    (index < (f.first + f.count) as usize).then_some(k)
}

/// Decodes the instruction at an index of a function.
pub fn insn_at(p: &JvmProgram, fn_index: usize, index: usize, insn: &mut JvmInsn) {
    let body = p.bodies[fn_index];
    let cf = &p.classes[body.cls as usize];
    let Some(code) = &cf.methods[body.method as usize].code else { return };
    let pos = code.offset as i64 + p.result.offsets[index] as i64 - body.base as i64;
    let end = code.offset + code.length;
    if pos < code.offset as i64 || pos as usize >= end {
        insn.op = None;
        insn.m = ".byte";
        insn.len = 1;
        return;
    }
    decode_at(&cf.bytes, code.offset, pos as usize, end, insn);
}

/* ------------------------------------------------------------------ *
 * Lifting
 * ------------------------------------------------------------------ */

struct State<'a> {
    p: &'a JvmProgram,
    cf: &'a ClassFile,
    cls: u32,
    info: &'a MethodInfo,
    names: &'a dyn JvmNaming,
    insn: JvmInsn,
    stack: Vec<Expr>,
    out: Vec<String>,
    words: Words,
}

fn wide(e: &Expr) -> bool {
    matches!(e.kind, Some(K::L | K::D))
}

impl State<'_> {
    fn class_name(&mut self, internal: &Wtf8) -> String {
        let short = short_class(&marked(internal), internal);
        quoted(&short, &mut self.words)
    }

    /// A class between angle brackets, where an array type needs no quotes: `checkcast<int[]>`.
    fn type_argument(&mut self, internal: &Wtf8) -> String {
        if internal.starts_with("[") {
            short_class(&marked(internal), internal)
        } else {
            self.class_name(internal)
        }
    }

    /// `L12`: the pc an address is at in its method.
    fn label_name(&self, addr: f64) -> String {
        let p = self.p;
        let index = if addr >= 0.0 && addr.fract() == 0.0 && addr <= u32::MAX as f64 { p.result.offsets.binary_search(&(addr as u32)).ok() } else { None };
        match index.and_then(|i| function_of_index(p, i)) {
            Some(f) => format!("L{}", js_number(addr - p.functions[f].addr as f64)),
            None => format!("L{}", js_hex(addr)),
        }
    }

    fn addr_of(&self, target: i64) -> f64 {
        if target < 0 {
            return 0.0;
        }
        self.p.result.offsets.get(target as usize).map_or(0.0, |&a| a as f64)
    }

    fn branch_targets(&self, index: usize) -> &[u32] {
        let r = &self.p.result;
        match r.target_index.binary_search(&(index as u32)) {
            Ok(k) => &r.target_values[r.target_starts[k] as usize..r.target_starts[k + 1] as usize],
            Err(_) => &[],
        }
    }

    fn first_target(&self, index: usize) -> i64 {
        self.branch_targets(index).first().map_or(-1, |&t| t as i64)
    }

    /// The name of a local at an instruction: the class's own name for it, `this`, or `l` and the slot.
    fn local_name(&self, slot: u32, store: bool) -> String {
        let pc = self.insn.at as u32;
        let after = pc + self.insn.len as u32;
        let info = self.info;
        let mut found: Option<&Local> = None;
        for v in &info.locals {
            if v.slot != slot {
                continue;
            }
            if pc >= v.start && pc < v.start + v.length {
                found = Some(v);
                break;
            }
            // A store starts the variable's range: the range begins after it.
            if store && after >= v.start && after <= v.start + v.length && found.is_none() {
                found = Some(v);
            }
        }
        let name: Option<&str> = match found {
            Some(v) => Some(v.name.as_str()),
            None if info.locals.is_empty() => info.params.get(&slot).map(String::as_str),
            None => None,
        };
        if name == Some("this") && slot == 0 && info.instance && !info.this_written {
            return "this".into();
        }
        if let Some(name) = name.filter(|n| !n.is_empty()) {
            if is_identifier(name) && !reserved(name) && !slot_like(name) && !info.ambiguous.contains(name) {
                return name.to_string();
            }
        }
        if slot == 0 && info.instance && !info.this_written && found.is_none() {
            return "this".into();
        }
        format!("l{slot}")
    }

    fn variable(&mut self, slot: i64, kind: Kind, store: bool) -> Expr {
        self.words.push("jvm-local");
        let name = self.local_name(slot as u32, store);
        copyable(atom(mark('v', slot as f64, &name), kind, true))
    }

    fn label_mark(&self, target: i64) -> String {
        let addr = self.addr_of(target);
        mark('l', addr, &self.label_name(addr))
    }

    fn goto_label(&mut self, target: i64) -> String {
        self.words.push("goto");
        format!("goto {}", self.label_mark(target))
    }

    fn assign(&mut self, dest: &str, value: &Expr) -> String {
        self.words.push("assign");
        if let (Some(op), Some(left), Some(right)) = (value.op, &value.left, &value.right) {
            if left.text == dest && matches!(op, "+" | "-" | "*" | "/" | "%" | "&" | "|" | "^" | "<<" | ">>" | ">>>") {
                self.words.push("compound");
                return format!("{dest} {op}= {}", right.text);
            }
        }
        format!("{dest} = {}", value.text)
    }

    /// The instruction as a function of its operands: `checkcast<String>(x)`, `monitorenter(x)`.
    fn folded(&mut self, name: &str, imm: &str, args: &[Expr], kind: Kind, pure: bool) -> Expr {
        self.words.push("jvm-folded");
        let list: Vec<&str> = args.iter().map(|a| a.text.as_str()).collect();
        let imm = if imm.is_empty() { String::new() } else { format!("<{imm}>") };
        atom(format!("{name}{imm}({})", list.join(", ")), kind, pure)
    }

    fn take(&mut self, count: i64) -> Option<Vec<Expr>> {
        if count > self.stack.len() as i64 {
            return None;
        }
        if count <= 0 {
            return Some(Vec::new());
        }
        Some(self.stack.split_off(self.stack.len() - count as usize))
    }

    fn take1(&mut self) -> Option<Expr> {
        self.take(1).and_then(|mut v| v.pop())
    }

    fn take2(&mut self) -> Option<(Expr, Expr)> {
        let mut v = self.take(2)?;
        let b = v.pop()?;
        let a = v.pop()?;
        Some((a, b))
    }

    /// The address of a function a constant pool reference of the class leads to, or -1.
    fn callee(&self, index: i64) -> f64 {
        let r = &self.p.result;
        let key = self.cls as f64 * 65536.0 + index as f64;
        let Some(k) = find(&r.callee_keys, key) else { return -1.0 };
        let addr = r.callee_values[k];
        if addr < 0.0 {
            return -1.0;
        }
        if addr >= IMPORT_BASE as f64 {
            return if self.p.imported.iter().any(|i| i.addr as f64 == addr) { addr } else { -1.0 };
        }
        // A function whose first instruction is at the address.
        let p = self.p;
        match p.result.offsets.binary_search(&(addr as u32)) {
            Ok(i) if p.functions.binary_search_by_key(&(i as u32), |f| f.first).is_ok() => addr,
            _ => -1.0,
        }
    }

    fn field_addr(&self, index: i64) -> f64 {
        let r = &self.p.result;
        find(&r.field_keys, self.cls as f64 * 65536.0 + index as f64).map_or(-1.0, |k| r.field_values[k])
    }

    fn callee_link(&self, index: i64, text: &str) -> String {
        mark('f', self.callee(index), text)
    }

    fn string_mark(&self, text: &str, limit: Option<usize>) -> String {
        mark('s', self.names.string_addr(text), &js_quote(text, limit))
    }

    /// The value a constant pool entry loads (ldc), or None when it has no form here.
    fn constant(&mut self, index: usize) -> Option<Expr> {
        let cf = self.cf;
        Some(match cf.tags.get(index).copied().unwrap_or(0) {
            constant::INTEGER => copyable(atom(num(cf.int(index) as i64), Some(K::I), true)),
            constant::LONG => copyable(atom(num(cf.long(index)), Some(K::L), true)),
            constant::FLOAT => {
                self.words.push("float");
                copyable(atom(float_literal(cf.float(index) as f64, true), Some(K::F), true))
            }
            constant::DOUBLE => {
                self.words.push("float");
                copyable(atom(float_literal(cf.double(index), false), Some(K::D), true))
            }
            constant::STRING => {
                let text = marked(cf.utf8(cf.ref1(index)));
                self.words.push("string");
                copyable(atom(self.string_mark(&text, Some(80)), Some(K::A), true))
            }
            constant::CLASS => {
                let ty = self.type_argument(cf.class_name(index));
                copyable(self.folded("ldc", &ty, &[], Some(K::A), true))
            }
            _ => return None,
        })
    }

    /// invokedynamic: string concatenation and lambdas have words; any other call site is written as the instruction with its name.
    fn dynamic(&mut self, index: usize, args: &[Expr]) -> Expr {
        let cf = self.cf;
        let site = cf.dynamic(index);
        let bootstrap = cf.bootstrap_methods().get(site.bootstrap as usize);
        let handle = bootstrap.filter(|b| cf.tags.get(b.method as usize) == Some(&constant::METHOD_HANDLE)).map(|b| cf.member(cf.handle(b.method as usize).reference as usize));
        let ret = letter(descriptor_kinds(site.descriptor).ret);
        let site_name = marked(site.name);
        let fallback = |s: &mut Self| {
            let name = quoted(&site_name, &mut s.words);
            s.folded("invokedynamic", &name, args, ret, false)
        };
        if let (Some(handle), Some(b)) = (&handle, bootstrap) {
            if handle.owner == "java/lang/invoke/StringConcatFactory"
                && handle.name == "makeConcatWithConstants"
                && !b.args.is_empty()
                && cf.tags.get(b.args[0] as usize) == Some(&constant::STRING)
            {
                // The recipe: \u0001 takes the next argument, \u0002 the next constant of the bootstrap's, the rest is text.
                let recipe = marked(cf.utf8(cf.ref1(b.args[0] as usize)));
                let mut parts: Vec<String> = Vec::new();
                let mut text = String::new();
                let mut next = 0;
                let mut constants = 1;
                for c in recipe.chars() {
                    if c == '\u{1}' {
                        if !text.is_empty() {
                            parts.push(self.string_mark(&text, None));
                            text.clear();
                        }
                        let Some(arg) = args.get(next) else { return fallback(self) };
                        next += 1;
                        parts.push(arg.text.clone());
                    } else if c == '\u{2}' {
                        let k = b.args.get(constants).copied();
                        constants += 1;
                        match k {
                            Some(k) if cf.tags.get(k as usize) == Some(&constant::STRING) => text.push_str(&marked(cf.utf8(cf.ref1(k as usize)))),
                            _ => return fallback(self),
                        }
                    } else {
                        text.push(c);
                    }
                }
                if !text.is_empty() {
                    parts.push(self.string_mark(&text, None));
                }
                if next != args.len() {
                    return fallback(self);
                }
                self.words.push("jvm-concat");
                return atom(format!("concat({})", parts.join(", ")), Some(K::A), false);
            }
            if handle.owner == "java/lang/invoke/LambdaMetafactory"
                && (handle.name == "metafactory" || handle.name == "altMetafactory")
                && b.args.len() >= 2
                && cf.tags.get(b.args[1] as usize) == Some(&constant::METHOD_HANDLE)
            {
                let implementation = cf.member(cf.handle(b.args[1] as usize).reference as usize);
                let target = self.callee(b.args[1] as i64);
                let iface = marked(&method_types(site.descriptor).ret);
                let owner = self.class_name(implementation.owner);
                let name = quoted(&marked(implementation.name), &mut self.words);
                let link = mark('f', target, &format!("{owner}::{name}"));
                self.words.push("jvm-lambda");
                // iface.slice(iface.lastIndexOf('.') + 1).replace(/^.*\$/, '')
                let simple = match iface.rfind('.') {
                    Some(k) => &iface[k + 1..],
                    None => iface.as_str(),
                };
                let line_end = simple.find(['\n', '\r', '\u{2028}', '\u{2029}']).unwrap_or(simple.len());
                let simple = match simple[..line_end].rfind('$') {
                    Some(k) => &simple[k + 1..],
                    None => simple,
                };
                let iface_name = quoted(simple, &mut self.words);
                let list: Vec<&str> = args.iter().map(|a| a.text.as_str()).collect();
                return atom(format!("lambda<{iface_name}, {link}>({})", list.join(", ")), Some(K::A), false);
            }
        }
        fallback(self)
    }

    /// A branch on a value against zero: joined with the comparison that made it where that means exactly the same.
    fn zero_condition(value: &Expr, cond: &str) -> String {
        let op = condition_op(cond).unwrap();
        if let Some(cmp) = &value.cmp {
            let (a, b, nan) = (&cmp.0, &cmp.1, cmp.2);
            // With a NaN the comparison leaves `nan`, and the branch is taken when `nan cond 0`; `a op b` is false for a NaN, `a != b` true. They must agree.
            let taken = match cond {
                "eq" => nan == 0,
                "ne" => nan != 0,
                "lt" => nan < 0,
                "le" => nan <= 0,
                "gt" => nan > 0,
                _ => nan >= 0,
            };
            if nan == 0 || taken == (cond == "ne") {
                return binary(a, op, 3.0, b, Some(K::I)).text;
            }
        }
        if value.boolean && cond == "ne" {
            return value.text.clone();
        }
        format!("{} {op} 0", wrap(value, 4.0))
    }

    fn push(&mut self, e: Expr) -> bool {
        self.stack.push(e);
        true
    }

    fn statement(&mut self, text: String) -> bool {
        self.out.push(text);
        true
    }

    /// One instruction applied to the expression stack. False when it has no form here.
    fn step(&mut self, index: usize) -> bool {
        let Some(op) = self.insn.op else { return false };
        if op.flags & F::SUBROUTINE != 0 {
            return false;
        }
        let m = self.insn.m;
        let cf = self.cf;
        let a = self.insn.a;

        // Locals: ([ilfda])(load|store)(_[0-3]|_w)?
        if let Some((kind, load, slot)) = local_op(m) {
            let slot = slot.map_or(a, i64::from);
            let kind = letter(kind);
            if load {
                let v = self.variable(slot, kind, false);
                return self.push(v);
            }
            let Some(value) = self.take1() else { return false };
            let v = self.variable(slot, kind, true);
            let line = self.assign(&v.text, &value);
            return self.statement(line);
        }
        if m == "iinc" || m == "iinc_w" {
            self.words.push("compound");
            let v = self.variable(a, Some(K::I), true).text;
            let b = self.insn.b as i64;
            return self.statement(if b < 0 { format!("{v} -= {}", num(-b)) } else { format!("{v} += {}", num(b)) });
        }
        // Constants: ([ilfd])const_(m1|\d)
        if let Some((kind, value)) = const_op(m) {
            let kind = letter(kind);
            let float = matches!(kind, Some(K::F | K::D));
            if float {
                self.words.push("float");
            }
            let mut e = copyable(atom(if float { format!("{value}.0") } else { value.to_string() }, kind, true));
            e.int = (kind == Some(K::I)).then_some(value);
            return self.push(e);
        }
        match m {
            "bipush" | "sipush" => {
                let mut e = copyable(atom(num(a), Some(K::I), true));
                e.int = Some(a);
                return self.push(e);
            }
            "aconst_null" => {
                self.words.push("jvm-new");
                return self.push(copyable(atom("null".into(), Some(K::A), true)));
            }
            "ldc" | "ldc_w" | "ldc2_w" => {
                return match self.constant(a as usize) {
                    Some(value) => self.push(value),
                    None => false,
                };
            }
            "pop" | "pop2" => {
                let Some(top) = self.stack.last() else { return false };
                if m == "pop2" && !wide(top) {
                    return false;
                }
                let top = self.stack.pop().unwrap();
                if !top.pure && top.text.ends_with(')') && top.construct.is_none() {
                    return self.statement(top.text);
                }
                self.words.push("jvm-pop");
                return self.statement(format!("_ = {}", top.text));
            }
            "dup" => {
                let Some(top) = self.stack.last().cloned() else { return false };
                if top.construct.is_some() {
                    return self.push(Expr { init: true, construct: None, ..top });
                }
                if top.array.is_some() {
                    return self.push(Expr { fill_copy: true, array: None, ..top });
                }
                if !top.copyable {
                    return false;
                }
                return self.push(top);
            }
            "dup2" => {
                let n = self.stack.len();
                let Some(top) = self.stack.last().cloned() else { return false };
                if wide(&top) {
                    return if top.copyable { self.push(top) } else { false };
                }
                let Some(below) = n.checked_sub(2).map(|k| self.stack[k].clone()) else { return false };
                if !top.copyable || !below.copyable || wide(&below) {
                    return false;
                }
                self.stack.push(below);
                self.stack.push(top);
                return true;
            }
            "ireturn" | "lreturn" | "freturn" | "dreturn" | "areturn" | "return" => {
                self.words.push("return");
                // ireturn … areturn take one value: when it was made before a label, the line cannot name it.
                let values = std::mem::take(&mut self.stack);
                if values.len() != usize::from(m != "return") {
                    return false;
                }
                return self.statement(match values.first() {
                    Some(v) => format!("return {}", v.text),
                    None => "return".into(),
                });
            }
            "goto" | "goto_w" => {
                let target = self.first_target(index);
                let line = self.goto_label(target);
                return self.statement(line);
            }
            "tableswitch" | "lookupswitch" => {
                let value = self.take1();
                let targets = self.branch_targets(index).to_vec();
                let keys = self.insn.keys.clone();
                let Some(value) = value else { return false };
                if targets.len() != keys.len() + 1 {
                    return false;
                }
                self.words.push("switch");
                self.words.push("goto");
                let mut by_target: Vec<(u32, Vec<i64>)> = Vec::new();
                for (k, &key) in keys.iter().enumerate() {
                    let target = targets[k];
                    match by_target.iter_mut().find(|(t, _)| *t == target) {
                        Some((_, values)) => values.push(key as i64),
                        None => by_target.push((target, vec![key as i64])),
                    }
                }
                let fallback = targets[keys.len()];
                let mut cases = Vec::new();
                for (target, values) in &by_target {
                    if *target == fallback {
                        continue;
                    }
                    let mut ranges = Vec::new();
                    let mut k = 0;
                    while k < values.len() {
                        let mut e = k;
                        while e + 1 < values.len() && values[e + 1] == values[e] + 1 {
                            e += 1;
                        }
                        ranges.push(if e == k {
                            num(values[k])
                        } else if e == k + 1 {
                            format!("{}, {}", num(values[k]), num(values[e]))
                        } else {
                            format!("{}..={}", num(values[k]), num(values[e]))
                        });
                        k = e + 1;
                    }
                    cases.push(format!("case {} {{ goto {} }}", ranges.join(", "), self.label_mark(*target as i64)));
                }
                cases.push(format!("default {{ goto {} }}", self.label_mark(fallback as i64)));
                return self.statement(format!("switch {} {{ {} }}", value.text, cases.join(" ")));
            }
            _ => {}
        }

        // Branches.
        if let Some(cond) = m.strip_prefix("if").filter(|c| condition_op(c).is_some()) {
            let Some(value) = self.take1() else { return false };
            let text = Self::zero_condition(&value, cond);
            self.words.push("if-goto");
            let target = self.first_target(index);
            let goto = self.goto_label(target);
            return self.statement(format!("if {text} {{ {goto} }}"));
        }
        if let Some(cond) = m.strip_prefix("if_icmp").or_else(|| m.strip_prefix("if_acmp")).and_then(condition_op) {
            let Some((x, y)) = self.take2() else { return false };
            self.words.push("if-goto");
            let text = binary(&x, cond, 3.0, &y, Some(K::I)).text;
            let target = self.first_target(index);
            let goto = self.goto_label(target);
            return self.statement(format!("if {text} {{ {goto} }}"));
        }
        if m == "ifnull" || m == "ifnonnull" {
            let Some(value) = self.take1() else { return false };
            self.words.push("if-goto");
            self.words.push("jvm-new");
            let target = self.first_target(index);
            let goto = self.goto_label(target);
            return self.statement(format!("if {} {} null {{ {goto} }}", wrap(&value, 4.0), if m == "ifnull" { "==" } else { "!=" }));
        }

        // Fields, calls, objects.
        match m {
            "getfield" | "putfield" | "getstatic" | "putstatic" => {
                let r = cf.member(a as usize);
                let kind = letter(field_kind(r.descriptor));
                let name = quoted(&marked(r.name), &mut self.words);
                let field = mark('g', self.field_addr(a), &name);
                self.words.push("jvm-member");
                let boolean = r.descriptor == "Z";
                if m == "getstatic" {
                    let owner = self.class_name(r.owner);
                    let mut e = atom(format!("{owner}::{field}"), kind, true);
                    e.boolean = boolean;
                    return self.push(e);
                }
                if m == "putstatic" {
                    let Some(value) = self.take1() else { return false };
                    let owner = self.class_name(r.owner);
                    let line = self.assign(&format!("{owner}::{field}"), &value);
                    return self.statement(line);
                }
                if m == "getfield" {
                    let Some(obj) = self.take1() else { return false };
                    let mut e = atom(format!("{}.{field}", wrap(&obj, 6.0)), kind, obj.pure);
                    e.boolean = boolean;
                    return self.push(e);
                }
                let Some((obj, value)) = self.take2() else { return false };
                let line = self.assign(&format!("{}.{field}", wrap(&obj, 6.0)), &value);
                return self.statement(line);
            }
            "invokestatic" | "invokevirtual" | "invokeinterface" | "invokespecial" => {
                let r = cf.member(a as usize);
                let shape = descriptor_kinds(r.descriptor);
                let count = shape.params.len() as i64 + i64::from(m != "invokestatic");
                let Some(args) = self.take(count) else { return false };
                let kind = letter(shape.ret);
                let list = |args: &[Expr]| args.iter().map(|a| a.text.as_str()).collect::<Vec<_>>().join(", ");
                if m == "invokespecial" && r.name == "<init>" && args.first().is_some_and(|x| x.init) {
                    // new C; dup; …; invokespecial C.<init>: the object made is the value below the copy.
                    let Some(made) = self.stack.last().and_then(|e| e.construct.clone()) else { return false };
                    self.words.push("jvm-new");
                    let text = format!("new {}({})", self.callee_link(a, &made), list(&args[1..]));
                    *self.stack.last_mut().unwrap() = unary(text, Some(K::A), false);
                    return true;
                }
                self.words.push("jvm-member");
                let text = if m == "invokevirtual" || m == "invokeinterface" {
                    let name = quoted(&marked(r.name), &mut self.words);
                    format!("{}.{}({})", wrap(&args[0], 6.0), self.callee_link(a, &name), list(&args[1..]))
                } else {
                    let owner = self.class_name(r.owner);
                    let name = quoted(&marked(r.name), &mut self.words);
                    format!("{}({})", self.callee_link(a, &format!("{owner}::{name}")), list(&args))
                };
                if !shape.ret.is_empty() {
                    let mut e = atom(text, kind, false);
                    e.boolean = r.descriptor.ends_with(")Z");
                    return self.push(e);
                }
                return self.statement(text);
            }
            "invokedynamic" => {
                let site = cf.dynamic(a as usize);
                let shape = descriptor_kinds(site.descriptor);
                let Some(args) = self.take(shape.params.len() as i64) else { return false };
                let value = self.dynamic(a as usize, &args);
                return if shape.ret.is_empty() { self.statement(value.text) } else { self.push(value) };
            }
            "new" => {
                let name = self.class_name(cf.class_name(a as usize));
                let construct = self.class_name(cf.class_name(a as usize));
                let mut e = unary(format!("new {name}"), Some(K::A), false);
                e.construct = Some(construct);
                return self.push(e);
            }
            "newarray" | "anewarray" => {
                let Some(length) = self.take1() else { return false };
                self.words.push("jvm-new");
                let element = if m == "newarray" { atype(a).unwrap_or("?").to_string() } else { self.class_name(cf.class_name(a as usize)) };
                let head = format!("new {element}[{}]", length.text);
                let mut e = unary(head.clone(), Some(K::A), false);
                e.array = Some((head, Vec::new()));
                return self.push(e);
            }
            "multianewarray" => {
                let Some(dims) = self.take(self.insn.b as i64) else { return false };
                let ty = cf.class_name(a as usize);
                let text = marked(ty);
                let depth = text.bytes().take_while(|&b| b == b'[').count();
                let base = if text.as_bytes().get(depth) == Some(&b'L') {
                    // type.slice(depth + 1, -1)
                    let inner = &text[depth + 1..];
                    let inner = inner.char_indices().last().map_or("", |(k, _)| &inner[..k]);
                    self.class_name(&wtf8_of(inner))
                } else {
                    marked(&field_type(&wtf8_of(&text[depth..])))
                };
                self.words.push("jvm-new");
                let dims_text: String = dims.iter().map(|d| format!("[{}]", d.text)).collect();
                return self.push(unary(format!("new {base}{dims_text}{}", "[]".repeat(depth.saturating_sub(dims.len()))), Some(K::A), false));
            }
            "arraylength" => {
                let Some(array) = self.take1() else { return false };
                self.words.push("jvm-array");
                return self.push(atom(format!("len({})", array.text), Some(K::I), array.pure));
            }
            "checkcast" | "instanceof" => {
                let Some(value) = self.take1() else { return false };
                let ty = self.type_argument(cf.class_name(a as usize));
                let instance_of = m == "instanceof";
                let pure = value.pure && instance_of;
                let mut e = self.folded(m, &ty, &[value], Some(if instance_of { K::I } else { K::A }), pure);
                e.boolean = instance_of;
                return self.push(e);
            }
            "athrow" | "monitorenter" | "monitorexit" => {
                let Some(value) = self.take1() else { return false };
                let e = self.folded(m, "", &[value], None, false);
                return self.statement(e.text);
            }
            _ => {}
        }

        // Arrays: ([ilfdabcs])a(load|store)
        if let Some((kind, load)) = array_op(m) {
            self.words.push("jvm-array");
            if load {
                let Some((array, at)) = self.take2() else { return false };
                return self.push(atom(format!("{}[{}]", wrap(&array, 6.0), at.text), letter(kind), array.pure && at.pure));
            }
            let Some(mut v) = self.take(3) else { return false };
            if v.len() < 3 {
                return false;
            }
            let value = v.pop().unwrap();
            let at = v.pop().unwrap();
            let array = v.pop().unwrap();
            if array.fill_copy {
                // An initializer's store: the next element of the new array below the copy.
                let Some(made) = self.stack.last() else { return false };
                let Some((head, items)) = &made.array else { return false };
                if at.int != Some(items.len() as i64) {
                    return false;
                }
                let mut items = items.clone();
                items.push(value.text);
                let head = head.clone();
                let mut e = unary(format!("{head} {{ {} }}", items.join(", ")), Some(K::A), false);
                e.array = Some((head, items));
                *self.stack.last_mut().unwrap() = e;
                return true;
            }
            let line = self.assign(&format!("{}[{}]", wrap(&array, 6.0), at.text), &value);
            return self.statement(line);
        }

        // Numbers: ([ilfd])(add|sub|…|neg)
        if let Some((kind, name)) = arith_op(m) {
            let kind = letter(kind);
            if name == "neg" {
                let Some(x) = self.take1() else { return false };
                self.words.push("arith");
                return self.push(unary(format!("-{}", wrap(&x, 6.0)), kind, x.pure));
            }
            let Some((x, y)) = self.take2() else { return false };
            let (sym, prec, word, integers) = binary_op(name).unwrap();
            let float = matches!(kind, Some(K::F | K::D));
            if integers && float {
                let pure = x.pure && y.pure;
                let e = self.folded(m, "", &[x, y], kind, pure);
                return self.push(e);
            }
            self.words.push(word);
            if float {
                self.words.push("float");
            }
            return self.push(binary(&x, sym, prec, &y, kind));
        }
        if let Some((to, kind)) = conversion(m) {
            let Some(x) = self.take1() else { return false };
            self.words.push("jvm-convert");
            return self.push(atom(format!("{to}({})", x.text), kind, x.pure));
        }
        if op.flags & F::COMPARE != 0 {
            let Some((x, y)) = self.take2() else { return false };
            let nan = if m == "lcmp" {
                0
            } else if m.ends_with('l') {
                -1
            } else {
                1
            };
            let mut e = atom(format!("{m}({}, {})", x.text, y.text), Some(K::I), x.pure && y.pure);
            e.cmp = Some(Box::new((x, y, nan)));
            return self.push(e);
        }
        false
    }
}

/// A String (lone surrogates marked) as Java text again.
fn wtf8_of(text: &str) -> super::wtf8::Wtf8Buf {
    let mut out = super::wtf8::Wtf8Buf::new();
    for c in text.chars() {
        match lone_surrogate(c) {
            Some(unit) => out.push_unit(unit),
            None => out.push_char(c),
        }
    }
    out
}

/// Binary search of a sorted key list.
fn find(keys: &[f64], key: f64) -> Option<usize> {
    let (mut lo, mut hi) = (0isize, keys.len() as isize - 1);
    while lo <= hi {
        let mid = (lo + hi) >> 1;
        let at = keys[mid as usize];
        if at == key {
            return Some(mid as usize);
        }
        if at < key {
            lo = mid + 1;
        } else {
            hi = mid - 1;
        }
    }
    None
}

/// `^([ilfda])(load|store)(?:_([0-3])|_w)?$`: the type letter, whether it loads, and the slot it names.
fn local_op(m: &str) -> Option<(&str, bool, Option<u8>)> {
    let kind = m.get(..1)?;
    if !matches!(kind, "i" | "l" | "f" | "d" | "a") {
        return None;
    }
    let rest = &m[1..];
    let (load, rest) = match (rest.strip_prefix("load"), rest.strip_prefix("store")) {
        (Some(r), _) => (true, r),
        (_, Some(r)) => (false, r),
        _ => return None,
    };
    match rest {
        "" | "_w" => Some((kind, load, None)),
        _ => match rest.as_bytes() {
            [b'_', c @ b'0'..=b'3'] => Some((kind, load, Some(c - b'0'))),
            _ => None,
        },
    }
}

/// `^([ilfd])const_(m1|\d)$`: the type letter and the value.
fn const_op(m: &str) -> Option<(&str, i64)> {
    let kind = m.get(..1)?;
    if !matches!(kind, "i" | "l" | "f" | "d") {
        return None;
    }
    let rest = m[1..].strip_prefix("const_")?;
    match rest.as_bytes() {
        b"m1" => Some((kind, -1)),
        [c @ b'0'..=b'9'] => Some((kind, (c - b'0') as i64)),
        _ => None,
    }
}

/// `^([ilfdabcs])a(load|store)$`: the element's letter, and whether it loads.
fn array_op(m: &str) -> Option<(&str, bool)> {
    let kind = m.get(..1)?;
    if !matches!(kind, "i" | "l" | "f" | "d" | "a" | "b" | "c" | "s") {
        return None;
    }
    match &m[1..] {
        "aload" => Some((kind, true)),
        "astore" => Some((kind, false)),
        _ => None,
    }
}

/// `^([ilfd])(add|sub|mul|div|rem|and|or|xor|shl|shr|ushr|neg)$`: the type letter and the operation.
fn arith_op(m: &str) -> Option<(&str, &str)> {
    let kind = m.get(..1)?;
    if !matches!(kind, "i" | "l" | "f" | "d") {
        return None;
    }
    let name = &m[1..];
    (binary_op(name).is_some() || name == "neg").then_some((kind, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_classes() {
        let short = |s: &str| short_class(s, Wtf8::new(s));
        assert_eq!(short("java/lang/String"), "String");
        assert_eq!(short("hello/Hello$Point"), "Point");
        assert_eq!(short("hello/Hello$1"), "Hello$1");
        assert_eq!(short("[[Ljava/util/Map$Entry;"), "Entry[][]");
        assert_eq!(short("[I"), "int[]");
    }

    #[test]
    fn quoting_java_text() {
        assert_eq!(js_quote("a\"b\n", Some(80)), "\"a\\\"b\\n\"");
        let lone = marked(&Wtf8Buf::from_utf16(&[0x61, 0xd800, 0x62]));
        assert_eq!(js_quote(&lone, None), "\"a\\ud800b\"");
        assert_eq!(js_quote(&"x".repeat(81), Some(80)), format!("\"{}…\"", "x".repeat(80)));
        assert!(compares("x = lcmp(a, b)") && compares("fcmpg(a, b)") && !compares("xlcmp(a)"));
    }

    use super::super::wtf8::Wtf8Buf;
}
