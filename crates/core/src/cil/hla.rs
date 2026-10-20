//! The HLA64 view of CIL.
//!
//! CIL is a stack machine, like WebAssembly, and its view is written the same
//! way: the analysis (program.rs) marks the runs of instructions that make one
//! statement, and lift_group() turns a run back into that statement by
//! evaluating the stack with expressions instead of values — `ldloc.0,
//! ldloc.0, ldlen, conv.i4, call Sum, stloc.1` is `V_1 = Program::Sum(V_0,
//! i32(len(V_0)))`. Every line stands for the instructions at its addresses and
//! means exactly what they do, operands in the order the instructions compute
//! them; whatever has no word stays an instruction, as HLA64 accepts.
//!
//! What a word needs to mean exactly decides where it is written: `>u` only
//! between integers (cgt.un between floats is "greater or unordered", between
//! references a test for null), a negated condition only where no NaN can make
//! it wrong, `%` only on integers. To know, every value carries what kind of
//! thing it is — an integer, a float, a reference, a pointer — from the
//! signatures of the locals, arguments, fields and methods it comes from.
//!
//! Names in a line — methods, fields, labels, strings, variables — are wrapped
//! in the WebAssembly view's marks, so the page can make each one a link. A
//! port of src/core/cil/hla.ts.

use super::decode::{decode_at, CilInsn};
use super::metadata::{self as m, decode_index, table as t, token, token_row, token_table, Coded, Metadata, MethodBody, USER_STRING};
use super::names::{GenericContext, Names, NamesParts, SigReader, NO_CONTEXT};
use super::opcodes::{f, operand};
use super::program::{local_method, method_blob, shape_of, CilProgram, Locals, Shape};
use crate::lift::{unique, HlaLine, Words};
use crate::refs::{FxHashMap, FxHashSet};
use crate::text::{js_hex, js_number};

/// What kind of value: an integer, a float, a reference, a pointer (managed or not); None when it is not known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum K {
    I,
    F,
    R,
    P,
}

type Kind = Option<K>;

/// A value on the stack, as HLA64 writes it.
#[derive(Clone)]
struct Expr {
    text: String,
    /// Go's levels: 6 an operand, 5.5 a unary operator, 5 * / % << >> >>> &, 4 + - | ^, 3 comparisons.
    prec: f64,
    /// Computing it has no effect (no call, store, allocation).
    pure: bool,
    kind: Kind,
    /// For x op= y, and for negating a condition: the operator and operands of a binary expression.
    op: Option<&'static str>,
    left: Option<Box<Expr>>,
    right: Option<Box<Expr>>,
    /// A variable or a constant: dup may write it twice.
    copyable: bool,
    /// The null reference.
    is_null: bool,
}

fn atom(text: String, kind: Kind, pure: bool) -> Expr {
    Expr { text, prec: 6.0, pure, kind, op: None, left: None, right: None, copyable: false, is_null: false }
}

fn copyable(mut e: Expr) -> Expr {
    e.copyable = true;
    e
}

/// `&x`, `-x`, `~x`, `new T()`: tighter than any binary operator, looser than a member access, so `(&V_0).n`.
fn unary(text: String, kind: Kind, pure: bool) -> Expr {
    Expr { prec: 5.5, ..atom(text, kind, pure) }
}

fn wrap(e: &Expr, min: f64) -> String {
    if e.prec >= min {
        e.text.clone()
    } else {
        format!("({})", e.text)
    }
}

/// A shift inside another operation gets parentheses, as the other views write them: `x + (y << 2)`.
fn operand_text(e: &Expr, min: f64) -> String {
    if matches!(e.op, Some("<<" | ">>" | ">>>")) && e.prec == 5.0 {
        format!("({})", e.text)
    } else {
        wrap(e, min)
    }
}

/// `a op b`; a comparison of comparisons keeps both in parentheses: `(a > 0) == 0`.
fn binary(left: &Expr, op: &'static str, prec: f64, right: &Expr, kind: Kind) -> Expr {
    let min = if prec == 3.0 { 4.0 } else { prec };
    let text = format!("{} {op} {}", operand_text(left, min), operand_text(right, if prec == 3.0 { 4.0 } else { prec + 1.0 }));
    Expr {
        text,
        prec,
        pure: left.pure && right.pure,
        kind,
        op: Some(op),
        left: Some(Box::new(left.clone())),
        right: Some(Box::new(right.clone())),
        copyable: false,
        is_null: false,
    }
}

/// A number as HLA64 writes it: small ones in decimal, the rest in hex.
fn num(v: i64) -> String {
    if v > -10 && v < 10 {
        v.to_string()
    } else if v < 0 {
        format!("-0x{:x}", v.unsigned_abs())
    } else {
        format!("0x{v:x}")
    }
}

/// `Number(value.toPrecision(digits))`: the number of `digits` significant digits nearest the
/// value (a tie goes up, as JavaScript picks the larger), read back as a double.
fn to_precision(value: f64, digits: usize) -> f64 {
    // An f64's exact decimal expansion ends well within 800 digits for what an f32 holds.
    let exact = format!("{:.800e}", value.abs());
    let (mantissa, exponent) = exact.split_once('e').unwrap_or((&exact, "0"));
    let mut exponent: i32 = exponent.parse().unwrap_or(0);
    let all: Vec<u8> = mantissa.bytes().filter(u8::is_ascii_digit).collect();
    let mut kept: Vec<u8> = all[..digits.min(all.len())].to_vec();
    if all.get(digits).is_some_and(|&d| d >= b'5') {
        let mut k = kept.len();
        loop {
            if k == 0 {
                kept.insert(0, b'1');
                kept.pop();
                exponent += 1;
                break;
            }
            k -= 1;
            if kept[k] == b'9' {
                kept[k] = b'0';
            } else {
                kept[k] += 1;
                break;
            }
        }
    }
    let text = format!("{}{}.{}e{exponent}", if value < 0.0 { "-" } else { "" }, kept[0] as char, String::from_utf8_lossy(&kept[1..]));
    text.parse().unwrap_or(value)
}

/// The shortest decimal that reads back as the same float (`0.1`, `1.5`, `3.4e+38`), always with a point or an exponent.
pub fn float_literal(value: f64, single: bool) -> String {
    if value.is_nan() {
        return "nan".into();
    }
    if value.is_infinite() {
        return if value > 0.0 { "inf".into() } else { "-inf".into() };
    }
    let mut text = js_number(value);
    if single {
        for digits in 1..=9 {
            let candidate = to_precision(value, digits);
            if (candidate as f32) as f64 == value {
                text = js_number(candidate);
                break;
            }
        }
    }
    if value == 0.0 && value.is_sign_negative() {
        return "-0.0".into();
    }
    if text.contains(['.', 'e']) {
        text
    } else {
        format!("{text}.0")
    }
}

/// `type.replace(/ (pinned|mod(req|opt)\([^)]*\))/g, '')`: a type without its modifiers.
fn strip_modifiers(ty: &str) -> String {
    let b = ty.as_bytes();
    let mut out = String::with_capacity(ty.len());
    let (mut i, mut copied) = (0, 0);
    while i < b.len() {
        let rest = &ty[i..];
        let end = if rest.starts_with(" pinned") {
            Some(i + 7)
        } else if rest.starts_with(" modreq(") || rest.starts_with(" modopt(") {
            rest[8..].find(')').map(|k| i + 8 + k + 1)
        } else {
            None
        };
        match end {
            Some(e) => {
                out.push_str(&ty[copied..i]);
                i = e;
                copied = e;
            }
            // On to the next character (names need not be ASCII).
            None => i += utf8_len(b[i]),
        }
    }
    out.push_str(&ty[copied..]);
    out
}

/// The kind of a type as ildasm writes it in a signature.
fn kind_of(ty: &str) -> Kind {
    if ty.is_empty() {
        return None;
    }
    let t = strip_modifiers(ty);
    if t.ends_with('&') || t.ends_with('*') {
        return Some(K::P);
    }
    if t.ends_with(']') || t == "string" || t == "object" || t.starts_with("class ") {
        return Some(K::R);
    }
    let integer = matches!(t.as_str(), "bool" | "char" | "native int" | "native uint") || {
        let n = t.strip_prefix('u').unwrap_or(&t);
        matches!(n, "int8" | "int16" | "int32" | "int64")
    };
    if integer {
        return Some(K::I);
    }
    if t == "float32" || t == "float64" {
        return Some(K::F);
    }
    None
}

/// What each conversion is called: conv.i1 is i8(x), conv.u is nuint(x).
fn conversion(m: &str) -> Option<&'static str> {
    Some(match m {
        "conv.i1" => "i8",
        "conv.u1" => "u8",
        "conv.i2" => "i16",
        "conv.u2" => "u16",
        "conv.i4" => "i32",
        "conv.u4" => "u32",
        "conv.i8" => "i64",
        "conv.u8" => "u64",
        "conv.i" => "nint",
        "conv.u" => "nuint",
        "conv.r4" => "f32",
        "conv.r8" => "f64",
        "conv.r.un" => "f64u",
        _ => return None,
    })
}

/// Loads and stores through a pointer that have a typed form: ldind.u1 reads u8[p].
fn indirect(m: &str) -> Option<&'static str> {
    Some(match m {
        "ldind.i1" | "stind.i1" => "i8",
        "ldind.u1" => "u8",
        "ldind.i2" | "stind.i2" => "i16",
        "ldind.u2" => "u16",
        "ldind.i4" | "stind.i4" => "i32",
        "ldind.u4" => "u32",
        "ldind.i8" | "stind.i8" => "i64",
        "ldind.r4" | "stind.r4" => "f32",
        "ldind.r8" | "stind.r8" => "f64",
        _ => return None,
    })
}

/// What a conversion or a typed access gives: a float for f32, f64, f64u, else an integer.
fn type_kind(ty: &str) -> Kind {
    Some(if ty.starts_with('f') { K::F } else { K::I })
}

/// The kind of what an array element load gives; the outer None when it is not one.
fn element(m: &str) -> Option<Kind> {
    Some(match m {
        "ldelem.i1" | "ldelem.u1" | "ldelem.i2" | "ldelem.u2" | "ldelem.i4" | "ldelem.u4" | "ldelem.i8" | "ldelem.i" => Some(K::I),
        "ldelem.r4" | "ldelem.r8" => Some(K::F),
        "ldelem.ref" => Some(K::R),
        "ldelem" => None,
        _ => return None,
    })
}

/// The operators of the arithmetic: the operator, its level, its word, and whether integers alone may use it.
fn binary_op(m: &str) -> Option<(&'static str, f64, &'static str, bool)> {
    Some(match m {
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
        "shr.un" => (">>>", 5.0, "shift", false),
        "ceq" => ("==", 3.0, "condition-value", false),
        "cgt" => (">", 3.0, "condition-value", false),
        "clt" => ("<", 3.0, "condition-value", false),
        _ => return None,
    })
}

/// The conditional branches, by their comparison: the operator, and whether it is unsigned.
fn branch_op(m: &str) -> Option<(&'static str, bool)> {
    Some(match m.strip_suffix(".s").unwrap_or(m) {
        "beq" => ("==", false),
        "bne.un" => ("!=", false),
        "bge" => (">=", false),
        "bgt" => (">", false),
        "ble" => ("<=", false),
        "blt" => ("<", false),
        "bge.un" => (">=u", true),
        "bgt.un" => (">u", true),
        "ble.un" => ("<=u", true),
        "blt.un" => ("<u", true),
        _ => return None,
    })
}

fn negate(op: &str) -> Option<&'static str> {
    Some(match op {
        "==" => "!=",
        "!=" => "==",
        "<" => ">=",
        ">=" => "<",
        ">" => "<=",
        "<=" => ">",
        "<u" => ">=u",
        ">=u" => "<u",
        ">u" => "<=u",
        "<=u" => ">u",
        _ => return None,
    })
}

fn integral(e: &Expr) -> bool {
    matches!(e.kind, Some(K::I | K::P))
}

fn mark(kind: char, value: &str, text: &str) -> String {
    format!("\u{1}{kind}{value}\u{2}{text}\u{3}")
}

fn is_identifier(name: &str) -> bool {
    let b = name.as_bytes();
    match b.first() {
        Some(c) if c.is_ascii_alphabetic() || *c == b'_' => b[1..].iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_'),
        _ => false,
    }
}

fn quoted(name: &str, words: &mut Words) -> String {
    if is_identifier(name) {
        return name.to_string();
    }
    words.push("quoted-name");
    format!("`{name}`")
}

/// `JSON.stringify` of UTF-16 text cut at `limit` units (with `…` when longer): lone surrogates as `\udxxx`.
fn json_units(units: &[u16], limit: usize) -> String {
    let cut = units.len() > limit;
    let units = &units[..units.len().min(limit)];
    let mut out = String::with_capacity(units.len() + 4);
    out.push('"');
    for c in char::decode_utf16(units.iter().copied()) {
        match c {
            Ok(c) => crate::lift::escape_json_char(&mut out, c),
            Err(e) => out.push_str(&format!("\\u{:04x}", e.unpaired_surrogate())),
        }
    }
    if cut {
        out.push('…');
    }
    out.push('"');
    out
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// A type as ildasm writes it, shortened: no `class`, `valuetype`, assembly, namespace or arity — `List<string>`, `Func<int32,int32>`.
pub fn short_type(text: &str) -> String {
    // /\b(?:class|valuetype) /g
    let mut a = String::with_capacity(text.len());
    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let boundary = i == 0 || !is_word_byte(b[i - 1]);
        if boundary && text[i..].starts_with("class ") {
            i += 6;
        } else if boundary && text[i..].starts_with("valuetype ") {
            i += 10;
        } else {
            let n = utf8_len(b[i]);
            a.push_str(&text[i..i + n]);
            i += n;
        }
    }
    // /\[(?:\.module )?[A-Za-z_][^\]]*\]/g
    let mut c = String::with_capacity(a.len());
    let b = a.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'[' {
            let mut j = i + 1;
            if a[j..].starts_with(".module ") && b.get(j + 8).is_some_and(|x| x.is_ascii_alphabetic() || *x == b'_') {
                j += 8;
            }
            if b.get(j).is_some_and(|x| x.is_ascii_alphabetic() || *x == b'_') {
                if let Some(k) = a[j + 1..].find(']') {
                    i = j + 1 + k + 1;
                    continue;
                }
            }
        }
        let n = utf8_len(b[i]);
        c.push_str(&a[i..i + n]);
        i += n;
    }
    // /(?:[A-Za-z_$][\w$]*\.)+(?=[A-Za-z_$'])/g
    let mut d = String::with_capacity(c.len());
    let b = c.as_bytes();
    let start = |x: u8| x.is_ascii_alphabetic() || x == b'_' || x == b'$';
    let mut i = 0;
    while i < b.len() {
        // The ends of each repetition of `ident.`, as far as they go.
        let mut ends = Vec::new();
        let mut j = i;
        while j < b.len() && start(b[j]) {
            let mut k = j + 1;
            while k < b.len() && (is_word_byte(b[k]) || b[k] == b'$') {
                k += 1;
            }
            if b.get(k) != Some(&b'.') {
                break;
            }
            j = k + 1;
            ends.push(j);
        }
        let found = ends.iter().rev().find(|&&e| b.get(e).is_some_and(|&x| start(x) || x == b'\''));
        match found {
            Some(&e) => i = e,
            None => {
                let n = utf8_len(b[i]);
                d.push_str(&c[i..i + n]);
                i += n;
            }
        }
    }
    // /`\d+/g
    let mut out = String::with_capacity(d.len());
    let b = d.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'`' && b.get(i + 1).is_some_and(u8::is_ascii_digit) {
            i += 1;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            continue;
        }
        let n = utf8_len(b[i]);
        out.push_str(&d[i..i + n]);
        i += n;
    }
    out
}

fn utf8_len(first: u8) -> usize {
    match first {
        0..=0x7f => 1,
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        _ => 4,
    }
}

/// `text.replace(/ \S+$/, '')`: without its last word, when a space comes before it.
fn without_last_word(text: &str) -> &str {
    let space = |c: char| (c.is_whitespace() && c != '\u{85}') || c == '\u{feff}';
    match text.char_indices().rev().find(|&(_, c)| space(c)) {
        Some((i, ' ')) if i + 1 < text.len() => &text[..i],
        _ => text,
    }
}

/// `text.replace(/^(explicit |instance |vararg |unmanaged \w* ?)+/, '')`.
fn without_call_prefix(mut text: &str) -> &str {
    loop {
        if let Some(rest) = text.strip_prefix("explicit ").or_else(|| text.strip_prefix("instance ")).or_else(|| text.strip_prefix("vararg ")) {
            text = rest;
        } else if let Some(rest) = text.strip_prefix("unmanaged ") {
            let n = rest.bytes().take_while(|&b| is_word_byte(b)).count();
            text = rest[n..].strip_prefix(' ').unwrap_or(&rest[n..]);
        } else {
            return text;
        }
    }
}

/* ------------------------------------------------------------------ *
 * What a program's methods hold
 * ------------------------------------------------------------------ */

/// What lifting needs beyond the program: the metadata, what the names and calls have worked out.
pub struct CilLines {
    pub(crate) md: Metadata,
    /// The body of each function of the program, in its order.
    pub(crate) bodies: Vec<MethodBody>,
    pub(crate) method_fn: FxHashMap<u32, usize>,
    pub(crate) import_by_token: FxHashMap<u32, usize>,
    pub(crate) locals: Locals,
    pub(crate) names: NamesParts,
    shapes: FxHashMap<u32, Shape>,
    enums: Option<FxHashSet<String>>,
    local_kinds: FxHashMap<usize, Vec<Kind>>,
}

impl CilLines {
    pub(crate) fn new(md: Metadata, bodies: Vec<MethodBody>, method_fn: FxHashMap<u32, usize>, import_by_token: FxHashMap<u32, usize>, locals: Locals) -> CilLines {
        let names = Names::new(&md).into_parts();
        CilLines { md, bodies, method_fn, import_by_token, locals, names, shapes: FxHashMap::default(), enums: None, local_kinds: FxHashMap::default() }
    }

    /// The HLA64 line of the instructions first..=last (one statement), or None when they cannot
    /// be written as one — then each stays an instruction.
    pub fn lift_group(&mut self, p: &CilProgram, first: usize, last: usize) -> Option<HlaLine> {
        let parts = std::mem::take(&mut self.names);
        let mut names = Names::from_parts(&self.md, parts);
        let line = lift(
            &mut Ctx {
                p,
                md: &self.md,
                bodies: &self.bodies,
                method_fn: &self.method_fn,
                import_by_token: &self.import_by_token,
                locals: &mut self.locals,
                shapes: &mut self.shapes,
                enums: &mut self.enums,
                local_kinds: &mut self.local_kinds,
                names: &mut names,
            },
            first,
            last,
        );
        self.names = names.into_parts();
        line
    }
}

struct Ctx<'a, 'n> {
    p: &'a CilProgram,
    md: &'a Metadata,
    bodies: &'a [MethodBody],
    method_fn: &'a FxHashMap<u32, usize>,
    import_by_token: &'a FxHashMap<u32, usize>,
    locals: &'a mut Locals,
    shapes: &'a mut FxHashMap<u32, Shape>,
    enums: &'a mut Option<FxHashSet<String>>,
    local_kinds: &'a mut FxHashMap<usize, Vec<Kind>>,
    names: &'a mut Names<'n>,
}

impl Ctx<'_, '_> {
    /// The enums this assembly defines, as signatures write them (`valuetype Hello.Kind`): their values are integers.
    fn is_enum(&mut self, ty: &str) -> bool {
        if self.enums.is_none() {
            let md = self.md;
            let mut found = FxHashSet::default();
            for row in 2..=md.rows(t::TYPE_DEF) {
                let (table, base) = decode_index(Coded::TypeDefOrRef, md.get(m::TYPE_DEF_EXTENDS, row));
                if table == t::TYPE_REF as i16 && md.string(md.get(m::TYPE_REF_NAME, base)) == "Enum" && md.string(md.get(m::TYPE_REF_NAMESPACE, base)) == "System" {
                    found.insert(format!("valuetype {}", self.names.type_def(row)));
                }
            }
            *self.enums = Some(found);
        }
        self.enums.as_ref().is_some_and(|e| e.contains(&strip_modifiers(ty)))
    }

    /// The kind of a type in a signature of this program: an enum it defines is an integer.
    fn kind_in(&mut self, ty: &str) -> Kind {
        kind_of(ty).or_else(|| (!ty.is_empty() && self.is_enum(ty)).then_some(K::I))
    }

    /// The kinds of a method's locals (by its index in `functions`), from its LocalVarSig.
    fn local_kinds(&mut self, fn_index: usize) -> Vec<Kind> {
        if let Some(kinds) = self.local_kinds.get(&fn_index) {
            return kinds.clone();
        }
        let token = self.bodies[fn_index].locals_token;
        let kinds: Vec<Kind> = if token != 0 {
            let types = self.names.locals(token, NO_CONTEXT);
            types.iter().map(|ty| self.kind_in(ty)).collect()
        } else {
            Vec::new()
        };
        self.local_kinds.insert(fn_index, kinds.clone());
        kinds
    }

    /// `this` is a reference in a class's method and a pointer to the value in a struct's.
    fn this_kind(&self, method: u32) -> Kind {
        let md = self.md;
        let owner = self.names.method_owner(method);
        let (table, base) = decode_index(Coded::TypeDefOrRef, md.get(m::TYPE_DEF_EXTENDS, owner));
        if table != t::TYPE_REF as i16 {
            return Some(K::R);
        }
        let name = md.string(md.get(m::TYPE_REF_NAME, base));
        Some(if md.string(md.get(m::TYPE_REF_NAMESPACE, base)) == "System" && (name == "ValueType" || name == "Enum") { K::P } else { K::R })
    }

    fn shape(&mut self, tok: u32) -> Shape {
        if let Some(&shape) = self.shapes.get(&tok) {
            return shape;
        }
        let md = self.md;
        let blob = if token_table(tok) == t::STAND_ALONE_SIG { md.blob(md.get(m::STAND_ALONE_SIG_SIGNATURE, token_row(tok))) } else { method_blob(md, tok) };
        let shape = shape_of(blob);
        self.shapes.insert(tok, shape);
        shape
    }

    /// The address of the function a method token reaches: one here, or the member of another assembly (its token).
    fn callee(&mut self, tok: u32) -> Option<f64> {
        let row = token_row(tok);
        let function = |f: Option<&usize>| f.map(|&f| self.p.functions[f].addr as f64);
        match token_table(tok) {
            t::METHOD_DEF => function(self.method_fn.get(&row)),
            t::MEMBER_REF => {
                if let Some(&k) = self.import_by_token.get(&tok) {
                    return Some(self.p.imported[k].token as f64);
                }
                let method = local_method(self.md, &self.names.method_owner, self.locals, row);
                function(self.method_fn.get(&method))
            }
            t::METHOD_SPEC => {
                let (table, row) = decode_index(Coded::MethodDefOrRef, self.md.get(m::METHOD_SPEC_METHOD, row));
                if table < 0 {
                    return None;
                }
                self.callee(token(table as u8, row))
            }
            _ => None,
        }
    }
}

/* ------------------------------------------------------------------ *
 * Lifting
 * ------------------------------------------------------------------ */

struct State<'c, 'a, 'n> {
    c: &'c mut Ctx<'a, 'n>,
    insn: CilInsn,
    /// The method's body (for reading operands the decoder does not keep).
    body: usize,
    /// The class and method whose generic parameters the line may name.
    generic: GenericContext,
    instance: bool,
    params: Vec<Option<String>>,
    arg_kinds: Vec<Kind>,
    local_kinds: Vec<Kind>,
    /// The method returns a value.
    returns: bool,
    stack: Vec<Expr>,
    out: Vec<String>,
    words: Words,
}

impl State<'_, '_, '_> {
    /// A type as the view names it: its own name, without namespace or generic arity — `Console`; a generic instance with its arguments — `List<string>`.
    fn type_name(&mut self, table: u8, row: u32) -> String {
        let md = self.c.md;
        if table == t::TYPE_DEF || table == t::TYPE_REF {
            let column = if table == t::TYPE_DEF { m::TYPE_DEF_NAME } else { m::TYPE_REF_NAME };
            let name = md.string(md.get(column, row));
            let name = strip_arity(&name);
            return quoted(name, &mut self.words);
        }
        if table == t::TYPE_SPEC {
            let blob = md.blob(md.get(m::TYPE_SPEC_SIGNATURE, row));
            let at = |k: usize| blob.get(k).copied().unwrap_or(0) as u32;
            if at(0) == 0x15 && (at(1) == 0x12 || at(1) == 0x11) {
                let value = if at(2) & 0x80 != 0 { (at(2) & 0x3f) << 8 | at(3) } else { at(2) };
                let full = short_type(&self.c.names.type_spec(row, self.generic));
                let base = match value & 3 {
                    0 => Some(t::TYPE_DEF),
                    1 => Some(t::TYPE_REF),
                    _ => None,
                };
                if let Some(base) = base {
                    // `full.slice(full.indexOf('<'))`: from the arguments on (the last character when there are none).
                    let args = match full.find('<') {
                        Some(k) => &full[k..],
                        None => full.char_indices().last().map_or("", |(k, _)| &full[k..]),
                    };
                    return format!("{}{args}", self.type_name(base, value >> 2));
                }
            }
            let text = short_type(&self.c.names.type_spec(row, self.generic));
            return quoted(&text, &mut self.words);
        }
        "?".into()
    }

    fn type_of_token(&mut self, tok: u32) -> String {
        self.type_name(token_table(tok), token_row(tok))
    }

    /// The class part of a member reference, `Console`, and the member's name.
    fn member(&mut self, tok: u32) -> (String, String) {
        let md = self.c.md;
        let (mut table, mut row) = (token_table(tok), token_row(tok));
        // A generic method's instantiation follows its name: `IsEvenInteger<float32>`.
        let mut inst = String::new();
        if table == t::METHOD_SPEC {
            let mut r = SigReader::of_blob(md, md.get(m::METHOD_SPEC_INSTANTIATION, row));
            r.byte();
            let mut args = Vec::new();
            let mut k = r.u();
            while k > 0 && !r.done() {
                args.push(short_type(&self.c.names.sig_type(&mut r, self.generic, 0)));
                k -= 1;
            }
            inst = format!("<{}>", args.join(","));
            let (target, target_row) = decode_index(Coded::MethodDefOrRef, md.get(m::METHOD_SPEC_METHOD, row));
            table = if target < 0 { 0xff } else { target as u8 };
            row = target_row;
        }
        if table == t::METHOD_DEF || table == t::FIELD {
            let owners = if table == t::METHOD_DEF { &self.c.names.method_owner } else { &self.c.names.field_owner };
            let owner = owners.get(row as usize).copied().unwrap_or(0);
            let owner = if owner > 1 { self.type_name(t::TYPE_DEF, owner) } else { String::new() };
            let column = if table == t::METHOD_DEF { m::METHOD_DEF_NAME } else { m::FIELD_NAME };
            let name = quoted(&md.string(md.get(column, row)), &mut self.words);
            return (owner, name + &inst);
        }
        let (parent, parent_row) = decode_index(Coded::MemberRefParent, md.get(m::MEMBER_REF_CLASS, row));
        let owner = if parent == t::METHOD_DEF as i16 {
            let owner = self.c.names.method_owner.get(parent_row as usize).copied().unwrap_or(0);
            self.type_name(t::TYPE_DEF, owner)
        } else if parent == t::MODULE_REF as i16 {
            String::new()
        } else if parent < 0 {
            "?".into()
        } else {
            self.type_name(parent as u8, parent_row)
        };
        let name = quoted(&md.string(md.get(m::MEMBER_REF_NAME, row)), &mut self.words);
        (owner, name + &inst)
    }

    fn qualified((owner, name): (String, String)) -> String {
        if owner.is_empty() {
            name
        } else {
            format!("{owner}::{name}")
        }
    }

    /// The kind of what a field holds.
    fn field_kind(&mut self, tok: u32) -> Kind {
        let text = self.c.names.field(tok, NO_CONTEXT);
        self.c.kind_in(without_last_word(&text))
    }

    /// The kind of what a method returns.
    fn return_kind(&mut self, tok: u32) -> Kind {
        let text = self.c.names.method(tok, NO_CONTEXT);
        // text.lastIndexOf(' ', text.indexOf('(')), then text.slice(0, that).
        let space = match text.find('(') {
            Some(paren) => text[..=paren].rfind(' ').map_or(-1, |k| k as i64),
            None => {
                if text.starts_with(' ') {
                    0
                } else {
                    -1
                }
            }
        };
        let head = if space >= 0 {
            &text[..space as usize]
        } else {
            // slice(0, -1): all but the last character.
            text.char_indices().last().map_or("", |(k, _)| &text[..k])
        };
        self.c.kind_in(without_call_prefix(head))
    }

    fn variable(&mut self, local: bool, index: i64) -> Expr {
        self.words.push("cil-local");
        let kind_at = |kinds: &[Kind]| if index >= 0 { kinds.get(index as usize).copied().flatten() } else { None };
        if local {
            return copyable(atom(mark('v', &index.to_string(), &format!("V_{index}")), kind_at(&self.local_kinds), true));
        }
        if self.instance && index == 0 {
            return copyable(atom(mark('v', "0", "this"), kind_at(&self.arg_kinds), true));
        }
        let at = if self.instance { index } else { index + 1 };
        let name = if at >= 0 { self.params.get(at as usize).cloned().flatten() } else { None };
        let text = match name {
            Some(name) => quoted(&name, &mut self.words),
            None => format!("A_{index}"),
        };
        copyable(atom(mark('v', &index.to_string(), &text), kind_at(&self.arg_kinds), true))
    }

    fn branch_targets(&self, index: usize) -> &[u32] {
        let p = self.c.p;
        match p.target_index.binary_search(&(index as u32)) {
            Ok(k) => &p.target_values[p.target_starts[k] as usize..p.target_starts[k + 1] as usize],
            Err(_) => &[],
        }
    }

    /// `IL_001f`: where an address is in its method's IL.
    fn label_name(&self, addr: f64) -> String {
        let p = self.c.p;
        let index = p.offsets.binary_search(&(addr as u32)).ok().filter(|_| addr >= 0.0 && addr.fract() == 0.0 && addr <= u32::MAX as f64);
        if let Some(f) = index.and_then(|i| function_of_index(p, i)) {
            return format!("IL_{:04x}", (addr as i64 - p.functions[f].addr as i64) as u32);
        }
        format!("L{}", js_hex(addr))
    }

    fn label_mark(&self, target: Option<u32>) -> String {
        let addr = target.and_then(|t| self.c.p.offsets.get(t as usize)).map_or(0.0, |&a| a as f64);
        mark('l', &js_number(addr), &self.label_name(addr))
    }

    fn goto_label(&mut self, index: usize) -> String {
        self.words.push("goto");
        let target = self.branch_targets(index).first().copied();
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

    /// The instruction as a function of its operands: `box<Kind>(x)`, `add.ovf(a, b)`, `sizeof<Point>()`.
    fn folded(&mut self, args: &[Expr], kind: Kind) -> Expr {
        self.words.push("cil-folded");
        let op = self.insn.op.unwrap();
        let imm = if op.operand == operand::TYPE {
            Some(self.type_of_token(self.insn.a as u32))
        } else if op.operand == operand::NONE {
            Some(String::new())
        } else {
            None
        };
        let pure = op.flags & (f::LOAD | f::STORE | f::CALL | f::TRAPS | f::THROW) == 0;
        let list: Vec<&str> = args.iter().map(|a| a.text.as_str()).collect();
        let imm = match imm {
            Some(i) if !i.is_empty() => format!("<{i}>"),
            _ => String::new(),
        };
        atom(format!("{}{imm}({})", self.insn.m, list.join(", ")), kind, pure)
    }

    /// Takes `count` values off the stack; None when it has fewer (a negative count takes none).
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

    /// The bytes of the instruction's last `size` bytes: an operand the decoder does not keep.
    fn operand_bytes(&self, size: usize) -> [u8; 8] {
        let body = &self.c.bodies[self.body];
        let end = body.code + self.insn.at as usize + self.insn.len as usize;
        let mut out = [0u8; 8];
        if let Some(bytes) = self.c.md.bytes.get(end.saturating_sub(size)..end) {
            out[..size].copy_from_slice(bytes);
        }
        out
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
        if op.flags & f::PREFIX != 0 {
            return false;
        }
        let m = self.insn.m;

        // Variables and constants: (ld|st)(loc|arg)(a?)(.0-3|.s)?
        if let Some((ld, local, address, digit)) = variable_op(m) {
            let n = digit.map_or(self.insn.a, |d| d as i64);
            let v = self.variable(local, n);
            if ld {
                if !address {
                    return self.push(v);
                }
                self.words.push("address");
                return self.push(unary(format!("&{}", v.text), Some(K::P), true));
            }
            let Some(value) = self.take1() else { return false };
            let line = self.assign(&v.text, &value);
            return self.statement(line);
        }
        if let Some(value) = ldc_i4(m) {
            let v = value.unwrap_or(self.insn.a);
            return self.push(copyable(atom(num(v), Some(K::I), true)));
        }
        match m {
            "ldc.i8" => {
                let v = i64::from_le_bytes(self.operand_bytes(8));
                return self.push(copyable(atom(num(v), Some(K::I), true)));
            }
            "ldc.r4" | "ldc.r8" => {
                self.words.push("float");
                let value = if m == "ldc.r4" { f32::from_bits(self.insn.a as u32) as f64 } else { f64::from_le_bytes(self.operand_bytes(8)) };
                return self.push(copyable(atom(float_literal(value, m == "ldc.r4"), Some(K::F), true)));
            }
            "ldnull" => {
                self.words.push("cil-new");
                let mut e = copyable(atom("null".into(), Some(K::R), true));
                e.is_null = true;
                return self.push(e);
            }
            "ldstr" => {
                let tok = self.insn.a as u32;
                if token_table(tok) != USER_STRING {
                    return false;
                }
                let units = self.c.md.user_string(token_row(tok)).unwrap_or_default();
                self.words.push("string");
                return self.push(copyable(atom(mark('s', &tok.to_string(), &json_units(&units, 80)), Some(K::R), true)));
            }
            "dup" => {
                let Some(top) = self.stack.last().filter(|e| e.copyable).cloned() else { return false };
                return self.push(top);
            }
            "pop" => {
                let Some(value) = self.take1() else { return false };
                if !value.pure && value.text.ends_with(')') {
                    return self.statement(value.text);
                }
                self.words.push("cil-pop");
                return self.statement(format!("_ = {}", value.text));
            }
            "ret" => {
                self.words.push("return");
                // ret takes the return value when the method has one: when it was made before a label, the line cannot name it.
                let values = std::mem::take(&mut self.stack);
                if values.len() != usize::from(self.returns) {
                    return false;
                }
                return self.statement(match values.first() {
                    Some(v) => format!("return {}", v.text),
                    None => "return".into(),
                });
            }
            "br" | "br.s" => {
                let line = self.goto_label(index);
                return self.statement(line);
            }
            "brtrue" | "brtrue.s" | "brfalse" | "brfalse.s" => {
                let Some(value) = self.take1() else { return false };
                self.words.push("if-goto");
                let cond = condition(&value, m.starts_with("brfalse"));
                let goto = self.goto_label(index);
                return self.statement(format!("if {cond} {{ {goto} }}"));
            }
            "switch" => {
                let value = self.take1();
                let targets = self.branch_targets(index).to_vec();
                let Some(value) = value else { return false };
                if targets.is_empty() {
                    return false;
                }
                self.words.push("switch");
                self.words.push("goto");
                let mut by_target: Vec<(u32, Vec<usize>)> = Vec::new();
                for (k, &target) in targets.iter().enumerate() {
                    match by_target.iter_mut().find(|(t, _)| *t == target) {
                        Some((_, keys)) => keys.push(k),
                        None => by_target.push((target, vec![k])),
                    }
                }
                let mut cases = Vec::new();
                for (target, keys) in &by_target {
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
                    cases.push(format!("case {} {{ goto {} }}", ranges.join(", "), self.label_mark(Some(*target))));
                }
                return self.statement(format!("switch {} {{ {} }}", value.text, cases.join(" ")));
            }
            _ => {}
        }
        if let Some((sym, unsigned)) = branch_op(m) {
            let Some((a, b)) = self.take2() else { return false };
            // Unsigned between integers only: between floats the .un forms mean "or unordered".
            if unsigned && !(integral(&a) && integral(&b)) {
                return false;
            }
            self.words.push("if-goto");
            if unsigned {
                self.words.push("unsigned-compare");
            }
            let cond = binary(&a, sym, 3.0, &b, Some(K::I)).text;
            let goto = self.goto_label(index);
            return self.statement(format!("if {cond} {{ {goto} }}"));
        }

        // Fields, calls, objects.
        let tok = self.insn.a as u32;
        match m {
            "ldfld" | "ldflda" => {
                let Some(obj) = self.take1() else { return false };
                self.words.push("cil-member");
                let name = self.member(tok).1;
                let text = format!("{}.{}", wrap(&obj, 6.0), mark('g', &tok.to_string(), &name));
                if m == "ldflda" {
                    self.words.push("address");
                    return self.push(unary(format!("&{text}"), Some(K::P), true));
                }
                let kind = self.field_kind(tok);
                return self.push(atom(text, kind, obj.pure));
            }
            "ldsfld" | "ldsflda" => {
                self.words.push("cil-member");
                let who = self.member(tok);
                let text = mark('g', &tok.to_string(), &Self::qualified(who));
                if m == "ldsflda" {
                    self.words.push("address");
                    return self.push(unary(format!("&{text}"), Some(K::P), true));
                }
                let kind = self.field_kind(tok);
                return self.push(atom(text, kind, true));
            }
            "stfld" => {
                let Some((obj, value)) = self.take2() else { return false };
                self.words.push("cil-member");
                let name = self.member(tok).1;
                let dest = format!("{}.{}", wrap(&obj, 6.0), mark('g', &tok.to_string(), &name));
                let line = self.assign(&dest, &value);
                return self.statement(line);
            }
            "stsfld" => {
                let Some(value) = self.take1() else { return false };
                self.words.push("cil-member");
                let who = self.member(tok);
                let dest = mark('g', &tok.to_string(), &Self::qualified(who));
                let line = self.assign(&dest, &value);
                return self.statement(line);
            }
            "call" | "callvirt" | "newobj" => {
                let shape = self.c.shape(tok);
                let count = shape.params as i64 + i64::from(shape.instance && m != "newobj");
                let Some(args) = self.take(count) else { return false };
                let callee = self.c.callee(tok).unwrap_or(-1.0);
                let (owner, name) = self.member(tok);
                let link = |text: &str| mark('f', &js_number(callee), text);
                let list = |args: &[Expr]| args.iter().map(|a| a.text.as_str()).collect::<Vec<_>>().join(", ");
                let text = if m == "newobj" {
                    self.words.push("cil-new");
                    format!("new {}({})", link(&owner), list(&args))
                } else if m == "callvirt" && shape.instance {
                    self.words.push("cil-member");
                    format!("{}.{}({})", wrap(&args[0], 6.0), link(&name), list(&args[1..]))
                } else {
                    self.words.push("cil-member");
                    format!("{}({})", link(&Self::qualified((owner, name))), list(&args))
                };
                if m == "newobj" {
                    return self.push(unary(text, Some(K::R), false));
                }
                if shape.returns {
                    let kind = self.return_kind(tok);
                    return self.push(atom(text, kind, false));
                }
                return self.statement(text);
            }
            "ldtoken" => {
                self.words.push("cil-folded");
                let table = token_table(tok);
                let what = if matches!(table, t::FIELD | t::MEMBER_REF | t::METHOD_DEF | t::METHOD_SPEC) { Self::qualified(self.member(tok)) } else { self.type_of_token(tok) };
                return self.push(atom(format!("ldtoken<{what}>()"), None, true));
            }
            "ldftn" => {
                self.words.push("address");
                let callee = self.c.callee(tok).unwrap_or(-1.0);
                let who = Self::qualified(self.member(tok));
                return self.push(unary(format!("&{}", mark('f', &js_number(callee), &who)), Some(K::P), true));
            }
            "newarr" => {
                let Some(length) = self.take1() else { return false };
                self.words.push("cil-new");
                let ty = self.type_of_token(tok);
                return self.push(unary(format!("new {ty}[{}]", length.text), Some(K::R), false));
            }
            "ldlen" => {
                let Some(array) = self.take1() else { return false };
                self.words.push("cil-array");
                return self.push(atom(format!("len({})", array.text), Some(K::I), array.pure));
            }
            "ldelema" => {
                let Some((array, at)) = self.take2() else { return false };
                self.words.push("cil-array");
                self.words.push("address");
                return self.push(unary(format!("&{}[{}]", wrap(&array, 6.0), at.text), Some(K::P), true));
            }
            _ => {}
        }
        if let Some(kind) = element(m) {
            let Some((array, at)) = self.take2() else { return false };
            self.words.push("cil-array");
            return self.push(atom(format!("{}[{}]", wrap(&array, 6.0), at.text), kind, array.pure && at.pure));
        }
        if m.starts_with("stelem") {
            let Some(mut v) = self.take(3) else { return false };
            if v.len() < 3 {
                return false;
            }
            let value = v.pop().unwrap();
            let at = v.pop().unwrap();
            let array = v.pop().unwrap();
            self.words.push("cil-array");
            let line = self.assign(&format!("{}[{}]", wrap(&array, 6.0), at.text), &value);
            return self.statement(line);
        }
        if let Some(ty) = indirect(m) {
            self.words.push("typed-memory");
            if m.starts_with("ld") {
                let Some(pointer) = self.take1() else { return false };
                return self.push(atom(format!("{ty}[{}]", pointer.text), type_kind(ty), pointer.pure));
            }
            let Some((pointer, value)) = self.take2() else { return false };
            return self.statement(format!("{ty}[{}] = {}", pointer.text, value.text));
        }

        // Numbers.
        if let Some((sym, prec, word, integers)) = binary_op(m) {
            let Some((a, b)) = self.take2() else { return false };
            if integers && !(a.kind == Some(K::I) && b.kind == Some(K::I)) {
                let e = self.folded(&[a, b], None);
                return self.push(e);
            }
            self.words.push(word);
            let kind = if prec == 3.0 {
                Some(K::I)
            } else if a.kind == Some(K::F) || b.kind == Some(K::F) {
                Some(K::F)
            } else if a.kind == Some(K::P) || b.kind == Some(K::P) {
                Some(K::P)
            } else if a.kind == Some(K::I) && b.kind == Some(K::I) {
                Some(K::I)
            } else {
                None
            };
            return self.push(binary(&a, sym, prec, &b, kind));
        }
        if m == "cgt.un" || m == "clt.un" {
            let Some((a, b)) = self.take2() else { return false };
            // cgt.un against null is the test a reference is not null; between integers an unsigned comparison.
            if m == "cgt.un" && b.is_null && a.kind == Some(K::R) {
                self.words.push("condition-value");
                return self.push(binary(&a, "!=", 3.0, &b, Some(K::I)));
            }
            if !(integral(&a) && integral(&b)) {
                let e = self.folded(&[a, b], Some(K::I));
                return self.push(e);
            }
            self.words.push("condition-value");
            self.words.push("unsigned-compare");
            return self.push(binary(&a, if m == "cgt.un" { ">u" } else { "<u" }, 3.0, &b, Some(K::I)));
        }
        if m == "div.un" || m == "rem.un" {
            let Some((a, b)) = self.take2() else { return false };
            self.words.push("udiv");
            return self.push(atom(format!("{}({}, {})", if m == "div.un" { "udiv" } else { "urem" }, a.text, b.text), a.kind, a.pure && b.pure));
        }
        if m == "neg" || m == "not" {
            let Some(a) = self.take1() else { return false };
            self.words.push("arith");
            return self.push(unary(format!("{}{}", if m == "neg" { "-" } else { "~" }, wrap(&a, 6.0)), a.kind, a.pure));
        }
        if let Some(conv) = conversion(m) {
            let Some(a) = self.take1() else { return false };
            self.words.push("cil-convert");
            return self.push(atom(format!("{conv}({})", a.text), type_kind(conv), a.pure));
        }

        // Anything else with a known stack effect and no branch: the instruction as a function of its operands.
        if op.flags & (f::BRANCH | f::END) != 0 && m != "throw" {
            return false;
        }
        if op.operand != operand::NONE && op.operand != operand::TYPE {
            return false;
        }
        // The effect, as the TypeScript's Effects.of() gives it for these operands.
        let (pops, pushes) = (op.pop as i64, op.push as i64);
        if pushes > 1 {
            return false;
        }
        let Some(args) = self.take(pops) else { return false };
        let kind = match m {
            "isinst" | "castclass" | "box" => Some(K::R),
            "sizeof" => Some(K::I),
            _ => None,
        };
        let value = self.folded(&args, kind);
        if pushes != 0 {
            self.push(value)
        } else {
            self.statement(value.text)
        }
    }
}

/// A condition for `if c { … }`: a branch on false negates it where that means exactly the opposite.
fn condition(value: &Expr, negate_it: bool) -> String {
    if !negate_it {
        return value.text.clone();
    }
    if let (Some(op), Some(left), Some(right)) = (value.op, &value.left, &value.right) {
        if let Some(flipped) = negate(op) {
            if value.prec == 3.0 {
                let flips = op == "==" || op == "!=" || (integral(left) && integral(right)) || op.ends_with('u');
                if flips {
                    return binary(left, flipped, 3.0, right, Some(K::I)).text;
                }
            }
        }
    }
    format!("{} == {}", wrap(value, 4.0), if value.kind == Some(K::R) { "null" } else { "0" })
}

/// `name.replace(/`\d+$/, '')`: a type's name without its generic arity.
fn strip_arity(name: &str) -> &str {
    let digits = name.bytes().rev().take_while(u8::is_ascii_digit).count();
    if digits > 0 && name.as_bytes().get(name.len() - digits - 1) == Some(&b'`') {
        &name[..name.len() - digits - 1]
    } else {
        name
    }
}

/// `^(ld|st)(loc|arg)(a?)(?:\.([0-3])|\.s)?$`: load or store, local or argument, its address, its number.
fn variable_op(m: &str) -> Option<(bool, bool, bool, Option<u8>)> {
    let (ld, rest) = match (m.strip_prefix("ld"), m.strip_prefix("st")) {
        (Some(r), _) => (true, r),
        (_, Some(r)) => (false, r),
        _ => return None,
    };
    let (local, rest) = match (rest.strip_prefix("loc"), rest.strip_prefix("arg")) {
        (Some(r), _) => (true, r),
        (_, Some(r)) => (false, r),
        _ => return None,
    };
    let (address, rest) = match rest.strip_prefix('a') {
        Some(r) => (true, r),
        None => (false, rest),
    };
    match rest {
        "" | ".s" => Some((ld, local, address, None)),
        _ => {
            let d = rest.strip_prefix('.')?;
            match d.as_bytes() {
                [c @ b'0'..=b'3'] => Some((ld, local, address, Some(c - b'0'))),
                _ => None,
            }
        }
    }
}

/// `^ldc\.i4(?:\.(m1|\d))?(?:\.s)?$`: Some(the constant it names, or None for its operand's).
fn ldc_i4(m: &str) -> Option<Option<i64>> {
    let rest = m.strip_prefix("ldc.i4")?;
    let (value, rest) = if let Some(r) = rest.strip_prefix(".m1") {
        (Some(-1), r)
    } else if let [b'.', c @ b'0'..=b'9', ..] = rest.as_bytes() {
        (Some((c - b'0') as i64), &rest[2..])
    } else {
        (None, rest)
    };
    matches!(rest, "" | ".s").then_some(value)
}

/// The function holding an instruction, or None.
fn function_of_index(p: &CilProgram, index: usize) -> Option<usize> {
    let k = p.functions.partition_point(|f| f.first as usize <= index).checked_sub(1)?;
    let f = &p.functions[k];
    (index < (f.first + f.count) as usize).then_some(k)
}

fn lift(c: &mut Ctx, first: usize, last: usize) -> Option<HlaLine> {
    let fn_index = function_of_index(c.p, first)?;
    let method = c.bodies[fn_index].method;
    let md = c.md;
    let sig_blob = md.blob(md.get(m::METHOD_DEF_SIGNATURE, method));
    let instance = sig_blob.first().is_some_and(|b| b & 0x20 != 0);
    let generic = GenericContext { ty: c.names.method_owner(method), method };
    let params = c.names.param_names(method);
    let sig = c.names.method_def_sig(method);
    let mut arg_kinds: Vec<Kind> = if instance { vec![c.this_kind(method)] } else { Vec::new() };
    for ty in &sig.params {
        let kind = c.kind_in(ty);
        arg_kinds.push(kind);
    }
    let local_kinds = c.local_kinds(fn_index);
    let mut s = State {
        c,
        insn: CilInsn::default(),
        body: fn_index,
        generic,
        instance,
        params,
        arg_kinds,
        local_kinds,
        returns: sig.ret != "void",
        stack: Vec::new(),
        out: Vec::new(),
        words: Vec::new(),
    };
    for i in first..=last {
        let body = &s.c.bodies[fn_index];
        let at = body.code as i64 + s.c.p.offsets[i] as i64 - (body.rva as i64 + body.header_size as i64);
        if at < body.code as i64 || at as usize >= body.code + body.size {
            return None;
        }
        decode_at(&s.c.md.bytes, body.code, at as usize, body.code + body.size, &mut s.insn);
        if !s.step(i) {
            return None;
        }
    }
    if !s.stack.is_empty() || s.out.len() != 1 {
        return None;
    }
    Some(HlaLine { text: s.out.pop().unwrap(), words: unique(s.words), comment: None })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_of_types() {
        let kinds: Vec<Kind> = [
            "int32",
            "float64",
            "class [System.Runtime]System.String",
            "uint8&",
            "valuetype X",
            "native uint",
            "int32 modreq([System.Runtime]System.Runtime.CompilerServices.IsVolatile)",
        ]
        .iter()
        .map(|t| kind_of(t))
        .collect();
        assert_eq!(kinds, [Some(K::I), Some(K::F), Some(K::R), Some(K::P), None, Some(K::I), Some(K::I)]);
        assert_eq!(strip_modifiers("valuetype Ns.Тип pinned"), "valuetype Ns.Тип");
    }

    #[test]
    fn float_literals() {
        let f32 = |v: f32| v as f64;
        assert_eq!(
            [
                float_literal(1.0, false),
                float_literal(f32(0.1), true),
                float_literal(f32(6.2831855), true),
                float_literal(f64::NAN, false),
                float_literal(-0.0, true),
                float_literal(f32(3.4e38), true),
                float_literal(f32(1e-7), true)
            ],
            ["1.0", "0.1", "6.2831855", "nan", "-0.0", "3.4e+38", "1e-7"]
        );
        // A tie at the precision that reads back goes up, as toPrecision rounds it: 0.5 to one digit is 0.5, 2.5 stays 2.5.
        assert_eq!([to_precision(2.5, 1), to_precision(0.125, 2), to_precision(-2.5, 1)], [3.0, 0.13, -3.0]);
    }

    #[test]
    fn short_types() {
        assert_eq!(
            short_type("class [System.Collections]System.Collections.Generic.List`1<valuetype [System.Runtime]System.ValueTuple`2<int32,string>>"),
            "List<ValueTuple<int32,string>>"
        );
        assert_eq!(short_type("class [.module Other.dll]Ns.Outer/Inner[]"), "Outer/Inner[]");
        assert_eq!(short_type("a.b.0"), "b.0");
        assert_eq!(short_type("subclass x"), "subclass x");
    }
}
