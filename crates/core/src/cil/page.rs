//! What the page shows of a .NET assembly besides the listing's structure: an instruction as
//! ildasm prints it (with the method its operand calls and the field it names), a method's card
//! and its header, what a method's code calls and loads, the Assembly page (the manifest, the
//! metadata streams and tables, the resources, the types) and the References page (the
//! assemblies referenced, the types forwarded). Everything here is text as the TypeScript made
//! it, so the page only lays it out; a port of what src/app/cil.ts and src/core/cil/decode.ts
//! read from the metadata.

use super::decode::{decode_at, CilInsn};
use super::hla::CilLines;
use super::metadata::{
    self as m, compressed, decode_index, table as t, table_name, token, token_row, token_table, utf8, Clause, Coded, Metadata, MethodBody, CLI_FLAGS, USER_STRING,
};
use super::names::{proper_local_name, proper_name, GenericContext, Names, NO_CONTEXT};
use super::opcodes::{f, operand as o};
use super::program::{local_method, CilProgram, Locals};
use crate::refs::FxHashMap;

/* ------------------------------------------------------------------ *
 * Numbers as JavaScript writes them
 * ------------------------------------------------------------------ */

/// The exact decimal digits of a finite, non-zero magnitude, and the power of ten of the first:
/// `v = d0.d1d2… × 10^exp`. A double has at most 767 significant digits; Rust writes them all.
fn exact_digits(v: f64) -> (Vec<u8>, i32) {
    let text = format!("{:.1100e}", v.abs());
    let (mantissa, exp) = text.split_once('e').unwrap_or((&text, "0"));
    let mut digits: Vec<u8> = mantissa.bytes().filter(u8::is_ascii_digit).map(|b| b - b'0').collect();
    while digits.len() > 1 && digits.last() == Some(&0) {
        digits.pop();
    }
    (digits, exp.parse().unwrap_or(0))
}

/// The first `n` digits, rounded as JavaScript rounds (on the exact value, a tie up): the digits
/// and how much the exponent grew (1 when 9.99… became 10).
fn round_digits(digits: &[u8], n: usize) -> (Vec<u8>, i32) {
    let mut out: Vec<u8> = digits.iter().copied().take(n).collect();
    out.resize(n, 0);
    if digits.get(n).is_some_and(|&d| d >= 5) {
        let mut k = n;
        loop {
            if k == 0 {
                out.insert(0, 1);
                out.truncate(n.max(1));
                return (out, 1);
            }
            k -= 1;
            if out[k] == 9 {
                out[k] = 0;
            } else {
                out[k] += 1;
                break;
            }
        }
    }
    (out, 0)
}

/// `Number.prototype.toExponential(n - 1)` of a magnitude: n digits and the exponent.
fn to_exponential(v: f64, n: usize) -> (Vec<u8>, i32) {
    let (digits, exp) = exact_digits(v);
    let (rounded, grew) = round_digits(&digits, n);
    (rounded, exp + grew)
}

/// `Number.prototype.toFixed(f)` of a magnitude below 10^21.
fn to_fixed(v: f64, f: usize) -> String {
    let (digits, exp) = exact_digits(v);
    // The digits that stay: those down to 10^-f.
    let keep = exp + 1 + f as i32;
    let number: Vec<u8> = if keep < 0 {
        vec![0]
    } else if keep == 0 {
        vec![if digits[0] >= 5 { 1 } else { 0 }]
    } else {
        let (rounded, grew) = round_digits(&digits, keep as usize);
        if grew == 1 {
            let mut r = rounded;
            r.push(0);
            r
        } else {
            rounded
        }
    };
    let mut text: String = number.iter().map(|d| (b'0' + d) as char).collect();
    if f == 0 {
        return text;
    }
    if text.len() < f + 1 {
        text = format!("{}{text}", "0".repeat(f + 1 - text.len()));
    }
    let point = text.len() - f;
    format!("{}.{}", &text[..point], &text[point..])
}

/// Floating point as ildasm writes it (C's `%.8g` / `%.17g`), as the page's TypeScript worked it
/// out with JavaScript's `toExponential` and `toFixed`.
pub fn g_format(value: f64, digits: usize) -> String {
    if value == 0.0 {
        return if value.is_sign_negative() { "-0.0".into() } else { "0.0".into() };
    }
    let sign = if value < 0.0 { "-" } else { "" };
    let (mantissa, exp) = to_exponential(value, digits);
    if exp < -4 || exp >= digits as i32 {
        let mut m: String = String::new();
        m.push((b'0' + mantissa[0]) as char);
        if mantissa.len() > 1 {
            m.push('.');
            m.extend(mantissa[1..].iter().map(|d| (b'0' + d) as char));
            while m.ends_with('0') {
                m.pop();
            }
            if m.ends_with('.') {
                m.pop();
            }
        }
        return format!("{sign}{m}e{}{:02}", if exp < 0 { '-' } else { '+' }, exp.abs());
    }
    let mut fixed = to_fixed(value, (digits as i32 - 1 - exp).max(0) as usize);
    if fixed.contains('.') {
        while fixed.ends_with('0') {
            fixed.pop();
        }
        if fixed.ends_with('.') {
            fixed.pop();
        }
    }
    format!("{sign}{fixed}")
}

/* ------------------------------------------------------------------ *
 * Operands
 * ------------------------------------------------------------------ */

/// `IL_001f`: an offset in a method's IL.
pub fn label(offset: i64) -> String {
    format!("IL_{:04x}", offset as u32)
}

/// Characters ildasm writes with a backslash in a string it can print as text (`?`, so that no C trigraph is read).
fn escape(c: u16) -> Option<&'static str> {
    Some(match c {
        9 => "\\t",
        10 => "\\n",
        13 => "\\r",
        34 => "\\\"",
        63 => "\\?",
        92 => "\\\\",
        _ => return None,
    })
}

/// Is the string printable as a quoted literal (ASCII and the escapes above)?
pub fn plain_string(text: &[u16]) -> bool {
    text.iter().all(|&c| c < 0x7f && (c >= 0x20 || escape(c).is_some()))
}

/// ldstr's operand: `"text"` with escapes, or `bytearray (…)` with the UTF-16 bytes.
pub fn string_text(text: &[u16]) -> String {
    if plain_string(text) {
        let mut out = String::from("\"");
        for &c in text {
            match escape(c) {
                Some(e) => out.push_str(e),
                None => out.push(c as u8 as char),
            }
        }
        out.push('"');
        return out;
    }
    let bytes: Vec<String> = text.iter().flat_map(|&c| [format!("{:02X}", c & 0xff), format!("{:02X}", c >> 8)]).collect();
    format!("bytearray ({})", bytes.join(" "))
}

/// What printing an operand needs to know of the method it is in.
pub struct MethodContext {
    pub generic: GenericContext,
    /// The method has `this`: argument 0 is it.
    pub instance: bool,
    /// Parameter names by sequence (1 = the first parameter).
    pub params: Vec<Option<String>>,
}

pub fn method_context(md: &Metadata, names: &Names, method: u32) -> MethodContext {
    let sig = md.blob(md.get(m::METHOD_DEF_SIGNATURE, method));
    MethodContext { generic: GenericContext { ty: names.method_owner(method), method }, instance: sig.first().is_some_and(|b| b & 0x20 != 0), params: names.param_names(method) }
}

/// The name of an argument as ildasm writes it: its parameter's name, `A_n` when it has none; `this` stays 0.
fn arg_name(ctx: &MethodContext, index: i64) -> String {
    if ctx.instance && index == 0 {
        return "0".into();
    }
    let seq = if ctx.instance { index } else { index + 1 };
    match usize::try_from(seq).ok().and_then(|s| ctx.params.get(s)).and_then(|n| n.as_deref()) {
        Some(name) if !name.is_empty() => proper_local_name(name),
        _ => format!("A_{index}"),
    }
}

/// The bytes at the end of an instruction (its floating-point or 64-bit operand).
fn tail(bytes: &[u8], end: usize, size: usize) -> &[u8] {
    let end = end.min(bytes.len());
    &bytes[end.saturating_sub(size)..end]
}

/// The operand of an instruction as ildasm prints it; `end` is where the instruction ends in the file.
pub fn operand_text(md: &Metadata, names: &mut Names, insn: &CilInsn, ctx: &MethodContext, end: usize) -> String {
    let Some(op) = insn.op else { return format!("0x{:02X}", insn.a) };
    let a = insn.a;
    match op.operand {
        o::NONE => String::new(),
        o::VAR8 | o::VAR16 => {
            if op.name.contains("arg") {
                arg_name(ctx, a)
            } else {
                format!("V_{a}")
            }
        }
        o::I8 | o::U8 => a.to_string(),
        o::I32 => format!("0x{:x}", a as u32),
        o::I64 => {
            let b = tail(&md.bytes, end, 8);
            let mut raw = [0u8; 8];
            raw[8 - b.len()..].copy_from_slice(b);
            format!("0x{:x}", u64::from_le_bytes(raw))
        }
        o::R4 | o::R8 => {
            let size = if op.operand == o::R4 { 4 } else { 8 };
            let b = tail(&md.bytes, end, size);
            let value = if size == 4 { f32::from_le_bytes([b[0], b[1], b[2], b[3]]) as f64 } else { f64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]) };
            if value.is_finite() {
                g_format(value, if size == 4 { 8 } else { 17 })
            } else {
                format!("({})", b.iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(" "))
            }
        }
        o::BR8 | o::BR32 => label(a),
        o::SWITCH => format!("( {})", insn.targets.iter().map(|&t| label(t)).collect::<Vec<_>>().join(", ")),
        o::STRING => {
            let tok = a as u32;
            match (token_table(tok) == USER_STRING).then(|| md.user_string(token_row(tok))).flatten() {
                Some(text) => string_text(&text),
                None => format!("0x{tok:x}"),
            }
        }
        o::METHOD => names.method(a as u32, ctx.generic),
        o::FIELD => names.field(a as u32, ctx.generic),
        o::TYPE => names.type_token(a as u32, ctx.generic),
        o::TOKEN => names.token(a as u32, ctx.generic),
        o::SIG => {
            if token_table(a as u32) == t::STAND_ALONE_SIG {
                names.standalone(a as u32, ctx.generic)
            } else {
                format!("0x{:x}", a as u32)
            }
        }
        _ => String::new(),
    }
}

/// An instruction as one line of ildasm's text: `ldstr      "hello"`.
pub fn insn_text(md: &Metadata, names: &mut Names, insn: &CilInsn, ctx: &MethodContext, end: usize) -> String {
    let operand = operand_text(md, names, insn, ctx, end);
    if insn.op.is_none() {
        return format!(".byte {operand}");
    }
    if operand.is_empty() {
        insn.m.to_string()
    } else {
        format!("{:<10} {operand}", insn.m)
    }
}

/// The bytes of an instruction as hex: `72 25 00 00 70`, the first `max` of them.
pub fn bytes_text(bytes: &[u8], at: usize, len: usize, max: usize) -> String {
    let start = at.min(bytes.len());
    let shown = &bytes[start..(at + len.min(max)).min(bytes.len())];
    let mut out = shown.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ");
    if len > max {
        out.push_str(" …");
    }
    out
}

/* ------------------------------------------------------------------ *
 * The page's questions
 * ------------------------------------------------------------------ */

/// What the page asks of an assembly, over the metadata the session keeps.
pub struct Page<'a> {
    pub(crate) p: &'a CilProgram,
    pub(crate) md: &'a Metadata,
    pub(crate) bodies: &'a [MethodBody],
    pub(crate) method_fn: &'a FxHashMap<u32, usize>,
    pub(crate) import_by_token: &'a FxHashMap<u32, usize>,
    pub(crate) locals: &'a mut Locals,
    pub(crate) names: Names<'a>,
}

/// An instruction for a row or the details.
pub struct InsnView {
    pub insn: CilInsn,
    pub operand: String,
    pub text: String,
    pub file_offset: i64,
    pub bytes5: String,
    pub bytes24: String,
    /// What a method operand reaches: a function here (its address) or a member of another assembly (its token).
    pub callee: Option<f64>,
    /// The function it reaches, by its number (None for a member of another assembly).
    pub callee_fn: Option<usize>,
    /// A #US string's text (ldstr), and whether ildasm writes it as text.
    pub string: Option<Vec<u16>>,
    /// The field a field operand (or ldtoken's) names, as ildasm writes it.
    pub field: Option<String>,
    /// The table of a token operand: `MethodDef`, `#US`.
    pub token_kind: String,
}

/// A method's card and header.
pub struct MethodView {
    pub token: u32,
    pub attributes: String,
    pub rva: u32,
    pub size: usize,
    pub fat: bool,
    pub max_stack: u32,
    pub init_locals: bool,
    pub locals: Vec<String>,
    /// Each clause, with its text as ILAsm writes it and what it catches (a type, or `object`).
    pub clauses: Vec<(Clause, String, String)>,
    /// `static int32 (string[] args)`, for the row of its header.
    pub signature: String,
    /// The parameters of its HLA64 header (name, type) and its return type.
    pub params: Vec<(String, String)>,
    pub ret: String,
}

const METHOD_ACCESS: [&str; 8] = ["privatescope", "private", "famandassem", "assembly", "family", "famorassem", "public", ""];
const METHOD_FLAGS: [(u32, &str); 9] = [
    (0x10, "static"),
    (0x20, "final"),
    (0x40, "virtual"),
    (0x80, "hidebysig"),
    (0x100, "newslot"),
    (0x400, "abstract"),
    (0x800, "specialname"),
    (0x2000, "pinvokeimpl"),
    (0x1000, "rtspecialname"),
];
const IMPL_FLAGS: [(u32, &str); 8] = [
    (0x8, "noinlining"),
    (0x40, "nooptimization"),
    (0x100, "aggressiveinlining"),
    (0x200, "aggressiveoptimization"),
    (0x20, "synchronized"),
    (0x80, "preservesig"),
    (0x1000, "internalcall"),
    (0x2000, "async"),
];
const TYPE_VISIBILITY: [&str; 8] = ["private", "public", "nested public", "nested private", "nested family", "nested assembly", "nested famandassem", "nested famorassem"];

const METHOD_DEF_IMPL_FLAGS: m::Col = (t::METHOD_DEF, 1);
const CUSTOM_ATTRIBUTE_PARENT: m::Col = (t::CUSTOM_ATTRIBUTE, 0);
const CUSTOM_ATTRIBUTE_TYPE: m::Col = (t::CUSTOM_ATTRIBUTE, 1);
const CUSTOM_ATTRIBUTE_VALUE: m::Col = (t::CUSTOM_ATTRIBUTE, 2);
const MODULE_NAME: m::Col = (t::MODULE, 1);
const MODULE_MVID: m::Col = (t::MODULE, 2);
const ASSEMBLY_PUBLIC_KEY: m::Col = (t::ASSEMBLY, 6);
const ASSEMBLY_NAME: m::Col = (t::ASSEMBLY, 7);
const ASSEMBLY_CULTURE: m::Col = (t::ASSEMBLY, 8);
const ASSEMBLY_REF_KEY: m::Col = (t::ASSEMBLY_REF, 5);
const ASSEMBLY_REF_CULTURE: m::Col = (t::ASSEMBLY_REF, 7);
const FILE_NAME: m::Col = (t::FILE, 1);
const EXPORTED_TYPE_NAME: m::Col = (t::EXPORTED_TYPE, 2);
const EXPORTED_TYPE_NAMESPACE: m::Col = (t::EXPORTED_TYPE, 3);
const EXPORTED_TYPE_IMPLEMENTATION: m::Col = (t::EXPORTED_TYPE, 4);
const RESOURCE_FLAGS: m::Col = (t::MANIFEST_RESOURCE, 1);
const RESOURCE_NAME: m::Col = (t::MANIFEST_RESOURCE, 2);
const RESOURCE_IMPLEMENTATION: m::Col = (t::MANIFEST_RESOURCE, 3);

/// `1.2.3.4`: the version of the Assembly (`table` 0x20, its columns from 1) or an AssemblyRef (0x23, from 0).
fn version(md: &Metadata, table: u8, row: u32) -> String {
    let first = if table == t::ASSEMBLY { 1 } else { 0 };
    (0..4).map(|k| md.get((table, first + k), row).to_string()).collect::<Vec<_>>().join(".")
}

/// The public key token of an assembly reference: the token itself, or a full key shown short.
fn key_text(blob: &[u8]) -> String {
    if blob.is_empty() {
        return String::new();
    }
    let hexed: String = blob.iter().map(|b| format!("{b:02x}")).collect();
    if blob.len() == 8 {
        hexed
    } else {
        format!("{}… ({} B)", &hexed[..16], blob.len())
    }
}

/// The function holding an instruction, or None.
fn function_of_index(p: &CilProgram, index: usize) -> Option<usize> {
    let k = p.functions.partition_point(|f| f.first as usize <= index).checked_sub(1)?;
    let f = &p.functions[k];
    (index < (f.first + f.count) as usize).then_some(k)
}

impl Page<'_> {
    /// The address of what a method token reaches: a function here, or the member of another assembly (its token).
    pub fn callee(&mut self, tok: u32) -> Option<f64> {
        self.callee_of(tok).map(|(addr, _)| addr)
    }

    /// What a method token reaches: its address, and the function's number when it is one here.
    fn callee_of(&mut self, tok: u32) -> Option<(f64, Option<usize>)> {
        let row = token_row(tok);
        let function = |p: &CilProgram, f: Option<&usize>| f.map(|&f| (p.functions[f].addr as f64, Some(f)));
        match token_table(tok) {
            t::METHOD_DEF => function(self.p, self.method_fn.get(&row)),
            t::MEMBER_REF => {
                if let Some(&k) = self.import_by_token.get(&tok) {
                    return Some((self.p.imported[k].token as f64, None));
                }
                let method = local_method(self.md, &self.names.method_owner, self.locals, row);
                function(self.p, self.method_fn.get(&method))
            }
            t::METHOD_SPEC => {
                let (table, row) = decode_index(Coded::MethodDefOrRef, self.md.get(m::METHOD_SPEC_METHOD, row));
                if table < 0 {
                    return None;
                }
                self.callee_of(token(table as u8, row))
            }
            _ => None,
        }
    }

    /// Where an instruction is in the file, and its body.
    fn place(&self, index: usize) -> Option<(usize, &MethodBody, usize)> {
        let f = function_of_index(self.p, index)?;
        let body = &self.bodies[f];
        let offset = body.code as i64 + (self.p.offsets[index] as i64 - (body.rva as i64 + body.header_size as i64));
        Some((f, body, offset.max(0) as usize))
    }

    pub fn insn(&mut self, index: usize) -> Option<InsnView> {
        let (_, body, at) = self.place(index)?;
        let (code, size, method) = (body.code, body.size, body.method);
        let file_offset = body.code as i64 + (self.p.offsets[index] as i64 - (body.rva as i64 + body.header_size as i64));
        let mut insn = CilInsn::default();
        decode_at(&self.md.bytes, code, at, code + size, &mut insn);
        let ctx = method_context(self.md, &self.names, method);
        let end = at + insn.len as usize;
        let operand = operand_text(self.md, &mut self.names, &insn, &ctx, end);
        let text = if insn.op.is_none() {
            format!(".byte {operand}")
        } else if operand.is_empty() {
            insn.m.to_string()
        } else {
            format!("{:<10} {operand}", insn.m)
        };
        let tok = insn.a as u32;
        let kind = insn.op.map(|op| op.operand);
        let (callee, callee_fn) = match kind {
            Some(o::METHOD) => self.callee_of(tok).map_or((None, None), |(addr, f)| (Some(addr), f)),
            _ => (None, None),
        };
        let string = (kind == Some(o::STRING) && token_table(tok) == USER_STRING).then(|| self.md.user_string(token_row(tok))).flatten();
        let is_field =
            kind == Some(o::FIELD) || (kind == Some(o::TOKEN) && (token_table(tok) == t::FIELD || (token_table(tok) == t::MEMBER_REF && self.names.is_field_ref(token_row(tok)))));
        let field = is_field.then(|| self.names.field(tok, ctx.generic));
        let token_kind = match table_name(token_table(tok)) {
            Some(name) => name.to_string(),
            None if token_table(tok) == USER_STRING => "#US".into(),
            None => String::new(),
        };
        Some(InsnView {
            bytes5: bytes_text(&self.md.bytes, at, insn.len as usize, 5),
            bytes24: bytes_text(&self.md.bytes, at, insn.len as usize, 24),
            operand,
            text,
            file_offset,
            callee,
            callee_fn,
            string,
            field,
            token_kind,
            insn,
        })
    }

    pub fn method(&mut self, fn_index: usize) -> Option<MethodView> {
        let body = self.bodies.get(fn_index)?;
        let method = body.method;
        let md = self.md;
        let flags = md.get(m::METHOD_DEF_FLAGS, method);
        let implementation = md.get(METHOD_DEF_IMPL_FLAGS, method);
        let mut words: Vec<&str> = vec![METHOD_ACCESS[(flags & 7) as usize]];
        words.extend(METHOD_FLAGS.iter().filter(|(bit, _)| flags & bit != 0).map(|(_, w)| *w));
        words.retain(|w| !w.is_empty());
        let mut attributes = format!(
            "{} · {} {}",
            words.join(" "),
            ["cil", "native", "optil", "runtime"][(implementation & 3) as usize],
            if implementation & 4 != 0 { "unmanaged" } else { "managed" }
        );
        for (bit, w) in IMPL_FLAGS {
            if implementation & bit != 0 {
                attributes.push(' ');
                attributes.push_str(w);
            }
        }
        let generic = GenericContext { ty: self.names.method_owner(method), method };
        let locals = if body.locals_token != 0 { self.names.locals(body.locals_token, generic) } else { Vec::new() };
        let clauses = body
            .clauses
            .iter()
            .map(|&c| {
                let catch = if c.class_token != 0 { self.names.type_token(c.class_token, generic) } else { "object".into() };
                let kind = if c.kind & 1 != 0 {
                    format!("filter {}", label(c.filter_start))
                } else if c.kind & 2 != 0 {
                    "finally".into()
                } else if c.kind & 4 != 0 {
                    "fault".into()
                } else {
                    format!("catch {catch}")
                };
                let text = format!(
                    ".try {} to {} {kind} handler {} to {}",
                    label(c.try_start as i64),
                    label(c.try_end as i64),
                    label(c.handler_start as i64),
                    label(c.handler_end as i64)
                );
                (c, text, catch)
            })
            .collect();
        let sig = self.names.method_def_sig(method);
        let param_names = self.names.param_names(method);
        let name_of = |k: usize| param_names.get(k + 1).and_then(|n| n.as_deref()).filter(|n| !n.is_empty());
        let listed: Vec<String> = sig
            .params
            .iter()
            .enumerate()
            .map(|(k, ty)| match name_of(k) {
                Some(name) => format!("{ty} {}", proper_name(name)),
                None => ty.clone(),
            })
            .collect();
        let signature = format!("{}{} ({})", if sig.conv & 0x20 != 0 { "instance " } else { "static " }, sig.ret, listed.join(", "));
        let identifier = |n: &str| n.as_bytes().first().is_some_and(|c| c.is_ascii_alphabetic() || *c == b'_') && n.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_');
        let params = sig
            .params
            .iter()
            .enumerate()
            .map(|(k, ty)| {
                let name = match name_of(k) {
                    Some(name) if identifier(name) => name.to_string(),
                    _ => format!("A_{}", k + if sig.conv & 0x20 != 0 { 1 } else { 0 }),
                };
                (name, ty.clone())
            })
            .collect();
        Some(MethodView {
            token: token(t::METHOD_DEF, method),
            attributes,
            rva: body.rva,
            size: body.size,
            fat: body.fat,
            max_stack: body.max_stack,
            init_locals: body.init_locals,
            locals,
            clauses,
            signature,
            params,
            ret: sig.ret,
        })
    }

    /// What a method's code calls (the address reached by each call with a method operand, in order),
    /// how many calls go through a function pointer, and the strings it loads (token, text; empty
    /// when the token is not a string's).
    pub fn function_refs(&mut self, fn_index: usize) -> (Vec<f64>, u32, Vec<(u32, Vec<u16>)>) {
        let (mut calls, mut indirect, mut strings) = (Vec::new(), 0, Vec::new());
        let Some(f) = self.p.functions.get(fn_index) else { return (calls, indirect, strings) };
        let (first, count) = (f.first as usize, f.count.min(50000) as usize);
        let body = &self.bodies[fn_index];
        let (code, size, rva, header) = (body.code, body.size, body.rva as i64, body.header_size as i64);
        let mut insn = CilInsn::default();
        for i in first..first + count {
            let at = code as i64 + (self.p.offsets[i] as i64 - (rva + header));
            decode_at(&self.md.bytes, code, at.max(0) as usize, code + size, &mut insn);
            let Some(op) = insn.op else { continue };
            if op.flags & f::CALL != 0 && op.operand == o::METHOD {
                if let Some(addr) = self.callee(insn.a as u32) {
                    calls.push(addr);
                }
            } else if op.flags & f::CALL != 0 {
                indirect += 1;
            }
            if op.operand == o::STRING {
                let tok = insn.a as u32;
                strings.push((tok, self.md.user_string(token_row(tok)).unwrap_or_default()));
            }
        }
        (calls, indirect, strings)
    }

    /// What a type is: an interface, an enum, a struct, a delegate or a class (by what it extends).
    fn type_kind(&self, row: u32) -> &'static str {
        let md = self.md;
        if md.get(m::TYPE_DEF_FLAGS, row) & 0x20 != 0 {
            return "interface";
        }
        let extends = md.get(m::TYPE_DEF_EXTENDS, row);
        if extends == 0 {
            return if row == 1 { "<Module>" } else { "class" };
        }
        let (table, base) = decode_index(Coded::TypeDefOrRef, extends);
        let name = if table == t::TYPE_REF as i16 {
            md.string(md.get(m::TYPE_REF_NAME, base))
        } else if table == t::TYPE_DEF as i16 {
            md.string(md.get(m::TYPE_DEF_NAME, base))
        } else {
            String::new()
        };
        let ns = if table == t::TYPE_REF as i16 { md.string(md.get(m::TYPE_REF_NAMESPACE, base)) } else { String::new() };
        match (ns.as_str(), name.as_str()) {
            ("System", "Enum") => "enum",
            ("System", "ValueType") => "struct",
            ("System", "MulticastDelegate") => "delegate",
            _ => "class",
        }
    }

    /// Where a resource or a forwarded type is: an assembly referenced, or a file of this one.
    fn implementation_name(&self, coded: u32) -> String {
        let md = self.md;
        let (table, row) = decode_index(Coded::Implementation, coded);
        if table == t::ASSEMBLY_REF as i16 {
            md.string(md.get(m::ASSEMBLY_REF_NAME, row))
        } else {
            md.string(md.get(FILE_NAME, row))
        }
    }

    /// The Assembly page.
    pub fn assembly(&mut self) -> AssemblyView {
        let md = self.md;
        let header = &md.header;
        let assembly = (md.rows(t::ASSEMBLY) != 0).then(|| {
            let culture = md.string(md.get(ASSEMBLY_CULTURE, 1));
            (md.string(md.get(ASSEMBLY_NAME, 1)), version(md, t::ASSEMBLY, 1), culture, key_text(md.blob(md.get(ASSEMBLY_PUBLIC_KEY, 1))))
        });
        let mut tables = Vec::new();
        for id in 0..64u8 {
            let rows = md.rows(id);
            if rows != 0 {
                tables.push((id, table_name(id).unwrap_or("?"), rows));
            }
        }
        let resources = (1..=md.rows(t::MANIFEST_RESOURCE))
            .map(|r| {
                let implementation = md.get(RESOURCE_IMPLEMENTATION, r);
                (md.string(md.get(RESOURCE_NAME, r)), md.get(RESOURCE_FLAGS, r) & 7 == 1, (implementation != 0).then(|| self.implementation_name(implementation)))
            })
            .collect();
        let rows = md.rows(t::TYPE_DEF);
        let mut methods = FxHashMap::<u32, u32>::default();
        for method in 1..=md.rows(t::METHOD_DEF) {
            *methods.entry(self.names.method_owner(method)).or_default() += 1;
        }
        let mut first: FxHashMap<u32, f64> = FxHashMap::default();
        for f in &self.p.functions {
            first.entry(self.names.method_owner(f.method)).or_insert(f.addr as f64);
        }
        let types = (2..=rows.min(3001))
            .map(|r| {
                (
                    self.names.type_def(r),
                    self.type_kind(r),
                    TYPE_VISIBILITY[(md.get(m::TYPE_DEF_FLAGS, r) & 7) as usize],
                    methods.get(&r).copied().unwrap_or(0),
                    first.get(&r).copied(),
                )
            })
            .collect();
        AssemblyView {
            assembly,
            module: (md.string(md.get(MODULE_NAME, 1)), md.guid(md.get(MODULE_MVID, 1))),
            runtime: (md.version.clone(), header.runtime.clone(), md.schema.clone()),
            flags: CLI_FLAGS.iter().filter(|(bit, _)| header.flags & bit != 0).map(|(_, name)| *name).collect::<Vec<_>>().join(" "),
            strong_name: header.strong_name.size,
            counts: [rows, md.rows(t::METHOD_DEF), md.rows(t::FIELD), md.rows(t::PROPERTY), md.rows(t::EVENT)],
            warnings: md.warnings.clone(),
            streams: md.streams.iter().map(|s| (s.name.clone(), s.offset, s.size)).collect(),
            tables,
            resources,
            types,
        }
    }

    /// The References page: the assemblies referenced and the types forwarded to others.
    pub fn references(&mut self) -> ReferencesView {
        let md = self.md;
        let assemblies = (1..=md.rows(t::ASSEMBLY_REF))
            .map(|r| {
                (
                    md.string(md.get(m::ASSEMBLY_REF_NAME, r)),
                    version(md, t::ASSEMBLY_REF, r),
                    md.string(md.get(ASSEMBLY_REF_CULTURE, r)),
                    key_text(md.blob(md.get(ASSEMBLY_REF_KEY, r))),
                )
            })
            .collect();
        let exported = md.rows(t::EXPORTED_TYPE);
        let forwarders = (1..=exported.min(5000))
            .map(|r| {
                let implementation = md.get(EXPORTED_TYPE_IMPLEMENTATION, r);
                let (table, row) = decode_index(Coded::Implementation, implementation);
                let to = if table == t::ASSEMBLY_REF as i16 {
                    md.string(md.get(m::ASSEMBLY_REF_NAME, row))
                } else if table == t::FILE as i16 {
                    md.string(md.get(FILE_NAME, row))
                } else {
                    String::new()
                };
                let ns = md.string(md.get(EXPORTED_TYPE_NAMESPACE, r));
                let name = md.string(md.get(EXPORTED_TYPE_NAME, r));
                (if ns.is_empty() { name } else { format!("{ns}.{name}") }, to)
            })
            .collect();
        ReferencesView { assemblies, forwarders, exported }
    }

    /// The framework the assembly was built for, from its TargetFrameworkAttribute: `.NETCoreApp,Version=v10.0`.
    pub fn framework(&mut self) -> Option<String> {
        let md = self.md;
        for r in 1..=md.rows(t::CUSTOM_ATTRIBUTE) {
            let (parent, _) = decode_index(Coded::HasCustomAttribute, md.get(CUSTOM_ATTRIBUTE_PARENT, r));
            if parent != t::ASSEMBLY as i16 {
                continue;
            }
            let (table, row) = decode_index(Coded::CustomAttributeType, md.get(CUSTOM_ATTRIBUTE_TYPE, r));
            if table != t::MEMBER_REF as i16 {
                continue;
            }
            let (owner, owner_row) = decode_index(Coded::MemberRefParent, md.get(m::MEMBER_REF_CLASS, row));
            if owner != t::TYPE_REF as i16 || !self.names.type_ref(owner_row).ends_with("System.Runtime.Versioning.TargetFrameworkAttribute") {
                continue;
            }
            let blob = md.blob(md.get(CUSTOM_ATTRIBUTE_VALUE, r));
            if blob.first() != Some(&1) || blob.get(1) != Some(&0) {
                continue;
            }
            let (length, size) = compressed(blob, 2);
            let start = (2 + size).min(blob.len());
            return Some(utf8(&blob[start..(2 + size + length as usize).min(blob.len())]));
        }
        None
    }

    /// The name of the assembly, or of the module when it is a module of another one.
    pub fn assembly_name(&self) -> String {
        let md = self.md;
        if md.rows(t::ASSEMBLY) != 0 {
            md.string(md.get(ASSEMBLY_NAME, 1))
        } else {
            md.string(md.get(MODULE_NAME, 1))
        }
    }

    /// The metadata the session keeps.
    pub fn metadata(&self) -> &Metadata {
        self.md
    }

    /// How many bytes of IL the methods with code have.
    pub fn code_bytes(&self) -> usize {
        self.bodies.iter().map(|b| b.size).sum()
    }

    /// A string of #US (by its index) as ldstr's operand: an index past the heap is an empty string.
    pub fn string_text(&self, index: u32) -> String {
        string_text(&self.md.user_string(index).unwrap_or_default())
    }

    /// A field token as ildasm writes it, with no generic context (for a line's tooltip).
    pub fn field(&mut self, tok: u32) -> String {
        self.names.field(tok, NO_CONTEXT)
    }
}

pub struct AssemblyView {
    /// Name, version, culture, public key.
    pub assembly: Option<(String, String, String, String)>,
    /// Name and MVID.
    pub module: (String, String),
    /// The metadata's version, the CLI header's runtime, the table schema.
    pub runtime: (String, String, String),
    pub flags: String,
    pub strong_name: u32,
    /// Rows of TypeDef, MethodDef, Field, Property, Event.
    pub counts: [u32; 5],
    pub warnings: Vec<String>,
    pub streams: Vec<(String, usize, u32)>,
    pub tables: Vec<(u8, &'static str, u32)>,
    /// Name, public, where (None: in this file).
    pub resources: Vec<(String, bool, Option<String>)>,
    /// Name, kind, visibility, methods, the address of its first function.
    pub types: Vec<(String, &'static str, &'static str, u32, Option<f64>)>,
}

pub struct ReferencesView {
    /// Name, version, culture, public key token.
    pub assemblies: Vec<(String, String, String, String)>,
    /// The first 5000 forwarded types: the type, where it went.
    pub forwarders: Vec<(String, String)>,
    pub exported: u32,
}

impl CilLines {
    /// The page's questions, over the metadata and what the names have worked out.
    pub fn page<R>(&mut self, p: &CilProgram, f: impl FnOnce(&mut Page) -> R) -> R {
        let parts = std::mem::take(&mut self.names);
        let names = Names::from_parts(&self.md, parts);
        let mut page = Page { p, md: &self.md, bodies: &self.bodies, method_fn: &self.method_fn, import_by_token: &self.import_by_token, locals: &mut self.locals, names };
        let out = f(&mut page);
        self.names = page.names.into_parts();
        out
    }
}
