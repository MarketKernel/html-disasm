//! What every architecture's HLA64 lifter shares: how a line names things it
//! points at (the context the page fills in with function names and strings),
//! the line itself, and how names, numbers and strings are written in HLA64.

use crate::text::{js_hex, js_number};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetKind {
    Label,
    Function,
    Import,
}

#[derive(Clone, Debug)]
pub struct Target {
    pub name: String,
    pub kind: TargetKind,
}

/// What is at a data address, as the views name it. A string with `objc` set is a constant NSString (`@"text"`).
#[derive(Clone, Debug)]
pub enum DataAt {
    String { text: String, objc: bool },
    Symbol { name: String },
}

pub trait LiftContext {
    /// How to name a branch or call target.
    fn target(&self, addr: i64) -> Option<Target>;
    /// What is at a data address: a string, or a named symbol.
    fn data(&self, addr: i64) -> Option<DataAt>;
    /// Start of the function the instruction is in (for telling a tail call from a goto).
    fn function_start(&self, pc: i64) -> i64;
}

/// A context that knows no names: what the analysis lifts with.
pub struct NoContext;

impl LiftContext for NoContext {
    fn target(&self, _: i64) -> Option<Target> {
        None
    }
    fn data(&self, _: i64) -> Option<DataAt> {
        None
    }
    fn function_start(&self, _: i64) -> i64 {
        -1
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct HlaLine {
    pub text: String,
    pub words: Vec<&'static str>,
    pub comment: Option<String>,
}

pub type Words = Vec<&'static str>;

/// `[...new Set(words)]`: the words in order of first use.
pub fn unique(words: Words) -> Words {
    let mut out: Words = Vec::with_capacity(words.len());
    for w in words {
        if !out.contains(&w) {
            out.push(w);
        }
    }
    out
}

/// A number as HLA64 writes it: small ones in decimal, the rest in hex.
pub fn num(v: f64) -> String {
    if v.abs() < 10.0 {
        js_number(v)
    } else if v < 0.0 {
        format!("-0x{}", js_hex(-v))
    } else {
        format!("0x{}", js_hex(v))
    }
}

fn is_ident(name: &str) -> bool {
    let b = name.as_bytes();
    match b.first() {
        Some(c) if c.is_ascii_alphabetic() || *c == b'_' => b[1..].iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_'),
        _ => false,
    }
}

/// A Rust or C++ path, or anything else that is not an identifier, goes between backticks.
pub fn hla_name(name: &str, words: &mut Words) -> String {
    if is_ident(name) {
        return name.to_string();
    }
    words.push("quoted-name");
    format!("`{name}`")
}

/// `JSON.stringify` of the first `limit` UTF-16 units of a string, with `…` when it was longer.
pub fn quoted(text: &str, limit: usize) -> String {
    let mut out = String::with_capacity(text.len().min(limit.saturating_mul(3)) + 2);
    out.push('"');
    let mut units = 0;
    let total: usize = text.chars().map(char::len_utf16).sum();
    let cut = total > limit;
    for c in text.chars() {
        let n = c.len_utf16();
        if cut && units + n > limit {
            if units < limit {
                // The cut falls inside a surrogate pair: JavaScript keeps the lone high half.
                let mut buf = [0u16; 2];
                c.encode_utf16(&mut buf);
                out.push_str(&format!("\\u{:04x}", buf[0]));
            }
            break;
        }
        units += n;
        escape_json_char(&mut out, c);
    }
    if cut {
        out.push('…');
    }
    out.push('"');
    out
}

pub fn escape_json_char(out: &mut String, c: char) {
    match c {
        '"' => out.push_str("\\\""),
        '\\' => out.push_str("\\\\"),
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        '\u{8}' => out.push_str("\\b"),
        '\u{c}' => out.push_str("\\f"),
        c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
        c => out.push(c),
    }
}
