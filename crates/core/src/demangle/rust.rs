//! Rust names: v0 (`_R…`, RFC 2603) and the legacy escapes of `_ZN…17h<hash>E`.
//!
//! The v0 printer writes the name into one buffer as it parses, in the order
//! the TypeScript built its strings; what it parsed only to skip (the path of
//! an impl's own crate) is written and cut off again.

use super::{from_code_point, Units};
use crate::text::js_number;

fn basic(c: u8) -> Option<&'static str> {
    Some(match c {
        b'a' => "i8",
        b'b' => "bool",
        b'c' => "char",
        b'd' => "f64",
        b'e' => "str",
        b'f' => "f32",
        b'h' => "u8",
        b'i' => "isize",
        b'j' => "usize",
        b'l' => "i32",
        b'm' => "u32",
        b'n' => "i128",
        b'o' => "u128",
        b's' => "i16",
        b't' => "u16",
        b'u' => "()",
        b'v' => "...",
        b'x' => "i64",
        b'y' => "u64",
        b'z' => "!",
        b'p' => "_",
        _ => return None,
    })
}

/// The name does not parse.
struct Parse;

/// How many back-references to constants may lead into one another.
const MAX_CONSTANT_NESTING: u32 = 1000;

type R<T> = Result<T, Parse>;

/// An identifier of the name: where its text is, and whether it is punycode (`u…`).
#[derive(Clone, Copy)]
struct Ident {
    start: usize,
    end: usize,
    punycode: bool,
}

struct V0<'a> {
    u: &'a Units<'a>,
    s: &'a [u8],
    pos: usize,
    depth: u32,
    /// Constants reached through back-references, nested. Nothing else bounds them: a constant
    /// that refers to itself recursed until JavaScript's stack ran out, and the name stayed as
    /// it was; here the name fails long before the stack would.
    constants: u32,
    /// Lifetimes bound by enclosing for<…> binders, innermost last. A JavaScript number, as the
    /// counts it adds up are (they come from base-62 numbers of any size).
    bound: f64,
    out: String,
}

impl V0<'_> {
    fn peek(&self) -> u8 {
        self.s.get(self.pos).copied().unwrap_or(0)
    }
    fn next(&mut self) -> R<u8> {
        let c = *self.s.get(self.pos).ok_or(Parse)?;
        self.pos += 1;
        Ok(c)
    }
    fn eat(&mut self, c: u8) -> bool {
        if self.s.get(self.pos) == Some(&c) {
            self.pos += 1;
            return true;
        }
        false
    }

    /// A base-62 number, computed in a double as JavaScript computes it, so a huge
    /// disambiguator prints as the TypeScript printed it.
    fn base62(&mut self) -> R<f64> {
        if self.eat(b'_') {
            return Ok(0.0);
        }
        let mut x = 0.0f64;
        loop {
            let c = self.next()?;
            if c == b'_' {
                return Ok(x + 1.0);
            }
            let d = match c {
                b'0'..=b'9' => c - 48,
                b'a'..=b'z' => c - 87,
                b'A'..=b'Z' => c - 29,
                _ => return Err(Parse),
            };
            x = x * 62.0 + d as f64;
        }
    }
    fn opt_base62(&mut self, tag: u8) -> R<f64> {
        Ok(if self.eat(tag) { self.base62()? + 1.0 } else { 0.0 })
    }
    /// "0", or digits without a leading zero: in "0023_x" the 0, 0 and 23 are three numbers.
    fn decimal(&mut self) -> R<f64> {
        let start = self.pos;
        if self.eat(b'0') {
            return Ok(0.0);
        }
        while self.peek().is_ascii_digit() {
            self.pos += 1;
        }
        if start == self.pos {
            return Err(Parse);
        }
        // Number(digits): the nearest double, as Rust's parse gives it.
        let digits = core::str::from_utf8(&self.s[start..self.pos]).unwrap_or_default();
        Ok(digits.parse::<f64>().unwrap_or(f64::INFINITY))
    }

    fn ident(&mut self) -> R<(Ident, f64)> {
        let disambiguator = self.opt_base62(b's')?;
        Ok((self.undisambiguated()?, disambiguator))
    }
    fn undisambiguated(&mut self) -> R<Ident> {
        let punycode = self.eat(b'u');
        let length = self.decimal()?;
        self.eat(b'_');
        if self.pos as f64 + length > self.s.len() as f64 {
            return Err(Parse);
        }
        let start = self.pos;
        self.pos += length as usize;
        Ok(Ident { start, end: self.pos, punycode })
    }
    /// Writes an identifier; a punycode one with its underscores as hyphens (or any one, with `dashes`).
    fn push_ident(&mut self, ident: Ident, dashes: bool) {
        let at = self.out.len();
        self.u.push_text(&mut self.out, ident.start, ident.end);
        if (ident.punycode || dashes) && self.out[at..].contains('_') {
            let text = self.out[at..].replace('_', "-");
            self.out.truncate(at);
            self.out.push_str(&text);
        }
    }

    /// Where a back-reference points: offsets count from after "_R", and must point back.
    fn backref_target(&mut self) -> R<usize> {
        let target = self.base62()? + 2.0;
        if target >= self.pos as f64 {
            return Err(Parse);
        }
        Ok(target as usize)
    }

    fn path(&mut self, value_context: bool) -> R<()> {
        self.depth += 1;
        if self.depth > 200 {
            return Err(Parse);
        }
        self.path_body(value_context)?;
        self.depth -= 1;
        Ok(())
    }

    /// A path parsed only to be skipped: written, then cut off again.
    fn skip_path(&mut self) -> R<()> {
        let at = self.out.len();
        self.path(false)?;
        self.out.truncate(at);
        Ok(())
    }

    fn path_body(&mut self, value_context: bool) -> R<()> {
        match self.next()? {
            b'C' => {
                let (name, _) = self.ident()?;
                self.push_ident(name, false);
            }
            b'M' => {
                self.opt_base62(b's')?;
                self.skip_path()?;
                self.out.push('<');
                self.type_()?;
                self.out.push('>');
            }
            b'X' => {
                self.opt_base62(b's')?;
                self.skip_path()?;
                self.out.push('<');
                self.type_()?;
                self.out.push_str(" as ");
                self.path(false)?;
                self.out.push('>');
            }
            b'Y' => {
                self.out.push('<');
                self.type_()?;
                self.out.push_str(" as ");
                self.path(false)?;
                self.out.push('>');
            }
            b'N' => {
                let ns = self.next()?;
                self.path(value_context)?;
                let (name, disambiguator) = self.ident()?;
                let word = match ns {
                    b'C' => "closure",
                    b'S' => "shim",
                    b'A'..=b'Z' => "",
                    _ => {
                        if name.end > name.start {
                            self.out.push_str("::");
                            self.push_ident(name, false);
                        }
                        return Ok(());
                    }
                };
                self.out.push_str("::{");
                if word.is_empty() {
                    self.out.push(ns as char);
                } else {
                    self.out.push_str(word);
                }
                if name.end > name.start {
                    self.out.push(':');
                    self.push_ident(name, false);
                }
                self.out.push('#');
                self.out.push_str(&js_number(disambiguator));
                self.out.push('}');
            }
            b'I' => {
                self.path(value_context)?;
                self.out.push_str(if value_context { "::<" } else { "<" });
                let mut first = true;
                while !self.eat(b'E') {
                    if !first {
                        self.out.push_str(", ");
                    }
                    first = false;
                    self.generic_arg()?;
                }
                self.out.push('>');
            }
            b'B' => {
                let target = self.backref_target()?;
                let saved = self.pos;
                self.pos = target;
                self.path(value_context)?;
                self.pos = saved;
            }
            _ => return Err(Parse),
        }
        Ok(())
    }

    fn lifetime_name(&mut self, n: f64) -> R<()> {
        if n == 0.0 {
            self.out.push_str("'_");
            return Ok(());
        }
        let depth = self.bound - n;
        if depth < 0.0 {
            return Err(Parse);
        }
        push_bound_name(&mut self.out, depth);
        Ok(())
    }

    fn generic_arg(&mut self) -> R<()> {
        if self.eat(b'L') {
            let n = self.base62()?;
            return self.lifetime_name(n);
        }
        if self.eat(b'K') {
            return self.constant();
        }
        self.type_()
    }

    fn lifetime(&mut self) -> R<()> {
        if !self.eat(b'L') {
            return Ok(());
        }
        let n = self.base62()?;
        if n != 0.0 {
            self.lifetime_name(n)?;
            self.out.push(' ');
        }
        Ok(())
    }

    fn type_(&mut self) -> R<()> {
        self.depth += 1;
        if self.depth > 200 {
            return Err(Parse);
        }
        self.type_body()?;
        self.depth -= 1;
        Ok(())
    }

    fn type_body(&mut self) -> R<()> {
        let c = self.peek();
        if let Some(name) = basic(c) {
            self.pos += 1;
            self.out.push_str(name);
            return Ok(());
        }
        match c {
            b'A' => {
                self.pos += 1;
                self.out.push('[');
                self.type_()?;
                self.out.push_str("; ");
                self.constant()?;
                self.out.push(']');
            }
            b'S' => {
                self.pos += 1;
                self.out.push('[');
                self.type_()?;
                self.out.push(']');
            }
            b'T' => {
                self.pos += 1;
                self.out.push('(');
                let mut items = 0;
                while !self.eat(b'E') {
                    if items > 0 {
                        self.out.push_str(", ");
                    }
                    self.type_()?;
                    items += 1;
                }
                self.out.push_str(if items == 1 { ",)" } else { ")" });
            }
            b'R' | b'Q' => {
                self.pos += 1;
                self.out.push('&');
                self.lifetime()?;
                if c == b'Q' {
                    self.out.push_str("mut ");
                }
                self.type_()?;
            }
            b'P' => {
                self.pos += 1;
                self.out.push_str("*const ");
                self.type_()?;
            }
            b'O' => {
                self.pos += 1;
                self.out.push_str("*mut ");
                self.type_()?;
            }
            b'F' => {
                self.pos += 1;
                self.fn_sig()?;
            }
            b'D' => {
                self.pos += 1;
                self.out.push_str("dyn ");
                self.dyn_bounds()?;
                // The lifetime after the bounds is not printed.
                if self.eat(b'L') {
                    self.base62()?;
                }
            }
            b'B' => {
                self.pos += 1;
                let target = self.backref_target()?;
                let saved = self.pos;
                self.pos = target;
                self.type_()?;
                self.pos = saved;
            }
            _ => self.path(false)?,
        }
        Ok(())
    }

    /// Opens `count` more bound lifetimes, writing the for<'a, …> prefix their binder prints.
    fn open_binder(&mut self, count: f64) {
        self.bound += count;
        let first = self.bound - count;
        self.out.push_str("for<");
        let mut i = 0.0;
        while i < count {
            if i > 0.0 {
                self.out.push_str(", ");
            }
            push_bound_name(&mut self.out, first + i);
            i += 1.0;
        }
        self.out.push_str("> ");
    }

    fn fn_sig(&mut self) -> R<()> {
        let count = self.opt_base62(b'G')?;
        if count == 0.0 {
            return self.fn_sig_body();
        }
        self.open_binder(count);
        self.fn_sig_body()?;
        self.bound -= count;
        Ok(())
    }

    fn fn_sig_body(&mut self) -> R<()> {
        if self.eat(b'U') {
            self.out.push_str("unsafe ");
        }
        if self.eat(b'K') {
            if self.eat(b'C') {
                self.out.push_str("extern \"C\" ");
            } else {
                let abi = self.undisambiguated()?;
                self.out.push_str("extern \"");
                self.push_ident(abi, true);
                self.out.push_str("\" ");
            }
        }
        self.out.push_str("fn(");
        let mut first = true;
        while !self.eat(b'E') {
            if !first {
                self.out.push_str(", ");
            }
            first = false;
            self.type_()?;
        }
        self.out.push(')');
        // The return type, unless it is ().
        let at = self.out.len();
        self.out.push_str(" -> ");
        self.type_()?;
        if &self.out[at + 4..] == "()" {
            self.out.truncate(at);
        }
        Ok(())
    }

    fn dyn_bounds(&mut self) -> R<()> {
        let count = self.opt_base62(b'G')?;
        if count == 0.0 {
            return self.dyn_bounds_body();
        }
        self.open_binder(count);
        self.dyn_bounds_body()?;
        self.bound -= count;
        Ok(())
    }

    fn dyn_bounds_body(&mut self) -> R<()> {
        let mut first = true;
        while !self.eat(b'E') {
            if !first {
                self.out.push_str(" + ");
            }
            first = false;
            let at = self.out.len();
            self.path(false)?;
            // Associated type bindings go inside the trait's generic arguments, or in new ones.
            let mut bindings = 0;
            while self.eat(b'p') {
                let name = self.undisambiguated()?;
                if bindings == 0 {
                    if self.out.len() > at && self.out.ends_with('>') {
                        self.out.pop();
                        self.out.push_str(", ");
                    } else {
                        self.out.push('<');
                    }
                } else {
                    self.out.push_str(", ");
                }
                self.push_ident(name, false);
                self.out.push_str(" = ");
                self.type_()?;
                bindings += 1;
            }
            if bindings > 0 {
                self.out.push('>');
            }
        }
        Ok(())
    }

    fn constant(&mut self) -> R<()> {
        if self.eat(b'p') {
            self.out.push('_');
            return Ok(());
        }
        if self.eat(b'B') {
            let target = self.backref_target()?;
            self.constants += 1;
            if self.constants > MAX_CONSTANT_NESTING {
                return Err(Parse);
            }
            let saved = self.pos;
            self.pos = target;
            self.constant()?;
            self.pos = saved;
            self.constants -= 1;
            return Ok(());
        }
        let ty = self.next()?;
        let negative = self.eat(b'n');
        let start = self.pos;
        while self.peek() != b'_' {
            let c = self.next()?;
            if !(c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
                return Err(Parse);
            }
        }
        let hex = &self.s[start..self.pos];
        self.pos += 1;
        if ty == b'b' {
            self.out.push_str(if hex == b"1" { "true" } else { "false" });
            return Ok(());
        }
        if ty == b'c' {
            // String.fromCodePoint throws past U+10FFFF, and the name then does not parse.
            let mut v = 0u32;
            for &d in hex {
                v = v.saturating_mul(16).saturating_add(hex_digit(d));
            }
            if v > 0x10ffff {
                return Err(Parse);
            }
            self.out.push('\'');
            self.out.push(from_code_point(v));
            self.out.push('\'');
            return Ok(());
        }
        // A BigInt: as many digits as the name has.
        if negative {
            self.out.push('-');
        }
        push_hex_as_decimal(&mut self.out, hex);
        Ok(())
    }

    fn symbol(&mut self) -> R<()> {
        if self.peek().is_ascii_digit() {
            self.decimal()?; // encoding version
        }
        self.path(true)
    }
}

/// The name of the bound lifetime at a depth: 'a to 'z, then '_26 and on.
fn push_bound_name(out: &mut String, depth: f64) {
    if depth < 26.0 {
        out.push('\'');
        out.push(char::from(97 + depth as u8));
    } else {
        out.push_str("'_");
        out.push_str(&js_number(depth));
    }
}

fn hex_digit(c: u8) -> u32 {
    match c {
        b'0'..=b'9' => (c - b'0') as u32,
        _ => (c - b'a' + 10) as u32,
    }
}

/// Lowercase hex digits (any number of them) in decimal, as BigInt prints them.
fn push_hex_as_decimal(out: &mut String, hex: &[u8]) {
    if hex.len() <= 32 {
        let v = hex.iter().fold(0u128, |v, &d| (v << 4) | hex_digit(d) as u128);
        out.push_str(&v.to_string());
        return;
    }
    // Base 10^9 limbs, least significant first.
    let mut limbs: Vec<u32> = vec![0];
    for &d in hex {
        let mut carry = hex_digit(d) as u64;
        for limb in limbs.iter_mut() {
            let v = *limb as u64 * 16 + carry;
            *limb = (v % 1_000_000_000) as u32;
            carry = v / 1_000_000_000;
        }
        if carry > 0 {
            limbs.push(carry as u32);
        }
    }
    out.push_str(&limbs.last().unwrap().to_string());
    for limb in limbs.iter().rev().skip(1) {
        out.push_str(&format!("{limb:09}"));
    }
}

/// A Rust v0 name, or None when it does not parse.
pub(super) fn v0(name: &str) -> Option<String> {
    let u = Units::new(name);
    // Back-references count from after "_R": the parser starts at 2 and adds 2 to every one.
    let mut p = V0 { u: &u, s: &u.bytes, pos: 2, depth: 0, constants: 0, bound: 0.0, out: String::with_capacity(name.len() * 2) };
    p.symbol().ok()?;
    Some(p.out)
}

fn legacy_escape(code: &str) -> Option<&'static str> {
    Some(match code {
        "SP" => "@",
        "BP" => "*",
        "RF" => "&",
        "LT" => "<",
        "GT" => ">",
        "LP" => "(",
        "RP" => ")",
        "C" => ",",
        _ => return None,
    })
}

/// One component of a legacy Rust name with its escapes undone: what
/// `.replace(/\$([A-Z]{1,2}|u[0-9a-f]{2,6})\$/g, …)` and then `.replace(/\.\./g, '::')` did.
pub(super) fn legacy_component(part: &str) -> String {
    let text = if part.starts_with("_$") { &part[1..] } else { part };
    let b = text.as_bytes();
    let mut unescaped = String::with_capacity(text.len());
    let mut i = 0;
    let mut copied = 0;
    while i < b.len() {
        if b[i] == b'$' {
            if let Some((len, replacement)) = legacy_escape_at(&b[i + 1..]) {
                unescaped.push_str(&text[copied..i]);
                match replacement {
                    Some(r) => unescaped.push_str(&r),
                    None => unescaped.push_str(&text[i..i + len + 2]),
                }
                i += len + 2;
                copied = i;
                continue;
            }
        }
        i += 1;
    }
    unescaped.push_str(&text[copied..]);
    unescaped.replace("..", "::")
}

/// The escape code after a `$`, when `code$` follows: its length and what it stands for (None: kept as written).
fn legacy_escape_at(b: &[u8]) -> Option<(usize, Option<String>)> {
    let upper = b.iter().take(3).take_while(|c| c.is_ascii_uppercase()).count();
    if (1..=2).contains(&upper) && b.get(upper) == Some(&b'$') {
        let code = core::str::from_utf8(&b[..upper]).unwrap();
        return Some((upper, legacy_escape(code).map(String::from)));
    }
    if b.first() == Some(&b'u') {
        let hex = b[1..].iter().take(7).take_while(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c)).count();
        if (2..=6).contains(&hex) && b.get(1 + hex) == Some(&b'$') {
            let v = u32::from_str_radix(core::str::from_utf8(&b[1..1 + hex]).unwrap(), 16).unwrap();
            // String.fromCodePoint throws past U+10FFFF; such an escape is kept as written.
            if v > 0x10ffff {
                return Some((1 + hex, None));
            }
            return Some((1 + hex, Some(from_code_point(v).to_string())));
        }
    }
    None
}
