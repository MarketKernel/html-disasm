//! Symbol names back to source names.
//!
//! - Rust v0 (`_R…`), what rustc emits by default since 1.80 for libraries
//!   built with it and what the program in front of us uses: a full parser of
//!   the grammar in RFC 2603, with back-references, generic arguments, impls,
//!   closures, function pointers and dyn traits.
//! - Rust legacy (`_ZN…17h<hash>E`): the hash is dropped and `$LT$`-style
//!   escapes are undone.
//! - C++ (Itanium) names: the nested name, with `(…)` for the parameters.
//! - Swift (`$s…`): [`swift`], in full and in the simplified form
//!   `swift-demangle --simplified` gives, which the listing shows.
//! - MSVC (`?f@@YAXXZ`), the names of Windows programs: [`msvc`].
//!
//! The leading underscore Mach-O adds to every C-level name is removed first.
//! A name that does not parse is returned as it was.
//!
//! The TypeScript core this replaces read names as JavaScript strings, which
//! are UTF-16: lengths, positions and slices count UTF-16 code units. Symbols
//! are ASCII almost always, but to print every name byte for byte as before,
//! the parsers here read the name as UTF-16 code units too.

pub mod msvc;
mod rust;
pub mod swift;

use core::fmt;
use std::borrow::Cow;

/// The source language a name was mangled for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Language {
    Rust,
    Cpp,
    C,
    Swift,
    Objc,
    Other,
}

impl Language {
    /// The name the TypeScript core gave the language: `rust`, `c++`, `c`, `swift`, `objc`, `other`.
    pub fn as_str(self) -> &'static str {
        match self {
            Language::Rust => "rust",
            Language::Cpp => "c++",
            Language::C => "c",
            Language::Swift => "swift",
            Language::Objc => "objc",
            Language::Other => "other",
        }
    }
}

impl fmt::Display for Language {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Demangled {
    /// The full source name.
    pub full: String,
    /// The same with generic arguments folded to <…>, for the listing.
    pub short: String,
    pub language: Language,
}

impl Demangled {
    fn same(name: &str, language: Language) -> Demangled {
        Demangled { full: name.to_string(), short: name.to_string(), language }
    }
}

/// A name as the parsers read it, as JavaScript saw it: one byte per UTF-16
/// code unit — the unit itself when it is ASCII, 0x80 when it is not — so
/// lengths and positions are JavaScript's. Every rule of the grammars names
/// ASCII characters only. An ASCII name (almost every one) is read in place;
/// for the others the units are kept, to take text from.
pub(crate) struct Units<'a> {
    pub bytes: Cow<'a, [u8]>,
    wide: Vec<u16>,
}

impl<'a> Units<'a> {
    pub fn new(s: &'a str) -> Self {
        if s.is_ascii() {
            return Units { bytes: Cow::Borrowed(s.as_bytes()), wide: Vec::new() };
        }
        let wide: Vec<u16> = s.encode_utf16().collect();
        let bytes = wide.iter().map(|&u| if u < 0x80 { u as u8 } else { 0x80 }).collect();
        Units { bytes: Cow::Owned(bytes), wide }
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether every unit is ASCII (the bytes are the name itself).
    pub fn is_ascii(&self) -> bool {
        self.wide.is_empty()
    }

    /// The code unit at `i`, as it is.
    pub fn unit(&self, i: usize) -> u16 {
        if self.wide.is_empty() {
            self.bytes[i] as u16
        } else {
            self.wide[i]
        }
    }

    /// Appends the text of the units `a..b`.
    pub fn push_text(&self, out: &mut String, a: usize, b: usize) {
        if self.wide.is_empty() {
            // ASCII throughout.
            out.push_str(core::str::from_utf8(&self.bytes[a..b]).unwrap_or_default());
        } else {
            push_utf16(out, &self.wide[a..b]);
        }
    }

    pub fn text(&self, a: usize, b: usize) -> String {
        let mut out = String::with_capacity(b - a);
        self.push_text(&mut out, a, b);
        out
    }

    /// Appends the units `a..b` themselves.
    pub fn push_units(&self, out: &mut Vec<u16>, a: usize, b: usize) {
        if self.wide.is_empty() {
            out.extend(self.bytes[a..b].iter().map(|&c| c as u16));
        } else {
            out.extend_from_slice(&self.wide[a..b]);
        }
    }
}

/// Appends UTF-16 code units as text. A surrogate left alone by a slice (which
/// a JavaScript string can hold and a Rust one cannot) becomes U+FFFD.
pub(crate) fn push_utf16(out: &mut String, units: &[u16]) {
    if units.iter().all(|&u| u < 0x80) {
        out.extend(units.iter().map(|&u| u as u8 as char));
    } else {
        out.extend(char::decode_utf16(units.iter().copied()).map(|c| c.unwrap_or('\u{fffd}')));
    }
}

/// `String.fromCodePoint(c)`: U+FFFD for a lone surrogate, which a Rust string cannot hold.
pub(crate) fn from_code_point(c: u32) -> char {
    char::from_u32(c).unwrap_or('\u{fffd}')
}

/// Itanium nested names: _ZN <len><name>… E, as used by C++ and legacy Rust.
fn itanium(units: &Units) -> Option<(Vec<String>, String)> {
    let name: &[u8] = &units.bytes;
    let at = |p: usize| name.get(p).copied().unwrap_or(0);
    let mut p = 2usize;
    let mut parts: Vec<String> = Vec::new();
    let nested = at(p) == b'N';
    if nested {
        p += 1;
    }
    while matches!(at(p), b'K' | b'V' | b'r') {
        p += 1;
    }
    loop {
        'piece: {
            if at(p) == b'S' && at(p + 1) == b't' {
                parts.push("std".into());
                p += 2;
                break 'piece;
            }
            let digits = name.get(p..).unwrap_or(&[]).iter().take_while(|c| c.is_ascii_digit()).count();
            if digits == 0 {
                if at(p) == b'C' && (b'1'..=b'3').contains(&at(p + 1)) {
                    parts.push(parts.last().cloned().unwrap_or_default());
                    p += 2;
                    break 'piece;
                }
                if at(p) == b'D' && (b'0'..=b'2').contains(&at(p + 1)) {
                    let destructor = format!("~{}", parts.last().map(String::as_str).unwrap_or(""));
                    parts.push(destructor);
                    p += 2;
                    break 'piece;
                }
                return finish(units, parts, nested, p);
            }
            // A length past the end only runs the position off it, as in JavaScript: saturate.
            let mut length = 0usize;
            for &c in &name[p..p + digits] {
                length = length.saturating_mul(10).saturating_add((c - b'0') as usize);
            }
            p += digits;
            let end = p.saturating_add(length).min(name.len());
            parts.push(if p < end { units.text(p, end) } else { String::new() });
            p = p.saturating_add(length);
        }
        if !(nested && at(p) != b'E' && p < name.len()) {
            break;
        }
    }
    finish(units, parts, nested, p)
}

fn finish(units: &Units, parts: Vec<String>, nested: bool, mut p: usize) -> Option<(Vec<String>, String)> {
    if parts.is_empty() {
        return None;
    }
    if nested && units.bytes.get(p) == Some(&b'E') {
        p += 1;
    }
    Some((parts, if p < units.len() { units.text(p, units.len()) } else { String::new() }))
}

/// `/^h[0-9a-f]{16}$/`: the hash legacy Rust names end with.
fn is_legacy_hash(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 17 && b[0] == b'h' && b[1..].iter().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c))
}

/// Folds every <…> group (balanced) to <…>, keeping the outer path readable.
pub fn fold_generics(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut depth = 0u32;
    for c in name.chars() {
        if c == '<' {
            depth += 1;
            if depth <= 2 {
                out.push_str(if depth == 2 { "<…" } else { "<" });
            }
        } else if c == '>' && depth > 0 {
            if depth <= 2 {
                out.push('>');
            }
            depth -= 1;
        } else if depth <= 1 {
            out.push(c);
        }
    }
    out
}

/// A Mach-O name: C-level names carry an extra leading underscore.
pub fn demangle(raw: &str) -> Demangled {
    let name = if raw.starts_with("__") || raw.starts_with("_$") { &raw[1..] } else { raw };
    if name.starts_with("_R") {
        return match rust::v0(name) {
            Some(full) => Demangled { short: fold_generics(&full), full, language: Language::Rust },
            None => Demangled::same(raw, Language::Rust),
        };
    }
    if name.starts_with("_Z") {
        if let Some((parts, rest)) = itanium(&Units::new(name)) {
            let last = parts.last().map(String::as_str).unwrap_or("");
            if is_legacy_hash(last) && parts.len() > 1 {
                let full = parts[..parts.len() - 1].iter().map(|p| rust::legacy_component(p)).collect::<Vec<_>>().join("::");
                return Demangled { short: fold_generics(&full), full, language: Language::Rust };
            }
            let params = if !rest.is_empty() && rest != "v" { "(…)" } else { "()" };
            let full = format!("{}{params}", parts.join("::"));
            return Demangled { short: full.clone(), full, language: Language::Cpp };
        }
    }
    if name.starts_with("$s") || name.starts_with("$S") || name.starts_with("$e") {
        return match swift::demangle_swift(name) {
            Some((full, short)) => Demangled { full, short, language: Language::Swift },
            None => Demangled::same(raw, Language::Swift),
        };
    }
    if raw.starts_with("+[") || raw.starts_with("-[") {
        return Demangled::same(raw, Language::Objc);
    }
    if let Some(rest) = raw.strip_prefix('_') {
        return Demangled::same(rest, Language::C);
    }
    Demangled::same(raw, Language::Other)
}

/// A name from an ELF file or a WebAssembly module. There C names carry no
/// extra leading underscore (`main`, `_start`, `__cxa_finalize`), so only
/// mangled Rust, C++ and Swift names change; anything else stays as the file
/// writes it. A Windows program's C++ names are MSVC's (`?f@@YAXXZ`).
pub fn demangle_unprefixed(raw: &str) -> Demangled {
    if raw.starts_with("$s") || raw.starts_with("$e") {
        return demangle(raw);
    }
    if raw.starts_with('?') || raw.starts_with(".?A") {
        if let Some((full, short)) = msvc::demangle_msvc(raw) {
            return Demangled { full, short, language: Language::Cpp };
        }
    }
    if raw.starts_with("_Z") || raw.starts_with("_R") {
        let prefixed = format!("_{raw}");
        let found = demangle(&prefixed);
        if found.full != prefixed {
            return found;
        }
    }
    Demangled::same(raw, Language::Other)
}

/// The same as [`demangle_unprefixed`], under the name the WebAssembly views use.
pub fn demangle_wasm(raw: &str) -> Demangled {
    demangle_unprefixed(raw)
}
