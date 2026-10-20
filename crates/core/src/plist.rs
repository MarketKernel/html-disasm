//! Property lists, as an app bundle keeps its Info.plist (binary, `bplist00`, as Xcode writes it)
//! and a provisioning profile carries its contents (XML). A port of the TypeScript reader the page
//! had, which made plain JavaScript values of them: so strings here are UTF-16 (a lone surrogate
//! stays one), a date is a JavaScript time (milliseconds, NaN for an invalid date), a number a
//! double, and a dict keeps the last value of a key, as an object assigned in turn does.

/// A value of a property list.
#[derive(Clone, Debug, PartialEq)]
pub enum Plist {
    Str(Vec<u16>),
    Num(f64),
    Bool(bool),
    /// Milliseconds since 1970 (NaN: an invalid date).
    Date(f64),
    Data(Vec<u8>),
    Array(Vec<Plist>),
    Dict(Vec<(Vec<u16>, Plist)>),
}

impl Plist {
    /// The value of a key of a dict (the last one of that key), as `object[key]` reads it.
    pub fn get(&self, key: &str) -> Option<&Plist> {
        let Plist::Dict(entries) = self else { return None };
        let key: Vec<u16> = key.encode_utf16().collect();
        entries.iter().rev().find(|(k, _)| *k == key).map(|(_, v)| v)
    }

    /// A string's text (`typeof v === 'string'`).
    pub fn text(&self) -> Option<&[u16]> {
        match self {
            Plist::Str(s) => Some(s),
            _ => None,
        }
    }
}

/// Why a property list cannot be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotPlist(pub &'static str);

fn units(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

/// Windows-1252, which a `TextDecoder('latin1')` decodes (WHATWG maps the label to it).
pub fn windows_1252(b: u8) -> u16 {
    const HIGH: [u16; 32] = [
        0x20ac, 0x0081, 0x201a, 0x0192, 0x201e, 0x2026, 0x2020, 0x2021, 0x02c6, 0x2030, 0x0160, 0x2039, 0x0152, 0x008d, 0x017d, 0x008f, 0x0090, 0x2018, 0x2019, 0x201c, 0x201d,
        0x2022, 0x2013, 0x2014, 0x02dc, 0x2122, 0x0161, 0x203a, 0x0153, 0x009d, 0x017e, 0x0178,
    ];
    if (0x80..0xa0).contains(&b) {
        HIGH[(b - 0x80) as usize]
    } else {
        b as u16
    }
}

/// UTF-8 as a `TextDecoder()` reads it: bad bytes replaced, a leading byte order mark dropped.
fn utf8_text(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    s.strip_prefix('\u{feff}').map_or_else(|| s.to_string(), str::to_string)
}

/// Reads a binary or XML property list.
pub fn parse_plist(bytes: &[u8]) -> Result<Plist, NotPlist> {
    if bytes.len() >= 8 && &bytes[..8] == b"bplist00" {
        return parse_binary(bytes);
    }
    let text = utf8_text(bytes);
    if plist_tag(&text) {
        return parse_xml(&text);
    }
    Err(NotPlist("not a property list"))
}

/// `/<plist[\s>]/`.
fn plist_tag(text: &str) -> bool {
    let mut rest = text;
    while let Some(k) = rest.find("<plist") {
        let after = &rest[k + 6..];
        if after.chars().next().is_some_and(|c| c == '>' || js_space(c)) {
            return true;
        }
        rest = after;
    }
    false
}

/* ------------------------------------------------------------------ *
 * bplist00: a trailer that says where the offset table is, objects that refer to each other by number
 * ------------------------------------------------------------------ */

/// A read past the end: the TypeScript's DataView threw, or its arithmetic went NaN and ended in an error.
const PAST_END: NotPlist = NotPlist("past the end");

fn parse_binary(bytes: &[u8]) -> Result<Plist, NotPlist> {
    if bytes.len() < 40 {
        return Err(NotPlist("truncated binary property list"));
    }
    let byte = |at: f64| -> Result<u8, NotPlist> {
        if at >= 0.0 && at < bytes.len() as f64 && at.fract() == 0.0 {
            Ok(bytes[at as usize])
        } else {
            Err(PAST_END)
        }
    };
    let u64be = |at: usize| -> Result<u64, NotPlist> { bytes.get(at..at + 8).map(|b| u64::from_be_bytes(b.try_into().unwrap())).ok_or(PAST_END) };
    let trailer = bytes.len() - 32;
    let offset_size = bytes[trailer + 6] as f64;
    let ref_size = bytes[trailer + 7] as f64;
    let count = u64be(trailer + 8)? as f64;
    let top = u64be(trailer + 16)? as f64;
    let table_at = u64be(trailer + 24)? as f64;
    let uint = |at: f64, size: f64| -> Result<f64, NotPlist> {
        let mut v = 0.0;
        let mut i = 0.0;
        while i < size {
            v = v * 256.0 + byte(at + i)? as f64;
            i += 1.0;
        }
        Ok(v)
    };
    struct Reader<'a> {
        bytes: &'a [u8],
        offset_size: f64,
        ref_size: f64,
        count: f64,
        table_at: f64,
        depth: Vec<f64>,
        uint: &'a dyn Fn(f64, f64) -> Result<f64, NotPlist>,
        byte: &'a dyn Fn(f64) -> Result<u8, NotPlist>,
    }
    impl Reader<'_> {
        fn read(&mut self, r: f64) -> Result<Plist, NotPlist> {
            if r >= self.count || self.depth.contains(&r) {
                return Err(NotPlist("a bad object reference"));
            }
            self.depth.push(r);
            let at = (self.uint)(self.table_at + r * self.offset_size, self.offset_size);
            let out = at.and_then(|at| self.object(at));
            self.depth.pop();
            out
        }

        /// The length of an object: in the marker's low nibble, or an integer object after it when that is 0xf.
        fn length_at(&self, at: f64) -> Result<(f64, f64), NotPlist> {
            let low = (self.byte)(at)? & 0xf;
            if low != 0xf {
                return Ok((low as f64, at + 1.0));
            }
            let size = (1u64 << ((self.byte)(at + 1.0)? & 0xf)) as f64;
            Ok(((self.uint)(at + 2.0, size)?, at + 2.0 + size))
        }

        fn slice(&self, start: f64, n: f64) -> &[u8] {
            let s = (start.max(0.0) as usize).min(self.bytes.len());
            let e = ((start + n).max(0.0) as usize).min(self.bytes.len()).max(s);
            &self.bytes[s..e]
        }

        fn be(&self, at: f64, n: usize) -> Result<&[u8], NotPlist> {
            if at < 0.0 || at.fract() != 0.0 {
                return Err(PAST_END);
            }
            self.bytes.get(at as usize..at as usize + n).ok_or(PAST_END)
        }

        fn object(&mut self, at: f64) -> Result<Plist, NotPlist> {
            let marker = (self.byte)(at)?;
            let kind = marker >> 4;
            Ok(match kind {
                0x0 => Plist::Bool(marker == 0x09),
                0x1 => {
                    let size = (1u64 << (marker & 0xf)) as f64;
                    if size == 8.0 {
                        Plist::Num(i64::from_be_bytes(self.be(at + 1.0, 8)?.try_into().unwrap()) as f64)
                    } else {
                        Plist::Num((self.uint)(at + 1.0, size)?)
                    }
                }
                0x2 => {
                    if marker & 0xf == 2 {
                        Plist::Num(f32::from_be_bytes(self.be(at + 1.0, 4)?.try_into().unwrap()) as f64)
                    } else {
                        Plist::Num(f64::from_be_bytes(self.be(at + 1.0, 8)?.try_into().unwrap()))
                    }
                }
                0x3 => Plist::Date(time_clip((f64::from_be_bytes(self.be(at + 1.0, 8)?.try_into().unwrap()) + 978307200.0) * 1000.0)),
                0x4 => {
                    let (n, start) = self.length_at(at)?;
                    Plist::Data(self.slice(start, n).to_vec())
                }
                0x5 => {
                    let (n, start) = self.length_at(at)?;
                    Plist::Str(self.slice(start, n).iter().map(|&b| windows_1252(b)).collect())
                }
                0x6 => {
                    let (n, start) = self.length_at(at)?;
                    let mut s = Vec::new();
                    let mut i = 0.0;
                    while i < n {
                        let b = self.be(start + i * 2.0, 2)?;
                        s.push(u16::from_be_bytes([b[0], b[1]]));
                        i += 1.0;
                    }
                    Plist::Str(s)
                }
                0x8 => Plist::Num((self.uint)(at + 1.0, ((marker & 0xf) + 1) as f64)?),
                0xa => {
                    let (n, start) = self.length_at(at)?;
                    let mut out = Vec::new();
                    let mut i = 0.0;
                    while i < n {
                        let r = (self.uint)(start + i * self.ref_size, self.ref_size)?;
                        out.push(self.read(r)?);
                        i += 1.0;
                    }
                    Plist::Array(out)
                }
                0xd => {
                    let (n, start) = self.length_at(at)?;
                    let mut out: Vec<(Vec<u16>, Plist)> = Vec::new();
                    let mut i = 0.0;
                    while i < n {
                        let key = self.read((self.uint)(start + i * self.ref_size, self.ref_size)?)?;
                        let value = self.read((self.uint)(start + (n + i) * self.ref_size, self.ref_size)?)?;
                        out.push((js_string(&key), value));
                        i += 1.0;
                    }
                    Plist::Dict(out)
                }
                _ => return Err(NotPlist("an object of an unknown kind")),
            })
        }
    }
    let mut reader = Reader { bytes, offset_size, ref_size, count, table_at, depth: Vec::new(), uint: &uint, byte: &byte };
    reader.read(top)
}

/// `String(value)`, for a dict's key: what a key that is not a string becomes.
fn js_string(v: &Plist) -> Vec<u16> {
    match v {
        Plist::Str(s) => s.clone(),
        Plist::Num(n) => units(&crate::text::js_number(*n)),
        Plist::Bool(b) => units(if *b { "true" } else { "false" }),
        Plist::Data(d) => units(&d.iter().map(u8::to_string).collect::<Vec<_>>().join(",")),
        Plist::Array(a) => {
            let mut out = Vec::new();
            for (k, x) in a.iter().enumerate() {
                if k > 0 {
                    out.push(b',' as u16);
                }
                out.extend(js_string(x));
            }
            out
        }
        Plist::Dict(_) => units("[object Object]"),
        // A Date's String() depends on the time zone; a date as a key has never been seen.
        Plist::Date(_) => units("Invalid Date"),
    }
}

/// `new Date(ms)`'s TimeClip: past ±8.64e15 an invalid date, else the time truncated toward zero.
fn time_clip(ms: f64) -> f64 {
    if !ms.is_finite() || ms.abs() > 8.64e15 {
        f64::NAN
    } else {
        ms.trunc() + 0.0
    }
}

/* ------------------------------------------------------------------ *
 * XML: the elements Apple's DTD has
 * ------------------------------------------------------------------ */

/// JavaScript's `\s`: white space and line terminators.
fn js_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'
    )
}

fn js_trim(s: &[u16]) -> String {
    let text = String::from_utf16_lossy(s);
    text.trim_matches(js_space).to_string()
}

/// A token of `/<(\/?)(\w+)(?:\s[^>]*?)?(\/?)>|([^<]+)/g`: a tag (closing, its name, empty) or text.
enum Token {
    Tag { close: bool, name: String, empty: bool },
    Text(String),
}

fn tokens(text: &str) -> Vec<Token> {
    let b: Vec<char> = text.chars().collect();
    let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] != '<' {
            let start = i;
            while i < b.len() && b[i] != '<' {
                i += 1;
            }
            out.push(Token::Text(b[start..i].iter().collect()));
            continue;
        }
        // A tag, or a `<` that starts none (`<?xml`, `<!DOCTYPE`): then it is passed over.
        let mut p = i + 1;
        let close = b.get(p) == Some(&'/');
        if close {
            p += 1;
        }
        let name_start = p;
        while p < b.len() && word(b[p]) {
            p += 1;
        }
        let tag = (p > name_start).then(|| {
            let name: String = b[name_start..p].iter().collect();
            // `(\/?)>` right after the name, or white space and the fewest characters up to it.
            let end = |q: usize| -> Option<(usize, bool)> {
                if b.get(q) == Some(&'/') && b.get(q + 1) == Some(&'>') {
                    Some((q + 2, true))
                } else if b.get(q) == Some(&'>') {
                    Some((q + 1, false))
                } else {
                    None
                }
            };
            end(p)
                .or_else(|| {
                    if !b.get(p).is_some_and(|&c| js_space(c)) {
                        return None;
                    }
                    let mut q = p + 1;
                    loop {
                        if let Some(found) = end(q) {
                            return Some(found);
                        }
                        if q >= b.len() || b[q] == '>' {
                            return None;
                        }
                        q += 1;
                    }
                })
                .map(|(next, empty)| (next, name, empty))
        });
        match tag.flatten() {
            Some((next, name, empty)) => {
                out.push(Token::Tag { close, name, empty });
                i = next;
            }
            None => i += 1,
        }
    }
    out
}

/// `&amp;`, `&#x41;`, `&#65;`: the entities of the text, as the TypeScript replaced them.
fn unescape(s: &str) -> Result<Vec<u16>, NotPlist> {
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(k) = rest.find('&') {
        out.extend(rest[..k].encode_utf16());
        let after = &rest[k + 1..];
        let body_len = after.chars().take_while(|&c| c.is_ascii_alphanumeric() || c == '_' || c == '#').map(char::len_utf8).sum::<usize>();
        let body = &after[..body_len];
        let ok = after[body_len..].starts_with(';');
        let entity = if !ok || body.is_empty() {
            None
        } else if let Some(hex) = body.strip_prefix("#x").or_else(|| body.strip_prefix("#X")) {
            (!hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit())).then(|| u32::from_str_radix(hex, 16).unwrap_or(u32::MAX))
        } else if let Some(dec) = body.strip_prefix('#') {
            (!dec.is_empty() && dec.chars().all(|c| c.is_ascii_digit())).then(|| dec.parse::<u32>().unwrap_or(u32::MAX))
        } else if !body.contains('#') {
            match body {
                "amp" => Some('&' as u32),
                "lt" => Some('<' as u32),
                "gt" => Some('>' as u32),
                "quot" => Some('"' as u32),
                "apos" => Some('\'' as u32),
                _ => {
                    // An entity the TypeScript did not know stays as it is.
                    out.extend(format!("&{body};").encode_utf16());
                    rest = &after[body_len + 1..];
                    continue;
                }
            }
        } else {
            None
        };
        match entity {
            Some(code) => {
                // String.fromCodePoint: a RangeError past U+10FFFF; a surrogate stays one unit.
                if code > 0x10ffff {
                    return Err(NotPlist("an entity past U+10FFFF"));
                }
                match char::from_u32(code) {
                    Some(c) => out.extend(c.encode_utf16(&mut [0; 2]).iter()),
                    None => out.push(code as u16),
                }
                rest = &after[body_len + 1..];
            }
            None => {
                out.push(b'&' as u16);
                rest = after;
            }
        }
    }
    out.extend(rest.encode_utf16());
    Ok(out)
}

/// `Number(text)` for an integer or a real: what JavaScript makes of the text.
fn js_number_of(text: &str) -> f64 {
    let t = text.trim_matches(js_space);
    if t.is_empty() {
        return 0.0;
    }
    for (prefix, radix) in [("0x", 16), ("0X", 16), ("0o", 8), ("0O", 8), ("0b", 2), ("0B", 2)] {
        if let Some(digits) = t.strip_prefix(prefix) {
            return if !digits.is_empty() && digits.chars().all(|c| c.is_digit(radix)) {
                digits.chars().fold(0.0, |v, c| v * radix as f64 + c.to_digit(radix).unwrap() as f64)
            } else {
                f64::NAN
            };
        }
    }
    let unsigned = t.strip_prefix(['+', '-']).unwrap_or(t);
    if unsigned == "Infinity" {
        return if t.starts_with('-') { f64::NEG_INFINITY } else { f64::INFINITY };
    }
    // A decimal literal: digits, a point, digits (one of the two runs at least), an exponent.
    let b = unsigned.as_bytes();
    let mut i = 0;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    let int_digits = i;
    let mut frac_digits = 0;
    if i < b.len() && b[i] == b'.' {
        i += 1;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
            frac_digits += 1;
        }
    }
    if int_digits + frac_digits == 0 {
        return f64::NAN;
    }
    if i < b.len() && (b[i] == b'e' || b[i] == b'E') {
        i += 1;
        if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
            i += 1;
        }
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return f64::NAN;
        }
    }
    if i != b.len() {
        return f64::NAN;
    }
    t.parse::<f64>().unwrap_or(f64::NAN)
}

/// Days from 1970-01-01 to a date of the proleptic Gregorian calendar.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// `new Date(text)` of the date time string format (ISO 8601: `2026-10-17T09:30:00Z`), the one a
/// property list writes; NaN for anything else. A date and time without an offset would be local
/// time: such a date is taken as UTC here.
pub fn parse_date(text: &str) -> f64 {
    iso_date(text).map_or(f64::NAN, time_clip)
}

fn iso_date(text: &str) -> Option<f64> {
    let b = text.as_bytes();
    let num =
        |from: usize, n: usize| -> Option<i64> { b.get(from..from + n).filter(|s| s.iter().all(u8::is_ascii_digit)).map(|s| std::str::from_utf8(s).unwrap().parse().unwrap()) };
    let (year, mut p) = match b.first() {
        Some(&sign @ (b'+' | b'-')) => {
            let y = num(1, 6)?;
            if sign == b'-' && y == 0 {
                return None;
            }
            (if sign == b'-' { -y } else { y }, 7)
        }
        _ => (num(0, 4)?, 4),
    };
    let (mut month, mut day) = (1, 1);
    if b.get(p) == Some(&b'-') {
        month = num(p + 1, 2)?;
        p += 3;
        if b.get(p) == Some(&b'-') {
            day = num(p + 1, 2)?;
            p += 3;
        }
    }
    let (mut hour, mut minute, mut second, mut ms) = (0, 0, 0, 0);
    let mut offset = 0i64;
    if b.get(p) == Some(&b'T') {
        hour = num(p + 1, 2)?;
        if b.get(p + 3) != Some(&b':') {
            return None;
        }
        minute = num(p + 4, 2)?;
        p += 6;
        if b.get(p) == Some(&b':') {
            second = num(p + 1, 2)?;
            p += 3;
            if b.get(p) == Some(&b'.') {
                let start = p + 1;
                let mut q = start;
                while q < b.len() && b[q].is_ascii_digit() {
                    q += 1;
                }
                if q == start {
                    return None;
                }
                let digits = &text[start..q.min(start + 3)];
                ms = format!("{digits:0<3}").parse().unwrap();
                p = q;
            }
        }
        match b.get(p) {
            Some(b'Z') => p += 1,
            Some(&sign @ (b'+' | b'-')) => {
                let h = num(p + 1, 2)?;
                if b.get(p + 3) != Some(&b':') {
                    return None;
                }
                let m = num(p + 4, 2)?;
                offset = (h * 60 + m) * if sign == b'-' { -1 } else { 1 };
                p += 6;
            }
            _ => {}
        }
    }
    if p != b.len() || !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 24 || minute > 59 || second > 59 || (hour == 24 && (minute | second | ms) != 0) {
        return None;
    }
    let days = days_from_civil(year, month, day);
    Some(((days * 24 + hour) * 60 + minute - offset) as f64 * 60_000.0 + (second * 1000 + ms) as f64)
}

/// Base64 as `atob` reads it (white space already gone): None where atob throws.
fn base64(text: &str) -> Option<Vec<u8>> {
    let mut s: Vec<u8> = text.bytes().collect();
    if s.len().is_multiple_of(4) {
        if s.ends_with(b"==") {
            s.truncate(s.len() - 2);
        } else if s.ends_with(b"=") {
            s.truncate(s.len() - 1);
        }
    }
    if s.len() % 4 == 1 {
        return None;
    }
    let value = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for c in s {
        acc = acc << 6 | value(c)?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

fn parse_xml(text: &str) -> Result<Plist, NotPlist> {
    let tokens = tokens(text);
    let mut k = 0;
    // Skip to the first value inside <plist>.
    while k < tokens.len() && !matches!(&tokens[k], Token::Tag { name, .. } if name == "plist") {
        k += 1;
    }
    k += 1;
    let mut parser = Xml { tokens: &tokens, k };
    parser.value()
}

struct Xml<'a> {
    tokens: &'a [Token],
    k: usize,
}

impl Xml<'_> {
    fn skip_text(&mut self) {
        while self.k < self.tokens.len() && matches!(&self.tokens[self.k], Token::Text(t) if t.trim_matches(js_space).is_empty()) {
            self.k += 1;
        }
    }

    fn text_until(&mut self, tag: &str) -> Result<Vec<u16>, NotPlist> {
        let mut s = String::new();
        while self.k < self.tokens.len() && !matches!(&self.tokens[self.k], Token::Tag { close: true, name, .. } if name == tag) {
            if let Token::Text(t) = &self.tokens[self.k] {
                s.push_str(t);
            }
            self.k += 1;
        }
        self.k += 1;
        unescape(&s)
    }

    /// At a closing tag of `name` (or past the end).
    fn closing(&self, name: &str) -> bool {
        match self.tokens.get(self.k) {
            None => true,
            Some(Token::Tag { close: true, name: n, .. }) => n == name,
            _ => false,
        }
    }

    fn value(&mut self) -> Result<Plist, NotPlist> {
        self.skip_text();
        let token = self.tokens.get(self.k);
        self.k += 1;
        let (name, empty) = match token {
            Some(Token::Tag { close: false, name, empty }) => (name.as_str(), *empty),
            _ => return Err(NotPlist("unexpected end of a property list")),
        };
        Ok(match name {
            "dict" => {
                let mut out = Vec::new();
                if empty {
                    return Ok(Plist::Dict(out));
                }
                loop {
                    self.skip_text();
                    if self.closing("dict") {
                        self.k += 1;
                        return Ok(Plist::Dict(out));
                    }
                    let is_key = matches!(&self.tokens[self.k], Token::Tag { name, .. } if name == "key");
                    self.k += 1;
                    if !is_key {
                        return Err(NotPlist("a dict without a key"));
                    }
                    let key = self.text_until("key")?;
                    let value = self.value()?;
                    out.push((key, value));
                }
            }
            "array" => {
                let mut out = Vec::new();
                if empty {
                    return Ok(Plist::Array(out));
                }
                loop {
                    self.skip_text();
                    if self.closing("array") {
                        self.k += 1;
                        return Ok(Plist::Array(out));
                    }
                    out.push(self.value()?);
                }
            }
            "string" => Plist::Str(if empty { Vec::new() } else { self.text_until("string")? }),
            "integer" => Plist::Num(js_number_of(&String::from_utf16_lossy(&self.text_until("integer")?))),
            "real" => Plist::Num(js_number_of(&String::from_utf16_lossy(&self.text_until("real")?))),
            "true" | "false" => {
                if !empty {
                    self.text_until(name)?;
                }
                Plist::Bool(name == "true")
            }
            "date" => Plist::Date(parse_date(&js_trim(&self.text_until("date")?))),
            "data" => {
                if empty {
                    return Ok(Plist::Data(Vec::new()));
                }
                let text: String = String::from_utf16_lossy(&self.text_until("data")?).chars().filter(|&c| !js_space(c)).collect();
                Plist::Data(base64(&text).ok_or(NotPlist("bad base64"))?)
            }
            _ => return Err(NotPlist("an element the format does not have")),
        })
    }
}

/// The property list inside a provisioning profile, which is signed (CMS) around its XML.
pub fn profile_plist(bytes: &[u8]) -> Option<Plist> {
    let find = |needle: &[u8], from: usize| bytes.get(from..).and_then(|b| b.windows(needle.len()).position(|w| w == needle)).map(|k| k + from);
    let start = find(b"<?xml", 0)?;
    let end = find(b"</plist>", start)?;
    parse_xml(&utf8_text(&bytes[start..end + 8])).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(parse_date("2026-10-17T09:30:00Z"), 1792229400000.0);
        assert_eq!(parse_date("1970-01-01T00:00:00.5Z"), 500.0);
        assert_eq!(parse_date("2001-01-01"), 978307200000.0);
        assert!(parse_date("yesterday").is_nan());
    }

    #[test]
    fn xml() {
        let text = br#"<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist><plist version="1.0"><dict><key>A</key><string>x &amp; y</string><key>B</key><array><true/><integer> 0x10 </integer></array><key>C</key><data>aGk=</data></dict></plist>"#;
        let v = parse_plist(text).unwrap();
        assert_eq!(v.get("A").and_then(Plist::text), Some(units("x & y").as_slice()));
        assert_eq!(v.get("B"), Some(&Plist::Array(vec![Plist::Bool(true), Plist::Num(16.0)])));
        assert_eq!(v.get("C"), Some(&Plist::Data(b"hi".to_vec())));
    }

    #[test]
    fn numbers() {
        assert_eq!([js_number_of(" 12 "), js_number_of(""), js_number_of("1e3"), js_number_of(".5")], [12.0, 0.0, 1000.0, 0.5]);
        assert!(js_number_of("inf").is_nan() && js_number_of("1.2.3").is_nan());
    }
}
