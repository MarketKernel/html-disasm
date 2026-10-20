//! The AArch64 assembler: one line of text in, one 32-bit word out — the
//! reverse of decode.rs, for patching an instruction in place.
//!
//! It reads the syntax the decoder prints (LLVM's generic syntax), so a line
//! copied from the listing and edited assembles back, and the spellings people
//! type besides: decimal immediates, `cs` for `hs`, `movz` for `mov`, a
//! negative `add` immediate, an `ldr` offset only `ldur` can hold. Branch and
//! address targets are absolute addresses, as llvm-objdump prints them, or
//! names the caller resolves (`Resolve`).
//!
//! Every word is decoded again before it is returned, and the decoded text is
//! compared with the input by meaning: both are brought to one form (aliases
//! to the instruction they stand for, numbers to their values) and must agree.
//! A word that would decode to anything else is an error, never a patch.
//!
//! A port of src/core/arm64/encode.ts. Numbers are what JavaScript made of
//! them there: integers of any size (BigInt; here an i128, and `Big` past it,
//! for what an error says), addresses and distances as doubles.

use super::decode::{barrier_name, decode, hint_name};
use super::simd::fp_imm;
use super::types::{format_insn, CONDITIONS};
use crate::text::js_number;

/* ------------------------------------------------------------------ *
 * What goes wrong
 * ------------------------------------------------------------------ */

/// Why a line does not assemble; the page words it in its language.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AsmError {
    /// Nothing but a comment, or nothing at all.
    Empty,
    /// An operand that is not one: the text.
    Unreadable(String),
    /// Vector registers, SVE, or a mnemonic this assembler does not know.
    Unsupported,
    /// An immediate that cannot be encoded: `#0x…`, or a float as written.
    Immediate(String),
    Offset(String),
    /// An offset that is not a multiple of the access size: the offset, the size.
    Multiple(String, u32),
    Unpredictable,
    /// A target that is not a multiple of 4 bytes away.
    Align,
    /// A target too far: the distance, as JavaScript writes the number.
    Far(String),
    /// A name the caller does not know.
    Name(String),
    /// The operands do not fit the mnemonic.
    Operands(String),
    /// The word decodes to other text than was entered: that text.
    Differs(String),
}

/// What goes wrong inside: None means the operands do not fit the mnemonic.
struct Problem(Option<AsmError>);

type R<T> = Result<T, Problem>;

fn fail<T>() -> R<T> {
    Err(Problem(None))
}

fn fail_with<T>(e: AsmError) -> R<T> {
    Err(Problem(Some(e)))
}

/// Gives the address of a name: a function, a label, a symbol (as a JavaScript number), or None.
pub trait Resolve {
    fn resolve(&self, name: &str) -> Option<f64>;
}

/// No names: what the decoded text is read back with.
struct NoNames;

impl Resolve for NoNames {
    fn resolve(&self, _: &str) -> Option<f64> {
        None
    }
}

/* ------------------------------------------------------------------ *
 * Integers past i128
 * ------------------------------------------------------------------ */

/// An integer that does not fit an i128 (JavaScript kept it as a BigInt): its sign and magnitude.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Big {
    neg: bool,
    /// Little-endian 32-bit limbs, no zero at the top.
    mag: Vec<u32>,
}

impl Big {
    fn parse(digits: &str, radix: u32) -> Big {
        let mut mag: Vec<u32> = Vec::new();
        for c in digits.chars() {
            let mut carry = c.to_digit(radix).unwrap_or(0) as u64;
            for limb in mag.iter_mut() {
                let v = *limb as u64 * radix as u64 + carry;
                *limb = v as u32;
                carry = v >> 32;
            }
            if carry != 0 {
                mag.push(carry as u32);
            }
        }
        Big { neg: false, mag }
    }

    fn from_i128(v: i128) -> Big {
        let mut m = v.unsigned_abs();
        let mut mag = Vec::new();
        while m != 0 {
            mag.push(m as u32);
            m >>= 32;
        }
        Big { neg: v < 0, mag }
    }

    fn bits(&self) -> usize {
        self.mag.last().map_or(0, |top| (self.mag.len() - 1) * 32 + (32 - top.leading_zeros() as usize))
    }

    /// The low 128 bits of the magnitude.
    fn low(&self) -> u128 {
        self.mag.iter().take(4).enumerate().fold(0u128, |v, (k, &l)| v | (l as u128) << (32 * k))
    }

    /// The value as an i128 when it fits.
    fn small(&self) -> Option<i128> {
        if self.bits() > 127 {
            return None;
        }
        let m = self.low() as i128;
        Some(if self.neg { -m } else { m })
    }

    fn add(&self, other: &Big) -> Big {
        let cmp = |a: &[u32], b: &[u32]| a.len().cmp(&b.len()).then_with(|| a.iter().rev().cmp(b.iter().rev()));
        if self.neg == other.neg {
            let mut out = Vec::new();
            let mut carry = 0u64;
            for k in 0..self.mag.len().max(other.mag.len()) {
                let v = *self.mag.get(k).unwrap_or(&0) as u64 + *other.mag.get(k).unwrap_or(&0) as u64 + carry;
                out.push(v as u32);
                carry = v >> 32;
            }
            if carry != 0 {
                out.push(carry as u32);
            }
            return Big { neg: self.neg, mag: out }.trimmed();
        }
        let (a, b, neg) = if cmp(&self.mag, &other.mag).is_ge() { (self, other, self.neg) } else { (other, self, other.neg) };
        let mut out = Vec::new();
        let mut borrow = 0i64;
        for k in 0..a.mag.len() {
            let mut v = a.mag[k] as i64 - *b.mag.get(k).unwrap_or(&0) as i64 - borrow;
            borrow = 0;
            if v < 0 {
                v += 1 << 32;
                borrow = 1;
            }
            out.push(v as u32);
        }
        Big { neg, mag: out }.trimmed()
    }

    fn trimmed(mut self) -> Big {
        while self.mag.last() == Some(&0) {
            self.mag.pop();
        }
        if self.mag.is_empty() {
            self.neg = false;
        }
        self
    }

    /// `v < 0 ? '-0x…' : '0x…'`
    fn hex(&self) -> String {
        let mut digits = String::new();
        for (k, limb) in self.mag.iter().rev().enumerate() {
            if k == 0 {
                digits.push_str(&format!("{limb:x}"));
            } else {
                digits.push_str(&format!("{limb:08x}"));
            }
        }
        if digits.is_empty() {
            digits.push('0');
        }
        format!("{}0x{digits}", if self.neg { "-" } else { "" })
    }

    /// `Number(v)`: rounded to nearest, ties to even.
    fn number(&self) -> f64 {
        let bits = self.bits();
        let m = if bits <= 128 {
            self.low() as f64
        } else {
            // The top 128 bits, the lowest of them set when anything below them is: the rounding is the same.
            let shift = bits - 128;
            let mut top = 0u128;
            for k in (0..128).rev() {
                let bit = shift + k;
                if self.mag[bit / 32] >> (bit % 32) & 1 != 0 {
                    top |= 1 << k;
                }
            }
            let sticky = (0..shift).any(|bit| self.mag[bit / 32] >> (bit % 32) & 1 != 0);
            (top | sticky as u128) as f64 * 2f64.powi(shift as i32)
        };
        if self.neg {
            -m
        } else {
            m
        }
    }
}

/// An integer as JavaScript's BigInt held it: the i128 for every comparison (saturated past it),
/// and the value itself when it is larger, for what errors and distances say.
#[derive(Clone, Debug)]
struct Int {
    v: i128,
    big: Option<Box<Big>>,
}

impl Int {
    fn of(v: i128) -> Int {
        Int { v, big: None }
    }

    fn from_big(b: Big) -> Int {
        match b.small() {
            Some(v) => Int::of(v),
            None => Int { v: if b.neg { i128::MIN } else { i128::MAX }, big: Some(Box::new(b)) },
        }
    }

    /// `#${hex(v)}`
    fn shown(&self) -> String {
        match &self.big {
            Some(b) => format!("#{}", b.hex()),
            None => format!("#{}", hex(self.v)),
        }
    }

    /// `Number(v)`
    fn number(&self) -> f64 {
        match &self.big {
            Some(b) => b.number(),
            None => self.v as f64,
        }
    }

    /// Whether `v % bytes` is nonzero (bytes a power of two).
    fn misaligned(&self, bytes: i128) -> bool {
        match &self.big {
            Some(b) => b.low() & (bytes as u128 - 1) != 0,
            None => self.v % bytes != 0,
        }
    }
}

fn hex(v: i128) -> String {
    if v < 0 {
        format!("-0x{:x}", v.unsigned_abs())
    } else {
        format!("0x{v:x}")
    }
}

/* ------------------------------------------------------------------ *
 * Operands
 * ------------------------------------------------------------------ */

#[derive(Clone, Debug)]
struct Reg {
    cls: char,
    n: u32,
    sp: bool,
}

#[derive(Clone, Debug)]
struct Shift {
    s: &'static str,
    amount: u32,
    given: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Off,
    Pre,
    Post,
}

#[derive(Clone, Debug)]
struct Mem {
    base: Reg,
    off: Int,
    bare: bool,
    index: Option<Reg>,
    ext: Option<Shift>,
    mode: Mode,
}

#[derive(Clone, Debug)]
enum Operand {
    Reg(Reg),
    /// An integer: an immediate, or a target address (a bare number or a resolved name).
    Imm(Int),
    Float(f64),
    /// A condition, a barrier or prefetch name, a BTI target.
    Word(String),
    Shift(Shift),
    Mem(Box<Mem>),
}

use Operand as O;

struct Line {
    m: String,
    ops: Vec<Operand>,
}

fn bad_immediate(v: &Int) -> AsmError {
    AsmError::Immediate(v.shown())
}

fn bad_small(v: i128) -> AsmError {
    AsmError::Immediate(format!("#{}", hex(v)))
}

fn bad_offset(v: &Int) -> AsmError {
    AsmError::Offset(v.shown())
}

fn unpredictable<T>() -> R<T> {
    fail_with(AsmError::Unpredictable)
}

fn unsupported<T>() -> R<T> {
    fail_with(AsmError::Unsupported)
}

fn unreadable<T>(text: &str) -> R<T> {
    fail_with(AsmError::Unreadable(text.to_string()))
}

fn cond_name(w: &str) -> &str {
    match w {
        "cs" => "hs",
        "cc" => "lo",
        _ => w,
    }
}

fn cond_index(w: &str) -> Option<usize> {
    CONDITIONS.iter().position(|c| *c == w)
}

const EXTENDS: [&str; 8] = ["uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw", "sxtx"];
const SHIFT_KINDS: [&str; 12] = ["lsl", "lsr", "asr", "ror", "uxtb", "uxth", "uxtw", "uxtx", "sxtb", "sxth", "sxtw", "sxtx"];

/// JavaScript's `\s`.
fn js_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'
    )
}

fn js_trim(s: &str) -> &str {
    s.trim_matches(js_space)
}

fn is_word(w: &str) -> bool {
    cond_index(w).is_some()
        || matches!(w, "cs" | "cc" | "oshnxs" | "nshnxs" | "ishnxs" | "synxs" | "c" | "j" | "jc" | "r" | "csync" | "dsync")
        || (0..16).any(|n| barrier_name(n) == Some(w))
}

/// `^(pld|pli|pst)(l[123]|slc)(keep|strm)$`: the prfop's three fields.
fn prfop_parts(w: &str) -> Option<(u32, u32, u32)> {
    let kind = ["pld", "pli", "pst"].iter().position(|k| w.starts_with(k))?;
    let rest = &w[3..];
    let target = ["l1", "l2", "l3", "slc"].iter().position(|t| rest.starts_with(t))?;
    let rest = &rest[if target == 3 { 3 } else { 2 }..];
    let policy = match rest {
        "keep" => 0,
        "strm" => 1,
        _ => return None,
    };
    Some((kind as u32, target as u32, policy))
}

/// `^#?\s*([+-]?)\s*(0x[0-9a-f]+|\d+)$`
fn parse_integer(text: &str) -> Option<Int> {
    let mut s = text.strip_prefix('#').unwrap_or(text);
    s = s.trim_start_matches(js_space);
    let neg = s.starts_with('-');
    if neg || s.starts_with('+') {
        s = &s[1..];
    }
    s = s.trim_start_matches(js_space);
    let big = if let Some(h) = s.strip_prefix("0x") {
        if h.is_empty() || !h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return None;
        }
        Big::parse(h, 16)
    } else {
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        Big::parse(s, 10)
    };
    Some(Int::from_big(Big { neg, ..big }.trimmed()))
}

/// `^#?\s*([+-]?(?:\d+\.\d*|\.\d+|\d+)(?:e[+-]?\d+)?)$`, read as JavaScript reads the number.
fn parse_float_text(text: &str) -> Option<f64> {
    let s = text.strip_prefix('#').unwrap_or(text).trim_start_matches(js_space);
    let b = s.as_bytes();
    let mut i = usize::from(matches!(b.first(), Some(b'+' | b'-')));
    let int_start = i;
    while i < b.len() && b[i].is_ascii_digit() {
        i += 1;
    }
    let int_digits = i - int_start;
    let mut frac_digits = 0;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let f = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        frac_digits = i - f;
        if int_digits == 0 && frac_digits == 0 {
            return None;
        }
    } else if int_digits == 0 {
        return None;
    }
    if b.get(i) == Some(&b'e') {
        i += 1;
        if matches!(b.get(i), Some(b'+' | b'-')) {
            i += 1;
        }
        let e = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == e {
            return None;
        }
    }
    if i != b.len() {
        return None;
    }
    let _ = frac_digits;
    // Rust reads `1.` and `.5` as JavaScript does; an empty fraction needs a digit after the point for the exponent.
    let text = s.replace(".e", ".0e");
    let text = if text.ends_with('.') { format!("{text}0") } else { text };
    text.parse().ok()
}

fn parse_reg(text: &str) -> Option<Reg> {
    let special = |cls: char, n: u32, sp: bool| Some(Reg { cls, n, sp });
    match text {
        "sp" => return special('x', 31, true),
        "wsp" => return special('w', 31, true),
        "xzr" => return special('x', 31, false),
        "wzr" => return special('w', 31, false),
        "fp" => return special('x', 29, false),
        "lr" => return special('x', 30, false),
        _ => {}
    }
    let mut chars = text.chars();
    let cls = chars.next()?;
    if !"xwbhsdq".contains(cls) {
        return None;
    }
    let digits = chars.as_str();
    let ok = match digits.as_bytes() {
        [d] => d.is_ascii_digit(),
        [a, d] => d.is_ascii_digit() && (*a == b'1' || *a == b'2' || (*a == b'3' && (*d == b'0' || *d == b'1'))),
        _ => false,
    };
    if !ok {
        return None;
    }
    let n: u32 = digits.parse().ok()?;
    if n == 31 && (cls == 'x' || cls == 'w') {
        return None;
    }
    Some(Reg { cls, n, sp: false })
}

/// `^(lsl|lsr|asr|ror|uxt[bhwx]|sxt[bhwx])(?:\s+(.+))?$`; Ok(None) when the text is not one.
fn parse_shift(text: &str) -> R<Option<Shift>> {
    let Some(&s) = SHIFT_KINDS.iter().find(|k| text.starts_with(*k)) else { return Ok(None) };
    let rest = &text[s.len()..];
    if rest.is_empty() {
        // Only an extend may leave its amount out.
        return if s.contains("xt") { Ok(Some(Shift { s, amount: 0, given: false })) } else { unreadable(text) };
    }
    let amount_text = rest.trim_start_matches(js_space);
    if amount_text.len() == rest.len() || amount_text.is_empty() || amount_text.contains(['\n', '\r', '\u{2028}', '\u{2029}']) {
        return Ok(None);
    }
    let Some(amount) = parse_integer(amount_text) else { return unreadable(text) };
    if amount.v < 0 || amount.v > 63 {
        return fail_with(bad_immediate(&amount));
    }
    Ok(Some(Shift { s, amount: amount.v as u32, given: true }))
}

/// `^\[([^\]]*)\]\s*(!?)$`
fn parse_mem(text: &str) -> R<Mem> {
    let Some(inner_end) = text.strip_prefix('[').and_then(|r| r.find(']')) else { return unreadable(text) };
    let inner = &text[1..1 + inner_end];
    let after = text[2 + inner_end..].trim_start_matches(js_space);
    let pre = match after {
        "" => false,
        "!" => true,
        _ => return unreadable(text),
    };
    let parts: Vec<&str> = inner.split(',').map(js_trim).collect();
    let Some(base) = parse_reg(parts[0]) else { return unreadable(text) };
    let mut mem = Mem { base, off: Int::of(0), bare: parts.len() == 1, index: None, ext: None, mode: if pre { Mode::Pre } else { Mode::Off } };
    if parts.len() > 1 {
        if let Some(off) = parse_integer(parts[1]) {
            if parts.len() > 2 {
                return unreadable(text);
            }
            mem.off = off;
        } else {
            let Some(index) = parse_reg(parts[1]) else { return unreadable(text) };
            if pre {
                return unreadable(text);
            }
            mem.index = Some(index);
            if parts.len() > 2 {
                let ext = parse_shift(parts[2])?;
                let Some(ext) = ext.filter(|_| parts.len() <= 3) else { return unreadable(text) };
                mem.ext = Some(ext);
            }
        }
    }
    Ok(mem)
}

/// Splits at the commas outside brackets: each piece and where it starts.
fn split(text: &str) -> Vec<(&str, usize)> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut start = 0;
    for (i, c) in text.char_indices() {
        match c {
            '[' => depth += 1,
            ']' => depth -= 1,
            ',' if depth == 0 => {
                out.push((&text[start..i], start));
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push((&text[start..], start));
    out
}

fn resolve_name(name: &str, resolve: &dyn Resolve) -> R<Int> {
    if let Some(direct) = resolve.resolve(name) {
        return Ok(Int::of(direct as i128));
    }
    // name+0x10, name-8: an address past a symbol (/^(.*?)\s*([+-])\s*(0x[0-9a-f]+|\d+)$/i).
    let line_end = name.find(['\n', '\r', '\u{2028}', '\u{2029}']);
    for (i, _) in name.char_indices() {
        if line_end.is_some_and(|e| i > e) {
            break;
        }
        let rest = name[i..].trim_start_matches(js_space);
        let Some(sign) = rest.chars().next().filter(|c| *c == '+' || *c == '-') else { continue };
        let number = rest[1..].trim_start_matches(js_space).to_ascii_lowercase();
        let value = if let Some(h) = number.strip_prefix("0x") {
            (!h.is_empty() && h.bytes().all(|b| b.is_ascii_hexdigit())).then(|| Big::parse(h, 16))
        } else {
            (!number.is_empty() && number.bytes().all(|b| b.is_ascii_digit())).then(|| Big::parse(&number, 10))
        };
        let Some(value) = value else { continue };
        let Some(base) = resolve.resolve(&name[..i]) else { break };
        let offset = Big { neg: sign == '-', ..value }.trimmed();
        return Ok(Int::from_big(Big::from_i128(base as i128).add(&offset)));
    }
    fail_with(AsmError::Name(name.to_string()))
}

/// `text.replace(/(\/\/|;).*$/, '')`: the first comment that runs to the end without a line break.
fn strip_comment(text: &str) -> &str {
    for (i, _) in text.char_indices() {
        let rest = &text[i..];
        let len = if rest.starts_with("//") {
            2
        } else if rest.starts_with(';') {
            1
        } else {
            continue;
        };
        if !rest[len..].contains(['\n', '\r', '\u{2028}', '\u{2029}']) {
            return &text[..i];
        }
    }
    text
}

/// `raw.replace(/\s+<[^>]*>$/, '')`: without the `<symbol>` llvm-objdump writes after a target —
/// from the first `<` that only whitespace precedes and no `>` follows before the closing one.
fn strip_symbol(text: &str) -> &str {
    let Some(body) = text.strip_suffix('>') else { return text };
    let from = body.rfind('>').map_or(0, |k| k + 1);
    for (j, c) in body[from..].char_indices() {
        if c != '<' {
            continue;
        }
        let head = &text[..from + j];
        let trimmed = head.trim_end_matches(js_space);
        if trimmed.len() < head.len() {
            return trimmed;
        }
    }
    text
}

/// `^([vzp]\d+\b|\{)`: a vector register or list.
fn vector_like(text: &str) -> bool {
    let b = text.as_bytes();
    if b.first() == Some(&b'{') {
        return true;
    }
    if !matches!(b.first(), Some(b'v' | b'z' | b'p')) {
        return false;
    }
    let digits = b[1..].iter().take_while(|c| c.is_ascii_digit()).count();
    digits > 0 && !b.get(1 + digits).is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

/// One line into a mnemonic and operands. Comments (`//`, `;`) and the `<symbol>` llvm-objdump
/// adds after a target are dropped. Anything that is not a register, number, shift or keyword is a
/// name, and runs to the end of the line: a demangled name may hold commas and brackets.
fn parse(text: &str, resolve: &dyn Resolve) -> R<Option<Line>> {
    let source = js_trim(strip_comment(text));
    if source.is_empty() {
        return Ok(None);
    }
    let head_end = source.find(js_space).unwrap_or(source.len());
    let mut m = source[..head_end].to_lowercase();
    let rest = source[head_end..].trim_start_matches(js_space);
    for b in ["b.", "bc."] {
        if let Some(c) = m.strip_prefix(b) {
            if c == "cs" || c == "cc" {
                m = format!("{b}{}", cond_name(c));
            }
        }
    }
    let mut ops: Vec<Operand> = Vec::new();
    if rest.is_empty() {
        return Ok(Some(Line { m, ops }));
    }
    for (piece, start) in split(rest) {
        let raw = js_trim(piece);
        let lowered = raw.to_lowercase();
        let lower = strip_symbol(&lowered);
        if lower.is_empty() {
            return unreadable(rest);
        }
        if lower.starts_with('[') {
            ops.push(O::Mem(Box::new(parse_mem(lower)?)));
            continue;
        }
        if let Some(integer) = parse_integer(lower) {
            // `[x0], #8` is one operand: post-index.
            if let Some(O::Mem(last)) = ops.last_mut() {
                if last.bare && last.mode == Mode::Off {
                    last.mode = Mode::Post;
                    last.off = integer;
                    continue;
                }
            }
            ops.push(O::Imm(integer));
            continue;
        }
        if let Some(float) = parse_float_text(lower) {
            ops.push(O::Float(float));
            continue;
        }
        if let Some(r) = parse_reg(lower) {
            ops.push(O::Reg(r));
            continue;
        }
        if let Some(s) = parse_shift(lower)? {
            ops.push(O::Shift(s));
            continue;
        }
        if is_word(lower) || prfop_parts(lower).is_some() {
            ops.push(O::Word(lower.to_string()));
            continue;
        }
        if lower.starts_with('#') {
            return unreadable(raw);
        }
        // Vector registers and lists (NEON, SVE, SME) are outside what this assembler knows.
        if vector_like(lower) {
            return unsupported();
        }
        ops.push(O::Imm(resolve_name(js_trim(&rest[start..]), resolve)?));
        break;
    }
    Ok(Some(Line { m, ops }))
}

/* ------------------------------------------------------------------ *
 * Operand checks
 * ------------------------------------------------------------------ */

fn reg_name(r: &Reg) -> String {
    if r.n == 31 && (r.cls == 'x' || r.cls == 'w') {
        return if r.sp {
            if r.cls == 'x' {
                "sp".into()
            } else {
                "wsp".into()
            }
        } else {
            format!("{}zr", r.cls)
        };
    }
    format!("{}{}", r.cls, r.n)
}

fn zr_like(r: &Reg) -> Reg {
    Reg { cls: r.cls, n: 31, sp: false }
}

fn as_reg(op: Option<&Operand>) -> Option<&Reg> {
    match op {
        Some(O::Reg(r)) => Some(r),
        _ => None,
    }
}

fn is_gp(op: Option<&Operand>) -> bool {
    as_reg(op).is_some_and(|r| r.cls == 'x' || r.cls == 'w')
}

fn is_zr(op: Option<&Operand>) -> bool {
    is_gp(op) && as_reg(op).is_some_and(|r| r.n == 31 && !r.sp)
}

fn is_sp(op: Option<&Operand>) -> bool {
    is_gp(op) && as_reg(op).is_some_and(|r| r.n == 31 && r.sp)
}

fn as_imm(op: Option<&Operand>) -> Option<&Int> {
    match op {
        Some(O::Imm(v)) => Some(v),
        _ => None,
    }
}

fn count(ops: &[Operand], allowed: &[usize]) -> R<()> {
    if allowed.contains(&ops.len()) {
        Ok(())
    } else {
        fail()
    }
}

/// A general register; register 31 must be what the slot means — sp or the zero register.
fn gpr(op: Option<&Operand>, sp: bool) -> R<Reg> {
    let Some(r) = as_reg(op).filter(|r| r.cls == 'x' || r.cls == 'w') else { return fail() };
    if r.n == 31 && r.sp != sp {
        return fail();
    }
    Ok(r.clone())
}

fn gp(op: Option<&Operand>) -> R<Reg> {
    gpr(op, false)
}

fn xreg(op: Option<&Operand>, sp: bool) -> R<u32> {
    let r = gpr(op, sp)?;
    if r.cls != 'x' {
        return fail();
    }
    Ok(r.n)
}

fn wreg(op: Option<&Operand>) -> R<u32> {
    let r = gp(op)?;
    if r.cls != 'w' {
        return fail();
    }
    Ok(r.n)
}

fn sf_of(r: &Reg) -> u32 {
    u32::from(r.cls == 'x')
}

/// The sf bit of registers that must all be the same width.
fn same_width(regs: &[&Reg]) -> R<u32> {
    let sf = sf_of(regs[0]);
    if regs.iter().any(|r| sf_of(r) != sf) {
        return fail();
    }
    Ok(sf)
}

fn immediate(op: Option<&Operand>) -> R<Int> {
    match as_imm(op) {
        Some(v) => Ok(v.clone()),
        None => fail(),
    }
}

fn in_range(op: Option<&Operand>, lo: i64, hi: i64) -> R<i64> {
    let v = immediate(op)?;
    if v.v < lo as i128 || v.v > hi as i128 {
        return fail_with(bad_immediate(&v));
    }
    Ok(v.v as i64)
}

fn condition(op: Option<&Operand>) -> R<u32> {
    let Some(O::Word(w)) = op else { return fail() };
    match cond_index(cond_name(w)) {
        Some(c) => Ok(c as u32),
        None => fail(),
    }
}

fn shift_amount(op: Option<&Operand>, kinds: &[&str], limit: u32) -> R<(u32, u32)> {
    let Some(O::Shift(s)) = op else { return fail() };
    let Some(kind) = kinds.iter().position(|k| *k == s.s) else { return fail() };
    if s.amount >= limit {
        return fail_with(bad_small(s.amount as i128));
    }
    Ok((kind as u32, s.amount))
}

/// A value for a register of `width` bits, as LLVM takes it: unsigned or negative, wrapped to the width.
fn fit_width(v: &Int, width: u32) -> R<i128> {
    if v.v < -(1i128 << (width - 1)) || v.v >= 1i128 << width {
        return fail_with(bad_immediate(v));
    }
    Ok(as_uint(width, v.v))
}

/// `BigInt.asUintN(width, v)`
fn as_uint(width: u32, v: i128) -> i128 {
    if width >= 128 {
        return v;
    }
    v & ((1i128 << width) - 1)
}

/// A pc-relative field of `width` bits counting `unit`-byte steps (distances as doubles, as JavaScript had them).
fn relative(distance: f64, unit: f64, width: u32, shown: f64) -> R<u32> {
    if distance % unit != 0.0 {
        return fail_with(AsmError::Align);
    }
    let steps = distance / unit;
    let half = 2f64.powi(width as i32 - 1);
    if steps < -half || steps >= half {
        return fail_with(AsmError::Far(js_number(shown)));
    }
    Ok((steps as i64 as u32) & ((1u32 << width) - 1))
}

fn target(op: Option<&Operand>) -> R<f64> {
    Ok(immediate(op)?.number())
}

/* ------------------------------------------------------------------ *
 * Logical immediates
 * ------------------------------------------------------------------ */

/// The N:immr:imms of a bitmask immediate: the value must be a rotated run of ones repeated across
/// the register (the reverse of decode_bit_mask). The element is the smallest period the value repeats with.
pub fn encode_bit_mask(value: u64, width: u32) -> Option<(u32, u32, u32)> {
    let mask = if width == 64 { u64::MAX } else { (1u64 << width) - 1 };
    let v = value & mask;
    if v == 0 || v == mask {
        return None;
    }
    let mut size = width;
    while size > 2 {
        let half = size / 2;
        let half_mask = (1u64 << half) - 1;
        if v & half_mask != (v >> half) & half_mask {
            break;
        }
        size /= 2;
    }
    let elem_mask = if size == 64 { u64::MAX } else { (1u64 << size) - 1 };
    let elem = v & elem_mask;
    let ones = elem.count_ones();
    let run = if ones == 64 { u64::MAX } else { (1u64 << ones) - 1 };
    // elem is the run rotated right by immr: rotating it left by as much gives the run back.
    for r in 0..size {
        let rotated = if r == 0 { elem } else { ((elem << r) | (elem >> (size - r))) & elem_mask };
        if rotated == run {
            return Some((u32::from(size == 64), r, (!(size * 2 - 1) & 0x3f) | (ones - 1)));
        }
    }
    None
}

/// The imm8 of fmov: the values ±(16…31)/16 × 2^(−3…4).
fn fp_imm8(value: f64) -> Option<u32> {
    (0..256).find(|&i| fp_imm(i) == value)
}

/* ------------------------------------------------------------------ *
 * Data processing
 * ------------------------------------------------------------------ */

fn zero() -> Operand {
    O::Imm(Int::of(0))
}

/// ADD, SUB, ADDS, SUBS: immediate, shifted register or extended register.
fn add_sub(op: u32, s: u32, ops: &[Operand]) -> R<u32> {
    count(ops, &[3, 4])?;
    let (d, n, x, extra) = (ops.first(), ops.get(1), ops.get(2), ops.get(3));
    if !is_gp(d) || !is_gp(n) {
        return fail();
    }
    let mut op = op;
    if let Some(xv) = as_imm(x) {
        let rd = gpr(d, s == 0)?;
        let rn = gpr(n, true)?;
        let sf = same_width(&[&rd, &rn])?;
        let mut v = xv.v;
        let mut sh = 0;
        if extra.is_some() {
            let (_, amount) = shift_amount(extra, &["lsl"], 13)?;
            if amount != 0 && amount != 12 {
                return fail_with(bad_small(amount as i128));
            }
            sh = amount / 12;
        }
        // LLVM takes add #-n as sub #n, and a multiple of 4096 as the shifted form.
        if v < 0 {
            v = v.saturating_neg();
            op ^= 1;
        }
        if sh == 0 && v > 0xfff && v & 0xfff == 0 && v >> 12 <= 0xfff {
            v >>= 12;
            sh = 1;
        }
        if v > 0xfff {
            return fail_with(bad_immediate(xv));
        }
        return Ok(sf << 31 | op << 30 | s << 29 | 0x11000000 | sh << 22 | (v as u32) << 10 | rn.n << 5 | rd.n);
    }
    let rm = gp(x)?;
    let extend = matches!(extra, Some(O::Shift(e)) if EXTENDS.contains(&e.s));
    // The shifted form reads register 31 as zr; sp needs the extended form.
    if extend || (s == 0 && is_sp(d)) || is_sp(n) {
        let rd = gpr(d, s == 0)?;
        let rn = gpr(n, true)?;
        let sf = same_width(&[&rd, &rn])?;
        let mut option: i32 = if sf == 1 { 3 } else { 2 };
        let mut amount = 0;
        if let Some(extra) = extra {
            let O::Shift(ext) = extra else { return fail() };
            if ext.s != "lsl" {
                option = EXTENDS.iter().position(|e| *e == ext.s).map_or(-1, |p| p as i32);
            }
            if option < 0 {
                return fail();
            }
            amount = ext.amount;
            if amount > 4 {
                return fail_with(bad_small(amount as i128));
            }
        }
        if (rm.cls == 'x') != (sf == 1 && option & 3 == 3) {
            return fail();
        }
        return Ok(sf << 31 | op << 30 | s << 29 | 0x0b200000 | rm.n << 16 | (option as u32) << 13 | amount << 10 | rn.n << 5 | rd.n);
    }
    let rd = gp(d)?;
    let rn = gp(n)?;
    let sf = same_width(&[&rd, &rn, &rm])?;
    let (kind, amount) = if extra.is_some() { shift_amount(extra, &["lsl", "lsr", "asr"], if sf == 1 { 64 } else { 32 })? } else { (0, 0) };
    Ok(sf << 31 | op << 30 | s << 29 | 0x0b000000 | kind << 22 | rm.n << 16 | amount << 10 | rn.n << 5 | rd.n)
}

/// AND, ORR, EOR, ANDS and their inverted forms: bitmask immediate or shifted register.
fn logical(opc: u32, invert: u32, ops: &[Operand]) -> R<u32> {
    count(ops, &[3, 4])?;
    let (d, n, x, extra) = (ops.first(), ops.get(1), ops.get(2), ops.get(3));
    if let Some(xv) = as_imm(x) {
        if extra.is_some() {
            return fail();
        }
        let rd = gpr(d, opc != 3)?;
        let rn = gp(n)?;
        let sf = same_width(&[&rd, &rn])?;
        let width = if sf == 1 { 64 } else { 32 };
        let mut v = fit_width(xv, width)?;
        if invert != 0 {
            v = as_uint(width, !v);
        }
        let Some((en, immr, imms)) = encode_bit_mask(v as u64, width) else { return fail_with(bad_immediate(xv)) };
        return Ok(sf << 31 | opc << 29 | 0x12000000 | en << 22 | immr << 16 | imms << 10 | rn.n << 5 | rd.n);
    }
    let rd = gp(d)?;
    let rn = gp(n)?;
    let rm = gp(x)?;
    let sf = same_width(&[&rd, &rn, &rm])?;
    let (kind, amount) = if extra.is_some() { shift_amount(extra, &["lsl", "lsr", "asr", "ror"], if sf == 1 { 64 } else { 32 })? } else { (0, 0) };
    Ok(sf << 31 | opc << 29 | 0x0a000000 | kind << 22 | invert << 21 | rm.n << 16 | amount << 10 | rn.n << 5 | rd.n)
}

/// MOVZ, MOVN, MOVK: a 16-bit value at a multiple of 16 bits.
fn move_wide(opc: u32, ops: &[Operand]) -> R<u32> {
    count(ops, &[2, 3])?;
    let rd = gp(ops.first())?;
    let sf = sf_of(&rd);
    let width = if sf == 1 { 64 } else { 32 };
    let v = immediate(ops.get(1))?;
    let mut amount = 0;
    if ops.get(2).is_some() {
        amount = shift_amount(ops.get(2), &["lsl"], width)?.1;
        if amount % 16 != 0 {
            return fail_with(bad_small(amount as i128));
        }
    }
    if v.v < 0 || v.v > 0xffff {
        return fail_with(bad_immediate(&v));
    }
    Ok(sf << 31 | opc << 29 | 0x12800000 | (amount / 16) << 21 | (v.v as u32) << 5 | rd.n)
}

/// MOV with an immediate, the way LLVM picks the instruction: movz if one 16-bit piece makes the
/// value, movn if one makes its complement, a bitmask orr otherwise.
fn mov_immediate(d: &Operand, x: &Int) -> R<u32> {
    let rd = gpr(Some(d), is_sp(Some(d)))?;
    let width: u32 = if rd.cls == 'x' { 64 } else { 32 };
    let value = fit_width(x, width)?;
    if !rd.sp {
        for (opc, v) in [(2, value), (0, as_uint(width, !value))] {
            let mut shift = 0;
            while shift < width {
                if v & !(0xffffi128 << shift) == 0 {
                    return move_wide(opc, &[O::Reg(rd.clone()), O::Imm(Int::of(v >> shift)), O::Shift(Shift { s: "lsl", amount: shift, given: true })]);
                }
                shift += 16;
            }
        }
    }
    if encode_bit_mask(value as u64, width).is_none() {
        return fail_with(bad_immediate(x));
    }
    logical(1, 0, &[O::Reg(rd.clone()), O::Reg(zr_like(&rd)), O::Imm(Int::of(value))])
}

fn mov(ops: &[Operand]) -> R<u32> {
    count(ops, &[2])?;
    let (d, x) = (&ops[0], &ops[1]);
    if let O::Imm(v) = x {
        return mov_immediate(d, v);
    }
    if !is_gp(Some(d)) || !is_gp(Some(x)) {
        return fail();
    }
    if is_sp(Some(d)) || is_sp(Some(x)) {
        return add_sub(0, 0, &[d.clone(), x.clone(), zero()]);
    }
    let O::Reg(rd) = d else { return fail() };
    logical(1, 0, &[d.clone(), O::Reg(zr_like(rd)), x.clone()])
}

/// SBFM, BFM, UBFM.
fn bitfield(opc: u32, d: Option<&Operand>, n: Option<&Operand>, immr: u32, imms: u32) -> R<u32> {
    let rd = gp(d)?;
    let rn = gp(n)?;
    let sf = same_width(&[&rd, &rn])?;
    Ok(sf << 31 | opc << 29 | 0x13000000 | sf << 22 | immr << 16 | imms << 10 | rn.n << 5 | rd.n)
}

fn width_of(op: Option<&Operand>) -> R<i64> {
    Ok(if gp(op)?.cls == 'x' { 64 } else { 32 })
}

/// The bitfield aliases that take a position and a width: ubfx, ubfiz, bfi…
fn bitfield_field(opc: u32, insert: bool, ops: &[Operand]) -> R<u32> {
    count(ops, &[4])?;
    let width = width_of(ops.first())?;
    let lsb = in_range(ops.get(2), 0, width - 1)?;
    let size = in_range(ops.get(3), 1, width - lsb)?;
    if insert {
        bitfield(opc, ops.first(), ops.get(1), ((width - lsb) % width) as u32, (size - 1) as u32)
    } else {
        bitfield(opc, ops.first(), ops.get(1), lsb as u32, (lsb + size - 1) as u32)
    }
}

/// SXTB, SXTH, SXTW, UXTB, UXTH: the source is always a w register.
fn extend(opc: u32, imms: u32, ops: &[Operand]) -> R<u32> {
    count(ops, &[2])?;
    let rn = gp(ops.get(1))?;
    if rn.cls != 'w' {
        return fail();
    }
    let rd = gp(ops.first())?;
    bitfield(opc, Some(&O::Reg(rd.clone())), Some(&O::Reg(Reg { cls: rd.cls, ..rn })), 0, imms)
}

fn extr(d: Option<&Operand>, n: Option<&Operand>, m: Option<&Operand>, lsb: Option<&Operand>) -> R<u32> {
    let rd = gp(d)?;
    let rn = gp(n)?;
    let rm = gp(m)?;
    let sf = same_width(&[&rd, &rn, &rm])?;
    let lsb = in_range(lsb, 0, if sf == 1 { 63 } else { 31 })? as u32;
    Ok(sf << 31 | 0x13800000 | sf << 22 | rm.n << 16 | lsb << 10 | rn.n << 5 | rd.n)
}

/// LSL, LSR, ASR, ROR: by an immediate (a bitfield or extr) or by a register.
fn shift_insn(kind: u32, ops: &[Operand]) -> R<u32> {
    count(ops, &[3])?;
    if as_imm(ops.get(2)).is_none() {
        return data_processing2(8 + kind, ops);
    }
    let width = width_of(ops.first())?;
    let amount = in_range(ops.get(2), 0, width - 1)?;
    match kind {
        0 => bitfield(2, ops.first(), ops.get(1), ((width - amount) % width) as u32, (width - 1 - amount) as u32),
        3 => extr(ops.first(), ops.get(1), ops.get(1), ops.get(2)),
        _ => bitfield(if kind == 1 { 2 } else { 0 }, ops.first(), ops.get(1), amount as u32, (width - 1) as u32),
    }
}

fn data_processing2(opcode: u32, ops: &[Operand]) -> R<u32> {
    count(ops, &[3])?;
    let rd = gp(ops.first())?;
    let rn = gp(ops.get(1))?;
    let rm = gp(ops.get(2))?;
    let sf = same_width(&[&rd, &rn, &rm])?;
    Ok(sf << 31 | 0x1ac00000 | rm.n << 16 | opcode << 10 | rn.n << 5 | rd.n)
}

fn data_processing1(opcode: u32, ops: &[Operand], only_x: bool) -> R<u32> {
    count(ops, &[2])?;
    let rd = gp(ops.first())?;
    let rn = gp(ops.get(1))?;
    let sf = same_width(&[&rd, &rn])?;
    if only_x && sf == 0 {
        return fail();
    }
    Ok(sf << 31 | 0x5ac00000 | opcode << 10 | rn.n << 5 | rd.n)
}

/// SMAX, UMAX, SMIN, UMIN (FEAT_CSSC): with a register, or an 8-bit immediate, signed for the s forms.
fn min_max(opc: u32, ops: &[Operand]) -> R<u32> {
    count(ops, &[3])?;
    if as_imm(ops.get(2)).is_none() {
        return data_processing2(24 + opc, ops);
    }
    let rd = gp(ops.first())?;
    let rn = gp(ops.get(1))?;
    let sf = same_width(&[&rd, &rn])?;
    let value = if opc & 1 != 0 { in_range(ops.get(2), 0, 255)? } else { in_range(ops.get(2), -128, 127)? & 0xff };
    Ok(sf << 31 | 0x11c00000 | opc << 18 | (value as u32) << 10 | rn.n << 5 | rd.n)
}

/// ADC, ADCS, SBC, SBCS.
fn carry(op: u32, s: u32, ops: &[Operand]) -> R<u32> {
    count(ops, &[3])?;
    let rd = gp(ops.first())?;
    let rn = gp(ops.get(1))?;
    let rm = gp(ops.get(2))?;
    let sf = same_width(&[&rd, &rn, &rm])?;
    Ok(sf << 31 | op << 30 | s << 29 | 0x1a000000 | rm.n << 16 | rn.n << 5 | rd.n)
}

/// CSEL, CSINC, CSINV, CSNEG.
fn cond_select(op: u32, o2: u32, d: Option<&Operand>, n: Option<&Operand>, m: Option<&Operand>, c: u32) -> R<u32> {
    let rd = gp(d)?;
    let rn = gp(n)?;
    let rm = gp(m)?;
    let sf = same_width(&[&rd, &rn, &rm])?;
    Ok(sf << 31 | op << 30 | 0x1a800000 | rm.n << 16 | c << 12 | o2 << 10 | rn.n << 5 | rd.n)
}

/// The aliases that test the inverted condition; al and nv have no inverse LLVM accepts.
fn invertible(op: Option<&Operand>) -> R<u32> {
    let c = condition(op)?;
    if c >= 14 {
        return fail();
    }
    Ok(c ^ 1)
}

fn cond_compare(op: u32, ops: &[Operand]) -> R<u32> {
    count(ops, &[4])?;
    let rn = gp(ops.first())?;
    let nzcv = in_range(ops.get(2), 0, 15)? as u32;
    let c = condition(ops.get(3))?;
    let (second, is_immediate) = if as_imm(ops.get(1)).is_some() {
        (in_range(ops.get(1), 0, 31)? as u32, 1)
    } else {
        let rm = gp(ops.get(1))?;
        same_width(&[&rn, &rm])?;
        (rm.n, 0)
    };
    Ok(sf_of(&rn) << 31 | op << 30 | 0x3a400000 | second << 16 | c << 12 | is_immediate << 11 | rn.n << 5 | nzcv)
}

/// MADD, MSUB and the multiplies that accumulate into zr.
fn multiply(o0: u32, ops: &[Operand], accumulate: bool) -> R<u32> {
    count(ops, &[if accumulate { 4 } else { 3 }])?;
    let rd = gp(ops.first())?;
    let rn = gp(ops.get(1))?;
    let rm = gp(ops.get(2))?;
    let ra = if accumulate { gp(ops.get(3))? } else { zr_like(&rd) };
    let sf = same_width(&[&rd, &rn, &rm, &ra])?;
    Ok(sf << 31 | 0x1b000000 | rm.n << 16 | o0 << 15 | ra.n << 10 | rn.n << 5 | rd.n)
}

/// SMADDL, UMADDL, SMSUBL, UMSUBL (and SMULH, UMULH, which take x sources): a 64-bit result.
fn multiply_long(op31: u32, o0: u32, ops: &[Operand], accumulate: bool, wide: bool) -> R<u32> {
    count(ops, &[if accumulate { 4 } else { 3 }])?;
    let rd = xreg(ops.first(), false)?;
    let rn = if wide { xreg(ops.get(1), false)? } else { wreg(ops.get(1))? };
    let rm = if wide { xreg(ops.get(2), false)? } else { wreg(ops.get(2))? };
    let ra = if accumulate { xreg(ops.get(3), false)? } else { 31 };
    Ok(0x9b000000 | op31 << 21 | rm << 16 | o0 << 15 | ra << 10 | rn << 5 | rd)
}

/* ------------------------------------------------------------------ *
 * Branches and system
 * ------------------------------------------------------------------ */

fn hint_number(name: &str) -> Option<u32> {
    (0..128).find(|&n| hint_name(n) == Some(name))
}

fn barrier_number(name: &str) -> Option<u32> {
    (0..16).find(|&n| barrier_name(n) == Some(name))
}

/// DSB with the nXS qualifier (FEAT_XS), by the number LLVM also takes for it.
fn nxs_name(n: f64) -> Option<&'static str> {
    Some(match n as i64 {
        _ if n.fract() != 0.0 => return None,
        16 => "oshnxs",
        20 => "nshnxs",
        24 => "ishnxs",
        28 => "synxs",
        _ => return None,
    })
}

fn nxs_number(name: &str) -> Option<u32> {
    [16, 20, 24, 28].into_iter().find(|&n| nxs_name(n as f64) == Some(name))
}

fn barrier(op2: u32, ops: &[Operand], none: Option<u32>) -> R<u32> {
    count(ops, &[if none.is_none() { 1 } else { 0 }, 1])?;
    let nxs = if op2 == 4 {
        match ops.first() {
            Some(O::Word(w)) => nxs_number(w).map(|n| n as f64),
            Some(O::Imm(v)) => Some(v.number()),
            _ => None,
        }
    } else {
        None
    };
    if let Some(n) = nxs {
        if nxs_name(n).is_some() {
            return Ok(0xd503323f | ((n as u32) & 12) << 8);
        }
    }
    let crm = match ops.first() {
        None => none.unwrap_or(0),
        Some(O::Word(w)) if barrier_number(w).is_some() && op2 != 6 => barrier_number(w).unwrap(),
        op => in_range(op, 0, 15)? as u32,
    };
    Ok(0xd503301f | crm << 8 | op2 << 5)
}

/// HINT and the hints with names: nop, yield, paciasp, bti c…
fn hint(m: &str, ops: &[Operand]) -> R<Option<u32>> {
    if m == "hint" {
        count(ops, &[1])?;
        return Ok(Some(0xd503201f | (in_range(ops.first(), 0, 127)? as u32) << 5));
    }
    let mut name = m.to_string();
    for op in ops {
        name.push(' ');
        match op {
            O::Word(w) => name.push_str(w),
            O::Reg(r) => name.push_str(&reg_name(r)),
            _ => name.push('?'),
        }
    }
    Ok(hint_number(&name).map(|n| 0xd503201f | n << 5))
}

fn prfop(op: Option<&Operand>) -> R<u32> {
    if let Some(O::Word(w)) = op {
        let Some((kind, target, policy)) = prfop_parts(w) else { return fail() };
        return Ok(kind << 3 | target << 1 | policy);
    }
    Ok(in_range(op, 0, 31)? as u32)
}

/* ------------------------------------------------------------------ *
 * Loads and stores
 * ------------------------------------------------------------------ */

fn fp_size(cls: char) -> Option<u32> {
    Some(match cls {
        'b' => 0,
        'h' => 1,
        's' => 2,
        'd' => 3,
        'q' => 0,
        _ => return None,
    })
}

/// The base register of an address: x0…x30 or sp.
fn base_of(mem: &Mem) -> R<u32> {
    xreg(Some(&O::Reg(mem.base.clone())), true)
}

fn offset_field(off: &Int, scale: u32, lo: i64, hi: i64) -> R<i64> {
    let bytes = 1i128 << scale;
    if off.misaligned(bytes) {
        return fail_with(AsmError::Multiple(off.shown(), bytes as u32));
    }
    // BigInt division truncates toward zero.
    let v = off.v / bytes;
    if v < lo as i128 || v > hi as i128 {
        return fail_with(bad_offset(off));
    }
    Ok(v as i64)
}

/// LDR, STR, LDUR, STUR, LDTR, STTR and their byte, halfword and sign-extending forms, for general
/// and SIMD&FP registers; PRFM and PRFUM.
fn single(m: &str, ops: &[Operand], pc: f64) -> R<u32> {
    count(ops, &[2])?;
    let prefetch = m == "prfm" || m == "prfum";
    // ^(ld|st)(r|ur|tr)(b|h|sb|sh|sw)?$
    let (load, form, suffix) = if prefetch {
        (true, if m == "prfm" { "r" } else { "ur" }, "")
    } else {
        let load = m.starts_with("ld");
        if !load && !m.starts_with("st") {
            return fail();
        }
        let rest = &m[2..];
        let Some(form) = ["ur", "tr", "r"].into_iter().find(|f| rest.starts_with(f)) else { return fail() };
        let suffix = &rest[form.len()..];
        if !matches!(suffix, "" | "b" | "h" | "sb" | "sh" | "sw") {
            return fail();
        }
        (load, form, suffix)
    };
    let mut v = 0;
    let (size, opc, scale, rt);
    let r = ops.first();
    if prefetch {
        rt = prfop(r)?;
        size = 3;
        opc = 2;
        scale = 3;
    } else if let Some(fp) = as_reg(r).and_then(|r| fp_size(r.cls).map(|size| (r, size))) {
        let (reg, fsize) = fp;
        if !suffix.is_empty() || form == "tr" {
            return fail();
        }
        v = 1;
        size = fsize;
        opc = (if reg.cls == 'q' { 2 } else { 0 }) | u32::from(load);
        scale = if reg.cls == 'q' { 4 } else { size };
        rt = reg.n;
    } else {
        let g = gp(r)?;
        rt = g.n;
        if !load && suffix.starts_with('s') {
            return fail();
        }
        let (s, o) = match suffix {
            "" => (if g.cls == 'x' { 3 } else { 2 }, u32::from(load)),
            "b" | "h" => {
                if g.cls != 'w' {
                    return fail();
                }
                (if suffix == "b" { 0 } else { 1 }, u32::from(load))
            }
            "sw" => {
                if g.cls != 'x' {
                    return fail();
                }
                (2, 2)
            }
            _ => (if suffix == "sb" { 0 } else { 1 }, if g.cls == 'x' { 2 } else { 3 }),
        };
        size = s;
        opc = o;
        scale = size;
    }
    let mem = match &ops[1] {
        O::Imm(_) => {
            // A literal: ldr (w, x, s, d, q), ldrsw, prfm.
            if form != "r" || !load || (!suffix.is_empty() && suffix != "sw") {
                return fail();
            }
            let lit: i32 = if prefetch {
                3
            } else if suffix == "sw" {
                2
            } else if v != 0 {
                [2, 3, 4].iter().position(|&s| s == scale).map_or(-1, |p| p as i32)
            } else if size == 3 {
                1
            } else {
                0
            };
            if lit < 0 {
                return fail();
            }
            let distance = target(ops.get(1))? - pc;
            return Ok((lit as u32) << 30 | 0x18000000 | v << 26 | relative(distance, 4.0, 19, distance)? << 5 | rt);
        }
        O::Mem(mem) => mem,
        _ => return fail(),
    };
    let rn = base_of(mem)?;
    let head = size << 30 | v << 26 | opc << 22 | rn << 5 | rt;
    let unscaled = |op: u32| -> R<u32> {
        if mem.off.v < -256 || mem.off.v > 255 {
            return fail_with(bad_offset(&mem.off));
        }
        // With writeback, the base must not also be the register loaded or stored.
        if (op == 1 || op == 3) && v == 0 && rn == rt && rn != 31 {
            return unpredictable();
        }
        Ok(head | 0x38000000 | ((mem.off.v as i64 & 0x1ff) as u32) << 12 | op << 10)
    };
    if let Some(index) = &mem.index {
        if form != "r" || mem.mode != Mode::Off {
            return fail();
        }
        let ext = mem.ext.as_ref().map_or("lsl", |e| e.s);
        let Some(option) = ["", "", "uxtw", "lsl", "", "", "sxtw", "sxtx"].iter().position(|o| *o == ext) else { return fail() };
        if (index.cls == 'x') != (option & 1 != 0) || (index.cls != 'x' && index.cls != 'w') || (index.n == 31 && index.sp) {
            return fail();
        }
        let mut s = 0;
        if let Some(e) = mem.ext.as_ref().filter(|e| e.given) {
            if e.amount == scale {
                s = 1;
            } else if e.amount != 0 {
                return fail_with(bad_small(e.amount as i128));
            }
        }
        return Ok(head | 0x38200800 | index.n << 16 | (option as u32) << 13 | s << 12);
    }
    if form == "ur" || form == "tr" {
        if mem.mode != Mode::Off {
            return fail();
        }
        return unscaled(if form == "ur" { 0 } else { 2 });
    }
    if mem.mode != Mode::Off {
        if prefetch {
            return fail();
        }
        return unscaled(if mem.mode == Mode::Post { 1 } else { 3 });
    }
    // An offset the scaled form cannot hold goes to ldur / stur, as LLVM does.
    let bytes = 1i128 << scale;
    if mem.off.v < 0 || mem.off.misaligned(bytes) || mem.off.v / bytes > 0xfff {
        if mem.off.v >= -256 && mem.off.v <= 255 {
            return unscaled(0);
        }
        offset_field(&mem.off, scale, 0, 0xfff)?;
    }
    Ok(head | 0x39000000 | ((mem.off.v / bytes) as u32) << 10)
}

/// LDP, STP, LDNP, STNP, LDPSW.
fn pair(m: &str, ops: &[Operand]) -> R<u32> {
    count(ops, &[3])?;
    let l = u32::from(m.starts_with("ld"));
    let (Some(r1), Some(r2)) = (as_reg(ops.first()), as_reg(ops.get(1))) else { return fail() };
    let Some(O::Mem(mem)) = ops.get(2) else { return fail() };
    if r1.cls != r2.cls || mem.index.is_some() {
        return fail();
    }
    let mut v = 0;
    let (opc, scale);
    if m == "ldpsw" {
        gp(ops.first())?;
        gp(ops.get(1))?;
        if r1.cls != 'x' {
            return fail();
        }
        opc = 1;
        scale = 2;
    } else if let Some(k) = ['s', 'd', 'q'].iter().position(|c| *c == r1.cls) {
        v = 1;
        opc = k as u32;
        scale = opc + 2;
    } else {
        gp(ops.first())?;
        gp(ops.get(1))?;
        opc = if r1.cls == 'x' { 2 } else { 0 };
        scale = if r1.cls == 'x' { 3 } else { 2 };
    }
    let noalloc = m == "ldnp" || m == "stnp";
    if noalloc && mem.mode != Mode::Off {
        return fail();
    }
    let mode = if noalloc {
        0
    } else {
        match mem.mode {
            Mode::Post => 1,
            Mode::Off => 2,
            Mode::Pre => 3,
        }
    };
    let imm7 = offset_field(&mem.off, scale, -64, 63)?;
    let rn = base_of(mem)?;
    // As LLVM does, refuse what Arm leaves unpredictable: one register loaded twice, or a written-back base also transferred.
    if (l != 0 && !noalloc && r1.n == r2.n) || ((mode == 1 || mode == 3) && v == 0 && rn != 31 && (rn == r1.n || rn == r2.n)) {
        return unpredictable();
    }
    Ok(opc << 30 | 0x28000000 | v << 26 | mode << 23 | l << 22 | ((imm7 & 0x7f) as u32) << 15 | r2.n << 10 | rn << 5 | r1.n)
}

/// The exclusive and acquire/release loads and stores: their o2, L, o1, o0, whether a status
/// register comes first, whether they take a pair.
fn exclusive_spec(m: &str) -> Option<(u32, u32, u32, u32, bool, bool)> {
    Some(match m {
        "stxr" => (0, 0, 0, 0, true, false),
        "stlxr" => (0, 0, 0, 1, true, false),
        "ldxr" => (0, 1, 0, 0, false, false),
        "ldaxr" => (0, 1, 0, 1, false, false),
        "stllr" => (1, 0, 0, 0, false, false),
        "stlr" => (1, 0, 0, 1, false, false),
        "ldlar" => (1, 1, 0, 0, false, false),
        "ldar" => (1, 1, 0, 1, false, false),
        "stxp" => (0, 0, 1, 0, true, true),
        "stlxp" => (0, 0, 1, 1, true, true),
        "ldxp" => (0, 1, 1, 0, false, true),
        "ldaxp" => (0, 1, 1, 1, false, true),
        _ => return None,
    })
}

/// LDXR, STXR, LDAXR, STLXR, LDAR, STLR, LDLAR, STLLR (with b and h), and the exclusive pairs.
fn exclusive(m: &str, ops: &[Operand]) -> R<Option<u32>> {
    // ^(.*?)(b|h)?$
    let (stem, size_suffix) = match m.as_bytes().last() {
        Some(b'b') => (&m[..m.len() - 1], Some('b')),
        Some(b'h') => (&m[..m.len() - 1], Some('h')),
        _ => (m, None),
    };
    let mem = ops.last();
    if (m == "stlr" || m == "ldapr") && matches!(mem, Some(O::Mem(x)) if x.mode != Mode::Off) {
        return rcpc_writeback(m == "ldapr", ops).map(Some);
    }
    if stem == "ldapr" {
        return acquire_rcpc(size_suffix, ops).map(Some);
    }
    let own = exclusive_spec(m);
    let spec = own.or_else(|| if size_suffix.is_some() && !m.ends_with('p') { exclusive_spec(stem) } else { None });
    let Some((o2, l, o1, o0, status, is_pair)) = spec else { return Ok(None) };
    count(ops, &[2 + usize::from(status) + usize::from(is_pair)])?;
    let rs = if status { wreg(ops.first())? } else { 31 };
    let regs = &ops[usize::from(status)..ops.len() - 1];
    let Some(O::Mem(mem)) = mem else { return fail() };
    if mem.index.is_some() || mem.mode != Mode::Off || mem.off.v != 0 {
        return fail();
    }
    let rt = gp(regs.first())?;
    let rt2 = if is_pair { Some(gp(regs.get(1))?) } else { None };
    let mut size = if rt.cls == 'x' { 3 } else { 2 };
    if let Some(rt2) = &rt2 {
        same_width(&[&rt, rt2])?;
    }
    // The status register of a store-exclusive must differ from the registers it stores and the base.
    let rn = base_of(mem)?;
    if status && (rs == rt.n || rt2.as_ref().is_some_and(|r| rs == r.n) || (rs == rn && rn != 31)) {
        return unpredictable();
    }
    if let Some(suffix) = size_suffix {
        if own.is_none() {
            if rt.cls != 'w' {
                return fail();
            }
            size = if suffix == 'b' { 0 } else { 1 };
        }
    }
    Ok(Some(size << 30 | 0x08000000 | o2 << 23 | l << 22 | o1 << 21 | rs << 16 | o0 << 15 | rt2.map_or(31, |r| r.n) << 10 | rn << 5 | rt.n))
}

/// A plain [Xn] address, as the exclusives and atomics take.
fn plain_base(op: Option<&Operand>) -> R<u32> {
    let Some(O::Mem(mem)) = op else { return fail() };
    if mem.index.is_some() || mem.mode != Mode::Off || mem.off.v != 0 {
        return fail();
    }
    base_of(mem)
}

/// The size of an access by suffix (b, h) or by the register.
fn access_size(suffix: Option<char>, rt: &Reg) -> R<u32> {
    let Some(suffix) = suffix else { return Ok(if rt.cls == 'x' { 3 } else { 2 }) };
    if rt.cls != 'w' {
        return fail();
    }
    Ok(if suffix == 'b' { 0 } else { 1 })
}

/// LDAPR (FEAT_LRCPC): a load-acquire with the weaker RCpc ordering.
fn acquire_rcpc(suffix: Option<char>, ops: &[Operand]) -> R<u32> {
    count(ops, &[2])?;
    let rt = gp(ops.first())?;
    Ok(access_size(suffix, &rt)? << 30 | 0x38bfc000 | plain_base(ops.get(1))? << 5 | rt.n)
}

/// STLR with pre-decrement and LDAPR with post-increment (FEAT_LRCPC3): the step is the access size.
fn rcpc_writeback(load: bool, ops: &[Operand]) -> R<u32> {
    count(ops, &[2])?;
    let rt = gp(ops.first())?;
    let Some(O::Mem(mem)) = ops.get(1) else { return fail() };
    let size = access_size(None, &rt)?;
    if mem.index.is_some() || mem.mode != if load { Mode::Post } else { Mode::Pre } {
        return fail();
    }
    let step = 1i128 << size;
    if mem.off.big.is_some() || mem.off.v != if load { step } else { -step } {
        return fail_with(bad_offset(&mem.off));
    }
    Ok(size << 30 | 0x19000800 | (if load { 3 } else { 2 }) << 22 | base_of(mem)? << 5 | rt.n)
}

const ATOMIC_OPS: [&str; 8] = ["add", "clr", "eor", "set", "smax", "smin", "umax", "umin"];

/// `(a|l|al)?(b|h)?$` after a stem: the ordering and the size suffix.
fn order_and_size(rest: &str) -> Option<(&str, Option<char>)> {
    let (order, suffix) = match rest.as_bytes().last() {
        Some(b'b') => (&rest[..rest.len() - 1], Some('b')),
        Some(b'h') => (&rest[..rest.len() - 1], Some('h')),
        _ => (rest, None),
    };
    matches!(order, "" | "a" | "l" | "al").then_some((order, suffix))
}

/// The LSE atomics: LD<op>, ST<op> (LD<op> into zr, without acquire), SWP, CAS and CASP, each with
/// its a/l ordering and b/h size suffixes.
fn atomic(m: &str, ops: &[Operand]) -> R<Option<u32>> {
    let lse = ["ld", "st"].into_iter().find(|k| m.starts_with(k)).and_then(|kind| {
        let rest = &m[2..];
        let op = ATOMIC_OPS.iter().position(|op| rest.starts_with(op))?;
        let (order, suffix) = order_and_size(&rest[ATOMIC_OPS[op].len()..])?;
        Some((kind, op as u32, order, suffix))
    });
    if let Some((kind, op, order, suffix)) = lse {
        let store = kind == "st";
        if store && order.contains('a') {
            return Ok(None);
        }
        count(ops, &[if store { 2 } else { 3 }])?;
        let rs = gp(ops.first())?;
        let rt = if store { zr_like(&rs) } else { gp(ops.get(1))? };
        same_width(&[&rs, &rt])?;
        let a = u32::from(order.contains('a'));
        let r = u32::from(order.contains('l'));
        let size = access_size(suffix, &rs)?;
        return Ok(Some(size << 30 | 0x38200000 | a << 23 | r << 22 | rs.n << 16 | op << 12 | plain_base(ops.last())? << 5 | rt.n));
    }
    let swap = ["casp", "cas", "swp"].into_iter().find_map(|kind| m.strip_prefix(kind).and_then(order_and_size).map(|(order, suffix)| (kind, order, suffix)));
    let Some((kind, order, suffix)) = swap else { return Ok(None) };
    let a = u32::from(order.contains('a'));
    let r = u32::from(order.contains('l'));
    if kind == "casp" {
        // Two pairs of consecutive registers, each starting at an even one; only the first of each is encoded.
        if suffix.is_some() {
            return Ok(None);
        }
        count(ops, &[5])?;
        let mut regs = Vec::new();
        for op in &ops[..4] {
            regs.push(gp(Some(op))?);
        }
        same_width(&regs.iter().collect::<Vec<_>>())?;
        if regs[0].n & 1 != 0 || regs[2].n & 1 != 0 || regs[1].n != regs[0].n + 1 || regs[3].n != regs[2].n + 1 {
            return fail();
        }
        return Ok(Some(u32::from(regs[0].cls == 'x') << 30 | 0x08207c00 | a << 22 | regs[0].n << 16 | r << 15 | plain_base(ops.get(4))? << 5 | regs[2].n));
    }
    count(ops, &[3])?;
    let rs = gp(ops.first())?;
    let rt = gp(ops.get(1))?;
    same_width(&[&rs, &rt])?;
    let size = access_size(suffix, &rs)? << 30;
    if kind == "cas" {
        return Ok(Some(size | 0x08a07c00 | a << 22 | rs.n << 16 | r << 15 | plain_base(ops.get(2))? << 5 | rt.n));
    }
    Ok(Some(size | 0x38208000 | a << 23 | r << 22 | rs.n << 16 | plain_base(ops.get(2))? << 5 | rt.n))
}

/* ------------------------------------------------------------------ *
 * Floating point
 * ------------------------------------------------------------------ */

const FP1: [&str; 20] =
    ["fmov", "fabs", "fneg", "fsqrt", "", "", "", "", "frintn", "frintp", "frintm", "frintz", "frinta", "", "frintx", "frinti", "frint32z", "frint32x", "frint64z", "frint64x"];
const FP2: [&str; 9] = ["fmul", "fdiv", "fadd", "fsub", "fmax", "fmin", "fmaxnm", "fminnm", "fnmul"];
const FP3: [&str; 4] = ["fmadd", "fmsub", "fnmadd", "fnmsub"];

/// A scalar s, d or h register, and its ftype.
fn fpr(op: Option<&Operand>, like: Option<&Reg>) -> R<(Reg, u32)> {
    let Some(r) = as_reg(op) else { return fail() };
    let ty = match r.cls {
        's' => 0,
        'd' => 1,
        'h' => 3,
        _ => return fail(),
    };
    if like.is_some_and(|l| l.cls != r.cls) {
        return fail();
    }
    Ok((r.clone(), ty))
}

fn fp_value(op: Option<&Operand>) -> R<f64> {
    if let Some(O::Float(v)) = op {
        return Ok(*v);
    }
    Ok(immediate(op)?.number())
}

fn fmov(ops: &[Operand]) -> R<u32> {
    count(ops, &[2])?;
    let (d, n) = (ops.first(), ops.get(1));
    if is_gp(d) {
        // To a general register: w from s or h, x from d or h.
        let (rn, ty) = fpr(n, None)?;
        let dr = as_reg(d).unwrap();
        if (rn.cls == 's' && dr.cls != 'w') || (rn.cls == 'd' && dr.cls != 'x') {
            return fail();
        }
        return Ok(sf_of(&gp(d)?) << 31 | 0x1e260000 | ty << 22 | rn.n << 5 | dr.n);
    }
    let (rd, ty) = fpr(d, None)?;
    if is_gp(n) {
        let nr = as_reg(n).unwrap();
        if (rd.cls == 's' && nr.cls != 'w') || (rd.cls == 'd' && nr.cls != 'x') {
            return fail();
        }
        return Ok(sf_of(&gp(n)?) << 31 | 0x1e270000 | ty << 22 | nr.n << 5 | rd.n);
    }
    if as_reg(n).is_some() {
        return Ok(0x1e204000 | ty << 22 | fpr(n, Some(&rd))?.0.n << 5 | rd.n);
    }
    let value = fp_value(n)?;
    // Zero has no imm8; LLVM moves it from the zero register.
    if value == 0.0 && value.is_sign_positive() {
        let zr = Reg { cls: if rd.cls == 'd' { 'x' } else { 'w' }, n: 31, sp: false };
        return fmov(&[O::Reg(rd), O::Reg(zr)]);
    }
    let Some(imm8) = fp_imm8(value) else { return fail_with(AsmError::Immediate(format!("#{}", js_number(value)))) };
    Ok(0x1e201000 | ty << 22 | imm8 << 13 | rd.n)
}

fn fp_compare(e: u32, ops: &[Operand]) -> R<u32> {
    count(ops, &[2])?;
    let (rn, ty) = fpr(ops.first(), None)?;
    if as_reg(ops.get(1)).is_some() {
        return Ok(0x1e202000 | ty << 22 | fpr(ops.get(1), Some(&rn))?.0.n << 16 | rn.n << 5 | e << 4);
    }
    let value = fp_value(ops.get(1))?;
    if value != 0.0 {
        return fail_with(AsmError::Immediate(format!("#{}", js_number(value))));
    }
    Ok(0x1e202008 | ty << 22 | rn.n << 5 | e << 4)
}

/// The conversions between SIMD&FP registers: U, size<1> and opcode of the Advanced SIMD scalar form
/// (both registers the same size), and rmode:opcode of the FEAT_FPRCVT form (sizes differ).
fn simd_convert_spec(m: &str) -> Option<(u32, u32, u32, u32)> {
    Some(match m {
        "fcvtns" => (0, 0, 26, 0b01010),
        "fcvtms" => (0, 0, 27, 0b10100),
        "fcvtas" => (0, 0, 28, 0b11010),
        "scvtf" => (0, 0, 29, 0b11100),
        "fcvtps" => (0, 1, 26, 0b10010),
        "fcvtzs" => (0, 1, 27, 0b10110),
        "fcvtnu" => (1, 0, 26, 0b01011),
        "fcvtmu" => (1, 0, 27, 0b10101),
        "fcvtau" => (1, 0, 28, 0b11011),
        "ucvtf" => (1, 0, 29, 0b11101),
        "fcvtpu" => (1, 1, 26, 0b10011),
        "fcvtzu" => (1, 1, 27, 0b10111),
        _ => return None,
    })
}

/// A conversion with both registers SIMD&FP: the integer in s or d (or h, when both are h).
fn simd_convert(m: &str, ops: &[Operand]) -> R<u32> {
    let Some((u, hi, opcode, fprcvt)) = simd_convert_spec(m) else { return fail() };
    let (rd, rd_ty) = fpr(ops.first(), None)?;
    let (rn, rn_ty) = fpr(ops.get(1), None)?;
    if rd.cls != rn.cls {
        // FEAT_FPRCVT: sf says whether the integer is in d or s.
        count(ops, &[2])?;
        let to_fp = m.ends_with("cvtf");
        let (int, fp_ty) = if to_fp { (&rn, rd_ty) } else { (&rd, rn_ty) };
        if int.cls == 'h' {
            return fail();
        }
        return Ok(u32::from(int.cls == 'd') << 31 | 0x1e200000 | fp_ty << 22 | fprcvt << 16 | rn.n << 5 | rd.n);
    }
    if ops.len() == 3 {
        // Fixed point, by the shift-immediate encoding: immh:immb is twice the element size less fbits.
        if opcode != 27 && opcode != 29 {
            return fail();
        }
        let esize = match rd.cls {
            'h' => 16,
            's' => 32,
            _ => 64,
        };
        let value = (2 * esize - in_range(ops.get(2), 1, esize)?) as u32;
        return Ok(0x5f000400 | u << 29 | value << 16 | (if opcode == 27 { 31 } else { 28 }) << 11 | rn.n << 5 | rd.n);
    }
    count(ops, &[2])?;
    let size = if rd.cls == 'h' { 0x00780000 } else { 0x00200000 | u32::from(rd.cls == 'd') << 22 };
    Ok(0x5e000800 | u << 29 | size | hi << 23 | opcode << 12 | rn.n << 5 | rd.n)
}

/// SCVTF, UCVTF and FCVT<mode>S/U between a general register and s, d or h; fixed point with fbits.
fn fp_int_convert(to_fp: bool, rmode: u32, opcode: u32, ops: &[Operand], m: &str) -> R<u32> {
    count(ops, &[2, 3])?;
    if !is_gp(ops.first()) && !is_gp(ops.get(1)) {
        return simd_convert(m, ops);
    }
    let g = gp(ops.get(if to_fp { 1 } else { 0 }))?;
    let (f, ty) = fpr(ops.get(if to_fp { 0 } else { 1 }), None)?;
    let sf = sf_of(&g);
    let fields = sf << 31 | ty << 22 | rmode << 19 | opcode << 16 | (if to_fp { g.n } else { f.n }) << 5 | if to_fp { f.n } else { g.n };
    if ops.len() == 2 {
        return Ok(0x1e200000 | fields);
    }
    // Fixed point: only scvtf, ucvtf, fcvtzs and fcvtzu.
    if opcode > 3 || (rmode != 0 && rmode != 3) {
        return fail();
    }
    let fbits = in_range(ops.get(2), 1, if sf == 1 { 64 } else { 32 })? as u32;
    Ok(0x1e000000 | fields | (64 - fbits) << 10)
}

/* ------------------------------------------------------------------ *
 * The mnemonics
 * ------------------------------------------------------------------ */

fn is_d(op: Option<&Operand>) -> bool {
    as_reg(op).is_some_and(|r| r.cls == 'd')
}

fn as_w(op: Option<&Operand>) -> R<Operand> {
    match op {
        Some(O::Reg(r)) if r.cls == 'x' || r.cls == 'w' => Ok(O::Reg(Reg { cls: 'w', ..r.clone() })),
        _ => fail(),
    }
}

/// ADD, SUB (three-same) and NEG, ABS (two-register misc) on d registers: Advanced SIMD scalar.
fn scalar_d(u: u32, opcode: u32, ops: &[Operand]) -> R<u32> {
    let mut regs = Vec::new();
    for op in ops {
        if !is_d(Some(op)) {
            return fail();
        }
        regs.push(as_reg(Some(op)).unwrap().n);
    }
    if opcode == 11 {
        count(ops, &[2])?;
        return Ok(0x5ee0b800 | u << 29 | regs[1] << 5 | regs[0]);
    }
    count(ops, &[3])?;
    Ok(0x5ee00400 | u << 29 | regs[2] << 16 | opcode << 11 | regs[1] << 5 | regs[0])
}

fn zr_of(op: Option<&Operand>) -> R<Operand> {
    Ok(O::Reg(zr_like(&gpr(op, is_sp(op))?)))
}

/// `[zr_of(ops[0]), ...ops]`
fn with_zr_first(ops: &[Operand]) -> R<Vec<Operand>> {
    let mut out = vec![zr_of(ops.first())?];
    out.extend_from_slice(ops);
    Ok(out)
}

/// `[ops[0], zr_of(ops[0]), ...ops.slice(1)]`
fn with_zr_second(ops: &[Operand]) -> R<Vec<Operand>> {
    let zr = zr_of(ops.first())?;
    let mut out = vec![ops[0].clone(), zr];
    out.extend_from_slice(&ops[1..]);
    Ok(out)
}

fn test_branch(nz: u32, ops: &[Operand], pc: f64) -> R<u32> {
    count(ops, &[3])?;
    let rt = gp(ops.first())?;
    let n = in_range(ops.get(1), 0, if rt.cls == 'x' { 63 } else { 31 })? as u32;
    let distance = target(ops.get(2))? - pc;
    Ok((n >> 5) << 31 | 0x36000000 | nz << 24 | (n & 31) << 19 | relative(distance, 4.0, 14, distance)? << 5 | rt.n)
}

fn fp_cond_compare(e: u32, ops: &[Operand]) -> R<u32> {
    count(ops, &[4])?;
    let (rn, ty) = fpr(ops.first(), None)?;
    let rm = fpr(ops.get(1), Some(&rn))?.0;
    let c = condition(ops.get(3))?;
    Ok(0x1e200400 | ty << 22 | rm.n << 16 | c << 12 | rn.n << 5 | e << 4 | in_range(ops.get(2), 0, 15)? as u32)
}

fn branch(base: u32, ops: &[Operand], pc: f64, width: u32) -> R<u32> {
    let distance = target(ops.first())? - pc;
    Ok(base | relative(distance, 4.0, width, distance)?)
}

/// The encoder of a mnemonic, or None when there is none by that name.
fn encoder(m: &str, ops: &[Operand], pc: f64) -> Option<R<u32>> {
    let c = |n: &[usize]| count(ops, n);
    Some(match m {
        ".inst" => c(&[1]).and_then(|_| in_range(ops.first(), 0, 0xffffffff).map(|v| v as u32)),

        "b" => c(&[1]).and_then(|_| branch(0x14000000, ops, pc, 26)),
        "bl" => c(&[1]).and_then(|_| branch(0x94000000, ops, pc, 26)),
        "cbz" | "cbnz" => c(&[2]).and_then(|_| {
            let rt = gp(ops.first())?;
            let distance = target(ops.get(1))? - pc;
            let field = relative(distance, 4.0, 19, distance)?;
            Ok(sf_of(&rt) << 31 | (if m == "cbz" { 0x34000000 } else { 0x35000000 }) | field << 5 | gp(ops.first())?.n)
        }),
        "tbz" => test_branch(0, ops, pc),
        "tbnz" => test_branch(1, ops, pc),
        "br" => c(&[1]).and_then(|_| Ok(0xd61f0000 | xreg(ops.first(), false)? << 5)),
        "blr" => c(&[1]).and_then(|_| Ok(0xd63f0000 | xreg(ops.first(), false)? << 5)),
        "ret" => c(&[0, 1]).and_then(|_| Ok(0xd65f0000 | (if ops.is_empty() { 30 } else { xreg(ops.first(), false)? }) << 5)),

        "svc" => c(&[1]).and_then(|_| Ok(0xd4000001 | (in_range(ops.first(), 0, 0xffff)? as u32) << 5)),
        "hvc" => c(&[1]).and_then(|_| Ok(0xd4000002 | (in_range(ops.first(), 0, 0xffff)? as u32) << 5)),
        "smc" => c(&[1]).and_then(|_| Ok(0xd4000003 | (in_range(ops.first(), 0, 0xffff)? as u32) << 5)),
        "brk" => c(&[1]).and_then(|_| Ok(0xd4200000 | (in_range(ops.first(), 0, 0xffff)? as u32) << 5)),
        "hlt" => c(&[1]).and_then(|_| Ok(0xd4400000 | (in_range(ops.first(), 0, 0xffff)? as u32) << 5)),
        "udf" => c(&[1]).and_then(|_| Ok(in_range(ops.first(), 0, 0xffff)? as u32)),
        "dsb" => barrier(4, ops, None),
        "dmb" => barrier(5, ops, None),
        "isb" => barrier(6, ops, Some(15)),
        "clrex" => barrier(2, ops, Some(15)),
        "sb" => c(&[0]).map(|_| 0xd50330ff),

        "adr" => c(&[2]).and_then(|_| {
            let distance = target(ops.get(1))? - pc;
            let field = relative(distance, 1.0, 21, distance)?;
            Ok(0x10000000 | (field & 3) << 29 | (field >> 2) << 5 | xreg(ops.first(), false)?)
        }),
        "adrp" => c(&[2]).and_then(|_| {
            let address = target(ops.get(1))?;
            let field = relative((address / 4096.0).floor() - (pc / 4096.0).floor(), 1.0, 21, address - pc)?;
            Ok(0x90000000 | (field & 3) << 29 | (field >> 2) << 5 | xreg(ops.first(), false)?)
        }),

        "add" => {
            if is_d(ops.first()) {
                scalar_d(0, 16, ops)
            } else {
                add_sub(0, 0, ops)
            }
        }
        "adds" => add_sub(0, 1, ops),
        "sub" => {
            if is_d(ops.first()) {
                scalar_d(1, 16, ops)
            } else {
                add_sub(1, 0, ops)
            }
        }
        "subs" => add_sub(1, 1, ops),
        "cmp" => with_zr_first(ops).and_then(|o| add_sub(1, 1, &o)),
        "cmn" => with_zr_first(ops).and_then(|o| add_sub(0, 1, &o)),
        "neg" => {
            if is_d(ops.first()) {
                scalar_d(1, 11, ops)
            } else {
                c(&[2, 3]).and_then(|_| with_zr_second(ops)).and_then(|o| add_sub(1, 0, &o))
            }
        }
        "negs" => c(&[2, 3]).and_then(|_| with_zr_second(ops)).and_then(|o| add_sub(1, 1, &o)),
        "adc" => carry(0, 0, ops),
        "adcs" => carry(0, 1, ops),
        "sbc" => carry(1, 0, ops),
        "sbcs" => carry(1, 1, ops),
        "ngc" => c(&[2]).and_then(|_| with_zr_second(ops)).and_then(|o| carry(1, 0, &o)),
        "ngcs" => c(&[2]).and_then(|_| with_zr_second(ops)).and_then(|o| carry(1, 1, &o)),

        "and" => logical(0, 0, ops),
        "orr" => logical(1, 0, ops),
        "eor" => logical(2, 0, ops),
        "ands" => logical(3, 0, ops),
        "bic" => logical(0, 1, ops),
        "orn" => logical(1, 1, ops),
        "eon" => logical(2, 1, ops),
        "bics" => logical(3, 1, ops),
        "tst" => with_zr_first(ops).and_then(|o| logical(3, 0, &o)),
        "mvn" => c(&[2, 3]).and_then(|_| if as_imm(ops.get(1)).is_some() { fail() } else { with_zr_second(ops).and_then(|o| logical(1, 1, &o)) }),
        "mov" => mov(ops),
        "movz" => move_wide(2, ops),
        "movn" => move_wide(0, ops),
        "movk" => move_wide(3, ops),

        "lsl" => shift_insn(0, ops),
        "lsr" => shift_insn(1, ops),
        "asr" => shift_insn(2, ops),
        "ror" => shift_insn(3, ops),
        "lslv" => data_processing2(8, ops),
        "lsrv" => data_processing2(9, ops),
        "asrv" => data_processing2(10, ops),
        "rorv" => data_processing2(11, ops),
        "udiv" => data_processing2(2, ops),
        "sdiv" => data_processing2(3, ops),
        "extr" => c(&[4]).and_then(|_| extr(ops.first(), ops.get(1), ops.get(2), ops.get(3))),
        "sbfm" | "bfm" | "ubfm" => c(&[4]).and_then(|_| {
            let opc = match m {
                "sbfm" => 0,
                "bfm" => 1,
                _ => 2,
            };
            let immr = in_range(ops.get(2), 0, width_of(ops.first())? - 1)? as u32;
            let imms = in_range(ops.get(3), 0, width_of(ops.first())? - 1)? as u32;
            bitfield(opc, ops.first(), ops.get(1), immr, imms)
        }),
        "sbfx" => bitfield_field(0, false, ops),
        "bfxil" => bitfield_field(1, false, ops),
        "ubfx" => bitfield_field(2, false, ops),
        "sbfiz" => bitfield_field(0, true, ops),
        "bfi" => bitfield_field(1, true, ops),
        "ubfiz" => bitfield_field(2, true, ops),
        "sxtb" => extend(0, 7, ops),
        "sxth" => extend(0, 15, ops),
        "sxtw" => width_of(ops.first()).and_then(|w| if w == 64 { extend(0, 31, ops) } else { fail() }),
        // A zero-extend into x is the same as into w, which clears the top half anyway; LLVM takes both.
        "uxtb" | "uxth" => as_w(ops.first()).and_then(|w| {
            let mut o = vec![w];
            o.extend_from_slice(&ops[1..]);
            extend(2, if m == "uxtb" { 7 } else { 15 }, &o)
        }),

        "rbit" => data_processing1(0, ops, false),
        "rev16" => data_processing1(1, ops, false),
        "rev32" => data_processing1(2, ops, true),
        "rev" => width_of(ops.first()).and_then(|w| data_processing1(if w == 64 { 3 } else { 2 }, ops, false)),
        "clz" => data_processing1(4, ops, false),
        "cls" => data_processing1(5, ops, false),
        "ctz" => data_processing1(6, ops, false),
        "cnt" => data_processing1(7, ops, false),
        "abs" => {
            if is_d(ops.first()) {
                scalar_d(0, 11, ops)
            } else {
                data_processing1(8, ops, false)
            }
        }
        "smax" => min_max(0, ops),
        "umax" => min_max(1, ops),
        "smin" => min_max(2, ops),
        "umin" => min_max(3, ops),

        "csel" | "csinc" | "csinv" | "csneg" => c(&[4]).and_then(|_| {
            let (op, o2) = match m {
                "csel" => (0, 0),
                "csinc" => (0, 1),
                "csinv" => (1, 0),
                _ => (1, 1),
            };
            let cond = condition(ops.get(3))?;
            cond_select(op, o2, ops.first(), ops.get(1), ops.get(2), cond)
        }),
        "cset" | "csetm" => c(&[2]).and_then(|_| {
            let zr = zr_of(ops.first())?;
            let zr2 = zr_of(ops.first())?;
            let cond = invertible(ops.get(1))?;
            if m == "cset" {
                cond_select(0, 1, ops.first(), Some(&zr), Some(&zr2), cond)
            } else {
                cond_select(1, 0, ops.first(), Some(&zr), Some(&zr2), cond)
            }
        }),
        "cinc" | "cinv" | "cneg" => c(&[3]).and_then(|_| {
            let (op, o2) = match m {
                "cinc" => (0, 1),
                "cinv" => (1, 0),
                _ => (1, 1),
            };
            let cond = invertible(ops.get(2))?;
            cond_select(op, o2, ops.first(), ops.get(1), ops.get(1), cond)
        }),
        "ccmn" => cond_compare(0, ops),
        "ccmp" => cond_compare(1, ops),

        "madd" => multiply(0, ops, true),
        "msub" => multiply(1, ops, true),
        "mul" => multiply(0, ops, false),
        "mneg" => multiply(1, ops, false),
        "smaddl" => multiply_long(1, 0, ops, true, false),
        "smsubl" => multiply_long(1, 1, ops, true, false),
        "umaddl" => multiply_long(5, 0, ops, true, false),
        "umsubl" => multiply_long(5, 1, ops, true, false),
        "smull" => multiply_long(1, 0, ops, false, false),
        "smnegl" => multiply_long(1, 1, ops, false, false),
        "umull" => multiply_long(5, 0, ops, false, false),
        "umnegl" => multiply_long(5, 1, ops, false, false),
        "smulh" => multiply_long(2, 0, ops, false, true),
        "umulh" => multiply_long(6, 0, ops, false, true),

        "ldp" | "stp" | "ldnp" | "stnp" | "ldpsw" => pair(m, ops),

        "fmov" => fmov(ops),
        "fcmp" => fp_compare(0, ops),
        "fcmpe" => fp_compare(1, ops),
        "fcsel" => c(&[4]).and_then(|_| {
            let (rd, ty) = fpr(ops.first(), None)?;
            let rm = fpr(ops.get(2), Some(&rd))?.0;
            let cond = condition(ops.get(3))?;
            let rn = fpr(ops.get(1), Some(&rd))?.0;
            Ok(0x1e200c00 | ty << 22 | rm.n << 16 | cond << 12 | rn.n << 5 | rd.n)
        }),
        "fccmp" => fp_cond_compare(0, ops),
        "fccmpe" => fp_cond_compare(1, ops),
        "fcvt" => c(&[2]).and_then(|_| {
            let (rd, rd_ty) = fpr(ops.first(), None)?;
            let (rn, rn_ty) = fpr(ops.get(1), None)?;
            if rd.cls == rn.cls {
                return fail();
            }
            Ok(0x1e204000 | rn_ty << 22 | (4 + rd_ty) << 15 | rn.n << 5 | rd.n)
        }),
        "scvtf" => fp_int_convert(true, 0, 2, ops, m),
        "ucvtf" => fp_int_convert(true, 0, 3, ops, m),
        _ => {
            if let Some(i) = FP1.iter().position(|f| *f == m).filter(|&i| i > 0) {
                return Some(c(&[2]).and_then(|_| {
                    let (rd, ty) = fpr(ops.first(), None)?;
                    if i >= 16 && rd.cls == 'h' {
                        return fail();
                    }
                    let rn = fpr(ops.get(1), Some(&rd))?.0;
                    Ok(0x1e204000 | ty << 22 | (i as u32) << 15 | rn.n << 5 | rd.n)
                }));
            }
            if let Some(i) = FP2.iter().position(|f| *f == m) {
                return Some(c(&[3]).and_then(|_| {
                    let (rd, ty) = fpr(ops.first(), None)?;
                    let rm = fpr(ops.get(2), Some(&rd))?.0;
                    let rn = fpr(ops.get(1), Some(&rd))?.0;
                    Ok(0x1e200800 | ty << 22 | rm.n << 16 | (i as u32) << 12 | rn.n << 5 | rd.n)
                }));
            }
            if let Some(i) = FP3.iter().position(|f| *f == m) {
                return Some(c(&[4]).and_then(|_| {
                    let (rd, ty) = fpr(ops.first(), None)?;
                    let rm = fpr(ops.get(2), Some(&rd))?.0;
                    let ra = fpr(ops.get(3), Some(&rd))?.0;
                    let rn = fpr(ops.get(1), Some(&rd))?.0;
                    let i = i as u32;
                    Ok(0x1f000000 | ty << 22 | (i >> 1) << 21 | rm.n << 16 | (i & 1) << 15 | ra.n << 10 | rn.n << 5 | rd.n)
                }));
            }
            // FCVTNS … FCVTAU: the rounding mode is rmode, except "a", which has opcodes of its own.
            if let Some(rest) = m.strip_prefix("fcvt") {
                let b = rest.as_bytes();
                if b.len() == 2 && b"npmza".contains(&b[0]) && (b[1] == b's' || b[1] == b'u') {
                    let u = u32::from(b[1] == b'u');
                    return Some(if b[0] == b'a' {
                        fp_int_convert(false, 0, 4 + u, ops, m)
                    } else {
                        let mode = b"npmz".iter().position(|c| *c == b[0]).unwrap() as u32;
                        fp_int_convert(false, mode, u, ops, m)
                    });
                }
            }
            for base in ["ldr", "str", "ldur", "stur", "ldtr", "sttr", "prfm", "prfum"] {
                if let Some(suffix) = m.strip_prefix(base) {
                    if suffix.is_empty() || (!base.starts_with("prf") && matches!(suffix, "b" | "h" | "sb" | "sh" | "sw")) {
                        return Some(single(m, ops, pc));
                    }
                }
            }
            return None;
        }
    })
}

fn encode(line: &Line, pc: f64) -> R<u32> {
    let (m, ops) = (line.m.as_str(), line.ops.as_slice());
    // ^(bc?)\.(\w+)$
    for (prefix, bc) in [("b.", false), ("bc.", true)] {
        if let Some(cond) = m.strip_prefix(prefix) {
            if !cond.is_empty() && cond.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                count(ops, &[1])?;
                let Some(c) = cond_index(cond) else { return fail() };
                let distance = target(ops.first())? - pc;
                return Ok(0x54000000 | relative(distance, 4.0, 19, distance)? << 5 | if bc { 0x10 } else { 0 } | c as u32);
            }
        }
    }
    if let Some(word) = encoder(m, ops, pc) {
        return word;
    }
    let named = match m {
        "ssbb" => Some(0),
        "pssbb" => Some(4),
        "dfb" => Some(12),
        _ => None,
    };
    if let Some(none) = named {
        return barrier(4, ops, Some(none));
    }
    if let Some(word) = hint(m, ops)? {
        return Ok(word);
    }
    if let Some(word) = exclusive(m, ops)? {
        return Ok(word);
    }
    if let Some(word) = atomic(m, ops)? {
        return Ok(word);
    }
    unsupported()
}

/* ------------------------------------------------------------------ *
 * Meaning: what the round trip compares
 * ------------------------------------------------------------------ */

fn imm(v: i128) -> Operand {
    O::Imm(Int::of(v))
}

fn word(w: &str) -> Operand {
    O::Word(w.to_string())
}

fn width(op: Option<&Operand>) -> i128 {
    if as_reg(op).is_some_and(|r| r.cls == 'x') {
        64
    } else {
        32
    }
}

fn inverse(op: Option<&Operand>) -> Option<Operand> {
    let c = match op {
        Some(O::Word(w)) => cond_index(w),
        _ => None,
    };
    match c {
        Some(c) if c < 14 => Some(word(CONDITIONS[c ^ 1])),
        _ => op.cloned(),
    }
}

fn with_cls(op: &Operand, cls: char) -> Operand {
    match op {
        O::Reg(r) => O::Reg(Reg { cls, ..r.clone() }),
        other => other.clone(),
    }
}

/// One form for every spelling of an instruction: the aliases a person types and the ones the
/// decoder prints are taken to the same text when they mean the same thing — `movz x0, #1` and
/// `mov x0, #0x1`, `cmp w0, #-1` and `cmn w0, #0x1`, `ubfx w0, w1, #0, #8` and `uxtb w0, w1`,
/// `ldr x0, [x1, #8]` and `ldur x0, [x1, #8]`. Both the input and the decoded word go through it,
/// so the comparison is between meanings, not spellings. None where the TypeScript would have
/// failed (an operand missing where it read one): then the two do not agree.
fn meaning(line: &Line) -> Option<(String, Vec<Option<Operand>>)> {
    let mut m = line.m.clone();
    let mut ops: Vec<Option<Operand>> = line
        .ops
        .iter()
        .filter(|op| !matches!(op, O::Shift(s) if s.s == "lsl" && s.amount == 0))
        .map(|op| Some(if let O::Word(w) = op { word(cond_name(w)) } else { op.clone() }))
        .collect();
    let at = |ops: &Vec<Option<Operand>>, k: usize| ops.get(k).and_then(|o| o.as_ref()).cloned();
    let get = |ops: &Vec<Option<Operand>>, k: usize| -> Option<Operand> { at(ops, k) };
    let imm_at = |ops: &Vec<Option<Operand>>, k: usize| -> Option<i128> {
        match ops.get(k) {
            Some(Some(O::Imm(v))) => Some(v.v),
            _ => None,
        }
    };
    let reg_at = |ops: &Vec<Option<Operand>>, k: usize| -> Option<Reg> {
        match ops.get(k) {
            Some(Some(O::Reg(r))) => Some(r.clone()),
            _ => None,
        }
    };
    let zr_at = |ops: &Vec<Option<Operand>>, k: usize| is_zr(ops.get(k).and_then(|o| o.as_ref()));
    let slice = |ops: &Vec<Option<Operand>>, from: usize| -> Vec<Option<Operand>> { ops.get(from..).map_or(Vec::new(), |s| s.to_vec()) };
    let first = |ops: &Vec<Option<Operand>>| -> Option<Operand> { at(ops, 0) };

    if m == "ret" && reg_at(&ops, 0).is_some_and(|r| r.cls == 'x' && r.n == 30) {
        ops = Vec::new();
    }
    if m == "hint" {
        if let Some(name) = imm_at(&ops, 0).filter(|v| (0..=u32::MAX as i128).contains(v)).and_then(|v| hint_name(v as u32)) {
            let mut parts = name.split(' ');
            m = parts.next().unwrap_or("").to_string();
            ops = parts.next().map(|o| vec![Some(word(o))]).unwrap_or_default();
        }
    }
    // Barriers by number, as the names the decoder prints; DSB with these domains has names of its own.
    if m == "dsb" || m == "dmb" {
        if let Some(n) = imm_at(&ops, 0) {
            let dsb = match n {
                0 => Some("ssbb"),
                4 => Some("pssbb"),
                12 => Some("dfb"),
                _ => None,
            };
            if let (true, Some(name)) = (m == "dsb", dsb) {
                m = name.to_string();
                ops = Vec::new();
            } else if let Some(name) = (0..16).contains(&n).then(|| barrier_name(n as u32)).flatten() {
                ops = vec![Some(word(name))];
            } else if let Some(name) = (m == "dsb").then(|| nxs_name(n as f64)).flatten() {
                ops = vec![Some(word(name))];
            }
        }
    }
    if (m == "isb" || m == "clrex") && imm_at(&ops, 0) == Some(15) {
        ops = Vec::new();
    }
    if matches!(m.as_str(), "lslv" | "lsrv" | "asrv" | "rorv") {
        m.pop();
    }
    let logical_not = match m.as_str() {
        "bic" => Some("and"),
        "orn" => Some("orr"),
        "eon" => Some("eor"),
        "bics" => Some("ands"),
        _ => None,
    };
    if let (Some(to), Some(v)) = (logical_not, imm_at(&ops, 2)) {
        m = to.to_string();
        ops = vec![get(&ops, 0), get(&ops, 1), Some(imm(!v))];
    }
    if matches!(m.as_str(), "subs" | "adds" | "ands") && zr_at(&ops, 0) {
        m = match m.as_str() {
            "subs" => "cmp",
            "adds" => "cmn",
            _ => "tst",
        }
        .to_string();
        ops = slice(&ops, 1);
    }
    // add/sub immediates: the lsl #12 folded into the value, a negative value turned around.
    let flip = |m: &str| -> Option<&'static str> {
        Some(match m {
            "add" => "sub",
            "sub" => "add",
            "adds" => "subs",
            "subs" => "adds",
            "cmp" => "cmn",
            "cmn" => "cmp",
            _ => return None,
        })
    };
    let at_k = if m == "cmp" || m == "cmn" { 1 } else { 2 };
    if let (Some(to), Some(mut v)) = (flip(&m), imm_at(&ops, at_k)) {
        if let Some(Some(O::Shift(s))) = ops.get(at_k + 1) {
            v = v.checked_shl(s.amount)?;
        }
        if v < 0 {
            m = to.to_string();
            v = -v;
        }
        ops = ops[..at_k].to_vec();
        ops.push(Some(imm(v)));
        if (m == "add" || m == "sub") && v == 0 {
            m = "mov".into();
            ops.truncate(2);
        }
    }
    if flip(&m).is_some() {
        if let Some(Some(O::Shift(ext))) = ops.get(at_k + 1).cloned() {
            // The extend that changes nothing reads as lsl.
            let w = width(first(&ops).as_ref());
            if (ext.s == "uxtx" && w == 64) || (ext.s == "uxtw" && w == 32) {
                let mut kept = ops[..at_k + 1].to_vec();
                if ext.amount != 0 {
                    kept.push(Some(O::Shift(Shift { s: "lsl", ..ext })));
                }
                ops = kept;
            }
        }
    }
    if (m == "sub" || m == "subs") && zr_at(&ops, 1) && reg_at(&ops, 2).is_some() {
        m = if m == "sub" { "neg".into() } else { "negs".into() };
        let mut o = vec![get(&ops, 0)];
        o.extend(slice(&ops, 2));
        ops = o;
    }
    if m == "orr" && zr_at(&ops, 1) && ops.len() == 3 {
        m = "mov".into();
        ops = vec![get(&ops, 0), get(&ops, 2)];
    }
    if m == "orn" && zr_at(&ops, 1) && reg_at(&ops, 2).is_some() {
        m = "mvn".into();
        let mut o = vec![get(&ops, 0)];
        o.extend(slice(&ops, 2));
        ops = o;
    }
    if m == "movz" || m == "movn" {
        if let Some(v) = imm_at(&ops, 1) {
            let shift = match ops.get(2) {
                Some(Some(O::Shift(s))) => s.amount,
                _ => 0,
            };
            let v = v.checked_shl(shift)?;
            ops = vec![get(&ops, 0), Some(imm(if m == "movn" { !v } else { v }))];
            m = "mov".into();
        }
    }
    if matches!(m.as_str(), "mov" | "and" | "orr" | "eor" | "ands" | "tst") {
        if let Some(Some(O::Imm(last))) = ops.last() {
            let v = as_uint(width(first(&ops).as_ref()) as u32, last.v);
            let n = ops.len();
            ops[n - 1] = Some(imm(v));
        }
    }
    // The conditional aliases, first spelt out, then taken back to the one the decoder prefers.
    let spelled = match m.as_str() {
        "cset" | "cinc" => Some("csinc"),
        "csetm" | "cinv" => Some("csinv"),
        "cneg" => Some("csneg"),
        _ => None,
    };
    if let (Some(to), Some(r0)) = (spelled, reg_at(&ops, 0)) {
        let n = if m.starts_with("cset") { Some(O::Reg(zr_like(&r0))) } else { get(&ops, 1) };
        let last = ops.last().cloned().flatten();
        ops = vec![Some(O::Reg(r0)), n.clone(), n, inverse(last.as_ref())];
        m = to.to_string();
    }
    if matches!(m.as_str(), "csinc" | "csinv" | "csneg") && ops.len() == 4 {
        if let (Some(r1), Some(r2)) = (reg_at(&ops, 1), reg_at(&ops, 2)) {
            if r1.n == r2.n && r1.sp == r2.sp {
                let c = match ops.get(3) {
                    Some(Some(O::Word(w))) => cond_index(w),
                    _ => None,
                };
                if c.is_some_and(|c| c < 14) {
                    let inv = inverse(at(&ops, 3).as_ref());
                    if zr_at(&ops, 1) && m != "csneg" {
                        m = if m == "csinc" { "cset".into() } else { "csetm".into() };
                        ops = vec![get(&ops, 0), inv];
                    } else {
                        m = match m.as_str() {
                            "csinc" => "cinc",
                            "csinv" => "cinv",
                            _ => "cneg",
                        }
                        .into();
                        ops = vec![get(&ops, 0), get(&ops, 1), inv];
                    }
                }
            }
        }
    }
    let last_zr = ops.len() == 4 && zr_at(&ops, 3);
    let product = match m.as_str() {
        "madd" => Some("mul"),
        "msub" => Some("mneg"),
        "smaddl" => Some("smull"),
        "umaddl" => Some("umull"),
        "smsubl" => Some("smnegl"),
        "umsubl" => Some("umnegl"),
        _ => None,
    };
    if let (Some(to), true) = (product, last_zr) {
        m = to.to_string();
        ops.truncate(3);
    }

    // The bitfield aliases, as the bitfield move they are.
    let mut w = width(first(&ops).as_ref());
    let num = |ops: &Vec<Option<Operand>>, k: usize| imm_at(ops, k);
    let bfm = |m: &mut String, ops: &mut Vec<Option<Operand>>, w: i128, opc: usize, immr: i128, imms: i128| {
        *m = ["sbfm", "bfm", "ubfm"][opc].to_string();
        let same = at(ops, 1).map(|op| with_cls(&op, if w == 64 { 'x' } else { 'w' }));
        *ops = vec![get(ops, 0), same, Some(imm(immr)), Some(imm(imms))];
    };
    let field_alias = match m.as_str() {
        "sbfx" => Some((0, false)),
        "bfxil" => Some((1, false)),
        "ubfx" => Some((2, false)),
        "sbfiz" => Some((0, true)),
        "bfi" => Some((1, true)),
        "ubfiz" => Some((2, true)),
        _ => None,
    };
    if let (Some((opc, insert)), 4) = (field_alias, ops.len()) {
        // Number(op.v) of an operand that is not an immediate is NaN, and BigInt(NaN) throws.
        let (lsb, size) = (num(&ops, 2)?, num(&ops, 3)?);
        if insert {
            bfm(&mut m, &mut ops, w, opc, (w - lsb) % w, size - 1);
        } else {
            bfm(&mut m, &mut ops, w, opc, lsb, lsb + size - 1);
        }
    } else if matches!(m.as_str(), "lsl" | "lsr" | "asr") && imm_at(&ops, 2).is_some() {
        let s = num(&ops, 2)?;
        if m == "lsl" {
            bfm(&mut m, &mut ops, w, 2, (w - s) % w, w - 1 - s);
        } else {
            let opc = if m == "lsr" { 2 } else { 0 };
            bfm(&mut m, &mut ops, w, opc, s, w - 1);
        }
    } else if m == "ror" && imm_at(&ops, 2).is_some() {
        m = "extr".into();
        ops = vec![get(&ops, 0), get(&ops, 1), get(&ops, 1), get(&ops, 2)];
    } else if matches!(m.as_str(), "sxtb" | "sxth" | "sxtw" | "uxtb" | "uxth" | "uxtw") && ops.len() == 2 {
        if m.starts_with('u') {
            if let Some(r0) = reg_at(&ops, 0) {
                ops = vec![Some(O::Reg(Reg { cls: 'w', ..r0 })), get(&ops, 1)];
            }
        }
        w = width(first(&ops).as_ref());
        let opc = if m.starts_with('s') { 0 } else { 2 };
        let imms = match m.as_bytes()[3] {
            b'b' => 7,
            b'h' => 15,
            _ => 31,
        };
        bfm(&mut m, &mut ops, w, opc, 0, imms);
    }

    if (m == "tbz" || m == "tbnz") && imm_at(&ops, 1).is_some_and(|v| v < 32) {
        if let Some(r0) = reg_at(&ops, 0) {
            ops[0] = Some(O::Reg(Reg { cls: 'w', ..r0 }));
        }
    }
    let plain_offset = matches!(ops.get(1), Some(Some(O::Mem(mem))) if mem.mode == Mode::Off && mem.index.is_none());
    if plain_offset {
        let load_store = m == "prfm" || {
            let rest = m.strip_prefix("ldr").or_else(|| m.strip_prefix("str"));
            rest.is_some_and(|s| matches!(s, "" | "b" | "h" | "sb" | "sh" | "sw"))
        };
        if load_store {
            m = if m == "prfm" { "prfum".into() } else { format!("{}ur{}", &m[..2], &m[3..]) };
        }
    }
    if m == "fmov" || m == "fcmp" || m == "fcmpe" {
        for op in ops.iter_mut() {
            if let Some(O::Imm(v)) = op {
                *op = Some(O::Float(v.number()));
            }
        }
        if m == "fmov" {
            if let (Some(Some(O::Float(v))), Some(r0)) = (ops.get(1), reg_at(&ops, 0)) {
                if *v == 0.0 && v.is_sign_positive() {
                    let zr = Reg { cls: if r0.cls == 'd' { 'x' } else { 'w' }, n: 31, sp: false };
                    ops = vec![Some(O::Reg(r0)), Some(O::Reg(zr))];
                }
            }
        }
    }
    // ^ld(add|clr|eor|set|smax|smin|umax|umin)(l?)(b|h)?$
    if let Some(rest) = m.strip_prefix("ld") {
        if let Some(op) = ATOMIC_OPS.iter().find(|op| rest.starts_with(*op)) {
            let tail = &rest[op.len()..];
            if matches!(tail, "" | "l" | "b" | "h" | "lb" | "lh") && ops.len() == 3 && zr_at(&ops, 1) {
                m = format!("st{op}{tail}");
                ops = vec![get(&ops, 0), get(&ops, 2)];
            }
        }
    }
    if m == "adrp" {
        if let Some(v) = imm_at(&ops, 1) {
            ops[1] = Some(imm(v & !0xfff));
        }
    }
    Some((m, ops))
}

fn canonical(op: &Operand) -> String {
    match op {
        O::Reg(r) => reg_name(r),
        O::Imm(v) => match &v.big {
            Some(b) => format!("#{}", b.hex()),
            None => format!("#{}", v.v),
        },
        O::Float(v) => format!("#f{}", js_number(*v)),
        O::Word(w) => w.clone(),
        O::Shift(s) => {
            if s.amount != 0 {
                format!("{} #{}", s.s, s.amount)
            } else {
                s.s.to_string()
            }
        }
        O::Mem(mem) => {
            let mut inner = reg_name(&mem.base);
            if let Some(index) = &mem.index {
                inner.push_str(&format!(", {}", reg_name(index)));
                if let Some(ext) = mem.ext.as_ref().filter(|e| !(e.s == "lsl" && e.amount == 0)) {
                    inner.push_str(&format!(", {}", canonical(&O::Shift(ext.clone()))));
                }
            } else {
                inner.push_str(&format!(", {}", canonical(&O::Imm(mem.off.clone()))));
            }
            format!(
                "[{inner}]{}",
                match mem.mode {
                    Mode::Pre => "!",
                    Mode::Post => " post",
                    Mode::Off => "",
                }
            )
        }
    }
}

fn spell((m, ops): &(String, Vec<Option<Operand>>)) -> Option<String> {
    let mut parts = Vec::new();
    for op in ops {
        parts.push(canonical(op.as_ref()?));
    }
    Some(format!("{m} {}", parts.join(", ")))
}

fn same_meaning(input: &Line, decoded: &str) -> bool {
    let Ok(Some(back)) = parse(decoded, &NoNames) else { return false };
    let ours = meaning(input).and_then(|x| spell(&x));
    let theirs = meaning(&back).and_then(|x| spell(&x));
    ours.is_some() && ours == theirs
}

/* ------------------------------------------------------------------ */

/// One instruction in the syntax the decoder prints, to be placed at `pc`: its word, or why it does
/// not assemble. `resolve` gives the address of a name — a function, a label, a symbol — where the
/// text uses one as a branch or address target.
pub fn assemble(text: &str, pc: f64, resolve: &dyn Resolve) -> Result<u32, AsmError> {
    let mut mnemonic = String::new();
    let run = |mnemonic: &mut String| -> R<u32> {
        let Some(line) = parse(text, resolve)? else { return fail_with(AsmError::Empty) };
        *mnemonic = line.m.clone();
        let word = encode(&line, pc)?;
        if line.m == ".inst" {
            return Ok(word);
        }
        let back = format_insn(&decode(word, pc as i64)).as_str().to_string();
        if !same_meaning(&line, &back) {
            return fail_with(AsmError::Differs(back));
        }
        Ok(word)
    };
    run(&mut mnemonic).map_err(|Problem(e)| e.unwrap_or(AsmError::Operands(mnemonic)))
}

#[cfg(test)]
mod tests {
    use super::super::decode::decode_bit_mask;
    use super::*;

    #[test]
    fn bit_masks_round_trip() {
        let mut wrong = 0;
        for width in [32u32, 64] {
            for n in 0..=u32::from(width == 64) {
                for imms in 0..64 {
                    for immr in 0..64 {
                        let Some(value) = decode_bit_mask(n, imms, immr, width) else { continue };
                        match encode_bit_mask(value, width) {
                            Some((en, eimmr, eimms)) if decode_bit_mask(en, eimms, eimmr, width) == Some(value) => {}
                            _ => wrong += 1,
                        }
                    }
                }
            }
        }
        assert_eq!(wrong, 0);
        assert_eq!([decode_bit_mask(1, 7, 0, 64), decode_bit_mask(0, 0x3c, 0, 64), decode_bit_mask(0, 0x3f, 0, 32)], [Some(0xff), Some(0x5555555555555555), None]);
    }

    #[test]
    fn numbers_past_i128() {
        let big = parse_integer("#0x1000000000000000000000000000000000").unwrap();
        assert_eq!(big.shown(), "#0x1000000000000000000000000000000000");
        assert_eq!(big.number(), 2f64.powi(132));
        assert_eq!(parse_integer("-5").unwrap().v, -5);
        assert_eq!(assemble("add x0, x1, #0x1000000000000000000000000000000000", 0.0, &NoNames), Err(AsmError::Immediate("#0x1000000000000000000000000000000000".into())));
    }
}
