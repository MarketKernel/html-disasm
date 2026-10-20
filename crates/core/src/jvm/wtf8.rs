//! Text as JavaScript holds it, in WTF-8.
//!
//! A class file's names and strings are "modified" UTF-8, which may encode a
//! surrogate on its own (half of a pair, or a lone one): the TypeScript core
//! decoded them into JavaScript strings, which are UTF-16 and keep a lone
//! surrogate as it is. A Rust `str` cannot hold one, so the text here is
//! WTF-8 (the encoding of "potentially ill-formed UTF-16"): UTF-8, except that
//! a lone surrogate is written as the three bytes UTF-8 would give its code
//! point, and a high surrogate followed by a low one is always the four bytes
//! of the character they make. A string without a lone surrogate — nearly all
//! of them — is plain UTF-8 (`as_str`), and every JavaScript string has one
//! WTF-8 form and back (`to_utf16`, `from_utf16`), so two texts are the same
//! JavaScript string exactly when their bytes are equal.

use core::fmt;
use core::ops::Deref;
use std::borrow::{Borrow, Cow};

/// Borrowed WTF-8 text, like `str`.
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Wtf8 {
    bytes: [u8],
}

/// Owned WTF-8 text, like `String`.
#[derive(Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Wtf8Buf {
    bytes: Vec<u8>,
}

impl Wtf8 {
    /// UTF-8 is WTF-8.
    #[inline]
    pub fn new(s: &str) -> &Wtf8 {
        // SAFETY: valid UTF-8 is valid WTF-8.
        unsafe { Wtf8::from_bytes_unchecked(s.as_bytes()) }
    }

    /// # Safety
    /// `bytes` must be well-formed WTF-8.
    #[inline]
    pub(crate) unsafe fn from_bytes_unchecked(bytes: &[u8]) -> &Wtf8 {
        // SAFETY: Wtf8 is a transparent wrapper of [u8].
        unsafe { &*(bytes as *const [u8] as *const Wtf8) }
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Its length in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    #[inline]
    pub fn is_ascii(&self) -> bool {
        self.bytes.is_ascii()
    }

    /// The text as a `str`, unless it holds a lone surrogate.
    #[inline]
    pub fn as_str(&self) -> Option<&str> {
        // A lone surrogate is the only thing WTF-8 has that UTF-8 rejects.
        core::str::from_utf8(&self.bytes).ok()
    }

    /// The text with each lone surrogate replaced by U+FFFD (what a browser shows, or `TextEncoder` writes).
    pub fn to_string_lossy(&self) -> Cow<'_, str> {
        if let Some(s) = self.as_str() {
            return Cow::Borrowed(s);
        }
        Cow::Owned(self.code_points().map(|c| char::from_u32(c).unwrap_or('\u{fffd}')).collect())
    }

    /// The code points, a lone surrogate as its own value (0xD800–0xDFFF): JavaScript's `for (const c of text)`.
    #[inline]
    pub fn code_points(&self) -> CodePoints<'_> {
        CodePoints { bytes: &self.bytes, at: 0 }
    }

    /// The UTF-16 code units: the JavaScript string.
    pub fn to_utf16(&self) -> Vec<u16> {
        let mut out = Vec::with_capacity(self.bytes.len());
        for c in self.code_points() {
            if c >= 0x10000 {
                let v = c - 0x10000;
                out.push(0xd800 | (v >> 10) as u16);
                out.push(0xdc00 | (v & 0x3ff) as u16);
            } else {
                out.push(c as u16);
            }
        }
        out
    }

    #[inline]
    pub fn starts_with(&self, prefix: &str) -> bool {
        self.bytes.starts_with(prefix.as_bytes())
    }

    #[inline]
    pub fn ends_with(&self, suffix: &str) -> bool {
        self.bytes.ends_with(suffix.as_bytes())
    }

    /// The order of JavaScript's `<` on the two strings: by UTF-16 code units, which is not the
    /// order of the code points (a character past the BMP sorts before U+E000–U+FFFF).
    pub fn cmp_utf16(&self, other: &Wtf8) -> core::cmp::Ordering {
        if self.is_ascii() && other.is_ascii() {
            return self.bytes.cmp(&other.bytes);
        }
        utf16_units(self).cmp(utf16_units(other))
    }

    /// The text with every ASCII `from` replaced by the ASCII `to` (`text.replace(/\//g, '.')`).
    pub fn replace_ascii(&self, from: u8, to: u8) -> Wtf8Buf {
        debug_assert!(from.is_ascii() && to.is_ascii());
        Wtf8Buf { bytes: self.bytes.iter().map(|&b| if b == from { to } else { b }).collect() }
    }
}

impl ToOwned for Wtf8 {
    type Owned = Wtf8Buf;
    fn to_owned(&self) -> Wtf8Buf {
        Wtf8Buf { bytes: self.bytes.to_vec() }
    }
}

impl PartialEq<str> for Wtf8 {
    #[inline]
    fn eq(&self, other: &str) -> bool {
        &self.bytes == other.as_bytes()
    }
}

impl PartialEq<&str> for Wtf8 {
    #[inline]
    fn eq(&self, other: &&str) -> bool {
        &self.bytes == other.as_bytes()
    }
}

impl fmt::Display for Wtf8 {
    /// Lossy, as `to_string_lossy`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_string_lossy())
    }
}

impl fmt::Debug for Wtf8 {
    /// As a Rust string literal, a lone surrogate as `\u{d800}`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("\"")?;
        for c in self.code_points() {
            match char::from_u32(c) {
                Some(ch) => write!(f, "{}", ch.escape_debug())?,
                None => write!(f, "\\u{{{c:x}}}")?,
            }
        }
        f.write_str("\"")
    }
}

impl Default for &Wtf8 {
    fn default() -> Self {
        Wtf8::new("")
    }
}

/// The UTF-16 code units of WTF-8 text, one after another.
fn utf16_units(text: &Wtf8) -> impl Iterator<Item = u16> + '_ {
    text.code_points().flat_map(|c| {
        let pair = if c >= 0x10000 { [0xd800 | ((c - 0x10000) >> 10) as u16, 0xdc00 | ((c - 0x10000) & 0x3ff) as u16] } else { [c as u16, 0] };
        pair.into_iter().take(if c >= 0x10000 { 2 } else { 1 })
    })
}

/// The code points of WTF-8 text.
pub struct CodePoints<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Iterator for CodePoints<'_> {
    type Item = u32;

    #[inline]
    fn next(&mut self) -> Option<u32> {
        let b = &self.bytes[self.at..];
        let first = *b.first()? as u32;
        // Well-formed WTF-8: the lead byte says the length, the rest are continuation bytes.
        let (c, n) = if first < 0x80 {
            (first, 1)
        } else if first < 0xe0 {
            (((first & 0x1f) << 6) | (b[1] as u32 & 0x3f), 2)
        } else if first < 0xf0 {
            (((first & 0x0f) << 12) | ((b[1] as u32 & 0x3f) << 6) | (b[2] as u32 & 0x3f), 3)
        } else {
            (((first & 0x07) << 18) | ((b[1] as u32 & 0x3f) << 12) | ((b[2] as u32 & 0x3f) << 6) | (b[3] as u32 & 0x3f), 4)
        };
        self.at += n;
        Some(c)
    }
}

impl Wtf8Buf {
    #[inline]
    pub const fn new() -> Self {
        Wtf8Buf { bytes: Vec::new() }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Wtf8Buf { bytes: Vec::with_capacity(capacity) }
    }

    /// A JavaScript string's code units, a lone surrogate kept.
    pub fn from_utf16(units: &[u16]) -> Self {
        let mut out = Wtf8Buf::with_capacity(units.len());
        for &u in units {
            out.push_unit(u);
        }
        out
    }

    #[inline]
    pub fn as_wtf8(&self) -> &Wtf8 {
        // SAFETY: the buffer is kept well-formed.
        unsafe { Wtf8::from_bytes_unchecked(&self.bytes) }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// The text as a `String`, unless it holds a lone surrogate.
    pub fn into_string(self) -> Result<String, Wtf8Buf> {
        String::from_utf8(self.bytes).map_err(|e| Wtf8Buf { bytes: e.into_bytes() })
    }

    pub fn clear(&mut self) {
        self.bytes.clear();
    }

    /// Cuts the text to `len` bytes, where the text from there on is ASCII the caller wrote.
    pub fn truncate_ascii(&mut self, len: usize) {
        debug_assert!(self.bytes[len.min(self.bytes.len())..].is_ascii());
        self.bytes.truncate(len);
    }

    #[inline]
    pub fn push_str(&mut self, s: &str) {
        // A str starts with no lone low surrogate, so nothing joins.
        self.bytes.extend_from_slice(s.as_bytes());
    }

    #[inline]
    pub fn push_byte(&mut self, b: u8) {
        debug_assert!(b.is_ascii());
        self.bytes.push(b);
    }

    /// Appends one byte of well-formed text that is being copied whole, byte by byte: the caller
    /// keeps the result well formed (and the text it copies does not start with a lone low
    /// surrogate the buffer's end could join).
    #[inline]
    pub(crate) fn push_raw_byte(&mut self, b: u8) {
        self.bytes.push(b);
    }

    pub fn push_char(&mut self, c: char) {
        let mut buf = [0u8; 4];
        self.push_str(c.encode_utf8(&mut buf));
    }

    /// Appends text: a lone high surrogate at the end and a lone low one at the start of `s` become
    /// one character, as they do when JavaScript strings are joined.
    pub fn push_wtf8(&mut self, s: &Wtf8) {
        let b = s.as_bytes();
        if b.len() >= 3 && b[0] == 0xed && b[1] >= 0xb0 {
            if let Some(high) = self.trailing_high() {
                let low = (((b[1] as u32) & 0x3f) << 6 | (b[2] as u32 & 0x3f)) | 0xd000;
                self.bytes.truncate(self.bytes.len() - 3);
                self.push_code_point(0x10000 + ((high - 0xd800) << 10) + (low - 0xdc00));
                self.bytes.extend_from_slice(&b[3..]);
                return;
            }
        }
        self.bytes.extend_from_slice(b);
    }

    /// Appends one UTF-16 code unit (JavaScript's `String.fromCharCode`).
    pub fn push_unit(&mut self, unit: u16) {
        let u = unit as u32;
        if (0xdc00..0xe000).contains(&u) {
            if let Some(high) = self.trailing_high() {
                self.bytes.truncate(self.bytes.len() - 3);
                self.push_code_point(0x10000 + ((high - 0xd800) << 10) + (u - 0xdc00));
                return;
            }
        }
        self.push_code_point(u);
    }

    /// The lone high surrogate the text ends with.
    fn trailing_high(&self) -> Option<u32> {
        let n = self.bytes.len();
        if n >= 3 && self.bytes[n - 3] == 0xed && (0xa0..0xb0).contains(&self.bytes[n - 2]) {
            Some(0xd000 | ((self.bytes[n - 2] as u32 & 0x3f) << 6) | (self.bytes[n - 1] as u32 & 0x3f))
        } else {
            None
        }
    }

    /// Appends a code point as it is encoded, a surrogate as three bytes (the caller joins pairs).
    fn push_code_point(&mut self, c: u32) {
        if c < 0x80 {
            self.bytes.push(c as u8);
        } else if c < 0x800 {
            self.bytes.extend_from_slice(&[0xc0 | (c >> 6) as u8, 0x80 | (c & 0x3f) as u8]);
        } else if c < 0x10000 {
            self.bytes.extend_from_slice(&[0xe0 | (c >> 12) as u8, 0x80 | ((c >> 6) & 0x3f) as u8, 0x80 | (c & 0x3f) as u8]);
        } else {
            self.bytes.extend_from_slice(&[0xf0 | (c >> 18) as u8, 0x80 | ((c >> 12) & 0x3f) as u8, 0x80 | ((c >> 6) & 0x3f) as u8, 0x80 | (c & 0x3f) as u8]);
        }
    }
}

impl Deref for Wtf8Buf {
    type Target = Wtf8;
    #[inline]
    fn deref(&self) -> &Wtf8 {
        self.as_wtf8()
    }
}

impl Borrow<Wtf8> for Wtf8Buf {
    fn borrow(&self) -> &Wtf8 {
        self.as_wtf8()
    }
}

impl AsRef<Wtf8> for Wtf8Buf {
    fn as_ref(&self) -> &Wtf8 {
        self.as_wtf8()
    }
}

impl AsRef<Wtf8> for Wtf8 {
    fn as_ref(&self) -> &Wtf8 {
        self
    }
}

impl AsRef<Wtf8> for str {
    fn as_ref(&self) -> &Wtf8 {
        Wtf8::new(self)
    }
}

impl From<&str> for Wtf8Buf {
    fn from(s: &str) -> Self {
        Wtf8Buf { bytes: s.as_bytes().to_vec() }
    }
}

impl From<String> for Wtf8Buf {
    fn from(s: String) -> Self {
        Wtf8Buf { bytes: s.into_bytes() }
    }
}

impl From<&Wtf8> for Wtf8Buf {
    fn from(s: &Wtf8) -> Self {
        s.to_owned()
    }
}

impl PartialEq<str> for Wtf8Buf {
    fn eq(&self, other: &str) -> bool {
        self.bytes == other.as_bytes()
    }
}

impl PartialEq<&str> for Wtf8Buf {
    fn eq(&self, other: &&str) -> bool {
        self.bytes == other.as_bytes()
    }
}

impl fmt::Display for Wtf8Buf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.as_wtf8(), f)
    }
}

impl fmt::Debug for Wtf8Buf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_wtf8(), f)
    }
}

impl fmt::Write for Wtf8Buf {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.push_str(s);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn surrogates_join_like_javascript() {
        let mut s = Wtf8Buf::new();
        s.push_unit(0xd83d);
        assert!(s.as_str().is_none());
        assert_eq!(s.to_utf16(), [0xd83d]);
        let mut low = Wtf8Buf::new();
        low.push_unit(0xde00);
        low.push_str("x");
        s.push_wtf8(&low);
        assert_eq!(s.as_str(), Some("😀x"));
        assert_eq!(Wtf8Buf::from_utf16(&[0x61, 0xdc00, 0xd800]).to_utf16(), [0x61, 0xdc00, 0xd800]);
        assert_eq!(Wtf8::new("é😀").code_points().collect::<Vec<_>>(), [0xe9, 0x1f600]);
    }
}
