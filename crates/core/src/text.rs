//! Short strings kept inline, and numbers written the way JavaScript writes them.
//!
//! A decoded instruction is a handful of short strings — a mnemonic, register
//! names, an immediate's text. The analysis decodes every instruction of a
//! program, millions of them, so these strings live inside the instruction
//! itself rather than on the heap: decoding allocates nothing.
//!
//! The TypeScript core this one replaces computed with JavaScript numbers, and
//! the listing must stay byte for byte what it printed, so the formatting
//! helpers here follow JavaScript's `toString(16)` and `String(n)`.

use core::fmt;
use core::ops::Deref;

/// A string of at most `N` bytes, stored inline. Longer text is cut (and is a
/// bug the debug build reports): every caller knows its bound.
#[derive(Clone, Copy)]
pub struct Str<const N: usize> {
    len: u8,
    buf: [u8; N],
}

impl<const N: usize> Str<N> {
    pub const fn new() -> Self {
        Str { len: 0, buf: [0; N] }
    }

    /// A string known at compile time: register names and the like, built into tables once.
    pub const fn from_static(s: &str) -> Self {
        let bytes = s.as_bytes();
        let mut buf = [0u8; N];
        let mut i = 0;
        while i < bytes.len() && i < N {
            buf[i] = bytes[i];
            i += 1;
        }
        Str { len: i as u8, buf }
    }

    #[inline(always)]
    pub fn from(s: &str) -> Self {
        let mut out = Self::new();
        out.push(s);
        out
    }

    #[inline(always)]
    pub fn push(&mut self, s: &str) {
        let len = self.len as usize;
        let room = N - len;
        debug_assert!(s.len() <= room, "Str<{N}> overflow: {:?} + {:?}", self.as_str(), s);
        let mut take = s.len().min(room);
        // Never cut a character in two: the bytes stay valid UTF-8, so as_str needs no check.
        while !s.is_char_boundary(take) {
            take -= 1;
        }
        self.buf[len..len + take].copy_from_slice(&s.as_bytes()[..take]);
        self.len = (len + take) as u8;
    }

    /// Appends one ASCII byte.
    #[inline]
    pub fn push_byte(&mut self, b: u8) {
        debug_assert!(b.is_ascii());
        let len = self.len as usize;
        debug_assert!(len < N, "Str<{N}> overflow");
        if len < N {
            self.buf[len] = b;
            self.len += 1;
        }
    }

    #[inline]
    pub fn as_str(&self) -> &str {
        // SAFETY: only whole characters are ever pushed (push cuts at a character boundary, push_byte takes ASCII).
        unsafe { core::str::from_utf8_unchecked(&self.buf[..self.len as usize]) }
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Str<15> {
    /// The whole string — length and bytes, zeros past the end — as one number: a mnemonic
    /// compares and hashes as a single value.
    #[inline]
    pub fn key(&self) -> u128 {
        let mut bytes = [0u8; 16];
        bytes[0] = self.len;
        bytes[1..].copy_from_slice(&self.buf);
        u128::from_le_bytes(bytes)
    }
}

impl<const N: usize> Default for Str<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Deref for Str<N> {
    type Target = str;
    #[inline]
    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl<const N: usize> fmt::Write for Str<N> {
    #[inline]
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.push(s);
        Ok(())
    }
}

impl<const N: usize> fmt::Display for Str<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<const N: usize> fmt::Debug for Str<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}

impl<const N: usize> PartialEq for Str<N> {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl<const N: usize> Eq for Str<N> {}

impl<const N: usize> core::hash::Hash for Str<N> {
    #[inline]
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        state.write(self.as_str().as_bytes());
    }
}

impl<const N: usize> PartialEq<str> for Str<N> {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl<const N: usize> PartialEq<&str> for Str<N> {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

/// Builds a `Str` from format arguments: `sfmt!(Mn, "ld{}{}", op, order)`.
#[macro_export]
macro_rules! sfmt {
    ($ty:ty, $($arg:tt)*) => {{
        let mut s = <$ty>::new();
        let _ = core::fmt::Write::write_fmt(&mut s, format_args!($($arg)*));
        s
    }};
}

const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Appends the hex digits of `v` (no prefix).
#[inline]
pub fn push_hex_u128<const N: usize>(out: &mut Str<N>, mut v: u128) {
    if v <= u64::MAX as u128 {
        return push_hex_u64(out, v as u64);
    }
    let mut tmp = [0u8; 32];
    let mut i = tmp.len();
    loop {
        i -= 1;
        tmp[i] = DIGITS[(v & 15) as usize];
        v >>= 4;
        if v == 0 {
            break;
        }
    }
    // SAFETY: hex digits are ASCII.
    out.push(unsafe { core::str::from_utf8_unchecked(&tmp[i..]) });
}

#[inline]
pub fn push_hex_u64<const N: usize>(out: &mut Str<N>, mut v: u64) {
    let mut tmp = [0u8; 16];
    let mut i = tmp.len();
    loop {
        i -= 1;
        tmp[i] = DIGITS[(v & 15) as usize];
        v >>= 4;
        if v == 0 {
            break;
        }
    }
    // SAFETY: hex digits are ASCII.
    out.push(unsafe { core::str::from_utf8_unchecked(&tmp[i..]) });
}

/// JavaScript's `v < 0 ? '-0x' + (-v).toString(16) : '0x' + v.toString(16)` for an integer.
#[inline]
pub fn push_hex<const N: usize>(out: &mut Str<N>, v: i64) {
    if v < 0 {
        out.push("-0x");
        push_hex_u64(out, v.unsigned_abs());
    } else {
        out.push("0x");
        push_hex_u64(out, v as u64);
    }
}

/// The same for a 128-bit value (BigInt arithmetic in the TypeScript core).
#[inline]
pub fn push_hex_i128<const N: usize>(out: &mut Str<N>, v: i128) {
    if v < 0 {
        out.push("-0x");
        push_hex_u128(out, v.unsigned_abs());
    } else {
        out.push("0x");
        push_hex_u128(out, v as u128);
    }
}

/// An integer in decimal.
#[inline]
pub fn push_dec<const N: usize>(out: &mut Str<N>, v: i64) {
    let mut tmp = [0u8; 21];
    let mut i = tmp.len();
    let mut u = v.unsigned_abs();
    loop {
        i -= 1;
        tmp[i] = b'0' + (u % 10) as u8;
        u /= 10;
        if u == 0 {
            break;
        }
    }
    if v < 0 {
        i -= 1;
        tmp[i] = b'-';
    }
    out.push(unsafe { core::str::from_utf8_unchecked(&tmp[i..]) });
}

/// `hex(v)` into a String (for the code that builds text on the heap anyway).
pub fn hex(v: i64) -> String {
    let mut s = Str::<24>::new();
    push_hex(&mut s, v);
    s.as_str().to_string()
}

/// JavaScript's `String(v)` for a number: integers without a fraction, others
/// in the shortest form that reads back the same, `NaN`, `Infinity`.
pub fn js_number(v: f64) -> String {
    if v.is_nan() {
        return "NaN".into();
    }
    if v.is_infinite() {
        return if v > 0.0 { "Infinity".into() } else { "-Infinity".into() };
    }
    if v == 0.0 {
        return "0".into();
    }
    let abs = v.abs();
    // JavaScript writes digits with a point while the decimal exponent n of the shortest digits
    // has −6 < n ≤ 21: from 1e-6 (0.000001) up to 1e21; 1e-7 is already `1e-7`.
    if (1e-6..1e21).contains(&abs) {
        // Rust's shortest round-trip form matches JavaScript's in this range,
        // except that Rust prints integral floats with no fraction already.
        let s = format!("{}", v);
        return s;
    }
    // Exponent form: JavaScript writes 1e+21, 1.5e-7.
    let s = format!("{:e}", v);
    match s.split_once('e') {
        Some((mantissa, exp)) if !exp.starts_with('-') => format!("{mantissa}e+{exp}"),
        _ => s,
    }
}

/// JavaScript's `v.toString(16)` for an integral number (exact, whatever its size).
pub fn js_hex(v: f64) -> String {
    if v < 0.0 {
        return format!("-{}", js_hex(-v));
    }
    if v.fract() != 0.0 || !v.is_finite() {
        // Fractions do not occur where the core prints hex.
        return js_number(v);
    }
    let mut s = Str::<40>::new();
    push_hex_u128(&mut s, v as u128);
    s.as_str().to_string()
}

/// JavaScript's ToInt32: what a bitwise operator makes of a number (its integer part, modulo 2^32, signed).
pub fn to_int32(v: f64) -> i32 {
    to_uint32(v) as i32
}

/// JavaScript's ToUint32 (`v >>> 0`).
pub fn to_uint32(v: f64) -> u32 {
    if !v.is_finite() {
        return 0;
    }
    let t = v.trunc();
    // The integer part modulo 2^32: exact in a double, whatever its size.
    (t.rem_euclid(4294967296.0)) as u32
}

/// JavaScript's `v.toLocaleString('en')` for an integral number: the digits of `String(v)` (padded
/// with zeros past 1e21, where that turns to an exponent) in groups of three.
pub fn js_locale(v: f64) -> String {
    if !v.is_finite() || v.fract() != 0.0 {
        // Fractions and non-numbers do not occur where the core groups digits.
        return js_number(v);
    }
    let digits = if v.abs() < 1e21 {
        format!("{}", v.abs())
    } else {
        let s = format!("{:e}", v.abs());
        let (mantissa, exp) = s.split_once('e').unwrap_or((&s, "0"));
        let digits: String = mantissa.chars().filter(|c| c.is_ascii_digit()).collect();
        let zeros = exp.parse::<usize>().unwrap_or(0) + 1 - digits.len();
        digits + &"0".repeat(zeros)
    };
    let mut out = String::with_capacity(digits.len() + digits.len() / 3 + 1);
    if v < 0.0 {
        out.push('-');
    }
    for (k, c) in digits.chars().enumerate() {
        if k > 0 && (digits.len() - k) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_like_javascript() {
        let mut s = Str::<24>::new();
        push_hex(&mut s, -16);
        assert_eq!(s.as_str(), "-0x10");
        assert_eq!(js_hex(2f64.powi(64)), "10000000000000000");
        assert_eq!(js_number(1.0), "1");
        assert_eq!(js_number(0.5), "0.5");
        assert_eq!(js_number(1e21), "1e+21");
        assert_eq!([js_number(1e-6), js_number(1e-7), js_number(5e-7), js_number(1.5e-6)], ["0.000001", "1e-7", "5e-7", "0.0000015"]);
        assert_eq!(js_number(18446744073709552000.0), "18446744073709552000");
        assert_eq!(js_locale(2f64.powi(64)), "18,446,744,073,709,552,000");
        assert_eq!(js_locale(2f64.powi(70)), "1,180,591,620,717,411,300,000");
        assert_eq!(js_locale(123456789012.0), "123,456,789,012");
        assert_eq!(js_locale(999.0), "999");
        assert_eq!(to_int32(2147483648.0), -2147483648);
        assert_eq!(to_uint32(-1.0), 4294967295);
        assert_eq!(to_int32(2f64.powi(64) + 4096.0), 4096);
        assert_eq!(to_uint32(-5.5), 4294967291);
    }
}
