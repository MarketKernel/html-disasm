//! Reading the WebAssembly binary format: LEB128 integers, floats, names and
//! the value types, and their text as the WebAssembly text format writes them
//! (`i32`, `funcref`, `(ref null 3)`).
//!
//! The TypeScript core kept integers that fit a double exactly as numbers, and
//! 64-bit values that do not (an i64.const, an offset of a 64-bit memory) as
//! bigints, so their text is exact. [`Num`] keeps that distinction: the
//! analysis looks at which of the two a value is.
//!
//! A port of src/core/wasm/reader.ts. One thing JavaScript did silently is
//! kept on purpose: a reader may be given an end past the end of the file (a
//! function body whose size says so), and a byte read there was `undefined`,
//! which most readers took for 0. [`Reader::u8`] reads such a byte as 0, and
//! [`Reader::byte`] says it is missing, for the few places where JavaScript
//! did something else with it.

use core::fmt::{self, Write};

/// What went wrong reading the binary format: an error code and its
/// parameters. The page words the message; the English text of each is in its
/// doc comment, as the TypeScript core wrote it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WasmError {
    /// `unexpected end at 0x{at}` (`at` in hex).
    UnexpectedEnd { at: usize },
    /// `LEB128 too long`
    LebTooLong,
    /// `unknown value type 0x{byte} at 0x{at}` (both in hex). With no byte
    /// (read past the end of the file) the TypeScript threw a TypeError instead:
    /// `Cannot read properties of undefined (reading 'toString')`.
    UnknownValType { byte: Option<u8>, at: usize },
    /// `unknown heap type {index}`
    UnknownHeapType { index: i64 },
    /// `bad block type {index}`
    BadBlockType { index: i64 },
    /// `unknown opcode`
    UnknownOpcode,
    /// `br_table too long`
    BrTableTooLong,
    /// `select too long`
    SelectTooLong,
    /// `try_table too long`
    TryTableTooLong,
    /// `atomic.fence: reserved byte`
    FenceReserved,
    /// `bad catch`
    BadCatch,
    /// `br_on_cast flags`
    BrOnCastFlags,
    /// The bits of an f64.const read past the end of the file: the TypeScript
    /// threw a TypeError, `Cannot convert undefined to a BigInt`.
    MissingBytes,
    /// `unknown type form 0x{form}` (in hex). With no form (read past the end of the file)
    /// the TypeScript threw a TypeError: `Cannot read properties of undefined (reading 'toString')`.
    UnknownTypeForm { form: Option<u8> },
    /// `import {module}.{name}: unknown kind` (boxed: errors pass through every read, so the type stays small).
    UnknownImportKind(Box<ImportName>),
    /// `bad constant expression at 0x{at}` (in hex).
    BadConstExpr { at: usize },
    /// `DWARF form {form}`
    DwarfForm { form: u64 },
}

/// The names of an import.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportName {
    pub module: String,
    pub name: String,
}

pub type Result<T> = core::result::Result<T, WasmError>;

impl fmt::Display for WasmError {
    /// The message the TypeScript core's error carried (English: the page shows it as it is).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const UNDEFINED_TO_STRING: &str = "Cannot read properties of undefined (reading 'toString')";
        match self {
            WasmError::UnexpectedEnd { at } => write!(f, "unexpected end at 0x{at:x}"),
            WasmError::LebTooLong => f.write_str("LEB128 too long"),
            WasmError::UnknownValType { byte: Some(byte), at } => write!(f, "unknown value type 0x{byte:x} at 0x{at:x}"),
            WasmError::UnknownValType { byte: None, .. } => f.write_str(UNDEFINED_TO_STRING),
            WasmError::UnknownHeapType { index } => write!(f, "unknown heap type {index}"),
            WasmError::BadBlockType { index } => write!(f, "bad block type {index}"),
            WasmError::UnknownOpcode => f.write_str("unknown opcode"),
            WasmError::BrTableTooLong => f.write_str("br_table too long"),
            WasmError::SelectTooLong => f.write_str("select too long"),
            WasmError::TryTableTooLong => f.write_str("try_table too long"),
            WasmError::FenceReserved => f.write_str("atomic.fence: reserved byte"),
            WasmError::BadCatch => f.write_str("bad catch"),
            WasmError::BrOnCastFlags => f.write_str("br_on_cast flags"),
            WasmError::MissingBytes => f.write_str("Cannot convert undefined to a BigInt"),
            WasmError::UnknownTypeForm { form: Some(form) } => write!(f, "unknown type form 0x{form:x}"),
            WasmError::UnknownTypeForm { form: None } => f.write_str(UNDEFINED_TO_STRING),
            WasmError::UnknownImportKind(name) => write!(f, "import {}.{}: unknown kind", name.module, name.name),
            WasmError::BadConstExpr { at } => write!(f, "bad constant expression at 0x{at:x}"),
            WasmError::DwarfForm { form } => write!(f, "DWARF form {form}"),
        }
    }
}

/// A JavaScript number or bigint holding an integer, as the TypeScript core
/// had it: values that fit a double exactly are numbers, the others bigints.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Num {
    Number(i64),
    BigInt(i128),
}

impl Num {
    /// The value, whichever kind it is.
    #[inline]
    pub fn value(self) -> i128 {
        match self {
            Num::Number(v) => v as i128,
            Num::BigInt(v) => v,
        }
    }

    /// `v !== 0 && v !== 0n` negated: zero of either kind.
    #[inline]
    pub fn is_zero(self) -> bool {
        self.value() == 0
    }

    /// Is it a JavaScript number (`typeof v === 'number'`)?
    #[inline]
    pub fn is_number(self) -> bool {
        matches!(self, Num::Number(_))
    }

    /// The number, when it is one.
    #[inline]
    pub fn number(self) -> Option<i64> {
        match self {
            Num::Number(v) => Some(v),
            Num::BigInt(_) => None,
        }
    }
}

impl Default for Num {
    fn default() -> Self {
        Num::Number(0)
    }
}

impl fmt::Display for Num {
    /// `String(v)`: the decimal digits of either kind.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Num::Number(v) => write!(f, "{v}"),
            Num::BigInt(v) => write!(f, "{v}"),
        }
    }
}

/// `Number.MAX_SAFE_INTEGER`
pub const MAX_SAFE_INTEGER: i128 = (1 << 53) - 1;

/// Bytes as UTF-8 text, as TextDecoder reads them: what does not decode
/// becomes U+FFFD, and a byte order mark at the start is dropped.
pub fn utf8(bytes: &[u8]) -> String {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    String::from_utf8_lossy(bytes).into_owned()
}

/// `pos + n` for a size read from the file: on a 32-bit target, a sum past the
/// address space stays at its end, past the end of any file there.
#[inline]
pub(crate) fn add(pos: usize, n: u64) -> usize {
    usize::try_from(n).ok().and_then(|n| pos.checked_add(n)).unwrap_or(usize::MAX)
}

#[derive(Clone, Copy, Debug)]
pub struct Reader<'a> {
    pub bytes: &'a [u8],
    pub pos: usize,
    pub end: usize,
}

impl<'a> Reader<'a> {
    #[inline]
    pub fn new(bytes: &'a [u8], pos: usize, end: usize) -> Self {
        Reader { bytes, pos, end }
    }

    #[inline]
    pub fn done(&self) -> bool {
        self.pos >= self.end
    }

    /// The next byte, or None past the end of the file while still before the
    /// reader's end (JavaScript's `undefined`).
    #[inline]
    pub fn byte(&mut self) -> Result<Option<u8>> {
        if self.pos >= self.end {
            return Err(WasmError::UnexpectedEnd { at: self.pos });
        }
        let b = self.bytes.get(self.pos).copied();
        self.pos += 1;
        Ok(b)
    }

    /// The next byte; one past the end of the file reads as 0.
    #[inline]
    pub fn u8(&mut self) -> Result<u8> {
        if self.pos >= self.end {
            return Err(WasmError::UnexpectedEnd { at: self.pos });
        }
        let b = self.bytes.get(self.pos).copied().unwrap_or(0);
        self.pos += 1;
        Ok(b)
    }

    /// The next byte without reading it, or -1 at the end.
    #[inline]
    pub fn peek(&self) -> i32 {
        if self.pos < self.end {
            self.bytes.get(self.pos).map_or(-1, |&b| b as i32)
        } else {
            -1
        }
    }

    /// An unsigned LEB128 of up to 32 bits (redundant leading bytes allowed).
    /// Like the TypeScript, it keeps the bits of the first five bytes: up to 35.
    #[inline]
    pub fn u32(&mut self) -> Result<u64> {
        // The usual case, one byte, first.
        if self.pos < self.end {
            if let Some(&b) = self.bytes.get(self.pos) {
                if b & 0x80 == 0 {
                    self.pos += 1;
                    return Ok(b as u64);
                }
            }
        }
        let mut result = 0u64;
        let mut shift = 0u32;
        loop {
            let byte = self.u8()?;
            if shift < 35 {
                result += ((byte & 0x7f) as u64) << shift;
            }
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
            if shift > 70 {
                return Err(WasmError::LebTooLong);
            }
        }
        Ok(result)
    }

    /// A signed LEB128 that fits in a double: s32, and the s33 of block types.
    #[inline]
    pub fn s32(&mut self) -> Result<i64> {
        let mut result = 0i64;
        let mut shift = 0u32;
        let mut byte;
        loop {
            byte = self.u8()?;
            if shift < 49 {
                result += ((byte & 0x7f) as i64) << shift;
            }
            shift += 7;
            if shift > 70 {
                return Err(WasmError::LebTooLong);
            }
            if byte & 0x80 == 0 {
                break;
            }
        }
        if byte & 0x40 != 0 {
            result -= if shift < 53 { 1i64 << shift } else { 1i64 << 49 };
        }
        Ok(result)
    }

    /// An unsigned 64-bit LEB128: a number when it is exact, a bigint otherwise.
    pub fn u64(&mut self) -> Result<Num> {
        let mut result = 0u128;
        let mut shift = 0u32;
        loop {
            let byte = self.u8()?;
            result += ((byte & 0x7f) as u128) << shift;
            shift += 7;
            if shift > 70 {
                return Err(WasmError::LebTooLong);
            }
            if byte & 0x80 == 0 {
                break;
            }
        }
        // The double sum is exact up to MAX_SAFE_INTEGER, so comparing the exact sum decides the same.
        if result as i128 <= MAX_SAFE_INTEGER {
            return Ok(Num::Number(result as i64));
        }
        // BigInt.asUintN(64, …) of the same bits.
        Ok(Num::BigInt((result as u64) as i128))
    }

    /// A signed 64-bit LEB128: a number when it is exact, a bigint otherwise.
    pub fn s64(&mut self) -> Result<Num> {
        let start = self.pos;
        let mut length = 0usize;
        while self.bytes.get(start + length).map_or(0, |&b| b & 0x80) != 0 {
            length += 1;
            if start + length >= self.end {
                return Err(WasmError::UnexpectedEnd { at: self.pos });
            }
        }
        length += 1;
        // Seven bytes carry 49 bits: their value is exact in a double.
        if length <= 7 {
            return Ok(Num::Number(self.s32()?));
        }
        // BigInt.asIntN(64, …) of the whole number: only its low 64 bits count.
        let mut result = 0u64;
        let mut shift = 0u32;
        let mut byte;
        loop {
            byte = self.u8()?;
            if shift < 64 {
                result |= ((byte & 0x7f) as u64) << shift;
            }
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
        }
        if byte & 0x40 != 0 && shift < 64 {
            result = result.wrapping_sub(1u64 << shift);
        }
        let value = result as i64 as i128;
        Ok(if (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&value) { Num::Number(value as i64) } else { Num::BigInt(value) })
    }

    /// The bits of an f32: bytes past the end of the file read as 0.
    pub fn f32_bits(&mut self) -> Result<u32> {
        let b = self.bytes_n(4)?;
        let at = |i: usize| b.get(i).copied().unwrap_or(0) as u32;
        Ok(at(0) | (at(1) << 8) | (at(2) << 16) | (at(3) << 24))
    }

    pub fn f64_bits(&mut self) -> Result<u64> {
        let b = self.bytes_n(8)?;
        if b.len() < 8 {
            return Err(WasmError::MissingBytes);
        }
        Ok(u64::from_le_bytes(b.try_into().unwrap()))
    }

    /// The next `n` bytes (fewer when the file ends first).
    pub fn bytes_n(&mut self, n: u64) -> Result<&'a [u8]> {
        let to = add(self.pos, n);
        if to > self.end || to == usize::MAX {
            return Err(WasmError::UnexpectedEnd { at: self.pos });
        }
        let len = self.bytes.len();
        let out = &self.bytes[self.pos.min(len)..to.min(len)];
        self.pos = to;
        Ok(out)
    }

    pub fn name(&mut self) -> Result<String> {
        let length = self.u32()?;
        Ok(utf8(self.bytes_n(length)?))
    }
}

/* ------------------------------------------------------------------ *
 * Value types
 * ------------------------------------------------------------------ */

/// Abstract heap types by their byte.
pub fn abstract_heap_name(byte: u8) -> Option<&'static str> {
    Some(match byte {
        0x70 => "func",
        0x6f => "extern",
        0x6e => "any",
        0x6d => "eq",
        0x6c => "i31",
        0x6b => "struct",
        0x6a => "array",
        0x69 => "exn",
        0x71 => "none",
        0x72 => "noextern",
        0x73 => "nofunc",
        0x74 => "noexn",
        0x68 => "cont",
        0x75 => "nocont",
        _ => return None,
    })
}

fn numeric_name(byte: i32) -> Option<ValType> {
    Some(match byte {
        0x7f => ValType::I32,
        0x7e => ValType::I64,
        0x7d => ValType::F32,
        0x7c => ValType::F64,
        0x7b => ValType::V128,
        _ => return None,
    })
}

/// What a heap type is, under its `shared` wrappers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum HeapBase {
    /// The empty text: what an instruction holds before it has read a heap type.
    #[default]
    Empty,
    /// An abstract heap type, by its byte (`abstract_heap_name`).
    Abstract(u8),
    /// A type index.
    Index(i64),
}

/// A heap type: an abstract one by name, or a type index, inside `shared`
/// wrappers. The TypeScript held it as text (`func`, `(shared any)`) or a number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub struct HeapType {
    /// How many `(shared …)` wrap it.
    pub shared: u32,
    pub base: HeapBase,
}

impl HeapType {
    pub const fn abstract_type(byte: u8) -> Self {
        HeapType { shared: 0, base: HeapBase::Abstract(byte) }
    }

    /// The name of an abstract heap type not inside `shared` (a string not starting with `(`), or None.
    fn bare_name(&self) -> Option<&'static str> {
        match (self.shared, self.base) {
            (0, HeapBase::Abstract(b)) => abstract_heap_name(b),
            (0, HeapBase::Empty) => Some(""),
            _ => None,
        }
    }
}

impl fmt::Display for HeapType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for _ in 0..self.shared {
            f.write_str("(shared ")?;
        }
        match self.base {
            HeapBase::Empty => {}
            HeapBase::Abstract(b) => f.write_str(abstract_heap_name(b).unwrap_or(""))?,
            HeapBase::Index(i) => write!(f, "{i}")?,
        }
        for _ in 0..self.shared {
            f.write_char(')')?;
        }
        Ok(())
    }
}

/// A value type as the decoder keeps it; `Display` gives its text, `kind` the
/// TypeScript's `kind`: i32, i64, f32, f64, v128, i8, i16, or `ref`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ValType {
    I32,
    I64,
    F32,
    F64,
    V128,
    /// Packed, in a struct field or an array element only.
    I8,
    I16,
    Ref {
        nullable: bool,
        heap: HeapType,
    },
}

impl ValType {
    pub fn kind(&self) -> &'static str {
        match self {
            ValType::I32 => "i32",
            ValType::I64 => "i64",
            ValType::F32 => "f32",
            ValType::F64 => "f64",
            ValType::V128 => "v128",
            ValType::I8 => "i8",
            ValType::I16 => "i16",
            ValType::Ref { .. } => "ref",
        }
    }

    /// The text, `i32`, `(ref null 3)` (the TypeScript's `text`).
    pub fn text(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for ValType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValType::Ref { nullable, heap } => write_ref(f, *nullable, heap),
            _ => f.write_str(self.kind()),
        }
    }
}

/// Reads a heap type.
pub fn heap_type(r: &mut Reader) -> Result<HeapType> {
    let mut shared = 0;
    while r.peek() == 0x65 {
        r.u8()?;
        shared += 1;
    }
    let byte = r.peek();
    if byte >= 0 && abstract_heap_name(byte as u8).is_some() {
        r.u8()?;
        return Ok(HeapType { shared, base: HeapBase::Abstract(byte as u8) });
    }
    let index = r.s32()?;
    if index < 0 {
        return Err(WasmError::UnknownHeapType { index });
    }
    Ok(HeapType { shared, base: HeapBase::Index(index) })
}

/// Writes a reference type.
pub fn write_ref<W: Write + ?Sized>(out: &mut W, nullable: bool, heap: &HeapType) -> fmt::Result {
    if nullable {
        if let Some(name) = heap.bare_name() {
            // The bottom types read as null…ref: (ref null nofunc) is nullfuncref.
            if name == "none" {
                return out.write_str("nullref");
            }
            if let Some(rest) = name.strip_prefix("no") {
                return write!(out, "null{rest}ref");
            }
            return write!(out, "{name}ref");
        }
    }
    if nullable {
        write!(out, "(ref null {heap})")
    } else {
        write!(out, "(ref {heap})")
    }
}

/// The text of a reference type.
pub fn ref_text(nullable: bool, heap: &HeapType) -> String {
    let mut s = String::new();
    let _ = write_ref(&mut s, nullable, heap);
    s
}

/// Reads a value type.
pub fn val_type(r: &mut Reader) -> Result<ValType> {
    match r.byte()? {
        Some(first) => val_type_from(r, first),
        None => Err(WasmError::UnknownValType { byte: None, at: r.pos - 1 }),
    }
}

/// Reads a value type whose first byte the caller has already read.
pub fn val_type_from(r: &mut Reader, first: u8) -> Result<ValType> {
    if let Some(numeric) = numeric_name(first as i32) {
        return Ok(numeric);
    }
    if first == 0x63 || first == 0x64 {
        return Ok(ValType::Ref { nullable: first == 0x63, heap: heap_type(r)? });
    }
    if abstract_heap_name(first).is_some() {
        return Ok(ValType::Ref { nullable: true, heap: HeapType::abstract_type(first) });
    }
    Err(WasmError::UnknownValType { byte: Some(first), at: r.pos - 1 })
}

/// A field of a struct or the element of an array: a value type or a packed i8 / i16.
pub fn storage_type(r: &mut Reader) -> Result<ValType> {
    match r.byte()? {
        Some(0x78) => Ok(ValType::I8),
        Some(0x77) => Ok(ValType::I16),
        Some(first) => val_type_from(r, first),
        // valType(r, undefined) reads its first byte itself.
        None => val_type(r),
    }
}

/// Is this byte the start of a value type (as opposed to an s33 type index in a block type)?
#[inline]
pub fn is_val_type_byte(byte: i32) -> bool {
    numeric_name(byte).is_some() || ((0..256).contains(&byte) && abstract_heap_name(byte as u8).is_some()) || byte == 0x63 || byte == 0x64
}

/* ------------------------------------------------------------------ *
 * Floats, as the text format writes them
 * ------------------------------------------------------------------ */

/// The hexadecimal text of a float's bits, as wasm-tools prints it: `0x1.8p+0`,
/// `-0x1.999999999999ap-4`, `nan`, `nan:0x200000`, `-inf`. Subnormals are
/// normalised (`0x1.p-1074`).
pub fn hex_float(bits: u64, mantissa_bits: u32, exponent_bits: u32) -> String {
    let mut s = String::new();
    let _ = write_hex_float(&mut s, bits, mantissa_bits, exponent_bits);
    s
}

fn write_hex_float<W: Write + ?Sized>(out: &mut W, bits: u64, mantissa_bits: u32, exponent_bits: u32) -> fmt::Result {
    let sign = if (bits >> (mantissa_bits + exponent_bits)) & 1 != 0 { "-" } else { "" };
    let exponent_mask = (1u64 << exponent_bits) - 1;
    let mantissa_mask = (1u64 << mantissa_bits) - 1;
    let exponent = (bits >> mantissa_bits) & exponent_mask;
    let mut mantissa = bits & mantissa_mask;
    if exponent == exponent_mask {
        if mantissa == 0 {
            return write!(out, "{sign}inf");
        }
        if mantissa == 1 << (mantissa_bits - 1) {
            return write!(out, "{sign}nan");
        }
        return write!(out, "{sign}nan:0x{mantissa:x}");
    }
    if exponent == 0 && mantissa == 0 {
        return write!(out, "{sign}0x0p+0");
    }
    let bias = (1i64 << (exponent_bits - 1)) - 1;
    let mut power = exponent as i64 - bias;
    let mut subnormal = false;
    if exponent == 0 {
        // Shift the leading one up to the implicit position.
        subnormal = true;
        power = 1 - bias;
        while mantissa & (1 << mantissa_bits) == 0 {
            mantissa <<= 1;
            power -= 1;
        }
        mantissa &= mantissa_mask;
    }
    // The fraction in whole hex digits, trailing zeros dropped.
    let digits = mantissa_bits.div_ceil(4) as usize;
    let mut fraction = [0u8; 16];
    let shifted = mantissa << (digits as u32 * 4 - mantissa_bits);
    for (i, d) in fraction[..digits].iter_mut().enumerate() {
        *d = b"0123456789abcdef"[((shifted >> ((digits - 1 - i) * 4)) & 15) as usize];
    }
    let mut used = digits;
    while used > 0 && fraction[used - 1] == b'0' {
        used -= 1;
    }
    let fraction = core::str::from_utf8(&fraction[..used]).unwrap();
    let dot = if !fraction.is_empty() || subnormal { "." } else { "" };
    let plus = if power >= 0 { "+" } else { "" };
    write!(out, "{sign}0x1{dot}{fraction}p{plus}{power}")
}

/// A float as Rust's Display writes it, which is what wasm-tools prints:
/// `1.5`, `-0.1`, `1000000000000000000000000000000`, `NaN`, `-inf`. `single`:
/// the value is an f32 (widened to f64 exactly).
///
/// The TypeScript worked the shortest digits out by hand and differed from
/// Rust (and wasm-tools) on a few f32 powers of two, where the interval of
/// values that read back the same is uneven: ±2^-96, ±2^87 and ±2^90 (2^87 is
/// `154742504910672534362390528`, which Rust writes `154742510000000000000000000`
/// and the TypeScript `154742505000000000000000000`). This follows Rust.
pub fn decimal_float(value: f64, single: bool) -> String {
    if single {
        format!("{}", value as f32)
    } else {
        format!("{value}")
    }
}

#[inline]
pub fn f32_from_bits(bits: u32) -> f64 {
    f32::from_bits(bits) as f64
}

#[inline]
pub fn f64_from_bits(bits: u64) -> f64 {
    f64::from_bits(bits)
}

/// Writes the text of an f32.const / f64.const operand: hex, then the value in a comment.
pub fn write_float<W: Write + ?Sized>(out: &mut W, bits: u64, single: bool) -> fmt::Result {
    if single {
        write_hex_float(out, bits & 0xffff_ffff, 23, 8)?;
        write!(out, " (;={};)", f32::from_bits(bits as u32))
    } else {
        write_hex_float(out, bits, 52, 11)?;
        write!(out, " (;={};)", f64::from_bits(bits))
    }
}

/// The text of an f32.const / f64.const operand: hex, then the value in a comment.
pub fn float_text(bits: u64, single: bool) -> String {
    let mut s = String::new();
    let _ = write_float(&mut s, bits, single);
    s
}
