//! A program as the analysis needs it, whatever the container: its bytes and
//! its sections — which are code, which hold C strings, which are written at
//! run time — and the reading of values and strings at a virtual address.
//!
//! The passes of x86 and 32-bit Arm read this one; it is made from the native
//! image the core builds from the container (`native::x86::core_image`).

use crate::disassembly::is_text;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    MachO,
    Elf,
    Pe,
}

#[derive(Clone, Debug, Default)]
pub struct Section {
    /// `__text`, `.text`
    pub name: String,
    pub addr: i64,
    pub size: i64,
    /// Where its bytes are in the file; 0 for zero-fill sections.
    pub offset: i64,
    pub code: bool,
    /// Only NUL-terminated strings: Mach-O's cstring sections, ELF's merged string sections.
    pub cstrings: bool,
    /// No bytes in the file (bss).
    pub zerofill: bool,
    /// Written at run time (data, relocated pointers): text found there is not taken for a literal.
    pub writable: bool,
    /// A Mach-O __stubs section: the size of each stub.
    pub stub_size: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StringKind {
    /// NUL-terminated.
    CString,
    /// A run of printable bytes in constant data.
    Const,
}

#[derive(Clone, Debug, PartialEq)]
pub struct StringRef {
    pub addr: i64,
    pub text: String,
    /// The name of the section it is in.
    pub section: String,
    pub kind: StringKind,
}

pub struct Image {
    pub format: Format,
    pub bytes: Vec<u8>,
    pub sections: Vec<Section>,
}

impl Image {
    /// The first section that holds an address.
    pub fn section_of(&self, addr: i64) -> Option<&Section> {
        self.sections.iter().find(|s| addr >= s.addr && addr < s.addr + s.size)
    }

    /// The file bytes behind a virtual address (none for zero-fill sections), at most `length`, not past the section.
    pub fn bytes_at(&self, addr: i64, length: usize) -> Option<&[u8]> {
        let section = self.section_of(addr)?;
        if section.zerofill || section.offset == 0 {
            return None;
        }
        let at = (section.offset + (addr - section.addr)) as usize;
        let end = (at + length).min((section.offset + section.size) as usize).min(self.bytes.len());
        Some(self.bytes.get(at..end.max(at)).unwrap_or(&[]))
    }

    /// A little-endian value of 1, 2, 4 or 8 bytes at an address in the file, as a JavaScript number
    /// (8-byte values rounded as `Number(bigint)` rounds them).
    pub fn value_at(&self, addr: i64, size: usize, signed: bool) -> Option<f64> {
        let b = self.bytes_at(addr, size)?;
        if b.len() < size {
            return None;
        }
        Some(match (size, signed) {
            (1, false) => b[0] as f64,
            (1, true) => b[0] as i8 as f64,
            (2, false) => u16::from_le_bytes([b[0], b[1]]) as f64,
            (2, true) => i16::from_le_bytes([b[0], b[1]]) as f64,
            (4, false) => u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as f64,
            (4, true) => i32::from_le_bytes([b[0], b[1], b[2], b[3]]) as f64,
            (_, false) => u64::from_le_bytes(b[..8].try_into().unwrap()) as f64,
            (_, true) => i64::from_le_bytes(b[..8].try_into().unwrap()) as f64,
        })
    }

    /// A string that starts at an address in data: a C string, or — when the code
    /// says how long it is (`known`, from Rust's pointer-and-length pairs) — a run
    /// of text without a NUL. Short runs are not taken for strings.
    pub fn text_at(&self, addr: i64, known: Option<usize>) -> Option<StringRef> {
        let section = self.section_of(addr)?;
        if section.offset == 0 || section.code || section.zerofill || section.writable {
            return None;
        }
        let at = (section.offset + (addr - section.addr)) as usize;
        let end = (at + 96).min((section.offset + section.size) as usize).min(self.bytes.len());
        let bytes = self.bytes.get(at..end.max(at)).unwrap_or(&[]);
        let limit = known.map_or(bytes.len(), |k| k.min(bytes.len()));
        let mut n = 0;
        while n < limit && is_text(bytes[n]) {
            n += 1;
        }
        let text = strict_utf8(&bytes[..n])?;
        let make = |kind| Some(StringRef { addr, text: text.clone(), section: section.name.clone(), kind });
        if let Some(k) = known {
            if n == k && k > 0 {
                return make(StringKind::Const);
            }
        }
        let terminated = bytes.get(n) == Some(&0);
        if n < if terminated { 2 } else { 6 } {
            return None;
        }
        make(if terminated { StringKind::CString } else { StringKind::Const })
    }
}

/// UTF-8 as a `TextDecoder('utf-8', { fatal: true })` reads it: None on any malformed byte, and
/// without a leading byte order mark (the decoder drops it).
pub fn strict_utf8(bytes: &[u8]) -> Option<String> {
    let s = core::str::from_utf8(bytes).ok()?;
    Some(s.strip_prefix('\u{feff}').unwrap_or(s).to_string())
}

/// UTF-8 as a `TextDecoder('utf-8')` reads it: what does not decode becomes U+FFFD; a leading byte order mark is dropped.
pub fn lossy_utf8(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    match s.strip_prefix('\u{feff}') {
        Some(rest) => rest.to_string(),
        None => s.into_owned(),
    }
}
