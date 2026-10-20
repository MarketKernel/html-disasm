//! What every disassembled program has, whatever its architecture: the
//! instructions as small typed arrays (a mnemonic number and a few flag bits
//! each), the code ranges they come from, and the cross references.

/// Bits of the per-instruction flags, one byte per instruction (the page reads them as they are).
pub mod iflag {
    pub const LABEL: u8 = 1; // a branch lands here
    pub const FUSE: u8 = 2; // reads as one HLA64 line together with the next instruction
    pub const FUNCTION: u8 = 4; // a function starts here
    pub const CALL: u8 = 8; // bl / blr, call / call_indirect
    pub const UNKNOWN: u8 = 16; // not a decodable instruction
    pub const BRANCH: u8 = 32;
}

/// A run of code: a section of a Mach-O, ELF or PE file, by its address and its instructions.
#[derive(Clone, Copy, Debug)]
pub struct CodeRange {
    pub addr: i64,
    /// Where its bytes are in the file.
    pub offset: u64,
    /// Index of the first instruction, and how many there are.
    pub first: u32,
    pub count: u32,
}

/// Printable ASCII, tab, newline, and the bytes of UTF-8 sequences.
#[inline]
pub fn is_text(b: u8) -> bool {
    (0x20..0x7f).contains(&b) || b == 9 || b == 10 || b == 13 || b >= 0xc2
}
