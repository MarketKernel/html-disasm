//! The x86 decoder: bytes in, an instruction out, the way LLVM's X86
//! disassembler reads them — so that, printed (print.rs), it is the line
//! llvm-objdump prints in Intel syntax. tools/verify-x86.mjs checks it.
//!
//! The decoding goes in LLVM's steps. The prefixes give a set of attributes
//! (64-bit mode, REX.W, 66, F2/F3, VEX.L, EVEX.b…), and the attributes a
//! context; the opcode map, the context and the opcode select a decision,
//! which may need the ModR/M byte to settle on one instruction; the
//! instruction's operand specifiers say where each operand is encoded and
//! what it is. The tables for all of it are in tables.bin, generated from
//! LLVM's description of the target; this file is the reading of them.
//!
//! The result is a list of operands as LLVM's MCInst has them: a register
//! name, an immediate, or a memory reference as five of them (base, scale,
//! index, displacement, segment). The printer and the analysis work on that.
//!
//! A port of src/core/x86/decode.ts, line for line: the two must decode every
//! byte sequence the same. Numbers are kept the way JavaScript held them (an
//! `i64` holds every value the TypeScript computes), and decoding allocates
//! nothing.

use core::mem::MaybeUninit;
use std::sync::OnceLock;

use super::tables::{special, BLOB, CONTEXT_COUNT, PARTS};

/* ------------------------------------------------------------------ *
 * The tables
 * ------------------------------------------------------------------ */

/// The decoding tables, inflated from tables.bin.
pub struct Tables {
    pub contexts: Vec<u8>,
    pub ctx_block: Vec<u16>,
    pub block_types: Vec<u8>,
    pub block_offsets: Vec<u16>,
    pub modrm: Vec<u16>,
    pub opset: Vec<u16>,
    pub template: Vec<u16>,
    pub info: Vec<u32>,
    pub sem: Vec<u32>,
    pub sets: Vec<u8>,
    /// `id * 65536 + id16` for each instruction with a 16-bit form, sorted.
    pub pairs: Vec<u32>,
    /// The templates, `\0`-separated (ASCII), and where each one starts and ends in it.
    templates_text: String,
    templates: Vec<(u32, u32)>,
}

impl Tables {
    /// The template of index `index` (the TypeScript `templates[index] ?? ''`).
    #[inline]
    pub fn template_text(&self, index: usize) -> &str {
        match self.templates.get(index) {
            Some(&(start, end)) => &self.templates_text[start as usize..end as usize],
            None => "",
        }
    }

    pub fn template_count(&self) -> usize {
        self.templates.len()
    }

    #[inline]
    fn has_pair(&self, key: u32) -> bool {
        self.pairs.binary_search(&key).is_ok()
    }
}

fn unpack(raw: &[u8]) -> Tables {
    let mut parts: [&[u8]; PARTS.len()] = [&[]; PARTS.len()];
    let mut at = 0;
    for part in parts.iter_mut() {
        let length = u32::from_le_bytes(raw[at..at + 4].try_into().unwrap()) as usize;
        *part = &raw[at + 4..at + 4 + length];
        at += 4 + ((length + 3) & !3);
    }
    let part = |name: &str| parts[PARTS.iter().position(|p| *p == name).expect("a part of the x86 tables")];
    let u16s = |b: &[u8]| b.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect::<Vec<u16>>();
    let u32s = |b: &[u8]| b.chunks_exact(4).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect::<Vec<u32>>();
    // String.fromCharCode of each byte: the templates are ASCII, so the bytes are the text.
    let templates_text: String = part("templates").iter().map(|&b| b as char).collect();
    let mut templates = Vec::new();
    let mut start = 0u32;
    for (i, b) in templates_text.bytes().enumerate() {
        if b == 0 {
            templates.push((start, i as u32));
            start = i as u32 + 1;
        }
    }
    templates.push((start, templates_text.len() as u32));
    let mut pairs = u32s(part("pairs"));
    pairs.sort_unstable();
    Tables {
        contexts: part("contexts").to_vec(),
        ctx_block: u16s(part("ctxBlock")),
        block_types: part("blockTypes").to_vec(),
        block_offsets: u16s(part("blockOffsets")),
        modrm: u16s(part("modrm")),
        opset: u16s(part("opset")),
        template: u16s(part("template")),
        info: u32s(part("info")),
        sem: u32s(part("sem")),
        sets: part("sets").to_vec(),
        pairs,
        templates_text,
        templates,
    }
}

static TABLES: OnceLock<Tables> = OnceLock::new();

/// The tables, inflated on first use (loadX86 in the TypeScript).
#[inline]
pub fn x86_tables() -> &'static Tables {
    TABLES.get_or_init(|| unpack(&miniz_oxide::inflate::decompress_to_vec(BLOB).expect("the x86 tables inflate")))
}

/// What instruction `id` does, for the analysis (`SEM` bits; 0 for an id out of range).
#[inline]
pub fn sem(id: u32) -> u32 {
    x86_tables().sem.get(id as usize).copied().unwrap_or(0)
}

/// The printer's facts about instruction `id` (`INFO` bits; 0 for an id out of range).
#[inline]
pub fn info(id: u32) -> u32 {
    x86_tables().info.get(id as usize).copied().unwrap_or(0)
}

/* ------------------------------------------------------------------ *
 * Enums, as X86DisassemblerDecoderCommon.h numbers them
 * ------------------------------------------------------------------ */

mod enc {
    pub const NONE: u8 = 0;
    pub const REG: u8 = 1;
    pub const RM: u8 = 2;
    pub const RM_CD64: u8 = 8;
    pub const SIB: u8 = 9;
    pub const VSIB: u8 = 10;
    pub const VSIB_CD64: u8 = 16;
    pub const VVVV: u8 = 17;
    pub const WRITEMASK: u8 = 18;
    pub const IB: u8 = 19;
    pub const IW: u8 = 20;
    pub const ID: u8 = 21;
    pub const IO: u8 = 22;
    pub const RB: u8 = 23;
    pub const RW: u8 = 24;
    pub const RD: u8 = 25;
    pub const RO: u8 = 26;
    pub const FP: u8 = 27;
    pub const IV: u8 = 28;
    pub const IA: u8 = 29;
    pub const IRC: u8 = 30;
    pub const RV: u8 = 31;
    pub const CC: u8 = 32;
    pub const CF: u8 = 33;
    pub const DUP: u8 = 34;
    pub const SI: u8 = 35;
    pub const DI: u8 = 36;
}

/// Operand types (`TYPE` in decode.ts): what `X86Decoded::types` holds for each operand.
pub mod ty {
    pub const NONE: u8 = 0;
    pub const REL: u8 = 1;
    pub const R8: u8 = 2;
    pub const R16: u8 = 3;
    pub const R32: u8 = 4;
    pub const R64: u8 = 5;
    pub const IMM: u8 = 6;
    pub const UIMM8: u8 = 7;
    pub const M: u8 = 8;
    pub const MSIB: u8 = 9;
    pub const MVSIBX: u8 = 10;
    pub const MVSIBY: u8 = 11;
    pub const MVSIBZ: u8 = 12;
    pub const SRCIDX: u8 = 13;
    pub const DSTIDX: u8 = 14;
    pub const MOFFS: u8 = 15;
    pub const ST: u8 = 16;
    pub const MM64: u8 = 17;
    pub const XMM: u8 = 18;
    pub const YMM: u8 = 19;
    pub const ZMM: u8 = 20;
    pub const VK: u8 = 21;
    pub const VK_PAIR: u8 = 22;
    pub const TMM: u8 = 23;
    pub const TMM_PAIR: u8 = 24;
    pub const SEGMENTREG: u8 = 25;
    pub const DEBUGREG: u8 = 26;
    pub const CONTROLREG: u8 = 27;
    pub const BNDR: u8 = 28;
    pub const RV: u8 = 29;
    pub const RELV: u8 = 30;
    pub const DUP0: u8 = 31;
}

mod attr {
    pub const BIT64: u32 = 1;
    pub const XS: u32 = 2;
    pub const XD: u32 = 4;
    pub const REXW: u32 = 8;
    pub const OPSIZE: u32 = 0x10;
    pub const ADSIZE: u32 = 0x20;
    pub const VEX: u32 = 0x40;
    pub const VEXL: u32 = 0x80;
    pub const EVEX: u32 = 0x100;
    pub const EVEXL2: u32 = 0x200;
    pub const EVEXK: u32 = 0x400;
    pub const EVEXKZ: u32 = 0x800;
    pub const EVEXB: u32 = 0x1000;
    pub const REX2: u32 = 0x2000;
    pub const EVEXNF: u32 = 0x4000;
    pub const EVEXU: u32 = 0x8000;
}

mod map {
    pub const ONEBYTE: usize = 0;
    pub const TWOBYTE: usize = 1;
    pub const THREEBYTE_38: usize = 2;
    pub const THREEBYTE_3A: usize = 3;
    pub const XOP8: usize = 4;
    pub const THREEDNOW: usize = 7;
    pub const MAP4: usize = 8;
    pub const MAP5: usize = 9;
    pub const MAP6: usize = 10;
    pub const MAP7: usize = 11;
}

mod vext {
    pub const NONE: u8 = 0;
    pub const VEX2: u8 = 1;
    pub const VEX3: u8 = 2;
    pub const EVEX: u8 = 3;
    pub const XOP: u8 = 4;
}

const SEG: [&str; 7] = ["", "cs", "ss", "ds", "es", "fs", "gs"];

/// Bits of the generated `info` table (tools/x86-index.mjs); `INFO` in decode.ts.
pub mod info {
    pub const MEMOP_SHIFT: u32 = 0;
    pub const ADSIZE_SHIFT: u32 = 4;
    pub const RAW_SHIFT: u32 = 6;
    pub const LOCK: u32 = 1 << 8;
    pub const NOTRACK: u32 = 1 << 9;
    pub const NF: u32 = 1 << 10;
    pub const EXPLICIT_VEX: u32 = 1 << 11;
    pub const EXPLICIT_EVEX: u32 = 1 << 12;
    pub const NAME64: u32 = 1 << 13;
    pub const VCMP_SHIFT: u32 = 14;
    pub const SRCMEM: u32 = 1 << 17;
    pub const XS: u32 = 1 << 18;
    pub const XD: u32 = 1 << 19;
    pub const TA: u32 = 1 << 20;
    pub const EVEX_K: u32 = 1 << 21;
    pub const EVEX_B: u32 = 1 << 22;
    pub const REX_W: u32 = 1 << 23;
    pub const EVEX_L2: u32 = 1 << 24;
    pub const VEX_L: u32 = 1 << 25;
    pub const SUFFIX_SHIFT: u32 = 26;
    pub const CCMP: u32 = 1 << 30;
}

/// Bits of the generated `sem` table: what an instruction does, for the analysis; `SEM` in decode.ts.
pub mod sem {
    pub const CALL: u32 = 1;
    pub const BRANCH: u32 = 2;
    pub const RET: u32 = 4;
    pub const INDIRECT: u32 = 8;
    pub const COND: u32 = 16;
    pub const BARRIER: u32 = 32;
    pub const TRAP: u32 = 64;
    pub const LOAD: u32 = 128;
    pub const STORE: u32 = 256;
    pub const SETS_FLAGS: u32 = 512;
    pub const READS_FLAGS: u32 = 1024;
    pub const PREFIX: u32 = 2048;
}

/// Prefix flags the printer reads (`X86Decoded::flags`); `PFX` in decode.ts.
pub mod pfx {
    pub const AD_SIZE: u8 = 1;
    pub const LOCK: u8 = 2;
    pub const REPEAT: u8 = 4;
    pub const REPEAT_NE: u8 = 8;
}

/// Concatenates name tables at compile time.
const fn concat<const N: usize>(parts: &[&[&'static str]]) -> [&'static str; N] {
    let mut out = [""; N];
    let mut at = 0;
    let mut p = 0;
    while p < parts.len() {
        let part = parts[p];
        let mut i = 0;
        while i < part.len() {
            out[at] = part[i];
            at += 1;
            i += 1;
        }
        p += 1;
    }
    assert!(at == N);
    out
}

/// The names of `[from..]` of a table, at compile time.
const fn tail<const N: usize>(names: &[&'static str], from: usize) -> [&'static str; N] {
    let mut out = [""; N];
    let mut i = 0;
    while i < N {
        out[i] = names[from + i];
        i += 1;
    }
    out
}

/*
 * LLVM's `Reg` enum (ALL_REGS) as names: the decoder adds field values to
 * the start of a class, so the order matters.
 */
#[rustfmt::skip]
static GPR8: [&str; 36] = ["al", "cl", "dl", "bl", "ah", "ch", "dh", "bh", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b", "r16b", "r17b", "r18b", "r19b", "r20b", "r21b", "r22b", "r23b", "r24b", "r25b", "r26b", "r27b", "r28b", "r29b", "r30b", "r31b", "spl", "bpl", "sil", "dil"];
#[rustfmt::skip]
static GPR16: [&str; 32] = ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w", "r16w", "r17w", "r18w", "r19w", "r20w", "r21w", "r22w", "r23w", "r24w", "r25w", "r26w", "r27w", "r28w", "r29w", "r30w", "r31w"];
#[rustfmt::skip]
static GPR32: [&str; 32] = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d", "r16d", "r17d", "r18d", "r19d", "r20d", "r21d", "r22d", "r23d", "r24d", "r25d", "r26d", "r27d", "r28d", "r29d", "r30d", "r31d"];
#[rustfmt::skip]
static GPR64: [&str; 32] = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23", "r24", "r25", "r26", "r27", "r28", "r29", "r30", "r31"];
static MM: [&str; 8] = ["mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7"];
#[rustfmt::skip]
pub(crate) static XMM: [&str; 32] = ["xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15", "xmm16", "xmm17", "xmm18", "xmm19", "xmm20", "xmm21", "xmm22", "xmm23", "xmm24", "xmm25", "xmm26", "xmm27", "xmm28", "xmm29", "xmm30", "xmm31"];
#[rustfmt::skip]
pub(crate) static YMM: [&str; 32] = ["ymm0", "ymm1", "ymm2", "ymm3", "ymm4", "ymm5", "ymm6", "ymm7", "ymm8", "ymm9", "ymm10", "ymm11", "ymm12", "ymm13", "ymm14", "ymm15", "ymm16", "ymm17", "ymm18", "ymm19", "ymm20", "ymm21", "ymm22", "ymm23", "ymm24", "ymm25", "ymm26", "ymm27", "ymm28", "ymm29", "ymm30", "ymm31"];
#[rustfmt::skip]
pub(crate) static ZMM: [&str; 32] = ["zmm0", "zmm1", "zmm2", "zmm3", "zmm4", "zmm5", "zmm6", "zmm7", "zmm8", "zmm9", "zmm10", "zmm11", "zmm12", "zmm13", "zmm14", "zmm15", "zmm16", "zmm17", "zmm18", "zmm19", "zmm20", "zmm21", "zmm22", "zmm23", "zmm24", "zmm25", "zmm26", "zmm27", "zmm28", "zmm29", "zmm30", "zmm31"];
static K: [&str; 8] = ["k0", "k1", "k2", "k3", "k4", "k5", "k6", "k7"];
#[rustfmt::skip]
static OTHERS: [&str; 55] = [
    // The pairs have no assembler names, so LLVM prints their record names (only an out-of-range field reaches them).
    "K0_K1", "K2_K3", "K4_K5", "K6_K7", "es", "cs", "ss", "ds", "fs", "gs",
    "dr0", "dr1", "dr2", "dr3", "dr4", "dr5", "dr6", "dr7", "dr8", "dr9", "dr10", "dr11", "dr12", "dr13", "dr14", "dr15",
    "cr0", "cr1", "cr2", "cr3", "cr4", "cr5", "cr6", "cr7", "cr8", "cr9", "cr10", "cr11", "cr12", "cr13", "cr14", "cr15",
    "tmm0", "tmm1", "tmm2", "tmm3", "tmm4", "tmm5", "tmm6", "tmm7", "TMM0_TMM1", "TMM2_TMM3", "TMM4_TMM5", "TMM6_TMM7", "rip",
];
/// LLVM's register enum as names (ALL_REGS in decode.ts).
pub static ALL_REGS: [&str; 299] = concat(&[&GPR8, &GPR16, &GPR32, &GPR64, &MM, &XMM, &YMM, &ZMM, &K, &OTHERS]);

const fn reg_index(name: &str) -> i32 {
    let mut i = 0;
    while i < ALL_REGS.len() {
        let a = ALL_REGS[i].as_bytes();
        let b = name.as_bytes();
        if a.len() == b.len() {
            let mut k = 0;
            while k < a.len() && a[k] == b[k] {
                k += 1;
            }
            if k == a.len() {
                return i as i32;
            }
        }
        i += 1;
    }
    panic!("no such register")
}

mod reg {
    use super::reg_index as r;
    pub const AL: i32 = r("al");
    pub const SPL: i32 = r("spl");
    pub const AX: i32 = r("ax");
    pub const EAX: i32 = r("eax");
    pub const RAX: i32 = r("rax");
    pub const MM0: i32 = r("mm0");
    pub const XMM0: i32 = r("xmm0");
    pub const YMM0: i32 = r("ymm0");
    pub const ZMM0: i32 = r("zmm0");
    pub const K0: i32 = r("k0");
    pub const K0_K1: i32 = r("K0_K1");
    pub const ES: i32 = r("es");
    pub const DR0: i32 = r("dr0");
    pub const CR0: i32 = r("cr0");
    pub const TMM0: i32 = r("tmm0");
    pub const TMM0_TMM1: i32 = r("TMM0_TMM1");
}

// EABase: none, the 16-, 32- and 64-bit bases (with `sib` in place of esp/rsp), then the registers.
static EA_BASES_16: [&str; 32] = concat(&[&["bx_si", "bx_di", "bp_si", "bp_di", "si", "di", "bp", "bx"], &tail::<24>(&GPR16, 8)]);
static EA_BASES_32: [&str; 32] = concat(&[&["eax", "ecx", "edx", "ebx", "sib", "ebp", "esi", "edi"], &tail::<24>(&GPR32, 8)]);
static EA_BASES_64: [&str; 32] = concat(&[&["rax", "rcx", "rdx", "rbx", "sib64", "rbp", "rsi", "rdi"], &tail::<24>(&GPR64, 8)]);

mod ea {
    pub const NONE: i32 = 0;
    pub const BX_SI: i32 = 1;
    pub const EAX: i32 = 33;
    pub const SIB: i32 = 37;
    pub const RAX: i32 = 65;
    pub const SIB64: i32 = 69;
    pub const REG: i32 = 97;
}

#[inline]
fn ea_name(base: i32) -> &'static str {
    if base <= 32 {
        EA_BASES_16[(base - 1) as usize]
    } else if base <= 64 {
        EA_BASES_32[(base - 33) as usize]
    } else {
        EA_BASES_64[(base - 65) as usize]
    }
}

// SIBIndex: none, the EA bases, then xmm, ymm, zmm. SIBBase: none, then the 32- and 64-bit registers.
mod sib_index {
    pub const NONE: i32 = 0;
    pub const EAX: i32 = 33;
    pub const RAX: i32 = 65;
    pub const XMM0: i32 = 97;
    pub const YMM0: i32 = 129;
    pub const ZMM0: i32 = 161;
}
mod sib_base {
    pub const NONE: i32 = 0;
    pub const EAX: i32 = 1;
    pub const RAX: i32 = 33;
}

#[inline]
fn sib_index_name(index: i32) -> Option<&'static str> {
    if (sib_index::EAX..sib_index::XMM0).contains(&index) {
        return Some(ea_name(index));
    }
    if (sib_index::XMM0..sib_index::YMM0).contains(&index) {
        return Some(XMM[(index - sib_index::XMM0) as usize]);
    }
    if (sib_index::YMM0..sib_index::ZMM0).contains(&index) {
        return Some(YMM[(index - sib_index::YMM0) as usize]);
    }
    if (sib_index::ZMM0..sib_index::ZMM0 + 32).contains(&index) {
        return Some(ZMM[(index - sib_index::ZMM0) as usize]);
    }
    None
}

#[inline]
fn sib_base_name(base: i32) -> &'static str {
    if base <= 32 {
        GPR32[(base - 1) as usize]
    } else {
        GPR64[(base - 33) as usize]
    }
}

static ST: [&str; 8] = ["st", "st(1)", "st(2)", "st(3)", "st(4)", "st(5)", "st(6)", "st(7)"];

/* ------------------------------------------------------------------ *
 * The decoded instruction
 * ------------------------------------------------------------------ */

/// An MCInst operand as decode.ts has it: a register name (`""` for none), a
/// JavaScript number, or a bigint (only an immediate that took 8 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum McOp {
    Reg(&'static str),
    /// A JavaScript number (always an integer here).
    Imm(i64),
    /// A bigint: the 64 bits as read. The TypeScript value is them unsigned (`BigInt.asUintN(64, v)`).
    Big(i64),
}

impl McOp {
    /// JavaScript's `Number(op)`: a register name is NaN (`''` is 0), a bigint its unsigned value.
    #[inline]
    pub fn number(&self) -> f64 {
        match *self {
            McOp::Reg(s) => {
                if s.is_empty() {
                    0.0
                } else {
                    f64::NAN
                }
            }
            McOp::Imm(v) => v as f64,
            McOp::Big(v) => v as u64 as f64,
        }
    }

    /// The register name, if the operand is one.
    #[inline]
    pub fn reg(&self) -> Option<&'static str> {
        match *self {
            McOp::Reg(s) => Some(s),
            _ => None,
        }
    }
}

/// JavaScript's ToInt32, for what `| 0`, `>>` and `&` do to a number.
#[inline]
pub fn to_int32(v: f64) -> i32 {
    if !v.is_finite() {
        return 0;
    }
    let t = v.trunc();
    if t.abs() < 9.007_199_254_740_992e15 {
        return t as i64 as i32;
    }
    let m = t.rem_euclid(4_294_967_296.0);
    m as u32 as i32
}

/// Room for the operands of any instruction: the tables give at most 10, so this leaves a margin.
pub const MAX_OPS: usize = 12;

/// A short list kept inline: the operands of an instruction, or their types.
#[derive(Clone, Copy)]
pub struct List<T: Copy, const N: usize> {
    len: u8,
    items: [MaybeUninit<T>; N],
}

impl<T: Copy, const N: usize> List<T, N> {
    #[inline(always)]
    pub const fn new() -> Self {
        List { len: 0, items: [MaybeUninit::uninit(); N] }
    }

    #[inline(always)]
    pub fn push(&mut self, item: T) {
        debug_assert!((self.len as usize) < N, "too many operands");
        if (self.len as usize) < N {
            self.items[self.len as usize] = MaybeUninit::new(item);
            self.len += 1;
        }
    }

    #[inline(always)]
    pub fn as_slice(&self) -> &[T] {
        // SAFETY: the first `len` items were written by push.
        unsafe { core::slice::from_raw_parts(self.items.as_ptr() as *const T, self.len as usize) }
    }
}

impl<T: Copy, const N: usize> Default for List<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Copy, const N: usize> core::ops::Deref for List<T, N> {
    type Target = [T];
    #[inline(always)]
    fn deref(&self) -> &[T] {
        self.as_slice()
    }
}

impl<T: Copy + core::fmt::Debug, const N: usize> core::fmt::Debug for List<T, N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_list().entries(self.as_slice()).finish()
    }
}

pub type Ops = List<McOp, MAX_OPS>;
pub type Types = List<u8, MAX_OPS>;

#[derive(Clone, Copy, Debug)]
pub struct X86Decoded {
    /// The instruction, in the tables' dense numbering; 0 when the bytes do not decode.
    pub id: u32,
    /// Bytes taken — on failure, the bytes read before it failed (at least 1), as llvm-objdump skips them.
    pub length: u32,
    pub addr: i64,
    /// 64 or 32.
    pub mode: u8,
    pub ops: Ops,
    /// Which operand specifier each MCInst operand came from (its type, `ty`), for the analysis.
    pub types: Types,
    /// Prefix flags the printer reads (`pfx`): lock, rep, repne, addr32.
    pub flags: u8,
    /// rep/repne before a locked instruction or xchg: printed as xrelease/xacquire.
    pub xacquire: bool,
}

struct Insn<'a> {
    bytes: &'a [u8],
    start: usize,
    end: usize,
    cursor: usize,
    mode: u8,
    mandatory_prefix: i32,
    vex: [i32; 4],
    vex_type: u8,
    rex2: [i32; 2],
    rex: i32,
    segment: usize,
    x_acquire_release: bool,
    has_ad_size: bool,
    has_op_size: bool,
    has_lock: bool,
    repeat: i32,
    register_size: i32,
    address_size: i32,
    displacement_size: i32,
    immediate_size: i32,
    opcode: i32,
    map: usize,
    id: u32,
    vvvv: i32,
    writemask: i32,
    consumed_modrm: bool,
    modrm: i32,
    displacement: i64,
    ea_displacement: u8, // 0 none, 1 disp8, 2 disp16, 3 disp32
    immediates: [McOp; 6],
    imm_count: usize,
    imm_translated: usize,
    opcode_register: i32,
    ea_reg_base: i32,
    reg_base: i32,
    ea_base: i32,
    reg: i32,
    sib_index_base: i32,
    sib_index: i32,
    sib_scale: i32,
    sib_base: i32,
    rc: i32,
}

impl<'a> Insn<'a> {
    #[inline(always)]
    fn new(bytes: &'a [u8], start: usize, end: usize, mode: u8) -> Insn<'a> {
        Insn {
            bytes,
            start,
            end,
            cursor: start,
            mode,
            mandatory_prefix: 0,
            vex: [0; 4],
            vex_type: vext::NONE,
            rex2: [0; 2],
            rex: 0,
            segment: 0,
            x_acquire_release: false,
            has_ad_size: false,
            has_op_size: false,
            has_lock: false,
            repeat: 0,
            register_size: 0,
            address_size: 0,
            displacement_size: 0,
            immediate_size: 0,
            opcode: 0,
            map: 0,
            id: 0,
            vvvv: 0,
            writemask: 0,
            consumed_modrm: false,
            modrm: 0,
            displacement: 0,
            ea_displacement: 0,
            immediates: [McOp::Imm(0); 6],
            imm_count: 0,
            imm_translated: 0,
            opcode_register: 0,
            ea_reg_base: 0,
            reg_base: 0,
            ea_base: 0,
            reg: 0,
            sib_index_base: 0,
            sib_index: 0,
            sib_scale: 0,
            sib_base: 0,
            rc: 0,
        }
    }

    /// The next byte without taking it, or -1 at the end.
    #[inline(always)]
    fn peek(&self) -> i32 {
        if self.cursor < self.end {
            self.bytes[self.cursor] as i32
        } else {
            -1
        }
    }

    /// Takes the next byte, or returns -1 (and takes nothing) at the end.
    #[inline(always)]
    fn byte(&mut self) -> i32 {
        if self.cursor < self.end {
            self.cursor += 1;
            self.bytes[self.cursor - 1] as i32
        } else {
            -1
        }
    }

    /// Takes a little-endian value of 1, 2 or 4 bytes (unsigned), or -1.
    #[inline(always)]
    fn take(&mut self, size: usize) -> i64 {
        if self.cursor + size > self.end {
            return -1;
        }
        let b = self.bytes;
        let at = self.cursor;
        self.cursor += size;
        match size {
            1 => b[at] as i64,
            2 => (b[at] as i64) | ((b[at + 1] as i64) << 8),
            _ => u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]) as i64,
        }
    }

    #[inline(always)]
    fn is_rex(&self, b: i32) -> bool {
        self.mode == 64 && (0x40..=0x4f).contains(&b)
    }

    #[inline(always)]
    fn is_rex2(&self, b: i32) -> bool {
        self.mode == 64 && b == 0xd5
    }

    // REX, REX2 and the vector prefixes' fields.
    #[inline(always)]
    fn rex_w(&self) -> i32 {
        (self.rex >> 3) & 1
    }
    #[inline(always)]
    fn rex_r(&self) -> i32 {
        (self.rex >> 2) & 1
    }
    #[inline(always)]
    fn rex_x(&self) -> i32 {
        (self.rex >> 1) & 1
    }
    #[inline(always)]
    fn rex_b(&self) -> i32 {
        self.rex & 1
    }
    #[inline(always)]
    fn rex2_m(&self) -> i32 {
        (self.rex2[1] >> 7) & 1
    }
    #[inline(always)]
    fn rex2_r2(&self) -> i32 {
        (self.rex2[1] >> 6) & 1
    }
    #[inline(always)]
    fn rex2_x2(&self) -> i32 {
        (self.rex2[1] >> 5) & 1
    }
    #[inline(always)]
    fn rex2_b2(&self) -> i32 {
        (self.rex2[1] >> 4) & 1
    }
}

#[inline(always)]
fn inv(v: i32, bit: u32) -> i32 {
    (!v >> bit) & 1
}

fn read_prefixes(insn: &mut Insn) -> i32 {
    let mut is_prefix = true;
    let mut byte = 0;
    while is_prefix {
        let b = insn.byte();
        if b < 0 {
            break;
        }
        byte = b;
        // A LOCK first is an instruction of its own.
        if insn.cursor - 1 == insn.start && byte == 0xf0 {
            break;
        }
        let next = insn.peek();
        if (byte == 0xf2 || byte == 0xf3) && next >= 0 {
            // Before a LOCK or an xchg they are xacquire/xrelease, not repne/rep.
            if next == 0xf0 || (next & 0xfe) == 0x86 || (next & 0xf8) == 0x90 {
                insn.x_acquire_release = true;
                if !(byte == 0xf3 && next == 0x90) {
                    break;
                }
            }
            if byte == 0xf3 && (next == 0x88 || next == 0x89 || next == 0xc6 || next == 0xc7) {
                insn.x_acquire_release = true;
                break;
            }
            if insn.is_rex(next) {
                insn.cursor += 1;
                if insn.peek() < 0 {
                    return -1;
                }
                insn.cursor -= 1;
            }
        }
        match byte {
            0xf0 => insn.has_lock = true,
            0xf2 | 0xf3 => {
                let nb = insn.peek();
                if nb >= 0 {
                    if insn.is_rex(nb) || insn.is_rex2(nb) || nb == 0x0f || nb == 0x66 {
                        insn.mandatory_prefix = byte;
                    }
                    insn.repeat = byte;
                }
            }
            0x2e => insn.segment = 1,
            0x36 => insn.segment = 2,
            0x3e => insn.segment = 3,
            0x26 => insn.segment = 4,
            0x64 => insn.segment = 5,
            0x65 => insn.segment = 6,
            0x66 => {
                insn.has_op_size = true;
                let nb = insn.peek();
                if nb >= 0 && insn.mandatory_prefix == 0 && (nb == 0x0f || insn.is_rex(nb)) {
                    insn.mandatory_prefix = byte;
                }
            }
            0x67 => insn.has_ad_size = true,
            _ => is_prefix = false,
        }
        if insn.is_rex(byte) {
            insn.rex = byte;
            is_prefix = true;
        } else if is_prefix {
            insn.rex = 0;
        }
    }

    insn.vex_type = vext::NONE;
    if byte == 0x62 {
        let b1 = insn.byte();
        if b1 < 0 {
            return -1;
        }
        if insn.peek() < 0 {
            return -1;
        }
        if insn.mode == 64 || (b1 & 0xc0) == 0xc0 {
            insn.vex_type = vext::EVEX;
        } else {
            insn.cursor -= 2;
        }
        if insn.vex_type == vext::EVEX {
            insn.vex[0] = byte;
            insn.vex[1] = b1;
            let b2 = insn.byte();
            if b2 < 0 {
                return -1;
            }
            insn.vex[2] = b2;
            let b3 = insn.byte();
            if b3 < 0 {
                return -1;
            }
            insn.vex[3] = b3;
            if insn.mode == 64 {
                let v = insn.vex;
                insn.rex = 0x40 | (((v[2] >> 7) & 1) << 3) | (inv(v[1], 7) << 2) | (inv(v[1], 6) << 1) | inv(v[1], 5);
                insn.rex2[1] = (inv(v[1], 4) << 6) | (inv(v[2], 2) << 5) | (((v[1] >> 3) & 1) << 4);
            }
        }
    } else if byte == 0xc4 {
        let b1 = insn.peek();
        if b1 < 0 {
            return -1;
        }
        if insn.mode == 64 || (b1 & 0xc0) == 0xc0 {
            insn.vex_type = vext::VEX3;
        } else {
            insn.cursor -= 1;
        }
        if insn.vex_type == vext::VEX3 {
            insn.vex[0] = byte;
            insn.vex[1] = insn.byte().max(0);
            insn.vex[2] = insn.byte().max(0);
            let v = insn.vex;
            if insn.mode == 64 {
                insn.rex = 0x40 | (((v[2] >> 7) & 1) << 3) | (inv(v[1], 7) << 2) | (inv(v[1], 6) << 1) | inv(v[1], 5);
            }
        }
    } else if byte == 0xc5 {
        let b1 = insn.peek();
        if b1 < 0 {
            return -1;
        }
        if insn.mode == 64 || (b1 & 0xc0) == 0xc0 {
            insn.vex_type = vext::VEX2;
        } else {
            insn.cursor -= 1;
        }
        if insn.vex_type == vext::VEX2 {
            insn.vex[0] = byte;
            insn.vex[1] = insn.byte().max(0);
            let v = insn.vex;
            if insn.mode == 64 {
                insn.rex = 0x40 | (inv(v[1], 7) << 2);
            }
            if (v[1] & 3) == 1 {
                insn.has_op_size = true;
            }
        }
    } else if byte == 0x8f {
        let b1 = insn.peek();
        if b1 < 0 {
            return -1;
        }
        if (b1 & 0x38) != 0 {
            insn.vex_type = vext::XOP;
        } else {
            insn.cursor -= 1;
        }
        if insn.vex_type == vext::XOP {
            insn.vex[0] = byte;
            insn.vex[1] = insn.byte().max(0);
            insn.vex[2] = insn.byte().max(0);
            let v = insn.vex;
            if insn.mode == 64 {
                insn.rex = 0x40 | (((v[2] >> 7) & 1) << 3) | (inv(v[1], 7) << 2) | (inv(v[1], 6) << 1) | inv(v[1], 5);
            }
            if (v[2] & 3) == 1 {
                insn.has_op_size = true;
            }
        }
    } else if insn.is_rex2(byte) {
        if insn.peek() < 0 {
            return -1;
        }
        insn.rex2[0] = byte;
        insn.rex2[1] = insn.byte().max(0);
        let r2 = insn.rex2[1];
        insn.rex = 0x40 | (((r2 >> 3) & 1) << 3) | (((r2 >> 2) & 1) << 2) | (((r2 >> 1) & 1) << 1) | (r2 & 1);
    } else {
        insn.cursor -= 1;
    }

    if insn.mode == 32 {
        insn.register_size = if insn.has_op_size { 2 } else { 4 };
        insn.address_size = if insn.has_ad_size { 2 } else { 4 };
        insn.displacement_size = if insn.has_ad_size { 2 } else { 4 };
        insn.immediate_size = if insn.has_op_size { 2 } else { 4 };
    } else {
        insn.displacement_size = 4;
        if insn.rex != 0 && insn.rex_w() != 0 {
            insn.register_size = 8;
            insn.address_size = if insn.has_ad_size { 4 } else { 8 };
            insn.immediate_size = 4;
            insn.has_op_size = false;
        } else {
            insn.register_size = if insn.has_op_size { 2 } else { 4 };
            insn.address_size = if insn.has_ad_size { 4 } else { 8 };
            insn.immediate_size = if insn.has_op_size { 2 } else { 4 };
        }
    }
    0
}

fn read_sib(insn: &mut Insn) -> i32 {
    let sib_base_base;
    if insn.address_size == 4 {
        insn.sib_index_base = sib_index::EAX;
        sib_base_base = sib_base::EAX;
    } else {
        insn.sib_index_base = sib_index::RAX;
        sib_base_base = sib_base::RAX;
    }
    let sib = insn.byte();
    if sib < 0 {
        return -1;
    }
    let index = ((sib >> 3) & 7) | (insn.rex_x() << 3) | (insn.rex2_x2() << 4);
    insn.sib_index = if index == 4 { sib_index::NONE } else { insn.sib_index_base + index };
    insn.sib_scale = 1 << (sib >> 6);
    let base = (sib & 7) | (insn.rex_b() << 3) | (insn.rex2_b2() << 4);
    if base == 5 || base == 0xd {
        match insn.modrm >> 6 {
            0 => {
                insn.ea_displacement = 3;
                insn.sib_base = sib_base::NONE;
            }
            1 => {
                insn.ea_displacement = 1;
                insn.sib_base = sib_base_base + base;
            }
            _ => {
                insn.ea_displacement = 3;
                insn.sib_base = sib_base_base + base;
            }
        }
    } else {
        insn.sib_base = sib_base_base + base;
    }
    0
}

fn read_displacement(insn: &mut Insn) -> i32 {
    match insn.ea_displacement {
        1 => {
            let d = insn.take(1);
            if d < 0 {
                return -1;
            }
            insn.displacement = d as u8 as i8 as i64;
        }
        2 => {
            let d = insn.take(2);
            if d < 0 {
                return -1;
            }
            insn.displacement = d as u16 as i16 as i64;
        }
        3 => {
            let d = insn.take(4);
            if d < 0 {
                return -1;
            }
            insn.displacement = d as u32 as i32 as i64;
        }
        _ => {}
    }
    0
}

fn read_modrm(insn: &mut Insn) -> i32 {
    if insn.consumed_modrm {
        return 0;
    }
    let m = insn.byte();
    if m < 0 {
        return -1;
    }
    insn.modrm = m;
    insn.consumed_modrm = true;
    let mode = m >> 6;
    let mut rm = m & 7;
    let mut reg = (m >> 3) & 7;
    match insn.register_size {
        2 => {
            insn.reg_base = reg::AX;
            insn.ea_reg_base = ea::REG + reg::AX;
        }
        4 => {
            insn.reg_base = reg::EAX;
            insn.ea_reg_base = ea::REG + reg::EAX;
        }
        8 => {
            insn.reg_base = reg::RAX;
            insn.ea_reg_base = ea::REG + reg::RAX;
        }
        _ => {}
    }
    reg |= (insn.rex_r() << 3) | (insn.rex2_r2() << 4);
    rm |= (insn.rex_b() << 3) | (insn.rex2_b2() << 4);
    if insn.vex_type == vext::EVEX && insn.mode == 64 {
        reg |= inv(insn.vex[1], 4) << 4;
    }
    insn.reg = insn.reg_base + reg;

    if insn.address_size == 2 {
        match mode {
            0 => {
                if rm == 6 {
                    insn.ea_base = ea::NONE;
                    insn.ea_displacement = 2;
                    if read_displacement(insn) != 0 {
                        return -1;
                    }
                } else {
                    insn.ea_base = ea::BX_SI + rm;
                    insn.ea_displacement = 0;
                }
            }
            1 => {
                insn.ea_base = ea::BX_SI + rm;
                insn.ea_displacement = 1;
                insn.displacement_size = 1;
                if read_displacement(insn) != 0 {
                    return -1;
                }
            }
            2 => {
                insn.ea_base = ea::BX_SI + rm;
                insn.ea_displacement = 2;
                if read_displacement(insn) != 0 {
                    return -1;
                }
            }
            _ => {
                insn.ea_base = insn.ea_reg_base + rm;
                if read_displacement(insn) != 0 {
                    return -1;
                }
            }
        }
        return 0;
    }
    let ea_base_base = if insn.address_size == 4 { ea::EAX } else { ea::RAX };
    match mode {
        0 => {
            insn.ea_displacement = 0;
            match rm & 7 {
                4 => {
                    insn.ea_base = if insn.address_size == 4 { ea::SIB } else { ea::SIB64 };
                    if read_sib(insn) != 0 || read_displacement(insn) != 0 {
                        return -1;
                    }
                }
                5 => {
                    insn.ea_base = ea::NONE;
                    insn.ea_displacement = 3;
                    if read_displacement(insn) != 0 {
                        return -1;
                    }
                }
                _ => insn.ea_base = ea_base_base + rm,
            }
        }
        1 | 2 => {
            if mode == 1 {
                insn.displacement_size = 1;
            }
            insn.ea_displacement = if mode == 1 { 1 } else { 3 };
            if (rm & 7) == 4 {
                insn.ea_base = ea::SIB;
                if read_sib(insn) != 0 || read_displacement(insn) != 0 {
                    return -1;
                }
            } else {
                insn.ea_base = ea_base_base + rm;
                if read_displacement(insn) != 0 {
                    return -1;
                }
            }
        }
        _ => {
            insn.ea_displacement = 0;
            insn.ea_base = insn.ea_reg_base + rm;
        }
    }
    0
}

/// fixupRegValue / fixupRMValue: a field's value as a register of the operand's type, or -1 when invalid.
fn fixup_value(insn: &Insn, kind: u8, mut index: i32, base: i32) -> i32 {
    match kind {
        ty::RV => base + index,
        ty::R8 => {
            if insn.rex != 0 && (4..=7).contains(&index) {
                reg::SPL + (index - 4)
            } else {
                reg::AL + index
            }
        }
        ty::R16 => reg::AX + index,
        ty::R32 => reg::EAX + index,
        ty::R64 => reg::RAX + index,
        ty::ZMM | ty::MVSIBZ => reg::ZMM0 + index,
        ty::YMM | ty::MVSIBY => reg::YMM0 + index,
        ty::XMM | ty::MVSIBX => reg::XMM0 + index,
        ty::TMM => {
            if index > 7 {
                -1
            } else {
                reg::TMM0 + index
            }
        }
        ty::TMM_PAIR => {
            if index > 7 {
                -1
            } else {
                reg::TMM0_TMM1 + (index >> 1)
            }
        }
        ty::VK => {
            index &= 0xf;
            if index > 7 {
                -1
            } else {
                reg::K0 + index
            }
        }
        ty::VK_PAIR => {
            if index > 7 {
                -1
            } else {
                reg::K0_K1 + (index >> 1)
            }
        }
        ty::MM64 => reg::MM0 + (index & 7),
        ty::SEGMENTREG => {
            if (index & 7) > 5 {
                -1
            } else {
                reg::ES + (index & 7)
            }
        }
        ty::DEBUGREG => {
            if index > 15 {
                -1
            } else {
                reg::DR0 + index
            }
        }
        ty::CONTROLREG => {
            if index > 15 {
                -1
            } else {
                reg::CR0 + index
            }
        }
        _ => -1,
    }
}

fn fixup_reg(insn: &mut Insn, encoding: u8, kind: u8) -> i32 {
    if encoding == enc::VVVV {
        let v = fixup_value(insn, kind, insn.vvvv, insn.reg_base);
        if v < 0 {
            return -1;
        }
        insn.vvvv = v;
    } else if encoding == enc::REG {
        let v = fixup_value(insn, kind, insn.reg - insn.reg_base, insn.reg_base);
        if v < 0 {
            return -1;
        }
        insn.reg = v;
    } else if (enc::RM..=enc::RM_CD64).contains(&encoding) || encoding == enc::SIB {
        if encoding != enc::SIB && insn.vex_type == vext::EVEX && insn.mode == 64 && insn.modrm >> 6 == 3 {
            // EVEX.X extends a vector register in r/m to 32.
            if kind != ty::RV && kind != ty::R8 && kind != ty::R16 && kind != ty::R32 && kind != ty::R64 {
                insn.ea_base += inv(insn.vex[1], 6) << 4;
            }
        }
        if insn.ea_base >= insn.ea_reg_base {
            let v = fixup_value(insn, kind, insn.ea_base - insn.ea_reg_base, insn.ea_reg_base - ea::REG);
            if v < 0 {
                return -1;
            }
            insn.ea_base = ea::REG + v;
        }
    } else {
        return -1;
    }
    0
}

/// The opcode map of each EVEX map field (mmm) and VEX map select (mmmmm); -1 for none.
const EVEX_MAPS: [i32; 8] = [-1, map::TWOBYTE as i32, map::THREEBYTE_38 as i32, map::THREEBYTE_3A as i32, map::MAP4 as i32, map::MAP5 as i32, map::MAP6 as i32, map::MAP7 as i32];
const VEX_MAPS: [i32; 8] = [-1, map::TWOBYTE as i32, map::THREEBYTE_38 as i32, map::THREEBYTE_3A as i32, -1, map::MAP5 as i32, map::MAP6 as i32, map::MAP7 as i32];

/// Takes the opcode byte; true on running out of bytes.
#[inline(always)]
fn take_opcode(insn: &mut Insn) -> bool {
    let b = insn.byte();
    if b < 0 {
        return true;
    }
    insn.opcode = b;
    false
}

fn read_opcode(insn: &mut Insn) -> bool {
    insn.map = map::ONEBYTE;
    let v = insn.vex;
    if insn.vex_type == vext::EVEX {
        let mmm = (v[1] & 7) as usize;
        let m = EVEX_MAPS[mmm];
        if m < 0 {
            return true;
        }
        insn.map = m as usize;
        return take_opcode(insn);
    } else if insn.vex_type == vext::VEX3 {
        let m = VEX_MAPS.get((v[1] & 0x1f) as usize).copied().unwrap_or(-1);
        if m < 0 {
            return true;
        }
        insn.map = m as usize;
        return take_opcode(insn);
    } else if insn.vex_type == vext::VEX2 {
        insn.map = map::TWOBYTE;
        return take_opcode(insn);
    } else if insn.vex_type == vext::XOP {
        let sel = v[1] & 0x1f;
        if !(8..=10).contains(&sel) {
            return true;
        }
        insn.map = map::XOP8 + (sel - 8) as usize;
        return take_opcode(insn);
    } else if insn.rex2_m() != 0 {
        insn.map = map::TWOBYTE;
        return take_opcode(insn);
    }
    let mut current = insn.byte();
    if current < 0 {
        return true;
    }
    if current == 0x0f {
        current = insn.byte();
        if current < 0 {
            return true;
        }
        if current == 0x38 {
            current = insn.byte();
            if current < 0 {
                return true;
            }
            insn.map = map::THREEBYTE_38;
        } else if current == 0x3a {
            current = insn.byte();
            if current < 0 {
                return true;
            }
            insn.map = map::THREEBYTE_3A;
        } else if current == 0x0f {
            // 3DNow!: the ModR/M byte (and what follows it) comes before the opcode.
            if read_modrm(insn) != 0 {
                return true;
            }
            current = insn.byte();
            if current < 0 {
                return true;
            }
            insn.map = map::THREEDNOW;
        } else {
            insn.map = map::TWOBYTE;
        }
    } else if insn.mandatory_prefix != 0 {
        insn.mandatory_prefix = 0;
    }
    insn.opcode = current;
    false
}

/// The instruction an attribute mask selects for the opcode read (0 if none), reading the ModR/M byte when the decision needs it; -1 on running out of bytes.
fn id_with_attr_mask(t: &Tables, insn: &mut Insn, attr_mask: u32) -> i32 {
    let ctx = t.contexts[attr_mask as usize] as usize;
    let block = t.ctx_block[insn.map * CONTEXT_COUNT + ctx] as usize;
    if block == 0 {
        return 0;
    }
    let at = (block - 1) * 256 + insn.opcode as usize;
    let kind = t.block_types[at];
    let off = t.block_offsets[at] as usize;
    if kind == 0 {
        return t.modrm[off] as i32;
    }
    if read_modrm(insn) != 0 {
        return -1;
    }
    let m = insn.modrm as usize;
    let mod3 = m >> 6 == 3;
    let at = match kind {
        1 => off + mod3 as usize,
        2 => off + if mod3 { (m & 0x3f) + 8 } else { (m & 0x38) >> 3 },
        3 => off + if mod3 { ((m & 0x38) >> 3) + 8 } else { (m & 0x38) >> 3 },
        _ => off + m,
    };
    t.modrm[at] as i32
}

fn is_ccmp_or_ctest(insn: &Insn) -> bool {
    if insn.map != map::MAP4 {
        return false;
    }
    let reg = (insn.modrm >> 3) & 7;
    if insn.opcode == 0x83 && reg == 7 {
        return true;
    }
    match insn.opcode & 0xfe {
        0x38 | 0x3a | 0x84 => true,
        0x80 => reg == 7,
        0xf6 => reg == 0,
        _ => false,
    }
}

fn is_nf(insn: &Insn) -> bool {
    if (insn.vex[3] >> 2) & 1 == 0 {
        return false;
    }
    if insn.map == map::MAP4 {
        return true;
    }
    if insn.map == map::THREEBYTE_38 && (insn.vex[2] & 3) == 0 {
        return matches!(insn.opcode, 0xf2 | 0xf3 | 0xf5 | 0xf7);
    }
    false
}

fn get_instruction_id(t: &Tables, insn: &mut Insn) -> i32 {
    let mut attr_mask = 0u32;
    if insn.mode == 64 {
        attr_mask |= attr::BIT64;
    }
    let v = insn.vex;
    if insn.vex_type != vext::NONE {
        attr_mask |= if insn.vex_type == vext::EVEX { attr::EVEX } else { attr::VEX };
        let pp = if insn.vex_type == vext::VEX2 { v[1] & 3 } else { v[2] & 3 };
        if pp == 1 {
            attr_mask |= attr::OPSIZE;
        } else if pp == 2 {
            attr_mask |= attr::XS;
        } else if pp == 3 {
            attr_mask |= attr::XD;
        }
        if insn.vex_type == vext::EVEX {
            if (v[3] >> 7) & 1 != 0 {
                attr_mask |= attr::EVEXKZ;
            }
            if is_nf(insn) && read_modrm(insn) == 0 && !is_ccmp_or_ctest(insn) {
                attr_mask |= attr::EVEXNF;
            } else if v[3] & 7 != 0 && insn.map != map::MAP4 {
                attr_mask |= attr::EVEXK;
            }
            if (v[3] >> 4) & 1 != 0 {
                attr_mask |= attr::EVEXB;
                if inv(v[2], 2) != 0 && read_modrm(insn) == 0 && insn.modrm >> 6 == 3 {
                    attr_mask |= attr::EVEXU;
                }
            }
            if (v[3] >> 5) & 1 != 0 {
                attr_mask |= attr::VEXL;
            }
            if (v[3] >> 6) & 1 != 0 {
                attr_mask |= attr::EVEXL2;
            }
        } else if insn.vex_type == vext::VEX3 {
            if (v[2] >> 2) & 1 != 0 {
                attr_mask |= attr::VEXL;
            }
        } else if insn.vex_type == vext::VEX2 {
            if pp == 1 && insn.has_ad_size {
                attr_mask |= attr::ADSIZE;
            }
            if (v[1] >> 2) & 1 != 0 {
                attr_mask |= attr::VEXL;
            }
        } else if (v[2] >> 2) & 1 != 0 {
            attr_mask |= attr::VEXL;
        }
    } else if insn.mandatory_prefix == 0 {
        if insn.has_op_size {
            attr_mask |= attr::OPSIZE;
        }
        if insn.has_ad_size {
            attr_mask |= attr::ADSIZE;
        }
        if insn.map == map::ONEBYTE {
            if insn.repeat == 0xf3 && insn.opcode == 0x90 {
                attr_mask |= attr::XS;
            }
        } else if insn.repeat == 0xf2 {
            attr_mask |= attr::XD;
        } else if insn.repeat == 0xf3 {
            attr_mask |= attr::XS;
        }
    } else {
        match insn.mandatory_prefix {
            0xf2 => attr_mask |= attr::XD,
            0xf3 => attr_mask |= attr::XS,
            0x66 => {
                attr_mask |= attr::OPSIZE;
                if insn.has_ad_size {
                    attr_mask |= attr::ADSIZE;
                }
            }
            0x67 => attr_mask |= attr::ADSIZE,
            _ => {}
        }
    }
    if insn.rex & 0x08 != 0 {
        attr_mask |= attr::REXW;
        attr_mask &= !attr::ADSIZE;
    }
    // Absolute jump and pushp/popp.
    if insn.rex2[0] == 0xd5 && insn.map == map::ONEBYTE && (insn.opcode == 0xa1 || (insn.opcode & 0xf0) == 0x50) {
        attr_mask |= attr::REX2;
    }

    let mut id = id_with_attr_mask(t, insn, attr_mask);
    if id < 0 {
        return -1;
    }

    // The tables cannot tell W selecting the register size from W being part of the opcode outside 64-bit mode.
    if insn.mode != 64 && insn.vex_type != vext::NONE {
        let w = if insn.vex_type == vext::VEX2 { 0 } else { (v[2] >> 7) & 1 };
        if w != 0 && insn.vex_type != vext::VEX2 {
            let with_w = id_with_attr_mask(t, insn, attr_mask | attr::REXW);
            if with_w < 0 {
                insn.id = id as u32;
                return 0;
            }
            if t.info[with_w as usize] & info::NAME64 == 0 {
                insn.id = with_w as u32;
                return 0;
            }
        }
    }

    // Absolute moves, umonitor and movdir64b: the prefixes count wherever they are.
    if (insn.map == map::ONEBYTE && (insn.opcode & 0xfc) == 0xa0)
        || (insn.map == map::TWOBYTE && insn.opcode == 0xae)
        || (insn.map == map::THREEBYTE_38 && insn.opcode == 0xf8)
        || (insn.map == map::MAP4 && insn.opcode == 0xf8)
    {
        if insn.has_ad_size {
            attr_mask |= attr::ADSIZE;
        }
        if insn.has_op_size {
            attr_mask |= attr::OPSIZE;
        }
        id = id_with_attr_mask(t, insn, attr_mask);
        if id < 0 {
            return -1;
        }
        insn.id = id as u32;
        return 0;
    }

    if insn.has_op_size && attr_mask & attr::OPSIZE == 0 {
        // OpSize out of its place: take the 16-bit form when there is one.
        let with_op_size = id_with_attr_mask(t, insn, attr_mask | attr::OPSIZE);
        if with_op_size < 0 {
            insn.id = id as u32;
            return 0;
        }
        insn.id = if t.has_pair((id as u32) * 65536 + with_op_size as u32) { with_op_size as u32 } else { id as u32 };
        return 0;
    }

    if insn.map == map::ONEBYTE && insn.opcode == 0x90 && insn.rex & 1 != 0 {
        // With REX.B, 90 is xchg r8, eax, not a nop: borrow the opcode of the other xchg forms.
        insn.opcode = 0x91;
        let xchg = id_with_attr_mask(t, insn, attr_mask);
        insn.opcode = 0x90;
        insn.id = if xchg < 0 { id as u32 } else { xchg as u32 };
        return 0;
    }
    insn.id = id as u32;
    0
}

fn read_opcode_register(insn: &mut Insn, mut size: i32) {
    if size == 0 {
        size = insn.register_size;
    }
    let index = (insn.rex_b() << 3) | (insn.rex2_b2() << 4) | (insn.opcode & 7);
    match size {
        1 => {
            insn.opcode_register = reg::AL + index;
            if insn.rex != 0 && (4..8).contains(&index) {
                insn.opcode_register = reg::SPL + (index - 4);
            }
        }
        2 => insn.opcode_register = reg::AX + index,
        4 => insn.opcode_register = reg::EAX + index,
        8 => insn.opcode_register = reg::RAX + index,
        _ => {}
    }
}

fn read_immediate(insn: &mut Insn, size: i32) -> i32 {
    insn.immediate_size = size;
    let value = if size == 8 {
        if insn.cursor + 8 > insn.end {
            return -1;
        }
        let lo = insn.take(4) as u64;
        let hi = insn.take(4) as u64;
        McOp::Big(((hi << 32) | lo) as i64)
    } else {
        let v = insn.take(size as usize);
        if v < 0 {
            return -1;
        }
        McOp::Imm(v)
    };
    insn.immediates[insn.imm_count] = value;
    insn.imm_count += 1;
    0
}

fn read_vvvv(insn: &mut Insn) -> i32 {
    let v = insn.vex;
    let mut vvvv = if insn.vex_type == vext::EVEX {
        (inv(v[3], 3) << 4) | ((!v[2] >> 3) & 0xf)
    } else if insn.vex_type == vext::VEX3 || insn.vex_type == vext::XOP {
        (!v[2] >> 3) & 0xf
    } else if insn.vex_type == vext::VEX2 {
        (!v[1] >> 3) & 0xf
    } else {
        return -1;
    };
    if insn.mode != 64 {
        vvvv &= 0xf;
    }
    insn.vvvv = vvvv;
    0
}

fn read_operands(t: &Tables, insn: &mut Insn) -> i32 {
    let has_vvvv = read_vvvv(insn) == 0;
    let mut need_vvvv = has_vvvv && insn.vvvv != 0;
    let mut saw_reg_imm = false;
    let base = t.opset[insn.id as usize] as usize * 12;
    for k in 0..6 {
        let encoding = t.sets[base + k * 2];
        let kind = t.sets[base + k * 2 + 1];
        match encoding {
            enc::NONE | enc::SI | enc::DI | enc::FP | enc::DUP => {}
            enc::SIB => {
                if insn.ea_base != ea::SIB && insn.ea_base != ea::SIB64 {
                    return -1;
                }
                if read_modrm(insn) != 0 {
                    return -1;
                }
                if fixup_reg(insn, encoding, kind) != 0 {
                    return -1;
                }
            }
            enc::REG => {
                if read_modrm(insn) != 0 {
                    return -1;
                }
                if fixup_reg(insn, encoding, kind) != 0 {
                    return -1;
                }
            }
            enc::IB => {
                if saw_reg_imm {
                    // A register in the immediate's high nibble, and the low nibble as an immediate of its own.
                    insn.immediates[insn.imm_count] = McOp::Imm((to_int32(insn.immediates[insn.imm_count - 1].number()) & 0xf) as i64);
                    insn.imm_count += 1;
                    continue;
                }
                if read_immediate(insn, 1) != 0 {
                    return -1;
                }
                if kind == ty::XMM || kind == ty::YMM {
                    saw_reg_imm = true;
                }
            }
            enc::IW => {
                if read_immediate(insn, 2) != 0 {
                    return -1;
                }
            }
            enc::ID => {
                if read_immediate(insn, 4) != 0 {
                    return -1;
                }
            }
            enc::IO => {
                if read_immediate(insn, 8) != 0 {
                    return -1;
                }
            }
            enc::IV => {
                if read_immediate(insn, insn.immediate_size) != 0 {
                    return -1;
                }
            }
            enc::IA => {
                if read_immediate(insn, insn.address_size) != 0 {
                    return -1;
                }
            }
            enc::IRC => insn.rc = (((insn.vex[3] >> 6) & 1) << 1) | ((insn.vex[3] >> 5) & 1),
            enc::RB => read_opcode_register(insn, 1),
            enc::RW => read_opcode_register(insn, 2),
            enc::RD => read_opcode_register(insn, 4),
            enc::RO => read_opcode_register(insn, 8),
            enc::RV => read_opcode_register(insn, 0),
            enc::CF => {
                insn.immediates[1] = McOp::Imm(((insn.vex[2] >> 3) & 0xf) as i64);
                need_vvvv = false;
            }
            enc::CC => {
                if is_ccmp_or_ctest(insn) {
                    insn.immediates[2] = McOp::Imm((insn.vex[3] & 0xf) as i64);
                } else {
                    insn.immediates[1] = McOp::Imm((insn.opcode & 0xf) as i64);
                }
            }
            enc::VVVV => {
                need_vvvv = false;
                if !has_vvvv {
                    return -1;
                }
                if insn.mode != 64 {
                    insn.vvvv &= 7;
                }
                if fixup_reg(insn, encoding, kind) != 0 {
                    return -1;
                }
            }
            enc::WRITEMASK => {
                if insn.vex_type != vext::EVEX {
                    return -1;
                }
                insn.writemask = insn.vex[3] & 7;
            }
            _ => {
                if (enc::VSIB..=enc::VSIB_CD64).contains(&encoding) {
                    if need_vvvv {
                        need_vvvv = has_vvvv && (insn.vvvv & 0xf) != 0;
                    }
                    if read_modrm(insn) != 0 {
                        return -1;
                    }
                    if insn.ea_base != ea::SIB && insn.ea_base != ea::SIB64 {
                        return -1;
                    }
                    if insn.sib_index == sib_index::NONE {
                        insn.sib_index = insn.sib_index_base + 4;
                    }
                    if insn.vex_type == vext::EVEX && insn.mode == 64 && inv(insn.vex[3], 3) != 0 {
                        insn.sib_index += 16;
                    }
                    let offset = insn.sib_index - insn.sib_index_base;
                    if kind == ty::MVSIBX {
                        insn.sib_index = sib_index::XMM0 + offset;
                    } else if kind == ty::MVSIBY {
                        insn.sib_index = sib_index::YMM0 + offset;
                    } else if kind == ty::MVSIBZ {
                        insn.sib_index = sib_index::ZMM0 + offset;
                    } else {
                        return -1;
                    }
                    if insn.ea_displacement == 1 {
                        insn.displacement *= 1 << (encoding - enc::VSIB);
                    }
                } else if (enc::RM..=enc::RM_CD64).contains(&encoding) {
                    if read_modrm(insn) != 0 {
                        return -1;
                    }
                    if fixup_reg(insn, encoding, kind) != 0 {
                        return -1;
                    }
                    if insn.ea_displacement == 1 {
                        insn.displacement *= 1 << (encoding - enc::RM);
                    }
                } else {
                    return -1;
                }
            }
        }
    }
    if need_vvvv {
        -1
    } else {
        0
    }
}

/* ------------------------------------------------------------------ *
 * The MCInst
 * ------------------------------------------------------------------ */

#[inline]
fn sign_extend(value: McOp, bytes: i32) -> McOp {
    match value {
        McOp::Imm(v) => McOp::Imm(match bytes {
            1 => ((v as i32) << 24 >> 24) as i64,
            2 => ((v as i32) << 16 >> 16) as i64,
            4 => v as i32 as i64,
            _ => v,
        }),
        // A bigint stays as it is.
        other => other,
    }
}

impl X86Decoded {
    #[inline(always)]
    fn push(&mut self, op: McOp, kind: u8) {
        self.ops.push(op);
        self.types.push(kind);
    }
}

fn translate_immediate(insn: &Insn, mut value: McOp, encoding: u8, kind: u8, out: &mut X86Decoded) {
    if kind == ty::REL {
        let bytes = match encoding {
            enc::IV => insn.displacement_size,
            enc::IB => 1,
            enc::IW => 2,
            enc::ID => 4,
            _ => 8,
        };
        value = sign_extend(value, bytes);
    } else if kind == ty::IMM {
        let bytes = match encoding {
            enc::IB => 1,
            enc::IW => 2,
            enc::ID => 4,
            _ => 0,
        };
        if bytes != 0 {
            value = sign_extend(value, bytes);
        }
    }
    if kind == ty::XMM || kind == ty::YMM || kind == ty::ZMM {
        let names = if kind == ty::XMM {
            &XMM
        } else if kind == ty::YMM {
            &YMM
        } else {
            &ZMM
        };
        let n = to_int32(value.number()) >> 4;
        debug_assert!((0..32).contains(&n), "a register in an immediate out of range: {n}");
        out.push(McOp::Reg(names.get(n as usize).copied().unwrap_or("")), kind);
        return;
    }
    out.push(value, kind);
    if kind == ty::MOFFS {
        out.push(McOp::Reg(SEG[insn.segment]), kind);
    }
}

fn translate_rm_register(insn: &Insn, out: &mut Ops) -> bool {
    if insn.ea_base < ea::REG {
        return true;
    }
    out.push(McOp::Reg(ALL_REGS[(insn.ea_base - ea::REG) as usize]));
    false
}

fn translate_rm_memory(insn: &Insn, out: &mut Ops, force_sib: bool) -> bool {
    let base: &'static str;
    let index: &'static str;
    let scale: i32;
    if insn.ea_base == ea::SIB || insn.ea_base == ea::SIB64 {
        base = if insn.sib_base != sib_base::NONE { sib_base_name(insn.sib_base) } else { "" };
        if insn.sib_index != sib_index::NONE {
            match sib_index_name(insn.sib_index) {
                Some(name) => index = name,
                None => return true,
            }
        } else {
            let b = insn.sib_base;
            let sp_like = b == sib_base::EAX + 4 || b == sib_base::RAX + 4 || b == sib_base::EAX + 12 || b == sib_base::RAX + 12;
            index = if !force_sib && (insn.sib_scale != 1 || (b == sib_base::NONE && insn.mode != 64) || (b != sib_base::NONE && !sp_like)) {
                if insn.address_size == 4 {
                    "eiz"
                } else {
                    "riz"
                }
            } else {
                ""
            };
        }
        scale = insn.sib_scale;
    } else {
        match insn.ea_base {
            ea::NONE => {
                if insn.ea_displacement == 0 {
                    return true;
                }
                base = if insn.mode == 64 {
                    if insn.address_size == 4 {
                        "eip"
                    } else {
                        "rip"
                    }
                } else {
                    ""
                };
                index = "";
            }
            ea::BX_SI => {
                base = "bx";
                index = "si";
            }
            b if b == ea::BX_SI + 1 => {
                base = "bx";
                index = "di";
            }
            b if b == ea::BX_SI + 2 => {
                base = "bp";
                index = "si";
            }
            b if b == ea::BX_SI + 3 => {
                base = "bp";
                index = "di";
            }
            _ => {
                if insn.ea_base >= ea::REG {
                    return true;
                }
                base = ea_name(insn.ea_base);
                index = "";
            }
        }
        scale = 1;
    }
    out.push(McOp::Reg(base));
    out.push(McOp::Imm(scale as i64));
    out.push(McOp::Reg(index));
    out.push(McOp::Imm(insn.displacement));
    out.push(McOp::Reg(SEG[insn.segment]));
    false
}

fn translate_operand(t: &Tables, insn: &mut Insn, k: usize, out: &mut X86Decoded) -> bool {
    let base = t.opset[insn.id as usize] as usize * 12;
    let encoding = t.sets[base + k * 2];
    let kind = t.sets[base + k * 2 + 1];
    let before = out.ops.len();
    let ops = &mut out.ops;
    match encoding {
        enc::REG => ops.push(McOp::Reg(ALL_REGS[insn.reg as usize])),
        enc::WRITEMASK => {
            if insn.writemask >= 8 {
                return true;
            }
            ops.push(McOp::Reg(K[insn.writemask as usize]));
        }
        enc::IB | enc::IW | enc::ID | enc::IO | enc::IV | enc::IA => {
            let value = insn.immediates[insn.imm_translated];
            insn.imm_translated += 1;
            translate_immediate(insn, value, encoding, kind, out);
            return false;
        }
        enc::IRC => ops.push(McOp::Imm(insn.rc as i64)),
        enc::SI => {
            ops.push(McOp::Reg(if insn.mode == 64 {
                if insn.has_ad_size {
                    "esi"
                } else {
                    "rsi"
                }
            } else if insn.has_ad_size {
                "si"
            } else {
                "esi"
            }));
            ops.push(McOp::Reg(SEG[insn.segment]));
        }
        enc::DI => ops.push(McOp::Reg(if insn.mode == 64 {
            if insn.has_ad_size {
                "edi"
            } else {
                "rdi"
            }
        } else if insn.has_ad_size {
            "di"
        } else {
            "edi"
        })),
        enc::RB | enc::RW | enc::RD | enc::RO | enc::RV => ops.push(McOp::Reg(ALL_REGS[insn.opcode_register as usize])),
        enc::CF => ops.push(insn.immediates[1]),
        enc::CC => ops.push(if is_ccmp_or_ctest(insn) { insn.immediates[2] } else { insn.immediates[1] }),
        enc::FP => ops.push(McOp::Reg(ST[(insn.modrm & 7) as usize])),
        enc::VVVV => ops.push(McOp::Reg(ALL_REGS[insn.vvvv as usize])),
        enc::DUP => return translate_operand(t, insn, kind.wrapping_sub(ty::DUP0) as usize, out),
        _ => {
            if (enc::RM..=enc::RM_CD64).contains(&encoding) || encoding == enc::SIB || (enc::VSIB..=enc::VSIB_CD64).contains(&encoding) {
                let failed = if kind == ty::M || kind == ty::MVSIBX || kind == ty::MVSIBY || kind == ty::MVSIBZ {
                    translate_rm_memory(insn, ops, false)
                } else if kind == ty::MSIB {
                    translate_rm_memory(insn, ops, true)
                } else {
                    translate_rm_register(insn, ops)
                };
                if failed {
                    return true;
                }
            } else {
                return true;
            }
        }
    }
    for _ in before..out.ops.len() {
        out.types.push(kind);
    }
    false
}

/// Decodes one instruction at `offset` in `bytes` (not past `end`), at the
/// virtual address `addr`. `mode` is 64 for x86-64 code, 32 for i386.
pub fn decode_x86(bytes: &[u8], offset: usize, end: usize, addr: i64, mode: u8) -> X86Decoded {
    let mut d = X86Decoded::empty();
    decode_x86_into(&mut d, bytes, offset, end, addr, mode);
    d
}

impl X86Decoded {
    /// Nothing decoded yet (a place for decode_x86_into to write to).
    #[inline(always)]
    pub const fn empty() -> X86Decoded {
        X86Decoded { id: 0, length: 0, addr: 0, mode: 64, ops: Ops::new(), types: Types::new(), flags: 0, xacquire: false }
    }
}

/// decode_x86 into an instruction the caller keeps: the same result, without
/// moving the instruction (a few hundred bytes) out of the call.
pub fn decode_x86_into(d: &mut X86Decoded, bytes: &[u8], offset: usize, end: usize, addr: i64, mode: u8) {
    let t = x86_tables();
    d.id = 0;
    d.length = 1;
    d.addr = addr;
    d.mode = mode;
    d.ops = Ops::new();
    d.types = Types::new();
    d.flags = 0;
    d.xacquire = false;
    let mut insn = Insn::new(bytes, offset, end.min(bytes.len()), mode);
    if offset >= insn.end || read_prefixes(&mut insn) != 0 || read_opcode(&mut insn) || get_instruction_id(t, &mut insn) != 0 || insn.id == 0 || read_operands(t, &mut insn) != 0 {
        return failed(d, &insn, offset);
    }
    let base = t.opset[insn.id as usize] as usize * 12;
    for k in 0..6 {
        let encoding = t.sets[base + k * 2];
        if encoding == enc::NONE {
            continue;
        }
        if translate_operand(t, &mut insn, k, d) {
            return failed(d, &insn, offset);
        }
    }
    d.id = insn.id;
    d.length = (insn.cursor - offset) as u32;
    if insn.has_ad_size {
        d.flags |= pfx::AD_SIZE;
    }
    if insn.mandatory_prefix == 0 {
        if insn.repeat == 0xf2 {
            d.flags |= pfx::REPEAT_NE;
        } else if insn.repeat == 0xf3 && insn.opcode != 0x90 {
            d.flags |= pfx::REPEAT;
        }
        if insn.has_lock {
            d.flags |= pfx::LOCK;
        }
    }
    d.xacquire = insn.x_acquire_release && (insn.id == special::REP_PREFIX || insn.id == special::REPNE_PREFIX);
}

/// What did not decode: no operands, and the bytes read before it failed (at least 1).
#[cold]
fn failed(d: &mut X86Decoded, insn: &Insn, offset: usize) {
    d.length = insn.cursor.saturating_sub(offset).max(1) as u32;
    d.ops = Ops::new();
    d.types = Types::new();
}
