//! A decoded AArch64 instruction.
//!
//! The decoder keeps operands structured, not only as text: the listing prints
//! them, but the HLA64 view and the analysis (branch targets, adrp pairs,
//! string references) read registers, offsets and addressing modes from them.
//! Immediates carry the exact text LLVM's disassembler prints (hex for most,
//! decimal for shift amounts and bit positions), so the listing can be checked
//! against llvm-objdump line by line.
//!
//! Everything here is inline (see `text::Str`): decoding allocates nothing.

use core::mem::MaybeUninit;

use crate::text::{push_dec, push_hex, push_hex_i128, Str};

// The sizes are what the longest text needs (crates/core/examples/lengths.rs measures them
// over millions of words) with room to spare: an instruction is copied as a whole, so every
// byte here is paid for at every one of a program's millions of instructions.

/// A register name, a shift or extend name: `x0`, `v31.16b`, `v20.4b[0]`, `uxtw`.
pub type Name = Str<11>;
/// Operand text: a register list, a system register, a prefetch operation.
pub type Text = Str<43>;
/// An immediate as printed: `#0x10`, `#-0x709f000000000001`, `#1.00000000`.
pub type ImmText = Str<23>;
/// A shift as printed: `lsl #12`, `msl #0x10`.
pub type ShiftText = Str<15>;
/// A mnemonic as printed: `add`, `b.ne`, `ldbfmaxnmal`.
pub type Mn = Str<15>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Off,
    Pre,
    Post,
}

#[derive(Clone, Copy, Debug)]
pub struct Mem {
    pub base: Name,
    pub off: i64,
    pub index: Option<Name>,
    pub ext: Option<Name>,
    pub amount: Option<u8>,
    pub show_amount: bool,
    pub mode: Mode,
    /// A post-index by register, or a fixed amount printed as is (`#16`, `x3`).
    pub post: Option<Name>,
    /// A few RCpc forms with a fixed writeback amount print it in decimal.
    pub decimal: bool,
}

impl Mem {
    #[inline]
    pub fn new(base: Name, off: i64, mode: Mode) -> Mem {
        Mem { base, off, index: None, ext: None, amount: None, show_amount: false, mode, post: None, decimal: false }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Op {
    Reg(Name),
    /// `v` is the value as the TypeScript core held it (a JavaScript number), `t` the exact text.
    Imm {
        v: f64,
        t: ImmText,
    },
    Label(i64),
    Mem(Mem),
    Shift {
        s: Name,
        amount: i64,
        t: ShiftText,
    },
    Text(Text),
}

/// What an instruction does to control flow and memory, for the analysis.
pub mod f {
    pub const BRANCH: u32 = 1; // changes the PC: b, b.cond, cbz, tbz, br, ret, …
    pub const COND: u32 = 2; // only sometimes (b.cond, cbz, tbz)
    pub const CALL: u32 = 4; // bl, blr
    pub const RET: u32 = 8; // ret and its pointer-authenticated forms
    pub const INDIRECT: u32 = 16; // target in a register: br, blr, ret
    pub const LOAD: u32 = 32;
    pub const STORE: u32 = 64;
    pub const SETS_FLAGS: u32 = 128;
    pub const READS_FLAGS: u32 = 256;
    pub const TRAP: u32 = 512; // brk, udf, hlt: execution does not continue
    pub const UNKNOWN: u32 = 1024; // not an instruction the decoder knows
    pub const ATOMIC: u32 = 2048;
}

pub const MAX_OPS: usize = 6;

/// The operands of an instruction, at most `MAX_OPS`, inline. Slots past `len` are never
/// initialised: a decoded instruction writes only the operands it has.
#[derive(Clone, Copy)]
pub struct Ops {
    len: u8,
    items: [MaybeUninit<Op>; MAX_OPS],
}

impl Ops {
    #[inline]
    pub const fn new() -> Ops {
        Ops { len: 0, items: [MaybeUninit::uninit(); MAX_OPS] }
    }

    #[inline]
    pub fn from_slice(ops: &[Op]) -> Ops {
        let mut out = Ops::new();
        out.extend(ops);
        out
    }

    #[inline]
    pub fn push(&mut self, op: Op) {
        debug_assert!((self.len as usize) < MAX_OPS, "too many operands");
        if (self.len as usize) < MAX_OPS {
            self.items[self.len as usize] = MaybeUninit::new(op);
            self.len += 1;
        }
    }

    #[inline]
    pub fn extend(&mut self, ops: &[Op]) {
        for op in ops {
            self.push(*op);
        }
    }

    #[inline]
    pub fn as_slice(&self) -> &[Op] {
        // SAFETY: the first `len` items were written by push.
        unsafe { core::slice::from_raw_parts(self.items.as_ptr() as *const Op, self.len as usize) }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len as usize
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub fn get(&self, i: usize) -> Option<&Op> {
        self.as_slice().get(i)
    }
}

impl core::ops::Deref for Ops {
    type Target = [Op];
    #[inline]
    fn deref(&self) -> &[Op] {
        self.as_slice()
    }
}

impl core::fmt::Debug for Ops {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_list().entries(self.as_slice()).finish()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Insn {
    /// As printed: add, b.ne, ld1, mov.
    pub m: Mn,
    pub ops: Ops,
    pub f: u32,
    /// Branch, adr/adrp or literal-load target.
    pub target: Option<i64>,
    /// The condition of b.cond, csel, ccmp…: eq, ne, lt…
    pub cond: Option<&'static str>,
    /// Bytes a load or store moves per register (1, 2, 4, 8, 16); 0 when it is none.
    pub size: u8,
    /// A load that sign-extends (ldrsb, ldrsw, …).
    pub signed: bool,
}

impl Insn {
    #[inline]
    pub fn new(m: Mn, ops: &[Op], f: u32) -> Insn {
        Insn { m, ops: Ops::from_slice(ops), f, target: None, cond: None, size: 0, signed: false }
    }

    #[inline]
    pub fn target(mut self, target: i64) -> Insn {
        self.target = Some(target);
        self
    }

    #[inline]
    pub fn cond(mut self, cond: &'static str) -> Insn {
        self.cond = Some(cond);
        self
    }

    #[inline]
    pub fn size(mut self, size: u32) -> Insn {
        self.size = size as u8;
        self
    }

    #[inline]
    pub fn signed(mut self, signed: bool) -> Insn {
        self.signed = signed;
        self
    }
}

/// `mk('add', [...], F.X)` of the TypeScript decoder.
#[inline(always)]
pub fn mk(m: &str, ops: &[Op], f: u32) -> Insn {
    Insn::new(Mn::from(m), ops, f)
}

pub const CONDITIONS: [&str; 16] = ["eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"];

/// `#0x…` (or `#…` in decimal) for an integer immediate.
#[inline(always)]
pub fn imm(v: i64) -> Op {
    let mut t = ImmText::new();
    t.push("#");
    push_hex(&mut t, v);
    Op::Imm { v: v as f64, t }
}

#[inline(always)]
pub fn imm_dec(v: i64) -> Op {
    let mut t = ImmText::new();
    t.push("#");
    push_dec(&mut t, v);
    Op::Imm { v: v as f64, t }
}

#[inline(always)]
pub fn imm_text(v: f64, t: &str) -> Op {
    Op::Imm { v, t: ImmText::from(t) }
}

/// A 64-bit immediate from BigInt arithmetic: exact text, the value rounded as `Number(v)` does.
#[inline]
pub fn big_imm(v: i128) -> Op {
    let mut t = ImmText::new();
    t.push("#");
    push_hex_i128(&mut t, v);
    Op::Imm { v: v as f64, t }
}

/// A register operand, from its name as text or as a ready-made `Name` (decode.rs's tables).
#[inline(always)]
pub fn reg(r: impl IntoName) -> Op {
    Op::Reg(r.into_name())
}

pub trait IntoName {
    fn into_name(self) -> Name;
}

impl IntoName for Name {
    #[inline(always)]
    fn into_name(self) -> Name {
        self
    }
}

impl IntoName for &str {
    #[inline(always)]
    fn into_name(self) -> Name {
        Name::from(self)
    }
}

impl IntoName for &Name {
    #[inline(always)]
    fn into_name(self) -> Name {
        *self
    }
}

#[inline]
pub fn reg_name(r: Name) -> Op {
    Op::Reg(r)
}

#[inline(always)]
pub fn text(t: &str) -> Op {
    Op::Text(Text::from(t))
}

#[inline(always)]
pub fn label(addr: i64) -> Op {
    Op::Label(addr)
}

/// `lsl #12`; `hex_amount` prints the amount as `#0x…`.
#[inline(always)]
pub fn shift_op(s: &str, amount: i64, hex_amount: bool) -> Op {
    let mut t = ShiftText::new();
    t.push(s);
    t.push(" #");
    if hex_amount {
        push_hex(&mut t, amount);
    } else {
        push_dec(&mut t, amount);
    }
    Op::Shift { s: Name::from(s), amount, t }
}

#[inline(always)]
pub fn shift(s: &str, amount: i64) -> Op {
    shift_op(s, amount, false)
}

#[inline(always)]
pub fn mem(base: Name, off: i64, mode: Mode) -> Op {
    Op::Mem(Mem::new(base, off, mode))
}

/// An operand as llvm-objdump prints it.
pub fn format_op<const N: usize>(out: &mut Str<N>, op: &Op) {
    match op {
        Op::Reg(r) => out.push(r),
        Op::Imm { t, .. } => out.push(t),
        Op::Label(addr) => push_hex(out, *addr),
        Op::Shift { t, .. } => out.push(t),
        Op::Text(t) => out.push(t),
        Op::Mem(m) => {
            let push_off = |out: &mut Str<N>| {
                if m.decimal {
                    push_dec(out, m.off)
                } else {
                    push_hex(out, m.off)
                }
            };
            out.push("[");
            out.push(&m.base);
            if let Some(index) = &m.index {
                out.push(", ");
                out.push(index);
                if let Some(ext) = &m.ext {
                    out.push(", ");
                    out.push(ext);
                    if m.show_amount {
                        out.push(" #");
                        push_dec(out, m.amount.unwrap_or(0) as i64);
                    }
                }
            } else if (m.off != 0 && m.mode != Mode::Post) || m.mode == Mode::Pre {
                out.push(", #");
                push_off(out);
            }
            match m.mode {
                Mode::Pre => out.push("]!"),
                Mode::Post => {
                    out.push("], ");
                    match &m.post {
                        Some(post) => out.push(post),
                        None => {
                            out.push("#");
                            push_off(out);
                        }
                    }
                }
                Mode::Off => out.push("]"),
            }
        }
    }
}

/// The whole instruction as llvm-objdump prints it: `add x0, x1, #0x10`.
pub type Line = Str<96>;

pub fn format_insn(insn: &Insn) -> Line {
    let mut out = Line::new();
    out.push(&insn.m);
    for (i, op) in insn.ops.iter().enumerate() {
        out.push(if i == 0 { " " } else { ", " });
        format_op(&mut out, op);
    }
    out
}

pub fn format_op_string(op: &Op) -> String {
    let mut out = Line::new();
    format_op(&mut out, op);
    out.as_str().to_string()
}
