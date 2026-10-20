//! A decoded AArch32 instruction — A32 (ARM state) or T32 (Thumb state, 16 or
//! 32 bits).
//!
//! As on A64, operands stay structured: the listing prints them, the analysis
//! reads branch targets, PC-relative literals and the registers an `add rX, pc`
//! completes. Each operand carries the exact text LLVM's printer gives it, since
//! the ARM printer is not uniform (`add r0, r1, #4` in decimal, `ldr r0, [r1,
//! #0x4]` in hex, `ldr r0, [r1], #4` in decimal again) and the decoder is
//! checked against llvm-objdump line by line (tools/verify-arm32.mjs).
//!
//! Everything here is inline (see `text::Str`): decoding allocates nothing. A
//! register list keeps register numbers, not names, and prints its text when
//! asked: a list of 32 D registers would otherwise carry 150 bytes of text.

use core::mem::MaybeUninit;

pub use crate::arm64::types::f;
use crate::text::{push_dec, push_hex_u64, Str};

// The sizes are what the longest text needs (measured over every A32 word and every T32
// instruction in and out of IT blocks) with some room to spare: an instruction is copied as a
// whole, so every byte here is paid for at each of a program's instructions.

/// A register name: `r0`, `sp`, `d31`, `q15`, `apsr_nzcv`, `d17[1]`, `fpinst2`.
pub type Name = Str<11>;
/// Anything else printed as is: `ish`, `eq` (of an it), `APSR_nzcvqg`, `SPSR_fiq`, `p15`, `#0x3!`.
pub type Text = Str<15>;
/// An immediate as printed: `#0x1f`, `#-2147483648`, `#255, #30`, `#-1.250000e-01`, `#0xff00ff0000ff00ff`.
pub type ImmText = Str<23>;
/// A shift as printed: `lsl #2`, `asr r10`, `rrx`.
pub type ShiftText = Str<11>;
/// A memory operand as printed: `[r10, -r11, lsl #31]!`, `[r10:256], r12`.
pub type MemText = Str<23>;
/// A mnemonic as printed, with its condition and data type: `addeq`, `ldr.w`, `vcvtt<und>.bf16.f32`.
pub type Mn = Str<23>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Off,
    Pre,
    Post,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Off => "off",
            Mode::Pre => "pre",
            Mode::Post => "post",
        }
    }
}

/// A memory operand with its whole text: `[r1, #0x4]`, `[r2], #4`, `[sp, #-4]!`, `[r0, r1, lsl #2]`, `[lr:128]!`.
#[derive(Clone, Copy, Debug)]
pub struct Mem {
    pub base: Name,
    pub t: MemText,
    pub off: Option<i64>,
    pub index: Option<Name>,
    pub mode: Mode,
}

/// The register file a list names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bank {
    /// r0…r12, sp, lr, pc
    Core,
    /// d0…d31, and past them fpinst2, mvfr0, mvfr1 (LLVM's numbering: see `simd_common::dname`)
    D,
    S,
}

/// The longest list: vldm/vstm of 32 registers (ldm/stm take 16).
pub const MAX_LIST: usize = 32;

/// No lane suffix, `[]` (every lane), or `[i]`.
const LANE_NONE: u8 = 0xff;
const LANE_ALL: u8 = 0xfe;

/// A register list: `{r4, r5, lr}`, `{d16, d17}`, `{d0[], d1[]}`, `{d2[1]}`, `{r0, r1} ^`.
/// The registers are kept as numbers in their bank; `reg(i)` names one, `push_text` prints the list.
#[derive(Clone, Copy)]
pub struct List {
    bank: Bank,
    lane: u8,
    /// ldm/stm of the user registers: ` ^` after the braces.
    pub user: bool,
    len: u8,
    n: [u8; MAX_LIST],
}

impl List {
    #[inline]
    pub fn new(bank: Bank) -> List {
        List { bank, lane: LANE_NONE, user: false, len: 0, n: [0; MAX_LIST] }
    }

    #[inline]
    pub fn push(&mut self, n: u32) {
        debug_assert!((self.len as usize) < MAX_LIST, "register list overflow");
        if (self.len as usize) < MAX_LIST {
            self.n[self.len as usize] = n as u8;
            self.len += 1;
        }
    }

    /// Every register of the list followed by `[]`.
    #[inline]
    pub fn all_lanes(mut self) -> List {
        self.lane = LANE_ALL;
        self
    }

    /// Every register of the list followed by `[index]`.
    #[inline]
    pub fn lane(mut self, index: u32) -> List {
        self.lane = index as u8;
        self
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len as usize
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn bank(&self) -> Bank {
        self.bank
    }

    /// The register numbers, in their bank.
    #[inline]
    pub fn numbers(&self) -> &[u8] {
        &self.n[..self.len as usize]
    }

    /// The name of the `i`th register, as printed: `r4`, `d30`, `fpinst2`, `d0[]`, `s3`.
    pub fn reg(&self, i: usize) -> Name {
        let n = self.n[i] as u32;
        let mut name = match self.bank {
            Bank::Core => REG_NAMES[(n & 15) as usize],
            Bank::D => crate::arm32::simd_common::dname(n),
            Bank::S => crate::arm32::simd_common::sname(n),
        };
        match self.lane {
            LANE_NONE => {}
            LANE_ALL => name.push("[]"),
            index => {
                name.push("[");
                push_dec(&mut name, index as i64);
                name.push("]");
            }
        }
        name
    }

    pub fn regs(&self) -> impl Iterator<Item = Name> + '_ {
        (0..self.len()).map(move |i| self.reg(i))
    }

    /// `{r4, r5, lr}`, `{r0, r1} ^`.
    pub fn push_text<const N: usize>(&self, out: &mut Str<N>) {
        out.push("{");
        for i in 0..self.len() {
            if i > 0 {
                out.push(", ");
            }
            out.push(&self.reg(i));
        }
        out.push(if self.user { "} ^" } else { "}" });
    }
}

impl core::fmt::Debug for List {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut t = Line::new();
        self.push_text(&mut t);
        f.write_str(&t)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Op {
    /// A register: r0…r12, sp, lr, pc, s0, d16, q8, apsr_nzcv, fpscr, p15, c13… `wb` prints `!` after it (ldm r0!, …).
    Reg {
        r: Name,
        wb: bool,
    },
    /// `v` is the value as the TypeScript core held it (a JavaScript number), `t` the exact text.
    Imm {
        v: f64,
        t: ImmText,
    },
    /// A branch target, printed as LLVM prints it: the absolute address in hex.
    Label(i64),
    Mem(Mem),
    List(List),
    /// A shift of the last register: `lsl #2`, `asr r3`, `rrx`.
    Shift(ShiftText),
    /// Anything else, printed as it is: `ish`, `eq` (of an it), `aif`, `be`, `cpsr_fc`.
    Text(Text),
}

pub const MAX_OPS: usize = 6;

/// The operands of an instruction, at most `MAX_OPS` (mcr, mrc), inline. Slots past `len` are never initialised.
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
}

impl Default for Ops {
    fn default() -> Self {
        Ops::new()
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

/// A short list of IT conditions (0…15), inline: what an IT instruction covers (at most four, five
/// for the mask 0 no IT has), or, as `ItPending`, what is left of the blocks around an instruction.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CondList<const N: usize> {
    len: u8,
    c: [u8; N],
}

impl<const N: usize> CondList<N> {
    #[inline]
    pub const fn new() -> Self {
        CondList { len: 0, c: [0; N] }
    }

    #[inline]
    pub fn from_slice(c: &[u8]) -> Self {
        let mut out = Self::new();
        for &x in c {
            out.push(x);
        }
        out
    }

    /// Appends a condition; one past the capacity is dropped (see `ItPending`).
    #[inline]
    pub fn push(&mut self, c: u8) {
        if (self.len as usize) < N {
            self.c[self.len as usize] = c;
            self.len += 1;
        }
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.c[..self.len as usize]
    }
}

impl<const N: usize> Default for CondList<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> core::ops::Deref for CondList<N> {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<const N: usize> core::fmt::Debug for CondList<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_list().entries(self.as_slice()).finish()
    }
}

/// The conditions of an IT instruction.
pub type ItConds = CondList<5>;

#[derive(Clone, Copy, Debug)]
pub struct Insn {
    /// As printed, with the condition and qualifiers: `addeq`, `ldr.w`, `vadd.f32`, `itte`.
    pub m: Mn,
    pub ops: Ops,
    pub f: u32,
    /// Bytes: 4 for A32 and 32-bit T32, 2 for 16-bit T32.
    pub size: u8,
    /// Branch target, or the address a PC-relative operand names (ldr/vldr literal, adr, pld literal).
    pub target: Option<i64>,
    /// The condition the instruction executes under (eq, ne…): its own or that of the IT block around it.
    pub cond: Option<&'static str>,
    /// bl/blx to an immediate: whether the code at the target is Thumb.
    pub thumb: Option<bool>,
    /// An IT instruction: the conditions of the instructions it covers, in order.
    pub it: Option<ItConds>,
    /// Bytes a load or store moves per register (1, 2, 4, 8); 0 when it is none.
    pub bytes: u8,
}

impl Insn {
    #[inline]
    pub fn new(m: Mn, ops: &[Op], f: u32, size: u8) -> Insn {
        Insn { m, ops: Ops::from_slice(ops), f, size, target: None, cond: None, thumb: None, it: None, bytes: 0 }
    }

    #[inline]
    pub fn target(mut self, target: i64) -> Insn {
        self.target = Some(target);
        self
    }

    #[inline]
    pub fn bytes(mut self, bytes: u32) -> Insn {
        self.bytes = bytes as u8;
        self
    }

    #[inline]
    pub fn thumb(mut self, thumb: bool) -> Insn {
        self.thumb = Some(thumb);
        self
    }

    #[inline]
    pub fn it(mut self, it: ItConds) -> Insn {
        self.it = Some(it);
        self
    }
}

/// Condition codes as LLVM prints them; 14 (al) prints nothing.
pub const CONDS: [&str; 16] = ["eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "", ""];

/// `CONDS[c]` for a condition that may lie outside 0…15: JavaScript's lookup gives `undefined` there.
#[inline]
pub fn cond_at(c: i32) -> Option<&'static str> {
    if (0..16).contains(&c) {
        Some(CONDS[c as usize])
    } else {
        None
    }
}

/// `CONDS[c]` concatenated to a string: what JavaScript prints for a missing entry.
#[inline]
pub fn cond_text(c: i32) -> &'static str {
    cond_at(c).unwrap_or("undefined")
}

pub const REGS: [&str; 16] = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc"];

pub(crate) static REG_NAMES: [Name; 16] = [
    Name::from_static("r0"),
    Name::from_static("r1"),
    Name::from_static("r2"),
    Name::from_static("r3"),
    Name::from_static("r4"),
    Name::from_static("r5"),
    Name::from_static("r6"),
    Name::from_static("r7"),
    Name::from_static("r8"),
    Name::from_static("r9"),
    Name::from_static("r10"),
    Name::from_static("r11"),
    Name::from_static("r12"),
    Name::from_static("sp"),
    Name::from_static("lr"),
    Name::from_static("pc"),
];

/// The name of a core register, as a ready-made inline string.
#[inline(always)]
pub fn r(n: u32) -> Name {
    REG_NAMES[(n & 15) as usize]
}

#[inline(always)]
pub fn bits(w: u32, hi: u32, lo: u32) -> u32 {
    let mask = if hi - lo == 31 { u32::MAX } else { (1u32 << (hi - lo + 1)) - 1 };
    (w >> lo) & mask
}

#[inline(always)]
pub fn bit(w: u32, n: u32) -> u32 {
    (w >> n) & 1
}

/// Sign-extends the low `width` bits of `v` (JavaScript's `(v << (32 - width)) >> (32 - width)`).
#[inline(always)]
pub fn sext(v: u32, width: u32) -> i32 {
    ((v << (32 - width)) as i32) >> (32 - width)
}

/// `0x1f`, `-0x4`: LLVM's hex for immediates and offsets (JavaScript's `v >>> 0` for the positive side).
#[inline]
pub fn push_hex<const N: usize>(out: &mut Str<N>, v: i64) {
    if v < 0 {
        out.push("-0x");
        push_hex_u64(out, v.unsigned_abs());
    } else {
        out.push("0x");
        push_hex_u64(out, v as u32 as u64);
    }
}

#[inline(always)]
pub fn reg(name: Name, wb: bool) -> Op {
    Op::Reg { r: name, wb }
}

/// A register named by text, for the few names outside the tables: `apsr_nzcv`, `fpscr`.
#[inline(always)]
pub fn reg_str(name: &str) -> Op {
    Op::Reg { r: Name::from(name), wb: false }
}

/// `#0x1f`
#[inline(always)]
pub fn imm_hex(v: i64) -> Op {
    let mut t = ImmText::new();
    t.push("#");
    push_hex(&mut t, v);
    Op::Imm { v: v as f64, t }
}

/// `#31`
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

/// A branch target: addresses are unsigned 32-bit (JavaScript's `addr >>> 0`).
#[inline(always)]
pub fn label(addr: i64) -> Op {
    Op::Label(addr as u32 as i64)
}

#[inline(always)]
pub fn shift(t: &str) -> Op {
    Op::Shift(ShiftText::from(t))
}

#[inline(always)]
pub fn text(t: &str) -> Op {
    Op::Text(Text::from(t))
}

/// The registers of a 16-bit mask, lowest first: {r4, r5, lr}.
#[inline]
pub fn reg_list(mask: u32) -> List {
    let mut out = List::new(Bank::Core);
    let mut m = mask & 0xffff;
    while m != 0 {
        out.push(m.trailing_zeros());
        m &= m - 1;
    }
    out
}

/// An operand as llvm-objdump prints it.
pub fn format_op<const N: usize>(out: &mut Str<N>, op: &Op) {
    match op {
        Op::Reg { r, wb } => {
            out.push(r);
            if *wb {
                out.push("!");
            }
        }
        Op::Label(addr) => push_hex(out, *addr),
        Op::Imm { t, .. } => out.push(t),
        Op::Mem(m) => out.push(&m.t),
        Op::List(l) => l.push_text(out),
        Op::Shift(t) => out.push(t),
        Op::Text(t) => out.push(t),
    }
}

/// The whole instruction as llvm-objdump prints it. The longest is a vldm/vstm of 32 registers
/// (`fstmdbx<und> r10!, {d0, …, d31}`, 169 bytes).
pub type Line = Str<191>;

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

/// What is not an instruction: `.inst 0xe7f000f0`, `.inst.n 0xde00`, `.inst.w 0xf7f0a000`.
pub fn unknown(word: u32, size: u8, thumb: bool) -> Insn {
    let m = if thumb {
        if size == 2 {
            ".inst.n"
        } else {
            ".inst.w"
        }
    } else {
        ".inst"
    };
    let mut t = ImmText::from("0x");
    let digits = if word == 0 { 1 } else { (32 - word.leading_zeros()).div_ceil(4) };
    for _ in digits..(size as u32) * 2 {
        t.push_byte(b'0');
    }
    push_hex_u64(&mut t, word as u64);
    Insn::new(Mn::from(m), &[Op::Imm { v: word as f64, t }], f::UNKNOWN, size)
}

/// The state an IT instruction leaves for the instructions after it: `it`
/// holds their conditions in order. A decoder of a T32 instruction inside the
/// block gets its condition (0…14); outside a block it gets -1.
pub fn it_conditions(firstcond: u32, mask: u32) -> ItConds {
    let mut out = ItConds::new();
    out.push(firstcond as u8);
    // The mask's lowest set bit ends the block; each bit above it says then (= firstcond[0]) or else.
    let trailing = (mask as i32) & (mask as i32).wrapping_neg();
    let mut b = 3;
    while b >= 0 && (1i32 << b) > trailing {
        out.push(((firstcond & !1) | ((mask >> b) & 1)) as u8);
        b -= 1;
    }
    out
}

/// The suffix of an IT instruction: `itte` for firstcond eq, mask 0b0110.
pub fn it_suffix(firstcond: u32, mask: u32) -> Str<7> {
    let mut s = Str::<7>::new();
    let trailing = (mask as i32) & (mask as i32).wrapping_neg();
    let mut b = 3;
    while b >= 0 && (1i32 << b) > trailing {
        s.push(if (mask >> b) & 1 == firstcond & 1 { "t" } else { "e" });
        b -= 1;
    }
    s
}

/* ------------------------------------------------------------------ *
 * Building text: `cat!(MemText; "[", base, ", #", Dec(imm), "]")` is the
 * template literal `[${base}, #${imm}]`, written inline without core::fmt.
 * ------------------------------------------------------------------ */

/// A number in decimal, as `${v}` prints an integer.
pub struct Dec(pub i64);
/// A number as `hex(v)` prints it: `0x1f`, `-0x4`.
pub struct Hex(pub i64);

pub trait Piece {
    fn put<const N: usize>(self, out: &mut Str<N>);
}

impl Piece for &str {
    #[inline(always)]
    fn put<const N: usize>(self, out: &mut Str<N>) {
        out.push(self);
    }
}

impl<const M: usize> Piece for Str<M> {
    #[inline(always)]
    fn put<const N: usize>(self, out: &mut Str<N>) {
        out.push(&self);
    }
}

impl<const M: usize> Piece for &Str<M> {
    #[inline(always)]
    fn put<const N: usize>(self, out: &mut Str<N>) {
        out.push(self);
    }
}

impl Piece for Dec {
    #[inline(always)]
    fn put<const N: usize>(self, out: &mut Str<N>) {
        push_dec(out, self.0);
    }
}

impl Piece for Hex {
    #[inline(always)]
    fn put<const N: usize>(self, out: &mut Str<N>) {
        push_hex(out, self.0);
    }
}

#[macro_export]
#[doc(hidden)]
macro_rules! arm32_cat {
    ($ty:ty; $($part:expr),* $(,)?) => {{
        let mut s = <$ty>::new();
        $( $crate::arm32::types::Piece::put($part, &mut s); )*
        s
    }};
}
pub use crate::arm32_cat as cat;
