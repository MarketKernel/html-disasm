//! The analysis of 32-bit Arm code (Android's armeabi-v7a, old iOS armv7,
//! Windows on Arm): statistics, labels, call and data references, switch
//! tables, for code that mixes two instruction sets and keeps its constants
//! among the instructions.
//!
//! Which bytes are A32, which are T32 and which are data is the first thing
//! to settle. A library that kept its symbol table says it with mapping
//! symbols ($a, $t, $d), exactly as llvm-objdump reads them. A stripped one
//! (every library in an APK) does not, and the analysis works it out:
//!
//! - every function symbol, init/fini pointer and the entry point says the
//!   instruction set at its address (bit 0 set is Thumb), and the PLT is A32;
//! - the code is decoded with that, and every `bl` and `blx` to an address
//!   says the set at its target (`blx` switches, `bl` keeps);
//! - every PC-relative load names a literal-pool word, and every `tbb`/`tbh`
//!   a table of branch offsets right after it: those bytes are data, shown as
//!   `.word`, `.short` or `.byte`, and decoding resumes after them.
//!
//! Twice round that loop is enough for what compilers emit. Instructions are
//! kept as small arrays — address, encoding, kind, IT condition — and decoded
//! again only for the rows on screen. What needs names (functions, stubs, the
//! entry point) is the job of the code around it (src/core/arm32/program.ts).

use super::decode::{decode_arm, decode_thumb, is_wide, it_after};
use super::types::{Insn, Mode as MemMode, Op};
use crate::arm64::types::f;
use crate::disassembly::iflag;
use crate::image::{Format, Image, StringRef};
use crate::refs::{FxHashMap, FxHashSet, RefBuilder, RefIndex};

/// What an entry of the instruction arrays is.
pub mod kind {
    pub const A32: u8 = 0;
    pub const T16: u8 = 1;
    pub const T32: u8 = 2;
    pub const WORD: u8 = 3;
    pub const SHORT: u8 = 4;
    pub const BYTE: u8 = 5;
}

const SIZE: [u32; 6] = [4, 2, 4, 4, 2, 1];
pub const DATA_NAMES: [&str; 6] = ["", "", "", ".word", ".short", ".byte"];

/// The instruction set (or data) at a place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Set {
    A,
    T,
    D,
}

impl Set {
    pub fn from_char(c: u8) -> Set {
        match c {
            b'a' => Set::A,
            b'd' => Set::D,
            _ => Set::T,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Mark {
    pub addr: i64,
    pub set: Set,
}

/// The run of instructions of one code section.
#[derive(Clone, Copy, Debug)]
pub struct Range {
    /// Its section, by index in the image's sections.
    pub section: usize,
    pub first: u32,
    pub count: u32,
}

#[derive(Default, Clone)]
pub struct Layout {
    pub addrs: Vec<u32>,
    /// A32 word, T16 halfword, T32 as hw1 << 16 | hw2, or the data value.
    pub words: Vec<u32>,
    pub kinds: Vec<u8>,
    /// The condition an IT block gives the instruction (0…14), or -1.
    pub its: Vec<i8>,
    pub ranges: Vec<Range>,
}

/// One entry of the arrays, decoded (instructions only: data is no instruction).
pub fn decode_at(k: u8, word: u32, pc: i64, it: i32) -> Insn {
    match k {
        kind::A32 => decode_arm(word, pc),
        kind::T16 => decode_thumb(word, 0, pc, it),
        _ => decode_thumb(word >> 16, word & 0xffff, pc, it),
    }
}

/// An A32 modified immediate: eight bits rotated right by twice the rotation field.
#[inline]
fn arm_imm(word: u32) -> u32 {
    let rot = ((word >> 8) & 0xf) * 2;
    (word & 0xff).rotate_right(rot)
}

/// `r0`…`r12`, `sp`, `lr`, `pc` by number, or -1.
fn reg_number(name: &str) -> i32 {
    match name {
        "sp" => 13,
        "lr" => 14,
        "pc" => 15,
        _ => match name.strip_prefix('r') {
            Some(n) if !n.is_empty() && n.len() <= 2 && n.bytes().all(|c| c.is_ascii_digit()) && !(n.len() == 2 && n.starts_with('0')) => {
                let v: i32 = n.parse().unwrap_or(99);
                if v <= 12 {
                    v
                } else {
                    -1
                }
            }
            _ => -1,
        },
    }
}

fn reg_of(op: Option<&Op>) -> i32 {
    match op {
        Some(Op::Reg { r, .. }) => reg_number(r),
        _ => -1,
    }
}

fn first_mem(insn: &Insn) -> Option<&Op> {
    insn.ops.iter().find(|op| matches!(op, Op::Mem(_)))
}

fn first_list(insn: &Insn) -> Option<&Op> {
    insn.ops.iter().find(|op| matches!(op, Op::List(_)))
}

/// The file's bytes as the TypeScript read them: past the end, a byte is 0 (`undefined | x` is x).
struct Bytes<'a> {
    bytes: &'a [u8],
    base: i64,
}

impl Bytes<'_> {
    #[inline]
    fn u8(&self, addr: i64) -> u32 {
        let at = self.base + addr;
        if at < 0 {
            return 0;
        }
        self.bytes.get(at as usize).copied().unwrap_or(0) as u32
    }
    #[inline]
    fn u16(&self, addr: i64) -> u32 {
        self.u8(addr) | (self.u8(addr + 1) << 8)
    }
    #[inline]
    fn u32(&self, addr: i64) -> u32 {
        self.u16(addr) | (self.u16(addr + 2) << 16)
    }
}

/// What the analysis is given besides the image: what the file says.
pub struct Arm32Input {
    /// Mapping symbols ($a, $t, $d) in code, in the file's order: when there are any, they are the truth.
    pub file_marks: Vec<Mark>,
    /// The set the code is in where nothing says (most functions Thumb: 't').
    pub fallback: Set,
    /// Where the set is known (the PLT, symbols, init/fini pointers, the entry point, Thumb starts), in the order the page settled them.
    pub known: Vec<Mark>,
    /// Functions the unwind tables list: their set is sniffed when nothing else says it.
    pub function_starts: Vec<i64>,
    /// The spans of the functions the symbols describe (start, end), sorted: code inside one keeps its set.
    pub spans: Vec<(i64, i64)>,
    /// Data the file marks among the instructions (LC_DATA_IN_CODE): address, length.
    pub data_in_code: Vec<(i64, i64)>,
    /// Addresses that name something: symbols, import slots, C strings, Objective-C references.
    pub symbols: Vec<i64>,
    pub slots: Vec<i64>,
    pub strings: Vec<i64>,
    pub objc: Vec<i64>,
    /// ELF relative relocations: slot → the address the loader puts there.
    pub relative: Vec<(i64, i64)>,
}

pub struct Arm32Pass {
    pub image: Image,
    /// The code sections, by index in the image, in address order.
    code: Vec<usize>,
    pub mapped: bool,
    pub layout: Layout,
    symbols: FxHashSet<i64>,
    slots: FxHashSet<i64>,
    strings: FxHashSet<i64>,
    objc: FxHashSet<i64>,
    relative: FxHashMap<i64, i64>,

    pub mnemonic_ids: Vec<u16>,
    pub flags: Vec<u8>,
    pub mnemonics: Vec<String>,
    pub counts: Vec<u32>,
    ids: FxHashMap<String, u16>,
    printed: FxHashMap<String, u16>,
    callers: RefBuilder,
    data_refs: RefBuilder,
    /// References taken back (an address that was an offset after all): key, instruction, and how many pairs existed then.
    retracted: Vec<(i64, u32, usize)>,
    slot_callers: RefBuilder,
    pub slot_calls: Vec<(u32, i64)>,
    pub address_at: FxHashMap<u32, i64>,
    tables: Vec<(u32, Vec<i64>)>,
    label_targets: Vec<i64>,
    /// Calls and branches with a target: the instruction → where it goes.
    pub targets: Vec<(u32, i64)>,

    // Where the pass is, between steps.
    at: u32,
    range_end: u32,
    value: [f64; 16],
    set_at: [i64; 16],
    is_address: [bool; 16],
    slot_in: [f64; 16],
    slot_at: [i64; 16],
}

pub struct Arm32Refs {
    pub callers: RefIndex,
    pub data_refs: RefIndex,
    pub slot_callers: RefIndex,
    pub table_index: Vec<u32>,
    pub table_starts: Vec<u32>,
    pub table_targets: Vec<f64>,
    /// Strings in constant data that code points at, not among the C strings the page already has, by address.
    pub strings: Vec<StringRef>,
}

struct Table {
    start: i64,
    length: i64,
    targets: Vec<i64>,
}

impl Arm32Pass {
    /// Settles which bytes are A32, T32 and data, and readies the pass.
    pub fn new(image: Image, input: Arm32Input) -> Arm32Pass {
        let mut code: Vec<usize> = (0..image.sections.len()).filter(|&k| image.sections[k].code && image.sections[k].size >= 2 && image.sections[k].offset != 0).collect();
        code.sort_by_key(|&k| image.sections[k].addr);
        let mut pass = Arm32Pass {
            image,
            code,
            mapped: false,
            layout: Layout::default(),
            symbols: input.symbols.iter().copied().collect(),
            slots: input.slots.iter().copied().collect(),
            strings: input.strings.iter().copied().collect(),
            objc: input.objc.iter().copied().collect(),
            relative: input.relative.iter().copied().collect(),
            mnemonic_ids: Vec::new(),
            flags: Vec::new(),
            mnemonics: Vec::new(),
            counts: Vec::new(),
            ids: FxHashMap::default(),
            printed: FxHashMap::default(),
            callers: RefBuilder::default(),
            data_refs: RefBuilder::default(),
            retracted: Vec::new(),
            slot_callers: RefBuilder::default(),
            slot_calls: Vec::new(),
            address_at: FxHashMap::default(),
            tables: Vec::new(),
            label_targets: Vec::new(),
            targets: Vec::new(),
            at: 0,
            range_end: 0,
            value: [f64::NAN; 16],
            set_at: [-1; 16],
            is_address: [false; 16],
            slot_in: [-1.0; 16],
            slot_at: [-1; 16],
        };
        let file_marks: Vec<Mark> = input.file_marks.iter().copied().filter(|m| pass.in_code(m.addr)).collect();
        pass.mapped = !file_marks.is_empty();
        let mut data: FxHashMap<i64, i64> = FxHashMap::default();
        if pass.mapped {
            pass.layout = pass.lay_out(&file_marks, &data, input.fallback);
        } else {
            // Insertion order kept (a Map in the TypeScript), each address once.
            let mut known: FxHashMap<i64, Set> = FxHashMap::default();
            for m in &input.known {
                known.insert(m.addr, m.set);
            }
            // Functions the unwind tables list but no symbol names (static ones, often reached only through
            // a pointer) get the set their first instructions look like.
            for &addr in &input.function_starts {
                if pass.in_code(addr) && !known.contains_key(&addr) {
                    let set = pass.sniff(addr);
                    known.insert(addr, set);
                }
            }
            let spans = input.spans;
            let owned = |addr: i64| -> bool {
                let (mut lo, mut hi) = (0i64, spans.len() as i64 - 1);
                while lo <= hi {
                    let mid = (lo + hi) >> 1;
                    let (start, end) = spans[mid as usize];
                    if start <= addr {
                        if addr < end {
                            return true;
                        }
                        lo = mid + 1;
                    } else {
                        hi = mid - 1;
                    }
                }
                false
            };
            // Data the file marks among the instructions is data whatever the code says.
            let marked = |pass: &Arm32Pass, into: &mut FxHashMap<i64, i64>| {
                for &(addr, length) in &input.data_in_code {
                    if pass.in_code(addr) && length != 0 {
                        into.insert(addr, length);
                    }
                }
            };
            let sorted = |known: &FxHashMap<i64, Set>| -> Vec<Mark> {
                let mut v: Vec<Mark> = known.iter().map(|(&addr, &set)| Mark { addr, set }).collect();
                v.sort_by_key(|m| m.addr);
                v
            };
            marked(&pass, &mut data);
            let mut marks = sorted(&known);
            pass.layout = pass.lay_out(&marks, &data, input.fallback);
            // Each round starts the data afresh from the latest layout, so a literal that only a wrong
            // decoding saw does not outlive it; the instruction sets found at call targets stay. It is
            // over when no new call target turns up and the data hardly moves (a few words can flip
            // back and forth between two readings for ever).
            for round in 0..5 {
                let targets = known.len();
                let mut found: FxHashMap<i64, i64> = FxHashMap::default();
                let mut found_order: Vec<i64> = Vec::new();
                pass.discover(&owned, &mut found, &mut found_order, &mut known);
                let mut moved = 0usize;
                for addr in &found_order {
                    if data.get(addr) != found.get(addr) {
                        moved += 1;
                    }
                }
                for addr in data.keys() {
                    if !found.contains_key(addr) {
                        moved += 1;
                    }
                }
                data = found;
                marked(&pass, &mut data);
                if round > 0 && known.len() == targets && moved as f64 <= f64::max(8.0, found_order.len() as f64 / 1000.0) {
                    break;
                }
                marks = sorted(&known);
                pass.layout = pass.lay_out(&marks, &data, input.fallback);
            }
        }
        let total = pass.layout.addrs.len();
        pass.mnemonic_ids = vec![0; total];
        pass.flags = vec![0; total];
        pass
    }

    fn in_code(&self, addr: i64) -> bool {
        self.code.iter().any(|&k| {
            let s = &self.image.sections[k];
            addr >= s.addr && addr < s.addr + s.size
        })
    }

    pub fn total(&self) -> u32 {
        self.layout.addrs.len() as u32
    }

    pub fn done(&self) -> u32 {
        self.at
    }

    fn size_of(&self, index: usize) -> i64 {
        SIZE.get(self.layout.kinds[index] as usize).copied().unwrap_or(4) as i64
    }

    /// The instruction containing an address in code, or -1.
    pub fn index_of(&self, addr: i64) -> i64 {
        let addrs = &self.layout.addrs;
        let (mut lo, mut hi, mut found) = (0i64, addrs.len() as i64 - 1, -1i64);
        while lo <= hi {
            let mid = (lo + hi) >> 1;
            if (addrs[mid as usize] as i64) <= addr {
                found = mid;
                lo = mid + 1;
            } else {
                hi = mid - 1;
            }
        }
        if found < 0 || addr >= addrs[found as usize] as i64 + self.size_of(found as usize) {
            return -1;
        }
        found
    }

    fn decoded(layout: &Layout, k: usize) -> Insn {
        decode_at(layout.kinds[k], layout.words[k], layout.addrs[k] as i64, layout.its[k] as i32)
    }

    /// Cuts the code sections into instructions and data: `marks` (sorted) switch the instruction set,
    /// `data` holds the bytes known to be data (address → length) wherever the set is.
    fn lay_out(&self, marks: &[Mark], data: &FxHashMap<i64, i64>, fallback: Set) -> Layout {
        let mut out = Layout::default();
        let push = |out: &mut Layout, addr: i64, word: u32, k: u8, it: i32| {
            out.addrs.push(addr as u32);
            out.words.push(word);
            out.kinds.push(k);
            out.its.push(it as i8);
        };
        // The data, by address, walked with a cursor as the layout moves forward.
        let mut claims: Vec<(i64, i64)> = data.iter().map(|(&a, &l)| (a, l)).collect();
        claims.sort_by_key(|c| c.0);
        let mut c = 0usize;
        let mut m = 0usize;
        for &si in &self.code {
            let section = &self.image.sections[si];
            let first = out.addrs.len() as u32;
            let b = Bytes { bytes: &self.image.bytes, base: section.offset - section.addr };
            let end = section.addr + section.size;
            while m < marks.len() && marks[m].addr < section.addr {
                m += 1;
            }
            let mut set = fallback;
            let mut it: Vec<u8> = Vec::new();
            // Data from addr up to limit, in words where aligned.
            let data_unit = |out: &mut Layout, addr: i64, limit: i64| -> i64 {
                if addr % 4 == 0 && addr + 4 <= limit {
                    push(out, addr, b.u32(addr), kind::WORD, -1);
                    return 4;
                }
                if addr % 2 == 0 && addr + 2 <= limit {
                    push(out, addr, b.u16(addr), kind::SHORT, -1);
                    return 2;
                }
                push(out, addr, b.u8(addr), kind::BYTE, -1);
                1
            };
            let mut addr = section.addr;
            while addr < end {
                while m < marks.len() && marks[m].addr <= addr {
                    set = marks[m].set;
                    it.clear();
                    m += 1;
                }
                let limit = end.min(if m < marks.len() { marks[m].addr } else { end });
                let known = if set == Set::D {
                    0
                } else {
                    while c < claims.len() && claims[c].0 < addr {
                        c += 1;
                    }
                    if c < claims.len() && claims[c].0 == addr {
                        claims[c].1
                    } else {
                        0
                    }
                };
                if known != 0 {
                    let stop = limit.min(addr + known);
                    while addr < stop {
                        addr += data_unit(&mut out, addr, stop);
                    }
                    it.clear();
                    continue;
                }
                if set == Set::D {
                    addr += data_unit(&mut out, addr, limit);
                    continue;
                }
                // lld fills the gaps between functions with 0xd4: as A32 a nonsense ldrble, as T32 two bmi
                // in a row of which the second could never run.
                if addr % 4 == 0 && addr + 4 <= limit && b.u32(addr) == 0xd4d4d4d4 {
                    addr += data_unit(&mut out, addr, limit);
                    it.clear();
                    continue;
                }
                if set == Set::A {
                    if addr % 4 != 0 || addr + 4 > limit {
                        addr += data_unit(&mut out, addr, limit);
                        continue;
                    }
                    push(&mut out, addr, b.u32(addr), kind::A32, -1);
                    addr += 4;
                    continue;
                }
                if addr % 2 != 0 || addr + 2 > limit {
                    addr += data_unit(&mut out, addr, limit);
                    continue;
                }
                let hw1 = b.u16(addr);
                let cond: i32 = it.first().map_or(-1, |c| *c as i32);
                let wide = is_wide(hw1);
                let claimed = |at: i64| -> bool {
                    let mut k = c;
                    while k < claims.len() && claims[k].0 <= at {
                        if claims[k].0 == at {
                            return true;
                        }
                        k += 1;
                    }
                    false
                };
                if wide && (addr + 4 > limit || claimed(addr + 2)) {
                    addr += data_unit(&mut out, addr, limit.min(addr + 2));
                    continue;
                }
                let word = if wide { (hw1 << 16) | b.u16(addr + 2) } else { hw1 };
                push(&mut out, addr, word, if wide { kind::T32 } else { kind::T16 }, cond);
                // An IT instruction makes the next one to four conditional. Only inside a block, or at an
                // IT, is the instruction decoded here: whether it takes a slot depends on what it is.
                if !it.is_empty() || (hw1 & 0xff00) == 0xbf00 {
                    let insn = decode_thumb(hw1, if wide { word & 0xffff } else { 0 }, addr, cond);
                    it = it_after(&it, &insn, word).to_vec();
                }
                addr += if wide { 4 } else { 2 };
            }
            out.ranges.push(Range { section: si, first, count: out.addrs.len() as u32 - first });
        }
        out
    }

    /// What decoding a layout teaches about a stripped library: the literal-pool words and branch
    /// tables (data), and the instruction set at every call target.
    fn discover(&self, owned: &dyn Fn(i64) -> bool, data: &mut FxHashMap<i64, i64>, order: &mut Vec<i64>, marks: &mut FxHashMap<i64, Set>) {
        let layout = &self.layout;
        let n = layout.addrs.len();
        let set_data = |data: &mut FxHashMap<i64, i64>, order: &mut Vec<i64>, addr: i64, length: i64| {
            if data.insert(addr, length).is_none() {
                order.push(addr);
            }
        };
        for i in 0..n {
            let k = layout.kinds[i];
            if k >= kind::WORD || !may_name(k, layout.words[i]) {
                continue;
            }
            let insn = Self::decoded(layout, i);
            if insn.f & f::UNKNOWN != 0 {
                continue;
            }
            let Some(target) = insn.target else { continue };
            if insn.f & f::LOAD != 0 {
                // A literal: the bytes it reads are data, not code.
                if self.in_code(target) && !data.contains_key(&target) {
                    set_data(data, order, target, (if insn.bytes == 0 { 4 } else { insn.bytes as i64 }).max(4));
                }
                continue;
            }
            // adr (or A32 `add rX, pc, #…`) and a load through the register right after: constants
            // kept in the code, often NEON ones (`adr r1, …` / `vld1.32 {d16, d17}, [r1]`).
            if insn.f & (f::BRANCH | f::CALL) == 0 && self.in_code(target) {
                if let Some(Op::Reg { r: base, .. }) = insn.ops.first() {
                    let mut k2 = i + 1;
                    while k2 <= i + 4 && k2 < n && layout.kinds[k2] < kind::WORD {
                        let next = Self::decoded(layout, k2);
                        if let Some(Op::Mem(mm)) = first_mem(&next) {
                            let (mb, off, index, mode) = (&mm.base, &mm.off, &mm.index, &mm.mode);
                            if next.f & f::LOAD != 0 && mb.as_str() == base.as_str() && index.is_none() && *mode != MemMode::Pre {
                                let count = match first_list(&next) {
                                    Some(Op::List(list)) => list.len() as i64,
                                    _ => {
                                        if next.ops.iter().filter(|op| matches!(op, Op::Reg { .. })).count() > 2 {
                                            2
                                        } else {
                                            1
                                        }
                                    }
                                };
                                let at = target + if *mode == MemMode::Off { off.unwrap_or(0) } else { 0 };
                                if self.in_code(at) && !data.contains_key(&at) {
                                    let bytes = if next.bytes == 0 { 4 } else { next.bytes as i64 };
                                    set_data(data, order, at, (bytes * count).max(4));
                                }
                                break;
                            }
                        }
                        if let Some(Op::Reg { r, .. }) = next.ops.first() {
                            if r.as_str() == base.as_str() {
                                break;
                            }
                        }
                        k2 += 1;
                    }
                    continue;
                }
            }
            if insn.f & f::CALL != 0 {
                if let Some(thumb) = insn.thumb {
                    if self.in_code(target) && !owned(target) {
                        let set = if thumb { Set::T } else { Set::A };
                        if (set == Set::A && target % 4 != 0) || target % 2 != 0 {
                            continue;
                        }
                        // A call decoded from bytes that are not code (or code read in the wrong set) names a
                        // random place: its claim stands only if the code around the call reads cleanly and the
                        // bytes at the target look like that instruction set.
                        if !marks.contains_key(&target) && self.clean_around(i) && !self.clean_otherwise(target, set) && self.sniff(target) == set {
                            marks.insert(target, set);
                        }
                    }
                }
            }
        }
        // Switch tables: tbb/tbh in T32, an indexed `add pc` or `ldr pc` in A32.
        for i in 0..n {
            let w = layout.words[i];
            let table = if layout.kinds[i] == kind::T32 && (w & 0xfff0ffe0) == 0xe8d0f000 {
                self.branch_table(layout, i)
            } else if layout.kinds[i] == kind::A32 && ((w & 0x0ffffff0) == 0x079ff100 || (w & 0x0ff0fff0) == 0x0080f000) {
                self.arm_table(layout, i)
            } else {
                None
            };
            if let Some(t) = table {
                if data.insert(t.start, t.length).is_none() {
                    order.push(t.start);
                }
            }
        }
    }

    /// No undecodable instruction among the three before and the three after an instruction.
    fn clean_around(&self, i: usize) -> bool {
        let layout = &self.layout;
        let n = layout.addrs.len();
        for k in i.saturating_sub(3)..=(i + 3) {
            if k >= n {
                break;
            }
            if k == i || layout.kinds[k] >= kind::WORD {
                continue;
            }
            if Self::decoded(layout, k).f & f::UNKNOWN != 0 {
                return false;
            }
        }
        true
    }

    /// Whether the code at an address already reads cleanly in the other instruction set (or is
    /// data): a call that says otherwise is the one that is wrong.
    fn clean_otherwise(&self, addr: i64, set: Set) -> bool {
        let addrs = &self.layout.addrs;
        let (mut lo, mut hi, mut at) = (0i64, addrs.len() as i64 - 1, -1i64);
        while lo <= hi {
            let mid = (lo + hi) >> 1;
            if (addrs[mid as usize] as i64) <= addr {
                at = mid;
                lo = mid + 1;
            } else {
                hi = mid - 1;
            }
        }
        if at < 0 {
            return false;
        }
        let k = self.layout.kinds[at as usize];
        let now = if k == kind::A32 {
            Set::A
        } else if k == kind::T16 || k == kind::T32 {
            Set::T
        } else {
            Set::D
        };
        now != set && now != Set::D && self.clean_around(at as usize)
    }

    /// An A32 switch: `adr rT, table` / `ldr rO, [rT, rI, lsl #2]` / `add pc, rT, rO` with offsets
    /// from the table, or `ldrls pc, [pc, rI, lsl #2]` / `b default` with addresses after it. The
    /// `cmp rI, #n` that bounds the index says the table has n + 1 entries; without one, as with tbb,
    /// the table ends where the nearest place it sends execution begins.
    fn arm_table(&self, layout: &Layout, i: usize) -> Option<Table> {
        let (addrs, words, kinds) = (&layout.addrs, &layout.words, &layout.kinds);
        let word = words[i];
        let via_load = (word & 0x0ffffff0) == 0x079ff100;
        if !via_load && (word & 0x0ff0fff0) != 0x0080f000 {
            return None;
        }
        let mut base: i64 = if via_load { addrs[i] as i64 + 8 } else { -1 };
        // The index register: of the ldr pc itself, or of the `ldr rO, [rT, rI, lsl #2]` before the add.
        let mut index: i64 = if via_load { (word & 0xf) as i64 } else { -1 };
        let mut count = f64::INFINITY;
        let mut k = i as i64 - 1;
        while k >= 0 && k >= i as i64 - 8 && kinds[k as usize] == kind::A32 {
            let w = words[k as usize];
            if !via_load && base < 0 && (w & 0x0fff0000) == 0x028f0000 && ((w >> 12) & 0xf) == ((word >> 16) & 0xf) {
                base = addrs[k as usize] as i64 + 8 + arm_imm(w) as i64;
            }
            if index < 0 && (w & 0x0ff00ff0) == 0x07900100 {
                index = (w & 0xf) as i64;
            }
            // The bound check of that index, when there is one, says how many entries there are.
            if index >= 0 && count == f64::INFINITY && (w & 0x0ff0f000) == 0x03500000 && ((w >> 16) & 0xf) as i64 == index {
                count = arm_imm(w) as f64 + 1.0;
            }
            k -= 1;
        }
        if base < 0 {
            return None;
        }
        let bytes = self.image.bytes_at(base, 16384)?;
        let mut targets = Vec::new();
        let mut nearest = base + bytes.len() as i64;
        let mut p = 0usize;
        while base + (p as i64) < nearest && p + 4 <= bytes.len() && (targets.len() as f64) < count {
            let entry = u32::from_le_bytes([bytes[p], bytes[p + 1], bytes[p + 2], bytes[p + 3]]);
            let target = if via_load { entry as i64 } else { ((base + entry as i64) as u64 & 0xffff_ffff) as i64 };
            targets.push(target);
            if target > base {
                nearest = nearest.min(target);
            }
            p += 4;
        }
        if targets.is_empty() {
            None
        } else {
            Some(Table { start: base, length: p as i64, targets })
        }
    }

    /// The table of a `tbb`/`tbh`: offsets in halfwords from the instruction's pc + 4. Usually it
    /// follows the instruction (`tbb [pc, rX]`) and ends where the nearest place it sends execution
    /// begins. When it sits elsewhere — `adr rT, table` / `tbb [rT, rX]` — the `cmp rX, #n` before
    /// says it has n + 1 entries.
    fn branch_table(&self, layout: &Layout, i: usize) -> Option<Table> {
        let word = layout.words[i];
        if layout.kinds[i] != kind::T32 || (word & 0xfff0ffe0) != 0xe8d0f000 {
            return None;
        }
        let half = word & 0x10 != 0;
        let step = if half { 2usize } else { 1 };
        let pc = layout.addrs[i] as i64;
        let rn = (word >> 16) & 0xf;
        let entry_at = |bytes: &[u8], p: usize| -> i64 {
            if half {
                bytes[p] as i64 | ((bytes[p + 1] as i64) << 8)
            } else {
                bytes[p] as i64
            }
        };
        let mut targets = Vec::new();
        if rn == 15 {
            let start = pc + 4;
            let bytes = self.image.bytes_at(start, 2048)?;
            let mut nearest = start + bytes.len() as i64;
            let mut p = 0usize;
            while start + (p as i64) < nearest && p + step <= bytes.len() && targets.len() < 1024 {
                let target = start + entry_at(bytes, p) * 2;
                targets.push(target);
                if target > start {
                    nearest = nearest.min(target);
                }
                p += step;
            }
            return if targets.is_empty() { None } else { Some(Table { start, length: p as i64, targets }) };
        }
        let rm = word & 0xf;
        let (mut base, mut count) = (-1i64, -1f64);
        let mut k = i as i64 - 1;
        let base_name = format!("r{rn}");
        let index_name = format!("r{rm}");
        while k >= 0 && k >= i as i64 - 6 && (layout.kinds[k as usize] == kind::T16 || layout.kinds[k as usize] == kind::T32) && (base < 0 || count < 0.0) {
            let insn = Self::decoded(layout, k as usize);
            let dest = match insn.ops.first() {
                Some(Op::Reg { r, .. }) => r.as_str(),
                _ => "",
            };
            if let Some(target) = insn.target.filter(|_| base < 0 && insn.m.starts_with("adr") && dest == base_name) {
                base = target;
            }
            if count < 0.0 && insn.m.starts_with("cmp") && dest == index_name {
                if let Some(Op::Imm { v, .. }) = insn.ops.get(1) {
                    count = v + 1.0;
                }
            }
            k -= 1;
        }
        if base < 0 || count <= 0.0 || count > 1024.0 {
            return None;
        }
        let count = count as usize;
        let bytes = self.image.bytes_at(base, count * step)?;
        if bytes.len() < count * step {
            return None;
        }
        for e in 0..count {
            targets.push(pc + 4 + entry_at(bytes, e * step) * 2);
        }
        Some(Table { start: base, length: (count * step) as i64, targets })
    }

    /// A32 or T32, from the bytes alone. A prologue says it outright: push {…, lr} is b5xx in T16 and
    /// e92d 4xxx in T32, but e92d4xxx as an A32 word. Otherwise the first 32 bytes are read both ways
    /// and each reading is charged for what real code rarely has: an undecodable word in either; in
    /// A32, instructions that do not always run (most compiled A32 runs always); in T32, an
    /// unconditional 16-bit branch or a 0x0000 halfword mid-function — what A32 words read as T32 are
    /// full of. A start that is not word-aligned is T32.
    fn sniff(&self, addr: i64) -> Set {
        if addr % 4 != 0 {
            return Set::T;
        }
        let Some(bytes) = self.image.bytes_at(addr, 32) else { return Set::T };
        if bytes.len() < 4 {
            return Set::T;
        }
        let half = |p: usize| -> u32 { bytes[p] as u32 | ((bytes[p + 1] as u32) << 8) };
        let first = half(0);
        if (first & 0xff00) == 0xb500 || first == 0xe92d {
            return Set::T;
        }
        // e92d in the upper half: an A32 push whose register list (the lower half) has lr — or a T32
        // push.w after one 16-bit instruction (`sub sp, #…` opens a variadic function).
        if half(2) == 0xe92d {
            return if first & 0x4000 != 0 { Set::A } else { Set::T };
        }
        let mut a = 0;
        let mut p = 0;
        while p + 4 <= bytes.len() {
            let word = half(p) | (half(p + 2) << 16);
            if decode_arm(word, addr + p as i64).f & f::UNKNOWN != 0 {
                a += 3;
            } else if word >> 28 < 0xe {
                a += 1;
            }
            p += 4;
        }
        let mut t = 0;
        let mut p = 0;
        while p + 2 <= bytes.len() {
            let hw = half(p);
            let wide = is_wide(hw);
            if wide && p + 4 > bytes.len() {
                break;
            }
            if decode_thumb(hw, if wide { half(p + 2) } else { 0 }, addr + p as i64, -1).f & f::UNKNOWN != 0 {
                t += 3;
            } else if !wide && (hw == 0 || (hw & 0xf800) == 0xe000) {
                t += 2;
            }
            p += if wide { 4 } else { 2 };
        }
        if a < t {
            Set::A
        } else {
            Set::T
        }
    }

    /// What is at a data address, as far as naming it goes: an Objective-C reference, a string, an import slot, a symbol.
    fn names_data(&self, addr: i64) -> bool {
        self.objc.contains(&addr) || self.strings.contains(&addr) || self.image.text_at(addr, None).is_some() || self.slots.contains(&addr) || self.symbols.contains(&addr)
    }

    fn intern(&mut self, m: &str) -> u16 {
        if let Some(&id) = self.printed.get(m) {
            return id;
        }
        // Statistics count the mnemonic as printed, without the .w/.n width qualifier.
        let name = width_free(m);
        let id = match self.ids.get(&name) {
            Some(&id) => id,
            None => {
                let id = self.mnemonics.len() as u16;
                self.ids.insert(name.clone(), id);
                self.mnemonics.push(name);
                self.counts.push(0);
                id
            }
        };
        self.printed.insert(m.to_string(), id);
        id
    }

    fn forget(&mut self) {
        self.value = [f64::NAN; 16];
        self.is_address = [false; 16];
    }

    fn reference(&mut self, addr: i64, i: u32) {
        self.data_refs.add(addr, i);
    }

    /// Decodes up to `budget` instructions more; true once the pass (and what follows it) is over.
    pub fn step(&mut self, budget: u32) -> bool {
        let total = self.total();
        let mut left = budget;
        while self.at < total {
            if left == 0 {
                return false;
            }
            left -= 1;
            let i = self.at;
            self.visit(i);
            self.at += 1;
        }
        true
    }

    fn visit(&mut self, i: u32) {
        let total = self.total();
        let iu = i as usize;
        if i >= self.range_end {
            self.forget();
            self.slot_in = [-1.0; 16];
            self.range_end = match self.layout.ranges.iter().find(|r| i >= r.first && i < r.first + r.count) {
                Some(r) => r.first + r.count,
                None => total,
            };
        }
        let k = self.layout.kinds[iu];
        let pc = self.layout.addrs[iu] as i64;
        let word = self.layout.words[iu];
        let insn = if k >= kind::WORD { None } else { Some(decode_at(k, word, pc, self.layout.its[iu] as i32)) };
        let id = match &insn {
            Some(insn) => self.intern(&insn.m),
            None => self.intern(DATA_NAMES[k as usize]),
        };
        self.mnemonic_ids[iu] = id;
        self.counts[id as usize] += 1;
        let Some(insn) = insn else { return };
        let fl = insn.f;
        if fl & f::UNKNOWN != 0 {
            self.flags[iu] |= iflag::UNKNOWN;
            return;
        }
        if fl & (f::CALL | f::BRANCH) != 0 {
            if let Some(t) = insn.target {
                self.targets.push((i, t));
            }
        }
        if fl & f::CALL != 0 {
            self.flags[iu] |= iflag::CALL;
            if let Some(t) = insn.target {
                self.callers.add(t, i);
            }
        } else if fl & f::BRANCH != 0 {
            self.flags[iu] |= iflag::BRANCH;
            // `ldr pc, [pc, #…]` names its literal, not where it goes.
            if let Some(t) = insn.target {
                if fl & f::INDIRECT == 0 {
                    self.label_targets.push(t);
                }
            }
        }
        if (k == kind::T32 || k == kind::A32) && fl & f::BRANCH != 0 {
            let table = if k == kind::T32 { self.branch_table(&self.layout, iu) } else { self.arm_table(&self.layout, iu) };
            if let Some(table) = table {
                self.label_targets.extend_from_slice(&table.targets);
                self.tables.push((i, table.targets));
                self.flags[iu] |= iflag::BRANCH;
            }
        }

        // PC-relative addresses. A literal load gives a register a value: an address already (an
        // absolute pointer the loader relocates), or an offset that `add rX, pc` turns into one.
        // movw/movt build the same offsets in two halves.
        let dest = reg_of(insn.ops.first());
        if let Some(target) = insn.target.filter(|_| fl & f::LOAD != 0 && !insn.ops.iter().any(|op| matches!(op, Op::List(_)))) {
            let literal = if insn.bytes == 4 || insn.bytes == 0 { self.image.value_at(target, 4, false) } else { None };
            let named = match insn.ops.first() {
                Some(Op::Reg { r, .. }) => r.starts_with('r') || r.starts_with("sp") || r.starts_with("lr"),
                _ => false,
            };
            if let (true, Some(literal), true) = ((0..15).contains(&dest), literal, named) {
                let d = dest as usize;
                self.value[d] = literal;
                self.set_at[d] = i as i64;
                // In a Windows program a literal is already an address (relocated by the loader), not an offset from pc.
                self.is_address[d] = self.image.format == Format::Pe && self.image.section_of(literal as i64).is_some();
                let pointed = self.relative.get(&target).copied().unwrap_or(literal as i64);
                if self.image.section_of(pointed).is_some() && !self.in_code(pointed) && (self.strings.contains(&pointed) || self.names_data(pointed)) {
                    self.address_at.insert(i, pointed);
                    self.reference(pointed, i);
                }
            }
            return;
        }
        // adr, and the `add`/`sub rX, pc, #imm` A32 prints instead: an address made from pc.
        if let Some(target) = insn.target {
            if fl & (f::BRANCH | f::CALL) == 0 {
                self.address_at.insert(i, target);
                self.reference(target, i);
                if dest >= 0 {
                    let d = dest as usize;
                    self.value[d] = target as f64;
                    self.set_at[d] = i as i64;
                    self.is_address[d] = true;
                }
                return;
            }
        }
        let (mut added, mut source) = (-1i32, -1i32);
        if k == kind::T16 && (word & 0xff78) == 0x4478 {
            added = ((word & 7) | ((word >> 4) & 8)) as i32;
            source = added;
        } else if k == kind::A32 && (word & 0x0fff0ff0) == 0x008f0000 {
            added = ((word >> 12) & 0xf) as i32;
            source = (word & 0xf) as i32;
        } else if k == kind::A32 && (word & 0x0ff00fff) == 0x0080000f {
            added = ((word >> 12) & 0xf) as i32;
            source = ((word >> 16) & 0xf) as i32;
        }
        if added >= 0 {
            let (a, s) = (added as usize, source as usize);
            let v = self.value[s];
            if !v.is_nan() && !self.is_address[s] && i as i64 - self.set_at[s] <= 32 {
                let addr = js_u32(v + pc as f64 + if k == kind::A32 { 8.0 } else { 4.0 });
                self.address_at.insert(i, addr);
                // The load (or movt) that brought the offset names the same address.
                self.address_at.insert(self.set_at[s] as u32, addr);
                self.reference(addr, i);
                self.value[a] = addr as f64;
                self.set_at[a] = i as i64;
                self.is_address[a] = true;
            } else {
                self.value[a] = f64::NAN;
            }
            return;
        }
        // An address plus an offset a literal brought (glibc's start code adds the GOT's offset to
        // an address made by adr): the sum is the address, and the literal, which may happen to
        // fall inside a section, was no address at all.
        if is_add(&insn.m) && insn.ops.len() >= 2 && insn.ops.iter().all(|op| matches!(op, Op::Reg { .. })) {
            let (x, y) = if insn.ops.len() == 3 { (reg_of(insn.ops.get(1)), reg_of(insn.ops.get(2))) } else { (dest, reg_of(insn.ops.get(1))) };
            let (address, offset) = if x >= 0 && y >= 0 && x < 15 && y < 15 {
                let (xa, ya) = (self.is_address[x as usize], self.is_address[y as usize]);
                if xa && !ya {
                    (x, y)
                } else if ya && !xa {
                    (y, x)
                } else {
                    (-1, -1)
                }
            } else {
                (-1, -1)
            };
            if address >= 0 {
                let (a, o) = (address as usize, offset as usize);
                let sum = self.value[a] + self.value[o];
                if !sum.is_nan() {
                    let addr = js_u32(sum);
                    if i as i64 - self.set_at[a] <= 32 && i as i64 - self.set_at[o] <= 32 && self.image.section_of(addr).is_some() {
                        let at = self.set_at[o] as u32;
                        if self.address_at.get(&at).map(|&v| v as f64) == Some(self.value[o]) {
                            self.address_at.remove(&at);
                            // Its reference goes too: every one from that instruction to that address.
                            self.retracted.push((self.value[o] as i64, at, self.data_refs.len()));
                        }
                        self.address_at.insert(i, addr);
                        self.reference(addr, i);
                        if dest >= 0 {
                            let d = dest as usize;
                            self.value[d] = addr as f64;
                            self.set_at[d] = i as i64;
                            self.is_address[d] = true;
                        }
                        return;
                    }
                }
            }
        }
        if insn.m.starts_with("movw") && dest >= 0 {
            if let Some(Op::Imm { v, .. }) = insn.ops.get(1) {
                let d = dest as usize;
                self.value[d] = (js_i32(*v) & 0xffff) as f64;
                self.set_at[d] = i as i64;
                self.is_address[d] = false;
                return;
            }
        }
        if insn.m.starts_with("movt") && dest >= 0 {
            if let Some(Op::Imm { v, .. }) = insn.ops.get(1) {
                let d = dest as usize;
                let low = self.value[d];
                self.value[d] = if low.is_nan() { f64::NAN } else { (((js_i32(low) & 0xffff) | ((js_i32(*v) & 0xffff) << 16)) as u32) as f64 };
                // A Windows program is not position-independent: the two halves are the address itself.
                if self.image.format == Format::Pe && !self.value[d].is_nan() && self.image.section_of(self.value[d] as i64).is_some() {
                    let addr = self.value[d] as i64;
                    self.address_at.insert(i, addr);
                    if !self.in_code(addr) {
                        self.reference(addr, i);
                    }
                    self.is_address[d] = true;
                }
                return;
            }
        }
        // A load through a register holding an address: a GOT slot, a global.
        let mut loaded_slot = -1f64;
        if fl & f::LOAD != 0 {
            if let Some(Op::Mem(mm)) = first_mem(&insn) {
                let (base, off) = (&mm.base, &mm.off);
                if mm.index.is_none() && mm.mode == MemMode::Off {
                    let b = reg_number(base);
                    if b >= 0 && self.is_address[b as usize] && !self.value[b as usize].is_nan() && i as i64 - self.set_at[b as usize] <= 32 {
                        let addr = js_u32(self.value[b as usize] + off.unwrap_or(0) as f64);
                        self.address_at.insert(i, addr);
                        self.reference(addr, i);
                        if self.image.format == Format::Pe && dest >= 0 && self.slots.contains(&addr) {
                            loaded_slot = addr as f64;
                        }
                    }
                }
            }
        }
        // A call or jump through a register that holds an import (`blx r3`, `bx r12`).
        if fl & (f::BRANCH | f::CALL) != 0 && insn.target.is_none() {
            if let Some(Op::Reg { r, .. }) = insn.ops.first() {
                let reg = reg_number(r);
                if reg >= 0 && self.slot_in[reg as usize] >= 0.0 && i as i64 - self.slot_at[reg as usize] <= 16 {
                    let slot = self.slot_in[reg as usize] as i64;
                    self.slot_calls.push((i, slot));
                    self.slot_callers.add(slot, i);
                }
            }
        }
        // What the instruction writes is no longer known.
        if dest >= 0 && fl & (f::BRANCH | f::CALL) == 0 {
            self.slot_in[dest as usize] = -1.0;
        }
        if loaded_slot >= 0.0 {
            self.slot_in[dest as usize] = loaded_slot;
            self.slot_at[dest as usize] = i as i64;
        }
        if fl & (f::BRANCH | f::CALL) != 0 {
            self.forget();
            // A call keeps r4–r11; a branch may land anywhere.
            if fl & f::CALL != 0 {
                for r in [0, 1, 2, 3, 12, 14] {
                    self.slot_in[r] = -1.0;
                }
            } else {
                self.slot_in = [-1.0; 16];
            }
        } else {
            if let Some(Op::List(list)) = first_list(&insn) {
                if fl & f::LOAD != 0 {
                    for r in list.regs() {
                        let n = reg_number(&r);
                        self.value[if n >= 0 { n as usize } else { 15 }] = f64::NAN;
                    }
                }
            }
            if dest >= 0 && fl & f::STORE == 0 {
                self.value[dest as usize] = f64::NAN;
            }
            if dest >= 0 {
                if let Some(Op::Reg { wb: true, .. }) = insn.ops.first() {
                    self.value[dest as usize] = f64::NAN;
                }
            }
        }
    }

    /// After the pass: the labels, and the references handed over.
    pub fn finish(&mut self) -> Arm32Refs {
        for k in 0..self.label_targets.len() {
            let target = self.label_targets[k];
            let index = self.index_of(target);
            if index >= 0 && self.layout.addrs[index as usize] as i64 == target {
                self.flags[index as usize] |= iflag::LABEL;
            }
        }
        self.label_targets = Vec::new();
        let mut table_index = Vec::with_capacity(self.tables.len());
        let mut table_starts = Vec::with_capacity(self.tables.len() + 1);
        let mut table_targets = Vec::new();
        for (i, targets) in &self.tables {
            table_index.push(*i);
            table_starts.push(table_targets.len() as u32);
            table_targets.extend(targets.iter().map(|&t| t as f64));
        }
        table_starts.push(table_targets.len() as u32);
        let retracted = core::mem::take(&mut self.retracted);
        let data_refs = core::mem::take(&mut self.data_refs).build_without(&retracted);
        // Strings in constant data that code points at.
        let strings = data_refs.keys.iter().map(|&k| k as i64).filter(|a| !self.strings.contains(a)).filter_map(|a| self.image.text_at(a, None)).collect();
        Arm32Refs {
            strings,
            callers: core::mem::take(&mut self.callers).build(),
            data_refs,
            slot_callers: core::mem::take(&mut self.slot_callers).build(),
            table_index,
            table_starts,
            table_targets,
        }
    }

    /// The addresses instructions name, in index order.
    pub fn address_pairs(&self) -> Vec<(u32, i64)> {
        let mut v: Vec<(u32, i64)> = self.address_at.iter().map(|(&i, &a)| (i, a)).collect();
        v.sort_unstable();
        v
    }
}

/// `m.replace(/\.[wn]$/, '').replace(/\.[wn]\./, '.')`: a mnemonic without its width qualifier.
fn width_free(m: &str) -> String {
    let mut s = m.to_string();
    if s.ends_with(".w") || s.ends_with(".n") {
        s.truncate(s.len() - 2);
    }
    // The first `.w.` or `.n.`, whichever comes first, as one regular expression finds it.
    let at = [s.find(".w."), s.find(".n.")].into_iter().flatten().min();
    if let Some(at) = at {
        s.replace_range(at..at + 3, ".");
    }
    s
}

/// `^adds?(\.w)?$`
fn is_add(m: &str) -> bool {
    matches!(m, "add" | "adds" | "add.w" | "adds.w")
}

/// JavaScript's `v >>> 0` as an address.
#[inline]
fn js_u32(v: f64) -> i64 {
    if !v.is_finite() {
        return 0;
    }
    (v.trunc() as i64 as u64 & 0xffff_ffff) as i64
}

/// JavaScript's ToInt32, for `v & 0xffff` and the like.
#[inline]
fn js_i32(v: f64) -> i64 {
    if !v.is_finite() {
        return 0;
    }
    (v.trunc() as i64 as u64 & 0xffff_ffff) as u32 as i32 as i64
}

/// Whether an instruction can teach discovery anything — a call, a load from pc, a write to pc —
/// judged from its bits so the rest is never decoded: T16 literal loads; T32 branches with link and
/// anything with base register pc; A32 branches, and anything reading or writing pc.
fn may_name(k: u8, word: u32) -> bool {
    if k == kind::T16 {
        return (word & 0xf800) == 0x4800 || (word & 0xf800) == 0xa000;
    }
    if k == kind::T32 {
        return (word & 0xf8000000) == 0xf0000000 || ((word >> 16) & 0xf) == 0xf;
    }
    ((word >> 25) & 7) == 5 || ((word >> 16) & 0xf) == 15 || ((word >> 12) & 0xf) == 15
}
