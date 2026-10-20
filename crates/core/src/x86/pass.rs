//! The pass over an x86 program — x86-64 or i386 code in an ELF file (Linux,
//! Android), a Mach-O slice or a PE file: the statistics, labels, call and data
//! references and switch tables, for instructions of one to fifteen bytes.
//!
//! The code is cut into instructions as llvm-objdump cuts it: a linear sweep
//! through each code section that starts afresh wherever a function is known
//! to begin (a symbol, an export, the unwind table, the entry point), so the
//! listing lines up with LLVM's. A call into the middle of what the sweep took
//! for one instruction adds a start there, and the section is swept again.
//!
//! What the instructions point at is read from their operands: x86-64 code
//! names data relative to rip; i386 code that is position-independent keeps the
//! address of its GOT in a register it got from a call (`call
//! __x86.get_pc_thunk.bx` / `add ebx, …`), which is followed; code that is not
//! uses absolute addresses. `jmp` through a table of offsets (a switch) gets its
//! cases.
//!
//! Per instruction only its offset, its length, a mnemonic number and a few
//! flag bits are kept. What needs names — functions, stubs, the entry point —
//! is the job of the code around it (src/core/x86/program.ts).

use super::decode::{decode_x86, sem, ty, McOp, X86Decoded};
use super::hla::{fuse_x86, is_x86_consumer, is_x86_setter, Bare, X86Insn};
use super::print::{mnemonic_x86, print_x86};
use crate::arm64::types::f;
use crate::disassembly::iflag;
use crate::image::{Format, Image, StringRef};
use crate::refs::{FxHashMap, FxHashSet, RefBuilder, RefIndex};

/// kinds: 0 an instruction; data entries by size.
pub const DATA_NAMES: [&str; 5] = ["", ".byte", ".short", ".long", ".quad"];
const DATA_SIZES: [u32; 5] = [0, 1, 2, 4, 8];

fn data_kind(size: u32) -> u8 {
    match size {
        1 => 1,
        2 => 2,
        4 => 3,
        _ => 4,
    }
}

/// Bytes known to be data among the instructions: a switch table, an entry of LC_DATA_IN_CODE.
#[derive(Clone, Copy, Debug)]
pub struct DataRegion {
    pub addr: i64,
    pub length: i64,
    /// The size of each entry: 1, 2, 4 or 8.
    pub entry: u32,
}

/// The run of instructions of one code section.
#[derive(Clone, Copy, Debug)]
pub struct Range {
    /// Its section, by index in the image's sections.
    pub section: usize,
    pub first: u32,
    pub count: u32,
}

/// A memory operand as the decoder gives it.
#[derive(Clone, Copy, Debug)]
pub struct X86Memory {
    /// Where its five MCInst operands start.
    pub at: usize,
    pub base: &'static str,
    pub scale: f64,
    pub index: &'static str,
    pub disp: f64,
    pub seg: &'static str,
}

#[inline]
fn op_str(op: Option<&McOp>) -> &'static str {
    match op {
        Some(McOp::Reg(r)) => r,
        _ => "",
    }
}

/// `Number(op)`: a register name is no number (NaN, '' is 0); a 64-bit immediate its unsigned value.
#[inline]
fn op_num(op: Option<&McOp>) -> f64 {
    op.map_or(f64::NAN, McOp::number)
}

fn is_memory_type(t: u8) -> bool {
    t == ty::M || t == ty::MSIB || t == ty::MVSIBX || t == ty::MVSIBY || t == ty::MVSIBZ
}

/// The first memory operand of an instruction.
pub fn memory_of(d: &X86Decoded) -> Option<X86Memory> {
    let types = d.types;
    let ops = d.ops;
    for k in 0..types.len() {
        if !is_memory_type(types[k]) {
            continue;
        }
        return Some(X86Memory {
            at: k,
            base: op_str(ops.get(k)),
            scale: op_num(ops.get(k + 1)),
            index: op_str(ops.get(k + 2)),
            disp: op_num(ops.get(k + 3)),
            seg: op_str(ops.get(k + 4)),
        });
    }
    None
}

/// Where a branch or call with a relative target goes.
pub fn target_of(d: &X86Decoded) -> Option<i64> {
    let types = d.types;
    for k in 0..types.len() {
        if types[k] != ty::REL {
            continue;
        }
        let target = d.addr as f64 + d.length as f64 + op_num(d.ops.get(k));
        return Some(if d.mode == 32 { u32_of(target) as i64 } else { target as i64 });
    }
    None
}

/// JavaScript's `v >>> 0`.
#[inline]
fn u32_of(v: f64) -> u32 {
    if !v.is_finite() {
        return 0;
    }
    (v.trunc() as i64 as u64 & 0xffff_ffff) as u32
}

/// The address a memory operand names on its own: rip-relative, or absolute; an absolute moffs.
pub fn fixed_address_of(d: &X86Decoded, absolute: bool) -> Option<i64> {
    if let Some(mem) = memory_of(d) {
        let next = d.addr as f64 + d.length as f64;
        if mem.base == "rip" {
            return Some((next + mem.disp) as i64);
        }
        if mem.base == "eip" {
            return Some(u32_of(next + mem.disp) as i64);
        }
        if absolute && mem.base.is_empty() && mem.index.is_empty() && mem.seg.is_empty() {
            return Some(if d.mode == 32 { u32_of(mem.disp) as i64 } else { mem.disp as i64 });
        }
        return None;
    }
    if absolute {
        let (types, ops) = (d.types, d.ops);
        for k in 0..types.len() {
            if types[k] == ty::MOFFS && !matches!(ops.get(k), Some(McOp::Reg(_))) {
                return Some(op_num(ops.get(k)) as i64);
            }
        }
    }
    None
}

/// F bits from the analysis bits of the tables.
pub fn flags_of(d: &X86Decoded) -> u32 {
    if d.id == 0 {
        return f::UNKNOWN;
    }
    let s = sem(d.id);
    let mut out = 0;
    for (bit, flag) in [
        (sem::CALL, f::CALL),
        (sem::BRANCH, f::BRANCH),
        (sem::RET, f::RET),
        (sem::INDIRECT, f::INDIRECT),
        (sem::COND, f::COND),
        (sem::TRAP, f::TRAP),
        (sem::LOAD, f::LOAD),
        (sem::STORE, f::STORE),
        (sem::SETS_FLAGS, f::SETS_FLAGS),
        (sem::READS_FLAGS, f::READS_FLAGS),
    ] {
        if s & bit != 0 {
            out |= flag;
        }
    }
    out
}

/// An instruction as the HLA64 lifter and the page read it.
pub fn insn_of(d: &X86Decoded, absolute: bool) -> X86Insn {
    let printed = print_x86(d);
    X86Insn {
        prefix: printed.prefix.to_string(),
        m: printed.m.to_string(),
        ops: printed.ops.to_string(),
        addr: d.addr,
        length: d.length,
        f: flags_of(d),
        target: target_of(d),
        mem: fixed_address_of(d, absolute),
    }
}

/// The general registers by number, whatever their width: rax, eax, ax and al are 0 — as far as
/// the TypeScript's table went: the 64- and 32-bit names (r8…r31 and r8d…r31d).
fn gpr_name(r: &str) -> i32 {
    const R64: [&str; 8] = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"];
    const R32: [&str; 8] = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"];
    if let Some(i) = R64.iter().position(|x| *x == r) {
        return i as i32;
    }
    if let Some(i) = R32.iter().position(|x| *x == r) {
        return i as i32;
    }
    if let Some(rest) = r.strip_prefix('r') {
        let digits = rest.strip_suffix('d').unwrap_or(rest);
        if !digits.is_empty() && digits.bytes().all(|c| c.is_ascii_digit()) && !(digits.len() > 1 && digits.starts_with('0')) {
            if let Ok(n) = digits.parse::<i32>() {
                if (8..32).contains(&n) {
                    return n;
                }
            }
        }
    }
    -1
}

#[inline]
fn gpr(op: Option<&McOp>) -> i32 {
    match op {
        Some(McOp::Reg(r)) => gpr_name(r),
        _ => -1,
    }
}

fn is_gpr_type(t: u8) -> bool {
    t == ty::R8 || t == ty::R16 || t == ty::R32 || t == ty::R64 || t == ty::RV
}

/// What the analysis is given besides the image: what the file says.
pub struct X86Input {
    pub mode: u8,
    /// Whether addresses in immediates and displacements are absolute (code that is not position-independent).
    pub absolute: bool,
    /// Where functions start, for the sweep to start afresh.
    pub known: Vec<i64>,
    /// Data the file says is among the instructions (Mach-O's LC_DATA_IN_CODE).
    pub data: Vec<DataRegion>,
    /// Addresses that name something: symbols, import slots, C strings.
    pub symbols: Vec<i64>,
    pub slots: Vec<i64>,
    pub strings: Vec<i64>,
    /// i386 PLT stubs jump through [ebx + offset], ebx holding the address of .got.plt.
    pub got_plt: Option<i64>,
}

/// The layout of the code: each instruction's offset in its section, its length, whether it is data.
#[derive(Default)]
struct Layout {
    offs: Vec<u32>,
    lens: Vec<u8>,
    kinds: Vec<u8>,
    ranges: Vec<Range>,
}

pub struct X86Pass {
    pub image: Image,
    pub mode: u8,
    pub absolute: bool,
    /// The code sections, by index in the image, in address order.
    code: Vec<usize>,
    known: FxHashSet<i64>,
    data: Vec<DataRegion>,
    symbols: FxHashSet<i64>,
    slots: FxHashSet<i64>,
    strings: FxHashSet<i64>,
    got_plt: Option<i64>,

    pub ranges: Vec<Range>,
    pub offs: Vec<u32>,
    pub lens: Vec<u8>,
    pub kinds: Vec<u8>,
    pub mnemonic_ids: Vec<u16>,
    pub flags: Vec<u8>,
    pub mnemonics: Vec<String>,
    pub counts: Vec<u32>,
    ids: FxHashMap<String, u16>,
    data_ids: [i32; 5],

    callers: RefBuilder,
    data_refs: RefBuilder,
    slot_callers: RefBuilder,
    pub address_at: Vec<(u32, i64)>,
    pub code_at: Vec<(u32, i64)>,
    base_values: FxHashMap<u32, f64>,
    tables: Vec<(u32, Vec<i64>)>,
    label_targets: Vec<i64>,
    /// Instructions with a relative target (calls, jumps) and where they go.
    pub rel_targets: Vec<(u32, i64)>,

    // Where the pass is, between steps.
    at: u32,
    value: [f64; 32],
    range_end: u32,
    range: usize,
    /// Whether the current range is a PLT (its section's name says so).
    plt: bool,
}

/// What the pass hands over once it is done.
pub struct X86Refs {
    pub callers: RefIndex,
    pub data_refs: RefIndex,
    pub slot_callers: RefIndex,
    /// A jump through a table: the instructions (ascending), where each one's cases start, and the cases' addresses.
    pub table_index: Vec<u32>,
    pub table_starts: Vec<u32>,
    pub table_targets: Vec<f64>,
    /// Strings in constant data that code points at, not among the C strings the page already has, by address.
    pub strings: Vec<StringRef>,
}

impl X86Pass {
    /// Lays the code out (twice when calls land inside instructions or switch tables are found) and readies the pass.
    pub fn new(image: Image, input: X86Input) -> X86Pass {
        let mut code: Vec<usize> = (0..image.sections.len()).filter(|&k| image.sections[k].code && image.sections[k].size != 0 && image.sections[k].offset != 0).collect();
        code.sort_by_key(|&k| image.sections[k].addr);
        let mut pass = X86Pass {
            mode: input.mode,
            absolute: input.absolute,
            code,
            known: input.known.iter().copied().collect(),
            data: input.data,
            symbols: input.symbols.into_iter().collect(),
            slots: input.slots.into_iter().collect(),
            strings: input.strings.into_iter().collect(),
            got_plt: input.got_plt,
            image,
            ranges: Vec::new(),
            offs: Vec::new(),
            lens: Vec::new(),
            kinds: Vec::new(),
            mnemonic_ids: Vec::new(),
            flags: Vec::new(),
            mnemonics: Vec::new(),
            counts: Vec::new(),
            ids: FxHashMap::default(),
            data_ids: [-1; 5],
            callers: RefBuilder::default(),
            data_refs: RefBuilder::default(),
            slot_callers: RefBuilder::default(),
            address_at: Vec::new(),
            code_at: Vec::new(),
            base_values: FxHashMap::default(),
            tables: Vec::new(),
            label_targets: Vec::new(),
            rel_targets: Vec::new(),
            at: 0,
            value: [f64::NAN; 32],
            range_end: 0,
            range: 0,
            plt: false,
        };
        pass.data.sort_by_key(|d| d.addr);
        let layout = pass.lay_out(&pass.sorted_known(), &pass.data.clone(), false);
        pass.apply(layout.0);
        let (calls, jumps) = layout.1;
        // A call into what the sweep took for the middle of an instruction starts afresh there; a switch
        // table among the instructions is data. Once more over the code with both.
        let mut again = false;
        for target in calls {
            if pass.known.contains(&target) || !pass.in_code(target) {
                continue;
            }
            let at = pass.index_of(target);
            if at >= 0 && pass.addr_of(at as u32) != target {
                pass.known.insert(target);
                again = true;
            }
        }
        for index in jumps {
            let Some(found) = pass.switch_of(index) else { continue };
            if !pass.in_code(found.table) {
                continue;
            }
            pass.data.push(DataRegion { addr: found.table, length: found.targets.len() as i64 * found.entry as i64, entry: found.entry });
            again = true;
        }
        if again {
            let merged = merge_regions(&mut pass.data);
            let layout = pass.lay_out(&pass.sorted_known(), &merged, true);
            pass.apply(layout.0);
        }
        let total = pass.offs.len();
        pass.mnemonic_ids = vec![0; total];
        pass.flags = vec![0; total];
        pass.range_end = 0;
        pass
    }

    /// Whether a function is known to start at an address: the file said so, or a call lands there.
    pub fn is_known(&self, addr: i64) -> bool {
        self.known.contains(&addr)
    }

    fn sorted_known(&self) -> Vec<i64> {
        let mut v: Vec<i64> = self.known.iter().copied().collect();
        v.sort_unstable();
        v
    }

    fn apply(&mut self, layout: Layout) {
        self.ranges = layout.ranges;
        self.offs = layout.offs;
        self.lens = layout.lens;
        self.kinds = layout.kinds;
    }

    pub fn total(&self) -> u32 {
        self.offs.len() as u32
    }

    pub fn done(&self) -> u32 {
        self.at
    }

    fn in_code(&self, addr: i64) -> bool {
        self.code.iter().any(|&k| {
            let s = &self.image.sections[k];
            addr >= s.addr && addr < s.addr + s.size
        })
    }

    fn range_of_index(&self, index: u32) -> Option<&Range> {
        self.ranges.iter().find(|r| index >= r.first && index < r.first + r.count)
    }

    pub fn addr_of(&self, index: u32) -> i64 {
        match self.range_of_index(index) {
            Some(r) => self.image.sections[r.section].addr + self.offs[index as usize] as i64,
            None => 0,
        }
    }

    /// The instruction containing an address in code, or -1.
    pub fn index_of(&self, addr: i64) -> i64 {
        for r in &self.ranges {
            let s = &self.image.sections[r.section];
            if addr < s.addr || addr >= s.addr + s.size {
                continue;
            }
            let offset = addr - s.addr;
            let (mut lo, mut hi) = (r.first as i64, r.first as i64 + r.count as i64 - 1);
            let mut found = -1i64;
            while lo <= hi {
                let mid = (lo + hi) >> 1;
                if (self.offs[mid as usize] as i64) <= offset {
                    found = mid;
                    lo = mid + 1;
                } else {
                    hi = mid - 1;
                }
            }
            if found < 0 || offset >= self.offs[found as usize] as i64 + self.lens[found as usize] as i64 {
                return -1;
            }
            return found;
        }
        -1
    }

    /// The decoder's view of an instruction.
    pub fn decoded(&self, index: u32) -> X86Decoded {
        let r = self.range_of_index(index).copied().unwrap_or(Range { section: 0, first: 0, count: 0 });
        let s = &self.image.sections[r.section];
        let at = s.offset as usize + self.offs[index as usize] as usize;
        decode_x86(&self.image.bytes, at, (s.offset + s.size) as usize, s.addr + self.offs[index as usize] as i64, self.mode)
    }

    /// Sweeps every code section from its start, as llvm-objdump does, and starts afresh at each of
    /// `starts` (sorted): an instruction that would run past one still has its whole length, but the
    /// next begins at the start. The bytes of `data` (sorted) become entries of data instead.
    /// Besides the layout: where calls with a relative target go, and the indirect jumps (for switches).
    ///
    /// `again`: the layout already applied is the first one, and this one is its correction — where
    /// an instruction starts at the same place as before it has the same length (an instruction is
    /// its bytes, its address and its section's end), so only the places that moved are decoded
    /// again; and the calls and jumps, which only the first layout's caller wants, are not gathered.
    fn lay_out(&self, starts: &[i64], data: &[DataRegion], again: bool) -> (Layout, (Vec<i64>, Vec<u32>)) {
        let mut out = Layout::default();
        let mut calls_seen = FxHashSet::default();
        let mut calls = Vec::new();
        let mut jumps = Vec::new();
        let (mut k, mut r) = (0usize, 0usize);
        for (ri, &si) in self.code.iter().enumerate() {
            let s = &self.image.sections[si];
            let first = out.offs.len() as u32;
            let end = (s.offset + s.size) as usize;
            let mut pos: i64 = 0;
            // The first layout's run for this section, and a cursor into it.
            let before = if again { self.ranges.get(ri).filter(|p| p.section == si).copied() } else { None };
            let mut q = before.map_or(0, |b| b.first as usize);
            let q_end = before.map_or(0, |b| (b.first + b.count) as usize);
            while pos < s.size {
                let addr = s.addr + pos;
                while k < starts.len() && starts[k] <= addr {
                    k += 1;
                }
                while r < data.len() && data[r].addr + data[r].length <= addr {
                    r += 1;
                }
                let region = data.get(r);
                if let Some(region) = region {
                    if region.addr <= addr {
                        // Inside data: entries of its size, up to its end (and bytes for a tail that is not one).
                        let left = region.addr + region.length - addr;
                        let size = if left >= region.entry as i64 { region.entry } else { 1 };
                        let take = (size as i64).min(s.size - pos);
                        out.offs.push(pos as u32);
                        out.lens.push(take as u8);
                        out.kinds.push(data_kind(size));
                        pos += take;
                        continue;
                    }
                }
                if before.is_some() {
                    while q < q_end && (self.offs[q] as i64) < pos {
                        q += 1;
                    }
                    if q < q_end && self.offs[q] as i64 == pos && self.kinds[q] == 0 && self.lens[q] < 255 {
                        let full = self.lens[q] as i64;
                        out.offs.push(pos as u32);
                        out.lens.push(full as u8);
                        out.kinds.push(0);
                        let next = starts.get(k).copied().unwrap_or(i64::MAX).min(region.map_or(i64::MAX, |r| r.addr));
                        pos += if next > addr && next < addr + full { next - addr } else { full };
                        continue;
                    }
                }
                let d = decode_x86(&self.image.bytes, (s.offset + pos) as usize, end, addr, self.mode);
                out.offs.push(pos as u32);
                out.lens.push(d.length.min(255) as u8);
                out.kinds.push(0);
                let mut length = d.length as i64;
                let next = starts.get(k).copied().unwrap_or(i64::MAX).min(region.map_or(i64::MAX, |r| r.addr));
                if next > addr && next < addr + length {
                    length = next - addr;
                }
                pos += length;
                if d.id == 0 || again {
                    continue;
                }
                let bits = sem(d.id);
                if bits & sem::CALL != 0 {
                    if let Some(target) = target_of(&d) {
                        if target != addr + d.length as i64 && calls_seen.insert(target) {
                            calls.push(target);
                        }
                    }
                } else if bits & sem::BRANCH != 0 && bits & sem::INDIRECT != 0 && bits & sem::RET == 0 {
                    jumps.push(out.offs.len() as u32 - 1);
                }
            }
            out.ranges.push(Range { section: si, first, count: out.offs.len() as u32 - first });
        }
        (out, (calls, jumps))
    }

    fn intern(&mut self, m: &str) -> u16 {
        if let Some(&id) = self.ids.get(m) {
            return id;
        }
        let id = self.mnemonics.len() as u16;
        self.ids.insert(m.to_string(), id);
        self.mnemonics.push(m.to_string());
        self.counts.push(0);
        id
    }

    /// Whether an address may be data the listing can name: a string, a slot, a symbol, or in a section that is not code.
    fn is_data(&self, addr: i64) -> bool {
        self.strings.contains(&addr) || self.slots.contains(&addr) || self.symbols.contains(&addr) || (!self.in_code(addr) && self.image.section_of(addr).is_some())
    }

    fn thunk_reg(&self, addr: i64) -> i32 {
        match self.image.bytes_at(addr, 4) {
            Some(b) if b.len() == 4 && b[0] == 0x8b && (b[1] & 0xc7) == 0x04 && b[2] == 0x24 && b[3] == 0xc3 => ((b[1] >> 3) & 7) as i32,
            _ => -1,
        }
    }

    fn forget(&mut self, all: bool) {
        // A call keeps what the callee must preserve: ebx, esi, edi, ebp.
        for reg in 0..32 {
            if all || reg < 3 {
                self.value[reg] = f64::NAN;
            }
        }
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
        if i >= self.range_end {
            self.forget(true);
            match self.ranges.iter().position(|r| i >= r.first && i < r.first + r.count) {
                Some(k) => {
                    self.range = k;
                    self.range_end = self.ranges[k].first + self.ranges[k].count;
                    self.plt = self.image.sections[self.ranges[k].section].name.contains("plt");
                }
                None => self.range_end = total,
            }
        }
        let iu = i as usize;
        let kind = self.kinds[iu];
        if kind != 0 {
            let mut id = self.data_ids[kind as usize];
            if id < 0 {
                id = self.mnemonics.len() as i32;
                self.data_ids[kind as usize] = id;
                self.mnemonics.push(DATA_NAMES[kind as usize].to_string());
                self.counts.push(0);
            }
            self.mnemonic_ids[iu] = id as u16;
            self.counts[id as usize] += 1;
            return;
        }
        let r = self.ranges[self.range];
        let s = &self.image.sections[r.section];
        let (s_addr, s_offset, s_size) = (s.addr, s.offset, s.size);
        let plt = self.plt;
        let pc = s_addr + self.offs[iu] as i64;
        // A function starts with nothing known of its registers.
        if self.known.contains(&pc) {
            self.forget(true);
        }
        let d = decode_x86(&self.image.bytes, (s_offset + self.offs[iu] as i64) as usize, (s_offset + s_size) as usize, pc, self.mode);
        let m = mnemonic_x86(&d);
        let id = self.intern(&m);
        self.mnemonic_ids[iu] = id;
        self.counts[id as usize] += 1;
        if d.id == 0 {
            self.flags[iu] |= iflag::UNKNOWN;
            return;
        }
        let bits = sem(d.id);
        let next = pc + d.length as i64;
        let target = target_of(&d);
        if let Some(t) = target {
            self.rel_targets.push((i, t));
        }
        if bits & sem::CALL != 0 {
            self.flags[iu] |= iflag::CALL;
            // `call` to the next instruction is i386 code reading its own address, not a call.
            if let Some(t) = target {
                if t != next {
                    self.callers.add(t, i);
                }
            }
        } else if bits & sem::BRANCH != 0 {
            self.flags[iu] |= iflag::BRANCH;
            if let Some(t) = target {
                self.label_targets.push(t);
            }
        }

        // The data the instruction names.
        let mem = memory_of(&d);
        let mut addr = fixed_address_of(&d, self.absolute || (self.mode == 32 && self.image.format != Format::Elf));
        if addr.is_none() {
            if let Some(mem) = mem {
                // Through a register holding an address: the GOT register of i386 code, a stub's [ebx + offset].
                let base = gpr_name(mem.base);
                if base >= 0 && !self.value[base as usize].is_nan() {
                    if mem.index.is_empty() {
                        addr = Some(u32_of(self.value[base as usize] + mem.disp) as i64);
                    } else {
                        self.base_values.insert(i, self.value[base as usize]);
                    }
                } else if self.mode == 32 && mem.base == "ebx" && mem.index.is_empty() && plt {
                    if let Some(got) = self.got_plt {
                        addr = Some(u32_of(got as f64 + mem.disp) as i64);
                    }
                }
            }
        }
        if let Some(a) = addr.filter(|a| bits & (sem::CALL | sem::BRANCH) != 0 && self.slots.contains(a)) {
            self.address_at.push((i, a));
            self.slot_callers.add(a, i);
        } else if let Some(a) = addr.filter(|a| self.is_data(*a)) {
            self.address_at.push((i, a));
            self.data_refs.add(a, i);
        } else if let Some(a) = addr.filter(|a| bits & (sem::CALL | sem::BRANCH) == 0 && self.in_code(*a)) {
            self.code_at.push((i, a));
        } else if self.absolute {
            // An immediate that is an address (`push offset`, `mov dword ptr [esp], offset` in code that is not PIC).
            let (types, ops) = (d.types, d.ops);
            for k in 0..types.len() {
                if types[k] != ty::IMM {
                    continue;
                }
                let v = u32_of(op_num(ops.get(k))) as i64;
                if v >= 0x1000 && (self.strings.contains(&v) || self.symbols.contains(&v) || (self.is_data(v) && self.image.text_at(v, None).is_some())) {
                    self.address_at.push((i, v));
                    self.data_refs.add(v, i);
                } else if self.in_code(v) && v >= 0x1000 {
                    self.code_at.push((i, v));
                }
                break;
            }
        }

        // Registers holding addresses, for i386 position-independent code.
        if self.mode == 32 {
            let types = d.types;
            let ops = d.ops;
            let dest = if types.first().is_some_and(|t| is_gpr_type(*t)) { gpr(ops.first()) } else { -1 };
            if bits & sem::CALL != 0 {
                self.forget(false);
                let reg = if target == Some(next) {
                    -2
                } else if let Some(t) = target {
                    self.thunk_reg(t)
                } else {
                    -1
                };
                if reg >= 0 {
                    self.value[reg as usize] = next as f64;
                }
                return;
            }
            if bits & sem::BRANCH != 0 {
                return;
            }
            if m.as_str() == "pop" && dest >= 0 && i > 0 && self.kinds[iu - 1] == 0 {
                // call next / pop reg: the address of the pop.
                let prev = self.decoded(i - 1);
                self.value[dest as usize] = if prev.id != 0 && sem(prev.id) & sem::CALL != 0 && target_of(&prev) == Some(pc) { pc as f64 } else { f64::NAN };
                return;
            }
            let last = ops.len().wrapping_sub(1);
            if m.as_str() == "add" && dest >= 0 && mem.is_none() && matches!(ops.get(last), Some(McOp::Imm(_))) && types.get(last) == Some(&ty::IMM) {
                let v = self.value[dest as usize];
                self.value[dest as usize] = if v.is_nan() { f64::NAN } else { u32_of(v + op_num(ops.get(last))) as f64 };
                return;
            }
            if m.as_str() == "lea" && dest >= 0 {
                self.value[dest as usize] = addr.map_or(f64::NAN, |a| a as f64);
                return;
            }
            if dest >= 0 && bits & sem::STORE == 0 {
                self.value[dest as usize] = f64::NAN;
            }
        }
    }

    /// After the pass: the switches, the labels, and which compares the HLA64 view joins with their jumps.
    pub fn finish(&mut self) -> X86Refs {
        let total = self.total();
        // Switches: a jump through a table of offsets or addresses.
        for i in 0..total {
            if self.flags[i as usize] & (iflag::BRANCH | iflag::CALL) != iflag::BRANCH {
                continue;
            }
            if let Some(found) = self.switch_of(i) {
                self.label_targets.extend_from_slice(&found.targets);
                self.tables.push((i, found.targets));
            }
        }
        // Labels: branch targets inside code.
        for k in 0..self.label_targets.len() {
            let target = self.label_targets[k];
            let index = self.index_of(target);
            if index >= 0 && self.addr_of(index as u32) == target {
                self.flags[index as usize] |= iflag::LABEL;
            }
        }
        self.label_targets = Vec::new();
        // The HLA64 view of x86-64 code joins a compare with the jump or conditional move that reads its flags.
        // The page drops the join where a function starts at the second (it knows the functions; this does not).
        if self.mode == 64 && total > 1 {
            let setters: Vec<bool> = self.mnemonics.iter().map(|m| is_x86_setter(m)).collect();
            let consumers: Vec<bool> = self.mnemonics.iter().map(|m| is_x86_consumer(m)).collect();
            for i in 0..total - 1 {
                let (a, b) = (i as usize, i as usize + 1);
                if !setters[self.mnemonic_ids[a] as usize] || !consumers[self.mnemonic_ids[b] as usize] {
                    continue;
                }
                if self.flags[b] & iflag::LABEL != 0 || self.kinds[a] != 0 || self.kinds[b] != 0 {
                    continue;
                }
                let first = insn_of(&self.decoded(i), self.absolute);
                let second = insn_of(&self.decoded(i + 1), self.absolute);
                if fuse_x86(&first, &second, &Bare).is_some() {
                    self.flags[a] |= iflag::FUSE;
                }
            }
        }
        // Switches are found in index order: their instructions, where each one's cases start, the cases.
        let mut table_index = Vec::with_capacity(self.tables.len());
        let mut table_starts = Vec::with_capacity(self.tables.len() + 1);
        let mut table_targets = Vec::new();
        for (i, targets) in &self.tables {
            table_index.push(*i);
            table_starts.push(table_targets.len() as u32);
            table_targets.extend(targets.iter().map(|&t| t as f64));
        }
        table_starts.push(table_targets.len() as u32);
        let data_refs = core::mem::take(&mut self.data_refs).build();
        // Strings in constant data that code points at.
        let strings = data_refs.keys.iter().map(|&k| k as i64).filter(|a| !self.strings.contains(a)).filter_map(|a| self.image.text_at(a, None)).collect();
        X86Refs {
            strings,
            data_refs,
            callers: core::mem::take(&mut self.callers).build(),
            slot_callers: core::mem::take(&mut self.slot_callers).build(),
            table_index,
            table_starts,
            table_targets,
        }
    }

    /// The switch tables found: instruction index → case addresses, in order.
    pub fn tables(&self) -> &[(u32, Vec<i64>)] {
        &self.tables
    }

    /// The cases of a switch that jumps through a table, from the instructions
    /// before the jump. Compilers write it in one of these ways:
    ///
    ///   lea rcx, [rip + T] / movsxd rax, dword ptr [rcx + 4*rax] / add rax, rcx / jmp rax
    ///     (offsets from the table: x86-64 position-independent code)
    ///   mov ecx, dword ptr [ebx + 4*eax + D] / add ecx, ebx / jmp ecx, or
    ///   add edx, dword ptr [edx + 4*esi + D] / jmp edx
    ///     (offsets from the GOT, a register holding its address: i386 position-independent code)
    ///   jmp qword ptr [8*rax + T], jmp dword ptr [4*eax + T]
    ///     (addresses: code that is not position-independent)
    ///
    /// How many cases there are is read from the bounds check before it (`cmp
    /// reg, N` and `ja`); without one the table is read while its entries land
    /// on instructions and before the next function.
    fn switch_of(&self, index: u32) -> Option<Switch> {
        let jump = self.decoded(index);
        if jump.id == 0 {
            return None;
        }
        // What rules a jump out without looking back: a direct one (a relative target), a memory
        // operand that is no table of addresses, a register that is none of the general ones.
        let jump_mem = memory_of(&jump);
        match jump_mem {
            Some(mem) => {
                if !mem.base.is_empty() || mem.index.is_empty() || mem.scale != if self.mode == 32 { 4.0 } else { 8.0 } || !mem.seg.is_empty() {
                    return None;
                }
            }
            None => {
                if gpr(jump.ops.first()) < 0 {
                    return None;
                }
            }
        }
        let mut window: Vec<(X86Decoded, u32)> = Vec::with_capacity(16);
        for k in index.saturating_sub(16)..index {
            if self.kinds[k as usize] == 0 {
                window.push((self.decoded(k), k));
            }
        }
        let mut table: Option<i64> = None;
        let mut entry: u32 = 8;
        // What an entry is added to: the table (x86-64) or the GOT (i386); None for addresses.
        let mut base: Option<f64> = None;
        if let Some(mem) = jump_mem {
            table = Some(if self.mode == 32 { u32_of(mem.disp) as i64 } else { mem.disp as i64 });
            entry = mem.scale as u32;
        } else {
            let reg = gpr(jump.ops.first());
            if reg < 0 {
                return None;
            }
            let mut k = window.len();
            while k > 0 && table.is_none() {
                k -= 1;
                let (d, at) = &window[k];
                let Some(load) = memory_of(d) else { continue };
                let m = mnemonic_x86(d);
                let m = m.as_str();
                if !((m == "movsxd" || m == "mov" || m == "add") && !load.index.is_empty() && load.scale == 4.0 && !load.base.is_empty()) {
                    continue;
                }
                // `add reg, [got + 4*i + D]` loads and adds at once (clang's i386 PIC switch).
                let got = self.base_values.get(at).copied();
                if m == "add" && got.is_none() {
                    continue;
                }
                if let Some(got) = got {
                    table = Some(u32_of(got + load.disp) as i64);
                    entry = 4;
                    base = Some(got);
                    break;
                }
                // The base came from `lea base, [rip + T]` before it: the table itself (clang, entries are offsets
                // from it), or the image base (MSVC: `mov ecx, [rdx + 4*rax + RVA]`, entries are RVAs).
                if load.disp != 0.0 && self.image.format != Format::Pe {
                    continue;
                }
                let reg2 = gpr_name(load.base);
                let mut j = k;
                while j > 0 {
                    j -= 1;
                    let lea = &window[j].0;
                    if mnemonic_x86(lea).as_str() != "lea" || gpr(lea.ops.first()) != reg2 {
                        continue;
                    }
                    if let Some(at2) = fixed_address_of(lea, self.absolute) {
                        table = Some((at2 as f64 + load.disp) as i64);
                        entry = 4;
                        base = Some(at2 as f64);
                    }
                    break;
                }
            }
            table?;
        }
        let table = table?;
        // The bound: `cmp reg, N` and a branch that leaves when the index is above it — unless a byte table
        // maps the index to a case first (MSVC), when the cases are fewer than the values it checks.
        let mut count: u64 = 0;
        let mut k = window.len();
        while k > 1 {
            k -= 1;
            let m = mnemonic_x86(&window[k].0);
            let m = m.as_str();
            if m == "movzx" && memory_of(&window[k].0).is_some_and(|mm| !mm.index.is_empty()) {
                break;
            }
            if m != "ja" && m != "jae" && m != "jbe" && m != "jb" {
                continue;
            }
            let cmp = &window[k - 1].0;
            let ops = cmp.ops;
            let types = cmp.types;
            let last = ops.len().wrapping_sub(1);
            if mnemonic_x86(cmp).as_str() == "cmp" && matches!(ops.get(last), Some(McOp::Imm(_))) && types.get(last) == Some(&ty::IMM) {
                let n = u32_of(op_num(ops.get(last))) as u64;
                count = if m == "ja" || m == "jbe" { n + 1 } else { n };
            }
            break;
        }
        if count > 4096 {
            return None;
        }
        let limit = if count != 0 { count } else { 512 };
        let mut targets: Vec<i64> = Vec::new();
        let signed = base.is_some();
        for k in 0..limit {
            let at = table + k as i64 * entry as i64;
            // Without a bound, a table ends where code or the next function begins.
            if count == 0 && k != 0 && (self.known.contains(&at) || targets.contains(&at)) {
                break;
            }
            let Some(v) = self.image.value_at(at, entry as usize, signed) else { break };
            let target = match base {
                Some(b) => {
                    if self.mode == 32 {
                        u32_of(b + v) as i64
                    } else {
                        (b + v) as i64
                    }
                }
                None => v as i64,
            };
            let i = self.index_of(target);
            if !self.in_code(target) || i < 0 || self.addr_of(i as u32) != target {
                if count != 0 {
                    return None;
                }
                break;
            }
            targets.push(target);
        }
        if targets.is_empty() {
            None
        } else {
            Some(Switch { table, entry, targets })
        }
    }
}

struct Switch {
    table: i64,
    entry: u32,
    targets: Vec<i64>,
}

/// Regions sorted, the ones that overlap joined (keeping the first one's entry size).
fn merge_regions(regions: &mut [DataRegion]) -> Vec<DataRegion> {
    regions.sort_by_key(|r| r.addr);
    let mut out: Vec<DataRegion> = Vec::new();
    for r in regions.iter() {
        if let Some(last) = out.last_mut() {
            if r.addr < last.addr + last.length {
                last.length = last.length.max(r.addr + r.length - last.addr);
                continue;
            }
        }
        out.push(*r);
    }
    out
}

/// The bytes of a data entry of a kind.
pub fn data_size(kind: u8) -> u32 {
    DATA_SIZES[kind as usize]
}
