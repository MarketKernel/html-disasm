//! The pass over every instruction of an arm64 program — a Mach-O file, an
//! ELF library for Android or Linux, a Windows PE: each instruction is decoded
//! once, and from that pass come the statistics, the labels, the call and data
//! cross references, the lengths Rust code gives its strings, and which
//! neighbouring instructions the HLA64 view joins.
//!
//! The pass runs in steps (`step`), so a host can show progress between them;
//! it never calls out. What it finds stays in flat arrays the host reads in
//! place: one mnemonic number and one flag byte per instruction, the cross
//! references as compressed sparse rows (refs.rs).
//!
//! What needs the names and the file's structures — functions, strings, the
//! entry point — is the job of the code around it (src/core/program.ts).

use super::decode::decode;
use super::hla::{fuses, is_consumer, is_setter, paired_address};
use super::types::{f, Insn, Mn, Mode, Op};
use crate::disassembly::{iflag, CodeRange};
use crate::refs::{FxHashMap, FxHashSet, RefBuilder, RefIndex};

/// The register number of `x5` / `w5`, or -1.
#[inline]
fn reg_index(op: Option<&Op>) -> i32 {
    match op {
        Some(Op::Reg(r)) => gpr_number(r.as_bytes(), true),
        _ => -1,
    }
}

/// `^[xw](\d+)$` (or `^x(\d+)$` when `w` is not allowed) as a number, or -1.
#[inline]
fn gpr_number(b: &[u8], w_too: bool) -> i32 {
    if b.len() < 2 || !(b[0] == b'x' || (w_too && b[0] == b'w')) {
        return -1;
    }
    let mut n: i32 = 0;
    for &c in &b[1..] {
        if !c.is_ascii_digit() {
            return -1;
        }
        n = n.saturating_mul(10).saturating_add((c - b'0') as i32);
    }
    n
}

fn first_mem(insn: &Insn) -> Option<&super::types::Mem> {
    insn.ops.iter().find_map(|op| if let Op::Mem(m) = op { Some(m) } else { None })
}

/// The base register of an add-immediate or a load/store with an immediate offset, which may complete an adrp.
fn base_of(insn: &Insn, k: u8) -> i32 {
    if k & kind::ADD != 0 && insn.ops.len() == 3 && matches!(insn.ops.get(2), Some(Op::Imm { .. })) {
        return reg_index(insn.ops.get(1));
    }
    if insn.f & (f::LOAD | f::STORE) != 0 {
        if let Some(mem) = first_mem(insn) {
            if mem.index.is_none() && mem.mode == Mode::Off {
                return gpr_number(mem.base.as_bytes(), false);
            }
        }
    }
    -1
}

fn offset_of(insn: &Insn, k: u8) -> f64 {
    if k & kind::ADD != 0 {
        return match insn.ops.get(2) {
            Some(Op::Imm { v, .. }) => *v,
            _ => 0.0,
        };
    }
    first_mem(insn).map_or(0.0, |m| m.off as f64)
}

/// The general register an instruction writes, as far as tracking adrp pages needs.
pub fn written_reg(insn: &Insn) -> i32 {
    if insn.f & f::STORE != 0 && insn.f & f::LOAD == 0 {
        return -1;
    }
    // A branch or call through a register reads it (`blr x21`).
    if insn.f & (f::BRANCH | f::CALL) != 0 {
        return -1;
    }
    reg_index(insn.ops.first())
}

/// What the pass needs to know of a mnemonic, worked out once when it is first seen,
/// so that the pass compares numbers, not strings, at each instruction.
mod kind {
    pub const ADRP: u8 = 1;
    pub const ADD: u8 = 2;
    pub const MOV: u8 = 4;
    pub const LDR: u8 = 8;
    pub const BLR_BR: u8 = 16;
    pub const ADR: u8 = 32;
    pub const SETTER: u8 = 64;
    pub const CONSUMER: u8 = 128;
}

fn kind_of(m: &str) -> u8 {
    let mut k = match m {
        "adrp" => kind::ADRP,
        "add" => kind::ADD,
        "mov" => kind::MOV,
        "ldr" => kind::LDR,
        "blr" | "br" => kind::BLR_BR,
        "adr" => kind::ADR,
        _ => 0,
    };
    if is_setter(m) {
        k |= kind::SETTER;
    }
    if is_consumer(m) {
        k |= kind::CONSUMER;
    }
    k
}

struct Pending {
    reg: i32,
    addr: i64,
    index: u32,
}

/// What the pass found, once it is done.
pub struct Arm64Refs {
    /// Call target → the calls (instruction indices).
    pub callers: RefIndex,
    /// Data address → the instructions that build or read it.
    pub data_refs: RefIndex,
    /// An import's slot → the calls through it (`ldr x8, [x8, #…]; blr x8`).
    pub slot_callers: RefIndex,
    /// The calls through a slot: instruction indices, ascending, and the slot each one goes through.
    pub slot_call_index: Vec<u32>,
    pub slot_call_slot: Vec<f64>,
    /// Rust's &str lengths: addresses ascending, and the shortest length seen for each.
    pub length_addr: Vec<f64>,
    pub length_value: Vec<u32>,
}

pub struct Arm64Pass {
    pub ranges: Vec<CodeRange>,
    pub words: Vec<u32>,
    pub mnemonic_ids: Vec<u16>,
    pub flags: Vec<u8>,
    pub mnemonics: Vec<Mn>,
    pub counts: Vec<u32>,
    kinds: Vec<u8>,
    ids: FxHashMap<u128, u16>,
    import_slots: FxHashSet<i64>,
    pe: bool,
    callers: RefBuilder,
    data_refs: RefBuilder,
    slot_callers: RefBuilder,
    slot_calls: Vec<(u32, i64)>,
    length_at: FxHashMap<i64, u32>,
    label_targets: Vec<i64>,
    // Where the pass is.
    range: usize,
    at: u32,
    done: u32,
    /// The previous instruction's kind (0 at the start of a range), and the instruction itself
    /// when it is one the next may join (an adrp, a flag setter): only those are kept.
    prev_kind: u8,
    prev: Option<Insn>,
    pending: Pending,
    pages: [i64; 32],
    page_at: [i64; 32],
    // A register loaded from an import's slot, for a call through it (`ldr x8, [x8, #…]; blr x8`, as MSVC calls imports).
    slots: [i64; 32],
    slot_at: [i64; 32],
}

impl Arm64Pass {
    /// `bytes` is the file (or the slice of a universal file); each range names its code by file offset.
    /// `import_slots` are the addresses of the import table's slots (a PE file's, for calls through them).
    pub fn new(bytes: &[u8], ranges: &[(i64, u64, u32)], import_slots: &[i64], pe: bool) -> Arm64Pass {
        let mut total = 0u32;
        let mut code = Vec::with_capacity(ranges.len());
        for &(addr, offset, count) in ranges {
            code.push(CodeRange { addr, offset, first: total, count });
            total += count;
        }
        let mut words = vec![0u32; total as usize];
        for range in &code {
            let start = range.offset as usize;
            for i in 0..range.count as usize {
                let at = start + i * 4;
                let word = bytes.get(at..at + 4).map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
                words[range.first as usize + i] = word;
            }
        }
        Arm64Pass {
            ranges: code,
            mnemonic_ids: vec![0; total as usize],
            flags: vec![0; total as usize],
            words,
            mnemonics: Vec::new(),
            counts: Vec::new(),
            kinds: Vec::new(),
            ids: FxHashMap::default(),
            import_slots: import_slots.iter().copied().collect(),
            pe,
            callers: RefBuilder::default(),
            data_refs: RefBuilder::default(),
            slot_callers: RefBuilder::default(),
            slot_calls: Vec::new(),
            length_at: FxHashMap::default(),
            label_targets: Vec::new(),
            range: 0,
            at: 0,
            done: 0,
            prev_kind: 0,
            prev: None,
            pending: Pending { reg: -1, addr: 0, index: 0 },
            pages: [-1; 32],
            page_at: [-1; 32],
            slots: [-1; 32],
            slot_at: [-1; 32],
        }
    }

    pub fn total(&self) -> u32 {
        self.words.len() as u32
    }

    /// Instructions decoded so far.
    pub fn done(&self) -> u32 {
        self.done
    }

    /// The address of an instruction.
    pub fn addr_of(&self, index: u32) -> i64 {
        for range in &self.ranges {
            if index >= range.first && index < range.first + range.count {
                return range.addr + (index - range.first) as i64 * 4;
            }
        }
        0
    }

    /// The instruction index of an address in code, or -1.
    pub fn index_of(&self, addr: i64) -> i64 {
        for range in &self.ranges {
            if addr >= range.addr && addr < range.addr + range.count as i64 * 4 {
                return range.first as i64 + (addr - range.addr) / 4;
            }
        }
        -1
    }

    pub fn insn(&self, index: u32) -> Insn {
        decode(self.words[index as usize], self.addr_of(index))
    }

    fn intern(&mut self, m: &Mn) -> u16 {
        let key = m.key();
        if let Some(&id) = self.ids.get(&key) {
            return id;
        }
        let id = self.mnemonics.len() as u16;
        self.ids.insert(key, id);
        self.mnemonics.push(*m);
        self.counts.push(0);
        self.kinds.push(kind_of(m));
        id
    }

    /// Decodes up to `budget` more instructions; true once every one is done.
    pub fn step(&mut self, budget: u32) -> bool {
        let mut left = budget;
        while self.range < self.ranges.len() {
            let range = self.ranges[self.range];
            if self.at == 0 {
                self.pages = [-1; 32];
                self.slots = [-1; 32];
                self.prev_kind = 0;
            }
            while self.at < range.count {
                if left == 0 {
                    return false;
                }
                left -= 1;
                let index = range.first + self.at;
                let pc = range.addr + self.at as i64 * 4;
                self.visit(index, pc);
                self.at += 1;
                self.done += 1;
            }
            self.range += 1;
            self.at = 0;
        }
        true
    }

    #[inline]
    fn visit(&mut self, index: u32, pc: i64) {
        let insn = decode(self.words[index as usize], pc);
        let i = index as usize;
        let id = self.intern(&insn.m);
        self.mnemonic_ids[i] = id;
        self.counts[id as usize] += 1;
        let mut flags = self.flags[i];
        if insn.f & f::UNKNOWN != 0 {
            flags |= iflag::UNKNOWN;
        }
        if let Some(target) = insn.target {
            if insn.f & f::CALL != 0 {
                flags |= iflag::CALL;
                self.callers.add(target, index);
            } else if insn.f & f::BRANCH != 0 {
                flags |= iflag::BRANCH;
                self.label_targets.push(target);
            }
        } else if insn.f & f::CALL != 0 {
            flags |= iflag::CALL;
        } else if insn.f & f::BRANCH != 0 {
            flags |= iflag::BRANCH;
        }
        self.flags[i] = flags;

        let k = self.kinds[id as usize];

        // adrp + add / load / store: the address they make together is a data reference.
        if self.prev_kind & (kind::ADRP | kind::SETTER) != 0 {
            if let Some(previous) = &self.prev {
                if self.prev_kind & kind::ADRP != 0 {
                    if let Some(joined) = paired_address(previous, &insn) {
                        self.flags[i - 1] |= iflag::FUSE;
                        if k & kind::ADD != 0 {
                            self.pending = Pending { reg: reg_index(insn.ops.first()), addr: joined, index };
                        }
                    }
                } else if k & kind::CONSUMER != 0 && fuses(previous, &insn) {
                    self.flags[i - 1] |= iflag::FUSE;
                }
            }
        }
        if self.pending.reg >= 0 && index - self.pending.index <= 4 && k & kind::MOV != 0 && reg_index(insn.ops.first()) == self.pending.reg + 1 {
            if let Some(Op::Imm { v, .. }) = insn.ops.get(1) {
                let length = *v;
                if length > 0.0 && length < 4096.0 {
                    let length = length as u32;
                    self.length_at.entry(self.pending.addr).and_modify(|seen| *seen = (*seen).min(length)).or_insert(length);
                }
                self.pending.reg = -1;
            }
        }
        if k & kind::ADRP != 0 {
            let r = reg_index(insn.ops.first());
            if r >= 0 {
                self.pages[r as usize] = insn.target.unwrap_or(-1);
                self.page_at[r as usize] = index as i64;
            }
        } else {
            let base = base_of(&insn, k);
            let mut slot = -1;
            if base >= 0 && self.pages[base as usize] >= 0 && index as i64 - self.page_at[base as usize] <= 16 {
                let addr = (self.pages[base as usize] as f64 + offset_of(&insn, k)) as i64;
                self.data_refs.add(addr, index);
                if self.pe && k & kind::LDR != 0 && self.import_slots.contains(&addr) {
                    slot = addr;
                }
            }
            if k & kind::BLR_BR != 0 && matches!(insn.ops.first(), Some(Op::Reg(_))) {
                let r = reg_index(insn.ops.first());
                if r >= 0 && self.slots[r as usize] >= 0 && index as i64 - self.slot_at[r as usize] <= 16 {
                    let target = self.slots[r as usize];
                    self.slot_calls.push((index, target));
                    self.slot_callers.add(target, index);
                }
            }
            let written = written_reg(&insn);
            if written >= 0 {
                let w = written as usize;
                if w < 32 {
                    self.pages[w] = -1;
                    self.slots[w] = slot;
                    self.slot_at[w] = index as i64;
                }
            }
            if insn.f & (f::BRANCH | f::CALL) != 0 {
                self.pages = [-1; 32];
                // A call keeps x19–x28 (MSVC holds an import it calls twice in one of them); a branch may land anywhere.
                if insn.f & f::CALL != 0 {
                    self.slots[..19].fill(-1);
                } else {
                    self.slots = [-1; 32];
                }
            }
        }
        if k & kind::ADR != 0 {
            if let Some(target) = insn.target {
                self.data_refs.add(target, index);
            }
        }
        self.prev_kind = k;
        if k & (kind::ADRP | kind::SETTER) != 0 {
            self.prev = Some(insn);
        }
    }

    /// Marks the branch targets as labels and hands over the cross references.
    pub fn finish(&mut self) -> Arm64Refs {
        for k in 0..self.label_targets.len() {
            let index = self.index_of(self.label_targets[k]);
            if index >= 0 {
                self.flags[index as usize] |= iflag::LABEL;
            }
        }
        self.label_targets = Vec::new();
        let mut lengths: Vec<(i64, u32)> = self.length_at.drain().collect();
        lengths.sort_unstable();
        // Calls are found in index order already.
        let slot_calls = core::mem::take(&mut self.slot_calls);
        Arm64Refs {
            callers: core::mem::take(&mut self.callers).build(),
            data_refs: core::mem::take(&mut self.data_refs).build(),
            slot_callers: core::mem::take(&mut self.slot_callers).build(),
            slot_call_index: slot_calls.iter().map(|c| c.0).collect(),
            slot_call_slot: slot_calls.iter().map(|c| c.1 as f64).collect(),
            length_addr: lengths.iter().map(|l| l.0 as f64).collect(),
            length_value: lengths.iter().map(|l| l.1).collect(),
        }
    }
}
