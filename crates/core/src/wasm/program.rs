//! The analysis of a whole WebAssembly module (a port of src/core/wasm/program.ts
//! and effects.ts): every instruction of every function body is decoded once,
//! and from that pass come the statistics, the functions and their names, the
//! labels branches go to (worked out from the nesting of blocks), the call
//! graph, the places code reads or builds an address of data, the strings, and
//! which instructions the HLA64 view writes as one line.
//!
//! Addresses of code are offsets in the file; addresses of data are addresses
//! in the module's linear memory, where the data segments put their bytes.
//! The page keeps its own reading of the module (for its tables of types,
//! imports and sections) and takes from here what the pass found.

use super::decode::{decode_at, BlockType, WasmInsn};
use super::hla::{lift_group, WasmLines, WasmNaming};
use super::module::{at, func_type_of, parse_wasm, DataMode, ExternKind, ParseError, SymbolKind, WasmModule};
use super::opcodes::{all_ops, imm, w, OpInfo};
use super::reader::{utf8, Num};
use crate::demangle::{demangle_wasm, Demangled};
use crate::disassembly::{iflag, is_text};
use crate::lift::HlaLine;
use crate::refs::{FxHashMap, FxHashSet, RefBuilder, RefIndex};

/// Bits of the flags beyond the shared ones (`WF` in src/core/wasm/hla.ts).
pub mod wflag {
    /// An `if` written `if c {`: its condition is in its line.
    pub const SUGAR_IF: u8 = 64;
    /// The `else` or `end` of such an if: `} else {`, `}`.
    pub const IF_END: u8 = 128;
}

/// The opcodes the pass looks for.
mod op {
    pub const UNREACHABLE: u32 = 0x00;
    pub const BLOCK: u32 = 0x02;
    pub const LOOP: u32 = 0x03;
    pub const IF: u32 = 0x04;
    pub const ELSE: u32 = 0x05;
    pub const TRY: u32 = 0x06;
    pub const CATCH: u32 = 0x07;
    pub const THROW: u32 = 0x08;
    pub const END: u32 = 0x0b;
    pub const BR: u32 = 0x0c;
    pub const BR_IF: u32 = 0x0d;
    pub const BR_TABLE: u32 = 0x0e;
    pub const RETURN: u32 = 0x0f;
    pub const CALL: u32 = 0x10;
    pub const CALL_INDIRECT: u32 = 0x11;
    pub const RETURN_CALL: u32 = 0x12;
    pub const RETURN_CALL_INDIRECT: u32 = 0x13;
    pub const CALL_REF: u32 = 0x14;
    pub const RETURN_CALL_REF: u32 = 0x15;
    pub const DELEGATE: u32 = 0x18;
    pub const CATCH_ALL: u32 = 0x19;
    pub const TRY_TABLE: u32 = 0x1f;
    pub const GLOBAL_GET: u32 = 0x23;
    pub const GLOBAL_SET: u32 = 0x24;
    pub const I32_CONST: u32 = 0x41;
    pub const I64_CONST: u32 = 0x42;
    pub const REF_FUNC: u32 = 0xd2;
    pub const STRUCT_NEW: u32 = 0xfb << 16;
    pub const ARRAY_NEW_FIXED: u32 = 0xfb << 16 | 8;
    pub const MEMORY_INIT: u32 = 0xfc << 16 | 8;
}

/// Where a data segment's bytes are in memory and in the file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    pub index: u32,
    pub addr: i64,
    pub end: i64,
    /// File offset of its first byte.
    pub start: usize,
    pub name: String,
    /// A passive segment, placed by memory.init in the start function.
    pub passive: bool,
}

/// A string in the data segments: its memory address, its text, the segment it is in (by its
/// place in `segments`), and whether a NUL ends it (`cstring`) or not (`const`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WasmString {
    pub addr: i64,
    pub text: String,
    pub segment: u32,
    pub cstring: bool,
}

/// How a function is known: the start function, an export, by a name the module gives, or not at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FnKind {
    Entry,
    Export,
    Symbol,
    Anonymous,
}

impl FnKind {
    pub fn as_str(self) -> &'static str {
        match self {
            FnKind::Entry => "entry",
            FnKind::Export => "export",
            FnKind::Symbol => "symbol",
            FnKind::Anonymous => "anonymous",
        }
    }
}

/// A function the module defines, one per body.
#[derive(Clone, Debug)]
pub struct Function {
    /// Its index in the function index space (imports first).
    pub index: u64,
    /// Its first instruction (the offset of its code) and how many it has.
    pub addr: usize,
    pub first: u32,
    pub count: u32,
    pub kind: FnKind,
    /// The name it was found under, and what it demangles to; None for an unnamed one.
    pub name: Option<(String, Demangled)>,
}

/// An imported function: the name the module calls it by, and what it demangles to.
#[derive(Clone, Debug)]
pub struct ImportedFn {
    pub index: u64,
    pub raw: String,
    pub name: Demangled,
}

#[derive(Default)]
pub struct WasmProgram {
    pub offsets: Vec<u32>,
    /// How deep in blocks each instruction is (for indentation).
    pub depth: Vec<u16>,
    pub mnemonic_ids: Vec<u16>,
    pub flags: Vec<u8>,
    pub mnemonics: Vec<&'static str>,
    pub counts: Vec<u32>,
    /// One per body of the module, in its order (the bodies with no instruction too).
    pub bodies: Vec<Function>,
    pub imported: Vec<ImportedFn>,
    pub segments: Vec<Segment>,
    pub strings: Vec<WasmString>,
    /// Function address → calls; data address → instructions; function address → ref.func; global → its uses.
    pub callers: RefIndex,
    pub data_refs: RefIndex,
    pub ref_funcs: RefIndex,
    pub global_refs: RefIndex,
    /// Type index → the functions a call_indirect of that type may reach (those in a table), as found.
    pub indirect: RefIndex,
    /// Branches: the instruction, where its run of targets starts in `target_values` (-1: a slot of
    /// a br_table whose label was never found).
    pub target_index: Vec<u32>,
    pub target_starts: Vec<u32>,
    pub target_values: Vec<i32>,
    /// Branches that carry values to their label, in order.
    pub value_branches: Vec<u32>,
    /// String address → the length Rust code gives it, by address.
    pub length_addr: Vec<f64>,
    pub length_value: Vec<f64>,
    pub indirect_calls: u32,
}

impl WasmProgram {
    /// The data segment holding a memory address.
    pub fn segment_at(&self, addr: i64) -> Option<usize> {
        segment_at(&self.segments, addr)
    }
}

fn segment_at(segments: &[Segment], addr: i64) -> Option<usize> {
    let (mut lo, mut hi) = (0isize, segments.len() as isize - 1);
    while lo <= hi {
        let mid = (lo + hi) >> 1;
        let s = &segments[mid as usize];
        if addr < s.addr {
            hi = mid - 1;
        } else if addr >= s.end {
            lo = mid + 1;
        } else {
            return Some(mid as usize);
        }
    }
    None
}

/* ------------------------------------------------------------------ *
 * Stack effects
 * ------------------------------------------------------------------ */

/// The parameters of a tag, for throw.
fn tag_params(module: &WasmModule, tag: u64) -> u64 {
    at(&module.tags, tag).and_then(|&ty| at(&module.types, ty)).and_then(|t| t.func.as_ref()).map_or(0, |f| f.params.len() as u64)
}

/// pops and pushes of a plain instruction — anything but the structure (block, loop, if, else,
/// end, try…) and the branches, which the caller handles — or None when it cannot tell.
pub fn effect(insn: &WasmInsn, module: &WasmModule) -> Option<(u64, u64)> {
    let o: &OpInfo = insn.op?;
    if o.flags & w::STRUCTURE != 0 {
        return None;
    }
    if let Some((pops, pushes)) = o.fixed {
        return Some((pops as u64, pushes as u64));
    }
    match o.code {
        op::CALL | op::RETURN_CALL => {
            let ty = func_type_of(module, insn.a)?;
            Some((ty.params.len() as u64, if o.code == op::CALL { ty.results.len() as u64 } else { 0 }))
        }
        op::CALL_INDIRECT | op::RETURN_CALL_INDIRECT | op::CALL_REF | op::RETURN_CALL_REF => {
            let ty = at(&module.types, insn.a)?.func.as_ref()?;
            let returns = o.code == op::RETURN_CALL_INDIRECT || o.code == op::RETURN_CALL_REF;
            Some((ty.params.len() as u64 + 1, if returns { 0 } else { ty.results.len() as u64 }))
        }
        op::STRUCT_NEW => at(&module.types, insn.a)?.fields.as_ref().map(|f| (f.len() as u64, 1)),
        op::ARRAY_NEW_FIXED => Some((insn.b, 1)),
        op::THROW => Some((tag_params(module, insn.a), 0)),
        op::UNREACHABLE => Some((0, 0)),
        _ => None,
    }
}

/* ------------------------------------------------------------------ *
 * Data segments
 * ------------------------------------------------------------------ */

/// What a 64-bit constant is as a JavaScript number (`Number(v)`), as an integer when it is one.
fn js_number(v: Num) -> i64 {
    match v {
        Num::Number(n) => n,
        Num::BigInt(b) => b as f64 as i64,
    }
}

/// Where passive segments go: a module with shared memory (threads) keeps its data passive and
/// copies it in from the start function — `i32.const dest, i32.const 0, i32.const size,
/// memory.init n` — so that is where the addresses are found.
fn place_passive(module: &WasmModule) -> FxHashMap<u64, i64> {
    let mut placed = FxHashMap::default();
    if !module.data.iter().any(|d| d.mode == DataMode::Passive) {
        return placed;
    }
    let mut candidates: Vec<u64> = Vec::new();
    if let Some(start) = module.start {
        candidates.push(start);
    }
    for (&index, name) in module.names.functions.iter() {
        if (name.contains("init_memory") || name.contains("init_data")) && !candidates.contains(&index) {
            candidates.push(index);
        }
    }
    let mut insn = WasmInsn::new();
    for func in candidates {
        let Some(body) = func.checked_sub(module.imported_funcs).and_then(|b| at(&module.bodies, b)) else { continue };
        let mut consts: [Option<i64>; 3] = [None; 3];
        let mut seen = 0usize;
        let mut pos = body.code;
        while pos < body.end {
            decode_at(&module.bytes, pos, body.end, &mut insn);
            let Some(o) = insn.op else { break };
            if o.code == op::MEMORY_INIT && seen >= 3 {
                if let (Some(dest), Some(offset)) = (consts[0], consts[1]) {
                    placed.entry(insn.a).or_insert(dest - offset);
                }
            }
            let value = if o.code == op::I32_CONST || o.code == op::I64_CONST { Some(js_number(insn.value)) } else { None };
            consts = [consts[1], consts[2], value];
            seen += 1;
            pos += insn.len;
        }
    }
    placed
}

fn data_name(module: &WasmModule, index: u64) -> String {
    module.names.data.get(&index).cloned().unwrap_or_else(|| format!("data[{index}]"))
}

fn lay_out_segments(module: &WasmModule) -> Vec<Segment> {
    let passive = place_passive(module);
    let mut segments = Vec::new();
    for (index, d) in module.data.iter().enumerate() {
        let addr = match d.mode {
            DataMode::Active => d.addr.map(|a| a as i64),
            DataMode::Passive => passive.get(&(index as u64)).copied(),
        };
        let Some(addr) = addr else { continue };
        if d.size == 0 || d.memory != 0 {
            continue;
        }
        segments.push(Segment {
            index: index as u32,
            addr,
            end: addr + d.size as i64,
            start: d.start,
            name: data_name(module, index as u64),
            passive: d.mode == DataMode::Passive,
        });
    }
    segments.sort_by_key(|s| s.addr);
    segments
}

/// At most this many strings are collected from the data segments.
const STRING_LIMIT: usize = 300_000;

/// NUL-terminated runs of text in the data segments: the C strings.
fn find_strings(bytes: &[u8], segments: &[Segment], out: &mut Vec<WasmString>) {
    for (k, segment) in segments.iter().enumerate() {
        let size = (segment.end - segment.addr) as usize;
        let mut start: Option<usize> = None;
        for i in 0..size {
            // Past the end of the file there is nothing: not text, not a NUL.
            let b = bytes.get(segment.start + i).copied();
            if b == Some(0) {
                if let Some(s) = start {
                    if i - s >= 4 {
                        out.push(WasmString { addr: segment.addr + s as i64, text: utf8(&bytes[segment.start + s..segment.start + i]), segment: k as u32, cstring: true });
                        if out.len() >= STRING_LIMIT {
                            return;
                        }
                    }
                }
                start = None;
            } else if !b.is_some_and(is_text) {
                start = None;
            } else if start.is_none() {
                start = Some(i);
            }
        }
    }
}

/// A string that starts at an address inside another one, or one the code gives a length for:
/// its text and whether a NUL ends it (`printableAt` in the TypeScript).
fn printable_at(bytes: &[u8], segments: &[Segment], length_at: &FxHashMap<i64, i64>, addr: i64) -> Option<(String, bool)> {
    let segment = &segments[segment_at(segments, addr)?];
    let from = segment.start as i64 + (addr - segment.addr);
    let to = (from + 160).min(segment.start as i64 + (segment.end - segment.addr)).min(bytes.len() as i64);
    let from = from.min(bytes.len() as i64) as usize;
    let memory = &bytes[from..(to as usize).max(from)];
    let known = length_at.get(&addr).copied();
    let limit = known.map_or(memory.len(), |k| (k.max(0) as usize).min(memory.len()));
    let mut end = 0;
    while end < limit && is_text(memory[end]) {
        end += 1;
    }
    if let Some(k) = known {
        if end as i64 == k && k > 0 {
            return Some((utf8(&memory[..end]), false));
        }
    }
    let terminated = memory.get(end) == Some(&0);
    if end < if terminated { 2 } else { 6 } {
        return None;
    }
    Some((utf8(&memory[..end]), terminated))
}

/* ------------------------------------------------------------------ *
 * The pass over every instruction
 * ------------------------------------------------------------------ */

const FRAME_FUNCTION: u8 = 0;
const FRAME_BLOCK: u8 = 1;
const FRAME_LOOP: u8 = 2;
const FRAME_IF: u8 = 3;
const FRAME_TRY: u8 = 4;

/// What the analysis keeps of a block while it is open.
struct Frame {
    kind: u8,
    /// The instruction that opened it (the first of the function for the function itself).
    start: u32,
    /// The if (or else) waiting for its end, for the arrows; -1 for none.
    open: i64,
    /// Branches waiting for the end of the block: the branch, and its place in a br_table (-1 for others).
    pending: Vec<(u32, i32)>,
    params: u64,
    results: u64,
    /// An if written `if c {` in HLA64.
    sugar: bool,
}

impl Frame {
    fn new(kind: u8, start: u32, open: i64, (params, results): (u64, u64), sugar: bool) -> Frame {
        Frame { kind, start, open, pending: Vec::new(), params, results, sugar }
    }
}

/// A value on the stack while the analysis groups instructions: the instructions that made it.
#[derive(Clone, Copy)]
struct Node {
    start: u32,
    end: u32,
    /// It can be written as an expression inside the instruction that takes it.
    ok: bool,
    /// The value of a lone i32.const / i64.const.
    value: Option<i64>,
}

/// Where a branch goes, as the TypeScript's map held it: one instruction, or a list (a br_table's
/// slots, or the clauses of a try_table, in the order they were found).
enum Target {
    One(u32),
    List(Vec<i32>),
}

fn block_arity(module: &WasmModule, insn: &WasmInsn) -> (u64, u64) {
    match insn.block {
        None | Some(BlockType::Empty) => (0, 0),
        Some(BlockType::Value(_)) => (0, 1),
        Some(BlockType::Type(index)) => at(&module.types, index as u64).and_then(|t| t.func.as_ref()).map_or((0, 0), |f| (f.params.len() as u64, f.results.len() as u64)),
    }
}

/// Do the top `count` values fold into the instruction at `at`: made right before it, one after another, each an expression?
fn folds(nodes: &[Node], count: u64, at: u32) -> bool {
    if count > nodes.len() as u64 {
        return false;
    }
    let mut expected = at as i64;
    for node in nodes[nodes.len() - count as usize..].iter().rev() {
        if !node.ok || node.end as i64 != expected - 1 {
            return false;
        }
        expected = node.start as i64;
    }
    true
}

struct Pass {
    module: WasmModule,
    p: WasmProgram,
    /// Function index → the address calls to it are counted under: its first instruction, or its import entry (-1: none).
    fn_addr: Vec<i64>,
    capacity: i64,
    total: u32,
    next_body: usize,
    mnemonic_of: Vec<u16>,
    targets: FxHashMap<u32, Target>,
    length_at: FxHashMap<i64, i64>,
    callers: RefBuilder,
    data_refs: RefBuilder,
    ref_funcs: RefBuilder,
    global_refs: RefBuilder,
    frames: Vec<Frame>,
    nodes: Vec<Node>,
    insn: WasmInsn,
}

impl Pass {
    fn new(module: WasmModule) -> Pass {
        let mut p = WasmProgram::default();
        let imported_funcs = module.imported_funcs as usize;
        let mut fn_addr = vec![-1i64; imported_funcs + module.bodies.len()];

        // The imported functions, named as the module calls them (or as its name section does).
        for imp in &module.imports {
            if imp.kind != ExternKind::Func {
                continue;
            }
            let raw = module.names.functions.get(&imp.index).unwrap_or(&imp.name).clone();
            let name = demangle_wasm(&raw);
            p.imported.push(ImportedFn { index: imp.index, raw, name });
            if let Ok(index) = usize::try_from(imp.index) {
                if index >= fn_addr.len() {
                    fn_addr.resize(index + 1, -1);
                }
                fn_addr[index] = imp.offset as i64;
            }
        }
        p.segments = lay_out_segments(&module);

        // Functions in tables, by type: what a call_indirect may reach.
        let mut reach: Vec<(u64, u64)> = Vec::new();
        let mut in_table: FxHashSet<(u64, u64)> = FxHashSet::default();
        for element in &module.elements {
            for &func in element.funcs.iter().flatten() {
                let Some(&ty) = at(&module.func_types, func) else { continue };
                if in_table.insert((ty, func)) {
                    reach.push((ty, func));
                }
            }
        }
        // By type, each type's functions in the order the tables have them (a stable sort).
        reach.sort_by_key(|r| r.0);
        for (k, &(ty, func)) in reach.iter().enumerate() {
            if k == 0 || reach[k - 1].0 != ty {
                p.indirect.keys.push(ty as f64);
                p.indirect.starts.push(k as u32);
            }
            p.indirect.values.push(func as u32);
        }
        p.indirect.starts.push(reach.len() as u32);

        // Function addresses must be known before calls are counted: they are the offsets of the first instructions.
        for (i, body) in module.bodies.iter().enumerate() {
            fn_addr[imported_funcs + i] = body.code as i64;
        }
        let capacity = module.bodies.iter().map(|b| b.end as i64 - b.code as i64).sum::<i64>();
        let reserve = capacity.clamp(0, 1 << 26) as usize;
        p.offsets.reserve(reserve);
        p.depth.reserve(reserve);
        p.mnemonic_ids.reserve(reserve);
        p.flags.reserve(reserve);
        Pass {
            p,
            fn_addr,
            capacity,
            total: 0,
            next_body: 0,
            mnemonic_of: vec![u16::MAX; all_ops().len()],
            targets: FxHashMap::default(),
            length_at: FxHashMap::default(),
            callers: RefBuilder::default(),
            data_refs: RefBuilder::default(),
            ref_funcs: RefBuilder::default(),
            global_refs: RefBuilder::default(),
            frames: Vec::new(),
            nodes: Vec::new(),
            insn: WasmInsn::new(),
            module,
        }
    }

    fn func_addr(&self, index: u64) -> i64 {
        usize::try_from(index).ok().and_then(|i| self.fn_addr.get(i)).copied().unwrap_or(-1)
    }

    fn mnemonic_id(&mut self, insn_op: Option<&'static OpInfo>, m: &'static str) -> u16 {
        let slot = insn_op.map(|o| (o as *const OpInfo as usize - all_ops().as_ptr() as usize) / core::mem::size_of::<OpInfo>());
        if let Some(s) = slot {
            if self.mnemonic_of[s] != u16::MAX {
                return self.mnemonic_of[s];
            }
        }
        let id = match self.p.mnemonics.iter().position(|&known| known == m) {
            Some(id) => id as u16,
            None => {
                self.p.mnemonics.push(m);
                self.p.counts.push(0);
                (self.p.mnemonics.len() - 1) as u16
            }
        };
        if let Some(s) = slot {
            self.mnemonic_of[s] = id;
        }
        id
    }

    fn fuse(&mut self, start: u32, end: u32) {
        for k in start..end {
            self.p.flags[k as usize] |= iflag::FUSE;
        }
    }

    fn add_target(&mut self, from: u32, slot: i32, target: u32) {
        match self.targets.get_mut(&from) {
            None => {
                self.targets.insert(from, Target::One(target));
            }
            Some(Target::List(list)) if slot >= 0 => list[slot as usize] = target as i32,
            Some(Target::List(list)) => list.push(target as i32),
            Some(known) => {
                if let Target::One(first) = *known {
                    *known = Target::List(vec![first as i32, target as i32]);
                }
            }
        }
    }

    /// Records a branch to the label `depth_of` blocks out (at `slot` of a br_table); returns how many values it carries.
    fn branch_to(&mut self, from: u32, depth_of: u64, slot: i32) -> u64 {
        let n = self.frames.len() as u64;
        if depth_of >= n {
            return 0;
        }
        let f = (n - 1 - depth_of) as usize;
        if self.frames[f].kind == FRAME_LOOP {
            let start = self.frames[f].start;
            self.add_target(from, slot, start);
            self.p.flags[start as usize] |= iflag::LABEL;
            return self.frames[f].params;
        }
        self.frames[f].pending.push((from, slot));
        self.frames[f].results
    }

    /// Decodes bodies until about `budget` instructions are done; true once all are.
    fn step(&mut self, budget: usize) -> bool {
        let stop = (self.total as usize).saturating_add(budget);
        while self.next_body < self.module.bodies.len() {
            if self.total as usize >= stop {
                return false;
            }
            self.body(self.next_body);
            self.next_body += 1;
        }
        self.finish();
        true
    }

    fn body(&mut self, b: usize) {
        let module = &self.module;
        let (code, end_of_body) = (module.bodies[b].code, module.bodies[b].end);
        let func = module.imported_funcs + b as u64;
        let results = func_type_of(module, func).map_or(0, |t| t.results.len() as u64);
        let first = self.total;
        self.frames.clear();
        self.nodes.clear();
        self.frames.push(Frame::new(FRAME_FUNCTION, first, -1, (0, results), false));
        let mut previous_const: Option<i64> = None;
        let mut insn = core::mem::take(&mut self.insn);
        let mut pos = code;
        while pos < end_of_body && (self.total as i64) < self.capacity {
            let i = self.total;
            self.total += 1;
            decode_at(&self.module.bytes, pos, end_of_body, &mut insn);
            self.p.offsets.push(pos as u32);
            let id = self.mnemonic_id(insn.op, insn.m);
            self.p.mnemonic_ids.push(id);
            self.p.counts[id as usize] += 1;
            let level = self.frames.len().saturating_sub(1);
            self.p.depth.push(level as u16);
            self.p.flags.push(0);
            let iu = i as usize;
            pos += insn.len;
            let Some(o) = insn.op else {
                self.p.flags[iu] |= iflag::UNKNOWN;
                self.nodes.clear();
                continue;
            };
            let code = o.code;

            if o.flags & w::STRUCTURE != 0 {
                match code {
                    op::BLOCK | op::LOOP | op::TRY | op::TRY_TABLE => {
                        let arity = block_arity(&self.module, &insn);
                        let kind = match code {
                            op::LOOP => FRAME_LOOP,
                            op::BLOCK => FRAME_BLOCK,
                            _ => FRAME_TRY,
                        };
                        if code == op::TRY_TABLE {
                            // Catch clauses go to labels outside the try_table.
                            for c in &insn.catches {
                                self.branch_to(i, c.label, -1);
                            }
                            if !insn.catches.is_empty() {
                                self.p.flags[iu] |= iflag::BRANCH;
                            }
                        }
                        self.frames.push(Frame::new(kind, i, -1, arity, false));
                    }
                    op::IF => {
                        let arity = block_arity(&self.module, &insn);
                        // `if c {` when the condition is in the line and no values go in or out of the block.
                        let fold = arity == (0, 0) && folds(&self.nodes, 1, i);
                        if fold {
                            self.fuse(self.nodes[self.nodes.len() - 1].start, i);
                            self.p.flags[iu] |= wflag::SUGAR_IF;
                        }
                        self.frames.push(Frame::new(FRAME_IF, i, i as i64, arity, fold));
                        self.p.flags[iu] |= iflag::BRANCH;
                    }
                    op::ELSE | op::CATCH | op::CATCH_ALL => {
                        self.p.depth[iu] = level.saturating_sub(1) as u16;
                        if let Some(frame) = self.frames.last_mut() {
                            if frame.kind == FRAME_IF && code == op::ELSE {
                                if frame.sugar {
                                    self.p.flags[iu] |= wflag::IF_END;
                                }
                                let open = frame.open as u32;
                                frame.open = i as i64;
                                self.targets.insert(open, Target::One(i));
                                self.p.flags[iu] |= iflag::BRANCH;
                            }
                        }
                    }
                    op::END | op::DELEGATE => {
                        self.p.depth[iu] = level.saturating_sub(1) as u16;
                        if let Some(frame) = self.frames.pop() {
                            if frame.kind == FRAME_IF && frame.open >= 0 {
                                self.targets.insert(frame.open as u32, Target::One(i));
                            }
                            if frame.kind == FRAME_IF && frame.sugar {
                                self.p.flags[iu] |= wflag::IF_END;
                            }
                            if !frame.pending.is_empty() {
                                for &(from, slot) in &frame.pending {
                                    self.add_target(from, slot, i);
                                }
                                self.p.flags[iu] |= iflag::LABEL;
                            }
                            // The function's end returns what is on the stack.
                            if frame.kind == FRAME_FUNCTION && results == 1 && folds(&self.nodes, 1, i) {
                                self.fuse(self.nodes[self.nodes.len() - 1].start, i);
                            }
                        }
                    }
                    _ => {}
                }
                self.nodes.clear();
                previous_const = None;
                continue;
            }

            if o.flags & w::BRANCH != 0 || code == op::RETURN {
                self.p.flags[iu] |= iflag::BRANCH;
                let mut pops: i64 = -1;
                match code {
                    op::BR => {
                        if self.branch_to(i, insn.a, -1) == 0 {
                            pops = 0;
                        }
                    }
                    op::BR_IF => {
                        if self.branch_to(i, insn.a, -1) == 0 {
                            pops = 1;
                        }
                    }
                    op::BR_TABLE => {
                        let mut arity = 0;
                        self.targets.insert(i, Target::List(vec![-1; insn.labels.len()]));
                        let labels = core::mem::take(&mut insn.labels);
                        for (slot, &label) in labels.iter().enumerate() {
                            arity = self.branch_to(i, label, slot as i32);
                        }
                        insn.labels = labels;
                        if arity == 0 {
                            pops = 1;
                        }
                    }
                    op::RETURN => {
                        self.p.flags[iu] &= !iflag::BRANCH;
                        if results <= 1 {
                            pops = results as i64;
                        }
                    }
                    // br_on_null, br_on_cast…: they leave values behind; the line stays an instruction.
                    _ => {
                        self.branch_to(i, insn.a, -1);
                    }
                }
                if pops < 0 {
                    self.p.value_branches.push(i);
                }
                if pops > 0 && folds(&self.nodes, pops as u64, i) {
                    self.fuse(self.nodes[self.nodes.len() - pops as usize].start, i);
                }
                self.nodes.clear();
                previous_const = None;
                continue;
            }

            let Some((pops, pushes)) = effect(&insn, &self.module) else {
                self.nodes.clear();
                previous_const = None;
                continue;
            };
            let fold = folds(&self.nodes, pops, i);
            let len = self.nodes.len();
            let start = if fold && pops > 0 { self.nodes[len - pops as usize].start } else { i };
            let mut const_value: Option<i64> = None;

            // Memory at a constant address: the address operand is the first value taken.
            if o.imm == imm::MEMARG || o.imm == imm::MEMARG_LANE {
                let address = if pops <= len as u64 { self.nodes.get(len - pops as usize) } else { None };
                if let (Some(a), Num::Number(offset)) = (address, insn.value) {
                    if a.start == a.end {
                        if let Some(value) = a.value {
                            // A JavaScript sum: past 2^53 it rounds as a double does.
                            self.data_refs.add((value as i128 + offset as i128) as f64 as i64, i);
                        }
                    }
                }
            }
            if o.imm == imm::I32 || o.imm == imm::I64 {
                if let Num::Number(value) = insn.value {
                    const_value = Some(value);
                    if value > 0 && segment_at(&self.p.segments, value).is_some() {
                        self.data_refs.add(value, i);
                    }
                    // Rust passes a &str as a pointer and then its length.
                    if let Some(previous) = previous_const {
                        if value > 0 && value < 4096 && segment_at(&self.p.segments, previous).is_some() {
                            self.length_at.entry(previous).and_modify(|seen| *seen = (*seen).min(value)).or_insert(value);
                        }
                    }
                }
            }
            match code {
                op::CALL | op::RETURN_CALL => {
                    self.p.flags[iu] |= iflag::CALL;
                    self.callers.add(self.func_addr(insn.a), i);
                }
                op::CALL_INDIRECT | op::RETURN_CALL_INDIRECT | op::CALL_REF | op::RETURN_CALL_REF => {
                    self.p.flags[iu] |= iflag::CALL;
                    self.p.indirect_calls += 1;
                }
                op::REF_FUNC => self.ref_funcs.add(self.func_addr(insn.a), i),
                op::GLOBAL_GET | op::GLOBAL_SET => self.global_refs.add(insn.a as i64, i),
                _ => {}
            }

            if pops > len as u64 {
                self.nodes.clear();
            } else {
                self.nodes.truncate(len - pops as usize);
            }
            if pushes == 0 {
                if fold && pops > 0 {
                    self.fuse(start, i);
                }
            } else if pushes == 1 {
                self.nodes.push(Node { start, end: i, ok: fold || pops == 0, value: const_value });
            } else {
                for _ in 0..pushes {
                    self.nodes.push(Node { start: i, end: i, ok: false, value: None });
                }
            }
            if o.flags & w::END != 0 {
                self.nodes.clear();
            }
            previous_const = const_value;
        }
        self.insn = insn;
        let count = self.total - first;
        if count > 0 {
            self.p.flags[first as usize] |= iflag::FUNCTION;
        }
        self.p.bodies.push(Function { index: func, addr: code, first, count, kind: FnKind::Anonymous, name: None });
    }

    /// Names, kinds and strings, once every instruction is decoded.
    fn finish(&mut self) {
        let module = &self.module;
        let p = &mut self.p;
        let total = p.flags.len();

        // Names and kinds.
        let mut exports: FxHashMap<u64, &str> = FxHashMap::default();
        let mut exported: FxHashSet<u64> = FxHashSet::default();
        for e in &module.exports {
            if e.kind == ExternKind::Func {
                exports.entry(e.index).or_insert(&e.name);
                exported.insert(e.index);
            }
        }
        let mut symbols: FxHashMap<i64, &str> = FxHashMap::default();
        for s in module.linking.iter().flat_map(|l| &l.symbols) {
            if s.kind == SymbolKind::Function && !s.name.is_empty() {
                symbols.entry(s.index).or_insert(&s.name);
            }
        }
        for f in p.bodies.iter_mut().filter(|f| f.count > 0) {
            let index = f.index;
            let raw = module.names.functions.get(&index).map(String::as_str).or_else(|| symbols.get(&(index as i64)).copied()).or_else(|| exports.get(&index).copied());
            let raw = raw.filter(|r| !r.is_empty());
            if let Some(raw) = raw {
                f.name = Some((raw.to_string(), demangle_wasm(raw)));
            }
            f.kind = if Some(index) == module.start {
                FnKind::Entry
            } else if exported.contains(&index) {
                FnKind::Export
            } else if raw.is_some() {
                FnKind::Symbol
            } else {
                FnKind::Anonymous
            };
        }

        // Branches into the end of their own function stay; labels on a function's first instruction are not shown twice.
        for k in 0..total.saturating_sub(1) {
            if p.flags[k] & iflag::FUSE != 0 && p.flags[k + 1] & iflag::FUNCTION != 0 {
                p.flags[k] &= !iflag::FUSE;
            }
        }

        let bytes = &module.bytes;
        find_strings(bytes, &p.segments, &mut p.strings);
        // A Rust literal has no NUL: the length its code passes cuts it from the next one.
        for s in p.strings.iter_mut() {
            if let Some(&length) = self.length_at.get(&s.addr) {
                if length > 0 && (length as usize) < s.text.len() {
                    s.text = utf8(&s.text.as_bytes()[..length as usize]);
                    s.cstring = false;
                }
            }
        }
        let data_refs = core::mem::take(&mut self.data_refs).build();
        // Strings code points at that the scan did not find (no NUL, or short).
        let known: FxHashSet<i64> = p.strings.iter().map(|s| s.addr).collect();
        for &key in &data_refs.keys {
            let addr = key as i64;
            if known.contains(&addr) {
                continue;
            }
            if let Some((text, _)) = printable_at(bytes, &p.segments, &self.length_at, addr) {
                let segment = segment_at(&p.segments, addr).unwrap() as u32;
                p.strings.push(WasmString { addr, text, segment, cstring: false });
            }
        }
        p.strings.sort_by_key(|s| s.addr);

        p.data_refs = data_refs;
        p.callers = core::mem::take(&mut self.callers).build();
        p.ref_funcs = core::mem::take(&mut self.ref_funcs).build();
        p.global_refs = core::mem::take(&mut self.global_refs).build();
        let mut lengths: Vec<(i64, i64)> = self.length_at.iter().map(|(&a, &l)| (a, l)).collect();
        lengths.sort_unstable();
        p.length_addr = lengths.iter().map(|&(a, _)| a as f64).collect();
        p.length_value = lengths.iter().map(|&(_, l)| l as f64).collect();
        let mut targets: Vec<(u32, Target)> = core::mem::take(&mut self.targets).into_iter().collect();
        targets.sort_unstable_by_key(|t| t.0);
        for (from, target) in targets {
            p.target_index.push(from);
            p.target_starts.push(p.target_values.len() as u32);
            match target {
                Target::One(t) => p.target_values.push(t as i32),
                Target::List(list) => p.target_values.extend_from_slice(&list),
            }
        }
        p.target_starts.push(p.target_values.len() as u32);
    }
}

/// Analysing a WebAssembly module, in steps.
pub struct WasmSession {
    pass: Option<Box<Pass>>,
    program: Option<WasmProgram>,
    /// The module, kept once the pass is over for the HLA64 lines of the rows on screen.
    module: Option<WasmModule>,
    lines: Option<WasmLines>,
}

impl WasmSession {
    pub fn open(file: Vec<u8>) -> Result<WasmSession, ParseError> {
        let module = parse_wasm(file)?;
        Ok(WasmSession { pass: Some(Box::new(Pass::new(module))), program: None, module: None, lines: None })
    }

    /// Works on for about `budget` instructions; true once the program is ready.
    pub fn step(&mut self, budget: usize) -> bool {
        let Some(pass) = self.pass.as_mut() else { return true };
        if !pass.step(budget) {
            return false;
        }
        let pass = self.pass.take().unwrap();
        let Pass { p, total, module, .. } = *pass;
        debug_assert_eq!(total as usize, p.offsets.len());
        self.lines = Some(WasmLines::new(&p, &module));
        self.program = Some(p);
        self.module = Some(module);
        true
    }

    pub fn module(&self) -> Option<&WasmModule> {
        self.module.as_ref()
    }

    /// Decodes an instruction of the program into `insn`, as the page shows it: up to the end of its
    /// function's body (or of the file, outside every function). False before the program is ready.
    pub fn decode_insn(&self, index: usize, insn: &mut WasmInsn) -> bool {
        let (Some(p), Some(module), Some(lines)) = (self.program.as_ref(), self.module.as_ref(), self.lines.as_ref()) else { return false };
        let Some(&pos) = p.offsets.get(index) else { return false };
        let end = lines.body_of(p, index).map_or(module.bytes.len(), |b| module.bodies[b].end);
        decode_at(&module.bytes, pos as usize, end, insn);
        true
    }

    /// The HLA64 line of the instructions first..=last, once the program is ready.
    pub fn lift_group(&self, first: usize, last: usize, names: &dyn WasmNaming) -> Option<HlaLine> {
        let (p, module, lines) = (self.program.as_ref()?, self.module.as_ref()?, self.lines.as_ref()?);
        if first > last || last >= p.offsets.len() {
            return None;
        }
        lift_group(p, module, lines, first, last, names)
    }

    /// How far the work is: bodies decoded, of how many.
    pub fn progress(&self) -> (usize, usize) {
        match (&self.pass, &self.program) {
            (Some(pass), _) => (pass.next_body, pass.module.bodies.len()),
            (None, Some(p)) => (p.bodies.len(), p.bodies.len()),
            _ => (0, 0),
        }
    }

    pub fn program(&self) -> Option<&WasmProgram> {
        self.program.as_ref()
    }

    /// Analyses a module at once.
    pub fn analyse(file: Vec<u8>) -> Result<WasmProgram, ParseError> {
        let mut session = WasmSession::open(file)?;
        while !session.step(usize::MAX) {}
        Ok(session.program.take().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::op;
    use crate::wasm::opcodes::op_info;

    #[test]
    fn opcodes_are_the_named_ones() {
        let named = [
            (op::UNREACHABLE, "unreachable"),
            (op::BLOCK, "block"),
            (op::LOOP, "loop"),
            (op::IF, "if"),
            (op::ELSE, "else"),
            (op::TRY, "try"),
            (op::CATCH, "catch"),
            (op::THROW, "throw"),
            (op::END, "end"),
            (op::BR, "br"),
            (op::BR_IF, "br_if"),
            (op::BR_TABLE, "br_table"),
            (op::RETURN, "return"),
            (op::CALL, "call"),
            (op::CALL_INDIRECT, "call_indirect"),
            (op::RETURN_CALL, "return_call"),
            (op::RETURN_CALL_INDIRECT, "return_call_indirect"),
            (op::CALL_REF, "call_ref"),
            (op::RETURN_CALL_REF, "return_call_ref"),
            (op::DELEGATE, "delegate"),
            (op::CATCH_ALL, "catch_all"),
            (op::TRY_TABLE, "try_table"),
            (op::GLOBAL_GET, "global.get"),
            (op::GLOBAL_SET, "global.set"),
            (op::I32_CONST, "i32.const"),
            (op::I64_CONST, "i64.const"),
            (op::REF_FUNC, "ref.func"),
            (op::STRUCT_NEW, "struct.new"),
            (op::ARRAY_NEW_FIXED, "array.new_fixed"),
            (op::MEMORY_INIT, "memory.init"),
        ];
        for (code, name) in named {
            assert_eq!(op_info(code).map(|o| o.name), Some(name));
        }
        // Only `return` among these is a branch by its name rather than its flags.
        for o in crate::wasm::opcodes::all_ops() {
            assert!(o.sig.is_empty() || o.sig.contains('>'), "{}", o.name);
        }
    }
}
