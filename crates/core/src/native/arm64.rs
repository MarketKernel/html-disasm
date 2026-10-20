//! An arm64 program around its pass (a port of the rest of `analyze` in
//! src/core/program.ts): the code ranges the pass reads, and afterwards the
//! stubs of an ELF PLT or a Windows import table, the functions and their
//! names, a stripped program's main, and the strings code points at.

use super::functions::{name_main, windows_main, Call, Callee, Function, Kind, Starts, StartupCode};
use super::image::{Format, NativeImage};
use super::{Found, FoundString};
use crate::arm64::pass::{written_reg, Arm64Pass, Arm64Refs};
use crate::arm64::types::{f, Insn, Mode, Op};
use crate::arm64::{decode, format_insn};
use crate::disassembly::iflag;
use crate::macho::NumberMap;
use crate::refs::{FxHashMap, FxHashSet};

/// The code sections the pass reads, by index in the image, in address order.
pub fn code_sections(image: &NativeImage) -> Vec<usize> {
    let mut code: Vec<usize> = (0..image.sections.len()).filter(|&k| image.sections[k].code && image.sections[k].size >= 4.0 && image.sections[k].offset != 0.0).collect();
    code.sort_by(|&a, &b| image.sections[a].addr.partial_cmp(&image.sections[b].addr).unwrap_or(core::cmp::Ordering::Equal));
    code
}

/// What the pass is opened with: the ranges (address, file offset, instruction count), the import
/// slots of a PE file, and whether it is one.
pub fn pass_input(image: &NativeImage) -> (Vec<(i64, u64, u32)>, Vec<i64>, bool) {
    let ranges =
        code_sections(image).into_iter().map(|k| (image.sections[k].addr as i64, image.sections[k].offset as u64, (image.sections[k].size / 4.0).floor() as u32)).collect();
    let pe = image.format == Format::Pe;
    let slots = if pe { image.slots.entries.iter().map(|&(slot, _)| slot as i64).collect() } else { Vec::new() };
    (ranges, slots, pe)
}

/// `^[xw](\d+)$` as a register number, or -1.
fn reg_index(op: Option<&Op>) -> i32 {
    let Some(Op::Reg(r)) = op else { return -1 };
    let b = r.as_bytes();
    if b.len() < 2 || !(b[0] == b'x' || b[0] == b'w') || !b[1..].iter().all(u8::is_ascii_digit) {
        return -1;
    }
    r.as_str()[1..].parse().unwrap_or(-1)
}

fn mem_of(op: Option<&Op>) -> Option<&crate::arm64::types::Mem> {
    match op {
        Some(Op::Mem(m)) => Some(m),
        _ => None,
    }
}

/// The program as the analysis after the pass sees it.
struct Program<'a> {
    image: &'a NativeImage,
    pass: &'a Arm64Pass,
    sections: Vec<usize>,
    functions: Vec<Function>,
    function_at_index: FxHashMap<u32, usize>,
}

impl Program<'_> {
    fn total(&self) -> u32 {
        self.pass.words.len() as u32
    }

    fn addr_of(&self, index: u32) -> f64 {
        self.pass.addr_of(index) as f64
    }

    fn index_of(&self, addr: f64) -> i64 {
        if !addr.is_finite() {
            return -1;
        }
        for r in &self.pass.ranges {
            let start = r.addr as f64;
            if addr >= start && addr < start + r.count as f64 * 4.0 {
                return r.first as i64 + ((addr - start) / 4.0).floor() as i64;
            }
        }
        -1
    }

    fn range_end(&self, index: u32) -> u32 {
        self.pass.ranges.iter().find(|r| index >= r.first && index < r.first + r.count).map_or(index, |r| r.first + r.count)
    }

    fn insn(&self, index: u32) -> Insn {
        decode(self.pass.words[index as usize], self.addr_of(index) as i64)
    }

    fn text(&self, index: u32) -> String {
        format_insn(&self.insn(index)).as_str().to_string()
    }

    /// The function an instruction belongs to (binary search), or -1.
    fn function_of_index(&self, index: i64) -> i64 {
        let (mut lo, mut hi, mut found) = (0i64, self.functions.len() as i64 - 1, -1i64);
        while lo <= hi {
            let mid = (lo + hi) >> 1;
            if self.functions[mid as usize].first as i64 <= index {
                found = mid;
                lo = mid + 1;
            } else {
                hi = mid - 1;
            }
        }
        if found < 0 {
            return -1;
        }
        let f = &self.functions[found as usize];
        if index < f.first as i64 + f.count as i64 {
            found
        } else {
            -1
        }
    }

    fn function_at(&self, addr: f64) -> Option<usize> {
        let index = self.index_of(addr);
        if index < 0 {
            return None;
        }
        self.function_at_index.get(&(index as u32)).copied()
    }
}

/// The stubs of an ELF PLT, named after the GOT slot each one jumps through:
/// `adrp x16, page; ldr x17, [x16, #off]; add x16, …; br x17`, the header's padding left out.
fn plt_stubs(p: &Program) -> NumberMap<String> {
    let mut stubs: NumberMap<String> = NumberMap::default();
    for (k, r) in p.pass.ranges.iter().enumerate() {
        let name = &p.image.sections[p.sections[k]].name;
        if !(name.starts_with(".plt") || name.starts_with(".iplt")) {
            continue;
        }
        let mut start = r.addr as f64;
        let mut page = -1.0f64;
        for i in 0..r.count {
            let pc = r.addr as f64 + i as f64 * 4.0;
            let insn = decode(p.pass.words[(r.first + i) as usize], pc as i64);
            if insn.m.as_str() == "adrp" && reg_index(insn.ops.first()) == 16 {
                page = insn.target.unwrap_or(0) as f64;
            } else if insn.m.as_str() == "ldr" && page >= 0.0 {
                if let Some(mem) = mem_of(insn.ops.get(1)) {
                    if mem.base.as_str() == "x16" {
                        if let Some(name) = p.image.slots.get(page + mem.off as f64).filter(|n| !n.is_empty()) {
                            stubs.set(start, name.clone());
                        }
                    }
                }
            } else if insn.f & f::BRANCH != 0 {
                start = pc + 4.0;
                page = -1.0;
            } else if insn.m.as_str() == "nop" && start == pc {
                start = pc + 4.0; // the header's padding
            }
        }
    }
    stubs
}

/// The import thunks of a Windows program: `adrp xN, page; ldr xN, [xN, #off]; br xN`.
fn import_thunks(p: &Program) -> NumberMap<String> {
    let mut thunks: NumberMap<String> = NumberMap::default();
    let words = &p.pass.words;
    for r in &p.pass.ranges {
        let mut i = r.first;
        while i + 2 < r.first + r.count {
            let adrp = words[i as usize];
            let br = words[i as usize + 2];
            let here = i;
            i += 1;
            // adrp xN, …  then  br xN (with N the same register)
            if adrp & 0x9f00_0000 != 0x9000_0000 || br & 0xffff_fc1f != 0xd61f_0000 || (br >> 5) & 31 != adrp & 31 {
                continue;
            }
            let pc = p.addr_of(here);
            let page = decode(adrp, pc as i64);
            let ldr = decode(words[here as usize + 1], pc as i64 + 4);
            let reg = (adrp & 31) as i32;
            let Some(mem) = mem_of(ldr.ops.get(1)) else { continue };
            if ldr.m.as_str() != "ldr" || reg_index(ldr.ops.first()) != reg || mem.mode != Mode::Off || mem.base.as_str() != format!("x{reg}") {
                continue;
            }
            if let Some(name) = p.image.slots.get(page.target.unwrap_or(0) as f64 + mem.off as f64).filter(|n| !n.is_empty()) {
                thunks.set(pc, name.clone());
            }
        }
    }
    thunks
}

/// Where main is, for an ELF program without symbols: what the entry point passes to
/// __libc_start_main in x0 (adrp + add, adr, or a load from the GOT).
fn main_of(p: &Program) -> Option<f64> {
    let image = p.image;
    if image.format != Format::Elf {
        return None;
    }
    let entry = p.index_of(image.entry?);
    if entry < 0 {
        return None;
    }
    let mut regs = [f64::NAN; 31];
    let value = |regs: &[f64; 31], op: Option<&Op>| {
        let r = reg_index(op);
        if (0..31).contains(&r) {
            regs[r as usize]
        } else {
            f64::NAN
        }
    };
    let end = (entry as u32 + 32).min(p.total());
    for i in entry as u32..end {
        let insn = p.insn(i);
        if insn.f & f::CALL != 0 {
            let target = insn.target?;
            if image.stubs.get(target as f64).map(String::as_str) != Some("__libc_start_main") {
                return None;
            }
            return (p.index_of(regs[0]) >= 0).then_some(regs[0]);
        }
        if insn.f & f::BRANCH != 0 {
            return None;
        }
        let written = written_reg(&insn);
        if written < 0 {
            continue;
        }
        let mut v = f64::NAN;
        let m = insn.m.as_str();
        if m == "adr" || m == "adrp" {
            v = insn.target.map_or(f64::NAN, |t| t as f64);
        } else if m == "add" && insn.ops.len() == 3 {
            if let Some(Op::Imm { v: imm, .. }) = insn.ops.get(2) {
                v = value(&regs, insn.ops.get(1)) + imm;
            }
        } else if m == "ldr" && matches!(insn.ops.first(), Some(Op::Reg(r)) if r.as_str().starts_with('x')) {
            if let Some(mem) = mem_of(insn.ops.get(1)) {
                let base = mem.base.as_str();
                let number = base.strip_prefix('x').filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())).and_then(|n| n.parse::<usize>().ok());
                if mem.index.is_none() && mem.mode == Mode::Off {
                    if let Some(n) = number {
                        let slot = regs.get(n).copied().unwrap_or(f64::NAN) + mem.off as f64;
                        v = if slot.is_nan() { f64::NAN } else { image.slot_value(slot, 8).unwrap_or(f64::NAN) };
                    }
                }
            }
        }
        if (written as usize) < 31 {
            regs[written as usize] = v;
        }
    }
    None
}

struct Startup<'a, 'b> {
    p: &'a Program<'b>,
}

impl StartupCode for Startup<'_, '_> {
    fn straight(&self, from: u32, to: u32) -> bool {
        for i in from + 1..to {
            let insn = self.p.insn(i);
            let m = insn.m.as_str();
            let conditional = m.starts_with("b.") || m.starts_with("cbz") || m.starts_with("cbnz") || m.starts_with("tbz") || m.starts_with("tbnz");
            if (insn.f & f::BRANCH != 0 && !conditional) || matches!(m, "brk" | "udf" | "hlt") {
                return false;
            }
        }
        true
    }

    fn argc(&self, from: u32, to: u32) -> bool {
        (from + 1..to).any(|i| self.p.text(i) == "ldr w0, [x0]")
    }

    fn instance(&self, from: u32, to: u32) -> bool {
        let base_addr = self.p.image.pe.as_ref().map(|pe| pe.image_base);
        let mut base = -1;
        let (mut first, mut second) = (false, false);
        for i in from + 1..to {
            let insn = self.p.insn(i);
            let text = format_insn(&insn).as_str().to_string();
            if insn.m.as_str() == "adrp" && insn.target.map(|t| t as f64) == base_addr {
                base = reg_index(insn.ops.first());
            } else if base >= 0 && text == format!("add x0, x{base}, #0x0") {
                first = true;
            } else if matches!(text.as_str(), "mov x1, #0x0" | "mov w1, #0x0" | "mov x1, xzr" | "mov x1, wzr" | "mov w1, xzr" | "mov w1, wzr") {
                second = true;
            }
        }
        first && second
    }

    // No arm64 runtime keeps argc in a global for main.
    fn globals(&self, _: u32, _: u32) -> bool {
        false
    }
}

/// The analysis after the pass: stubs, functions, a stripped program's main, the joins a label
/// breaks, and the strings. Sets the FUNCTION flags (and clears FUSE where it must) in the pass.
pub fn after_pass(image: &mut NativeImage, pass: &mut Arm64Pass, refs: &Arm64Refs) -> Found {
    let sections = code_sections(image);
    let found_stubs: Vec<(f64, String)> = {
        let p = Program { image, pass, sections: sections.clone(), functions: Vec::new(), function_at_index: FxHashMap::default() };
        match image.format {
            Format::Elf => plt_stubs(&p).entries,
            Format::Pe => import_thunks(&p).entries,
            Format::MachO => Vec::new(),
        }
    };
    for (at, name) in &found_stubs {
        image.stubs.set(*at, name.clone());
    }
    let image: &NativeImage = image;

    // Strings: the C-string sections, whole.
    let mut strings: Vec<FoundString> = image.cstrings().into_iter().map(|(addr, text, section)| FoundString { addr, text, section, cstring: true }).collect();
    let string_at: FxHashSet<u64> = strings.iter().map(|s| crate::macho::number_key(s.addr)).collect();

    // Functions.
    let (functions, function_at_index) = {
        let p = Program { image, pass, sections: sections.clone(), functions: Vec::new(), function_at_index: FxHashMap::default() };
        let mut starts = Starts::default();
        let add = |starts: &mut Starts, addr: f64, raw: Option<&str>, kind: Kind| {
            if p.index_of(addr) >= 0 {
                starts.add(addr, raw, kind);
            }
        };
        for (k, r) in p.pass.ranges.iter().enumerate() {
            let section = &image.sections[p.sections[k]];
            add(&mut starts, r.addr as f64, None, Kind::Anonymous);
            if let Some(stride) = section.stub_size {
                let mut at = section.addr;
                while at < section.addr + section.size {
                    let name = image.stubs.get(at);
                    add(&mut starts, at, name.map(String::as_str), if name.is_some_and(|n| !n.is_empty()) { Kind::Import } else { Kind::Anonymous });
                    at += stride;
                }
            }
        }
        // ELF stubs are found by reading the PLT, not by a stride.
        if image.format != Format::MachO {
            for (at, name) in &image.stubs.entries {
                let (raw, import) = image.stub_function(name);
                add(&mut starts, *at, Some(&raw), if import { Kind::Import } else { Kind::Symbol });
            }
        }
        for &addr in &image.function_starts {
            add(&mut starts, addr, None, Kind::Anonymous);
        }
        // Exports first: a function both exported and in the symbol table is listed as exported.
        for e in &image.exports {
            add(&mut starts, e.addr, Some(&e.name), Kind::Export);
        }
        for s in &image.symbols {
            if !s.name.is_empty() {
                add(&mut starts, s.addr, Some(&s.name), Kind::Symbol);
            }
        }
        for &target in &refs.callers.keys {
            add(&mut starts, target, None, Kind::Anonymous);
        }
        if let Some(entry) = image.entry {
            let raw = starts.raw(entry).map(String::from).unwrap_or_else(|| image.entry_name().into());
            add(&mut starts, entry, Some(&raw), Kind::Entry);
        }
        // A stripped Linux program's main is what _start hands to __libc_start_main.
        if let Some(main) = main_of(&p) {
            if starts.raw(main).is_none_or(str::is_empty) {
                add(&mut starts, main, Some("main"), Kind::Symbol);
            }
        }
        let functions = starts.build(image, &|addr| p.index_of(addr), &|first| p.range_end(first), true);
        let mut at_index = FxHashMap::default();
        for (k, f) in functions.iter().enumerate() {
            at_index.insert(f.first, k);
        }
        (functions, at_index)
    };
    for f in &functions {
        pass.flags[f.first as usize] |= iflag::FUNCTION;
    }

    // A stripped Windows program's main is found from how its C runtime calls it.
    let functions = {
        let p = Program { image, pass, sections, functions, function_at_index };
        if image.format != Format::Pe {
            p.functions
        } else {
            let slot_calls: FxHashMap<u32, f64> = refs.slot_call_index.iter().copied().zip(refs.slot_call_slot.iter().copied()).collect();
            let mut calls: Vec<Call> = Vec::new();
            for r in &p.pass.ranges {
                for i in r.first..r.first + r.count {
                    let word = p.pass.words[i as usize];
                    if let Some(&slot) = slot_calls.get(&i) {
                        let name = image.slots.get(slot).cloned().unwrap_or_default();
                        calls.push(Call { at: i, within: p.function_of_index(i as i64), callee: Callee::Import(name) });
                        continue;
                    }
                    if word & 0xfc00_0000 != 0x9400_0000 {
                        continue; // bl
                    }
                    let target = p.addr_of(i) + (((word << 6) as i32 >> 6) as f64) * 4.0;
                    if let Some(callee) = p.function_at(target) {
                        if p.functions[callee].addr == target {
                            calls.push(Call { at: i, within: p.function_of_index(i as i64), callee: Callee::Function(callee) });
                        }
                    }
                }
            }
            // The entry point, and what it calls or jumps to, two steps deep.
            let mut startup: FxHashSet<i64> = FxHashSet::default();
            let entry = image.entry.map_or(-1, |e| p.index_of(e));
            let mut level: Vec<i64> = if entry >= 0 { vec![p.function_of_index(entry)] } else { Vec::new() };
            let mut depth = 0;
            while depth < 3 && !level.is_empty() {
                let mut next = Vec::new();
                for &at in &level {
                    if at < 0 || !startup.insert(at) {
                        continue;
                    }
                    let func = &p.functions[at as usize];
                    if depth < 2 {
                        for i in func.first..func.first + func.count {
                            let insn = p.insn(i);
                            let Some(target) = insn.target else { continue };
                            if insn.f & (f::BRANCH | f::CALL) == 0 {
                                continue;
                            }
                            let index = p.index_of(target as f64);
                            if index >= 0 {
                                next.push(p.function_of_index(index));
                            }
                        }
                    }
                }
                level = next;
                depth += 1;
            }
            let found = windows_main(&calls, &startup, &p.functions, &Startup { p: &p });
            let mut out = p.functions;
            name_main(&mut out, found);
            out
        }
    };

    // The listing should not join an instruction with one that a branch also reaches.
    let total = pass.flags.len();
    for i in 0..total.saturating_sub(1) {
        if pass.flags[i] & iflag::FUSE != 0 && pass.flags[i + 1] & (iflag::LABEL | iflag::FUNCTION) != 0 {
            pass.flags[i] &= !iflag::FUSE;
        }
    }

    // Strings in constant data that code points at (Rust keeps its literals there, without a NUL).
    let length_at: FxHashMap<u64, f64> = refs.length_addr.iter().zip(&refs.length_value).map(|(&a, &l)| (crate::macho::number_key(a), l as f64)).collect();
    for &addr in &refs.data_refs.keys {
        if string_at.contains(&crate::macho::number_key(addr)) || image.objc_data(addr).is_some() {
            continue;
        }
        if let Some((text, _)) = image.text_at(addr, length_at.get(&crate::macho::number_key(addr)).copied()) {
            strings.push(FoundString { addr, text, section: image.section_of(addr).map(|s| s.name.clone()).unwrap_or_default(), cstring: false });
        }
    }
    strings.sort_by(|a, b| a.addr.partial_cmp(&b.addr).unwrap_or(core::cmp::Ordering::Equal));
    Found { functions, strings, stubs: found_stubs }
}
