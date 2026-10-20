//! An x86 program around its pass (a port of the rest of `analyzeX86` in
//! src/core/x86/program.ts): what the pass is opened with — where functions
//! are known to start, the data among the instructions, the addresses that
//! name something — and afterwards the stubs, the functions and their names
//! (with the `j_` names of jump thunks), a stripped program's main, and the
//! strings.

use super::functions::{name_main, windows_main, Call, Callee, Function, Kind, Starts, StartupCode};
use super::image::{Format, NativeImage, NumberSet};
use super::{Found, FoundString};
use crate::disassembly::iflag;
use crate::refs::{FxHashMap, FxHashSet};
use crate::x86::decode::decode_x86;
use crate::x86::pass::{DataRegion, X86Input, X86Pass, X86Refs};
use crate::x86::print::{format_x86, print_x86};

/// The image as the pass reads it: its format, bytes and sections.
pub fn core_image(image: &NativeImage) -> crate::image::Image {
    crate::image::Image {
        format: match image.format {
            Format::MachO => crate::image::Format::MachO,
            Format::Elf => crate::image::Format::Elf,
            Format::Pe => crate::image::Format::Pe,
        },
        bytes: image.bytes.clone(),
        sections: image
            .sections
            .iter()
            .map(|s| crate::image::Section {
                name: s.name.clone(),
                addr: s.addr as i64,
                size: s.size as i64,
                offset: s.offset as i64,
                code: s.code,
                cstrings: s.cstrings,
                zerofill: s.zerofill,
                writable: s.writable,
                stub_size: s.stub_size.unwrap_or(0.0) as u32,
            })
            .collect(),
    }
}

/// What an x86 pass is opened with.
pub fn pass_input(image: &NativeImage) -> X86Input {
    let mode: u8 = if image.arch == "x86_64" { 64 } else { 32 };
    let mut sections: Vec<&super::image::ImageSection> = image.sections.iter().filter(|s| s.code && s.size != 0.0 && s.offset != 0.0).collect();
    sections.sort_by(|a, b| a.addr.partial_cmp(&b.addr).unwrap_or(core::cmp::Ordering::Equal));
    let in_code = |addr: f64| sections.iter().any(|s| addr >= s.addr && addr < s.addr + s.size);
    // Code that is not position-independent puts addresses in its immediates and displacements.
    let absolute = match image.format {
        Format::Elf => image.elf.as_ref().is_some_and(|e| e.ty == 2.0),
        Format::Pe => mode == 32,
        Format::MachO => false,
    };
    let macho = image.format == Format::MachO;
    // Where functions start, for the sweep to start afresh.
    let mut known = NumberSet::default();
    for sym in image.symbols.iter().chain(&image.exports) {
        if in_code(sym.addr) && (sym.function || macho) {
            known.add(sym.addr);
        }
    }
    for &addr in &image.function_starts {
        if in_code(addr) {
            known.add(addr);
        }
    }
    for &(addr, _) in &image.stubs.entries {
        if in_code(addr) {
            known.add(addr);
        }
    }
    if let Some(entry) = image.entry.filter(|&e| in_code(e)) {
        known.add(entry);
    }
    for s in &sections {
        if let Some(stride) = s.stub_size {
            let mut at = s.addr;
            while at < s.addr + s.size {
                known.add(at);
                at += stride;
            }
        }
    }
    // Data the file says is among the instructions (Mach-O).
    let mut data = Vec::new();
    for &(addr, length, kind) in image.macho.as_ref().map_or(&[][..], |m| m.data_in_code.as_slice()) {
        if !in_code(addr) || length == 0 {
            continue;
        }
        let entry = match kind {
            2 => 1,
            3 => 2,
            _ if length % 4 != 0 => 1,
            _ => 4,
        };
        data.push(DataRegion { addr: addr as i64, length: length as i64, entry });
    }
    let mut symbols: Vec<i64> = image.symbols.iter().filter(|s| !s.name.is_empty() && s.addr != 0.0).map(|s| s.addr as i64).collect();
    symbols.extend(image.exports.iter().map(|e| e.addr as i64));
    let got_plt = image.sections.iter().find(|s| s.name == ".got.plt").or_else(|| image.sections.iter().find(|s| s.name == ".got")).map(|s| s.addr as i64);
    X86Input {
        mode,
        absolute,
        known: known.list.iter().map(|&a| a as i64).collect(),
        data,
        symbols,
        slots: image.slots.entries.iter().map(|&(a, _)| a as i64).collect(),
        strings: image.cstrings().iter().map(|s| s.0 as i64).collect(),
        got_plt,
    }
}

/// The program as the analysis after the pass sees it.
struct Program<'a> {
    image: &'a NativeImage,
    pass: &'a X86Pass,
    address_at: FxHashMap<u32, i64>,
    code_at: FxHashMap<u32, i64>,
    targets: FxHashMap<u32, i64>,
    functions: Vec<Function>,
    function_at_index: FxHashMap<u32, usize>,
    jmp: i64,
}

impl Program<'_> {
    fn total(&self) -> u32 {
        self.pass.offs.len() as u32
    }

    fn range_of(&self, index: u32) -> Option<&crate::x86::pass::Range> {
        self.pass.ranges.iter().find(|r| index >= r.first && index < r.first + r.count)
    }

    fn addr_of(&self, index: u32) -> f64 {
        self.range_of(index).map_or(0.0, |r| self.pass.image.sections[r.section].addr as f64 + self.pass.offs[index as usize] as f64)
    }

    /// The instruction containing an address in code, or -1.
    fn index_of(&self, addr: f64) -> i64 {
        for r in &self.pass.ranges {
            let s = &self.pass.image.sections[r.section];
            let start = s.addr as f64;
            if addr < start || addr >= start + s.size as f64 {
                continue;
            }
            let offset = addr - start;
            let (mut lo, mut hi, mut found) = (r.first as i64, r.first as i64 + r.count as i64 - 1, -1i64);
            while lo <= hi {
                let mid = (lo + hi) >> 1;
                if self.pass.offs[mid as usize] as f64 <= offset {
                    found = mid;
                    lo = mid + 1;
                } else {
                    hi = mid - 1;
                }
            }
            if found < 0 || offset >= self.pass.offs[found as usize] as f64 + self.pass.lens[found as usize] as f64 {
                return -1;
            }
            return found;
        }
        -1
    }

    fn range_end(&self, index: u32) -> u32 {
        self.range_of(index).map_or(index, |r| r.first + r.count)
    }

    fn mnemonic(&self, index: u32) -> &str {
        &self.pass.mnemonics[self.pass.mnemonic_ids[index as usize] as usize]
    }

    fn text(&self, index: u32) -> String {
        let r = self.range_of(index).unwrap();
        let s = &self.pass.image.sections[r.section];
        let off = s.offset as usize + self.pass.offs[index as usize] as usize;
        let d = decode_x86(&self.pass.image.bytes, off, (s.offset + s.size) as usize, s.addr + self.pass.offs[index as usize] as i64, self.pass.mode);
        format_x86(&print_x86(&d)).as_str().to_string()
    }

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

    /// The function a direct call or jump reaches, through the jmp thunks of an incremental link.
    fn reached(&self, i: u32) -> Option<usize> {
        let target = *self.targets.get(&i)? as f64;
        let mut f = self.function_at(target)?;
        if self.functions[f].addr != target {
            return None;
        }
        let mut hop = 0;
        while self.functions[f].count <= 2 && self.pass.mnemonic_ids[self.functions[f].first as usize] as i64 == self.jmp && hop < 3 {
            let Some(&to) = self.targets.get(&self.functions[f].first) else { break };
            let Some(next) = self.function_at(to as f64) else { break };
            if self.functions[next].addr != to as f64 {
                break;
            }
            f = next;
            hop += 1;
        }
        Some(f)
    }
}

/// Where main is, for an ELF program without symbols: the code address the entry point passes to
/// __libc_start_main (in rdi on x86-64, pushed last on i386), the last one named before that call.
fn main_of(p: &Program) -> Option<f64> {
    let image = p.image;
    if image.format != Format::Elf {
        return None;
    }
    let entry = p.index_of(image.entry?);
    if entry < 0 {
        return None;
    }
    let mut found = None;
    let size = if p.pass.mode == 64 { 8 } else { 4 };
    for i in entry as u32..(entry as u32 + 48).min(p.total()) {
        // A function pointer in the instruction, or in the GOT slot it reads (i386 PIE).
        let slotted = p.address_at.get(&i).copied();
        let pointed = slotted.and_then(|s| image.slot_value(s as f64, size));
        let code = p.code_at.get(&i).map(|&c| c as f64).or_else(|| pointed.filter(|&v| p.index_of(v) >= 0));
        if code.is_some() {
            found = code;
        }
        if p.pass.flags[i as usize] & iflag::CALL == 0 {
            continue;
        }
        let callee = match slotted {
            Some(slot) => image.slots.get(slot as f64).map(String::as_str),
            None => p.targets.get(&i).and_then(|&t| image.stubs.get(t as f64)).map(String::as_str),
        };
        if callee == Some("__libc_start_main") {
            return found;
        }
    }
    None
}

struct Startup<'a, 'b> {
    p: &'a Program<'b>,
    stops: FxHashSet<u16>,
}

impl StartupCode for Startup<'_, '_> {
    fn straight(&self, from: u32, to: u32) -> bool {
        (from + 1..to).all(|i| !self.stops.contains(&self.p.pass.mnemonic_ids[i as usize]))
    }

    // `mov ecx, dword ptr [rax]` on x86-64, `push dword ptr [eax]` on i386.
    fn argc(&self, from: u32, to: u32) -> bool {
        (from + 1..to).any(|i| matches!(self.p.text(i).as_str(), "mov ecx, dword ptr [rax]" | "push dword ptr [eax]"))
    }

    // x86-64: `lea rcx, [__ImageBase]` and `xor edx, edx`; i386: `push 0` and `push <image base>`.
    fn instance(&self, from: u32, to: u32) -> bool {
        let base = self.p.image.pe.as_ref().map(|pe| pe.image_base);
        let push_base = base.map(|b| format!("push 0x{}", crate::text::js_hex(b)));
        let (mut first, mut second) = (false, false);
        for i in from + 1..to {
            let line = self.p.text(i);
            if (line.starts_with("lea rcx, ") && self.p.address_at.get(&i).map(|&a| a as f64) == base) || Some(&line) == push_base.as_ref() {
                first = true;
            } else if line == "xor edx, edx" || line == "push 0x0" {
                second = true;
            }
        }
        first && second
    }

    // x86-64: three `mov ecx|rdx|r8, [dq]word ptr [rip ± …]`; i386: three `push dword ptr [0x…]`.
    fn globals(&self, from: u32, to: u32) -> bool {
        let mut seen: Vec<String> = Vec::new();
        for i in from + 1..to {
            let line = self.p.text(i);
            let hex = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
            let mov = ["ecx", "rdx", "r8"].iter().find(|r| {
                line.strip_prefix(&format!("mov {r}, "))
                    .and_then(|rest| rest.strip_prefix("dword ptr [rip ").or_else(|| rest.strip_prefix("qword ptr [rip ")))
                    .and_then(|rest| rest.strip_prefix("+ 0x").or_else(|| rest.strip_prefix("- 0x")))
                    .and_then(|rest| rest.strip_suffix(']'))
                    .is_some_and(hex)
            });
            let push = line.strip_prefix("push dword ptr [0x").and_then(|rest| rest.strip_suffix(']')).is_some_and(hex);
            let key = match (mov, push) {
                (Some(r), _) => r.to_string(),
                (None, true) => format!("push{}", seen.len()),
                _ => continue,
            };
            if !seen.contains(&key) {
                seen.push(key);
            }
        }
        seen.len() >= 3
    }
}

/// The analysis after the pass: stubs, functions, `j_` names, a stripped program's main, the
/// joins a function start breaks, and the strings. Sets the FUNCTION flags in the pass.
pub fn after_pass(image: &mut NativeImage, pass: &mut X86Pass, refs: &X86Refs) -> Found {
    let address_at: FxHashMap<u32, i64> = pass.address_at.iter().copied().collect();
    let code_at: FxHashMap<u32, i64> = pass.code_at.iter().copied().collect();
    let targets: FxHashMap<u32, i64> = pass.rel_targets.iter().copied().collect();
    let jmp = pass.mnemonics.iter().position(|m| m == "jmp").map_or(-1, |k| k as i64);
    let pe = image.format == Format::Pe;

    // Stubs: a jump through an import's slot in a stub section or the PLT; in a Windows program
    // the thunks the linker puts among the code, one after another or after padding.
    let found_stubs: Vec<(f64, String)> = {
        let p = Program {
            image,
            pass,
            address_at: address_at.clone(),
            code_at: FxHashMap::default(),
            targets: FxHashMap::default(),
            functions: Vec::new(),
            function_at_index: FxHashMap::default(),
            jmp,
        };
        let mut set = crate::macho::NumberMap::default();
        for r in &pass.ranges {
            let name = &image.sections[r.section].name;
            if !(pe || name.contains("plt") || name.contains("stub")) {
                continue;
            }
            for i in r.first..r.first + r.count {
                let Some(&slot) = address_at.get(&i) else { continue };
                if pass.flags[i as usize] & iflag::BRANCH == 0 {
                    continue;
                }
                let Some(name) = image.slots.get(slot as f64).filter(|n| !n.is_empty()) else { continue };
                if pe && i > r.first && !pass.is_known(p.addr_of(i) as i64) {
                    let before = p.mnemonic(i - 1);
                    let thunk_before = address_at.contains_key(&(i - 1)) && pass.flags[i as usize - 1] & iflag::BRANCH != 0;
                    if !thunk_before && !matches!(before, "int3" | "nop" | "ret" | "jmp" | "ud2") {
                        continue;
                    }
                }
                // An endbr64 before the jump (a PLT with IBT) starts the stub.
                let mut start = p.addr_of(i);
                if i > r.first && pass.lens[i as usize - 1] == 4 && p.mnemonic(i - 1).starts_with("endbr") {
                    start = p.addr_of(i - 1);
                }
                if !image.stubs.has(start) && !set.has(start) {
                    set.set(start, name.clone());
                }
            }
        }
        set.entries
    };
    for (at, name) in &found_stubs {
        image.stubs.set(*at, name.clone());
    }
    let image: &NativeImage = image;
    let macho = image.format == Format::MachO;

    // Functions.
    let (functions, function_at_index) = {
        let p = Program {
            image,
            pass,
            address_at: address_at.clone(),
            code_at: code_at.clone(),
            targets: targets.clone(),
            functions: Vec::new(),
            function_at_index: FxHashMap::default(),
            jmp,
        };
        let mut starts = Starts::default();
        let add = |starts: &mut Starts, addr: f64, raw: Option<&str>, kind: Kind| {
            let index = p.index_of(addr);
            if index < 0 || p.addr_of(index as u32) != addr || pass.kinds[index as usize] != 0 {
                return;
            }
            starts.add(addr, raw, kind);
        };
        for r in &pass.ranges {
            let section = &image.sections[r.section];
            add(&mut starts, section.addr, None, Kind::Anonymous);
            if let Some(stride) = section.stub_size {
                let mut at = section.addr;
                while at < section.addr + section.size {
                    let name = image.stubs.get(at);
                    add(&mut starts, at, name.map(String::as_str), if name.is_some() { Kind::Import } else { Kind::Anonymous });
                    at += stride;
                }
            }
        }
        for (at, name) in &image.stubs.entries {
            if macho {
                add(&mut starts, *at, Some(name), Kind::Import);
            } else {
                let (raw, import) = image.stub_function(name);
                add(&mut starts, *at, Some(&raw), if import { Kind::Import } else { Kind::Symbol });
            }
        }
        for &addr in &image.function_starts {
            add(&mut starts, addr, None, Kind::Anonymous);
        }
        // Exports first: a function both exported and in the symbol table is listed as exported.
        for e in &image.exports {
            if e.function || macho {
                add(&mut starts, e.addr, Some(&e.name), Kind::Export);
            }
        }
        for s in &image.symbols {
            if !s.name.is_empty() && (s.function || macho) {
                add(&mut starts, s.addr, Some(&s.name), Kind::Symbol);
            }
        }
        for &target in &refs.callers.keys {
            add(&mut starts, target, None, Kind::Anonymous);
        }
        // A run of `jmp rel32` thunks (the table an incremental link puts calls through): a function each.
        for r in &pass.ranges {
            let mut run = 0u32;
            for i in r.first..=r.first + r.count {
                let thunk = i < r.first + r.count && pass.mnemonic_ids[i as usize] as i64 == jmp && pass.lens[i as usize] == 5 && pass.kinds[i as usize] == 0;
                if thunk {
                    run += 1;
                } else {
                    if run >= 4 {
                        for k in i - run..i {
                            add(&mut starts, p.addr_of(k), None, Kind::Anonymous);
                        }
                    }
                    run = 0;
                }
            }
        }
        if let Some(entry) = image.entry {
            let raw = starts.raw(entry).map(String::from).unwrap_or_else(|| image.entry_name().into());
            add(&mut starts, entry, Some(&raw), Kind::Entry);
        }
        // A Windows entry point may end by jumping to the C runtime's startup: that is a function too.
        if let Some(entry) = image.entry.filter(|_| pe) {
            let first = p.index_of(entry);
            if first >= 0 {
                for i in first as u32..(first as u32 + 16).min(p.total()) {
                    let m = p.mnemonic(i);
                    if m == "ret" || m == "int3" || (pass.flags[i as usize] & iflag::BRANCH != 0 && m != "jmp") {
                        break;
                    }
                    if m != "jmp" {
                        continue;
                    }
                    if let Some(&target) = targets.get(&i) {
                        let target = target as f64;
                        if target < entry || target > p.addr_of(i) {
                            add(&mut starts, target, None, Kind::Anonymous);
                        }
                    }
                    break;
                }
            }
        }
        // A stripped program's main is what _start hands to __libc_start_main.
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

    let functions = {
        let mut p = Program { image, pass, address_at, code_at, targets, functions, function_at_index, jmp };
        // A function that only jumps elsewhere is a thunk: without a name of its own it is named after where it goes.
        for _ in 0..3 {
            for k in 0..p.functions.len() {
                let f = &p.functions[k];
                if f.kind != Kind::Anonymous || f.raw.as_deref().is_some_and(|r| !r.is_empty()) || p.pass.mnemonic_ids[f.first as usize] as i64 != jmp {
                    continue;
                }
                let Some(to) = p.targets.get(&f.first).and_then(|&t| p.function_at(t as f64)) else { continue };
                if to == k || p.functions[to].name.starts_with("sub_") {
                    continue;
                }
                let (name, full) = (format!("j_{}", p.functions[to].name), format!("j_{}", p.functions[to].full));
                p.functions[k].name = name;
                p.functions[k].full = full;
            }
        }
        if pe {
            let mut calls: Vec<Call> = Vec::new();
            for i in 0..p.total() {
                if p.pass.flags[i as usize] & iflag::CALL == 0 {
                    continue;
                }
                let name = p.address_at.get(&i).and_then(|&slot| image.slots.get(slot as f64));
                let callee = match name {
                    Some(name) => Some(Callee::Import(name.clone())),
                    None => p.reached(i).map(Callee::Function),
                };
                if let Some(callee) = callee {
                    calls.push(Call { at: i, within: p.function_of_index(i as i64), callee });
                }
            }
            // The entry point and what it calls or jumps to, two steps deep.
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
                    let f = &p.functions[at as usize];
                    if depth < 2 {
                        for i in f.first..f.first + f.count {
                            if p.pass.flags[i as usize] & (iflag::CALL | iflag::BRANCH) == 0 {
                                continue;
                            }
                            // A jump may land inside what the analysis takes for another function: that one is meant.
                            if let Some(to) = p.reached(i) {
                                next.push(to as i64);
                            } else if let Some(&target) = p.targets.get(&i) {
                                let index = p.index_of(target as f64);
                                if index >= 0 {
                                    next.push(p.function_of_index(index));
                                }
                            }
                        }
                    }
                }
                level = next;
                depth += 1;
            }
            let stops: FxHashSet<u16> = ["jmp", "ret", "int3", "ud2", "hlt"].iter().filter_map(|m| p.pass.mnemonics.iter().position(|x| x == m)).map(|k| k as u16).collect();
            let found = windows_main(&calls, &startup, &p.functions, &Startup { p: &p, stops });
            let mut out = p.functions;
            name_main(&mut out, found);
            out
        } else {
            p.functions
        }
    };

    // The core joined each compare with the jump that reads its flags; not where a function starts at the second.
    let total = pass.flags.len();
    for i in 0..total.saturating_sub(1) {
        if pass.flags[i] & iflag::FUSE != 0 && pass.flags[i + 1] & iflag::FUNCTION != 0 {
            pass.flags[i] &= !iflag::FUSE;
        }
    }

    // Strings: the C-string sections, and those in constant data that code points at (the pass read them).
    let mut strings: Vec<FoundString> = image.cstrings().into_iter().map(|(addr, text, section)| FoundString { addr, text, section, cstring: true }).collect();
    for s in &refs.strings {
        strings.push(FoundString { addr: s.addr as f64, text: s.text.clone(), section: s.section.clone(), cstring: s.kind == crate::image::StringKind::CString });
    }
    strings.sort_by(|a, b| a.addr.partial_cmp(&b.addr).unwrap_or(core::cmp::Ordering::Equal));
    Found { functions, strings, stubs: found_stubs }
}
