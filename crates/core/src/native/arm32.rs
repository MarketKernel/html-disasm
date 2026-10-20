//! A 32-bit Arm program around its pass (a port of the rest of `analyzeArm32` in
//! src/core/arm32/program.ts): where the file says each instruction set is and
//! what else the pass is opened with, and afterwards the PLT stubs and Windows
//! import thunks, the functions and their names, a stripped program's main,
//! and the strings.

use super::functions::{name_main, windows_main, Call, Callee, Function, Kind, Starts, StartupCode};
use super::image::{clear_thumb, Format, NativeImage};
use super::x86::core_image;
use super::{Found, FoundString};
use crate::arm32::pass::{decode_at, kind, Arm32Input, Arm32Pass, Arm32Refs, Mark, Set};
use crate::arm32::types::Mode;
use crate::arm32::{f, format_insn, Insn, Op};
use crate::disassembly::iflag;
use crate::macho::NumberMap;
use crate::refs::{FxHashMap, FxHashSet};
use crate::text::{to_int32, to_uint32};

/// What an AArch32 pass is opened with.
pub fn pass_input(image: &NativeImage) -> Arm32Input {
    let mut sections: Vec<&super::image::ImageSection> = image.sections.iter().filter(|s| s.code && s.size >= 2.0 && s.offset != 0.0).collect();
    sections.sort_by(|a, b| a.addr.partial_cmp(&b.addr).unwrap_or(core::cmp::Ordering::Equal));
    let in_code = |addr: f64| sections.iter().any(|s| addr >= s.addr && addr < s.addr + s.size);
    // Where each instruction set is, as far as the file says: the core settles the rest.
    let thumb_symbols = image.symbols.iter().filter(|s| s.function && s.thumb).count();
    let functions = image.symbols.iter().filter(|s| s.function).count();
    let fallback = if thumb_symbols * 2 >= functions { Set::T } else { Set::A };
    let mut known: NumberMap<Set> = NumberMap::default();
    for s in &sections {
        if s.name.starts_with(".plt") || s.name.starts_with(".iplt") {
            known.set(s.addr, Set::A);
        }
    }
    for sym in image.symbols.iter().chain(&image.exports) {
        if sym.function && in_code(sym.addr) {
            known.set(sym.addr, if sym.thumb { Set::T } else { Set::A });
        }
    }
    if let Some(e) = &image.elf {
        for &value in e.init_array.iter().chain(&e.fini_array) {
            if in_code(clear_thumb(value)) {
                known.set(clear_thumb(value), if to_int32(value) & 1 != 0 { Set::T } else { Set::A });
            }
        }
    }
    if let Some(entry) = image.entry.filter(|&e| in_code(clear_thumb(e))) {
        known.set(clear_thumb(entry), if to_int32(entry) & 1 != 0 { Set::T } else { Set::A });
    }
    for &addr in image.thumb.as_deref().unwrap_or(&[]) {
        if in_code(addr) && !known.has(addr) {
            known.set(addr, Set::T);
        }
    }
    // Code inside a function the symbols describe keeps that function's set, whatever a stray call says.
    let mut spans: Vec<(i64, i64)> = image.symbols.iter().filter_map(|s| s.size.filter(|_| s.function).map(|size| (s.addr as i64, (s.addr + size) as i64))).collect();
    spans.sort_by_key(|s| s.0);
    let mut symbols: Vec<i64> = image.symbols.iter().filter(|s| !s.name.is_empty() && s.addr != 0.0).map(|s| s.addr as i64).collect();
    symbols.extend(image.exports.iter().map(|e| e.addr as i64));
    let objc = image.objc.as_ref().map_or_else(Vec::new, |o| {
        o.selrefs.entries.iter().map(|e| e.0 as i64).chain(o.classrefs.entries.iter().map(|e| e.0 as i64)).chain(o.cfstrings.entries.iter().map(|e| e.0 as i64)).collect()
    });
    Arm32Input {
        file_marks: image.marks.iter().filter(|m| m.1 != 'x').map(|&(addr, k)| Mark { addr: addr as i64, set: Set::from_char(k as u8) }).collect(),
        fallback,
        known: known.entries.iter().map(|&(addr, set)| Mark { addr: addr as i64, set }).collect(),
        function_starts: image.function_starts.iter().map(|&a| a as i64).collect(),
        spans,
        data_in_code: image.data_in_code.as_deref().unwrap_or(&[]).iter().map(|&(a, l)| (a as i64, l as i64)).collect(),
        symbols,
        slots: image.slots.entries.iter().map(|&(a, _)| a as i64).collect(),
        strings: image.cstrings().iter().map(|s| s.0 as i64).collect(),
        objc,
        relative: image.elf.as_ref().map_or_else(Vec::new, |e| e.relative.entries.iter().map(|&(a, v)| (a as i64, v as i64)).collect()),
    }
}

/// The image the pass reads.
pub fn pass_image(image: &NativeImage) -> crate::image::Image {
    core_image(image)
}

const SIZE: [u32; 6] = [4, 2, 4, 4, 2, 1];

/// `r0`…`r12`, `sp`, `lr`, `pc` by number, or -1.
fn reg_number(name: &str) -> i32 {
    match name {
        "sp" => 13,
        "lr" => 14,
        "pc" => 15,
        _ => name.strip_prefix('r').and_then(|n| n.parse::<i32>().ok()).filter(|&n| (0..=12).contains(&n) && name.len() == 1 + n.to_string().len()).unwrap_or(-1),
    }
}

fn reg_of(op: Option<&Op>) -> i32 {
    match op {
        Some(Op::Reg { r, .. }) => reg_number(r.as_str()),
        _ => -1,
    }
}

/// An A32 modified immediate: eight bits rotated right by twice the rotation field.
fn arm_imm(word: u32) -> f64 {
    let rot = ((word >> 8) & 0xf) * 2;
    (word & 0xff).rotate_right(rot) as f64
}

struct Program<'a> {
    image: &'a NativeImage,
    pass: &'a Arm32Pass,
    targets: FxHashMap<u32, i64>,
    functions: Vec<Function>,
    function_at_index: FxHashMap<u32, usize>,
}

impl Program<'_> {
    fn total(&self) -> u32 {
        self.pass.layout.addrs.len() as u32
    }

    fn addr(&self, i: u32) -> f64 {
        self.pass.layout.addrs[i as usize] as f64
    }

    fn is_data(&self, i: u32) -> bool {
        self.pass.layout.kinds[i as usize] >= kind::WORD
    }

    fn index_of(&self, addr: f64) -> i64 {
        let addrs = &self.pass.layout.addrs;
        let (mut lo, mut hi, mut found) = (0i64, addrs.len() as i64 - 1, -1i64);
        while lo <= hi {
            let mid = (lo + hi) >> 1;
            if addrs[mid as usize] as f64 <= addr {
                found = mid;
                lo = mid + 1;
            } else {
                hi = mid - 1;
            }
        }
        if found < 0 || addr >= addrs[found as usize] as f64 + SIZE[self.pass.layout.kinds[found as usize] as usize] as f64 {
            return -1;
        }
        found
    }

    fn range_end(&self, index: u32) -> u32 {
        self.pass.layout.ranges.iter().find(|r| index >= r.first && index < r.first + r.count).map_or(index, |r| r.first + r.count)
    }

    fn insn(&self, i: u32) -> Insn {
        let l = &self.pass.layout;
        decode_at(l.kinds[i as usize], l.words[i as usize], l.addrs[i as usize] as i64, l.its[i as usize] as i32)
    }

    fn text(&self, i: u32) -> String {
        if self.is_data(i) {
            String::new()
        } else {
            format_insn(&self.insn(i)).as_str().to_string()
        }
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
}

/// The stubs of the PLT: `add r12, pc, #…; add r12, r12, #…; ldr pc, [r12, #…]!`, read from their encodings.
fn plt_stubs(p: &Program) -> NumberMap<String> {
    let mut stubs = NumberMap::default();
    let l = &p.pass.layout;
    for r in &l.ranges {
        let name = &p.pass.image.sections[r.section].name;
        if !(name.starts_with(".plt") || name.starts_with(".iplt")) {
            continue;
        }
        let mut start = -1.0;
        let mut ip = f64::NAN;
        for i in r.first..r.first + r.count {
            if l.kinds[i as usize] != kind::A32 {
                continue;
            }
            let word = l.words[i as usize];
            let pc = l.addrs[i as usize] as f64;
            if word & 0x0fff_f000 == 0x028f_c000 {
                start = pc;
                ip = pc + 8.0 + arm_imm(word);
            } else if word & 0x0fff_f000 == 0x028c_c000 {
                ip += arm_imm(word);
            } else if word & 0x0f7f_f000 == 0x053c_f000 || word & 0x0f7f_f000 == 0x051c_f000 {
                let offset = (word & 0xfff) as f64;
                let slot = to_uint32(ip + if word & 0x80_0000 != 0 { offset } else { -offset }) as f64;
                if let Some(name) = p.image.slots.get(slot).filter(|n| !n.is_empty()) {
                    if start >= 0.0 {
                        stubs.set(start, name.clone());
                    }
                }
                start = -1.0;
                ip = f64::NAN;
            }
        }
    }
    stubs
}

/// The import thunks of a Windows program: `movw r12, #lo; movt r12, #hi; ldr.w pc, [r12]`.
fn import_thunks(p: &Program) -> NumberMap<String> {
    let mut thunks = NumberMap::default();
    let l = &p.pass.layout;
    for i in 2..p.total() {
        if l.kinds[i as usize] != kind::T32 || l.words[i as usize] != 0xf8dc_f000 {
            continue; // ldr.w pc, [r12]
        }
        let slot = p.pass.address_at.get(&i).map_or(-1.0, |&a| a as f64);
        if let Some(name) = p.image.slots.get(slot).filter(|n| !n.is_empty()) {
            if p.insn(i - 2).m.as_str().starts_with("movw") {
                thunks.set(l.addrs[i as usize - 2] as f64, name.clone());
            }
        }
    }
    thunks
}

/// `^adds?(\.w)?$` and `^movs?(\.w)?$`.
fn is_plain(m: &str, base: &str) -> bool {
    let Some(rest) = m.strip_prefix(base) else { return false };
    let rest = rest.strip_prefix('s').unwrap_or(rest);
    rest.is_empty() || rest == ".w"
}

/// Where main is, for an ELF program without symbols: what the entry point passes to
/// __libc_start_main in r0 (a literal, or from the GOT through pc and a literal).
fn main_of(p: &Program) -> Option<f64> {
    let image = p.image;
    if image.format != Format::Elf {
        return None;
    }
    let entry = p.index_of(clear_thumb(image.entry?));
    if entry < 0 {
        return None;
    }
    let mut regs = [f64::NAN; 16];
    let pointer = |addr: f64| if addr.is_nan() { f64::NAN } else { image.slot_value(addr, 4).unwrap_or(f64::NAN) };
    let reg_value = |regs: &[f64; 16], r: i32| if (0..16).contains(&r) { regs[r as usize] } else { f64::NAN };
    for i in entry as u32..(entry as u32 + 32).min(p.total()) {
        if p.is_data(i) {
            return None;
        }
        let insn = p.insn(i);
        regs[15] = p.addr(i) + if p.pass.layout.kinds[i as usize] == kind::A32 { 8.0 } else { 4.0 };
        if insn.f & f::CALL != 0 {
            let target = insn.target?;
            if image.stubs.get(target as f64).map(String::as_str) != Some("__libc_start_main") {
                return None;
            }
            let main = to_uint32((to_int32(regs[0]) & !1) as f64) as f64;
            let index = p.index_of(main);
            return (index >= 0 && p.addr(index as u32) == main).then_some(main);
        }
        if insn.f & f::BRANCH != 0 {
            return None;
        }
        let dest = reg_of(insn.ops.first());
        if insn.f & f::STORE != 0 || dest < 0 || dest == 15 {
            continue;
        }
        let ops = &insn.ops;
        let (a, b) = (ops.get(1), ops.get(2));
        let mem = ops.iter().find_map(|op| match op {
            Op::Mem(m) => Some(*m),
            _ => None,
        });
        let m = insn.m.as_str();
        let value = |op: Option<&Op>| reg_value(&regs, reg_of(op));
        let imm = |op: Option<&Op>| match op {
            Some(Op::Imm { v, .. }) => Some(*v),
            _ => None,
        };
        let mut v = f64::NAN;
        if let (true, Some(t)) = (insn.f & f::LOAD != 0, insn.target) {
            v = pointer(t as f64);
        } else if let Some(t) = insn.target {
            v = t as f64;
        } else if let Some(mem) = mem.filter(|mem| {
            m.starts_with("ldr")
                && insn.bytes == 4
                && mem.mode == Mode::Off
                && mem.index.is_none_or(|index| mem.t.as_str() == format!("[{}, {}]", mem.base.as_str(), index.as_str()))
        }) {
            let base = reg_value(&regs, reg_number(mem.base.as_str()));
            let add = match mem.index {
                Some(index) => reg_value(&regs, reg_number(index.as_str())),
                None => mem.off.unwrap_or(0) as f64,
            };
            v = pointer(to_uint32(base + add) as f64);
        } else if is_plain(m, "add") && ops.len() <= 3 {
            let (x, y) = if ops.len() == 3 { (a, b) } else { (ops.first(), a) };
            let right = imm(y).unwrap_or_else(|| value(y));
            v = to_uint32(value(x) + right) as f64;
        } else if is_plain(m, "mov") && ops.len() == 2 {
            v = match imm(a) {
                Some(i) => to_uint32(i) as f64,
                None => value(a),
            };
        } else if m.starts_with("movw") && imm(a).is_some() {
            v = (to_int32(imm(a).unwrap()) & 0xffff) as f64;
        } else if m.starts_with("movt") && imm(a).is_some() {
            v = to_uint32(((to_int32(regs[dest as usize]) & 0xffff) | ((to_int32(imm(a).unwrap()) & 0xffff) << 16)) as f64) as f64;
        }
        regs[dest as usize] = v;
        // A load with writeback (`ldr r1, [sp], #4`) changes its base too.
        if let Some(mem) = mem {
            if mem.mode != Mode::Off {
                let r = reg_number(mem.base.as_str());
                regs[if r >= 0 { r as usize } else { 15 }] = f64::NAN;
            }
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
            let t = self.p.text(i);
            let jump = ["b ", "b.w ", "bx ", "udf ", "bkpt "].iter().any(|p| t.starts_with(p));
            let pop = (t.starts_with("pop {") || t.starts_with("pop.w {")) && {
                let line = t.split(['\n', '\r', '\u{2028}', '\u{2029}']).next().unwrap_or("");
                line.find('{').is_some_and(|k| line[k..].contains("pc}"))
            };
            if jump || pop {
                return false;
            }
        }
        true
    }

    fn argc(&self, from: u32, to: u32) -> bool {
        (from + 1..to).any(|i| self.p.text(i) == "ldr r0, [r0]")
    }

    // `movw r0, …; movt r0, …` to the image base, and `movs r1, #0`
    fn instance(&self, from: u32, to: u32) -> bool {
        let base = self.p.image.pe.as_ref().map(|pe| pe.image_base);
        let (mut first, mut second) = (false, false);
        for i in from + 1..to {
            let t = self.p.text(i);
            if t.starts_with("movt r0, ") && self.p.pass.address_at.get(&i).map(|&a| a as f64) == base {
                first = true;
            } else if matches!(
                t.as_str(),
                "mov r1, #0" | "movs r1, #0" | "mov.w r1, #0" | "movs.w r1, #0" | "mov r1, #0x0" | "movs r1, #0x0" | "mov.w r1, #0x0" | "movs.w r1, #0x0"
            ) {
                second = true;
            }
        }
        first && second
    }

    fn globals(&self, _: u32, _: u32) -> bool {
        false
    }
}

/// The analysis after the pass: stubs, functions, a stripped program's main, and the strings.
/// Sets the FUNCTION flags in the pass.
pub fn after_pass(image: &mut NativeImage, pass: &mut Arm32Pass, refs: &Arm32Refs) -> Found {
    let targets: FxHashMap<u32, i64> = pass.targets.iter().copied().collect();
    let mut found_stubs: Vec<(f64, String)> = Vec::new();
    {
        let p = Program { image, pass, targets: FxHashMap::default(), functions: Vec::new(), function_at_index: FxHashMap::default() };
        found_stubs.extend(plt_stubs(&p).entries);
    }
    for (at, name) in &found_stubs {
        image.stubs.set(*at, name.clone());
    }
    if image.format == Format::Pe {
        let thunks = {
            let p = Program { image, pass, targets: FxHashMap::default(), functions: Vec::new(), function_at_index: FxHashMap::default() };
            import_thunks(&p).entries
        };
        for (at, name) in &thunks {
            image.stubs.set(*at, name.clone());
        }
        found_stubs.extend(thunks);
    }
    let image: &NativeImage = image;

    // Functions.
    let (functions, function_at_index) = {
        let p = Program { image, pass, targets: targets.clone(), functions: Vec::new(), function_at_index: FxHashMap::default() };
        let mut starts = Starts::default();
        let add = |starts: &mut Starts, addr: f64, raw: Option<&str>, kind: Kind| {
            let index = p.index_of(addr);
            if index < 0 || p.addr(index as u32) != addr {
                return;
            }
            starts.add(addr, raw, kind);
        };
        for r in &pass.layout.ranges {
            add(&mut starts, pass.image.sections[r.section].addr as f64, None, Kind::Anonymous);
        }
        for (at, name) in &image.stubs.entries {
            let (raw, import) = image.stub_function(name);
            add(&mut starts, *at, Some(&raw), if import { Kind::Import } else { Kind::Symbol });
        }
        for &addr in &image.function_starts {
            add(&mut starts, addr, None, Kind::Anonymous);
        }
        // Exports first: a function both exported and in the symbol table is listed as exported.
        for e in &image.exports {
            if e.function {
                add(&mut starts, e.addr, Some(&e.name), Kind::Export);
            }
        }
        for s in &image.symbols {
            if !s.name.is_empty() && s.function {
                add(&mut starts, s.addr, Some(&s.name), Kind::Symbol);
            }
        }
        for &target in &refs.callers.keys {
            add(&mut starts, target, None, Kind::Anonymous);
        }
        if let Some(entry) = image.entry {
            let at = clear_thumb(entry);
            let raw = starts.raw(at).map(String::from).unwrap_or_else(|| image.entry_name().into());
            add(&mut starts, at, Some(&raw), Kind::Entry);
        }
        // A stripped Linux program's main is what _start hands to __libc_start_main.
        if let Some(main) = main_of(&p) {
            if starts.raw(main).is_none_or(str::is_empty) {
                add(&mut starts, main, Some("main"), Kind::Symbol);
            }
        }
        let functions = starts.build(image, &|addr| p.index_of(addr), &|first| p.range_end(first), false);
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
        let p = Program { image, pass, targets, functions, function_at_index };
        if image.format != Format::Pe {
            p.functions
        } else {
            let slot_calls: FxHashMap<u32, i64> = pass.slot_calls.iter().copied().collect();
            let mut calls: Vec<Call> = Vec::new();
            for i in 0..p.total() {
                if p.is_data(i) || pass.flags[i as usize] & iflag::CALL == 0 {
                    continue;
                }
                if let Some(&slot) = slot_calls.get(&i) {
                    let name = image.slots.get(slot as f64).cloned().unwrap_or_default();
                    calls.push(Call { at: i, within: p.function_of_index(i as i64), callee: Callee::Import(name) });
                    continue;
                }
                let Some(&target) = p.targets.get(&i) else { continue };
                if let Some(callee) = p.function_at(target as f64) {
                    if p.functions[callee].addr == target as f64 {
                        calls.push(Call { at: i, within: p.function_of_index(i as i64), callee: Callee::Function(callee) });
                    }
                }
            }
            // The entry point and what it calls or jumps to, two steps deep.
            let mut startup: FxHashSet<i64> = FxHashSet::default();
            let entry = image.entry.map_or(-1, |e| p.index_of(clear_thumb(e)));
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
                            let target = if !p.is_data(i) && pass.flags[i as usize] & (iflag::CALL | iflag::BRANCH) != 0 { p.targets.get(&i).copied() } else { None };
                            let index = target.map_or(-1, |t| p.index_of(t as f64));
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

    // Strings: the C-string sections, and those in constant data that code points at (the pass read them).
    let mut strings: Vec<FoundString> = image.cstrings().into_iter().map(|(addr, text, section)| FoundString { addr, text, section, cstring: true }).collect();
    for s in &refs.strings {
        strings.push(FoundString { addr: s.addr as f64, text: s.text.clone(), section: s.section.clone(), cstring: s.kind == crate::image::StringKind::CString });
    }
    strings.sort_by(|a, b| a.addr.partial_cmp(&b.addr).unwrap_or(core::cmp::Ordering::Equal));
    Found { functions, strings, stubs: found_stubs }
}
