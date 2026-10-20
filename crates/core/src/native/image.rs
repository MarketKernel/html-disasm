//! A program as the analysis needs it, whatever the container — a port of
//! src/core/image.ts: its sections (which are code, which hold C strings), the
//! symbols it defines, what it imports and exports, where functions start,
//! and the reading of values and strings at an address. A Mach-O, an ELF or a
//! PE file read by the core is turned into one (`from_macho`, `from_elf`,
//! `from_pe`).
//!
//! Addresses are JavaScript numbers (`f64`), with JavaScript's bitwise
//! operations, as in the TypeScript.

use crate::demangle::{demangle, demangle_unprefixed, Demangled};
use crate::disassembly::is_text;
use crate::elf::{self, Elf};
use crate::macho::{utf8, MachO, NumberMap};
use crate::objc::{parse_objc, Objc};
use crate::pe::{self, Pe};
use crate::refs::FxHashSet;
use crate::text::to_int32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    MachO,
    Elf,
    Pe,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ImageSection {
    pub name: String,
    /// As the listing names it: `__TEXT,__text`, `.text`.
    pub label: String,
    pub addr: f64,
    pub size: f64,
    /// Where its bytes are in the file; 0 for zero-fill sections.
    pub offset: f64,
    pub code: bool,
    pub cstrings: bool,
    pub zerofill: bool,
    pub writable: bool,
    /// A Mach-O __stubs section: the size of each stub.
    pub stub_size: Option<f64>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ImageSymbol {
    pub name: String,
    pub addr: f64,
    pub function: bool,
    pub thumb: bool,
    pub size: Option<f64>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ImageImport {
    pub name: String,
    pub library: String,
    /// A weak import (Mach-O, ELF), and the symbol version an ELF import is bound to (LIBC).
    pub weak: bool,
    pub version: Option<String>,
}

/// Which code of a hybrid Windows program the image holds: its Arm code, or its x64 code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeView {
    Arm,
    X64,
}

pub struct NativeImage {
    pub format: Format,
    /// The bytes addresses are read from: a Mach-O slice, the ELF file, the PE file (or its x64 view).
    pub bytes: Vec<u8>,
    pub arch: String,
    pub sections: Vec<ImageSection>,
    pub symbols: Vec<ImageSymbol>,
    pub exports: Vec<ImageSymbol>,
    pub imports: Vec<ImageImport>,
    /// Code that stands for an imported function → its name (the analysis adds the stubs it finds).
    pub stubs: NumberMap<String>,
    /// A pointer slot holding an imported (or exported) symbol's address → its name.
    pub slots: NumberMap<String>,
    pub function_starts: Vec<f64>,
    pub entry: Option<f64>,
    /// ELF mapping symbols: address and kind.
    pub marks: Vec<(f64, char)>,
    /// Where Thumb code starts, as a 32-bit Mach-O file's function starts say.
    pub thumb: Option<Vec<f64>>,
    /// Data among the instructions the file marks (LC_DATA_IN_CODE): address, length.
    pub data_in_code: Option<Vec<(f64, f64)>>,
    pub objc: Option<Objc>,
    pub macho: Option<MachO>,
    pub elf: Option<Elf>,
    pub pe: Option<Pe>,
}

fn is_mach_code(flags: u32, sectname: &str) -> bool {
    flags & 0x8000_0000 != 0 || flags & 0x400 != 0 || sectname == "__text"
}

/// `addr & ~1` as JavaScript computes it.
#[inline]
pub fn clear_thumb(addr: f64) -> f64 {
    (to_int32(addr) & !1) as f64
}

/// An insertion-ordered set of numbers (JavaScript's Set).
#[derive(Default)]
pub struct NumberSet {
    pub list: Vec<f64>,
    seen: FxHashSet<u64>,
}

impl NumberSet {
    pub fn add(&mut self, v: f64) {
        if self.seen.insert(crate::macho::number_key(v)) {
            self.list.push(v + 0.0);
        }
    }

    pub fn has(&self, v: f64) -> bool {
        self.seen.contains(&crate::macho::number_key(v))
    }
}

impl NativeImage {
    pub fn from_macho(m: MachO, bytes: Vec<u8>) -> NativeImage {
        let sections: Vec<ImageSection> = m
            .sections
            .iter()
            .map(|s| {
                let ty = s.flags & 0xff;
                ImageSection {
                    name: s.sectname.clone(),
                    label: format!("{},{}", s.segname, s.sectname),
                    addr: s.addr,
                    size: s.size,
                    offset: s.offset as f64,
                    code: is_mach_code(s.flags, &s.sectname),
                    cstrings: ty == 2,
                    zerofill: ty == 1 || ty == 0xc || ty == 0x12 || s.offset == 0,
                    writable: false,
                    stub_size: (ty == 8 && s.reserved2 != 0).then_some(s.reserved2 as f64),
                }
            })
            .collect();
        let section_of = |addr: f64| sections.iter().find(|s| addr >= s.addr && addr < s.addr + s.size);
        let mut stubs = NumberMap::default();
        let mut slots = NumberMap::default();
        for (addr, name) in &m.stubs.entries {
            match section_of(*addr) {
                Some(s) if s.code => stubs.set(*addr, name.clone()),
                Some(_) => slots.set(*addr, name.strip_prefix('_').unwrap_or(name).to_string()),
                None => {}
            }
        }
        // N_SECT symbols: defined in a section of this file; in a code section, a function. On 32-bit
        // Arm, code is Thumb where N_ARM_THUMB_DEF (desc 8) says so, where an address has its low bit
        // set, or where the function starts (which keep that bit) say so.
        let arm = m.cputype == 12;
        let in_code = |addr: f64| sections.iter().any(|s| s.code && addr >= s.addr && addr < s.addr + s.size);
        let mut thumb = NumberSet::default();
        if arm {
            for &a in &m.function_starts {
                if to_int32(a) & 1 != 0 {
                    thumb.add(clear_thumb(a));
                }
            }
        }
        let thumb_at = |addr: f64, flagged: bool| arm && (flagged || to_int32(addr) & 1 != 0 || thumb.has(clear_thumb(addr)));
        let mut symbols: Vec<ImageSymbol> = m
            .symbols
            .iter()
            .filter(|s| !s.undefined && !s.name.is_empty() && s.ty & 0x0e == 0x0e)
            .map(|s| ImageSymbol { name: s.name.clone(), addr: s.addr, function: in_code(s.addr), thumb: thumb_at(s.addr, s.desc & 8 != 0), size: None })
            .collect();
        let exports = m
            .exports
            .iter()
            .map(|e| {
                let addr = if arm { clear_thumb(e.addr) } else { e.addr };
                ImageSymbol { name: e.name.clone(), addr, function: in_code(addr), thumb: thumb_at(e.addr, false), size: None }
            })
            .collect();
        let entry = m.entry.map(|e| if thumb.has(clear_thumb(e)) { (to_int32(e) | 1) as f64 } else { e });
        // A stripped program still names its Objective-C methods and its objc_msgSend stubs.
        let objc = parse_objc(&m, &bytes);
        if let Some(objc) = &objc {
            let named: FxHashSet<u64> = symbols.iter().map(|s| crate::macho::number_key(s.addr)).collect();
            for (imp, name) in &objc.methods.entries {
                let addr = if arm { clear_thumb(*imp) } else { *imp };
                if !named.contains(&crate::macho::number_key(addr)) {
                    symbols.push(ImageSymbol { name: name.clone(), addr, function: true, thumb: thumb_at(*imp, false), size: None });
                }
            }
            for (addr, selector) in &objc.stubs.entries {
                if !named.contains(&crate::macho::number_key(*addr)) {
                    symbols.push(ImageSymbol { name: format!("_objc_msgSend${selector}"), addr: *addr, function: true, thumb: false, size: None });
                }
            }
        }
        NativeImage {
            format: Format::MachO,
            arch: m.arch.clone(),
            sections,
            symbols,
            exports,
            imports: m.imports.iter().map(|i| ImageImport { name: i.name.clone(), library: i.library.clone(), weak: i.weak, version: None }).collect(),
            stubs,
            slots,
            function_starts: if arm { m.function_starts.iter().map(|&a| clear_thumb(a)).collect() } else { m.function_starts.clone() },
            entry,
            marks: Vec::new(),
            thumb: arm.then(|| thumb.list.clone()),
            data_in_code: arm.then(|| m.data_in_code.iter().map(|&(addr, length, _)| (addr, length as f64)).collect()),
            objc,
            macho: Some(m),
            elf: None,
            pe: None,
            bytes,
        }
    }

    pub fn from_elf(e: Elf, bytes: Vec<u8>) -> NativeImage {
        let sections: Vec<ImageSection> = e
            .sections
            .iter()
            .filter(|s| to_int32(s.flags) & elf::shf::ALLOC != 0 && s.size != 0.0 && (s.addr != 0.0 || e.ty != 1.0))
            .map(|s| {
                let f = to_int32(s.flags);
                ImageSection {
                    name: s.name.clone(),
                    label: s.name.clone(),
                    addr: s.addr,
                    size: s.size,
                    offset: if s.ty == elf::sht::NOBITS { 0.0 } else { s.offset },
                    code: f & elf::shf::EXEC != 0,
                    cstrings: f & elf::shf::STRINGS != 0 && s.entsize <= 1.0,
                    zerofill: s.ty == elf::sht::NOBITS,
                    writable: f & elf::shf::WRITE != 0,
                    stub_size: None,
                }
            })
            .collect();
        let is_function = |ty: f64| ty == elf::stt::FUNC || ty == elf::stt::GNU_IFUNC;
        let mut seen: FxHashSet<(u64, String)> = FxHashSet::default();
        let mut symbols = Vec::new();
        for sym in e.symtab.iter().chain(&e.dynsyms) {
            let b = sym.name.as_bytes();
            let mark = b.len() >= 2 && b[0] == b'$' && matches!(b[1], b'a' | b't' | b'x' | b'd') && (b.len() == 2 || b[2] == b'.');
            if sym.name.is_empty() || sym.shndx == 0.0 || sym.ty == elf::stt::SECTION || sym.ty == elf::stt::FILE || mark {
                continue;
            }
            if !seen.insert((crate::macho::number_key(sym.addr), sym.name.clone())) {
                continue;
            }
            symbols.push(ImageSymbol { name: sym.name.clone(), addr: sym.addr, function: is_function(sym.ty), thumb: sym.thumb, size: (sym.size != 0.0).then_some(sym.size) });
        }
        NativeImage {
            format: Format::Elf,
            arch: e.arch.clone(),
            sections,
            symbols,
            exports: e.exports.iter().map(|x| ImageSymbol { name: x.name.clone(), addr: x.addr, function: is_function(x.ty), thumb: x.thumb, size: None }).collect(),
            imports: e.imports.iter().map(|i| ImageImport { name: i.name.clone(), library: i.library.clone(), weak: i.weak, version: i.version.clone() }).collect(),
            stubs: NumberMap::default(),
            slots: e.slots.clone(),
            function_starts: e.function_starts.clone(),
            entry: (e.entry != 0.0).then_some(e.entry),
            marks: e.marks.clone(),
            thumb: None,
            data_in_code: None,
            objc: None,
            macho: None,
            elf: Some(e),
            pe: None,
            bytes,
        }
    }

    /// A PE image; for a hybrid program, the code of `view` (its Arm code or its x64 code).
    pub fn from_pe(native: Pe, file: Vec<u8>, view: PeView) -> NativeImage {
        const CODE: i32 = 0x20;
        const EXECUTE: i32 = 0x2000_0000;
        const WRITE: i32 = 0x8000_0000u32 as i32;
        let hybrid = native.hybrid.as_ref();
        let x64 = view == PeView::X64;
        // An ARM64X program's x64 code is described by the view an x64 process gets.
        let use_ec = hybrid.is_some_and(|h| x64 && h.ec.is_some());
        let mut ranges: Vec<(f64, f64, &'static str)> = hybrid.map(|h| h.ranges.clone()).unwrap_or_default();
        ranges.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(core::cmp::Ordering::Equal));
        let label_of = |kind: &str| match kind {
            "arm64" => "ARM64",
            "arm64ec" => "ARM64EC",
            _ => "x64",
        };
        let wanted = |kind: &str| if x64 { kind == "x64" } else { kind == "arm64" || kind == "arm64ec" };
        let mut sections: Vec<ImageSection> = Vec::new();
        for s in &native.sections {
            let in_file = s.raw_size > 0.0;
            // Bytes past the end of the raw data are zero; only what the file holds is read as the section.
            let size = if in_file { (if s.virtual_size != 0.0 { s.virtual_size } else { s.raw_size }).min(s.raw_size) } else { s.virtual_size };
            let addr = native.image_base + s.rva;
            let code = to_int32(s.flags) & (CODE | EXECUTE) != 0;
            let mut pieces: Vec<(f64, f64, Option<&'static str>)> = Vec::new();
            if hybrid.is_some() && code {
                let mut at = addr;
                for &(raddr, rsize, kind) in &ranges {
                    let from = raddr.max(addr);
                    let to = (raddr + rsize).min(addr + size);
                    if from >= to {
                        continue;
                    }
                    if from > at {
                        pieces.push((at, from - at, None));
                    }
                    pieces.push((from, to - from, Some(kind)));
                    at = to;
                }
                if at < addr + size {
                    pieces.push((at, addr + size - at, None));
                }
            } else {
                pieces.push((addr, size, None));
            }
            for (paddr, psize, kind) in pieces {
                sections.push(ImageSection {
                    name: s.name.clone(),
                    label: match kind {
                        Some(k) => format!("{} ({})", s.name, label_of(k)),
                        None => s.name.clone(),
                    },
                    addr: paddr,
                    size: psize,
                    offset: if in_file { s.raw_offset + (paddr - addr) } else { 0.0 },
                    code: if hybrid.is_some() { kind.is_some_and(wanted) } else { code },
                    cstrings: false,
                    zerofill: !in_file,
                    writable: to_int32(s.flags) & WRITE != 0,
                    stub_size: None,
                });
            }
        }
        let in_code = |addr: f64| sections.iter().any(|s| s.code && addr >= s.addr && addr < s.addr + s.size);
        let p: &Pe = if use_ec { hybrid.unwrap().ec.as_deref().unwrap() } else { &native };
        // Windows on 32-bit Arm runs Thumb code only; a code address there has its low bit set.
        let thumb = p.machine == pe::ARMNT;
        let code = |addr: f64| if thumb && in_code(clear_thumb(addr)) { clear_thumb(addr) } else { addr };
        let mut symbols: Vec<ImageSymbol> =
            p.symbols.iter().map(|s| ImageSymbol { name: s.name.clone(), addr: code(s.addr), function: s.function && in_code(code(s.addr)), thumb, size: None }).collect();
        // An x64 entry point of an ARM64EC function names the function itself in the Arm view.
        if let (Some(h), false) = (hybrid, x64) {
            let ec_exports = h.ec.as_ref().map(|ec| ec.exports.as_slice()).unwrap_or(&[]);
            for e in native.exports.iter().chain(ec_exports) {
                if let Some(&to) = h.redirections.get(e.addr) {
                    if in_code(to) {
                        symbols.push(ImageSymbol { name: e.name.clone(), addr: to, function: true, thumb: false, size: None });
                    }
                }
            }
        }
        let ec_exports: &[pe::PeExport] = match (hybrid, x64) {
            (Some(h), false) => h.ec.as_ref().map(|ec| ec.exports.as_slice()).unwrap_or(&[]),
            _ => &[],
        };
        let exports = p
            .exports
            .iter()
            .chain(ec_exports)
            .filter(|e| e.forwarder.is_none() && (hybrid.is_none() || in_code(e.addr)))
            .map(|e| ImageSymbol { name: e.name.clone(), addr: code(e.addr), function: in_code(code(e.addr)), thumb, size: None })
            .collect();
        let mut slots = NumberMap::default();
        let ec_imports: &[pe::PeImport] = match (hybrid, x64) {
            (Some(h), false) => h.ec.as_ref().map(|ec| ec.imports.as_slice()).unwrap_or(&[]),
            _ => &[],
        };
        for i in ec_imports.iter().chain(&p.imports) {
            slots.set(i.slot, i.name.clone());
        }
        let arm_starts: &[f64] = match (hybrid, x64) {
            (Some(h), false) => &h.arm_starts,
            _ => &[],
        };
        let function_starts = p
            .function_starts
            .iter()
            .copied()
            .chain(p.tls_callbacks.iter().map(|&a| code(a)))
            .chain(arm_starts.iter().copied())
            .filter(|&a| hybrid.is_none() || in_code(a))
            .collect();
        let entry = p.entry.filter(|&e| hybrid.is_none() || in_code(e));
        let marks = if thumb { sections.iter().filter(|s| s.code).map(|s| (s.addr, 't')).collect() } else { Vec::new() };
        let arch = match hybrid {
            Some(h) if x64 => "x86_64".to_string(),
            Some(h) => (if h.ranges.iter().any(|r| r.2 == "arm64") { "arm64x" } else { "arm64ec" }).to_string(),
            None => p.arch.clone(),
        };
        let imports = p.imports.iter().map(|i| ImageImport { name: i.name.clone(), library: i.library.clone(), weak: false, version: None }).collect();
        // The bytes the image reads: the x64 view's own, when that is the one.
        let bytes = if use_ec { apply_patches(&file, &hybrid.unwrap().ec_patches) } else { file };
        let pe = if use_ec { hybrid.unwrap().ec.as_deref().cloned() } else { Some(native.clone()) };
        NativeImage {
            format: Format::Pe,
            arch,
            sections,
            symbols,
            exports,
            imports,
            stubs: NumberMap::default(),
            slots,
            function_starts,
            entry,
            marks,
            thumb: None,
            data_in_code: None,
            objc: None,
            macho: None,
            elf: None,
            pe,
            bytes,
        }
    }

    pub fn is_macho(&self) -> bool {
        self.format == Format::MachO
    }

    /// The raw name the entry point goes by when no symbol names it.
    pub fn entry_name(&self) -> &'static str {
        match self.format {
            Format::MachO => {
                if self.macho.as_ref().and_then(|m| m.entry_kind) == Some("thread") {
                    "start"
                } else {
                    "_main"
                }
            }
            Format::Pe => "entry",
            Format::Elf => "_start",
        }
    }

    /// A symbol name back to source: Mach-O names carry an extra leading underscore, others do not.
    pub fn demangle(&self, raw: &str) -> Demangled {
        if self.is_macho() {
            demangle(raw)
        } else {
            demangle_unprefixed(raw)
        }
    }

    /// How an ELF PLT stub is listed: under the import's name, or `name@plt` when the library defines it.
    pub fn stub_function(&self, name: &str) -> (String, bool) {
        if self.imports.iter().any(|i| i.name == name) {
            (name.to_string(), true)
        } else {
            (format!("{name}@plt"), false)
        }
    }

    /// A function's names from its symbol; `@plt` stays after the demangled name.
    pub fn function_names(&self, raw: &str) -> Demangled {
        match raw.strip_suffix("@plt") {
            Some(base) => {
                let mut d = self.demangle(base);
                d.full.push_str("@plt");
                d.short.push_str("@plt");
                d
            }
            None => self.demangle(raw),
        }
    }

    pub fn section_of(&self, addr: f64) -> Option<&ImageSection> {
        self.sections.iter().find(|s| addr >= s.addr && addr < s.addr + s.size)
    }

    /// The file bytes behind a virtual address (none for zero-fill sections).
    pub fn bytes_at(&self, addr: f64, length: f64) -> Option<&[u8]> {
        let section = self.section_of(addr)?;
        if section.zerofill || section.offset == 0.0 {
            return None;
        }
        let at = section.offset + (addr - section.addr);
        let (a, b) = elf::subarray(self.bytes.len(), at, (at + length).min(section.offset + section.size));
        Some(&self.bytes[a..b])
    }

    /// A little-endian value of 4 or 8 bytes at an address in the file.
    pub fn value_at(&self, addr: f64, size: usize) -> Option<f64> {
        let b = self.bytes_at(addr, size as f64)?;
        if b.len() < size {
            return None;
        }
        Some(if size == 4 { u32::from_le_bytes(b[..4].try_into().unwrap()) as f64 } else { u64::from_le_bytes(b[..8].try_into().unwrap()) as f64 })
    }

    /// What a pointer-sized slot holds once loaded: its ELF relative relocation's target, or its bytes.
    pub fn slot_value(&self, addr: f64, size: usize) -> Option<f64> {
        if let Some(v) = self.elf.as_ref().and_then(|e| e.relative.get(addr)) {
            return Some(*v);
        }
        self.value_at(addr, size)
    }

    /// Is there Objective-C data at an address: a selector or class reference (not a string), a CFString (a string of its own)?
    pub fn objc_data(&self, addr: f64) -> Option<bool> {
        let objc = self.objc.as_ref()?;
        if objc.selrefs.has(addr) || objc.classrefs.has(addr) {
            return Some(false);
        }
        objc.cfstrings.has(addr).then_some(true)
    }

    /// A string that starts at an address in data: a C string, or a run of text the code gives a
    /// length for (`known`). Its text, and whether a NUL ends it.
    pub fn text_at(&self, addr: f64, known: Option<f64>) -> Option<(String, bool)> {
        let section = self.section_of(addr)?;
        if section.offset == 0.0 || section.code || section.zerofill || section.writable {
            return None;
        }
        let at = section.offset + (addr - section.addr);
        let (a, b) = elf::subarray(self.bytes.len(), at, (at + 96.0).min(section.offset + section.size));
        let bytes = &self.bytes[a..b];
        let limit = known.map_or(bytes.len(), |k| (k.max(0.0) as usize).min(bytes.len()));
        let mut end = 0;
        while end < limit && is_text(bytes[end]) {
            end += 1;
        }
        let text = strict_utf8(&bytes[..end])?;
        if let Some(k) = known {
            if end as f64 == k && k > 0.0 {
                return Some((text, false));
            }
        }
        let terminated = bytes.get(end) == Some(&0);
        if end < if terminated { 2 } else { 6 } {
            return None;
        }
        Some((text, terminated))
    }

    /// Every string of the sections that hold only NUL-terminated strings: address, text, section.
    pub fn cstrings(&self) -> Vec<(f64, String, String)> {
        let mut out = Vec::new();
        let elf = self.format == Format::Elf;
        for section in &self.sections {
            if !section.cstrings || section.offset == 0.0 {
                continue;
            }
            let (a, b) = elf::subarray(self.bytes.len(), section.offset, section.offset + section.size);
            let bytes = &self.bytes[a..b];
            let mut start = 0;
            for i in 0..bytes.len() {
                if bytes[i] != 0 {
                    continue;
                }
                if i > start {
                    let run = &bytes[start..i];
                    let text = if elf { (i - start >= 2 && run.iter().all(|&b| is_text(b))).then(|| strict_utf8(run)).flatten() } else { Some(utf8(run)) };
                    if let Some(text) = text {
                        out.push((section.addr + start as f64, text, section.name.clone()));
                    }
                }
                start = i + 1;
            }
        }
        out
    }
}

/// UTF-8 that must be valid (the page's fatal TextDecoder; a leading byte order mark dropped).
pub fn strict_utf8(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    Some(text.strip_prefix('\u{feff}').unwrap_or(text).to_string())
}

/// A copy of the file with an ARM64X program's dynamic relocations written again.
fn apply_patches(file: &[u8], patches: &[(usize, Vec<u8>)]) -> Vec<u8> {
    let mut out = file.to_vec();
    for (at, bytes) in patches {
        out[*at..*at + bytes.len()].copy_from_slice(bytes);
    }
    out
}
