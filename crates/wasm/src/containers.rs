//! The containers read in the core (`disasm_core::macho`): the page hands a
//! file over and gets the reading back as JSON, which it turns into the
//! objects its pages show. Why a file cannot be read comes back as a code the
//! page words in its language.

use disasm_core::elf::{parse_elf, Elf, ElfError, ElfSymbol};
use disasm_core::macho::{parse_macho, MachO, MachOError};
use disasm_core::pe::{parse_pe, Pe, PeError};
use disasm_core::text::js_number;

use super::{json_str, put_out, slice};

/// A JavaScript number as JSON writes it. Most are integers below 2^53: their digits are written
/// directly, without the float formatting the others need.
fn num(out: &mut String, v: f64) {
    if v.fract() == 0.0 && v.abs() < 9007199254740992.0 {
        let mut n = v as i64;
        if n < 0 {
            out.push('-');
            n = -n;
        }
        let mut digits = [0u8; 20];
        let mut k = digits.len();
        loop {
            k -= 1;
            digits[k] = b'0' + (n % 10) as u8;
            n /= 10;
            if n == 0 {
                break;
            }
        }
        out.push_str(core::str::from_utf8(&digits[k..]).unwrap());
        return;
    }
    out.push_str(&js_number(v));
}

fn opt_str(out: &mut String, key: &str, v: &Option<String>) {
    if let Some(v) = v {
        out.push_str(",\"");
        out.push_str(key);
        out.push_str("\":");
        json_str(out, v);
    }
}

fn list<T>(out: &mut String, items: &[T], mut item: impl FnMut(&mut String, &T)) {
    out.push('[');
    for (k, x) in items.iter().enumerate() {
        if k > 0 {
            out.push(',');
        }
        item(out, x);
    }
    out.push(']');
}

fn strings(out: &mut String, items: &[String]) {
    list(out, items, |out, s| json_str(out, s));
}

fn macho_json(m: &MachO) -> String {
    let mut o = String::with_capacity(1 << 16);
    o.push_str("{\"arches\":");
    list(&mut o, &m.arches, |o, a| {
        o.push_str("{\"name\":");
        json_str(o, &a.name);
        o.push_str(",\"offset\":");
        num(o, a.offset);
        o.push_str(",\"size\":");
        num(o, a.size);
        o.push('}');
    });
    o.push_str(&format!(",\"slice\":[{},{}],\"cputype\":{},\"cpusubtype\":{},\"arch\":", m.slice.0, m.slice.1, m.cputype, m.cpusubtype));
    json_str(&mut o, &m.arch);
    o.push_str(&format!(",\"is64\":{},\"filetype\":{},\"fileTypeName\":", m.is64, m.filetype));
    json_str(&mut o, &m.file_type_name);
    o.push_str(&format!(",\"flags\":{},\"flagNames\":", m.flags));
    list(&mut o, &m.flag_names, |o, n| json_str(o, n));
    o.push_str(",\"commands\":");
    list(&mut o, &m.commands, |o, c| {
        o.push_str(&format!("{{\"cmd\":{},\"name\":", c.cmd));
        json_str(o, &c.name);
        o.push_str(&format!(",\"size\":{},\"offset\":{},\"summary\":", c.size, c.offset));
        json_str(o, &c.summary);
        o.push('}');
    });
    o.push_str(",\"sections\":");
    list(&mut o, &m.sections, |o, s| {
        o.push_str("{\"sectname\":");
        json_str(o, &s.sectname);
        o.push_str(",\"segname\":");
        json_str(o, &s.segname);
        o.push_str(",\"addr\":");
        num(o, s.addr);
        o.push_str(",\"size\":");
        num(o, s.size);
        o.push_str(&format!(",\"offset\":{},\"align\":{},\"flags\":{},\"reserved1\":{},\"reserved2\":{}}}", s.offset, s.align, s.flags, s.reserved1, s.reserved2));
    });
    o.push_str(",\"segments\":");
    list(&mut o, &m.segments, |o, s| {
        o.push_str("{\"name\":");
        json_str(o, &s.name);
        for (key, v) in [("vmaddr", s.vmaddr), ("vmsize", s.vmsize), ("fileoff", s.fileoff), ("filesize", s.filesize)] {
            o.push_str(",\"");
            o.push_str(key);
            o.push_str("\":");
            num(o, v);
        }
        o.push_str(&format!(",\"maxprot\":{},\"initprot\":{},\"sections\":", s.maxprot, s.initprot));
        list(o, &s.sections, |o, k| o.push_str(&k.to_string()));
        o.push('}');
    });
    // Symbols as rows: name, address, type, section, desc (external and undefined follow from the type).
    o.push_str(",\"symbols\":");
    list(&mut o, &m.symbols, |o, s| {
        o.push('[');
        json_str(o, &s.name);
        o.push(',');
        num(o, s.addr);
        o.push_str(&format!(",{},{},{}]", s.ty, s.sect, s.desc));
    });
    o.push_str(",\"libraries\":");
    strings(&mut o, &m.libraries);
    o.push_str(",\"imports\":");
    list(&mut o, &m.imports, |o, i| {
        o.push('[');
        json_str(o, &i.name);
        o.push(',');
        json_str(o, &i.library);
        o.push(',');
        match i.slot {
            Some(s) => num(o, s),
            None => o.push_str("null"),
        }
        o.push_str(if i.weak { ",1]" } else { ",0]" });
    });
    o.push_str(",\"exports\":");
    list(&mut o, &m.exports, |o, e| {
        o.push('[');
        json_str(o, &e.name);
        o.push(',');
        num(o, e.addr);
        o.push(',');
        num(o, e.flags);
        o.push(']');
    });
    o.push_str(",\"stubs\":");
    list(&mut o, &m.stubs.entries, |o, (addr, name)| {
        o.push('[');
        num(o, *addr);
        o.push(',');
        json_str(o, name);
        o.push(']');
    });
    // Rebases flat: address, target, address, target…
    o.push_str(",\"rebases\":");
    list(&mut o, &m.rebases.entries, |o, (addr, target)| {
        num(o, *addr);
        o.push(',');
        num(o, *target);
    });
    o.push_str(",\"functionStarts\":");
    list(&mut o, &m.function_starts, |o, &a| num(o, a));
    o.push_str(",\"dataInCode\":");
    list(&mut o, &m.data_in_code, |o, &(addr, length, kind)| {
        num(o, addr);
        o.push_str(&format!(",{length},{kind}"));
    });
    o.push_str(",\"rpaths\":");
    strings(&mut o, &m.rpaths);
    o.push_str(",\"base\":");
    num(&mut o, m.base);
    o.push_str(",\"sliceOffset\":");
    num(&mut o, m.slice_offset);
    if let Some(e) = m.entry {
        o.push_str(",\"entry\":");
        num(&mut o, e);
    }
    if let Some(k) = m.entry_kind {
        o.push_str(&format!(",\"entryKind\":\"{k}\""));
    }
    opt_str(&mut o, "uuid", &m.uuid);
    if let Some(b) = &m.build {
        o.push_str(",\"build\":{\"platform\":");
        json_str(&mut o, &b.platform);
        o.push_str(",\"minos\":");
        json_str(&mut o, &b.minos);
        o.push_str(",\"sdk\":");
        json_str(&mut o, &b.sdk);
        o.push_str(",\"tools\":");
        strings(&mut o, &b.tools);
        o.push('}');
    }
    opt_str(&mut o, "sourceVersion", &m.source_version);
    opt_str(&mut o, "dylinker", &m.dylinker);
    opt_str(&mut o, "installName", &m.install_name);
    if let Some(s) = &m.signature {
        o.push_str(",\"signature\":{");
        let mut first = true;
        let mut key = |o: &mut String, k: &str| {
            if !first {
                o.push(',');
            }
            first = false;
            o.push('"');
            o.push_str(k);
            o.push_str("\":");
        };
        if let Some(v) = &s.identifier {
            key(&mut o, "identifier");
            json_str(&mut o, v);
        }
        if let Some(v) = &s.team_id {
            key(&mut o, "teamId");
            json_str(&mut o, v);
        }
        if let Some(v) = &s.hash_type {
            key(&mut o, "hashType");
            json_str(&mut o, v);
        }
        if let Some(v) = s.flags {
            key(&mut o, "flags");
            o.push_str(&v.to_string());
        }
        if let Some(v) = &s.entitlements {
            key(&mut o, "entitlements");
            json_str(&mut o, v);
        }
        if let Some(v) = s.pages {
            key(&mut o, "pages");
            o.push_str(&v.to_string());
        }
        o.push('}');
    }
    if let Some(e) = m.encrypted {
        o.push_str(&format!(",\"encrypted\":{e}"));
    }
    if let Some((offset, size, id)) = m.encryption {
        o.push_str(&format!(",\"encryption\":{{\"offset\":{offset},\"size\":{size},\"id\":{id}}}"));
    }
    if let Some((offset, size)) = m.signature_at {
        o.push_str(&format!(",\"signatureAt\":{{\"offset\":{offset},\"size\":{size}}}"));
    }
    o.push('}');
    o
}

/// Reads a Mach-O file (or the slice named `want`, UTF-8, empty for the default) and leaves its
/// reading as JSON in the output buffer, or `{"error": code}`.
///
/// # Safety
/// The pointers must address that many bytes in this module's memory.
#[no_mangle]
pub unsafe extern "C" fn macho_parse(bytes: *const u8, len: usize, want: *const u8, want_len: usize) -> usize {
    let file = slice(bytes, len);
    let want = std::str::from_utf8(slice(want, want_len)).ok().filter(|w| !w.is_empty());
    let text = match parse_macho(file, want) {
        Ok(m) => macho_json(&m),
        Err(e) => format!(
            "{{\"error\":\"{}\"}}",
            match e {
                MachOError::TooSmall => "tooSmall",
                MachOError::JavaClass => "javaClass",
                MachOError::NoArches => "noArches",
                MachOError::NotMachO => "notMachO",
                MachOError::OutOfBounds => "outOfBounds",
            }
        ),
    };
    put_out(&text)
}

fn opt_json(out: &mut String, v: &Option<String>) {
    match v {
        Some(v) => json_str(out, v),
        None => out.push_str("null"),
    }
}

fn nums(out: &mut String, values: &[f64]) {
    list(out, values, |o, &v| num(o, v));
}

/// A symbol as a row: name, address, size, type, bind, visibility, section, thumb, version, library.
fn elf_symbol(o: &mut String, s: &ElfSymbol) {
    o.push('[');
    json_str(o, &s.name);
    for v in [s.addr, s.size, s.ty, s.bind, s.visibility, s.shndx] {
        o.push(',');
        num(o, v);
    }
    o.push_str(if s.thumb { ",1," } else { ",0," });
    opt_json(o, &s.version);
    o.push(',');
    opt_json(o, &s.library);
    o.push(']');
}

fn elf_json(e: &Elf) -> String {
    let mut o = String::with_capacity(1 << 16);
    o.push_str(&format!("{{\"is64\":{},\"machine\":", e.is64));
    num(&mut o, e.machine);
    o.push_str(",\"machineName\":");
    json_str(&mut o, &e.machine_name);
    o.push_str(",\"arch\":");
    json_str(&mut o, &e.arch);
    o.push_str(",\"type\":");
    num(&mut o, e.ty);
    o.push_str(",\"typeName\":");
    json_str(&mut o, &e.type_name);
    o.push_str(",\"osabi\":");
    num(&mut o, e.osabi);
    o.push_str(",\"flags\":");
    num(&mut o, e.flags);
    o.push_str(",\"flagNames\":");
    strings(&mut o, &e.flag_names);
    o.push_str(",\"entry\":");
    num(&mut o, e.entry);
    // Segments as rows: type, flags, offset, vaddr, filesz, memsz, align.
    o.push_str(",\"segments\":");
    list(&mut o, &e.segments, |o, s| nums(o, &[s.ty, s.flags, s.offset, s.vaddr, s.filesz, s.memsz, s.align]));
    // Sections as rows: name, then index, type, flags, addr, offset, size, link, info, align, entsize.
    o.push_str(",\"sections\":");
    list(&mut o, &e.sections, |o, s| {
        o.push('[');
        json_str(o, &s.name);
        for v in [s.index, s.ty, s.flags, s.addr, s.offset, s.size, s.link, s.info, s.align, s.entsize] {
            o.push(',');
            num(o, v);
        }
        o.push(']');
    });
    o.push_str(&format!(",\"sectionless\":{},\"dynamic\":", e.sectionless));
    list(&mut o, &e.dynamic, |o, d| {
        o.push('[');
        num(o, d.tag);
        o.push(',');
        json_str(o, &d.name);
        o.push(',');
        num(o, d.value);
        o.push(',');
        json_str(o, &d.text);
        o.push(']');
    });
    o.push_str(",\"needed\":");
    strings(&mut o, &e.needed);
    o.push_str(",\"soname\":");
    opt_json(&mut o, &e.soname);
    o.push_str(",\"runpath\":");
    strings(&mut o, &e.runpath);
    o.push_str(",\"interpreter\":");
    opt_json(&mut o, &e.interpreter);
    o.push_str(",\"dynsyms\":");
    list(&mut o, &e.dynsyms, elf_symbol);
    o.push_str(",\"symtab\":");
    list(&mut o, &e.symtab, elf_symbol);
    o.push_str(",\"imports\":");
    list(&mut o, &e.imports, |o, i| {
        o.push('[');
        json_str(o, &i.name);
        o.push(',');
        json_str(o, &i.library);
        o.push(',');
        opt_json(o, &i.version);
        o.push_str(if i.weak { ",1," } else { ",0," });
        num(o, i.ty);
        o.push(']');
    });
    o.push_str(",\"exports\":");
    list(&mut o, &e.exports, |o, x| {
        o.push('[');
        json_str(o, &x.name);
        for v in [x.addr, x.size, x.ty] {
            o.push(',');
            num(o, v);
        }
        o.push_str(if x.thumb { ",1," } else { ",0," });
        opt_json(o, &x.version);
        o.push(']');
    });
    o.push_str(",\"marks\":");
    list(&mut o, &e.marks, |o, &(addr, kind)| {
        num(o, addr);
        o.push_str(&format!(",\"{kind}\""));
    });
    // Relocations flat: offset, type, sym, addend…
    o.push_str(",\"relocations\":");
    list(&mut o, &e.relocations, |o, r| {
        num(o, r.offset);
        o.push(',');
        num(o, r.ty);
        o.push(',');
        num(o, r.sym);
        o.push(',');
        num(o, r.addend);
    });
    o.push_str(",\"relocationCounts\":");
    list(&mut o, &e.relocation_counts, |o, (name, n)| {
        o.push('[');
        json_str(o, name);
        o.push(',');
        num(o, *n);
        o.push(']');
    });
    o.push_str(",\"relocationFormats\":");
    list(&mut o, &e.relocation_formats, |o, f| json_str(o, f));
    o.push_str(",\"slots\":");
    list(&mut o, &e.slots.entries, |o, (addr, name)| {
        o.push('[');
        num(o, *addr);
        o.push(',');
        json_str(o, name);
        o.push(']');
    });
    o.push_str(",\"relative\":");
    list(&mut o, &e.relative.entries, |o, &(slot, value)| {
        num(o, slot);
        o.push(',');
        num(o, value);
    });
    o.push_str(",\"functionStarts\":");
    nums(&mut o, &e.function_starts);
    o.push_str(",\"initArray\":");
    nums(&mut o, &e.init_array);
    o.push_str(",\"finiArray\":");
    nums(&mut o, &e.fini_array);
    o.push_str(",\"notes\":");
    list(&mut o, &e.notes, |o, n| {
        o.push('[');
        json_str(o, &n.owner);
        o.push(',');
        num(o, n.ty);
        o.push_str(&format!(",{},{}]", n.desc.0, n.desc.1));
    });
    if let Some(a) = &e.android {
        o.push_str(",\"android\":{\"api\":");
        num(&mut o, a.api);
        if let Some(ndk) = &a.ndk {
            o.push_str(",\"ndk\":");
            json_str(&mut o, ndk);
        }
        if let Some(build) = &a.build {
            o.push_str(",\"build\":");
            json_str(&mut o, build);
        }
        o.push('}');
    }
    opt_str(&mut o, "buildId", &e.build_id);
    o.push_str(",\"features\":");
    list(&mut o, &e.features, |o, f| json_str(o, f));
    o.push_str(",\"attributes\":");
    list(&mut o, &e.attributes, |o, (k, v)| {
        o.push('[');
        json_str(o, k);
        o.push(',');
        json_str(o, v);
        o.push(']');
    });
    o.push_str(",\"comment\":");
    strings(&mut o, &e.comment);
    o.push_str(&format!(",\"debugInfo\":{}}}", e.debug_info));
    o
}

/// Reads an ELF file and leaves its reading as JSON in the output buffer, or `{"error": code}`.
///
/// # Safety
/// The pointer must address `len` bytes in this module's memory.
#[no_mangle]
pub unsafe extern "C" fn elf_parse(bytes: *const u8, len: usize) -> usize {
    let text = match parse_elf(slice(bytes, len)) {
        Ok(e) => elf_json(&e),
        Err(e) => format!(
            "{{\"error\":\"{}\"}}",
            match e {
                ElfError::NotElf => "notElf",
                ElfError::UnknownClass => "unknownClass",
                ElfError::BigEndian => "bigEndian",
            }
        ),
    };
    put_out(&text)
}

fn pe_json(p: &Pe, o: &mut String) {
    o.push_str("{\"machine\":");
    num(o, p.machine);
    o.push_str(",\"machineName\":");
    json_str(o, &p.machine_name);
    o.push_str(",\"arch\":");
    json_str(o, &p.arch);
    o.push_str(&format!(",\"is64\":{},\"timestamp\":", p.is64));
    num(o, p.timestamp);
    o.push_str(",\"characteristics\":");
    num(o, p.characteristics);
    o.push_str(",\"flagNames\":");
    list(o, &p.flag_names, |o, n| json_str(o, n));
    o.push_str(&format!(",\"dll\":{},\"imageBase\":", p.dll));
    num(o, p.image_base);
    if let Some(e) = p.entry {
        o.push_str(",\"entry\":");
        num(o, e);
    }
    for (key, v) in [("sectionAlignment", p.section_alignment), ("fileAlignment", p.file_alignment)] {
        o.push_str(&format!(",\"{key}\":"));
        num(o, v);
    }
    for (key, v) in [("osVersion", &p.os_version), ("subsystemVersion", &p.subsystem_version), ("linkerVersion", &p.linker_version)] {
        o.push_str(&format!(",\"{key}\":"));
        json_str(o, v);
    }
    o.push_str(",\"subsystem\":");
    num(o, p.subsystem);
    o.push_str(",\"subsystemName\":");
    json_str(o, &p.subsystem_name);
    o.push_str(",\"dllCharacteristics\":");
    num(o, p.dll_characteristics);
    o.push_str(",\"dllFlagNames\":");
    list(o, &p.dll_flag_names, |o, n| json_str(o, n));
    for (key, v) in [("sizeOfImage", p.size_of_image), ("checksum", p.checksum), ("relocationCount", p.relocation_count)] {
        o.push_str(&format!(",\"{key}\":"));
        num(o, v);
    }
    o.push_str(",\"directories\":");
    list(o, &p.directories, |o, &(name, rva, size)| {
        o.push('[');
        json_str(o, name);
        o.push(',');
        num(o, rva);
        o.push(',');
        num(o, size);
        o.push(']');
    });
    // Sections as rows: name, rva, virtual size, raw size, raw offset, flags.
    o.push_str(",\"sections\":");
    list(o, &p.sections, |o, s| {
        o.push('[');
        json_str(o, &s.name);
        for v in [s.rva, s.virtual_size, s.raw_size, s.raw_offset, s.flags] {
            o.push(',');
            num(o, v);
        }
        o.push(']');
    });
    // Imports as rows: name, library, ordinal, hint, slot, delayed.
    o.push_str(",\"imports\":");
    list(o, &p.imports, |o, i| {
        o.push('[');
        json_str(o, &i.name);
        o.push(',');
        json_str(o, &i.library);
        for v in [i.ordinal, i.hint] {
            o.push(',');
            match v {
                Some(v) => num(o, v),
                None => o.push_str("null"),
            }
        }
        o.push(',');
        num(o, i.slot);
        o.push_str(if i.delayed { ",1]" } else { ",0]" });
    });
    o.push_str(",\"libraries\":");
    strings(o, &p.libraries);
    o.push_str(",\"exports\":");
    list(o, &p.exports, |o, e| {
        o.push('[');
        json_str(o, &e.name);
        o.push(',');
        num(o, e.ordinal);
        o.push(',');
        num(o, e.addr);
        o.push(',');
        opt_json(o, &e.forwarder);
        o.push(']');
    });
    opt_str(o, "dllName", &p.dll_name);
    o.push_str(",\"functionStarts\":");
    nums(o, &p.function_starts);
    o.push_str(",\"tlsCallbacks\":");
    nums(o, &p.tls_callbacks);
    o.push_str(",\"symbols\":");
    list(o, &p.symbols, |o, s| {
        o.push('[');
        json_str(o, &s.name);
        o.push(',');
        num(o, s.addr);
        o.push_str(&format!(",{},{}]", s.function as u8, s.external as u8));
    });
    if let Some(pdb) = &p.pdb {
        o.push_str(",\"pdb\":{\"path\":");
        json_str(o, &pdb.path);
        o.push_str(",\"guid\":");
        json_str(o, &pdb.guid);
        o.push_str(",\"age\":");
        num(o, pdb.age);
        o.push('}');
    }
    o.push_str(&format!(",\"clr\":{},\"signed\":{}", p.clr, p.signed));
    if let Some(h) = &p.hybrid {
        o.push_str(",\"hybrid\":{\"ranges\":");
        list(o, &h.ranges, |o, &(addr, size, kind)| {
            o.push('[');
            num(o, addr);
            o.push(',');
            num(o, size);
            o.push_str(&format!(",\"{kind}\"]"));
        });
        o.push_str(",\"redirections\":");
        list(o, &h.redirections.entries, |o, &(from, to)| {
            num(o, from);
            o.push(',');
            num(o, to);
        });
        o.push_str(",\"armStarts\":");
        nums(o, &h.arm_starts);
        if let Some(ec) = &h.ec {
            o.push_str(",\"ecPatches\":");
            list(o, &h.ec_patches, |o, (at, bytes)| {
                o.push_str(&format!("[{at}"));
                for b in bytes {
                    o.push_str(&format!(",{b}"));
                }
                o.push(']');
            });
            o.push_str(",\"ec\":");
            pe_json(ec, o);
        }
        o.push('}');
    }
    o.push('}');
}

/// Reads a PE file and leaves its reading as JSON in the output buffer, or `{"error": code}`.
///
/// # Safety
/// The pointer must address `len` bytes in this module's memory.
#[no_mangle]
pub unsafe extern "C" fn pe_parse(bytes: *const u8, len: usize) -> usize {
    let text = match parse_pe(slice(bytes, len), false) {
        Ok(p) => {
            let mut o = String::with_capacity(1 << 16);
            pe_json(&p, &mut o);
            o
        }
        Err(e) => format!(
            "{{\"error\":\"{}\"}}",
            match e {
                PeError::NotPe => "notPe",
                PeError::NoPeHeader => "noPeHeader",
                PeError::NoOptionalHeader => "noOptionalHeader",
                PeError::OutOfBounds => "outOfBounds",
            }
        ),
    };
    put_out(&text)
}
