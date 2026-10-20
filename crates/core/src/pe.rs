//! The PE reader, a port of src/core/pe.ts: Windows executables and DLLs (PE32
//! for i386, PE32+ for x86-64 and arm64) — the headers and data directories,
//! the sections, the imports with each one's slot in the import address
//! table, the exports, where functions start (the exception table), the TLS
//! callbacks, the relocations, the PDB a build points at, the COFF symbols, and
//! the CHPE metadata of a hybrid (ARM64EC, ARM64X) program with the view an x64
//! process gets of an ARM64X one.
//!
//! As in the TypeScript, values are JavaScript numbers (`f64` here) and the
//! bitwise operations go through [`to_int32`].

use crate::elf::subarray;
use crate::macho::{utf8, NumberMap};
use crate::text::{js_hex, js_number, to_int32};

pub const I386: f64 = 332.0;
pub const AMD64: f64 = 34404.0;
pub const ARM64: f64 = 43620.0;
pub const ARMNT: f64 = 452.0;

const DIRECTORY_NAMES: [&str; 16] = [
    "Export",
    "Import",
    "Resource",
    "Exception",
    "Certificate",
    "Base relocation",
    "Debug",
    "Architecture",
    "Global pointer",
    "TLS",
    "Load config",
    "Bound import",
    "IAT",
    "Delay import",
    "CLR runtime",
    "Reserved",
];
const CHARACTERISTICS: [(i32, &str); 7] =
    [(0x1, "RELOCS_STRIPPED"), (0x2, "EXECUTABLE_IMAGE"), (0x20, "LARGE_ADDRESS_AWARE"), (0x100, "32BIT_MACHINE"), (0x200, "DEBUG_STRIPPED"), (0x1000, "SYSTEM"), (0x2000, "DLL")];
const DLL_CHARACTERISTICS: [(i32, &str); 11] = [
    (0x20, "HIGH_ENTROPY_VA"),
    (0x40, "DYNAMIC_BASE"),
    (0x80, "FORCE_INTEGRITY"),
    (0x100, "NX_COMPAT"),
    (0x200, "NO_ISOLATION"),
    (0x400, "NO_SEH"),
    (0x800, "NO_BIND"),
    (0x1000, "APPCONTAINER"),
    (0x2000, "WDM_DRIVER"),
    (0x4000, "GUARD_CF"),
    (0x8000, "TERMINAL_SERVER_AWARE"),
];
const SECTION_EXECUTE: i32 = 0x2000_0000;

fn machine_name(m: f64) -> Option<&'static str> {
    Some(match m as i64 {
        0x14c => "i386",
        0x8664 => "x86-64",
        0xaa64 => "arm64",
        0x1c4 => "arm (Thumb-2)",
        0xa641 => "arm64ec",
        0xa64e => "arm64x",
        0x200 => "ia64",
        0x1c0 => "arm",
        0x5064 => "riscv64",
        _ => return None,
    })
}

fn subsystem_name(s: f64) -> Option<&'static str> {
    Some(match s as i64 {
        1 => "native",
        2 => "Windows GUI",
        3 => "Windows console",
        5 => "OS/2 console",
        7 => "POSIX console",
        9 => "Windows CE",
        10 => "EFI application",
        11 => "EFI boot driver",
        12 => "EFI runtime driver",
        13 => "EFI ROM",
        14 => "Xbox",
        16 => "Windows boot application",
        _ => return None,
    })
}

fn arch_of(machine: f64) -> String {
    match machine as i64 {
        0x8664 => "x86_64".into(),
        0x14c => "x86".into(),
        0xaa64 => "arm64".into(),
        0x1c4 => "armv7".into(),
        _ => machine_name(machine).map_or_else(|| format!("machine 0x{}", js_hex(machine)), String::from),
    }
}

fn names(value: f64, table: &[(i32, &'static str)]) -> Vec<&'static str> {
    let v = to_int32(value);
    table.iter().filter(|&&(bit, _)| v & bit != 0).map(|&(_, n)| n).collect()
}

#[derive(Clone, Debug, PartialEq)]
pub struct PeSection {
    pub name: String,
    pub rva: f64,
    pub virtual_size: f64,
    pub raw_size: f64,
    pub raw_offset: f64,
    pub flags: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PeImport {
    pub name: String,
    pub library: String,
    pub ordinal: Option<f64>,
    pub hint: Option<f64>,
    pub slot: f64,
    pub delayed: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PeExport {
    pub name: String,
    pub ordinal: f64,
    pub addr: f64,
    pub forwarder: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct PeSymbol {
    pub name: String,
    pub addr: f64,
    pub function: bool,
    pub external: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Pdb {
    pub path: String,
    pub guid: String,
    pub age: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Hybrid {
    /// The code map: address, size, kind (`arm64`, `arm64ec`, `x64`).
    pub ranges: Vec<(f64, f64, &'static str)>,
    pub redirections: NumberMap<f64>,
    pub arm_starts: Vec<f64>,
    /// ARM64X: the program as an x64 process sees it, read from the file with `ec_patches` applied.
    pub ec: Option<Box<Pe>>,
    /// The bytes the ARM64X dynamic relocations write, in order: file offset and the bytes there.
    pub ec_patches: Vec<(usize, Vec<u8>)>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Pe {
    pub machine: f64,
    pub machine_name: String,
    pub arch: String,
    pub is64: bool,
    pub timestamp: f64,
    pub characteristics: f64,
    pub flag_names: Vec<&'static str>,
    pub dll: bool,
    pub image_base: f64,
    pub entry: Option<f64>,
    pub section_alignment: f64,
    pub file_alignment: f64,
    pub os_version: String,
    pub subsystem_version: String,
    pub linker_version: String,
    pub subsystem: f64,
    pub subsystem_name: String,
    pub dll_characteristics: f64,
    pub dll_flag_names: Vec<&'static str>,
    pub size_of_image: f64,
    pub checksum: f64,
    /// Name, RVA, size.
    pub directories: Vec<(&'static str, f64, f64)>,
    pub sections: Vec<PeSection>,
    pub imports: Vec<PeImport>,
    pub libraries: Vec<String>,
    pub exports: Vec<PeExport>,
    pub dll_name: Option<String>,
    pub function_starts: Vec<f64>,
    pub tls_callbacks: Vec<f64>,
    pub symbols: Vec<PeSymbol>,
    pub relocation_count: f64,
    pub pdb: Option<Pdb>,
    pub clr: bool,
    pub signed: bool,
    pub hybrid: Option<Hybrid>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeError {
    /// No MZ signature.
    NotPe,
    /// An MS-DOS program without a PE header.
    NoPeHeader,
    /// No optional header the reader knows.
    NoOptionalHeader,
    /// A read at a negative offset, where the TypeScript's DataView threw.
    OutOfBounds,
}

type Result<T> = core::result::Result<T, PeError>;

pub fn is_pe(bytes: &[u8]) -> bool {
    bytes.len() >= 64 && bytes[0] == 0x4d && bytes[1] == 0x5a
}

/// Reads the file as the TypeScript's Reader did: past the end reads as 0; a negative offset fails.
struct Reader<'a> {
    bytes: &'a [u8],
}

impl Reader<'_> {
    fn take<const N: usize>(&self, at: f64) -> Result<Option<[u8; N]>> {
        if at + N as f64 > self.bytes.len() as f64 {
            return Ok(None);
        }
        if at < 0.0 {
            return Err(PeError::OutOfBounds);
        }
        let a = at as usize;
        Ok(Some(self.bytes[a..a + N].try_into().unwrap()))
    }

    fn u8(&self, at: f64) -> f64 {
        if at >= 0.0 && at < self.bytes.len() as f64 {
            self.bytes[at as usize] as f64
        } else {
            // `bytes[-1]` is undefined, and so is what is made of it: a NaN.
            if at < 0.0 {
                f64::NAN
            } else {
                0.0
            }
        }
    }

    fn u16(&self, at: f64) -> Result<f64> {
        Ok(self.take::<2>(at)?.map_or(0.0, |b| u16::from_le_bytes(b) as f64))
    }

    fn u32(&self, at: f64) -> Result<f64> {
        Ok(self.take::<4>(at)?.map_or(0.0, |b| u32::from_le_bytes(b) as f64))
    }

    fn u64(&self, at: f64) -> Result<f64> {
        Ok(self.take::<8>(at)?.map_or(0.0, |b| u64::from_le_bytes(b) as f64))
    }

    fn cstr(&self, at: f64, max: f64) -> String {
        let len = self.bytes.len() as f64;
        let mut end = at;
        if end < 0.0 {
            end = len.min(at + max).min(0.0);
        }
        while end < len && end - at < max && self.bytes[end as usize] != 0 {
            end += 1.0;
        }
        let (start, stop) = subarray(self.bytes.len(), at, end);
        utf8(&self.bytes[start..stop])
    }
}

/// Opens a PE file. `as_ec`: the bytes are an ARM64X program's EC view, and are not read for another.
pub fn parse_pe(file: &[u8], as_ec: bool) -> Result<Pe> {
    let r = Reader { bytes: file };
    if !is_pe(file) {
        return Err(PeError::NotPe);
    }
    let pe_at = r.u32(60.0)?;
    if pe_at + 24.0 > file.len() as f64 || r.u32(pe_at)? != 17744.0 {
        return Err(PeError::NoPeHeader);
    }
    let coff = pe_at + 4.0;
    let machine = r.u16(coff)?;
    let section_count = r.u16(coff + 2.0)?;
    let timestamp = r.u32(coff + 4.0)?;
    let symbol_table = r.u32(coff + 8.0)?;
    let symbol_count = r.u32(coff + 12.0)?;
    let optional_size = r.u16(coff + 16.0)?;
    let characteristics = r.u16(coff + 18.0)?;
    let opt = coff + 20.0;
    let magic = r.u16(opt)?;
    if magic != 0x10b as f64 && magic != 0x20b as f64 {
        return Err(PeError::NoOptionalHeader);
    }
    let is64 = magic == 0x20b as f64;
    let image_base = if is64 { r.u64(opt + 24.0)? } else { r.u32(opt + 28.0)? };
    let entry_rva = r.u32(opt + 16.0)?;
    let dir_count = r.u32(opt + if is64 { 108.0 } else { 92.0 })?;
    let dir_at = opt + if is64 { 112.0 } else { 96.0 };
    let mut directories = Vec::new();
    for (i, &name) in DIRECTORY_NAMES.iter().enumerate().take(dir_count.min(16.0) as usize) {
        directories.push((name, r.u32(dir_at + i as f64 * 8.0)?, r.u32(dir_at + i as f64 * 8.0 + 4.0)?));
    }

    // The string table after the COFF symbols holds section names longer than eight bytes (/4…).
    let strings = if symbol_table != 0.0 && symbol_count != 0.0 { symbol_table + symbol_count * 18.0 } else { 0.0 };
    let mut sections: Vec<PeSection> = Vec::new();
    let section_at = opt + optional_size;
    for i in 0..section_count as usize {
        let at = section_at + i as f64 * 40.0;
        let mut name = r.cstr(at, 8.0);
        if strings != 0.0 && name.len() > 1 && name.starts_with('/') && name[1..].bytes().all(|b| b.is_ascii_digit()) {
            name = r.cstr(strings + name[1..].parse::<f64>().unwrap_or(f64::NAN), 512.0);
        }
        sections.push(PeSection {
            name,
            virtual_size: r.u32(at + 8.0)?,
            rva: r.u32(at + 12.0)?,
            raw_size: r.u32(at + 16.0)?,
            raw_offset: r.u32(at + 20.0)?,
            flags: r.u32(at + 36.0)?,
        });
    }
    let first_rva = sections.first().map_or(4096.0, |s| s.rva);
    // The file offset of a relative virtual address, or -1.
    let offset_of = |rva: f64| -> f64 {
        for s in &sections {
            let size = s.virtual_size.max(s.raw_size);
            if rva >= s.rva && rva < s.rva + size {
                return if rva - s.rva < s.raw_size { s.raw_offset + (rva - s.rva) } else { -1.0 };
            }
        }
        if rva < first_rva && rva < file.len() as f64 {
            rva
        } else {
            -1.0
        }
    };
    let str_at = |rva: f64| {
        let at = offset_of(rva);
        if at < 0.0 {
            String::new()
        } else {
            r.cstr(at, 512.0)
        }
    };
    let dir = |i: usize| directories.get(i).map_or((0.0, 0.0), |d| (d.1, d.2));
    let ptr = if is64 { 8.0 } else { 4.0 };
    let read_ptr = |at: f64| if is64 { r.u64(at) } else { r.u32(at) };

    let subsystem = r.u16(opt + 68.0)?;
    let dll_characteristics = r.u16(opt + 70.0)?;
    let mut pe = Pe {
        machine,
        machine_name: machine_name(machine).map_or_else(|| format!("0x{}", js_hex(machine)), String::from),
        arch: arch_of(machine),
        is64,
        timestamp,
        characteristics,
        flag_names: names(characteristics, &CHARACTERISTICS),
        dll: to_int32(characteristics) & 0x2000 != 0,
        image_base,
        entry: if entry_rva != 0.0 { Some(image_base + entry_rva) } else { None },
        section_alignment: r.u32(opt + 32.0)?,
        file_alignment: r.u32(opt + 36.0)?,
        os_version: format!("{}.{}", js_number(r.u16(opt + 40.0)?), js_number(r.u16(opt + 42.0)?)),
        subsystem_version: format!("{}.{}", js_number(r.u16(opt + 48.0)?), js_number(r.u16(opt + 50.0)?)),
        linker_version: format!("{}.{}", js_number(r.u8(opt + 2.0)), js_number(r.u8(opt + 3.0))),
        subsystem,
        subsystem_name: subsystem_name(subsystem).map_or_else(|| format!("subsystem {}", js_number(subsystem)), String::from),
        dll_characteristics,
        dll_flag_names: names(dll_characteristics, &DLL_CHARACTERISTICS),
        size_of_image: r.u32(opt + 56.0)?,
        checksum: r.u32(opt + 64.0)?,
        directories: directories.clone(),
        sections: sections.clone(),
        imports: Vec::new(),
        libraries: Vec::new(),
        exports: Vec::new(),
        dll_name: None,
        function_starts: Vec::new(),
        tls_callbacks: Vec::new(),
        symbols: Vec::new(),
        relocation_count: 0.0,
        pdb: None,
        clr: dir(14).0 != 0.0,
        signed: dir(4).1 != 0.0,
        hybrid: None,
    };

    // Imports: one descriptor per DLL; the lookup table names each import, the address table holds its slot.
    let mut libraries: Vec<String> = Vec::new();
    let read_thunks = |pe: &mut Pe, library: &str, lookup: f64, iat: f64, delayed: bool| -> Result<()> {
        for i in 0..65536 {
            let at = offset_of(lookup + i as f64 * ptr);
            if at < 0.0 {
                break;
            }
            let value = read_ptr(at)?;
            if value == 0.0 {
                break;
            }
            let slot = image_base + iat + i as f64 * ptr;
            let by_ordinal = if is64 { value >= 9223372036854775808.0 } else { value >= 2147483648.0 };
            if by_ordinal {
                let ordinal = value % 65536.0;
                pe.imports.push(PeImport { name: format!("#{}", js_number(ordinal)), library: library.into(), ordinal: Some(ordinal), hint: None, slot, delayed });
            } else {
                let hint_at = offset_of(value % 2147483648.0);
                if hint_at < 0.0 {
                    continue;
                }
                pe.imports.push(PeImport { name: r.cstr(hint_at + 2.0, 512.0), library: library.into(), ordinal: None, hint: Some(r.u16(hint_at)?), slot, delayed });
            }
        }
        Ok(())
    };
    if dir(1).0 != 0.0 {
        let mut at = offset_of(dir(1).0);
        let mut k = 0;
        while at >= 0.0 && k < 4096 {
            let lookup = r.u32(at)?;
            let name_rva = r.u32(at + 12.0)?;
            let iat = r.u32(at + 16.0)?;
            if name_rva == 0.0 && iat == 0.0 {
                break;
            }
            let library = str_at(name_rva);
            if !libraries.contains(&library) {
                libraries.push(library.clone());
            }
            read_thunks(&mut pe, &library, if lookup != 0.0 { lookup } else { iat }, iat, false)?;
            at += 20.0;
            k += 1;
        }
    }
    if dir(13).0 != 0.0 {
        let mut at = offset_of(dir(13).0);
        let mut k = 0;
        while at >= 0.0 && k < 4096 {
            let attributes = r.u32(at)?;
            let name_rva = r.u32(at + 4.0)?;
            if name_rva == 0.0 {
                break;
            }
            // Old (Visual C++ 6) descriptors hold virtual addresses instead of RVAs.
            let fix = |v: f64| if to_int32(attributes) & 1 != 0 { v } else { v - image_base };
            let library = str_at(fix(name_rva));
            if !libraries.contains(&library) {
                libraries.push(library.clone());
            }
            let lookup = fix(r.u32(at + 16.0)?);
            let iat = fix(r.u32(at + 12.0)?);
            read_thunks(&mut pe, &library, lookup, iat, true)?;
            at += 32.0;
            k += 1;
        }
    }
    pe.libraries = libraries;

    // Exports, by ordinal; the names point at some of them. An address inside the export directory is a forwarder.
    if dir(0).0 != 0.0 {
        let at = offset_of(dir(0).0);
        if at >= 0.0 {
            let name = str_at(r.u32(at + 12.0)?);
            pe.dll_name = (!name.is_empty()).then_some(name);
            let base = r.u32(at + 16.0)?;
            let functions = r.u32(at + 20.0)?.min(1048576.0);
            let names_count = r.u32(at + 24.0)?.min(1048576.0);
            let address_at = offset_of(r.u32(at + 28.0)?);
            let name_at = offset_of(r.u32(at + 32.0)?);
            let ordinal_at = offset_of(r.u32(at + 36.0)?);
            let mut named: NumberMap<String> = NumberMap::default();
            let mut i = 0.0;
            while i < names_count && name_at >= 0.0 && ordinal_at >= 0.0 {
                let ordinal = r.u16(ordinal_at + i * 2.0)?;
                let name = str_at(r.u32(name_at + i * 4.0)?);
                named.set(ordinal, name);
                i += 1.0;
            }
            let (export_rva, export_size) = dir(0);
            let mut i = 0.0;
            while i < functions && address_at >= 0.0 {
                let rva = r.u32(address_at + i * 4.0)?;
                if rva != 0.0 {
                    let name = named.get(i).cloned().unwrap_or_else(|| format!("#{}", js_number(base + i)));
                    let forwarded = rva >= export_rva && rva < export_rva + export_size;
                    pe.exports.push(PeExport { name, ordinal: base + i, addr: image_base + rva, forwarder: forwarded.then(|| str_at(rva)) });
                }
                i += 1.0;
            }
        }
    }

    // The exception table: x86-64 entries are 12 bytes (begin, end, unwind info), arm64 and 32-bit Arm ones 8
    // (a Thumb function's start has its low bit set).
    if dir(3).0 != 0.0 && (machine == AMD64 || machine == ARM64 || machine == ARMNT) {
        let size = if machine == AMD64 { 12.0 } else { 8.0 };
        let at = offset_of(dir(3).0);
        let mut i = 0.0;
        while at >= 0.0 && i * size + size <= dir(3).1 {
            let begin = to_int32(r.u32(at + i * size)?) & if machine == ARMNT { !1 } else { !0 };
            if begin != 0 {
                pe.function_starts.push(image_base + begin as f64);
            }
            i += 1.0;
        }
    }

    // TLS callbacks run before the entry point: functions too.
    if dir(9).0 != 0.0 {
        let at = offset_of(dir(9).0);
        let callbacks = if at >= 0.0 { read_ptr(at + ptr * 3.0)? } else { 0.0 };
        let cb = if callbacks != 0.0 { offset_of(callbacks - image_base) } else { -1.0 };
        let mut k = 0.0;
        while cb >= 0.0 && k < 64.0 {
            let v = read_ptr(cb + k * ptr)?;
            if v == 0.0 {
                break;
            }
            pe.tls_callbacks.push(v);
            k += 1.0;
        }
    }

    // Relocations: blocks of a page and its 16-bit entries (type 0 is padding).
    if dir(5).0 != 0.0 {
        let mut at = offset_of(dir(5).0);
        let end = at + dir(5).1;
        while at >= 0.0 && at + 8.0 <= end {
            let block = r.u32(at + 4.0)?;
            if block < 8.0 {
                break;
            }
            let mut k = 8.0;
            while k < block {
                if to_int32(r.u16(at + k)?) >> 12 != 0 {
                    pe.relocation_count += 1.0;
                }
                k += 2.0;
            }
            at += block;
        }
    }

    // Debug directory: a CodeView RSDS record names the PDB.
    if dir(6).0 != 0.0 {
        let at = offset_of(dir(6).0);
        let mut i = 0.0;
        while at >= 0.0 && i * 28.0 < dir(6).1 {
            let entry = at + i * 28.0;
            i += 1.0;
            if r.u32(entry + 12.0)? != 2.0 {
                continue;
            }
            let data = r.u32(entry + 24.0)?;
            if r.u32(data)? != 1396986706.0 {
                continue;
            }
            let (a, b) = subarray(file.len(), data + 4.0, data + 20.0);
            let g = &file[a..b];
            let hex = |from: usize, to: usize, reverse: bool| -> String {
                let part = &g[from.min(g.len())..to.min(g.len()).max(from.min(g.len()))];
                let mut bytes: Vec<u8> = part.to_vec();
                if reverse {
                    bytes.reverse();
                }
                bytes.iter().map(|b| format!("{b:02x}")).collect()
            };
            let guid = format!("{}-{}-{}-{}-{}", hex(0, 4, true), hex(4, 6, true), hex(6, 8, true), hex(8, 10, false), hex(10, 16, false)).to_uppercase();
            pe.pdb = Some(Pdb { path: r.cstr(data + 24.0, 512.0), guid, age: r.u32(data + 20.0)? });
            break;
        }
    }

    // The load configuration of a 64-bit program: the CHPE metadata of a hybrid one, and the
    // dynamic relocations that turn an ARM64X program into its x64-compatible view.
    if is64 && dir(10).0 != 0.0 {
        let at = offset_of(dir(10).0);
        let size = if at >= 0.0 { r.u32(at)? } else { 0.0 };
        let chpe = if size >= 208.0 { r.u64(at + 200.0)? } else { 0.0 };
        let meta = if chpe != 0.0 { offset_of(chpe - image_base) } else { -1.0 };
        if meta >= 0.0 && r.u32(meta)? >= 1.0 {
            let mut hybrid = Hybrid { ranges: Vec::new(), redirections: NumberMap::default(), arm_starts: Vec::new(), ec: None, ec_patches: Vec::new() };
            let map = offset_of(r.u32(meta + 4.0)?);
            let count = r.u32(meta + 8.0)?;
            let mut i = 0.0;
            while map >= 0.0 && i < count.min(65536.0) {
                let start = r.u32(map + i * 8.0)?;
                let kind = match to_int32(start) & 3 {
                    0 => Some("arm64"),
                    1 => Some("arm64ec"),
                    2 => Some("x64"),
                    _ => None,
                };
                if let Some(kind) = kind {
                    hybrid.ranges.push((image_base + (to_int32(start) & !3) as f64, r.u32(map + i * 8.0 + 4.0)?, kind));
                }
                i += 1.0;
            }
            let redirects = offset_of(r.u32(meta + 16.0)?);
            let count = r.u32(meta + 52.0)?;
            let mut i = 0.0;
            while redirects >= 0.0 && i < count.min(1048576.0) {
                hybrid.redirections.set(image_base + r.u32(redirects + i * 8.0)?, image_base + r.u32(redirects + i * 8.0 + 4.0)?);
                i += 1.0;
            }
            let rfe = offset_of(r.u32(meta + 64.0)?);
            let count = (r.u32(meta + 68.0)? / 8.0).floor();
            let mut i = 0.0;
            while rfe >= 0.0 && i < count {
                let begin = r.u32(rfe + i * 8.0)?;
                if begin != 0.0 {
                    hybrid.arm_starts.push(image_base + begin);
                }
                i += 1.0;
            }
            if !hybrid.ranges.is_empty() {
                if !as_ec && size >= 232.0 {
                    if let Some((view, patches)) = ec_view(&r, &sections, r.u32(at + 224.0)?, r.u16(at + 228.0)?)? {
                        // Without its EC view the program still opens as arm64.
                        if let Ok(ec) = parse_pe(&view, true) {
                            hybrid.ec = Some(Box::new(ec));
                            hybrid.ec_patches = patches;
                        }
                    }
                }
                pe.hybrid = Some(hybrid);
            }
        }
    }

    // COFF symbols, which MinGW and some other linkers keep in an unstripped image.
    if symbol_table != 0.0 && symbol_count != 0.0 && symbol_table + symbol_count * 18.0 <= file.len() as f64 {
        let mut i = 0.0;
        while i < symbol_count {
            let at = symbol_table + i * 18.0;
            let aux = r.u8(at + 17.0);
            let section = r.u16(at + 12.0)?;
            let storage = r.u8(at + 16.0);
            let ty = r.u16(at + 14.0)?;
            if section >= 1.0 && section <= sections.len() as f64 && (storage == 2.0 || storage == 3.0) {
                let name = if r.u32(at)? == 0.0 { r.cstr(strings + r.u32(at + 4.0)?, 512.0) } else { r.cstr(at, 8.0) };
                let s = &sections[section as usize - 1];
                let is_function = to_int32(ty) >> 4 == 2 || (storage == 2.0 && to_int32(s.flags) & SECTION_EXECUTE != 0);
                if !name.is_empty() && !name.starts_with('.') {
                    pe.symbols.push(PeSymbol { name, addr: image_base + s.rva + r.u32(at + 8.0)?, function: is_function, external: storage == 2.0 });
                }
            }
            i += aux + 1.0;
        }
    }
    Ok(pe)
}

/// An ARM64X program as an x64 process loads it: its ARM64X dynamic relocations applied to a copy of
/// the file, and the writes they made (offset, bytes) in order; None for a program that has none.
#[allow(clippy::type_complexity)]
fn ec_view(r: &Reader, sections: &[PeSection], table_offset: f64, table_section: f64) -> Result<Option<(Vec<u8>, Vec<(usize, Vec<u8>)>)>> {
    let Some(section) = (table_section >= 1.0).then(|| sections.get(table_section as usize - 1)).flatten() else { return Ok(None) };
    if table_offset == 0.0 {
        return Ok(None);
    }
    let table = section.raw_offset + table_offset;
    if r.u32(table)? != 1.0 {
        return Ok(None);
    }
    let end = table + 8.0 + r.u32(table + 4.0)?;
    let mut out = r.bytes.to_vec();
    let mut patches: Vec<(usize, Vec<u8>)> = Vec::new();
    let first_rva = sections.first().map_or(4096.0, |s| s.rva);
    // Relative addresses in the headers are file offsets; past them, the section that holds them says.
    let file_at = |rva: f64| -> f64 {
        for s in sections {
            if rva >= s.rva && rva < s.rva + s.raw_size {
                return s.raw_offset + rva - s.rva;
            }
        }
        if rva < first_rva {
            rva
        } else {
            -1.0
        }
    };
    let len = out.len() as f64;
    let mut at = table + 8.0;
    while at + 12.0 <= end {
        let symbol = r.u64(at)?;
        let size = r.u32(at + 8.0)?;
        at += 12.0;
        if symbol == 6.0 {
            // IMAGE_DYNAMIC_RELOCATION_ARM64X: blocks of a page and its entries, like base relocations.
            let mut block = at;
            while block + 8.0 <= at + size {
                let page = r.u32(block)?;
                let block_size = r.u32(block + 4.0)?;
                if block_size < 8.0 {
                    break;
                }
                let mut p = block + 8.0;
                while p + 2.0 <= block + block_size {
                    let entry = to_int32(r.u16(p)?);
                    p += 2.0;
                    let offset = (entry & 0xfff) as f64;
                    let ty = (entry >> 12) & 3;
                    let meta = entry >> 14;
                    let target = file_at(page + offset);
                    if ty == 0 || ty == 1 {
                        // Zero-fill, or a value of 1 << meta bytes that follows.
                        let bytes = 1usize << meta;
                        if entry == 0 && p >= block + block_size {
                            break; // padding at the end of a block
                        }
                        if target >= 0.0 && target + bytes as f64 <= len {
                            let t = target as usize;
                            for k in 0..bytes {
                                out[t + k] = if ty == 1 { r.u8(p + k as f64) as u8 } else { 0 };
                            }
                            patches.push((t, out[t..t + bytes].to_vec()));
                        }
                        if ty == 1 {
                            p += bytes as f64;
                        }
                    } else if ty == 2 {
                        // A delta: a 16-bit count of 4- or 8-byte units, added or taken away.
                        let delta = r.u16(p)? as i64 * if meta & 1 != 0 { 8 } else { 4 } * if meta & 2 != 0 { -1 } else { 1 };
                        p += 2.0;
                        if target >= 0.0 && target + 8.0 <= len {
                            let t = target as usize;
                            let v = u64::from_le_bytes(out[t..t + 8].try_into().unwrap()).wrapping_add(delta as u64);
                            out[t..t + 8].copy_from_slice(&v.to_le_bytes());
                            patches.push((t, out[t..t + 8].to_vec()));
                        }
                    } else {
                        break;
                    }
                }
                block += block_size;
            }
        }
        at += size;
    }
    Ok((!patches.is_empty()).then_some((out, patches)))
}
