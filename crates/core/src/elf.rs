//! An ELF reader, a port of src/core/elf.ts: everything about an Android or
//! Linux library or program that is not its code — the header, segments and
//! sections, the symbol tables with the Arm mapping symbols, the dynamic
//! section, the symbol versions, the relocations in every form (REL, RELA,
//! RELR, Android's packed APS2), the notes, the Arm build attributes and the
//! unwind tables. A file without section headers is read through its segments.
//!
//! The TypeScript kept every value as a JavaScript number, and did its sums,
//! remainders and bitwise operations on them: here they are `f64`, and the
//! bitwise operations go through [`to_int32`] and [`to_uint32`] as JavaScript's
//! do, so a value past 2^31 or 2^53 comes out the same.

use crate::macho::{number_key, sleb, uleb, utf8, NumberMap};
use crate::refs::FxHashMap;
use crate::text::{js_hex, js_number, to_int32, to_uint32};

pub const EM_ARM: f64 = 40.0;
pub const EM_AARCH64: f64 = 183.0;
pub const EM_X86: f64 = 3.0;
pub const EM_X86_64: f64 = 62.0;

pub mod shf {
    pub const WRITE: i32 = 1;
    pub const ALLOC: i32 = 2;
    pub const EXEC: i32 = 4;
    pub const STRINGS: i32 = 0x20;
}

pub mod sht {
    pub const PROGBITS: f64 = 1.0;
    pub const SYMTAB: f64 = 2.0;
    pub const RELA: f64 = 4.0;
    pub const DYNAMIC: f64 = 6.0;
    pub const NOTE: f64 = 7.0;
    pub const NOBITS: f64 = 8.0;
    pub const REL: f64 = 9.0;
    pub const DYNSYM: f64 = 11.0;
    pub const ARM_EXIDX: f64 = 1879048193.0;
    pub const ARM_ATTRIBUTES: f64 = 1879048195.0;
}

pub mod stt {
    pub const NOTYPE: f64 = 0.0;
    pub const FUNC: f64 = 2.0;
    pub const SECTION: f64 = 3.0;
    pub const FILE: f64 = 4.0;
    pub const GNU_IFUNC: f64 = 10.0;
}

mod pt {
    pub const LOAD: f64 = 1.0;
    pub const DYNAMIC: f64 = 2.0;
    pub const INTERP: f64 = 3.0;
    pub const NOTE: f64 = 4.0;
    pub const GNU_EH_FRAME: f64 = 1685382480.0;
    pub const ARM_EXIDX: f64 = 1879048193.0;
}

#[derive(Clone, Debug, PartialEq)]
pub struct ElfSection {
    pub index: f64,
    pub name: String,
    pub ty: f64,
    pub flags: f64,
    pub addr: f64,
    pub offset: f64,
    pub size: f64,
    pub link: f64,
    pub info: f64,
    pub align: f64,
    pub entsize: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ElfSegment {
    pub ty: f64,
    pub flags: f64,
    pub offset: f64,
    pub vaddr: f64,
    pub filesz: f64,
    pub memsz: f64,
    pub align: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ElfSymbol {
    pub name: String,
    /// The address, without the Thumb bit of an A32/T32 function.
    pub addr: f64,
    pub size: f64,
    pub ty: f64,
    pub bind: f64,
    pub visibility: f64,
    pub shndx: f64,
    pub thumb: bool,
    pub version: Option<String>,
    pub library: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ElfImport {
    pub name: String,
    pub library: String,
    pub version: Option<String>,
    pub weak: bool,
    pub ty: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ElfExport {
    pub name: String,
    pub addr: f64,
    pub size: f64,
    pub ty: f64,
    pub thumb: bool,
    pub version: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DynamicEntry {
    pub tag: f64,
    pub name: String,
    pub value: f64,
    pub text: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Relocation {
    pub offset: f64,
    pub ty: f64,
    pub sym: f64,
    pub addend: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ElfNote {
    pub owner: String,
    pub ty: f64,
    /// Where its description is in the file (a subarray's ends).
    pub desc: (usize, usize),
}

#[derive(Clone, Debug, PartialEq)]
pub struct Android {
    pub api: f64,
    pub ndk: Option<String>,
    pub build: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Elf {
    pub is64: bool,
    pub machine: f64,
    pub machine_name: String,
    pub arch: String,
    pub ty: f64,
    pub type_name: String,
    pub osabi: f64,
    pub flags: f64,
    pub flag_names: Vec<String>,
    pub entry: f64,
    pub segments: Vec<ElfSegment>,
    pub sections: Vec<ElfSection>,
    pub sectionless: bool,
    pub dynamic: Vec<DynamicEntry>,
    pub needed: Vec<String>,
    pub soname: Option<String>,
    pub runpath: Vec<String>,
    pub interpreter: Option<String>,
    pub dynsyms: Vec<ElfSymbol>,
    pub symtab: Vec<ElfSymbol>,
    pub imports: Vec<ElfImport>,
    pub exports: Vec<ElfExport>,
    /// Arm mapping symbols: address and kind (`a`, `t`, `x`, `d`).
    pub marks: Vec<(f64, char)>,
    pub relocations: Vec<Relocation>,
    /// Relocation counts by type name, in the order first counted.
    pub relocation_counts: Vec<(String, f64)>,
    pub relocation_formats: Vec<&'static str>,
    pub slots: NumberMap<String>,
    pub relative: NumberMap<f64>,
    pub function_starts: Vec<f64>,
    pub init_array: Vec<f64>,
    pub fini_array: Vec<f64>,
    pub notes: Vec<ElfNote>,
    pub android: Option<Android>,
    pub build_id: Option<String>,
    pub features: Vec<&'static str>,
    pub attributes: Vec<(String, String)>,
    pub comment: Vec<String>,
    pub debug_info: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElfError {
    /// No \x7fELF signature.
    NotElf,
    /// The class is neither 32 nor 64 bits.
    UnknownClass,
    BigEndian,
}

pub fn is_elf(bytes: &[u8]) -> bool {
    bytes.len() >= 16 && bytes[..4] == [0x7f, 0x45, 0x4c, 0x46]
}

fn machine_name(m: f64) -> Option<&'static str> {
    Some(match m as i64 {
        2 => "SPARC",
        3 => "x86",
        8 => "MIPS",
        20 => "PowerPC",
        21 => "PowerPC 64",
        22 => "S/390",
        40 => "ARM",
        42 => "SuperH",
        50 => "IA-64",
        62 => "x86-64",
        183 => "AArch64",
        243 => "RISC-V",
        247 => "BPF",
        258 => "LoongArch",
        _ => return None,
    })
}

fn type_name(t: f64) -> Option<&'static str> {
    Some(match t as i64 {
        0 => "None",
        1 => "Relocatable object",
        2 => "Executable",
        3 => "Shared library",
        4 => "Core dump",
        _ => return None,
    })
}

fn dt_name(tag: f64) -> Option<&'static str> {
    if tag.fract() != 0.0 {
        return None;
    }
    Some(match tag as i64 {
        0 => "NULL",
        1 => "NEEDED",
        2 => "PLTRELSZ",
        3 => "PLTGOT",
        4 => "HASH",
        5 => "STRTAB",
        6 => "SYMTAB",
        7 => "RELA",
        8 => "RELASZ",
        9 => "RELAENT",
        10 => "STRSZ",
        11 => "SYMENT",
        12 => "INIT",
        13 => "FINI",
        14 => "SONAME",
        15 => "RPATH",
        16 => "SYMBOLIC",
        17 => "REL",
        18 => "RELSZ",
        19 => "RELENT",
        20 => "PLTREL",
        21 => "DEBUG",
        22 => "TEXTREL",
        23 => "JMPREL",
        24 => "BIND_NOW",
        25 => "INIT_ARRAY",
        26 => "FINI_ARRAY",
        27 => "INIT_ARRAYSZ",
        28 => "FINI_ARRAYSZ",
        29 => "RUNPATH",
        30 => "FLAGS",
        32 => "PREINIT_ARRAY",
        33 => "PREINIT_ARRAYSZ",
        35 => "RELRSZ",
        36 => "RELR",
        37 => "RELRENT",
        0x6000_000f => "ANDROID_REL",
        0x6000_0010 => "ANDROID_RELSZ",
        0x6000_0011 => "ANDROID_RELA",
        0x6000_0012 => "ANDROID_RELASZ",
        0x6fff_e000 => "ANDROID_RELR",
        0x6fff_e001 => "ANDROID_RELRSZ",
        0x6fff_e003 => "ANDROID_RELRENT",
        0x6fff_fef5 => "GNU_HASH",
        0x6fff_fff0 => "VERSYM",
        0x6fff_fff9 => "RELACOUNT",
        0x6fff_fffa => "RELCOUNT",
        0x6fff_fffb => "FLAGS_1",
        0x6fff_fffc => "VERDEF",
        0x6fff_fffd => "VERDEFNUM",
        0x6fff_fffe => "VERNEED",
        0x6fff_ffff => "VERNEEDNUM",
        0x7000_0001 => "AARCH64_BTI_PLT",
        0x7000_0003 => "AARCH64_PAC_PLT",
        0x7000_0005 => "AARCH64_VARIANT_PCS",
        0x7000_0009 => "AARCH64_MEMTAG_MODE",
        _ => return None,
    })
}

/// The relocation types the overview counts, by machine.
fn relocation_name(machine: f64, ty: f64) -> Option<&'static str> {
    if ty.fract() != 0.0 {
        return None;
    }
    let t = ty as i64;
    Some(match machine as i64 {
        40 => match t {
            0 => "NONE",
            2 => "ABS32",
            3 => "REL32",
            17 => "TLS_DTPMOD32",
            18 => "TLS_DTPOFF32",
            19 => "TLS_TPOFF32",
            20 => "COPY",
            21 => "GLOB_DAT",
            22 => "JUMP_SLOT",
            23 => "RELATIVE",
            160 => "IRELATIVE",
            _ => return None,
        },
        183 => match t {
            0 => "NONE",
            257 => "ABS64",
            258 => "ABS32",
            1024 => "COPY",
            1025 => "GLOB_DAT",
            1026 => "JUMP_SLOT",
            1027 => "RELATIVE",
            1028 => "TLS_DTPMOD",
            1029 => "TLS_DTPREL",
            1030 => "TLS_TPREL",
            1031 => "TLSDESC",
            1032 => "IRELATIVE",
            _ => return None,
        },
        62 => match t {
            1 => "ABS64",
            5 => "COPY",
            6 => "GLOB_DAT",
            7 => "JUMP_SLOT",
            8 => "RELATIVE",
            37 => "IRELATIVE",
            _ => return None,
        },
        3 => match t {
            1 => "ABS32",
            5 => "COPY",
            6 => "GLOB_DAT",
            7 => "JUMP_SLOT",
            8 => "RELATIVE",
            42 => "IRELATIVE",
            _ => return None,
        },
        _ => return None,
    })
}

/// The architecture as the file chip shows it.
pub fn arch_of(machine: f64, flags: f64) -> String {
    match machine as i64 {
        183 => "arm64".into(),
        40 => (if to_int32(flags) & 0x80_0000 != 0 { "armv7 (be8)" } else { "armv7" }).into(),
        62 => "x86_64".into(),
        3 => "x86".into(),
        _ => machine_name(machine).map_or_else(|| format!("machine {}", js_number(machine)), String::from),
    }
}

/// JavaScript's `\s` and what `trim` removes: white space and line terminators.
fn js_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'
    )
}

/// The patterns of `KNOWN_LIBRARIES` in src/core/elf.ts, in its order: does a name begin as that
/// Android NDK library's exports do?
fn known_library(name: &str, k: usize) -> bool {
    let starts = |prefixes: &[&str]| prefixes.iter().any(|p| name.starts_with(p));
    let upper_after = |prefix: &str| name.strip_prefix(prefix).and_then(|r| r.chars().next()).is_some_and(|c| c.is_ascii_uppercase());
    match k {
        0 => name.starts_with("__android_log_") || name == "__android_log",
        1 => {
            const WORDS: [&str; 23] = [
                "Asset",
                "Configuration",
                "Looper",
                "NativeActivity",
                "NativeWindow",
                "InputQueue",
                "InputEvent",
                "KeyEvent",
                "MotionEvent",
                "Sensor",
                "Choreographer",
                "Surface",
                "Thermal",
                "Hardware",
                "Font",
                "Storage",
                "Trace",
                "Performance",
                "Window",
                "SharedMemory",
                "Bitmap",
                "Chooser",
                "Activity",
            ];
            name.strip_prefix('A').is_some_and(|rest| WORDS.iter().any(|w| rest.starts_with(w))) || name.starts_with("ATrace_")
        }
        2 => starts(&["ANativeWindow_", "AHardwareBuffer_"]),
        3 => name.starts_with("AndroidBitmap_"),
        4 => upper_after("egl"),
        5 => upper_after("gl"),
        6 => upper_after("vk"),
        7 => name.starts_with("AAudio"),
        8 => starts(&["AMedia", "AImage"]),
        9 => name.starts_with("ACamera"),
        10 => upper_after("sl") || name.starts_with("SL_IID"),
        11 => starts(&["inflate", "deflate", "crc32", "adler32", "compress", "uncompress", "zlib", "gz"]),
        12 => name.starts_with("ANeuralNetworks"),
        13 => starts(&["ABinder", "AIBinder", "AParcel", "AStatus"]),
        14 => {
            // `^_Z.*St3__1`: `.` stops at a line terminator.
            let any = name.strip_prefix("_Z").is_some_and(|rest| {
                let line = rest.split(['\n', '\r', '\u{2028}', '\u{2029}']).next().unwrap_or("");
                line.contains("St3__1")
            });
            any || starts(&["_ZNSt6__ndk1", "_ZNKSt6__ndk1", "_ZTVNSt6__ndk1"])
        }
        15 => starts(&["_Unwind_", "__cxa_", "__gxx_personality"]),
        _ => false,
    }
}

/// The library of each pattern of [`known_library`].
const KNOWN_LIBRARIES: [&str; 16] = [
    "liblog.so",
    "libandroid.so",
    "libnativewindow.so",
    "libjnigraphics.so",
    "libEGL.so",
    "libGLESv3.so",
    "libvulkan.so",
    "libaaudio.so",
    "libmediandk.so",
    "libcamera2ndk.so",
    "libOpenSLES.so",
    "libz.so",
    "libneuralnetworks.so",
    "libbinder_ndk.so",
    "libc++_shared.so",
    "libc++_shared.so",
];

/// Unversioned imports name no library: the NDK library whose exports a name looks like, when the file needs it.
fn guess_library(name: &str, needed: &[String]) -> String {
    for (k, &library) in KNOWN_LIBRARIES.iter().enumerate() {
        if !known_library(name, k) {
            continue;
        }
        if needed.iter().any(|n| n == library) {
            return library.into();
        }
        if library == "libGLESv3.so" {
            return needed.iter().find(|n| n.starts_with("libGLES")).cloned().unwrap_or_default();
        }
    }
    String::new()
}

fn flag_names(machine: f64, flags: f64) -> Vec<String> {
    let mut out = Vec::new();
    if machine == EM_ARM {
        let f = to_uint32(flags);
        let eabi = f >> 24;
        if eabi != 0 {
            out.push(format!("EABI{eabi}"));
        }
        if f & 0x400 != 0 {
            out.push("hard-float".into());
        }
        if f & 0x200 != 0 {
            out.push("soft-float".into());
        }
        if f & 0x80_0000 != 0 {
            out.push("BE8".into());
        }
    }
    out
}

fn flag_list(value: f64, names: &[&str]) -> String {
    let v = to_int32(value);
    let list: Vec<&str> = names.iter().enumerate().filter(|&(i, _)| v & (1i32 << i) != 0).map(|(_, &n)| n).collect();
    if list.is_empty() {
        "0".into()
    } else {
        list.join(" ")
    }
}

/// Reads the file as the TypeScript's Reader did: whatever is out of the file reads as 0.
struct Reader<'a> {
    bytes: &'a [u8],
    is64: bool,
}

impl Reader<'_> {
    #[inline]
    fn ok(&self, at: f64, length: f64) -> bool {
        at >= 0.0 && at + length <= self.bytes.len() as f64
    }

    #[inline]
    fn at<const N: usize>(&self, at: f64) -> Option<[u8; N]> {
        if !self.ok(at, N as f64) {
            return None;
        }
        let a = at as usize;
        Some(self.bytes[a..a + N].try_into().unwrap())
    }

    fn u8(&self, at: f64) -> f64 {
        if at >= 0.0 && at.fract() == 0.0 && at < self.bytes.len() as f64 {
            self.bytes[at as usize] as f64
        } else {
            0.0
        }
    }

    fn u16(&self, at: f64) -> f64 {
        self.at::<2>(at).map_or(0.0, |b| u16::from_le_bytes(b) as f64)
    }

    fn u32(&self, at: f64) -> f64 {
        self.at::<4>(at).map_or(0.0, |b| u32::from_le_bytes(b) as f64)
    }

    fn i32(&self, at: f64) -> f64 {
        self.at::<4>(at).map_or(0.0, |b| i32::from_le_bytes(b) as f64)
    }

    fn u64(&self, at: f64) -> f64 {
        self.at::<8>(at).map_or(0.0, |b| u64::from_le_bytes(b) as f64)
    }

    fn i64(&self, at: f64) -> f64 {
        self.at::<8>(at).map_or(0.0, |b| i64::from_le_bytes(b) as f64)
    }

    fn word(&self, at: f64) -> f64 {
        if self.is64 {
            self.u64(at)
        } else {
            self.u32(at)
        }
    }

    fn sword(&self, at: f64) -> f64 {
        if self.is64 {
            self.i64(at)
        } else {
            self.i32(at)
        }
    }

    /// A NUL-terminated string of at most `max` bytes. As the TypeScript scanned: bytes before the
    /// start of the file are never NUL, and the piece is cut with subarray's rules.
    fn cstr(&self, at: f64, max: f64) -> String {
        let len = self.bytes.len() as f64;
        let limit = len.min(at + max);
        let mut end = at;
        if end < 0.0 {
            end = limit.min(0.0);
        }
        while end < limit && self.bytes[end as usize] != 0 {
            end += 1.0;
        }
        let (start, stop) = subarray(self.bytes.len(), at, end);
        utf8(&self.bytes[start..stop])
    }

    fn uleb(&self, at: f64) -> (f64, f64) {
        if at < 0.0 {
            return (0.0, at + 1.0);
        }
        let (v, p) = uleb(self.bytes, at as usize);
        (v, p as f64)
    }

    fn sleb(&self, at: f64) -> (f64, f64) {
        if at < 0.0 {
            return (0.0, at + 1.0);
        }
        let (v, p) = sleb(self.bytes, at as usize);
        (v, p as f64)
    }
}

/// `Uint8Array.subarray(begin, end)`: negative ends count from the end, both clamped.
pub fn subarray(len: usize, begin: f64, end: f64) -> (usize, usize) {
    let clamp = |v: f64| -> usize {
        let v = if v.is_nan() { 0.0 } else { v.trunc() };
        if v < 0.0 {
            (len as f64 + v).max(0.0) as usize
        } else {
            v.min(len as f64) as usize
        }
    };
    let (b, e) = (clamp(begin), clamp(end));
    (b, e.max(b))
}

/// Opens an ELF file.
pub fn parse_elf(file: &[u8]) -> Result<Elf, ElfError> {
    if !is_elf(file) {
        return Err(ElfError::NotElf);
    }
    let cls = file[4];
    if cls != 1 && cls != 2 {
        return Err(ElfError::UnknownClass);
    }
    if file[5] != 1 {
        return Err(ElfError::BigEndian);
    }
    let is64 = cls == 2;
    let r = Reader { bytes: file, is64 };
    let ty = r.u16(16.0);
    let machine = r.u16(18.0);
    let entry = r.word(24.0);
    let phoff = if is64 { r.u64(32.0) } else { r.u32(28.0) };
    let shoff = if is64 { r.u64(40.0) } else { r.u32(32.0) };
    let flags = r.u32(if is64 { 48.0 } else { 36.0 });
    let phentsize = r.u16(if is64 { 54.0 } else { 42.0 });
    let phnum = r.u16(if is64 { 56.0 } else { 44.0 });
    let shentsize = r.u16(if is64 { 58.0 } else { 46.0 });
    let mut shnum = r.u16(if is64 { 60.0 } else { 48.0 });
    let mut shstrndx = r.u16(if is64 { 62.0 } else { 50.0 });

    let mut elf = Elf {
        is64,
        machine,
        machine_name: machine_name(machine).map_or_else(|| format!("machine {}", js_number(machine)), String::from),
        arch: arch_of(machine, flags),
        ty,
        type_name: type_name(ty).map_or_else(|| format!("type {}", js_number(ty)), String::from),
        osabi: file.get(7).copied().unwrap_or(0) as f64,
        flags,
        flag_names: flag_names(machine, flags),
        entry,
        segments: Vec::new(),
        sections: Vec::new(),
        sectionless: false,
        dynamic: Vec::new(),
        needed: Vec::new(),
        soname: None,
        runpath: Vec::new(),
        interpreter: None,
        dynsyms: Vec::new(),
        symtab: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        marks: Vec::new(),
        relocations: Vec::new(),
        relocation_counts: Vec::new(),
        relocation_formats: Vec::new(),
        slots: NumberMap::default(),
        relative: NumberMap::default(),
        function_starts: Vec::new(),
        init_array: Vec::new(),
        fini_array: Vec::new(),
        notes: Vec::new(),
        android: None,
        build_id: None,
        features: Vec::new(),
        attributes: Vec::new(),
        comment: Vec::new(),
        debug_info: false,
    };

    // Segments.
    let mut i = 0.0;
    while i < phnum && phoff != 0.0 {
        let at = phoff + i * phentsize;
        if !r.ok(at, if is64 { 56.0 } else { 32.0 }) {
            break;
        }
        elf.segments.push(if is64 {
            ElfSegment {
                ty: r.u32(at),
                flags: r.u32(at + 4.0),
                offset: r.u64(at + 8.0),
                vaddr: r.u64(at + 16.0),
                filesz: r.u64(at + 32.0),
                memsz: r.u64(at + 40.0),
                align: r.u64(at + 48.0),
            }
        } else {
            ElfSegment {
                ty: r.u32(at),
                offset: r.u32(at + 4.0),
                vaddr: r.u32(at + 8.0),
                filesz: r.u32(at + 16.0),
                memsz: r.u32(at + 20.0),
                flags: r.u32(at + 24.0),
                align: r.u32(at + 28.0),
            }
        });
        i += 1.0;
    }

    // Sections. A count too large for the header lives in section 0's size field.
    if shoff != 0.0 && shnum == 0.0 && r.ok(shoff, shentsize) {
        shnum = if is64 { r.u64(shoff + 32.0) } else { r.u32(shoff + 20.0) };
    }
    if shstrndx == 65535.0 && shoff != 0.0 {
        shstrndx = r.u32(shoff + if is64 { 44.0 } else { 28.0 });
    }
    let mut name_offsets: Vec<f64> = Vec::new();
    let mut i = 0.0;
    while i < shnum && shoff != 0.0 {
        let at = shoff + i * shentsize;
        if !r.ok(at, if is64 { 64.0 } else { 40.0 }) {
            break;
        }
        name_offsets.push(r.u32(at));
        elf.sections.push(if is64 {
            ElfSection {
                index: i,
                name: String::new(),
                ty: r.u32(at + 4.0),
                flags: r.u64(at + 8.0),
                addr: r.u64(at + 16.0),
                offset: r.u64(at + 24.0),
                size: r.u64(at + 32.0),
                link: r.u32(at + 40.0),
                info: r.u32(at + 44.0),
                align: r.u64(at + 48.0),
                entsize: r.u64(at + 56.0),
            }
        } else {
            ElfSection {
                index: i,
                name: String::new(),
                ty: r.u32(at + 4.0),
                flags: r.u32(at + 8.0),
                addr: r.u32(at + 12.0),
                offset: r.u32(at + 16.0),
                size: r.u32(at + 20.0),
                link: r.u32(at + 24.0),
                info: r.u32(at + 28.0),
                align: r.u32(at + 32.0),
                entsize: r.u32(at + 36.0),
            }
        });
        i += 1.0;
    }
    if let Some(names_offset) = section_at(&elf.sections, shstrndx).map(|s| s.offset) {
        for (k, s) in elf.sections.iter_mut().enumerate() {
            s.name = r.cstr(names_offset + name_offsets[k], 256.0);
        }
    }
    if !elf.sections.iter().any(|s| s.ty != 0.0) {
        elf.sectionless = true;
        elf.sections = sections_from_segments(&elf.segments);
    }

    let segments = elf.segments.clone();
    // The file offset of a virtual address, through the loaded segments.
    let offset_of = move |addr: f64| -> f64 {
        for seg in &segments {
            if seg.ty == pt::LOAD && addr >= seg.vaddr && addr < seg.vaddr + seg.filesz {
                return seg.offset + (addr - seg.vaddr);
            }
        }
        -1.0
    };

    // The dynamic section.
    let dyn_seg = elf.segments.iter().find(|s| s.ty == pt::DYNAMIC);
    let dyn_section = elf.sections.iter().find(|s| s.ty == sht::DYNAMIC);
    let dyn_at = dyn_section.map(|s| s.offset).or(dyn_seg.map(|s| s.offset));
    let dyn_size = dyn_section.map(|s| s.size).or(dyn_seg.map(|s| s.filesz)).unwrap_or(0.0);
    let mut dynm: FxHashMap<u64, f64> = FxHashMap::default();
    let mut dyn_list: Vec<(f64, f64)> = Vec::new();
    if let Some(dyn_at) = dyn_at {
        let step = if is64 { 16.0 } else { 8.0 };
        let mut at = dyn_at;
        while at + step <= dyn_at + dyn_size {
            let tag = if is64 { r.i64(at) } else { r.i32(at) };
            let value = r.word(at + if is64 { 8.0 } else { 4.0 });
            if tag == 0.0 {
                break;
            }
            dyn_list.push((tag, value));
            dynm.entry(number_key(tag)).or_insert(value);
            at += step;
        }
    }
    let dyn_get = |tag: f64| dynm.get(&number_key(tag)).copied();
    let dynstr_at = match dyn_get(5.0) {
        Some(v) => offset_of(v),
        None => elf.sections.iter().find(|s| s.name == ".dynstr").map_or(-1.0, |s| s.offset),
    };
    let dynstr = |offset: f64| if dynstr_at >= 0.0 { r.cstr(dynstr_at + offset, 1024.0) } else { String::new() };
    for &(tag, value) in &dyn_list {
        let name = dt_name(tag).map_or_else(|| format!("0x{:x}", to_uint32(tag)), String::from);
        let t = tag as i64;
        let text = if tag.fract() == 0.0 && matches!(t, 1 | 14 | 15 | 29) {
            dynstr(value)
        } else if tag.fract() == 0.0
            && matches!(
                t,
                2 | 8
                    | 9
                    | 10
                    | 11
                    | 18
                    | 19
                    | 27
                    | 28
                    | 33
                    | 35
                    | 37
                    | 0x6000_0010
                    | 0x6000_0012
                    | 0x6fff_e001
                    | 0x6fff_e003
                    | 0x6fff_fff9
                    | 0x6fff_fffa
                    | 0x6fff_fffd
                    | 0x6fff_ffff
            )
        {
            js_number(value)
        } else if tag == 20.0 {
            (if value == 7.0 { "RELA" } else { "REL" }).into()
        } else if tag == 30.0 {
            flag_list(value, &["ORIGIN", "SYMBOLIC", "TEXTREL", "BIND_NOW", "STATIC_TLS"])
        } else if tag == 1879048187.0 {
            flag_list(
                value,
                &[
                    "NOW",
                    "GLOBAL",
                    "GROUP",
                    "NODELETE",
                    "LOADFLTR",
                    "INITFIRST",
                    "NOOPEN",
                    "ORIGIN",
                    "DIRECT",
                    "TRANS",
                    "INTERPOSE",
                    "NODEFLIB",
                    "NODUMP",
                    "CONFALT",
                    "ENDFILTEE",
                    "DISPRELDNE",
                    "DISPRELPND",
                    "NODIRECT",
                    "IGNMULDEF",
                    "NOKSYMS",
                    "NOHDR",
                    "EDITED",
                    "NORELOC",
                    "SYMINTPOSE",
                    "GLOBAUDIT",
                    "SINGLETON",
                    "STUB",
                    "PIE",
                ],
            )
        } else {
            format!("0x{}", js_hex(value))
        };
        if tag == 1.0 {
            elf.needed.push(text.clone());
        }
        if tag == 14.0 {
            elf.soname = Some(text.clone());
        }
        if tag == 15.0 || tag == 29.0 {
            elf.runpath.extend(text.split(':').filter(|s| !s.is_empty()).map(String::from));
        }
        elf.dynamic.push(DynamicEntry { tag, name, value, text });
    }
    if let Some(interp) = elf.segments.iter().find(|s| s.ty == pt::INTERP) {
        elf.interpreter = Some(r.cstr(interp.offset, interp.filesz));
    }

    // Symbol versions: index → (version, library).
    let mut versions: FxHashMap<u64, (String, Option<String>)> = FxHashMap::default();
    let verneed_at = dyn_get(1879048190.0).map_or(-1.0, &offset_of);
    let verneed_num = dyn_get(1879048191.0).unwrap_or(0.0);
    let mut at = verneed_at;
    let mut n = 0.0;
    while at >= 0.0 && n < verneed_num && r.ok(at, 16.0) {
        let count = r.u16(at + 2.0);
        let library = dynstr(r.u32(at + 4.0));
        let mut aux = at + r.u32(at + 8.0);
        let mut k = 0.0;
        while k < count && r.ok(aux, 16.0) {
            versions.insert((to_int32(r.u16(aux + 6.0)) & 0x7fff) as u64, (dynstr(r.u32(aux + 8.0)), Some(library.clone())));
            let next = r.u32(aux + 12.0);
            if next == 0.0 {
                break;
            }
            aux += next;
            k += 1.0;
        }
        let next = r.u32(at + 12.0);
        if next == 0.0 {
            break;
        }
        at += next;
        n += 1.0;
    }
    let verdef_at = dyn_get(1879048188.0).map_or(-1.0, &offset_of);
    let verdef_num = dyn_get(1879048189.0).unwrap_or(0.0);
    let mut at = verdef_at;
    let mut n = 0.0;
    while at >= 0.0 && n < verdef_num && r.ok(at, 20.0) {
        let index = r.u16(at + 4.0);
        let base = to_int32(r.u16(at + 2.0)) & 1;
        if base == 0 {
            versions.insert(index as u64, (dynstr(r.u32(at + r.u32(at + 12.0))), None));
        }
        let next = r.u32(at + 16.0);
        if next == 0.0 {
            break;
        }
        at += next;
        n += 1.0;
    }

    // Symbols: .dynsym (through the section, or DT_SYMTAB with a count from the hash tables) and .symtab.
    let symsize = if is64 { 24.0 } else { 16.0 };
    let read_symbols = |at: f64, count: f64, str_at: f64, versym: f64| -> Vec<ElfSymbol> {
        let mut out = Vec::new();
        let mut i = 0.0;
        while i < count && r.ok(at + i * symsize, symsize) {
            let p = at + i * symsize;
            let name_at = r.u32(p);
            let value = if is64 { r.u64(p + 8.0) } else { r.u32(p + 4.0) };
            let size = if is64 { r.u64(p + 16.0) } else { r.u32(p + 8.0) };
            let info = r.u8(if is64 { p + 4.0 } else { p + 12.0 }) as i32;
            let other = r.u8(if is64 { p + 5.0 } else { p + 13.0 }) as i32;
            let shndx = r.u16(if is64 { p + 6.0 } else { p + 14.0 });
            let sym_type = (info & 0xf) as f64;
            let thumb = machine == EM_ARM && (sym_type == stt::FUNC || sym_type == stt::GNU_IFUNC) && to_int32(value) & 1 == 1;
            let mut sym = ElfSymbol {
                name: if str_at >= 0.0 && name_at != 0.0 { r.cstr(str_at + name_at, 4096.0) } else { String::new() },
                addr: if thumb { value - 1.0 } else { value },
                size,
                ty: sym_type,
                bind: (info >> 4) as f64,
                visibility: (other & 3) as f64,
                shndx,
                thumb,
                version: None,
                library: None,
            };
            if versym >= 0.0 {
                if let Some((name, library)) = versions.get(&((to_int32(r.u16(versym + i * 2.0)) & 0x7fff) as u64)) {
                    sym.version = Some(name.clone());
                    sym.library = library.clone();
                }
            }
            out.push(sym);
            i += 1.0;
        }
        out
    };
    let versym_at = dyn_get(1879048176.0).map_or(-1.0, &offset_of);
    if let Some(dynsym) = elf.sections.iter().find(|s| s.ty == sht::DYNSYM) {
        let str_at = section_at(&elf.sections, dynsym.link).map_or(dynstr_at, |s| s.offset);
        elf.dynsyms = read_symbols(dynsym.offset, (dynsym.size / symsize).floor(), str_at, versym_at);
    } else if let Some(symtab_addr) = dyn_get(6.0) {
        let count = symbol_count(&r, &dyn_get, &offset_of);
        elf.dynsyms = read_symbols(offset_of(symtab_addr), count, dynstr_at, versym_at);
    }
    if let Some(symtab) = elf.sections.iter().find(|s| s.ty == sht::SYMTAB) {
        let str_at = section_at(&elf.sections, symtab.link).map_or(-1.0, |s| s.offset);
        elf.symtab = read_symbols(symtab.offset, (symtab.size / symsize).floor(), str_at, -1.0);
        for sym in &elf.symtab {
            let b = sym.name.as_bytes();
            let mark = b.len() >= 2 && b[0] == b'$' && matches!(b[1], b'a' | b't' | b'x' | b'd') && (b.len() == 2 || b[2] == b'.');
            if mark && sym.ty == stt::NOTYPE {
                elf.marks.push((sym.addr, b[1] as char));
            }
        }
        elf.marks.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(core::cmp::Ordering::Equal));
    }

    // Imports and exports.
    for sym in &elf.dynsyms {
        if sym.name.is_empty() || sym.ty == stt::SECTION || sym.ty == stt::FILE {
            continue;
        }
        if sym.shndx == 0.0 {
            let library = sym.library.clone().unwrap_or_else(|| guess_library(&sym.name, &elf.needed));
            elf.imports.push(ElfImport { name: sym.name.clone(), library, version: sym.version.clone(), weak: sym.bind == 2.0, ty: sym.ty });
        } else if (sym.bind == 1.0 || sym.bind == 2.0 || sym.bind == 10.0) && (sym.visibility == 0.0 || sym.visibility == 3.0) {
            // An empty version is left out, as the TypeScript's spread of a falsy one was.
            elf.exports.push(ElfExport {
                name: sym.name.clone(),
                addr: sym.addr,
                size: sym.size,
                ty: sym.ty,
                thumb: sym.thumb,
                version: sym.version.clone().filter(|v| !v.is_empty()),
            });
        }
    }

    read_relocations(&mut elf, &r, &dyn_get, dynm.len(), &offset_of);
    read_notes(&mut elf, &r);
    read_unwind_tables(&mut elf, &r);
    read_init_arrays(&mut elf, &r, &dyn_get, &offset_of);
    if let Some(attributes) = elf.sections.iter().find(|s| s.ty == sht::ARM_ATTRIBUTES) {
        elf.attributes = arm_attributes(&r, attributes.offset, attributes.size);
    }
    if let Some(comment) = elf.sections.iter().find(|s| s.name == ".comment") {
        let (a, b) = subarray(file.len(), comment.offset, comment.offset + comment.size);
        let text = utf8(&file[a..b]);
        let mut seen = Vec::new();
        for part in text.split('\0') {
            let part = part.trim_matches(js_space);
            if !part.is_empty() && !seen.iter().any(|s: &String| s == part) {
                seen.push(part.to_string());
            }
        }
        elf.comment = seen;
    }
    elf.debug_info = elf.sections.iter().any(|s| s.name == ".debug_info" || s.name == ".zdebug_info");
    Ok(elf)
}

/// `sections[index]` for an index read from the file.
fn section_at(sections: &[ElfSection], index: f64) -> Option<&ElfSection> {
    if index >= 0.0 && index.fract() == 0.0 {
        sections.get(index as usize)
    } else {
        None
    }
}

/// Without section headers: one made-up section per loaded segment, code where the segment is executable.
fn sections_from_segments(segments: &[ElfSegment]) -> Vec<ElfSection> {
    let mut out: Vec<ElfSection> = Vec::new();
    for (i, seg) in segments.iter().enumerate() {
        if seg.ty != pt::LOAD {
            continue;
        }
        let f = to_int32(seg.flags);
        let exec = f & 1 != 0;
        let write = f & 2 != 0;
        let name = if exec {
            ".text"
        } else if write {
            ".data"
        } else {
            ".rodata"
        };
        let flags = shf::ALLOC | if exec { shf::EXEC } else { 0 } | if write { shf::WRITE } else { 0 };
        out.push(ElfSection {
            index: (out.len() + 1) as f64,
            name: format!("{name} (LOAD {i})"),
            ty: sht::PROGBITS,
            flags: flags as f64,
            addr: seg.vaddr,
            offset: seg.offset,
            size: seg.filesz,
            link: 0.0,
            info: 0.0,
            align: seg.align,
            entsize: 0.0,
        });
        if seg.memsz > seg.filesz {
            out.push(ElfSection {
                index: (out.len() + 1) as f64,
                name: format!(".bss (LOAD {i})"),
                ty: sht::NOBITS,
                flags: (shf::ALLOC | shf::WRITE) as f64,
                addr: seg.vaddr + seg.filesz,
                offset: 0.0,
                size: seg.memsz - seg.filesz,
                link: 0.0,
                info: 0.0,
                align: 1.0,
                entsize: 0.0,
            });
        }
    }
    out
}

/// How many dynamic symbols there are, when no section header says: from DT_HASH, or by walking DT_GNU_HASH.
fn symbol_count(r: &Reader, dyn_get: &dyn Fn(f64) -> Option<f64>, offset_of: &dyn Fn(f64) -> f64) -> f64 {
    if let Some(hash) = dyn_get(4.0) {
        let at = offset_of(hash);
        if at >= 0.0 {
            return r.u32(at + 4.0);
        }
    }
    let Some(gnu) = dyn_get(1879047925.0) else { return 0.0 };
    let at = offset_of(gnu);
    if at < 0.0 {
        return 0.0;
    }
    let nbuckets = r.u32(at);
    let symoffset = r.u32(at + 4.0);
    let bloom_size = r.u32(at + 8.0);
    let buckets = at + 16.0 + bloom_size * if r.is64 { 8.0 } else { 4.0 };
    let chains = buckets + nbuckets * 4.0;
    let mut last = 0.0f64;
    let mut i = 0.0;
    while i < nbuckets {
        last = last.max(r.u32(buckets + i * 4.0));
        i += 1.0;
    }
    if last < symoffset {
        return symoffset;
    }
    while r.ok(chains + (last - symoffset) * 4.0, 4.0) && to_int32(r.u32(chains + (last - symoffset) * 4.0)) & 1 == 0 {
        last += 1.0;
    }
    last + 1.0
}

/* ------------------------------------------------------------------ *
 * Relocations
 * ------------------------------------------------------------------ */

fn read_relocations(elf: &mut Elf, r: &Reader, dyn_get: &dyn Fn(f64) -> Option<f64>, dyn_size: usize, offset_of: &dyn Fn(f64) -> f64) {
    let word = if elf.is64 { 8.0 } else { 4.0 };
    let mut counts: Vec<(String, f64)> = Vec::new();
    let mut count = |name: &str, n: f64| match counts.iter_mut().find(|(k, _)| k == name) {
        Some((_, v)) => *v += n,
        None => counts.push((name.into(), n)),
    };
    let mut formats: Vec<&'static str> = Vec::new();
    let add_format = |f: &'static str, formats: &mut Vec<&'static str>| {
        if !formats.contains(&f) {
            formats.push(f);
        }
    };
    let is64 = elf.is64;
    let machine = elf.machine;
    let take = |elf: &mut Elf, offset: f64, info: f64, addend: Option<f64>, count: &mut dyn FnMut(&str, f64)| {
        let ty = if is64 { info % 4294967296.0 } else { (to_int32(info) & 0xff) as f64 };
        let sym = if is64 { (info / 4294967296.0).floor() } else { (to_uint32(info) >> 8) as f64 };
        let name = relocation_name(machine, ty).map_or_else(|| format!("type {}", js_number(ty)), String::from);
        count(&name, 1.0);
        if name == "RELATIVE" || name == "IRELATIVE" {
            // REL keeps the address in the slot itself; RELA keeps it here.
            let value = addend.unwrap_or_else(|| r.word(offset_of(offset)));
            elf.relative.set(offset, value);
            return;
        }
        elf.relocations.push(Relocation { offset, ty, sym, addend: addend.unwrap_or(0.0) });
        let symbol = if sym >= 0.0 && sym.fract() == 0.0 { elf.dynsyms.get(sym as usize) } else { None };
        if let Some(symbol) = symbol {
            if !symbol.name.is_empty() && matches!(name.as_str(), "ABS32" | "ABS64" | "GLOB_DAT" | "JUMP_SLOT") {
                let name = symbol.name.clone();
                elf.slots.set(offset, name);
            }
        }
    };

    // Plain tables, through the dynamic section (or the sections of a file without one).
    let mut tables: Vec<(f64, f64, bool)> = Vec::new();
    if let Some(a) = dyn_get(17.0) {
        tables.push((a, dyn_get(18.0).unwrap_or(0.0), false));
    }
    if let Some(a) = dyn_get(7.0) {
        tables.push((a, dyn_get(8.0).unwrap_or(0.0), true));
    }
    if let Some(a) = dyn_get(23.0) {
        tables.push((a, dyn_get(2.0).unwrap_or(0.0), dyn_get(20.0) == Some(7.0)));
    }
    if dyn_size == 0 {
        for s in &elf.sections {
            if (s.ty == sht::REL || s.ty == sht::RELA) && to_int32(s.flags) & shf::ALLOC != 0 {
                tables.push((s.addr, s.size, s.ty == sht::RELA));
            }
        }
    }
    for (addr, size, rela) in tables {
        let at = offset_of(addr);
        if at < 0.0 {
            continue;
        }
        add_format(if rela { "RELA" } else { "REL" }, &mut formats);
        let step = if rela { word * 3.0 } else { word * 2.0 };
        let mut p = at;
        while p + step <= at + size && r.ok(p, step) {
            let addend = if rela { Some(r.sword(p + word * 2.0)) } else { None };
            take(elf, r.word(p), r.word(p + word), addend, &mut count);
            p += step;
        }
    }

    // Android's packed relocations (APS2): groups of relocations sharing an info word, an offset
    // step or an addend, all in SLEB128.
    for (tag_at, tag_size, rela) in [(1610612751.0, 1610612752.0, false), (1610612753.0, 1610612754.0, true)] {
        let Some(addr) = dyn_get(tag_at) else { continue };
        let start = offset_of(addr);
        if start < 0.0 || r.u32(start) != 844255297.0 {
            continue; // "APS2"
        }
        add_format(if rela { "Android packed RELA" } else { "Android packed REL" }, &mut formats);
        let end = start + dyn_get(tag_size).unwrap_or(0.0);
        let mut p = start + 4.0;
        let next = |p: &mut f64| {
            let (v, q) = r.sleb(*p);
            *p = q;
            v
        };
        let mut remaining = next(&mut p);
        let mut offset = next(&mut p);
        let mut info = 0.0;
        let mut addend = 0.0;
        while remaining > 0.0 && p < end {
            let group_size = next(&mut p);
            let group_flags = to_int32(next(&mut p));
            let by_info = group_flags & 1 != 0;
            let by_offset = group_flags & 2 != 0;
            let by_addend = group_flags & 4 != 0;
            let has_addend = group_flags & 8 != 0;
            let delta = if by_offset { next(&mut p) } else { 0.0 };
            if by_info {
                info = next(&mut p);
            }
            if has_addend && by_addend {
                addend += next(&mut p);
            }
            if !has_addend {
                addend = 0.0;
            }
            let mut i = 0.0;
            while i < group_size && remaining > 0.0 {
                offset += if by_offset { delta } else { next(&mut p) };
                if !by_info {
                    info = next(&mut p);
                }
                if has_addend && !by_addend {
                    addend += next(&mut p);
                }
                take(elf, offset, info, if rela { Some(addend) } else { None }, &mut count);
                i += 1.0;
                remaining -= 1.0;
            }
            if group_size <= 0.0 {
                break;
            }
        }
    }

    // RELR: relative relocations as a bitmap of words after each address.
    if let Some(relr) = dyn_get(36.0).or_else(|| dyn_get(1879040000.0)) {
        let at = offset_of(relr);
        let size = dyn_get(35.0).or_else(|| dyn_get(1879040001.0)).unwrap_or(0.0);
        if at >= 0.0 {
            add_format("RELR", &mut formats);
            let mut base = 0.0;
            let mut n = 0.0;
            // RELR slots hold their addresses in place, as REL ones do.
            let mut relocate = |elf: &mut Elf, slot: f64| {
                n += 1.0;
                elf.relative.set(slot, r.word(offset_of(slot)));
            };
            let mut p = at;
            while p + word <= at + size {
                let entry = r.word(p);
                if entry % 2.0 == 0.0 {
                    relocate(elf, entry);
                    base = entry + word;
                } else {
                    let mut bitmap: u64 = if is64 { r.at::<8>(p).map_or(0, u64::from_le_bytes) } else { to_uint32(entry) as u64 } >> 1;
                    let mut i = 0.0;
                    while bitmap != 0 {
                        if bitmap & 1 != 0 {
                            relocate(elf, base + i * word);
                        }
                        i += 1.0;
                        bitmap >>= 1;
                    }
                    base += word * (word * 8.0 - 1.0);
                }
                p += word;
            }
            count("RELATIVE (RELR)", n);
        }
    }
    elf.relocation_counts = counts;
    elf.relocation_formats = formats;
}

/* ------------------------------------------------------------------ *
 * Notes, unwind tables, init arrays, Arm attributes
 * ------------------------------------------------------------------ */

/// `(n + 3) & ~3` as JavaScript computes it, on 32-bit integers.
fn align_js(n: f64, mask: i32) -> f64 {
    (to_int32(n + mask as f64) & !mask) as f64
}

fn read_notes(elf: &mut Elf, r: &Reader) {
    let mut regions: Vec<(f64, f64)> = elf.sections.iter().filter(|s| s.ty == sht::NOTE).map(|s| (s.offset, s.size)).collect();
    if regions.is_empty() {
        regions = elf.segments.iter().filter(|s| s.ty == pt::NOTE).map(|s| (s.offset, s.filesz)).collect();
    }
    let len = r.bytes.len();
    for (start, size) in regions {
        let mut at = start;
        while at + 12.0 <= start + size {
            let namesz = r.u32(at);
            let descsz = r.u32(at + 4.0);
            let ty = r.u32(at + 8.0);
            let owner = r.cstr(at + 12.0, namesz);
            let desc_at = at + 12.0 + align_js(namesz, 3);
            let desc = subarray(len, desc_at, desc_at + descsz);
            elf.notes.push(ElfNote { owner: owner.clone(), ty, desc });
            let next = desc_at + align_js(descsz, 3);
            if owner == "Android" && ty == 1.0 && descsz >= 4.0 {
                let mut android = Android { api: r.u32(desc_at), ndk: None, build: None };
                if descsz >= 68.0 {
                    android.ndk = Some(r.cstr(desc_at + 4.0, 64.0));
                }
                if descsz >= 132.0 {
                    android.build = Some(r.cstr(desc_at + 68.0, 64.0));
                }
                elf.android = Some(android);
            } else if owner == "GNU" && ty == 3.0 {
                elf.build_id = Some(r.bytes[desc.0..desc.1].iter().map(|b| format!("{b:02x}")).collect());
            } else if owner == "GNU" && ty == 5.0 {
                // Program properties: on AArch64, GNU_PROPERTY_AARCH64_FEATURE_1_AND says BTI and PAC.
                let mut p = desc_at;
                while p + 8.0 <= desc_at + descsz {
                    let kind = r.u32(p);
                    let length = r.u32(p + 4.0);
                    if kind == 3221225472.0 && length >= 4.0 {
                        let bits = to_int32(r.u32(p + 8.0));
                        if bits & 1 != 0 {
                            elf.features.push("BTI");
                        }
                        if bits & 2 != 0 {
                            elf.features.push("PAC");
                        }
                        if bits & 4 != 0 {
                            elf.features.push("GCS");
                        }
                    }
                    let step = 8.0 + align_js(length, if elf.is64 { 7 } else { 3 });
                    // A step that does not move on would loop for ever (the TypeScript's would hang).
                    if step <= 0.0 {
                        break;
                    }
                    p += step;
                }
            }
            if next <= at {
                break;
            }
            at = next;
        }
    }
}

/// An insertion-ordered set of numbers.
#[derive(Default)]
struct NumberSet {
    list: Vec<f64>,
    seen: crate::refs::FxHashSet<u64>,
}

impl NumberSet {
    fn add(&mut self, v: f64) {
        // SameValueZero: -0 is 0, and every NaN is one.
        let v = v + 0.0;
        let key = if v.is_nan() { number_key(f64::NAN) } else { number_key(v) };
        if self.seen.insert(key) {
            self.list.push(v);
        }
    }
}

/// Function starts from the unwind tables: ARM's EHABI index, and the .eh_frame_hdr of other machines.
fn read_unwind_tables(elf: &mut Elf, r: &Reader) {
    let mut starts = NumberSet::default();
    let exidx = elf
        .sections
        .iter()
        .find(|s| s.ty == sht::ARM_EXIDX)
        .map(|s| (s.addr, s.offset, s.size))
        .or_else(|| elf.segments.iter().find(|s| s.ty == pt::ARM_EXIDX).map(|s| (s.vaddr, s.offset, s.filesz)));
    if let Some((addr, offset, size)) = exidx {
        let mut i = 0.0;
        while i + 8.0 <= size {
            let word = to_int32(r.u32(offset + i));
            let prel31 = (word << 1) >> 1;
            starts.add((to_uint32(addr + i + prel31 as f64) as i32 & !1) as f64);
            i += 8.0;
        }
    }
    let hdr = elf
        .sections
        .iter()
        .find(|s| s.name == ".eh_frame_hdr")
        .map(|s| (s.addr, s.offset, s.size))
        .or_else(|| elf.segments.iter().find(|s| s.ty == pt::GNU_EH_FRAME).map(|s| (s.vaddr, s.offset, s.filesz)));
    if let Some((addr, base, size)) = hdr {
        if r.u8(base) == 1.0 {
            let frame_ptr_enc = r.u8(base + 1.0) as i32;
            let count_enc = r.u8(base + 2.0) as i32;
            let table_enc = r.u8(base + 3.0) as i32;
            let mut p = base + 4.0;
            let is64 = elf.is64;
            let read = |enc: i32, p: &mut f64| -> f64 {
                let at = *p;
                let mut value = match enc & 0x0f {
                    0x00 => {
                        *p += if is64 { 8.0 } else { 4.0 };
                        r.word(at)
                    }
                    0x01 => {
                        let (v, q) = r.uleb(at);
                        *p = q;
                        v
                    }
                    0x02 => {
                        *p += 2.0;
                        r.u16(at)
                    }
                    0x03 => {
                        *p += 4.0;
                        r.u32(at)
                    }
                    0x04 => {
                        *p += 8.0;
                        r.u64(at)
                    }
                    0x09 => {
                        let (v, q) = r.sleb(at);
                        *p = q;
                        v
                    }
                    0x0a => {
                        *p += 2.0;
                        ((to_int32(r.u16(at)) << 16) >> 16) as f64
                    }
                    0x0b => {
                        *p += 4.0;
                        r.i32(at)
                    }
                    0x0c => {
                        *p += 8.0;
                        r.i64(at)
                    }
                    _ => return f64::NAN,
                };
                if enc & 0x70 == 0x10 {
                    value += addr + (at - base);
                } else if enc & 0x70 == 0x30 {
                    value += addr;
                }
                value
            };
            if frame_ptr_enc != 0xff {
                read(frame_ptr_enc, &mut p);
            }
            let count = if count_enc == 0xff { 0.0 } else { read(count_enc, &mut p) };
            if count.is_finite() && table_enc != 0xff {
                let mut i = 0.0;
                while i < count && p < base + size {
                    let start = read(table_enc, &mut p);
                    read(table_enc, &mut p);
                    if start.is_finite() {
                        starts.add(start);
                    }
                    i += 1.0;
                }
            }
        }
    }
    elf.function_starts.extend(starts.list);
}

fn read_init_arrays(elf: &mut Elf, r: &Reader, dyn_get: &dyn Fn(f64) -> Option<f64>, offset_of: &dyn Fn(f64) -> f64) {
    let word = if elf.is64 { 8.0 } else { 4.0 };
    let read = |elf: &Elf, addr_tag: f64, size_tag: f64| -> Vec<f64> {
        let Some(addr) = dyn_get(addr_tag) else { return Vec::new() };
        let size = dyn_get(size_tag).unwrap_or(0.0);
        let mut out = Vec::new();
        let mut i = 0.0;
        while i < size {
            let slot = addr + i;
            let value = elf.relative.get(slot).copied().unwrap_or_else(|| r.word(offset_of(slot)));
            if value != 0.0 && value != -1.0 && value != 4294967295.0 {
                out.push(value);
            }
            i += word;
        }
        out
    };
    // The pointers stay as stored: on ARM, bit 0 says the function is Thumb code.
    elf.init_array = read(elf, 25.0, 27.0);
    elf.fini_array = read(elf, 26.0, 28.0);
    let arm = elf.machine == EM_ARM;
    let values: Vec<f64> = elf.init_array.iter().chain(&elf.fini_array).copied().collect();
    for value in values {
        elf.function_starts.push(if arm { (to_int32(value) & !1) as f64 } else { value });
    }
}

const CPU_ARCH: [&str; 20] = [
    "Pre-v4",
    "v4",
    "v4T",
    "v5T",
    "v5TE",
    "v5TEJ",
    "v6",
    "v6KZ",
    "v6T2",
    "v6K",
    "v7",
    "v6-M",
    "v6S-M",
    "v7E-M",
    "v8-A",
    "v8-R",
    "v8-M.baseline",
    "v8-M.mainline",
    "v8.1-M.mainline",
    "v9-A",
];
const FP_ARCH: [&str; 9] = ["none", "VFPv1", "VFPv2", "VFPv3", "VFPv3-D16", "VFPv4", "VFPv4-D16", "ARMv8 FP", "ARMv8 FP-D16"];
const SIMD_ARCH: [&str; 5] = ["none", "NEON", "NEON with FMA", "ARMv8 NEON", "ARMv8.1 NEON"];

/// `list[value] ?? `${value}``.
fn named(list: &[&str], value: f64) -> String {
    if value >= 0.0 && value.fract() == 0.0 && (value as usize) < list.len() {
        list[value as usize].into()
    } else {
        js_number(value)
    }
}

/// The public "aeabi" attributes of .ARM.attributes: architecture, FPU and SIMD unit, float arguments.
fn arm_attributes(r: &Reader, start: f64, size: f64) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    if r.u8(start) != 0x41 as f64 {
        return out; // 'A'
    }
    let mut at = start + 1.0;
    while at + 4.0 < start + size {
        let length = r.u32(at);
        let vendor = r.cstr(at + 4.0, 32.0);
        let end = at + length;
        if vendor == "aeabi" {
            let mut p = at + 4.0 + 5.0 + 1.0;
            while p < end {
                let tag = r.u8(p);
                let sub_length = r.u32(p + 1.0);
                let sub_end = p + sub_length;
                if tag == 1.0 {
                    // Tag_File: tag/value pairs; the string-valued tags are 4, 5, 32, 65 and 67.
                    let mut q = p + 5.0;
                    while q < sub_end {
                        let (attr, next) = r.uleb(q);
                        q = next;
                        if attr == 4.0 || attr == 5.0 || attr == 67.0 || attr == 65.0 || attr == 32.0 {
                            let value = r.cstr(q, 256.0);
                            // The TypeScript stepped by the text's length in UTF-16 units.
                            q += value.encode_utf16().count() as f64 + 1.0;
                            if attr == 5.0 {
                                out.push(("CPU".into(), value));
                            }
                            continue;
                        }
                        let (value, next) = r.uleb(q);
                        q = next;
                        let a = attr as i64;
                        if attr.fract() != 0.0 {
                            continue;
                        }
                        match a {
                            6 => out.push(("Architecture".into(), named(&CPU_ARCH, value))),
                            7 if value != 0.0 => out.push(("Profile".into(), String::from_utf16_lossy(&[to_uint32(value) as u16]))),
                            8 => out.push(("A32".into(), (if value != 0.0 { "yes" } else { "no" }).into())),
                            9 => out.push(("Thumb".into(), named(&["no", "Thumb-1", "Thumb-2"], value))),
                            10 => out.push(("FPU".into(), named(&FP_ARCH, value))),
                            12 => out.push(("SIMD".into(), named(&SIMD_ARCH, value))),
                            28 => out.push(("Float arguments".into(), (if value == 1.0 { "in VFP registers (hard-float)" } else { "in core registers (soft-float)" }).into())),
                            44 => out.push(("Integer division".into(), named(&["if v7-R/v7-M", "not used", "allowed"], value))),
                            _ => {}
                        }
                    }
                }
                if sub_length <= 0.0 {
                    break;
                }
                p = sub_end;
            }
        }
        if length <= 0.0 {
            break;
        }
        at = end;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::guess_library;

    #[test]
    fn ndk_libraries() {
        let needed: Vec<String> =
            ["liblog.so", "libandroid.so", "libneuralnetworks.so", "libbinder_ndk.so", "libc++_shared.so", "libz.so", "libGLESv2.so"].map(String::from).to_vec();
        let cases = [
            ("__android_log_print", "liblog.so"),
            ("AAssetManager_open", "libandroid.so"),
            ("ANeuralNetworksModel_create", "libneuralnetworks.so"),
            ("AIBinder_new", "libbinder_ndk.so"),
            ("_ZNSt6__ndk112basic_stringIcEE", "libc++_shared.so"),
            ("__cxa_atexit", "libc++_shared.so"),
            ("inflateInit2_", "libz.so"),
            ("glDrawArrays", "libGLESv2.so"),
            ("eglGetDisplay", ""),
            ("printf", ""),
        ];
        for (name, want) in cases {
            assert_eq!(guess_library(name, &needed), want, "{name}");
        }
    }
}
