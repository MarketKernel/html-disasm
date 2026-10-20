//! A Mach-O reader, a port of src/core/macho.ts: everything about a macOS or
//! iOS program that is not its code. 64-bit files and the 32-bit ones (i386,
//! armv7); universal files are opened at the slice asked for, else arm64, else
//! the first. From the load commands come the segments and sections, the
//! symbol table, the libraries, the entry point, the build and source
//! versions, the UUID, the code signature, the function starts and the
//! data-in-code ranges; imports are named through the indirect symbol table
//! and through the bind opcodes or the chained fixups; exports come from the
//! export trie.
//!
//! The values the TypeScript kept as JavaScript numbers are `f64` here, and
//! computed as JavaScript computes them, so an address past 2^53 rounds the
//! same way. A read the TypeScript's DataView would have refused (past the end
//! of the slice) fails the same way: [`MachOError::OutOfBounds`].

use crate::refs::FxHashMap;
use crate::text::{js_hex, js_locale, js_number};

#[derive(Clone, Debug, PartialEq)]
pub struct Section {
    pub segname: String,
    pub sectname: String,
    pub addr: f64,
    pub size: f64,
    pub offset: u32,
    pub align: u32,
    pub flags: u32,
    pub reserved1: u32,
    pub reserved2: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Segment {
    pub name: String,
    pub vmaddr: f64,
    pub vmsize: f64,
    pub fileoff: f64,
    pub filesize: f64,
    pub maxprot: u32,
    pub initprot: u32,
    /// Its sections, as indices into [`MachO::sections`].
    pub sections: Vec<usize>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MachSymbol {
    pub name: String,
    pub addr: f64,
    pub ty: u8,
    pub sect: u8,
    pub desc: u16,
    pub external: bool,
    pub undefined: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Import {
    pub name: String,
    pub library: String,
    /// Where the pointer to it lives (a GOT or lazy pointer slot), when known.
    pub slot: Option<f64>,
    pub weak: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Export {
    pub name: String,
    pub addr: f64,
    pub flags: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct LoadCommand {
    pub cmd: u32,
    pub name: String,
    pub size: u32,
    pub offset: usize,
    /// One line about what it says.
    pub summary: String,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct CodeSignature {
    pub identifier: Option<String>,
    pub team_id: Option<String>,
    pub hash_type: Option<String>,
    pub flags: Option<u32>,
    pub entitlements: Option<String>,
    pub pages: Option<u32>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Build {
    pub platform: String,
    pub minos: String,
    pub sdk: String,
    pub tools: Vec<String>,
}

/// A map with JavaScript's Map semantics for number keys: insertion order kept, a key set again keeps its place.
#[derive(Clone, Debug, PartialEq)]
pub struct NumberMap<V> {
    pub entries: Vec<(f64, V)>,
    index: FxHashMap<u64, usize>,
}

impl<V> Default for NumberMap<V> {
    fn default() -> Self {
        NumberMap { entries: Vec::new(), index: FxHashMap::default() }
    }
}

/// A number as a hash key: its bits, mixed (splitmix64's finaliser, which loses nothing). A double's
/// low bits are zeros for most integers, and FxHasher would put such keys in a few buckets.
#[inline]
pub fn number_key(v: f64) -> u64 {
    // SameValueZero: -0 is 0.
    let mut x = (v + 0.0).to_bits();
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

impl<V> NumberMap<V> {
    pub fn set(&mut self, key: f64, value: V) {
        match self.index.get(&number_key(key)) {
            Some(&k) => self.entries[k].1 = value,
            None => {
                self.index.insert(number_key(key), self.entries.len());
                self.entries.push((key, value));
            }
        }
    }

    pub fn has(&self, key: f64) -> bool {
        self.index.contains_key(&number_key(key))
    }

    pub fn get(&self, key: f64) -> Option<&V> {
        self.index.get(&number_key(key)).map(|&k| &self.entries[k].1)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Arch {
    pub name: String,
    pub offset: f64,
    pub size: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct MachO {
    /// The architecture slices of a universal file; one entry for a thin file.
    pub arches: Vec<Arch>,
    /// Where the opened slice's bytes are in the file.
    pub slice: (usize, usize),
    pub cputype: u32,
    pub cpusubtype: u32,
    pub arch: String,
    pub is64: bool,
    pub filetype: u32,
    pub file_type_name: String,
    pub flags: u32,
    pub flag_names: Vec<&'static str>,
    pub commands: Vec<LoadCommand>,
    pub segments: Vec<Segment>,
    pub sections: Vec<Section>,
    pub symbols: Vec<MachSymbol>,
    pub libraries: Vec<String>,
    /// In the order they were found (the page sorts them by name).
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    /// Address of a stub (or GOT slot, or lazy pointer) → the imported name.
    pub stubs: NumberMap<String>,
    /// A pointer dyld rebases through a fixup chain → the address it holds.
    pub rebases: NumberMap<f64>,
    pub function_starts: Vec<f64>,
    /// Address, length, kind.
    pub data_in_code: Vec<(f64, u32, u32)>,
    pub entry: Option<f64>,
    /// "main" (LC_MAIN) or "thread" (LC_UNIXTHREAD).
    pub entry_kind: Option<&'static str>,
    pub uuid: Option<String>,
    pub build: Option<Build>,
    pub source_version: Option<String>,
    pub dylinker: Option<String>,
    pub rpaths: Vec<String>,
    pub install_name: Option<String>,
    pub signature: Option<CodeSignature>,
    pub encrypted: Option<bool>,
    /// Offset, size, id.
    pub encryption: Option<(u32, u32, u32)>,
    pub base: f64,
    pub slice_offset: f64,
    /// Offset and size of LC_CODE_SIGNATURE's data.
    pub signature_at: Option<(u32, u32)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MachOError {
    /// The file is too small to be a Mach-O program.
    TooSmall,
    /// A universal header with more than 64 slices: a Java class file.
    JavaClass,
    /// The universal file has no architectures.
    NoArches,
    /// No 0xfeedfacf signature.
    NotMachO,
    /// A read past the end, where the TypeScript's DataView threw.
    OutOfBounds,
}

type Result<T> = core::result::Result<T, MachOError>;

const CPU_ARM64: u32 = 0x0100_000c;
const CPU_X86_64: u32 = 0x0100_0007;

fn file_type(t: u32) -> Option<&'static str> {
    Some(match t {
        1 => "Object file",
        2 => "Executable",
        3 => "Fixed VM library",
        4 => "Core dump",
        5 => "Preloaded executable",
        6 => "Dynamic library",
        7 => "Dynamic linker",
        8 => "Bundle",
        9 => "Dynamic library stub",
        10 => "Debug symbols (dSYM)",
        11 => "Kernel extension",
        _ => return None,
    })
}

const HEADER_FLAGS: [&str; 32] = [
    "NOUNDEFS",
    "INCRLINK",
    "DYLDLINK",
    "BINDATLOAD",
    "PREBOUND",
    "SPLIT_SEGS",
    "LAZY_INIT",
    "TWOLEVEL",
    "FORCE_FLAT",
    "NOMULTIDEFS",
    "NOFIXPREBINDING",
    "PREBINDABLE",
    "ALLMODSBOUND",
    "SUBSECTIONS_VIA_SYMBOLS",
    "CANONICAL",
    "WEAK_DEFINES",
    "BINDS_TO_WEAK",
    "ALLOW_STACK_EXECUTION",
    "ROOT_SAFE",
    "SETUID_SAFE",
    "NO_REEXPORTED_DYLIBS",
    "PIE",
    "DEAD_STRIPPABLE_DYLIB",
    "HAS_TLV_DESCRIPTORS",
    "NO_HEAP_EXECUTION",
    "APP_EXTENSION_SAFE",
    "NLIST_OUTOFSYNC_WITH_DYLDINFO",
    "SIM_SUPPORT",
    "",
    "",
    "",
    "DYLIB_IN_CACHE",
];

fn command_name(cmd: u32) -> Option<&'static str> {
    Some(match cmd {
        0x1 => "LC_SEGMENT",
        0x2 => "LC_SYMTAB",
        0x5 => "LC_UNIXTHREAD",
        0xb => "LC_DYSYMTAB",
        0xc => "LC_LOAD_DYLIB",
        0xd => "LC_ID_DYLIB",
        0xe => "LC_LOAD_DYLINKER",
        0xf => "LC_ID_DYLINKER",
        0x8000_0018 => "LC_LOAD_WEAK_DYLIB",
        0x19 => "LC_SEGMENT_64",
        0x1b => "LC_UUID",
        0x8000_001c => "LC_RPATH",
        0x1d => "LC_CODE_SIGNATURE",
        0x1e => "LC_SEGMENT_SPLIT_INFO",
        0x8000_001f => "LC_REEXPORT_DYLIB",
        0x21 => "LC_ENCRYPTION_INFO",
        0x22 => "LC_DYLD_INFO",
        0x8000_0022 => "LC_DYLD_INFO_ONLY",
        0x8000_0023 => "LC_LOAD_UPWARD_DYLIB",
        0x24 => "LC_VERSION_MIN_MACOSX",
        0x25 => "LC_VERSION_MIN_IPHONEOS",
        0x26 => "LC_FUNCTION_STARTS",
        0x27 => "LC_DYLD_ENVIRONMENT",
        0x8000_0028 => "LC_MAIN",
        0x29 => "LC_DATA_IN_CODE",
        0x2a => "LC_SOURCE_VERSION",
        0x2b => "LC_DYLIB_CODE_SIGN_DRS",
        0x2c => "LC_ENCRYPTION_INFO_64",
        0x2d => "LC_LINKER_OPTION",
        0x2e => "LC_LINKER_OPTIMIZATION_HINT",
        0x32 => "LC_BUILD_VERSION",
        0x8000_0033 => "LC_DYLD_EXPORTS_TRIE",
        0x8000_0034 => "LC_DYLD_CHAINED_FIXUPS",
        0x35 => "LC_FILESET_ENTRY",
        0x36 => "LC_ATOM_INFO",
        _ => return None,
    })
}

fn platform_name(p: u32) -> Option<&'static str> {
    Some(match p {
        1 => "macOS",
        2 => "iOS",
        3 => "tvOS",
        4 => "watchOS",
        5 => "bridgeOS",
        6 => "Mac Catalyst",
        7 => "iOS Simulator",
        8 => "tvOS Simulator",
        9 => "watchOS Simulator",
        10 => "DriverKit",
        11 => "visionOS",
        12 => "visionOS Simulator",
        _ => return None,
    })
}

fn tool_name(t: u32) -> Option<&'static str> {
    Some(match t {
        1 => "clang",
        2 => "swift",
        3 => "ld",
        4 => "lld",
        1024 => "Metal",
        _ => return None,
    })
}

/// `arm64`, `x86_64`, `armv7s`…: the architecture of a CPU type and subtype.
pub fn arch_name(cputype: u32, subtype: u32) -> String {
    match cputype {
        CPU_ARM64 => (if subtype & 0xff == 2 { "arm64e" } else { "arm64" }).into(),
        CPU_X86_64 => "x86_64".into(),
        0x0200_000c => "arm64_32".into(),
        12 => match subtype & 0xff {
            5 => "armv4t",
            6 => "armv6",
            7 => "armv5",
            9 => "armv7",
            10 => "armv7f",
            11 => "armv7s",
            12 => "armv7k",
            14 => "armv6m",
            15 => "armv7m",
            16 => "armv7em",
            _ => "arm",
        }
        .into(),
        7 => "i386".into(),
        _ => format!("cpu {cputype:x}"),
    }
}

/// major.minor.patch packed as xxxx.yy.zz
fn version32(v: u32) -> String {
    let patch = v & 0xff;
    if patch != 0 {
        format!("{}.{}.{patch}", v >> 16, (v >> 8) & 0xff)
    } else {
        format!("{}.{}", v >> 16, (v >> 8) & 0xff)
    }
}

/// Text from UTF-8 as the page's TextDecoder makes it: a leading byte order mark dropped, bad bytes replaced.
pub fn utf8(bytes: &[u8]) -> String {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    String::from_utf8_lossy(bytes).into_owned()
}

/// An unsigned LEB128 number at `at` as JavaScript summed it (a double), and where it ends.
pub fn uleb(bytes: &[u8], at: usize) -> (f64, usize) {
    let mut result = 0.0f64;
    let mut shift = 0i32;
    let mut p = at;
    loop {
        let byte = bytes.get(p).copied().unwrap_or(0);
        p += 1;
        result += (byte & 0x7f) as f64 * 2f64.powi(shift);
        shift += 7;
        if byte & 0x80 == 0 || p >= bytes.len() {
            break;
        }
    }
    (result, p)
}

/// A signed LEB128 number at `at` as JavaScript summed it, and where it ends.
pub fn sleb(bytes: &[u8], at: usize) -> (f64, usize) {
    let mut result = 0.0f64;
    let mut shift = 0i32;
    let mut p = at;
    let mut byte;
    loop {
        byte = bytes.get(p).copied().unwrap_or(0);
        p += 1;
        result += (byte & 0x7f) as f64 * 2f64.powi(shift);
        shift += 7;
        if !(byte & 0x80 != 0 && p < bytes.len()) {
            break;
        }
    }
    if byte & 0x40 != 0 {
        result -= 2f64.powi(shift);
    }
    (result, p)
}

/// Reads the slice as the TypeScript's Reader did: bytes past the end read as 0, wider values past it fail.
struct Reader<'a> {
    bytes: &'a [u8],
}

impl Reader<'_> {
    #[inline]
    fn u8(&self, at: usize) -> u32 {
        self.bytes.get(at).copied().unwrap_or(0) as u32
    }

    #[inline]
    fn take<const N: usize>(&self, at: usize) -> Result<[u8; N]> {
        let end = at.checked_add(N).ok_or(MachOError::OutOfBounds)?;
        self.bytes.get(at..end).map(|b| b.try_into().unwrap()).ok_or(MachOError::OutOfBounds)
    }

    fn u16(&self, at: usize) -> Result<u32> {
        Ok(u16::from_le_bytes(self.take(at)?) as u32)
    }

    fn u32(&self, at: usize) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(at)?))
    }

    fn big64(&self, at: usize) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(at)?))
    }

    /// `Number(getBigUint64())`: rounded to a double past 2^53.
    fn u64(&self, at: usize) -> Result<f64> {
        Ok(self.big64(at)? as f64)
    }

    fn be32(&self, at: usize) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(at)?))
    }

    /// A NUL-terminated string, at most `max` bytes.
    fn cstr(&self, at: usize, max: usize) -> String {
        let limit = self.bytes.len().min(at.saturating_add(max));
        let mut end = at;
        while end < limit && self.bytes[end] != 0 {
            end += 1;
        }
        utf8(self.bytes.get(at..end.max(at)).unwrap_or(&[]))
    }

    fn uleb(&self, at: usize) -> (f64, usize) {
        uleb(self.bytes, at)
    }

    /// A ULEB128 that the bind opcodes use as a 64-bit step, where a step back wraps around.
    fn uleb_step(&self, at: usize) -> (f64, usize) {
        let mut result = 0u64;
        let mut shift = 0u32;
        let mut p = at;
        loop {
            let byte = self.bytes.get(p).copied().unwrap_or(0);
            p += 1;
            if shift < 64 {
                result |= ((byte & 0x7f) as u64) << shift;
            }
            shift += 7;
            if byte & 0x80 == 0 || p >= self.bytes.len() {
                break;
            }
        }
        (result as i64 as f64, p)
    }
}

/// A position from a JavaScript number: past what a slice can hold, it is past its end.
#[inline]
fn pos(v: f64) -> usize {
    if v >= 0.0 && v < usize::MAX as f64 {
        v as usize
    } else {
        usize::MAX
    }
}

/// Opens a Mach-O file, or one slice of a universal one: the one named `want`, else the arm64 slice, else the first.
pub fn parse_macho(file: &[u8], want: Option<&str>) -> Result<MachO> {
    if file.len() < 32 {
        return Err(MachOError::TooSmall);
    }
    let outer = Reader { bytes: file };
    let magic_be = outer.be32(0)?;
    let mut arches: Vec<Arch> = Vec::new();
    let mut slice = (0, file.len());
    let mut slice_offset = 0.0;
    if magic_be == 0xcafe_babe || magic_be == 0xcafe_babf {
        let wide = magic_be == 0xcafe_babf;
        let count = outer.be32(4)?;
        if count > 64 {
            return Err(MachOError::JavaClass);
        }
        let mut entries = Vec::new();
        for i in 0..count as usize {
            let at = 8 + i * if wide { 32 } else { 20 };
            let cputype = outer.be32(at)?;
            let subtype = outer.be32(at + 4)?;
            let (offset, size) = if wide {
                (u64::from_be_bytes(outer.take(at + 8)?) as f64, u64::from_be_bytes(outer.take(at + 16)?) as f64)
            } else {
                (outer.be32(at + 8)? as f64, outer.be32(at + 12)? as f64)
            };
            entries.push((arch_name(cputype, subtype), offset, size, cputype));
        }
        arches = entries.iter().map(|(name, offset, size, _)| Arch { name: name.clone(), offset: *offset, size: *size }).collect();
        let pick =
            want.and_then(|w| entries.iter().find(|e| e.0 == w)).or_else(|| entries.iter().find(|e| e.3 == CPU_ARM64)).or_else(|| entries.first()).ok_or(MachOError::NoArches)?;
        // subarray(): both ends clamped to the file.
        let start = pos(pick.1).min(file.len());
        let end = pos(pick.1 + pick.2).min(file.len()).max(start);
        slice = (start, end);
        slice_offset = pick.1;
    }
    let bytes = &file[slice.0..slice.1];
    let r = Reader { bytes };
    let magic = r.u32(0)?;
    if magic != 0xfeed_facf && magic != 0xfeed_face {
        return Err(MachOError::NotMachO);
    }
    let is64 = magic == 0xfeed_facf;
    // Pointers, and the fields that hold addresses, are 8 bytes in a 64-bit file and 4 in a 32-bit one.
    let ptr_size = if is64 { 8 } else { 4 };
    let addr_at = |at: usize| -> Result<f64> {
        if is64 {
            r.u64(at)
        } else {
            Ok(r.u32(at)? as f64)
        }
    };
    let cputype = r.u32(4)?;
    let cpusubtype = r.u32(8)?;
    let filetype = r.u32(12)?;
    let ncmds = r.u32(16)?;
    let flags = r.u32(24)?;
    let arch = arch_name(cputype, cpusubtype);
    if arches.is_empty() {
        arches.push(Arch { name: arch.clone(), offset: 0.0, size: file.len() as f64 });
    }
    let mut m = MachO {
        arches,
        slice,
        cputype,
        cpusubtype,
        arch,
        is64,
        filetype,
        file_type_name: file_type(filetype).map_or_else(|| format!("type {filetype}"), String::from),
        flags,
        flag_names: HEADER_FLAGS.iter().enumerate().filter(|&(i, name)| !name.is_empty() && flags & (1 << i) != 0).map(|(_, &n)| n).collect(),
        commands: Vec::new(),
        segments: Vec::new(),
        sections: Vec::new(),
        symbols: Vec::new(),
        libraries: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        stubs: NumberMap::default(),
        rebases: NumberMap::default(),
        function_starts: Vec::new(),
        data_in_code: Vec::new(),
        entry: None,
        entry_kind: None,
        uuid: None,
        build: None,
        source_version: None,
        dylinker: None,
        rpaths: Vec::new(),
        install_name: None,
        signature: None,
        encrypted: None,
        encryption: None,
        base: 0.0,
        slice_offset,
        signature_at: None,
    };

    let mut symtab: Option<(u32, u32, u32, u32)> = None;
    let mut dysymtab: Option<(u32, u32)> = None;
    // bind, weak, lazy, exports
    let mut dyld_info: Option<[(u32, u32); 4]> = None;
    let mut exports_trie: Option<(u32, u32)> = None;
    let mut chained: Option<(u32, u32)> = None;
    let mut function_starts: Option<(u32, u32)> = None;
    let mut data_in_code: Option<(u32, u32)> = None;
    let mut signature: Option<(u32, u32)> = None;
    let mut entry_off: Option<f64> = None;
    let mut thread_entry: Option<f64> = None;

    let mut at = if is64 { 32 } else { 28 };
    let mut i = 0;
    while i < ncmds && at + 8 <= bytes.len() {
        i += 1;
        let cmd = r.u32(at)?;
        let size = r.u32(at + 4)?;
        if size < 8 {
            break;
        }
        let name = command_name(cmd).map_or_else(|| format!("0x{cmd:x}"), String::from);
        let mut summary = String::new();
        match cmd {
            0x19 | 0x1 => {
                let wide = cmd == 0x19;
                let (vmaddr, vmsize, fileoff, filesize, maxprot, initprot, nsects) = if wide {
                    (r.u64(at + 24)?, r.u64(at + 32)?, r.u64(at + 40)?, r.u64(at + 48)?, r.u32(at + 56)?, r.u32(at + 60)?, r.u32(at + 64)?)
                } else {
                    (r.u32(at + 24)? as f64, r.u32(at + 28)? as f64, r.u32(at + 32)? as f64, r.u32(at + 36)? as f64, r.u32(at + 40)?, r.u32(at + 44)?, r.u32(at + 48)?)
                };
                let mut segment = Segment { name: r.cstr(at + 8, 16), vmaddr, vmsize, fileoff, filesize, maxprot, initprot, sections: Vec::new() };
                for s in 0..nsects as usize {
                    let section = if wide {
                        let p = at + 72 + s * 80;
                        Section {
                            sectname: r.cstr(p, 16),
                            segname: r.cstr(p + 16, 16),
                            addr: r.u64(p + 32)?,
                            size: r.u64(p + 40)?,
                            offset: r.u32(p + 48)?,
                            align: r.u32(p + 52)?,
                            flags: r.u32(p + 64)?,
                            reserved1: r.u32(p + 68)?,
                            reserved2: r.u32(p + 72)?,
                        }
                    } else {
                        let p = at + 56 + s * 68;
                        Section {
                            sectname: r.cstr(p, 16),
                            segname: r.cstr(p + 16, 16),
                            addr: r.u32(p + 32)? as f64,
                            size: r.u32(p + 36)? as f64,
                            offset: r.u32(p + 40)?,
                            align: r.u32(p + 44)?,
                            flags: r.u32(p + 56)?,
                            reserved1: r.u32(p + 60)?,
                            reserved2: r.u32(p + 64)?,
                        }
                    };
                    segment.sections.push(m.sections.len());
                    m.sections.push(section);
                }
                if segment.name == "__TEXT" {
                    m.base = segment.vmaddr - segment.fileoff;
                }
                summary = format!("{} at 0x{}, {} bytes, {nsects} section{}", segment.name, js_hex(segment.vmaddr), js_locale(segment.vmsize), if nsects == 1 { "" } else { "s" });
                m.segments.push(segment);
            }
            0x5 => {
                // LC_UNIXTHREAD: the initial registers of the main thread, programs before LC_MAIN start where their pc says.
                thread_entry = thread_pc(&r, at, size as usize, cputype)?;
                if let Some(e) = thread_entry {
                    summary = format!("entry at 0x{}", js_hex(e));
                }
            }
            0x2 => {
                let s = (r.u32(at + 8)?, r.u32(at + 12)?, r.u32(at + 16)?, r.u32(at + 20)?);
                summary = format!("{} symbols", js_locale(s.1 as f64));
                symtab = Some(s);
            }
            0xb => {
                let d = (r.u32(at + 56)?, r.u32(at + 60)?);
                summary = format!("{} indirect symbols", js_locale(d.1 as f64));
                dysymtab = Some(d);
            }
            0xc | 0x8000_0018 | 0x8000_001f | 0x8000_0023 => {
                let lib = r.cstr(at + r.u32(at + 8)? as usize, size as usize);
                summary = format!("{lib} ({})", version32(r.u32(at + 16)?));
                m.libraries.push(lib);
            }
            0xd => {
                let name = r.cstr(at + r.u32(at + 8)? as usize, size as usize);
                summary = name.clone();
                m.install_name = Some(name);
            }
            0xe => {
                let name = r.cstr(at + r.u32(at + 8)? as usize, size as usize);
                summary = name.clone();
                m.dylinker = Some(name);
            }
            0x8000_001c => {
                let path = r.cstr(at + r.u32(at + 8)? as usize, size as usize);
                summary = path.clone();
                m.rpaths.push(path);
            }
            0x1b => {
                let raw = bytes.get((at + 8).min(bytes.len())..(at + 24).min(bytes.len())).unwrap_or(&[]);
                let hex: String = raw.iter().map(|b| format!("{b:02X}")).collect();
                // String.slice: past the end, an empty piece.
                let part = |a: usize, b: usize| hex.get(a.min(hex.len())..b.min(hex.len())).unwrap_or("").to_string();
                let uuid = format!("{}-{}-{}-{}-{}", part(0, 8), part(8, 12), part(12, 16), part(16, 20), part(20, usize::MAX));
                summary = uuid.clone();
                m.uuid = Some(uuid);
            }
            0x22 | 0x8000_0022 => {
                let info = [(r.u32(at + 16)?, r.u32(at + 20)?), (r.u32(at + 24)?, r.u32(at + 28)?), (r.u32(at + 32)?, r.u32(at + 36)?), (r.u32(at + 40)?, r.u32(at + 44)?)];
                summary = format!("rebase {} B, bind {} B, lazy bind {} B, exports {} B", r.u32(at + 12)?, info[0].1, info[2].1, info[3].1);
                dyld_info = Some(info);
            }
            0x8000_0033 => {
                let t = (r.u32(at + 8)?, r.u32(at + 12)?);
                summary = format!("{} bytes", js_locale(t.1 as f64));
                exports_trie = Some(t);
            }
            0x8000_0034 => {
                let c = (r.u32(at + 8)?, r.u32(at + 12)?);
                summary = format!("{} bytes", js_locale(c.1 as f64));
                chained = Some(c);
            }
            0x26 => {
                let f = (r.u32(at + 8)?, r.u32(at + 12)?);
                summary = format!("{} bytes", js_locale(f.1 as f64));
                function_starts = Some(f);
            }
            0x29 => {
                let d = (r.u32(at + 8)?, r.u32(at + 12)?);
                summary = format!("{} entries", js_number(d.1 as f64 / 8.0));
                data_in_code = Some(d);
            }
            0x1d => {
                let s = (r.u32(at + 8)?, r.u32(at + 12)?);
                summary = format!("{} bytes at offset 0x{:x}", js_locale(s.1 as f64), s.0);
                signature = Some(s);
            }
            0x8000_0028 => {
                let off = r.u64(at + 8)?;
                let stack = r.u64(at + 16)?;
                summary = format!("entry at file offset 0x{}, stack {}", js_hex(off), if stack == 0.0 { "default".into() } else { js_number(stack) });
                entry_off = Some(off);
            }
            0x2a => {
                let v = r.big64(at + 8)?;
                let mut parts = vec![v >> 40, (v >> 30) & 0x3ff, (v >> 20) & 0x3ff, (v >> 10) & 0x3ff, v & 0x3ff];
                while parts.len() > 2 && parts.last() == Some(&0) {
                    parts.pop();
                }
                let text = parts.iter().map(u64::to_string).collect::<Vec<_>>().join(".");
                summary = text.clone();
                m.source_version = Some(text);
            }
            0x32 => {
                let p = r.u32(at + 8)?;
                let platform = platform_name(p).map_or_else(|| format!("platform {p}"), String::from);
                let ntools = r.u32(at + 20)?;
                let mut tools = Vec::new();
                for t in 0..ntools as usize {
                    let tool = r.u32(at + 24 + t * 8)?;
                    tools.push(format!("{} {}", tool_name(tool).map_or_else(|| format!("tool {tool}"), String::from), version32(r.u32(at + 28 + t * 8)?)));
                }
                let build = Build { platform: platform.clone(), minos: version32(r.u32(at + 12)?), sdk: version32(r.u32(at + 16)?), tools: tools.clone() };
                summary = format!("{platform} {}, SDK {}{}", build.minos, build.sdk, if tools.is_empty() { String::new() } else { format!(", {}", tools.join(", ")) });
                m.build = Some(build);
            }
            0x24 | 0x25 => {
                summary = format!("min {}, SDK {}", version32(r.u32(at + 8)?), version32(r.u32(at + 12)?));
                if m.build.is_none() {
                    m.build = Some(Build {
                        platform: (if cmd == 0x24 { "macOS" } else { "iOS" }).into(),
                        minos: version32(r.u32(at + 8)?),
                        sdk: version32(r.u32(at + 12)?),
                        tools: Vec::new(),
                    });
                }
            }
            0x21 | 0x2c => {
                let e = (r.u32(at + 8)?, r.u32(at + 12)?, r.u32(at + 16)?);
                let encrypted = e.2 != 0 && e.1 != 0;
                summary = format!("{}: {} bytes at 0x{:x}", if encrypted { "encrypted (FairPlay)" } else { "not encrypted" }, js_locale(e.1 as f64), e.0);
                m.encryption = Some(e);
                m.encrypted = Some(encrypted);
            }
            _ => {}
        }
        m.commands.push(LoadCommand { cmd, name, size, offset: at, summary });
        at += size as usize;
    }

    if let Some(off) = entry_off {
        m.entry = Some(m.base + off);
        m.entry_kind = Some("main");
    } else if let Some(e) = thread_entry {
        m.entry = Some(e);
        m.entry_kind = Some("thread");
    }

    let nlist_size = if is64 { 16 } else { 12 };
    if let Some((symoff, nsyms, stroff, strsize)) = symtab {
        for s in 0..nsyms as usize {
            let p = symoff as usize + s * nlist_size;
            if p + nlist_size > bytes.len() {
                break;
            }
            let strx = r.u32(p)?;
            let ty = r.u8(p + 4) as u8;
            if ty & 0xe0 != 0 {
                continue; // stabs: debugging entries
            }
            let name = if strx != 0 && strx < strsize { r.cstr(stroff as usize + strx as usize, 4096) } else { String::new() };
            m.symbols.push(MachSymbol { name, ty, sect: r.u8(p + 5) as u8, desc: r.u16(p + 6)? as u16, addr: addr_at(p + 8)?, external: ty & 1 != 0, undefined: ty & 0x0e == 0 });
        }
    }
    let symbol_name = |index: u32| -> Result<String> {
        let Some((symoff, _, stroff, strsize)) = symtab else { return Ok(String::new()) };
        let p = symoff as usize + index as usize * nlist_size;
        let strx = r.u32(p)?;
        Ok(if strx < strsize { r.cstr(stroff as usize + strx as usize, 4096) } else { String::new() })
    };

    // __stubs, __got, __la_symbol_ptr: each slot is one entry of the indirect symbol table.
    if let (Some((indirectoff, nindirect)), Some((_, nsyms, _, _))) = (dysymtab, symtab) {
        for section in &m.sections {
            let ty = section.flags & 0xff;
            // S_NON_LAZY_SYMBOL_POINTERS 6, S_LAZY_SYMBOL_POINTERS 7, S_SYMBOL_STUBS 8, S_THREAD_LOCAL_VARIABLE_POINTERS 0x14
            if ty != 6 && ty != 7 && ty != 8 && ty != 0x14 {
                continue;
            }
            let stride = if ty == 8 { section.reserved2 } else { ptr_size };
            if stride == 0 {
                continue;
            }
            let mut k = 0u64;
            while ((k * stride as u64) as f64) < section.size {
                let entry = section.reserved1 as u64 + k;
                if entry >= nindirect as u64 {
                    break;
                }
                let index = r.u32(pos(indirectoff as f64 + entry as f64 * 4.0))?;
                k += 1;
                if index & 0xc000_0000 != 0 || index >= nsyms {
                    continue; // INDIRECT_SYMBOL_LOCAL / ABS
                }
                let name = symbol_name(index)?;
                if !name.is_empty() {
                    m.stubs.set(section.addr + ((k - 1) * stride as u64) as f64, name);
                }
            }
        }
    }

    let mut imports = Imports::default();
    if let Some(info) = dyld_info {
        for (range, lazy) in [(info[0], false), (info[2], true), (info[1], false)] {
            if range.1 != 0 {
                run_bind_opcodes(&r, range.0 as usize, range.1 as usize, lazy, &m.segments, ptr_size as f64, &mut |name, ordinal, slot, weak| {
                    imports.add(&mut m.stubs, &m.libraries, name, ordinal, slot, weak)
                });
            }
        }
    }
    if let Some((start, size)) = chained {
        if size != 0 && is64 {
            parse_chained_fixups(&r, start as usize, m.base, &mut m.rebases, &mut |name, ordinal, slot, weak| imports.add(&mut m.stubs, &m.libraries, name, ordinal, slot, weak))?;
        }
    }
    m.imports = imports.list;

    let trie = exports_trie.or_else(|| dyld_info.map(|i| i[3]).filter(|e| e.1 != 0));
    if let Some((start, size)) = trie {
        if size != 0 {
            m.exports = parse_export_trie(&r, start as usize, size as usize, m.base);
        }
    }

    if let Some((start, size)) = function_starts {
        if size != 0 {
            let mut addr = m.segments.iter().find(|s| s.name == "__TEXT").map_or(m.base, |s| s.vmaddr);
            let mut p = start as usize;
            let end = start as usize + size as usize;
            while p < end {
                let (delta, next) = r.uleb(p);
                p = next;
                if delta == 0.0 {
                    break;
                }
                addr += delta;
                m.function_starts.push(addr);
            }
        }
    }

    if let Some((start, size)) = data_in_code {
        if size != 0 {
            let mut p = start as usize;
            while p + 8 <= start as usize + size as usize {
                m.data_in_code.push((m.base + r.u32(p)? as f64, r.u16(p + 4)?, r.u16(p + 6)?));
                p += 8;
            }
        }
    }

    if let Some((start, size)) = signature {
        if size != 0 {
            m.signature_at = Some((start, size));
            m.signature = parse_signature(&r, start as usize, size as usize)?;
        }
    }
    Ok(m)
}

/// The imports as they are found, once per name and slot.
#[derive(Default)]
struct Imports {
    list: Vec<Import>,
    seen: crate::refs::FxHashSet<(String, Option<u64>)>,
}

impl Imports {
    fn add(&mut self, stubs: &mut NumberMap<String>, libraries: &[String], name: &str, ordinal: f64, slot: Option<f64>, weak: bool) {
        if name.is_empty() {
            return;
        }
        if self.seen.insert((name.to_string(), slot.map(number_key))) {
            self.list.push(Import { name: name.into(), library: library_name(libraries, ordinal), slot, weak });
        }
        if let Some(slot) = slot {
            if !stubs.has(slot) {
                stubs.set(slot, name.into());
            }
        }
    }
}

fn library_name(libraries: &[String], ordinal: f64) -> String {
    if ordinal == 0.0 {
        return "this image".into();
    }
    if ordinal == -1.0 {
        return "main executable".into();
    }
    if ordinal == -2.0 {
        return "flat lookup".into();
    }
    if ordinal == -3.0 {
        return "weak lookup".into();
    }
    let index = ordinal - 1.0;
    if index >= 0.0 && index.fract() == 0.0 && (index as usize) < libraries.len() {
        return libraries[index as usize].clone();
    }
    format!("library #{}", js_number(ordinal))
}

/// The pc a thread state starts at: LC_UNIXTHREAD holds one or more (flavor, count, registers) entries.
fn thread_pc(r: &Reader, at: usize, size: usize, cputype: u32) -> Result<Option<f64>> {
    let mut p = at + 8;
    while p + 8 <= at + size {
        let flavor = r.u32(p)?;
        let count = r.u32(p + 4)?;
        let state = p + 8;
        if cputype == 7 && flavor == 1 {
            return Ok(Some(r.u32(state + 10 * 4)? as f64)); // x86_THREAD_STATE32: eip
        }
        if cputype == 12 && flavor == 1 {
            return Ok(Some(r.u32(state + 15 * 4)? as f64)); // ARM_THREAD_STATE: pc
        }
        if cputype == CPU_X86_64 && flavor == 4 {
            return Ok(Some(r.u64(state + 16 * 8)?)); // x86_THREAD_STATE64: rip
        }
        if cputype == CPU_ARM64 && flavor == 6 {
            return Ok(Some(r.u64(state + 32 * 8)?)); // ARM_THREAD_STATE64: pc
        }
        p = state + count as usize * 4;
    }
    Ok(None)
}

type AddImport<'a> = dyn FnMut(&str, f64, Option<f64>, bool) + 'a;

fn run_bind_opcodes(r: &Reader, start: usize, size: usize, lazy: bool, segments: &[Segment], ptr_size: f64, add: &mut AddImport) {
    let mut p = start;
    let end = start + size;
    let mut ordinal = 0.0;
    let mut name = String::new();
    let mut weak = false;
    let mut segment = 0usize;
    let mut offset = 0.0f64;
    let slot = |segment: usize, offset: f64| segments.get(segment).map_or(0.0, |s| s.vmaddr) + offset;
    while p < end {
        let byte = r.u8(p);
        p += 1;
        let op = byte & 0xf0;
        let immediate = byte & 0x0f;
        match op {
            0x00 => {
                // DONE
                if !lazy {
                    return;
                }
            }
            0x10 => ordinal = immediate as f64,
            0x20 => (ordinal, p) = r.uleb(p),
            // SET_DYLIB_SPECIAL_IMM: 0 this image, then -1, -2, -3 sign-extended from four bits
            0x30 => ordinal = if immediate != 0 { (immediate as i32 | !0xf) as f64 } else { 0.0 },
            0x40 => {
                weak = immediate & 1 != 0;
                let at = p;
                while p < end && r.u8(p) != 0 {
                    p += 1;
                }
                name = utf8(r.bytes.get(at.min(r.bytes.len())..p.min(r.bytes.len()).max(at.min(r.bytes.len()))).unwrap_or(&[]));
                p += 1;
            }
            0x50 => {} // SET_TYPE
            0x60 => p = sleb(r.bytes, p).1,
            0x70 => {
                segment = immediate as usize;
                (offset, p) = r.uleb(p);
            }
            0x80 => {
                let (step, next) = r.uleb_step(p);
                p = next;
                offset += step;
            }
            0x90 => {
                add(&name, ordinal, Some(slot(segment, offset)), weak);
                offset += ptr_size;
            }
            0xa0 => {
                add(&name, ordinal, Some(slot(segment, offset)), weak);
                let (step, next) = r.uleb_step(p);
                p = next;
                offset += ptr_size + step;
            }
            0xb0 => {
                add(&name, ordinal, Some(slot(segment, offset)), weak);
                offset += ptr_size + immediate as f64 * ptr_size;
            }
            0xc0 => {
                let (count, next) = r.uleb(p);
                let (skip, next) = r.uleb_step(next);
                p = next;
                let mut i = 0.0;
                while i < count && i < (1 << 20) as f64 {
                    add(&name, ordinal, Some(slot(segment, offset)), weak);
                    offset += ptr_size + skip;
                    i += 1.0;
                }
            }
            _ => return,
        }
    }
}

/// dyld's chained fixups: the import table, and the chains that say which pointer binds to which import.
fn parse_chained_fixups(r: &Reader, start: usize, base: f64, rebases: &mut NumberMap<f64>, add: &mut AddImport) -> Result<()> {
    let starts_offset = r.u32(start + 4)? as usize;
    let imports_offset = r.u32(start + 8)? as usize;
    let symbols_offset = r.u32(start + 12)? as usize;
    let imports_count = r.u32(start + 16)?;
    let format = r.u32(start + 20)?;
    let mut names: Vec<(String, f64, bool)> = Vec::new();
    for i in 0..imports_count as usize {
        let (ordinal, weak, name_offset) = match format {
            1 | 2 => {
                let v = r.u32(start + imports_offset + i * if format == 1 { 4 } else { 8 })?;
                let mut ordinal = (v & 0xff) as f64;
                if ordinal > 240.0 {
                    ordinal -= 256.0;
                }
                (ordinal, v & 0x100 != 0, (v >> 9) as usize)
            }
            _ => {
                let v = r.big64(start + imports_offset + i * 16)?;
                let mut ordinal = (v & 0xffff) as f64;
                if ordinal > 65520.0 {
                    ordinal -= 65536.0;
                }
                (ordinal, v & 0x10000 != 0, (v >> 32) as usize)
            }
        };
        names.push((r.cstr(start + symbols_offset + name_offset, 4096), ordinal, weak));
    }

    let seg_count = r.u32(start + starts_offset)?;
    for s in 0..seg_count as usize {
        let seg_info = r.u32(start + starts_offset + 4 + s * 4)? as usize;
        if seg_info == 0 {
            continue;
        }
        let at = start + starts_offset + seg_info;
        let page_size = r.u16(at + 4)? as f64;
        let pointer_format = r.u16(at + 6)?;
        let segment_offset = r.u64(at + 8)?;
        let page_count = r.u16(at + 20)?;
        let stride = if pointer_format == 1 || pointer_format == 12 { 8.0 } else { 4.0 }; // ARM64E (and its userland24) use 8-byte strides
        for page in 0..page_count as usize {
            let page_start = r.u16(at + 22 + page * 2)?;
            if page_start == 0xffff || page_start & 0x8000 != 0 {
                continue; // none, or multiple starts (32-bit formats only)
            }
            let mut offset = segment_offset + page as f64 * page_size + page_start as f64;
            for _ in 0..1 << 16 {
                if offset + 8.0 > r.bytes.len() as f64 {
                    break;
                }
                let raw = r.big64(offset as usize)?;
                let addr = base + offset;
                let (bind, next, ordinal, target) = if pointer_format == 1 || pointer_format == 9 || pointer_format == 12 {
                    // DYLD_CHAINED_PTR_ARM64E(_USERLAND/_USERLAND24): an authenticated rebase has a 32-bit offset, a plain one 43 bits.
                    let ordinal = raw & if pointer_format == 12 { 0xff_ffff } else { 0xffff };
                    let target = raw & if raw >> 63 != 0 { 0xffff_ffff } else { 0x7ff_ffff_ffff };
                    (raw >> 62 & 1 != 0, (raw >> 51) & 0x7ff, ordinal, target as f64)
                } else {
                    // DYLD_CHAINED_PTR_64 / 64_OFFSET
                    (raw >> 63 != 0, (raw >> 51) & 0xfff, raw & 0xff_ffff, (raw & 0xf_ffff_ffff) as f64)
                };
                if bind {
                    if let Some((name, ordinal, weak)) = names.get(ordinal as usize) {
                        add(name, *ordinal, Some(addr), *weak);
                    }
                } else {
                    // The formats differ in whether the target is an address or an offset from the base; the size tells.
                    rebases.set(addr, if target < base { base + target } else { target });
                }
                if next == 0 {
                    break;
                }
                offset += next as f64 * stride;
            }
        }
    }
    for (name, ordinal, weak) in &names {
        add(name, *ordinal, None, *weak);
    }
    Ok(())
}

fn parse_export_trie(r: &Reader, start: usize, size: usize, base: f64) -> Vec<Export> {
    let mut out: Vec<Export> = Vec::new();
    let end = start + size;
    let mut stack: Vec<(f64, String)> = vec![(start as f64, String::new())];
    let mut seen = crate::refs::FxHashSet::default();
    while out.len() < 1 << 20 {
        let Some((node, prefix)) = stack.pop() else { break };
        if node >= end as f64 || !seen.insert(number_key(node)) {
            continue;
        }
        let node = node as usize;
        let (terminal, mut p) = r.uleb(node);
        let children_at = p as f64 + terminal;
        if terminal != 0.0 {
            let (flags, next) = r.uleb(p);
            p = next;
            if (flags as i64) & 8 == 0 {
                let (offset, _) = r.uleb(p);
                out.push(Export { name: prefix.clone(), addr: base + offset, flags });
            }
        }
        let mut p = pos(children_at);
        let children = r.u8(p);
        p = p.saturating_add(1);
        for _ in 0..children {
            let at = p;
            while p < end && r.u8(p) != 0 {
                p += 1;
            }
            let len = r.bytes.len();
            let edge = utf8(r.bytes.get(at.min(len)..p.min(len).max(at.min(len))).unwrap_or(&[]));
            p += 1;
            let (child, next) = r.uleb(p);
            p = next;
            stack.push((start as f64 + child, prefix.clone() + &edge));
        }
    }
    out.sort_by(|a, b| a.addr.partial_cmp(&b.addr).unwrap_or(core::cmp::Ordering::Equal));
    out
}

fn hash_name(h: u32) -> String {
    match h {
        1 => "SHA-1".into(),
        2 => "SHA-256".into(),
        3 => "SHA-256 (truncated)".into(),
        4 => "SHA-384".into(),
        _ => format!("hash {h}"),
    }
}

fn parse_signature(r: &Reader, start: usize, size: usize) -> Result<Option<CodeSignature>> {
    if start + 12 > r.bytes.len() || r.be32(start)? != 0xfade_0cc0 {
        return Ok(None);
    }
    let mut out = CodeSignature::default();
    let count = r.be32(start + 8)?;
    for i in 0..count.min(64) as usize {
        let offset = r.be32(start + 12 + i * 8 + 4)? as usize;
        let at = start + offset;
        if offset >= size {
            continue;
        }
        let magic = r.be32(at)?;
        if magic == 0xfade_0c02 && out.identifier.is_none() {
            let version = r.be32(at + 8)?;
            out.flags = Some(r.be32(at + 12)?);
            out.identifier = Some(r.cstr(at + r.be32(at + 20)? as usize, 512));
            out.pages = Some(r.be32(at + 28)?);
            out.hash_type = Some(hash_name(r.u8(at + 37)));
            if version >= 0x20200 {
                let team = r.be32(at + 48)?;
                if team != 0 {
                    out.team_id = Some(r.cstr(at + team as usize, 64));
                }
            }
        } else if magic == 0xfade_7171 {
            let length = r.be32(at + 4)? as usize;
            let len = r.bytes.len();
            let from = (at + 8).min(len);
            out.entitlements = Some(utf8(r.bytes.get(from..(at + length).min(len).max(from)).unwrap_or(&[])));
        }
    }
    Ok(Some(out))
}

impl MachO {
    /// The section an address falls in.
    pub fn section_at(&self, addr: f64) -> Option<&Section> {
        self.sections.iter().find(|s| addr >= s.addr && addr < s.addr + s.size)
    }

    /// The bytes behind a virtual address (none for zero-fill sections), from the slice's bytes.
    pub fn bytes_at<'a>(&self, slice: &'a [u8], addr: f64, length: f64) -> Option<&'a [u8]> {
        let section = self.section_at(addr)?;
        if section.offset == 0 {
            return None;
        }
        let ty = section.flags & 0xff;
        if ty == 1 || ty == 0xc || ty == 0x12 {
            return None; // zerofill
        }
        let at = section.offset as f64 + (addr - section.addr);
        let end = (at + length).min(section.offset as f64 + section.size);
        let (a, b) = crate::elf::subarray(slice.len(), at, end);
        Some(&slice[a..b])
    }

    /// A NUL-terminated string at a virtual address (empty when it starts with a NUL).
    pub fn cstring_at(&self, slice: &[u8], addr: f64, max: f64) -> Option<String> {
        let bytes = self.bytes_at(slice, addr, max)?;
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        Some(if end == 0 { String::new() } else { utf8(&bytes[..end]) })
    }

    /// A pointer at a virtual address, as stored (a rebase's target when the chains say; a chained
    /// rebase's low 36 bits otherwise); 4 bytes in a 32-bit file.
    pub fn pointer_at(&self, slice: &[u8], addr: f64) -> Option<f64> {
        if !self.is64 {
            let b = self.bytes_at(slice, addr, 4.0)?;
            if b.len() < 4 {
                return None;
            }
            return Some(self.rebases.get(addr).copied().unwrap_or(u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as f64));
        }
        let b = self.bytes_at(slice, addr, 8.0)?;
        if b.len() < 8 {
            return None;
        }
        if let Some(&rebased) = self.rebases.get(addr) {
            return Some(rebased);
        }
        let raw = u64::from_le_bytes(b[..8].try_into().unwrap());
        if raw >> 51 != 0 {
            let target = (raw & 0xf_ffff_ffff) as f64;
            return Some(if target < self.base { self.base + target } else { target });
        }
        Some(raw as f64)
    }
}
