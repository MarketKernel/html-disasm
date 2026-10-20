//! A WebAssembly module reader: everything in the file that is not code.
//!
//! Every section of the binary format is read — types (with the rec groups,
//! structs and arrays of GC), imports, functions, tables, memories, globals,
//! exports, the start function, element and data segments, tags — and the
//! custom sections tools leave behind: the `name` section (names of
//! functions, locals, globals, data segments and more), `producers` (the
//! languages and compilers), `target_features`, `dylink.0` of dynamic
//! libraries, `linking` and `reloc.*` of object files, `sourceMappingURL`,
//! `external_debug_info`, `build_id` and the DWARF `.debug_*` sections.
//!
//! Function bodies are only located here; the analysis decodes them.
//!
//! A port of src/core/wasm/module.ts. A damaged section is read as far as it
//! goes: what came before the damage stays, and a warning says what was
//! skipped, so a module that is not quite valid still opens.

use core::borrow::Borrow;
use core::fmt::{self, Write};
use core::hash::Hash;
use std::collections::HashMap;

use super::decode::{decode_at, write_insn, FormatContext, WasmInsn};
use super::reader::{add, storage_type, utf8, val_type, HeapType, ImportName, Num, Reader, Result, ValType, WasmError, MAX_SAFE_INTEGER};

/// Why a file is not read as a WebAssembly module (the TypeScript's NotWasm).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NotWasm {
    /// `Not a WebAssembly module (no \0asm signature).`
    NoSignature,
    /// `This is a WebAssembly component, not a core module: the disassembler reads core modules.`
    Component,
    /// `Unknown WebAssembly version {version}.`, the version written `0x{hex}` of the signed
    /// 32-bit value (JavaScript's `version.toString(16)`: a negative one reads `0x-…`).
    UnknownVersion { version: i32 },
}

/// What parse_wasm can fail with: not a module, or a module so damaged its
/// sections cannot be told apart (the TypeScript threw a WasmError then).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
    NotWasm(NotWasm),
    Wasm(WasmError),
}

impl From<NotWasm> for ParseError {
    fn from(e: NotWasm) -> Self {
        ParseError::NotWasm(e)
    }
}

impl From<WasmError> for ParseError {
    fn from(e: WasmError) -> Self {
        ParseError::Wasm(e)
    }
}

/// A problem met while reading, kept so the page can say what it skipped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Warning {
    /// `section {id} at 0x{offset} runs past the end of the file` (offset in hex).
    SectionPastEnd { id: u8, offset: usize },
    /// `unknown section {id} at 0x{offset}` (offset in hex).
    UnknownSection { id: u8, offset: usize },
    /// `{section} section: {error}`: the section stopped being read there.
    Section { section: String, error: WasmError },
    /// `{declared} functions declared, {bodies} bodies`
    BodyCount { declared: usize, bodies: usize },
}

impl fmt::Display for Warning {
    /// The warning as the TypeScript core wrote it (English: the page shows it as it is).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Warning::SectionPastEnd { id, offset } => write!(f, "section {id} at 0x{offset:x} runs past the end of the file"),
            Warning::UnknownSection { id, offset } => write!(f, "unknown section {id} at 0x{offset:x}"),
            Warning::Section { section, error } => write!(f, "{section} section: {error}"),
            Warning::BodyCount { declared, bodies } => write!(f, "{declared} functions declared, {bodies} bodies"),
        }
    }
}

/// A map that keeps the order its keys were first set in, as a JavaScript Map does.
#[derive(Clone, Debug)]
pub struct OrderedMap<K, V> {
    entries: Vec<(K, V)>,
    index: HashMap<K, usize>,
}

impl<K, V> Default for OrderedMap<K, V> {
    fn default() -> Self {
        OrderedMap { entries: Vec::new(), index: HashMap::new() }
    }
}

impl<K: Eq + Hash + Clone, V> OrderedMap<K, V> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get<Q: Eq + Hash + ?Sized>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
    {
        self.index.get(key).map(|&i| &self.entries[i].1)
    }

    pub fn contains_key<Q: Eq + Hash + ?Sized>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
    {
        self.index.contains_key(key)
    }

    /// Sets a value; a key set before keeps its place.
    pub fn set(&mut self, key: K, value: V) {
        match self.index.get(&key) {
            Some(&i) => self.entries[i].1 = value,
            None => {
                self.index.insert(key.clone(), self.entries.len());
                self.entries.push((key, value));
            }
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.entries.iter().map(|(k, v)| (k, v))
    }

    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.entries.iter().map(|(k, _)| k)
    }

    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.entries.iter().map(|(_, v)| v)
    }
}

pub type NameMap = OrderedMap<u64, String>;
pub type IndirectNameMap = OrderedMap<u64, NameMap>;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FuncType {
    pub params: Vec<ValType>,
    pub results: Vec<ValType>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TypeKind {
    Func,
    Struct,
    Array,
    Cont,
}

impl TypeKind {
    pub fn name(self) -> &'static str {
        match self {
            TypeKind::Func => "func",
            TypeKind::Struct => "struct",
            TypeKind::Array => "array",
            TypeKind::Cont => "cont",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Field {
    pub ty: ValType,
    pub mutable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeDef {
    pub kind: TypeKind,
    pub func: Option<FuncType>,
    /// The fields of a struct, the element of an array.
    pub fields: Option<Vec<Field>>,
    /// The function type a continuation type wraps.
    pub cont: Option<u64>,
    /// `final` in the TypeScript.
    pub is_final: bool,
    pub supers: Vec<u64>,
    /// Index of the first type of its rec group, and how many the group has.
    pub group: usize,
    pub group_size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WasmSection {
    pub id: u8,
    /// The section's name: `type`, `code`, or the name of a custom section.
    pub name: String,
    /// Where the section starts (its id byte) and where its contents start.
    pub offset: usize,
    pub start: usize,
    pub size: u64,
    /// The number of entries, for sections that are a vector.
    pub count: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub min: Num,
    pub max: Option<Num>,
    pub shared: bool,
    pub is64: bool,
    /// log2 of the page size, when it is not the usual 64 KiB.
    pub page_size_log2: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExternKind {
    Func,
    Table,
    Memory,
    Global,
    Tag,
}

impl ExternKind {
    pub fn name(self) -> &'static str {
        match self {
            ExternKind::Func => "func",
            ExternKind::Table => "table",
            ExternKind::Memory => "memory",
            ExternKind::Global => "global",
            ExternKind::Tag => "tag",
        }
    }

    fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            0 => ExternKind::Func,
            1 => ExternKind::Table,
            2 => ExternKind::Memory,
            3 => ExternKind::Global,
            4 => ExternKind::Tag,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WasmImport {
    pub module: String,
    pub name: String,
    pub kind: ExternKind,
    /// Its index among the items of its kind (imports come first).
    pub index: u64,
    /// For a function or tag: its type.
    pub ty: Option<u64>,
    /// Where the entry is in the file.
    pub offset: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WasmExport {
    pub name: String,
    pub kind: ExternKind,
    pub index: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WasmTable {
    pub ty: ValType,
    pub limits: Limits,
    pub imported: bool,
    pub init: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WasmMemory {
    pub limits: Limits,
    pub imported: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WasmGlobal {
    pub ty: ValType,
    pub mutable: bool,
    pub imported: bool,
    pub init: Option<String>,
    /// The value of a constant initialiser.
    pub value: Option<Num>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElementMode {
    Active,
    Passive,
    Declarative,
}

impl ElementMode {
    pub fn name(self) -> &'static str {
        match self {
            ElementMode::Active => "active",
            ElementMode::Passive => "passive",
            ElementMode::Declarative => "declarative",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WasmElement {
    pub mode: ElementMode,
    pub table: u64,
    pub offset: Option<String>,
    pub offset_value: Option<i64>,
    /// Its element type (`type` in the TypeScript, held there as its text).
    pub ty: ValType,
    /// Function indices (None for an entry that is not a ref.func).
    pub funcs: Vec<Option<u64>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DataMode {
    Active,
    Passive,
}

impl DataMode {
    pub fn name(self) -> &'static str {
        match self {
            DataMode::Active => "active",
            DataMode::Passive => "passive",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WasmData {
    pub mode: DataMode,
    pub memory: u64,
    pub offset: Option<String>,
    /// The memory address of an active segment with a constant offset.
    pub addr: Option<u64>,
    /// Where its bytes are in the file.
    pub start: usize,
    pub size: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Local {
    pub count: u64,
    pub ty: ValType,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WasmBody {
    /// Index of the function in the function index space (imports first).
    pub func: u64,
    /// Where the body's size is, where its locals start, where its first instruction is, where it ends.
    pub offset: usize,
    pub start: usize,
    pub code: usize,
    pub end: usize,
    pub locals: Vec<Local>,
}

#[derive(Clone, Debug, Default)]
pub struct Names {
    pub module: Option<String>,
    pub functions: NameMap,
    pub locals: IndirectNameMap,
    pub labels: IndirectNameMap,
    pub types: NameMap,
    pub tables: NameMap,
    pub memories: NameMap,
    pub globals: NameMap,
    pub elements: NameMap,
    pub data: NameMap,
    pub fields: IndirectNameMap,
    pub tags: NameMap,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProducerValue {
    pub name: String,
    pub version: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Producer {
    pub field: String,
    pub values: Vec<ProducerValue>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CustomSection {
    pub name: String,
    pub offset: usize,
    pub start: usize,
    pub size: usize,
    /// Its contents, when they are short printable text.
    pub text: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Dylink {
    pub memory_size: u64,
    pub memory_align: u64,
    pub table_size: u64,
    pub table_align: u64,
    pub needed: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SymbolKind {
    Function,
    Data,
    Global,
    Section,
    Tag,
    Table,
}

impl SymbolKind {
    pub fn name(self) -> &'static str {
        match self {
            SymbolKind::Function => "function",
            SymbolKind::Data => "data",
            SymbolKind::Global => "global",
            SymbolKind::Section => "section",
            SymbolKind::Tag => "tag",
            SymbolKind::Table => "table",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkingSymbol {
    pub kind: SymbolKind,
    pub name: String,
    /// -1 when it has none.
    pub index: i64,
    pub flags: u64,
    pub defined: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Linking {
    pub version: u64,
    pub symbols: Vec<LinkingSymbol>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Relocation {
    /// The section the relocations apply to.
    pub section: String,
    pub count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Feature {
    /// `+`, `-` or `=`: the byte as a character.
    pub prefix: char,
    pub name: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DebugSection {
    pub start: usize,
    pub size: usize,
}

#[derive(Clone, Debug, Default)]
pub struct WasmModule {
    pub bytes: Vec<u8>,
    pub version: u32,
    pub sections: Vec<WasmSection>,
    pub types: Vec<TypeDef>,
    pub imports: Vec<WasmImport>,
    /// The type of every function, imported ones first.
    pub func_types: Vec<u64>,
    pub imported_funcs: u64,
    pub tables: Vec<WasmTable>,
    pub memories: Vec<WasmMemory>,
    pub globals: Vec<WasmGlobal>,
    pub tags: Vec<u64>,
    pub exports: Vec<WasmExport>,
    pub start: Option<u64>,
    pub elements: Vec<WasmElement>,
    pub data: Vec<WasmData>,
    pub data_count: Option<u64>,
    pub bodies: Vec<WasmBody>,
    pub names: Names,
    pub producers: Vec<Producer>,
    pub features: Vec<Feature>,
    pub customs: Vec<CustomSection>,
    pub dylink: Option<Dylink>,
    /// A relocatable object file (from `clang -c`): its symbols.
    pub linking: Option<Linking>,
    pub relocations: Vec<Relocation>,
    pub source_mapping_url: Option<String>,
    pub external_debug_info: Option<String>,
    pub build_id: Option<String>,
    /// The DWARF sections, by name.
    pub debug: OrderedMap<String, DebugSection>,
    /// True when any memory is 64-bit (addresses are i64).
    pub memory64: bool,
    /// Problems met while reading, kept so the page can say what it skipped.
    pub warnings: Vec<Warning>,
}

const SECTION_NAMES: [&str; 14] = ["custom", "type", "import", "function", "table", "memory", "global", "export", "start", "element", "code", "data", "data count", "tag"];

/// An element of a list by a number read from the file (`list[index]` in JavaScript).
#[inline]
pub fn at<T>(list: &[T], index: u64) -> Option<&T> {
    usize::try_from(index).ok().and_then(|i| list.get(i))
}

pub fn is_wasm(bytes: &[u8]) -> bool {
    bytes.len() >= 8 && bytes[0] == 0 && bytes[1] == 0x61 && bytes[2] == 0x73 && bytes[3] == 0x6d
}

/// Reads a WebAssembly module.
pub fn parse_wasm(bytes: Vec<u8>) -> core::result::Result<WasmModule, ParseError> {
    if !is_wasm(&bytes) {
        return Err(NotWasm::NoSignature.into());
    }
    let version = i32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let high = (version as u32) >> 16;
    if version & 0xffff != 1 || high != 0 {
        if high == 1 {
            return Err(NotWasm::Component.into());
        }
        return Err(NotWasm::UnknownVersion { version }.into());
    }
    let mut module = WasmModule { version: 1, ..Default::default() };
    read_sections(&bytes, &mut module)?;
    module.bytes = bytes;
    Ok(module)
}

fn read_sections(bytes: &[u8], module: &mut WasmModule) -> Result<()> {
    let mut r = Reader::new(bytes, 8, bytes.len());
    let mut defined: Vec<u64> = Vec::new();
    while !r.done() {
        let offset = r.pos;
        let id = r.u8()?;
        let size = r.u32()?;
        let start = r.pos;
        let end = add(start, size);
        if end > bytes.len() {
            module.warnings.push(Warning::SectionPastEnd { id, offset });
            break;
        }
        let mut s = Reader::new(bytes, start, end);
        let name = match SECTION_NAMES.get(id as usize) {
            Some(name) => name.to_string(),
            None => format!("unknown {id}"),
        };
        let mut section = WasmSection { id, name, offset, start, size, count: None };
        if let Err(error) = read_section(&mut s, &mut section, module, &mut defined, end) {
            module.warnings.push(Warning::Section { section: section.name.clone(), error });
        }
        module.sections.push(section);
        r.pos = end;
    }
    module.func_types.extend_from_slice(&defined);
    module.memory64 = module.memories.iter().any(|m| m.limits.is64);
    if module.bodies.len() != defined.len() {
        module.warnings.push(Warning::BodyCount { declared: defined.len(), bodies: module.bodies.len() });
    }
    Ok(())
}

fn read_section(s: &mut Reader, section: &mut WasmSection, module: &mut WasmModule, defined: &mut Vec<u64>, end: usize) -> Result<()> {
    let bytes = s.bytes;
    match section.id {
        0 => {
            section.name = s.name()?;
            read_custom(module, &section.name, &mut Reader::new(bytes, s.pos, end), section.offset)?;
        }
        1 => section.count = Some(read_types(s, &mut module.types)?),
        2 => section.count = Some(read_imports(s, module)?),
        3 => {
            let count = s.u32()?;
            section.count = Some(count);
            defined.clear();
            for _ in 0..count {
                defined.push(s.u32()?);
            }
        }
        4 => {
            let count = s.u32()?;
            section.count = Some(count);
            for _ in 0..count {
                if s.peek() == 0x40 {
                    s.u8()?;
                    s.u8()?;
                    let ty = val_type(s)?;
                    let limits = read_limits(s)?;
                    let init = const_expr(s, module)?.text;
                    module.tables.push(WasmTable { ty, limits, imported: false, init: Some(init) });
                } else {
                    let ty = val_type(s)?;
                    let limits = read_limits(s)?;
                    module.tables.push(WasmTable { ty, limits, imported: false, init: None });
                }
            }
        }
        5 => {
            let count = s.u32()?;
            section.count = Some(count);
            for _ in 0..count {
                let limits = read_limits(s)?;
                module.memories.push(WasmMemory { limits, imported: false });
            }
        }
        6 => {
            let count = s.u32()?;
            section.count = Some(count);
            for _ in 0..count {
                let ty = val_type(s)?;
                let mutable = s.u8()? & 1 != 0;
                let init = const_expr(s, module)?;
                module.globals.push(WasmGlobal { ty, mutable, imported: false, init: Some(init.text), value: init.value });
            }
        }
        7 => {
            let count = s.u32()?;
            section.count = Some(count);
            for _ in 0..count {
                let name = s.name()?;
                let kind = ExternKind::from_byte(s.u8()?).unwrap_or(ExternKind::Func);
                let index = s.u32()?;
                module.exports.push(WasmExport { name, kind, index });
            }
        }
        8 => module.start = Some(s.u32()?),
        9 => section.count = Some(read_elements(s, module)?),
        10 => {
            let count = s.u32()?;
            section.count = Some(count);
            for i in 0..count {
                let body_offset = s.pos;
                let body_size = s.u32()?;
                let body_start = s.pos;
                let body_end = add(body_start, body_size);
                let mut b = Reader::new(bytes, body_start, body_end);
                let mut locals = Vec::new();
                let groups = b.u32()?;
                for _ in 0..groups {
                    let count = b.u32()?;
                    let ty = val_type(&mut b)?;
                    locals.push(Local { count, ty });
                }
                module.bodies.push(WasmBody { func: module.imported_funcs + i, offset: body_offset, start: body_start, code: b.pos, end: body_end, locals });
                s.pos = body_end;
            }
        }
        11 => {
            let count = s.u32()?;
            section.count = Some(count);
            for _ in 0..count {
                let flags = s.u32()?;
                let memory = if flags == 2 { s.u32()? } else { 0 };
                let mut offset = None;
                let mut addr = None;
                if flags != 1 {
                    let expr = const_expr(s, module)?;
                    offset = Some(expr.text);
                    match expr.value {
                        // `value >>> 0`
                        Some(Num::Number(v)) => addr = Some(v as u32 as u64),
                        Some(Num::BigInt(v)) if (0..=MAX_SAFE_INTEGER).contains(&v) => addr = Some(v as u64),
                        _ => {}
                    }
                }
                let size = s.u32()?;
                let mode = if flags == 1 { DataMode::Passive } else { DataMode::Active };
                module.data.push(WasmData { mode, memory, offset, addr, start: s.pos, size });
                s.pos = add(s.pos, size);
            }
        }
        12 => module.data_count = Some(s.u32()?),
        13 => {
            let count = s.u32()?;
            section.count = Some(count);
            for _ in 0..count {
                s.u8()?;
                let ty = s.u32()?;
                module.tags.push(ty);
            }
        }
        id => module.warnings.push(Warning::UnknownSection { id, offset: section.offset }),
    }
    Ok(())
}

/* ------------------------------------------------------------------ *
 * Sections
 * ------------------------------------------------------------------ */

fn func_type(s: &mut Reader) -> Result<FuncType> {
    let mut params = Vec::new();
    let mut results = Vec::new();
    for _ in 0..s.u32()? {
        params.push(val_type(s)?);
    }
    for _ in 0..s.u32()? {
        results.push(val_type(s)?);
    }
    Ok(FuncType { params, results })
}

fn field(s: &mut Reader) -> Result<Field> {
    let ty = storage_type(s)?;
    Ok(Field { ty, mutable: s.u8()? & 1 != 0 })
}

fn sub_type(s: &mut Reader, group: usize, group_size: u64) -> Result<TypeDef> {
    let mut first = s.byte()?;
    let mut is_final = true;
    let mut supers = Vec::new();
    if first == Some(0x50) || first == Some(0x4f) {
        is_final = first == Some(0x4f);
        for _ in 0..s.u32()? {
            supers.push(s.u32()?);
        }
        first = s.byte()?;
    }
    if first == Some(0x65) {
        // A shared composite type.
        first = s.byte()?;
    }
    let mut def = TypeDef { kind: TypeKind::Func, func: None, fields: None, cont: None, is_final, supers, group, group_size };
    match first {
        Some(0x60) => def.func = Some(func_type(s)?),
        Some(0x5f) => {
            def.kind = TypeKind::Struct;
            let mut fields = Vec::new();
            for _ in 0..s.u32()? {
                fields.push(field(s)?);
            }
            def.fields = Some(fields);
        }
        Some(0x5e) => {
            def.kind = TypeKind::Array;
            def.fields = Some(vec![field(s)?]);
        }
        Some(0x5d) => {
            def.kind = TypeKind::Cont;
            def.cont = Some(s.u32()?);
        }
        form => return Err(WasmError::UnknownTypeForm { form }),
    }
    Ok(def)
}

fn read_types(s: &mut Reader, types: &mut Vec<TypeDef>) -> Result<u64> {
    let count = s.u32()?;
    for _ in 0..count {
        if s.peek() == 0x4e {
            s.u8()?;
            let size = s.u32()?;
            let group = types.len();
            for _ in 0..size {
                types.push(sub_type(s, group, size)?);
            }
        } else {
            let group = types.len();
            types.push(sub_type(s, group, 1)?);
        }
    }
    Ok(count)
}

fn read_limits(s: &mut Reader) -> Result<Limits> {
    let flags = s.u8()?;
    let is64 = flags & 4 != 0;
    let min = if is64 { s.u64()? } else { Num::Number(s.u32()? as i64) };
    let max = if flags & 1 != 0 { Some(if is64 { s.u64()? } else { Num::Number(s.u32()? as i64) }) } else { None };
    let page_size_log2 = if flags & 8 != 0 { Some(s.u32()?) } else { None };
    Ok(Limits { min, max, shared: flags & 2 != 0, is64, page_size_log2 })
}

fn read_imports(s: &mut Reader, module: &mut WasmModule) -> Result<u64> {
    let count = s.u32()?;
    let mut counters = [0u64; 5];
    for _ in 0..count {
        let offset = s.pos;
        let module_name = s.name()?;
        let name = s.name()?;
        let Some(kind) = s.byte()?.and_then(ExternKind::from_byte) else {
            return Err(WasmError::UnknownImportKind(Box::new(ImportName { module: module_name, name })));
        };
        let index = counters[kind as usize];
        counters[kind as usize] += 1;
        let mut entry = WasmImport { module: module_name, name, kind, index, ty: None, offset };
        match kind {
            ExternKind::Func => {
                let ty = s.u32()?;
                entry.ty = Some(ty);
                module.func_types.push(ty);
                module.imported_funcs += 1;
            }
            ExternKind::Table => {
                let ty = val_type(s)?;
                let limits = read_limits(s)?;
                module.tables.push(WasmTable { ty, limits, imported: true, init: None });
            }
            ExternKind::Memory => {
                let limits = read_limits(s)?;
                module.memories.push(WasmMemory { limits, imported: true });
            }
            ExternKind::Global => {
                let ty = val_type(s)?;
                let mutable = s.u8()? & 1 != 0;
                module.globals.push(WasmGlobal { ty, mutable, imported: true, init: None, value: None });
            }
            ExternKind::Tag => {
                s.u8()?;
                let ty = s.u32()?;
                entry.ty = Some(ty);
                module.tags.push(ty);
            }
        }
        module.imports.push(entry);
    }
    Ok(count)
}

/// A constant expression: its text, its value when it can be worked out, and
/// the function of an element entry that is a lone ref.func.
pub struct ConstExpr {
    pub text: String,
    pub value: Option<Num>,
    pub func: Option<u64>,
}

/// A constant expression up to its `end`: its text, and its value when it can
/// be worked out — constants, the extended-constant arithmetic, and the
/// globals a dynamic library is given (__memory_base and __table_base, taken
/// as 0 so its data shows at offsets from its base).
fn const_expr(s: &mut Reader, module: &WasmModule) -> Result<ConstExpr> {
    let mut text = String::new();
    let mut insn = WasmInsn::new();
    let mut stack: Vec<Option<Num>> = Vec::new();
    // undefined, null (a ref.null), or a function (a ref.func).
    let mut func: Option<Option<u64>> = None;
    let mut count = 0;
    let ctx = format_context(module);
    let binary = |stack: &mut Vec<Option<Num>>, f: fn(i128, i128) -> i128, bits: u32| {
        let b = stack.pop().flatten();
        let a = stack.pop().flatten();
        let (Some(a), Some(b)) = (a, b) else {
            stack.push(None);
            return;
        };
        let r = f(a.value(), b.value());
        stack.push(Some(if bits == 32 { Num::Number(r as i32 as i64) } else { Num::BigInt(r as i64 as i128) }));
    };
    loop {
        decode_at(s.bytes, s.pos, s.end, &mut insn);
        if insn.op.is_none() {
            return Err(WasmError::BadConstExpr { at: s.pos });
        }
        s.pos += insn.len;
        if insn.m == "end" {
            break;
        }
        count += 1;
        if count > 1 {
            text.push(' ');
        }
        let _ = write_insn(&mut text, &insn, Some(&ctx));
        match insn.m {
            "i32.const" | "i64.const" => stack.push(Some(insn.value)),
            "global.get" => {
                let global = at(&module.globals, insn.a);
                let imported = module.imports.iter().find(|i| i.kind == ExternKind::Global && i.index == insn.a);
                if imported.is_some_and(|i| i.name == "__memory_base" || i.name == "__table_base") {
                    stack.push(Some(Num::Number(0)));
                } else {
                    stack.push(global.and_then(|g| if g.imported { None } else { g.value }));
                }
            }
            "i32.add" => binary(&mut stack, i128::wrapping_add, 32),
            "i32.sub" => binary(&mut stack, i128::wrapping_sub, 32),
            "i32.mul" => binary(&mut stack, i128::wrapping_mul, 32),
            "i64.add" => binary(&mut stack, i128::wrapping_add, 64),
            "i64.sub" => binary(&mut stack, i128::wrapping_sub, 64),
            "i64.mul" => binary(&mut stack, i128::wrapping_mul, 64),
            "ref.func" => {
                func = Some(Some(insn.a));
                stack.push(None);
            }
            "ref.null" => {
                func = Some(None);
                stack.push(None);
            }
            _ => stack.push(None),
        }
    }
    let mut value = if stack.len() == 1 { stack[0] } else { None };
    if let Some(Num::BigInt(v)) = value {
        if (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&v) {
            value = Some(Num::Number(v as i64));
        }
    }
    Ok(ConstExpr { text, value, func: if count == 1 { func.flatten() } else { None } })
}

fn read_elements(s: &mut Reader, module: &mut WasmModule) -> Result<u64> {
    let count = s.u32()?;
    for _ in 0..count {
        let flags = s.u32()?;
        let passive_or_declarative = flags & 1 != 0;
        let explicit_table = flags & 2 != 0;
        let uses_exprs = flags & 4 != 0;
        let mode = if passive_or_declarative {
            if explicit_table {
                ElementMode::Declarative
            } else {
                ElementMode::Passive
            }
        } else {
            ElementMode::Active
        };
        let mut table = 0;
        let mut offset = None;
        let mut offset_value = None;
        if !passive_or_declarative {
            if explicit_table {
                table = s.u32()?;
            }
            let expr = const_expr(s, module)?;
            offset = Some(expr.text);
            offset_value = expr.value.and_then(Num::number);
        }
        let mut ty = ValType::Ref { nullable: true, heap: HeapType::abstract_type(0x70) };
        if passive_or_declarative || explicit_table {
            if uses_exprs {
                ty = val_type(s)?;
            } else {
                s.u8()?; // elemkind 0x00: funcref
            }
        }
        let mut funcs = Vec::new();
        for _ in 0..s.u32()? {
            if uses_exprs {
                funcs.push(const_expr(s, module)?.func);
            } else {
                funcs.push(Some(s.u32()?));
            }
        }
        module.elements.push(WasmElement { mode, table, offset, offset_value, ty, funcs });
    }
    Ok(count)
}

/* ------------------------------------------------------------------ *
 * Custom sections
 * ------------------------------------------------------------------ */

fn is_printable(bytes: &[u8]) -> bool {
    !bytes.iter().any(|&b| (b < 0x20 && b != 9 && b != 10 && b != 13) || b == 0x7f)
}

fn read_custom(module: &mut WasmModule, name: &str, s: &mut Reader, offset: usize) -> Result<()> {
    let size = s.end - s.pos;
    module.customs.push(CustomSection { name: name.to_string(), offset, start: s.pos, size, text: None });
    if name.starts_with(".debug_") {
        module.debug.set(name.to_string(), DebugSection { start: s.pos, size });
        return Ok(());
    }
    match name {
        "name" => return read_names(s, &mut module.names),
        "producers" => {
            for _ in 0..s.u32()? {
                let field = s.name()?;
                let mut values = Vec::new();
                for _ in 0..s.u32()? {
                    let name = s.name()?;
                    let version = s.name()?;
                    values.push(ProducerValue { name, version });
                }
                module.producers.push(Producer { field, values });
            }
            return Ok(());
        }
        "target_features" => {
            for _ in 0..s.u32()? {
                let prefix = char::from(s.u8()?);
                let name = s.name()?;
                module.features.push(Feature { prefix, name });
            }
            return Ok(());
        }
        "sourceMappingURL" => {
            module.source_mapping_url = Some(s.name()?);
            return Ok(());
        }
        "external_debug_info" => {
            module.external_debug_info = Some(s.name()?);
            return Ok(());
        }
        "build_id" => {
            let n = s.u32()?;
            let bytes = s.bytes_n(n)?;
            let mut hex = String::with_capacity(bytes.len() * 2);
            for b in bytes {
                let _ = write!(hex, "{b:02x}");
            }
            module.build_id = Some(hex);
            return Ok(());
        }
        "dylink.0" => {
            let mut dylink = Dylink::default();
            while !s.done() {
                let ty = s.u8()?;
                let size = s.u32()?;
                let end = add(s.pos, size);
                if ty == 1 {
                    dylink.memory_size = s.u32()?;
                    dylink.memory_align = s.u32()?;
                    dylink.table_size = s.u32()?;
                    dylink.table_align = s.u32()?;
                } else if ty == 2 {
                    for _ in 0..s.u32()? {
                        dylink.needed.push(s.name()?);
                    }
                }
                s.pos = end;
            }
            module.dylink = Some(dylink);
            return Ok(());
        }
        "dylink" => {
            let mut dylink = Dylink { memory_size: s.u32()?, memory_align: s.u32()?, table_size: s.u32()?, table_align: s.u32()?, needed: Vec::new() };
            for _ in 0..s.u32()? {
                dylink.needed.push(s.name()?);
            }
            module.dylink = Some(dylink);
            return Ok(());
        }
        "linking" => {
            module.linking = Some(read_linking(s)?);
            return Ok(());
        }
        _ => {}
    }
    if let Some(section) = name.strip_prefix("reloc.") {
        s.u32()?;
        let count = s.u32()?;
        module.relocations.push(Relocation { section: section.to_string(), count });
        return Ok(());
    }
    // Short custom sections that are text (go:buildid, a URL, a version) are shown as they are.
    let bytes = &s.bytes[s.pos..s.end];
    if !bytes.is_empty() && bytes.len() <= 512 && is_printable(bytes) {
        module.customs.last_mut().unwrap().text = Some(utf8(bytes));
    }
    Ok(())
}

fn name_map(s: &mut Reader, into: &mut NameMap) -> Result<()> {
    for _ in 0..s.u32()? {
        let index = s.u32()?;
        let name = s.name()?;
        into.set(index, name);
    }
    Ok(())
}

fn indirect_name_map(s: &mut Reader, into: &mut IndirectNameMap) -> Result<()> {
    for _ in 0..s.u32()? {
        let index = s.u32()?;
        let mut map = NameMap::new();
        name_map(s, &mut map)?;
        into.set(index, map);
    }
    Ok(())
}

fn read_names(s: &mut Reader, names: &mut Names) -> Result<()> {
    while !s.done() {
        let id = s.u8()?;
        let size = s.u32()?;
        let end = add(s.pos, size);
        let mut sub = Reader::new(s.bytes, s.pos, end);
        // A damaged subsection loses its names; the others stay.
        let _ = match id {
            0 => sub.name().map(|name| names.module = Some(name)),
            1 => name_map(&mut sub, &mut names.functions),
            2 => indirect_name_map(&mut sub, &mut names.locals),
            3 => indirect_name_map(&mut sub, &mut names.labels),
            4 => name_map(&mut sub, &mut names.types),
            5 => name_map(&mut sub, &mut names.tables),
            6 => name_map(&mut sub, &mut names.memories),
            7 => name_map(&mut sub, &mut names.globals),
            8 => name_map(&mut sub, &mut names.elements),
            9 => name_map(&mut sub, &mut names.data),
            10 => indirect_name_map(&mut sub, &mut names.fields),
            11 => name_map(&mut sub, &mut names.tags),
            _ => Ok(()),
        };
        s.pos = end;
    }
    Ok(())
}

fn symbol_kind(b: u8) -> SymbolKind {
    match b {
        1 => SymbolKind::Data,
        2 => SymbolKind::Global,
        3 => SymbolKind::Section,
        4 => SymbolKind::Tag,
        5 => SymbolKind::Table,
        _ => SymbolKind::Function,
    }
}

fn read_linking(s: &mut Reader) -> Result<Linking> {
    let version = s.u32()?;
    let mut symbols = Vec::new();
    while !s.done() {
        let ty = s.u8()?;
        let size = s.u32()?;
        let end = add(s.pos, size);
        if ty == 8 {
            for _ in 0..s.u32()? {
                let kind = symbol_kind(s.u8()?);
                let flags = s.u32()?;
                let undefined_symbol = flags & 0x10 != 0;
                let explicit_name = flags & 0x40 != 0;
                let mut name = String::new();
                let mut index = -1;
                match kind {
                    SymbolKind::Data => {
                        name = s.name()?;
                        if !undefined_symbol {
                            index = s.u32()? as i64;
                            s.u64()?;
                            s.u64()?;
                        }
                    }
                    SymbolKind::Section => index = s.u32()? as i64,
                    _ => {
                        index = s.u32()? as i64;
                        if !undefined_symbol || explicit_name {
                            name = s.name()?;
                        }
                    }
                }
                symbols.push(LinkingSymbol { kind, name, index, flags, defined: !undefined_symbol });
            }
        }
        s.pos = end;
    }
    Ok(Linking { version, symbols })
}

/* ------------------------------------------------------------------ *
 * Lookups
 * ------------------------------------------------------------------ */

/// The block types' context of a module: its function types.
pub struct ModuleContext<'a> {
    pub types: &'a [TypeDef],
}

impl FormatContext for ModuleContext<'_> {
    fn func_type(&self, index: i64) -> Option<&FuncType> {
        u64::try_from(index).ok().and_then(|i| at(self.types, i)).and_then(|t| t.func.as_ref())
    }
}

pub fn format_context(module: &WasmModule) -> ModuleContext<'_> {
    ModuleContext { types: &module.types }
}

/// The type of a function by its index, or None.
pub fn func_type_of(module: &WasmModule, func: u64) -> Option<&FuncType> {
    let ty = *at(&module.func_types, func)?;
    at(&module.types, ty)?.func.as_ref()
}

fn join_types(types: &[ValType]) -> String {
    let mut s = String::new();
    for (i, t) in types.iter().enumerate() {
        if i > 0 {
            s.push_str(", ");
        }
        let _ = write!(s, "{t}");
    }
    s
}

/// `(i32, i32) -> i32`
pub fn signature_text(ty: Option<&FuncType>) -> String {
    let Some(ty) = ty else { return "?".into() };
    let params = format!("({})", join_types(&ty.params));
    match ty.results.len() {
        0 => params,
        1 => format!("{params} -> {}", ty.results[0]),
        _ => format!("{params} -> ({})", join_types(&ty.results)),
    }
}

/// The text of a type definition: `func (i32) -> i32`, `struct { i32, mut i8 }`, `array mut i8`.
pub fn type_text(def: Option<&TypeDef>) -> String {
    let Some(def) = def else { return "?".into() };
    let field = |f: &Field| format!("{}{}", if f.mutable { "mut " } else { "" }, f.ty);
    let fields = def.fields.as_deref().unwrap_or(&[]);
    match def.kind {
        TypeKind::Func => format!("func {}", signature_text(def.func.as_ref())),
        TypeKind::Struct => format!("struct {{ {} }}", fields.iter().map(field).collect::<Vec<_>>().join(", ")),
        TypeKind::Array => format!("array {}", fields.first().map(field).unwrap_or_default()),
        TypeKind::Cont => match def.cont {
            Some(cont) => format!("cont {cont}"),
            None => "cont undefined".into(),
        },
    }
}

/// `1..`, `1..16`: the minimum and the maximum, if any.
pub fn limits_text(limits: &Limits) -> String {
    match limits.max {
        Some(max) => format!("{}..{max}", limits.min),
        None => format!("{}..", limits.min),
    }
}

/// Bytes in one page of a memory (a JavaScript number: Infinity for an absurd page size).
pub fn page_size(limits: &Limits) -> f64 {
    let log2 = limits.page_size_log2.unwrap_or(16);
    if log2 > 1100 {
        f64::INFINITY
    } else {
        2f64.powi(log2 as i32)
    }
}
