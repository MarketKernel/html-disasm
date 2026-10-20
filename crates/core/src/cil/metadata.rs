//! The metadata of a .NET assembly (ECMA-335, Partition II), a port of the
//! TypeScript reader the page had: the CLI header a PE file's CLR data directory
//! points at, the metadata root and its streams — the tables (`#~`, or `#-`),
//! the string heaps, `#Blob` and `#GUID` — and the method bodies, with their
//! headers and exception-handling clauses.
//!
//! Every table is read whole into one array per column. Rows are numbered from
//! 1, as tokens number them; row 0 means none. Columns are named by constants
//! (`METHOD_DEF_NAME`: the table and the column's place in it).

/// Table numbers, as the top byte of a token has them.
pub mod table {
    pub const MODULE: u8 = 0x00;
    pub const TYPE_REF: u8 = 0x01;
    pub const TYPE_DEF: u8 = 0x02;
    pub const FIELD_PTR: u8 = 0x03;
    pub const FIELD: u8 = 0x04;
    pub const METHOD_PTR: u8 = 0x05;
    pub const METHOD_DEF: u8 = 0x06;
    pub const PARAM_PTR: u8 = 0x07;
    pub const PARAM: u8 = 0x08;
    pub const INTERFACE_IMPL: u8 = 0x09;
    pub const MEMBER_REF: u8 = 0x0a;
    pub const CONSTANT: u8 = 0x0b;
    pub const CUSTOM_ATTRIBUTE: u8 = 0x0c;
    pub const FIELD_MARSHAL: u8 = 0x0d;
    pub const DECL_SECURITY: u8 = 0x0e;
    pub const CLASS_LAYOUT: u8 = 0x0f;
    pub const FIELD_LAYOUT: u8 = 0x10;
    pub const STAND_ALONE_SIG: u8 = 0x11;
    pub const EVENT_MAP: u8 = 0x12;
    pub const EVENT_PTR: u8 = 0x13;
    pub const EVENT: u8 = 0x14;
    pub const PROPERTY_MAP: u8 = 0x15;
    pub const PROPERTY_PTR: u8 = 0x16;
    pub const PROPERTY: u8 = 0x17;
    pub const METHOD_SEMANTICS: u8 = 0x18;
    pub const METHOD_IMPL: u8 = 0x19;
    pub const MODULE_REF: u8 = 0x1a;
    pub const TYPE_SPEC: u8 = 0x1b;
    pub const IMPL_MAP: u8 = 0x1c;
    pub const FIELD_RVA: u8 = 0x1d;
    pub const ENC_LOG: u8 = 0x1e;
    pub const ENC_MAP: u8 = 0x1f;
    pub const ASSEMBLY: u8 = 0x20;
    pub const ASSEMBLY_PROCESSOR: u8 = 0x21;
    pub const ASSEMBLY_OS: u8 = 0x22;
    pub const ASSEMBLY_REF: u8 = 0x23;
    pub const ASSEMBLY_REF_PROCESSOR: u8 = 0x24;
    pub const ASSEMBLY_REF_OS: u8 = 0x25;
    pub const FILE: u8 = 0x26;
    pub const EXPORTED_TYPE: u8 = 0x27;
    pub const MANIFEST_RESOURCE: u8 = 0x28;
    pub const NESTED_CLASS: u8 = 0x29;
    pub const GENERIC_PARAM: u8 = 0x2a;
    pub const METHOD_SPEC: u8 = 0x2b;
    pub const GENERIC_PARAM_CONSTRAINT: u8 = 0x2c;
}

use table as t;

/// The name of a table, as ECMA-335 names it (`MethodDef`), by its number.
pub fn table_name(id: u8) -> Option<&'static str> {
    const NAMES: [&str; 45] = [
        "Module",
        "TypeRef",
        "TypeDef",
        "FieldPtr",
        "Field",
        "MethodPtr",
        "MethodDef",
        "ParamPtr",
        "Param",
        "InterfaceImpl",
        "MemberRef",
        "Constant",
        "CustomAttribute",
        "FieldMarshal",
        "DeclSecurity",
        "ClassLayout",
        "FieldLayout",
        "StandAloneSig",
        "EventMap",
        "EventPtr",
        "Event",
        "PropertyMap",
        "PropertyPtr",
        "Property",
        "MethodSemantics",
        "MethodImpl",
        "ModuleRef",
        "TypeSpec",
        "ImplMap",
        "FieldRVA",
        "ENCLog",
        "ENCMap",
        "Assembly",
        "AssemblyProcessor",
        "AssemblyOS",
        "AssemblyRef",
        "AssemblyRefProcessor",
        "AssemblyRefOS",
        "File",
        "ExportedType",
        "ManifestResource",
        "NestedClass",
        "GenericParam",
        "MethodSpec",
        "GenericParamConstraint",
    ];
    NAMES.get(id as usize).copied()
}

/// The token type of a #US string (ldstr).
pub const USER_STRING: u8 = 0x70;

/// A column of a table: the table, and the column's place in its row.
pub type Col = (u8, usize);

pub const TYPE_REF_SCOPE: Col = (t::TYPE_REF, 0);
pub const TYPE_REF_NAME: Col = (t::TYPE_REF, 1);
pub const TYPE_REF_NAMESPACE: Col = (t::TYPE_REF, 2);
pub const TYPE_DEF_FLAGS: Col = (t::TYPE_DEF, 0);
pub const TYPE_DEF_NAME: Col = (t::TYPE_DEF, 1);
pub const TYPE_DEF_NAMESPACE: Col = (t::TYPE_DEF, 2);
pub const TYPE_DEF_EXTENDS: Col = (t::TYPE_DEF, 3);
pub const TYPE_DEF_FIELD_LIST: Col = (t::TYPE_DEF, 4);
pub const TYPE_DEF_METHOD_LIST: Col = (t::TYPE_DEF, 5);
pub const FIELD_PTR_FIELD: Col = (t::FIELD_PTR, 0);
pub const FIELD_FLAGS: Col = (t::FIELD, 0);
pub const FIELD_NAME: Col = (t::FIELD, 1);
pub const FIELD_SIGNATURE: Col = (t::FIELD, 2);
pub const METHOD_PTR_METHOD: Col = (t::METHOD_PTR, 0);
pub const METHOD_DEF_RVA: Col = (t::METHOD_DEF, 0);
pub const METHOD_DEF_FLAGS: Col = (t::METHOD_DEF, 2);
pub const METHOD_DEF_NAME: Col = (t::METHOD_DEF, 3);
pub const METHOD_DEF_SIGNATURE: Col = (t::METHOD_DEF, 4);
pub const METHOD_DEF_PARAM_LIST: Col = (t::METHOD_DEF, 5);
pub const PARAM_PTR_PARAM: Col = (t::PARAM_PTR, 0);
pub const PARAM_SEQUENCE: Col = (t::PARAM, 1);
pub const PARAM_NAME: Col = (t::PARAM, 2);
pub const MEMBER_REF_CLASS: Col = (t::MEMBER_REF, 0);
pub const MEMBER_REF_NAME: Col = (t::MEMBER_REF, 1);
pub const MEMBER_REF_SIGNATURE: Col = (t::MEMBER_REF, 2);
pub const STAND_ALONE_SIG_SIGNATURE: Col = (t::STAND_ALONE_SIG, 0);
pub const MODULE_REF_NAME: Col = (t::MODULE_REF, 0);
pub const TYPE_SPEC_SIGNATURE: Col = (t::TYPE_SPEC, 0);
pub const IMPL_MAP_FLAGS: Col = (t::IMPL_MAP, 0);
pub const IMPL_MAP_MEMBER: Col = (t::IMPL_MAP, 1);
pub const IMPL_MAP_IMPORT_NAME: Col = (t::IMPL_MAP, 2);
pub const IMPL_MAP_IMPORT_SCOPE: Col = (t::IMPL_MAP, 3);
pub const ASSEMBLY_REF_NAME: Col = (t::ASSEMBLY_REF, 6);
pub const NESTED_CLASS_NESTED: Col = (t::NESTED_CLASS, 0);
pub const NESTED_CLASS_ENCLOSING: Col = (t::NESTED_CLASS, 1);
pub const GENERIC_PARAM_NUMBER: Col = (t::GENERIC_PARAM, 0);
pub const GENERIC_PARAM_OWNER: Col = (t::GENERIC_PARAM, 2);
pub const GENERIC_PARAM_NAME: Col = (t::GENERIC_PARAM, 3);
pub const METHOD_SPEC_METHOD: Col = (t::METHOD_SPEC, 0);
pub const METHOD_SPEC_INSTANTIATION: Col = (t::METHOD_SPEC, 1);

/// Coded indexes: the tables a column may point into, in the order of their tags (-1: a tag no table has).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Coded {
    TypeDefOrRef,
    HasConstant,
    HasCustomAttribute,
    HasFieldMarshal,
    HasDeclSecurity,
    MemberRefParent,
    HasSemantics,
    MethodDefOrRef,
    MemberForwarded,
    Implementation,
    CustomAttributeType,
    ResolutionScope,
    TypeOrMethodDef,
}

impl Coded {
    pub fn tables(self) -> &'static [i16] {
        match self {
            Coded::TypeDefOrRef => &[0x02, 0x01, 0x1b],
            Coded::HasConstant => &[0x04, 0x08, 0x17],
            Coded::HasCustomAttribute => &[0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0a, 0x00, 0x0e, 0x17, 0x14, 0x11, 0x1a, 0x1b, 0x20, 0x23, 0x26, 0x27, 0x28, 0x2a, 0x2c, 0x2b],
            Coded::HasFieldMarshal => &[0x04, 0x08],
            Coded::HasDeclSecurity => &[0x02, 0x06, 0x20],
            Coded::MemberRefParent => &[0x02, 0x01, 0x1a, 0x06, 0x1b],
            Coded::HasSemantics => &[0x14, 0x17],
            Coded::MethodDefOrRef => &[0x06, 0x0a],
            Coded::MemberForwarded => &[0x04, 0x06],
            Coded::Implementation => &[0x26, 0x23, 0x27],
            Coded::CustomAttributeType => &[-1, -1, 0x06, 0x0a, -1],
            Coded::ResolutionScope => &[0x00, 0x1a, 0x23, 0x01],
            Coded::TypeOrMethodDef => &[0x02, 0x06],
        }
    }

    /// Bits of the tag: `ceil(log2(tables))`.
    fn bits(self) -> u32 {
        let n = self.tables().len() as u32;
        32 - (n - 1).leading_zeros()
    }
}

/// A coded index split into its table (-1 for none) and row.
#[inline]
pub fn decode_index(kind: Coded, value: u32) -> (i16, u32) {
    let bits = kind.bits();
    let table = kind.tables().get((value & ((1 << bits) - 1)) as usize).copied().unwrap_or(-1);
    (table, value >> bits)
}

#[inline]
pub fn token(table: u8, row: u32) -> u32 {
    (table as u32) << 24 | row
}

#[inline]
pub fn token_table(tok: u32) -> u8 {
    (tok >> 24) as u8
}

#[inline]
pub fn token_row(tok: u32) -> u32 {
    tok & 0xff_ffff
}

#[derive(Clone, Copy)]
enum Column {
    Fixed(u8),
    Str,
    Guid,
    Blob,
    Index(u8),
    Coded(Coded),
}

fn schema(id: u8) -> Option<&'static [Column]> {
    use self::Coded as C;
    use Column::{Blob, Fixed, Guid, Index, Str};
    Some(match id {
        t::MODULE => &[Fixed(2), Str, Guid, Guid, Guid],
        t::TYPE_REF => &[Column::Coded(C::ResolutionScope), Str, Str],
        t::TYPE_DEF => &[Fixed(4), Str, Str, Column::Coded(C::TypeDefOrRef), Index(t::FIELD), Index(t::METHOD_DEF)],
        t::FIELD_PTR => &[Index(t::FIELD)],
        t::FIELD => &[Fixed(2), Str, Blob],
        t::METHOD_PTR => &[Index(t::METHOD_DEF)],
        t::METHOD_DEF => &[Fixed(4), Fixed(2), Fixed(2), Str, Blob, Index(t::PARAM)],
        t::PARAM_PTR => &[Index(t::PARAM)],
        t::PARAM => &[Fixed(2), Fixed(2), Str],
        t::INTERFACE_IMPL => &[Index(t::TYPE_DEF), Column::Coded(C::TypeDefOrRef)],
        t::MEMBER_REF => &[Column::Coded(C::MemberRefParent), Str, Blob],
        t::CONSTANT => &[Fixed(2), Column::Coded(C::HasConstant), Blob],
        t::CUSTOM_ATTRIBUTE => &[Column::Coded(C::HasCustomAttribute), Column::Coded(C::CustomAttributeType), Blob],
        t::FIELD_MARSHAL => &[Column::Coded(C::HasFieldMarshal), Blob],
        t::DECL_SECURITY => &[Fixed(2), Column::Coded(C::HasDeclSecurity), Blob],
        t::CLASS_LAYOUT => &[Fixed(2), Fixed(4), Index(t::TYPE_DEF)],
        t::FIELD_LAYOUT => &[Fixed(4), Index(t::FIELD)],
        t::STAND_ALONE_SIG => &[Blob],
        t::EVENT_MAP => &[Index(t::TYPE_DEF), Index(t::EVENT)],
        t::EVENT_PTR => &[Index(t::EVENT)],
        t::EVENT => &[Fixed(2), Str, Column::Coded(C::TypeDefOrRef)],
        t::PROPERTY_MAP => &[Index(t::TYPE_DEF), Index(t::PROPERTY)],
        t::PROPERTY_PTR => &[Index(t::PROPERTY)],
        t::PROPERTY => &[Fixed(2), Str, Blob],
        t::METHOD_SEMANTICS => &[Fixed(2), Index(t::METHOD_DEF), Column::Coded(C::HasSemantics)],
        t::METHOD_IMPL => &[Index(t::TYPE_DEF), Column::Coded(C::MethodDefOrRef), Column::Coded(C::MethodDefOrRef)],
        t::MODULE_REF => &[Str],
        t::TYPE_SPEC => &[Blob],
        t::IMPL_MAP => &[Fixed(2), Column::Coded(C::MemberForwarded), Str, Index(t::MODULE_REF)],
        t::FIELD_RVA => &[Fixed(4), Index(t::FIELD)],
        t::ENC_LOG => &[Fixed(4), Fixed(4)],
        t::ENC_MAP => &[Fixed(4)],
        t::ASSEMBLY => &[Fixed(4), Fixed(2), Fixed(2), Fixed(2), Fixed(2), Fixed(4), Blob, Str, Str],
        t::ASSEMBLY_PROCESSOR => &[Fixed(4)],
        t::ASSEMBLY_OS => &[Fixed(4), Fixed(4), Fixed(4)],
        t::ASSEMBLY_REF => &[Fixed(2), Fixed(2), Fixed(2), Fixed(2), Fixed(4), Blob, Str, Str, Blob],
        t::ASSEMBLY_REF_PROCESSOR => &[Fixed(4), Index(t::ASSEMBLY_REF)],
        t::ASSEMBLY_REF_OS => &[Fixed(4), Fixed(4), Fixed(4), Index(t::ASSEMBLY_REF)],
        t::FILE => &[Fixed(4), Str, Blob],
        t::EXPORTED_TYPE => &[Fixed(4), Fixed(4), Str, Str, Column::Coded(C::Implementation)],
        t::MANIFEST_RESOURCE => &[Fixed(4), Fixed(4), Str, Column::Coded(C::Implementation)],
        t::NESTED_CLASS => &[Index(t::TYPE_DEF), Index(t::TYPE_DEF)],
        t::GENERIC_PARAM => &[Fixed(2), Fixed(2), Column::Coded(C::TypeOrMethodDef), Str],
        t::METHOD_SPEC => &[Column::Coded(C::MethodDefOrRef), Blob],
        t::GENERIC_PARAM_CONSTRAINT => &[Index(t::GENERIC_PARAM), Column::Coded(C::TypeDefOrRef)],
        _ => return None,
    })
}

/// A table: its rows, one array per column; a coded index stays coded.
#[derive(Default)]
pub struct Table {
    pub rows: u32,
    pub columns: Vec<Vec<u32>>,
}

/// An exception-handling clause of a method body; offsets are in the method's IL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clause {
    /// 0 catch, 1 filter, 2 finally, 4 fault.
    pub kind: u32,
    pub try_start: u32,
    /// Where the protected block and the handler end: the start plus the length, as JavaScript adds them (past 2^32 in a damaged body).
    pub try_end: u64,
    pub handler_start: u32,
    pub handler_end: u64,
    pub class_token: u32,
    /// -1 when it is not a filter.
    pub filter_start: i64,
}

#[derive(Clone, Debug)]
pub struct MethodBody {
    /// The MethodDef row.
    pub method: u32,
    pub rva: u32,
    /// File offset of the header and of the first IL byte; the IL's length.
    pub offset: usize,
    pub code: usize,
    pub size: usize,
    pub header_size: u32,
    /// The fat header's fields (a tiny one: 8, no locals).
    pub max_stack: u32,
    /// The StandAloneSig token of its locals (0: none, as in a tiny header).
    pub locals_token: u32,
    pub init_locals: bool,
    pub fat: bool,
    pub clauses: Vec<Clause>,
}

/// An RVA and a size, as the CLI header's directories give them.
#[derive(Clone, Copy, Debug, Default)]
pub struct Directory {
    pub rva: u32,
    pub size: u32,
}

/// The CLI header.
#[derive(Clone, Debug, Default)]
pub struct CliHeader {
    /// The runtime version it asks for: `2.5`.
    pub runtime: String,
    pub flags: u32,
    /// A MethodDef token, or — with the native entry point flag — an RVA.
    pub entry_token: u32,
    pub metadata_rva: u32,
    pub metadata_size: u32,
    pub resources: Directory,
    pub strong_name: Directory,
    pub vtable_fixups: Directory,
    /// ReadyToRun: the header of the native code compiled ahead of time.
    pub managed_native: Directory,
}

/// The CLI header's flags, by their names in the standard.
pub const CLI_FLAGS: [(u32, &str); 7] = [
    (0x1, "ILONLY"),
    (0x2, "32BITREQUIRED"),
    (0x4, "IL_LIBRARY"),
    (0x8, "STRONGNAMESIGNED"),
    (0x10, "NATIVE_ENTRYPOINT"),
    (0x10000, "TRACKDEBUGDATA"),
    (0x20000, "32BITPREFERRED"),
];

/// A stream of the metadata: its name, file offset and size.
#[derive(Clone, Debug)]
pub struct Stream {
    pub name: String,
    pub offset: usize,
    pub size: u32,
}

/// A PE section, as the page read it: where its bytes are in memory and in the file.
#[derive(Clone, Copy, Debug)]
pub struct Section {
    pub rva: u32,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub raw_offset: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum MetadataError {
    /// The CLR directory, the metadata root or its signature is not there.
    NotFound,
    /// There is no `#~` or `#-` stream.
    NoTables,
}

/// The heap a blob or a string is read from, as a range of the file (`None`: the stream is missing).
type Heap = Option<(usize, usize)>;

pub struct Metadata {
    pub bytes: Vec<u8>,
    sections: Vec<Section>,
    pub header: CliHeader,
    /// The version string of the metadata root (`v4.0.30319`), and of the table schema (`2.0`).
    pub version: String,
    pub schema: String,
    pub streams: Vec<Stream>,
    /// What was not read: a table the standard does not have, a table cut short.
    pub warnings: Vec<String>,
    tables: Vec<Table>,
    strings: Heap,
    blobs: Heap,
    us: Heap,
    guids: Option<usize>,
}

#[inline]
fn u16_at(bytes: &[u8], at: usize) -> u32 {
    bytes.get(at..at + 2).map_or(0, |b| u16::from_le_bytes([b[0], b[1]]) as u32)
}

#[inline]
fn u32_at(bytes: &[u8], at: usize) -> u32 {
    bytes.get(at..at + 4).map_or(0, |b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// A compressed unsigned integer (II.23.2): its value and how many bytes it took (0 past the end).
#[inline]
pub fn compressed(bytes: &[u8], at: usize) -> (u32, usize) {
    let byte = |k: usize| bytes.get(at + k).copied().unwrap_or(0) as u32;
    let b = byte(0);
    if b & 0x80 == 0 {
        (b, 1)
    } else if b & 0xc0 == 0x80 {
        ((b & 0x3f) << 8 | byte(1), 2)
    } else if b & 0xe0 == 0xc0 {
        ((b & 0x1f) << 24 | byte(1) << 16 | byte(2) << 8 | byte(3), 4)
    } else {
        (0, 1)
    }
}

/// Text from UTF-8 as the page's TextDecoder makes it: a leading byte order mark dropped, bad bytes replaced.
pub fn utf8(bytes: &[u8]) -> String {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    String::from_utf8_lossy(bytes).into_owned()
}

impl Metadata {
    /// Reads the CLI header the CLR data directory (at `clr_rva`) points at, the metadata root,
    /// its streams and the tables.
    pub fn read(bytes: Vec<u8>, sections: Vec<Section>, clr_rva: Option<u32>) -> Result<Metadata, MetadataError> {
        let mut md = Metadata {
            bytes,
            sections,
            header: CliHeader::default(),
            version: String::new(),
            schema: String::new(),
            streams: Vec::new(),
            warnings: Vec::new(),
            tables: Vec::new(),
            strings: None,
            blobs: None,
            us: None,
            guids: None,
        };
        let at = clr_rva.and_then(|rva| md.offset_of(rva)).ok_or(MetadataError::NotFound)?;
        let pair = |o: usize| Directory { rva: md.u32(at + o), size: md.u32(at + o + 4) };
        md.header = CliHeader {
            runtime: format!("{}.{}", md.u16(at + 4), md.u16(at + 6)),
            metadata_rva: md.u32(at + 8),
            metadata_size: md.u32(at + 12),
            flags: md.u32(at + 16),
            entry_token: md.u32(at + 20),
            resources: pair(24),
            strong_name: pair(32),
            vtable_fixups: pair(48),
            managed_native: pair(64),
        };
        md.read_root()?;
        Ok(md)
    }

    /// Where an RVA's byte is in the file, or None.
    pub fn offset_of(&self, rva: u32) -> Option<usize> {
        let rva = rva as u64;
        for s in &self.sections {
            let size = s.virtual_size.max(s.raw_size) as u64;
            if rva >= s.rva as u64 && rva < s.rva as u64 + size {
                return (rva - (s.rva as u64) < s.raw_size as u64).then(|| s.raw_offset as usize + (rva - s.rva as u64) as usize);
            }
        }
        None
    }

    #[inline]
    pub fn u8(&self, at: usize) -> u32 {
        self.bytes.get(at).copied().unwrap_or(0) as u32
    }

    #[inline]
    pub fn u16(&self, at: usize) -> u32 {
        u16_at(&self.bytes, at)
    }

    #[inline]
    pub fn u32(&self, at: usize) -> u32 {
        u32_at(&self.bytes, at)
    }

    pub fn rows(&self, id: u8) -> u32 {
        self.tables.get(id as usize).map_or(0, |t| t.rows)
    }

    /// A column of a row (rows from 1); 0 for none.
    #[inline]
    pub fn get(&self, (id, column): Col, row: u32) -> u32 {
        match self.tables.get(id as usize) {
            Some(t) if row >= 1 && row <= t.rows => t.columns.get(column).map_or(0, |c| c[row as usize - 1]),
            _ => 0,
        }
    }

    /// A whole column (zeros for a table that is not there).
    pub fn column(&self, (id, column): Col) -> std::borrow::Cow<'_, [u32]> {
        match self.tables.get(id as usize).and_then(|t| t.columns.get(column)) {
            Some(c) => std::borrow::Cow::Borrowed(c),
            None => std::borrow::Cow::Owned(vec![0; self.rows(id) as usize]),
        }
    }

    /// The bytes of a name in #Strings (UTF-8, NUL-terminated).
    pub fn string_bytes(&self, index: u32) -> &[u8] {
        let Some((at, end)) = self.strings else { return &[] };
        if index == 0 {
            return &[];
        }
        let start = (at + index as usize).min(self.bytes.len());
        let stop = end.min(self.bytes.len()).max(start);
        let len = self.bytes[start..stop].iter().position(|&b| b == 0).unwrap_or(stop - start);
        &self.bytes[start..start + len]
    }

    /// A name from #Strings.
    pub fn string(&self, index: u32) -> String {
        utf8(self.string_bytes(index))
    }

    /// A blob: where its bytes are in the file (its length is a compressed integer before it).
    /// None when there is no #Blob or the index is past it — an empty blob of its own.
    pub fn blob_range(&self, index: u32) -> Option<(usize, usize)> {
        let (at, end) = self.blobs?;
        let at = at + index as usize;
        if at >= end {
            return None;
        }
        let (length, size) = compressed(&self.bytes, at);
        let file = self.bytes.len();
        let start = (at + size).min(file);
        let stop = (at + size + length as usize).min(end).min(file).max(start);
        Some((start, stop))
    }

    pub fn blob(&self, index: u32) -> &[u8] {
        self.blob_range(index).map_or(&[], |(start, stop)| &self.bytes[start..stop])
    }

    /// A GUID of #GUID (from 1), as the page writes it: `0F8FAD5B-D9CB-469F-A165-70867728950E`.
    pub fn guid(&self, index: u32) -> String {
        let Some(at) = self.guids else { return String::new() };
        if index == 0 {
            return String::new();
        }
        let at = at + (index as usize - 1) * 16;
        let Some(b) = self.bytes.get(at..at + 16) else { return String::new() };
        let hex = |part: &[u8], reverse: bool| -> String {
            let mut bytes = part.to_vec();
            if reverse {
                bytes.reverse();
            }
            bytes.iter().map(|x| format!("{x:02X}")).collect()
        };
        format!("{}-{}-{}-{}-{}", hex(&b[0..4], true), hex(&b[4..6], true), hex(&b[6..8], true), hex(&b[8..10], false), hex(&b[10..16], false))
    }

    /// Where #US is in the file.
    pub fn user_strings(&self) -> Heap {
        self.us
    }

    /// A user string (#US), as the UTF-16 units it holds; None past the heap or when it runs over its end.
    pub fn user_string(&self, index: u32) -> Option<Vec<u16>> {
        let (at, end) = self.us?;
        let at = at + index as usize;
        if at >= end {
            return None;
        }
        let (length, size) = compressed(&self.bytes, at);
        let start = at + size;
        let chars = ((length as i64 - 1) >> 1).max(0) as usize;
        if start + chars * 2 > end {
            return None;
        }
        Some((0..chars).map(|k| self.u16(start + k * 2) as u16).collect())
    }

    /// Every string of #US, in the order of the heap: its index and its text.
    pub fn user_string_list(&self) -> Vec<(u32, Vec<u16>)> {
        let mut out = Vec::new();
        let Some((at, end)) = self.us else { return out };
        let mut index = 1usize;
        while at + index < end {
            let (length, size) = compressed(&self.bytes, at + index);
            if length != 0 {
                out.push((index as u32, self.user_string(index as u32).unwrap_or_default()));
            }
            index += size + length as usize;
        }
        out
    }

    fn read_root(&mut self) -> Result<(), MetadataError> {
        let at = self.offset_of(self.header.metadata_rva).ok_or(MetadataError::NotFound)?;
        if self.u32(at) != 0x424a_5342 {
            return Err(MetadataError::NotFound);
        }
        let length = self.u32(at + 12) as usize;
        let start = (at + 16).min(self.bytes.len());
        let mut end = start;
        while end < (at + 16 + length).min(self.bytes.len()) && self.bytes[end] != 0 {
            end += 1;
        }
        self.version = utf8(&self.bytes[start..end]);
        let mut p = at + 16 + length;
        let count = self.u16(p + 2);
        p += 4;
        let mut tables_at = None;
        let mut tables_named = None;
        for _ in 0..count {
            let offset = self.u32(p) as usize;
            let size = self.u32(p + 4) as usize;
            let mut name_end = p + 8;
            while name_end < self.bytes.len() && self.bytes[name_end] != 0 && name_end - p < 40 {
                name_end += 1;
            }
            let name = utf8(&self.bytes[(p + 8).min(name_end)..name_end]);
            p = p + 8 + ((name_end - (p + 8) + 4) & !3);
            self.streams.push(Stream { name: name.clone(), offset: at + offset, size: size as u32 });
            let range = Some((at + offset, at + offset + size));
            // The first stream of each name counts, as the TypeScript's find() took it.
            match name.as_str() {
                "#Strings" if self.strings.is_none() => self.strings = range,
                "#Blob" if self.blobs.is_none() => self.blobs = range,
                "#US" if self.us.is_none() => self.us = range,
                "#GUID" if self.guids.is_none() => self.guids = Some(at + offset),
                "#~" if tables_at.is_none() => tables_at = Some(at + offset),
                "#-" if tables_named.is_none() => tables_named = Some(at + offset),
                _ => {}
            }
        }
        let tables = tables_at.or(tables_named).ok_or(MetadataError::NoTables)?;
        self.read_tables(tables);
        Ok(())
    }

    fn read_tables(&mut self, at: usize) {
        self.schema = format!("{}.{}", self.u8(at + 4), self.u8(at + 5));
        let heap_sizes = self.u8(at + 6);
        let valid = self.u32(at + 8) as u64 | (self.u32(at + 12) as u64) << 32;
        let mut p = at + 24;
        let mut counts = [0u32; 64];
        for (id, count) in counts.iter_mut().enumerate() {
            if valid >> id & 1 != 0 {
                *count = self.u32(p);
                p += 4;
            }
        }
        // Edit and Continue's uncompressed tables may carry four bytes more.
        if heap_sizes & 0x40 != 0 {
            p += 4;
        }
        let size_of = |column: Column| -> usize {
            match column {
                Column::Str => 2 + 2 * (heap_sizes & 1 != 0) as usize,
                Column::Guid => 2 + 2 * (heap_sizes & 2 != 0) as usize,
                Column::Blob => 2 + 2 * (heap_sizes & 4 != 0) as usize,
                Column::Fixed(n) => n as usize,
                Column::Index(id) => 2 + 2 * (counts[id as usize] >= 65536) as usize,
                Column::Coded(kind) => {
                    let max = kind.tables().iter().map(|&id| if id < 0 { 0 } else { counts[id as usize] }).max().unwrap_or(0);
                    2 + 2 * (max as u64 >= 1u64 << (16 - kind.bits())) as usize
                }
            }
        };
        for id in 0..64u8 {
            let rows = counts[id as usize];
            if rows == 0 {
                continue;
            }
            // Tables after the standard ones (a portable PDB's) come last: nothing that matters follows them.
            let Some(schema) = schema(id) else {
                self.warnings.push(format!("table 0x{id:x}: not in the standard"));
                break;
            };
            let sizes: Vec<usize> = schema.iter().map(|&c| size_of(c)).collect();
            let row_size: usize = sizes.iter().sum();
            if p + row_size * rows as usize > self.bytes.len() {
                self.warnings.push(format!("table {}: cut short", table_name(id).unwrap_or("undefined")));
                break;
            }
            let mut columns: Vec<Vec<u32>> = sizes.iter().map(|_| Vec::with_capacity(rows as usize)).collect();
            let mut q = p;
            for _ in 0..rows {
                for (c, &size) in sizes.iter().enumerate() {
                    let b = &self.bytes[q..q + size];
                    columns[c].push(match size {
                        1 => b[0] as u32,
                        2 => u16::from_le_bytes([b[0], b[1]]) as u32,
                        _ => u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
                    });
                    q += size;
                }
            }
            p += row_size * rows as usize;
            if self.tables.len() <= id as usize {
                self.tables.resize_with(id as usize + 1, Table::default);
            }
            self.tables[id as usize] = Table { rows, columns };
        }
    }

    /// The body of a method, from its RVA: the header, the IL, and the clauses after it.
    pub fn body(&self, method: u32) -> Option<MethodBody> {
        let rva = self.get(METHOD_DEF_RVA, method);
        if rva == 0 {
            return None;
        }
        let offset = self.offset_of(rva)?;
        let first = self.u8(offset);
        if first & 3 == 2 {
            return Some(MethodBody {
                method,
                rva,
                offset,
                code: offset + 1,
                size: (first >> 2) as usize,
                header_size: 1,
                max_stack: 8,
                locals_token: 0,
                init_locals: false,
                fat: false,
                clauses: Vec::new(),
            });
        }
        if first & 3 != 3 {
            return None;
        }
        let flags = self.u16(offset);
        let header_size = (flags >> 12) * 4;
        let size = self.u32(offset + 4) as usize;
        let code = offset + header_size as usize;
        if header_size < 12 || code + size > self.bytes.len() {
            return None;
        }
        let mut body = MethodBody {
            method,
            rva,
            offset,
            code,
            size,
            header_size,
            max_stack: self.u16(offset + 2),
            locals_token: self.u32(offset + 8),
            init_locals: flags & 0x10 != 0,
            fat: true,
            clauses: Vec::new(),
        };
        let mut more = flags & 0x08 != 0;
        let mut p = (code + size + 3) & !3;
        let mut guard = 0;
        while more && guard < 64 && p < self.bytes.len() {
            guard += 1;
            let kind = self.u8(p);
            let fat = kind & 0x40 != 0;
            let data_size = if fat { self.u8(p + 1) | self.u8(p + 2) << 8 | self.u8(p + 3) << 16 } else { self.u8(p + 1) };
            if kind & 0x01 != 0 {
                let clause_size = if fat { 24 } else { 12 };
                let n = (data_size as i64 - 4).div_euclid(clause_size);
                for k in 0..n.max(0) as usize {
                    let c = p + 4 + k * clause_size as usize;
                    let (flags, try_start, try_length, handler_start, handler_length, extra) = if fat {
                        (self.u32(c), self.u32(c + 4), self.u32(c + 8), self.u32(c + 12), self.u32(c + 16), self.u32(c + 20))
                    } else {
                        (self.u16(c), self.u16(c + 2), self.u8(c + 4), self.u8(c + 5) | self.u8(c + 6) << 8, self.u8(c + 7), self.u32(c + 8))
                    };
                    body.clauses.push(Clause {
                        kind: flags & 7,
                        try_start,
                        // JavaScript numbers: a sum past 2^32 stays as it is.
                        try_end: try_start as u64 + try_length as u64,
                        handler_start,
                        handler_end: handler_start as u64 + handler_length as u64,
                        class_token: if flags & 1 != 0 { 0 } else { extra },
                        filter_start: if flags & 1 != 0 { extra as i64 } else { -1 },
                    });
                }
            }
            more = kind & 0x80 != 0;
            p = (p + (data_size as usize).max(4) + 3) & !3;
        }
        Some(body)
    }

    /// The rows of a list a parent owns (its fields, methods, parameters): from its start to the next parent's.
    pub fn range(&self, column: Col, row: u32, target: u8) -> (u32, u32) {
        let start = self.get(column, row);
        let end = if row < self.rows(column.0) { self.get(column, row + 1) } else { self.rows(target) + 1 };
        (start, start.max(end))
    }
}
