//! Names and signatures of a .NET assembly written as ildasm writes them, a
//! port of src/core/cil/names.ts (whose comments explain ildasm's quirks):
//! `[System.Runtime]System.String` for a type another assembly defines,
//! `Outer/Inner` for a nested one, `class …<int32,string>` for a generic
//! instance, `instance void Owner::Name(int32, string)` for a method; a name
//! that is not an ILAsm identifier, or is one of its keywords, is quoted.

use super::metadata::{self as m, compressed, decode_index, table as t, token_row, token_table, Coded, Metadata};
use crate::refs::FxHashMap;

/// Where a signature is read: the class and method whose generic parameters it may name (rows; 0 for none).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GenericContext {
    pub ty: u32,
    pub method: u32,
}

pub const NO_CONTEXT: GenericContext = GenericContext { ty: 0, method: 0 };

/// The words of ILAsm (its opcodes, their aliases, and il_kywd.h), which a name must not be written as unquoted; sorted.
const KEYWORDS: &[&str] = &[
    "#define",
    "#else",
    "#endif",
    "#ifdef",
    "#ifndef",
    "#include",
    "#line",
    "#undef",
    "abstract",
    "add",
    "add.ovf",
    "add.ovf.un",
    "aggressiveinlining",
    "aggressiveoptimization",
    "algorithm",
    "alignment",
    "amd64",
    "and",
    "ansi",
    "any",
    "arglist",
    "arm",
    "arm64",
    "array",
    "as",
    "assembly",
    "assert",
    "async",
    "at",
    "auto",
    "autochar",
    "beforefieldinit",
    "beq",
    "beq.s",
    "bestfit",
    "bge",
    "bge.s",
    "bge.un",
    "bge.un.s",
    "bgt",
    "bgt.s",
    "bgt.un",
    "bgt.un.s",
    "ble",
    "ble.s",
    "ble.un",
    "ble.un.s",
    "blob",
    "blob_object",
    "blt",
    "blt.s",
    "blt.un",
    "blt.un.s",
    "bne.un",
    "bne.un.s",
    "bool",
    "box",
    "br",
    "br.s",
    "break",
    "brfalse",
    "brfalse.s",
    "brinst",
    "brinst.s",
    "brnull",
    "brnull.s",
    "brtrue",
    "brtrue.s",
    "brzero",
    "brzero.s",
    "bstr",
    "byreflike",
    "bytearray",
    "byvalstr",
    "call",
    "callconv",
    "calli",
    "callmostderived",
    "callvirt",
    "carray",
    "castclass",
    "catch",
    "cdecl",
    "ceq",
    "cf",
    "cgt",
    "cgt.un",
    "char",
    "charmaperror",
    "cil",
    "ckfinite",
    "class",
    "clsid",
    "clt",
    "clt.un",
    "codelabel",
    "constrained.",
    "constraint",
    "conv.i",
    "conv.i1",
    "conv.i2",
    "conv.i4",
    "conv.i8",
    "conv.ovf.i",
    "conv.ovf.i.un",
    "conv.ovf.i1",
    "conv.ovf.i1.un",
    "conv.ovf.i2",
    "conv.ovf.i2.un",
    "conv.ovf.i4",
    "conv.ovf.i4.un",
    "conv.ovf.i8",
    "conv.ovf.i8.un",
    "conv.ovf.u",
    "conv.ovf.u.un",
    "conv.ovf.u1",
    "conv.ovf.u1.un",
    "conv.ovf.u2",
    "conv.ovf.u2.un",
    "conv.ovf.u4",
    "conv.ovf.u4.un",
    "conv.ovf.u8",
    "conv.ovf.u8.un",
    "conv.r.un",
    "conv.r4",
    "conv.r8",
    "conv.u",
    "conv.u1",
    "conv.u2",
    "conv.u4",
    "conv.u8",
    "cpblk",
    "cpobj",
    "currency",
    "custom",
    "date",
    "decimal",
    "default",
    "demand",
    "deny",
    "div",
    "div.un",
    "dup",
    "endfault",
    "endfilter",
    "endfinally",
    "endmac",
    "enum",
    "error",
    "explicit",
    "extends",
    "extern",
    "false",
    "famandassem",
    "family",
    "famorassem",
    "fastcall",
    "fault",
    "field",
    "filetime",
    "filter",
    "final",
    "finally",
    "fixed",
    "flags",
    "float",
    "float32",
    "float64",
    "forwarder",
    "forwardref",
    "fromunmanaged",
    "handler",
    "hidebysig",
    "hresult",
    "idispatch",
    "iidparam",
    "il",
    "illegal",
    "implements",
    "import",
    "in",
    "inheritcheck",
    "init",
    "initblk",
    "initobj",
    "initonly",
    "instance",
    "int",
    "int16",
    "int32",
    "int64",
    "int8",
    "interface",
    "internalcall",
    "isinst",
    "iunknown",
    "jmp",
    "lasterr",
    "ldarg",
    "ldarg.0",
    "ldarg.1",
    "ldarg.2",
    "ldarg.3",
    "ldarg.s",
    "ldarga",
    "ldarga.s",
    "ldc.i4",
    "ldc.i4.0",
    "ldc.i4.1",
    "ldc.i4.2",
    "ldc.i4.3",
    "ldc.i4.4",
    "ldc.i4.5",
    "ldc.i4.6",
    "ldc.i4.7",
    "ldc.i4.8",
    "ldc.i4.M1",
    "ldc.i4.m1",
    "ldc.i4.s",
    "ldc.i8",
    "ldc.r4",
    "ldc.r8",
    "ldelem",
    "ldelem.any",
    "ldelem.i",
    "ldelem.i1",
    "ldelem.i2",
    "ldelem.i4",
    "ldelem.i8",
    "ldelem.r4",
    "ldelem.r8",
    "ldelem.ref",
    "ldelem.u1",
    "ldelem.u2",
    "ldelem.u4",
    "ldelem.u8",
    "ldelema",
    "ldfld",
    "ldflda",
    "ldftn",
    "ldind.i",
    "ldind.i1",
    "ldind.i2",
    "ldind.i4",
    "ldind.i8",
    "ldind.r4",
    "ldind.r8",
    "ldind.ref",
    "ldind.u1",
    "ldind.u2",
    "ldind.u4",
    "ldind.u8",
    "ldlen",
    "ldloc",
    "ldloc.0",
    "ldloc.1",
    "ldloc.2",
    "ldloc.3",
    "ldloc.s",
    "ldloca",
    "ldloca.s",
    "ldnull",
    "ldobj",
    "ldsfld",
    "ldsflda",
    "ldstr",
    "ldtoken",
    "ldvirtftn",
    "leave",
    "leave.s",
    "legacy",
    "library",
    "linkcheck",
    "literal",
    "localloc",
    "lpstr",
    "lpstruct",
    "lptstr",
    "lpvoid",
    "lpwstr",
    "managed",
    "marshal",
    "mdtoken",
    "method",
    "mkrefany",
    "modopt",
    "modreq",
    "mul",
    "mul.ovf",
    "mul.ovf.un",
    "native",
    "neg",
    "nested",
    "newarr",
    "newobj",
    "newslot",
    "noinlining",
    "nomangle",
    "nometadata",
    "noncasdemand",
    "noncasinheritance",
    "noncaslinkdemand",
    "nooptimization",
    "nop",
    "noplatform",
    "not",
    "notserialized",
    "null",
    "nullref",
    "object",
    "objectref",
    "off",
    "on",
    "opt",
    "optil",
    "or",
    "out",
    "permitonly",
    "pinned",
    "pinvokeimpl",
    "pop",
    "prefix1",
    "prefix2",
    "prefix3",
    "prefix4",
    "prefix5",
    "prefix6",
    "prefix7",
    "prefixref",
    "prejitdeny",
    "prejitgrant",
    "preservesig",
    "private",
    "privatescope",
    "property",
    "public",
    "readonly.",
    "record",
    "refany",
    "refanytype",
    "refanyval",
    "rem",
    "rem.un",
    "reqmin",
    "reqopt",
    "reqrefuse",
    "reqsecobj",
    "request",
    "ret",
    "retainappdomain",
    "retargetable",
    "rethrow",
    "rtspecialname",
    "runtime",
    "safearray",
    "sealed",
    "sequential",
    "serializable",
    "shl",
    "shr",
    "shr.un",
    "sizeof",
    "specialname",
    "starg",
    "starg.s",
    "static",
    "stdcall",
    "stelem",
    "stelem.any",
    "stelem.i",
    "stelem.i1",
    "stelem.i2",
    "stelem.i4",
    "stelem.i8",
    "stelem.r4",
    "stelem.r8",
    "stelem.ref",
    "stfld",
    "stind.i",
    "stind.i1",
    "stind.i2",
    "stind.i4",
    "stind.i8",
    "stind.r4",
    "stind.r8",
    "stind.ref",
    "stloc",
    "stloc.0",
    "stloc.1",
    "stloc.2",
    "stloc.3",
    "stloc.s",
    "stobj",
    "storage",
    "stored_object",
    "stream",
    "streamed_object",
    "strict",
    "string",
    "struct",
    "stsfld",
    "sub",
    "sub.ovf",
    "sub.ovf.un",
    "switch",
    "synchronized",
    "syschar",
    "sysstring",
    "tail.",
    "tbstr",
    "thiscall",
    "throw",
    "tls",
    "to",
    "true",
    "type",
    "typedref",
    "uint",
    "uint16",
    "uint32",
    "uint64",
    "uint8",
    "unaligned.",
    "unbox",
    "unbox.any",
    "unicode",
    "unmanaged",
    "unmanagedexp",
    "unsigned",
    "unused",
    "userdefined",
    "value",
    "valuetype",
    "vararg",
    "variant",
    "vector",
    "virtual",
    "void",
    "volatile.",
    "wchar",
    "winapi",
    "windowsruntime",
    "with",
    "x86",
    "xor",
];

#[inline]
fn letter(c: u8) -> bool {
    c.is_ascii_alphabetic()
}

/// A name may start with a letter or one of `#_@$.`, and go on with those (but `#`), digits, `?` and `\``.
#[inline]
fn start(c: u8) -> bool {
    letter(c) || matches!(c, b'#' | b'_' | b'@' | b'$' | b'.')
}

#[inline]
fn cont(c: u8) -> bool {
    letter(c) || c.is_ascii_digit() || matches!(c, b'_' | b'@' | b'$' | b'.' | b'?' | b'`')
}

/// Does a name need quotes to be read back by ILAsm (ildasm's IsNameToQuote)?
pub fn needs_quotes(name: &str) -> bool {
    let b = name.as_bytes();
    if b.is_empty() {
        return true;
    }
    let mut starting = true;
    for k in 0..b.len() {
        // A byte of a character beyond ASCII is neither, as its UTF-16 unit is not.
        let c = b[k];
        if if starting { !start(c) } else { !cont(c) } {
            return true;
        }
        starting = c == b'.';
        if starting && b.get(k + 1) == Some(&b'.') {
            return true;
        }
    }
    if name == ".ctor" || name == ".cctor" {
        return false;
    }
    KEYWORDS.binary_search(&name).is_ok() || name.starts_with('.') || name.ends_with('.')
}

fn escape_name(name: &str, out: &mut String) {
    if !name.bytes().any(|b| matches!(b, b'\t' | b'\n' | 8 | b'\r' | 12 | 11 | 7 | b'\\' | b'\'' | b'"')) {
        out.push_str(name);
        return;
    }
    for c in name.chars() {
        match c {
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{8}' => out.push_str("\\b"),
            '\r' => out.push_str("\\r"),
            '\u{c}' => out.push_str("\\f"),
            '\u{b}' => out.push_str("\\v"),
            '\u{7}' => out.push_str("\\a"),
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            '"' => out.push_str("\\\""),
            c => out.push(c),
        }
    }
}

/// A name as ildasm writes it, onto `out`: escaped, and quoted when it must be. An empty name is written as nothing.
pub fn proper_name_into(name: &str, out: &mut String) {
    if name.is_empty() {
        return;
    }
    let quote = needs_quotes(name);
    if quote {
        out.push('\'');
    }
    escape_name(name, out);
    if quote {
        out.push('\'');
    }
}

/// A parameter's or a local's name: quoted also when it has a dot after its first character.
pub fn proper_local_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 2);
    if name.is_empty() {
        return out;
    }
    let quote = needs_quotes(name) || name.chars().skip(1).any(|c| c == '.');
    if quote {
        out.push('\'');
    }
    escape_name(name, &mut out);
    if quote {
        out.push('\'');
    }
    out
}

/// A name as ildasm writes it: escaped, and quoted when it must be. An empty name is written as nothing.
pub fn proper_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 2);
    proper_name_into(name, &mut out);
    out
}

fn primitive(et: u8) -> Option<&'static str> {
    Some(match et {
        0x01 => "void",
        0x02 => "bool",
        0x03 => "char",
        0x04 => "int8",
        0x05 => "uint8",
        0x06 => "int16",
        0x07 => "uint16",
        0x08 => "int32",
        0x09 => "uint32",
        0x0a => "int64",
        0x0b => "uint64",
        0x0c => "float32",
        0x0d => "float64",
        0x0e => "string",
        0x16 => "typedref",
        0x18 => "native int",
        0x19 => "native uint",
        0x1c => "object",
        _ => return None,
    })
}

/// A cursor over a signature blob, which lies in the file at `start..end` (None: a blob of its own, empty).
pub struct SigReader<'a> {
    file: &'a [u8],
    bytes: &'a [u8],
    start: Option<usize>,
    pub pos: usize,
}

impl<'a> SigReader<'a> {
    pub fn new(file: &'a [u8], range: Option<(usize, usize)>) -> Self {
        let bytes = range.map_or(&[][..], |(s, e)| &file[s..e]);
        SigReader { file, bytes, start: range.map(|r| r.0), pos: 0 }
    }

    pub fn of_blob(md: &'a Metadata, index: u32) -> Self {
        Self::new(&md.bytes, md.blob_range(index))
    }

    #[inline]
    pub fn done(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    #[inline]
    pub fn byte(&mut self) -> u8 {
        let b = self.bytes.get(self.pos).copied().unwrap_or(0);
        self.pos += 1;
        b
    }

    #[inline]
    pub fn peek(&self) -> u8 {
        self.bytes.get(self.pos).copied().unwrap_or(0)
    }

    /// The next byte even past the end of the blob, in the heap that holds it (0 past the file).
    pub fn peek_past(&self) -> u8 {
        if self.pos < self.bytes.len() {
            return self.bytes[self.pos];
        }
        self.start.and_then(|s| self.file.get(s + self.pos)).copied().unwrap_or(0)
    }

    pub fn u(&mut self) -> u32 {
        let (value, size) = compressed(self.bytes, self.pos);
        self.pos += size;
        value
    }

    /// A signed compressed integer (II.23.2): the sign is the lowest bit, rotated.
    pub fn s(&mut self) -> i64 {
        let first = self.peek();
        let value = self.u() as i64;
        let bits = if first & 0x80 == 0 {
            7
        } else if first & 0xc0 == 0x80 {
            14
        } else {
            29
        };
        if value & 1 != 0 {
            (value >> 1) - (1i64 << (bits - 1))
        } else {
            value >> 1
        }
    }
}

/// A method signature as it is in the blob.
#[derive(Clone, Debug, Default)]
pub struct MethodSig {
    pub conv: u8,
    pub generics: u32,
    pub ret: String,
    pub params: Vec<String>,
}

/// The calling convention as ildasm writes it before the return type.
pub fn conv_text(conv: u8, out: &mut String) {
    if conv & 0x40 != 0 {
        out.push_str("explicit ");
    }
    if conv & 0x20 != 0 {
        out.push_str("instance ");
    }
    match conv & 0x0f {
        0 => {}
        1 => out.push_str("unmanaged cdecl "),
        2 => out.push_str("unmanaged stdcall "),
        3 => out.push_str("unmanaged thiscall "),
        4 => out.push_str("unmanaged fastcall "),
        5 => out.push_str("vararg "),
        9 => out.push_str("unmanaged "),
        kind => {
            out.push_str("callconv(");
            out.push_str(&kind.to_string());
            out.push_str(") ");
        }
    }
}

/// ildasm's SplitSignatureByCommas (see src/core/cil/names.ts): from `start`, every comma with no
/// bracket, quote, parenthesis (beyond the list's own) or angle bracket open since the start of its
/// line starts a new line, written `, `; one that does not stays `,`.
pub fn split_commas(text: &str, start: usize) -> String {
    let b = text.as_bytes();
    if start >= b.len() {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len() + 8);
    let mut line_start = 0;
    let mut from = 0;
    let next = |from: usize| b[from.min(b.len())..].iter().position(|&c| c == b',').map(|k| k + from);
    let mut pos = next(start);
    while let Some(p) = pos {
        let (mut brackets, mut quote, mut parens, mut angles) = (0i64, 0, 0i64, 0i64);
        for &c in &b[line_start..p] {
            if c == b'\'' {
                quote = 1 - quote;
            } else if quote == 0 {
                match c {
                    b'[' => brackets += 1,
                    b']' => brackets -= 1,
                    b'(' => parens += 1,
                    b')' => parens -= 1,
                    b'<' => angles += 1,
                    b'>' => angles -= 1,
                    _ => {}
                }
            }
        }
        if brackets == 0 && quote == 0 && (0..=1).contains(&parens) && angles == 0 {
            out.push_str(&text[from..p]);
            out.push_str(", ");
            from = p + 1;
            line_start = p + 1;
        }
        pos = next(p + 1);
    }
    out.push_str(&text[from..]);
    out
}

/// `0x1A`-style: a number in upper-case hex.
fn hex_upper(n: u32) -> String {
    format!("{n:X}")
}

/// What Names has worked out, apart from the metadata it reads: kept between uses
/// (`Names::into_parts`, `Names::from_parts`) by what outlives a borrow of the metadata.
#[derive(Default)]
pub struct NamesParts {
    enclosing: FxHashMap<u32, u32>,
    method_owner: Vec<u32>,
    field_owner: Vec<u32>,
    generic_types: FxHashMap<u32, Vec<Option<String>>>,
    generic_methods: FxHashMap<u32, Vec<Option<String>>>,
    type_def_cache: FxHashMap<u32, String>,
    type_ref_cache: FxHashMap<u32, String>,
    type_spec_cache: FxHashMap<u32, String>,
}

pub struct Names<'a> {
    pub md: &'a Metadata,
    /// TypeDef row → the TypeDef it is nested in.
    pub enclosing: FxHashMap<u32, u32>,
    /// MethodDef row → its TypeDef row; Field row → its TypeDef row.
    pub method_owner: Vec<u32>,
    pub field_owner: Vec<u32>,
    /// Generic parameter names by number (None: a number no parameter has), by owner row.
    generic_types: FxHashMap<u32, Vec<Option<String>>>,
    generic_methods: FxHashMap<u32, Vec<Option<String>>>,
    type_def_cache: FxHashMap<u32, String>,
    type_ref_cache: FxHashMap<u32, String>,
    /// TypeSpecs read with no generic context (the imports' classes): the same text each time.
    type_spec_cache: FxHashMap<u32, String>,
}

impl<'a> Names<'a> {
    pub fn new(md: &'a Metadata) -> Self {
        let mut enclosing = FxHashMap::default();
        for r in 1..=md.rows(t::NESTED_CLASS) {
            enclosing.insert(md.get(m::NESTED_CLASS_NESTED, r), md.get(m::NESTED_CLASS_ENCLOSING, r));
        }
        let method_owner = owners(md, t::METHOD_DEF, m::TYPE_DEF_METHOD_LIST, t::METHOD_PTR, m::METHOD_PTR_METHOD);
        let field_owner = owners(md, t::FIELD, m::TYPE_DEF_FIELD_LIST, t::FIELD_PTR, m::FIELD_PTR_FIELD);
        let mut generic_types: FxHashMap<u32, Vec<Option<String>>> = FxHashMap::default();
        let mut generic_methods: FxHashMap<u32, Vec<Option<String>>> = FxHashMap::default();
        for r in 1..=md.rows(t::GENERIC_PARAM) {
            let (table, row) = decode_index(Coded::TypeOrMethodDef, md.get(m::GENERIC_PARAM_OWNER, r));
            let map = if table == t::TYPE_DEF as i16 { &mut generic_types } else { &mut generic_methods };
            let list = map.entry(row).or_default();
            let number = md.get(m::GENERIC_PARAM_NUMBER, r) as usize;
            if list.len() <= number {
                list.resize(number + 1, None);
            }
            list[number] = Some(md.string(md.get(m::GENERIC_PARAM_NAME, r)));
        }
        Names {
            md,
            enclosing,
            method_owner,
            field_owner,
            generic_types,
            generic_methods,
            type_def_cache: FxHashMap::default(),
            type_ref_cache: FxHashMap::default(),
            type_spec_cache: FxHashMap::default(),
        }
    }

    /// Everything but the metadata, to be put together again with it by `from_parts`.
    pub fn into_parts(self) -> NamesParts {
        NamesParts {
            enclosing: self.enclosing,
            method_owner: self.method_owner,
            field_owner: self.field_owner,
            generic_types: self.generic_types,
            generic_methods: self.generic_methods,
            type_def_cache: self.type_def_cache,
            type_ref_cache: self.type_ref_cache,
            type_spec_cache: self.type_spec_cache,
        }
    }

    /// Names over `md` again, from what `into_parts` kept of them (over the same metadata).
    pub fn from_parts(md: &'a Metadata, parts: NamesParts) -> Self {
        Names {
            md,
            enclosing: parts.enclosing,
            method_owner: parts.method_owner,
            field_owner: parts.field_owner,
            generic_types: parts.generic_types,
            generic_methods: parts.generic_methods,
            type_def_cache: parts.type_def_cache,
            type_ref_cache: parts.type_ref_cache,
            type_spec_cache: parts.type_spec_cache,
        }
    }

    #[inline]
    pub fn method_owner(&self, row: u32) -> u32 {
        self.method_owner.get(row as usize).copied().unwrap_or(0)
    }

    /// The generic parameters of a type (`method` false) or a method, by row.
    pub fn generic_params(&self, method: bool, row: u32) -> &[Option<String>] {
        let map = if method { &self.generic_methods } else { &self.generic_types };
        map.get(&row).map_or(&[], |v| v.as_slice())
    }

    /* ---------------- types ---------------- */

    /// A type this assembly defines: `Ns.Name`, `Ns.Outer/Inner`.
    pub fn type_def(&mut self, row: u32) -> String {
        self.type_def_at(row, 0)
    }

    fn type_def_at(&mut self, row: u32, depth: u32) -> String {
        if let Some(cached) = self.type_def_cache.get(&row) {
            return cached.clone();
        }
        let md = self.md;
        let ns = md.string(md.get(m::TYPE_DEF_NAMESPACE, row));
        let mut name = md.string(md.get(m::TYPE_DEF_NAME, row));
        if name.is_empty() {
            name = format!("$TD${}", hex_upper(row));
        }
        let mut text = String::new();
        if !ns.is_empty() {
            text.push_str(&proper_name(&ns));
            text.push('.');
        }
        text.push_str(&proper_name(&name));
        if let Some(&outer) = self.enclosing.get(&row) {
            if outer != 0 && outer != row && depth < 64 {
                text = format!("{}/{text}", self.type_def_at(outer, depth + 1));
            }
        }
        self.type_def_cache.insert(row, text.clone());
        text
    }

    /// A type another assembly or module defines: `[System.Runtime]System.Object`.
    pub fn type_ref(&mut self, row: u32) -> String {
        self.type_ref_at(row, 0)
    }

    fn type_ref_at(&mut self, row: u32, depth: u32) -> String {
        if let Some(cached) = self.type_ref_cache.get(&row) {
            return cached.clone();
        }
        let md = self.md;
        let ns = md.string(md.get(m::TYPE_REF_NAMESPACE, row));
        let mut name = md.string(md.get(m::TYPE_REF_NAME, row));
        if name.is_empty() {
            name = format!("$TR${}", hex_upper(row));
        }
        let coded = md.get(m::TYPE_REF_SCOPE, row);
        let (table, scope) = decode_index(Coded::ResolutionScope, coded);
        let mut text = String::new();
        if coded == 0 {
            text.push_str("[*]");
        } else if scope != 0 {
            if table == t::TYPE_REF as i16 {
                if depth < 64 {
                    text.push_str(&self.type_ref_at(scope, depth + 1));
                    text.push('/');
                }
            } else if table == t::ASSEMBLY_REF as i16 {
                let assembly = md.string(md.get(m::ASSEMBLY_REF_NAME, scope));
                if !assembly.is_empty() {
                    text.push('[');
                    text.push_str(&proper_name(&assembly));
                    text.push(']');
                }
            } else if table == t::MODULE_REF as i16 {
                let module = md.string(md.get(m::MODULE_REF_NAME, scope));
                if !module.is_empty() {
                    text.push_str("[.module ");
                    text.push_str(&proper_name(&module));
                    text.push(']');
                }
            }
        }
        if !ns.is_empty() {
            text.push_str(&proper_name(&ns));
            text.push('.');
        }
        text.push_str(&proper_name(&name));
        self.type_ref_cache.insert(row, text.clone());
        text
    }

    /// The assembly a TypeRef comes from (following nesting), or '' for this one.
    pub fn type_ref_assembly(&self, mut row: u32) -> String {
        let md = self.md;
        for _ in 0..32 {
            if row == 0 {
                break;
            }
            let (table, scope) = decode_index(Coded::ResolutionScope, md.get(m::TYPE_REF_SCOPE, row));
            if table == t::ASSEMBLY_REF as i16 {
                return md.string(md.get(m::ASSEMBLY_REF_NAME, scope));
            }
            if table == t::MODULE_REF as i16 {
                return md.string(md.get(m::MODULE_REF_NAME, scope));
            }
            if table != t::TYPE_REF as i16 {
                return String::new();
            }
            row = scope;
        }
        String::new()
    }

    pub fn type_spec(&mut self, row: u32, ctx: GenericContext) -> String {
        if ctx == NO_CONTEXT {
            if let Some(text) = self.type_spec_cache.get(&row) {
                return text.clone();
            }
        }
        let md = self.md;
        let mut r = SigReader::of_blob(md, md.get(m::TYPE_SPEC_SIGNATURE, row));
        let text = self.sig_type(&mut r, ctx, 0);
        if ctx == NO_CONTEXT {
            self.type_spec_cache.insert(row, text.clone());
        }
        text
    }

    /// Is a TypeSpec a generic instance (through pointers, arrays and references)? ildasm's IsGenericInst.
    pub fn is_generic_inst(&self, row: u32) -> bool {
        for &b in self.md.blob(self.md.get(m::TYPE_SPEC_SIGNATURE, row)) {
            if matches!(b, 0x0f | 0x1d | 0x14 | 0x10) {
                continue;
            }
            return b == 0x15;
        }
        false
    }

    /// A type this assembly defines, onto `out`.
    fn type_def_into(&mut self, row: u32, out: &mut String) {
        match self.type_def_cache.get(&row) {
            Some(text) => out.push_str(text),
            None => out.push_str(&self.type_def_at(row, 0)),
        }
    }

    /// A type another assembly or module defines, onto `out`.
    fn type_ref_into(&mut self, row: u32, out: &mut String) {
        match self.type_ref_cache.get(&row) {
            Some(text) => out.push_str(text),
            None => out.push_str(&self.type_ref_at(row, 0)),
        }
    }

    /// A TypeDefOrRefOrSpecEncoded token in a signature, onto `out`.
    fn encoded_type_into(&mut self, r: &mut SigReader, ctx: GenericContext, depth: u32, out: &mut String) {
        let value = r.u();
        let row = value >> 2;
        match value & 3 {
            0 => self.type_def_into(row, out),
            1 => self.type_ref_into(row, out),
            2 if depth < 32 => {
                let md = self.md;
                let mut inner = SigReader::of_blob(md, md.get(m::TYPE_SPEC_SIGNATURE, row));
                self.sig_type_into(&mut inner, ctx, depth + 1, out);
            }
            _ => out.push('?'),
        }
    }

    /// `T` for generic parameter `number` of the owner, unless the owner has no such parameter or two of that name (ildasm's PrettyPrintGP).
    fn generic_name_into(&self, method: bool, number: u32, ctx: GenericContext, out: &mut String) {
        let owner = if method { ctx.method } else { ctx.ty };
        if owner != 0 {
            let names = self.generic_params(method, owner);
            if let Some(Some(name)) = names.get(number as usize) {
                let first = names.iter().position(|n| n.as_ref() == Some(name));
                let last = names.iter().rposition(|n| n.as_ref() == Some(name));
                if first == Some(number as usize) && last == Some(number as usize) {
                    proper_name_into(name, out);
                    return;
                }
            }
        }
        out.push_str(&number.to_string());
    }

    /// A type in a signature (II.23.2.12), as ildasm prints it.
    pub fn sig_type(&mut self, r: &mut SigReader, ctx: GenericContext, depth: u32) -> String {
        let mut out = String::new();
        self.sig_type_into(r, ctx, depth, &mut out);
        out
    }

    /// The same, onto `out`.
    pub fn sig_type_into(&mut self, r: &mut SigReader, ctx: GenericContext, depth: u32, out: &mut String) {
        if depth > 64 || r.done() {
            out.push('?');
            return;
        }
        let et = r.byte();
        if let Some(p) = primitive(et) {
            out.push_str(p);
            return;
        }
        match et {
            0x0f => {
                self.sig_type_into(r, ctx, depth + 1, out);
                out.push('*');
            }
            0x10 => {
                self.sig_type_into(r, ctx, depth + 1, out);
                out.push('&');
            }
            0x11 => {
                out.push_str("valuetype ");
                self.encoded_type_into(r, ctx, depth, out);
            }
            0x12 => {
                out.push_str("class ");
                self.encoded_type_into(r, ctx, depth, out);
            }
            0x13 => {
                let n = r.u();
                out.push('!');
                self.generic_name_into(false, n, ctx, out);
            }
            0x1e => {
                let n = r.u();
                out.push_str("!!");
                self.generic_name_into(true, n, ctx, out);
            }
            0x1d => {
                self.sig_type_into(r, ctx, depth + 1, out);
                out.push_str("[]");
            }
            0x14 => {
                self.sig_type_into(r, ctx, depth + 1, out);
                let rank = r.u();
                let mut sizes: Vec<i64> = Vec::new();
                let mut k = r.u();
                while k > 0 && !r.done() {
                    sizes.push(r.u() as i64);
                    k -= 1;
                }
                let mut lower: Vec<i64> = Vec::new();
                let mut k = r.u();
                while k > 0 && !r.done() {
                    lower.push(r.s());
                    k -= 1;
                }
                if rank == 0 {
                    out.push_str("[BAD: RANK == 0!]");
                    return;
                }
                if rank == 1 && sizes.is_empty() && lower.is_empty() {
                    out.push_str("[...]");
                    return;
                }
                out.push('[');
                for i in 0..rank as usize {
                    if i > 0 {
                        out.push(',');
                    }
                    let lo = lower.get(i).copied().unwrap_or(0);
                    if lo == 0 && i < sizes.len() {
                        out.push_str(&sizes[i].to_string());
                    } else if i < lower.len() {
                        out.push_str(&lo.to_string());
                        out.push_str("...");
                        if i < sizes.len() {
                            out.push_str(&(lo + sizes[i] - 1).to_string());
                        }
                    }
                }
                out.push(']');
            }
            0x15 => {
                self.sig_type_into(r, ctx, depth + 1, out);
                out.push('<');
                let mut k = r.u();
                let mut first = true;
                while k > 0 && !r.done() {
                    if !first {
                        out.push(',');
                    }
                    first = false;
                    self.sig_type_into(r, ctx, depth + 1, out);
                    k -= 1;
                }
                out.push('>');
            }
            0x1b => {
                let sig = self.method_sig(r, ctx, depth + 1, true);
                out.push_str("method ");
                conv_text(sig.conv, out);
                out.push_str(&sig.ret);
                out.push_str(" *(");
                out.push_str(&sig.params.join(","));
                out.push(')');
            }
            0x1f | 0x20 => {
                let mut modifier = String::new();
                self.encoded_type_into(r, ctx, depth, &mut modifier);
                self.sig_type_into(r, ctx, depth + 1, out);
                out.push_str(if et == 0x1f { " modreq(" } else { " modopt(" });
                out.push_str(&modifier);
                out.push(')');
            }
            0x45 => {
                self.sig_type_into(r, ctx, depth + 1, out);
                out.push_str(" pinned");
            }
            0 => {}
            _ => out.push_str(&format!("/* UNKNOWN TYPE (0x{et:X})*/")),
        }
    }

    /// A method signature (MethodDefSig, MethodRefSig, StandAloneMethodSig); a function pointer's
    /// is read as ildasm reads it, with no end but its count.
    pub fn method_sig(&mut self, r: &mut SigReader, ctx: GenericContext, depth: u32, pointer: bool) -> MethodSig {
        let conv = r.byte();
        let generics = if conv & 0x10 != 0 { r.u() } else { 0 };
        let mut count = r.u() as i64;
        let ret = self.sig_type(r, ctx, depth);
        let mut params = Vec::new();
        let mut guard = 0;
        while guard < 0x10000 && (pointer || !r.done()) {
            guard += 1;
            if (if pointer { r.peek_past() } else { r.peek() }) == 0x41 {
                r.pos += 1;
                params.push("...".to_string());
                continue;
            }
            if count <= 0 || r.done() {
                break;
            }
            params.push(self.sig_type(r, ctx, depth));
            count -= 1;
        }
        MethodSig { conv, generics, ret, params }
    }

    /* ---------------- members ---------------- */

    /// The class part of a member: nothing for a global function or field of `<Module>`.
    fn owner_of(&mut self, type_def: u32) -> String {
        let mut out = String::new();
        if type_def > 1 {
            self.type_def_into(type_def, &mut out);
            out.push_str("::");
        }
        out
    }

    /// A member's name; a privatescope one carries its token (`Name$PST06000123`).
    fn member_name(&self, table: u8, row: u32, private_scope: bool) -> String {
        let md = self.md;
        let column = if table == t::FIELD { m::FIELD_NAME } else { m::METHOD_DEF_NAME };
        let mut plain = md.string(md.get(column, row));
        if plain.is_empty() {
            plain = format!("${}${}", if table == t::FIELD { "FD" } else { "MD" }, hex_upper(row));
        }
        if private_scope {
            plain = format!("{plain}$PST{:08X}", (table as u32) << 24 | row);
        }
        proper_name(&plain)
    }

    /// `instance void Owner::Name<inst>(params)` for a MethodDef, MemberRef or MethodSpec token,
    /// with ildasm's line breaks as `, `.
    pub fn method(&mut self, tok: u32, ctx: GenericContext) -> String {
        match self.method_parts(tok, ctx) {
            Some((text, list_start)) => split_commas(&text, list_start),
            None => format!("[unknown token 0x{tok:x}]"),
        }
    }

    fn method_parts(&mut self, tok: u32, ctx: GenericContext) -> Option<(String, usize)> {
        let md = self.md;
        let mut target = (token_table(tok) as i16, token_row(tok));
        let mut inst = None;
        let mut outer = ctx;
        if target.0 == t::METHOD_SPEC as i16 {
            inst = Some(md.blob_range(md.get(m::METHOD_SPEC_INSTANTIATION, target.1)));
            target = decode_index(Coded::MethodDefOrRef, md.get(m::METHOD_SPEC_METHOD, target.1));
            outer = GenericContext { ty: ctx.ty, method: 0 };
        }
        let mut inner = outer;
        let (owner, name, blob) = if target.0 == t::METHOD_DEF as i16 {
            let owner = self.owner_of(self.method_owner(target.1));
            let name = self.member_name(t::METHOD_DEF, target.1, md.get(m::METHOD_DEF_FLAGS, target.1) & 7 == 0);
            (owner, name, md.get(m::METHOD_DEF_SIGNATURE, target.1))
        } else if target.0 == t::MEMBER_REF as i16 {
            let parent = decode_index(Coded::MemberRefParent, md.get(m::MEMBER_REF_CLASS, target.1));
            let owner = self.member_parent(parent, outer);
            if parent.0 == t::TYPE_SPEC as i16 && self.is_generic_inst(parent.1) {
                inner = GenericContext { ty: 0, method: outer.method };
            }
            let mut plain = md.string(md.get(m::MEMBER_REF_NAME, target.1));
            if plain.is_empty() {
                plain = format!("$MR${}", hex_upper(target.1));
            }
            let scoped = parent.0 == t::METHOD_DEF as i16 && md.get(m::METHOD_DEF_FLAGS, parent.1) & 7 == 0;
            if scoped {
                plain = format!("{plain}$PST06{:06X}", parent.1);
            }
            (owner, proper_name(&plain), md.get(m::MEMBER_REF_SIGNATURE, target.1))
        } else {
            return None;
        };
        let mut head = owner + &name;
        if let Some(range) = inst {
            let mut r = SigReader::new(&md.bytes, range);
            r.byte();
            let mut args: Vec<String> = Vec::new();
            let mut k = r.u();
            while k > 0 && !r.done() {
                args.push(self.sig_type(&mut r, inner, 0));
                k -= 1;
            }
            head.push('<');
            head.push_str(&args.join(","));
            head.push('>');
        }
        let mut r = SigReader::of_blob(md, blob);
        let sig = self.method_sig(&mut r, inner, 0, false);
        let mut text = String::with_capacity(sig.ret.len() + head.len() + sig.params.iter().map(|p| p.len() + 1).sum::<usize>() + 24);
        conv_text(sig.conv, &mut text);
        text.push_str(&sig.ret);
        text.push(' ');
        let before = text.len();
        text.push_str(&head);
        if inst.is_none() && sig.generics != 0 {
            text.push_str(&format!("<[{}]>", sig.generics));
        }
        text.push('(');
        text.push_str(&sig.params.join(","));
        text.push(')');
        // ildasm finds the name in the text again; the list starts one character after it. It is
        // there after `before` at the latest, so only the positions up to that one are tried.
        let (t, h) = (text.as_bytes(), head.as_bytes());
        let at = (0..=before).find(|&p| t[p..].starts_with(h)).unwrap_or(before);
        Some((text, at + head.len() + 1))
    }

    /// The class part of a MemberRef, by its parent.
    fn member_parent(&mut self, (table, row): (i16, u32), ctx: GenericContext) -> String {
        if row == 0 {
            return String::new();
        }
        match table {
            x if x == t::TYPE_DEF as i16 => self.owner_of(row),
            x if x == t::TYPE_REF as i16 => {
                let mut out = String::new();
                self.type_ref_into(row, &mut out);
                out.push_str("::");
                out
            }
            x if x == t::TYPE_SPEC as i16 => self.type_spec(row, ctx) + "::",
            x if x == t::MODULE_REF as i16 => {
                let module = self.md.string(self.md.get(m::MODULE_REF_NAME, row));
                if module.is_empty() {
                    "::".into()
                } else {
                    format!("[.module {}]::", proper_name(&module))
                }
            }
            x if x == t::METHOD_DEF as i16 => self.owner_of(self.method_owner(row)),
            _ => String::new(),
        }
    }

    /// `int32 Owner::Name` for a Field or MemberRef token.
    pub fn field(&mut self, tok: u32, ctx: GenericContext) -> String {
        let md = self.md;
        let row = token_row(tok);
        if token_table(tok) == t::FIELD {
            let name = self.member_name(t::FIELD, row, md.get(m::FIELD_FLAGS, row) & 7 == 0);
            let mut out = self.field_type(md.get(m::FIELD_SIGNATURE, row), ctx);
            out.push(' ');
            out.push_str(&self.owner_of(self.field_owner.get(row as usize).copied().unwrap_or(0)));
            out.push_str(&name);
            return out;
        }
        if token_table(tok) == t::MEMBER_REF {
            let parent = decode_index(Coded::MemberRefParent, md.get(m::MEMBER_REF_CLASS, row));
            let owner = self.member_parent(parent, ctx);
            let inner = if parent.0 == t::TYPE_SPEC as i16 && self.is_generic_inst(parent.1) { GenericContext { ty: 0, method: ctx.method } } else { ctx };
            let mut name = md.string(md.get(m::MEMBER_REF_NAME, row));
            if name.is_empty() {
                name = format!("$MR${}", hex_upper(row));
            }
            let mut out = self.field_type(md.get(m::MEMBER_REF_SIGNATURE, row), inner);
            out.push(' ');
            out.push_str(&owner);
            proper_name_into(&name, &mut out);
            return out;
        }
        format!("[unknown token 0x{tok:x}]")
    }

    fn field_type(&mut self, blob: u32, ctx: GenericContext) -> String {
        let mut r = SigReader::of_blob(self.md, blob);
        r.byte();
        self.sig_type(&mut r, ctx, 0)
    }

    /// A TypeDef, TypeRef or TypeSpec token as an operand: a class name, or the type a TypeSpec spells out.
    pub fn type_token(&mut self, tok: u32, ctx: GenericContext) -> String {
        let row = token_row(tok);
        match token_table(tok) {
            t::TYPE_DEF => self.type_def(row),
            t::TYPE_REF => self.type_ref(row),
            t::TYPE_SPEC => self.type_spec(row, ctx),
            _ => format!("[unknown token 0x{tok:x}]"),
        }
    }

    /// The operand of ldtoken: a type, `field …` or `method …`.
    pub fn token(&mut self, tok: u32, ctx: GenericContext) -> String {
        let field = match token_table(tok) {
            t::FIELD => true,
            t::METHOD_DEF | t::METHOD_SPEC => false,
            t::MEMBER_REF => self.is_field_ref(token_row(tok)),
            _ => return self.type_token(tok, ctx),
        };
        if field {
            format!("field {}", self.field(tok, ctx))
        } else {
            format!("method {}", self.method(tok, ctx))
        }
    }

    /// The operand of calli: a stand-alone method signature, `unmanaged cdecl int32(int32)`.
    pub fn standalone(&mut self, tok: u32, ctx: GenericContext) -> String {
        let md = self.md;
        let mut r = SigReader::of_blob(md, md.get(m::STAND_ALONE_SIG_SIGNATURE, token_row(tok)));
        let sig = self.method_sig(&mut r, ctx, 0, false);
        let mut out = String::new();
        conv_text(sig.conv, &mut out);
        out.push_str(&sig.ret);
        out.push('(');
        out.push_str(&sig.params.join(","));
        out.push(')');
        out
    }

    /// A MemberRef is a field when its signature says so (0x06).
    pub fn is_field_ref(&self, row: u32) -> bool {
        self.md.blob(self.md.get(m::MEMBER_REF_SIGNATURE, row)).first() == Some(&0x06)
    }

    /// A MethodDef's own signature, generic parameters named.
    pub fn method_def_sig(&mut self, row: u32) -> MethodSig {
        let md = self.md;
        let mut r = SigReader::of_blob(md, md.get(m::METHOD_DEF_SIGNATURE, row));
        self.method_sig(&mut r, GenericContext { ty: self.method_owner(row), method: row }, 0, false)
    }

    /// The types of a method's locals, from its LocalVarSig.
    pub fn locals(&mut self, tok: u32, ctx: GenericContext) -> Vec<String> {
        let md = self.md;
        if token_table(tok) != t::STAND_ALONE_SIG {
            return Vec::new();
        }
        let mut r = SigReader::of_blob(md, md.get(m::STAND_ALONE_SIG_SIGNATURE, token_row(tok)));
        if r.byte() != 0x07 {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut k = r.u();
        while k > 0 && !r.done() && out.len() < 65536 {
            out.push(self.sig_type(&mut r, ctx, 0));
            k -= 1;
        }
        out
    }

    /// The names of a MethodDef's parameters by sequence (1 = the first; 0 = the return value).
    pub fn param_names(&self, row: u32) -> Vec<Option<String>> {
        let md = self.md;
        let mut out: Vec<Option<String>> = Vec::new();
        let (start, end) = md.range(m::METHOD_DEF_PARAM_LIST, row, t::PARAM);
        let pointer = md.rows(t::PARAM_PTR) != 0;
        let last = if pointer { md.rows(t::PARAM_PTR) } else { md.rows(t::PARAM) };
        let mut k = start;
        while k < end && k <= last {
            let p = if pointer { md.get(m::PARAM_PTR_PARAM, k) } else { k };
            let name = md.string(md.get(m::PARAM_NAME, p));
            if !name.is_empty() {
                let sequence = md.get(m::PARAM_SEQUENCE, p) as usize;
                if out.len() <= sequence {
                    out.resize(sequence + 1, None);
                }
                out[sequence] = Some(name);
            }
            k += 1;
        }
        out
    }
}

/// Which TypeDef each row of a member table belongs to, from the TypeDefs' lists (through the pointer table when there is one).
fn owners(md: &Metadata, table: u8, column: m::Col, pointer: u8, pointer_column: m::Col) -> Vec<u32> {
    let mut out = vec![0u32; md.rows(table) as usize + 1];
    let types = md.rows(t::TYPE_DEF);
    let has_ptr = md.rows(pointer) != 0;
    let list_end = if has_ptr { md.rows(pointer) + 1 } else { md.rows(table) + 1 };
    let lists = md.column(column);
    for ty in 1..=types {
        let start = lists[ty as usize - 1];
        let end = if ty < types { lists[ty as usize] } else { list_end };
        let mut k = start;
        while k < end && k < list_end {
            let row = if has_ptr { md.get(pointer_column, k) } else { k };
            if row > 0 && (row as usize) < out.len() {
                out[row as usize] = ty;
            }
            k += 1;
        }
    }
    out
}
