//! The class file format (the Java Virtual Machine Specification, chapter 4):
//! the constant pool, the class's own name, its super class and interfaces,
//! its fields and methods, and the attributes the disassembler shows — Code
//! with its exception table, line numbers and local variables, the bootstrap
//! methods of invokedynamic, the source file, inner classes, records, sealed
//! classes, nests and modules.
//!
//! Constants are printed as javap prints them (its ConstantWriter): a class or
//! member name that is not a Java binary name in quotes, strings with Java's
//! escapes, floating point as Java's Double.toString and Float.toString write
//! it, and a member of the class itself without its class.
//!
//! A port of src/core/jvm/classfile.ts. Text is WTF-8 (`Wtf8`, see wtf8.rs):
//! a class file may encode a lone surrogate, which the TypeScript kept in its
//! JavaScript strings and the text here keeps too. Positions in a descriptor
//! (`read_type`) count UTF-16 code units, as JavaScript's do.
//!
//! Where the TypeScript threw a RangeError reading past the end of the file,
//! `parse` returns `ClassError::OutOfBounds`; the readers of attributes after
//! parsing (local variables, bootstrap methods…) read 0 there instead, so a
//! malformed attribute gives odd values rather than an error.

use std::cell::OnceCell;

use super::unicode;
use super::wtf8::{Wtf8, Wtf8Buf};

/// The tags of constant pool entries.
pub mod constant {
    pub const UTF8: u8 = 1;
    pub const INTEGER: u8 = 3;
    pub const FLOAT: u8 = 4;
    pub const LONG: u8 = 5;
    pub const DOUBLE: u8 = 6;
    pub const CLASS: u8 = 7;
    pub const STRING: u8 = 8;
    pub const FIELDREF: u8 = 9;
    pub const METHODREF: u8 = 10;
    pub const INTERFACE_METHODREF: u8 = 11;
    pub const NAME_AND_TYPE: u8 = 12;
    pub const METHOD_HANDLE: u8 = 15;
    pub const METHOD_TYPE: u8 = 16;
    pub const DYNAMIC: u8 = 17;
    pub const INVOKE_DYNAMIC: u8 = 18;
    pub const MODULE: u8 = 19;
    pub const PACKAGE: u8 = 20;
}

use constant::*;

/// Why bytes are not a class file this reader can read (`NotClass` in the TypeScript). The page
/// words the message; the English the TypeScript used is in each variant's comment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClassError {
    /// "not a class file"
    NotClassFile,
    /// "the class file is cut short"
    CutShort,
    /// "constant #{index} has an unknown tag {tag}"
    UnknownTag { index: u16, tag: u8 },
    /// "an attribute runs past the end of the class file"
    AttributeTooLong,
    /// "a method's code runs past its attribute"
    CodeTooLong,
    /// A method's Code read past the end of the file. The TypeScript's DataView throws a RangeError
    /// there ("Offset is outside the bounds of the DataView"), not a NotClass.
    OutOfBounds,
}

/// The class file's magic number.
pub fn is_class_file(bytes: &[u8]) -> bool {
    // 0xCAFEBABE is also a universal Mach-O file's: there the next word counts its slices (a few), here it is the version (45 or more).
    bytes.len() >= 10 && bytes[..4] == [0xca, 0xfe, 0xba, 0xbe] && ((bytes[6] as u16) << 8 | bytes[7] as u16) >= 45
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attribute {
    /// The Utf8 entry of its name (`cf.utf8(a.name_index)`).
    pub name_index: u16,
    /// Where its contents start in the class file, and their length.
    pub offset: usize,
    pub length: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Handler {
    pub start: u16,
    pub end: u16,
    pub handler: u16,
    /// The Class entry of what it catches; 0 catches anything (finally).
    pub catch_type: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LocalVariable<'a> {
    pub start: u16,
    pub length: u16,
    pub name: &'a Wtf8,
    pub descriptor: &'a Wtf8,
    pub slot: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Code {
    pub max_stack: u16,
    pub max_locals: u16,
    /// Where the bytecode starts in the class file, and its length.
    pub offset: usize,
    pub length: usize,
    pub handlers: Vec<Handler>,
    pub attributes: Vec<Attribute>,
}

/// A field or a method.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub access: u16,
    /// The Utf8 entries of its name and descriptor (`cf.utf8(m.name_index)`).
    pub name_index: u16,
    pub descriptor_index: u16,
    pub attributes: Vec<Attribute>,
    /// A method's Code; none for an abstract or native method, or a field.
    pub code: Option<Code>,
}

/// A method is a member with code.
pub type Method = Member;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootstrapMethod {
    /// A MethodHandle entry, and the constants passed to it.
    pub method: u16,
    pub args: Vec<u16>,
}

/// A member reference: its class's internal name, its name and its descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemberRef<'a> {
    pub owner: &'a Wtf8,
    pub name: &'a Wtf8,
    pub descriptor: &'a Wtf8,
}

/// The NameAndType of an InvokeDynamic or Dynamic entry, and its bootstrap method's number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DynamicRef<'a> {
    pub bootstrap: u16,
    pub name: &'a Wtf8,
    pub descriptor: &'a Wtf8,
}

/// A MethodHandle: its kind (1 getField … 9 invokeInterface) and the member it refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MethodHandle {
    pub kind: u8,
    pub reference: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InnerClass<'a> {
    pub inner: &'a Wtf8,
    pub outer: &'a Wtf8,
    pub name: &'a Wtf8,
    pub access: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordComponent<'a> {
    pub name: &'a Wtf8,
    pub descriptor: &'a Wtf8,
}

/// A module-info's module: its name, version, and what it requires, exports and opens.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Module<'a> {
    pub name: &'a Wtf8,
    pub version: &'a Wtf8,
    pub requires: Vec<&'a Wtf8>,
    pub exports: Vec<Wtf8Buf>,
    pub opens: Vec<Wtf8Buf>,
    pub uses: Vec<Wtf8Buf>,
    pub provides: Vec<Wtf8Buf>,
}

/// Where a Utf8 entry's text is: its bytes in the class file as they are, or decoded into `ClassFile::decoded`.
const DECODED: u32 = 1 << 31;

pub struct ClassFile {
    /// The class file. `path` is where the class was found (its entry in a JAR), for the page.
    pub bytes: Vec<u8>,
    pub path: String,
    pub minor: u16,
    pub major: u16,
    /// The constant pool: each entry's tag, and where its contents start (after the tag). Index 0 is unused, as is the slot after a long or double.
    pub tags: Vec<u8>,
    pub at: Vec<u32>,
    pub access: u16,
    pub this_class: u16,
    pub super_class: u16,
    pub interfaces: Vec<u16>,
    pub fields: Vec<Member>,
    pub methods: Vec<Method>,
    pub attributes: Vec<Attribute>,
    /// Each Utf8 entry's text: where it starts (with `DECODED` when in `decoded`) and its length.
    spans: Vec<(u32, u32)>,
    decoded: Vec<u8>,
    bootstraps: OnceCell<Vec<BootstrapMethod>>,
}

#[inline]
fn be16(bytes: &[u8], p: usize) -> u16 {
    u16::from_be_bytes([bytes[p], bytes[p + 1]])
}

/// A big-endian read that fails where the TypeScript's DataView throws.
fn read_be(bytes: &[u8], p: u64, n: u64) -> Result<u32, ClassError> {
    if p + n > bytes.len() as u64 {
        return Err(ClassError::OutOfBounds);
    }
    Ok(bytes[p as usize..(p + n) as usize].iter().fold(0u32, |v, &b| (v << 8) | b as u32))
}

/// A name in the constant pool's UTF-8 is "modified": NUL is two bytes and a character outside the
/// BMP is two surrogates of three bytes each. The TypeScript decodes it unit by unit (not checking
/// continuation bytes, a byte it cannot read as U+FFFD), and so does this, appending WTF-8 to `out`.
fn modified_utf8(bytes: &[u8], out: &mut Vec<u8>) {
    let end = bytes.len();
    let mut p = 0;
    // A high surrogate waiting to see whether a low one follows (then the two are one character).
    let mut high: Option<u32> = None;
    let three = |out: &mut Vec<u8>, c: u32| out.extend_from_slice(&[0xe0 | (c >> 12) as u8, 0x80 | ((c >> 6) & 0x3f) as u8, 0x80 | (c & 0x3f) as u8]);
    while p < end {
        let b = bytes[p] as u32;
        let unit;
        if b < 0x80 {
            if let Some(h) = high.take() {
                three(out, h);
            }
            // A run of ASCII as it is.
            let run = bytes[p..].iter().position(|&c| c >= 0x80).unwrap_or(end - p);
            out.extend_from_slice(&bytes[p..p + run]);
            p += run;
            continue;
        } else if b & 0xe0 == 0xc0 && p + 1 < end {
            unit = ((b & 0x1f) << 6) | (bytes[p + 1] as u32 & 0x3f);
            p += 2;
        } else if b & 0xf0 == 0xe0 && p + 2 < end {
            unit = ((b & 0x0f) << 12) | ((bytes[p + 1] as u32 & 0x3f) << 6) | (bytes[p + 2] as u32 & 0x3f);
            p += 3;
        } else {
            unit = 0xfffd;
            p += 1;
        }
        if (0xdc00..0xe000).contains(&unit) {
            if let Some(h) = high.take() {
                let c = 0x10000 + ((h - 0xd800) << 10) + (unit - 0xdc00);
                out.extend_from_slice(&[0xf0 | (c >> 18) as u8, 0x80 | ((c >> 12) & 0x3f) as u8, 0x80 | ((c >> 6) & 0x3f) as u8, 0x80 | (c & 0x3f) as u8]);
                continue;
            }
        }
        if let Some(h) = high.take() {
            three(out, h);
        }
        if (0xd800..0xdc00).contains(&unit) {
            high = Some(unit);
        } else if unit < 0x80 {
            out.push(unit as u8);
        } else if unit < 0x800 {
            out.extend_from_slice(&[0xc0 | (unit >> 6) as u8, 0x80 | (unit & 0x3f) as u8]);
        } else {
            three(out, unit);
        }
    }
    if let Some(h) = high {
        three(out, h);
    }
}

/// Is the modified UTF-8 already the WTF-8 its decoding gives? Valid UTF-8 without surrogates
/// (which UTF-8 rejects; so is the two-byte NUL) or four-byte sequences (which the decoding takes
/// byte by byte). A NUL byte decodes to itself: the TypeScript leaves it out of its fast path, but
/// its decoding gives the same.
#[inline]
fn verbatim(bytes: &[u8]) -> bool {
    bytes.is_ascii() || (!bytes.iter().any(|&b| b >= 0xf0) && core::str::from_utf8(bytes).is_ok())
}

impl ClassFile {
    /// Reads a class file. `path` is where it was found, for the page.
    pub fn parse(bytes: Vec<u8>, path: &str) -> Result<ClassFile, ClassError> {
        if !is_class_file(&bytes) {
            return Err(ClassError::NotClassFile);
        }
        let end = bytes.len() as u64;
        let need = |p: u64, n: u64| if p + n > end { Err(ClassError::CutShort) } else { Ok(()) };
        let minor = be16(&bytes, 4);
        let major = be16(&bytes, 6);
        let count = be16(&bytes, 8) as usize;
        let mut tags = vec![0u8; count];
        let mut at = vec![0u32; count];
        let mut p = 10u64;
        let mut i = 1;
        while i < count {
            need(p, 1)?;
            let tag = bytes[p as usize];
            tags[i] = tag;
            at[i] = (p + 1) as u32;
            p += 1;
            match tag {
                UTF8 => {
                    need(p, 2)?;
                    p += 2 + be16(&bytes, p as usize) as u64;
                }
                INTEGER | FLOAT | FIELDREF | METHODREF | INTERFACE_METHODREF | NAME_AND_TYPE | DYNAMIC | INVOKE_DYNAMIC => p += 4,
                LONG | DOUBLE => {
                    p += 8;
                    i += 1;
                }
                CLASS | STRING | METHOD_TYPE | MODULE | PACKAGE => p += 2,
                METHOD_HANDLE => p += 3,
                _ => return Err(ClassError::UnknownTag { index: i as u16, tag }),
            }
            i += 1;
        }
        need(p, 8)?;
        let mut cf = ClassFile {
            minor,
            major,
            access: be16(&bytes, p as usize),
            this_class: be16(&bytes, p as usize + 2),
            super_class: be16(&bytes, p as usize + 4),
            tags,
            at,
            interfaces: Vec::new(),
            fields: Vec::new(),
            methods: Vec::new(),
            attributes: Vec::new(),
            spans: Vec::new(),
            decoded: Vec::new(),
            bootstraps: OnceCell::new(),
            bytes,
            path: path.to_string(),
        };
        // Every entry is inside the file now: the texts can be read.
        cf.read_texts();
        let bytes = &cf.bytes;
        let interfaces = be16(bytes, p as usize + 6) as u64;
        p += 8;
        need(p, interfaces * 2)?;
        cf.interfaces = (0..interfaces).map(|k| be16(bytes, (p + k * 2) as usize)).collect();
        p += interfaces * 2;
        let mut lists = [Vec::new(), Vec::new()];
        for into in lists.iter_mut() {
            need(p, 2)?;
            let members = be16(bytes, p as usize);
            p += 2;
            into.reserve(members as usize);
            for _ in 0..members {
                need(p, 6)?;
                let q = p as usize;
                let mut member = Member { access: be16(bytes, q), name_index: be16(bytes, q + 2), descriptor_index: be16(bytes, q + 4), attributes: Vec::new(), code: None };
                p = read_attributes(bytes, p + 6, &mut member.attributes)?;
                into.push(member);
            }
        }
        let mut attributes = Vec::new();
        read_attributes(bytes, p, &mut attributes)?;
        let [fields, mut methods] = lists;
        for method in &mut methods {
            if let Some(attr) = method.attributes.iter().find(|a| cf.utf8(a.name_index as usize) == "Code") {
                method.code = Some(read_code(&cf.bytes, attr)?);
            }
        }
        cf.fields = fields;
        cf.methods = methods;
        cf.attributes = attributes;
        Ok(cf)
    }

    fn read_texts(&mut self) {
        let mut spans = vec![(0u32, 0u32); self.tags.len()];
        let mut decoded = Vec::new();
        for (i, &tag) in self.tags.iter().enumerate() {
            if tag != UTF8 {
                continue;
            }
            let p = self.at[i] as usize;
            let length = be16(&self.bytes, p) as usize;
            let raw = &self.bytes[p + 2..p + 2 + length];
            if verbatim(raw) {
                spans[i] = ((p + 2) as u32, length as u32);
            } else {
                let start = decoded.len();
                modified_utf8(raw, &mut decoded);
                spans[i] = (start as u32 | DECODED, (decoded.len() - start) as u32);
            }
        }
        self.spans = spans;
        self.decoded = decoded;
    }

    /// The class's name as the file writes it: `java/lang/String`.
    pub fn name(&self) -> &Wtf8 {
        self.class_name(self.this_class as usize)
    }

    /// The byte at `p`, or 0 past the end.
    #[inline]
    pub fn u1(&self, p: usize) -> u8 {
        self.bytes.get(p).copied().unwrap_or(0)
    }

    /// The big-endian u2 at `p`, or 0 past the end.
    #[inline]
    pub fn u2(&self, p: usize) -> u16 {
        match self.bytes.get(p..p.wrapping_add(2)) {
            Some(b) => u16::from_be_bytes([b[0], b[1]]),
            None => 0,
        }
    }

    /// The big-endian u4 at `p`, or 0 past the end.
    #[inline]
    pub fn u4(&self, p: usize) -> u32 {
        match self.bytes.get(p..p.wrapping_add(4)) {
            Some(b) => u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
            None => 0,
        }
    }

    fn u8_at(&self, p: usize) -> u64 {
        match self.bytes.get(p..p.wrapping_add(8)) {
            Some(b) => u64::from_be_bytes(b.try_into().unwrap()),
            None => 0,
        }
    }

    /// Is `index` an entry of the pool with this tag?
    #[inline]
    pub fn is(&self, index: usize, tag: u8) -> bool {
        index > 0 && index < self.tags.len() && self.tags[index] == tag
    }

    /// The text of a Utf8 entry; empty for any other index.
    pub fn utf8(&self, index: usize) -> &Wtf8 {
        if !self.is(index, UTF8) {
            return Wtf8::new("");
        }
        let (start, len) = self.spans[index];
        let (source, start) = if start & DECODED != 0 { (&self.decoded, start & !DECODED) } else { (&self.bytes, start) };
        // SAFETY: read_texts keeps only valid UTF-8 as it is and writes the rest as WTF-8.
        unsafe { Wtf8::from_bytes_unchecked(&source[start as usize..(start + len) as usize]) }
    }

    /// The first and second u2 of an entry (a Class's name, a Fieldref's class and NameAndType…).
    #[inline]
    pub fn ref1(&self, index: usize) -> usize {
        if index > 0 && index < self.tags.len() {
            self.u2(self.at[index] as usize) as usize
        } else {
            0
        }
    }

    #[inline]
    pub fn ref2(&self, index: usize) -> usize {
        if index > 0 && index < self.tags.len() {
            self.u2(self.at[index] as usize + 2) as usize
        } else {
            0
        }
    }

    /// The internal name of a Class entry: `java/lang/String`, `[I`.
    pub fn class_name(&self, index: usize) -> &Wtf8 {
        if self.is(index, CLASS) {
            self.utf8(self.ref1(index))
        } else {
            Wtf8::new("")
        }
    }

    /// A member reference: its class's internal name, its name and its descriptor.
    pub fn member(&self, index: usize) -> MemberRef<'_> {
        let nat = self.ref2(index);
        MemberRef { owner: self.class_name(self.ref1(index)), name: self.utf8(self.ref1(nat)), descriptor: self.utf8(self.ref2(nat)) }
    }

    /// The NameAndType of an InvokeDynamic or Dynamic entry, and its bootstrap method's number.
    pub fn dynamic(&self, index: usize) -> DynamicRef<'_> {
        let nat = self.ref2(index);
        DynamicRef { bootstrap: self.ref1(index) as u16, name: self.utf8(self.ref1(nat)), descriptor: self.utf8(self.ref2(nat)) }
    }

    fn entry_at(&self, index: usize) -> usize {
        self.at.get(index).map_or(usize::MAX, |&p| p as usize)
    }

    pub fn int(&self, index: usize) -> i32 {
        self.u4(self.entry_at(index)) as i32
    }

    pub fn float(&self, index: usize) -> f32 {
        f32::from_bits(self.u4(self.entry_at(index)))
    }

    pub fn long(&self, index: usize) -> i64 {
        self.u8_at(self.entry_at(index)) as i64
    }

    pub fn double(&self, index: usize) -> f64 {
        f64::from_bits(self.u8_at(self.entry_at(index)))
    }

    /// A MethodHandle: its kind (1 getField … 9 invokeInterface) and the member it refers to.
    pub fn handle(&self, index: usize) -> MethodHandle {
        let p = self.entry_at(index);
        MethodHandle { kind: self.u1(p), reference: self.u2(p.wrapping_add(1)) }
    }

    /// The first attribute of `list` (the class's own, or a member's, or a Code's) named `name`.
    pub fn attribute<'a>(&self, name: &str, list: &'a [Attribute]) -> Option<&'a Attribute> {
        list.iter().find(|a| self.utf8(a.name_index as usize) == name)
    }

    /// The bootstrap methods invokedynamic and dynamic constants name by number.
    pub fn bootstrap_methods(&self) -> &[BootstrapMethod] {
        self.bootstraps.get_or_init(|| {
            let mut out = Vec::new();
            if let Some(attr) = self.attribute("BootstrapMethods", &self.attributes) {
                let mut p = attr.offset + 2;
                let mut k = self.u2(attr.offset);
                while k > 0 && p + 4 <= attr.offset + attr.length {
                    let count = self.u2(p + 2) as usize;
                    let args = (0..count).map(|a| self.u2(p + 4 + a * 2)).collect();
                    out.push(BootstrapMethod { method: self.u2(p), args });
                    p += 4 + count * 2;
                    k -= 1;
                }
            }
            out
        })
    }

    /// The source file the class was compiled from (SourceFile), if the compiler kept it.
    pub fn source_file(&self) -> Option<&Wtf8> {
        self.attribute("SourceFile", &self.attributes).map(|a| self.utf8(self.u2(a.offset) as usize))
    }

    /// The generic signature of the class, a field or a method (Signature), from that list of attributes.
    pub fn signature(&self, list: &[Attribute]) -> Option<&Wtf8> {
        self.attribute("Signature", list).map(|a| self.utf8(self.u2(a.offset) as usize))
    }

    /// The local variables a method's code names (LocalVariableTable), when it was compiled with them.
    pub fn local_variables(&self, code: &Code) -> Vec<LocalVariable<'_>> {
        let mut out = Vec::new();
        for attr in &code.attributes {
            if self.utf8(attr.name_index as usize) != "LocalVariableTable" {
                continue;
            }
            let mut p = attr.offset + 2;
            for _ in 0..self.u2(attr.offset) {
                out.push(LocalVariable {
                    start: self.u2(p),
                    length: self.u2(p + 2),
                    name: self.utf8(self.u2(p + 4) as usize),
                    descriptor: self.utf8(self.u2(p + 6) as usize),
                    slot: self.u2(p + 8),
                });
                p += 10;
            }
        }
        out
    }

    /// The source lines of a method's code (LineNumberTable): (pc, line), in the order of the table.
    pub fn line_numbers(&self, code: &Code) -> Vec<(u16, u16)> {
        let mut out = Vec::new();
        for attr in &code.attributes {
            if self.utf8(attr.name_index as usize) != "LineNumberTable" {
                continue;
            }
            let mut p = attr.offset + 2;
            for _ in 0..self.u2(attr.offset) {
                out.push((self.u2(p), self.u2(p + 2)));
                p += 4;
            }
        }
        out
    }

    /// The names of a method's parameters (MethodParameters), when the compiler kept them.
    pub fn parameter_names(&self, method: &Method) -> Option<Vec<&Wtf8>> {
        let attr = self.attribute("MethodParameters", &method.attributes)?;
        Some((0..self.u1(attr.offset) as usize).map(|k| self.utf8(self.u2(attr.offset + 1 + k * 4) as usize)).collect())
    }

    /// The exceptions a method declares (Exceptions), as internal names.
    pub fn exceptions(&self, method: &Method) -> Vec<&Wtf8> {
        match self.attribute("Exceptions", &method.attributes) {
            Some(attr) => (0..self.u2(attr.offset) as usize).map(|k| self.class_name(self.u2(attr.offset + 2 + k * 2) as usize)).collect(),
            None => Vec::new(),
        }
    }

    /// The types of the annotations on the class, a field or a method, visible and invisible: `Lkotlin/Metadata;`.
    pub fn annotations(&self, list: &[Attribute]) -> Vec<&Wtf8> {
        let mut out = Vec::new();
        for attr in list {
            let name = self.utf8(attr.name_index as usize);
            if name != "RuntimeVisibleAnnotations" && name != "RuntimeInvisibleAnnotations" {
                continue;
            }
            // Only the first level's types: skipping an annotation's values needs walking them.
            let mut p = attr.offset + 2;
            let end = attr.offset + attr.length;
            let mut k = self.u2(attr.offset);
            while k > 0 && p + 4 <= end {
                out.push(self.utf8(self.u2(p) as usize));
                p = self.skip_annotation(p, end, 0);
                k -= 1;
            }
        }
        out
    }

    /// `depth` stops a malformed nesting before the stack runs out (the TypeScript's would, with a RangeError).
    fn skip_annotation(&self, mut p: usize, end: usize, depth: u32) -> usize {
        let pairs = self.u2(p + 2);
        p += 4;
        let mut k = 0;
        while k < pairs && p < end {
            p = self.skip_element(p + 2, end, depth + 1);
            k += 1;
        }
        p
    }

    fn skip_element(&self, mut p: usize, end: usize, depth: u32) -> usize {
        if depth > 1000 {
            return end;
        }
        let tag = self.u1(p);
        p += 1;
        match tag {
            b'e' => p + 4,
            b'@' => self.skip_annotation(p, end, depth),
            b'[' => {
                let n = self.u2(p);
                p += 2;
                let mut k = 0;
                while k < n && p < end {
                    p = self.skip_element(p, end, depth + 1);
                    k += 1;
                }
                p
            }
            _ => p + 2,
        }
    }

    /// The classes nested in this one, and the class this one is nested in, by InnerClasses.
    pub fn inner_classes(&self) -> Vec<InnerClass<'_>> {
        let Some(attr) = self.attribute("InnerClasses", &self.attributes) else { return Vec::new() };
        let mut p = attr.offset + 2;
        let mut out = Vec::new();
        for _ in 0..self.u2(attr.offset) {
            out.push(InnerClass {
                inner: self.class_name(self.u2(p) as usize),
                outer: self.class_name(self.u2(p + 2) as usize),
                name: self.utf8(self.u2(p + 4) as usize),
                access: self.u2(p + 6),
            });
            p += 8;
        }
        out
    }

    /// Classes named by a list attribute (NestMembers, PermittedSubclasses).
    pub fn class_list(&self, name: &str) -> Vec<&Wtf8> {
        match self.attribute(name, &self.attributes) {
            Some(attr) => (0..self.u2(attr.offset) as usize).map(|k| self.class_name(self.u2(attr.offset + 2 + k * 2) as usize)).collect(),
            None => Vec::new(),
        }
    }

    /// A record's components (Record): name and descriptor. A component whose attributes run past
    /// the end of the file ends the list (the TypeScript throws there).
    pub fn record_components(&self) -> Vec<RecordComponent<'_>> {
        let Some(attr) = self.attribute("Record", &self.attributes) else { return Vec::new() };
        let mut out = Vec::new();
        let mut p = attr.offset + 2;
        let mut attrs = Vec::new();
        for _ in 0..self.u2(attr.offset) {
            out.push(RecordComponent { name: self.utf8(self.u2(p) as usize), descriptor: self.utf8(self.u2(p + 2) as usize) });
            attrs.clear();
            match read_attributes(&self.bytes, p as u64 + 4, &mut attrs) {
                Ok(next) => p = next as usize,
                Err(_) => break,
            }
        }
        out
    }

    /// A module-info's module: its name, version, and what it requires, exports and opens.
    pub fn module(&self) -> Option<Module<'_>> {
        let attr = self.attribute("Module", &self.attributes)?;
        let mut p = attr.offset;
        let module = |index: u16| if self.is(index as usize, MODULE) { self.utf8(self.ref1(index as usize)) } else { Wtf8::new("") };
        let package = |index: u16| if self.is(index as usize, PACKAGE) { self.utf8(self.ref1(index as usize)).replace_ascii(b'/', b'.') } else { Wtf8Buf::new() };
        let mut out = Module {
            name: module(self.u2(p)),
            version: self.utf8(self.u2(p + 4) as usize),
            requires: Vec::new(),
            exports: Vec::new(),
            opens: Vec::new(),
            uses: Vec::new(),
            provides: Vec::new(),
        };
        p += 6;
        for k in 0..self.u2(p) as usize {
            out.requires.push(module(self.u2(p + 2 + k * 6)));
        }
        p += 2 + self.u2(p) as usize * 6;
        for list in [&mut out.exports, &mut out.opens] {
            let n = self.u2(p);
            p += 2;
            for _ in 0..n {
                list.push(package(self.u2(p)));
                p += 6 + self.u2(p + 4) as usize * 2;
            }
        }
        let uses = self.u2(p) as usize;
        for k in 0..uses {
            out.uses.push(java_name(self.class_name(self.u2(p + 2 + k * 2) as usize)));
        }
        p += 2 + uses * 2;
        let provides = self.u2(p);
        p += 2;
        for _ in 0..provides {
            out.provides.push(java_name(self.class_name(self.u2(p) as usize)));
            p += 4 + self.u2(p + 2) as usize * 2;
        }
        Some(out)
    }
}

fn read_attributes(bytes: &[u8], mut p: u64, into: &mut Vec<Attribute>) -> Result<u64, ClassError> {
    let end = bytes.len() as u64;
    if p + 2 > end {
        return Err(ClassError::CutShort);
    }
    let count = be16(bytes, p as usize);
    p += 2;
    into.reserve(count as usize);
    for _ in 0..count {
        if p + 6 > end {
            return Err(ClassError::CutShort);
        }
        let length = read_be(bytes, p + 2, 4)? as u64;
        if p + 6 + length > end {
            return Err(ClassError::AttributeTooLong);
        }
        into.push(Attribute { name_index: be16(bytes, p as usize), offset: (p + 6) as usize, length: length as usize });
        p += 6 + length;
    }
    Ok(p)
}

fn read_code(bytes: &[u8], attr: &Attribute) -> Result<Code, ClassError> {
    let mut p = attr.offset as u64;
    let length = read_be(bytes, p + 4, 4)? as u64;
    let mut code = Code {
        max_stack: read_be(bytes, p, 2)? as u16,
        max_locals: read_be(bytes, p + 2, 2)? as u16,
        offset: (p + 8) as usize,
        length: length as usize,
        handlers: Vec::new(),
        attributes: Vec::new(),
    };
    if 8 + length > attr.length as u64 {
        return Err(ClassError::CodeTooLong);
    }
    p += 8 + length;
    let handlers = read_be(bytes, p, 2)?;
    p += 2;
    code.handlers.reserve(handlers as usize);
    for _ in 0..handlers {
        code.handlers.push(Handler {
            start: read_be(bytes, p, 2)? as u16,
            end: read_be(bytes, p + 2, 2)? as u16,
            handler: read_be(bytes, p + 4, 2)? as u16,
            catch_type: read_be(bytes, p + 6, 2)? as u16,
        });
        p += 8;
    }
    read_attributes(bytes, p, &mut code.attributes)?;
    Ok(code)
}

/* ------------------------------------------------------------------ *
 * Constants as javap prints them
 * ------------------------------------------------------------------ */

// Character.isJavaIdentifierStart and isJavaIdentifierPart: letters, letter numbers, currency symbols, connectors; and digits, marks and the ignorable controls and formats.
fn is_start(c: u32) -> bool {
    if c < 0x80 {
        (c as u8).is_ascii_alphabetic() || c == b'_' as u32 || c == b'$' as u32
    } else {
        unicode::is_start(c)
    }
}

fn is_part(c: u32) -> bool {
    if c < 0x80 {
        let b = c as u8;
        b.is_ascii_alphanumeric() || b == b'_' || b == b'$' || b <= 0x08 || (0x0e..=0x1b).contains(&b) || b == 0x7f
    } else {
        unicode::is_part(c)
    }
}

/// A class, member or package name as javap writes it: as it is when it is a binary name (identifiers between slashes), else in quotes.
pub fn check_name(name: &Wtf8) -> Wtf8Buf {
    let mut out = Wtf8Buf::with_capacity(name.len() + 2);
    write_check_name(name, &mut out);
    out
}

/// `check_name`, appended to `out`.
pub fn write_check_name(name: &Wtf8, out: &mut Wtf8Buf) {
    if name.is_empty() {
        out.push_str("\"\"");
        return;
    }
    let mut previous = b'/' as u32;
    for c in name.code_points() {
        if (previous == b'/' as u32 && !is_start(c)) || (c != b'/' as u32 && !is_part(c)) {
            out.push_byte(b'"');
            for &b in name.as_bytes() {
                match b {
                    b'\\' => out.push_str("\\\\"),
                    b'"' => out.push_str("\\\""),
                    b'\n' => out.push_str("\\n"),
                    b'\t' => out.push_str("\\t"),
                    // Copied byte by byte, the text stays well formed: only ASCII is replaced.
                    _ => out.push_raw_byte(b),
                }
            }
            out.push_byte(b'"');
            return;
        }
        previous = c;
    }
    out.push_wtf8(name);
}

/// A string constant as javap writes it: Java's escapes, and \uXXXX for the other control characters.
pub fn escape_string(text: &Wtf8) -> Wtf8Buf {
    let mut out = Wtf8Buf::with_capacity(text.len());
    write_escape_string(text, &mut out);
    out
}

/// `escape_string`, appended to `out`.
pub fn write_escape_string(text: &Wtf8, out: &mut Wtf8Buf) {
    let b = text.as_bytes();
    let mut k = 0;
    // A lone low surrogate in front joins a high one `out` may end with; the rest is copied byte by byte.
    if b.len() >= 3 && b[0] == 0xed && b[1] >= 0xb0 {
        // SAFETY: the three bytes of a surrogate are well-formed WTF-8.
        out.push_wtf8(unsafe { Wtf8::from_bytes_unchecked(&b[..3]) });
        k = 3;
    }
    while k < b.len() {
        let c = b[k];
        let escape = match c {
            b'\t' => Some("\\t"),
            b'\n' => Some("\\n"),
            b'\r' => Some("\\r"),
            0x08 => Some("\\b"),
            0x0c => Some("\\f"),
            b'"' => Some("\\\""),
            b'\'' => Some("\\'"),
            b'\\' => Some("\\\\"),
            _ => None,
        };
        if let Some(e) = escape {
            out.push_str(e);
        } else if c < 0x20 || c == 0x7f {
            push_unicode_escape(out, c as u32);
        } else if c == 0xc2 && k + 1 < b.len() && (0x80..0xa0).contains(&b[k + 1]) {
            // U+0080–U+009F, two bytes.
            push_unicode_escape(out, b[k + 1] as u32);
            k += 1;
        } else {
            out.push_raw_byte(c);
        }
        k += 1;
    }
}

fn push_unicode_escape(out: &mut Wtf8Buf, c: u32) {
    use core::fmt::Write;
    let _ = write!(out, "\\u{c:04x}");
}

/* ---------------- Java's floating point ---------------- */

/// A number as JavaScript's toExponential writes it, reduced to what matters here: its digits
/// (as written, trailing zeros too) and the exponent of the first.
#[derive(Clone, PartialEq, Eq, Debug)]
struct Exp {
    digits: Vec<u8>,
    exp: i32,
}

impl Exp {
    /// `Number(text)`.
    fn value(&self) -> f64 {
        let mut s = String::with_capacity(self.digits.len() + 8);
        s.push(self.digits[0] as char);
        if self.digits.len() > 1 {
            s.push('.');
            s.extend(self.digits[1..].iter().map(|&d| d as char));
        }
        s.push('e');
        s.push_str(&self.exp.to_string());
        s.parse().unwrap_or(f64::NAN)
    }

    /// `decimal(text)`: the digits without trailing zeros (at least one).
    fn decimal(mut self) -> Exp {
        while self.digits.len() > 1 && self.digits.last() == Some(&b'0') {
            self.digits.pop();
        }
        if self.digits.iter().all(|&d| d == b'0') {
            self.digits = vec![b'0'];
        }
        self
    }
}

/// The digits one unit up in the last place: 9.99 → 10.0, one more digit in front and the last dropped.
fn up(mut e: Exp) -> Exp {
    let mut k = e.digits.len();
    loop {
        if k == 0 {
            e.digits.insert(0, b'1');
            e.digits.pop();
            e.exp += 1;
            return e;
        }
        k -= 1;
        if e.digits[k] == b'9' {
            e.digits[k] = b'0';
        } else {
            e.digits[k] += 1;
            return e;
        }
    }
}

/// The decimal value of a finite positive double, exactly as far as the formatting needs it: its
/// first significant digits and the exponent of the first; and whether nonzero digits follow
/// (`more`). Without `more`, `digits` are all of them, without trailing zeros (a double has at
/// most 767). The formatting looks at no more than the first 19 digits, and at the rest only to
/// know whether it is all zeros (a tie).
struct Exact {
    digits: Vec<u8>,
    exp: i32,
    more: bool,
}

/// How many digits `Exact` keeps when the value has more.
const KEPT: usize = 20;

/// Digits and exponent of Rust's `{:e}` text.
fn split_exp(text: &str) -> (Vec<u8>, i32) {
    let (mantissa, e) = text.split_once('e').unwrap_or((text, "0"));
    (mantissa.bytes().filter(|b| b.is_ascii_digit()).collect(), e.parse().unwrap_or(0))
}

impl Exact {
    fn of(value: f64) -> Exact {
        // Forty digits, rounded at the last: unless the digits after the first KEPT are all zeros or
        // all nines (where the rounding may have carried, or the value may end there), the first
        // KEPT are exact and something nonzero follows them.
        let (digits, exp) = split_exp(&format!("{value:.39e}"));
        let tail = &digits[KEPT..];
        if !tail.iter().all(|&d| d == b'0') && !tail.iter().all(|&d| d == b'9') {
            return Exact { digits: digits[..KEPT].to_vec(), exp, more: true };
        }
        // value = m·2^e with m odd. With e < 0 it is m·5^-e / 10^-e: as many digits as m·5^-e has,
        // at most 16 + 0.7·-e; with e ≥ 0 an integer of at most 16 + 0.31·e. Asked for that many,
        // Rust writes them all, exactly, and pads with zeros.
        let bits = value.to_bits();
        let biased = ((bits >> 52) & 0x7ff) as i32;
        let m = if biased == 0 { bits & 0xf_ffff_ffff_ffff } else { (bits & 0xf_ffff_ffff_ffff) | 1 << 52 };
        let e = biased.max(1) - 1075 + m.trailing_zeros() as i32;
        let precision = if e < 0 { 18 + (-e as usize * 7).div_ceil(10) } else { 18 + (e as usize * 31).div_ceil(100) };
        let (mut digits, exp) = split_exp(&format!("{value:.precision$e}"));
        while digits.len() > 1 && digits.last() == Some(&b'0') {
            digits.pop();
        }
        Exact { digits, exp, more: false }
    }

    /// The first `n` digits, cut (padded with zeros).
    fn cut(&self, n: usize) -> Exp {
        Exp { digits: (0..n).map(|k| self.digits.get(k).copied().unwrap_or(b'0')).collect(), exp: self.exp }
    }

    /// JavaScript's `value.toExponential(fraction)`: `fraction + 1` digits, rounded half up (of two
    /// equally close, the larger).
    fn to_exponential(&self, fraction: usize) -> Exp {
        let n = fraction + 1;
        let cut = self.cut(n);
        if self.digits.get(n).is_some_and(|&d| d >= b'5') {
            up(cut)
        } else {
            cut
        }
    }

    /// JavaScript's `value.toExponential()`: the shortest digits that read back as the double and,
    /// of two as short, the closer; of two as close, the even one. Rust's shortest digits are
    /// the same but for that last rule: of two as close it takes the larger, so a tie is settled here.
    fn shortest(&self, value: f64) -> Exp {
        let text = format!("{value:e}");
        let (mantissa, e) = text.split_once('e').unwrap_or((&text, "0"));
        let rust = Exp { digits: mantissa.bytes().filter(|b| b.is_ascii_digit()).collect(), exp: e.parse().unwrap_or(0) };
        let n = rust.digits.len();
        // A tie: the value is exactly halfway between n digits and the next n digits up.
        if self.more || self.digits.len() != n + 1 || self.digits[n] != b'5' {
            return rust;
        }
        let lower = self.cut(n);
        let upper = up(lower.clone());
        let even = |e: &Exp| e.digits.last().is_some_and(|&d| (d - b'0').is_multiple_of(2));
        let reads_back = |e: &Exp| e.value() == value;
        match (reads_back(&lower), reads_back(&upper)) {
            (true, true) if even(&lower) => lower,
            (true, true) => upper,
            (true, false) => lower,
            _ => rust,
        }
    }

    /// JavaScript rounds a tie up (toExponential), Java to the even digit: when the value is
    /// exactly halfway between the digits `text` has and the ones below, and the last digit is odd,
    /// the ones below. Exact: value = (10·digits − 5)·10^(q − 1), q the exponent of the last digit.
    fn even_tie(&self, text: &Exp) -> Exp {
        if text.digits.last().is_none_or(|&d| (d - b'0').is_multiple_of(2)) {
            return text.clone();
        }
        let n = text.digits.len() as i32;
        let q = text.exp - n + 1;
        let digits: u64 = text.digits.iter().fold(0u64, |v, &d| v * 10 + (d - b'0') as u64);
        let half = (digits * 10 - 5).to_string();
        // The exact value's last digit is at exponent exp − (len − 1).
        let last = self.exp - (self.digits.len() as i32 - 1);
        if self.more || half.as_bytes() != self.digits.as_slice() || last != q - 1 {
            return text.clone();
        }
        Exp { digits: (digits - 1).to_string().into_bytes(), exp: text.exp }
    }
}

/// Java's Double.toString and Float.toString (JDK 19 and later): the shortest decimal that reads
/// back as the same value — two digits when one would do but two are closer —, written plainly
/// between 10^-3 and 10^7 and as `1.0E10` outside.
fn java_number(value: f64, single: bool) -> String {
    if value.is_nan() {
        return "NaN".into();
    }
    if value.is_infinite() {
        return if value > 0.0 { "Infinity".into() } else { "-Infinity".into() };
    }
    if value == 0.0 {
        return if value.is_sign_negative() { "-0.0".into() } else { "0.0".into() };
    }
    let abs = value.abs();
    let exact = Exact::of(abs);
    let same = |text: &Exp| if single { text.value() as f32 as f64 == abs } else { text.value() == abs };
    // Of two digits equally close the even one, when it too reads back as the value.
    let pick = |text: Exp| {
        let even = exact.even_tie(&text);
        if even != text && same(&even) {
            even
        } else {
            text
        }
    };
    let mut d = exact.shortest(abs).decimal();
    if single {
        for p in 1..=9 {
            let text = pick(exact.to_exponential(p - 1));
            if same(&text) {
                d = text.decimal();
                break;
            }
        }
    }
    if d.digits.len() == 1 {
        let two = pick(exact.to_exponential(1));
        if same(&two) {
            d = two.decimal();
        }
    }
    let Exp { digits, exp } = d;
    let digits = String::from_utf8(digits).unwrap_or_default();
    let mut out = String::with_capacity(digits.len() + 8);
    if value < 0.0 {
        out.push('-');
    }
    if (1e-3..1e7).contains(&abs) {
        if exp >= 0 {
            let whole = exp as usize + 1;
            if digits.len() > whole {
                out.push_str(&digits[..whole]);
                out.push('.');
                out.push_str(&digits[whole..]);
            } else {
                out.push_str(&digits);
                out.extend(std::iter::repeat_n('0', whole - digits.len()));
                out.push_str(".0");
            }
        } else {
            out.push_str("0.");
            out.extend(std::iter::repeat_n('0', (-exp - 1) as usize));
            out.push_str(&digits);
        }
    } else {
        out.push_str(&digits[..1]);
        out.push('.');
        out.push_str(if digits.len() > 1 { &digits[1..] } else { "0" });
        out.push('E');
        out.push_str(&exp.to_string());
    }
    out
}

/// Java's Double.toString.
pub fn java_double(value: f64) -> String {
    java_number(value, false)
}

/// Java's Float.toString.
pub fn java_float(value: f32) -> String {
    java_number(value as f64, true)
}

/// javap's names for the kinds of entry, as it writes them before a constant.
fn tag_name(tag: u8) -> Option<&'static str> {
    Some(match tag {
        1 => "Utf8",
        3 => "int",
        4 => "float",
        5 => "long",
        6 => "double",
        7 => "class",
        8 => "String",
        9 => "Field",
        10 => "Method",
        11 => "InterfaceMethod",
        12 => "NameAndType",
        15 => "MethodHandle",
        16 => "MethodType",
        17 => "Dynamic",
        18 => "InvokeDynamic",
        19 => "Module",
        20 => "Package",
        _ => return None,
    })
}

const HANDLE_KINDS: [&str; 10] = [
    "",
    "REF_getField",
    "REF_getStatic",
    "REF_putField",
    "REF_putStatic",
    "REF_invokeVirtual",
    "REF_invokeStatic",
    "REF_invokeSpecial",
    "REF_newInvokeSpecial",
    "REF_invokeInterface",
];

/// How deep `constant_value` follows references: only a malformed class has a cycle, which the TypeScript follows until the stack runs out.
const MAX_DEPTH: u32 = 256;

/// An entry's value as javap writes it (ConstantWriter.stringValue).
pub fn constant_value(cf: &ClassFile, index: usize) -> Wtf8Buf {
    let mut out = Wtf8Buf::new();
    write_constant_value(cf, index, &mut out);
    out
}

/// `constant_value`, appended to `out`.
pub fn write_constant_value(cf: &ClassFile, index: usize, out: &mut Wtf8Buf) {
    value_into(cf, index, out, 0);
}

fn value_into(cf: &ClassFile, index: usize, out: &mut Wtf8Buf, depth: u32) {
    use core::fmt::Write;
    let tag = cf.tags.get(index).copied().unwrap_or(0);
    if depth > MAX_DEPTH {
        let _ = write!(out, "#{index}");
        return;
    }
    match tag {
        UTF8 => write_escape_string(cf.utf8(index), out),
        INTEGER => {
            let _ = write!(out, "{}", cf.int(index));
        }
        FLOAT => {
            out.push_str(&java_float(cf.float(index)));
            out.push_byte(b'f');
        }
        LONG => {
            let _ = write!(out, "{}l", cf.long(index));
        }
        DOUBLE => {
            out.push_str(&java_double(cf.double(index)));
            out.push_byte(b'd');
        }
        CLASS | MODULE | PACKAGE => write_check_name(cf.utf8(cf.ref1(index)), out),
        STRING => write_escape_string(cf.utf8(cf.ref1(index)), out),
        FIELDREF | METHODREF | INTERFACE_METHODREF => {
            value_into(cf, cf.ref1(index), out, depth + 1);
            out.push_byte(b'.');
            value_into(cf, cf.ref2(index), out, depth + 1);
        }
        NAME_AND_TYPE => {
            write_check_name(cf.utf8(cf.ref1(index)), out);
            out.push_byte(b':');
            out.push_wtf8(cf.utf8(cf.ref2(index)));
        }
        METHOD_HANDLE => {
            let MethodHandle { kind, reference } = cf.handle(index);
            // An interface's static or special method is still REF_invokeStatic or REF_invokeSpecial.
            match HANDLE_KINDS.get(kind as usize) {
                Some(name) => out.push_str(name),
                None => {
                    let _ = write!(out, "kind {kind}");
                }
            }
            out.push_byte(b' ');
            value_into(cf, reference as usize, out, depth + 1);
        }
        METHOD_TYPE => out.push_wtf8(cf.utf8(cf.ref1(index))),
        DYNAMIC | INVOKE_DYNAMIC => {
            let _ = write!(out, "#{}:", cf.ref1(index));
            value_into(cf, cf.ref2(index), out, depth + 1);
        }
        _ => {
            let _ = write!(out, "#{index}");
        }
    }
}

/// What javap writes after an instruction's `//`: the kind of entry and its value; a member of the class itself without its class.
pub fn constant_comment(cf: &ClassFile, index: usize) -> Wtf8Buf {
    let mut out = Wtf8Buf::new();
    write_constant_comment(cf, index, &mut out);
    out
}

/// `constant_comment`, appended to `out`.
pub fn write_constant_comment(cf: &ClassFile, index: usize, out: &mut Wtf8Buf) {
    use core::fmt::Write;
    if index == 0 {
        out.push_str("#0");
        return;
    }
    let tag = cf.tags.get(index).copied().unwrap_or(0);
    let mut shown = index;
    if (tag == FIELDREF || tag == METHODREF || tag == INTERFACE_METHODREF) && cf.ref1(index) == cf.this_class as usize {
        shown = cf.ref2(index);
    }
    match tag_name(tag) {
        Some(name) => out.push_str(name),
        None => {
            let _ = write!(out, "(unknown tag {tag})");
        }
    }
    out.push_byte(b' ');
    write_constant_value(cf, shown, out);
}

/* ------------------------------------------------------------------ *
 * Descriptors
 * ------------------------------------------------------------------ */

/// A descriptor as JavaScript indexes it: by UTF-16 code unit. Nearly every descriptor is ASCII,
/// where the units are the bytes.
enum Units<'a> {
    Ascii(&'a [u8]),
    Wide(Vec<u16>),
}

impl Units<'_> {
    fn of(text: &Wtf8) -> Units<'_> {
        if text.is_ascii() {
            Units::Ascii(text.as_bytes())
        } else {
            Units::Wide(text.to_utf16())
        }
    }

    #[inline]
    fn len(&self) -> usize {
        match self {
            Units::Ascii(b) => b.len(),
            Units::Wide(u) => u.len(),
        }
    }

    /// `descriptor[at]`.
    #[inline]
    fn get(&self, at: usize) -> Option<u16> {
        match self {
            Units::Ascii(b) => b.get(at).map(|&c| c as u16),
            Units::Wide(u) => u.get(at).copied(),
        }
    }

    /// `descriptor.indexOf(c, from)`.
    fn index_of(&self, c: u8, from: usize) -> Option<usize> {
        match self {
            Units::Ascii(b) => b.get(from..)?.iter().position(|&x| x == c).map(|k| k + from),
            Units::Wide(u) => u.get(from..)?.iter().position(|&x| x == c as u16).map(|k| k + from),
        }
    }

    /// `descriptor.slice(start, end)`.
    fn slice(&self, start: usize, end: usize) -> Wtf8Buf {
        let end = end.min(self.len());
        let start = start.min(end);
        match self {
            // SAFETY: ASCII is valid UTF-8.
            Units::Ascii(b) => Wtf8Buf::from(unsafe { core::str::from_utf8_unchecked(&b[start..end]) }),
            Units::Wide(u) => Wtf8Buf::from_utf16(&u[start..end]),
        }
    }
}

fn primitive(c: u16) -> Option<&'static str> {
    Some(match c as u8 {
        _ if c > 0x7f => return None,
        b'B' => "byte",
        b'C' => "char",
        b'D' => "double",
        b'F' => "float",
        b'I' => "int",
        b'J' => "long",
        b'S' => "short",
        b'Z' => "boolean",
        b'V' => "void",
        _ => return None,
    })
}

fn read_units(descriptor: &Units, mut at: usize) -> (Wtf8Buf, usize) {
    let mut dims = 0;
    while descriptor.get(at) == Some(b'[' as u16) {
        dims += 1;
        at += 1;
    }
    let mut name;
    let c = descriptor.get(at);
    if c == Some(b'L' as u16) {
        let Some(end) = descriptor.index_of(b';', at) else { return (descriptor.slice(at, descriptor.len()), descriptor.len()) };
        name = descriptor.slice(at + 1, end).replace_ascii(b'/', b'.');
        at = end + 1;
    } else {
        name = match c {
            None => Wtf8Buf::new(),
            Some(c) => match primitive(c) {
                Some(p) => Wtf8Buf::from(p),
                None => Wtf8Buf::from_utf16(&[c]),
            },
        };
        at += 1;
    }
    for _ in 0..dims {
        name.push_str("[]");
    }
    (name, at)
}

/// Where the type `read_units` reads ends, without its name.
fn skip_units(descriptor: &Units, mut at: usize) -> usize {
    while descriptor.get(at) == Some(b'[' as u16) {
        at += 1;
    }
    if descriptor.get(at) == Some(b'L' as u16) {
        match descriptor.index_of(b';', at) {
            Some(end) => end + 1,
            None => descriptor.len(),
        }
    } else {
        at + 1
    }
}

/// One field type of a descriptor, from `at` (in UTF-16 units), as Java writes it: `int`, `java.lang.String[]`; and where it ends.
pub fn read_type(descriptor: &Wtf8, at: usize) -> (Wtf8Buf, usize) {
    read_units(&Units::of(descriptor), at)
}

/// A field descriptor as Java writes the type.
pub fn field_type(descriptor: &Wtf8) -> Wtf8Buf {
    read_type(descriptor, 0).0
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MethodTypes {
    pub params: Vec<Wtf8Buf>,
    pub ret: Wtf8Buf,
}

/// `descriptor.indexOf(c) + 1`.
fn after(descriptor: &Units, c: u8) -> usize {
    descriptor.index_of(c, 0).map_or(0, |k| k + 1)
}

/// A method descriptor's parameter types and return type, as Java writes them.
pub fn method_types(descriptor: &Wtf8) -> MethodTypes {
    let units = Units::of(descriptor);
    let mut params = Vec::new();
    let mut at = after(&units, b'(');
    while at > 0 && at < units.len() && units.get(at) != Some(b')' as u16) {
        let (ty, next) = read_units(&units, at);
        params.push(ty);
        at = next;
    }
    MethodTypes { params, ret: read_units(&units, after(&units, b')')).0 }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DescriptorKinds {
    /// One letter per parameter: i, l, f, d, or a for a reference.
    pub params: String,
    /// The return's letter, or '' for void.
    pub ret: &'static str,
}

fn kind_of(c: Option<u16>) -> &'static str {
    match c.map(|c| if c > 0x7f { 0 } else { c as u8 }).unwrap_or(b'V') {
        b'J' => "l",
        b'F' => "f",
        b'D' => "d",
        b'L' | b'[' => "a",
        b'V' => "",
        _ => "i",
    }
}

/// What a descriptor's values are: one letter per parameter (I, J, F, D, or A for a reference), and the return's ('' for void).
pub fn descriptor_kinds(descriptor: &Wtf8) -> DescriptorKinds {
    let units = Units::of(descriptor);
    let mut params = String::new();
    let mut at = after(&units, b'(');
    while at > 0 && at < units.len() && units.get(at) != Some(b')' as u16) {
        params.push_str(kind_of(units.get(at)));
        at = skip_units(&units, at);
    }
    if at == 0 {
        return DescriptorKinds { params: String::new(), ret: kind_of(units.get(0)) };
    }
    DescriptorKinds { params, ret: kind_of(units.get(at + 1)) }
}

/// What `descriptor_kinds` says of a descriptor without spelling the parameters out: how many there are, and the return's kind.
pub fn descriptor_shape(descriptor: &Wtf8) -> (usize, &'static str) {
    let units = Units::of(descriptor);
    let mut count = 0;
    let mut at = after(&units, b'(');
    while at > 0 && at < units.len() && units.get(at) != Some(b')' as u16) {
        count += 1;
        at = skip_units(&units, at);
    }
    if at == 0 {
        return (0, kind_of(units.get(0)));
    }
    (count, kind_of(units.get(at + 1)))
}

/// The kind of a field's value, by its descriptor: `descriptor_kinds("()" + descriptor).ret`.
pub fn field_kind(descriptor: &Wtf8) -> &'static str {
    // A first byte past ASCII is the first of a character that is not ASCII, as its first UTF-16 unit is.
    kind_of(descriptor.as_bytes().first().map(|&b| b as u16))
}

/// `java/lang/String` → `java.lang.String`; an array class as Java writes its type.
pub fn java_name(internal: &Wtf8) -> Wtf8Buf {
    if internal.starts_with("[") {
        field_type(internal)
    } else {
        internal.replace_ascii(b'/', b'.')
    }
}

/// What `modifiers` writes the flags of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum What {
    Class,
    Method,
    Field,
}

const CLASS_FLAGS: [(u16, &str); 3] = [(0x0001, "public"), (0x0010, "final"), (0x0400, "abstract")];
const MEMBER_FLAGS: [(u16, &str); 9] = [
    (0x0001, "public"),
    (0x0002, "private"),
    (0x0004, "protected"),
    (0x0008, "static"),
    (0x0010, "final"),
    (0x0020, "synchronized"),
    (0x0100, "native"),
    (0x0400, "abstract"),
    (0x0800, "strictfp"),
];
const FIELD_FLAGS: [(u16, &str); 7] =
    [(0x0001, "public"), (0x0002, "private"), (0x0004, "protected"), (0x0008, "static"), (0x0010, "final"), (0x0040, "volatile"), (0x0080, "transient")];

/// The Java modifiers of a class, a method or a field: `public static final`.
pub fn modifiers(access: u16, what: What) -> String {
    let table: &[(u16, &str)] = match what {
        What::Class => &CLASS_FLAGS,
        What::Method => &MEMBER_FLAGS,
        What::Field => &FIELD_FLAGS,
    };
    let mut out = String::new();
    for &(bit, word) in table {
        if access & bit != 0 {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(word);
        }
    }
    out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClassKind {
    Class,
    Interface,
    Annotation,
    Enum,
    Record,
    Module,
}

impl ClassKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            ClassKind::Class => "class",
            ClassKind::Interface => "interface",
            ClassKind::Annotation => "annotation",
            ClassKind::Enum => "enum",
            ClassKind::Record => "record",
            ClassKind::Module => "module",
        }
    }
}

/// What a class is: an interface, an annotation, an enum, a record, a module, or a class.
pub fn class_kind(cf: &ClassFile) -> ClassKind {
    if cf.access & 0x8000 != 0 {
        ClassKind::Module
    } else if cf.access & 0x2000 != 0 {
        ClassKind::Annotation
    } else if cf.access & 0x0200 != 0 {
        ClassKind::Interface
    } else if cf.access & 0x4000 != 0 {
        ClassKind::Enum
    } else if cf.class_name(cf.super_class as usize) == "java/lang/Record" {
        ClassKind::Record
    } else {
        ClassKind::Class
    }
}

/// The Java release a class file version is from: 52 → 8, 49 → 5, 48 → 1.4.
pub fn java_release(major: u16) -> String {
    if major >= 49 {
        (major - 44).to_string()
    } else {
        format!("1.{}", (major as i32 - 44).max(1))
    }
}
