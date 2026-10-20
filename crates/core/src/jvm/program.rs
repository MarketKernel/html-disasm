//! The analysis of Java bytecode: a class file, or every class of a JAR (or a
//! .jmod, a .war, an Android library's classes.jar) as one program. Every
//! method with code is decoded once, and from that pass come the statistics,
//! the methods (the functions of the listing, named `package.Class::method`),
//! the labels branches and exception handlers go to, the calls — to methods of
//! the program, and to members of classes it does not have, which are its
//! imports —, the fields and the strings `ldc` loads.
//!
//! A class file has no addresses: each method's code is given a place of its
//! own, one after another in the order of the classes, and an instruction's
//! address is that place plus its pc; the listing writes the pc, as javap
//! does. What is not code has addresses of its own that are never an
//! instruction's: a string (all classes' constants of the same text are one)
//! from STRING_BASE, a field of the program from FIELD_BASE, a member of
//! another class from IMPORT_BASE.
//!
//! A port of src/core/jvm/program.ts. The reading of the archive and the pass
//! run in steps (`JvmSession::step`), so the page can show its progress; the
//! classes stay in the session afterwards, for the page to take one at a time.

use super::classfile::{constant, descriptor_shape, field_kind, is_class_file, java_name, method_types, modifiers, ClassError, ClassFile, What};
use super::decode::{decode_at, pool_index, JvmInsn};
use super::hla::{JvmLines, JvmNaming};
use super::opcodes::{all_ops, flags as F, Operand};
use super::wtf8::{Wtf8, Wtf8Buf};
use crate::disassembly::iflag;
use crate::lift::HlaLine;
use crate::refs::{FxHashMap, RefBuilder, RefIndex};
use crate::zip::{is_zip, zip_entries, zip_read, ZipEntry, ZipError};

pub const STRING_BASE: u32 = 0x4000_0000;
pub const FIELD_BASE: u32 = 0x5000_0000;
pub const IMPORT_BASE: u32 = 0x6000_0000;
/// Where the first method's code is placed.
const CODE_BASE: u32 = 0x10000;
/// A method without code has no function.
const NO_FUNCTION: u32 = u32::MAX;

/* ------------------------------------------------------------------ *
 * Opening files
 * ------------------------------------------------------------------ */

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContainerKind {
    Class,
    Jar,
    Jmod,
}

/// Why a class of an archive could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Broken {
    Zip(ZipError),
    Class(ClassError),
}

/// What the file around the classes says: a JAR's manifest and the entries that are not classes.
#[derive(Clone, Debug)]
pub struct Container {
    pub kind: ContainerKind,
    /// The manifest's attributes, in the order they first appear.
    pub manifest: Vec<(String, String)>,
    /// Entries that are not classes of the program (resources, nested JARs, other releases' classes).
    pub resources: Vec<(String, u64)>,
    /// Classes for other Java releases (META-INF/versions/…), which are not read.
    pub versioned: u32,
    /// Classes that could not be read, and why.
    pub broken: Vec<(String, Broken)>,
    /// The classes came from an Android library's classes.jar.
    pub from_classes_jar: bool,
}

impl Container {
    fn of(kind: ContainerKind) -> Container {
        Container { kind, manifest: Vec::new(), resources: Vec::new(), versioned: 0, broken: Vec::new(), from_classes_jar: false }
    }

    pub fn manifest_value(&self, key: &str) -> Option<&str> {
        self.manifest.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }
}

/// Why a file cannot be opened as Java classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadError {
    /// "This is not a class file or a JAR."
    NotJava,
    /// "The archive holds no Java classes."
    NoClasses,
    Zip(ZipError),
    Class(ClassError),
}

/// A .jmod starts with `JM`, a version, and a ZIP.
pub fn is_jmod(bytes: &[u8]) -> bool {
    bytes.len() > 8 && bytes[0] == 0x4a && bytes[1] == 0x4d && bytes[2] == 1 && bytes[3] == 0 && is_zip(&bytes[4..])
}

/// JavaScript's `trim()`: its white space and line terminators, which are not quite Unicode's.
pub fn js_trim(s: &str) -> &str {
    let js_space = |c: char| {
        matches!(
            c,
            '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
                ..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'
        )
    };
    s.trim_matches(js_space)
}

/// The attributes of a JAR's META-INF/MANIFEST.MF; a line starting with a space continues the one before.
pub fn parse_manifest(text: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut last = String::new();
    for line in text.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.starts_with(' ') && !last.is_empty() {
            if let Some(entry) = out.iter_mut().find(|(k, _)| *k == last) {
                entry.1.push_str(&line[1..]);
            }
        } else {
            let Some(colon) = line.find(':') else { continue };
            if colon == 0 {
                continue;
            }
            last = js_trim(&line[..colon]).to_string();
            if !out.iter().any(|(k, _)| *k == last) {
                out.push((last.clone(), js_trim(&line[colon + 1..]).to_string()));
            }
        }
    }
    out
}

/// Text as the page's TextDecoder gives it: UTF-8, a bad sequence as U+FFFD, a leading BOM dropped.
fn decode_utf8(bytes: &[u8]) -> String {
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    String::from_utf8_lossy(bytes).into_owned()
}

/// Is a name of the form `META-INF/versions/<digits>/…`?
fn is_versioned(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("META-INF/versions/") else { return false };
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    digits > 0 && rest.as_bytes().get(digits) == Some(&b'/')
}

/// Reading an archive's classes, a batch at a time.
struct Reading {
    /// The archive (a .jmod's without its four-byte header), as it came in.
    file: Vec<u8>,
    jmod: bool,
    /// The ZIP's bytes when they are not the file's (an AAR's classes.jar).
    inner: Option<Vec<u8>>,
    wanted: Vec<ZipEntry>,
    next: usize,
    container: Container,
    classes: Vec<ClassFile>,
}

impl Reading {
    fn zip(&self) -> &[u8] {
        match &self.inner {
            Some(inner) => inner,
            None if self.jmod => &self.file[4..],
            None => &self.file,
        }
    }
}

/// What opening a file gives: its classes at once (a class file), or an archive to read in steps.
enum Opened {
    Done(Vec<ClassFile>, Container),
    Reading(Box<Reading>),
}

fn open(file: Vec<u8>) -> Result<Opened, ReadError> {
    if is_class_file(&file) {
        let cf = ClassFile::parse(file, "").map_err(ReadError::Class)?;
        return Ok(Opened::Done(vec![cf], Container::of(ContainerKind::Class)));
    }
    let jmod = is_jmod(&file);
    let mut container = Container::of(if jmod { ContainerKind::Jmod } else { ContainerKind::Jar });
    // An AAR's classes.jar, read as the file itself would be: a class file, a .jmod or a JAR.
    let mut inner: Option<Vec<u8>> = None;
    loop {
        let zip: &[u8] = match &inner {
            Some(bytes) => bytes,
            None if jmod => &file[4..],
            None => &file,
        };
        if !is_zip(zip) {
            return Err(ReadError::NotJava);
        }
        let entries = zip_entries(zip).map_err(ReadError::Zip)?;
        if !entries.iter().any(|e| e.name.ends_with(".class")) {
            let Some(entry) = entries.iter().find(|e| e.name == "classes.jar") else { return Err(ReadError::NoClasses) };
            let bytes = zip_read(zip, entry).map_err(ReadError::Zip)?.into_owned();
            container.from_classes_jar = true;
            if is_class_file(&bytes) {
                let cf = ClassFile::parse(bytes, "").map_err(ReadError::Class)?;
                container.kind = ContainerKind::Class;
                return Ok(Opened::Done(vec![cf], container));
            }
            let inner_jmod = is_jmod(&bytes);
            container.kind = if inner_jmod { ContainerKind::Jmod } else { ContainerKind::Jar };
            inner = Some(if inner_jmod { bytes[4..].to_vec() } else { bytes });
            continue;
        }
        let mut wanted = Vec::new();
        let mut manifest = None;
        for e in &entries {
            if manifest.is_none() && e.name.to_uppercase() == "META-INF/MANIFEST.MF" {
                manifest = Some(e);
            }
            if !e.name.ends_with(".class") {
                if !e.name.ends_with('/') {
                    container.resources.push((e.name.clone(), e.size));
                }
            } else if is_versioned(&e.name) {
                container.versioned += 1;
            } else {
                wanted.push(e.clone());
            }
        }
        if let Some(m) = manifest {
            let text = zip_read(zip, m).map_err(ReadError::Zip)?;
            container.manifest = parse_manifest(&decode_utf8(&text));
        }
        return Ok(Opened::Reading(Box::new(Reading { file, jmod, inner, wanted, next: 0, container, classes: Vec::new() })));
    }
}

impl Reading {
    /// Reads up to `count` classes more; true once every one is read (and the classes sorted).
    fn step(&mut self, count: usize) -> bool {
        let end = (self.next + count.max(1)).min(self.wanted.len());
        for k in self.next..end {
            let entry = &self.wanted[k];
            let read = zip_read(self.zip(), entry).map(|data| data.into_owned());
            let name = entry.name.clone();
            match read {
                Err(err) => self.container.broken.push((name, Broken::Zip(err))),
                Ok(data) => match ClassFile::parse(data, &name) {
                    Ok(cf) => self.classes.push(cf),
                    Err(err) => self.container.broken.push((name, Broken::Class(err))),
                },
            }
        }
        self.next = end;
        if self.next < self.wanted.len() {
            return false;
        }
        // By name, as JavaScript compares strings (UTF-16 code units); the sort is stable.
        self.classes.sort_by(|a, b| a.name().cmp_utf16(b.name()));
        true
    }
}

/* ------------------------------------------------------------------ *
 * The program
 * ------------------------------------------------------------------ */

/// A method with code: its class (an index into `classes`), the method (an index into its
/// class's methods), and where its code is placed.
#[derive(Clone, Copy, Debug)]
pub struct Body {
    pub cls: u32,
    pub method: u32,
    pub base: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FnKind {
    Export,
    Symbol,
    Entry,
}

impl FnKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            FnKind::Export => "export",
            FnKind::Symbol => "symbol",
            FnKind::Entry => "entry",
        }
    }
}

/// A function of the listing: a method with code.
#[derive(Clone, Debug)]
pub struct Function {
    pub addr: u32,
    pub first: u32,
    pub count: u32,
    /// What its declaration says before the class (`public static void `), and its parameters
    /// (`int[], int`): the page puts them around the class's and the method's names
    /// (`JvmProgram::function_full`), which it has already.
    pub prefix: Wtf8Buf,
    pub params: Wtf8Buf,
    pub kind: FnKind,
}

/// A member of a class the program does not have: a method or a field its code uses.
#[derive(Clone, Debug)]
pub struct Import {
    pub addr: u32,
    /// The class as the code names it (`java/io/PrintStream`), the member and its descriptor.
    pub owner: Wtf8Buf,
    pub member: Wtf8Buf,
    pub descriptor: Wtf8Buf,
    pub field: bool,
    /// Its type (a method's return type) and a method's parameters, as Java writes them: the page
    /// makes the declaration of them (`JvmProgram::import_full`).
    pub ret: Wtf8Buf,
    pub params: Wtf8Buf,
}

/// A run of the listing: the methods of one class.
#[derive(Clone, Debug)]
pub struct Range {
    /// The class, named in the listing as `class_kind java_name`: `record hello.Hello$Point`.
    pub cls: u32,
    pub first: u32,
    pub count: u32,
}

/// Where a reference of a constant pool leads: a function of the program, or an import.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Target {
    Function(u32),
    Import(u32),
}

/// What the pass finds, by the arrays the page takes.
#[derive(Default)]
pub struct JvmResult {
    pub offsets: Vec<u32>,
    pub mnemonic_ids: Vec<u16>,
    pub flags: Vec<u8>,
    pub mnemonics: Vec<&'static str>,
    pub counts: Vec<u32>,
    pub callers: RefIndex,
    pub data_refs: RefIndex,
    pub field_refs: RefIndex,
    /// Branches: the instruction, where its run of targets starts in `target_values`, and whether
    /// it is a switch (a list of targets) rather than one target.
    pub target_index: Vec<u32>,
    pub target_starts: Vec<u32>,
    pub target_values: Vec<u32>,
    pub target_lists: Vec<u8>,
    /// What each constant pool reference the code uses leads to: key `cls * 65536 + index`, value an address (-1: nothing).
    pub callee_keys: Vec<f64>,
    pub callee_values: Vec<f64>,
    pub field_keys: Vec<f64>,
    pub field_values: Vec<f64>,
}

pub struct JvmProgram {
    pub classes: Vec<ClassFile>,
    pub container: Container,
    pub bodies: Vec<Body>,
    pub functions: Vec<Function>,
    pub imported: Vec<Import>,
    /// The program's own fields, from FIELD_BASE: where each class's start (one more entry at the end).
    pub field_starts: Vec<u32>,
    pub strings: Vec<Wtf8Buf>,
    pub ranges: Vec<Range>,
    /// invokedynamic call sites: where they go is decided at run time.
    pub dynamic_calls: u32,
    /// The function the program starts at, by Main-Class or `main`.
    pub entry: Option<u32>,
    /// The newest class file version, for the platform label: (major, minor).
    pub version: (u16, u16),
    pub kotlin: bool,
    pub result: JvmResult,
    class_index: FxHashMap<Wtf8Buf, u32>,
    /// Each method's function (NO_FUNCTION without code), the methods of class k from `method_starts[k]`.
    fn_of_method: Vec<u32>,
    method_starts: Vec<u32>,
    import_key: FxHashMap<(Wtf8Buf, Wtf8Buf, Wtf8Buf), u32>,
    /// What the entries of the class being read lead to, and every reference resolved so far.
    pool: PoolCache,
    resolved: Vec<(u64, Option<Target>)>,
    field_resolved: Vec<(u64, u32)>,
    string_key: FxHashMap<Wtf8Buf, u32>,
    /// What a member reference reaches, by its owner, name and descriptor (`member_key`), whichever class names it.
    method_found: FxHashMap<Box<[u8]>, Target>,
    field_found: FxHashMap<Box<[u8]>, u32>,
    scratch: Vec<u8>,
}

/// A slot of a PoolCache not filled yet; a reference that leads nowhere; the mark of an import.
const UNSEEN: u32 = u32::MAX;
const NOTHING: u32 = u32::MAX - 1;
const IMPORT_BIT: u32 = 1 << 31;

/// What a class's constant pool entries lead to, by index. The pass reads the code of one class
/// after another and resolves only the current class's references, so one class's worth is kept:
/// a slot each, no hashing.
#[derive(Default)]
struct PoolCache {
    cls: Option<u32>,
    callee: Vec<u32>,
    field: Vec<u32>,
    shape: Vec<u32>,
}

impl PoolCache {
    fn enter(&mut self, cls: u32, len: usize) {
        if self.cls == Some(cls) {
            return;
        }
        self.cls = Some(cls);
        for v in [&mut self.callee, &mut self.field, &mut self.shape] {
            v.clear();
            v.resize(len, UNSEEN);
        }
    }

    /// A slot, made room for: an index past the pool (a broken class) has one too.
    #[inline]
    fn slot(v: &mut Vec<u32>, index: usize) -> &mut u32 {
        if index >= v.len() {
            v.resize(index + 1, UNSEEN);
        }
        &mut v[index]
    }
}

/// A member reference as one key: its owner, name and descriptor, each after its length.
fn member_key(out: &mut Vec<u8>, owner: &Wtf8, name: &Wtf8, descriptor: &Wtf8) {
    out.clear();
    for part in [owner, name, descriptor] {
        out.extend_from_slice(&(part.len() as u32).to_le_bytes());
        out.extend_from_slice(part.as_bytes());
    }
}

/// The kind of value an opcode's table entry names: 1 int, 2 long, 3 float, 4 double, 5 reference, 6 return address.
fn kind_code(kind: &str) -> u8 {
    match kind {
        "i" => 1,
        "l" => 2,
        "f" => 3,
        "d" => 4,
        "a" => 5,
        "r" => 6,
        _ => 0,
    }
}

#[inline]
fn is_wide(kind: u8) -> bool {
    kind == 2 || kind == 4
}

impl JvmProgram {
    fn new(classes: Vec<ClassFile>, container: Container) -> JvmProgram {
        let mut class_index = FxHashMap::default();
        for (k, cf) in classes.iter().enumerate() {
            class_index.insert(cf.name().to_owned(), k as u32);
        }
        JvmProgram {
            classes,
            container,
            bodies: Vec::new(),
            functions: Vec::new(),
            imported: Vec::new(),
            field_starts: Vec::new(),
            strings: Vec::new(),
            ranges: Vec::new(),
            dynamic_calls: 0,
            entry: None,
            version: (0, 0),
            kotlin: false,
            result: JvmResult::default(),
            class_index,
            fn_of_method: Vec::new(),
            method_starts: Vec::new(),
            import_key: FxHashMap::default(),
            pool: PoolCache::default(),
            resolved: Vec::new(),
            field_resolved: Vec::new(),
            string_key: FxHashMap::default(),
            method_found: FxHashMap::default(),
            field_found: FxHashMap::default(),
            scratch: Vec::new(),
        }
    }

    fn target_addr(&self, target: Target) -> u32 {
        match target {
            Target::Function(f) => self.functions[f as usize].addr,
            Target::Import(k) => self.imported[k as usize].addr,
        }
    }

    /// A method of the program by its class, name and descriptor, looked for in the class, its super classes and its interfaces.
    fn find_method(&self, owner: &Wtf8, name: &Wtf8, descriptor: &Wtf8) -> Option<u32> {
        let mut seen = Vec::new();
        let start = self.class_index.get(owner).copied();
        self.walk(start, name, descriptor, &mut seen)
    }

    fn walk(&self, cls: Option<u32>, name: &Wtf8, descriptor: &Wtf8, seen: &mut Vec<u32>) -> Option<u32> {
        let cls = cls?;
        if seen.contains(&cls) {
            return None;
        }
        seen.push(cls);
        let cf = &self.classes[cls as usize];
        if let Some(at) = self.method_of(cls, name, descriptor) {
            return Some(at);
        }
        let sup = self.class_index.get(cf.class_name(cf.super_class as usize)).copied();
        if let Some(found) = self.walk(sup, name, descriptor, seen) {
            return Some(found);
        }
        for &i in &cf.interfaces {
            let inner = self.class_index.get(cf.class_name(i as usize)).copied();
            if let Some(found) = self.walk(inner, name, descriptor, seen) {
                return Some(found);
            }
        }
        None
    }

    /// The function of a method of a class, by its name and descriptor: the last one with code, as a map keyed by them would keep.
    fn method_of(&self, cls: u32, name: &Wtf8, descriptor: &Wtf8) -> Option<u32> {
        let cf = &self.classes[cls as usize];
        let start = self.method_starts[cls as usize] as usize;
        cf.methods.iter().enumerate().rev().find_map(|(m, method)| {
            let f = self.fn_of_method[start + m];
            (f != NO_FUNCTION && cf.utf8(method.name_index as usize) == name && cf.utf8(method.descriptor_index as usize) == descriptor).then_some(f)
        })
    }

    /// A field of a class by its name and descriptor (its number from FIELD_BASE): the last, as a map keyed by them would keep.
    fn field_of(&self, cls: u32, name: &Wtf8, descriptor: &Wtf8) -> Option<u32> {
        let cf = &self.classes[cls as usize];
        let at = cf.fields.iter().rposition(|f| cf.utf8(f.name_index as usize) == name && cf.utf8(f.descriptor_index as usize) == descriptor)?;
        Some(self.field_starts[cls as usize] + at as u32)
    }

    /// The function or import a method reference of a class reaches.
    fn callee(&mut self, cls: u32, index: usize) -> Option<Target> {
        self.pool.enter(cls, self.classes[cls as usize].tags.len());
        match *PoolCache::slot(&mut self.pool.callee, index) {
            UNSEEN => {}
            NOTHING => return None,
            v if v & IMPORT_BIT != 0 => return Some(Target::Import(v & !IMPORT_BIT)),
            v => return Some(Target::Function(v)),
        }
        let cf = &self.classes[cls as usize];
        let tag = cf.tags.get(index).copied().unwrap_or(0);
        let found = if tag == constant::METHODREF || tag == constant::INTERFACE_METHODREF {
            let m = cf.member(index);
            // Many classes name the same member: it is looked for once.
            member_key(&mut self.scratch, m.owner, m.name, m.descriptor);
            if let Some(&known) = self.method_found.get(&self.scratch[..]) {
                Some(known)
            } else {
                let found = match self.find_method(m.owner, m.name, m.descriptor) {
                    Some(f) => Target::Function(f),
                    None => {
                        let (owner, name, descriptor) = (m.owner.to_owned(), m.name.to_owned(), m.descriptor.to_owned());
                        Target::Import(self.import_of(owner, name, descriptor, false))
                    }
                };
                self.method_found.insert(self.scratch.as_slice().into(), found);
                Some(found)
            }
        } else if tag == constant::METHOD_HANDLE {
            let h = cf.handle(index);
            if h.kind >= 5 {
                self.callee(cls, h.reference as usize)
            } else {
                None
            }
        } else {
            None
        };
        *PoolCache::slot(&mut self.pool.callee, index) = match found {
            None => NOTHING,
            Some(Target::Function(f)) => f,
            Some(Target::Import(k)) => IMPORT_BIT | k,
        };
        self.resolved.push((cls as u64 * 65536 + index as u64, found));
        found
    }

    /// The address of a field a Fieldref of a class names: the program's own field, or an import.
    fn field_addr(&mut self, cls: u32, index: usize) -> u32 {
        self.pool.enter(cls, self.classes[cls as usize].tags.len());
        let cached = *PoolCache::slot(&mut self.pool.field, index);
        if cached != UNSEEN {
            return cached;
        }
        let key = cls as u64 * 65536 + index as u64;
        let m = self.classes[cls as usize].member(index);
        member_key(&mut self.scratch, m.owner, m.name, m.descriptor);
        if let Some(&known) = self.field_found.get(&self.scratch[..]) {
            *PoolCache::slot(&mut self.pool.field, index) = known;
            self.field_resolved.push((key, known));
            return known;
        }
        let mut addr = None;
        // Declared in the class or one of its super classes here.
        let mut seen = Vec::new();
        let mut c = self.class_index.get(m.owner).copied();
        while let Some(at) = c {
            if seen.contains(&at) {
                break;
            }
            seen.push(at);
            if let Some(k) = self.field_of(at, m.name, m.descriptor) {
                addr = Some(FIELD_BASE + k);
                break;
            }
            let sup = &self.classes[at as usize];
            c = self.class_index.get(sup.class_name(sup.super_class as usize)).copied();
        }
        let addr = match addr {
            Some(a) => a,
            None => {
                let (owner, name, descriptor) = (m.owner.to_owned(), m.name.to_owned(), m.descriptor.to_owned());
                let k = self.import_of(owner, name, descriptor, true);
                self.imported[k as usize].addr
            }
        };
        *PoolCache::slot(&mut self.pool.field, index) = addr;
        self.field_resolved.push((key, addr));
        // The key is still the one made above: neither the walk nor import_of touches it.
        self.field_found.insert(self.scratch.as_slice().into(), addr);
        addr
    }

    fn import_of(&mut self, owner: Wtf8Buf, name: Wtf8Buf, descriptor: Wtf8Buf, field: bool) -> u32 {
        let key = (owner, name, descriptor);
        if let Some(&k) = self.import_key.get(&key) {
            return k;
        }
        let (owner, name, descriptor) = key;
        let (ret, params) = if field {
            let mut d = Wtf8Buf::from("()");
            d.push_wtf8(&descriptor);
            (java_name(&method_types(&d).ret), Wtf8Buf::new())
        } else {
            let types = method_types(&descriptor);
            let mut params = Wtf8Buf::new();
            push_joined(&mut params, &types.params);
            (types.ret, params)
        };
        let k = self.imported.len() as u32;
        self.imported.push(Import { addr: IMPORT_BASE + k, owner: owner.clone(), member: name.clone(), descriptor: descriptor.clone(), field, ret, params });
        self.import_key.insert((owner, name, descriptor), k);
        k
    }

    /// The address of the text of a class's String constant, made when the text is first seen.
    fn string_addr(&mut self, cls: u32, index: usize) -> u32 {
        let cf = &self.classes[cls as usize];
        let text = cf.utf8(cf.ref1(index));
        if let Some(&addr) = self.string_key.get(text) {
            return addr;
        }
        let addr = STRING_BASE + self.strings.len() as u32;
        self.string_key.insert(text.to_owned(), addr);
        self.strings.push(text.to_owned());
        addr
    }

    /// A method's own name.
    pub fn function_raw(&self, f: usize) -> &Wtf8 {
        let b = &self.bodies[f];
        let cf = &self.classes[b.cls as usize];
        cf.utf8(cf.methods[b.method as usize].name_index as usize)
    }

    /// A function's name in the listing: `package.Class::method`.
    pub fn function_name(&self, f: usize) -> Wtf8Buf {
        let mut out = java_name(self.classes[self.bodies[f].cls as usize].name());
        out.push_str("::");
        out.push_wtf8(self.function_raw(f));
        out
    }

    /// A function's declaration as Java writes it: `static long hello.Hello.sum(int[], int)`.
    pub fn function_full(&self, f: usize) -> Wtf8Buf {
        let fun = &self.functions[f];
        let mut out = fun.prefix.clone();
        out.push_wtf8(&java_name(self.classes[self.bodies[f].cls as usize].name()));
        out.push_str(".");
        out.push_wtf8(self.function_raw(f));
        out.push_str("(");
        out.push_wtf8(&fun.params);
        out.push_str(")");
        out
    }

    /// An import's declaration: `void java.io.PrintStream.println(java.lang.String)`.
    pub fn import_full(&self, k: usize) -> Wtf8Buf {
        let m = &self.imported[k];
        let mut out = m.ret.clone();
        out.push_str(" ");
        out.push_wtf8(&java_name(&m.owner));
        out.push_str(".");
        out.push_wtf8(&m.member);
        if !m.field {
            out.push_str("(");
            out.push_wtf8(&m.params);
            out.push_str(")");
        }
        out
    }

    /// Registers the classes' methods and fields; called once, before the code is read.
    fn index(&mut self) {
        let mut base = CODE_BASE;
        let mut fields = 0u32;
        for (cls, cf) in self.classes.iter().enumerate() {
            let cls = cls as u32;
            self.field_starts.push(fields);
            fields += cf.fields.len() as u32;
            self.method_starts.push(self.fn_of_method.len() as u32);
            let visible = cf.access & 0x0001 != 0;
            for (m, method) in cf.methods.iter().enumerate() {
                let Some(code) = method.code.as_ref().filter(|c| c.length > 0) else {
                    self.fn_of_method.push(NO_FUNCTION);
                    continue;
                };
                let name = cf.utf8(method.name_index as usize);
                let descriptor = cf.utf8(method.descriptor_index as usize);
                let types = method_types(descriptor);
                let mods = modifiers(method.access, What::Method);
                let mut prefix = Wtf8Buf::new();
                if !mods.is_empty() {
                    prefix.push_str(&mods);
                    prefix.push_str(" ");
                }
                if name != "<init>" && name != "<clinit>" {
                    prefix.push_wtf8(&types.ret);
                    prefix.push_str(" ");
                }
                let mut params = Wtf8Buf::new();
                push_joined(&mut params, &types.params);
                self.fn_of_method.push(self.functions.len() as u32);
                self.functions.push(Function {
                    addr: base,
                    first: 0,
                    count: 0,
                    prefix,
                    params,
                    kind: if visible && method.access & 0x0001 != 0 { FnKind::Export } else { FnKind::Symbol },
                });
                self.bodies.push(Body { cls, method: m as u32, base });
                base += (code.length as u32 + 1).div_ceil(16) * 16;
            }
            if cf.major > self.version.0 || (cf.major == self.version.0 && cf.minor > self.version.1) {
                self.version = (cf.major, cf.minor);
            }
            if !self.kotlin && cf.annotations(&cf.attributes).iter().any(|a| *a == "Lkotlin/Metadata;") {
                self.kotlin = true;
            }
        }
        self.field_starts.push(fields);
    }
}

fn push_joined(out: &mut Wtf8Buf, list: &[Wtf8Buf]) {
    for (k, item) in list.iter().enumerate() {
        if k > 0 {
            out.push_str(", ");
        }
        out.push_wtf8(item);
    }
}

/* ------------------------------------------------------------------ *
 * Statements for the HLA64 view
 * ------------------------------------------------------------------ */

/// Bits of the kinds the grouping looks at.
mod kind {
    pub const BARRIER: u8 = 1;
    pub const PURE: u8 = 2;
    pub const NEW: u8 = 4;
    pub const INIT: u8 = 8;
    pub const ARRAY: u8 = 16;
    pub const ARRAY_STORE: u8 = 32;
    pub const INT: u8 = 64;
    pub const OPAQUE: u8 = 128;
}

/// The stack operations whose effect depends on what is on the stack: pop2 … swap.
mod stack_op {
    pub const POP2: u8 = 0x58;
    pub const DUP: u8 = 0x59;
    pub const DUP2: u8 = 0x5c;
    pub const SWAP: u8 = 0x5f;
}

/// A value on the stack while the statements are grouped: the instructions that made it.
#[derive(Clone, Copy, Default)]
struct Node {
    start: i64,
    end: i64,
    /// It can be written as an expression inside the instruction that takes it.
    ok: bool,
    /// What kind of value (kind_code): a long or a double is one value of two slots.
    kind: u8,
    /// Its instructions start with a dup: the line must also take the value the dup copied, right below it.
    copy: bool,
    /// The lower of the two copies one dup2 makes: it ends where the copy above it starts.
    twin: bool,
    /// A `new` its `dup` has copied: the object is made by the constructor that takes the copy.
    construct: bool,
    /// The copy of a `new` that the constructor takes.
    init: bool,
    /// A new array: how many of its elements, from the first, the stores after it have set (-1: not an array).
    fill: i32,
    /// A new array its `dup` has copied for a store; and that copy.
    filling: bool,
    fill_copy: bool,
}

impl Node {
    fn new(start: i64, end: i64, ok: bool, kind: u8) -> Node {
        Node { start, end, ok, kind, fill: -1, ..Node::default() }
    }
}

/// What the pass keeps per instruction for grouping the statements of a method.
#[derive(Default)]
struct Stack {
    pops: Vec<i16>,
    /// -1 when it cannot be known.
    pushes: Vec<i8>,
    push_kinds: Vec<u8>,
    kinds: Vec<u8>,
    stack_ops: Vec<u8>,
    /// An int constant's value (iconst, bipush, sipush): an array initializer's index.
    ints: Vec<i32>,
    /// The instructions a handler starts at.
    handlers: Vec<u32>,
}

/// Marks the runs of instructions that make one statement of the HLA64 view (`groupStatements` in
/// src/core/jvm/program.ts, which says how): an instruction that takes values made right before
/// it, one after another, each an expression, joins them into its line. src/core/jvm/hla.ts writes
/// the lines and must agree with this on what makes one. The stack's arrays are the method's, from
/// its first instruction `first`.
fn group_statements(flags: &mut [u8], first: usize, end: usize, s: &Stack) {
    let mut nodes: Vec<Node> = Vec::new();
    let at = |i: usize| i - first;
    let folds = |nodes: &[Node], count: usize, at: i64| -> bool {
        if count > nodes.len() {
            return false;
        }
        let mut expected = at;
        for j in (nodes.len() - count..nodes.len()).rev() {
            let node = &nodes[j];
            if !node.ok || (node.end != expected - 1 && !(node.twin && node.end == expected)) {
                return false;
            }
            expected = node.start;
        }
        true
    };
    let single = |node: Option<&Node>, i: usize| -> bool {
        match node {
            Some(n) => n.ok && n.start == n.end && n.start >= 0 && s.kinds[at(n.start as usize)] & kind::PURE != 0 && n.end < i as i64,
            None => false,
        }
    };
    for i in first..end {
        let ii = i as i64;
        let k = at(i);
        if i == first || flags[i] & iflag::LABEL != 0 {
            nodes.clear();
            // A handler starts with the exception on the stack: a value no line can name.
            if s.handlers.contains(&(i as u32)) {
                nodes.push(Node::new(-2, -2, false, 5));
            }
        }
        let op = s.stack_ops[k];
        if op != 0 {
            let len = nodes.len();
            let top = if len > 0 { Some(nodes[len - 1]) } else { None };
            let below = if len > 1 { Some(nodes[len - 2]) } else { None };
            if op == stack_op::POP2 && top.is_some_and(|t| is_wide(t.kind)) {
                // pop2 of a long or a double: one value thrown away, as pop does.
            } else if op == stack_op::DUP && top.is_some() {
                let t = top.unwrap();
                if t.ok && t.fill >= 0 && t.end == ii - 1 {
                    // new int[n]; dup; k; v; iastore — the array's initializer, element k = the count so far.
                    let top = &mut nodes[len - 1];
                    top.filling = true;
                    top.ok = false;
                    nodes.push(Node { copy: true, fill_copy: true, ..Node::new(ii, ii, true, 5) });
                } else if t.ok && t.start == t.end && t.end == ii - 1 && t.start >= 0 && s.kinds[at(t.start as usize)] & kind::NEW != 0 {
                    let top = &mut nodes[len - 1];
                    top.construct = true;
                    top.ok = false;
                    nodes.push(Node { copy: true, init: true, ..Node::new(ii, ii, true, 5) });
                } else {
                    let pure = single(top.as_ref(), i) && t.end == ii - 1;
                    nodes[len - 1].ok = pure;
                    nodes.push(Node { copy: true, ..Node::new(ii, ii, pure, t.kind) });
                }
                continue;
            } else if op == stack_op::DUP2 && top.is_some_and(|t| is_wide(t.kind)) {
                let t = top.unwrap();
                let pure = single(top.as_ref(), i) && t.end == ii - 1;
                nodes[len - 1].ok = pure;
                nodes.push(Node { copy: true, ..Node::new(ii, ii, pure, t.kind) });
                continue;
            } else if op == stack_op::DUP2
                && top.is_some()
                && below.is_some()
                && !is_wide(top.unwrap().kind)
                && !is_wide(below.unwrap().kind)
                && single(top.as_ref(), i)
                && single(below.as_ref(), i)
                && top.unwrap().end == ii - 1
                && below.unwrap().end == top.unwrap().start - 1
            {
                let (t, b) = (top.unwrap(), below.unwrap());
                nodes.push(Node { copy: true, twin: true, ..Node::new(ii, ii, true, b.kind) });
                nodes.push(Node { copy: true, ..Node::new(ii, ii, true, t.kind) });
                continue;
            } else {
                nodes.clear();
                continue;
            }
        }
        // pop2 that got here throws away one long or double.
        let popped = if op == stack_op::POP2 { 1 } else { s.pops[k] as usize };
        let pushed = s.pushes[k];
        if pushed < 0 || (s.kinds[k] & kind::BARRIER != 0 && pushed > 0) {
            nodes.clear();
            continue;
        }
        let fold = folds(&nodes, popped, ii);
        let bottom = if fold && popped > 0 { Some(nodes[nodes.len() - popped]) } else { None };
        let start = bottom.map_or(ii, |b| b.start);
        let copy = bottom.is_some_and(|b| b.copy);
        if s.kinds[k] & kind::INIT != 0 && bottom.is_some_and(|b| b.init) {
            let b = bottom.unwrap();
            if nodes.len() > popped {
                let made = nodes.len() - popped - 1;
                if nodes[made].construct && nodes[made].end == b.start - 1 {
                    nodes.truncate(nodes.len() - popped);
                    let m = &mut nodes[made];
                    m.end = ii;
                    m.ok = true;
                    m.construct = false;
                    continue;
                }
            }
        }
        if s.kinds[k] & kind::ARRAY_STORE != 0 && bottom.is_some_and(|b| b.fill_copy) {
            let b = bottom.unwrap();
            let len = nodes.len();
            if len >= 4 {
                let array = nodes[len - 4];
                let at_node = nodes[len - 2];
                if array.filling
                    && array.end == b.start - 1
                    && at_node.start == at_node.end
                    && at_node.start >= 0
                    && s.kinds[at(at_node.start as usize)] & kind::INT != 0
                    && s.ints[at(at_node.start as usize)] == array.fill
                {
                    nodes.truncate(len - 3);
                    let a = &mut nodes[len - 4];
                    a.end = ii;
                    a.ok = true;
                    a.filling = false;
                    a.fill += 1;
                    continue;
                }
            }
        }
        if popped > nodes.len() {
            nodes.clear();
        } else {
            nodes.truncate(nodes.len() - popped);
        }
        if pushed == 0 {
            // A line that takes a dup's copy without the value it copied would need that value from before it.
            if fold && popped > 0 && !copy {
                for f in &mut flags[start as usize..i] {
                    *f |= iflag::FUSE;
                }
            }
        } else {
            let ok = (fold || popped == 0) && s.kinds[k] & kind::OPAQUE == 0;
            nodes.push(Node { copy, fill: if s.kinds[k] & kind::ARRAY != 0 { 0 } else { -1 }, ..Node::new(start, ii, ok, s.push_kinds[k]) });
        }
        if s.kinds[k] & kind::BARRIER != 0 {
            nodes.clear();
        }
    }
}

/// What the value an ldc loads is: by the kind of its constant.
fn constant_kind(cf: &ClassFile, index: usize) -> u8 {
    match cf.tags.get(index).copied().unwrap_or(0) {
        constant::INTEGER => 1,
        constant::LONG => 2,
        constant::FLOAT => 3,
        constant::DOUBLE => 4,
        constant::DYNAMIC => match kind_code(field_kind(cf.dynamic(index).descriptor)) {
            0 => 5,
            k => k,
        },
        _ => 5,
    }
}

/// In entry_shape's number: the method is a constructor.
const SHAPE_INIT: u32 = 1 << 13;

/// What an instruction that names a constant pool entry does to the stack, as one number: the
/// values a call takes besides its object (bits 0–7), whether it leaves one (8–9), its kind
/// (10–12), whether the method is a constructor (13).
fn entry_shape(cf: &ClassFile, name: &str, index: usize) -> u32 {
    let ref_kind = |descriptor: &Wtf8| -> u32 {
        match kind_code(field_kind(descriptor)) {
            0 => 5,
            k => k as u32,
        }
    };
    if name.starts_with("invoke") {
        let (member_name, descriptor) = if name == "invokedynamic" {
            let d = cf.dynamic(index);
            (d.name, d.descriptor)
        } else {
            let m = cf.member(index);
            (m.name, m.descriptor)
        };
        let (params, ret) = descriptor_shape(descriptor);
        return (params.min(255) as u32) | (if ret.is_empty() { 0 } else { 1 << 8 }) | ((kind_code(ret) as u32) << 10) | (if member_name == "<init>" { SHAPE_INIT } else { 0 });
    }
    if name == "getfield" || name == "getstatic" {
        return ref_kind(cf.member(index).descriptor) << 10;
    }
    if name.starts_with("ldc") {
        return (constant_kind(cf, index) as u32) << 10;
    }
    5 << 10
}

/// Loads that read nothing but a variable or a constant: dup may copy them as text.
fn pure_load(name: &str) -> bool {
    let b = name.as_bytes();
    // [ilfda]load(_\d|_w)?
    if b.len() >= 5 && b"ilfda".contains(&b[0]) && &b[1..5] == b"load" {
        let rest = &b[5..];
        return rest.is_empty() || rest == b"_w" || (rest.len() == 2 && rest[0] == b'_' && rest[1].is_ascii_digit());
    }
    // [ilfd]const_m?\d
    if b.len() >= 8 && b"ilfd".contains(&b[0]) && &b[1..7] == b"const_" {
        let rest = &b[7..];
        return (rest.len() == 1 && rest[0].is_ascii_digit()) || (rest.len() == 2 && rest[0] == b'm' && rest[1].is_ascii_digit());
    }
    matches!(name, "aconst_null" | "bipush" | "sipush" | "ldc" | "ldc_w" | "ldc2_w")
}

/* ------------------------------------------------------------------ *
 * The pass
 * ------------------------------------------------------------------ */

/// A branch's target found in a method, resolved once its instructions are known: the
/// instruction, the target pc, and the slot (a switch's case, its default after them; -1 for a
/// plain branch).
struct Pending {
    from: u32,
    target: i64,
    slot: i32,
}

/// Decoding the methods, a batch at a time.
struct Pass {
    program: JvmProgram,
    capacity: usize,
    next: usize,
    total: usize,
    mnemonic_ids: Vec<i32>,
    pure: Vec<bool>,
    at: Vec<i32>,
    insn: JvmInsn,
    stack: Stack,
    callers: RefBuilder,
    data_refs: RefBuilder,
    field_refs: RefBuilder,
    last_class: i64,
    /// Branch → its targets (instruction indices), and whether it is a switch.
    targets: Vec<(u32, bool, Vec<u32>)>,
}

impl Pass {
    fn new(classes: Vec<ClassFile>, container: Container) -> Pass {
        let mut program = JvmProgram::new(classes, container);
        program.index();
        let mut capacity = 0;
        for b in &program.bodies {
            capacity += program.classes[b.cls as usize].methods[b.method as usize].code.as_ref().map_or(0, |c| c.length);
        }
        let r = &mut program.result;
        r.offsets = vec![0; capacity];
        r.mnemonic_ids = vec![0; capacity];
        r.flags = vec![0; capacity];
        let mut pure = vec![false; 0x10000];
        for op in all_ops() {
            if pure_load(op.name) {
                pure[op.code as usize] = true;
            }
        }
        Pass {
            program,
            capacity,
            next: 0,
            total: 0,
            mnemonic_ids: vec![-1; 0x10000],
            pure,
            at: Vec::new(),
            insn: JvmInsn::new(),
            stack: Stack::default(),
            callers: RefBuilder::default(),
            data_refs: RefBuilder::default(),
            field_refs: RefBuilder::default(),
            last_class: -1,
            targets: Vec::new(),
        }
    }

    /// Decodes methods until `budget` instructions more are done; true once every method is.
    fn step(&mut self, budget: usize) -> bool {
        let stop = self.total.saturating_add(budget.max(1));
        while self.next < self.program.bodies.len() && self.total < stop {
            self.method(self.next);
            self.next += 1;
        }
        if self.next < self.program.bodies.len() {
            return false;
        }
        self.finish();
        true
    }

    fn method(&mut self, f: usize) {
        let body = self.program.bodies[f];
        let cls = body.cls;
        let first = self.total;
        let (code_offset, code_length) = {
            let code = self.program.classes[cls as usize].methods[body.method as usize].code.as_ref().unwrap();
            (code.offset, code.length)
        };
        let end = code_offset + code_length;
        let mut pending: Vec<Pending> = Vec::new();
        if self.at.len() < code_length {
            self.at = vec![-1; code_length * 2];
        }
        self.at[..code_length].fill(-1);
        let s = &mut self.stack;
        s.pops.clear();
        s.pushes.clear();
        s.push_kinds.clear();
        s.kinds.clear();
        s.stack_ops.clear();
        s.ints.clear();
        s.handlers.clear();
        let mut pos = code_offset;
        while pos < end && self.total < self.capacity {
            let i = self.total;
            self.total += 1;
            let p = &mut self.program;
            let cf = &p.classes[cls as usize];
            decode_at(&cf.bytes, code_offset, pos, end, &mut self.insn);
            let insn = &self.insn;
            let offset = body.base + insn.at as u32;
            p.result.offsets[i] = offset;
            self.at[insn.at] = i as i32;
            let code0 = insn.op.map_or(0xffff, |op| op.code as usize);
            let mut id = self.mnemonic_ids[code0];
            if id < 0 {
                id = p.result.mnemonics.len() as i32;
                self.mnemonic_ids[code0] = id;
                p.result.mnemonics.push(insn.m);
                p.result.counts.push(0);
            }
            p.result.mnemonic_ids[i] = id as u16;
            p.result.counts[id as usize] += 1;
            pos += insn.len;
            let s = &mut self.stack;
            s.pops.push(0);
            s.pushes.push(0);
            s.push_kinds.push(0);
            s.kinds.push(0);
            s.stack_ops.push(0);
            s.ints.push(0);
            let k = i - first;
            let Some(op) = insn.op else {
                p.result.flags[i] |= iflag::UNKNOWN;
                s.pushes[k] = -1;
                continue;
            };
            // The stack: what it takes and leaves, and what kind of value; what a constant pool entry says is worked out once per class.
            let mut pop = op.pop as i32;
            let mut pushed = op.push as i32;
            let mut kind = kind_code(op.kind) as u32;
            let mut init = false;
            let index = pool_index(insn);
            if (stack_op::POP2 as u16..=stack_op::SWAP as u16).contains(&op.code) {
                s.stack_ops[k] = op.code as u8;
            } else if index != 0 && (op.flags & F::CALL != 0 || op.pop < 0 || op.push < 0 || kind == 0) {
                p.pool.enter(cls, cf.tags.len());
                let slot = PoolCache::slot(&mut p.pool.shape, index);
                if *slot == UNSEEN {
                    *slot = entry_shape(cf, op.name, index);
                }
                let shape = *slot;
                if op.flags & F::CALL != 0 {
                    pop = (shape & 0xff) as i32 + if op.name == "invokestatic" || op.name == "invokedynamic" { 0 } else { 1 };
                    pushed = ((shape >> 8) & 3) as i32;
                    init = shape & SHAPE_INIT != 0;
                }
                kind = (shape >> 10) & 7;
                if op.operand == Operand::Dimensions {
                    pop = insn.b;
                    kind = 5;
                }
            }
            s.pops[k] = pop.max(0) as i16;
            s.pushes[k] = pushed as i8;
            s.push_kinds[k] = kind as u8;
            let c = op.code;
            s.kinds[k] = (if op.flags & (F::END | F::BRANCH) != 0 { kind::BARRIER } else { 0 })
                | (if self.pure[c as usize] { kind::PURE } else { 0 })
                | (if c == 0xbb { kind::NEW } else { 0 })
                | (if init && c == 0xb7 { kind::INIT } else { 0 })
                | (if c == 0xbc || c == 0xbd { kind::ARRAY } else { 0 })
                | (if (0x4f..=0x56).contains(&c) { kind::ARRAY_STORE } else { 0 });
            let tag = cf.tags.get(index).copied().unwrap_or(0);
            // A method handle, a method type or a dynamic constant has no form in a line: its ldc stays an instruction.
            if (0x12..=0x14).contains(&c) && (tag == constant::METHOD_HANDLE || tag == constant::METHOD_TYPE || tag == constant::DYNAMIC) {
                s.kinds[k] |= kind::OPAQUE;
            }
            if (0x02..=0x08).contains(&c) || c == 0x10 || c == 0x11 {
                s.kinds[k] |= kind::INT;
                s.ints[k] = if c <= 0x08 { c as i32 - 0x03 } else { insn.a as i32 };
            }

            if op.flags & F::BRANCH != 0 {
                p.result.flags[i] |= iflag::BRANCH;
                for (slot, &target) in insn.targets.iter().enumerate() {
                    pending.push(Pending { from: i as u32, target, slot: slot as i32 });
                }
                if op.operand == Operand::TableSwitch || op.operand == Operand::LookupSwitch {
                    pending.push(Pending { from: i as u32, target: insn.a, slot: insn.targets.len() as i32 });
                } else {
                    pending.push(Pending { from: i as u32, target: insn.a, slot: -1 });
                }
            }
            if op.flags & F::CALL != 0 {
                p.result.flags[i] |= iflag::CALL;
                if op.operand == Operand::Dynamic {
                    p.dynamic_calls += 1;
                    // The methods a call site's bootstrap is given (a lambda's body, a method reference) are taken, not called.
                    let bootstrap = cf.dynamic(index).bootstrap as usize;
                    let args: Vec<u16> = cf.bootstrap_methods().get(bootstrap).map(|b| b.args.clone()).unwrap_or_default();
                    for arg in args {
                        if p.classes[cls as usize].tags.get(arg as usize).copied() != Some(constant::METHOD_HANDLE) {
                            continue;
                        }
                        if let Some(target) = p.callee(cls, arg as usize) {
                            self.data_refs.add(p.target_addr(target) as i64, i as u32);
                        }
                    }
                } else if let Some(callee) = p.callee(cls, index) {
                    self.callers.add(p.target_addr(callee) as i64, i as u32);
                }
                continue;
            }
            if matches!(op.name, "getfield" | "putfield" | "getstatic" | "putstatic") {
                let addr = p.field_addr(cls, index);
                self.field_refs.add(addr as i64, i as u32);
            }
            if index != 0 && matches!(op.operand, Operand::Cp8 | Operand::Cp16 | Operand::Dimensions) {
                if tag == constant::STRING {
                    let addr = p.string_addr(cls, index);
                    self.data_refs.add(addr as i64, i as u32);
                } else if tag == constant::METHOD_HANDLE {
                    if let Some(target) = p.callee(cls, index) {
                        self.data_refs.add(p.target_addr(target) as i64, i as u32);
                    }
                }
            }
        }
        let total = self.total;
        let flags = &mut self.program.result.flags;
        for pend in &pending {
            let to = if pend.target >= 0 && (pend.target as usize) < code_length { self.at[pend.target as usize] } else { -1 };
            if to < 0 {
                continue;
            }
            flags[to as usize] |= iflag::LABEL;
            if pend.slot >= 0 {
                match self.targets.last_mut() {
                    Some((from, true, list)) if *from == pend.from => list.push(to as u32),
                    _ => self.targets.push((pend.from, true, vec![to as u32])),
                }
            } else {
                self.targets.push((pend.from, false, vec![to as u32]));
            }
        }
        let cf = &self.program.classes[cls as usize];
        let code = cf.methods[body.method as usize].code.as_ref().unwrap();
        for handler in &code.handlers {
            for (pc, is_handler) in [(handler.start as usize, false), (handler.handler as usize, true)] {
                let index = if pc < code_length { self.at[pc] } else { -1 };
                if index < 0 {
                    continue;
                }
                flags[index as usize] |= iflag::LABEL;
                if is_handler {
                    self.stack.handlers.push(index as u32);
                }
            }
        }
        let p = &mut self.program;
        let fn_ = &mut p.functions[f];
        fn_.first = first as u32;
        fn_.count = (total - first) as u32;
        group_statements(&mut p.result.flags, first, total, &self.stack);
        let flags = &mut p.result.flags;
        if first < flags.len() {
            flags[first] |= iflag::FUNCTION;
            flags[first] &= !iflag::LABEL;
        }
        // The methods of one class make one range of the listing.
        if cls as i64 != self.last_class {
            self.last_class = cls as i64;
            p.ranges.push(Range { cls, first: first as u32, count: 0 });
        }
        p.ranges.last_mut().unwrap().count += (total - first) as u32;
    }

    fn finish(&mut self) {
        let total = self.total;
        let p = &mut self.program;
        let mut callees: Vec<(u64, f64)> = p.resolved.iter().map(|&(k, t)| (k, t.map_or(-1.0, |t| p.target_addr(t) as f64))).collect();
        callees.sort_unstable_by_key(|c| c.0);
        callees.dedup_by_key(|c| c.0);
        let mut fields = std::mem::take(&mut p.field_resolved);
        fields.sort_unstable_by_key(|c| c.0);
        fields.dedup_by_key(|c| c.0);
        p.entry = find_entry(p);
        if let Some(e) = p.entry {
            p.functions[e as usize].kind = FnKind::Entry;
        }
        let r = &mut p.result;
        r.offsets.truncate(total);
        r.mnemonic_ids.truncate(total);
        r.flags.truncate(total);
        r.callers = std::mem::take(&mut self.callers).build();
        r.data_refs = std::mem::take(&mut self.data_refs).build();
        r.field_refs = std::mem::take(&mut self.field_refs).build();
        for (from, list, targets) in self.targets.drain(..) {
            r.target_index.push(from);
            r.target_starts.push(r.target_values.len() as u32);
            r.target_values.extend_from_slice(&targets);
            r.target_lists.push(list as u8);
        }
        r.target_starts.push(r.target_values.len() as u32);
        r.callee_keys = callees.iter().map(|c| c.0 as f64).collect();
        r.callee_values = callees.iter().map(|c| c.1).collect();
        r.field_keys = fields.iter().map(|c| c.0 as f64).collect();
        r.field_values = fields.iter().map(|c| c.1 as f64).collect();
    }
}

/// The method the program starts at: Main-Class's `main`, else the only class with one.
fn find_entry(p: &JvmProgram) -> Option<u32> {
    let is_main = |b: &Body| {
        let cf = &p.classes[b.cls as usize];
        let m = &cf.methods[b.method as usize];
        let descriptor = cf.utf8(m.descriptor_index as usize);
        cf.utf8(m.name_index as usize) == "main" && (descriptor == "([Ljava/lang/String;)V" || descriptor == "()V") && (m.access & 0x0008 != 0 || descriptor == "()V")
    };
    if let Some(main_class) = p.container.manifest_value("Main-Class") {
        let main_class = js_trim(main_class).replace('.', "/");
        if !main_class.is_empty() {
            let cls = p.class_index.get(Wtf8::new(&main_class)).copied();
            if let Some(at) = p.bodies.iter().position(|b| Some(b.cls) == cls && is_main(b)) {
                return Some(at as u32);
            }
        }
    }
    let mains: Vec<u32> = p.bodies.iter().enumerate().filter(|(_, b)| is_main(b)).map(|(k, _)| k as u32).collect();
    if mains.len() == 1 || (!mains.is_empty() && p.container.kind == ContainerKind::Class) {
        Some(mains[0])
    } else {
        None
    }
}

/* ------------------------------------------------------------------ *
 * The session
 * ------------------------------------------------------------------ */

enum Stage {
    Reading(Box<Reading>),
    Decoding(Box<Pass>),
    Done(Box<JvmProgram>),
    /// Only the classes were wanted (`analyse` false), which the page reads one at a time.
    Read(Vec<ClassFile>),
}

/// Opening a file of Java classes and analysing it, in steps.
pub struct JvmSession {
    stage: Option<Stage>,
    analyse: bool,
    /// What the HLA64 lines of the rows on screen have worked out of their methods.
    lines: JvmLines,
}

/// The classes a step reads, for every `budget` instructions it may decode.
const CLASSES_PER_BUDGET: usize = 256;

impl JvmSession {
    /// Opens a class file, a JAR, a .jmod or an AAR. With `analyse` false, only the classes are read.
    pub fn open(file: Vec<u8>, analyse: bool) -> Result<JvmSession, ReadError> {
        let stage = match open(file)? {
            Opened::Done(classes, container) => Self::after_reading(classes, container, analyse),
            Opened::Reading(reading) => Stage::Reading(reading),
        };
        Ok(JvmSession { stage: Some(stage), analyse, lines: JvmLines::default() })
    }

    fn after_reading(classes: Vec<ClassFile>, container: Container, analyse: bool) -> Stage {
        if analyse {
            Stage::Decoding(Box::new(Pass::new(classes, container)))
        } else {
            Stage::Read(classes)
        }
    }

    /// Works on for about `budget` instructions; true once the program is ready.
    pub fn step(&mut self, budget: usize) -> bool {
        let stage = self.stage.take().expect("a session in a step");
        let next = match stage {
            Stage::Reading(mut reading) => {
                if reading.step((budget / CLASSES_PER_BUDGET).max(1)) {
                    let Reading { classes, container, .. } = *reading;
                    Self::after_reading(classes, container, self.analyse)
                } else {
                    Stage::Reading(reading)
                }
            }
            Stage::Decoding(mut pass) => {
                if pass.step(budget) {
                    Stage::Done(Box::new(pass.program))
                } else {
                    Stage::Decoding(pass)
                }
            }
            done => done,
        };
        let ready = matches!(next, Stage::Done(_) | Stage::Read(_));
        self.stage = Some(next);
        ready
    }

    /// How far the work is: (done, total) of the classes being read, then of the methods decoded.
    pub fn progress(&self) -> (usize, usize) {
        match self.stage.as_ref().unwrap() {
            Stage::Reading(r) => (r.next, r.wanted.len()),
            Stage::Decoding(p) => (p.next, p.program.bodies.len()),
            Stage::Done(p) => (p.bodies.len(), p.bodies.len()),
            Stage::Read(c) => (c.len(), c.len()),
        }
    }

    pub fn program(&self) -> Option<&JvmProgram> {
        match self.stage.as_ref()? {
            Stage::Done(p) => Some(p),
            _ => None,
        }
    }

    /// The HLA64 line of the instructions first..=last, once the program is ready.
    pub fn lift_group(&mut self, first: usize, last: usize, names: &dyn JvmNaming) -> Option<HlaLine> {
        let Some(Stage::Done(p)) = self.stage.as_ref() else { return None };
        if first > last || last >= p.result.offsets.len() {
            return None;
        }
        self.lines.lift_group(p, first, last, names)
    }

    /// The parameters of a method's HLA64 header (`JvmLines::header_params`), once the program is ready.
    pub fn header_params(&mut self, fn_index: usize) -> Vec<(String, String)> {
        let Some(Stage::Done(p)) = self.stage.as_ref() else { return Vec::new() };
        if fn_index >= p.functions.len() {
            return Vec::new();
        }
        self.lines.header_params(p, fn_index)
    }

    /// The classes, once read.
    pub fn classes(&self) -> &[ClassFile] {
        match self.stage.as_ref() {
            Some(Stage::Done(p)) => &p.classes,
            Some(Stage::Read(c)) => c,
            _ => &[],
        }
    }

    /// Opens and analyses a file at once.
    pub fn analyse(file: Vec<u8>) -> Result<JvmProgram, ReadError> {
        let mut session = JvmSession::open(file, true)?;
        while !session.step(usize::MAX) {}
        match session.stage.take() {
            Some(Stage::Done(p)) => Ok(*p),
            _ => unreachable!(),
        }
    }
}
