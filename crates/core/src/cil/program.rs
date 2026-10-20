//! The analysis of a .NET assembly, a port of src/core/cil/program.ts and
//! effects.ts: every method body is decoded once, and from that pass come the
//! statistics, the methods (the functions of the listing, named
//! `Namespace.Type::Method`), the labels branches and exception handlers go
//! to, the calls — to methods of this assembly, and to members of others,
//! which are its imports — and the groups of instructions the HLA64 view
//! writes as one line.
//!
//! An instruction's address is its RVA; a string of #US or a member of another
//! assembly is addressed by its metadata token. What the page shows of the
//! metadata is read in page.rs, over the same session.

use super::decode::{decode_at, CilInsn};
use super::hla::CilLines;
use super::metadata::{self as m, compressed, decode_index, table as t, token, token_row, token_table, utf8, Coded, Metadata, MetadataError, MethodBody, Section};
use super::names::{proper_name, Names, NO_CONTEXT};
use super::opcodes::{f, operand, OpInfo};
use crate::disassembly::iflag;
use crate::lift::HlaLine;
use crate::refs::{FxHashMap, FxHashSet, RefBuilder, RefIndex};

/// How a method is known: the entry point, a public method of a public type, or any other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FnKind {
    Entry,
    Export,
    Symbol,
}

impl FnKind {
    pub fn as_str(self) -> &'static str {
        match self {
            FnKind::Entry => "entry",
            FnKind::Export => "export",
            FnKind::Symbol => "symbol",
        }
    }
}

/// A method with code.
#[derive(Clone, Debug)]
pub struct Function {
    /// The MethodDef row.
    pub method: u32,
    /// The RVA of its first instruction (past the header).
    pub addr: u64,
    pub first: u32,
    pub count: u32,
    pub kind: FnKind,
    /// `Ns.Type::Name<T>`, the declaration, and the name as the metadata has it.
    pub name: String,
    pub full: String,
    pub raw: String,
    /// Its TypeDef row.
    pub owner: u32,
}

/// A member of another assembly the code uses: a method or a field, through a MemberRef.
#[derive(Clone, Debug)]
pub struct Import {
    pub token: u32,
    pub name: String,
    pub full: String,
    pub raw: String,
    pub assembly: String,
    pub ty: String,
    pub field: bool,
}

/// A P/Invoke: a method whose code is a function of a native library.
#[derive(Clone, Debug)]
pub struct PInvoke {
    pub method: u32,
    pub name: String,
    pub library: String,
    pub entry: String,
    pub flags: u32,
}

/// The functions of one type: one range of the listing.
#[derive(Clone, Debug)]
pub struct Range {
    pub first: u32,
    pub count: u32,
    /// `.class Ns.Type`, or None for the global functions.
    pub class: Option<String>,
}

/// Where a clause's part starts.
pub mod part {
    pub const TRY: u8 = 0;
    pub const HANDLER: u8 = 1;
    pub const FILTER: u8 = 2;
}

#[derive(Default)]
pub struct CilProgram {
    pub offsets: Vec<u32>,
    pub mnemonic_ids: Vec<u16>,
    pub flags: Vec<u8>,
    pub mnemonics: Vec<&'static str>,
    pub counts: Vec<u32>,
    pub functions: Vec<Function>,
    pub imported: Vec<Import>,
    pub pinvokes: Vec<PInvoke>,
    pub ranges: Vec<Range>,
    pub callers: RefIndex,
    pub data_refs: RefIndex,
    pub field_refs: RefIndex,
    pub type_refs: RefIndex,
    /// Branches: the instruction, where its run of targets starts in `target_values`.
    pub target_index: Vec<u32>,
    pub target_starts: Vec<u32>,
    pub target_values: Vec<u32>,
    /// Where exception-handling regions start: instruction, the clause's place in its body, the part — in the order they were found.
    pub regions: Vec<u32>,
    /// Calls through a function pointer (calli) and through a delegate's Invoke.
    pub indirect_calls: u32,
}

/* ------------------------------------------------------------------ *
 * Stack effects
 * ------------------------------------------------------------------ */

/// A method signature's shape: whether it has `this`, how many parameters, whether it returns a value.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Shape {
    pub instance: bool,
    pub params: u32,
    pub returns: bool,
}

/// The shape of a method signature blob (MethodDefSig, MethodRefSig, StandAloneMethodSig).
pub(crate) fn shape_of(blob: &[u8]) -> Shape {
    let at = |p: usize| blob.get(p).copied().unwrap_or(0) as u32;
    let mut p = 0;
    let conv = at(p);
    p += 1;
    let u = |p: &mut usize| -> u32 {
        let b = at(*p);
        if b & 0x80 == 0 {
            *p += 1;
            b
        } else if b & 0xc0 == 0x80 {
            *p += 2;
            (b & 0x3f) << 8 | at(*p - 1)
        } else {
            *p += 4;
            (b & 0x1f) << 24 | at(*p - 3) << 16 | at(*p - 2) << 8 | at(*p - 1)
        }
    };
    if conv & 0x10 != 0 {
        u(&mut p);
    }
    let params = u(&mut p);
    // The return type: custom modifiers, then void (0x01) or anything else.
    while matches!(blob.get(p), Some(0x1f | 0x20)) {
        p += 1;
        u(&mut p);
    }
    Shape { instance: conv & 0x20 != 0 && conv & 0x40 == 0, params, returns: blob.get(p) != Some(&0x01) }
}

/// The signature blob of a method token (through a MethodSpec to its method).
pub(crate) fn method_blob(md: &Metadata, tok: u32) -> &[u8] {
    let (mut table, mut row) = (token_table(tok) as i16, token_row(tok));
    if table == t::METHOD_SPEC as i16 {
        (table, row) = decode_index(Coded::MethodDefOrRef, md.get(m::METHOD_SPEC_METHOD, row));
    }
    if table == t::METHOD_DEF as i16 {
        return md.blob(md.get(m::METHOD_DEF_SIGNATURE, row));
    }
    if table == t::MEMBER_REF as i16 {
        return md.blob(md.get(m::MEMBER_REF_SIGNATURE, row));
    }
    &[]
}

/// Loads that read nothing but a variable or a constant: `dup` may copy them as text.
fn pure_load(name: &str) -> bool {
    matches!(
        name,
        "ldarg.0"
            | "ldarg.1"
            | "ldarg.2"
            | "ldarg.3"
            | "ldarg.s"
            | "ldarg"
            | "ldloc.0"
            | "ldloc.1"
            | "ldloc.2"
            | "ldloc.3"
            | "ldloc.s"
            | "ldloc"
            | "ldnull"
            | "ldstr"
            | "ldc.i4.m1"
            | "ldc.i4.0"
            | "ldc.i4.1"
            | "ldc.i4.2"
            | "ldc.i4.3"
            | "ldc.i4.4"
            | "ldc.i4.5"
            | "ldc.i4.6"
            | "ldc.i4.7"
            | "ldc.i4.8"
            | "ldc.i4.s"
            | "ldc.i4"
            | "ldc.i8"
            | "ldc.r4"
            | "ldc.r8"
    )
}

/* ------------------------------------------------------------------ *
 * Grouping the statements of the HLA64 view
 * ------------------------------------------------------------------ */

const BARRIER: u8 = 1;
const PURE: u8 = 2;

/// A value on the stack while the statements are grouped: the instructions that made it (-2: the exception a handler starts with).
#[derive(Clone, Copy)]
struct Node {
    start: i64,
    end: i64,
    ok: bool,
    /// Its instructions start with a dup: the line must also take the value the dup copied, right below it.
    copy: bool,
}

fn folds(nodes: &[Node], count: i64, at: i64) -> bool {
    if count > nodes.len() as i64 {
        return false;
    }
    if count <= 0 {
        return true;
    }
    let mut expected = at;
    for node in nodes[nodes.len() - count as usize..].iter().rev() {
        if !node.ok || node.end != expected - 1 {
            return false;
        }
        expected = node.start;
    }
    true
}

/// Marks the runs of instructions that make one statement of the HLA64 view (see
/// `groupStatements` in src/core/cil/program.ts, and src/core/cil/hla.ts, which must agree).
fn group_statements(flags: &mut [u8], first: usize, end: usize, pops: &[i16], pushes: &[i8], kinds: &[u8], starts: &FxHashMap<u32, Vec<(u32, u8)>>) {
    let mut nodes: Vec<Node> = Vec::new();
    for i in first..end {
        let k = i - first;
        if i == first || flags[i] & iflag::LABEL != 0 {
            nodes.clear();
            // A catch or filter starts with the exception on the stack: a value no line can name.
            for &(kind, p) in starts.get(&(i as u32)).map_or(&[][..], |v| v.as_slice()) {
                if (p == part::HANDLER && kind & 6 == 0) || p == part::FILTER {
                    nodes.push(Node { start: -2, end: -2, ok: false, copy: false });
                }
            }
        }
        let popped = pops[k] as i64;
        let pushed = pushes[k];
        if pushed < 0 || (kinds[k] & BARRIER != 0 && pushed > 0) {
            nodes.clear();
            continue;
        }
        let fold = folds(&nodes, popped, i as i64);
        let below = if fold && popped != 0 { (nodes.len() as i64 - popped).try_into().ok().and_then(|j: usize| nodes.get(j)).copied() } else { None };
        let start = below.map_or(i as i64, |n| n.start);
        let copy = below.is_some_and(|n| n.copy);
        if pushed == 2 {
            // dup: the copy is the dup itself, and both are values only when a variable or a constant is copied.
            let Some(source) = nodes.last_mut() else {
                nodes.clear();
                continue;
            };
            let pure = source.ok && source.start == source.end && source.end == i as i64 - 1 && source.start >= 0 && kinds[(source.start as usize) - first] & PURE != 0;
            source.ok = pure;
            nodes.push(Node { start: i as i64, end: i as i64, ok: pure, copy: true });
            continue;
        }
        if popped > nodes.len() as i64 {
            nodes.clear();
        } else if popped > 0 {
            nodes.truncate(nodes.len() - popped as usize);
        }
        if pushed == 0 {
            // A line that takes a dup's copy without the value it copied would need that value from before it.
            if fold && popped != 0 && !copy && start >= 0 {
                for flag in &mut flags[start as usize..i] {
                    *flag |= iflag::FUSE;
                }
            }
        } else {
            nodes.push(Node { start, end: i as i64, ok: fold || popped == 0, copy });
        }
        if kinds[k] & BARRIER != 0 {
            nodes.clear();
        }
    }
}

/* ------------------------------------------------------------------ *
 * The assembly before the pass: functions, imports, P/Invoke
 * ------------------------------------------------------------------ */

/// Where a method token leads: a function here, or a member of another assembly.
#[derive(Clone, Copy)]
enum Callee {
    Function(usize),
    Import(usize),
}

/// Is a type visible outside the assembly: public, and nested only in public types?
fn visible(md: &Metadata, names: &Names, mut ty: u32) -> bool {
    for _ in 0..32 {
        if ty == 0 {
            break;
        }
        let vis = md.get(m::TYPE_DEF_FLAGS, ty) & 7;
        let Some(&outer) = names.enclosing.get(&ty) else { return vis == 1 };
        if vis != 2 && vis != 4 && vis != 7 {
            return false;
        }
        ty = outer;
    }
    false
}

/// A name of #Strings as the page reads it, to compare names by: its bytes when they are plain
/// UTF-8, else the text the page decodes from them.
fn name_key(bytes: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    if std::str::from_utf8(bytes).is_ok() && !bytes.starts_with(b"\xEF\xBB\xBF") {
        std::borrow::Cow::Borrowed(bytes)
    } else {
        std::borrow::Cow::Owned(utf8(bytes).into_bytes())
    }
}

/// What MemberRefs of classes defined here stand for: each MemberRef's MethodDef (0: none), and
/// each type's methods by name, in order, made when the type is first asked about.
#[derive(Default)]
pub(crate) struct Locals {
    found: FxHashMap<u32, u32>,
    by_type: FxHashMap<u32, FxHashMap<Box<[u8]>, Vec<u32>>>,
}

struct Pass {
    md: Metadata,
    p: CilProgram,
    bodies: Vec<MethodBody>,
    method_owner: Vec<u32>,
    /// MethodDef row → its function.
    method_fn: FxHashMap<u32, usize>,
    import_by_token: FxHashMap<u32, usize>,
    locals: Locals,
    /// `.class` names of the types that own functions.
    class_names: FxHashMap<u32, String>,
    shapes: FxHashMap<u32, Shape>,
    callers: RefBuilder,
    data_refs: RefBuilder,
    field_refs: RefBuilder,
    type_refs: RefBuilder,
    /// Every resolved branch target, as (branch, target), in the order of the branches: a switch's together.
    targets: Vec<(u32, u32)>,
    capacity: usize,
    next: usize,
    last_type: Option<u32>,
    mnemonic_of: [u16; 512],
    insn: CilInsn,
    /// Per instruction of the function being read: IL offset → instruction (u32::MAX: none).
    at: Vec<u32>,
    pops: Vec<i16>,
    pushes: Vec<i8>,
    kinds: Vec<u8>,
}

/// The MethodDef a MemberRef stands for when its class is defined here (a generic one, through a TypeSpec): matched by name and signature.
pub(crate) fn local_method(md: &Metadata, method_owner: &[u32], locals: &mut Locals, member_ref: u32) -> u32 {
    if let Some(&found) = locals.found.get(&member_ref) {
        return found;
    }
    let (table, row) = decode_index(Coded::MemberRefParent, md.get(m::MEMBER_REF_CLASS, member_ref));
    let mut ty = 0;
    if table == t::TYPE_DEF as i16 {
        ty = row;
    } else if table == t::METHOD_DEF as i16 {
        ty = method_owner.get(row as usize).copied().unwrap_or(0);
    } else if table == t::TYPE_SPEC as i16 {
        let blob = md.blob(md.get(m::TYPE_SPEC_SIGNATURE, row));
        if blob.first() == Some(&0x15) {
            let (value, _) = compressed(blob, 2);
            if value & 3 == 0 {
                ty = value >> 2;
            }
        }
    }
    let mut found = 0;
    if ty != 0 {
        let methods = locals.by_type.entry(ty).or_insert_with(|| {
            let mut by_name: FxHashMap<Box<[u8]>, Vec<u32>> = FxHashMap::default();
            let (start, end) = md.range(m::TYPE_DEF_METHOD_LIST, ty, t::METHOD_DEF);
            for method in start..end {
                by_name.entry(name_key(md.string_bytes(md.get(m::METHOD_DEF_NAME, method))).into()).or_default().push(method);
            }
            by_name
        });
        let sig = md.blob(md.get(m::MEMBER_REF_SIGNATURE, member_ref));
        let name = name_key(md.string_bytes(md.get(m::MEMBER_REF_NAME, member_ref)));
        if let Some(list) = methods.get(name.as_ref()) {
            found = list.iter().copied().find(|&method| md.blob(md.get(m::METHOD_DEF_SIGNATURE, method)) == sig).unwrap_or(0);
        }
    }
    locals.found.insert(member_ref, found);
    found
}

/// The members of other assemblies the code may use: every MemberRef whose class is not defined here; and the P/Invokes.
fn collect_imports(md: &Metadata, names: &mut Names, locals: &mut Locals, p: &mut CilProgram) {
    for r in 1..=md.rows(t::MEMBER_REF) {
        let (table, row) = decode_index(Coded::MemberRefParent, md.get(m::MEMBER_REF_CLASS, r));
        let mut type_ref = 0;
        let mut type_text = String::new();
        if table == t::TYPE_REF as i16 {
            type_ref = row;
            type_text = names.type_ref(row);
        } else if table == t::TYPE_SPEC as i16 {
            if local_method(md, &names.method_owner, locals, r) != 0 {
                continue;
            }
            let blob = md.blob(md.get(m::TYPE_SPEC_SIGNATURE, row));
            match blob.first() {
                Some(0x15) => {
                    let (value, _) = compressed(blob, 2);
                    if value & 3 == 1 {
                        type_ref = value >> 2;
                    } else {
                        continue;
                    }
                }
                Some(0x14 | 0x1d) => type_text = names.type_spec(row, NO_CONTEXT),
                _ => continue,
            }
            if type_ref != 0 {
                type_text = names.type_spec(row, NO_CONTEXT);
            }
        } else if table == t::MODULE_REF as i16 {
            type_text = format!("[.module {}]", md.string(md.get(m::MODULE_REF_NAME, row)));
        } else {
            continue;
        }
        let tok = token(t::MEMBER_REF, r);
        let field = names.is_field_ref(r);
        let name = md.string(md.get(m::MEMBER_REF_NAME, r));
        let assembly = if type_ref != 0 { names.type_ref_assembly(type_ref) } else { String::new() };
        let full = if field { names.field(tok, NO_CONTEXT) } else { names.method(tok, NO_CONTEXT) };
        let owner = if type_ref != 0 {
            let text = names.type_ref(type_ref);
            // Without the assembly: `[System.Runtime]System.Object` → `System.Object`.
            match text.strip_prefix('[').and_then(|rest| rest.find(']').map(|k| rest[k + 1..].to_string())) {
                Some(rest) => rest,
                None => text,
            }
        } else {
            type_text.clone()
        };
        let mut shown = owner;
        shown.push_str("::");
        shown.push_str(&name);
        p.imported.push(Import { token: tok, name: shown, full, raw: name, assembly, ty: type_text, field });
    }
    for r in 1..=md.rows(t::IMPL_MAP) {
        let (table, method) = decode_index(Coded::MemberForwarded, md.get(m::IMPL_MAP_MEMBER, r));
        if table != t::METHOD_DEF as i16 {
            continue;
        }
        let owner = names.method_owner(method);
        let mut name = if owner > 1 { format!("{}::", names.type_def(owner)) } else { String::new() };
        name.push_str(&proper_name(&md.string(md.get(m::METHOD_DEF_NAME, method))));
        p.pinvokes.push(PInvoke {
            method,
            name,
            library: md.string(md.get(m::MODULE_REF_NAME, md.get(m::IMPL_MAP_IMPORT_SCOPE, r))),
            entry: md.string(md.get(m::IMPL_MAP_IMPORT_NAME, r)),
            flags: md.get(m::IMPL_MAP_FLAGS, r),
        });
    }
}

impl Pass {
    fn new(md: Metadata) -> Pass {
        let mut p = CilProgram::default();
        let mut names = Names::new(&md);
        let mut locals = Locals::default();
        collect_imports(&md, &mut names, &mut locals, &mut p);
        let import_by_token = p.imported.iter().enumerate().map(|(k, i)| (i.token, k)).collect();

        // Every method with a body, in the order of the file.
        let mut bodies: Vec<MethodBody> = Vec::new();
        let mut seen = FxHashSet::default();
        for method in 1..=md.rows(t::METHOD_DEF) {
            let Some(body) = md.body(method) else { continue };
            if body.size == 0 || !seen.insert(body.rva) {
                continue;
            }
            bodies.push(body);
        }
        bodies.sort_by_key(|b| b.rva);
        let capacity: usize = bodies.iter().map(|b| b.size).sum();

        // Functions first, so calls can be counted against their addresses.
        let entry = md.header.entry_token;
        let entry_method = if md.header.flags & 0x10 == 0 && token_table(entry) == t::METHOD_DEF { token_row(entry) } else { 0 };
        let mut method_fn = FxHashMap::default();
        let mut class_names = FxHashMap::default();
        for body in &bodies {
            let method = body.method;
            let owner = names.method_owner(method);
            let raw = md.string(md.get(m::METHOD_DEF_NAME, method));
            let type_name = if owner > 1 { names.type_def(owner) } else { String::new() };
            let sig = names.method_def_sig(method);
            let flags = md.get(m::METHOD_DEF_FLAGS, method);
            let kind = if method == entry_method {
                FnKind::Entry
            } else if flags & 7 == 6 && owner != 0 && visible(&md, &names, owner) {
                FnKind::Export
            } else {
                FnKind::Symbol
            };
            let mut shown = String::new();
            if !type_name.is_empty() {
                shown.push_str(&type_name);
                shown.push_str("::");
                class_names.entry(owner).or_insert_with(|| format!(".class {type_name}"));
            }
            shown.push_str(&proper_name(&raw));
            let generics = names.generic_params(true, method);
            if !generics.is_empty() {
                let list: Vec<String> = generics.iter().map(|g| g.as_deref().map_or(String::new(), proper_name)).collect();
                shown.push('<');
                shown.push_str(&list.join(","));
                shown.push('>');
            }
            let mut full = String::with_capacity(sig.ret.len() + shown.len() + sig.params.iter().map(|p| p.len() + 2).sum::<usize>() + 4);
            full.push_str(&sig.ret);
            full.push(' ');
            full.push_str(&shown);
            full.push('(');
            for (k, param) in sig.params.iter().enumerate() {
                if k > 0 {
                    full.push_str(", ");
                }
                full.push_str(param);
            }
            full.push(')');
            method_fn.insert(method, p.functions.len());
            p.functions.push(Function { method, addr: body.rva as u64 + body.header_size as u64, first: 0, count: 0, kind, name: shown, full, raw, owner });
        }
        let method_owner = core::mem::take(&mut names.method_owner);
        drop(names);
        p.offsets.reserve(capacity.min(1 << 26));
        p.mnemonic_ids.reserve(capacity.min(1 << 26));
        p.flags.reserve(capacity.min(1 << 26));
        Pass {
            md,
            p,
            bodies,
            method_owner,
            method_fn,
            import_by_token,
            locals,
            class_names,
            shapes: FxHashMap::default(),
            callers: RefBuilder::default(),
            data_refs: RefBuilder::default(),
            field_refs: RefBuilder::default(),
            type_refs: RefBuilder::default(),
            targets: Vec::new(),
            capacity,
            next: 0,
            last_type: None,
            mnemonic_of: [u16::MAX; 512],
            insn: CilInsn::default(),
            at: Vec::new(),
            pops: Vec::new(),
            pushes: Vec::new(),
            kinds: Vec::new(),
        }
    }

    /// A method token, as the function it reaches here or the member of another assembly.
    fn callee(&mut self, tok: u32) -> Option<Callee> {
        let row = token_row(tok);
        match token_table(tok) {
            t::METHOD_DEF => self.method_fn.get(&row).map(|&f| Callee::Function(f)),
            t::MEMBER_REF => {
                if let Some(&k) = self.import_by_token.get(&tok) {
                    return Some(Callee::Import(k));
                }
                let local = local_method(&self.md, &self.method_owner, &mut self.locals, row);
                self.method_fn.get(&local).map(|&f| Callee::Function(f))
            }
            t::METHOD_SPEC => {
                let (table, target) = decode_index(Coded::MethodDefOrRef, self.md.get(m::METHOD_SPEC_METHOD, row));
                self.callee(token(table as u8, target))
            }
            _ => None,
        }
    }

    fn callee_addr(&self, c: Callee) -> i64 {
        match c {
            Callee::Function(f) => self.p.functions[f].addr as i64,
            Callee::Import(k) => self.p.imported[k].token as i64,
        }
    }

    fn callee_raw(&self, c: Callee) -> &str {
        match c {
            Callee::Function(f) => &self.p.functions[f].raw,
            Callee::Import(k) => &self.p.imported[k].raw,
        }
    }

    fn shape(&mut self, tok: u32) -> Shape {
        if let Some(&s) = self.shapes.get(&tok) {
            return s;
        }
        let md = &self.md;
        let blob = if token_table(tok) == t::STAND_ALONE_SIG { md.blob(md.get(m::STAND_ALONE_SIG_SIGNATURE, token_row(tok))) } else { method_blob(md, tok) };
        let s = shape_of(blob);
        self.shapes.insert(tok, s);
        s
    }

    /// pops and pushes of an instruction, or None when it cannot be known (an opcode that is not one).
    fn effect(&mut self, op: Option<&'static OpInfo>, a: i64, returns: bool) -> Option<(i64, i64)> {
        let op = op?;
        let tok = a as u32;
        match op.name {
            "call" | "callvirt" => {
                let s = self.shape(tok);
                Some((s.params as i64 + s.instance as i64, s.returns as i64))
            }
            "newobj" => Some((self.shape(tok).params as i64, 1)),
            "calli" => {
                let s = self.shape(tok);
                Some((s.params as i64 + s.instance as i64 + 1, s.returns as i64))
            }
            "ret" => Some((returns as i64, 0)),
            "jmp" => Some((0, 0)),
            _ if op.operand == operand::METHOD && op.pop < 0 => None,
            _ => Some((op.pop as i64, op.push as i64)),
        }
    }

    fn mnemonic_id(&mut self, op: Option<&'static OpInfo>, m: &'static str) -> u16 {
        let slot = op.map(|o| if o.code > 0xff { 256 + (o.code & 0xff) as usize } else { o.code as usize });
        if let Some(s) = slot {
            if self.mnemonic_of[s] != u16::MAX {
                return self.mnemonic_of[s];
            }
        }
        let id = match self.p.mnemonics.iter().position(|&known| known == m) {
            Some(id) => id as u16,
            None => {
                self.p.mnemonics.push(m);
                self.p.counts.push(0);
                (self.p.mnemonics.len() - 1) as u16
            }
        };
        if let Some(s) = slot {
            self.mnemonic_of[s] = id;
        }
        id
    }

    /// Decodes functions until about `budget` instructions are done; true once all are.
    fn step(&mut self, budget: usize) -> bool {
        let stop = self.p.offsets.len().saturating_add(budget);
        while self.next < self.bodies.len() {
            if self.p.offsets.len() >= stop {
                return false;
            }
            self.function(self.next);
            self.next += 1;
        }
        self.finish();
        true
    }

    fn function(&mut self, f: usize) {
        let body = core::mem::replace(
            &mut self.bodies[f],
            MethodBody { method: 0, rva: 0, offset: 0, code: 0, size: 0, header_size: 0, max_stack: 0, init_locals: false, fat: false, locals_token: 0, clauses: Vec::new() },
        );
        let first = self.p.offsets.len();
        let code_rva = self.p.functions[f].addr;
        let end = body.code + body.size;
        let returns = shape_of(self.md.blob(self.md.get(m::METHOD_DEF_SIGNATURE, body.method))).returns;
        // Branch targets inside the method, by IL offset, resolved once its instructions are known.
        let mut pending: Vec<(u32, i64, i32)> = Vec::new();
        self.at.clear();
        self.at.resize(body.size, u32::MAX);
        self.pops.clear();
        self.pushes.clear();
        self.kinds.clear();
        let mut insn = core::mem::take(&mut self.insn);
        let mut pos = body.code;
        while pos < end && self.p.offsets.len() < self.capacity {
            let i = self.p.offsets.len() as u32;
            decode_at(&self.md.bytes, body.code, pos, end, &mut insn);
            let addr = (code_rva + insn.at as u64) as u32;
            self.p.offsets.push(addr);
            self.at[insn.at as usize] = i;
            let id = self.mnemonic_id(insn.op, insn.m);
            self.p.mnemonic_ids.push(id);
            self.p.counts[id as usize] += 1;
            self.p.flags.push(0);
            pos += insn.len as usize;
            let op = insn.op;
            let eff = self.effect(op, insn.a, returns);
            // What the HLA64 grouping keeps: the counts as the TypeScript's 16- and 8-bit arrays held them.
            self.pops.push(eff.map_or(0, |e| e.0 as i16));
            self.pushes.push(eff.map_or(-1, |e| e.1 as i8));
            self.kinds.push(op.map_or(0, |o| (if o.flags & (f::END | f::BRANCH | f::PREFIX) != 0 { BARRIER } else { 0 }) | if pure_load(o.name) { PURE } else { 0 }));
            let Some(op) = op else {
                self.p.flags[i as usize] |= iflag::UNKNOWN;
                continue;
            };
            if op.flags & f::BRANCH != 0 {
                self.p.flags[i as usize] |= iflag::BRANCH;
                if insn.is_switch {
                    for (slot, &target) in insn.targets.iter().enumerate() {
                        pending.push((i, target, slot as i32));
                    }
                } else {
                    pending.push((i, insn.a, -1));
                }
            }
            if op.flags & f::CALL != 0 {
                self.p.flags[i as usize] |= iflag::CALL;
                if op.operand == operand::METHOD {
                    let callee = self.callee(insn.a as u32);
                    if let Some(c) = callee {
                        self.callers.add(self.callee_addr(c), i);
                    }
                    if op.name == "callvirt" && callee.is_some_and(|c| self.callee_raw(c) == "Invoke") {
                        self.p.indirect_calls += 1;
                    }
                } else {
                    self.p.indirect_calls += 1;
                }
            } else if op.operand == operand::METHOD {
                // ldftn, ldvirtftn: the method is taken, not called.
                if let Some(c) = self.callee(insn.a as u32) {
                    self.data_refs.add(self.callee_addr(c), i);
                }
            }
            match op.operand {
                operand::STRING => self.data_refs.add(insn.a, i),
                operand::FIELD => self.field_refs.add(insn.a, i),
                operand::TYPE => self.type_refs.add(insn.a, i),
                operand::TOKEN => {
                    let table = token_table(insn.a as u32);
                    if table == t::FIELD || table == t::MEMBER_REF {
                        self.field_refs.add(insn.a, i);
                    } else {
                        self.type_refs.add(insn.a, i);
                    }
                }
                _ => {}
            }
        }
        self.insn = insn;
        let total = self.p.offsets.len();
        let index_at = |at: &[u32], offset: i64| -> Option<u32> { usize::try_from(offset).ok().and_then(|o| at.get(o)).copied().filter(|&i| i != u32::MAX) };
        for (from, target, _) in pending {
            let Some(to) = index_at(&self.at, target) else { continue };
            self.p.flags[to as usize] |= iflag::LABEL;
            self.targets.push((from, to));
        }
        let mut starts: FxHashMap<u32, Vec<(u32, u8)>> = FxHashMap::default();
        for (k, clause) in body.clauses.iter().enumerate() {
            let mut mark = |offset: i64, p: u8| {
                let Some(index) = index_at(&self.at, offset) else { return };
                self.p.flags[index as usize] |= iflag::LABEL;
                self.p.regions.extend_from_slice(&[index, k as u32, p as u32]);
                starts.entry(index).or_default().push((clause.kind, p));
            };
            mark(clause.try_start as i64, part::TRY);
            if clause.kind & 1 != 0 {
                mark(clause.filter_start, part::FILTER);
            }
            mark(clause.handler_start as i64, part::HANDLER);
        }
        self.bodies[f] = body;
        let func = &mut self.p.functions[f];
        func.first = first as u32;
        func.count = (total - first) as u32;
        let owner = func.owner;
        let count = func.count;
        group_statements(&mut self.p.flags, first, total, &self.pops, &self.pushes, &self.kinds, &starts);
        if first < total {
            self.p.flags[first] |= iflag::FUNCTION;
            self.p.flags[first] &= !iflag::LABEL;
        }
        // The functions of one type make one range of the listing.
        if self.last_type != Some(owner) {
            self.last_type = Some(owner);
            let class = if owner > 1 { self.class_names.get(&owner).cloned() } else { None };
            self.p.ranges.push(Range { first: first as u32, count: 0, class });
        }
        self.p.ranges.last_mut().unwrap().count += count;
    }

    fn finish(&mut self) {
        let p = &mut self.p;
        p.callers = core::mem::take(&mut self.callers).build();
        p.data_refs = core::mem::take(&mut self.data_refs).build();
        p.field_refs = core::mem::take(&mut self.field_refs).build();
        p.type_refs = core::mem::take(&mut self.type_refs).build();
        // The branches come in order, each once; a switch's targets one after another.
        for (k, &(from, to)) in self.targets.iter().enumerate() {
            if k == 0 || self.targets[k - 1].0 != from {
                p.target_index.push(from);
                p.target_starts.push(p.target_values.len() as u32);
            }
            p.target_values.push(to);
        }
        p.target_starts.push(p.target_values.len() as u32);
    }
}

/// Analysing a .NET assembly, in steps.
pub struct CilSession {
    pass: Option<Box<Pass>>,
    program: Option<CilProgram>,
    /// The metadata and what the names have worked out, kept for the HLA64 lines of the rows on screen.
    lines: Option<CilLines>,
    total: usize,
}

impl CilSession {
    /// Reads the metadata of a PE file whose sections and CLR directory the page found.
    pub fn open(file: Vec<u8>, sections: Vec<Section>, clr_rva: Option<u32>) -> Result<CilSession, MetadataError> {
        let md = Metadata::read(file, sections, clr_rva)?;
        let pass = Pass::new(md);
        let total = pass.bodies.len();
        Ok(CilSession { pass: Some(Box::new(pass)), program: None, lines: None, total })
    }

    /// Works on for about `budget` instructions; true once the program is ready.
    pub fn step(&mut self, budget: usize) -> bool {
        let Some(pass) = self.pass.as_mut() else { return true };
        if !pass.step(budget) {
            return false;
        }
        let Pass { md, p, bodies, method_fn, import_by_token, locals, .. } = *self.pass.take().unwrap();
        self.program = Some(p);
        self.lines = Some(CilLines::new(md, bodies, method_fn, import_by_token, locals));
        true
    }

    /// The HLA64 line of the instructions first..=last, once the program is ready.
    pub fn lift_group(&mut self, first: usize, last: usize) -> Option<HlaLine> {
        let (p, lines) = (self.program.as_ref()?, self.lines.as_mut()?);
        if first > last || last >= p.offsets.len() {
            return None;
        }
        lines.lift_group(p, first, last)
    }

    /// The page's questions (src/core/cil/page.rs), once the program is ready.
    pub fn page<R>(&mut self, f: impl FnOnce(&mut super::page::Page) -> R) -> Option<R> {
        let (p, lines) = (self.program.as_ref()?, self.lines.as_mut()?);
        Some(lines.page(p, f))
    }

    /// How far the work is: functions decoded, of how many.
    pub fn progress(&self) -> (usize, usize) {
        match &self.pass {
            Some(pass) => (pass.next, self.total),
            None => (self.total, self.total),
        }
    }

    pub fn program(&self) -> Option<&CilProgram> {
        self.program.as_ref()
    }

    /// Analyses an assembly at once.
    pub fn analyse(file: Vec<u8>, sections: Vec<Section>, clr_rva: Option<u32>) -> Result<CilProgram, MetadataError> {
        let mut session = CilSession::open(file, sections, clr_rva)?;
        while !session.step(usize::MAX) {}
        Ok(session.program.take().unwrap())
    }
}
