//! What the page shows of Java classes besides the listing's structure: an instruction as javap
//! prints it (with what its constant names and the local it reads), a method's card (its
//! declaration, frame, locals, lines, handlers, the parameters of its HLA64 header), a class's
//! card (its declaration, fields, module), and what a method's code calls and loads. The page
//! asks for the ones it shows; everything here is text as the TypeScript made it, so the page
//! only lays it out. A port of what src/app/jvm.ts and src/core/jvm/hla.ts read from the classes.

use super::classfile::{class_kind, constant, constant_comment, escape_string, field_type, java_name, java_release, method_types, modifiers, ClassFile, What};
use super::decode::{bytes_text, insn_text, operand_text, pool_index, JvmInsn};
use super::hla::{function_of_index, insn_at, marked, strip_packages};
use super::opcodes::{flags as F, Operand};
use super::program::JvmProgram;
use super::wtf8::{Wtf8, Wtf8Buf};

/// An instruction for a row or the details.
pub struct InsnView {
    pub insn: JvmInsn,
    /// The operand as javap prints it, and the whole instruction.
    pub operand: String,
    pub text: Wtf8Buf,
    /// The constant pool index it names (0: none), that entry's tag, and javap's comment for it.
    pub pool: usize,
    pub tag: u8,
    pub comment: Wtf8Buf,
    /// A String constant's text.
    pub string: Option<Wtf8Buf>,
    /// The local it reads or writes, as the class names it: `count: int` (empty: none).
    pub local: Wtf8Buf,
    /// Its bytes in hex: the first five, the first twenty-four.
    pub bytes5: String,
    pub bytes24: String,
    /// invokedynamic: the bootstrap method's comment (None: there is none) and each of its arguments (index, tag, comment).
    pub dynamic: Option<(Option<Wtf8Buf>, Vec<(usize, u8, Wtf8Buf)>)>,
}

/// `${v.name}: ${fieldType(v.descriptor)}` of the local a slot holds at an instruction.
fn local_comment(cf: &ClassFile, p: &JvmProgram, fn_index: usize, slot: i64, pc: u32, len: u32) -> Wtf8Buf {
    let body = p.bodies[fn_index];
    let Some(code) = &cf.methods[body.method as usize].code else { return Wtf8Buf::new() };
    let locals: Vec<_> = cf.local_variables(code).into_iter().filter(|v| v.slot as i64 == slot).collect();
    let found = locals
        .iter()
        .find(|l| pc >= l.start as u32 && pc < l.start as u32 + l.length as u32)
        .or_else(|| locals.iter().find(|l| pc + len >= l.start as u32 && pc + len <= l.start as u32 + l.length as u32));
    let mut out = Wtf8Buf::new();
    if let Some(v) = found {
        out.push_wtf8(v.name);
        out.push_str(": ");
        out.push_wtf8(&field_type(v.descriptor));
    }
    out
}

/// `^[ilfda](?:load|store)_([0-3])$`: the slot of a short load or store.
fn short_slot(m: &str) -> Option<i64> {
    let b = m.as_bytes();
    if b.len() < 2 || !b"ilfda".contains(&b[0]) {
        return None;
    }
    let rest = &m[1..];
    let digit = rest.strip_prefix("load_").or_else(|| rest.strip_prefix("store_"))?;
    match digit.as_bytes() {
        [d @ b'0'..=b'3'] => Some((d - b'0') as i64),
        _ => None,
    }
}

pub fn insn_view(p: &JvmProgram, index: usize) -> Option<InsnView> {
    let fn_index = function_of_index(p, index)?;
    let body = p.bodies[fn_index];
    let cf = &p.classes[body.cls as usize];
    let mut insn = JvmInsn::new();
    insn_at(p, fn_index, index, &mut insn);
    let ot = operand_text(cf, &insn);
    let pool = pool_index(&insn);
    let tag = cf.tags.get(pool).copied().unwrap_or(0);
    let comment = if pool != 0 { constant_comment(cf, pool) } else { Wtf8Buf::new() };
    let string = (pool != 0 && tag == constant::STRING).then(|| cf.utf8(cf.ref1(pool)).to_owned());
    let pc = insn.at as u32;
    let len = insn.len as u32;
    let local = match insn.op.map(|o| o.operand) {
        Some(Operand::None) => short_slot(insn.m).map_or_else(Wtf8Buf::new, |slot| local_comment(cf, p, fn_index, slot, pc, len)),
        Some(Operand::Local | Operand::LocalW | Operand::Iinc | Operand::IincW) => local_comment(cf, p, fn_index, insn.a, pc, len),
        _ => Wtf8Buf::new(),
    };
    let code = cf.methods[body.method as usize].code.as_ref();
    let file_offset = code.map_or(0, |c| c.offset) + (p.result.offsets[index] - body.base) as usize;
    let dynamic = (insn.op.is_some_and(|o| o.operand == Operand::Dynamic) && pool != 0).then(|| {
        let site = cf.dynamic(pool);
        match cf.bootstrap_methods().get(site.bootstrap as usize) {
            Some(b) => (
                Some(constant_comment(cf, b.method as usize)),
                b.args.iter().map(|&a| (a as usize, cf.tags.get(a as usize).copied().unwrap_or(0), constant_comment(cf, a as usize))).collect(),
            ),
            None => (None, Vec::new()),
        }
    });
    Some(InsnView {
        operand: ot.operand,
        text: insn_text(cf, &insn),
        pool,
        tag,
        comment,
        string,
        local,
        bytes5: bytes_text(&cf.bytes, file_offset, insn.len, 5),
        bytes24: bytes_text(&cf.bytes, file_offset, insn.len, 24),
        dynamic,
        insn,
    })
}

/// A method's card and its header.
pub struct MethodView {
    pub access: u16,
    pub modifiers: String,
    pub descriptor: Wtf8Buf,
    pub signature: Option<Wtf8Buf>,
    /// The exceptions it declares, as Java names them.
    pub exceptions: Vec<Wtf8Buf>,
    /// Its class as Java names it, and where the class was in the archive.
    pub class: Wtf8Buf,
    pub path: String,
    pub source: Option<Wtf8Buf>,
    /// The first line of its code, from LineNumberTable.
    pub first_line: Option<u16>,
    pub code_length: usize,
    pub max_stack: u16,
    pub max_locals: u16,
    /// Its locals: slot, name, type as Java writes it, start, length.
    pub locals: Vec<(u16, Wtf8Buf, Wtf8Buf, u16, u16)>,
    /// Its exception table: start, end, handler, what it catches (`any` for a finally).
    pub handlers: Vec<(u16, u16, u16, Wtf8Buf)>,
    /// The parameters of its HLA64 header: name, type (packages left out); and its return type so.
    pub params: Vec<(String, String)>,
    pub ret: String,
}

pub fn method_view(p: &JvmProgram, fn_index: usize, params: Vec<(String, String)>) -> MethodView {
    let body = p.bodies[fn_index];
    let cf = &p.classes[body.cls as usize];
    let method = &cf.methods[body.method as usize];
    let code = method.code.as_ref();
    let descriptor = cf.utf8(method.descriptor_index as usize);
    let locals = code.map_or_else(Vec::new, |c| cf.local_variables(c).into_iter().map(|v| (v.slot, v.name.to_owned(), field_type(v.descriptor), v.start, v.length)).collect());
    let handlers = code.map_or_else(Vec::new, |c| {
        c.handlers
            .iter()
            .map(|h| {
                let catch = if h.catch_type != 0 {
                    java_name(cf.class_name(h.catch_type as usize))
                } else {
                    let mut any = Wtf8Buf::new();
                    any.push_str("any");
                    any
                };
                (h.start, h.end, h.handler, catch)
            })
            .collect()
    });
    let lines = code.map_or_else(Vec::new, |c| cf.line_numbers(c));
    MethodView {
        access: method.access,
        modifiers: modifiers(method.access, What::Method),
        descriptor: descriptor.to_owned(),
        signature: cf.signature(&method.attributes).map(Wtf8::to_owned),
        exceptions: cf.exceptions(method).into_iter().map(java_name).collect(),
        class: java_name(cf.name()),
        path: cf.path.clone(),
        source: cf.source_file().map(Wtf8::to_owned),
        first_line: lines.iter().map(|&(_, line)| line).min(),
        code_length: code.map_or(0, |c| c.length),
        max_stack: code.map_or(0, |c| c.max_stack),
        max_locals: code.map_or(0, |c| c.max_locals),
        locals,
        handlers,
        params,
        ret: strip_packages(&marked(&method_types(descriptor).ret)),
    }
}

/// A class's card.
pub struct ClassView {
    pub java: Wtf8Buf,
    pub modifiers: String,
    pub kind: &'static str,
    pub extends: Option<Wtf8Buf>,
    pub implements: Vec<Wtf8Buf>,
    pub source: Option<Wtf8Buf>,
    pub pool: usize,
    pub attributes: Vec<Wtf8Buf>,
    /// The module a module-info declares: name, version, requires, exports, opens, uses, provides.
    pub module: Option<(Wtf8Buf, Wtf8Buf, [Vec<Wtf8Buf>; 5])>,
    /// Its fields: name, descriptor, access, declaration (`private int hello.More.count`).
    pub fields: Vec<(Wtf8Buf, Wtf8Buf, u16, Wtf8Buf)>,
}

pub fn class_view(cf: &ClassFile) -> ClassView {
    let java = java_name(cf.name());
    let fields = cf
        .fields
        .iter()
        .map(|f| {
            let name = cf.utf8(f.name_index as usize);
            let descriptor = cf.utf8(f.descriptor_index as usize);
            let mods = modifiers(f.access, What::Field);
            let mut decl = Wtf8Buf::new();
            if !mods.is_empty() {
                decl.push_str(&mods);
                decl.push_str(" ");
            }
            decl.push_wtf8(&field_type(descriptor));
            decl.push_str(" ");
            decl.push_wtf8(&java);
            decl.push_str(".");
            decl.push_wtf8(name);
            (name.to_owned(), descriptor.to_owned(), f.access, decl)
        })
        .collect();
    let module = cf.module().map(|m| {
        let owned = |list: Vec<&Wtf8>| list.into_iter().map(Wtf8::to_owned).collect::<Vec<_>>();
        (m.name.to_owned(), m.version.to_owned(), [owned(m.requires), m.exports, m.opens, m.uses, m.provides])
    });
    ClassView {
        modifiers: modifiers(cf.access, What::Class),
        kind: class_kind(cf).as_str(),
        extends: (cf.super_class != 0).then(|| java_name(cf.class_name(cf.super_class as usize))),
        implements: cf.interfaces.iter().map(|&i| java_name(cf.class_name(i as usize))).collect(),
        source: cf.source_file().map(Wtf8::to_owned),
        pool: cf.tags.len().saturating_sub(1),
        attributes: cf.attributes.iter().map(|a| cf.utf8(a.name_index as usize).to_owned()).collect(),
        module,
        fields,
        java,
    }
}

/// What a method's code calls and loads (its first 50000 instructions): the constant pool index of
/// each call that is not invokedynamic, in order; how many invokedynamic calls; each String constant loaded, in order.
pub fn fn_refs(p: &JvmProgram, fn_index: usize) -> (Vec<usize>, u32, Vec<Wtf8Buf>) {
    let f = &p.functions[fn_index];
    let cf = &p.classes[p.bodies[fn_index].cls as usize];
    let mut calls = Vec::new();
    let mut dynamic = 0;
    let mut strings = Vec::new();
    let mut insn = JvmInsn::new();
    for i in f.first..f.first + f.count.min(50000) {
        insn_at(p, fn_index, i as usize, &mut insn);
        let Some(op) = insn.op else { continue };
        let pool = pool_index(&insn);
        if op.flags & F::CALL != 0 && op.operand != Operand::Dynamic {
            calls.push(pool);
        } else if op.flags & F::CALL != 0 {
            dynamic += 1;
        }
        if pool != 0 && cf.tags.get(pool) == Some(&constant::STRING) {
            strings.push(cf.utf8(cf.ref1(pool)).to_owned());
        }
    }
    (calls, dynamic, strings)
}

/// A string as javap writes it in a comment.
pub fn escaped(units: &[u16]) -> Wtf8Buf {
    escape_string(&Wtf8Buf::from_utf16(units))
}

/// `javaRelease(major)`: the Java release a class file version is.
pub fn release(major: u16) -> String {
    java_release(major)
}
