//! What the page shows of Java classes, asked one thing at a time for what is on screen
//! (`disasm_core::jvm::page`): an instruction of a row, a method's card and header, a class's card,
//! what a method calls and loads, and a string as javap writes it. Text comes as JavaScript holds
//! it (a lone surrogate as a `\uD800` escape).

use disasm_core::jvm::page::{class_view, escaped, fn_refs, insn_view, method_view};
use disasm_core::jvm::wtf8::Wtf8;

use super::jvm::{json_wtf8, state};
use super::{json_str, put_out, slice};

fn list<T>(out: &mut String, items: &[T], mut item: impl FnMut(&mut String, &T)) {
    out.push('[');
    for (k, x) in items.iter().enumerate() {
        if k > 0 {
            out.push(',');
        }
        item(out, x);
    }
    out.push(']');
}

fn opt_wtf8(out: &mut String, v: Option<&Wtf8>) {
    match v {
        Some(v) => json_wtf8(out, v),
        None => out.push_str("null"),
    }
}

/// An instruction of the program as the page shows it, or null outside every method.
#[no_mangle]
pub extern "C" fn jvm_insn(handle: u32, index: u32) -> usize {
    let text = state(handle, |s| {
        let Some(p) = s.session.program() else { return "null".to_string() };
        let Some(v) = insn_view(p, index as usize) else { return "null".to_string() };
        let i = &v.insn;
        let mut out = String::with_capacity(256);
        out.push_str("{\"m\":");
        json_str(&mut out, i.m);
        out.push_str(&format!(",\"at\":{},\"len\":{},\"a\":{},\"b\":{},\"keys\":", i.at, i.len, i.a, i.b));
        list(&mut out, &i.keys, |out, k| out.push_str(&k.to_string()));
        out.push_str(",\"targets\":");
        list(&mut out, &i.targets, |out, t| out.push_str(&t.to_string()));
        out.push_str(",\"op\":");
        match i.op {
            Some(o) => out.push_str(&format!("[{},{},{}]", o.code, o.operand as u8, o.flags)),
            None => out.push_str("null"),
        }
        out.push_str(",\"operand\":");
        json_str(&mut out, &v.operand);
        out.push_str(",\"text\":");
        json_wtf8(&mut out, &v.text);
        out.push_str(&format!(",\"pool\":{},\"tag\":{},\"comment\":", v.pool, v.tag));
        json_wtf8(&mut out, &v.comment);
        out.push_str(",\"string\":");
        opt_wtf8(&mut out, v.string.as_deref());
        out.push_str(",\"local\":");
        json_wtf8(&mut out, &v.local);
        out.push_str(",\"bytes5\":");
        json_str(&mut out, &v.bytes5);
        out.push_str(",\"bytes24\":");
        json_str(&mut out, &v.bytes24);
        out.push_str(",\"dynamic\":");
        match &v.dynamic {
            Some((method, args)) => {
                out.push_str("{\"method\":");
                opt_wtf8(&mut out, method.as_deref());
                out.push_str(",\"args\":");
                list(&mut out, args, |out, (index, tag, comment)| {
                    out.push_str(&format!("[{index},{tag},"));
                    json_wtf8(out, comment);
                    out.push(']');
                });
                out.push('}');
            }
            None => out.push_str("null"),
        }
        out.push('}');
        out
    });
    put_out(&text)
}

/// A method's card and header, by its function's number.
#[no_mangle]
pub extern "C" fn jvm_method(handle: u32, fn_index: u32) -> usize {
    let text = state(handle, |s| {
        let params = s.session.header_params(fn_index as usize);
        let Some(p) = s.session.program() else { return "null".to_string() };
        if fn_index as usize >= p.functions.len() {
            return "null".to_string();
        }
        let v = method_view(p, fn_index as usize, params);
        let mut out = String::with_capacity(512);
        out.push_str(&format!("{{\"access\":{},\"modifiers\":", v.access));
        json_str(&mut out, &v.modifiers);
        out.push_str(",\"descriptor\":");
        json_wtf8(&mut out, &v.descriptor);
        out.push_str(",\"signature\":");
        opt_wtf8(&mut out, v.signature.as_deref());
        out.push_str(",\"exceptions\":");
        list(&mut out, &v.exceptions, |out, e| json_wtf8(out, e));
        out.push_str(",\"class\":");
        json_wtf8(&mut out, &v.class);
        out.push_str(",\"path\":");
        json_str(&mut out, &v.path);
        out.push_str(",\"source\":");
        opt_wtf8(&mut out, v.source.as_deref());
        out.push_str(",\"firstLine\":");
        match v.first_line {
            Some(l) => out.push_str(&l.to_string()),
            None => out.push_str("null"),
        }
        out.push_str(&format!(",\"codeLength\":{},\"maxStack\":{},\"maxLocals\":{},\"locals\":", v.code_length, v.max_stack, v.max_locals));
        list(&mut out, &v.locals, |out, (slot, name, ty, start, length)| {
            out.push_str(&format!("[{slot},"));
            json_wtf8(out, name);
            out.push(',');
            json_wtf8(out, ty);
            out.push_str(&format!(",{start},{length}]"));
        });
        out.push_str(",\"handlers\":");
        list(&mut out, &v.handlers, |out, (start, end, handler, catch)| {
            out.push_str(&format!("[{start},{end},{handler},"));
            json_wtf8(out, catch);
            out.push(']');
        });
        out.push_str(",\"params\":");
        list(&mut out, &v.params, |out, (name, ty)| {
            out.push('[');
            json_str(out, name);
            out.push(',');
            json_str(out, ty);
            out.push(']');
        });
        out.push_str(",\"ret\":");
        json_str(&mut out, &v.ret);
        out.push('}');
        super::hla::unmark(&out)
    });
    put_out(&text)
}

/// A class's card, by its number.
#[no_mangle]
pub extern "C" fn jvm_class_info(handle: u32, k: u32) -> usize {
    let text = state(handle, |s| {
        let Some(cf) = s.session.classes().get(k as usize) else { return "null".to_string() };
        let v = class_view(cf);
        let mut out = String::with_capacity(512);
        out.push_str("{\"java\":");
        json_wtf8(&mut out, &v.java);
        out.push_str(",\"modifiers\":");
        json_str(&mut out, &v.modifiers);
        out.push_str(&format!(",\"kind\":\"{}\",\"extends\":", v.kind));
        opt_wtf8(&mut out, v.extends.as_deref());
        out.push_str(",\"implements\":");
        list(&mut out, &v.implements, |out, i| json_wtf8(out, i));
        out.push_str(",\"source\":");
        opt_wtf8(&mut out, v.source.as_deref());
        out.push_str(&format!(",\"pool\":{},\"attributes\":", v.pool));
        list(&mut out, &v.attributes, |out, a| json_wtf8(out, a));
        out.push_str(",\"module\":");
        match &v.module {
            Some((name, version, lists)) => {
                out.push_str("{\"name\":");
                json_wtf8(&mut out, name);
                out.push_str(",\"version\":");
                json_wtf8(&mut out, version);
                for (key, items) in ["requires", "exports", "opens", "uses", "provides"].iter().zip(lists) {
                    out.push_str(&format!(",\"{key}\":"));
                    list(&mut out, items, |out, x| json_wtf8(out, x));
                }
                out.push('}');
            }
            None => out.push_str("null"),
        }
        out.push_str(",\"fields\":");
        list(&mut out, &v.fields, |out, (name, descriptor, access, decl)| {
            out.push('[');
            json_wtf8(out, name);
            out.push(',');
            json_wtf8(out, descriptor);
            out.push_str(&format!(",{access},"));
            json_wtf8(out, decl);
            out.push(']');
        });
        out.push('}');
        out
    });
    put_out(&text)
}

/// What a method's code calls and loads: `{"calls":[pool…],"dynamic":n,"strings":[…]}`.
#[no_mangle]
pub extern "C" fn jvm_fn_refs(handle: u32, fn_index: u32) -> usize {
    let text = state(handle, |s| {
        let Some(p) = s.session.program() else { return "null".to_string() };
        if fn_index as usize >= p.functions.len() {
            return "null".to_string();
        }
        let (calls, dynamic, strings) = fn_refs(p, fn_index as usize);
        let mut out = String::from("{\"calls\":");
        list(&mut out, &calls, |out, c| out.push_str(&c.to_string()));
        out.push_str(&format!(",\"dynamic\":{dynamic},\"strings\":"));
        list(&mut out, &strings, |out, t| json_wtf8(out, t));
        out.push('}');
        out
    });
    put_out(&text)
}

/// A string (its UTF-16 units, little-endian) as javap writes it in a comment, as JSON.
///
/// # Safety
/// `units` and `len` (in bytes) must name memory the host wrote.
#[no_mangle]
pub unsafe extern "C" fn jvm_escape(units: *const u8, len: usize) -> usize {
    let bytes = slice(units, len);
    let units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    let mut out = String::new();
    json_wtf8(&mut out, &escaped(&units));
    put_out(&out)
}
