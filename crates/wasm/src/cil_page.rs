//! What the page shows of a .NET assembly, asked one thing at a time for what is on screen
//! (`disasm_core::cil::page`): an instruction of a row, a method's card and header, what a method
//! calls and loads, a field's name, a string of #US, and the Assembly and References pages. Text
//! comes as JavaScript holds it: a #US string's lone surrogate as a `\uD800` escape.

use disasm_core::cil::page::Page;

use super::cil::state;
use super::{json_str, put_out};

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

/// UTF-16 text as a JSON string: a lone surrogate as its escape, as JSON.stringify writes it.
pub(crate) fn json_utf16(out: &mut String, units: &[u16]) {
    let mut text = String::new();
    out.push('"');
    for unit in char::decode_utf16(units.iter().copied()) {
        match unit {
            Ok(c) => text.push(c),
            Err(e) => {
                let mut quoted = String::new();
                json_str(&mut quoted, &text);
                out.push_str(&quoted[1..quoted.len() - 1]);
                text.clear();
                out.push_str(&format!("\\u{:04x}", e.unpaired_surrogate()));
            }
        }
    }
    let mut quoted = String::new();
    json_str(&mut quoted, &text);
    out.push_str(&quoted[1..quoted.len() - 1]);
    out.push('"');
}

fn opt_str(out: &mut String, v: Option<&str>) {
    match v {
        Some(v) => json_str(out, v),
        None => out.push_str("null"),
    }
}

/// Runs a question over the session's metadata; `null` before the program is ready.
fn ask(handle: u32, f: impl FnOnce(&mut Page) -> String) -> usize {
    let text = state(handle, |s| s.session.page(f)).unwrap_or_else(|| "null".into());
    put_out(&text)
}

/// An instruction of the program as the page shows it, or null outside every method.
#[no_mangle]
pub extern "C" fn cil_insn(handle: u32, index: u32) -> usize {
    ask(handle, |page| {
        let Some(v) = page.insn(index as usize) else { return "null".into() };
        let i = &v.insn;
        let mut out = String::with_capacity(256);
        out.push_str("{\"m\":");
        json_str(&mut out, i.m);
        out.push_str(&format!(",\"at\":{},\"len\":{},\"a\":{},\"targets\":", i.at, i.len, i.a));
        if i.is_switch {
            list(&mut out, &i.targets, |out, t| out.push_str(&t.to_string()));
        } else {
            out.push_str("null");
        }
        out.push_str(",\"op\":");
        match i.op {
            Some(o) => out.push_str(&format!("[{},{},{}]", o.code, o.operand, o.flags)),
            None => out.push_str("null"),
        }
        out.push_str(",\"operand\":");
        json_str(&mut out, &v.operand);
        out.push_str(",\"text\":");
        json_str(&mut out, &v.text);
        out.push_str(&format!(",\"fileOffset\":{},\"bytes5\":", v.file_offset));
        json_str(&mut out, &v.bytes5);
        out.push_str(",\"bytes24\":");
        json_str(&mut out, &v.bytes24);
        out.push_str(",\"callee\":");
        match v.callee {
            Some(addr) => out.push_str(&addr.to_string()),
            None => out.push_str("null"),
        }
        out.push_str(&format!(",\"calleeFn\":{}", v.callee_fn.map_or(-1, |f| f as i64)));
        out.push_str(",\"string\":");
        match &v.string {
            Some(text) => json_utf16(&mut out, text),
            None => out.push_str("null"),
        }
        out.push_str(&format!(",\"plain\":{},\"field\":", v.string.as_deref().is_some_and(disasm_core::cil::page::plain_string)));
        opt_str(&mut out, v.field.as_deref());
        out.push_str(",\"tokenKind\":");
        json_str(&mut out, &v.token_kind);
        out.push('}');
        out
    })
}

/// A method's card and header, by its function's number.
#[no_mangle]
pub extern "C" fn cil_method(handle: u32, fn_index: u32) -> usize {
    ask(handle, |page| {
        let Some(v) = page.method(fn_index as usize) else { return "null".into() };
        let mut out = String::with_capacity(512);
        out.push_str(&format!("{{\"token\":{},\"attributes\":", v.token));
        json_str(&mut out, &v.attributes);
        out.push_str(&format!(",\"rva\":{},\"size\":{},\"fat\":{},\"maxStack\":{},\"initLocals\":{},\"locals\":", v.rva, v.size, v.fat, v.max_stack, v.init_locals));
        list(&mut out, &v.locals, |out, t| json_str(out, t));
        out.push_str(",\"clauses\":");
        list(&mut out, &v.clauses, |out, (c, text, catch)| {
            out.push_str(&format!(
                "{{\"kind\":{},\"tryStart\":{},\"tryEnd\":{},\"handlerStart\":{},\"handlerEnd\":{},\"filterStart\":{},\"text\":",
                c.kind, c.try_start, c.try_end, c.handler_start, c.handler_end, c.filter_start
            ));
            json_str(out, text);
            out.push_str(",\"catch\":");
            json_str(out, catch);
            out.push('}');
        });
        out.push_str(",\"signature\":");
        json_str(&mut out, &v.signature);
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
        out
    })
}

/// What a method calls (the address each call reaches), how many calls go through a function
/// pointer, and the strings it loads (token, text).
#[no_mangle]
pub extern "C" fn cil_fn_refs(handle: u32, fn_index: u32) -> usize {
    ask(handle, |page| {
        let (calls, indirect, strings) = page.function_refs(fn_index as usize);
        let mut out = String::from("{\"calls\":");
        list(&mut out, &calls, |out, a| out.push_str(&a.to_string()));
        out.push_str(&format!(",\"indirect\":{indirect},\"strings\":"));
        list(&mut out, &strings, |out, (tok, text)| {
            out.push_str(&format!("[{tok},"));
            json_utf16(out, text);
            out.push(']');
        });
        out.push('}');
        out
    })
}

/// A field token as ildasm writes it, with no generic context.
#[no_mangle]
pub extern "C" fn cil_field(handle: u32, tok: u32) -> usize {
    ask(handle, |page| {
        let mut out = String::new();
        json_str(&mut out, &page.field(tok));
        out
    })
}

/// A string of #US by its index, or null past the heap.
#[no_mangle]
pub extern "C" fn cil_user_string(handle: u32, index: u32) -> usize {
    ask(handle, |page| match page.metadata().user_string(index) {
        Some(text) => {
            let mut out = String::new();
            json_utf16(&mut out, &text);
            out
        }
        None => "null".into(),
    })
}

/// A string of #US (by its index) as ldstr's operand writes it.
#[no_mangle]
pub extern "C" fn cil_string_text(handle: u32, index: u32) -> usize {
    ask(handle, |page| {
        let mut out = String::new();
        json_str(&mut out, &page.string_text(index));
        out
    })
}

/// The Assembly page.
#[no_mangle]
pub extern "C" fn cil_assembly(handle: u32) -> usize {
    ask(handle, |page| {
        let v = page.assembly();
        let mut out = String::with_capacity(4096);
        out.push_str("{\"assembly\":");
        match &v.assembly {
            Some((name, version, culture, key)) => {
                out.push('[');
                for (k, text) in [name, version, culture, key].into_iter().enumerate() {
                    if k > 0 {
                        out.push(',');
                    }
                    json_str(&mut out, text);
                }
                out.push(']');
            }
            None => out.push_str("null"),
        }
        out.push_str(",\"module\":[");
        json_str(&mut out, &v.module.0);
        out.push(',');
        json_str(&mut out, &v.module.1);
        out.push_str("],\"runtime\":[");
        json_str(&mut out, &v.runtime.0);
        out.push(',');
        json_str(&mut out, &v.runtime.1);
        out.push(',');
        json_str(&mut out, &v.runtime.2);
        out.push_str("],\"flags\":");
        json_str(&mut out, &v.flags);
        out.push_str(&format!(",\"strongName\":{},\"counts\":[{}],\"warnings\":", v.strong_name, v.counts.map(|c| c.to_string()).join(",")));
        list(&mut out, &v.warnings, |out, w| json_str(out, w));
        out.push_str(",\"streams\":");
        list(&mut out, &v.streams, |out, (name, offset, size)| {
            out.push('[');
            json_str(out, name);
            out.push_str(&format!(",{offset},{size}]"));
        });
        out.push_str(",\"tables\":");
        list(&mut out, &v.tables, |out, (id, name, rows)| {
            out.push_str(&format!("[{id},"));
            json_str(out, name);
            out.push_str(&format!(",{rows}]"));
        });
        out.push_str(",\"resources\":");
        list(&mut out, &v.resources, |out, (name, public, place)| {
            out.push('[');
            json_str(out, name);
            out.push_str(&format!(",{public},"));
            opt_str(out, place.as_deref());
            out.push(']');
        });
        out.push_str(",\"types\":");
        list(&mut out, &v.types, |out, (name, kind, visibility, methods, first)| {
            out.push('[');
            json_str(out, name);
            out.push(',');
            json_str(out, kind);
            out.push(',');
            json_str(out, visibility);
            out.push_str(&format!(",{methods},"));
            match first {
                Some(addr) => out.push_str(&addr.to_string()),
                None => out.push_str("null"),
            }
            out.push(']');
        });
        out.push('}');
        out
    })
}

/// The References page: the assemblies referenced, the types forwarded to others.
#[no_mangle]
pub extern "C" fn cil_references(handle: u32) -> usize {
    ask(handle, |page| {
        let v = page.references();
        let mut out = String::from("{\"assemblies\":");
        list(&mut out, &v.assemblies, |out, (name, version, culture, key)| {
            out.push('[');
            for (k, text) in [name, version, culture, key].into_iter().enumerate() {
                if k > 0 {
                    out.push(',');
                }
                json_str(out, text);
            }
            out.push(']');
        });
        out.push_str(",\"forwarders\":");
        list(&mut out, &v.forwarders, |out, (name, to)| {
            out.push('[');
            json_str(out, name);
            out.push(',');
            json_str(out, to);
            out.push(']');
        });
        out.push_str(&format!(",\"exported\":{}}}", v.exported));
        out
    })
}
