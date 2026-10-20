//! A WebAssembly module read by the core (`disasm_core::wasm::module`), handed to the page as JSON:
//! the page shows its sections, types, imports, exports, tables, memories, globals, segments and
//! custom sections, and builds the TypeScript's `WasmModule` from this (src/core/wasm/module.ts).
//! Why a file is not a module comes as a code the page words in its language.

use disasm_core::wasm::module::{parse_wasm, Limits, NameMap, NotWasm, ParseError, WasmModule};
use disasm_core::wasm::reader::{Num, ValType};

use super::{json_str, put_out, slice};

/// A number as JavaScript had it: a number, or `{"big":"…"}` for a BigInt.
fn num(out: &mut String, v: Num) {
    match v {
        Num::Number(n) => out.push_str(&n.to_string()),
        Num::BigInt(b) => out.push_str(&format!("{{\"big\":\"{b}\"}}")),
    }
}

fn val_type(out: &mut String, t: &ValType) {
    out.push_str("{\"text\":");
    json_str(out, &t.text());
    out.push_str(",\"kind\":\"");
    out.push_str(t.kind());
    out.push_str("\"}");
}

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

/// `"key":`, after a comma unless it opens the object.
fn key(out: &mut String, name: &str) {
    if !out.ends_with('{') {
        out.push(',');
    }
    out.push('"');
    out.push_str(name);
    out.push_str("\":");
}

fn opt_text(out: &mut String, name: &str, v: &Option<String>) {
    if let Some(v) = v {
        key(out, name);
        json_str(out, v);
    }
}

fn opt_num(out: &mut String, name: &str, v: Option<u64>) {
    if let Some(v) = v {
        key(out, name);
        out.push_str(&v.to_string());
    }
}

fn limits(out: &mut String, l: &Limits) {
    out.push('{');
    key(out, "min");
    num(out, l.min);
    if let Some(max) = l.max {
        key(out, "max");
        num(out, max);
    }
    key(out, "shared");
    out.push_str(if l.shared { "true" } else { "false" });
    key(out, "is64");
    out.push_str(if l.is64 { "true" } else { "false" });
    opt_num(out, "pageSizeLog2", l.page_size_log2);
    out.push('}');
}

/// A Map as its entries, in the order they were set.
fn name_map(out: &mut String, m: &NameMap) {
    let entries: Vec<_> = m.iter().collect();
    list(out, &entries, |out, (k, v)| {
        out.push_str(&format!("[{k},"));
        json_str(out, v);
        out.push(']');
    });
}

fn bool_text(v: bool) -> &'static str {
    if v {
        "true"
    } else {
        "false"
    }
}

fn module_json(m: &WasmModule) -> String {
    let mut out = String::with_capacity(4096);
    out.push('{');
    key(&mut out, "version");
    out.push_str(&m.version.to_string());
    key(&mut out, "sections");
    list(&mut out, &m.sections, |out, s| {
        out.push('{');
        key(out, "id");
        out.push_str(&s.id.to_string());
        key(out, "name");
        json_str(out, &s.name);
        out.push_str(&format!(",\"offset\":{},\"start\":{},\"size\":{}", s.offset, s.start, s.size));
        opt_num(out, "count", s.count);
        out.push('}');
    });
    key(&mut out, "types");
    list(&mut out, &m.types, |out, t| {
        out.push('{');
        key(out, "kind");
        json_str(out, t.kind.name());
        if let Some(f) = &t.func {
            key(out, "func");
            out.push_str("{\"params\":");
            list(out, &f.params, val_type);
            out.push_str(",\"results\":");
            list(out, &f.results, val_type);
            out.push('}');
        }
        if let Some(fields) = &t.fields {
            key(out, "fields");
            list(out, fields, |out, f| {
                out.push_str("{\"type\":");
                val_type(out, &f.ty);
                out.push_str(&format!(",\"mutable\":{}}}", bool_text(f.mutable)));
            });
        }
        opt_num(out, "cont", t.cont);
        key(out, "final");
        out.push_str(bool_text(t.is_final));
        key(out, "supers");
        list(out, &t.supers, |out, s| out.push_str(&s.to_string()));
        out.push_str(&format!(",\"group\":{},\"groupSize\":{}}}", t.group, t.group_size));
    });
    key(&mut out, "imports");
    list(&mut out, &m.imports, |out, i| {
        out.push('{');
        key(out, "module");
        json_str(out, &i.module);
        key(out, "name");
        json_str(out, &i.name);
        out.push_str(&format!(",\"kind\":\"{}\",\"index\":{}", i.kind.name(), i.index));
        opt_num(out, "type", i.ty);
        out.push_str(&format!(",\"offset\":{}}}", i.offset));
    });
    key(&mut out, "funcTypes");
    list(&mut out, &m.func_types, |out, t| out.push_str(&t.to_string()));
    key(&mut out, "importedFuncs");
    out.push_str(&m.imported_funcs.to_string());
    key(&mut out, "tables");
    list(&mut out, &m.tables, |out, t| {
        out.push_str("{\"type\":");
        val_type(out, &t.ty);
        out.push_str(",\"limits\":");
        limits(out, &t.limits);
        out.push_str(&format!(",\"imported\":{}", bool_text(t.imported)));
        opt_text(out, "init", &t.init);
        out.push('}');
    });
    key(&mut out, "memories");
    list(&mut out, &m.memories, |out, mem| {
        out.push_str("{\"limits\":");
        limits(out, &mem.limits);
        out.push_str(&format!(",\"imported\":{}}}", bool_text(mem.imported)));
    });
    key(&mut out, "globals");
    list(&mut out, &m.globals, |out, g| {
        out.push_str("{\"type\":");
        val_type(out, &g.ty);
        out.push_str(&format!(",\"mutable\":{},\"imported\":{}", bool_text(g.mutable), bool_text(g.imported)));
        opt_text(out, "init", &g.init);
        if let Some(v) = g.value {
            key(out, "value");
            num(out, v);
        }
        out.push('}');
    });
    key(&mut out, "tags");
    list(&mut out, &m.tags, |out, t| out.push_str(&t.to_string()));
    key(&mut out, "exports");
    list(&mut out, &m.exports, |out, e| {
        out.push_str("{\"name\":");
        json_str(out, &e.name);
        out.push_str(&format!(",\"kind\":\"{}\",\"index\":{}}}", e.kind.name(), e.index));
    });
    opt_num(&mut out, "start", m.start);
    key(&mut out, "elements");
    list(&mut out, &m.elements, |out, e| {
        out.push_str(&format!("{{\"mode\":\"{}\",\"table\":{}", e.mode.name(), e.table));
        opt_text(out, "offset", &e.offset);
        if let Some(v) = e.offset_value {
            key(out, "offsetValue");
            out.push_str(&v.to_string());
        }
        key(out, "type");
        json_str(out, &e.ty.text());
        key(out, "funcs");
        list(out, &e.funcs, |out, f| match f {
            Some(f) => out.push_str(&f.to_string()),
            None => out.push_str("null"),
        });
        out.push('}');
    });
    key(&mut out, "data");
    list(&mut out, &m.data, |out, d| {
        out.push_str(&format!("{{\"mode\":\"{}\",\"memory\":{}", d.mode.name(), d.memory));
        opt_text(out, "offset", &d.offset);
        opt_num(out, "addr", d.addr);
        out.push_str(&format!(",\"start\":{},\"size\":{}}}", d.start, d.size));
    });
    opt_num(&mut out, "dataCount", m.data_count);
    key(&mut out, "bodies");
    list(&mut out, &m.bodies, |out, b| {
        out.push_str(&format!("{{\"func\":{},\"offset\":{},\"start\":{},\"code\":{},\"end\":{},\"locals\":", b.func, b.offset, b.start, b.code, b.end));
        list(out, &b.locals, |out, l| {
            out.push_str(&format!("{{\"count\":{},\"type\":", l.count));
            val_type(out, &l.ty);
            out.push('}');
        });
        out.push('}');
    });
    key(&mut out, "names");
    out.push('{');
    let n = &m.names;
    opt_text(&mut out, "module", &n.module);
    for (name, map) in [
        ("functions", &n.functions),
        ("types", &n.types),
        ("tables", &n.tables),
        ("memories", &n.memories),
        ("globals", &n.globals),
        ("elements", &n.elements),
        ("data", &n.data),
        ("tags", &n.tags),
    ] {
        key(&mut out, name);
        name_map(&mut out, map);
    }
    for (name, map) in [("locals", &n.locals), ("labels", &n.labels), ("fields", &n.fields)] {
        key(&mut out, name);
        let entries: Vec<_> = map.iter().collect();
        list(&mut out, &entries, |out, (k, inner)| {
            out.push_str(&format!("[{k},"));
            name_map(out, inner);
            out.push(']');
        });
    }
    out.push('}');
    key(&mut out, "producers");
    list(&mut out, &m.producers, |out, p| {
        out.push_str("{\"field\":");
        json_str(out, &p.field);
        out.push_str(",\"values\":");
        list(out, &p.values, |out, v| {
            out.push_str("{\"name\":");
            json_str(out, &v.name);
            out.push_str(",\"version\":");
            json_str(out, &v.version);
            out.push('}');
        });
        out.push('}');
    });
    key(&mut out, "features");
    list(&mut out, &m.features, |out, f| {
        out.push_str("{\"prefix\":");
        json_str(out, &f.prefix.to_string());
        out.push_str(",\"name\":");
        json_str(out, &f.name);
        out.push('}');
    });
    key(&mut out, "customs");
    list(&mut out, &m.customs, |out, c| {
        out.push_str("{\"name\":");
        json_str(out, &c.name);
        out.push_str(&format!(",\"offset\":{},\"start\":{},\"size\":{}", c.offset, c.start, c.size));
        opt_text(out, "text", &c.text);
        out.push('}');
    });
    if let Some(d) = &m.dylink {
        key(&mut out, "dylink");
        out.push_str(&format!("{{\"memorySize\":{},\"memoryAlign\":{},\"tableSize\":{},\"tableAlign\":{},\"needed\":", d.memory_size, d.memory_align, d.table_size, d.table_align));
        list(&mut out, &d.needed, |out, s| json_str(out, s));
        out.push('}');
    }
    if let Some(l) = &m.linking {
        key(&mut out, "linking");
        out.push_str(&format!("{{\"version\":{},\"symbols\":", l.version));
        list(&mut out, &l.symbols, |out, s| {
            out.push_str(&format!("{{\"kind\":\"{}\",\"name\":", s.kind.name()));
            json_str(out, &s.name);
            out.push_str(&format!(",\"index\":{},\"flags\":{},\"defined\":{}}}", s.index, s.flags, bool_text(s.defined)));
        });
        out.push('}');
    }
    key(&mut out, "relocations");
    list(&mut out, &m.relocations, |out, r| {
        out.push_str("{\"section\":");
        json_str(out, &r.section);
        out.push_str(&format!(",\"count\":{}}}", r.count));
    });
    opt_text(&mut out, "sourceMappingUrl", &m.source_mapping_url);
    opt_text(&mut out, "externalDebugInfo", &m.external_debug_info);
    opt_text(&mut out, "buildId", &m.build_id);
    key(&mut out, "debug");
    let debug: Vec<_> = m.debug.iter().collect();
    list(&mut out, &debug, |out, (name, s)| {
        out.push('[');
        json_str(out, name);
        out.push_str(&format!(",{{\"start\":{},\"size\":{}}}]", s.start, s.size));
    });
    key(&mut out, "memory64");
    out.push_str(bool_text(m.memory64));
    key(&mut out, "warnings");
    list(&mut out, &m.warnings, |out, w| json_str(out, &w.to_string()));
    out.push('}');
    out
}

/// Reads a WebAssembly module (the bytes are copied; the host frees its own): the module as JSON,
/// or `{"error":code,…}` — `signature`, `component`, `version` (with the version's text), or
/// `damaged` (with the reader's message).
///
/// # Safety
/// `bytes` and `len` must name memory the host wrote.
#[no_mangle]
pub unsafe extern "C" fn wasm_parse(bytes: *const u8, len: usize) -> usize {
    let text = match parse_wasm(slice(bytes, len).to_vec()) {
        Ok(module) => module_json(&module),
        Err(ParseError::NotWasm(NotWasm::NoSignature)) => "{\"error\":\"signature\"}".into(),
        Err(ParseError::NotWasm(NotWasm::Component)) => "{\"error\":\"component\"}".into(),
        Err(ParseError::NotWasm(NotWasm::UnknownVersion { version })) => format!("{{\"error\":\"version\",\"version\":\"0x{}\"}}", js_hex_i32(version)),
        Err(ParseError::Wasm(e)) => {
            let mut out = String::from("{\"error\":\"damaged\",\"message\":");
            json_str(&mut out, &e.to_string());
            out.push('}');
            out
        }
    };
    put_out(&text)
}

/// `version.toString(16)` of a signed 32-bit number: a negative one keeps its sign.
fn js_hex_i32(v: i32) -> String {
    if v < 0 {
        format!("-{:x}", v.unsigned_abs())
    } else {
        format!("{v:x}")
    }
}
