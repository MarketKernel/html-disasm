//! A native program's image as the page shows it (`disasm_core::native::image`): the sections, the
//! symbols, what it imports and exports, the stubs and pointer slots, where functions start, and
//! its Objective-C classes and references — the same image the analysis reads, made by the same
//! code, handed over once as JSON.

use disasm_core::native::image::{ImageSymbol, NativeImage, PeView};
use disasm_core::native::{open_image, Container};
use disasm_core::objc::ObjcClass;
use disasm_core::text::js_number;

use super::cil_page::json_utf16;
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

fn symbol(out: &mut String, s: &ImageSymbol) {
    out.push('[');
    json_str(out, &s.name);
    out.push_str(&format!(",{},{},{},", js_number(s.addr), s.function, s.thumb));
    match s.size {
        Some(size) => out.push_str(&js_number(size)),
        None => out.push_str("null"),
    }
    out.push(']');
}

fn named(out: &mut String, entries: &[(f64, String)]) {
    list(out, entries, |out, (addr, name)| {
        out.push('[');
        out.push_str(&js_number(*addr));
        out.push(',');
        json_str(out, name);
        out.push(']');
    });
}

fn class(out: &mut String, c: &ObjcClass) {
    out.push_str("{\"name\":");
    json_str(out, &c.name);
    out.push_str(&format!(",\"addr\":{},\"swift\":", js_number(c.addr)));
    for (k, v) in [&c.swift, &c.superclass, &c.category].into_iter().enumerate() {
        if k == 1 {
            out.push_str(",\"superclass\":");
        } else if k == 2 {
            out.push_str(",\"category\":");
        }
        match v {
            Some(v) => json_str(out, v),
            None => out.push_str("null"),
        }
    }
    out.push_str(",\"methods\":");
    list(out, &c.methods, |out, m| {
        out.push('[');
        json_str(out, &m.name);
        out.push(',');
        json_str(out, &m.selector);
        out.push_str(&format!(",{},{}]", js_number(m.imp), m.class_method));
    });
    out.push('}');
}

pub fn image_json(image: &NativeImage) -> String {
    let mut out = String::with_capacity(1 << 16);
    out.push_str("{\"arch\":");
    json_str(&mut out, &image.arch);
    out.push_str(",\"sections\":");
    list(&mut out, &image.sections, |out, s| {
        out.push_str("{\"name\":");
        json_str(out, &s.name);
        out.push_str(",\"label\":");
        json_str(out, &s.label);
        out.push_str(&format!(
            ",\"addr\":{},\"size\":{},\"offset\":{},\"code\":{},\"cstrings\":{},\"zerofill\":{},\"writable\":{},\"stubSize\":{}}}",
            js_number(s.addr),
            js_number(s.size),
            js_number(s.offset),
            s.code,
            s.cstrings,
            s.zerofill,
            s.writable,
            s.stub_size.map_or("null".to_string(), js_number)
        ));
    });
    out.push_str(",\"symbols\":");
    list(&mut out, &image.symbols, symbol);
    out.push_str(",\"exports\":");
    list(&mut out, &image.exports, symbol);
    out.push_str(",\"imports\":");
    list(&mut out, &image.imports, |out, i| {
        out.push('[');
        json_str(out, &i.name);
        out.push(',');
        json_str(out, &i.library);
        out.push_str(&format!(",{},", i.weak));
        match &i.version {
            Some(v) => json_str(out, v),
            None => out.push_str("null"),
        }
        out.push(']');
    });
    out.push_str(",\"stubs\":");
    named(&mut out, &image.stubs.entries);
    out.push_str(",\"slots\":");
    named(&mut out, &image.slots.entries);
    out.push_str(",\"functionStarts\":");
    list(&mut out, &image.function_starts, |out, a| out.push_str(&js_number(*a)));
    out.push_str(",\"entry\":");
    out.push_str(&image.entry.map_or("null".to_string(), js_number));
    out.push_str(",\"marks\":");
    list(&mut out, &image.marks, |out, (addr, kind)| out.push_str(&format!("[{},\"{kind}\"]", js_number(*addr))));
    out.push_str(",\"thumb\":");
    match &image.thumb {
        Some(t) => list(&mut out, t, |out, a| out.push_str(&js_number(*a))),
        None => out.push_str("null"),
    }
    out.push_str(",\"dataInCode\":");
    match &image.data_in_code {
        Some(d) => list(&mut out, d, |out, (addr, length)| out.push_str(&format!("[{},{}]", js_number(*addr), js_number(*length)))),
        None => out.push_str("null"),
    }
    out.push_str(",\"objc\":");
    match &image.objc {
        Some(o) => {
            out.push_str("{\"classes\":");
            list(&mut out, &o.classes, class);
            out.push_str(",\"categories\":");
            list(&mut out, &o.categories, class);
            out.push_str(",\"protocols\":");
            list(&mut out, &o.protocols, |out, p| json_str(out, p));
            out.push_str(",\"selrefs\":");
            named(&mut out, &o.selrefs.entries);
            out.push_str(",\"classrefs\":");
            named(&mut out, &o.classrefs.entries);
            out.push_str(",\"cfstrings\":");
            list(&mut out, &o.cfstrings.entries, |out, (addr, text)| {
                out.push('[');
                out.push_str(&js_number(*addr));
                out.push(',');
                json_utf16(out, text);
                out.push(']');
            });
            out.push_str(",\"methods\":");
            named(&mut out, &o.methods.entries);
            out.push_str(",\"stubs\":");
            named(&mut out, &o.stubs.entries);
            out.push('}');
        }
        None => out.push_str("null"),
    }
    out.push('}');
    out
}

/// The image of a native program, as JSON: `container` 0 Mach-O (the slice), 1 ELF, 2 PE (its Arm
/// code), 3 PE (its x64 code). `null` when the file cannot be read. The file is only read.
///
/// # Safety
/// `bytes` must address `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn native_image(bytes: *const u8, len: usize, container: u32) -> usize {
    let container = match container {
        0 => Container::MachO,
        1 => Container::Elf,
        2 => Container::Pe(PeView::Arm),
        _ => Container::Pe(PeView::X64),
    };
    let text = match open_image(slice(bytes, len).to_vec(), container) {
        Some(image) => image_json(&image),
        None => "null".into(),
    };
    put_out(&text)
}
