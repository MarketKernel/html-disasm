//! Java classes: a class file, a JAR, a .jmod or an AAR read and analysed in
//! the core (`disasm_core::jvm::program`). The session lives as long as the
//! page's program: the page takes the results once, and then a class's bytes
//! whenever it shows something of that class.

use disasm_core::jvm::classfile::{class_kind, java_name, java_release, modifiers, ClassError, What};
use disasm_core::jvm::program::{Broken, ContainerKind, JvmSession, ReadError};
use disasm_core::jvm::wtf8::Wtf8;
use disasm_core::zip::ZipError;

use super::{add_session, json_str, put_out, session, slice_owned, with, Session};

pub struct JvmState {
    pub session: JvmSession,
    /// Per function, once the program is ready: class, method, base, access, code offset, code length, first, count.
    pub bodies: Vec<u32>,
    /// Per range of the listing: first, count, class.
    pub ranges: Vec<u32>,
}

/// Opens a class file, a JAR, a .jmod or an AAR; the core takes over `bytes` (from `alloc`, not to
/// be freed). With `analyse` 0 only the classes are read. 0 when the file cannot be opened: then
/// `jvm_open_error` says why.
///
/// # Safety
/// `bytes` and `len` must come from one `alloc` call, and the host must not use them again.
#[no_mangle]
pub unsafe extern "C" fn jvm_open(bytes: *mut u8, len: usize, analyse: u32) -> u32 {
    let file = slice_owned(bytes, len);
    match JvmSession::open(file, analyse != 0) {
        Ok(session) => add_session(Session::Jvm(Box::new(JvmState { session, bodies: Vec::new(), ranges: Vec::new() }))),
        Err(err) => {
            let mut out = String::from("{\"error\":");
            match err {
                ReadError::NotJava => out.push_str("\"notJava\""),
                ReadError::NoClasses => out.push_str("\"noClasses\""),
                ReadError::Zip(e) => {
                    out.push_str("\"zip\",\"text\":");
                    json_str(&mut out, &zip_message(e));
                }
                ReadError::Class(e) => {
                    out.push_str("\"class\",\"text\":");
                    json_str(&mut out, &class_message(e));
                }
            }
            out.push('}');
            with(|s| s.open_error = out);
            0
        }
    }
}

#[no_mangle]
pub extern "C" fn jvm_open_error() -> usize {
    let text = with(|s| s.open_error.clone());
    put_out(&text)
}

/// What the TypeScript said when a class file could not be read (its NotClass messages, or its DataView's RangeError).
fn class_message(e: ClassError) -> String {
    match e {
        ClassError::NotClassFile => "not a class file".into(),
        ClassError::CutShort => "the class file is cut short".into(),
        ClassError::UnknownTag { index, tag } => format!("constant #{index} has an unknown tag {tag}"),
        ClassError::AttributeTooLong => "an attribute runs past the end of the class file".into(),
        ClassError::CodeTooLong => "a method's code runs past its attribute".into(),
        ClassError::OutOfBounds => "Offset is outside the bounds of the DataView".into(),
    }
}

/// What the TypeScript said when an archive could not be read (its NotZip messages; the browser words a deflate failure).
fn zip_message(e: ZipError) -> String {
    match e {
        ZipError::NoEndOfDirectory => "no end of central directory".into(),
        ZipError::BadLocalHeader => "bad local header".into(),
        ZipError::Method(m) => format!("compression method {m}"),
        ZipError::OutOfBounds => "Offset is outside the bounds of the DataView".into(),
        ZipError::Inflate => "The compressed data was not valid".into(),
    }
}

pub(crate) fn state<R>(handle: u32, f: impl FnOnce(&mut JvmState) -> R) -> R {
    session(handle, |s| match s {
        Session::Jvm(state) => f(state),
        _ => panic!("not a JVM session"),
    })
}

/// Works on for about `budget` instructions; 1 once the program (or, without analysis, the classes) is ready.
#[no_mangle]
pub extern "C" fn jvm_step(handle: u32, budget: u32) -> u32 {
    state(handle, |s| {
        if !s.session.step(budget as usize) {
            return 0;
        }
        if let Some(p) = s.session.program() {
            if s.bodies.is_empty() && !p.bodies.is_empty() {
                for (b, f) in p.bodies.iter().zip(&p.functions) {
                    let m = &p.classes[b.cls as usize].methods[b.method as usize];
                    let code = m.code.as_ref().unwrap();
                    s.bodies.extend_from_slice(&[b.cls, b.method, b.base, m.access as u32, code.offset as u32, code.length as u32, f.first, f.count]);
                }
                for r in &p.ranges {
                    s.ranges.extend_from_slice(&[r.first, r.count, r.cls]);
                }
            }
        }
        1
    })
}

/// How far the work is: classes read, then methods decoded.
#[no_mangle]
pub extern "C" fn jvm_done(handle: u32) -> u32 {
    state(handle, |s| s.session.progress().0 as u32)
}

#[no_mangle]
pub extern "C" fn jvm_total(handle: u32) -> u32 {
    state(handle, |s| s.session.progress().1 as u32)
}

/// A text, as JavaScript would hold it: a lone surrogate as a `\uD800` escape.
pub(crate) fn json_wtf8(out: &mut String, s: &Wtf8) {
    if let Some(text) = s.as_str() {
        json_str(out, text);
        return;
    }
    out.push('"');
    for c in s.code_points() {
        match char::from_u32(c) {
            Some('"') => out.push_str("\\\""),
            Some('\\') => out.push_str("\\\\"),
            Some(ch) if (ch as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", ch as u32)),
            Some(ch) => out.push(ch),
            None => out.push_str(&format!("\\u{c:04X}")),
        }
    }
    out.push('"');
}

/// One of the program's texts in the output buffer (`what`): 0 the mnemonics, one per line; as
/// JSON, 1 the functions (each its method's name, what its declaration says before the class, its
/// parameters, its kind), 2 the imports (owner, member, descriptor, field, type, parameters), 3 the
/// strings, 4 the classes, 5 the container, 7 the rest.
#[no_mangle]
pub extern "C" fn jvm_text(handle: u32, what: u32) -> usize {
    let text = state(handle, |s| {
        let mut out = String::new();
        let classes = s.session.classes();
        if what == 4 {
            out.push('[');
            for (k, cf) in classes.iter().enumerate() {
                if k > 0 {
                    out.push(',');
                }
                out.push('[');
                json_wtf8(&mut out, cf.name());
                out.push(',');
                json_str(&mut out, &cf.path);
                out.push_str(&format!(",\"{}\",{},{},{},", class_kind(cf).as_str(), cf.access, cf.major, cf.minor));
                match cf.source_file() {
                    Some(source) => json_wtf8(&mut out, source),
                    None => out.push_str("null"),
                }
                // As the page shows them: the name as Java writes it, the modifiers, the release.
                out.push(',');
                json_wtf8(&mut out, &java_name(cf.name()));
                out.push(',');
                json_str(&mut out, &modifiers(cf.access, What::Class));
                out.push(',');
                json_str(&mut out, &java_release(cf.major));
                out.push(']');
            }
            out.push(']');
            return out;
        }
        let p = s.session.program().expect("the program is not ready");
        let list = |out: &mut String, n: usize, mut item: Box<dyn FnMut(&mut String, usize) + '_>| {
            out.push('[');
            for k in 0..n {
                if k > 0 {
                    out.push(',');
                }
                item(out, k);
            }
            out.push(']');
        };
        match what {
            0 => out = p.result.mnemonics.join("\n"),
            1 => list(
                &mut out,
                p.functions.len(),
                Box::new(|out, k| {
                    let f = &p.functions[k];
                    out.push('[');
                    json_wtf8(out, p.function_raw(k));
                    out.push(',');
                    json_wtf8(out, &f.prefix);
                    out.push(',');
                    json_wtf8(out, &f.params);
                    out.push_str(",\"");
                    out.push_str(f.kind.as_str());
                    out.push_str("\"]");
                }),
            ),
            2 => list(
                &mut out,
                p.imported.len(),
                Box::new(|out, k| {
                    let m = &p.imported[k];
                    out.push('[');
                    for (j, text) in [&m.owner, &m.member, &m.descriptor].into_iter().enumerate() {
                        if j > 0 {
                            out.push(',');
                        }
                        json_wtf8(out, text);
                    }
                    out.push_str(if m.field { ",1," } else { ",0," });
                    json_wtf8(out, &m.ret);
                    out.push(',');
                    json_wtf8(out, &m.params);
                    out.push(',');
                    json_wtf8(out, &java_name(&m.owner));
                    out.push(']');
                }),
            ),
            3 => list(&mut out, p.strings.len(), Box::new(|out, k| json_wtf8(out, &p.strings[k]))),
            5 => {
                let c = &p.container;
                out.push_str("{\"kind\":\"");
                out.push_str(match c.kind {
                    ContainerKind::Class => "class",
                    ContainerKind::Jar => "jar",
                    ContainerKind::Jmod => "jmod",
                });
                out.push_str("\",\"manifest\":");
                list(
                    &mut out,
                    c.manifest.len(),
                    Box::new(|out, k| {
                        out.push('[');
                        json_str(out, &c.manifest[k].0);
                        out.push(',');
                        json_str(out, &c.manifest[k].1);
                        out.push(']');
                    }),
                );
                out.push_str(",\"resources\":");
                list(
                    &mut out,
                    c.resources.len(),
                    Box::new(|out, k| {
                        out.push('[');
                        json_str(out, &c.resources[k].0);
                        out.push_str(&format!(",{}]", c.resources[k].1));
                    }),
                );
                out.push_str(&format!(",\"versioned\":{},\"broken\":", c.versioned));
                list(
                    &mut out,
                    c.broken.len(),
                    Box::new(|out, k| {
                        let (name, why) = &c.broken[k];
                        out.push('[');
                        json_str(out, name);
                        out.push(',');
                        json_str(
                            out,
                            &match *why {
                                Broken::Zip(e) => zip_message(e),
                                Broken::Class(e) => class_message(e),
                            },
                        );
                        out.push(']');
                    }),
                );
                out.push_str(if c.from_classes_jar { ",\"from\":true}" } else { ",\"from\":false}" });
            }
            7 => {
                out.push_str(&format!(
                    "{{\"version\":[{},{}],\"release\":\"{}\",\"kotlin\":{},\"dynamicCalls\":{},\"entry\":{}}}",
                    p.version.0,
                    p.version.1,
                    java_release(p.version.0),
                    p.kotlin,
                    p.dynamic_calls,
                    p.entry.map_or(-1, |e| e as i64)
                ));
            }
            _ => panic!("no such text"),
        }
        out
    });
    put_out(&text)
}
