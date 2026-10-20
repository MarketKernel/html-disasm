//! .NET assemblies analysed in the core (`disasm_core::cil::program`). The page
//! hands the core the PE file with its sections, takes what the pass found
//! once, and keeps the session for the HLA64 lines of the rows it shows
//! (`cil_hla`) and for what it shows of the metadata (cil_page.rs).

use std::sync::atomic::{AtomicU32, Ordering};

use disasm_core::cil::metadata::{MetadataError, Section};
use disasm_core::cil::program::{CilProgram, CilSession};
use disasm_core::refs::RefIndex;

use super::{add_session, json_str, put_out, session, slice, slice_owned, Session};

pub struct CilState {
    pub session: CilSession,
    /// Per function, once the program is ready: its MethodDef row, first instruction and count.
    pub functions: Vec<u32>,
}

/// Opens an assembly; the core takes over `bytes` (from `alloc`, not to be freed). `sections` are
/// `count` quadruples of f64 — RVA, virtual size, raw size, raw offset — and `clr` the RVA of the CLR
/// data directory (negative for none). 0 when the metadata cannot be read; `cil_open_error` says why.
///
/// # Safety
/// `bytes` and `len` must come from one `alloc` call, and the host must not use them again;
/// `sections` must address `count * 4` f64.
#[no_mangle]
pub unsafe extern "C" fn cil_open(bytes: *mut u8, len: usize, sections: *const f64, count: usize, clr: f64) -> u32 {
    let sections = slice(sections, count * 4).chunks(4).map(|s| Section { rva: s[0] as u32, virtual_size: s[1] as u32, raw_size: s[2] as u32, raw_offset: s[3] as u32 }).collect();
    let clr = (clr >= 0.0).then_some(clr as u32);
    match CilSession::open(slice_owned(bytes, len), sections, clr) {
        Ok(session) => add_session(Session::Cil(Box::new(CilState { session, functions: Vec::new() }))),
        Err(e) => {
            OPEN_ERROR.store(if e == MetadataError::NoTables { 2 } else { 1 }, Ordering::Relaxed);
            0
        }
    }
}

static OPEN_ERROR: AtomicU32 = AtomicU32::new(0);

/// Why the last `cil_open` failed: 1 the metadata cannot be found or is damaged, 2 it has no tables.
#[no_mangle]
pub extern "C" fn cil_open_error() -> u32 {
    OPEN_ERROR.load(Ordering::Relaxed)
}

pub(crate) fn state<R>(handle: u32, f: impl FnOnce(&mut CilState) -> R) -> R {
    session(handle, |s| match s {
        Session::Cil(state) => f(state),
        _ => panic!("not a .NET session"),
    })
}

/// Works on for about `budget` instructions; 1 once the program is ready.
#[no_mangle]
pub extern "C" fn cil_step(handle: u32, budget: u32) -> u32 {
    state(handle, |s| {
        if !s.session.step(budget as usize) {
            return 0;
        }
        if let Some(p) = s.session.program() {
            if s.functions.is_empty() {
                s.functions = p.functions.iter().flat_map(|f| [f.method, f.first, f.count]).collect();
            }
        }
        1
    })
}

#[no_mangle]
pub extern "C" fn cil_done(handle: u32) -> u32 {
    state(handle, |s| s.session.progress().0 as u32)
}

#[no_mangle]
pub extern "C" fn cil_total(handle: u32) -> u32 {
    state(handle, |s| s.session.progress().1 as u32)
}

fn meta(s: &mut CilState) -> String {
    let indirect = s.session.program().map_or(0, |p| p.indirect_calls);
    s.session
        .page(|page| {
            let header = &page.metadata().header;
            let (flags, entry, r2r) = (header.flags, header.entry_token, header.managed_native.rva != 0);
            let code = page.code_bytes();
            let mut out = format!("{{\"indirectCalls\":{indirect},\"assembly\":");
            json_str(&mut out, &page.assembly_name());
            out.push_str(",\"framework\":");
            match page.framework() {
                Some(f) => json_str(&mut out, &f),
                None => out.push_str("null"),
            }
            out.push_str(&format!(",\"flags\":{flags},\"entryToken\":{entry},\"r2r\":{r2r},\"codeBytes\":{code}}}"));
            out
        })
        .expect("the program is not ready")
}

fn user_strings(s: &mut CilState) -> String {
    s.session
        .page(|page| {
            let mut out = String::from("[");
            for (k, (index, text)) in page.metadata().user_string_list().iter().enumerate() {
                if k > 0 {
                    out.push(',');
                }
                out.push_str(&format!("[{index},"));
                super::cil_page::json_utf16(&mut out, text);
                out.push(']');
            }
            out.push(']');
            out
        })
        .expect("the program is not ready")
}

fn list(out: &mut String, n: usize, item: &mut dyn FnMut(&mut String, usize)) {
    out.push('[');
    for k in 0..n {
        if k > 0 {
            out.push(',');
        }
        item(out, k);
    }
    out.push(']');
}

/// One of the program's texts in the output buffer (`what`): 0 the mnemonics, one per line; as
/// JSON, 1 the functions (address, kind, name, declaration, the name as the metadata has it), 2 the
/// imports (token, name, declaration, raw name, assembly, type, field), 3 the P/Invokes (method,
/// name, library, entry, flags), 4 the ranges (first, count, `.class` name or null), 5 the rest (the
/// calls not followed, the assembly's name, its target framework, the CLI header's flags and entry
/// token, whether it is ReadyToRun), 6 the strings of #US (index, text).
#[no_mangle]
pub extern "C" fn cil_text(handle: u32, what: u32) -> usize {
    let text = state(handle, |s| {
        match what {
            5 => return meta(s),
            6 => return user_strings(s),
            _ => {}
        }
        let p: &CilProgram = s.session.program().expect("the program is not ready");
        let mut out = String::new();
        match what {
            0 => out = p.mnemonics.join("\n"),
            1 => list(&mut out, p.functions.len(), &mut |out, k| {
                let f = &p.functions[k];
                out.push_str(&format!("[{},\"{}\",", f.addr, f.kind.as_str()));
                json_str(out, &f.name);
                out.push(',');
                json_str(out, &f.full);
                out.push(',');
                json_str(out, &f.raw);
                out.push(']');
            }),
            2 => list(&mut out, p.imported.len(), &mut |out, k| {
                let m = &p.imported[k];
                out.push_str(&format!("[{},", m.token));
                for (j, text) in [&m.name, &m.full, &m.raw, &m.assembly, &m.ty].into_iter().enumerate() {
                    if j > 0 {
                        out.push(',');
                    }
                    json_str(out, text);
                }
                out.push_str(if m.field { ",1]" } else { ",0]" });
            }),
            3 => list(&mut out, p.pinvokes.len(), &mut |out, k| {
                let v = &p.pinvokes[k];
                out.push_str(&format!("[{},", v.method));
                json_str(out, &v.name);
                out.push(',');
                json_str(out, &v.library);
                out.push(',');
                json_str(out, &v.entry);
                out.push_str(&format!(",{}]", v.flags));
            }),
            4 => list(&mut out, p.ranges.len(), &mut |out, k| {
                let r = &p.ranges[k];
                out.push_str(&format!("[{},{},", r.first, r.count));
                match &r.class {
                    Some(class) => json_str(out, class),
                    None => out.push_str("null"),
                }
                out.push(']');
            }),
            _ => panic!("no such text"),
        }
        out
    });
    put_out(&text)
}

/// The arrays of a .NET session, by number (`CIL_VIEW` in src/core/engine/engine.ts).
pub fn view(state: &CilState, id: u32) -> (*const u8, usize) {
    fn of<T>(v: &[T]) -> (*const u8, usize) {
        (v.as_ptr() as *const u8, v.len())
    }
    fn refs(r: &RefIndex, part: u32) -> (*const u8, usize) {
        match part {
            0 => of(&r.keys),
            1 => of(&r.starts),
            _ => of(&r.values),
        }
    }
    let Some(p) = state.session.program() else { return (core::ptr::null(), 0) };
    match id {
        0 => of(&p.offsets),
        1 => of(&p.mnemonic_ids),
        2 => of(&p.flags),
        3 => of(&p.counts),
        4..=6 => refs(&p.callers, id - 4),
        7..=9 => refs(&p.data_refs, id - 7),
        10..=12 => refs(&p.field_refs, id - 10),
        13..=15 => refs(&p.type_refs, id - 13),
        16 => of(&p.target_index),
        17 => of(&p.target_starts),
        18 => of(&p.target_values),
        19 => of(&p.regions),
        20 => of(&state.functions),
        _ => (core::ptr::null(), 0),
    }
}

/// The HLA64 line of the CIL instructions first..=last of an assembly's session, as one statement
/// (`{"none":true}` when they do not make one): its names all come from the metadata.
#[no_mangle]
pub extern "C" fn cil_hla(handle: u32, first: u32, last: u32) -> usize {
    let line = state(handle, |s| s.session.lift_group(first as usize, last as usize));
    put_out(&match line {
        Some(line) => super::hla::line_json(&line, false, None),
        None => "{\"none\":true}".to_string(),
    })
}
