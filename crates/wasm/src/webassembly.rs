//! WebAssembly modules analysed in the core (`disasm_core::wasm::program`). The
//! page reads the module itself for its tables; it takes what the pass found
//! once, and keeps the session for the HLA64 lines of the rows it shows (`wasm_hla`).

use disasm_core::demangle::Demangled;
use disasm_core::refs::RefIndex;
use disasm_core::wasm::decode::{decode_at, operands_text, WasmInsn};
use disasm_core::wasm::dwarf::{read_lines, LineTable};
use disasm_core::wasm::module::{format_context, WasmModule};
use disasm_core::wasm::program::{WasmProgram, WasmSession};
use disasm_core::wasm::reader::Num;

use super::{add_session, json_str, put_out, session, slice, slice_owned, Session};

pub struct WasmState {
    pub session: WasmSession,
    /// Per body of the module, once the program is ready: its first instruction and how many it has.
    pub bodies: Vec<u32>,
    /// The module's source lines (DWARF), once asked for: None while not read, then the table if any.
    pub lines: Option<Option<LineTable>>,
}

/// Opens a module; the core takes over `bytes` (from `alloc`, not to be freed). 0 when the core
/// cannot read it (the page read it first, so that does not happen).
///
/// # Safety
/// `bytes` and `len` must come from one `alloc` call, and the host must not use them again.
#[no_mangle]
pub unsafe extern "C" fn wasm_open(bytes: *mut u8, len: usize) -> u32 {
    match WasmSession::open(slice_owned(bytes, len)) {
        Ok(session) => add_session(Session::Wasm(Box::new(WasmState { session, bodies: Vec::new(), lines: None }))),
        Err(_) => 0,
    }
}

pub(crate) fn state<R>(handle: u32, f: impl FnOnce(&mut WasmState) -> R) -> R {
    session(handle, |s| match s {
        Session::Wasm(state) => f(state),
        _ => panic!("not a WebAssembly session"),
    })
}

/// Works on for about `budget` instructions; 1 once the program is ready.
#[no_mangle]
pub extern "C" fn wasm_step(handle: u32, budget: u32) -> u32 {
    state(handle, |s| {
        if !s.session.step(budget as usize) {
            return 0;
        }
        if let Some(p) = s.session.program() {
            if s.bodies.is_empty() {
                s.bodies = p.bodies.iter().flat_map(|f| [f.first, f.count]).collect();
            }
        }
        1
    })
}

/// How far the work is: bodies decoded, of how many.
#[no_mangle]
pub extern "C" fn wasm_done(handle: u32) -> u32 {
    state(handle, |s| s.session.progress().0 as u32)
}

#[no_mangle]
pub extern "C" fn wasm_total(handle: u32) -> u32 {
    state(handle, |s| s.session.progress().1 as u32)
}

/// A name as the page takes it: the name it was found under, then what it demangles to (null
/// where that is the name itself), and the language.
fn name_json(out: &mut String, raw: &str, d: &Demangled) {
    json_str(out, raw);
    for text in [&d.short, &d.full] {
        out.push(',');
        if text == raw {
            out.push_str("null");
        } else {
            json_str(out, text);
        }
    }
    out.push_str(",\"");
    out.push_str(d.language.as_str());
    out.push('"');
}

/// One of the program's texts in the output buffer (`what`): 0 the mnemonics, one per line; as
/// JSON, 1 the bodies (each its kind, or its kind and name), 2 the imported functions' names,
/// 3 the strings (address, text, segment, NUL-terminated), 4 the segments (index, address, end,
/// file offset, passive), 5 the rest.
#[no_mangle]
pub extern "C" fn wasm_text(handle: u32, what: u32) -> usize {
    let text = state(handle, |s| {
        let p: &WasmProgram = s.session.program().expect("the program is not ready");
        let mut out = String::new();
        let list = |out: &mut String, n: usize, item: &mut dyn FnMut(&mut String, usize)| {
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
            0 => out = p.mnemonics.join("\n"),
            1 => list(&mut out, p.bodies.len(), &mut |out, k| {
                let f = &p.bodies[k];
                match &f.name {
                    None => {
                        out.push('"');
                        out.push_str(f.kind.as_str());
                        out.push('"');
                    }
                    Some((raw, d)) => {
                        out.push_str("[\"");
                        out.push_str(f.kind.as_str());
                        out.push_str("\",");
                        name_json(out, raw, d);
                        out.push(']');
                    }
                }
            }),
            2 => list(&mut out, p.imported.len(), &mut |out, k| {
                let f = &p.imported[k];
                out.push('[');
                name_json(out, &f.raw, &f.name);
                out.push(']');
            }),
            3 => list(&mut out, p.strings.len(), &mut |out, k| {
                let s = &p.strings[k];
                out.push('[');
                out.push_str(&s.addr.to_string());
                out.push(',');
                json_str(out, &s.text);
                out.push_str(&format!(",{},{}]", s.segment, s.cstring as u8));
            }),
            4 => list(&mut out, p.segments.len(), &mut |out, k| {
                let s = &p.segments[k];
                out.push_str(&format!("[{},{},{},{},{}]", s.index, s.addr, s.end, s.start, s.passive as u8));
            }),
            5 => out = format!("{{\"indirectCalls\":{}}}", p.indirect_calls),
            _ => panic!("no such text"),
        }
        out
    });
    put_out(&text)
}

/// The arrays of a WebAssembly session, by number (`WASM_VIEW` in src/core/engine/engine.ts).
pub fn view(state: &WasmState, id: u32) -> (*const u8, usize) {
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
        1 => of(&p.depth),
        2 => of(&p.mnemonic_ids),
        3 => of(&p.flags),
        4 => of(&p.counts),
        5..=7 => refs(&p.callers, id - 5),
        8..=10 => refs(&p.data_refs, id - 8),
        11..=13 => refs(&p.ref_funcs, id - 11),
        14..=16 => refs(&p.global_refs, id - 14),
        17..=19 => refs(&p.indirect, id - 17),
        20 => of(&p.target_index),
        21 => of(&p.target_starts),
        22 => of(&p.target_values),
        23 => of(&p.value_branches),
        24 => of(&p.length_addr),
        25 => of(&p.length_value),
        26 => of(&state.bodies),
        27 => state.lines.as_ref().and_then(|l| l.as_ref()).map_or((core::ptr::null(), 0), |l| of(&l.addrs)),
        28 => state.lines.as_ref().and_then(|l| l.as_ref()).map_or((core::ptr::null(), 0), |l| of(&l.rows)),
        _ => (core::ptr::null(), 0),
    }
}

fn num_json(out: &mut String, v: Num) {
    match v {
        Num::Number(n) => out.push_str(&n.to_string()),
        Num::BigInt(b) => out.push_str(&format!("{{\"big\":\"{b}\"}}")),
    }
}

/// An instruction as the page reads it: what the decoder read (its mnemonic, where it is, its
/// immediates; the opcode as [code, immediate kind, flags, group, bytes a load or store moves]) and
/// its operands as the text format prints them, alone and with the module's types (block types by
/// signature) when there is a module.
fn insn_json(insn: &WasmInsn, module: Option<&WasmModule>) -> String {
    let mut out = String::with_capacity(160);
    out.push_str("{\"m\":");
    json_str(&mut out, insn.m);
    out.push_str(&format!(",\"pos\":{},\"len\":{},\"a\":{},\"b\":{},\"value\":", insn.pos, insn.len, insn.a, insn.b));
    num_json(&mut out, insn.value);
    out.push_str(&format!(",\"align\":{},\"mem\":{},\"labels\":", insn.align, insn.mem));
    if insn.op.is_some_and(|o| o.imm == disasm_core::wasm::imm::BR_TABLE) {
        out.push('[');
        for (k, l) in insn.labels.iter().enumerate() {
            if k > 0 {
                out.push(',');
            }
            out.push_str(&l.to_string());
        }
        out.push(']');
    } else {
        out.push_str("null");
    }
    out.push_str(",\"op\":");
    match insn.op {
        Some(o) => out.push_str(&format!("[{},{},{},\"{}\",{}]", o.code, o.imm, o.flags, o.group.name(), o.size)),
        None => out.push_str("null"),
    }
    let plain = operands_text(insn, None);
    out.push_str(",\"ops\":");
    json_str(&mut out, &plain);
    out.push_str(",\"opsCtx\":");
    match module {
        Some(module) => json_str(&mut out, &operands_text(insn, Some(&format_context(module)))),
        None => json_str(&mut out, &plain),
    }
    out.push('}');
    out
}

/// One instruction of the program, for a row or the details (`insn_json`), or null.
#[no_mangle]
pub extern "C" fn wasm_insn(handle: u32, index: u32) -> usize {
    let text = state(handle, |s| {
        let mut insn = WasmInsn::new();
        if !s.session.decode_insn(index as usize, &mut insn) {
            return "null".to_string();
        }
        insn_json(&insn, s.session.module())
    });
    put_out(&text)
}

/// The first instruction of some bytes, with no module around them (`insn_json`): for the tests.
///
/// # Safety
/// `bytes` and `len` must name memory the host wrote.
#[no_mangle]
pub unsafe extern "C" fn wasm_decode(bytes: *const u8, len: usize) -> usize {
    let bytes = slice(bytes, len);
    let mut insn = WasmInsn::new();
    decode_at(bytes, 0, bytes.len(), &mut insn);
    put_out(&insn_json(&insn, None))
}

/// Every instruction of every function body of a module, as the text format prints it, for
/// tools/verify-wasm.mjs: a line each, `pos len known typed text` (tab-separated; known 1 when the
/// opcode is one, typed 1 when its block type is a type index), a body ending at an unknown opcode as
/// the decoder does; or `error` and the reason when the module cannot be read.
///
/// # Safety
/// `bytes` and `len` must name memory the host wrote.
#[no_mangle]
pub unsafe extern "C" fn wasm_print(bytes: *const u8, len: usize) -> usize {
    let module = match disasm_core::wasm::module::parse_wasm(slice(bytes, len).to_vec()) {
        Ok(m) => m,
        Err(e) => return put_out(&format!("error\t{e:?}")),
    };
    let ctx = format_context(&module);
    let mut out = String::new();
    let mut insn = WasmInsn::new();
    for body in &module.bodies {
        let mut pos = body.code;
        while pos < body.end {
            decode_at(&module.bytes, pos, body.end, &mut insn);
            let typed = matches!(insn.block, Some(disasm_core::wasm::BlockType::Type(_)));
            out.push_str(&format!("{}\t{}\t{}\t{}\t{}{}\n", pos, insn.len, u8::from(insn.op.is_some()), u8::from(typed), insn.m, operands_text(&insn, Some(&ctx))));
            if insn.op.is_none() || insn.len == 0 {
                break;
            }
            pos += insn.len;
        }
    }
    put_out(&out)
}

/// What a function's instructions call and name (the first 50000 of them, from `first`, `count`
/// in all): `{"calls":[[func,times]…],"indirect":n,"consts":[…]}` — the functions called by index
/// in the order first met, how many calls go through a table or a reference, and the i32
/// constants the analysis found used as data addresses, in order.
#[no_mangle]
pub extern "C" fn wasm_fn_refs(handle: u32, first: u32, count: u32) -> usize {
    let text = state(handle, |s| {
        let p = s.session.program().expect("the program is not ready");
        let mut insn = WasmInsn::new();
        let mut calls: Vec<(u64, u32)> = Vec::new();
        let mut indirect = 0u32;
        let mut consts = String::new();
        for i in first..first + count.min(50000) {
            if !s.session.decode_insn(i as usize, &mut insn) {
                break;
            }
            if insn.m == "call" || insn.m == "return_call" {
                match calls.iter_mut().find(|(f, _)| *f == insn.a) {
                    Some((_, n)) => *n += 1,
                    None => calls.push((insn.a, 1)),
                }
            } else if insn.op.is_some_and(|o| o.flags & disasm_core::wasm::w::CALL != 0) {
                indirect += 1;
            } else if insn.m == "i32.const" {
                if let Num::Number(v) = insn.value {
                    if p.data_refs.has(v) {
                        if !consts.is_empty() {
                            consts.push(',');
                        }
                        consts.push_str(&v.to_string());
                    }
                }
            }
        }
        let calls: Vec<String> = calls.iter().map(|(f, n)| format!("[{f},{n}]")).collect();
        format!("{{\"calls\":[{}],\"indirect\":{indirect},\"consts\":[{consts}]}}", calls.join(","))
    });
    put_out(&text)
}

/// The module's source lines from DWARF: the file names as JSON (null when it has no line table or
/// it cannot be read); the rows are then views 27 (addresses) and 28 (file, line, column).
#[no_mangle]
pub extern "C" fn wasm_lines(handle: u32) -> usize {
    let text = state(handle, |s| {
        if s.lines.is_none() {
            let module = s.session.module().expect("the program is not ready");
            s.lines = Some(read_lines(module).ok().flatten());
        }
        match s.lines.as_ref().and_then(|l| l.as_ref()) {
            Some(lines) => {
                let mut out = String::from("[");
                for (k, f) in lines.files.iter().enumerate() {
                    if k > 0 {
                        out.push(',');
                    }
                    json_str(&mut out, f);
                }
                out.push(']');
                out
            }
            None => "null".to_string(),
        }
    });
    put_out(&text)
}
