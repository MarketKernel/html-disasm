//! The core as a WebAssembly module: a plain C ABI, and no imports at all.
//!
//! The module asks nothing of its host — no console, no clock, no callbacks —
//! so the same file runs in a browser, in Node, in Electron or in wasmtime.
//! The host:
//!
//! - copies a file in once (`alloc`, then a write into `memory`);
//! - opens a session on it (`arm64_open`) and runs it in steps
//!   (`arm64_step`), showing progress between them if it likes;
//! - reads the results in place: `view` / `view_len` give the address and
//!   length of each array (instruction words, mnemonic numbers, flags, cross
//!   references), which the host wraps in a typed array without copying;
//! - asks small questions one at a time (`arm64_insn`: one instruction as
//!   JSON), the answer's text left in the output buffer (`out_ptr`).
//!
//! Views stay valid until memory grows: a host re-reads `view` after any call
//! that may allocate (the TypeScript side checks `memory.buffer` for that).
//! A panic traps; the message is kept for `error_ptr` / `error_len`.

use std::cell::RefCell;

mod archive;
mod assemble;
mod cil;
mod cil_page;
mod containers;
mod demangle;
mod hla;
mod jvm;
mod jvm_page;
mod native;
mod native_image;
mod resign;
mod wasm_module;
mod webassembly;

use disasm_core::arm32::pass::{kind as arm32_kind, Arm32Pass, Arm32Refs, DATA_NAMES as ARM32_DATA};
use disasm_core::arm64::pass::{Arm64Pass, Arm64Refs};
use disasm_core::arm64::types::{Insn, Mode, Op};
use disasm_core::arm64::{decode, format_insn};
use disasm_core::refs::RefIndex;
use disasm_core::text::js_number;
use disasm_core::x86::decode::{decode_x86, McOp};
use disasm_core::x86::pass::{fixed_address_of, flags_of, target_of, X86Pass, X86Refs};
use disasm_core::x86::print::print_x86;

pub(crate) enum Session {
    Arm64 { pass: Arm64Pass, refs: Option<Arm64Refs> },
    X86 { pass: Box<X86Pass>, refs: Option<X86Refs>, pairs: X86Pairs },
    Arm32 { pass: Box<Arm32Pass>, refs: Option<Arm32Refs>, pairs: X86Pairs },
    Jvm(Box<jvm::JvmState>),
    Wasm(Box<webassembly::WasmState>),
    Cil(Box<cil::CilState>),
    Archive(Box<archive::ArchiveState>),
}

/// The sparse maps of an x86 pass (instruction index → address), split into the two arrays a view gives.
#[derive(Default)]
pub(crate) struct X86Pairs {
    address_index: Vec<u32>,
    address_value: Vec<f64>,
    code_index: Vec<u32>,
    code_value: Vec<f64>,
    target_index: Vec<u32>,
    target_value: Vec<f64>,
    ranges: Vec<u32>,
}

#[derive(Default)]
struct State {
    sessions: Vec<Option<Session>>,
    out: Vec<u8>,
    error: String,
    /// The JSON of why the last `jvm_open` failed.
    open_error: String,
    /// The images of native sessions (by handle), and what the analysis after their pass found.
    natives: std::collections::HashMap<u32, native::NativeState>,
}

thread_local! {
    static STATE: RefCell<State> = RefCell::new(State::default());
}

fn with<R>(f: impl FnOnce(&mut State) -> R) -> R {
    STATE.with(|s| f(&mut s.borrow_mut()))
}

/// Keeps the text of a panic for the host, which sees only a trap.
#[no_mangle]
pub extern "C" fn init() {
    std::panic::set_hook(Box::new(|info| {
        let message = info.to_string();
        // The state may be borrowed where the panic happened: then the message is lost, not the trap.
        STATE.with(|s| {
            if let Ok(mut s) = s.try_borrow_mut() {
                s.error = message;
            }
        });
    }));
}

#[no_mangle]
pub extern "C" fn error_ptr() -> *const u8 {
    with(|s| s.error.as_ptr())
}

#[no_mangle]
pub extern "C" fn error_len() -> usize {
    with(|s| s.error.len())
}

/* ------------------------------------------------------------------ *
 * Memory
 * ------------------------------------------------------------------ */

/// A buffer of `len` bytes for the host to write into; it is the host's until `dealloc`.
#[no_mangle]
pub extern "C" fn alloc(len: usize) -> *mut u8 {
    let mut buf = Vec::<u8>::with_capacity(len.max(1));
    let ptr = buf.as_mut_ptr();
    core::mem::forget(buf);
    ptr
}

/// # Safety
/// `ptr` and `len` must come from one `alloc` call.
#[no_mangle]
pub unsafe extern "C" fn dealloc(ptr: *mut u8, len: usize) {
    drop(Vec::from_raw_parts(ptr, 0, len.max(1)));
}

/// The text the last call left (its length is what that call returned).
#[no_mangle]
pub extern "C" fn out_ptr() -> *const u8 {
    with(|s| s.out.as_ptr())
}

fn put_out(text: &str) -> usize {
    with(|s| {
        s.out.clear();
        s.out.extend_from_slice(text.as_bytes());
        s.out.len()
    })
}

fn add_session(session: Session) -> u32 {
    with(|s| {
        if let Some(free) = s.sessions.iter().position(Option::is_none) {
            s.sessions[free] = Some(session);
            return free as u32 + 1;
        }
        s.sessions.push(Some(session));
        s.sessions.len() as u32
    })
}

fn session<R>(handle: u32, f: impl FnOnce(&mut Session) -> R) -> R {
    with(|s| {
        let session = s.sessions.get_mut(handle.wrapping_sub(1) as usize).and_then(Option::as_mut).expect("no such session");
        f(session)
    })
}

#[no_mangle]
pub extern "C" fn close(handle: u32) {
    with(|s| {
        if let Some(slot) = s.sessions.get_mut(handle.wrapping_sub(1) as usize) {
            *slot = None;
        }
        s.natives.remove(&handle);
    });
}

/* ------------------------------------------------------------------ *
 * arm64
 * ------------------------------------------------------------------ */

/// A buffer from `alloc`, taken over by the core.
unsafe fn slice_owned(ptr: *mut u8, len: usize) -> Vec<u8> {
    Vec::from_raw_parts(ptr, len, len.max(1))
}

unsafe fn slice<'a, T>(ptr: *const T, len: usize) -> &'a [T] {
    if len == 0 {
        &[]
    } else {
        core::slice::from_raw_parts(ptr, len)
    }
}

/// Decodes up to `budget` instructions more; 1 once the pass is over (and its references are built).
#[no_mangle]
pub extern "C" fn arm64_step(handle: u32, budget: u32) -> u32 {
    session(handle, |s| match s {
        Session::Arm64 { pass, refs } => {
            if refs.is_some() {
                return 1;
            }
            if pass.step(budget) {
                *refs = Some(pass.finish());
                1
            } else {
                0
            }
        }
        _ => panic!("not an arm64 session"),
    })
}

#[no_mangle]
pub extern "C" fn arm64_done(handle: u32) -> u32 {
    session(handle, |s| match s {
        Session::Arm64 { pass, .. } => pass.done(),
        Session::X86 { pass, .. } => pass.done(),
        Session::Arm32 { pass, .. } => pass.done(),
        Session::Jvm(_) | Session::Wasm(_) | Session::Cil(_) | Session::Archive(_) => panic!("a bytecode session has its own progress"),
    })
}

#[no_mangle]
pub extern "C" fn arm64_total(handle: u32) -> u32 {
    session(handle, |s| match s {
        Session::Arm64 { pass, .. } => pass.total(),
        Session::X86 { pass, .. } => pass.total(),
        Session::Arm32 { pass, .. } => pass.total(),
        Session::Jvm(_) | Session::Wasm(_) | Session::Cil(_) | Session::Archive(_) => panic!("a bytecode session has its own progress"),
    })
}

/// The mnemonics by number, one per line, in the output buffer.
#[no_mangle]
pub extern "C" fn arm64_mnemonics(handle: u32) -> usize {
    let text = session(handle, |s| match s {
        Session::Arm64 { pass, .. } => pass.mnemonics.iter().map(|m| m.as_str()).collect::<Vec<_>>().join("\n"),
        Session::X86 { pass, .. } => pass.mnemonics.join("\n"),
        Session::Arm32 { pass, .. } => pass.mnemonics.join("\n"),
        Session::Jvm(_) | Session::Wasm(_) | Session::Cil(_) | Session::Archive(_) => panic!("a bytecode session has its own texts"),
    });
    put_out(&text)
}

/// One instruction of the program as JSON (the TypeScript `Insn`), in the output buffer.
#[no_mangle]
pub extern "C" fn arm64_insn(handle: u32, index: u32) -> usize {
    let insn = session(handle, |s| match s {
        Session::Arm64 { pass, .. } => pass.insn(index),
        _ => panic!("not an arm64 session"),
    });
    put_out(&insn_json(&insn))
}

/// Any word decoded at an address, as JSON: for the editor, which tries words not in the file.
#[no_mangle]
pub extern "C" fn arm64_decode(word: u32, pc: f64) -> usize {
    put_out(&insn_json(&decode(word, pc as i64)))
}

/// The same as text, as llvm-objdump prints it.
#[no_mangle]
pub extern "C" fn arm64_text(word: u32, pc: f64) -> usize {
    put_out(format_insn(&decode(word, pc as i64)).as_str())
}

/* ------------------------------------------------------------------ *
 * x86
 * ------------------------------------------------------------------ */

/// Decodes up to `budget` instructions more; 1 once the pass and what follows it are over.
#[no_mangle]
pub extern "C" fn x86_step(handle: u32, budget: u32) -> u32 {
    session(handle, |s| match s {
        Session::X86 { pass, refs, pairs } => {
            if refs.is_some() {
                return 1;
            }
            if !pass.step(budget) {
                return 0;
            }
            *refs = Some(pass.finish());
            let split = |list: &[(u32, i64)]| -> (Vec<u32>, Vec<f64>) { (list.iter().map(|p| p.0).collect(), list.iter().map(|p| p.1 as f64).collect()) };
            (pairs.address_index, pairs.address_value) = split(&pass.address_at);
            (pairs.code_index, pairs.code_value) = split(&pass.code_at);
            (pairs.target_index, pairs.target_value) = split(&pass.rel_targets);
            1
        }
        _ => panic!("not an x86 session"),
    })
}

/// One x86 instruction decoded from `len` bytes (at most 15, the instruction's and what follows it in
/// its section), with its printed text and what the analysis reads of it, as JSON.
///
/// # Safety
/// `bytes` must address `len` valid bytes in this module's memory.
#[no_mangle]
pub unsafe extern "C" fn x86_decode(bytes: *const u8, len: usize, addr: f64, mode: u32) -> usize {
    let bytes = slice(bytes, len);
    let d = decode_x86(bytes, 0, bytes.len(), addr as i64, mode as u8);
    let p = print_x86(&d);
    let mut out = String::with_capacity(256);
    out.push_str("{\"id\":");
    out.push_str(&d.id.to_string());
    out.push_str(",\"length\":");
    out.push_str(&d.length.to_string());
    out.push_str(",\"addr\":");
    out.push_str(&d.addr.to_string());
    out.push_str(",\"mode\":");
    out.push_str(&d.mode.to_string());
    out.push_str(",\"ops\":[");
    for (k, op) in d.ops.iter().enumerate() {
        if k > 0 {
            out.push(',');
        }
        match op {
            McOp::Reg(r) => json_str(&mut out, r),
            McOp::Imm(v) => out.push_str(&v.to_string()),
            McOp::Big(v) => {
                // The TypeScript's bigint is the unsigned value of the eight bytes.
                out.push_str("{\"big\":\"");
                out.push_str(&(*v as u64).to_string());
                out.push_str("\"}");
            }
        }
    }
    out.push_str("],\"types\":[");
    for (k, t) in d.types.iter().enumerate() {
        if k > 0 {
            out.push(',');
        }
        out.push_str(&t.to_string());
    }
    out.push_str("],\"flags\":");
    out.push_str(&d.flags.to_string());
    out.push_str(",\"xacquire\":");
    out.push_str(if d.xacquire { "true" } else { "false" });
    out.push_str(",\"prefix\":");
    json_str(&mut out, &p.prefix);
    out.push_str(",\"m\":");
    json_str(&mut out, &p.m);
    out.push_str(",\"text\":");
    json_str(&mut out, &p.ops);
    out.push_str(",\"f\":");
    out.push_str(&flags_of(&d).to_string());
    if let Some(t) = target_of(&d) {
        out.push_str(",\"target\":");
        out.push_str(&t.to_string());
    }
    if let Some(m) = fixed_address_of(&d, false) {
        out.push_str(",\"mem\":");
        out.push_str(&m.to_string());
    }
    if let Some(m) = fixed_address_of(&d, true) {
        out.push_str(",\"memAbs\":");
        out.push_str(&m.to_string());
    }
    out.push('}');
    put_out(&out)
}

/* ------------------------------------------------------------------ *
 * AArch32
 * ------------------------------------------------------------------ */

#[no_mangle]
pub extern "C" fn arm32_step(handle: u32, budget: u32) -> u32 {
    session(handle, |s| match s {
        Session::Arm32 { pass, refs, pairs } => {
            if refs.is_some() {
                return 1;
            }
            if !pass.step(budget) {
                return 0;
            }
            *refs = Some(pass.finish());
            let split = |list: &[(u32, i64)]| -> (Vec<u32>, Vec<f64>) { (list.iter().map(|p| p.0).collect(), list.iter().map(|p| p.1 as f64).collect()) };
            (pairs.address_index, pairs.address_value) = split(&pass.address_pairs());
            // The calls through an import's slot ride in the code pairs (an AArch32 pass has no code addresses of its own).
            (pairs.code_index, pairs.code_value) = split(&pass.slot_calls);
            (pairs.target_index, pairs.target_value) = split(&pass.targets);
            1
        }
        _ => panic!("not an AArch32 session"),
    })
}

/// Whether the layout came from the file's mapping symbols (exact) rather than worked out.
#[no_mangle]
pub extern "C" fn arm32_mapped(handle: u32) -> u32 {
    session(handle, |s| match s {
        Session::Arm32 { pass, .. } => pass.mapped as u32,
        _ => 0,
    })
}

/// Whether an Armv8 T32 FP or SIMD encoding ignores the IT block around it (and takes no slot of it).
#[no_mangle]
pub extern "C" fn arm32_ignores_it(word: u32) -> u32 {
    disasm_core::arm32::simd::ignores_it(word) as u32
}

/// One entry of AArch32 code by its kind (A32, T16, T32, or a data word, short, byte) at an address,
/// with the IT condition it runs under (-1 for none), as JSON: the TypeScript `Insn`.
#[no_mangle]
pub extern "C" fn arm32_decode(k: u32, word: u32, pc: f64, it: i32) -> usize {
    let k = k as u8;
    if k >= arm32_kind::WORD {
        let bytes = match k {
            arm32_kind::WORD => 4,
            arm32_kind::SHORT => 2,
            _ => 1,
        };
        let text = format!("0x{:0width$x}", word, width = bytes * 2);
        let mut out = String::from("{\"m\":");
        json_str(&mut out, ARM32_DATA[k as usize]);
        out.push_str(&format!(",\"ops\":[{{\"k\":\"imm\",\"v\":{word},\"t\":\"{text}\"}}],\"f\":0,\"size\":{},\"bytes\":{bytes}}}", if bytes == 4 { 4 } else { 2 }));
        return put_out(&out);
    }
    let insn = disasm_core::arm32::pass::decode_at(k, word, pc as i64, it);
    put_out(&arm32_json(&insn))
}

fn arm32_json(insn: &disasm_core::arm32::Insn) -> String {
    use disasm_core::arm32::types::Mode;
    use disasm_core::arm32::Op as A;
    let mut out = String::with_capacity(160);
    out.push_str("{\"m\":");
    json_str(&mut out, &insn.m);
    out.push_str(",\"ops\":[");
    for (k, op) in insn.ops.iter().enumerate() {
        if k > 0 {
            out.push(',');
        }
        match op {
            A::Reg { r, wb } => {
                out.push_str("{\"k\":\"reg\",\"r\":");
                json_str(&mut out, r);
                if *wb {
                    out.push_str(",\"wb\":true");
                }
            }
            A::Imm { v, t } => {
                out.push_str("{\"k\":\"imm\",\"v\":");
                out.push_str(&js_number(*v));
                out.push_str(",\"t\":");
                json_str(&mut out, t);
            }
            A::Label(addr) => {
                out.push_str("{\"k\":\"label\",\"addr\":");
                out.push_str(&addr.to_string());
            }
            A::Mem(m) => {
                out.push_str("{\"k\":\"mem\",\"base\":");
                json_str(&mut out, &m.base);
                out.push_str(",\"t\":");
                json_str(&mut out, &m.t);
                if let Some(off) = m.off {
                    out.push_str(",\"off\":");
                    out.push_str(&off.to_string());
                }
                if let Some(index) = &m.index {
                    out.push_str(",\"index\":");
                    json_str(&mut out, index);
                }
                out.push_str(match m.mode {
                    Mode::Off => ",\"mode\":\"off\"",
                    Mode::Pre => ",\"mode\":\"pre\"",
                    Mode::Post => ",\"mode\":\"post\"",
                });
            }
            A::List(list) => {
                out.push_str("{\"k\":\"list\",\"regs\":[");
                for (i, r) in list.regs().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    json_str(&mut out, &r);
                }
                out.push_str("],\"t\":");
                let mut t = disasm_core::text::Str::<200>::new();
                list.push_text(&mut t);
                json_str(&mut out, &t);
            }
            A::Shift(t) => {
                out.push_str("{\"k\":\"shift\",\"t\":");
                json_str(&mut out, t);
            }
            A::Text(t) => {
                out.push_str("{\"k\":\"text\",\"t\":");
                json_str(&mut out, t);
            }
        }
        out.push('}');
    }
    out.push_str("],\"f\":");
    out.push_str(&insn.f.to_string());
    out.push_str(",\"size\":");
    out.push_str(&insn.size.to_string());
    if let Some(t) = insn.target {
        out.push_str(",\"target\":");
        out.push_str(&t.to_string());
    }
    if let Some(c) = insn.cond {
        out.push_str(",\"cond\":");
        json_str(&mut out, c);
    }
    if let Some(t) = insn.thumb {
        out.push_str(if t { ",\"thumb\":true" } else { ",\"thumb\":false" });
    }
    if let Some(it) = &insn.it {
        out.push_str(",\"it\":[");
        for (i, c) in it.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str(&c.to_string());
        }
        out.push(']');
    }
    if insn.bytes != 0 {
        out.push_str(",\"bytes\":");
        out.push_str(&insn.bytes.to_string());
    }
    out.push('}');
    out
}

/* ------------------------------------------------------------------ *
 * Views
 * ------------------------------------------------------------------ */

/// The arrays a session exposes, by number. The TypeScript side (src/engine) names them.
fn view_of(session: &Session, id: u32) -> (*const u8, usize) {
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
    match session {
        Session::Arm64 { pass, refs: found } => match (id, found) {
            (0, _) => of(&pass.words),
            (1, _) => of(&pass.mnemonic_ids),
            (2, _) => of(&pass.flags),
            (3, _) => of(&pass.counts),
            (4..=6, Some(r)) => refs(&r.callers, id - 4),
            (7..=9, Some(r)) => refs(&r.data_refs, id - 7),
            (10..=12, Some(r)) => refs(&r.slot_callers, id - 10),
            (13, Some(r)) => of(&r.slot_call_index),
            (14, Some(r)) => of(&r.slot_call_slot),
            (15, Some(r)) => of(&r.length_addr),
            (16, Some(r)) => of(&r.length_value),
            _ => (core::ptr::null(), 0),
        },
        Session::X86 { pass, refs: found, pairs } => match (id, found) {
            (0, _) => of(&pass.offs),
            (1, _) => of(&pass.lens),
            (2, _) => of(&pass.kinds),
            (3, _) => of(&pass.mnemonic_ids),
            (4, _) => of(&pass.flags),
            (5, _) => of(&pass.counts),
            (6, _) => of(&pairs.ranges),
            (7..=9, Some(r)) => refs(&r.callers, id - 7),
            (10..=12, Some(r)) => refs(&r.data_refs, id - 10),
            (13..=15, Some(r)) => refs(&r.slot_callers, id - 13),
            (16, Some(r)) => of(&r.table_index),
            (17, Some(r)) => of(&r.table_starts),
            (18, Some(r)) => of(&r.table_targets),
            (19, _) => of(&pairs.address_index),
            (20, _) => of(&pairs.address_value),
            (21, _) => of(&pairs.code_index),
            (22, _) => of(&pairs.code_value),
            (23, _) => of(&pairs.target_index),
            (24, _) => of(&pairs.target_value),
            _ => (core::ptr::null(), 0),
        },
        Session::Arm32 { pass, refs: found, pairs } => match (id, found) {
            (0, _) => of(&pass.layout.addrs),
            (1, _) => of(&pass.layout.words),
            (2, _) => of(&pass.layout.kinds),
            (3, _) => of(&pass.layout.its),
            (4, _) => of(&pass.mnemonic_ids),
            (5, _) => of(&pass.flags),
            (6, _) => of(&pass.counts),
            (7, _) => of(&pairs.ranges),
            (8..=10, Some(r)) => refs(&r.callers, id - 8),
            (11..=13, Some(r)) => refs(&r.data_refs, id - 11),
            (14..=16, Some(r)) => refs(&r.slot_callers, id - 14),
            (17, Some(r)) => of(&r.table_index),
            (18, Some(r)) => of(&r.table_starts),
            (19, Some(r)) => of(&r.table_targets),
            (20, _) => of(&pairs.address_index),
            (21, _) => of(&pairs.address_value),
            (22, _) => of(&pairs.code_index),
            (23, _) => of(&pairs.code_value),
            (24, _) => of(&pairs.target_index),
            (25, _) => of(&pairs.target_value),
            _ => (core::ptr::null(), 0),
        },
        Session::Jvm(state) => match state.session.program() {
            Some(p) => {
                let r = &p.result;
                match id {
                    0 => of(&r.offsets),
                    1 => of(&r.mnemonic_ids),
                    2 => of(&r.flags),
                    3 => of(&r.counts),
                    4..=6 => refs(&r.callers, id - 4),
                    7..=9 => refs(&r.data_refs, id - 7),
                    10..=12 => refs(&r.field_refs, id - 10),
                    13 => of(&r.target_index),
                    14 => of(&r.target_starts),
                    15 => of(&r.target_values),
                    16 => of(&r.target_lists),
                    17 => of(&state.bodies),
                    18 => of(&state.ranges),
                    19 => of(&p.field_starts),
                    20 => of(&r.callee_keys),
                    21 => of(&r.callee_values),
                    22 => of(&r.field_keys),
                    23 => of(&r.field_values),
                    _ => (core::ptr::null(), 0),
                }
            }
            None => (core::ptr::null(), 0),
        },
        Session::Wasm(state) => webassembly::view(state, id),
        Session::Cil(state) => cil::view(state, id),
        Session::Archive(state) => (state.read.as_ptr(), state.read.len()),
    }
}

#[no_mangle]
pub extern "C" fn view(handle: u32, id: u32) -> *const u8 {
    session(handle, |s| view_of(s, id).0)
}

/// The number of elements (not bytes) in a view.
#[no_mangle]
pub extern "C" fn view_len(handle: u32, id: u32) -> usize {
    session(handle, |s| view_of(s, id).1)
}

/* ------------------------------------------------------------------ *
 * JSON
 * ------------------------------------------------------------------ */

fn json_str(out: &mut String, s: &str) {
    out.push('"');
    // Runs that need no escape are copied whole.
    let mut start = 0;
    for (i, &b) in s.as_bytes().iter().enumerate() {
        if b == b'"' || b == b'\\' || b < 0x20 {
            out.push_str(&s[start..i]);
            match b {
                b'"' => out.push_str("\\\""),
                b'\\' => out.push_str("\\\\"),
                _ => {
                    const HEX: &[u8; 16] = b"0123456789abcdef";
                    out.push_str("\\u00");
                    out.push(HEX[(b >> 4) as usize] as char);
                    out.push(HEX[(b & 15) as usize] as char);
                }
            }
            start = i + 1;
        }
    }
    out.push_str(&s[start..]);
    out.push('"');
}

fn op_json(out: &mut String, op: &Op) {
    match op {
        Op::Reg(r) => {
            out.push_str("{\"k\":\"reg\",\"r\":");
            json_str(out, r);
        }
        Op::Imm { v, t } => {
            out.push_str("{\"k\":\"imm\",\"v\":");
            out.push_str(&js_number(*v));
            out.push_str(",\"t\":");
            json_str(out, t);
        }
        Op::Label(addr) => {
            out.push_str("{\"k\":\"label\",\"addr\":");
            out.push_str(&addr.to_string());
        }
        Op::Shift { s, amount, t } => {
            out.push_str("{\"k\":\"shift\",\"s\":");
            json_str(out, s);
            out.push_str(",\"amount\":");
            out.push_str(&amount.to_string());
            out.push_str(",\"t\":");
            json_str(out, t);
        }
        Op::Text(t) => {
            out.push_str("{\"k\":\"text\",\"t\":");
            json_str(out, t);
        }
        Op::Mem(m) => {
            out.push_str("{\"k\":\"mem\",\"base\":");
            json_str(out, &m.base);
            out.push_str(",\"off\":");
            out.push_str(&m.off.to_string());
            if let Some(index) = &m.index {
                out.push_str(",\"index\":");
                json_str(out, index);
                if let Some(ext) = &m.ext {
                    out.push_str(",\"ext\":");
                    json_str(out, ext);
                }
                out.push_str(",\"amount\":");
                out.push_str(&m.amount.unwrap_or(0).to_string());
                out.push_str(",\"showAmount\":");
                out.push_str(if m.show_amount { "true" } else { "false" });
            }
            out.push_str(",\"mode\":");
            out.push_str(match m.mode {
                Mode::Off => "\"off\"",
                Mode::Pre => "\"pre\"",
                Mode::Post => "\"post\"",
            });
            if let Some(post) = &m.post {
                out.push_str(",\"post\":");
                json_str(out, post);
            }
            if m.decimal {
                out.push_str(",\"decimal\":true");
            }
        }
    }
    out.push('}');
}

/// An instruction as the TypeScript `Insn` (src/core/arm64/types.ts).
pub fn insn_json(insn: &Insn) -> String {
    let mut out = String::with_capacity(160);
    out.push_str("{\"m\":");
    json_str(&mut out, &insn.m);
    out.push_str(",\"ops\":[");
    for (i, op) in insn.ops.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        op_json(&mut out, op);
    }
    out.push_str("],\"f\":");
    out.push_str(&insn.f.to_string());
    if let Some(target) = insn.target {
        out.push_str(",\"target\":");
        out.push_str(&target.to_string());
    }
    if let Some(cond) = insn.cond {
        out.push_str(",\"cond\":");
        json_str(&mut out, cond);
    }
    if insn.size != 0 {
        out.push_str(",\"size\":");
        out.push_str(&insn.size.to_string());
    }
    if insn.signed {
        out.push_str(",\"signed\":true");
    }
    out.push('}');
    out
}
