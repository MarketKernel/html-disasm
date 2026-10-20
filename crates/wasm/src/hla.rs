//! HLA64 lines for the rows on screen (`disasm_core::arm64::hla`, `disasm_core::x86::hla`).
//!
//! A line names what it points at — a function, a label, a string, an import — and those names
//! are the page's: it knows how the settings want functions named. The core cannot ask the page
//! in the middle of a call (it imports nothing), so a line is made in rounds: the page hands over
//! the instruction and the answers it has, the lifter runs, and if it asked about anything the
//! page has not answered yet the call returns those questions (`{"need":[[kind,addr],…]}`) instead
//! of the line. The page answers them and calls again; two rounds are the most a line takes.
//!
//! The input is one little-endian buffer: the instructions (x86 only: as the page printed them),
//! then the answers — a count, and for each its kind (0 target, 1 data, 2 function start,
//! 3 import, 4 a WebAssembly function's name by its index, 5 the address of a Java string, 6 the
//! address of a name the assembler meets), its address (for 5 and 6, the text's number in the order
//! the call asked: the question carries the text) and what is there.

use disasm_core::arm64::decode;
use disasm_core::arm64::hla::{fuse, lift_one, paired_address, raw_instruction};
use disasm_core::jvm::hla::{lone_surrogate, JvmNaming};
use disasm_core::lift::{DataAt, HlaLine, LiftContext, Target, TargetKind};
use disasm_core::text::js_number;
use disasm_core::wasm::hla::WasmNaming;
use disasm_core::x86::hla::{fuse_x86, lift_x86, X86Insn, X86LiftContext};
use std::cell::RefCell;

use super::{json_str, jvm, put_out, slice, webassembly};

const TARGET: u8 = 0;
const DATA: u8 = 1;
const START: u8 = 2;
const IMPORT: u8 = 3;
const NAME: u8 = 4;
const STRING: u8 = 5;
pub(crate) const NAME_ADDR: u8 = 6;

enum Answer {
    Target(Option<Target>),
    Data(Option<DataAt>),
    Start(i64),
    Import(Option<String>),
    Name(String),
    Addr(f64),
}

pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Reader { bytes, at: 0 }
    }

    fn u8(&mut self) -> u8 {
        self.at += 1;
        self.bytes[self.at - 1]
    }

    fn u32(&mut self) -> u32 {
        self.at += 4;
        u32::from_le_bytes(self.bytes[self.at - 4..self.at].try_into().unwrap())
    }

    fn f64(&mut self) -> f64 {
        self.at += 8;
        f64::from_le_bytes(self.bytes[self.at - 8..self.at].try_into().unwrap())
    }

    pub(crate) fn text(&mut self) -> String {
        let len = self.u32() as usize;
        self.at += len;
        String::from_utf8_lossy(&self.bytes[self.at - len..self.at]).into_owned()
    }

    fn maybe(&mut self) -> Option<i64> {
        let v = self.f64();
        (!v.is_nan()).then_some(v as i64)
    }
}

/// The page's answers so far, and the questions the lifter asked that they do not cover.
pub(crate) struct Replay {
    answers: Vec<(u8, i64, Answer)>,
    missing: RefCell<Vec<(u8, i64)>>,
    /// The Java strings asked for, in order: a string's number is its place here.
    texts: RefCell<Vec<String>>,
}

impl Replay {
    pub(crate) fn read(r: &mut Reader) -> Replay {
        let count = r.u32();
        let mut answers = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let kind = r.u8();
            let addr = r.f64() as i64;
            let answer = match kind {
                TARGET => Answer::Target(match r.u8() {
                    0 => None,
                    k => Some(Target {
                        kind: match k {
                            1 => TargetKind::Label,
                            2 => TargetKind::Function,
                            _ => TargetKind::Import,
                        },
                        name: r.text(),
                    }),
                }),
                DATA => Answer::Data(match r.u8() {
                    0 => None,
                    1 => Some(DataAt::String { text: r.text(), objc: false }),
                    2 => Some(DataAt::String { text: r.text(), objc: true }),
                    _ => Some(DataAt::Symbol { name: r.text() }),
                }),
                START => Answer::Start(r.f64() as i64),
                NAME => Answer::Name(r.text()),
                STRING | NAME_ADDR => Answer::Addr(r.f64()),
                _ => Answer::Import(match r.u8() {
                    0 => None,
                    _ => Some(r.text()),
                }),
            };
            answers.push((kind, addr, answer));
        }
        Replay { answers, missing: RefCell::new(Vec::new()), texts: RefCell::new(Vec::new()) }
    }

    fn find(&self, kind: u8, addr: i64) -> Option<&Answer> {
        let found = self.answers.iter().find(|(k, a, _)| *k == kind && *a == addr).map(|(_, _, answer)| answer);
        if found.is_none() {
            let mut missing = self.missing.borrow_mut();
            if !missing.contains(&(kind, addr)) {
                missing.push((kind, addr));
            }
        }
        found
    }

    /// The questions left, as JSON, or None when the line is complete.
    pub(crate) fn need(&self) -> Option<String> {
        let missing = self.missing.borrow();
        if missing.is_empty() {
            return None;
        }
        let texts = self.texts.borrow();
        let list: Vec<String> = missing
            .iter()
            .map(|&(k, a)| {
                if k == STRING || k == NAME_ADDR {
                    let mut text = String::new();
                    json_str(&mut text, &texts[a as usize]);
                    format!("[{k},{a},{}]", unmark(&text))
                } else {
                    format!("[{k},{}]", js_number(a as f64))
                }
            })
            .collect();
        Some(format!("{{\"need\":[{}]}}", list.join(",")))
    }
}

impl LiftContext for Replay {
    fn target(&self, addr: i64) -> Option<Target> {
        match self.find(TARGET, addr) {
            Some(Answer::Target(t)) => t.clone(),
            _ => None,
        }
    }

    fn data(&self, addr: i64) -> Option<DataAt> {
        match self.find(DATA, addr) {
            Some(Answer::Data(d)) => d.clone(),
            _ => None,
        }
    }

    fn function_start(&self, pc: i64) -> i64 {
        match self.find(START, pc) {
            Some(Answer::Start(at)) => *at,
            _ => -1,
        }
    }
}

impl X86LiftContext for Replay {
    fn import_at(&self, addr: i64) -> Option<String> {
        match self.find(IMPORT, addr) {
            Some(Answer::Import(name)) => name.clone(),
            _ => None,
        }
    }
}

impl WasmNaming for Replay {
    fn func(&self, index: u64) -> String {
        match self.find(NAME, index as i64) {
            Some(Answer::Name(name)) => name.clone(),
            _ => String::new(),
        }
    }
}

impl Replay {
    /// The answer to a question about a text (a Java string, a name to assemble): None while unanswered.
    pub(crate) fn text_answer(&self, kind: u8, text: &str) -> Option<f64> {
        let id = {
            let mut texts = self.texts.borrow_mut();
            match texts.iter().position(|t| t == text) {
                Some(k) => k,
                None => {
                    texts.push(text.to_string());
                    texts.len() - 1
                }
            }
        };
        match self.find(kind, id as i64) {
            Some(Answer::Addr(addr)) => Some(*addr),
            _ => None,
        }
    }
}

impl JvmNaming for Replay {
    fn string_addr(&self, text: &str) -> f64 {
        self.text_answer(STRING, text).unwrap_or(-1.0)
    }
}

/// JSON with the lone surrogates of Java text (marked characters, see disasm_core::jvm::hla) as `\udxxx`.
pub(crate) fn unmark(json: &str) -> String {
    if json.is_ascii() {
        return json.to_string();
    }
    let mut out = String::with_capacity(json.len());
    for c in json.chars() {
        match lone_surrogate(c) {
            Some(unit) => out.push_str(&format!("\\u{unit:04x}")),
            None => out.push(c),
        }
    }
    out
}

/// The line as JSON: its text, the HLA64 words it uses, its comment, whether it stands for two
/// instructions, and (arm64) the address its names lead to.
pub(crate) fn line_json(line: &HlaLine, fused: bool, link: Option<i64>) -> String {
    let mut out = String::with_capacity(line.text.len() + 64);
    out.push_str("{\"text\":");
    json_str(&mut out, &line.text);
    out.push_str(",\"words\":[");
    for (k, w) in line.words.iter().enumerate() {
        if k > 0 {
            out.push(',');
        }
        json_str(&mut out, w);
    }
    out.push(']');
    if let Some(comment) = &line.comment {
        out.push_str(",\"comment\":");
        json_str(&mut out, comment);
    }
    out.push_str(if fused { ",\"fused\":true" } else { ",\"fused\":false" });
    if let Some(link) = link {
        out.push_str(",\"link\":");
        out.push_str(&js_number(link as f64));
    }
    out.push('}');
    out
}

/// The HLA64 line of the arm64 instruction `word` at `pc`: `mode` 0 alone, 1 joined with the
/// next one (`next` at `next_pc`) when they make one line, 2 the instruction as printed with
/// its targets named (`{"text"}` only). `input` holds the answers.
///
/// # Safety
/// `input` and `len` must name memory the host wrote.
#[no_mangle]
pub unsafe extern "C" fn arm64_hla(word: u32, pc: f64, next: u32, next_pc: f64, mode: u32, input: *const u8, len: usize) -> usize {
    let mut r = Reader { bytes: slice(input, len), at: 0 };
    let ctx = Replay::read(&mut r);
    let insn = decode(word, pc as i64);
    let text = match mode {
        2 => {
            let mut out = String::from("{\"text\":");
            json_str(&mut out, &raw_instruction(&insn, &ctx));
            out.push('}');
            out
        }
        _ => {
            let pair = if mode == 1 {
                let second = decode(next, next_pc as i64);
                fuse(&insn, &second, &ctx).map(|line| {
                    let link = if insn.m == "adrp" { paired_address(&insn, &second) } else { second.target };
                    (line, link)
                })
            } else {
                None
            };
            match pair {
                Some((line, link)) => line_json(&line, true, link),
                None => line_json(&lift_one(&insn, pc as i64, &ctx), false, insn.target),
            }
        }
    };
    put_out(&ctx.need().unwrap_or(text))
}

/// The address an adrp and the instruction after it build together; NaN when they do not.
#[no_mangle]
pub extern "C" fn arm64_paired(word: u32, pc: f64, next: u32, next_pc: f64) -> f64 {
    paired_address(&decode(word, pc as i64), &decode(next, next_pc as i64)).map_or(f64::NAN, |a| a as f64)
}

fn read_x86(r: &mut Reader) -> X86Insn {
    X86Insn { prefix: r.text(), m: r.text(), ops: r.text(), addr: r.f64() as i64, length: r.f64() as u32, f: r.f64() as u32, target: r.maybe(), mem: r.maybe() }
}

/// The HLA64 line of an x86-64 instruction, given as the page printed it: alone, or (`fused` 1,
/// a second instruction following it in `input`) joined with the next one when they make one line.
///
/// # Safety
/// `input` and `len` must name memory the host wrote.
#[no_mangle]
pub unsafe extern "C" fn x86_hla(fused: u32, input: *const u8, len: usize) -> usize {
    let mut r = Reader { bytes: slice(input, len), at: 0 };
    let first = read_x86(&mut r);
    let second = (fused == 1).then(|| read_x86(&mut r));
    let ctx = Replay::read(&mut r);
    let pair = second.and_then(|second| fuse_x86(&first, &second, &ctx));
    let text = match pair {
        Some(line) => line_json(&line, true, None),
        None => line_json(&lift_x86(&first, &ctx), false, None),
    };
    put_out(&ctx.need().unwrap_or(text))
}

/// The HLA64 line of the WebAssembly instructions first..=last of a module's session, as one
/// statement (`{"none":true}` when they do not make one). `input` holds the answers.
///
/// # Safety
/// `input` and `len` must name memory the host wrote.
#[no_mangle]
pub unsafe extern "C" fn wasm_hla(handle: u32, first: u32, last: u32, input: *const u8, len: usize) -> usize {
    let mut r = Reader { bytes: slice(input, len), at: 0 };
    let ctx = Replay::read(&mut r);
    let line = webassembly::state(handle, |s| s.session.lift_group(first as usize, last as usize, &ctx));
    let text = match line {
        Some(line) => line_json(&line, false, None),
        None => "{\"none\":true}".to_string(),
    };
    put_out(&ctx.need().unwrap_or(text))
}

/// The HLA64 line of the Java instructions first..=last of a session, as one statement
/// (`{"none":true}` when they do not make one). `input` holds the answers (string addresses).
///
/// # Safety
/// `input` and `len` must name memory the host wrote.
#[no_mangle]
pub unsafe extern "C" fn jvm_hla(handle: u32, first: u32, last: u32, input: *const u8, len: usize) -> usize {
    let mut r = Reader { bytes: slice(input, len), at: 0 };
    let ctx = Replay::read(&mut r);
    let line = jvm::state(handle, |s| s.session.lift_group(first as usize, last as usize, &ctx));
    let text = match line {
        Some(line) => unmark(&line_json(&line, false, None)),
        None => "{\"none\":true}".to_string(),
    };
    put_out(&ctx.need().unwrap_or(text))
}
