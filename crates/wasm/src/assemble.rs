//! The arm64 assembler (`disasm_core::arm64::encode`) for the instruction editor: a line goes in,
//! its word or the reason it does not assemble comes out. A name used as a target is the page's
//! to resolve, so the call works in rounds as the HLA64 lines do (hla.rs): the input is the line,
//! then the answers so far; a call that meets a name not answered yet returns the question.

use disasm_core::arm64::encode::{assemble, AsmError, Resolve};

use super::hla::{Reader, Replay, NAME_ADDR};
use super::{json_str, put_out, slice};

impl Resolve for Replay {
    fn resolve(&self, name: &str) -> Option<f64> {
        // Unanswered and unknown both read as no address here; an unanswered one is asked for.
        self.text_answer(NAME_ADDR, name).filter(|a| !a.is_nan())
    }
}

fn error_json(e: &AsmError) -> String {
    let mut out = String::from("{\"error\":");
    let (code, params): (&str, Vec<(&str, String)>) = match e {
        AsmError::Empty => ("empty", vec![]),
        AsmError::Unreadable(text) => ("unreadable", vec![("text", text.clone())]),
        AsmError::Unsupported => ("unsupported", vec![]),
        AsmError::Immediate(value) => ("immediate", vec![("value", value.clone())]),
        AsmError::Offset(value) => ("offset", vec![("value", value.clone())]),
        AsmError::Multiple(value, size) => ("multiple", vec![("value", value.clone()), ("size", size.to_string())]),
        AsmError::Unpredictable => ("unpredictable", vec![]),
        AsmError::Align => ("align", vec![]),
        AsmError::Far(distance) => ("far", vec![("distance", distance.clone())]),
        AsmError::Name(name) => ("name", vec![("name", name.clone())]),
        AsmError::Operands(mnemonic) => ("operands", vec![("mnemonic", mnemonic.clone())]),
        AsmError::Differs(text) => ("differs", vec![("text", text.clone())]),
    };
    json_str(&mut out, code);
    for (key, value) in params {
        out.push(',');
        json_str(&mut out, key);
        out.push(':');
        json_str(&mut out, &value);
    }
    out.push('}');
    out
}

/// Assembles the line in `input` (a u32 length and its UTF-8, then the answers) for `pc`:
/// `{"word":n}`, `{"error":code,…}` with what the message names, or `{"need":[[6,k,"name"]…]}`.
///
/// # Safety
/// `input` and `len` must name memory the host wrote.
#[no_mangle]
pub unsafe extern "C" fn arm64_assemble(pc: f64, input: *const u8, len: usize) -> usize {
    let mut r = Reader::new(slice(input, len));
    let text = r.text();
    let ctx = Replay::read(&mut r);
    let result = assemble(&text, pc, &ctx);
    if let Some(need) = ctx.need() {
        return put_out(&need);
    }
    put_out(&match result {
        Ok(word) => format!("{{\"word\":{word}}}"),
        Err(e) => error_json(&e),
    })
}
