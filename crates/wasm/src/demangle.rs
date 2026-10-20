//! Names back to source (`disasm_core::demangle`) for the page: a batch of names goes in at
//! once — every import of a program for its page, or the one a row names — separated by NUL
//! (no symbol holds one), and their readings come out as one JSON array.

use disasm_core::demangle::msvc::{demangle_msvc, undname};
use disasm_core::demangle::swift::{demangle_swift, parse_swift, swift_tree};
use disasm_core::demangle::{demangle, demangle_unprefixed};

use super::{json_str, put_out, slice};

fn names(input: &[u8]) -> impl Iterator<Item = std::borrow::Cow<'_, str>> {
    input.split(|&b| b == 0).map(String::from_utf8_lossy)
}

/// What each name of `input` (NUL-separated UTF-8) reads as: `[full, short, language]`, with null
/// where the text is the name itself. `unprefixed` 0 for Mach-O's names (a C name carries an
/// underscore), 1 for ELF's, PE's and WebAssembly's.
///
/// # Safety
/// `input` and `len` must name memory the host wrote.
#[no_mangle]
pub unsafe extern "C" fn demangle_names(input: *const u8, len: usize, unprefixed: u32) -> usize {
    let mut out = String::with_capacity(len * 2 + 2);
    out.push('[');
    for (k, raw) in names(slice(input, len)).enumerate() {
        if k > 0 {
            out.push(',');
        }
        let d = if unprefixed != 0 { demangle_unprefixed(&raw) } else { demangle(&raw) };
        out.push('[');
        for text in [&d.full, &d.short] {
            if *text == raw {
                out.push_str("null");
            } else {
                json_str(&mut out, text);
            }
            out.push(',');
        }
        out.push('"');
        out.push_str(d.language.as_str());
        out.push_str("\"]");
    }
    out.push(']');
    put_out(&out)
}

/// The demanglers one by one, for the tools that check them against LLVM's and Swift's own
/// (tools/verify-msvc.mjs, tools/verify-swift.mjs): for each name of `input`, by `what` — 0
/// `undname(name, flags)`, 1 MSVC's `[full, short]`, 2 Swift's `[full, short]`, 3 the Swift tree as
/// `swift-demangle --tree-only` prints it — or null.
///
/// # Safety
/// `input` and `len` must name memory the host wrote.
#[no_mangle]
pub unsafe extern "C" fn demangle_tool(what: u32, flags: u32, input: *const u8, len: usize) -> usize {
    let mut out = String::from("[");
    for (k, raw) in names(slice(input, len)).enumerate() {
        if k > 0 {
            out.push(',');
        }
        let pair = |found: Option<(String, String)>, out: &mut String| match found {
            Some((full, short)) => {
                out.push('[');
                json_str(out, &full);
                out.push(',');
                json_str(out, &short);
                out.push(']');
            }
            None => out.push_str("null"),
        };
        let text = |found: Option<String>, out: &mut String| match found {
            Some(text) => json_str(out, &text),
            None => out.push_str("null"),
        };
        match what {
            0 => text(undname(&raw, flags), &mut out),
            1 => pair(demangle_msvc(&raw), &mut out),
            2 => pair(demangle_swift(&raw), &mut out),
            _ => text(parse_swift(&raw).map(|t| swift_tree(&t)), &mut out),
        }
    }
    out.push(']');
    put_out(&out)
}
