//! Native programs read and analysed in the core (`disasm_core::native`): the page hands over the
//! file it opened, and the core reads its container, builds the image and opens the
//! architecture's pass as an ordinary session (the `arm64_*` calls drive it); once the pass is
//! over, `native_finish` runs the analysis around it, and `native_text` hands its findings over.

use disasm_core::arm32::pass::Arm32Pass;
use disasm_core::arm64::pass::Arm64Pass;
use disasm_core::native::image::{NativeImage, PeView};
use disasm_core::native::{arm32, arm64, open_image, x86, Container, Found};
use disasm_core::text::js_number;
use disasm_core::x86::pass::X86Pass;

use super::{add_session, json_str, put_out, session, slice_owned, with, Session, X86Pairs};

pub struct NativeState {
    pub image: NativeImage,
    pub found: Option<Found>,
}

/// Opens a native program: `container` 0 Mach-O (the slice), 1 ELF, 2 PE (its Arm code), 3 PE (its
/// x64 code); `arch` 0 arm64, 1 x86, 2 32-bit Arm. The core takes over `bytes` (from `alloc`, not to be freed). 0 when the
/// file cannot be read.
///
/// # Safety
/// `bytes` and `len` must come from one `alloc` call, and the host must not use them again.
#[no_mangle]
pub unsafe extern "C" fn native_open(bytes: *mut u8, len: usize, container: u32, arch: u32) -> u32 {
    let container = match container {
        0 => Container::MachO,
        1 => Container::Elf,
        2 => Container::Pe(PeView::Arm),
        _ => Container::Pe(PeView::X64),
    };
    let Some(image) = open_image(slice_owned(bytes, len), container) else { return 0 };
    let handle = match arch {
        1 => {
            let pass = X86Pass::new(x86::core_image(&image), x86::pass_input(&image));
            let ranges = pass.ranges.iter().flat_map(|r| [r.section as u32, r.first, r.count]).collect();
            add_session(Session::X86 { pass: Box::new(pass), refs: None, pairs: X86Pairs { ranges, ..X86Pairs::default() } })
        }
        2 => {
            let pass = Arm32Pass::new(arm32::pass_image(&image), arm32::pass_input(&image));
            let ranges = pass.layout.ranges.iter().flat_map(|r| [r.section as u32, r.first, r.count]).collect();
            add_session(Session::Arm32 { pass: Box::new(pass), refs: None, pairs: X86Pairs { ranges, ..X86Pairs::default() } })
        }
        _ => {
            let (ranges, slots, pe) = arm64::pass_input(&image);
            add_session(Session::Arm64 { pass: Arm64Pass::new(&image.bytes, &ranges, &slots, pe), refs: None })
        }
    };
    with(|s| s.natives.insert(handle, NativeState { image, found: None }));
    handle
}

/// The analysis after the pass (which must be over): stubs, functions, strings.
#[no_mangle]
pub extern "C" fn native_finish(handle: u32) {
    let mut state = with(|s| s.natives.remove(&handle)).expect("not a native session");
    let found = session(handle, |s| match s {
        Session::Arm64 { pass, refs: Some(refs) } => arm64::after_pass(&mut state.image, pass, refs),
        Session::X86 { pass, refs: Some(refs), .. } => x86::after_pass(&mut state.image, pass, refs),
        Session::Arm32 { pass, refs: Some(refs), .. } => arm32::after_pass(&mut state.image, pass, refs),
        _ => panic!("the pass is not over"),
    });
    state.found = Some(found);
    with(|s| s.natives.insert(handle, state));
}

/// What the analysis found, as JSON (`what`): 0 the functions (address, first, count, name, full,
/// raw, kind, language), 1 the strings (address, text, section, NUL-terminated), 2 the stubs it
/// named (address, name).
#[no_mangle]
pub extern "C" fn native_text(handle: u32, what: u32) -> usize {
    let text = with(|s| {
        let found = s.natives.get(&handle).and_then(|n| n.found.as_ref()).expect("the analysis is not over");
        let mut o = String::new();
        o.push('[');
        match what {
            0 => {
                for (k, f) in found.functions.iter().enumerate() {
                    if k > 0 {
                        o.push(',');
                    }
                    o.push('[');
                    o.push_str(&js_number(f.addr));
                    o.push_str(&format!(",{},{},", f.first, f.count));
                    json_str(&mut o, &f.name);
                    o.push(',');
                    json_str(&mut o, &f.full);
                    o.push(',');
                    match &f.raw {
                        Some(raw) => json_str(&mut o, raw),
                        None => o.push_str("null"),
                    }
                    o.push_str(&format!(",\"{}\",", f.kind.as_str()));
                    match f.language {
                        Some(l) => json_str(&mut o, l),
                        None => o.push_str("null"),
                    }
                    o.push(']');
                }
            }
            1 => {
                for (k, st) in found.strings.iter().enumerate() {
                    if k > 0 {
                        o.push(',');
                    }
                    o.push('[');
                    o.push_str(&js_number(st.addr));
                    o.push(',');
                    json_str(&mut o, &st.text);
                    o.push(',');
                    json_str(&mut o, &st.section);
                    o.push_str(if st.cstring { ",1]" } else { ",0]" });
                }
            }
            _ => {
                for (k, (addr, name)) in found.stubs.iter().enumerate() {
                    if k > 0 {
                        o.push(',');
                    }
                    o.push('[');
                    o.push_str(&js_number(*addr));
                    o.push(',');
                    json_str(&mut o, name);
                    o.push(']');
                }
            }
        }
        o.push(']');
        o
    });
    put_out(&text)
}
