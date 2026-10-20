//! Signing a patched macOS program again (`disasm_core::sign`): the page hands over a copy of the
//! file, the core signs every slice again in place, and the page takes the bytes back.

use disasm_core::sign::{resign_file, SignError};

use super::{json_str, put_out};

/// Signs the file at `bytes` again, in place: `{"was","team","identifier","entitlements"}` for the
/// slice the page opens, or `{"cannot": why}`, `{"range": true}` (a typed array's RangeError in
/// the TypeScript), `{"parse": k}` (slice `k`, or -1 the file, is not Mach-O: the page reads it again
/// for its words).
///
/// # Safety
/// `bytes` must address `len` writable bytes the host does not touch during the call.
#[no_mangle]
pub unsafe extern "C" fn macho_resign(bytes: *mut u8, len: usize) -> usize {
    let file = if len == 0 { &mut [][..] } else { std::slice::from_raw_parts_mut(bytes, len) };
    let text = match resign_file(file) {
        Ok(r) => {
            let mut out = format!("{{\"was\":\"{}\",\"team\":", r.was);
            match &r.team {
                Some(t) => json_str(&mut out, t),
                None => out.push_str("null"),
            }
            out.push_str(",\"identifier\":");
            json_str(&mut out, &r.identifier);
            out.push_str(&format!(",\"entitlements\":{}}}", r.entitlements));
            out
        }
        Err(SignError::Cannot(why)) => {
            let mut out = String::from("{\"cannot\":");
            json_str(&mut out, &why);
            out.push('}');
            out
        }
        Err(SignError::Range) => "{\"range\":true}".into(),
        Err(SignError::Parse(k)) => format!("{{\"parse\":{}}}", if k == usize::MAX { -1 } else { k as i64 }),
    };
    put_out(&text)
}
