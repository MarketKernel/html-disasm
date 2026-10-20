//! ZIP files the page opens that are not Java: an app (.ipa, a zipped macOS app), whose bundles'
//! programs it lists (`disasm_core::bundle`), or an Android package, whose native libraries it
//! lists (`disasm_core::zip`). The session keeps the file; the page asks for the list, then for
//! the bytes of the one program chosen, which come out through view 0.

use disasm_core::bundle::{bundled_programs, is_app_archive, BundledProgram, Profile};
use disasm_core::text::js_number;
use disasm_core::zip::{packaged_libraries, read_packaged, zip_entries, zip_read, PackagedLibrary, ZipEntry, ZipError};

use super::cil_page::json_utf16;
use super::{add_session, json_str, put_out, session, slice_owned, Session};

pub struct ArchiveState {
    file: Vec<u8>,
    entries: Vec<ZipEntry>,
    programs: Vec<BundledProgram>,
    apks: Vec<Vec<u8>>,
    libraries: Vec<PackagedLibrary>,
    /// The bytes of the last program read.
    pub read: Vec<u8>,
}

/// Opens a ZIP file; the core takes over `bytes` (from `alloc`, not to be freed).
///
/// # Safety
/// `bytes` and `len` must come from one `alloc` call, and the host must not use them again.
#[no_mangle]
pub unsafe extern "C" fn archive_open(bytes: *mut u8, len: usize) -> u32 {
    add_session(Session::Archive(Box::new(ArchiveState {
        file: slice_owned(bytes, len),
        entries: Vec::new(),
        programs: Vec::new(),
        apks: Vec::new(),
        libraries: Vec::new(),
        read: Vec::new(),
    })))
}

fn state<R>(handle: u32, f: impl FnOnce(&mut ArchiveState) -> R) -> R {
    session(handle, |s| match s {
        Session::Archive(state) => f(state),
        _ => panic!("not an archive session"),
    })
}

/// Why the archive could not be read, as the TypeScript's errors were: a NotZip with its message, a
/// RangeError of its DataView, a TypeError of DecompressionStream.
fn error_json(e: ZipError) -> String {
    let (kind, text) = match e {
        ZipError::NoEndOfDirectory => ("zip", "no end of central directory".to_string()),
        ZipError::BadLocalHeader => ("zip", "bad local header".to_string()),
        ZipError::Method(m) => ("zip", format!("compression method {m}")),
        ZipError::OutOfBounds => ("range", "Offset is outside the bounds of the DataView".to_string()),
        ZipError::Inflate => ("inflate", "The compressed data was not valid".to_string()),
    };
    let mut out = format!("{{\"error\":\"{kind}\",\"text\":");
    json_str(&mut out, &text);
    out.push('}');
    out
}

fn opt_units(out: &mut String, v: &Option<Vec<u16>>) {
    match v {
        Some(v) => json_utf16(out, v),
        None => out.push_str("null"),
    }
}

fn opt_number(out: &mut String, v: Option<f64>) {
    match v {
        Some(v) if v.is_nan() => out.push_str("\"NaN\""),
        Some(v) => out.push_str(&js_number(v)),
        None => out.push_str("null"),
    }
}

fn profile_json(out: &mut String, p: &Profile) {
    out.push_str("{\"name\":");
    opt_units(out, &p.name);
    out.push_str(",\"team\":");
    opt_units(out, &p.team);
    out.push_str(",\"teamId\":");
    opt_units(out, &p.team_id);
    out.push_str(",\"appId\":");
    opt_units(out, &p.app_id);
    out.push_str(",\"created\":");
    opt_number(out, p.created);
    out.push_str(",\"expires\":");
    opt_number(out, p.expires);
    out.push_str(",\"devices\":");
    match p.devices {
        Some(n) => out.push_str(&n.to_string()),
        None => out.push_str("null"),
    }
    out.push_str(&format!(",\"allDevices\":{},\"debuggable\":{}}}", p.all_devices, p.debuggable));
}

/// The names of the archive's entries (to see whether it holds Java classes), or its error.
#[no_mangle]
pub extern "C" fn archive_names(handle: u32) -> usize {
    let text = state(handle, |s| match zip_entries(&s.file) {
        Ok(entries) => {
            let mut out = String::from("{\"names\":[");
            for (k, e) in entries.iter().enumerate() {
                if k > 0 {
                    out.push(',');
                }
                json_str(&mut out, &e.name);
            }
            out.push_str("]}");
            s.entries = entries;
            out
        }
        Err(e) => error_json(e),
    });
    put_out(&text)
}

/// The programs of an app in the archive (none when it holds no app), or why it cannot be read.
#[no_mangle]
pub extern "C" fn archive_programs(handle: u32) -> usize {
    let text = state(handle, |s| {
        let entries = match zip_entries(&s.file) {
            Ok(e) => e,
            Err(e) => return error_json(e),
        };
        if !is_app_archive(&entries) {
            return "{\"programs\":[]}".into();
        }
        s.programs = match bundled_programs(&s.file) {
            Ok(p) => p,
            Err(e) => return error_json(e),
        };
        let mut out = String::from("{\"programs\":[");
        for (k, p) in s.programs.iter().enumerate() {
            if k > 0 {
                out.push(',');
            }
            let b = &p.bundle;
            out.push_str("{\"kind\":");
            json_str(&mut out, b.kind);
            out.push_str(",\"path\":");
            json_str(&mut out, &b.path);
            out.push_str(",\"name\":");
            json_str(&mut out, &b.name);
            for (key, v) in [("identifier", &b.identifier), ("version", &b.version), ("build", &b.build), ("minimumOS", &b.minimum_os)] {
                out.push_str(&format!(",\"{key}\":"));
                opt_units(&mut out, v);
            }
            out.push_str(",\"platforms\":");
            match &b.platforms {
                Some(list) => {
                    out.push('[');
                    for (j, x) in list.iter().enumerate() {
                        if j > 0 {
                            out.push(',');
                        }
                        json_utf16(&mut out, x);
                    }
                    out.push(']');
                }
                None => out.push_str("null"),
            }
            out.push_str(",\"profile\":");
            match &b.profile {
                Some(profile) => profile_json(&mut out, profile),
                None => out.push_str("null"),
            }
            out.push_str(",\"file\":");
            json_str(&mut out, &p.file);
            out.push_str(&format!(",\"size\":{}}}", p.size));
        }
        out.push_str("]}");
        out
    });
    put_out(&text)
}

/// The native libraries of an Android package, or why it cannot be read.
#[no_mangle]
pub extern "C" fn archive_libraries(handle: u32) -> usize {
    let text = state(handle, |s| {
        let (apks, libraries) = match packaged_libraries(&s.file) {
            Ok(p) => p.into_parts(),
            Err(e) => return error_json(e),
        };
        s.apks = apks;
        s.libraries = libraries;
        let mut out = String::from("{\"libraries\":[");
        for (k, lib) in s.libraries.iter().enumerate() {
            if k > 0 {
                out.push(',');
            }
            out.push_str("{\"abi\":");
            json_str(&mut out, &lib.abi);
            out.push_str(",\"file\":");
            json_str(&mut out, &lib.file);
            out.push_str(&format!(",\"size\":{},\"from\":", lib.size));
            match &lib.from {
                Some(f) => json_str(&mut out, f),
                None => out.push_str("null"),
            }
            out.push('}');
        }
        out.push_str("]}");
        out
    });
    put_out(&text)
}

/// Reads program `k` of the list (`what` 0: an app's programs, 1: a package's libraries, 2: the
/// archive's entries as `archive_names` listed them) into view 0:
/// `{"len":…}`, or why it cannot be read.
#[no_mangle]
pub extern "C" fn archive_read(handle: u32, what: u32, k: u32) -> usize {
    let text = state(handle, |s| {
        let read = match what {
            0 => zip_read(&s.file, &s.programs[k as usize].entry).map(|b| b.into_owned()),
            1 => read_packaged(&s.file, &s.apks, &s.libraries[k as usize]).map(|b| b.into_owned()),
            _ => zip_read(&s.file, &s.entries[k as usize]).map(|b| b.into_owned()),
        };
        match read {
            Ok(bytes) => {
                s.read = bytes;
                format!("{{\"len\":{}}}", s.read.len())
            }
            Err(e) => error_json(e),
        }
    });
    put_out(&text)
}
