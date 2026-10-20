//! Signing a patched macOS program again, ad hoc — a port of the TypeScript the page had (patch.ts).
//!
//! A patch keeps the file's size and layout, but the code signature holds a hash of every page up to
//! it, and Apple Silicon does not run arm64 code whose pages do not match. So the patched slice is
//! signed again in its existing room, the way `codesign --sign -` and the linker sign: the code
//! directory kept with its page hashes computed afresh, the ad hoc flag set and the team dropped;
//! the entitlements (XML and DER) kept byte for byte; the requirements made the empty set; the CMS
//! blob of a Developer ID signature and the alternate code directories dropped. In a universal file
//! every slice is signed again: codesign refuses a file whose slices mix ad hoc and Developer ID.
//!
//! Where the TypeScript's typed arrays threw a RangeError (a hash written past the code directory,
//! a signature cut short by the end of the file), so does this, as `SignError::Range`.

use crate::macho::{parse_macho, utf8};
use crate::sha::{sha1, sha256, sha384};

/// What the signature was before signing again, for the page to say what was lost.
#[derive(Clone, Debug, PartialEq)]
pub struct Resigned {
    /// none, adhoc (also the linker's), developer
    pub was: &'static str,
    pub team: Option<String>,
    pub identifier: String,
    /// Entitlements kept in the new signature.
    pub entitlements: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub enum SignError {
    /// The slice cannot be signed again (CannotSign): why.
    Cannot(String),
    /// A typed array's RangeError in the TypeScript.
    Range,
    /// Slice `k` of a universal file could not be read as Mach-O (the page reads it for the message).
    Parse(usize),
}

const CSMAGIC_EMBEDDED_SIGNATURE: u32 = 0xfade0cc0;
const CSMAGIC_CODEDIRECTORY: u32 = 0xfade0c02;
const CSMAGIC_REQUIREMENTS: u32 = 0xfade0c01;
const CSSLOT_CODEDIRECTORY: u32 = 0;
const CSSLOT_REQUIREMENTS: u32 = 2;
const CSSLOT_ENTITLEMENTS: u32 = 5;
const CSSLOT_DER_ENTITLEMENTS: u32 = 7;
const CSSLOT_ALTERNATE: u32 = 0x1000;
const CSSLOT_SIGNATURE: u32 = 0x10000;
const CS_ADHOC: u32 = 0x2;
const CS_LINKER_SIGNED: u32 = 0x20000;

/// A big-endian u32; bytes past the end read as 0, as `undefined << 24` does.
fn be32(b: &[u8], at: usize) -> u32 {
    let byte = |k: usize| b.get(at + k).copied().unwrap_or(0) as u32;
    byte(0) << 24 | byte(1) << 16 | byte(2) << 8 | byte(3)
}

/// Writes a big-endian u32; bytes past the end are not written, as a typed array ignores them.
fn put32(b: &mut [u8], at: usize, v: u32) {
    for (k, byte) in v.to_be_bytes().into_iter().enumerate() {
        if let Some(x) = b.get_mut(at + k) {
            *x = byte;
        }
    }
}

/// `target.set(source, offset)`: a RangeError where it does not fit.
fn set(target: &mut [u8], source: &[u8], offset: f64) -> Result<(), SignError> {
    if offset < 0.0 || offset + source.len() as f64 > target.len() as f64 {
        return Err(SignError::Range);
    }
    target[offset as usize..offset as usize + source.len()].copy_from_slice(source);
    Ok(())
}

/// The digest a code directory's hash type names, cut to `length` bytes (Web Crypto's names: 1
/// SHA-1, 2 SHA-256, 3 SHA-256 truncated to 20 bytes, 4 SHA-384).
fn digest(kind: u8, length: usize, data: &[u8]) -> Vec<u8> {
    let full: Vec<u8> = match kind {
        1 => sha1(data).to_vec(),
        2 | 3 => sha256(data).to_vec(),
        _ => sha384(data).to_vec(),
    };
    full[..length.min(full.len())].to_vec()
}

/// `subarray(start, end)` with JavaScript's clamping, positions as doubles.
fn sub(b: &[u8], start: f64, end: f64) -> &[u8] {
    let clamp = |v: f64| if v.is_nan() { 0 } else { v.max(0.0).min(b.len() as f64) as usize };
    let (s, e) = (clamp(start), clamp(end));
    &b[s..e.max(s)]
}

/// Signs a thin slice again, ad hoc, in place: `at` is LC_CODE_SIGNATURE's (offset, size). The
/// slice must already hold the patched bytes.
pub fn resign(slice: &mut [u8], at: Option<(u32, u32)>) -> Result<Resigned, SignError> {
    let Some((at_offset, at_size)) = at else { return Err(SignError::Cannot("no LC_CODE_SIGNATURE".into())) };
    let sig_start = (at_offset as usize).min(slice.len());
    let sig_end = (at_offset as usize + at_size as usize).min(slice.len()).max(sig_start);
    let sig = slice[sig_start..sig_end].to_vec();
    if sig.len() < 12 || be32(&sig, 0) != CSMAGIC_EMBEDDED_SIGNATURE {
        return Err(SignError::Cannot("no embedded signature".into()));
    }

    // The blobs of the old signature. Entries past the end read as type 0 at offset 0, which
    // nothing after keeps: the reading stops there.
    let count = be32(&sig, 8) as usize;
    let mut blobs: Vec<(u32, Vec<u8>)> = Vec::new();
    for i in 0..count {
        if 12 + i * 8 >= sig.len() {
            break;
        }
        let ty = be32(&sig, 12 + i * 8);
        let offset = be32(&sig, 16 + i * 8) as usize;
        if offset + 8 > sig.len() {
            continue;
        }
        let length = be32(&sig, offset + 4) as usize;
        blobs.push((ty, sig[offset..(offset + length).min(sig.len()).max(offset)].to_vec()));
    }
    // The code directory to keep: the one with the strongest hash the kernel checks.
    let rank = |d: &[u8]| -> u32 { d.get(37).and_then(|&k| [0, 1, 3, 2, 4].get(k as usize).copied()).unwrap_or(0) };
    let mut directories: Vec<&(u32, Vec<u8>)> =
        blobs.iter().filter(|(ty, d)| (*ty == CSSLOT_CODEDIRECTORY || (CSSLOT_ALTERNATE..CSSLOT_ALTERNATE + 5).contains(ty)) && be32(d, 0) == CSMAGIC_CODEDIRECTORY).collect();
    directories.sort_by(|a, b| rank(&b.1).cmp(&rank(&a.1)));
    let Some((_, cd)) = directories.first() else { return Err(SignError::Cannot("no code directory".into())) };
    let cd = cd.clone();
    let kind = match cd.get(37) {
        Some(&k @ 1..=4) => k,
        Some(k) => return Err(SignError::Cannot(format!("hash type {k}"))),
        None => return Err(SignError::Cannot("hash type undefined".into())),
    };

    let version = be32(&cd, 8);
    let flags = be32(&cd, 12);
    let hash_offset = be32(&cd, 16) as f64;
    let identifier = {
        let start = be32(&cd, 20) as usize;
        let mut end = start;
        while end < cd.len() && cd[end] != 0 {
            end += 1;
        }
        utf8(cd.get(start..end).unwrap_or(&[]))
    };
    let n_special = be32(&cd, 24);
    let n_code = be32(&cd, 28) as f64;
    let code_limit = be32(&cd, 32) as f64;
    let hash_size = cd.get(36).copied().unwrap_or(0) as usize;
    let page_size = match cd.get(39) {
        Some(&shift) if shift != 0 => 2f64.powi(shift as i32),
        _ => code_limit,
    };
    let team_at = if version >= 0x20200 { be32(&cd, 48) as usize } else { 0 };
    let team = (team_at != 0).then(|| {
        // cd.indexOf(0, teamAt), and subarray's end of -1 when there is none.
        let end = cd.get(team_at..).and_then(|rest| rest.iter().position(|&b| b == 0)).map_or(cd.len() as f64 - 1.0, |k| (team_at + k) as f64);
        utf8(sub(&cd, team_at as f64, end))
    });
    let developer = blobs.iter().any(|(ty, d)| *ty == CSSLOT_SIGNATURE && d.len() > 8);
    let was = if developer { "developer" } else { "adhoc" };

    // The code directory afresh: ad hoc, no team, every page hashed again.
    let mut next = cd.clone();
    put32(&mut next, 12, (flags & !CS_LINKER_SIGNED) | CS_ADHOC);
    if team_at != 0 {
        put32(&mut next, 48, 0);
    }
    let pages = (code_limit / page_size).ceil();
    if pages != n_code {
        return Err(SignError::Cannot("the page count does not match the code limit".into()));
    }
    let mut i = 0.0;
    while i < pages {
        let page = sub(slice, i * page_size, code_limit.min((i + 1.0) * page_size));
        let h = digest(kind, hash_size, page);
        set(&mut next, &h, hash_offset + i * hash_size as f64)?;
        i += 1.0;
    }

    // The requirements an ad hoc signature carries: none. Their special slot (if the directory has
    // one) gets the new blob's hash; the entitlements' slots stay right, the blobs being the same.
    let mut requirements = vec![0u8; 12];
    put32(&mut requirements, 0, CSMAGIC_REQUIREMENTS);
    put32(&mut requirements, 4, 12);
    let keep: Vec<&(u32, Vec<u8>)> =
        blobs.iter().filter(|(ty, _)| *ty != CSSLOT_CODEDIRECTORY && *ty != CSSLOT_SIGNATURE && !(CSSLOT_ALTERNATE..CSSLOT_ALTERNATE + 5).contains(ty)).collect();
    let had_requirements = keep.iter().any(|(ty, _)| *ty == CSSLOT_REQUIREMENTS);
    let others: Vec<(u32, Vec<u8>)> = keep.iter().map(|(ty, d)| (*ty, if *ty == CSSLOT_REQUIREMENTS { requirements.clone() } else { d.clone() })).collect();
    if had_requirements && n_special >= CSSLOT_REQUIREMENTS {
        let h = digest(kind, hash_size, &requirements);
        set(&mut next, &h, hash_offset - (CSSLOT_REQUIREMENTS as usize * hash_size) as f64)?;
    }

    // The new superblob, in the old one's room; what is left is zeros.
    let mut parts = vec![(CSSLOT_CODEDIRECTORY, next)];
    parts.extend(others.iter().cloned());
    let header = 12 + parts.len() * 8;
    let total = parts.iter().fold(header, |n, (_, d)| n + d.len());
    if total > at_size as usize {
        return Err(SignError::Cannot("the new signature does not fit".into()));
    }
    let mut out = vec![0u8; at_size as usize];
    put32(&mut out, 0, CSMAGIC_EMBEDDED_SIGNATURE);
    put32(&mut out, 4, total as u32);
    put32(&mut out, 8, parts.len() as u32);
    let mut offset = header;
    for (k, (ty, data)) in parts.iter().enumerate() {
        put32(&mut out, 12 + k * 8, *ty);
        put32(&mut out, 16 + k * 8, offset as u32);
        out[offset..offset + data.len()].copy_from_slice(data);
        offset += data.len();
    }
    if out.len() > sig_end - sig_start {
        return Err(SignError::Range);
    }
    slice[sig_start..sig_start + out.len()].copy_from_slice(&out);
    Ok(Resigned { was, team, identifier, entitlements: others.iter().any(|(ty, _)| *ty == CSSLOT_ENTITLEMENTS || *ty == CSSLOT_DER_ENTITLEMENTS) })
}

/// Signs every slice of a file again, ad hoc — the one the page opens (the default slice) with
/// its patches, the others as they are — and says what the opened one had.
pub fn resign_file(file: &mut [u8]) -> Result<Resigned, SignError> {
    let image = parse_macho(file, None).map_err(|_| SignError::Parse(usize::MAX))?;
    let mut opened = None;
    for (k, arch) in image.arches.iter().enumerate() {
        let start = (arch.offset.max(0.0) as usize).min(file.len());
        let end = ((arch.offset + arch.size).max(0.0) as usize).min(file.len()).max(start);
        let is_opened = arch.offset == image.slice_offset;
        let at = if is_opened { image.signature_at } else { parse_macho(&file[start..end], None).map_err(|_| SignError::Parse(k))?.signature_at };
        if at.is_none() {
            if is_opened {
                return Err(SignError::Cannot("no LC_CODE_SIGNATURE".into()));
            }
            continue;
        }
        let result = resign(&mut file[start..end], at)?;
        if is_opened {
            opened = Some(result);
        }
    }
    opened.ok_or(SignError::Cannot("the opened slice was not found".into()))
}
