//! Just enough of ZIP to take a native library out of an Android package
//! (.apk, .aab, .apks, .xapk — all ZIP files) or the classes out of a JAR: the
//! central directory lists the entries, and an entry is either stored as it is
//! (Android keeps native libraries uncompressed when it may load them straight
//! from the APK) or compressed with deflate. ZIP64 directories are read too.
//!
//! A port of src/core/zip.ts. The TypeScript inflates with the browser's own
//! DecompressionStream, so its `zipRead` is asynchronous; here miniz_oxide
//! inflates, and `zip_read` simply returns.

use std::borrow::Cow;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZipEntry {
    pub name: String,
    pub method: u16,
    pub compressed_size: u64,
    pub size: u64,
    /// Where the entry's local header starts.
    pub offset: u64,
}

/// Why an archive cannot be read (`NotZip` in the TypeScript; the page words the message).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZipError {
    /// "no end of central directory"
    NoEndOfDirectory,
    /// "bad local header"
    BadLocalHeader,
    /// "compression method {0}"
    Method(u16),
    /// A record that runs past the end of the file. The TypeScript's DataView throws a RangeError
    /// there ("Offset is outside the bounds of the DataView"), not a NotZip.
    OutOfBounds,
    /// Deflated data that does not inflate (DecompressionStream's TypeError in the TypeScript).
    Inflate,
}

pub fn is_zip(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[0] == 0x50 && bytes[1] == 0x4b && bytes[2] == 3 && bytes[3] == 4
}

/// Little-endian reads that fail where the TypeScript's DataView throws.
fn le(bytes: &[u8], at: u64, n: usize) -> Result<u64, ZipError> {
    let at = usize::try_from(at).map_err(|_| ZipError::OutOfBounds)?;
    let b = bytes.get(at..at.checked_add(n).ok_or(ZipError::OutOfBounds)?).ok_or(ZipError::OutOfBounds)?;
    Ok(b.iter().rev().fold(0u64, |v, &x| (v << 8) | x as u64))
}

fn u16le(bytes: &[u8], at: u64) -> Result<u16, ZipError> {
    le(bytes, at, 2).map(|v| v as u16)
}

fn u32le(bytes: &[u8], at: u64) -> Result<u32, ZipError> {
    le(bytes, at, 4).map(|v| v as u32)
}

fn u64le(bytes: &[u8], at: u64) -> Result<u64, ZipError> {
    le(bytes, at, 8)
}

/// `bytes.subarray(start, end)`: clamped to the bytes.
fn subarray(bytes: &[u8], start: u64, end: u64) -> &[u8] {
    let len = bytes.len() as u64;
    let start = start.min(len) as usize;
    let end = end.min(len) as usize;
    &bytes[start..end.max(start)]
}

/// What TextDecoder makes of the bytes: UTF-8, a bad sequence as U+FFFD, a leading byte order mark dropped.
fn decode_utf8(bytes: &[u8]) -> String {
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    String::from_utf8_lossy(bytes).into_owned()
}

/// The entries of the central directory.
pub fn zip_entries(bytes: &[u8]) -> Result<Vec<ZipEntry>, ZipError> {
    let len = bytes.len() as u64;
    // The end-of-directory record is in the last 64 KiB (it may carry a comment).
    let mut eocd = None;
    if len >= 22 {
        let lowest = (len - 22).saturating_sub(0xffff);
        let mut at = len - 22;
        loop {
            if u32le(bytes, at)? == 0x06054b50 {
                eocd = Some(at);
                break;
            }
            if at == lowest {
                break;
            }
            at -= 1;
        }
    }
    let eocd = eocd.ok_or(ZipError::NoEndOfDirectory)?;
    let mut count = u16le(bytes, eocd + 10)? as u64;
    let mut dir_offset = u32le(bytes, eocd + 16)? as u64;
    // ZIP64: the locator right before the record points at the 64-bit one.
    if (count == 0xffff || dir_offset == 0xffffffff) && eocd >= 20 && u32le(bytes, eocd - 20)? == 0x07064b50 {
        let record = u64le(bytes, eocd - 12)?;
        if u32le(bytes, record)? == 0x06064b50 {
            count = u64le(bytes, record.checked_add(32).ok_or(ZipError::OutOfBounds)?)?;
            dir_offset = u64le(bytes, record.checked_add(48).ok_or(ZipError::OutOfBounds)?)?;
        }
    }
    let mut entries = Vec::new();
    let mut at = dir_offset;
    let mut i = 0u64;
    while i < count && at.checked_add(46).is_some_and(|end| end <= len) && u32le(bytes, at)? == 0x02014b50 {
        let method = u16le(bytes, at + 10)?;
        let mut compressed_size = u32le(bytes, at + 20)? as u64;
        let mut size = u32le(bytes, at + 24)? as u64;
        let name_length = u16le(bytes, at + 28)? as u64;
        let extra_length = u16le(bytes, at + 30)? as u64;
        let comment_length = u16le(bytes, at + 32)? as u64;
        let mut offset = u32le(bytes, at + 42)? as u64;
        let name = decode_utf8(subarray(bytes, at + 46, at + 46 + name_length));
        // ZIP64 extra field: the 64-bit values of the fields that overflowed, in this order.
        let extra_end = at + 46 + name_length + extra_length;
        let mut p = at + 46 + name_length;
        while p + 4 <= extra_end {
            let id = u16le(bytes, p)?;
            let length = u16le(bytes, p + 2)? as u64;
            if id == 1 {
                let mut q = p + 4;
                if size == 0xffffffff {
                    size = u64le(bytes, q)?;
                    q += 8;
                }
                if compressed_size == 0xffffffff {
                    compressed_size = u64le(bytes, q)?;
                    q += 8;
                }
                if offset == 0xffffffff {
                    offset = u64le(bytes, q)?;
                }
            }
            p += 4 + length;
        }
        entries.push(ZipEntry { name, method, compressed_size, size, offset });
        at += 46 + name_length + extra_length + comment_length;
        i += 1;
    }
    Ok(entries)
}

/// The bytes of an entry, inflated if they were deflated (a stored entry is borrowed as it is).
pub fn zip_read<'a>(bytes: &'a [u8], entry: &ZipEntry) -> Result<Cow<'a, [u8]>, ZipError> {
    if u32le(bytes, entry.offset)? != 0x04034b50 {
        return Err(ZipError::BadLocalHeader);
    }
    let start = entry.offset + 30 + u16le(bytes, entry.offset + 26)? as u64 + u16le(bytes, entry.offset + 28)? as u64;
    let data = subarray(bytes, start, start.saturating_add(entry.compressed_size));
    match entry.method {
        0 => Ok(Cow::Borrowed(data)),
        8 => inflate_raw(data).map(Cow::Owned),
        m => Err(ZipError::Method(m)),
    }
}

/// Raw deflate, as the browser's DecompressionStream('deflate-raw') inflates it: data that stops
/// before the end of the stream, refers back before its start, or goes on after its end is an error.
fn inflate_raw(data: &[u8]) -> Result<Vec<u8>, ZipError> {
    use miniz_oxide::inflate::core::{decompress, inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF, DecompressorOxide};
    use miniz_oxide::inflate::TINFLStatus;
    let mut out = vec![0u8; data.len().saturating_mul(2).max(64)];
    let mut decompressor = Box::<DecompressorOxide>::default();
    let (mut at, mut written) = (0, 0);
    loop {
        // The whole output is the window: a distance past its start is an error, as zlib makes it.
        let (status, consumed, made) = decompress(&mut decompressor, &data[at..], &mut out, written, TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF);
        at += consumed;
        written += made;
        match status {
            TINFLStatus::Done => {
                out.truncate(written);
                return if at == data.len() { Ok(out) } else { Err(ZipError::Inflate) };
            }
            TINFLStatus::HasMoreOutput => {
                let grown = out.len().saturating_mul(2);
                out.resize(grown, 0);
            }
            _ => return Err(ZipError::Inflate),
        }
    }
}

/// A native library in an Android package: lib/<abi>/name.so (base/lib/… in an .aab).
#[derive(Clone, Debug)]
pub struct PackagedLibrary {
    pub abi: String,
    pub file: String,
    pub size: u64,
    /// The split APK it is in, for an .apks or .xapk bundle.
    pub from: Option<String>,
    entry: ZipEntry,
    /// Which of the package's inner APKs it is in (`Package::apks`), or none for the package itself.
    apk: Option<usize>,
}

/// A package's native libraries, and the inner APKs that hold some of them, to read them from.
pub struct Package<'a> {
    bytes: &'a [u8],
    apks: Vec<Vec<u8>>,
    pub libraries: Vec<PackagedLibrary>,
}

impl Package<'_> {
    /// The bytes of a library (its `read()` in the TypeScript).
    pub fn read(&self, lib: &PackagedLibrary) -> Result<Cow<'_, [u8]>, ZipError> {
        read_packaged(self.bytes, &self.apks, lib)
    }

    /// The inner APKs and the libraries, to keep without the package's borrow of the file.
    pub fn into_parts(self) -> (Vec<Vec<u8>>, Vec<PackagedLibrary>) {
        (self.apks, self.libraries)
    }
}

/// The bytes of a library of a package whose inner APKs are `apks` (`Package::into_parts`).
pub fn read_packaged<'a>(bytes: &'a [u8], apks: &'a [Vec<u8>], lib: &PackagedLibrary) -> Result<Cow<'a, [u8]>, ZipError> {
    match lib.apk {
        Some(k) => zip_read(&apks[k], &lib.entry),
        None => zip_read(bytes, &lib.entry),
    }
}

/// `/(?:^|\/)lib\/([^/]+)\/([^/]+\.so)$/`: the ABI and the file.
fn library(name: &str) -> Option<(&str, &str)> {
    let mut parts = name.rsplitn(3, '/');
    let file = parts.next()?;
    let abi = parts.next()?;
    let rest = parts.next()?;
    let lib_dir = rest.rsplit('/').next().unwrap_or(rest);
    (lib_dir == "lib" && !abi.is_empty() && file.len() > 3 && file.ends_with(".so")).then_some((abi, file))
}

/// The native libraries of a package. An .apk or .aab has them under lib/<abi>/; a bundle of
/// split APKs (.apks from bundletool, .xapk, .apkm) has them in the APKs inside it — usually one
/// per ABI, split_config.arm64_v8a.apk — which are opened in turn.
pub fn packaged_libraries(bytes: &[u8]) -> Result<Package<'_>, ZipError> {
    let mut out = Package { bytes, apks: Vec::new(), libraries: Vec::new() };
    let entries = zip_entries(bytes)?;
    for entry in &entries {
        if let Some((abi, file)) = library(&entry.name) {
            out.libraries.push(PackagedLibrary { abi: abi.into(), file: file.into(), size: entry.size, from: None, entry: entry.clone(), apk: None });
        }
    }
    for entry in &entries {
        let name = entry.name.as_bytes();
        if name.len() < 4 || !name[name.len() - 4..].eq_ignore_ascii_case(b".apk") {
            continue;
        }
        let inner = zip_read(bytes, entry)?.into_owned();
        if !is_zip(&inner) {
            continue;
        }
        let from = entry.name.rsplit('/').next().unwrap_or("").to_string();
        let k = out.apks.len();
        for lib in zip_entries(&inner)? {
            if let Some((abi, file)) = library(&lib.name) {
                out.libraries.push(PackagedLibrary { abi: abi.into(), file: file.into(), size: lib.size, from: Some(from.clone()), entry: lib.clone(), apk: Some(k) });
            }
        }
        out.apks.push(inner);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::library;

    #[test]
    fn library_paths() {
        assert_eq!(library("lib/arm64-v8a/libfoo.so"), Some(("arm64-v8a", "libfoo.so")));
        assert_eq!(library("base/lib/x86/a.so"), Some(("x86", "a.so")));
        assert_eq!(library("xlib/x86/a.so"), None);
        assert_eq!(library("lib/x86/.so"), None);
        assert_eq!(library("lib//a.so"), None);
        assert_eq!(library("lib/a.so"), None);
    }
}
