//! Source lines from DWARF: the `.debug_line` section a module built with
//! `-g` or `-gline-tables-only` carries. Its line programs (DWARF 2 to 5) are
//! run to a table of rows — address, file, line, column — and an instruction
//! is looked up by its offset. In a WebAssembly module the addresses count
//! from the start of the code section's contents.
//!
//! A port of src/core/wasm/dwarf.ts. The TypeScript ran the line program on
//! JavaScript numbers and stored the rows in Uint32Arrays, so addresses,
//! lines and columns are worked out here as doubles and cut to 32 bits the
//! same way when stored.

use std::collections::HashMap;

use super::module::WasmModule;
use super::reader::{add, utf8, Reader, Result, WasmError};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LineTable {
    pub files: Vec<String>,
    /// The rows, sorted by address: offset in the file, and file, line (0 where no line applies), column.
    pub addrs: Vec<u32>,
    pub rows: Vec<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceLine<'a> {
    pub file: &'a str,
    pub line: u32,
    pub column: u32,
}

impl LineTable {
    /// The source line of the instruction at `offset` in the file.
    pub fn lookup(&self, offset: u64) -> Option<SourceLine<'_>> {
        let mut lo = 0i64;
        let mut hi = self.addrs.len() as i64 - 1;
        let mut found = -1i64;
        while lo <= hi {
            let mid = (lo + hi) >> 1;
            if self.addrs[mid as usize] as u64 <= offset {
                found = mid;
                lo = mid + 1;
            } else {
                hi = mid - 1;
            }
        }
        if found < 0 {
            return None;
        }
        let found = found as usize;
        let line = self.rows[found * 3 + 1];
        let file = self.files.get(self.rows[found * 3] as usize)?;
        if line == 0 {
            return None;
        }
        Some(SourceLine { file, line, column: self.rows[found * 3 + 2] })
    }
}

mod form {
    pub const STRING: u64 = 0x08;
    pub const LINE_STRP: u64 = 0x1f;
    pub const STRP: u64 = 0x0e;
    pub const UDATA: u64 = 0x0f;
    pub const DATA1: u64 = 0x0b;
    pub const DATA2: u64 = 0x05;
    pub const DATA4: u64 = 0x06;
    pub const DATA8: u64 = 0x07;
    pub const DATA16: u64 = 0x1e;
    pub const BLOCK: u64 = 0x09;
}

fn u16(r: &mut Reader) -> Result<u64> {
    Ok(r.u8()? as u64 | (r.u8()? as u64) << 8)
}

fn u32(r: &mut Reader) -> Result<u64> {
    Ok(r.u8()? as u64 | (r.u8()? as u64) << 8 | (r.u8()? as u64) << 16 | (r.u8()? as u64) << 24)
}

/// A 4-byte offset, or an 8-byte one in 64-bit DWARF.
fn offset(r: &mut Reader, wide: bool) -> Result<u64> {
    if wide {
        let low = u32(r)?;
        Ok(low + (u32(r)? << 32))
    } else {
        u32(r)
    }
}

fn cstring(r: &mut Reader) -> Result<String> {
    let start = r.pos;
    while r.u8()? != 0 {}
    Ok(utf8(&r.bytes[start..r.pos - 1]))
}

fn string_at(module: &WasmModule, section: &str, offset: u64) -> Result<String> {
    let Some(s) = module.debug.get(section) else { return Ok(String::new()) };
    cstring(&mut Reader::new(&module.bytes, add(s.start, offset), s.start + s.size))
}

fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() || name.starts_with('/') {
        return name.to_string();
    }
    format!("{}/{name}", dir.strip_suffix('/').unwrap_or(dir))
}

/// ToUint32 of an integral double, as a store into a Uint32Array does.
fn to_uint32(v: f64) -> u32 {
    if !v.is_finite() {
        return 0;
    }
    let r = v.trunc() % 4294967296.0;
    (if r < 0.0 { r + 4294967296.0 } else { r }) as u32
}

/// JavaScript's whitespace, as `Number(string)` trims it.
fn js_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'
    )
}

/// `Number(text)`: what a directory index given as a string reads as.
fn js_number(text: &str) -> f64 {
    let t = text.trim_matches(js_space);
    if t.is_empty() {
        return 0.0;
    }
    let radix = |digits: &str, base: u32| {
        if digits.is_empty() || !digits.chars().all(|c| c.is_digit(base)) {
            return f64::NAN;
        }
        digits.chars().fold(0.0, |v, c| v * base as f64 + c.to_digit(base).unwrap() as f64)
    };
    let lower = t.get(..2).map(|p| p.to_ascii_lowercase());
    match lower.as_deref() {
        Some("0x") => return radix(&t[2..], 16),
        Some("0o") => return radix(&t[2..], 8),
        Some("0b") => return radix(&t[2..], 2),
        _ => {}
    }
    let unsigned = t.strip_prefix(['+', '-']).unwrap_or(t);
    if unsigned == "Infinity" {
        return if t.starts_with('-') { f64::NEG_INFINITY } else { f64::INFINITY };
    }
    // A decimal literal: digits, a point, digits (one side at least), an exponent.
    let b = unsigned.as_bytes();
    let mut i = 0;
    let digits = |i: &mut usize| {
        let from = *i;
        while *i < b.len() && b[*i].is_ascii_digit() {
            *i += 1;
        }
        *i - from
    };
    let mut count = digits(&mut i);
    if i < b.len() && b[i] == b'.' {
        i += 1;
        count += digits(&mut i);
    }
    if count == 0 {
        return f64::NAN;
    }
    if i < b.len() && (b[i] == b'e' || b[i] == b'E') {
        i += 1;
        if i < b.len() && (b[i] == b'+' || b[i] == b'-') {
            i += 1;
        }
        if digits(&mut i) == 0 {
            return f64::NAN;
        }
    }
    if i != b.len() {
        return f64::NAN;
    }
    t.parse().unwrap_or(f64::NAN)
}

/// An attribute of a DWARF 5 directory or file entry.
enum Value {
    Text(String),
    Number(u64),
}

/// Reads the source lines of a module, or None when it has none. An error
/// (the TypeScript threw) means the line table could not be read; the page
/// goes on without source lines.
pub fn read_lines(module: &WasmModule) -> Result<Option<LineTable>> {
    let Some(section) = module.debug.get(".debug_line").copied() else { return Ok(None) };
    let Some(code) = module.sections.iter().find(|s| s.id == 10) else { return Ok(None) };
    let code_start = code.start as f64;
    let code_size = code.size as f64;
    let mut files: Vec<String> = Vec::new();
    let mut file_ids: HashMap<String, i64> = HashMap::new();
    let mut file_id = |path: String| -> i64 {
        if let Some(&id) = file_ids.get(&path) {
            return id;
        }
        let id = files.len() as i64;
        files.push(path.clone());
        file_ids.insert(path, id);
        id
    };
    let mut addrs: Vec<f64> = Vec::new();
    let mut rows: Vec<f64> = Vec::new();
    let mut r = Reader::new(&module.bytes, section.start, section.start + section.size);
    while r.pos + 4 <= r.end {
        let mut length = u32(&mut r)?;
        let mut wide = false;
        if length == 0xffffffff {
            wide = true;
            length = offset(&mut r, true)?;
        }
        let unit_end = add(r.pos, length);
        if unit_end > r.end || length < 2 {
            break;
        }
        let version = u16(&mut r)?;
        if !(2..=5).contains(&version) {
            r.pos = unit_end;
            continue;
        }
        let mut address_size = 4;
        if version >= 5 {
            address_size = r.u8()?;
            r.u8()?;
        }
        let header_length = offset(&mut r, wide)?;
        let program_start = add(r.pos, header_length);
        let min_length = r.u8()? as f64;
        if version >= 4 {
            r.u8()?;
        }
        let _default_is_stmt = r.u8()?;
        let line_base = r.u8()? as i8 as f64;
        let line_range = match r.u8()? {
            0 => 1.0,
            n => n as f64,
        };
        let opcode_base = r.u8()?;
        let mut op_lengths: Vec<u8> = vec![0];
        for _ in 1..opcode_base {
            op_lengths.push(r.u8()?);
        }
        let mut dirs: Vec<String> = Vec::new();
        let mut names: Vec<i64> = Vec::new();
        if version >= 5 {
            for is_dir in [true, false] {
                let mut formats: Vec<(u64, u64)> = Vec::new();
                for _ in 0..r.u8()? {
                    let ty = r.u32()?;
                    formats.push((ty, r.u32()?));
                }
                let count = r.u32()?;
                for _ in 0..count {
                    let mut path = String::new();
                    let mut dir = 0f64;
                    for &(ty, f) in &formats {
                        let value = match f {
                            form::STRING => Value::Text(cstring(&mut r)?),
                            form::LINE_STRP => {
                                let at = offset(&mut r, wide)?;
                                Value::Text(string_at(module, ".debug_line_str", at)?)
                            }
                            form::STRP => {
                                let at = offset(&mut r, wide)?;
                                Value::Text(string_at(module, ".debug_str", at)?)
                            }
                            form::UDATA => Value::Number(r.u32()?),
                            form::DATA1 => Value::Number(r.u8()? as u64),
                            form::DATA2 => Value::Number(u16(&mut r)?),
                            form::DATA4 => Value::Number(u32(&mut r)?),
                            form::DATA8 => {
                                r.bytes_n(8)?;
                                Value::Number(0)
                            }
                            form::DATA16 => {
                                r.bytes_n(16)?;
                                Value::Number(0)
                            }
                            form::BLOCK => {
                                let n = r.u32()?;
                                r.bytes_n(n)?;
                                Value::Number(0)
                            }
                            _ => return Err(WasmError::DwarfForm { form: f }),
                        };
                        // DW_LNCT_path, DW_LNCT_directory_index: String(value), Number(value).
                        if ty == 1 {
                            path = match &value {
                                Value::Text(t) => t.clone(),
                                Value::Number(n) => n.to_string(),
                            };
                        }
                        if ty == 2 {
                            dir = match &value {
                                Value::Text(t) => js_number(t),
                                Value::Number(n) => *n as f64,
                            };
                        }
                    }
                    if is_dir {
                        dirs.push(path);
                    } else {
                        // dirs[dir] ?? '': an index only when it is a whole number in range.
                        let base = if dir >= 0.0 && dir.fract() == 0.0 && dir < dirs.len() as f64 { dirs[dir as usize].as_str() } else { "" };
                        names.push(file_id(join(base, &path)));
                    }
                }
            }
        } else {
            dirs.push(String::new());
            loop {
                let dir = cstring(&mut r)?;
                if dir.is_empty() {
                    break;
                }
                dirs.push(dir);
            }
            names.push(-1); // file numbers start at 1 before DWARF 5
            loop {
                let name = cstring(&mut r)?;
                if name.is_empty() {
                    break;
                }
                let dir = r.u32()?;
                r.u32()?;
                r.u32()?;
                let base = usize::try_from(dir).ok().and_then(|d| dirs.get(d)).map_or("", |d| d.as_str());
                names.push(file_id(join(base, &name)));
            }
        }
        r.pos = program_start;

        let mut address = 0f64;
        let mut file = 1u64;
        let mut line = 1f64;
        let mut column = 0f64;
        let mut dead = false;
        let emit = |addrs: &mut Vec<f64>, rows: &mut Vec<f64>, end: bool, address: f64, file: u64, line: f64, column: f64, dead: bool| {
            if dead {
                return;
            }
            addrs.push(code_start + address);
            let id = usize::try_from(file).ok().and_then(|f| names.get(f)).copied().unwrap_or(-1);
            rows.extend_from_slice(&[if end { 0.0 } else { id as f64 }, if end { 0.0 } else { line }, column]);
        };
        while r.pos < unit_end {
            let opcode = r.u8()?;
            if opcode >= opcode_base {
                let adjusted = (opcode - opcode_base) as f64;
                address += (adjusted / line_range).floor() * min_length;
                line += line_base + adjusted % line_range;
                emit(&mut addrs, &mut rows, false, address, file, line, column, dead);
                continue;
            }
            match opcode {
                0 => {
                    let size = r.u32()?;
                    let end = add(r.pos, size);
                    let sub = if size != 0 { r.u8()? } else { 0 };
                    if sub == 1 {
                        emit(&mut addrs, &mut rows, true, address, file, line, column, dead);
                        address = 0.0;
                        file = 1;
                        line = 1.0;
                        column = 0.0;
                        dead = false;
                    } else if sub == 2 {
                        let mut value = 0f64;
                        for i in 0..address_size.min(8) {
                            value += r.u8()? as f64 * 2f64.powi(8 * i as i32);
                        }
                        address = value;
                        // Code the linker dropped keeps a tombstone address: its rows are left out.
                        dead = value >= 4294967294.0 || value >= code_size;
                    }
                    r.pos = end;
                }
                1 => emit(&mut addrs, &mut rows, false, address, file, line, column, dead),
                2 => address += r.u32()? as f64 * min_length,
                3 => line += r.s32()? as f64,
                4 => file = r.u32()?,
                5 => column = r.u32()? as f64,
                6 | 7 | 10 | 11 => {}
                8 => address += ((255 - opcode_base as u32) as f64 / line_range).floor() * min_length,
                9 => address += u16(&mut r)? as f64,
                12 => {
                    r.u32()?;
                }
                _ => {
                    for _ in 0..op_lengths.get(opcode as usize).copied().unwrap_or(0) {
                        r.u32()?;
                    }
                }
            }
        }
        r.pos = unit_end;
    }
    if addrs.is_empty() {
        return Ok(None);
    }
    // Sort the rows by address, keeping the order of rows at the same address.
    let mut order: Vec<usize> = (0..addrs.len()).collect();
    order.sort_by(|&a, &b| addrs[a].partial_cmp(&addrs[b]).unwrap_or(core::cmp::Ordering::Equal).then(a.cmp(&b)));
    let mut sorted_addrs = Vec::with_capacity(order.len());
    let mut sorted_rows = Vec::with_capacity(order.len() * 3);
    for &from in &order {
        sorted_addrs.push(to_uint32(addrs[from]));
        sorted_rows.extend_from_slice(&[to_uint32(rows[from * 3]), to_uint32(rows[from * 3 + 1]), to_uint32(rows[from * 3 + 2])]);
    }
    Ok(Some(LineTable { files, addrs: sorted_addrs, rows: sorted_rows }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn number_of_a_string_like_javascript() {
        assert_eq!(js_number(" 12 "), 12.0);
        assert_eq!(js_number(""), 0.0);
        assert_eq!(js_number("0x1f"), 31.0);
        assert!(js_number("inf").is_nan());
        assert!(js_number("1_0").is_nan());
        assert_eq!(js_number("1e1"), 10.0);
        assert_eq!(js_number(".5"), 0.5);
        assert_eq!(js_number("-Infinity"), f64::NEG_INFINITY);
        assert!(js_number("-0x1").is_nan());
    }

    #[test]
    fn uint32_like_a_typed_array() {
        assert_eq!(to_uint32(-1.0), 0xffffffff);
        assert_eq!(to_uint32(4294967296.0 + 5.0), 5);
        assert_eq!(to_uint32(3.0), 3);
    }
}
