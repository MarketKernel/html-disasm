//! Objective-C metadata of a Mach-O image, a port of src/core/objc.ts: the
//! classes and categories with their methods, the selector and class
//! references the code loads, the constant NSStrings, and the objc_msgSend
//! stubs of arm64. A stripped program keeps these, so its methods get their
//! names back (`-[Greeter greeting]`).
//!
//! The lists are pointers dyld fixes up: a rebase is read from its chained
//! encoding, a bind is named by its import. Values are JavaScript numbers
//! (`f64`), with JavaScript's bitwise operations, as in the TypeScript.

use crate::macho::{MachO, NumberMap};
use crate::text::to_int32;

#[derive(Clone, Debug, PartialEq)]
pub struct ObjcMethod {
    /// `-[Greeter greeting]`, `+[Greeter defaultGreeter]`
    pub name: String,
    pub selector: String,
    /// Where its code is (0 when the method has none here).
    pub imp: f64,
    pub class_method: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ObjcClass {
    pub name: String,
    pub swift: Option<String>,
    pub addr: f64,
    pub superclass: Option<String>,
    /// For a category: its name.
    pub category: Option<String>,
    pub methods: Vec<ObjcMethod>,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Objc {
    pub classes: Vec<ObjcClass>,
    pub categories: Vec<ObjcClass>,
    pub protocols: Vec<String>,
    /// A selector reference → the selector.
    pub selrefs: NumberMap<String>,
    /// A class reference → the class name.
    pub classrefs: NumberMap<String>,
    /// A constant NSString → its text, in UTF-16 units (a lone surrogate stays one).
    pub cfstrings: NumberMap<Vec<u16>>,
    /// Method code → `-[Class selector]`.
    pub methods: NumberMap<String>,
    /// An arm64 `__objc_stubs` entry → the selector it sends.
    pub stubs: NumberMap<String>,
}

/// `name.replace(/^_OBJC_(?:META)?CLASS_\$_/, '')`.
fn without_class_prefix(name: &str) -> &str {
    name.strip_prefix("_OBJC_CLASS_$_").or_else(|| name.strip_prefix("_OBJC_METACLASS_$_")).unwrap_or(name)
}

/// A Swift class's runtime name as Swift writes it: `_TtC5Hello14ViewController` is
/// Hello.ViewController. Lengths count UTF-16 units, as the TypeScript's did.
pub fn swift_class_name(name: &str) -> Option<String> {
    let rest = name.strip_prefix("_Tt")?;
    let kinds = rest.bytes().take_while(|&b| b == b'C' || b == b'P').count();
    if kinds == 0 {
        return None;
    }
    let rest = &rest[kinds..];
    // `(.*)$`: the rest may hold no line terminator.
    if rest.contains(['\n', '\r', '\u{2028}', '\u{2029}']) {
        return None;
    }
    let units: Vec<u16> = rest.encode_utf16().collect();
    let mut at = 0usize;
    let mut parts: Vec<String> = Vec::new();
    if units.first() == Some(&(b's' as u16)) {
        parts.push("Swift".into());
        at = 1;
    }
    while at < units.len() {
        let digits = units[at..].iter().take_while(|&&u| (b'0' as u16..=b'9' as u16).contains(&u)).count();
        if digits == 0 {
            return None;
        }
        let number: String = units[at..at + digits].iter().map(|&u| u as u8 as char).collect();
        let len = number.parse::<f64>().unwrap_or(f64::INFINITY);
        let start = at + digits;
        let end = if len >= (units.len() - start) as f64 { units.len() } else { start + len as usize };
        parts.push(String::from_utf16_lossy(&units[start..end]));
        at = end;
    }
    (parts.len() >= 2).then(|| parts.join("."))
}

/// Reads the Objective-C metadata of an image (`slice`: the bytes of its slice); None when it has none.
pub fn parse_objc(m: &MachO, slice: &[u8]) -> Option<Objc> {
    let find = |name: &str| m.sections.iter().filter(|s| s.sectname == name && s.offset != 0).collect::<Vec<_>>();
    let classlist = find("__objc_classlist");
    let catlist = find("__objc_catlist");
    let selref_sections = find("__objc_selrefs");
    if classlist.is_empty() && catlist.is_empty() && selref_sections.is_empty() {
        return None;
    }
    if ![0x0100_000c, 0x0100_0007, 12, 7].contains(&m.cputype) {
        return None;
    }
    // Pointer-sized fields: 8 bytes, or 4 in a 32-bit image, where class_ro_t has no padding before its name.
    let p = if m.is64 { 8.0 } else { 4.0 };
    let ro_name = if m.is64 { 24.0 } else { 16.0 };
    let ro_methods = ro_name + p;
    let mut out = Objc::default();

    let u32_at = |addr: f64| -> Option<f64> {
        let b = m.bytes_at(slice, addr, 4.0)?;
        (b.len() == 4).then(|| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as f64)
    };
    let i32_at = |addr: f64| u32_at(addr).map(|v| to_int32(v) as f64);
    // A pointer field: the name it is bound to, or the address it holds.
    let bound = |addr: f64| m.stubs.get(addr);
    let ptr = |addr: f64| -> Option<f64> {
        if bound(addr).is_some() {
            return None;
        }
        // Pointer authentication and Swift's flag bits live outside the address.
        m.pointer_at(slice, addr).filter(|&v| v != 0.0).map(|v| v % 140737488355328.0)
    };
    let string = |addr: Option<f64>| addr.and_then(|a| m.cstring_at(slice, a, 1024.0));
    let ro_of = |cls: f64| -> Option<f64> {
        // FAST_DATA_MASK: the low bits are flags (Swift classes set 1 or 2).
        ptr(cls + 4.0 * p).map(|data| data - data % if p == 8.0 { 8.0 } else { 4.0 })
    };
    let class_name = |cls: f64| ro_of(cls).and_then(|ro| string(ptr(ro + ro_name)));
    let class_name_at = |field: f64| -> Option<String> {
        if let Some(name) = bound(field) {
            return Some(without_class_prefix(name).to_string());
        }
        ptr(field).and_then(class_name)
    };

    let methods_at = |out: &mut Objc, list: Option<f64>, owner: &str, class_method: bool| -> Vec<ObjcMethod> {
        let Some(list) = list else { return Vec::new() };
        let (Some(flags), Some(count)) = (u32_at(list), u32_at(list + 4.0)) else { return Vec::new() };
        if count > 65536.0 {
            return Vec::new();
        }
        let f = to_int32(flags);
        let small = f & (0x8000_0000u32 as i32) != 0;
        let size = (f & 0xfffc) as f64;
        let mut methods = Vec::new();
        let mut i = 0.0;
        while i < count {
            let at = list + 8.0 + i * size;
            i += 1.0;
            let selector;
            let imp;
            if small {
                // Offsets from each field: the name to a selector reference, the code to itself.
                let (Some(name_offset), Some(imp_offset)) = (i32_at(at), i32_at(at + 8.0)) else { break };
                // In the shared cache the offset is to the selector itself; in an image, to its reference.
                selector = if f & 0x4000_0000 != 0 { string(Some(at + name_offset)) } else { string(ptr(at + name_offset)) };
                imp = if imp_offset != 0.0 { at + 8.0 + imp_offset } else { 0.0 };
            } else {
                selector = string(ptr(at));
                imp = ptr(at + 2.0 * p).unwrap_or(0.0);
            }
            let Some(selector) = selector.filter(|s| !s.is_empty()) else { continue };
            let name = format!("{}[{owner} {selector}]", if class_method { '+' } else { '-' });
            if imp != 0.0 && !out.methods.has(imp) {
                out.methods.set(imp, name.clone());
            }
            methods.push(ObjcMethod { name, selector, imp, class_method });
        }
        methods
    };

    for section in &classlist {
        let mut at = section.addr;
        while at + p <= section.addr + section.size {
            let here = at;
            at += p;
            let Some(cls) = ptr(here) else { continue };
            let ro = ro_of(cls);
            let Some(ro) = ro else { continue };
            let Some(name) = string(ptr(ro + ro_name)).filter(|n| !n.is_empty()) else { continue };
            let swift = swift_class_name(&name);
            let shown = swift.clone().unwrap_or_else(|| name.clone());
            let mut methods = methods_at(&mut out, ptr(ro + ro_methods), &shown, false);
            // The metaclass (the class's isa) has the class methods.
            if let Some(meta_ro) = ptr(cls).and_then(ro_of) {
                let more = methods_at(&mut out, ptr(meta_ro + ro_methods), &shown, true);
                methods.extend(more);
            }
            out.classes.push(ObjcClass { name, swift, addr: cls, superclass: class_name_at(cls + p), category: None, methods });
        }
    }
    for section in &catlist {
        let mut at = section.addr;
        while at + p <= section.addr + section.size {
            let here = at;
            at += p;
            let Some(cat) = ptr(here) else { continue };
            let category = string(ptr(cat));
            let owner = class_name_at(cat + p).unwrap_or_else(|| "?".into());
            let shown = swift_class_name(&owner).unwrap_or_else(|| owner.clone());
            let mut methods = methods_at(&mut out, ptr(cat + 2.0 * p), &shown, false);
            let more = methods_at(&mut out, ptr(cat + 3.0 * p), &shown, true);
            methods.extend(more);
            out.categories.push(ObjcClass { name: owner, swift: None, addr: cat, superclass: None, category: Some(category.unwrap_or_default()), methods });
        }
    }
    for section in find("__objc_protolist") {
        let mut at = section.addr;
        while at + p <= section.addr + section.size {
            if let Some(name) = ptr(at).and_then(|proto| string(ptr(proto + p))).filter(|n| !n.is_empty()) {
                out.protocols.push(swift_class_name(&name).unwrap_or(name));
            }
            at += p;
        }
    }
    for section in &selref_sections {
        let mut at = section.addr;
        while at + p <= section.addr + section.size {
            if let Some(name) = string(ptr(at)).filter(|n| !n.is_empty()) {
                out.selrefs.set(at, name);
            }
            at += p;
        }
    }
    for section in find("__objc_classrefs").into_iter().chain(find("__objc_superrefs")) {
        let mut at = section.addr;
        while at + p <= section.addr + section.size {
            if let Some(name) = class_name_at(at).filter(|n| !n.is_empty()) {
                out.classrefs.set(at, swift_class_name(&name).unwrap_or(name));
            }
            at += p;
        }
    }
    // CFString: isa, flags, the characters, the length. Flag 0x7d0 has UTF-16 characters, 0x7c8 bytes.
    for section in find("__cfstring") {
        let mut at = section.addr;
        while at + 4.0 * p <= section.addr + section.size {
            let here = at;
            at += 4.0 * p;
            let flags = u32_at(here + p);
            let (Some(chars), Some(length)) = (ptr(here + 2.0 * p), u32_at(here + 3.0 * p)) else { continue };
            if length > 1048576.0 {
                continue;
            }
            if flags == Some(2000.0) {
                if let Some(b) = m.bytes_at(slice, chars, length * 2.0) {
                    if b.len() as f64 == length * 2.0 {
                        out.cfstrings.set(here, b.chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect());
                    }
                }
            } else if let Some(text) = m.cstring_at(slice, chars, (length + 1.0).max(1.0)) {
                out.cfstrings.set(here, text.encode_utf16().collect());
            }
        }
    }
    // An objc_msgSend stub loads its selector with adrp + ldr x1, then jumps to objc_msgSend:
    // through the GOT in 32 bytes, or with a direct b in 12 (-objc_stubs_small).
    if m.cputype == 0x0100_000c {
        for section in find("__objc_stubs") {
            let mut at = section.addr;
            while at + 12.0 <= section.addr + section.size {
                let (adrp, ldr) = (u32_at(at), u32_at(at + 4.0));
                let ok = matches!((adrp, ldr), (Some(a), Some(l)) if (to_int32(a) as u32 & 0x9f00_001f) == 0x9000_0001 && (to_int32(l) as u32 & 0xffc0_03ff) == 0xf940_0021);
                if !ok {
                    at += 4.0;
                    continue;
                }
                let (a, l) = (to_int32(adrp.unwrap()) as u32, to_int32(ldr.unwrap()) as u32);
                let imm = ((((a >> 29) & 3) | (((a >> 5) & 0x7ffff) << 2)) << 11) as i32 >> 11;
                let page = (at - at % 4096.0) + imm as f64 * 4096.0;
                if let Some(selector) = out.selrefs.get(page + ((l >> 10) & 0xfff) as f64 * 8.0).cloned() {
                    out.stubs.set(at, selector);
                }
                let next = u32_at(at + 8.0).unwrap_or(0.0);
                at += if (to_int32(next) as u32 & 0xfc00_0000) == 0x1400_0000 { 12.0 } else { 32.0 };
            }
        }
    }
    Some(out)
}
