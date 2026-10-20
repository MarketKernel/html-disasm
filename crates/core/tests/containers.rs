//! The container readers on the fixtures: a Mach-O program (and a universal file made of it), an
//! Android ELF library, Windows programs including an ARM64X one — the cases of tests/macho.mjs,
//! tests/elf.mjs and tests/winarm.mjs the readers answer. tools/diff-containers.mjs checks every
//! field against the TypeScript on real files.

use disasm_core::elf::{parse_elf, ElfError};
use disasm_core::macho::{parse_macho, MachOError};
use disasm_core::pe::{parse_pe, PeError};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

#[test]
fn macho() {
    let bytes = fixture("hello");
    let m = parse_macho(&bytes, None).unwrap();
    assert_eq!(m.arch, "arm64");
    assert_eq!(m.file_type_name, "Executable");
    assert!(m.flag_names.contains(&"PIE"));
    let segments: Vec<&str> = m.segments.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(segments, ["__PAGEZERO", "__TEXT", "__DATA_CONST", "__DATA", "__LINKEDIT"]);
    assert!(m.libraries.iter().any(|l| l.contains("libSystem")));
    let printf = m.imports.iter().find(|i| i.name == "_printf").expect("printf is imported");
    assert_eq!(printf.library, "/usr/lib/libSystem.B.dylib");
    let main = m.exports.iter().find(|e| e.name == "_main").expect("main is exported");
    assert_eq!(m.entry, Some(main.addr), "the entry point is main");
    assert_eq!(m.build.as_ref().map(|b| b.platform.as_str()), Some("macOS"));
    assert!(m.function_starts.len() >= 4);
    assert_eq!(m.signature.as_ref().and_then(|s| s.hash_type.as_deref()), Some("SHA-256"));
    assert!(m.stubs.entries.iter().any(|(_, n)| n == "_printf"), "stubs are named");

    // A universal file opens at its arm64 slice.
    let mut fat = vec![0u8; 0x4000 + bytes.len()];
    let be = |fat: &mut Vec<u8>, at: usize, v: u32| fat[at..at + 4].copy_from_slice(&v.to_be_bytes());
    be(&mut fat, 0, 0xcafe_babe);
    be(&mut fat, 4, 2);
    be(&mut fat, 8, 0x0100_0007);
    be(&mut fat, 16, 0x4000);
    be(&mut fat, 20, 16);
    be(&mut fat, 28, 0x0100_000c);
    be(&mut fat, 36, 0x4000);
    be(&mut fat, 40, bytes.len() as u32);
    fat[0x4000..].copy_from_slice(&bytes);
    let u = parse_macho(&fat, None).unwrap();
    assert_eq!(u.arches.iter().map(|a| a.name.as_str()).collect::<Vec<_>>(), ["x86_64", "arm64"]);
    assert_eq!((u.arch.as_str(), u.exports.len()), ("arm64", m.exports.len()));

    assert_eq!(parse_macho(&[0; 16], None), Err(MachOError::TooSmall));
    assert_eq!(parse_macho(&[0; 64], None), Err(MachOError::NotMachO));
}

#[test]
fn elf() {
    let e = parse_elf(&fixture("android/libhello-arm64-v8a.so")).unwrap();
    assert_eq!(e.arch, "arm64");
    assert!(e.android.is_some(), "the Android note");
    assert!(e.needed.iter().any(|n| n == "libc.so"));
    assert!(e.imports.iter().any(|i| i.name == "printf" || i.name == "__android_log_print"));
    assert!(!e.exports.is_empty());
    assert!(!e.slots.entries.is_empty(), "GOT slots are named");
    let thumb = parse_elf(&fixture("android/libhello-armeabi-v7a.full.so")).unwrap();
    assert_eq!(thumb.arch, "armv7");
    assert!(!thumb.marks.is_empty(), "mapping symbols");
    assert_eq!(parse_elf(b"not an ELF file at all"), Err(ElfError::NotElf));
}

#[test]
fn pe() {
    let p = parse_pe(&fixture("x86/hello-x64.exe"), false).unwrap();
    assert_eq!(p.arch, "x86_64");
    assert!(!p.imports.is_empty() && !p.function_starts.is_empty());
    let x = parse_pe(&fixture("winarm/arm64x.dll"), false).unwrap();
    let hybrid = x.hybrid.expect("an ARM64X program is hybrid");
    assert!(hybrid.ranges.iter().any(|r| r.2 == "x64") && hybrid.ranges.iter().any(|r| r.2 == "arm64"));
    let ec = hybrid.ec.expect("its x64 view");
    assert!(!hybrid.ec_patches.is_empty());
    assert_eq!(ec.arch, "x86_64", "the view an x64 process gets");
    assert_eq!(parse_pe(&[0x4d; 32], false), Err(PeError::NotPe));
}
