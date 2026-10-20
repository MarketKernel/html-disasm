//! The x86 decoder and printer against tests/fixtures/x86-vectors.json: x86-64
//! and i386 encodings with the exact text llvm-objdump -M intel prints for
//! them, the same file tests/x86.mjs checks the TypeScript decoder against.

use disasm_core::x86::{decode_x86, format_x86, print_x86};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// The line and the length, as tests/x86.mjs makes them.
fn line(bytes: &str, addr: i64, mode: u8) -> (String, u32) {
    let code = hex(&bytes.replace(' ', ""));
    let d = decode_x86(&code, 0, code.len(), addr, mode);
    (format_x86(&print_x86(&d)).to_string(), d.length)
}

#[test]
fn vectors_match_llvm_objdump() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/x86-vectors.json");
    let json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let vectors = json["vectors"].as_array().unwrap();
    let mut wrong = Vec::new();
    let mut modes = [0usize; 2];
    for v in vectors {
        let bytes = v[0].as_str().unwrap();
        let addr = i64::from_str_radix(v[1].as_str().unwrap(), 16).unwrap();
        let want = v[2].as_str().unwrap();
        let mode = v.get(3).and_then(|m| m.as_u64()).unwrap_or(64) as u8;
        modes[(mode == 32) as usize] += 1;
        let (got, length) = line(bytes, addr, mode);
        if got != want || length as usize != bytes.len() / 2 {
            wrong.push(format!("{bytes} @{addr:x} ({mode}): want {want:?} ({}), got {got:?} ({length})", bytes.len() / 2));
        }
    }
    assert!(modes[0] > 0 && modes[1] > 0, "both modes are covered: {modes:?}");
    assert!(wrong.is_empty(), "{} of {} differ:\n{}", wrong.len(), vectors.len(), wrong.iter().take(40).cloned().collect::<Vec<_>>().join("\n"));
}

#[test]
fn cases_of_tests_x86_mjs() {
    for (bytes, addr, mode, text, length) in [
        // Ordinary code.
        ("55", 0x1000, 64, "push rbp", 1),
        ("4889e5", 0x1000, 64, "mov rbp, rsp", 3),
        ("48897df8", 0x1000, 64, "mov qword ptr [rbp - 0x8], rdi", 4),
        ("4883c480", 0x1000, 64, "add rsp, -0x80", 4),
        ("488d0500010000", 0x17, 64, "lea rax, [rip + 0x100]", 7),
        ("e82d000000", 0x22, 64, "call 0x54", 5),
        ("e8f0ffffff", 0, 64, "call 0xfffffffffffffff5", 5),
        ("48b88967452301000000", 0x1000, 64, "movabs rax, 0x123456789", 10),
        ("2e660f1f840000000000", 0x1000, 64, "nop word ptr cs:[rax + rax]", 10),
        ("f348ab", 0x1000, 64, "rep stosq qword ptr es:[rdi], rax", 3),
        ("62f175d9fe4010", 0x1000, 64, "vpaddd zmm0 {k1} {z}, zmm1, dword ptr [rax + 0x40]{1to16}", 7),
        ("62f1741858c2", 0x1000, 64, "vaddps zmm0, zmm1, zmm2, {rn-sae}", 6),
        ("0fc2c101", 0x1000, 64, "cmpltps xmm0, xmm1", 4),
        ("f30f1efa", 0x1000, 64, "endbr64", 4),
        // Prefixes as LLVM reads them.
        ("f00fc108", 0x1000, 64, "lock", 1),
        ("66f00fc108", 0x1000, 64, "lock xadd word ptr [rax], cx", 5),
        ("f387c8", 0x1000, 64, "xrelease", 1),
        ("f390", 0x1000, 64, "pause", 2),
        ("4190", 0x1000, 64, "xchg eax, r8d", 2),
        ("678b00", 0x1000, 64, "mov eax, dword ptr [eax]", 3),
        // What does not decode: LLVM skips the bytes it read.
        ("0fff", 0x1000, 64, "<unknown>", 2),
        ("660f3aff", 0x1000, 64, "<unknown>", 4),
        ("d6", 0x1000, 64, "<unknown>", 1),
        ("48", 0x1000, 64, "rex64", 1),
        ("0f", 0x1000, 64, "<unknown>", 1),
        // i386.
        ("55", 0x1000, 32, "push ebp", 1),
        ("40", 0x1000, 32, "inc eax", 1),
        ("e800000000", 0x1000, 32, "call 0x1005", 5),
        ("a134120000", 0x1000, 32, "mov eax, dword ptr [0x1234]", 5),
        ("e8f0ffffff", 0, 32, "call 0xfffffff5", 5),
    ] {
        assert_eq!(line(bytes, addr, mode), (text.to_string(), length), "{bytes}");
    }
}
