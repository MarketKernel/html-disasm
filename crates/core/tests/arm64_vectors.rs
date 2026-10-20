//! The decoder against tests/fixtures/decode-vectors.json: thousands of words
//! with the exact text llvm-objdump prints for them, the same file the
//! TypeScript decoder was checked against.

use disasm_core::arm64::{decode, format_insn};

#[test]
fn vectors_match_llvm_objdump() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/decode-vectors.json");
    let json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let vectors = json["vectors"].as_array().unwrap();
    let only = std::env::var("ONLY").ok();
    let mut wrong = Vec::new();
    for v in vectors {
        let word = u32::from_str_radix(v[0].as_str().unwrap(), 16).unwrap();
        let pc = i64::from_str_radix(v[1].as_str().unwrap(), 16).unwrap();
        let want = v[2].as_str().unwrap();
        let got = format_insn(&decode(word, pc));
        if got.as_str() != want && only.as_deref().is_none_or(|o| want.starts_with(o)) {
            wrong.push(format!("{:08x}: want {:?}, got {:?}", word, want, got.as_str()));
        }
    }
    let shown: Vec<_> = wrong.iter().filter(|s| std::env::var("ALL").is_ok() || !s.contains("got \".inst")).take(40).collect();
    assert!(wrong.is_empty(), "{} of {} differ:\n{}", wrong.len(), vectors.len(), shown.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("\n"));
}
