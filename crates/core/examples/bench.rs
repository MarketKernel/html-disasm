//! Times the arm64 decoder and pass on the code of a file: `cargo run --release --example bench -- <file> <offset> <count>`.
use disasm_core::arm64::{decode, format_insn, pass::Arm64Pass};
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let bytes = std::fs::read(&args[1]).unwrap();
    let offset: u64 = args[2].parse().unwrap();
    let count: u32 = args[3].parse().unwrap();
    let words: Vec<u32> = (0..count as usize).map(|i| u32::from_le_bytes(bytes[offset as usize + i * 4..][..4].try_into().unwrap())).collect();
    let mut sink = 0u64;
    let repeat: usize = std::env::var("REPEAT").ok().and_then(|r| r.parse().ok()).unwrap_or(0);
    for _ in 0..repeat {
        for (i, w) in words.iter().enumerate() {
            sink += decode(*w, 0x100000000 + i as i64 * 4).f as u64;
        }
    }
    let t = Instant::now();
    for (i, w) in words.iter().enumerate() {
        let insn = decode(*w, 0x100000000 + i as i64 * 4);
        sink += insn.f as u64 + insn.m.len() as u64;
    }
    let d = t.elapsed();
    println!("decode: {:?} ({:.0} ns/insn) {sink}", d, d.as_nanos() as f64 / count as f64);
    let t = Instant::now();
    for (i, w) in words.iter().enumerate().take(200000) {
        sink += format_insn(&decode(*w, 0x100000000 + i as i64 * 4)).len() as u64;
    }
    println!("decode+format 200k: {:?}", t.elapsed());
    let t = Instant::now();
    let mut pass = Arm64Pass::new(&bytes, &[(0x100000000, offset, count)], &[], false);
    while !pass.step(u32::MAX) {}
    let refs = pass.finish();
    let d = t.elapsed();
    println!("pass: {:?} ({:.0} ns/insn), {} data refs", d, d.as_nanos() as f64 / count as f64, refs.data_refs.values.len());
    println!("size_of Insn = {}, Op = {}", std::mem::size_of::<disasm_core::arm64::Insn>(), std::mem::size_of::<disasm_core::arm64::Op>());
}
