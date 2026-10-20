//! The WebAssembly decoder against tests/fixtures/wasm-vectors.json (the text
//! wasm-tools prints, made by `node tools/verify-wasm.mjs … --vectors`, the
//! same file tests/wasm.mjs checks the TypeScript against), the small cases of
//! tests/wasm.mjs, and the module reader on tests/fixtures/hello.wasm — hello.c
//! built with Emscripten 5.0.7:
//!
//!   emcc -O1 -g2 -gline-tables-only -matomics -mbulk-memory -sSHARED_MEMORY hello.c -o hello.wasm

use disasm_core::wasm::module::{DataMode, ExternKind};
use disasm_core::wasm::{bytes_text, decode_at, float_text, format_context, format_insn, operands_text, parse_wasm, read_lines, NotWasm, ParseError, WasmInsn, WasmModule};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn decode(bytes: &[u8]) -> WasmInsn {
    WasmInsn::decode(bytes, 0, bytes.len())
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/../../tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

#[test]
fn vectors_match_wasm_tools() {
    let json: serde_json::Value = serde_json::from_slice(&fixture("wasm-vectors.json")).unwrap();
    let vectors = json["vectors"].as_array().unwrap();
    let mut wrong = Vec::new();
    for v in vectors {
        let bytes = hex(v[0].as_str().unwrap());
        let want = v[1].as_str().unwrap();
        let insn = decode(&bytes);
        let got = format_insn(&insn, None);
        if got != want || insn.len != bytes.len() {
            wrong.push(format!("{}: want {want:?} ({}), got {got:?} ({})", v[0].as_str().unwrap(), bytes.len(), insn.len));
        }
    }
    assert!(vectors.len() > 1000, "the vectors are there: {}", vectors.len());
    assert!(wrong.is_empty(), "{} of {} differ:\n{}", wrong.len(), vectors.len(), wrong.iter().take(40).cloned().collect::<Vec<_>>().join("\n"));
}

#[test]
fn cases_of_tests_wasm_mjs() {
    let unknown = decode(&[0xff, 1, 2]);
    assert_eq!((unknown.m, unknown.len), (".bytes", 3), "an unknown opcode takes the rest of the body");
    assert_eq!(operands_text(&unknown, None), " ff 01 02");
    assert_eq!(format_insn(&decode(&[0x41, 0x80, 0x80, 0x80, 0x80, 0x00]), None), "i32.const 0", "redundant LEB128");
    assert_eq!(format_insn(&decode(&[0x42, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7f]), None), "i64.const -9223372036854775808", "i64.const, 64 bits");
    assert_eq!(format_insn(&decode(&[0x28, 0x42, 0x01, 0x08]), None), "i32.load 1 offset=8", "memarg with a memory index");

    // Floats as wasm-tools writes them: hex, and Rust's shortest decimal in a comment.
    let f64 = |v: f64| float_text(v.to_bits(), false);
    assert_eq!(f64(1.5), "0x1.8p+0 (;=1.5;)");
    assert_eq!(f64(-0.1), "-0x1.999999999999ap-4 (;=-0.1;)");
    assert_eq!(f64(1.0), "0x1p+0 (;=1;)");
    assert!(f64(5e-324).starts_with("0x1.p-1074"), "f64 subnormal");
    // -17126899348908.5625, a tie between two shortest forms: Rust rounds it up.
    assert_eq!(float_text(0xc2af_2755_80eb_5920, false), "-0x1.f275580eb592p+43 (;=-17126899348908.563;)");
    assert_eq!(float_text(0x7149f2ca, true), "0x1.93e594p+99 (;=1000000000000000000000000000000;)");
    assert_eq!(float_text(0x7fa00000, true), "nan:0x200000 (;=NaN;)");
    // Where the TypeScript's own shortest digits were one too many (an f32 power of two): Rust's.
    assert_eq!(float_text(0x6b000000, true), "0x1p+87 (;=154742510000000000000000000;)");

    let insn = decode(&[0x41, 0x80, 0x08]);
    assert_eq!(bytes_text(&[0x41, 0x80, 0x08], &insn, 12), "41 80 08");
    assert_eq!(bytes_text(&[0x41, 0x80, 0x08], &insn, 2), "41 80 …");
}

#[test]
fn a_reused_instruction() {
    // Decoding into the same instruction: lists are cleared, the bytes are those of the last one.
    let code = [0x0e, 2, 0, 1, 2, 0x1c, 1, 0x7f, 0xfd, 0x0c, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 0x0b];
    let mut insn = WasmInsn::new();
    let mut lines = Vec::new();
    let mut pos = 0;
    while pos < code.len() {
        decode_at(&code, pos, code.len(), &mut insn);
        lines.push(format_insn(&insn, None));
        pos += insn.len;
    }
    assert_eq!(lines, ["br_table 0 1 2", "select (result i32)", "v128.const i32x4 0x00000001 0x00000002 0x00000003 0x00000004", "end"]);
    assert!(insn.labels.is_empty() && insn.types.is_empty() && insn.bytes.is_none());
}

fn hello() -> WasmModule {
    parse_wasm(fixture("hello.wasm")).unwrap()
}

#[test]
fn the_module() {
    let module = hello();
    assert_eq!(module.warnings, []);
    let names: Vec<&str> = module.sections.iter().filter(|s| s.id != 0).map(|s| s.name.as_str()).collect();
    assert_eq!(names, ["type", "import", "function", "table", "memory", "global", "export", "start", "element", "data count", "code", "data"]);
    assert!(module.imports.iter().any(|i| i.module == "wasi_snapshot_preview1" && i.name == "fd_write"));
    assert!(module.exports.iter().any(|e| e.name == "_start" && e.kind == ExternKind::Func));
    assert!(module.memories[0].limits.shared, "shared memory");
    assert!(module.data.iter().all(|d| d.mode == DataMode::Passive), "passive data");
    assert_eq!(module.names.module.as_deref(), Some("hello.wasm"));
    for name in ["sum", "kind", "average", "main"] {
        assert!(module.names.functions.values().any(|n| n == name), "function {name}");
    }
    assert!(module.features.iter().any(|f| f.name == "atomics"), "target features");
    assert!(module.debug.contains_key(".debug_line"), "DWARF sections");
    assert_eq!(module.bodies.len() as u64 + module.imported_funcs, module.func_types.len() as u64);

    assert!(matches!(parse_wasm(vec![0; 16]), Err(ParseError::NotWasm(NotWasm::NoSignature))), "not a module");
    assert!(matches!(parse_wasm(vec![0, 0x61, 0x73, 0x6d, 0x0d, 0, 1, 0]), Err(ParseError::NotWasm(NotWasm::Component))), "a component is refused");
    assert!(matches!(parse_wasm(vec![0, 0x61, 0x73, 0x6d, 2, 0, 0, 0]), Err(ParseError::NotWasm(NotWasm::UnknownVersion { version: 2 }))));
}

#[test]
fn every_body_decodes() {
    let module = hello();
    let ctx = format_context(&module);
    let mut insn = WasmInsn::new();
    let (mut count, mut unknown, mut atomics) = (0, 0, 0);
    for body in &module.bodies {
        let mut pos = body.code;
        while pos < body.end {
            decode_at(&module.bytes, pos, body.end, &mut insn);
            let text = format_insn(&insn, Some(&ctx));
            unknown += (insn.op.is_none()) as usize;
            atomics += text.starts_with("i32.atomic.rmw.add") as usize;
            pos += insn.len;
            count += 1;
        }
        assert_eq!(pos, body.end, "body {} ends where its size says", body.func);
    }
    assert!(count > 5000, "{count} instructions");
    assert_eq!(unknown, 0);
    assert!(atomics > 0, "atomics");
}

#[test]
fn source_lines() {
    let module = hello();
    let lines = read_lines(&module).unwrap().expect("a line table");
    assert!(lines.files.iter().any(|f| f.ends_with("hello.c")));
    assert!(lines.addrs.windows(2).all(|w| w[0] <= w[1]), "sorted");
    // main's first instruction is line 32 of hello.c (tests/wasm.mjs, through the analysis).
    let main = module.names.functions.iter().find(|(_, n)| *n == "main").map(|(&i, _)| i).unwrap();
    let body = module.bodies.iter().find(|b| b.func == main).unwrap();
    let line = lines.lookup(body.code as u64).unwrap();
    assert_eq!((line.file, line.line, line.column), ("hello.c", 32, 0));
}

/* ---------------- the analysis (the rest of tests/wasm.mjs) ---------------- */

#[test]
fn the_analysis() {
    use disasm_core::disassembly::iflag;
    use disasm_core::wasm::program::{FnKind, WasmSession};
    let module = hello();
    let p = WasmSession::analyse(fixture("hello.wasm")).unwrap();
    let named = |name: &str| p.bodies.iter().find(|f| f.name.as_ref().is_some_and(|(_, d)| d.short == name)).unwrap_or_else(|| panic!("no {name}"));
    assert!(p.bodies.iter().all(|f| f.count > 0), "every body has code");
    assert_eq!(p.bodies.len(), module.bodies.len());
    assert_eq!(p.bodies.iter().find(|f| f.kind == FnKind::Entry).map(|f| f.name.as_ref().unwrap().0.as_str()), Some("__wasm_init_memory"), "the start function");
    assert_eq!(named("_start").kind, FnKind::Export);
    named("__wasm_call_ctors");
    assert!(p.imported.iter().any(|f| f.name.short == "fd_write" || f.name.short == "__wasi_fd_write"), "imports");
    assert!(!p.segments.is_empty() && p.segments.iter().all(|s| s.passive) && p.segments[0].addr >= 1024, "passive segments placed by the start function");
    let strings: Vec<&str> = p.strings.iter().map(|s| s.text.as_str()).collect();
    assert!(strings.contains(&"Hello, world! sum=%ld avg=%.2f kind=%s\n") && strings.contains(&"--help"), "strings");
    let counter = p.data_refs.keys.iter().enumerate().any(|(k, &addr)| p.data_refs.starts[k + 1] - p.data_refs.starts[k] >= 2 && p.segment_at(addr as i64).is_none());
    assert!(counter, "the atomic counter is a data reference");
    assert_eq!(p.callers.get(named("sum").addr as i64).len(), 2, "sum is called twice");
    assert!(p.offsets.windows(2).all(|w| w[0] < w[1]), "offsets ascend");
    assert!(p.flags.iter().any(|f| f & iflag::LABEL != 0), "labels");
    assert!(p.mnemonics.contains(&"i32.atomic.rmw.add"), "atomics counted");
    for f in &p.bodies {
        assert!(p.flags[f.first as usize] & iflag::FUNCTION != 0);
    }
    // HLA64 statements: main's are joined into lines.
    let main = named("main");
    assert!((main.first..main.first + main.count).filter(|&i| p.flags[i as usize] & iflag::FUSE != 0).count() > 10, "main's statements are joined");
}
