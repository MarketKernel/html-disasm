//! .NET: the metadata, the names and the analysis of tests/fixtures/dotnet/hello.dll (made by its
//! build.sh), the cases of tests/cil.mjs the core answers.

use disasm_core::cil::metadata::{token_table, Metadata, Section, USER_STRING};
use disasm_core::cil::names::{needs_quotes, proper_local_name, proper_name, split_commas};
use disasm_core::cil::page::{g_format, string_text};
use disasm_core::cil::program::{part, CilSession, FnKind};
use disasm_core::disassembly::iflag;

/// The sections and the CLR directory of a PE file, as the page's reader gives them.
fn pe_layout(b: &[u8]) -> (Vec<Section>, Option<u32>) {
    let u16 = |at: usize| u16::from_le_bytes([b[at], b[at + 1]]) as usize;
    let u32 = |at: usize| u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
    let pe = u32(0x3c) as usize;
    assert_eq!(&b[pe..pe + 4], b"PE\0\0");
    let count = u16(pe + 6);
    let optional = pe + 24;
    let dirs = optional + if u16(optional) == 0x20b { 112 } else { 96 };
    let clr = u32(dirs + 14 * 8);
    let table = optional + u16(pe + 20);
    let sections = (0..count)
        .map(|k| {
            let s = table + k * 40;
            Section { virtual_size: u32(s + 8), rva: u32(s + 12), raw_size: u32(s + 16), raw_offset: u32(s + 20) }
        })
        .collect();
    (sections, Some(clr))
}

fn hello() -> Vec<u8> {
    std::fs::read(format!("{}/../../tests/fixtures/dotnet/hello.dll", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

#[test]
fn the_metadata() {
    let file = hello();
    let (sections, clr) = pe_layout(&file);
    let md = Metadata::read(file, sections, clr).unwrap();
    assert!(md.user_strings().is_some(), "#US");
    let main = (1..=md.rows(0x06)).find(|&m| md.string(md.get(disasm_core::cil::metadata::METHOD_DEF_NAME, m)) == "Main").unwrap();
    let kinds: Vec<u32> = md.body(main).unwrap().clauses.iter().map(|c| c.kind).collect();
    assert_eq!(kinds, [0, 2], "a fat body with clauses");
}

#[test]
fn the_analysis() {
    let file = hello();
    let (sections, clr) = pe_layout(&file);
    let p = CilSession::analyse(file, sections, clr).unwrap();
    let f = |name: &str| p.functions.iter().position(|f| f.name == name).unwrap_or_else(|| panic!("no {name}"));
    assert_eq!(p.functions.len(), 59, "every method with a body is a function");
    let main = &p.functions[f("Hello.Program::Main")];
    assert_eq!(main.kind, FnKind::Entry);
    assert_eq!(p.functions[f("Hello.Program::Sum")].kind, FnKind::Symbol);
    assert_eq!(p.functions[f("Hello.More.Edge::Constants")].kind, FnKind::Export);
    f("Hello.Program::Largest<T>");
    let sum = &p.functions[f("Hello.Program::Sum")];
    assert_eq!(sum.full, "int64 Hello.Program::Sum(int32[], int32)", "full signature");
    assert_eq!(p.callers.get(sum.addr as i64).len(), 1, "callers");
    let write_line = p.imported.iter().find(|m| m.full == "void [System.Console]System.Console::WriteLine(string)").expect("WriteLine is an import");
    assert_eq!(write_line.assembly, "System.Console");
    assert!(p.callers.get(write_line.token as i64).len() >= 2, "calls to it are counted");
    assert!(!p.imported.iter().any(|m| m.name.contains("Hello.More.Box")), "a method of a generic class here is not an import");
    let pinvokes: Vec<(&str, &str, &str)> = p.pinvokes.iter().map(|x| (x.name.as_str(), x.library.as_str(), x.entry.as_str())).collect();
    assert_eq!(pinvokes, [("Hello.More.Edge::Abs", "libc", "abs")], "P/Invoke");
    assert!(p.data_refs.keys.iter().any(|&k| token_table(k as u32) == USER_STRING), "strings are #US tokens");
    let classes: Vec<Option<&str>> = p.ranges.iter().take(2).map(|r| r.class.as_deref()).collect();
    assert_eq!(classes, [Some(".class Hello.Point"), Some(".class Hello.Program")], "ranges are types");
    // The switch of Edge::Switch has seven targets.
    let switch = p.functions[f("Hello.More.Edge::Switch")].first + 1;
    let k = p.target_index.iter().position(|&i| i == switch).unwrap();
    assert_eq!(p.target_starts[k + 1] - p.target_starts[k], 7);
    // Main's try blocks and handlers start at labels.
    let mut regions: Vec<(u32, Vec<u8>)> = Vec::new();
    for r in p.regions.chunks(3).filter(|r| r[0] >= main.first && r[0] < main.first + main.count) {
        match regions.iter_mut().find(|(i, _)| *i == r[0]) {
            Some((_, parts)) => parts.push(r[2] as u8),
            None => regions.push((r[0], vec![r[2] as u8])),
        }
    }
    let parts: Vec<Vec<u8>> = regions.into_iter().map(|(_, parts)| parts).collect();
    assert_eq!(parts, [vec![part::TRY, part::TRY], vec![part::HANDLER], vec![part::HANDLER]]);
    assert!(!p.mnemonics.contains(&".byte"), "no instruction left undecoded");
    for func in &p.functions {
        assert!(p.flags[func.first as usize] & iflag::FUNCTION != 0);
    }
    // HLA64 statements: Sum's loop body joins into lines.
    assert!((sum.first..sum.first + sum.count).filter(|&i| p.flags[i as usize] & iflag::FUSE != 0).count() >= 4);
}

#[test]
fn names() {
    let names = ["Main", "<>c", "value", "Value", ".ctor", ".cctor", "Func`2", "a.b", "a..b", "x.", "#x", "_$@", "?x", "x?", "Привет", "async", "ldc.i4"];
    let quoted: Vec<bool> = names.iter().map(|n| needs_quotes(n)).collect();
    assert_eq!(quoted, [false, true, true, false, false, false, false, false, true, true, false, false, true, false, true, true, true]);
    assert_eq!(proper_name("process'@347"), "'process\\'@347'");
    assert_eq!([proper_local_name("a.b"), proper_name("a.b")], ["'a.b'", "a.b"], "a local name with a dot is quoted");
    assert_eq!(split_commas("void A::f(int32,string)", 10), "void A::f(int32, string)");
    assert_eq!(split_commas("void A::f(class X`2<int32,int32>,int32)", 10), "void A::f(class X`2<int32,int32>, int32)");
    assert_eq!(split_commas("int32 A::f(method void *(void*,uint8*),void*)", 11), "int32 A::f(method void *(void*,uint8*), void*)");
    assert_eq!(split_commas("int32 A::f(object,method void *(void*,uint8*),void*)", 11), "int32 A::f(object, method void *(void*, uint8*),void*)");
    assert_eq!(split_commas("void A::'f\\'1'(int32,int32)", 15), "void A::'f\\'1'(int32,int32)");
}

#[test]
fn floats_as_g() {
    let got = [g_format(1.0, 8), g_format(0.1, 8), g_format(3.4e38, 8), g_format(1e-7, 8), g_format(0.1, 17), g_format(123456789.125, 17), g_format(-0.0, 8)];
    assert_eq!(got, ["1", "0.1", "3.4e+38", "1e-07", "0.10000000000000001", "123456789.125", "-0.0"]);
    // JavaScript's toFixed and toExponential round a tie up, as the TypeScript did: 1000000.25 to 8 digits.
    assert_eq!([g_format(1000000.25, 8), g_format(-2.5, 1), g_format(9.5, 1), g_format(0.000123456785, 8)], ["1000000.3", "-3", "1e+01", "0.00012345679"]);
}

#[test]
fn strings() {
    let units = |s: &str| s.encode_utf16().collect::<Vec<u16>>();
    assert_eq!(string_text(&units("a\t\"b\"?\\")), "\"a\\t\\\"b\\\"\\?\\\\\"");
    assert_eq!(string_text(&units("é")), "bytearray (E9 00)");
}
