//! Java bytecode: the JVM decoder against javap's text of tests/fixtures/jvm/hello.jar
//! (hello.javap, made by its build.sh), every instruction of every method; and the rules of
//! javap's that the JDK and the IDEs' JARs taught, on small cases — quoting names, Java's way of
//! writing floating point. The decoder and class reader parts of tests/jvm.mjs.

use disasm_core::jvm::{
    check_name, decode_at, descriptor_kinds, escape_string, field_type, insn_text, is_class_file, java_double, java_float, method_types, ClassFile, JvmInsn, Wtf8, Wtf8Buf,
};
use disasm_core::zip::{zip_entries, zip_read};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/../../tests/fixtures/jvm/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

/* ---------------- javap's text, read back (tools/javap-text.mjs) ---------------- */

/// JavaScript's `\s` (and what `trim` removes): its white space and line terminators.
fn js_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'
    )
}

fn js_trim(s: &str) -> &str {
    s.trim_matches(js_space)
}

/// Runs of spaces count as one: javap pads its columns.
fn normal(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut space = false;
    for c in text.chars() {
        if js_space(c) {
            space = true;
        } else {
            if space && !out.is_empty() {
                out.push(' ');
            }
            space = false;
            out.push(c);
        }
    }
    out
}

/// The text of each class, in the order javap printed them: a class ends at a `}` of its own.
fn javap_classes(text: &str) -> Vec<Vec<&str>> {
    let mut classes = Vec::new();
    let mut lines = Vec::new();
    for line in text.split('\n') {
        lines.push(line);
        if line == "}" {
            classes.push(std::mem::take(&mut lines));
        }
    }
    classes
}

/// `/^\s+(\d+): (.*)$/s`: an instruction's pc and text.
fn insn_line(line: &str) -> Option<(usize, &str)> {
    let rest = line.trim_start_matches(js_space);
    if rest.len() == line.len() {
        return None;
    }
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    let text = rest[digits..].strip_prefix(": ")?;
    if digits == 0 {
        return None;
    }
    Some((rest[..digits].parse().ok()?, text))
}

/// The methods' code in a class's text: one list of (pc, text) per Code block, in order. javap
/// writes a switch on several lines; they are joined with spaces, as the decoder writes them.
fn code_blocks(lines: &[&str]) -> Vec<Vec<(usize, String)>> {
    let mut blocks: Vec<Vec<(usize, String)>> = Vec::new();
    let mut in_block = false;
    let mut pending: Option<(usize, String)> = None;
    for line in lines {
        if let Some(entry) = pending.as_mut() {
            entry.1.push(' ');
            entry.1.push_str(js_trim(line));
            if js_trim(line) == "}" {
                blocks.last_mut().unwrap().push(pending.take().unwrap());
            }
            continue;
        }
        let code = line.trim_start_matches(js_space);
        if code.len() < line.len() && code == "Code:" {
            blocks.push(Vec::new());
            in_block = true;
            continue;
        }
        match insn_line(line).filter(|_| in_block) {
            Some((pc, text)) => {
                let switch = ["tableswitch", "lookupswitch"]
                    .iter()
                    .any(|m| text.strip_prefix(m).is_some_and(|r| r.trim_start_matches(js_space).starts_with('{') && r.len() > r.trim_start_matches(js_space).len()));
                if switch {
                    pending = Some((pc, text.to_string()));
                } else {
                    blocks.last_mut().unwrap().push((pc, text.to_string()));
                }
            }
            None => in_block = false,
        }
    }
    blocks
}

/// javap's output is UTF-8, where a lone surrogate becomes `?`.
fn as_javap(text: &Wtf8) -> String {
    text.code_points().map(|c| char::from_u32(c).unwrap_or('?')).collect()
}

#[test]
fn every_instruction_matches_javap() {
    let jar = fixture("hello.jar");
    let javap = String::from_utf8(fixture("hello.javap")).unwrap();
    // javap printed the classes in the order of the JAR's entries.
    let entries: Vec<_> = zip_entries(&jar).unwrap().into_iter().filter(|e| e.name.ends_with(".class")).collect();
    let reference = javap_classes(&javap);
    assert_eq!(reference.len(), entries.len(), "javap printed every class");
    let mut insn = JvmInsn::new();
    let mut total = 0;
    let mut wrong = Vec::new();
    for (k, entry) in entries.iter().enumerate() {
        let cf = ClassFile::parse(zip_read(&jar, entry).unwrap().into_owned(), &entry.name).unwrap();
        let blocks = code_blocks(&reference[k]);
        let methods: Vec<_> = cf.methods.iter().filter(|m| m.code.is_some()).collect();
        assert_eq!(methods.len(), blocks.len(), "{}: methods with code", cf.name());
        for (method, block) in methods.iter().zip(&blocks) {
            let code = method.code.as_ref().unwrap();
            let mut ours = std::collections::HashMap::new();
            let mut pos = code.offset;
            while pos < code.offset + code.length {
                decode_at(&cf.bytes, code.offset, pos, code.offset + code.length, &mut insn);
                ours.insert(insn.at, normal(&as_javap(&insn_text(&cf, &insn))));
                pos += insn.len;
            }
            for (pc, want) in block {
                total += 1;
                let want = normal(want);
                if ours.get(pc) != Some(&want) {
                    wrong.push(format!("{}.{} @{pc}: want {want:?}, got {:?}", cf.name(), cf.utf8(method.name_index as usize), ours.get(pc)));
                }
            }
            assert_eq!(ours.len(), block.len(), "{}.{}: instruction count", cf.name(), cf.utf8(method.name_index as usize));
        }
    }
    assert!(total > 500, "the fixture has its instructions ({total})");
    assert!(wrong.is_empty(), "{} of {total} differ:\n{}", wrong.len(), wrong.iter().take(20).cloned().collect::<Vec<_>>().join("\n"));
}

/* ---------------- constants as javap writes them ---------------- */

#[test]
fn double_to_string() {
    let values = [4.9e-324, 1e23, 1e7, 9999999.0, 0.001, 1e-3 / 2.0, 123456789.125, -0.0, 100.0, 0.1, 2.5e-5];
    let want = ["4.9E-324", "1.0E23", "1.0E7", "9999999.0", "0.001", "5.0E-4", "1.23456789125E8", "-0.0", "100.0", "0.1", "2.5E-5"];
    assert_eq!(values.map(java_double), want);
}

#[test]
// 1.28515625 is a float exactly, halfway between 1.2851562 and 1.2851563: Java takes the even one.
#[allow(clippy::excessive_precision)]
fn float_to_string() {
    // f32::from_bits(1) is Math.fround(1.4e-45), the smallest float.
    let values = [f32::from_bits(1), 0.1, 3.4e38, 1e-7, 1.28515625, 1e7, f32::NAN, f32::NEG_INFINITY];
    let want = ["1.4E-45", "0.1", "3.4E38", "1.0E-7", "1.2851562", "1.0E7", "NaN", "-Infinity"];
    assert_eq!(values.map(java_float), want);
}

#[test]
fn names_javap_quotes() {
    let names = ["java/lang/String", "<init>", "[I", "with space", "имя", "emoji😀", "a//b", "1st", "kebab-case", ""];
    let want = ["java/lang/String", "\"<init>\"", "\"[I\"", "\"with space\"", "имя", "\"emoji😀\"", "\"a//b\"", "\"1st\"", "\"kebab-case\"", "\"\""];
    assert_eq!(names.map(|n| check_name(Wtf8::new(n)).into_string().unwrap()), want);
    // A lone surrogate is no identifier's part: the name is quoted, the surrogate kept.
    let lone = Wtf8Buf::from_utf16(&[0x61, 0xd800]);
    assert_eq!(check_name(&lone).to_utf16(), [0x22, 0x61, 0xd800, 0x22]);
}

#[test]
fn string_escapes() {
    assert_eq!(escape_string(Wtf8::new("tab\t\"q\"'s\\ \u{1}\u{85} é")), "tab\\t\\\"q\\\"\\'s\\\\ \\u0001\\u0085 é");
}

#[test]
fn descriptors() {
    let types = method_types(Wtf8::new("([Ljava/lang/String;IJ)V"));
    assert_eq!(types.params, ["java.lang.String[]", "int", "long"]);
    assert_eq!(types.ret, "void");
    assert_eq!(field_type(Wtf8::new("[[D")), "double[][]");
    let kinds = descriptor_kinds(Wtf8::new("(IJLjava/lang/Object;[DF)Z"));
    assert_eq!((kinds.params.as_str(), kinds.ret), ("ilaaf", "i"));
    // JavaScript indexes a descriptor by UTF-16 unit: a character outside the BMP is two "types".
    let odd = method_types(Wtf8::new("(😀)V"));
    assert_eq!(odd.params.iter().map(|p| p.to_utf16()).collect::<Vec<_>>(), [vec![0xd83d], vec![0xde00]]);
}

#[test]
fn a_universal_mach_o_file_is_not_a_class_file() {
    assert!(!is_class_file(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2, 0, 0]));
}

/* ---------------- the archive and the analysis (the rest of tests/jvm.mjs) ---------------- */

#[test]
fn the_archive_and_the_analysis() {
    use disasm_core::disassembly::iflag;
    use disasm_core::jvm::program::{FnKind, JvmSession};
    let p = JvmSession::analyse(fixture("hello.jar")).unwrap();
    let names: Vec<String> = p.classes.iter().take(4).map(|c| c.name().to_string()).collect();
    assert_eq!(names, ["hello/Hello", "hello/Hello$Kind", "hello/Hello$Point", "hello/More"], "classes, sorted");
    assert_eq!(p.container.manifest_value("Main-Class"), Some("hello.Hello"), "the manifest");
    assert_eq!(p.version.0, 69, "Java 25");
    let fn_named = |name: &str| (0..p.functions.len()).find(|&f| p.function_name(f) == name).unwrap_or_else(|| panic!("no {name}"));
    let main = fn_named("hello.Hello::main");
    assert_eq!(p.entry, Some(main as u32), "the entry point");
    assert_eq!(p.functions[main].kind, FnKind::Entry);
    let with_code: usize = p.classes.iter().map(|c| c.methods.iter().filter(|m| m.code.as_ref().is_some_and(|c| c.length > 0)).count()).sum();
    assert_eq!(p.functions.len(), with_code, "every method with code is a function");
    let sum = fn_named("hello.Hello::sum");
    assert_eq!(p.function_full(sum), "static long hello.Hello.sum(int[], int)", "a declaration");
    assert_eq!(p.result.callers.get(p.functions[sum].addr as i64).len(), 1, "callers");
    let println =
        p.imported.iter().position(|m| m.owner == "java/io/PrintStream" && m.member == "println" && m.descriptor == "(Ljava/lang/String;)V").expect("println is an import");
    assert_eq!(p.import_full(println), "void java.io.PrintStream.println(java.lang.String)");
    assert!(p.result.callers.get(p.imported[println].addr as i64).len() >= 4, "calls to it are counted");
    assert!(!p.imported.iter().any(|m| m.owner.starts_with("hello/") && m.member == "sum"), "a method of a class here is not an import");
    let lambda = fn_named("hello.Hello::lambda$main$0");
    assert!(!p.result.data_refs.get(p.functions[lambda].addr as i64).is_empty(), "a lambda body is taken");
    let usage = p.strings.iter().position(|s| *s == "usage: hello [numbers...]").expect("the usage string");
    assert_eq!(p.result.data_refs.get(0x4000_0000 + usage as i64).len(), 1, "strings are counted once, used where ldc loads them");
    // Every function starts with its flag, every instruction has a mnemonic, none is left undecoded.
    for f in &p.functions {
        assert!(p.result.flags[f.first as usize] & iflag::FUNCTION != 0);
    }
    assert!(!p.result.mnemonics.contains(&".byte"), "no instruction left undecoded");
    let ranges: Vec<u32> = p.ranges.iter().take(3).map(|r| r.cls).collect();
    assert_eq!(ranges, [0, 1, 2], "ranges are classes");
    // HLA64 statements: `total += i64(values[i])` is one line of five instructions.
    let f = &p.functions[sum];
    let joined = (f.first..f.first + f.count).filter(|&i| p.result.flags[i as usize] & iflag::FUSE != 0).count();
    assert!(joined >= 4, "the statements of a loop are joined");
}

#[test]
fn not_java() {
    use disasm_core::jvm::program::{JvmSession, ReadError};
    assert!(matches!(JvmSession::open(b"not a class".to_vec(), true), Err(ReadError::NotJava)));
}
