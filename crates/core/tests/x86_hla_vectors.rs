//! The x86 HLA64 lifter against tests/fixtures/x86-hla-vectors.json: what the
//! TypeScript lifter wrote for real x86-64 instructions, alone and as
//! setter/consumer pairs, with no names and with the made-up names of
//! tools/x86-hla-vectors.mjs (fake() here makes the same ones).

use disasm_core::lift::{DataAt, HlaLine, LiftContext, Target, TargetKind};
use disasm_core::x86::hla::{fuse_x86, lift_x86, Bare, X86Insn, X86LiftContext};
use serde_json::Value;

struct Fake;

impl LiftContext for Fake {
    fn target(&self, addr: i64) -> Option<Target> {
        match addr % 7 {
            0 => Some(Target { name: format!("f_{addr:x}"), kind: TargetKind::Function }),
            1 => Some(Target { name: format!("L{addr:x}"), kind: TargetKind::Label }),
            2 => Some(Target { name: format!("ns::g<{}>", addr % 5), kind: TargetKind::Import }),
            _ => None,
        }
    }
    fn data(&self, addr: i64) -> Option<DataAt> {
        match addr % 5 {
            0 => Some(DataAt::String { text: format!("s\"\\{}\n{}", addr % 97, "x".repeat((addr % 90) as usize)), objc: false }),
            1 => Some(DataAt::String { text: "objc".into(), objc: true }),
            2 => Some(DataAt::Symbol { name: format!("sym_{}", addr % 11) }),
            _ => None,
        }
    }
    fn function_start(&self, pc: i64) -> i64 {
        pc - pc % 64
    }
}

impl X86LiftContext for Fake {
    fn import_at(&self, addr: i64) -> Option<String> {
        (addr % 3 == 0).then(|| format!("imp_{}", addr % 13))
    }
}

fn insn(v: &Value) -> X86Insn {
    X86Insn {
        prefix: v["prefix"].as_str().unwrap().into(),
        m: v["m"].as_str().unwrap().into(),
        ops: v["ops"].as_str().unwrap().into(),
        addr: v["addr"].as_f64().unwrap() as i64,
        length: v["length"].as_u64().unwrap() as u32,
        f: v["f"].as_u64().unwrap() as u32,
        target: v["target"].as_f64().map(|t| t as i64),
        mem: v["mem"].as_f64().map(|t| t as i64),
    }
}

fn line(l: &HlaLine) -> Value {
    serde_json::json!({ "text": l.text, "words": l.words })
}

#[test]
fn lines_match_the_typescript_lifter() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/x86-hla-vectors.json");
    let json: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut wrong = Vec::new();
    let vectors = json["vectors"].as_array().unwrap();
    for v in vectors {
        let (a, b) = (insn(&v["a"]), insn(&v["b"]));
        let text = |l: &Value| serde_json::json!({ "text": l["text"], "words": l["words"] });
        let checks: [(&str, Value, Value); 4] = [
            ("bare", line(&lift_x86(&a, &Bare)), text(&v["bare"])),
            ("named", line(&lift_x86(&a, &Fake)), text(&v["named"])),
            ("fuseBare", fuse_x86(&a, &b, &Bare).map_or(Value::Null, |l| line(&l)), if v["fuseBare"].is_null() { Value::Null } else { text(&v["fuseBare"]) }),
            ("fuseNamed", fuse_x86(&a, &b, &Fake).map_or(Value::Null, |l| line(&l)), if v["fuseNamed"].is_null() { Value::Null } else { text(&v["fuseNamed"]) }),
        ];
        for (what, got, want) in checks {
            if got != want {
                wrong.push(format!("{what}: {} {} | {} {}\n  want {want}\n  got  {got}", a.m, a.ops, b.m, b.ops));
            }
        }
    }
    assert!(wrong.is_empty(), "{} of {} differ:\n{}", wrong.len(), vectors.len() * 4, wrong.iter().take(25).cloned().collect::<Vec<_>>().join("\n"));
}

/// A 64-bit immediate becomes a JavaScript number as parseInt reads it: rounded once, to nearest.
#[test]
fn wide_immediates_round_once() {
    let line = |ops: &str| lift_x86(&X86Insn { m: "movabs".into(), ops: ops.into(), length: 10, ..Default::default() }, &Bare).text;
    assert_eq!(line("rax, 0x646165725f633412"), "rax = 0x646165725f633400");
    assert_eq!(line("rax, 0x646165725f6334ff"), "rax = 0x646165725f633400");
    assert_eq!(line("rax, 0x646165725f633c00"), "rax = 0x646165725f633c00");
}
