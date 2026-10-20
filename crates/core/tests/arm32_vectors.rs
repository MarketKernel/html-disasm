//! The AArch32 decoder against tests/fixtures/arm32-vectors.json: thousands of
//! A32 and T32 instructions with the exact text llvm-objdump prints for them,
//! the same file the TypeScript decoder was checked against (tests/arm32.mjs),
//! and the structure behind a few: targets, IT blocks, flags, sizes.

use disasm_core::arm32::{decode_arm, decode_thumb, f, format_insn, is_wide, it_after, it_conditions, it_suffix, unknown, Insn};

#[test]
fn vectors_match_llvm_objdump() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/arm32-vectors.json");
    let json: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let vectors = json["vectors"].as_array().unwrap();
    let mut wrong = Vec::new();
    let (mut a32, mut t16, mut t32) = (0, 0, 0);
    for v in vectors {
        let encoding = v[0].as_str().unwrap();
        let value = u32::from_str_radix(encoding, 16).unwrap();
        let pc = i64::from_str_radix(v[1].as_str().unwrap(), 16).unwrap();
        let want = v[2].as_str().unwrap();
        let wide = v.get(3).is_some_and(|w| w.as_i64() == Some(1));
        let insn = if encoding.len() == 8 && !wide {
            a32 += 1;
            decode_arm(value, pc)
        } else if wide {
            t32 += 1;
            decode_thumb(value >> 16, value & 0xffff, pc, -1)
        } else {
            t16 += 1;
            decode_thumb(value, 0, pc, -1)
        };
        let got = format_insn(&insn);
        if got.as_str() != want {
            wrong.push(format!("{encoding} at {}: want {want:?}, got {:?}", v[1].as_str().unwrap(), got.as_str()));
        }
    }
    assert!(a32 > 0 && t16 > 0 && t32 > 0, "vectors cover A32, 16- and 32-bit T32");
    assert!(wrong.is_empty(), "{} of {} differ:\n{}", wrong.len(), vectors.len(), wrong.iter().take(40).cloned().collect::<Vec<_>>().join("\n"));
}

fn t16(hw: u32, pc: i64, it: i32) -> Insn {
    decode_thumb(hw, 0, pc, it)
}
fn t32(hw1: u32, hw2: u32, pc: i64) -> Insn {
    decode_thumb(hw1, hw2, pc, -1)
}
fn text(insn: &Insn) -> String {
    format_insn(insn).as_str().to_string()
}

#[test]
fn structure() {
    // Sizes.
    assert_eq!([t16(0x4770, 0x1000, -1).size, t32(0xf852, 0x3b04, 0x1000).size, decode_arm(0xe12fff1e, 0x1000).size], [2, 4, 4]);
    assert_eq!([is_wide(0xe800), is_wide(0xf000), is_wide(0xdfff)], [true, true, false]);

    // Branches: targets, conditions, and the instruction set at the other end.
    let bhi = t16(0xd804, 0x7a2, -1);
    assert_eq!((text(&bhi).as_str(), bhi.target, bhi.cond, bhi.f & f::COND != 0), ("bhi 0x7ae", Some(0x7ae), Some("hi"), true));
    let blx = t32(0xf000, 0xec34, 0x7c4);
    assert_eq!((blx.target, blx.thumb, blx.f & f::CALL != 0), (Some(0x1030), Some(false), true));
    assert_eq!(decode_arm(0xeafffff8, 0x738).target, Some(0x720));
    assert_eq!(decode_arm(0xebfffffe, 0x1030).thumb, Some(false));
    assert_eq!((t16(0xb108, 0x100, -1).target, t16(0xb108, 0x1000, -1).f & f::COND != 0), (Some(0x106), true));
    let ret = t16(0xbd80, 0x1000, -1);
    assert!(ret.f & f::RET != 0 && ret.f & f::LOAD != 0);
    assert!(t16(0x4770, 0x1000, -1).f & f::RET != 0);
    assert_eq!((text(&decode_arm(0x08bd8800, 0x1000)).as_str(), decode_arm(0x08bd8800, 0x1000).cond), ("popeq {r11, pc}", Some("eq")));

    // Literals: the address a PC-relative load reads.
    assert_eq!(t16(0x4904, 0x7a4, -1).target, Some(0x7b8));
    assert_eq!(decode_arm(0xe59f0008, 0x70c).target, Some(0x71c));
    assert_eq!(t16(0x4904, 0x1000, -1).bytes, 4);

    // IT blocks: the IT names the conditions, the instructions in it print and carry them.
    let itt = t16(0xbfbc, 0x782, -1);
    assert_eq!((text(&itt).as_str(), itt.it.as_deref()), ("itt lt", Some(&[11u8, 11][..])));
    assert_eq!(text(&t16(0x2000, 0x784, 11)), "movlt r0, #0x0");
    assert_eq!((text(&t16(0x4770, 0x786, 11)).as_str(), t16(0x4770, 0x786, 11).cond), ("bxlt lr", Some("lt")));
    assert_eq!(&*it_conditions(0, 0b0110), &[0, 0, 1]);
    assert_eq!(it_suffix(0, 0b0110).as_str(), "te");
    assert_eq!(&*it_after(&[1, 1], &itt, 0xbfbc), &[11, 11, 1]);
    assert_eq!(&*it_after(&[1, 1], &unknown(0xffffffff, 4, true), 0xffffffff), &[1, 1]);
    assert_eq!(&*it_after(&[1, 1], &t16(0x4770, 0x786, 1), 0x4770), &[1]);

    // Table branches, NEON, traps, unknown words.
    assert_eq!(text(&t32(0xe8df, 0xf012, 0x1000)), "tbh [pc, r2, lsl #1]");
    let vld1 = t32(0xf96e, 0x2a8d, 0x1000);
    assert_eq!((text(&vld1).as_str(), vld1.f & f::LOAD != 0), ("vld1.32 {d18, d19}, [lr]!", true));
    assert_eq!(text(&t32(0xeef8, 0x0bc0, 0x1000)), "vcvt.f64.s32 d16, s0");
    let trap = t16(0xdefe, 0x1000, -1);
    assert_eq!((text(&trap).as_str(), trap.f & f::TRAP != 0), ("trap", true));
    assert_eq!(text(&decode_arm(0xe7ffdefe, 0x1000)), "trap");
    let bad = decode_arm(0xffffffff, 0x1000);
    assert_eq!((bad.m.as_str(), bad.f & f::UNKNOWN != 0), (".inst", true));
}
