use disasm_core::arm64::{decode, types::Op};
fn main() {
    let (mut name, mut text, mut imm, mut mn, mut ops) = (0, 0, 0, 0, 0);
    let mut worst = [String::new(), String::new(), String::new(), String::new()];
    let mut seed: u64 = 88172645463325252;
    for _ in 0..30_000_000u32 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let insn = decode(seed as u32, 0x100000000);
        if insn.m.len() > mn {
            mn = insn.m.len();
            worst[0] = insn.m.to_string();
        }
        ops = ops.max(insn.ops.len());
        for op in insn.ops.iter() {
            match op {
                Op::Reg(r) => {
                    if r.len() > name {
                        name = r.len();
                        worst[1] = r.to_string();
                    }
                }
                Op::Text(t) => {
                    if t.len() > text {
                        text = t.len();
                        worst[2] = t.to_string();
                    }
                }
                Op::Imm { t, .. } => {
                    if t.len() > imm {
                        imm = t.len();
                        worst[3] = t.to_string();
                    }
                }
                Op::Mem(m) => {
                    for n in [Some(&m.base), m.index.as_ref(), m.ext.as_ref(), m.post.as_ref()].into_iter().flatten() {
                        if n.len() > name {
                            name = n.len();
                            worst[1] = n.to_string();
                        }
                    }
                }
                Op::Shift { s, t, .. } => {
                    if s.len() > name {
                        name = s.len();
                        worst[1] = s.to_string();
                    }
                    if t.len() > text {
                        text = t.len();
                        worst[2] = t.to_string();
                    }
                }
                _ => {}
            }
        }
    }
    println!("mn {mn} name {name} text {text} imm {imm} ops {ops} {:?}", worst);
}
