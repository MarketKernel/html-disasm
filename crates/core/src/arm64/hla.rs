//! The HLA64 view: decoded instructions written as HLA64.
//!
//! HLA64 is an assembler with sugar, not a separate language, so this is not
//! decompilation: each line still stands for the instruction (or the two) at
//! its address. Where HLA64 has a word for what an instruction does —
//! `x0 = [x1 + 8]`, `if x8 == 0 { goto L… }`, `push x29, x30`, `f()` — the
//! line uses it; where it has none (SIMD, exclusives, system registers) the
//! instruction stays as it is, which HLA64 accepts too.
//!
//! Two kinds of neighbours read better as one line, and fuse() joins them: a
//! compare and the branch or select that tests its flags, and the adrp + add
//! (or load) that together build an address.
//!
//! Each line lists the words of src/data/hla64-words.json it uses, so the
//! page can explain them; words marked "new" there are this project's
//! additions to HLA64.
//!
//! Lines are built on the heap: only the rows on screen are lifted, and the
//! analysis asks fuse() only about a compare followed by its consumer.

use super::types::{f, format_insn, Insn, Mem, Mode, Op};
pub use crate::lift::{escape_json_char, hla_name, num, quoted, unique, DataAt, HlaLine, LiftContext, NoContext, Target, TargetKind, Words};
use crate::text::{js_hex, js_number};

fn imm_value(op: Option<&Op>) -> f64 {
    match op {
        Some(Op::Imm { v, .. }) => *v,
        _ => f64::NAN,
    }
}

/// An immediate operand as HLA64 writes it (64-bit ones keep LLVM's exact text).
fn imm_of(op: &Op) -> String {
    let Op::Imm { v, t } = op else { return "?".into() };
    if v.abs() >= 2f64.powi(53) || !v.is_finite() || v.fract() != 0.0 {
        return t.strip_prefix('#').unwrap_or(t).to_string();
    }
    num(*v)
}

fn is_zr(r: &str) -> bool {
    r == "xzr" || r == "wzr"
}

fn val(op: Option<&Op>) -> String {
    match op {
        None => "?".into(),
        Some(Op::Reg(r)) => {
            if is_zr(r) {
                "0".into()
            } else {
                r.to_string()
            }
        }
        Some(op @ Op::Imm { .. }) => imm_of(op),
        Some(Op::Text(t)) => t.to_string(),
        Some(_) => "?".into(),
    }
}

fn reg_of(op: Option<&Op>) -> Option<&str> {
    match op {
        Some(Op::Reg(r)) => Some(r.as_str()),
        _ => None,
    }
}

fn same_reg(a: Option<&Op>, b: Option<&Op>) -> bool {
    match (reg_of(a), reg_of(b)) {
        (Some(a), Some(b)) => same_reg_name(a, b),
        _ => false,
    }
}

/// `reg_no(a) == reg_no(b)`, without building either.
fn same_reg_name(a: &str, b: &str) -> bool {
    reg_key(a) == reg_key(b)
}

fn reg_key(r: &str) -> (u8, &str) {
    if r == "sp" || r == "wsp" {
        return (b's', "p");
    }
    match r.as_bytes().first() {
        Some(b'x') | Some(b'w') => (b'r', &r[1..]),
        Some(&c) => (c, &r[1..]),
        None => (0, ""),
    }
}

fn extend_fn(name: &str) -> Option<&'static str> {
    Some(match name {
        "uxtb" => "zext8",
        "uxth" => "zext16",
        "uxtw" => "zext32",
        "sxtb" => "sext8",
        "sxth" => "sext16",
        "sxtw" => "sext32",
        _ => return None,
    })
}

/// The second operand of an arithmetic instruction with its optional shift or extension.
fn operand2(ops: &[Op], words: &mut Words) -> String {
    let Some(value) = ops.first() else { return "?".into() };
    let mut text = val(Some(value));
    let Some(modifier) = ops.get(1) else { return text };
    match modifier {
        Op::Shift { s, amount, .. } => {
            if let Op::Imm { v, .. } = value {
                return num(v * 2f64.powf(*amount as f64));
            }
            if let Some(ext) = extend_fn(s) {
                words.push("extend");
                text = format!("{ext}({text})");
                return if *amount != 0 { format!("({text} << {amount})") } else { text };
            }
            if s.as_str() == "uxtx" || s.as_str() == "sxtx" {
                return if *amount != 0 { format!("({text} << {amount})") } else { text };
            }
            words.push("shift");
            let op = match s.as_str() {
                "lsl" => "<<",
                "lsr" => ">>>",
                "asr" => ">>",
                _ => {
                    words.push("ror");
                    return format!("ror({text}, {amount})");
                }
            };
            format!("({text} {op} {amount})")
        }
        Op::Text(t) => {
            if let Some(ext) = extend_fn(t) {
                words.push("extend");
                return format!("{ext}({text})");
            }
            text
        }
        _ => text,
    }
}

/// `d = a op b`, or `d op= b` when d is a.
fn binary(d: Option<&Op>, a: &str, op: &str, b: &str, words: &mut Words) -> String {
    let dest = val(d);
    words.push("arith");
    if dest == a && dest != "0" {
        words.push("compound");
        return format!("{dest} {op}= {b}");
    }
    format!("{dest} = {a} {op} {b}")
}

/// The address of a memory operand as an HLA64 expression (without brackets).
fn address(op: &Mem, words: &mut Words) -> String {
    if let Some(index) = &op.index {
        let scale = if op.show_amount && op.amount.unwrap_or(0) != 0 { 2f64.powf(op.amount.unwrap_or(0) as f64) } else { 1.0 };
        let mut index = index.to_string();
        if let Some(ext) = op.ext.as_ref().and_then(|e| extend_fn(e)) {
            words.push("extend");
            index = format!("{ext}({index})");
        }
        return if scale == 1.0 { format!("{} + {}", op.base, index) } else { format!("{} + {} * {}", op.base, index, js_number(scale)) };
    }
    if op.mode == Mode::Post || op.off == 0 {
        return op.base.to_string();
    }
    if op.off < 0 {
        format!("{} - {}", op.base, num(-op.off as f64))
    } else {
        format!("{} + {}", op.base, num(op.off as f64))
    }
}

/// The type prefix of a load or store: '' when the register's width says it all.
fn mem_type(insn: &Insn, r: &str) -> Option<String> {
    let size = if insn.size == 0 { 8 } else { insn.size as u32 };
    let b = r.as_bytes();
    let fp = b.len() >= 2 && b"bhsdq".contains(&b[0]) && b[1].is_ascii_digit();
    if fp {
        return match b[0] {
            b'd' => Some("f64".into()),
            b's' => Some("f32".into()),
            _ => None,
        };
    }
    if size == 8 || (size == 4 && b.first() == Some(&b'w') && !insn.signed) {
        return Some(String::new());
    }
    Some(format!("{}{}", if insn.signed { "i" } else { "u" }, size * 8))
}

fn step(m: &Mem) -> String {
    if m.off < 0 {
        format!("{} -= {}", m.base, num(-m.off as f64))
    } else {
        format!("{} += {}", m.base, num(m.off as f64))
    }
}

fn load_store(insn: &Insn, words: &mut Words) -> Option<String> {
    let (Some(Op::Reg(rt)), Some(Op::Mem(mem))) = (insn.ops.first(), insn.ops.get(1)) else { return None };
    let ty = mem_type(insn, rt)?;
    let load = insn.f & f::LOAD != 0;
    words.push(if ty.is_empty() { "memory" } else { "typed-memory" });
    let value = if is_zr(rt) { "0".to_string() } else { rt.to_string() };
    let access = |addr: &str| format!("{ty}[{addr}]");
    if mem.mode == Mode::Pre {
        words.push("compound");
        let st = step(mem);
        return Some(if load { format!("{st}; {} = {}", rt, access(&mem.base)) } else { format!("{st}; {} = {value}", access(&mem.base)) });
    }
    if mem.mode == Mode::Post {
        let size = if insn.size == 0 { 8 } else { insn.size as i64 };
        if mem.off == size {
            words.push("post-increment");
            let at = access(&format!("{}++", mem.base));
            return Some(if load { format!("{rt} = {at}") } else { format!("{at} = {value}") });
        }
        words.push("compound");
        let st = step(mem);
        return Some(if load { format!("{} = {}; {st}", rt, access(&mem.base)) } else { format!("{} = {value}; {st}", access(&mem.base)) });
    }
    let addr = address(mem, words);
    Some(if load { format!("{} = {}", rt, access(&addr)) } else { format!("{} = {value}", access(&addr)) })
}

fn pair(insn: &Insn, words: &mut Words) -> Option<String> {
    let (Some(a @ Op::Reg(ar)), Some(b @ Op::Reg(br)), Some(Op::Mem(mem))) = (insn.ops.first(), insn.ops.get(1), insn.ops.get(2)) else { return None };
    let load = insn.m == "ldp";
    if insn.m != "ldp" && insn.m != "stp" {
        return None;
    }
    let ty = match ar.as_bytes().first() {
        Some(b'x') => "u64",
        Some(b'w') => "u32",
        Some(b'd') => "f64",
        Some(b's') => "f32",
        _ => return None,
    };
    let size: i64 = if ty.ends_with("64") { 8 } else { 4 };
    if ty == "u64" && mem.base == "sp" && size == 8 {
        if !load && mem.mode == Mode::Pre && mem.off == -16 {
            words.push("push-pop");
            return Some(format!("push {ar}, {br}"));
        }
        if load && mem.mode == Mode::Post && mem.off == 16 {
            words.push("push-pop");
            return Some(format!("pop {ar}, {br}"));
        }
    }
    words.push("pair");
    let regs = format!("({}, {})", val(Some(a)), val(Some(b)));
    let base = &mem.base;
    if mem.mode == Mode::Post {
        if mem.off == 2 * size {
            return Some(if load { format!("{regs} = {ty}[{base}++]") } else { format!("{ty}[{base}++] = {regs}") });
        }
        if mem.off == -2 * size {
            return Some(if load { format!("{regs} = {ty}[{base}--]") } else { format!("{ty}[{base}--] = {regs}") });
        }
        words.push("compound");
        let st = step(mem);
        return Some(if load { format!("{regs} = {ty}[{base}]; {st}") } else { format!("{ty}[{base}] = {regs}; {st}") });
    }
    let addr = if mem.off != 0 { format!("{base} {} {}", if mem.off < 0 { '-' } else { '+' }, num(mem.off.unsigned_abs() as f64)) } else { base.to_string() };
    let bang = if mem.mode == Mode::Pre { "!" } else { "" };
    Some(if load { format!("{regs} = {ty}[{addr}]{bang}") } else { format!("{ty}[{addr}]{bang} = {regs}") })
}

/// The memory order an atomic's suffix names: `al`, `a`, `l` or none.
fn order(suffix: &str) -> &'static str {
    match suffix {
        "al" => "acq_rel",
        "a" => "acquire",
        "l" => "release",
        _ => "relaxed",
    }
}

fn atomic_name(op: &str) -> &'static str {
    match op {
        "add" => "atomic_add",
        "clr" => "atomic_clr",
        "eor" => "atomic_eor",
        "set" => "atomic_or",
        "smax" => "atomic_smax",
        "smin" => "atomic_smin",
        "umax" => "atomic_umax",
        _ => "atomic_umin",
    }
}

fn atomic_type(m: &str, r: &str) -> &'static str {
    if m.ends_with('b') && !m.ends_with("sb") {
        "u8"
    } else if m.ends_with('h') {
        "u16"
    } else if r.starts_with('x') {
        "u64"
    } else {
        "u32"
    }
}

const ATOMIC_OPS: [&str; 8] = ["add", "clr", "eor", "set", "smax", "smin", "umax", "umin"];

/// Matches `prefix` + one of `ops` + one of `orders` (or none) + `b`/`h` (or none), the whole mnemonic.
fn split<'a>(m: &'a str, prefix: &str, ops: &[&'static str], orders: &[&'static str]) -> Option<(&'static str, &'a str, &'a str)> {
    let rest = m.strip_prefix(prefix)?;
    for op in ops {
        let Some(after) = rest.strip_prefix(op) else { continue };
        let (body, size) = match after.as_bytes().last() {
            Some(b'b') | Some(b'h') => (&after[..after.len() - 1], &after[after.len() - 1..]),
            _ => (after, ""),
        };
        if body.is_empty() || orders.contains(&body) {
            return Some((op, body, size));
        }
        // `b`/`h` may also be the whole of what follows the op with no order: handled above. An order ending in neither is checked as is.
        if orders.contains(&after) {
            return Some((op, after, ""));
        }
    }
    None
}

fn atomic(insn: &Insn, words: &mut Words) -> Option<String> {
    let m = insn.m.as_str();
    let ops = &insn.ops;
    if let Some((op, ord, _)) = split(m, "ld", &ATOMIC_OPS, &["a", "al", "l"]) {
        let (Some(s @ Op::Reg(sr)), Some(Op::Reg(tr)), Some(Op::Mem(mem))) = (ops.first(), ops.get(1), ops.get(2)) else { return None };
        words.push("atomic");
        let call = format!("{}({}[{}], {}, {})", atomic_name(op), atomic_type(m, sr), mem.base, val(Some(s)), order(ord));
        return Some(if is_zr(tr) { call } else { format!("{tr} = {call}") });
    }
    if let Some((op, ord, _)) = split(m, "st", &ATOMIC_OPS, &["l"]) {
        let (Some(s @ Op::Reg(sr)), Some(Op::Mem(mem))) = (ops.first(), ops.get(1)) else { return None };
        words.push("atomic");
        return Some(format!("{}({}[{}], {}, {})", atomic_name(op), atomic_type(m, sr), mem.base, val(Some(s)), if ord.is_empty() { "relaxed" } else { "release" }));
    }
    if let Some((_, ord, _)) = split(m, "", &["swp"], &["a", "al", "l"]) {
        let (Some(s @ Op::Reg(sr)), Some(Op::Reg(tr)), Some(Op::Mem(mem))) = (ops.first(), ops.get(1), ops.get(2)) else { return None };
        words.push("atomic");
        let call = format!("atomic_swap({}[{}], {}, {})", atomic_type(m, sr), mem.base, val(Some(s)), order(ord));
        return Some(if is_zr(tr) { call } else { format!("{tr} = {call}") });
    }
    if let Some((_, ord, _)) = split(m, "", &["cas"], &["a", "al", "l"]) {
        let (Some(s @ Op::Reg(sr)), Some(t @ Op::Reg(_)), Some(Op::Mem(mem))) = (ops.first(), ops.get(1), ops.get(2)) else { return None };
        words.push("cas");
        return Some(format!("{sr} = cas({}[{}], {}, {}, {})", atomic_type(m, sr), mem.base, val(Some(s)), val(Some(t)), order(ord)));
    }
    // Only the plain forms: not the writeback ones of FEAT_LRCPC3, nor its SIMD&FP registers.
    if split(m, "", &["ldar", "ldapr", "ldapur"], &[]).is_some_and(|(op, _, _)| strip_size(m) == op) {
        let (Some(Op::Reg(tr)), Some(Op::Mem(mem))) = (ops.first(), ops.get(1)) else { return None };
        if mem.mode != Mode::Off || !is_gpr(tr) {
            return None;
        }
        words.push("atomic-load-store");
        let addr = if mem.off != 0 { address(mem, words) } else { mem.base.to_string() };
        return Some(format!("{tr} = load_acquire({}[{addr}])", atomic_type(m, tr)));
    }
    if split(m, "", &["stlr", "stlur"], &[]).is_some_and(|(op, _, _)| strip_size(m) == op) {
        let (Some(t @ Op::Reg(tr)), Some(Op::Mem(mem))) = (ops.first(), ops.get(1)) else { return None };
        if mem.mode != Mode::Off || !is_gpr(tr) {
            return None;
        }
        words.push("atomic-load-store");
        let addr = if mem.off != 0 { address(mem, words) } else { mem.base.to_string() };
        return Some(format!("store_release({}[{addr}], {})", atomic_type(m, tr), val(Some(t))));
    }
    None
}

/// The mnemonic without a final `b` or `h`.
fn strip_size(m: &str) -> &str {
    m.strip_suffix('b').or_else(|| m.strip_suffix('h')).unwrap_or(m)
}

/// `^(ldar|ldapr|ldapur|stlr|stlur)[bh]?$`
fn is_acquire_release(m: &str) -> bool {
    matches!(strip_size(m), "ldar" | "ldapr" | "ldapur" | "stlr" | "stlur")
}

fn branch_target(insn: &Insn, ctx: &dyn LiftContext, words: &mut Words) -> String {
    let addr = insn.target.unwrap_or(0);
    match ctx.target(addr) {
        None => num(addr as f64),
        Some(t) if t.kind == TargetKind::Label => t.name,
        Some(t) => hla_name(&t.name, words),
    }
}

/// `^(?:[xw](?:[12]?\d|3[01])|sp|wsp|xzr|wzr)$`: general-purpose registers, the only ones integer sugar may name.
pub fn is_gpr(r: &str) -> bool {
    match r {
        "sp" | "wsp" | "xzr" | "wzr" => true,
        _ => matches!(r.as_bytes().first(), Some(b'x') | Some(b'w')) && reg_number(&r[1..]),
    }
}

/// `[12]?\d|3[01]`: 0 to 31, written without a leading zero beyond `0`…`9`.
fn reg_number(n: &str) -> bool {
    let b = n.as_bytes();
    match b.len() {
        1 => b[0].is_ascii_digit(),
        2 => (b[0] == b'1' || b[0] == b'2') && b[1].is_ascii_digit() || b[0] == b'3' && (b[1] == b'0' || b[1] == b'1'),
        _ => false,
    }
}

/// `^[hsd](?:[12]?\d|3[01])$`: scalar floating-point registers.
fn is_fpr(r: &str) -> bool {
    matches!(r.as_bytes().first(), Some(b'h') | Some(b's') | Some(b'd')) && reg_number(&r[1..])
}

fn is_integer(m: &str) -> bool {
    matches!(
        m,
        "add"
            | "sub"
            | "adds"
            | "subs"
            | "ands"
            | "bics"
            | "neg"
            | "negs"
            | "mvn"
            | "and"
            | "orr"
            | "eor"
            | "bic"
            | "orn"
            | "eon"
            | "lsl"
            | "lsr"
            | "asr"
            | "ror"
            | "mul"
            | "madd"
            | "msub"
            | "mneg"
            | "smull"
            | "umull"
            | "smaddl"
            | "umaddl"
            | "smsubl"
            | "umsubl"
            | "smnegl"
            | "umnegl"
            | "umulh"
            | "smulh"
            | "sdiv"
            | "udiv"
            | "sxtb"
            | "sxth"
            | "sxtw"
            | "uxtb"
            | "uxth"
            | "clz"
            | "rbit"
            | "rev"
            | "rev16"
            | "rev32"
            | "cls"
            | "ctz"
            | "cnt"
            | "ubfx"
            | "ubfiz"
            | "sbfx"
            | "sbfiz"
    )
}

fn is_float_op(m: &str) -> bool {
    matches!(m, "fadd" | "fsub" | "fmul" | "fdiv" | "fnmul" | "fmadd" | "fmsub" | "fnmadd" | "fnmsub" | "fneg" | "fabs" | "fsqrt" | "fmin" | "fmax" | "fminnm" | "fmaxnm" | "fcvt")
}

fn is_vector(op: Option<&Op>) -> bool {
    matches!(op, Some(Op::Reg(r)) if r.starts_with('v'))
}

fn lift(insn: &Insn, pc: i64, ctx: &dyn LiftContext, words: &mut Words) -> Option<String> {
    let m = insn.m.as_str();
    let ops = &insn.ops;
    let (d, a, b) = (ops.first(), ops.get(1), ops.get(2));
    let regs = || ops.iter().filter_map(|op| if let Op::Reg(r) = op { Some(r.as_str()) } else { None });
    if is_integer(m) && !regs().all(is_gpr) {
        return None;
    }
    if is_float_op(m) && !regs().all(is_fpr) {
        return None;
    }
    if ops.iter().any(|op| matches!(op, Op::Text(t) if t.starts_with('{'))) {
        return None;
    }
    let tail = |from: usize| &ops[from.min(ops.len())..];
    match m {
        "mov" => {
            if is_vector(d) || is_vector(a) {
                return None;
            }
            words.push("assign");
            return Some(format!("{} = {}", val(d), val(a)));
        }
        "movz" | "movn" => return None,
        "add" | "sub" => {
            if !matches!(d, Some(Op::Reg(_))) || !matches!(a, Some(Op::Reg(_))) {
                return None;
            }
            let second = operand2(tail(2), words);
            return Some(binary(d, &val(a), if m == "add" { "+" } else { "-" }, &second, words));
        }
        "adds" | "subs" | "ands" | "bics" => {
            let second = operand2(tail(2), words);
            let op = match m {
                "adds" => "+",
                "subs" => "-",
                "ands" => "&",
                _ => "& ~",
            };
            return Some(binary(d, &val(a), op, &second, words));
        }
        "neg" | "negs" => {
            words.push("arith");
            let rest = operand2(tail(1), words);
            return Some(format!("{} = -{}", val(d), rest));
        }
        "mvn" => {
            words.push("arith");
            let rest = operand2(tail(1), words);
            return Some(format!("{} = ~{}", val(d), rest));
        }
        "and" | "orr" | "eor" => {
            if is_vector(d) {
                return None;
            }
            let op = match m {
                "and" => "&",
                "orr" => "|",
                _ => "^",
            };
            let second = operand2(tail(2), words);
            return Some(binary(d, &val(a), op, &second, words));
        }
        "bic" | "orn" | "eon" => {
            if is_vector(d) {
                return None;
            }
            words.push("arith");
            let op = match m {
                "bic" => "&",
                "orn" => "|",
                _ => "^",
            };
            let second = operand2(tail(2), words);
            return Some(format!("{} = {} {op} ~{}", val(d), val(a), second));
        }
        "lsl" | "lsr" | "asr" => {
            words.push("shift");
            let op = match m {
                "lsl" => "<<",
                "lsr" => ">>>",
                _ => ">>",
            };
            return Some(binary(d, &val(a), op, &val(b), words));
        }
        "ror" => {
            words.push("ror");
            return Some(format!("{} = ror({}, {})", val(d), val(a), val(b)));
        }
        "mul" => {
            if is_vector(d) {
                return None;
            }
            return Some(binary(d, &val(a), "*", &val(b), words));
        }
        "madd" | "msub" => {
            words.push("arith");
            return Some(format!("{} = {} {} {} * {}", val(d), val(ops.get(3)), if m == "madd" { "+" } else { "-" }, val(a), val(b)));
        }
        "mneg" => {
            words.push("arith");
            return Some(format!("{} = -({} * {})", val(d), val(a), val(b)));
        }
        "smull" | "umull" | "smaddl" | "umaddl" | "smsubl" | "umsubl" | "smnegl" | "umnegl" => {
            if is_vector(d) {
                return None;
            }
            words.push("widening-multiply");
            words.push("extend");
            let ext = if m.starts_with('s') { "sext32" } else { "zext32" };
            let product = format!("{ext}({}) * {ext}({})", val(a), val(b));
            if m.ends_with("mull") {
                return Some(format!("{} = {product}", val(d)));
            }
            if m.ends_with("negl") {
                return Some(format!("{} = -({product})", val(d)));
            }
            return Some(format!("{} = {} {} {product}", val(d), val(ops.get(3)), if m.contains("add") { "+" } else { "-" }));
        }
        "umulh" | "smulh" => {
            words.push("mul-high");
            return Some(format!("{} = {m}({}, {})", val(d), val(a), val(b)));
        }
        "sdiv" => return Some(binary(d, &val(a), "/", &val(b), words)),
        "udiv" => {
            words.push("udiv");
            return Some(format!("{} = udiv({}, {})", val(d), val(a), val(b)));
        }
        "sxtb" | "sxth" | "sxtw" | "uxtb" | "uxth" => {
            words.push("extend");
            return Some(format!("{} = {}({})", val(d), extend_fn(m).unwrap_or(""), val(a)));
        }
        "clz" | "rbit" | "rev" => {
            if is_vector(d) {
                return None;
            }
            words.push("builtin");
            return Some(format!("{} = {m}({})", val(d), val(a)));
        }
        "rev16" | "rev32" | "cls" | "ctz" | "cnt" => {
            if is_vector(d) {
                return None;
            }
            words.push("bit-builtins");
            return Some(format!("{} = {}({})", val(d), if m == "cnt" { "popcount" } else { m }, val(a)));
        }
        "ubfx" => {
            let lsb = imm_value(b);
            let width = imm_value(ops.get(3));
            let reg_width = if val(d).starts_with('w') { 32.0 } else { 64.0 };
            words.push("shift");
            words.push("arith");
            let mask = num(2f64.powf(width) - 1.0);
            if lsb == 0.0 {
                return Some(format!("{} = {} & {mask}", val(d), val(a)));
            }
            if lsb + width == reg_width {
                return Some(format!("{} = {} >>> {}", val(d), val(a), js_number(lsb)));
            }
            return Some(format!("{} = ({} >>> {}) & {mask}", val(d), val(a), js_number(lsb)));
        }
        "ubfiz" => {
            let lsb = imm_value(b);
            let width = imm_value(ops.get(3));
            words.push("shift");
            words.push("arith");
            return Some(format!("{} = ({} & {}) << {}", val(d), val(a), num(2f64.powf(width) - 1.0), js_number(lsb)));
        }
        "sbfx" => {
            words.push("bits");
            return Some(format!("{} = sbits({}, {}, {})", val(d), val(a), val(b), val(ops.get(3))));
        }
        "sbfiz" => {
            words.push("bits");
            words.push("shift");
            return Some(format!("{} = sbits({}, 0, {}) << {}", val(d), val(a), val(ops.get(3)), val(b)));
        }
        "b" => {
            let target = insn.target.unwrap_or(0);
            if let Some(t) = ctx.target(target) {
                if t.kind != TargetKind::Label && target != ctx.function_start(pc) {
                    words.push("tail-call");
                    return Some(format!("return {}()", hla_name(&t.name, words)));
                }
            }
            words.push("goto");
            return Some(format!("goto {}", branch_target(insn, ctx, words)));
        }
        "bl" => {
            words.push("call");
            return Some(format!("{}()", branch_target(insn, ctx, words)));
        }
        "blr" => {
            words.push("call");
            return Some(format!("{}()", val(d)));
        }
        "br" => {
            words.push("jump-table");
            return Some(format!("goto [{}]", val(d)));
        }
        "ret" => {
            words.push("return");
            return if ops.is_empty() { Some("return".into()) } else { None };
        }
        "cbz" | "cbnz" => {
            words.push("if-goto");
            let target = branch_target(insn, ctx, words);
            return Some(format!("if {} {} 0 {{ goto {target} }}", val(d), if m == "cbz" { "==" } else { "!=" }));
        }
        "tbz" | "tbnz" => {
            words.push("if-goto");
            let bit_no = imm_value(a);
            let r = val(d);
            let top = if r.starts_with('w') { 31.0 } else { 63.0 };
            let goto = format!("goto {}", branch_target(insn, ctx, words));
            if bit_no == top {
                return Some(format!("if {r} {} 0 {{ {goto} }}", if m == "tbz" { ">=" } else { "<" }));
            }
            return Some(format!("if {r} & {} {} 0 {{ {goto} }}", num(2f64.powf(bit_no)), if m == "tbz" { "==" } else { "!=" }));
        }
        "brk" | "udf" => {
            words.push("trap");
            return Some(format!("trap({})", val(d)));
        }
        "fadd" | "fsub" | "fmul" | "fdiv" => {
            if !matches!(d, Some(Op::Reg(_))) || is_vector(d) {
                return None;
            }
            words.push("float");
            let op = match m {
                "fadd" => "+",
                "fsub" => "-",
                "fmul" => "*",
                _ => "/",
            };
            return Some(binary(d, &val(a), op, &val(b), words));
        }
        "fnmul" => {
            if !matches!(d, Some(Op::Reg(_))) || is_vector(d) {
                return None;
            }
            words.push("float");
            return Some(format!("{} = -({} * {})", val(d), val(a), val(b)));
        }
        "fmadd" | "fmsub" | "fnmadd" | "fnmsub" => {
            words.push("float");
            let product = format!("{} * {}", val(a), val(b));
            let acc = val(ops.get(3));
            let text = match m {
                "fmadd" => format!("{acc} + {product}"),
                "fmsub" => format!("{acc} - {product}"),
                "fnmadd" => format!("-{acc} - {product}"),
                _ => format!("{product} - {acc}"),
            };
            return Some(format!("{} = {text}", val(d)));
        }
        "fneg" | "fabs" | "fsqrt" => {
            if !matches!(d, Some(Op::Reg(_))) || is_vector(d) {
                return None;
            }
            words.push("float");
            if m == "fneg" {
                return Some(format!("{} = -{}", val(d), val(a)));
            }
            return Some(format!("{} = {}({})", val(d), if m == "fabs" { "fabs" } else { "sqrt" }, val(a)));
        }
        "fmin" | "fmax" | "fminnm" | "fmaxnm" => {
            if !matches!(d, Some(Op::Reg(_))) || is_vector(d) {
                return None;
            }
            words.push("float-extra");
            return Some(format!("{} = {}({}, {})", val(d), &m[..4], val(a), val(b)));
        }
        "scvtf" | "ucvtf" => {
            let (Some(Op::Reg(dr)), Some(Op::Reg(ar))) = (d, a) else { return None };
            if !is_fpr(dr) || !is_gpr(ar) || ops.len() > 2 {
                return None;
            }
            words.push(if m == "scvtf" { "float" } else { "float-extra" });
            return Some(format!("{} = {}({})", val(d), if m == "scvtf" { "float" } else { "ufloat" }, val(a)));
        }
        "fcvtzs" | "fcvtzu" => {
            let (Some(Op::Reg(dr)), Some(Op::Reg(ar))) = (d, a) else { return None };
            if !is_gpr(dr) || !is_fpr(ar) || ops.len() > 2 {
                return None;
            }
            words.push(if m == "fcvtzs" { "float" } else { "float-extra" });
            return Some(format!("{} = {}({})", val(d), if m == "fcvtzs" { "int" } else { "uint" }, val(a)));
        }
        "fcvt" => {
            let Some(Op::Reg(dr)) = d else { return None };
            if !dr.starts_with('d') && !dr.starts_with('s') {
                return None;
            }
            words.push("float-extra");
            return Some(format!("{} = {}({})", val(d), if dr.starts_with('d') { "f64" } else { "f32" }, val(a)));
        }
        "fmov" => {
            let Some(Op::Reg(dr)) = d else { return None };
            let a_op = a?;
            if dr.starts_with('v') || is_vector(Some(a_op)) {
                return None;
            }
            if let Op::Imm { v, .. } = a_op {
                words.push("float");
                let s = js_number(*v);
                return Some(format!("{} = {}", val(d), if s.contains('.') { s } else { format!("{v:.1}") }));
            }
            let fp = |r: &str| matches!(r.as_bytes(), [b'h' | b's' | b'd', c, ..] if c.is_ascii_digit());
            if let Op::Reg(ar) = a_op {
                if fp(dr) != fp(ar) {
                    words.push("float-extra");
                    return Some(format!("{} = bitcast({})", val(d), val(a)));
                }
            }
            words.push("assign");
            return Some(format!("{} = {}", val(d), val(a)));
        }
        _ => {}
    }
    if insn.f & f::ATOMIC != 0 || is_acquire_release(m) {
        return atomic(insn, words);
    }
    if m == "ldp" || m == "stp" {
        return pair(insn, words);
    }
    if is_plain_load_store(m) && matches!(ops.first(), Some(Op::Reg(_))) {
        return if matches!(ops.get(1), Some(Op::Mem(_))) { load_store(insn, words) } else { None };
    }
    None
}

/// `^(ldr|ldur|str|stur)(b|h|sb|sh|sw)?$`
fn is_plain_load_store(m: &str) -> bool {
    for base in ["ldr", "ldur", "str", "stur"] {
        if let Some(rest) = m.strip_prefix(base) {
            if matches!(rest, "" | "b" | "h" | "sb" | "sh" | "sw") {
                return true;
            }
        }
    }
    false
}

/// One instruction as an HLA64 line; the instruction itself when HLA64 has no better word.
pub fn lift_one(insn: &Insn, pc: i64, ctx: &dyn LiftContext) -> HlaLine {
    let mut words = Vec::new();
    match lift(insn, pc, ctx, &mut words) {
        Some(text) => HlaLine { text, words: unique(words), comment: None },
        None => HlaLine { text: raw_instruction(insn, ctx), words: vec!["instruction"], comment: None },
    }
}

/// The instruction as printed, with branch targets by name.
pub fn raw_instruction(insn: &Insn, ctx: &dyn LiftContext) -> String {
    let text = format_insn(insn).as_str().to_string();
    let Some(target) = insn.target else { return text };
    if insn.m == "adrp" || insn.m == "adr" {
        return text;
    }
    let Some(t) = ctx.target(target) else { return text };
    let name = if t.kind == TargetKind::Label { t.name } else { hla_name(&t.name, &mut Vec::new()) };
    text.replacen(&format!("0x{}", js_hex(target as f64)), &name, 1)
}

/* ------------------------------------------------------------------ *
 * Pairs: a compare and its consumer; adrp and the instruction that completes the address
 * ------------------------------------------------------------------ */

fn signed_op(cond: &str) -> Option<&'static str> {
    Some(match cond {
        "eq" => "==",
        "ne" => "!=",
        "ge" => ">=",
        "lt" => "<",
        "gt" => ">",
        "le" => "<=",
        _ => return None,
    })
}

fn unsigned_op(cond: &str) -> Option<&'static str> {
    Some(match cond {
        "hs" => ">=u",
        "lo" => "<u",
        "hi" => ">u",
        "ls" => "<=u",
        _ => return None,
    })
}

fn float_op(cond: &str) -> Option<&'static str> {
    Some(match cond {
        "eq" => "==",
        "ne" => "!=",
        "gt" => ">",
        "ge" => ">=",
        "mi" => "<",
        "ls" => "<=",
        _ => return None,
    })
}

fn zero_test(cond: &str) -> Option<&'static str> {
    Some(match cond {
        "eq" => "== 0",
        "ne" => "!= 0",
        "mi" => "< 0",
        "pl" => ">= 0",
        _ => return None,
    })
}

/// The instructions that set the flags a following consumer tests.
pub fn is_setter(m: &str) -> bool {
    matches!(m, "cmp" | "cmn" | "tst" | "subs" | "adds" | "ands" | "negs" | "fcmp" | "fcmpe")
}

/// The branches and selects that read the flags.
pub fn is_consumer(m: &str) -> bool {
    matches!(
        m,
        "b.eq"
            | "b.ne"
            | "b.hs"
            | "b.lo"
            | "b.mi"
            | "b.pl"
            | "b.vs"
            | "b.vc"
            | "b.hi"
            | "b.ls"
            | "b.ge"
            | "b.lt"
            | "b.gt"
            | "b.le"
            | "csel"
            | "csinc"
            | "csinv"
            | "csneg"
            | "cset"
            | "csetm"
            | "cinc"
            | "cinv"
            | "cneg"
            | "fcsel"
    )
}

struct Relation {
    pre: Option<String>,
    expr: String,
}

/// `/^-?(0x)?[0-9a-f]+$/i`: a plain number, which negates by its sign.
fn negated(v: &str) -> String {
    let body = v.strip_prefix('-').unwrap_or(v);
    let digits = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")).unwrap_or(body);
    let plain = !digits.is_empty() && digits.bytes().all(|c| c.is_ascii_hexdigit());
    if plain {
        if let Some(rest) = v.strip_prefix('-') {
            return rest.to_string();
        }
    }
    format!("-{v}")
}

/// What the flags of `setter` say under condition `cond`, as an expression; None when no plain one fits.
fn relation(setter: &Insn, cond: &str, words: &mut Words) -> Option<Relation> {
    let m = setter.m.as_str();
    let ops = &setter.ops;
    if m == "fcmp" || m == "fcmpe" {
        let op = float_op(cond)?;
        words.push("float");
        let right = if matches!(ops.get(1), Some(Op::Text(_))) { "0.0".to_string() } else { val(ops.get(1)) };
        return Some(Relation { pre: None, expr: format!("{} {op} {right}", val(ops.first())) });
    }
    let compare = |left: &str, right: &str, words: &mut Words| -> Option<String> {
        if let Some(op) = signed_op(cond) {
            return Some(format!("{left} {op} {right}"));
        }
        if let Some(op) = unsigned_op(cond) {
            words.push("unsigned-compare");
            return Some(format!("{left} {op} {right}"));
        }
        None
    };
    let mut expr_words = Vec::new();
    let from = if m == "cmp" || m == "cmn" || m == "tst" { 1 } else { 2 };
    let right = operand2(&ops[from.min(ops.len())..], &mut expr_words);
    if m == "cmp" {
        let expr = compare(&val(ops.first()), &right, words);
        words.extend(expr_words);
        return expr.map(|expr| Relation { pre: None, expr });
    }
    if m == "cmn" {
        let op = signed_op(cond)?;
        words.extend(expr_words);
        return Some(Relation { pre: None, expr: format!("{} {op} {}", val(ops.first()), negated(&right)) });
    }
    if m == "tst" {
        let anded = format!("{} & {right}", val(ops.first()));
        words.extend(expr_words);
        words.push("arith");
        if let Some(test) = zero_test(cond) {
            return Some(Relation { pre: None, expr: format!("{anded} {test}") });
        }
        if let Some(op) = signed_op(cond) {
            return Some(Relation { pre: None, expr: format!("{anded} {op} 0") });
        }
        return None;
    }
    // With a destination: the operation stays a statement before the test.
    let mut pre_words = Vec::new();
    let pre = lift(setter, 0, &NoContext, &mut pre_words)?;
    words.extend(pre_words);
    let dest = ops.first();
    if m == "ands" || m == "negs" || same_reg(dest, ops.get(1)) || same_reg(dest, ops.get(2)) {
        if let Some(test) = zero_test(cond) {
            return Some(Relation { pre: Some(pre), expr: format!("{} {test}", val(dest)) });
        }
        if m == "ands" {
            if let Some(op) = signed_op(cond) {
                return Some(Relation { pre: Some(pre), expr: format!("{} {op} 0", val(dest)) });
            }
        }
        return None;
    }
    let expr = if m == "subs" { compare(&val(ops.get(1)), &right, words) } else { signed_op(cond).map(|op| format!("{} {op} {}", val(ops.get(1)), negated(&right))) };
    expr.map(|expr| Relation { pre: Some(pre), expr })
}

fn consume(consumer: &Insn, expr: &str, ctx: &dyn LiftContext, words: &mut Words) -> Option<String> {
    let ops = &consumer.ops;
    let (d, a, b) = (val(ops.first()), val(ops.get(1)), val(ops.get(2)));
    let r = format!("({expr})");
    let m = consumer.m.as_str();
    let line = match m {
        "csel" | "fcsel" => {
            words.push("ternary");
            format!("{d} = {expr} ? {a} : {b}")
        }
        "cset" => {
            words.push("condition-value");
            format!("{d} = {expr}")
        }
        "csetm" => {
            words.push("condition-value");
            format!("{d} = -{r}")
        }
        "cinc" => {
            words.push("condition-value");
            words.push("arith");
            format!("{d} = {a} + {r}")
        }
        "cinv" => {
            words.push("ternary");
            format!("{d} = {expr} ? ~{a} : {a}")
        }
        "cneg" => {
            words.push("ternary");
            format!("{d} = {expr} ? -{a} : {a}")
        }
        "csinc" => {
            words.push("ternary");
            format!("{d} = {expr} ? {a} : {b} + 1")
        }
        "csinv" => {
            words.push("ternary");
            format!("{d} = {expr} ? {a} : ~{b}")
        }
        "csneg" => {
            words.push("ternary");
            format!("{d} = {expr} ? {a} : -{b}")
        }
        _ if m.starts_with("b.") => {
            words.push("if-goto");
            format!("if {expr} {{ goto {} }}", branch_target(consumer, ctx, words))
        }
        _ => return None,
    };
    Some(line)
}

/// A string or symbol for an address an adrp pair builds, as a comment and as an HLA64 value.
fn describe_address(addr: i64, ctx: &dyn LiftContext, words: &mut Words) -> (String, Option<String>) {
    let data = ctx.data(addr);
    if let Some(DataAt::String { text, objc }) = &data {
        words.push(if *objc { "nsstring" } else { "string" });
        return (format!("{}{}", if *objc { "@" } else { "" }, quoted(text, 80)), None);
    }
    if let Some(t) = ctx.target(addr) {
        words.push("address");
        let name = if t.kind == TargetKind::Label { t.name } else { hla_name(&t.name, words) };
        return (format!("&{name}"), None);
    }
    if let Some(DataAt::Symbol { name }) = &data {
        words.push("address");
        return (format!("&{}", hla_name(name, words)), None);
    }
    words.push("address");
    (format!("&data_{}", js_hex(addr as f64)), None)
}

/// The address an adrp + second instruction pair forms, or None when the
/// second one does not complete it (add #pageoff or a load/store at [reg, #pageoff]).
pub fn paired_address(adrp: &Insn, next: &Insn) -> Option<i64> {
    if adrp.m != "adrp" {
        return None;
    }
    let target = adrp.target?;
    let reg = adrp.ops.first();
    if next.m == "add" && next.ops.len() == 3 && same_reg(next.ops.get(1), reg) {
        if let Some(Op::Imm { v, .. }) = next.ops.get(2) {
            return Some((target as f64 + v) as i64);
        }
    }
    let mem = next.ops.iter().find_map(|op| if let Op::Mem(m) = op { Some(m) } else { None });
    if let (Some(mem), Some(r)) = (mem, reg_of(reg)) {
        if mem.mode == Mode::Off && mem.index.is_none() && same_reg_name(&mem.base, r) && next.f & (f::LOAD | f::STORE) != 0 {
            return Some(target + mem.off);
        }
    }
    None
}

/// Whether a flag setter and its consumer read as one line: `fuse(first, second, ctx).is_some()`
/// for such a pair, without building the line. The analysis asks it of every compare and branch.
pub fn fuses(first: &Insn, second: &Insn) -> bool {
    if !is_setter(&first.m) || !is_consumer(&second.m) {
        return false;
    }
    let Some(cond) = second.cond else { return false };
    let m = first.m.as_str();
    let ops = &first.ops;
    match m {
        "fcmp" | "fcmpe" => float_op(cond).is_some(),
        "cmp" => signed_op(cond).is_some() || unsigned_op(cond).is_some(),
        "cmn" => signed_op(cond).is_some(),
        "tst" => zero_test(cond).is_some() || signed_op(cond).is_some(),
        _ => {
            // What lift() refuses: integer sugar on other than general registers, or a register list.
            let regs_ok = !is_integer(m) || ops.iter().all(|op| !matches!(op, Op::Reg(r) if !is_gpr(r)));
            if !regs_ok || ops.iter().any(|op| matches!(op, Op::Text(t) if t.starts_with('{'))) {
                return false;
            }
            let dest = ops.first();
            if m == "ands" || m == "negs" || same_reg(dest, ops.get(1)) || same_reg(dest, ops.get(2)) {
                return zero_test(cond).is_some() || (m == "ands" && signed_op(cond).is_some());
            }
            if m == "subs" {
                signed_op(cond).is_some() || unsigned_op(cond).is_some()
            } else {
                signed_op(cond).is_some()
            }
        }
    }
}

/// Two neighbouring instructions as one line, or None when they do not pair.
pub fn fuse(first: &Insn, second: &Insn, ctx: &dyn LiftContext) -> Option<HlaLine> {
    let mut words = Vec::new();
    if first.m == "adrp" {
        let addr = paired_address(first, second)?;
        let (value, comment) = describe_address(addr, ctx, &mut words);
        if second.m == "add" {
            return Some(HlaLine { text: format!("{} = {value}", val(second.ops.first())), words: unique(words), comment });
        }
        // A load or store through the page: the address goes inside the brackets.
        let rt_op = second.ops.first();
        let Some(Op::Reg(rt)) = rt_op else { return None };
        let ty = mem_type(second, rt)?;
        if second.m == "ldp" || second.m == "stp" {
            return None;
        }
        words.push(if ty.is_empty() { "memory" } else { "typed-memory" });
        // Reading or writing at a string's address: the address is the operand, the text a comment.
        let is_string = value.starts_with('"') || value.starts_with("@\"");
        let slot = if is_string { format!("data_{}", js_hex(addr as f64)) } else { value[1..].to_string() };
        let access = format!("{ty}[&{slot}]");
        let text = if second.f & f::LOAD != 0 { format!("{rt} = {access}") } else { format!("{access} = {}", if is_zr(rt) { "0" } else { rt }) };
        // When the load goes elsewhere, the adrp register keeps only the page: say so.
        let keeps = if same_reg(first.ops.first(), rt_op) && second.f & f::LOAD != 0 {
            None
        } else {
            Some(format!("{} = page {}", val(first.ops.first()), num(first.target.unwrap_or(0) as f64)))
        };
        let parts: Vec<String> = [if is_string { Some(value) } else { comment }, keeps].into_iter().flatten().filter(|s| !s.is_empty()).collect();
        let comment = if parts.is_empty() { None } else { Some(parts.join("; ")) };
        return Some(HlaLine { text, words: unique(words), comment });
    }
    if !is_setter(&first.m) || !is_consumer(&second.m) {
        return None;
    }
    let cond = second.cond?;
    let rel = relation(first, cond, &mut words)?;
    let tail = consume(second, &rel.expr, ctx, &mut words)?;
    let text = match rel.pre {
        Some(pre) => format!("{pre}; {tail}"),
        None => tail,
    };
    Some(HlaLine { text, words: unique(words), comment: None })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arm64::decode;

    /// fuses() says what fuse() would, for every compare-like and flag-reading pair of encodings tried.
    #[test]
    fn fuses_agrees_with_fuse() {
        let mut seed: u64 = 0x2545f4914f6cdd1d;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed as u32
        };
        let (mut setters, mut consumers) = (Vec::new(), Vec::new());
        while setters.len() < 3000 || consumers.len() < 3000 {
            let insn = decode(next(), 0x1000);
            if is_setter(&insn.m) && setters.len() < 3000 {
                setters.push(insn);
            } else if is_consumer(&insn.m) && consumers.len() < 3000 {
                consumers.push(insn);
            }
        }
        for (k, a) in setters.iter().enumerate() {
            for b in consumers.iter().skip(k % 7).step_by(7) {
                assert_eq!(fuses(a, b), fuse(a, b, &NoContext).is_some(), "{} / {}", format_insn(a), format_insn(b));
            }
        }
    }
}
