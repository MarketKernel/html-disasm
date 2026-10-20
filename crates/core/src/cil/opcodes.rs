//! The CIL opcodes of ECMA-335 (Partition III), as src/core/cil/opcodes.ts has
//! them: a byte, or 0xFE and a byte, then the operand its kind says; what each
//! takes from the evaluation stack and leaves there (-1: the signature of the
//! call or the return says), and flags for the analysis. The page keeps the
//! groups, categories and descriptions.

/// The kinds of operand an opcode is followed by.
pub mod operand {
    pub const NONE: u8 = 0;
    /// An argument or local number: one byte (ShortInlineVar) or two (InlineVar).
    pub const VAR8: u8 = 1;
    pub const VAR16: u8 = 2;
    /// A signed byte (ldc.i4.s) or an unsigned one (unaligned., no.).
    pub const I8: u8 = 3;
    pub const U8: u8 = 4;
    pub const I32: u8 = 5;
    pub const I64: u8 = 6;
    pub const R4: u8 = 7;
    pub const R8: u8 = 8;
    /// A branch offset from the next instruction: one signed byte or four.
    pub const BR8: u8 = 9;
    pub const BR32: u8 = 10;
    /// A count of four-byte branch offsets.
    pub const SWITCH: u8 = 11;
    /// Metadata tokens: a method, a field, a type, a #US string, a stand-alone signature, any of the first three.
    pub const METHOD: u8 = 12;
    pub const FIELD: u8 = 13;
    pub const TYPE: u8 = 14;
    pub const STRING: u8 = 15;
    pub const SIG: u8 = 16;
    pub const TOKEN: u8 = 17;
}

/// Bits of [`OpInfo::flags`].
pub mod f {
    pub const BRANCH: u16 = 1;
    pub const CONDITIONAL: u16 = 2;
    pub const CALL: u16 = 4;
    pub const RETURN: u16 = 8;
    pub const THROW: u16 = 16;
    pub const PREFIX: u16 = 32;
    /// Ends a block of code: nothing after it runs unless something branches there.
    pub const END: u16 = 64;
    pub const LOAD: u16 = 128;
    pub const STORE: u16 = 256;
    pub const COMPARE: u16 = 512;
    /// Can throw on its own (overflow, a null reference, a bad cast, an index out of range).
    pub const TRAPS: u16 = 1024;
}

#[derive(Debug, PartialEq, Eq)]
pub struct OpInfo {
    /// 0x00–0xE0, or 0xFE00–0xFE1E.
    pub code: u16,
    pub name: &'static str,
    pub operand: u8,
    /// Values taken from and pushed on the stack; -1 when the operand's signature says.
    pub pop: i8,
    pub push: i8,
    pub flags: u16,
}

type Row = (u16, &'static str, u8, i8, i8, u16);

const ROWS: [Row; 219] = [
    (0x00, "nop", operand::NONE, 0, 0, 0),
    (0x01, "break", operand::NONE, 0, 0, 0),
    (0x02, "ldarg.0", operand::NONE, 0, 1, 0),
    (0x03, "ldarg.1", operand::NONE, 0, 1, 0),
    (0x04, "ldarg.2", operand::NONE, 0, 1, 0),
    (0x05, "ldarg.3", operand::NONE, 0, 1, 0),
    (0x06, "ldloc.0", operand::NONE, 0, 1, 0),
    (0x07, "ldloc.1", operand::NONE, 0, 1, 0),
    (0x08, "ldloc.2", operand::NONE, 0, 1, 0),
    (0x09, "ldloc.3", operand::NONE, 0, 1, 0),
    (0x0a, "stloc.0", operand::NONE, 1, 0, 0),
    (0x0b, "stloc.1", operand::NONE, 1, 0, 0),
    (0x0c, "stloc.2", operand::NONE, 1, 0, 0),
    (0x0d, "stloc.3", operand::NONE, 1, 0, 0),
    (0x0e, "ldarg.s", operand::VAR8, 0, 1, 0),
    (0x0f, "ldarga.s", operand::VAR8, 0, 1, 0),
    (0x10, "starg.s", operand::VAR8, 1, 0, 0),
    (0x11, "ldloc.s", operand::VAR8, 0, 1, 0),
    (0x12, "ldloca.s", operand::VAR8, 0, 1, 0),
    (0x13, "stloc.s", operand::VAR8, 1, 0, 0),
    (0x14, "ldnull", operand::NONE, 0, 1, 0),
    (0x15, "ldc.i4.m1", operand::NONE, 0, 1, 0),
    (0x16, "ldc.i4.0", operand::NONE, 0, 1, 0),
    (0x17, "ldc.i4.1", operand::NONE, 0, 1, 0),
    (0x18, "ldc.i4.2", operand::NONE, 0, 1, 0),
    (0x19, "ldc.i4.3", operand::NONE, 0, 1, 0),
    (0x1a, "ldc.i4.4", operand::NONE, 0, 1, 0),
    (0x1b, "ldc.i4.5", operand::NONE, 0, 1, 0),
    (0x1c, "ldc.i4.6", operand::NONE, 0, 1, 0),
    (0x1d, "ldc.i4.7", operand::NONE, 0, 1, 0),
    (0x1e, "ldc.i4.8", operand::NONE, 0, 1, 0),
    (0x1f, "ldc.i4.s", operand::I8, 0, 1, 0),
    (0x20, "ldc.i4", operand::I32, 0, 1, 0),
    (0x21, "ldc.i8", operand::I64, 0, 1, 0),
    (0x22, "ldc.r4", operand::R4, 0, 1, 0),
    (0x23, "ldc.r8", operand::R8, 0, 1, 0),
    (0x25, "dup", operand::NONE, 1, 2, 0),
    (0x26, "pop", operand::NONE, 1, 0, 0),
    (0x27, "jmp", operand::METHOD, 0, 0, f::CALL | f::END),
    (0x28, "call", operand::METHOD, -1, -1, f::CALL),
    (0x29, "calli", operand::SIG, -1, -1, f::CALL),
    (0x2a, "ret", operand::NONE, -1, 0, f::RETURN | f::END),
    (0x2b, "br.s", operand::BR8, 0, 0, f::BRANCH | f::END),
    (0x2c, "brfalse.s", operand::BR8, 1, 0, f::BRANCH | f::CONDITIONAL),
    (0x2d, "brtrue.s", operand::BR8, 1, 0, f::BRANCH | f::CONDITIONAL),
    (0x2e, "beq.s", operand::BR8, 2, 0, f::BRANCH | f::CONDITIONAL),
    (0x2f, "bge.s", operand::BR8, 2, 0, f::BRANCH | f::CONDITIONAL),
    (0x30, "bgt.s", operand::BR8, 2, 0, f::BRANCH | f::CONDITIONAL),
    (0x31, "ble.s", operand::BR8, 2, 0, f::BRANCH | f::CONDITIONAL),
    (0x32, "blt.s", operand::BR8, 2, 0, f::BRANCH | f::CONDITIONAL),
    (0x33, "bne.un.s", operand::BR8, 2, 0, f::BRANCH | f::CONDITIONAL),
    (0x34, "bge.un.s", operand::BR8, 2, 0, f::BRANCH | f::CONDITIONAL),
    (0x35, "bgt.un.s", operand::BR8, 2, 0, f::BRANCH | f::CONDITIONAL),
    (0x36, "ble.un.s", operand::BR8, 2, 0, f::BRANCH | f::CONDITIONAL),
    (0x37, "blt.un.s", operand::BR8, 2, 0, f::BRANCH | f::CONDITIONAL),
    (0x38, "br", operand::BR32, 0, 0, f::BRANCH | f::END),
    (0x39, "brfalse", operand::BR32, 1, 0, f::BRANCH | f::CONDITIONAL),
    (0x3a, "brtrue", operand::BR32, 1, 0, f::BRANCH | f::CONDITIONAL),
    (0x3b, "beq", operand::BR32, 2, 0, f::BRANCH | f::CONDITIONAL),
    (0x3c, "bge", operand::BR32, 2, 0, f::BRANCH | f::CONDITIONAL),
    (0x3d, "bgt", operand::BR32, 2, 0, f::BRANCH | f::CONDITIONAL),
    (0x3e, "ble", operand::BR32, 2, 0, f::BRANCH | f::CONDITIONAL),
    (0x3f, "blt", operand::BR32, 2, 0, f::BRANCH | f::CONDITIONAL),
    (0x40, "bne.un", operand::BR32, 2, 0, f::BRANCH | f::CONDITIONAL),
    (0x41, "bge.un", operand::BR32, 2, 0, f::BRANCH | f::CONDITIONAL),
    (0x42, "bgt.un", operand::BR32, 2, 0, f::BRANCH | f::CONDITIONAL),
    (0x43, "ble.un", operand::BR32, 2, 0, f::BRANCH | f::CONDITIONAL),
    (0x44, "blt.un", operand::BR32, 2, 0, f::BRANCH | f::CONDITIONAL),
    (0x45, "switch", operand::SWITCH, 1, 0, f::BRANCH | f::CONDITIONAL),
    (0x46, "ldind.i1", operand::NONE, 1, 1, f::LOAD | f::TRAPS),
    (0x47, "ldind.u1", operand::NONE, 1, 1, f::LOAD | f::TRAPS),
    (0x48, "ldind.i2", operand::NONE, 1, 1, f::LOAD | f::TRAPS),
    (0x49, "ldind.u2", operand::NONE, 1, 1, f::LOAD | f::TRAPS),
    (0x4a, "ldind.i4", operand::NONE, 1, 1, f::LOAD | f::TRAPS),
    (0x4b, "ldind.u4", operand::NONE, 1, 1, f::LOAD | f::TRAPS),
    (0x4c, "ldind.i8", operand::NONE, 1, 1, f::LOAD | f::TRAPS),
    (0x4d, "ldind.i", operand::NONE, 1, 1, f::LOAD | f::TRAPS),
    (0x4e, "ldind.r4", operand::NONE, 1, 1, f::LOAD | f::TRAPS),
    (0x4f, "ldind.r8", operand::NONE, 1, 1, f::LOAD | f::TRAPS),
    (0x50, "ldind.ref", operand::NONE, 1, 1, f::LOAD | f::TRAPS),
    (0x51, "stind.ref", operand::NONE, 2, 0, f::STORE | f::TRAPS),
    (0x52, "stind.i1", operand::NONE, 2, 0, f::STORE | f::TRAPS),
    (0x53, "stind.i2", operand::NONE, 2, 0, f::STORE | f::TRAPS),
    (0x54, "stind.i4", operand::NONE, 2, 0, f::STORE | f::TRAPS),
    (0x55, "stind.i8", operand::NONE, 2, 0, f::STORE | f::TRAPS),
    (0x56, "stind.r4", operand::NONE, 2, 0, f::STORE | f::TRAPS),
    (0x57, "stind.r8", operand::NONE, 2, 0, f::STORE | f::TRAPS),
    (0x58, "add", operand::NONE, 2, 1, 0),
    (0x59, "sub", operand::NONE, 2, 1, 0),
    (0x5a, "mul", operand::NONE, 2, 1, 0),
    (0x5b, "div", operand::NONE, 2, 1, f::TRAPS),
    (0x5c, "div.un", operand::NONE, 2, 1, f::TRAPS),
    (0x5d, "rem", operand::NONE, 2, 1, f::TRAPS),
    (0x5e, "rem.un", operand::NONE, 2, 1, f::TRAPS),
    (0x5f, "and", operand::NONE, 2, 1, 0),
    (0x60, "or", operand::NONE, 2, 1, 0),
    (0x61, "xor", operand::NONE, 2, 1, 0),
    (0x62, "shl", operand::NONE, 2, 1, 0),
    (0x63, "shr", operand::NONE, 2, 1, 0),
    (0x64, "shr.un", operand::NONE, 2, 1, 0),
    (0x65, "neg", operand::NONE, 1, 1, 0),
    (0x66, "not", operand::NONE, 1, 1, 0),
    (0x67, "conv.i1", operand::NONE, 1, 1, 0),
    (0x68, "conv.i2", operand::NONE, 1, 1, 0),
    (0x69, "conv.i4", operand::NONE, 1, 1, 0),
    (0x6a, "conv.i8", operand::NONE, 1, 1, 0),
    (0x6b, "conv.r4", operand::NONE, 1, 1, 0),
    (0x6c, "conv.r8", operand::NONE, 1, 1, 0),
    (0x6d, "conv.u4", operand::NONE, 1, 1, 0),
    (0x6e, "conv.u8", operand::NONE, 1, 1, 0),
    (0x6f, "callvirt", operand::METHOD, -1, -1, f::CALL | f::TRAPS),
    (0x70, "cpobj", operand::TYPE, 2, 0, f::LOAD | f::STORE | f::TRAPS),
    (0x71, "ldobj", operand::TYPE, 1, 1, f::LOAD | f::TRAPS),
    (0x72, "ldstr", operand::STRING, 0, 1, 0),
    (0x73, "newobj", operand::METHOD, -1, 1, f::CALL),
    (0x74, "castclass", operand::TYPE, 1, 1, f::TRAPS),
    (0x75, "isinst", operand::TYPE, 1, 1, 0),
    (0x76, "conv.r.un", operand::NONE, 1, 1, 0),
    (0x79, "unbox", operand::TYPE, 1, 1, f::TRAPS),
    (0x7a, "throw", operand::NONE, 1, 0, f::THROW | f::END),
    (0x7b, "ldfld", operand::FIELD, 1, 1, f::LOAD | f::TRAPS),
    (0x7c, "ldflda", operand::FIELD, 1, 1, f::TRAPS),
    (0x7d, "stfld", operand::FIELD, 2, 0, f::STORE | f::TRAPS),
    (0x7e, "ldsfld", operand::FIELD, 0, 1, f::LOAD),
    (0x7f, "ldsflda", operand::FIELD, 0, 1, 0),
    (0x80, "stsfld", operand::FIELD, 1, 0, f::STORE),
    (0x81, "stobj", operand::TYPE, 2, 0, f::STORE | f::TRAPS),
    (0x82, "conv.ovf.i1.un", operand::NONE, 1, 1, f::TRAPS),
    (0x83, "conv.ovf.i2.un", operand::NONE, 1, 1, f::TRAPS),
    (0x84, "conv.ovf.i4.un", operand::NONE, 1, 1, f::TRAPS),
    (0x85, "conv.ovf.i8.un", operand::NONE, 1, 1, f::TRAPS),
    (0x86, "conv.ovf.u1.un", operand::NONE, 1, 1, f::TRAPS),
    (0x87, "conv.ovf.u2.un", operand::NONE, 1, 1, f::TRAPS),
    (0x88, "conv.ovf.u4.un", operand::NONE, 1, 1, f::TRAPS),
    (0x89, "conv.ovf.u8.un", operand::NONE, 1, 1, f::TRAPS),
    (0x8a, "conv.ovf.i.un", operand::NONE, 1, 1, f::TRAPS),
    (0x8b, "conv.ovf.u.un", operand::NONE, 1, 1, f::TRAPS),
    (0x8c, "box", operand::TYPE, 1, 1, 0),
    (0x8d, "newarr", operand::TYPE, 1, 1, f::TRAPS),
    (0x8e, "ldlen", operand::NONE, 1, 1, f::TRAPS),
    (0x8f, "ldelema", operand::TYPE, 2, 1, f::TRAPS),
    (0x90, "ldelem.i1", operand::NONE, 2, 1, f::LOAD | f::TRAPS),
    (0x91, "ldelem.u1", operand::NONE, 2, 1, f::LOAD | f::TRAPS),
    (0x92, "ldelem.i2", operand::NONE, 2, 1, f::LOAD | f::TRAPS),
    (0x93, "ldelem.u2", operand::NONE, 2, 1, f::LOAD | f::TRAPS),
    (0x94, "ldelem.i4", operand::NONE, 2, 1, f::LOAD | f::TRAPS),
    (0x95, "ldelem.u4", operand::NONE, 2, 1, f::LOAD | f::TRAPS),
    (0x96, "ldelem.i8", operand::NONE, 2, 1, f::LOAD | f::TRAPS),
    (0x97, "ldelem.i", operand::NONE, 2, 1, f::LOAD | f::TRAPS),
    (0x98, "ldelem.r4", operand::NONE, 2, 1, f::LOAD | f::TRAPS),
    (0x99, "ldelem.r8", operand::NONE, 2, 1, f::LOAD | f::TRAPS),
    (0x9a, "ldelem.ref", operand::NONE, 2, 1, f::LOAD | f::TRAPS),
    (0x9b, "stelem.i", operand::NONE, 3, 0, f::STORE | f::TRAPS),
    (0x9c, "stelem.i1", operand::NONE, 3, 0, f::STORE | f::TRAPS),
    (0x9d, "stelem.i2", operand::NONE, 3, 0, f::STORE | f::TRAPS),
    (0x9e, "stelem.i4", operand::NONE, 3, 0, f::STORE | f::TRAPS),
    (0x9f, "stelem.i8", operand::NONE, 3, 0, f::STORE | f::TRAPS),
    (0xa0, "stelem.r4", operand::NONE, 3, 0, f::STORE | f::TRAPS),
    (0xa1, "stelem.r8", operand::NONE, 3, 0, f::STORE | f::TRAPS),
    (0xa2, "stelem.ref", operand::NONE, 3, 0, f::STORE | f::TRAPS),
    (0xa3, "ldelem", operand::TYPE, 2, 1, f::LOAD | f::TRAPS),
    (0xa4, "stelem", operand::TYPE, 3, 0, f::STORE | f::TRAPS),
    (0xa5, "unbox.any", operand::TYPE, 1, 1, f::TRAPS),
    (0xb3, "conv.ovf.i1", operand::NONE, 1, 1, f::TRAPS),
    (0xb4, "conv.ovf.u1", operand::NONE, 1, 1, f::TRAPS),
    (0xb5, "conv.ovf.i2", operand::NONE, 1, 1, f::TRAPS),
    (0xb6, "conv.ovf.u2", operand::NONE, 1, 1, f::TRAPS),
    (0xb7, "conv.ovf.i4", operand::NONE, 1, 1, f::TRAPS),
    (0xb8, "conv.ovf.u4", operand::NONE, 1, 1, f::TRAPS),
    (0xb9, "conv.ovf.i8", operand::NONE, 1, 1, f::TRAPS),
    (0xba, "conv.ovf.u8", operand::NONE, 1, 1, f::TRAPS),
    (0xc2, "refanyval", operand::TYPE, 1, 1, f::TRAPS),
    (0xc3, "ckfinite", operand::NONE, 1, 1, f::TRAPS),
    (0xc6, "mkrefany", operand::TYPE, 1, 1, 0),
    (0xd0, "ldtoken", operand::TOKEN, 0, 1, 0),
    (0xd1, "conv.u2", operand::NONE, 1, 1, 0),
    (0xd2, "conv.u1", operand::NONE, 1, 1, 0),
    (0xd3, "conv.i", operand::NONE, 1, 1, 0),
    (0xd4, "conv.ovf.i", operand::NONE, 1, 1, f::TRAPS),
    (0xd5, "conv.ovf.u", operand::NONE, 1, 1, f::TRAPS),
    (0xd6, "add.ovf", operand::NONE, 2, 1, f::TRAPS),
    (0xd7, "add.ovf.un", operand::NONE, 2, 1, f::TRAPS),
    (0xd8, "mul.ovf", operand::NONE, 2, 1, f::TRAPS),
    (0xd9, "mul.ovf.un", operand::NONE, 2, 1, f::TRAPS),
    (0xda, "sub.ovf", operand::NONE, 2, 1, f::TRAPS),
    (0xdb, "sub.ovf.un", operand::NONE, 2, 1, f::TRAPS),
    (0xdc, "endfinally", operand::NONE, 0, 0, f::END),
    (0xdd, "leave", operand::BR32, 0, 0, f::BRANCH | f::END),
    (0xde, "leave.s", operand::BR8, 0, 0, f::BRANCH | f::END),
    (0xdf, "stind.i", operand::NONE, 2, 0, f::STORE | f::TRAPS),
    (0xe0, "conv.u", operand::NONE, 1, 1, 0),
    (0xfe00, "arglist", operand::NONE, 0, 1, 0),
    (0xfe01, "ceq", operand::NONE, 2, 1, f::COMPARE),
    (0xfe02, "cgt", operand::NONE, 2, 1, f::COMPARE),
    (0xfe03, "cgt.un", operand::NONE, 2, 1, f::COMPARE),
    (0xfe04, "clt", operand::NONE, 2, 1, f::COMPARE),
    (0xfe05, "clt.un", operand::NONE, 2, 1, f::COMPARE),
    (0xfe06, "ldftn", operand::METHOD, 0, 1, 0),
    (0xfe07, "ldvirtftn", operand::METHOD, 1, 1, f::TRAPS),
    (0xfe09, "ldarg", operand::VAR16, 0, 1, 0),
    (0xfe0a, "ldarga", operand::VAR16, 0, 1, 0),
    (0xfe0b, "starg", operand::VAR16, 1, 0, 0),
    (0xfe0c, "ldloc", operand::VAR16, 0, 1, 0),
    (0xfe0d, "ldloca", operand::VAR16, 0, 1, 0),
    (0xfe0e, "stloc", operand::VAR16, 1, 0, 0),
    (0xfe0f, "localloc", operand::NONE, 1, 1, f::TRAPS),
    (0xfe11, "endfilter", operand::NONE, 1, 0, f::END),
    (0xfe12, "unaligned.", operand::U8, 0, 0, f::PREFIX),
    (0xfe13, "volatile.", operand::NONE, 0, 0, f::PREFIX),
    (0xfe14, "tail.", operand::NONE, 0, 0, f::PREFIX),
    (0xfe15, "initobj", operand::TYPE, 1, 0, f::STORE | f::TRAPS),
    (0xfe16, "constrained.", operand::TYPE, 0, 0, f::PREFIX),
    (0xfe17, "cpblk", operand::NONE, 3, 0, f::LOAD | f::STORE | f::TRAPS),
    (0xfe18, "initblk", operand::NONE, 3, 0, f::STORE | f::TRAPS),
    (0xfe19, "no.", operand::U8, 0, 0, f::PREFIX),
    (0xfe1a, "rethrow", operand::NONE, 0, 0, f::THROW | f::END),
    (0xfe1c, "sizeof", operand::TYPE, 0, 1, 0),
    (0xfe1d, "refanytype", operand::NONE, 1, 1, 0),
    (0xfe1e, "readonly.", operand::NONE, 0, 0, f::PREFIX),
];

static OPS: [OpInfo; 219] = {
    let mut out = [const { OpInfo { code: 0, name: "", operand: 0, pop: 0, push: 0, flags: 0 } }; 219];
    let mut k = 0;
    while k < ROWS.len() {
        let (code, name, operand, pop, push, flags) = ROWS[k];
        out[k] = OpInfo { code, name, operand, pop, push, flags };
        k += 1;
    }
    out
};

/// Index + 1 into [`OPS`] by the opcode's byte (one-byte opcodes) or second byte (0xFE xx); 0 for none.
static INDEX: ([u8; 256], [u8; 256]) = {
    let mut one = [0u8; 256];
    let mut two = [0u8; 256];
    let mut k = 0;
    while k < ROWS.len() {
        let code = ROWS[k].0;
        if code > 0xff {
            two[(code & 0xff) as usize] = k as u8 + 1;
        } else {
            one[code as usize] = k as u8 + 1;
        }
        k += 1;
    }
    (one, two)
};

/// A one-byte opcode by its byte.
#[inline]
pub fn one(byte: u8) -> Option<&'static OpInfo> {
    let k = INDEX.0[byte as usize];
    (k != 0).then(|| &OPS[k as usize - 1])
}

/// A two-byte opcode (0xFE xx) by its second byte.
#[inline]
pub fn two(byte: u8) -> Option<&'static OpInfo> {
    let k = INDEX.1[byte as usize];
    (k != 0).then(|| &OPS[k as usize - 1])
}

pub fn all_ops() -> &'static [OpInfo] {
    &OPS
}
