//! The JVM's opcodes (the Java Virtual Machine Specification, chapter 6): a
//! byte, then the operand its kind says. `wide` (0xC4) is not one of them on
//! its own: with the instruction it widens it is one instruction, and javap
//! names the pair as the ClassFile API does — `iload_w`, `iinc_w`, `ret_w`. Each
//! opcode has the values it takes from the operand stack and leaves there
//! (values, not slots: a long is one value; `-1` when the descriptor of what it
//! calls or names says), and flags for the analysis and the colours of the
//! listing. The descriptions are in src/data/jvm-instructions.json.
//!
//! A port of src/core/jvm/opcodes.ts: the same rows, as static data.

/// The kinds of operand an opcode is followed by.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Operand {
    None = 0,
    /// A local variable's slot: one byte, or two after wide.
    Local = 1,
    LocalW = 2,
    /// iinc: a slot and a signed constant, a byte each, or two bytes each after wide.
    Iinc = 3,
    IincW = 4,
    /// A signed byte (bipush) or a signed short (sipush).
    Byte = 5,
    Short = 6,
    /// A constant pool index: one byte (ldc) or two.
    Cp8 = 7,
    Cp16 = 8,
    /// invokeinterface: an index, the count of argument slots and a zero byte.
    Interface = 9,
    /// invokedynamic: an index and two zero bytes.
    Dynamic = 10,
    /// multianewarray: an index and the number of dimensions.
    Dimensions = 11,
    /// newarray: the type of the elements (4 boolean … 11 long).
    Atype = 12,
    /// A branch offset from the instruction: two bytes or four.
    Branch16 = 13,
    Branch32 = 14,
    TableSwitch = 15,
    LookupSwitch = 16,
    /// jsr and ret, whose operands javap does not print.
    Jsr16 = 17,
    Jsr32 = 18,
    Ret = 19,
    RetW = 20,
}

/// Bits of `OpInfo::flags`.
pub mod flags {
    pub const BRANCH: u16 = 1;
    pub const CONDITIONAL: u16 = 2;
    pub const CALL: u16 = 4;
    pub const RETURN: u16 = 8;
    pub const THROW: u16 = 16;
    /// Ends a block of code: nothing after it runs unless something branches there.
    pub const END: u16 = 32;
    pub const LOAD: u16 = 64;
    pub const STORE: u16 = 128;
    pub const COMPARE: u16 = 256;
    /// Can throw on its own (a null reference, an index out of the array, a bad cast, division by zero).
    pub const TRAPS: u16 = 512;
    /// A subroutine (jsr, ret): the return address is a value no line can name.
    pub const SUBROUTINE: u16 = 1024;
}

/// The groups the listing colours opcodes by.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Group {
    Constants,
    Loads,
    Stores,
    Stack,
    Math,
    Conversions,
    Comparisons,
    Control,
    References,
    Extended,
}

impl Group {
    /// The name the page uses: `jvm-constants`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Group::Constants => "jvm-constants",
            Group::Loads => "jvm-loads",
            Group::Stores => "jvm-stores",
            Group::Stack => "jvm-stack",
            Group::Math => "jvm-math",
            Group::Conversions => "jvm-conversions",
            Group::Comparisons => "jvm-comparisons",
            Group::Control => "jvm-control",
            Group::References => "jvm-references",
            Group::Extended => "jvm-extended",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct OpInfo {
    pub name: &'static str,
    /// 0x00–0xC9, or 0xC4xx for a wide form.
    pub code: u16,
    pub operand: Operand,
    /// Values taken from and pushed on the stack; -1 when the descriptor of the operand says.
    pub pop: i8,
    pub push: i8,
    pub flags: u16,
    pub group: Group,
    pub category: &'static str,
    /// What kind of value it pushes: i(nt), l(ong), f(loat), d(ouble), a (reference), r(eturn address); '' when it pushes nothing or the descriptor says.
    pub kind: &'static str,
}

use flags::*;
use Group::{Comparisons as P, Constants as C, Control as T, Conversions as V, Extended as X, Loads as L, Math as M, References as R, Stack as K, Stores as S};
use Operand as O;

const IF: u16 = BRANCH | CONDITIONAL;

#[allow(clippy::too_many_arguments)]
const fn op(code: u16, name: &'static str, operand: Operand, pop: i8, push: i8, flags: u16, group: Group, category: &'static str, kind: &'static str) -> OpInfo {
    OpInfo { name, code, operand, pop, push, flags, group, category, kind }
}

const ROWS: [OpInfo; 213] = [
    op(0x00, "nop", O::None, 0, 0, 0, C, "other", ""),
    op(0x01, "aconst_null", O::None, 0, 1, 0, C, "constant", "a"),
    op(0x02, "iconst_m1", O::None, 0, 1, 0, C, "constant", "i"),
    op(0x03, "iconst_0", O::None, 0, 1, 0, C, "constant", "i"),
    op(0x04, "iconst_1", O::None, 0, 1, 0, C, "constant", "i"),
    op(0x05, "iconst_2", O::None, 0, 1, 0, C, "constant", "i"),
    op(0x06, "iconst_3", O::None, 0, 1, 0, C, "constant", "i"),
    op(0x07, "iconst_4", O::None, 0, 1, 0, C, "constant", "i"),
    op(0x08, "iconst_5", O::None, 0, 1, 0, C, "constant", "i"),
    op(0x09, "lconst_0", O::None, 0, 1, 0, C, "constant", "l"),
    op(0x0a, "lconst_1", O::None, 0, 1, 0, C, "constant", "l"),
    op(0x0b, "fconst_0", O::None, 0, 1, 0, C, "constant", "f"),
    op(0x0c, "fconst_1", O::None, 0, 1, 0, C, "constant", "f"),
    op(0x0d, "fconst_2", O::None, 0, 1, 0, C, "constant", "f"),
    op(0x0e, "dconst_0", O::None, 0, 1, 0, C, "constant", "d"),
    op(0x0f, "dconst_1", O::None, 0, 1, 0, C, "constant", "d"),
    op(0x10, "bipush", O::Byte, 0, 1, 0, C, "constant", "i"),
    op(0x11, "sipush", O::Short, 0, 1, 0, C, "constant", "i"),
    op(0x12, "ldc", O::Cp8, 0, 1, 0, C, "constant", ""),
    op(0x13, "ldc_w", O::Cp16, 0, 1, 0, C, "constant", ""),
    op(0x14, "ldc2_w", O::Cp16, 0, 1, 0, C, "constant", ""),
    op(0x15, "iload", O::Local, 0, 1, 0, L, "variable", "i"),
    op(0x16, "lload", O::Local, 0, 1, 0, L, "variable", "l"),
    op(0x17, "fload", O::Local, 0, 1, 0, L, "variable", "f"),
    op(0x18, "dload", O::Local, 0, 1, 0, L, "variable", "d"),
    op(0x19, "aload", O::Local, 0, 1, 0, L, "variable", "a"),
    op(0x1a, "iload_0", O::None, 0, 1, 0, L, "variable", "i"),
    op(0x1b, "iload_1", O::None, 0, 1, 0, L, "variable", "i"),
    op(0x1c, "iload_2", O::None, 0, 1, 0, L, "variable", "i"),
    op(0x1d, "iload_3", O::None, 0, 1, 0, L, "variable", "i"),
    op(0x1e, "lload_0", O::None, 0, 1, 0, L, "variable", "l"),
    op(0x1f, "lload_1", O::None, 0, 1, 0, L, "variable", "l"),
    op(0x20, "lload_2", O::None, 0, 1, 0, L, "variable", "l"),
    op(0x21, "lload_3", O::None, 0, 1, 0, L, "variable", "l"),
    op(0x22, "fload_0", O::None, 0, 1, 0, L, "variable", "f"),
    op(0x23, "fload_1", O::None, 0, 1, 0, L, "variable", "f"),
    op(0x24, "fload_2", O::None, 0, 1, 0, L, "variable", "f"),
    op(0x25, "fload_3", O::None, 0, 1, 0, L, "variable", "f"),
    op(0x26, "dload_0", O::None, 0, 1, 0, L, "variable", "d"),
    op(0x27, "dload_1", O::None, 0, 1, 0, L, "variable", "d"),
    op(0x28, "dload_2", O::None, 0, 1, 0, L, "variable", "d"),
    op(0x29, "dload_3", O::None, 0, 1, 0, L, "variable", "d"),
    op(0x2a, "aload_0", O::None, 0, 1, 0, L, "variable", "a"),
    op(0x2b, "aload_1", O::None, 0, 1, 0, L, "variable", "a"),
    op(0x2c, "aload_2", O::None, 0, 1, 0, L, "variable", "a"),
    op(0x2d, "aload_3", O::None, 0, 1, 0, L, "variable", "a"),
    op(0x2e, "iaload", O::None, 2, 1, LOAD | TRAPS, L, "array", "i"),
    op(0x2f, "laload", O::None, 2, 1, LOAD | TRAPS, L, "array", "l"),
    op(0x30, "faload", O::None, 2, 1, LOAD | TRAPS, L, "array", "f"),
    op(0x31, "daload", O::None, 2, 1, LOAD | TRAPS, L, "array", "d"),
    op(0x32, "aaload", O::None, 2, 1, LOAD | TRAPS, L, "array", "a"),
    op(0x33, "baload", O::None, 2, 1, LOAD | TRAPS, L, "array", "i"),
    op(0x34, "caload", O::None, 2, 1, LOAD | TRAPS, L, "array", "i"),
    op(0x35, "saload", O::None, 2, 1, LOAD | TRAPS, L, "array", "i"),
    op(0x36, "istore", O::Local, 1, 0, 0, S, "variable", ""),
    op(0x37, "lstore", O::Local, 1, 0, 0, S, "variable", ""),
    op(0x38, "fstore", O::Local, 1, 0, 0, S, "variable", ""),
    op(0x39, "dstore", O::Local, 1, 0, 0, S, "variable", ""),
    op(0x3a, "astore", O::Local, 1, 0, 0, S, "variable", ""),
    op(0x3b, "istore_0", O::None, 1, 0, 0, S, "variable", ""),
    op(0x3c, "istore_1", O::None, 1, 0, 0, S, "variable", ""),
    op(0x3d, "istore_2", O::None, 1, 0, 0, S, "variable", ""),
    op(0x3e, "istore_3", O::None, 1, 0, 0, S, "variable", ""),
    op(0x3f, "lstore_0", O::None, 1, 0, 0, S, "variable", ""),
    op(0x40, "lstore_1", O::None, 1, 0, 0, S, "variable", ""),
    op(0x41, "lstore_2", O::None, 1, 0, 0, S, "variable", ""),
    op(0x42, "lstore_3", O::None, 1, 0, 0, S, "variable", ""),
    op(0x43, "fstore_0", O::None, 1, 0, 0, S, "variable", ""),
    op(0x44, "fstore_1", O::None, 1, 0, 0, S, "variable", ""),
    op(0x45, "fstore_2", O::None, 1, 0, 0, S, "variable", ""),
    op(0x46, "fstore_3", O::None, 1, 0, 0, S, "variable", ""),
    op(0x47, "dstore_0", O::None, 1, 0, 0, S, "variable", ""),
    op(0x48, "dstore_1", O::None, 1, 0, 0, S, "variable", ""),
    op(0x49, "dstore_2", O::None, 1, 0, 0, S, "variable", ""),
    op(0x4a, "dstore_3", O::None, 1, 0, 0, S, "variable", ""),
    op(0x4b, "astore_0", O::None, 1, 0, 0, S, "variable", ""),
    op(0x4c, "astore_1", O::None, 1, 0, 0, S, "variable", ""),
    op(0x4d, "astore_2", O::None, 1, 0, 0, S, "variable", ""),
    op(0x4e, "astore_3", O::None, 1, 0, 0, S, "variable", ""),
    op(0x4f, "iastore", O::None, 3, 0, STORE | TRAPS, S, "array", ""),
    op(0x50, "lastore", O::None, 3, 0, STORE | TRAPS, S, "array", ""),
    op(0x51, "fastore", O::None, 3, 0, STORE | TRAPS, S, "array", ""),
    op(0x52, "dastore", O::None, 3, 0, STORE | TRAPS, S, "array", ""),
    op(0x53, "aastore", O::None, 3, 0, STORE | TRAPS, S, "array", ""),
    op(0x54, "bastore", O::None, 3, 0, STORE | TRAPS, S, "array", ""),
    op(0x55, "castore", O::None, 3, 0, STORE | TRAPS, S, "array", ""),
    op(0x56, "sastore", O::None, 3, 0, STORE | TRAPS, S, "array", ""),
    op(0x57, "pop", O::None, 1, 0, 0, K, "stack", ""),
    op(0x58, "pop2", O::None, -1, 0, 0, K, "stack", ""),
    op(0x59, "dup", O::None, -1, -1, 0, K, "stack", ""),
    op(0x5a, "dup_x1", O::None, -1, -1, 0, K, "stack", ""),
    op(0x5b, "dup_x2", O::None, -1, -1, 0, K, "stack", ""),
    op(0x5c, "dup2", O::None, -1, -1, 0, K, "stack", ""),
    op(0x5d, "dup2_x1", O::None, -1, -1, 0, K, "stack", ""),
    op(0x5e, "dup2_x2", O::None, -1, -1, 0, K, "stack", ""),
    op(0x5f, "swap", O::None, -1, -1, 0, K, "stack", ""),
    op(0x60, "iadd", O::None, 2, 1, 0, M, "arithmetic", "i"),
    op(0x61, "ladd", O::None, 2, 1, 0, M, "arithmetic", "l"),
    op(0x62, "fadd", O::None, 2, 1, 0, M, "arithmetic", "f"),
    op(0x63, "dadd", O::None, 2, 1, 0, M, "arithmetic", "d"),
    op(0x64, "isub", O::None, 2, 1, 0, M, "arithmetic", "i"),
    op(0x65, "lsub", O::None, 2, 1, 0, M, "arithmetic", "l"),
    op(0x66, "fsub", O::None, 2, 1, 0, M, "arithmetic", "f"),
    op(0x67, "dsub", O::None, 2, 1, 0, M, "arithmetic", "d"),
    op(0x68, "imul", O::None, 2, 1, 0, M, "arithmetic", "i"),
    op(0x69, "lmul", O::None, 2, 1, 0, M, "arithmetic", "l"),
    op(0x6a, "fmul", O::None, 2, 1, 0, M, "arithmetic", "f"),
    op(0x6b, "dmul", O::None, 2, 1, 0, M, "arithmetic", "d"),
    op(0x6c, "idiv", O::None, 2, 1, TRAPS, M, "arithmetic", "i"),
    op(0x6d, "ldiv", O::None, 2, 1, TRAPS, M, "arithmetic", "l"),
    op(0x6e, "fdiv", O::None, 2, 1, 0, M, "arithmetic", "f"),
    op(0x6f, "ddiv", O::None, 2, 1, 0, M, "arithmetic", "d"),
    op(0x70, "irem", O::None, 2, 1, TRAPS, M, "arithmetic", "i"),
    op(0x71, "lrem", O::None, 2, 1, TRAPS, M, "arithmetic", "l"),
    op(0x72, "frem", O::None, 2, 1, 0, M, "arithmetic", "f"),
    op(0x73, "drem", O::None, 2, 1, 0, M, "arithmetic", "d"),
    op(0x74, "ineg", O::None, 1, 1, 0, M, "arithmetic", "i"),
    op(0x75, "lneg", O::None, 1, 1, 0, M, "arithmetic", "l"),
    op(0x76, "fneg", O::None, 1, 1, 0, M, "arithmetic", "f"),
    op(0x77, "dneg", O::None, 1, 1, 0, M, "arithmetic", "d"),
    op(0x78, "ishl", O::None, 2, 1, 0, M, "shift", "i"),
    op(0x79, "lshl", O::None, 2, 1, 0, M, "shift", "l"),
    op(0x7a, "ishr", O::None, 2, 1, 0, M, "shift", "i"),
    op(0x7b, "lshr", O::None, 2, 1, 0, M, "shift", "l"),
    op(0x7c, "iushr", O::None, 2, 1, 0, M, "shift", "i"),
    op(0x7d, "lushr", O::None, 2, 1, 0, M, "shift", "l"),
    op(0x7e, "iand", O::None, 2, 1, 0, M, "logic", "i"),
    op(0x7f, "land", O::None, 2, 1, 0, M, "logic", "l"),
    op(0x80, "ior", O::None, 2, 1, 0, M, "logic", "i"),
    op(0x81, "lor", O::None, 2, 1, 0, M, "logic", "l"),
    op(0x82, "ixor", O::None, 2, 1, 0, M, "logic", "i"),
    op(0x83, "lxor", O::None, 2, 1, 0, M, "logic", "l"),
    op(0x84, "iinc", O::Iinc, 0, 0, 0, M, "arithmetic", ""),
    op(0x85, "i2l", O::None, 1, 1, 0, V, "conversion", "l"),
    op(0x86, "i2f", O::None, 1, 1, 0, V, "conversion", "f"),
    op(0x87, "i2d", O::None, 1, 1, 0, V, "conversion", "d"),
    op(0x88, "l2i", O::None, 1, 1, 0, V, "conversion", "i"),
    op(0x89, "l2f", O::None, 1, 1, 0, V, "conversion", "f"),
    op(0x8a, "l2d", O::None, 1, 1, 0, V, "conversion", "d"),
    op(0x8b, "f2i", O::None, 1, 1, 0, V, "conversion", "i"),
    op(0x8c, "f2l", O::None, 1, 1, 0, V, "conversion", "l"),
    op(0x8d, "f2d", O::None, 1, 1, 0, V, "conversion", "d"),
    op(0x8e, "d2i", O::None, 1, 1, 0, V, "conversion", "i"),
    op(0x8f, "d2l", O::None, 1, 1, 0, V, "conversion", "l"),
    op(0x90, "d2f", O::None, 1, 1, 0, V, "conversion", "f"),
    op(0x91, "i2b", O::None, 1, 1, 0, V, "conversion", "i"),
    op(0x92, "i2c", O::None, 1, 1, 0, V, "conversion", "i"),
    op(0x93, "i2s", O::None, 1, 1, 0, V, "conversion", "i"),
    op(0x94, "lcmp", O::None, 2, 1, COMPARE, P, "compare", "i"),
    op(0x95, "fcmpl", O::None, 2, 1, COMPARE, P, "compare", "i"),
    op(0x96, "fcmpg", O::None, 2, 1, COMPARE, P, "compare", "i"),
    op(0x97, "dcmpl", O::None, 2, 1, COMPARE, P, "compare", "i"),
    op(0x98, "dcmpg", O::None, 2, 1, COMPARE, P, "compare", "i"),
    op(0x99, "ifeq", O::Branch16, 1, 0, IF, P, "branch", ""),
    op(0x9a, "ifne", O::Branch16, 1, 0, IF, P, "branch", ""),
    op(0x9b, "iflt", O::Branch16, 1, 0, IF, P, "branch", ""),
    op(0x9c, "ifge", O::Branch16, 1, 0, IF, P, "branch", ""),
    op(0x9d, "ifgt", O::Branch16, 1, 0, IF, P, "branch", ""),
    op(0x9e, "ifle", O::Branch16, 1, 0, IF, P, "branch", ""),
    op(0x9f, "if_icmpeq", O::Branch16, 2, 0, IF, P, "branch", ""),
    op(0xa0, "if_icmpne", O::Branch16, 2, 0, IF, P, "branch", ""),
    op(0xa1, "if_icmplt", O::Branch16, 2, 0, IF, P, "branch", ""),
    op(0xa2, "if_icmpge", O::Branch16, 2, 0, IF, P, "branch", ""),
    op(0xa3, "if_icmpgt", O::Branch16, 2, 0, IF, P, "branch", ""),
    op(0xa4, "if_icmple", O::Branch16, 2, 0, IF, P, "branch", ""),
    op(0xa5, "if_acmpeq", O::Branch16, 2, 0, IF, P, "branch", ""),
    op(0xa6, "if_acmpne", O::Branch16, 2, 0, IF, P, "branch", ""),
    op(0xa7, "goto", O::Branch16, 0, 0, BRANCH | END, T, "branch", ""),
    op(0xa8, "jsr", O::Jsr16, 0, 1, BRANCH | SUBROUTINE, T, "branch", "r"),
    op(0xa9, "ret", O::Ret, 0, 0, END | SUBROUTINE, T, "branch", ""),
    op(0xaa, "tableswitch", O::TableSwitch, 1, 0, IF | END, T, "branch", ""),
    op(0xab, "lookupswitch", O::LookupSwitch, 1, 0, IF | END, T, "branch", ""),
    op(0xac, "ireturn", O::None, 1, 0, RETURN | END | TRAPS, T, "branch", ""),
    op(0xad, "lreturn", O::None, 1, 0, RETURN | END | TRAPS, T, "branch", ""),
    op(0xae, "freturn", O::None, 1, 0, RETURN | END | TRAPS, T, "branch", ""),
    op(0xaf, "dreturn", O::None, 1, 0, RETURN | END | TRAPS, T, "branch", ""),
    op(0xb0, "areturn", O::None, 1, 0, RETURN | END | TRAPS, T, "branch", ""),
    op(0xb1, "return", O::None, 0, 0, RETURN | END | TRAPS, T, "branch", ""),
    op(0xb2, "getstatic", O::Cp16, 0, 1, LOAD | TRAPS, R, "object", ""),
    op(0xb3, "putstatic", O::Cp16, 1, 0, STORE | TRAPS, R, "object", ""),
    op(0xb4, "getfield", O::Cp16, 1, 1, LOAD | TRAPS, R, "object", ""),
    op(0xb5, "putfield", O::Cp16, 2, 0, STORE | TRAPS, R, "object", ""),
    op(0xb6, "invokevirtual", O::Cp16, -1, -1, CALL | TRAPS, R, "call", ""),
    op(0xb7, "invokespecial", O::Cp16, -1, -1, CALL | TRAPS, R, "call", ""),
    op(0xb8, "invokestatic", O::Cp16, -1, -1, CALL | TRAPS, R, "call", ""),
    op(0xb9, "invokeinterface", O::Interface, -1, -1, CALL | TRAPS, R, "call", ""),
    op(0xba, "invokedynamic", O::Dynamic, -1, -1, CALL | TRAPS, R, "call", ""),
    op(0xbb, "new", O::Cp16, 0, 1, TRAPS, R, "object", "a"),
    op(0xbc, "newarray", O::Atype, 1, 1, TRAPS, R, "array", "a"),
    op(0xbd, "anewarray", O::Cp16, 1, 1, TRAPS, R, "array", "a"),
    op(0xbe, "arraylength", O::None, 1, 1, TRAPS, R, "array", "i"),
    op(0xbf, "athrow", O::None, 1, 0, THROW | END | TRAPS, R, "exception", ""),
    op(0xc0, "checkcast", O::Cp16, 1, 1, TRAPS, R, "object", "a"),
    op(0xc1, "instanceof", O::Cp16, 1, 1, TRAPS, R, "object", "i"),
    op(0xc2, "monitorenter", O::None, 1, 0, TRAPS, R, "system", ""),
    op(0xc3, "monitorexit", O::None, 1, 0, TRAPS, R, "system", ""),
    op(0xc5, "multianewarray", O::Dimensions, -1, 1, TRAPS, X, "array", "a"),
    op(0xc6, "ifnull", O::Branch16, 1, 0, IF, X, "branch", ""),
    op(0xc7, "ifnonnull", O::Branch16, 1, 0, IF, X, "branch", ""),
    op(0xc8, "goto_w", O::Branch32, 0, 0, BRANCH | END, X, "branch", ""),
    op(0xc9, "jsr_w", O::Jsr32, 0, 1, BRANCH | SUBROUTINE, X, "branch", "r"),
    // The wide forms: 0xC4 and the opcode they widen.
    op(0xc415, "iload_w", O::LocalW, 0, 1, 0, X, "variable", "i"),
    op(0xc416, "lload_w", O::LocalW, 0, 1, 0, X, "variable", "l"),
    op(0xc417, "fload_w", O::LocalW, 0, 1, 0, X, "variable", "f"),
    op(0xc418, "dload_w", O::LocalW, 0, 1, 0, X, "variable", "d"),
    op(0xc419, "aload_w", O::LocalW, 0, 1, 0, X, "variable", "a"),
    op(0xc436, "istore_w", O::LocalW, 1, 0, 0, X, "variable", ""),
    op(0xc437, "lstore_w", O::LocalW, 1, 0, 0, X, "variable", ""),
    op(0xc438, "fstore_w", O::LocalW, 1, 0, 0, X, "variable", ""),
    op(0xc439, "dstore_w", O::LocalW, 1, 0, 0, X, "variable", ""),
    op(0xc43a, "astore_w", O::LocalW, 1, 0, 0, X, "variable", ""),
    op(0xc484, "iinc_w", O::IincW, 0, 0, 0, X, "arithmetic", ""),
    op(0xc4a9, "ret_w", O::RetW, 0, 0, END | SUBROUTINE, X, "branch", ""),
];

/// Every opcode, the wide forms last.
pub static ALL: [OpInfo; 213] = ROWS;

const NONE: u8 = 0xff;

/// Row numbers by the opcode's byte (`NONE` where there is none), or the wide forms' by the byte they widen.
const fn index(wide: bool) -> [u8; 256] {
    let mut out = [NONE; 256];
    let mut k = 0;
    while k < ROWS.len() {
        let code = ROWS[k].code;
        if (code > 0xff) == wide {
            out[(code & 0xff) as usize] = k as u8;
        }
        k += 1;
    }
    out
}

static ONE_INDEX: [u8; 256] = index(false);
static WIDE_INDEX: [u8; 256] = index(true);

/// The opcode of a byte (`ONE[byte]`).
#[inline]
pub fn one(byte: u8) -> Option<&'static OpInfo> {
    match ONE_INDEX[byte as usize] {
        NONE => None,
        k => Some(&ALL[k as usize]),
    }
}

/// The wide form of the opcode `byte` (`WIDE[byte]`): what follows 0xC4.
#[inline]
pub fn wide(byte: u8) -> Option<&'static OpInfo> {
    match WIDE_INDEX[byte as usize] {
        NONE => None,
        k => Some(&ALL[k as usize]),
    }
}

pub fn all_ops() -> &'static [OpInfo] {
    &ALL
}

/// The opcode as the bytes it is written with: `B6`, `C4 15`.
pub fn opcode_text(code: u16) -> String {
    if code > 0xff {
        format!("C4 {:02X}", code & 0xff)
    } else {
        format!("{code:02X}")
    }
}

/// newarray's element types, by its operand (`ATYPES`).
pub fn atype(value: i64) -> Option<&'static str> {
    Some(match value {
        4 => "boolean",
        5 => "char",
        6 => "float",
        7 => "double",
        8 => "byte",
        9 => "short",
        10 => "int",
        11 => "long",
        _ => return None,
    })
}
