//! MSVC symbol names (`?f@@YAXXZ`) back to declarations, printed as LLVM's
//! llvm-undname prints them (`void __cdecl f(void)`), so that
//! tools/verify-msvc.mjs can compare the two line by line.
//!
//! The name is read into a small tree — symbols, qualified names, types — the
//! way LLVM's Microsoft demangler reads it, with its two tables of back
//! references (the first ten names, and the first ten parameter types longer
//! than one letter), and the tree prints itself. A name that does not parse is
//! returned as None and shown as it is.
//!
//! The tree's nodes live in arenas and point at each other by index: a back
//! reference is the same node seen twice, and a node filled in after it was
//! linked (a conversion operator's type, a constructor's class) is seen filled
//! in from everywhere, as the objects of the TypeScript original were.

use super::Units;
use core::mem;

mod q {
    pub const CONST: u8 = 1;
    pub const VOLATILE: u8 = 2;
    pub const UNALIGNED: u8 = 16;
    pub const RESTRICT: u8 = 32;
    pub const POINTER64: u8 = 64;
}

mod fc {
    pub const NONE: u32 = 0;
    pub const PUBLIC: u32 = 1;
    pub const PROTECTED: u32 = 2;
    pub const PRIVATE: u32 = 4;
    pub const GLOBAL: u32 = 8;
    pub const STATIC: u32 = 16;
    pub const VIRTUAL: u32 = 32;
    pub const FAR: u32 = 64;
    pub const EXTERN_C: u32 = 128;
    pub const NO_PARAMETER_LIST: u32 = 256;
    pub const VIRTUAL_THIS_ADJUST: u32 = 512;
    pub const VIRTUAL_THIS_ADJUST_EX: u32 = 1024;
    pub const STATIC_THIS_ADJUST: u32 = 2048;
}

/// Output flags: what llvm-undname's --no-… options leave out.
pub mod of {
    pub const DEFAULT: u32 = 0;
    pub const NO_CALLING_CONVENTION: u32 = 1;
    pub const NO_TAG_SPECIFIER: u32 = 2;
    pub const NO_ACCESS_SPECIFIER: u32 = 4;
    pub const NO_MEMBER_TYPE: u32 = 8;
    pub const NO_RETURN_TYPE: u32 = 16;
    pub const NO_VARIABLE_TYPE: u32 = 32;
}
const OF_MINIMAL: u32 = of::NO_CALLING_CONVENTION | of::NO_ACCESS_SPECIFIER | of::NO_MEMBER_TYPE | of::NO_RETURN_TYPE | of::NO_VARIABLE_TYPE;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Affinity {
    None,
    Pointer,
    Reference,
    Rvalue,
}

/// The name does not parse.
struct Bad;

type R<T> = Result<T, Bad>;

type TypeId = u32;
type IdentId = u32;
type NameId = u32;
type SymId = u32;
type ArrId = u32;
type RefId = u32;

#[derive(Clone)]
struct Thunk {
    static_offset: i64,
    vbptr_offset: i64,
    vboffset_offset: i64,
    vtordisp_offset: i64,
}

#[derive(Clone)]
struct Signature {
    calling_convention: &'static str,
    function_class: u32,
    ref_qualifier: &'static str,
    return_type: Option<TypeId>,
    variadic: bool,
    params: Option<ArrId>,
    noexcept: bool,
    /// Present on a thunk's signature (`[thunk]: …`, with its this-adjustments).
    thunk: Option<Thunk>,
}

impl Signature {
    fn new() -> Signature {
        Signature { calling_convention: "", function_class: fc::GLOBAL, ref_qualifier: "", return_type: None, variadic: false, params: None, noexcept: false, thunk: None }
    }
}

enum TypeKind {
    Primitive(&'static str),
    Function(Signature),
    Pointer { affinity: Affinity, class_parent: Option<NameId>, pointer_auth: Option<ArrId>, pointee: TypeId },
    Tag { tag: &'static str, name: NameId },
    Array { dimensions: Vec<u64>, element: TypeId },
    Custom(IdentId),
}

struct Type {
    quals: u8,
    kind: TypeKind,
}

enum IdentKind {
    Named(String),
    Text(&'static str),
    ConversionOperator { target: Option<TypeId> },
    Structor { destructor: bool, cls: Option<IdentId> },
    LiteralOperator(String),
    LocalStaticGuard { thread: bool, scope_index: u32 },
    VcallThunk { offset: u64 },
    RttiBaseClassDescriptor([i64; 4]),
    DynamicStructor { destructor: bool, variable: Option<SymId>, name: Option<NameId> },
}

struct Ident {
    template_params: Option<ArrId>,
    kind: IdentKind,
}

#[derive(Clone, Copy)]
enum Node {
    Type(TypeId),
    Name(NameId),
    Literal { value: u64, negative: bool },
    TemplateRef(RefId),
}

struct TemplateRef {
    symbol: Option<SymId>,
    offsets: Vec<i64>,
    affinity: Affinity,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Storage {
    None,
    Private,
    Protected,
    Public,
    Global,
    Local,
}

enum SymKind {
    Plain,
    SpecialTable { target: Option<NameId>, quals: u8 },
    StringLiteral { text: String, truncated: bool, prefix: &'static str },
    Variable { storage: Storage, ty: Option<TypeId> },
    Function { signature: TypeId },
}

struct Sym {
    name: Option<NameId>,
    kind: SymKind,
}

#[derive(Default)]
struct Tree {
    types: Vec<Type>,
    idents: Vec<Ident>,
    names: Vec<Vec<IdentId>>,
    syms: Vec<Sym>,
    arrays: Vec<Vec<Node>>,
    refs: Vec<TemplateRef>,
}

impl Tree {
    fn add_type(&mut self, quals: u8, kind: TypeKind) -> TypeId {
        self.types.push(Type { quals, kind });
        (self.types.len() - 1) as TypeId
    }
    fn add_ident(&mut self, kind: IdentKind) -> IdentId {
        self.idents.push(Ident { template_params: None, kind });
        (self.idents.len() - 1) as IdentId
    }
    fn add_name(&mut self, components: Vec<IdentId>) -> NameId {
        self.names.push(components);
        (self.names.len() - 1) as NameId
    }
    fn add_sym(&mut self, name: Option<NameId>, kind: SymKind) -> SymId {
        self.syms.push(Sym { name, kind });
        (self.syms.len() - 1) as SymId
    }
    fn add_array(&mut self, nodes: Vec<Node>) -> ArrId {
        self.arrays.push(nodes);
        (self.arrays.len() - 1) as ArrId
    }
    fn last(&self, name: NameId) -> IdentId {
        *self.names[name as usize].last().unwrap()
    }
    fn signature(&self, t: TypeId) -> Option<&Signature> {
        match &self.types[t as usize].kind {
            TypeKind::Function(sig) => Some(sig),
            _ => None,
        }
    }
    fn signature_mut(&mut self, t: TypeId) -> &mut Signature {
        match &mut self.types[t as usize].kind {
            TypeKind::Function(sig) => sig,
            _ => unreachable!("not a function signature"),
        }
    }
}

/* ------------------------------------------------------------------ *
 * Printing
 * ------------------------------------------------------------------ */

struct Out<'t> {
    t: &'t Tree,
    s: String,
    /// Template arguments inside template arguments print as `<…>` (the short form).
    fold: bool,
    templates: u32,
}

impl<'t> Out<'t> {
    fn new(t: &'t Tree) -> Out<'t> {
        Out { t, s: String::new(), fold: false, templates: 0 }
    }

    fn template_parameters(&mut self, params: ArrId, f: u32) {
        if self.fold && self.templates > 0 {
            self.s.push_str("<…>");
            return;
        }
        self.templates += 1;
        self.s.push('<');
        self.array(params, f, ", ");
        self.s.push('>');
        self.templates -= 1;
    }

    fn back(&self) -> u8 {
        self.s.as_bytes().last().copied().unwrap_or(0)
    }

    /// A space unless the last token ends with punctuation.
    fn space_if_necessary(&mut self) {
        let c = self.back();
        if c.is_ascii_alphanumeric() || c == b'>' {
            self.s.push(' ');
        }
    }

    fn qualifiers(&mut self, quals: u8, mut space_before: bool, space_after: bool) {
        if quals & (q::CONST | q::VOLATILE | q::RESTRICT) == 0 {
            return;
        }
        let start = self.s.len();
        for (mask, text) in [(q::CONST, "const"), (q::VOLATILE, "volatile"), (q::RESTRICT, "__restrict")] {
            if quals & mask == 0 {
                continue;
            }
            if space_before {
                self.s.push(' ');
            }
            self.s.push_str(text);
            space_before = true;
        }
        if space_after && self.s.len() > start {
            self.s.push(' ');
        }
    }

    fn calling_convention(&mut self, cc: &str) {
        self.space_if_necessary();
        self.s.push_str(cc);
    }

    fn array(&mut self, a: ArrId, f: u32, separator: &str) {
        let nodes = &self.t.arrays[a as usize];
        for (i, &n) in nodes.iter().enumerate() {
            if i > 0 {
                self.s.push_str(separator);
            }
            self.node(n, f);
        }
    }

    fn node(&mut self, n: Node, f: u32) {
        match n {
            Node::Type(t) => self.type_(t, f),
            Node::Name(name) => self.name(name, f),
            Node::Literal { value, negative } => {
                if negative {
                    self.s.push('-');
                }
                self.s.push_str(&value.to_string());
            }
            Node::TemplateRef(r) => self.template_ref(r, f),
        }
    }

    fn template_ref(&mut self, r: RefId, f: u32) {
        let r = &self.t.refs[r as usize];
        if !r.offsets.is_empty() {
            self.s.push('{');
        } else if r.affinity == Affinity::Pointer {
            self.s.push('&');
        }
        if let Some(sym) = r.symbol {
            self.sym(sym, f);
            if !r.offsets.is_empty() {
                self.s.push_str(", ");
            }
        }
        if !r.offsets.is_empty() {
            self.s.push_str(&r.offsets.iter().map(i64::to_string).collect::<Vec<_>>().join(", "));
            self.s.push('}');
        }
    }

    fn type_(&mut self, t: TypeId, f: u32) {
        self.type_pre(t, f);
        self.type_post(t, f);
    }

    fn type_pre(&mut self, t: TypeId, f: u32) {
        let ty = &self.t.types[t as usize];
        match &ty.kind {
            TypeKind::Primitive(name) => {
                self.s.push_str(name);
                self.qualifiers(ty.quals, true, false);
            }
            TypeKind::Function(sig) => self.signature_pre(sig, f),
            TypeKind::Pointer { affinity, class_parent, pointer_auth, pointee } => {
                let fun = self.t.signature(*pointee).filter(|s| s.thunk.is_none());
                if fun.is_some() {
                    self.type_pre(*pointee, of::NO_CALLING_CONVENTION);
                } else {
                    self.type_pre(*pointee, f);
                }
                self.space_if_necessary();
                if ty.quals & q::UNALIGNED != 0 {
                    self.s.push_str("__unaligned ");
                }
                if matches!(self.t.types[*pointee as usize].kind, TypeKind::Array { .. }) {
                    self.s.push('(');
                } else if let Some(fun) = fun {
                    self.s.push('(');
                    self.calling_convention(fun.calling_convention);
                    self.s.push(' ');
                }
                if let Some(parent) = class_parent {
                    self.name(*parent, f);
                    self.s.push_str("::");
                }
                self.s.push_str(match affinity {
                    Affinity::Pointer => "*",
                    Affinity::Reference => "&",
                    Affinity::Rvalue => "&&",
                    Affinity::None => "",
                });
                self.qualifiers(ty.quals, false, false);
                if let Some(auth) = pointer_auth {
                    self.s.push_str("__ptrauth(");
                    self.array(*auth, f, ", ");
                    self.s.push(')');
                }
            }
            TypeKind::Tag { tag, name } => {
                if f & of::NO_TAG_SPECIFIER == 0 {
                    self.s.push_str(tag);
                    self.s.push(' ');
                }
                self.name(*name, f);
                self.qualifiers(ty.quals, true, false);
            }
            TypeKind::Array { element, .. } => {
                self.type_pre(*element, f);
                self.qualifiers(ty.quals, true, false);
            }
            TypeKind::Custom(id) => self.ident(*id, f),
        }
    }

    fn type_post(&mut self, t: TypeId, f: u32) {
        let ty = &self.t.types[t as usize];
        match &ty.kind {
            TypeKind::Primitive(_) | TypeKind::Tag { .. } | TypeKind::Custom(_) => {}
            TypeKind::Function(sig) => self.signature_post(sig, ty.quals, f),
            TypeKind::Pointer { pointee, .. } => {
                let pointee_ty = &self.t.types[*pointee as usize];
                let paren = match &pointee_ty.kind {
                    TypeKind::Array { .. } => true,
                    TypeKind::Function(sig) => sig.thunk.is_none(),
                    _ => false,
                };
                if paren {
                    self.s.push(')');
                }
                self.type_post(*pointee, f);
            }
            TypeKind::Array { dimensions, element } => {
                self.s.push('[');
                for (i, &d) in dimensions.iter().enumerate() {
                    if i > 0 {
                        self.s.push_str("][");
                    }
                    if d != 0 {
                        self.s.push_str(&d.to_string());
                    }
                }
                self.s.push(']');
                self.type_post(*element, f);
            }
        }
    }

    fn signature_pre(&mut self, sig: &Signature, f: u32) {
        if sig.thunk.is_some() {
            self.s.push_str("[thunk]: ");
        }
        let class = sig.function_class;
        if f & of::NO_ACCESS_SPECIFIER == 0 {
            if class & fc::PUBLIC != 0 {
                self.s.push_str("public: ");
            }
            if class & fc::PROTECTED != 0 {
                self.s.push_str("protected: ");
            }
            if class & fc::PRIVATE != 0 {
                self.s.push_str("private: ");
            }
        }
        if f & of::NO_MEMBER_TYPE == 0 {
            if class & fc::GLOBAL == 0 && class & fc::STATIC != 0 {
                self.s.push_str("static ");
            }
            if class & fc::VIRTUAL != 0 {
                self.s.push_str("virtual ");
            }
            if class & fc::EXTERN_C != 0 {
                self.s.push_str("extern \"C\" ");
            }
        }
        if f & of::NO_RETURN_TYPE == 0 {
            if let Some(ret) = sig.return_type {
                self.type_pre(ret, f);
                self.s.push(' ');
            }
        }
        if f & of::NO_CALLING_CONVENTION == 0 {
            self.calling_convention(sig.calling_convention);
        }
    }

    fn signature_post(&mut self, sig: &Signature, quals: u8, f: u32) {
        let class = sig.function_class;
        if let Some(thunk) = &sig.thunk {
            if class & fc::STATIC_THIS_ADJUST != 0 {
                self.s.push_str(&format!("`adjustor{{{}}}'", thunk.static_offset));
            } else if class & fc::VIRTUAL_THIS_ADJUST != 0 {
                if class & fc::VIRTUAL_THIS_ADJUST_EX != 0 {
                    self.s.push_str(&format!("`vtordispex{{{}, {}, {}, {}}}'", thunk.vbptr_offset, thunk.vboffset_offset, thunk.vtordisp_offset, thunk.static_offset));
                } else {
                    self.s.push_str(&format!("`vtordisp{{{}, {}}}'", thunk.vtordisp_offset, thunk.static_offset));
                }
            }
        }
        if class & fc::NO_PARAMETER_LIST == 0 {
            self.s.push('(');
            match sig.params {
                Some(params) => self.array(params, f, ", "),
                None => self.s.push_str("void"),
            }
            if sig.variadic {
                if self.back() != b'(' {
                    self.s.push_str(", ");
                }
                self.s.push_str("...");
            }
            self.s.push(')');
        }
        if quals & q::CONST != 0 {
            self.s.push_str(" const");
        }
        if quals & q::VOLATILE != 0 {
            self.s.push_str(" volatile");
        }
        if quals & q::RESTRICT != 0 {
            self.s.push_str(" __restrict");
        }
        if quals & q::UNALIGNED != 0 {
            self.s.push_str(" __unaligned");
        }
        if sig.noexcept {
            self.s.push_str(" noexcept");
        }
        if !sig.ref_qualifier.is_empty() {
            self.s.push(' ');
            self.s.push_str(sig.ref_qualifier);
        }
        if f & of::NO_RETURN_TYPE == 0 {
            if let Some(ret) = sig.return_type {
                self.type_post(ret, f);
            }
        }
    }

    fn template_params_of(&mut self, id: &Ident, f: u32) {
        if let Some(params) = id.template_params {
            self.template_parameters(params, f);
        }
    }

    fn ident(&mut self, id: IdentId, f: u32) {
        let ident = &self.t.idents[id as usize];
        match &ident.kind {
            IdentKind::Named(name) => {
                self.s.push_str(name);
                self.template_params_of(ident, f);
            }
            IdentKind::Text(text) => {
                self.s.push_str(text);
                self.template_params_of(ident, f);
            }
            IdentKind::ConversionOperator { target } => {
                self.s.push_str("operator");
                self.template_params_of(ident, f);
                self.s.push(' ');
                if let Some(target) = target {
                    self.type_(*target, f);
                }
            }
            IdentKind::Structor { destructor, cls } => {
                if *destructor {
                    self.s.push('~');
                }
                if let Some(cls) = cls {
                    self.ident(*cls, f);
                }
                self.template_params_of(ident, f);
            }
            IdentKind::LiteralOperator(name) => {
                self.s.push_str("operator \"\"");
                self.s.push_str(name);
                self.template_params_of(ident, f);
            }
            IdentKind::LocalStaticGuard { thread, scope_index } => {
                self.s.push_str(if *thread { "`local static thread guard'" } else { "`local static guard'" });
                if *scope_index > 0 {
                    self.s.push_str(&format!("{{{scope_index}}}"));
                }
            }
            IdentKind::VcallThunk { offset } => self.s.push_str(&format!("`vcall'{{{offset}, {{flat}}}}")),
            IdentKind::RttiBaseClassDescriptor(v) => {
                self.s.push_str(&format!("`RTTI Base Class Descriptor at ({}, {}, {}, {})'", v[0], v[1], v[2], v[3]));
            }
            IdentKind::DynamicStructor { destructor, variable, name } => {
                self.s.push_str(if *destructor { "`dynamic atexit destructor for " } else { "`dynamic initializer for " });
                if let Some(variable) = variable {
                    self.s.push('`');
                    self.sym(*variable, f);
                    self.s.push_str("''");
                } else {
                    self.s.push('\'');
                    if let Some(name) = name {
                        self.name(*name, f);
                    }
                    self.s.push_str("''");
                }
            }
        }
    }

    fn name(&mut self, name: NameId, f: u32) {
        for (i, &c) in self.t.names[name as usize].iter().enumerate() {
            if i > 0 {
                self.s.push_str("::");
            }
            self.ident(c, f);
        }
    }

    fn opt_name(&mut self, name: Option<NameId>, f: u32) {
        if let Some(name) = name {
            self.name(name, f);
        }
    }

    fn sym(&mut self, s: SymId, f: u32) {
        let sym = &self.t.syms[s as usize];
        match &sym.kind {
            SymKind::Plain => self.opt_name(sym.name, f),
            SymKind::SpecialTable { target, quals } => {
                self.qualifiers(*quals, false, true);
                self.opt_name(sym.name, f);
                if let Some(target) = target {
                    self.s.push_str("{for `");
                    self.name(*target, f);
                    self.s.push_str("'}");
                }
            }
            SymKind::StringLiteral { text, truncated, prefix } => {
                self.s.push_str(prefix);
                self.s.push_str(text);
                self.s.push('"');
                if *truncated {
                    self.s.push_str("...");
                }
            }
            SymKind::Variable { storage, ty } => {
                let access = match storage {
                    Storage::Private => "private",
                    Storage::Protected => "protected",
                    Storage::Public => "public",
                    _ => "",
                };
                if f & of::NO_ACCESS_SPECIFIER == 0 && !access.is_empty() {
                    self.s.push_str(access);
                    self.s.push_str(": ");
                }
                if f & of::NO_MEMBER_TYPE == 0 && !access.is_empty() {
                    self.s.push_str("static ");
                }
                let ty = if f & of::NO_VARIABLE_TYPE == 0 { *ty } else { None };
                if let Some(ty) = ty {
                    self.type_pre(ty, f);
                    self.space_if_necessary();
                }
                self.opt_name(sym.name, f);
                if let Some(ty) = ty {
                    self.type_post(ty, f);
                }
            }
            SymKind::Function { signature } => {
                self.type_pre(*signature, f);
                self.space_if_necessary();
                self.opt_name(sym.name, f);
                self.type_post(*signature, f);
            }
        }
    }
}

/* ------------------------------------------------------------------ *
 * The parser
 * ------------------------------------------------------------------ */

fn intrinsic_text(code: &[u8]) -> &'static str {
    match code {
        b"2" => "operator new",
        b"3" => "operator delete",
        b"4" => "operator=",
        b"5" => "operator>>",
        b"6" => "operator<<",
        b"7" => "operator!",
        b"8" => "operator==",
        b"9" => "operator!=",
        b"A" => "operator[]",
        b"C" => "operator->",
        b"D" => "operator*",
        b"E" => "operator++",
        b"F" => "operator--",
        b"G" => "operator-",
        b"H" => "operator+",
        b"I" => "operator&",
        b"J" => "operator->*",
        b"K" => "operator/",
        b"L" => "operator%",
        b"M" => "operator<",
        b"N" => "operator<=",
        b"O" => "operator>",
        b"P" => "operator>=",
        b"Q" => "operator,",
        b"R" => "operator()",
        b"S" => "operator~",
        b"T" => "operator^",
        b"U" => "operator|",
        b"V" => "operator&&",
        b"W" => "operator||",
        b"X" => "operator*=",
        b"Y" => "operator+=",
        b"Z" => "operator-=",
        b"_0" => "operator/=",
        b"_1" => "operator%=",
        b"_2" => "operator>>=",
        b"_3" => "operator<<=",
        b"_4" => "operator&=",
        b"_5" => "operator|=",
        b"_6" => "operator^=",
        b"_D" => "`vbase dtor'",
        b"_E" => "`vector deleting dtor'",
        b"_F" => "`default ctor closure'",
        b"_G" => "`scalar deleting dtor'",
        b"_H" => "`vector ctor iterator'",
        b"_I" => "`vector dtor iterator'",
        b"_J" => "`vector vbase ctor iterator'",
        b"_K" => "`virtual displacement map'",
        b"_L" => "`eh vector ctor iterator'",
        b"_M" => "`eh vector dtor iterator'",
        b"_N" => "`eh vector vbase ctor iterator'",
        b"_O" => "`copy ctor closure'",
        b"_T" => "`local vftable ctor closure'",
        b"_U" => "operator new[]",
        b"_V" => "operator delete[]",
        b"__A" => "`managed vector ctor iterator'",
        b"__B" => "`managed vector dtor iterator'",
        b"__C" => "`EH vector copy ctor iterator'",
        b"__D" => "`EH vector vbase copy ctor iterator'",
        b"__G" => "`vector copy ctor iterator'",
        b"__H" => "`vector vbase copy constructor iterator'",
        b"__I" => "`managed vector vbase copy constructor iterator'",
        b"__L" => "operator co_await",
        b"__M" => "operator<=>",
        // Codes with no text of their own print nothing, as llvm-undname prints them.
        _ => "",
    }
}

fn primitive(code: &[u8]) -> Option<&'static str> {
    Some(match code {
        b"X" => "void",
        b"D" => "char",
        b"C" => "signed char",
        b"E" => "unsigned char",
        b"F" => "short",
        b"G" => "unsigned short",
        b"H" => "int",
        b"I" => "unsigned int",
        b"J" => "long",
        b"K" => "unsigned long",
        b"M" => "float",
        b"N" => "double",
        b"O" => "long double",
        b"_N" => "bool",
        b"_J" => "__int64",
        b"_K" => "unsigned __int64",
        b"_W" => "wchar_t",
        b"_Q" => "char8_t",
        b"_S" => "char16_t",
        b"_U" => "char32_t",
        b"_P" => "auto",
        b"_T" => "decltype(auto)",
        _ => return None,
    })
}

fn function_class_of(c: u8) -> Option<u32> {
    use fc::*;
    Some(match c {
        b'A' => PRIVATE,
        b'B' => PRIVATE | FAR,
        b'C' => PRIVATE | STATIC,
        b'D' => PRIVATE | STATIC | FAR,
        b'E' => PRIVATE | VIRTUAL,
        b'F' => PRIVATE | VIRTUAL | FAR,
        b'G' => PRIVATE | STATIC_THIS_ADJUST,
        b'H' => PRIVATE | STATIC_THIS_ADJUST | FAR,
        b'I' => PROTECTED,
        b'J' => PROTECTED | FAR,
        b'K' => PROTECTED | STATIC,
        b'L' => PROTECTED | STATIC | FAR,
        b'M' => PROTECTED | VIRTUAL,
        b'N' => PROTECTED | VIRTUAL | FAR,
        b'O' => PROTECTED | VIRTUAL | STATIC_THIS_ADJUST,
        b'P' => PROTECTED | VIRTUAL | STATIC_THIS_ADJUST | FAR,
        b'Q' => PUBLIC,
        b'R' => PUBLIC | FAR,
        b'S' => PUBLIC | STATIC,
        b'T' => PUBLIC | STATIC | FAR,
        b'U' => PUBLIC | VIRTUAL,
        b'V' => PUBLIC | VIRTUAL | FAR,
        b'W' => PUBLIC | VIRTUAL | STATIC_THIS_ADJUST,
        b'X' => PUBLIC | VIRTUAL | STATIC_THIS_ADJUST | FAR,
        b'Y' => GLOBAL,
        b'Z' => GLOBAL | FAR,
        b'9' => EXTERN_C | NO_PARAMETER_LIST,
        _ => return None,
    })
}

fn calling_convention_of(c: u8) -> &'static str {
    match c {
        b'A' | b'B' => "__cdecl",
        b'C' | b'D' => "__pascal",
        b'E' | b'F' => "__thiscall",
        b'G' | b'H' => "__stdcall",
        b'I' | b'J' => "__fastcall",
        b'M' | b'N' => "__clrcall",
        b'O' | b'P' => "__eabi",
        b'Q' => "__vectorcall",
        b'S' => "__attribute__((__swiftcall__)) ",
        b'W' => "__attribute__((__swiftasynccall__)) ",
        _ => "",
    }
}

fn is_digit(c: Option<u8>) -> bool {
    matches!(c, Some(b'0'..=b'9'))
}

#[derive(Default)]
struct Backrefs {
    names: Vec<IdentId>,
    params: Vec<TypeId>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Mangle,
    Result,
    Drop,
}

/// How deep template names may nest inside one another. The TypeScript gave
/// up only when JavaScript's stack ran out; this keeps the native stack safe.
const MAX_TEMPLATE_NESTING: u32 = 512;

struct Demangler<'a> {
    u: &'a Units<'a>,
    s: &'a [u8],
    pos: usize,
    tree: Tree,
    backrefs: Backrefs,
    depth: u32,
    templates: u32,
}

impl<'a> Demangler<'a> {
    fn rest(&self) -> &'a [u8] {
        &self.s[self.pos.min(self.s.len())..]
    }
    fn empty(&self) -> bool {
        self.pos >= self.s.len()
    }
    fn first(&self) -> Option<u8> {
        self.s.get(self.pos).copied()
    }
    fn starts(&self, p: &[u8]) -> bool {
        self.rest().starts_with(p)
    }
    fn consume(&mut self, p: &[u8]) -> bool {
        if !self.starts(p) {
            return false;
        }
        self.pos += p.len();
        true
    }
    fn front(&self) -> R<u8> {
        self.first().ok_or(Bad)
    }
    fn take(&mut self) -> R<u8> {
        let c = self.front()?;
        self.pos += 1;
        Ok(c)
    }
    /// The position of the next `c` at or after `from` characters into what is left, relative to what is left.
    fn index_of(&self, c: u8, from: usize) -> Option<usize> {
        self.rest().iter().skip(from).position(|&u| u == c).map(|i| i + from)
    }

    fn parse(&mut self) -> R<SymId> {
        self.depth += 1;
        if self.depth > 256 {
            return Err(Bad);
        }
        let out = self.parse_body();
        self.depth -= 1;
        out
    }

    fn parse_body(&mut self) -> R<SymId> {
        if self.starts(b".") {
            return self.typeinfo_name();
        }
        if self.starts(b"??@") {
            return self.md5_name();
        }
        if !self.consume(b"?") {
            return Err(Bad);
        }
        match self.special_intrinsic()? {
            Some(sym) => Ok(sym),
            None => self.declarator(),
        }
    }

    fn typeinfo_name(&mut self) -> R<SymId> {
        self.consume(b".");
        let t = self.type_(Mode::Result)?;
        if !self.empty() {
            return Err(Bad);
        }
        Ok(self.synthesize_variable(t, "`RTTI Type Descriptor Name'"))
    }

    fn md5_name(&mut self) -> R<SymId> {
        let end = self.index_of(b'@', 3).ok_or(Bad)?;
        let start = self.pos;
        self.pos += end + 1;
        self.consume(b"??_R4@");
        let text = self.u.text(start, self.pos);
        let id = self.tree.add_ident(IdentKind::Named(text));
        let name = self.tree.add_name(vec![id]);
        Ok(self.tree.add_sym(Some(name), SymKind::Plain))
    }

    fn special_intrinsic(&mut self) -> R<Option<SymId>> {
        const KINDS: [&[u8]; 16] = [b"?_7", b"?_8", b"?_9", b"?_A", b"?_B", b"?_C", b"?_P", b"?_R0", b"?_R1", b"?_R2", b"?_R3", b"?_R4", b"?_S", b"?__E", b"?__F", b"?__J"];
        let Some(&found) = KINDS.iter().find(|p| self.starts(p)) else { return Ok(None) };
        self.consume(found);
        Ok(Some(match found {
            b"?_C" => self.string_literal()?,
            b"?_7" => self.special_table("`vftable'")?,
            b"?_8" => self.special_table("`vbtable'")?,
            b"?_S" => self.special_table("`local vftable'")?,
            b"?_R4" => self.special_table("`RTTI Complete Object Locator'")?,
            b"?_9" => self.vcall_thunk()?,
            b"?_B" => self.local_static_guard(false)?,
            b"?__J" => self.local_static_guard(true)?,
            b"?_R0" => {
                let t = self.type_(Mode::Result)?;
                if !self.consume(b"@8") || !self.empty() {
                    return Err(Bad);
                }
                self.synthesize_variable(t, "`RTTI Type Descriptor'")
            }
            b"?_R2" => self.untyped_variable("`RTTI Base Class Array'")?,
            b"?_R3" => self.untyped_variable("`RTTI Class Hierarchy Descriptor'")?,
            b"?_R1" => {
                // Kept in 32 bits, as LLVM keeps them: the offset of the vbptr signed, the rest unsigned.
                let a = self.unsigned()? as u32 as i64;
                let b = self.signed()? as i32 as i64;
                let c = self.unsigned()? as u32 as i64;
                let d = self.unsigned()? as u32 as i64;
                let id = self.tree.add_ident(IdentKind::RttiBaseClassDescriptor([a, b, c, d]));
                let name = self.name_scope_chain(id)?;
                self.consume(b"8");
                self.tree.add_sym(Some(name), SymKind::Variable { storage: Storage::None, ty: None })
            }
            b"?__E" => self.init_fini_stub(false)?,
            b"?__F" => self.init_fini_stub(true)?,
            _ => return Err(Bad),
        }))
    }

    fn special_table(&mut self, text: &str) -> R<SymId> {
        let id = self.tree.add_ident(IdentKind::Named(text.into()));
        let name = self.name_scope_chain(id)?;
        let c = self.take()?;
        if c != (b'6') && c != (b'7') {
            return Err(Bad);
        }
        let quals = self.qualifiers()?.0;
        let target = if !self.consume(b"@") { Some(self.fully_qualified_type_name()?) } else { None };
        Ok(self.tree.add_sym(Some(name), SymKind::SpecialTable { target, quals }))
    }

    fn local_static_guard(&mut self, thread: bool) -> R<SymId> {
        let id = self.tree.add_ident(IdentKind::LocalStaticGuard { thread, scope_index: 0 });
        let name = self.name_scope_chain(id)?;
        if !self.consume(b"4IA") && !self.consume(b"5") {
            return Err(Bad);
        }
        if !self.empty() {
            let index = self.unsigned()? as u32;
            if let IdentKind::LocalStaticGuard { scope_index, .. } = &mut self.tree.idents[id as usize].kind {
                *scope_index = index;
            }
        }
        Ok(self.tree.add_sym(Some(name), SymKind::Plain))
    }

    fn untyped_variable(&mut self, text: &str) -> R<SymId> {
        let id = self.tree.add_ident(IdentKind::Named(text.into()));
        let name = self.name_scope_chain(id)?;
        if !self.consume(b"8") {
            return Err(Bad);
        }
        Ok(self.tree.add_sym(Some(name), SymKind::Variable { storage: Storage::None, ty: None }))
    }

    fn vcall_thunk(&mut self) -> R<SymId> {
        let id = self.tree.add_ident(IdentKind::VcallThunk { offset: 0 });
        let mut sig = Signature::new();
        sig.thunk = Some(Thunk { static_offset: 0, vbptr_offset: 0, vboffset_offset: 0, vtordisp_offset: 0 });
        sig.function_class = fc::NO_PARAMETER_LIST;
        let name = self.name_scope_chain(id)?;
        if !self.consume(b"$B") {
            return Err(Bad);
        }
        let value = self.unsigned()?;
        if let IdentKind::VcallThunk { offset } = &mut self.tree.idents[id as usize].kind {
            *offset = value;
        }
        if !self.consume(b"A") {
            return Err(Bad);
        }
        sig.calling_convention = self.calling_convention()?;
        let signature = self.tree.add_type(0, TypeKind::Function(sig));
        Ok(self.tree.add_sym(Some(name), SymKind::Function { signature }))
    }

    fn init_fini_stub(&mut self, destructor: bool) -> R<SymId> {
        let id = self.tree.add_ident(IdentKind::DynamicStructor { destructor, variable: None, name: None });
        let known_static_member = self.consume(b"?");
        let symbol = self.declarator()?;
        match self.tree.syms[symbol as usize].kind {
            SymKind::Variable { .. } => {
                if let IdentKind::DynamicStructor { variable, .. } = &mut self.tree.idents[id as usize].kind {
                    *variable = Some(symbol);
                }
                for _ in 0..if known_static_member { 2 } else { 1 } {
                    if !self.consume(b"@") {
                        return Err(Bad);
                    }
                }
                let fun = self.function_encoding()?;
                self.tree.syms[fun as usize].name = Some(self.tree.add_name(vec![id]));
                Ok(fun)
            }
            SymKind::Function { .. } if !known_static_member => {
                let old = self.tree.syms[symbol as usize].name;
                if let IdentKind::DynamicStructor { name, .. } = &mut self.tree.idents[id as usize].kind {
                    *name = old;
                }
                self.tree.syms[symbol as usize].name = Some(self.tree.add_name(vec![id]));
                Ok(symbol)
            }
            _ => Err(Bad),
        }
    }

    fn string_literal(&mut self) -> R<SymId> {
        if !self.consume(b"@_") {
            return Err(Bad);
        }
        let kind = self.take()?;
        if kind != b'0' && kind != (b'1') {
            return Err(Bad);
        }
        let wide = kind == (b'1');
        let (size, negative) = self.number()?;
        // Number(size): a double, as the TypeScript counted the bytes.
        let mut bytes = size as f64;
        if negative || bytes < if wide { 2.0 } else { 1.0 } {
            return Err(Bad);
        }
        let crc_end = self.index_of(b'@', 0).ok_or(Bad)?;
        self.pos += crc_end + 1;
        if self.empty() {
            return Err(Bad);
        }
        let mut text = String::new();
        let prefix;
        let mut truncated = false;
        if wide {
            prefix = "L\"";
            if bytes > 64.0 {
                truncated = true;
            }
            while !self.consume(b"@") {
                if bytes % 2.0 != 0.0 || bytes == 0.0 || self.rest().len() < 2 {
                    return Err(Bad);
                }
                let hi = self.char_literal()?;
                if self.empty() {
                    return Err(Bad);
                }
                let w = (hi << 8) | self.char_literal()?;
                if bytes != 2.0 || truncated {
                    escaped_char(&mut text, w);
                }
                bytes -= 2.0;
            }
        } else {
            let mut decoded: Vec<u32> = Vec::new();
            while !self.consume(b"@") {
                if self.empty() || decoded.len() >= 128 {
                    return Err(Bad);
                }
                decoded.push(self.char_literal()?);
            }
            if bytes > decoded.len() as f64 {
                truncated = true;
            }
            let width = guess_char_byte_size(&decoded, bytes);
            prefix = match width {
                1 => "\"",
                2 => "u\"",
                _ => "U\"",
            };
            let count = decoded.len() / width;
            for i in 0..count {
                let mut c = 0u32;
                for b in 0..width {
                    c |= decoded[i * width + b] << (8 * b);
                }
                if i + 1 < count || truncated {
                    escaped_char(&mut text, c);
                }
            }
        }
        Ok(self.tree.add_sym(None, SymKind::StringLiteral { text, truncated, prefix }))
    }

    fn char_literal(&mut self) -> R<u32> {
        if !self.consume(b"?") {
            // charCodeAt(0) & 0xff: the code unit itself, not its byte here.
            self.front()?;
            let c = self.u.unit(self.pos);
            self.pos += 1;
            return Ok((c & 0xff) as u32);
        }
        if self.empty() {
            return Err(Bad);
        }
        if self.consume(b"$") {
            let rest = self.rest();
            if rest.len() < 2 {
                return Err(Bad);
            }
            let hex = |c: u8| if (b'A'..=b'P').contains(&c) { Some((c - b'A') as u32) } else { None };
            let (Some(a), Some(b)) = (hex(rest[0]), hex(rest[1])) else { return Err(Bad) };
            self.pos += 2;
            return Ok((a << 4) | b);
        }
        let c = self.take()?;
        match c {
            0x30..=0x39 => Ok(b",/\\:. \n\t'-"[(c - 0x30) as usize] as u32),
            0x61..=0x7a => Ok(0xe1 + (c - 0x61) as u32),
            0x41..=0x5a => Ok(0xc1 + (c - 0x41) as u32),
            _ => Err(Bad),
        }
    }

    /// A number: one digit for 1 to 10, or hex digits A to P ending in `@`, kept in 64 bits.
    fn number(&mut self) -> R<(u64, bool)> {
        let negative = self.consume(b"?");
        if is_digit(self.first()) {
            let d = self.take()? - 0x30;
            return Ok((d as u64 + 1, negative));
        }
        let mut value = 0u64;
        let rest = self.rest();
        for (i, &c) in rest.iter().enumerate() {
            if c == (b'@') {
                self.pos += i + 1;
                return Ok((value, negative));
            }
            if (0x41..=0x50).contains(&c) {
                value = (value << 4).wrapping_add((c - 0x41) as u64);
                continue;
            }
            break;
        }
        Err(Bad)
    }
    fn unsigned(&mut self) -> R<u64> {
        let (v, negative) = self.number()?;
        if negative {
            return Err(Bad);
        }
        Ok(v)
    }
    fn signed(&mut self) -> R<i64> {
        let (v, negative) = self.number()?;
        if v > i64::MAX as u64 {
            return Err(Bad);
        }
        Ok(if negative { -(v as i64) } else { v as i64 })
    }

    fn name_text(&self, id: IdentId) -> Option<&str> {
        match &self.tree.idents[id as usize].kind {
            IdentKind::Named(name) => Some(name),
            _ => None,
        }
    }

    fn memorize_string(&mut self, s: String) {
        if self.backrefs.names.len() >= 10 || self.backrefs.names.iter().any(|&n| self.name_text(n) == Some(&s)) {
            return;
        }
        let id = self.tree.add_ident(IdentKind::Named(s));
        self.backrefs.names.push(id);
    }
    fn memorize_identifier(&mut self, id: IdentId) {
        let mut o = Out::new(&self.tree);
        o.ident(id, of::DEFAULT);
        let text = o.s;
        self.memorize_string(text);
    }

    fn back_ref_name(&mut self) -> R<IdentId> {
        let i = (self.first().ok_or(Bad)? - 0x30) as usize;
        let n = *self.backrefs.names.get(i).ok_or(Bad)?;
        self.pos += 1;
        Ok(n)
    }

    fn simple_string(&mut self, memorize: bool) -> R<String> {
        let at = self.index_of(b'@', 0).ok_or(Bad)?;
        if at == 0 {
            return Err(Bad);
        }
        let s = self.u.text(self.pos, self.pos + at);
        self.pos += at + 1;
        if memorize {
            self.memorize_string(s.clone());
        }
        Ok(s)
    }

    fn template_instantiation_name(&mut self, template: bool) -> R<IdentId> {
        self.templates += 1;
        if self.templates > MAX_TEMPLATE_NESTING {
            return Err(Bad);
        }
        self.consume(b"?$");
        let outer = mem::take(&mut self.backrefs);
        let inner = self.template_instantiation_body();
        self.backrefs = outer;
        self.templates -= 1;
        let id = inner?;
        if template {
            if matches!(self.tree.idents[id as usize].kind, IdentKind::ConversionOperator { .. } | IdentKind::Structor { .. }) {
                return Err(Bad);
            }
            self.memorize_identifier(id);
        }
        Ok(id)
    }

    fn template_instantiation_body(&mut self) -> R<IdentId> {
        let id = self.unqualified_symbol_name(true)?;
        let params = self.template_parameter_list()?;
        self.tree.idents[id as usize].template_params = Some(params);
        Ok(id)
    }

    fn anonymous_namespace_name(&mut self) -> R<IdentId> {
        self.consume(b"?A");
        let end = self.index_of(b'@', 0).ok_or(Bad)?;
        let s = self.u.text(self.pos, self.pos + end);
        self.memorize_string(s);
        self.pos += end + 1;
        Ok(self.tree.add_ident(IdentKind::Named("`anonymous namespace'".into())))
    }

    fn locally_scoped_name_piece(&mut self) -> R<IdentId> {
        self.consume(b"?");
        let (n, _) = self.number()?;
        self.consume(b"?");
        let scope = self.parse()?;
        let mut o = Out::new(&self.tree);
        o.s.push('`');
        o.sym(scope, of::DEFAULT);
        o.s.push_str(&format!("'::`{n}'"));
        let text = o.s;
        Ok(self.tree.add_ident(IdentKind::Named(text)))
    }

    fn fully_qualified_type_name(&mut self) -> R<NameId> {
        let id = self.unqualified_type_name(true)?;
        self.name_scope_chain(id)
    }

    fn fully_qualified_symbol_name(&mut self) -> R<NameId> {
        let id = self.unqualified_symbol_name(true)?;
        let name = self.name_scope_chain(id)?;
        if matches!(self.tree.idents[id as usize].kind, IdentKind::Structor { .. }) {
            let components = &self.tree.names[name as usize];
            if components.len() < 2 {
                return Err(Bad);
            }
            let class = components[components.len() - 2];
            if let IdentKind::Structor { cls, .. } = &mut self.tree.idents[id as usize].kind {
                *cls = Some(class);
            }
        }
        Ok(name)
    }

    fn unqualified_type_name(&mut self, memorize: bool) -> R<IdentId> {
        if is_digit(self.first()) {
            return self.back_ref_name();
        }
        if self.starts(b"?$") {
            return self.template_instantiation_name(true);
        }
        let s = self.simple_string(memorize)?;
        Ok(self.tree.add_ident(IdentKind::Named(s)))
    }

    fn unqualified_symbol_name(&mut self, memorize_simple: bool) -> R<IdentId> {
        if is_digit(self.first()) {
            return self.back_ref_name();
        }
        if self.starts(b"?$") {
            return self.template_instantiation_name(false);
        }
        if self.starts(b"?") {
            return self.function_identifier_code();
        }
        let s = self.simple_string(memorize_simple)?;
        Ok(self.tree.add_ident(IdentKind::Named(s)))
    }

    fn name_scope_piece(&mut self) -> R<IdentId> {
        if is_digit(self.first()) {
            return self.back_ref_name();
        }
        if self.starts(b"?$") {
            return self.template_instantiation_name(true);
        }
        if self.starts(b"?A") {
            return self.anonymous_namespace_name();
        }
        if starts_with_local_scope_pattern(self.rest()) {
            return self.locally_scoped_name_piece();
        }
        let s = self.simple_string(true)?;
        Ok(self.tree.add_ident(IdentKind::Named(s)))
    }

    fn name_scope_chain(&mut self, unqualified: IdentId) -> R<NameId> {
        // Collected innermost first, then turned around: each piece goes in front of the last.
        let mut components = vec![unqualified];
        while !self.consume(b"@") {
            if self.empty() {
                return Err(Bad);
            }
            components.push(self.name_scope_piece()?);
        }
        components.reverse();
        Ok(self.tree.add_name(components))
    }

    fn function_identifier_code(&mut self) -> R<IdentId> {
        self.consume(b"?");
        if self.empty() {
            return Err(Bad);
        }
        if self.consume(b"__") {
            let c = self.take()?;
            if c == (b'K') {
                let s = self.simple_string(false)?;
                return Ok(self.tree.add_ident(IdentKind::LiteralOperator(s)));
            }
            return self.intrinsic(&[b'_', b'_', c]);
        }
        if self.consume(b"_") {
            let c = self.take()?;
            return self.intrinsic(&[b'_', c]);
        }
        let c = self.take()?;
        if c == b'0' || c == (b'1') {
            return Ok(self.tree.add_ident(IdentKind::Structor { destructor: c == (b'1'), cls: None }));
        }
        if c == (b'B') {
            return Ok(self.tree.add_ident(IdentKind::ConversionOperator { target: None }));
        }
        self.intrinsic(&[c])
    }

    fn intrinsic(&mut self, code: &[u8]) -> R<IdentId> {
        let last = *code.last().unwrap();
        if !(last.is_ascii_digit() || last.is_ascii_uppercase()) {
            return Err(Bad);
        }
        Ok(self.tree.add_ident(IdentKind::Text(intrinsic_text(code))))
    }

    fn declarator(&mut self) -> R<SymId> {
        let name = self.fully_qualified_symbol_name()?;
        let symbol = self.encoded_symbol(name)?;
        self.tree.syms[symbol as usize].name = Some(name);
        let last = self.tree.last(name);
        if let IdentKind::ConversionOperator { target: None } = self.tree.idents[last as usize].kind {
            return Err(Bad);
        }
        Ok(symbol)
    }

    fn encoded_symbol(&mut self, name: NameId) -> R<SymId> {
        let c = self.front()?;
        if (0x30..=0x34).contains(&c) {
            self.take()?;
            let storage = [Storage::Private, Storage::Protected, Storage::Public, Storage::Global, Storage::Local][(c - 0x30) as usize];
            return self.variable_encoding(storage);
        }
        let fun = self.function_encoding()?;
        let last = self.tree.last(name);
        if let IdentKind::ConversionOperator { .. } = self.tree.idents[last as usize].kind {
            let SymKind::Function { signature } = self.tree.syms[fun as usize].kind else { unreachable!() };
            let ret = self.tree.signature(signature).and_then(|s| s.return_type);
            self.tree.idents[last as usize].kind = IdentKind::ConversionOperator { target: ret };
        }
        Ok(fun)
    }

    fn variable_encoding(&mut self, storage: Storage) -> R<SymId> {
        let t = self.type_(Mode::Drop)?;
        if let TypeKind::Pointer { class_parent, pointee, .. } = self.tree.types[t as usize].kind {
            let ext = self.pointer_ext_qualifiers();
            self.tree.types[t as usize].quals |= ext;
            let (extra, _) = self.qualifiers()?;
            if class_parent.is_some() {
                self.fully_qualified_type_name()?;
            }
            self.tree.types[pointee as usize].quals |= extra;
        } else {
            let quals = self.qualifiers()?.0;
            self.tree.types[t as usize].quals = quals;
        }
        Ok(self.tree.add_sym(None, SymKind::Variable { storage, ty: Some(t) }))
    }

    fn function_class(&mut self) -> R<u32> {
        let c = self.take()?;
        if c == (b'$') {
            let mut flag = fc::VIRTUAL_THIS_ADJUST;
            if self.consume(b"R") {
                flag |= fc::VIRTUAL_THIS_ADJUST_EX;
            }
            let d = self.take()?;
            let class = match d {
                0x30 => fc::PRIVATE | fc::VIRTUAL,
                0x31 => fc::PRIVATE | fc::VIRTUAL | fc::FAR,
                0x32 => fc::PROTECTED | fc::VIRTUAL,
                0x33 => fc::PROTECTED | fc::VIRTUAL | fc::FAR,
                0x34 => fc::PUBLIC | fc::VIRTUAL,
                0x35 => fc::PUBLIC | fc::VIRTUAL | fc::FAR,
                _ => return Err(Bad),
            };
            return Ok(class | flag);
        }
        function_class_of(c).ok_or(Bad)
    }

    fn calling_convention(&mut self) -> R<&'static str> {
        Ok(calling_convention_of(self.take()?))
    }

    fn qualifiers(&mut self) -> R<(u8, bool)> {
        Ok(match self.take()? {
            b'Q' => (0, true),
            b'R' => (q::CONST, true),
            b'S' => (q::VOLATILE, true),
            b'T' => (q::CONST | q::VOLATILE, true),
            b'A' => (0, false),
            b'B' => (q::CONST, false),
            b'C' => (q::VOLATILE, false),
            b'D' => (q::CONST | q::VOLATILE, false),
            _ => return Err(Bad),
        })
    }

    fn type_(&mut self, mode: Mode) -> R<TypeId> {
        self.depth += 1;
        if self.depth > 256 {
            return Err(Bad);
        }
        let out = self.type_body(mode);
        self.depth -= 1;
        out
    }

    fn type_body(&mut self, mode: Mode) -> R<TypeId> {
        let mut quals = 0;
        if mode == Mode::Mangle || (mode == Mode::Result && self.consume(b"?")) {
            quals = self.qualifiers()?.0;
        }
        let c = self.front()?;
        let t = if matches!(c, 0x54..=0x57) {
            // T, U, V, W
            self.class_type()?
        } else if self.starts(b"$$Q") || [b'A', b'P', b'Q', b'R', b'S'].contains(&c) {
            if self.is_member_pointer()? {
                self.member_pointer_type()?
            } else {
                self.pointer_type()?
            }
        } else if c == (b'Y') {
            self.array_type()?
        } else if self.consume(b"$$A8@@") {
            self.function_type(true)?
        } else if self.consume(b"$$A6") {
            self.function_type(false)?
        } else if c == (b'?') {
            self.custom_type()?
        } else {
            self.primitive_type()?
        };
        self.tree.types[t as usize].quals |= quals;
        Ok(t)
    }

    fn is_member_pointer(&mut self) -> R<bool> {
        let rest = self.rest();
        let f = rest[0];
        let mut p = 1usize;
        if f == (b'$') || f == (b'A') {
            return Ok(false);
        }
        let at = |p: usize| rest.get(p).copied();
        if is_digit(at(p)) {
            let d = at(p).unwrap();
            if d != (b'6') && d != (b'8') {
                return Err(Bad);
            }
            return Ok(d == (b'8'));
        }
        for q in [b'E', b'I', b'F'] {
            if at(p) == Some(q) {
                p += 1;
            }
        }
        if rest[p.min(rest.len())..].starts_with(b"__ptrauth") {
            // Read past the three numbers of the qualifier, or as far as they go.
            let saved = self.pos;
            self.pos += p + 9;
            for _ in 0..3 {
                if self.number().is_err() {
                    break;
                }
            }
            p = self.pos - saved;
            self.pos = saved;
        }
        let Some(c) = at(p) else { return Err(Bad) };
        if (0x41..=0x44).contains(&c) {
            return Ok(false);
        }
        if (0x51..=0x54).contains(&c) {
            return Ok(true);
        }
        Err(Bad)
    }

    fn pointer_cv_qualifiers(&mut self) -> R<(u8, Affinity)> {
        if self.consume(b"$$Q") {
            return Ok((0, Affinity::Rvalue));
        }
        Ok(match self.take()? {
            b'A' => (0, Affinity::Reference),
            b'P' => (0, Affinity::Pointer),
            b'Q' => (q::CONST, Affinity::Pointer),
            b'R' => (q::VOLATILE, Affinity::Pointer),
            b'S' => (q::CONST | q::VOLATILE, Affinity::Pointer),
            _ => return Err(Bad),
        })
    }

    fn pointer_ext_qualifiers(&mut self) -> u8 {
        let mut quals = 0;
        if self.consume(b"E") {
            quals |= q::POINTER64;
        }
        if self.consume(b"I") {
            quals |= q::RESTRICT;
        }
        if self.consume(b"F") {
            quals |= q::UNALIGNED;
        }
        quals
    }

    fn pointer_auth_qualifier(&mut self) -> R<Option<ArrId>> {
        if !self.consume(b"__ptrauth") {
            return Ok(None);
        }
        let mut values = Vec::with_capacity(3);
        for _ in 0..3 {
            let (value, negative) = self.number()?;
            if negative {
                return Ok(None);
            }
            values.push(Node::Literal { value, negative: false });
        }
        Ok(Some(self.tree.add_array(values)))
    }

    fn pointer_type(&mut self) -> R<TypeId> {
        let (mut quals, affinity) = self.pointer_cv_qualifiers()?;
        if self.consume(b"6") {
            let pointee = self.function_type(false)?;
            return Ok(self.tree.add_type(quals, TypeKind::Pointer { affinity, class_parent: None, pointer_auth: None, pointee }));
        }
        quals |= self.pointer_ext_qualifiers();
        let pointer_auth = self.pointer_auth_qualifier()?;
        let pointee = self.type_(Mode::Mangle)?;
        Ok(self.tree.add_type(quals, TypeKind::Pointer { affinity, class_parent: None, pointer_auth, pointee }))
    }

    fn member_pointer_type(&mut self) -> R<TypeId> {
        let (mut quals, affinity) = self.pointer_cv_qualifiers()?;
        quals |= self.pointer_ext_qualifiers();
        let (class_parent, pointee) = if self.consume(b"8") {
            let parent = self.fully_qualified_type_name()?;
            (parent, self.function_type(true)?)
        } else {
            let (pointee_quals, _) = self.qualifiers()?;
            let parent = self.fully_qualified_type_name()?;
            let pointee = self.type_(Mode::Drop)?;
            self.tree.types[pointee as usize].quals = pointee_quals;
            (parent, pointee)
        };
        Ok(self.tree.add_type(quals, TypeKind::Pointer { affinity, class_parent: Some(class_parent), pointer_auth: None, pointee }))
    }

    fn array_type(&mut self) -> R<TypeId> {
        self.consume(b"Y");
        let (rank, negative) = self.number()?;
        if negative || rank == 0 {
            return Err(Bad);
        }
        let mut dimensions = Vec::new();
        let mut i = 0u64;
        while i < rank {
            let (d, negative) = self.number()?;
            if negative {
                return Err(Bad);
            }
            dimensions.push(d);
            if dimensions.len() > 64 {
                return Err(Bad);
            }
            i += 1;
        }
        let mut quals = 0;
        if self.consume(b"$$C") {
            let (q, member) = self.qualifiers()?;
            if member {
                return Err(Bad);
            }
            quals = q;
        }
        let element = self.type_(Mode::Drop)?;
        Ok(self.tree.add_type(quals, TypeKind::Array { dimensions, element }))
    }

    fn class_type(&mut self) -> R<TypeId> {
        let c = self.take()?;
        if c == (b'W') && !self.consume(b"4") {
            return Err(Bad);
        }
        let tag = match c {
            b'T' => "union",
            b'U' => "struct",
            b'V' => "class",
            _ => "enum",
        };
        let name = self.fully_qualified_type_name()?;
        Ok(self.tree.add_type(0, TypeKind::Tag { tag, name }))
    }

    fn custom_type(&mut self) -> R<TypeId> {
        self.consume(b"?");
        let id = self.unqualified_type_name(true)?;
        let t = self.tree.add_type(0, TypeKind::Custom(id));
        if !self.consume(b"@") {
            return Err(Bad);
        }
        Ok(t)
    }

    fn primitive_type(&mut self) -> R<TypeId> {
        if self.consume(b"$$T") {
            return Ok(self.tree.add_type(0, TypeKind::Primitive("std::nullptr_t")));
        }
        let c = self.take()?;
        let name = if c == (b'_') {
            let d = self.take()?;
            if d > 0x7f {
                return Err(Bad);
            }
            primitive(&[b'_', d])
        } else if c > 0x7f {
            None
        } else {
            primitive(&[c])
        };
        let name = name.ok_or(Bad)?;
        Ok(self.tree.add_type(0, TypeKind::Primitive(name)))
    }

    fn function_type(&mut self, this_quals: bool) -> R<TypeId> {
        let mut sig = Signature::new();
        let mut quals = 0;
        if this_quals {
            quals = self.pointer_ext_qualifiers();
            if self.consume(b"G") {
                sig.ref_qualifier = "&";
            } else if self.consume(b"H") {
                sig.ref_qualifier = "&&";
            }
            quals |= self.qualifiers()?.0;
        }
        sig.calling_convention = self.calling_convention()?;
        if !self.consume(b"@") {
            sig.return_type = Some(self.type_(Mode::Result)?);
        }
        let (params, variadic) = self.function_parameter_list()?;
        sig.params = params;
        sig.variadic = variadic;
        if self.consume(b"_E") {
            sig.noexcept = true;
        } else if !self.consume(b"Z") {
            return Err(Bad);
        }
        Ok(self.tree.add_type(quals, TypeKind::Function(sig)))
    }

    fn function_encoding(&mut self) -> R<SymId> {
        let extra = if self.consume(b"$$J0") { fc::EXTERN_C } else { fc::NONE };
        if self.empty() {
            return Err(Bad);
        }
        let class = self.function_class()? | extra;
        let mut thunk: Option<Thunk> = None;
        // The adjustments are kept in 32 bits, as LLVM keeps them: the static one unsigned, the others signed.
        if class & fc::STATIC_THIS_ADJUST != 0 {
            let static_offset = self.signed()? as u32 as i64;
            thunk = Some(Thunk { static_offset, vbptr_offset: 0, vboffset_offset: 0, vtordisp_offset: 0 });
        } else if class & fc::VIRTUAL_THIS_ADJUST != 0 {
            let mut t = Thunk { static_offset: 0, vbptr_offset: 0, vboffset_offset: 0, vtordisp_offset: 0 };
            if class & fc::VIRTUAL_THIS_ADJUST_EX != 0 {
                t.vbptr_offset = self.signed()? as i32 as i64;
                t.vboffset_offset = self.signed()? as i32 as i64;
            }
            t.vtordisp_offset = self.signed()? as i32 as i64;
            t.static_offset = self.signed()? as u32 as i64;
            thunk = Some(t);
        }
        let signature = if class & fc::NO_PARAMETER_LIST != 0 {
            self.tree.add_type(0, TypeKind::Function(Signature::new()))
        } else {
            self.function_type(class & (fc::GLOBAL | fc::STATIC) == 0)?
        };
        let signature = match thunk {
            // A thunk's signature is a copy of the function's, with the adjustments.
            Some(thunk) => {
                let mut sig = self.tree.signature(signature).unwrap().clone();
                sig.thunk = Some(thunk);
                sig.function_class = fc::GLOBAL;
                let quals = self.tree.types[signature as usize].quals;
                self.tree.add_type(quals, TypeKind::Function(sig))
            }
            None => signature,
        };
        self.tree.signature_mut(signature).function_class = class;
        Ok(self.tree.add_sym(None, SymKind::Function { signature }))
    }

    fn function_parameter_list(&mut self) -> R<(Option<ArrId>, bool)> {
        if self.consume(b"X") {
            return Ok((None, false));
        }
        let mut params: Vec<Node> = Vec::new();
        while !self.starts(b"@") && !self.starts(b"Z") {
            if self.empty() {
                return Err(Bad);
            }
            if is_digit(self.first()) {
                let i = (self.first().unwrap() - 0x30) as usize;
                let t = *self.backrefs.params.get(i).ok_or(Bad)?;
                self.pos += 1;
                params.push(Node::Type(t));
                continue;
            }
            let before = self.pos;
            let t = self.type_(Mode::Drop)?;
            params.push(Node::Type(t));
            // One-letter types are not remembered: a back reference would save nothing.
            if self.backrefs.params.len() <= 9 && self.pos - before > 1 {
                self.backrefs.params.push(t);
            }
        }
        if self.consume(b"@") {
            return Ok((Some(self.tree.add_array(params)), false));
        }
        self.consume(b"Z");
        Ok((Some(self.tree.add_array(params)), true))
    }

    fn template_parameter_list(&mut self) -> R<ArrId> {
        let mut params: Vec<Node> = Vec::new();
        while !self.starts(b"@") {
            if self.empty() {
                return Err(Bad);
            }
            if self.consume(b"$S") || self.consume(b"$$V") || self.consume(b"$$$V") || self.consume(b"$$Z") {
                continue;
            }
            let auto = self.consume(b"$M");
            if auto {
                self.type_(Mode::Drop)?;
            }
            let prefixed = |d: &Self, c: u8| if auto { d.starts(&[c]) } else { d.starts(&[b'$', c]) };
            let param = if self.consume(b"$$Y") {
                Node::Name(self.fully_qualified_type_name()?)
            } else if self.consume(b"$$B") {
                Node::Type(self.type_(Mode::Drop)?)
            } else if self.consume(b"$$C") {
                Node::Type(self.type_(Mode::Mangle)?)
            } else if prefixed(self, b'1') || prefixed(self, b'H') || prefixed(self, b'I') || prefixed(self, b'J') {
                if !auto {
                    self.take()?;
                }
                let inheritance = self.take()?;
                let mut symbol = None;
                if self.starts(b"?") {
                    let sym = self.parse()?;
                    let name = self.tree.syms[sym as usize].name.ok_or(Bad)?;
                    symbol = Some(sym);
                    let last = self.tree.last(name);
                    self.memorize_identifier(last);
                }
                let count = match inheritance {
                    _ if inheritance > 0x7f => 0,
                    b'J' => 3,
                    b'I' => 2,
                    b'H' => 1,
                    _ => 0,
                };
                let mut offsets = Vec::new();
                for _ in 0..count {
                    offsets.push(self.signed()?);
                }
                self.add_ref(TemplateRef { symbol, offsets, affinity: Affinity::Pointer })
            } else if self.starts(b"$E?") {
                self.consume(b"$E");
                let symbol = Some(self.parse()?);
                self.add_ref(TemplateRef { symbol, offsets: Vec::new(), affinity: Affinity::Reference })
            } else if prefixed(self, b'F') || prefixed(self, b'G') {
                if !auto {
                    self.take()?;
                }
                let inheritance = self.take()?;
                let mut offsets = Vec::new();
                for _ in 0..if inheritance == (b'G') { 3 } else { 2 } {
                    offsets.push(self.signed()?);
                }
                self.add_ref(TemplateRef { symbol: None, offsets, affinity: Affinity::None })
            } else if self.consume(if auto { b"0" } else { b"$0" }) {
                let (value, negative) = self.number()?;
                Node::Literal { value, negative }
            } else {
                Node::Type(self.type_(Mode::Drop)?)
            };
            params.push(param);
        }
        self.consume(b"@");
        Ok(self.tree.add_array(params))
    }

    fn add_ref(&mut self, r: TemplateRef) -> Node {
        self.tree.refs.push(r);
        Node::TemplateRef((self.tree.refs.len() - 1) as RefId)
    }

    fn synthesize_variable(&mut self, t: TypeId, text: &str) -> SymId {
        let id = self.tree.add_ident(IdentKind::Named(text.into()));
        let name = self.tree.add_name(vec![id]);
        self.tree.add_sym(Some(name), SymKind::Variable { storage: Storage::None, ty: Some(t) })
    }
}

/// `?<number>?` at the front: a local scope inside a function (`?1??f@@YAXXZ@`).
fn starts_with_local_scope_pattern(s: &[u8]) -> bool {
    if s.first() != Some(&(b'?')) {
        return false;
    }
    let s = &s[1..];
    let Some(end) = s.iter().position(|&c| c == (b'?')) else { return false };
    if end == 0 {
        return false;
    }
    let candidate = &s[..end];
    if candidate.len() == 1 {
        return candidate[0] == (b'@') || is_digit(Some(candidate[0]));
    }
    if *candidate.last().unwrap() != (b'@') {
        return false;
    }
    let digits = &candidate[..candidate.len() - 1];
    if !(0x42..=0x50).contains(&digits[0]) {
        return false;
    }
    digits[1..].iter().all(|&c| (0x41..=0x50).contains(&c))
}

fn escaped_char(out: &mut String, mut c: u32) {
    let named = match c {
        0 => "\\0",
        39 => "\\'",
        34 => "\\\"",
        92 => "\\\\",
        7 => "\\a",
        8 => "\\b",
        12 => "\\f",
        10 => "\\n",
        13 => "\\r",
        9 => "\\t",
        11 => "\\v",
        _ => "",
    };
    if !named.is_empty() {
        out.push_str(named);
        return;
    }
    if c > 0x1f && c < 0x7f {
        out.push(c as u8 as char);
        return;
    }
    let mut hex = Vec::new();
    while c != 0 {
        for _ in 0..2 {
            hex.push(b"0123456789ABCDEF"[(c % 16) as usize]);
            c /= 16;
        }
    }
    hex.reverse();
    out.push_str("\\x");
    out.push_str(core::str::from_utf8(&hex).unwrap());
}

/// The width of the characters of a narrow string literal, guessed as LLVM guesses it.
fn guess_char_byte_size(bytes: &[u32], total: f64) -> usize {
    if total % 2.0 == 1.0 {
        return 1;
    }
    if total < 32.0 {
        let trailing = bytes.iter().rev().take_while(|&&b| b == 0).count();
        if trailing >= 4 && total % 4.0 == 0.0 {
            return 4;
        }
        if trailing >= 2 {
            return 2;
        }
        return 1;
    }
    let nulls = bytes.iter().filter(|&&b| b == 0).count();
    if nulls >= (2 * bytes.len()) / 3 && total % 4.0 == 0.0 {
        return 4;
    }
    if nulls >= bytes.len() / 3 {
        return 2;
    }
    1
}

/// The parsed symbol, or None.
fn parse_msvc(mangled: &str) -> Option<(Tree, SymId)> {
    let u = Units::new(mangled);
    let mut d = Demangler { u: &u, s: &u.bytes, pos: 0, tree: Tree::default(), backrefs: Backrefs::default(), depth: 0, templates: 0 };
    let sym = d.parse().ok()?;
    Some((d.tree, sym))
}

/// The symbol printed with the given llvm-undname output flags ([`of`]), or None when it does not parse.
pub fn undname(mangled: &str, flags: u32) -> Option<String> {
    let (tree, sym) = parse_msvc(mangled)?;
    let mut o = Out::new(&tree);
    o.sym(sym, flags);
    Some(o.s)
}

/// An MSVC name demangled: in full as llvm-undname prints it, and short for
/// the listing — the qualified name without `class`/`struct`, template
/// arguments inside template arguments folded to `<…>`, and `(…)` or `()` for
/// a function's parameters, as the other C++ names are shown.
pub fn demangle_msvc(mangled: &str) -> Option<(String, String)> {
    let (tree, sym) = parse_msvc(mangled)?;
    let mut full = Out::new(&tree);
    full.sym(sym, of::DEFAULT);
    let mut short = Out::new(&tree);
    short.fold = true;
    let symbol = &tree.syms[sym as usize];
    match (&symbol.kind, symbol.name) {
        (SymKind::Function { signature }, Some(name)) => {
            short.name(name, OF_MINIMAL | of::NO_TAG_SPECIFIER);
            let sig = tree.signature(*signature).unwrap();
            if sig.function_class & fc::NO_PARAMETER_LIST == 0 {
                let any = sig.params.is_some_and(|p| !tree.arrays[p as usize].is_empty()) || sig.variadic;
                short.s.push_str(if any { "(…)" } else { "()" });
            }
        }
        _ => short.sym(sym, OF_MINIMAL | of::NO_TAG_SPECIFIER),
    }
    Some((full.s, short.s))
}
