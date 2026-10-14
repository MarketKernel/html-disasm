/**
 * MSVC symbol names (`?f@@YAXXZ`) back to declarations, printed as LLVM's
 * llvm-undname prints them (`void __cdecl f(void)`), so that
 * tools/verify-msvc.mjs can compare the two line by line.
 *
 * The name is read into a small tree — symbols, qualified names, types — the
 * way LLVM's Microsoft demangler reads it, with its two tables of back
 * references (the first ten names, and the first ten parameter types longer
 * than one letter), and the tree prints itself. A name that does not parse is
 * returned as null and shown as it is.
 */

const enum Q {
  None = 0,
  Const = 1,
  Volatile = 2,
  Far = 4,
  Huge = 8,
  Unaligned = 16,
  Restrict = 32,
  Pointer64 = 64,
}

const enum FC {
  None = 0,
  Public = 1,
  Protected = 2,
  Private = 4,
  Global = 8,
  Static = 16,
  Virtual = 32,
  Far = 64,
  ExternC = 128,
  NoParameterList = 256,
  VirtualThisAdjust = 512,
  VirtualThisAdjustEx = 1024,
  StaticThisAdjust = 2048,
}

/** Output flags: what llvm-undname's --no-… options leave out. */
export const enum OF {
  Default = 0,
  NoCallingConvention = 1,
  NoTagSpecifier = 2,
  NoAccessSpecifier = 4,
  NoMemberType = 8,
  NoReturnType = 16,
  NoVariableType = 32,
}
const OF_MINIMAL = OF.NoCallingConvention | OF.NoAccessSpecifier | OF.NoMemberType | OF.NoReturnType | OF.NoVariableType;

type Affinity = 'none' | 'pointer' | 'reference' | 'rvalue';

class Bad extends Error {}

class Out {
  s = '';
  /** Template arguments inside template arguments print as `<…>` (the short form). */
  fold = false;
  private templates = 0;
  templateParameters(params: NodeArray, f: number): void {
    if (this.fold && this.templates) {
      this.s += '<…>';
      return;
    }
    this.templates++;
    this.s += '<';
    params.output(this, f);
    this.s += '>';
    this.templates--;
  }
  back(): string {
    return this.s[this.s.length - 1] ?? '';
  }
  /** A space unless the last token ends with punctuation. */
  spaceIfNecessary(): void {
    const c = this.back();
    if (c && (/[A-Za-z0-9>]/.test(c))) this.s += ' ';
  }
}

function outputQualifiers(o: Out, q: number, spaceBefore: boolean, spaceAfter: boolean): void {
  if (!(q & (Q.Const | Q.Volatile | Q.Restrict))) return;
  const start = o.s.length;
  for (const [mask, text] of [[Q.Const, 'const'], [Q.Volatile, 'volatile'], [Q.Restrict, '__restrict']] as const) {
    if (!(q & mask)) continue;
    if (spaceBefore) o.s += ' ';
    o.s += text;
    spaceBefore = true;
  }
  if (spaceAfter && o.s.length > start) o.s += ' ';
}

const CALLING_CONVENTIONS: Record<string, string> = {
  A: '__cdecl', B: '__cdecl', C: '__pascal', D: '__pascal', E: '__thiscall', F: '__thiscall', G: '__stdcall', H: '__stdcall',
  I: '__fastcall', J: '__fastcall', M: '__clrcall', N: '__clrcall', O: '__eabi', P: '__eabi', Q: '__vectorcall',
  S: '__attribute__((__swiftcall__)) ', W: '__attribute__((__swiftasynccall__)) ',
};

function outputCallingConvention(o: Out, cc: string): void {
  o.spaceIfNecessary();
  o.s += cc;
}

/* ------------------------------------------------------------------ *
 * Nodes
 * ------------------------------------------------------------------ */

interface Node {
  output(o: Out, f: number): void;
}

abstract class TypeNode implements Node {
  quals = 0;
  abstract outputPre(o: Out, f: number): void;
  abstract outputPost(o: Out, f: number): void;
  output(o: Out, f: number): void {
    this.outputPre(o, f);
    this.outputPost(o, f);
  }
}

class PrimitiveType extends TypeNode {
  constructor(readonly name: string) {
    super();
  }
  outputPre(o: Out): void {
    o.s += this.name;
    outputQualifiers(o, this.quals, true, false);
  }
  outputPost(): void {}
}

class NodeArray implements Node {
  constructor(readonly nodes: (Node | null)[]) {}
  output(o: Out, f: number, separator = ', '): void {
    if (!this.nodes.length) return;
    this.nodes[0]?.output(o, f);
    for (let i = 1; i < this.nodes.length; i++) {
      o.s += separator;
      this.nodes[i]!.output(o, f);
    }
  }
}

class FunctionSignature extends TypeNode {
  callingConvention = '';
  functionClass: number = FC.Global;
  refQualifier: '' | '&' | '&&' = '';
  returnType: TypeNode | null = null;
  variadic = false;
  params: NodeArray | null = null;
  noexcept = false;
  outputPre(o: Out, f: number): void {
    if (!(f & OF.NoAccessSpecifier)) {
      if (this.functionClass & FC.Public) o.s += 'public: ';
      if (this.functionClass & FC.Protected) o.s += 'protected: ';
      if (this.functionClass & FC.Private) o.s += 'private: ';
    }
    if (!(f & OF.NoMemberType)) {
      if (!(this.functionClass & FC.Global) && this.functionClass & FC.Static) o.s += 'static ';
      if (this.functionClass & FC.Virtual) o.s += 'virtual ';
      if (this.functionClass & FC.ExternC) o.s += 'extern "C" ';
    }
    if (!(f & OF.NoReturnType) && this.returnType) {
      this.returnType.outputPre(o, f);
      o.s += ' ';
    }
    if (!(f & OF.NoCallingConvention)) outputCallingConvention(o, this.callingConvention);
  }
  outputPost(o: Out, f: number): void {
    if (!(this.functionClass & FC.NoParameterList)) {
      o.s += '(';
      if (this.params) this.params.output(o, f);
      else o.s += 'void';
      if (this.variadic) {
        if (o.back() !== '(') o.s += ', ';
        o.s += '...';
      }
      o.s += ')';
    }
    if (this.quals & Q.Const) o.s += ' const';
    if (this.quals & Q.Volatile) o.s += ' volatile';
    if (this.quals & Q.Restrict) o.s += ' __restrict';
    if (this.quals & Q.Unaligned) o.s += ' __unaligned';
    if (this.noexcept) o.s += ' noexcept';
    if (this.refQualifier) o.s += ` ${this.refQualifier}`;
    if (!(f & OF.NoReturnType) && this.returnType) this.returnType.outputPost(o, f);
  }
}

class ThunkSignature extends FunctionSignature {
  staticOffset = 0;
  vbptrOffset = 0;
  vboffsetOffset = 0;
  vtordispOffset = 0;
  override outputPre(o: Out, f: number): void {
    o.s += '[thunk]: ';
    super.outputPre(o, f);
  }
  override outputPost(o: Out, f: number): void {
    if (this.functionClass & FC.StaticThisAdjust) o.s += `\`adjustor{${this.staticOffset}}'`;
    else if (this.functionClass & FC.VirtualThisAdjust) {
      if (this.functionClass & FC.VirtualThisAdjustEx) o.s += `\`vtordispex{${this.vbptrOffset}, ${this.vboffsetOffset}, ${this.vtordispOffset}, ${this.staticOffset}}'`;
      else o.s += `\`vtordisp{${this.vtordispOffset}, ${this.staticOffset}}'`;
    }
    super.outputPost(o, f);
  }
}

class PointerType extends TypeNode {
  affinity: Affinity = 'none';
  classParent: QualifiedName | null = null;
  pointerAuth: NodeArray | null = null;
  pointee!: TypeNode;
  outputPre(o: Out, f: number): void {
    const fn = this.pointee instanceof FunctionSignature && !(this.pointee instanceof ThunkSignature) ? this.pointee : null;
    if (fn) fn.outputPre(o, OF.NoCallingConvention);
    else this.pointee.outputPre(o, f);
    o.spaceIfNecessary();
    if (this.quals & Q.Unaligned) o.s += '__unaligned ';
    if (this.pointee instanceof ArrayType) o.s += '(';
    else if (fn) {
      o.s += '(';
      outputCallingConvention(o, fn.callingConvention);
      o.s += ' ';
    }
    if (this.classParent) {
      this.classParent.output(o, f);
      o.s += '::';
    }
    o.s += this.affinity === 'pointer' ? '*' : this.affinity === 'reference' ? '&' : this.affinity === 'rvalue' ? '&&' : '';
    outputQualifiers(o, this.quals, false, false);
    if (this.pointerAuth) {
      o.s += '__ptrauth(';
      this.pointerAuth.output(o, f);
      o.s += ')';
    }
  }
  outputPost(o: Out, f: number): void {
    if (this.pointee instanceof ArrayType || (this.pointee instanceof FunctionSignature && !(this.pointee instanceof ThunkSignature))) o.s += ')';
    this.pointee.outputPost(o, f);
  }
}

class TagType extends TypeNode {
  constructor(
    readonly tag: string,
    readonly name: QualifiedName,
  ) {
    super();
  }
  outputPre(o: Out, f: number): void {
    if (!(f & OF.NoTagSpecifier)) o.s += `${this.tag} `;
    this.name.output(o, f);
    outputQualifiers(o, this.quals, true, false);
  }
  outputPost(): void {}
}

class ArrayType extends TypeNode {
  dimensions: IntegerLiteral[] = [];
  element!: TypeNode;
  outputPre(o: Out, f: number): void {
    this.element.outputPre(o, f);
    outputQualifiers(o, this.quals, true, false);
  }
  outputPost(o: Out, f: number): void {
    o.s += '[';
    this.dimensions.forEach((d, i) => {
      if (i) o.s += '][';
      if (d.value !== 0n) d.output(o);
    });
    o.s += ']';
    this.element.outputPost(o, f);
  }
}

class CustomType extends TypeNode {
  constructor(readonly identifier: Identifier) {
    super();
  }
  outputPre(o: Out, f: number): void {
    this.identifier.output(o, f);
  }
  outputPost(): void {}
}

class IntegerLiteral implements Node {
  constructor(
    readonly value: bigint,
    readonly negative: boolean,
  ) {}
  output(o: Out): void {
    if (this.negative) o.s += '-';
    o.s += this.value.toString();
  }
}

abstract class Identifier implements Node {
  templateParams: NodeArray | null = null;
  abstract output(o: Out, f: number): void;
  protected outputTemplateParameters(o: Out, f: number): void {
    if (this.templateParams) o.templateParameters(this.templateParams, f);
  }
}

class NamedIdentifier extends Identifier {
  constructor(public name: string) {
    super();
  }
  output(o: Out, f: number): void {
    o.s += this.name;
    this.outputTemplateParameters(o, f);
  }
}

class TextIdentifier extends Identifier {
  constructor(readonly text: string) {
    super();
  }
  output(o: Out, f: number): void {
    o.s += this.text;
    this.outputTemplateParameters(o, f);
  }
}

class ConversionOperatorIdentifier extends Identifier {
  target: TypeNode | null = null;
  output(o: Out, f: number): void {
    o.s += 'operator';
    this.outputTemplateParameters(o, f);
    o.s += ' ';
    this.target?.output(o, f);
  }
}

class StructorIdentifier extends Identifier {
  cls: Identifier | null = null;
  constructor(readonly destructor: boolean) {
    super();
  }
  output(o: Out, f: number): void {
    if (this.destructor) o.s += '~';
    this.cls?.output(o, f);
    this.outputTemplateParameters(o, f);
  }
}

class LiteralOperatorIdentifier extends Identifier {
  constructor(readonly name: string) {
    super();
  }
  output(o: Out, f: number): void {
    o.s += `operator ""${this.name}`;
    this.outputTemplateParameters(o, f);
  }
}

class LocalStaticGuardIdentifier extends Identifier {
  scopeIndex = 0n;
  constructor(readonly thread: boolean) {
    super();
  }
  output(o: Out): void {
    o.s += this.thread ? "`local static thread guard'" : "`local static guard'";
    if (this.scopeIndex > 0n) o.s += `{${this.scopeIndex}}`;
  }
}

class VcallThunkIdentifier extends Identifier {
  offset = 0n;
  output(o: Out): void {
    o.s += `\`vcall'{${this.offset}, {flat}}`;
  }
}

class RttiBaseClassDescriptor extends Identifier {
  constructor(readonly values: bigint[]) {
    super();
  }
  output(o: Out): void {
    o.s += `\`RTTI Base Class Descriptor at (${this.values.join(', ')})'`;
  }
}

class DynamicStructorIdentifier extends Identifier {
  variable: VariableSymbol | null = null;
  name: QualifiedName | null = null;
  constructor(readonly destructor: boolean) {
    super();
  }
  output(o: Out, f: number): void {
    o.s += this.destructor ? '`dynamic atexit destructor for ' : '`dynamic initializer for ';
    if (this.variable) {
      o.s += '`';
      this.variable.output(o, f);
      o.s += "''";
    } else {
      o.s += "'";
      this.name!.output(o, f);
      o.s += "''";
    }
  }
}

class QualifiedName implements Node {
  constructor(readonly components: Identifier[]) {}
  output(o: Out, f: number): void {
    this.components.forEach((c, i) => {
      if (i) o.s += '::';
      c.output(o, f);
    });
  }
  get last(): Identifier {
    return this.components[this.components.length - 1]!;
  }
}

class TemplateParameterReference implements Node {
  symbol: Sym | null = null;
  offsets: bigint[] = [];
  affinity: Affinity = 'none';
  output(o: Out, f: number): void {
    if (this.offsets.length) o.s += '{';
    else if (this.affinity === 'pointer') o.s += '&';
    if (this.symbol) {
      this.symbol.output(o, f);
      if (this.offsets.length) o.s += ', ';
    }
    if (this.offsets.length) o.s += `${this.offsets.join(', ')}}`;
  }
}

abstract class Sym implements Node {
  name: QualifiedName | null = null;
  output(o: Out, f: number): void {
    this.name!.output(o, f);
  }
}

class PlainSymbol extends Sym {}

class SpecialTableSymbol extends Sym {
  target: QualifiedName | null = null;
  quals = 0;
  override output(o: Out, f: number): void {
    outputQualifiers(o, this.quals, false, true);
    this.name!.output(o, f);
    if (this.target) {
      o.s += '{for `';
      this.target.output(o, f);
      o.s += "'}";
    }
  }
}

class StringLiteralSymbol extends Sym {
  text = '';
  truncated = false;
  prefix = '"';
  override output(o: Out): void {
    o.s += `${this.prefix}${this.text}"`;
    if (this.truncated) o.s += '...';
  }
}

class VariableSymbol extends Sym {
  storage: 'none' | 'private' | 'protected' | 'public' | 'global' | 'local' = 'none';
  type: TypeNode | null = null;
  override output(o: Out, f: number): void {
    const access = this.storage === 'private' || this.storage === 'protected' || this.storage === 'public' ? this.storage : '';
    if (!(f & OF.NoAccessSpecifier) && access) o.s += `${access}: `;
    if (!(f & OF.NoMemberType) && access) o.s += 'static ';
    if (!(f & OF.NoVariableType) && this.type) {
      this.type.outputPre(o, f);
      o.spaceIfNecessary();
    }
    this.name!.output(o, f);
    if (!(f & OF.NoVariableType) && this.type) this.type.outputPost(o, f);
  }
}

class FunctionSymbol extends Sym {
  signature!: FunctionSignature;
  override output(o: Out, f: number): void {
    this.signature.outputPre(o, f);
    o.spaceIfNecessary();
    this.name!.output(o, f);
    this.signature.outputPost(o, f);
  }
}

/* ------------------------------------------------------------------ *
 * The parser
 * ------------------------------------------------------------------ */

const INTRINSICS: Record<string, string> = {
  2: 'operator new', 3: 'operator delete', 4: 'operator=', 5: 'operator>>', 6: 'operator<<', 7: 'operator!', 8: 'operator==',
  9: 'operator!=', A: 'operator[]', C: 'operator->', D: 'operator*', E: 'operator++', F: 'operator--', G: 'operator-',
  H: 'operator+', I: 'operator&', J: 'operator->*', K: 'operator/', L: 'operator%', M: 'operator<', N: 'operator<=',
  O: 'operator>', P: 'operator>=', Q: 'operator,', R: 'operator()', S: 'operator~', T: 'operator^', U: 'operator|',
  V: 'operator&&', W: 'operator||', X: 'operator*=', Y: 'operator+=', Z: 'operator-=',
  _0: 'operator/=', _1: 'operator%=', _2: 'operator>>=', _3: 'operator<<=', _4: 'operator&=', _5: 'operator|=', _6: 'operator^=',
  _D: "`vbase dtor'", _E: "`vector deleting dtor'", _F: "`default ctor closure'", _G: "`scalar deleting dtor'",
  _H: "`vector ctor iterator'", _I: "`vector dtor iterator'", _J: "`vector vbase ctor iterator'", _K: "`virtual displacement map'",
  _L: "`eh vector ctor iterator'", _M: "`eh vector dtor iterator'", _N: "`eh vector vbase ctor iterator'", _O: "`copy ctor closure'",
  _T: "`local vftable ctor closure'", _U: 'operator new[]', _V: 'operator delete[]',
  __A: "`managed vector ctor iterator'", __B: "`managed vector dtor iterator'", __C: "`EH vector copy ctor iterator'",
  __D: "`EH vector vbase copy ctor iterator'", __G: "`vector copy ctor iterator'", __H: "`vector vbase copy constructor iterator'",
  __I: "`managed vector vbase copy constructor iterator'", __L: 'operator co_await', __M: 'operator<=>',
};

const PRIMITIVES: Record<string, string> = {
  X: 'void', D: 'char', C: 'signed char', E: 'unsigned char', F: 'short', G: 'unsigned short', H: 'int', I: 'unsigned int',
  J: 'long', K: 'unsigned long', M: 'float', N: 'double', O: 'long double',
  _N: 'bool', _J: '__int64', _K: 'unsigned __int64', _W: 'wchar_t', _Q: 'char8_t', _S: 'char16_t', _U: 'char32_t', _P: 'auto',
  _T: 'decltype(auto)',
};

const FUNCTION_CLASSES: Record<string, number> = {
  A: FC.Private, B: FC.Private | FC.Far, C: FC.Private | FC.Static, D: FC.Private | FC.Static | FC.Far,
  E: FC.Private | FC.Virtual, F: FC.Private | FC.Virtual | FC.Far, G: FC.Private | FC.StaticThisAdjust,
  H: FC.Private | FC.StaticThisAdjust | FC.Far, I: FC.Protected, J: FC.Protected | FC.Far, K: FC.Protected | FC.Static,
  L: FC.Protected | FC.Static | FC.Far, M: FC.Protected | FC.Virtual, N: FC.Protected | FC.Virtual | FC.Far,
  O: FC.Protected | FC.Virtual | FC.StaticThisAdjust, P: FC.Protected | FC.Virtual | FC.StaticThisAdjust | FC.Far,
  Q: FC.Public, R: FC.Public | FC.Far, S: FC.Public | FC.Static, T: FC.Public | FC.Static | FC.Far, U: FC.Public | FC.Virtual,
  V: FC.Public | FC.Virtual | FC.Far, W: FC.Public | FC.Virtual | FC.StaticThisAdjust,
  X: FC.Public | FC.Virtual | FC.StaticThisAdjust | FC.Far, Y: FC.Global, Z: FC.Global | FC.Far,
  9: FC.ExternC | FC.NoParameterList,
};

const isDigit = (c: string | undefined) => c !== undefined && c >= '0' && c <= '9';

interface Backrefs {
  names: NamedIdentifier[];
  params: TypeNode[];
}

class Demangler {
  private s: string;
  private backrefs: Backrefs = { names: [], params: [] };
  private depth = 0;

  constructor(mangled: string) {
    this.s = mangled;
  }

  get rest(): string {
    return this.s;
  }

  private fail(): never {
    throw new Bad();
  }
  private starts(p: string): boolean {
    return this.s.startsWith(p);
  }
  private consume(p: string): boolean {
    if (!this.s.startsWith(p)) return false;
    this.s = this.s.slice(p.length);
    return true;
  }
  private front(): string {
    if (!this.s) this.fail();
    return this.s[0]!;
  }
  private take(): string {
    const c = this.front();
    this.s = this.s.slice(1);
    return c;
  }

  parse(): Sym {
    if (++this.depth > 256) this.fail();
    try {
      if (this.starts('.')) return this.typeinfoName();
      if (this.starts('??@')) return this.md5Name();
      if (!this.consume('?')) this.fail();
      return this.specialIntrinsic() ?? this.declarator();
    } finally {
      this.depth--;
    }
  }

  private typeinfoName(): Sym {
    this.consume('.');
    const t = this.type('result');
    if (this.s) this.fail();
    return synthesizeVariable(t, "`RTTI Type Descriptor Name'");
  }

  private md5Name(): Sym {
    const end = this.s.indexOf('@', 3);
    if (end < 0) this.fail();
    const start = this.s;
    this.s = this.s.slice(end + 1);
    this.consume('??_R4@');
    const sym = new PlainSymbol();
    sym.name = new QualifiedName([new NamedIdentifier(start.slice(0, start.length - this.s.length))]);
    return sym;
  }

  private specialIntrinsic(): Sym | null {
    const kinds: [string, string][] = [
      ['?_7', 'vftable'], ['?_8', 'vbtable'], ['?_9', 'vcall'], ['?_A', 'typeof'], ['?_B', 'guard'], ['?_C', 'string'],
      ['?_P', 'udt'], ['?_R0', 'rtti0'], ['?_R1', 'rtti1'], ['?_R2', 'rtti2'], ['?_R3', 'rtti3'], ['?_R4', 'rtti4'],
      ['?_S', 'local vftable'], ['?__E', 'init'], ['?__F', 'atexit'], ['?__J', 'thread guard'],
    ];
    const found = kinds.find(([p]) => this.starts(p));
    if (!found) return null;
    this.consume(found[0]);
    switch (found[1]) {
      case 'string': return this.stringLiteral();
      case 'vftable': return this.specialTable("`vftable'");
      case 'vbtable': return this.specialTable("`vbtable'");
      case 'local vftable': return this.specialTable("`local vftable'");
      case 'rtti4': return this.specialTable("`RTTI Complete Object Locator'");
      case 'vcall': return this.vcallThunk();
      case 'guard': return this.localStaticGuard(false);
      case 'thread guard': return this.localStaticGuard(true);
      case 'rtti0': {
        const t = this.type('result');
        if (!this.consume('@8') || this.s) this.fail();
        return synthesizeVariable(t, "`RTTI Type Descriptor'");
      }
      case 'rtti2': return this.untypedVariable("`RTTI Base Class Array'");
      case 'rtti3': return this.untypedVariable("`RTTI Class Hierarchy Descriptor'");
      case 'rtti1': {
        // Kept in 32 bits, as LLVM keeps them: the offset of the vbptr signed, the rest unsigned.
        const values = [BigInt.asUintN(32, this.unsigned()), BigInt.asIntN(32, this.signed()), BigInt.asUintN(32, this.unsigned()), BigInt.asUintN(32, this.unsigned())];
        const v = new VariableSymbol();
        v.name = this.nameScopeChain(new RttiBaseClassDescriptor(values));
        this.consume('8');
        return v;
      }
      case 'init': return this.initFiniStub(false);
      case 'atexit': return this.initFiniStub(true);
      default: this.fail();
    }
  }

  private specialTable(name: string): Sym {
    const sym = new SpecialTableSymbol();
    sym.name = this.nameScopeChain(new NamedIdentifier(name));
    const c = this.take();
    if (c !== '6' && c !== '7') this.fail();
    sym.quals = this.qualifiers()[0];
    if (!this.consume('@')) sym.target = this.fullyQualifiedTypeName();
    return sym;
  }

  private localStaticGuard(thread: boolean): Sym {
    const id = new LocalStaticGuardIdentifier(thread);
    const sym = new PlainSymbol();
    sym.name = this.nameScopeChain(id);
    if (!this.consume('4IA') && !this.consume('5')) this.fail();
    if (this.s) id.scopeIndex = BigInt.asUintN(32, this.unsigned());
    return sym;
  }

  private untypedVariable(name: string): Sym {
    const v = new VariableSymbol();
    v.name = this.nameScopeChain(new NamedIdentifier(name));
    if (!this.consume('8')) this.fail();
    return v;
  }

  private vcallThunk(): Sym {
    const fn = new FunctionSymbol();
    const id = new VcallThunkIdentifier();
    fn.signature = new ThunkSignature();
    fn.signature.functionClass = FC.NoParameterList;
    fn.name = this.nameScopeChain(id);
    if (!this.consume('$B')) this.fail();
    id.offset = this.unsigned();
    if (!this.consume('A')) this.fail();
    fn.signature.callingConvention = this.callingConvention();
    return fn;
  }

  private initFiniStub(destructor: boolean): Sym {
    const id = new DynamicStructorIdentifier(destructor);
    const knownStaticMember = this.consume('?');
    const symbol = this.declarator();
    if (symbol instanceof VariableSymbol) {
      id.variable = symbol;
      for (let i = 0; i < (knownStaticMember ? 2 : 1); i++) if (!this.consume('@')) this.fail();
      const fn = this.functionEncoding();
      fn.name = new QualifiedName([id]);
      return fn;
    }
    if (knownStaticMember || !(symbol instanceof FunctionSymbol)) this.fail();
    id.name = symbol.name;
    symbol.name = new QualifiedName([id]);
    return symbol;
  }

  private stringLiteral(): Sym {
    const sym = new StringLiteralSymbol();
    if (!this.consume('@_')) this.fail();
    const kind = this.take();
    if (kind !== '0' && kind !== '1') this.fail();
    const wide = kind === '1';
    const [size, negative] = this.number();
    let bytes = Number(size);
    if (negative || bytes < (wide ? 2 : 1)) this.fail();
    const crcEnd = this.s.indexOf('@');
    if (crcEnd < 0) this.fail();
    this.s = this.s.slice(crcEnd + 1);
    if (!this.s) this.fail();
    let text = '';
    if (wide) {
      sym.prefix = 'L"';
      if (bytes > 64) sym.truncated = true;
      while (!this.consume('@')) {
        if (bytes % 2 !== 0 || bytes === 0 || this.s.length < 2) this.fail();
        const hi = this.charLiteral();
        if (!this.s) this.fail();
        const w = (hi << 8) | this.charLiteral();
        if (bytes !== 2 || sym.truncated) text += escapedChar(w);
        bytes -= 2;
      }
    } else {
      const decoded: number[] = [];
      while (!this.consume('@')) {
        if (!this.s || decoded.length >= 128) this.fail();
        decoded.push(this.charLiteral());
      }
      if (bytes > decoded.length) sym.truncated = true;
      const width = guessCharByteSize(decoded, bytes);
      sym.prefix = width === 1 ? '"' : width === 2 ? 'u"' : 'U"';
      const count = Math.floor(decoded.length / width);
      for (let i = 0; i < count; i++) {
        let c = 0;
        for (let b = 0; b < width; b++) c |= decoded[i * width + b]! << (8 * b);
        if (i + 1 < count || sym.truncated) text += escapedChar(c >>> 0);
      }
    }
    sym.text = text;
    return sym;
  }

  private charLiteral(): number {
    if (!this.consume('?')) return this.take().charCodeAt(0) & 0xff;
    if (!this.s) this.fail();
    if (this.consume('$')) {
      if (this.s.length < 2) this.fail();
      const hex = (c: string) => (c >= 'A' && c <= 'P' ? c.charCodeAt(0) - 65 : -1);
      const a = hex(this.s[0]!);
      const b = hex(this.s[1]!);
      if (a < 0 || b < 0) this.fail();
      this.s = this.s.slice(2);
      return (a << 4) | b;
    }
    const c = this.take();
    if (isDigit(c)) return ",/\\:. \n\t'-".charCodeAt(Number(c));
    if (c >= 'a' && c <= 'z') return 0xe1 + c.charCodeAt(0) - 97;
    if (c >= 'A' && c <= 'Z') return 0xc1 + c.charCodeAt(0) - 65;
    this.fail();
  }

  private number(): [bigint, boolean] {
    const negative = this.consume('?');
    if (isDigit(this.s[0])) return [BigInt(Number(this.take()) + 1), negative];
    let value = 0n;
    for (let i = 0; i < this.s.length; i++) {
      const c = this.s[i]!;
      if (c === '@') {
        this.s = this.s.slice(i + 1);
        return [value, negative];
      }
      if (c >= 'A' && c <= 'P') {
        value = ((value << 4n) + BigInt(c.charCodeAt(0) - 65)) & 0xffffffffffffffffn;
        continue;
      }
      break;
    }
    this.fail();
  }
  private unsigned(): bigint {
    const [v, negative] = this.number();
    if (negative) this.fail();
    return v;
  }
  private signed(): bigint {
    const [v, negative] = this.number();
    if (v > 0x7fffffffffffffffn) this.fail();
    return negative ? -v : v;
  }

  private memorizeString(s: string): void {
    if (this.backrefs.names.length >= 10 || this.backrefs.names.some((n) => n.name === s)) return;
    this.backrefs.names.push(new NamedIdentifier(s));
  }
  private memorizeIdentifier(id: Identifier): void {
    const o = new Out();
    id.output(o, OF.Default);
    this.memorizeString(o.s);
  }

  private backRefName(): NamedIdentifier {
    const i = Number(this.s[0]);
    const n = this.backrefs.names[i];
    if (!n) this.fail();
    this.s = this.s.slice(1);
    return n;
  }

  private simpleString(memorize: boolean): string {
    const at = this.s.indexOf('@');
    if (at <= 0) this.fail();
    const s = this.s.slice(0, at);
    this.s = this.s.slice(at + 1);
    if (memorize) this.memorizeString(s);
    return s;
  }

  private templateInstantiationName(template: boolean): Identifier {
    this.consume('?$');
    const outer = this.backrefs;
    this.backrefs = { names: [], params: [] };
    let id: Identifier;
    try {
      id = this.unqualifiedSymbolName(true);
      id.templateParams = this.templateParameterList();
    } finally {
      this.backrefs = outer;
    }
    if (template) {
      if (id instanceof ConversionOperatorIdentifier || id instanceof StructorIdentifier) this.fail();
      this.memorizeIdentifier(id);
    }
    return id;
  }

  private anonymousNamespaceName(): Identifier {
    this.consume('?A');
    const end = this.s.indexOf('@');
    if (end < 0) this.fail();
    this.memorizeString(this.s.slice(0, end));
    this.s = this.s.slice(end + 1);
    return new NamedIdentifier("`anonymous namespace'");
  }

  private locallyScopedNamePiece(): Identifier {
    this.consume('?');
    const [n] = this.number();
    this.consume('?');
    const scope = this.parse();
    const o = new Out();
    o.s += '`';
    scope.output(o, OF.Default);
    o.s += `'::\`${n}'`;
    return new NamedIdentifier(o.s);
  }

  private fullyQualifiedTypeName(): QualifiedName {
    return this.nameScopeChain(this.unqualifiedTypeName(true));
  }

  fullyQualifiedSymbolName(): QualifiedName {
    const id = this.unqualifiedSymbolName(true);
    const name = this.nameScopeChain(id);
    if (id instanceof StructorIdentifier) {
      if (name.components.length < 2) this.fail();
      id.cls = name.components[name.components.length - 2]!;
    }
    return name;
  }

  private unqualifiedTypeName(memorize: boolean): Identifier {
    if (isDigit(this.s[0])) return this.backRefName();
    if (this.starts('?$')) return this.templateInstantiationName(true);
    return new NamedIdentifier(this.simpleString(memorize));
  }

  private unqualifiedSymbolName(memorizeSimple: boolean): Identifier {
    if (isDigit(this.s[0])) return this.backRefName();
    if (this.starts('?$')) return this.templateInstantiationName(false);
    if (this.starts('?')) return this.functionIdentifierCode();
    return new NamedIdentifier(this.simpleString(memorizeSimple));
  }

  private nameScopePiece(): Identifier {
    if (isDigit(this.s[0])) return this.backRefName();
    if (this.starts('?$')) return this.templateInstantiationName(true);
    if (this.starts('?A')) return this.anonymousNamespaceName();
    if (startsWithLocalScopePattern(this.s)) return this.locallyScopedNamePiece();
    return new NamedIdentifier(this.simpleString(true));
  }

  private nameScopeChain(unqualified: Identifier): QualifiedName {
    const components = [unqualified];
    while (!this.consume('@')) {
      if (!this.s) this.fail();
      components.unshift(this.nameScopePiece());
    }
    return new QualifiedName(components);
  }

  private functionIdentifierCode(): Identifier {
    this.consume('?');
    if (!this.s) this.fail();
    if (this.consume('__')) {
      const c = this.take();
      if (c === 'K') return new LiteralOperatorIdentifier(this.simpleString(false));
      return this.intrinsic(`__${c}`);
    }
    if (this.consume('_')) return this.intrinsic(`_${this.take()}`);
    const c = this.take();
    if (c === '0' || c === '1') return new StructorIdentifier(c === '1');
    if (c === 'B') return new ConversionOperatorIdentifier();
    return this.intrinsic(c);
  }

  private intrinsic(code: string): Identifier {
    const ch = code[code.length - 1]!;
    if (!(isDigit(ch) || (ch >= 'A' && ch <= 'Z'))) this.fail();
    // Codes with no text of their own print nothing, as llvm-undname prints them.
    return new TextIdentifier(INTRINSICS[code] ?? '');
  }

  private declarator(): Sym {
    const name = this.fullyQualifiedSymbolName();
    const symbol = this.encodedSymbol(name);
    symbol.name = name;
    const last = name.last;
    if (last instanceof ConversionOperatorIdentifier && !last.target) this.fail();
    return symbol;
  }

  private encodedSymbol(name: QualifiedName): Sym {
    const c = this.front();
    if (c >= '0' && c <= '4') {
      this.take();
      const storage = (['private', 'protected', 'public', 'global', 'local'] as const)[Number(c)]!;
      return this.variableEncoding(storage);
    }
    const fn = this.functionEncoding();
    const last = name.last;
    if (last instanceof ConversionOperatorIdentifier) last.target = fn.signature.returnType;
    return fn;
  }

  private variableEncoding(storage: VariableSymbol['storage']): VariableSymbol {
    const v = new VariableSymbol();
    v.type = this.type('drop');
    v.storage = storage;
    if (v.type instanceof PointerType) {
      const p = v.type;
      p.quals |= this.pointerExtQualifiers();
      const [extra] = this.qualifiers();
      if (p.classParent) this.fullyQualifiedTypeName();
      p.pointee.quals |= extra;
    } else v.type.quals = this.qualifiers()[0];
    return v;
  }

  private functionClass(): number {
    const c = this.take();
    if (c === '$') {
      let flag = FC.VirtualThisAdjust as number;
      if (this.consume('R')) flag |= FC.VirtualThisAdjustEx;
      const d = this.take();
      const map: Record<string, number> = {
        0: FC.Private | FC.Virtual, 1: FC.Private | FC.Virtual | FC.Far, 2: FC.Protected | FC.Virtual,
        3: FC.Protected | FC.Virtual | FC.Far, 4: FC.Public | FC.Virtual, 5: FC.Public | FC.Virtual | FC.Far,
      };
      if (map[d] === undefined) this.fail();
      return map[d]! | flag;
    }
    const fc = FUNCTION_CLASSES[c];
    if (fc === undefined) this.fail();
    return fc;
  }

  private callingConvention(): string {
    return CALLING_CONVENTIONS[this.take()] ?? '';
  }

  private qualifiers(): [number, boolean] {
    switch (this.take()) {
      case 'Q': return [Q.None, true];
      case 'R': return [Q.Const, true];
      case 'S': return [Q.Volatile, true];
      case 'T': return [Q.Const | Q.Volatile, true];
      case 'A': return [Q.None, false];
      case 'B': return [Q.Const, false];
      case 'C': return [Q.Volatile, false];
      case 'D': return [Q.Const | Q.Volatile, false];
      default: this.fail();
    }
  }

  private type(mode: 'mangle' | 'result' | 'drop'): TypeNode {
    if (++this.depth > 256) this.fail();
    try {
      let quals = 0;
      if (mode === 'mangle') quals = this.qualifiers()[0];
      else if (mode === 'result' && this.consume('?')) quals = this.qualifiers()[0];
      const c = this.front();
      let t: TypeNode;
      if ('TUVW'.includes(c)) t = this.classType();
      else if (this.starts('$$Q') || 'APQRS'.includes(c)) t = this.isMemberPointer() ? this.memberPointerType() : this.pointerType();
      else if (c === 'Y') t = this.arrayType();
      else if (this.consume('$$A8@@')) t = this.functionType(true);
      else if (this.consume('$$A6')) t = this.functionType(false);
      else if (c === '?') t = this.customType();
      else t = this.primitiveType();
      t.quals |= quals;
      return t;
    } finally {
      this.depth--;
    }
  }

  private isMemberPointer(): boolean {
    let s = this.s;
    const f = s[0]!;
    s = s.slice(1);
    if (f === '$' || f === 'A') return false;
    if (isDigit(s[0])) {
      if (s[0] !== '6' && s[0] !== '8') this.fail();
      return s[0] === '8';
    }
    for (const q of ['E', 'I', 'F']) if (s.startsWith(q)) s = s.slice(1);
    if (s.startsWith('__ptrauth')) {
      const saved = this.s;
      this.s = s.slice(9);
      try {
        for (let i = 0; i < 3; i++) this.number();
        s = this.s;
      } catch {
        s = this.s;
      } finally {
        this.s = saved;
      }
    }
    if (!s) this.fail();
    if ('ABCD'.includes(s[0]!)) return false;
    if ('QRST'.includes(s[0]!)) return true;
    this.fail();
  }

  private pointerCVQualifiers(): [number, Affinity] {
    if (this.consume('$$Q')) return [Q.None, 'rvalue'];
    switch (this.take()) {
      case 'A': return [Q.None, 'reference'];
      case 'P': return [Q.None, 'pointer'];
      case 'Q': return [Q.Const, 'pointer'];
      case 'R': return [Q.Volatile, 'pointer'];
      case 'S': return [Q.Const | Q.Volatile, 'pointer'];
      default: this.fail();
    }
  }

  private pointerExtQualifiers(): number {
    let q = 0;
    if (this.consume('E')) q |= Q.Pointer64;
    if (this.consume('I')) q |= Q.Restrict;
    if (this.consume('F')) q |= Q.Unaligned;
    return q;
  }

  private pointerAuthQualifier(): NodeArray | null {
    if (!this.consume('__ptrauth')) return null;
    const values: IntegerLiteral[] = [];
    for (let i = 0; i < 3; i++) {
      const [v, negative] = this.number();
      if (negative) return null;
      values.push(new IntegerLiteral(v, false));
    }
    return new NodeArray(values);
  }

  private pointerType(): PointerType {
    const p = new PointerType();
    [p.quals, p.affinity] = this.pointerCVQualifiers();
    if (this.consume('6')) {
      p.pointee = this.functionType(false);
      return p;
    }
    p.quals |= this.pointerExtQualifiers();
    p.pointerAuth = this.pointerAuthQualifier();
    p.pointee = this.type('mangle');
    return p;
  }

  private memberPointerType(): PointerType {
    const p = new PointerType();
    [p.quals, p.affinity] = this.pointerCVQualifiers();
    p.quals |= this.pointerExtQualifiers();
    if (this.consume('8')) {
      p.classParent = this.fullyQualifiedTypeName();
      p.pointee = this.functionType(true);
    } else {
      const [quals] = this.qualifiers();
      p.classParent = this.fullyQualifiedTypeName();
      p.pointee = this.type('drop');
      p.pointee.quals = quals;
    }
    return p;
  }

  private arrayType(): ArrayType {
    this.consume('Y');
    const [rank, negative] = this.number();
    if (negative || rank === 0n) this.fail();
    const a = new ArrayType();
    for (let i = 0n; i < rank; i++) {
      const [d, neg] = this.number();
      if (neg) this.fail();
      a.dimensions.push(new IntegerLiteral(d, false));
      if (a.dimensions.length > 64) this.fail();
    }
    if (this.consume('$$C')) {
      const [quals, member] = this.qualifiers();
      if (member) this.fail();
      a.quals = quals;
    }
    a.element = this.type('drop');
    return a;
  }

  private classType(): TagType {
    const c = this.take();
    if (c === 'W' && !this.consume('4')) this.fail();
    const tag = c === 'T' ? 'union' : c === 'U' ? 'struct' : c === 'V' ? 'class' : 'enum';
    return new TagType(tag, this.fullyQualifiedTypeName());
  }

  private customType(): CustomType {
    this.consume('?');
    const t = new CustomType(this.unqualifiedTypeName(true));
    if (!this.consume('@')) this.fail();
    return t;
  }

  private primitiveType(): PrimitiveType {
    if (this.consume('$$T')) return new PrimitiveType('std::nullptr_t');
    let c = this.take();
    if (c === '_') c += this.take();
    const name = PRIMITIVES[c];
    if (!name) this.fail();
    return new PrimitiveType(name);
  }

  private functionType(thisQuals: boolean): FunctionSignature {
    const fn = new FunctionSignature();
    if (thisQuals) {
      fn.quals = this.pointerExtQualifiers();
      if (this.consume('G')) fn.refQualifier = '&';
      else if (this.consume('H')) fn.refQualifier = '&&';
      fn.quals |= this.qualifiers()[0];
    }
    fn.callingConvention = this.callingConvention();
    if (!this.consume('@')) fn.returnType = this.type('result');
    fn.params = this.functionParameterList(fn);
    if (this.consume('_E')) fn.noexcept = true;
    else if (!this.consume('Z')) this.fail();
    return fn;
  }

  private functionEncoding(): FunctionSymbol {
    const extra = this.consume('$$J0') ? FC.ExternC : FC.None;
    if (!this.s) this.fail();
    const fc = this.functionClass() | extra;
    let thunk: ThunkSignature | null = null;
    // The adjustments are kept in 32 bits, as LLVM keeps them: the static one unsigned, the others signed.
    const i32 = () => Number(BigInt.asIntN(32, this.signed()));
    const u32 = () => Number(BigInt.asUintN(32, this.signed()));
    if (fc & FC.StaticThisAdjust) {
      thunk = new ThunkSignature();
      thunk.staticOffset = u32();
    } else if (fc & FC.VirtualThisAdjust) {
      thunk = new ThunkSignature();
      if (fc & FC.VirtualThisAdjustEx) {
        thunk.vbptrOffset = i32();
        thunk.vboffsetOffset = i32();
      }
      thunk.vtordispOffset = i32();
      thunk.staticOffset = u32();
    }
    let sig: FunctionSignature;
    if (fc & FC.NoParameterList) sig = new FunctionSignature();
    else sig = this.functionType(!(fc & (FC.Global | FC.Static)));
    if (thunk) {
      Object.assign(thunk, { callingConvention: sig.callingConvention, refQualifier: sig.refQualifier, returnType: sig.returnType,
        variadic: sig.variadic, params: sig.params, noexcept: sig.noexcept, quals: sig.quals });
      sig = thunk;
    }
    sig.functionClass = fc;
    const fn = new FunctionSymbol();
    fn.signature = sig;
    return fn;
  }

  private functionParameterList(fn: FunctionSignature): NodeArray | null {
    if (this.consume('X')) return null;
    const params: TypeNode[] = [];
    while (!this.starts('@') && !this.starts('Z')) {
      if (!this.s) this.fail();
      if (isDigit(this.s[0])) {
        const t = this.backrefs.params[Number(this.s[0])];
        if (!t) this.fail();
        this.s = this.s.slice(1);
        params.push(t);
        continue;
      }
      const before = this.s.length;
      const t = this.type('drop');
      params.push(t);
      // One-letter types are not remembered: a back reference would save nothing.
      if (this.backrefs.params.length <= 9 && before - this.s.length > 1) this.backrefs.params.push(t);
    }
    if (this.consume('@')) return new NodeArray(params);
    this.consume('Z');
    fn.variadic = true;
    return new NodeArray(params);
  }

  private templateParameterList(): NodeArray {
    const params: Node[] = [];
    while (!this.starts('@')) {
      if (!this.s) this.fail();
      if (this.consume('$S') || this.consume('$$V') || this.consume('$$$V') || this.consume('$$Z')) continue;
      const auto = this.consume('$M');
      if (auto) this.type('drop');
      const prefixed = (c: string) => this.starts(auto ? c : `$${c}`);
      let param: Node;
      if (this.consume('$$Y')) param = this.fullyQualifiedTypeName();
      else if (this.consume('$$B')) param = this.type('drop');
      else if (this.consume('$$C')) param = this.type('mangle');
      else if (prefixed('1') || prefixed('H') || prefixed('I') || prefixed('J')) {
        const ref = new TemplateParameterReference();
        if (!auto) this.take();
        const inheritance = this.take();
        if (this.starts('?')) {
          ref.symbol = this.parse();
          if (!ref.symbol.name) this.fail();
          this.memorizeIdentifier(ref.symbol.name.last);
        }
        const count = { J: 3, I: 2, H: 1, 1: 0 }[inheritance as 'J'] ?? 0;
        for (let i = 0; i < count; i++) ref.offsets.push(this.signed());
        ref.affinity = 'pointer';
        param = ref;
      } else if (this.starts('$E?')) {
        this.consume('$E');
        const ref = new TemplateParameterReference();
        ref.symbol = this.parse();
        ref.affinity = 'reference';
        param = ref;
      } else if (prefixed('F') || prefixed('G')) {
        const ref = new TemplateParameterReference();
        if (!auto) this.take();
        const inheritance = this.take();
        for (let i = 0; i < (inheritance === 'G' ? 3 : 2); i++) ref.offsets.push(this.signed());
        param = ref;
      } else if (this.consume(auto ? '0' : '$0')) {
        const [v, negative] = this.number();
        param = new IntegerLiteral(v, negative);
      } else param = this.type('drop');
      params.push(param);
    }
    this.consume('@');
    return new NodeArray(params);
  }
}

function synthesizeVariable(type: TypeNode, name: string): VariableSymbol {
  const v = new VariableSymbol();
  v.type = type;
  v.name = new QualifiedName([new NamedIdentifier(name)]);
  return v;
}

/** `?<number>?` at the front: a local scope inside a function (`?1??f@@YAXXZ@`). */
function startsWithLocalScopePattern(s: string): boolean {
  if (!s.startsWith('?')) return false;
  s = s.slice(1);
  const end = s.indexOf('?');
  if (end <= 0) return false;
  const candidate = s.slice(0, end);
  if (candidate.length === 1) return candidate === '@' || isDigit(candidate);
  if (!candidate.endsWith('@')) return false;
  const digits = candidate.slice(0, -1);
  if (digits[0]! < 'B' || digits[0]! > 'P') return false;
  return [...digits.slice(1)].every((c) => c >= 'A' && c <= 'P');
}

function escapedChar(c: number): string {
  const named: Record<number, string> = { 0: '\\0', 39: "\\'", 34: '\\"', 92: '\\\\', 7: '\\a', 8: '\\b', 12: '\\f', 10: '\\n', 13: '\\r', 9: '\\t', 11: '\\v' };
  if (named[c] !== undefined) return named[c]!;
  if (c > 0x1f && c < 0x7f) return String.fromCharCode(c);
  let hex = '';
  while (c !== 0) {
    for (let i = 0; i < 2; i++) {
      hex = '0123456789ABCDEF'[c % 16] + hex;
      c = Math.floor(c / 16);
    }
  }
  return `\\x${hex}`;
}

/** The width of the characters of a narrow string literal, guessed as LLVM guesses it. */
function guessCharByteSize(bytes: number[], total: number): number {
  if (total % 2 === 1) return 1;
  if (total < 32) {
    let trailing = 0;
    for (let i = bytes.length - 1; i >= 0 && bytes[i] === 0; i--) trailing++;
    if (trailing >= 4 && total % 4 === 0) return 4;
    if (trailing >= 2) return 2;
    return 1;
  }
  const nulls = bytes.filter((b) => b === 0).length;
  if (nulls >= Math.floor((2 * bytes.length) / 3) && total % 4 === 0) return 4;
  if (nulls >= Math.floor(bytes.length / 3)) return 2;
  return 1;
}

/** The parsed symbol, or null. */
function parseMsvc(mangled: string): Sym | null {
  try {
    return new Demangler(mangled).parse();
  } catch (err) {
    if (err instanceof Bad || err instanceof RangeError) return null;
    throw err;
  }
}

/** The symbol printed with the given llvm-undname output flags (`OF`), or null when it does not parse. */
export function undname(mangled: string, flags = 0): string | null {
  const sym = parseMsvc(mangled);
  if (!sym) return null;
  const o = new Out();
  sym.output(o, flags);
  return o.s;
}

/**
 * An MSVC name demangled: in full as llvm-undname prints it, and short for
 * the listing — the qualified name without `class`/`struct`, template
 * arguments inside template arguments folded to `<…>`, and `(…)` or `()` for
 * a function's parameters, as the other C++ names are shown.
 */
export function demangleMsvc(mangled: string): { full: string; short: string } | null {
  const sym = parseMsvc(mangled);
  if (!sym) return null;
  const full = new Out();
  sym.output(full, OF.Default);
  const short = new Out();
  short.fold = true;
  if (sym instanceof FunctionSymbol && sym.name) {
    sym.name.output(short, OF_MINIMAL | OF.NoTagSpecifier);
    if (!(sym.signature.functionClass & FC.NoParameterList)) short.s += sym.signature.params?.nodes.length || sym.signature.variadic ? '(…)' : '()';
  } else sym.output(short, OF_MINIMAL | OF.NoTagSpecifier);
  return { full: full.s, short: short.s };
}
